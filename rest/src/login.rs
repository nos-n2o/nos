//! Getting a client certificate. `POST /v1/login` trades a password for one —
//! the only route reachable without a certificate — and `POST /v1/renew`
//! trades a still-valid one for a fresh one. Both ask `nos-watchdogd` (the CA)
//! over the shared IPC connection; the client's private key never leaves it.
//!
//! The certificate is issued by the REST CA on the public key in the CSR the
//! client sends (an ECDSA P-256 key — `openssl req -new -newkey ec
//! -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -outform DER`, the
//! DER base64-encoded). Later requests present it in the TLS handshake and
//! carry no password.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::{Extension, Json};
use base64::Engine as _;
use nos_proto::{WatchdogEvent, WatchdogRequest, INVALID_CREDENTIALS, LOGIN_BUSY, SESSION_EXPIRED};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::PeerUser;
use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::ipc::Daemons;

/// A failed login costs the account this much before the next attempt on it.
// Per (source address, username); `MAX_INFLIGHT_LOGINS` caps the rest (many usernames at
// once), and `nos-watchdogd` is the authoritative bound on argon2 work (#381).
const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(1);

/// After this many failures inside `FAILED_LOGIN_WINDOW` (counted from the
/// first), further attempts on the account get `429` until the window ends.
const MAX_FAILED_LOGINS: u32 = 5;
const FAILED_LOGIN_WINDOW: Duration = Duration::from_secs(60);

/// Same window per source address, over all usernames. Higher than the
/// per-user limit because a NAT or proxy puts many users behind one address;
/// a success does not reset it (else one valid account would launder guesses).
const MAX_FAILED_LOGINS_PER_IP: u32 = 20;
/// Addresses tracked at once; past this, expired windows are pruned and, if
/// that frees nothing, the map starts over (a forgotten source gets a fresh
/// window).
const MAX_TRACKED_IPS: usize = 4096;

/// The peer address of the connection a request arrived on.
#[derive(Clone, Copy)]
pub struct ClientIp(pub IpAddr);

/// Logins in flight to the watchdog at once, across all usernames. Above its
/// own limit so the watchdog stays the real bound; this only stops `nos-restd`
/// from queueing unbounded IPC connections behind it.
const MAX_INFLIGHT_LOGINS: usize = 8;

/// One attempt at a time per username, so guessing one account's password is
/// limited to one guess per `FAILED_LOGIN_DELAY` however many streams or
/// connections the guesses arrive on.
pub struct LoginGate {
    inflight: Arc<tokio::sync::Semaphore>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Per (source address, username): failures so far and when the window
    /// opened. Keyed on the address too so an attacker can't lock the real
    /// user out from elsewhere (#635).
    failures: Mutex<HashMap<(IpAddr, String), (u32, Instant)>>,
    /// Per source address: failures so far and when the window opened.
    failures_by_ip: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Default for LoginGate {
    fn default() -> Self {
        Self::with_inflight(MAX_INFLIGHT_LOGINS)
    }
}

impl LoginGate {
    fn with_inflight(n: usize) -> Self {
        Self {
            inflight: Arc::new(tokio::sync::Semaphore::new(n)),
            locks: Mutex::default(),
            failures: Mutex::default(),
            failures_by_ip: Mutex::default(),
        }
    }

    /// A slot for one login, or `429` straight away when all are taken.
    fn try_slot(&self) -> ApiResult<tokio::sync::OwnedSemaphorePermit> {
        self.inflight
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests {
                detail: "too many logins in progress".into(),
                retry_after_secs: 1,
            })
    }

    /// Seconds until `user` may try again from `ip`, if it is locked out.
    fn retry_after(&self, ip: IpAddr, user: &str) -> Option<u64> {
        let failures = self.failures.lock().expect("login gate lock");
        let &(count, since) = failures.get(&(ip, user.to_string()))?;
        let left = FAILED_LOGIN_WINDOW.checked_sub(since.elapsed())?;
        (count >= MAX_FAILED_LOGINS).then(|| left.as_secs() + 1)
    }

    /// Seconds until `ip` may try again, if it is locked out.
    fn retry_after_ip(&self, ip: IpAddr) -> Option<u64> {
        let failures = self.failures_by_ip.lock().expect("login gate lock");
        let &(count, since) = failures.get(&ip)?;
        let left = FAILED_LOGIN_WINDOW.checked_sub(since.elapsed())?;
        (count >= MAX_FAILED_LOGINS_PER_IP).then(|| left.as_secs() + 1)
    }

    fn record_failure_ip(&self, ip: IpAddr) {
        let mut failures = self.failures_by_ip.lock().expect("login gate lock");
        if failures.len() >= MAX_TRACKED_IPS && !failures.contains_key(&ip) {
            failures.retain(|_, (_, since)| since.elapsed() < FAILED_LOGIN_WINDOW);
            if failures.len() >= MAX_TRACKED_IPS {
                failures.clear();
            }
        }
        let e = failures.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() >= FAILED_LOGIN_WINDOW {
            *e = (0, Instant::now());
        }
        e.0 += 1;
    }

    fn record_failure(&self, ip: IpAddr, user: &str) {
        let mut failures = self.failures.lock().expect("login gate lock");
        let key = (ip, user.to_string());
        if failures.len() >= MAX_TRACKED_IPS && !failures.contains_key(&key) {
            failures.retain(|_, (_, since)| since.elapsed() < FAILED_LOGIN_WINDOW);
            if failures.len() >= MAX_TRACKED_IPS {
                failures.clear();
            }
        }
        let e = failures.entry(key).or_insert((0, Instant::now()));
        if e.1.elapsed() >= FAILED_LOGIN_WINDOW {
            *e = (0, Instant::now());
        }
        e.0 += 1;
    }

    fn clear(&self, ip: IpAddr, user: &str) {
        self.failures
            .lock()
            .expect("login gate lock")
            .remove(&(ip, user.to_string()));
    }

    fn lock_for(&self, user: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks
            .lock()
            .expect("login gate lock")
            .entry(user.to_string())
            .or_default()
            .clone()
    }

    /// Forgets `user` once nobody else is waiting on it.
    fn release(&self, user: &str, mine: &Arc<tokio::sync::Mutex<()>>) {
        let mut gates = self.locks.lock().expect("login gate lock");
        // The map's copy and ours: nobody else holds it.
        if Arc::strong_count(mine) == 2 {
            gates.remove(user);
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub user: String,
    pub password: String,
    /// Base64 of a DER PKCS#10 certificate request for an ECDSA P-256 key you generated.
    pub csr: String,
}

// A `Debug` that hides the password: request bodies must never be one log line
// from leaking it.
impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("user", &self.user)
            .field("password", &"<hidden>")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct RenewRequest {
    /// As `LoginRequest::csr`, for a fresh key.
    pub csr: String,
}

#[derive(Serialize, ToSchema)]
pub struct Certificate {
    /// Base64 of the DER client certificate, issued by the REST CA.
    pub certificate: String,
    /// Seconds it is valid for; renew at half of that.
    pub lifetime_secs: u64,
}

fn decode_csr(csr: &str) -> ApiResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(csr.trim())
        .map_err(|_| ApiError::BadRequest("csr is not valid base64".to_string()))
}

fn certificate(reply: WatchdogEvent) -> ApiResult<Json<Certificate>> {
    match reply {
        WatchdogEvent::Issued {
            cert_der,
            lifetime_secs,
        } => Ok(Json(Certificate {
            certificate: base64::engine::general_purpose::STANDARD.encode(cert_der),
            lifetime_secs,
        })),
        WatchdogEvent::Denied(m)
            if m == INVALID_CREDENTIALS || m == "no such user" || m == SESSION_EXPIRED =>
        {
            Err(ApiError::Unauthorized(m))
        }
        WatchdogEvent::Denied(m) if m == "bad certificate request" => Err(ApiError::BadRequest(m)),
        WatchdogEvent::Denied(m) if m == LOGIN_BUSY => Err(ApiError::TooManyRequests {
            detail: m,
            retry_after_secs: 1,
        }),
        WatchdogEvent::Denied(m) => Err(ApiError::Unavailable(m)),
        other => Err(crate::ipc::unexpected("nos-watchdogd", &other)),
    }
}

/// Trade a password for a client certificate.
#[utoipa::path(
    post, path = "/v1/login", tag = "auth", summary = "Trade a password for a client certificate",
    description = "The only route that needs no client certificate. Send a certificate request for a key you generated; the response is the certificate.",
    security(()),
    request_body = LoginRequest,
    responses(
        (status = 200, body = Certificate),
        (status = 400, body = ErrorBody, description = "malformed certificate request"),
        (status = 401, body = ErrorBody, description = "unknown user or wrong password"),
        (status = 429, body = ErrorBody, description = "too many failed attempts for this user or source address, or too many logins in progress; see Retry-After")
    )
)]
pub async fn login(
    State(d): State<Daemons>,
    ip: Option<Extension<ClientIp>>,
    Json(body): Json<LoginRequest>,
) -> ApiResult<Json<Certificate>> {
    // No `ClientIp` only in tests that skip the TLS listener: one shared key.
    let ip = ip.map(|Extension(ClientIp(ip))| ip);
    let key_ip = ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    if let Some(retry_after_secs) = ip.and_then(|ip| d.login_gate.retry_after_ip(ip)) {
        return Err(ApiError::TooManyRequests {
            detail: "too many failed logins from this address".into(),
            retry_after_secs,
        });
    }
    let csr_der = decode_csr(&body.csr)?;
    let _slot = d.login_gate.try_slot()?;
    let gate = d.login_gate.lock_for(&body.user);
    let held = gate.lock().await;
    if let Some(retry_after_secs) = d.login_gate.retry_after(key_ip, &body.user) {
        drop(held);
        d.login_gate.release(&body.user, &gate);
        return Err(ApiError::TooManyRequests {
            detail: "too many failed logins for this user".into(),
            retry_after_secs,
        });
    }
    let reply = d
        .broker(WatchdogRequest::RestLogin {
            user: body.user.clone(),
            password: body.password,
            csr_der,
        })
        .await;
    if matches!(&reply, Ok(WatchdogEvent::Denied(m)) if m == INVALID_CREDENTIALS) {
        d.login_gate.record_failure(key_ip, &body.user);
        if let Some(ip) = ip {
            d.login_gate.record_failure_ip(ip);
        }
        tokio::time::sleep(FAILED_LOGIN_DELAY).await;
    } else if matches!(&reply, Ok(WatchdogEvent::Issued { .. })) {
        d.login_gate.clear(key_ip, &body.user);
    }
    drop(held);
    d.login_gate.release(&body.user, &gate);
    certificate(reply?)
}

/// Trade the certificate this connection presented for a fresh one.
#[utoipa::path(
    post, path = "/v1/renew", tag = "auth", summary = "Renew the client certificate",
    request_body = RenewRequest,
    responses(
        (status = 200, body = Certificate),
        (status = 401, body = ErrorBody, description = "no valid certificate, or the user no longer exists")
    )
)]
pub async fn renew(
    State(d): State<Daemons>,
    Extension(PeerUser(user, serial)): Extension<PeerUser>,
    Json(body): Json<RenewRequest>,
) -> ApiResult<Json<Certificate>> {
    // The middleware only lets a request with a certificate this far.
    let (Some(user), Some(serial)) = (user, serial) else {
        return Err(ApiError::Unauthorized("authentication required".into()));
    };
    let csr_der = decode_csr(&body.csr)?;
    certificate(
        d.broker(WatchdogRequest::RestRenew {
            user,
            serial,
            csr_der,
        })
        .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_forgets_the_user_only_when_nobody_else_waits() {
        let gate = LoginGate::default();
        let a = gate.lock_for("u");
        gate.release("u", &a);
        assert!(gate.locks.lock().unwrap().is_empty());

        let a = gate.lock_for("u");
        let b = gate.lock_for("u");
        assert!(Arc::ptr_eq(&a, &b));
        gate.release("u", &a);
        assert!(Arc::ptr_eq(&gate.lock_for("u"), &b));
    }

    #[test]
    fn lockout_after_max_failures_until_cleared_per_address_and_user() {
        let gate = LoginGate::default();
        let (a, b): (IpAddr, IpAddr) = ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        for _ in 0..MAX_FAILED_LOGINS - 1 {
            gate.record_failure(a, "u");
        }
        assert_eq!(gate.retry_after(a, "u"), None);
        gate.record_failure(a, "u");
        // A fresh window: 60s minus a sliver, rounded up to whole seconds.
        assert_eq!(gate.retry_after(a, "u"), Some(60));
        assert_eq!(gate.retry_after(a, "other"), None);
        assert_eq!(gate.retry_after(b, "u"), None);
        // Clearing is per pair too.
        for _ in 0..MAX_FAILED_LOGINS {
            gate.record_failure(b, "u");
        }
        gate.clear(a, "u");
        assert_eq!(gate.retry_after(a, "u"), None);
        assert!(gate.retry_after(b, "u").is_some());
    }

    #[test]
    fn user_lockout_map_is_bounded() {
        let gate = LoginGate::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        for i in 0..MAX_TRACKED_IPS + 10 {
            gate.record_failure(ip, &format!("u{i}"));
        }
        assert!(gate.failures.lock().unwrap().len() <= MAX_TRACKED_IPS);
    }

    #[test]
    fn try_slot_refuses_past_the_limit_and_frees_on_drop() {
        let gate = LoginGate::with_inflight(2);
        let a = gate.try_slot().unwrap();
        let _b = gate.try_slot().unwrap();
        assert!(matches!(
            gate.try_slot(),
            Err(ApiError::TooManyRequests {
                retry_after_secs: 1,
                ..
            })
        ));
        drop(a);
        assert!(gate.try_slot().is_ok());
    }

    #[test]
    fn ip_lockout_is_per_address_and_bounded() {
        let gate = LoginGate::default();
        let (a, b): (IpAddr, IpAddr) = ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        for _ in 0..MAX_FAILED_LOGINS_PER_IP - 1 {
            gate.record_failure_ip(a);
        }
        assert_eq!(gate.retry_after_ip(a), None);
        gate.record_failure_ip(a);
        assert_eq!(gate.retry_after_ip(a), Some(60));
        assert_eq!(gate.retry_after_ip(b), None);
        for i in 0..u32::try_from(MAX_TRACKED_IPS).unwrap() + 10 {
            gate.record_failure_ip(IpAddr::from(std::net::Ipv4Addr::from(i)));
        }
        assert!(gate.failures_by_ip.lock().unwrap().len() <= MAX_TRACKED_IPS);
    }

    #[test]
    fn busy_watchdog_becomes_429() {
        assert!(matches!(
            err(WatchdogEvent::Denied(LOGIN_BUSY.into())),
            ApiError::TooManyRequests { .. }
        ));
    }

    #[test]
    fn debug_hides_the_password() {
        let r = LoginRequest {
            user: "alice".into(),
            password: "hunter2".into(),
            csr: "x".into(),
        };
        let s = format!("{r:?}");
        assert!(s.contains("alice") && s.contains("<hidden>") && !s.contains("hunter2"));
    }

    fn err(reply: WatchdogEvent) -> ApiError {
        match certificate(reply) {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    #[test]
    fn issued_becomes_a_base64_certificate() {
        let Ok(Json(c)) = certificate(WatchdogEvent::Issued {
            cert_der: vec![1, 2, 3],
            lifetime_secs: 7,
        }) else {
            panic!("expected a certificate");
        };
        assert_eq!(c.certificate, "AQID");
        assert_eq!(c.lifetime_secs, 7);
    }

    #[test]
    fn denials_map_to_distinct_statuses() {
        for m in [INVALID_CREDENTIALS, "no such user", SESSION_EXPIRED] {
            assert!(
                matches!(err(WatchdogEvent::Denied(m.into())), ApiError::Unauthorized(x) if x == m)
            );
        }
        assert!(matches!(
            err(WatchdogEvent::Denied("bad certificate request".into())),
            ApiError::BadRequest(x) if x == "bad certificate request"
        ));
        assert!(matches!(
            err(WatchdogEvent::Denied("other".into())),
            ApiError::Unavailable(x) if x == "other"
        ));
        assert!(matches!(
            err(WatchdogEvent::NotAvailable),
            ApiError::BadGateway(_)
        ));
    }
}
