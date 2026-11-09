use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use nos_pki::{Incoming, PeerId};
use nos_proto::{
    IpcCodec, Role, WatchdogEvent, WatchdogRequest, INVALID_CREDENTIALS, INVALID_TICKET,
    LOGIN_BUSY, LOGIN_TICKET_TTL, SESSION_EXPIRED,
};
use tokio::io::split;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::pki::Pki;
use crate::registry::EndpointRegistry;
use crate::users_client;

/// A failed login costs the caller this much wall time, and the connection is
/// dropped after `MAX_FAILED_LOGINS` of them.
// This is per connection only (a client can reconnect); `MAX_CONCURRENT_VERIFIES`
// bounds the total cost of guessing, `nos-restd` adds a per-user lockout.
const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(1);
const MAX_FAILED_LOGINS: u32 = 3;

/// How many password verifications (argon2id, ~64 MiB x 4 threads each) run at
/// once in this process, across every connection. The rest wait up to
/// `LOGIN_QUEUE_WAIT` and are then refused with `LOGIN_BUSY` (#381).
const MAX_CONCURRENT_VERIFIES: usize = 2;
const LOGIN_QUEUE_WAIT: Duration = Duration::from_secs(5);

/// Where the singleton daemons listen — answered directly for their
/// `ServiceRef`s, not through the registry.
pub struct Sockets {
    pub config: PathBuf,
    pub interfaces: PathBuf,
    pub log: PathBuf,
    pub lacp: PathBuf,
    pub lldp: PathBuf,
    pub bfd: PathBuf,
    pub stp: PathBuf,
    pub acl: PathBuf,
}

/// Everything one broker connection needs.
struct Ctx {
    registry: EndpointRegistry,
    sockets: Sockets,
    pki: Arc<Pki>,
    login_slots: Semaphore,
}

/// Binds `listen_socket` and spawns the accept loop for the endpoint-broker
/// IPC: any authenticated daemon or client can dial this socket to ask where
/// to reach another service, instead of assuming a hardcoded default.
///
/// The socket accepts TLS peers *without* a client certificate too, but only
/// for `Login` — the one request that turns a password into a certificate.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    registry: EndpointRegistry,
    sockets: Sockets,
    pki: Arc<Pki>,
) -> io::Result<JoinHandle<()>> {
    let listener = pki.identity.listen_optional_client_auth(listen_socket)?;
    info!(listen_socket = %listen_socket.display(), "broker IPC listening");
    let ctx = Arc::new(Ctx {
        registry,
        sockets,
        pki,
        login_slots: Semaphore::new(MAX_CONCURRENT_VERIFIES),
    });
    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok(incoming) => {
                    tokio::spawn(handle_connection(incoming, ctx.clone()));
                }
                Err(e) => {
                    error!(error = %e, "broker IPC accept loop terminated");
                    break;
                }
            }
        }
    }))
}

async fn handle_connection(incoming: Incoming, ctx: Arc<Ctx>) {
    let (stream, peer) = match incoming.handshake().await {
        Ok(ok) => ok,
        Err(e) => {
            debug!(error = %e, "broker tls handshake failed");
            return;
        }
    };
    let (read_half, write_half) = split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<WatchdogRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<WatchdogEvent>::default());
    let mut failed_logins = 0;

    while let Some(msg) = reader.next().await {
        let request = match msg {
            Ok(request) => request,
            Err(e) => {
                warn!(error = %e, "broker IPC read error");
                break;
            }
        };
        // Only direct logins are throttled here: `RestLogin` comes over
        // `nos-restd`'s shared connection, which does its own per-user delay.
        let is_login = matches!(
            request,
            WatchdogRequest::Login { .. }
                | WatchdogRequest::LoginTicket { .. }
                | WatchdogRequest::RedeemTicket { .. }
        );
        // An anonymous peer may only log in: answer its first other request
        // (one warn in `dispatch`) and hang up, so it can't flood the log.
        let hang_up = peer.is_none() && !allowed(None, &request);
        let event = dispatch(&ctx, peer.as_ref(), request).await;
        let rejected_login = is_login
            && matches!(&event, WatchdogEvent::Denied(m) if m == INVALID_CREDENTIALS || m == INVALID_TICKET);
        if rejected_login {
            failed_logins += 1;
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
        }
        if writer.send(event).await.is_err() || hang_up || failed_logins >= MAX_FAILED_LOGINS {
            break;
        }
    }
}

/// Who may send what. No wildcard arm: a new `WatchdogRequest` variant does
/// not compile until it is classified here.
fn allowed(peer: Option<&PeerId>, request: &WatchdogRequest) -> bool {
    let role = peer.map(|p| p.role.as_str());
    match request {
        // The only things an unauthenticated peer may do: turn a password (or
        // a ticket a password bought) into a certificate.
        WatchdogRequest::Login { .. }
        | WatchdogRequest::LoginTicket { .. }
        | WatchdogRequest::RedeemTicket { .. } => true,
        WatchdogRequest::ResolveEndpoint { .. } => peer.is_some(),
        WatchdogRequest::RenewCert { .. } => role == Some(Role::User.as_str()),
        // `nos-restd` vouches for REST clients: it has verified their certificate
        // (or, for a login, forwards the password it was given).
        WatchdogRequest::IssueRestServerCert { .. }
        | WatchdogRequest::RestLogin { .. }
        | WatchdogRequest::RestRenew { .. }
        | WatchdogRequest::RestCertCheck { .. } => role == Some(Role::Restd.as_str()),
    }
}

async fn dispatch(ctx: &Ctx, peer: Option<&PeerId>, request: WatchdogRequest) -> WatchdogEvent {
    if !allowed(peer, &request) {
        warn!(peer = ?peer, ?request, "refusing a broker request the caller may not make");
        return WatchdogEvent::Denied(if peer.is_none() {
            "authentication required".to_string()
        } else {
            "not permitted".to_string()
        });
    }
    match request {
        WatchdogRequest::Login {
            user,
            password,
            csr_der,
        } => login(ctx, &user, password, &csr_der, Realm::Ipc).await,
        WatchdogRequest::LoginTicket { user, password } => {
            if let Err(denied) = verify_password(ctx, &user, password).await {
                if matches!(&denied, WatchdogEvent::Denied(m) if m == INVALID_CREDENTIALS) {
                    info!(reason = "bad-password", "login ticket refused");
                }
                return denied;
            }
            let ticket = ctx.pki.tickets.issue(&user, Instant::now());
            info!(user = ?user, "login ticket issued");
            WatchdogEvent::Ticket {
                ticket,
                ttl_secs: LOGIN_TICKET_TTL.as_secs(),
            }
        }
        WatchdogRequest::RedeemTicket { ticket, csr_der } => {
            let Some(user) = ctx.pki.tickets.redeem(&ticket, Instant::now()) else {
                info!(reason = "unknown-ticket", "login ticket refused");
                return WatchdogEvent::Denied(INVALID_TICKET.to_string());
            };
            match users_client::fetch_users(&ctx.pki.identity, &ctx.sockets.config).await {
                Ok(users) if users.iter().any(|u| u.name == user) => {
                    let event = issue(ctx, &user, &csr_der, Realm::Ipc, Instant::now());
                    if matches!(event, WatchdogEvent::Issued { .. }) {
                        info!(user = ?user, "login ticket redeemed");
                    }
                    event
                }
                Ok(_) => {
                    info!(reason = "user-gone", "login ticket refused");
                    WatchdogEvent::Denied(INVALID_TICKET.to_string())
                }
                Err(e) => {
                    warn!(error = %e, "cannot read users from nos-configd, refusing ticket");
                    WatchdogEvent::Denied("login unavailable".to_string())
                }
            }
        }
        WatchdogRequest::ResolveEndpoint { service } => {
            let s = &ctx.sockets;
            let resolved = ctx
                .registry
                .resolve(
                    &service,
                    &s.config,
                    &s.interfaces,
                    &s.log,
                    &s.lacp,
                    &s.lldp,
                    &s.bfd,
                    &s.stp,
                    &s.acl,
                )
                .await;
            if let Some(path) = resolved {
                trace!(?service, "resolved endpoint");
                WatchdogEvent::Endpoint(path)
            } else {
                debug!(?service, "endpoint not available");
                WatchdogEvent::NotAvailable
            }
        }
        // `allowed` has already required a `user` peer.
        WatchdogRequest::RenewCert { csr_der } => {
            renew(
                ctx,
                peer.map_or("", |p| &p.name),
                &csr_der,
                Realm::Ipc,
                Instant::now(),
            )
            .await
        }
        WatchdogRequest::RestLogin {
            user,
            password,
            csr_der,
        } => login(ctx, &user, password, &csr_der, Realm::Rest).await,
        WatchdogRequest::RestRenew {
            user,
            serial,
            csr_der,
        } => {
            // The renewed certificate inherits the login time, so renewals
            // cannot outlast `--pki-rest-session-max`.
            if let Some(started) = ctx.pki.rest_session(&serial, &user) {
                renew(ctx, &user, &csr_der, Realm::Rest, started).await
            } else {
                info!(user = ?user, "renewal refused, rest certificate revoked or past the session cap");
                WatchdogEvent::Denied(SESSION_EXPIRED.to_string())
            }
        }
        WatchdogRequest::RestCertCheck { user, serial } => {
            if ctx.pki.rest_session(&serial, &user).is_some() {
                WatchdogEvent::Ok
            } else {
                WatchdogEvent::Denied(SESSION_EXPIRED.to_string())
            }
        }
        WatchdogRequest::IssueRestServerCert { addresses, csr_der } => {
            match ctx.pki.sign_rest_server(&csr_der, &addresses) {
                Ok((cert_der, ca_der)) => {
                    info!(?addresses, "issued a REST listener certificate");
                    WatchdogEvent::RestServerCert {
                        cert_der,
                        ca_der,
                        lifetime_secs: ctx.pki.leaf_lifetime.as_secs(),
                    }
                }
                Err(e) => {
                    warn!(error = %e, "rejected a malformed REST certificate request");
                    WatchdogEvent::Denied("bad certificate request".to_string())
                }
            }
        }
    }
}

/// Which CA a login/renewal is certified by.
#[derive(Clone, Copy)]
enum Realm {
    Ipc,
    Rest,
}

/// Runs `job` on the blocking pool holding one of `slots` for its whole run, so
/// at most `slots` jobs exist at once; waits at most `wait` for a slot (`None`
/// then). A panicked job yields `T::default()`.
async fn run_bounded<T: Default + Send + 'static>(
    slots: &Semaphore,
    wait: Duration,
    job: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let _permit = tokio::time::timeout(wait, slots.acquire())
        .await
        .ok()?
        .ok()?;
    Some(tokio::task::spawn_blocking(job).await.unwrap_or_default())
}

/// Checks `password` against the running config's users (argon2, run off the
/// async threads — it is deliberately slow) and, on success, certifies the
/// caller's own public key as that user.
async fn login(
    ctx: &Ctx,
    user: &str,
    password: String,
    csr_der: &[u8],
    realm: Realm,
) -> WatchdogEvent {
    if let Err(denied) = verify_password(ctx, user, password).await {
        return denied;
    }
    let event = issue(ctx, user, csr_der, realm, Instant::now());
    if matches!(event, WatchdogEvent::Issued { .. }) {
        info!(user = ?user, rest = matches!(realm, Realm::Rest), "login accepted");
    }
    event
}

/// The password half of a login: `Err` carries the reply to send.
async fn verify_password(ctx: &Ctx, user: &str, password: String) -> Result<(), WatchdogEvent> {
    let users = match users_client::fetch_users(&ctx.pki.identity, &ctx.sockets.config).await {
        Ok(users) => users,
        Err(e) => {
            warn!(error = %e, "cannot read users from nos-configd, refusing login");
            return Err(WatchdogEvent::Denied("login unavailable".to_string()));
        }
    };
    let stored = users
        .into_iter()
        .find(|u| u.name == user)
        .map(|u| u.password);
    // `verify_or_dummy` burns the same time for an unknown user as for a wrong
    // password, so response time doesn't reveal which usernames exist. A
    // correct password against a hash made with weaker parameters than today's
    // is re-hashed here, while the clear text is at hand.
    let old = stored.clone();
    let Some((ok, upgraded)) = run_bounded(&ctx.login_slots, LOGIN_QUEUE_WAIT, move || {
        let ok = nos_password::verify_or_dummy(&password, stored.as_deref());
        let upgraded = stored
            .filter(|h| ok && nos_password::needs_rehash(h))
            .map(|_| nos_password::hash(&password));
        (ok, upgraded)
    })
    .await
    else {
        warn!(user = %user, "login refused: too many password checks in flight");
        return Err(WatchdogEvent::Denied(LOGIN_BUSY.to_string()));
    };
    if !ok {
        info!(user = ?user, "login rejected");
        return Err(WatchdogEvent::Denied(INVALID_CREDENTIALS.to_string()));
    }
    if let (Some(old), Some(new)) = (old, upgraded) {
        // Best effort: never fail a correct login over an upgrade. Noted first,
        // so the users diff it causes is known not to be a password change.
        ctx.pki.note_rehash(user, &new);
        match users_client::upgrade_password_hash(
            &ctx.pki.identity,
            &ctx.sockets.config,
            user,
            &old,
            new,
        )
        .await
        {
            Ok(()) => info!(user = ?user, "upgraded password hash to current parameters"),
            Err(e) => warn!(user = ?user, error = %e, "could not upgrade password hash"),
        }
    }
    Ok(())
}

/// A still-valid certificate is proof enough — but a user deleted since must
/// not be able to keep renewing.
async fn renew(
    ctx: &Ctx,
    user: &str,
    csr_der: &[u8],
    realm: Realm,
    started: Instant,
) -> WatchdogEvent {
    match users_client::fetch_users(&ctx.pki.identity, &ctx.sockets.config).await {
        Ok(users) if users.iter().any(|u| u.name == user) => {
            let event = issue(ctx, user, csr_der, realm, started);
            if matches!(event, WatchdogEvent::Issued { .. }) {
                info!(user = ?user, rest = matches!(realm, Realm::Rest), "user certificate renewed");
            }
            event
        }
        Ok(_) => {
            info!(user = ?user, "renewal refused, user no longer exists");
            WatchdogEvent::Denied("no such user".to_string())
        }
        Err(e) => {
            warn!(error = %e, "cannot read users from nos-configd, refusing renewal");
            WatchdogEvent::Denied("renewal unavailable".to_string())
        }
    }
}

fn issue(ctx: &Ctx, user: &str, csr_der: &[u8], realm: Realm, started: Instant) -> WatchdogEvent {
    let signed = match realm {
        Realm::Ipc => ctx.pki.sign_user(csr_der, user),
        Realm::Rest => ctx.pki.sign_rest_user(csr_der, user, started),
    };
    match signed {
        Ok(cert_der) => WatchdogEvent::Issued {
            cert_der,
            lifetime_secs: ctx.pki.user_lifetime.as_secs(),
        },
        Err(e) => {
            warn!(user = ?user, error = %e, "rejected a malformed certificate request");
            WatchdogEvent::Denied("bad certificate request".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn run_bounded_never_exceeds_its_slots() {
        let slots = Arc::new(Semaphore::new(2));
        let (now, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (slots, now, peak) = (slots.clone(), now.clone(), peak.clone());
                tokio::spawn(async move {
                    run_bounded(&slots, Duration::from_secs(10), move || {
                        peak.fetch_max(now.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(20));
                        now.fetch_sub(1, Ordering::SeqCst);
                        true
                    })
                    .await
                })
            })
            .collect();
        for t in tasks {
            assert_eq!(t.await.unwrap(), Some(true));
        }
        assert!((1..=2).contains(&peak.load(Ordering::SeqCst)));
    }

    #[tokio::test]
    async fn run_bounded_refuses_when_no_slot_frees_in_time() {
        let slots = Semaphore::new(1);
        let _held = slots.acquire().await.unwrap();
        let r = run_bounded(&slots, Duration::from_millis(20), || true).await;
        assert_eq!(r, None);
    }
}
