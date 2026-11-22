use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use nos_pki::{Incoming, PeerId};
use nos_proto::{
    IpcCodec, LoginBackend, Role, RoleAttribute, UserRole, WatchdogEvent, WatchdogRequest,
    INVALID_CREDENTIALS, INVALID_TICKET, LOGIN_BUSY, LOGIN_TICKET_TTL, MAX_FAILURES_DEFAULT,
    RADIUS_ACCT_PORT_DEFAULT, RADIUS_PORT_DEFAULT, RADIUS_RETRIES_DEFAULT,
    RADIUS_TIMEOUT_DEFAULT_SECS, SESSION_EXPIRED,
};
use tokio::io::split;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, trace, warn};

use crate::accounting::{self, Record};
use crate::pki::Pki;
use crate::registry::EndpointRegistry;
use crate::users_client;

/// A failed login costs the caller this much wall time, and the connection is
/// dropped after `LoginPolicy.max_failures` of them (default 5; #1148).
// This is per connection only (a client can reconnect); `MAX_CONCURRENT_VERIFIES`
// bounds the total cost of guessing, `nos-restd` adds a per-user lockout.
const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(1);

/// How many password verifications (argon2id, ~64 MiB x 4 threads each) run at
/// once in this process, across every connection. The rest wait up to
/// `LOGIN_QUEUE_WAIT` and are then refused with `LOGIN_BUSY` (#381).
const MAX_CONCURRENT_VERIFIES: usize = 2;
const LOGIN_QUEUE_WAIT: Duration = Duration::from_secs(5);

/// RADIUS exchanges in flight at once (#1360): each can hold a broker task for
/// `timeout*(retries+1)` per server, so a few slow REST logins must not take
/// every task. Beyond it a login waits `LOGIN_QUEUE_WAIT`, then `LOGIN_BUSY`.
/// The total RADIUS time must stay under `nos-restd`'s 20s IPC call limit.
const MAX_CONCURRENT_RADIUS: usize = 4;

/// Anonymous (no client certificate) connections may only `Login`, so they are
/// capped and dropped when idle; authenticated peers are neither (#950).
const MAX_ANON_CONNECTIONS: usize = 64;
const IDLE_ANON: Duration = Duration::from_secs(30);

/// Tunables of the anonymous-connection guard; `Default` is the production value.
#[derive(Clone, Copy)]
pub struct Limits {
    pub max_anonymous: usize,
    /// How long an anonymous peer may wait before sending its next request.
    pub anonymous_idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_anonymous: MAX_ANON_CONNECTIONS,
            anonymous_idle: IDLE_ANON,
        }
    }
}

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
    radius_slots: Semaphore,
    anon_slots: Arc<Semaphore>,
    anonymous_idle: Duration,
    /// `LoginPolicy.max_failures`, live (#1148).
    max_failures: Arc<AtomicU8>,
    /// Accounting records for the worker (#1153); bounded, never waited on.
    acct: accounting::Sender,
    /// When the over-cap warning last fired (at most one per second).
    last_cap_warn: Mutex<Option<Instant>>,
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
    start_with_limits(listen_socket, registry, sockets, pki, Limits::default())
}

/// [`start`] with explicit [`Limits`] (tests).
pub fn start_with_limits(
    listen_socket: &Path,
    registry: EndpointRegistry,
    sockets: Sockets,
    pki: Arc<Pki>,
    limits: Limits,
) -> io::Result<JoinHandle<()>> {
    let listener = pki.identity.listen_optional_client_auth(listen_socket)?;
    info!(listen_socket = %listen_socket.display(), "broker IPC listening");
    let max_failures = Arc::new(AtomicU8::new(MAX_FAILURES_DEFAULT));
    tokio::spawn(users_client::follow_login_policy(
        pki.identity.clone(),
        sockets.config.clone(),
        max_failures.clone(),
    ));
    let (acct, acct_rx) = accounting::queue();
    let ctx = Arc::new(Ctx {
        registry,
        sockets,
        pki,
        login_slots: Semaphore::new(MAX_CONCURRENT_VERIFIES),
        radius_slots: Semaphore::new(MAX_CONCURRENT_RADIUS),
        anon_slots: Arc::new(Semaphore::new(limits.max_anonymous)),
        anonymous_idle: limits.anonymous_idle,
        max_failures,
        acct,
        last_cap_warn: Mutex::new(None),
    });
    tokio::spawn(account_worker(ctx.clone(), acct_rx));
    Ok(tokio::spawn(async move {
        loop {
            let incoming = listener.accept_resilient().await;
            tokio::spawn(handle_connection(incoming, ctx.clone()));
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
    // Held for the connection's life; authenticated peers take none.
    let _permit = if peer.is_none() {
        if let Ok(p) = ctx.anon_slots.clone().try_acquire_owned() {
            Some(p)
        } else {
            let mut last = ctx.last_cap_warn.lock().unwrap();
            if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                warn!("too many anonymous broker connections, dropping one");
                *last = Some(Instant::now());
            }
            return;
        }
    } else {
        None
    };
    let serial = stream.peer_serial();
    let claim = stream.peer_claim();
    let (read_half, write_half) = split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<WatchdogRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<WatchdogEvent>::default());
    let mut failed_logins = 0;

    loop {
        // The idle limit covers only the wait for the next request, never
        // dispatch or the failed-login sleep.
        let next = if peer.is_none() {
            if let Ok(next) = tokio::time::timeout(ctx.anonymous_idle, reader.next()).await {
                next
            } else {
                debug!("anonymous broker connection idle, closing");
                break;
            }
        } else {
            reader.next().await
        };
        let Some(msg) = next else { break };
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
        let event = dispatch(
            &ctx,
            peer.as_ref(),
            serial.as_deref(),
            claim.as_deref(),
            request,
        )
        .await;
        let rejected_login = is_login
            && matches!(&event, WatchdogEvent::Denied(m) if m == INVALID_CREDENTIALS || m == INVALID_TICKET);
        if rejected_login {
            failed_logins += 1;
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
        }
        let limit = u32::from(ctx.max_failures.load(Ordering::Relaxed));
        if failed_logins >= limit {
            warn!(
                failures = failed_logins,
                "login failures reached the limit, closing the connection"
            );
        }
        if writer.send(event).await.is_err() || hang_up || failed_logins >= limit {
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
        WatchdogRequest::AccountCommit { .. } => role == Some(Role::Configd.as_str()),
        WatchdogRequest::RenewCert { .. } => role == Some(Role::User.as_str()),
        // `nos-restd` vouches for REST clients: it has verified their certificate
        // (or, for a login, forwards the password it was given).
        WatchdogRequest::IssueRestServerCert { .. }
        | WatchdogRequest::RestLogin { .. }
        | WatchdogRequest::RestRenew { .. }
        | WatchdogRequest::RestCertCheck { .. } => role == Some(Role::Restd.as_str()),
        // Any supervised daemon (a person has no process to supervise).
        WatchdogRequest::Heartbeat => role.is_some_and(|r| r != Role::User.as_str()),
    }
}

async fn dispatch(
    ctx: &Ctx,
    peer: Option<&PeerId>,
    serial: Option<&str>,
    claim: Option<&str>,
    request: WatchdogRequest,
) -> WatchdogEvent {
    if !allowed(peer, &request) {
        warn!(peer = ?peer, ?request, "refusing a broker request the caller may not make");
        return WatchdogEvent::Denied(if peer.is_none() {
            "authentication required".to_string()
        } else {
            "not permitted".to_string()
        });
    }
    match request {
        WatchdogRequest::Heartbeat => {
            if let Some(p) = peer {
                crate::heartbeat::record(&p.role, &p.name);
            }
            WatchdogEvent::Ok
        }
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
                    let event = issue(ctx, &user, &csr_der, Realm::Ipc, Instant::now(), None);
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
        WatchdogRequest::AccountCommit { actor, transaction } => {
            accounting::offer(&ctx.acct, Record::Commit { actor, transaction });
            WatchdogEvent::Ok
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
            // The serial comes from the verified TLS peer certificate, never
            // from the client; renewals inherit the login time (#637).
            let user = peer.map_or("", |p| &p.name);
            if let Some(started) = serial.and_then(|s| ctx.pki.ipc_session(s, user)) {
                renew(ctx, user, &csr_der, Realm::Ipc, started, claim).await
            } else {
                info!(user = ?user, "renewal refused, ipc certificate unknown or past the session cap");
                WatchdogEvent::Denied(SESSION_EXPIRED.to_string())
            }
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
            // The claim is the stored session's, never the client's (#1360).
            if let Some((started, claim)) = ctx.pki.rest_session_claim(&serial, &user) {
                renew(ctx, &user, &csr_der, Realm::Rest, started, claim.as_deref()).await
            } else {
                info!(user = ?user, "renewal refused, rest certificate revoked or past the session cap");
                WatchdogEvent::Denied(SESSION_EXPIRED.to_string())
            }
        }
        WatchdogRequest::RestCertCheck { user, serial } => {
            if let Some((_, claim)) = ctx.pki.rest_session_claim(&serial, &user) {
                WatchdogEvent::RestSessionLive {
                    claim: claim.as_deref().and_then(UserRole::from_claim),
                }
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
    // One path for IPC and REST (#1360): `aaa login-order`, local fallthrough.
    let claim = match authenticate(ctx, user, password).await {
        Ok(claim) => claim,
        Err(denied) => return denied,
    };
    let started = Instant::now();
    let event = issue(ctx, user, csr_der, realm, started, claim.as_deref());
    if matches!(event, WatchdogEvent::Issued { .. }) {
        info!(user = ?user, rest = matches!(realm, Realm::Rest), "login accepted");
        account_session(ctx, user, started, realm);
    }
    event
}

/// How often an accounting session is checked for its end.
const SESSION_POLL: Duration = Duration::from_secs(5);

/// Queues a Start now and, from a task, the Stop once no certificate of this
/// login is live any more (expired, or revoked by a password change or a
/// deleted user; for REST also past the session cap). The Stop is therefore up
/// to `SESSION_POLL` late.
fn account_session(ctx: &Ctx, user: &str, started: Instant, realm: Realm) {
    let session = accounting::session_id();
    let user = user.to_string();
    accounting::offer(
        &ctx.acct,
        Record::Start {
            user: user.clone(),
            session: session.clone(),
        },
    );
    let (tx, pki) = (ctx.acct.clone(), ctx.pki.clone());
    tokio::spawn(async move {
        while match realm {
            Realm::Ipc => pki.session_live(&user, started),
            Realm::Rest => pki.rest_session_live(&user, started),
        } {
            tokio::time::sleep(SESSION_POLL).await;
        }
        let secs = u32::try_from(started.elapsed().as_secs()).unwrap_or(u32::MAX);
        accounting::offer(
            &tx,
            Record::Stop {
                user,
                session,
                secs,
            },
        );
    });
}

/// Sends queued records one at a time, so a slow server backs the bounded
/// queue up (and drops) instead of delaying anything else.
async fn account_worker(ctx: Arc<Ctx>, mut rx: tokio::sync::mpsc::Receiver<Record>) {
    while let Some(record) = rx.recv().await {
        let Ok(cfg) = users_client::fetch_config(&ctx.pki.identity, &ctx.sockets.config).await
        else {
            debug!("accounting record dropped: the config is not readable");
            continue;
        };
        if !cfg.aaa.accounting {
            continue;
        }
        let servers = radius_servers(&ctx, &cfg, true).await;
        if servers.is_empty() {
            continue;
        }
        if nos_radius::account(&servers, accounting::attrs(&record)).await {
            debug!(?record, "radius accounting acknowledged");
        } else {
            warn!(?record, "radius accounting not acknowledged by any server");
        }
    }
}

/// Walks `aaa login-order` (#1153). `Ok(Some(role))` is a RADIUS accept (the
/// role goes into the certificate), `Ok(None)` a local one. A reject ends the
/// walk; the next backend runs only when no RADIUS server answered, or, after
/// `local`, when the name is no local user.
async fn authenticate(
    ctx: &Ctx,
    user: &str,
    password: String,
) -> Result<Option<String>, WatchdogEvent> {
    let cfg = match users_client::fetch_config(&ctx.pki.identity, &ctx.sockets.config).await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(error = %e, "cannot read the config from nos-configd, refusing login");
            return Err(WatchdogEvent::Denied("login unavailable".to_string()));
        }
    };
    let order = cfg.aaa.order();
    if order == [LoginBackend::Local] {
        return verify_password(ctx, user, password).await.map(|()| None);
    }
    let invalid = || WatchdogEvent::Denied(INVALID_CREDENTIALS.to_string());
    if user.is_empty() || user.len() > 64 {
        return Err(invalid());
    }
    for backend in &order {
        match backend {
            LoginBackend::Local if cfg.users.iter().any(|u| u.name == user) => {
                return verify_password(ctx, user, password).await.map(|()| None);
            }
            LoginBackend::Local => {}
            LoginBackend::Radius => match radius_slot_login(ctx, &cfg, user, &password).await {
                Err(None) => return Err(WatchdogEvent::Denied(LOGIN_BUSY.to_string())),
                Ok(role) => {
                    info!(user = ?user, role = role.claim(), "login accepted by radius");
                    return Ok(Some(role.claim().to_string()));
                }
                Err(Some(nos_radius::AuthError::Unreachable)) => {
                    warn!(user = ?user, "no radius server answered");
                }
                Err(Some(e)) => {
                    info!(user = ?user, reason = %e, "radius login rejected");
                    return Err(invalid());
                }
            },
        }
    }
    if order.contains(&LoginBackend::Local) {
        // Not a local user: burns the same time as a wrong password.
        verify_password(ctx, user, password).await.map(|()| None)
    } else {
        Err(WatchdogEvent::Denied("login unavailable".to_string()))
    }
}

/// The Linux VRF device of routing table `table`, asked of its `nos-ribd`
/// (`None` while it is not up).
async fn vrf_name(ctx: &Ctx, table: &str) -> Option<String> {
    use nos_proto::{RibEvent, RibRequest, ServiceRef};
    let s = &ctx.sockets;
    let path = ctx
        .registry
        .resolve(
            &ServiceRef::RibTable(table.to_string()),
            &s.config,
            &s.interfaces,
            &s.log,
            &s.lacp,
            &s.lldp,
            &s.bfd,
            &s.stp,
            &s.acl,
        )
        .await?;
    let call = async {
        let stream = ctx
            .pki
            .identity
            .connect(&path, &PeerId::new(Role::Ribd.as_str(), table))
            .await
            .ok()?;
        let (r, w) = split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<RibEvent>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<RibRequest>::default());
        writer.send(RibRequest::GetVrfName).await.ok()?;
        match reader.next().await {
            Some(Ok(RibEvent::VrfName(name))) => name,
            _ => None,
        }
    };
    tokio::time::timeout(Duration::from_secs(3), call)
        .await
        .ok()
        .flatten()
}

/// The configured servers, with their secret, port (authentication or
/// accounting) and VRF device; one whose secret or VRF is missing is skipped.
async fn radius_servers(
    ctx: &Ctx,
    cfg: &nos_proto::Config,
    accounting: bool,
) -> Vec<nos_radius::Server> {
    let mut servers = Vec::new();
    for s in &cfg.aaa.servers {
        let Some(secret) = cfg.key(&s.secret_ref) else {
            continue;
        };
        let mut vrf = None;
        if let Some(t) = &s.routing_table {
            vrf = vrf_name(ctx, t).await;
            if vrf.is_none() {
                warn!(server = %s.name, table = %t, "radius server skipped: the VRF of its routing table is not available");
                continue;
            }
        }
        let port = if accounting {
            s.accounting_port.unwrap_or(RADIUS_ACCT_PORT_DEFAULT)
        } else {
            s.port.unwrap_or(RADIUS_PORT_DEFAULT)
        };
        servers.push(nos_radius::Server {
            addr: std::net::SocketAddr::new(s.address, port),
            secret: secret.as_bytes().to_vec(),
            timeout: Duration::from_secs(u64::from(
                s.timeout_secs.unwrap_or(RADIUS_TIMEOUT_DEFAULT_SECS),
            )),
            retries: s.retries.unwrap_or(RADIUS_RETRIES_DEFAULT),
            vrf,
        });
    }
    servers
}

/// `radius_login` holding one of `MAX_CONCURRENT_RADIUS` slots; `Err(None)`
/// when none frees in time.
async fn radius_slot_login(
    ctx: &Ctx,
    cfg: &nos_proto::Config,
    user: &str,
    password: &str,
) -> Result<UserRole, Option<nos_radius::AuthError>> {
    let Ok(Ok(_slot)) = tokio::time::timeout(LOGIN_QUEUE_WAIT, ctx.radius_slots.acquire()).await
    else {
        warn!(user = ?user, "login refused: too many radius exchanges in flight");
        return Err(None);
    };
    radius_login(ctx, cfg, user, password).await.map_err(Some)
}

/// One Access-Request across the configured servers; the role comes from the
/// reply attribute `aaa role-attribute` names (read-only when absent).
async fn radius_login(
    ctx: &Ctx,
    cfg: &nos_proto::Config,
    user: &str,
    password: &str,
) -> Result<UserRole, nos_radius::AuthError> {
    let servers = radius_servers(ctx, cfg, false).await;
    let accepted = nos_radius::authenticate(&servers, user, password, "nos").await?;
    let ty = match cfg.aaa.role_attribute {
        RoleAttribute::FilterId => nos_radius::attr::FILTER_ID,
        RoleAttribute::Class => nos_radius::attr::CLASS,
        RoleAttribute::ReplyMessage => nos_radius::attr::REPLY_MESSAGE,
    };
    Ok(accepted
        .attr(ty)
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(UserRole::from_claim)
        .unwrap_or(UserRole::ReadOnly))
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
    claim: Option<&str>,
) -> WatchdogEvent {
    match users_client::fetch_users(&ctx.pki.identity, &ctx.sockets.config).await {
        // A RADIUS user has no local entry: the role in the presented
        // certificate is carried over (the session cap still bounds it).
        Ok(users) if users.iter().any(|u| u.name == user) || claim.is_some() => {
            let claim = claim.filter(|_| !users.iter().any(|u| u.name == user));
            let event = issue(ctx, user, csr_der, realm, started, claim);
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

fn issue(
    ctx: &Ctx,
    user: &str,
    csr_der: &[u8],
    realm: Realm,
    started: Instant,
    claim: Option<&str>,
) -> WatchdogEvent {
    let signed = match realm {
        Realm::Ipc => ctx.pki.sign_user(csr_der, user, started, claim),
        Realm::Rest => ctx.pki.sign_rest_user(csr_der, user, started, claim),
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
