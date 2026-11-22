//! Owns the HTTP listener: which address it is bound to, inside which VRF.
//!
//! Every tick (and immediately on a routing-table config change) it compares
//! what this table's `rest_api` config *wants* with what is *bound*, and
//! converges: bind when wanted and possible, rebind when the address/port/VRF
//! changed, drop when unpinned. "Not possible yet" — the owning `nos-ribd`
//! hasn't created the VRF, or `nos-interfaced` hasn't yet put the address on
//! an interface in it — is an ordinary transient state, retried next tick,
//! exactly like `nos-bgpd`'s VRF resolution.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::Extension;
use futures::{SinkExt, StreamExt};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use nos_pki::rest::RestServer;
use nos_proto::{
    DiffScope, Event, IpcCodec, Request, RestApi, RibEvent, RibRequest, Role, ServiceRef,
};
use socket2::SockRef;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tower::ServiceExt as _;
use tracing::{debug, info, warn};

use crate::auth::PeerUser;
use crate::ipc::Daemons;
use crate::ratelimit::LogLimiter;

const TICK: Duration = Duration::from_secs(1);

/// HTTP/2 streams one client may have in flight on a connection.
const MAX_STREAMS: u32 = 128;

/// Open TCP connections (handshaking or serving) at once. A connection past
/// this is dropped before any post-quantum handshake work is spent on it.
pub const MAX_CONNECTIONS: usize = 256;

/// What one bound listener was bound *to*, so a later tick can tell whether
/// it is still the right one.
struct Bound {
    want: RestApi,
    vrf: String,
    /// The VRF device's ifindex at bind time. `SO_BINDTODEVICE` resolves the
    /// name once, so a VRF deleted and recreated under the same name (its
    /// `nos-ribd` restarted) leaves this socket bound to a device that no
    /// longer exists — detected by the ifindex changing.
    ifindex: Option<u32>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    /// Keeps the listener's TLS certificate renewed.
    renew: JoinHandle<()>,
}

pub struct Listener {
    pub table: String,
    pub daemons: Daemons,
    pub router: axum::Router,
}

impl Listener {
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut bound: Option<Bound> = None;
        // Last "can't bind" reason logged, so a retry loop logs once per change.
        let mut last_problem = String::new();
        let mut diffs = self.config_trigger().await;

        while !*shutdown.borrow() {
            self.converge(&mut bound, &mut last_problem).await;
            tokio::select! {
                () = tokio::time::sleep(TICK) => {}
                Some(()) = async { match diffs.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {}
                _ = shutdown.changed() => {}
            }
        }
        if let Some(b) = bound.take() {
            stop(b, &self.table).await;
        }
    }

    /// A channel that fires when routing-table config changes, so a change is
    /// applied immediately instead of on the next tick. Best effort: `None`
    /// (tick-only) if `nos-configd` can't be subscribed to right now, and not
    /// re-established if the subscription later drops — the 1s tick still
    /// converges, just later. ponytail: resubscribe if that latency matters.
    async fn config_trigger(&self) -> Option<tokio::sync::mpsc::Receiver<()>> {
        let stream = nos_pki::connect(&self.daemons.config_socket, Role::Configd, "")
            .await
            .ok()?;
        let (r, w) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
        writer
            .send(Request::SubscribeDiff {
                scopes: vec![DiffScope::RoutingTables],
            })
            .await
            .ok()?;
        let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let _keep_write_half_open = writer;
            while let Some(Ok(_)) = reader.next().await {
                if tx.send(()).await.is_err() {
                    break;
                }
            }
        });
        Some(rx)
    }

    async fn converge(&self, bound: &mut Option<Bound>, last_problem: &mut String) {
        let Some(want) = self.wanted().await else {
            return; // config unreadable: keep whatever is bound
        };

        // Drop a listener that is no longer the right one.
        if let Some(b) = bound.as_ref() {
            let vrf_now = self.vrf_name().await;
            let stale = want.as_ref() != Some(&b.want)
                || vrf_now.as_deref() != Some(b.vrf.as_str())
                || ifindex(&b.vrf) != b.ifindex;
            if stale && let Some(b) = bound.take() {
                stop(b, &self.table).await;
            }
        }
        let (Some(want), None) = (want, bound.as_ref()) else {
            return;
        };

        let problem = match self.bind(&want).await {
            Ok(b) => {
                info!(
                    table = %self.table, vrf = %b.vrf, address = %want.address, port = want.port,
                    "rest api listening"
                );
                *bound = Some(b);
                last_problem.clear();
                return;
            }
            Err(problem) => problem,
        };
        if *last_problem != problem {
            warn!(table = %self.table, address = %want.address, port = want.port, "rest api not listening yet: {problem}");
            *last_problem = problem;
        }
    }

    /// This table's pinned `rest_api` (`Some(None)` = read fine, not pinned);
    /// `None` if the config couldn't be read, so a `nos-configd` blip never
    /// tears down a healthy listener.
    async fn wanted(&self) -> Option<Option<RestApi>> {
        match self.daemons.rest_api(&self.table).await {
            Ok(api) => Some(api),
            Err(e) => {
                debug!(error = ?e, "could not read config; keeping current listener");
                None
            }
        }
    }

    async fn vrf_name(&self) -> Option<String> {
        match self
            .daemons
            .service::<_, RibEvent>(
                ServiceRef::RibTable(self.table.clone()),
                RibRequest::GetVrfName,
            )
            .await
        {
            Ok(RibEvent::VrfName(name)) => name,
            _ => None,
        }
    }

    async fn bind(&self, want: &RestApi) -> Result<Bound, String> {
        let vrf = self
            .vrf_name()
            .await
            .ok_or_else(|| format!("vrf of table '{}' does not exist yet", self.table))?;
        let listener = bind_listener(SocketAddr::new(want.address, want.port), &vrf)
            .map_err(|e| format!("bind in vrf {vrf} failed: {e}"))?;
        // After the bind, so an address that isn't on the VRF yet (retried
        // every tick) doesn't cost a certificate request each time.
        let (tls, renew) = crate::tls::start(&self.daemons, want.address)
            .await
            .map_err(|e| format!("cannot get a REST listener certificate: {e}"))?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let task = tokio::spawn(serve(
            listener,
            self.router.clone(),
            tls,
            stop_rx,
            MAX_CONNECTIONS,
        ));
        Ok(Bound {
            want: want.clone(),
            ifindex: ifindex(&vrf),
            vrf,
            stop: stop_tx,
            task,
            renew,
        })
    }
}

/// Accepts connections until told to stop: TLS handshake in each connection's
/// own task (a slow peer never stalls accept), then HTTP/1.1 or HTTP/2 —
/// whichever ALPN chose — with the user the client certificate names attached
/// to every request on that connection.
pub async fn serve(
    listener: TcpListener,
    app: axum::Router,
    tls: Arc<RestServer>,
    mut stop: watch::Receiver<bool>,
    max_connections: usize,
) {
    let mut http = auto::Builder::new(TokioExecutor::new());
    http.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10));
    http.http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(MAX_STREAMS)
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20));
    let http = Arc::new(http);
    let graceful = GracefulShutdown::new();
    let slots = Arc::new(Semaphore::new(max_connections));
    let log = Arc::new(Mutex::new(LogLimiter::default()));
    let mut refused_log = LogLimiter::default();

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = async { let _ = stop.wait_for(|s| *s).await; } => break,
        };
        let (tcp, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(error = %e, "rest accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // Nagle off (#759): hyper writes a response's HEADERS and DATA frames
        // separately, and Nagle holds the second until the client's delayed ACK
        // (~40 ms) releases it, so every small response took 40 ms.
        let _ = tcp.set_nodelay(true);
        // try_acquire, never an awaiting acquire: that would stall the stop path.
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            if let Some(n) = refused_log.allow(peer.ip(), Instant::now()) {
                warn!(%peer, suppressed = n, max = max_connections, "rest connection refused: too many open connections");
            }
            continue; // `tcp` dropped: closed before any TLS work
        };
        let (tls, app, http, watcher, log) = (
            tls.clone(),
            app.clone(),
            http.clone(),
            graceful.watcher(),
            log.clone(),
        );
        tokio::spawn(async move {
            let _permit = permit; // held through handshake and serving
            let accepted = match tls.accept(tcp).await {
                Ok(accepted) => accepted,
                Err(e) => {
                    let allowed = log
                        .lock()
                        .expect("log limiter")
                        .allow(peer.ip(), Instant::now());
                    if let Some(n) = allowed {
                        warn!(%peer, error = %e, suppressed = n, "rest tls handshake failed");
                    }
                    return;
                }
            };
            let service = TowerToHyperService::new(
                app.layer(Extension(crate::login::ClientIp(peer.ip())))
                    .layer(Extension(PeerUser(
                        accepted.user,
                        accepted.serial,
                        accepted
                            .claim
                            .as_deref()
                            .and_then(nos_proto::UserRole::from_claim),
                    )))
                    .map_request(|req: axum::http::Request<Incoming>| req.map(Body::new)),
            );
            let conn = http
                .serve_connection_with_upgrades(TokioIo::new(accepted.stream), service)
                .into_owned();
            if let Err(e) = watcher.watch(conn).await {
                debug!(%peer, error = %e, "rest connection ended");
            }
        });
    }
    drop(listener);
    // The caller (`stop`) gives this a couple of seconds, then gives up.
    graceful.shutdown().await;
}

async fn stop(b: Bound, table: &str) {
    b.renew.abort();
    let _ = b.stop.send(true);
    // Graceful shutdown waits for open connections; don't let a keep-alive
    // client hold a rebind hostage.
    if tokio::time::timeout(Duration::from_secs(2), b.task)
        .await
        .is_err()
    {
        debug!(table = %table, "listener did not drain in time");
    }
    info!(table = %table, vrf = %b.vrf, address = %b.want.address, port = b.want.port, "rest api stopped listening");
}

/// `SO_BINDTODEVICE` into `vrf`, then bind the one configured address (a
/// per-crate copy of `nos-bgpd`'s `tcp::bind_listener`, narrowed to that
/// address rather than a wildcard).
fn bind_listener(local: SocketAddr, vrf: &str) -> io::Result<TcpListener> {
    let socket = if local.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    SockRef::from(&socket).bind_device(Some(vrf.as_bytes()))?;
    socket.bind(local)?;
    socket.listen(1024)
}

fn ifindex(dev: &str) -> Option<u32> {
    std::fs::read_to_string(Path::new("/sys/class/net").join(dev).join("ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}
