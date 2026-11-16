//! One generic request/reply call over a daemon's Unix socket, replacing a
//! per-daemon client module: every query here is "send one request, read one
//! event" framed by `IpcCodec`.
//!
//! Every IPC connection is a mutual-TLS handshake, so connections are pooled:
//! a finished call parks its connection and the next call to the same daemon
//! reuses it. That leans on one convention every daemon's server already
//! follows — a plain (non-streaming) request gets **exactly one** event back,
//! and the server keeps reading requests on the same connection. Streaming
//! replies (`LogRequest::Tail`) use `open_stream` and a connection of their own.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use futures::StreamExt;
use nos_proto::{
    Config, Event, IpcCodec, Request, Role, ServiceRef, WatchdogEvent, WatchdogRequest,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{split, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_util::codec::{Encoder, FramedRead, FramedWrite};
use tracing::debug;

type Stream = nos_pki::Stream;

use crate::error::{ApiError, ApiResult};

/// Connections kept per daemon; a burst wider than this opens (and then drops)
/// the extras.
const MAX_IDLE_PER_DAEMON: usize = 8;
/// A parked connection older than this is discarded rather than trusted.
const MAX_IDLE_AGE: Duration = Duration::from_secs(300);
/// Longest a daemon may take to accept a request or to answer it; below
/// `api::REQUEST_TIMEOUT`, so the 504 names the daemon, not the request.
const IPC_TIMEOUT: Duration = Duration::from_secs(20);

/// Shared by every handler: where to find `nos-configd` (resolved once at
/// startup), the broker used to find everything else, and the connection pool.
#[derive(Clone)]
pub struct Daemons {
    pub watchdog_socket: Arc<PathBuf>,
    pub config_socket: Arc<PathBuf>,
    pool: Arc<Pool>,
    pub(crate) login_gate: Arc<crate::login::LoginGate>,
}

/// Which daemon a pooled connection leads to, and who it proved to be.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Target {
    socket: PathBuf,
    role: String,
    name: String,
}

#[derive(Default)]
struct Pool {
    idle: Mutex<HashMap<Target, Vec<(Instant, Stream)>>>,
    /// Broker answers. Socket paths are fixed per daemon name, so only
    /// *availability* changes — which surfaces as a failed call and drops the
    /// entry (a "not running" answer is never cached).
    resolved: Mutex<HashMap<ServiceRef, PathBuf>>,
}

impl Pool {
    fn take(&self, target: &Target) -> Option<Stream> {
        let mut idle = self.idle.lock().expect("pool lock");
        let parked = idle.get_mut(target)?;
        while let Some((since, stream)) = parked.pop() {
            if since.elapsed() < MAX_IDLE_AGE {
                return Some(stream);
            }
        }
        None
    }

    fn put(&self, target: Target, stream: Stream) {
        let mut idle = self.idle.lock().expect("pool lock");
        let parked = idle.entry(target).or_default();
        if parked.len() < MAX_IDLE_PER_DAEMON {
            parked.push((Instant::now(), stream));
        }
    }
}

// Short-lived and moved once per call: boxing the stream would cost an
// allocation on every request to save nothing.
#[allow(clippy::large_enum_variant)]
enum Exchange<Ev, S = Stream> {
    /// The reply, and the connection if it is clean enough to reuse.
    Done(Option<S>, Ev),
    /// The connection was dead before any reply arrived.
    Stale,
    Bad(ApiError),
}

/// Writes one pre-encoded request and reads the first event back.
async fn exchange<Ev: DeserializeOwned>(stream: Stream, frame: &[u8]) -> Exchange<Ev> {
    exchange_within(IPC_TIMEOUT, stream, frame).await
}

async fn exchange_within<Ev: DeserializeOwned, S>(
    limit: Duration,
    mut stream: S,
    frame: &[u8],
) -> Exchange<Ev, S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Not `Stale`: a daemon that hung is not retried on a fresh connection,
    // and this connection is dropped, not parked.
    let timed_out = || Exchange::Bad(ApiError::GatewayTimeout("ipc call timed out".to_string()));
    let sent = tokio::time::timeout(limit, async {
        stream.write_all(frame).await?;
        stream.flush().await
    })
    .await;
    match sent {
        Err(_) => return timed_out(),
        Ok(Err(_)) => return Exchange::Stale,
        Ok(Ok(())) => {}
    }
    let mut reader = FramedRead::new(stream, IpcCodec::<Ev>::default());
    let Ok(next) = tokio::time::timeout(limit, reader.next()).await else {
        return timed_out();
    };
    match next {
        Some(Ok(ev)) => {
            let clean = reader.read_buffer().is_empty();
            Exchange::Done(clean.then(|| reader.into_inner()), ev)
        }
        Some(Err(e)) => Exchange::Bad(ApiError::BadGateway(format!("bad reply: {e}"))),
        None => Exchange::Stale,
    }
}

fn unavailable(socket: &Path, e: impl std::fmt::Display) -> ApiError {
    ApiError::Unavailable(format!("cannot reach daemon at {}: {e}", socket.display()))
}

impl Daemons {
    pub fn new(watchdog_socket: PathBuf, config_socket: PathBuf) -> Self {
        Self {
            watchdog_socket: Arc::new(watchdog_socket),
            config_socket: Arc::new(config_socket),
            pool: Arc::default(),
            login_gate: Arc::default(),
        }
    }

    /// The login lockout gate, for `login::follow_policy`.
    pub fn login_gate(&self) -> Arc<crate::login::LoginGate> {
        self.login_gate.clone()
    }

    /// Sends `req` to the daemon at `socket` — which must prove it is
    /// `role`/`name` — and returns the first event of the reply, over a pooled
    /// connection when one is parked.
    pub async fn call<Req, Ev>(
        &self,
        socket: &Path,
        role: impl AsRef<str>,
        name: &str,
        req: Req,
    ) -> ApiResult<Ev>
    where
        Req: Serialize,
        Ev: DeserializeOwned,
    {
        let target = Target {
            socket: socket.to_path_buf(),
            role: role.as_ref().to_string(),
            name: name.to_string(),
        };
        let mut frame = BytesMut::new();
        IpcCodec::<Req>::default()
            .encode(req, &mut frame)
            .map_err(|e| ApiError::BadGateway(format!("cannot encode request: {e}")))?;

        // A parked connection may have been closed by the daemon since (a
        // restart): that shows up as no reply at all, and is retried once on a
        // fresh connection. Only "dead before any reply" is retried, so a
        // request the daemon did receive is never sent twice.
        if let Some(stream) = self.pool.take(&target) {
            match exchange::<Ev>(stream, &frame).await {
                Exchange::Done(stream, ev) => return Ok(self.park(target, stream, ev)),
                Exchange::Bad(e) => return Err(e),
                Exchange::Stale => {
                    debug!(socket = %socket.display(), "pooled ipc connection was stale");
                }
            }
        }
        let stream = nos_pki::connect(socket, &target.role, name)
            .await
            .map_err(|e| unavailable(socket, e))?;
        match exchange::<Ev>(stream, &frame).await {
            Exchange::Done(stream, ev) => Ok(self.park(target, stream, ev)),
            Exchange::Bad(e) => Err(e),
            Exchange::Stale => Err(ApiError::Unavailable(
                "daemon closed the connection without replying".to_string(),
            )),
        }
    }

    fn park<Ev>(&self, target: Target, stream: Option<Stream>, ev: Ev) -> Ev {
        if let Some(stream) = stream {
            self.pool.put(target, stream);
        }
        ev
    }

    /// Where `service` listens right now, from the broker (cached).
    async fn resolve(&self, service: &ServiceRef) -> ApiResult<PathBuf> {
        if let Some(path) = self.pool.resolved.lock().expect("pool lock").get(service) {
            return Ok(path.clone());
        }
        let reply: WatchdogEvent = self
            .call(
                &self.watchdog_socket,
                Role::Watchdog,
                "",
                WatchdogRequest::ResolveEndpoint {
                    service: service.clone(),
                },
            )
            .await?;
        match reply {
            WatchdogEvent::Endpoint(path) => {
                self.pool
                    .resolved
                    .lock()
                    .expect("pool lock")
                    .insert(service.clone(), path.clone());
                Ok(path)
            }
            _ => Err(ApiError::Unavailable(format!("{service:?} is not running"))),
        }
    }

    fn forget(&self, service: &ServiceRef) {
        self.pool
            .resolved
            .lock()
            .expect("pool lock")
            .remove(service);
    }

    /// Resolves `service` through the watchdog broker, then `call`s it.
    pub async fn service<Req, Ev>(&self, service: ServiceRef, req: Req) -> ApiResult<Ev>
    where
        Req: Serialize,
        Ev: DeserializeOwned,
    {
        let socket = self.resolve(&service).await?;
        let reply = self
            .call(&socket, service.role(), service.instance(), req)
            .await;
        if matches!(reply, Err(ApiError::Unavailable(_))) {
            // Re-resolve on the next request rather than keep a dead path.
            self.forget(&service);
        }
        reply
    }

    /// Sends `req` on a connection of its own and hands it back still open,
    /// for a daemon reply that keeps streaming (`LogRequest::Tail`). The write
    /// half must be kept alive for as long as the stream is read: the daemon
    /// treats a closed connection as the client leaving.
    pub async fn open_stream<Req, Ev>(
        &self,
        service: ServiceRef,
        req: Req,
    ) -> ApiResult<(
        FramedRead<ReadHalf<Stream>, IpcCodec<Ev>>,
        FramedWrite<WriteHalf<Stream>, IpcCodec<Req>>,
    )>
    where
        Req: Serialize,
        Ev: DeserializeOwned,
    {
        use futures::SinkExt;
        let socket = self.resolve(&service).await?;
        let stream = nos_pki::connect(&socket, service.role(), service.instance())
            .await
            .map_err(|e| unavailable(&socket, e))?;
        let (r, w) = split(stream);
        let reader = FramedRead::new(r, IpcCodec::<Ev>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<Req>::default());
        writer
            .send(req)
            .await
            .map_err(|e| ApiError::Unavailable(format!("sending request failed: {e}")))?;
        Ok((reader, writer))
    }

    /// One request to `nos-configd`, with its `Event::Error` mapped to a status.
    pub async fn config(&self, req: Request) -> ApiResult<Event> {
        match self
            .call::<_, Event>(&self.config_socket, Role::Configd, "", req)
            .await?
        {
            Event::Error(msg) => Err(ApiError::from_config(msg)),
            ev => Ok(ev),
        }
    }

    /// The running config.
    pub async fn running_config(&self) -> ApiResult<Config> {
        match self.config(Request::Get).await? {
            Event::Config(cfg) => Ok(cfg),
            other => Err(unexpected("nos-configd", &other)),
        }
    }

    /// Whether `name` is a user in the running config (cheap probe, #755).
    pub async fn user_exists(&self, name: &str) -> ApiResult<bool> {
        match self
            .config(Request::UserExists { name: name.into() })
            .await?
        {
            Event::UserExists(b) => Ok(b),
            other => Err(unexpected("nos-configd", &other)),
        }
    }

    async fn names(&self, req: Request) -> ApiResult<Vec<String>> {
        match self.config(req).await? {
            Event::InstanceNames(n) => Ok(n),
            other => Err(unexpected("nos-configd", &other)),
        }
    }

    /// Names of the running config's BGP instances (#759).
    pub async fn bgp_instance_names(&self) -> ApiResult<Vec<String>> {
        self.names(Request::ListBgpInstances).await
    }

    /// Names of the running config's OSPF instances (#759).
    pub async fn ospf_instance_names(&self) -> ApiResult<Vec<String>> {
        self.names(Request::ListOspfInstances).await
    }

    /// Names of the running config's `OSPFv3` instances (#759).
    pub async fn ospfv3_instance_names(&self) -> ApiResult<Vec<String>> {
        self.names(Request::ListOspfv3Instances).await
    }

    /// `rest_api` pinned to routing table `table` (#759, #758).
    pub async fn rest_api(&self, table: &str) -> ApiResult<Option<nos_proto::RestApi>> {
        match self
            .config(Request::GetRestApi {
                table: table.into(),
            })
            .await?
        {
            Event::RestApi(r) => Ok(r),
            other => Err(unexpected("nos-configd", &other)),
        }
    }

    /// One request to `nos-watchdogd`'s broker.
    pub async fn broker(&self, req: WatchdogRequest) -> ApiResult<WatchdogEvent> {
        self.call(&self.watchdog_socket, Role::Watchdog, "", req)
            .await
    }
}

pub fn unexpected(daemon: &str, ev: &impl std::fmt::Debug) -> ApiError {
    // Variant name only: a full reply (a `Config`) must not reach nos-logd.
    let dbg = format!("{ev:?}");
    let variant = dbg.split([' ', '(', '{']).next().unwrap_or("");
    ApiError::BadGateway(format!("{daemon} sent an unexpected reply: {variant}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_never_replies_is_a_gateway_timeout_not_a_stale_connection() {
        let (client, _silent_daemon) = tokio::io::duplex(1024);
        let r = exchange_within::<u8, _>(Duration::from_secs(1), client, b"req").await;
        assert!(matches!(r, Exchange::Bad(ApiError::GatewayTimeout(_))));
    }
}
