use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{IpcCodec, Role, ServiceRef, WatchdogEvent, WatchdogRequest};
use thiserror::Error;
use tokio::io::{split, ReadHalf, WriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum WatchdogClientError {
    #[error("could not connect to nos-watchdogd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-watchdogd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-watchdogd: {0}")]
    Io(#[from] std::io::Error),
    /// The watchdog said no: bad credentials, an expired session, …
    #[error("{0}")]
    Denied(String),
    #[error("nos-watchdogd sent an unexpected reply")]
    Unexpected,
}

type Reader = FramedRead<ReadHalf<nos_pki::Stream>, IpcCodec<WatchdogEvent>>;
type Writer = FramedWrite<WriteHalf<nos_pki::Stream>, IpcCodec<WatchdogRequest>>;

async fn open(watchdog_socket: &Path) -> Result<(Reader, Writer), WatchdogClientError> {
    let stream = nos_pki::connect(watchdog_socket, Role::Watchdog, "")
        .await
        .map_err(|source| WatchdogClientError::Connect {
            path: watchdog_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = split(stream);
    Ok((
        FramedRead::new(r, IpcCodec::<WatchdogEvent>::default()),
        FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default()),
    ))
}

async fn ask(
    watchdog_socket: &Path,
    request: WatchdogRequest,
) -> Result<WatchdogEvent, WatchdogClientError> {
    let (mut reader, mut writer) = open(watchdog_socket).await?;
    writer.send(request).await?;
    match reader.next().await {
        Some(Ok(WatchdogEvent::Denied(reason))) => Err(WatchdogClientError::Denied(reason)),
        Some(Ok(event)) => Ok(event),
        Some(Err(e)) => Err(WatchdogClientError::Io(e)),
        None => Err(WatchdogClientError::ConnectionClosed),
    }
}

/// Resolves `service` against `nos-watchdogd`'s broker socket. `Ok(None)`
/// means the broker is reachable but reports the service as not currently
/// available (e.g. the routing table isn't configured, or its `nos-ribd`
/// hasn't finished starting yet) — distinct from `Err`, which means the
/// broker itself couldn't be reached at all.
pub async fn resolve(
    watchdog_socket: &Path,
    service: ServiceRef,
) -> Result<Option<PathBuf>, WatchdogClientError> {
    match ask(
        watchdog_socket,
        WatchdogRequest::ResolveEndpoint { service },
    )
    .await?
    {
        WatchdogEvent::Endpoint(path) => Ok(Some(path)),
        WatchdogEvent::NotAvailable => Ok(None),
        _ => Err(WatchdogClientError::Unexpected),
    }
}

/// A certificate the watchdog issued, and how long it is good for.
#[derive(Debug)]
pub struct Issued {
    pub cert_der: Vec<u8>,
    pub lifetime: Duration,
}

fn issued(event: WatchdogEvent) -> Result<Issued, WatchdogClientError> {
    match event {
        WatchdogEvent::Issued {
            cert_der,
            lifetime_secs,
        } => Ok(Issued {
            cert_der,
            lifetime: Duration::from_secs(lifetime_secs),
        }),
        _ => Err(WatchdogClientError::Unexpected),
    }
}

/// Trades a password for a certificate on the key behind `csr_der`. Works
/// with no certificate yet — it is the one thing the watchdog allows then.
pub async fn login(
    watchdog_socket: &Path,
    user: &str,
    password: &str,
    csr_der: Vec<u8>,
) -> Result<Issued, WatchdogClientError> {
    let request = WatchdogRequest::Login {
        user: user.to_string(),
        password: password.to_string(),
        csr_der,
    };
    issued(ask(watchdog_socket, request).await?)
}

/// Trades a single-use login ticket (from PAM, #990) for a certificate on the
/// key behind `csr_der`. A refused ticket is `Denied`; never logs the ticket.
pub async fn redeem(
    watchdog_socket: &Path,
    ticket: &[u8],
    csr_der: Vec<u8>,
) -> Result<Issued, WatchdogClientError> {
    let request = WatchdogRequest::RedeemTicket {
        ticket: ticket.to_vec(),
        csr_der,
    };
    issued(ask(watchdog_socket, request).await?)
}

/// Trades the current (still valid) certificate for a fresh one — no password.
pub async fn renew(
    watchdog_socket: &Path,
    csr_der: Vec<u8>,
) -> Result<Issued, WatchdogClientError> {
    issued(ask(watchdog_socket, WatchdogRequest::RenewCert { csr_der }).await?)
}
