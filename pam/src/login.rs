use std::path::Path;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, PeerId};
use nos_proto::{ticket_to_env, IpcCodec, WatchdogEvent, WatchdogRequest, INVALID_CREDENTIALS};
use tokio::io::split;
use tokio_util::codec::{FramedRead, FramedWrite};
use zeroize::Zeroizing;

use crate::session::NosTicket;

/// Why the broker did not issue a ticket. Fail closed: no cache, no retry.
#[derive(Debug, PartialEq, Eq)]
pub enum LoginError {
    /// The broker said `INVALID_CREDENTIALS`: a wrong user or password.
    Denied,
    /// Anything else: broker absent, busy, TLS/CA mismatch, hang-up, timeout,
    /// unreadable `ca.crt`, an unexpected reply.
    Unavailable,
}

/// Trades `password` for a single-use login ticket (`LoginTicket`, #990): the
/// one password check. One identity per call, never `nos_pki::install`/`connect`
/// (their process-global identity would keep a stale CA for the life of sshd's
/// monitor after the watchdog re-keys). `timeout` bounds the whole exchange:
/// dial, TLS handshake, request and reply.
pub fn login(
    socket: &Path,
    ca: &Path,
    user: &str,
    password: &str,
    timeout: Duration,
) -> Result<NosTicket, LoginError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| LoginError::Unavailable)?;
    runtime.block_on(async {
        tokio::time::timeout(timeout, exchange(socket, ca, user, password))
            .await
            .unwrap_or(Err(LoginError::Unavailable))
    })
}

async fn exchange(
    socket: &Path,
    ca: &Path,
    user: &str,
    password: &str,
) -> Result<NosTicket, LoginError> {
    let unavailable = |_| LoginError::Unavailable;
    let identity = std::fs::read(ca)
        .and_then(|pem| Identity::anonymous_from_pem(&pem))
        .map_err(unavailable)?;
    let stream = identity
        .connect(socket, &PeerId::new("watchdog", ""))
        .await
        .map_err(unavailable)?;
    let (r, w) = split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<WatchdogEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogRequest>::default());
    // ponytail: the codec's copy of the password is a plain String, freed but
    // not zeroed; fixing it means a zeroizing field in `nos-proto`'s wire type.
    writer
        .send(WatchdogRequest::LoginTicket {
            user: user.to_string(),
            password: password.to_string(),
        })
        .await
        .map_err(unavailable)?;
    match reader.next().await {
        Some(Ok(WatchdogEvent::Ticket { ticket, .. })) => {
            let ticket = Zeroizing::new(ticket);
            Ok(NosTicket {
                user: user.to_string(),
                encoded: Zeroizing::new(ticket_to_env(&ticket)),
            })
        }
        Some(Ok(WatchdogEvent::Denied(m))) if m == INVALID_CREDENTIALS => Err(LoginError::Denied),
        _ => Err(LoginError::Unavailable),
    }
}
