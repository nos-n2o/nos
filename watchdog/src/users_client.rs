use std::io;
use std::path::Path;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, PeerId, Stream};
use nos_proto::{Config, DiffScope, Event, IpcCodec, Request, Role, User};
use tokio::io::{split, ReadHalf};
use tokio_util::codec::{FramedRead, FramedWrite};

type Reader = FramedRead<ReadHalf<Stream>, IpcCodec<Event>>;

/// A dead `nos-configd` must fail a login, not hang it.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

fn configd() -> PeerId {
    PeerId::new(Role::Configd.as_str(), "")
}

/// Dials `nos-configd`, sends `Request::SubscribeDiff { scopes }`, and
/// returns the reader half for the caller to loop on indefinitely: an
/// initial diff (synthesized against an empty config, so every
/// currently-configured item in `scopes` shows up as `Added`), then one more
/// `Event::Diff` per future commit that touches a requested scope.
///
/// Mirrors `nos-cli`'s `client::subscribe`, but deliberately not shared with
/// it — `nos-watchdog` must not depend on `nos-cli`, a consumer binary, not
/// a shared library.
pub async fn subscribe_diff(
    identity: &Identity,
    socket_path: &Path,
    scopes: Vec<DiffScope>,
) -> io::Result<Reader> {
    let stream = identity.connect(socket_path, &configd()).await?;
    let (r, w) = split(stream);
    let reader = FramedRead::new(r, IpcCodec::<Event>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
    writer.send(Request::SubscribeDiff { scopes }).await?;
    Ok(reader)
}

/// The locally configured users, hashes included — what a login is checked
/// against. The hashes never leave the watchdog: a client only ever sends a
/// password and gets back a certificate.
pub async fn fetch_users(identity: &Identity, socket_path: &Path) -> io::Result<Vec<User>> {
    Ok(fetch_config(identity, socket_path).await?.users)
}

/// The running config, fetched once.
pub async fn fetch_config(identity: &Identity, socket_path: &Path) -> io::Result<Config> {
    let fetch = async {
        let stream = identity.connect(socket_path, &configd()).await?;
        let (r, w) = split(stream);
        let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
        let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
        writer.send(Request::Get).await?;
        match reader.next().await {
            Some(Ok(Event::Config(config))) => Ok(config),
            Some(Ok(other)) => Err(io::Error::other(format!(
                "unexpected reply to Get: {other:?}"
            ))),
            Some(Err(e)) => Err(e),
            None => Err(io::ErrorKind::UnexpectedEof.into()),
        }
    };
    tokio::time::timeout(FETCH_TIMEOUT, fetch)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "nos-configd did not answer"))?
}

/// Keeps `max_failures` on the running `login_policy` (#1148), forever: applied
/// at start and after each commit touching it. Until `nos-configd` is
/// reachable (it starts after the watchdog) the defaults stand, as they do
/// when the connection drops.
pub async fn follow_login_policy(
    identity: Identity,
    socket_path: std::path::PathBuf,
    max_failures: std::sync::Arc<std::sync::atomic::AtomicU8>,
) {
    let mut warned = false;
    loop {
        match subscribe_diff(&identity, &socket_path, vec![DiffScope::LoginPolicy]).await {
            Ok(mut events) => {
                warned = false;
                while events.next().await.is_some_and(|e| e.is_ok()) {
                    if let Ok(cfg) = fetch_config(&identity, &socket_path).await {
                        let p = cfg.login_policy;
                        max_failures.store(p.max_failures, std::sync::atomic::Ordering::Relaxed);
                        tracing::info!(
                            max_failures = p.max_failures,
                            "broker login policy applied"
                        );
                    }
                }
            }
            Err(e) if !warned => {
                warned = true;
                tracing::info!(error = %e, "nos-configd not reachable, using the default login policy");
            }
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Asks `nos-configd` to swap `user`'s hash `old` for `new` (see
/// `Request::UpgradePasswordHash`).
pub async fn upgrade_password_hash(
    identity: &Identity,
    socket_path: &Path,
    user: &str,
    old: &str,
    new: String,
) -> io::Result<()> {
    let call = async {
        let stream = identity.connect(socket_path, &configd()).await?;
        let (r, w) = split(stream);
        let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
        let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
        writer
            .send(Request::UpgradePasswordHash {
                user: user.to_string(),
                old: old.to_string(),
                new,
            })
            .await?;
        match reader.next().await {
            Some(Ok(Event::Committed { .. })) => Ok(()),
            Some(Ok(other)) => Err(io::Error::other(format!("{other:?}"))),
            Some(Err(e)) => Err(e),
            None => Err(io::ErrorKind::UnexpectedEof.into()),
        }
    };
    tokio::time::timeout(FETCH_TIMEOUT, call)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "nos-configd did not answer"))?
}

/// One request to `nos-configd` and its single reply.
async fn call(identity: &Identity, socket_path: &Path, req: Request) -> io::Result<Event> {
    let call = async {
        let stream = identity.connect(socket_path, &configd()).await?;
        let (r, w) = split(stream);
        let mut writer = FramedWrite::new(w, IpcCodec::<Request>::default());
        let mut reader = FramedRead::new(r, IpcCodec::<Event>::default());
        writer.send(req).await?;
        match reader.next().await {
            Some(Ok(Event::Error(e))) => Err(io::Error::other(e)),
            Some(Ok(ev)) => Ok(ev),
            Some(Err(e)) => Err(e),
            None => Err(io::ErrorKind::UnexpectedEof.into()),
        }
    };
    tokio::time::timeout(FETCH_TIMEOUT, call)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "nos-configd did not answer"))?
}

/// Asks `nos-configd` for a persistent uid for the RADIUS-accepted `name`
/// (`Request::AllocateExternalUser`, idempotent).
pub async fn allocate_external_user(
    identity: &Identity,
    socket_path: &Path,
    name: &str,
) -> io::Result<u32> {
    let req = Request::AllocateExternalUser {
        name: name.to_string(),
    };
    match call(identity, socket_path, req).await? {
        Event::ExternalUser { uid } => Ok(uid),
        other => Err(io::Error::other(format!("{other:?}"))),
    }
}

/// The names `nos-configd` currently serves as external users.
pub async fn external_users(identity: &Identity, socket_path: &Path) -> io::Result<Vec<String>> {
    match call(identity, socket_path, Request::ListExternalUsers).await? {
        Event::ExternalUsers(l) => Ok(l.into_iter().map(|(n, _)| n).collect()),
        other => Err(io::Error::other(format!("{other:?}"))),
    }
}
