use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{IpcCodec, LogEvent, LogRequest, Role};
use tokio::io::{split, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, trace, warn};

use crate::store::LogStore;

/// Binds `listen_socket` and spawns the IPC accept loop.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    store: LogStore,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(socket = %listen_socket.display(), "log IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, store)))
}

/// Every daemon pushes its own logs; only people (and `Restd` on their
/// behalf) read them back. No wildcard arm: a new request must be classified.
fn allowed(role: Role, req: &LogRequest) -> bool {
    match req {
        LogRequest::Push(_) => role.is_daemon(),
        LogRequest::GetLogs { .. } | LogRequest::Tail { .. } => {
            matches!(role, Role::User | Role::Restd)
        }
    }
}

async fn accept_loop(listener: Listener, store: LogStore) {
    loop {
        let incoming = listener.accept_resilient().await;
        tokio::spawn(serve(incoming, store.clone()));
    }
}

/// Handles one connection for its whole lifetime. `Push` (sent continuously
/// by every other component process) gets no reply, so the loop just keeps
/// reading further requests on the same connection; `GetLogs` sends one
/// reply and the connection typically closes right after (the client's
/// choice, not enforced here); `Tail` sends one reply then switches into
/// streaming new entries from the store's broadcast channel until the
/// client's read side reports an error/EOF or a write to it fails.
async fn serve(incoming: Incoming, store: LogStore) {
    let (stream, peer) = match incoming.handshake().await {
        Ok(ok) => ok,
        Err(e) => {
            debug!(error = %e, "log IPC tls handshake failed");
            return;
        }
    };
    let Some((role, name)) = peer.and_then(|p| Some((Role::parse(&p.role)?, p.name))) else {
        warn!("log IPC peer's certificate carries no recognised role, dropping it");
        return;
    };
    handle_connection(stream, role, name, store).await;
}

/// `nos-<daemon>` plus `[<name>]` when the certificate carries a name: the
/// shape every daemon already uses (`nos-bgpd[r1]`, `nos-interfaced`).
fn stamped_source(role: Role, name: &str) -> String {
    let role = role.as_str();
    let d = if role.ends_with('d') { "" } else { "d" };
    if name.is_empty() {
        format!("nos-{role}{d}")
    } else {
        format!("nos-{role}{d}[{name}]")
    }
}

async fn handle_connection(stream: Stream, role: Role, name: String, store: LogStore) {
    let (read_half, write_half) = split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<LogRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<LogEvent>::default());

    while let Some(msg) = reader.next().await {
        let req = match msg {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "log IPC read error");
                break;
            }
        };
        if !allowed(role, &req) {
            warn!(role = role.as_str(), name = %name, "log request refused: this role may not send it");
            break;
        }
        match req {
            LogRequest::Push(mut entry) => {
                // The source is who the certificate says, never what the
                // sender wrote: a daemon can't pass itself off as another.
                entry.source = stamped_source(role, &name);
                store.record(entry).await;
            }
            LogRequest::GetLogs { source, limit } => {
                let logs = store.snapshot(source.as_deref(), limit).await;
                trace!(source = ?source, limit = ?limit, count = logs.len(), "served GetLogs query");
                if writer.send(LogEvent::Logs(logs)).await.is_err() {
                    break;
                }
            }
            LogRequest::Tail { source } => {
                let logs = store.snapshot(source.as_deref(), None).await;
                if writer.send(LogEvent::Logs(logs)).await.is_err() {
                    break;
                }
                debug!(source = ?source, "log tail subscription started");
                let result = tail(&mut reader, &mut writer, &store, source.as_deref()).await;
                debug!("log tail subscription ended");
                if !result {
                    break;
                }
            }
        }
    }
}

/// Streams new matching entries to `writer` until the client disconnects
/// (a read error/EOF on `reader`, or a failed write). Returns `false` when
/// the connection should be torn down.
async fn tail(
    reader: &mut FramedRead<ReadHalf<Stream>, IpcCodec<LogRequest>>,
    writer: &mut FramedWrite<WriteHalf<Stream>, IpcCodec<LogEvent>>,
    store: &LogStore,
    source: Option<&str>,
) -> bool {
    let mut rx = store.subscribe();
    loop {
        tokio::select! {
            entry = rx.recv() => match entry {
                Ok(entry) => {
                    if source.is_some_and(|s| entry.source != s) {
                        continue;
                    }
                    if writer.send(LogEvent::Line(entry)).await.is_err() {
                        return false;
                    }
                }
                // A slow subscriber that fell behind the broadcast channel's
                // capacity — resubscribing loses only the gap, not the
                // connection; a truly closed channel never happens while
                // `store` (and thus its `tail_tx`) is still alive.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "log tail subscriber lagged, entries dropped");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return false,
            },
            // Per this codebase's connection-lifecycle convention (see root
            // `docs/architecture/endpoint-broker.md`/`SubscribeDiff` notes), a
            // subscriber is only expected to send its request and never
            // write again — so any activity here at all (EOF, a read error,
            // or even an unexpected extra request) means it's time to tear
            // the connection down rather than keep tailing.
            _ = reader.next() => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_pki::PeerId;
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[test]
    fn source_comes_from_the_certificate() {
        assert_eq!(stamped_source(Role::Bgpd, "r1"), "nos-bgpd[r1]");
        assert_eq!(stamped_source(Role::Interfaced, ""), "nos-interfaced");
        assert_eq!(stamped_source(Role::Watchdog, ""), "nos-watchdogd");
    }

    #[test]
    fn daemons_push_and_people_read() {
        let push = LogRequest::Push(nos_proto::LogEntry {
            timestamp_ms: 0,
            level: nos_proto::LogLevel::Info,
            source: String::new(),
            target: String::new(),
            message: String::new(),
            fields: Vec::new(),
        });
        let get = LogRequest::GetLogs {
            source: None,
            limit: None,
        };
        for role in Role::ALL {
            assert_eq!(allowed(role, &push), role != Role::User, "{role:?} push");
            assert_eq!(
                allowed(role, &get),
                matches!(role, Role::User | Role::Restd),
                "{role:?} read"
            );
        }
    }

    type Reader = FramedRead<ReadHalf<Stream>, IpcCodec<LogEvent>>;
    type Writer = FramedWrite<WriteHalf<Stream>, IpcCodec<LogRequest>>;

    fn entry(message: &str) -> nos_proto::LogEntry {
        nos_proto::LogEntry {
            timestamp_ms: 1,
            level: nos_proto::LogLevel::Info,
            source: "bgpd".into(),
            target: String::new(),
            message: message.into(),
            fields: Vec::new(),
        }
    }

    async fn connect(path: &Path, role: &str) -> (Reader, Writer) {
        let id = nos_pki::testing::shared().identity(role, "x");
        let s = id.connect(path, &PeerId::new("logd", "")).await.unwrap();
        let (r, w) = split(s);
        (
            FramedRead::new(r, IpcCodec::default()),
            FramedWrite::new(w, IpcCodec::default()),
        )
    }

    async fn next(r: &mut Reader) -> Option<LogEvent> {
        tokio::time::timeout(Duration::from_secs(5), r.next())
            .await
            .expect("connection left open")
            .map(|e| e.unwrap())
    }

    /// Returns the store, plus the persistence receiver (kept alive so
    /// `record` never sees a closed channel) and the server handle.
    fn server(
        path: &Path,
    ) -> (
        LogStore,
        mpsc::UnboundedReceiver<nos_proto::LogEntry>,
        JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        let store = LogStore::new(100, vec![], tx);
        let id = nos_pki::testing::shared().identity("logd", "");
        let h = start(path, store.clone(), &id).unwrap();
        (store, rx, h)
    }

    #[tokio::test]
    async fn push_is_for_daemons_only() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("log.sock");
        let (store, _rx, _h) = server(&path);

        // `user` may not push: closed, nothing stored.
        let (mut r, mut w) = connect(&path, "user").await;
        w.send(LogRequest::Push(entry("from user"))).await.unwrap();
        assert!(next(&mut r).await.is_none());
        assert_eq!(store.snapshot(None, None).await.len(), 0);

        // A daemon's push is stored, with no reply frame.
        let (_r, mut w) = connect(&path, "bgpd").await;
        w.send(LogRequest::Push(entry("from bgpd"))).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while store.snapshot(None, None).await.len() != 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("bgpd push stored");
    }

    #[tokio::test]
    async fn reads_are_for_people_only() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("log.sock");
        let (store, _rx, _h) = server(&path);
        store.record(entry("seeded")).await;

        for role in Role::ALL {
            let (mut r, mut w) = connect(&path, role.as_str()).await;
            w.send(LogRequest::GetLogs {
                source: None,
                limit: None,
            })
            .await
            .unwrap();
            let reply = next(&mut r).await;
            if matches!(role, Role::User | Role::Restd) {
                let Some(LogEvent::Logs(l)) = reply else {
                    panic!("{role:?}: no logs");
                };
                assert_eq!(l.len(), 1, "{role:?}");
                assert_eq!(l[0].message, "seeded");
            } else {
                assert!(reply.is_none(), "{role:?} must be closed");
            }
        }
    }

    #[tokio::test]
    async fn tail_is_for_people_only() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("log.sock");
        let (store, _rx, _h) = server(&path);
        store.record(entry("old")).await;

        let (mut r, mut w) = connect(&path, "bgpd").await;
        w.send(LogRequest::Tail { source: None }).await.unwrap();
        assert!(next(&mut r).await.is_none(), "daemon tail must be closed");

        for role in ["user", "restd"] {
            let (mut r, mut w) = connect(&path, role).await;
            w.send(LogRequest::Tail { source: None }).await.unwrap();
            let Some(LogEvent::Logs(l)) = next(&mut r).await else {
                panic!("{role}: no backlog");
            };
            assert!(l.iter().any(|e| e.message == "old"), "{role}: backlog");
            // `Tail` subscribes after the backlog is sent, so keep recording
            // until a live line shows.
            let mut got = None;
            for i in 0..50 {
                store.record(entry(&format!("live {i}"))).await;
                if let Ok(Some(Ok(LogEvent::Line(e)))) =
                    tokio::time::timeout(Duration::from_millis(100), r.next()).await
                {
                    got = Some(e);
                    break;
                }
            }
            assert!(got.is_some(), "{role}: no live line");
        }
    }

    #[tokio::test]
    async fn unrecognised_certificate_role_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("log.sock");
        let (store, _rx, _h) = server(&path);
        let (mut r, mut w) = connect(&path, "martian").await;
        // The server may drop it before the write lands; either way no reply.
        let _ = w.send(LogRequest::Push(entry("x"))).await;
        assert!(next(&mut r).await.is_none());
        assert_eq!(store.snapshot(None, None).await.len(), 0);
    }
}
