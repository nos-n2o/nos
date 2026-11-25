//! Per-commit and per-command AAA accounting (#1153, #1155). `nos-configd` holds no RADIUS secret,
//! so each commit is handed to `nos-watchdogd` (`WatchdogRequest::AccountCommit`),
//! which sends it when `aaa accounting` is on. The hand-over goes through a
//! bounded queue: a full queue (the watchdog slow or down) drops the record
//! and never delays a commit.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use nos_proto::{Role, WatchdogEvent, WatchdogRequest};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Commits waiting to be handed over.
const QUEUE: usize = 256;
/// Bound on one hand-over.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

type Entry = WatchdogRequest;

static TX: OnceLock<mpsc::Sender<Entry>> = OnceLock::new();

/// Starts the hand-over worker (once per process, inside the runtime).
pub fn start(watchdog_socket: PathBuf) {
    let (tx, rx) = mpsc::channel(QUEUE);
    if TX.set(tx).is_ok() {
        tokio::spawn(run(rx, watchdog_socket));
    }
}

/// Queues one commit; a no-op until [`start`] ran, drops when the queue is full.
pub fn record(actor: &str, transaction: &str) {
    offer(WatchdogRequest::AccountCommit {
        actor: actor.to_string(),
        transaction: transaction.to_string(),
    });
}

/// Queues one show/ops command (#1155), like [`record`].
pub fn record_command(actor: &str, command: &str) {
    offer(WatchdogRequest::AccountCommand {
        actor: actor.to_string(),
        command: command.to_string(),
    });
}

fn offer(entry: Entry) {
    if let Some(tx) = TX.get() {
        offer_to(tx, entry);
    }
}

fn offer_to(tx: &mpsc::Sender<Entry>, entry: Entry) {
    if tx.try_send(entry).is_err() {
        warn!("accounting queue full, dropping a record");
    }
}

async fn run(mut rx: mpsc::Receiver<Entry>, socket: PathBuf) {
    while let Some(request) = rx.recv().await {
        let sent = tokio::time::timeout(
            SEND_TIMEOUT,
            nos_daemon::ipc::request::<_, WatchdogEvent>(&socket, Role::Watchdog, request),
        )
        .await;
        if !matches!(sent, Ok(Ok(WatchdogEvent::Ok))) {
            debug!("commit accounting record not delivered to the watchdog");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use nos_proto::IpcCodec;
    use tokio_util::codec::{FramedRead, FramedWrite};

    #[test]
    fn a_full_queue_drops_and_record_before_start_is_a_no_op() {
        record("a", "t");
        record_command("a", "show version");
        let (tx, mut rx) = mpsc::channel(1);
        let commit = |t: &str| WatchdogRequest::AccountCommit {
            actor: "a".into(),
            transaction: t.into(),
        };
        offer_to(&tx, commit("t1"));
        offer_to(&tx, commit("t2"));
        assert!(
            matches!(rx.try_recv().unwrap(), WatchdogRequest::AccountCommit { transaction, .. } if transaction == "t1")
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn the_worker_hands_each_commit_to_the_watchdog() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("w.sock");
        let l = nos_pki::testing::shared()
            .identity("watchdog", "")
            .listen(&sock)
            .unwrap();
        let (got_tx, mut got) = mpsc::channel(4);
        tokio::spawn(async move {
            loop {
                let (stream, _) = l.accept().await.unwrap().handshake().await.unwrap();
                let (r, w) = tokio::io::split(stream);
                let mut reader = FramedRead::new(r, IpcCodec::<WatchdogRequest>::default());
                let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogEvent>::default());
                let Some(Ok(req)) = reader.next().await else {
                    continue;
                };
                let got = match req {
                    WatchdogRequest::AccountCommit { actor, transaction } => (actor, transaction),
                    WatchdogRequest::AccountCommand { actor, command } => (actor, command),
                    _ => continue,
                };
                got_tx.send(got).await.unwrap();
                let _ = writer.send(WatchdogEvent::Ok).await;
            }
        });
        let (tx, rx) = mpsc::channel(QUEUE);
        tokio::spawn(run(rx, sock));
        offer_to(
            &tx,
            WatchdogRequest::AccountCommit {
                actor: "alice".into(),
                transaction: "tx1".into(),
            },
        );
        assert_eq!(got.recv().await.unwrap(), ("alice".into(), "tx1".into()));
        offer_to(
            &tx,
            WatchdogRequest::AccountCommand {
                actor: "alice".into(),
                command: "show version".into(),
            },
        );
        assert_eq!(
            got.recv().await.unwrap(),
            ("alice".into(), "show version".into())
        );
    }
}
