//! Per-commit RADIUS accounting (#1153). `nos-configd` holds no RADIUS secret,
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

type Entry = (String, String);

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
    if let Some(tx) = TX.get() {
        offer(tx, actor, transaction);
    }
}

fn offer(tx: &mpsc::Sender<Entry>, actor: &str, transaction: &str) {
    if tx
        .try_send((actor.to_string(), transaction.to_string()))
        .is_err()
    {
        warn!("commit accounting queue full, dropping a record");
    }
}

async fn run(mut rx: mpsc::Receiver<Entry>, socket: PathBuf) {
    while let Some((actor, transaction)) = rx.recv().await {
        let sent = tokio::time::timeout(
            SEND_TIMEOUT,
            nos_daemon::ipc::request::<_, WatchdogEvent>(
                &socket,
                Role::Watchdog,
                WatchdogRequest::AccountCommit { actor, transaction },
            ),
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
        let (tx, mut rx) = mpsc::channel(1);
        offer(&tx, "a", "t1");
        offer(&tx, "a", "t2");
        assert_eq!(rx.try_recv().unwrap().1, "t1");
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
                if let Some(Ok(WatchdogRequest::AccountCommit { actor, transaction })) =
                    reader.next().await
                {
                    got_tx.send((actor, transaction)).await.unwrap();
                    let _ = writer.send(WatchdogEvent::Ok).await;
                }
            }
        });
        let (tx, rx) = mpsc::channel(QUEUE);
        tokio::spawn(run(rx, sock));
        offer(&tx, "alice", "tx1");
        assert_eq!(got.recv().await.unwrap(), ("alice".into(), "tx1".into()));
    }
}
