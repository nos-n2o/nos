//! Liveness heartbeat (#1150). `nos-watchdogd` restarts a supervised daemon
//! whose beats stop (`watchdog/src/heartbeat.rs`).
//!
//! A task on the daemon's own runtime bumps a counter every second; a
//! dedicated std thread (so a deadlocked or starved runtime cannot silence the
//! check by itself) reads it every [`BEAT_EVERY`] and sends one
//! `WatchdogRequest::Heartbeat` only if it advanced. So the beat proves the
//! runtime still schedules tasks, not merely that the process exists.
//!
//! ponytail: the counter is bumped by one runtime task, not by each daemon's
//! own reconcile loop; a single wedged sub-task is not seen. Add a per-loop
//! bump if one proves to hang alone.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nos_proto::{Role, WatchdogEvent, WatchdogRequest};
use tracing::debug;

/// How often the beat thread looks at the counter.
pub const BEAT_EVERY: Duration = Duration::from_secs(5);

/// Starts the heartbeat for this daemon. Call once, inside the tokio runtime,
/// after the identity is loaded.
pub fn start(watchdog_socket: PathBuf) {
    let progress = Arc::new(AtomicU64::new(0));
    let ticker = progress.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(1));
        loop {
            every.tick().await;
            ticker.fetch_add(1, Ordering::Relaxed);
        }
    });
    spawn_beat(progress, watchdog_socket, BEAT_EVERY);
}

/// The beat thread; it ends once `progress` has no other holder.
fn spawn_beat(progress: Arc<AtomicU64>, socket: PathBuf, every: Duration) {
    let spawned = std::thread::Builder::new()
        .name("nos-heartbeat".into())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            let mut seen = 0;
            while Arc::strong_count(&progress) > 1 {
                std::thread::sleep(every);
                let now = progress.load(Ordering::Relaxed);
                if now != seen {
                    seen = now;
                    rt.block_on(beat(&socket));
                }
            }
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "cannot start the heartbeat thread");
    }
}

/// One beat; best-effort (a missed one is simply a later one), a fresh
/// connection each time.
async fn beat(socket: &Path) {
    let reply = crate::ipc::one_shot::<_, WatchdogEvent>(
        socket,
        Role::Watchdog,
        WatchdogRequest::Heartbeat,
    )
    .await;
    if !matches!(reply, Some(WatchdogEvent::Ok)) {
        debug!("heartbeat not delivered");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use nos_proto::IpcCodec;
    use std::sync::atomic::AtomicUsize;
    use tokio_util::codec::{FramedRead, FramedWrite};

    /// Counts the `Heartbeat`s received, one connection per beat.
    fn listener(sock: &Path) -> Arc<AtomicUsize> {
        let l = nos_pki::testing::shared()
            .identity("watchdog", "")
            .listen(sock)
            .unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let count = n.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = l.accept().await.unwrap().handshake().await.unwrap();
                let (r, w) = tokio::io::split(stream);
                let mut reader = FramedRead::new(r, IpcCodec::<WatchdogRequest>::default());
                let mut writer = FramedWrite::new(w, IpcCodec::<WatchdogEvent>::default());
                if let Some(Ok(WatchdogRequest::Heartbeat)) = reader.next().await {
                    count.fetch_add(1, Ordering::Relaxed);
                    let _ = writer.send(WatchdogEvent::Ok).await;
                }
            }
        });
        n
    }

    #[tokio::test]
    async fn beats_only_while_the_counter_advances() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("w.sock");
        let beats = listener(&sock);
        let progress = Arc::new(AtomicU64::new(0));
        spawn_beat(progress.clone(), sock, Duration::from_millis(100));

        // Stalled: nothing moves, nothing is sent.
        tokio::time::sleep(Duration::from_millis(450)).await;
        assert_eq!(beats.load(Ordering::Relaxed), 0);

        // Alive again: a beat per interval.
        for _ in 0..8 {
            progress.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        assert!(beats.load(Ordering::Relaxed) >= 3);
    }
}
