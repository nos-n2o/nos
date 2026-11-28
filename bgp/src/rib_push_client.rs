//! Pushes this instance's current BGP best-path routes to the owning
//! `nos-ribd` instance for kernel installation, mirroring `nos-rib`'s
//! `bgp_client.rs` (a persistent connection, `Full` snapshot on connect,
//! diffed `Add`/`Remove` afterward) but role-reversed: this side connects
//! out and pushes.
//!
//! Change-driven (#420): it wakes on [`SessionManager::push_changed`] (a
//! generation bumped whenever the shared RIB is mutated), waits
//! [`HOLD_DOWN`] so a burst of UPDATEs becomes one diff, then snapshots and
//! diffs [`SessionManager::bgp_push_snapshot`]. A [`FALLBACK_TICK`] re-diff
//! is the safety net when no change was signalled. The write-only connection
//! is also watched for EOF (like `fdb_push_client`), so a restarted
//! `nos-ribd` gets a fresh `Full` at once instead of at the next route
//! change (#718).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::SinkExt;
use ipnet::IpNet;
use nos_proto::{BgpRoute, BgpRouteUpdate, IpcCodec, RibRequest, Role, ServiceRef};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::FramedWrite;
use tracing::{debug, warn};

use crate::push_conn::{split, PushReader};
use crate::session::SessionManager;
use nos_daemon::watchdog::resolve_once;

/// Safety-net re-diff when no change was signalled.
const FALLBACK_TICK: Duration = Duration::from_secs(10);
/// Coalesces a burst of RIB mutations into one snapshot + diff.
const HOLD_DOWN: Duration = Duration::from_millis(50);
/// Matches every other reconnect/resolve loop in this codebase.
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Spawns the background task that owns the route-push connection for this
/// process's lifetime.
pub fn spawn(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(run(watchdog_socket, sessions, shutdown))
}

async fn run(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    mut shutdown: watch::Receiver<bool>,
) {
    // Subscribed before the first snapshot: a change after it is never lost.
    let mut changed = sessions.push_changed();
    while !*shutdown.borrow() {
        let (table, routes) = sessions.bgp_push_snapshot().await;
        let Some(table) = table else {
            // No owning routing table yet — idle until the RIB changes.
            if wait_change(&mut changed, &mut shutdown, None::<&mut PushReader>).await == Wake::Stop
            {
                break;
            }
            continue;
        };

        let Some(rib_socket) =
            resolve_once(&watchdog_socket, &ServiceRef::RibTable(table.clone())).await
        else {
            debug!(table = %table, "failed to resolve nos-ribd instance via nos-watchdogd, retrying");
            if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                break;
            }
            continue;
        };

        let stream = match nos_pki::connect(&rib_socket, Role::Ribd, &table).await {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    table = %table,
                    socket = %rib_socket.display(),
                    error = %e,
                    "failed to connect to nos-ribd, retrying"
                );
                if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };

        let (write_half, mut reader) = split(stream);
        let mut writer = FramedWrite::new(write_half, IpcCodec::<RibRequest>::default());
        if send(&mut writer, vec![BgpRouteUpdate::Full(to_routes(&routes))])
            .await
            .is_err()
        {
            warn!(table = %table, "failed to send initial bgp route snapshot to nos-ribd, retrying");
            if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                break;
            }
            continue;
        }
        let mut last_sent = routes;
        debug!(table = %table, routes = last_sent.len(), "sent initial bgp route snapshot to nos-ribd");

        // Inner loop: same connection, same owning table, until the table
        // changes to something else (including `None`) or a write fails.
        loop {
            match wait_change(&mut changed, &mut shutdown, Some(&mut reader)).await {
                Wake::Stop => return,
                Wake::Closed => {
                    warn!(table = %table, "nos-ribd closed the push connection, reconnecting");
                    break;
                }
                Wake::Changed => {}
            }
            // A close that raced with the change: don't write into a dead socket.
            if reader.closed() {
                warn!(table = %table, "nos-ribd closed the push connection, reconnecting");
                break;
            }
            let (new_table, new_routes) = sessions.bgp_push_snapshot().await;
            if new_table.as_deref() != Some(table.as_str()) {
                // Withdraw everything from this connection before switching
                // away — best-effort, we're tearing this connection down
                // regardless of the outcome.
                let _ = send(&mut writer, vec![BgpRouteUpdate::Full(Vec::new())]).await;
                break;
            }
            let updates = diff_routes(&last_sent, &new_routes);
            if send(&mut writer, updates).await.is_err() {
                warn!(table = %table, "write failure sending bgp route update, reconnecting");
                break;
            }
            last_sent = new_routes;
        }
        // Reconnect (or idle, if the table is now None) immediately — the
        // outer loop re-reads the current snapshot from scratch.
    }
}

/// Sends one push cut into frames that each fit the codec's `MAX_FRAME`
/// (a full-internet `Full` is ~1M routes, well past it): see
/// `BgpRouteUpdate::frames`. Nothing is sent for an empty push.
async fn send<S>(
    writer: &mut FramedWrite<S, IpcCodec<RibRequest>>,
    updates: Vec<BgpRouteUpdate>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    for frame in BgpRouteUpdate::frames(updates) {
        writer.feed(RibRequest::PushBgpRoutes(frame)).await?;
    }
    writer.flush().await
}

/// Why [`wait_change`] returned.
#[derive(Debug, PartialEq, Eq)]
enum Wake {
    Changed,
    /// The consumer closed the connection.
    Closed,
    Stop,
}

/// Waits for a RIB change (plus [`HOLD_DOWN`]), [`FALLBACK_TICK`], or the
/// consumer closing `reader`, whichever is first.
async fn wait_change<S: tokio::io::AsyncRead + Unpin>(
    changed: &mut watch::Receiver<u64>,
    shutdown: &mut watch::Receiver<bool>,
    reader: Option<&mut PushReader<S>>,
) -> Wake {
    let eof = async {
        match reader {
            Some(r) => r.eof().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        r = changed.changed() => {
            if r.is_ok() {
                tokio::time::sleep(HOLD_DOWN).await;
                // Everything up to here is covered by the snapshot taken next.
                changed.borrow_and_update();
            } else {
                tokio::time::sleep(FALLBACK_TICK).await;
            }
            Wake::Changed
        }
        () = tokio::time::sleep(FALLBACK_TICK) => Wake::Changed,
        () = eof => Wake::Closed,
        _ = shutdown.changed() => if *shutdown.borrow() { Wake::Stop } else { Wake::Changed },
    }
}

/// Waits out `delay`, interruptible by `shutdown` firing. Returns `true` if
/// the caller should stop entirely.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

fn to_route(
    prefix: IpNet,
    (next_hops, backup_next_hop, discard, metric): &crate::rib::Hops,
) -> BgpRoute {
    BgpRoute {
        ibgp: false,
        prefix,
        next_hops: next_hops.clone(),
        backup_next_hop: *backup_next_hop,
        discard: *discard,
        metric: *metric,
    }
}

fn to_routes(routes: &HashMap<IpNet, crate::rib::Hops>) -> Vec<BgpRoute> {
    routes
        .iter()
        .map(|(&prefix, hops)| to_route(prefix, hops))
        .collect()
}

/// Computes the minimal `BgpRouteUpdate`s needed to bring `last_sent` (what
/// the connection was last told) up to `new_routes`: an `Add` for every
/// prefix that's new or whose next-hop set or backup changed, a `Remove` for
/// every prefix `last_sent` had that `new_routes` no longer does. Pure and
/// unit-tested directly — the surrounding connection/reconnect machinery
/// isn't.
fn diff_routes(
    last_sent: &HashMap<IpNet, crate::rib::Hops>,
    new_routes: &HashMap<IpNet, crate::rib::Hops>,
) -> Vec<BgpRouteUpdate> {
    let mut updates = Vec::new();
    for (&prefix, hops) in new_routes {
        if last_sent.get(&prefix) != Some(hops) {
            updates.push(BgpRouteUpdate::Add(to_route(prefix, hops)));
        }
    }
    for prefix in last_sent.keys() {
        if !new_routes.contains_key(prefix) {
            updates.push(BgpRouteUpdate::Remove(*prefix));
        }
    }
    updates
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn routes(pairs: &[(&str, &str)]) -> HashMap<IpNet, crate::rib::Hops> {
        pairs
            .iter()
            .map(|(p, gw)| {
                (
                    p.parse().unwrap(),
                    (vec![gw.parse().unwrap()], None, false, None),
                )
            })
            .collect()
    }

    fn route(prefix: &str, gws: &[&str], backup: Option<&str>) -> BgpRoute {
        BgpRoute {
            ibgp: false,
            prefix: prefix.parse().unwrap(),
            next_hops: gws.iter().map(|g| g.parse().unwrap()).collect(),
            discard: false,
            metric: None,
            backup_next_hop: backup.map(|b| b.parse().unwrap()),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn change_wakes_within_hold_down_not_fallback_tick() {
        let (tx, mut rx) = watch::channel(0u64);
        let (_stx, mut srx) = watch::channel(false);
        let start = tokio::time::Instant::now();
        let waiter =
            tokio::spawn(
                async move { wait_change(&mut rx, &mut srx, None::<&mut PushReader>).await },
            );
        tokio::time::sleep(Duration::from_millis(5)).await;
        tx.send_modify(|g| *g += 1);
        assert_eq!(waiter.await.unwrap(), Wake::Changed);
        assert!(start.elapsed() < FALLBACK_TICK);
        assert!(start.elapsed() >= HOLD_DOWN);
    }

    #[tokio::test(start_paused = true)]
    async fn quiet_rib_wakes_on_fallback_tick() {
        let (_tx, mut rx) = watch::channel(0u64);
        let (_stx, mut srx) = watch::channel(false);
        let start = tokio::time::Instant::now();
        assert_eq!(
            wait_change(&mut rx, &mut srx, None::<&mut PushReader>).await,
            Wake::Changed
        );
        assert_eq!(start.elapsed(), FALLBACK_TICK);
    }

    #[tokio::test(start_paused = true)]
    async fn peer_close_wakes_immediately() {
        let (_tx, mut rx) = watch::channel(0u64);
        let (_stx, mut srx) = watch::channel(false);
        let (a, b) = tokio::io::duplex(64);
        let (_w, mut reader) = split(a);
        drop(b);
        let start = tokio::time::Instant::now();
        assert_eq!(
            wait_change(&mut rx, &mut srx, Some(&mut reader)).await,
            Wake::Closed
        );
        assert!(start.elapsed() < FALLBACK_TICK);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_stops() {
        let (_tx, mut rx) = watch::channel(0u64);
        let (stx, mut srx) = watch::channel(false);
        stx.send(true).unwrap();
        assert_eq!(
            wait_change(&mut rx, &mut srx, None::<&mut PushReader>).await,
            Wake::Stop
        );
    }

    #[test]
    fn diff_empty_to_empty_is_empty() {
        assert_eq!(diff_routes(&HashMap::new(), &HashMap::new()), []);
    }

    #[test]
    fn diff_unchanged_prefix_is_noop() {
        let r = routes(&[("10.0.0.0/24", "10.0.0.1")]);
        assert_eq!(diff_routes(&r, &r), []);
    }

    #[test]
    fn diff_changed_next_hop_is_add() {
        let last_sent = routes(&[("10.0.0.0/24", "10.0.0.1")]);
        let new_routes = routes(&[("10.0.0.0/24", "10.0.0.2")]);
        assert_eq!(
            diff_routes(&last_sent, &new_routes),
            vec![BgpRouteUpdate::Add(route(
                "10.0.0.0/24",
                &["10.0.0.2"],
                None
            ))]
        );
    }

    #[test]
    fn diff_removed_prefix_is_remove() {
        let last_sent = routes(&[("10.0.0.0/24", "10.0.0.1")]);
        assert_eq!(
            diff_routes(&last_sent, &HashMap::new()),
            vec![BgpRouteUpdate::Remove("10.0.0.0/24".parse().unwrap())]
        );
    }

    #[test]
    fn diff_mixed_add_and_remove() {
        let last_sent = routes(&[("10.0.0.0/24", "10.0.0.1"), ("10.0.1.0/24", "10.0.1.1")]);
        let new_routes = routes(&[("10.0.0.0/24", "10.0.0.1"), ("10.0.2.0/24", "10.0.2.1")]);
        let mut updates = diff_routes(&last_sent, &new_routes);
        updates.sort_by_key(|u| format!("{u:?}"));
        let mut expected = vec![
            BgpRouteUpdate::Add(route("10.0.2.0/24", &["10.0.2.1"], None)),
            BgpRouteUpdate::Remove("10.0.1.0/24".parse().unwrap()),
        ];
        expected.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(updates, expected);
    }

    /// RFC 7999: a route flipping to a blackhole is re-pushed as a discard.
    #[test]
    fn diff_blackhole_flip_is_add_with_discard() {
        let gw: IpAddr = "10.0.0.1".parse().unwrap();
        let p: IpNet = "10.0.0.1/32".parse().unwrap();
        let last_sent = HashMap::from([(p, (vec![gw], None, false, None))]);
        let new_routes = HashMap::from([(p, (vec![], None, true, None))]);
        let want = BgpRoute {
            ibgp: false,
            prefix: p,
            next_hops: vec![],
            backup_next_hop: None,
            discard: true,
            metric: None,
        };
        assert_eq!(
            diff_routes(&last_sent, &new_routes),
            vec![BgpRouteUpdate::Add(want)]
        );
    }

    #[test]
    fn diff_backup_only_change_is_add() {
        let gw: IpAddr = "10.0.0.1".parse().unwrap();
        let bk: IpAddr = "10.0.9.9".parse().unwrap();
        let p: IpNet = "10.0.0.0/24".parse().unwrap();
        let last_sent = HashMap::from([(p, (vec![gw], None, false, None))]);
        let new_routes = HashMap::from([(p, (vec![gw], Some(bk), false, None))]);
        assert_eq!(
            diff_routes(&last_sent, &new_routes),
            vec![BgpRouteUpdate::Add(route(
                "10.0.0.0/24",
                &["10.0.0.1"],
                Some("10.0.9.9")
            ))]
        );
    }

    #[test]
    fn diff_multipath_set_only_change_is_add() {
        let gw: IpAddr = "10.0.0.1".parse().unwrap();
        let gw2: IpAddr = "10.0.0.2".parse().unwrap();
        let p: IpNet = "10.0.0.0/24".parse().unwrap();
        let last_sent = HashMap::from([(p, (vec![gw], None, false, None))]);
        let new_routes = HashMap::from([(p, (vec![gw, gw2], None, false, None))]);
        assert_eq!(
            diff_routes(&last_sent, &new_routes),
            vec![BgpRouteUpdate::Add(route(
                "10.0.0.0/24",
                &["10.0.0.1", "10.0.0.2"],
                None
            ))]
        );
    }
}
