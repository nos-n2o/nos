//! Forwards this table's redistributable routes to the owning `nos-ospfd`
//! or `nos-ospfv3d` instance over one long-lived connection — the
//! OSPF-redistribution analogue of `bgp_client.rs`, near line-for-line: same
//! single-connection, fixed-delay-reconnect, fire-and-forget-with-no-reply
//! shape (`OspfRequest`/`Ospfv3Request::RedistributeRoutes` get no reply,
//! like `BgpRequest::RedistributeRoutes`). One task per daemon family, told
//! apart by a `Peer` (`OSPFV2`/`OSPFV3`); `bgp_client.rs` stays its own copy
//! (its request shape differs).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use futures::SinkExt;
use ipnet::IpNet;
use nos_proto::{
    IpcCodec, OspfRequest, Ospfv3Request, RedistributeUpdate, RedistributedRoute, Role, ServiceRef,
};
use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use tokio_util::codec::FramedWrite;
use tracing::{debug, warn};

use nos_daemon::watchdog::resolve_once;

/// Fixed retry delay, matching every other reconnect/resolve loop in this
/// crate (`nos_daemon::watchdog`'s retry delay, `reconcile::RECONNECT_DELAY`,
/// `bgp_client::RETRY_DELAY`).
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// What differs between the two OSPF daemon families this client feeds.
pub struct Peer<R> {
    /// How the broker names an instance of it.
    pub service: fn(String) -> ServiceRef,
    /// Its request carrying one update.
    pub wrap: fn(RedistributeUpdate) -> R,
    /// The role its certificate must prove (`nos_pki::connect`).
    pub role: Role,
}

// Manual: the derive would demand `R: Copy`, but only fn pointers are held.
impl<R> Clone for Peer<R> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R> Copy for Peer<R> {}

/// `nos-ospfd` (`redistribute … to ospf`).
pub const OSPFV2: Peer<OspfRequest> = Peer {
    service: ServiceRef::OspfInstance,
    wrap: OspfRequest::RedistributeRoutes,
    role: Role::Ospfd,
};

/// `nos-ospfv3d` (`redistribute … to ospfv3`).
pub const OSPFV3: Peer<Ospfv3Request> = Peer {
    service: ServiceRef::Ospfv3Instance,
    wrap: Ospfv3Request::RedistributeRoutes,
    role: Role::Ospfv3d,
};

/// The desired redistribution state for this table, published by
/// `crate::reconcile::resync` on every resync (diff-triggered or timer
/// alike) regardless of whether anything actually changed — mirrors
/// `bgp_client::RedistributeTarget` exactly, this module is what makes a
/// redundant publish a no-op.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RedistributeTarget {
    /// Which instance (by `OspfInstance`/`Ospfv3Instance` name) this
    /// table's routes should be pushed into. `None` when the table has no
    /// owning instance, or doesn't exist in the running config at all.
    pub instance: Option<String>,
    /// The routes to redistribute — already filtered to whatever rule is
    /// active (e.g. `redistribute from static to ospf`): v4 and v6 alike for
    /// `OSPFv2` (which consumes only the v4 ones — see `ospf::link::
    /// LinkManager::apply_redistribute_update`), v6 only for `OSPFv3`.
    pub routes: Vec<RedistributedRoute>,
}

/// Spawns the background task that owns the redistribution-push connection
/// for this table's lifetime and returns the `watch::Sender` `resync` uses
/// to publish the current desired state. Seeded with an empty target
/// (`instance: None`) — the task starts idle until the first resync. `chunk`
/// is the routes per frame of the initial `Full` (`RedistributeUpdate::split_with`).
pub fn spawn<R: Serialize + Send + 'static>(
    watchdog_socket: PathBuf,
    shutdown: watch::Receiver<bool>,
    peer: Peer<R>,
    chunk: usize,
) -> watch::Sender<RedistributeTarget> {
    let (tx, rx) = watch::channel(RedistributeTarget::default());
    tokio::spawn(run(watchdog_socket, rx, shutdown, peer, chunk));
    tx
}

/// One `run` task per instance named by the published set: the `OSPFv3`
/// feed of a table claiming several instances (and `OSPFv2`'s single one).
/// An instance that leaves the set gets an idle target (the task withdraws
/// its routes) and its sender dropped, which ends the task.
pub fn spawn_set<R: Serialize + Send + 'static>(
    watchdog_socket: PathBuf,
    shutdown: watch::Receiver<bool>,
    peer: Peer<R>,
    chunk: usize,
) -> watch::Sender<Vec<RedistributeTarget>> {
    let (tx, mut rx) = watch::channel(Vec::<RedistributeTarget>::new());
    tokio::spawn(async move {
        let mut feeds: HashMap<String, watch::Sender<RedistributeTarget>> = HashMap::new();
        let mut shutdown_w = shutdown.clone();
        loop {
            let targets = rx.borrow_and_update().clone();
            feeds.retain(|name, feed| {
                let keep = targets.iter().any(|t| t.instance.as_ref() == Some(name));
                if !keep {
                    let _ = feed.send(RedistributeTarget::default());
                }
                keep
            });
            for t in targets {
                let Some(name) = t.instance.clone() else {
                    continue;
                };
                let feed = feeds.entry(name).or_insert_with(|| {
                    spawn(watchdog_socket.clone(), shutdown.clone(), peer, chunk)
                });
                let _ = feed.send(t);
            }
            tokio::select! {
                changed = rx.changed() => if changed.is_err() { return },
                _ = shutdown_w.changed() => return,
            }
        }
    });
    tx
}

/// Owns the connection to this table's `peer` instance for the whole
/// process lifetime. See the module doc comment for the overall shape.
async fn run<R: Serialize>(
    watchdog_socket: PathBuf,
    mut target_rx: watch::Receiver<RedistributeTarget>,
    mut shutdown: watch::Receiver<bool>,
    peer: Peer<R>,
    chunk: usize,
) {
    let daemon = peer.role.as_str();
    while !*shutdown.borrow() {
        let target = target_rx.borrow_and_update().clone();
        let Some(name) = target.instance.clone() else {
            // Nothing to connect to yet — idle until the target changes.
            if wait_idle(&mut target_rx, &mut shutdown).await {
                break;
            }
            continue;
        };

        let Some(ospf_socket) = resolve_once(&watchdog_socket, &(peer.service)(name.clone())).await
        else {
            debug!(daemon, instance = %name, "failed to resolve redistribution target via nos-watchdogd, retrying");
            if wait_retry(RETRY_DELAY, &mut target_rx, &mut shutdown).await {
                break;
            }
            continue;
        };

        let stream = match nos_pki::connect(&ospf_socket, peer.role, &name).await {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    daemon,
                    instance = %name,
                    socket = %ospf_socket.display(),
                    error = %e,
                    "failed to connect to redistribution target, retrying"
                );
                if wait_retry(RETRY_DELAY, &mut target_rx, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };

        // The peer never replies, so a read returning means it went away (a
        // restart): reconnect with a fresh `Full`, like `bgp_client.rs` (#729).
        let (mut reader, write_half) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(write_half, IpcCodec::<R>::default());
        let mut eof_buf = [0u8; 1];

        // Re-read the target once more: it may have changed while we were
        // resolving/connecting. If it no longer names the instance we just
        // connected to, drop this connection unsent and let the outer loop
        // re-evaluate from scratch — nothing was sent on it, so there is
        // nothing to withdraw.
        let current = target_rx.borrow_and_update().clone();
        if current.instance != target.instance {
            continue;
        }

        // A `Full` over `chunk` routes goes as `FullPart`s closed by a `Full`
        // (16 MiB frame cap, #729); `last_sent` moves only once all are out.
        let frames = RedistributeUpdate::Full(current.routes.clone()).split_with(chunk);
        if !nos_proto::chunk::send_all(&mut writer, frames.into_iter().map(peer.wrap)).await {
            warn!(daemon, instance = %name, "failed to send initial redistribution snapshot, retrying");
            if wait_retry(RETRY_DELAY, &mut target_rx, &mut shutdown).await {
                break;
            }
            continue;
        }
        let mut last_sent = build_last_sent(&current.routes);
        debug!(
            daemon,
            instance = %name,
            routes = last_sent.len(),
            "sent initial redistribution snapshot"
        );

        // Inner loop: same connection, same target instance, until the
        // target changes to something else or a write fails.
        loop {
            tokio::select! {
                changed = target_rx.changed() => {
                    if changed.is_err() {
                        // Sender dropped: the process is exiting.
                        return;
                    }
                    let new_target = target_rx.borrow_and_update().clone();
                    if new_target.instance != Some(name.clone()) {
                        // Withdraw everything from this connection before
                        // switching away — best-effort, we're tearing this
                        // connection down regardless of the outcome.
                        let _ = writer
                            .send((peer.wrap)(RedistributeUpdate::Full(Vec::new())))
                            .await;
                        break;
                    }
                    let updates = diff_routes(&last_sent, &new_target.routes);
                    let mut write_failed = false;
                    for update in updates {
                        if writer.send((peer.wrap)(update)).await.is_err() {
                            write_failed = true;
                            break;
                        }
                    }
                    if write_failed {
                        warn!(daemon, instance = %name, "write failure sending redistribution update, reconnecting");
                        break;
                    }
                    last_sent = build_last_sent(&new_target.routes);
                }
                _ = reader.read(&mut eof_buf) => {
                    warn!(daemon, instance = %name, "redistribution target closed the connection, reconnecting");
                    break;
                }
                _ = shutdown.changed() => return,
            }
        }
        // Reconnect (or idle, if the new target is None) immediately — the
        // outer loop re-reads the current target from scratch.
    }
}

/// Waits until `target_rx` changes or `shutdown` fires. Returns `true` if
/// the caller should stop entirely (shutdown requested, or the sender side
/// of `target_rx` was dropped).
async fn wait_idle(
    target_rx: &mut watch::Receiver<RedistributeTarget>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        changed = target_rx.changed() => changed.is_err(),
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

/// Waits out `delay`, interruptible by either `target_rx` changing (so a
/// resolve/connect retry doesn't sit on a stale target) or `shutdown`
/// firing. Returns `true` if the caller should stop entirely.
async fn wait_retry(
    delay: Duration,
    target_rx: &mut watch::Receiver<RedistributeTarget>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        changed = target_rx.changed() => changed.is_err(),
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

/// Builds the `prefix -> gateway` map a set of routes reduces to, for
/// diffing purposes.
fn build_last_sent(routes: &[RedistributedRoute]) -> HashMap<IpNet, IpAddr> {
    routes.iter().map(|r| (r.prefix, r.gateway)).collect()
}

/// Computes the minimal `RedistributeUpdate`s needed to bring `last_sent`
/// (what the peer connection was last told) up to `new_routes`: an `Add`
/// for every prefix that's new or whose gateway changed, a `Remove` for
/// every prefix `last_sent` had that `new_routes` no longer does. Pure and
/// unit-tested directly — the surrounding connection/reconnect machinery
/// isn't.
fn diff_routes(
    last_sent: &HashMap<IpNet, IpAddr>,
    new_routes: &[RedistributedRoute],
) -> Vec<RedistributeUpdate> {
    let mut updates = Vec::new();
    let new_map = build_last_sent(new_routes);

    for route in new_routes {
        match last_sent.get(&route.prefix) {
            Some(gateway) if *gateway == route.gateway => {}
            _ => updates.push(RedistributeUpdate::Add(route.clone())),
        }
    }
    for prefix in last_sent.keys() {
        if !new_map.contains_key(prefix) {
            updates.push(RedistributeUpdate::Remove(*prefix));
        }
    }
    updates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(prefix: &str, gateway: &str) -> RedistributedRoute {
        RedistributedRoute {
            prefix: prefix.parse().unwrap(),
            gateway: gateway.parse().unwrap(),
        }
    }

    #[test]
    fn diff_empty_to_empty_is_empty() {
        let last_sent = HashMap::new();
        assert_eq!(
            diff_routes(&last_sent, &[]),
            [] as [nos_proto::RedistributeUpdate; 0]
        );
    }

    #[test]
    fn diff_new_prefix_is_add() {
        let last_sent = HashMap::new();
        let new = vec![route("10.0.0.0/24", "10.0.0.1")];
        assert_eq!(
            diff_routes(&last_sent, &new),
            vec![RedistributeUpdate::Add(route("10.0.0.0/24", "10.0.0.1"))]
        );
    }

    #[test]
    fn diff_unchanged_prefix_is_noop() {
        let new = vec![route("10.0.0.0/24", "10.0.0.1")];
        let last_sent = build_last_sent(&new);
        assert_eq!(
            diff_routes(&last_sent, &new),
            [] as [nos_proto::RedistributeUpdate; 0]
        );
    }

    #[test]
    fn diff_changed_gateway_is_add() {
        let old = vec![route("10.0.0.0/24", "10.0.0.1")];
        let last_sent = build_last_sent(&old);
        let new = vec![route("10.0.0.0/24", "10.0.0.2")];
        assert_eq!(
            diff_routes(&last_sent, &new),
            vec![RedistributeUpdate::Add(route("10.0.0.0/24", "10.0.0.2"))]
        );
    }

    #[test]
    fn diff_removed_prefix_is_remove() {
        let old = vec![route("10.0.0.0/24", "10.0.0.1")];
        let last_sent = build_last_sent(&old);
        assert_eq!(
            diff_routes(&last_sent, &[]),
            vec![RedistributeUpdate::Remove("10.0.0.0/24".parse().unwrap())]
        );
    }

    #[test]
    fn diff_mixed_add_and_remove() {
        let old = vec![
            route("10.0.0.0/24", "10.0.0.1"),
            route("10.0.1.0/24", "10.0.1.1"),
        ];
        let last_sent = build_last_sent(&old);
        let new = vec![
            route("10.0.0.0/24", "10.0.0.1"),
            route("10.0.2.0/24", "10.0.2.1"),
        ];
        let mut updates = diff_routes(&last_sent, &new);
        updates.sort_by_key(|u| format!("{u:?}"));
        let mut expected = vec![
            RedistributeUpdate::Add(route("10.0.2.0/24", "10.0.2.1")),
            RedistributeUpdate::Remove("10.0.1.0/24".parse().unwrap()),
        ];
        expected.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(updates, expected);
    }

    #[test]
    fn default_target_is_idle() {
        let target = RedistributeTarget::default();
        assert_eq!(target.instance, None);
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    /// Frames the client sends for `routes` with a `chunk` budget, on a first
    /// connection and again once the receiver closes it (a restart, which
    /// must get a fresh `Full`).
    async fn sent(chunk: usize, routes: Vec<RedistributedRoute>) -> [Vec<RedistributeUpdate>; 2] {
        use nos_test_support::{serve, FakeWatchdog, Reply};

        let tmp = tempfile::tempdir().unwrap();
        let wd = FakeWatchdog::new(&tmp.path().join("wd.sock"));
        let peer = serve(
            &tmp.path().join("peer.sock"),
            "ospfd",
            "i1",
            |_: &OspfRequest| Reply::<()>::None,
        );
        wd.set(ServiceRef::OspfInstance("i1".into()), peer.path.clone());
        let (_stop, shutdown) = watch::channel(false);
        let tx = spawn(wd.path().to_path_buf(), shutdown, OSPFV2, chunk);
        tx.send(RedistributeTarget {
            instance: Some("i1".into()),
            routes,
        })
        .unwrap();
        let mut out = [Vec::new(), Vec::new()];
        for (i, o) in out.iter_mut().enumerate() {
            for _ in 0..500 {
                o.extend(peer.take_seen().into_iter().map(|r| match r {
                    OspfRequest::RedistributeRoutes(u) => u,
                    other => panic!("unexpected {other:?}"),
                }));
                if matches!(o.last(), Some(RedistributeUpdate::Full(_))) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            if i == 0 {
                peer.close_connections();
            }
        }
        out
    }

    /// #729: a `Full` over the chunk crosses as `FullPart`s closed by a
    /// `Full`, in order; one under it stays a single request.
    #[tokio::test]
    async fn initial_full_is_split_at_the_chunk_and_resent_on_close() {
        let all: Vec<_> = (0..5)
            .map(|i| route(&format!("10.{i}.0.0/24"), "10.0.0.1"))
            .collect();
        let split = vec![
            RedistributeUpdate::FullPart(all[0..2].to_vec()),
            RedistributeUpdate::FullPart(all[2..4].to_vec()),
            RedistributeUpdate::Full(all[4..].to_vec()),
        ];
        assert_eq!(sent(2, all.clone()).await, [split.clone(), split]);
        let whole = vec![RedistributeUpdate::Full(all.clone())];
        assert_eq!(sent(5, all).await, [whole.clone(), whole]);
    }

    async fn saw(p: &nos_test_support::Server<OspfRequest>, want: RedistributeUpdate) -> bool {
        for _ in 0..500 {
            let seen = p.take_seen();
            if seen
                .iter()
                .any(|r| matches!(r, OspfRequest::RedistributeRoutes(u) if *u == want))
            {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        false
    }

    /// #1279: `spawn_set` feeds each named instance its own connection, and an
    /// instance leaving the set is told to withdraw.
    #[tokio::test]
    async fn spawn_set_feeds_each_instance_and_withdraws_a_dropped_one() {
        use nos_test_support::{serve, FakeWatchdog, Reply};

        let tmp = tempfile::tempdir().unwrap();
        let wd = FakeWatchdog::new(&tmp.path().join("wd.sock"));
        let peers: Vec<_> = ["i1", "i2"]
            .into_iter()
            .map(|n| {
                let p = serve(
                    &tmp.path().join(format!("{n}.sock")),
                    "ospfd",
                    n,
                    |_: &OspfRequest| Reply::<()>::None,
                );
                wd.set(ServiceRef::OspfInstance(n.into()), p.path.clone());
                p
            })
            .collect();
        let (_stop, shutdown) = watch::channel(false);
        let tx = spawn_set(wd.path().to_path_buf(), shutdown, OSPFV2, 100);
        let target = |n: &str, r: &str| RedistributeTarget {
            instance: Some(n.into()),
            routes: vec![route(r, "10.0.0.1")],
        };
        tx.send(vec![
            target("i1", "10.1.0.0/24"),
            target("i2", "10.2.0.0/24"),
        ])
        .unwrap();
        let wait = |i: usize, want: RedistributeUpdate| saw(&peers[i], want);
        assert!(
            wait(
                0,
                RedistributeUpdate::Full(vec![route("10.1.0.0/24", "10.0.0.1")])
            )
            .await
        );
        assert!(
            wait(
                1,
                RedistributeUpdate::Full(vec![route("10.2.0.0/24", "10.0.0.1")])
            )
            .await
        );
        tx.send(vec![target("i1", "10.1.0.0/24")]).unwrap();
        assert!(wait(1, RedistributeUpdate::Full(Vec::new())).await);
    }
}
