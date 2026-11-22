//! Pushes this instance's current SPF-computed routes to the owning
//! `nos-ribd` instance for kernel installation — the OSPF analogue of
//! `bgp::rib_push_client`, same shape (a persistent connection, `Full`
//! snapshot on connect, diffed `Add`/`Remove` afterward).
//!
//! Event-driven: every `Lsdb` change wakes it (`LinkManager::route_changed`),
//! a 50ms hold-down coalesces an LSU burst into one SPF, and a 2s poll
//! remains as a safety net for inputs that don't touch an LSDB.

use std::collections::HashMap;
use std::net::IpAddr;

/// A route's equal-cost next hops (sorted), its LFA backup (if any) and its
/// SPF metric.
/// Next hops, backup (`true`: an RFC 7490 remote LFA tunnel to that PQ node),
/// metric.
type Hops = (Vec<IpAddr>, Option<(IpAddr, bool)>, u32, Vec<Vec<u32>>);
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use nos_proto::{IlmRoute, IpcCodec, OspfRoute, OspfRouteUpdate, RibRequest, Role, ServiceRef};
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::FramedWrite;
use tracing::{debug, info, warn};

use nos_ospf_common::throttle::{SpfThrottle, Timers};

use crate::link::LinkManager;
use nos_daemon::watchdog::resolve_once;

// ponytail: the 2s poll is only a safety net for SPF inputs that don't touch
// an LSDB (neighbor state, area reconcile); upgrade by notifying from them.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Matches every other reconnect/resolve loop in this codebase.
const RETRY_DELAY: Duration = Duration::from_secs(1);
/// How often restart mode is re-checked while the push is held back.
const RESTART_POLL: Duration = Duration::from_millis(200);

/// Spawns the background task that owns the route-push connection for this
/// process's lifetime.
pub fn spawn(
    watchdog_socket: PathBuf,
    links: Arc<LinkManager>,
    routing_table_rx: watch::Receiver<Option<String>>,
    shutdown: watch::Receiver<bool>,
    instance: String,
    chunk: usize,
) -> JoinHandle<()> {
    tokio::spawn(run(
        watchdog_socket,
        links,
        routing_table_rx,
        shutdown,
        instance,
        chunk,
    ))
}

async fn run(
    watchdog_socket: PathBuf,
    links: Arc<LinkManager>,
    routing_table_rx: watch::Receiver<Option<String>>,
    mut shutdown: watch::Receiver<bool>,
    instance: String,
    chunk: usize,
) {
    while !*shutdown.borrow() {
        // RFC 3623 restart mode: push nothing, so `nos-ribd` keeps the routes
        // of the previous process (it drops none on disconnect; only a `Full`
        // replaces them) until the first, complete `Full` after the exit.
        if links.restart_active() {
            if wait_or_shutdown(RESTART_POLL, &mut shutdown).await {
                break;
            }
            continue;
        }
        let Some(table) = routing_table_rx.borrow().clone() else {
            if wait_or_shutdown(POLL_INTERVAL, &mut shutdown).await {
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

        // nos-ribd never replies on this connection, so a read returning means
        // it went away (a restart): reconnect and send a fresh `Full` at once,
        // like `bgp::rib_push_client`, not at the next route change (#729).
        let (mut reader, write_half) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(write_half, IpcCodec::<RibRequest>::default());
        let mut eof_buf = [0u8; 1];
        let (routes, ilm) = compute_routes(&links).await;
        if !push(
            &mut writer,
            &instance,
            vec![OspfRouteUpdate::Full(to_routes(&routes))],
            chunk,
        )
        .await
        {
            warn!(table = %table, "failed to send initial ospf route snapshot to nos-ribd, retrying");
            if wait_or_shutdown(RETRY_DELAY, &mut shutdown).await {
                break;
            }
            continue;
        }
        let mut last_sent = routes;
        let mut last_ilm = ilm;
        if !last_ilm.is_empty() {
            push_ilm(&mut writer, &instance, &last_ilm).await;
        }
        debug!(table = %table, routes = last_sent.len(), "sent initial ospf route snapshot to nos-ribd");

        // Inner loop: same connection, same owning table, until the table
        // changes to something else (including `None`) or a write fails.
        let changed = links.route_changed();
        let mut throttle = SpfThrottle::new(Timers::default());
        loop {
            tokio::select! {
                stop = wait_for_change(&changed, &mut shutdown, &mut throttle, links.spf_timers()) => if stop { return },
                _ = reader.read(&mut eof_buf) => {
                    warn!(table = %table, "nos-ribd closed the ospf push connection, reconnecting");
                    break;
                }
            }
            let new_table = routing_table_rx.borrow().clone();
            if new_table.as_deref() != Some(table.as_str()) {
                // Withdraw everything from this connection before switching
                // away — best-effort, we're tearing this connection down
                // regardless of the outcome.
                push(
                    &mut writer,
                    &instance,
                    vec![OspfRouteUpdate::Full(Vec::new())],
                    chunk,
                )
                .await;
                push_ilm(&mut writer, &instance, &[]).await;
                break;
            }
            let (new_routes, new_ilm) = compute_routes(&links).await;
            let updates = diff_routes(&last_sent, &new_routes);
            if !push(&mut writer, &instance, updates, chunk).await {
                warn!(table = %table, "write failure sending ospf route update, reconnecting");
                break;
            }
            last_sent = new_routes;
            if new_ilm != last_ilm {
                if !push_ilm(&mut writer, &instance, &new_ilm).await {
                    warn!(table = %table, "write failure sending ospf ilm routes, reconnecting");
                    break;
                }
                last_ilm = new_ilm;
            }
        }
        // Reconnect (or idle, if the table is now None) immediately — the
        // outer loop re-reads the current snapshot from scratch.
    }
}

/// Sends one push as `PushOspfRoutes` frames of at most `chunk` weight
/// (`OspfRouteUpdate::frames_with`: a big `Full` becomes `FullPart`s plus a
/// closing `Full`), in order, stopping on the first error. Nothing is sent
/// for an empty push. `false` means the connection is gone.
async fn push<S>(
    writer: &mut S,
    instance: &str,
    updates: Vec<OspfRouteUpdate>,
    chunk: usize,
) -> bool
where
    S: futures::Sink<RibRequest> + Unpin,
{
    let frames = OspfRouteUpdate::frames_with(updates, chunk);
    nos_proto::chunk::send_all(
        writer,
        frames
            .into_iter()
            .map(|updates| RibRequest::PushOspfRoutes {
                instance: instance.to_string(),
                updates,
            }),
    )
    .await
}

/// Sends the instance's whole ILM set (`PushMplsRoutes` replaces it; empty
/// removes it), #1381.
async fn push_ilm<S>(writer: &mut S, instance: &str, routes: &[IlmRoute]) -> bool
where
    S: futures::Sink<RibRequest> + Unpin,
{
    nos_proto::chunk::send_all(
        writer,
        [RibRequest::PushMplsRoutes {
            instance: instance.to_string(),
            routes: routes.to_vec(),
        }],
    )
    .await
}

/// Waits for the next reason to recompute routes: an LSDB change (then a
/// RFC 8405 throttle pause, so an LSU burst costs one SPF, not one per LSA),
/// the `POLL_INTERVAL` fallback (not a change: it bypasses the throttle so a
/// 2 s tick can't keep it in `long_wait`), or shutdown. Returns `true` to stop.
async fn wait_for_change(
    changed: &tokio::sync::Notify,
    shutdown: &mut watch::Receiver<bool>,
    throttle: &mut SpfThrottle,
    timers: Timers,
) -> bool {
    tokio::select! {
        () = changed.notified() => {
            throttle.set_timers(timers);
            let (delay, state) = throttle.on_change(std::time::Instant::now());
            let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
            info!(delay_ms, state = state.name(), "ospf spf scheduled");
            wait_or_shutdown(delay, shutdown).await
        }
        () = tokio::time::sleep(POLL_INTERVAL) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

async fn compute_routes(links: &Arc<LinkManager>) -> (HashMap<IpNet, Hops>, Vec<IlmRoute>) {
    let entries = links.compute_routes().await;
    let ilm = links.ilm_routes(&entries);
    let routes = entries
        .into_iter()
        .map(|e| {
            // One stack per next hop, in next-hop order; none is plain IP.
            let labels = if e.labels.is_empty() {
                Vec::new()
            } else {
                e.next_hops
                    .iter()
                    .map(|h| e.labels.get(h).cloned().unwrap_or_default())
                    .collect()
            };
            (
                IpNet::V4(e.prefix),
                (
                    e.next_hops.into_iter().map(IpAddr::V4).collect(),
                    e.backup_next_hop
                        .map(|b| (IpAddr::V4(b), false))
                        .or(e.backup_tunnel.map(|pq| (IpAddr::V4(pq), true))),
                    e.metric,
                    labels,
                ),
            )
        })
        .collect();
    (routes, ilm)
}

/// Waits out `delay`, interruptible by `shutdown` firing. Returns `true` if
/// the caller should stop entirely.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

fn to_routes(routes: &HashMap<IpNet, Hops>) -> Vec<OspfRoute> {
    routes
        .iter()
        .map(|(&prefix, hops)| to_route(prefix, hops))
        .collect()
}

/// RFC 2328 next hops are routable IPv4 addresses: no interface id needed.
/// No next hop at all is an area range's discard route
/// (`LinkManager::compute_routes`).
fn to_route(prefix: IpNet, (next_hops, backup, metric, labels): &Hops) -> OspfRoute {
    OspfRoute {
        prefix,
        next_hops: next_hops.iter().map(|gw| (*gw, None)).collect(),
        backup_next_hop: backup.filter(|(_, tunnel)| !tunnel).map(|(a, _)| a),
        backup_tunnel: backup.filter(|(_, tunnel)| *tunnel).map(|(a, _)| a),
        backup_interface_id: None,
        metric: *metric,
        discard: next_hops.is_empty(),
        next_hop_labels: labels.clone(),
    }
}

/// Computes the minimal `OspfRouteUpdate`s needed to bring `last_sent` (what
/// the connection was last told) up to `new_routes`: an `Add` for every
/// prefix that's new or whose next-hop changed, a `Remove` for every prefix
/// `last_sent` had that `new_routes` no longer does. Pure and unit-tested
/// directly, mirroring `bgp::rib_push_client::diff_routes` exactly.
fn diff_routes(
    last_sent: &HashMap<IpNet, Hops>,
    new_routes: &HashMap<IpNet, Hops>,
) -> Vec<OspfRouteUpdate> {
    let mut updates = Vec::new();
    for (&prefix, hops) in new_routes {
        if last_sent.get(&prefix) != Some(hops) {
            updates.push(OspfRouteUpdate::Add(to_route(prefix, hops)));
        }
    }
    for prefix in last_sent.keys() {
        if !new_routes.contains_key(prefix) {
            updates.push(OspfRouteUpdate::Remove(*prefix));
        }
    }
    updates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(pairs: &[(&str, &str)]) -> HashMap<IpNet, Hops> {
        pairs
            .iter()
            .map(|(p, gw)| {
                (
                    p.parse().unwrap(),
                    (vec![gw.parse().unwrap()], None, 10, vec![]),
                )
            })
            .collect()
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
            vec![OspfRouteUpdate::Add(OspfRoute {
                prefix: "10.0.0.0/24".parse().unwrap(),
                next_hops: vec![("10.0.0.2".parse().unwrap(), None)],
                backup_next_hop: None,
                backup_interface_id: None,
                backup_tunnel: None,
                metric: 10,
                discard: false,
                next_hop_labels: Vec::new(),
            })]
        );
    }

    /// A discard route is pushed with `discard` set, and withdrawn with an
    /// ordinary `Remove` once its range goes away.
    #[test]
    fn discard_route_is_pushed_then_removed() {
        let p: IpNet = "10.9.0.0/16".parse().unwrap();
        let with = HashMap::from([(p, (Vec::new(), None, 5, vec![]))]);
        assert_eq!(
            diff_routes(&HashMap::new(), &with),
            vec![OspfRouteUpdate::Add(OspfRoute {
                prefix: p,
                next_hops: Vec::new(),
                backup_next_hop: None,
                backup_interface_id: None,
                backup_tunnel: None,
                metric: 5,
                discard: true,
                next_hop_labels: Vec::new(),
            })]
        );
        assert_eq!(
            diff_routes(&with, &HashMap::new()),
            vec![OspfRouteUpdate::Remove(p)]
        );
    }

    #[test]
    fn diff_removed_prefix_is_remove() {
        let last_sent = routes(&[("10.0.0.0/24", "10.0.0.1")]);
        assert_eq!(
            diff_routes(&last_sent, &HashMap::new()),
            vec![OspfRouteUpdate::Remove("10.0.0.0/24".parse().unwrap())]
        );
    }

    #[test]
    fn diff_mixed_add_and_remove() {
        let last_sent = routes(&[("10.0.0.0/24", "10.0.0.1"), ("10.0.1.0/24", "10.0.1.1")]);
        let new_routes = routes(&[("10.0.0.0/24", "10.0.0.1"), ("10.0.2.0/24", "10.0.2.1")]);
        let mut updates = diff_routes(&last_sent, &new_routes);
        updates.sort_by_key(|u| format!("{u:?}"));
        let mut expected = vec![
            OspfRouteUpdate::Add(OspfRoute {
                prefix: "10.0.2.0/24".parse().unwrap(),
                next_hops: vec![("10.0.2.1".parse().unwrap(), None)],
                backup_next_hop: None,
                backup_interface_id: None,
                backup_tunnel: None,
                metric: 10,
                discard: false,
                next_hop_labels: Vec::new(),
            }),
            OspfRouteUpdate::Remove("10.0.1.0/24".parse().unwrap()),
        ];
        expected.sort_by_key(|u| format!("{u:?}"));
        assert_eq!(updates, expected);
    }

    #[test]
    fn diff_backup_only_change_is_add() {
        let gw: IpAddr = "10.0.0.1".parse().unwrap();
        let bk: IpAddr = "10.0.9.9".parse().unwrap();
        let p: IpNet = "10.0.0.0/24".parse().unwrap();
        let last_sent = HashMap::from([(p, (vec![gw], None, 10, vec![]))]);
        let new_routes = HashMap::from([(p, (vec![gw], Some((bk, false)), 10, vec![]))]);
        assert_eq!(
            diff_routes(&last_sent, &new_routes),
            vec![OspfRouteUpdate::Add(OspfRoute {
                prefix: p,
                next_hops: vec![(gw, None)],
                backup_next_hop: Some(bk),
                backup_interface_id: None,
                backup_tunnel: None,
                metric: 10,
                discard: false,
                next_hop_labels: Vec::new(),
            })]
        );
    }

    #[test]
    fn a_remote_lfa_is_pushed_as_backup_tunnel() {
        let gw: IpAddr = "10.0.0.1".parse().unwrap();
        let pq: IpAddr = "10.255.0.4".parse().unwrap();
        let p: IpNet = "10.0.0.0/24".parse().unwrap();
        let route = to_route(p, &(vec![gw], Some((pq, true)), 10, vec![]));
        assert_eq!(route.backup_next_hop, None);
        assert_eq!(route.backup_tunnel, Some(pq));
    }

    #[test]
    fn diff_ecmp_set_change_is_add_carrying_every_hop() {
        let p: IpNet = "10.0.0.0/24".parse().unwrap();
        let (a, b): (IpAddr, IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.1.1".parse().unwrap());
        let last_sent = HashMap::from([(p, (vec![a], None, 10, vec![]))]);
        let new_routes = HashMap::from([(p, (vec![a, b], None, 10, vec![]))]);
        assert_eq!(
            diff_routes(&last_sent, &new_routes),
            vec![OspfRouteUpdate::Add(OspfRoute {
                prefix: p,
                next_hops: vec![(a, None), (b, None)],
                backup_next_hop: None,
                backup_interface_id: None,
                backup_tunnel: None,
                metric: 10,
                discard: false,
                next_hop_labels: Vec::new(),
            })]
        );
    }

    /// A change wakes the loop long before the fallback poll; a burst of
    /// changes stores one permit, so it costs exactly one wake-up.
    #[tokio::test(start_paused = true)]
    async fn change_wakes_early_and_bursts_coalesce() {
        let n = tokio::sync::Notify::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut th = SpfThrottle::new(Timers::default());
        let hold_down = Timers::default().initial;
        let start = tokio::time::Instant::now();
        for _ in 0..5 {
            n.notify_one();
        }
        assert!(!wait_for_change(&n, &mut rx, &mut th, Timers::default()).await);
        assert_eq!(start.elapsed(), hold_down);
        // The burst is spent: the next wait falls back to the poll tick,
        // which is not a change and leaves the throttle alone.
        assert!(!wait_for_change(&n, &mut rx, &mut th, Timers::default()).await);
        assert_eq!(start.elapsed(), hold_down + POLL_INTERVAL);
    }

    /// A snapshot heavier than `chunk` reaches the RIB as `FullPart`s closed
    /// by one `Full`, in order, one `PushOspfRoutes` per frame (#727).
    #[tokio::test]
    async fn push_cuts_a_heavy_full_into_ordered_frames() {
        use futures::{SinkExt, StreamExt};
        use tokio_util::codec::FramedRead;

        let tmp = tempfile::tempdir().unwrap();
        let ribd = nos_test_support::FakeRibd::new(&tmp.path().join("rib.sock"), "rt1");
        let stream = nos_pki::connect(ribd.path(), Role::Ribd, "rt1")
            .await
            .unwrap();
        let (r, w) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(w, IpcCodec::<RibRequest>::default());
        let mut reader = FramedRead::new(r, IpcCodec::<nos_proto::RibEvent>::default());
        // One next hop each: weight 2, so a chunk of 4 carries two routes.
        let all: Vec<OspfRoute> = (0..5)
            .map(|i| OspfRoute {
                prefix: format!("10.{i}.0.0/24").parse().unwrap(),
                next_hops: vec![("10.0.0.1".parse().unwrap(), None)],
                backup_next_hop: None,
                backup_interface_id: None,
                backup_tunnel: None,
                metric: 10,
                discard: false,
                next_hop_labels: Vec::new(),
            })
            .collect();

        assert!(push(&mut writer, "i1", Vec::new(), 4).await);
        assert!(
            push(
                &mut writer,
                "i1",
                vec![OspfRouteUpdate::Full(all.clone())],
                4
            )
            .await
        );
        // The query's reply proves every push before it was read.
        writer.send(RibRequest::GetVrfName).await.unwrap();
        reader.next().await.unwrap().unwrap();

        let frames: Vec<Vec<OspfRouteUpdate>> = ribd
            .take_pushed()
            .into_iter()
            .map(|r| match r {
                RibRequest::PushOspfRoutes { instance, updates } => {
                    assert_eq!(instance, "i1");
                    updates
                }
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        let expect = |i: usize| all[i..(i + 2).min(5)].to_vec();
        assert_eq!(
            frames,
            vec![
                vec![OspfRouteUpdate::FullPart(expect(0))],
                vec![OspfRouteUpdate::FullPart(expect(2))],
                vec![OspfRouteUpdate::Full(expect(4))],
            ]
        );
    }

    fn frames_of(r: RibRequest) -> Vec<OspfRouteUpdate> {
        match r {
            RibRequest::PushOspfRoutes { instance, updates } => {
                assert_eq!(instance, "i1");
                updates
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A restarted `nos-ribd` (its connection closed) gets a fresh `Full` at
    /// once, with no route change to make the next write fail (#729).
    #[tokio::test]
    async fn closed_connection_resends_a_full_at_once() {
        use nos_test_support::{Fake, Fakes};

        let f = Fakes::start(&[Fake::Watchdog, Fake::Ribd("rt1".into())]);
        let wire = Arc::new(crate::link::tests::wire::Wire::default());
        let links = LinkManager::with_opener(
            1,
            None,
            crate::boot::BootCounter::in_memory(),
            wire.opener(),
        );
        let (_rt_tx, rt) = watch::channel(Some("rt1".to_string()));
        let (_stop, shutdown) = watch::channel(false);
        let task = spawn(f.watchdog_socket(), links, rt, shutdown, "i1".into(), 4);
        let ribd = &f.ribd["rt1"];
        let full = vec![vec![OspfRouteUpdate::Full(Vec::new())]];
        let pushed_on = |conns: usize| async move {
            for _ in 0..500 {
                let p = if ribd.connections() >= conns {
                    ribd.take_pushed()
                } else {
                    Vec::new()
                };
                if !p.is_empty() {
                    return p.into_iter().map(frames_of).collect::<Vec<_>>();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("no push on connection {conns}");
        };

        assert_eq!(pushed_on(1).await, full);
        ribd.close_connections();
        assert_eq!(pushed_on(2).await, full);
        task.abort();
    }

    /// RFC 3623 restart mode (#1145): nothing is pushed (not even a
    /// connection made) until it ends, then the first `Full` goes out.
    #[tokio::test]
    async fn restart_mode_holds_back_the_first_full() {
        use nos_test_support::{Fake, Fakes};

        let f = Fakes::start(&[Fake::Watchdog, Fake::Ribd("rt1".into())]);
        let wire = Arc::new(crate::link::tests::wire::Wire::default());
        let links = LinkManager::with_opener(
            1,
            None,
            crate::boot::BootCounter::in_memory(),
            wire.opener(),
        );
        links.begin_restart(
            [std::net::Ipv4Addr::new(9, 9, 9, 9)].into(),
            Duration::from_millis(100),
        );
        let (_rt_tx, rt) = watch::channel(Some("rt1".to_string()));
        let (_stop, shutdown) = watch::channel(false);
        let task = spawn(
            f.watchdog_socket(),
            links.clone(),
            rt,
            shutdown,
            "i1".into(),
            4,
        );
        let ribd = &f.ribd["rt1"];
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(ribd.connections(), 0);
        assert!(ribd.take_pushed().is_empty());
        // The deadline has passed: the next tick ends the mode (timeout).
        links.restart_tick(false).await;
        assert!(!links.restart_active());
        for _ in 0..500 {
            if let Some(p) = ribd.take_pushed().into_iter().next() {
                assert_eq!(frames_of(p), vec![OspfRouteUpdate::Full(Vec::new())]);
                task.abort();
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no push after restart mode ended");
    }

    #[test]
    fn labels_ride_to_the_wire_and_a_label_change_is_an_add() {
        let p: IpNet = "10.9.0.1/32".parse().unwrap();
        let gw: IpAddr = "10.0.0.2".parse().unwrap();
        let old = HashMap::from([(p, (vec![gw], None, 10, vec![vec![16001]]))]);
        let new = HashMap::from([(p, (vec![gw], None, 10, vec![vec![17001]]))]);
        let [OspfRouteUpdate::Add(r)] = &diff_routes(&old, &new)[..] else {
            panic!("expected one add");
        };
        assert_eq!(r.next_hop_labels, vec![vec![17001]]);
    }
}
