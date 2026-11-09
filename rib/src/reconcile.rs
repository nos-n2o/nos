use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use nos_proto::{
    BroadcastDomainStatus, Config, DiffScope, Event, InterfaceStatus, IpNet, PortAggregateStatus,
    RedistributeSource, RedistributeTarget, RedistributedRoute, ServiceRef,
};
use tokio::sync::{watch, Mutex, MutexGuard, Notify, RwLock};
use tokio::time::sleep;
use tracing::{debug, error, info, trace, warn};

use crate::bfd_client;
use crate::bgp_client;
use crate::driver::{Mpls, RibDriver};
use crate::evpn::{self, L3Vni};
use crate::evpn_client::EvpnTarget;
use crate::interface_client;
use crate::ospf_client;
use crate::rib::{build_from_config, Rib, RibEntry, RouteSource};
use crate::vpn;
use crate::vpn_client::VpnTarget;
use nos_daemon::config;
use nos_daemon::watchdog;

/// Fixed reconnect delay for the config subscription, matching
/// `nos-watchdog`'s `bgp_instances::RECONNECT_DELAY` for consistency across
/// the codebase's config-subscribing consumers.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// How often to re-apply the current `Rib` to the driver even without a new
/// config diff. Needed for two reasons: a driver's kernel state can drift
/// out of band (an operator or another process editing routes/the VRF
/// directly), and — the motivating case — the VRF device this table's
/// routes are installed into may not exist yet if `nos-interfaced` races
/// this daemon's own VRF creation on startup; nothing about *our* config
/// changes when that happens, so nothing else would ever retry it.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

/// Serialises every kernel write of this `nos-ribd` (#653). A producer
/// (`server.rs`) or a resync holds the gate across "mutate the `Rib`, take
/// the snapshot, call the driver", so a full `apply` built from an older
/// snapshot can never land after a newer delta (nor two deltas interleave).
/// Lock order, everywhere: the gate first, then the `Rib` lock. Queries never
/// take it.
///
/// It also carries the dirty flag: a failed kernel write calls `mark_dirty`
/// and `run` answers with a full `apply` at once, rather than waiting for the
/// next `REAPPLY_INTERVAL` tick.
pub struct KernelGate {
    lock: Mutex<()>,
    dirty: AtomicBool,
    notify: Notify,
    hold: std::sync::Mutex<HoldState>,
    hold_timeout: Duration,
}

impl Default for KernelGate {
    fn default() -> Self {
        Self::new(STARTUP_HOLD)
    }
}

/// How long a restarted `nos-ribd` keeps the kernel routes a crashed
/// predecessor left behind while it waits for its producers to re-push (#654).
pub const STARTUP_HOLD: Duration = Duration::from_secs(120);

/// Startup hold (#654): after a crash restart the kernel still has the old
/// `Bgp`/`Ospf`/`Evpn`/`Vpn` routes, but the fresh `Rib` does not, so the
/// first full `apply` would delete them until the producers reconnect and send
/// their `Full`. Until every source this table is configured to have has sent
/// one (or `deadline` passes), full applies only add.
#[derive(Debug)]
struct StartupHold {
    pending: HashSet<RouteSource>,
    deadline: Instant,
}

#[derive(Debug, Default)]
enum HoldState {
    /// The first resync has not run yet.
    #[default]
    Unarmed,
    Holding(StartupHold),
    /// Armed once, then over (or never needed).
    Done,
}

/// The sources the running config says feed `table`.
// ponytail: `ospf_instance` and `ospfv3_instance` both map to `Ospf`, so the
// first of the two `Full`s ends the wait for both; a split key would need a
// per-family tag on `PushOspfRoutes`.
fn configured_sources(cfg: &Config, table: &str) -> HashSet<RouteSource> {
    let mut s = HashSet::new();
    if let Some(t) = cfg.routing_tables.iter().find(|t| t.name == table) {
        let mut set = |on: bool, src| {
            if on {
                s.insert(src);
            }
        };
        set(t.bgp_instance.is_some(), RouteSource::Bgp);
        set(
            t.ospf_instance.is_some() || t.ospfv3_instance.is_some(),
            RouteSource::Ospf,
        );
        set(t.evpn.bgp_instance.is_some(), RouteSource::Evpn);
        set(t.vpn.bgp_instance.is_some(), RouteSource::Vpn);
    }
    s
}

/// Proof that the gate is held.
pub type GateGuard<'a> = MutexGuard<'a, ()>;

impl KernelGate {
    pub fn new(hold_timeout: Duration) -> Self {
        Self {
            lock: Mutex::default(),
            dirty: AtomicBool::default(),
            notify: Notify::default(),
            hold: std::sync::Mutex::default(),
            hold_timeout,
        }
    }

    pub async fn lock(&self) -> GateGuard<'_> {
        self.lock.lock().await
    }

    /// A kernel write failed: the kernel may differ from the `Rib`.
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Reads and clears the flag, for tests.
    #[cfg(test)]
    pub(crate) fn take_dirty_for_test(&self) -> bool {
        self.dirty.swap(false, Ordering::SeqCst)
    }

    /// First successful resync only: starts the hold when the table has
    /// producers, and tells the driver. `true` when a hold began.
    pub(crate) fn arm_hold(
        &self,
        _held: &GateGuard<'_>,
        pending: HashSet<RouteSource>,
        driver: &dyn RibDriver,
        table: &str,
    ) -> bool {
        let mut h = self.hold.lock().unwrap();
        if !matches!(*h, HoldState::Unarmed) {
            return false;
        }
        if pending.is_empty() {
            *h = HoldState::Done;
            return false;
        }
        info!(table = %table, sources = ?pending, timeout = ?self.hold_timeout, "startup hold: keeping existing kernel routes");
        driver.keep_stale(true);
        *h = HoldState::Holding(StartupHold {
            pending,
            deadline: Instant::now() + self.hold_timeout,
        });
        true
    }

    /// `source` sent its closing `Full`. `true` when that ends the hold.
    pub(crate) fn source_done(&self, _held: &GateGuard<'_>, source: RouteSource) -> bool {
        match &mut *self.hold.lock().unwrap() {
            HoldState::Holding(h) => {
                h.pending.remove(&source);
                h.pending.is_empty()
            }
            _ => false,
        }
    }

    /// The deadline passed.
    fn hold_expired(&self, now: Instant) -> bool {
        matches!(&*self.hold.lock().unwrap(), HoldState::Holding(h) if now >= h.deadline)
    }

    /// Ends the hold (when one is running) and re-applies the whole table,
    /// which now removes what is still stale. The caller holds the gate.
    pub(crate) async fn release_hold(
        &self,
        table: &str,
        rib: &RwLock<Rib>,
        gate: &GateGuard<'_>,
        driver: &dyn RibDriver,
        reason: &str,
    ) {
        {
            let mut h = self.hold.lock().unwrap();
            if !matches!(*h, HoldState::Holding(_)) {
                return;
            }
            *h = HoldState::Done;
        }
        driver.keep_stale(false);
        info!(table = %table, reason, "startup hold released");
        apply_to_kernel(table, rib, self, gate, driver).await;
    }

    async fn notified(&self) {
        self.notify.notified().await;
    }

    fn take_dirty(&self, _held: &GateGuard<'_>) -> bool {
        self.dirty.swap(false, Ordering::SeqCst)
    }
}

/// Minimum spacing of dirty-triggered full applies when the kernel keeps
/// refusing; the `REAPPLY_INTERVAL` tick stays the floor.
const DIRTY_RETRY: Duration = Duration::from_secs(1);

/// Runs until `shutdown` fires. Subscribes to `RoutingTables` and
/// `StaticRoutingInstances` diffs purely as an edge trigger: every
/// `Event::Diff` received (including the first, synthesized one) causes a
/// full `resync` — a fresh `Request::Get` plus a from-scratch rebuild of
/// this table's `Static` candidates (via `Rib::replace_source`, leaving any
/// `Bgp`-sourced candidates pushed by `crate::server::apply_bgp_route_update`
/// untouched) — rather than incremental diff application, since
/// `SectionDiff`/`FieldDiff` only carry pre-formatted display strings, not
/// structured route data (see `nos_proto::diff::routing_table`/`static_routing_instance`).
/// The `Connected` candidates are rebuilt the same way, from what
/// `nos-interfaced` (resolved through `watchdog_socket`) reports it applied
/// — so a new address is visible to `show route` and to `nos-bgpd`'s
/// next-hop check within one `REAPPLY_INTERVAL` at worst.
///
/// On exit, tears down this table's kernel VRF/routes via `driver` (see
/// `RibDriver::teardown`) — the same SIGINT `nos-watchdog` sends both for
/// "shutting down" and "this table was removed from config" (root
/// `CLAUDE.md`), so this runs on every ordinary restart too, not only a
/// real removal. That's an accepted tradeoff: the driver's persisted
/// table-id registry (see `driver::table_registry`) is untouched by
/// `teardown`, so the next `apply` recreates the exact same VRF name.
#[allow(clippy::too_many_arguments)] // one socket/channel per collaborator, wired once by main.rs
pub async fn run(
    config_socket: PathBuf,
    watchdog_socket: PathBuf,
    table: String,
    rib: Arc<RwLock<Rib>>,
    kernel: Arc<KernelGate>,
    driver: Arc<dyn RibDriver>,
    redistribute_tx: watch::Sender<bgp_client::RedistributeTarget>,
    ospf_redistribute_tx: Vec<OspfFeed>,
    evpn_tx: watch::Sender<EvpnTarget>,
    vpn: VpnFeed,
    bfd_target_tx: watch::Sender<bfd_client::Target>,
    bfd_up: watch::Receiver<bfd_client::UpSet>,
    mut shutdown: watch::Receiver<bool>,
) {
    // A change of which BFD gateways are up is a reason to resync: the
    // routes through them come or go.
    let mut bfd_changed = bfd_up.clone();
    while !*shutdown.borrow() {
        match config::subscribe_diff(
            &config_socket,
            // `OspfInstances`: an instance's `remote-lfa` adds or removes this
            // table's IP-in-IP device.
            vec![
                DiffScope::RoutingTables,
                DiffScope::StaticRoutingInstances,
                DiffScope::OspfInstances,
            ],
        )
        .await
        {
            Ok(mut reader) => {
                info!(table = %table, "connected to nos-configd diff stream");
                let mut reapply = tokio::time::interval(REAPPLY_INTERVAL);
                reapply.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                reapply.tick().await; // consume the immediate first tick — the
                                      // diff stream's own synthesized first
                                      // Event::Diff already resyncs
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &watchdog_socket, &table, &rib, &kernel, driver.as_ref(), &redistribute_tx, &ospf_redistribute_tx, &evpn_tx, &vpn, &bfd_target_tx, &bfd_up).await;
                            }
                            Some(Ok(_)) => {}
                            Some(Err(e)) => {
                                warn!(table = %table, error = %e, "error reading diff stream, reconnecting");
                                break;
                            }
                            None => {
                                warn!(table = %table, "diff stream closed, reconnecting");
                                break;
                            }
                        },
                        r = bfd_changed.changed() => {
                            if r.is_ok() {
                                resync(&config_socket, &watchdog_socket, &table, &rib, &kernel, driver.as_ref(), &redistribute_tx, &ospf_redistribute_tx, &evpn_tx, &vpn, &bfd_target_tx, &bfd_up).await;
                            }
                        }
                        _ = reapply.tick() => {
                            if kernel.hold_expired(Instant::now()) {
                                let gate = kernel.lock().await;
                                kernel.release_hold(&table, &rib, &gate, driver.as_ref(), "timeout").await;
                            }
                            resync(&config_socket, &watchdog_socket, &table, &rib, &kernel, driver.as_ref(), &redistribute_tx, &ospf_redistribute_tx, &evpn_tx, &vpn, &bfd_target_tx, &bfd_up).await;
                        }
                        () = kernel.notified() => {
                            if dirty_apply(&table, &rib, &kernel, driver.as_ref()).await
                                && wait_or_shutdown(DIRTY_RETRY, &mut shutdown).await
                            {
                                break;
                            }
                        }
                        _ = shutdown.changed() => break,
                    }
                }
            }
            Err(e) => warn!(
                table = %table,
                error = %e,
                socket = %config_socket.display(),
                "failed to connect to nos-configd"
            ),
        }

        if *shutdown.borrow() {
            break;
        }
        if wait_or_shutdown(RECONNECT_DELAY, &mut shutdown).await {
            break;
        }
    }

    let gate = kernel.lock().await;
    let torn = driver.teardown(&table).await;
    drop(gate);
    match torn {
        Ok(()) => debug!(table = %table, "tore down VRF/table on shutdown"),
        Err(e) => warn!(table = %table, error = %e, "failed to tear down VRF on shutdown"),
    }
    info!(table = %table, "reconciliation loop stopped");
}

#[allow(clippy::too_many_arguments)] // one channel per push target
async fn resync(
    config_socket: &Path,
    watchdog_socket: &Path,
    table: &str,
    rib: &Arc<RwLock<Rib>>,
    kernel: &KernelGate,
    driver: &dyn RibDriver,
    redistribute_tx: &watch::Sender<bgp_client::RedistributeTarget>,
    ospf_redistribute_tx: &[OspfFeed],
    evpn_tx: &watch::Sender<EvpnTarget>,
    vpn: &VpnFeed,
    bfd_target_tx: &watch::Sender<bfd_client::Target>,
    bfd_up: &watch::Receiver<bfd_client::UpSet>,
) {
    match config::fetch_config(config_socket).await {
        Ok(cfg) => {
            let _ = bfd_target_tx.send_if_modified(|t| {
                let want = crate::rib::bfd_target(&cfg, table);
                let changed = *t != want;
                if changed {
                    *t = want;
                }
                changed
            });
            let up = bfd_up.borrow().clone();
            let static_entries = if let Some(new_rib) = build_from_config(&cfg, table, &up) {
                new_rib
                    .all_routes()
                    .into_iter()
                    .flat_map(|(_, candidates)| candidates)
                    .collect::<Vec<_>>()
            } else {
                warn!(
                    table = %table,
                    "routing table not found in running config; static routes cleared until it reappears"
                );
                Vec::new()
            };
            let connected = fetch_connected(watchdog_socket, &cfg, table).await;
            let l3 = resolve_l3vni(watchdog_socket, &cfg, table).await;

            // Held until the kernel apply below: the static/connected rebuild
            // and its snapshot must not be overtaken by a producer's delta.
            let gate = kernel.lock().await;
            let mut guard = rib.write().await;
            guard.replace_source(RouteSource::Static, static_entries);
            match connected {
                Some(entries) => {
                    debug!(table = %table, connected = entries.len(), "resolved connected prefixes");
                    guard.replace_source(RouteSource::Connected, entries);
                }
                // Same "keep the last good set on a transient failure" rule
                // as nos-bgpd's `igp_client`.
                None => {
                    debug!(table = %table, "nos-interfaced unreachable, keeping previous connected prefixes");
                }
            }
            if let Some(l3) = l3 {
                guard.evpn.local = l3;
            }
            guard.refresh_evpn();
            let routes = guard.best_routes_for_kernel();
            drop(guard);

            if let Err(e) = driver.sync_tunnel(table, remote_lfa(&cfg, table)).await {
                warn!(table = %table, error = %e, "failed to sync the remote lfa tunnel device");
            }

            debug!(table = %table, prefixes = routes.len(), "recomputed RIB");
            for (prefix, entry) in &routes {
                trace!(
                    table = %table,
                    %prefix,
                    next_hops = ?entry.next_hops,
                    source = ?entry.source,
                    "best route"
                );
            }
            // Before the routes: the pop route gates the export, and a
            // labelled route needs the underlay `sync_mpls` records.
            vpn_export(&cfg, table, rib, driver, vpn).await;
            kernel.arm_hold(&gate, configured_sources(&cfg, table), driver, table);
            apply_to_kernel(table, rib, kernel, &gate, driver).await;
            drop(gate);
            let _ = redistribute_tx.send(compute_redistribute_target(&cfg, table, &routes));
            for (to, tx) in ospf_redistribute_tx {
                let _ = tx.send(compute_redistribute_target_ospf(&cfg, table, &routes, *to));
            }
            let _ = evpn_tx.send(evpn_target(&*rib.read().await));
        }
        Err(e) => {
            warn!(table = %table, error = %e, "failed to fetch running config, keeping previous RIB");
        }
    }
}

/// Whether this table's OSPF instance runs RFC 7490 remote LFA (so the
/// table needs its IP-in-IP device, to tunnel to and to be tunnelled to).
fn remote_lfa(cfg: &Config, table: &str) -> bool {
    cfg.routing_tables
        .iter()
        .find(|t| t.name == table)
        .and_then(|t| t.ospf_instance.as_ref())
        .and_then(|name| cfg.ospf_instances.iter().find(|i| &i.name == name))
        .is_some_and(|i| i.remote_lfa)
}

/// Brings the kernel in line with `rib`: the L3 VNI devices and remote VTEPs
/// first (`Evpn` routes leave through that bridge, and it gives our Router's
/// MAC), then every best route. Shared with `server.rs`'s Type-5 push; the
/// caller holds the gate. A failed apply marks the gate dirty.
pub(crate) async fn apply_to_kernel(
    table: &str,
    rib: &RwLock<Rib>,
    kernel: &KernelGate,
    gate: &GateGuard<'_>,
    driver: &dyn RibDriver,
) {
    sync_l3vni(table, rib, gate, driver).await;
    let routes = rib.read().await.best_routes_for_kernel();
    if let Err(e) = driver.apply(table, &routes).await {
        error!(table = %table, error = %e, "failed to apply routes to kernel");
        kernel.mark_dirty();
    }
}

/// A dirty-triggered full apply (from a fresh snapshot). `true` when it
/// failed again, so the caller backs off.
async fn dirty_apply(
    table: &str,
    rib: &RwLock<Rib>,
    kernel: &KernelGate,
    driver: &dyn RibDriver,
) -> bool {
    let gate = kernel.lock().await;
    // Cleared before the snapshot: a failure of this very apply re-marks it.
    if !kernel.take_dirty(&gate) {
        return false;
    }
    info!(table = %table, "kernel write failed earlier, re-applying the whole table");
    apply_to_kernel(table, rib, kernel, &gate, driver).await;
    kernel.dirty.load(Ordering::SeqCst)
}

/// The L3 VNI half of `apply_to_kernel`: devices, remote VTEPs, our Router's
/// MAC. The caller holds the gate.
pub(crate) async fn sync_l3vni(
    table: &str,
    rib: &RwLock<Rib>,
    _gate: &GateGuard<'_>,
    driver: &dyn RibDriver,
) {
    let (l3, remotes) = {
        let guard = rib.read().await;
        (guard.evpn.local.clone(), guard.evpn.remotes.clone())
    };
    match driver.sync_l3vni(table, l3.as_ref(), &remotes).await {
        Ok(rmac) => rib.write().await.evpn.rmac = rmac,
        Err(e) => warn!(table = %table, error = %e, "failed to build the l3 vni devices"),
    }
}

/// This table's `evpn`, resolved: `Some(None)` without one, `None` while its
/// VTEP isn't resolvable (the caller keeps what it had, so a transient
/// `nos-interfaced` failure doesn't tear the devices down).
async fn resolve_l3vni(watchdog_socket: &Path, cfg: &Config, table: &str) -> Option<Option<L3Vni>> {
    let Some(e) = cfg
        .routing_tables
        .iter()
        .find(|t| t.name == table)
        .map(|t| &t.evpn)
    else {
        return Some(None);
    };
    // Commit-time validation guarantees the rest once there is an L3 VNI.
    let (Some(vni), Some(bgp_instance), Some(source)) =
        (e.l3_vni, e.bgp_instance.as_ref(), e.vtep_source.as_ref())
    else {
        return Some(None);
    };
    let underlay_table = cfg
        .bgp_instances
        .iter()
        .find(|i| &i.name == bgp_instance)
        .and_then(|i| i.routing_table.as_deref());
    let Some((vtep, underlay)) =
        interface_client::resolve_vtep(watchdog_socket, underlay_table, source).await
    else {
        debug!(table = %table, "evpn vtep-source not resolvable yet");
        return None;
    };
    let rts = |list: &[String]| {
        list.iter()
            .filter_map(|r| nos_proto::evpn_id::parse_rt(r))
            .collect()
    };
    Some(Some(L3Vni {
        vni,
        rd: e
            .rd
            .as_deref()
            .and_then(nos_proto::evpn_id::parse_rd)
            .unwrap_or_default(),
        import: rts(&e.route_targets_import),
        export: rts(&e.route_targets_export),
        bgp_instance: bgp_instance.clone(),
        vtep,
        underlay,
    }))
}

/// What `evpn_client` originates: every best route but the `Evpn` ones, once
/// the table has an L3 VNI and the driver gave its Router's MAC.
fn evpn_target(rib: &Rib) -> EvpnTarget {
    match (&rib.evpn.local, rib.evpn.rmac) {
        (Some(l3), Some(rmac)) => EvpnTarget {
            bgp_instance: Some(l3.bgp_instance.clone()),
            routes: evpn::originated(&rib.best_routes(), l3, rmac),
        },
        _ => EvpnTarget::default(),
    }
}

/// What `vpn_client` exports (`vpn::originated`), once `vpn` resolves, its
/// label is known and the driver programmed it (`RibDriver::sync_mpls`: a
/// label the kernel cannot pop would black-hole the traffic, so nothing is
/// exported then); the label is kept in the `Rib` for `show route`. A failed
/// label allocation keeps the previous target.
async fn vpn_export(
    cfg: &Config,
    table: &str,
    rib: &Arc<RwLock<Rib>>,
    driver: &dyn RibDriver,
    (tx, registry): &VpnFeed,
) {
    let resolved = vpn::resolve(cfg, table, |reserved| {
        crate::driver::table_registry::ensure_label(registry, table, reserved)
    });
    let mpls = match &resolved {
        Ok(v) => v.as_ref().map(|v| Mpls {
            label: v.label,
            underlay: v.underlay.clone(),
        }),
        Err(_) => None,
    };
    let programmed = if resolved.is_ok() {
        match driver.sync_mpls(table, mpls.as_ref()).await {
            Ok(()) => true,
            Err(e) => {
                error!(table = %table, label = ?mpls.map(|m| m.label), error = %e, "mpls label not programmed, vpn export withheld");
                false
            }
        }
    } else {
        false
    };
    let mut guard = rib.write().await;
    let target = match resolved {
        Ok(Some(v)) => {
            guard.vpn_label = Some(v.label);
            if programmed {
                VpnTarget {
                    bgp_instance: Some(v.bgp_instance.clone()),
                    routes: vpn::originated(&guard.best_routes(), &v),
                }
            } else {
                VpnTarget::default()
            }
        }
        Ok(None) => {
            guard.vpn_label = None;
            VpnTarget::default()
        }
        Err(e) => {
            warn!(table = %table, error = %e, "failed to allocate the vpn label, keeping the previous export");
            return;
        }
    };
    drop(guard);
    let _ = tx.send(target);
}

/// Asks `nos-interfaced` (resolved via the broker, `ServiceRef::Interfaces`)
/// for every interface, plus each `cfg.broadcast_domains` entry in `table`
/// with an SVI address (one `GetBroadcastDomain` each — there is no "list
/// every domain" request, the same per-name lookup `nos-fdbd` does), and
/// derives this table's `Connected` candidates. `None` if any call failed.
async fn fetch_connected(
    watchdog_socket: &Path,
    cfg: &Config,
    table: &str,
) -> Option<Vec<RibEntry>> {
    let socket = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let interfaces = interface_client::get_interfaces(&socket).await?;
    let aggregates = if cfg.port_aggregates.iter().any(|a| {
        a.subinterfaces
            .iter()
            .any(|s| s.routing_table.as_deref() == Some(table))
    }) {
        interface_client::get_port_aggregates(&socket).await?
    } else {
        Vec::new()
    };
    let mut domains = Vec::new();
    for d in &cfg.broadcast_domains {
        if d.routing_table.as_deref() == Some(table) && !d.addresses.is_empty() {
            domains.push(interface_client::get_broadcast_domain(&socket, &d.name).await?);
        }
    }
    Some(connected_entries(table, &interfaces, &aggregates, &domains))
}

/// The `Connected` candidates of `table`: the network of every address on an
/// interface (a loopback's flat `addresses`, or any `Subinterface`'s per
/// tag), port aggregate subinterface or broadcast-domain SVI whose
/// `routing_table` is `table`. The entry's
/// `gateway` is the local address itself — display only, never installed
/// (see `RouteSource::Connected`). A prefix addressed twice keeps the first
/// address seen. Pure, so it's unit-tested without IPC.
fn connected_entries(
    table: &str,
    interfaces: &[InterfaceStatus],
    aggregates: &[PortAggregateStatus],
    domains: &[BroadcastDomainStatus],
) -> Vec<RibEntry> {
    let in_table = |rt: &Option<String>| rt.as_deref() == Some(table);
    let mut entries: Vec<RibEntry> = Vec::new();
    let addressed = interfaces
        .iter()
        .flat_map(|i| {
            std::iter::once((&i.routing_table, &i.addresses)).chain(
                i.subinterfaces
                    .iter()
                    .map(|s| (&s.routing_table, &s.addresses)),
            )
        })
        .chain(
            aggregates
                .iter()
                .flat_map(|a| &a.subinterfaces)
                .map(|s| (&s.routing_table, &s.addresses)),
        )
        .chain(domains.iter().map(|d| (&d.routing_table, &d.addresses)))
        .filter(|(rt, _)| in_table(rt))
        .flat_map(|(_, addresses)| addresses.iter().map(|a| a.address));
    for address in addressed {
        let prefix = address.trunc();
        if entries.iter().any(|e| e.prefix == prefix) {
            continue;
        }
        entries.push(RibEntry {
            prefix,
            next_hops: vec![(address.addr(), None).into()],
            source: RouteSource::Connected,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        });
    }
    entries
}

/// Computes the `bgp_client::RedistributeTarget` to publish for `table`,
/// given the just-fetched `cfg` and this resync's freshly recomputed best
/// routes (`new_rib.best_routes()`). Pure and unit-tested directly.
///
/// Redistribution forwards every `RouteSource::Static` entry, v4 and v6
/// alike (nos-bgp negotiates MP-BGP per peer independently), only when
/// `table.redistribute` holds a `from Static to Bgp` rule (other rules, for
/// OSPF/OSPFv3, feed their own targets independently).
fn compute_redistribute_target(
    cfg: &Config,
    table_name: &str,
    routes: &HashMap<IpNet, RibEntry>,
) -> bgp_client::RedistributeTarget {
    let Some(table) = cfg.routing_tables.iter().find(|t| t.name == table_name) else {
        return bgp_client::RedistributeTarget::default();
    };

    let active_rule = table
        .redistribute
        .iter()
        .any(|r| r.from == RedistributeSource::Static && r.to == RedistributeTarget::Bgp);

    let redistributed = if active_rule {
        routes
            .values()
            .filter(|entry| entry.source == RouteSource::Static)
            .map(|entry| RedistributedRoute {
                prefix: entry.prefix,
                gateway: entry.next_hops[0].gateway,
            })
            .collect()
    } else {
        Vec::new()
    };

    bgp_client::RedistributeTarget {
        bgp_instance: table.bgp_instance.clone(),
        routes: redistributed,
    }
}

/// One OSPF redistribution feed: the rule target it serves (`Ospf` or
/// `Ospfv3`) and its `ospf_client` task.
/// The VPN export channel and the label registry (`--table-registry-path`).
pub type VpnFeed = (watch::Sender<VpnTarget>, PathBuf);

pub type OspfFeed = (
    RedistributeTarget,
    watch::Sender<ospf_client::RedistributeTarget>,
);

/// The OSPF-redistribution analogue of `compute_redistribute_target` — same
/// shape, matching `to` (`Ospf` or `Ospfv3`) instead of `to: Bgp` and
/// populating `ospf_client::RedistributeTarget` with the table's
/// `ospf_instance` or `ospfv3_instance`. `OSPFv3` gets the IPv6 routes only.
fn compute_redistribute_target_ospf(
    cfg: &Config,
    table_name: &str,
    routes: &HashMap<IpNet, RibEntry>,
    to: RedistributeTarget,
) -> ospf_client::RedistributeTarget {
    let Some(table) = cfg.routing_tables.iter().find(|t| t.name == table_name) else {
        return ospf_client::RedistributeTarget::default();
    };
    let v3 = to == RedistributeTarget::Ospfv3;
    let active_rule = table
        .redistribute
        .iter()
        .any(|r| r.from == RedistributeSource::Static && r.to == to);

    let redistributed = if active_rule {
        routes
            .values()
            .filter(|entry| entry.source == RouteSource::Static)
            .filter(|entry| !v3 || matches!(entry.prefix, IpNet::V6(_)))
            .map(|entry| RedistributedRoute {
                prefix: entry.prefix,
                gateway: entry.next_hops[0].gateway,
            })
            .collect()
    } else {
        Vec::new()
    };

    ospf_client::RedistributeTarget {
        instance: if v3 {
            table.ospfv3_instance.clone()
        } else {
            table.ospf_instance.clone()
        },
        routes: redistributed,
    }
}

/// Local copy of `nos-watchdog::supervisor::wait_or_shutdown` — not
/// imported, per the star-dependency rule.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use nos_proto::Redistribute;
    use nos_proto::RoutingTable;

    fn cfg_with_table(table: RoutingTable) -> Config {
        Config {
            routing_tables: vec![table],
            ..Default::default()
        }
    }

    fn static_entry(prefix: &str, gateway: &str) -> RibEntry {
        RibEntry {
            prefix: prefix.parse().unwrap(),
            next_hops: vec![(gateway.parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        }
    }

    fn addrs(list: &[&str]) -> Vec<nos_proto::InterfaceAddress> {
        list.iter()
            .map(|a| nos_proto::InterfaceAddress {
                address: a.parse().unwrap(),
                label: None,
            })
            .collect()
    }

    fn iface(
        name: &str,
        flat: (&[&str], Option<&str>),
        subs: &[(u16, &[&str], Option<&str>)],
    ) -> InterfaceStatus {
        InterfaceStatus {
            name: name.into(),
            addresses: addrs(flat.0),
            routing_table: flat.1.map(String::from),
            switching_profile: None,
            port_aggregate: None,
            mtu: 1500,
            subinterfaces: subs
                .iter()
                .map(|(tag, a, rt)| nos_proto::SubinterfaceStatus {
                    mtu: 1500,
                    tag: *tag,
                    addresses: addrs(a),
                    routing_table: rt.map(String::from),
                    link_local_address: None,
                })
                .collect(),
            link_local_address: None,
            err_disabled: false,
        }
    }

    fn domain(name: &str, a: &[&str], rt: Option<&str>) -> BroadcastDomainStatus {
        BroadcastDomainStatus {
            name: name.into(),
            addresses: addrs(a),
            routing_table: rt.map(String::from),
            link_local_address: None,
            bridge_name: None,
        }
    }

    #[test]
    fn connected_entries_cover_loopback_subinterface_bond_and_svi_addresses_of_this_table() {
        let interfaces = vec![
            iface("loopback-rt1", (&["203.0.113.1/32"], Some("rt1")), &[]),
            iface(
                "eth0",
                (&[], None),
                &[
                    (0, &["10.50.0.2/24"], Some("rt1")),
                    (300, &["192.0.2.1/24", "2001:db8::1/64"], Some("rt1")),
                    (301, &["10.99.0.1/24"], Some("rt2")),
                ],
            ),
            iface("loopback-rt2", (&["203.0.113.2/32"], Some("rt2")), &[]),
        ];
        let domains = vec![
            domain("bd-svi", &["203.0.113.65/28"], Some("rt1")),
            domain("bd-other", &["203.0.113.81/28"], Some("rt2")),
        ];
        let aggregates = vec![nos_proto::PortAggregateStatus {
            name: "bond1".into(),
            mode: nos_proto::PortAggregateMode::Xor,
            switching_profile: None,
            mtu: 1500,
            subinterfaces: iface(
                "bond1",
                (&[], None),
                &[
                    (0, &["198.51.100.1/29"], Some("rt1")),
                    (10, &["198.51.100.9/29"], Some("rt2")),
                ],
            )
            .subinterfaces,
            link_local_address: None,
            bond_name: None,
            err_disabled: false,
        }];
        let mut got: Vec<(String, String)> =
            connected_entries("rt1", &interfaces, &aggregates, &domains)
                .into_iter()
                .map(|e| {
                    assert_eq!(e.source, RouteSource::Connected);
                    (e.prefix.to_string(), e.next_hops[0].gateway.to_string())
                })
                .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("10.50.0.0/24".into(), "10.50.0.2".into()),
                ("192.0.2.0/24".into(), "192.0.2.1".into()),
                ("198.51.100.0/29".into(), "198.51.100.1".into()),
                ("2001:db8::/64".into(), "2001:db8::1".into()),
                ("203.0.113.1/32".into(), "203.0.113.1".into()),
                ("203.0.113.64/28".into(), "203.0.113.65".into()),
            ]
        );
    }

    #[test]
    fn connected_entries_keep_first_address_for_a_prefix_seen_twice() {
        let interfaces = vec![iface(
            "eth0",
            (&[], None),
            &[(0, &["10.0.0.1/24", "10.0.0.2/24"], Some("rt1"))],
        )];
        let got = connected_entries("rt1", &interfaces, &[], &[]);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].next_hops[0].gateway,
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn remote_lfa_follows_the_tables_ospf_instance() {
        let mut cfg = cfg_with_table(RoutingTable {
            name: "rt1".into(),
            ospf_instance: Some("o1".into()),
            ..Default::default()
        });
        cfg.ospf_instances.push(nos_proto::OspfInstance {
            name: "o1".into(),
            ..Default::default()
        });
        assert!(!remote_lfa(&cfg, "rt1"));
        cfg.ospf_instances[0].remote_lfa = true;
        assert!(remote_lfa(&cfg, "rt1"));
        assert!(!remote_lfa(&cfg, "rt2"));
    }

    #[test]
    fn table_not_found_publishes_idle_target() {
        let cfg = Config::default();
        let target = compute_redistribute_target(&cfg, "rt1", &HashMap::new());
        assert_eq!(target, bgp_client::RedistributeTarget::default());
    }

    #[test]
    fn no_redistribute_rule_publishes_bgp_instance_with_empty_routes() {
        let table = RoutingTable {
            rest_api: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: Vec::new(),
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = static_entry("10.0.0.0/24", "10.0.0.1");
        routes.insert(entry.prefix, entry);

        let target = compute_redistribute_target(&cfg, "rt1", &routes);
        assert_eq!(target.bgp_instance.as_deref(), Some("bgp1"));
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    #[test]
    fn active_rule_redistributes_static_ipv4_routes() {
        let table = RoutingTable {
            rest_api: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: vec![Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
                metric: None,
                metric_type: None,
            }],
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = static_entry("10.0.0.0/24", "10.0.0.1");
        routes.insert(entry.prefix, entry);

        let target = compute_redistribute_target(&cfg, "rt1", &routes);
        assert_eq!(target.bgp_instance.as_deref(), Some("bgp1"));
        assert_eq!(target.routes.len(), 1);
        assert_eq!(target.routes[0].prefix, "10.0.0.0/24".parse().unwrap());
        assert_eq!(
            target.routes[0].gateway,
            "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn active_rule_skips_bgp_sourced_routes() {
        let table = RoutingTable {
            rest_api: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: vec![Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
                metric: None,
                metric_type: None,
            }],
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        routes.insert(
            prefix,
            RibEntry {
                prefix,
                next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
                source: RouteSource::Bgp,
                backup: None,
                backup_interface_id: None,
                backup_tunnel: false,
            },
        );

        let target = compute_redistribute_target(&cfg, "rt1", &routes);
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    #[test]
    fn active_rule_redistributes_static_ipv6_routes_too() {
        let table = RoutingTable {
            rest_api: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: vec![Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
                metric: None,
                metric_type: None,
            }],
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = RibEntry {
            prefix: "2001:db8::/32".parse().unwrap(),
            next_hops: vec![("2001:db8::1".parse().unwrap(), None).into()],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        };
        routes.insert(entry.prefix, entry);

        let target = compute_redistribute_target(&cfg, "rt1", &routes);
        assert_eq!(
            target.routes,
            vec![nos_proto::RedistributedRoute {
                prefix: "2001:db8::/32".parse().unwrap(),
                gateway: "2001:db8::1".parse().unwrap(),
            }]
        );
    }

    #[test]
    fn ospf_table_not_found_publishes_idle_target() {
        let cfg = Config::default();
        let target = compute_redistribute_target_ospf(
            &cfg,
            "rt1",
            &HashMap::new(),
            RedistributeTarget::Ospf,
        );
        assert_eq!(target, ospf_client::RedistributeTarget::default());
    }

    #[test]
    fn ospf_no_redistribute_rule_publishes_ospf_instance_with_empty_routes() {
        let table = RoutingTable {
            rest_api: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: Some("ospf1".into()),
            static_routing_instance: None,
            redistribute: Vec::new(),
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = static_entry("10.0.0.0/24", "10.0.0.1");
        routes.insert(entry.prefix, entry);

        let target =
            compute_redistribute_target_ospf(&cfg, "rt1", &routes, RedistributeTarget::Ospf);
        assert_eq!(target.instance.as_deref(), Some("ospf1"));
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    #[test]
    fn ospf_active_rule_redistributes_static_ipv4_routes() {
        let table = RoutingTable {
            rest_api: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: Some("ospf1".into()),
            static_routing_instance: None,
            redistribute: vec![Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Ospf,
                policy: None,
                metric: None,
                metric_type: None,
            }],
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = static_entry("10.0.0.0/24", "10.0.0.1");
        routes.insert(entry.prefix, entry);

        let target =
            compute_redistribute_target_ospf(&cfg, "rt1", &routes, RedistributeTarget::Ospf);
        assert_eq!(target.instance.as_deref(), Some("ospf1"));
        assert_eq!(target.routes.len(), 1);
        assert_eq!(target.routes[0].prefix, "10.0.0.0/24".parse().unwrap());
    }

    #[test]
    fn rules_for_every_target_feed_independently() {
        let rule = |to| Redistribute {
            from: RedistributeSource::Static,
            to,
            policy: None,
            metric: None,
            metric_type: None,
        };
        let table = RoutingTable {
            rest_api: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: Some("o3".into()),
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: Some("ospf1".into()),
            static_routing_instance: None,
            redistribute: vec![
                rule(RedistributeTarget::Bgp),
                rule(RedistributeTarget::Ospf),
                rule(RedistributeTarget::Ospfv3),
            ],
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        for (p, gw) in [
            ("10.0.0.0/24", "10.0.0.1"),
            ("2001:db8::/48", "2001:db8::1"),
        ] {
            let e = static_entry(p, gw);
            routes.insert(e.prefix, e);
        }
        assert_eq!(
            compute_redistribute_target(&cfg, "rt1", &routes)
                .routes
                .len(),
            2
        );
        let ospf = compute_redistribute_target_ospf(&cfg, "rt1", &routes, RedistributeTarget::Ospf);
        assert_eq!(ospf.routes.len(), 2);
        let v3 = compute_redistribute_target_ospf(&cfg, "rt1", &routes, RedistributeTarget::Ospfv3);
        assert_eq!(v3.routes.len(), 1);
    }

    #[test]
    fn ospf_active_rule_skips_bgp_sourced_routes() {
        let table = RoutingTable {
            rest_api: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: Some("ospf1".into()),
            static_routing_instance: None,
            redistribute: vec![Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Ospf,
                policy: None,
                metric: None,
                metric_type: None,
            }],
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let prefix: IpNet = "10.0.0.0/24".parse().unwrap();
        routes.insert(
            prefix,
            RibEntry {
                prefix,
                next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
                source: RouteSource::Bgp,
                backup: None,
                backup_interface_id: None,
                backup_tunnel: false,
            },
        );

        let target =
            compute_redistribute_target_ospf(&cfg, "rt1", &routes, RedistributeTarget::Ospf);
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    #[test]
    fn ospfv3_rule_redistributes_static_ipv6_routes_only() {
        let table = RoutingTable {
            rest_api: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: Some("v3".into()),
            name: "rt1".into(),
            bgp_instance: None,
            ospf_instance: Some("ospf1".into()),
            static_routing_instance: None,
            redistribute: vec![Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Ospfv3,
                policy: None,
                metric: None,
                metric_type: None,
            }],
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        for entry in [
            static_entry("10.0.0.0/24", "10.0.0.1"),
            static_entry("2001:db8:e::/48", "2001:db8::1"),
        ] {
            routes.insert(entry.prefix, entry);
        }

        let v3 = compute_redistribute_target_ospf(&cfg, "rt1", &routes, RedistributeTarget::Ospfv3);
        assert_eq!(v3.instance.as_deref(), Some("v3"));
        assert_eq!(v3.routes.len(), 1);
        assert_eq!(v3.routes[0].prefix, "2001:db8:e::/48".parse().unwrap());
        // The OSPFv2 feed of the same table carries nothing.
        let v2 = compute_redistribute_target_ospf(&cfg, "rt1", &routes, RedistributeTarget::Ospf);
        assert_eq!(v2.instance.as_deref(), Some("ospf1"));
        assert_eq!(v2.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }

    #[test]
    fn ospf_rule_does_not_redistribute_when_target_is_bgp() {
        let table = RoutingTable {
            rest_api: None,
            evpn: nos_proto::RoutingTableEvpn::default(),
            vpn: nos_proto::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".into(),
            bgp_instance: Some("bgp1".into()),
            ospf_instance: Some("ospf1".into()),
            static_routing_instance: None,
            redistribute: vec![Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
                metric: None,
                metric_type: None,
            }],
        };
        let cfg = cfg_with_table(table);
        let mut routes = HashMap::new();
        let entry = static_entry("10.0.0.0/24", "10.0.0.1");
        routes.insert(entry.prefix, entry);

        let target =
            compute_redistribute_target_ospf(&cfg, "rt1", &routes, RedistributeTarget::Ospf);
        assert_eq!(target.routes, [] as [nos_proto::RedistributedRoute; 0]);
    }
}

#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod resync_tests;
