//! `resync`, `run` and the IPC queries against the shared fakes (#344, #347):
//! a real `Rib`, a recording `RibDriver`, real `watch` channels for the five
//! push targets, and fake configd/watchdog/interfaced/ribd servers.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use nos_proto::{
    BfdProfile, BroadcastDomain, BroadcastDomainStatus, ConfigDiff, InterfaceAddress,
    InterfaceStatus, PortAggregate, PortAggregateStatus, RoutingTable, RoutingTableEvpn,
    SourceAddress, StaticRoute, StaticRoutingInstance, Subinterface, SubinterfaceStatus,
};
use nos_test_support::{Fake, Fakes};

use super::*;
use crate::driver::{DriverError, RibDriver};
use crate::evpn::Mac;

// ---------------------------------------------------------------- fixtures

/// Records what the reconciler asks of the kernel; each call can be made to
/// fail.
#[derive(Default)]
struct Rec {
    applies: Mutex<Vec<HashMap<IpNet, RibEntry>>>,
    deltas: Mutex<Vec<HashMap<IpNet, Option<RibEntry>>>>,
    tunnels: Mutex<Vec<(String, bool)>>,
    l3: Mutex<Vec<Option<u32>>>,
    teardowns: AtomicUsize,
    rmac: Mutex<Option<Mac>>,
    /// Each `sync_mpls`: label, underlay, and how many `apply`s preceded it.
    mpls: Mutex<Vec<MplsCall>>,
    fail_mpls: AtomicBool,
    fail_apply: AtomicBool,
    fail_delta: AtomicBool,
    /// When set, `apply` signals `entered` then waits for `release` (#653).
    block_apply: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    fail_tunnel: AtomicBool,
    fail_l3: AtomicBool,
    fail_teardown: AtomicBool,
    /// Each `keep_stale` call, in order (#654).
    keep: Mutex<Vec<bool>>,
}

impl Rec {
    fn last_apply(&self) -> Option<HashMap<IpNet, RibEntry>> {
        self.applies.lock().unwrap().last().cloned()
    }
}

/// One `sync_mpls`: label, underlay, and how many `apply`s preceded it.
type MplsCall = (Option<u32>, Option<String>, usize);

fn err() -> DriverError {
    DriverError::Other("boom".into())
}

#[async_trait]
impl RibDriver for Rec {
    async fn apply(
        &self,
        _table: &str,
        best: &HashMap<IpNet, RibEntry>,
    ) -> Result<(), DriverError> {
        self.applies.lock().unwrap().push(best.clone());
        if self.block_apply.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        if self.fail_apply.load(Ordering::SeqCst) {
            return Err(err());
        }
        Ok(())
    }
    fn keep_stale(&self, on: bool) {
        self.keep.lock().unwrap().push(on);
    }
    async fn apply_delta(
        &self,
        _table: &str,
        changes: &HashMap<IpNet, Option<RibEntry>>,
    ) -> Result<(), DriverError> {
        self.deltas.lock().unwrap().push(changes.clone());
        if self.fail_delta.load(Ordering::SeqCst) {
            return Err(err());
        }
        Ok(())
    }
    async fn teardown(&self, _table: &str) -> Result<(), DriverError> {
        self.teardowns.fetch_add(1, Ordering::SeqCst);
        if self.fail_teardown.load(Ordering::SeqCst) {
            return Err(err());
        }
        Ok(())
    }
    async fn vrf_name(&self, _table: &str) -> Option<String> {
        None
    }
    async fn table_id(&self, _table: &str) -> Option<u32> {
        None
    }
    async fn sync_tunnel(&self, table: &str, enabled: bool) -> Result<(), DriverError> {
        self.tunnels.lock().unwrap().push((table.into(), enabled));
        if self.fail_tunnel.load(Ordering::SeqCst) {
            return Err(err());
        }
        Ok(())
    }
    async fn sync_l3vni(
        &self,
        _table: &str,
        l3: Option<&L3Vni>,
        _remotes: &BTreeMap<IpAddr, Mac>,
    ) -> Result<Option<Mac>, DriverError> {
        self.l3.lock().unwrap().push(l3.map(|l| l.vni));
        if self.fail_l3.load(Ordering::SeqCst) {
            return Err(err());
        }
        Ok(*self.rmac.lock().unwrap())
    }
    async fn sync_mpls(
        &self,
        _table: &str,
        m: Option<&crate::driver::Mpls>,
    ) -> Result<(), DriverError> {
        let applies = self.applies.lock().unwrap().len();
        self.mpls.lock().unwrap().push((
            m.map(|m| m.label),
            m.and_then(|m| m.underlay.clone()),
            applies,
        ));
        if self.fail_mpls.load(Ordering::SeqCst) {
            return Err(err());
        }
        Ok(())
    }
}

fn addr(a: &str, label: Option<&str>) -> InterfaceAddress {
    InterfaceAddress {
        address: a.parse().unwrap(),
        label: label.map(Into::into),
    }
}

fn if_status(name: &str, flat: &[&str], tag0: &[&str]) -> InterfaceStatus {
    InterfaceStatus {
        name: name.into(),
        addresses: flat.iter().map(|a| addr(a, None)).collect(),
        routing_table: (!flat.is_empty()).then(|| "rt1".to_string()),
        switching_profile: None,
        port_aggregate: None,
        mtu: 1500,
        subinterfaces: if tag0.is_empty() {
            vec![]
        } else {
            vec![SubinterfaceStatus {
                mtu: 1500,
                tag: 0,
                addresses: tag0.iter().map(|a| addr(a, None)).collect(),
                routing_table: Some("rt1".into()),
                link_local_address: None,
            }]
        },
        link_local_address: None,
        err_disabled: false,
    }
}

fn static_route(subnet: &str, gateway: &str, bfd: Option<&str>) -> StaticRoute {
    StaticRoute {
        subnet: subnet.parse().unwrap(),
        gateway: gateway.parse().unwrap(),
        bfd: bfd.map(Into::into),
    }
}

fn redistribute(to: RedistributeTarget) -> nos_proto::Redistribute {
    nos_proto::Redistribute {
        from: RedistributeSource::Static,
        to,
        policy: None,
        metric: None,
        metric_type: None,
    }
}

/// `rt1` owning BGP `b1`, OSPF `o1` and `OSPFv3` `o3`, redistributing statics
/// to all three, with one v4 and one v6 static route.
fn base_cfg() -> Config {
    Config {
        routing_tables: vec![RoutingTable {
            name: "rt1".into(),
            bgp_instance: Some("b1".into()),
            static_routing_instance: Some("s1".into()),
            ospf_instance: Some("o1".into()),
            ospfv3_instance: Some("o3".into()),
            redistribute: vec![
                redistribute(RedistributeTarget::Bgp),
                redistribute(RedistributeTarget::Ospf),
                redistribute(RedistributeTarget::Ospfv3),
            ],
            ..Default::default()
        }],
        static_routing_instances: vec![StaticRoutingInstance {
            name: "s1".into(),
            routes: vec![
                static_route("10.9.0.0/24", "10.0.0.2", None),
                static_route("2001:db8:9::/48", "2001:db8::2", None),
            ],
        }],
        ..Default::default()
    }
}

fn bgp_instance(underlay_table: &str) -> nos_proto::BgpInstance {
    serde_norway::from_str(&format!(
        "name: b1\nasn: 65001\nrouter_id: 1.1.1.1\npeers: []\npeer_groups: []\nrouting_table: {underlay_table}\n"
    ))
    .unwrap()
}

fn evpn_cfg(source: SourceAddress) -> Config {
    let mut cfg = base_cfg();
    cfg.bgp_instances = vec![bgp_instance("rt1")];
    cfg.routing_tables[0].evpn = RoutingTableEvpn {
        l3_vni: Some(5000),
        rd: Some("65000:5000".into()),
        route_targets_import: vec!["65000:5000".into(), "not-an-rt".into()],
        route_targets_export: vec!["65000:5001".into()],
        vtep_source: Some(source),
        bgp_instance: Some("b1".into()),
    };
    cfg
}

struct Env {
    fakes: Fakes,
    rib: Arc<RwLock<Rib>>,
    kernel: Arc<KernelGate>,
    rec: Arc<Rec>,
    bgp_tx: watch::Sender<bgp_client::RedistributeTarget>,
    bgp_rx: watch::Receiver<bgp_client::RedistributeTarget>,
    ospf: Vec<OspfFeed>,
    ospf_rx: Vec<watch::Receiver<ospf_client::RedistributeTarget>>,
    evpn_tx: watch::Sender<EvpnTarget>,
    evpn_rx: watch::Receiver<EvpnTarget>,
    vpn: VpnFeed,
    vpn_rx: watch::Receiver<VpnTarget>,
    registry_dir: tempfile::TempDir,
    bfd_tx: watch::Sender<bfd_client::Target>,
    bfd_target_rx: watch::Receiver<bfd_client::Target>,
    bfd_up_tx: watch::Sender<bfd_client::UpSet>,
    bfd_up_rx: watch::Receiver<bfd_client::UpSet>,
}

impl Env {
    fn with(which: &[Fake]) -> Self {
        let (bgp_tx, bgp_rx) = watch::channel(bgp_client::RedistributeTarget::default());
        let (ospf_tx, ospf_r) = watch::channel(ospf_client::RedistributeTarget::default());
        let (ospfv3_tx, ospfv3_r) = watch::channel(ospf_client::RedistributeTarget::default());
        let (evpn_tx, evpn_rx) = watch::channel(EvpnTarget::default());
        let (vpn_tx, vpn_rx) = watch::channel(VpnTarget::default());
        let registry = tempfile::tempdir().unwrap();
        let (bfd_tx, bfd_target_rx) = watch::channel(bfd_client::Target::default());
        let (bfd_up_tx, bfd_up_rx) = watch::channel(bfd_client::UpSet::default());
        Env {
            fakes: Fakes::start(which),
            rib: Arc::new(RwLock::new(Rib::new())),
            kernel: Arc::default(),
            rec: Arc::new(Rec::default()),
            bgp_tx,
            bgp_rx,
            ospf: vec![
                (RedistributeTarget::Ospf, ospf_tx),
                (RedistributeTarget::Ospfv3, ospfv3_tx),
            ],
            ospf_rx: vec![ospf_r, ospfv3_r],
            evpn_tx,
            evpn_rx,
            vpn: (vpn_tx, registry.path().join("table-ids.yaml")),
            vpn_rx,
            registry_dir: registry,
            bfd_tx,
            bfd_target_rx,
            bfd_up_tx,
            bfd_up_rx,
        }
    }

    /// Every fake up; `eth0` carries 10.0.0.1/24 in `rt1`.
    fn ready(cfg: Config) -> Self {
        let e = Self::with(&[
            Fake::Configd(cfg),
            Fake::Watchdog,
            Fake::Ribd("rt1".into()),
            Fake::Interfaced,
        ]);
        e.ifaced()
            .set_interface(if_status("eth0", &[], &["10.0.0.1/24"]));
        e
    }

    fn ifaced(&self) -> &nos_test_support::FakeInterfaced {
        self.fakes.interfaced.as_ref().unwrap()
    }

    fn configd(&self) -> &nos_test_support::FakeConfigd {
        self.fakes.configd.as_ref().unwrap()
    }

    async fn resync(&self) {
        resync(
            &self.fakes.config_socket(),
            &self.fakes.watchdog_socket(),
            "rt1",
            &self.rib,
            &self.kernel,
            self.rec.as_ref(),
            &self.bgp_tx,
            &self.ospf,
            &self.evpn_tx,
            &self.vpn,
            &self.bfd_tx,
            &self.bfd_up_rx,
        )
        .await;
    }

    async fn best(&self) -> HashMap<IpNet, RibEntry> {
        self.rib.read().await.best_routes()
    }
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn sorted_prefixes(routes: &[RedistributedRoute]) -> Vec<IpNet> {
    let mut v: Vec<IpNet> = routes.iter().map(|r| r.prefix).collect();
    v.sort();
    v
}

// ------------------------------------------------------------------ resync

#[tokio::test]
async fn resync_builds_the_rib_programs_the_kernel_and_feeds_every_target() {
    let e = Env::ready(base_cfg());
    e.resync().await;

    let best = e.best().await;
    assert_eq!(best[&net("10.9.0.0/24")].source, RouteSource::Static);
    assert_eq!(best[&net("10.0.0.0/24")].source, RouteSource::Connected);

    // The kernel got the static routes, never the Connected one (left to it).
    let applied = e.rec.last_apply().expect("applied");
    assert!(applied.contains_key(&net("10.9.0.0/24")));
    assert!(!applied.contains_key(&net("10.0.0.0/24")));
    assert_eq!(*e.rec.tunnels.lock().unwrap(), [("rt1".to_string(), false)]);

    let bgp = e.bgp_rx.borrow().clone();
    assert_eq!(bgp.bgp_instance.as_deref(), Some("b1"));
    assert_eq!(
        sorted_prefixes(&bgp.routes),
        [net("10.9.0.0/24"), net("2001:db8:9::/48")]
    );
    let ospf = e.ospf_rx[0].borrow().clone();
    assert_eq!(ospf.instance.as_deref(), Some("o1"));
    assert_eq!(ospf.routes.len(), 2);
    let ospfv3 = e.ospf_rx[1].borrow().clone();
    assert_eq!(ospfv3.instance.as_deref(), Some("o3"));
    assert_eq!(sorted_prefixes(&ospfv3.routes), [net("2001:db8:9::/48")]);
    assert_eq!(*e.evpn_rx.borrow(), EvpnTarget::default(), "no evpn");
}

#[tokio::test]
async fn resync_without_a_config_leaves_everything_alone() {
    // No configd socket at all.
    let e = Env::with(&[Fake::Watchdog, Fake::Interfaced]);
    e.rib.write().await.insert(RibEntry {
        prefix: net("10.7.0.0/24"),
        next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
        source: RouteSource::Static,
        backup: None,
        backup_interface_id: None,
        backup_tunnel: false,
    });
    e.resync().await;
    assert_eq!(e.best().await.len(), 1, "previous RIB kept");
    assert!(e.rec.applies.lock().unwrap().is_empty());
    assert!(!e.bgp_rx.has_changed().unwrap());
    assert!(!e.evpn_rx.has_changed().unwrap());
}

#[tokio::test]
async fn resync_of_a_table_missing_from_config_clears_the_statics() {
    let mut cfg = base_cfg();
    cfg.routing_tables.clear();
    let e = Env::ready(cfg);
    e.rib.write().await.insert(RibEntry {
        prefix: net("10.7.0.0/24"),
        next_hops: vec![("10.0.0.9".parse().unwrap(), None).into()],
        source: RouteSource::Static,
        backup: None,
        backup_interface_id: None,
        backup_tunnel: false,
    });
    e.resync().await;
    let best = e.best().await;
    assert!(!best.contains_key(&net("10.7.0.0/24")), "static cleared");
    assert!(
        best.contains_key(&net("10.0.0.0/24")),
        "connected still known"
    );
    assert_eq!(
        *e.bgp_rx.borrow(),
        bgp_client::RedistributeTarget::default()
    );
    assert_eq!(
        *e.ospf_rx[0].borrow(),
        ospf_client::RedistributeTarget::default()
    );
}

#[tokio::test]
async fn an_unreachable_interfaced_keeps_the_previous_connected_set() {
    let e = Env::ready(base_cfg());
    e.resync().await;
    assert!(e.best().await.contains_key(&net("10.0.0.0/24")));

    // The broker no longer knows nos-interfaced: the set is kept.
    e.fakes
        .watchdog
        .as_ref()
        .unwrap()
        .remove(&ServiceRef::Interfaces);
    e.resync().await;
    assert!(e.best().await.contains_key(&net("10.0.0.0/24")));

    // Back, with the address gone: the set is replaced.
    let p = e.fakes.interface_socket();
    e.fakes
        .watchdog
        .as_ref()
        .unwrap()
        .set(ServiceRef::Interfaces, p);
    e.ifaced().remove_interface("eth0");
    e.resync().await;
    assert!(!e.best().await.contains_key(&net("10.0.0.0/24")));
}

#[tokio::test]
async fn bfd_guarded_routes_wait_for_the_session_and_the_target_moves_once() {
    let mut cfg = base_cfg();
    cfg.bfd_profiles = vec![BfdProfile {
        name: "fast".into(),
        ..Default::default()
    }];
    cfg.static_routing_instances[0].routes =
        vec![static_route("10.9.0.0/24", "10.0.0.2", Some("fast"))];
    let e = Env::ready(cfg);

    e.resync().await;
    assert!(e.bfd_target_rx.has_changed().unwrap());
    assert!(e
        .bfd_target_rx
        .borrow()
        .contains_key(&"10.0.0.2".parse().unwrap()));
    assert!(
        !e.best().await.contains_key(&net("10.9.0.0/24")),
        "held out until the session is up"
    );

    // Same want again: the target does not notify.
    let mut rx = e.bfd_target_rx.clone();
    rx.mark_unchanged();
    e.resync().await;
    assert!(!rx.has_changed().unwrap());

    // The session comes up: the route enters.
    e.bfd_up_tx
        .send(HashSet::from(["10.0.0.2".parse::<IpAddr>().unwrap()]))
        .unwrap();
    e.resync().await;
    assert!(e.best().await.contains_key(&net("10.9.0.0/24")));
}

#[tokio::test]
async fn driver_failures_are_logged_and_the_resync_carries_on() {
    let e = Env::ready(evpn_cfg(SourceAddress::Interface {
        interface: "eth0".into(),
        label: None,
    }));
    e.rec.fail_tunnel.store(true, Ordering::SeqCst);
    e.rec.fail_l3.store(true, Ordering::SeqCst);
    e.rec.fail_apply.store(true, Ordering::SeqCst);
    e.resync().await;
    // Everything was attempted and the targets still went out.
    assert_eq!(e.rec.tunnels.lock().unwrap().len(), 1);
    assert_eq!(*e.rec.l3.lock().unwrap(), [Some(5000)]);
    assert_eq!(e.rec.applies.lock().unwrap().len(), 1);
    assert_eq!(e.bgp_rx.borrow().routes.len(), 2);
}

#[tokio::test]
async fn remote_lfa_asks_the_driver_for_the_tunnel_device() {
    let mut cfg = base_cfg();
    cfg.ospf_instances = vec![nos_proto::OspfInstance {
        name: "o1".into(),
        remote_lfa: true,
        ..Default::default()
    }];
    let e = Env::ready(cfg);
    e.resync().await;
    assert_eq!(*e.rec.tunnels.lock().unwrap(), [("rt1".to_string(), true)]);
}

// --------------------------------------------------------------------- vpn

fn vpn_cfg(label: Option<u32>) -> Config {
    let mut cfg = base_cfg();
    cfg.routing_tables[0].vpn = nos_proto::RoutingTableVpn {
        rd: Some("65000:1".into()),
        route_targets_import: vec![],
        route_targets_export: vec!["65000:1".into()],
        bgp_instance: Some("core".into()),
        label,
        site_of_origin: None,
    };
    cfg
}

/// #580: `vpn` set exports every best route with an allocated label that a
/// reload keeps; unset, the target goes idle (`Full([])` withdraws all).
#[tokio::test]
async fn vpn_set_then_unset_exports_then_withdraws_with_a_stable_label() {
    let e = Env::ready(vpn_cfg(None));
    e.resync().await;
    let target = e.vpn_rx.borrow().clone();
    assert_eq!(target.bgp_instance.as_deref(), Some("core"));
    assert!(!target.routes.is_empty(), "the statics are exported");
    assert!(target.routes.iter().all(|r| r.labels == [1000]));
    assert!(
        target.routes.iter().any(|r| r.prefix == net("10.0.0.0/24")),
        "connected too"
    );
    assert_eq!(e.rib.read().await.vpn_label, Some(1000));
    e.resync().await;
    assert_eq!(e.rib.read().await.vpn_label, Some(1000), "reused");

    e.configd().set_config(base_cfg());
    e.resync().await;
    assert_eq!(*e.vpn_rx.borrow(), VpnTarget::default());
    assert_eq!(e.rib.read().await.vpn_label, None);

    e.configd().set_config(vpn_cfg(Some(77)));
    e.resync().await;
    assert!(e.vpn_rx.borrow().routes.iter().all(|r| r.labels == [77]));
}

/// #581: the label is programmed (with its underlay) before the routes are
/// applied, a label change reaches the driver, and `vpn` unset removes it.
#[tokio::test]
async fn the_mpls_label_is_synced_before_the_routes_and_removed_with_vpn() {
    let mut cfg = vpn_cfg(None);
    cfg.bgp_instances = vec![bgp_instance("rt1")];
    cfg.bgp_instances[0].name = "core".into();
    let e = Env::ready(cfg.clone());
    e.resync().await;
    let rt1 = Some("rt1".to_string());
    assert_eq!(*e.rec.mpls.lock().unwrap(), [(Some(1000), rt1.clone(), 0)]);
    assert_eq!(e.rec.applies.lock().unwrap().len(), 1);
    cfg.routing_tables[0].vpn.label = Some(2000);
    e.configd().set_config(cfg);
    e.resync().await;
    assert_eq!(e.rec.mpls.lock().unwrap()[1], (Some(2000), rt1, 1));
    assert!(e.vpn_rx.borrow().routes.iter().all(|r| r.labels == [2000]));
    e.configd().set_config(base_cfg());
    e.resync().await;
    assert_eq!(e.rec.mpls.lock().unwrap()[2], (None, None, 2));
}

/// #581 decision 1: a label the kernel cannot pop is not advertised.
#[tokio::test]
async fn an_unprogrammable_label_withholds_the_export() {
    let e = Env::ready(vpn_cfg(None));
    e.rec.fail_mpls.store(true, Ordering::SeqCst);
    e.resync().await;
    assert_eq!(*e.vpn_rx.borrow(), VpnTarget::default());
    assert_eq!(e.rib.read().await.vpn_label, Some(1000), "still shown");
    e.rec.fail_mpls.store(false, Ordering::SeqCst);
    e.resync().await;
    assert!(
        !e.vpn_rx.borrow().routes.is_empty(),
        "exported once programmed"
    );
}

#[tokio::test]
async fn a_failed_label_allocation_keeps_the_previous_export() {
    let mut e = Env::ready(vpn_cfg(None));
    // A directory where the registry file should be: unreadable.
    let dir = e.registry_dir.path().join("table-ids.yaml");
    std::fs::create_dir(&dir).unwrap();
    e.vpn.1 = dir;
    e.resync().await;
    assert_eq!(*e.vpn_rx.borrow(), VpnTarget::default());
    assert_eq!(e.rib.read().await.vpn_label, None);
}

// -------------------------------------------------------------------- evpn

#[tokio::test]
async fn an_l3_vni_with_a_resolvable_vtep_is_built_and_originated() {
    let e = Env::ready(evpn_cfg(SourceAddress::Interface {
        interface: "eth0".into(),
        label: None,
    }));
    *e.rec.rmac.lock().unwrap() = Some([0xaa, 0, 0, 0, 0, 1]);
    e.resync().await;

    let l3 = e.rib.read().await.evpn.local.clone().expect("resolved");
    assert_eq!(l3.vni, 5000);
    assert_eq!(l3.vtep, "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(l3.underlay, "eth0");
    assert_eq!(l3.bgp_instance, "b1");
    assert_eq!(l3.rd, nos_proto::evpn_id::parse_rd("65000:5000").unwrap());
    assert_eq!(
        l3.import,
        [nos_proto::evpn_id::parse_rt("65000:5000").unwrap()],
        "the unparsable RT is skipped"
    );
    assert_eq!(l3.export.len(), 1);

    let target = e.evpn_rx.borrow().clone();
    assert_eq!(target.bgp_instance.as_deref(), Some("b1"));
    assert!(!target.routes.is_empty(), "the statics are originated");
}

#[tokio::test]
async fn incremental_evpn_pushes_apply_deltas_and_sync_devices_only_on_remote_changes() {
    use nos_proto::{EvpnKey, EvpnRoute, EvpnUpdate};
    let e = Env::ready(evpn_cfg(SourceAddress::Interface {
        interface: "eth0".into(),
        label: None,
    }));
    *e.rec.rmac.lock().unwrap() = Some([0xaa, 0, 0, 0, 0, 1]);
    e.resync().await;
    let rt = nos_proto::evpn_id::parse_rt("65000:5000").unwrap();
    let route = |p: &str| EvpnRoute {
        key: EvpnKey::IpPrefix {
            rd: [0; 8],
            prefix: p.parse().unwrap(),
        },
        vni: 5000,
        next_hop: "10.50.0.3".parse().unwrap(),
        ext_communities: vec![rt, nos_proto::evpn_id::router_mac_ext([2; 6])],
        esi: [0; 10],
        l3_vni: None,
    };
    let push = |u: EvpnUpdate| {
        crate::server::apply_evpn_route_update("rt1", &e.rib, &e.kernel, e.rec.as_ref(), u)
    };
    let counts = || {
        (
            e.rec.applies.lock().unwrap().len(),
            e.rec.l3.lock().unwrap().len(),
            e.rec.deltas.lock().unwrap().len(),
        )
    };
    let (applies, l3, deltas) = counts();

    // First route of the VTEP: devices synced, one delta, no table apply.
    push(EvpnUpdate::Add(route("10.2.0.0/24"))).await;
    assert_eq!(counts(), (applies, l3 + 1, deltas + 1));
    // Same VTEP, another prefix: no device sync.
    push(EvpnUpdate::Add(route("10.3.0.0/24"))).await;
    assert_eq!(counts(), (applies, l3 + 1, deltas + 2));
    // Identical resend: nothing at all.
    push(EvpnUpdate::Add(route("10.3.0.0/24"))).await;
    assert_eq!(counts(), (applies, l3 + 1, deltas + 2));
    // Removing one of two: delta only; removing the last: the VTEP leaves too.
    push(EvpnUpdate::Remove(route("10.2.0.0/24").key)).await;
    assert_eq!(counts(), (applies, l3 + 1, deltas + 3));
    push(EvpnUpdate::Remove(route("10.3.0.0/24").key)).await;
    assert_eq!(counts(), (applies, l3 + 2, deltas + 4));
    assert!(e
        .rec
        .deltas
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .values()
        .all(Option::is_none));
    // A Full still resyncs the whole table.
    push(EvpnUpdate::Full(vec![route("10.2.0.0/24")])).await;
    assert_eq!(counts(), (applies + 1, l3 + 3, deltas + 4));
    // A failed delta marks the table dirty (#653).
    assert!(!e.kernel.take_dirty_for_test());
    e.rec.fail_delta.store(true, Ordering::SeqCst);
    push(EvpnUpdate::Add(route("10.3.0.0/24"))).await;
    assert!(e.kernel.take_dirty_for_test());
}

/// A dirty notification with nothing dirty (already cleaned by a resync) does nothing.
#[tokio::test]
async fn a_spurious_dirty_notification_applies_nothing() {
    let e = Env::ready(base_cfg());
    assert!(!dirty_apply("rt1", &e.rib, &e.kernel, e.rec.as_ref()).await);
    assert!(e.rec.applies.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_l3_vni_without_the_drivers_router_mac_originates_nothing() {
    let e = Env::ready(evpn_cfg(SourceAddress::Interface {
        interface: "eth0".into(),
        label: None,
    }));
    e.resync().await;
    assert!(e.rib.read().await.evpn.local.is_some());
    assert_eq!(*e.evpn_rx.borrow(), EvpnTarget::default());
}

#[tokio::test]
async fn an_unresolvable_vtep_keeps_the_previous_l3_vni() {
    let e = Env::ready(evpn_cfg(SourceAddress::Interface {
        interface: "eth0".into(),
        label: None,
    }));
    e.resync().await;
    assert!(e.rib.read().await.evpn.local.is_some());
    e.ifaced().remove_interface("eth0");
    e.resync().await;
    assert!(
        e.rib.read().await.evpn.local.is_some(),
        "a transient interfaced failure does not tear the devices down"
    );
}

#[tokio::test]
async fn a_loopback_vtep_is_resolved_through_the_underlay_tables_ribd() {
    let mut cfg = evpn_cfg(SourceAddress::Loopback { label: None });
    cfg.bgp_instances = vec![bgp_instance("rt1")];
    let e = Env::ready(cfg);
    e.fakes.ribd["rt1"].set_table_id(Some(7));
    e.ifaced().set_interface(if_status(
        &format!("{}rt1", nos_proto::LOOPBACK_PREFIX),
        &["192.0.2.1/32"],
        &[],
    ));
    e.resync().await;
    let l3 = e.rib.read().await.evpn.local.clone().expect("resolved");
    assert_eq!(l3.vtep, "192.0.2.1".parse::<IpAddr>().unwrap());
    assert_eq!(l3.underlay, "lo7");
}

#[tokio::test]
async fn resolve_l3vni_cases() {
    let f = Fakes::start(&[Fake::Watchdog, Fake::Interfaced]);
    let wd = f.watchdog_socket();
    let cfg = base_cfg();
    // No such table, and a table without an L3 VNI.
    assert_eq!(resolve_l3vni(&wd, &cfg, "nope").await, Some(None));
    assert_eq!(resolve_l3vni(&wd, &cfg, "rt1").await, Some(None));
    // A VNI whose interface the broker cannot answer for.
    let cfg = evpn_cfg(SourceAddress::Interface {
        interface: "eth0".into(),
        label: None,
    });
    assert_eq!(resolve_l3vni(&wd, &cfg, "rt1").await, None);
}

// --------------------------------------------------------- fetch_connected

#[tokio::test]
async fn fetch_connected_needs_the_interfaces_endpoint() {
    let f = Fakes::start(&[Fake::Watchdog]);
    assert!(fetch_connected(&f.watchdog_socket(), &base_cfg(), "rt1")
        .await
        .is_none());
}

#[tokio::test]
async fn fetch_connected_asks_for_aggregates_and_domains_only_when_the_table_uses_them() {
    let f = Fakes::start(&[Fake::Watchdog, Fake::Interfaced]);
    let ifaced = f.interfaced.as_ref().unwrap();
    ifaced.set_interface(if_status("eth0", &[], &["10.0.0.1/24"]));
    ifaced.set_port_aggregate(
        "bond1",
        PortAggregateStatus {
            name: "bond1".into(),
            mode: nos_proto::PortAggregateMode::Xor,
            switching_profile: None,
            mtu: 1500,
            subinterfaces: if_status("bond1", &[], &["198.51.100.1/29"]).subinterfaces,
            link_local_address: None,
            bond_name: None,
            err_disabled: false,
        },
    );
    ifaced.set_broadcast_domain(
        "bd1",
        BroadcastDomainStatus {
            name: "bd1".into(),
            addresses: vec![addr("203.0.113.65/28", None)],
            routing_table: Some("rt1".into()),
            link_local_address: None,
            bridge_name: None,
        },
    );
    let wd = f.watchdog_socket();
    let prefixes = |v: Option<Vec<RibEntry>>| {
        let mut p: Vec<String> = v
            .expect("answered")
            .iter()
            .map(|e| e.prefix.to_string())
            .collect();
        p.sort();
        p
    };

    // Neither a bond subinterface nor a domain in the table: not asked for.
    let mut cfg = Config::default();
    assert_eq!(
        prefixes(fetch_connected(&wd, &cfg, "rt1").await),
        ["10.0.0.0/24"]
    );

    // A bond subinterface in the table, and an addressed domain in it.
    cfg.port_aggregates = vec![PortAggregate {
        name: "bond1".into(),
        subinterfaces: vec![Subinterface {
            routing_table: Some("rt1".into()),
            ..Default::default()
        }],
        ..Default::default()
    }];
    cfg.broadcast_domains = vec![BroadcastDomain {
        name: "bd1".into(),
        routing_table: Some("rt1".into()),
        addresses: vec![addr("203.0.113.65/28", None)],
        ..Default::default()
    }];
    assert_eq!(
        prefixes(fetch_connected(&wd, &cfg, "rt1").await),
        ["10.0.0.0/24", "198.51.100.0/29", "203.0.113.64/28"]
    );

    // A domain the interfaced does not know fails the whole fetch.
    cfg.broadcast_domains.push(BroadcastDomain {
        name: "ghost".into(),
        routing_table: Some("rt1".into()),
        addresses: vec![addr("203.0.113.97/28", None)],
        ..Default::default()
    });
    assert!(fetch_connected(&wd, &cfg, "rt1").await.is_none());

    // ... but one in another table, or without addresses, is never asked for.
    cfg.broadcast_domains[1].routing_table = Some("rt2".into());
    assert!(fetch_connected(&wd, &cfg, "rt1").await.is_some());
}

// -------------------------------------------------------------- the loop

struct Running {
    env: Env,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

fn start(e: Env) -> Running {
    let (shutdown, rx) = watch::channel(false);
    let task = tokio::spawn(super::run(
        e.fakes.config_socket(),
        e.fakes.watchdog_socket(),
        "rt1".into(),
        e.rib.clone(),
        e.kernel.clone(),
        e.rec.clone(),
        e.bgp_tx.clone(),
        e.ospf.clone(),
        e.evpn_tx.clone(),
        e.vpn.clone(),
        e.bfd_tx.clone(),
        e.bfd_up_rx.clone(),
        rx,
    ));
    Running {
        env: e,
        shutdown,
        task,
    }
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..600 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

impl Running {
    /// Stops `run`, polling in small steps (a single long timeout lets the
    /// paused clock jump past work on the blocking pool).
    async fn stop(self) -> Env {
        self.shutdown.send(true).unwrap();
        until("run to stop", || self.task.is_finished()).await;
        self.task.await.unwrap();
        self.env
    }
}

#[tokio::test(start_paused = true)]
async fn run_resyncs_on_connect_on_a_diff_and_on_a_bfd_change() {
    let r = start(Env::ready(base_cfg()));
    let configd = r.env.configd();
    until("connect resync", || {
        configd.gets() >= 1 && r.env.rec.last_apply().is_some()
    })
    .await;
    assert!(r
        .env
        .rib
        .read()
        .await
        .best_route(&net("10.9.0.0/24"))
        .is_some());

    // A diff after the config changed.
    let mut cfg = configd.config();
    cfg.static_routing_instances[0].routes.pop();
    configd.set_config(cfg);
    let gets = configd.gets();
    configd.push_diff(ConfigDiff::default());
    until("diff resync", || configd.gets() > gets).await;
    for _ in 0..600 {
        if r.env
            .rib
            .read()
            .await
            .best_route(&net("2001:db8:9::/48"))
            .is_none()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(r
        .env
        .rib
        .read()
        .await
        .best_route(&net("2001:db8:9::/48"))
        .is_none());

    // A BFD session change alone.
    let gets = configd.gets();
    r.env
        .bfd_up_tx
        .send(HashSet::from(["10.0.0.2".parse::<IpAddr>().unwrap()]))
        .unwrap();
    until("bfd resync", || configd.gets() > gets).await;
    r.stop().await;
}

#[tokio::test(start_paused = true)]
async fn run_reapplies_on_the_tick_and_reconnects_after_a_close() {
    let r = start(Env::ready(base_cfg()));
    let configd = r.env.configd();
    until("first resync", || configd.gets() >= 1).await;
    let gets = configd.gets();
    until("tick resync", || configd.gets() > gets + 1).await;

    let connections = configd.connections();
    configd.close_stream();
    until("redial", || configd.connections() > connections).await;
    r.stop().await;
}

#[tokio::test(start_paused = true)]
async fn run_waits_out_an_unreachable_configd_and_tears_down_once_on_shutdown() {
    let r = start(Env::with(&[Fake::Watchdog]));
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!r.task.is_finished());
    let env = r.stop().await;
    assert_eq!(env.rec.teardowns.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn a_failing_teardown_only_warns() {
    let e = Env::ready(base_cfg());
    e.rec.fail_teardown.store(true, Ordering::SeqCst);
    let r = start(e);
    until("first resync", || r.env.configd().gets() >= 1).await;
    let env = r.stop().await;
    assert_eq!(env.rec.teardowns.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn run_stops_at_once_when_shutdown_is_already_set() {
    let e = Env::ready(base_cfg());
    let (_tx, rx) = watch::channel(true);
    let rec = e.rec.clone();
    super::run(
        e.fakes.config_socket(),
        e.fakes.watchdog_socket(),
        "rt1".into(),
        e.rib.clone(),
        e.kernel.clone(),
        rec.clone(),
        e.bgp_tx.clone(),
        e.ospf.clone(),
        e.evpn_tx.clone(),
        e.vpn.clone(),
        e.bfd_tx.clone(),
        e.bfd_up_rx.clone(),
        rx,
    )
    .await;
    assert_eq!(rec.teardowns.load(Ordering::SeqCst), 1);
    assert_eq!(e.configd().gets(), 0);
}

#[tokio::test(start_paused = true)]
async fn wait_or_shutdown_cases() {
    let (tx, mut rx) = watch::channel(false);
    assert!(!wait_or_shutdown(Duration::from_secs(1), &mut rx).await);
    tx.send(true).unwrap();
    assert!(wait_or_shutdown(Duration::from_secs(60), &mut rx).await);
    let (tx, mut rx) = watch::channel(false);
    tx.send(false).unwrap();
    assert!(!wait_or_shutdown(Duration::from_secs(60), &mut rx).await);
}

// ------------------------------------------------- kernel gate (#653)

fn bgp_add(prefix: &str) -> RibEntry {
    RibEntry {
        prefix: net(prefix),
        next_hops: vec![("10.0.0.2".parse::<IpAddr>().unwrap(), None).into()],
        source: RouteSource::Bgp,
        backup: None,
        backup_interface_id: None,
        backup_tunnel: false,
    }
}

/// A producer's delta that lands while a full apply is in the driver waits for
/// it, so the delta is the last kernel write.
#[tokio::test]
async fn a_delta_waits_for_the_full_apply_in_flight() {
    let e = Env::ready(base_cfg());
    e.rib.write().await.upsert_and_diff(bgp_add("10.7.0.0/24"));
    e.rec.block_apply.store(true, Ordering::SeqCst);
    let (rib, kernel, rec) = (e.rib.clone(), e.kernel.clone(), e.rec.clone());
    let full = tokio::spawn(async move {
        let gate = kernel.lock().await;
        apply_to_kernel("rt1", &rib, &kernel, &gate, rec.as_ref()).await;
    });
    e.rec.entered.notified().await;

    // The withdraw arrives mid-apply.
    let (rib, kernel, rec) = (e.rib.clone(), e.kernel.clone(), e.rec.clone());
    let delta = tokio::spawn(async move {
        let gate = kernel.lock().await;
        rib.write()
            .await
            .remove_and_diff(&net("10.7.0.0/24"), RouteSource::Bgp);
        let d = HashMap::from([(net("10.7.0.0/24"), None)]);
        rec.apply_delta("rt1", &d).await.unwrap();
        drop(gate);
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        e.rec.deltas.lock().unwrap().is_empty(),
        "delta overtook the apply"
    );
    e.rec.release.notify_one();
    full.await.unwrap();
    delta.await.unwrap();
    assert!(e
        .rec
        .last_apply()
        .unwrap()
        .contains_key(&net("10.7.0.0/24")));
    assert_eq!(e.rec.deltas.lock().unwrap().len(), 1);
}

/// A failed write marks the table dirty and `run` re-applies at once.
#[tokio::test(start_paused = true)]
async fn a_failed_write_triggers_a_full_apply_without_the_tick() {
    let r = start(Env::ready(base_cfg()));
    until("first apply", || r.env.rec.last_apply().is_some()).await;
    let applies = r.env.rec.applies.lock().unwrap().len();
    r.env.kernel.mark_dirty();
    until("dirty re-apply", || {
        r.env.rec.applies.lock().unwrap().len() > applies
    })
    .await;
    r.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_kernel_that_keeps_failing_is_retried_at_most_once_a_second() {
    let e = Env::ready(base_cfg());
    e.rec.fail_apply.store(true, Ordering::SeqCst);
    let r = start(e);
    until("first apply", || r.env.rec.last_apply().is_some()).await;
    let before = r.env.rec.applies.lock().unwrap().len();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let n = r.env.rec.applies.lock().unwrap().len() - before;
    assert!((1..=7).contains(&n), "{n} applies in 5 s");
    r.stop().await;
}

// ------------------------------------------------- startup hold (#654)

#[test]
fn configured_sources_follow_the_table() {
    let mut cfg = base_cfg();
    assert_eq!(
        configured_sources(&cfg, "rt1"),
        HashSet::from([RouteSource::Bgp, RouteSource::Ospf])
    );
    cfg.routing_tables[0].bgp_instance = None;
    cfg.routing_tables[0].ospf_instance = None;
    cfg.routing_tables[0].evpn.bgp_instance = Some("b1".into());
    cfg.routing_tables[0].vpn.bgp_instance = Some("b1".into());
    assert_eq!(
        configured_sources(&cfg, "rt1"),
        HashSet::from([RouteSource::Ospf, RouteSource::Evpn, RouteSource::Vpn])
    );
    assert!(configured_sources(&cfg, "nope").is_empty());
}

#[tokio::test]
async fn the_first_resync_holds_until_every_source_pushed() {
    let e = Env::ready(base_cfg());
    e.resync().await;
    assert_eq!(*e.rec.keep.lock().unwrap(), [true]);
    // A later resync does not re-arm.
    e.resync().await;
    assert_eq!(*e.rec.keep.lock().unwrap(), [true]);

    let applies = e.rec.applies.lock().unwrap().len();
    let gate = e.kernel.lock().await;
    assert!(!e.kernel.source_done(&gate, RouteSource::Bgp));
    assert!(e.kernel.source_done(&gate, RouteSource::Ospf));
    e.kernel
        .release_hold("rt1", &e.rib, &gate, e.rec.as_ref(), "test")
        .await;
    assert_eq!(*e.rec.keep.lock().unwrap(), [true, false]);
    assert_eq!(e.rec.applies.lock().unwrap().len(), applies + 1);
    // Released once only.
    e.kernel
        .release_hold("rt1", &e.rib, &gate, e.rec.as_ref(), "test")
        .await;
    assert_eq!(e.rec.applies.lock().unwrap().len(), applies + 1);
}

#[tokio::test]
async fn a_table_without_producers_never_holds() {
    let mut cfg = base_cfg();
    cfg.routing_tables[0].bgp_instance = None;
    cfg.routing_tables[0].ospf_instance = None;
    cfg.routing_tables[0].ospfv3_instance = None;
    let e = Env::ready(cfg);
    e.resync().await;
    assert!(e.rec.keep.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_hold_expires_at_its_deadline() {
    let mut e = Env::ready(base_cfg());
    e.kernel = Arc::new(KernelGate::new(Duration::from_secs(5)));
    assert!(!e.kernel.hold_expired(Instant::now()));
    e.resync().await;
    assert!(!e.kernel.hold_expired(Instant::now()));
    assert!(e
        .kernel
        .hold_expired(Instant::now() + Duration::from_secs(6)));
}
