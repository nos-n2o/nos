//! `resync`, `run` and the IPC resolvers against the shared fakes (#344, #347).
//! A resync really drives a `SessionManager` (`with_listen`, unscoped, free
//! ports), and the assertions read back what it applied through
//! `SessionManager::applied` and the BFD target channel.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{
    BgpInstance, BgpShutdown, BroadcastDomain, Config, ConfigDiff, Event, InterfaceAddress,
    InterfaceStatus, Request, RoutingTable, RoutingTableEvpn, ServiceRef, SourceAddress,
    SubinterfaceStatus, LOOPBACK_PREFIX,
};
use nos_test_support::{free_port, serve, Fake, Fakes, Reply};
use serde_json::{json, Value};
use tokio::sync::watch;

use super::{
    resolve_source_address, resolve_vrf, restart_check, resync, wait_or_shutdown, PolicyCache,
    REAPPLY_INTERVAL,
};
use crate::session::{ResolvedPeer, SessionManager, VrfRequirement};

fn addr(s: &str, label: Option<&str>) -> InterfaceAddress {
    InterfaceAddress {
        address: s.parse().unwrap(),
        label: label.map(Into::into),
    }
}

fn status(
    name: &str,
    flat: Vec<InterfaceAddress>,
    tags: &[(u16, Vec<InterfaceAddress>)],
) -> InterfaceStatus {
    InterfaceStatus {
        name: name.into(),
        addresses: flat,
        routing_table: None,
        switching_profile: None,
        port_aggregate: None,
        mtu: 1500,
        subinterfaces: tags
            .iter()
            .map(|(tag, addresses)| SubinterfaceStatus {
                mtu: 1500,
                tag: *tag,
                addresses: addresses.clone(),
                routing_table: Some("rt1".into()),
                link_local_address: None,
            })
            .collect(),
        link_local_address: None,
        err_disabled: false,
    }
}

#[allow(clippy::needless_pass_by_value, reason = "test builder")]
fn group(name: &str, extra: Value) -> Value {
    let mut g = json!({
        "name": name, "remote_as": 65002, "address_families": [],
        "route_reflector_client": false, "route_server_client": false,
    });
    g.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    g
}

#[allow(clippy::needless_pass_by_value, reason = "test builder")]
fn instance(extra: Value) -> Value {
    let mut i = json!({
        "name": "r1", "asn": 65001, "router_id": "1.1.1.1",
        "peers": [], "peer_groups": [], "routing_table": "rt1",
        "graceful_restart": {"disabled": true},
    });
    i.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    i
}

fn config(inst: Value) -> Config {
    Config {
        bgp_instances: vec![serde_json::from_value(inst).unwrap()],
        routing_tables: vec![RoutingTable {
            name: "rt1".into(),
            bgp_instance: Some("r1".into()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn own(cfg: &Config) -> &BgpInstance {
    &cfg.bgp_instances[0]
}

/// One peer in group `g` (`remote_as` 65002, nothing else set).
fn simple_cfg() -> Config {
    config(instance(json!({
        "peers": [{"remote_address": "127.0.0.2", "peer_group": "g"}],
        "peer_groups": [group("g", json!({}))],
    })))
}

/// The world of a resync: fakes, a real `SessionManager`, and the state
/// `resync` threads between passes.
struct Env {
    fakes: Fakes,
    sessions: Arc<SessionManager>,
    cache: PolicyCache,
    decided: bool,
}

impl Env {
    /// Everything up, `rt1`'s VRF is `vrf100`.
    fn ready(cfg: Config) -> Self {
        let e = Self::with(&[
            Fake::Configd(cfg),
            Fake::Watchdog,
            Fake::Ribd("rt1".into()),
            Fake::Interfaced,
        ]);
        e.ribd().set_vrf_name(Some("vrf100".into()));
        e
    }

    fn with(which: &[Fake]) -> Self {
        Env {
            fakes: Fakes::start(which),
            sessions: SessionManager::with_listen("r1".into(), free_port(), free_port(), false),
            cache: PolicyCache::default(),
            decided: false,
        }
    }

    fn ribd(&self) -> &nos_test_support::FakeRibd {
        &self.fakes.ribd["rt1"]
    }

    fn ifaced(&self) -> &nos_test_support::FakeInterfaced {
        self.fakes.interfaced.as_ref().unwrap()
    }

    async fn resync(&mut self) {
        resync(
            &self.fakes.config_socket(),
            &self.fakes.watchdog_socket(),
            "r1",
            &self.sessions,
            &mut self.cache,
            &mut self.decided,
        )
        .await;
    }

    async fn resolve_source(&self, own_table: Option<&str>, s: &SourceAddress) -> Vec<IpAddr> {
        resolve_source_address(&self.fakes.watchdog_socket(), own_table, s).await
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// ---------------------------------------------------------------- resolvers

#[tokio::test]
async fn resolve_vrf_cases() {
    let f = Fakes::start(&[Fake::Watchdog, Fake::Ribd("rt1".into())]);
    let wd = f.watchdog_socket();
    // The broker does not know the table.
    assert_eq!(resolve_vrf(&wd, "rt9").await, None);
    // Known, but its ribd has no VRF yet.
    assert_eq!(resolve_vrf(&wd, "rt1").await, None);
    f.ribd["rt1"].set_vrf_name(Some("vrf100".into()));
    assert_eq!(resolve_vrf(&wd, "rt1").await.as_deref(), Some("vrf100"));
    // No broker at all.
    assert_eq!(
        resolve_vrf(Path::new("/nonexistent/wd.sock"), "rt1").await,
        None
    );
}

#[tokio::test]
async fn resolve_source_address_cases() {
    let e = Env::with(&[Fake::Watchdog, Fake::Interfaced]);
    let eth0 = || SourceAddress::Interface {
        interface: "eth0".into(),
        label: None,
    };
    // Not configured yet in interfaced.
    assert_eq!(e.resolve_source(Some("rt1"), &eth0()).await.len(), 0);

    e.ifaced().set_interface(status(
        "eth0",
        // Flat addresses are ignored for a non-loopback interface.
        vec![addr("9.9.9.9/32", None)],
        &[
            (
                0,
                vec![addr("10.0.0.1/24", Some("a")), addr("fd00::1/64", None)],
            ),
            (100, vec![addr("172.16.0.1/24", None)]),
        ],
    ));
    // Tag 0 only, every label kept.
    assert_eq!(
        e.resolve_source(Some("rt1"), &eth0()).await,
        [ip("10.0.0.1"), ip("fd00::1")]
    );
    // A label filter keeps just the matching address.
    let labelled = SourceAddress::Interface {
        interface: "eth0".into(),
        label: Some("a".into()),
    };
    assert_eq!(e.resolve_source(None, &labelled).await, [ip("10.0.0.1")]);
    let nomatch = SourceAddress::Interface {
        interface: "eth0".into(),
        label: Some("zz".into()),
    };
    assert_eq!(e.resolve_source(None, &nomatch).await.len(), 0);

    // Loopback: derived name, flat addresses.
    let lo = SourceAddress::Loopback { label: None };
    assert!(
        e.resolve_source(None, &lo).await.is_empty(),
        "no owning routing table"
    );
    assert_eq!(e.resolve_source(Some("rt1"), &lo).await.len(), 0);
    e.ifaced().set_interface(status(
        &format!("{LOOPBACK_PREFIX}rt1"),
        vec![
            addr("1.1.1.1/32", None),
            addr("2001:db8::1/128", Some("v6")),
        ],
        &[(0, vec![addr("8.8.8.8/32", None)])],
    ));
    assert_eq!(
        e.resolve_source(Some("rt1"), &lo).await,
        [ip("1.1.1.1"), ip("2001:db8::1")]
    );
    let lo_v6 = SourceAddress::Loopback {
        label: Some("v6".into()),
    };
    assert_eq!(
        e.resolve_source(Some("rt1"), &lo_v6).await,
        [ip("2001:db8::1")]
    );
}

#[tokio::test]
async fn resolve_source_address_without_interfaced_is_empty() {
    // The broker answers NotAvailable for `Interfaces`.
    let e = Env::with(&[Fake::Watchdog]);
    let s = SourceAddress::Interface {
        interface: "eth0".into(),
        label: None,
    };
    assert_eq!(e.resolve_source(Some("rt1"), &s).await.len(), 0);
}

// ------------------------------------------------------------ restart_check

fn resolved_peer(addr: &str, shutdown: bool) -> ResolvedPeer {
    // Round-trip through a real resync would be heavy; one literal is enough.
    let accept = Arc::new(nos_rpl::ACCEPT_ALL.clone());
    ResolvedPeer {
        remote_address: ip(addr),
        source_address: None,
        remote_as: 65002,
        peer_group: "g".into(),
        hold_time: 30,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(1),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: accept.clone(),
        export_policy: accept,
        evpn_import_policy: None,
        flowspec_import_policy: None,
        flowspec_export_policy: None,
        enforce_first_as: true,
        flowspec_validation: nos_proto::BgpFlowspecValidation::default(),
        shutdown: shutdown.then_some(BgpShutdown { message: None }),
        maximum_prefix: nos_proto::BgpMaximumPrefix::default(),
        announce_rpki_state: false,
        blackhole: None,
        soft_reconfiguration_inbound: false,
        local_as: None,
        add_path: None,
        add_path_send_count: None,
        role: None,
        strict_mode: false,
        confed_id: None,
        confed_member: false,
        graceful_restart: Some(120),
    }
}

#[tokio::test]
async fn restart_check_decides_per_vrf_and_route_count() {
    let gr_on = config(instance(json!({"graceful_restart": {}})));
    let gr_off = config(instance(json!({})));
    let e = Env::with(&[Fake::Watchdog, Fake::Ribd("rt1".into())]);
    let wd = e.fakes.watchdog_socket();
    let resolved = VrfRequirement::Resolved("vrf100".into());
    let peers = [
        resolved_peer("127.0.0.2", false),
        resolved_peer("127.0.0.3", true),
    ];
    let check = |c: &Config, v: VrfRequirement| {
        let (wd, s, p) = (wd.clone(), e.sessions.clone(), peers.clone());
        let c = c.clone();
        async move { restart_check(&wd, own(&c), &v, &p, &s).await }
    };

    assert!(
        check(&gr_off, resolved.clone()).await,
        "graceful restart off"
    );
    assert!(check(&gr_on, VrfRequirement::Invalid).await);
    assert!(!check(&gr_on, VrfRequirement::Pending).await);

    // Resolved, but the broker has no ribd for the table.
    let mut other = gr_on.clone();
    other.bgp_instances[0].routing_table = Some("rt9".into());
    assert!(!check(&other, resolved.clone()).await);

    // Count 0: decided, no deferral.
    e.ribd().set_bgp_route_count(0);
    assert!(check(&gr_on, resolved.clone()).await);
    assert_eq!(e.sessions.applied().await.deferral_waiting, None);

    // Routes survived: deferral starts, waiting for the non-shut peer only.
    e.ribd().set_bgp_route_count(5);
    assert!(check(&gr_on, resolved.clone()).await);
    assert_eq!(
        e.sessions.applied().await.deferral_waiting,
        Some(vec![ip("127.0.0.2")])
    );
}

#[tokio::test]
async fn restart_check_waits_while_the_count_is_unanswerable() {
    // The broker resolves rt1 to a path nobody listens on.
    let e = Env::with(&[Fake::Watchdog]);
    let gone = e.fakes.dir().join("gone.sock");
    e.fakes
        .watchdog
        .as_ref()
        .unwrap()
        .set(ServiceRef::RibTable("rt1".into()), gone);
    let c = config(instance(json!({"graceful_restart": {}})));
    let ok = restart_check(
        &e.fakes.watchdog_socket(),
        own(&c),
        &VrfRequirement::Resolved("vrf100".into()),
        &[],
        &e.sessions,
    )
    .await;
    assert!(!ok);
}

// ------------------------------------------------------------------- resync

#[tokio::test]
async fn resync_keeps_state_when_the_fetch_fails() {
    // No configd socket at all.
    let mut e = Env::with(&[Fake::Watchdog, Fake::Ribd("rt1".into())]);
    e.resync().await;
    let a = e.sessions.applied().await;
    assert_eq!(a.peers.len(), 0);
    assert_eq!(a.vrf, VrfRequirement::Pending, "untouched");
    assert!(!e.decided);
}

#[tokio::test]
async fn resync_returns_early_without_its_own_instance() {
    let mut cfg = simple_cfg();
    cfg.bgp_instances[0].name = "other".into();
    let mut e = Env::ready(cfg);
    e.resync().await;
    let a = e.sessions.applied().await;
    assert_eq!(a.peers.len(), 0);
    assert_eq!(a.vrf, VrfRequirement::Pending);
}

#[tokio::test]
async fn resync_without_a_routing_table_is_invalid_and_opens_nothing() {
    let mut cfg = simple_cfg();
    cfg.bgp_instances[0].routing_table = None;
    let mut e = Env::ready(cfg);
    e.resync().await;
    let a = e.sessions.applied().await;
    assert_eq!(a.vrf, VrfRequirement::Invalid);
    assert_eq!(a.local.asn, 65001);
    assert!(e.decided, "an invalid vrf decides the restart check");
}

#[tokio::test]
async fn resync_applies_defaults_and_group_values() {
    let cfg = config(instance(json!({
        "cluster_id": "9.9.9.9",
        "peers": [
            {"remote_address": "127.0.0.2", "peer_group": "g"},
            {"remote_address": "127.0.0.3", "peer_group": "tuned"},
            {"remote_address": "127.0.0.4", "peer_group": "missing"},
        ],
        "peer_groups": [
            group("g", json!({})),
            group("tuned", json!({
                "hold_time": 45, "connect_retry_time": 7, "mrai": 11,
                "route_refresh_stale_time": 13, "keepalive_interval": 15,
            })),
        ],
    })));
    let mut e = Env::ready(cfg);
    e.resync().await;
    let a = e.sessions.applied().await;
    assert_eq!(a.vrf, VrfRequirement::Resolved("vrf100".into()));
    assert_eq!(a.routing_table.as_deref(), Some("rt1"));
    assert_eq!(a.local.router_id, Ipv4Addr::new(1, 1, 1, 1));
    assert_eq!(a.local.cluster_id, Ipv4Addr::new(9, 9, 9, 9));
    assert_eq!(
        a.peers.len(),
        2,
        "the peer naming an unknown group is skipped"
    );
    let (g, tuned) = (&a.peers[0], &a.peers[1]);
    assert_eq!(g.hold_time, nos_proto::HOLD_TIME_DEFAULT);
    assert_eq!(g.connect_retry_time, crate::fsm::CONNECT_RETRY_TIME);
    assert_eq!(g.mrai, Duration::ZERO);
    assert_eq!(
        g.route_refresh_stale_time,
        Duration::from_secs(u64::from(nos_proto::ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS))
    );
    assert_eq!(g.keepalive_interval, None);
    assert_eq!(tuned.hold_time, 45);
    assert_eq!(tuned.connect_retry_time, Duration::from_secs(7));
    assert_eq!(tuned.mrai, Duration::from_secs(11));
    assert_eq!(tuned.route_refresh_stale_time, Duration::from_secs(13));
    assert_eq!(tuned.keepalive_interval, Some(15));
    assert_eq!(g.graceful_restart, None, "disabled in the instance");
}

#[tokio::test]
async fn resync_cluster_id_defaults_to_the_router_id() {
    let mut e = Env::ready(simple_cfg());
    e.resync().await;
    assert_eq!(
        e.sessions.applied().await.local.cluster_id,
        Ipv4Addr::new(1, 1, 1, 1)
    );
}

#[tokio::test]
async fn resync_peer_shutdown_overrides_the_groups() {
    let cfg = config(instance(json!({
        "peers": [
            {"remote_address": "127.0.0.2", "peer_group": "g"},
            {"remote_address": "127.0.0.3", "peer_group": "g",
             "shutdown": {"message": "peer"}},
            {"remote_address": "127.0.0.4", "peer_group": "down"},
        ],
        "peer_groups": [
            group("g", json!({})),
            group("down", json!({"shutdown": {"message": "group"}})),
        ],
    })));
    let mut e = Env::ready(cfg);
    e.resync().await;
    let msg = |p: &ResolvedPeer| p.shutdown.as_ref().map(|s| s.message.clone());
    let a = e.sessions.applied().await;
    assert_eq!(msg(&a.peers[0]), None);
    assert_eq!(msg(&a.peers[1]), Some(Some("peer".into())));
    assert_eq!(msg(&a.peers[2]), Some(Some("group".into())));
}

#[tokio::test]
async fn resync_picks_the_source_address_of_the_peers_family() {
    let mut cfg = config(instance(json!({
        "peers": [
            {"remote_address": "127.0.0.2", "peer_group": "g"},
            {"remote_address": "::1", "peer_group": "g"},
            {"remote_address": "127.0.0.3", "peer_group": "v6only"},
            {"remote_address": "127.0.0.4", "peer_group": "plain"},
        ],
        "peer_groups": [
            group("g", json!({})),
            group("v6only", json!({})),
            group("plain", json!({})),
        ],
    })));
    {
        let groups = &mut cfg.bgp_instances[0].peer_groups;
        groups[0].source_address = Some(SourceAddress::Loopback { label: None });
        groups[1].source_address = Some(SourceAddress::Interface {
            interface: "eth1".into(),
            label: None,
        });
    }
    let mut e = Env::ready(cfg);
    e.ifaced().set_interface(status(
        &format!("{LOOPBACK_PREFIX}rt1"),
        vec![addr("127.0.0.9/32", None), addr("::9/128", None)],
        &[],
    ));
    // eth1 only has a v6 address: the v4 peer of `v6only` gets none.
    e.ifaced().set_interface(status(
        "eth1",
        vec![],
        &[(0, vec![addr("fd00::1/64", None)])],
    ));
    e.resync().await;
    let a = e.sessions.applied().await;
    let src = |p: &str| {
        a.peers
            .iter()
            .find(|x| x.remote_address == ip(p))
            .unwrap()
            .source_address
    };
    assert_eq!(src("127.0.0.2"), Some(ip("127.0.0.9")));
    assert_eq!(src("::1"), Some(IpAddr::V6(Ipv6Addr::from_bits(9))));
    assert_eq!(src("127.0.0.3"), None);
    assert_eq!(src("127.0.0.4"), None, "no source-address configured");
}

#[tokio::test]
async fn resync_pending_vrf_is_published_until_the_ribd_answers() {
    let mut e = Env::ready(simple_cfg());
    e.ribd().set_vrf_name(None);
    e.resync().await;
    assert_eq!(e.sessions.applied().await.vrf, VrfRequirement::Pending);
    e.ribd().set_vrf_name(Some("vrf7".into()));
    e.resync().await;
    assert_eq!(
        e.sessions.applied().await.vrf,
        VrfRequirement::Resolved("vrf7".into())
    );
}

#[tokio::test]
async fn resync_feeds_only_the_evpn_consumers_of_this_instance() {
    let mut cfg = simple_cfg();
    let bd = |name: &str, vni: Option<u32>, to: Option<&str>| BroadcastDomain {
        name: name.into(),
        vni,
        mac_redistribute: to.map(Into::into),
        ..Default::default()
    };
    cfg.broadcast_domains = vec![
        bd("mine", Some(100), Some("r1")),
        bd("novni", None, Some("r1")),
        bd("other", Some(200), Some("r2")),
        bd("unset", Some(300), None),
    ];
    let t = |name: &str, vni: Option<u32>, inst: Option<&str>| RoutingTable {
        name: name.into(),
        evpn: RoutingTableEvpn {
            l3_vni: vni,
            bgp_instance: inst.map(Into::into),
            ..Default::default()
        },
        ..Default::default()
    };
    cfg.routing_tables = vec![
        t("rt1", None, None),
        t("vrf-a", Some(5000), Some("r1")),
        t("vrf-b", None, Some("r1")),
        t("vrf-c", Some(5001), Some("r2")),
    ];
    let mut e = Env::ready(cfg);
    e.resync().await;
    let a = e.sessions.applied().await;
    assert_eq!(a.fdb_domains, ["mine"]);
    assert_eq!(a.evpn_tables, ["vrf-a"]);
}

#[tokio::test]
async fn resync_holds_everything_back_until_the_restart_is_decided() {
    // GR on (the default) and the ribd cannot be reached for the count yet.
    let mut cfg = config(instance(json!({
        "graceful_restart": {},
        "peers": [{"remote_address": "127.0.0.2", "peer_group": "g"}],
        "peer_groups": [group("g", json!({}))],
    })));
    cfg.broadcast_domains = vec![BroadcastDomain {
        name: "mine".into(),
        vni: Some(100),
        mac_redistribute: Some("r1".into()),
        ..Default::default()
    }];
    let mut e = Env::ready(cfg);
    let gone = e.fakes.dir().join("gone.sock");
    e.fakes
        .watchdog
        .as_ref()
        .unwrap()
        .set(ServiceRef::RibTable("rt1".into()), gone);
    e.resync().await;
    assert!(!e.decided);
    let a = e.sessions.applied().await;
    assert_eq!(a.vrf, VrfRequirement::Pending, "forced");
    assert_eq!(a.routing_table, None);
    assert_eq!(a.fdb_domains.len(), 0);
    assert_eq!(a.peers.len(), 1, "peers are still known");

    // Back in service with surviving routes: decided, deferral begins.
    let p = e.fakes.rib_socket("rt1");
    e.fakes
        .watchdog
        .as_ref()
        .unwrap()
        .set(ServiceRef::RibTable("rt1".into()), p);
    e.ribd().set_bgp_route_count(3);
    e.resync().await;
    assert!(e.decided);
    let a = e.sessions.applied().await;
    assert_eq!(a.vrf, VrfRequirement::Resolved("vrf100".into()));
    assert_eq!(a.fdb_domains, ["mine"]);
    assert_eq!(a.deferral_waiting, Some(vec![ip("127.0.0.2")]));
}

#[tokio::test]
async fn resync_publishes_bfd_targets_only_once_resolved() {
    let cfg = config(instance(json!({
        "peers": [{"remote_address": "127.0.0.2", "peer_group": "g"}],
        "peer_groups": [group("g", json!({"bfd": "fast"}))],
    })));
    let mut cfg = cfg;
    cfg.bfd_profiles = vec![nos_proto::schema::BfdProfile {
        name: "fast".into(),
        ..Default::default()
    }];
    let mut e = Env::ready(cfg);
    let rx = e.sessions.bfd_targets();
    e.ribd().set_vrf_name(None);
    e.resync().await;
    assert!(rx.borrow().peers.is_empty(), "pending vrf: no target");
    e.ribd().set_vrf_name(Some("vrf100".into()));
    e.resync().await;
    let t = rx.borrow().clone();
    assert_eq!(t.table, "rt1");
    assert!(t.peers.contains_key(&ip("127.0.0.2")));
}

// ---------------------------------------------------------- wait_or_shutdown

#[tokio::test(start_paused = true)]
async fn wait_or_shutdown_cases() {
    let (tx, mut rx) = watch::channel(false);
    assert!(!wait_or_shutdown(Duration::from_secs(1), &mut rx).await);
    tx.send(true).unwrap();
    assert!(wait_or_shutdown(Duration::from_secs(60), &mut rx).await);
    // A change back to `false` ends the wait but is not a shutdown.
    let (tx, mut rx) = watch::channel(false);
    tx.send(false).unwrap();
    assert!(!wait_or_shutdown(Duration::from_secs(60), &mut rx).await);
}

// ---------------------------------------------------------------- run loop

struct Running {
    fakes: Fakes,
    sessions: Arc<SessionManager>,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

fn start(e: Env, shutdown_at_entry: bool) -> Running {
    let Env {
        fakes, sessions, ..
    } = e;
    let (shutdown, rx) = watch::channel(shutdown_at_entry);
    let task = tokio::spawn(super::run(
        fakes.config_socket(),
        fakes.watchdog_socket(),
        "r1".into(),
        Arc::clone(&sessions),
        rx,
    ));
    Running {
        fakes,
        sessions,
        shutdown,
        task,
    }
}

impl Running {
    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        // Polled in small steps: a single long timeout would let the paused
        // clock jump past work still running on the blocking pool.
        until("run to stop", || self.task.is_finished()).await;
        self.task.await.unwrap();
        assert!(
            self.sessions.applied().await.peers.is_empty(),
            "shutdown cleared the sessions"
        );
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

/// Waits for `run` to return, in small steps: a single long timeout would
/// let the paused clock jump past work still on the blocking pool.
async fn finished(task: tokio::task::JoinHandle<()>) {
    until("run to stop", || task.is_finished()).await;
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn run_resyncs_on_connect_and_on_diff_and_stops_on_shutdown() {
    let r = start(Env::ready(simple_cfg()), false);
    let configd = r.fakes.configd.as_ref().unwrap();
    until("connected resync", || configd.gets() >= 1).await;
    until("peer applied", || {
        // The connect-time resync and the stream's synthesized first diff.
        configd.gets() >= 2
    })
    .await;
    assert_eq!(r.sessions.applied().await.peers.len(), 1);
    let gets = configd.gets();
    configd.push_diff(ConfigDiff::default());
    until("diff resync", || configd.gets() > gets).await;
    r.stop().await;
}

#[tokio::test(start_paused = true)]
async fn run_stops_at_once_when_shutdown_is_already_set() {
    let r = start(Env::ready(simple_cfg()), true);
    let gets = r.fakes.configd.as_ref().unwrap().gets();
    finished(r.task).await;
    assert_eq!(gets, 0);
}

#[tokio::test(start_paused = true)]
async fn run_survives_an_unreachable_configd_and_stops_on_shutdown() {
    let r = start(Env::with(&[Fake::Watchdog]), false);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!r.task.is_finished());
    r.stop().await;
}

#[tokio::test(start_paused = true)]
async fn run_reapplies_on_the_tick_without_a_diff() {
    let r = start(Env::ready(simple_cfg()), false);
    let configd = r.fakes.configd.as_ref().unwrap();
    until("first resync", || configd.gets() >= 1).await;
    let gets = configd.gets();
    tokio::time::sleep(REAPPLY_INTERVAL * 3).await;
    until("tick resyncs", || configd.gets() >= gets + 2).await;
    r.stop().await;
}

#[tokio::test(start_paused = true)]
async fn run_reconnects_after_the_stream_closes() {
    let r = start(Env::ready(simple_cfg()), false);
    let configd = r.fakes.configd.as_ref().unwrap();
    until("first resync", || configd.gets() >= 1).await;
    let connections = configd.connections();
    configd.close_stream();
    until("redialed", || configd.connections() > connections).await;
    r.stop().await;
}

#[tokio::test(start_paused = true)]
async fn run_ignores_non_diff_events_and_resubscribes_after_a_close() {
    let f = Fakes::start(&[Fake::Watchdog, Fake::Ribd("rt1".into())]);
    f.ribd["rt1"].set_vrf_name(Some("vrf100".into()));
    let subscribes = Arc::new(AtomicUsize::new(0));
    let (s, cfg) = (Arc::clone(&subscribes), simple_cfg());
    let _configd = serve(
        &f.config_socket(),
        "configd",
        "",
        move |req: &Request| match req {
            Request::Get => Reply::One(Event::Config(cfg.clone())),
            Request::SubscribeDiff { .. } => {
                s.fetch_add(1, Ordering::SeqCst);
                Reply::Stream(
                    vec![Event::Error("not a diff".into())],
                    futures::stream::empty().boxed(),
                )
            }
            _ => Reply::Close,
        },
    );
    let sessions = SessionManager::with_listen("r1".into(), free_port(), free_port(), false);
    let (shutdown, rx) = watch::channel(false);
    let task = tokio::spawn(super::run(
        f.config_socket(),
        f.watchdog_socket(),
        "r1".into(),
        sessions,
        rx,
    ));
    until("resubscribed", || subscribes.load(Ordering::SeqCst) >= 2).await;
    shutdown.send(true).unwrap();
    finished(task).await;
}

/// A configd answering the subscription with a frame the codec refuses:
/// `run` takes the read-error arm and reconnects.
#[tokio::test(start_paused = true)]
async fn run_reconnects_after_a_read_error() {
    use tokio::io::AsyncWriteExt;

    let f = Fakes::start(&[Fake::Watchdog]);
    let listener = nos_pki::testing::shared()
        .identity("configd", "")
        .listen(&f.config_socket())
        .unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let a = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok(incoming) = listener.accept().await {
            a.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok((mut stream, _)) = incoming.handshake().await else {
                    return;
                };
                let mut buf = [0u8; 256];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                // A well-framed payload that is no `Event`.
                let _ = stream
                    .write_all(&[4, 0, 0, 0, 0xff, 0xff, 0xff, 0xff])
                    .await;
                let _ = stream.flush().await;
                tokio::time::sleep(Duration::from_secs(3600)).await;
            });
        }
    });
    let sessions = SessionManager::with_listen("r1".into(), free_port(), free_port(), false);
    let (shutdown, rx) = watch::channel(false);
    let task = tokio::spawn(super::run(
        f.config_socket(),
        f.watchdog_socket(),
        "r1".into(),
        sessions,
        rx,
    ));
    until("reconnected", || accepted.load(Ordering::SeqCst) >= 2).await;
    shutdown.send(true).unwrap();
    finished(task).await;
}

#[test]
fn flowspec_policies_resolve_per_peer_group_and_unset_is_none() {
    let cfg = config(instance(json!({
        "peers": [
            {"remote_address": "127.0.0.2", "peer_group": "g"},
            {"remote_address": "127.0.0.3", "peer_group": "h"},
        ],
        "peer_groups": [
            group("g", json!({
                "flowspec_import_policy": "deny-all",
                "flowspec_export_policy": "accept-all",
            })),
            group("h", json!({})),
        ],
    })));
    let peers = super::resolve_peers(
        own(&cfg),
        &std::collections::HashMap::new(),
        &mut PolicyCache::default(),
        &cfg,
    );
    let g = peers.iter().find(|p| p.peer_group == "g").unwrap();
    assert_eq!(
        g.flowspec_import_policy.as_deref(),
        Some(&*nos_rpl::DENY_ALL)
    );
    assert_eq!(
        g.flowspec_export_policy.as_deref(),
        Some(&*nos_rpl::ACCEPT_ALL)
    );
    let h = peers.iter().find(|p| p.peer_group == "h").unwrap();
    assert!(h.flowspec_import_policy.is_none() && h.flowspec_export_policy.is_none());
}

#[test]
fn blackhole_resolves_the_named_prefix_list_into_the_peer() {
    let mut cfg = config(instance(json!({
        "peers": [
            {"remote_address": "127.0.0.2", "peer_group": "g"},
            {"remote_address": "127.0.0.3", "peer_group": "h"},
        ],
        "peer_groups": [
            group("g", json!({"blackhole": {"prefix_list": "bh"}})),
            group("h", json!({})),
        ],
    })));
    cfg.prefix_lists = vec![nos_proto::PrefixList {
        name: "bh".to_string(),
        entries: vec![nos_proto::PrefixListEntry {
            cidr: "192.0.2.0/24".parse().unwrap(),
            range: Some((32, 32)),
        }],
    }];
    let peers = super::resolve_peers(
        own(&cfg),
        &std::collections::HashMap::new(),
        &mut PolicyCache::default(),
        &cfg,
    );
    let g = peers.iter().find(|p| p.peer_group == "g").unwrap();
    let list = g.blackhole.as_ref().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].range, Some((32, 32)));
    assert!(peers
        .iter()
        .find(|p| p.peer_group == "h")
        .unwrap()
        .blackhole
        .is_none());
}

#[test]
fn gs_knobs_come_from_the_peers_group_and_skip_peers_with_none_set() {
    let cfg = config(instance(json!({
        "peers": [
            {"remote_address": "127.0.0.2", "peer_group": "drain"},
            {"remote_address": "127.0.0.3", "peer_group": "g"},
            {"remote_address": "127.0.0.4", "peer_group": "quiet"},
        ],
        "peer_groups": [
            group("drain", json!({"graceful_shutdown": true})),
            group("g", json!({})),
            group("quiet", json!({"graceful_shutdown_receive_disabled": true})),
        ],
    })));
    let k = super::gs_knobs(own(&cfg));
    assert_eq!(k.len(), 2);
    assert!(k[&"127.0.0.2".parse::<IpAddr>().unwrap()].send);
    assert!(k[&"127.0.0.4".parse::<IpAddr>().unwrap()].receive_off);
}
