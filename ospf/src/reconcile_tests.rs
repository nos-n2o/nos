//! `resync`, `run` and the IPC resolvers against the shared fakes (#342, #347).
//! The link layer runs over the in-memory wire of `link::tests`, so a resync
//! really builds links and the assertions read them back through
//! `LinkManager::running_config`.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use ipnet::Ipv4Net;
use nos_proto::schema::BfdProfile;
use nos_proto::{
    AsPathList, BroadcastDomain, BroadcastDomainStatus, CommunityAlias, CommunityGroup, Config,
    ConfigDiff, Event, Interface, InterfaceAddress, InterfaceEvent, InterfaceStatus, LinkState,
    NetworkType, OspfArea, OspfAreaRange, OspfAreaType, OspfAuth, OspfCryptoAlgorithm,
    OspfCryptoKey, OspfInstance, OspfProfile, OspfVirtualLink, PolicyDefinition, PrefixList,
    PrefixListEntry, Request, Subinterface, SubinterfaceStatus,
};
use nos_test_support::{serve, Fake, Fakes, Reply};
use tokio::sync::watch;

use super::{
    area_settings, bfd_profile, gate_link, note_fallback, resolve_algorithm, resolve_auth,
    resolve_broadcast_domain, resolve_effective_mtu, resolve_local_address,
    resolve_loopback_prefix, resolve_redistribute_policy, resolve_vrf, resync,
    subinterface_kernel_interface, virtual_links, wait_or_shutdown, Ctx, State, DEFAULT_OSPF_MTU,
};
use crate::boot::BootCounter;
use crate::link::tests::wire::Wire;
use crate::link::{LinkAuthConfig, LinkManager};
use crate::link_client::{apply, Gate, LinkTable};
use crate::packet;

// ------------------------------------------------------------- fixtures

fn addr(s: &str) -> InterfaceAddress {
    InterfaceAddress {
        address: s.parse().unwrap(),
        label: None,
    }
}

fn sub(tag: u16, addrs: &[&str], rt: Option<&str>, profile: Option<&str>) -> Subinterface {
    Subinterface {
        tag,
        addresses: addrs.iter().map(|a| addr(a)).collect(),
        routing_table: rt.map(Into::into),
        ospf_profile: profile.map(Into::into),
        ..Default::default()
    }
}

fn iface(name: &str, subs: Vec<Subinterface>) -> Interface {
    Interface {
        name: name.into(),
        subinterfaces: subs,
        ..Default::default()
    }
}

fn loopback(name: &str, profile: &str) -> Interface {
    Interface {
        name: name.into(),
        ospf_profile: Some(profile.into()),
        ..Default::default()
    }
}

fn domain(name: &str, rt: Option<&str>, addrs: &[&str]) -> BroadcastDomain {
    BroadcastDomain {
        name: name.into(),
        routing_table: rt.map(Into::into),
        ospf_profile: Some("p1".into()),
        addresses: addrs.iter().map(|a| addr(a)).collect(),
        ..Default::default()
    }
}

fn profile(name: &str) -> OspfProfile {
    OspfProfile {
        name: name.into(),
        ..Default::default()
    }
}

fn area(id: &str, profiles: Vec<OspfProfile>) -> OspfArea {
    OspfArea {
        area_id: id.parse().unwrap(),
        profiles,
        ..Default::default()
    }
}

fn instance(areas: Vec<OspfArea>) -> OspfInstance {
    OspfInstance {
        name: "i1".into(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        areas,
        routing_table: Some("rt1".into()),
        ..Default::default()
    }
}

/// One instance, area 0 with profile `p1`, `eth0.0` 10.0.0.1/30 in `rt1`.
/// Admin keystore: label `pw` holds the secret `pw`, `k<id>` holds `k<id>`.
fn keystore() -> nos_proto::schema::Admin {
    let key = |l: &str| nos_proto::schema::AdminKey {
        label: l.into(),
        secret: l.into(),
    };
    nos_proto::schema::Admin {
        keys: ["pw", "secret", "k1", "k9"].into_iter().map(key).collect(),
    }
}

fn p2p_cfg() -> Config {
    Config {
        admin: keystore(),
        ospf_instances: vec![instance(vec![area("0.0.0.0", vec![profile("p1")])])],
        interfaces: vec![iface(
            "eth0",
            vec![sub(0, &["10.0.0.1/30"], Some("rt1"), Some("p1"))],
        )],
        ..Default::default()
    }
}

fn status(name: &str, mtu: u32, subs: Vec<SubinterfaceStatus>) -> InterfaceStatus {
    InterfaceStatus {
        name: name.into(),
        addresses: vec![],
        routing_table: None,
        switching_profile: None,
        port_aggregate: None,
        mtu,
        subinterfaces: subs,
        link_local_address: None,
        err_disabled: false,
        speed_mbps: None,
        link: None,
    }
}

fn sub_status(tag: u16, addrs: &[&str]) -> SubinterfaceStatus {
    SubinterfaceStatus {
        mtu: 1500,
        tag,
        addresses: addrs.iter().map(|a| addr(a)).collect(),
        routing_table: Some("rt1".into()),
        link_local_address: None,
        link: None,
    }
}

fn loopback_status(name: &str, addrs: &[&str]) -> InterfaceStatus {
    InterfaceStatus {
        addresses: addrs.iter().map(|a| addr(a)).collect(),
        ..status(name, 65536, vec![])
    }
}

fn bd_status(name: &str, bridge: Option<&str>, addrs: &[&str]) -> BroadcastDomainStatus {
    BroadcastDomainStatus {
        name: name.into(),
        addresses: addrs.iter().map(|a| addr(a)).collect(),
        routing_table: Some("rt1".into()),
        link_local_address: None,
        bridge_name: bridge.map(Into::into),
        mtu: Some(1400),
        speed_mbps: None,
    }
}

fn table(links: &[(&str, u32, bool)]) -> LinkTable {
    let mut t = LinkTable::default();
    apply(
        &mut t,
        InterfaceEvent::LinkSnapshot {
            observed: true,
            links: links
                .iter()
                .map(|(n, i, up)| LinkState {
                    name: (*n).into(),
                    ifindex: *i,
                    admin_up: *up,
                    carrier: *up,
                    port_aggregate: None,
                })
                .collect(),
        },
    );
    t
}

/// A resync's world: the four fakes, a real `LinkManager` over the in-memory
/// wire, and the `Ctx`/`State` `resync` takes.
struct Env {
    fakes: Fakes,
    links: Arc<LinkManager>,
    ctx: Ctx,
    state: State,
    rt: watch::Receiver<Option<String>>,
    link_tx: watch::Sender<LinkTable>,
}

impl Env {
    /// All four fakes up, `rt1`'s VRF `vrf100` and `eth0` (MTU 9000) with
    /// the `10.0.0.1/30` of `p2p_cfg` resolvable.
    fn ready(cfg: Config) -> Self {
        let e = Self::with(&[
            Fake::Configd(cfg),
            Fake::Watchdog,
            Fake::Ribd("rt1".into()),
            Fake::Interfaced,
        ]);
        e.ribd().set_vrf_name(Some("vrf100".into()));
        e.ifaced()
            .set_interface(status("eth0", 9000, vec![sub_status(0, &["10.0.0.1/30"])]));
        e
    }

    fn with(which: &[Fake]) -> Self {
        let fakes = Fakes::start(which);
        let wire = Arc::new(Wire::default());
        let links = LinkManager::with_opener(1, None, BootCounter::in_memory(), wire.opener());
        let (rt_tx, rt) = watch::channel(None);
        let (link_tx, link_rx) = watch::channel(LinkTable::default());
        let ctx = Ctx {
            config_socket: fakes.config_socket(),
            watchdog_socket: fakes.watchdog_socket(),
            instance: "i1".into(),
            links: Arc::clone(&links),
            routing_table_tx: rt_tx,
            link_rx,
        };
        Env {
            fakes,
            links,
            ctx,
            state: State::default(),
            rt,
            link_tx,
        }
    }

    fn ribd(&self) -> &nos_test_support::FakeRibd {
        &self.fakes.ribd["rt1"]
    }

    fn ifaced(&self) -> &nos_test_support::FakeInterfaced {
        self.fakes.interfaced.as_ref().unwrap()
    }

    fn configd(&self) -> &nos_test_support::FakeConfigd {
        self.fakes.configd.as_ref().unwrap()
    }

    async fn resync(&mut self) {
        resync(&mut self.ctx, &mut self.state).await;
    }

    async fn running(&self, link: &str) -> Option<crate::link::LinkConfig> {
        self.links.running_config(link).await
    }
}

fn names(set: &HashSet<String>) -> Vec<&str> {
    let mut v: Vec<_> = set.iter().map(String::as_str).collect();
    v.sort_unstable();
    v
}

// ------------------------------------------------------- resync: attach

#[tokio::test]
async fn resync_p2p_subinterface_builds_link() {
    let mut e = Env::ready(p2p_cfg());
    e.resync().await;

    let l = e.running("eth0.0").await.expect("link built");
    assert_eq!(l.vrf, "vrf100");
    assert_eq!(l.local_addr, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(l.local_prefix_len, 30);
    assert_eq!(l.kernel_interface, "eth0");
    assert_eq!(l.network_type, NetworkType::PointToPoint);
    assert_eq!(l.cost, 1);
    assert_eq!(l.hello_interval, nos_proto::HELLO_INTERVAL_DEFAULT);
    assert_eq!(l.dead_interval, nos_proto::DEAD_INTERVAL_DEFAULT);
    assert_eq!(l.priority, nos_proto::PRIORITY_DEFAULT);
    assert_eq!(l.mtu, 9000);
    assert_eq!(l.ifindex, 0, "no link stream: ungated");
    assert_eq!(e.rt.borrow().as_deref(), Some("rt1"));
    assert_eq!(names(&e.state.watched), ["eth0"]);
    assert_eq!(e.state.signature, [("eth0".to_string(), Gate::Ungated)]);
    assert!(e.state.down.is_empty() && e.state.degraded.is_empty());
}

#[tokio::test]
async fn resync_profile_knobs_override_the_defaults() {
    let mut cfg = p2p_cfg();
    let mut a = area(
        "0.0.0.1",
        vec![OspfProfile {
            hello_interval: Some(5),
            dead_interval: Some(20),
            priority: Some(7),
            cost: Some(9),
            mtu: Some(1400),
            mtu_ignore: true,
            network_type: Some(NetworkType::Broadcast),
            auth: Some(OspfAuth::Simple { key: "pw".into() }),
            ..profile("p1")
        }],
    );
    a.area_type = OspfAreaType::Nssa;
    cfg.ospf_instances[0].areas = vec![a];
    let mut e = Env::ready(cfg);
    e.resync().await;

    let l = e.running("eth0.0").await.expect("link built");
    assert_eq!(
        (l.hello_interval, l.dead_interval, l.priority, l.cost),
        (5, 20, 7, 9)
    );
    assert_eq!(l.mtu, 1400, "the profile's mtu beats the interface's");
    assert!(l.mtu_ignore);
    assert_eq!(l.network_type, NetworkType::Broadcast);
    assert_eq!(l.area_id, Ipv4Addr::new(0, 0, 0, 1));
    assert!(l.stub && l.nssa);
    assert!(matches!(l.auth, LinkAuthConfig::Simple { ref password } if password == b"pw"));
}

#[tokio::test]
async fn resync_dangling_auth_label_does_not_start_the_link() {
    let mut cfg = p2p_cfg();
    cfg.ospf_instances[0].areas = vec![area(
        "0.0.0.0",
        vec![OspfProfile {
            auth: Some(OspfAuth::Simple { key: "nope".into() }),
            ..profile("p1")
        }],
    )];
    let mut e = Env::ready(cfg);
    e.resync().await;
    assert!(
        e.running("eth0.0").await.is_none(),
        "must fail closed, not start unauthenticated"
    );
}

#[tokio::test]
async fn resync_tagged_subinterface_uses_the_dotted_kernel_name() {
    let mut cfg = p2p_cfg();
    cfg.interfaces = vec![iface(
        "eth0",
        vec![sub(100, &["10.0.0.1/30"], Some("rt1"), Some("p1"))],
    )];
    let mut e = Env::ready(cfg);
    e.ifaced().set_interface(status(
        "eth0",
        1500,
        vec![sub_status(100, &["10.0.0.1/30"])],
    ));
    e.resync().await;

    let l = e.running("eth0.100").await.expect("link built");
    assert_eq!(l.kernel_interface, "eth0.100");
    assert_eq!(names(&e.state.watched), ["eth0.100"]);
}

#[test]
fn subinterface_kernel_interface_table() {
    assert_eq!(subinterface_kernel_interface("eth0", 0), "eth0");
    assert_eq!(subinterface_kernel_interface("eth0", 100), "eth0.100");
}

#[tokio::test]
async fn resync_broadcast_domain_builds_link() {
    let mut cfg = p2p_cfg();
    cfg.interfaces.clear();
    cfg.broadcast_domains = vec![domain("bd1", Some("rt1"), &["10.1.0.1/24"])];
    let mut e = Env::ready(cfg);
    e.ifaced()
        .set_broadcast_domain("bd1", bd_status("bd1", Some("br-bd1"), &["10.1.0.1/24"]));
    e.resync().await;

    let l = e.running("broadcast-domain:bd1").await.expect("link built");
    assert_eq!(l.kernel_interface, "br-bd1");
    assert_eq!(l.network_type, NetworkType::Broadcast);
    assert_eq!(l.mtu, 1400, "the bridge's observed MTU");
    assert_eq!(l.local_prefix_len, 24);
    assert_eq!(names(&e.state.watched), ["br-bd1"]);
}

#[tokio::test]
async fn resync_passive_subinterface_is_a_stub_not_a_link() {
    let mut cfg = p2p_cfg();
    cfg.ospf_instances[0].areas[0].profiles[0].passive = true;
    let mut e = Env::ready(cfg);
    e.resync().await;

    assert!(
        e.running("eth0.0").await.is_none(),
        "no link for a passive one"
    );
    assert_eq!(
        e.links.stub_networks().await,
        HashMap::from([(
            Ipv4Addr::UNSPECIFIED,
            vec![("10.0.0.0/30".parse::<Ipv4Net>().unwrap(), 1)]
        )])
    );
    assert_eq!(names(&e.state.passive), ["eth0.0"]);
}

#[tokio::test]
async fn resync_passive_down_device_withdraws_the_stub() {
    let mut cfg = p2p_cfg();
    cfg.ospf_instances[0].areas[0].profiles[0].passive = true;
    let mut e = Env::ready(cfg);
    e.link_tx.send(table(&[("eth0", 7, true)])).unwrap();
    e.resync().await;
    assert_eq!(e.links.stub_networks().await.len(), 1);

    e.link_tx.send(table(&[("eth0", 7, false)])).unwrap();
    e.resync().await;
    assert!(e.links.stub_networks().await.is_empty(), "stub withdrawn");
    assert!(e.state.passive.is_empty());
    assert_eq!(e.state.down.get("eth0.0"), Some(&"admin-down"));

    e.link_tx.send(table(&[("eth0", 7, true)])).unwrap();
    e.resync().await;
    assert_eq!(e.links.stub_networks().await.len(), 1, "stub back");
}

#[tokio::test]
async fn resync_toggling_passive_swaps_link_and_stub_in_place() {
    let mut cfg = p2p_cfg();
    cfg.ospf_instances[0].areas[0].profiles[0].passive = true;
    let mut e = Env::ready(cfg.clone());
    e.resync().await;
    assert!(e.running("eth0.0").await.is_none());
    assert_eq!(e.links.stub_networks().await.len(), 1);

    cfg.ospf_instances[0].areas[0].profiles[0].passive = false;
    e.configd().set_config(cfg.clone());
    e.resync().await;
    assert!(e.running("eth0.0").await.is_some(), "link starts");
    assert!(e.links.stub_networks().await.is_empty(), "stub withdrawn");
    assert!(e.state.passive.is_empty());

    cfg.ospf_instances[0].areas[0].profiles[0].passive = true;
    e.configd().set_config(cfg);
    e.resync().await;
    assert!(e.running("eth0.0").await.is_none(), "link stops");
    assert_eq!(e.links.stub_networks().await.len(), 1, "stub back");
    assert_eq!(names(&e.state.passive), ["eth0.0"]);
}

#[tokio::test]
async fn resync_loopback_feeds_stub_networks() {
    let mut cfg = p2p_cfg();
    cfg.ospf_instances[0].areas[0].profiles[0].cost = Some(5);
    cfg.interfaces = vec![
        loopback("loopback-rt1", "p1"),
        loopback("loopback-v6", "p1"),
        loopback("loopback-gone", "p1"),
    ];
    let mut e = Env::ready(cfg);
    e.ifaced()
        .set_interface(loopback_status("loopback-rt1", &["1.1.1.1/32"]));
    e.ifaced()
        .set_interface(loopback_status("loopback-v6", &["2001:db8::1/128"]));
    e.resync().await;

    let stubs = e.links.stub_networks().await;
    assert_eq!(
        stubs,
        HashMap::from([(
            Ipv4Addr::UNSPECIFIED,
            vec![("1.1.1.1/32".parse::<Ipv4Net>().unwrap(), 5)]
        )]),
        "only the resolvable IPv4 loopback is a stub network"
    );
}

#[tokio::test]
async fn resync_applies_the_instance_knobs() {
    let mut cfg = p2p_cfg();
    let i = &mut cfg.ospf_instances[0];
    i.graceful_restart_grace_period = Some(120);
    i.max_metric_administrative = true;
    i.prefix_suppression = true;
    i.host_router = true;
    i.remote_lfa = true;
    i.max_metric_on_shutdown = Some(2);
    i.redistribute_metric = Some(77);
    i.redistribute_metric_type = Some(2);
    i.redistribute_policy = Some("deny-all".into());
    let mut e = Env::ready(cfg);
    e.resync().await;

    assert_eq!(e.links.grace_period(), 120);
    assert!(e.links.max_metric_active());
}

#[tokio::test]
async fn resync_own_instance_missing_clears_the_routing_table() {
    let mut e = Env::ready(Config::default());
    e.ctx.routing_table_tx.send(Some("stale".into())).unwrap();
    e.resync().await;

    assert_eq!(*e.rt.borrow(), None);
    assert!(e.running("eth0.0").await.is_none());
}

#[tokio::test]
async fn resync_keeps_state_when_the_config_fetch_fails() {
    // No configd: the dial fails, the previous state survives.
    let mut e = Env::with(&[Fake::Watchdog]);
    e.state.watched.insert("eth0".into());
    e.state.degraded.insert("eth0.0".into());
    e.ctx.routing_table_tx.send(Some("rt1".into())).unwrap();
    e.resync().await;

    assert_eq!(names(&e.state.watched), ["eth0"]);
    assert!(e.state.degraded.contains("eth0.0"));
    assert_eq!(e.rt.borrow().as_deref(), Some("rt1"));
}

#[tokio::test]
async fn resync_skips_attach_points_without_a_routing_table() {
    let mut cfg = p2p_cfg();
    cfg.interfaces = vec![iface(
        "eth0",
        vec![sub(0, &["10.0.0.1/30"], None, Some("p1"))],
    )];
    cfg.broadcast_domains = vec![domain("bd1", None, &["10.1.0.1/24"])];
    let mut e = Env::ready(cfg);
    e.resync().await;

    assert!(e.running("eth0.0").await.is_none());
    assert!(e.running("broadcast-domain:bd1").await.is_none());
    assert!(e.state.watched.is_empty());
}

#[tokio::test]
async fn resync_bfd_profile_does_not_block_the_link() {
    let mut cfg = p2p_cfg();
    cfg.ospf_instances[0].areas[0].profiles[0].bfd = Some("b1".into());
    cfg.bfd_profiles = vec![BfdProfile {
        name: "b1".into(),
        ..Default::default()
    }];
    cfg.broadcast_domains = vec![domain("bd1", Some("rt1"), &["10.1.0.1/24"])];
    let mut e = Env::ready(cfg);
    e.ifaced()
        .set_broadcast_domain("bd1", bd_status("bd1", Some("br-bd1"), &["10.1.0.1/24"]));
    e.resync().await;

    assert!(e.running("eth0.0").await.is_some());
    assert!(e.running("broadcast-domain:bd1").await.is_some());
}

#[test]
fn bfd_profile_lookup() {
    let cfg = Config {
        bfd_profiles: vec![BfdProfile {
            name: "b1".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(bfd_profile(&cfg, None).is_none());
    assert!(bfd_profile(&cfg, Some("nope")).is_none());
    assert_eq!(bfd_profile(&cfg, Some("b1")).unwrap().name, "b1");
}

// ------------------------------------------------- resync: gate/fallback

#[tokio::test]
async fn resync_down_device_aborts_then_restores_the_link() {
    let mut e = Env::ready(p2p_cfg());
    e.link_tx.send(table(&[("eth0", 7, true)])).unwrap();
    e.resync().await;
    let l = e.running("eth0.0").await.expect("up");
    assert_eq!(l.ifindex, 7);
    assert_eq!(e.state.signature, [("eth0".to_string(), Gate::Up(7))]);

    e.link_tx.send(table(&[("eth0", 7, false)])).unwrap();
    e.resync().await;
    assert!(e.running("eth0.0").await.is_none(), "aborted");
    assert_eq!(e.state.down.get("eth0.0"), Some(&"admin-down"));
    // Same reason again: still down, nothing new to log, state unchanged.
    e.resync().await;
    assert_eq!(e.state.down.get("eth0.0"), Some(&"admin-down"));

    e.link_tx.send(table(&[("eth0", 8, true)])).unwrap();
    e.resync().await;
    assert_eq!(e.running("eth0.0").await.unwrap().ifindex, 8);
    assert!(e.state.down.is_empty());
}

#[tokio::test]
async fn resync_absent_device_is_down() {
    let mut e = Env::ready(p2p_cfg());
    e.link_tx.send(table(&[("other", 1, true)])).unwrap();
    e.resync().await;
    assert!(e.running("eth0.0").await.is_none());
    assert_eq!(e.state.down.get("eth0.0"), Some(&"absent"));
}

#[tokio::test]
async fn resync_unresolvable_without_a_running_link_skips() {
    let mut e = Env::ready(p2p_cfg());
    e.ribd().set_vrf_name(None);
    e.resync().await;
    assert!(e.running("eth0.0").await.is_none());
    // The attach point is still watched: its device may come back.
    assert_eq!(names(&e.state.watched), ["eth0"]);
}

#[tokio::test]
async fn resync_keeps_the_running_link_while_the_lookup_fails() {
    let mut e = Env::ready(p2p_cfg());
    e.resync().await;
    let built = e.running("eth0.0").await.unwrap();

    // nos-interfaced forgets the interface; the config still has the address.
    e.ifaced().remove_interface("eth0");
    e.resync().await;
    let kept = e.running("eth0.0").await.expect("kept");
    assert_eq!(kept.local_addr, built.local_addr);
    assert_eq!(kept.mtu, built.mtu, "the running MTU stands in");
    assert!(e.state.degraded.contains("eth0.0"));
    // Second failing pass: already degraded, still kept.
    e.resync().await;
    assert!(e.running("eth0.0").await.is_some());
    assert!(e.state.degraded.contains("eth0.0"));

    // The address leaves the config: nothing to keep the link for.
    let mut cfg = e.configd().config();
    cfg.interfaces[0].subinterfaces[0].addresses.clear();
    e.configd().set_config(cfg);
    e.resync().await;
    assert!(e.running("eth0.0").await.is_none());
    assert!(e.state.degraded.is_empty());
}

#[tokio::test]
async fn resync_broadcast_domain_unresolvable_or_down_builds_nothing() {
    let mut cfg = p2p_cfg();
    cfg.interfaces.clear();
    // `nobridge` has no address in config and no bridge; `down` resolves but
    // its bridge device is admin-down.
    cfg.broadcast_domains = vec![
        domain("nobridge", Some("rt1"), &[]),
        domain("down", Some("rt1"), &["10.2.0.1/24"]),
    ];
    let mut e = Env::ready(cfg);
    e.ifaced()
        .set_broadcast_domain("down", bd_status("down", Some("br-down"), &["10.2.0.1/24"]));
    e.link_tx.send(table(&[("br-down", 4, false)])).unwrap();
    e.resync().await;

    assert!(e.running("broadcast-domain:nobridge").await.is_none());
    assert!(e.running("broadcast-domain:down").await.is_none());
    assert_eq!(
        e.state.down.get("broadcast-domain:down"),
        Some(&"admin-down")
    );
    assert_eq!(names(&e.state.watched), ["br-down"]);
}

#[tokio::test]
async fn resync_keeps_a_broadcast_link_when_the_bridge_lookup_fails() {
    let mut cfg = p2p_cfg();
    cfg.interfaces.clear();
    cfg.broadcast_domains = vec![domain("bd1", Some("rt1"), &["10.1.0.1/24"])];
    let mut e = Env::ready(cfg);
    e.ifaced()
        .set_broadcast_domain("bd1", bd_status("bd1", Some("br-bd1"), &["10.1.0.1/24"]));
    e.resync().await;
    assert!(e.running("broadcast-domain:bd1").await.is_some());

    e.ifaced().remove_broadcast_domain("bd1");
    e.resync().await;
    let kept = e.running("broadcast-domain:bd1").await.expect("kept");
    assert_eq!(kept.kernel_interface, "br-bd1");
    assert!(e.state.degraded.contains("broadcast-domain:bd1"));
}

#[test]
fn gate_link_table() {
    let mut state = State::default();
    let mut down = HashMap::new();
    let t = table(&[("up", 7, true), ("dn", 3, false)]);

    assert_eq!(gate_link(&state, &mut down, &t, "l", "dn"), None);
    assert_eq!(down.get("l"), Some(&"admin-down"));
    assert_eq!(gate_link(&state, &mut down, &t, "l", "missing"), None);
    assert_eq!(down.get("l"), Some(&"absent"));
    // Already recorded as down for the same reason: still None.
    state.down.insert("l".into(), "absent");
    assert_eq!(gate_link(&state, &mut down, &t, "l", "missing"), None);
    // Coming back after a down pass takes the "interface up" branch.
    assert_eq!(gate_link(&state, &mut down, &t, "l", "up"), Some(7));
    assert_eq!(
        gate_link(&State::default(), &mut down, &t, "l", "up"),
        Some(7)
    );
    assert_eq!(
        gate_link(&state, &mut down, &LinkTable::default(), "l", "up"),
        Some(0),
        "no stream: ungated"
    );
}

#[test]
fn note_fallback_table() {
    let mut state = State::default();
    let mut next = HashSet::new();
    note_fallback(&state, &mut next, "l", &[]);
    assert!(next.is_empty());
    note_fallback(&state, &mut next, "l", &["vrf", "address"]);
    assert_eq!(names(&next), ["l"]);
    state.degraded.insert("m".into());
    note_fallback(&state, &mut next, "m", &["bridge"]);
    assert_eq!(names(&next), ["l", "m"]);
}

// ----------------------------------------------------------- pure helpers

#[test]
fn virtual_links_defaults_and_flattening() {
    let mut a1 = area("0.0.0.1", vec![]);
    a1.virtual_links = vec![
        OspfVirtualLink {
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            ..Default::default()
        },
        OspfVirtualLink {
            router_id: Ipv4Addr::new(3, 3, 3, 3),
            hello_interval: Some(3),
            dead_interval: Some(12),
            auth: Some(OspfAuth::Simple { key: "pw".into() }),
        },
    ];
    let mut a2 = area("0.0.0.2", vec![]);
    a2.virtual_links = vec![OspfVirtualLink {
        router_id: Ipv4Addr::new(4, 4, 4, 4),
        ..Default::default()
    }];
    let v = virtual_links(&[a1, area("0.0.0.9", vec![]), a2], &p2p_cfg());

    assert_eq!(v.len(), 3);
    assert_eq!(v[0].transit_area, Ipv4Addr::new(0, 0, 0, 1));
    assert_eq!(v[0].endpoint, Ipv4Addr::new(2, 2, 2, 2));
    assert_eq!(
        (v[0].hello_interval, v[0].dead_interval),
        (
            nos_proto::HELLO_INTERVAL_DEFAULT,
            nos_proto::DEAD_INTERVAL_DEFAULT
        )
    );
    assert!(matches!(v[0].auth, LinkAuthConfig::None));
    assert_eq!((v[1].hello_interval, v[1].dead_interval), (3, 12));
    assert!(matches!(v[1].auth, LinkAuthConfig::Simple { .. }));
    assert_eq!(v[2].transit_area, Ipv4Addr::new(0, 0, 0, 2));
}

#[test]
fn area_settings_per_area_type() {
    let mut stub = area("0.0.0.1", vec![]);
    stub.area_type = OspfAreaType::Stub;
    let mut totally = area("0.0.0.2", vec![]);
    totally.area_type = OspfAreaType::TotallyStubby;
    totally.stub_default_cost = Some(7);
    let mut nssa = area("0.0.0.3", vec![]);
    nssa.area_type = OspfAreaType::Nssa;
    nssa.nssa_translate_always = true;
    nssa.nssa_default_originate = true;
    nssa.ranges = vec![
        OspfAreaRange {
            cidr: "10.0.0.0/16".parse().unwrap(),
            not_advertise: false,
        },
        OspfAreaRange {
            cidr: "10.1.0.0/16".parse().unwrap(),
            not_advertise: true,
        },
    ];
    let s = area_settings(&[stub, totally, nssa, area("0.0.0.0", vec![])]);
    let get = |a: &str| &s[&a.parse::<Ipv4Addr>().unwrap()];

    let (st, to, ns, bb) = (
        get("0.0.0.1"),
        get("0.0.0.2"),
        get("0.0.0.3"),
        get("0.0.0.0"),
    );
    assert!(st.stub && !st.nssa && st.import_summaries);
    assert_eq!(st.default_cost, 1);
    assert!(to.stub && !to.import_summaries);
    assert_eq!(to.default_cost, 7);
    assert!(ns.nssa && ns.nssa_translate_always && ns.nssa_default_originate);
    assert_eq!(
        ns.ranges,
        vec![
            ("10.0.0.0/16".parse().unwrap(), true),
            ("10.1.0.0/16".parse().unwrap(), false)
        ]
    );
    assert!(!bb.stub && !bb.nssa && bb.ranges.is_empty());
}

#[test]
fn resolve_effective_mtu_table() {
    let with = |mtu| OspfProfile {
        mtu,
        ..profile("p")
    };
    assert_eq!(resolve_effective_mtu(&with(Some(1200)), Some(9000)), 1200);
    assert_eq!(resolve_effective_mtu(&with(None), Some(9000)), 9000);
    assert_eq!(
        resolve_effective_mtu(&with(None), Some(u32::from(u16::MAX) + 1)),
        DEFAULT_OSPF_MTU
    );
    assert_eq!(resolve_effective_mtu(&with(None), None), DEFAULT_OSPF_MTU);
}

#[test]
fn resolve_auth_table() {
    let cfg = p2p_cfg();
    assert!(matches!(
        resolve_auth(None, true, &cfg),
        Ok(LinkAuthConfig::None)
    ));
    let simple = OspfAuth::Simple {
        key: "secret".into(),
    };
    assert!(matches!(
        resolve_auth(Some(&simple), false, &cfg),
        Ok(LinkAuthConfig::Simple { ref password }) if password == b"secret"
    ));
    let dangling = OspfAuth::Simple { key: "nope".into() };
    assert_eq!(
        resolve_auth(Some(&dangling), false, &cfg).unwrap_err(),
        "nope"
    );
    let key = |id, algorithm, is_current| OspfCryptoKey {
        key_id: id,
        algorithm,
        key: format!("k{id}"),
        is_current,
    };
    let crypto = OspfAuth::Crypto {
        keys: vec![
            key(1, OspfCryptoAlgorithm::Md5, false),
            key(9, OspfCryptoAlgorithm::HmacSha256, true),
        ],
    };
    match resolve_auth(Some(&crypto), true, &cfg).unwrap() {
        LinkAuthConfig::Crypto {
            keys,
            current_key_id,
            extended,
        } => {
            assert_eq!(current_key_id, 9);
            assert!(extended);
            assert_eq!(keys.len(), 2);
            assert_eq!((keys[1].0, keys[1].2.as_slice()), (9, b"k9".as_slice()));
        }
        _ => panic!("expected crypto"),
    }
    // No current key (commit validation forbids it): falls back to 0.
    let none_current = OspfAuth::Crypto {
        keys: vec![key(1, OspfCryptoAlgorithm::HmacSha1, false)],
    };
    assert!(matches!(
        resolve_auth(Some(&none_current), false, &cfg),
        Ok(LinkAuthConfig::Crypto {
            current_key_id: 0,
            ..
        })
    ));
    // A dangling label in a crypto list fails the whole list.
    let mut bad = key(1, OspfCryptoAlgorithm::HmacSha1, true);
    bad.key = "nope".into();
    let dangling = OspfAuth::Crypto { keys: vec![bad] };
    assert_eq!(
        resolve_auth(Some(&dangling), false, &cfg).unwrap_err(),
        "nope"
    );
}

#[test]
fn resolve_algorithm_table() {
    use packet::CryptoAlgorithm as P;
    assert!(matches!(
        resolve_algorithm(OspfCryptoAlgorithm::Md5),
        P::Md5
    ));
    assert!(matches!(
        resolve_algorithm(OspfCryptoAlgorithm::HmacSha1),
        P::HmacSha1
    ));
    assert!(matches!(
        resolve_algorithm(OspfCryptoAlgorithm::HmacSha256),
        P::HmacSha256
    ));
    assert!(matches!(
        resolve_algorithm(OspfCryptoAlgorithm::HmacSha384),
        P::HmacSha384
    ));
    assert!(matches!(
        resolve_algorithm(OspfCryptoAlgorithm::HmacSha512),
        P::HmacSha512
    ));
}

fn policy_cfg(source: &str) -> Config {
    Config {
        community_aliases: vec![CommunityAlias {
            name: "CUST".into(),
            value: "65000:100".into(),
        }],
        community_groups: vec![CommunityGroup {
            name: "GRP".into(),
            members: vec!["CUST".into(), "65000:200".into(), "garbage".into()],
        }],
        prefix_lists: vec![PrefixList {
            name: "PL".into(),
            entries: vec![PrefixListEntry {
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: None,
            }],
        }],
        as_path_lists: vec![AsPathList {
            name: "AP".into(),
            patterns: vec!["^65001_".into()],
        }],
        policy_definitions: vec![PolicyDefinition {
            name: "pol".into(),
            source: source.into(),
        }],
        ..Default::default()
    }
}

fn verdict(policy: &nos_rpl::CompiledPolicy, prefix: &str, communities: &[u32]) -> bool {
    let input = nos_rpl::Input {
        prefix: prefix.parse().unwrap(),
        bgp: nos_rpl::BgpInput {
            tag: 0,
            origin: nos_rpl::Origin::Igp,
            as_path: &[65001, 65002],
            as_path_segments: &[],
            local_pref: 100,
            med: None,
            next_hop: None,
            learned_via_ibgp: false,
            router_id: None,
            originator_id: None,
            cluster_list: &[],
            peer: None,
            peer_as: 0,
            communities,
            extended_communities: &[],
            large_communities: &[],
            validation_state: nos_rpl::ValidationState::default(),
            rd: None,
            local_role: None,
            remote_role: None,
            otc: None,
        },
    };
    matches!(
        nos_rpl::vm::run(policy, &input),
        nos_rpl::Verdict::Accept { .. }
    )
}

#[test]
fn redistribute_policy_resolution() {
    let cfg = policy_cfg("");
    let accepts = |p: &nos_rpl::CompiledPolicy| verdict(p, "192.0.2.0/24", &[]);
    assert!(accepts(&resolve_redistribute_policy(&cfg, None)));
    assert!(accepts(&resolve_redistribute_policy(
        &cfg,
        Some("accept-all")
    )));
    assert!(!accepts(&resolve_redistribute_policy(
        &cfg,
        Some("deny-all")
    )));
    assert!(
        !accepts(&resolve_redistribute_policy(&cfg, Some("undefined"))),
        "unknown name: deny-all"
    );
    assert!(
        !accepts(&resolve_redistribute_policy(&cfg, Some("pol"))),
        "a source with a syntax error: deny-all"
    );
}

#[test]
fn redistribute_policy_wires_every_symbol_table() {
    let src = "\
if this.prefix in PL:
    if this.bgp.as_path in AP:
        if this.bgp.communities.contains(CUST):
            if this.bgp.communities.contains(GRP):
                accept
reject
";
    let cfg = policy_cfg(src);
    let p = resolve_redistribute_policy(&cfg, Some("pol"));
    let cust = 0xFDE8_0064; // 65000:100
    let other = 0xFDE8_00C8; // 65000:200

    assert!(verdict(&p, "10.0.0.0/8", &[cust, other]));
    assert!(
        !verdict(&p, "10.0.0.0/9", &[cust, other]),
        "prefix-list entries without a range are exact"
    );
    assert!(!verdict(&p, "10.0.0.0/8", &[other]), "alias missing");
    assert!(!verdict(&p, "10.0.0.0/8", &[]));
}

// -------------------------------------------------------- IPC resolvers

fn all_fakes() -> Fakes {
    let f = Fakes::start(&[Fake::Watchdog, Fake::Ribd("rt1".into()), Fake::Interfaced]);
    f.ribd["rt1"].set_vrf_name(Some("vrf100".into()));
    f
}

#[tokio::test]
async fn resolve_vrf_cases() {
    let f = all_fakes();
    let wd = f.watchdog_socket();
    assert_eq!(resolve_vrf(&wd, "rt1").await.as_deref(), Some("vrf100"));
    assert_eq!(
        resolve_vrf(&wd, "rt9").await,
        None,
        "watchdog: not available"
    );
    f.ribd["rt1"].set_vrf_name(None);
    assert_eq!(resolve_vrf(&wd, "rt1").await, None, "ribd has no VRF yet");
    assert_eq!(
        resolve_vrf(Path::new("/nonexistent/wd.sock"), "rt1").await,
        None
    );
}

#[tokio::test]
async fn resolve_local_address_cases() {
    let f = all_fakes();
    let wd = f.watchdog_socket();
    let ifd = f.interfaced.as_ref().unwrap();
    ifd.set_interface(status(
        "eth0",
        1500,
        vec![
            sub_status(0, &["10.0.0.1/30", "10.9.9.9/24"]),
            sub_status(1, &[]),
            sub_status(2, &["2001:db8::1/64"]),
        ],
    ));

    assert_eq!(
        resolve_local_address(&wd, "eth0", 0).await,
        Some((Ipv4Addr::new(10, 0, 0, 1), 30, 1500, None)),
        "first address wins"
    );
    assert_eq!(
        resolve_local_address(&wd, "eth0", 5).await,
        None,
        "no such tag"
    );
    assert_eq!(
        resolve_local_address(&wd, "eth0", 1).await,
        None,
        "no address"
    );
    assert_eq!(resolve_local_address(&wd, "eth0", 2).await, None, "IPv6");
    assert_eq!(
        resolve_local_address(&wd, "nope", 0).await,
        None,
        "no interface"
    );

    let no_ifaced = Fakes::start(&[Fake::Watchdog]);
    assert_eq!(
        resolve_local_address(&no_ifaced.watchdog_socket(), "eth0", 0).await,
        None,
        "watchdog cannot resolve nos-interfaced"
    );
}

#[tokio::test]
async fn resolve_loopback_prefix_cases() {
    let f = all_fakes();
    let wd = f.watchdog_socket();
    let ifd = f.interfaced.as_ref().unwrap();
    ifd.set_interface(loopback_status("loopback-a", &["1.1.1.1/32"]));
    ifd.set_interface(loopback_status("loopback-b", &[]));
    ifd.set_interface(loopback_status("loopback-c", &["2001:db8::1/128"]));

    assert_eq!(
        resolve_loopback_prefix(&wd, "loopback-a").await,
        Some((Ipv4Addr::new(1, 1, 1, 1), 32))
    );
    assert_eq!(resolve_loopback_prefix(&wd, "loopback-b").await, None);
    assert_eq!(resolve_loopback_prefix(&wd, "loopback-c").await, None);
    assert_eq!(resolve_loopback_prefix(&wd, "loopback-z").await, None);
    let no_ifaced = Fakes::start(&[Fake::Watchdog]);
    assert_eq!(
        resolve_loopback_prefix(&no_ifaced.watchdog_socket(), "loopback-a").await,
        None
    );
}

#[tokio::test]
async fn resolve_broadcast_domain_cases() {
    let f = all_fakes();
    let wd = f.watchdog_socket();
    let ifd = f.interfaced.as_ref().unwrap();
    ifd.set_broadcast_domain("ok", bd_status("ok", Some("br1"), &["10.1.0.1/24"]));
    ifd.set_broadcast_domain("nobridge", bd_status("nobridge", None, &["10.1.0.1/24"]));
    ifd.set_broadcast_domain("noaddr", bd_status("noaddr", Some("br2"), &[]));
    ifd.set_broadcast_domain("v6", bd_status("v6", Some("br3"), &["2001:db8::1/64"]));

    assert_eq!(
        resolve_broadcast_domain(&wd, "ok").await,
        Some((
            Ipv4Addr::new(10, 1, 0, 1),
            24,
            "br1".to_string(),
            Some(1400),
            None
        ))
    );
    assert_eq!(resolve_broadcast_domain(&wd, "nobridge").await, None);
    assert_eq!(resolve_broadcast_domain(&wd, "noaddr").await, None);
    assert_eq!(resolve_broadcast_domain(&wd, "v6").await, None);
    assert_eq!(resolve_broadcast_domain(&wd, "gone").await, None);
    let no_ifaced = Fakes::start(&[Fake::Watchdog]);
    assert_eq!(
        resolve_broadcast_domain(&no_ifaced.watchdog_socket(), "ok").await,
        None
    );
}

#[tokio::test(start_paused = true)]
async fn wait_or_shutdown_cases() {
    let (tx, mut rx) = watch::channel(false);
    assert!(!wait_or_shutdown(Duration::from_secs(1), &mut rx).await);
    tx.send(true).unwrap();
    assert!(wait_or_shutdown(Duration::from_secs(60), &mut rx).await);
    // A change to `false` ends the wait but is not a shutdown.
    let (tx, mut rx) = watch::channel(false);
    tx.send(false).unwrap();
    assert!(!wait_or_shutdown(Duration::from_secs(60), &mut rx).await);
}

// --------------------------------------------------------------- run loop

/// `run` over an `Env`, with the knobs a test needs to poke at it.
struct Running {
    fakes: Fakes,
    links: Arc<LinkManager>,
    link_tx: Option<watch::Sender<LinkTable>>,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

fn start(e: Env, shutdown_at_entry: bool) -> Running {
    let Env {
        fakes,
        links,
        ctx,
        link_tx,
        ..
    } = e;
    let (shutdown, shutdown_rx) = watch::channel(shutdown_at_entry);
    let task = tokio::spawn(super::run(
        ctx.config_socket,
        ctx.watchdog_socket,
        ctx.instance,
        ctx.links,
        ctx.routing_table_tx,
        ctx.link_rx,
        shutdown_rx,
    ));
    Running {
        fakes,
        links,
        link_tx: Some(link_tx),
        shutdown,
        task,
    }
}

impl Running {
    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(60), self.task)
            .await
            .expect("run stops on shutdown")
            .unwrap();
    }
}

/// Polls `cond` on the (paused) clock, 50ms apart, for at most 30s.
async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..600 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Waits until `link` is running and `pred` holds for its config.
async fn link_until(
    links: &LinkManager,
    link: &str,
    pred: impl Fn(&crate::link::LinkConfig) -> bool,
) {
    for _ in 0..600 {
        if links.running_config(link).await.is_some_and(|l| pred(&l)) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for link {link}");
}

#[tokio::test(start_paused = true)]
async fn run_resyncs_on_connect_and_on_diff() {
    let r = start(Env::ready(p2p_cfg()), false);
    let configd = r.fakes.configd.as_ref().unwrap();
    link_until(&r.links, "eth0.0", |_| true).await;
    until("connected", || {
        configd.connections() >= 1 && configd.gets() >= 1
    })
    .await;
    assert!(r.links.running_config("eth0.0").await.is_some());

    // Edit the served config, then announce it.
    let mut cfg = configd.config();
    cfg.ospf_instances[0].areas[0].profiles[0].cost = Some(42);
    configd.set_config(cfg);
    let gets = configd.gets();
    configd.push_diff(ConfigDiff::default());
    until("diff resync", || configd.gets() > gets).await;
    link_until(&r.links, "eth0.0", |l| l.cost == 42).await;
    r.stop().await;
}

#[tokio::test(start_paused = true)]
async fn run_stops_at_once_when_shutdown_is_already_set() {
    let r = start(Env::ready(p2p_cfg()), true);
    let gets = r.fakes.configd.as_ref().unwrap().gets();
    tokio::time::timeout(Duration::from_secs(60), r.task)
        .await
        .expect("returns")
        .unwrap();
    assert_eq!(gets, 0);
}

#[tokio::test(start_paused = true)]
async fn run_survives_an_unreachable_configd_and_stops_on_shutdown() {
    // No configd socket at all: warn, wait RECONNECT_DELAY, retry.
    let e = Env::with(&[Fake::Watchdog]);
    let r = start(e, false);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!r.task.is_finished());
    r.stop().await;
}

#[tokio::test(start_paused = true)]
async fn run_reapplies_on_the_tick_without_a_diff() {
    let r = start(Env::ready(p2p_cfg()), false);
    let configd = r.fakes.configd.as_ref().unwrap();
    until("first resync", || configd.gets() >= 1).await;
    // Nothing is pushed from here on: only REAPPLY_INTERVAL ticks can add
    // fetches (the connect-time ones may still be in flight, hence +3).
    let gets = configd.gets();
    // The paused clock no longer auto-advances while socket I/O is pending
    // (tokio 1.53.3), so step it by hand, giving the real I/O time to land.
    for _ in 0..20 {
        if configd.gets() >= gets + 3 {
            break;
        }
        tokio::time::advance(Duration::from_secs(10)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    assert!(configd.gets() >= gets + 3, "ticks resync");
    r.stop().await;
}

/// Real time (a resync is real socket I/O): the debounce is 200ms, so the
/// whole test stays under a couple of seconds. The clock is only frozen for
/// the final shutdown, whose flush window is 6s.
#[tokio::test]
async fn run_resyncs_on_a_link_change_only_when_the_signature_moves() {
    let mut r = start(Env::ready(p2p_cfg()), false);
    let configd = r.fakes.configd.as_ref().unwrap();
    link_until(&r.links, "eth0.0", |_| true).await;
    // The connect-time resyncs (subscribe, the fake's first diff) settle.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let settled = configd.gets();
    let link_tx = r.link_tx.as_ref().unwrap();

    // A device nobody watches: the debounced check finds the signature equal.
    let mut unrelated = LinkTable::default();
    unrelated.links.insert(
        "dummy9".into(),
        LinkState {
            name: "dummy9".into(),
            ifindex: 9,
            admin_up: true,
            carrier: true,
            port_aggregate: None,
        },
    );
    link_tx.send(unrelated).unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(configd.gets(), settled, "no resync for an unwatched link");

    // The watched device appears with an ifindex: signature moves, one resync.
    link_tx.send(table(&[("eth0", 5, true)])).unwrap();
    link_until(&r.links, "eth0.0", |l| l.ifindex == 5).await;
    assert_eq!(configd.gets(), settled + 1);

    // The sender going away closes that arm; the loop keeps running.
    r.link_tx = None;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!r.task.is_finished());
    tokio::time::pause();
    r.stop().await;
}

/// A configd whose subscription stream ends right away (and counts the
/// subscribes) and that sends a non-diff event first.
#[tokio::test(start_paused = true)]
async fn run_ignores_non_diff_events_and_resubscribes_after_a_close() {
    let f = Fakes::start(&[Fake::Watchdog, Fake::Ribd("rt1".into()), Fake::Interfaced]);
    f.ribd["rt1"].set_vrf_name(Some("vrf100".into()));
    f.interfaced.as_ref().unwrap().set_interface(status(
        "eth0",
        1500,
        vec![sub_status(0, &["10.0.0.1/30"])],
    ));
    let subscribes = Arc::new(AtomicUsize::new(0));
    let gets = Arc::new(AtomicUsize::new(0));
    let (s, g) = (Arc::clone(&subscribes), Arc::clone(&gets));
    let cfg = p2p_cfg();
    let _configd = serve(
        &f.config_socket(),
        "configd",
        "",
        move |req: &Request| match req {
            Request::Get => {
                g.fetch_add(1, Ordering::SeqCst);
                Reply::One(Event::Config(cfg.clone()))
            }
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

    let wire = Arc::new(Wire::default());
    let links = LinkManager::with_opener(1, None, BootCounter::in_memory(), wire.opener());
    let (rt_tx, rt) = watch::channel(None);
    let (_link_tx, link_rx) = watch::channel(LinkTable::default());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(super::run(
        f.config_socket(),
        f.watchdog_socket(),
        "i1".into(),
        Arc::clone(&links),
        rt_tx,
        link_rx,
        shutdown_rx,
    ));

    until("resubscribed", || subscribes.load(Ordering::SeqCst) >= 2).await;
    // Every (re)connect resyncs once; the non-diff event adds nothing.
    until("second resync", || gets.load(Ordering::SeqCst) >= 2).await;
    assert_eq!(rt.borrow().as_deref(), Some("rt1"));
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .unwrap()
        .unwrap();
}

/// A configd that answers the subscription with a frame the codec refuses:
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
                // A well-framed payload that is no `Event` (variant index 0xffffffff).
                let _ = stream
                    .write_all(&[4, 0, 0, 0, 0xff, 0xff, 0xff, 0xff])
                    .await;
                let _ = stream.flush().await;
                tokio::time::sleep(Duration::from_secs(3600)).await;
            });
        }
    });

    let wire = Arc::new(Wire::default());
    let links = LinkManager::with_opener(1, None, BootCounter::in_memory(), wire.opener());
    let (rt_tx, _rt) = watch::channel(None);
    let (_link_tx, link_rx) = watch::channel(LinkTable::default());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(super::run(
        f.config_socket(),
        f.watchdog_socket(),
        "i1".into(),
        links,
        rt_tx,
        link_rx,
        shutdown_rx,
    ));
    until("reconnected", || accepted.load(Ordering::SeqCst) >= 2).await;
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .unwrap()
        .unwrap();
}
