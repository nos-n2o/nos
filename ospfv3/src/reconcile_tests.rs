//! `resync`, `run` and the IPC resolvers against the shared fakes (#343, #347).
//! The link layer runs over the in-memory wire of `link::tests`, so a resync
//! really builds links and the assertions read them back through
//! `LinkManager::running_config`.
//!
//! The attach points use `nostst0`, a device no host has: an ungated link
//! (no stream) must then fail `if_nametoindex`, and a gated one gets its
//! ifindex from the `LinkTable` a test feeds in.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use ipnet::Ipv6Net;
use nos_proto::schema::BfdProfile;
use nos_proto::{
    AsPathList, BroadcastDomain, BroadcastDomainStatus, CommunityAlias, CommunityGroup, Config,
    ConfigDiff, Event, Interface, InterfaceAddress, InterfaceEvent, InterfaceStatus, LinkState,
    NetworkType, OspfCryptoAlgorithm, OspfCryptoKey, Ospfv3Area, Ospfv3Instance, Ospfv3Profile,
    PolicyDefinition, PrefixList, PrefixListEntry, Request, Subinterface, SubinterfaceStatus,
};
use nos_test_support::{serve, Fake, Fakes, Reply};
use tokio::sync::watch;

use super::{
    attach_points_for, bfd_profile, broadcast_domain_attach_points, gate_link, kernel_ifindex,
    loopback_attach_points, note_fallback, pick_interface_id, resolve_auth,
    resolve_broadcast_domain, resolve_effective_mtu, resolve_local_address,
    resolve_loopback_prefix, resolve_redistribute_policy, resolve_vrf, resync,
    subinterface_attach_points, subinterface_kernel_interface, wait_or_shutdown, Ctx, State,
    DEFAULT_OSPF_MTU,
};
use crate::link::tests::wire::Wire;
use crate::link::{LinkConfig, LinkManager};
use crate::link_client::{apply, Gate, LinkTable};
use crate::packet::CryptoAlgorithm as P;

/// The kernel device every attach point sits on.
const IF: &str = "nostst0";

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
        ospfv3_profiles: profile.map(Into::into).into_iter().collect(),
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
        ospfv3_profiles: vec![profile.into()],
        ..Default::default()
    }
}

fn domain(name: &str, rt: Option<&str>, addrs: &[&str]) -> BroadcastDomain {
    BroadcastDomain {
        name: name.into(),
        routing_table: rt.map(Into::into),
        ospfv3_profiles: vec!["p1".into()],
        addresses: addrs.iter().map(|a| addr(a)).collect(),
        ..Default::default()
    }
}

fn profile(name: &str) -> Ospfv3Profile {
    Ospfv3Profile {
        name: name.into(),
        ..Default::default()
    }
}

fn area(id: &str, profiles: Vec<Ospfv3Profile>) -> Ospfv3Area {
    Ospfv3Area {
        area_id: id.parse().unwrap(),
        profiles,
        ranges: Vec::new(),
        area_type: nos_proto::OspfAreaType::Normal,
        stub_default_cost: None,
        nssa_translate_always: false,
        nssa_default_originate: false,
        virtual_links: Vec::new(),
    }
}

fn instance(areas: Vec<Ospfv3Area>) -> Ospfv3Instance {
    Ospfv3Instance {
        name: "i1".into(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        areas,
        routing_table: Some("rt1".into()),
        ..Default::default()
    }
}

const V6: &str = "2001:db8:1::1/64";
const LL: &str = "fe80::1";

/// One instance, area 0 with profile `p1`, `nostst0.0` with `2001:db8:1::1/64` in `rt1`.
/// Admin keystore: label `k<id>` holds the secret `k<id>`.
fn keystore() -> Config {
    let key = |l: &str| nos_proto::schema::AdminKey {
        label: l.into(),
        secret: l.into(),
    };
    Config {
        admin: nos_proto::schema::Admin {
            keys: ["k1", "k2", "k3", "k4", "k5", "k9"]
                .into_iter()
                .map(key)
                .collect(),
        },
        ..Default::default()
    }
}

fn p2p_cfg() -> Config {
    Config {
        admin: keystore().admin,
        ospfv3_instances: vec![instance(vec![area("0.0.0.0", vec![profile("p1")])])],
        interfaces: vec![iface(IF, vec![sub(0, &[V6], Some("rt1"), Some("p1"))])],
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
    }
}

fn sub_status(tag: u16, addrs: &[&str], ll: Option<&str>) -> SubinterfaceStatus {
    SubinterfaceStatus {
        mtu: 1500,
        tag,
        addresses: addrs.iter().map(|a| addr(a)).collect(),
        routing_table: Some("rt1".into()),
        link_local_address: ll.map(|l| l.parse().unwrap()),
    }
}

fn loopback_status(name: &str, addrs: &[&str]) -> InterfaceStatus {
    InterfaceStatus {
        addresses: addrs.iter().map(|a| addr(a)).collect(),
        ..status(name, 65536, vec![])
    }
}

fn bd_status(
    name: &str,
    bridge: Option<&str>,
    ll: Option<&str>,
    addrs: &[&str],
) -> BroadcastDomainStatus {
    BroadcastDomainStatus {
        name: name.into(),
        addresses: addrs.iter().map(|a| addr(a)).collect(),
        routing_table: Some("rt1".into()),
        link_local_address: ll.map(|l| l.parse().unwrap()),
        bridge_name: bridge.map(Into::into),
        mtu: Some(1400),
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

/// What every attach point of these tests is up on, by default.
fn all_up() -> LinkTable {
    table(&[(IF, 7, true), ("nostst0.100", 8, true), ("br-bd1", 9, true)])
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
    /// All four fakes up, `rt1`'s VRF `vrf100` and `nostst0` (MTU 9000) with
    /// the address of `p2p_cfg` resolvable, every device up.
    fn ready(cfg: Config) -> Self {
        let e = Self::with(&[
            Fake::Configd(cfg),
            Fake::Watchdog,
            Fake::Ribd("rt1".into()),
            Fake::Interfaced,
        ]);
        e.ribd().set_vrf_name(Some("vrf100".into()));
        e.ifaced()
            .set_interface(status(IF, 9000, vec![sub_status(0, &[V6], Some(LL))]));
        e.link_tx.send(all_up()).unwrap();
        e
    }

    fn with(which: &[Fake]) -> Self {
        let fakes = Fakes::start(which);
        let wire = Arc::new(Wire::default());
        let links = LinkManager::with_opener(1, None, wire.opener());
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

    async fn running(&self, link: &str) -> Option<LinkConfig> {
        self.links.running_config(link).await
    }

    /// Serves `bd1` with bridge `br-bd1` and builds the config around it.
    fn with_domain(mut cfg: Config) -> Self {
        cfg.interfaces.clear();
        cfg.broadcast_domains = vec![domain("bd1", Some("rt1"), &[V6])];
        let e = Self::ready(cfg);
        e.ifaced()
            .set_broadcast_domain("bd1", bd_status("bd1", Some("br-bd1"), Some(LL), &[V6]));
        e
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

    let l = e.running("nostst0.0").await.expect("link built");
    assert_eq!(l.vrf, "vrf100");
    assert_eq!(l.link_local_address, LL.parse::<Ipv6Addr>().unwrap());
    assert_eq!(l.prefix, V6.parse::<Ipv6Net>().unwrap());
    assert_eq!(l.kernel_interface, IF);
    assert_eq!(l.interface_id, 7, "the stream's ifindex");
    assert_eq!(l.area_id, Ipv4Addr::UNSPECIFIED);
    assert_eq!(l.network_type, NetworkType::PointToPoint);
    assert_eq!(l.cost, 1);
    assert_eq!(l.hello_interval, nos_proto::HELLO_INTERVAL_DEFAULT);
    assert_eq!(l.dead_interval, nos_proto::DEAD_INTERVAL_DEFAULT);
    assert_eq!(l.priority, nos_proto::PRIORITY_DEFAULT);
    assert_eq!(l.mtu, 9000, "the interface's MTU from nos-interfaced");
    assert_eq!(l.instance_id, 0);
    assert!(l.auth.is_none() && !l.mtu_ignore);
    assert_eq!(e.rt.borrow().as_deref(), Some("rt1"));
    assert_eq!(names(&e.state.watched), [IF]);
    assert_eq!(e.state.signature, [(IF.to_string(), Gate::Up(7))]);
    assert!(e.state.down.is_empty() && e.state.degraded.is_empty());
}

#[tokio::test]
async fn resync_profile_knobs_override_the_defaults() {
    let mut cfg = p2p_cfg();
    cfg.ospfv3_instances[0].areas = vec![area(
        "0.0.0.1",
        vec![Ospfv3Profile {
            hello_interval: Some(5),
            dead_interval: Some(20),
            priority: Some(7),
            cost: Some(9),
            mtu: Some(1400),
            mtu_ignore: true,
            network_type: Some(NetworkType::Broadcast),
            instance_id: Some(3),
            auth: Some(vec![
                OspfCryptoKey {
                    key_id: 1,
                    algorithm: OspfCryptoAlgorithm::Md5,
                    key: "dropped".into(),
                    is_current: false,
                },
                OspfCryptoKey {
                    key_id: 9,
                    algorithm: OspfCryptoAlgorithm::HmacSha256,
                    key: "k9".into(),
                    is_current: true,
                },
            ]),
            ..profile("p1")
        }],
    )];
    let mut e = Env::ready(cfg);
    e.resync().await;

    let l = e.running("nostst0.0").await.expect("link built");
    assert_eq!(
        (l.hello_interval, l.dead_interval, l.priority, l.cost),
        (5, 20, 7, 9)
    );
    assert_eq!(l.mtu, 1400, "the profile's mtu beats the interface's");
    assert!(l.mtu_ignore);
    assert_eq!(l.network_type, NetworkType::Broadcast);
    assert_eq!(l.area_id, Ipv4Addr::new(0, 0, 0, 1));
    assert_eq!(l.instance_id, 3);
    let auth = l.auth.expect("authenticated");
    assert_eq!(auth.current_key_id, 9);
    assert_eq!(
        auth.keys,
        [(9, P::HmacSha256, b"k9".to_vec())],
        "the md5 key is not representable and is dropped"
    );
}

#[tokio::test]
async fn resync_stub_area_marks_the_link_and_feeds_the_manager() {
    let mut cfg = p2p_cfg();
    cfg.ospfv3_instances[0].areas = vec![Ospfv3Area {
        area_type: nos_proto::OspfAreaType::TotallyStubby,
        stub_default_cost: Some(3),
        ..area("0.0.0.1", vec![profile("p1")])
    }];
    let mut e = Env::ready(cfg);
    e.resync().await;
    let l = e.running("nostst0.0").await.expect("link built");
    assert!(l.stub, "the link's area is a stub");
    assert_eq!(
        e.links.stub_areas_for_test(),
        std::collections::HashMap::from([(Ipv4Addr::new(0, 0, 0, 1), (false, 3))])
    );
}

#[tokio::test]
async fn resync_nssa_area_marks_the_link_and_feeds_the_manager() {
    let mut cfg = p2p_cfg();
    cfg.ospfv3_instances[0].areas = vec![Ospfv3Area {
        area_type: nos_proto::OspfAreaType::Nssa,
        nssa_translate_always: true,
        ..area("0.0.0.1", vec![profile("p1")])
    }];
    let mut e = Env::ready(cfg);
    e.resync().await;
    let l = e.running("nostst0.0").await.expect("link built");
    assert!(l.stub && l.nssa, "an NSSA link is stub-like and N-bit");
    let id = Ipv4Addr::new(0, 0, 0, 1);
    assert_eq!(
        e.links.nssa_areas_for_test(),
        std::collections::HashMap::from([(
            id,
            crate::link::NssaSettings {
                translate_always: true,
                default_originate: false
            }
        )])
    );
    assert_eq!(
        e.links.stub_areas_for_test(),
        std::collections::HashMap::from([(id, (true, 1))])
    );
}

#[tokio::test]
async fn resync_dangling_auth_label_does_not_start_the_link() {
    let mut cfg = p2p_cfg();
    let mut p = profile("p1");
    p.auth = Some(vec![OspfCryptoKey {
        key_id: 1,
        algorithm: OspfCryptoAlgorithm::HmacSha256,
        key: "nope".into(),
        is_current: true,
    }]);
    cfg.ospfv3_instances[0].areas = vec![area("0.0.0.0", vec![p])];
    let mut e = Env::ready(cfg);
    e.resync().await;
    assert!(
        e.running(&format!("{IF}.0")).await.is_none(),
        "must fail closed, not start unauthenticated"
    );
}

#[tokio::test]
async fn resync_tagged_subinterface_uses_the_dotted_kernel_name() {
    let mut cfg = p2p_cfg();
    cfg.interfaces = vec![iface(IF, vec![sub(100, &[V6], Some("rt1"), Some("p1"))])];
    let mut e = Env::ready(cfg);
    e.ifaced()
        .set_interface(status(IF, 1500, vec![sub_status(100, &[V6], Some(LL))]));
    e.resync().await;

    let l = e.running("nostst0.100").await.expect("link built");
    assert_eq!(l.kernel_interface, "nostst0.100");
    assert_eq!(l.interface_id, 8);
    assert_eq!(names(&e.state.watched), ["nostst0.100"]);
}

#[test]
fn subinterface_kernel_interface_table() {
    assert_eq!(subinterface_kernel_interface("eth0", 0), "eth0");
    assert_eq!(subinterface_kernel_interface("eth0", 5), "eth0.5");
}

#[tokio::test]
async fn resync_broadcast_domain_builds_link() {
    let mut e = Env::with_domain(p2p_cfg());
    e.resync().await;

    let l = e.running("broadcast-domain:bd1").await.expect("link built");
    assert_eq!(l.kernel_interface, "br-bd1");
    assert_eq!(l.interface_id, 9);
    assert_eq!(l.network_type, NetworkType::Broadcast);
    assert_eq!(l.mtu, 1400, "the bridge's observed MTU");
    assert_eq!(l.link_local_address, LL.parse::<Ipv6Addr>().unwrap());
    assert_eq!(l.vrf, "vrf100");
    assert_eq!(names(&e.state.watched), ["br-bd1"]);
}

#[tokio::test]
async fn resync_loopback_feeds_the_prefix_map() {
    let mut cfg = p2p_cfg();
    cfg.ospfv3_instances[0].areas[0].profiles[0].cost = Some(5);
    cfg.interfaces = vec![
        loopback("loopback-rt1", "p1"),
        loopback("loopback-v4", "p1"),
        loopback("loopback-gone", "p1"),
        // Not a loopback: carries the profile but is never a stub network.
        Interface {
            ospfv3_profiles: vec!["p1".into()],
            ..iface("eth9", vec![])
        },
    ];
    let mut e = Env::ready(cfg);
    e.ifaced()
        .set_interface(loopback_status("loopback-rt1", &["2001:db8::1/128"]));
    e.ifaced()
        .set_interface(loopback_status("loopback-v4", &["1.1.1.1/32"]));
    e.resync().await;

    assert_eq!(
        e.links.loopback_prefixes().await,
        HashMap::from([(
            Ipv4Addr::UNSPECIFIED,
            vec![("2001:db8::1/128".parse::<Ipv6Net>().unwrap(), 5)]
        )]),
        "only the resolvable IPv6 loopback"
    );
}

#[tokio::test]
async fn resync_applies_the_instance_knobs() {
    let mut cfg = p2p_cfg();
    let i = &mut cfg.ospfv3_instances[0];
    i.extended_lsa = true;
    i.graceful_restart_grace_period = Some(120);
    i.redistribute_policy = Some("deny-all".into());
    let mut e = Env::ready(cfg);
    e.resync().await;

    assert!(e.links.extended_lsa());
    assert_eq!(e.links.grace_period(), 120);
    let p = e.links.redistribute_policy().await;
    assert!(!verdict(&p, "2001:db8::/32", &[]), "deny-all installed");
}

#[tokio::test]
async fn resync_sparse_mode_originates_the_legacy_flavor() {
    let mut cfg = p2p_cfg();
    cfg.ospfv3_instances[0].extended_lsa_sparse = true;
    let mut e = Env::ready(cfg);
    e.resync().await;
    assert!(!e.links.extended_lsa());
}

#[tokio::test]
async fn resync_own_instance_missing_clears_the_routing_table() {
    let mut e = Env::ready(Config::default());
    e.ctx.routing_table_tx.send(Some("stale".into())).unwrap();
    e.resync().await;

    assert_eq!(*e.rt.borrow(), None);
    assert!(e.running("nostst0.0").await.is_none());
}

#[tokio::test]
async fn resync_keeps_state_when_the_config_fetch_fails() {
    // No configd: the dial fails, the previous state survives.
    let mut e = Env::with(&[Fake::Watchdog]);
    e.state.watched.insert(IF.into());
    e.state.degraded.insert("nostst0.0".into());
    e.ctx.routing_table_tx.send(Some("rt1".into())).unwrap();
    e.resync().await;

    assert_eq!(names(&e.state.watched), [IF]);
    assert!(e.state.degraded.contains("nostst0.0"));
    assert_eq!(e.rt.borrow().as_deref(), Some("rt1"));
}

#[tokio::test]
async fn resync_skips_attach_points_without_a_routing_table() {
    let mut cfg = p2p_cfg();
    cfg.interfaces = vec![iface(IF, vec![sub(0, &[V6], None, Some("p1"))])];
    cfg.broadcast_domains = vec![domain("bd1", None, &[V6])];
    let mut e = Env::ready(cfg);
    e.resync().await;

    assert!(e.running("nostst0.0").await.is_none());
    assert!(e.running("broadcast-domain:bd1").await.is_none());
    assert!(e.state.watched.is_empty());
}

#[tokio::test]
async fn resync_bfd_profile_is_wanted_on_both_attach_kinds() {
    let mut cfg = p2p_cfg();
    cfg.ospfv3_instances[0].areas[0].profiles[0].bfd = Some("b1".into());
    cfg.bfd_profiles = vec![BfdProfile {
        name: "b1".into(),
        ..Default::default()
    }];
    cfg.broadcast_domains = vec![domain("bd1", Some("rt1"), &[V6])];
    let mut e = Env::ready(cfg);
    e.ifaced()
        .set_broadcast_domain("bd1", bd_status("bd1", Some("br-bd1"), Some(LL), &[V6]));
    e.resync().await;

    assert!(e.running("nostst0.0").await.is_some());
    assert!(e.running("broadcast-domain:bd1").await.is_some());
    let mut wanted: Vec<_> = e.links.bfd_wanted().into_keys().collect();
    wanted.sort();
    assert_eq!(wanted, ["broadcast-domain:bd1", "nostst0.0"]);
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
    e.resync().await;
    assert_eq!(e.running("nostst0.0").await.unwrap().interface_id, 7);

    e.link_tx.send(table(&[(IF, 7, false)])).unwrap();
    e.resync().await;
    assert!(e.running("nostst0.0").await.is_none(), "aborted");
    assert_eq!(e.state.down.get("nostst0.0"), Some(&"admin-down"));
    assert_eq!(
        e.state.signature,
        [(IF.to_string(), Gate::Down("admin-down"))]
    );
    // Same reason again: still down, state unchanged.
    e.resync().await;
    assert_eq!(e.state.down.get("nostst0.0"), Some(&"admin-down"));
    // A different reason.
    e.link_tx.send(table(&[("other", 1, true)])).unwrap();
    e.resync().await;
    assert_eq!(e.state.down.get("nostst0.0"), Some(&"absent"));

    // Recreated with another ifindex: back up, a new interface id.
    e.link_tx.send(table(&[(IF, 8, true)])).unwrap();
    e.resync().await;
    assert_eq!(e.running("nostst0.0").await.unwrap().interface_id, 8);
    assert!(e.state.down.is_empty());
}

#[tokio::test]
async fn resync_unresolvable_without_a_running_link_skips() {
    let mut e = Env::ready(p2p_cfg());
    e.ribd().set_vrf_name(None);
    e.resync().await;
    assert!(e.running("nostst0.0").await.is_none());
    // The attach point is still watched: its device may come back.
    assert_eq!(names(&e.state.watched), [IF]);
    assert!(e.state.degraded.is_empty());
}

#[tokio::test]
async fn resync_ungated_missing_device_is_not_present_yet() {
    let mut e = Env::ready(p2p_cfg());
    // No stream, and `nostst0` is no device of this host.
    e.link_tx.send(LinkTable::default()).unwrap();
    e.resync().await;
    assert!(e.running("nostst0.0").await.is_none());
    assert_eq!(e.state.signature, [(IF.to_string(), Gate::Ungated)]);
}

#[tokio::test]
async fn resync_keeps_the_running_link_while_the_lookup_fails() {
    let mut e = Env::ready(p2p_cfg());
    e.resync().await;
    let built = e.running("nostst0.0").await.unwrap();

    // nos-interfaced forgets the interface; the config still has the address.
    e.ifaced().remove_interface(IF);
    e.resync().await;
    let kept = e.running("nostst0.0").await.expect("kept");
    assert_eq!(kept, built, "every value stands in from the running link");
    assert!(e.state.degraded.contains("nostst0.0"));
    // Second failing pass: already degraded, still kept.
    e.resync().await;
    assert!(e.running("nostst0.0").await.is_some());
    assert!(e.state.degraded.contains("nostst0.0"));

    // The stream goes away too: the running link's interface id stands in.
    e.link_tx.send(LinkTable::default()).unwrap();
    e.resync().await;
    assert_eq!(e.running("nostst0.0").await.unwrap().interface_id, 7);

    // The address leaves the config: nothing to keep the link for.
    let mut cfg = e.configd().config();
    cfg.interfaces[0].subinterfaces[0].addresses.clear();
    e.configd().set_config(cfg);
    e.resync().await;
    assert!(e.running("nostst0.0").await.is_none());
    assert!(e.state.degraded.is_empty());
}

#[tokio::test]
async fn resync_broadcast_domain_unresolvable_or_down_builds_nothing() {
    let mut cfg = p2p_cfg();
    cfg.interfaces.clear();
    // `nobridge` resolves to nothing and has no address; `down` resolves but
    // its bridge is admin-down; `nodev` resolves but its bridge device does
    // not exist (ungated: `if_nametoindex` fails).
    cfg.broadcast_domains = vec![
        domain("nobridge", Some("rt1"), &[]),
        domain("down", Some("rt1"), &[V6]),
        domain("nodev", Some("rt1"), &[V6]),
    ];
    let mut e = Env::ready(cfg);
    e.ifaced()
        .set_broadcast_domain("down", bd_status("down", Some("br-down"), Some(LL), &[V6]));
    e.ifaced().set_broadcast_domain(
        "nodev",
        bd_status("nodev", Some("br-nostst-nodev"), Some(LL), &[V6]),
    );
    e.link_tx.send(table(&[("br-down", 4, false)])).unwrap();
    e.resync().await;

    assert!(e.running("broadcast-domain:nobridge").await.is_none());
    assert!(e.running("broadcast-domain:down").await.is_none());
    assert_eq!(
        e.state.down.get("broadcast-domain:down"),
        Some(&"admin-down")
    );
    // `br-nostst-nodev` is absent from the stream: down, never built.
    assert!(e.running("broadcast-domain:nodev").await.is_none());
    assert_eq!(e.state.down.get("broadcast-domain:nodev"), Some(&"absent"));

    // Same, with no stream at all: the device lookup is the one that fails.
    e.link_tx.send(LinkTable::default()).unwrap();
    e.resync().await;
    assert!(e.running("broadcast-domain:nodev").await.is_none());
    assert!(e.state.down.is_empty());
}

#[tokio::test]
async fn resync_keeps_a_broadcast_link_when_the_bridge_lookup_fails() {
    let mut e = Env::with_domain(p2p_cfg());
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
    // A different reason than the recorded one.
    assert_eq!(gate_link(&state, &mut down, &t, "l", "dn"), None);
    assert_eq!(down.get("l"), Some(&"admin-down"));
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
fn kernel_ifindex_and_interface_id() {
    assert!(kernel_ifindex("lo").is_some());
    assert_eq!(kernel_ifindex("nostst-nope0"), None);
    assert!(pick_interface_id(0, "lo", None).is_some());
    assert_eq!(pick_interface_id(0, "nostst-nope0", None), None);
}

#[test]
fn resolve_effective_mtu_table() {
    let with = |mtu| Ospfv3Profile {
        mtu,
        ..profile("p")
    };
    assert_eq!(resolve_effective_mtu(&with(Some(1200)), Some(9000)), 1200);
    assert_eq!(resolve_effective_mtu(&with(None), Some(1400)), 1400);
    assert_eq!(
        resolve_effective_mtu(&with(None), Some(70_000)),
        DEFAULT_OSPF_MTU,
        "does not fit a u16"
    );
    assert_eq!(resolve_effective_mtu(&with(None), None), DEFAULT_OSPF_MTU);
}

#[test]
fn resolve_auth_table() {
    let cfg = keystore();
    assert_eq!(resolve_auth(&profile("p"), &cfg), Ok(None));
    let key = |key_id, algorithm, is_current| OspfCryptoKey {
        key_id,
        algorithm,
        key: format!("k{key_id}"),
        is_current,
    };
    let keyed = |keys| Ospfv3Profile {
        auth: Some(keys),
        ..profile("p")
    };
    let a = resolve_auth(
        &keyed(vec![
            key(1, OspfCryptoAlgorithm::Md5, false),
            key(2, OspfCryptoAlgorithm::HmacSha1, false),
            key(3, OspfCryptoAlgorithm::HmacSha256, false),
            key(4, OspfCryptoAlgorithm::HmacSha384, true),
            key(5, OspfCryptoAlgorithm::HmacSha512, false),
        ]),
        &cfg,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        a.keys,
        [
            (2, P::HmacSha1, b"k2".to_vec()),
            (3, P::HmacSha256, b"k3".to_vec()),
            (4, P::HmacSha384, b"k4".to_vec()),
            (5, P::HmacSha512, b"k5".to_vec()),
        ]
    );
    assert_eq!(a.current_key_id, 4);
    // No current key (commit validation forbids it): falls back to 0.
    let b = resolve_auth(
        &keyed(vec![key(1, OspfCryptoAlgorithm::HmacSha1, false)]),
        &cfg,
    )
    .unwrap()
    .unwrap();
    assert_eq!(b.current_key_id, 0);
    // A dangling label fails the whole list.
    let mut bad = key(1, OspfCryptoAlgorithm::HmacSha1, true);
    bad.key = "nope".into();
    assert_eq!(resolve_auth(&keyed(vec![bad]), &cfg), Err("nope".into()));
}

#[test]
fn attach_points_mixed_config_in_order() {
    let mut cfg = Config {
        interfaces: vec![
            Interface {
                ospfv3_profiles: vec!["p1".into()],
                ..iface(
                    "loopback-a",
                    vec![
                        sub(7, &[], Some("rt1"), Some("p1")),
                        sub(8, &[], Some("rt1"), Some("other")),
                    ],
                )
            },
            Interface {
                ospfv3_profiles: vec!["other".into()],
                ..iface("eth1", vec![])
            },
            // Carries the profile but is no loopback.
            Interface {
                ospfv3_profiles: vec!["p1".into()],
                ..iface("eth2", vec![])
            },
        ],
        broadcast_domains: vec![domain("bd1", Some("rt1"), &["2001:db8::1/64"])],
        ..Default::default()
    };
    cfg.broadcast_domains.push(BroadcastDomain {
        ospfv3_profiles: vec!["other".into()],
        ..domain("bd2", None, &[])
    });

    assert_eq!(
        attach_points_for(&cfg, "p1"),
        ["loopback-a", "loopback-a.7", "eth2", "broadcast-domain:bd1"]
    );
    let l = loopback_attach_points(&cfg, "p1");
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].interface, "loopback-a");
    assert_eq!(subinterface_attach_points(&cfg, "p1").len(), 1);
}

#[test]
fn broadcast_domain_has_address_means_ipv6() {
    let cfg = Config {
        broadcast_domains: vec![
            domain("v6", Some("rt1"), &["2001:db8::1/64"]),
            domain("v4", Some("rt1"), &["10.0.0.1/24"]),
            domain("none", Some("rt1"), &[]),
        ],
        ..Default::default()
    };
    let pts = broadcast_domain_attach_points(&cfg, "p1");
    assert_eq!(
        pts.iter().map(|p| p.has_address).collect::<Vec<_>>(),
        [true, false, false]
    );
}

// --------------------------------------------------- redistribute policy

fn policy_cfg(source: &str) -> Config {
    Config {
        community_aliases: vec![
            CommunityAlias {
                name: "CUST".into(),
                value: "65000:100".into(),
            },
            // An unparseable value: filtered out of the alias table.
            CommunityAlias {
                name: "BAD".into(),
                value: "not-a-community".into(),
            },
        ],
        community_groups: vec![CommunityGroup {
            name: "GRP".into(),
            // by alias, by literal, and one unparseable member (dropped)
            members: vec!["CUST".into(), "65000:200".into(), "garbage".into()],
        }],
        prefix_lists: vec![
            PrefixList {
                name: "PL".into(),
                entries: vec![PrefixListEntry {
                    cidr: "2001:db8::/32".parse().unwrap(),
                    range: Some((48, 64)),
                }],
            },
            PrefixList {
                name: "EXACT".into(),
                entries: vec![PrefixListEntry {
                    cidr: "2001:db8:ffff::/48".parse().unwrap(),
                    range: None,
                }],
            },
        ],
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
    let accepts = |p: &nos_rpl::CompiledPolicy| verdict(p, "2001:db8:1::/48", &[]);
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
        "a source that does not compile: deny-all"
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

    assert!(verdict(&p, "2001:db8:1::/48", &[cust, other]));
    assert!(
        verdict(&p, "2001:db8:1:2::/64", &[cust, other]),
        "inside the entry's range"
    );
    assert!(
        !verdict(&p, "2001:db8::/32", &[cust, other]),
        "shorter than the range"
    );
    assert!(!verdict(&p, "2001:db8:1::/48", &[other]), "alias missing");
    assert!(!verdict(&p, "2001:db8:1::/48", &[]));
    assert!(!verdict(&p, "2001:db9::/48", &[cust, other]));
}

#[test]
fn redistribute_policy_literal_and_bad_alias_references() {
    // The exact entry has no range; the unparseable alias is not defined for
    // the compiler, so its use is a compile error: deny-all.
    let cfg = policy_cfg("if this.prefix in EXACT:\n    accept\nreject\n");
    let p = resolve_redistribute_policy(&cfg, Some("pol"));
    assert!(verdict(&p, "2001:db8:ffff::/48", &[]));
    assert!(!verdict(&p, "2001:db8:ffff::/64", &[]));

    let cfg = policy_cfg("if this.bgp.communities.contains(BAD):\n    accept\nreject\n");
    let p = resolve_redistribute_policy(&cfg, Some("pol"));
    assert!(!verdict(&p, "2001:db8:ffff::/48", &[]));
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
    f.interfaced.as_ref().unwrap().set_interface(status(
        "eth0",
        1500,
        vec![
            sub_status(
                0,
                &["10.9.9.9/24", "2001:db8::1/64", "2001:db8:2::1/64"],
                Some(LL),
            ),
            sub_status(1, &["2001:db8:3::1/64"], None),
            sub_status(2, &["10.0.0.1/24"], Some("fe80::2")),
        ],
    ));

    let ok = resolve_local_address(&wd, "eth0", 0).await.expect("found");
    assert_eq!(ok.link_local_address, LL.parse::<Ipv6Addr>().unwrap());
    assert_eq!(
        ok.prefix,
        "2001:db8::1/64".parse::<Ipv6Net>().unwrap(),
        "first IPv6 address wins"
    );
    assert_eq!(ok.mtu, Some(1500));
    assert!(
        resolve_local_address(&wd, "eth0", 5).await.is_none(),
        "no such tag"
    );
    assert!(
        resolve_local_address(&wd, "eth0", 1).await.is_none(),
        "no link-local address yet"
    );
    assert!(
        resolve_local_address(&wd, "eth0", 2).await.is_none(),
        "IPv4 only"
    );
    assert!(resolve_local_address(&wd, "nope", 0).await.is_none());

    let no_ifaced = Fakes::start(&[Fake::Watchdog]);
    assert!(
        resolve_local_address(&no_ifaced.watchdog_socket(), "eth0", 0)
            .await
            .is_none(),
        "watchdog cannot resolve nos-interfaced"
    );
}

#[tokio::test]
async fn resolve_loopback_prefix_cases() {
    let f = all_fakes();
    let wd = f.watchdog_socket();
    let ifd = f.interfaced.as_ref().unwrap();
    ifd.set_interface(loopback_status("loopback-a", &["2001:db8::1/128"]));
    ifd.set_interface(loopback_status("loopback-b", &["1.1.1.1/32"]));

    assert_eq!(
        resolve_loopback_prefix(&wd, "loopback-a").await,
        Some("2001:db8::1/128".parse().unwrap())
    );
    assert_eq!(resolve_loopback_prefix(&wd, "loopback-b").await, None);
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
    ifd.set_broadcast_domain("ok", bd_status("ok", Some("br1"), Some(LL), &[V6]));
    ifd.set_broadcast_domain("nobridge", bd_status("nobridge", None, Some(LL), &[V6]));
    ifd.set_broadcast_domain("noll", bd_status("noll", Some("br2"), None, &[V6]));
    ifd.set_broadcast_domain("noaddr", bd_status("noaddr", Some("br3"), Some(LL), &[]));
    ifd.set_broadcast_domain(
        "v4",
        bd_status("v4", Some("br4"), Some(LL), &["10.1.0.1/24"]),
    );

    let (l, bridge) = resolve_broadcast_domain(&wd, "ok").await.expect("found");
    assert_eq!(bridge, "br1");
    assert_eq!(l.link_local_address, LL.parse::<Ipv6Addr>().unwrap());
    assert_eq!(l.prefix, V6.parse::<Ipv6Net>().unwrap());
    assert_eq!(l.mtu, Some(1400), "the bridge's observed MTU");
    for name in ["nobridge", "noll", "noaddr", "v4", "gone"] {
        assert!(
            resolve_broadcast_domain(&wd, name).await.is_none(),
            "{name}"
        );
    }
    let no_ifaced = Fakes::start(&[Fake::Watchdog]);
    assert!(resolve_broadcast_domain(&no_ifaced.watchdog_socket(), "ok")
        .await
        .is_none());
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
async fn link_until(links: &LinkManager, link: &str, pred: impl Fn(&LinkConfig) -> bool) {
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
    link_until(&r.links, "nostst0.0", |_| true).await;
    until("connected", || {
        configd.connections() >= 1 && configd.gets() >= 1
    })
    .await;

    // Edit the served config, then announce it.
    let mut cfg = configd.config();
    cfg.ospfv3_instances[0].areas[0].profiles[0].cost = Some(42);
    configd.set_config(cfg);
    let gets = configd.gets();
    configd.push_diff(ConfigDiff::default());
    until("diff resync", || configd.gets() > gets).await;
    link_until(&r.links, "nostst0.0", |l| l.cost == 42).await;
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
    link_until(&r.links, "nostst0.0", |_| true).await;
    // The connect-time resyncs (subscribe, the fake's first diff) settle.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let settled = configd.gets();
    let link_tx = r.link_tx.as_ref().unwrap();

    // A device nobody watches appears: the signature is unchanged.
    link_tx
        .send(table(&[(IF, 7, true), ("dummy9", 9, true)]))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(configd.gets(), settled, "no resync for an unwatched link");

    // The watched device is recreated: signature moves, one resync.
    link_tx.send(table(&[(IF, 5, true)])).unwrap();
    link_until(&r.links, "nostst0.0", |l| l.interface_id == 5).await;
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
        IF,
        1500,
        vec![sub_status(0, &[V6], Some(LL))],
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
    let links = LinkManager::with_opener(1, None, wire.opener());
    let (rt_tx, rt) = watch::channel(None);
    let (link_tx, link_rx) = watch::channel(LinkTable::default());
    link_tx.send(all_up()).unwrap();
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
    let links = LinkManager::with_opener(1, None, wire.opener());
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

#[tokio::test]
async fn resync_passive_advertises_the_prefix_without_a_link_and_toggles() {
    let mut cfg = p2p_cfg();
    cfg.ospfv3_instances[0].areas[0].profiles[0].passive = true;
    let mut e = Env::ready(cfg);
    e.resync().await;

    assert!(e.running("nostst0.0").await.is_none(), "no link");
    let net = V6.parse::<Ipv6Net>().unwrap().trunc();
    assert_eq!(
        e.links.loopback_prefixes().await,
        HashMap::from([(Ipv4Addr::UNSPECIFIED, vec![(net, 1)])])
    );
    assert_eq!(names(&e.state.passive), ["nostst0.0"]);

    // Clearing the flag starts the link and drops the stub, no restart.
    let mut cfg = e.configd().config();
    cfg.ospfv3_instances[0].areas[0].profiles[0].passive = false;
    e.configd().set_config(cfg);
    e.resync().await;
    assert!(e.running("nostst0.0").await.is_some());
    assert!(e.links.loopback_prefixes().await.is_empty());
    assert!(e.state.passive.is_empty());
}
