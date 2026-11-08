//! The post-policy BMP tap (#864): which Adj-RIB-In changes reach a station.

use super::*;
use crate::bmp::{Hub, PeerUpInfo, Scope, StationCfg};
use crate::flowspec::{Afi, FlowSpec};
use crate::message::{BgpCodec, BgpMessage};
use crate::rib::bmp_tap::BmpKey;
use bytes::BytesMut;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Decoder;

const PEER: &str = "10.0.0.1";

async fn frame(s: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut h = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut h))
        .await
        .expect("a BMP frame in time")
        .unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(h[1..5].try_into().unwrap()) as usize - 6];
    s.read_exact(&mut body).await.unwrap();
    (h[5], body)
}

/// The next Route Monitoring frame: (L flag, decoded UPDATE).
async fn route(s: &mut TcpStream) -> (bool, UpdateMessage) {
    let (t, body) = frame(s).await;
    assert_eq!(t, 0, "Route Monitoring");
    let mut b = BytesMut::from(&body[42..]);
    let Some(BgpMessage::Update(u)) = BgpCodec::default().decode(&mut b).unwrap() else {
        panic!("an UPDATE")
    };
    (body[1] & 0x40 != 0, u)
}

async fn setup() -> (BgpRib, Arc<Hub>, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub = Hub::new();
    hub.set_stations(vec![StationCfg {
        name: "s".into(),
        addr: listener.local_addr().unwrap(),
        vrf: None,
        sys_name: "x".into(),
        table: None,
        scope: Scope::default(),
        monitor: nos_proto::BmpMonitor::PostPolicy,
        statistics_interval: None,
        monitor_out: nos_proto::BmpMonitorOut::None,
    }])
    .await;
    let (mut c, _) = listener.accept().await.unwrap();
    assert_eq!(frame(&mut c).await.0, 4, "Initiation");
    hub.peer_up(PeerUpInfo {
        peer: addr(PEER),
        asn: 65001,
        bgp_id: v4("192.0.2.1"),
        two_octet_as: false,
        local: addr("10.0.0.254"),
        local_port: 179,
        remote_port: 1,
        sent_open: bytes::Bytes::new(),
        recv_open: bytes::Bytes::new(),
        time: Duration::ZERO,
        add_path_afis: HashSet::new(),
    });
    assert_eq!(frame(&mut c).await.0, 3, "Peer Up");
    let mut rib = new_rib(65000);
    rib.set_bmp(hub.clone());
    std::mem::forget(register_mp_peer(
        &mut rib,
        addr(PEER),
        false,
        addr("10.0.0.254"),
        AddressFamily::ALL.into_iter().collect(),
    ));
    (rib, hub, c)
}

fn learn(rib: &mut BgpRib, prefixes: &[&str], policy: &nos_rpl::CompiledPolicy) {
    let u = ebgp_update(prefixes.to_vec(), vec![65001], PEER);
    rib.handle_update(addr(PEER), false, v4("192.0.2.1"), &u, policy);
}

fn withdraw(rib: &mut BgpRib, p: &str) {
    let u = UpdateMessage {
        withdrawn_routes: vec![p.parse().unwrap()],
        ..empty_update()
    };
    rib.handle_update(addr(PEER), false, v4("192.0.2.1"), &u, &nos_rpl::ACCEPT_ALL);
}

#[tokio::test]
async fn announce_withdraw_and_state_compression() {
    let (mut rib, hub, mut c) = setup().await;
    learn(&mut rib, &["1.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    let (post, u) = route(&mut c).await;
    assert!(post, "L flag set");
    assert_eq!(u.nlri, vec!["1.0.0.0/24".parse().unwrap()]);
    assert_eq!(u.attributes.unwrap().as_path.flat(), [65001]);

    // An identical re-announcement and a policy-rejected prefix send nothing:
    // the next frame is the sentinel.
    learn(&mut rib, &["1.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    learn(&mut rib, &["9.0.0.0/24"], &nos_rpl::DENY_ALL);
    learn(&mut rib, &["2.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    assert_eq!(
        route(&mut c).await.1.nlri,
        vec!["2.0.0.0/24".parse().unwrap()]
    );

    // A rejected re-announcement of a held prefix is a withdraw.
    learn(&mut rib, &["2.0.0.0/24"], &nos_rpl::DENY_ALL);
    assert_eq!(
        route(&mut c).await.1.withdrawn_routes,
        vec!["2.0.0.0/24".parse().unwrap()]
    );

    withdraw(&mut rib, "1.0.0.0/24");
    assert_eq!(
        route(&mut c).await.1.withdrawn_routes,
        vec!["1.0.0.0/24".parse().unwrap()]
    );
    // Withdrawing what is not held sends nothing.
    withdraw(&mut rib, "1.0.0.0/24");
    learn(&mut rib, &["3.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    assert_eq!(
        route(&mut c).await.1.nlri,
        vec!["3.0.0.0/24".parse().unwrap()]
    );
    hub.shutdown().await;
}

#[tokio::test]
async fn re_evaluation_reaches_the_station() {
    let (mut rib, hub, mut c) = setup().await;
    let peer = addr(PEER);
    rib.set_peer_soft_reconfig(peer, true);
    learn(&mut rib, &["1.0.0.0/24"], &nos_rpl::DENY_ALL);
    // Loosening the policy admits the retained route: announced post-policy.
    rib.reevaluate_peer(peer, Arc::new(nos_rpl::ACCEPT_ALL.clone()));
    assert_eq!(
        route(&mut c).await.1.nlri,
        vec!["1.0.0.0/24".parse().unwrap()]
    );
    // Tightening withdraws it.
    rib.reevaluate_peer(peer, Arc::new(nos_rpl::DENY_ALL.clone()));
    assert_eq!(
        route(&mut c).await.1.withdrawn_routes,
        vec!["1.0.0.0/24".parse().unwrap()]
    );
    hub.shutdown().await;
}

#[test]
fn an_unmonitored_rib_does_no_work() {
    let mut rib = new_rib(65000);
    rib.set_bmp(Hub::new());
    assert!(
        super::super::bmp_tap::tap(rib.bmp.as_ref()).is_none(),
        "no station: gate closed"
    );
    std::mem::forget(register_peer(
        &mut rib,
        addr(PEER),
        false,
        addr("10.0.0.254"),
    ));
    learn(&mut rib, &["1.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    assert_eq!(rib.bmp_keys(addr(PEER), true).len(), 1);
}

#[test]
fn dump_reads_the_current_paths_and_skips_withdrawn_keys() {
    let mut rib = new_rib(65000);
    let peer = addr(PEER);
    std::mem::forget(register_peer(&mut rib, peer, false, addr("10.0.0.254")));
    rib.set_peer_soft_reconfig(peer, true);
    learn(&mut rib, &["1.0.0.0/24", "2.0.0.0/24"], &nos_rpl::DENY_ALL);
    assert!(
        rib.bmp_keys(peer, true).is_empty(),
        "rejected: not post-policy"
    );
    let mut pre = rib.bmp_keys(peer, false);
    pre.sort_by_key(|k| format!("{k:?}"));
    assert_eq!(
        pre,
        vec![
            BmpKey::Prefix(prefix("1.0.0.0/24")),
            BmpKey::Prefix(prefix("2.0.0.0/24"))
        ]
    );
    withdraw(&mut rib, "2.0.0.0/24");
    // The snapshot predates the withdrawal: its key yields nothing.
    let updates = rib.bmp_updates(peer, false, &pre, &HashSet::new());
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].nlri, vec!["1.0.0.0/24".parse().unwrap()]);
    assert_eq!(
        rib.bmp_families(peer).len(),
        2,
        "both unicast families negotiated"
    );
    assert_eq!(rib.bmp_families(addr("10.9.9.9")), Vec::<(u16, u8)>::new());
}

fn feed(rib: &mut BgpRib, u: &UpdateMessage) {
    rib.handle_update(addr(PEER), false, v4("192.0.2.1"), u, &nos_rpl::ACCEPT_ALL);
}

fn flow_rule(last: u8) -> FlowSpec {
    FlowSpec::decode(Afi::V4, &[5, 1, 24, 10, last, 0])
        .unwrap()
        .0
}

fn flow_reach(rule: FlowSpec) -> UpdateMessage {
    let mut u = ebgp_update(vec![], vec![65001], "0.0.0.0");
    u.attributes.as_mut().unwrap().extended_communities = vec![0x8006_0000_0000_0000];
    u.mp_reach = vec![message::MpReachNlri {
        afi: 1,
        safi: message::SAFI_FLOWSPEC,
        next_hop: addr("0.0.0.0"),
        nlri: vec![],
        nlri_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![rule],
        vpn: vec![],
        rtc: vec![],
    }];
    u
}

fn mp_unreach(afi: u16, safi: u8) -> message::MpUnreachNlri {
    message::MpUnreachNlri {
        afi,
        safi,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![],
        vpn: vec![],
        rtc: vec![],
    }
}

fn vpn_nlri(last: u8) -> crate::vpn::VpnNlri {
    super::vpn::nlri(
        super::vpn::RD1,
        &format!("10.10.{last}.0/24"),
        100 + u32::from(last),
    )
}

#[tokio::test]
async fn evpn_announce_withdraw_and_state_compression() {
    let (mut rib, hub, mut c) = setup().await;
    let n = evpn_nlri(1);
    feed(&mut rib, &evpn_reach(vec![n.clone()], vec![65001]));
    let (post, u) = route(&mut c).await;
    assert!(post);
    assert_eq!(u.mp_reach[0].evpn, vec![n.clone()]);
    assert_eq!(u.mp_reach[0].next_hop, addr("192.0.2.1"));
    assert_eq!(
        u.attributes.unwrap().extended_communities,
        vec![0x0002_fde8_0000_2710]
    );
    // Identical re-announcement: nothing; the next frame is the sentinel.
    feed(&mut rib, &evpn_reach(vec![n.clone()], vec![65001]));
    feed(&mut rib, &evpn_reach(vec![evpn_nlri(2)], vec![65001]));
    assert_eq!(route(&mut c).await.1.mp_reach[0].evpn, vec![evpn_nlri(2)]);
    let mut w = empty_update();
    w.mp_unreach = vec![message::MpUnreachNlri {
        evpn: vec![n.clone()],
        ..mp_unreach(message::AFI_L2VPN, message::SAFI_EVPN)
    }];
    feed(&mut rib, &w);
    assert_eq!(route(&mut c).await.1.mp_unreach[0].evpn, vec![n]);
    hub.shutdown().await;
}

#[tokio::test]
async fn evpn_import_policy_rejection_is_a_withdraw() {
    let (mut rib, hub, mut c) = setup().await;
    let n = evpn_nlri(1);
    feed(&mut rib, &evpn_reach(vec![n.clone()], vec![65001]));
    route(&mut c).await;
    rib.set_peer_evpn_import_policy(addr(PEER), Some(Arc::new(nos_rpl::DENY_ALL.clone())), false);
    assert_eq!(route(&mut c).await.1.mp_unreach[0].evpn, vec![n]);
    hub.shutdown().await;
}

#[tokio::test]
async fn flowspec_announce_and_withdraw() {
    let (mut rib, hub, mut c) = setup().await;
    feed(&mut rib, &flow_reach(flow_rule(1)));
    let u = route(&mut c).await.1;
    assert_eq!(u.mp_reach[0].flowspec, vec![flow_rule(1)]);
    assert_eq!(
        u.attributes.unwrap().extended_communities,
        vec![0x8006_0000_0000_0000]
    );
    feed(&mut rib, &flow_reach(flow_rule(1)));
    feed(&mut rib, &flow_reach(flow_rule(2)));
    assert_eq!(
        route(&mut c).await.1.mp_reach[0].flowspec,
        vec![flow_rule(2)]
    );
    let mut w = empty_update();
    w.mp_unreach = vec![message::MpUnreachNlri {
        flowspec: vec![flow_rule(1)],
        ..mp_unreach(1, message::SAFI_FLOWSPEC)
    }];
    feed(&mut rib, &w);
    assert_eq!(
        route(&mut c).await.1.mp_unreach[0].flowspec,
        vec![flow_rule(1)]
    );
    hub.shutdown().await;
}

#[tokio::test]
async fn vpn_announce_withdraw_and_policy_rejection() {
    let (mut rib, hub, mut c) = setup().await;
    feed(
        &mut rib,
        &super::vpn::reach("192.0.2.7", vec![65001], vec![vpn_nlri(1)]),
    );
    let u = route(&mut c).await.1;
    assert_eq!(u.mp_reach[0].vpn, vec![vpn_nlri(1)]);
    assert_eq!(u.mp_reach[0].next_hop, addr("192.0.2.7"));
    feed(
        &mut rib,
        &super::vpn::reach("192.0.2.7", vec![65001], vec![vpn_nlri(1)]),
    );
    feed(
        &mut rib,
        &super::vpn::reach("192.0.2.7", vec![65001], vec![vpn_nlri(2)]),
    );
    assert_eq!(route(&mut c).await.1.mp_reach[0].vpn, vec![vpn_nlri(2)]);
    let mut w = empty_update();
    w.mp_unreach = vec![message::MpUnreachNlri {
        vpn: vec![crate::vpn::VpnNlri {
            labels: vec![],
            ..vpn_nlri(1)
        }],
        ..mp_unreach(1, message::SAFI_VPN)
    }];
    feed(&mut rib, &w);
    assert_eq!(
        route(&mut c).await.1.mp_unreach[0].vpn[0].prefix,
        vpn_nlri(1).prefix
    );
    // A rejecting import policy withdraws a held path.
    rib.handle_update(
        addr(PEER),
        false,
        v4("192.0.2.1"),
        &super::vpn::reach("192.0.2.7", vec![65001], vec![vpn_nlri(2)]),
        &nos_rpl::DENY_ALL,
    );
    assert_eq!(
        route(&mut c).await.1.mp_unreach[0].vpn[0].prefix,
        vpn_nlri(2).prefix
    );
    hub.shutdown().await;
}

#[test]
fn the_dump_walks_every_family_post_and_pre_policy() {
    let mut rib = new_rib(65000);
    let peer = addr(PEER);
    std::mem::forget(register_mp_peer(
        &mut rib,
        peer,
        false,
        addr("10.0.0.254"),
        AddressFamily::ALL.into_iter().collect(),
    ));
    rib.set_peer_soft_reconfig(peer, true);
    learn(&mut rib, &["1.0.0.0/24"], &nos_rpl::ACCEPT_ALL);
    feed(&mut rib, &evpn_reach(vec![evpn_nlri(1)], vec![65001]));
    feed(&mut rib, &flow_reach(flow_rule(1)));
    feed(
        &mut rib,
        &super::vpn::reach("192.0.2.7", vec![65001], vec![vpn_nlri(1)]),
    );
    for post in [true, false] {
        let keys = rib.bmp_keys(peer, post);
        assert_eq!(keys.len(), 4, "post={post}: one key per family");
        let updates = rib.bmp_updates(peer, post, &keys, &HashSet::new());
        assert_eq!(updates.len(), 4);
        assert_eq!(
            updates
                .iter()
                .map(|u| (u.mp_reach.first().map(|m| (m.afi, m.safi)), u.nlri.len()))
                .collect::<HashSet<_>>(),
            HashSet::from([
                (None, 1),
                (Some((message::AFI_L2VPN, message::SAFI_EVPN)), 0),
                (Some((1, message::SAFI_FLOWSPEC)), 0),
                (Some((1, message::SAFI_VPN)), 0),
            ])
        );
    }
    // A rejected EVPN route is pre-policy only (the policy change itself
    // dropped the held one).
    rib.set_peer_evpn_import_policy(peer, Some(Arc::new(nos_rpl::DENY_ALL.clone())), false);
    feed(&mut rib, &evpn_reach(vec![evpn_nlri(9)], vec![65001]));
    let evpn = |post| {
        rib.bmp_keys(peer, post)
            .into_iter()
            .filter(|k| matches!(k, BmpKey::Evpn(_)))
            .count()
    };
    assert_eq!((evpn(true), evpn(false)), (0, 1));
    assert_eq!(rib.bmp_families(peer).len(), 7);
}
