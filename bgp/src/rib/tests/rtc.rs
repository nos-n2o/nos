//! RFC 4684 RT-Constraint (#875): membership exchange, reflection and the
//! outbound VPN/EVPN filter.

use super::vpn::{advs, feed, nlri, reach, EBGP, IBGP, P, RD1, RT, SRC};
use super::*;
use crate::message::RtcNlri;
use crate::rib::rtc::RtcInterest;

const RT2: u64 = 0x0002_fde8_0000_0002; // RT:65000:2
pub(super) const OBS_AS: u32 = 65003;

fn key(origin_as: u32, rt: u64, bits: u8) -> RtcNlri {
    RtcNlri {
        origin_as,
        rt,
        bits,
    }
}

pub(super) fn exact(rt: u64) -> RtcNlri {
    key(OBS_AS, rt, 96)
}

fn default_rt() -> RtcNlri {
    key(0, 0, 0)
}

fn rtc_afs() -> HashSet<AddressFamily> {
    HashSet::from([
        AddressFamily::Ipv4Unicast,
        AddressFamily::Vpnv4Unicast,
        AddressFamily::RtConstraint,
        AddressFamily::L2vpnEvpn,
    ])
}

fn plain_afs() -> HashSet<AddressFamily> {
    HashSet::from([AddressFamily::Ipv4Unicast, AddressFamily::Vpnv4Unicast])
}

fn reg(
    rib: &mut BgpRib,
    peer: &str,
    ibgp: bool,
    rr_client: bool,
    afs: HashSet<AddressFamily>,
) -> mpsc::Receiver<OutboundUpdate> {
    let (tx, rx) = test_channel();
    rib.peer_established(
        addr(peer),
        ibgp,
        Some(addr("10.0.0.254")),
        afs,
        true,
        None,
        rr_client,
        false,
        HashSet::new(),
        accept_all_policy(),
        tx,
    );
    rx
}

pub(super) fn rtc_update(peer_as: u32, next_hop: &str, rtc: Vec<RtcNlri>) -> UpdateMessage {
    let mut u = ebgp_update(vec![], vec![peer_as], "0.0.0.0");
    u.mp_reach = vec![message::MpReachNlri {
        afi: 1,
        safi: message::SAFI_RTC,
        next_hop: addr(next_hop),
        nlri: vec![],
        nlri_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![],
        flowspec_vpn: vec![],
        vpn: vec![],
        rtc,
    }];
    u
}

pub(super) fn rtc_withdraw(rtc: Vec<RtcNlri>) -> UpdateMessage {
    let mut u = empty_update();
    u.mp_unreach = vec![message::MpUnreachNlri {
        afi: 1,
        safi: message::SAFI_RTC,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![],
        flowspec_vpn: vec![],
        vpn: vec![],
        rtc,
    }];
    u
}

/// A reflector (AS 65000) with the VPN source `SRC` (eBGP), an eBGP observer
/// with RTC, an iBGP observer without RTC and one more eBGP observer that
/// never negotiated it. Receivers: source, rtc observer, plain observer.
fn setup() -> (BgpRib, Vec<mpsc::Receiver<OutboundUpdate>>) {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr(SRC), 65001);
    rib.set_peer_asn(addr(EBGP), OBS_AS);
    let rx = vec![
        reg(&mut rib, SRC, false, false, plain_afs()),
        reg(&mut rib, EBGP, false, false, rtc_afs()),
        reg(&mut rib, IBGP, true, false, plain_afs()),
    ];
    (rib, rx)
}

fn rtcs(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Vec<OutboundUpdate> {
    recv_all(rx)
        .into_iter()
        .filter(|u| {
            matches!(
                u,
                OutboundUpdate::AnnounceRtc(_) | OutboundUpdate::WithdrawRtc(_)
            )
        })
        .collect()
}

fn withdrawn_vpn(rx: &mut mpsc::Receiver<OutboundUpdate>) -> usize {
    recv_all(rx)
        .into_iter()
        .filter(|u| matches!(u, OutboundUpdate::WithdrawVpn(..)))
        .count()
}

#[test]
fn interest_permits_default_exact_partial_and_ignores_non_rt_communities() {
    let ext = |keys: &[RtcNlri]| RtcInterest::from_keys(keys.iter());
    // No membership at all: nothing is wanted.
    assert!(!ext(&[]).permits(&[RT]));
    // The default route wants everything, even a route with no RT.
    assert!(ext(&[default_rt()]).permits(&[]));
    // 96 bits: RT equality, the origin AS is ignored.
    let exact_rt = ext(&[key(1, RT, 96)]);
    assert!(exact_rt.permits(&[RT]) && exact_rt.permits(&[0, RT]));
    assert!(!exact_rt.permits(&[RT2]));
    // 48 bits: the first 16 bits of the RT (type and subtype).
    let by_type = ext(&[key(1, 0x0002_0000_0000_0000, 48)]);
    assert!(by_type.permits(&[RT]) && by_type.permits(&[RT2]));
    assert!(!by_type.permits(&[0x0102_fde8_0000_0001]));
    // 64 bits: type, subtype and the AS (first 32 RT bits).
    let by_admin = ext(&[key(1, 0x0002_fde8_0000_0000, 64)]);
    assert!(by_admin.permits(&[RT]) && !by_admin.permits(&[0x0002_fde9_0000_0001]));
    // 32 bits: every RT.
    assert!(ext(&[key(1, 0, 32)]).permits(&[RT]));
    // A Site of Origin (subtype 3) or an encapsulation community is no RT.
    let soo = 0x0003_fde8_0000_0001;
    assert!(!ext(&[key(1, 0, 32)]).permits(&[soo]));
    assert!(!ext(&[key(1, soo, 96)]).permits(&[soo]));
}

#[test]
fn a_vpn_route_waits_for_membership_then_follows_it() {
    let (mut rib, mut rx) = setup();
    let u = reach(SRC, vec![65001], vec![nlri(RD1, P, 100)]);
    feed(&mut rib, SRC, false, &u);
    // RTC negotiated, no membership yet: held back; the plain peer gets it.
    assert_eq!(advs(&mut rx[1]), vec![]);
    assert_eq!(advs(&mut rx[2]).len(), 1);

    // A membership for another RT changes nothing.
    feed_rtc(&mut rib, vec![exact(RT2)]);
    assert_eq!(advs(&mut rx[1]), vec![]);
    // The matching one releases the route.
    feed_rtc(&mut rib, vec![exact(RT)]);
    let sent = advs(&mut rx[1]);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].key.1, prefix(P));
    // Withdrawing it withdraws the route again.
    rib.handle_update(
        addr(EBGP),
        false,
        v4("2.2.2.2"),
        &rtc_withdraw(vec![exact(RT)]),
        &nos_rpl::ACCEPT_ALL,
    );
    assert_eq!(withdrawn_vpn(&mut rx[1]), 1);
    // The RTC-less peer never saw any of it.
    assert_eq!(recv_all(&mut rx[2]), vec![]);
}

fn feed_rtc(rib: &mut BgpRib, keys: Vec<RtcNlri>) {
    let u = rtc_update(OBS_AS, EBGP, keys);
    rib.handle_update(addr(EBGP), false, v4("2.2.2.2"), &u, &nos_rpl::ACCEPT_ALL);
}

#[test]
fn the_default_route_wants_everything_and_its_withdrawal_removes_it() {
    let (mut rib, mut rx) = setup();
    feed_rtc(&mut rib, vec![default_rt()]);
    let u = reach(SRC, vec![65001], vec![nlri(RD1, P, 100)]);
    feed(&mut rib, SRC, false, &u);
    assert_eq!(advs(&mut rx[1]).len(), 1);
    rib.handle_update(
        addr(EBGP),
        false,
        v4("2.2.2.2"),
        &rtc_withdraw(vec![default_rt()]),
        &nos_rpl::ACCEPT_ALL,
    );
    assert_eq!(withdrawn_vpn(&mut rx[1]), 1);
}

#[test]
fn a_new_session_gets_membership_before_the_dump_and_an_end_of_rib() {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr(SRC), 65001);
    rib.set_peer_asn(addr(EBGP), OBS_AS);
    let _src = reg(&mut rib, SRC, false, false, plain_afs());
    let u = reach(SRC, vec![65001], vec![nlri(RD1, P, 100)]);
    feed(&mut rib, SRC, false, &u);
    rib.set_rtc_membership(std::collections::BTreeSet::from([RT2]));
    let mut rx = reg(&mut rib, EBGP, false, false, rtc_afs());
    let all = recv_all(&mut rx);
    // Our membership (one RT), then the RTC End-of-RIB; the VPN route is
    // held (no membership from this peer yet), so nothing follows.
    assert!(matches!(&all[0], OutboundUpdate::AnnounceRtc(a)
        if a.key == key(65000, RT2, 96) && a.route.next_hop == addr("10.0.0.254")));
    assert_eq!(
        all[1],
        OutboundUpdate::EndOfRib(AddressFamily::RtConstraint)
    );
    assert_eq!(all.len(), 2, "{all:?}");
}

#[test]
fn local_membership_is_originated_changed_and_withdrawn() {
    let (mut rib, mut rx) = setup();
    rib.set_rtc_membership(std::collections::BTreeSet::from([RT, RT2]));
    let sent = rtcs(&mut rx[1]);
    assert_eq!(sent.len(), 2);
    // eBGP toward the observer: our AS is prepended, next hop is ours.
    let OutboundUpdate::AnnounceRtc(a) = &sent[0] else {
        panic!("{sent:?}");
    };
    assert_eq!(a.route.as_path.to_string(), "65000");
    assert_eq!(a.route.next_hop, addr("10.0.0.254"));
    // A peer without the family hears nothing.
    assert_eq!(rtcs(&mut rx[2]), vec![]);
    rib.set_rtc_membership(std::collections::BTreeSet::from([RT]));
    let sent = rtcs(&mut rx[1]);
    assert!(
        matches!(&sent[..], [OutboundUpdate::WithdrawRtc(k)] if *k == key(65000, RT2, 96)),
        "{sent:?}"
    );
}

#[test]
fn a_confederation_originates_membership_from_its_identifier() {
    let (mut rib, mut rx) = setup();
    rib.set_confederation(Some(64999));
    rib.set_rtc_membership(std::collections::BTreeSet::from([RT]));
    let sent = rtcs(&mut rx[1]);
    assert!(
        matches!(&sent[..], [OutboundUpdate::AnnounceRtc(a)] if a.key.origin_as == 64999),
        "{sent:?}"
    );
}

#[test]
fn a_client_membership_is_reflected_to_non_clients_but_not_back() {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    let (client, other, nonclient) = ("10.0.0.5", "10.0.0.6", "10.0.0.7");
    let mut rx_client = reg(&mut rib, client, true, true, rtc_afs());
    let mut rx_other = reg(&mut rib, other, true, true, rtc_afs());
    let mut rx_non = reg(&mut rib, nonclient, true, false, rtc_afs());
    let _ = (
        recv_all(&mut rx_client),
        recv_all(&mut rx_other),
        recv_all(&mut rx_non),
    );
    let mut u = rtc_update(65000, "192.0.2.5", vec![exact(RT)]);
    u.attributes.as_mut().unwrap().as_path = crate::as_path::AsPath::default();
    rib.handle_update(addr(client), true, v4("5.5.5.5"), &u, &nos_rpl::ACCEPT_ALL);

    assert!(rtcs(&mut rx_client).is_empty(), "never back to the sender");
    for rx in [&mut rx_other, &mut rx_non] {
        let sent = rtcs(rx);
        assert_eq!(sent.len(), 1, "{sent:?}");
        let OutboundUpdate::AnnounceRtc(a) = &sent[0] else {
            panic!("{sent:?}");
        };
        // RFC 4456: the originator and our cluster id are added.
        assert_eq!(a.route.originator_id, Some(v4("5.5.5.5")));
        assert_eq!(a.route.cluster_list, vec![v4("1.1.1.1")]);
        assert_eq!(a.route.next_hop, addr("10.0.0.254"));
    }
}

#[test]
fn two_origins_for_one_key_use_the_best_and_a_disconnect_withdraws() {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    let (a, b) = ("10.0.0.1", "10.0.0.2");
    rib.set_peer_asn(addr(a), 65001);
    rib.set_peer_asn(addr(b), 65002);
    let mut rx_obs = reg(&mut rib, EBGP, false, false, rtc_afs());
    rib.set_peer_asn(addr(EBGP), OBS_AS);
    let _ra = reg(&mut rib, a, false, false, rtc_afs());
    let _rb = reg(&mut rib, b, false, false, rtc_afs());
    let _ = recv_all(&mut rx_obs);
    let k = key(64512, RT, 96);
    // `a` has the longer AS path, `b` the shorter: `b` is best.
    let ua = rtc_update(65001, a, vec![k]);
    let mut ua = ua;
    ua.attributes.as_mut().unwrap().as_path = as_path(&[65001, 65010]);
    rib.handle_update(addr(a), false, v4("2.2.2.2"), &ua, &nos_rpl::ACCEPT_ALL);
    let ub = rtc_update(65002, b, vec![k]);
    rib.handle_update(addr(b), false, v4("3.3.3.3"), &ub, &nos_rpl::ACCEPT_ALL);
    let sent = rtcs(&mut rx_obs);
    let OutboundUpdate::AnnounceRtc(last) = sent.last().unwrap() else {
        panic!("{sent:?}");
    };
    assert_eq!(last.route.as_path.to_string(), "65000 65002");
    // The best one goes away: the other takes over, then the key is gone.
    rib.peer_disconnected(addr(b), Disconnect::Transport);
    let sent = rtcs(&mut rx_obs);
    let OutboundUpdate::AnnounceRtc(last) = sent.last().unwrap() else {
        panic!("{sent:?}");
    };
    assert_eq!(last.route.as_path.to_string(), "65000 65001 65010");
    rib.peer_disconnected(addr(a), Disconnect::Transport);
    let sent = rtcs(&mut rx_obs);
    assert!(
        matches!(&sent[..], [OutboundUpdate::WithdrawRtc(w)] if *w == k),
        "{sent:?}"
    );
}

fn as_path(asns: &[u32]) -> crate::as_path::AsPath {
    let mut p = crate::as_path::AsPath::default();
    for asn in asns.iter().rev() {
        p.prepend_seq(*asn);
    }
    p
}

#[test]
fn membership_for_a_family_not_negotiated_is_ignored() {
    let (mut rib, mut rx) = setup();
    let u = rtc_update(65001, SRC, vec![default_rt()]);
    rib.handle_update(addr(SRC), false, v4("2.2.2.2"), &u, &nos_rpl::ACCEPT_ALL);
    assert!(!rib.rtc_adj_rib_in.contains_key(&addr(SRC)));
    let _ = recv_all(&mut rx[0]);
}

#[test]
fn an_unchanged_membership_resend_sends_nothing() {
    let (mut rib, mut rx) = setup();
    feed_rtc(&mut rib, vec![exact(RT)]);
    let u = reach(SRC, vec![65001], vec![nlri(RD1, P, 100)]);
    feed(&mut rib, SRC, false, &u);
    assert_eq!(advs(&mut rx[1]).len(), 1);
    // Re-announcing the same membership is no change and sends nothing.
    feed_rtc(&mut rib, vec![exact(RT)]);
    assert_eq!(advs(&mut rx[1]), vec![]);
}

#[test]
fn membership_unions_vrf_domain_and_ip_vrf_import_targets() {
    use nos_proto::{BroadcastDomain, Config, RoutingTable, RoutingTableEvpn, RoutingTableVpn};
    let cfg = Config {
        routing_tables: vec![
            RoutingTable {
                name: "red".into(),
                vpn: RoutingTableVpn {
                    rd: Some("65000:1".into()),
                    route_targets_import: vec!["65000:1".into(), "65000:2".into()],
                    bgp_instance: Some("core".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
            RoutingTable {
                name: "l3".into(),
                evpn: RoutingTableEvpn {
                    l3_vni: Some(5000),
                    bgp_instance: Some("core".into()),
                    route_targets_import: vec!["65000:5000".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            RoutingTable {
                name: "elsewhere".into(),
                vpn: RoutingTableVpn {
                    rd: Some("65000:9".into()),
                    route_targets_import: vec!["65000:9".into()],
                    bgp_instance: Some("other".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        ],
        broadcast_domains: vec![
            BroadcastDomain {
                name: "bd1".into(),
                vni: Some(10100),
                mac_redistribute: Some("core".into()),
                route_targets_import: vec!["65000:10100".into(), "65000:1".into()],
                ..Default::default()
            },
            BroadcastDomain {
                name: "no-vni".into(),
                mac_redistribute: Some("core".into()),
                route_targets_import: vec!["65000:7".into()],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let rt = |s: &str| nos_proto::evpn_id::parse_rt(s).unwrap();
    assert_eq!(
        crate::rib::rtc_membership(&cfg, "core"),
        [
            rt("65000:1"),
            rt("65000:2"),
            rt("65000:5000"),
            rt("65000:10100")
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(crate::rib::rtc_membership(&cfg, "none").len(), 0);
}

fn local_route(key: nos_proto::EvpnKey, rt: u64) -> nos_proto::EvpnRoute {
    nos_proto::EvpnRoute {
        key,
        vni: 10100,
        next_hop: addr("192.0.2.9"),
        ext_communities: vec![rt],
        esi: [0; 10],
        l3_vni: None,
    }
}

#[test]
fn evpn_local_routes_follow_membership_but_type_4_is_never_filtered() {
    let (mut rib, mut rx) = setup();
    let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
    let imet = local_route(
        nos_proto::EvpnKey::Imet {
            rd,
            origin: addr("192.0.2.9"),
        },
        RT,
    );
    let type4 = local_route(
        nos_proto::EvpnKey::EthernetSegment {
            rd,
            esi: [1; 10],
            origin: addr("192.0.2.9"),
        },
        0x0006_0000_0000_0000, // ES-Import: not an RT
    );
    let _ = recv_all(&mut rx[1]);
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(imet.clone()));
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(type4));
    let sent = recv_all(&mut rx[1]);
    assert!(
        matches!(&sent[..], [OutboundUpdate::AnnounceEvpn(a)] if a.nlri.route_type() == 4),
        "only the Type-4 goes without membership: {sent:?}"
    );
    // Membership for the Type-3's RT releases it.
    feed_rtc(&mut rib, vec![exact(RT)]);
    let sent = recv_all(&mut rx[1]);
    assert!(
        matches!(&sent[..], [OutboundUpdate::AnnounceEvpn(a)] if a.nlri.route_type() == 3),
        "{sent:?}"
    );
    // And withdrawing it takes the Type-3 back.
    rib.handle_update(
        addr(EBGP),
        false,
        v4("2.2.2.2"),
        &rtc_withdraw(vec![exact(RT)]),
        &nos_rpl::ACCEPT_ALL,
    );
    let sent = recv_all(&mut rx[1]);
    assert!(
        matches!(&sent[..], [OutboundUpdate::WithdrawEvpn(n)] if n.route_type() == 3),
        "{sent:?}"
    );
    // A peer that never negotiated RT-Constraint gets both, unfiltered.
    let mut plain = reg(&mut rib, "10.0.0.9", true, false, {
        let mut a = plain_afs();
        a.insert(AddressFamily::L2vpnEvpn);
        a
    });
    assert_eq!(
        recv_all(&mut plain)
            .iter()
            .filter(|u| matches!(u, OutboundUpdate::AnnounceEvpn(_)))
            .count(),
        2
    );
}

#[test]
fn the_max_prefix_count_includes_membership() {
    let (mut rib, _rx) = setup();
    feed_rtc(&mut rib, vec![exact(RT), exact(RT2)]);
    assert_eq!(rib.accepted_rtc(addr(EBGP)), 2);
}

#[test]
fn membership_is_not_propagated_while_deferring() {
    let (mut rib, mut rx) = setup();
    rib.begin_deferral(1, 120, 300, [addr(IBGP)]);
    rib.set_rtc_membership(std::collections::BTreeSet::from([RT]));
    assert_eq!(rtcs(&mut rx[1]), vec![]);
}

#[test]
fn a_route_refresh_resends_the_membership_last_sent() {
    let (mut rib, mut rx) = setup();
    rib.set_rtc_membership(std::collections::BTreeSet::from([RT]));
    let _ = recv_all(&mut rx[1]);
    rib.resend_all(addr(EBGP), AddressFamily::RtConstraint, true);
    let sent = recv_all(&mut rx[1]);
    assert_eq!(sent.len(), 3, "BoRR, the membership, EoRR: {sent:?}");
    assert!(matches!(&sent[1], OutboundUpdate::AnnounceRtc(a) if a.key == key(65000, RT, 96)));
}

#[test]
fn a_lost_membership_update_is_re_sent_from_the_backlog_state() {
    let (mut rib, mut rx) = setup();
    rib.set_rtc_membership(std::collections::BTreeSet::from([RT]));
    let _ = recv_all(&mut rx[1]);
    // Forced, as `drain_backlog` does: an unchanged state is sent again.
    rib.sync_rtc_to(addr(EBGP), &key(65000, RT, 96), true);
    assert_eq!(rtcs(&mut rx[1]).len(), 1);
    // A forced sync of a key we never held withdraws it (legal if unknown).
    rib.sync_rtc_to(addr(EBGP), &key(65000, RT2, 96), true);
    assert!(matches!(
        &rtcs(&mut rx[1])[..],
        [OutboundUpdate::WithdrawRtc(_)]
    ));
}

#[test]
fn covers_rejects_an_illegal_length_and_the_default_logs_as_such() {
    assert!(!key(1, RT, 31).covers(RT));
    assert!(!key(1, RT, 97).covers(RT));
    assert_eq!(crate::rib::rtc::rt_text_for_tests(&default_rt()), "default");
}

// --- graceful restart (RFC 4724, Q10 b) ---

const OBS: &str = "10.0.0.8";

fn gr_cap(families: &[AddressFamily]) -> PeerGr {
    let f: Vec<_> = families.iter().map(|f| (*f, true)).collect();
    gr(true, &f)
}

fn rtc_gr_cap() -> PeerGr {
    gr_cap(&[AddressFamily::Vpnv4Unicast, AddressFamily::RtConstraint])
}

type Rx = mpsc::Receiver<OutboundUpdate>;

/// `EBGP` (RTC + GR cap `cap`) holds membership `RT`; `SRC` sends a VPN
/// route for that RT; `OBS` is an RTC observer. Receivers: ebgp, obs.
fn gr_world(cap: Option<PeerGr>) -> (BgpRib, Rx, Rx) {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr(SRC), 65001);
    rib.set_peer_asn(addr(EBGP), OBS_AS);
    rib.set_peer_gr(addr(EBGP), cap);
    let _src = reg(&mut rib, SRC, false, false, plain_afs());
    let mut ebgp = reg(&mut rib, EBGP, false, false, rtc_afs());
    let mut obs = reg(&mut rib, OBS, true, false, rtc_afs());
    feed_rtc(&mut rib, vec![exact(RT)]);
    feed(
        &mut rib,
        SRC,
        false,
        &reach(SRC, vec![65001], vec![nlri(RD1, P, 100)]),
    );
    let _ = (recv_all(&mut ebgp), recv_all(&mut obs));
    (rib, ebgp, obs)
}

fn rtc_withdraws(v: &[OutboundUpdate]) -> usize {
    v.iter()
        .filter(|u| matches!(u, OutboundUpdate::WithdrawRtc(_)))
        .count()
}

#[test]
fn membership_is_retained_stale_only_with_rtc_in_the_gr_families() {
    // Listed: kept, counted stale, still propagated to others.
    let (mut rib, _e, mut obs) = gr_world(Some(rtc_gr_cap()));
    rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
    assert_eq!(rib.accepted_rtc(addr(EBGP)), 1);
    assert_eq!(rib.stale_count(addr(EBGP)), 1);
    assert!(rib.has_stale(addr(EBGP), Some(AddressFamily::RtConstraint)));
    assert_eq!(rtc_withdraws(&recv_all(&mut obs)), 0);

    // Not listed: dropped and withdrawn at once.
    let (mut rib, _e, mut obs) = gr_world(Some(gr_cap(&[AddressFamily::Vpnv4Unicast])));
    rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
    assert_eq!(rib.accepted_rtc(addr(EBGP)), 0);
    assert_eq!(rib.stale_count(addr(EBGP)), 0);
    assert_eq!(rtc_withdraws(&recv_all(&mut obs)), 1);

    // No capability: same.
    let (mut rib, _e, mut obs) = gr_world(None);
    rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
    assert_eq!(rib.accepted_rtc(addr(EBGP)), 0);
    assert_eq!(rtc_withdraws(&recv_all(&mut obs)), 1);
}

#[test]
fn stale_membership_is_live_interest_until_it_is_purged() {
    let (mut rib, _e, mut obs) = gr_world(Some(rtc_gr_cap()));
    rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
    let _ = recv_all(&mut obs);
    // The peer returns: its dump is filtered by the retained membership.
    let mut ebgp = reg(&mut rib, EBGP, false, false, rtc_afs());
    assert_eq!(advs(&mut ebgp).len(), 1, "stale membership still permits");
    assert_eq!(rib.stale_count(addr(EBGP)), 1);

    // End-of-RIB without re-announcing: purged, VPN route withdrawn, the
    // observer told.
    rib.end_of_rib(addr(EBGP), AddressFamily::RtConstraint);
    assert_eq!(rib.stale_count(addr(EBGP)), 0);
    assert_eq!(rib.accepted_rtc(addr(EBGP)), 0);
    assert_eq!(withdrawn_vpn(&mut ebgp), 1);
    assert_eq!(rtc_withdraws(&recv_all(&mut obs)), 1);
    assert!(!rib.gr_deadline.contains_key(&addr(EBGP)));
}

#[test]
fn a_reannounced_or_withdrawn_membership_stops_being_stale() {
    let (mut rib, _e, _obs) = gr_world(Some(rtc_gr_cap()));
    feed_rtc(&mut rib, vec![exact(RT2)]);
    rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
    assert_eq!(rib.stale_count(addr(EBGP)), 2);
    let _e = reg(&mut rib, EBGP, false, false, rtc_afs());
    feed_rtc(&mut rib, vec![exact(RT)]);
    assert_eq!(rib.stale_count(addr(EBGP)), 1);
    rib.handle_update(
        addr(EBGP),
        false,
        v4("2.2.2.2"),
        &rtc_withdraw(vec![exact(RT2)]),
        &nos_rpl::ACCEPT_ALL,
    );
    assert_eq!(rib.stale_count(addr(EBGP)), 0);
    assert_eq!(rib.accepted_rtc(addr(EBGP)), 1);
    rib.end_of_rib(addr(EBGP), AddressFamily::RtConstraint);
    assert_eq!(rib.accepted_rtc(addr(EBGP)), 1, "the fresh one stays");
}

#[test]
fn stale_membership_is_purged_by_the_timers_and_by_bfd() {
    // Restart timer while the peer is down.
    let (mut rib, _e, mut obs) = gr_world(Some(rtc_gr_cap()));
    rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
    let _ = recv_all(&mut obs);
    rib.gr_tick_at(Instant::now() + Duration::from_secs(121));
    assert_eq!(rtc_withdraws(&recv_all(&mut obs)), 1);
    assert_eq!(rib.accepted_rtc(addr(EBGP)), 0);

    // Stale timer once it is back.
    let (mut rib, _e, mut obs) = gr_world(Some(rtc_gr_cap()));
    rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
    rib.set_gr_stale_time(10);
    let _e = reg(&mut rib, EBGP, false, false, rtc_afs());
    let _ = recv_all(&mut obs);
    rib.gr_tick_at(Instant::now() + Duration::from_secs(11));
    assert_eq!(rtc_withdraws(&recv_all(&mut obs)), 1);

    // BFD abort.
    let (mut rib, _e, mut obs) = gr_world(Some(rtc_gr_cap()));
    assert!(!rib.gr_abort(addr(EBGP)));
    rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
    let _ = recv_all(&mut obs);
    assert!(rib.gr_abort(addr(EBGP)));
    assert_eq!(rtc_withdraws(&recv_all(&mut obs)), 1);
    assert_eq!(rib.stale_count(addr(EBGP)), 0);
}

#[test]
fn stale_membership_is_flushed_when_the_peer_returns_without_forwarding_state() {
    for back in [
        None,
        Some(gr(true, &[(AddressFamily::RtConstraint, false)])),
        Some(gr_cap(&[AddressFamily::Vpnv4Unicast])),
    ] {
        let (mut rib, _e, mut obs) = gr_world(Some(rtc_gr_cap()));
        rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
        let _ = recv_all(&mut obs);
        rib.set_peer_gr(addr(EBGP), back);
        let _e = reg(&mut rib, EBGP, false, false, rtc_afs());
        assert_eq!(rtc_withdraws(&recv_all(&mut obs)), 1, "{back:?}");
        assert_eq!(rib.accepted_rtc(addr(EBGP)), 0);
    }
}

#[test]
fn a_consecutive_restart_without_the_n_bit_drops_the_previous_stale_set() {
    let mut cap = rtc_gr_cap();
    cap.notification = false;
    let (mut rib, _e, mut obs) = gr_world(Some(cap));
    rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
    let _ = recv_all(&mut obs);
    let _e = reg(&mut rib, EBGP, false, false, rtc_afs());
    rib.peer_disconnected(addr(EBGP), Disconnect::Transport);
    assert_eq!(rib.accepted_rtc(addr(EBGP)), 0);
    assert_eq!(rtc_withdraws(&recv_all(&mut obs)), 1);
}

#[test]
fn route_refresh_markers_stale_and_purge_membership() {
    let (mut rib, _e, mut obs) = gr_world(Some(rtc_gr_cap()));
    feed_rtc(&mut rib, vec![exact(RT2)]);
    rib.begin_refresh_in(addr(EBGP), AddressFamily::RtConstraint);
    assert_eq!(rib.stale_count(addr(EBGP)), 2);
    let _ = recv_all(&mut obs);
    feed_rtc(&mut rib, vec![exact(RT)]);
    assert_eq!(
        rib.end_refresh_in(addr(EBGP), AddressFamily::RtConstraint),
        1
    );
    assert_eq!(rib.accepted_rtc(addr(EBGP)), 1);
    assert_eq!(rtc_withdraws(&recv_all(&mut obs)), 1);
    // Nothing held from an unknown peer.
    rib.begin_refresh_in(addr("10.9.9.9"), AddressFamily::RtConstraint);
}

#[test]
fn our_restart_defers_until_the_rtc_end_of_rib() {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.apply_redistribute_update(RedistributeUpdate::Full(Vec::new()));
    rib.begin_deferral(1, 120, 300, [addr(EBGP)]);
    rib.set_peer_gr(addr(EBGP), Some(rtc_gr_cap()));
    let _rx = reg(&mut rib, EBGP, false, false, rtc_afs());
    assert!(rib.deferring());
    for family in [
        AddressFamily::Vpnv4Unicast,
        AddressFamily::Ipv4Unicast,
        AddressFamily::L2vpnEvpn,
    ] {
        rib.end_of_rib(addr(EBGP), family);
        assert!(rib.deferring(), "{family} alone is not enough");
    }
    rib.end_of_rib(addr(EBGP), AddressFamily::RtConstraint);
    assert!(!rib.deferring());
}

/// #1134: RT-Constraint gates each Add-Path copy on its own RTs, so narrowing
/// membership withdraws only the copy it no longer covers.
#[test]
fn rtc_gates_each_add_path_copy_on_its_own_rts() {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr(SRC), 65001);
    rib.set_peer_asn(addr(EBGP), OBS_AS);
    let _src = reg(&mut rib, SRC, false, false, plain_afs());
    let (tx, mut rx) = test_channel();
    rib.peer_established(
        addr(EBGP),
        false,
        Some(addr("10.0.0.254")),
        rtc_afs(),
        true,
        None,
        false,
        false,
        HashSet::from([AddressFamily::Vpnv4Unicast]),
        accept_all_policy(),
        tx,
    );
    feed_rtc(&mut rib, vec![exact(RT), exact(RT2)]);
    for (id, rt) in [(1, RT), (2, RT2)] {
        let mut n = nlri(RD1, P, 100 + id);
        n.path_id = Some(id);
        let mut u = reach(SRC, vec![65001], vec![n]);
        u.attributes.as_mut().unwrap().extended_communities = vec![rt];
        feed(&mut rib, SRC, false, &u);
    }
    let ids: Vec<_> = advs(&mut rx).iter().map(|a| a.route.path_id).collect();
    assert!(ids.contains(&Some(1)) && ids.contains(&Some(2)), "{ids:?}");
    // Membership narrows to RT2: only copy 1 is withdrawn.
    rib.handle_update(
        addr(EBGP),
        false,
        v4("2.2.2.2"),
        &rtc_withdraw(vec![exact(RT)]),
        &nos_rpl::ACCEPT_ALL,
    );
    let got: Vec<_> = recv_all(&mut rx)
        .into_iter()
        .filter_map(|u| match u {
            OutboundUpdate::WithdrawVpn(_, id) => Some(id),
            _ => None,
        })
        .collect();
    assert_eq!(got, [Some(1)]);
}
