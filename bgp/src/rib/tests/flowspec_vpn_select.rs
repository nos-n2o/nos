//! VPN Flowspec (SAFI 134) selection, import/export policy and propagation
//! (#1085).

use super::flowspec_vpn::{feed, flow, flow_reach, unicast, vrf, RT2, SOO};
use super::rtc::{exact, rtc_update, OBS_AS};
use super::vpn::{RD1, RT};
use super::*;
use crate::vpn::VrfSet;

const SRC: &str = "10.0.0.1"; // eBGP source, AS 65001
const EBGP: &str = "10.0.0.3"; // eBGP observer, AS 65003, RT-Constraint
const IBGP: &str = "10.0.0.4"; // iBGP observer, not a client
const CLIENT: &str = "10.0.0.5"; // iBGP observer, route-reflector client
const I1: &str = "10.0.0.7"; // iBGP source, not a client

fn afs(rtc: bool) -> HashSet<AddressFamily> {
    let mut s = HashSet::from([
        AddressFamily::Ipv4Unicast,
        AddressFamily::Vpnv4Unicast,
        AddressFamily::Vpnv4Flowspec,
    ]);
    if rtc {
        s.insert(AddressFamily::RtConstraint);
    }
    s
}

fn reg(
    rib: &mut BgpRib,
    peer: &str,
    ibgp: bool,
    rr_client: bool,
    rtc: bool,
) -> mpsc::Receiver<OutboundUpdate> {
    let (tx, rx) = test_channel();
    rib.peer_established(
        addr(peer),
        ibgp,
        Some(addr("10.0.0.254")),
        afs(rtc),
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

/// AS 65000 (router-id/cluster-id 1.1.1.1), VRF `red` importing `RT`.
/// Receivers: source, eBGP observer (no RT-Constraint), iBGP, client.
fn setup() -> (BgpRib, [mpsc::Receiver<OutboundUpdate>; 4]) {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr(SRC), 65001);
    rib.set_peer_asn(addr(EBGP), OBS_AS);
    rib.set_vpn_vrfs(VrfSet(vec![vrf("red", vec![RT], Some(SOO))]));
    let rx = [
        reg(&mut rib, SRC, false, false, false),
        reg(&mut rib, EBGP, false, false, false),
        reg(&mut rib, IBGP, true, false, false),
        reg(&mut rib, CLIENT, true, true, false),
    ];
    (rib, rx)
}

fn policy(script: &str) -> Arc<CompiledPolicy> {
    Arc::new(nos_rpl::compile(script, &nos_rpl::Symbols::EMPTY).unwrap())
}

fn vflows(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Vec<OutboundUpdate> {
    recv_all(rx)
        .into_iter()
        .filter(|u| {
            matches!(
                u,
                OutboundUpdate::AnnounceVpnFlowspec(..) | OutboundUpdate::WithdrawVpnFlowspec(_)
            )
        })
        .collect()
}

fn announced(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Option<(Rd, AdvertisedFlowspec)> {
    vflows(rx).into_iter().find_map(|u| match u {
        OutboundUpdate::AnnounceVpnFlowspec(rd, a) => Some((rd, a)),
        _ => None,
    })
}

fn withdrawn(rx: &mut mpsc::Receiver<OutboundUpdate>) -> bool {
    vflows(rx)
        .iter()
        .any(|u| matches!(u, OutboundUpdate::WithdrawVpnFlowspec(k) if *k == key()))
}

fn key() -> VpnFlowKey {
    (AddressFamily::Vpnv4Flowspec, (RD1, flow()))
}

/// The covering VPN route, then the rule: valid in `red`.
fn valid_flow(rib: &mut BgpRib) {
    unicast(rib, SRC, 65001, "10.10.0.0/24");
    feed(rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
}

fn withdraw_unicast(rib: &mut BgpRib) {
    let u = super::vpn::unreach(vec![super::vpn::nlri(RD1, "10.10.0.0/24", 0)]);
    feed(rib, SRC, &u);
}

fn selected(rib: &BgpRib) -> Option<IpAddr> {
    rib.vpn_flow_loc.get(&key()).map(|(p, _)| *p)
}

#[test]
fn a_valid_rule_is_propagated_with_unicast_rules_and_follows_its_validity() {
    let (mut rib, [mut src, mut ebgp, mut ibgp, mut client]) = setup();
    // Held but invalid (no covering route): nothing selected or sent.
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert_eq!(selected(&rib), None);
    assert_eq!(vflows(&mut ebgp).len(), 0);
    // The covering VPN route arrives: re-validated, selected, advertised.
    unicast(&mut rib, SRC, 65001, "10.10.0.0/24");
    assert_eq!(selected(&rib), Some(addr(SRC)));
    let (rd_sent, external) = announced(&mut ebgp).expect("advertised to eBGP");
    assert_eq!((rd_sent, &external.nlri), (RD1, &flow()));
    assert_eq!(external.family, AddressFamily::Vpnv4Flowspec);
    assert_eq!(external.route.as_path, vec![65000u32, 65001]);
    // The traffic action and the Route Target are carried unchanged.
    assert!(external.route.extended_communities.contains(&RT));
    assert!(external
        .route
        .extended_communities
        .contains(&0x8006_0000_0000_0000));
    let (_, internal) = announced(&mut ibgp).expect("eBGP-learned goes to iBGP");
    assert_eq!(internal.route.as_path, vec![65001u32]);
    assert_eq!(internal.route.local_pref, Some(100));
    assert!(announced(&mut client).is_some());
    // Split horizon: never back to the peer it came from.
    assert_eq!(vflows(&mut src).len(), 0);
    // The covering route goes: the rule is invalid, withdrawn everywhere.
    withdraw_unicast(&mut rib);
    assert_eq!(selected(&rib), None);
    assert!(withdrawn(&mut ebgp) && withdrawn(&mut ibgp) && withdrawn(&mut client));
}

#[test]
fn an_import_route_target_change_withdraws_the_rule() {
    let (mut rib, [_src, mut ebgp, ..]) = setup();
    valid_flow(&mut rib);
    assert!(announced(&mut ebgp).is_some());
    // No VRF imports the rule any more: imported nowhere is no candidate.
    rib.set_vpn_vrfs(VrfSet(vec![vrf("red", vec![RT2], Some(SOO))]));
    assert_eq!(selected(&rib), None);
    assert!(withdrawn(&mut ebgp));
    // Back: validated again, advertised again.
    rib.set_vpn_vrfs(VrfSet(vec![vrf("red", vec![RT], Some(SOO))]));
    assert_eq!(selected(&rib), Some(addr(SRC)));
    assert!(announced(&mut ebgp).is_some());
}

#[test]
fn import_policy_sees_the_destination_and_a_reject_is_not_held() {
    let (mut rib, _rx) = setup();
    rib.set_peer_flowspec_policies(
        addr(SRC),
        Some(policy(
            "if this.prefix == 10.10.0.0/24:\n    reject\naccept\n",
        )),
        None,
    );
    valid_flow(&mut rib);
    assert_eq!(rib.accepted_vpn_flow(addr(SRC)), [0, 0]);
    assert_eq!(selected(&rib), None);
    // Loosening re-runs what is held: set a rewrite on a held rule.
    rib.set_peer_flowspec_policies(addr(SRC), None, None);
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert_eq!(selected(&rib), Some(addr(SRC)));
    rib.set_peer_flowspec_policies(addr(SRC), Some(policy("reject\n")), None);
    assert_eq!(rib.accepted_vpn_flow(addr(SRC)), [0, 0]);
    assert_eq!(selected(&rib), None);
}

#[test]
fn export_policy_is_per_peer() {
    let (mut rib, [_src, mut ebgp, mut ibgp, _client]) = setup();
    rib.set_peer_flowspec_policies(addr(EBGP), None, Some(policy("reject\n")));
    valid_flow(&mut rib);
    assert_eq!(vflows(&mut ebgp).len(), 0);
    assert!(announced(&mut ibgp).is_some());
}

#[test]
fn rt_constraint_holds_a_rule_until_the_peer_wants_its_target() {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    rib.set_peer_asn(addr(SRC), 65001);
    rib.set_peer_asn(addr(EBGP), OBS_AS);
    rib.set_vpn_vrfs(VrfSet(vec![vrf("red", vec![RT], Some(SOO))]));
    let _src = reg(&mut rib, SRC, false, false, false);
    let mut rx = reg(&mut rib, EBGP, false, false, true);
    valid_flow(&mut rib);
    // RTC negotiated, no membership yet: held back.
    assert_eq!(vflows(&mut rx).len(), 0);
    let membership = |rib: &mut BgpRib, keys| {
        let u = rtc_update(OBS_AS, EBGP, keys);
        rib.handle_update(addr(EBGP), false, v4("2.2.2.2"), &u, &nos_rpl::ACCEPT_ALL);
    };
    membership(&mut rib, vec![exact(RT2)]);
    assert_eq!(vflows(&mut rx).len(), 0);
    membership(&mut rib, vec![exact(RT)]);
    assert!(announced(&mut rx).is_some());
    // Its membership going withdraws the rule again.
    let u = super::rtc::rtc_withdraw(vec![exact(RT)]);
    rib.handle_update(addr(EBGP), false, v4("2.2.2.2"), &u, &nos_rpl::ACCEPT_ALL);
    assert!(withdrawn(&mut rx));
}

#[test]
fn route_reflection_follows_the_client_rules_and_stamps_the_cluster() {
    let (mut rib, [_src, _ebgp, mut ibgp, mut client]) = setup();
    let _i1 = reg(&mut rib, I1, true, false, false);
    // An iBGP non-client source: reflected to a client only.
    let mut u = super::vpn::reach(I1, vec![], vec![super::vpn::nlri(RD1, "10.10.0.0/24", 5)]);
    u.attributes.as_mut().unwrap().as_path = crate::as_path::AsPath::default();
    let feed_i1 = |rib: &mut BgpRib, u: &UpdateMessage| {
        rib.handle_update(addr(I1), true, v4("2.2.2.2"), u, &nos_rpl::ACCEPT_ALL);
    };
    feed_i1(&mut rib, &u);
    let mut f = flow_reach(65001, vec![RT], RD1, flow());
    f.attributes.as_mut().unwrap().as_path = crate::as_path::AsPath::default();
    feed_i1(&mut rib, &f);
    assert_eq!(selected(&rib), Some(addr(I1)));
    assert_eq!(vflows(&mut ibgp).len(), 0, "non-client to non-client");
    let (_, adv) = announced(&mut client).expect("reflected to the client");
    assert_eq!(adv.route.cluster_list, vec![v4("1.1.1.1")]);
    assert_eq!(adv.route.originator_id, Some(v4("2.2.2.2")));
}

#[test]
fn a_new_peer_gets_the_table_and_a_refresh_resends_it() {
    let (mut rib, _rx) = setup();
    valid_flow(&mut rib);
    let mut late = reg(&mut rib, "10.0.0.9", false, false, false);
    let got = recv_all(&mut late);
    assert!(got
        .iter()
        .any(|u| matches!(u, OutboundUpdate::AnnounceVpnFlowspec(rd, a) if *rd == RD1 && a.nlri == flow())));
    rib.resend_all(addr("10.0.0.9"), AddressFamily::Vpnv4Flowspec, true);
    let got = recv_all(&mut late);
    assert_eq!(got.len(), 3, "BoRR, the rule, EoRR: {got:?}");
    assert!(matches!(got[1], OutboundUpdate::AnnounceVpnFlowspec(..)));
    // The other families send no SAFI 134, and BMP counts what was sent.
    rib.resend_all(addr("10.0.0.9"), AddressFamily::Ipv4Unicast, false);
    assert_eq!(vflows(&mut late).len(), 0);
    // The covering VPN route and the rule.
    assert_eq!(rib.bmp_out_counts(addr("10.0.0.9")).post, 2);
}

#[test]
fn graceful_restart_keeps_the_rule_stale_until_end_of_rib() {
    let (mut rib, [_src, mut ebgp, ..]) = setup();
    rib.set_peer_gr(
        addr(SRC),
        Some(gr(
            true,
            &[
                (AddressFamily::Vpnv4Unicast, true),
                (AddressFamily::Vpnv4Flowspec, true),
            ],
        )),
    );
    valid_flow(&mut rib);
    assert!(announced(&mut ebgp).is_some());
    rib.peer_disconnected(addr(SRC), Disconnect::Transport);
    // Retained, stale, still selected and advertised: nothing withdrawn.
    assert_eq!(rib.stale_count(addr(SRC)), 2);
    assert!(rib.has_stale(addr(SRC), Some(AddressFamily::Vpnv4Flowspec)));
    assert_eq!(selected(&rib), Some(addr(SRC)));
    assert_eq!(vflows(&mut ebgp).len(), 0);
    // The peer returns and re-announces nothing: End-of-RIB purges the rule.
    let _src = reg(&mut rib, SRC, false, false, false);
    rib.end_of_rib(addr(SRC), AddressFamily::Vpnv4Flowspec);
    assert_eq!(rib.stale_count(addr(SRC)), 1);
    assert_eq!(selected(&rib), None);
    assert!(withdrawn(&mut ebgp));
}

#[test]
fn a_restarting_peer_that_re_announces_the_rule_clears_its_stale_mark() {
    let (mut rib, _rx) = setup();
    rib.set_peer_gr(
        addr(SRC),
        Some(gr(
            true,
            &[
                (AddressFamily::Vpnv4Unicast, true),
                (AddressFamily::Vpnv4Flowspec, true),
            ],
        )),
    );
    valid_flow(&mut rib);
    rib.peer_disconnected(addr(SRC), Disconnect::Transport);
    let _src = reg(&mut rib, SRC, false, false, false);
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert!(!rib.has_stale(addr(SRC), Some(AddressFamily::Vpnv4Flowspec)));
    // A family not listed is dropped with the session.
    rib.peer_disconnected(addr(SRC), Disconnect::Hard);
    assert_eq!(selected(&rib), None);
}

#[test]
fn a_hard_disconnect_withdraws_the_rule_downstream() {
    let (mut rib, [_src, mut ebgp, ..]) = setup();
    valid_flow(&mut rib);
    assert!(announced(&mut ebgp).is_some());
    rib.peer_disconnected(addr(SRC), Disconnect::Transport);
    assert!(withdrawn(&mut ebgp));
}

fn flow_policies(flowspec: &str) -> crate::rib::ImportPolicies {
    crate::rib::ImportPolicies {
        unicast: accept_all_policy(),
        evpn: None,
        flowspec: Some(policy(flowspec)),
    }
}

#[test]
fn reevaluation_readmits_a_rejected_rule_and_withdraws_a_tightened_one() {
    let (mut rib, [_src, mut ebgp, ..]) = setup();
    let src = addr(SRC);
    rib.set_peer_soft_reconfig(src, true);
    rib.set_peer_flowspec_policies(src, Some(policy("reject\n")), None);
    valid_flow(&mut rib);
    assert_eq!(selected(&rib), None);
    // Loosen with a rewrite: the rule is back, selected and advertised.
    let fams = rib.reevaluate_peer(
        src,
        flow_policies("this.bgp.communities.add(65000:7)\naccept\n"),
    );
    let f = fams
        .iter()
        .find(|f| f.family == nos_proto::ReevalFamily::Vpnv4Flowspec)
        .unwrap();
    assert_eq!((f.retained, f.accepted), (1, 1));
    assert_eq!(selected(&rib), Some(src));
    let (_, adv) = announced(&mut ebgp).unwrap();
    assert_eq!(adv.route.communities, vec![(65000 << 16) | 7]);
    // Tighten: removed and withdrawn; the raw copy stays for later.
    rib.reevaluate_peer(src, flow_policies("reject\n"));
    assert_eq!(selected(&rib), None);
    assert!(withdrawn(&mut ebgp));
    assert!(rib.retained_count(src) >= 1);
}

#[test]
fn flow_prefix_defaults_to_the_family_of_a_vpn_rule() {
    let proto_only6 = FlowSpec::decode(Afi::V6, &[3, 3, 0x81, 6]).unwrap().0;
    assert_eq!(
        crate::rib::flowspec_out::flow_prefix(AddressFamily::Vpnv6Flowspec, &proto_only6),
        prefix("::/0")
    );
}

use crate::flowspec::{Afi, FlowSpec};
use crate::vpn::Rd;
