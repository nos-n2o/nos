//! RFC 8955 section 6 validation inside the RIB: the incremental
//! revalidation on unicast changes.

use super::*;
use crate::flowspec::{Afi, FlowSpec};
use crate::rib::{FlowValidity, InvalidReason};

const P1: &str = "10.0.0.1";
const P2: &str = "10.0.0.2";

/// RFC 8955 as written, for the tests that prove it.
const STRICT: nos_proto::BgpFlowspecValidation = nos_proto::BgpFlowspecValidation {
    disable_dest_prefix_rule: false,
    rfc8955_strict: true,
};

fn dest(bytes: &[u8]) -> FlowSpec {
    FlowSpec::decode(Afi::V4, bytes).unwrap().0
}

/// 10.1.2.0/24
fn flow_in_10_1() -> FlowSpec {
    dest(&[5, 1, 24, 10, 1, 2])
}

/// 192.168.7.0/24
fn flow_elsewhere() -> FlowSpec {
    dest(&[5, 1, 24, 192, 168, 7])
}

fn setup() -> BgpRib {
    let mut rib = new_rib(65000);
    for (p, asn) in [(P1, 65001), (P2, 65002)] {
        rib.set_peer_asn(addr(p), asn);
        std::mem::forget(register_mp_peer(
            &mut rib,
            addr(p),
            false,
            addr("10.0.0.254"),
            HashSet::from([AddressFamily::Ipv4Unicast, AddressFamily::Ipv4Flowspec]),
        ));
    }
    rib
}

fn feed(rib: &mut BgpRib, peer: &str, u: &UpdateMessage) {
    rib.handle_update(addr(peer), false, v4(peer), u, &nos_rpl::ACCEPT_ALL);
}

fn announce(rib: &mut BgpRib, peer: &str, asn: u32, net: &str) {
    feed(rib, peer, &ebgp_update(vec![net], vec![asn], peer));
}

fn withdraw(rib: &mut BgpRib, peer: &str, net: &str) {
    let mut u = empty_update();
    u.withdrawn_routes = vec![net.parse().unwrap()];
    feed(rib, peer, &u);
}

fn flow_update(peer_asn: u32, originator: Option<&str>, rules: Vec<FlowSpec>) -> UpdateMessage {
    let mut u = ebgp_update(vec![], vec![peer_asn], "0.0.0.0");
    let a = u.attributes.as_mut().unwrap();
    a.extended_communities = vec![0x8006_0000_0000_0000];
    a.originator_id = originator.map(v4);
    u.mp_reach = vec![message::MpReachNlri {
        afi: 1,
        safi: message::SAFI_FLOWSPEC,
        next_hop: addr("0.0.0.0"),
        nlri: vec![],
        nlri_path_ids: vec![],
        evpn: vec![],
        flowspec: rules,
        flowspec_vpn: vec![],
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    u
}

fn validity(rib: &BgpRib, rule: &FlowSpec) -> Option<FlowValidity> {
    rib.flowspec_routes()
        .into_iter()
        .find(|(_, r)| &r.nlri == rule)
        .and_then(|(_, r)| r.validity)
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "compared against Option<FlowValidity>"
)]
fn invalid(r: InvalidReason) -> Option<FlowValidity> {
    Some(FlowValidity::Invalid(r))
}

const VALID: Option<FlowValidity> = Some(FlowValidity::Valid);

#[test]
fn flow_follows_the_unicast_route_announce_and_withdraw() {
    let mut rib = setup();
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![flow_in_10_1()]),
    );
    assert_eq!(
        validity(&rib, &flow_in_10_1()),
        invalid(InvalidReason::NoUnicastRoute)
    );
    assert!(!rib.flowspec_routes()[0].1.is_usable());
    // The covering route arrives after the flow: revalidated.
    announce(&mut rib, P1, 65001, "10.1.0.0/16");
    assert_eq!(validity(&rib, &flow_in_10_1()), VALID);
    assert!(rib.flowspec_routes()[0].1.is_usable());
    withdraw(&mut rib, P1, "10.1.0.0/16");
    assert_eq!(
        validity(&rib, &flow_in_10_1()),
        invalid(InvalidReason::NoUnicastRoute)
    );
}

#[test]
fn originator_id_and_peer_down_are_honoured() {
    let mut rib = setup();
    rib.set_peer_flowspec_validation(addr(P1), STRICT);
    announce(&mut rib, P2, 65002, "10.1.0.0/16");
    // The flow comes from P1 with no ORIGINATOR_ID: P2 owns the unicast route.
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![flow_in_10_1()]),
    );
    assert_eq!(
        validity(&rib, &flow_in_10_1()),
        invalid(InvalidReason::OriginatorMismatch)
    );
    // The same flow re-sent with ORIGINATOR_ID = P2 is valid (re-announcement
    // revalidates).
    feed(
        &mut rib,
        P1,
        &flow_update(65001, Some(P2), vec![flow_in_10_1()]),
    );
    assert_eq!(validity(&rib, &flow_in_10_1()), VALID);
    // P2 going down removes the unicast route.
    rib.peer_disconnected(addr(P2), Disconnect::Transport);
    assert_eq!(
        validity(&rib, &flow_in_10_1()),
        invalid(InvalidReason::NoUnicastRoute)
    );
}

#[test]
fn a_more_specific_route_from_another_as_invalidates_even_when_not_best() {
    let mut rib = setup();
    announce(&mut rib, P1, 65001, "10.1.0.0/16");
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![flow_in_10_1()]),
    );
    assert_eq!(validity(&rib, &flow_in_10_1()), VALID);
    // Same AS more-specific: fine.
    announce(&mut rib, P1, 65001, "10.1.2.0/25");
    assert_eq!(validity(&rib, &flow_in_10_1()), VALID);
    // Another AS: invalid, and the same prefix from P1 stays best-eligible.
    announce(&mut rib, P2, 65002, "10.1.2.128/25");
    assert_eq!(
        validity(&rib, &flow_in_10_1()),
        invalid(InvalidReason::MoreSpecificFromOtherAs)
    );
    withdraw(&mut rib, P2, "10.1.2.128/25");
    assert_eq!(validity(&rib, &flow_in_10_1()), VALID);
}

#[test]
fn a_non_best_path_from_another_as_counts_for_rule_c() {
    let mut rib = setup();
    announce(&mut rib, P1, 65001, "10.1.0.0/16");
    // P1's /25 is best (shorter AS path); P2's longer path for the same /25
    // loses but is still a received route from another AS.
    announce(&mut rib, P1, 65001, "10.1.2.0/25");
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![flow_in_10_1()]),
    );
    assert_eq!(validity(&rib, &flow_in_10_1()), VALID);
    feed(
        &mut rib,
        P2,
        &ebgp_update(vec!["10.1.2.0/25"], vec![65002, 65003, 65004], P2),
    );
    assert_eq!(
        validity(&rib, &flow_in_10_1()),
        invalid(InvalidReason::MoreSpecificFromOtherAs)
    );
}

#[test]
fn a_unicast_change_only_revisits_overlapping_flows() {
    let mut rib = setup();
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![flow_in_10_1(), flow_elsewhere()]),
    );
    let visits = |rib: &BgpRib| rib.flow_ix.visits;
    let base = visits(&rib);
    // Overlaps only 10.1.2.0/24 (an ancestor of the flow's destination).
    announce(&mut rib, P1, 65001, "10.1.0.0/16");
    assert_eq!(visits(&rib) - base, 1);
    // A descendant of the destination is revisited too.
    let base = visits(&rib);
    announce(&mut rib, P1, 65001, "10.1.2.128/25");
    assert_eq!(visits(&rib) - base, 1);
    // Unrelated space revisits nothing.
    let base = visits(&rib);
    announce(&mut rib, P1, 65001, "172.16.0.0/12");
    announce(&mut rib, P1, 65001, "10.2.0.0/16");
    assert_eq!(visits(&rib) - base, 0);
    assert_eq!(
        validity(&rib, &flow_elsewhere()),
        invalid(InvalidReason::NoUnicastRoute)
    );
    // A withdrawn flow's index entry is dropped when next met, not revisited.
    feed(&mut rib, P1, &{
        let mut u = empty_update();
        u.attributes = None;
        u.mp_unreach = vec![message::MpUnreachNlri {
            afi: 1,
            safi: message::SAFI_FLOWSPEC,
            withdrawn: vec![],
            withdrawn_path_ids: vec![],
            evpn: vec![],
            flowspec: vec![flow_elsewhere()],
            flowspec_vpn: vec![],
            vpn: Vec::new(),
            rtc: Vec::new(),
        }];
        u
    });
    let base = visits(&rib);
    announce(&mut rib, P1, 65001, "192.168.0.0/16");
    assert_eq!(visits(&rib) - base, 0);
}

#[test]
fn indexes_are_built_from_routes_learned_before_the_first_flow() {
    let mut rib = setup();
    announce(&mut rib, P1, 65001, "10.1.0.0/16");
    announce(&mut rib, P2, 65002, "10.1.2.0/25");
    // No flow yet: nothing was indexed. The first flow builds the index and
    // sees the older more-specific route.
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![flow_in_10_1()]),
    );
    assert_eq!(
        validity(&rib, &flow_in_10_1()),
        invalid(InvalidReason::MoreSpecificFromOtherAs)
    );
}

#[test]
fn the_first_as_check_applies_to_ebgp_only() {
    let mut rib = setup();
    rib.set_peer_flowspec_validation(addr(P1), STRICT);
    announce(&mut rib, P1, 65001, "10.1.0.0/16");
    // eBGP peer P1 (AS 65001) sending a path starting with another AS.
    feed(
        &mut rib,
        P1,
        &flow_update(65099, None, vec![flow_in_10_1()]),
    );
    assert_eq!(
        validity(&rib, &flow_in_10_1()),
        invalid(InvalidReason::BadNeighbourAs)
    );

    // An iBGP peer is accepted whatever the path says.
    let mut rib = new_rib(65000);
    rib.set_peer_asn(addr(P1), 65000);
    std::mem::forget(register_mp_peer(
        &mut rib,
        addr(P1),
        true,
        addr("10.0.0.254"),
        HashSet::from([AddressFamily::Ipv4Unicast, AddressFamily::Ipv4Flowspec]),
    ));
    rib.handle_update(
        addr(P1),
        true,
        v4(P1),
        &ebgp_update(vec!["10.1.0.0/16"], vec![], P1),
        &nos_rpl::ACCEPT_ALL,
    );
    rib.handle_update(
        addr(P1),
        true,
        v4(P1),
        &flow_update(65099, None, vec![flow_in_10_1()]),
        &nos_rpl::ACCEPT_ALL,
    );
    assert_eq!(validity(&rib, &flow_in_10_1()), VALID);
}

#[test]
fn rule_a_and_its_knob() {
    let no_dest = dest(&[3, 3, 0x81, 6]);
    let mut rib = setup();
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![no_dest.clone()]),
    );
    assert_eq!(
        validity(&rib, &no_dest),
        invalid(InvalidReason::NoDestinationPrefix)
    );
    rib.set_peer_flowspec_validation(
        addr(P1),
        nos_proto::BgpFlowspecValidation {
            disable_dest_prefix_rule: true,
            ..Default::default()
        },
    );
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![no_dest.clone()]),
    );
    assert_eq!(validity(&rib, &no_dest), VALID);
    rib.set_peer_flowspec_validation(addr(P1), nos_proto::BgpFlowspecValidation::default());
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![no_dest.clone()]),
    );
    assert_eq!(
        validity(&rib, &no_dest),
        invalid(InvalidReason::NoDestinationPrefix)
    );
}

#[test]
fn index_compaction_drops_withdrawn_rules() {
    let mut rib = setup();
    // 80 distinct rules, withdrawn, then one more: the index shrinks.
    let rules: Vec<FlowSpec> = (0..80u8).map(|i| dest(&[5, 1, 24, 10, 9, i])).collect();
    feed(&mut rib, P1, &flow_update(65001, None, rules.clone()));
    assert_eq!(rib.flow_ix.entries(), 80);
    let mut u = empty_update();
    u.attributes = None;
    u.mp_unreach = vec![message::MpUnreachNlri {
        afi: 1,
        safi: message::SAFI_FLOWSPEC,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![],
        flowspec: rules,
        flowspec_vpn: vec![],
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    feed(&mut rib, P1, &u);
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![flow_in_10_1()]),
    );
    assert_eq!(rib.flow_ix.entries(), 1);
}

#[test]
fn rfc9117_is_the_default_and_strict_restores_rfc8955() {
    let mut rib = setup();
    announce(&mut rib, P1, 65001, "10.1.0.0/16");
    // Same leftmost AS as the covering route: valid.
    feed(
        &mut rib,
        P1,
        &flow_update(65001, None, vec![flow_in_10_1()]),
    );
    assert_eq!(validity(&rib, &flow_in_10_1()), VALID);
    // eBGP flow whose leftmost AS is not the best-match route's.
    feed(
        &mut rib,
        P1,
        &flow_update(65099, None, vec![flow_in_10_1()]),
    );
    assert_eq!(
        validity(&rib, &flow_in_10_1()),
        invalid(InvalidReason::LeftmostAsMismatch)
    );
    rib.set_peer_flowspec_validation(addr(P1), STRICT);
    feed(
        &mut rib,
        P1,
        &flow_update(65099, None, vec![flow_in_10_1()]),
    );
    assert_eq!(
        validity(&rib, &flow_in_10_1()),
        invalid(InvalidReason::BadNeighbourAs)
    );
}
