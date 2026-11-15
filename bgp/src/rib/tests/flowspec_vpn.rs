//! VPN Flowspec (SAFI 134) receive side: Adj-RIB-In, RT import, per-VRF
//! validation against the imported SAFI 128 routes (#1084).

use super::vpn::{nlri, reach, RD1, RT};
use super::*;
use crate::flowspec::{Afi, FlowSpec, FlowSpecVpn};
use crate::rib::FlowFilter;
use crate::vpn::{Rd, Vrf, VrfSet};

const SRC: &str = "10.0.0.1"; // eBGP, AS 65001
const OTHER: &str = "10.0.0.2"; // eBGP, AS 65002
pub(super) const RT2: u64 = 0x0002_fde8_0000_0002; // RT:65000:2
pub(super) const SOO: u64 = 0x0003_fde8_0000_0077; // SoO:65000:119
pub(super) const RD2: Rd = [0, 0, 0xfd, 0xe9, 0, 0, 0, 2];

/// 10.10.0.0/24, the prefix `vpn::P` announces.
pub(super) fn flow() -> FlowSpec {
    FlowSpec::decode(Afi::V4, &[5, 1, 24, 10, 10, 0]).unwrap().0
}

pub(super) fn vrf(table: &str, import: Vec<u64>, soo: Option<u64>) -> Vrf {
    Vrf {
        table: table.to_string(),
        rd: [0; 8],
        import,
        export: vec![],
        soo,
    }
}

fn setup() -> BgpRib {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    for (p, asn) in [(SRC, 65001), (OTHER, 65002)] {
        rib.set_peer_asn(addr(p), asn);
        std::mem::forget(register_mp_peer(
            &mut rib,
            addr(p),
            false,
            addr("10.0.0.254"),
            HashSet::from([AddressFamily::Vpnv4Unicast, AddressFamily::Vpnv4Flowspec]),
        ));
    }
    rib.set_vpn_vrfs(VrfSet(vec![
        vrf("red", vec![RT], Some(SOO)),
        vrf("blue", vec![RT2], None),
    ]));
    rib
}

pub(super) fn feed(rib: &mut BgpRib, peer: &str, u: &UpdateMessage) {
    rib.handle_update(addr(peer), false, v4("2.2.2.2"), u, &nos_rpl::ACCEPT_ALL);
}

pub(super) fn unicast(rib: &mut BgpRib, peer: &str, asn: u32, p: &str) {
    feed(rib, peer, &reach(peer, vec![asn], vec![nlri(RD1, p, 100)]));
}

pub(super) fn flow_reach(peer_asn: u32, rts: Vec<u64>, rd: Rd, rule: FlowSpec) -> UpdateMessage {
    let mut u = ebgp_update(vec![], vec![peer_asn], "0.0.0.0");
    let mut ext = vec![0x8006_0000_0000_0000];
    ext.extend(rts);
    u.attributes.as_mut().unwrap().extended_communities = ext;
    u.mp_reach = vec![message::MpReachNlri {
        afi: 1,
        safi: message::SAFI_FLOWSPEC_VPN,
        next_hop: addr("0.0.0.0"),
        nlri: vec![],
        nlri_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![],
        flowspec_vpn: vec![FlowSpecVpn { rd, flow: rule }],
        vpn: vec![],
        rtc: vec![],
    }];
    u
}

fn flow_unreach(rd: Rd, rule: FlowSpec) -> UpdateMessage {
    let mut u = empty_update();
    u.mp_unreach = vec![message::MpUnreachNlri {
        afi: 1,
        safi: message::SAFI_FLOWSPEC_VPN,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![],
        flowspec_vpn: vec![FlowSpecVpn { rd, flow: rule }],
        vpn: vec![],
        rtc: vec![],
    }];
    u
}

/// The validity text of every rule `table` shows.
fn view(rib: &BgpRib, table: &str) -> Vec<String> {
    let f = FlowFilter {
        family: None,
        vrf: Some(table),
    };
    rib.flowspec_keys(&f)
        .iter()
        .map(|k| rib.flowspec_at(k).unwrap().validity.unwrap())
        .collect()
}

fn global(rib: &BgpRib, family: Option<AddressFamily>) -> usize {
    rib.flowspec_keys(&FlowFilter { family, vrf: None }).len()
}

#[test]
fn a_rule_is_in_the_views_of_the_vrfs_whose_import_matches() {
    let mut rib = setup();
    unicast(&mut rib, SRC, 65001, "10.10.0.0/24");
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert_eq!(view(&rib, "red"), ["valid"]);
    assert_eq!(view(&rib, "blue").len(), 0);
    assert_eq!(rib.accepted_vpn_flow(addr(SRC)), [1, 0]);
    // The global listing shows it only for its own family, and the SAFI 133
    // listing stays as it was.
    assert_eq!(global(&rib, Some(AddressFamily::Vpnv4Flowspec)), 1);
    assert_eq!(global(&rib, Some(AddressFamily::Ipv4Flowspec)), 0);
    assert_eq!(global(&rib, None), 0);
    let keys = rib.flowspec_keys(&FlowFilter {
        family: Some(AddressFamily::Vpnv4Flowspec),
        vrf: None,
    });
    let shown = rib.flowspec_at(&keys[0]).unwrap();
    assert_eq!(shown.rd, Some(RD1));
    assert_eq!(shown.validity.as_deref(), Some("red:valid"));
}

#[test]
fn a_rule_with_no_matching_route_target_is_held_but_in_no_view() {
    let mut rib = setup();
    feed(
        &mut rib,
        SRC,
        &flow_reach(65001, vec![0x0002_fde8_0000_0063], RD1, flow()),
    );
    assert!(view(&rib, "red").is_empty() && view(&rib, "blue").is_empty());
    assert_eq!(rib.accepted_vpn_flow(addr(SRC)), [1, 0]);
    let keys = rib.flowspec_keys(&FlowFilter {
        family: Some(AddressFamily::Vpnv4Flowspec),
        vrf: None,
    });
    assert_eq!(
        rib.flowspec_at(&keys[0]).unwrap().validity.as_deref(),
        Some("-")
    );
}

#[test]
fn the_vrfs_own_site_of_origin_blocks_the_import() {
    let mut rib = setup();
    unicast(&mut rib, SRC, 65001, "10.10.0.0/24");
    feed(
        &mut rib,
        SRC,
        &flow_reach(65001, vec![RT, SOO], RD1, flow()),
    );
    assert_eq!(view(&rib, "red").len(), 0);
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert_eq!(view(&rib, "red"), ["valid"]);
}

#[test]
fn validity_follows_the_vpn_unicast_route_in_the_vrf() {
    let mut rib = setup();
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert_eq!(view(&rib, "red"), ["invalid:no-covering-unicast-route"]);
    unicast(&mut rib, SRC, 65001, "10.0.0.0/8");
    assert_eq!(view(&rib, "red"), ["valid"], "a covering route is enough");
    // The same route under another RT is imported elsewhere: no help.
    let mut rib2 = setup();
    feed(&mut rib2, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    let mut u = reach(SRC, vec![65001], vec![nlri(RD1, "10.10.0.0/24", 1)]);
    u.attributes.as_mut().unwrap().extended_communities = vec![RT2];
    feed(&mut rib2, SRC, &u);
    assert_eq!(view(&rib2, "red"), ["invalid:no-covering-unicast-route"]);
    // Withdrawn again: invalid again.
    let mut w = empty_update();
    w.mp_unreach = vec![message::MpUnreachNlri {
        afi: 1,
        safi: message::SAFI_VPN,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![],
        flowspec_vpn: vec![],
        vpn: vec![nlri(RD1, "10.0.0.0/8", 0)],
        rtc: vec![],
    }];
    feed(&mut rib, SRC, &w);
    assert_eq!(view(&rib, "red"), ["invalid:no-covering-unicast-route"]);
}

#[test]
fn originator_and_more_specific_rules_apply_per_vrf() {
    let mut rib = setup();
    // The route comes from OTHER, the rule from SRC: originator mismatch.
    unicast(&mut rib, OTHER, 65002, "10.10.0.0/24");
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert!(
        view(&rib, "red")[0].starts_with("invalid:"),
        "{:?}",
        view(&rib, "red")
    );
    // Same peer: valid; a more-specific from another AS then invalidates.
    let mut rib = setup();
    unicast(&mut rib, SRC, 65001, "10.10.0.0/16");
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert_eq!(view(&rib, "red"), ["valid"]);
    unicast(&mut rib, OTHER, 65002, "10.10.0.128/25");
    assert_eq!(view(&rib, "red"), ["invalid:more-specific-from-other-as"]);
}

#[test]
fn a_unicast_change_only_revisits_overlapping_rules() {
    let mut rib = setup();
    let far = FlowSpec::decode(Afi::V4, &[5, 1, 24, 192, 168, 7])
        .unwrap()
        .0;
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD2, far));
    let before = rib.vpn_flow_visits;
    unicast(&mut rib, SRC, 65001, "10.0.0.0/8");
    assert_eq!(rib.vpn_flow_visits - before, 1);
}

#[test]
fn withdraw_and_session_loss_remove_the_rule() {
    let mut rib = setup();
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    feed(&mut rib, SRC, &flow_unreach(RD1, flow()));
    assert_eq!(rib.accepted_vpn_flow(addr(SRC)), [0, 0]);
    assert_eq!(view(&rib, "red").len(), 0);
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    rib.peer_disconnected(addr(SRC), crate::gr::Disconnect::Hard);
    assert_eq!(rib.accepted_vpn_flow(addr(SRC)), [0, 0]);
    assert_eq!(view(&rib, "red").len(), 0);
}

#[test]
fn a_family_the_session_did_not_negotiate_is_ignored() {
    let mut rib = new_rib(65000);
    rib.set_peer_asn(addr(SRC), 65001);
    std::mem::forget(register_mp_peer(
        &mut rib,
        addr(SRC),
        false,
        addr("10.0.0.254"),
        HashSet::from([AddressFamily::Vpnv4Unicast]),
    ));
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert_eq!(rib.accepted_vpn_flow(addr(SRC)), [0, 0]);
}

#[test]
fn the_vpn_flowspec_slot_of_maximum_prefix_counts_the_rules() {
    let mut rib = setup();
    let limit = nos_proto::BgpPrefixLimit {
        limit: 1,
        warning_only: false,
        restart_interval: 0,
    };
    rib.set_peer_max_prefix(
        addr(SRC),
        nos_proto::BgpMaximumPrefix {
            vpnv4_flowspec: Some(limit),
            ..Default::default()
        },
    );
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert!(rib.check_max_prefix(addr(SRC)).is_none());
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD2, flow()));
    assert_eq!(
        rib.check_max_prefix(addr(SRC)).map(|(f, _, n)| (f, n)),
        Some((AddressFamily::Vpnv4Flowspec, 2))
    );
}

/// #1083: `nos-acld` gets, per VRF, the rules valid there (once, whatever
/// the RD or peer), and every VRF is listed so a push can clear it.
#[test]
fn the_acld_snapshot_holds_the_valid_rules_of_each_vrf() {
    let mut rib = setup();
    let tables = |rib: &BgpRib| {
        rib.vpn_flowspec_push_snapshot()
            .unwrap()
            .into_iter()
            .map(|(t, r)| (t, r.len()))
            .collect::<Vec<_>>()
    };
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    // Invalid (no covering route): nothing to enforce.
    assert_eq!(tables(&rib), [("red".into(), 0), ("blue".into(), 0)]);
    unicast(&mut rib, SRC, 65001, "10.10.0.0/24");
    assert_eq!(tables(&rib), [("red".into(), 1), ("blue".into(), 0)]);
    // The same flow from another RD and peer is one rule.
    unicast(&mut rib, OTHER, 65002, "10.10.0.0/24");
    feed(&mut rib, OTHER, &flow_reach(65002, vec![RT], RD2, flow()));
    assert_eq!(tables(&rib), [("red".into(), 1), ("blue".into(), 0)]);
    let rules = rib.vpn_flowspec_push_snapshot().unwrap();
    assert_eq!(rules[0].1[0].flow, flow().to_string());
}

/// #1086 (owner D7): per VRF, the copy of a flow from the lowest RD is the
/// one enforced; two VRFs importing the same flow each enforce their own;
/// nothing is pushed while deferring.
#[test]
fn the_lowest_rd_copy_is_enforced_per_vrf() {
    let mut rib = setup();
    rib.set_vpn_vrfs(VrfSet(vec![
        vrf("red", vec![RT], None),
        vrf("blue", vec![RT, RT2], None),
    ]));
    unicast(&mut rib, SRC, 65001, "10.10.0.0/24");
    // The higher RD arrives first.
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD2, flow()));
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    let k = |rd| (AddressFamily::Vpnv4Flowspec, (rd, flow()));
    for table in ["red", "blue"] {
        assert!(rib.vpn_flow_enforced(table, addr(SRC), &k(RD1)), "{table}");
        assert!(!rib.vpn_flow_enforced(table, addr(SRC), &k(RD2)), "{table}");
    }
    let sizes: Vec<_> = rib
        .vpn_flowspec_push_snapshot()
        .unwrap()
        .into_iter()
        .map(|(t, r)| (t, r.len()))
        .collect();
    assert_eq!(sizes, [("red".into(), 1), ("blue".into(), 1)]);
    // Withdrawn: the other copy takes over.
    feed(&mut rib, SRC, &flow_unreach(RD1, flow()));
    assert!(rib.vpn_flow_enforced("red", addr(SRC), &k(RD2)));
    // A rule only `blue` imports is not enforced in `red`.
    feed(&mut rib, SRC, &flow_unreach(RD2, flow()));
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT2], RD2, flow()));
    assert!(rib.vpn_flow_enforced("blue", addr(SRC), &k(RD2)));
    assert!(!rib.vpn_flow_enforced("red", addr(SRC), &k(RD2)));
}

/// The IGP admits a VPN path late (its next hop was unresolved): the rules
/// that path covers are revalidated then (#1083).
#[test]
fn an_igp_change_revalidates_the_rules() {
    let mut rib = setup();
    rib.set_igp(HashMap::new());
    unicast(&mut rib, SRC, 65001, "10.10.0.0/24");
    feed(&mut rib, SRC, &flow_reach(65001, vec![RT], RD1, flow()));
    assert_eq!(view(&rib, "red"), ["invalid:no-covering-unicast-route"]);
    rib.set_igp(HashMap::from([("10.0.0.0/24".parse().unwrap(), 0)]));
    assert_eq!(view(&rib, "red"), ["valid"]);
}
