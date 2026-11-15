//! RFC 4271 §6.3 `NEXT_HOP` validation in `handle_update`.

use super::*;

const PEER: &str = "10.0.0.3";
const OWN: &str = "10.0.0.254";

fn rib_with_peer() -> BgpRib {
    let mut rib = new_rib(65100);
    register_peer(&mut rib, addr(PEER), false, addr(OWN));
    rib
}

fn feed(rib: &mut BgpRib, u: &UpdateMessage) {
    rib.handle_update(addr(PEER), false, v4("3.3.3.3"), u, &accept_all_policy());
}

fn mp_update(p: &str, nh: &str) -> UpdateMessage {
    let mut u = ebgp_update(vec![], vec![65003], "192.0.2.3");
    u.mp_reach = vec![message::MpReachNlri {
        afi: if p.contains(':') { 2 } else { 1 },
        safi: 1,
        next_hop: addr(nh),
        nlri: vec![prefix(p)],
        nlri_path_ids: vec![],
        evpn: vec![],
        flowspec: Vec::new(),
        flowspec_vpn: Vec::new(),
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    u
}

#[test]
fn martian_legacy_next_hop_withdraws_earlier_path() {
    for nh in [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        OWN,
    ] {
        let mut rib = rib_with_peer();
        feed(
            &mut rib,
            &ebgp_update(vec!["198.51.100.0/24"], vec![65003], "192.0.2.3"),
        );
        assert!(rib.loc_rib.contains_key(&prefix("198.51.100.0/24")));
        feed(
            &mut rib,
            &ebgp_update(vec!["198.51.100.0/24"], vec![65003], nh),
        );
        assert!(rib.loc_rib.is_empty(), "{nh} accepted");
    }
}

#[test]
fn martian_mp_reach_next_hop_withdraws_earlier_path() {
    for (p, good, bad) in [
        ("198.51.100.0/24", "192.0.2.3", "240.0.0.1"),
        ("198.51.100.0/24", "192.0.2.3", OWN),
        ("2001:db8::/32", "2001:db8::3", "::"),
        ("2001:db8::/32", "2001:db8::3", "::1"),
        ("2001:db8::/32", "2001:db8::3", "ff02::1"),
    ] {
        let mut rib = rib_with_peer();
        feed(&mut rib, &mp_update(p, good));
        assert!(rib.loc_rib.contains_key(&prefix(p)), "{good} rejected");
        feed(&mut rib, &mp_update(p, bad));
        assert!(rib.loc_rib.is_empty(), "{bad} accepted");
    }
}

#[test]
fn own_ipv6_session_address_is_rejected() {
    let mut rib = new_rib(65100);
    register_peer(&mut rib, addr("2001:db8::3"), false, addr("2001:db8::1"));
    rib.handle_update(
        addr("2001:db8::3"),
        false,
        v4("3.3.3.3"),
        &mp_update("2001:db8:1::/48", "2001:db8::1"),
        &accept_all_policy(),
    );
    assert!(rib.loc_rib.is_empty());
}

#[test]
fn link_local_ipv6_next_hop_is_valid() {
    let mut rib = rib_with_peer();
    feed(&mut rib, &mp_update("2001:db8::/32", "fe80::3"));
    assert_eq!(rib.loc_rib.len(), 1);
}

#[test]
fn martian_table() {
    use crate::message::next_hop_is_martian as m;
    assert!(m(addr("::ffff:192.0.2.1"), None));
    assert!(!m(addr("192.0.2.1"), None));
    assert!(!m(addr("192.0.2.1"), Some(addr("192.0.2.2"))));
    assert!(m(addr("192.0.2.1"), Some(addr("192.0.2.1"))));
}

#[test]
fn next_hop_family_rule() {
    let ok = |p, nh, l: Option<&str>| next_hop_family_ok(prefix(p), addr(nh), l.map(addr));
    assert!(ok("2001:db8::/32", "2001:db8::1", None));
    assert!(!ok("2001:db8::/32", "192.0.2.1", Some("2001:db8::9")));
    assert!(ok("198.51.100.0/24", "192.0.2.1", None));
    // RFC 8950: v6 next hop for v4 only over a v6 session.
    assert!(ok("198.51.100.0/24", "2001:db8::1", Some("2001:db8::9")));
    assert!(!ok("198.51.100.0/24", "2001:db8::1", Some("10.0.0.9")));
}

#[test]
fn import_policy_v4_next_hop_on_v6_route_is_ignored() {
    let mut rib = rib_with_peer();
    let policy = nos_rpl::compile(
        "set this.bgp.next_hop = 192.0.2.99\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    rib.handle_update(
        addr(PEER),
        false,
        v4("3.3.3.3"),
        &mp_update("2001:db8::/32", "2001:db8::3"),
        &policy,
    );
    let route = &rib.loc_rib[&prefix("2001:db8::/32")];
    assert_eq!(route.next_hop, Some(addr("2001:db8::3")));
}
