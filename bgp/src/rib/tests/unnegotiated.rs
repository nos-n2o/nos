//! #622: NLRI of a family the session never negotiated is ignored.

use super::*;

const PEER: &str = "10.0.0.1";

/// The receiver is returned so the outbox channel stays open.
fn rib_with(afs: &[AddressFamily]) -> (BgpRib, mpsc::Receiver<OutboundUpdate>) {
    let mut rib = new_rib(65000);
    rib.set_peer_asn(addr(PEER), 65001);
    let rx = register_mp_peer(
        &mut rib,
        addr(PEER),
        false,
        addr("10.0.0.254"),
        afs.iter().copied().collect(),
    );
    (rib, rx)
}

fn feed(rib: &mut BgpRib, u: &UpdateMessage) {
    rib.handle_update(addr(PEER), false, v4("1.1.1.1"), u, &accept_all_policy());
}

fn has(rib: &BgpRib, p: &str) -> bool {
    rib.loc_rib.contains_key(&prefix(p))
}

#[test]
fn legacy_nlri_ignored_without_ipv4_unicast() {
    let (mut rib, _rx) = rib_with(&[AddressFamily::Ipv6Unicast]);
    feed(
        &mut rib,
        &ebgp_update(vec!["198.51.100.0/24"], vec![65001], "192.0.2.1"),
    );
    assert!(!has(&rib, "198.51.100.0/24"));
}

#[test]
fn ipv6_mp_reach_ignored_on_ipv4_only_session() {
    let (mut rib, _rx) = rib_with(&[AddressFamily::Ipv4Unicast]);
    feed(&mut rib, &v6_update(vec!["2001:db8:1::/48"]));
    assert!(!has(&rib, "2001:db8:1::/48"));
}

#[test]
fn negotiated_families_unaffected() {
    let (mut rib, _rx) = rib_with(&[AddressFamily::Ipv4Unicast, AddressFamily::Ipv6Unicast]);
    feed(
        &mut rib,
        &ebgp_update(vec!["198.51.100.0/24"], vec![65001], "192.0.2.1"),
    );
    feed(&mut rib, &v6_update(vec!["2001:db8:1::/48"]));
    assert!(has(&rib, "198.51.100.0/24") && has(&rib, "2001:db8:1::/48"));
}

#[test]
fn safi2_batches_neither_learn_nor_withdraw_unicast() {
    let (mut rib, _rx) = rib_with(&[AddressFamily::Ipv4Unicast]);
    feed(
        &mut rib,
        &ebgp_update(vec!["198.51.100.0/24"], vec![65001], "192.0.2.1"),
    );
    let mut u = ebgp_update(vec![], vec![65001], "192.0.2.1");
    u.mp_reach = vec![message::MpReachNlri {
        afi: 1,
        safi: 2,
        next_hop: addr("192.0.2.1"),
        nlri: vec![],
        nlri_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![],
        flowspec_vpn: vec![],
        vpn: vec![],
        rtc: vec![],
    }];
    u.mp_unreach = vec![message::MpUnreachNlri {
        afi: 1,
        safi: 2,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![],
        flowspec: vec![],
        flowspec_vpn: vec![],
        vpn: vec![],
        rtc: vec![],
    }];
    feed(&mut rib, &u);
    assert!(has(&rib, "198.51.100.0/24"));
}
