use super::*;

/// Receives one EVPN UPDATE (RT 65000:10000) from `10.0.0.1` into a rib whose
/// peer has `script` as its EVPN import policy; returns the rib.
fn evpn_import(script: Option<&str>, nlri: EvpnNlri) -> BgpRib {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.set_peer_evpn_import_policy(
        peer,
        script.map(|s| Arc::new(nos_rpl::compile(s, &nos_rpl::Symbols::EMPTY).unwrap())),
        false,
    );
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &evpn_reach(vec![nlri], vec![65001]),
        &deny_all_policy(),
    );
    rib
}

fn rt_script(accept_rt: bool) -> String {
    let rt = (65000u64 << 32) | 10_000;
    let (hit, miss) = if accept_rt {
        ("accept", "reject")
    } else {
        ("reject", "accept")
    };
    format!("if this.bgp.extended_communities.contains(0:2:{rt}):\n    {hit}\nelse:\n    {miss}\n")
}

#[test]
fn accepts_and_rejects_by_route_target() {
    assert_eq!(
        evpn_import(Some(&rt_script(true)), evpn_nlri(1))
            .evpn_push_snapshot()
            .len(),
        1
    );
    let rejected = evpn_import(Some(&rt_script(false)), evpn_nlri(1));
    assert!(rejected.evpn_push_snapshot().is_empty());
    assert_eq!(
        rejected.peer_stats(addr("10.0.0.1")).rejected,
        1,
        "BMP stat 0"
    );
}

#[test]
fn unset_policy_accepts_everything() {
    assert_eq!(
        evpn_import(None, evpn_nlri(1)).evpn_push_snapshot().len(),
        1
    );
}

#[test]
fn ethernet_segment_routes_bypass_the_policy() {
    let nlri = EvpnNlri::EthernetSegment {
        rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
        esi: [1; 10],
        origin: addr("192.0.2.1"),
    };
    assert_eq!(
        evpn_import(Some("reject\n"), nlri)
            .evpn_push_snapshot()
            .len(),
        1
    );
}

#[test]
fn rejected_type2_creates_no_mobility_candidate() {
    let held = |rib: &BgpRib| {
        rib.mac_mobility
            .holds(10_000, [0xaa, 0, 0, 0, 0, 1], addr("192.0.2.1"), [0; 10])
    };
    assert!(held(&evpn_import(None, evpn_nlri(1))));
    assert!(!held(&evpn_import(Some("reject\n"), evpn_nlri(1))));
}

#[test]
fn changing_the_policy_purges_stored_routes() {
    let mut rib = evpn_import(None, evpn_nlri(1));
    assert_eq!(rib.evpn_push_snapshot().len(), 1);
    let reject = Arc::new(nos_rpl::compile("reject\n", &nos_rpl::Symbols::EMPTY).unwrap());
    rib.set_peer_evpn_import_policy(addr("10.0.0.1"), Some(reject), false);
    assert!(rib.evpn_push_snapshot().is_empty());
}

fn policies(evpn: Option<&str>) -> crate::rib::ImportPolicies {
    crate::rib::ImportPolicies {
        unicast: accept_all_policy(),
        evpn: evpn.map(|s| Arc::new(nos_rpl::compile(s, &nos_rpl::Symbols::EMPTY).unwrap())),
        flowspec: None,
    }
}

fn flagged_evpn_rib(script: &str, macs: &[u8]) -> BgpRib {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.set_peer_soft_reconfig(peer, true);
    rib.set_peer_evpn_import_policy(
        peer,
        Some(Arc::new(
            nos_rpl::compile(script, &nos_rpl::Symbols::EMPTY).unwrap(),
        )),
        false,
    );
    let routes = macs.iter().map(|m| evpn_nlri(*m)).collect();
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &evpn_reach(routes, vec![65001]),
        &deny_all_policy(),
    );
    rib
}

fn evpn_counts(fams: &[nos_proto::FamilyReeval]) -> (u32, u32) {
    let f = fams
        .iter()
        .find(|f| f.family == nos_proto::ReevalFamily::L2vpnEvpn)
        .expect("an EVPN entry");
    (f.retained, f.accepted)
}

#[test]
fn reevaluation_readmits_and_rejects_without_a_session_event() {
    let peer = addr("10.0.0.1");
    let mut rib = flagged_evpn_rib("reject\n", &[1, 2]);
    assert!(rib.evpn_push_snapshot().is_empty());
    assert_eq!(rib.retained_count(peer), 2, "the rejected ones are kept");
    // Loosen: both come back, and each registers with MAC mobility once.
    let fams = rib.reevaluate_peer(peer, policies(None));
    assert_eq!(evpn_counts(&fams), (2, 2));
    assert_eq!(rib.evpn_push_snapshot().len(), 2);
    assert!(rib
        .mac_mobility
        .holds(10_000, [0xaa, 0, 0, 0, 0, 1], addr("192.0.2.1"), [0; 10]));
    // Tighten: gone from the feed, still counted (the peer still sends them).
    let fams = rib.reevaluate_peer(peer, policies(Some("reject\n")));
    assert_eq!(evpn_counts(&fams), (2, 0));
    assert!(rib.evpn_push_snapshot().is_empty());
    assert_eq!(rib.retained_count(peer), 2);
    // Back again: re-admission is not a move.
    rib.reevaluate_peer(peer, policies(None));
    assert_eq!(rib.evpn_push_snapshot().len(), 2);
}

#[test]
fn a_withdrawal_drops_the_rejected_copy_and_a_chunk_skips_it() {
    let peer = addr("10.0.0.1");
    let mut rib = flagged_evpn_rib("reject\n", &[1, 2]);
    let mut pass = rib.begin_reevaluation(peer, policies(None)).unwrap();
    assert_eq!(
        rib.reevaluate_chunk(&mut pass, 1),
        crate::rib::ChunkOutcome::More
    );
    // Whichever route is still unvisited gets withdrawn between chunks.
    let mut u = empty_update();
    u.mp_unreach = vec![message::MpUnreachNlri {
        afi: 25,
        safi: message::SAFI_EVPN,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![evpn_nlri(1), evpn_nlri(2)],
        flowspec: vec![],
        vpn: vec![],
        rtc: Vec::new(),
    }];
    rib.handle_update(peer, false, v4("192.0.2.1"), &u, &deny_all_policy());
    assert_eq!(rib.retained_count(peer), 0);
    assert_eq!(
        rib.reevaluate_chunk(&mut pass, 1),
        crate::rib::ChunkOutcome::Done
    );
    assert!(rib.evpn_push_snapshot().is_empty(), "nothing resurrected");
}

#[test]
fn a_disconnect_ends_the_pass() {
    let peer = addr("10.0.0.1");
    let mut rib = flagged_evpn_rib("reject\n", &[1]);
    let mut pass = rib.begin_reevaluation(peer, policies(None)).unwrap();
    rib.peer_disconnected(peer, crate::gr::Disconnect::Hard);
    assert_eq!(
        rib.reevaluate_chunk(&mut pass, 1),
        crate::rib::ChunkOutcome::Gone
    );
}
