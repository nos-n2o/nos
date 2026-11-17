use super::*;

#[test]
fn peer_learned_route_beats_nothing_and_is_never_echoed_back_to_source() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let mut source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));

    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );

    // Never echoed back to the source peer.
    assert_eq!(recv_all(&mut source_rx), []);
}

#[test]
fn higher_local_pref_wins_best_path() {
    // peer_a/peer_b are confederation sources (LOCAL_PREF is honoured from
    // them, unlike plain eBGP, #601; and split-horizon doesn't remove them
    // for the iBGP observer below) proposing the same prefix with different
    // LOCAL_PREF values.
    let mut rib = new_rib(65000);
    let peer_a = addr("10.0.0.1");
    let peer_b = addr("10.0.0.2");
    let observer = addr("10.0.0.3");
    rib.set_peer_confed(peer_a, true);
    rib.set_peer_confed(peer_b, true);
    let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
    let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
    let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.252"));

    rib.handle_update(
        peer_a,
        false,
        v4("192.0.2.1"),
        &UpdateMessage {
            nlri: vec!["9.9.9.0/24".parse().unwrap()],
            attributes: Some(message::PathAttributes {
                origin: message::Origin::Igp,
                as_path: vec![].into(),
                next_hop: v4("10.0.0.1"),
                local_pref: Some(50),
                med: None,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
                otc: None,
                unknown: std::sync::Arc::default(),
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                ipv6_extended_communities: Vec::new(),
                pmsi: None,
            }),
            ..empty_update()
        },
        &nos_rpl::ACCEPT_ALL,
    );
    let _ = recv_all(&mut observer_rx);

    rib.handle_update(
        peer_b,
        false,
        v4("192.0.2.1"),
        &UpdateMessage {
            nlri: vec!["9.9.9.0/24".parse().unwrap()],
            attributes: Some(message::PathAttributes {
                origin: message::Origin::Igp,
                as_path: vec![].into(),
                next_hop: v4("10.0.0.2"),
                local_pref: Some(200),
                med: None,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
                otc: None,
                unknown: std::sync::Arc::default(),
                cluster_list: vec![],
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                ipv6_extended_communities: Vec::new(),
                pmsi: None,
            }),
            ..empty_update()
        },
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut observer_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            unknown: std::sync::Arc::default(),
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("9.9.9.0/24"),
            as_path: vec![].into(),
            // iBGP defaults to Unchanged: peer_b's own advertised
            // next-hop (10.0.0.2) is preserved, not rewritten to the
            // observer's local address.
            next_hop: addr("10.0.0.2"),
            local_pref: Some(200),
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn local_redistributed_route_beats_peer_learned_route_for_same_prefix() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let observer = addr("10.0.0.2");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["5.5.5.0/24"], vec![65099], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );
    let _ = recv_all(&mut observer_rx);

    rib.apply_redistribute_update(full_update(vec![("5.5.5.0/24", "10.9.9.9")]));

    let updates = recv_all(&mut observer_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            unknown: std::sync::Arc::default(),
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("5.5.5.0/24"),
            as_path: vec![65000].into(),
            next_hop: addr("10.0.0.253"),
            local_pref: None,
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn lower_origin_type_wins_when_local_pref_and_as_path_tie() {
    let mut rib = new_rib(65000);
    let peer_a = addr("10.0.0.1");
    let peer_b = addr("10.0.0.2");
    let observer = addr("10.0.0.3");
    let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
    let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
    let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.252"));

    rib.handle_update(
        peer_a,
        false,
        v4("192.0.2.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.1",
            message::Origin::Incomplete,
            None,
        ),
        &nos_rpl::ACCEPT_ALL,
    );
    let _ = recv_all(&mut observer_rx);

    rib.handle_update(
        peer_b,
        false,
        v4("192.0.2.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.2",
            message::Origin::Igp,
            None,
        ),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut observer_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            unknown: std::sync::Arc::default(),
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("9.9.9.0/24"),
            as_path: vec![65001].into(),
            next_hop: addr("10.0.0.2"),
            local_pref: Some(100),
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn lower_med_wins_when_neighboring_as_matches() {
    let mut rib = new_rib(65000);
    let peer_a = addr("10.0.0.1");
    let peer_b = addr("10.0.0.2");
    let observer = addr("10.0.0.3");
    let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
    let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
    let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.252"));

    // Both candidates' AS_PATH starts with 65001 — same neighboring AS —
    // so MED is directly comparable between them.
    rib.handle_update(
        peer_a,
        false,
        v4("192.0.2.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.1",
            message::Origin::Igp,
            Some(200),
        ),
        &nos_rpl::ACCEPT_ALL,
    );
    let _ = recv_all(&mut observer_rx);

    rib.handle_update(
        peer_b,
        false,
        v4("192.0.2.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.2",
            message::Origin::Igp,
            Some(100),
        ),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut observer_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            unknown: std::sync::Arc::default(),
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("9.9.9.0/24"),
            as_path: vec![65001].into(),
            next_hop: addr("10.0.0.2"),
            local_pref: Some(100),
            med: Some(100), // forwarded: the destination is an iBGP peer
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn med_is_ignored_between_different_neighboring_as() {
    let mut rib = new_rib(65000);
    let peer_a = addr("10.0.0.1");
    let peer_b = addr("10.0.0.2");
    let observer = addr("10.0.0.3");
    let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
    let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
    let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.252"));

    // peer_a's MED (999) is far worse than peer_b's (1), but their
    // AS_PATHs start with different ASes, so MED must not be compared
    // between them — peer_a keeps winning via the earlier "oldest
    // route" step (step 8), since both are eBGP-learned and peer_a
    // arrived first, proving the MED comparison was skipped rather
    // than deciding in peer_b's favor.
    rib.handle_update(
        peer_a,
        false,
        v4("192.0.2.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.1",
            message::Origin::Igp,
            Some(999),
        ),
        &nos_rpl::ACCEPT_ALL,
    );
    let initial = recv_all(&mut observer_rx);
    assert_eq!(
        initial,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            unknown: std::sync::Arc::default(),
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("9.9.9.0/24"),
            as_path: vec![65001].into(),
            next_hop: addr("10.0.0.1"),
            local_pref: Some(100),
            med: Some(999), // forwarded: the destination is an iBGP peer
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );

    rib.handle_update(
        peer_b,
        false,
        v4("192.0.2.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65002],
            "10.0.0.2",
            message::Origin::Igp,
            Some(1),
        ),
        &nos_rpl::ACCEPT_ALL,
    );

    // The winner is unchanged (still peer_a), so no new announcement is
    // sent at all — if MED had been compared across the differing
    // neighboring ASes, peer_b's much lower MED would have won instead.
    assert_eq!(recv_all(&mut observer_rx), []);
}

#[test]
fn ebgp_learned_route_beats_ibgp_learned_route_when_otherwise_tied() {
    let mut rib = new_rib(65000);
    // The iBGP source has the numerically lower peer address, so an
    // eBGP win here can only be explained by the eBGP-over-iBGP step,
    // not the final peer-address tiebreak.
    let ibgp_peer = addr("10.0.0.1");
    let ebgp_peer = addr("10.0.0.2");
    let observer = addr("10.0.0.3");
    let _rx_ibgp = register_peer(&mut rib, ibgp_peer, true, addr("10.0.0.254"));
    let _rx_ebgp = register_peer(&mut rib, ebgp_peer, false, addr("10.0.0.253"));
    let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.252"));

    rib.handle_update(
        ibgp_peer,
        true,
        v4("192.0.2.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.1",
            message::Origin::Igp,
            None,
        ),
        &nos_rpl::ACCEPT_ALL,
    );
    let _ = recv_all(&mut observer_rx);

    rib.handle_update(
        ebgp_peer,
        false,
        v4("192.0.2.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.2",
            message::Origin::Igp,
            None,
        ),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut observer_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            unknown: std::sync::Arc::default(),
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("9.9.9.0/24"),
            as_path: vec![65000, 65001].into(),
            // Destination is eBGP, so next-hop-self rewrites to the
            // observer's own local address, not either source's.
            next_hop: addr("10.0.0.252"),
            local_pref: None,
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn lower_igp_cost_to_next_hop_wins_and_follows_igp_changes() {
    let mut rib = new_rib(65000);
    // Both iBGP with equal attributes; peer_a has the lower router-id, so
    // without step (d) it would win at step 9.
    let peer_a = addr("10.0.0.1");
    let peer_b = addr("10.0.0.2");
    let _rx_a = register_peer(&mut rib, peer_a, true, addr("10.0.0.254"));
    let _rx_b = register_peer(&mut rib, peer_b, true, addr("10.0.0.253"));
    rib.set_routing_table(Some("rt1".to_string()));
    for (peer, rid, nh) in [
        (peer_a, "1.1.1.1", "10.1.0.1"),
        (peer_b, "5.5.5.5", "10.2.0.1"),
    ] {
        rib.handle_update(
            peer,
            true,
            v4(rid),
            &update_with("9.9.9.0/24", vec![65001], nh, message::Origin::Igp, None),
            &nos_rpl::ACCEPT_ALL,
        );
    }
    let best = |rib: &BgpRib| rib.push_snapshot().1[&prefix("9.9.9.0/24")].0[0];
    assert_eq!(best(&rib), addr("10.1.0.1"));

    let igp =
        |a: u32, b: u32| HashMap::from([(prefix("10.1.0.0/16"), a), (prefix("10.2.0.0/16"), b)]);
    rib.set_igp(igp(30, 10));
    assert_eq!(best(&rib), addr("10.2.0.1"));
    rib.set_igp(igp(10, 30));
    assert_eq!(best(&rib), addr("10.1.0.1"));
    // Longest match wins: a /24 for peer_a's next hop overrides its /16.
    let mut more = igp(10, 20);
    more.insert(prefix("10.1.0.0/24"), 99);
    rib.set_igp(more);
    assert_eq!(best(&rib), addr("10.2.0.1"));
}

// --- RFC 4271 §9.1.2 next-hop feasibility ---

/// One peer-learned route for `9.9.9.0/24` with next hop `10.1.0.1`.
fn learn_one(rib: &mut BgpRib, peer: IpAddr, next_hop: &str) {
    rib.handle_update(
        peer,
        false,
        v4("5.5.5.5"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            next_hop,
            message::Origin::Igp,
            None,
        ),
        &nos_rpl::ACCEPT_ALL,
    );
}

#[test]
fn unresolved_next_hop_excluded_once_igp_ready_and_admitted_when_igp_learns_it() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.set_routing_table(Some("rt1".to_string()));
    // The IGP knows the peer's own subnet, not the advertised next hop.
    rib.set_igp(HashMap::from([(prefix("10.0.0.0/24"), 0)]));

    learn_one(&mut rib, peer, "10.1.0.1");
    assert!(
        rib.push_snapshot().1.is_empty(),
        "unfeasible route reached the loc-rib"
    );
    assert!(rib.loc_rib.is_empty());

    // An IGP route covering the next hop appears: no BGP event, but the
    // candidate must be re-decided and win.
    rib.set_igp(HashMap::from([
        (prefix("10.0.0.0/24"), 0),
        (prefix("10.1.0.0/16"), 20),
    ]));
    assert_eq!(
        rib.push_snapshot().1[&prefix("9.9.9.0/24")].0[0],
        addr("10.1.0.1")
    );

    // ...and disappears again: withdrawn from the loc-rib.
    rib.set_igp(HashMap::from([(prefix("10.0.0.0/24"), 0)]));
    assert!(rib.loc_rib.is_empty());
}

#[test]
fn unresolved_next_hop_not_excluded_before_first_igp_poll() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.set_routing_table(Some("rt1".to_string()));

    learn_one(&mut rib, peer, "10.1.0.1");
    assert_eq!(
        rib.push_snapshot().1[&prefix("9.9.9.0/24")].0[0],
        addr("10.1.0.1")
    );

    // The very first poll — even an empty table — turns the check on.
    rib.set_igp(HashMap::new());
    assert!(rib.loc_rib.is_empty());
}

#[test]
fn local_redistributed_route_never_filtered() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.set_igp(HashMap::new());

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
    assert!(rib.loc_rib.contains_key(&prefix("192.168.1.0/24")));
    assert!(matches!(
        recv_all(&mut rx).as_slice(),
        [OutboundUpdate::Announce(_)]
    ));
}

#[test]
fn route_server_client_still_sees_infeasible_path_transparently() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let rs_client = addr("10.0.0.2");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let mut rs_rx = register_peer_full(
        &mut rib,
        rs_client,
        false,
        addr("10.0.0.253"),
        false,
        true,
        [AddressFamily::Ipv4Unicast].into_iter().collect(),
    );
    rib.set_igp(HashMap::new());

    learn_one(&mut rib, peer, "10.1.0.1");
    // Not in this instance's own loc-rib...
    assert!(rib.loc_rib.is_empty());
    // ...but the route-server client gets the path as submitted.
    let updates = recv_all(&mut rs_rx);
    assert!(
        matches!(
            updates.as_slice(),
            [OutboundUpdate::Announce(AdvertisedRoute {
                path_id: Some(_),
                ..
            })]
        ),
        "{updates:?}"
    );
}

#[test]
fn runner_up_backup_also_requires_resolvable_next_hop() {
    let mut rib = new_rib(65000);
    let peer_a = addr("10.0.0.1");
    let peer_b = addr("10.0.0.2");
    let _rx_a = register_peer(&mut rib, peer_a, true, addr("10.0.0.254"));
    let _rx_b = register_peer(&mut rib, peer_b, true, addr("10.0.0.253"));
    rib.set_routing_table(Some("rt1".to_string()));
    // Only peer_a's next hop resolves.
    rib.set_igp(HashMap::from([(prefix("10.1.0.0/16"), 10)]));
    for (peer, nh) in [(peer_a, "10.1.0.1"), (peer_b, "10.2.0.1")] {
        rib.handle_update(
            peer,
            true,
            v4("5.5.5.5"),
            &update_with("9.9.9.0/24", vec![65001], nh, message::Origin::Igp, None),
            &nos_rpl::ACCEPT_ALL,
        );
    }
    assert_eq!(
        rib.push_snapshot().1[&prefix("9.9.9.0/24")],
        (vec![addr("10.1.0.1")], None, false)
    );

    // Once peer_b's resolves too, it becomes the backup.
    rib.set_igp(HashMap::from([
        (prefix("10.1.0.0/16"), 10),
        (prefix("10.2.0.0/16"), 10),
    ]));
    assert_eq!(
        rib.push_snapshot().1[&prefix("9.9.9.0/24")],
        (vec![addr("10.1.0.1")], Some(addr("10.2.0.1")), false)
    );
}

#[test]
fn lower_router_id_wins_when_otherwise_tied() {
    let mut rib = new_rib(65000);
    // Both sources are iBGP, so the eBGP-over-iBGP step (6) and the
    // eBGP-only "oldest route" step (8) both tie — router-id (9) must
    // decide. peer_b has the higher address but the lower router-id, so
    // its win can only be explained by the router-id step, not the
    // final peer-address tiebreak.
    let peer_a = addr("10.0.0.1");
    let peer_b = addr("10.0.0.2");
    let observer = addr("10.0.0.3");
    let _rx_a = register_peer(&mut rib, peer_a, true, addr("10.0.0.254"));
    let _rx_b = register_peer(&mut rib, peer_b, true, addr("10.0.0.253"));
    let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.252"));

    rib.handle_update(
        peer_a,
        true,
        v4("5.5.5.5"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.1",
            message::Origin::Igp,
            None,
        ),
        &nos_rpl::ACCEPT_ALL,
    );
    let _ = recv_all(&mut observer_rx);

    rib.handle_update(
        peer_b,
        true,
        v4("1.1.1.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.2",
            message::Origin::Igp,
            None,
        ),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut observer_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            unknown: std::sync::Arc::default(),
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("9.9.9.0/24"),
            // Destination is eBGP, so our own ASN is prepended and
            // next-hop-self rewrites to the observer's own local
            // address, not either source's.
            as_path: vec![65000, 65001].into(),
            next_hop: addr("10.0.0.252"),
            local_pref: None,
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn oldest_route_wins_over_a_later_lower_router_id_and_address() {
    let mut rib = new_rib(65000);
    // peer_a has the higher address and router-id (would lose steps 9
    // and 10) but is received first; peer_b has the lower address and
    // router-id but arrives second. peer_a winning proves the "oldest
    // route" step (8) is applied, and applied before router-id/address.
    let peer_a = addr("10.0.0.9");
    let peer_b = addr("10.0.0.1");
    let observer = addr("10.0.0.3");
    let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
    let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
    let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.252"));

    rib.handle_update(
        peer_a,
        false,
        v4("9.9.9.9"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.9",
            message::Origin::Igp,
            None,
        ),
        &nos_rpl::ACCEPT_ALL,
    );
    let initial = recv_all(&mut observer_rx);
    assert_eq!(
        initial,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            unknown: std::sync::Arc::default(),
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("9.9.9.0/24"),
            as_path: vec![65001].into(),
            next_hop: addr("10.0.0.9"),
            local_pref: Some(100),
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );

    rib.handle_update(
        peer_b,
        false,
        v4("1.1.1.1"),
        &update_with(
            "9.9.9.0/24",
            vec![65001],
            "10.0.0.1",
            message::Origin::Igp,
            None,
        ),
        &nos_rpl::ACCEPT_ALL,
    );

    // The winner is unchanged (still peer_a), so no new announcement is
    // sent — if the oldest-route step didn't apply, peer_b's lower
    // router-id and address would have won at steps 9/10 instead.
    assert_eq!(recv_all(&mut observer_rx), []);
}

#[test]
fn push_snapshot_carries_runner_up_as_backup() {
    let mut rib = new_rib(65000);
    rib.handle_update(
        addr("10.0.0.1"),
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.9"),
        &nos_rpl::ACCEPT_ALL,
    );
    // Longer AS_PATH → loses, but its distinct next hop is the backup.
    rib.handle_update(
        addr("10.0.0.2"),
        false,
        v4("192.0.2.2"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65002, 65003], "10.0.0.8"),
        &nos_rpl::ACCEPT_ALL,
    );
    // A third path sharing the winner's next hop can't be a backup.
    rib.handle_update(
        addr("10.0.0.3"),
        false,
        v4("192.0.2.3"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65004, 65005, 65006], "10.0.0.9"),
        &nos_rpl::ACCEPT_ALL,
    );

    let (_, routes) = rib.push_snapshot();
    assert_eq!(
        routes.get(&prefix("1.2.3.0/24")),
        Some(&(vec![addr("10.0.0.9")], Some(addr("10.0.0.8")), false))
    );

    // Losing the runner-up drops the backup.
    rib.peer_disconnected(addr("10.0.0.2"), Disconnect::Transport);
    let (_, routes) = rib.push_snapshot();
    assert_eq!(
        routes.get(&prefix("1.2.3.0/24")),
        Some(&(vec![addr("10.0.0.9")], None, false))
    );
}

// --- BGP multipath (`maximum_paths`) ---

/// Learns `1.2.3.0/24` from `peer` (`ibgp` session) with `as_path`, `nh`
/// and `med`.
fn learn_mp(
    rib: &mut BgpRib,
    peer: &str,
    ibgp: bool,
    as_path: Vec<u32>,
    nh: &str,
    med: Option<u32>,
) {
    rib.handle_update(
        addr(peer),
        ibgp,
        v4("192.0.2.1"),
        &update_with("1.2.3.0/24", as_path, nh, message::Origin::Igp, med),
        &nos_rpl::ACCEPT_ALL,
    );
}

fn mp_hops(rib: &BgpRib) -> (Vec<IpAddr>, Option<IpAddr>) {
    let (hops, backup, _) = rib.push_snapshot().1[&prefix("1.2.3.0/24")].clone();
    (hops, backup)
}

#[test]
fn multipath_installs_equal_paths_from_the_same_neighbour_as() {
    let mut rib = new_rib(65000);
    rib.set_maximum_paths(Some(2));
    learn_mp(&mut rib, "10.0.0.2", false, vec![65001], "10.0.0.20", None);
    learn_mp(&mut rib, "10.0.0.1", false, vec![65001], "10.0.0.10", None);
    assert_eq!(
        mp_hops(&rib),
        (vec![addr("10.0.0.10"), addr("10.0.0.20")], None)
    );

    // Back to 1: the winner alone, the sibling becomes the backup.
    rib.set_maximum_paths(Some(1));
    let (hops, backup) = mp_hops(&rib);
    assert_eq!(hops.len(), 1);
    assert!(backup.is_some() && !hops.contains(&backup.unwrap()));
}

#[test]
fn multipath_unset_installs_the_winner_alone() {
    let mut rib = new_rib(65000);
    learn_mp(&mut rib, "10.0.0.1", false, vec![65001], "10.0.0.10", None);
    learn_mp(&mut rib, "10.0.0.2", false, vec![65001], "10.0.0.20", None);
    assert_eq!(mp_hops(&rib).0.len(), 1);
}

#[test]
fn multipath_excludes_paths_that_differ_before_step_8() {
    // (as_path, med, ibgp) of the second path, each losing to
    // ([65001], None, eBGP) or not sharing its neighbour AS.
    for (as_path, med, ibgp) in [
        (vec![65001, 65009], None, false), // longer AS_PATH
        (vec![65001], Some(5), false),     // higher MED
        (vec![65001], None, true),         // iBGP vs eBGP
        (vec![65002], None, false),        // other neighbour AS
    ] {
        let mut rib = new_rib(65000);
        rib.set_maximum_paths(Some(4));
        learn_mp(&mut rib, "10.0.0.1", false, vec![65001], "10.0.0.10", None);
        learn_mp(
            &mut rib,
            "10.0.0.2",
            ibgp,
            as_path.clone(),
            "10.0.0.20",
            med,
        );
        assert_eq!(
            mp_hops(&rib),
            (vec![addr("10.0.0.10")], Some(addr("10.0.0.20"))),
            "{as_path:?} {med:?} ibgp={ibgp}"
        );
    }

    // A higher IGP cost to the next hop (step 7) too.
    let mut rib = new_rib(65000);
    rib.set_maximum_paths(Some(4));
    rib.set_igp(HashMap::from([
        (prefix("10.0.0.0/28"), 1),
        (prefix("10.0.0.16/28"), 9),
    ]));
    learn_mp(&mut rib, "10.0.0.1", false, vec![65001], "10.0.0.10", None);
    learn_mp(&mut rib, "10.0.0.2", false, vec![65001], "10.0.0.20", None);
    assert_eq!(mp_hops(&rib).0, vec![addr("10.0.0.10")]);
}

#[test]
fn multipath_caps_at_maximum_paths_and_backs_up_outside_the_set() {
    let mut rib = new_rib(65000);
    rib.set_maximum_paths(Some(2));
    // Equal on steps 1–7; step 10 (lowest peer address) orders them.
    learn_mp(&mut rib, "10.0.0.3", false, vec![65001], "10.0.0.30", None);
    learn_mp(&mut rib, "10.0.0.2", false, vec![65001], "10.0.0.20", None);
    learn_mp(&mut rib, "10.0.0.1", false, vec![65001], "10.0.0.10", None);
    // Step 8 (oldest eBGP route) comes before step 10, so the first
    // learned wins and the next oldest joins.
    assert_eq!(
        mp_hops(&rib),
        (
            vec![addr("10.0.0.20"), addr("10.0.0.30")],
            Some(addr("10.0.0.10"))
        )
    );
}

#[test]
fn multipath_sibling_leaving_changes_the_push_not_the_loc_rib() {
    let mut rib = new_rib(65000);
    rib.set_maximum_paths(Some(2));
    let peer = addr("10.0.0.9");
    let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    learn_mp(&mut rib, "10.0.0.1", false, vec![65001], "10.0.0.10", None);
    learn_mp(&mut rib, "10.0.0.2", false, vec![65001], "10.0.0.20", None);
    let best = rib.loc_rib[&prefix("1.2.3.0/24")].clone();
    recv_all(&mut rx);

    rib.peer_disconnected(addr("10.0.0.2"), Disconnect::Transport);
    assert_eq!(mp_hops(&rib), (vec![addr("10.0.0.10")], None));
    assert_eq!(rib.loc_rib[&prefix("1.2.3.0/24")], best);
    assert!(recv_all(&mut rx).is_empty(), "advertisement must not move");
}

#[test]
fn identical_reannouncement_keeps_oldest_route_tiebreak() {
    // Step 8: the older eBGP route wins; re-sending it unchanged must not
    // make it "newer" and hand the best path to the other peer (#160).
    let mut rib = new_rib(65000);
    let (old, new) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let _a = register_peer(&mut rib, old, false, addr("10.0.0.254"));
    let _b = register_peer(&mut rib, new, false, addr("10.0.0.253"));
    let from_old = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
    let from_new = ebgp_update(vec!["1.2.3.0/24"], vec![65002], "10.0.0.2");
    // `old` has the higher router id, so only step 8 can make it win.
    rib.handle_update(old, false, v4("192.0.2.2"), &from_old, &nos_rpl::ACCEPT_ALL);
    rib.handle_update(new, false, v4("192.0.2.1"), &from_new, &nos_rpl::ACCEPT_ALL);
    rib.handle_update(old, false, v4("192.0.2.2"), &from_old, &nos_rpl::ACCEPT_ALL);
    assert_eq!(
        rib.loc_rib[&prefix("1.2.3.0/24")].origin,
        RouteOrigin::Peer(old)
    );
}

mod deterministic_med {
    use super::*;
    use crate::as_path::SegKind;
    use proptest::prelude::*;

    fn cand(asn: u32, med: u32, id: u32) -> Candidate {
        let mut path = AsPath::default();
        path.push_segment(SegKind::Sequence, &[asn]);
        let mut r = redistributed_route();
        r.origin = RouteOrigin::Peer(IpAddr::V4(Ipv4Addr::new(
            10,
            0,
            0,
            u8::try_from(id).unwrap() + 1,
        )));
        r.as_path = Arc::new(path);
        r.med = Some(med);
        r.router_id = Some(Ipv4Addr::new(1, 1, 1, u8::try_from(id).unwrap() + 1));
        r.next_hop = Some(IpAddr::V4(Ipv4Addr::new(
            192,
            0,
            2,
            u8::try_from(id).unwrap() + 1,
        )));
        (r, id)
    }

    fn ids(v: &[Candidate]) -> Vec<u32> {
        v.iter().map(|c| c.1).collect()
    }

    /// A, B share AS 1 (A has the worse MED); C is AS 2. Pairwise, B > A
    /// (MED), A > C (router-id), C > B (router-id): a cycle.
    #[test]
    fn mixed_as_cycle_is_ranked_by_group_winners() {
        let igp = HashMap::new();
        let all = vec![cand(1, 20, 0), cand(2, 0, 1), cand(1, 10, 2)];
        // B wins its group; B vs C -> C has the lower router-id.
        assert_eq!(ids(&rank(&all, &igp)), [1, 2, 0]);
        assert_eq!(best_path(&all, &igp).unwrap().next_hop, all[1].0.next_hop);
    }

    #[test]
    fn ranked_does_not_panic_on_many_mixed_as_candidates() {
        let rib = new_rib(65000);
        let cands: Vec<Candidate> = (0..30).map(|i| cand(1 + i % 3, 30 - i, i)).collect();
        assert_eq!(rib.ranked(&cands).len(), 30);
    }

    fn arb_cands() -> impl Strategy<Value = Vec<Candidate>> {
        proptest::collection::vec((1..5u32, 0..4u32, 0..3u32), 0..40).prop_map(|v| {
            v.into_iter()
                .zip(0u32..)
                .map(|((asn, med, lp), id)| {
                    let mut c = cand(asn, med, id % 200);
                    c.0.local_pref = 100 + lp;
                    c.1 = id;
                    c
                })
                .collect()
        })
    }

    proptest! {
        #[test]
        fn rank_is_total_and_order_independent(cands in arb_cands(), seed in any::<u64>()) {
            let igp = HashMap::new();
            let r = rank(&cands, &igp);
            let mut sorted = ids(&r);
            sorted.sort_unstable();
            prop_assert_eq!(sorted, (0..u32::try_from(cands.len()).unwrap()).collect::<Vec<_>>());
            let mut shuffled = cands.clone();
            shuffled.rotate_left(usize::try_from(seed).unwrap() % cands.len().max(1));
            shuffled.reverse();
            prop_assert_eq!(ids(&rank(&shuffled, &igp)), ids(&r));
            if let Some(first) = r.first() {
                prop_assert_eq!(best_path(&cands, &igp), Some(first.0.clone()));
            }
            // Within one neighbouring AS, an otherwise-equal lower MED never ranks later.
            for (i, x) in r.iter().enumerate() {
                for y in &r[..i] {
                    if x.0.as_path.neighbor_as() == y.0.as_path.neighbor_as()
                        && x.0.local_pref == y.0.local_pref
                    {
                        prop_assert!(y.0.med <= x.0.med);
                    }
                }
            }
        }
    }
}

fn lp_update(local_pref: u32, next_hop: &str) -> UpdateMessage {
    let mut u = ebgp_update(vec!["9.9.9.0/24"], vec![65001], next_hop);
    u.attributes.as_mut().unwrap().local_pref = Some(local_pref);
    u
}

#[test]
fn ebgp_local_pref_is_ignored_ibgp_and_confed_keep_it() {
    // RFC 4271 §5.1.5 (#601).
    let p = prefix("9.9.9.0/24");
    for (ibgp, confed, want) in [
        (false, false, 100),
        (true, false, 1000),
        (false, true, 1000),
    ] {
        let mut rib = new_rib(65000);
        let peer = addr("10.0.0.1");
        rib.set_peer_confed(peer, confed);
        let _rx = register_peer(&mut rib, peer, ibgp, addr("10.0.0.254"));
        rib.handle_update(
            peer,
            ibgp,
            v4("1.1.1.1"),
            &lp_update(1000, "10.0.0.1"),
            &nos_rpl::ACCEPT_ALL,
        );
        assert_eq!(
            rib.loc_rib[&p].local_pref, want,
            "ibgp={ibgp} confed={confed}"
        );
    }
}

#[test]
fn ebgp_local_pref_loses_to_ibgp_150_and_policy_can_still_set_it() {
    let p = prefix("9.9.9.0/24");
    let mut rib = new_rib(65000);
    let (e, i) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let _rx_e = register_peer(&mut rib, e, false, addr("10.0.0.254"));
    let _rx_i = register_peer(&mut rib, i, true, addr("10.0.0.253"));
    rib.handle_update(
        e,
        false,
        v4("1.1.1.1"),
        &lp_update(1000, "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );
    rib.handle_update(
        i,
        true,
        v4("2.2.2.2"),
        &lp_update(150, "10.0.0.2"),
        &nos_rpl::ACCEPT_ALL,
    );
    assert_eq!(rib.loc_rib[&p].local_pref, 150);
    assert_eq!(rib.loc_rib[&p].origin, RouteOrigin::Peer(i));
}
