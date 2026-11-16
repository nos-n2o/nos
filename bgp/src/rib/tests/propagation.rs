use super::*;

#[test]
fn route_server_client_defaults_to_unchanged_next_hop() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let _src_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut rs_rx = register_peer_full(
        &mut rib,
        addr("10.0.0.2"),
        false,
        addr("10.0.0.253"),
        false,
        true,
        HashSet::new(),
    );
    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["9.9.9.0/24"], vec![65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );
    let next_hops: Vec<IpAddr> = recv_all(&mut rs_rx)
        .into_iter()
        .filter_map(|u| match u {
            OutboundUpdate::Announce(a) => Some(a.next_hop),
            _ => None,
        })
        .collect();
    assert_eq!(next_hops, vec![addr("10.0.0.1")]);
}

#[test]
fn redistributed_route_is_announced_to_ebgp_peer_with_prepend_and_no_local_pref() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

    let updates = recv_all(&mut rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("192.168.1.0/24"),
            as_path: vec![65000].into(),
            next_hop: addr("10.0.0.254"),
            local_pref: None,
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn redistributed_route_is_announced_to_ibgp_peer_with_local_pref_and_no_prepend() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.2");
    let mut rx = register_peer(&mut rib, peer, true, addr("10.0.0.253"));

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

    let updates = recv_all(&mut rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("192.168.1.0/24"),
            as_path: vec![].into(),
            next_hop: addr("10.0.0.253"),
            local_pref: Some(100),
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn peer_learned_route_is_propagated_to_a_third_peer() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let other = addr("10.0.0.2");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut other_rx = register_peer(&mut rib, other, false, addr("10.0.0.253"));

    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut other_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("1.2.3.0/24"),
            as_path: vec![65000, 65001].into(),
            next_hop: addr("10.0.0.253"),
            local_pref: None,
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn ibgp_split_horizon_never_reflects_between_two_ibgp_peers() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let other = addr("10.0.0.2");
    let _source_rx = register_peer(&mut rib, source, true, addr("10.0.0.254"));
    let mut other_rx = register_peer(&mut rib, other, true, addr("10.0.0.253"));

    rib.handle_update(
        source,
        true,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );

    assert_eq!(recv_all(&mut other_rx), []);
}

#[test]
fn ebgp_learned_route_is_still_propagated_to_an_ibgp_peer_with_next_hop_unchanged() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1"); // eBGP source
    let ibgp_peer = addr("10.0.0.2");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut ibgp_rx = register_peer(&mut rib, ibgp_peer, true, addr("10.0.0.253"));

    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut ibgp_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("1.2.3.0/24"),
            as_path: vec![65001].into(),
            // iBGP defaults to Unchanged: the eBGP source's own
            // next-hop (10.0.0.1) is preserved, not rewritten to the
            // ibgp_peer's own local address.
            next_hop: addr("10.0.0.1"),
            local_pref: Some(100),
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn ibgp_peer_with_next_hop_self_override_rewrites_to_local_address() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1"); // eBGP source
    let ibgp_peer = addr("10.0.0.2");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut ibgp_rx = register_peer_with_mode(
        &mut rib,
        ibgp_peer,
        true,
        addr("10.0.0.253"),
        Some(NextHopMode::SelfAddress),
    );

    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut ibgp_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("1.2.3.0/24"),
            as_path: vec![65001].into(),
            next_hop: addr("10.0.0.253"),
            local_pref: Some(100),
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn ebgp_peer_with_next_hop_unchanged_override_preserves_received_next_hop() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let other = addr("10.0.0.2");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut other_rx = register_peer_with_mode(
        &mut rib,
        other,
        false,
        addr("10.0.0.253"),
        Some(NextHopMode::Unchanged),
    );

    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut other_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("1.2.3.0/24"),
            as_path: vec![65000, 65001].into(),
            next_hop: addr("10.0.0.1"),
            local_pref: None,
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn redistributed_route_always_gets_next_hop_self_even_with_unchanged_override() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_peer_with_mode(
        &mut rib,
        peer,
        true,
        addr("10.0.0.253"),
        Some(NextHopMode::Unchanged),
    );

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

    let updates = recv_all(&mut rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("192.168.1.0/24"),
            as_path: vec![].into(),
            // No stored next-hop on a Local-origin route, so it always
            // falls back to next-hop-self regardless of mode.
            next_hop: addr("10.0.0.253"),
            local_pref: Some(100),
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn route_with_own_asn_in_as_path_is_dropped_for_loop_prevention() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let other = addr("10.0.0.2");
    let _source_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let mut other_rx = register_peer(&mut rib, other, false, addr("10.0.0.253"));

    rib.handle_update(
        source,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65002, 65000, 65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );

    assert_eq!(recv_all(&mut other_rx), []);
}

#[test]
fn withdrawal_removes_route_and_notifies_downstream_peers() {
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

    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &UpdateMessage {
            withdrawn_routes: vec!["5.5.5.0/24".parse().unwrap()],
            ..empty_update()
        },
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut observer_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Withdraw(prefix("5.5.5.0/24"), false, None)]
    );
}

#[test]
fn peer_disconnected_withdraws_every_route_it_contributed() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let observer = addr("10.0.0.2");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["5.5.5.0/24", "6.6.6.0/24"], vec![65099], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );
    let _ = recv_all(&mut observer_rx);

    rib.peer_disconnected(peer, Disconnect::Transport);

    let mut updates = recv_all(&mut observer_rx);
    updates.sort_by_key(|u| match u {
        OutboundUpdate::Withdraw(p, _, _) => p.to_string(),
        OutboundUpdate::Announce(a) => a.prefix.to_string(),
        OutboundUpdate::AnnounceEvpn(_)
        | OutboundUpdate::WithdrawEvpn(_)
        | OutboundUpdate::RefreshMarker { .. }
        | OutboundUpdate::EndOfRib(_)
        | OutboundUpdate::AnnounceFlowspec(_)
        | OutboundUpdate::WithdrawFlowspec(..)
        | OutboundUpdate::AnnounceVpn(_)
        | OutboundUpdate::WithdrawVpn(_)
        | OutboundUpdate::AnnounceRtc(_)
        | OutboundUpdate::WithdrawRtc(_)
        | OutboundUpdate::AnnounceVpnFlowspec(..)
        | OutboundUpdate::WithdrawVpnFlowspec(..) => String::new(),
    });
    assert_eq!(
        updates,
        vec![
            OutboundUpdate::Withdraw(prefix("5.5.5.0/24"), false, None),
            OutboundUpdate::Withdraw(prefix("6.6.6.0/24"), false, None),
        ]
    );
}

#[test]
fn peer_with_no_local_address_is_never_eligible_for_self_address() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let (tx, mut rx) = test_channel();
    rib.peer_established(
        peer,
        false,
        None,
        all_afs(),
        false,
        None,
        false,
        false,
        HashSet::new(),
        accept_all_policy(),
        tx,
    );

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

    assert_eq!(recv_all(&mut rx), []);
}

#[test]
fn redistribute_full_matching_current_state_is_a_no_op() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
    let _ = recv_all(&mut rx);

    // A reconnect-triggered Full with the exact same prefix set: no
    // touched prefixes, so no new sends.
    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
    assert_eq!(recv_all(&mut rx), []);
}

#[test]
fn redistribute_remove_of_absent_prefix_is_a_no_op() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));

    rib.apply_redistribute_update(RedistributeUpdate::Remove(prefix("10.10.10.0/24")));
    assert_eq!(recv_all(&mut rx), []);
}

#[test]
fn newly_established_peer_gets_full_initial_advertisement_of_loc_rib() {
    let mut rib = new_rib(65000);
    let first = addr("10.0.0.1");
    let _rx_first = register_peer(&mut rib, first, false, addr("10.0.0.254"));

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

    // A second peer joining afterward should get the existing route
    // immediately, without needing a fresh redistribute push.
    let second = addr("10.0.0.2");
    let mut rx_second = register_peer(&mut rib, second, false, addr("10.0.0.253"));

    let updates = recv_all(&mut rx_second);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("192.168.1.0/24"),
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
fn ipv6_redistributed_route_is_announced_to_a_dual_stack_peer() {
    let mut rib = new_rib(65000);
    let peer = addr("2001:db8::1");
    let mut rx = register_mp_peer(&mut rib, peer, false, addr("2001:db8::254"), all_afs());

    rib.apply_redistribute_update(full_update(vec![("2001:db8:1::/48", "2001:db8::9")]));

    let updates = recv_all(&mut rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("2001:db8:1::/48"),
            as_path: vec![65000].into(),
            next_hop: addr("2001:db8::254"),
            local_pref: None,
            med: None,
            origin: message::Origin::Igp,
            use_mp: true,
        })]
    );
}

#[test]
fn peer_only_negotiated_ipv4_never_gets_an_ipv6_prefix() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_mp_peer(
        &mut rib,
        peer,
        false,
        addr("10.0.0.254"),
        [AddressFamily::Ipv4Unicast].into_iter().collect(),
    );

    rib.apply_redistribute_update(full_update(vec![("2001:db8:1::/48", "2001:db8::9")]));

    assert_eq!(recv_all(&mut rx), []);
}

#[test]
fn cross_family_next_hop_self_uses_transport_local_address() {
    // RFC 8950: an IPv6-transport peer carrying IPv4 unicast still gets
    // next-hop-self rewritten to its own (IPv6) session-local address.
    let mut rib = new_rib(65000);
    let peer = addr("2001:db8::1");
    let mut rx = register_mp_peer(
        &mut rib,
        peer,
        false,
        addr("2001:db8::254"),
        [AddressFamily::Ipv4Unicast].into_iter().collect(),
    );

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

    let updates = recv_all(&mut rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("192.168.1.0/24"),
            as_path: vec![65000].into(),
            next_hop: addr("2001:db8::254"),
            local_pref: None,
            med: None,
            origin: message::Origin::Igp,
            use_mp: true,
        })]
    );
}

#[test]
fn mp_peer_ipv4_withdrawal_is_marked_use_mp() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_mp_peer(&mut rib, peer, false, addr("10.0.0.254"), all_afs());

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
    let _ = recv_all(&mut rx);
    rib.apply_redistribute_update(RedistributeUpdate::Remove(prefix("192.168.1.0/24")));

    let updates = recv_all(&mut rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Withdraw(
            prefix("192.168.1.0/24"),
            true,
            None
        )]
    );
}

// --- RFC 4456 route reflection ---

#[test]
fn route_reflector_reflects_ibgp_route_from_non_client_to_client() {
    let router_id = v4("1.1.1.1");
    let cluster_id = v4("9.9.9.9");
    let mut rib = new_rib_with_identity(65000, router_id, cluster_id);
    let source = addr("10.0.0.1"); // plain iBGP peer, not a client
    let client = addr("10.0.0.2"); // route-reflector client
    let _source_rx = register_peer(&mut rib, source, true, addr("10.0.0.254"));
    let mut client_rx = register_peer_full(
        &mut rib,
        client,
        true,
        addr("10.0.0.253"),
        true,
        false,
        HashSet::new(),
    );

    rib.handle_update(
        source,
        true,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut client_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: Some(v4("192.0.2.1")),
            cluster_list: vec![cluster_id],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            path_id: None,
            prefix: prefix("1.2.3.0/24"),
            as_path: vec![].into(),
            next_hop: addr("10.0.0.1"),
            local_pref: Some(100),
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn route_reflector_reflects_ibgp_route_from_client_to_non_client() {
    let router_id = v4("1.1.1.1");
    let cluster_id = v4("9.9.9.9");
    let mut rib = new_rib_with_identity(65000, router_id, cluster_id);
    let client = addr("10.0.0.1"); // route-reflector client (source)
    let other = addr("10.0.0.2"); // plain iBGP peer, not a client
    let _client_rx = register_peer_full(
        &mut rib,
        client,
        true,
        addr("10.0.0.254"),
        true,
        false,
        HashSet::new(),
    );
    let mut other_rx = register_peer(&mut rib, other, true, addr("10.0.0.253"));

    rib.handle_update(
        client,
        true,
        v4("192.0.2.2"),
        &ebgp_update(vec!["4.5.6.0/24"], vec![], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut other_rx);
    assert_eq!(
        updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: Some(v4("192.0.2.2")),
            cluster_list: vec![cluster_id],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            path_id: None,
            prefix: prefix("4.5.6.0/24"),
            as_path: vec![].into(),
            next_hop: addr("10.0.0.1"),
            local_pref: Some(100),
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn inbound_update_with_own_cluster_id_in_cluster_list_is_dropped() {
    let router_id = v4("1.1.1.1");
    let cluster_id = v4("9.9.9.9");
    let mut rib = new_rib_with_identity(65000, router_id, cluster_id);
    let source = addr("10.0.0.1");
    let observer = addr("10.0.0.2");
    let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.253"));

    let mut update = ebgp_update(vec!["7.8.9.0/24"], vec![], "10.0.0.1");
    update.attributes.as_mut().unwrap().cluster_list = vec![cluster_id];

    rib.handle_update(source, true, v4("192.0.2.1"), &update, &nos_rpl::ACCEPT_ALL);

    assert_eq!(recv_all(&mut observer_rx), []);
}

#[test]
fn inbound_update_with_own_router_id_as_originator_id_is_dropped() {
    let router_id = v4("1.1.1.1");
    let cluster_id = v4("9.9.9.9");
    let mut rib = new_rib_with_identity(65000, router_id, cluster_id);
    let source = addr("10.0.0.1");
    let observer = addr("10.0.0.2");
    let mut observer_rx = register_peer(&mut rib, observer, true, addr("10.0.0.253"));

    let mut update = ebgp_update(vec!["7.8.9.0/24"], vec![], "10.0.0.1");
    update.attributes.as_mut().unwrap().originator_id = Some(router_id);

    rib.handle_update(source, true, v4("192.0.2.1"), &update, &nos_rpl::ACCEPT_ALL);

    assert_eq!(recv_all(&mut observer_rx), []);
}

// --- RFC 7947 route server ---

#[test]
fn route_server_client_gets_no_as_path_prepend_but_plain_ebgp_peer_does() {
    let mut rib = new_rib(65000);
    let plain_peer = addr("10.0.0.1");
    let rs_client = addr("10.0.0.2");
    let mut plain_rx = register_peer(&mut rib, plain_peer, false, addr("10.0.0.254"));
    let mut rs_rx = register_peer_full(
        &mut rib,
        rs_client,
        false,
        addr("10.0.0.253"),
        false,
        true,
        HashSet::new(),
    );

    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

    let plain_updates = recv_all(&mut plain_rx);
    assert_eq!(
        plain_updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("192.168.1.0/24"),
            as_path: vec![65000].into(),
            next_hop: addr("10.0.0.254"),
            local_pref: None,
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );

    let rs_updates = recv_all(&mut rs_rx);
    assert_eq!(
        rs_updates,
        vec![OutboundUpdate::Announce(AdvertisedRoute {
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: Vec::new(),
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: None,
            prefix: prefix("192.168.1.0/24"),
            as_path: vec![].into(), // route-server-client: transparent, no local-asn prepend
            next_hop: addr("10.0.0.253"),
            local_pref: None,
            med: None,
            origin: message::Origin::Igp,
            use_mp: false,
        })]
    );
}

#[test]
fn push_snapshot_includes_peer_learned_route_with_next_hop() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.9"),
        &nos_rpl::ACCEPT_ALL,
    );

    let (_, routes) = rib.push_snapshot();
    assert_eq!(
        routes.get(&prefix("1.2.3.0/24")),
        Some(&(vec![addr("10.0.0.9")], None, false))
    );
}

#[test]
fn push_snapshot_excludes_local_origin_redistributed_route() {
    let mut rib = new_rib(65000);
    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));

    let (_, routes) = rib.push_snapshot();
    assert!(!routes.contains_key(&prefix("192.168.1.0/24")));
}

#[test]
fn push_snapshot_reflects_routing_table_after_set() {
    let mut rib = new_rib(65000);
    assert_eq!(rib.push_snapshot().0, None);

    rib.set_routing_table(Some("rt1".to_string()));
    assert_eq!(rib.push_snapshot().0, Some("rt1".to_string()));
}

#[test]
fn flapping_route_is_suppressed_then_released_after_decay() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    // Ceiling 1500 = suppress, so two flaps suppress; decays under 750 in ~1s.
    rib.set_peer_damping(
        peer,
        Some(BgpDamping {
            half_life: 1,
            reuse: 750,
            suppress: 1500,
            max_suppress: 1,
        }),
    );
    let p = prefix("1.2.3.0/24");
    let announce = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
    let withdraw = UpdateMessage {
        withdrawn_routes: vec!["1.2.3.0/24".parse().unwrap()],
        ..empty_update()
    };
    for _ in 0..2 {
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &announce,
            &nos_rpl::ACCEPT_ALL,
        );
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &withdraw,
            &nos_rpl::ACCEPT_ALL,
        );
    }
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &announce,
        &nos_rpl::ACCEPT_ALL,
    );
    assert!(rib.damping.is_suppressed(peer, &p));
    assert!(
        !rib.push_snapshot().1.contains_key(&p),
        "suppressed route in loc-rib"
    );

    std::thread::sleep(std::time::Duration::from_millis(1100));
    rib.damping_tick();
    assert!(
        rib.push_snapshot().1.contains_key(&p),
        "released route missing"
    );
}

#[test]
fn identical_readvertisement_is_not_a_flap() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.set_peer_damping(
        peer,
        Some(BgpDamping {
            half_life: 900,
            reuse: 750,
            suppress: 1000,
            max_suppress: 3600,
        }),
    );
    let announce = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
    for _ in 0..5 {
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &announce,
            &nos_rpl::ACCEPT_ALL,
        );
    }
    assert!(!rib.damping.is_suppressed(peer, &prefix("1.2.3.0/24")));
    assert!(rib.push_snapshot().1.contains_key(&prefix("1.2.3.0/24")));
}

#[test]
fn identical_reannouncement_is_not_repropagated() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let mut observer_rx = register_peer(&mut rib, addr("10.0.0.2"), false, addr("10.0.0.253"));
    let announce = ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1");
    let send = |rib: &mut BgpRib| {
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &announce,
            &nos_rpl::ACCEPT_ALL,
        );
    };
    send(&mut rib);
    assert_eq!(recv_all(&mut observer_rx).len(), 1);
    let age = rib.loc_rib[&prefix("1.2.3.0/24")].received_at;
    send(&mut rib);
    assert_eq!(recv_all(&mut observer_rx), vec![]);
    assert_eq!(rib.loc_rib[&prefix("1.2.3.0/24")].received_at, age);
}

#[test]
fn prefix_counters_match_a_recount_through_every_mutation() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let accept = &nos_rpl::ACCEPT_ALL;
    let step = |rib: &mut BgpRib, u: &UpdateMessage, policy: &CompiledPolicy, want| {
        rib.handle_update(peer, false, v4("192.0.2.1"), u, policy);
        assert_eq!(rib.accepted_prefixes(peer), recount(rib, peer));
        assert_eq!(rib.accepted_prefixes(peer), want);
    };
    let v4s = ebgp_update(vec!["1.0.0.0/24", "2.0.0.0/24"], vec![65001], "10.0.0.1");
    let v6s = v6_update(vec!["2001:db8:1::/48", "2001:db8:2::/48"]);
    step(&mut rib, &v4s, accept, [2, 0, 0]);
    step(&mut rib, &v6s, accept, [2, 2, 0]);
    // Re-announcing is not a new prefix.
    step(&mut rib, &v4s, accept, [2, 2, 0]);
    step(&mut rib, &v6s, accept, [2, 2, 0]);
    let withdraw = UpdateMessage {
        withdrawn_routes: vec!["1.0.0.0/24".parse().unwrap()],
        mp_unreach: vec![message::MpUnreachNlri {
            afi: 2,
            safi: 1,
            withdrawn: vec![prefix("2001:db8:1::/48")],
            withdrawn_path_ids: vec![],
            evpn: vec![],
            flowspec: Vec::new(),
            flowspec_vpn: Vec::new(),
            vpn: Vec::new(),
            rtc: Vec::new(),
        }],
        ..empty_update()
    };
    step(&mut rib, &withdraw, accept, [1, 1, 0]);
    // An import policy now rejecting a held route removes it.
    step(
        &mut rib,
        &v6_update(vec!["2001:db8:2::/48"]),
        &nos_rpl::DENY_ALL,
        [1, 0, 0],
    );
    step(&mut rib, &v6s, accept, [1, 2, 0]);
    // RFC 7313: a refresh that re-announces nothing purges everything.
    rib.begin_refresh_in(peer, AddressFamily::Ipv6Unicast);
    rib.end_refresh_in(peer, AddressFamily::Ipv6Unicast);
    assert_eq!(rib.accepted_prefixes(peer), [1, 0, 0]);
    assert_eq!(rib.accepted_prefixes(peer), recount(&rib, peer));
    rib.peer_disconnected(peer, Disconnect::Transport);
    assert_eq!(rib.accepted_prefixes(peer), [0, 0, 0]);
}

/// RFC 4724 §4.2 vs RFC 8538 §4.1: a second drop before End-of-RIB
/// deletes what is still stale without N, keeps it with N.
#[test]
fn consecutive_restarts_keep_stale_routes_only_with_n() {
    for n in [false, true] {
        let cap = gr(n, &[(AddressFamily::Ipv4Unicast, true)]);
        let (mut rib, peer, mut observer) = gr_rib(Some(cap));
        rib.peer_disconnected(peer, Disconnect::Transport);
        let _rx = register_gr_peer(&mut rib, peer);
        let _ = recv_all(&mut observer);
        rib.peer_disconnected(peer, Disconnect::Transport);
        let gone = withdrawn(&mut observer);
        if n {
            assert_eq!(gone, [] as [String; 0]);
            assert_eq!(rib.stale_count(peer), 2);
        } else {
            assert_eq!(gone, ["1.0.0.0/24", "2.0.0.0/24"]);
        }
    }
}

mod well_known {
    use super::*;
    use message::{COMMUNITY_NO_ADVERTISE, COMMUNITY_NO_EXPORT, COMMUNITY_NO_EXPORT_SUBCONFED};

    const SRC: &str = "10.0.0.1";

    #[derive(Clone, Copy, Debug)]
    enum Dest {
        Ibgp,
        Ebgp,
        OtherMember,
        RrClient,
        RsClient,
    }

    fn reg(
        rib: &mut BgpRib,
        ip: &str,
        d: Dest,
        export: Arc<CompiledPolicy>,
    ) -> mpsc::Receiver<OutboundUpdate> {
        if matches!(d, Dest::OtherMember) {
            rib.set_peer_confed(addr(ip), true);
        }
        let (tx, rx) = test_channel();
        rib.peer_established(
            addr(ip),
            matches!(d, Dest::Ibgp | Dest::RrClient),
            Some(addr("10.0.0.254")),
            all_afs(),
            false,
            None,
            matches!(d, Dest::RrClient),
            matches!(d, Dest::RsClient),
            HashSet::new(),
            export,
            tx,
        );
        rx
    }

    fn tagged(communities: &[u32]) -> UpdateMessage {
        let mut u = ebgp_update(vec!["1.2.3.0/24"], vec![65001], SRC);
        u.attributes.as_mut().unwrap().communities = communities.to_vec();
        u
    }

    fn pol(src: &str) -> Arc<CompiledPolicy> {
        Arc::new(nos_rpl::compile(src, &nos_rpl::Symbols::EMPTY).unwrap())
    }

    /// Learn `communities` from an eBGP source and report whether `d` got it.
    fn sent(confederation: bool, d: Dest, communities: &[u32]) -> bool {
        let mut rib = new_rib(65101);
        if confederation {
            rib.set_confederation(Some(65100));
        }
        let _src = reg(&mut rib, SRC, Dest::Ebgp, accept_all_policy());
        let mut rx = reg(&mut rib, "10.0.0.2", d, accept_all_policy());
        rib.handle_update(
            addr(SRC),
            false,
            v4("9.9.9.9"),
            &tagged(communities),
            &accept_all_policy(),
        );
        announced(&mut rx, "1.2.3.0/24").is_some()
    }

    #[test]
    fn matrix() {
        use Dest::{Ebgp, Ibgp, OtherMember, RrClient, RsClient};
        // (community, confederation?, dest, sent?)
        let cases = [
            (COMMUNITY_NO_ADVERTISE, false, Ibgp, false),
            (COMMUNITY_NO_ADVERTISE, false, Ebgp, false),
            (COMMUNITY_NO_ADVERTISE, true, OtherMember, false),
            (COMMUNITY_NO_ADVERTISE, false, RrClient, false),
            (COMMUNITY_NO_ADVERTISE, false, RsClient, false),
            (COMMUNITY_NO_EXPORT, false, Ibgp, true),
            (COMMUNITY_NO_EXPORT, false, Ebgp, false),
            (COMMUNITY_NO_EXPORT, true, Ebgp, false),
            (COMMUNITY_NO_EXPORT, true, OtherMember, true),
            (COMMUNITY_NO_EXPORT, false, RsClient, false),
            (COMMUNITY_NO_EXPORT_SUBCONFED, false, Ibgp, true),
            (COMMUNITY_NO_EXPORT_SUBCONFED, false, Ebgp, false),
            (COMMUNITY_NO_EXPORT_SUBCONFED, true, Ebgp, false),
            (COMMUNITY_NO_EXPORT_SUBCONFED, true, OtherMember, false),
        ];
        for (c, confed, d, want) in cases {
            assert_eq!(sent(confed, d, &[c]), want, "{c:#x} confed={confed} {d:?}");
        }
    }

    #[test]
    fn other_communities_are_unaffected() {
        for c in [0xFFFF_029A, (65001 << 16) | 100] {
            assert!(sent(false, Dest::Ebgp, &[c]));
        }
        assert!(sent(false, Dest::Ebgp, &[]));
    }

    #[test]
    fn locally_originated_route_tagged_by_export_policy_is_sent() {
        let mut rib = new_rib(65000);
        let mut rx = reg(
            &mut rib,
            "10.0.0.2",
            Dest::Ebgp,
            pol("this.bgp.communities.add(65535:65281)\naccept\n"),
        );
        rib.apply_redistribute_update(full_update(vec![("198.51.100.0/24", "10.9.9.9")]));
        assert!(announced(&mut rx, "198.51.100.0/24").is_some());
    }

    #[test]
    fn import_policy_can_lift_it_export_policy_cannot_add_or_lift() {
        // import policy strips -> sent
        let mut rib = new_rib(65000);
        let _src = reg(&mut rib, SRC, Dest::Ebgp, accept_all_policy());
        let mut rx = reg(&mut rib, "10.0.0.2", Dest::Ebgp, accept_all_policy());
        rib.handle_update(
            addr(SRC),
            false,
            v4("9.9.9.9"),
            &tagged(&[COMMUNITY_NO_EXPORT]),
            &pol("this.bgp.communities.remove(65535:65281)\naccept\n"),
        );
        assert!(announced(&mut rx, "1.2.3.0/24").is_some());

        // export policy adds NO_EXPORT to a received route -> still sent
        let mut rib = new_rib(65000);
        let _src = reg(&mut rib, SRC, Dest::Ebgp, accept_all_policy());
        let mut rx = reg(
            &mut rib,
            "10.0.0.2",
            Dest::Ebgp,
            pol("this.bgp.communities.add(65535:65281)\naccept\n"),
        );
        rib.handle_update(
            addr(SRC),
            false,
            v4("9.9.9.9"),
            &tagged(&[]),
            &accept_all_policy(),
        );
        assert!(announced(&mut rx, "1.2.3.0/24").is_some());

        // export policy removes it -> still blocked
        let mut rib = new_rib(65000);
        let _src = reg(&mut rib, SRC, Dest::Ebgp, accept_all_policy());
        let mut rx = reg(
            &mut rib,
            "10.0.0.2",
            Dest::Ebgp,
            pol("this.bgp.communities.remove(65535:65281)\naccept\n"),
        );
        rib.handle_update(
            addr(SRC),
            false,
            v4("9.9.9.9"),
            &tagged(&[COMMUNITY_NO_EXPORT]),
            &accept_all_policy(),
        );
        assert!(announced(&mut rx, "1.2.3.0/24").is_none());
    }

    #[test]
    fn relearned_with_no_export_is_withdrawn_from_ebgp_only() {
        let mut rib = new_rib(65000);
        let _src = reg(&mut rib, SRC, Dest::Ebgp, accept_all_policy());
        let mut ebgp = reg(&mut rib, "10.0.0.2", Dest::Ebgp, accept_all_policy());
        let mut ibgp = reg(&mut rib, "10.0.0.3", Dest::Ibgp, accept_all_policy());
        rib.handle_update(
            addr(SRC),
            false,
            v4("9.9.9.9"),
            &tagged(&[]),
            &accept_all_policy(),
        );
        assert!(announced(&mut ebgp, "1.2.3.0/24").is_some());
        recv_all(&mut ibgp);
        rib.handle_update(
            addr(SRC),
            false,
            v4("9.9.9.9"),
            &tagged(&[COMMUNITY_NO_EXPORT]),
            &accept_all_policy(),
        );
        assert!(recv_all(&mut ebgp)
            .iter()
            .any(|u| matches!(u, OutboundUpdate::Withdraw(p, ..) if *p == prefix("1.2.3.0/24"))));
        assert!(!recv_all(&mut ibgp)
            .iter()
            .any(|u| matches!(u, OutboundUpdate::Withdraw(..))));
    }

    #[test]
    fn route_refresh_replay_honours_it() {
        let mut rib = new_rib(65000);
        let _src = reg(&mut rib, SRC, Dest::Ebgp, accept_all_policy());
        let mut rx = reg(&mut rib, "10.0.0.2", Dest::Ebgp, accept_all_policy());
        rib.handle_update(
            addr(SRC),
            false,
            v4("9.9.9.9"),
            &tagged(&[]),
            &accept_all_policy(),
        );
        recv_all(&mut rx);
        rib.resend_all(addr("10.0.0.2"), AddressFamily::Ipv4Unicast, false);
        assert!(announced(&mut rx, "1.2.3.0/24").is_some(), "control");
        recv_all(&mut rx);
        rib.handle_update(
            addr(SRC),
            false,
            v4("9.9.9.9"),
            &tagged(&[COMMUNITY_NO_EXPORT]),
            &accept_all_policy(),
        );
        recv_all(&mut rx);
        rib.resend_all(addr("10.0.0.2"), AddressFamily::Ipv4Unicast, false);
        assert!(announced(&mut rx, "1.2.3.0/24").is_none());
    }

    #[test]
    fn add_path_peer_honours_it() {
        let mut rib = new_rib(65000);
        let _src = reg(&mut rib, SRC, Dest::Ebgp, accept_all_policy());
        let mut rx = register_peer_full(
            &mut rib,
            addr("10.0.0.3"),
            false,
            addr("10.0.0.252"),
            false,
            true,
            [AddressFamily::Ipv4Unicast].into_iter().collect(),
        );
        rib.handle_update(
            addr(SRC),
            false,
            v4("9.9.9.9"),
            &tagged(&[]),
            &accept_all_policy(),
        );
        assert!(announced(&mut rx, "1.2.3.0/24").is_some(), "control");
        rib.handle_update(
            addr(SRC),
            false,
            v4("9.9.9.9"),
            &tagged(&[COMMUNITY_NO_EXPORT]),
            &accept_all_policy(),
        );
        assert!(announced(&mut rx, "1.2.3.0/24").is_none());
    }
}
