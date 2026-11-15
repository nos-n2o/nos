use super::*;

#[test]
fn propagate_add_path_sends_distinct_path_ids_and_withdraws_on_source_disconnect() {
    let mut rib = new_rib(65000);
    let peer_a = addr("10.0.0.1");
    let peer_b = addr("10.0.0.2");
    let rs_client = addr("10.0.0.3");

    let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
    let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
    let mut rs_rx = register_peer_full(
        &mut rib,
        rs_client,
        false,
        addr("10.0.0.252"),
        false,
        true,
        [AddressFamily::Ipv4Unicast].into_iter().collect(),
    );

    rib.handle_update(
        peer_a,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );
    rib.handle_update(
        peer_b,
        false,
        v4("192.0.2.2"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65002], "10.0.0.2"),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut rs_rx);
    // Each source's own path reaches the rs-client transparently (no
    // local-asn prepend), each carrying its own distinct, stable path id
    // — alongside whichever single path the ordinary fan-out also sends
    // (with no path id at all).
    let id_for_a = updates
        .iter()
        .find_map(|u| match u {
            OutboundUpdate::Announce(r) if r.as_path == vec![65001] => r.path_id,
            _ => None,
        })
        .expect("peer_a's path reached the rs-client with a path id");
    let id_for_b = updates
        .iter()
        .find_map(|u| match u {
            OutboundUpdate::Announce(r) if r.as_path == vec![65002] => r.path_id,
            _ => None,
        })
        .expect("peer_b's path reached the rs-client with a path id");
    assert_ne!(id_for_a, id_for_b);

    // Disconnecting peer_a withdraws only its path id; peer_b's stays.
    rib.peer_disconnected(peer_a, Disconnect::Transport);
    let after = recv_all(&mut rs_rx);
    let withdrawn_ids: Vec<Option<u32>> = after
        .iter()
        .filter_map(|u| match u {
            OutboundUpdate::Withdraw(_, _, id) if id.is_some() => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(withdrawn_ids, vec![Some(id_for_a)]);
}

#[test]
fn route_server_client_without_add_path_gets_only_ordinary_single_best() {
    let mut rib = new_rib(65000);
    let peer_a = addr("10.0.0.1");
    let peer_b = addr("10.0.0.2");
    let rs_client_no_add_path = addr("10.0.0.3");

    let _rx_a = register_peer(&mut rib, peer_a, false, addr("10.0.0.254"));
    let _rx_b = register_peer(&mut rib, peer_b, false, addr("10.0.0.253"));
    let mut rs_rx = register_peer_full(
        &mut rib,
        rs_client_no_add_path,
        false,
        addr("10.0.0.252"),
        false,
        true,
        HashSet::new(), // is_rs_client but no negotiated add_path_afs
    );

    rib.handle_update(
        peer_a,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );
    rib.handle_update(
        peer_b,
        false,
        v4("192.0.2.2"),
        &ebgp_update(vec!["1.2.3.0/24"], vec![65002], "10.0.0.2"),
        &nos_rpl::ACCEPT_ALL,
    );

    let updates = recv_all(&mut rs_rx);
    assert_ne!(updates, []);
    // No path-id'd traffic at all — propagate_add_path never runs for a
    // family this peer didn't negotiate ADD-PATH for.
    assert!(updates.iter().all(|u| match u {
        OutboundUpdate::Announce(r) => r.path_id.is_none(),
        OutboundUpdate::Withdraw(_, _, id) => id.is_none(),
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
        | OutboundUpdate::WithdrawVpnFlowspec(_) => true,
    }));
    // Still transparent (no AS_PATH prepend) — that's governed by
    // is_rs_client alone, independent of ADD-PATH negotiation. Only
    // peer_a's route ever wins the ordinary single-best election (lower
    // router-id), so that's the one path this peer ever sees.
    assert!(updates.iter().any(|u| matches!(
        u,
        OutboundUpdate::Announce(r) if r.as_path == vec![65001]
    )));
}

fn path_withdraw(prefix: &str, id: u32) -> UpdateMessage {
    UpdateMessage {
        withdrawn_routes: vec![prefix.parse().unwrap()],
        withdrawn_path_ids: vec![id],
        ..empty_update()
    }
}

#[test]
fn add_path_keeps_every_path_and_withdraws_one_by_id() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let learn = |rib: &mut BgpRib, u: &UpdateMessage| {
        rib.handle_update(peer, false, v4("192.0.2.1"), u, &nos_rpl::ACCEPT_ALL);
    };
    let best_med = |rib: &BgpRib| rib.loc_rib.get(&prefix("203.0.113.0/24")).map(|r| r.med);
    learn(
        &mut rib,
        &path_update("203.0.113.0/24", 1, "10.0.0.1", Some(50)),
    );
    learn(
        &mut rib,
        &path_update("203.0.113.0/24", 2, "10.0.0.11", Some(10)),
    );
    assert_eq!(held_ids(&rib, peer, "203.0.113.0/24"), [1, 2]);
    assert_eq!(best_med(&rib), Some(Some(10)));
    // Maximum-prefix counts paths.
    assert_eq!(rib.accepted_prefixes(peer), [2, 0, 0]);
    assert_eq!(rib.accepted_prefixes(peer), recount(&rib, peer));

    // RFC 7911 §5: an unknown path id is ignored.
    learn(&mut rib, &path_withdraw("203.0.113.0/24", 7));
    assert_eq!(held_ids(&rib, peer, "203.0.113.0/24"), [1, 2]);

    // Withdrawing path 2 keeps path 1, which becomes the best path.
    learn(&mut rib, &path_withdraw("203.0.113.0/24", 2));
    assert_eq!(held_ids(&rib, peer, "203.0.113.0/24"), [1]);
    assert_eq!(best_med(&rib), Some(Some(50)));
    assert_eq!(rib.accepted_prefixes(peer), [1, 0, 0]);

    // A re-announcement under the same id replaces the path in place.
    learn(
        &mut rib,
        &path_update("203.0.113.0/24", 1, "10.0.0.1", Some(70)),
    );
    assert_eq!(held_ids(&rib, peer, "203.0.113.0/24"), [1]);
    assert_eq!(best_med(&rib), Some(Some(70)));
}

#[test]
fn two_paths_of_one_peer_break_the_tie_on_path_id_and_form_multipath() {
    let mut rib = new_rib(65000);
    rib.set_maximum_paths(Some(2));
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, true, addr("10.0.0.254"));
    // iBGP, so step 8 (oldest eBGP route) doesn't decide; everything
    // else ties, so step 10 falls to the lower path id.
    for (id, nh) in [(5, "10.0.0.5"), (3, "10.0.0.3")] {
        rib.handle_update(
            peer,
            true,
            v4("192.0.2.1"),
            &path_update("203.0.113.0/24", id, nh, None),
            &nos_rpl::ACCEPT_ALL,
        );
    }
    let p = prefix("203.0.113.0/24");
    assert_eq!(rib.loc_rib[&p].next_hop, Some(addr("10.0.0.3")));
    assert_eq!(rib.multipaths[&p], [addr("10.0.0.3"), addr("10.0.0.5")]);
}

#[test]
fn treat_as_withdraw_removes_only_the_announced_path_ids() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    for id in [1, 2] {
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &path_update("203.0.113.0/24", id, "10.0.0.1", None),
            &nos_rpl::ACCEPT_ALL,
        );
    }
    // Path 1 again, now looped through our own AS.
    let looped = UpdateMessage {
        nlri_path_ids: vec![1],
        ..update_with(
            "203.0.113.0/24",
            vec![65001, 65000],
            "10.0.0.1",
            message::Origin::Igp,
            None,
        )
    };
    rib.handle_update(peer, false, v4("192.0.2.1"), &looped, &nos_rpl::ACCEPT_ALL);
    assert_eq!(held_ids(&rib, peer, "203.0.113.0/24"), [2]);
}

#[test]
fn add_path_send_peers_never_get_a_path_without_an_id() {
    let mut rib = new_rib(65000);
    let source = addr("10.0.0.1");
    let _src_rx = register_peer(&mut rib, source, false, addr("10.0.0.254"));
    let v4_only: HashSet<AddressFamily> = HashSet::from([AddressFamily::Ipv4Unicast]);
    // A route-server client gets the best path through its ADD-PATH
    // view only; an ordinary peer gets it under path id 1.
    let mut rs_rx = register_peer_full(
        &mut rib,
        addr("10.0.0.2"),
        false,
        addr("10.0.0.253"),
        false,
        true,
        v4_only.clone(),
    );
    let mut plain_rx = register_peer_full(
        &mut rib,
        addr("10.0.0.3"),
        false,
        addr("10.0.0.252"),
        false,
        false,
        v4_only,
    );
    let send = |rib: &mut BgpRib, u: &UpdateMessage| {
        rib.handle_update(source, false, v4("192.0.2.1"), u, &nos_rpl::ACCEPT_ALL);
    };
    send(
        &mut rib,
        &ebgp_update(vec!["9.9.9.0/24"], vec![65001], "10.0.0.1"),
    );
    send(
        &mut rib,
        &UpdateMessage {
            withdrawn_routes: vec!["9.9.9.0/24".parse().unwrap()],
            ..empty_update()
        },
    );
    let ids = |updates: Vec<OutboundUpdate>| -> Vec<(bool, Option<u32>)> {
        updates
            .into_iter()
            .filter_map(|u| match u {
                OutboundUpdate::Announce(a) => Some((true, a.path_id)),
                OutboundUpdate::Withdraw(_, _, id) => Some((false, id)),
                _ => None,
            })
            .collect()
    };
    let rs = ids(recv_all(&mut rs_rx));
    assert_eq!(rs.len(), 2, "{rs:?}");
    assert!(rs.iter().all(|(_, id)| id.is_some()), "{rs:?}");
    assert_eq!(
        ids(recv_all(&mut plain_rx)),
        [(true, Some(1)), (false, Some(1))]
    );
}

/// Registers an ADD-PATH send (ipv4) peer with `policy` as its export
/// policy and `count` as its `add_path_send_count` (`None`: every path).
fn add_path_peer(
    rib: &mut BgpRib,
    peer: &str,
    is_ibgp: bool,
    is_rs_client: bool,
    count: Option<usize>,
    policy: Arc<CompiledPolicy>,
) -> mpsc::Receiver<OutboundUpdate> {
    rib.set_peer_add_path_send_count(addr(peer), count);
    let (tx, rx) = test_channel();
    rib.peer_established(
        addr(peer),
        is_ibgp,
        Some(addr("10.0.0.254")),
        all_afs(),
        false,
        None,
        false,
        is_rs_client,
        HashSet::from([AddressFamily::Ipv4Unicast]),
        policy,
        tx,
    );
    rx
}

/// `(announce, path id, med)` of every unicast update, in order.
fn path_events(rx: &mut mpsc::Receiver<OutboundUpdate>) -> Vec<(bool, u32, Option<u32>)> {
    recv_all(rx)
        .into_iter()
        .filter_map(|u| match u {
            OutboundUpdate::Announce(a) => Some((true, a.path_id.expect("an id"), a.med)),
            OutboundUpdate::Withdraw(_, _, id) => Some((false, id.expect("an id"), None)),
            _ => None,
        })
        .collect()
}

const AP_PREFIX: &str = "203.0.113.0/24";

const AP_PEERS: [&str; 3] = ["10.0.0.1", "10.0.0.2", "10.0.0.3"];

/// eBGP peer `i` of `AP_PEERS` announces `AP_PREFIX` (AS 65001, its own
/// next hop, `med`) — MED decides between them.
fn ap_announce(rib: &mut BgpRib, i: usize, med: u32) {
    let u = update_with(
        AP_PREFIX,
        vec![65001],
        AP_PEERS[i],
        message::Origin::Igp,
        Some(med),
    );
    rib.handle_update(
        addr(AP_PEERS[i]),
        false,
        v4(AP_PEERS[i]),
        &u,
        &nos_rpl::ACCEPT_ALL,
    );
}

fn ap_withdraw(rib: &mut BgpRib, i: usize) {
    let u = UpdateMessage {
        withdrawn_routes: vec![AP_PREFIX.parse().unwrap()],
        ..empty_update()
    };
    rib.handle_update(
        addr(AP_PEERS[i]),
        false,
        v4(AP_PEERS[i]),
        &u,
        &nos_rpl::ACCEPT_ALL,
    );
}

fn ap_sources(rib: &mut BgpRib) -> Vec<mpsc::Receiver<OutboundUpdate>> {
    AP_PEERS
        .iter()
        .map(|p| register_peer(rib, addr(p), false, addr("10.0.0.250")))
        .collect()
}

#[test]
fn add_path_sends_the_best_n_with_stable_ids() {
    let mut rib = new_rib(65000);
    let _src = ap_sources(&mut rib);
    // An iBGP peer with the default count, 2.
    let mut d = add_path_peer(
        &mut rib,
        "10.0.0.9",
        true,
        false,
        Some(2),
        accept_all_policy(),
    );

    ap_announce(&mut rib, 0, 10);
    ap_announce(&mut rib, 1, 30);
    ap_announce(&mut rib, 2, 50);
    assert_eq!(
        path_events(&mut d),
        [(true, 1, Some(10)), (true, 2, Some(30))]
    );

    // P2 now ranks below P3: P3 takes P2's id in place, no withdrawal.
    ap_announce(&mut rib, 1, 60);
    assert_eq!(path_events(&mut d), [(true, 2, Some(50))]);

    // P1 gone: P2 is back in, under P1's freed id; P3 keeps id 2.
    ap_withdraw(&mut rib, 0);
    assert_eq!(path_events(&mut d), [(true, 1, Some(60))]);

    ap_withdraw(&mut rib, 1);
    ap_withdraw(&mut rib, 2);
    assert_eq!(path_events(&mut d), [(false, 1, None), (false, 2, None)]);

    // Never recycled once withdrawn: a fresh id.
    ap_announce(&mut rib, 0, 10);
    assert_eq!(path_events(&mut d), [(true, 3, Some(10))]);
}

#[test]
fn add_path_counts_only_paths_the_export_policy_lets_through() {
    let mut rib = new_rib(65000);
    let _src = ap_sources(&mut rib);
    let policy = nos_rpl::compile(
        "if this.bgp.next_hop == 10.0.0.1:\n    reject\naccept\n",
        &nos_rpl::Symbols::EMPTY,
    )
    .unwrap();
    let mut d = add_path_peer(&mut rib, "10.0.0.9", true, false, Some(2), Arc::new(policy));
    ap_announce(&mut rib, 0, 10);
    ap_announce(&mut rib, 1, 30);
    ap_announce(&mut rib, 2, 50);
    // The rejected best path doesn't use up a slot.
    assert_eq!(
        path_events(&mut d),
        [(true, 1, Some(30)), (true, 2, Some(50))]
    );

    // P2's new attributes are rejected (fix 4): its id is withdrawn, as
    // nothing is left to take it.
    let u = update_with(
        AP_PREFIX,
        vec![65001],
        "10.0.0.1",
        message::Origin::Igp,
        Some(30),
    );
    rib.handle_update(
        addr(AP_PEERS[1]),
        false,
        v4(AP_PEERS[1]),
        &u,
        &nos_rpl::ACCEPT_ALL,
    );
    assert_eq!(path_events(&mut d), [(false, 1, None)]);
}

#[test]
fn add_path_never_sends_a_peer_its_own_path_nor_ibgp_paths_to_a_non_client() {
    let mut rib = new_rib(65000);
    let _src = ap_sources(&mut rib);
    // An eBGP ADD-PATH peer that itself sends the best path.
    let mut e = add_path_peer(
        &mut rib,
        "10.0.0.8",
        false,
        false,
        Some(2),
        accept_all_policy(),
    );
    // A non-client iBGP ADD-PATH peer.
    let mut i = add_path_peer(
        &mut rib,
        "10.0.0.9",
        true,
        false,
        Some(2),
        accept_all_policy(),
    );
    let ibgp = addr("10.0.0.7");
    let _ibgp_rx = register_peer(&mut rib, ibgp, true, addr("10.0.0.250"));

    let u = update_with(
        AP_PREFIX,
        vec![65001],
        "10.0.0.8",
        message::Origin::Igp,
        Some(5),
    );
    rib.handle_update(
        addr("10.0.0.8"),
        false,
        v4("10.0.0.8"),
        &u,
        &nos_rpl::ACCEPT_ALL,
    );
    let u = update_with(
        AP_PREFIX,
        vec![65001],
        "10.0.0.7",
        message::Origin::Igp,
        Some(7),
    );
    rib.handle_update(ibgp, true, v4("10.0.0.7"), &u, &nos_rpl::ACCEPT_ALL);
    ap_announce(&mut rib, 0, 10);
    ap_announce(&mut rib, 1, 30);
    let nexthops = |rx: &mut mpsc::Receiver<OutboundUpdate>| -> Vec<IpAddr> {
        let mut hops: Vec<IpAddr> = recv_all(rx)
            .into_iter()
            .filter_map(|u| match u {
                OutboundUpdate::Announce(a) => Some(a.next_hop),
                _ => None,
            })
            .collect();
        hops.dedup();
        hops
    };
    // Its own (best) path never comes back and takes no slot: the iBGP
    // path and P1 fill both.
    assert_eq!(path_events(&mut e), [(true, 1, None), (true, 2, None)]);
    // The non-client iBGP peer never gets the iBGP-learned path (next
    // hop unchanged toward iBGP): the eBGP peer's path and P1.
    assert_eq!(nexthops(&mut i), [addr("10.0.0.8"), addr("10.0.0.1")]);
}

#[test]
fn add_path_route_server_client_count_caps_its_view() {
    let mut rib = new_rib(65000);
    let _src = ap_sources(&mut rib);
    let mut all = add_path_peer(&mut rib, "10.0.0.8", false, true, None, accept_all_policy());
    let mut two = add_path_peer(
        &mut rib,
        "10.0.0.9",
        false,
        true,
        Some(2),
        accept_all_policy(),
    );
    ap_announce(&mut rib, 0, 10);
    ap_announce(&mut rib, 1, 30);
    ap_announce(&mut rib, 2, 50);
    assert_eq!(path_events(&mut all).len(), 3);
    assert_eq!(
        path_events(&mut two),
        [(true, 1, Some(10)), (true, 2, Some(30))]
    );
}

#[test]
fn add_path_new_session_and_route_refresh_replay_the_top_n() {
    let mut rib = new_rib(65000);
    let _src = ap_sources(&mut rib);
    ap_announce(&mut rib, 0, 10);
    ap_announce(&mut rib, 1, 30);
    ap_announce(&mut rib, 2, 50);
    let mut d = add_path_peer(
        &mut rib,
        "10.0.0.9",
        true,
        false,
        Some(2),
        accept_all_policy(),
    );
    let top = [(true, 1, Some(10)), (true, 2, Some(30))];
    assert_eq!(path_events(&mut d), top);
    rib.resend_all(addr("10.0.0.9"), AddressFamily::Ipv4Unicast, false);
    assert_eq!(path_events(&mut d), top);
}

/// #722: walking `route_keys` through `crate::page` yields exactly `routes()`
/// (local first, then peers, then ADD-PATH ids), whatever the page size.
#[test]
fn paged_route_walk_equals_the_unpaged_listing() {
    let mut rib = new_rib(65000);
    let (p1, p2) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let _rx1 = register_peer(&mut rib, p1, false, addr("10.0.0.254"));
    let _rx2 = register_peer(&mut rib, p2, false, addr("10.0.0.253"));
    for id in [1, 2] {
        rib.handle_update(
            p1,
            false,
            v4("192.0.2.1"),
            &path_update("203.0.113.0/24", id, "10.0.0.1", Some(id)),
            &nos_rpl::ACCEPT_ALL,
        );
    }
    rib.handle_update(
        p2,
        false,
        v4("192.0.2.2"),
        &path_update("203.0.113.0/24", 1, "10.0.0.2", None),
        &nos_rpl::ACCEPT_ALL,
    );
    rib.apply_redistribute_update(full_update(vec![
        ("203.0.113.0/24", "10.0.0.9"),
        ("9.9.9.0/24", "10.0.0.9"),
    ]));
    let want = rib.routes();
    assert_eq!(want.len(), 5);
    for limit in [1, 2, 3, 5, 9] {
        let mut snap = crate::page::Snapshot::default();
        let (mut got, mut after) = (Vec::new(), None);
        loop {
            let (rows, next) = crate::page::page(
                &mut snap,
                &crate::page::Ask {
                    after: after.as_ref(),
                    limit,
                    budget: usize::MAX,
                    now: std::time::Instant::now(),
                },
                || rib.route_keys(),
                |k| rib.route_at(k),
                nos_proto::page::wire_len,
            );
            got.extend(rows);
            match next {
                Some(k) => after = Some(k),
                None => break,
            }
        }
        assert_eq!(got, want, "limit {limit}");
    }
    // A key that no longer exists yields no row.
    let gone = nos_proto::BgpRouteCursor {
        prefix: prefix("1.1.1.0/24"),
        peer: None,
        path_id: 0,
    };
    assert!(rib.route_at(&gone).is_none());
}
