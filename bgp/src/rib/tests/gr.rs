use super::*;

#[test]
fn resend_all_resends_loc_rib_filtered_to_one_family() {
    let mut rib = new_rib(65000);
    let v4_peer = addr("10.0.0.1");
    let v6_peer = addr("10.0.0.2");
    let mut v4_rx = register_mp_peer(
        &mut rib,
        v4_peer,
        false,
        addr("10.0.0.254"),
        [AddressFamily::Ipv4Unicast].into_iter().collect(),
    );
    let mut v6_rx = register_mp_peer(
        &mut rib,
        v6_peer,
        false,
        addr("2001:db8::fe"),
        [AddressFamily::Ipv6Unicast].into_iter().collect(),
    );

    rib.apply_redistribute_update(full_update(vec![
        ("192.168.1.0/24", "10.9.9.9"),
        ("2001:db8::/32", "2001:db8::1"),
    ]));
    // Drain the initial full-advertisement sends from registration/redistribution.
    recv_all(&mut v4_rx);
    recv_all(&mut v6_rx);

    rib.resend_all(v4_peer, AddressFamily::Ipv4Unicast, false);
    rib.resend_all(v6_peer, AddressFamily::Ipv6Unicast, false);

    let v4_updates = recv_all(&mut v4_rx);
    assert_eq!(v4_updates.len(), 1);
    assert!(matches!(
        &v4_updates[0],
        OutboundUpdate::Announce(adv) if adv.prefix == prefix("192.168.1.0/24")
    ));

    let v6_updates = recv_all(&mut v6_rx);
    assert_eq!(v6_updates.len(), 1);
    assert!(matches!(
        &v6_updates[0],
        OutboundUpdate::Announce(adv) if adv.prefix == prefix("2001:db8::/32")
    ));

    // Requesting the family a peer didn't negotiate is a silent no-op.
    rib.resend_all(v4_peer, AddressFamily::Ipv6Unicast, false);
    assert_eq!(recv_all(&mut v4_rx), []);
}

#[test]
fn enhanced_refresh_purges_unrefreshed_routes_at_eorr() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let policy = accept_all_policy();
    for p in ["192.0.2.0/24", "198.51.100.0/24"] {
        let u = update_with(p, vec![65001], "10.0.0.1", message::Origin::Igp, None);
        rib.handle_update(peer, false, v4("1.1.1.1"), &u, &policy);
    }
    let v4f = AddressFamily::Ipv4Unicast;
    rib.begin_refresh_in(peer, v4f);
    // Only one prefix is re-announced during the refresh.
    let u = update_with(
        "192.0.2.0/24",
        vec![65001],
        "10.0.0.1",
        message::Origin::Igp,
        None,
    );
    rib.handle_update(peer, false, v4("1.1.1.1"), &u, &policy);
    rib.end_refresh_in(peer, v4f);
    assert!(rib.adj_rib_in[&peer].contains_key(&prefix("192.0.2.0/24")));
    assert!(!rib.adj_rib_in[&peer].contains_key(&prefix("198.51.100.0/24")));
}

#[test]
fn enhanced_resend_is_bracketed_by_markers() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.apply_redistribute_update(full_update(vec![("192.168.1.0/24", "10.9.9.9")]));
    recv_all(&mut rx);
    rib.resend_all(peer, AddressFamily::Ipv4Unicast, true);
    let got = recv_all(&mut rx);
    assert!(matches!(
        got.as_slice(),
        [
            OutboundUpdate::RefreshMarker {
                subtype: message::REFRESH_BORR,
                ..
            },
            OutboundUpdate::Announce(_),
            OutboundUpdate::RefreshMarker {
                subtype: message::REFRESH_EORR,
                ..
            },
        ]
    ));
}

/// RFC 4724 §4.2: the families the peer listed (and negotiated) stay in
/// use, marked stale — nothing is withdrawn downstream, and the counters
/// still match — while an unlisted one is withdrawn. A re-announced
/// route loses its mark and End-of-RIB purges the rest.
#[test]
fn graceful_restart_keeps_listed_families_until_end_of_rib() {
    let ipv4 = (AddressFamily::Ipv4Unicast, true);
    let evpn = (AddressFamily::L2vpnEvpn, true);
    let (mut rib, peer, mut observer) = gr_rib(Some(gr(true, &[ipv4, evpn])));
    let _ = recv_all(&mut observer);

    rib.peer_disconnected(peer, Disconnect::Transport);
    assert_eq!(withdrawn(&mut observer), ["2001:db8:1::/48"]);
    assert_eq!(rib.accepted_prefixes(peer), [2, 0, 1]);
    assert_eq!(rib.accepted_prefixes(peer), recount(&rib, peer));
    assert_eq!(rib.stale_count(peer), 3);
    assert!(rib.push_snapshot().1.contains_key(&prefix("1.0.0.0/24")));
    // `reconcile_peers` deregistering again after an abort changes nothing.
    rib.peer_disconnected(peer, Disconnect::Graceful);
    assert_eq!(rib.stale_count(peer), 3);

    // Back with F=1: kept until End-of-RIB; 1.0.0.0/24 is re-announced.
    let _rx = register_gr_peer(&mut rib, peer);
    assert_eq!(rib.stale_count(peer), 3);
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.0.0.0/24"], vec![65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &evpn_reach(vec![evpn_nlri(1)], vec![65001]),
        &nos_rpl::ACCEPT_ALL,
    );
    assert_eq!(rib.stale_count(peer), 1);
    rib.end_of_rib(peer, AddressFamily::Ipv4Unicast);
    assert_eq!(withdrawn(&mut observer), ["2.0.0.0/24"]);
    assert_eq!(rib.accepted_prefixes(peer), [1, 0, 1]);
    assert_eq!(rib.accepted_prefixes(peer), recount(&rib, peer));
    assert!(!rib.gr_deadline.contains_key(&peer));
}

/// No capability, or a Hard end: everything goes at once, as without GR.
#[test]
fn graceful_restart_needs_the_capability_and_a_soft_end() {
    let ipv4 = (AddressFamily::Ipv4Unicast, true);
    for (cap, kind) in [
        (None, Disconnect::Transport),
        (Some(gr(true, &[ipv4])), Disconnect::Hard),
        (Some(gr(false, &[ipv4])), Disconnect::Graceful),
        (Some(gr(true, &[])), Disconnect::Transport),
    ] {
        let (mut rib, peer, mut observer) = gr_rib(cap);
        let _ = recv_all(&mut observer);
        rib.peer_disconnected(peer, kind);
        assert_eq!(
            withdrawn(&mut observer),
            ["1.0.0.0/24", "2.0.0.0/24", "2001:db8:1::/48"],
            "{cap:?} {kind:?}"
        );
        assert_eq!(rib.accepted_prefixes(peer), [0, 0, 0]);
        assert_eq!(rib.stale_count(peer), 0);
    }
}

/// RFC 4724 §4.2: on the new session, a family with F = 0, missing from
/// the capability, or no capability at all is purged at once.
#[test]
fn graceful_restart_flushes_on_return_without_forwarding_state() {
    let both = [
        (AddressFamily::Ipv4Unicast, true),
        (AddressFamily::Ipv6Unicast, true),
    ];
    for (back, want) in [
        (Some(gr(true, &both)), vec![]),
        (
            Some(gr(true, &[(AddressFamily::Ipv4Unicast, false)])),
            vec!["1.0.0.0/24", "2.0.0.0/24", "2001:db8:1::/48"],
        ),
        (
            Some(gr(true, &[(AddressFamily::Ipv4Unicast, true)])),
            vec!["2001:db8:1::/48"],
        ),
        (None, vec!["1.0.0.0/24", "2.0.0.0/24", "2001:db8:1::/48"]),
    ] {
        let (mut rib, peer, mut observer) = gr_rib(Some(gr(true, &both)));
        rib.peer_disconnected(peer, Disconnect::Transport);
        let _ = recv_all(&mut observer);
        rib.set_peer_gr(peer, back);
        let _rx = register_gr_peer(&mut rib, peer);
        assert_eq!(withdrawn(&mut observer), want, "{back:?}");
    }
}

/// RFC 5882 §4.3.1: BFD Down aborts a graceful restart in progress.
#[test]
fn gr_abort_purges_stale_routes_now() {
    let cap = gr(true, &[(AddressFamily::Ipv4Unicast, true)]);
    let (mut rib, peer, mut observer) = gr_rib(Some(cap));
    assert!(!rib.gr_abort(peer), "nothing stale yet");
    rib.peer_disconnected(peer, Disconnect::Transport);
    let _ = recv_all(&mut observer);
    assert!(rib.gr_abort(peer));
    assert_eq!(withdrawn(&mut observer), ["1.0.0.0/24", "2.0.0.0/24"]);
    assert_eq!(rib.stale_count(peer), 0);
    assert!(!rib.gr_abort(peer));
}

/// The restart timer while the peer is down, the stale timer once it's
/// back; restart time 0 keeps nothing.
#[test]
fn graceful_restart_timers_purge() {
    let cap = gr(true, &[(AddressFamily::Ipv4Unicast, true)]);
    let (mut rib, peer, mut observer) = gr_rib(Some(cap));
    rib.peer_disconnected(peer, Disconnect::Transport);
    let _ = recv_all(&mut observer);
    rib.gr_tick_at(Instant::now() + Duration::from_secs(119));
    assert_eq!(rib.stale_count(peer), 2);
    rib.gr_tick_at(Instant::now() + Duration::from_secs(121));
    assert_eq!(withdrawn(&mut observer), ["1.0.0.0/24", "2.0.0.0/24"]);

    let (mut rib, peer, mut observer) = gr_rib(Some(cap));
    rib.peer_disconnected(peer, Disconnect::Transport);
    rib.set_gr_stale_time(10);
    let _rx = register_gr_peer(&mut rib, peer);
    let _ = recv_all(&mut observer);
    rib.gr_tick_at(Instant::now() + Duration::from_secs(11));
    assert_eq!(withdrawn(&mut observer), ["1.0.0.0/24", "2.0.0.0/24"]);

    let mut zero = cap;
    zero.time = 0;
    let (mut rib, peer, mut observer) = gr_rib(Some(zero));
    let _ = recv_all(&mut observer);
    rib.peer_disconnected(peer, Disconnect::Transport);
    assert_eq!(rib.stale_count(peer), 0);
    assert_eq!(rib.accepted_prefixes(peer), [0, 0, 0]);
}

/// RFC 4724 §4.1: while deferring, nothing leaves — no UPDATE, no
/// End-of-RIB, no push to `nos-ribd` — though the Loc-RIB fills; the
/// last End-of-RIB ends it and every peer gets its dump + End-of-RIB.
#[test]
fn selection_deferral_holds_output_until_the_last_end_of_rib() {
    let mut rib = new_rib(65000);
    rib.set_routing_table(Some("rt1".into()));
    let (a, b) = (addr("10.0.0.1"), addr("10.0.0.2"));
    rib.begin_deferral(5, 120, 360, [a, b]);
    assert!(rib.deferring() && rib.gr_forwarding(a));
    let cap = gr(true, &[(AddressFamily::Ipv4Unicast, true)]);
    rib.set_peer_gr(a, Some(cap));
    let mut rx_a = register_gr_peer(&mut rib, a);
    rib.set_peer_gr(b, Some(cap));
    let mut rx_b = register_gr_peer(&mut rib, b);
    rib.handle_update(
        a,
        false,
        v4("192.0.2.1"),
        &ebgp_update(vec!["1.0.0.0/24"], vec![65001], "10.0.0.1"),
        &nos_rpl::ACCEPT_ALL,
    );
    assert!(rib.loc_rib.contains_key(&prefix("1.0.0.0/24")));
    assert!(recv_all(&mut rx_a).is_empty() && recv_all(&mut rx_b).is_empty());
    assert_eq!(rib.push_snapshot(), (None, HashMap::new()));
    // `nos-ribd`'s redistribution snapshot is waited for too.
    rib.apply_redistribute_update(RedistributeUpdate::Full(Vec::new()));

    for peer in [a, b] {
        assert!(rib.deferring());
        for family in AddressFamily::ALL {
            rib.end_of_rib(peer, family);
        }
    }
    assert!(!rib.deferring());
    let to_b = recv_all(&mut rx_b);
    assert!(matches!(&to_b[0], OutboundUpdate::Announce(_)), "{to_b:?}");
    let eors = |v: &[OutboundUpdate]| {
        v.iter()
            .filter(|u| matches!(u, OutboundUpdate::EndOfRib(_)))
            .count()
    };
    assert_eq!(eors(&to_b), 3);
    assert_eq!(eors(&recv_all(&mut rx_a)), 3);
    assert_eq!(rib.push_snapshot().0.as_deref(), Some("rt1"));
}

/// A peer without the capability, or restarting itself (R), is not
/// waited for; with nobody left the deferral ends at once.
#[test]
fn selection_deferral_skips_peers_without_gr_or_restarting() {
    let mut rib = new_rib(65000);
    let (a, b) = (addr("10.0.0.1"), addr("10.0.0.2"));
    rib.apply_redistribute_update(RedistributeUpdate::Full(Vec::new()));
    rib.begin_deferral(5, 120, 360, [a, b]);
    let _rx_a = register_gr_peer(&mut rib, a);
    assert!(rib.deferring());
    let mut restarting = gr(true, &[(AddressFamily::Ipv4Unicast, true)]);
    restarting.restart = true;
    rib.set_peer_gr(b, Some(restarting));
    let mut rx_b = register_gr_peer(&mut rib, b);
    assert!(!rib.deferring());
    assert_eq!(
        recv_all(&mut rx_b)
            .iter()
            .filter(|u| matches!(u, OutboundUpdate::EndOfRib(_)))
            .count(),
        3
    );
    // No peers at all: only the redistributed routes to wait for.
    let mut rib = new_rib(65000);
    rib.begin_deferral(5, 120, 360, []);
    assert!(rib.deferring());
    rib.apply_redistribute_update(RedistributeUpdate::Full(Vec::new()));
    assert!(!rib.deferring());
}

#[test]
fn no_limit_and_limit_zero_never_trip() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let accept = &nos_rpl::ACCEPT_ALL;
    let upd = ebgp_update(vec!["1.0.0.0/24", "2.0.0.0/24"], vec![65001], "10.0.0.1");
    rib.handle_update(peer, false, v4("192.0.2.1"), &upd, accept);
    assert_eq!(rib.check_max_prefix(peer), None, "nothing configured");
    rib.set_peer_max_prefix(
        peer,
        nos_proto::BgpMaximumPrefix {
            ipv4: Some(nos_proto::BgpPrefixLimit::default()),
            ..Default::default()
        },
    );
    assert_eq!(rib.check_max_prefix(peer), None, "limit 0 is uncapped");
}

#[test]
fn maximum_prefix_families_are_independent_and_warning_only_never_trips() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let limit = |limit, warning_only| {
        Some(nos_proto::BgpPrefixLimit {
            limit,
            warning_only,
            restart_interval: 0,
        })
    };
    rib.set_peer_max_prefix(
        peer,
        nos_proto::BgpMaximumPrefix {
            ipv4: limit(5, false),
            ipv6: limit(1, false),
            l2vpn_evpn: None,
            ipv4_flowspec: None,
            ipv6_flowspec: None,
            vpnv4: None,
            vpnv6: None,
            rt_constraint: None,
            vpnv4_flowspec: None,
            vpnv6_flowspec: None,
        },
    );
    let accept = &nos_rpl::ACCEPT_ALL;
    let three_v4 = ebgp_update(
        vec!["1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24"],
        vec![65001],
        "10.0.0.1",
    );
    rib.handle_update(peer, false, v4("192.0.2.1"), &three_v4, accept);
    assert_eq!(
        rib.check_max_prefix(peer),
        None,
        "3 v4 under v4's 5, v6's 1 unused"
    );
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &v6_update(vec!["2001:db8:1::/48", "2001:db8:2::/48"]),
        accept,
    );
    let (family, l, count) = rib.check_max_prefix(peer).expect("v6 over its limit");
    assert_eq!((family, l.limit, count), (AddressFamily::Ipv6Unicast, 1, 2));

    rib.set_peer_max_prefix(
        peer,
        nos_proto::BgpMaximumPrefix {
            ipv4: limit(2, true),
            ipv6: limit(1, true),
            l2vpn_evpn: None,
            ipv4_flowspec: None,
            ipv6_flowspec: None,
            vpnv4: None,
            vpnv6: None,
            rt_constraint: None,
            vpnv4_flowspec: None,
            vpnv6_flowspec: None,
        },
    );
    assert_eq!(rib.check_max_prefix(peer), None, "warning-only never trips");
}

#[test]
fn route_refresh_stale_marks_are_per_path() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let learn = |rib: &mut BgpRib, id| {
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &path_update("203.0.113.0/24", id, "10.0.0.1", None),
            &nos_rpl::ACCEPT_ALL,
        );
    };
    learn(&mut rib, 1);
    learn(&mut rib, 2);
    rib.begin_refresh_in(peer, AddressFamily::Ipv4Unicast);
    // Re-announcing path 2 clears its mark only.
    learn(&mut rib, 2);
    assert_eq!(rib.end_refresh_in(peer, AddressFamily::Ipv4Unicast), 1);
    assert_eq!(held_ids(&rib, peer, "203.0.113.0/24"), [2]);
}
