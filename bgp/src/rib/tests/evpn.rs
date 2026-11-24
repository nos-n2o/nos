use super::*;

fn mac_route(mac: u8) -> nos_proto::EvpnRoute {
    nos_proto::EvpnRoute {
        key: nos_proto::EvpnKey::Mac {
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            mac: [0, 0, 0, 0, 0, mac],
        },
        vni: 10100,
        next_hop: addr("192.0.2.9"),
        ext_communities: vec![0x0002_fde8_0000_2774],
        esi: [0; 10],
        l3_vni: None,
    }
}

fn evpn_afs() -> HashSet<AddressFamily> {
    HashSet::from([AddressFamily::Ipv4Unicast, AddressFamily::L2vpnEvpn])
}

/// #723: the paging keys list the same routes in the same order as the old
/// unpaged `evpn_routes`, each key resolves to its route, a vanished one to
/// `None`.
#[test]
fn evpn_keys_match_the_unpaged_order_and_resolve_to_their_routes() {
    let mut rib = new_rib(65000);
    let (p1, p2) = (addr("10.0.0.2"), addr("10.0.0.1"));
    let _rx1 = register_peer(&mut rib, p1, false, addr("10.0.0.254"));
    let _rx2 = register_peer(&mut rib, p2, false, addr("10.0.0.253"));
    for (p, macs) in [(p1, vec![3, 1]), (p2, vec![2, 9])] {
        rib.handle_update(
            p,
            false,
            v4("192.0.2.1"),
            &evpn_reach(macs.into_iter().map(evpn_nlri).collect(), vec![65001]),
            &deny_all_policy(),
        );
    }
    let keys = rib.evpn_keys();
    let want: Vec<_> = rib
        .evpn_routes()
        .into_iter()
        .map(|(peer, n, _)| (peer, n.to_string()))
        .collect();
    let got: Vec<_> = keys
        .iter()
        .map(|k| (k.cursor.peer, k.cursor.route.clone()))
        .collect();
    assert_eq!((got.len(), &got), (4, &want));
    for k in &keys {
        let (peer, r) = rib.evpn_at(k).unwrap();
        assert_eq!(
            (peer, r.nlri.to_string()),
            (k.cursor.peer, k.cursor.route.clone())
        );
    }
    // A client's `after` has no table key: it resolves to nothing.
    assert!(rib
        .evpn_at(&crate::page::Keyed::at(keys[0].cursor.clone()))
        .is_none());
    rib.peer_disconnected(p1, Disconnect::Transport);
    assert!(keys
        .iter()
        .filter(|k| k.cursor.peer == p1)
        .all(|k| rib.evpn_at(k).is_none()));
    assert_eq!(rib.evpn_keys().len(), 2);
}

#[test]
fn local_evpn_route_to_a_local_as_peer_carries_both_ases() {
    let mut rib = new_rib(65000);
    rib.set_peer_local_as(
        addr("10.0.0.1"),
        Some(nos_proto::BgpLocalAs {
            asn: 65009,
            ..Default::default()
        }),
    );
    let mut rx = register_mp_peer(
        &mut rib,
        addr("10.0.0.1"),
        false,
        addr("10.0.0.254"),
        evpn_afs(),
    );
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(mac_route(1)));
    let updates = recv_all(&mut rx);
    let [OutboundUpdate::AnnounceEvpn(adv)] = updates.as_slice() else {
        panic!("expected one EVPN announcement, got {updates:?}");
    };
    assert_eq!(adv.as_path, vec![65009, 65000]);
}

#[test]
fn local_evpn_routes_are_announced_withdrawn_and_replayed_to_new_peers() {
    let mut rib = new_rib(65000);
    let mut evpn_rx = register_mp_peer(
        &mut rib,
        addr("10.0.0.1"),
        false,
        addr("10.0.0.254"),
        evpn_afs(),
    );
    let mut plain_rx = register_mp_peer(
        &mut rib,
        addr("10.0.0.2"),
        false,
        addr("10.0.0.253"),
        HashSet::from([AddressFamily::Ipv4Unicast]),
    );

    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(mac_route(1)));
    let updates = recv_all(&mut evpn_rx);
    assert_eq!(updates.len(), 1);
    let OutboundUpdate::AnnounceEvpn(adv) = &updates[0] else {
        panic!("expected an EVPN announcement, got {updates:?}");
    };
    // eBGP: our ASN prepended; the VTEP next-hop is untouched.
    assert_eq!(adv.as_path, vec![65000]);
    assert_eq!(adv.next_hop, addr("192.0.2.9"));
    // The stored RT plus a freshly attached RFC 7432 §7.7 MAC Mobility
    // community (sequence 0, not sticky — see `with_local_mobility`).
    assert_eq!(
        adv.extended_communities,
        vec![0x0002_fde8_0000_2774, 0x0600_0000_0000_0000]
    );
    assert!(recv_all(&mut plain_rx).is_empty(), "EVPN not negotiated");

    // An identical re-push is not re-announced.
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(mac_route(1)));
    assert_eq!(recv_all(&mut evpn_rx), []);

    // A peer that comes up later gets the current set.
    let mut late_rx = register_mp_peer(
        &mut rib,
        addr("10.0.0.3"),
        false,
        addr("10.0.0.252"),
        evpn_afs(),
    );
    assert_eq!(recv_all(&mut late_rx).len(), 1);

    // Full replaces only that domain's routes: mac 1 is withdrawn, 2 announced.
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Full(vec![mac_route(2)]));
    let updates = recv_all(&mut evpn_rx);
    assert_eq!(updates.len(), 2);
    assert!(updates
        .iter()
        .any(|u| matches!(u, OutboundUpdate::WithdrawEvpn(_))));

    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Remove(mac_route(2).key));
    assert!(matches!(
        recv_all(&mut evpn_rx).as_slice(),
        [OutboundUpdate::WithdrawEvpn(_)]
    ));
}

#[test]
fn type2_carries_its_esi_and_moving_onto_a_segment_withdraws_the_old_nlri() {
    let mut rib = new_rib(65000);
    let mut rx = register_mp_peer(
        &mut rib,
        addr("10.0.0.1"),
        false,
        addr("10.0.0.254"),
        evpn_afs(),
    );
    let esi = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(mac_route(1)));
    let _ = recv_all(&mut rx);

    // Same key, now on a segment: the old (ESI 0) NLRI goes, the new one comes.
    let mut on_es = mac_route(1);
    on_es.esi = esi;
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(on_es));
    let updates = recv_all(&mut rx);
    assert_eq!(updates.len(), 2, "{updates:?}");
    assert!(matches!(
        &updates[0],
        OutboundUpdate::WithdrawEvpn(EvpnNlri::MacIp { esi, .. }) if *esi == [0; 10]
    ));
    assert!(matches!(
        &updates[1],
        OutboundUpdate::AnnounceEvpn(a) if matches!(a.nlri, EvpnNlri::MacIp { esi: e, .. } if e == esi)
    ));
}

#[test]
fn local_ethernet_segment_route_is_originated_and_received_ones_reach_fdbd() {
    let mut rib = new_rib(65000);
    let mut rx = register_mp_peer(
        &mut rib,
        addr("10.0.0.1"),
        false,
        addr("10.0.0.254"),
        evpn_afs(),
    );
    let esi = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
    let route = nos_proto::EvpnRoute {
        key: nos_proto::EvpnKey::EthernetSegment {
            rd,
            esi,
            origin: addr("192.0.2.9"),
        },
        vni: 0,
        next_hop: addr("192.0.2.9"),
        ext_communities: vec![nos_proto::evpn_id::es_import_rt(&esi)],
        esi,
        l3_vni: None,
    };
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(route));
    let updates = recv_all(&mut rx);
    assert!(matches!(
        updates.as_slice(),
        [OutboundUpdate::AnnounceEvpn(a)] if matches!(a.nlri, EvpnNlri::EthernetSegment { .. })
    ));

    // A received Type-4 is handed to fdbd (previously dropped).
    let peer = addr("10.0.0.2");
    let _peer_rx = register_peer(&mut rib, peer, false, addr("10.0.0.253"));
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.2"),
        &evpn_reach(
            vec![EvpnNlri::EthernetSegment {
                rd,
                esi,
                origin: addr("192.0.2.2"),
            }],
            vec![65001],
        ),
        &deny_all_policy(),
    );
    let snap = rib.evpn_push_snapshot();
    assert!(snap.keys().any(|k| matches!(
        k,
        nos_proto::EvpnKey::EthernetSegment { origin, .. } if *origin == addr("192.0.2.2")
    )));
}

#[test]
fn ethernet_ad_routes_are_originated_per_es_and_per_evi_and_received_ones_keep_their_origin() {
    use nos_proto::fdb::AD_TAG_ES;
    let mut rib = new_rib(65000);
    let mut rx = register_mp_peer(
        &mut rib,
        addr("10.0.0.1"),
        false,
        addr("10.0.0.254"),
        evpn_afs(),
    );
    let esi = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
    let ad = |tag: u32, vni: u32| nos_proto::EvpnRoute {
        key: nos_proto::EvpnKey::EthernetAd {
            rd,
            esi,
            tag,
            origin: addr("192.0.2.9"),
        },
        vni,
        next_hop: addr("192.0.2.9"),
        ext_communities: vec![nos_proto::evpn_id::esi_label_ext(false)],
        esi,
        l3_vni: None,
    };
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(ad(AD_TAG_ES, 0)));
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(ad(0, 10_100)));
    let updates = recv_all(&mut rx);
    // Per-ES: MAX-ET and no label; per-EVI: tag 0, the VNI in the label.
    assert!(matches!(
        &updates[0],
        OutboundUpdate::AnnounceEvpn(a)
            if matches!(a.nlri, EvpnNlri::EthernetAd { tag: AD_TAG_ES, label: 0, .. })
    ));
    assert!(matches!(
        &updates[1],
        OutboundUpdate::AnnounceEvpn(a)
            if matches!(a.nlri, EvpnNlri::EthernetAd { tag: 0, label: 10_100, .. })
    ));

    // Two PEs sending the same NLRI stay two entries, told apart by origin.
    for (peer, nh) in [
        (addr("10.0.0.2"), "192.0.2.2"),
        (addr("10.0.0.3"), "192.0.2.3"),
    ] {
        let _peer_rx = register_peer(&mut rib, peer, false, addr("10.0.0.253"));
        let mut u = evpn_reach(
            vec![EvpnNlri::EthernetAd {
                rd,
                esi,
                tag: AD_TAG_ES,
                label: 0,
            }],
            vec![65001],
        );
        u.mp_reach[0].next_hop = addr(nh);
        rib.handle_update(peer, false, v4(nh), &u, &deny_all_policy());
    }
    let snap = rib.evpn_push_snapshot();
    let origins: std::collections::BTreeSet<_> = snap
        .keys()
        .filter_map(|k| match k {
            nos_proto::EvpnKey::EthernetAd { origin, tag, .. } if *tag == AD_TAG_ES => {
                Some(*origin)
            }
            _ => None,
        })
        .collect();
    assert_eq!(origins.len(), 2, "{snap:?}");
}

#[test]
fn received_type2_and_type3_become_wire_routes_for_fdbd() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &evpn_reach(vec![evpn_nlri(1)], vec![65001]),
        &deny_all_policy(),
    );
    let snap = rib.evpn_push_snapshot();
    assert_eq!(snap.len(), 1);
    let r = snap.values().next().unwrap();
    assert_eq!(r.next_hop, addr("192.0.2.1"));
    assert_eq!(r.ext_communities, vec![0x0002_fde8_0000_2710]);
}

fn type5(prefix: &str) -> nos_proto::EvpnRoute {
    nos_proto::EvpnRoute {
        key: nos_proto::EvpnKey::IpPrefix {
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0x13, 0x88],
            prefix: prefix.parse().unwrap(),
        },
        vni: 5000,
        next_hop: addr("192.0.2.9"),
        ext_communities: vec![nos_proto::evpn_id::router_mac_ext([2, 0, 0, 0, 0, 9])],
        esi: [0; 10],
        l3_vni: None,
    }
}

#[test]
fn type5_routes_are_originated_per_table_apart_from_a_same_named_domain() {
    let mut rib = new_rib(65000);
    let mut rx = register_mp_peer(
        &mut rib,
        addr("10.0.0.1"),
        false,
        addr("10.0.0.254"),
        evpn_afs(),
    );
    rib.apply_evpn_local("x", nos_proto::EvpnUpdate::Add(mac_route(1)));
    for p in ["10.1.0.0/24", "2001:db8:1::/64"] {
        rib.apply_evpn_source(
            EvpnSource::Table("x".to_string()),
            nos_proto::EvpnUpdate::Add(type5(p)),
        );
    }
    let updates = recv_all(&mut rx);
    assert_eq!(updates.len(), 3, "{updates:?}");
    // RFC 9136 §4.4.1: no ESI, a zero gateway of the prefix's family, the
    // L3 VNI as the label — and it survives the wire both ways.
    for u in &updates[1..] {
        let OutboundUpdate::AnnounceEvpn(a) = u else {
            panic!("expected a Type-5 announcement, got {u:?}");
        };
        let EvpnNlri::IpPrefix {
            gateway,
            label,
            esi,
            prefix,
            ..
        } = &a.nlri
        else {
            panic!("expected a Type-5 NLRI, got {:?}", a.nlri);
        };
        assert!(gateway.is_unspecified() && gateway.is_ipv4() == prefix.addr().is_ipv4());
        assert_eq!((*label, *esi), (5000, [0; 10]));
        let mut wire = Vec::new();
        crate::evpn::encode_nlri(&a.nlri, &mut wire);
        assert_eq!(wire.len(), if prefix.addr().is_ipv4() { 36 } else { 60 });
        assert_eq!(
            crate::evpn::decode_nlris(&wire).unwrap(),
            vec![a.nlri.clone()]
        );
    }

    // A table's Full replaces only the table's routes, not the domain's.
    rib.apply_evpn_source(
        EvpnSource::Table("x".to_string()),
        nos_proto::EvpnUpdate::Full(vec![]),
    );
    let updates = recv_all(&mut rx);
    assert_eq!(updates.len(), 2, "{updates:?}");
    assert!(updates
        .iter()
        .all(|u| matches!(u, OutboundUpdate::WithdrawEvpn(EvpnNlri::IpPrefix { .. }))));
}

#[test]
fn received_type5_reaches_the_feed_only_without_an_overlay_index() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
    let nlri = |p: &str, gateway: &str, esi: [u8; 10]| EvpnNlri::IpPrefix {
        rd,
        esi,
        tag: 0,
        prefix: p.parse().unwrap(),
        gateway: addr(gateway),
        label: 5000,
    };
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &evpn_reach(
            vec![
                nlri("10.1.0.0/24", "0.0.0.0", [0; 10]),
                nlri("10.2.0.0/24", "10.9.9.9", [0; 10]),
                nlri("10.3.0.0/24", "0.0.0.0", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
                evpn_nlri(1),
            ],
            vec![65001],
        ),
        &deny_all_policy(),
    );
    let snap = rib.evpn_push_snapshot();
    let type5: Vec<_> = snap
        .values()
        .filter(|r| matches!(r.key, nos_proto::EvpnKey::IpPrefix { .. }))
        .collect();
    assert_eq!(type5.len(), 1, "{snap:?}");
    assert_eq!(
        type5[0].key,
        nos_proto::EvpnKey::IpPrefix {
            rd,
            prefix: "10.1.0.0/24".parse().unwrap()
        }
    );
    assert_eq!((type5[0].vni, type5[0].next_hop), (5000, addr("192.0.2.1")));
    // The Type-2 is still there for nos-fdbd.
    assert_eq!(snap.len(), 2);
}

/// RFC 7432 §15 vs §8.4: a peer's higher-sequence Type-2 for a MAC we
/// advertise locally makes us withdraw ours only when it is behind a
/// different ESI; on our own segment both PEs keep theirs (#172).
/// Returns (we withdrew ours, the peer's copy reaches fdbd).
fn remote_claim_on(remote_esi: [u8; 10]) -> (bool, bool) {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_mp_peer(&mut rib, peer, false, addr("10.0.0.254"), evpn_afs());
    let mut local = mac_route(1);
    local.esi = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(local));
    let _ = recv_all(&mut rx);

    let remote = EvpnNlri::MacIp {
        rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 2],
        esi: remote_esi,
        tag: 0,
        mac: [0, 0, 0, 0, 0, 1],
        ip: None,
        labels: vec![10100],
    };
    // The peer's VTEP (192.0.2.1) is lower than ours (192.0.2.9), seq 5.
    let mut u = evpn_reach(vec![remote], vec![65001]);
    u.attributes
        .as_mut()
        .unwrap()
        .extended_communities
        .push(nos_proto::evpn_id::mac_mobility_ext(5, false));
    rib.handle_update(peer, false, v4("192.0.2.1"), &u, &deny_all_policy());
    let withdrew = recv_all(&mut rx)
        .iter()
        .any(|u| matches!(u, OutboundUpdate::WithdrawEvpn(_)));
    let pushed = rib
        .evpn_push_snapshot()
        .values()
        .any(|r| r.next_hop == addr("192.0.2.1"));
    (withdrew, pushed)
}

#[test]
fn same_esi_remote_type2_is_not_a_mac_move() {
    assert_eq!(
        remote_claim_on([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        (false, true)
    );
}

#[test]
fn different_esi_remote_type2_is_a_mac_move() {
    assert_eq!(remote_claim_on([9; 10]), (true, true));
}

#[test]
fn same_esi_copies_reach_fdbd_once_from_the_lowest_vtep() {
    let mut rib = new_rib(65000);
    for (peer, nh, rd) in [("10.0.0.1", "192.0.2.5", 5), ("10.0.0.2", "192.0.2.3", 3)] {
        let _rx = register_peer(&mut rib, addr(peer), false, addr("10.0.0.254"));
        let mut u = evpn_reach(
            vec![EvpnNlri::MacIp {
                rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, rd],
                esi: [7; 10],
                tag: 0,
                mac: [0, 0, 0, 0, 0, 1],
                ip: None,
                labels: vec![10100],
            }],
            vec![65001],
        );
        u.mp_reach[0].next_hop = addr(nh);
        rib.handle_update(addr(peer), false, v4(peer), &u, &deny_all_policy());
    }
    let snap = rib.evpn_push_snapshot();
    assert_eq!(snap.len(), 1, "{snap:?}");
    assert!(snap.values().all(|r| r.next_hop == addr("192.0.2.3")));
}

#[test]
fn evpn_routes_are_stored_per_peer_withdrawn_and_cleared_on_disconnect() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let observer = addr("10.0.0.2");
    let _peer_rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let mut observer_rx = register_peer(&mut rib, observer, false, addr("10.0.0.253"));

    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &evpn_reach(vec![evpn_nlri(1), evpn_nlri(2)], vec![65001]),
        &deny_all_policy(), // import policy is prefix-shaped: not applied to EVPN
    );
    let routes = rib.evpn_routes();
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].0, peer);
    assert_eq!(routes[0].2.next_hop, addr("192.0.2.1"));
    assert_eq!(
        routes[0].2.extended_communities,
        vec![0x0002_fde8_0000_2710]
    );
    // Nothing is re-advertised: no consumer exists yet.
    assert_eq!(recv_all(&mut observer_rx), []);

    // Re-announcing an existing route replaces it rather than duplicating.
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &evpn_reach(vec![evpn_nlri(1)], vec![65001]),
        &deny_all_policy(),
    );
    assert_eq!(rib.evpn_routes().len(), 2);

    let mut withdraw = empty_update();
    withdraw.mp_unreach = vec![message::MpUnreachNlri {
        afi: message::AFI_L2VPN,
        safi: message::SAFI_EVPN,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![evpn_nlri(1)],
        flowspec: Vec::new(),
        flowspec_vpn: Vec::new(),
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    rib.handle_update(peer, false, v4("192.0.2.1"), &withdraw, &deny_all_policy());
    let routes = rib.evpn_routes();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].1, &evpn_nlri(2));

    rib.peer_disconnected(peer, Disconnect::Transport);
    assert_eq!(rib.evpn_routes(), []);
}

/// RFC 7432 §7.2: labels and ESI are attributes. A re-announce changing
/// them replaces the route, and a withdrawal with other labels removes it.
#[test]
fn evpn_labels_and_esi_are_not_part_of_the_route_key() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let with = |labels: Vec<u32>, esi: u8| match evpn_nlri(1) {
        EvpnNlri::MacIp {
            rd, tag, mac, ip, ..
        } => EvpnNlri::MacIp {
            rd,
            esi: [esi; 10],
            tag,
            mac,
            ip,
            labels,
        },
        _ => unreachable!(),
    };
    let announce = |rib: &mut BgpRib, nlri: EvpnNlri| {
        rib.handle_update(
            peer,
            false,
            v4("192.0.2.1"),
            &evpn_reach(vec![nlri], vec![65001]),
            &deny_all_policy(),
        );
    };
    announce(&mut rib, with(vec![10_100], 0));
    announce(&mut rib, with(vec![10_100, 5000], 0));
    let routes = rib.evpn_routes();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].1, &with(vec![10_100, 5000], 0));

    announce(&mut rib, with(vec![10_100, 5000], 7));
    let routes = rib.evpn_routes();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].1, &with(vec![10_100, 5000], 7));

    let mut withdraw = empty_update();
    withdraw.mp_unreach = vec![message::MpUnreachNlri {
        afi: message::AFI_L2VPN,
        safi: message::SAFI_EVPN,
        withdrawn: vec![],
        withdrawn_path_ids: vec![],
        evpn: vec![with(vec![0], 0)],
        flowspec: Vec::new(),
        flowspec_vpn: Vec::new(),
        vpn: Vec::new(),
        rtc: Vec::new(),
    }];
    rib.handle_update(peer, false, v4("192.0.2.1"), &withdraw, &deny_all_policy());
    assert_eq!(rib.evpn_routes(), []);
}

/// RFC 9135 §5.2: a non-zero Label2 is the L3 VNI, zero means asymmetric.
#[test]
fn evpn_snapshot_maps_label2_to_the_l3_vni() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let host = |last: u8, labels: Vec<u32>| EvpnNlri::MacIp {
        rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
        esi: [0; 10],
        tag: 0,
        mac: [2, 0, 0, 0, 0, last],
        ip: Some(IpAddr::from([10, 72, 0, last])),
        labels,
    };
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &evpn_reach(
            vec![host(1, vec![10_300, 5000]), host(2, vec![10_300, 0])],
            vec![65001],
        ),
        &deny_all_policy(),
    );
    let mut got: Vec<_> = rib
        .evpn_push_snapshot()
        .into_values()
        .map(|r| (r.vni, r.l3_vni))
        .collect();
    got.sort();
    assert_eq!(got, vec![(10_300, None), (10_300, Some(5000))]);
}

#[test]
fn evpn_update_with_own_asn_in_as_path_is_dropped() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    rib.handle_update(
        peer,
        false,
        v4("192.0.2.1"),
        &evpn_reach(vec![evpn_nlri(1)], vec![65001, 65000]),
        &deny_all_policy(),
    );
    assert_eq!(rib.evpn_routes(), []);
}

/// A ROUTE-REFRESH for EVPN re-sends what the peer was last sent (#866).
#[test]
fn an_evpn_route_refresh_resends_the_last_advertisements() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let mut rx = register_mp_peer(&mut rib, peer, false, addr("10.0.0.254"), evpn_afs());
    rib.apply_evpn_local("bd1", nos_proto::EvpnUpdate::Add(mac_route(1)));
    assert_eq!(recv_all(&mut rx).len(), 1);
    rib.resend_all(peer, AddressFamily::L2vpnEvpn, false);
    let again = recv_all(&mut rx);
    assert!(matches!(
        again.as_slice(),
        [OutboundUpdate::AnnounceEvpn(_)]
    ));
}

/// RFC 7313 §4 (#625): `BoRR` marks every EVPN route stale, a re-announced one
/// is kept, `EoRR` purges the rest; a `BoRR` alone leaves them for `expire_stale`.
#[test]
fn borr_eorr_purges_unrefreshed_evpn_routes() {
    let mut rib = new_rib(65000);
    let peer = addr("10.0.0.1");
    let _rx = register_peer(&mut rib, peer, false, addr("10.0.0.254"));
    let feed = |rib: &mut BgpRib, macs: Vec<u8>| {
        let u = evpn_reach(macs.into_iter().map(evpn_nlri).collect(), vec![65001]);
        rib.handle_update(peer, false, v4("192.0.2.1"), &u, &deny_all_policy());
    };
    feed(&mut rib, vec![1, 2]);
    rib.begin_refresh_in(peer, AddressFamily::L2vpnEvpn);
    assert!(rib.has_stale(peer, Some(AddressFamily::L2vpnEvpn)));
    feed(&mut rib, vec![1]);
    assert_eq!(rib.end_refresh_in(peer, AddressFamily::L2vpnEvpn), 1);
    assert_eq!(rib.evpn_routes().len(), 1);
    assert!(!rib.has_stale(peer, None));
    // BoRR without EoRR: the stale deadline path purges the lot.
    rib.begin_refresh_in(peer, AddressFamily::L2vpnEvpn);
    assert_eq!(rib.purge_stale(peer, AddressFamily::L2vpnEvpn), 1);
    assert_eq!(rib.evpn_routes().len(), 0);
}
