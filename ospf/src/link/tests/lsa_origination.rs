use futures::FutureExt as _;

use super::*;

#[test]
fn router_lsa_links_includes_p2p_link_with_a_neighbor() {
    let cfg = link("eth0.0", 10);
    let mut status = LinkStatus::new(NetworkType::PointToPoint);
    let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
    status.neighbors.insert(
        neighbor_id,
        neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2)),
    );
    let links = router_lsa_links(
        Ipv4Addr::new(1, 1, 1, 1),
        &[(cfg.clone(), status)],
        false,
        false,
    );
    assert_eq!(links.len(), 2);
    let p2p = links
        .iter()
        .find(|l| l.link_type == LINK_TYPE_POINT_TO_POINT)
        .unwrap();
    assert_eq!(p2p.link_id, neighbor_id);
    assert_eq!(p2p.link_data, cfg.local_addr);
    assert!(links.iter().any(|l| l.link_type == LINK_TYPE_STUB_NETWORK));
}

/// #463, RFC 2328 §12.4.1.1: a neighbor back in Init (one Hello after a BFD
/// kill) is not fully adjacent, so only the stub network is advertised.
#[test]
fn router_lsa_links_omits_p2p_link_until_full() {
    let mut status = LinkStatus::new(NetworkType::PointToPoint);
    status.neighbors.insert(
        Ipv4Addr::new(9, 9, 9, 10),
        neighbor_info(NeighborState::Init, Ipv4Addr::new(10, 0, 0, 2)),
    );
    let links = router_lsa_links(
        Ipv4Addr::new(1, 1, 1, 1),
        &[(link("eth0.0", 10), status)],
        false,
        false,
    );
    assert!(links.iter().all(|l| l.link_type == LINK_TYPE_STUB_NETWORK));
}

#[test]
fn router_lsa_links_max_metric_raises_transit_links_only() {
    // RFC 6987 §2: type-1/type-2 at MaxLinkMetric, type-3 keeps its cost.
    let mut p2p = link("eth0.0", 10);
    p2p.cost = 7;
    let mut p2p_status = LinkStatus::new(NetworkType::PointToPoint);
    p2p_status.neighbors.insert(
        Ipv4Addr::new(9, 9, 9, 10),
        neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2)),
    );
    let mut bcast = link("broadcast-domain:d", 10);
    bcast.network_type = NetworkType::Broadcast;
    bcast.local_addr = Ipv4Addr::new(10, 1, 0, 1);
    bcast.cost = 7;
    let mut bcast_status = LinkStatus::new(NetworkType::Broadcast);
    bcast_status.dr = Some(Ipv4Addr::new(1, 1, 1, 1));
    let links = router_lsa_links(
        Ipv4Addr::new(1, 1, 1, 1),
        &[(p2p, p2p_status), (bcast, bcast_status)],
        false,
        true,
    );
    let metric = |t| links.iter().find(|l| l.link_type == t).unwrap().metric;
    assert_eq!(links.len(), 3);
    assert_eq!(metric(LINK_TYPE_POINT_TO_POINT), lsa::MAX_LINK_METRIC);
    assert_eq!(metric(LINK_TYPE_TRANSIT_NETWORK), lsa::MAX_LINK_METRIC);
    assert_eq!(metric(LINK_TYPE_STUB_NETWORK), 7);
}

#[test]
fn prefix_suppression_hides_the_p2p_stub_and_the_network_mask() {
    // RFC 6860 §2.1: only the type-1 link is left on a p2p link.
    let cfg = link("eth0.0", 10);
    let mut status = LinkStatus::new(NetworkType::PointToPoint);
    status.neighbors.insert(
        Ipv4Addr::new(9, 9, 9, 10),
        neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2)),
    );
    let links = router_lsa_links(
        Ipv4Addr::new(1, 1, 1, 1),
        &[(cfg.clone(), status)],
        true,
        false,
    );
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].link_type, LINK_TYPE_POINT_TO_POINT);

    // A broadcast link's transit entry is unaffected.
    let mut bcast = link("bd1", 10);
    bcast.network_type = NetworkType::Broadcast;
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let mut status = LinkStatus::new(NetworkType::Broadcast);
    status.interface_state = InterfaceState::Dr;
    status.dr = Some(local_router_id);
    let on = router_lsa_links(
        local_router_id,
        &[(bcast.clone(), status.clone())],
        true,
        false,
    );
    let off = router_lsa_links(local_router_id, &[(bcast, status)], false, false);
    assert_eq!(on, off);

    // §2.2.2.1: the DR's Network-LSA mask.
    assert_eq!(
        network_lsa_mask(&cfg, false),
        Ipv4Addr::new(255, 255, 255, 0)
    );
    assert_eq!(network_lsa_mask(&cfg, true), Ipv4Addr::BROADCAST);
}

#[test]
fn router_lsa_links_skips_broadcast_link_with_no_dr_yet() {
    let mut cfg = link("bd1", 10);
    cfg.network_type = NetworkType::Broadcast;
    let status = LinkStatus::new(NetworkType::Broadcast);
    assert_eq!(
        router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg, status)], false, false),
        []
    );
}

#[test]
fn router_lsa_links_uses_own_address_when_self_is_dr() {
    let mut cfg = link("bd1", 10);
    cfg.network_type = NetworkType::Broadcast;
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let mut status = LinkStatus::new(NetworkType::Broadcast);
    status.interface_state = InterfaceState::Dr;
    status.dr = Some(local_router_id);
    let links = router_lsa_links(local_router_id, &[(cfg.clone(), status)], false, false);
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].link_id, cfg.local_addr);
    assert_eq!(links[0].link_type, 2);
}

#[test]
fn router_lsa_links_uses_dr_neighbor_address_when_not_self() {
    let mut cfg = link("bd1", 10);
    cfg.network_type = NetworkType::Broadcast;
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let dr_id = Ipv4Addr::new(9, 9, 9, 10);
    let dr_addr = Ipv4Addr::new(10, 0, 0, 2);
    let mut status = LinkStatus::new(NetworkType::Broadcast);
    status.interface_state = InterfaceState::Backup;
    status.dr = Some(dr_id);
    status
        .neighbors
        .insert(dr_id, neighbor_info(NeighborState::Full, dr_addr));
    let links = router_lsa_links(local_router_id, &[(cfg, status)], false, false);
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].link_id, dr_addr);
}

#[test]
fn install_self_originated_first_install_uses_initial_sequence_number() {
    let mut lsdb = Lsdb::new();
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let body = LsaBody::Router(RouterLsaBody {
        flags: 0,
        links: Vec::new(),
    });
    install_self_originated(
        &mut lsdb,
        local_router_id,
        lsa::LSA_TYPE_ROUTER,
        local_router_id,
        body.clone(),
    );
    let key = LsaKey {
        lsa_type: lsa::LSA_TYPE_ROUTER,
        link_state_id: local_router_id,
        advertising_router: local_router_id,
    };
    let installed = lsdb.get(&key).unwrap();
    assert_eq!(
        installed.header.sequence_number,
        lsa::INITIAL_SEQUENCE_NUMBER
    );
    assert_eq!(installed.body, body);
}

#[test]
fn install_self_originated_unchanged_body_is_a_no_op() {
    let mut lsdb = Lsdb::new();
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let body = LsaBody::Router(RouterLsaBody {
        flags: 0,
        links: Vec::new(),
    });
    install_self_originated(
        &mut lsdb,
        local_router_id,
        lsa::LSA_TYPE_ROUTER,
        local_router_id,
        body.clone(),
    );
    install_self_originated(
        &mut lsdb,
        local_router_id,
        lsa::LSA_TYPE_ROUTER,
        local_router_id,
        body,
    );
    let key = LsaKey {
        lsa_type: lsa::LSA_TYPE_ROUTER,
        link_state_id: local_router_id,
        advertising_router: local_router_id,
    };
    assert_eq!(
        lsdb.get(&key).unwrap().header.sequence_number,
        lsa::INITIAL_SEQUENCE_NUMBER
    );
}

#[test]
fn install_self_originated_age_based_refresh_bumps_sequence_number_even_with_unchanged_body() {
    let mut lsdb = Lsdb::new();
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let body = LsaBody::Router(RouterLsaBody {
        flags: 0,
        links: Vec::new(),
    });
    install_self_originated(
        &mut lsdb,
        local_router_id,
        lsa::LSA_TYPE_ROUTER,
        local_router_id,
        body.clone(),
    );
    lsdb.age_and_evict(lsa::LS_REFRESH_TIME, &HashSet::new());

    install_self_originated(
        &mut lsdb,
        local_router_id,
        lsa::LSA_TYPE_ROUTER,
        local_router_id,
        body,
    );

    let key = LsaKey {
        lsa_type: lsa::LSA_TYPE_ROUTER,
        link_state_id: local_router_id,
        advertising_router: local_router_id,
    };
    let installed = lsdb.get(&key).unwrap();
    assert_eq!(
        installed.header.sequence_number,
        lsa::INITIAL_SEQUENCE_NUMBER + 1
    );
    assert_eq!(installed.header.age, 0);
}

#[tokio::test]
async fn originate_router_lsas_includes_loopback_stub_for_area_with_no_live_link() {
    // Regression test for the area-union fix: an area with only a
    // loopback stub network and no live `LinkConfig` must still get a
    // Router-LSA originated for it.
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area = Ipv4Addr::UNSPECIFIED;
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let subnet: Ipv4Net = "192.168.9.0/24".parse().unwrap();
    manager
        .reconcile(
            Vec::new(),
            HashMap::from([(area, vec![(subnet, 5)])]),
            router_id,
        )
        .await;
    manager.originate_router_lsas(router_id).await;

    let lsdb = manager.lsdb_for(area).await;
    let key = LsaKey {
        lsa_type: lsa::LSA_TYPE_ROUTER,
        link_state_id: router_id,
        advertising_router: router_id,
    };
    let installed = lsdb.lock().await.get(&key).unwrap();
    let LsaBody::Router(body) = &installed.body else {
        panic!("expected router lsa")
    };
    assert_eq!(body.links.len(), 1);
    assert_eq!(body.links[0].link_type, LINK_TYPE_STUB_NETWORK);
    assert_eq!(body.links[0].link_id, Ipv4Addr::new(192, 168, 9, 0));
    assert_eq!(body.links[0].metric, 5);
}

/// RFC 2328 A.4.2 (#34): B while stubs sit in 2+ areas, E while a
/// Type-5 is originated — each cleared again once that stops, even
/// though `lsdbs` still holds the area that was left.
#[tokio::test]
async fn originate_router_lsas_sets_b_and_e_flags() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area0 = Ipv4Addr::UNSPECIFIED;
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let stub0 = ("192.168.9.0/24".parse::<Ipv4Net>().unwrap(), 1);
    let stub1 = ("192.168.10.0/24".parse::<Ipv4Net>().unwrap(), 1);
    let key = LsaKey {
        lsa_type: lsa::LSA_TYPE_ROUTER,
        link_state_id: router_id,
        advertising_router: router_id,
    };
    // Originates, then reads the area's Router-LSA flags; ages every
    // area past MinLSInterval first so changed content isn't paced.
    let flags = |area: Ipv4Addr| {
        let manager = &manager;
        async move {
            for lsdb in manager.lsdbs.lock().await.values() {
                lsdb.lock()
                    .await
                    .age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
            }
            manager.originate_router_lsas(router_id).await;
            let lsdb = manager.lsdb_for(area).await;
            let lsa = lsdb.lock().await.get(&key).unwrap();
            let LsaBody::Router(body) = &lsa.body else {
                panic!("expected router lsa")
            };
            body.flags
        }
    };

    manager
        .reconcile(Vec::new(), HashMap::from([(area0, vec![stub0])]), router_id)
        .await;
    assert_eq!(flags(area0).await, 0);

    manager
        .reconcile(
            Vec::new(),
            HashMap::from([(area0, vec![stub0]), (area1, vec![stub1])]),
            router_id,
        )
        .await;
    assert_eq!(flags(area0).await, lsa::ROUTER_FLAG_B);
    assert_eq!(flags(area1).await, lsa::ROUTER_FLAG_B);

    *manager.redistribute_filtered.lock().await = HashSet::from([stub1.0]);
    assert_eq!(flags(area0).await, lsa::ROUTER_FLAG_B | lsa::ROUTER_FLAG_E);

    *manager.redistribute_filtered.lock().await = HashSet::new();
    manager
        .reconcile(Vec::new(), HashMap::from([(area0, vec![stub0])]), router_id)
        .await;
    assert_eq!(flags(area0).await, 0);
    assert!(manager.lsdbs.lock().await.contains_key(&area1));
}

/// RFC 8770 §3: H in the Router-LSA of every area while set, stubs at
/// their cost, and the router counts as max-metric (transit links at
/// 0xFFFF — `router_lsa_links_max_metric_raises_transit_links_only`).
#[tokio::test]
async fn host_router_sets_the_h_bit_in_every_area() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let (area0, area1) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(0, 0, 0, 1));
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let stub0 = ("192.168.9.0/24".parse::<Ipv4Net>().unwrap(), 5);
    let stub1 = ("192.168.10.0/24".parse::<Ipv4Net>().unwrap(), 5);
    manager
        .reconcile(
            Vec::new(),
            HashMap::from([(area0, vec![stub0]), (area1, vec![stub1])]),
            router_id,
        )
        .await;
    let key = LsaKey {
        lsa_type: lsa::LSA_TYPE_ROUTER,
        link_state_id: router_id,
        advertising_router: router_id,
    };
    let held = |area: Ipv4Addr| {
        let manager = &manager;
        async move {
            for lsdb in manager.lsdbs.lock().await.values() {
                lsdb.lock()
                    .await
                    .age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
            }
            manager.originate_router_lsas(router_id).await;
            let lsa = manager.lsdb_for(area).await.lock().await.get(&key).unwrap();
            let LsaBody::Router(body) = &lsa.body else {
                panic!("expected router lsa")
            };
            body.clone()
        }
    };
    assert!(!manager.max_metric_active());
    manager.set_host_router(true);
    assert!(manager.max_metric_active());
    for area in [area0, area1] {
        let body = held(area).await;
        assert_eq!(body.flags & lsa::ROUTER_FLAG_H, lsa::ROUTER_FLAG_H);
        assert_eq!(body.links[0].metric, 5);
    }
    manager.set_host_router(false);
    assert_eq!(held(area0).await.flags & lsa::ROUTER_FLAG_H, 0);
}

/// RFC 7770: one type-10 RI per area, GR helper always, GR capable only
/// with a grace period; flushed from an area that was left.
#[tokio::test]
async fn originate_router_lsas_originates_router_info_per_area() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area0 = Ipv4Addr::UNSPECIFIED;
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let stub0 = ("192.168.9.0/24".parse::<Ipv4Net>().unwrap(), 1);
    let stub1 = ("192.168.10.0/24".parse::<Ipv4Net>().unwrap(), 1);
    let key = LsaKey {
        lsa_type: lsa::LSA_TYPE_OPAQUE_AREA,
        link_state_id: lsa::ROUTER_INFO_LINK_STATE_ID,
        advertising_router: router_id,
    };
    let held = |area: Ipv4Addr| {
        let manager = &manager;
        async move {
            for lsdb in manager.lsdbs.lock().await.values() {
                lsdb.lock()
                    .await
                    .age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
            }
            manager.originate_router_lsas(router_id).await;
            let lsdb = manager.lsdb_for(area).await;
            let lsa = lsdb.lock().await.get(&key).unwrap();
            (lsa.header.age < lsa::MAX_AGE, lsa.body.clone())
        }
    };
    let body = |caps| (true, LsaBody::Opaque(lsa::encode_router_info(caps)));

    manager
        .reconcile(
            Vec::new(),
            HashMap::from([(area0, vec![stub0]), (area1, vec![stub1])]),
            router_id,
        )
        .await;
    // Helper and stub-router support are capabilities, always set.
    let always = lsa::RI_CAP_GR_HELPER | lsa::RI_CAP_STUB_ROUTER | lsa::RI_CAP_HOST_ROUTER;
    assert_eq!(held(area0).await, body(always));
    assert_eq!(held(area1).await, body(always));

    manager.set_graceful_restart(Some(120));
    let both = always | lsa::RI_CAP_GR_CAPABLE;
    assert_eq!(held(area0).await, body(both));

    manager
        .reconcile(Vec::new(), HashMap::from([(area0, vec![stub0])]), router_id)
        .await;
    assert_eq!(held(area0).await, body(both));
    assert!(!held(area1).await.0);
}

#[tokio::test]
async fn originate_summary_lsas_installs_type3_into_every_other_area() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area0 = Ipv4Addr::UNSPECIFIED;
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let net0: Ipv4Net = "192.168.10.0/24".parse().unwrap();
    let net1: Ipv4Net = "192.168.11.0/24".parse().unwrap();
    manager
        .reconcile(
            Vec::new(),
            HashMap::from([(area0, vec![(net0, 5)]), (area1, vec![(net1, 7)])]),
            router_id,
        )
        .await;
    manager.originate_router_lsas(router_id).await;
    manager.originate_summary_lsas(router_id).await;

    let lsdb0 = manager.lsdb_for(area0).await;
    let key0 = LsaKey {
        lsa_type: lsa::LSA_TYPE_NETWORK_SUMMARY,
        link_state_id: net1.network(),
        advertising_router: router_id,
    };
    let installed0 = lsdb0.lock().await.get(&key0).unwrap();
    let LsaBody::Summary(body0) = &installed0.body else {
        panic!("expected summary lsa")
    };
    assert_eq!(body0.metric, 7);

    let lsdb1 = manager.lsdb_for(area1).await;
    let key1 = LsaKey {
        lsa_type: lsa::LSA_TYPE_NETWORK_SUMMARY,
        link_state_id: net0.network(),
        advertising_router: router_id,
    };
    let installed1 = lsdb1.lock().await.get(&key1).unwrap();
    let LsaBody::Summary(body1) = &installed1.body else {
        panic!("expected summary lsa")
    };
    assert_eq!(body1.metric, 5);
}

#[test]
fn withdraw_self_originated_sets_max_age_and_keeps_sequence_number() {
    let mut lsdb = Lsdb::new();
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let key = router_key(router_id);
    assert!(!withdraw_self_originated(&mut lsdb, &key));

    install_self_originated(
        &mut lsdb,
        router_id,
        lsa::LSA_TYPE_ROUTER,
        router_id,
        router_body(0),
    );
    lsdb.age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
    install_self_originated(
        &mut lsdb,
        router_id,
        lsa::LSA_TYPE_ROUTER,
        router_id,
        router_body(1),
    );
    assert!(withdraw_self_originated(&mut lsdb, &key));
    let flushed = lsdb.get(&key).unwrap();
    assert_eq!(flushed.header.age, lsa::MAX_AGE);
    assert_eq!(
        flushed.header.sequence_number,
        lsa::INITIAL_SEQUENCE_NUMBER + 1
    );
    assert_eq!(flushed.body, router_body(1));
    // Already flushed: a no-op.
    assert!(!withdraw_self_originated(&mut lsdb, &key));
}

/// A neighbor's echo of a self-originated LSA (decoded from the wire, so
/// with the real checksum) must be a duplicate of the held instance, not
/// newer — otherwise it would supersede a prematurely aged one.
#[test]
fn self_originated_lsa_ties_with_its_own_wire_copy() {
    let mut lsdb = Lsdb::new();
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    install_self_originated(
        &mut lsdb,
        router_id,
        lsa::LSA_TYPE_ROUTER,
        router_id,
        router_body(0),
    );
    let held = lsdb.get(&router_key(router_id)).unwrap();
    let echo = lsa::decode_lsa(&lsa::encode_lsa(&held)).unwrap();
    assert_ne!(held.header.checksum, 0);
    assert_eq!(
        lsa::is_newer(&echo.header, &held.header),
        std::cmp::Ordering::Equal
    );
    assert_eq!(lsdb.install(echo), crate::lsdb::InstallOutcome::Rejected);
}

/// Issue #32 / RFC 2328 §12.1.6: at `MaxSequenceNumber` the LSA is
/// flushed at that number (never `0x8000_0000`), held for the flood window,
/// then re-originated at `InitialSequenceNumber`.
#[test]
fn install_self_originated_at_max_sequence_flushes_then_restarts_at_initial() {
    let mut lsdb = Lsdb::new();
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let key = router_key(router_id);
    lsdb.install(Lsa {
        header: LsaHeader {
            age: 100,
            options: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router_id,
            advertising_router: router_id,
            sequence_number: lsa::MAX_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: router_body(0),
    });

    install_self_originated(
        &mut lsdb,
        router_id,
        lsa::LSA_TYPE_ROUTER,
        router_id,
        router_body(1),
    );
    let flushed = lsdb.get(&key).unwrap();
    assert_eq!(flushed.header.sequence_number, lsa::MAX_SEQUENCE_NUMBER);
    assert_eq!(flushed.header.age, lsa::MAX_AGE);
    assert_eq!(flushed.body, router_body(0));

    // Deferred while the flushed copy is still held.
    for _ in 0..crate::lsdb::MAX_AGE_HOLD_TICKS - 1 {
        assert_eq!(lsdb.age_and_evict(1, &HashSet::new()), []);
        install_self_originated(
            &mut lsdb,
            router_id,
            lsa::LSA_TYPE_ROUTER,
            router_id,
            router_body(1),
        );
        assert_eq!(
            lsdb.get(&key).unwrap().header.sequence_number,
            lsa::MAX_SEQUENCE_NUMBER
        );
    }
    assert_eq!(lsdb.age_and_evict(1, &HashSet::new()), vec![key]);

    install_self_originated(
        &mut lsdb,
        router_id,
        lsa::LSA_TYPE_ROUTER,
        router_id,
        router_body(1),
    );
    let fresh = lsdb.get(&key).unwrap();
    assert_eq!(fresh.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
    assert_eq!(fresh.header.age, 0);
    assert_eq!(fresh.body, router_body(1));
}

/// `redistribute ... metric 50 metric-type 2` reaches the originated
/// Type-5; changing it re-originates the LSA with a bumped sequence number.
#[tokio::test]
async fn configured_external_metric_is_originated_and_change_bumps_sequence() {
    async fn body(m: &LinkManager, key: &LsaKey) -> (u32, bool, i32) {
        let lsdb = m.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
        let lsdb = lsdb.lock().await;
        let l = lsdb.get(key).unwrap();
        let LsaBody::AsExternal(e) = &l.body else {
            panic!()
        };
        (e.metric, e.e_type2, l.header.sequence_number)
    }
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let prefix: Ipv4Net = "192.0.2.0/24".parse().unwrap();
    let key = LsaKey {
        lsa_type: lsa::LSA_TYPE_AS_EXTERNAL,
        link_state_id: prefix.network(),
        advertising_router: router_id,
    };
    manager.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
    *manager.redistribute_filtered.lock().await = HashSet::from([prefix]);
    manager.originate_as_external_lsas(router_id).await;
    assert_eq!(
        body(&manager, &key).await,
        (20, false, lsa::INITIAL_SEQUENCE_NUMBER)
    );
    manager.set_redistribute_metric(Some(50), Some(2)).await;
    // RFC 2328 §12.4 MinLSInterval: a change waits for the held LSA to age.
    manager
        .lsdb_for(Ipv4Addr::UNSPECIFIED)
        .await
        .lock()
        .await
        .age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
    manager.originate_as_external_lsas(router_id).await;
    let (m, e, seq) = body(&manager, &key).await;
    assert_eq!((m, e), (50, true));
    assert!(seq > lsa::INITIAL_SEQUENCE_NUMBER);
}

#[tokio::test]
async fn originate_as_external_lsas_withdraws_a_prefix_no_longer_redistributed() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area = Ipv4Addr::UNSPECIFIED;
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let kept: Ipv4Net = "192.0.2.0/24".parse().unwrap();
    let dropped: Ipv4Net = "198.51.100.0/24".parse().unwrap();
    manager.lsdb_for(area).await;
    *manager.redistribute_filtered.lock().await = HashSet::from([kept, dropped]);
    manager.originate_as_external_lsas(router_id).await;
    *manager.redistribute_filtered.lock().await = HashSet::from([kept]);
    manager.originate_as_external_lsas(router_id).await;

    let lsdb = manager.lsdb_for(area).await;
    let lsdb = lsdb.lock().await;
    let key = |p: Ipv4Net| LsaKey {
        lsa_type: lsa::LSA_TYPE_AS_EXTERNAL,
        link_state_id: p.network(),
        advertising_router: router_id,
    };
    let flushed = lsdb.get(&key(dropped)).unwrap();
    assert_eq!(flushed.header.age, lsa::MAX_AGE);
    assert_eq!(flushed.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
    let live = lsdb.get(&key(kept)).unwrap();
    assert_eq!(live.header.age, 0);
    assert_eq!(live.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
}

/// RFC 2328 Appendix E: the shortest mask keeps the network address, a
/// longer one with the same address gets its host bits set.
#[test]
fn assign_link_state_ids_follows_appendix_e() {
    let expected = vec![
        ("192.0.2.128/25".to_string(), Ipv4Addr::new(192, 0, 2, 128)),
        ("192.0.2.128/26".to_string(), Ipv4Addr::new(192, 0, 2, 191)),
    ];
    assert_eq!(ids(&["192.0.2.128/25", "192.0.2.128/26"]), expected);
    assert_eq!(ids(&["192.0.2.128/26", "192.0.2.128/25"]), expected);
    assert_eq!(
        ids(&["0.0.0.0/8", "0.0.0.0/0"]),
        vec![
            ("0.0.0.0/0".to_string(), Ipv4Addr::UNSPECIFIED),
            ("0.0.0.0/8".to_string(), Ipv4Addr::new(0, 255, 255, 255)),
        ]
    );
    // Both IDs of the /32 are taken: skipped.
    assert_eq!(
        ids(&["10.0.0.255/32", "10.0.0.0/24", "10.0.0.0/16"]),
        vec![
            ("10.0.0.0/16".to_string(), Ipv4Addr::new(10, 0, 0, 0)),
            ("10.0.0.0/24".to_string(), Ipv4Addr::new(10, 0, 0, 255)),
        ]
    );
    assert_eq!(
        ids(&["198.51.100.0/24", "192.0.2.0/24"]),
        vec![
            ("192.0.2.0/24".to_string(), Ipv4Addr::new(192, 0, 2, 0)),
            (
                "198.51.100.0/24".to_string(),
                Ipv4Addr::new(198, 51, 100, 0)
            ),
        ]
    );
}

/// Two overlapping redistributed prefixes are two Type-5s (Appendix E);
/// once the shorter one goes, the longer one moves back to the network
/// address and its host-bits ID is flushed.
#[tokio::test]
async fn overlapping_redistributed_prefixes_get_distinct_type5s() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area = Ipv4Addr::UNSPECIFIED;
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let wide: Ipv4Net = "192.0.2.128/25".parse().unwrap();
    let narrow: Ipv4Net = "192.0.2.128/26".parse().unwrap();
    let (low, high) = (Ipv4Addr::new(192, 0, 2, 128), Ipv4Addr::new(192, 0, 2, 191));
    manager.lsdb_for(area).await;
    *manager.redistribute_filtered.lock().await = HashSet::from([wide, narrow]);
    manager.originate_as_external_lsas(router_id).await;
    {
        let lsdb = manager.lsdb_for(area).await;
        let lsdb = lsdb.lock().await;
        let t5 = lsa::LSA_TYPE_AS_EXTERNAL;
        assert_eq!(mask_at(&lsdb, t5, low, router_id), (wide.netmask(), 0));
        assert_eq!(mask_at(&lsdb, t5, high, router_id), (narrow.netmask(), 0));
    }

    *manager.redistribute_filtered.lock().await = HashSet::from([narrow]);
    // Past `MinLSInterval`, so `.128` may change content.
    manager
        .lsdb_for(area)
        .await
        .lock()
        .await
        .age_and_evict(lsa::MIN_LS_INTERVAL, &HashSet::new());
    manager.originate_as_external_lsas(router_id).await;
    let lsdb = manager.lsdb_for(area).await;
    let lsdb = lsdb.lock().await;
    let t5 = lsa::LSA_TYPE_AS_EXTERNAL;
    assert_eq!(mask_at(&lsdb, t5, low, router_id), (narrow.netmask(), 0));
    assert_eq!(
        mask_at(&lsdb, t5, high, router_id),
        (narrow.netmask(), lsa::MAX_AGE)
    );
}

#[tokio::test]
async fn overlapping_redistributed_prefixes_get_distinct_type7s_in_an_nssa() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area = Ipv4Addr::new(0, 0, 0, 1);
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let wide: Ipv4Net = "192.0.2.128/25".parse().unwrap();
    let narrow: Ipv4Net = "192.0.2.128/26".parse().unwrap();
    manager
        .set_area_settings(HashMap::from([(
            area,
            AreaSettings {
                stub: true,
                nssa: true,
                import_summaries: true,
                ..AreaSettings::default()
            },
        )]))
        .await;
    manager.lsdb_for(area).await;
    *manager.redistribute_filtered.lock().await = HashSet::from([wide, narrow]);
    manager.originate_as_external_lsas(router_id).await;
    let lsdb = manager.lsdb_for(area).await;
    let lsdb = lsdb.lock().await;
    let t7 = lsa::LSA_TYPE_NSSA_EXTERNAL;
    let id = |d| Ipv4Addr::new(192, 0, 2, d);
    assert_eq!(mask_at(&lsdb, t7, id(128), router_id).0, wide.netmask());
    assert_eq!(mask_at(&lsdb, t7, id(191), router_id).0, narrow.netmask());
}

/// Overlapping intra-area stubs in area 0 become two Type-3s in area 1.
#[tokio::test]
async fn overlapping_intra_area_prefixes_get_distinct_type3s() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area0 = Ipv4Addr::UNSPECIFIED;
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let wide: Ipv4Net = "10.1.0.0/16".parse().unwrap();
    let narrow: Ipv4Net = "10.1.0.0/24".parse().unwrap();
    let net1: Ipv4Net = "192.168.11.0/24".parse().unwrap();
    manager
        .reconcile(
            Vec::new(),
            HashMap::from([
                (area0, vec![(wide, 5), (narrow, 6)]),
                (area1, vec![(net1, 7)]),
            ]),
            router_id,
        )
        .await;
    manager.originate_router_lsas(router_id).await;
    manager.originate_summary_lsas(router_id).await;

    let lsdb1 = manager.lsdb_for(area1).await;
    let lsdb1 = lsdb1.lock().await;
    let t3 = lsa::LSA_TYPE_NETWORK_SUMMARY;
    assert_eq!(
        mask_at(&lsdb1, t3, Ipv4Addr::new(10, 1, 0, 0), router_id).0,
        wide.netmask()
    );
    assert_eq!(
        mask_at(&lsdb1, t3, Ipv4Addr::new(10, 1, 0, 255), router_id).0,
        narrow.netmask()
    );
}

#[tokio::test]
async fn leaving_an_area_withdraws_its_router_lsa_and_the_summaries_of_it() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area0 = Ipv4Addr::UNSPECIFIED;
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let net0: Ipv4Net = "192.168.10.0/24".parse().unwrap();
    let net1: Ipv4Net = "192.168.11.0/24".parse().unwrap();
    manager
        .reconcile(
            Vec::new(),
            HashMap::from([(area0, vec![(net0, 5)]), (area1, vec![(net1, 7)])]),
            router_id,
        )
        .await;
    manager.originate_router_lsas(router_id).await;
    manager.originate_summary_lsas(router_id).await;

    // The area1 loopback goes away: area1 keeps its (now empty) LSDB.
    manager
        .reconcile(
            Vec::new(),
            HashMap::from([(area0, vec![(net0, 5)])]),
            router_id,
        )
        .await;
    manager.originate_router_lsas(router_id).await;
    manager.originate_summary_lsas(router_id).await;

    let lsdb1 = manager.lsdb_for(area1).await;
    assert_eq!(
        lsdb1
            .lock()
            .await
            .get(&router_key(router_id))
            .unwrap()
            .header
            .age,
        lsa::MAX_AGE
    );
    let lsdb0 = manager.lsdb_for(area0).await;
    let lsdb0 = lsdb0.lock().await;
    let summary = lsdb0
        .get(&LsaKey {
            lsa_type: lsa::LSA_TYPE_NETWORK_SUMMARY,
            link_state_id: net1.network(),
            advertising_router: router_id,
        })
        .unwrap();
    assert_eq!(summary.header.age, lsa::MAX_AGE);
    assert_eq!(summary.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
    assert_eq!(lsdb0.get(&router_key(router_id)).unwrap().header.age, 0);
}

#[tokio::test]
async fn withdraw_all_self_originated_flushes_every_area() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area0 = Ipv4Addr::UNSPECIFIED;
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let net0: Ipv4Net = "192.168.10.0/24".parse().unwrap();
    let net1: Ipv4Net = "192.168.11.0/24".parse().unwrap();
    manager
        .reconcile(
            Vec::new(),
            HashMap::from([(area0, vec![(net0, 5)]), (area1, vec![(net1, 7)])]),
            router_id,
        )
        .await;
    manager.originate_router_lsas(router_id).await;
    manager.originate_summary_lsas(router_id).await;

    // A Router-LSA, an RI LSA and a Type-3 per area.
    assert_eq!(manager.withdraw_all_self_originated().await, 6);
    for area in [area0, area1] {
        let lsdb = manager.lsdb_for(area).await;
        for header in lsdb.lock().await.headers() {
            assert_eq!(header.advertising_router, router_id);
            assert_eq!(header.age, lsa::MAX_AGE, "{header:?}");
        }
    }
    assert_eq!(manager.withdraw_all_self_originated().await, 0);
}

#[tokio::test]
async fn an_abr_copies_a_foreign_type5_into_its_other_areas_and_propagates_a_flush() {
    let (manager, router_id, l0, l1) = abr_with_external(false).await;
    let key = foreign_type5(0).header.key();
    manager.flood_external_lsas_across_areas(router_id).await;
    assert!(l0.lock().await.get(&key).is_some());

    // A flush in area 1 (same sequence, MaxAge) reaches area 0 too.
    l1.lock().await.install(foreign_type5(lsa::MAX_AGE));
    manager.flood_external_lsas_across_areas(router_id).await;
    assert_eq!(l0.lock().await.get(&key).unwrap().header.age, lsa::MAX_AGE);
}

#[tokio::test]
async fn an_abr_never_copies_a_type5_into_a_stub_area_or_over_a_newer_one() {
    let (manager, router_id, l0, _l1) = abr_with_external(true).await;
    let key = foreign_type5(0).header.key();
    manager.flood_external_lsas_across_areas(router_id).await;
    assert!(l0.lock().await.get(&key).is_none());

    let (manager, router_id, l0, _l1) = abr_with_external(false).await;
    let mut newer = foreign_type5(0);
    newer.header.sequence_number += 1;
    lsa::fill_checksum(&mut newer);
    l0.lock().await.install(newer);
    manager.flood_external_lsas_across_areas(router_id).await;
    assert_eq!(
        l0.lock().await.get(&key).unwrap().header.sequence_number,
        lsa::INITIAL_SEQUENCE_NUMBER + 1
    );
}

#[tokio::test]
async fn a_non_abr_and_a_flush_with_nothing_held_copy_nothing() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area = Ipv4Addr::UNSPECIFIED;
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    manager
        .lsdb_for(area)
        .await
        .lock()
        .await
        .install(foreign_type5(0));
    manager.flood_external_lsas_across_areas(router_id).await;

    let (manager, router_id, l0, l1) = abr_with_external(false).await;
    l1.lock().await.install(foreign_type5(lsa::MAX_AGE));
    manager.flood_external_lsas_across_areas(router_id).await;
    assert!(l0
        .lock()
        .await
        .get(&foreign_type5(0).header.key())
        .is_none());
}

#[tokio::test]
async fn originate_summary_lsas_is_a_noop_with_only_one_area() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area = Ipv4Addr::UNSPECIFIED;
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let net: Ipv4Net = "192.168.12.0/24".parse().unwrap();
    manager
        .reconcile(
            Vec::new(),
            HashMap::from([(area, vec![(net, 5)])]),
            router_id,
        )
        .await;
    manager.originate_router_lsas(router_id).await;
    manager.originate_summary_lsas(router_id).await;

    let lsdb = manager.lsdb_for(area).await;
    let has_summary = lsdb
        .lock()
        .await
        .all()
        .iter()
        .any(|l| l.header.lsa_type == lsa::LSA_TYPE_NETWORK_SUMMARY);
    assert!(!has_summary);
}

#[tokio::test]
async fn originate_summary_lsas_installs_type4_for_reachable_asbr() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area0 = Ipv4Addr::UNSPECIFIED;
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let asbr = Ipv4Addr::new(2, 2, 2, 2);

    let lsdb0 = manager.lsdb_for(area0).await;
    lsdb0.lock().await.install(Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router_id,
            advertising_router: router_id,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Router(RouterLsaBody {
            flags: 0,
            links: vec![RouterLink {
                tos: Vec::new(),
                link_id: asbr,
                link_data: Ipv4Addr::new(10, 0, 0, 1),
                link_type: LINK_TYPE_POINT_TO_POINT,
                metric: 5,
            }],
        }),
    });
    lsdb0.lock().await.install(Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: asbr,
            advertising_router: asbr,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Router(RouterLsaBody {
            flags: 0,
            links: vec![RouterLink {
                tos: Vec::new(),
                link_id: router_id,
                link_data: Ipv4Addr::new(10, 0, 0, 2),
                link_type: LINK_TYPE_POINT_TO_POINT,
                metric: 5,
            }],
        }),
    });
    lsdb0.lock().await.install(Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
            lsa_type: lsa::LSA_TYPE_AS_EXTERNAL,
            link_state_id: Ipv4Addr::new(198, 51, 100, 0),
            advertising_router: asbr,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::AsExternal(AsExternalLsaBody {
            tos: Vec::new(),
            network_mask: Ipv4Addr::new(255, 255, 255, 0),
            metric: 0,
            e_type2: false,
            forwarding_address: Ipv4Addr::UNSPECIFIED,
            external_route_tag: 0,
        }),
    });
    // Make area1 exist (empty) so this router is a real 2-area ABR.
    manager.lsdb_for(area1).await;

    manager.originate_summary_lsas(router_id).await;

    let lsdb1 = manager.lsdb_for(area1).await;
    let key = LsaKey {
        lsa_type: lsa::LSA_TYPE_ASBR_SUMMARY,
        link_state_id: asbr,
        advertising_router: router_id,
    };
    let installed = lsdb1.lock().await.get(&key).unwrap();
    let LsaBody::Summary(body) = &installed.body else {
        panic!("expected summary lsa")
    };
    assert_eq!(body.metric, 5);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "linear scenario: three areas, run, assert"
)]
async fn originate_summary_lsas_type4_takes_minimum_over_two_source_areas() {
    fn router(id: Ipv4Addr, peer: Ipv4Addr, metric: u16) -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: id,
                advertising_router: id,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: vec![RouterLink {
                    tos: Vec::new(),
                    link_id: peer,
                    link_data: Ipv4Addr::new(10, 0, 0, 1),
                    link_type: LINK_TYPE_POINT_TO_POINT,
                    metric,
                }],
            }),
        }
    }
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area0 = Ipv4Addr::UNSPECIFIED;
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let area2 = Ipv4Addr::new(0, 0, 0, 2);
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let asbr = Ipv4Addr::new(2, 2, 2, 2);
    manager.lsdb_for(area0).await;
    for (area, cost) in [(area1, 5), (area2, 9)] {
        let lsdb = manager.lsdb_for(area).await;
        let mut lsdb = lsdb.lock().await;
        lsdb.install(router(router_id, asbr, cost));
        lsdb.install(router(asbr, router_id, cost));
        lsdb.install(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_AS_EXTERNAL,
                link_state_id: Ipv4Addr::new(198, 51, 100, 0),
                advertising_router: asbr,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsaBody {
                tos: Vec::new(),
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                metric: 0,
                e_type2: false,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: 0,
            }),
        });
    }
    let key = LsaKey {
        lsa_type: lsa::LSA_TYPE_ASBR_SUMMARY,
        link_state_id: asbr,
        advertising_router: router_id,
    };
    let mut seq0 = None;
    // HashMap order is random per run: repeat so a regression fails reliably.
    for _ in 0..20 {
        manager.originate_summary_lsas(router_id).await;
        for (area, want) in [(area0, 5), (area1, 9), (area2, 5)] {
            let lsa = manager.lsdb_for(area).await.lock().await.get(&key).unwrap();
            let LsaBody::Summary(body) = &lsa.body else {
                panic!("expected summary lsa")
            };
            assert_eq!(body.metric, want, "area {area}");
            if area == area0 {
                let seq = *seq0.get_or_insert(lsa.header.sequence_number);
                assert_eq!(lsa.header.sequence_number, seq, "seq bumped");
            }
        }
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "linear scenario: build two areas, run, assert"
)]
async fn compute_routes_keeps_cheaper_of_two_areas_computed_route_to_same_prefix() {
    fn router_lsa(id: Ipv4Addr, link: RouterLink) -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: id,
                advertising_router: id,
                sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: vec![link],
            }),
        }
    }

    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area0 = Ipv4Addr::UNSPECIFIED;
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let w = Ipv4Addr::new(2, 2, 2, 2);
    let v = Ipv4Addr::new(3, 3, 3, 3);
    let prefix_net = Ipv4Addr::new(192, 168, 20, 0);
    let mask = Ipv4Addr::new(255, 255, 255, 0);

    // Area 0: root -> w (cost 3), w advertises the stub at cost 10. Total 13.
    let lsdb0 = manager.lsdb_for(area0).await;
    lsdb0.lock().await.install(router_lsa(
        router_id,
        RouterLink {
            tos: Vec::new(),
            link_id: w,
            link_data: Ipv4Addr::new(10, 0, 0, 1),
            link_type: LINK_TYPE_POINT_TO_POINT,
            metric: 3,
        },
    ));
    lsdb0.lock().await.install(Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: w,
            advertising_router: w,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Router(RouterLsaBody {
            flags: 0,
            links: vec![
                RouterLink {
                    tos: Vec::new(),
                    link_id: router_id,
                    link_data: Ipv4Addr::new(10, 0, 0, 2),
                    link_type: LINK_TYPE_POINT_TO_POINT,
                    metric: 3,
                },
                RouterLink {
                    tos: Vec::new(),
                    link_id: prefix_net,
                    link_data: mask,
                    link_type: LINK_TYPE_STUB_NETWORK,
                    metric: 10,
                },
            ],
        }),
    });

    // Area 1: root -> v (cost 1), v advertises the same stub at cost 2. Total 3.
    let lsdb1 = manager.lsdb_for(area1).await;
    lsdb1.lock().await.install(router_lsa(
        router_id,
        RouterLink {
            tos: Vec::new(),
            link_id: v,
            link_data: Ipv4Addr::new(10, 0, 1, 1),
            link_type: LINK_TYPE_POINT_TO_POINT,
            metric: 1,
        },
    ));
    lsdb1.lock().await.install(Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: v,
            advertising_router: v,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Router(RouterLsaBody {
            flags: 0,
            links: vec![
                RouterLink {
                    tos: Vec::new(),
                    link_id: router_id,
                    link_data: Ipv4Addr::new(10, 0, 1, 2),
                    link_type: LINK_TYPE_POINT_TO_POINT,
                    metric: 1,
                },
                RouterLink {
                    tos: Vec::new(),
                    link_id: prefix_net,
                    link_data: mask,
                    link_type: LINK_TYPE_STUB_NETWORK,
                    metric: 2,
                },
            ],
        }),
    });

    // `router_id` must be set for `compute_routes` to run at all.
    manager
        .reconcile(Vec::new(), HashMap::new(), router_id)
        .await;

    let routes = manager.compute_routes().await;
    let route = routes
        .iter()
        .find(|r| r.prefix == Ipv4Net::new(prefix_net, 24).unwrap())
        .unwrap();
    assert_eq!(route.metric, 3);
    assert_eq!(route.next_hops, vec![Ipv4Addr::new(10, 0, 1, 2)]);

    // Area 1's stub re-costed to 12: 1 + 12 = 13, equal to area 0's —
    // both areas' next hops are kept.
    lsdb1.lock().await.install(Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: v,
            advertising_router: v,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER + 1,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Router(RouterLsaBody {
            flags: 0,
            links: vec![
                RouterLink {
                    tos: Vec::new(),
                    link_id: router_id,
                    link_data: Ipv4Addr::new(10, 0, 1, 2),
                    link_type: LINK_TYPE_POINT_TO_POINT,
                    metric: 1,
                },
                RouterLink {
                    tos: Vec::new(),
                    link_id: prefix_net,
                    link_data: mask,
                    link_type: LINK_TYPE_STUB_NETWORK,
                    metric: 12,
                },
            ],
        }),
    });
    let routes = manager.compute_routes().await;
    let route = routes
        .iter()
        .find(|r| r.prefix == Ipv4Net::new(prefix_net, 24).unwrap())
        .unwrap();
    assert_eq!(route.metric, 13);
    assert_eq!(
        route.next_hops,
        vec![Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 1, 2)]
    );
}

#[tokio::test]
async fn database_summaries_flattens_every_area() {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let area = Ipv4Addr::UNSPECIFIED;
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let lsdb = manager.lsdb_for(area).await;
    lsdb.lock().await.install(Lsa {
        header: LsaHeader {
            age: 5,
            options: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router_id,
            advertising_router: router_id,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0xabcd,
            length: 0,
        },
        body: LsaBody::Router(RouterLsaBody {
            flags: 0,
            links: Vec::new(),
        }),
    });

    let summaries = manager.database_summaries().await;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].area_id, area);
    assert_eq!(summaries[0].lsa_type, lsa::LSA_TYPE_ROUTER);
    assert_eq!(summaries[0].link_state_id, router_id);
    assert_eq!(summaries[0].advertising_router, router_id);
    assert_eq!(summaries[0].sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
    assert_eq!(summaries[0].age, 5);
    assert_eq!(summaries[0].checksum, 0xabcd);
}

/// RFC 2328 §12.4 `MinLSInterval`: changed content is held back until
/// the held instance is `MIN_LS_INTERVAL` old, then re-originated with a
/// bumped sequence number.
#[test]
fn install_self_originated_changed_body_bumps_sequence_number_after_min_ls_interval() {
    let mut lsdb = Lsdb::new();
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let key = router_key(local_router_id);
    install_self_originated(
        &mut lsdb,
        local_router_id,
        lsa::LSA_TYPE_ROUTER,
        local_router_id,
        router_body(0),
    );
    lsdb.age_and_evict(lsa::MIN_LS_INTERVAL - 1, &HashSet::new());
    install_self_originated(
        &mut lsdb,
        local_router_id,
        lsa::LSA_TYPE_ROUTER,
        local_router_id,
        router_body(1),
    );
    let held = lsdb.get(&key).unwrap();
    assert_eq!(held.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
    assert_eq!(held.body, router_body(0));

    lsdb.age_and_evict(1, &HashSet::new());
    install_self_originated(
        &mut lsdb,
        local_router_id,
        lsa::LSA_TYPE_ROUTER,
        local_router_id,
        router_body(1),
    );
    let held = lsdb.get(&key).unwrap();
    assert_eq!(
        held.header.sequence_number,
        lsa::INITIAL_SEQUENCE_NUMBER + 1
    );
    assert_eq!(held.header.age, 0);
    assert_eq!(held.body, router_body(1));
}

#[test]
fn run_election_keeps_a_neighbor_past_two_way_in_the_candidate_pool() {
    // Regression test: once a neighbor progresses to `ExStart` (or
    // beyond), it must stay eligible for DR/BDR election — excluding
    // it here would make this router think it's alone on the segment
    // and incorrectly re-elect itself DR on every subsequent
    // recomputation, flapping a segment that already converged.
    let mut cfg = link("bd1", 10);
    cfg.network_type = NetworkType::Broadcast;
    cfg.priority = 1;
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let neighbor_id = Ipv4Addr::new(9, 9, 9, 9);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::Broadcast));
    status.send_modify(|s| {
        // A previously-converged, stable outcome: the neighbor is DR
        // (and its own Hello already self-declares that), this router
        // is Backup.
        s.dr = Some(neighbor_id);
        s.bdr = Some(local_router_id);
        s.interface_state = InterfaceState::Backup;
        let mut info = neighbor_info(NeighborState::ExStart, Ipv4Addr::new(10, 0, 0, 2));
        info.declared_dr = neighbor_id;
        s.neighbors.insert(neighbor_id, info);
    });

    run_election(&cfg, local_router_id, &status);

    let result = status.borrow();
    assert_eq!(result.dr, Some(neighbor_id));
    assert_eq!(result.bdr, Some(local_router_id));
}

fn own_router_lsa(seq: i32, flags: u8) -> Lsa {
    let mut l = Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: id(1),
            advertising_router: id(1),
            sequence_number: seq,
            checksum: 0,
            length: 0,
        },
        body: router_body(flags),
    };
    lsa::fill_checksum(&mut l);
    l
}

/// RFC 2328 §13.4: a reflected newer copy is re-originated above it even
/// with an unchanged body, inside `MinLSInterval`; without the mark the same
/// call stays a no-op.
#[test]
fn install_self_originated_reoriginates_above_a_reflected_copy() {
    let mut lsdb = Lsdb::new();
    let key = router_key(id(1));
    let seq_after = |lsdb: &mut Lsdb| {
        install_self_originated(lsdb, id(1), lsa::LSA_TYPE_ROUTER, id(1), router_body(0));
        lsdb.get(&key).unwrap().header.sequence_number
    };
    lsdb.install(own_router_lsa(lsa::INITIAL_SEQUENCE_NUMBER + 9, 0));
    assert_eq!(seq_after(&mut lsdb), lsa::INITIAL_SEQUENCE_NUMBER + 9);
    lsdb.mark_reflected(key);
    assert_eq!(seq_after(&mut lsdb), lsa::INITIAL_SEQUENCE_NUMBER + 10);
    // The mark is consumed: no re-origination storm.
    assert_eq!(seq_after(&mut lsdb), lsa::INITIAL_SEQUENCE_NUMBER + 10);
}

#[test]
fn install_self_originated_reflected_at_max_sequence_flushes() {
    let mut lsdb = Lsdb::new();
    let key = router_key(id(1));
    lsdb.install(own_router_lsa(lsa::MAX_SEQUENCE_NUMBER, 0));
    lsdb.mark_reflected(key);
    install_self_originated(
        &mut lsdb,
        id(1),
        lsa::LSA_TYPE_ROUTER,
        id(1),
        router_body(0),
    );
    let held = lsdb.get(&key).unwrap();
    assert_eq!(held.header.age, lsa::MAX_AGE);
    assert_eq!(held.header.sequence_number, lsa::MAX_SEQUENCE_NUMBER);
}

/// A reflected own LSA is marked and wakes the originator; a foreign LSA
/// is not.
#[tokio::test]
async fn handle_lsu_marks_a_reflected_own_lsa_and_wakes_the_originator() {
    let neighbor_id = id(9);
    let cfg = link("eth0.0", 10);
    let n = Arc::new(tokio::sync::Notify::new());
    let lsdb = Mutex::new(Lsdb::new().with_reflect_notify(Arc::clone(&n)));
    let link_local = Mutex::new(Lsdb::new());
    lsdb.lock()
        .await
        .install(own_router_lsa(lsa::INITIAL_SEQUENCE_NUMBER, 0));
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    status.send_modify(|s| {
        let mut info = neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2));
        info.adjacency = Some(AdjacencyData::default());
        s.neighbors.insert(neighbor_id, info);
    });
    let lsu = |lsas| LsuPacket {
        router_id: neighbor_id,
        area_id: Ipv4Addr::UNSPECIFIED,
        lsas,
    };
    let mut foreign = own_router_lsa(lsa::INITIAL_SEQUENCE_NUMBER + 1, 0);
    foreign.header.link_state_id = id(2);
    foreign.header.advertising_router = id(2);
    rx::handle_lsu(
        &cfg,
        id(1),
        &status,
        &lsdb,
        &link_local,
        &lsu(vec![foreign]),
    )
    .await;
    assert_eq!(lsdb.lock().await.reflected_keys(), Vec::<LsaKey>::new());
    assert!(n.notified().now_or_never().is_none());

    let newer = own_router_lsa(lsa::INITIAL_SEQUENCE_NUMBER + 5, 1);
    rx::handle_lsu(&cfg, id(1), &status, &lsdb, &link_local, &lsu(vec![newer])).await;
    assert_eq!(lsdb.lock().await.reflected_keys(), vec![router_key(id(1))]);
    assert!(n.notified().now_or_never().is_some());
}

/// §13.4: a Network-LSA of a stale router-id whose Link State ID is one of
/// our addresses is flushed; one for another address is left alone.
#[test]
fn stale_network_lsa_for_our_address_is_flushed() {
    let mut lsdb = Lsdb::new();
    let network = |lsid: Ipv4Addr| {
        let mut l = own_router_lsa(lsa::INITIAL_SEQUENCE_NUMBER, 0);
        l.header.lsa_type = lsa::LSA_TYPE_NETWORK;
        l.header.link_state_id = lsid;
        l.header.advertising_router = id(7);
        l.body = LsaBody::Network(NetworkLsaBody {
            network_mask: Ipv4Addr::new(255, 255, 255, 0),
            attached_routers: vec![id(7)],
        });
        l
    };
    let ours = Ipv4Addr::new(10, 0, 0, 1);
    let (stale, other) = (network(ours), network(Ipv4Addr::new(10, 0, 0, 77)));
    lsdb.install(stale.clone());
    lsdb.install(other.clone());
    let flushed = flush_stale_network_lsas(&mut lsdb, id(1), &HashSet::from([ours]));
    assert_eq!(flushed, vec![stale.header.key()]);
    assert_eq!(
        lsdb.get(&stale.header.key()).unwrap().header.age,
        lsa::MAX_AGE
    );
    assert_eq!(lsdb.get(&other.header.key()).unwrap().header.age, 0);
    // Already flushed: nothing more to do.
    assert_eq!(
        flush_stale_network_lsas(&mut lsdb, id(1), &HashSet::from([ours])),
        Vec::<LsaKey>::new()
    );
}
