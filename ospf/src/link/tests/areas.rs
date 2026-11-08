use super::*;

#[test]
fn handle_hello_matches_the_e_bit_to_the_stub_flag() {
    let cfg = LinkConfig {
        stub: true,
        ..link("eth0.0", 10)
    };
    let peer = Ipv4Addr::new(9, 9, 9, 9);
    for (options, accepted) in [(packet::OPTION_E, false), (0, true)] {
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        let hello = packet::HelloPacket {
            options,
            ..matching_hello(&cfg, peer)
        };
        handle_hello(
            &cfg,
            Ipv4Addr::new(1, 1, 1, 1),
            &status,
            Ipv4Addr::new(10, 0, 0, 2),
            &hello,
            &mut Instant::now(),
            false,
            &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
        );
        assert_eq!(status.borrow().neighbors.contains_key(&peer), accepted);
    }
}

/// RFC 3101 §2.1: the N-bit must match the link's NSSA-ness (with the
/// E-bit clear in an NSSA).
#[test]
fn handle_hello_matches_the_n_bit_to_the_nssa_flag() {
    let peer = Ipv4Addr::new(9, 9, 9, 9);
    for (nssa, options, accepted) in [
        (true, packet::OPTION_N, true),
        (true, 0, false),
        (false, packet::OPTION_N | packet::OPTION_E, false),
        (false, packet::OPTION_E, true),
    ] {
        let cfg = LinkConfig {
            stub: nssa,
            nssa,
            ..link("eth0.0", 10)
        };
        assert_eq!(hello_options(&cfg) & packet::OPTION_N != 0, nssa);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        let hello = packet::HelloPacket {
            options,
            ..matching_hello(&cfg, peer)
        };
        handle_hello(
            &cfg,
            Ipv4Addr::new(1, 1, 1, 1),
            &status,
            Ipv4Addr::new(10, 0, 0, 2),
            &hello,
            &mut Instant::now(),
            false,
            &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
        );
        assert_eq!(
            status.borrow().neighbors.contains_key(&peer),
            accepted,
            "nssa={nssa} options={options}"
        );
    }
}

/// RFC 3101 (#36) over the in-memory wire: C is internal to NSSA area 1
/// and redistributes a static, B is the area's only ABR (so its
/// translator), A is in the backbone only.
#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn nssa_type7_is_translated_into_the_backbone() {
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let settings = HashMap::from([(
        area1,
        AreaSettings {
            stub: true,
            nssa: true,
            import_summaries: true,
            default_cost: 1,
            ..AreaSettings::default()
        },
    )]);
    let in_area1 = |addr| LinkConfig {
        area_id: area1,
        stub: true,
        nssa: true,
        ..wired_link(addr, 30, NetworkType::PointToPoint)
    };
    let wire = Arc::new(wire::Wire::default());
    let (a, b, c) = (router(&wire), router(&wire), router(&wire));
    for r in [&a, &b, &c] {
        r.set_area_settings(settings.clone()).await;
    }
    let prefix: Ipv4Net = "198.51.100.0/24".parse().unwrap();
    let redistribute = |routes: Vec<Ipv4Net>| {
        RedistributeUpdate::Full(
            routes
                .into_iter()
                .map(|p| nos_proto::RedistributedRoute {
                    prefix: p.into(),
                    gateway: "10.9.9.9".parse().unwrap(),
                })
                .collect(),
        )
    };
    c.apply_redistribute_update(redistribute(vec![prefix]))
        .await;
    c.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
        .await;
    a.reconcile(
        vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(1),
    )
    .await;
    b.reconcile(
        vec![
            wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint),
            in_area1([10, 0, 1, 1]),
        ],
        HashMap::new(),
        id(2),
    )
    .await;
    c.reconcile(vec![in_area1([10, 0, 1, 2])], HashMap::new(), id(3))
        .await;
    settle(60).await;

    let held = |lsdbs: Vec<LsaSummary>, lsa_type| -> Vec<(Ipv4Addr, Ipv4Addr)> {
        lsdbs
            .into_iter()
            .filter(|l| l.lsa_type == lsa_type && l.age < lsa::MAX_AGE)
            .map(|l| (l.link_state_id, l.advertising_router))
            .collect()
    };
    let net = prefix.network();
    // The backbone holds B's translated Type-5 and no Type-7.
    assert_eq!(
        held(a.database_summaries().await, lsa::LSA_TYPE_AS_EXTERNAL),
        [(net, id(2))]
    );
    assert_eq!(
        held(a.database_summaries().await, lsa::LSA_TYPE_NSSA_EXTERNAL),
        vec![]
    );
    let route = a
        .compute_routes()
        .await
        .into_iter()
        .find(|r| r.prefix == prefix)
        .expect("translated route on A");
    assert_eq!(route.next_hops, [Ipv4Addr::new(10, 0, 0, 2)]);
    // The NSSA holds C's Type-7 (P-bit, forwarding address C's own
    // link address) and no Type-5.
    assert_eq!(
        held(c.database_summaries().await, lsa::LSA_TYPE_AS_EXTERNAL),
        vec![]
    );
    let type7 = b
        .lsdb_for(area1)
        .await
        .lock()
        .await
        .get(&LsaKey {
            lsa_type: lsa::LSA_TYPE_NSSA_EXTERNAL,
            link_state_id: net,
            advertising_router: id(3),
        })
        .expect("type-7 on B");
    assert_eq!(type7.header.options, lsa::OPTION_P);
    let LsaBody::AsExternal(body) = &type7.body else {
        panic!("expected an external body")
    };
    assert_eq!(body.forwarding_address, Ipv4Addr::new(10, 0, 1, 2));
    // B, the ABR, routes to it from the Type-7.
    assert!(b.compute_routes().await.iter().any(|r| r.prefix == prefix));

    // Redistribution removed: C flushes its Type-7. (B's Type-5 flush
    // can't follow here — `MinLSArrival` runs on the real clock, which a
    // paused-time test never advances; `nos-e2e ospf-nssa` covers it.)
    c.apply_redistribute_update(redistribute(Vec::new())).await;
    c.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
        .await;
    settle(4).await;
    assert_eq!(
        held(c.database_summaries().await, lsa::LSA_TYPE_NSSA_EXTERNAL),
        vec![]
    );
}

/// #288: a Full neighbor on a link with a `bfd` profile gets a session
/// (and a link without one doesn't); BFD reporting the path down kills it
/// at once, ahead of the 40s dead interval, and the next Hello restores it.
#[tokio::test(start_paused = true)]
async fn bfd_down_kills_a_full_neighbor_at_once() {
    let wire = Arc::new(wire::Wire::default());
    let (a, b) = (router(&wire), router(&wire));
    let la = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
    a.reconcile(vec![la.clone()], HashMap::new(), id(1)).await;
    b.reconcile(
        vec![wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(2),
    )
    .await;
    settle(60).await;
    let state = |m: &Arc<LinkManager>| {
        let m = Arc::clone(m);
        async move { m.neighbor_summaries().await[0].state }
    };
    assert_eq!(state(&a).await, OspfNeighborState::Full);
    assert!(a.target().await.is_empty(), "no profile, no session");

    a.set_bfd(HashMap::from([(
        la.attach_point.clone(),
        BfdProfile::default(),
    )]));
    let want = a.target().await;
    assert_eq!(want.len(), 1);
    let peer = IpAddr::from([10, 0, 0, 2]);
    assert_eq!(want[&peer].local, Some(IpAddr::from([10, 0, 0, 1])));

    a.down(IpAddr::from([10, 0, 0, 9]), BfdDiag::PathDown).await;
    settle(1).await;
    assert_eq!(state(&a).await, OspfNeighborState::Full, "stranger");
    a.down(peer, BfdDiag::ControlDetectionTimeExpired).await;
    settle(1).await;
    assert_eq!(state(&a).await, OspfNeighborState::Down);
    assert!(a.target().await.is_empty(), "deregistered below 2-Way");
    settle(60).await;
    assert_eq!(
        state(&a).await,
        OspfNeighborState::Full,
        "Hello restores it"
    );
}

/// RFC 5250 scoping over the wire: X floods a type 9, 10 and 11 to A on
/// link 1; A keeps the type 9 in link 1's own store and floods only the
/// type 10 and 11 on to B over link 2.
#[tokio::test(start_paused = true)]
async fn opaque_lsas_are_flooded_by_scope() {
    let wire = Arc::new(wire::Wire::default());
    let (x, a, b) = (router(&wire), router(&wire), router(&wire));
    x.reconcile(
        vec![wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(3),
    )
    .await;
    a.reconcile(
        vec![
            wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint),
            wired_link([10, 0, 1, 1], 30, NetworkType::PointToPoint),
        ],
        HashMap::new(),
        id(1),
    )
    .await;
    b.reconcile(
        vec![wired_link([10, 0, 1, 2], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(2),
    )
    .await;
    settle(60).await;

    let origin = id(9);
    {
        let area = x.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
        let mut area = area.lock().await;
        for t in [lsa::LSA_TYPE_OPAQUE_AREA, lsa::LSA_TYPE_OPAQUE_AS] {
            area.install(opaque_lsa(t, origin));
        }
        let links = x.links.lock().await;
        let link = &links.values().next().unwrap().link_local_lsdb;
        link.lock()
            .await
            .install(opaque_lsa(lsa::LSA_TYPE_OPAQUE_LINK, origin));
    }
    settle(30).await;

    assert_eq!(
        types_from(&a.database_summaries().await, origin),
        [9, 10, 11]
    );
    let a_area = a.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
    assert!(a_area
        .lock()
        .await
        .headers()
        .iter()
        .all(|h| h.lsa_type != lsa::LSA_TYPE_OPAQUE_LINK));
    assert_eq!(types_from(&b.database_summaries().await, origin), [10, 11]);
}

/// A cost change (a virtual link's SPF distance, a profile's cost) keeps
/// the link running; an address change restarts it.
#[test]
fn diff_ignores_cost_but_not_the_virtual_neighbor() {
    let mut running = link("vlink", 10);
    running.virtual_link = Some(VirtualLinkEnd {
        transit_area: Ipv4Addr::new(0, 0, 0, 1),
        endpoint: id(3),
        neighbor: Ipv4Addr::new(10, 0, 1, 2),
    });
    let current = HashMap::from([("vlink".to_string(), running.clone())]);
    let cheaper = LinkConfig {
        cost: 9,
        ..running.clone()
    };
    let (stop, spawn) = diff_links(&current, &HashMap::from([("vlink".to_string(), cheaper)]));
    assert_eq!((stop.len(), spawn.len()), (0, 0));
    let mut moved = running;
    moved.virtual_link.as_mut().unwrap().neighbor = Ipv4Addr::new(10, 0, 1, 9);
    let (stop, spawn) = diff_links(&current, &HashMap::from([("vlink".to_string(), moved)]));
    assert_eq!((stop.len(), spawn.len()), (1, 1));
}

/// RFC 2328 §8.2: a virtual link takes only backbone packets from its
/// endpoint; a transit link drops backbone packets; a backbone link and
/// a mismatched non-backbone Hello (left to `handle_hello`) pass.
#[test]
fn accepts_packet_demuxes_virtual_link_traffic_by_area_and_source() {
    let packet = |area: [u8; 4]| {
        let mut data = vec![0u8; 24];
        data[8..12].copy_from_slice(&area);
        data
    };
    let (backbone, area1, area2) = (packet([0; 4]), packet([0, 0, 0, 1]), packet([0, 0, 0, 2]));
    let endpoint = Ipv4Addr::new(10, 0, 1, 2);
    let vlink = LinkConfig {
        virtual_link: Some(VirtualLinkEnd {
            transit_area: Ipv4Addr::new(0, 0, 0, 1),
            endpoint: id(3),
            neighbor: endpoint,
        }),
        ..link("vlink", 10)
    };
    assert!(accepts_packet(&vlink, endpoint, &backbone));
    assert!(!accepts_packet(
        &vlink,
        Ipv4Addr::new(10, 0, 1, 3),
        &backbone
    ));
    assert!(!accepts_packet(&vlink, endpoint, &area1));
    let transit = LinkConfig {
        area_id: Ipv4Addr::new(0, 0, 0, 1),
        ..link("eth1", 10)
    };
    assert!(!accepts_packet(&transit, endpoint, &backbone));
    assert!(accepts_packet(&transit, endpoint, &area1));
    assert!(accepts_packet(&transit, endpoint, &area2));
    assert!(accepts_packet(&link("eth0", 10), endpoint, &backbone));
    assert!(!accepts_packet(&vlink, endpoint, &[0u8; 4]));
}

/// RFC 2328 §16.7: up through the transit link toward the endpoint, at the
/// path's cost, with the endpoint's address; down with no path or no
/// transit-area link of ours.
#[test]
fn resolve_virtual_link_up_down_and_address() {
    let rlsa = |router: Ipv4Addr, links: Vec<RouterLink>| {
        Arc::new(Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: router,
                advertising_router: router,
                sequence_number: 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody { flags: 0, links }),
        })
    };
    let p2p = |to: Ipv4Addr, own: [u8; 4], metric| RouterLink {
        tos: Vec::new(),
        link_id: to,
        link_data: Ipv4Addr::from(own),
        link_type: LINK_TYPE_POINT_TO_POINT,
        metric,
    };
    let lsas = vec![
        rlsa(id(2), vec![p2p(id(3), [10, 0, 1, 1], 4)]),
        rlsa(id(3), vec![p2p(id(2), [10, 0, 1, 2], 4)]),
    ];
    let transit = LinkConfig {
        area_id: Ipv4Addr::new(0, 0, 0, 1),
        local_addr: Ipv4Addr::new(10, 0, 1, 1),
        local_prefix_len: 30,
        mtu: 1400,
        ..link("eth1", 10)
    };
    let physical = [link("eth0", 10), transit];
    let up = resolve_virtual_link(&vlink_config(id(3)), id(2), &lsas, &physical)
        .expect("endpoint reachable");
    assert_eq!(up.attach_point, "vlink-0.0.0.1-3.3.3.3");
    assert_eq!(up.area_id, Ipv4Addr::UNSPECIFIED);
    assert_eq!(up.cost, 4);
    assert_eq!(up.local_addr, Ipv4Addr::new(10, 0, 1, 1));
    assert_eq!(up.vrf, up.kernel_interface);
    assert_eq!((up.mtu, up.mtu_ignore), (1400, true));
    assert_eq!(local_netmask(&up), Ipv4Addr::UNSPECIFIED);
    assert_eq!(
        up.virtual_link.map(|v| v.neighbor),
        Some(Ipv4Addr::new(10, 0, 1, 2))
    );
    // No such endpoint, or none of our links in the transit area: down.
    assert!(resolve_virtual_link(&vlink_config(id(7)), id(2), &lsas, &physical).is_none());
    assert!(resolve_virtual_link(&vlink_config(id(3)), id(2), &lsas, &physical[..1]).is_none());
}

/// RFC 2328 §12.4.1.3: a type-4 link only while the virtual neighbor is
/// Full, never a stub.
#[test]
fn router_lsa_links_virtual_link_only_when_full() {
    let vlink = LinkConfig {
        cost: 7,
        local_prefix_len: 0,
        virtual_link: Some(VirtualLinkEnd {
            transit_area: Ipv4Addr::new(0, 0, 0, 1),
            endpoint: id(3),
            neighbor: Ipv4Addr::new(10, 0, 1, 2),
        }),
        ..link("vlink", 10)
    };
    let mut status = LinkStatus::new(NetworkType::PointToPoint);
    status.neighbors.insert(
        id(3),
        neighbor_info(NeighborState::Loading, Ipv4Addr::new(10, 0, 1, 2)),
    );
    let links = |status: &LinkStatus| {
        router_lsa_links(id(2), &[(vlink.clone(), status.clone())], false, false)
    };
    assert_eq!(links(&status), []);
    status.neighbors.get_mut(&id(3)).unwrap().state = NeighborState::Full;
    assert_eq!(
        links(&status),
        [RouterLink {
            tos: Vec::new(),
            link_id: id(3),
            link_data: Ipv4Addr::new(10, 0, 0, 1),
            link_type: LINK_TYPE_VIRTUAL,
            metric: 7,
        }]
    );
}

/// RFC 2328 §15 over the in-memory wire: A-B backbone, B-C transit area 1,
/// C's loopback in area 2 and no backbone link of its own. The virtual
/// link B-C comes up from area 1's SPF, reaches Full, puts a type-4 link
/// in both area-0 Router-LSAs and V in both area-1 ones, and carries C's
/// area-2 summary into the backbone, up to A.
#[tokio::test(start_paused = true)]
async fn virtual_link_reaches_full_and_joins_the_backbone() {
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let area2 = Ipv4Addr::new(0, 0, 0, 2);
    let in_area1 = |addr| LinkConfig {
        area_id: area1,
        ..wired_link(addr, 30, NetworkType::PointToPoint)
    };
    let wire = Arc::new(wire::Wire::default());
    let (a, b, c) = (router(&wire), router(&wire), router(&wire));
    a.reconcile(
        vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(1),
    )
    .await;
    b.set_virtual_links(vec![vlink_config(id(3))]).await;
    b.reconcile(
        vec![
            wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint),
            in_area1([10, 0, 1, 1]),
        ],
        HashMap::new(),
        id(2),
    )
    .await;
    c.set_virtual_links(vec![vlink_config(id(2))]).await;
    c.reconcile(
        vec![in_area1([10, 0, 1, 2])],
        HashMap::from([(area2, vec![("192.0.2.3/32".parse().unwrap(), 1)])]),
        id(3),
    )
    .await;
    settle(90).await;

    let vlink_state = |m: Arc<LinkManager>, name: &'static str| async move {
        m.neighbor_summaries()
            .await
            .into_iter()
            .find(|n| n.link == name)
            .map(|n| (n.area_id, n.state))
    };
    assert_eq!(
        vlink_state(Arc::clone(&b), "vlink-0.0.0.1-3.3.3.3").await,
        Some((Ipv4Addr::UNSPECIFIED, OspfNeighborState::Full))
    );
    assert_eq!(
        vlink_state(Arc::clone(&c), "vlink-0.0.0.1-2.2.2.2").await,
        Some((Ipv4Addr::UNSPECIFIED, OspfNeighborState::Full))
    );
    let own_router_lsa = |m: Arc<LinkManager>, router: Ipv4Addr, area| async move {
        let held = m.lsdb_for(area).await.lock().await.get(&router_key(router));
        match held.map(|l| l.body.clone()) {
            Some(LsaBody::Router(body)) => body,
            other => panic!("no router lsa: {other:?}"),
        }
    };
    for (m, own, far) in [(&b, id(2), id(3)), (&c, id(3), id(2))] {
        let backbone = own_router_lsa(Arc::clone(m), own, Ipv4Addr::UNSPECIFIED).await;
        assert!(
            backbone
                .links
                .iter()
                .any(|l| l.link_type == LINK_TYPE_VIRTUAL && l.link_id == far),
            "{backbone:?}"
        );
        let transit = own_router_lsa(Arc::clone(m), own, area1).await;
        assert_ne!(transit.flags & lsa::ROUTER_FLAG_V, 0);
        assert_ne!(backbone.flags & lsa::ROUTER_FLAG_B, 0);
    }
    // C's area-2 loopback, summarized into the backbone over the virtual
    // link, reaches A.
    let summary = LsaKey {
        lsa_type: lsa::LSA_TYPE_NETWORK_SUMMARY,
        link_state_id: Ipv4Addr::new(192, 0, 2, 3),
        advertising_router: id(3),
    };
    assert!(a
        .lsdb_for(Ipv4Addr::UNSPECIFIED)
        .await
        .lock()
        .await
        .get(&summary)
        .is_some());
    // The database report carries the flags and the virtual link.
    let reported = b
        .database_summaries()
        .await
        .into_iter()
        .find(|l| l.area_id.is_unspecified() && l.lsa_type == 1 && l.advertising_router == id(2))
        .expect("b's backbone router lsa");
    assert_eq!(reported.virtual_links, [id(3)]);

    // #226, §16.1: A reaches C's loopback through B's type-4 link (next
    // hop B), B through its transit-area next hop (C on area 1), and C
    // the backbone through B, which it also summarizes into area 2.
    let route = |m: Arc<LinkManager>, prefix: &'static str| async move {
        let prefix: Ipv4Net = prefix.parse().unwrap();
        m.compute_routes()
            .await
            .into_iter()
            .find(|r| r.prefix == prefix)
            .map(|r| r.next_hops)
    };
    let loopback = "192.0.2.3/32";
    assert_eq!(
        route(Arc::clone(&a), loopback).await,
        Some(vec![Ipv4Addr::new(10, 0, 0, 2)])
    );
    assert_eq!(
        route(Arc::clone(&b), loopback).await,
        Some(vec![Ipv4Addr::new(10, 0, 1, 2)])
    );
    assert_eq!(
        route(Arc::clone(&c), "10.0.0.0/30").await,
        Some(vec![Ipv4Addr::new(10, 0, 1, 1)])
    );
    let backbone_summary = LsaKey {
        lsa_type: lsa::LSA_TYPE_NETWORK_SUMMARY,
        link_state_id: Ipv4Addr::new(10, 0, 0, 0),
        advertising_router: id(3),
    };
    assert!(c
        .lsdb_for(area2)
        .await
        .lock()
        .await
        .get(&backbone_summary)
        .is_some());

    // §16.2: C drops its end, so the virtual link dies; C's area-1
    // summary of its loopback stays at B, but B (a backbone ABR) doesn't
    // route on it, and A loses the route too.
    c.set_virtual_links(Vec::new()).await;
    settle(90).await;
    let held = b.lsdb_for(area1).await.lock().await.get(&summary);
    assert!(held.is_some_and(|l| l.header.age < lsa::MAX_AGE));
    assert_eq!(route(Arc::clone(&b), loopback).await, None);
    assert_eq!(route(Arc::clone(&a), loopback).await, None);
    c.set_virtual_links(vec![vlink_config(id(2))]).await;

    // The endpoint unreachable (C's transit link gone): the link is down.
    c.reconcile(Vec::new(), HashMap::new(), id(3)).await;
    settle(90).await;
    assert_eq!(
        vlink_state(Arc::clone(&b), "vlink-0.0.0.1-3.3.3.3").await,
        None
    );
}
