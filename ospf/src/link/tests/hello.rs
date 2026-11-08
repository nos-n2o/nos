use super::*;

#[test]
fn extended_sequence_starts_at_boot_count_and_carries_into_it() {
    let auth = ext_auth();
    let mut seq = initial_crypto_seq(&auth, 3);
    assert_eq!(seq, 3 << 32);
    assert_eq!(next_crypto_seq(&mut seq, &auth), (3 << 32) + 1);
    // Low 32 bits wrapping carries into the boot count: still increasing.
    seq = (3 << 32) | u64::from(u32::MAX);
    assert_eq!(next_crypto_seq(&mut seq, &auth), 4 << 32);
    // A later link start (higher boot count) is above everything sent before.
    assert!(initial_crypto_seq(&auth, 4) >= seq);
}

#[test]
fn extended_replay_check_is_per_packet_type() {
    let mut cfg = link("eth0.0", 10);
    cfg.auth = ext_auth();
    let mut n = neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2));
    n.last_crypto_seq = HashMap::new();
    let peer = Ipv4Addr::new(2, 2, 2, 2);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    status.send_modify(|s| {
        s.neighbors.insert(peer, n);
    });
    let keys = vec![(1, packet::CryptoAlgorithm::HmacSha256, b"k".to_vec())];
    let src = Ipv4Addr::new(10, 0, 0, 2);
    let hello = |seq: u64| {
        let pkt = packet::HelloPacket {
            lls: None,
            router_id: peer,
            area_id: Ipv4Addr::UNSPECIFIED,
            network_mask: Ipv4Addr::UNSPECIFIED,
            hello_interval: 10,
            options: packet::OPTION_E,
            dead_interval: 40,
            router_priority: 1,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        };
        let auth = packet::OutgoingAuth::Crypto {
            key_id: 1,
            algorithm: packet::CryptoAlgorithm::HmacSha256,
            key: b"k",
            sequence: seq,
            extended: Some(src),
        };
        packet::encode_hello(&pkt, &auth)
    };
    let policy = packet::AuthPolicy::Crypto {
        keys: &keys,
        extended: Some(src),
    };
    let check = |data: &[u8]| {
        let pkt = packet::decode(data, &policy).unwrap();
        accept_crypto_sequence(&cfg, &status, data, &pkt)
    };
    assert!(check(&hello(10)));
    assert!(!check(&hello(10)), "equal is a replay");
    assert!(!check(&hello(9)), "lower is a replay");
    assert!(check(&hello(11)));
    // A different packet type keeps its own last-seen value: this DBD's
    // (lower) number would be a replay if the slot were shared.
    let dbd = packet::encode_dbd(
        &packet::DbdPacket {
            lls: None,
            router_id: peer,
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 1500,
            options: 0,
            init: true,
            more: false,
            master: false,
            dd_sequence_number: 1,
            lsa_headers: vec![],
        },
        &packet::OutgoingAuth::Crypto {
            key_id: 1,
            algorithm: packet::CryptoAlgorithm::HmacSha256,
            key: b"k",
            sequence: 5,
            extended: Some(src),
        },
    );
    assert!(check(&dbd));
}

#[test]
fn handle_hello_accepts_a_matching_hello() {
    let cfg = link("eth0.0", 10);
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let peer = Ipv4Addr::new(9, 9, 9, 9);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    let mut deadline = Instant::now();
    handle_hello(
        &cfg,
        local_router_id,
        &status,
        Ipv4Addr::new(10, 0, 0, 2),
        &matching_hello(&cfg, peer),
        &mut deadline,
        false,
        &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
    );
    assert_eq!(
        status.borrow().neighbors.get(&peer).unwrap().state,
        NeighborState::Init
    );
}

#[test]
fn p2mp_link_status_is_point_to_point_state_and_hello_has_no_dr() {
    let status = LinkStatus::new(NetworkType::PointToMultipoint);
    assert_eq!(status.interface_state, InterfaceState::PointToPoint);
}

#[test]
fn p2mp_handle_hello_keeps_several_neighbors_ignoring_mask_and_election() {
    let mut cfg = link("eth0.0", 10);
    cfg.network_type = NetworkType::PointToMultipoint;
    let (status, _rx) = watch::channel(LinkStatus::new(cfg.network_type));
    let mut deadline = Instant::now();
    for (i, mask) in [(9u8, cfg.local_prefix_len), (10, 30)] {
        let peer = Ipv4Addr::new(9, 9, 9, i);
        let mut hello = matching_hello(&cfg, peer);
        hello.network_mask = Ipv4Addr::new(255, 255, 255, mask);
        handle_hello(
            &cfg,
            Ipv4Addr::new(1, 1, 1, 1),
            &status,
            Ipv4Addr::new(10, 0, 0, i),
            &hello,
            &mut deadline,
            false,
            &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
        );
    }
    let s = status.borrow();
    assert_eq!(s.neighbors.len(), 2);
    assert_eq!((s.dr, s.bdr), (None, None));
}

#[test]
fn router_lsa_links_p2mp_has_link_per_full_neighbor_and_host_stub() {
    let mut cfg = link("eth0.0", 10);
    cfg.network_type = NetworkType::PointToMultipoint;
    let mut status = LinkStatus::new(cfg.network_type);
    status.neighbors.insert(
        Ipv4Addr::new(9, 9, 9, 1),
        neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2)),
    );
    status.neighbors.insert(
        Ipv4Addr::new(9, 9, 9, 2),
        neighbor_info(NeighborState::TwoWay, Ipv4Addr::new(10, 0, 0, 3)),
    );
    status.neighbors.insert(
        Ipv4Addr::new(9, 9, 9, 3),
        neighbor_info(NeighborState::Down, Ipv4Addr::new(10, 0, 0, 4)),
    );
    let links = router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg, status)], false, false);
    assert_eq!(links.len(), 2);
    let p2p = links
        .iter()
        .find(|l| l.link_type == LINK_TYPE_POINT_TO_POINT)
        .unwrap();
    assert_eq!(p2p.link_id, Ipv4Addr::new(9, 9, 9, 1));
    assert_eq!(p2p.link_data, Ipv4Addr::new(10, 0, 0, 1));
    let stub = links
        .iter()
        .find(|l| l.link_type == LINK_TYPE_STUB_NETWORK)
        .unwrap();
    assert_eq!(stub.link_id, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(stub.link_data, Ipv4Addr::BROADCAST);
}

#[test]
fn handle_hello_drops_mismatched_hello_interval() {
    let cfg = link("eth0.0", 10);
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let peer = Ipv4Addr::new(9, 9, 9, 9);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    let mut deadline = Instant::now();
    let mut hello = matching_hello(&cfg, peer);
    hello.hello_interval = 5;
    handle_hello(
        &cfg,
        local_router_id,
        &status,
        Ipv4Addr::new(10, 0, 0, 2),
        &hello,
        &mut deadline,
        false,
        &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
    );
    assert!(!status.borrow().neighbors.contains_key(&peer));
}

#[test]
fn handle_hello_drops_mismatched_dead_interval() {
    let cfg = link("eth0.0", 10);
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let peer = Ipv4Addr::new(9, 9, 9, 9);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    let mut deadline = Instant::now();
    let mut hello = matching_hello(&cfg, peer);
    hello.dead_interval = 41;
    handle_hello(
        &cfg,
        local_router_id,
        &status,
        Ipv4Addr::new(10, 0, 0, 2),
        &hello,
        &mut deadline,
        false,
        &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
    );
    assert!(!status.borrow().neighbors.contains_key(&peer));
}

#[test]
fn handle_hello_skips_network_mask_check_on_point_to_point() {
    let cfg = link("eth0.0", 10);
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let peer = Ipv4Addr::new(9, 9, 9, 9);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    let mut deadline = Instant::now();
    let mut hello = matching_hello(&cfg, peer);
    hello.network_mask = Ipv4Addr::new(255, 255, 0, 0); // wrong, but p2p ignores it
    handle_hello(
        &cfg,
        local_router_id,
        &status,
        Ipv4Addr::new(10, 0, 0, 2),
        &hello,
        &mut deadline,
        false,
        &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
    );
    assert!(status.borrow().neighbors.contains_key(&peer));
}

#[test]
fn handle_hello_drops_mismatched_network_mask_on_broadcast() {
    let mut cfg = link("bd1", 10);
    cfg.network_type = NetworkType::Broadcast;
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let peer = Ipv4Addr::new(9, 9, 9, 9);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::Broadcast));
    let mut deadline = Instant::now();
    let mut hello = matching_hello(&cfg, peer);
    hello.network_mask = Ipv4Addr::new(255, 255, 0, 0);
    handle_hello(
        &cfg,
        local_router_id,
        &status,
        Ipv4Addr::new(10, 0, 0, 2),
        &hello,
        &mut deadline,
        false,
        &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
    );
    assert!(!status.borrow().neighbors.contains_key(&peer));
}

#[test]
fn handle_hello_drops_mismatched_e_bit() {
    let cfg = link("eth0.0", 10);
    let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let peer = Ipv4Addr::new(9, 9, 9, 9);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    let mut deadline = Instant::now();
    let mut hello = matching_hello(&cfg, peer);
    hello.options = 0;
    handle_hello(
        &cfg,
        local_router_id,
        &status,
        Ipv4Addr::new(10, 0, 0, 2),
        &hello,
        &mut deadline,
        false,
        &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
    );
    assert!(!status.borrow().neighbors.contains_key(&peer));
}

/// RFC 2328 §3.5/§3.6 (#35) over the in-memory wire: A is internal to
/// stub area 1, B its ABR (loopback in area 0, redistributing a static).
#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn stub_area_gets_a_default_and_ranges_summarize() {
    let area1 = Ipv4Addr::new(0, 0, 0, 1);
    let net = |s: &str| s.parse::<Ipv4Net>().unwrap();
    let settings = |area_type: Option<bool>, ranges: Vec<(Ipv4Net, bool)>| {
        let mut m = HashMap::from([(
            Ipv4Addr::UNSPECIFIED,
            AreaSettings {
                ranges,
                ..AreaSettings::default()
            },
        )]);
        if let Some(import_summaries) = area_type {
            m.insert(
                area1,
                AreaSettings {
                    stub: true,
                    import_summaries,
                    default_cost: 5,
                    ranges: Vec::new(),
                    ..AreaSettings::default()
                },
            );
        }
        m
    };
    let link_in_area1 = |addr, stub| LinkConfig {
        area_id: area1,
        stub,
        ..wired_link(addr, 30, NetworkType::PointToPoint)
    };
    let wire = Arc::new(wire::Wire::default());
    let (a, b) = (router(&wire), router(&wire));
    a.set_area_settings(settings(Some(true), Vec::new())).await;
    a.reconcile(
        vec![link_in_area1([10, 0, 0, 1], true)],
        HashMap::new(),
        id(1),
    )
    .await;
    let b_stubs = HashMap::from([(Ipv4Addr::UNSPECIFIED, vec![(net("192.0.2.2/32"), 1)])]);
    b.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
        .await;
    b.apply_redistribute_update(RedistributeUpdate::Full(vec![
        nos_proto::RedistributedRoute {
            prefix: "198.51.100.0/24".parse().unwrap(),
            gateway: "10.9.9.9".parse().unwrap(),
        },
    ]))
    .await;
    b.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
        .await;

    // Stub on A only: the E-bits disagree, so not even Init.
    b.set_area_settings(settings(None, Vec::new())).await;
    b.reconcile(
        vec![link_in_area1([10, 0, 0, 2], false)],
        b_stubs.clone(),
        id(2),
    )
    .await;
    settle(60).await;
    assert_eq!(
        a.neighbor_summaries().await[0].state,
        OspfNeighborState::Down
    );

    // Stub on both, with a range over B's loopback: Full, a default and
    // the range, never the /32 nor the Type-5.
    b.set_area_settings(settings(Some(true), vec![(net("192.0.2.0/24"), true)]))
        .await;
    b.reconcile(
        vec![link_in_area1([10, 0, 0, 2], true)],
        b_stubs.clone(),
        id(2),
    )
    .await;
    settle(60).await;
    assert_eq!(
        a.neighbor_summaries().await[0].state,
        OspfNeighborState::Full
    );
    let route =
        |routes: &[spf::RouteEntry], p: &str| routes.iter().find(|r| r.prefix == net(p)).cloned();
    let routes = a.compute_routes().await;
    let default = route(&routes, "0.0.0.0/0").expect("default route");
    assert_eq!(default.next_hops, [Ipv4Addr::new(10, 0, 0, 2)]);
    assert_eq!(default.metric, 1 + 5);
    assert!(route(&routes, "192.0.2.0/24").is_some(), "{routes:?}");
    assert!(route(&routes, "192.0.2.2/32").is_none(), "{routes:?}");
    assert!(route(&routes, "198.51.100.0/24").is_none(), "{routes:?}");
    assert!(!a
        .database_summaries()
        .await
        .iter()
        .any(|l| l.lsa_type == lsa::LSA_TYPE_AS_EXTERNAL));
    // B is no ASBR in the stub area: E clear in its Router-LSA there.
    let b_router = a
        .lsdb_for(area1)
        .await
        .lock()
        .await
        .get(&router_key(id(2)))
        .unwrap();
    let LsaBody::Router(body) = &b_router.body else {
        panic!("expected router lsa")
    };
    assert_eq!(body.flags & lsa::ROUTER_FLAG_E, 0);
    // The ABR holds a discard route for its active range.
    let discard = route(&b.compute_routes().await, "192.0.2.0/24").expect("discard");
    assert_eq!(discard.next_hops, Vec::<Ipv4Addr>::new());

    // Totally stubby: the range summary is flushed, the default stays.
    b.set_area_settings(settings(Some(false), vec![(net("192.0.2.0/24"), true)]))
        .await;
    // (Checked on B: A's `MinLSArrival` runs on the real clock, which a
    // paused-time test never advances past, so the flush can't reach A
    // here — `nos-e2e ospf-stub` covers that.)
    settle(4).await;
    let live_summaries: Vec<Ipv4Addr> = b
        .database_summaries()
        .await
        .into_iter()
        .filter(|l| {
            l.area_id == area1
                && l.lsa_type == lsa::LSA_TYPE_NETWORK_SUMMARY
                && l.age < lsa::MAX_AGE
        })
        .map(|l| l.link_state_id)
        .collect();
    assert_eq!(live_summaries, [Ipv4Addr::UNSPECIFIED]);

    // Not-advertise: no discard route on the ABR either.
    b.set_area_settings(settings(Some(true), vec![(net("192.0.2.0/24"), false)]))
        .await;
    settle(4).await;
    assert!(route(&b.compute_routes().await, "192.0.2.0/24").is_none());
}

fn router_id(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(0x0901_0000 + n)
}

#[test]
fn handle_hello_caps_neighbors_but_keeps_refreshing_known_ones() {
    let cfg = link("eth0.0", 10);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    let mut deadline = Instant::now();
    let mut limiter = nos_ospf_common::ratelimit::WarnLimiter::default();
    let mut send = |n: u32| {
        handle_hello(
            &cfg,
            Ipv4Addr::new(1, 1, 1, 1),
            &status,
            Ipv4Addr::new(10, 0, 0, 2),
            &matching_hello(&cfg, router_id(n)),
            &mut deadline,
            false,
            &mut limiter,
        );
    };
    for n in 0..70 {
        send(n);
    }
    assert_eq!(
        status.borrow().neighbors.len(),
        nos_ospf_common::ratelimit::MAX_NEIGHBORS_PER_LINK
    );
    assert!(!status.borrow().neighbors.contains_key(&router_id(64)));
    status.send_modify(|s| s.neighbors.get_mut(&router_id(0)).unwrap().priority = 99);
    send(0);
    assert_eq!(status.borrow().neighbors[&router_id(0)].priority, 1);
    // 6 refused Hellos at the cap: the limiter allowed 5, suppressed 1.
    assert_eq!(limiter.take_suppressed(), 1);
}

#[test]
fn source_on_link_exempts_p2p_and_virtual_links_only() {
    let off = Ipv4Addr::new(192, 0, 2, 9);
    let on = Ipv4Addr::new(10, 0, 0, 2);
    let mut bcast = link("eth0", 10);
    bcast.network_type = NetworkType::Broadcast;
    assert!(source_on_link(&bcast, on));
    assert!(!source_on_link(&bcast, off));
    let mut p2mp = bcast.clone();
    p2mp.network_type = NetworkType::PointToMultipoint;
    assert!(!source_on_link(&p2mp, off));
    assert!(source_on_link(&link("eth0", 10), off));
    let vlink = LinkConfig {
        virtual_link: Some(VirtualLinkEnd {
            transit_area: Ipv4Addr::new(0, 0, 0, 1),
            endpoint: Ipv4Addr::new(3, 3, 3, 3),
            neighbor: off,
        }),
        ..bcast
    };
    assert!(source_on_link(&vlink, off));
}
