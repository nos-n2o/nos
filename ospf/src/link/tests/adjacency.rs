use super::*;

#[tokio::test(start_paused = true)]
async fn point_to_point_pair_reaches_full_and_routes_to_the_far_loopback() {
    let wire = Arc::new(wire::Wire::default());
    let (a, b) = (router(&wire), router(&wire));
    a.reconcile(
        vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(1),
    )
    .await;
    b.reconcile(
        vec![wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)],
        stub("192.0.2.2/32"),
        id(2),
    )
    .await;
    // B also redistributes two overlapping static routes: two Type-5s
    // for A to learn, the /25 at the host-bits ID (RFC 2328 Appendix E).
    b.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
        .await;
    b.apply_redistribute_update(RedistributeUpdate::Full(
        ["198.51.100.0/24", "198.51.100.0/25"]
            .into_iter()
            .map(|prefix| nos_proto::RedistributedRoute {
                prefix: prefix.parse().unwrap(),
                gateway: "10.9.9.9".parse().unwrap(),
            })
            .collect(),
    ))
    .await;
    b.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
        .await;
    settle(60).await;

    let n = a.neighbor_summaries().await;
    assert_eq!(n.len(), 1);
    assert_eq!(n[0].state, OspfNeighborState::Full, "{n:?}");
    assert_eq!(n[0].neighbor_router_id, Some(id(2)));
    let routes = a.compute_routes().await;
    for prefix in ["192.0.2.2/32", "198.51.100.0/24", "198.51.100.0/25"] {
        let r = routes
            .iter()
            .find(|r| r.prefix == prefix.parse::<Ipv4Net>().unwrap())
            .unwrap_or_else(|| panic!("no route to {prefix}: {routes:?}"));
        assert_eq!(r.next_hops, [Ipv4Addr::new(10, 0, 0, 2)]);
    }
    assert!(a
        .database_summaries()
        .await
        .iter()
        .any(|l| l.lsa_type == 5 && l.advertising_router == id(2)));
    // RFC 2328 A.4.2 (#34): B's Router-LSA reached A with E set.
    let b_router = a
        .lsdb_for(Ipv4Addr::UNSPECIFIED)
        .await
        .lock()
        .await
        .get(&LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: id(2),
            advertising_router: id(2),
        })
        .unwrap();
    let LsaBody::Router(body) = &b_router.body else {
        panic!("expected router lsa")
    };
    assert_eq!(body.flags, lsa::ROUTER_FLAG_E);

    // B goes silent: A's dead interval drops the neighbor.
    wire.cut.lock().unwrap().insert(Ipv4Addr::new(10, 0, 0, 2));
    settle(60).await;
    assert_eq!(
        a.neighbor_summaries().await[0].state,
        OspfNeighborState::Down
    );

    // Graceful shutdown flushes A's own LSAs.
    a.shutdown().await;
    assert_eq!(a.neighbor_summaries().await, []);
}

#[tokio::test(start_paused = true)]
async fn point_to_point_adjacency_survives_lost_hellos() {
    adjacency_survives_lost_hellos(NetworkType::PointToPoint).await;
}

#[tokio::test(start_paused = true)]
async fn broadcast_adjacency_survives_lost_hellos() {
    adjacency_survives_lost_hellos(NetworkType::Broadcast).await;
}

#[test]
fn note_alive_only_refreshes_an_adjacency() {
    let peer = Ipv4Addr::new(9, 9, 9, 9);
    let addr = Ipv4Addr::new(10, 0, 0, 2);
    for (state, refreshed) in [
        (NeighborState::Down, false),
        (NeighborState::Init, false),
        (NeighborState::TwoWay, false),
        (NeighborState::ExStart, true),
        (NeighborState::Full, true),
    ] {
        let mut info = neighbor_info(state, addr);
        let past = Instant::now().checked_sub(Duration::from_secs(30)).unwrap();
        info.last_heard = past;
        info.last_hello_received = past;
        let mut s = LinkStatus::new(NetworkType::PointToPoint);
        s.neighbors.insert(peer, info);
        let (status, _rx) = watch::channel(s);
        note_alive(&status, peer);
        let n = status.borrow().neighbors[&peer].clone();
        assert_eq!(n.last_heard > past, refreshed, "{state:?}");
        assert_eq!(n.last_hello_received, past, "{state:?}");
    }
    // An unknown router changes nothing.
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    note_alive(&status, peer);
    assert!(status.borrow().neighbors.is_empty());
}

#[tokio::test(start_paused = true)]
async fn broadcast_segment_elects_dr_and_bdr_and_dr_others_stay_two_way() {
    let wire = Arc::new(wire::Wire::default());
    let segment: Vec<_> = (1..=4).map(|_| router(&wire)).collect();
    for (i, r) in segment.iter().enumerate() {
        let n = u8::try_from(i + 1).unwrap();
        r.reconcile(
            vec![wired_link([10, 1, 0, n], 24, NetworkType::Broadcast)],
            stub(&format!("192.0.2.{n}/32")),
            id(n),
        )
        .await;
    }
    settle(120).await;

    let one = segment[0].neighbor_summaries().await;
    assert_eq!(one.len(), 3, "{one:?}");
    for n in &one {
        assert_eq!(n.dr, Some(id(4)));
        assert_eq!(n.bdr, Some(id(3)));
        assert_eq!(n.interface_state, LinkInterfaceState::DrOther);
        let want = if n.neighbor_router_id == Some(id(2)) {
            OspfNeighborState::TwoWay
        } else {
            OspfNeighborState::Full
        };
        assert_eq!(n.state, want, "{n:?}");
    }
    let routes = segment[0].compute_routes().await;
    let to_four = routes
        .iter()
        .find(|r| r.prefix == "192.0.2.4/32".parse::<Ipv4Net>().unwrap())
        .unwrap_or_else(|| panic!("{routes:?}"));
    assert_eq!(to_four.next_hops, [Ipv4Addr::new(10, 1, 0, 4)]);
    // The DR originated a Network-LSA for the segment.
    assert!(segment[0]
        .database_summaries()
        .await
        .iter()
        .any(|l| l.lsa_type == 2 && l.advertising_router == id(4)));
}

#[tokio::test(start_paused = true)]
async fn matching_crypto_auth_reaches_full_and_a_mismatch_never_does() {
    assert_eq!(
        pair_with_auth(crypto(b"k", false), crypto(b"k", false)).await,
        OspfNeighborState::Full
    );
    assert_eq!(
        pair_with_auth(crypto(b"k", true), crypto(b"k", true)).await,
        OspfNeighborState::Full
    );
    let simple = || LinkAuthConfig::Simple {
        password: b"pw".to_vec(),
    };
    assert_eq!(
        pair_with_auth(simple(), simple()).await,
        OspfNeighborState::Full
    );
    assert_eq!(
        pair_with_auth(crypto(b"k", false), crypto(b"other", false)).await,
        OspfNeighborState::Down
    );
    assert_eq!(
        pair_with_auth(crypto(b"k", false), LinkAuthConfig::None).await,
        OspfNeighborState::Down
    );
}

#[tokio::test(start_paused = true)]
async fn tiny_dbd_budget_still_reaches_full() {
    let wire = Arc::new(wire::Wire::default());
    let mk = || {
        LinkManager::with_opener(
            1,
            Some(1),
            crate::boot::BootCounter::in_memory(),
            wire.opener(),
        )
    };
    let (a, b) = (mk(), mk());
    for (m, n, prefixes) in [(&a, 1u8, 3u8), (&b, 2, 3)] {
        m.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
            .await;
        m.apply_redistribute_update(RedistributeUpdate::Full(
            (0..prefixes)
                .map(|p| nos_proto::RedistributedRoute {
                    prefix: format!("198.51.{n}.{p}/32").parse().unwrap(),
                    gateway: "10.9.9.9".parse().unwrap(),
                })
                .collect(),
        ))
        .await;
        m.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
            .await;
        m.reconcile(
            vec![wired_link([10, 0, 0, n], 30, NetworkType::PointToPoint)],
            HashMap::new(),
            id(n),
        )
        .await;
    }
    // Let both originate before the adjacency forms, then restart A's
    // link so the DBD exchange carries several LSAs one at a time.
    settle(3).await;
    a.reconcile(Vec::new(), HashMap::new(), id(1)).await;
    a.reconcile(
        vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(1),
    )
    .await;
    settle(90).await;
    assert_eq!(
        a.neighbor_summaries().await[0].state,
        OspfNeighborState::Full
    );
    let externals = a
        .database_summaries()
        .await
        .into_iter()
        .filter(|l| l.lsa_type == 5 && l.advertising_router == id(2))
        .count();
    assert_eq!(externals, 3);
}

/// #146: A hits `SeqNumberMismatch` on its own side (a `BadLSReq`) while
/// Hellos keep both sides listed; B, still `Full`, must answer A's Init
/// DBD with `SeqNumberMismatch` too, or A sits in `ExStart` for good.
#[tokio::test(start_paused = true)]
async fn one_sided_seq_number_mismatch_renegotiates_back_to_full() {
    let wire = Arc::new(wire::Wire::default());
    let (a, b) = (router(&wire), router(&wire));
    let (a_addr, b_addr) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
    a.reconcile(
        vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(1),
    )
    .await;
    b.reconcile(
        vec![wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(2),
    )
    .await;
    settle(60).await;
    assert_eq!(
        a.neighbor_summaries().await[0].state,
        OspfNeighborState::Full
    );

    // A forged LSR "from B" for an LSA A doesn't hold: BadLSReq on A only.
    let lsr = LsrPacket {
        router_id: id(2),
        area_id: Ipv4Addr::UNSPECIFIED,
        requests: vec![LsaKey {
            lsa_type: 1,
            link_state_id: id(77),
            advertising_router: id(77),
        }],
    };
    let auth = LinkAuthConfig::None.as_outgoing(0, b_addr);
    wire.inject(b_addr, a_addr, &packet::encode_lsr(&lsr, &auth));
    // Renegotiation on the in-memory wire is near-instant, so there is no
    // reliable non-`Full` window to observe; without the fix A ends here
    // stuck in `ExStart`.
    settle(30).await;
    for (m, side) in [(&a, "a"), (&b, "b")] {
        assert_eq!(
            m.neighbor_summaries().await[0].state,
            OspfNeighborState::Full,
            "{side}"
        );
    }
}

#[test]
fn only_the_slave_keeps_its_final_dbd_once_full() {
    let cfg = link("eth0.0", 10);
    let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
    for is_master in [false, true] {
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        status.send_modify(|s| {
            let mut info = neighbor_info(NeighborState::Exchange, Ipv4Addr::new(10, 0, 0, 2));
            info.adjacency = Some(AdjacencyData::default());
            s.neighbors.insert(neighbor_id, info);
        });
        let (_, reply) = start_negotiation(&cfg, Ipv4Addr::new(9, 9, 9, 9));
        let adj = AdjacencyData {
            is_master,
            ..Default::default()
        };
        finish_neighbor_event(
            &cfg,
            Ipv4Addr::new(9, 9, 9, 9),
            &status,
            neighbor_id,
            NeighborState::Exchange,
            adj,
            vec![
                exchange::Action::SendDbd(reply.clone()),
                exchange::Action::NeighborEvent(neighbor::Event::ExchangeDone {
                    more_to_load: false,
                }),
            ],
        );
        let s = status.borrow();
        let info = &s.neighbors[&neighbor_id];
        assert_eq!(info.state, NeighborState::Full);
        let kept = info.adjacency.as_ref().unwrap().last_dbd_sent.clone();
        assert_eq!(kept, (!is_master).then_some(reply), "is_master={is_master}");
    }
}

#[tokio::test]
async fn retransmit_pending_resends_a_dbd_only_while_negotiating() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
    let socket = (wire.opener())(&cfg).unwrap();
    let LinkSocket::Mem(peer) =
        (wire.opener())(&wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)).unwrap()
    else {
        unreachable!()
    };
    let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
    let (_, dbd) = start_negotiation(&cfg, Ipv4Addr::new(9, 9, 9, 9));
    for (state, sent) in [
        (NeighborState::Full, false),
        (NeighborState::Loading, false),
        (NeighborState::Exchange, true),
    ] {
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        status.send_modify(|s| {
            let mut info = neighbor_info(state, Ipv4Addr::new(10, 0, 0, 2));
            info.adjacency = Some(AdjacencyData {
                last_dbd_sent: Some(dbd.clone()),
                ..Default::default()
            });
            s.neighbors.insert(neighbor_id, info);
        });
        let mut seq = 0;
        retransmit_pending(&socket, &cfg, Ipv4Addr::new(9, 9, 9, 9), &status, &mut seq);
        let got = tokio::time::timeout(Duration::from_millis(20), peer.recv()).await;
        assert_eq!(got.is_ok(), sent, "{state:?}");
    }
}

/// RFC 2328 §13.7: an `LSAck` from a neighbor below Exchange is ignored.
#[test]
fn lsack_ignored_below_exchange() {
    let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
    let header = LsaHeader {
        age: 0,
        options: 0,
        lsa_type: lsa::LSA_TYPE_ROUTER,
        link_state_id: neighbor_id,
        advertising_router: neighbor_id,
        sequence_number: 0x8000_0001u32.cast_signed(),
        checksum: 1,
        length: 24,
    };
    let key = header.key();
    for (state, cleared) in [
        (NeighborState::ExStart, false),
        (NeighborState::Exchange, true),
    ] {
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        status.send_modify(|s| {
            let mut info = neighbor_info(state, Ipv4Addr::new(10, 0, 0, 2));
            let mut adj = AdjacencyData::default();
            adj.retransmission_list.insert(
                key,
                Arc::new(Lsa {
                    header,
                    body: router_body(0),
                }),
            );
            info.adjacency = Some(adj);
            s.neighbors.insert(neighbor_id, info);
        });
        rx::handle_lsack(
            &status,
            &LsAckPacket {
                router_id: neighbor_id,
                area_id: Ipv4Addr::UNSPECIFIED,
                lsa_headers: vec![header],
            },
        );
        let left = status.borrow().neighbors[&neighbor_id]
            .adjacency
            .as_ref()
            .unwrap()
            .retransmission_list
            .len();
        assert_eq!(left == 0, cleared, "{state:?}");
    }
}

/// RFC 2328 §10.7/§13: LSR and LSU from a neighbor below Exchange are
/// ignored; from Exchange they are handled.
#[tokio::test]
async fn lsr_and_lsu_ignored_below_exchange() {
    let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
    let cfg = link("eth0.0", 10);
    let (lsdb, link_local) = (Mutex::new(Lsdb::new()), Mutex::new(Lsdb::new()));
    for (state, handled) in [
        (NeighborState::ExStart, false),
        (NeighborState::Exchange, true),
    ] {
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        status.send_modify(|s| {
            let mut info = neighbor_info(state, Ipv4Addr::new(10, 0, 0, 2));
            info.adjacency = Some(AdjacencyData::default());
            s.neighbors.insert(neighbor_id, info);
        });
        let lsr = LsrPacket {
            router_id: neighbor_id,
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![],
        };
        let got = rx::handle_lsr(&cfg, id(1), &status, &lsdb, &link_local, &lsr).await;
        assert_eq!(got.is_some(), handled, "lsr {state:?}");
        let lsu = LsuPacket {
            discarded: 0,
            last_error: None,
            router_id: neighbor_id,
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![],
        };
        let got = rx::handle_lsu(&cfg, id(1), &status, &lsdb, &link_local, &lsu).await;
        assert_eq!(got.is_some(), handled, "lsu {state:?}");
    }
}
