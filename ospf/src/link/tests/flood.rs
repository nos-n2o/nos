//! #879: LSU flooding and delayed `LSAck` go to 224.0.0.5/224.0.0.6 on broadcast links.
use super::wire::To;
use super::*;

const LSU: u8 = 4;
const LSACK: u8 = 5;

fn sent(wire: &wire::Wire, from: u8, ty: u8) -> Vec<To> {
    wire.sent
        .lock()
        .unwrap()
        .iter()
        .filter(|(f, _, t)| *f == Ipv4Addr::new(10, 0, 0, from) && *t == ty)
        .map(|(_, to, _)| *to)
        .collect()
}

/// Three routers on one broadcast net: 1 = DR, 2 = BDR, 3 = `DROther`.
async fn trio(wire: &Arc<wire::Wire>) -> Vec<Arc<LinkManager>> {
    let mut out = Vec::new();
    for n in 1..=3u8 {
        let m = router(wire);
        let mut l = wired_link([10, 0, 0, n], 24, NetworkType::Broadcast);
        l.priority = 4 - n;
        m.reconcile(vec![l], stub(&format!("192.0.2.{n}/32")), id(n))
            .await;
        out.push(m);
    }
    out
}

#[tokio::test(start_paused = true)]
async fn drother_uses_all_drouters_and_dr_bdr_use_all_spf() {
    let wire = Arc::new(wire::Wire::default());
    let m = trio(&wire).await;
    settle(90).await;
    // Steady-state floods go to 224.0.0.6 (only the LSR answers during
    // adjacency formation are unicast), acks only ever do.
    let c = sent(&wire, 3, LSU);
    assert!(c.last() == Some(&To::AllD), "{c:?}");
    assert!(c.iter().filter(|t| **t == To::AllD).count() >= 3, "{c:?}");
    assert!(sent(&wire, 3, LSACK).iter().all(|t| *t == To::AllD));
    // DR and BDR: 224.0.0.5.
    for n in [1, 2] {
        let s = sent(&wire, n, LSU);
        assert!(s.last() == Some(&To::AllSpf), "{n}: {s:?}");
        assert!(
            s.iter().filter(|t| **t == To::AllSpf).count() >= 3,
            "{n}: {s:?}"
        );
    }
    // The DR heard the DROther's LSA, and so did the BDR.
    for holder in [&m[0], &m[1]] {
        assert!(router_lsa_at(holder, id(3)).await.0 < 60);
    }
}

#[tokio::test(start_paused = true)]
async fn multicast_failure_falls_back_to_unicast() {
    let wire = Arc::new(wire::Wire::default());
    wire.fail_all_d
        .lock()
        .unwrap()
        .insert(Ipv4Addr::new(10, 0, 0, 3));
    let m = trio(&wire).await;
    settle(90).await;
    assert!(sent(&wire, 3, LSU)
        .iter()
        .any(|t| matches!(t, To::Unicast(_))));
    assert!(router_lsa_at(&m[0], id(3)).await.0 < 60);
}

#[tokio::test(start_paused = true)]
async fn point_to_point_never_uses_a_group_for_lsu_or_ack() {
    let wire = Arc::new(wire::Wire::default());
    for n in 1..=2u8 {
        router(&wire)
            .reconcile(
                vec![wired_link([10, 0, 0, n], 30, NetworkType::PointToPoint)],
                stub(&format!("192.0.2.{n}/32")),
                id(n),
            )
            .await;
    }
    settle(60).await;
    for n in [1, 2] {
        for ty in [LSU, LSACK] {
            let s = sent(&wire, n, ty);
            assert!(s.iter().all(|t| matches!(t, To::Unicast(_))), "{s:?}");
        }
    }
    assert!(sent(&wire, 1, LSU).len() > 1);
}

fn full_neighbor(n: u8, opaque: bool) -> (Ipv4Addr, NeighborInfo) {
    let mut info = neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, n));
    info.adjacency = Some(AdjacencyData {
        opaque_capable: opaque,
        ..Default::default()
    });
    (id(n), info)
}

fn dr_status(neighbors: &[(u8, bool)]) -> StatusHandle {
    let mut s = LinkStatus::new(NetworkType::Broadcast);
    s.interface_state = InterfaceState::Dr;
    for (n, opaque) in neighbors {
        let (k, v) = full_neighbor(*n, *opaque);
        s.neighbors.insert(k, v);
    }
    watch::channel(s).0
}

#[tokio::test]
async fn mixed_opaque_capability_multicasts_plain_and_unicasts_opaque() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let socket = wire.opener()(&cfg).unwrap();
    let status = dr_status(&[(2, true), (3, false)]);
    let mut area = Lsdb::new();
    area.install(opaque_lsa(lsa::LSA_TYPE_OPAQUE_AREA, id(9)));
    area.install(foreign_type5(0));
    let (area, link_local) = (Mutex::new(area), Mutex::new(Lsdb::new()));
    let mut last = None;
    flood_full_neighbors(
        &socket,
        &cfg,
        id(1),
        &area,
        &link_local,
        &status,
        &mut 0,
        &mut last,
    )
    .await;
    assert_eq!(last, Some(Dest::AllSpfRouters));
    let s = sent(&wire, 1, LSU);
    // One group packet (non-opaque) plus one unicast (opaque) to the capable peer.
    assert_eq!(s, vec![To::AllSpf, To::Unicast(Ipv4Addr::new(10, 0, 0, 2))]);
}

#[tokio::test]
async fn all_opaque_capable_is_one_group_packet() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let socket = wire.opener()(&cfg).unwrap();
    let status = dr_status(&[(2, true), (3, true)]);
    let mut area = Lsdb::new();
    area.install(opaque_lsa(lsa::LSA_TYPE_OPAQUE_AREA, id(9)));
    let (area, link_local) = (Mutex::new(area), Mutex::new(Lsdb::new()));
    flood_full_neighbors(
        &socket,
        &cfg,
        id(1),
        &area,
        &link_local,
        &status,
        &mut 0,
        &mut None,
    )
    .await;
    assert_eq!(sent(&wire, 1, LSU), vec![To::AllSpf]);
}

#[tokio::test]
async fn delayed_acks_are_one_deduplicated_group_set() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let socket = wire.opener()(&cfg).unwrap();
    let status = dr_status(&[(2, false), (3, false)]);
    let h = foreign_type5(0).header;
    status.send_modify(|s| {
        for n in s.neighbors.values_mut() {
            n.adjacency.as_mut().unwrap().pending_acks = vec![h];
        }
    });
    flush_pending_acks(&socket, &cfg, id(1), &status, &mut 0);
    assert_eq!(sent(&wire, 1, LSACK), vec![To::AllSpf]);
    assert!(status.borrow().neighbors.values().all(|n| n
        .adjacency
        .as_ref()
        .unwrap()
        .pending_acks
        .is_empty()));
    // Nothing left: no second packet.
    flush_pending_acks(&socket, &cfg, id(1), &status, &mut 0);
    assert_eq!(sent(&wire, 1, LSACK).len(), 1);
}

#[tokio::test]
async fn ack_group_failure_falls_back_to_unicast() {
    let wire = Arc::new(wire::Wire::default());
    wire.fail_all_d
        .lock()
        .unwrap()
        .insert(Ipv4Addr::new(10, 0, 0, 1));
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let socket = wire.opener()(&cfg).unwrap();
    let status = dr_status(&[(2, false)]);
    status.send_modify(|s| {
        s.interface_state = InterfaceState::DrOther;
        for n in s.neighbors.values_mut() {
            n.adjacency.as_mut().unwrap().pending_acks = vec![foreign_type5(0).header];
        }
    });
    flush_pending_acks(&socket, &cfg, id(1), &status, &mut 0);
    assert_eq!(
        sent(&wire, 1, LSACK),
        vec![To::Unicast(Ipv4Addr::new(10, 0, 0, 2))]
    );
}

#[tokio::test]
async fn destination_is_reported_only_on_change() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let socket = wire.opener()(&cfg).unwrap();
    let status = dr_status(&[]);
    let (area, link_local) = (Mutex::new(Lsdb::new()), Mutex::new(Lsdb::new()));
    let mut last = None;
    flood_full_neighbors(
        &socket,
        &cfg,
        id(1),
        &area,
        &link_local,
        &status,
        &mut 0,
        &mut last,
    )
    .await;
    assert_eq!(last, Some(Dest::AllSpfRouters));
    status.send_modify(|s| s.interface_state = InterfaceState::DrOther);
    flood_full_neighbors(
        &socket,
        &cfg,
        id(1),
        &area,
        &link_local,
        &status,
        &mut 0,
        &mut last,
    )
    .await;
    assert_eq!(last, Some(Dest::AllDRouters));
}

#[tokio::test]
async fn retransmission_resend_stays_unicast() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let socket = wire.opener()(&cfg).unwrap();
    let status = dr_status(&[(2, false)]);
    let l = foreign_type5(0);
    status.send_modify(|s| {
        let adj = s
            .neighbors
            .values_mut()
            .next()
            .unwrap()
            .adjacency
            .as_mut()
            .unwrap();
        adj.retransmission_list
            .insert(l.header.key(), Arc::new(l.clone()));
    });
    retransmit_pending(&socket, &cfg, id(1), &status, &mut 0);
    assert_eq!(
        sent(&wire, 1, LSU),
        vec![To::Unicast(Ipv4Addr::new(10, 0, 0, 2))]
    );
}
