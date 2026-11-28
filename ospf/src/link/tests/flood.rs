//! #879: LSU flooding and delayed `LSAck` go to 224.0.0.5/224.0.0.6 on broadcast links;
//! #1517: event-driven flooding, retransmission and acks.
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
    // A fresh LSA installed at each router leaves at once: DROther to
    // 224.0.0.6, DR and BDR to 224.0.0.5 (acks only ever go to a group).
    for (n, want) in [(3, To::AllD), (1, To::AllSpf), (2, To::AllSpf)] {
        let mut l = foreign_type5(0);
        l.header.link_state_id = Ipv4Addr::new(198, 51, 100 + n, 0);
        m[usize::from(n) - 1]
            .lsdb_for(Ipv4Addr::UNSPECIFIED)
            .await
            .lock()
            .await
            .install(l);
        settle(1).await;
        // Unicast LSUs may interleave: an older Router-LSA retransmission is
        // answered with the database copy (§13 step 8, #1626).
        let s = sent(&wire, n, LSU);
        let last_group = s.iter().rev().find(|t| !matches!(t, To::Unicast(_)));
        assert!(last_group == Some(&want), "{n}: {s:?}");
    }
    assert!(sent(&wire, 3, LSACK).iter().all(|t| *t == To::AllD));
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

fn ev(lsa: Lsa, origin: Option<nos_ospf_common::lsdb::Origin>) -> FloodEvent<Lsa> {
    FloodEvent {
        lsa: Arc::new(lsa),
        origin,
        outcome: InstallOutcome::Installed,
    }
}

fn from(link: u32, n: u8) -> nos_ospf_common::lsdb::Origin {
    nos_ospf_common::lsdb::Origin {
        link,
        neighbor: id(n),
    }
}

/// Floods `events` out `cfg` (link id 7) and returns what hit the wire.
fn flood(
    wire: &Arc<wire::Wire>,
    cfg: &LinkConfig,
    status: &StatusHandle,
    events: &[FloodEvent<Lsa>],
) {
    let socket = wire.opener()(cfg).unwrap();
    flood_events(&socket, cfg, id(1), 7, status, events, &mut 0, &mut None);
}

fn rxmt_len(status: &StatusHandle, n: u8) -> usize {
    status.borrow().neighbors[&id(n)]
        .adjacency
        .as_ref()
        .unwrap()
        .retransmission_list
        .len()
}

#[tokio::test]
async fn mixed_opaque_capability_multicasts_plain_and_unicasts_opaque() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let status = dr_status(&[(2, true), (3, false)]);
    let opaque = opaque_lsa(lsa::LSA_TYPE_OPAQUE_AREA, id(9));
    flood(
        &wire,
        &cfg,
        &status,
        &[ev(foreign_type5(0), None), ev(opaque, None)],
    );
    // One group packet (plain) plus one unicast (opaque) to the capable peer.
    assert_eq!(
        sent(&wire, 1, LSU),
        vec![To::AllSpf, To::Unicast(Ipv4Addr::new(10, 0, 0, 2))]
    );
    // Both on the retransmission list of 2, only the plain one of 3.
    assert_eq!((rxmt_len(&status, 2), rxmt_len(&status, 3)), (2, 1));
}

#[tokio::test]
async fn an_lsa_is_not_flooded_back_to_its_sender_but_to_the_other_neighbors() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
    let status = dr_status(&[(2, false), (3, false)]);
    flood(
        &wire,
        &cfg,
        &status,
        &[ev(foreign_type5(0), Some(from(7, 2)))],
    );
    assert_eq!(
        sent(&wire, 1, LSU),
        vec![To::Unicast(Ipv4Addr::new(10, 0, 0, 3))]
    );
    assert_eq!((rxmt_len(&status, 2), rxmt_len(&status, 3)), (0, 1));
    // Received on another link: every neighbor gets it.
    flood(
        &wire,
        &cfg,
        &status,
        &[ev(foreign_type5(0), Some(from(8, 2)))],
    );
    assert_eq!(sent(&wire, 1, LSU).len(), 3);
    assert_eq!(rxmt_len(&status, 2), 1);
}

#[tokio::test]
async fn dr_floods_back_out_a_broadcast_link_unless_the_sender_is_dr_or_bdr() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let status = dr_status(&[(2, false), (3, false)]);
    // Sender 2 is a DROther: the DR relays it to the group (RFC 2328 §13.3 step 4).
    flood(
        &wire,
        &cfg,
        &status,
        &[ev(foreign_type5(0), Some(from(7, 2)))],
    );
    assert_eq!(sent(&wire, 1, LSU), vec![To::AllSpf]);
    // Sender 2 is the BDR now: it already multicast it; lists updated, nothing sent.
    status.send_modify(|s| s.bdr = Some(id(2)));
    let mut again = foreign_type5(0);
    again.header.link_state_id = Ipv4Addr::new(198, 51, 101, 0);
    flood(&wire, &cfg, &status, &[ev(again, Some(from(7, 2)))]);
    assert_eq!(sent(&wire, 1, LSU).len(), 1);
    assert_eq!(rxmt_len(&status, 3), 2);
}

#[tokio::test]
async fn a_failed_group_send_falls_back_to_unicast_per_neighbor() {
    let wire = Arc::new(wire::Wire::default());
    wire.fail_all_d
        .lock()
        .unwrap()
        .insert(Ipv4Addr::new(10, 0, 0, 1));
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let status = dr_status(&[(2, false)]);
    status.send_modify(|s| s.interface_state = InterfaceState::DrOther);
    flood(&wire, &cfg, &status, &[ev(foreign_type5(0), None)]);
    assert_eq!(
        sent(&wire, 1, LSU),
        vec![To::Unicast(Ipv4Addr::new(10, 0, 0, 2))]
    );
}

#[tokio::test]
async fn a_stub_area_link_does_not_flood_type_5() {
    let wire = Arc::new(wire::Wire::default());
    let mut cfg = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
    cfg.stub = true;
    let status = dr_status(&[(2, false)]);
    flood(&wire, &cfg, &status, &[ev(foreign_type5(0), None)]);
    assert_eq!(sent(&wire, 1, LSU), Vec::<To>::new());
    assert_eq!(rxmt_len(&status, 2), 0);
}

#[tokio::test(start_paused = true)]
async fn retransmission_waits_rxmt_interval_then_stops_on_ack() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
    let socket = wire.opener()(&cfg).unwrap();
    let status = dr_status(&[(2, false)]);
    let l = foreign_type5(0);
    flood(&wire, &cfg, &status, &[ev(l.clone(), None)]);
    assert_eq!(sent(&wire, 1, LSU).len(), 1);
    // Not due yet.
    tokio::time::advance(Duration::from_secs(4)).await;
    retransmit_pending(&socket, &cfg, id(1), &status, &mut 0);
    assert_eq!(sent(&wire, 1, LSU).len(), 1);
    // Due: resent, unicast, once.
    tokio::time::advance(Duration::from_secs(2)).await;
    retransmit_pending(&socket, &cfg, id(1), &status, &mut 0);
    retransmit_pending(&socket, &cfg, id(1), &status, &mut 0);
    assert_eq!(
        sent(&wire, 1, LSU),
        vec![
            To::Unicast(Ipv4Addr::new(10, 0, 0, 2)),
            To::Unicast(Ipv4Addr::new(10, 0, 0, 2))
        ]
    );
    // Acked: gone.
    status.send_modify(|s| {
        let adj = s
            .neighbors
            .get_mut(&id(2))
            .unwrap()
            .adjacency
            .as_mut()
            .unwrap();
        exchange::on_lsack_received(adj, &[l.header]);
    });
    tokio::time::advance(Duration::from_secs(10)).await;
    retransmit_pending(&socket, &cfg, id(1), &status, &mut 0);
    assert_eq!(sent(&wire, 1, LSU).len(), 2);
}

#[tokio::test]
async fn a_lagged_store_is_reflooded_once() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
    let socket = wire.opener()(&cfg).unwrap();
    let status = dr_status(&[(2, false)]);
    let mut db = Lsdb::new();
    db.install(foreign_type5(0));
    let store = Mutex::new(db);
    let mut rx = None;
    on_flood_event(
        Err(broadcast::error::RecvError::Lagged(5)),
        &mut rx,
        &store,
        &socket,
        &cfg,
        id(1),
        7,
        &status,
        &mut 0,
        &mut None,
    )
    .await;
    assert_eq!(sent(&wire, 1, LSU).len(), 1);
    assert_eq!(rxmt_len(&status, 2), 1);
}

/// RFC 2328 §13.5: a new LSA is acked delayed, a duplicate at once.
#[tokio::test]
async fn delayed_ack_for_new_direct_ack_for_duplicate() {
    let cfg = link("eth0", 10);
    let (lsdb, link_local) = (Mutex::new(Lsdb::new()), Mutex::new(Lsdb::new()));
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    status.send_modify(|s| {
        let mut info = neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2));
        info.adjacency = Some(AdjacencyData::default());
        s.neighbors.insert(id(2), info);
    });
    let lsu = LsuPacket {
        discarded: 0,
        last_error: None,
        router_id: id(2),
        area_id: Ipv4Addr::UNSPECIFIED,
        lsas: vec![foreign_type5(0)],
    };
    let first = rx::handle_lsu(&cfg, id(1), &status, &lsdb, &link_local, &lsu, 7)
        .await
        .unwrap();
    assert!(!first
        .iter()
        .any(|a| matches!(a, exchange::Action::SendLsAck(_))));
    let pending = |s: &StatusHandle| {
        s.borrow().neighbors[&id(2)]
            .adjacency
            .as_ref()
            .unwrap()
            .pending_acks
            .len()
    };
    assert_eq!(pending(&status), 1);
    let again = rx::handle_lsu(&cfg, id(1), &status, &lsdb, &link_local, &lsu, 7)
        .await
        .unwrap();
    assert!(again
        .iter()
        .any(|a| matches!(a, exchange::Action::SendLsAck(h) if h.len() == 1)));
    assert_eq!(pending(&status), 1);
}

/// A→B→C: an LSA installed at A reaches C through B within a second, long
/// before any sweep.
#[tokio::test(start_paused = true)]
async fn an_lsa_is_relayed_across_a_transit_router_at_once() {
    let wire = Arc::new(wire::Wire::default());
    let (a, b, c) = (router(&wire), router(&wire), router(&wire));
    a.reconcile(
        vec![wired_link([10, 0, 1, 1], 30, NetworkType::PointToPoint)],
        stub("192.0.2.1/32"),
        id(1),
    )
    .await;
    b.reconcile(
        vec![
            wired_link([10, 0, 1, 2], 30, NetworkType::PointToPoint),
            wired_link([10, 0, 2, 2], 30, NetworkType::PointToPoint),
        ],
        stub("192.0.2.2/32"),
        id(2),
    )
    .await;
    c.reconcile(
        vec![wired_link([10, 0, 2, 1], 30, NetworkType::PointToPoint)],
        stub("192.0.2.3/32"),
        id(3),
    )
    .await;
    settle(60).await;
    let l = foreign_type5(0);
    let key = l.header.key();
    a.lsdb_for(Ipv4Addr::UNSPECIFIED)
        .await
        .lock()
        .await
        .install(l);
    settle(1).await;
    let held = c
        .lsdb_for(Ipv4Addr::UNSPECIFIED)
        .await
        .lock()
        .await
        .get(&key);
    assert!(held.is_some());
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

#[test]
fn destination_is_reported_only_on_change() {
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let status = dr_status(&[]);
    let mut last = None;
    note_flood_dest(&cfg, &status, &mut last);
    assert_eq!(last, Some(Dest::AllSpfRouters));
    status.send_modify(|s| s.interface_state = InterfaceState::DrOther);
    note_flood_dest(&cfg, &status, &mut last);
    assert_eq!(last, Some(Dest::AllDRouters));
}

/// #1626: a neighbor acks a newer instance of an LSA we advertise: we send
/// one LSR for it, and not a second within `MIN_LS_ARRIVAL`.
#[tokio::test]
async fn ack_of_a_newer_own_lsa_is_requested_once() {
    let held = foreign_type5(0); // advertised by 9.9.9.9
    let mut theirs = held.header;
    theirs.sequence_number += 5;
    let (lsdb, link_local) = (Mutex::new(Lsdb::new()), Mutex::new(Lsdb::new()));
    lsdb.lock().await.install(held);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    status.send_modify(|s| {
        let mut info = neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2));
        info.adjacency = Some(AdjacencyData::default());
        s.neighbors.insert(id(2), info);
    });
    let ack = LsAckPacket {
        router_id: id(2),
        area_id: Ipv4Addr::UNSPECIFIED,
        lsa_headers: vec![theirs],
    };
    let me = Ipv4Addr::new(9, 9, 9, 9);
    let first = rx::handle_lsack(me, &status, &lsdb, &link_local, &ack)
        .await
        .unwrap();
    assert!(matches!(&first[..], [exchange::Action::SendLsr(k)] if k.len() == 1));
    let again = rx::handle_lsack(me, &status, &lsdb, &link_local, &ack)
        .await
        .unwrap();
    assert_eq!(again, []);
}

/// RFC 2328 §13 step 8: an older instance is answered with the database copy
/// (a unicast LSU action), never acked.
#[tokio::test]
async fn older_lsa_is_answered_with_the_database_copy() {
    let cfg = link("eth0", 10);
    let mut held = foreign_type5(0);
    held.header.sequence_number += 1;
    lsa::fill_checksum(&mut held);
    let mut db = Lsdb::new();
    db.install(held);
    let (lsdb, link_local) = (Mutex::new(db), Mutex::new(Lsdb::new()));
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    status.send_modify(|s| {
        let mut info = neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2));
        info.adjacency = Some(AdjacencyData::default());
        s.neighbors.insert(id(2), info);
    });
    let lsu = LsuPacket {
        discarded: 0,
        last_error: None,
        router_id: id(2),
        area_id: Ipv4Addr::UNSPECIFIED,
        lsas: vec![foreign_type5(0)],
    };
    let acts = rx::handle_lsu(&cfg, id(1), &status, &lsdb, &link_local, &lsu, 7)
        .await
        .unwrap();
    assert!(acts
        .iter()
        .any(|a| matches!(a, exchange::Action::SendLsu(v) if v.len() == 1)));
    assert!(!acts
        .iter()
        .any(|a| matches!(a, exchange::Action::SendLsAck(_))));
}
