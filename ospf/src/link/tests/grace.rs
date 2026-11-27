use super::*;

#[tokio::test]
async fn grace_holds_full_through_a_hello_that_does_not_list_us() {
    let cfg = link("eth0.0", 10);
    for (grace, expected) in [
        (
            Some(Instant::now() + Duration::from_secs(60)),
            NeighborState::Full,
        ),
        (None, NeighborState::Init),
    ] {
        let status = grace_status(grace);
        handle_hello(
            &cfg,
            Ipv4Addr::new(1, 1, 1, 1),
            &status,
            Ipv4Addr::new(10, 0, 0, 2),
            &matching_hello(&cfg, Ipv4Addr::new(9, 9, 9, 10)),
            false,
            &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
        );
        assert_eq!(state_of(&status), expected);
    }
}

#[tokio::test(start_paused = true)]
async fn grace_suppresses_the_inactivity_timer_until_it_expires() {
    let cfg = link("eth0.0", 10);
    let status = grace_status(Some(Instant::now() + Duration::from_secs(60)));
    sweep_dead_neighbors(&cfg, &status);
    assert_eq!(state_of(&status), NeighborState::Full);

    status.send_modify(|s| {
        for n in s.neighbors.values_mut() {
            n.grace_deadline = Some(Instant::now());
        }
    });
    expire_grace(&cfg, &status);
    assert!(!in_grace(&status, Ipv4Addr::new(9, 9, 9, 10)));
    tokio::time::advance(Duration::from_secs(u64::from(cfg.dead_interval))).await;
    sweep_dead_neighbors(&cfg, &status);
    assert!(
        status.borrow().neighbors.is_empty(),
        "expired, then removed"
    );
}

#[tokio::test]
async fn grace_lsa_starts_helping_only_a_full_neighbor_and_is_idempotent() {
    let cfg = link("eth0.0", 10);
    let header = LsaHeader {
        age: 1,
        options: 0,
        lsa_type: lsa::LSA_TYPE_OPAQUE_LINK,
        link_state_id: lsa::GRACE_LINK_STATE_ID,
        advertising_router: Ipv4Addr::new(9, 9, 9, 10),
        sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
        checksum: 0,
        length: 0,
    };
    let body = GraceLsaBody {
        grace_period: 60,
        restart_reason: lsa::RESTART_REASON_SOFTWARE,
        interface_address: None,
    };
    let status = grace_status(None);
    on_grace_lsa(&cfg, &status, &header, body);
    on_grace_lsa(&cfg, &status, &header, body);
    assert!(in_grace(&status, header.advertising_router));

    let flushed = LsaHeader {
        age: lsa::MAX_AGE,
        ..header
    };
    on_grace_lsa(&cfg, &status, &flushed, body);
    assert!(!in_grace(&status, header.advertising_router));

    status.send_modify(|s| {
        for n in s.neighbors.values_mut() {
            n.state = NeighborState::ExStart;
        }
    });
    on_grace_lsa(&cfg, &status, &header, body);
    assert!(!in_grace(&status, header.advertising_router));
}

/// RFC 3623 over the wire: B announces a grace period and stops without
/// flushing its LSAs; A helps — keeps B `Full` and B's routes through
/// B's absence, past the dead interval, and through the restarted B's
/// Hellos and Init DBD — never holds or floods the Grace-LSA, and leaves
/// grace once the fresh B is `Full` again.
#[tokio::test(start_paused = true)]
async fn graceful_restart_is_helped_through_a_real_restart() {
    let wire = Arc::new(wire::Wire::default());
    let (a, b) = (router(&wire), router(&wire));
    let link_b = wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint);
    a.reconcile(
        vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(1),
    )
    .await;
    b.reconcile(vec![link_b.clone()], stub("192.0.2.2/32"), id(2))
        .await;
    b.set_graceful_restart(Some(120));
    // RFC 3623 §3.2 (c): on-shutdown must not change the Router-LSA.
    b.set_max_metric(None, Some(3), false);
    settle(60).await;
    assert_eq!(
        a.neighbor_summaries().await[0].state,
        OspfNeighborState::Full
    );
    assert!(routes_to(&a, "192.0.2.2/32").await);

    b.announce_graceful_restart().await;
    b.shutdown().await;
    assert!(helping(&a, id(2)).await);
    assert_eq!(router_lsa_at(&a, id(2)).await.1, [1]);
    let lsas = a.database_summaries().await;
    assert!(lsas.iter().all(|l| l.lsa_type != lsa::LSA_TYPE_OPAQUE_LINK));
    // RFC 3623 §2: the restarter keeps its LSAs, never prematurely aged.
    assert!(lsas
        .iter()
        .filter(|l| l.advertising_router == id(2))
        .all(|l| l.age < lsa::MAX_AGE));

    // B is gone for longer than the dead interval: A still holds it.
    settle(60).await;
    assert_eq!(
        a.neighbor_summaries().await[0].state,
        OspfNeighborState::Full
    );
    assert!(routes_to(&a, "192.0.2.2/32").await);

    let b2 = router(&wire);
    b2.reconcile(vec![link_b], stub("192.0.2.2/32"), id(2))
        .await;
    settle(60).await;
    assert_eq!(
        a.neighbor_summaries().await[0].state,
        OspfNeighborState::Full
    );
    assert!(!helping(&a, id(2)).await);
    assert!(routes_to(&a, "192.0.2.2/32").await);
}

/// RFC 6987 on-startup: max-metric transit links for the configured
/// period, then normal costs; stub links (and B's route to A's loopback)
/// never change.
#[tokio::test(start_paused = true)]
async fn on_startup_max_metric_lasts_its_period() {
    let (a, b) = stub_router_pair((Some(60), None, false)).await;
    settle(40).await;
    assert!(a.max_metric_active());
    let (_, p2p, stubs) = router_lsa_at(&b, id(1)).await;
    assert_eq!(p2p, [lsa::MAX_LINK_METRIC]);
    assert!(stubs.iter().all(|&m| m == 1), "{stubs:?}");
    assert!(routes_to(&b, "192.0.2.1/32").await);

    settle(40).await;
    assert!(!a.max_metric_active());
    assert_eq!(router_lsa_at(&b, id(1)).await.1, [1]);
    // Later resyncs never re-arm it.
    a.set_max_metric(Some(60), None, false);
    assert!(!a.max_metric_active());
}

#[tokio::test(start_paused = true)]
async fn on_startup_is_armed_once_cleared_by_none_and_skipped_after_graceful_restart() {
    let m = LinkManager::new(1, None, crate::boot::BootCounter::in_memory());
    m.set_max_metric(Some(60), None, false);
    assert!(m.max_metric_active());
    m.set_max_metric(None, None, false);
    assert!(!m.max_metric_active());
    m.set_max_metric(None, None, true);
    assert!(m.max_metric_active());

    let restarted = LinkManager::new(1, None, crate::boot::BootCounter::in_memory());
    restarted.set_after_graceful_restart(true);
    restarted.set_max_metric(Some(60), None, false);
    assert!(!restarted.max_metric_active());
}

/// RFC 6987 on-shutdown: B installs A's max-metric Router-LSA at once
/// (flooded by event, well inside `RXMT_INTERVAL`), then the flushed copy
/// of that same instance once the hold is over.
#[tokio::test(start_paused = true)]
async fn on_shutdown_advertises_max_metric_before_the_flush() {
    let (a, b) = stub_router_pair((None, Some(3), false)).await;
    settle(60).await;
    assert_eq!(router_lsa_at(&b, id(1)).await.1, [1]);

    let stopping = Arc::clone(&a);
    let task = tokio::spawn(async move { stopping.shutdown().await });
    settle(1).await;
    let (age, p2p, _) = router_lsa_at(&b, id(1)).await;
    assert_eq!(p2p, [lsa::MAX_LINK_METRIC]);
    assert!(age < lsa::MAX_AGE);
    settle(3).await;
    let (age, p2p, _) = router_lsa_at(&b, id(1)).await;
    assert_eq!((age, p2p), (lsa::MAX_AGE, vec![lsa::MAX_LINK_METRIC]));
    task.await.unwrap();
}

/// A Router-LSA that changed under `MinLSInterval` ago skips on-shutdown;
/// the flush still happens.
#[tokio::test(start_paused = true)]
async fn on_shutdown_is_skipped_when_the_router_lsa_just_changed() {
    let (a, b) = stub_router_pair((None, Some(3), false)).await;
    settle(60).await;
    a.set_prefix_suppression(true);
    settle(2).await;
    let stopping = Arc::clone(&a);
    let task = tokio::spawn(async move { stopping.shutdown().await });
    settle(2).await;
    let (age, p2p, _) = router_lsa_at(&b, id(1)).await;
    assert_eq!((age, p2p), (lsa::MAX_AGE, vec![1]));
    task.await.unwrap();
}

/// Without a configured grace period, SIGTERM's announce is a no-op and
/// shutdown flushes as before.
#[tokio::test(start_paused = true)]
async fn announce_without_a_grace_period_still_flushes_on_shutdown() {
    let wire = Arc::new(wire::Wire::default());
    let b = router(&wire);
    b.reconcile(Vec::new(), stub("192.0.2.2/32"), id(2)).await;
    settle(3).await;
    b.announce_graceful_restart().await;
    b.shutdown().await;
    let own: Vec<_> = b
        .database_summaries()
        .await
        .into_iter()
        .filter(|l| l.advertising_router == id(2))
        .collect();
    assert_ne!(own, []);
    assert!(own.iter().all(|l| l.age == lsa::MAX_AGE));
}

fn grace_lsa_from(age: u16) -> (LsaHeader, GraceLsaBody) {
    let header = LsaHeader {
        age,
        options: 0,
        lsa_type: lsa::LSA_TYPE_OPAQUE_LINK,
        link_state_id: lsa::GRACE_LINK_STATE_ID,
        advertising_router: Ipv4Addr::new(9, 9, 9, 10),
        sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
        checksum: 0,
        length: 0,
    };
    let body = GraceLsaBody {
        grace_period: 120,
        restart_reason: lsa::RESTART_REASON_SOFTWARE,
        interface_address: None,
    };
    (header, body)
}

fn grace_left(status: &StatusHandle) -> Option<Duration> {
    let d = status.borrow().neighbors[&Ipv4Addr::new(9, 9, 9, 10)].grace_deadline?;
    Some(d.saturating_duration_since(Instant::now()))
}

#[tokio::test(start_paused = true)]
async fn helper_honours_what_the_grace_lsa_has_left_up_to_the_cap() {
    let base = link("eth0.0", 10);
    for (age, grace, cap, expected) in [
        (30, 120, 1800, Some(90)),
        (0, 120, 60, Some(60)),
        (0, u32::MAX, 1800, Some(1800)),
        (120, 120, 1800, None),
        (500, 120, 1800, None),
    ] {
        let (header, mut body) = grace_lsa_from(age);
        body.grace_period = grace;
        let cfg = LinkConfig {
            helper_max_grace_period: cap,
            ..base.clone()
        };
        let status = grace_status(None);
        on_grace_lsa(&cfg, &status, &header, body);
        assert_eq!(grace_left(&status), expected.map(Duration::from_secs));
    }
}

#[tokio::test(start_paused = true)]
async fn an_expired_grace_lsa_ends_a_running_grace() {
    let cfg = link("eth0.0", 10);
    let (header, body) = grace_lsa_from(0);
    let status = grace_status(None);
    on_grace_lsa(&cfg, &status, &header, body);
    assert!(in_grace(&status, header.advertising_router));
    let (stale, body) = grace_lsa_from(120);
    on_grace_lsa(&cfg, &status, &stale, body);
    assert!(!in_grace(&status, header.advertising_router));
}

#[tokio::test(start_paused = true)]
async fn topology_change_ends_grace_unless_only_the_restarter_changed() {
    let cfg = link("eth0.0", 10);
    let restarter = Ipv4Addr::new(9, 9, 9, 10);
    let other = Ipv4Addr::new(1, 1, 1, 1);
    for (origins, exits) in [
        (vec![restarter], false),
        (vec![], false),
        (vec![other], true),
        (vec![restarter, other], true),
    ] {
        let status = grace_status(Some(Instant::now() + Duration::from_secs(60)));
        exit_grace_on_topology_change(&cfg, &status, &origins);
        assert_eq!(in_grace(&status, restarter), !exits, "{origins:?}");
    }
}

/// RFC 3623 §3.2 (c): while A helps B, a new topology LSA from a third
/// router ends the grace period on A's next aging tick.
#[tokio::test(start_paused = true)]
async fn helper_exits_grace_when_a_third_routers_topology_lsa_appears() {
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
    b.set_graceful_restart(Some(120));
    settle(60).await;
    b.announce_graceful_restart().await;
    b.shutdown().await;
    assert!(helping(&a, id(2)).await);

    let store = a.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
    let mut other = (*store
        .lock()
        .await
        .get(&LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: id(1),
            advertising_router: id(1),
        })
        .unwrap())
    .clone();
    other.header.advertising_router = id(7);
    other.header.link_state_id = id(7);
    store.lock().await.install(other);
    settle(2).await;
    assert!(!helping(&a, id(2)).await);
}

fn lls_link(helper_max: u32) -> LinkConfig {
    LinkConfig {
        lls: true,
        helper_max_grace_period: helper_max,
        ..link("eth0.0", 10)
    }
}

fn rs_hello(cfg: &LinkConfig, eof: u32) -> packet::HelloPacket {
    packet::HelloPacket {
        lls: Some(crate::lls::Lls { eof: Some(eof) }),
        ..matching_hello(cfg, Ipv4Addr::new(9, 9, 9, 10))
    }
}

fn hello_from_peer(cfg: &LinkConfig, status: &StatusHandle, hello: &packet::HelloPacket) {
    handle_hello(
        cfg,
        Ipv4Addr::new(1, 1, 1, 1),
        status,
        Ipv4Addr::new(10, 0, 0, 2),
        hello,
        false,
        &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
    );
}

fn deadline_of(status: &StatusHandle) -> Option<Instant> {
    status.borrow().neighbors[&Ipv4Addr::new(9, 9, 9, 10)].grace_deadline
}

/// RFC 4812: an RS Hello (which no longer lists us) holds a Full neighbor,
/// for at most the helper cap, and only once.
#[tokio::test(start_paused = true)]
async fn rs_hello_holds_a_full_neighbor_once_and_capped() {
    let cfg = lls_link(30);
    let status = grace_status(None);
    hello_from_peer(&cfg, &status, &rs_hello(&cfg, crate::lls::EOF_RS));
    assert_eq!(state_of(&status), NeighborState::Full);
    let first = deadline_of(&status).unwrap();
    assert_eq!(first - Instant::now(), Duration::from_secs(30));
    tokio::time::advance(Duration::from_secs(10)).await;
    hello_from_peer(&cfg, &status, &rs_hello(&cfg, crate::lls::EOF_RS));
    assert_eq!(deadline_of(&status), Some(first), "not extended again");
    // The signal runs out: back under the inactivity timer, torn down.
    tokio::time::advance(Duration::from_secs(21)).await;
    expire_grace(&cfg, &status);
    assert_eq!(deadline_of(&status), None);
    hello_from_peer(&cfg, &status, &rs_hello(&cfg, 0));
    assert_eq!(state_of(&status), NeighborState::Init);
}

#[tokio::test]
async fn rs_is_ignored_when_lls_is_off_extended_virtual_or_capped_to_zero() {
    let plain = link("eth0.0", 10);
    let ext = LinkConfig {
        lls: true,
        auth: ext_auth(),
        ..link("eth0.0", 10)
    };
    let vlink = LinkConfig {
        virtual_link: Some(VirtualLinkEnd {
            transit_area: Ipv4Addr::new(0, 0, 0, 1),
            endpoint: Ipv4Addr::new(9, 9, 9, 10),
            neighbor: Ipv4Addr::new(10, 0, 0, 2),
        }),
        ..lls_link(30)
    };
    for cfg in [plain, ext, vlink, lls_link(0)] {
        let status = grace_status(None);
        hello_from_peer(&cfg, &status, &rs_hello(&cfg, crate::lls::EOF_RS));
        assert_eq!(deadline_of(&status), None);
    }
}

fn oob_dbd(eof: u32, resync: bool, init: bool) -> packet::DbdPacket {
    packet::DbdPacket {
        lls: Some(crate::lls::Lls { eof: Some(eof) }),
        router_id: Ipv4Addr::new(9, 9, 9, 10),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 1500,
        options: 0,
        init,
        resync,
        more: true,
        master: true,
        dd_sequence_number: 1,
        lsa_headers: vec![],
    }
}

/// Feeds `dbd` to a `Full` neighbor and returns (state, held, `oob_resync`, sent R).
async fn dbd_to_full_neighbor(dbd: &packet::DbdPacket) -> (NeighborState, bool, bool, bool) {
    let cfg = lls_link(30);
    let (lsdb, local) = (Mutex::new(Lsdb::default()), Mutex::new(Lsdb::default()));
    let status = grace_status(None);
    let actions = handle_dbd(
        &cfg,
        Ipv4Addr::new(1, 1, 1, 1),
        &status,
        &lsdb,
        &local,
        dbd,
        100,
    )
    .await
    .unwrap();
    let sent_r = actions
        .iter()
        .any(|a| matches!(a, exchange::Action::SendDbd(d) if d.resync));
    let s = status.borrow();
    let n = &s.neighbors[&Ipv4Addr::new(9, 9, 9, 10)];
    (
        n.state,
        n.counts_as_full(),
        n.adjacency.as_ref().unwrap().oob_resync,
        sent_r,
    )
}

/// RFC 4811 §2.4: an R Init DBD (I, M, MS set) from an LR-capable `Full`
/// neighbor opens an OOB resync that keeps it counted as `Full`; our DBDs
/// carry R from then on.
#[tokio::test]
async fn r_bit_dbd_starts_an_oob_resync_that_stays_advertised() {
    let (state, held, oob, sent_r) =
        dbd_to_full_neighbor(&oob_dbd(crate::lls::EOF_LR, true, true)).await;
    assert_eq!(state, NeighborState::Exchange);
    assert!(held && oob && sent_r);
}

/// Without R an Init DBD from a `Full` peer is a genuine reset: the ordinary
/// `SeqNumberMismatch`, never held (even from an LR-capable peer).
#[tokio::test]
async fn init_dbd_without_r_is_an_ordinary_mismatch() {
    let (state, held, oob, _) =
        dbd_to_full_neighbor(&oob_dbd(crate::lls::EOF_LR, false, true)).await;
    assert_eq!(state, NeighborState::ExStart);
    assert!(!held && !oob);
}

/// R from a peer that never announced LR is dropped with a mismatch, and an
/// R DBD missing I, M or MS from a `Full` neighbor never opens a resync.
#[tokio::test]
async fn r_bit_from_a_non_lr_peer_or_without_imms_is_refused() {
    let (state, held, oob, _) = dbd_to_full_neighbor(&oob_dbd(0, true, true)).await;
    assert_eq!(state, NeighborState::ExStart);
    assert!(!held && !oob);
    let (state, held, oob, _) =
        dbd_to_full_neighbor(&oob_dbd(crate::lls::EOF_LR, true, false)).await;
    // Not a full OOB opener: ignored, and `Full` is "Exchange or higher", so
    // the neighbor FSM gets a SeqNumberMismatch (legacy resync).
    assert_eq!((state, held, oob), (NeighborState::ExStart, false, false));
}

/// RFC 4811 §2.4 rule 1: `OOBResync` set and an R-clear DBD is ignored with a
/// `SeqNumberMismatch`, which ends the hold (legacy resync).
#[tokio::test]
async fn r_clear_dbd_cancels_an_oob_resync() {
    let cfg = lls_link(30);
    let (lsdb, local) = (Mutex::new(Lsdb::default()), Mutex::new(Lsdb::default()));
    let status = grace_status(None);
    for dbd in [
        oob_dbd(crate::lls::EOF_LR, true, true),
        oob_dbd(crate::lls::EOF_LR, false, true),
    ] {
        handle_dbd(
            &cfg,
            Ipv4Addr::new(1, 1, 1, 1),
            &status,
            &lsdb,
            &local,
            &dbd,
            100,
        )
        .await;
    }
    let s = status.borrow();
    let n = &s.neighbors[&Ipv4Addr::new(9, 9, 9, 10)];
    assert_eq!(n.state, NeighborState::ExStart);
    assert!(!n.counts_as_full() && n.oob_deadline.is_none());
}

/// RFC 4811 §2.4: an OOB resync that never completes falls back to legacy.
#[tokio::test(start_paused = true)]
async fn oob_resync_times_out_into_a_legacy_resync() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = lls_link(30);
    let sock = wire.opener()(&wired_link([10, 0, 0, 1], 24, NetworkType::PointToPoint)).unwrap();
    let status = grace_status(None);
    let (lsdb, local) = (Mutex::new(Lsdb::default()), Mutex::new(Lsdb::default()));
    handle_dbd(
        &cfg,
        Ipv4Addr::new(1, 1, 1, 1),
        &status,
        &lsdb,
        &local,
        &oob_dbd(crate::lls::EOF_LR, true, true),
        100,
    )
    .await;
    assert!(status.borrow().neighbors[&Ipv4Addr::new(9, 9, 9, 10)].counts_as_full());
    tokio::time::advance(Duration::from_secs(u64::from(cfg.dead_interval) + 1)).await;
    expire_oob_resync(&sock, &cfg, Ipv4Addr::new(1, 1, 1, 1), &status, &mut 0);
    let s = status.borrow();
    let n = &s.neighbors[&Ipv4Addr::new(9, 9, 9, 10)];
    assert_eq!(n.state, NeighborState::ExStart);
    assert!(!n.counts_as_full() && n.oob_deadline.is_none());
}

/// The whole procedure between two routers: A starts the resync, both stay
/// counted as `Full` in every sample, neither re-originates its Router-LSA,
/// and the pair ends `Full` with `OOBResync` cleared.
#[tokio::test(start_paused = true)]
async fn oob_resync_between_two_routers_never_drops_the_adjacency() {
    let wire = Arc::new(wire::Wire::default());
    let (a, b) = (router(&wire), router(&wire));
    let mut la = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
    la.lls = true;
    let mut lb = wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint);
    lb.lls = true;
    let attach = la.attach_point.clone();
    a.reconcile(vec![la], HashMap::new(), id(1)).await;
    b.reconcile(vec![lb], HashMap::new(), id(2)).await;
    settle(60).await;
    let seq = |m: &Arc<LinkManager>, who| {
        let m = Arc::clone(m);
        async move {
            m.lsdb_for(Ipv4Addr::UNSPECIFIED)
                .await
                .lock()
                .await
                .get(&LsaKey {
                    lsa_type: lsa::LSA_TYPE_ROUTER,
                    link_state_id: who,
                    advertising_router: who,
                })
                .unwrap()
                .header
                .sequence_number
        }
    };
    let before = (seq(&a, id(1)).await, seq(&b, id(2)).await);
    let all_full = |m: &Arc<LinkManager>| {
        let m = Arc::clone(m);
        async move {
            m.links.lock().await.values().all(|e| {
                e.status
                    .borrow()
                    .neighbors
                    .values()
                    .all(NeighborInfo::counts_as_full)
            })
        }
    };
    let dd = || async {
        a.links
            .lock()
            .await
            .values()
            .next()
            .unwrap()
            .status
            .borrow()
            .neighbors[&id(2)]
            .adjacency
            .as_ref()
            .unwrap()
            .dd_sequence_number
    };
    let dd_before = dd().await;
    a.oob_resync(&attach).await;
    for _ in 0..200 {
        settle(0).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(all_full(&a).await && all_full(&b).await);
    }
    for m in [&a, &b] {
        for e in m.links.lock().await.values() {
            let s = e.status.borrow();
            let n = s.neighbors.values().next().unwrap();
            assert_eq!(n.state, NeighborState::Full);
            assert!(!n.adjacency.as_ref().unwrap().oob_resync && n.oob_deadline.is_none());
        }
    }
    assert_ne!(dd().await, dd_before, "the exchange restarted");
    assert_eq!((seq(&a, id(1)).await, seq(&b, id(2)).await), before);
}

/// #1213: after a §3.2 (c) topology exit the restarter is an ordinary
/// neighbor again, so a cold (one-way) Hello tears the adjacency down.
#[tokio::test(start_paused = true)]
async fn after_a_topology_exit_a_one_way_hello_tears_the_adjacency_down() {
    let cfg = link("eth0.0", 10);
    let status = grace_status(Some(Instant::now() + Duration::from_secs(60)));
    exit_grace_on_topology_change(&cfg, &status, &[Ipv4Addr::new(1, 1, 1, 1)]);
    handle_hello(
        &cfg,
        Ipv4Addr::new(1, 1, 1, 1),
        &status,
        Ipv4Addr::new(10, 0, 0, 2),
        &matching_hello(&cfg, Ipv4Addr::new(9, 9, 9, 10)),
        false,
        &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
    );
    assert_eq!(state_of(&status), NeighborState::Init);
}

fn own_lsas(lsas: &[nos_proto::LsaSummary], who: Ipv4Addr) -> usize {
    lsas.iter().filter(|l| l.advertising_router == who).count()
}

/// RFC 3623 restarting router: nothing is originated while it waits; the
/// timeout (or a topology change) ends it and origination resumes.
#[tokio::test(start_paused = true)]
async fn restart_mode_holds_origination_until_timeout_or_topology_change() {
    for topology in [false, true] {
        let wire = Arc::new(wire::Wire::default());
        let b = router(&wire);
        // No neighbors to wait for: not restart mode at all.
        b.begin_restart(std::collections::BTreeSet::new(), Duration::from_secs(30));
        assert!(!b.restart_active());
        b.begin_restart([id(9)].into(), Duration::from_secs(30));
        assert!(b.restart_active());
        b.reconcile(
            vec![wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)],
            stub("192.0.2.2/32"),
            id(2),
        )
        .await;
        settle(20).await;
        assert!(b.restart_active());
        assert_eq!(own_lsas(&b.database_summaries().await, id(2)), 0);
        if topology {
            b.restart_tick(true).await;
        } else {
            settle(20).await;
        }
        assert!(!b.restart_active());
        settle(5).await;
        assert!(own_lsas(&b.database_summaries().await, id(2)) > 0);
    }
}

/// The respawn waits for its pre-restart neighbor and ends `Complete` as soon
/// as it is `Full`; the helper's grace ends with it.
#[tokio::test(start_paused = true)]
async fn restart_mode_ends_when_the_neighbors_are_full_again() {
    let wire = Arc::new(wire::Wire::default());
    let (a, b) = (router(&wire), router(&wire));
    let link_b = wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint);
    a.reconcile(
        vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(1),
    )
    .await;
    b.reconcile(vec![link_b.clone()], stub("192.0.2.2/32"), id(2))
        .await;
    b.set_graceful_restart(Some(120));
    settle(60).await;
    assert_eq!(b.full_neighbor_ids().await, [id(1)].into());
    b.announce_graceful_restart().await;
    b.shutdown().await;
    settle(5).await;

    let b2 = router(&wire);
    b2.begin_restart([id(1)].into(), Duration::from_secs(100));
    b2.reconcile(vec![link_b], stub("192.0.2.2/32"), id(2))
        .await;
    settle(60).await;
    assert!(!b2.restart_active());
    assert_eq!(
        a.neighbor_summaries().await[0].state,
        OspfNeighborState::Full
    );
    assert!(!helping(&a, id(2)).await);
    assert!(routes_to(&a, "192.0.2.2/32").await);
}
