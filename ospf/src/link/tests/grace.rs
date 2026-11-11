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
/// (the flood kick, well inside `RXMT_INTERVAL`), then the flushed copy
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
