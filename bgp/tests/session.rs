//! `SessionManager` end to end over localhost (#131): two real instances,
//! each with its own listener (`with_listen`, no VRF, so no privileges),
//! peer, exchange a route, and go through the config changes `reconcile`
//! handles — restart, shutdown, removal, MD5.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nos_bgp::collision::FsmCommand;
use nos_bgp::session::{LocalIdentity, ResolvedAuth, ResolvedPeer, SessionManager, VrfRequirement};
use nos_proto::bgp::BgpSessionState;
use nos_proto::{AddressFamily, BgpShutdown, RedistributeUpdate, RedistributedRoute};
use tokio::io::AsyncReadExt;

const A: Ipv4Addr = Ipv4Addr::LOCALHOST;
const B: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn peer(remote: Ipv4Addr, source: Ipv4Addr, remote_as: u32) -> ResolvedPeer {
    let accept = Arc::new(nos_rpl::ACCEPT_ALL.clone());
    ResolvedPeer {
        remote_address: IpAddr::V4(remote),
        source_address: Some(IpAddr::V4(source)),
        remote_as,
        peer_group: "pg".to_string(),
        hold_time: 30,
        keepalive_interval: None,
        connect_retry_time: Duration::from_millis(300),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![AddressFamily::Ipv4Unicast, AddressFamily::L2vpnEvpn],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: accept.clone(),
        export_policy: accept,
        evpn_import_policy: None,
        flowspec_import_policy: None,
        flowspec_export_policy: None,
        enforce_first_as: true,
        flowspec_validation: nos_proto::BgpFlowspecValidation::default(),
        shutdown: None,
        maximum_prefix: nos_proto::BgpMaximumPrefix::default(),
        announce_rpki_state: false,
        blackhole: None,
        soft_reconfiguration_inbound: false,
        local_as: None,
        add_path: None,
        add_path_send_count: None,
        role: None,
        strict_mode: false,
        confed_id: None,
        confed_member: false,
        graceful_restart: Some(120),
    }
}

/// Polls `f` until it holds. The 30s bound is only a hang guard: a loaded
/// machine makes this slower, never a failure (#270).
async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !f().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

struct Router {
    manager: Arc<SessionManager>,
    local: LocalIdentity,
}

impl Router {
    async fn apply(&self, peers: Vec<ResolvedPeer>) {
        self.apply_with(peers, &[]).await;
    }

    async fn apply_with(&self, peers: Vec<ResolvedPeer>, rpki_caches: &[nos_proto::RpkiCache]) {
        self.manager
            .reconcile(
                VrfRequirement::Resolved("unscoped".to_string()),
                Some("rt1".to_string()),
                self.local,
                peers,
                Arc::new(nos_rpl::ACCEPT_ALL.clone()),
                Vec::new(),
                Vec::new(),
                rpki_caches,
                std::collections::HashMap::default(),
            )
            .await;
    }

    async fn state(&self) -> Option<BgpSessionState> {
        self.manager.peer_summaries().await.first().map(|p| p.state)
    }

    async fn wait_for(&self, want: BgpSessionState) {
        eventually(&format!("never reached {want:?}"), || async {
            self.state().await == Some(want)
        })
        .await;
    }
}

fn routers() -> (Router, Router, u16) {
    let (pa, pb) = (free_port(), free_port());
    let local = |id, asn| LocalIdentity {
        asn,
        router_id: id,
        cluster_id: id,
        confed_id: None,
    };
    (
        Router {
            manager: SessionManager::with_listen("a".to_string(), pa, pb, false),
            local: local(Ipv4Addr::new(1, 1, 1, 1), 65001),
        },
        Router {
            manager: SessionManager::with_listen("b".to_string(), pb, pa, false),
            local: local(Ipv4Addr::new(2, 2, 2, 2), 65002),
        },
        pa,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_instances_peer_exchange_a_route_and_follow_config_changes() {
    let (a, b, a_port) = routers();
    a.apply(vec![peer(B, A, 65002)]).await;
    b.apply(vec![peer(A, B, 65001)]).await;
    a.wait_for(BgpSessionState::Established).await;
    b.wait_for(BgpSessionState::Established).await;

    // A redistributes a static route; B learns it and would push it to its RIB.
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
            prefix: "198.51.100.0/24".parse().unwrap(),
            gateway: "10.0.0.9".parse().unwrap(),
        }]))
        .await;
    eventually("b learns a's route", || async {
        let (table, routes) = b.manager.bgp_push_snapshot().await;
        assert_eq!(table.as_deref(), Some("rt1"));
        routes.contains_key(&"198.51.100.0/24".parse().unwrap())
    })
    .await;

    // Operator commands and the periodic hooks all run against a live session.
    assert!(
        b.manager
            .send_command(IpAddr::V4(A), FsmCommand::SendRouteRefresh)
            .await
    );
    assert!(
        !b.manager
            .send_command(IpAddr::V4(B), FsmCommand::SendRouteRefresh)
            .await
    );
    b.manager.damping_tick().await;
    b.manager.mac_mobility_tick().await;
    b.manager
        .set_igp(std::collections::HashMap::default())
        .await;
    assert_eq!(
        b.manager
            .evpn_page(&mut nos_bgp::page::Snapshot::default(), None, 0, usize::MAX)
            .await,
        (vec![], None)
    );
    assert_eq!(
        b.manager.evpn_feed_snapshot(false).await.0,
        [] as [std::string::String; 0]
    );
    assert_eq!(
        b.manager.evpn_feed_snapshot(true).await.0,
        [] as [std::string::String; 0]
    );

    // An unconfigured source is turned away by the listener.
    let stranger = tokio::net::TcpSocket::new_v4().unwrap();
    stranger
        .bind(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 3).into(), 0))
        .unwrap();
    let mut s = stranger
        .connect(SocketAddr::new(A.into(), a_port))
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "connection from an unconfigured peer stays closed");

    // A changed peer restarts the session (Cease, other configuration change).
    let mut changed = peer(B, A, 65002);
    changed.hold_time = 12;
    a.apply(vec![changed.clone()]).await;
    a.wait_for(BgpSessionState::Established).await;

    // Administrative shutdown with an RFC 9003 message: no session until cleared.
    changed.shutdown = Some(BgpShutdown {
        message: Some("maintenance".to_string()),
    });
    a.apply(vec![changed.clone()]).await;
    assert!(a.manager.peer_summaries().await[0].shutdown);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_ne!(b.state().await, Some(BgpSessionState::Established));
    changed.shutdown = None;
    a.apply(vec![changed]).await;
    b.wait_for(BgpSessionState::Established).await;

    // Removing the peer (Cease, peer de-configured) leaves nothing behind.
    a.apply(Vec::new()).await;
    assert_eq!(
        a.manager.peer_summaries().await,
        [] as [nos_proto::PeerSummary; 0]
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_ne!(b.state().await, Some(BgpSessionState::Established));

    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

/// RFC 4724 / RFC 8538 (#12): with graceful restart on both sides, a config
/// change on A resets the session with Cease/Other Configuration Change, which
/// N makes graceful: B keeps A's route the whole time and shows A's
/// capability. With graceful restart off on B, the same reset withdraws it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_restart_keeps_routes_across_a_graceful_reset() {
    let prefix: ipnet::IpNet = "198.51.100.0/24".parse().unwrap();
    for gr_on_b in [true, false] {
        let (a, b, _) = routers();
        a.manager
            .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
                prefix,
                gateway: "10.0.0.9".parse().unwrap(),
            }]))
            .await;
        a.apply(vec![peer(B, A, 65002)]).await;
        b.apply(vec![ResolvedPeer {
            graceful_restart: gr_on_b.then_some(120),
            ..peer(A, B, 65001)
        }])
        .await;
        b.wait_for(BgpSessionState::Established).await;
        let has = || async { b.manager.bgp_push_snapshot().await.1.contains_key(&prefix) };
        eventually("b learns a's route", || async { has().await }).await;
        let gr = b.manager.peer_summaries().await[0].graceful_restart.clone();
        assert_eq!(
            gr.as_ref().map(|g| (g.restart_time, g.notification)),
            gr_on_b.then_some((120, true))
        );

        // Reset A with Cease/Other Configuration Change, and hold it down with
        // an MD5 key B lacks, so nothing reconnects until we say so: the state
        // B reaches is then stable, with no blip to catch (#270).
        let mut changed = peer(B, A, 65002);
        changed.hold_time = 12;
        let mut held_down = changed.clone();
        held_down.auth = Some(ResolvedAuth::Md5("secret".to_string()));
        a.apply(vec![held_down]).await;
        if gr_on_b {
            // Kept as stale, still handed to the RIB, for as long as A is gone.
            eventually("b keeps a's route as stale", || async {
                b.manager.peer_summaries().await[0].stale_prefixes == 1
            })
            .await;
            assert!(has().await, "graceful: the route stays while a is down");
        } else {
            eventually("b withdraws a's route", || async { !has().await }).await;
        }

        a.apply(vec![changed]).await;
        a.wait_for(BgpSessionState::Established).await;
        b.wait_for(BgpSessionState::Established).await;
        eventually("b has a's route again", || async { has().await }).await;
        eventually("no stale route left", || async {
            b.manager.peer_summaries().await[0].stale_prefixes == 0
        })
        .await;
        a.manager.shutdown().await;
        b.manager.shutdown().await;
    }
}

/// #12: `SessionManager::shutdown` (SIGINT) tells every Established peer
/// first — a Hard Reset with N exchanged — so B, which would keep A's routes
/// across a bare TCP close, drops them at once. Bounded by one `CEASE_GRACE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_sends_a_hard_reset_so_the_peer_keeps_nothing() {
    let prefix: ipnet::IpNet = "198.51.100.0/24".parse().unwrap();
    let (a, b, _) = routers();
    // A tight retry makes A's redial during the Cease grace near-certain on
    // unfixed code (#455): nothing may reconnect once shutdown began.
    let fast = |p: ResolvedPeer| ResolvedPeer {
        connect_retry_time: Duration::from_millis(20),
        ..p
    };
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
        }]))
        .await;
    a.apply(vec![fast(peer(B, A, 65002))]).await;
    b.apply(vec![fast(peer(A, B, 65001))]).await;
    b.wait_for(BgpSessionState::Established).await;
    let has = || async { b.manager.bgp_push_snapshot().await.1.contains_key(&prefix) };
    eventually("b learns a's route", || async { has().await }).await;
    // The shutdown Cease goes only to a session A itself holds Established.
    a.wait_for(BgpSessionState::Established).await;

    a.manager.shutdown().await;
    eventually("b drops a's route after a's shutdown", || async {
        !has().await
    })
    .await;
    // Stays gone: A did not redial (three retry intervals).
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(!has().await);
    assert_ne!(b.state().await, Some(BgpSessionState::Established));
    assert_eq!(b.manager.peer_summaries().await[0].stale_prefixes, 0);
    b.manager.shutdown().await;
}

/// RFC 4486 §4 (#79): b allows one prefix from a, which sends two — b closes
/// the session and holds a down; a clear is accepted, a raised limit lets
/// both routes in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maximum_prefix_trips_holds_and_clears() {
    let (a, b, _) = routers();
    let limited = |limit| ResolvedPeer {
        maximum_prefix: nos_proto::BgpMaximumPrefix {
            ipv4: Some(nos_proto::BgpPrefixLimit {
                limit,
                ..Default::default()
            }),
            ..Default::default()
        },
        ..peer(A, B, 65001)
    };
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(
            ["198.51.100.0/24", "198.51.101.0/24"]
                .map(|p| RedistributedRoute {
                    prefix: p.parse().unwrap(),
                    gateway: "10.0.0.9".parse().unwrap(),
                })
                .to_vec(),
        ))
        .await;
    a.apply(vec![peer(B, A, 65002)]).await;
    b.apply(vec![limited(1)]).await;
    eventually("b trips", || async {
        b.manager.peer_summaries().await[0].max_prefix_held
    })
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_ne!(b.state().await, Some(BgpSessionState::Established));

    assert!(b.manager.clear_peer(IpAddr::V4(A)).await);
    assert!(!b.manager.clear_peer(IpAddr::V4(B)).await);

    b.apply(vec![limited(5)]).await;
    b.wait_for(BgpSessionState::Established).await;
    eventually("b counts both routes", || async {
        b.manager.peer_summaries().await[0].accepted_prefixes == Some([2, 0, 0])
    })
    .await;
    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn md5_on_both_ends_establishes_over_localhost() {
    let (a, b, _) = routers();
    let md5 = |remote, source, asn| ResolvedPeer {
        auth: Some(ResolvedAuth::Md5("secret".to_string())),
        ..peer(remote, source, asn)
    };
    // Listener keys are primed on bind, then kept in step by later changes.
    a.apply(vec![md5(B, A, 65002)]).await;
    b.apply(vec![md5(A, B, 65001)]).await;
    a.wait_for(BgpSessionState::Established).await;
    let mut other = md5(B, A, 65002);
    other.auth = Some(ResolvedAuth::Md5("rotated".to_string()));
    a.apply(vec![other]).await;
    b.apply(vec![ResolvedPeer {
        auth: Some(ResolvedAuth::Md5("rotated".to_string())),
        ..peer(A, B, 65001)
    }])
    .await;
    a.wait_for(BgpSessionState::Established).await;
    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

/// #17 end to end over localhost: a scripted RTR cache makes A's route
/// invalid, B's import policy rejects it; a serial update makes it valid and
/// B gets it back through a route refresh, with no session reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpki_validation_follows_the_cache() {
    use futures::{SinkExt, StreamExt};
    use nos_bgp::rpki::rtr::{Intervals, Pdu, RtrCodec};
    use nos_bgp::rpki::Vrp;

    let prefix: ipnet::IpNet = "198.51.100.0/24".parse().unwrap();
    let vrp = move |asn| Vrp {
        prefix,
        max_len: 24,
        asn,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cache_addr = listener.local_addr().unwrap();
    let (proceed_tx, proceed_rx) = tokio::sync::oneshot::channel::<()>();
    let cache = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut f = tokio_util::codec::Framed::new(stream, RtrCodec { version: 1 });
        assert_eq!(f.next().await.unwrap().unwrap().pdu, Pdu::ResetQuery);
        for p in [
            Pdu::CacheResponse { session: 9 },
            Pdu::Prefix {
                announce: true,
                vrp: vrp(65999),
            },
            Pdu::EndOfData {
                session: 9,
                serial: 1,
                intervals: Some(Intervals::default()),
            },
        ] {
            f.send(p).await.unwrap();
        }
        proceed_rx.await.unwrap();
        f.send(Pdu::SerialNotify {
            session: 9,
            serial: 2,
        })
        .await
        .unwrap();
        assert_eq!(
            f.next().await.unwrap().unwrap().pdu,
            Pdu::SerialQuery {
                session: 9,
                serial: 1
            }
        );
        for p in [
            Pdu::CacheResponse { session: 9 },
            Pdu::Prefix {
                announce: false,
                vrp: vrp(65999),
            },
            Pdu::Prefix {
                announce: true,
                vrp: vrp(65001),
            },
            Pdu::EndOfData {
                session: 9,
                serial: 2,
                intervals: Some(Intervals::default()),
            },
        ] {
            f.send(p).await.unwrap();
        }
        f
    });

    let (a, b, _) = routers();
    let mut to_a = peer(A, B, 65001);
    to_a.import_policy = Arc::new(
        nos_rpl::compile(
            "if this.bgp.validation_state == rpki.invalid:\n    reject\naccept\n",
            &nos_rpl::Symbols::EMPTY,
        )
        .unwrap(),
    );
    let caches = [nos_proto::RpkiCache {
        address: cache_addr.ip(),
        port: cache_addr.port(),
        preference: 0,
        auth: None,
    }];
    a.apply(vec![peer(B, A, 65002)]).await;
    b.apply_with(vec![to_a], &caches).await;
    a.wait_for(BgpSessionState::Established).await;
    b.wait_for(BgpSessionState::Established).await;
    // Wait for the cache's first End of Data before A's route arrives.
    eventually("cache serial 1 and its VRP", || async {
        let s = &b.manager.rpki_summaries().await[0];
        s.serial == Some(1) && s.active && s.vrp_count == 1
    })
    .await;
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
            prefix,
            gateway: "10.0.0.9".parse().unwrap(),
        }]))
        .await;
    let has = || async { b.manager.bgp_push_snapshot().await.1.contains_key(&prefix) };
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!has().await, "an invalid route was accepted");

    proceed_tx.send(()).unwrap();
    // B route-refreshes only RPKI_REFRESH_DELAY (5s) after the VRP change.
    eventually("the now-valid route comes back", || async { has().await }).await;
    assert_eq!(b.manager.rpki_summaries().await[0].serial, Some(2));
    b.wait_for(BgpSessionState::Established).await;
    let _cache = cache.await.unwrap();

    // Removing the caches empties the VRP set.
    b.apply_with(vec![peer(A, B, 65001)], &[]).await;
    assert_eq!(b.manager.rpki_summaries().await, []);
}

/// Soft reconfiguration inbound (#859): B keeps what A sends before import
/// policy, so loosening B's policy re-admits the route with no new session;
/// enabling the flag on a live session asks A for a Route Refresh instead of
/// restarting; `soft-in` re-evaluates locally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn soft_reconfiguration_inbound_applies_policy_changes_in_place() {
    let (a, b, _) = routers();
    let unicast = |p: ResolvedPeer| ResolvedPeer {
        address_families: vec![AddressFamily::Ipv4Unicast],
        ..p
    };
    let b_peer = |flag: bool, accept: bool| {
        let mut p = unicast(peer(A, B, 65001));
        p.soft_reconfiguration_inbound = flag;
        if !accept {
            p.import_policy = Arc::new(nos_rpl::DENY_ALL.clone());
        }
        p
    };
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
            prefix: "198.51.100.0/24".parse().unwrap(),
            gateway: "10.0.0.9".parse().unwrap(),
        }]))
        .await;
    a.apply(vec![unicast(peer(B, A, 65002))]).await;
    b.apply(vec![b_peer(false, false)]).await;
    b.wait_for(BgpSessionState::Established).await;
    // Nothing to re-evaluate without the flag: soft-in is a Route Refresh.
    assert!(b.manager.soft_in_local(IpAddr::V4(A)).await.is_none());
    let accepted = || async { b.manager.peer_summaries().await[0].accepted_prefixes };
    tokio::time::sleep(Duration::from_millis(1300)).await;

    // Enable in place: no restart, and A's refresh reply is retained.
    b.apply(vec![b_peer(true, false)]).await;
    let retained = || async {
        match b.manager.soft_in_local(IpAddr::V4(A)).await {
            Some(Ok(f)) => f[0].retained,
            other => panic!("{other:?}"),
        }
    };
    eventually("b retains a's route", || async { retained().await == 1 }).await;
    assert_eq!(accepted().await, Some([0, 0, 0]));

    // Loosen the policy: re-admitted from the retained copy, same session.
    b.apply(vec![b_peer(true, true)]).await;
    eventually("b re-admits", || async {
        accepted().await == Some([1, 0, 0])
    })
    .await;
    assert!(
        b.manager.peer_summaries().await[0].uptime_secs >= Some(1),
        "the session must not have restarted"
    );
    let Some(Ok(f)) = b.manager.soft_in_local(IpAddr::V4(A)).await else {
        panic!("soft-in must re-evaluate locally")
    };
    assert_eq!((f[0].retained, f[0].accepted), (1, 1));

    // Disabling frees the retention, again without a restart.
    b.apply(vec![b_peer(false, true)]).await;
    assert!(b.manager.soft_in_local(IpAddr::V4(A)).await.is_none());
    assert_eq!(accepted().await, Some([1, 0, 0]));
    assert!(b.manager.peer_summaries().await[0].uptime_secs >= Some(1));
    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

/// One BMP message off the fake collector: (type, body after the 6-byte header).
async fn bmp_frame(s: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
    let mut h = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(30), s.read_exact(&mut h))
        .await
        .expect("a BMP frame in time")
        .unwrap();
    assert_eq!(h[0], 3, "BMP version");
    let len = u32::from_be_bytes(h[1..5].try_into().unwrap()) as usize;
    let mut body = vec![0u8; len - 6];
    s.read_exact(&mut body).await.unwrap();
    (h[5], body)
}

fn station(port: u16) -> nos_proto::BmpStation {
    nos_proto::BmpStation {
        name: "bmp-1".into(),
        address: IpAddr::V4(A),
        port,
        monitor: nos_proto::BmpMonitor::Both,
        statistics_interval: None,
        monitor_out: nos_proto::BmpMonitorOut::None,
    }
}

/// #878: Initiation, Peer Up, Peer Down on a config change, the replay after
/// the collector reconnects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bmp_station_gets_initiation_peer_up_peer_down_and_a_replay() {
    let collector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = collector.local_addr().unwrap().port();
    let (a, b, _) = routers();
    a.apply(vec![peer(B, A, 65002)]).await;
    a.manager
        .set_bmp_stations(&[station(port)], Some("rt1".into()), None)
        .await;
    b.apply(vec![peer(A, B, 65001)]).await;

    let (mut c, _) = collector.accept().await.unwrap();
    let (t, body) = bmp_frame(&mut c).await;
    assert_eq!(t, 4, "Initiation first");
    assert!(body.ends_with(b"vrf=rt1"));
    let (t, body) = bmp_frame(&mut c).await;
    assert_eq!(t, 3, "Peer Up");
    assert_eq!(&body[22..26], &[127, 0, 0, 2], "peer address");
    assert_eq!(&body[26..30], &65002u32.to_be_bytes(), "peer AS");

    // Dropping the collector reconnects and replays Initiation + Peer Up.
    drop(c);
    let (mut c, _) = collector.accept().await.unwrap();
    assert_eq!(bmp_frame(&mut c).await.0, 4);
    assert_eq!(bmp_frame(&mut c).await.0, 3, "replayed Peer Up");
    // `show bgp bmp` (#864): connected after one redial, first session frames counted.
    let st = &a.manager.bmp_status()[0];
    assert_eq!(st.state, nos_proto::BmpStationState::Connected);
    assert_eq!(st.peers_monitored, 1);
    assert!(st.reconnects >= 1 && st.connected_since.is_some());
    assert!(st.frames_sent.initiation >= 1 && st.frames_sent.peer_up >= 1);

    // Removing the peer from a's config ends the session: Peer Down.
    a.apply(vec![]).await;
    // End-of-RIB markers (#864) may precede it.
    let (t, body) = loop {
        let frame = bmp_frame(&mut c).await;
        if frame.0 != 0 {
            break frame;
        }
    };
    assert_eq!(t, 2, "Peer Down");
    assert_eq!(&body[22..26], &[127, 0, 0, 2]);

    // Removing the station sends Termination reason 0.
    a.manager
        .set_bmp_stations(&[], Some("rt1".into()), None)
        .await;
    let (t, body) = bmp_frame(&mut c).await;
    assert_eq!((t, &body[..]), (5, &[0, 1, 0, 2, 0, 0][..]));
}

/// #878: a queue that overflows terminates the session (reason 2), then the
/// station reconnects and replays the registry.
#[tokio::test]
async fn bmp_queue_overflow_resyncs_the_station() {
    use nos_bgp::bmp::{Hub, PeerUpInfo, QUEUE_CAPACITY};
    let collector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = collector.local_addr().unwrap().port();
    let hub = Hub::new();
    hub.set_stations(vec![nos_bgp::bmp::StationCfg {
        name: "s".into(),
        addr: SocketAddr::new(IpAddr::V4(A), port),
        vrf: None,
        sys_name: "x".into(),
        table: None,
        scope: nos_bgp::bmp::Scope::default(),
        monitor: nos_proto::BmpMonitor::Both,
        statistics_interval: None,
        monitor_out: nos_proto::BmpMonitorOut::None,
    }])
    .await;
    let (mut c, _) = collector.accept().await.unwrap();
    assert_eq!(bmp_frame(&mut c).await.0, 4);
    let info = |n: usize| PeerUpInfo {
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1 + u8::try_from(n % 200).unwrap())),
        asn: 65000,
        bgp_id: Ipv4Addr::new(9, 9, 9, 9),
        two_octet_as: false,
        local: IpAddr::V4(A),
        local_port: 179,
        remote_port: 1,
        sent_open: bytes::Bytes::new(),
        recv_open: bytes::Bytes::new(),
        time: Duration::ZERO,
        add_path_afis: std::collections::HashSet::default(),
    };
    // No await between pushes: the station task cannot drain meanwhile.
    for n in 0..QUEUE_CAPACITY + 10 {
        hub.peer_up(info(n));
    }
    let mut frames = 0;
    loop {
        let (t, body) = bmp_frame(&mut c).await;
        if t == 5 {
            assert_eq!(body, [0, 1, 0, 2, 0, 2], "out of resources");
            break;
        }
        frames += 1;
        assert!(frames <= QUEUE_CAPACITY, "bounded");
    }
    let (mut c, _) = collector.accept().await.unwrap();
    assert_eq!(bmp_frame(&mut c).await.0, 4);
    for _ in 0..200 {
        assert_eq!(bmp_frame(&mut c).await.0, 3, "replayed registry");
    }
    hub.shutdown().await;
}

/// One Route Monitoring frame off the fake collector: (L flag, BGP message).
async fn bmp_route(s: &mut tokio::net::TcpStream) -> (bool, nos_bgp::message::BgpMessage) {
    use tokio_util::codec::Decoder;
    let (t, body) = bmp_frame(s).await;
    assert_eq!(t, 0, "Route Monitoring");
    let mut b = bytes::BytesMut::from(&body[42..]);
    let msg = nos_bgp::message::BgpCodec::default()
        .decode(&mut b)
        .unwrap()
        .expect("a whole PDU");
    (body[1] & 0x40 != 0, msg)
}

fn unicast_only(p: ResolvedPeer) -> ResolvedPeer {
    ResolvedPeer {
        address_families: vec![AddressFamily::Ipv4Unicast],
        ..p
    }
}

/// #864: a station that connects after the routes arrived gets the pre-policy
/// dump (from the retained routes) and the is_post-policy dump, each closed by an
/// End-of-RIB; then incremental changes on both streams.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bmp_dump_and_incremental_updates_on_both_streams() {
    use nos_bgp::message::BgpMessage;
    let collector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = collector.local_addr().unwrap().port();
    let (a, b, _) = routers();
    let route = RedistributedRoute {
        prefix: "198.51.100.0/24".parse().unwrap(),
        gateway: "10.0.0.9".parse().unwrap(),
    };
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![route]))
        .await;
    let b_peer = |accept: bool| {
        let mut p = unicast_only(peer(A, B, 65001));
        p.soft_reconfiguration_inbound = true;
        if !accept {
            p.import_policy = Arc::new(nos_rpl::DENY_ALL.clone());
        }
        p
    };
    a.apply(vec![unicast_only(peer(B, A, 65002))]).await;
    b.apply(vec![b_peer(false)]).await;
    b.wait_for(BgpSessionState::Established).await;
    eventually("b retains a's route", || async {
        matches!(b.manager.soft_in_local(IpAddr::V4(A)).await, Some(Ok(f)) if f[0].retained == 1)
    })
    .await;

    b.manager
        .set_bmp_stations(&[station(port)], Some("rt1".into()), None)
        .await;
    let (mut c, _) = collector.accept().await.unwrap();
    assert_eq!(bmp_frame(&mut c).await.0, 4);
    assert_eq!(bmp_frame(&mut c).await.0, 3);
    // Pre-policy dump: the rejected route, then End-of-RIB. Peer A's own
    // End-of-RIB may still be in flight (#942): skip one leading live one.
    let (mut is_post, mut msg) = bmp_route(&mut c).await;
    if !is_post && matches!(msg, BgpMessage::EndOfRib { .. }) {
        (is_post, msg) = bmp_route(&mut c).await;
    }
    let BgpMessage::Update(upd) = msg else {
        panic!("{msg:?}")
    };
    assert!(!is_post);
    assert_eq!(upd.nlri, vec!["198.51.100.0/24".parse().unwrap()]);
    let (is_post, msg) = bmp_route(&mut c).await;
    assert!(!is_post && matches!(msg, BgpMessage::EndOfRib { afi: 1, safi: 1 }));
    // Post-policy dump: nothing was accepted, just the End-of-RIB.
    let (is_post, msg) = bmp_route(&mut c).await;
    assert!(is_post && matches!(msg, BgpMessage::EndOfRib { afi: 1, safi: 1 }));

    // Loosening the policy admits the route: is_post-policy only.
    b.apply(vec![b_peer(true)]).await;
    let (is_post, msg) = bmp_route(&mut c).await;
    assert!(
        is_post && matches!(&msg, BgpMessage::Update(upd) if upd.nlri.len() == 1),
        "{msg:?}"
    );

    // A withdraws it: the raw withdraw (pre) and the stored removal (is_post).
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(Vec::new()))
        .await;
    let mut seen = [false; 2];
    while seen != [true, true] {
        let (is_post, msg) = bmp_route(&mut c).await;
        // A late End-of-RIB of the peer's own (a pre-existing race) is not a withdraw.
        if matches!(msg, BgpMessage::EndOfRib { .. }) {
            continue;
        }
        assert!(
            matches!(&msg, BgpMessage::Update(upd) if upd.withdrawn_routes.len()
                + upd.mp_unreach.iter().map(|msg| msg.withdrawn.len()).sum::<usize>() == 1),
            "{msg:?}"
        );
        seen[usize::from(is_post)] = true;
    }
    assert_eq!(seen, [true, true]);
    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

/// #864: without soft-reconfiguration inbound the pre-policy dump is skipped
/// (its End-of-RIB is still sent) and the is_post-policy dump is complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bmp_pre_policy_dump_is_skipped_without_retention() {
    use nos_bgp::message::BgpMessage;
    let collector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = collector.local_addr().unwrap().port();
    let (a, b, _) = routers();
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
            prefix: "198.51.100.0/24".parse().unwrap(),
            gateway: "10.0.0.9".parse().unwrap(),
        }]))
        .await;
    a.apply(vec![unicast_only(peer(B, A, 65002))]).await;
    b.apply(vec![unicast_only(peer(A, B, 65001))]).await;
    b.wait_for(BgpSessionState::Established).await;
    eventually("b learns the route", || async {
        b.manager
            .bgp_push_snapshot()
            .await
            .1
            .contains_key(&"198.51.100.0/24".parse().unwrap())
    })
    .await;
    b.manager
        .set_bmp_stations(&[station(port)], Some("rt1".into()), None)
        .await;
    let (mut c, _) = collector.accept().await.unwrap();
    assert_eq!(bmp_frame(&mut c).await.0, 4);
    assert_eq!(bmp_frame(&mut c).await.0, 3);
    let (is_post, msg) = bmp_route(&mut c).await;
    assert!(
        !is_post && matches!(msg, BgpMessage::EndOfRib { afi: 1, safi: 1 }),
        "pre: only the End-of-RIB"
    );
    // A live End-of-RIB of the peer's own may follow (#942): skip one.
    let (mut is_post, mut msg) = bmp_route(&mut c).await;
    if !is_post && matches!(msg, BgpMessage::EndOfRib { .. }) {
        (is_post, msg) = bmp_route(&mut c).await;
    }
    assert!(
        is_post && matches!(&msg, BgpMessage::Update(upd) if upd.nlri.len() == 1),
        "{msg:?}"
    );
    let (is_post, msg) = bmp_route(&mut c).await;
    assert!(is_post && matches!(msg, BgpMessage::EndOfRib { afi: 1, safi: 1 }));
    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

/// #864: an EVPN route is part of both dumps (the pre-policy one from
/// retention), each family closed by its own End-of-RIB, and a later
/// withdrawal reaches the collector as an `MP_UNREACH` on both streams.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bmp_dump_covers_evpn_and_its_end_of_rib() {
    use nos_bgp::message::BgpMessage;
    let collector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = collector.local_addr().unwrap().port();
    let (a, b, _) = routers();
    let key = nos_proto::EvpnKey::Mac {
        rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
        mac: [0, 0, 0, 0, 0, 7],
    };
    a.manager
        .apply_evpn_local(
            "dom",
            nos_proto::EvpnUpdate::Full(vec![nos_proto::EvpnRoute {
                key: key.clone(),
                vni: 10100,
                next_hop: IpAddr::V4(A),
                ext_communities: vec![0x0002_fde8_0000_2774],
                esi: [0; 10],
                l3_vni: None,
            }]),
        )
        .await;
    a.apply(vec![peer(B, A, 65002)]).await;
    let mut pb = peer(A, B, 65001);
    pb.soft_reconfiguration_inbound = true;
    b.apply(vec![pb]).await;
    b.wait_for(BgpSessionState::Established).await;
    eventually("b holds the EVPN route", || async {
        b.manager
            .evpn_page(&mut nos_bgp::page::Snapshot::default(), None, 0, usize::MAX)
            .await
            .0
            .len()
            == 1
    })
    .await;
    b.manager
        .set_bmp_stations(&[station(port)], Some("rt1".into()), None)
        .await;
    let (mut c, _) = collector.accept().await.unwrap();
    assert_eq!(bmp_frame(&mut c).await.0, 4);
    assert_eq!(bmp_frame(&mut c).await.0, 3);
    // The peer's own End-of-RIB may be forwarded as well, at a moment that
    // depends on timing: collect until the dump is complete, ignoring repeats.
    let mut seen = std::collections::BTreeSet::new();
    while seen.len() < 6 {
        let (is_post, msg) = bmp_route(&mut c).await;
        let what = match msg {
            BgpMessage::Update(u) => {
                assert_eq!(u.mp_reach[0].evpn.len(), 1);
                "evpn route".to_string()
            }
            BgpMessage::EndOfRib { afi, safi } => format!("eor {afi}/{safi}"),
            other => panic!("{other:?}"),
        };
        seen.insert((is_post, what));
    }
    for post in [false, true] {
        for what in ["evpn route", "eor 1/1", "eor 25/70"] {
            assert!(seen.contains(&(post, what.to_string())), "{post} {what}");
        }
    }
    a.manager
        .apply_evpn_local("dom", nos_proto::EvpnUpdate::Remove(key))
        .await;
    let mut seen = [false; 2];
    while seen != [true, true] {
        let (is_post, msg) = bmp_route(&mut c).await;
        if matches!(msg, BgpMessage::EndOfRib { .. }) {
            continue;
        }
        assert!(
            matches!(&msg, BgpMessage::Update(u) if u.mp_unreach[0].evpn.len() == 1),
            "{msg:?}"
        );
        seen[usize::from(is_post)] = true;
    }
    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

/// A Statistics Report body as `(stat type, value octets)`, past the 42-byte
/// per-peer header and the count.
fn stat_entries(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let count = u32::from_be_bytes(body[42..46].try_into().unwrap());
    let mut rest = &body[46..];
    let mut out = Vec::new();
    for _ in 0..count {
        let t = u16::from_be_bytes([rest[0], rest[1]]);
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        out.push((t, rest[4..4 + len].to_vec()));
        rest = &rest[4 + len..];
    }
    assert_eq!(rest.len(), 0);
    out
}

/// #864: a station with `statistics-interval` gets one Statistics Report per
/// Established peer per interval: the inbound-policy reject counter and the
/// Adj-RIB-In gauges.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bmp_statistics_report_every_interval() {
    let collector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = collector.local_addr().unwrap().port();
    let (a, b, _) = routers();
    let route = RedistributedRoute {
        prefix: "198.51.100.0/24".parse().unwrap(),
        gateway: "10.0.0.9".parse().unwrap(),
    };
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![route]))
        .await;
    a.apply(vec![unicast_only(peer(B, A, 65002))]).await;
    let mut deny = unicast_only(peer(A, B, 65001));
    deny.import_policy = Arc::new(nos_rpl::DENY_ALL.clone());
    b.apply(vec![deny]).await;
    b.wait_for(BgpSessionState::Established).await;
    let mut st = station(port);
    st.statistics_interval = Some(1);
    b.manager
        .set_bmp_stations(&[st], Some("rt1".into()), None)
        .await;
    let (mut c, _) = collector.accept().await.unwrap();
    for _ in 0..2 {
        let body = loop {
            let (t, body) = bmp_frame(&mut c).await;
            if t == 1 {
                break body;
            }
        };
        assert_eq!(body[1] & 0x40, 0, "L flag clear");
        let stats = stat_entries(&body);
        let val = |t: u16| stats.iter().find(|s| s.0 == t).map(|s| s.1.clone());
        assert_eq!(val(0), Some(1u32.to_be_bytes().to_vec()), "rejected");
        assert_eq!(val(7), Some(0u64.to_be_bytes().to_vec()), "Adj-RIB-In");
        assert!(stats.iter().any(|s| s.0 == 9 && s.1.len() == 11));
    }
    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

/// The next `n` Adj-RIB-Out Route Monitoring frames (O = 1) off the fake
/// collector, as (L, A, message); anything else is skipped.
async fn bmp_out_frames(
    s: &mut tokio::net::TcpStream,
    n: usize,
) -> Vec<(bool, bool, nos_bgp::message::BgpMessage)> {
    use tokio_util::codec::Decoder;
    let mut out = Vec::new();
    while out.len() < n {
        let (t, body) = bmp_frame(s).await;
        if t != 0 || body[1] & 0x10 == 0 {
            continue;
        }
        let mut b = bytes::BytesMut::from(&body[42..]);
        let msg = nos_bgp::message::BgpCodec::default()
            .decode(&mut b)
            .unwrap()
            .expect("a whole PDU");
        out.push((body[1] & 0x40 != 0, body[1] & 0x20 != 0, msg));
    }
    out
}

fn announces(msg: &nos_bgp::message::BgpMessage, prefix: &str) -> bool {
    let p: ipnet::IpNet = prefix.parse().unwrap();
    matches!(msg, nos_bgp::message::BgpMessage::Update(u)
        if u.nlri.iter().any(|n| IpAddr::from(n.addr()) == p.addr())
            || u.mp_reach.iter().any(|m| m.nlri.contains(&p)))
}

/// #867: RFC 8671 Adj-RIB-Out: the connect-time dump (both views, each closed
/// by an O = 1 End-of-RIB), the wire increment and withdrawal, and a
/// `monitor-out` change reconnecting the station with only the new view.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bmp_adj_rib_out_dump_increments_and_mode_change() {
    use nos_bgp::message::BgpMessage;
    use nos_proto::BmpMonitorOut::{Both, PostPolicy};
    let station_out = |port, out| nos_proto::BmpStation {
        monitor_out: out,
        ..station(port)
    };
    let collector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = collector.local_addr().unwrap().port();
    let (a, b, _) = routers();
    let route = |p: &str| RedistributedRoute {
        prefix: p.parse().unwrap(),
        gateway: "10.0.0.9".parse().unwrap(),
    };
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![route("198.51.100.0/24")]))
        .await;
    a.apply(vec![unicast_only(peer(B, A, 65002))]).await;
    b.apply(vec![unicast_only(peer(A, B, 65001))]).await;
    b.wait_for(BgpSessionState::Established).await;
    a.wait_for(BgpSessionState::Established).await;
    eventually("b learns the route", || async {
        b.manager.peer_summaries().await[0].accepted_prefixes == Some([1, 0, 0])
    })
    .await;

    a.manager
        .set_bmp_stations(&[station_out(port, Both)], Some("rt1".into()), None)
        .await;
    let (mut c, _) = collector.accept().await.unwrap();
    // Dump: post update, pre update, then one End-of-RIB per view.
    let dump = bmp_out_frames(&mut c, 4).await;
    let routes: Vec<_> = dump
        .iter()
        .filter(|f| announces(&f.2, "198.51.100.0/24"))
        .collect();
    assert_eq!(routes.len(), 2, "{dump:?}");
    assert!(
        routes.iter().any(|f| f.0) && routes.iter().any(|f| !f.0),
        "both views"
    );
    let eors: Vec<_> = dump
        .iter()
        .filter(|f| matches!(f.2, BgpMessage::EndOfRib { afi: 1, safi: 1 }))
        .collect();
    assert_eq!(eors.len(), 2, "{dump:?}");
    assert!(dump.iter().all(|f| !f.1), "4-octet AS session: A clear");

    // Withdrawal: pre-policy candidate gone, and the wire withdrawal.
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(Vec::new()))
        .await;
    let gone = bmp_out_frames(&mut c, 2).await;
    assert!(
        gone.iter().any(|f| f.0) && gone.iter().any(|f| !f.0),
        "{gone:?}"
    );
    assert!(gone.iter().all(|f| matches!(&f.2, BgpMessage::Update(u)
        if u.withdrawn_routes.len() + u.mp_unreach.iter().map(|m| m.withdrawn.len()).sum::<usize>() == 1)));

    // RFC 8671 section 7.2: a mode change bounces the session, new view only.
    a.manager
        .set_bmp_stations(&[station_out(port, PostPolicy)], Some("rt1".into()), None)
        .await;
    let (mut c, _) = collector.accept().await.unwrap();
    let dump = bmp_out_frames(&mut c, 1).await;
    assert!(
        dump[0].0 && matches!(dump[0].2, BgpMessage::EndOfRib { .. }),
        "{dump:?}"
    );
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![route("203.0.113.0/24")]))
        .await;
    let inc = bmp_out_frames(&mut c, 1).await;
    assert!(
        inc[0].0 && announces(&inc[0].2, "203.0.113.0/24"),
        "{inc:?}"
    );
    // Nothing else Out: the pre-policy view is off.
    assert!(
        tokio::time::timeout(Duration::from_millis(800), bmp_out_frames(&mut c, 1))
            .await
            .is_err()
    );
    a.manager.shutdown().await;
    b.manager.shutdown().await;
}

/// #867: a peer that comes up after the station connected: the pre-policy
/// candidates are announced by the peer-up sync, the post-policy ones by the
/// wire hook.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bmp_adj_rib_out_follows_a_peer_that_comes_up_later() {
    let collector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = collector.local_addr().unwrap().port();
    let (a, b, _) = routers();
    a.manager
        .apply_redistribute_update(RedistributeUpdate::Full(vec![RedistributedRoute {
            prefix: "198.51.100.0/24".parse().unwrap(),
            gateway: "10.0.0.9".parse().unwrap(),
        }]))
        .await;
    a.apply(vec![]).await; // resolves the VRF, no peer yet
    let mut st = station(port);
    st.monitor_out = nos_proto::BmpMonitorOut::Both;
    a.manager
        .set_bmp_stations(&[st], Some("rt1".into()), None)
        .await;
    let (mut c, _) = collector.accept().await.unwrap();
    assert_eq!(bmp_frame(&mut c).await.0, 4, "Initiation, no peer yet");
    a.apply(vec![unicast_only(peer(B, A, 65002))]).await;
    b.apply(vec![unicast_only(peer(A, B, 65001))]).await;
    let mut seen = [false; 2]; // [pre-policy, post-policy]
    while seen != [true; 2] {
        let f = bmp_out_frames(&mut c, 1).await.remove(0);
        if announces(&f.2, "198.51.100.0/24") {
            seen[usize::from(f.0)] = true;
        }
    }
    a.manager.shutdown().await;
    b.manager.shutdown().await;
}
