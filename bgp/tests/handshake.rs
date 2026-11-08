//! Integration tests for `nos_bgp::fsm::run` over real loopback TCP
//! connections — this crate's first `tests/` integration directory. Unlike
//! `fsm.rs`'s unit tests (which exercise the pure `step` function), these
//! drive the actual async orchestrator end to end.
//!
//! `fsm::run` has no observable "we reached Established" signal other than
//! staying alive (it only returns once a session ends), so these tests use
//! a bounded timeout as a stable-session proxy: a session that neither
//! errors out nor times out immediately, but is still running once the
//! OPEN/KEEPALIVE exchange has had time to complete, is presumed
//! `Established`.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_bgp::collision::{PeerSlot, Role};
use nos_bgp::fsm::{self, FsmOutcome, PeerContext};
use nos_bgp::message::{self, BgpCodec, BgpMessage};
use nos_bgp::rib::{BgpRib, SharedRib};
use nos_bgp::session::{LocalIdentity, ResolvedPeer};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{FramedRead, FramedWrite};

fn new_bgp_rib() -> Arc<SharedRib> {
    Arc::new(SharedRib::new(BgpRib::new()))
}

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, connected) = tokio::join!(async { listener.accept().await.unwrap().0 }, async {
        TcpStream::connect(addr).await.unwrap()
    },);
    (connected, accepted)
}

/// A minimal stand-in peer: sends its own OPEN immediately, replies to the
/// real side's OPEN with a KEEPALIVE, then holds the connection open so the
/// real side's hold timer never fires during the test.
async fn fake_peer(stream: TcpStream, asn: u32, router_id: Ipv4Addr, hold_time: u16) {
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, BgpCodec::default());
    let mut writer = FramedWrite::new(w, BgpCodec::default());

    let _ = writer
        .send(BgpMessage::Open(message::build_open(
            asn, router_id, hold_time,
        )))
        .await;

    loop {
        match reader.next().await {
            Some(Ok(BgpMessage::Open(_))) => {
                let _ = writer.send(BgpMessage::Keepalive).await;
                break;
            }
            Some(Ok(_)) => {}
            _ => return,
        }
    }
    while reader.next().await.is_some() {}
}

#[tokio::test]
async fn two_real_instances_establish_a_session() {
    let (a_stream, b_stream) = loopback_pair().await;

    let a_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let b_router_id = Ipv4Addr::new(2, 2, 2, 2);
    let a_asn = 65001;
    let b_asn = 65002;

    let slot_a = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.2".parse().unwrap(),
        source_address: None,
        remote_as: b_asn,
        peer_group: "pg1".to_string(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
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
        graceful_restart: None,
    });
    let slot_b = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.1".parse().unwrap(),
        source_address: None,
        remote_as: a_asn,
        peer_group: "pg1".to_string(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
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
        graceful_restart: None,
    });

    let a_fut = fsm::run(
        a_stream,
        Role::Active,
        LocalIdentity {
            asn: a_asn,
            router_id: a_router_id,
            cluster_id: a_router_id,
            confed_id: None,
        },
        PeerContext {
            remote_address: "10.0.0.2".parse().unwrap(),
            expected_remote_as: b_asn,
            local_hold_time: 90,
            keepalive_override: None,
            mrai: Duration::ZERO,
            route_refresh_stale_time: Duration::ZERO,
            damping: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            is_rr_client: false,
            is_rs_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_a,
        new_bgp_rib(),
    );
    let b_fut = fsm::run(
        b_stream,
        Role::Passive,
        LocalIdentity {
            asn: b_asn,
            router_id: b_router_id,
            cluster_id: b_router_id,
            confed_id: None,
        },
        PeerContext {
            remote_address: "10.0.0.1".parse().unwrap(),
            expected_remote_as: a_asn,
            local_hold_time: 90,
            keepalive_override: None,
            mrai: Duration::ZERO,
            route_refresh_stale_time: Duration::ZERO,
            damping: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            is_rr_client: false,
            is_rs_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_b,
        new_bgp_rib(),
    );

    let timeout = Duration::from_millis(500);
    let (a_result, b_result) = tokio::join!(
        tokio::time::timeout(timeout, a_fut),
        tokio::time::timeout(timeout, b_fut),
    );

    assert!(
        a_result.is_err(),
        "instance A should have reached a stable (Established) session, got {a_result:?}"
    );
    assert!(
        b_result.is_err(),
        "instance B should have reached a stable (Established) session, got {b_result:?}"
    );
}

/// Exercises a non-default, configured local hold time end to end: the real
/// side proposes 30s, the fake peer proposes 60s, so negotiation must settle
/// on `min(30, 60) = 30` — the session should still establish and stay
/// stable well within the test's bounded timeout.
#[tokio::test]
async fn established_session_honors_configured_non_default_hold_time() {
    let (a_stream, b_stream) = loopback_pair().await;

    let a_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let b_router_id = Ipv4Addr::new(2, 2, 2, 2);
    let a_asn = 65001;
    let b_asn = 65002;

    let slot_a = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.2".parse().unwrap(),
        source_address: None,
        remote_as: b_asn,
        peer_group: "pg1".to_string(),
        hold_time: 30,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
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
        graceful_restart: None,
    });

    let a_fut = fsm::run(
        a_stream,
        Role::Active,
        LocalIdentity {
            asn: a_asn,
            router_id: a_router_id,
            cluster_id: a_router_id,
            confed_id: None,
        },
        PeerContext {
            remote_address: "10.0.0.2".parse().unwrap(),
            expected_remote_as: b_asn,
            local_hold_time: 30,
            keepalive_override: None,
            mrai: Duration::ZERO,
            route_refresh_stale_time: Duration::ZERO,
            damping: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            is_rr_client: false,
            is_rs_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_a,
        new_bgp_rib(),
    );
    let fake_b = tokio::spawn(fake_peer(b_stream, b_asn, b_router_id, 60));

    let timeout = Duration::from_millis(500);
    let a_result = tokio::time::timeout(timeout, a_fut).await;

    assert!(
        a_result.is_err(),
        "instance A should have reached a stable (Established) session \
         negotiated at min(30, 60) = 30s, got {a_result:?}"
    );

    fake_b.abort();
}

/// Exercises the shared `PeerSlot::status` reporting path end to end: once a
/// real session reaches `Established`, the slot's status (read via
/// `status_receiver`, the same way `session::to_peer_summary` does for
/// `show bgp brief`) must reflect it, including the negotiated hold-time and
/// keepalive derived during the handshake.
#[tokio::test]
async fn established_session_reports_status_via_peer_slot() {
    let (a_stream, b_stream) = loopback_pair().await;

    let a_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let b_router_id = Ipv4Addr::new(2, 2, 2, 2);
    let a_asn = 65001;
    let b_asn = 65002;

    let slot_a = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.2".parse().unwrap(),
        source_address: None,
        remote_as: b_asn,
        peer_group: "pg1".to_string(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
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
        graceful_restart: None,
    });
    let mut status = slot_a.status_receiver();

    let a_fut = fsm::run(
        a_stream,
        Role::Active,
        LocalIdentity {
            asn: a_asn,
            router_id: a_router_id,
            cluster_id: a_router_id,
            confed_id: None,
        },
        PeerContext {
            remote_address: "10.0.0.2".parse().unwrap(),
            expected_remote_as: b_asn,
            local_hold_time: 90,
            keepalive_override: None,
            mrai: Duration::ZERO,
            route_refresh_stale_time: Duration::ZERO,
            damping: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            is_rr_client: false,
            is_rs_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_a,
        new_bgp_rib(),
    );
    let fake_b = tokio::spawn(fake_peer(b_stream, b_asn, b_router_id, 90));

    let timeout = Duration::from_millis(500);
    let a_result = tokio::time::timeout(timeout, a_fut).await;
    assert!(
        a_result.is_err(),
        "instance A should have reached a stable (Established) session, got {a_result:?}"
    );

    // The session is presumed Established by now (per this module's timeout
    // convention); `status`'s watch channel already holds the latest value.
    let reported = *status.borrow_and_update();
    assert_eq!(reported.state, nos_bgp::status::PeerState::Established);
    assert_eq!(reported.remote_asn, Some(b_asn));
    assert_eq!(reported.remote_bgp_id, Some(b_router_id));
    assert_eq!(reported.negotiated_hold_time, Some(90));
    assert_eq!(reported.negotiated_keepalive, Some(30));
    assert!(reported.established_since.is_some());

    fake_b.abort();
}

/// Races a real active and a real passive connection against the same
/// `PeerSlot` for what looks like one peer. Over real sockets, one side's
/// full OPEN/KEEPALIVE round trip inevitably completes (reaches
/// `Established`) before the other side's OPEN is even processed, so this
/// exercises `collision.rs`'s Established-precedence rule rather than the
/// ID-comparison path — the two connections essentially never call
/// `on_open` "at the same time" in practice, no matter how the router-ids
/// are chosen. The ID-comparison path itself is covered deterministically
/// by `collision.rs`'s own unit tests, which call `PeerSlot::on_open`
/// directly without socket timing involved.
#[tokio::test]
async fn collision_leaves_exactly_one_side_running() {
    let (active_local, active_fake) = loopback_pair().await;
    let (passive_local, passive_fake) = loopback_pair().await;

    // Same remote ASN/router-id on both connections — as far as collision
    // resolution is concerned, this is one peer racing an active and a
    // passive connection against the same local instance.
    let remote_asn = 65002;
    let remote_router_id = Ipv4Addr::new(9, 9, 9, 9);
    let local = LocalIdentity {
        asn: 65001,
        router_id: Ipv4Addr::new(5, 5, 5, 5),
        cluster_id: Ipv4Addr::new(5, 5, 5, 5),
        confed_id: None,
    };

    let fake_active = tokio::spawn(fake_peer(active_fake, remote_asn, remote_router_id, 90));
    let fake_passive = tokio::spawn(fake_peer(passive_fake, remote_asn, remote_router_id, 90));

    let slot = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.2".parse().unwrap(),
        source_address: None,
        remote_as: remote_asn,
        peer_group: "pg1".to_string(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
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
        graceful_restart: None,
    });

    let peer_ctx = || PeerContext {
        remote_address: "10.0.0.2".parse().unwrap(),
        expected_remote_as: remote_asn,
        local_hold_time: 90,
        keepalive_override: None,
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        is_rr_client: false,
        is_rs_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
    };

    // Both sides share one `PeerSlot` (they're racing for the same peer), so
    // they share one `BgpRib` too — a real deployment would never run two
    // `fsm::run` tasks against different `BgpRib`s for the same peer.
    let bgp_rib = new_bgp_rib();
    let active_fut = fsm::run(
        active_local,
        Role::Active,
        local,
        peer_ctx(),
        slot.clone(),
        bgp_rib.clone(),
    );
    let passive_fut = fsm::run(
        passive_local,
        Role::Passive,
        local,
        peer_ctx(),
        slot.clone(),
        bgp_rib.clone(),
    );

    let timeout = Duration::from_millis(500);
    let (active_result, passive_result) = tokio::join!(
        tokio::time::timeout(timeout, active_fut),
        tokio::time::timeout(timeout, passive_fut),
    );

    let active_lost = matches!(active_result, Ok(FsmOutcome::CollisionLost));
    let passive_lost = matches!(passive_result, Ok(FsmOutcome::CollisionLost));
    assert!(
        active_lost ^ passive_lost,
        "expected exactly one side to lose the collision, got active={active_result:?} passive={passive_result:?}"
    );
    // The winner should have settled into a stable (Established) session,
    // not returned any outcome at all within the timeout.
    assert!(
        active_lost || active_result.is_err(),
        "active side neither lost the collision nor stayed running: {active_result:?}"
    );
    assert!(
        passive_lost || passive_result.is_err(),
        "passive side neither lost the collision nor stayed running: {passive_result:?}"
    );

    // RFC 4271 §6.8 regression: `BgpRib` is keyed by peer address, not by
    // connection, so the loser's teardown must not deregister the peer the
    // winner just registered. Before this was fixed the loser's
    // `peer_disconnected` wiped the winner's `adj_rib_in` *and* its outbox,
    // leaving a session that stayed up but could never advertise again —
    // which is what made tools/verify-bgp.sh's `communities` phase fail.
    assert!(
        bgp_rib.lock().await.has_peer("10.0.0.2".parse().unwrap()),
        "collision loser's teardown deregistered the winning session's outbox"
    );

    fake_active.abort();
    fake_passive.abort();
}

/// A peer that offers the EVPN capability (AFI 25 / SAFI 70), reports whether
/// the real side's OPEN offered it too, then — once the real side has had a
/// moment to reach `Established` — announces one Type-2 and one Type-3 route.
async fn fake_evpn_peer(
    stream: TcpStream,
    asn: u32,
    router_id: Ipv4Addr,
    saw_evpn_capability: tokio::sync::oneshot::Sender<bool>,
) {
    use nos_bgp::evpn::EvpnNlri;

    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, BgpCodec::default());
    let mut writer = FramedWrite::new(w, BgpCodec::default());

    let mut open = message::build_open(asn, router_id, 90);
    for (afi, safi) in [(1, 1), (25, 70)] {
        open.capabilities
            .push(message::Capability::MultiProtocol { afi, safi });
    }
    let _ = writer.send(BgpMessage::Open(open)).await;

    let mut saw_evpn_capability = Some(saw_evpn_capability);
    loop {
        match reader.next().await {
            Some(Ok(BgpMessage::Open(theirs))) => {
                let offered = theirs
                    .capabilities
                    .iter()
                    .any(|c| matches!(c, message::Capability::MultiProtocol { afi: 25, safi: 70 }));
                let _ = saw_evpn_capability.take().unwrap().send(offered);
                let _ = writer.send(BgpMessage::Keepalive).await;
                break;
            }
            Some(Ok(_)) => {}
            _ => return,
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
    let update = message::UpdateMessage {
        withdrawn_routes: vec![],
        withdrawn_path_ids: vec![],
        nlri: vec![],
        nlri_path_ids: vec![],
        attributes: Some(message::PathAttributes {
            origin: message::Origin::Igp,
            as_path: vec![asn].into(),
            next_hop: Ipv4Addr::UNSPECIFIED,
            local_pref: None,
            med: None,
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: vec![],
            extended_communities: vec![0x0002_fde8_0000_2710],
            large_communities: vec![],
            ipv6_extended_communities: Vec::new(),
            pmsi: None,
        }),
        mp_reach: vec![message::MpReachNlri {
            afi: 25,
            safi: 70,
            next_hop: "192.0.2.2".parse().unwrap(),
            nlri: vec![],
            nlri_path_ids: vec![],
            flowspec: vec![],
            vpn: Vec::new(),
            rtc: Vec::new(),
            evpn: vec![
                EvpnNlri::MacIp {
                    rd,
                    esi: [0; 10],
                    tag: 0,
                    mac: [0xaa, 0, 0, 0, 0, 1],
                    ip: None,
                    labels: vec![10_000],
                },
                EvpnNlri::InclusiveMulticast {
                    rd,
                    tag: 0,
                    origin: "192.0.2.2".parse().unwrap(),
                },
            ],
        }],
        mp_unreach: vec![],
        ..Default::default()
    };
    let _ = writer.send(BgpMessage::Update(update)).await;
    while reader.next().await.is_some() {}
}

#[tokio::test]
async fn evpn_routes_from_a_real_session_are_stored_and_cleared_on_close() {
    let (a_stream, b_stream) = loopback_pair().await;
    let (a_asn, b_asn) = (65001, 65002);
    let a_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let peer_addr: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    let families = vec![
        nos_proto::AddressFamily::Ipv4Unicast,
        nos_proto::AddressFamily::L2vpnEvpn,
    ];

    let slot_a = PeerSlot::new(ResolvedPeer {
        remote_address: peer_addr,
        source_address: None,
        remote_as: b_asn,
        peer_group: "pg1".to_string(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: families.clone(),
        route_reflector_client: false,
        route_server_client: false,
        import_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
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
        graceful_restart: None,
    });
    let rib = new_bgp_rib();
    rib.lock()
        .await
        .set_local_identity(a_asn, a_router_id, a_router_id);

    let a = tokio::spawn(fsm::run(
        a_stream,
        Role::Active,
        LocalIdentity {
            asn: a_asn,
            router_id: a_router_id,
            cluster_id: a_router_id,
            confed_id: None,
        },
        PeerContext {
            remote_address: peer_addr,
            expected_remote_as: b_asn,
            local_hold_time: 90,
            keepalive_override: None,
            mrai: Duration::ZERO,
            route_refresh_stale_time: Duration::ZERO,
            damping: None,
            next_hop: None,
            address_families: families,
            is_rr_client: false,
            is_rs_client: false,
            import_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_a,
        rib.clone(),
    ));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let fake_b = tokio::spawn(fake_evpn_peer(
        b_stream,
        b_asn,
        Ipv4Addr::new(2, 2, 2, 2),
        tx,
    ));

    assert!(
        rx.await.unwrap(),
        "our OPEN must offer MP capability 25/70 when the peer-group has l2vpn-evpn"
    );

    let mut learned = 0;
    for _ in 0..1500 {
        learned = rib.lock().await.evpn_routes().len();
        if learned == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(learned, 2, "both EVPN routes should reach the RIB");
    let guard = rib.lock().await;
    let routes = guard.evpn_routes();
    assert_eq!(routes[0].0, peer_addr);
    assert_eq!(
        routes[0].2.next_hop,
        "192.0.2.2".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(
        routes[0].2.extended_communities,
        vec![0x0002_fde8_0000_2710]
    );
    drop(guard);

    // Peer goes away: the session ends and its EVPN routes go with it.
    fake_b.abort();
    let _ = tokio::time::timeout(Duration::from_secs(30), a).await;
    assert_eq!(
        rib.lock().await.evpn_routes(),
        [] as [(
            std::net::IpAddr,
            &nos_bgp::evpn::EvpnNlri,
            &nos_bgp::rib::EvpnRoute
        ); 0]
    );
}

/// A peer negotiating RFC 7313 enhanced route refresh that announces P1 and
/// P2, sends `BoRR`, re-announces only P1, then — if `eorr` — sends `EoRR` and
/// re-announces P2 again.
async fn fake_refresh_peer(stream: TcpStream, asn: u32, eorr: bool) {
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, BgpCodec::default());
    let mut writer = FramedWrite::new(w, BgpCodec::default());

    let mut open = message::build_open(asn, Ipv4Addr::new(2, 2, 2, 2), 90);
    open.capabilities.extend([
        message::Capability::MultiProtocol { afi: 1, safi: 1 },
        message::Capability::RouteRefresh,
        message::Capability::EnhancedRouteRefresh,
    ]);
    let _ = writer.send(BgpMessage::Open(open)).await;
    loop {
        match reader.next().await {
            Some(Ok(BgpMessage::Open(_))) => {
                let _ = writer.send(BgpMessage::Keepalive).await;
                break;
            }
            Some(Ok(_)) => {}
            _ => return,
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let update = |prefixes: &[&str]| {
        BgpMessage::Update(message::UpdateMessage {
            withdrawn_routes: vec![],
            withdrawn_path_ids: vec![],
            nlri: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            nlri_path_ids: vec![],
            attributes: Some(message::PathAttributes {
                origin: message::Origin::Igp,
                as_path: vec![asn].into(),
                next_hop: Ipv4Addr::new(10, 0, 0, 2),
                local_pref: None,
                med: None,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
                otc: None,
                cluster_list: vec![],
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                ipv6_extended_communities: Vec::new(),
                pmsi: None,
            }),
            mp_reach: vec![],
            mp_unreach: vec![],
            ..Default::default()
        })
    };
    let marker = |subtype| {
        BgpMessage::RouteRefresh(message::RouteRefreshMessage {
            afi: 1,
            subtype,
            safi: 1,
        })
    };
    let _ = writer
        .send(update(&["192.0.2.0/24", "198.51.100.0/24"]))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = writer.send(marker(message::REFRESH_BORR)).await;
    let _ = writer.send(update(&["192.0.2.0/24"])).await;
    if eorr {
        let _ = writer.send(marker(message::REFRESH_EORR)).await;
        let _ = writer.send(update(&["198.51.100.0/24"])).await;
    }
    while reader.next().await.is_some() {}
}

/// Runs `fake_refresh_peer` against a real session with `stale_time` and
/// returns the accepted IPv4 prefix count from it after 2s, asserting the
/// session survived.
async fn refresh_case(stale_time: Duration, eorr: bool) -> u32 {
    let (a_stream, b_stream) = loopback_pair().await;
    let (a_asn, b_asn) = (65001, 65002);
    let a_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let peer_addr: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    let families = vec![nos_proto::AddressFamily::Ipv4Unicast];
    let slot_a = PeerSlot::new(ResolvedPeer {
        remote_address: peer_addr,
        source_address: None,
        remote_as: b_asn,
        peer_group: "pg1".to_string(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        mrai: Duration::ZERO,
        route_refresh_stale_time: stale_time,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: families.clone(),
        route_reflector_client: false,
        route_server_client: false,
        import_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
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
        graceful_restart: None,
    });
    let rib = new_bgp_rib();
    rib.lock()
        .await
        .set_local_identity(a_asn, a_router_id, a_router_id);
    let a = tokio::spawn(fsm::run(
        a_stream,
        Role::Active,
        LocalIdentity {
            asn: a_asn,
            router_id: a_router_id,
            cluster_id: a_router_id,
            confed_id: None,
        },
        PeerContext {
            remote_address: peer_addr,
            expected_remote_as: b_asn,
            local_hold_time: 90,
            keepalive_override: None,
            mrai: Duration::ZERO,
            route_refresh_stale_time: stale_time,
            damping: None,
            next_hop: None,
            address_families: families,
            is_rr_client: false,
            is_rs_client: false,
            import_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_a,
        rib.clone(),
    ));
    let fake_b = tokio::spawn(fake_refresh_peer(b_stream, b_asn, eorr));

    let mut held = 0;
    for _ in 0..1500 {
        held = rib.lock().await.accepted_prefixes(peer_addr)[0];
        if held == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(held, 2, "both prefixes should be learned before the BoRR");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!a.is_finished(), "the session must survive the stale timer");
    let held = rib.lock().await.accepted_prefixes(peer_addr)[0];
    fake_b.abort();
    a.abort();
    held
}

#[tokio::test]
async fn route_refresh_stale_timer_purges_when_no_eorr_arrives() {
    assert_eq!(refresh_case(Duration::from_secs(1), false).await, 1);
}

#[tokio::test]
async fn route_refresh_stale_timer_is_cancelled_by_eorr() {
    // EoRR purged P2, then P2 was re-learned; nothing purges it afterwards.
    assert_eq!(refresh_case(Duration::from_secs(1), true).await, 2);
}

#[tokio::test]
async fn zero_route_refresh_stale_time_keeps_stale_routes() {
    assert_eq!(refresh_case(Duration::ZERO, false).await, 2);
}

/// RFC 4271 §6.1: a message of an unknown type is answered with a Message
/// Header Error / Bad Message Type NOTIFICATION whose data is the type octet.
#[tokio::test]
async fn unknown_message_type_is_answered_with_bad_message_type() {
    use bytes::BytesMut;
    use tokio::io::AsyncWriteExt;
    use tokio_util::codec::Encoder;

    let (a_stream, b_stream) = loopback_pair().await;
    let a_router_id = Ipv4Addr::new(1, 1, 1, 1);
    let a_asn = 65001;
    let b_asn = 65002;

    let slot_a = PeerSlot::new(ResolvedPeer {
        remote_address: "10.0.0.2".parse().unwrap(),
        source_address: None,
        remote_as: b_asn,
        peer_group: "pg1".to_string(),
        hold_time: 30,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
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
        graceful_restart: None,
    });

    let a_fut = fsm::run(
        a_stream,
        Role::Active,
        LocalIdentity {
            asn: a_asn,
            router_id: a_router_id,
            cluster_id: a_router_id,
            confed_id: None,
        },
        PeerContext {
            remote_address: "10.0.0.2".parse().unwrap(),
            expected_remote_as: b_asn,
            local_hold_time: 30,
            keepalive_override: None,
            mrai: Duration::ZERO,
            route_refresh_stale_time: Duration::ZERO,
            damping: None,
            next_hop: None,
            address_families: vec![nos_proto::AddressFamily::Ipv4Unicast],
            is_rr_client: false,
            is_rs_client: false,
            import_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
            export_policy: std::sync::Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        },
        slot_a,
        new_bgp_rib(),
    );

    let fake_b = tokio::spawn(async move {
        let (r, mut w) = b_stream.into_split();
        let mut buf = BytesMut::new();
        BgpCodec::default()
            .encode(
                BgpMessage::Open(message::build_open(b_asn, Ipv4Addr::new(2, 2, 2, 2), 60)),
                &mut buf,
            )
            .unwrap();
        // A header-only message of the unassigned type 6.
        buf.extend_from_slice(&[0xff; 16]);
        buf.extend_from_slice(&19u16.to_be_bytes());
        buf.extend_from_slice(&[6]);
        w.write_all(&buf).await.unwrap();
        let mut reader = FramedRead::new(r, BgpCodec::default());
        loop {
            if let Some(Ok(BgpMessage::Notification(n))) = reader.next().await {
                return n;
            }
        }
    });

    let outcome = tokio::time::timeout(Duration::from_secs(5), a_fut)
        .await
        .expect("session should end on the bad message type");
    assert!(
        matches!(
            outcome,
            FsmOutcome::NotificationSent {
                code: 1,
                subcode: 3
            }
        ),
        "{outcome:?}"
    );
    let n = tokio::time::timeout(Duration::from_secs(5), fake_b)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((n.error_code, n.error_subcode), (1, 3));
    assert_eq!(&n.data[..], &[6]);
}
