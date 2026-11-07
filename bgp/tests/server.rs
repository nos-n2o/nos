//! Live role gate of the BGP IPC server over real mutual TLS (#364): a role
//! that may not send a request is disconnected with no reply, a role that may
//! gets a real answer. Complements the pure `allowed` tests in `server.rs`,
//! which cannot see the `handle_connection` glue.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_bgp::session::SessionManager;
use nos_pki::testing::shared;
use nos_pki::{PeerId, Stream};
use nos_proto::{BgpEvent, BgpRequest, EvpnUpdate, IpcCodec, RedistributeUpdate, Role};
use tokio_util::codec::{FramedRead, FramedWrite};

type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<BgpEvent>>;
type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<BgpRequest>>;

async fn connect_as(path: &std::path::Path, role: Role) -> (Reader, Writer) {
    let stream = shared()
        .identity(role.as_str(), "x")
        .connect(path, &PeerId::new("bgpd", "r1"))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    (
        FramedRead::new(r, IpcCodec::default()),
        FramedWrite::new(w, IpcCodec::default()),
    )
}

/// `true` while the server keeps the connection open and sends nothing.
async fn stays_open(reader: &mut Reader) -> bool {
    tokio::time::timeout(Duration::from_secs(1), reader.next())
        .await
        .is_err()
}

/// The next frame, or `None` when the server closed (or reset) instead.
async fn next_event(reader: &mut Reader) -> Option<BgpEvent> {
    tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("connection left open with no reply")
        .and_then(Result::ok)
}

fn start() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    tokio::task::JoinHandle<()>,
) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bgp.sock");
    // The default instance, no peers: `start` only binds the IPC socket.
    let server = nos_bgp::server::start(
        &path,
        "r1".to_string(),
        SessionManager::new("r1".to_string()),
        &shared().identity("bgpd", "r1"),
        tmp.path().join("no-watchdog.sock"),
    )
    .unwrap();
    (tmp, path, server)
}

fn is_person(role: Role) -> bool {
    matches!(role, Role::User | Role::Restd)
}

#[tokio::test]
async fn only_people_get_the_show_queries_answered() {
    let (_tmp, path, _server) = start();
    for role in Role::ALL {
        for query in 0..6 {
            let (mut r, mut w) = connect_as(&path, role).await;
            let req = match query {
                0 => BgpRequest::GetSummary,
                1 => BgpRequest::GetEvpnRoutesPage {
                    after: None,
                    limit: 10,
                },
                3 => BgpRequest::GetFlowspecRoutesPage {
                    after: None,
                    limit: 10,
                },
                4 => BgpRequest::GetVpnRoutesPage {
                    family: nos_proto::AddressFamily::Vpnv4Unicast,
                    rd: Some("65001:1".into()),
                    after: None,
                    limit: 10,
                },
                5 => BgpRequest::ShowBmp {
                    instance: "r1".into(),
                },
                _ => BgpRequest::GetRpkiSummary,
            };
            w.send(req).await.unwrap();
            let reply = next_event(&mut r).await;
            if !is_person(role) {
                assert!(reply.is_none(), "{role:?} query {query} must get no reply");
                continue;
            }
            let empty = match reply {
                Some(BgpEvent::Summary(v)) if query == 0 => v.is_empty(),
                Some(BgpEvent::EvpnRoutesPage { routes, next }) if query == 1 => {
                    routes.is_empty() && next.is_none()
                }
                Some(BgpEvent::RpkiSummary(v)) if query == 2 => v.is_empty(),
                Some(BgpEvent::BmpStatus(v)) if query == 5 => v.is_empty(),
                Some(BgpEvent::FlowspecRoutesPage { routes, next }) if query == 3 => {
                    routes.is_empty() && next.is_none()
                }
                Some(BgpEvent::VpnRoutesPage { routes, next }) if query == 4 => {
                    routes.is_empty() && next.is_none()
                }
                other => panic!("{role:?} query {query}: unexpected {other:?}"),
            };
            assert!(empty, "{role:?} query {query}: nothing is configured");
        }
    }
}

/// #723: the removed unpaged EVPN/Flowspec/VPN queries answer with an error
/// and keep the connection usable.
#[tokio::test]
async fn the_removed_unpaged_queries_answer_with_an_error() {
    let (_tmp, path, _server) = start();
    let (mut r, mut w) = connect_as(&path, Role::User).await;
    for req in [
        BgpRequest::GetEvpnRoutes,
        BgpRequest::GetFlowspecRoutes,
        BgpRequest::GetVpnRoutes {
            family: nos_proto::AddressFamily::Vpnv4Unicast,
            rd: None,
        },
    ] {
        w.send(req).await.unwrap();
        assert!(matches!(next_event(&mut r).await, Some(BgpEvent::Error(_))));
    }
}

#[tokio::test]
async fn only_people_may_clear_or_refresh_a_peer() {
    let (_tmp, path, _server) = start();
    let peer: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    for role in Role::ALL {
        for refresh in [false, true] {
            let (mut r, mut w) = connect_as(&path, role).await;
            let req = if refresh {
                BgpRequest::SendRouteRefresh { peer }
            } else {
                BgpRequest::ClearPeer { peer }
            };
            w.send(req).await.unwrap();
            let reply = next_event(&mut r).await;
            if is_person(role) {
                assert!(
                    matches!(reply, Some(BgpEvent::PeerNotFound)),
                    "{role:?} refresh={refresh}: {reply:?}"
                );
            } else {
                assert!(reply.is_none(), "{role:?} refresh={refresh}");
            }
        }
    }
}

/// The three feeds are fire-and-forget: the right role keeps its connection
/// open with no reply, any other role is disconnected.
#[tokio::test]
async fn each_feed_is_kept_for_its_one_role_and_refused_to_all_others() {
    let (_tmp, path, _server) = start();
    for (name, owner) in [
        ("routes", Role::Ribd),
        ("macs", Role::Fdbd),
        ("evpn prefixes", Role::Ribd),
    ] {
        for role in Role::ALL {
            let (mut r, mut w) = connect_as(&path, role).await;
            let req = match name {
                "routes" => BgpRequest::RedistributeRoutes(RedistributeUpdate::Full(vec![])),
                "macs" => BgpRequest::RedistributeMacs {
                    domain: "bd1".to_string(),
                    update: EvpnUpdate::Full(vec![]),
                },
                _ => BgpRequest::RedistributeEvpnPrefixes {
                    table: "tenant".to_string(),
                    update: EvpnUpdate::Full(vec![]),
                },
            };
            w.send(req).await.unwrap();
            if role == owner {
                assert!(stays_open(&mut r).await, "{name}: {role:?} was refused");
            } else {
                assert!(
                    next_event(&mut r).await.is_none(),
                    "{name}: {role:?} must be disconnected"
                );
            }
        }
    }
}

/// #722: `GetRoutesPage` over a real connection walks the redistributed
/// routes in order, a page on a fresh connection (no snapshot) continues from
/// the same cursor, a route removed mid-walk is skipped, and the removed
/// unpaged `GetRoutes` answers with an error.
#[tokio::test]
async fn routes_are_paged_over_a_connection_and_the_old_query_is_an_error() {
    use nos_proto::{BgpRouteCursor, RedistributedRoute};
    let (_tmp, path, _server) = start();
    let route = |n: u8| RedistributedRoute {
        prefix: format!("10.{n}.0.0/16").parse().unwrap(),
        gateway: "192.0.2.1".parse().unwrap(),
    };
    let (_ribd_r, mut ribd_w) = connect_as(&path, Role::Ribd).await;
    ribd_w
        .send(BgpRequest::RedistributeRoutes(RedistributeUpdate::Full(
            (1..=5).map(route).collect(),
        )))
        .await
        .unwrap();

    let page = |after: Option<BgpRouteCursor>| BgpRequest::GetRoutesPage { after, limit: 2 };
    let (mut r, mut w) = connect_as(&path, Role::Restd).await;
    let mut prefixes = Vec::new();
    // The feed is fire-and-forget: wait until all five are visible.
    for _ in 0..50 {
        w.send(BgpRequest::GetRoutesPage {
            after: None,
            limit: 100,
        })
        .await
        .unwrap();
        match next_event(&mut r).await {
            Some(BgpEvent::RoutesPage { routes, .. }) if routes.len() == 5 => break,
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    w.send(page(None)).await.unwrap();
    let Some(BgpEvent::RoutesPage { routes, next }) = next_event(&mut r).await else {
        panic!("no first page")
    };
    prefixes.extend(routes.iter().map(|r| r.prefix.clone()));
    assert_eq!(prefixes, ["10.1.0.0/16", "10.2.0.0/16"]);
    let mut after = next;
    assert!(after.is_some());

    // 10.3 disappears before its page is read; a new connection has no
    // snapshot and still continues after the cursor.
    ribd_w
        .send(BgpRequest::RedistributeRoutes(RedistributeUpdate::Remove(
            "10.3.0.0/16".parse().unwrap(),
        )))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (mut r2, mut w2) = connect_as(&path, Role::User).await;
    loop {
        w2.send(page(after)).await.unwrap();
        let Some(BgpEvent::RoutesPage { routes, next }) = next_event(&mut r2).await else {
            panic!("no page")
        };
        prefixes.extend(routes.iter().map(|r| r.prefix.clone()));
        match next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    assert_eq!(
        prefixes,
        ["10.1.0.0/16", "10.2.0.0/16", "10.4.0.0/16", "10.5.0.0/16"]
    );

    w.send(BgpRequest::GetRoutes).await.unwrap();
    assert!(matches!(
        next_event(&mut r).await,
        Some(BgpEvent::Error(m)) if m.contains("GetRoutesPage")
    ));
}

/// #724: a `RedistributeMacs`/`RedistributeEvpnPrefixes` `Full` past the
/// codec's 16 MiB `MAX_FRAME`, cut by `EvpnUpdate::split`, crosses the real
/// codec and is staged per source until its closing `Full`: nothing is held
/// from the `FullPart`s alone, then the whole set lands in one apply (parts
/// applied one by one would leave only the last chunk, each `Full` replacing
/// the previous). The domain and the table share a name and must not mix.
#[tokio::test]
async fn evpn_redistribution_past_max_frame_is_staged_until_the_closing_full() {
    use nos_proto::fdb::Esi;
    use nos_proto::{EvpnKey, EvpnRoute};
    use tokio_util::codec::Encoder;
    type Request = fn(EvpnUpdate) -> BgpRequest;
    // ~80 KB per route (8000 communities, 10 bytes each): 250 is ~19 MiB.
    const N: u8 = 250;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bgp.sock");
    let sessions = SessionManager::new("r1".to_string());
    let _server = nos_bgp::server::start(
        &path,
        "r1".to_string(),
        sessions.clone(),
        &shared().identity("bgpd", "r1"),
        tmp.path().join("no-watchdog.sock"),
    )
    .unwrap();

    let routes = |base: u8| -> Vec<EvpnRoute> {
        (0..N)
            .map(|i| EvpnRoute {
                key: EvpnKey::Mac {
                    rd: [0; 8],
                    mac: [0, 0, 0, 0, base, i],
                },
                vni: 10,
                next_hop: "10.0.0.1".parse().unwrap(),
                ext_communities: vec![u64::MAX; 8000],
                esi: Esi::default(),
                l3_vni: None,
            })
            .collect()
    };
    let requests: [(u8, Role, Request); 2] = [
        (1, Role::Fdbd, |update| BgpRequest::RedistributeMacs {
            domain: "x".into(),
            update,
        }),
        (2, Role::Ribd, |update| {
            BgpRequest::RedistributeEvpnPrefixes {
                table: "x".into(),
                update,
            }
        }),
    ];
    let mut held = 0;
    for (base, role, request) in requests {
        let all = routes(base);
        assert!(
            IpcCodec::<BgpRequest>::default()
                .encode(
                    request(EvpnUpdate::Full(all.clone())),
                    &mut bytes::BytesMut::new()
                )
                .is_err(),
            "the unchunked snapshot must exceed MAX_FRAME"
        );
        let mut frames = EvpnUpdate::Full(all).split();
        let last = frames.pop().unwrap();
        assert!(frames.len() > 1);
        let (mut r, mut w) = connect_as(&path, role).await;
        for frame in frames {
            w.feed(request(frame)).await.unwrap();
        }
        w.flush().await.unwrap();
        // Fire-and-forget: no reply to wait on, so give the server time.
        assert!(
            stays_open(&mut r).await,
            "{role:?} disconnected mid-snapshot"
        );
        assert_eq!(
            sessions.evpn_local_len().await,
            held,
            "half a snapshot held"
        );

        w.send(request(last)).await.unwrap();
        held += usize::from(N);
        for _ in 0..100 {
            if sessions.evpn_local_len().await == held {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(sessions.evpn_local_len().await, held, "{role:?} snapshot");
    }
}

/// #728: a `RedistributeRoutes` `Full` past the codec's 16 MiB `MAX_FRAME`
/// (a full table redistributed into BGP), cut by `RedistributeUpdate::split`,
/// crosses the real codec as `ribd` and is staged until its closing `Full`:
/// nothing is held from the `FullPart`s alone, then the whole set lands at
/// once (`BgpRib` diffs each `Full` against the raw set, so parts applied one
/// by one would leave only the last chunk).
#[tokio::test]
async fn redistribution_past_max_frame_is_staged_until_the_closing_full() {
    use nos_proto::RedistributedRoute;
    use tokio_util::codec::Encoder;
    // ~35 encoded bytes per IPv6 route: 500k is ~17 MiB.
    const N: u32 = 500_000;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bgp.sock");
    let sessions = SessionManager::new("r1".to_string());
    let _server = nos_bgp::server::start(
        &path,
        "r1".to_string(),
        sessions.clone(),
        &shared().identity("bgpd", "r1"),
        tmp.path().join("no-watchdog.sock"),
    )
    .unwrap();

    let v6 = |i: u32| std::net::Ipv6Addr::from((0x2001_0db8_u128 << 96) | (u128::from(i) << 16));
    let all: Vec<RedistributedRoute> = (0..N)
        .map(|i| RedistributedRoute {
            prefix: nos_proto::IpNet::new(v6(i).into(), 112).unwrap(),
            gateway: v6(N + 1).into(),
        })
        .collect();
    assert!(
        IpcCodec::<BgpRequest>::default()
            .encode(
                BgpRequest::RedistributeRoutes(RedistributeUpdate::Full(all.clone())),
                &mut bytes::BytesMut::new()
            )
            .is_err(),
        "the unchunked snapshot must exceed MAX_FRAME"
    );
    let mut frames = RedistributeUpdate::Full(all).split();
    let last = frames.pop().unwrap();
    assert!(frames.len() > 1);
    let (mut r, mut w) = connect_as(&path, Role::Ribd).await;
    for frame in frames {
        w.feed(BgpRequest::RedistributeRoutes(frame)).await.unwrap();
    }
    w.flush().await.unwrap();
    // Fire-and-forget: no reply to wait on, so give the server time.
    assert!(stays_open(&mut r).await, "ribd disconnected mid-snapshot");
    assert_eq!(
        sessions.redistribute_raw_len().await,
        0,
        "half a snapshot held"
    );

    w.send(BgpRequest::RedistributeRoutes(last)).await.unwrap();
    for _ in 0..600 {
        if sessions.redistribute_raw_len().await == N as usize {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(sessions.redistribute_raw_len().await, N as usize);
}

/// #791: a `RedistributeVpnPrefixes` `Full` past the codec's 16 MiB
/// `MAX_FRAME`, cut by `VpnPrefixUpdate::split_with`, crosses the real codec
/// as `ribd` and is staged per table until its closing `Full`: nothing is
/// held from the `FullPart`s alone, a reconnect mid-snapshot discards the
/// staged parts, and the whole set lands in one apply.
#[tokio::test]
async fn vpn_export_past_max_frame_is_staged_until_the_closing_full() {
    use nos_proto::{VpnPrefix, VpnPrefixUpdate};
    use tokio_util::codec::Encoder;
    // ~80 KB per route (8000 RTs, 10 varint bytes each): 250 is ~19 MiB.
    const N: u8 = 250;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bgp.sock");
    let sessions = SessionManager::new("r1".to_string());
    let _server = nos_bgp::server::start(
        &path,
        "r1".to_string(),
        sessions.clone(),
        &shared().identity("bgpd", "r1"),
        tmp.path().join("no-watchdog.sock"),
    )
    .unwrap();
    let request = |update| BgpRequest::RedistributeVpnPrefixes {
        table: "red".into(),
        update,
    };
    let all: Vec<VpnPrefix> = (0..N)
        .map(|i| VpnPrefix {
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            prefix: nos_proto::IpNet::new([10, i, 0, 0].into(), 24).unwrap(),
            labels: vec![1000],
            ext_communities: vec![u64::MAX; 8000],
        })
        .collect();
    assert!(
        IpcCodec::<BgpRequest>::default()
            .encode(
                request(VpnPrefixUpdate::Full(all.clone())),
                &mut bytes::BytesMut::new()
            )
            .is_err(),
        "the unchunked snapshot must exceed MAX_FRAME"
    );
    let mut frames = VpnPrefixUpdate::Full(all).split_with(nos_proto::fdb::EVPN_PUSH_BYTES);
    let last = frames.pop().unwrap();
    assert!(frames.len() > 1);

    // A connection lost mid-snapshot: its parts never surface.
    let (mut r, mut w) = connect_as(&path, Role::Ribd).await;
    for frame in frames.clone() {
        w.feed(request(frame)).await.unwrap();
    }
    w.flush().await.unwrap();
    assert!(stays_open(&mut r).await, "ribd disconnected mid-snapshot");
    assert_eq!(sessions.vpn_local_len().await, 0, "half a snapshot held");
    drop((r, w));

    // The reconnect resends the whole snapshot.
    let (mut r, mut w) = connect_as(&path, Role::Ribd).await;
    for frame in frames {
        w.feed(request(frame)).await.unwrap();
    }
    w.flush().await.unwrap();
    assert!(stays_open(&mut r).await, "ribd disconnected mid-snapshot");
    assert_eq!(sessions.vpn_local_len().await, 0, "half a snapshot held");
    w.send(request(last)).await.unwrap();
    for _ in 0..200 {
        if sessions.vpn_local_len().await == usize::from(N) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(sessions.vpn_local_len().await, usize::from(N));
}

/// #864: `show bgp bmp` asked of the wrong instance's daemon is an error.
#[tokio::test]
async fn show_bmp_for_another_instance_is_an_error() {
    let (_tmp, path, _server) = start();
    let (mut r, mut w) = connect_as(&path, Role::User).await;
    w.send(BgpRequest::ShowBmp {
        instance: "other".into(),
    })
    .await
    .unwrap();
    assert!(matches!(next_event(&mut r).await, Some(BgpEvent::Error(_))));
}
