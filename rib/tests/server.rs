use std::net::IpAddr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::testing::shared;
use nos_pki::Stream;
use nos_proto::{IpcCodec, PrefixRoutes, RibEvent, RibRequest, RouteSourceKind};
use nos_rib::{server, NoopRibDriver, Rib, RibEntry, RouteSource};
use tokio::sync::RwLock;
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_rib() -> Rib {
    let mut rib = Rib::new();
    let broad: nos_proto::IpNet = "10.0.0.0/16".parse().unwrap();
    let narrow: nos_proto::IpNet = "10.0.1.0/24".parse().unwrap();
    rib.insert(RibEntry {
        prefix: broad,
        next_hops: vec![("10.0.0.1".parse().unwrap(), None).into()],
        source: RouteSource::Static,
        backup: None,
        backup_interface_id: None,
        backup_tunnel: false,
        distance: None,
        tag: None,
        interfaces: std::collections::BTreeMap::new(),
    });
    // Two competing candidates for the same prefix, to prove ordering.
    rib.insert(RibEntry {
        prefix: narrow,
        next_hops: vec![("10.0.1.9".parse().unwrap(), None).into()],
        source: RouteSource::Bgp,
        backup: None,
        backup_interface_id: None,
        backup_tunnel: false,
        distance: None,
        tag: None,
        interfaces: std::collections::BTreeMap::new(),
    });
    rib.insert(RibEntry {
        prefix: narrow,
        next_hops: vec![("10.0.1.1".parse().unwrap(), None).into()],
        source: RouteSource::Static,
        backup: None,
        backup_interface_id: None,
        backup_tunnel: false,
        distance: None,
        tag: None,
        interfaces: std::collections::BTreeMap::new(),
    });
    rib
}

type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<RibEvent>>;
type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<RibRequest>>;

/// Connects as a person, who may query but never push routes.
async fn connect(path: &std::path::Path) -> (Reader, Writer) {
    connect_as(path, "user", "tester").await
}

async fn connect_as(path: &std::path::Path, role: &str, name: &str) -> (Reader, Writer) {
    let stream = shared()
        .identity(role, name)
        .connect(path, &nos_pki::PeerId::new("ribd", "rt1"))
        .await
        .unwrap();
    let (r, w) = tokio::io::split(stream);
    (
        FramedRead::new(r, IpcCodec::<RibEvent>::default()),
        FramedWrite::new(w, IpcCodec::<RibRequest>::default()),
    )
}

#[tokio::test]
async fn get_routes_returns_sorted_prefixes_with_ranked_candidates() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        Arc::default(),
        Arc::new(NoopRibDriver::default()),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer
        .send(RibRequest::GetRoutesPage {
            after: None,
            limit: 0,
            filter: nos_proto::RouteFilter::default(),
        })
        .await
        .unwrap();
    let event = reader.next().await.unwrap().unwrap();

    let RibEvent::RoutesPage { routes, next: None } = event else {
        panic!("expected the only RoutesPage, got {event:?}");
    };
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].prefix, "10.0.0.0/16".parse().unwrap());
    assert_eq!(routes[1].prefix, "10.0.1.0/24".parse().unwrap());
    // Best (Static) candidate first, then worst (Bgp).
    assert_eq!(routes[1].candidates.len(), 2);
    assert_eq!(routes[1].candidates[0].source, RouteSourceKind::Static);
    assert_eq!(routes[1].candidates[1].source, RouteSourceKind::Bgp);
}

#[tokio::test]
async fn lookup_matches_longest_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        Arc::default(),
        Arc::new(NoopRibDriver::default()),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    let addr: IpAddr = "10.0.1.5".parse().unwrap();
    writer.send(RibRequest::Lookup { addr }).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    let RibEvent::Match(PrefixRoutes { prefix, candidates }) = event else {
        panic!("expected Match, got {event:?}");
    };
    assert_eq!(prefix, "10.0.1.0/24".parse().unwrap());
    assert_eq!(candidates[0].source, RouteSourceKind::Static);
}

#[tokio::test]
async fn lookup_with_no_covering_prefix_returns_no_match() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        Arc::default(),
        Arc::new(NoopRibDriver::default()),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    let addr: IpAddr = "192.168.0.1".parse().unwrap();
    writer.send(RibRequest::Lookup { addr }).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::NoMatch));
}

/// A driver that reports a canned VRF name, so `GetVrfName`'s dispatch can
/// be tested without any real kernel/netlink involvement.
#[derive(Debug)]
struct FakeVrfDriver(Option<String>);

/// A driver that reports a canned table id, so `GetTableId`'s dispatch can
/// be tested the same way.
#[derive(Debug)]
struct FakeTableIdDriver(Option<u32>);

#[async_trait::async_trait]
impl nos_rib::RibDriver for FakeTableIdDriver {
    async fn apply(
        &self,
        _table_name: &str,
        _best_routes: &std::collections::HashMap<nos_proto::IpNet, RibEntry>,
    ) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn apply_delta(
        &self,
        _table_name: &str,
        _changes: &std::collections::HashMap<nos_proto::IpNet, Option<RibEntry>>,
    ) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn teardown(&self, _table_name: &str) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn vrf_name(&self, _table_name: &str) -> Option<String> {
        None
    }

    async fn table_id(&self, _table_name: &str) -> Option<u32> {
        self.0
    }
}

#[async_trait::async_trait]
impl nos_rib::RibDriver for FakeVrfDriver {
    async fn apply(
        &self,
        _table_name: &str,
        _best_routes: &std::collections::HashMap<nos_proto::IpNet, RibEntry>,
    ) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn apply_delta(
        &self,
        _table_name: &str,
        _changes: &std::collections::HashMap<nos_proto::IpNet, Option<RibEntry>>,
    ) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn teardown(&self, _table_name: &str) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn vrf_name(&self, _table_name: &str) -> Option<String> {
        self.0.clone()
    }

    async fn table_id(&self, _table_name: &str) -> Option<u32> {
        None
    }
}

#[tokio::test]
async fn get_vrf_name_returns_the_drivers_answer() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let driver: Arc<dyn nos_rib::RibDriver> = Arc::new(FakeVrfDriver(Some("vrf100".to_string())));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        Arc::default(),
        driver,
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(RibRequest::GetVrfName).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::VrfName(Some(name)) if name == "vrf100"));
}

#[tokio::test]
async fn get_vrf_name_is_none_when_the_driver_has_no_vrf_yet() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let driver: Arc<dyn nos_rib::RibDriver> = Arc::new(FakeVrfDriver(None));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        Arc::default(),
        driver,
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(RibRequest::GetVrfName).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::VrfName(None)));
}

#[tokio::test]
async fn get_table_id_returns_the_drivers_answer() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let driver: Arc<dyn nos_rib::RibDriver> = Arc::new(FakeTableIdDriver(Some(100)));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        Arc::default(),
        driver,
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect(&path).await;
    writer.send(RibRequest::GetTableId).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::TableId(Some(100))));
}

#[tokio::test]
async fn get_table_id_is_none_when_the_driver_has_no_id_yet() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(sample_rib()));
    let driver: Arc<dyn nos_rib::RibDriver> = Arc::new(FakeTableIdDriver(None));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib,
        Arc::default(),
        driver,
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (mut reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    writer.send(RibRequest::GetTableId).await.unwrap();
    let event = reader.next().await.unwrap().unwrap();

    assert!(matches!(event, RibEvent::TableId(None)));
}

/// A driver that records every `apply`/`apply_delta` call and notifies a
/// waiter, so `PushBgpRoutes`'s fire-and-forget dispatch (no reply on the
/// wire) can still be observed synchronizing with the test.
#[derive(Debug, Default)]
struct RecordingDriver {
    applied: tokio::sync::Mutex<Vec<std::collections::HashMap<nos_proto::IpNet, RibEntry>>>,
    applied_delta:
        tokio::sync::Mutex<Vec<std::collections::HashMap<nos_proto::IpNet, Option<RibEntry>>>>,
    notify: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl nos_rib::RibDriver for RecordingDriver {
    async fn apply(
        &self,
        _table_name: &str,
        best_routes: &std::collections::HashMap<nos_proto::IpNet, RibEntry>,
    ) -> Result<(), nos_rib::DriverError> {
        self.applied.lock().await.push(best_routes.clone());
        self.notify.notify_one();
        Ok(())
    }

    async fn apply_delta(
        &self,
        _table_name: &str,
        changes: &std::collections::HashMap<nos_proto::IpNet, Option<RibEntry>>,
    ) -> Result<(), nos_rib::DriverError> {
        self.applied_delta.lock().await.push(changes.clone());
        self.notify.notify_one();
        Ok(())
    }

    async fn teardown(&self, _table_name: &str) -> Result<(), nos_rib::DriverError> {
        Ok(())
    }

    async fn vrf_name(&self, _table_name: &str) -> Option<String> {
        None
    }

    async fn table_id(&self, _table_name: &str) -> Option<u32> {
        None
    }
}

#[tokio::test]
async fn push_bgp_routes_full_inserts_into_shared_rib_and_applies_to_driver() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(Rib::new()));
    let driver = Arc::new(RecordingDriver::default());
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib.clone(),
        Arc::default(),
        driver.clone(),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (_reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    let prefix: nos_proto::IpNet = "203.0.113.0/24".parse().unwrap();
    let next_hop: IpAddr = "203.0.113.1".parse().unwrap();
    let sibling: IpAddr = "203.0.113.2".parse().unwrap();
    writer
        .send(RibRequest::PushBgpRoutes(vec![
            nos_proto::BgpRouteUpdate::Full(vec![nos_proto::BgpRoute {
                prefix,
                next_hops: vec![next_hop, sibling],
                backup_next_hop: None,
                discard: false,
                metric: None,
            }]),
        ]))
        .await
        .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), driver.notify.notified())
        .await
        .expect("driver.apply was not called");

    let guard = rib.read().await;
    let best = guard.best_route(&prefix).unwrap();
    // A BGP multipath set reaches the kernel entry whole.
    assert_eq!(
        best.next_hops,
        vec![(next_hop, None).into(), (sibling, None).into()]
    );
    assert_eq!(best.source, RouteSource::Bgp);
}

/// A BGP `Full` past the codec's 16 MiB `MAX_FRAME` (a full-table shape)
/// cannot go as one frame; cut by `BgpRouteUpdate::frames` it crosses the
/// real codec, is staged by `nos-ribd` until its closing `Full` (nothing
/// published from the `FullPart`s alone) and lands as one kernel apply.
#[tokio::test]
async fn push_bgp_full_past_max_frame_is_chunked_and_applied_atomically() {
    use nos_proto::{BgpRoute, BgpRouteUpdate};
    use tokio_util::codec::Encoder;
    // ~54 encoded bytes per IPv6 route with a backup: 330k is ~17 MiB.
    const N: u32 = 330_000;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(Rib::new()));
    let driver = Arc::new(RecordingDriver::default());
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib.clone(),
        Arc::default(),
        driver.clone(),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let v6 = |i: u32| {
        IpAddr::from(std::net::Ipv6Addr::from(
            (0x2001_0db8_u128 << 96) | (u128::from(i) << 16),
        ))
    };
    let routes: Vec<BgpRoute> = (0..N)
        .map(|i| BgpRoute {
            prefix: nos_proto::IpNet::new(v6(i), 112).unwrap(),
            next_hops: vec![v6(N + 1)],
            backup_next_hop: Some(v6(N + 2)),
            discard: false,
            metric: None,
        })
        .collect();
    let whole = RibRequest::PushBgpRoutes(vec![BgpRouteUpdate::Full(routes.clone())]);
    assert!(
        IpcCodec::<RibRequest>::default()
            .encode(whole, &mut bytes::BytesMut::new())
            .is_err(),
        "the unchunked snapshot must exceed MAX_FRAME"
    );

    let mut frames = BgpRouteUpdate::frames(vec![BgpRouteUpdate::Full(routes)]);
    let last = frames.pop().unwrap();
    assert!(frames.len() > 100);
    let (mut reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    for frame in frames {
        writer.feed(RibRequest::PushBgpRoutes(frame)).await.unwrap();
    }
    writer.send(RibRequest::BgpRouteCount).await.unwrap();
    assert!(matches!(
        reader.next().await.unwrap().unwrap(),
        RibEvent::BgpRouteCount(0)
    ));
    assert!(
        driver.applied.lock().await.is_empty(),
        "half a table published"
    );

    writer.send(RibRequest::PushBgpRoutes(last)).await.unwrap();
    writer.send(RibRequest::BgpRouteCount).await.unwrap();
    assert!(matches!(
        reader.next().await.unwrap().unwrap(),
        RibEvent::BgpRouteCount(n) if n == N
    ));
    let applied = driver.applied.lock().await;
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].len(), N as usize);
}

/// The VPN twin (#715): an imported `Full` past `MAX_FRAME` (an internet
/// VRF) cut by `VpnRouteUpdate::frames` is staged until its closing `Full`
/// and lands as one kernel apply, `vpn_info` included.
#[tokio::test]
async fn push_vpn_full_past_max_frame_is_chunked_and_applied_atomically() {
    use nos_proto::{VpnPath, VpnRoute, VpnRouteUpdate};
    use tokio_util::codec::Encoder;
    // ~160 encoded bytes per IPv6 route with a 28-label path: 120k is ~19 MiB.
    const N: u32 = 120_000;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(Rib::new()));
    let driver = Arc::new(RecordingDriver::default());
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib.clone(),
        Arc::default(),
        driver.clone(),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let v6 = |i: u32| {
        IpAddr::from(std::net::Ipv6Addr::from(
            (0x2001_0db8_u128 << 96) | (u128::from(i) << 16),
        ))
    };
    let routes: Vec<VpnRoute> = (0..N)
        .map(|i| VpnRoute {
            prefix: nos_proto::IpNet::new(v6(i), 112).unwrap(),
            paths: vec![VpnPath {
                pe_next_hop: v6(N + 1),
                rd: "4294967295:65535".into(),
                gateway: v6(N + 2),
                interface_id: Some(7),
                labels: vec![0x000F_FFFF; 28],
            }],
        })
        .collect();
    let whole = RibRequest::PushVpnRoutes(vec![VpnRouteUpdate::Full(routes.clone())]);
    assert!(
        IpcCodec::<RibRequest>::default()
            .encode(whole, &mut bytes::BytesMut::new())
            .is_err(),
        "the unchunked snapshot must exceed MAX_FRAME"
    );

    let mut frames = VpnRouteUpdate::frames(vec![VpnRouteUpdate::Full(routes)]);
    let last = frames.pop().unwrap();
    assert!(frames.len() > 1);
    let (mut reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    // `ResolveNextHop`'s reply is the barrier: every earlier frame was handled.
    let barrier = || RibRequest::ResolveNextHop { addrs: vec![] };
    for frame in frames {
        writer.feed(RibRequest::PushVpnRoutes(frame)).await.unwrap();
    }
    writer.send(barrier()).await.unwrap();
    reader.next().await.unwrap().unwrap();
    {
        let guard = rib.read().await;
        assert_eq!(guard.count_source(RouteSource::Vpn), 0, "half a table");
        assert!(guard.vpn_info.is_empty());
    }
    assert!(
        driver.applied.lock().await.is_empty(),
        "half a table published"
    );

    writer.send(RibRequest::PushVpnRoutes(last)).await.unwrap();
    writer.send(barrier()).await.unwrap();
    reader.next().await.unwrap().unwrap();
    let guard = rib.read().await;
    assert_eq!(guard.count_source(RouteSource::Vpn), N);
    assert_eq!(guard.vpn_info.len(), N as usize);
    let applied = driver.applied.lock().await;
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].len(), N as usize);
}

/// The OSPF twin (#726): an SPF `Full` past `MAX_FRAME` cut by
/// `OspfRouteUpdate::frames` crosses the real codec as `ospfd`, is staged
/// until its closing `Full` and lands as one kernel apply.
#[tokio::test]
async fn push_ospf_full_past_max_frame_is_chunked_and_applied_atomically() {
    use nos_proto::{OspfRoute, OspfRouteUpdate};
    use tokio_util::codec::Encoder;
    // ~75 encoded bytes per IPv6 route with a hop, a backup and a tunnel:
    // 260k is ~18 MiB.
    const N: u32 = 260_000;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(Rib::new()));
    let driver = Arc::new(RecordingDriver::default());
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib.clone(),
        Arc::default(),
        driver.clone(),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let v6 = |i: u32| {
        IpAddr::from(std::net::Ipv6Addr::from(
            (0x2001_0db8_u128 << 96) | (u128::from(i) << 16),
        ))
    };
    let routes: Vec<OspfRoute> = (0..N)
        .map(|i| OspfRoute {
            prefix: nos_proto::IpNet::new(v6(i), 112).unwrap(),
            next_hops: vec![(v6(N + 1), Some(7))],
            backup_next_hop: Some(v6(N + 2)),
            backup_interface_id: Some(8),
            metric: 100_000,
            discard: false,
            backup_tunnel: Some(v6(N + 3)),
            next_hop_labels: Vec::new(),
        })
        .collect();
    let whole = RibRequest::PushOspfRoutes {
        instance: "o1".into(),
        updates: vec![OspfRouteUpdate::Full(routes.clone())],
    };
    assert!(
        IpcCodec::<RibRequest>::default()
            .encode(whole, &mut bytes::BytesMut::new())
            .is_err(),
        "the unchunked snapshot must exceed MAX_FRAME"
    );

    let mut frames = OspfRouteUpdate::frames(vec![OspfRouteUpdate::Full(routes)]);
    let last = frames.pop().unwrap();
    assert!(frames.len() > 1);
    let (mut reader, mut writer) = connect_as(&path, "ospfd", "o1").await;
    // `GetTableId`'s reply is the barrier: every earlier frame was handled.
    for frame in frames {
        writer
            .feed(RibRequest::PushOspfRoutes {
                instance: "o1".into(),
                updates: frame,
            })
            .await
            .unwrap();
    }
    writer.send(RibRequest::GetTableId).await.unwrap();
    reader.next().await.unwrap().unwrap();
    assert_eq!(rib.read().await.count_source(RouteSource::Ospf), 0);
    assert!(
        driver.applied.lock().await.is_empty(),
        "half a table published"
    );

    writer
        .send(RibRequest::PushOspfRoutes {
            instance: "o1".into(),
            updates: last,
        })
        .await
        .unwrap();
    writer.send(RibRequest::GetTableId).await.unwrap();
    reader.next().await.unwrap().unwrap();
    assert_eq!(rib.read().await.count_source(RouteSource::Ospf), N);
    let applied = driver.applied.lock().await;
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].len(), N as usize);
}

#[tokio::test]
async fn push_bgp_routes_add_only_calls_apply_delta_when_the_winner_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(Rib::new()));
    let driver = Arc::new(RecordingDriver::default());
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib.clone(),
        Arc::default(),
        driver.clone(),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    let (_reader, mut writer) = connect_as(&path, "bgpd", "r1").await;
    let prefix: nos_proto::IpNet = "203.0.113.0/24".parse().unwrap();
    let next_hop: IpAddr = "203.0.113.1".parse().unwrap();
    let route = nos_proto::BgpRoute {
        prefix,
        next_hops: vec![next_hop],
        backup_next_hop: None,
        discard: false,
        metric: None,
    };

    // A genuinely new prefix triggers apply_delta.
    writer
        .send(RibRequest::PushBgpRoutes(vec![
            nos_proto::BgpRouteUpdate::Add(route.clone()),
        ]))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), driver.notify.notified())
        .await
        .expect("driver.apply_delta was not called for a new route");
    assert_eq!(driver.applied_delta.lock().await.len(), 1);

    // The identical route re-sent doesn't change the winner, so this must
    // not trigger apply_delta at all.
    writer
        .send(RibRequest::PushBgpRoutes(vec![
            nos_proto::BgpRouteUpdate::Add(route),
        ]))
        .await
        .unwrap();

    // A different prefix's genuine change, on the same connection, proves
    // the server has already processed the no-op push sent just before it
    // (a single connection processes requests in order) — if that no-op had
    // wrongly triggered a call, it would show up as an extra entry below.
    let other_prefix: nos_proto::IpNet = "203.0.114.0/24".parse().unwrap();
    writer
        .send(RibRequest::PushBgpRoutes(vec![
            nos_proto::BgpRouteUpdate::Add(nos_proto::BgpRoute {
                prefix: other_prefix,
                next_hops: vec![next_hop],
                backup_next_hop: None,
                discard: false,
                metric: None,
            }),
        ]))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), driver.notify.notified())
        .await
        .expect("driver.apply_delta was not called for the second new route");

    let applied = driver.applied_delta.lock().await;
    assert_eq!(
        applied.len(),
        2,
        "the unchanged re-send must not have triggered apply_delta"
    );
}

/// The kernel-route write path is closed to everyone but the owning daemon
/// family: a person, or another family's daemon, is disconnected and no
/// route lands.
#[tokio::test]
async fn route_pushes_from_the_wrong_role_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(Rib::new()));
    let _server = server::start(
        &path,
        "rt1".to_string(),
        rib.clone(),
        Arc::default(),
        Arc::new(NoopRibDriver::default()),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();

    for (role, name) in [("user", "alice"), ("ospfd", "o1"), ("restd", "rt1")] {
        let (mut reader, mut writer) = connect_as(&path, role, name).await;
        writer
            .send(RibRequest::PushBgpRoutes(vec![
                nos_proto::BgpRouteUpdate::Add(nos_proto::BgpRoute {
                    prefix: "10.9.0.0/24".parse().unwrap(),
                    next_hops: vec!["10.0.0.1".parse().unwrap()],
                    backup_next_hop: None,
                    discard: false,
                    metric: None,
                }),
            ]))
            .await
            .unwrap();
        assert!(
            reader.next().await.is_none_or(|r| r.is_err()),
            "{role} should have been disconnected"
        );
    }
    assert!(
        rib.read().await.all_routes().is_empty(),
        "no refused push may land a route"
    );
}

// ---- live role gate (#364) -------------------------------------------------
// Every request, every role, over real mTLS: a refused role is disconnected
// with no reply (a bounded wait, so a broken gate fails instead of hanging),
// an allowed one is served. The expected sets are written out here on purpose,
// independent of `server::allowed`.

use nos_proto::Role;

type GateServer = (
    tempfile::TempDir,
    std::path::PathBuf,
    Arc<RwLock<Rib>>,
    Arc<RecordingDriver>,
    tokio::task::JoinHandle<()>,
);

fn gate_server() -> GateServer {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let rib = Arc::new(RwLock::new(Rib::new()));
    let driver = Arc::new(RecordingDriver::default());
    let server = server::start(
        &path,
        "rt1".to_string(),
        rib.clone(),
        Arc::default(),
        driver.clone(),
        &shared().identity("ribd", "rt1"),
    )
    .unwrap();
    (tmp, path, rib, driver, server)
}

/// The next reply, or `None` when the server closed instead; a connection
/// left open with no reply fails the test.
async fn reply_or_closed(reader: &mut Reader) -> Option<RibEvent> {
    tokio::time::timeout(std::time::Duration::from_secs(5), reader.next())
        .await
        .expect("connection left open with no reply")
        .and_then(Result::ok)
}

type Case<'a> = (
    &'a str,
    fn() -> RibRequest,
    &'a [Role],
    fn(&RibEvent) -> bool,
);

#[tokio::test]
async fn each_query_is_served_to_its_roles_and_refused_to_the_rest() {
    let (_tmp, path, _rib, _driver, _server) = gate_server();
    let people = [Role::User, Role::Restd];
    let vrf = [
        Role::User,
        Role::Logd,
        Role::Restd,
        Role::Interfaced,
        Role::Bgpd,
        Role::Ospfd,
        Role::Ospfv3d,
        Role::Ribd,
        Role::Fdbd,
        Role::Bfdd,
    ];
    // `nos-sshd` binds inside the VRF but never needs the table id.
    let vrf_name = [&vrf[..], &[Role::Sshd, Role::Watchdog]].concat();
    let igp = [Role::User, Role::Restd, Role::Bgpd];
    let cases: [Case; 8] = [
        (
            "GetRoutes",
            || RibRequest::GetRoutes,
            &people,
            |e| matches!(e, RibEvent::Error(m) if m.contains("GetRoutesPage")),
        ),
        (
            "GetRoutesPage",
            || RibRequest::GetRoutesPage {
                after: None,
                limit: 10,
                filter: nos_proto::RouteFilter::default(),
            },
            &people,
            |e| matches!(e, RibEvent::RoutesPage { routes, next: None } if routes.is_empty()),
        ),
        (
            "GetSummary",
            || RibRequest::GetSummary,
            &people,
            |e| matches!(e, RibEvent::Summary(s) if s.vrf.is_none() && s.kernel_table.is_none()),
        ),
        (
            "GetVrfName",
            || RibRequest::GetVrfName,
            &vrf_name,
            |e| matches!(e, RibEvent::VrfName(None)),
        ),
        (
            "GetTableId",
            || RibRequest::GetTableId,
            &vrf,
            |e| matches!(e, RibEvent::TableId(None)),
        ),
        (
            "IgpCosts",
            || RibRequest::IgpCosts,
            &igp,
            |e| matches!(e, RibEvent::IgpCosts(v) if v.is_empty()),
        ),
        (
            "BgpRouteCount",
            || RibRequest::BgpRouteCount,
            &[Role::Bgpd],
            |e| matches!(e, RibEvent::BgpRouteCount(0)),
        ),
        (
            "GetEvpnIrb",
            || RibRequest::GetEvpnIrb,
            &[Role::Fdbd],
            |e| matches!(e, RibEvent::EvpnIrb(None)),
        ),
    ];
    for (name, make, allowed, check) in cases {
        for role in Role::ALL {
            let (mut r, mut w) = connect_as(&path, role.as_str(), "x").await;
            w.send(make()).await.unwrap();
            let reply = reply_or_closed(&mut r).await;
            if allowed.contains(&role) {
                assert!(
                    reply.as_ref().is_some_and(check),
                    "{name} as {role:?}: {reply:?}"
                );
            } else {
                assert!(reply.is_none(), "{name} as {role:?} must get no reply");
            }
        }
    }
}

#[tokio::test]
async fn ospf_pushes_land_only_from_the_ospf_daemons() {
    let (_tmp, path, rib, driver, _server) = gate_server();
    for (i, role) in Role::ALL.into_iter().enumerate() {
        let prefix: nos_proto::IpNet = format!("10.{i}.0.0/24").parse().unwrap();
        let (mut r, mut w) = connect_as(&path, role.as_str(), "x").await;
        w.send(RibRequest::PushOspfRoutes {
            instance: "x".into(),
            updates: vec![nos_proto::OspfRouteUpdate::Add(nos_proto::OspfRoute {
                prefix,
                next_hops: vec![("10.0.0.1".parse().unwrap(), None)],
                backup_next_hop: None,
                backup_interface_id: None,
                metric: 10,
                discard: false,
                backup_tunnel: None,
                next_hop_labels: Vec::new(),
            })],
        })
        .await
        .unwrap();
        if matches!(role, Role::Ospfd | Role::Ospfv3d) {
            tokio::time::timeout(std::time::Duration::from_secs(5), driver.notify.notified())
                .await
                .unwrap_or_else(|_| panic!("{role:?}: the OSPF push was not applied"));
            let guard = rib.read().await;
            assert_eq!(
                guard.best_route(&prefix).map(|e| e.source),
                Some(RouteSource::Ospf),
                "{role:?}"
            );
        } else {
            assert!(
                reply_or_closed(&mut r).await.is_none(),
                "{role:?} must be disconnected"
            );
            assert!(rib.read().await.best_route(&prefix).is_none(), "{role:?}");
        }
    }
    // An Add/Remove programs only the touched prefix: a delta, never a full apply.
    assert_eq!(driver.applied_delta.lock().await.len(), 2);
    assert!(driver.applied.lock().await.is_empty());
}

#[tokio::test]
async fn evpn_pushes_are_applied_only_for_bgpd() {
    let (_tmp, path, _rib, driver, _server) = gate_server();
    for role in Role::ALL {
        let (mut r, mut w) = connect_as(&path, role.as_str(), "x").await;
        w.send(RibRequest::PushEvpnRoutes(nos_proto::EvpnUpdate::Full(
            vec![],
        )))
        .await
        .unwrap();
        if role == Role::Bgpd {
            tokio::time::timeout(std::time::Duration::from_secs(5), driver.notify.notified())
                .await
                .expect("the EVPN push was not applied to the kernel");
        } else {
            assert!(
                reply_or_closed(&mut r).await.is_none(),
                "{role:?} must be disconnected"
            );
        }
    }
    assert_eq!(driver.applied.lock().await.len(), 1);
}

#[tokio::test]
async fn bgp_pushes_are_refused_to_every_other_role() {
    let (_tmp, path, rib, _driver, _server) = gate_server();
    for role in Role::ALL {
        if role == Role::Bgpd {
            continue;
        }
        let (mut r, mut w) = connect_as(&path, role.as_str(), "x").await;
        w.send(RibRequest::PushBgpRoutes(vec![
            nos_proto::BgpRouteUpdate::Add(nos_proto::BgpRoute {
                prefix: "10.9.0.0/24".parse().unwrap(),
                next_hops: vec!["10.0.0.1".parse().unwrap()],
                backup_next_hop: None,
                discard: false,
                metric: None,
            }),
        ]))
        .await
        .unwrap();
        assert!(
            reply_or_closed(&mut r).await.is_none(),
            "{role:?} must be disconnected"
        );
    }
    assert_eq!(rib.read().await.all_routes().len(), 0);
}

fn evpn_routes(n: u8) -> Vec<nos_proto::EvpnRoute> {
    (0..n)
        .map(|i| nos_proto::EvpnRoute {
            key: nos_proto::EvpnKey::Mac {
                rd: [0; 8],
                mac: [0, 0, 0, 0, 0, i],
            },
            vni: 10100,
            next_hop: "192.0.2.9".parse().unwrap(),
            ext_communities: vec![1; 8],
            esi: [0; 10],
            l3_vni: None,
        })
        .collect()
}

#[tokio::test]
async fn a_chunked_evpn_full_is_applied_once_on_its_closing_frame() {
    let (_tmp, path, rib, driver, _server) = gate_server();
    let (_r, mut w) = connect_as(&path, "bgpd", "x").await;
    let frames = nos_proto::EvpnUpdate::Full(evpn_routes(30)).split_with(200);
    assert!(frames.len() > 2);
    let last = frames.len() - 1;
    for f in &frames[..last] {
        w.send(RibRequest::PushEvpnRoutes(f.clone())).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(driver.applied.lock().await.is_empty(), "applied early");
    assert!(rib.read().await.evpn.received.is_empty(), "half a snapshot");
    w.send(RibRequest::PushEvpnRoutes(frames[last].clone()))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), driver.notify.notified())
        .await
        .expect("closing Full not applied");
    assert_eq!(rib.read().await.evpn.received.len(), 30);
    assert_eq!(driver.applied.lock().await.len(), 1, "one apply");
}

use nos_proto::{OspfRoute, OspfRouteUpdate};

fn ospf_route(prefix: &str, metric: u32) -> OspfRoute {
    OspfRoute {
        prefix: prefix.parse().unwrap(),
        next_hops: vec![("10.0.0.1".parse().unwrap(), None)],
        backup_next_hop: None,
        backup_interface_id: None,
        metric,
        discard: false,
        backup_tunnel: None,
        next_hop_labels: Vec::new(),
    }
}

/// Two instances on one table: each `Full` replaces only its own routes, and a
/// chunked snapshot of one interleaved with the other's is neither half applied
/// nor clobbered (#1277).
#[tokio::test]
async fn ospf_instances_keep_their_own_routes() {
    let (_tmp, path, rib, _driver, _server) = gate_server();
    let (mut r1, mut w1) = connect_as(&path, "ospfd", "a").await;
    let (mut r3, mut w3) = connect_as(&path, "ospfv3d", "a").await;
    let push = |instance: &str, updates| RibRequest::PushOspfRoutes {
        instance: instance.into(),
        updates,
    };
    w1.send(push(
        "a",
        vec![OspfRouteUpdate::Full(vec![ospf_route("10.1.0.0/24", 10)])],
    ))
    .await
    .unwrap();
    // v3 FullPart first, then a v2 Full while it is staged, then the v3 close.
    w3.send(push(
        "a",
        vec![OspfRouteUpdate::FullPart(vec![ospf_route(
            "10.2.0.0/24",
            10,
        )])],
    ))
    .await
    .unwrap();
    w1.send(push(
        "a",
        vec![OspfRouteUpdate::Full(vec![ospf_route("10.1.0.0/24", 20)])],
    ))
    .await
    .unwrap();
    w1.send(RibRequest::GetTableId).await.unwrap();
    r1.next().await.unwrap().unwrap();
    assert_eq!(rib.read().await.count_source(RouteSource::Ospf), 1);
    w3.send(push(
        "a",
        vec![OspfRouteUpdate::Full(vec![ospf_route("10.3.0.0/24", 10)])],
    ))
    .await
    .unwrap();
    w3.send(RibRequest::GetTableId).await.unwrap();
    r3.next().await.unwrap().unwrap();
    let guard = rib.read().await;
    assert_eq!(guard.count_source(RouteSource::Ospf), 3);
    for p in ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"] {
        assert!(guard.best_route(&p.parse().unwrap()).is_some(), "{p}");
    }
}

/// A daemon cannot push as a sibling instance.
#[tokio::test]
async fn ospf_push_for_another_instance_is_refused() {
    let (_tmp, path, rib, _driver, _server) = gate_server();
    let (mut r, mut w) = connect_as(&path, "ospfd", "a").await;
    w.send(RibRequest::PushOspfRoutes {
        instance: "b".into(),
        updates: vec![OspfRouteUpdate::Add(ospf_route("10.1.0.0/24", 10))],
    })
    .await
    .unwrap();
    assert!(reply_or_closed(&mut r).await.is_none());
    assert!(rib.read().await.is_empty());
}
