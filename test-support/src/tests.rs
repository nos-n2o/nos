//! One loopback test per fake: dial it the way a daemon does.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::schema::PortAggregateMode;
use nos_proto::{
    BroadcastDomainStatus, Config, ConfigDiff, Event, InterfaceEvent, InterfaceRequest,
    InterfaceStatus, IpcCodec, LinkState, PortAggregateStatus, Request, RibEvent, RibRequest,
    ServiceRef, WatchdogEvent, WatchdogRequest,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::*;

type Tx<R> = FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<R>>;
type Rx<E> = FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<E>>;

async fn dial<R: Serialize, E: DeserializeOwned>(
    path: &std::path::Path,
    role: &str,
    name: &str,
) -> (Tx<R>, Rx<E>) {
    let s = nos_pki::connect(path, role, name).await.unwrap();
    let (r, w) = tokio::io::split(s);
    (
        FramedWrite::new(w, IpcCodec::default()),
        FramedRead::new(r, IpcCodec::default()),
    )
}

async fn next<E: DeserializeOwned>(rx: &mut Rx<E>) -> E {
    tokio::time::timeout(Duration::from_secs(5), rx.next())
        .await
        .expect("timed out")
        .expect("closed")
        .unwrap()
}

async fn ask<R: Serialize, E: DeserializeOwned>(
    path: &std::path::Path,
    role: &str,
    name: &str,
    req: R,
) -> E {
    let (mut tx, mut rx) = dial::<R, E>(path, role, name).await;
    tx.send(req).await.unwrap();
    next(&mut rx).await
}

fn link(name: &str, up: bool) -> LinkState {
    LinkState {
        name: name.into(),
        ifindex: 2,
        admin_up: up,
        carrier: up,
        port_aggregate: None,
    }
}

fn iface(name: &str) -> InterfaceStatus {
    InterfaceStatus {
        name: name.into(),
        addresses: vec![],
        routing_table: None,
        switching_profile: None,
        port_aggregate: None,
        mtu: 1500,
        subinterfaces: vec![],
        link_local_address: None,
        err_disabled: false,
        speed_mbps: None,
        link: None,
    }
}

#[tokio::test]
async fn configd_get_diff_stream_and_redial() {
    let tmp = tempfile::tempdir().unwrap();
    let f = FakeConfigd::new(&tmp.path().join("c.sock"), Config::default());
    let cfg = Config {
        hostname: "other".into(),
        ..Default::default()
    };
    f.set_config(cfg.clone());
    assert_eq!(f.config().hostname, "other");
    let ev: Event = ask(f.path(), "configd", "", Request::Get).await;
    assert!(matches!(ev, Event::Config(c) if c.hostname == "other"));
    assert_eq!(f.gets(), 1);
    let ev: Event = ask(f.path(), "configd", "", Request::Unsubscribe).await;
    assert!(matches!(ev, Event::Error(e) if e == "unsupported"));

    let (mut tx, mut rx) = dial::<Request, Event>(f.path(), "configd", "").await;
    tx.send(Request::SubscribeDiff { scopes: vec![] })
        .await
        .unwrap();
    assert!(matches!(next(&mut rx).await, Event::Diff(d) if d == ConfigDiff::default()));
    let diff = ConfigDiff {
        hostname: Some(nos_proto::FieldDiff {
            label: "hostname".into(),
            old: None,
            new: Some("x".into()),
        }),
        ..Default::default()
    };
    f.push_diff(diff.clone());
    assert!(matches!(next(&mut rx).await, Event::Diff(d) if d == diff));
    let before = f.connections();
    f.close_stream();
    assert!(rx.next().await.is_none());
    let (mut tx, mut rx) = dial::<Request, Event>(f.path(), "configd", "").await;
    tx.send(Request::SubscribeDiff { scopes: vec![] })
        .await
        .unwrap();
    next(&mut rx).await;
    assert_eq!(f.connections(), before + 1);
}

#[tokio::test]
async fn watchdog_resolves_set_and_not_available() {
    let tmp = tempfile::tempdir().unwrap();
    let w = FakeWatchdog::new(&tmp.path().join("w.sock"));
    let svc = ServiceRef::RibTable("rt1".into());
    let resolve = |s: &ServiceRef| {
        ask::<_, WatchdogEvent>(
            w.path(),
            "watchdog",
            "",
            WatchdogRequest::ResolveEndpoint { service: s.clone() },
        )
    };
    assert!(matches!(resolve(&svc).await, WatchdogEvent::NotAvailable));
    w.set(svc.clone(), "/x".into());
    assert!(matches!(resolve(&svc).await, WatchdogEvent::Endpoint(p) if p.ends_with("x")));
    w.remove(&svc);
    assert!(matches!(resolve(&svc).await, WatchdogEvent::NotAvailable));
    assert_eq!(w.resolutions(), vec![svc.clone(), svc.clone(), svc]);

    // Other requests close the connection.
    let (mut tx, mut rx) = dial::<WatchdogRequest, WatchdogEvent>(w.path(), "watchdog", "").await;
    tx.send(WatchdogRequest::RenewCert { csr_der: vec![] })
        .await
        .unwrap();
    assert!(rx.next().await.is_none());
}

#[tokio::test]
async fn serve_none_many_and_stream_end() {
    let tmp = tempfile::tempdir().unwrap();
    let s = serve(
        &tmp.path().join("s.sock"),
        "ribd",
        "rt1",
        |r: &RibRequest| match r {
            RibRequest::GetVrfName => Reply::Many(vec![RibEvent::NoMatch, RibEvent::NoMatch]),
            RibRequest::GetTableId => Reply::Stream(
                vec![RibEvent::TableId(None)],
                futures::stream::empty().boxed(),
            ),
            _ => Reply::None,
        },
    );
    let (mut tx, mut rx) = dial::<RibRequest, RibEvent>(&s.path, "ribd", "rt1").await;
    tx.send(RibRequest::GetEvpnIrb).await.unwrap();
    tx.send(RibRequest::GetVrfName).await.unwrap();
    assert!(matches!(next(&mut rx).await, RibEvent::NoMatch));
    assert!(matches!(next(&mut rx).await, RibEvent::NoMatch));
    tx.send(RibRequest::GetTableId).await.unwrap();
    assert!(matches!(next(&mut rx).await, RibEvent::TableId(None)));
    assert!(rx.next().await.is_none()); // empty stream ends the connection
    assert_eq!(s.take_seen().len(), 3);
    assert!(s.take_seen().is_empty());
}

#[tokio::test]
async fn ribd_defaults_values_and_pushed() {
    let tmp = tempfile::tempdir().unwrap();
    let r = FakeRibd::new(&tmp.path().join("r.sock"), "rt1");
    let q = |req| ask::<_, RibEvent>(r.path(), "ribd", "rt1", req);
    assert!(matches!(
        q(RibRequest::GetVrfName).await,
        RibEvent::VrfName(None)
    ));
    assert!(matches!(
        q(RibRequest::GetTableId).await,
        RibEvent::TableId(None)
    ));
    assert!(matches!(
        q(RibRequest::BgpRouteCount).await,
        RibEvent::BgpRouteCount(0)
    ));
    assert!(matches!(q(RibRequest::IgpCosts).await, RibEvent::IgpCosts(v) if v.is_empty()));
    assert!(matches!(
        q(RibRequest::GetEvpnIrb).await,
        RibEvent::EvpnIrb(None)
    ));
    assert!(matches!(
        q(RibRequest::GetRoutesPage { after: None, limit: 0, filter: nos_proto::RouteFilter::default() }).await,
        RibEvent::RoutesPage { routes, next: None } if routes.is_empty()
    ));
    let lookup = RibRequest::Lookup {
        addr: "10.0.0.1".parse().unwrap(),
    };
    assert!(matches!(q(lookup).await, RibEvent::NoMatch));

    r.set_vrf_name(Some("vrf1".into()));
    r.set_table_id(Some(100));
    r.set_bgp_route_count(7);
    r.set_igp_costs(vec![("10.0.0.0/8".parse().unwrap(), 5)]);
    r.set_evpn_irb(Some(nos_proto::rib::EvpnIrb {
        l3_vni: 1,
        router_mac: [0; 6],
        route_targets_export: vec![],
    }));
    assert!(matches!(q(RibRequest::GetVrfName).await, RibEvent::VrfName(Some(n)) if n == "vrf1"));
    assert!(matches!(
        q(RibRequest::GetTableId).await,
        RibEvent::TableId(Some(100))
    ));
    assert!(matches!(
        q(RibRequest::BgpRouteCount).await,
        RibEvent::BgpRouteCount(7)
    ));
    assert!(matches!(q(RibRequest::IgpCosts).await, RibEvent::IgpCosts(v) if v.len() == 1));
    assert!(matches!(
        q(RibRequest::GetEvpnIrb).await,
        RibEvent::EvpnIrb(Some(_))
    ));

    let (mut tx, mut rx) = dial::<RibRequest, RibEvent>(r.path(), "ribd", "rt1").await;
    tx.send(RibRequest::PushBgpRoutes(vec![])).await.unwrap();
    tx.send(RibRequest::PushOspfRoutes {
        instance: "o".into(),
        updates: vec![],
    })
    .await
    .unwrap();
    tx.send(RibRequest::GetVrfName).await.unwrap();
    // The query reply proves the pushes before it were read.
    next(&mut rx).await;
    let pushed = r.take_pushed();
    assert_eq!(pushed.len(), 2);
    assert!(matches!(pushed[0], RibRequest::PushBgpRoutes(_)));
    assert!(r.take_pushed().is_empty());
    assert!(r.connections() >= 1);
}

#[tokio::test]
async fn interfaced_lookups_links_and_pushed() {
    let tmp = tempfile::tempdir().unwrap();
    let i = FakeInterfaced::new(&tmp.path().join("i.sock"));
    let q = |req| ask::<_, InterfaceEvent>(i.path(), "interfaced", "", req);
    let get = |n: &str| InterfaceRequest::GetInterface { name: n.into() };

    assert!(matches!(q(get("eth0")).await, InterfaceEvent::NotFound));
    i.set_interface(iface("eth1"));
    i.set_interface(iface("eth0"));
    assert!(matches!(q(get("eth0")).await, InterfaceEvent::Interface(s) if s.name == "eth0"));
    match q(InterfaceRequest::GetInterfaces).await {
        InterfaceEvent::Interfaces(v) => {
            let names: Vec<_> = v.iter().map(|s| s.name.as_str()).collect();
            assert_eq!(names, ["eth0", "eth1"]);
        }
        _ => panic!(),
    }
    i.remove_interface("eth0");
    assert!(matches!(q(get("eth0")).await, InterfaceEvent::NotFound));

    let bd = || InterfaceRequest::GetBroadcastDomain { name: "d".into() };
    assert!(matches!(q(bd()).await, InterfaceEvent::NotFound));
    i.set_broadcast_domain(
        "d",
        BroadcastDomainStatus {
            name: "d".into(),
            addresses: vec![],
            routing_table: None,
            link_local_address: None,
            bridge_name: Some("br1".into()),
            mtu: None,
            speed_mbps: None,
        },
    );
    assert!(matches!(q(bd()).await, InterfaceEvent::BroadcastDomain(d) if d.bridge_name.is_some()));
    i.remove_broadcast_domain("d");
    assert!(matches!(q(bd()).await, InterfaceEvent::NotFound));

    let pa = || InterfaceRequest::GetPortAggregate {
        name: "bond".into(),
    };
    i.set_port_aggregate(
        "bond",
        PortAggregateStatus {
            name: "bond".into(),
            mode: PortAggregateMode::Xor,
            switching_profile: None,
            mtu: 1500,
            subinterfaces: vec![],
            link_local_address: None,
            bond_name: None,
            err_disabled: false,
            steering: Vec::new(),
            speed_mbps: None,
            link: None,
        },
    );
    assert!(matches!(q(pa()).await, InterfaceEvent::PortAggregate(_)));
    assert!(matches!(
        q(InterfaceRequest::GetPortAggregates).await,
        InterfaceEvent::PortAggregates(v) if v.len() == 1
    ));
    i.remove_port_aggregate("bond");
    assert!(matches!(q(pa()).await, InterfaceEvent::NotFound));

    i.set_links(true, vec![link("eth0", true)]);
    let (mut tx, mut rx) =
        dial::<InterfaceRequest, InterfaceEvent>(i.path(), "interfaced", "").await;
    tx.send(InterfaceRequest::SubscribeLinks).await.unwrap();
    assert!(matches!(
        next(&mut rx).await,
        InterfaceEvent::LinkSnapshot { observed: true, links } if links.len() == 1
    ));
    i.push_link(link("eth0", false));
    assert!(matches!(
        next(&mut rx).await,
        InterfaceEvent::LinkChanged(l) if !l.admin_up
    ));
    i.push_link(link("eth1", true));
    assert!(matches!(
        next(&mut rx).await,
        InterfaceEvent::LinkAdded(l) if l.name == "eth1"
    ));
    i.remove_link("eth1");
    assert!(matches!(
        next(&mut rx).await,
        InterfaceEvent::LinkRemoved { name } if name == "eth1"
    ));
    let before = i.connections();
    i.close_connections();
    assert!(rx.next().await.is_none());
    assert!(before >= 1);

    let (mut tx, mut rx) =
        dial::<InterfaceRequest, InterfaceEvent>(i.path(), "interfaced", "").await;
    tx.send(InterfaceRequest::SetErrDisabled {
        port: "eth0".into(),
        disabled: true,
    })
    .await
    .unwrap();
    tx.send(InterfaceRequest::FlushFdb {
        port: "p".into(),
        domain: "d".into(),
    })
    .await
    .unwrap();
    tx.send(InterfaceRequest::SubscribeLinks).await.unwrap();
    // Snapshot reflects push_link's update.
    assert!(matches!(
        next(&mut rx).await,
        InterfaceEvent::LinkSnapshot { links, .. } if !links[0].admin_up
    ));
    let pushed = i.take_pushed();
    assert_eq!(pushed.len(), 2);
    assert!(i.take_pushed().is_empty());
}

#[tokio::test]
async fn fakes_watchdog_resolves_only_started_services() {
    let f = Fakes::start(&[
        Fake::Configd(Config::default()),
        Fake::Watchdog,
        Fake::Interfaced,
    ]);
    let wd = f.watchdog_socket();
    let resolve = |s: ServiceRef| {
        ask::<_, WatchdogEvent>(
            &wd,
            "watchdog",
            "",
            WatchdogRequest::ResolveEndpoint { service: s },
        )
    };
    assert!(matches!(resolve(ServiceRef::Config).await,
        WatchdogEvent::Endpoint(p) if p == f.config_socket()));
    assert!(matches!(resolve(ServiceRef::Interfaces).await,
        WatchdogEvent::Endpoint(p) if p == f.interface_socket()));
    assert!(matches!(
        resolve(ServiceRef::RibTable("rt1".into())).await,
        WatchdogEvent::NotAvailable
    ));
    assert!(!f.rib_socket("rt1").exists());
    assert!(f.configd.is_some() && f.interfaced.is_some() && f.ribd.is_empty());
    assert!(f.dir().exists());

    // A started ribd is registered and answers on its own socket.
    let f = Fakes::start(&[Fake::Watchdog, Fake::Ribd("rt1".into())]);
    let ev: RibEvent = ask(&f.rib_socket("rt1"), "ribd", "rt1", RibRequest::GetVrfName).await;
    assert!(matches!(ev, RibEvent::VrfName(None)));
    assert!(f.ribd.contains_key("rt1"));
}
