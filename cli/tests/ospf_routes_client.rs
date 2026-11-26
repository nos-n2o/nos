//! `get_routes` of `ospf_client`/`ospfv3_client` (#1453).
use std::net::Ipv4Addr;

use futures::{SinkExt, StreamExt};
use nos_cli::{ospf_client, ospfv3_client};
use nos_pki::testing::shared;
use nos_proto::{
    IpcCodec, OspfEvent, OspfRequest, Ospfv3Event, Ospfv3Request, Ospfv3RouteSummary,
    RoutePathClass, RouteSummary,
};
use tokio_util::codec::{FramedRead, FramedWrite};

fn v2() -> RouteSummary {
    RouteSummary {
        prefix: "10.0.0.0/24".into(),
        class: RoutePathClass::IntraArea,
        cost: 1,
        type2_cost: None,
        area: Ipv4Addr::UNSPECIFIED,
        next_hops: vec!["10.0.0.2 dev eth0".into()],
        advertising_router: Some(Ipv4Addr::new(2, 2, 2, 2)),
    }
}

fn v3() -> Ospfv3RouteSummary {
    Ospfv3RouteSummary {
        prefix: "2001:db8::/64".into(),
        class: RoutePathClass::External2,
        cost: 1,
        type2_cost: Some(20),
        area: Ipv4Addr::UNSPECIFIED,
        next_hops: vec![],
        advertising_router: None,
    }
}

#[tokio::test]
async fn ospf_get_routes_returns_the_routes_and_rejects_a_wrong_reply() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("ospf.sock");
    let listener = shared().identity("ospfd", "r1").listen(&path).unwrap();
    let server = tokio::spawn(async move {
        for reply in [OspfEvent::Routes(vec![v2()]), OspfEvent::Neighbors(vec![])] {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            let (r, w) = tokio::io::split(stream);
            let mut reader = FramedRead::new(r, IpcCodec::<OspfRequest>::default());
            let mut writer = FramedWrite::new(w, IpcCodec::<OspfEvent>::default());
            assert!(matches!(
                reader.next().await.unwrap().unwrap(),
                OspfRequest::GetRoutes
            ));
            writer.send(reply).await.unwrap();
        }
    });
    assert_eq!(ospf_client::get_routes(&path).await.unwrap(), vec![v2()]);
    assert!(ospf_client::get_routes(&path).await.is_err());
    server.await.unwrap();
}

#[tokio::test]
async fn ospfv3_get_routes_returns_the_routes_and_rejects_a_wrong_reply() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("ospfv3.sock");
    let listener = shared().identity("ospfv3d", "r1").listen(&path).unwrap();
    let server = tokio::spawn(async move {
        for reply in [
            Ospfv3Event::Routes(vec![v3()]),
            Ospfv3Event::Neighbors(vec![]),
        ] {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            let (r, w) = tokio::io::split(stream);
            let mut reader = FramedRead::new(r, IpcCodec::<Ospfv3Request>::default());
            let mut writer = FramedWrite::new(w, IpcCodec::<Ospfv3Event>::default());
            assert!(matches!(
                reader.next().await.unwrap().unwrap(),
                Ospfv3Request::GetRoutes
            ));
            writer.send(reply).await.unwrap();
        }
    });
    assert_eq!(ospfv3_client::get_routes(&path).await.unwrap(), vec![v3()]);
    assert!(ospfv3_client::get_routes(&path).await.is_err());
    server.await.unwrap();
}
