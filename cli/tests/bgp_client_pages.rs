//! #723: the EVPN, Flowspec and VPN page walks of `nos_cli::bgp_client`.

use futures::{SinkExt, StreamExt};
use nos_pki::testing::shared;
use nos_proto::{
    AddressFamily, BgpEvent, BgpRequest, EvpnRouteCursor, EvpnRouteSummary, FlowspecRouteCursor,
    FlowspecRouteSummary, IpcCodec, VpnRouteCursor, VpnRouteSummary,
};
use tokio_util::codec::{FramedRead, FramedWrite};

/// Serves one connection, answering each of `n` requests with `reply` and
/// returning the requests it saw.
async fn serve_with(
    listener: nos_pki::Listener,
    n: usize,
    reply: impl Fn(&BgpRequest) -> BgpEvent,
) -> Vec<BgpRequest> {
    let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<BgpRequest>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<BgpEvent>::default());
    let mut seen = Vec::new();
    for _ in 0..n {
        let req = reader.next().await.unwrap().unwrap();
        writer.send(reply(&req)).await.unwrap();
        seen.push(req);
    }
    seen
}

fn listener(tmp: &tempfile::TempDir) -> (std::path::PathBuf, nos_pki::Listener) {
    let path = tmp.path().join("bgp.sock");
    let l = shared().identity("bgpd", "r1").listen(&path).unwrap();
    (path, l)
}

fn peer() -> std::net::IpAddr {
    "192.0.2.1".parse().unwrap()
}

#[tokio::test]
async fn evpn_routes_are_walked_page_by_page() {
    let tmp = tempfile::tempdir().unwrap();
    let (path, l) = listener(&tmp);
    let server = tokio::spawn(serve_with(l, 2, |req| {
        let BgpRequest::GetEvpnRoutesPage { after, .. } = req else {
            panic!("{req:?}");
        };
        let route = |s: &str| EvpnRouteSummary {
            peer: peer(),
            route_type: 2,
            route: s.into(),
            next_hop: peer(),
            extended_communities: vec![],
            local_pref: 100,
            communities: vec![],
        };
        match after {
            None => BgpEvent::EvpnRoutesPage {
                routes: vec![route("a")],
                next: Some(EvpnRouteCursor {
                    peer: peer(),
                    route: "a".into(),
                }),
            },
            Some(_) => BgpEvent::EvpnRoutesPage {
                routes: vec![route("b")],
                next: None,
            },
        }
    }));
    let mut seen = Vec::new();
    nos_cli::bgp_client::for_each_evpn_routes_page(&path, |p| {
        seen.extend(p.iter().map(|r| r.route.clone()));
    })
    .await
    .unwrap();
    assert_eq!(seen, ["a", "b"]);
    assert_eq!(server.await.unwrap().len(), 2);
}

#[tokio::test]
async fn flowspec_routes_are_walked_page_by_page() {
    let tmp = tempfile::tempdir().unwrap();
    let (path, l) = listener(&tmp);
    let server = tokio::spawn(serve_with(l, 2, |req| {
        let BgpRequest::GetFlowspecRoutesPage { after, .. } = req else {
            panic!("{req:?}");
        };
        let route = |s: &str| FlowspecRouteSummary {
            peer: peer(),
            nlri: s.into(),
            extended_communities: vec![],
            validity: "valid".into(),
            actions: vec![],
            dataplane: None,
            family: "ipv4-flowspec".into(),
            rd: None,
            path_id: None,
        };
        match after {
            None => BgpEvent::FlowspecRoutesPage {
                routes: vec![route("a")],
                next: Some(FlowspecRouteCursor {
                    peer: peer(),
                    family: "f".into(),
                    nlri: "a".into(),
                }),
            },
            Some(_) => BgpEvent::FlowspecRoutesPage {
                routes: vec![route("b")],
                next: None,
            },
        }
    }));
    let mut seen = Vec::new();
    nos_cli::bgp_client::for_each_flowspec_routes_page(&path, None, None, |p| {
        seen.extend(p.iter().map(|r| r.nlri.clone()));
    })
    .await
    .unwrap();
    assert_eq!(seen, ["a", "b"]);
    assert_eq!(server.await.unwrap().len(), 2);
}

/// The family and RD ride on every page request.
#[tokio::test]
async fn vpn_routes_are_walked_with_the_family_and_rd_on_every_page() {
    let tmp = tempfile::tempdir().unwrap();
    let (path, l) = listener(&tmp);
    let server = tokio::spawn(serve_with(l, 2, |req| {
        let BgpRequest::GetVpnRoutesPage { after, .. } = req else {
            panic!("{req:?}");
        };
        let route = |s: &str| VpnRouteSummary {
            peer: peer(),
            rd: "65001:1".into(),
            prefix: s.into(),
            labels: vec![],
            next_hop: peer(),
            route_targets: vec![],
            as_path: String::new(),
            local_pref: 100,
            best: true,
            site_of_origin: None,
        };
        match after {
            None => BgpEvent::VpnRoutesPage {
                routes: vec![route("10.0.0.0/24")],
                next: Some(VpnRouteCursor {
                    peer: peer(),
                    rd: [0; 8],
                    prefix: "10.0.0.0/24".parse().unwrap(),
                }),
            },
            Some(_) => BgpEvent::VpnRoutesPage {
                routes: vec![route("10.0.1.0/24")],
                next: None,
            },
        }
    }));
    let mut seen = Vec::new();
    nos_cli::bgp_client::for_each_vpn_routes_page(
        &path,
        AddressFamily::Vpnv4Unicast,
        Some("65001:1"),
        |p| seen.extend(p.iter().map(|r| r.prefix.clone())),
    )
    .await
    .unwrap();
    assert_eq!(seen, ["10.0.0.0/24", "10.0.1.0/24"]);
    for req in server.await.unwrap() {
        let BgpRequest::GetVpnRoutesPage { family, rd, .. } = req else {
            panic!("{req:?}");
        };
        assert_eq!(
            (family, rd.as_deref()),
            (AddressFamily::Vpnv4Unicast, Some("65001:1"))
        );
    }
}
