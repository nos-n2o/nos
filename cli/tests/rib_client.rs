use futures::{SinkExt, StreamExt};
use nos_cli::rib_client::{for_each_routes_page, get_vpn_label, lookup};
use nos_pki::testing::shared;
use nos_proto::{IpcCodec, PrefixRoutes, RibEvent, RibRequest, RouteEntry, RouteSourceKind};
use tokio_util::codec::{FramedRead, FramedWrite};

fn sample_prefix_routes() -> PrefixRoutes {
    PrefixRoutes {
        prefix: "10.0.0.0/24".parse().unwrap(),
        candidates: vec![RouteEntry {
            gateways: vec!["10.0.0.1".parse().unwrap()],
            source: RouteSourceKind::Static,
            backup: None,
            discard: false,
            evpn: None,
            backup_tunnel: false,
            mpls_labels: vec![],
            vpn: vec![],
            blackhole: false,
            metric: None,
            preference: 0,
            age_secs: 0,
            interfaces: vec![],
            installed: false,
        }],
    }
}

async fn serve_once(listener: nos_pki::Listener, expected: RibRequest, reply: RibEvent) {
    let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<RibRequest>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<RibEvent>::default());

    let got = reader.next().await.unwrap().unwrap();
    assert_eq!(format!("{got:?}"), format!("{expected:?}"));
    writer.send(reply).await.unwrap();
}

/// Serves `pages` in order on one connection, checking each request's cursor.
async fn serve_pages(listener: nos_pki::Listener, pages: Vec<(Option<&'static str>, RibEvent)>) {
    let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<RibRequest>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<RibEvent>::default());
    for (after, reply) in pages {
        let RibRequest::GetRoutesPage { after: got, .. } = reader.next().await.unwrap().unwrap()
        else {
            panic!("not a page request");
        };
        assert_eq!(got, after.map(|a| a.parse().unwrap()));
        writer.send(reply).await.unwrap();
    }
}

fn page(prefix: &str, next: Option<&str>) -> RibEvent {
    let mut r = sample_prefix_routes();
    r.prefix = prefix.parse().unwrap();
    RibEvent::RoutesPage {
        routes: vec![r],
        next: next.map(|n| n.parse().unwrap()),
    }
}

async fn walk(pages: Vec<(Option<&'static str>, RibEvent)>) -> (Vec<String>, Result<(), String>) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let listener = shared().identity("ribd", "rt1").listen(&path).unwrap();
    let server = tokio::spawn(serve_pages(listener, pages));
    let mut seen = Vec::new();
    let res = for_each_routes_page(&path, |p| {
        seen.extend(p.iter().map(|r| r.prefix.to_string()));
    })
    .await
    .map_err(|e| e.to_string());
    server.await.unwrap();
    (seen, res)
}

#[tokio::test]
async fn routes_are_walked_page_by_page_on_one_connection() {
    let (seen, res) = walk(vec![
        (None, page("10.0.0.0/24", Some("10.0.0.0/24"))),
        (
            Some("10.0.0.0/24"),
            page("10.0.1.0/24", Some("10.0.1.0/24")),
        ),
        (Some("10.0.1.0/24"), page("10.0.2.0/24", None)),
    ])
    .await;
    assert_eq!(res, Ok(()));
    assert_eq!(seen, ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]);
}

#[tokio::test]
async fn a_cursor_that_does_not_advance_is_an_error() {
    let (seen, res) = walk(vec![
        (None, page("10.0.0.0/24", Some("10.0.0.0/24"))),
        (
            Some("10.0.0.0/24"),
            page("10.0.0.0/24", Some("10.0.0.0/24")),
        ),
    ])
    .await;
    assert_eq!(seen.len(), 2);
    assert!(res.unwrap_err().contains("did not advance"));
}

#[tokio::test]
async fn a_routes_walk_reports_daemon_errors_and_odd_replies() {
    let (_, res) = walk(vec![(None, RibEvent::Error("boom".to_string()))]).await;
    assert!(res.unwrap_err().contains("boom"));
    let (_, res) = walk(vec![(None, RibEvent::NoMatch)]).await;
    assert!(res.unwrap_err().contains("unexpected"));
    // The daemon hanging up mid-walk.
    let (_, res) = walk(vec![(None, page("10.0.0.0/24", Some("10.0.0.0/24")))]).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn lookup_returns_none_on_no_match() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let listener = shared().identity("ribd", "rt1").listen(&path).unwrap();
    let addr = "192.168.0.1".parse().unwrap();

    let server = tokio::spawn(serve_once(
        listener,
        RibRequest::Lookup { addr },
        RibEvent::NoMatch,
    ));

    let matched = lookup(&path, addr).await.unwrap();
    assert_eq!(matched, None);

    server.await.unwrap();
}

#[tokio::test]
async fn get_vpn_label_returns_the_label_and_none_on_anything_else() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rib.sock");
    let listener = shared().identity("ribd", "rt1").listen(&path).unwrap();
    let server = tokio::spawn(serve_once(
        listener,
        RibRequest::GetVpnLabel,
        RibEvent::VpnLabel(Some(1000)),
    ));
    assert_eq!(get_vpn_label(&path).await, Some(1000));
    server.await.unwrap();

    let path = tmp.path().join("rib2.sock");
    let listener = shared().identity("ribd", "rt1").listen(&path).unwrap();
    let server = tokio::spawn(serve_once(
        listener,
        RibRequest::GetVpnLabel,
        RibEvent::NoMatch,
    ));
    assert_eq!(get_vpn_label(&path).await, None);
    server.await.unwrap();
}
