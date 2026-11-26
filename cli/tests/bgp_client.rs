use futures::{SinkExt, StreamExt};
use nos_cli::bgp_client::for_each_routes_page;
use nos_pki::testing::shared;
use nos_proto::{
    BgpEvent, BgpRequest, BgpRouteCursor, BgpRouteSummary, IpcCodec, RpkiValidationState,
};
use tokio_util::codec::{FramedRead, FramedWrite};

fn cursor(n: u8) -> BgpRouteCursor {
    BgpRouteCursor {
        prefix: format!("10.0.{n}.0/24").parse().unwrap(),
        peer: None,
        path_id: 0,
    }
}

fn page(n: u8, next: Option<u8>) -> BgpEvent {
    BgpEvent::RoutesPage {
        routes: vec![BgpRouteSummary {
            prefix: format!("10.0.{n}.0/24"),
            peer: None,
            next_hop: None,
            as_path: String::new(),
            origin_as: None,
            local_pref: 100,
            best: true,
            validation_state: RpkiValidationState::NotFound,
            unknown_attributes: vec![],
            tag: None,
        }],
        next: next.map(cursor),
    }
}

/// Serves `pages` in order on one connection, checking each request's cursor.
async fn serve_pages(listener: nos_pki::Listener, pages: Vec<(Option<u8>, BgpEvent)>) {
    let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<BgpRequest>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<BgpEvent>::default());
    for (after, reply) in pages {
        let BgpRequest::GetRoutesPage { after: got, limit } = reader.next().await.unwrap().unwrap()
        else {
            panic!("not a page request");
        };
        assert_eq!((got, limit), (after.map(cursor), nos_proto::BGP_PAGE_MAX));
        writer.send(reply).await.unwrap();
    }
}

async fn walk(pages: Vec<(Option<u8>, BgpEvent)>) -> (Vec<String>, Result<(), String>) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bgp.sock");
    let listener = shared().identity("bgpd", "r1").listen(&path).unwrap();
    let server = tokio::spawn(serve_pages(listener, pages));
    let mut seen = Vec::new();
    let res = for_each_routes_page(&path, |p| {
        seen.extend(p.iter().map(|r| r.prefix.clone()));
    })
    .await
    .map_err(|e| e.to_string());
    server.await.unwrap();
    (seen, res)
}

#[tokio::test]
async fn routes_are_walked_in_three_pages_on_one_connection() {
    let (seen, res) = walk(vec![
        (None, page(0, Some(0))),
        (Some(0), page(1, Some(1))),
        (Some(1), page(2, None)),
    ])
    .await;
    assert_eq!(res, Ok(()));
    assert_eq!(seen, ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]);
}

#[tokio::test]
async fn a_cursor_that_does_not_advance_is_an_error() {
    let (seen, res) = walk(vec![(None, page(0, Some(0))), (Some(0), page(0, Some(0)))]).await;
    assert_eq!(seen.len(), 2);
    assert!(res.unwrap_err().contains("did not advance"));
}

#[tokio::test]
async fn daemon_errors_odd_replies_and_hangups_end_the_walk() {
    let (_, res) = walk(vec![(None, BgpEvent::Error("boom".to_string()))]).await;
    assert!(res.unwrap_err().contains("boom"));
    let (_, res) = walk(vec![(None, BgpEvent::PeerCleared)]).await;
    assert!(res.unwrap_err().contains("unexpected"));
    // The daemon hanging up mid-walk.
    let (_, res) = walk(vec![(None, page(0, Some(0)))]).await;
    assert!(res.is_err());
}
