//! `show ... | json` (#1415): the key order, the escape-safe printer and the
//! streamed page walk against a fake daemon.

use futures::{SinkExt, StreamExt};
use nos_cli::pipe::{json_pretty, JqStream, JsonArray};
use nos_pki::testing::shared;
use nos_proto::{
    BgpEvent, BgpRequest, BgpRouteCursor, BgpRouteSummary, IpcCodec, RpkiValidationState,
};
use tokio_util::codec::{FramedRead, FramedWrite};

fn route(prefix: &str) -> BgpRouteSummary {
    BgpRouteSummary {
        prefix: prefix.into(),
        peer: None,
        next_hop: None,
        as_path: "\u{1b}[31m".into(),
        origin_as: None,
        local_pref: 100,
        best: true,
        validation_state: RpkiValidationState::NotFound,
        unknown_attributes: vec![],
    }
}

/// Answers every `GetRoutesPage`: three pages, the last an error when `fail`.
async fn serve(listener: nos_pki::Listener, fail: bool) {
    let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<BgpRequest>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<BgpEvent>::default());
    let mut n = 0;
    while let Some(Ok(BgpRequest::GetRoutesPage { .. })) = reader.next().await {
        n += 1;
        let ev = if fail && n == 3 {
            BgpEvent::Error("boom".into())
        } else {
            BgpEvent::RoutesPage {
                routes: vec![route(&format!("10.0.{n}.0/24"))],
                next: (n < 3).then(|| BgpRouteCursor {
                    prefix: format!("10.0.{n}.0/24").parse().unwrap(),
                    peer: None,
                    path_id: 0,
                }),
            }
        };
        writer.send(ev).await.unwrap();
    }
}

async fn walk(fail: bool) -> (String, bool) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bgp.sock");
    let l = shared().identity("bgpd", "r1").listen(&path).unwrap();
    tokio::spawn(serve(l, fail));
    let mut buf = Vec::new();
    let mut array = JsonArray::begin(&mut buf);
    let ok = nos_cli::bgp_client::for_each_routes_page(&path, |p| array.page(p))
        .await
        .is_ok();
    if ok {
        array.end();
    }
    (String::from_utf8(buf).unwrap(), ok)
}

/// `| jq` over the same three-page walk (#1508): per-row results equal the
/// filter applied to the `| json` array; `length` counts.
#[tokio::test]
async fn a_jq_walk_equals_filtering_the_array() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bgp.sock");
    let l = shared().identity("bgpd", "r1").listen(&path).unwrap();
    tokio::spawn(serve(l, false));
    let mut buf = Vec::new();
    let tail = nos_cli::jq::parse(".[] | select(.local_pref == 100) | .prefix")
        .unwrap()
        .stream_tail()
        .unwrap();
    let mut s = JqStream::begin(&mut buf, tail);
    nos_cli::bgp_client::for_each_routes_page(&path, |p| s.page(p))
        .await
        .unwrap();
    s.end().unwrap();
    assert_eq!(
        String::from_utf8(buf).unwrap(),
        "\"10.0.1.0/24\"\n\"10.0.2.0/24\"\n\"10.0.3.0/24\"\n"
    );
}

#[tokio::test]
async fn a_three_page_walk_is_one_valid_array() {
    let (out, ok) = walk(false).await;
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 3);
    assert_eq!(v[2]["prefix"], "10.0.3.0/24");
    // Lossless: the ESC survives the round trip, escaped on the wire.
    assert_eq!(v[0]["as_path"], "\u{1b}[31m");
    assert!(!out.contains('\u{1b}'));
}

#[tokio::test]
async fn a_failed_walk_is_not_valid_json() {
    let (out, ok) = walk(true).await;
    assert!(!ok);
    assert!(serde_json::from_str::<serde_json::Value>(&out).is_err());
}

#[test]
fn keys_follow_declaration_order() {
    let s = json_pretty(&route("p"));
    let at = |k: &str| s.find(&format!("\"{k}\"")).unwrap();
    assert!(at("prefix") < at("peer"));
    assert!(at("peer") < at("next_hop"));
    assert!(at("next_hop") < at("as_path"));
}

/// A pipe never turns a line into something that spawns: only `json` is known.
#[test]
fn an_unknown_pipe_is_refused() {
    assert!(nos_cli::pipe::split("show version | sh").is_err());
    assert!(nos_cli::pipe::split("show version | json | sh").is_err());
}
