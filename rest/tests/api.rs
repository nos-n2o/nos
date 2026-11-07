//! The REST layer against a real `ConfigStore` behind `nos-configd`'s own IPC
//! server (so the path-set semantics tested here are the shipped ones), plus a
//! fake watchdog broker and fake daemons for the show endpoints.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request as HttpRequest, StatusCode};
use axum::Router;
use futures::{SinkExt, StreamExt};
use nos_config::{Config, ConfigStore, ListenAddr};
use nos_pki::testing::shared;
use nos_proto::{
    BfdEvent, BfdRequest, BgpEvent, BgpInstance, BgpRequest, IpcCodec, LogEntry, LogEvent,
    LogLevel, LogRequest, PrefixRoutes, RibEvent, RibRequest, RouteEntry, RouteSourceKind,
    ServiceRef, User, WatchdogEvent, WatchdogRequest, INVALID_CREDENTIALS,
};
use nos_rest::auth::PeerUser;
use nos_rest::{api, ipc::Daemons};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use tokio_util::codec::{FramedRead, FramedWrite};
use tower::ServiceExt;

/// Serves `handler` on `path`, one reply per request, forever. Returns how
/// many connections it has accepted.
fn serve<Req, Ev>(
    path: &Path,
    who: (&str, &str),
    handler: impl Fn(Req) -> Ev + Send + Sync + 'static,
) -> Arc<AtomicUsize>
where
    Req: DeserializeOwned + Send + 'static,
    Ev: Serialize + Send + 'static,
{
    serve_with(path, who, false, handler)
}

/// `serve`, optionally hanging up after every reply — a daemon that restarted
/// between two requests, as far as a pooled connection can tell.
fn serve_with<Req, Ev>(
    path: &Path,
    (role, name): (&str, &str),
    hang_up_after_reply: bool,
    handler: impl Fn(Req) -> Ev + Send + Sync + 'static,
) -> Arc<AtomicUsize>
where
    Req: DeserializeOwned + Send + 'static,
    Ev: Serialize + Send + 'static,
{
    let listener = shared().identity(role, name).listen(path).unwrap();
    let handler = Arc::new(handler);
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let handler = handler.clone();
            tokio::spawn(async move {
                let (r, w) = tokio::io::split(stream);
                let mut reader = FramedRead::new(r, IpcCodec::<Req>::default());
                let mut writer = FramedWrite::new(w, IpcCodec::<Ev>::default());
                while let Some(Ok(req)) = reader.next().await {
                    if writer.send(handler(req)).await.is_err() || hang_up_after_reply {
                        break;
                    }
                }
            });
        }
    });
    accepted
}

/// The process-wide IPC identity is `nos-restd`'s (the real configd only answers
/// `UserExists` to that role); first call wins, later ones are no-ops.
fn as_restd() {
    shared().install("restd", "rt1");
}

/// The one user every fixture's config starts with (clear text here —
/// `ConfigStore::new` hashes it, like a seeded config file).
const USER: &str = "tester";
const PASSWORD: &str = "secret";

struct Fixture {
    app: Router,
    dir: tempfile::TempDir,
}

/// `services` are the fake daemons the broker knows about. `async` only for the
/// tokio context the spawned servers need.
async fn fixture(services: Vec<(ServiceRef, PathBuf)>) -> Fixture {
    fixture_with(services, None).await
}

/// `fixture`, with `nos-configd` saving to `config_file` (relative to the
/// fixture's temp dir) — `None` means no `--config-file`, so `Save` fails.
#[allow(clippy::unused_async)]
async fn fixture_with(services: Vec<(ServiceRef, PathBuf)>, config_file: Option<&str>) -> Fixture {
    as_restd();
    let dir = tempfile::tempdir().unwrap();
    let config_file = config_file.map(|f| dir.path().join(f));
    let config_socket = dir.path().join("config.sock");
    let config = Config {
        users: vec![User {
            name: USER.to_string(),
            password: PASSWORD.to_string(),
        }],
        ..Config::default()
    };
    ConfigStore::new(config, config_file)
        .start_ipc_server(
            &ListenAddr::Unix(config_socket.clone()),
            &shared().identity("configd", ""),
        )
        .unwrap();

    let watchdog_socket = dir.path().join("watchdog.sock");
    serve(
        &watchdog_socket,
        ("watchdog", ""),
        move |req: WatchdogRequest| match req {
            WatchdogRequest::ResolveEndpoint { service } => services
                .iter()
                .find(|(s, _)| *s == service)
                .map_or(WatchdogEvent::NotAvailable, |(_, p)| {
                    WatchdogEvent::Endpoint(p.clone())
                }),
            // A stand-in CA: one fixed certificate for the right password.
            WatchdogRequest::RestLogin { password, .. } if password == PASSWORD => {
                WatchdogEvent::Issued {
                    cert_der: vec![1, 2, 3],
                    lifetime_secs: 60,
                }
            }
            WatchdogRequest::RestLogin { .. } => {
                WatchdogEvent::Denied(INVALID_CREDENTIALS.to_string())
            }
            // The watchdog's allowlist, reduced to: serial "revoked" is not live.
            WatchdogRequest::RestCertCheck { serial, .. } if serial != "revoked" => {
                WatchdogEvent::Ok
            }
            WatchdogRequest::RestCertCheck { .. } => {
                WatchdogEvent::Denied("session expired".to_string())
            }
            WatchdogRequest::RestRenew { serial, .. } if serial == "revoked" => {
                WatchdogEvent::Denied("session expired".to_string())
            }
            WatchdogRequest::RestRenew { user, .. } if user == USER => WatchdogEvent::Issued {
                cert_der: vec![4, 5, 6],
                lifetime_secs: 60,
            },
            WatchdogRequest::RestRenew { .. } => WatchdogEvent::Denied("no such user".to_string()),
            other => panic!("the fake broker does not handle {other:?}"),
        },
    );
    let app = api::router(Daemons::new(watchdog_socket, config_socket));
    Fixture { app, dir }
}

async fn send(app: &Router, method: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    send_as(app, method, uri, body, Some(USER)).await
}

/// Like `send`, as the user a verified client certificate would name (`None`
/// = the connection presented no certificate). The listener sets that per
/// connection; TLS itself is covered by `over_tls` below.
async fn send_as(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    user: Option<&str>,
) -> (StatusCode, Value) {
    let (status, _, value) = send_full(app, method, uri, body, user, None).await;
    (status, value)
}

/// `send_as` with one extra request header, also returning the reply's `ETag`.
async fn send_full(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    user: Option<&str>,
    extra: Option<(header::HeaderName, &str)>,
) -> (StatusCode, Option<String>, Value) {
    let mut req = HttpRequest::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .extension(PeerUser(
            user.map(str::to_string),
            user.map(|_| "live".to_string()),
        ));
    if let Some((name, value)) = extra {
        req = req.header(name, value);
    }
    let req = req
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let etag = resp
        .headers()
        .get(header::ETAG)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()))
    };
    (status, etag, json)
}

/// Status of a request carrying the given headers.
async fn send_headers(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(header::HeaderName, &str)],
) -> StatusCode {
    let mut req = HttpRequest::builder()
        .method(method)
        .uri(uri)
        .extension(PeerUser(Some(USER.to_string()), Some("live".to_string())));
    for (n, v) in headers {
        req = req.header(n, *v);
    }
    app.clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

fn bgp_instance(name: &str, asn: u32) -> Value {
    serde_json::to_value(BgpInstance {
        name: name.to_string(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        asn,
        peer_groups: Vec::new(),
        peers: Vec::new(),
        cluster_id: None,
        maximum_paths: None,
        confederation: nos_proto::BgpConfederation::default(),
        rpki_caches: Vec::new(),
        bmp_stations: Vec::new(),
        aggregates: Vec::new(),
        graceful_restart: nos_proto::BgpGracefulRestart::default(),
        routing_table: None,
        redistribute_policy: None,
    })
    .unwrap()
}

#[tokio::test]
async fn version_reports_build_info() {
    let f = fixture(vec![]).await;
    let (s, v) = send(&f.app, Method::GET, "/v1/version", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v,
        json!({"version": nos_proto::version::VERSION, "revision": nos_proto::version::REVISION})
    );
}

#[tokio::test]
async fn transaction_lifecycle_over_the_config_tree() {
    let f = fixture(vec![]).await;
    let app = &f.app;

    let (s, snap) = send(app, Method::POST, "/v1/transactions/t1?base=current", None).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(snap["dirty"], false);
    // Resuming reports 200, not 201.
    assert_eq!(
        send(app, Method::POST, "/v1/transactions/t1", None).await.0,
        StatusCode::OK
    );

    // Scalar, then a whole list element, then a subsection nested inside it.
    let (s, v) = send(
        app,
        Method::PUT,
        "/v1/transactions/t1/hostname",
        Some(json!("rest-host")),
    )
    .await;
    assert_eq!((s, v), (StatusCode::OK, json!("rest-host")));
    let (s, _) = send(
        app,
        Method::PUT,
        "/v1/transactions/t1/bgp-instance/r1",
        Some(bgp_instance("r1", 65000)),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let mut r1 = bgp_instance("r1", 65001);
    r1["router_id"] = json!("2.2.2.2");
    let (s, v) = send(
        app,
        Method::PUT,
        "/v1/transactions/t1/bgp-instance/r1/",
        Some(r1),
    )
    .await;
    assert_eq!((s, v["asn"].clone()), (StatusCode::OK, json!(65001)));

    // Read a subsection back, by path and via the whole transaction.
    let (s, v) = send(
        app,
        Method::GET,
        "/v1/transactions/t1/bgp-instance/r1/asn",
        None,
    )
    .await;
    assert_eq!((s, v), (StatusCode::OK, json!(65001)));
    let (_, whole) = send(app, Method::GET, "/v1/transactions/t1", None).await;
    assert_eq!(whole["config"]["hostname"], "rest-host");
    assert_eq!(whole["dirty"], true);

    // Nothing reaches running until commit.
    assert_eq!(
        send(app, Method::GET, "/v1/config", None).await.1["hostname"],
        "nos"
    );
    let (s, d) = send(app, Method::GET, "/v1/transactions/t1/diff", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(d["bgp_instances"].is_array());

    let (s, v) = send(app, Method::POST, "/v1/transactions/t1/commit", None).await;
    assert_eq!(
        (s, v),
        (StatusCode::OK, json!({ "committed": "t1", "warnings": [] }))
    );
    let (_, running) = send(app, Method::GET, "/v1/config", None).await;
    assert_eq!(running["hostname"], "rest-host");
    assert_eq!(running["bgp_instances"][0]["asn"], 65001);
    // A committed transaction is gone.
    assert_eq!(
        send(app, Method::GET, "/v1/transactions/t1", None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn put_with_a_position_query_inserts_or_moves_a_list_element() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/t1?base=blank", None).await;
    let put = |name: &'static str, query: &'static str| async move {
        send(
            app,
            Method::PUT,
            &format!("/v1/transactions/t1/bgp-instance/{name}{query}"),
            Some(bgp_instance(name, 1)),
        )
        .await
        .0
    };
    let order = || async move {
        let (_, v) = send(app, Method::GET, "/v1/transactions/t1/bgp-instance", None).await;
        v.as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    for (name, query) in [("a", ""), ("b", ""), ("c", "?first"), ("a", "?after=b")] {
        assert_eq!(put(name, query).await, StatusCode::OK, "{name}{query}");
    }
    assert_eq!(order().await, ["c", "b", "a"]);
    assert_eq!(put("c", "?last").await, StatusCode::OK);
    assert_eq!(order().await, ["b", "a", "c"]);
    // Unknown anchor: 404, nothing moved. More than one, unknown or empty: 400.
    assert_eq!(put("a", "?after=zz").await, StatusCode::NOT_FOUND);
    for bad in [
        "?first&last",
        "?before=",
        "?sideways",
        "?first=1",
        "?before=a&after=b",
    ] {
        assert_eq!(put("a", bad).await, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(order().await, ["b", "a", "c"]);
}

#[tokio::test]
async fn save_writes_the_running_config_to_disk() {
    let f = fixture_with(vec![], Some("config.yaml")).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/s?base=current", None).await;
    send(
        app,
        Method::PUT,
        "/v1/transactions/s/hostname",
        Some(json!("saved-host")),
    )
    .await;
    send(app, Method::POST, "/v1/transactions/s/commit", None).await;

    let (s, v) = send(app, Method::POST, "/v1/config/save", None).await;
    assert_eq!((s, v), (StatusCode::NO_CONTENT, Value::Null));
    let saved = std::fs::read_to_string(f.dir.path().join("config.yaml")).unwrap();
    assert!(saved.contains("saved-host"), "{saved}");
}

#[tokio::test]
async fn save_failure_is_a_bad_gateway() {
    // No config file: nos-configd refuses the save, through no fault of the client.
    let f = fixture(vec![]).await;
    let (s, v) = send(&f.app, Method::POST, "/v1/config/save", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_eq!(v["status"], 502);
}

#[tokio::test]
async fn whole_config_put_delete_path_and_discard() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/t2?base=blank", None).await;

    let mut whole = send(app, Method::GET, "/v1/transactions/t2", None).await.1["config"].clone();
    whole["hostname"] = json!("bulk");
    whole["bgp_instances"] = json!([bgp_instance("a", 1), bgp_instance("b", 2)]);
    let (s, put) = send(app, Method::PUT, "/v1/transactions/t2", Some(whole)).await;
    assert_eq!(s, StatusCode::OK);
    // The whole-config PUT still replies with the transaction, like a GET.
    let (_, got) = send(app, Method::GET, "/v1/transactions/t2", None).await;
    assert_eq!(put, got);

    assert_eq!(
        send(
            app,
            Method::DELETE,
            "/v1/transactions/t2/bgp-instance/a",
            None
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let (_, list) = send(app, Method::GET, "/v1/transactions/t2/bgp-instance", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["name"], "b");

    assert_eq!(
        send(app, Method::DELETE, "/v1/transactions/t2", None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(app, Method::GET, "/v1/transactions/t2", None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(app, Method::DELETE, "/v1/transactions/t2", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn errors_map_to_statuses_and_leave_the_transaction_intact() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/t3?base=blank", None).await;

    // Unknown path / unknown transaction: 404. Malformed or ill-typed body: 400.
    assert_eq!(
        send(app, Method::GET, "/v1/transactions/t3/nonsense", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(app, Method::GET, "/v1/transactions/nope/hostname", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            app,
            Method::PUT,
            "/v1/transactions/t3/hostname",
            Some(json!(42))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (s, e) = send(
        app,
        Method::PUT,
        "/v1/transactions/t3/bgp-instance/x",
        Some(bgp_instance("y", 1)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(e["detail"].as_str().unwrap().contains("does not match"));
    assert_eq!(
        send(app, Method::POST, "/v1/transactions/t3?base=bogus", None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    // A commit that fails validation is 422 and keeps the transaction.
    send(
        app,
        Method::PUT,
        "/v1/transactions/t3/hostname",
        Some(json!("bad host name!")),
    )
    .await;
    assert_eq!(
        send(app, Method::POST, "/v1/transactions/t3/commit", None)
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (_, v) = send(app, Method::GET, "/v1/transactions/t3/hostname", None).await;
    assert_eq!(v, json!("bad host name!"));
}

/// RFC 9110 §8.8.1/§13.1.1/§13.1.2: a strong `ETag` on every transaction
/// reply, `If-Match` → 412 (nothing changed), `If-None-Match` → 304 (no body).
#[tokio::test]
async fn etag_if_match_and_if_none_match_on_transactions() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    let tx = "/v1/transactions/t4";
    let host = "/v1/transactions/t4/hostname";
    let with = |m: Method,
                uri: &'static str,
                body: Option<Value>,
                h: header::HeaderName,
                v: &'static str| async move {
        send_full(app, m, uri, body, Some(USER), Some((h, v))).await
    };

    let (s, etag, _) = send_full(
        app,
        Method::POST,
        "/v1/transactions/t4?base=current",
        None,
        Some(USER),
        None,
    )
    .await;
    assert_eq!((s, etag.as_deref()), (StatusCode::CREATED, Some("\"0\"")));

    // Stale `If-Match`: 412 problem document, the transaction untouched.
    let (s, etag, e) = with(
        Method::PUT,
        host,
        Some(json!("h1")),
        header::IF_MATCH,
        "\"9\"",
    )
    .await;
    assert_eq!(
        (s, etag, e["status"].clone()),
        (StatusCode::PRECONDITION_FAILED, None, json!(412))
    );
    let (s, etag, v) = send_full(app, Method::GET, host, None, Some(USER), None).await;
    assert_eq!(
        (s, etag.as_deref(), v),
        (StatusCode::OK, Some("\"0\""), json!("nos"))
    );

    // Matching (then `*`, then none at all): each edit bumps the tag.
    let (s, etag, _) = with(
        Method::PUT,
        host,
        Some(json!("h1")),
        header::IF_MATCH,
        "\"0\"",
    )
    .await;
    assert_eq!((s, etag.as_deref()), (StatusCode::OK, Some("\"1\"")));
    let (s, etag, _) = with(Method::PUT, host, Some(json!("h2")), header::IF_MATCH, "*").await;
    assert_eq!((s, etag.as_deref()), (StatusCode::OK, Some("\"2\"")));
    let (s, etag, _) = send_full(app, Method::PUT, host, Some(json!("h3")), Some(USER), None).await;
    assert_eq!((s, etag.as_deref()), (StatusCode::OK, Some("\"3\"")));
    assert_eq!(
        with(Method::PUT, host, Some(json!("h4")), header::IF_MATCH, "3")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    // `If-None-Match`: current or `*` → 304 with the tag and no body; stale → 200.
    let (s, etag, v) = with(Method::GET, tx, None, header::IF_NONE_MATCH, "\"3\"").await;
    assert_eq!(
        (s, etag.as_deref(), v),
        (StatusCode::NOT_MODIFIED, Some("\"3\""), Value::Null)
    );
    let (s, _, v) = with(Method::GET, host, None, header::IF_NONE_MATCH, "*").await;
    assert_eq!((s, v), (StatusCode::NOT_MODIFIED, Value::Null));
    let (s, etag, v) = with(Method::GET, host, None, header::IF_NONE_MATCH, "\"2\"").await;
    assert_eq!(
        (s, etag.as_deref(), v),
        (StatusCode::OK, Some("\"3\""), json!("h3"))
    );
    // A subsection DELETE and a commit honour it too; a refused commit keeps
    // the transaction, and a subsection DELETE's 204 carries the new tag.
    send(
        app,
        Method::PUT,
        "/v1/transactions/t4/bgp-instance/r1",
        Some(bgp_instance("r1", 1)),
    )
    .await;
    let (s, _, _) = with(
        Method::DELETE,
        "/v1/transactions/t4/bgp-instance/r1",
        None,
        header::IF_MATCH,
        "\"3\"",
    )
    .await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);
    let (s, etag, _) = with(
        Method::DELETE,
        "/v1/transactions/t4/bgp-instance/r1",
        None,
        header::IF_MATCH,
        "\"4\"",
    )
    .await;
    assert_eq!(
        (s, etag.as_deref()),
        (StatusCode::NO_CONTENT, Some("\"5\""))
    );
    let (s, _, _) = with(
        Method::POST,
        "/v1/transactions/t4/commit",
        None,
        header::IF_MATCH,
        "\"4\"",
    )
    .await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);
    assert_eq!(send(app, Method::GET, tx, None).await.0, StatusCode::OK);
    let (s, _, _) = with(
        Method::POST,
        "/v1/transactions/t4/commit",
        None,
        header::IF_MATCH,
        "\"5\"",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        send(app, Method::GET, "/v1/config", None).await.1["hostname"],
        "h3"
    );

    // Discarding the whole transaction: 412 when stale, 204 (no tag) when current.
    send(app, Method::POST, "/v1/transactions/t5?base=blank", None).await;
    let (s, _, _) = with(
        Method::DELETE,
        "/v1/transactions/t5",
        None,
        header::IF_MATCH,
        "\"1\"",
    )
    .await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);
    let (s, etag, _) = with(
        Method::DELETE,
        "/v1/transactions/t5",
        None,
        header::IF_MATCH,
        "\"0\"",
    )
    .await;
    assert_eq!((s, etag), (StatusCode::NO_CONTENT, None));
}

/// RFC 9110 §13.1: entity-tag lists, weak vs strong comparison, `If-Match` on
/// GET, and `If-Match` on a missing transaction.
#[tokio::test]
async fn etag_lists_weak_tags_and_missing_transaction() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    let tx = "/v1/transactions/t7";
    let host = "/v1/transactions/t7/hostname";
    send(app, Method::POST, "/v1/transactions/t7?base=blank", None).await;

    // If-None-Match: lists and weak tags (weak comparison); malformed is 400.
    for (raw, want) in [
        ("W/\"0\"", StatusCode::NOT_MODIFIED),
        ("W/\"0\", \"4\"", StatusCode::NOT_MODIFIED),
        ("\"1\", \"abc\"", StatusCode::OK),
        ("0", StatusCode::BAD_REQUEST),
    ] {
        let st = send_headers(app, Method::GET, tx, &[(header::IF_NONE_MATCH, raw)]).await;
        assert_eq!(st, want, "{raw}");
    }
    // If-Match on GET: strong comparison, evaluated before If-None-Match.
    for (m, none_match, want) in [
        ("\"1\", \"0\"", None, StatusCode::OK),
        ("W/\"0\"", None, StatusCode::PRECONDITION_FAILED),
        ("\"abc\"", None, StatusCode::PRECONDITION_FAILED),
        ("\"2\"", Some("\"0\""), StatusCode::PRECONDITION_FAILED),
        ("\"0\"", Some("\"0\""), StatusCode::NOT_MODIFIED),
    ] {
        let mut hs = vec![(header::IF_MATCH, m)];
        hs.extend(none_match.map(|n| (header::IF_NONE_MATCH, n)));
        let st = send_headers(app, Method::GET, tx, &hs).await;
        assert_eq!(st, want, "{m} / {none_match:?}");
    }

    // A list `If-Match` PUT passes when any strong entry is current; a weak one never does.
    let put = |m: &'static str| async move {
        send_full(
            app,
            Method::PUT,
            host,
            Some(json!("h")),
            Some(USER),
            Some((header::IF_MATCH, m)),
        )
        .await
    };
    let (st, etag, _) = put("\"7\", \"0\"").await;
    assert_eq!((st, etag.as_deref()), (StatusCode::OK, Some("\"1\"")));
    let (st, etag, _) = put("W/\"1\"").await;
    assert_eq!((st, etag), (StatusCode::PRECONDITION_FAILED, None));

    // Any `If-Match` on a missing transaction is 412; without it, still 404.
    let gone = "/v1/transactions/nope/hostname";
    for m in ["*", "\"1\""] {
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            let body = (method == Method::PUT).then(|| json!("x"));
            let (st, ..) = send_full(
                app,
                method,
                gone,
                body,
                Some(USER),
                Some((header::IF_MATCH, m)),
            )
            .await;
            assert_eq!(st, StatusCode::PRECONDITION_FAILED);
        }
    }
    assert_eq!(
        send(app, Method::GET, gone, None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn show_routes_via_the_broker_and_missing_daemons_are_503() {
    let dir = tempfile::tempdir().unwrap();
    let rib = dir.path().join("rib.sock");
    serve(&rib, ("ribd", "rt1"), |req: RibRequest| match req {
        RibRequest::GetRoutesPage { after, limit } => {
            assert_eq!((after, limit), (None, 1000));
            RibEvent::RoutesPage {
                routes: vec![PrefixRoutes {
                    prefix: "10.0.0.0/8".parse().unwrap(),
                    candidates: vec![RouteEntry {
                        gateways: vec!["192.0.2.1".parse().unwrap()],
                        source: RouteSourceKind::Static,
                        backup: None,
                        discard: false,
                        evpn: None,
                        backup_tunnel: false,
                        mpls_labels: vec![],
                        vpn: vec![],
                        blackhole: false,
                    }],
                }],
                next: Some("10.0.0.0/8".parse().unwrap()),
            }
        }
        RibRequest::Lookup { .. } => RibEvent::NoMatch,
        _ => RibEvent::Error("unsupported".into()),
    });
    let f = fixture(vec![(ServiceRef::RibTable("rt1".into()), rib)]).await;

    let (s, v) = send(&f.app, Method::GET, "/v1/routes/rt1", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["items"][0]["prefix"], "10.0.0.0/8");
    assert_eq!(v["pagination"]["limit"], 1000);
    assert_eq!(v["pagination"]["next"], "10.0.0.0/8");
    assert_eq!(
        send(&f.app, Method::GET, "/v1/routes/rt1/192.0.2.9", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (st, v) = send(&f.app, Method::GET, "/v1/routes/other", None).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["detail"], "a backend daemon is unavailable");
    assert_eq!(
        send(&f.app, Method::GET, "/v1/interfaces", None).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn show_bfd_sessions_filters_by_peer_and_rejects_a_bad_one() {
    let dir = tempfile::tempdir().unwrap();
    let bfd = dir.path().join("bfd.sock");
    serve(&bfd, ("bfdd", ""), |req: BfdRequest| match req {
        BfdRequest::GetSessions { peer } => BfdEvent::Sessions(
            [("192.0.2.1", 1u32), ("192.0.2.2", 2)]
                .into_iter()
                .filter(|(p, _)| peer.is_none_or(|q| q.to_string() == *p))
                .map(|(p, n)| nos_proto::BfdSessionView {
                    key: nos_proto::SessionKey {
                        aggregate: None,
                        table: "rt1".into(),
                        peer: p.parse().unwrap(),
                        local: None,
                        interface: None,
                        multihop: false,
                    },
                    state: nos_proto::BfdState::Up,
                    diag: nos_proto::BfdDiag::NoDiagnostic,
                    local_discriminator: n,
                    remote_discriminator: 9,
                    tx_interval_us: 100_000,
                    detection_time_us: 300_000,
                    auth_method: None,
                    auth_key_id: None,
                    auth_failures: 0,
                    echo_active: false,
                    echo_interval_us: 0,
                    echo_only: false,
                    tx_pdu_bytes: 0,
                    kind: nos_proto::BfdSessionKind::Classical,
                })
                .collect(),
        ),
        _ => panic!("only GetSessions is asked"),
    });
    let f = fixture(vec![(ServiceRef::Bfd, bfd)]).await;

    let (s, v) = send(&f.app, Method::GET, "/v1/bfd/sessions", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_array().unwrap().len(), 2);
    assert_eq!(v[0]["state"], "Up");
    let (s, v) = send(&f.app, Method::GET, "/v1/bfd/sessions?peer=192.0.2.2", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["key"]["peer"], "192.0.2.2");
    assert_eq!(
        send(&f.app, Method::GET, "/v1/bfd/sessions?peer=nope", None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    // No nos-bfdd registered with the broker: 503.
    let none = fixture(vec![]).await;
    assert_eq!(
        send(&none.app, Method::GET, "/v1/bfd/sessions", None)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn show_spanning_tree_serves_the_summary_and_503s_without_stpd() {
    let dir = tempfile::tempdir().unwrap();
    let stp = dir.path().join("stp.sock");
    serve(&stp, ("stpd", ""), |_: nos_proto::StpRequest| {
        nos_proto::StpEvent::Summary(nos_proto::StpSummary {
            enabled: true,
            bridge_id: "8000.02:00:00:00:00:01".into(),
            ports: vec![nos_proto::StpPortInfo {
                name: "eth1".into(),
                role: nos_proto::StpRole::Alternate,
                state: nos_proto::StpState::Discarding,
                ..nos_proto::StpPortInfo::default()
            }],
            ..nos_proto::StpSummary::default()
        })
    });
    let f = fixture(vec![(ServiceRef::Stp, stp)]).await;
    let (s, v) = send(&f.app, Method::GET, "/v1/spanning-tree", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["enabled"], true);
    assert_eq!(v["ports"][0]["role"], "alternate");
    assert_eq!(v["ports"][0]["state"], "discarding");

    let none = fixture(vec![]).await;
    assert_eq!(
        send(&none.app, Method::GET, "/v1/spanning-tree", None)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn show_spanning_tree_mst_views_404_outside_mstp() {
    let dir = tempfile::tempdir().unwrap();
    let (rstp, mstp) = (dir.path().join("rstp.sock"), dir.path().join("mstp.sock"));
    serve(&rstp, ("stpd", ""), |_: nos_proto::StpRequest| {
        nos_proto::StpEvent::Summary(nos_proto::StpSummary::default())
    });
    serve(&mstp, ("stpd", ""), |_: nos_proto::StpRequest| {
        nos_proto::StpEvent::Summary(nos_proto::StpSummary {
            enabled: true,
            mst: Some(nos_proto::StpMst {
                region_name: "lab".into(),
                revision: 2,
                digest: "00".repeat(16),
                max_hops: 20,
                instances: vec![nos_proto::StpInstance {
                    id: 1,
                    vlans: "10".into(),
                    ..nos_proto::StpInstance::default()
                }],
            }),
            ..nos_proto::StpSummary::default()
        })
    });
    let off = fixture(vec![(ServiceRef::Stp, rstp)]).await;
    for path in [
        "/v1/spanning-tree/instance/1",
        "/v1/spanning-tree/mst-config",
    ] {
        assert_eq!(
            send(&off.app, Method::GET, path, None).await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let on = fixture(vec![(ServiceRef::Stp, mstp)]).await;
    let (s, v) = send(&on.app, Method::GET, "/v1/spanning-tree/instance/1", None).await;
    assert_eq!((s, v["vlans"].as_str()), (StatusCode::OK, Some("10")));
    let (s, v) = send(&on.app, Method::GET, "/v1/spanning-tree/mst-config", None).await;
    assert_eq!(
        (s, v["region_name"].as_str()),
        (StatusCode::OK, Some("lab"))
    );
    assert_eq!(
        send(&on.app, Method::GET, "/v1/spanning-tree/instance/7", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn show_spanning_tree_domain_serves_a_pvst_tree_and_404s_otherwise() {
    let dir = tempfile::tempdir().unwrap();
    let (rstp, pvst) = (dir.path().join("rstp.sock"), dir.path().join("pvst.sock"));
    serve(&rstp, ("stpd", ""), |_: nos_proto::StpRequest| {
        nos_proto::StpEvent::Summary(nos_proto::StpSummary::default())
    });
    serve(&pvst, ("stpd", ""), |_: nos_proto::StpRequest| {
        nos_proto::StpEvent::Summary(nos_proto::StpSummary {
            enabled: true,
            pvst: vec![nos_proto::StpInstance {
                id: 10,
                vlans: "10".into(),
                domains: vec!["bd1".into()],
                ..nos_proto::StpInstance::default()
            }],
            ..nos_proto::StpSummary::default()
        })
    });
    let off = fixture(vec![(ServiceRef::Stp, rstp)]).await;
    assert_eq!(
        send(&off.app, Method::GET, "/v1/spanning-tree/domain/bd1", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let on = fixture(vec![(ServiceRef::Stp, pvst)]).await;
    let (s, v) = send(&on.app, Method::GET, "/v1/spanning-tree/domain/bd1", None).await;
    assert_eq!((s, v["id"].as_u64()), (StatusCode::OK, Some(10)));
    assert_eq!(
        send(&on.app, Method::GET, "/v1/spanning-tree/domain/nope", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn show_spanning_tree_counters_lists_one_row_per_port_and_tree() {
    let dir = tempfile::tempdir().unwrap();
    let (rstp, pvst) = (dir.path().join("rstp.sock"), dir.path().join("pvst.sock"));
    let counters = nos_proto::StpPortCounters {
        in_rstp_bpdu: 4,
        ..nos_proto::StpPortCounters::default()
    };
    serve(&rstp, ("stpd", ""), move |_: nos_proto::StpRequest| {
        nos_proto::StpEvent::Summary(nos_proto::StpSummary {
            enabled: true,
            ports: vec![nos_proto::StpPortInfo {
                name: "eth1".into(),
                counters,
                ..nos_proto::StpPortInfo::default()
            }],
            topology: nos_proto::StpTopology {
                count: 2,
                ..nos_proto::StpTopology::default()
            },
            ..nos_proto::StpSummary::default()
        })
    });
    serve(&pvst, ("stpd", ""), move |_: nos_proto::StpRequest| {
        nos_proto::StpEvent::Summary(nos_proto::StpSummary {
            enabled: true,
            pvst: vec![nos_proto::StpInstance {
                domains: vec!["bd1".into()],
                ports: vec![nos_proto::StpInstancePort {
                    name: "eth2".into(),
                    counters,
                    ..nos_proto::StpInstancePort::default()
                }],
                ..nos_proto::StpInstance::default()
            }],
            ..nos_proto::StpSummary::default()
        })
    });
    let f = fixture(vec![(ServiceRef::Stp, rstp)]).await;
    let (s, v) = send(&f.app, Method::GET, "/v1/spanning-tree/counters", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        (
            &v[0]["tree"],
            &v[0]["port"],
            &v[0]["counters"]["in_rstp_bpdu"]
        ),
        (&json!("cist"), &json!("eth1"), &json!(4))
    );
    let (_, v) = send(&f.app, Method::GET, "/v1/spanning-tree", None).await;
    assert_eq!(v["topology"]["count"], 2);
    let p = fixture(vec![(ServiceRef::Stp, pvst)]).await;
    let (_, v) = send(&p.app, Method::GET, "/v1/spanning-tree/counters", None).await;
    assert_eq!(
        (&v[0]["tree"], &v[0]["port"]),
        (&json!("bd1"), &json!("eth2"))
    );
    let none = fixture(vec![]).await;
    assert_eq!(
        send(&none.app, Method::GET, "/v1/spanning-tree/counters", None)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn router_wide_show_reports_each_instance_that_is_not_running() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/t4?base=current", None).await;
    send(
        app,
        Method::PUT,
        "/v1/transactions/t4/bgp-instance/r1",
        Some(bgp_instance("r1", 1)),
    )
    .await;
    send(app, Method::POST, "/v1/transactions/t4/commit", None).await;

    let (s, v) = send(app, Method::GET, "/v1/bgp/summary", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v, json!([{ "instance": "r1", "error": "not running" }]));
    let (s, v) = send(app, Method::GET, "/v1/bgp/evpn", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v, json!([{ "instance": "r1", "error": "not running" }]));
    let (s, v) = send(app, Method::GET, "/v1/bgp/rpki", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v, json!([{ "instance": "r1", "error": "not running" }]));
    assert_eq!(
        send(app, Method::GET, "/v1/ospf/neighbors", None).await.1,
        json!([])
    );
}

/// Every error is an RFC 9457 problem document whose `status` repeats the
/// HTTP status, with the right code for each kind of failure.
#[tokio::test]
async fn errors_are_problem_json_with_the_right_status() {
    let f = fixture(vec![]).await;
    send(&f.app, Method::POST, "/v1/transactions/p1?base=blank", None).await;
    send(
        &f.app,
        Method::PUT,
        "/v1/transactions/p1/hostname",
        Some(json!("bad host name!")),
    )
    .await;
    let cases: [(Method, &str, Option<&str>, StatusCode); 9] = [
        (
            Method::POST,
            "/v1/transactions/p2?base=bogus",
            Some(USER),
            StatusCode::BAD_REQUEST,
        ),
        (Method::GET, "/v1/config", None, StatusCode::UNAUTHORIZED),
        (
            Method::GET,
            "/v1/transactions/nope",
            Some(USER),
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/v1/transactions/p1/commit",
            Some(USER),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            Method::GET,
            "/v1/interfaces",
            Some(USER),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            Method::GET,
            "/v1/interfaces/eth9",
            Some(USER),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        // The framework's own errors, not a handler's: an extractor rejection
        // (`limit` is a `usize`), an unknown route, a wrong method.
        (
            Method::GET,
            "/v1/logs?limit=abc",
            Some(USER),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::GET,
            "/v1/no-such-route",
            Some(USER),
            StatusCode::NOT_FOUND,
        ),
        (
            Method::DELETE,
            "/v1/config",
            Some(USER),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ];
    for (method, uri, user, want) in cases {
        let req = HttpRequest::builder()
            .method(method)
            .uri(uri)
            .extension(PeerUser(
                user.map(str::to_string),
                user.map(|_| "live".to_string()),
            ))
            .body(Body::empty())
            .unwrap();
        let resp = f.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), want, "{uri}");
        assert_eq!(
            resp.headers()[header::CONTENT_TYPE],
            "application/problem+json",
            "{uri}"
        );
        // RFC 9110 §15.5.2 / §15.5.6.
        if want == StatusCode::UNAUTHORIZED {
            let c = resp.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
            assert!(
                c.contains("Mutual") && c.contains("/v1/login"),
                "{uri}: {c}"
            );
        }
        if want == StatusCode::METHOD_NOT_ALLOWED {
            assert!(resp.headers().contains_key(header::ALLOW), "{uri}");
        }
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let p: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(p["type"], "about:blank", "{uri}");
        assert_eq!(p["status"], want.as_u16(), "{uri}");
        assert_eq!(p["title"], want.canonical_reason().unwrap(), "{uri}");
        assert!(!p["detail"].as_str().unwrap().is_empty(), "{uri}");
    }
}

#[tokio::test]
async fn serves_its_openapi_document() {
    let f = fixture(vec![]).await;
    let (s, doc) = send(&f.app, Method::GET, "/openapi.json", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(doc["openapi"].as_str().unwrap().starts_with("3."));
    // Error responses are documented as problem documents, never plain JSON.
    let text = doc["paths"].to_string();
    assert!(text.contains("application/problem+json"));
    assert!(!text
        .contains(r##""application/json":{"schema":{"$ref":"#/components/schemas/ErrorBody"}}"##));
    assert_eq!(
        doc["components"]["schemas"]["ErrorBody"]["required"],
        json!(["type", "title", "status", "detail"])
    );
    let paths = doc["paths"].as_object().unwrap();
    assert!(!paths.contains_key("/v1/transactions/{tx}/bgp-instance/{bgp_instance}/name"));
    assert!(paths
        .contains_key("/v1/transactions/{tx}/bgp-instance/{bgp_instance}/peer-group/{peer_group}"));
    assert!(paths.contains_key("/v1/routes/{table}"));
}

#[tokio::test]
async fn serves_swagger_ui_from_vendored_assets() {
    let f = fixture(vec![]).await;
    let (s, html) = send(&f.app, Method::GET, "/swagger-ui/", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(html.as_str().unwrap().contains("Swagger UI"));
    let (s, _) = send(&f.app, Method::GET, "/swagger-ui/swagger-ui.css", None).await;
    assert_eq!(s, StatusCode::OK);
    // #408: hardening headers; CSP on the UI only.
    for (uri, csp) in [("/swagger-ui/", true), ("/openapi.json", false)] {
        let req = HttpRequest::builder()
            .uri(uri)
            .extension(PeerUser(Some(USER.to_string()), Some("live".into())))
            .body(Body::empty())
            .unwrap();
        let resp = f.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
        assert_eq!(
            resp.headers().contains_key("content-security-policy"),
            csp,
            "{uri}"
        );
    }
}

fn log_entry(source: &str, message: &str) -> LogEntry {
    LogEntry {
        timestamp_ms: 1,
        level: LogLevel::Info,
        source: source.to_string(),
        target: "t".to_string(),
        message: message.to_string(),
        fields: vec![],
    }
}

/// A fake `nos-logd`: a `Tail` gets a backlog of two entries, then one
/// streamed line, then the connection closes (which ends the SSE stream).
fn serve_logd(path: &Path) {
    let listener = shared().identity("logd", "").listen(path).unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            tokio::spawn(async move {
                let (r, w) = tokio::io::split(stream);
                let mut reader = FramedRead::new(r, IpcCodec::<LogRequest>::default());
                let mut writer = FramedWrite::new(w, IpcCodec::<LogEvent>::default());
                if let Some(Ok(LogRequest::Tail { source })) = reader.next().await {
                    let src = source.unwrap_or_else(|| "any".to_string());
                    writer
                        .send(LogEvent::Logs(vec![
                            log_entry(&src, "old-1"),
                            log_entry(&src, "old-2"),
                        ]))
                        .await
                        .unwrap();
                    writer
                        .send(LogEvent::Line(log_entry(&src, "live-1")))
                        .await
                        .unwrap();
                }
            });
        }
    });
}

#[tokio::test]
async fn follow_logs_streams_backlog_then_live_lines_as_sse() {
    let dir = tempfile::tempdir().unwrap();
    let logd = dir.path().join("log.sock");
    serve_logd(&logd);
    let f = fixture(vec![(ServiceRef::Log, logd)]).await;

    let req = HttpRequest::builder()
        .uri("/v1/logs/follow?source=nos-x")
        .extension(PeerUser(Some(USER.to_string()), Some("live".into())))
        .body(Body::empty())
        .unwrap();
    let resp = f.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let body = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(body.matches("event: log").count(), 3, "{body}");
    assert!(
        body.contains("old-1") && body.contains("live-1") && body.contains("nos-x"),
        "{body}"
    );

    // `limit` trims the backlog only: the newest backlog entry and the live line remain.
    let req = HttpRequest::builder()
        .uri("/v1/logs/follow?limit=1")
        .extension(PeerUser(Some(USER.to_string()), Some("live".into())))
        .body(Body::empty())
        .unwrap();
    let resp = f.app.clone().oneshot(req).await.unwrap();
    let body = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        !body.contains("old-1") && body.contains("old-2") && body.contains("live-1"),
        "{body}"
    );

    // Without a running nos-logd it is a plain 503, not a hung stream.
    let f = fixture(vec![]).await;
    let (s, _) = send(&f.app, Method::GET, "/v1/logs/follow", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn bgp_vpn_routes_pass_the_family_and_rd_through() {
    let dir = tempfile::tempdir().unwrap();
    let bgpd = dir.path().join("bgp.sock");
    serve(&bgpd, ("bgpd", "r1"), |req: BgpRequest| match req {
        BgpRequest::GetVpnRoutesPage {
            family,
            rd,
            after,
            limit,
        } => BgpEvent::VpnRoutesPage {
            routes: vec![nos_proto::VpnRouteSummary {
                peer: "192.0.2.1".parse().unwrap(),
                rd: rd.unwrap_or_default(),
                prefix: family.to_string(),
                labels: vec![100],
                next_hop: "192.0.2.1".parse().unwrap(),
                route_targets: vec!["RT:65000:1".into()],
                as_path: "65001".into(),
                local_pref: limit,
                best: true,
                site_of_origin: None,
            }],
            // A first page has a next one, the continuation is the last.
            next: after.is_none().then(|| nos_proto::VpnRouteCursor {
                peer: "192.0.2.1".parse().unwrap(),
                rd: [0, 0, 0xfd, 0xe9, 0, 0, 0, 1],
                prefix: "10.0.0.0/24".parse().unwrap(),
            }),
        },
        _ => BgpEvent::PeerNotFound,
    });
    let f = fixture(vec![(ServiceRef::BgpInstance("r1".into()), bgpd)]).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/v1?base=current", None).await;
    send(
        app,
        Method::PUT,
        "/v1/transactions/v1/bgp-instance/r1",
        Some(bgp_instance("r1", 1)),
    )
    .await;
    send(app, Method::POST, "/v1/transactions/v1/commit", None).await;

    let (s, v) = send(app, Method::GET, "/v1/bgp/vpnv4?rd=65001:1", None).await;
    assert_eq!(s, StatusCode::OK);
    let r = &v[0]["result"]["items"][0];
    assert_eq!(
        (&v[0]["instance"], &r["rd"], &r["prefix"], &r["labels"]),
        (
            &json!("r1"),
            &json!("65001:1"),
            &json!("vpnv4"),
            &json!([100])
        )
    );
    // The cursor continues the same walk, with the same filter, to the end.
    let next = v[0]["result"]["pagination"]["next"].as_str().unwrap();
    assert!(!next.contains(['/', '.', ':']), "opaque, URL-safe: {next}");
    let (s, v) = send(
        app,
        Method::GET,
        &format!("/v1/bgp/vpnv4?rd=65001:1&instance=r1&limit=7&after={next}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let r = &v[0]["result"];
    assert_eq!(r["items"][0]["rd"], json!("65001:1"));
    assert_eq!(r["items"][0]["local_pref"], json!(7));
    assert_eq!(r["pagination"], json!({"limit": 7, "next": null}));
    let (_, v) = send(app, Method::GET, "/v1/bgp/vpnv6", None).await;
    assert_eq!(v[0]["result"]["items"][0]["prefix"], json!("vpnv6"));
    for bad in [
        "/v1/bgp/vpnv4?rd=nope",
        "/v1/bgp/vpnv4?limit=2",
        "/v1/bgp/vpnv6?instance=r1&after=nope",
    ] {
        let (s, _) = send(app, Method::GET, bad, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (s, _) = send(app, Method::GET, "/v1/bgp/vpnv4?instance=zz", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn clear_bgp_peer_maps_the_daemons_reply_to_a_status() {
    let dir = tempfile::tempdir().unwrap();
    let bgpd = dir.path().join("bgp.sock");
    serve(&bgpd, ("bgpd", "r1"), |req: BgpRequest| match req {
        BgpRequest::ClearPeer { peer } if peer.to_string() == "192.0.2.1" => BgpEvent::PeerCleared,
        _ => BgpEvent::PeerNotFound,
    });
    let f = fixture(vec![(ServiceRef::BgpInstance("r1".into()), bgpd)]).await;
    let (s, v) = send(
        &f.app,
        Method::POST,
        "/v1/bgp/r1/peer/192.0.2.1/clear",
        None,
    )
    .await;
    assert_eq!(
        (s, v),
        (
            StatusCode::OK,
            json!({ "instance": "r1", "peer": "192.0.2.1", "cleared": true })
        )
    );
    let (s, _) = send(
        &f.app,
        Method::POST,
        "/v1/bgp/r1/peer/192.0.2.9/clear",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn clear_bgp_soft_in_maps_the_daemons_reply_to_a_status() {
    let dir = tempfile::tempdir().unwrap();
    let bgpd = dir.path().join("bgp.sock");
    serve(&bgpd, ("bgpd", "r1"), |req: BgpRequest| match req {
        BgpRequest::SendRouteRefresh { peer } if peer.to_string() == "192.0.2.1" => {
            BgpEvent::RouteRefreshSent
        }
        BgpRequest::SendRouteRefresh { peer } if peer.to_string() == "192.0.2.5" => {
            BgpEvent::SoftInReevaluated {
                families: vec![nos_proto::FamilyReeval {
                    family: nos_proto::ReevalFamily::Ipv4Unicast,
                    retained: 3,
                    accepted: 2,
                }],
            }
        }
        BgpRequest::SendRouteRefresh { peer } if peer.to_string() == "192.0.2.6" => {
            BgpEvent::Error("re-evaluation superseded/aborted: superseded".into())
        }
        _ => BgpEvent::PeerNotFound,
    });
    let f = fixture(vec![(ServiceRef::BgpInstance("r1".into()), bgpd)]).await;

    let (s, v) = send(
        &f.app,
        Method::POST,
        "/v1/bgp/r1/peer/192.0.2.1/soft-in",
        None,
    )
    .await;
    assert_eq!(
        (s, v),
        (
            StatusCode::OK,
            json!({ "instance": "r1", "peer": "192.0.2.1", "route_refresh": "sent" })
        )
    );
    // A peer-group with soft reconfiguration inbound re-evaluates locally.
    let (s, v) = send(
        &f.app,
        Method::POST,
        "/v1/bgp/r1/peer/192.0.2.5/soft-in",
        None,
    )
    .await;
    assert_eq!(
        (s, v),
        (
            StatusCode::OK,
            json!({ "instance": "r1", "peer": "192.0.2.5", "route_refresh": "none",
                    "reevaluated": [{ "family": "ipv4-unicast", "retained": 3, "accepted": 2 }] })
        )
    );
    assert_eq!(
        send(
            &f.app,
            Method::POST,
            "/v1/bgp/r1/peer/192.0.2.6/soft-in",
            None
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // No Established session (or unknown peer): 404. Unknown instance: 503. Bad address: 400.
    assert_eq!(
        send(
            &f.app,
            Method::POST,
            "/v1/bgp/r1/peer/192.0.2.9/soft-in",
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &f.app,
            Method::POST,
            "/v1/bgp/r2/peer/192.0.2.1/soft-in",
            None
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        send(
            &f.app,
            Method::POST,
            "/v1/bgp/r1/peer/not-an-ip/soft-in",
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    // It is an action, not a query.
    assert_eq!(
        send(
            &f.app,
            Method::GET,
            "/v1/bgp/r1/peer/192.0.2.1/soft-in",
            None
        )
        .await
        .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn every_route_requires_a_certificate_of_an_existing_user() {
    let f = fixture(vec![]).await;
    let app = &f.app;

    for uri in [
        "/v1/config",
        "/openapi.json",
        "/swagger-ui/",
        "/v1/logs/follow",
        "/v1/transactions/t1",
    ] {
        let (s, _) = send_as(app, Method::GET, uri, None, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{uri} without a certificate");
        let (s, _) = send_as(app, Method::GET, uri, None, Some("nobody")).await;
        assert_eq!(
            s,
            StatusCode::UNAUTHORIZED,
            "{uri} for a user that does not exist"
        );
    }
    let (s, _) = send_as(
        app,
        Method::POST,
        "/v1/renew",
        Some(json!({"csr": ""})),
        None,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "renewal needs the certificate to renew"
    );

    for uri in ["/v1/config", "/openapi.json"] {
        let (s, _) = send(app, Method::GET, uri, None).await;
        assert_eq!(s, StatusCode::OK, "{uri} with a valid certificate");
    }
    // The OpenAPI document advertises the scheme, and login is the one exception.
    let (_, doc) = send(app, Method::GET, "/openapi.json", None).await;
    assert_eq!(
        doc["components"]["securitySchemes"]["mtls"]["type"],
        "mutualTLS"
    );
    assert_eq!(doc["security"], json!([{"mtls": []}]));
    assert_eq!(
        doc["paths"]["/v1/login"]["post"]["security"],
        json!([{}]),
        "login must be documented as needing no certificate"
    );
}

#[tokio::test]
async fn secrets_never_leave_and_the_mask_round_trips() {
    let f = fixture_with(vec![], Some("config.yaml")).await;
    let app = &f.app;
    let saved = || std::fs::read_to_string(f.dir.path().join("config.yaml")).unwrap();

    send(app, Method::POST, "/v1/transactions/t1", None).await;
    let (s, _) = send(
        app,
        Method::PUT,
        "/v1/transactions/t1/admin/key/k1",
        Some(json!({"label": "k1", "secret": "needle-one"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // The PUT reply, a section GET and the whole-transaction GET are all masked.
    let (_, whole) = send(app, Method::GET, "/v1/transactions/t1", None).await;
    let (_, key) = send(app, Method::GET, "/v1/transactions/t1/admin/key/k1", None).await;
    assert_eq!(key, json!({"label": "k1", "secret": "<hidden>"}));
    assert!(!whole.to_string().contains("needle-one"), "{whole}");
    let (s, _) = send(app, Method::POST, "/v1/transactions/t1/commit", None).await;
    assert_eq!(s, StatusCode::OK);
    let (_, running) = send(app, Method::GET, "/v1/config", None).await;
    assert_eq!(running["admin"]["keys"][0]["secret"], "<hidden>");
    assert!(!running.to_string().contains("needle-one"), "{running}");

    // GET, then PUT the same document back: the stored secret survives.
    send(app, Method::POST, "/v1/transactions/t2", None).await;
    let (_, cfg) = send(app, Method::GET, "/v1/transactions/t2", None).await;
    let (s, _) = send(
        app,
        Method::PUT,
        "/v1/transactions/t2",
        Some(cfg["config"].clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(app, Method::POST, "/v1/transactions/t2/commit", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(app, Method::POST, "/v1/config/save", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(saved().contains("needle-one"), "mask destroyed the secret");
    assert!(!saved().contains("<hidden>"));

    // The mask on a label that does not exist is refused, not stored.
    send(app, Method::POST, "/v1/transactions/t3", None).await;
    let (s, _) = send(
        app,
        Method::PUT,
        "/v1/transactions/t3/admin/key/ghost",
        Some(json!({"label": "ghost", "secret": "<hidden>"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_user_deleted_from_the_config_is_locked_out_on_the_next_request() {
    let f = fixture(vec![]).await;
    let app = &f.app;

    // A certificate for a user who is not in the running config yet is refused…
    let (s, _) = send_as(app, Method::GET, "/v1/config", None, Some("bob")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    send(app, Method::POST, "/v1/transactions/t1", None).await;
    let (s, _) = send(
        app,
        Method::PUT,
        "/v1/transactions/t1/user/bob",
        Some(json!({"name": "bob", "password": "bobpw"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, snap) = send(app, Method::GET, "/v1/transactions/t1/user/bob", None).await;
    // Neither the clear text nor even the hash is returned (#507).
    assert_eq!(snap["password"], "<hidden>", "{snap}");
    // …still refused while the user only exists in an open transaction…
    let (s, _) = send_as(app, Method::GET, "/v1/config", None, Some("bob")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // …accepted once committed…
    let (s, _) = send(app, Method::POST, "/v1/transactions/t1/commit", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send_as(app, Method::GET, "/v1/config", None, Some("bob")).await;
    assert_eq!(s, StatusCode::OK);

    // …and locked out again as soon as they are deleted.
    send(app, Method::POST, "/v1/transactions/t2?base=current", None).await;
    let (s, _) = send(app, Method::DELETE, "/v1/transactions/t2/user/bob", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = send(app, Method::POST, "/v1/transactions/t2/commit", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send_as(app, Method::GET, "/v1/config", None, Some("bob")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_needs_no_certificate_and_a_failed_one_costs_a_second() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    let login = |password: &str, csr: &str| json!({"user": USER, "password": password, "csr": csr});

    let (s, body) = send_as(
        app,
        Method::POST,
        "/v1/login",
        Some(login(PASSWORD, "AQID")),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["certificate"], "AQID"); // base64 of the stand-in CA's [1, 2, 3]
    assert_eq!(body["lifetime_secs"], 60);

    let started = std::time::Instant::now();
    let (s, _) = send_as(
        app,
        Method::POST,
        "/v1/login",
        Some(login("nope", "AQID")),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));

    let (s, _) = send_as(
        app,
        Method::POST,
        "/v1/login",
        Some(login(PASSWORD, "!!!")),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a csr that is not base64");
}

/// However many streams or connections the guesses arrive on, one account
/// takes one guess per second.
#[tokio::test]
async fn guesses_at_one_account_are_serialised() {
    let f = fixture(vec![]).await;
    let started = std::time::Instant::now();
    let guess = |i: u8| {
        let app = f.app.clone();
        async move {
            let body = json!({"user": USER, "password": format!("wrong{i}"), "csr": "AQID"});
            send_as(&app, Method::POST, "/v1/login", Some(body), None)
                .await
                .0
        }
    };
    let statuses = futures::future::join_all((0..3).map(guess)).await;
    assert!(statuses.iter().all(|s| *s == StatusCode::UNAUTHORIZED));
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(3),
        "three guesses at one account must not run in parallel: {:?}",
        started.elapsed()
    );
}

/// RFC 6585: after five failures the account gets 429 + Retry-After at once.
#[tokio::test]
async fn too_many_failed_logins_get_429_with_retry_after() {
    let f = fixture(vec![]).await;
    let guess = |user: &str, password: &str| {
        let body = json!({"user": user, "password": password, "csr": "AQID"});
        HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/login")
            .header(header::CONTENT_TYPE, "application/json")
            .extension(PeerUser(None, None))
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    for _ in 0..5 {
        let resp = f.app.clone().oneshot(guess(USER, "nope")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    let started = std::time::Instant::now();
    // Even the right password is refused while locked out.
    let resp = f.app.clone().oneshot(guess(USER, PASSWORD)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let secs: u64 = resp.headers()[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&secs), "{secs}");
    assert_eq!(
        resp.headers()[header::CONTENT_TYPE],
        "application/problem+json"
    );
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
}

/// A certificate the watchdog no longer vouches for (password changed,
/// session past its cap) is refused on every route, renewal included.
#[tokio::test]
async fn a_revoked_certificate_gets_401_everywhere_including_renew() {
    let f = fixture(vec![]).await;
    for (method, uri, body) in [
        (Method::GET, "/v1/config", None),
        (Method::POST, "/v1/renew", Some(json!({"csr": "AQID"}))),
    ] {
        let req = HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(PeerUser(Some(USER.to_string()), Some("revoked".into())))
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        let resp = f.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn renewal_is_for_the_user_the_certificate_names() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    let (s, body) = send_as(
        app,
        Method::POST,
        "/v1/renew",
        Some(json!({"csr": "AQID"})),
        Some(USER),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["certificate"], "BAUG");
}

// By value: it is the `serve` handler shape.
#[allow(clippy::needless_pass_by_value)]
fn rib_with_one_route(req: RibRequest) -> RibEvent {
    match req {
        RibRequest::GetRoutesPage { .. } => RibEvent::RoutesPage {
            routes: vec![PrefixRoutes {
                prefix: "10.0.0.0/8".parse().unwrap(),
                candidates: vec![],
            }],
            next: None,
        },
        _ => RibEvent::Error("unsupported".into()),
    }
}

/// Every IPC connection is a mutual-TLS handshake: repeated requests must ride
/// one connection per daemon, not open a fresh one each time.
#[tokio::test]
async fn requests_reuse_one_ipc_connection_per_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let rib = dir.path().join("rib.sock");
    let ribd = serve(&rib, ("ribd", "rt1"), rib_with_one_route);
    let f = fixture(vec![(ServiceRef::RibTable("rt1".into()), rib)]).await;

    for _ in 0..10 {
        let (s, _) = send(&f.app, Method::GET, "/v1/routes/rt1", None).await;
        assert_eq!(s, StatusCode::OK);
    }
    assert_eq!(
        ribd.load(Ordering::SeqCst),
        1,
        "ten requests, one handshake to nos-ribd"
    );
}

/// A parked connection whose daemon has gone away is retried on a fresh one,
/// not surfaced as an error.
#[tokio::test]
async fn a_stale_pooled_connection_is_retried_on_a_fresh_one() {
    let dir = tempfile::tempdir().unwrap();
    let rib = dir.path().join("rib.sock");
    let ribd = serve_with(&rib, ("ribd", "rt1"), true, rib_with_one_route);
    let f = fixture(vec![(ServiceRef::RibTable("rt1".into()), rib)]).await;

    for _ in 0..3 {
        let (s, _) = send(&f.app, Method::GET, "/v1/routes/rt1", None).await;
        assert_eq!(s, StatusCode::OK);
    }
    assert_eq!(ribd.load(Ordering::SeqCst), 3);
}

/// `after`/`limit` reach `nos-ribd` (limit clamped), a bad cursor is a 400,
/// and the last page's `next` is null.
#[tokio::test]
async fn routes_pagination_params_are_forwarded_and_validated() {
    let dir = tempfile::tempdir().unwrap();
    let rib = dir.path().join("rib.sock");
    serve(&rib, ("ribd", "rt1"), |req: RibRequest| match req {
        RibRequest::GetRoutesPage { after, limit } => {
            assert_eq!(after, Some("10.0.0.0/8".parse().unwrap()));
            RibEvent::RoutesPage {
                routes: vec![],
                next: (limit == 5).then(|| "11.0.0.0/8".parse().unwrap()),
            }
        }
        _ => RibEvent::Error("unsupported".into()),
    });
    let f = fixture(vec![(ServiceRef::RibTable("rt1".into()), rib)]).await;
    let (s, v) = send(
        &f.app,
        Method::GET,
        "/v1/routes/rt1?after=10.0.0.0/8&limit=5",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["pagination"]["limit"], 5);
    assert_eq!(v["pagination"]["next"], "11.0.0.0/8");
    // 0 and over-large limits are clamped to 1 and 1000.
    let (_, v) = send(
        &f.app,
        Method::GET,
        "/v1/routes/rt1?after=10.0.0.0/8&limit=0",
        None,
    )
    .await;
    assert_eq!(v["pagination"]["limit"], 1);
    assert!(v["pagination"]["next"].is_null());
    let (_, v) = send(
        &f.app,
        Method::GET,
        "/v1/routes/rt1?after=10.0.0.0/8&limit=99999",
        None,
    )
    .await;
    assert_eq!(v["pagination"]["limit"], 1000);
    let (s, _) = send(&f.app, Method::GET, "/v1/routes/rt1?after=nope", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

mod over_tls {
    //! The real listener loop: TLS 1.3 with post-quantum key exchange, HTTP/2,
    //! and the user taken from the client's certificate.

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use hyper_util::rt::{TokioExecutor, TokioIo};
    use nos_pki::rest::{client_config, RestServer};
    use nos_pki::{generate_csr_for, Ca, KeyAlg, PeerId};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    use super::*;

    type Sender = hyper::client::conn::http2::SendRequest<Body>;

    struct Tls {
        ca: Ca,
        addr: std::net::SocketAddr,
        _stop: watch::Sender<bool>,
        _fixture: Fixture,
    }

    async fn start() -> Tls {
        start_capped(nos_rest::listen::MAX_CONNECTIONS).await
    }

    async fn start_capped(cap: usize) -> Tls {
        let f = fixture(vec![]).await;
        let ca = Ca::new(KeyAlg::EcdsaP256).unwrap();
        let server = Arc::new(RestServer::new(ca.cert_der()).unwrap());
        let (csr, key) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
        let cert = ca
            .sign_server_csr(
                &csr,
                &[Ipv4Addr::LOCALHOST.into()],
                Duration::from_secs(3600),
            )
            .unwrap();
        server.set_certificate(&cert, &key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stop_rx) = watch::channel(false);
        tokio::spawn(nos_rest::listen::serve(
            listener,
            f.app.clone(),
            server,
            stop_rx,
            cap,
        ));
        Tls {
            ca,
            addr,
            _stop: stop,
            _fixture: f,
        }
    }

    fn user_cert(ca: &Ca, name: &str) -> (Vec<u8>, Vec<u8>) {
        let (csr, key) = generate_csr_for(KeyAlg::EcdsaP256).unwrap();
        let cert = ca
            .sign_csr(&csr, &PeerId::new("user", name), Duration::from_secs(3600))
            .unwrap();
        (cert, key.to_vec())
    }

    impl Tls {
        /// An HTTP/2 connection presenting `identity`; asserts ALPN chose h2.
        async fn connect(&self, identity: Option<(&[u8], &[u8])>) -> Sender {
            let cfg = client_config(self.ca.cert_pem().as_bytes(), identity).unwrap();
            let tcp = TcpStream::connect(self.addr).await.unwrap();
            let tls = TlsConnector::from(Arc::new(cfg))
                .connect(ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()), tcp)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let (sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                    .await
                    .unwrap();
            tokio::spawn(conn);
            sender
        }
    }

    async fn get(mut sender: Sender, path: &str) -> StatusCode {
        let req = HttpRequest::builder()
            .uri(format!("https://127.0.0.1{path}"))
            .body(Body::empty())
            .unwrap();
        sender.send_request(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn many_requests_multiplex_over_one_connection_and_the_certificate_names_the_user() {
        let t = start().await;
        let (cert, key) = user_cert(&t.ca, USER);
        let sender = t.connect(Some((&cert, &key))).await;
        let statuses =
            futures::future::join_all((0..20).map(|_| get(sender.clone(), "/v1/config"))).await;
        assert!(
            statuses.iter().all(|s| *s == StatusCode::OK),
            "{statuses:?}"
        );
    }

    #[tokio::test]
    async fn a_connection_past_the_cap_is_closed_unhandshaken_and_its_slot_is_reused() {
        use tokio::io::AsyncReadExt;
        let t = start_capped(1).await;
        let (cert, key) = user_cert(&t.ca, USER);
        let first = t.connect(Some((&cert, &key))).await;
        assert_eq!(get(first.clone(), "/v1/config").await, StatusCode::OK);

        let mut second = TcpStream::connect(t.addr).await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buf))
            .await
            .expect("refused connection must be closed promptly");
        assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");

        drop(first);
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let tcp = TcpStream::connect(t.addr).await.unwrap();
            let cfg = client_config(t.ca.cert_pem().as_bytes(), Some((&cert, &key))).unwrap();
            if TlsConnector::from(Arc::new(cfg))
                .connect(ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()), tcp)
                .await
                .is_ok()
            {
                return;
            }
        }
        panic!("the slot was never released");
    }

    #[tokio::test]
    async fn a_certificate_for_an_unknown_user_or_none_at_all_is_401() {
        let t = start().await;
        let (cert, key) = user_cert(&t.ca, "nobody");
        assert_eq!(
            get(t.connect(Some((&cert, &key))).await, "/v1/config").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get(t.connect(None).await, "/v1/config").await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn login_works_without_a_certificate_over_tls() {
        let t = start().await;
        let mut sender = t.connect(None).await;
        let req = HttpRequest::builder()
            .method(Method::POST)
            .uri("https://127.0.0.1/v1/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"user": USER, "password": PASSWORD, "csr": "AQID"}).to_string(),
            ))
            .unwrap();
        assert_eq!(
            sender.send_request(req).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_certificate_from_another_ca_never_gets_a_request_through() {
        let t = start().await;
        let other = Ca::new(KeyAlg::EcdsaP256).unwrap();
        let (cert, key) = user_cert(&other, USER);
        let cfg = client_config(t.ca.cert_pem().as_bytes(), Some((&cert, &key))).unwrap();
        let tcp = TcpStream::connect(t.addr).await.unwrap();
        let tls = TlsConnector::from(Arc::new(cfg))
            .connect(ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()), tcp)
            .await;
        // TLS 1.3 completes the client side before the server rules on its
        // certificate, so the rejection shows up on first use.
        let refused = match tls {
            Err(_) => true,
            Ok(tls) => {
                let handshake = hyper::client::conn::http2::handshake::<_, _, Body>(
                    TokioExecutor::new(),
                    TokioIo::new(tls),
                )
                .await;
                match handshake {
                    Err(_) => true,
                    Ok((mut sender, conn)) => {
                        tokio::spawn(conn);
                        let req = HttpRequest::builder()
                            .uri("https://127.0.0.1/v1/config")
                            .body(Body::empty())
                            .unwrap();
                        sender.send_request(req).await.is_err()
                    }
                }
            }
        };
        assert!(refused, "a certificate from another CA must not be served");
    }
}

#[tokio::test]
async fn bgp_routes_are_paged_per_instance_with_an_opaque_cursor() {
    use nos_proto::{BgpRouteCursor, BgpRouteSummary, RpkiValidationState};
    let key = |n: u8| BgpRouteCursor {
        prefix: format!("10.0.{n}.0/24").parse().unwrap(),
        peer: None,
        path_id: 0,
    };
    let dir = tempfile::tempdir().unwrap();
    let bgpd = dir.path().join("bgp.sock");
    serve(&bgpd, ("bgpd", "r1"), move |req: BgpRequest| match req {
        BgpRequest::GetRoutesPage { after, limit } => {
            let rest: Vec<u8> = (0..3)
                .filter(|n| after.is_none_or(|a| key(*n) > a))
                .collect();
            let take = &rest[..rest.len().min(limit as usize)];
            BgpEvent::RoutesPage {
                routes: take
                    .iter()
                    .map(|n| BgpRouteSummary {
                        prefix: key(*n).prefix.to_string(),
                        peer: None,
                        next_hop: None,
                        as_path: String::new(),
                        origin_as: None,
                        local_pref: limit,
                        best: true,
                        validation_state: RpkiValidationState::NotFound,
                    })
                    .collect(),
                next: (take.len() < rest.len()).then(|| key(*take.last().unwrap())),
            }
        }
        _ => BgpEvent::PeerNotFound,
    });
    let f = fixture(vec![(ServiceRef::BgpInstance("r1".into()), bgpd)]).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/v1?base=current", None).await;
    send(
        app,
        Method::PUT,
        "/v1/transactions/v1/bgp-instance/r1",
        Some(bgp_instance("r1", 1)),
    )
    .await;
    send(app, Method::POST, "/v1/transactions/v1/commit", None).await;

    // No parameters: every instance's first page at the default size.
    let (s, v) = send(app, Method::GET, "/v1/bgp/routes", None).await;
    assert_eq!(s, StatusCode::OK);
    let r = &v[0]["result"];
    assert_eq!(r["items"].as_array().unwrap().len(), 3);
    assert_eq!(r["pagination"], json!({"limit": 1000, "next": null}));

    // Two pages by following the opaque cursor.
    let (_, v) = send(app, Method::GET, "/v1/bgp/routes?instance=r1&limit=2", None).await;
    let r = &v[0]["result"];
    assert_eq!(r["items"].as_array().unwrap().len(), 2);
    let next = r["pagination"]["next"].as_str().unwrap().to_string();
    assert!(!next.contains(['/', '.', ':']), "opaque, URL-safe: {next}");
    let (s, v) = send(
        app,
        Method::GET,
        &format!("/v1/bgp/routes?instance=r1&limit=2&after={next}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let r = &v[0]["result"];
    assert_eq!(r["items"][0]["prefix"], json!("10.0.2.0/24"));
    assert_eq!(r["pagination"], json!({"limit": 2, "next": null}));

    // The limit is clamped to 1..=1000.
    let (_, v) = send(app, Method::GET, "/v1/bgp/routes?instance=r1&limit=0", None).await;
    assert_eq!(v[0]["result"]["pagination"]["limit"], json!(1));
    let (_, v) = send(
        app,
        Method::GET,
        "/v1/bgp/routes?instance=r1&limit=5000",
        None,
    )
    .await;
    assert_eq!(v[0]["result"]["pagination"]["limit"], json!(1000));

    // Pagination needs ?instance=, a bad cursor is 400, an unknown instance 404.
    for bad in [
        "/v1/bgp/routes?limit=2",
        "/v1/bgp/routes?after=AAAA",
        "/v1/bgp/routes?instance=r1&after=nope",
    ] {
        let (s, _) = send(app, Method::GET, bad, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (s, _) = send(app, Method::GET, "/v1/bgp/routes?instance=zz", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// #723: `/v1/bgp/evpn` and `/v1/bgp/flowspec` use the same envelope, opaque
/// cursor and `?instance=` rule as `/v1/bgp/routes`.
#[tokio::test]
async fn bgp_evpn_and_flowspec_are_paged_per_instance_with_an_opaque_cursor() {
    use nos_proto::{EvpnRouteCursor, EvpnRouteSummary, FlowspecRouteCursor, FlowspecRouteSummary};
    let peer: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let bgpd = dir.path().join("bgp.sock");
    serve(&bgpd, ("bgpd", "r1"), move |req: BgpRequest| match req {
        BgpRequest::GetEvpnRoutesPage { after, limit } => BgpEvent::EvpnRoutesPage {
            routes: vec![EvpnRouteSummary {
                peer,
                route_type: 2,
                route: after.as_ref().map_or("first", |_| "second").into(),
                next_hop: peer,
                extended_communities: vec![limit.to_string()],
                local_pref: 0,
                communities: vec![0xFFFF_0000],
            }],
            next: after.is_none().then(|| EvpnRouteCursor {
                peer,
                route: "first".into(),
            }),
        },
        BgpRequest::GetFlowspecRoutesPage { after, .. } => BgpEvent::FlowspecRoutesPage {
            routes: vec![FlowspecRouteSummary {
                peer,
                nlri: after.as_ref().map_or("first", |_| "second").into(),
                extended_communities: vec![],
                validity: "valid".into(),
                actions: vec![],
                dataplane: None,
            }],
            next: after.is_none().then(|| FlowspecRouteCursor {
                peer,
                family: "ipv4-flowspec".into(),
                nlri: "first".into(),
            }),
        },
        _ => BgpEvent::PeerNotFound,
    });
    let f = fixture(vec![(ServiceRef::BgpInstance("r1".into()), bgpd)]).await;
    let app = &f.app;
    send(app, Method::POST, "/v1/transactions/v1?base=current", None).await;
    send(
        app,
        Method::PUT,
        "/v1/transactions/v1/bgp-instance/r1",
        Some(bgp_instance("r1", 1)),
    )
    .await;
    send(app, Method::POST, "/v1/transactions/v1/commit", None).await;

    for (path, field) in [("evpn", "route"), ("flowspec", "nlri")] {
        // No parameters: the first page of every instance, with a next.
        let (s, v) = send(app, Method::GET, &format!("/v1/bgp/{path}"), None).await;
        assert_eq!(s, StatusCode::OK);
        let r = &v[0]["result"];
        assert_eq!(r["items"][0][field], json!("first"), "{path}");
        let next = r["pagination"]["next"].as_str().unwrap().to_string();
        assert_eq!(r["pagination"]["limit"], json!(1000));
        assert!(!next.contains(['/', '.', ':']), "opaque, URL-safe: {next}");
        let (_, v) = send(
            app,
            Method::GET,
            &format!("/v1/bgp/{path}?instance=r1&limit=5&after={next}"),
            None,
        )
        .await;
        let r = &v[0]["result"];
        assert_eq!(r["items"][0][field], json!("second"), "{path}");
        assert_eq!(r["pagination"], json!({"limit": 5, "next": null}));
        for bad in [
            format!("/v1/bgp/{path}?limit=2"),
            format!("/v1/bgp/{path}?instance=r1&after=nope"),
        ] {
            let (s, _) = send(app, Method::GET, &bad, None).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
        }
        let (s, _) = send(
            app,
            Method::GET,
            &format!("/v1/bgp/{path}?instance=zz"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
}

/// `n` IPv4 /24 static routes from `10.<base>.0.0`, as the config's JSON.
fn static_routes(base: u32, n: u32) -> Vec<Value> {
    (0..n)
        .map(|i| {
            json!({
                "subnet": format!("10.{}.{}.0/24", base + i / 256, i % 256),
                "gateway": "192.0.2.1",
                "bfd": null,
            })
        })
        .collect()
}

/// Many routes go in as whole-subsection PUTs (#754): 20k in one list PUT, then
/// the same count as four instances of 5k. A list PUT replaces the list, and a
/// body past axum's 2 MiB default is refused with 413, not truncated.
#[tokio::test]
async fn a_large_list_goes_in_as_one_subsection_put() {
    let f = fixture(vec![]).await;
    let app = &f.app;
    let tx = "/v1/transactions/big";
    assert_eq!(
        send(app, Method::POST, &format!("{tx}?base=blank"), None)
            .await
            .0,
        StatusCode::CREATED
    );

    // The instance first, then every route of its list in one request.
    let (s, _) = send(
        app,
        Method::PUT,
        &format!("{tx}/static-routing-instance/s1"),
        Some(json!({"name": "s1", "routes": []})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = send(
        app,
        Method::PUT,
        &format!("{tx}/static-routing-instance/s1/route"),
        Some(Value::Array(static_routes(0, 20_000))),
    )
    .await;
    assert_eq!(
        (s, v.as_array().map(Vec::len)),
        (StatusCode::OK, Some(20_000))
    );

    // A second PUT of the list replaces it, it does not append.
    let (s, v) = send(
        app,
        Method::PUT,
        &format!("{tx}/static-routing-instance/s1/route"),
        Some(Value::Array(static_routes(0, 3))),
    )
    .await;
    assert_eq!((s, v.as_array().map(Vec::len)), (StatusCode::OK, Some(3)));

    // The split structure: four instances (a list each) of 5k routes.
    for (i, base) in [0u32, 30, 60, 90].into_iter().enumerate() {
        let name = format!("part{i}");
        let (s, _) = send(
            app,
            Method::PUT,
            &format!("{tx}/static-routing-instance/{name}"),
            Some(json!({"name": name, "routes": static_routes(base, 5_000)})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{name}");
    }
    let (_, whole) = send(app, Method::GET, tx, None).await;
    let counts: Vec<_> = whole["config"]["static_routing_instances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["routes"].as_array().unwrap().len())
        .collect();
    assert_eq!(counts, [3, 5_000, 5_000, 5_000, 5_000]);

    // Past the 2 MiB body limit the list is refused whole.
    let (s, _) = send(
        app,
        Method::PUT,
        &format!("{tx}/static-routing-instance/s1/route"),
        Some(Value::Array(static_routes(0, 40_000))),
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    let (_, v) = send(
        app,
        Method::GET,
        &format!("{tx}/static-routing-instance/s1/route"),
        None,
    )
    .await;
    assert_eq!(v.as_array().map(Vec::len), Some(3));
}

/// #755: authentication probes `UserExists`; it never fetches the config
/// (`Request::Get`), and an unreachable `nos-configd` fails closed (503).
#[tokio::test]
async fn client_auth_probes_user_exists_and_never_fetches_the_config() {
    use nos_proto::{Event, Request};
    as_restd();
    let dir = tempfile::tempdir().unwrap();
    let (config_socket, watchdog_socket) = (dir.path().join("c.sock"), dir.path().join("w.sock"));
    let (gets, probes) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (g, p) = (gets.clone(), probes.clone());
    serve(
        &config_socket,
        ("configd", ""),
        move |req: Request| match req {
            Request::UserExists { name } => {
                p.fetch_add(1, Ordering::SeqCst);
                Event::UserExists(name == USER)
            }
            Request::Get => {
                g.fetch_add(1, Ordering::SeqCst);
                Event::Error("no".into())
            }
            _ => Event::Error("unsupported".into()),
        },
    );
    serve(&watchdog_socket, ("watchdog", ""), |_: WatchdogRequest| {
        WatchdogEvent::Ok
    });
    let app = api::router(Daemons::new(watchdog_socket, config_socket));

    for _ in 0..5 {
        let (s, _) = send(&app, Method::GET, "/openapi.json", None).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (s, _) = send_as(&app, Method::GET, "/openapi.json", None, Some("mallory")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        gets.load(Ordering::SeqCst),
        0,
        "auth must not fetch the config"
    );
    assert_eq!(probes.load(Ordering::SeqCst), 6);

    // configd unreachable: fail closed.
    let dir2 = tempfile::tempdir().unwrap();
    let watchdog = dir2.path().join("w.sock");
    serve(&watchdog, ("watchdog", ""), |_: WatchdogRequest| {
        WatchdogEvent::Ok
    });
    let app = api::router(Daemons::new(watchdog, dir2.path().join("missing.sock")));
    let (s, _) = send(&app, Method::GET, "/openapi.json", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

/// #759: the show routes list instances with `ListBgpInstances` /
/// `ListOspfInstances` / `ListOspfv3Instances`, and the listener reads its
/// table with `GetRestApi`; none of them sends `Request::Get`.
#[tokio::test]
async fn show_routes_and_listener_never_fetch_the_config() {
    use nos_proto::{Event, Request};
    as_restd();
    let dir = tempfile::tempdir().unwrap();
    let (config_socket, watchdog_socket) = (dir.path().join("c.sock"), dir.path().join("w.sock"));
    let (gets, lists, apis) = (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    );
    let (g, l, a) = (gets.clone(), lists.clone(), apis.clone());
    serve(
        &config_socket,
        ("configd", ""),
        move |req: Request| match req {
            Request::UserExists { name } => Event::UserExists(name == USER),
            Request::ListBgpInstances
            | Request::ListOspfInstances
            | Request::ListOspfv3Instances => {
                l.fetch_add(1, Ordering::SeqCst);
                Event::InstanceNames(vec![])
            }
            Request::GetRestApi { .. } => {
                a.fetch_add(1, Ordering::SeqCst);
                Event::RestApi(None)
            }
            Request::Get => {
                g.fetch_add(1, Ordering::SeqCst);
                Event::Error("no".into())
            }
            _ => Event::Error("unsupported".into()),
        },
    );
    serve(&watchdog_socket, ("watchdog", ""), |_: WatchdogRequest| {
        WatchdogEvent::Ok
    });
    let daemons = Daemons::new(watchdog_socket, config_socket);
    let app = api::router(daemons.clone());
    for uri in [
        "/v1/bgp/summary",
        "/v1/bgp/rpki",
        "/v1/bgp/evpn",
        "/v1/ospf/neighbors",
        "/v1/ospf/database",
        "/v1/ospfv3/neighbors",
        "/v1/ospfv3/database",
    ] {
        let (s, _) = send(&app, Method::GET, uri, None).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
    }
    assert_eq!(lists.load(Ordering::SeqCst), 7);
    assert_eq!(daemons.rest_api("rt1").await.unwrap(), None);
    assert_eq!(apis.load(Ordering::SeqCst), 1);
    assert_eq!(gets.load(Ordering::SeqCst), 0, "no Request::Get");
}
