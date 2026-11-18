//! RESTCONF (RFC 8040) facade over the running config (#1176, part of #1173).
//!
//! JSON only, running datastore only, no YANG-patch. The data tree is the
//! generated `nos-config` YANG module (`docs/yang/nos-config.yang`): its
//! top-level nodes are the fields of `Config`, so `/restconf/data/nos-config:
//! bgp_instances=r1/peer=10.0.0.1` maps onto the `nos_proto::config_path`
//! segments `["bgp_instances","r1","peer","10.0.0.1"]` and inherits its
//! resolution and validation. `nos-config:config` is an alias for the whole
//! config. A write is one implicit transaction (open, edit, commit); the
//! datastore `ETag` is a hash of the running config, checked against
//! `If-Match` on the transaction's base.
//!
//! Errors reuse `ApiError`; [`errors_as_yang_data`] re-renders its problem
//! documents as the `ietf-restconf` `errors` body.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, MethodRouter};
use axum::{Extension, Router};
use nos_proto::config_path::{self, PathError};
use nos_proto::{Event, Request, TransactionBase};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use serde_json::{json, Value};

use crate::auth::PeerUser;
use crate::error::{ApiError, ApiResult, PROBLEM_JSON};
use crate::ipc::{unexpected, Daemons};
use crate::merge_patch;
use crate::tx::{etag, Condition};

/// RFC 8040 §5.2 media type; the only representation served.
pub const YANG_DATA: &str = "application/yang-data+json";
const MODULE: &str = "nos-config";
const DATA: &str = "/restconf/data";
const YANG_LIBRARY_VERSION: &str = "2019-01-04";
const YANG_TEXT: &str = include_str!("../../docs/yang/nos-config.yang");
/// What a key may not carry unescaped in a `Location` (RFC 8040 §3.5.3).
const KEY_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'/')
    .add(b'%')
    .add(b',')
    .add(b'=')
    .add(b'?')
    .add(b'#')
    .add(b'"')
    .add(b'<')
    .add(b'>');

/// A parsed `/restconf/data/...` target (RFC 8040 §3.5).
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    /// `config_path` segments (names and keys, decoded).
    pub segs: Vec<String>,
    /// The last node name (the body's expected key).
    pub name: String,
    /// The key of a response body (`module:node`).
    pub wrapper: String,
    /// The last node was a list entry (`name=key`): its body is a one-element array.
    pub is_entry: bool,
}

fn decode(s: &str) -> ApiResult<String> {
    percent_decode_str(s)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| ApiError::BadRequest(format!("path segment '{s}' is not UTF-8")))
}

/// Parses a request path. Segments split on `/` before percent-decoding, so a
/// key may carry `%2F`; a list entry is `name=key` (one key: every NOS list is
/// identified by one field).
///
/// # Errors
/// 400 for a foreign module, a missing module prefix on the first node, or a
/// key list that is not exactly one non-empty key.
pub fn parse_path(path: &str) -> ApiResult<Target> {
    let rest = path
        .strip_prefix(DATA)
        .ok_or_else(|| ApiError::BadRequest("not a RESTCONF data path".to_string()))?;
    let mut t = Target {
        segs: Vec::new(),
        name: "data".to_string(),
        wrapper: "ietf-restconf:data".to_string(),
        is_entry: false,
    };
    for (i, node) in rest.split('/').filter(|s| !s.is_empty()).enumerate() {
        let (name, keys) = match node.split_once('=') {
            Some((n, k)) => (n, Some(k)),
            None => (node, None),
        };
        let name = decode(name)?;
        let name = match name.split_once(':') {
            Some((m, n)) if m == MODULE => n.to_string(),
            Some((m, _)) => {
                return Err(ApiError::BadRequest(format!(
                    "unknown module '{m}': the only module is {MODULE}"
                )))
            }
            None if i == 0 => {
                return Err(ApiError::BadRequest(format!(
                    "the first node needs its module: {MODULE}:<node>"
                )))
            }
            None => name,
        };
        if name.is_empty() {
            return Err(ApiError::BadRequest("empty node name".to_string()));
        }
        t.wrapper = if i == 0 {
            format!("{MODULE}:{name}")
        } else {
            name.clone()
        };
        t.is_entry = keys.is_some();
        t.name.clone_from(&name);
        if i == 0 && name == "config" {
            if keys.is_some() {
                return Err(ApiError::BadRequest("config has no key".to_string()));
            }
            continue;
        }
        t.segs.push(name);
        if let Some(k) = keys {
            let keys = k.split(',').map(decode).collect::<ApiResult<Vec<_>>>()?;
            match keys.as_slice() {
                [k] if !k.is_empty() => t.segs.push(k.clone()),
                _ => {
                    return Err(ApiError::BadRequest(
                        "a list entry takes exactly one non-empty key".to_string(),
                    ))
                }
            }
        }
    }
    Ok(t)
}

// ---- datastore state ----------------------------------------------------

/// The datastore `ETag`: a hash of the config, as a quoted decimal (so the
/// `tx` conditional-request parser applies unchanged).
fn datastore_generation(config: &nos_proto::Config) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_string(config)
        .unwrap_or_default()
        .hash(&mut h);
    h.finish()
}

fn path_err(e: PathError) -> ApiError {
    match e {
        PathError::Invalid(m) => ApiError::Conflict(m),
        e @ PathError::NotFound(_) => ApiError::NotFound(e.to_string()),
    }
}

/// Exists and holds data (an unset optional or an empty list does not).
fn exists(root: &Value, path: &[String]) -> bool {
    match config_path::get(root, path) {
        Ok(v) => !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()),
        Err(_) => false,
    }
}

// ---- negotiation --------------------------------------------------------

fn media(v: &HeaderValue) -> String {
    v.to_str()
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// 406 unless the client accepts JSON (no `Accept` accepts anything).
fn negotiate(headers: &HeaderMap) -> ApiResult<()> {
    let lines: Vec<_> = headers.get_all(header::ACCEPT).iter().collect();
    if lines.is_empty() {
        return Ok(());
    }
    let ok = lines.iter().any(|l| {
        l.to_str().unwrap_or_default().split(',').any(|m| {
            let m = m
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            matches!(
                m.as_str(),
                "*/*" | "application/*" | YANG_DATA | "application/json"
            )
        })
    });
    ok.then_some(()).ok_or_else(|| {
        ApiError::NotAcceptable(format!("only {YANG_DATA} (or application/json) is served"))
    })
}

fn require_json_body(headers: &HeaderMap, patch: bool) -> ApiResult<()> {
    let t = headers
        .get(header::CONTENT_TYPE)
        .map_or_else(String::new, media);
    if t == YANG_DATA || t == "application/json" || (patch && t == "application/merge-patch+json") {
        Ok(())
    } else {
        Err(ApiError::UnsupportedMediaType(format!(
            "send Content-Type: {YANG_DATA}"
        )))
    }
}

/// `{"module:node": value}` → `(node, value)`.
fn unwrap_body(body: &[u8]) -> ApiResult<(String, Value)> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|e| ApiError::BadRequest(format!("body is not JSON: {e}")))?;
    let Value::Object(m) = v else {
        return Err(ApiError::BadRequest(
            "body must be an object with one member, \"module:node\"".to_string(),
        ));
    };
    let mut it = m.into_iter();
    match (it.next(), it.next()) {
        (Some((k, v)), None) => {
            let name = k.split_once(':').map_or(k.as_str(), |(_, n)| n).to_string();
            Ok((name, v))
        }
        _ => Err(ApiError::BadRequest(
            "body must hold exactly one member, \"module:node\"".to_string(),
        )),
    }
}

/// The body of a PUT/PATCH on `t`: its member must be the target node.
fn target_body(t: &Target, body: &[u8]) -> ApiResult<Value> {
    let (name, v) = unwrap_body(body)?;
    if name != t.name && !config_path::field_matches(&name, &t.name) {
        return Err(ApiError::BadRequest(format!(
            "body node '{name}' is not the target '{}'",
            t.name
        )));
    }
    one_entry(t.is_entry, v)
}

fn one_entry(is_entry: bool, v: Value) -> ApiResult<Value> {
    match (is_entry, v) {
        (true, Value::Array(mut a)) if a.len() == 1 => Ok(a.remove(0)),
        (true, Value::Array(_)) => Err(ApiError::BadRequest(
            "a list entry body holds exactly one entry".to_string(),
        )),
        (_, v) => Ok(v),
    }
}

// ---- reads ---------------------------------------------------------------

/// A `fields` selector (RFC 8040 §4.8.3): `a;b(c;d/e)`.
#[derive(Debug, PartialEq, Eq)]
struct Sel {
    name: String,
    sub: Vec<Sel>,
}

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

fn parse_sel(it: &mut Chars) -> Option<Sel> {
    let mut name = String::new();
    while let Some(&c) = it.peek() {
        if matches!(c, ';' | '(' | ')' | '/') {
            break;
        }
        name.push(c);
        it.next();
    }
    if name.is_empty() {
        return None;
    }
    let name = name
        .rsplit_once(':')
        .map_or(name.clone(), |(_, n)| n.to_string());
    let sub = match it.peek() {
        Some('(') => {
            it.next();
            let s = parse_sels(it)?;
            (it.next() == Some(')')).then_some(())?;
            s
        }
        Some('/') => {
            it.next();
            vec![parse_sel(it)?]
        }
        _ => Vec::new(),
    };
    Some(Sel { name, sub })
}

fn parse_sels(it: &mut Chars) -> Option<Vec<Sel>> {
    let mut out = vec![parse_sel(it)?];
    while it.peek() == Some(&';') {
        it.next();
        out.push(parse_sel(it)?);
    }
    Some(out)
}

fn select(v: &Value, sels: &[Sel]) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(|e| select(e, sels)).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .filter_map(|(k, val)| {
                    let s = sels
                        .iter()
                        .find(|s| *k == s.name || config_path::field_matches(k, &s.name))?;
                    let val = if s.sub.is_empty() {
                        val.clone()
                    } else {
                        select(val, &s.sub)
                    };
                    Some((k.clone(), val))
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `depth=n`: the target is level 1; a container or list at the last level
/// is returned empty (its children are level `n + 1`).
fn prune(v: Value, depth: usize) -> Value {
    match v {
        Value::Object(_) | Value::Array(_) if depth <= 1 => match v {
            Value::Object(_) => json!({}),
            _ => json!([]),
        },
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, c)| (k, prune(c, depth - 1)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(|c| prune(c, depth - 1)).collect()),
        other => other,
    }
}

struct Query {
    depth: Option<usize>,
    nonconfig: bool,
    fields: Option<Vec<Sel>>,
}

fn parse_query(q: Option<&str>) -> ApiResult<Query> {
    let mut out = Query {
        depth: None,
        nonconfig: false,
        fields: None,
    };
    for pair in q.unwrap_or_default().split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let bad = |what: &str| ApiError::BadRequest(format!("{k}: {what}"));
        let v = decode(&v.replace('+', " "))?;
        match k {
            "depth" if v == "unbounded" => out.depth = None,
            "depth" => {
                out.depth = Some(
                    v.parse::<usize>()
                        .ok()
                        .filter(|d| (1..=65535).contains(d))
                        .ok_or_else(|| bad("use 1-65535 or unbounded"))?,
                );
            }
            "content" => match v.as_str() {
                "config" | "all" => out.nonconfig = false,
                "nonconfig" => out.nonconfig = true,
                _ => return Err(bad("use config, nonconfig or all")),
            },
            "fields" => {
                let mut it = v.chars().peekable();
                let sels = parse_sels(&mut it).filter(|_| it.peek().is_none());
                out.fields = Some(sels.ok_or_else(|| bad("malformed selector"))?);
            }
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "unsupported query parameter '{k}': use depth, content or fields"
                )))
            }
        }
    }
    Ok(out)
}

fn yang_json(
    status: StatusCode,
    v: &Value,
    tag: Option<(header::HeaderName, HeaderValue)>,
) -> Response {
    let mut r = (status, [(header::CONTENT_TYPE, YANG_DATA)], v.to_string()).into_response();
    if let Some((n, v)) = tag {
        r.headers_mut().insert(n, v);
    }
    r
}

async fn read(State(d): State<Daemons>, uri: Uri, headers: HeaderMap) -> ApiResult<Response> {
    negotiate(&headers)?;
    let t = parse_path(uri.path())?;
    let q = parse_query(uri.query())?;
    let cfg = d.running_config().await?;
    let generation = datastore_generation(&cfg);
    if Condition::from_header(&headers, &header::IF_NONE_MATCH)?
        .is_some_and(|c| c.matches(generation, false))
    {
        return Ok((StatusCode::NOT_MODIFIED, [etag(generation)]).into_response());
    }
    let mut v = config_path::get(&cfg.redacted(), &t.segs)
        .map_err(path_err)?
        .clone();
    if q.nonconfig {
        // No operational state lives in this datastore.
        return Ok((StatusCode::NO_CONTENT, [etag(generation)]).into_response());
    }
    if let Some(f) = &q.fields {
        v = select(&v, f);
    }
    if let Some(n) = q.depth {
        v = prune(v, n);
    }
    if t.is_entry {
        v = Value::Array(vec![v]);
    }
    Ok(yang_json(
        StatusCode::OK,
        &json!({ t.wrapper.clone(): v }),
        Some(etag(generation)),
    ))
}

fn options() -> Response {
    (
        StatusCode::OK,
        [
            (
                header::ALLOW,
                "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE",
            ),
            (header::HeaderName::from_static("accept-patch"), YANG_DATA),
        ],
    )
        .into_response()
}

// ---- writes --------------------------------------------------------------

enum Op {
    /// POST: create the child in the body under the target.
    Create(Bytes),
    /// PUT: replace the target (creating it).
    Replace(Value),
    /// PATCH: merge into the existing target.
    Merge(Value),
    Delete,
}

struct Written {
    created: bool,
    location: Option<String>,
    generation: u64,
}

static NEXT_TX: AtomicU64 = AtomicU64::new(0);

/// Open, edit, commit; the transaction is discarded on any failure.
async fn write(
    d: &Daemons,
    actor: Option<String>,
    headers: &HeaderMap,
    uri: &Uri,
    t: &Target,
    op: Op,
) -> ApiResult<Written> {
    let condition = Condition::from_header(headers, &header::IF_MATCH)?;
    let name = format!(
        "restconf-{}-{}",
        std::process::id(),
        NEXT_TX.fetch_add(1, Ordering::Relaxed)
    );
    let snap = match d
        .config(Request::OpenTransaction {
            name: name.clone(),
            base: TransactionBase::Current,
            actor: actor.clone(),
        })
        .await?
    {
        Event::Transaction(s) => s,
        other => return Err(unexpected("nos-configd", &other)),
    };
    let r = edit_and_commit(d, actor, uri, t, op, &name, &snap, condition).await;
    if r.is_err() {
        let _ = d
            .config(Request::DiscardTransaction {
                name,
                if_match: None,
            })
            .await;
    }
    r
}

#[allow(clippy::too_many_arguments)]
async fn edit_and_commit(
    d: &Daemons,
    actor: Option<String>,
    uri: &Uri,
    t: &Target,
    op: Op,
    name: &str,
    snap: &nos_proto::TransactionSnapshot,
    condition: Option<Condition>,
) -> ApiResult<Written> {
    // The transaction was opened on the running config: its hash is the
    // datastore tag the client's `If-Match` was computed from.
    let base = datastore_generation(&snap.config);
    if condition.is_some_and(|c| !c.matches(base, true)) {
        return Err(ApiError::PreconditionFailed(format!(
            "precondition failed: datastore tag is {base}"
        )));
    }
    let root = serde_json::to_value(&snap.config)
        .map_err(|e| ApiError::BadGateway(format!("config not serializable: {e}")))?;
    let (path, value, created, location) = match op {
        Op::Replace(v) => {
            let had = exists(&root, &t.segs);
            (t.segs.clone(), Some(v), !had, None)
        }
        Op::Merge(delta) => {
            let cur = config_path::get(&root, &t.segs).map_err(path_err)?;
            if !exists(&root, &t.segs) {
                return Err(ApiError::NotFound(format!("no data at {}", uri.path())));
            }
            (
                t.segs.clone(),
                Some(merge_patch::apply(cur.clone(), delta)),
                false,
                None,
            )
        }
        Op::Delete => {
            if !exists(&root, &t.segs) {
                return Err(ApiError::NotFound(format!("no data at {}", uri.path())));
            }
            (t.segs.clone(), None, false, None)
        }
        Op::Create(body) => {
            if !exists(&root, &t.segs) {
                return Err(ApiError::NotFound(format!("no data at {}", uri.path())));
            }
            let (child, val) = unwrap_body(&body)?;
            let mut path = t.segs.clone();
            path.push(child.clone());
            let (val, node) = match val {
                Value::Array(mut items) if items.len() == 1 => {
                    let entry = items.remove(0);
                    let key = match &entry {
                        Value::Object(o) => config_path::key_field(o.keys().map(String::as_str))
                            .and_then(|k| scalar(&o[k])),
                        other => scalar(other),
                    }
                    .ok_or_else(|| ApiError::BadRequest("the entry has no key".to_string()))?;
                    path.push(key.clone());
                    let node = format!("{child}={}", utf8_percent_encode(&key, KEY_SET));
                    (entry, node)
                }
                Value::Array(_) => {
                    return Err(ApiError::BadRequest(
                        "POST creates one list entry at a time".to_string(),
                    ))
                }
                other => (other, child),
            };
            if exists(&root, &path) {
                return Err(ApiError::Conflict(format!(
                    "{} already exists",
                    path.join("/")
                )));
            }
            let module = if t.segs.is_empty() { "nos-config:" } else { "" };
            let loc = format!("{}/{module}{node}", uri.path().trim_end_matches('/'));
            (path, Some(val), true, Some(loc))
        }
    };
    match d
        .config(Request::EditTransactionPath {
            name: name.to_string(),
            path,
            value: value.map(|v| v.to_string()),
            if_match: None,
            position: None,
            actor: actor.clone(),
        })
        .await?
    {
        Event::TransactionEdit { .. } => {}
        other => return Err(unexpected("nos-configd", &other)),
    }
    match d
        .config(Request::CommitTransaction {
            actor,
            name: name.to_string(),
            if_match: None,
            confirm_timeout: None,
        })
        .await?
    {
        Event::Committed { .. } => {}
        other => return Err(unexpected("nos-configd", &other)),
    }
    let generation = datastore_generation(&d.running_config().await?);
    Ok(Written {
        created,
        location,
        generation,
    })
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

async fn modify(
    State(d): State<Daemons>,
    Extension(PeerUser(actor, _)): Extension<PeerUser>,
    uri: Uri,
    headers: HeaderMap,
    method: axum::http::Method,
    body: Bytes,
) -> ApiResult<Response> {
    negotiate(&headers)?;
    let t = parse_path(uri.path())?;
    let op = match method {
        axum::http::Method::DELETE => Op::Delete,
        axum::http::Method::POST => {
            require_json_body(&headers, false)?;
            Op::Create(body)
        }
        axum::http::Method::PUT => {
            require_json_body(&headers, false)?;
            Op::Replace(target_body(&t, &body)?)
        }
        _ => {
            require_json_body(&headers, true)?;
            Op::Merge(target_body(&t, &body)?)
        }
    };
    let w = write(&d, actor, &headers, &uri, &t, op).await?;
    let tag = etag(w.generation);
    let mut r = if w.created {
        StatusCode::CREATED.into_response()
    } else {
        StatusCode::NO_CONTENT.into_response()
    };
    r.headers_mut().insert(tag.0, tag.1);
    if let Some(l) = w.location {
        r.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&l)
                .map_err(|_| ApiError::BadRequest("location is not a header value".to_string()))?,
        );
    }
    Ok(r)
}

// ---- discovery -----------------------------------------------------------

async fn restconf_root() -> Response {
    yang_json(
        StatusCode::OK,
        &json!({"ietf-restconf:restconf": {
            "data": {},
            "yang-library-version": YANG_LIBRARY_VERSION,
        }}),
        None,
    )
}

async fn yang_library_version() -> Response {
    yang_json(
        StatusCode::OK,
        &json!({"ietf-restconf:yang-library-version": YANG_LIBRARY_VERSION}),
        None,
    )
}

/// RFC 8525 `ietf-yang-library` for the one module (and the type module it imports).
async fn yang_library() -> Response {
    let rev = nos_proto::yang::YANG_REVISION;
    yang_json(
        StatusCode::OK,
        &json!({"ietf-yang-library:yang-library": {
            "module-set": [{
                "name": "nos",
                "module": [{
                    "name": MODULE,
                    "revision": rev,
                    "namespace": "urn:nos:params:xml:ns:yang:nos-config",
                    "location": [format!("/restconf/yang/{MODULE}.yang")],
                }],
                "import-only-module": [{
                    "name": "ietf-inet-types",
                    "revision": "2013-07-15",
                    "namespace": "urn:ietf:params:xml:ns:yang:ietf-inet-types",
                }],
            }],
            "schema": [{"name": "nos", "module-set": ["nos"]}],
            "datastore": [{"name": "ietf-datastores:running", "schema": "nos"}],
            "content-id": rev,
        }}),
        None,
    )
}

/// The module source, as `nos-config.yang` or `nos-config@<revision>.yang`.
async fn yang_file(axum::extract::Path(file): axum::extract::Path<String>) -> ApiResult<Response> {
    let rev = format!("{MODULE}@{}.yang", nos_proto::yang::YANG_REVISION);
    if file != format!("{MODULE}.yang") && file != rev {
        return Err(ApiError::NotFound(format!("no YANG module file '{file}'")));
    }
    Ok(([(header::CONTENT_TYPE, "application/yang")], YANG_TEXT).into_response())
}

/// RFC 6415 / RFC 8040 §3.1.
async fn host_meta() -> Response {
    (
        [(header::CONTENT_TYPE, "application/xrd+xml")],
        "<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>\
         <Link rel='restconf' href='/restconf'/></XRD>",
    )
        .into_response()
}

// ---- errors --------------------------------------------------------------

/// `(error-type, error-tag)` of a status (RFC 8040 §7, RFC 6241 App. A).
fn error_tag(status: StatusCode) -> (&'static str, &'static str) {
    match status.as_u16() {
        400 | 406 | 415 => ("protocol", "invalid-value"),
        401 | 403 => ("protocol", "access-denied"),
        404 => ("application", "missing-element"),
        409 => ("application", "data-exists"),
        413 => ("protocol", "too-big"),
        429 => ("application", "resource-denied"),
        _ => ("application", "operation-failed"),
    }
}

/// Re-renders a problem document as the `ietf-restconf` `errors` body.
pub async fn errors_as_yang_data(resp: Response) -> Response {
    let status = resp.status();
    let is_problem = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v == PROBLEM_JSON);
    if !(status.is_client_error() || status.is_server_error()) || !is_problem {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .unwrap_or_default();
    let detail = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v["detail"].as_str().map(str::to_string))
        .unwrap_or_default();
    let (kind, tag) = error_tag(status);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts
        .headers
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(YANG_DATA));
    let body = json!({"ietf-restconf:errors": {"error": [{
        "error-type": kind,
        "error-tag": tag,
        "error-message": detail,
    }]}});
    Response::from_parts(parts, Body::from(body.to_string()))
}

fn data_methods() -> MethodRouter<Daemons> {
    get(read)
        .options(|| async { options() })
        .post(modify)
        .put(modify)
        .patch(modify)
        .delete(modify)
}

/// The `/restconf` and `/.well-known/host-meta` routes (behind `client_auth`
/// like every other route: the client certificate is the only credential).
pub fn routes() -> Router<Daemons> {
    Router::new()
        .route("/restconf", get(restconf_root))
        .route("/restconf/yang-library-version", get(yang_library_version))
        .route(
            "/restconf/data/ietf-yang-library:yang-library",
            get(yang_library),
        )
        .route("/restconf/yang/{file}", get(yang_file))
        .route("/restconf/data", data_methods())
        .route("/restconf/data/", data_methods())
        .route("/restconf/data/{*path}", data_methods())
        .route("/.well-known/host-meta", get(host_meta))
        .layer(axum::middleware::map_response(errors_as_yang_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segs(p: &str) -> Vec<String> {
        parse_path(p).unwrap().segs
    }

    #[test]
    fn paths_map_onto_config_path_segments() {
        assert_eq!(segs("/restconf/data"), Vec::<String>::new());
        assert_eq!(
            segs("/restconf/data/nos-config:config"),
            Vec::<String>::new()
        );
        assert_eq!(
            segs("/restconf/data/nos-config:config/bgp-instance=main/peer=10.0.0.1"),
            ["bgp-instance", "main", "peer", "10.0.0.1"]
        );
        // The raw path is split before decoding: %2F stays inside the key.
        assert_eq!(
            segs("/restconf/data/nos-config:static=a/route=10.1.0.0%2F16/"),
            ["static", "a", "route", "10.1.0.0/16"]
        );
        let t = parse_path("/restconf/data/nos-config:bgp_instances=r1").unwrap();
        assert_eq!(
            (t.wrapper.as_str(), t.name.as_str(), t.is_entry),
            ("nos-config:bgp_instances", "bgp_instances", true)
        );
        let t = parse_path("/restconf/data/nos-config:a/nos-config:b").unwrap();
        assert_eq!((t.wrapper.as_str(), t.segs.len()), ("b", 2));
        for bad in [
            "/restconf/data/bgp_instances",
            "/restconf/data/other:x",
            "/restconf/data/nos-config:x=a,b",
            "/restconf/data/nos-config:x=",
            "/restconf/data/nos-config:config=a",
            "/restconf/data/nos-config:x=%ff",
            "/other",
        ] {
            assert!(
                matches!(parse_path(bad), Err(ApiError::BadRequest(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn fields_and_depth() {
        let sels = |s: &str| {
            let mut it = s.chars().peekable();
            parse_sels(&mut it).filter(|_| it.peek().is_none())
        };
        assert!(sels("a;b(c;d/e)").is_some());
        for bad in ["", "a;", "a(b", "a)", "(a)"] {
            assert!(sels(bad).is_none(), "{bad}");
        }
        let v = json!({"a":1,"b":{"c":2,"d":{"e":3,"f":4}},"x":9});
        assert_eq!(
            select(&v, &sels("a;b(c;d/e)").unwrap()),
            json!({"a":1,"b":{"c":2,"d":{"e":3}}})
        );
        assert_eq!(prune(v.clone(), 1), json!({}));
        assert_eq!(prune(v, 2), json!({"a":1,"b":{},"x":9}));
        assert!(parse_query(Some("depth=0")).is_err());
        assert!(
            parse_query(Some("depth=2&content=nonconfig&fields=a"))
                .unwrap()
                .nonconfig
        );
        assert!(parse_query(Some("start-time=1")).is_err());
    }

    #[test]
    fn negotiation_and_tags() {
        let mut h = HeaderMap::new();
        assert!(negotiate(&h).is_ok());
        h.insert(
            header::ACCEPT,
            HeaderValue::from_static("text/html, application/yang-data+json;q=0.9"),
        );
        assert!(negotiate(&h).is_ok());
        h.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/yang-data+xml"),
        );
        assert!(matches!(negotiate(&h), Err(ApiError::NotAcceptable(_))));
        assert_eq!(
            error_tag(StatusCode::PRECONDITION_FAILED).1,
            "operation-failed"
        );
        assert_eq!(error_tag(StatusCode::CONFLICT).1, "data-exists");
        assert!(YANG_TEXT.starts_with("module nos-config"));
    }
}
