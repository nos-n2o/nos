//! Transaction endpoints. The config tree is the URL tree: `/v1/transactions/<tx>`
//! is the whole in-progress config, and everything below it is a subsection
//! addressed by `nos_proto::config_path` (e.g.
//! `/v1/transactions/t1/bgp-instance/r1/peer-group/pg1`).
//!
//! Handlers take the raw `Uri` and split its path themselves, so a key that
//! contains an encoded `/` (a static route's subnet, `10.1.0.0%2F16`) stays one
//! segment — decoding only happens per segment, after the split.

use crate::auth::PeerUser;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use nos_proto::config_path::{self, ListPosition};
use nos_proto::{
    redact_at, Config, ConfigDiff, Event, Request, TransactionBase, TransactionSnapshot,
};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use serde_json::{json, Value};

use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::ipc::{unexpected, Daemons};

const PREFIX: &str = "/v1/transactions/";

#[derive(serde::Serialize, ToSchema)]
pub struct CommitResult {
    committed: String,
    /// Non-blocking advice about the committed config; `[]` when none.
    warnings: Vec<String>,
}

/// `(transaction name, config path segments)` from the request URI.
fn split(uri: &Uri) -> ApiResult<(String, Vec<String>)> {
    let rest = uri
        .path()
        .strip_prefix(PREFIX)
        .ok_or_else(|| ApiError::BadRequest("not a transaction path".to_string()))?;
    let mut segs = rest.split('/').filter(|s| !s.is_empty()).map(|s| {
        percent_decode_str(s)
            .decode_utf8()
            .map(std::borrow::Cow::into_owned)
            .map_err(|_| ApiError::BadRequest(format!("path segment '{s}' is not UTF-8")))
    });
    let tx = segs
        .next()
        .ok_or_else(|| ApiError::BadRequest("missing transaction name".to_string()))??;
    Ok((tx, segs.collect::<ApiResult<_>>()?))
}

/// The list position a PUT asks for: at most one of `?first`, `?last`,
/// `?before=<k>`, `?after=<k>` (values percent-decoded).
fn position(uri: &Uri) -> ApiResult<Option<ListPosition>> {
    let mut found = None;
    for pair in uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
    {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let anchor = || {
            let v = percent_decode_str(&v.replace('+', " "))
                .decode_utf8()
                .map_err(|_| ApiError::BadRequest(format!("'{k}' is not UTF-8")))?
                .into_owned();
            if v.is_empty() {
                return Err(ApiError::BadRequest(format!("'{k}' needs a list key")));
            }
            Ok(v)
        };
        let p = match (k, v) {
            ("first", "") => ListPosition::First,
            ("last", "") => ListPosition::Last,
            ("before", _) => ListPosition::Before(anchor()?),
            ("after", _) => ListPosition::After(anchor()?),
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "unknown query parameter '{k}': use first, last, before=<key> or after=<key>"
                )))
            }
        };
        if found.replace(p).is_some() {
            return Err(ApiError::BadRequest(
                "give at most one of first, last, before, after".to_string(),
            ));
        }
    }
    Ok(found)
}

fn snapshot(ev: Event) -> ApiResult<TransactionSnapshot> {
    match ev {
        Event::Transaction(s) => Ok(s),
        other => Err(unexpected("nos-configd", &other)),
    }
}

/// The subsection of `snap`'s config at `path` (the whole config for an empty path).
fn subsection(snap: &TransactionSnapshot, path: &[String]) -> ApiResult<Value> {
    config_path::get(&snap.config.redacted(), path)
        .cloned()
        .map_err(|e| match e {
            config_path::PathError::Invalid(m) => ApiError::Conflict(m),
            e @ config_path::PathError::NotFound(_) => ApiError::NotFound(e.to_string()),
        })
}

/// The snapshot as JSON with its config redacted: secrets never leave as clear text.
fn redacted_snapshot(snap: &TransactionSnapshot) -> Value {
    let mut v = json!(snap);
    v["config"] = snap.config.redacted();
    v
}

#[derive(Deserialize)]
pub struct OpenQuery {
    base: Option<String>,
}

/// The transaction's `ETag` (RFC 9110 §8.8.3): its generation as a strong,
/// quoted decimal — every edit is a real content change, never `W/`.
fn etag(generation: u64) -> (HeaderName, HeaderValue) {
    (
        header::ETAG,
        HeaderValue::from_str(&format!("\"{generation}\"")).expect("digits are valid"),
    )
}

/// One entity-tag of an `If-Match`/`If-None-Match` list (RFC 9110 §8.8.3).
#[derive(Debug, PartialEq, Eq)]
struct Tag {
    weak: bool,
    /// `None` for a well-formed tag that is not a generation (opaque): valid
    /// syntax, never equal to ours.
    generation: Option<u64>,
}

/// A parsed `If-Match`/`If-None-Match` (RFC 9110 §13.1.1/§13.1.2).
#[derive(Debug, PartialEq, Eq)]
enum Condition {
    /// `*` — any current representation.
    Any,
    /// `1#entity-tag`.
    Tags(Vec<Tag>),
}

/// The entity-tag list `s` (OWS around commas; a comma is legal inside a
/// quoted tag, so quotes are scanned, not split on).
fn parse_tags(mut s: &str) -> Option<Vec<Tag>> {
    let mut tags = Vec::new();
    loop {
        s = s.trim_start_matches([' ', '\t']);
        let (weak, rest) = match s.strip_prefix("W/") {
            Some(r) => (true, r),
            None => (false, s),
        };
        let body = rest.strip_prefix('"')?;
        let end = body.find('"')?;
        let inner = &body[..end];
        let generation = (!inner.is_empty() && inner.bytes().all(|b| b.is_ascii_digit()))
            .then(|| inner.parse().ok())
            .flatten();
        tags.push(Tag { weak, generation });
        s = body[end + 1..].trim_start_matches([' ', '\t']);
        match s.strip_prefix(',') {
            Some(r) => s = r,
            None if s.is_empty() => return Some(tags),
            None => return None,
        }
    }
}

impl Condition {
    /// The header (all its lines, joined as a list), if sent. Malformed
    /// syntax is a 400; a well-formed tag that never matches is not.
    fn from_header(headers: &HeaderMap, name: &HeaderName) -> ApiResult<Option<Self>> {
        let lines = headers.get_all(name);
        if lines.iter().next().is_none() {
            return Ok(None);
        }
        let bad = || ApiError::BadRequest(format!("{name} must be * or a list of quoted ETags"));
        let joined = lines
            .iter()
            .map(|v| v.to_str().map_err(|_| bad()))
            .collect::<ApiResult<Vec<_>>>()?
            .join(",");
        if joined.trim() == "*" {
            return Ok(Some(Condition::Any));
        }
        parse_tags(&joined)
            .map(|t| Some(Condition::Tags(t)))
            .ok_or_else(bad)
    }

    /// `strong`: `If-Match` (a weak tag never matches); otherwise the weak
    /// comparison of `If-None-Match`.
    fn matches(&self, generation: u64, strong: bool) -> bool {
        match self {
            Condition::Any => true,
            Condition::Tags(tags) => tags
                .iter()
                .any(|t| (!strong || !t.weak) && t.generation == Some(generation)),
        }
    }
}

/// `If-Match` as the store's `if_match` (`*` is no store-side precondition:
/// the transaction's existence is checked there), plus whether the header was
/// sent at all — any `If-Match` on a missing transaction is a 412, see
/// [`missing_tx`].
fn if_match(headers: &HeaderMap) -> ApiResult<(Option<Vec<u64>>, bool)> {
    Ok(match Condition::from_header(headers, &header::IF_MATCH)? {
        Some(Condition::Tags(tags)) => (
            Some(
                tags.iter()
                    .filter(|t| !t.weak)
                    .filter_map(|t| t.generation)
                    .collect(),
            ),
            true,
        ),
        Some(Condition::Any) => (None, true),
        None => (None, false),
    })
}

/// RFC 9110 §13.1.1: `If-Match` fails when there is no current representation,
/// so "no such transaction" under a sent `If-Match` is 412, not 404 (a missing
/// config path inside an existing transaction stays 404).
fn missing_tx<T>(r: ApiResult<T>, if_match_sent: bool) -> ApiResult<T> {
    match r {
        Err(ApiError::NotFound(m)) if if_match_sent && m.starts_with("no transaction named") => {
            Err(ApiError::PreconditionFailed(m))
        }
        r => r,
    }
}

/// `POST /v1/transactions/<tx>?base=blank|current` — open, or resume if it exists.
#[utoipa::path(post, path = "/v1/transactions/{tx}", tag = "transactions", summary = "Open (or resume) a transaction", params(("tx" = String, Path, description = "transaction name"), ("base" = Option<String>, Query, description = "blank | current (default current)")), responses((status = 201, body = TransactionSnapshot, description = "created; `ETag` is the transaction's generation"), (status = 200, body = TransactionSnapshot, description = "resumed; `ETag` is the transaction's generation"), (status = 400, body = ErrorBody)))]
pub async fn open(
    State(d): State<Daemons>,
    Extension(PeerUser(actor, _)): Extension<PeerUser>,
    uri: Uri,
    Query(q): Query<OpenQuery>,
) -> ApiResult<Response> {
    let (name, path) = split(&uri)?;
    if !path.is_empty() {
        return Err(ApiError::BadRequest(
            "POST opens a transaction; use PUT to set a subsection".to_string(),
        ));
    }
    let base = match q.base.as_deref() {
        None | Some("current") => TransactionBase::Current,
        Some("blank") => TransactionBase::Blank,
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "base must be 'blank' or 'current', not '{other}'"
            )))
        }
    };
    let snap = snapshot(
        d.config(Request::OpenTransaction { name, base, actor })
            .await?,
    )?;
    let status = if snap.resumed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status,
        [etag(snap.generation)],
        Json(redacted_snapshot(&snap)),
    )
        .into_response())
}

/// `GET /v1/transactions/<tx>[/<path>]` — the transaction, or one subsection of it.
/// `If-Match` (strong) gives `412` on a mismatch, then `If-None-Match` (weak)
/// against the transaction's `ETag` gives `304` on a match.
#[utoipa::path(get, path = "/v1/transactions/{tx}", tag = "transactions", summary = "The whole in-progress config", params(("tx" = String, Path, description = "transaction name"), ("If-Match" = Option<String>, Header, description = "RFC 9110 §13.1.1: `*` or a list of `ETag`s (strong comparison); 412 unless one matches, or if the transaction does not exist"), ("If-None-Match" = Option<String>, Header, description = "RFC 9110 §13.1.2: `*` or a list of `ETag`s (weak comparison); 304 if one still matches")), responses((status = 200, body = TransactionSnapshot, description = "`ETag` is the transaction's generation"), (status = 304, description = "If-None-Match matched the transaction's current generation"), (status = 404, body = ErrorBody, description = "no such transaction or config path"), (status = 412, body = ErrorBody, description = "If-Match did not match, or the transaction does not exist")))]
pub async fn get(State(d): State<Daemons>, uri: Uri, headers: HeaderMap) -> ApiResult<Response> {
    let (name, path) = split(&uri)?;
    let if_match = Condition::from_header(&headers, &header::IF_MATCH)?;
    let snap = snapshot(missing_tx(
        d.config(Request::GetTransaction { name }).await,
        if_match.is_some(),
    )?)?;
    // RFC 9110 §13.2.2: If-Match is evaluated before If-None-Match.
    if if_match.is_some_and(|c| !c.matches(snap.generation, true)) {
        return Err(ApiError::PreconditionFailed(format!(
            "precondition failed: transaction generation is {}",
            snap.generation
        )));
    }
    let value = if path.is_empty() {
        redacted_snapshot(&snap)
    } else {
        subsection(&snap, &path)?
    };
    let tag = etag(snap.generation);
    if Condition::from_header(&headers, &header::IF_NONE_MATCH)?
        .is_some_and(|c| c.matches(snap.generation, false))
    {
        // RFC 9110 §15.4.5: no body on a 304.
        return Ok((StatusCode::NOT_MODIFIED, [tag]).into_response());
    }
    Ok(([tag], Json(value)).into_response())
}

/// `PUT /v1/transactions/<tx>[/<path>]` — set the whole config, or one
/// subsection (creating a list element that doesn't exist yet). Replies with
/// the stored value.
#[utoipa::path(put, path = "/v1/transactions/{tx}", tag = "transactions", summary = "Set the whole config (or one subsection)", description = "Also the way to push many items in few requests: `PUT /v1/transactions/{tx}/{path}` takes a whole subsection or list. A list PUT REPLACES the list, so one PUT must carry every element of that list; the body is limited to 2 MiB (about 25-30k IPv4 static routes), larger gets 413. Split a bigger set across several lists (e.g. several static routing instances).", params(("tx" = String, Path, description = "transaction name"), ("If-Match" = Option<String>, Header, description = "RFC 9110 §13.1.1: `*` or a list of `ETag`s (strong comparison); refused (412) unless one still matches, or if the transaction does not exist")), request_body = Config, responses((status = 200, body = TransactionSnapshot, description = "`ETag` is the transaction's new generation"), (status = 400, body = ErrorBody), (status = 422, body = ErrorBody, description = "semantic refusal: a `<hidden>` secret with no earlier value, or too many clear-text passwords in one edit"), (status = 404, body = ErrorBody, description = "no such transaction or config path"), (status = 412, body = ErrorBody, description = "If-Match did not match the transaction's current generation"), (status = 413, body = ErrorBody, description = "body over 2 MiB: split the list across several lists")))]
pub async fn put(
    State(d): State<Daemons>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let (name, path) = split(&uri)?;
    let (if_match, sent) = if_match(&headers)?;
    let position = position(&uri)?;
    let value = String::from_utf8(body.to_vec())
        .map_err(|_| ApiError::BadRequest("body is not UTF-8".to_string()))?;
    let (generation, dirty, value) = path_edit(missing_tx(
        d.config(Request::EditTransactionPath {
            name: name.clone(),
            path: path.clone(),
            value: Some(value),
            if_match,
            position,
        })
        .await,
        sent,
    )?)?;
    let mut value: Value = serde_json::from_str(value.as_deref().unwrap_or("null"))
        .map_err(|_| ApiError::BadGateway("nos-configd sent a malformed subsection".into()))?;
    redact_at(&mut value, &path);
    if path.is_empty() {
        // The whole-config PUT keeps its `TransactionSnapshot` reply.
        value = json!({
            "name": name,
            "config": value,
            "dirty": dirty,
            "resumed": true,
            "generation": generation,
        });
    }
    Ok(([etag(generation)], Json(value)).into_response())
}

/// `(generation, dirty, subsection JSON)` of an `EditTransactionPath` reply.
fn path_edit(ev: Event) -> ApiResult<(u64, bool, Option<String>)> {
    match ev {
        Event::TransactionEdit {
            generation,
            dirty,
            value,
        } => Ok((generation, dirty, value)),
        other => Err(unexpected("nos-configd", &other)),
    }
}

/// `DELETE /v1/transactions/<tx>` discards the transaction;
/// `DELETE /v1/transactions/<tx>/<path>` removes that subsection (the reply's
/// `ETag` is the transaction's new generation).
#[utoipa::path(delete, path = "/v1/transactions/{tx}", tag = "transactions", summary = "Discard the transaction", params(("tx" = String, Path, description = "transaction name"), ("If-Match" = Option<String>, Header, description = "RFC 9110 §13.1.1: `*` or a list of `ETag`s (strong comparison); refused (412) unless one still matches, or if the transaction does not exist")), responses((status = 204), (status = 404, body = ErrorBody, description = "no such transaction or config path"), (status = 412, body = ErrorBody, description = "If-Match did not match the transaction's current generation")))]
pub async fn delete(State(d): State<Daemons>, uri: Uri, headers: HeaderMap) -> ApiResult<Response> {
    let (name, path) = split(&uri)?;
    let (if_match, sent) = if_match(&headers)?;
    if path.is_empty() {
        match missing_tx(
            d.config(Request::DiscardTransaction { name, if_match })
                .await,
            sent,
        )? {
            Event::Discarded => Ok(StatusCode::NO_CONTENT.into_response()),
            other => Err(unexpected("nos-configd", &other)),
        }
    } else {
        let (generation, ..) = path_edit(missing_tx(
            d.config(Request::EditTransactionPath {
                name,
                path,
                value: None,
                if_match,
                position: None,
            })
            .await,
            sent,
        )?)?;
        Ok((StatusCode::NO_CONTENT, [etag(generation)]).into_response())
    }
}

/// `GET /v1/transactions/<tx>/diff` — what a commit would change.
#[utoipa::path(get, path = "/v1/transactions/{tx}/diff", tag = "transactions", summary = "What a commit would change", params(("tx" = String, Path, description = "transaction name")), responses((status = 200, body = ConfigDiff), (status = 404, body = ErrorBody, description = "no such transaction or config path")))]
pub async fn diff(State(d): State<Daemons>, uri: Uri) -> ApiResult<Json<ConfigDiff>> {
    let (name, _) = split(&uri)?;
    match d.config(Request::DiffTransaction { name }).await? {
        Event::Diff(diff) => Ok(Json(diff)),
        other => Err(unexpected("nos-configd", &other)),
    }
}

/// `POST /v1/transactions/<tx>/commit` — validate and promote to running.
/// On a validation error (or a failed `If-Match`) the transaction stays open.
#[utoipa::path(post, path = "/v1/transactions/{tx}/commit", tag = "transactions", summary = "Validate and commit", params(("tx" = String, Path, description = "transaction name"), ("If-Match" = Option<String>, Header, description = "RFC 9110 §13.1.1: `*` or a list of `ETag`s (strong comparison); refused (412) unless one still matches, or if the transaction does not exist")), responses((status = 200, body = CommitResult), (status = 422, body = ErrorBody, description = "validation failed, or the commit would remove every user or carry an invalid syslog trust-anchor; the transaction stays open"), (status = 404, body = ErrorBody, description = "no such transaction or config path"), (status = 412, body = ErrorBody, description = "If-Match did not match the transaction's current generation; the transaction stays open")))]
pub async fn commit(
    State(d): State<Daemons>,
    Extension(PeerUser(actor, _)): Extension<PeerUser>,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let (name, _) = split(&uri)?;
    let (if_match, sent) = if_match(&headers)?;
    match missing_tx(
        d.config(Request::CommitTransaction {
            actor,
            name: name.clone(),
            if_match,
        })
        .await,
        sent,
    )? {
        Event::Committed { warnings } => Ok(Json(json!(CommitResult {
            committed: name,
            warnings
        }))),
        other => Err(unexpected("nos-configd", &other)),
    }
}

/// `POST /v1/config/save` — persist the running config to disk, like the
/// CLI's `save`. A commit is live but not persisted until this is called.
#[utoipa::path(post, path = "/v1/config/save", tag = "transactions", summary = "Save the running config to disk", responses((status = 204, description = "the running config was written to disk"), (status = 502, body = ErrorBody, description = "nos-configd has no config file, or could not write it")))]
pub async fn save(State(d): State<Daemons>) -> ApiResult<StatusCode> {
    match d.config(Request::Save).await {
        Ok(Event::Saved) => Ok(StatusCode::NO_CONTENT),
        Ok(other) => Err(unexpected("nos-configd", &other)),
        // A failed save is nos-configd's fault (no --config-file, or a disk
        // error), not the client's: `from_config` would make it a 400.
        Err(ApiError::BadRequest(m)) => Err(ApiError::BadGateway(m)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(name: HeaderName, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).unwrap());
        h
    }

    fn snap_with_secret() -> TransactionSnapshot {
        let mut config = nos_proto::Config::default();
        config.admin.keys.push(nos_proto::AdminKey {
            label: "k1".into(),
            secret: "needle-secret".into(),
        });
        TransactionSnapshot {
            name: "t".into(),
            config,
            dirty: true,
            resumed: false,
            generation: 4,
        }
    }

    #[test]
    fn snapshot_and_subsections_never_carry_a_secret() {
        let snap = snap_with_secret();
        let whole = redacted_snapshot(&snap);
        assert_eq!(whole["generation"], 4);
        assert_eq!(whole["config"]["admin"]["keys"][0]["secret"], "<hidden>");
        assert!(!whole.to_string().contains("needle-secret"));
        for path in [vec!["admin"], vec!["admin", "key", "k1"]] {
            let path: Vec<String> = path.into_iter().map(String::from).collect();
            let v = subsection(&snap, &path).unwrap();
            assert!(!v.to_string().contains("needle-secret"), "{path:?}");
        }
        let v = subsection(&snap, &["admin".into(), "key".into(), "k1".into()]).unwrap();
        assert_eq!(v["label"], "k1");
        assert_eq!(v["secret"], "<hidden>");
    }

    #[test]
    fn commit_result_always_carries_warnings() {
        let r = |warnings: Vec<String>| {
            serde_json::to_value(CommitResult {
                committed: "t".into(),
                warnings,
            })
            .unwrap()
        };
        assert_eq!(r(vec![]), json!({"committed": "t", "warnings": []}));
        assert_eq!(r(vec!["w".into()])["warnings"], json!(["w"]));
    }

    #[test]
    fn conditions_parse_lists_weak_and_opaque_tags() {
        let parse = |name: HeaderName, raw: &str| {
            Condition::from_header(&headers(name.clone(), raw), &name)
        };
        let h = HeaderMap::new();
        assert_eq!(Condition::from_header(&h, &header::IF_MATCH).unwrap(), None);
        assert_eq!(
            parse(header::IF_MATCH, " * ").unwrap(),
            Some(Condition::Any)
        );
        let t = |weak, generation| Tag { weak, generation };
        assert_eq!(
            parse(header::IF_MATCH, "\"17\" , W/\"3\",\"abc\", \"a,b\"").unwrap(),
            Some(Condition::Tags(vec![
                t(false, Some(17)),
                t(true, Some(3)),
                t(false, None),
                t(false, None)
            ]))
        );
        for raw in ["17", "\"1", "W/3", "\"1\",", "\"1\" \"2\"", "", "*, \"1\""] {
            assert!(
                matches!(parse(header::IF_MATCH, raw), Err(ApiError::BadRequest(_))),
                "{raw}"
            );
        }

        // Strong (If-Match) never matches a weak tag; weak (If-None-Match) does.
        let c = parse(header::IF_MATCH, "W/\"3\", \"4\", \"x\"")
            .unwrap()
            .unwrap();
        assert!(!c.matches(3, true) && c.matches(3, false));
        assert!(c.matches(4, true) && !c.matches(5, false));

        // Several header lines are one list.
        let mut h = headers(header::IF_MATCH, "\"1\"");
        h.append(header::IF_MATCH, HeaderValue::from_static("\"2\""));
        assert_eq!(if_match(&h).unwrap(), (Some(vec![1, 2]), true));

        assert_eq!(if_match(&HeaderMap::new()).unwrap(), (None, false));
        assert_eq!(
            if_match(&headers(header::IF_MATCH, "*")).unwrap(),
            (None, true)
        );
        // Weak and opaque tags can never match: an empty list, not "unconditional".
        assert_eq!(
            if_match(&headers(header::IF_MATCH, "W/\"3\", \"abc\"")).unwrap(),
            (Some(vec![]), true)
        );
        assert_eq!(etag(3).1, "\"3\"");
    }

    #[test]
    fn missing_transaction_is_412_only_under_if_match() {
        let nf = || -> ApiResult<()> { Err(ApiError::NotFound("no transaction named 'x'".into())) };
        assert!(matches!(
            missing_tx(nf(), true),
            Err(ApiError::PreconditionFailed(_))
        ));
        assert!(matches!(
            missing_tx(nf(), false),
            Err(ApiError::NotFound(_))
        ));
        let path: ApiResult<()> = Err(ApiError::NotFound(
            "config path: no such config path".into(),
        ));
        assert!(matches!(missing_tx(path, true), Err(ApiError::NotFound(_))));
    }
}
