use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// Every failure a handler can report, rendered as an RFC 9457 problem document.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    /// No valid client certificate, or a login that failed.
    Unauthorized(String),
    NotFound(String),
    /// A list key selector matches several elements and none exactly.
    Conflict(String),
    /// RFC 6585 §4: too many failed logins; try again in `retry_after_secs`.
    TooManyRequests {
        detail: String,
        retry_after_secs: u64,
    },
    /// RFC 9110 §13.1.1: the request's `If-Match` no longer matches the
    /// transaction's current `ETag`; nothing was changed.
    PreconditionFailed(String),
    /// Well-formed request the config rejected (commit-time validation).
    Unprocessable(String),
    /// A daemon this endpoint needs isn't reachable right now.
    Unavailable(String),
    /// A daemon answered with something this endpoint can't interpret.
    BadGateway(String),
    /// The request (handler plus body read) outlived `api::REQUEST_TIMEOUT`.
    RequestTimeout,
    /// A daemon accepted the request and never answered (`ipc::IPC_TIMEOUT`).
    GatewayTimeout(String),
}

impl ApiError {
    /// Maps an `Event::Error` message from `nos-configd` onto a status. The
    /// daemon sends plain strings, so this keys on the stable prefixes of
    /// `nos-config`'s `ConfigError` messages.
    pub fn from_config(msg: String) -> Self {
        if msg.starts_with("no transaction named")
            || msg.starts_with("config path: no such config path")
        {
            ApiError::NotFound(msg)
        } else if msg.starts_with(&format!(
            "config path: {}",
            nos_proto::config_path::AMBIGUOUS_KEY_PREFIX
        )) {
            ApiError::Conflict(msg)
        } else if msg.starts_with("validation failed") {
            ApiError::Unprocessable(msg)
        } else if msg.starts_with("too many transactions") {
            ApiError::TooManyRequests {
                detail: msg,
                retry_after_secs: 60,
            }
        } else if msg.starts_with("precondition failed") {
            ApiError::PreconditionFailed(msg)
        } else {
            ApiError::BadRequest(msg)
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized(m) => {
                // RFC 9110 §15.5.2: a 401 MUST carry a challenge. The scheme is
                // a client certificate, so this names the flow that gets one.
                let mut resp = problem(StatusCode::UNAUTHORIZED, m);
                resp.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(r#"Mutual realm="nos", login="/v1/login""#),
                );
                return resp;
            }
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::TooManyRequests {
                detail,
                retry_after_secs,
            } => {
                let mut resp = problem(StatusCode::TOO_MANY_REQUESTS, detail);
                resp.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
                return resp;
            }
            ApiError::PreconditionFailed(m) => (StatusCode::PRECONDITION_FAILED, m),
            ApiError::Unprocessable(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            // 502/503 strings can carry socket paths or daemon replies: log
            // them, never send them (#408).
            ApiError::Unavailable(m) => {
                tracing::warn!(detail = %m, "503 to client");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "a backend daemon is unavailable".to_string(),
                )
            }
            ApiError::BadGateway(m) => {
                tracing::warn!(detail = %m, "502 to client");
                (
                    StatusCode::BAD_GATEWAY,
                    "a backend daemon returned an unexpected reply".to_string(),
                )
            }
            ApiError::RequestTimeout => (
                StatusCode::REQUEST_TIMEOUT,
                "the request took too long".to_string(),
            ),
            ApiError::GatewayTimeout(m) => {
                tracing::warn!(detail = %m, "504 to client");
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    "a backend daemon did not answer in time".to_string(),
                )
            }
        };
        problem(status, msg)
    }
}

fn problem(status: StatusCode, detail: String) -> Response {
    let body = ErrorBody {
        type_: "about:blank".to_string(),
        title: status.canonical_reason().unwrap_or("Error").to_string(),
        status: status.as_u16(),
        detail,
    };
    (
        status,
        [(header::CONTENT_TYPE, PROBLEM_JSON)],
        serde_json::to_vec(&body).unwrap_or_default(),
    )
        .into_response()
}

/// Outermost layer: errors the framework produces itself (unknown route 404,
/// 405, a malformed path/query/JSON body rejected by an extractor) are bare
/// or plain text; re-render them as problem documents. Anything already a
/// problem, and every non-error response (incl. the SSE stream), passes through.
pub async fn problem_for_framework_errors(resp: Response) -> Response {
    let is_error = resp.status().is_client_error() || resp.status().is_server_error();
    let is_problem = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v == PROBLEM_JSON);
    if !is_error || is_problem {
        return resp;
    }
    let status = resp.status();
    // RFC 9110 §15.5.6: axum's 405 carries `Allow`; keep it.
    let allow = resp.headers().get(header::ALLOW).cloned();
    // Framework messages are one short line; cap the read anyway.
    let bytes = axum::body::to_bytes(resp.into_body(), 4096)
        .await
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).trim().to_string();
    let detail = if text.is_empty() {
        status.canonical_reason().unwrap_or("Error").to_string()
    } else {
        text
    };
    let mut out = problem(status, detail);
    if let Some(allow) = allow {
        out.headers_mut().insert(header::ALLOW, allow);
    }
    out
}

/// Hardening headers on every response; a CSP on the bundled Swagger UI only.
pub async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let swagger = req.uri().path().starts_with("/swagger-ui");
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if swagger {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
            ),
        );
    }
    resp
}

/// Media type of every error response (RFC 9457).
pub const PROBLEM_JSON: &str = "application/problem+json";

/// The body of every error response: an RFC 9457 problem document.
/// `instance` is omitted (optional in the RFC; a handler can't see the URI).
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    /// Always `about:blank`: the status code alone says what kind of problem it is.
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub type_: String,
    /// The HTTP status' reason phrase.
    pub title: String,
    pub status: u16,
    /// What went wrong, for this request.
    pub detail: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    async fn body(e: ApiError) -> (u16, String) {
        let r = e.into_response();
        let st = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        (st, String::from_utf8(b.to_vec()).unwrap())
    }

    #[test]
    fn ambiguous_key_is_409() {
        let e = nos_config::error::ConfigError::from(
            nos_proto::config_path::select_key(
                &["pga", "pg-a"],
                "PGA",
                |e: &&str, b: &mut String| b.push_str(e),
            )
            .unwrap_err(),
        );
        assert!(matches!(
            ApiError::from_config(e.to_string()),
            ApiError::Conflict(_)
        ));
    }

    #[test]
    fn transaction_cap_is_429() {
        let e = ApiError::from_config("too many transactions: 32 are open".into());
        assert!(matches!(e, ApiError::TooManyRequests { .. }));
    }

    #[test]
    fn semantic_refusals_are_422() {
        for e in [
            nos_config::error::ConfigError::NoUsersLeft,
            nos_config::error::ConfigError::MaskedSecret("user 'u'".into()),
            nos_config::error::ConfigError::TooManyClearPasswords(4),
        ] {
            assert!(matches!(
                ApiError::from_config(e.to_string()),
                ApiError::Unprocessable(_)
            ));
        }
    }

    #[tokio::test]
    async fn backend_errors_are_generic() {
        let (s, b) = body(ApiError::Unavailable(
            "cannot reach daemon at /run/nos/watchdog.sock: x".into(),
        ))
        .await;
        assert_eq!(s, 503);
        assert!(!b.contains("/run/") && !b.contains(".sock") && !b.contains("cannot reach"));
        let (s, b) = body(ApiError::BadGateway("x sent Config { users: [] }".into())).await;
        assert_eq!(s, 502);
        assert!(!b.contains("Config"));
    }
}
