//! Client-certificate authentication for every route (including `/openapi.json`,
//! `/swagger-ui/` and the SSE log stream). The TLS layer has already verified
//! the certificate against the REST CA; `PeerUser` is the user its URI SAN
//! names (`listen.rs` puts it on each connection's requests). Here the user
//! must also *still exist* in `Config.users` — probed per request with the
//! cheap `Request::UserExists` (no config transfer, #755) — so a deleted user is locked out
//! on the very next request rather than when their certificate expires.
//! The watchdog is asked too whether that very certificate is still live
//! (`RestCertCheck`): a password change revokes it. Fails closed: a request with no verified user is 401, and if `nos-configd`
//! can't be reached it is refused (503), never let through.
//!
//! The one exception is `POST /v1/login`, which is how a client with no
//! certificate yet gets one (`login.rs`).
//!
//! ponytail: one pooled `UserExists` round trip per request, no cache (a cache
//! would break "locked out on the very next request").

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use nos_proto::{WatchdogEvent, WatchdogRequest};
use utoipa::openapi::security::SecurityScheme;

use crate::error::ApiError;
use crate::ipc::Daemons;

pub const LOGIN_PATH: &str = "/v1/login";

/// The user named by the client certificate this request's connection
/// presented, and that certificate's hex serial; `None`s if it presented none.
/// Set per connection by the listener.
#[derive(Clone, Debug)]
pub struct PeerUser(pub Option<String>, pub Option<String>);

/// Declares the mutual-TLS scheme in the `OpenAPI` document — the global
/// `security` requirement is on `ApiDoc`.
pub struct MutualTlsScheme;

impl utoipa::Modify for MutualTlsScheme {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "mtls",
                SecurityScheme::MutualTls {
                    description: Some(
                        "A client certificate issued by POST /v1/login (or /v1/renew)".to_string(),
                    ),
                    deprecated: None,
                    extensions: None,
                },
            );
    }
}

pub async fn client_auth(State(daemons): State<Daemons>, req: Request, next: Next) -> Response {
    if req.method() == Method::POST && req.uri().path() == LOGIN_PATH {
        return next.run(req).await;
    }
    let (Some(user), Some(serial)) = req
        .extensions()
        .get::<PeerUser>()
        .map_or_default(|p| (p.0.clone(), p.1.clone()))
    else {
        return unauthorized();
    };
    // The REST CA has no CRL: the watchdog knows which certificates are live
    // (a password change or user removal drops them).
    match daemons
        .broker(WatchdogRequest::RestCertCheck {
            user: user.clone(),
            serial,
        })
        .await
    {
        Ok(WatchdogEvent::Ok) => {}
        Ok(WatchdogEvent::Denied(_)) => return unauthorized(),
        Ok(other) => return crate::ipc::unexpected("nos-watchdogd", &other).into_response(),
        Err(e) => return e.into_response(),
    }
    match daemons.user_exists(&user).await {
        Ok(true) => {
            tracing::info!(user = ?user, method = %req.method(), path = %req.uri().path(), "rest request");
            next.run(req).await
        }
        Ok(false) => unauthorized(),
        Err(e) => e.into_response(),
    }
}

fn unauthorized() -> Response {
    ApiError::Unauthorized("a client certificate is required (POST /v1/login to get one)".into())
        .into_response()
}
