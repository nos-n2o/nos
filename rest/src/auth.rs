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
use nos_proto::{Actor, UserRole, WatchdogEvent, WatchdogRequest};
use utoipa::openapi::security::SecurityScheme;

use crate::error::ApiError;
use crate::ipc::Daemons;

pub const LOGIN_PATH: &str = "/v1/login";

/// The user named by the client certificate this request's connection
/// presented, and that certificate's hex serial; `None`s if it presented none.
/// Set per connection by the listener.
/// The third field is the role claim (#1360): what the certificate's SAN
/// carries when the listener builds it; `client_auth` replaces it with the
/// watchdog's server-side one (and refuses a mismatch), so a handler only
/// ever sees a verified claim.
#[derive(Clone, Debug)]
pub struct PeerUser(pub Option<String>, pub Option<String>, pub Option<UserRole>);

/// The `nos_proto::Actor` `nos-configd` is told about: the user, plus the
/// verified RADIUS role claim.
pub struct PeerActor(pub Option<Actor>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerActor {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(
            parts
                .extensions
                .get::<PeerUser>()
                .and_then(|p| p.0.clone().map(|name| Actor { name, claim: p.2 })),
        )))
    }
}

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
    let Some(PeerUser(Some(user), Some(serial), cert_claim)) =
        req.extensions().get::<PeerUser>().cloned()
    else {
        return unauthorized();
    };
    // The REST CA has no CRL: the watchdog knows which certificates are live
    // (a password change or user removal drops them) and the role RADIUS
    // granted that login (#1360).
    let claim = match daemons
        .broker(WatchdogRequest::RestCertCheck {
            user: user.clone(),
            serial: serial.clone(),
        })
        .await
    {
        Ok(WatchdogEvent::RestSessionLive { claim }) => claim,
        Ok(WatchdogEvent::Denied(_)) => return unauthorized(),
        Ok(other) => return crate::ipc::unexpected("nos-watchdogd", &other).into_response(),
        Err(e) => return e.into_response(),
    };
    // Both copies must agree (the certificate's SAN and the watchdog's
    // session): restd never asserts a role the certificate does not hold.
    if cert_claim != claim {
        tracing::warn!(user = ?user, "rest certificate role claim differs from the session's, refused");
        return unauthorized();
    }
    let mut req = req;
    match daemons.user_exists(&user).await {
        // A local user is decided locally: the claim is dropped.
        Ok(true) => {
            req.extensions_mut()
                .insert(PeerUser(Some(user.clone()), Some(serial), None));
        }
        // No local entry: only a claimed (RADIUS) session gets in.
        Ok(false) if claim.is_some() => {
            req.extensions_mut()
                .insert(PeerUser(Some(user.clone()), Some(serial), claim));
        }
        Ok(false) => return unauthorized(),
        Err(e) => return e.into_response(),
    }
    tracing::info!(user = ?user, method = %req.method(), path = %req.uri().path(), "rest request");
    next.run(req).await
}

fn unauthorized() -> Response {
    ApiError::Unauthorized("a client certificate is required (POST /v1/login to get one)".into())
        .into_response()
}
