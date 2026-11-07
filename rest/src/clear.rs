//! Operator actions — the `nos-cli` `clear` commands. Unlike `show` these
//! change live session state (never config), so they are `POST`s.

use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::Json;
use nos_proto::{BgpEvent, BgpRequest, ServiceRef, StpEvent, StpRequest};
use serde::Serialize;
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::ipc::{unexpected, Daemons};

#[derive(Serialize, ToSchema)]
pub struct SoftInResult {
    instance: String,
    #[schema(value_type = String)]
    peer: IpAddr,
    /// `"sent"`: a ROUTE-REFRESH was delivered to the live session. `"none"`:
    /// the peer-group keeps its received routes (soft reconfiguration
    /// inbound), so the import policy was re-evaluated locally and nothing
    /// was sent.
    route_refresh: &'static str,
    /// Per-family result of the local re-evaluation; absent when a
    /// ROUTE-REFRESH was sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    reevaluated: Option<Vec<FamilyReevaluated>>,
}

#[derive(Serialize, ToSchema)]
pub struct FamilyReevaluated {
    /// Kebab-case family, e.g. `ipv4-unicast`.
    family: String,
    /// Routes held before import policy.
    retained: u32,
    /// Of those, how many the import policy accepts.
    accepted: u32,
}

/// `clear bgp <instance> <peer> soft-in`: re-evaluate the import policy over
/// the routes kept by soft reconfiguration inbound, or else ask the peer's
/// live session to send a ROUTE-REFRESH (RFC 2918).
#[utoipa::path(
    post, path = "/v1/bgp/{instance}/peer/{peer}/soft-in", tag = "clear",
    summary = "Soft-reset a BGP peer inbound (ROUTE-REFRESH)",
    params(
        ("instance" = String, Path, description = "BGP instance name"),
        ("peer" = String, Path, description = "peer address")
    ),
    responses(
        (status = 200, body = SoftInResult),
        (status = 404, body = ErrorBody, description = "peer not configured, or no Established session with it"),
        (status = 503, body = ErrorBody, description = "that instance's nos-bgpd is not running, or the local re-evaluation was superseded or aborted")
    )
)]
pub async fn bgp_soft_in(
    State(d): State<Daemons>,
    Path((instance, peer)): Path<(String, IpAddr)>,
) -> ApiResult<Json<SoftInResult>> {
    match d
        .service(
            ServiceRef::BgpInstance(instance.clone()),
            BgpRequest::SendRouteRefresh { peer },
        )
        .await?
    {
        BgpEvent::RouteRefreshSent => Ok(Json(SoftInResult {
            instance,
            peer,
            route_refresh: "sent",
            reevaluated: None,
        })),
        BgpEvent::SoftInReevaluated { families } => Ok(Json(SoftInResult {
            instance,
            peer,
            route_refresh: "none",
            reevaluated: Some(
                families
                    .into_iter()
                    .map(|f| FamilyReevaluated {
                        family: f.family.to_string(),
                        retained: f.retained,
                        accepted: f.accepted,
                    })
                    .collect(),
            ),
        })),
        BgpEvent::Error(why) => Err(ApiError::Unavailable(why)),
        BgpEvent::PeerNotFound => Err(ApiError::NotFound(format!(
            "no Established session with {peer} in bgp instance '{instance}'"
        ))),
        other @ (BgpEvent::Summary(_)
        | BgpEvent::EvpnRoutes(_)
        | BgpEvent::FlowspecRoutes(_)
        | BgpEvent::VpnRoutes(_)
        | BgpEvent::PeerCleared
        | BgpEvent::Routes(_)
        | BgpEvent::RoutesPage { .. }
        | BgpEvent::EvpnRoutesPage { .. }
        | BgpEvent::FlowspecRoutesPage { .. }
        | BgpEvent::VpnRoutesPage { .. }
        | BgpEvent::RpkiSummary(_)
        | BgpEvent::BmpStatus(_)) => Err(unexpected("nos-bgpd", &other)),
    }
}

#[derive(Serialize, ToSchema)]
pub struct ClearPeerResult {
    instance: String,
    #[schema(value_type = String)]
    peer: IpAddr,
    /// Always `true`: any maximum-prefix hold is released, and an
    /// Established session was reset with Cease/Administrative Reset.
    cleared: bool,
}

/// `clear bgp <instance> <peer>`: release a peer held down by its
/// maximum-prefix limit (RFC 4486), and reset its session if one is up.
#[utoipa::path(
    post, path = "/v1/bgp/{instance}/peer/{peer}/clear", tag = "clear",
    summary = "Reset a BGP peer (and release a maximum-prefix hold)",
    params(
        ("instance" = String, Path, description = "BGP instance name"),
        ("peer" = String, Path, description = "peer address")
    ),
    responses(
        (status = 200, body = ClearPeerResult),
        (status = 404, body = ErrorBody, description = "peer not configured"),
        (status = 503, body = ErrorBody, description = "that instance's nos-bgpd is not running")
    )
)]
pub async fn bgp_clear_peer(
    State(d): State<Daemons>,
    Path((instance, peer)): Path<(String, IpAddr)>,
) -> ApiResult<Json<ClearPeerResult>> {
    match d
        .service(
            ServiceRef::BgpInstance(instance.clone()),
            BgpRequest::ClearPeer { peer },
        )
        .await?
    {
        BgpEvent::PeerCleared => Ok(Json(ClearPeerResult {
            instance,
            peer,
            cleared: true,
        })),
        BgpEvent::PeerNotFound => Err(ApiError::NotFound(format!(
            "no peer {peer} in bgp instance '{instance}'"
        ))),
        other @ (BgpEvent::Summary(_)
        | BgpEvent::EvpnRoutes(_)
        | BgpEvent::FlowspecRoutes(_)
        | BgpEvent::VpnRoutes(_)
        | BgpEvent::RouteRefreshSent
        | BgpEvent::SoftInReevaluated { .. }
        | BgpEvent::Error(_)
        | BgpEvent::Routes(_)
        | BgpEvent::RoutesPage { .. }
        | BgpEvent::EvpnRoutesPage { .. }
        | BgpEvent::FlowspecRoutesPage { .. }
        | BgpEvent::VpnRoutesPage { .. }
        | BgpEvent::RpkiSummary(_)
        | BgpEvent::BmpStatus(_)) => Err(unexpected("nos-bgpd", &other)),
    }
}

#[derive(Serialize, ToSchema)]
pub struct McheckResult {
    /// Ports that restarted protocol migration.
    ports: u32,
}

/// `clear spanning-tree detected-protocols`: 802.1Q `mcheck` on every port.
#[utoipa::path(
    post, path = "/v1/spanning-tree/mcheck", tag = "clear",
    summary = "Re-probe every spanning-tree port for RSTP (mcheck)",
    responses(
        (status = 200, body = McheckResult),
        (status = 503, body = ErrorBody, description = "nos-stpd is not running")
    )
)]
pub async fn stp_mcheck(State(d): State<Daemons>) -> ApiResult<Json<McheckResult>> {
    stp_mcheck_on(&d, None).await
}

/// `clear spanning-tree detected-protocols interface <name>`.
#[utoipa::path(
    post, path = "/v1/spanning-tree/port/{interface}/mcheck", tag = "clear",
    summary = "Re-probe one spanning-tree port for RSTP (mcheck)",
    params(("interface" = String, Path, description = "interface or port-aggregate name")),
    responses(
        (status = 200, body = McheckResult),
        (status = 404, body = ErrorBody, description = "not a spanning-tree port"),
        (status = 503, body = ErrorBody, description = "nos-stpd is not running")
    )
)]
pub async fn stp_mcheck_port(
    State(d): State<Daemons>,
    Path(interface): Path<String>,
) -> ApiResult<Json<McheckResult>> {
    stp_mcheck_on(&d, Some(interface)).await
}

async fn stp_mcheck_on(d: &Daemons, interface: Option<String>) -> ApiResult<Json<McheckResult>> {
    match d
        .service(
            ServiceRef::Stp,
            StpRequest::Mcheck {
                interface: interface.clone(),
            },
        )
        .await?
    {
        StpEvent::Mcheck { ports: 0 } if interface.is_some() => Err(ApiError::NotFound(format!(
            "{} is not a spanning-tree port",
            interface.unwrap_or_default()
        ))),
        StpEvent::Mcheck { ports } => Ok(Json(McheckResult { ports })),
        other @ (StpEvent::Summary(_) | StpEvent::ErrDisabledCleared { .. }) => {
            Err(unexpected("nos-stpd", &other))
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct ErrDisabledResult {
    /// The port was err-disabled and is being brought back up.
    cleared: bool,
}

/// `clear spanning-tree err-disabled <name>`.
#[utoipa::path(
    post, path = "/v1/spanning-tree/port/{interface}/err-disabled/clear", tag = "clear",
    summary = "Bring a port that BPDU guard shut down back up",
    params(("interface" = String, Path, description = "interface or port-aggregate name")),
    responses(
        (status = 200, body = ErrDisabledResult),
        (status = 404, body = ErrorBody, description = "not an err-disabled spanning-tree port"),
        (status = 503, body = ErrorBody, description = "nos-stpd is not running")
    )
)]
pub async fn stp_clear_err_disabled(
    State(d): State<Daemons>,
    Path(interface): Path<String>,
) -> ApiResult<Json<ErrDisabledResult>> {
    match d
        .service(
            ServiceRef::Stp,
            StpRequest::ClearErrDisabled {
                interface: interface.clone(),
            },
        )
        .await?
    {
        StpEvent::ErrDisabledCleared { cleared: true } => {
            Ok(Json(ErrDisabledResult { cleared: true }))
        }
        StpEvent::ErrDisabledCleared { cleared: false } => Err(ApiError::NotFound(format!(
            "{interface} is not err-disabled"
        ))),
        other @ (StpEvent::Summary(_) | StpEvent::Mcheck { .. }) => {
            Err(unexpected("nos-stpd", &other))
        }
    }
}
