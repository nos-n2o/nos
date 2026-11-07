use std::net::IpAddr;
use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{
    BgpEvent, BgpRequest, EvpnRouteSummary, FlowspecRouteSummary, IpcCodec, PeerSummary, Role,
};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum BgpClientError {
    #[error("could not connect to nos-bgpd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-bgpd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-bgpd: {0}")]
    Io(#[from] std::io::Error),
    #[error("unexpected reply from nos-bgpd: {0:?}")]
    UnexpectedReply(BgpEvent),
    #[error("nos-bgpd: {0}")]
    Daemon(String),
    #[error("route page cursor did not advance")]
    CursorStuck,
}

async fn connect(
    bgp_socket: &Path,
) -> Result<
    (
        FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<BgpEvent>>,
        FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<BgpRequest>>,
    ),
    BgpClientError,
> {
    let stream = nos_pki::connect_role(bgp_socket, Role::Bgpd)
        .await
        .map_err(|source| BgpClientError::Connect {
            path: bgp_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    Ok((
        FramedRead::new(r, IpcCodec::<BgpEvent>::default()),
        FramedWrite::new(w, IpcCodec::<BgpRequest>::default()),
    ))
}

/// Fetches every configured peer's current session summary.
pub async fn get_summary(bgp_socket: &Path) -> Result<Vec<PeerSummary>, BgpClientError> {
    let (mut reader, mut writer) = connect(bgp_socket).await?;
    writer.send(BgpRequest::GetSummary).await?;
    match reader.next().await {
        Some(Ok(BgpEvent::Summary(peers))) => Ok(peers),
        Some(Ok(other)) => Err(BgpClientError::UnexpectedReply(other)),
        Some(Err(e)) => Err(BgpClientError::Io(e)),
        None => Err(BgpClientError::ConnectionClosed),
    }
}

/// Walks a paged query page by page over one connection (the daemon keeps
/// its key snapshot per connection), handing each page to `on_page` as it
/// arrives so nothing holds the whole table. `ask` builds the request for an
/// `after` cursor, `split` takes a reply apart (`Err`: not this query's
/// reply). A cursor that does not advance is an error, never a loop.
async fn walk<C: Ord + Clone, T>(
    bgp_socket: &Path,
    ask: impl Fn(Option<C>) -> BgpRequest,
    split: impl Fn(BgpEvent) -> Result<(Vec<T>, Option<C>), BgpEvent>,
    mut on_page: impl FnMut(&[T]),
) -> Result<(), BgpClientError> {
    let (mut reader, mut writer) = connect(bgp_socket).await?;
    let mut after: Option<C> = None;
    loop {
        writer.send(ask(after.clone())).await?;
        let reply = match reader.next().await {
            Some(Ok(BgpEvent::Error(msg))) => return Err(BgpClientError::Daemon(msg)),
            Some(Ok(reply)) => reply,
            Some(Err(e)) => return Err(BgpClientError::Io(e)),
            None => return Err(BgpClientError::ConnectionClosed),
        };
        let (rows, next) = split(reply).map_err(BgpClientError::UnexpectedReply)?;
        on_page(&rows);
        match next {
            None => return Ok(()),
            Some(n) if after.as_ref().is_some_and(|a| &n <= a) => {
                return Err(BgpClientError::CursorStuck);
            }
            Some(n) => after = Some(n),
        }
    }
}

/// Walks the instance's received EVPN routes (`show bgp evpn`).
pub async fn for_each_evpn_routes_page(
    bgp_socket: &Path,
    on_page: impl FnMut(&[EvpnRouteSummary]),
) -> Result<(), BgpClientError> {
    walk(
        bgp_socket,
        |after| BgpRequest::GetEvpnRoutesPage {
            after,
            limit: nos_proto::BGP_PAGE_MAX,
        },
        |e| match e {
            BgpEvent::EvpnRoutesPage { routes, next } => Ok((routes, next)),
            other => Err(other),
        },
        on_page,
    )
    .await
}

/// Walks the instance's received Flowspec rules (`show bgp flowspec`).
pub async fn for_each_flowspec_routes_page(
    bgp_socket: &Path,
    on_page: impl FnMut(&[FlowspecRouteSummary]),
) -> Result<(), BgpClientError> {
    walk(
        bgp_socket,
        |after| BgpRequest::GetFlowspecRoutesPage {
            after,
            limit: nos_proto::BGP_PAGE_MAX,
        },
        |e| match e {
            BgpEvent::FlowspecRoutesPage { routes, next } => Ok((routes, next)),
            other => Err(other),
        },
        on_page,
    )
    .await
}

/// Walks the instance's received VPN paths of `family`, only those of Route
/// Distinguisher `rd` when set (`show bgp vpnv4|vpnv6 [rd <rd>]`).
pub async fn for_each_vpn_routes_page(
    bgp_socket: &Path,
    family: nos_proto::AddressFamily,
    rd: Option<&str>,
    on_page: impl FnMut(&[nos_proto::VpnRouteSummary]),
) -> Result<(), BgpClientError> {
    walk(
        bgp_socket,
        |after| BgpRequest::GetVpnRoutesPage {
            family,
            rd: rd.map(str::to_string),
            after,
            limit: nos_proto::BGP_PAGE_MAX,
        },
        |e| match e {
            BgpEvent::VpnRoutesPage { routes, next } => Ok((routes, next)),
            other => Err(other),
        },
        on_page,
    )
    .await
}

/// Walks the instance's unicast routes (`show bgp routes`).
pub async fn for_each_routes_page(
    bgp_socket: &Path,
    on_page: impl FnMut(&[nos_proto::BgpRouteSummary]),
) -> Result<(), BgpClientError> {
    walk(
        bgp_socket,
        |after| BgpRequest::GetRoutesPage {
            after,
            limit: nos_proto::BGP_PAGE_MAX,
        },
        |e| match e {
            BgpEvent::RoutesPage { routes, next } => Ok((routes, next)),
            other => Err(other),
        },
        on_page,
    )
    .await
}

/// Every configured BMP station's status.
pub async fn get_bmp_status(
    bgp_socket: &Path,
) -> Result<Vec<nos_proto::BmpStationStatus>, BgpClientError> {
    let (mut reader, mut writer) = connect(bgp_socket).await?;
    writer.send(BgpRequest::ShowBmp).await?;
    match reader.next().await {
        Some(Ok(BgpEvent::BmpStatus(stations))) => Ok(stations),
        Some(Ok(other)) => Err(BgpClientError::UnexpectedReply(other)),
        Some(Err(e)) => Err(BgpClientError::Io(e)),
        None => Err(BgpClientError::ConnectionClosed),
    }
}

/// Every configured RPKI cache's RTR session.
pub async fn get_rpki_summary(
    bgp_socket: &Path,
) -> Result<Vec<nos_proto::RpkiCacheStatus>, BgpClientError> {
    let (mut reader, mut writer) = connect(bgp_socket).await?;
    writer.send(BgpRequest::GetRpkiSummary).await?;
    match reader.next().await {
        Some(Ok(BgpEvent::RpkiSummary(caches))) => Ok(caches),
        Some(Ok(other)) => Err(BgpClientError::UnexpectedReply(other)),
        Some(Err(e)) => Err(BgpClientError::Io(e)),
        None => Err(BgpClientError::ConnectionClosed),
    }
}

/// `clear bgp <instance> <peer>`: releases `peer`'s maximum-prefix hold and
/// resets its session. `Ok(false)` if `peer` isn't configured.
pub async fn clear_peer(bgp_socket: &Path, peer: IpAddr) -> Result<bool, BgpClientError> {
    let (mut reader, mut writer) = connect(bgp_socket).await?;
    writer.send(BgpRequest::ClearPeer { peer }).await?;
    match reader.next().await {
        Some(Ok(BgpEvent::PeerCleared)) => Ok(true),
        Some(Ok(BgpEvent::PeerNotFound)) => Ok(false),
        Some(Ok(other)) => Err(BgpClientError::UnexpectedReply(other)),
        Some(Err(e)) => Err(BgpClientError::Io(e)),
        None => Err(BgpClientError::ConnectionClosed),
    }
}

/// What `clear bgp ... soft-in` did.
#[derive(Debug, PartialEq, Eq)]
pub enum SoftIn {
    /// An RFC 2918 `ROUTE_REFRESH` was delivered to the live session.
    RefreshSent,
    /// The peer-group keeps its received routes: the import policy was
    /// re-evaluated locally (per-family counts), nothing was sent.
    Reevaluated(Vec<nos_proto::FamilyReeval>),
    /// Peer not configured, or no `Established` session.
    NotFound,
}

/// Re-evaluates `peer`'s import policy over its retained routes, or else asks
/// its live session to send an RFC 2918 `ROUTE_REFRESH`.
pub async fn send_route_refresh(bgp_socket: &Path, peer: IpAddr) -> Result<SoftIn, BgpClientError> {
    let (mut reader, mut writer) = connect(bgp_socket).await?;
    writer.send(BgpRequest::SendRouteRefresh { peer }).await?;
    match reader.next().await {
        Some(Ok(BgpEvent::RouteRefreshSent)) => Ok(SoftIn::RefreshSent),
        Some(Ok(BgpEvent::SoftInReevaluated { families })) => Ok(SoftIn::Reevaluated(families)),
        Some(Ok(BgpEvent::PeerNotFound)) => Ok(SoftIn::NotFound),
        Some(Ok(other)) => Err(BgpClientError::UnexpectedReply(other)),
        Some(Err(e)) => Err(BgpClientError::Io(e)),
        None => Err(BgpClientError::ConnectionClosed),
    }
}
