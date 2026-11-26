use std::net::IpAddr;
use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_daemon::ipc::{self, IpcError};
use nos_proto::{
    IpcCodec, PrefixRoutes, RibEvent, RibRequest, RibSummary, Role, RouteFilter, ROUTES_PAGE_MAX,
};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum RibClientError {
    #[error("could not connect to nos-ribd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-ribd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-ribd: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-ribd reported an error: {0}")]
    Daemon(String),
}

async fn ask(rib_socket: &Path, req: RibRequest) -> Result<RibEvent, RibClientError> {
    ipc::request(rib_socket, Role::Ribd, req)
        .await
        .map_err(|e| match e {
            IpcError::Connect { path, source } => RibClientError::Connect { path, source },
            IpcError::Io(e) => RibClientError::Io(e),
            IpcError::Closed => RibClientError::ConnectionClosed,
            IpcError::Timeout(_) => RibClientError::Io(std::io::ErrorKind::TimedOut.into()),
        })
}

/// Walks the whole table page by page over one connection, handing each page
/// (prefixes ascending, each with its candidates best to worst) to `on_page`
/// as it arrives, so nothing holds the full table. The table may change
/// mid-walk (keyset paging, no snapshot); a cursor that does not advance is
/// an error, never a loop.
pub async fn for_each_routes_page(
    rib_socket: &Path,
    filter: RouteFilter,
    mut on_page: impl FnMut(&[PrefixRoutes]),
) -> Result<(), RibClientError> {
    let stream = nos_pki::connect_role(rib_socket, Role::Ribd)
        .await
        .map_err(|source| RibClientError::Connect {
            path: rib_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<RibEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<RibRequest>::default());
    let mut after = None;
    loop {
        writer
            .send(RibRequest::GetRoutesPage {
                after,
                limit: ROUTES_PAGE_MAX,
                filter: filter.clone(),
            })
            .await?;
        match reader.next().await {
            Some(Ok(RibEvent::RoutesPage { routes, next })) => {
                on_page(&routes);
                match next {
                    None => return Ok(()),
                    Some(n) if after.is_some_and(|a| n <= a) => {
                        return Err(RibClientError::Daemon(
                            "route page cursor did not advance".to_string(),
                        ));
                    }
                    Some(n) => after = Some(n),
                }
            }
            Some(Ok(RibEvent::Error(msg))) => return Err(RibClientError::Daemon(msg)),
            Some(Ok(_)) => {
                return Err(RibClientError::Daemon(
                    "unexpected event in reply to GetRoutesPage".to_string(),
                ));
            }
            Some(Err(e)) => return Err(RibClientError::Io(e)),
            None => return Err(RibClientError::ConnectionClosed),
        }
    }
}

/// The table's [`RibSummary`] (`GetSummary`, #1445).
pub async fn get_summary(rib_socket: &Path) -> Result<RibSummary, RibClientError> {
    match ask(rib_socket, RibRequest::GetSummary).await? {
        RibEvent::Summary(s) => Ok(s),
        RibEvent::Error(msg) => Err(RibClientError::Daemon(msg)),
        _ => Err(RibClientError::Daemon(
            "unexpected event in reply to GetSummary".to_string(),
        )),
    }
}

/// The table's VPN label (`None` without `vpn`, or from an older daemon
/// that does not know the request).
pub async fn get_vpn_label(rib_socket: &Path) -> Option<u32> {
    match ask(rib_socket, RibRequest::GetVpnLabel).await {
        Ok(RibEvent::VpnLabel(label)) => label,
        _ => None,
    }
}

/// Longest-prefix-match lookup for one destination address. `Ok(None)` means
/// no configured prefix covers `addr` (no default route).
pub async fn lookup(
    rib_socket: &Path,
    addr: IpAddr,
) -> Result<Option<PrefixRoutes>, RibClientError> {
    match ask(rib_socket, RibRequest::Lookup { addr }).await? {
        RibEvent::Match(routes) => Ok(Some(routes)),
        RibEvent::NoMatch => Ok(None),
        RibEvent::Error(msg) => Err(RibClientError::Daemon(msg)),
        _ => Err(RibClientError::Daemon(
            "unexpected event in reply to Lookup".to_string(),
        )),
    }
}
