use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{
    InterfaceSummary, IpcCodec, LsaSummary, NeighborSummary, OspfEvent, OspfRequest, Role,
    RouteSummary, SrSummary,
};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum OspfClientError {
    #[error("could not connect to nos-ospfd at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-ospfd closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-ospfd: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-ospfd sent an unexpected reply: {0}")]
    UnexpectedReply(&'static str),
}

async fn connect(
    ospf_socket: &Path,
) -> Result<
    (
        FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<OspfEvent>>,
        FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<OspfRequest>>,
    ),
    OspfClientError,
> {
    let stream = nos_pki::connect_role(ospf_socket, Role::Ospfd)
        .await
        .map_err(|source| OspfClientError::Connect {
            path: ospf_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    Ok((
        FramedRead::new(r, IpcCodec::<OspfEvent>::default()),
        FramedWrite::new(w, IpcCodec::<OspfRequest>::default()),
    ))
}

/// Fetches every configured link's current neighbor summary.
pub async fn get_neighbors(ospf_socket: &Path) -> Result<Vec<NeighborSummary>, OspfClientError> {
    let (mut reader, mut writer) = connect(ospf_socket).await?;
    writer.send(OspfRequest::GetNeighbors).await?;
    match reader.next().await {
        Some(Ok(OspfEvent::Neighbors(neighbors))) => Ok(neighbors),
        Some(Ok(_)) => Err(OspfClientError::UnexpectedReply("reply to GetNeighbors")),
        Some(Err(e)) => Err(OspfClientError::Io(e)),
        None => Err(OspfClientError::ConnectionClosed),
    }
}

/// Fetches every running interface's summary (#1438).
pub async fn get_interfaces(ospf_socket: &Path) -> Result<Vec<InterfaceSummary>, OspfClientError> {
    let (mut reader, mut writer) = connect(ospf_socket).await?;
    writer.send(OspfRequest::GetInterfaces).await?;
    match reader.next().await {
        Some(Ok(OspfEvent::Interfaces(v))) => Ok(v),
        Some(Ok(_)) => Err(OspfClientError::UnexpectedReply("reply to GetInterfaces")),
        Some(Err(e)) => Err(OspfClientError::Io(e)),
        None => Err(OspfClientError::ConnectionClosed),
    }
}

/// Fetches the computed routes (#1453).
pub async fn get_routes(ospf_socket: &Path) -> Result<Vec<RouteSummary>, OspfClientError> {
    let (mut reader, mut writer) = connect(ospf_socket).await?;
    writer.send(OspfRequest::GetRoutes).await?;
    match reader.next().await {
        Some(Ok(OspfEvent::Routes(v))) => Ok(v),
        Some(Ok(_)) => Err(OspfClientError::UnexpectedReply("reply to GetRoutes")),
        Some(Err(e)) => Err(OspfClientError::Io(e)),
        None => Err(OspfClientError::ConnectionClosed),
    }
}

/// Fetches every installed LSA's header, across every area.
pub async fn get_database(ospf_socket: &Path) -> Result<Vec<LsaSummary>, OspfClientError> {
    let (mut reader, mut writer) = connect(ospf_socket).await?;
    writer.send(OspfRequest::GetDatabase).await?;
    match reader.next().await {
        Some(Ok(OspfEvent::Database(entries))) => Ok(entries),
        Some(Ok(_)) => Err(OspfClientError::UnexpectedReply("reply to GetDatabase")),
        Some(Err(e)) => Err(OspfClientError::Io(e)),
        None => Err(OspfClientError::ConnectionClosed),
    }
}

/// Fetches the segment routing state (#1382).
pub async fn get_segment_routing(ospf_socket: &Path) -> Result<SrSummary, OspfClientError> {
    let (mut reader, mut writer) = connect(ospf_socket).await?;
    writer.send(OspfRequest::GetSegmentRouting).await?;
    match reader.next().await {
        Some(Ok(OspfEvent::SegmentRouting(sr))) => Ok(sr),
        Some(Ok(_)) => Err(OspfClientError::UnexpectedReply(
            "reply to GetSegmentRouting",
        )),
        Some(Err(e)) => Err(OspfClientError::Io(e)),
        None => Err(OspfClientError::ConnectionClosed),
    }
}
