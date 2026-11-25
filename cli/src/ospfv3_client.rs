use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{
    InstanceSummary, IpcCodec, Ospfv3Event, Ospfv3InterfaceSummary, Ospfv3LsaSummary,
    Ospfv3NeighborSummary, Ospfv3Request, Role,
};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum Ospfv3ClientError {
    #[error("could not connect to nos-ospfv3d at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-ospfv3d closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-ospfv3d: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-ospfv3d sent an unexpected reply: {0}")]
    UnexpectedReply(&'static str),
}

async fn connect(
    ospfv3_socket: &Path,
) -> Result<
    (
        FramedRead<tokio::io::ReadHalf<nos_pki::Stream>, IpcCodec<Ospfv3Event>>,
        FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<Ospfv3Request>>,
    ),
    Ospfv3ClientError,
> {
    let stream = nos_pki::connect_role(ospfv3_socket, Role::Ospfv3d)
        .await
        .map_err(|source| Ospfv3ClientError::Connect {
            path: ospfv3_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    Ok((
        FramedRead::new(r, IpcCodec::<Ospfv3Event>::default()),
        FramedWrite::new(w, IpcCodec::<Ospfv3Request>::default()),
    ))
}

/// Fetches every configured link's current neighbor summary.
pub async fn get_neighbors(
    ospfv3_socket: &Path,
) -> Result<Vec<Ospfv3NeighborSummary>, Ospfv3ClientError> {
    let (mut reader, mut writer) = connect(ospfv3_socket).await?;
    writer.send(Ospfv3Request::GetNeighbors).await?;
    match reader.next().await {
        Some(Ok(Ospfv3Event::Neighbors(neighbors))) => Ok(neighbors),
        Some(Ok(_)) => Err(Ospfv3ClientError::UnexpectedReply("reply to GetNeighbors")),
        Some(Err(e)) => Err(Ospfv3ClientError::Io(e)),
        None => Err(Ospfv3ClientError::ConnectionClosed),
    }
}

/// Fetches every running interface's summary (#1438).
pub async fn get_interfaces(
    ospfv3_socket: &Path,
) -> Result<Vec<Ospfv3InterfaceSummary>, Ospfv3ClientError> {
    let (mut reader, mut writer) = connect(ospfv3_socket).await?;
    writer.send(Ospfv3Request::GetInterfaces).await?;
    match reader.next().await {
        Some(Ok(Ospfv3Event::Interfaces(v))) => Ok(v),
        Some(Ok(_)) => Err(Ospfv3ClientError::UnexpectedReply("reply to GetInterfaces")),
        Some(Err(e)) => Err(Ospfv3ClientError::Io(e)),
        None => Err(Ospfv3ClientError::ConnectionClosed),
    }
}

/// Fetches every installed LSA's header, across every area.
pub async fn get_database(
    ospfv3_socket: &Path,
) -> Result<Vec<Ospfv3LsaSummary>, Ospfv3ClientError> {
    let (mut reader, mut writer) = connect(ospfv3_socket).await?;
    writer.send(Ospfv3Request::GetDatabase).await?;
    match reader.next().await {
        Some(Ok(Ospfv3Event::Database(entries))) => Ok(entries),
        Some(Ok(_)) => Err(Ospfv3ClientError::UnexpectedReply("reply to GetDatabase")),
        Some(Err(e)) => Err(Ospfv3ClientError::Io(e)),
        None => Err(Ospfv3ClientError::ConnectionClosed),
    }
}

/// Fetches the instance summary (#1439).
pub async fn get_instance(ospfv3_socket: &Path) -> Result<InstanceSummary, Ospfv3ClientError> {
    let (mut reader, mut writer) = connect(ospfv3_socket).await?;
    writer.send(Ospfv3Request::GetInstance).await?;
    match reader.next().await {
        Some(Ok(Ospfv3Event::Instance(i))) => Ok(i),
        Some(Ok(_)) => Err(Ospfv3ClientError::UnexpectedReply("reply to GetInstance")),
        Some(Err(e)) => Err(Ospfv3ClientError::Io(e)),
        None => Err(Ospfv3ClientError::ConnectionClosed),
    }
}
