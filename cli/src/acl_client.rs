use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use nos_proto::{AclEvent, AclRequest, AclStatus, FlowspecRuleStatus, IpcCodec, Role};
use thiserror::Error;
use tokio_util::codec::{FramedRead, FramedWrite};

#[derive(Debug, Error)]
pub enum AclClientError {
    #[error("could not connect to nos-acld at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("connection to nos-acld closed unexpectedly")]
    ConnectionClosed,
    #[error("i/o error talking to nos-acld: {0}")]
    Io(#[from] std::io::Error),
    #[error("nos-acld sent an unexpected reply")]
    Unexpected,
}

/// One request, one reply.
async fn ask(acl_socket: &Path, request: AclRequest) -> Result<AclEvent, AclClientError> {
    let stream = nos_pki::connect(acl_socket, Role::Acld, "")
        .await
        .map_err(|source| AclClientError::Connect {
            path: acl_socket.to_path_buf(),
            source,
        })?;
    let (r, w) = tokio::io::split(stream);
    let mut reader = FramedRead::new(r, IpcCodec::<AclEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<AclRequest>::default());
    writer.send(request).await?;
    match reader.next().await {
        Some(Ok(event)) => Ok(event),
        Some(Err(e)) => Err(AclClientError::Io(e)),
        None => Err(AclClientError::ConnectionClosed),
    }
}

/// Fetches every ACL (or the named one, empty when unknown) with its counters.
pub async fn show(acl_socket: &Path, name: Option<&str>) -> Result<Vec<AclStatus>, AclClientError> {
    let name = name.map(Into::into);
    match ask(acl_socket, AclRequest::Show { name }).await? {
        AclEvent::Acls(acls) => Ok(acls),
        AclEvent::Ack | AclEvent::Flowspec(_) | AclEvent::Cleared { .. } => {
            Err(AclClientError::Unexpected)
        }
    }
}

/// Fetches every flowspec rule `nos-acld` holds, with its state and counters.
pub async fn show_flowspec(acl_socket: &Path) -> Result<Vec<FlowspecRuleStatus>, AclClientError> {
    match ask(acl_socket, AclRequest::ShowFlowspec).await? {
        AclEvent::Flowspec(rules) => Ok(rules),
        AclEvent::Ack | AclEvent::Acls(_) | AclEvent::Cleared { .. } => {
            Err(AclClientError::Unexpected)
        }
    }
}

/// Reinstalls the ACLs on their idle chain so the counters restart at 0;
/// `(found, attachments replaced)`.
pub async fn clear_counters(
    acl_socket: &Path,
    name: Option<&str>,
) -> Result<(bool, u32), AclClientError> {
    let name = name.map(Into::into);
    match ask(acl_socket, AclRequest::ClearCounters { name }).await? {
        AclEvent::Cleared { found, attachments } => Ok((found, attachments)),
        AclEvent::Ack | AclEvent::Acls(_) | AclEvent::Flowspec(_) => {
            Err(AclClientError::Unexpected)
        }
    }
}
