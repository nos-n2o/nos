//! Binds `--listen-socket` and serves `LacpRequest::GetSummary` from the live
//! `AggregateManager`s — backs `nos-cli`'s `show lacp`. Mirrors
//! `interface::server`'s shape.

use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{IpcCodec, LacpEvent, LacpRequest, PortAggregateLacpSummary, Role};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, trace, warn};

use crate::reconcile::SharedAggregates;

pub fn start(
    listen_socket: &Path,
    aggregates: SharedAggregates,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(socket = %listen_socket.display(), "lacp IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, aggregates)))
}

/// The only request is a read-only summary: for people, and `Restd` on their
/// behalf.
fn may_query(role: Role) -> bool {
    matches!(role, Role::User | Role::Restd)
}

async fn serve(incoming: Incoming, aggregates: SharedAggregates) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, _)) if may_query(role) => handle_connection(stream, aggregates).await,
        Ok((_, role, name)) => warn!(
            role = role.as_str(), name = %name,
            "lacp query refused: this role may not send it"
        ),
        Err(e) => debug!(error = %e, "lacp IPC handshake refused"),
    }
}

async fn accept_loop(listener: Listener, aggregates: SharedAggregates) {
    loop {
        let incoming = listener.accept_resilient().await;
        tokio::spawn(serve(incoming, aggregates.clone()));
    }
}

async fn handle_connection(stream: Stream, aggregates: SharedAggregates) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<LacpRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<LacpEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(LacpRequest::GetSummary) => {
                trace!("serving lacp summary query");
                LacpEvent::Summary(summaries(&aggregates))
            }
            Err(e) => {
                warn!(error = %e, "lacp IPC read error");
                break;
            }
        };
        if writer.send(event).await.is_err() {
            break;
        }
    }
}

/// Every aggregate's summary, ordered by name. The std mutex is released
/// before any `.await` in the caller.
fn summaries(aggregates: &SharedAggregates) -> Vec<PortAggregateLacpSummary> {
    let mut all: Vec<PortAggregateLacpSummary> = aggregates
        .lock()
        .unwrap()
        .values()
        .map(|m| m.summary())
        .collect();
    all.sort_by(|a, b| a.aggregate.cmp(&b.aggregate));
    all
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use nos_pki::PeerId;

    async fn ask(path: &Path, role: Role) -> Option<LacpEvent> {
        let id = nos_pki::testing::shared().identity(role.as_str(), "x");
        let s = id.connect(path, &PeerId::new("lacpd", "")).await.unwrap();
        let (r, w) = tokio::io::split(s);
        let mut r = FramedRead::new(r, IpcCodec::<LacpEvent>::default());
        let mut w = FramedWrite::new(w, IpcCodec::<LacpRequest>::default());
        w.send(LacpRequest::GetSummary).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), r.next())
            .await
            .unwrap_or_else(|_| panic!("{role:?}: connection left open"))
            .map(|e| e.unwrap())
    }

    #[tokio::test]
    async fn only_people_are_served() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lacp.sock");
        let aggregates: SharedAggregates = Arc::new(Mutex::new(HashMap::new()));
        let id = nos_pki::testing::shared().identity("lacpd", "");
        let _server = start(&path, aggregates, &id).unwrap();

        for role in Role::ALL {
            let reply = ask(&path, role).await;
            if matches!(role, Role::User | Role::Restd) {
                assert!(
                    matches!(reply, Some(LacpEvent::Summary(ref s)) if s.is_empty()),
                    "{role:?}: {reply:?}"
                );
            } else {
                assert!(reply.is_none(), "{role:?} must get no reply");
            }
        }
    }
}
