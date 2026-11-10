use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::chunk::FullStaging;
use nos_proto::{IpcCodec, Ospfv3Event, Ospfv3Request, RedistributeUpdate, Role};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, trace, warn};

use crate::link::LinkManager;

/// Binds `listen_socket` and spawns the IPC accept loop for neighbor
/// summaries plus `nos-ribd`'s redistribution feed — mirrors
/// `ospf::server::start`.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    instance: String,
    links: Arc<LinkManager>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(instance = %instance, socket = %listen_socket.display(), "OSPFv3 IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, instance, links)))
}

/// Neighbor and database queries are for people (and `Restd` on their behalf);
/// the redistribution feed is `nos-ribd`'s alone. No wildcard arm.
fn allowed(role: Role, req: &Ospfv3Request) -> bool {
    match req {
        Ospfv3Request::GetNeighbors | Ospfv3Request::GetDatabase => {
            matches!(role, Role::User | Role::Restd)
        }
        Ospfv3Request::RedistributeRoutes(_) => role == Role::Ribd,
    }
}

async fn accept_loop(listener: Listener, instance: String, links: Arc<LinkManager>) {
    loop {
        let incoming = listener.accept_resilient().await;
        tokio::spawn(serve(incoming, instance.clone(), links.clone()));
    }
}

async fn serve(incoming: Incoming, instance: String, links: Arc<LinkManager>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, name, instance, links).await,
        Err(e) => debug!(instance = %instance, error = %e, "OSPFv3 IPC handshake refused"),
    }
}

async fn handle_connection(
    stream: Stream,
    role: Role,
    name: String,
    instance: String,
    links: Arc<LinkManager>,
) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<Ospfv3Request>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<Ospfv3Event>::default());
    let mut redistribute = FullStaging::default();

    while let Some(msg) = reader.next().await {
        let req = match msg {
            Ok(req) => req,
            Err(e) => {
                warn!(instance = %instance, error = %e, "OSPFv3 IPC read error");
                break;
            }
        };
        if !allowed(role, &req) {
            warn!(
                instance = %instance, role = role.as_str(), name = %name,
                "OSPFv3 request refused: this role may not send it"
            );
            break;
        }
        trace!(instance = %instance, request = ?req, "serving OSPF query");
        match req {
            Ospfv3Request::GetNeighbors => {
                let event = Ospfv3Event::Neighbors(links.neighbor_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            Ospfv3Request::GetDatabase => {
                let event = Ospfv3Event::Database(links.database_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            Ospfv3Request::RedistributeRoutes(update) => {
                // Only the closing `Full` is applied: it replaces the raw
                // set, so half a snapshot would withdraw the rest.
                if let Some((update, parts)) = update.absorb(&mut redistribute) {
                    if parts > 1
                        && let RedistributeUpdate::Full(r) = &update
                    {
                        info!(
                            instance = %instance, routes = r.len(), parts,
                            "assembled chunked redistribute snapshot"
                        );
                    }
                    links.apply_redistribute_update(update).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod authz_tests {
    use super::*;

    #[test]
    fn only_ribd_feeds_redistribution_and_only_people_query() {
        let feed = Ospfv3Request::RedistributeRoutes(nos_proto::RedistributeUpdate::Full(vec![]));
        for role in Role::ALL {
            assert_eq!(allowed(role, &feed), role == Role::Ribd, "{role:?} feed");
            assert_eq!(
                allowed(role, &Ospfv3Request::GetNeighbors),
                matches!(role, Role::User | Role::Restd),
                "{role:?} query"
            );
        }
    }
}
