//! Binds `--listen-socket` and serves `LldpRequest::GetNeighbors`/
//! `GetStatistics` from the live per-interface state — backs `nos-cli`'s
//! `show lldp neighbors`/`show lldp statistics`. Mirrors `nos-lacp`'s
//! `server.rs`.

use std::path::Path;
use std::time::Instant;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{IpcCodec, LldpEvent, LldpLinkStats, LldpNeighbor, LldpRequest, Role};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, trace, warn};

use crate::link::SharedPorts;

pub fn start(
    listen_socket: &Path,
    ports: SharedPorts,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(socket = %listen_socket.display(), "lldp IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, ports)))
}

/// Every request is a read-only query: for people, and `Restd` on their
/// behalf.
fn may_query(role: Role) -> bool {
    matches!(role, Role::User | Role::Restd)
}

async fn serve(incoming: Incoming, ports: SharedPorts) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, _)) if may_query(role) => handle_connection(stream, ports).await,
        Ok((_, role, name)) => warn!(
            role = role.as_str(), name = %name,
            "lldp query refused: this role may not send it"
        ),
        Err(e) => debug!(error = %e, "lldp IPC handshake refused"),
    }
}

async fn accept_loop(listener: Listener, ports: SharedPorts) {
    loop {
        let incoming = listener.accept_resilient().await;
        tokio::spawn(serve(incoming, ports.clone()));
    }
}

async fn handle_connection(stream: Stream, ports: SharedPorts) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<LldpRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<LldpEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(LldpRequest::GetNeighbors) => {
                trace!("serving lldp neighbor query");
                LldpEvent::Neighbors(all_neighbors(&ports))
            }
            Ok(LldpRequest::GetStatistics) => {
                trace!("serving lldp statistics query");
                LldpEvent::Statistics(all_statistics(&ports))
            }
            Err(e) => {
                warn!(error = %e, "lldp IPC read error");
                break;
            }
        };
        if writer.send(event).await.is_err() {
            break;
        }
    }
}

/// Every neighbor on every interface, ordered by interface then chassis then
/// port. The std mutex is released before any `.await` in the caller.
fn all_neighbors(ports: &SharedPorts) -> Vec<LldpNeighbor> {
    let now = Instant::now();
    let mut all: Vec<LldpNeighbor> = ports
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(interface, port)| port.neighbors.snapshot(interface, now))
        .collect();
    all.sort_by(|a, b| {
        (&a.local_interface, &a.chassis_id, &a.port_id).cmp(&(
            &b.local_interface,
            &b.chassis_id,
            &b.port_id,
        ))
    });
    all
}

/// Every LLDP-enabled interface's counters, ordered by interface.
fn all_statistics(ports: &SharedPorts) -> Vec<LldpLinkStats> {
    let mut all: Vec<LldpLinkStats> = ports
        .lock()
        .unwrap()
        .iter()
        .map(|(interface, port)| LldpLinkStats {
            interface: interface.clone(),
            ..port.stats.clone()
        })
        .collect();
    all.sort_by(|a, b| a.interface.cmp(&b.interface));
    all
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::link::Port;
    use nos_pki::PeerId;

    type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<LldpEvent>>;
    type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<LldpRequest>>;

    async fn connect(path: &Path, role: Role) -> (Reader, Writer) {
        let id = nos_pki::testing::shared().identity(role.as_str(), "x");
        let s = id.connect(path, &PeerId::new("lldpd", "")).await.unwrap();
        let (r, w) = tokio::io::split(s);
        (
            FramedRead::new(r, IpcCodec::default()),
            FramedWrite::new(w, IpcCodec::default()),
        )
    }

    /// Every role: `User`/`Restd` get real replies, any other role has the
    /// connection closed with no frame.
    #[tokio::test]
    async fn only_people_are_served() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lldp.sock");
        let ports: SharedPorts = Arc::new(Mutex::new(HashMap::from([(
            "eth0".to_string(),
            Port::default(),
        )])));
        let id = nos_pki::testing::shared().identity("lldpd", "");
        let _server = start(&path, ports, &id).unwrap();

        for role in Role::ALL {
            let (mut r, mut w) = connect(&path, role).await;
            w.send(LldpRequest::GetStatistics).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(5), r.next())
                .await
                .unwrap_or_else(|_| panic!("{role:?}: connection left open"));
            if matches!(role, Role::User | Role::Restd) {
                let Some(Ok(LldpEvent::Statistics(s))) = reply else {
                    panic!("{role:?}: no statistics");
                };
                assert_eq!(s.len(), 1, "{role:?}");
                assert_eq!(s[0].interface, "eth0");
                w.send(LldpRequest::GetNeighbors).await.unwrap();
                let Some(Ok(LldpEvent::Neighbors(n))) = r.next().await else {
                    panic!("{role:?}: no neighbors");
                };
                assert_eq!(n.len(), 0);
            } else {
                assert!(reply.is_none(), "{role:?} must get no reply");
            }
        }
    }
}
