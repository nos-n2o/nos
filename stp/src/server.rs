//! Binds `--listen-socket` and serves `StpRequest::GetSummary` from the
//! snapshot the daemon actor keeps current — backs `show spanning-tree`.
//! Mirrors `nos-lldp`'s `server.rs`.

use std::path::Path;
use std::sync::{Arc, RwLock};

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{IpcCodec, Role, StpEvent, StpRequest, StpSummary};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use crate::authz::allowed;

/// Written by the daemon actor after every change, read per query.
pub type Snapshot = Arc<RwLock<StpSummary>>;

/// An operator command, answered by the daemon actor.
pub enum Cmd {
    /// `mcheck`: the number of ports matched.
    Mcheck {
        interface: Option<String>,
        reply: oneshot::Sender<u32>,
    },
    /// `clear spanning-tree err-disabled`: whether the port was err-disabled.
    ClearErrDisabled {
        interface: String,
        reply: oneshot::Sender<bool>,
    },
}

pub fn start(
    listen_socket: &Path,
    snapshot: Snapshot,
    cmds: mpsc::Sender<Cmd>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(socket = %listen_socket.display(), "stp IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, snapshot, cmds)))
}

async fn accept_loop(listener: Listener, snapshot: Snapshot, cmds: mpsc::Sender<Cmd>) {
    loop {
        let incoming = listener.accept_resilient().await;
        tokio::spawn(serve(incoming, snapshot.clone(), cmds.clone()));
    }
}

async fn serve(incoming: Incoming, snapshot: Snapshot, cmds: mpsc::Sender<Cmd>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, &name, snapshot, cmds).await,
        Err(e) => debug!(error = %e, "stp IPC handshake refused"),
    }
}

async fn handle_connection(
    stream: Stream,
    role: Role,
    name: &str,
    snapshot: Snapshot,
    cmds: mpsc::Sender<Cmd>,
) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<StpRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<StpEvent>::default());
    while let Some(msg) = reader.next().await {
        let Ok(req) = msg else { break };
        if !allowed(role, &req) {
            warn!(
                role = role.as_str(),
                name, "stp request refused: this role may not send it"
            );
            break;
        }
        let event = match req {
            StpRequest::GetSummary => {
                StpEvent::Summary(snapshot.read().expect("snapshot lock").clone())
            }
            StpRequest::Mcheck { interface } => {
                let (reply, rx) = oneshot::channel();
                if cmds.send(Cmd::Mcheck { interface, reply }).await.is_err() {
                    break;
                }
                let Ok(ports) = rx.await else { break };
                StpEvent::Mcheck { ports }
            }
            StpRequest::ClearErrDisabled { interface } => {
                let (reply, rx) = oneshot::channel();
                if cmds
                    .send(Cmd::ClearErrDisabled { interface, reply })
                    .await
                    .is_err()
                {
                    break;
                }
                let Ok(cleared) = rx.await else { break };
                StpEvent::ErrDisabledCleared { cleared }
            }
        };
        if writer.send(event).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_pki::{testing::shared, PeerId};

    async fn ask(path: &Path, role: &str) -> Option<StpEvent> {
        let s = shared()
            .identity(role, "t")
            .connect(path, &PeerId::new("stpd", ""))
            .await
            .unwrap();
        let (r, w) = tokio::io::split(s);
        let mut reader = FramedRead::new(r, IpcCodec::<StpEvent>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<StpRequest>::default());
        writer.send(StpRequest::GetSummary).await.unwrap();
        reader.next().await.and_then(Result::ok)
    }

    #[tokio::test]
    async fn serves_the_snapshot_to_allowed_roles_only() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("stp.sock");
        let snap: Snapshot = Arc::default();
        snap.write().unwrap().bridge_id = "8000.02:00:00:00:00:01".into();
        let (cmds, mut cmd_rx) = mpsc::channel::<Cmd>(1);
        tokio::spawn(async move {
            while let Some(c) = cmd_rx.recv().await {
                match c {
                    Cmd::Mcheck { interface, reply } => {
                        let _ = reply.send(u32::from(interface.as_deref() == Some("eth1")));
                    }
                    Cmd::ClearErrDisabled { interface, reply } => {
                        let _ = reply.send(interface == "eth1");
                    }
                }
            }
        });
        let _server = start(&path, snap.clone(), cmds, &shared().identity("stpd", "")).unwrap();

        let Some(StpEvent::Summary(s)) = ask(&path, "user").await else {
            panic!("no reply for a user");
        };
        assert_eq!(s.bridge_id, "8000.02:00:00:00:00:01");
        assert!(!s.enabled, "default snapshot is the disabled one");
        // The snapshot is live: a later write is what the next query sees.
        snap.write().unwrap().enabled = true;
        let Some(StpEvent::Summary(s)) = ask(&path, "restd").await else {
            panic!("no reply for restd");
        };
        assert!(s.enabled);
        assert!(ask(&path, "bgpd").await.is_none(), "other roles are cut");
        let s = shared()
            .identity("user", "t")
            .connect(&path, &PeerId::new("stpd", ""))
            .await
            .unwrap();
        let (r, w) = tokio::io::split(s);
        let mut reader = FramedRead::new(r, IpcCodec::<StpEvent>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<StpRequest>::default());
        let interface = Some("eth1".to_string());
        writer.send(StpRequest::Mcheck { interface }).await.unwrap();
        assert!(matches!(
            reader.next().await,
            Some(Ok(StpEvent::Mcheck { ports: 1 }))
        ));
        let interface = "eth1".to_string();
        writer
            .send(StpRequest::ClearErrDisabled { interface })
            .await
            .unwrap();
        assert!(matches!(
            reader.next().await,
            Some(Ok(StpEvent::ErrDisabledCleared { cleared: true }))
        ));
    }
}
