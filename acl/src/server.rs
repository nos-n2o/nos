//! Binds `--listen-socket` and serves `AclRequest::Show`/`ShowFlowspec` from
//! the engine's live state (`show acl`, `GET /v1/acl`, `GET /v1/flowspec`)
//! and `PushFlowspec` from `nos-bgpd`. Mirrors `nos-lldp`'s `server.rs`.

use std::path::Path;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{AclEvent, AclRequest, IpcCodec, Role};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, trace, warn};

use crate::driver::Driver;
use crate::engine::Shared;

pub fn start<D: Driver>(
    listen_socket: &Path,
    engine: Shared<D>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(socket = %listen_socket.display(), "acl IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, engine)))
}

/// Queries are for people, and `Restd` on their behalf; flow rules come
/// from `nos-bgpd` only, which also reads their state back for
/// `show bgp flowspec` (#562).
pub fn allowed(role: Role, request: &AclRequest) -> bool {
    match request {
        AclRequest::Show { .. } => matches!(role, Role::User | Role::Restd),
        AclRequest::ShowFlowspec => matches!(role, Role::User | Role::Restd | Role::Bgpd),
        AclRequest::PushFlowspec(_) => role == Role::Bgpd,
    }
}

/// Runs `request` under the engine lock (counters are a blocking netlink
/// dump, a push a blocking install).
fn answer<D: Driver>(engine: &Shared<D>, request: AclRequest) -> AclEvent {
    let mut engine = engine.lock().unwrap();
    match request {
        AclRequest::Show { name } => {
            trace!(?name, "serving acl query");
            AclEvent::Acls(engine.show(name.as_deref()))
        }
        AclRequest::ShowFlowspec => AclEvent::Flowspec(engine.show_flowspec()),
        AclRequest::PushFlowspec(set) => {
            engine.push_flowspec(set);
            AclEvent::Ack
        }
    }
}

async fn accept_loop<D: Driver>(listener: Listener, engine: Shared<D>) {
    loop {
        let incoming = listener.accept_resilient().await;
        tokio::spawn(serve(incoming, engine.clone()));
    }
}

async fn serve<D: Driver>(incoming: Incoming, engine: Shared<D>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, &name, engine).await,
        Err(e) => debug!(error = %e, "acl IPC handshake refused"),
    }
}

async fn handle_connection<D: Driver>(stream: Stream, role: Role, peer: &str, engine: Shared<D>) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<AclRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<AclEvent>::default());

    while let Some(msg) = reader.next().await {
        let request = match msg {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "acl IPC read error");
                break;
            }
        };
        if !allowed(role, &request) {
            warn!(role = role.as_str(), name = %peer, "acl query refused: this role may not send it");
            break;
        }
        let engine = engine.clone();
        let Ok(event) = tokio::task::spawn_blocking(move || answer(&engine, request)).await else {
            break;
        };
        if writer.send(event).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use nos_pki::PeerId;

    use super::*;
    use crate::driver::NoopDriver;
    use crate::engine::Engine;

    fn push() -> AclRequest {
        AclRequest::PushFlowspec(nos_proto::FlowspecSet {
            instance: "b1".into(),
            devices: vec![],
            rules: vec![],
        })
    }

    #[test]
    fn only_people_may_query_and_only_bgp_push() {
        for role in Role::ALL {
            let people = matches!(role, Role::User | Role::Restd);
            assert_eq!(
                allowed(role, &AclRequest::Show { name: None }),
                people,
                "{role:?}"
            );
            assert_eq!(
                allowed(role, &AclRequest::ShowFlowspec),
                people || role == Role::Bgpd,
                "{role:?}"
            );
            assert_eq!(allowed(role, &push()), role == Role::Bgpd, "{role:?}");
        }
    }

    /// `nos-bgpd` pushes and gets an ack; a person reads the rules back.
    #[tokio::test]
    async fn bgp_pushes_and_people_read_flowspec() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("acl.sock");
        let engine = Arc::new(Mutex::new(Engine::new(NoopDriver::default())));
        let id = nos_pki::testing::shared().identity("acld", "");
        let _server = start(&path, engine, &id).unwrap();
        let ask = |role: Role, req: AclRequest| {
            let path = path.clone();
            async move {
                let id = nos_pki::testing::shared().identity(role.as_str(), "x");
                let s = id.connect(&path, &PeerId::new("acld", "")).await.unwrap();
                let (r, w) = tokio::io::split(s);
                let mut r = FramedRead::new(r, IpcCodec::<AclEvent>::default());
                let mut w = FramedWrite::new(w, IpcCodec::<AclRequest>::default());
                w.send(req).await.unwrap();
                tokio::time::timeout(Duration::from_secs(5), r.next())
                    .await
                    .unwrap()
                    .map(Result::unwrap)
            }
        };
        let rule = nos_proto::FlowRule {
            flow: "f".into(),
            ipv6: false,
            components: vec![],
            actions: vec![],
        };
        let AclRequest::PushFlowspec(mut set) = push() else {
            unreachable!()
        };
        set.rules.push(rule);
        let ack = ask(Role::Bgpd, AclRequest::PushFlowspec(set)).await;
        assert!(matches!(ack, Some(AclEvent::Ack)), "{ack:?}");
        let Some(AclEvent::Flowspec(rows)) = ask(Role::User, AclRequest::ShowFlowspec).await else {
            panic!("no flowspec reply");
        };
        assert_eq!((rows.len(), rows[0].flow.as_str()), (1, "f"));
        // A person may not push.
        assert!(ask(Role::User, push()).await.is_none());
    }

    /// A refused role has the connection closed with no frame; an allowed
    /// one gets a (here empty) reply.
    #[tokio::test]
    async fn serves_people_and_closes_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("acl.sock");
        let engine = Arc::new(Mutex::new(Engine::new(NoopDriver::default())));
        let id = nos_pki::testing::shared().identity("acld", "");
        let _server = start(&path, engine, &id).unwrap();

        for role in Role::ALL {
            let id = nos_pki::testing::shared().identity(role.as_str(), "x");
            let s = id.connect(&path, &PeerId::new("acld", "")).await.unwrap();
            let (r, w) = tokio::io::split(s);
            let mut r = FramedRead::new(r, IpcCodec::<AclEvent>::default());
            let mut w = FramedWrite::new(w, IpcCodec::<AclRequest>::default());
            w.send(AclRequest::Show { name: None }).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(5), r.next())
                .await
                .unwrap_or_else(|_| panic!("{role:?}: connection left open"));
            if matches!(role, Role::User | Role::Restd) {
                let Some(Ok(AclEvent::Acls(a))) = reply else {
                    panic!("{role:?}: no reply");
                };
                assert_eq!(a.len(), 0);
            } else {
                assert!(reply.is_none(), "{role:?} must get no reply");
            }
        }
    }
}
