//! `--listen-socket`: clients `Register` sessions on a persistent connection
//! and are streamed `BfdEvent::State` (the current state first, then every
//! change); `GetSessions` is answered once. A connection that goes away
//! releases everything it registered.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{BfdEvent, BfdRequest, IpcCodec, Role, SessionKey};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use crate::authz::allowed;
use crate::manager::Manager;
use crate::session::Status;

pub fn start(
    listen_socket: &Path,
    manager: Arc<Manager>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(socket = %listen_socket.display(), "bfd IPC server listening");
    Ok(tokio::spawn(accept_loop(listener, manager)))
}

async fn accept_loop(listener: Listener, manager: Arc<Manager>) {
    loop {
        let incoming = listener.accept_resilient().await;
        tokio::spawn(serve(incoming, manager.clone()));
    }
}

async fn serve(incoming: Incoming, manager: Arc<Manager>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, &name, manager).await,
        Err(e) => debug!(error = %e, "bfd IPC handshake refused"),
    }
}

/// Streams a session's state to the connection's writer: the current one
/// first, then every change of (state, diag).
async fn forward(key: SessionKey, mut rx: watch::Receiver<Status>, out: mpsc::Sender<BfdEvent>) {
    let mut last = None;
    loop {
        let s = *rx.borrow_and_update();
        let now = (s.state, s.diag, s.control_plane_independent);
        if last != Some(now) {
            last = Some(now);
            let ev = BfdEvent::State {
                key: key.clone(),
                state: s.state,
                diag: s.diag,
                control_plane_independent: s.control_plane_independent,
            };
            if out.send(ev).await.is_err() || rx.changed().await.is_err() {
                return;
            }
        } else if rx.changed().await.is_err() {
            return;
        }
    }
}

fn key_of(req: &BfdRequest) -> Option<SessionKey> {
    match req {
        BfdRequest::Register {
            table,
            peer,
            local,
            interface,
            multihop,
            ..
        } => Some(SessionKey {
            aggregate: None,
            table: table.clone(),
            peer: *peer,
            local: *local,
            interface: interface.clone(),
            multihop: *multihop,
        }),
        BfdRequest::Deregister { key } => Some(key.clone()),
        BfdRequest::GetSessions { .. } | BfdRequest::GetReflector => None,
    }
}

async fn handle_connection(stream: Stream, role: Role, name: &str, manager: Arc<Manager>) {
    let client = manager.new_client();
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<BfdRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<BfdEvent>::default());
    let (out_tx, mut out_rx) = mpsc::channel::<BfdEvent>(64);
    let mut forwarders: HashMap<SessionKey, JoinHandle<()>> = HashMap::new();

    loop {
        tokio::select! {
            msg = reader.next() => {
                // ponytail: request-side EOF ends the connection (clients
                // keep their write half open, `rib/src/bfd_client.rs`);
                // a client that half-closes would need the config
                // subscribers' "keep until a write fails" rule instead.
                let Some(Ok(req)) = msg else { break };
                if !allowed(role, &req) {
                    warn!(role = role.as_str(), name, "bfd request refused: this role may not send it");
                    break;
                }
                match &req {
                    BfdRequest::Register { profile, .. } => {
                        let key = key_of(&req).expect("register has a key");
                        let rx = manager.register(client, &key, profile);
                        if let Some(old) = forwarders.insert(key.clone(), tokio::spawn(forward(key, rx, out_tx.clone()))) {
                            old.abort();
                        }
                    }
                    BfdRequest::Deregister { key } => {
                        if let Some(f) = forwarders.remove(key) {
                            f.abort();
                        }
                        manager.deregister(client, key);
                    }
                    BfdRequest::GetSessions { peer } => {
                        if writer.send(BfdEvent::Sessions(manager.sessions(*peer))).await.is_err() {
                            break;
                        }
                    }
                    BfdRequest::GetReflector => {
                        if writer.send(BfdEvent::Reflector(manager.reflector().view())).await.is_err() {
                            break;
                        }
                    }
                }
            }
            Some(ev) = out_rx.recv() => {
                if writer.send(ev).await.is_err() {
                    break;
                }
            }
        }
    }
    for f in forwarders.into_values() {
        f.abort();
    }
    manager.drop_client(client);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::tests::mgr;
    use nos_pki::PeerId;
    use nos_proto::schema::BfdProfile;
    use nos_proto::{BfdDiag, BfdSessionKind, BfdState};
    use std::time::Duration;

    type Reader = FramedRead<tokio::io::ReadHalf<Stream>, IpcCodec<BfdEvent>>;
    type Writer = FramedWrite<tokio::io::WriteHalf<Stream>, IpcCodec<BfdRequest>>;

    async fn connect(path: &Path, role: &str) -> (Reader, Writer) {
        let id = nos_pki::testing::shared().identity(role, "x");
        let s = id.connect(path, &PeerId::new("bfdd", "")).await.unwrap();
        let (r, w) = tokio::io::split(s);
        (
            FramedRead::new(r, IpcCodec::default()),
            FramedWrite::new(w, IpcCodec::default()),
        )
    }

    /// A bounded read: a dead server fails the test fast instead of hanging
    /// (or ending a mutant as a Timeout, #374).
    async fn next(r: &mut Reader) -> Option<Result<BfdEvent, std::io::Error>> {
        tokio::time::timeout(Duration::from_secs(5), r.next())
            .await
            .expect("no reply within 5s")
    }

    fn status(state: BfdState, cpi: bool) -> Status {
        Status {
            state,
            diag: BfdDiag::NoDiagnostic,
            local_discriminator: 1,
            remote_discriminator: 0,
            tx_interval_us: 1_000_000,
            detection_time_us: 3_000_000,
            control_plane_independent: cpi,
            auth_method: None,
            auth_key_id: None,
            auth_failures: 0,
            echo_active: false,
            echo_interval_us: 0,
            echo_only: false,
            tx_pdu_bytes: 0,
            kind: BfdSessionKind::Classical,
        }
    }

    async fn ev(rx: &mut mpsc::Receiver<BfdEvent>) -> (BfdState, BfdDiag, bool) {
        let e = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("forward emitted nothing within 5s")
            .expect("forward closed the channel");
        let BfdEvent::State {
            state,
            diag,
            control_plane_independent,
            ..
        } = e
        else {
            panic!("not a State event");
        };
        (state, diag, control_plane_independent)
    }

    fn key() -> SessionKey {
        key_of(&register("192.0.2.1")).unwrap()
    }

    #[tokio::test]
    async fn forward_emits_current_then_only_changes() {
        let (tx, rx) = watch::channel(status(BfdState::Down, false));
        let (out, mut events) = mpsc::channel(8);
        let _task = tokio::spawn(forward(key(), rx, out));

        assert_eq!(
            ev(&mut events).await,
            (BfdState::Down, BfdDiag::NoDiagnostic, false)
        );
        // Identical status (even though `changed()` fires): nothing re-emitted.
        let mut same = status(BfdState::Down, false);
        same.tx_interval_us = 5; // not part of the dedup key
        tx.send_replace(same);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), events.recv())
                .await
                .is_err(),
            "an unchanged (state, diag, cpi) was re-emitted"
        );
        // Each tuple member alone is enough to emit.
        tx.send_replace(status(BfdState::Down, true));
        assert_eq!(
            ev(&mut events).await,
            (BfdState::Down, BfdDiag::NoDiagnostic, true)
        );
        let mut s = status(BfdState::Down, true);
        s.diag = BfdDiag::PathDown;
        tx.send_replace(s);
        assert_eq!(
            ev(&mut events).await,
            (BfdState::Down, BfdDiag::PathDown, true)
        );
        s.state = BfdState::Up;
        tx.send_replace(s);
        assert_eq!(
            ev(&mut events).await,
            (BfdState::Up, BfdDiag::PathDown, true)
        );
    }

    #[tokio::test]
    async fn forward_ends_when_either_side_goes_away() {
        // Subscriber gone while the session lives: the next send fails.
        let (tx, rx) = watch::channel(status(BfdState::Down, false));
        let (out, events) = mpsc::channel(8);
        let task = tokio::spawn(forward(key(), rx, out));
        drop(events);
        // The first send may already have failed; if it succeeded the task
        // is parked on `changed()`, so give it a change to send.
        tx.send_replace(status(BfdState::Up, false));
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("forward outlived its subscriber")
            .unwrap();

        // Session gone: `changed()` errors.
        let (tx, rx) = watch::channel(status(BfdState::Down, false));
        let (out, mut events) = mpsc::channel(8);
        let task = tokio::spawn(forward(key(), rx, out));
        ev(&mut events).await;
        drop(tx);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("forward outlived its session")
            .unwrap();
    }

    fn register(peer: &str) -> BfdRequest {
        BfdRequest::Register {
            table: "rt1".into(),
            peer: peer.parse().unwrap(),
            local: None,
            interface: None,
            profile: BfdProfile::default(),
            multihop: false,
        }
    }

    #[tokio::test]
    async fn register_streams_state_and_disconnect_releases() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bfd.sock");
        let (m, _, _) = mgr(false);
        let id = nos_pki::testing::shared().identity("bfdd", "");
        let _server = start(&path, m.clone(), &id).unwrap();

        let (mut r, mut w) = connect(&path, "ribd").await;
        w.send(register("192.0.2.1")).await.unwrap();
        let Some(Ok(BfdEvent::State { key, state, .. })) = next(&mut r).await else {
            panic!("no initial state");
        };
        assert_eq!(
            (key.peer.to_string().as_str(), state),
            ("192.0.2.1", BfdState::Down)
        );
        assert_eq!(m.sessions(None).len(), 1);

        // A second client asks, then the first deregisters explicitly.
        let (mut r2, mut w2) = connect(&path, "user").await;
        w2.send(BfdRequest::GetSessions { peer: None })
            .await
            .unwrap();
        let Some(Ok(BfdEvent::Sessions(v))) = next(&mut r2).await else {
            panic!("no sessions");
        };
        assert_eq!(v.len(), 1);
        w2.send(BfdRequest::GetReflector).await.unwrap();
        let Some(Ok(BfdEvent::Reflector(v))) = next(&mut r2).await else {
            panic!("no reflector");
        };
        assert_eq!((v.received, v.discriminators.len()), (0, 0));

        w.send(BfdRequest::Deregister { key }).await.unwrap();
        w.send(register("192.0.2.2")).await.unwrap();
        let _ = next(&mut r).await;
        drop((r, w));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !m.sessions(None).is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("connection drop released the sessions");
    }

    #[tokio::test]
    async fn refused_role_gets_the_connection_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bfd.sock");
        let (m, _, _) = mgr(false);
        let id = nos_pki::testing::shared().identity("bfdd", "");
        let _server = start(&path, m.clone(), &id).unwrap();

        // `user` may query, not register.
        let (mut r, mut w) = connect(&path, "user").await;
        w.send(register("192.0.2.1")).await.unwrap();
        assert!(next(&mut r).await.is_none());
        assert_eq!(m.sessions(None).len(), 0);
    }
}
