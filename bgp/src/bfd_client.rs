//! Registers each BFD-guarded peer with `nos-bfdd` on one persistent
//! connection and turns a session going `Up` -> `Down` into
//! `SessionManager::bfd_down` (RFC 5882 §3.2: BGP is the client, BFD the
//! faster detector). `AdminDown`, `Init` and a session that was never `Up`
//! do nothing, so `nos-bfdd` being absent leaves BGP working as before.
//! `resync` publishes the wanted sessions on a `watch`; after a reconnect
//! everything is registered again.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::schema::BfdProfile;
use nos_proto::{BfdEvent, BfdRequest, BfdState, IpcCodec, Role, ServiceRef, SessionKey};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use crate::session::SessionManager;
use nos_daemon::watchdog::resolve_once;

const RETRY_DELAY: Duration = Duration::from_secs(1);

/// One wanted session: its profile and path (RFC 5883 multihop when the
/// peer is not on a connected subnet or `max-hops` > 1; `local` is the
/// peer-group's `source-address` if it has one, else `nos-bfdd` picks the
/// kernel's source towards the peer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    pub profile: BfdProfile,
    pub multihop: bool,
    pub local: Option<IpAddr>,
}

/// The sessions this instance wants, in its routing table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Target {
    pub table: String,
    pub peers: HashMap<IpAddr, Want>,
}

/// Pure bookkeeping of what is registered and what each session last did.
#[derive(Debug, Default)]
pub struct Book {
    table: String,
    registered: HashMap<IpAddr, Want>,
    /// Peers whose session has been `Up` since they were registered.
    was_up: HashSet<IpAddr>,
    /// The last state each registered peer's session reported.
    states: HashMap<IpAddr, BfdState>,
}

impl Book {
    /// The last reported state per registered peer (`show bgp summary`).
    pub fn states(&self) -> HashMap<IpAddr, BfdState> {
        self.states.clone()
    }

    fn key(&self, peer: IpAddr, want: &Want) -> SessionKey {
        SessionKey {
            aggregate: None,
            table: self.table.clone(),
            peer,
            local: want.local,
            interface: None,
            multihop: want.multihop,
        }
    }

    /// The requests that bring `nos-bfdd` in line with `target` (a
    /// re-`Register` is the profile refresh).
    pub fn sync(&mut self, target: &Target) -> Vec<BfdRequest> {
        let mut reqs = Vec::new();
        if self.table != target.table {
            for (peer, want) in &self.registered {
                reqs.push(BfdRequest::Deregister {
                    key: self.key(*peer, want),
                });
            }
            self.registered.clear();
            self.was_up.clear();
            self.states.clear();
            self.table.clone_from(&target.table);
        }
        for (peer, want) in &target.peers {
            let old = self.registered.get(peer);
            if old == Some(want) {
                continue;
            }
            // A different path is a different session: the old one goes.
            if let Some(old) = old.filter(|o| (o.multihop, o.local) != (want.multihop, want.local))
            {
                reqs.push(BfdRequest::Deregister {
                    key: self.key(*peer, old),
                });
                self.was_up.remove(peer);
                self.states.remove(peer);
            }
            reqs.push(BfdRequest::Register {
                table: self.table.clone(),
                peer: *peer,
                local: want.local,
                interface: None,
                profile: want.profile.clone(),
                multihop: want.multihop,
            });
            self.registered.insert(*peer, want.clone());
        }
        let gone: Vec<IpAddr> = self
            .registered
            .keys()
            .filter(|p| !target.peers.contains_key(p))
            .copied()
            .collect();
        for peer in gone {
            let want = self.registered.remove(&peer).expect("just listed");
            self.was_up.remove(&peer);
            self.states.remove(&peer);
            reqs.push(BfdRequest::Deregister {
                key: self.key(peer, &want),
            });
        }
        reqs
    }

    /// A state event: `Some(cpi)` when it is a failure to act on, i.e. the
    /// session was `Up` and is now `Down`.
    pub fn on_state(
        &mut self,
        key: &SessionKey,
        state: BfdState,
        control_plane_independent: bool,
    ) -> Option<bool> {
        if key.table != self.table || !self.registered.contains_key(&key.peer) {
            return None;
        }
        self.states.insert(key.peer, state);
        match state {
            BfdState::Up => {
                self.was_up.insert(key.peer);
                None
            }
            BfdState::Down => self
                .was_up
                .remove(&key.peer)
                .then_some(control_plane_independent),
            // BGP's own keepalive covers an administratively down session.
            BfdState::Init | BfdState::AdminDown => {
                self.was_up.remove(&key.peer);
                None
            }
        }
    }

    /// The connection is gone: the next one registers everything again.
    pub fn reset(&mut self) {
        self.registered.clear();
        self.was_up.clear();
        self.states.clear();
    }
}

pub fn spawn(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let target_rx = sessions.bfd_targets();
    tokio::spawn(run(watchdog_socket, sessions, target_rx, shutdown))
}

async fn wait_retry(shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(RETRY_DELAY) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

async fn run(
    watchdog_socket: PathBuf,
    sessions: Arc<SessionManager>,
    mut target_rx: watch::Receiver<Target>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut book = Book::default();
    while !*shutdown.borrow() {
        // Nothing wants a session: leave nos-bfdd alone until something does.
        if target_rx.borrow().peers.is_empty() {
            tokio::select! {
                r = target_rx.changed() => if r.is_err() { return },
                _ = shutdown.changed() => {}
            }
            continue;
        }
        let Some(socket) = resolve_once(&watchdog_socket, &ServiceRef::Bfd).await else {
            debug!("failed to resolve nos-bfdd via nos-watchdogd, retrying");
            if wait_retry(&mut shutdown).await {
                return;
            }
            continue;
        };
        let stream = match nos_pki::connect(&socket, Role::Bfdd, "").await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to connect to nos-bfdd, retrying");
                if wait_retry(&mut shutdown).await {
                    return;
                }
                continue;
            }
        };
        let (r, w) = tokio::io::split(stream);
        let mut reader = FramedRead::new(r, IpcCodec::<BfdEvent>::default());
        let mut writer = FramedWrite::new(w, IpcCodec::<BfdRequest>::default());
        info!("connected to nos-bfdd");
        let mut pending = true;
        loop {
            if pending {
                pending = false;
                let target = target_rx.borrow_and_update().clone();
                let mut failed = false;
                for req in book.sync(&target) {
                    if writer.send(req).await.is_err() {
                        failed = true;
                        break;
                    }
                }
                sessions.set_bfd_states(book.states());
                if failed {
                    break;
                }
            }
            tokio::select! {
                r = target_rx.changed() => {
                    if r.is_err() { return }
                    pending = true;
                }
                ev = reader.next() => match ev {
                    Some(Ok(BfdEvent::State { key, state, diag, control_plane_independent })) => {
                        let down = book.on_state(&key, state, control_plane_independent);
                        sessions.set_bfd_states(book.states());
                        if let Some(cpi) = down {
                            info!(peer = %key.peer, diag = %diag, control_plane_independent = cpi, "bgp: bfd session down, closing");
                            sessions.bfd_down(key.peer, cpi).await;
                        }
                    }
                    Some(Ok(BfdEvent::Sessions(_) | BfdEvent::Reflector(_))) => {}
                    Some(Err(_)) | None => break,
                },
                _ = shutdown.changed() => if *shutdown.borrow() { return },
            }
        }
        warn!("lost nos-bfdd, BGP sessions are no longer bfd-guarded");
        book.reset();
        sessions.set_bfd_states(book.states());
        if wait_retry(&mut shutdown).await {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn want(multihop: bool, local: Option<IpAddr>) -> Want {
        Want {
            profile: BfdProfile::default(),
            multihop,
            local,
        }
    }

    fn target(table: &str, peers: &[&str]) -> Target {
        Target {
            table: table.into(),
            peers: peers.iter().map(|p| (ip(p), want(false, None))).collect(),
        }
    }

    fn key(table: &str, peer: &str) -> SessionKey {
        SessionKey {
            aggregate: None,
            table: table.into(),
            peer: ip(peer),
            local: None,
            interface: None,
            multihop: false,
        }
    }

    #[test]
    fn registers_new_and_deregisters_gone_and_moved_table() {
        let mut b = Book::default();
        let t = target("rt1", &["192.0.2.1"]);
        assert!(matches!(
            b.sync(&t).as_slice(),
            [BfdRequest::Register { peer, multihop: false, .. }] if *peer == ip("192.0.2.1")
        ));
        assert_eq!(b.sync(&t), vec![]);
        // The table changed: old session out, new one in.
        let reqs = b.sync(&target("rt2", &["192.0.2.1"]));
        assert_eq!(reqs.len(), 2);
        assert_eq!(
            reqs[0],
            BfdRequest::Deregister {
                key: key("rt1", "192.0.2.1")
            }
        );
        assert_eq!(
            b.sync(&target("rt2", &[])),
            vec![BfdRequest::Deregister {
                key: key("rt2", "192.0.2.1")
            }]
        );
    }

    #[test]
    fn multihop_peers_register_multihop_and_a_path_change_replaces_the_session() {
        let mut b = Book::default();
        let mut t = target("rt1", &[]);
        t.peers
            .insert(ip("2.2.2.2"), want(true, Some(ip("1.1.1.1"))));
        assert!(matches!(
            b.sync(&t).as_slice(),
            [BfdRequest::Register { multihop: true, local: Some(l), interface: None, .. }]
                if *l == ip("1.1.1.1")
        ));
        // Connected after all (an address appeared): single-hop replaces it.
        t.peers.insert(ip("2.2.2.2"), want(false, None));
        let reqs = b.sync(&t);
        assert!(matches!(
            reqs.as_slice(),
            [
                BfdRequest::Deregister {
                    key: SessionKey {
                        multihop: true,
                        local: Some(_),
                        ..
                    }
                },
                BfdRequest::Register {
                    multihop: false,
                    local: None,
                    ..
                },
            ]
        ));
        t.peers.clear();
        assert!(matches!(
            b.sync(&t).as_slice(),
            [BfdRequest::Deregister {
                key: SessionKey {
                    multihop: false,
                    ..
                }
            }]
        ));
    }

    #[test]
    fn only_up_to_down_is_a_failure_and_carries_the_c_bit() {
        let mut b = Book::default();
        b.sync(&target("rt1", &["192.0.2.1"]));
        let k = key("rt1", "192.0.2.1");
        // The state a fresh Register reports is not a failure.
        assert_eq!(b.on_state(&k, BfdState::Down, true), None);
        assert_eq!(b.on_state(&k, BfdState::Init, true), None);
        assert_eq!(b.on_state(&k, BfdState::Up, true), None);
        assert_eq!(b.on_state(&k, BfdState::Down, true), Some(true));
        assert_eq!(b.on_state(&k, BfdState::Down, true), None, "once per Up");
        b.on_state(&k, BfdState::Up, false);
        assert_eq!(b.on_state(&k, BfdState::Down, false), Some(false));
        // AdminDown does nothing; so do other tables and strangers.
        b.on_state(&k, BfdState::Up, true);
        assert_eq!(b.on_state(&k, BfdState::AdminDown, true), None);
        assert_eq!(b.on_state(&k, BfdState::Down, true), None);
        b.on_state(&k, BfdState::Up, true);
        assert_eq!(
            b.on_state(&key("rt2", "192.0.2.1"), BfdState::Down, true),
            None
        );
        assert_eq!(
            b.on_state(&key("rt1", "192.0.2.9"), BfdState::Down, true),
            None
        );
    }

    #[test]
    fn states_follow_events_and_clear_on_reset_and_deregister() {
        let mut b = Book::default();
        b.sync(&target("rt1", &["192.0.2.1"]));
        assert!(b.states().is_empty());
        let k = key("rt1", "192.0.2.1");
        b.on_state(&k, BfdState::Init, true);
        assert_eq!(b.states()[&ip("192.0.2.1")], BfdState::Init);
        b.on_state(&k, BfdState::Up, true);
        assert_eq!(b.states()[&ip("192.0.2.1")], BfdState::Up);
        // A stranger's event is not recorded.
        b.on_state(&key("rt1", "192.0.2.9"), BfdState::Up, true);
        assert_eq!(b.states().len(), 1);
        b.sync(&target("rt2", &["192.0.2.1"]));
        assert!(b.states().is_empty(), "table move");
        b.on_state(&key("rt2", "192.0.2.1"), BfdState::Up, true);
        b.sync(&target("rt2", &[]));
        assert!(b.states().is_empty(), "deregistered");
        b.sync(&target("rt2", &["192.0.2.1"]));
        b.on_state(&key("rt2", "192.0.2.1"), BfdState::Up, true);
        b.reset();
        assert!(b.states().is_empty(), "connection lost");
    }
}
