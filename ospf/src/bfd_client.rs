//! Registers each BFD-guarded OSPF neighbor with `nos-bfdd` on one persistent
//! connection and turns a session going `Up` -> `Down` into a neighbor kill
//! (RFC 5882 §4.1, RFC 2328 §10.2 `KillNbr`). `AdminDown`, `Init` and a
//! session that was never `Up` do nothing, and a lost connection leaves the
//! neighbors alone (RFC 5882 §3.2), so a missing `nos-bfdd` leaves OSPF
//! working as before.
//!
//! Shared by `nos-ospf` and `nos-ospfv3` (`ospfv3/src/lib.rs` includes this
//! file); the daemon plugs in through [`Host`].
//!
//! ponytail: the wanted set is polled every `POLL` instead of pushed, so a
//! neighbor reaching 2-Way is registered up to 250ms later; push it from the
//! link tasks if that ever matters (Full takes seconds anyway).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::schema::BfdProfile;
use nos_proto::{BfdDiag, BfdEvent, BfdRequest, BfdState, IpcCodec, Role, ServiceRef, SessionKey};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use nos_daemon::watchdog::resolve_once;

const RETRY_DELAY: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_millis(250);

/// One wanted single-hop session. `local` and `interface` are what the
/// daemon knows of the link (`interface` is needed for an IPv6 link-local peer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    pub profile: BfdProfile,
    pub local: Option<IpAddr>,
    pub interface: Option<String>,
}

/// A session's identity on the daemon side: the neighbor address and the
/// interface (`None` for `OSPFv2`, which has no link-local peers). Two links can
/// each hold a neighbor at the same link-local address (#1603), so the address
/// alone is not a key.
pub type Peer = (IpAddr, Option<String>);

/// The neighbors that want a session.
pub type Target = HashMap<Peer, Want>;

/// What the daemon provides to the client.
pub trait Host: Send + Sync + 'static {
    /// The sessions wanted right now (neighbors at 2-Way or later whose link
    /// has a `bfd` profile).
    fn target(&self) -> impl Future<Output = Target> + Send;
    /// BFD reports the path to `peer` on `interface` down: kill that neighbor.
    fn down(
        &self,
        peer: IpAddr,
        interface: Option<String>,
        diag: BfdDiag,
    ) -> impl Future<Output = ()> + Send;
}

/// Pure bookkeeping of what is registered and what has been `Up`.
#[derive(Debug, Default)]
pub struct Book {
    table: String,
    registered: Target,
    /// Peers whose session has been `Up` since they were registered.
    was_up: HashSet<Peer>,
}

impl Book {
    fn key(&self, peer: &Peer, want: &Want) -> SessionKey {
        SessionKey {
            aggregate: None,
            table: self.table.clone(),
            peer: peer.0,
            local: want.local,
            interface: want.interface.clone(),
            multihop: false,
        }
    }

    /// The requests that bring `nos-bfdd` in line with `target` in `table`
    /// (a re-`Register` is the profile refresh).
    pub fn sync(&mut self, table: &str, target: &Target) -> Vec<BfdRequest> {
        let mut reqs = Vec::new();
        if self.table != table {
            for (peer, want) in &self.registered {
                reqs.push(BfdRequest::Deregister {
                    key: self.key(peer, want),
                });
            }
            self.registered.clear();
            self.was_up.clear();
            self.table = table.to_string();
        }
        for (peer, want) in target {
            let old = self.registered.get(peer);
            if old == Some(want) {
                continue;
            }
            // A different local address is a different session: the old one goes.
            if let Some(old) = old.filter(|o| o.local != want.local) {
                reqs.push(BfdRequest::Deregister {
                    key: self.key(peer, old),
                });
                self.was_up.remove(peer);
            }
            reqs.push(BfdRequest::Register {
                table: self.table.clone(),
                peer: peer.0,
                local: want.local,
                interface: want.interface.clone(),
                profile: want.profile.clone(),
                multihop: false,
            });
            self.registered.insert(peer.clone(), want.clone());
        }
        let gone: Vec<Peer> = self
            .registered
            .keys()
            .filter(|p| !target.contains_key(p))
            .cloned()
            .collect();
        for peer in gone {
            let want = self.registered.remove(&peer).expect("just listed");
            self.was_up.remove(&peer);
            reqs.push(BfdRequest::Deregister {
                key: self.key(&peer, &want),
            });
        }
        reqs
    }

    /// A state event: whether it is a failure to act on, i.e. the session
    /// was `Up` and is now `Down` (not `AdminDown`, RFC 5882 §3.2).
    pub fn on_state(&mut self, key: &SessionKey, state: BfdState, diag: BfdDiag) -> bool {
        let peer = (key.peer, key.interface.clone());
        if key.table != self.table || !self.registered.contains_key(&peer) {
            return false;
        }
        match state {
            BfdState::Up => {
                self.was_up.insert(peer);
                false
            }
            BfdState::Down => self.was_up.remove(&peer) && diag != BfdDiag::AdministrativelyDown,
            BfdState::Init | BfdState::AdminDown => {
                self.was_up.remove(&peer);
                false
            }
        }
    }

    /// The connection is gone: the next one registers everything again.
    pub fn reset(&mut self) {
        self.registered.clear();
        self.was_up.clear();
    }
}

pub fn spawn<H: Host>(
    watchdog_socket: PathBuf,
    host: Arc<H>,
    table_rx: watch::Receiver<Option<String>>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(run(watchdog_socket, host, table_rx, shutdown))
}

async fn wait_retry(shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(RETRY_DELAY) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

async fn wanted<H: Host>(host: &H, table_rx: &watch::Receiver<Option<String>>) -> (String, Target) {
    let table = table_rx.borrow().clone();
    match table {
        Some(table) => (table, host.target().await),
        None => (String::new(), Target::new()),
    }
}

async fn run<H: Host>(
    watchdog_socket: PathBuf,
    host: Arc<H>,
    table_rx: watch::Receiver<Option<String>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut book = Book::default();
    while !*shutdown.borrow() {
        // Nothing wants a session: leave nos-bfdd alone until something does.
        if wanted(&*host, &table_rx).await.1.is_empty() {
            tokio::select! {
                () = tokio::time::sleep(POLL) => {}
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
        let mut tick = tokio::time::interval(POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        'conn: loop {
            tokio::select! {
                _ = tick.tick() => {
                    let (table, target) = wanted(&*host, &table_rx).await;
                    for req in book.sync(&table, &target) {
                        if writer.send(req).await.is_err() {
                            break 'conn;
                        }
                    }
                }
                ev = reader.next() => match ev {
                    Some(Ok(BfdEvent::State { key, state, diag, .. })) => {
                        if book.on_state(&key, state, diag) {
                            host.down(key.peer, key.interface, diag).await;
                        }
                    }
                    Some(Ok(BfdEvent::Sessions(_) | BfdEvent::Reflector(_))) => {}
                    Some(Err(_)) | None => break,
                },
                _ = shutdown.changed() => if *shutdown.borrow() { return },
            }
        }
        warn!("lost nos-bfdd, ospf neighbors are no longer bfd-guarded");
        book.reset();
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

    fn want(local: Option<&str>, interface: Option<&str>) -> Want {
        Want {
            profile: BfdProfile::default(),
            local: local.map(ip),
            interface: interface.map(str::to_string),
        }
    }

    fn target(peers: &[&str]) -> Target {
        peers
            .iter()
            .map(|p| ((ip(p), None), want(Some("192.0.2.254"), None)))
            .collect()
    }

    fn key(table: &str, peer: &str) -> SessionKey {
        SessionKey {
            aggregate: None,
            table: table.into(),
            peer: ip(peer),
            local: Some(ip("192.0.2.254")),
            interface: None,
            multihop: false,
        }
    }

    #[test]
    fn registers_new_and_deregisters_gone_and_moved_table() {
        let mut b = Book::default();
        let t = target(&["192.0.2.1"]);
        assert!(matches!(
            b.sync("rt1", &t).as_slice(),
            [BfdRequest::Register { peer, multihop: false, .. }] if *peer == ip("192.0.2.1")
        ));
        assert_eq!(b.sync("rt1", &t), vec![]);
        let reqs = b.sync("rt2", &t);
        assert_eq!(reqs.len(), 2);
        assert_eq!(
            reqs[0],
            BfdRequest::Deregister {
                key: key("rt1", "192.0.2.1")
            }
        );
        assert_eq!(
            b.sync("rt2", &Target::new()),
            vec![BfdRequest::Deregister {
                key: key("rt2", "192.0.2.1")
            }]
        );
    }

    #[test]
    fn link_local_peer_carries_its_interface_and_a_moved_path_replaces_the_session() {
        let mut b = Book::default();
        let mut t = Target::new();
        t.insert(
            (ip("fe80::2"), Some("eth1".into())),
            want(Some("fe80::1"), Some("eth1")),
        );
        assert!(matches!(
            b.sync("rt1", &t).as_slice(),
            [BfdRequest::Register { interface: Some(i), local: Some(_), .. }] if i == "eth1"
        ));
        t.insert(
            (ip("fe80::2"), Some("eth1".into())),
            want(Some("fe80::9"), Some("eth1")),
        );
        assert!(matches!(
            b.sync("rt1", &t).as_slice(),
            [BfdRequest::Deregister { .. }, BfdRequest::Register { .. }]
        ));
    }

    fn ll_key(interface: &str) -> SessionKey {
        SessionKey {
            interface: Some(interface.into()),
            local: Some(ip("fe80::1")),
            ..key("rt1", "fe80::2")
        }
    }

    #[test]
    fn one_link_local_peer_on_two_interfaces_is_two_sessions_and_downs_are_per_interface() {
        let mut b = Book::default();
        let mut t = Target::new();
        for i in ["eth0", "eth1"] {
            t.insert(
                (ip("fe80::2"), Some(i.into())),
                want(Some("fe80::1"), Some(i)),
            );
        }
        let reqs = b.sync("rt1", &t);
        assert_eq!(reqs.len(), 2, "{reqs:?}");
        assert!(reqs
            .iter()
            .all(|r| matches!(r, BfdRequest::Register { .. })));
        let d = BfdDiag::ControlDetectionTimeExpired;
        for i in ["eth0", "eth1"] {
            assert!(!b.on_state(&ll_key(i), BfdState::Up, d));
        }
        // eth1 drops: only eth1's neighbor is killed, eth0's stays guarded.
        assert!(b.on_state(&ll_key("eth1"), BfdState::Down, d));
        assert!(!b.on_state(&ll_key("eth1"), BfdState::Down, d));
        assert!(b.on_state(&ll_key("eth0"), BfdState::Down, d));
        // Withdrawing one neighbor deregisters only its session.
        t.remove(&(ip("fe80::2"), Some("eth0".into())));
        assert!(matches!(
            b.sync("rt1", &t).as_slice(),
            [BfdRequest::Deregister { key }] if key.interface.as_deref() == Some("eth0")
        ));
    }

    #[test]
    fn only_up_to_down_is_a_failure_and_admin_down_is_not() {
        let mut b = Book::default();
        b.sync("rt1", &target(&["192.0.2.1"]));
        let k = key("rt1", "192.0.2.1");
        let d = BfdDiag::ControlDetectionTimeExpired;
        // A fresh Register's initial Down is not a failure.
        assert!(!b.on_state(&k, BfdState::Down, d));
        assert!(!b.on_state(&k, BfdState::Init, d));
        assert!(!b.on_state(&k, BfdState::Up, d));
        assert!(b.on_state(&k, BfdState::Down, d));
        assert!(!b.on_state(&k, BfdState::Down, d), "once per Up");
        // Local shutdown: AdminDown, then Down with the admin diag.
        b.on_state(&k, BfdState::Up, d);
        assert!(!b.on_state(&k, BfdState::AdminDown, BfdDiag::AdministrativelyDown));
        assert!(!b.on_state(&k, BfdState::Down, BfdDiag::AdministrativelyDown));
        // Other tables and strangers.
        b.on_state(&k, BfdState::Up, d);
        assert!(!b.on_state(&key("rt2", "192.0.2.1"), BfdState::Down, d));
        assert!(!b.on_state(&key("rt1", "192.0.2.9"), BfdState::Down, d));
    }

    #[test]
    fn reset_forgets_everything_so_the_next_connection_registers_again() {
        let mut b = Book::default();
        let t = target(&["192.0.2.1"]);
        b.sync("rt1", &t);
        b.reset();
        assert_eq!(b.sync("rt1", &t).len(), 1);
    }
}
