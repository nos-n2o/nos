//! RFC 7130 micro-BFD: one session per member link of every `PortAggregate`
//! with `bfd` set, derived from the running config (`wanted`) and driven
//! through the same `Manager` as every other session, then the aggregate's
//! Up set pushed to `nos-interfaced` (`UpSets`), the only thing gating a
//! member's enslavement.
//!
//! - Sessions run on the member itself (`socket::MicroTx`), independent of
//!   whether the bond has enslaved it, so a released member keeps probing and
//!   comes back by itself.
//! - ponytail: sessions exist for every configured member, not only those
//!   LACP calls Distributing/Standby (RFC 7130 §3): that would need a
//!   `nos-lacpd` to `nos-bfdd` channel. The cost is a probe on a link LACP
//!   has not selected yet.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use nos_proto::schema::BfdProfile;
use nos_proto::{BfdAggregateMembers, BfdState, Config, DiffScope, Event, SessionKey};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::manager::Manager;
use crate::socket::ReflectorNet;

const RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// Insurance against a missed diff, like `nos-lacpd`'s.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

/// The sessions `cfg` asks for: per aggregate with `bfd` and `bfd-peer`, one
/// per member interface, sourced from the bond's untagged address of the
/// peer's family. An aggregate whose profile or source address is missing
/// (the commit-time check forbids it) gets none.
pub fn wanted(cfg: &Config) -> Vec<(SessionKey, BfdProfile)> {
    let mut out = Vec::new();
    for agg in &cfg.port_aggregates {
        let (Some(name), Some(peer)) = (&agg.bfd, agg.bfd_peer) else {
            continue;
        };
        let Some(profile) = cfg.bfd_profiles.iter().find(|p| &p.name == name) else {
            continue;
        };
        let Some(local) = agg
            .subinterfaces
            .iter()
            .filter(|s| s.tag == 0)
            .flat_map(|s| &s.addresses)
            .map(|a| a.address.addr())
            .find(|a| a.is_ipv4() == peer.is_ipv4())
        else {
            continue;
        };
        for member in cfg
            .interfaces
            .iter()
            .filter(|i| i.port_aggregate.as_deref() == Some(agg.name.as_str()))
        {
            out.push((
                SessionKey {
                    table: String::new(),
                    peer,
                    local: Some(local),
                    interface: Some(member.name.clone()),
                    multihop: false,
                    aggregate: Some(agg.name.clone()),
                },
                profile.clone(),
            ));
        }
    }
    out
}

/// Which sessions are Up, and what was last pushed per aggregate. A change
/// of an aggregate's Up set returns the push to send (the whole set); no
/// push, no change. An aggregate never pushed is "nothing Up" for
/// `nos-interfaced` already.
#[derive(Default)]
pub struct UpSets {
    state: HashMap<SessionKey, bool>,
    sent: HashMap<String, Vec<String>>,
}

impl UpSets {
    pub fn set(&mut self, key: &SessionKey, up: bool) -> Option<BfdAggregateMembers> {
        self.state.insert(key.clone(), up);
        self.recompute(key)
    }

    pub fn remove(&mut self, key: &SessionKey) -> Option<BfdAggregateMembers> {
        self.state.remove(key);
        self.recompute(key)
    }

    fn recompute(&mut self, key: &SessionKey) -> Option<BfdAggregateMembers> {
        let aggregate = key.aggregate.clone()?;
        let mut up: Vec<String> = self
            .state
            .iter()
            .filter(|(k, up)| **up && k.aggregate.as_ref() == Some(&aggregate))
            .filter_map(|(k, _)| k.interface.clone())
            .collect();
        up.sort();
        let last = self.sent.get(&aggregate).map_or(&[][..], Vec::as_slice);
        if up == last {
            return None;
        }
        self.sent.insert(aggregate.clone(), up.clone());
        Some(BfdAggregateMembers {
            aggregate,
            up_members: up,
        })
    }
}

/// The running micro-BFD sessions.
pub struct Micro {
    mgr: Arc<Manager>,
    client: u64,
    sessions: HashMap<SessionKey, (BfdProfile, JoinHandle<()>)>,
    ups: Arc<Mutex<UpSets>>,
    push: mpsc::Sender<BfdAggregateMembers>,
}

impl Micro {
    pub fn new(mgr: Arc<Manager>, push: mpsc::Sender<BfdAggregateMembers>) -> Self {
        let client = mgr.new_client("micro-bfd");
        Micro {
            mgr,
            client,
            sessions: HashMap::new(),
            ups: Arc::default(),
            push,
        }
    }

    /// Makes the running sessions equal to `wanted`: new ones start, gone ones
    /// stop (their member leaves the Up set), a changed profile runs
    /// Poll/Final through `Manager::register` without a flap.
    pub async fn apply(&mut self, wanted: Vec<(SessionKey, BfdProfile)>) {
        let keep: HashSet<&SessionKey> = wanted.iter().map(|(k, _)| k).collect();
        let gone: Vec<SessionKey> = self
            .sessions
            .keys()
            .filter(|k| !keep.contains(k))
            .cloned()
            .collect();
        for key in gone {
            if let Some((_, task)) = self.sessions.remove(&key) {
                task.abort();
            }
            self.mgr.deregister(self.client, &key);
            let push = self.ups.lock().unwrap().remove(&key);
            if let Some(p) = push {
                let _ = self.push.send(p).await;
            }
        }
        for (key, profile) in wanted {
            match self.sessions.get_mut(&key) {
                Some((have, _)) if *have == profile => {}
                Some((have, _)) => {
                    have.clone_from(&profile);
                    self.mgr.register(self.client, &key, &profile);
                }
                None => {
                    let rx = self.mgr.register(self.client, &key, &profile);
                    let task = tokio::spawn(watch_state(
                        key.clone(),
                        rx,
                        self.ups.clone(),
                        self.push.clone(),
                    ));
                    self.sessions.insert(key, (profile, task));
                }
            }
        }
    }

    pub fn stop(&mut self) {
        for (_, (_, task)) in self.sessions.drain() {
            task.abort();
        }
        self.mgr.drop_client(self.client);
    }
}

async fn watch_state(
    key: SessionKey,
    mut rx: watch::Receiver<crate::session::Status>,
    ups: Arc<Mutex<UpSets>>,
    push: mpsc::Sender<BfdAggregateMembers>,
) {
    loop {
        let up = rx.borrow_and_update().state == BfdState::Up;
        let msg = ups.lock().unwrap().set(&key, up);
        if let Some(m) = msg {
            info!(aggregate = %m.aggregate, up = ?m.up_members, "micro-bfd member set changed");
            if push.send(m).await.is_err() {
                return;
            }
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Follows the running config for the daemon's lifetime, like `nos-lacpd`'s
/// `reconcile::run`: any diff of the sections that matter re-derives the
/// sessions from a fresh `Get`.
pub async fn run(
    config_socket: PathBuf,
    mut micro: Micro,
    reflector: Arc<ReflectorNet>,
    mut shutdown: watch::Receiver<bool>,
) {
    let scopes = vec![
        DiffScope::Interfaces,
        DiffScope::PortAggregates,
        DiffScope::BfdProfiles,
        // The S-BFD reflector (#294) rides on the same resync.
        DiffScope::SbfdReflector,
        DiffScope::RoutingTables,
        // Profile auth keys are admin-keystore labels (#510).
        DiffScope::Admin,
    ];
    while !*shutdown.borrow() {
        match nos_daemon::config::subscribe_diff(&config_socket, scopes.clone()).await {
            Ok(mut reader) => {
                info!(socket = %config_socket.display(), "connected to nos-configd diff stream");
                let mut tick = tokio::time::interval(REAPPLY_INTERVAL);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => resync(&config_socket, &mut micro, &reflector).await,
                            Some(Ok(_)) => {}
                            Some(Err(e)) => {
                                warn!(error = %e, "error reading diff stream, reconnecting");
                                break;
                            }
                            None => {
                                warn!("diff stream closed, reconnecting");
                                break;
                            }
                        },
                        // The first tick is immediate: the initial sync.
                        _ = tick.tick() => resync(&config_socket, &mut micro, &reflector).await,
                        _ = shutdown.changed() => break,
                    }
                }
            }
            Err(e) => warn!(error = %e, "failed to connect to nos-configd"),
        }
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            () = tokio::time::sleep(RECONNECT_DELAY) => {}
            _ = shutdown.changed() => {}
        }
    }
    micro.stop();
}

async fn resync(config_socket: &Path, micro: &mut Micro, reflector: &ReflectorNet) {
    match nos_daemon::config::fetch_config(config_socket).await {
        Ok(cfg) => {
            // Keys first: sessions started below resolve their labels at once.
            micro.mgr.set_keys(
                cfg.admin
                    .keys
                    .iter()
                    .map(|k| (k.label.clone(), k.secret.clone()))
                    .collect(),
            );
            let wanted = wanted(&cfg);
            debug!(sessions = wanted.len(), "reconciling micro-bfd sessions");
            micro.apply(wanted).await;
            micro.mgr.set_unsolicited(crate::unsolicited::wanted(&cfg));
            micro.mgr.listen_unsolicited().await;
            reflector.configure(&cfg).await;
        }
        Err(e) => warn!(error = %e, "failed to fetch running config, keeping previous state"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::tests::mgr;
    use nos_proto::schema::{InterfaceAddress, Subinterface};
    use nos_proto::{Interface, PortAggregate};

    fn config(peer: &str, addr: &str) -> Config {
        let mut agg = PortAggregate {
            name: "bond0".into(),
            bfd: Some("fast".into()),
            bfd_peer: Some(peer.parse().unwrap()),
            ..PortAggregate::default()
        };
        agg.subinterfaces = vec![Subinterface {
            tag: 0,
            addresses: vec![InterfaceAddress {
                address: addr.parse().unwrap(),
                label: None,
            }],
            ..Subinterface::default()
        }];
        let member = |n: &str, agg: Option<&str>| Interface {
            name: n.into(),
            port_aggregate: agg.map(Into::into),
            ..Interface::default()
        };
        Config {
            port_aggregates: vec![agg],
            interfaces: vec![
                member("eth1", Some("bond0")),
                member("eth2", Some("bond0")),
                member("eth3", None),
            ],
            bfd_profiles: vec![BfdProfile {
                name: "fast".into(),
                ..BfdProfile::default()
            }],
            ..Config::default()
        }
    }

    #[test]
    fn one_session_per_member_from_the_bond_address() {
        let w = wanted(&config("10.0.0.2", "10.0.0.1/31"));
        let keys: Vec<_> = w
            .iter()
            .map(|(k, _)| (k.interface.clone().unwrap(), k.local.unwrap().to_string()))
            .collect();
        assert_eq!(
            keys,
            [
                ("eth1".into(), "10.0.0.1".into()),
                ("eth2".into(), "10.0.0.1".into())
            ]
        );
        assert!(w
            .iter()
            .all(|(k, _)| k.aggregate.as_deref() == Some("bond0")
                && k.peer.to_string() == "10.0.0.2"
                && !k.multihop));
    }

    #[test]
    fn nothing_without_profile_source_or_bfd() {
        let mut c = config("10.0.0.2", "10.0.0.1/31");
        c.bfd_profiles.clear();
        assert_eq!(wanted(&c).len(), 0);
        // The peer's family has no address on the bond.
        assert_eq!(wanted(&config("2001:db8::2", "10.0.0.1/31")).len(), 0);
        let mut c = config("10.0.0.2", "10.0.0.1/31");
        c.port_aggregates[0].bfd = None;
        assert_eq!(wanted(&c).len(), 0);
    }

    fn key(member: &str) -> SessionKey {
        wanted(&config("10.0.0.2", "10.0.0.1/31"))
            .into_iter()
            .map(|(k, _)| k)
            .find(|k| k.interface.as_deref() == Some(member))
            .unwrap()
    }

    #[test]
    fn up_set_is_pushed_whole_and_only_on_change() {
        let mut u = UpSets::default();
        let push = |p: Option<BfdAggregateMembers>| p.map(|p| p.up_members);
        // Down from the start: nothing to say, `nos-interfaced` fails closed.
        assert_eq!(push(u.set(&key("eth1"), false)), None);
        assert_eq!(push(u.set(&key("eth2"), true)), Some(vec!["eth2".into()]));
        assert_eq!(push(u.set(&key("eth2"), true)), None);
        assert_eq!(
            push(u.set(&key("eth1"), true)),
            Some(vec!["eth1".into(), "eth2".into()])
        );
        assert_eq!(push(u.set(&key("eth2"), false)), Some(vec!["eth1".into()]));
        // The session goes away (bfd removed): the set empties.
        assert_eq!(push(u.remove(&key("eth1"))), Some(vec![]));
        assert_eq!(push(u.remove(&key("eth1"))), None);
    }

    #[tokio::test]
    async fn apply_starts_and_stops_sessions() {
        let (m, _, _) = mgr(false);
        let (tx, _rx) = mpsc::channel(8);
        let mut micro = Micro::new(m.clone(), tx);
        let cfg = config("10.0.0.2", "10.0.0.1/31");
        micro.apply(wanted(&cfg)).await;
        assert_eq!(m.sessions(None).len(), 2);
        // A timer edit keeps the sessions (same keys, Poll/Final).
        let mut edited = wanted(&cfg);
        for (_, p) in &mut edited {
            p.min_tx_interval = 50;
        }
        let before: Vec<_> = m
            .sessions(None)
            .iter()
            .map(|s| s.local_discriminator)
            .collect();
        micro.apply(edited).await;
        let after: Vec<_> = m
            .sessions(None)
            .iter()
            .map(|s| s.local_discriminator)
            .collect();
        assert_eq!(before, after);
        // Removing `bfd` stops them.
        micro.apply(vec![]).await;
        assert_eq!(m.sessions(None).len(), 0);
    }
}
