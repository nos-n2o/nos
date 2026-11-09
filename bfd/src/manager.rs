//! The session table: one task per `SessionKey`, shared by every client
//! that registered it and dropped with the last one. Also the receive-side
//! demultiplexer the sockets feed.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use nos_proto::schema::{BfdMode, BfdProfile, EchoMode};
use nos_proto::{BfdSessionKind, BfdSessionView, BfdState, SessionKey};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::auth::AuthKey;
use crate::micro;
use crate::packet::{self, Packet};
use crate::reflector::Reflector;
use crate::sbfd::{self, Initiator, SbfdPath};
use crate::session::{self, Core, EchoPath, Status, Tx};
use crate::unsolicited::{self, Decision};

/// How long a session waits before retrying a failed `Net::open` (the VRF
/// not known to `nos-ribd` yet, no route to the peer, ...).
const OPEN_RETRY: Duration = Duration::from_secs(1);

/// How long a retiring session may take to put its `AdminDown` on the wire:
/// twice its tx interval, within these bounds (#659).
const GRACE_MIN: Duration = Duration::from_millis(300);
const GRACE_MAX: Duration = Duration::from_secs(2);

/// Opens the transmit path of a session and makes sure its receive socket
/// runs. The real one is `socket::UdpNet`.
#[async_trait]
pub trait Net: Send + Sync {
    async fn open(&self, key: &SessionKey) -> io::Result<Arc<dyn Tx>>;

    /// The Echo transport of a single-hop session with local discriminator
    /// `disc`; `None` when it cannot be had (the session then never runs
    /// Echo).
    /// `unaffiliated`: RFC 9747, Echo is the whole session (no Control
    /// traffic ever resolves the neighbour, so the transport must).
    /// RFC 7881 §2: the transport of an S-BFD initiator, a socket of its own
    /// (source port other than 7784) that the reflections come back to.
    /// Makes sure `table`'s single-hop receive socket runs, though no session
    /// opened it (RFC 9468: the first packet of an unsolicited peer must be
    /// heard).
    async fn listen(&self, _table: &str, _v6: bool) -> io::Result<()> {
        Ok(())
    }

    async fn open_sbfd(&self, _key: &SessionKey) -> io::Result<SbfdPath> {
        Err(io::Error::other("no S-BFD transport"))
    }

    async fn open_echo(
        &self,
        _key: &SessionKey,
        _disc: u32,
        _unaffiliated: bool,
    ) -> Option<EchoPath> {
        None
    }
}

/// A session as the receive path sees it.
#[derive(Clone)]
struct Slot {
    tx: mpsc::Sender<Packet>,
    multihop: bool,
    /// RFC 5883 §5 / GTSM floor from the profile (multihop only).
    min_ttl: u8,
    /// RFC 7130 §2.2: a micro-BFD session only takes packets that arrived on
    /// its member link.
    member: Option<String>,
}

/// The `by_peer` table half of `key`: the routing table, or a member's own.
fn peer_table(key: &SessionKey) -> String {
    match (&key.aggregate, &key.interface) {
        (Some(_), Some(member)) => micro::demux_table(member),
        _ => key.table.clone(),
    }
}

/// RFC 5881 §5: single-hop packets must arrive with TTL 255; RFC 5883 §5:
/// multihop ones with at least the profile's `minimum-ttl`.
pub fn ttl_ok(multihop: bool, ttl: Option<u8>, min_ttl: u8) -> bool {
    match ttl {
        Some(t) if multihop => t >= min_ttl,
        Some(t) => t == 255,
        None => false,
    }
}

/// Called for a single-hop packet with Your Discriminator 0 that no session
/// claims (table, source, TTL, packet): whether it made a session (RFC 9468).
type Unsolicited = Arc<dyn Fn(&str, IpAddr, Option<u8>, &Packet) -> bool + Send + Sync>;

#[derive(Default)]
struct Tables {
    unsolicited: Option<Unsolicited>,
    by_disc: HashMap<u32, Slot>,
    /// Packets with Your Discriminator 0 (§6.8.6: found by source address
    /// and table, plus the port the packet came in on). ponytail: no
    /// interface in the single-hop key (RFC 5881 §4 mentions it) and no
    /// local address in the multihop one (RFC 5883 §4 wants the pair), so two
    /// sessions to one peer address in one table collide; add the arrival
    /// interface / destination from `IP_PKTINFO` if that matters.
    by_peer: HashMap<(String, IpAddr, bool), Slot>,
}

/// Maps received datagrams to session tasks. Cloned into every socket task.
#[derive(Clone, Default)]
pub struct Demux(Arc<Mutex<Tables>>);

impl Demux {
    fn add(&self, disc: u32, key: &SessionKey, tx: &mpsc::Sender<Packet>, min_ttl: u8) {
        let mut t = self.0.lock().unwrap();
        let slot = Slot {
            tx: tx.clone(),
            multihop: key.multihop,
            min_ttl,
            member: key.aggregate.as_ref().and(key.interface.clone()),
        };
        t.by_disc.insert(disc, slot.clone());
        t.by_peer
            .insert((peer_table(key), key.peer, key.multihop), slot);
    }

    fn set_min_ttl(&self, disc: u32, key: &SessionKey, min_ttl: u8) {
        let mut t = self.0.lock().unwrap();
        if let Some(s) = t.by_disc.get_mut(&disc) {
            s.min_ttl = min_ttl;
        }
        if let Some(s) = t
            .by_peer
            .get_mut(&(peer_table(key), key.peer, key.multihop))
        {
            s.min_ttl = min_ttl;
        }
    }

    fn remove(&self, disc: u32, key: &SessionKey) {
        let mut t = self.0.lock().unwrap();
        t.by_disc.remove(&disc);
        t.by_peer.remove(&(peer_table(key), key.peer, key.multihop));
    }

    /// Decodes `data` (received on `table`'s single-hop or `multihop` socket
    /// from `src` with `ttl`) and hands it to its session. Whether a session
    /// took it.
    pub fn route(
        &self,
        table: &str,
        src: IpAddr,
        multihop: bool,
        ttl: Option<u8>,
        data: &[u8],
    ) -> bool {
        self.route_on(table, None, src, multihop, ttl, data)
    }

    /// A micro-BFD packet (already TTL-checked by `micro::parse_frame`) that
    /// arrived on LAG member `member`.
    pub fn route_micro(&self, member: &str, src: IpAddr, data: &[u8]) -> bool {
        self.route_on(
            &micro::demux_table(member),
            Some(member),
            src,
            false,
            Some(255),
            data,
        )
    }

    fn route_on(
        &self,
        table: &str,
        member: Option<&str>,
        src: IpAddr,
        multihop: bool,
        ttl: Option<u8>,
        data: &[u8],
    ) -> bool {
        let p = match packet::decode(data) {
            Ok(p) => p,
            Err(e) => {
                debug!(peer = %src, error = %e, "bfd packet discarded");
                return false;
            }
        };
        let mut t = self.0.lock().unwrap();
        if p.your_discriminator == 0
            && !multihop
            && member.is_none()
            && !t.by_peer.contains_key(&(table.to_string(), src, multihop))
            && let Some(hook) = t.unsolicited.clone()
        {
            drop(t);
            // The hook registers a session (taking this lock): look again.
            hook(table, src, ttl, &p);
            t = self.0.lock().unwrap();
        }
        let session = if p.your_discriminator == 0 {
            t.by_peer.get(&(table.to_string(), src, multihop))
        } else {
            t.by_disc
                .get(&p.your_discriminator)
                .filter(|s| s.multihop == multihop && s.member.as_deref() == member)
        };
        let Some(s) = session else { return false };
        if !ttl_ok(multihop, ttl, s.min_ttl) {
            debug!(peer = %src, ttl = ?ttl, multihop, "bfd packet discarded: ttl");
            return false;
        }
        // A full queue drops the packet: BFD tolerates loss by design.
        s.tx.try_send(p).is_ok()
    }
}

struct Entry {
    clients: HashSet<u64>,
    /// RFC 9468: created by a packet, no client holds it; a client that
    /// registers the key adopts it.
    unsolicited: bool,
    /// Since when an unsolicited session has not been Up (`unsolicited::age_step`).
    idle_since: Option<Instant>,
    profile: BfdProfile,
    disc: u32,
    cmd: mpsc::Sender<session::Cmd>,
    status: watch::Receiver<Status>,
    task: JoinHandle<()>,
}

pub struct Manager {
    net: Arc<dyn Net>,
    demux: Demux,
    sessions: Mutex<HashMap<SessionKey, Entry>>,
    next_disc: AtomicU32,
    next_client: AtomicU64,
    reflector: Arc<Reflector>,
    /// The subinterfaces that answer unsolicited BFD (`set_unsolicited`).
    rules: Mutex<Vec<unsolicited::Rule>>,
    last_cap_warn: Mutex<Option<Instant>>,
    /// The admin keystore (`Config.admin`), label to secret (#510). Locked
    /// after `sessions`, never before.
    keys: Mutex<HashMap<String, String>>,
}

impl Manager {
    pub fn new(net: Arc<dyn Net>, demux: Demux) -> Arc<Self> {
        let m = Arc::new(Manager {
            net,
            demux,
            sessions: Mutex::default(),
            // Random start (§6.8.1: not guessable), never 0.
            next_disc: AtomicU32::new(session::rand_u32() | 1),
            next_client: AtomicU64::new(1),
            reflector: Arc::default(),
            rules: Mutex::default(),
            last_cap_warn: Mutex::default(),
            keys: Mutex::default(),
        });
        let weak = Arc::downgrade(&m);
        m.demux.0.lock().unwrap().unsolicited = Some(Arc::new(move |table, src, ttl, p| {
            weak.upgrade()
                .is_some_and(|m| m.unsolicited_rx(table, src, ttl, p))
        }));
        m
    }

    /// `profile`'s auth key from the keystore. `None` for no auth, and for a
    /// label that is not there: the session then stays down (fail closed).
    fn resolve(&self, profile: &BfdProfile) -> Option<AuthKey> {
        let a = profile.auth.as_ref()?;
        let secret = self.keys.lock().unwrap().get(&a.key).cloned();
        if secret.is_none() {
            warn!(label = %a.key, "bfd auth key not found");
        }
        secret.map(|s| AuthKey::new(a, &s))
    }

    /// Replaces the admin keystore. Every running session that authenticates
    /// is handed its key again: the old one stays accepted for a few
    /// detection times, so a rotation under the same label does not flap.
    pub fn set_keys(&self, keys: HashMap<String, String>) {
        let sessions = self.sessions.lock().unwrap();
        if *self.keys.lock().unwrap() == keys {
            return;
        }
        *self.keys.lock().unwrap() = keys;
        for e in sessions.values().filter(|e| e.profile.auth.is_some()) {
            let _ = e
                .cmd
                .try_send((e.profile.clone(), self.resolve(&e.profile)));
        }
    }

    /// The S-BFD reflector's state: the socket side feeds it, `GetReflector`
    /// reads it.
    pub fn reflector(&self) -> Arc<Reflector> {
        self.reflector.clone()
    }

    pub fn new_client(&self) -> u64 {
        self.next_client.fetch_add(1, Ordering::Relaxed)
    }

    /// A discriminator from the daemon-wide counter, skipping 0 and any in
    /// use (4 billion values, so the scan is nearly never a second step).
    fn alloc_disc(&self, taken: &HashMap<SessionKey, Entry>) -> u32 {
        loop {
            let d = self.next_disc.fetch_add(1, Ordering::Relaxed);
            if d != 0 && !taken.values().any(|e| e.disc == d) {
                return d;
            }
        }
    }

    /// Adds `client` to the session `key`, starting it if it is new, and
    /// applies `profile` (a changed one runs Poll/Final). The status receiver
    /// holds the session's current state. ponytail: the last registration's
    /// profile wins when two clients disagree about one key.
    pub fn register(
        &self,
        client: u64,
        key: &SessionKey,
        profile: &BfdProfile,
    ) -> watch::Receiver<Status> {
        let mut sessions = self.sessions.lock().unwrap();
        self.start(&mut sessions, Some(client), key, profile, false)
    }

    fn start(
        &self,
        sessions: &mut HashMap<SessionKey, Entry>,
        client: Option<u64>,
        key: &SessionKey,
        profile: &BfdProfile,
        unsolicited: bool,
    ) -> watch::Receiver<Status> {
        if client.is_some() {
            // A client takes over an unsolicited session of the same peer: the
            // very key adopts it below, another one (different interface) goes.
            let stale: Vec<SessionKey> = sessions
                .iter()
                .filter(|(k, e)| {
                    e.unsolicited && k.table == key.table && k.peer == key.peer && *k != key
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in stale {
                self.release_all(sessions, &k);
            }
        }
        // The mode decides what the session is made of (a Control socket and
        // demux slot, or Echo alone): switching it starts a fresh session.
        // ponytail: the old one's clients are not carried over, they re-register.
        let echo_only = profile.echo_mode == EchoMode::Unaffiliated;
        let sbfd = profile.mode == BfdMode::Sbfd;
        if sessions.get(key).is_some_and(|e| {
            (e.profile.echo_mode == EchoMode::Unaffiliated) != echo_only
                || (e.profile.mode == BfdMode::Sbfd) != sbfd
        }) {
            self.release_all(sessions, key);
        }
        if let Some(e) = sessions.get_mut(key) {
            if let Some(c) = client {
                e.clients.insert(c);
                e.unsolicited = false;
                e.idle_since = None;
            }
            if e.profile != *profile {
                e.profile = profile.clone();
                self.demux.set_min_ttl(e.disc, key, profile.minimum_ttl);
                let _ = e.cmd.try_send((profile.clone(), self.resolve(profile)));
            }
            return e.status.clone();
        }
        let disc = self.alloc_disc(sessions);
        let core = Core::new(
            profile.clone(),
            self.resolve(profile),
            disc,
            tokio::time::Instant::now().into_std(),
        );
        let initiator = sbfd.then(|| {
            Initiator::new(
                profile,
                disc,
                sbfd::remote_discriminator(key.peer, profile),
                tokio::time::Instant::now().into_std(),
            )
        });
        let (status_tx, status_rx) = watch::channel(
            initiator
                .as_ref()
                .map_or_else(|| core.status(), Initiator::status),
        );
        let (pkt_tx, pkt_rx) = mpsc::channel(64);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        if !echo_only && !sbfd {
            self.demux.add(disc, key, &pkt_tx, profile.minimum_ttl);
        }
        info!(peer = %key.peer, table = %key.table, multihop = key.multihop, "bfd session registered");
        let net = self.net.clone();
        let k = key.clone();
        let core_profile = profile.clone();
        let task = tokio::spawn(async move {
            // An unaffiliated session has no Demux slot holding the sender: keep
            // it, or `run` sees the closed channel and ends at once.
            let _pkt_tx = pkt_tx;
            if let Some(initiator) = initiator {
                if sbfd::remote_discriminator(k.peer, &core_profile).is_none() {
                    sbfd::warn_no_discriminator(&k);
                }
                // The reflections come back to the session's own socket.
                let path = loop {
                    match net.open_sbfd(&k).await {
                        Ok(p) => break p,
                        Err(e) => {
                            debug!(peer = %k.peer, table = %k.table, error = %e, "bfd sbfd session not ready, retrying");
                            tokio::time::sleep(OPEN_RETRY).await;
                        }
                    }
                };
                sbfd::run(
                    k,
                    initiator,
                    path,
                    core_profile.minimum_ttl,
                    cmd_rx,
                    status_tx,
                )
                .await;
                return;
            }
            if echo_only {
                // RFC 9747: no Control socket. The Echo transport is retried
                // until the interface has an address towards the peer.
                if k.multihop {
                    warn!(peer = %k.peer, table = %k.table, "bfd unaffiliated echo needs a single-hop session");
                    return;
                }
                let path = loop {
                    if let Some(p) = net.open_echo(&k, disc, true).await {
                        break p;
                    }
                    tokio::time::sleep(OPEN_RETRY).await;
                };
                session::run(
                    k,
                    core,
                    Arc::new(session::NoTx),
                    Some(path),
                    pkt_rx,
                    cmd_rx,
                    status_tx,
                )
                .await;
                return;
            }
            let tx = loop {
                match net.open(&k).await {
                    Ok(tx) => break tx,
                    Err(e) => {
                        debug!(peer = %k.peer, table = %k.table, error = %e, "bfd session not ready, retrying");
                        tokio::time::sleep(OPEN_RETRY).await;
                    }
                }
            };
            let echo = if k.multihop || k.aggregate.is_some() {
                None
            } else {
                net.open_echo(&k, disc, false).await
            };
            session::run(k, core, tx, echo, pkt_rx, cmd_rx, status_tx).await;
        });
        sessions.insert(
            key.clone(),
            Entry {
                clients: client.into_iter().collect(),
                unsolicited,
                idle_since: None,
                profile: profile.clone(),
                disc,
                cmd: cmd_tx,
                status: status_rx.clone(),
                task,
            },
        );
        status_rx
    }

    /// Drops the session `key` whatever clients hold it.
    fn release_all(&self, sessions: &mut HashMap<SessionKey, Entry>, key: &SessionKey) {
        if let Some(e) = sessions.remove(key) {
            self.retire(e, key);
        }
    }

    /// Takes the session out of the receive path now; a classic or micro one
    /// first tells the peer `AdminDown` (RFC 5880 §6.8.16, RFC 5882 §3.2: no
    /// detection-time expiry on its side) and its task is aborted after
    /// `grace`. S-BFD initiators and unaffiliated echo have no Control
    /// packet to send and are aborted at once. Needs a tokio runtime.
    fn retire(&self, e: Entry, key: &SessionKey) {
        self.forget(&e, key);
        info!(peer = %key.peer, table = %key.table, "bfd session removed");
        let Some(grace) = self.announce_down(&e, key) else {
            e.task.abort();
            return;
        };
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            e.task.abort();
        });
    }

    /// Sends the `AdminDown` command; the time the task needs to put it on the
    /// wire (`None` when the session has no Control packets).
    fn announce_down(&self, e: &Entry, key: &SessionKey) -> Option<Duration> {
        if e.profile.mode == BfdMode::Sbfd || e.profile.echo_mode == EchoMode::Unaffiliated {
            return None;
        }
        let profile = BfdProfile {
            shutdown: true,
            ..e.profile.clone()
        };
        let resolved = self.resolve(&profile);
        e.cmd.try_send((profile, resolved)).ok()?;
        info!(peer = %key.peer, table = %key.table, "bfd session admin down sent");
        let tx = Duration::from_micros(u64::from(e.status.borrow().tx_interval_us));
        Some((tx * 2).clamp(GRACE_MIN, GRACE_MAX))
    }

    /// Daemon shutdown: every session announces `AdminDown`, one wait for all.
    pub async fn shutdown_all(&self) {
        let entries: Vec<(SessionKey, Entry)> = self.sessions.lock().unwrap().drain().collect();
        let mut grace = Duration::ZERO;
        let mut tasks = Vec::new();
        for (k, e) in entries {
            self.forget(&e, &k);
            if let Some(g) = self.announce_down(&e, &k) {
                grace = grace.max(g);
            }
            tasks.push(e.task);
        }
        tokio::time::sleep(grace).await;
        for t in tasks {
            t.abort();
        }
    }

    /// Takes a dropped session out of the receive path (an S-BFD one was never in it).
    fn forget(&self, e: &Entry, key: &SessionKey) {
        if e.profile.mode != BfdMode::Sbfd {
            self.demux.remove(e.disc, key);
        }
    }

    fn release(&self, sessions: &mut HashMap<SessionKey, Entry>, client: u64, key: &SessionKey) {
        let Some(e) = sessions.get_mut(key) else {
            return;
        };
        if e.unsolicited {
            return;
        }
        e.clients.remove(&client);
        if e.clients.is_empty() {
            let e = sessions.remove(key).expect("just seen");
            self.retire(e, key);
        }
    }

    pub fn deregister(&self, client: u64, key: &SessionKey) {
        let mut sessions = self.sessions.lock().unwrap();
        self.release(&mut sessions, client, key);
    }

    /// A client's connection went away: it releases everything it held.
    pub fn drop_client(&self, client: u64) {
        let mut sessions = self.sessions.lock().unwrap();
        let keys: Vec<SessionKey> = sessions
            .iter()
            .filter(|(_, e)| e.clients.contains(&client))
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            self.release(&mut sessions, client, &k);
        }
    }

    /// RFC 9468: a packet that matched no session. Creates a passive session
    /// when a rule of `table` covers `src` and `unsolicited::decide` agrees.
    fn unsolicited_rx(&self, table: &str, src: IpAddr, ttl: Option<u8>, p: &Packet) -> bool {
        // Sessions first, as `set_unsolicited` does: a rule dropped meanwhile
        // must not create a session after its sessions were released (#659).
        let mut sessions = self.sessions.lock().unwrap();
        let Some(rule) = unsolicited::rule_for(&self.rules.lock().unwrap(), table, src).cloned()
        else {
            return false;
        };
        let existing = sessions
            .iter()
            .filter(|(k, e)| {
                e.unsolicited && k.table == table && k.interface.as_deref() == Some(&rule.interface)
            })
            .count();
        match unsolicited::decide(p, src, ttl, &rule, existing) {
            Decision::Ignore => false,
            Decision::Capped => {
                let mut last = self.last_cap_warn.lock().unwrap();
                if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(10)) {
                    *last = Some(Instant::now());
                    warn!(interface = %rule.interface, table = %table, cap = unsolicited::MAX_PER_INTERFACE, "bfd unsolicited session limit reached, packet dropped");
                }
                false
            }
            Decision::Create => {
                let key = SessionKey {
                    aggregate: None,
                    table: table.to_string(),
                    peer: src,
                    local: None,
                    interface: Some(rule.interface.clone()),
                    multihop: false,
                };
                info!(peer = %src, table = %table, interface = %rule.interface, "bfd unsolicited session created");
                self.start(&mut sessions, None, &key, &rule.profile, true);
                true
            }
        }
    }

    /// The running config's unsolicited rules. Sessions of a gone rule (or
    /// whose peer left its subnet) are dropped, a changed profile runs
    /// Poll/Final.
    pub fn set_unsolicited(&self, rules: Vec<unsolicited::Rule>) {
        let mut sessions = self.sessions.lock().unwrap();
        let keys: Vec<SessionKey> = sessions
            .iter()
            .filter(|(_, e)| e.unsolicited)
            .map(|(k, _)| k.clone())
            .collect();
        for key in keys {
            let rule = rules.iter().find(|r| {
                r.table == key.table
                    && key.interface.as_deref() == Some(&r.interface)
                    && r.subnets.iter().any(|n| n.contains(&key.peer))
            });
            match rule {
                None => {
                    info!(peer = %key.peer, table = %key.table, "bfd unsolicited session removed: no longer configured");
                    self.release_all(&mut sessions, &key);
                }
                Some(r) => {
                    let e = sessions.get_mut(&key).expect("just listed");
                    if e.profile != r.profile {
                        e.profile = r.profile.clone();
                        self.demux.set_min_ttl(e.disc, &key, r.profile.minimum_ttl);
                        let _ = e
                            .cmd
                            .try_send((r.profile.clone(), self.resolve(&r.profile)));
                    }
                }
            }
        }
        *self.rules.lock().unwrap() = rules;
    }

    /// Opens (or re-checks) the receive socket of every table that has an
    /// unsolicited rule; the config resync repeats it, so a VRF that
    /// appears or is recreated is picked up.
    pub async fn listen_unsolicited(&self) {
        let rules = self.rules.lock().unwrap().clone();
        for r in &rules {
            for v6 in [false, true] {
                if r.subnets.iter().any(|n| n.addr().is_ipv6() == v6)
                    && let Err(e) = self.net.listen(&r.table, v6).await
                {
                    debug!(table = %r.table, error = %e, "bfd unsolicited listener not ready");
                }
            }
        }
    }

    /// Deletes the unsolicited sessions that have not been Up for
    /// `unsolicited::AGE`. Called every second by `sweep_loop`.
    pub fn sweep(&self, now: Instant) {
        let mut sessions = self.sessions.lock().unwrap();
        let mut gone = Vec::new();
        for (k, e) in sessions.iter_mut().filter(|(_, e)| e.unsolicited) {
            let up = e.status.borrow().state == BfdState::Up;
            let (since, expired) = unsolicited::age_step(up, e.idle_since, now);
            e.idle_since = since;
            if expired {
                gone.push(k.clone());
            }
        }
        for k in gone {
            info!(peer = %k.peer, table = %k.table, interface = ?k.interface, "bfd unsolicited session aged out");
            self.release_all(&mut sessions, &k);
        }
    }

    /// Every session (or the ones to `peer`), ordered by table then peer.
    pub fn sessions(&self, peer: Option<IpAddr>) -> Vec<BfdSessionView> {
        let sessions = self.sessions.lock().unwrap();
        let mut all: Vec<BfdSessionView> = sessions
            .iter()
            .filter(|(k, _)| peer.is_none_or(|p| k.peer == p))
            .map(|(k, e)| {
                let s = *e.status.borrow();
                BfdSessionView {
                    key: k.clone(),
                    state: s.state,
                    diag: s.diag,
                    local_discriminator: s.local_discriminator,
                    remote_discriminator: s.remote_discriminator,
                    tx_interval_us: s.tx_interval_us,
                    detection_time_us: s.detection_time_us,
                    auth_method: s.auth_method,
                    auth_key_id: s.auth_key_id,
                    auth_failures: s.auth_failures,
                    echo_active: s.echo_active,
                    echo_interval_us: s.echo_interval_us,
                    echo_only: s.echo_only,
                    tx_pdu_bytes: s.tx_pdu_bytes,
                    kind: if e.unsolicited {
                        BfdSessionKind::Unsolicited
                    } else {
                        s.kind
                    },
                }
            })
            .collect();
        all.sort_by(|a, b| {
            (&a.key.table, a.key.peer, &a.key.interface).cmp(&(
                &b.key.table,
                b.key.peer,
                &b.key.interface,
            ))
        });
        all
    }
}

/// Runs `Manager::sweep` once a second for the daemon's lifetime.
pub async fn sweep_loop(m: Arc<Manager>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        m.sweep(Instant::now());
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nos_proto::BfdState;

    pub struct Sent(pub Mutex<Vec<Vec<u8>>>);
    impl Tx for Sent {
        fn send(&self, b: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().push(b.to_vec());
            Ok(())
        }
    }

    pub struct MockNet {
        pub sent: Arc<Sent>,
        pub fail: bool,
        /// Echo payloads sent, when set the transport exists.
        pub echo: Option<Arc<Sent>>,
    }

    impl session::EchoTx for Sent {
        fn send(&self, payload: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().push(payload.to_vec());
            Ok(())
        }
    }

    #[async_trait]
    impl Net for MockNet {
        async fn open(&self, _: &SessionKey) -> io::Result<Arc<dyn Tx>> {
            if self.fail {
                return Err(io::Error::other("no vrf yet"));
            }
            Ok(self.sent.clone())
        }

        async fn open_echo(&self, _: &SessionKey, _: u32, _: bool) -> Option<EchoPath> {
            let tx = self.echo.clone()?;
            let (_keep, rx) = mpsc::channel(1);
            std::mem::forget(_keep); // the test wire never returns anything
            Some(EchoPath {
                tx,
                rx,
                tasks: vec![],
            })
        }
    }

    pub fn key(peer: &str) -> SessionKey {
        SessionKey {
            aggregate: None,
            table: "rt1".into(),
            peer: peer.parse().unwrap(),
            local: None,
            interface: None,
            multihop: false,
        }
    }

    pub fn mgr(fail: bool) -> (Arc<Manager>, Arc<Sent>, Demux) {
        let sent = Arc::new(Sent(Mutex::default()));
        let demux = Demux::default();
        let net = Arc::new(MockNet {
            sent: sent.clone(),
            fail,
            echo: None,
        });
        (Manager::new(net, demux.clone()), sent, demux)
    }

    #[tokio::test]
    async fn refcount_shares_one_session() {
        let (m, _, demux) = mgr(false);
        let (c1, c2) = (m.new_client(), m.new_client());
        let k = key("192.0.2.1");
        let p = BfdProfile::default();
        let r1 = m.register(c1, &k, &p);
        let r2 = m.register(c2, &k, &p);
        assert_eq!(m.sessions(None).len(), 1);
        assert_eq!(
            r1.borrow().local_discriminator,
            r2.borrow().local_discriminator
        );
        assert_ne!(r1.borrow().local_discriminator, 0);
        assert_eq!(r1.borrow().state, BfdState::Down);

        m.deregister(c1, &k);
        assert_eq!(m.sessions(None).len(), 1, "b still holds it");
        m.drop_client(c2);
        assert_eq!(m.sessions(None).len(), 0);
        assert!(demux.0.lock().unwrap().by_disc.is_empty());
        assert!(demux.0.lock().unwrap().by_peer.is_empty());
    }

    async fn until(mut f: impl FnMut() -> bool) -> bool {
        for _ in 0..100 {
            if f() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    fn admin_downs(sent: &Sent) -> usize {
        sent.0
            .lock()
            .unwrap()
            .iter()
            .filter(|b| packet::decode(b).is_ok_and(|p| p.state == BfdState::AdminDown))
            .count()
    }

    #[tokio::test]
    async fn last_deregister_sends_admin_down_then_aborts_after_grace() {
        let (m, sent, demux) = mgr(false);
        let (c, k) = (m.new_client(), key("192.0.2.1"));
        m.register(c, &k, &BfdProfile::default());
        assert!(until(|| !sent.0.lock().unwrap().is_empty()).await);
        let old = m.sessions(None)[0].local_discriminator;
        m.deregister(c, &k);
        assert_eq!(m.sessions(None).len(), 0);
        assert!(demux.0.lock().unwrap().by_disc.is_empty(), "no rx slot");
        assert!(
            until(|| admin_downs(&sent) == 1).await,
            "AdminDown on the wire"
        );
        // Re-register during the grace: a fresh session.
        m.register(c, &k, &BfdProfile::default());
        let new = m.sessions(None)[0].local_discriminator;
        assert_ne!(old, new);
        assert!(demux.0.lock().unwrap().by_disc.contains_key(&new));
    }

    #[tokio::test]
    async fn drop_client_and_shutdown_all_announce_admin_down() {
        let (m, sent, _) = mgr(false);
        let c = m.new_client();
        for p in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
            m.register(c, &key(p), &BfdProfile::default());
        }
        assert!(until(|| sent.0.lock().unwrap().len() >= 3).await);
        m.drop_client(c);
        assert!(until(|| admin_downs(&sent) == 3).await);

        let (m, sent, _) = mgr(false);
        for p in ["192.0.2.1", "192.0.2.2"] {
            m.register(c, &key(p), &BfdProfile::default());
        }
        assert!(until(|| sent.0.lock().unwrap().len() >= 2).await);
        let t = Instant::now();
        m.shutdown_all().await;
        assert!(t.elapsed() < Duration::from_secs(3), "one grace, not two");
        assert_eq!(admin_downs(&sent), 2);
        assert_eq!(m.sessions(None).len(), 0);
    }

    #[tokio::test]
    async fn sbfd_aborts_without_a_grace() {
        let (m, sent, _) = mgr(false);
        let p = BfdProfile {
            mode: BfdMode::Sbfd,
            ..BfdProfile::default()
        };
        m.register(m.new_client(), &key("192.0.2.1"), &p);
        let t = Instant::now();
        m.shutdown_all().await;
        assert!(t.elapsed() < Duration::from_millis(250));
        assert_eq!(admin_downs(&sent), 0);
    }

    #[tokio::test]
    async fn an_unresolved_auth_label_fails_closed_until_the_key_arrives() {
        use nos_proto::schema::{BfdAuth, BfdAuthMethod};
        let (m, sent, _) = mgr(false);
        let profile = BfdProfile {
            auth: Some(BfdAuth {
                key_id: 1,
                method: BfdAuthMethod::KeyedMd5,
                key: "lbl".into(),
            }),
            ..BfdProfile::default()
        };
        let rx = m.register(m.new_client(), &key("192.0.2.1"), &profile);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(sent.0.lock().unwrap().is_empty(), "nothing is sent unkeyed");
        assert_eq!(rx.borrow().auth_method, None);
        // The keystore arrives: the session picks the key up and signs.
        m.set_keys(HashMap::from([("lbl".to_string(), "s1".to_string())]));
        assert!(until(|| !sent.0.lock().unwrap().is_empty()).await);
        assert_eq!(rx.borrow().auth_method, Some(BfdAuthMethod::KeyedMd5));
        let first = sent.0.lock().unwrap()[0].clone();
        assert_ne!(first[1] & crate::auth::FLAG_AUTH, 0, "A bit set");
        // A rotation under the same label re-signs with the new secret.
        let n = sent.0.lock().unwrap().len();
        m.set_keys(HashMap::from([("lbl".to_string(), "s2".to_string())]));
        assert!(until(|| sent.0.lock().unwrap().len() > n + 1).await);
        let last = sent.0.lock().unwrap().last().unwrap().clone();
        let accepts = |secret: &str| {
            let now = Instant::now();
            let k = crate::auth::AuthKey::new(profile.auth.as_ref().unwrap(), secret);
            let mut st = crate::auth::AuthState::new(Some(k), 0, now);
            st.check(now, 3, crate::auth::parse(&last).as_ref(), None)
                .is_ok()
        };
        assert!(accepts("s2") && !accepts("s1"));
    }

    #[tokio::test]
    async fn discriminators_differ_and_peer_filter_works() {
        let (m, _, _) = mgr(false);
        let c = m.new_client();
        m.register(c, &key("192.0.2.1"), &BfdProfile::default());
        m.register(c, &key("192.0.2.2"), &BfdProfile::default());
        let all = m.sessions(None);
        assert_eq!(all.len(), 2);
        assert_ne!(
            all[0].local_discriminator, all[1].local_discriminator,
            "{all:?}"
        );
        assert_eq!(m.sessions(Some("192.0.2.2".parse().unwrap())).len(), 1);
        assert_eq!(m.sessions(Some("192.0.2.9".parse().unwrap())).len(), 0);
    }

    #[tokio::test]
    async fn session_transmits_once_open_and_demux_routes_replies() {
        let (m, sent, demux) = mgr(false);
        let k = key("192.0.2.1");
        let rx = m.register(m.new_client(), &k, &BfdProfile::default());
        // The first periodic packet goes out at once.
        for _ in 0..50 {
            if !sent.0.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let first = packet::decode(&sent.0.lock().unwrap()[0]).unwrap();
        assert_eq!(first.state, BfdState::Down);
        assert_eq!(first.my_discriminator, rx.borrow().local_discriminator);

        // A reply from the peer: Down with Your Discriminator 0 is found by
        // address, then Init is by discriminator.
        let mut reply = Packet {
            my_discriminator: 77,
            your_discriminator: 0,
            ..first
        };
        assert!(demux.route("rt1", k.peer, false, Some(255), &reply.encode()));
        assert!(
            !demux.route("rt2", k.peer, false, Some(255), &reply.encode()),
            "wrong table"
        );
        reply.state = BfdState::Init;
        reply.your_discriminator = rx.borrow().local_discriminator;
        assert!(demux.route(
            "rt1",
            "192.0.2.77".parse().unwrap(),
            false,
            Some(255),
            &reply.encode()
        ));
        assert!(
            !demux.route("rt1", k.peer, false, Some(255), &[0u8; 3]),
            "garbage"
        );
        assert!(
            !demux.route("rt1", k.peer, false, Some(254), &reply.encode()),
            "single-hop wants 255"
        );
        assert!(
            !demux.route("rt1", k.peer, true, Some(255), &reply.encode()),
            "wrong port"
        );
    }

    #[test]
    fn ttl_rule_single_and_multihop() {
        assert!(ttl_ok(false, Some(255), 254));
        assert!(!ttl_ok(false, Some(254), 254), "single-hop is exactly 255");
        assert!(ttl_ok(true, Some(254), 254));
        assert!(ttl_ok(true, Some(255), 254));
        assert!(!ttl_ok(true, Some(253), 254));
        assert!(!ttl_ok(true, None, 0), "no TTL from the kernel: drop");
    }

    /// RFC 5883: a multihop session shares no state with a single-hop one to
    /// the same address and is demuxed by port and TTL.
    #[tokio::test]
    async fn multihop_sessions_are_separate_and_demuxed_by_port_and_ttl() {
        let (m, _, demux) = mgr(false);
        let c = m.new_client();
        let single = key("192.0.2.1");
        let multi = SessionKey {
            multihop: true,
            local: Some("192.0.2.9".parse().unwrap()),
            ..single.clone()
        };
        m.register(c, &single, &BfdProfile::default());
        m.register(c, &multi, &BfdProfile::default());
        assert_eq!(m.sessions(None).len(), 2);
        let p = Packet {
            diag: 0,
            state: BfdState::Down,
            poll: false,
            final_: false,
            control_plane_independent: false,
            demand: false,
            detect_mult: 3,
            my_discriminator: 5,
            your_discriminator: 0,
            desired_min_tx: 1_000_000,
            required_min_rx: 1_000_000,
            required_min_echo_rx: 0,
            auth: None,
        };
        assert!(demux.route("rt1", multi.peer, true, Some(254), &p.encode()));
        assert!(!demux.route("rt1", multi.peer, true, Some(253), &p.encode()));
        let raised = BfdProfile {
            minimum_ttl: 255,
            ..BfdProfile::default()
        };
        m.register(c, &multi, &raised);
        assert!(!demux.route("rt1", multi.peer, true, Some(254), &p.encode()));
        m.drop_client(c);
        assert!(demux.0.lock().unwrap().by_peer.is_empty());
    }

    #[tokio::test]
    async fn unaffiliated_session_has_no_control_slot_and_a_mode_switch_restarts_it() {
        let sent = Arc::new(Sent(Mutex::default()));
        let echoed = Arc::new(Sent(Mutex::default()));
        let demux = Demux::default();
        let m = Manager::new(
            Arc::new(MockNet {
                sent: sent.clone(),
                fail: false,
                echo: Some(echoed.clone()),
            }),
            demux.clone(),
        );
        let (c, k) = (m.new_client(), key("192.0.2.1"));
        let un = BfdProfile {
            echo_mode: EchoMode::Unaffiliated,
            ..BfdProfile::default()
        };
        m.register(c, &k, &un);
        assert!(
            demux.0.lock().unwrap().by_disc.is_empty(),
            "no Control demux"
        );
        assert!(demux.0.lock().unwrap().by_peer.is_empty());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(sent.0.lock().unwrap().is_empty(), "no Control traffic");
        let first = echoed.0.lock().unwrap().first().cloned();
        let p = packet::decode(&first.expect("the session runs and echoes")).unwrap();
        assert_eq!(p.state, BfdState::Down);
        let d1 = m.sessions(None)[0].local_discriminator;
        assert_eq!(p.my_discriminator, d1);
        assert!(m.sessions(None)[0].echo_only);

        m.register(c, &k, &BfdProfile::default());
        let all = m.sessions(None);
        assert_eq!(all.len(), 1);
        assert!(!all[0].echo_only);
        assert_ne!(all[0].local_discriminator, d1, "a fresh session");
        assert_eq!(demux.0.lock().unwrap().by_disc.len(), 1);
    }

    /// A transport whose S-BFD replies the test injects.
    struct SbfdNet {
        sent: Arc<Sent>,
        replies: Mutex<Option<mpsc::Receiver<sbfd::Reflection>>>,
    }

    #[async_trait]
    impl Net for SbfdNet {
        async fn open(&self, _: &SessionKey) -> io::Result<Arc<dyn Tx>> {
            Err(io::Error::other(
                "classical sessions are not part of this test",
            ))
        }

        async fn open_sbfd(&self, _: &SessionKey) -> io::Result<SbfdPath> {
            let rx = self.replies.lock().unwrap().take().expect("opened once");
            let task = tokio::spawn(async {});
            Ok(SbfdPath {
                tx: self.sent.clone(),
                rx,
                task: task.abort_handle(),
            })
        }
    }

    #[tokio::test]
    async fn sbfd_session_probes_the_peer_discriminator_and_comes_up_on_a_reflection() {
        let sent = Arc::new(Sent(Mutex::default()));
        let (reply_tx, reply_rx) = mpsc::channel(4);
        let demux = Demux::default();
        let m = Manager::new(
            Arc::new(SbfdNet {
                sent: sent.clone(),
                replies: Mutex::new(Some(reply_rx)),
            }),
            demux.clone(),
        );
        let k = key("10.0.0.2");
        let profile = BfdProfile {
            mode: BfdMode::Sbfd,
            min_tx_interval: 20,
            ..BfdProfile::default()
        };
        let mut rx = m.register(m.new_client(), &k, &profile);
        assert_eq!(rx.borrow().state, BfdState::Down);
        assert!(
            demux.0.lock().unwrap().by_disc.is_empty(),
            "own socket, not the shared demux"
        );
        let probe = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(b) = sent.0.lock().unwrap().first() {
                    break packet::decode(b).unwrap();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("a probe goes out");
        assert!(probe.demand);
        assert_eq!(
            probe.your_discriminator, 0x0a00_0002,
            "the peer's IPv4 address"
        );
        let mine = rx.borrow().local_discriminator;
        assert_eq!(probe.my_discriminator, mine);

        let reflection = Packet {
            state: BfdState::Up,
            demand: false,
            my_discriminator: probe.your_discriminator,
            your_discriminator: mine,
            required_min_rx: 10_000,
            ..probe
        };
        reply_tx
            .send((reflection.clone(), Some(254)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            rx.borrow().state,
            BfdState::Down,
            "single-hop wants TTL 255"
        );
        reply_tx.send((reflection, Some(255))).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while rx.borrow().state != BfdState::Up {
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("up on a reflection");
        let v = &m.sessions(None)[0];
        assert_eq!(v.kind, nos_proto::BfdSessionKind::SbfdInitiator);
        assert_eq!(v.remote_discriminator, 0x0a00_0002);
    }

    #[tokio::test]
    async fn open_failure_retries_without_blocking_register() {
        let (m, sent, _) = mgr(true);
        let rx = m.register(m.new_client(), &key("192.0.2.1"), &BfdProfile::default());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(sent.0.lock().unwrap().is_empty());
        assert_eq!(rx.borrow().state, BfdState::Down);
    }

    #[tokio::test]
    async fn changed_profile_reaches_the_running_session() {
        let (m, _, _) = mgr(false);
        let c = m.new_client();
        let k = key("192.0.2.1");
        m.register(c, &k, &BfdProfile::default());
        let down = BfdProfile {
            shutdown: true,
            ..BfdProfile::default()
        };
        let mut rx = m.register(c, &k, &down);
        tokio::time::timeout(Duration::from_secs(2), async {
            while rx.borrow().state != BfdState::AdminDown {
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("session went admin-down");
    }

    fn rule() -> unsolicited::Rule {
        unsolicited::tests::rule()
    }

    fn unsolicited_key(peer: &str) -> SessionKey {
        SessionKey {
            interface: Some("eth1".into()),
            ..key(peer)
        }
    }

    #[tokio::test]
    async fn unsolicited_packet_makes_a_passive_session_only_where_asked() {
        let (m, _, demux) = mgr(false);
        let p = unsolicited::tests::pkt(BfdState::Down, 0).encode();
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        // No rule: dropped as before.
        assert!(!demux.route("rt1", peer, false, Some(255), &p));
        assert_eq!(m.sessions(None).len(), 0);

        m.set_unsolicited(vec![rule()]);
        assert!(!demux.route("rt1", peer, false, Some(254), &p), "GTSM");
        assert!(!demux.route("rt1", peer, true, Some(255), &p), "multihop");
        assert!(
            !demux.route("rt2", peer, false, Some(255), &p),
            "other table"
        );
        assert!(!demux.route("rt1", "10.1.0.2".parse().unwrap(), false, Some(255), &p));
        assert_eq!(m.sessions(None).len(), 0);

        assert!(demux.route("rt1", peer, false, Some(255), &p));
        let s = m.sessions(None);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].key, unsolicited_key("10.0.0.2"));
        assert_eq!(s[0].kind, BfdSessionKind::Unsolicited);
        // The same peer again reaches that session, no second one.
        assert!(demux.route("rt1", peer, false, Some(255), &p));
        assert_eq!(m.sessions(None).len(), 1);

        // The rule going away takes its sessions with it.
        m.set_unsolicited(vec![]);
        assert_eq!(m.sessions(None).len(), 0);
        assert!(demux.0.lock().unwrap().by_peer.is_empty());
    }

    #[tokio::test]
    async fn unsolicited_sessions_are_capped_per_interface() {
        let (m, _, demux) = mgr(false);
        let mut r = rule();
        r.subnets = vec!["10.0.0.0/16".parse().unwrap()];
        m.set_unsolicited(vec![r]);
        let p = unsolicited::tests::pkt(BfdState::Down, 0).encode();
        for i in 0..=unsolicited::MAX_PER_INTERFACE {
            let a = IpAddr::from([
                10,
                0,
                u8::try_from(i / 250).unwrap(),
                u8::try_from(i % 250 + 1).unwrap(),
            ]);
            let ok = demux.route("rt1", a, false, Some(255), &p);
            assert_eq!(ok, i < unsolicited::MAX_PER_INTERFACE, "{i}");
        }
        assert_eq!(m.sessions(None).len(), unsolicited::MAX_PER_INTERFACE);
    }

    #[tokio::test]
    async fn unsolicited_session_ages_out_unless_adopted() {
        let (m, _, demux) = mgr(false);
        m.set_unsolicited(vec![rule()]);
        let p = unsolicited::tests::pkt(BfdState::Down, 0).encode();
        for peer in ["10.0.0.2", "10.0.0.3"] {
            assert!(demux.route("rt1", peer.parse().unwrap(), false, Some(255), &p));
        }
        // A client registering the very key adopts the session.
        let c = m.new_client();
        m.register(c, &unsolicited_key("10.0.0.3"), &BfdProfile::default());
        let t0 = Instant::now();
        m.sweep(t0);
        m.sweep(t0 + Duration::from_secs(59));
        assert_eq!(m.sessions(None).len(), 2);
        m.sweep(t0 + unsolicited::AGE);
        let s = m.sessions(None);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].key.peer, "10.0.0.3".parse::<IpAddr>().unwrap());
        assert_eq!(s[0].kind, BfdSessionKind::Classical);
        m.deregister(c, &unsolicited_key("10.0.0.3"));
        assert_eq!(m.sessions(None).len(), 0);
    }
}
