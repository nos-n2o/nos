//! RFC 7854 BMP exporter (#878): `nos-bgpd` dials every configured
//! `bmp-station` inside the instance's VRF and sends Initiation, a Peer Up per
//! Established peer, Route Monitoring (every family, #864), Peer Down and
//! Termination. The codec half is pure; [`Hub`] is the registry + per-station
//! bounded queues the FSM and the RIB push into without ever awaiting the
//! network.

mod dump;
pub mod monitor;
pub mod stats;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::codec::Encoder;
use tracing::{debug, info, warn};

use crate::evpn::EvpnNlri;
use crate::message::{BgpCodec, BgpMessage, UpdateMessage};
use crate::rib::{EvpnRoute, FlowspecKey, FlowspecRoute, RibRoute, SharedRib, VpnRoute};
use crate::vpn::VpnKey;
use ipnet::IpNet;
use nos_proto::{BmpFrameCounts, BmpMonitor, BmpStationState, BmpStationStatus};

/// BMP version 3 (RFC 7854 section 4.1).
pub const BMP_VERSION: u8 = 3;
/// Frames a station's queue holds before it drops the oldest and resyncs.
pub const QUEUE_CAPACITY: usize = 1024;
/// A dial that takes longer than this is retried.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A collector that accepts no bytes for this long is treated as dead.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// First reconnect delay, doubling to [`BACKOFF_MAX`].
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(5);
/// Longest reconnect delay.
pub const BACKOFF_MAX: Duration = Duration::from_secs(120);

/// Prefixes the initial dump reads per RIB lock hold (#864).
pub const DUMP_CHUNK: usize = 1000;

const TYPE_ROUTE_MONITORING: u8 = 0;
const TYPE_PEER_DOWN: u8 = 2;
const TYPE_PEER_UP: u8 = 3;
const TYPE_INITIATION: u8 = 4;
const TYPE_TERMINATION: u8 = 5;

const TLV_STRING: u16 = 0;
const TLV_SYS_DESCR: u16 = 1;
const TLV_SYS_NAME: u16 = 2;
const TLV_TERM_REASON: u16 = 1;

/// Termination reasons (RFC 7854 section 4.5).
pub const TERM_ADMIN_CLOSED: u16 = 0;
/// Out of resources: used when the queue overflowed and the station resyncs.
pub const TERM_OUT_OF_RESOURCES: u16 = 2;

const FLAG_V: u8 = 0x80;
const FLAG_A: u8 = 0x20;
/// L: the message is post-policy (RFC 7854 section 4.2).
const FLAG_L: u8 = 0x40;

/// Peer Down reasons (RFC 7854 section 4.9), with their data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownReason {
    /// 1: we closed and sent this NOTIFICATION PDU.
    LocalNotification(Bytes),
    /// 2: we closed without a NOTIFICATION; the RFC 4271 section 8.1 FSM
    /// event code (0 = none).
    LocalFsm(u16),
    /// 3: the peer closed with this NOTIFICATION PDU.
    RemoteNotification(Bytes),
    /// 4: the peer closed (or the transport failed) without a NOTIFICATION.
    RemoteClosed,
}

impl DownReason {
    fn code(&self) -> u8 {
        match self {
            DownReason::LocalNotification(_) => 1,
            DownReason::LocalFsm(_) => 2,
            DownReason::RemoteNotification(_) => 3,
            DownReason::RemoteClosed => 4,
        }
    }
}

/// Peer type and distinguisher shared by every per-peer header of one
/// instance: type 0 with a zero distinguisher, or type 1 with the table's RD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scope {
    /// 0 global, 1 RD instance.
    pub peer_type: u8,
    /// The RD for type 1, else zero.
    pub distinguisher: [u8; 8],
}

impl Scope {
    /// Type 1 with `rd`, else the global type 0.
    pub fn for_rd(rd: Option<[u8; 8]>) -> Self {
        rd.map_or_else(Self::default, |d| Scope {
            peer_type: 1,
            distinguisher: d,
        })
    }
}

/// What a Peer Up carries, kept while the peer is Established so a station
/// that connects later gets it replayed (RFC 7854 section 3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerUpInfo {
    /// The peer's address.
    pub peer: IpAddr,
    /// The peer's (4-octet) AS.
    pub asn: u32,
    /// The peer's BGP identifier.
    pub bgp_id: Ipv4Addr,
    /// A flag: the session uses 2-octet `AS_PATH`.
    pub two_octet_as: bool,
    /// Our side of the TCP session.
    pub local: IpAddr,
    /// Our TCP port.
    pub local_port: u16,
    /// The peer's TCP port.
    pub remote_port: u16,
    /// The full OPEN PDU we sent.
    pub sent_open: Bytes,
    /// The full OPEN PDU we received.
    pub recv_open: Bytes,
    /// When the session came up.
    pub time: Duration,
    /// AFIs for which received NLRI carry ADD-PATH identifiers.
    pub add_path_afis: HashSet<u16>,
}

/// The current time as a BMP timestamp source.
pub fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Encodes one BGP message as a full PDU (header included), as Peer Up and
/// Peer Down carry them. ponytail: a re-encode, not the received bytes, so an
/// unknown capability or RFC 9003 shutdown text is lost; capture the raw
/// frames in the codec if a collector ever needs them byte for byte.
pub fn bgp_pdu(msg: BgpMessage) -> Bytes {
    let mut buf = BytesMut::new();
    // An OPEN or NOTIFICATION we built or decoded always re-encodes.
    let _ = BgpCodec::default().encode(msg, &mut buf);
    buf.freeze()
}

fn frame(msg_type: u8, body: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(6 + body.len());
    b.put_u8(BMP_VERSION);
    b.put_u32(u32::try_from(6 + body.len()).unwrap_or(u32::MAX));
    b.put_u8(msg_type);
    b.put_slice(body);
    b.freeze()
}

fn put_tlv(b: &mut BytesMut, kind: u16, value: &[u8]) {
    b.put_u16(kind);
    b.put_u16(u16::try_from(value.len()).unwrap_or(u16::MAX));
    b.put_slice(&value[..value.len().min(usize::from(u16::MAX))]);
}

fn put_addr(b: &mut BytesMut, addr: IpAddr) {
    match addr {
        IpAddr::V4(a) => {
            b.put_slice(&[0; 12]);
            b.put_slice(&a.octets());
        }
        IpAddr::V6(a) => b.put_slice(&a.octets()),
    }
}

impl PeerUpInfo {
    /// The 42-byte per-peer header (RFC 7854 section 4.2).
    fn put_header(&self, b: &mut BytesMut, scope: &Scope, time: Duration, a: bool, post: bool) {
        b.put_u8(scope.peer_type);
        let mut flags = 0;
        if self.peer.is_ipv6() {
            flags |= FLAG_V;
        }
        if a {
            flags |= FLAG_A;
        }
        if post {
            flags |= FLAG_L;
        }
        b.put_u8(flags);
        b.put_slice(&scope.distinguisher);
        put_addr(b, self.peer);
        b.put_u32(self.asn);
        b.put_slice(&self.bgp_id.octets());
        b.put_u32(u32::try_from(time.as_secs()).unwrap_or(u32::MAX));
        b.put_u32(time.subsec_micros());
    }
}

/// Initiation: sysDescr, sysName and optional string TLVs (section 4.3).
pub fn initiation(sys_descr: &str, sys_name: &str, strings: &[&str]) -> Bytes {
    let mut b = BytesMut::new();
    put_tlv(&mut b, TLV_SYS_DESCR, sys_descr.as_bytes());
    put_tlv(&mut b, TLV_SYS_NAME, sys_name.as_bytes());
    for s in strings {
        put_tlv(&mut b, TLV_STRING, s.as_bytes());
    }
    frame(TYPE_INITIATION, &b)
}

/// Termination with its mandatory Reason TLV (section 4.5).
pub fn termination(reason: u16) -> Bytes {
    let mut b = BytesMut::new();
    put_tlv(&mut b, TLV_TERM_REASON, &reason.to_be_bytes());
    frame(TYPE_TERMINATION, &b)
}

/// Peer Up (section 4.10).
pub fn peer_up(scope: &Scope, p: &PeerUpInfo) -> Bytes {
    let mut b = BytesMut::new();
    p.put_header(&mut b, scope, p.time, p.two_octet_as, false);
    put_addr(&mut b, p.local);
    b.put_u16(p.local_port);
    b.put_u16(p.remote_port);
    b.put_slice(&p.sent_open);
    b.put_slice(&p.recv_open);
    frame(TYPE_PEER_UP, &b)
}

/// Peer Down (section 4.9).
pub fn peer_down(scope: &Scope, p: &PeerUpInfo, reason: &DownReason, time: Duration) -> Bytes {
    let mut b = BytesMut::new();
    p.put_header(&mut b, scope, time, p.two_octet_as, false);
    b.put_u8(reason.code());
    match reason {
        DownReason::LocalNotification(pdu) | DownReason::RemoteNotification(pdu) => {
            b.put_slice(pdu);
        }
        DownReason::LocalFsm(event) => b.put_u16(*event),
        DownReason::RemoteClosed => {}
    }
    frame(TYPE_PEER_DOWN, &b)
}

/// The reconnect delay after `current`.
pub fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(BACKOFF_MAX)
}

/// Everything a station task needs; a change restarts the task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationCfg {
    /// The `bmp-station` name.
    pub name: String,
    /// Where to dial.
    pub addr: SocketAddr,
    /// VRF to scope the socket into, `None` outside the VRF (tests).
    pub vrf: Option<String>,
    /// sysName: the BGP instance name.
    pub sys_name: String,
    /// The routing table / VRF name for the Initiation string TLV.
    pub table: Option<String>,
    /// Peer type and distinguisher.
    pub scope: Scope,
    /// Which policy view this station gets as Route Monitoring.
    pub monitor: BmpMonitor,
    /// Seconds between Statistics Reports; `None` = none.
    pub statistics_interval: Option<u32>,
}

impl StationCfg {
    /// Whether this station wants the post-policy (`true`) or pre-policy view.
    pub fn wants(&self, post: bool) -> bool {
        match self.monitor {
            BmpMonitor::Both => true,
            BmpMonitor::PostPolicy => post,
            BmpMonitor::PrePolicy => !post,
        }
    }
}

#[derive(Debug)]
enum Kind {
    Up(IpAddr),
    Down(IpAddr, u8),
    /// A Route Monitoring frame: debug-logged by the sender only.
    Route,
    /// A per-peer End-of-RIB; `true` = post-policy stream.
    Eor(IpAddr, bool),
}

#[derive(Default)]
struct Queue {
    frames: VecDeque<(Bytes, Kind)>,
    /// Set while a connection is live: nothing is queued otherwise (the
    /// replay at connect time covers it).
    connected: bool,
    resync: bool,
    dropped: u64,
    stopping: bool,
}

/// What `show bgp bmp` reports for one station; survives reconnects.
#[derive(Default)]
struct Counters {
    state: BmpStationState,
    since: Option<u64>,
    frames: BmpFrameCounts,
    overflows: u64,
    dials: u64,
    last_error: Option<String>,
}

#[derive(Default)]
struct Shared {
    q: Mutex<Queue>,
    wake: Notify,
    stats: Mutex<Counters>,
}

impl Shared {
    /// Counts one sent frame by its BMP type (common header byte 5); an
    /// End-of-RIB is a Route Monitoring message the caller flags.
    fn count(&self, f: &[u8], eor: bool) {
        let mut c = lock(&self.stats);
        let n = &mut c.frames;
        match f.get(5) {
            Some(&TYPE_ROUTE_MONITORING) if eor => n.end_of_rib += 1,
            Some(&TYPE_ROUTE_MONITORING) if f.get(7).is_some_and(|b| b & FLAG_L != 0) => {
                n.route_monitoring_post += 1;
            }
            Some(&TYPE_ROUTE_MONITORING) => n.route_monitoring_pre += 1,
            Some(&stats::TYPE_STATS) => n.stats += 1,
            Some(&TYPE_PEER_DOWN) => n.peer_down += 1,
            Some(&TYPE_PEER_UP) => n.peer_up += 1,
            Some(&TYPE_INITIATION) => n.initiation += 1,
            Some(&TYPE_TERMINATION) => n.termination += 1,
            _ => {}
        }
    }

    fn set_state(&self, state: BmpStationState, error: Option<String>) {
        let mut c = lock(&self.stats);
        c.state = state;
        c.since = (state == BmpStationState::Connected).then(|| now().as_secs());
        if error.is_some() {
            c.last_error = error;
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Shared {
    fn push(&self, f: Bytes, kind: Kind) {
        {
            let mut q = lock(&self.q);
            if !q.connected {
                return;
            }
            if q.frames.len() >= QUEUE_CAPACITY {
                q.frames.pop_front();
                q.dropped += 1;
                q.resync = true;
            }
            q.frames.push_back((f, kind));
        }
        self.wake.notify_one();
    }

    fn stop(&self) {
        lock(&self.q).stopping = true;
        self.wake.notify_one();
    }

    fn stopping(&self) -> bool {
        lock(&self.q).stopping
    }
}

pub(crate) fn stream(post: bool) -> &'static str {
    if post {
        "post-policy"
    } else {
        "pre-policy"
    }
}

struct Station {
    cfg: StationCfg,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct State {
    registry: HashMap<IpAddr, PeerUpInfo>,
    scope: Scope,
    stations: HashMap<String, Station>,
}

/// The registry of Established peers plus the per-station queues.
#[derive(Default)]
pub struct Hub {
    state: Mutex<State>,
    /// Some station wants the pre-/post-policy stream: one atomic check on
    /// the UPDATE path when no station does.
    pre_on: AtomicBool,
    post_on: AtomicBool,
    rib: Mutex<Weak<SharedRib>>,
}

impl Hub {
    /// A hub with no stations: every call is a cheap no-op until
    /// [`Hub::set_stations`].
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// A peer reached Established.
    pub fn peer_up(&self, info: PeerUpInfo) {
        let mut st = lock(&self.state);
        let f = peer_up(&st.scope, &info);
        let peer = info.peer;
        st.registry.insert(peer, info);
        for s in st.stations.values() {
            s.shared.push(f.clone(), Kind::Up(peer));
        }
    }

    /// A peer that was reported up went down. Nothing for one that never was
    /// (a collision loser).
    pub fn peer_down(&self, peer: IpAddr, reason: &DownReason) {
        let mut st = lock(&self.state);
        let Some(info) = st.registry.remove(&peer) else {
            return;
        };
        let f = peer_down(&st.scope, &info, reason, now());
        for s in st.stations.values() {
            s.shared.push(f.clone(), Kind::Down(peer, reason.code()));
        }
    }

    /// Some station wants the post-policy stream (the RIB tap's cheap gate).
    pub fn post_enabled(&self) -> bool {
        self.post_on.load(Ordering::Relaxed)
    }

    /// Points the initial dump at the RIB it reads (a `Weak`: the RIB owns
    /// this hub).
    pub fn attach(&self, rib: Weak<SharedRib>) {
        *lock(&self.rib) = rib;
    }

    fn rib(&self) -> Option<Arc<SharedRib>> {
        lock(&self.rib).upgrade()
    }

    /// Whether `info` is still the registered session of its peer: a dump
    /// aborts when the peer went down (or came back) meanwhile.
    fn session_alive(&self, info: &PeerUpInfo) -> bool {
        lock(&self.state)
            .registry
            .get(&info.peer)
            .is_some_and(|i| i.time == info.time && i.remote_port == info.remote_port)
    }

    /// Builds one UPDATE for `peer` and queues its Route Monitoring frames on
    /// every station that wants the stream. A peer not reported up is skipped.
    fn emit(&self, peer: IpAddr, post: bool, mk: impl FnOnce(&PeerUpInfo) -> UpdateMessage) {
        let st = lock(&self.state);
        let Some(info) = st.registry.get(&peer) else {
            return;
        };
        let frames = monitor::route_monitoring(&st.scope, info, post, &mk(info), now());
        for s in st.stations.values().filter(|s| s.cfg.wants(post)) {
            for f in &frames {
                s.shared.push(f.clone(), Kind::Route);
            }
        }
    }

    /// The pre-policy stream: an UPDATE exactly as `peer` sent it, every
    /// family. Called before the RIB lock is taken.
    pub fn route_pre(&self, peer: IpAddr, update: &UpdateMessage) {
        if !self.pre_on.load(Ordering::Relaxed) {
            return;
        }
        if monitor::has_routes(update) {
            self.emit(peer, false, |_| update.clone());
        }
    }

    /// The post-policy stream: path `id` of `prefix` was stored (`Some`) or
    /// removed (`None`) in `peer`'s Adj-RIB-In. Called from the RIB under its
    /// lock, only while [`Hub::post_enabled`].
    pub fn route_post(&self, peer: IpAddr, prefix: IpNet, id: u32, route: Option<&RibRoute>) {
        self.emit(peer, true, |info| {
            let add_path = info.add_path_afis.contains(&monitor::afi_of(prefix));
            match route {
                Some(r) => monitor::rib_route_to_update(prefix, id, r, add_path),
                None => monitor::rib_withdraw_to_update(prefix, id, add_path),
            }
        });
    }

    /// `peer` sent its own End-of-RIB: forward it on both streams.
    pub fn end_of_rib(&self, peer: IpAddr, afi: u16, safi: u8) {
        let st = lock(&self.state);
        let Some(info) = st.registry.get(&peer) else {
            return;
        };
        for post in [false, true] {
            let f = monitor::end_of_rib(&st.scope, info, post, afi, safi);
            for s in st.stations.values().filter(|s| s.cfg.wants(post)) {
                s.shared.push(f.clone(), Kind::Eor(peer, post));
            }
        }
    }

    /// The post-policy stream for EVPN: `route` was stored (`Some`) or the
    /// route `nlri` removed (`None`). Same contract as [`Hub::route_post`].
    pub fn evpn_post(&self, peer: IpAddr, nlri: &EvpnNlri, route: Option<&EvpnRoute>) {
        self.emit(peer, true, |_| match route {
            Some(r) => monitor::evpn_to_update(r),
            None => monitor::evpn_withdraw_to_update(nlri),
        });
    }

    /// The post-policy stream for Flowspec rule `k`.
    pub fn flow_post(&self, peer: IpAddr, k: &FlowspecKey, route: Option<&FlowspecRoute>) {
        self.emit(peer, true, |_| match route {
            Some(r) => monitor::flowspec_to_update(r),
            None => monitor::flowspec_withdraw_to_update(k),
        });
    }

    /// The post-policy stream for VPN path `k`.
    pub fn vpn_post(&self, peer: IpAddr, k: &VpnKey<IpNet>, route: Option<&VpnRoute>) {
        self.emit(peer, true, |_| match route {
            Some(r) => monitor::vpn_to_update(k, r),
            None => monitor::vpn_withdraw_to_update(k),
        });
    }

    /// Brings the running stations to `want`, restarting only changed ones
    /// (Termination reason 0 for those stopped).
    pub async fn set_stations(self: &Arc<Self>, want: Vec<StationCfg>) {
        let mut retired = Vec::new();
        {
            let mut st = lock(&self.state);
            if let Some(first) = want.first() {
                st.scope = first.scope;
            }
            self.pre_on
                .store(want.iter().any(|c| c.wants(false)), Ordering::Relaxed);
            self.post_on
                .store(want.iter().any(|c| c.wants(true)), Ordering::Relaxed);
            let names: Vec<_> = want.iter().map(|c| c.name.clone()).collect();
            let stale: Vec<_> = st
                .stations
                .iter()
                .filter(|(n, s)| !names.contains(n) || !want.contains(&s.cfg))
                .map(|(n, _)| n.clone())
                .collect();
            for n in stale {
                if let Some(s) = st.stations.remove(&n) {
                    s.shared.stop();
                    retired.push(s.task);
                }
            }
            for cfg in want {
                if st.stations.contains_key(&cfg.name) {
                    continue;
                }
                let shared = Arc::new(Shared::default());
                let task = tokio::spawn(run_station(self.clone(), cfg.clone(), shared.clone()));
                st.stations
                    .insert(cfg.name.clone(), Station { cfg, shared, task });
            }
        }
        for t in retired {
            // Give the Termination a moment to leave, then cut it.
            let abort = t.abort_handle();
            if tokio::time::timeout(Duration::from_secs(2), t)
                .await
                .is_err()
            {
                abort.abort();
            }
        }
    }

    /// Every station's status, by name (`show bgp bmp`).
    pub fn station_status(&self) -> Vec<BmpStationStatus> {
        let st = lock(&self.state);
        let mut v: Vec<_> = st
            .stations
            .values()
            .map(|s| {
                let c = lock(&s.shared.stats);
                BmpStationStatus {
                    name: s.cfg.name.clone(),
                    address: s.cfg.addr.ip(),
                    port: s.cfg.addr.port(),
                    state: c.state,
                    connected_since: c.since,
                    monitor: s.cfg.monitor,
                    statistics_interval: s.cfg.statistics_interval,
                    peers_monitored: u32::try_from(st.registry.len()).unwrap_or(u32::MAX),
                    frames_sent: c.frames,
                    overflows: c.overflows,
                    reconnects: c.dials.saturating_sub(1),
                    last_error: c.last_error.clone(),
                }
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// SIGINT: Termination (reason 0) to every station.
    pub async fn shutdown(self: &Arc<Self>) {
        self.set_stations(Vec::new()).await;
    }
}

/// Sends `bytes`; `false` when the collector stalled or the socket failed.
async fn send(w: &mut OwnedWriteHalf, shared: &Shared, bytes: &[u8]) -> bool {
    send_as(w, shared, bytes, false).await
}

/// [`send`], with `eor` marking an End-of-RIB for the frame counters.
async fn send_as(w: &mut OwnedWriteHalf, shared: &Shared, bytes: &[u8], eor: bool) -> bool {
    let ok = matches!(
        tokio::time::timeout(WRITE_TIMEOUT, w.write_all(bytes)).await,
        Ok(Ok(()))
    );
    if ok {
        shared.count(bytes, eor);
    }
    ok
}

/// Sleeps `d`; `true` when the station was stopped meanwhile.
async fn pause(shared: &Shared, d: Duration) -> bool {
    let end = Instant::now() + d;
    loop {
        if shared.stopping() {
            return true;
        }
        tokio::select! {
            () = tokio::time::sleep_until(end) => return false,
            () = shared.wake.notified() => {}
        }
    }
}

enum Ended {
    Stop,
    Resync,
    Lost,
}

async fn run_station(hub: Arc<Hub>, cfg: StationCfg, shared: Arc<Shared>) {
    let mut backoff = BACKOFF_INITIAL;
    loop {
        if shared.stopping() {
            return;
        }
        {
            let mut c = lock(&shared.stats);
            c.dials += 1;
            c.state = BmpStationState::Connecting;
            c.since = None;
        }
        let dial = crate::tcp::connect(cfg.addr, None, cfg.vrf.as_deref(), None, None);
        let stream = match tokio::time::timeout(CONNECT_TIMEOUT, dial).await {
            Ok(Ok(s)) => s,
            other => {
                let error = other.map_or_else(
                    |_| "timed out".to_string(),
                    |r| r.err().map_or_else(String::new, |e| e.to_string()),
                );
                debug!(station = %cfg.name, address = %cfg.addr, %error, "bmp station unreachable");
                shared.set_state(
                    BmpStationState::Backoff,
                    Some(if error.is_empty() {
                        "connect failed".into()
                    } else {
                        error
                    }),
                );
                if pause(&shared, backoff).await {
                    return;
                }
                backoff = next_backoff(backoff);
                continue;
            }
        };
        backoff = BACKOFF_INITIAL;
        info!(station = %cfg.name, address = %cfg.addr, "bmp station connected");
        shared.set_state(BmpStationState::Connected, None);
        let ended = session(&hub, &cfg, &shared, stream).await;
        lock(&shared.q).connected = false;
        info!(station = %cfg.name, address = %cfg.addr, "bmp station disconnected");
        match ended {
            Ended::Stop => return,
            Ended::Resync => shared.set_state(BmpStationState::Connecting, None),
            Ended::Lost => {
                shared.set_state(BmpStationState::Backoff, Some("connection lost".into()));
                if pause(&shared, backoff).await {
                    return;
                }
            }
        }
    }
}

async fn session(
    hub: &Hub,
    cfg: &StationCfg,
    shared: &Shared,
    stream: tokio::net::TcpStream,
) -> Ended {
    let (mut rd, mut wr) = stream.into_split();
    // Snapshot the registry and clear the queue under both locks, so a
    // concurrent peer_up/down lands either in the replay or in the queue.
    let (peers, scope) = {
        let st = lock(&hub.state);
        let mut q = lock(&shared.q);
        q.frames.clear();
        q.resync = false;
        q.dropped = 0;
        q.connected = true;
        (st.registry.values().cloned().collect::<Vec<_>>(), st.scope)
    };
    let descr = format!("nos-bgpd {}", nos_proto::version::VERSION);
    let vrf_text = cfg.table.as_ref().map(|t| format!("vrf={t}"));
    let strings: Vec<&str> = vrf_text.iter().map(String::as_str).collect();
    if !send(
        &mut wr,
        shared,
        &initiation(&descr, &cfg.sys_name, &strings),
    )
    .await
    {
        return Ended::Lost;
    }
    info!(station = %cfg.name, "bmp initiation sent");
    for p in &peers {
        if !send(&mut wr, shared, &peer_up(&scope, p)).await {
            return Ended::Lost;
        }
        info!(station = %cfg.name, peer = %p.peer, "bmp peer up sent");
    }
    if let Some(ended) = dump::run(hub, cfg, shared, &mut wr, &peers, &scope).await {
        return ended;
    }
    let mut buf = [0u8; 512];
    let mut tick = cfg.statistics_interval.map(|s| {
        let d = Duration::from_secs(u64::from(s));
        let mut t = tokio::time::interval_at(Instant::now() + d, d);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        t
    });
    loop {
        if let Some(ended) = drain(&mut wr, cfg, shared).await {
            return ended;
        }
        tokio::select! {
            () = shared.wake.notified() => {}
            () = async {
                match tick.as_mut() {
                    Some(t) => { t.tick().await; }
                    None => std::future::pending().await,
                }
            } => if !stats::send_reports(hub, cfg, shared, &scope, &mut wr).await {
                return Ended::Lost;
            },
            r = rd.read(&mut buf) => if matches!(r, Ok(0) | Err(_)) {
                return Ended::Lost;
            },
        }
    }
}

/// Sends everything queued, in order. `Some` ends the session: a stop, an
/// overflow (resync) or a dead collector.
async fn drain(wr: &mut OwnedWriteHalf, cfg: &StationCfg, shared: &Shared) -> Option<Ended> {
    loop {
        enum Next {
            Stop,
            Resync(u64),
            Frame(Bytes, Kind),
            Idle,
        }
        let next = {
            let mut q = lock(&shared.q);
            if q.stopping {
                Next::Stop
            } else if q.resync {
                Next::Resync(q.dropped)
            } else {
                q.frames
                    .pop_front()
                    .map_or(Next::Idle, |(f, k)| Next::Frame(f, k))
            }
        };
        match next {
            Next::Stop => {
                let _ = send(wr, shared, &termination(TERM_ADMIN_CLOSED)).await;
                return Some(Ended::Stop);
            }
            Next::Resync(dropped) => {
                lock(&shared.stats).overflows += 1;
                warn!(station = %cfg.name, dropped, "bmp queue overflowed, resynchronising the station");
                let _ = send(wr, shared, &termination(TERM_OUT_OF_RESOURCES)).await;
                return Some(Ended::Resync);
            }
            Next::Frame(f, kind) => {
                if !send_as(wr, shared, &f, matches!(kind, Kind::Eor(..))).await {
                    return Some(Ended::Lost);
                }
                match kind {
                    Kind::Up(peer) => {
                        info!(station = %cfg.name, peer = %peer, "bmp peer up sent");
                    }
                    Kind::Down(peer, reason) => {
                        info!(station = %cfg.name, peer = %peer, reason, "bmp peer down sent");
                    }
                    Kind::Route => debug!(station = %cfg.name, "bmp route monitoring sent"),
                    Kind::Eor(peer, post) => {
                        info!(peer = %peer, stream = %stream(post), station = %cfg.name, "bmp end-of-rib sent");
                    }
                }
            }
            Next::Idle => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::NotificationMessage;

    fn info(peer: &str, local: &str) -> PeerUpInfo {
        PeerUpInfo {
            peer: peer.parse().unwrap(),
            asn: 0x0001_0002,
            bgp_id: Ipv4Addr::new(1, 2, 3, 4),
            two_octet_as: false,
            local: local.parse().unwrap(),
            local_port: 179,
            remote_port: 40000,
            sent_open: Bytes::from_static(b"SENT"),
            recv_open: Bytes::from_static(b"RECV"),
            time: Duration::new(7, 9000),
            add_path_afis: HashSet::new(),
        }
    }

    #[test]
    fn initiation_layout() {
        let m = initiation("d", "nm", &["vrf=x"]);
        let want: &[u8] = &[
            3, 0, 0, 0, 26, 4, // common header
            0, 1, 0, 1, b'd', //
            0, 2, 0, 2, b'n', b'm', //
            0, 0, 0, 5, b'v', b'r', b'f', b'=', b'x',
        ];
        assert_eq!(&m[..], want);
    }

    #[test]
    fn termination_layout() {
        assert_eq!(&termination(2)[..], &[3, 0, 0, 0, 12, 5, 0, 1, 0, 2, 0, 2]);
    }

    #[test]
    fn peer_up_v4_layout() {
        let m = peer_up(&Scope::default(), &info("192.0.2.1", "192.0.2.2"));
        assert_eq!(m[0], 3);
        assert_eq!(m[5], 3, "type");
        let body = &m[6..];
        assert_eq!(body[0], 0, "peer type");
        assert_eq!(body[1], 0, "flags: v4, 4-octet AS");
        assert_eq!(&body[2..10], &[0; 8], "distinguisher");
        assert_eq!(&body[10..22], &[0; 12]);
        assert_eq!(&body[22..26], &[192, 0, 2, 1]);
        assert_eq!(&body[26..30], &[0, 1, 0, 2], "AS");
        assert_eq!(&body[30..34], &[1, 2, 3, 4], "BGP ID");
        assert_eq!(&body[34..38], &7u32.to_be_bytes());
        assert_eq!(&body[38..42], &9u32.to_be_bytes());
        assert_eq!(&body[42..54], &[0; 12]);
        assert_eq!(&body[54..58], &[192, 0, 2, 2], "local address");
        assert_eq!(&body[58..62], &[0, 179, 0x9c, 0x40]);
        assert_eq!(&body[62..], b"SENTRECV");
        assert_eq!(
            u32::from_be_bytes(m[1..5].try_into().unwrap()) as usize,
            m.len()
        );
    }

    #[test]
    fn flags_and_scope() {
        let mut i = info("2001:db8::1", "2001:db8::2");
        i.two_octet_as = true;
        let scope = Scope::for_rd(Some([0, 2, 0, 0, 0xfd, 0xe8, 0, 5]));
        let m = peer_up(&scope, &i);
        assert_eq!(m[6], 1, "RD instance");
        assert_eq!(m[7], FLAG_V | FLAG_A);
        assert_eq!(&m[8..16], &[0, 2, 0, 0, 0xfd, 0xe8, 0, 5]);
        assert_eq!(
            &m[16..32],
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(Scope::for_rd(None), Scope::default());
    }

    #[test]
    fn every_peer_down_reason() {
        let i = info("192.0.2.1", "192.0.2.2");
        let pdu = bgp_pdu(BgpMessage::Notification(NotificationMessage {
            error_code: 6,
            error_subcode: 2,
            data: Bytes::new(),
        }));
        assert_eq!(pdu.len(), 21);
        let down = |r: DownReason| peer_down(&Scope::default(), &i, &r, Duration::new(1, 2000));
        let tail = |m: &Bytes| m[6 + 42..].to_vec();
        let m = down(DownReason::LocalNotification(pdu.clone()));
        assert_eq!(m[5], 2);
        assert_eq!(tail(&m), [&[1u8][..], &pdu].concat());
        assert_eq!(tail(&down(DownReason::LocalFsm(0))), [2, 0, 0]);
        assert_eq!(tail(&down(DownReason::LocalFsm(2))), [2, 0, 2]);
        assert_eq!(
            tail(&down(DownReason::RemoteNotification(pdu.clone()))),
            [&[3u8][..], &pdu].concat()
        );
        assert_eq!(tail(&down(DownReason::RemoteClosed)), [4]);
        assert_eq!(
            &down(DownReason::RemoteClosed)[6 + 34..6 + 42],
            &[0, 0, 0, 1, 0, 0, 0, 2]
        );
    }

    #[test]
    fn open_pdu_has_the_bgp_header() {
        let pdu = bgp_pdu(BgpMessage::Open(crate::message::build_open(
            65000,
            Ipv4Addr::new(1, 1, 1, 1),
            90,
        )));
        assert_eq!(&pdu[..16], &[0xff; 16]);
        assert_eq!(pdu[18], 1);
    }

    #[test]
    fn backoff_doubles_to_the_cap() {
        let mut d = BACKOFF_INITIAL;
        let mut seen = vec![d.as_secs()];
        for _ in 0..6 {
            d = next_backoff(d);
            seen.push(d.as_secs());
        }
        assert_eq!(seen, [5, 10, 20, 40, 80, 120, 120]);
    }

    #[test]
    fn queue_drops_oldest_and_flags_resync() {
        let s = Shared::default();
        s.push(Bytes::new(), Kind::Up("192.0.2.1".parse().unwrap()));
        assert!(
            lock(&s.q).frames.is_empty(),
            "not connected: nothing queued"
        );
        lock(&s.q).connected = true;
        for _ in 0..QUEUE_CAPACITY + 3 {
            s.push(Bytes::new(), Kind::Up("192.0.2.1".parse().unwrap()));
        }
        let q = lock(&s.q);
        assert_eq!(q.frames.len(), QUEUE_CAPACITY);
        assert!(q.resync);
        assert_eq!(q.dropped, 3);
    }

    #[test]
    fn frames_are_counted_by_type_and_stream() {
        let sh = Shared::default();
        let i = info("192.0.2.1", "192.0.2.2");
        let sc = Scope::default();
        sh.count(&initiation("d", "n", &[]), false);
        sh.count(&peer_up(&sc, &i), false);
        sh.count(&termination(0), false);
        sh.count(&monitor::end_of_rib(&sc, &i, true, 1, 1), true);
        let rm = |post| {
            let u = UpdateMessage::default();
            monitor::route_monitoring(&sc, &i, post, &u, Duration::ZERO)
        };
        for f in rm(true).iter().chain(&rm(false)).chain(&rm(false)) {
            sh.count(f, false);
        }
        sh.count(&stats::stats_report(&sc, &i, &[], Duration::ZERO), false);
        let f = lock(&sh.stats).frames;
        assert_eq!(
            (
                f.initiation,
                f.peer_up,
                f.termination,
                f.end_of_rib,
                f.stats
            ),
            (1, 1, 1, 1, 1)
        );
        assert_eq!((f.route_monitoring_post, f.route_monitoring_pre), (1, 2));
    }

    #[test]
    fn status_lists_stations_by_name() {
        let hub = Hub::new();
        assert_eq!(hub.station_status(), [] as [nos_proto::BmpStationStatus; 0]);
    }

    #[test]
    fn peer_down_needs_a_registered_peer() {
        let hub = Hub::new();
        hub.peer_down("192.0.2.1".parse().unwrap(), &DownReason::RemoteClosed);
        hub.peer_up(info("192.0.2.1", "192.0.2.2"));
        assert_eq!(lock(&hub.state).registry.len(), 1);
        hub.peer_down("192.0.2.1".parse().unwrap(), &DownReason::RemoteClosed);
        assert!(lock(&hub.state).registry.is_empty());
    }
}
