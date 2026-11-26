//! One `OSPFv3` link's driver, plus `LinkManager` — the RFC 5340 counterpart
//! of `ospf::link`. Same orchestrator architecture (one raw socket per
//! link, neighbor FSM(s) from `nos_ospf_common::neighbor`, RFC 2328 §9.4
//! DR/BDR election from `nos_ospf_common::election`, then `crate::exchange`'s
//! DBD/LSR/LSU/LSAck adjacency-forming exchange), but every self-origination
//! function is structurally new (RFC 5340 restructures where addresses and
//! prefixes live — see `crate::spf`'s module doc comment). Authentication is
//! RFC 7166's trailer: `LinkConfig.auth` sets the AT-bit in Hello/DBD and
//! makes the socket sign every send (`socket.rs`); `run` verifies every
//! receive (`packet::verify_trailer`) and keeps the per-neighbor anti-replay
//! sequence (`accept_crypto_sequence`), like `ospf::link`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::{IpNet, Ipv6Net};
use nos_proto::schema::BfdProfile;
use nos_proto::{
    BfdDiag, LinkInterfaceState, NetworkType, OspfNeighborState, Ospfv3InterfaceSummary,
    Ospfv3LsaSummary, Ospfv3NeighborSummary, Ospfv3RouteSummary, RedistributeUpdate,
};
use nos_rpl::CompiledPolicy;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use nos_ospf_common::drouters::{flood_dest, Dest};

use crate::bfd;
use crate::bfd_client::{Host, Target, Want};
use crate::election;
use crate::exchange::{self, AdjacencyData};
use crate::lsa::{
    self, AsExternalLsaBody, GraceLsaBody, InterAreaPrefixLsaBody, InterAreaRouterLsaBody,
    IntraAreaPrefixEntry, IntraAreaPrefixLsaBody, LinkLsaBody, LinkPrefixEntry, Lsa, LsaBody,
    LsaHeader, LsaKey, NetworkLsaBody, RouterLsaBody, RouterLsaLink, LINK_TYPE_POINT_TO_POINT,
    LINK_TYPE_TRANSIT_NETWORK, LINK_TYPE_VIRTUAL,
};
mod restart;
use crate::lsdb::Lsdb;
use crate::neighbor::{self, NeighborState};
use crate::packet::{self, DbdPacket, LsAckPacket, LsrPacket, LsuPacket, OspfPacket};
use crate::socket::OspfSocket;

/// What a link task sends and receives on: the real raw socket, or (in
/// tests) an in-memory wire — lets `run` and `LinkManager` be exercised
/// without `CAP_NET_RAW` (#131). Mirrors `ospf::link::LinkSocket`.
pub enum LinkSocket {
    Os(OspfSocket),
    #[cfg(test)]
    Mem(tests::wire::Port),
}

impl LinkSocket {
    fn send_multicast(&self, ifindex: u32, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Os(s) => s.send_multicast(ifindex, payload),
            #[cfg(test)]
            Self::Mem(p) => p.send(tests::wire::To::AllSpf, payload),
        }
    }

    fn send_all_drouters(&self, ifindex: u32, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Os(s) => s.send_all_drouters(ifindex, payload),
            #[cfg(test)]
            Self::Mem(p) => p.send(tests::wire::To::AllD, payload),
        }
    }

    /// One flood-path send (`flood_dest`): the group, or `neighbor` directly.
    fn send_flood(
        &self,
        dest: Dest,
        neighbor: Ipv6Addr,
        ifindex: u32,
        payload: &[u8],
    ) -> std::io::Result<()> {
        match dest {
            Dest::Unicast => self.send_unicast(neighbor, ifindex, payload),
            Dest::AllSpfRouters => self.send_multicast(ifindex, payload),
            Dest::AllDRouters => self.send_all_drouters(ifindex, payload),
        }
    }

    fn send_unicast(&self, dest: Ipv6Addr, ifindex: u32, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Os(s) => s.send_unicast(dest, ifindex, payload),
            #[cfg(test)]
            Self::Mem(p) => p.send(tests::wire::To::Unicast(dest), payload),
        }
    }

    /// Join/leave `FF02::6` (see `run_election`); whether membership changed.
    fn set_all_drouters(&self, ifindex: u32, want: bool) -> std::io::Result<bool> {
        match self {
            Self::Os(s) => s.set_all_drouters(ifindex, want),
            #[cfg(test)]
            Self::Mem(p) => p.set_all_drouters(want),
        }
    }

    async fn recv_packet(&self) -> std::io::Result<(Ipv6Addr, Vec<u8>)> {
        match self {
            Self::Os(s) => s.recv_packet().await,
            #[cfg(test)]
            Self::Mem(p) => p.recv().await,
        }
    }
}

/// Opens one link's socket — the real one in production, see `LinkSocket`.
/// Opens a link's socket; the `u32` is the RFC 7166 §4.1 boot count (fresh per
/// link (re)start).
pub type Opener = Arc<dyn Fn(&LinkConfig, u32) -> std::io::Result<LinkSocket> + Send + Sync>;
use crate::spf;

/// RFC 2328 Appendix C.3's `RxmtInterval` — same fixed value/ponytail
/// rationale as `ospf::link::RXMT_INTERVAL`.
const RXMT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Same cadence/rationale as `ospf::link::ORIGINATION_INTERVAL`.
const ORIGINATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Same cadence/rationale as `ospf::link::AGE_TICK_INTERVAL`.
const AGE_TICK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How long `LinkManager::shutdown` waits after each Grace-LSA send before
/// the next one (two sends) and before exiting — enough for the link tasks
/// to put them on the wire. ponytail: sent twice, not retransmitted until
/// acked; a lossless local link is the norm here.
const GRACE_SEND_WINDOW: std::time::Duration = std::time::Duration::from_millis(500);

/// One link's fully-resolved desired state — diffed wholesale by
/// `LinkManager::reconcile`, mirroring `ospf::link::LinkConfig`.
#[derive(Debug, Clone, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent per-link flags (mtu-ignore, stub, nssa, ipv4-af), diffed wholesale"
)]
pub struct LinkConfig {
    /// Display key, matching `reconcile::attach_points_for`'s
    /// `"<interface>.<tag>"`/`"broadcast-domain:<name>"` convention.
    pub attach_point: String,
    pub area_id: Ipv4Addr,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub vrf: String,
    /// The real Linux device this link's raw socket binds to — see
    /// `ospf::link::LinkConfig.kernel_interface`'s identical doc comment on
    /// why this is never the VRF device.
    pub kernel_interface: String,
    /// This link's RFC 5340 Interface ID — derived from the kernel
    /// interface's own ifindex (`libc::if_nametoindex`, resolved in
    /// `reconcile.rs`), doubling as the socket's multicast scope id (see
    /// `socket::OspfSocket::open`).
    pub interface_id: u32,
    /// This link's own kernel-assigned IPv6 link-local address — Hello and
    /// every self-originated Link-LSA are sourced from this.
    pub link_local_address: Ipv6Addr,
    /// Every global/ULA prefix of this link's attach point (non-empty,
    /// config order, primary first; link-local excluded), advertised via
    /// a Link-LSA and an Intra-Area-Prefix-LSA (#952).
    /// For an IPv4-unicast instance (`ipv4_af`) the interface's IPv4 prefix in
    /// `lsa`'s shadow form (RFC 5838 §2.5).
    pub prefixes: Vec<Ipv6Net>,
    pub cost: u16,
    pub network_type: NetworkType,
    pub priority: u8,
    pub mtu: u16,
    /// `mtu-ignore`: skip the RFC 2328 §10.6 DBD Interface MTU check.
    pub mtu_ignore: bool,
    /// RFC 7166 keys resolved from `Ospfv3Profile.auth` (`reconcile.rs`);
    /// `None` runs unauthenticated. Part of the wholesale-diffed struct, so
    /// a key change restarts the link like any other field.
    pub auth: Option<packet::TrailerAuth>,
    /// RFC 5340 §A.3.1 Instance ID (`Ospfv3Profile.instance_id`, 0 if
    /// unset): stamped on every packet sent, and a received packet carrying
    /// another one is dropped.
    pub instance_id: u8,
    /// RFC 3623 helper: the most seconds of a neighbor's grace period this
    /// link honours (`graceful-restart helper max-grace-period`).
    pub helper_max_grace_period: u32,
    /// The link's area is a stub or totally-stubby area (RFC 5340 §4.4.3):
    /// no E-bit, no AS-scope LSAs on this link.
    pub stub: bool,
    /// The instance's address family is IPv4 unicast (RFC 5838): the AF-bit
    /// is set in this link's Hellos, DBDs and LSAs, and a Hello without it
    /// is discarded.
    pub ipv4_af: bool,
    /// The link's area is an NSSA (RFC 3101; `stub` is set too): the N-bit
    /// replaces the E-bit in Options, and only here are Type-7s exchanged.
    pub nssa: bool,
    /// `Some` for an RFC 5340 §4.7 virtual link: area 0, unicast to
    /// `neighbor`, a type-4 Router-LSA link, no Link-LSA. Resolved from the
    /// transit area's SPF (`resolve_virtual_link`), never from an attach
    /// point. `link_local_address` then holds our own global source address.
    pub virtual_link: Option<VirtualLinkEnd>,
}

impl LinkConfig {
    /// The first (primary) prefix: its address is the router's own.
    fn primary(&self) -> Ipv6Net {
        self.prefixes[0]
    }

    /// The address this link's Link-LSA advertises as its next-hop address:
    /// the link-local one, or (RFC 5838 §2.5) the IPv4 address in shadow form.
    fn lsa_address(&self) -> Ipv6Addr {
        if self.ipv4_af {
            self.primary().addr()
        } else {
            self.link_local_address
        }
    }

    /// A prefix's address as a host prefix (/128, or /32 for IPv4).
    fn host_prefix(&self, p: &Ipv6Net) -> Ipv6Net {
        Ipv6Net::new(p.addr(), if self.ipv4_af { 32 } else { 128 }).expect("host length is valid")
    }
}

/// A virtual link's transit area, far endpoint's router id and its global
/// address in the transit area (where every packet is unicast to).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualLinkEnd {
    pub transit_area: Ipv4Addr,
    pub endpoint: Ipv4Addr,
    pub neighbor: Ipv6Addr,
}

/// One configured virtual link (`Ospfv3Area.virtual_links`), before §4.7 has
/// resolved it to a `LinkConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct VirtualLinkConfig {
    pub transit_area: Ipv4Addr,
    pub endpoint: Ipv4Addr,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub auth: Option<packet::TrailerAuth>,
}

/// The attach-point name of a virtual link.
fn virtual_link_name(transit_area: Ipv4Addr, endpoint: Ipv4Addr) -> String {
    format!("vlink-{transit_area}-{endpoint}")
}

/// RFC 5340 §4.7: `v` as a running link while its endpoint has an intra-area
/// path in the transit area (`lsas` is that area's LSDB) and advertises a
/// global address there, with the path's distance as cost; `None` (down)
/// otherwise. Our own source address is our first global `/128` loopback in
/// the transit area (`loopbacks`), the neighbor's the endpoint's (RFC 5340
/// §4.4.3.9). The transit area's first link in `physical` supplies the VRF,
/// MTU and Instance ID. ponytail: the Interface ID is the endpoint's router
/// id (unique per link, never an ifindex); RFC 5340 §A.3.1's Interface MTU 0
/// in the virtual link's DBDs is skipped (`mtu_ignore`).
fn resolve_virtual_link(
    v: &VirtualLinkConfig,
    local_router_id: Ipv4Addr,
    lsas: &[Arc<Lsa>],
    physical: &[LinkConfig],
    loopbacks: &[(Ipv6Net, u16)],
) -> Option<LinkConfig> {
    let end = spf::virtual_link_endpoint(local_router_id, lsas, v.endpoint)?;
    let local = loopbacks
        .iter()
        .filter(|(p, _)| p.prefix_len() == 128 && spf::is_virtual_address(p.addr()))
        .map(|(p, _)| p.addr())
        .min()?;
    let transit = physical.iter().find(|c| c.area_id == v.transit_area)?;
    Some(LinkConfig {
        attach_point: virtual_link_name(v.transit_area, v.endpoint),
        area_id: Ipv4Addr::UNSPECIFIED,
        hello_interval: v.hello_interval,
        dead_interval: v.dead_interval,
        vrf: transit.vrf.clone(),
        kernel_interface: transit.vrf.clone(),
        interface_id: u32::from(v.endpoint),
        link_local_address: local,
        prefixes: vec![Ipv6Net::new(local, 128).expect("128 is valid")],
        cost: u16::try_from(end.cost).unwrap_or(u16::MAX),
        network_type: NetworkType::PointToPoint,
        priority: 0,
        mtu: transit.mtu,
        mtu_ignore: true,
        auth: v.auth.clone(),
        instance_id: transit.instance_id,
        helper_max_grace_period: transit.helper_max_grace_period,
        stub: false,
        ipv4_af: transit.ipv4_af,
        nssa: false,
        virtual_link: Some(VirtualLinkEnd {
            transit_area: v.transit_area,
            endpoint: v.endpoint,
            neighbor: end.address,
        }),
    })
}

/// Equal in every field but `cost`, which `apply_links` updates in place.
fn same_but_cost(a: &LinkConfig, b: &LinkConfig) -> bool {
    *a == LinkConfig {
        cost: a.cost,
        ..b.clone()
    }
}

/// `helper_max_grace_period` when the instance sets none.
pub const DEFAULT_HELPER_MAX_GRACE_PERIOD: u32 = 1800;

/// The Options every self-originated LSA and packet carries: `V6`/`R`, and
/// `E` outside a stub area (RFC 5340 §A.2; an FRR neighbor treats a clear
/// E-bit in a normal area as a mismatch). `own_options` clears E on a stub
/// link and sets N (RFC 3101 §2.1) in an NSSA.
const OWN_OPTIONS: u32 = lsa::OPTION_V6 | lsa::OPTION_E | lsa::OPTION_R;

/// Hello/DBD Options for this link — `OWN_OPTIONS`, plus RFC 7166 §2.1's
/// AT-bit when the link is authenticated.
fn link_options(cfg: &LinkConfig) -> u32 {
    let at = if cfg.auth.is_some() {
        lsa::OPTION_AT
    } else {
        0
    };
    own_options(cfg.stub, cfg.nssa, cfg.ipv4_af) | at
}

/// `OWN_OPTIONS` for an area of this kind: no E-bit in a stub area or NSSA,
/// the N-bit in an NSSA, the AF-bit (RFC 5838) on an IPv4-unicast link.
fn own_options(stub: bool, nssa: bool, ipv4_af: bool) -> u32 {
    let base = match (stub, nssa) {
        (_, true) => (OWN_OPTIONS & !lsa::OPTION_E) | lsa::OPTION_N,
        (true, false) => OWN_OPTIONS & !lsa::OPTION_E,
        (false, false) => OWN_OPTIONS,
    };
    if ipv4_af {
        base | lsa::OPTION_AF
    } else {
        base
    }
}

/// RFC 7166 §4.1's anti-replay check, mirroring
/// `ospf::link::accept_crypto_sequence`: `true` to dispatch, `false` to
/// drop. Tracked per packet type: RFC 7166 §4.6 lets a sender keep one
/// counter per type. Always `true` unauthenticated (`seq` is `None`) or for a neighbor
/// not yet known (`handle_hello` creates the entry).
fn accept_crypto_sequence(status: &StatusHandle, seq: Option<u64>, pkt: &OspfPacket) -> bool {
    let Some(seq) = seq else { return true };
    let router_id = packet::router_id(pkt);
    let ptype = packet::packet_type(pkt);
    let last = status
        .borrow()
        .neighbors
        .get(&router_id)
        .and_then(|n| n.last_crypto_seq.get(&ptype).copied());
    if last.is_some_and(|last| seq <= last) {
        return false;
    }
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&router_id) {
            n.last_crypto_seq.insert(ptype, seq);
        }
    });
    true
}

/// RFC 5340 §4.5.1's interface states — mirrors `ospf::link::InterfaceState`
/// one-to-one (unchanged by RFC 5340).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceState {
    PointToPoint,
    Waiting,
    Dr,
    Backup,
    DrOther,
}

/// A neighbor gone `Down` forgets its crypto sequence numbers (#612): a
/// restarted peer may legitimately reseed below the stored value (RFC 7166
/// keeps this state per adjacency). `Init` keeps it (a live neighbor
/// mid-handshake).
fn clear_replay_state(info: &mut NeighborInfo) {
    if info.state == NeighborState::Down {
        info.last_crypto_seq.clear();
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NeighborInfo {
    pub state: NeighborState,
    pub priority: u8,
    pub declared_dr: Ipv4Addr,
    pub declared_bdr: Ipv4Addr,
    /// This neighbor's own RFC 5340 Interface ID on this link, learned from
    /// its Hello — needed both for `crate::spf`'s next-hop derivation (a
    /// Router-LSA link's `Neighbor Interface ID` field) and to look up its
    /// own Link-LSA.
    pub interface_id: u32,
    /// Reported only (`last_hello_secs`): when the last valid Hello arrived.
    pub last_hello_received: Instant,
    /// RFC 4222 §2 recommendation 2 — see `ospf::link::NeighborInfo::last_heard`.
    pub last_heard: Instant,
    /// The neighbor's own link-local address, as seen on the last Hello it
    /// sent — DBD/LSR/LSU/LSAck reply unicast to this.
    pub address: Ipv6Addr,
    pub adjacency: Option<AdjacencyData>,
    /// The last accepted RFC 7166 sequence number from this neighbor, per
    /// packet type (empty until one is seen, or on an unauthenticated link).
    pub last_crypto_seq: HashMap<u8, u64>,
    /// RFC 5187 helper mode: `Some` while this neighbor is restarting under
    /// a Grace-LSA it sent. Until then its adjacency is held `Full` through
    /// missing Hellos and Hellos that don't list us (see `in_grace`).
    pub grace_deadline: Option<Instant>,
    /// When the neighbor reached `Full`; `None` otherwise. Written only by `set_state`.
    pub full_since: Option<Instant>,
}

impl NeighborInfo {
    /// Every `state` write goes through here so `full_since` stays in step.
    pub fn set_state(&mut self, new: NeighborState) {
        if new == NeighborState::Full {
            if self.state != NeighborState::Full {
                self.full_since = Some(Instant::now());
            }
        } else {
            self.full_since = None;
        }
        self.state = new;
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinkStatus {
    pub interface_state: InterfaceState,
    pub neighbors: HashMap<Ipv4Addr, NeighborInfo>,
    pub dr: Option<Ipv4Addr>,
    pub bdr: Option<Ipv4Addr>,
}

impl LinkStatus {
    fn new(network_type: NetworkType) -> Self {
        Self {
            interface_state: match network_type {
                NetworkType::PointToPoint | NetworkType::PointToMultipoint => {
                    InterfaceState::PointToPoint
                }
                NetworkType::Broadcast | NetworkType::Hybrid => InterfaceState::Waiting,
            },
            neighbors: HashMap::new(),
            dr: None,
            bdr: None,
        }
    }
}

pub type StatusHandle = watch::Sender<LinkStatus>;

/// RFC 2328 §7.5/§10.4 (unchanged by RFC 5340) — mirrors
/// `ospf::link::should_form_adjacency` verbatim.
fn should_form_adjacency(
    interface_state: InterfaceState,
    neighbor_id: Ipv4Addr,
    dr: Option<Ipv4Addr>,
    bdr: Option<Ipv4Addr>,
) -> bool {
    matches!(
        interface_state,
        InterfaceState::PointToPoint | InterfaceState::Dr | InterfaceState::Backup
    ) || dr == Some(neighbor_id)
        || bdr == Some(neighbor_id)
}

/// Mirrors `ospf::link::initial_dd_sequence_number` verbatim.
fn initial_dd_sequence_number() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |d| d.subsec_nanos())
}

/// Builds a fresh `AdjacencyData` plus the negotiation DBD to send.
fn start_negotiation(cfg: &LinkConfig, local_router_id: Ipv4Addr) -> (AdjacencyData, DbdPacket) {
    let seed = initial_dd_sequence_number();
    let dbd = DbdPacket {
        lls: None,
        router_id: local_router_id,
        area_id: cfg.area_id,
        options: link_options(cfg),
        interface_mtu: cfg.mtu,
        init: true,
        resync: false,
        more: true,
        master: true,
        dd_sequence_number: seed,
        lsa_headers: Vec::new(),
    };
    let adj = AdjacencyData {
        dd_sequence_number: seed,
        last_dbd_sent: Some(dbd.clone()),
        unpolled: true,
        ..AdjacencyData::default()
    };
    (adj, dbd)
}

/// Runs until aborted. Owns the raw socket, the Hello send ticker, and
/// every timer this link's network type needs — mirrors `ospf::link::run`'s
/// shape, minus all crypto-sequence/auth bookkeeping. `lsdb` is the area's
/// shared store; `link_local_lsdb` is this link's own (RFC 5340 §4.5.1:
/// Link-LSAs never leave the link they belong to, so every summary/flood
/// below draws from both, but only ever *this* link's Link-LSAs).
#[allow(clippy::too_many_arguments)]
#[allow(
    clippy::too_many_lines,
    reason = "one select loop; the arms are the logic"
)]
pub async fn run(
    socket: std::io::Result<LinkSocket>,
    cfg: LinkConfig,
    local_router_id: Ipv4Addr,
    lsdb: Arc<Mutex<Lsdb>>,
    link_local_lsdb: Arc<Mutex<Lsdb>>,
    as_lsdb: Arc<Mutex<Lsdb>>,
    status: StatusHandle,
    dbd_max_headers: Option<usize>,
    mut grace_rx: mpsc::UnboundedReceiver<GraceCmd>,
    startup_grace: Option<(u32, u8)>,
    mut topology_rx: mpsc::UnboundedReceiver<Vec<Ipv4Addr>>,
    mut bfd_rx: mpsc::UnboundedReceiver<Ipv6Addr>,
) {
    let stores = Stores {
        area: &lsdb,
        link: &link_local_lsdb,
        as_scope: &as_lsdb,
        stub: cfg.stub,
    };
    let dbd_max_headers =
        dbd_max_headers.unwrap_or_else(|| exchange::mtu_based_max_headers(cfg.mtu));
    let socket = match socket {
        Ok(s) => s,
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "failed to open ospfv3 raw socket");
            return;
        }
    };

    let mut hello_ticker = tokio::time::interval(std::time::Duration::from_secs(u64::from(
        cfg.hello_interval,
    )));
    hello_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let is_broadcast = elects_dr(cfg.network_type);
    let mut dead_sweep = tokio::time::interval(std::time::Duration::from_secs(1));
    dead_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let wait_deadline =
        Instant::now() + std::time::Duration::from_secs(u64::from(cfg.dead_interval));
    let mut waiting = is_broadcast;
    let mut warn_limiter = nos_ospf_common::ratelimit::WarnLimiter::default();

    let mut last_flood_dest: Option<Dest> = None;
    let mut rxmt_sweep = tokio::time::interval(RXMT_INTERVAL);
    rxmt_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    info!(link = %cfg.attach_point, vrf = %cfg.vrf, authenticated = cfg.auth.is_some(), "ospfv3 link driver started");
    if is_broadcast {
        info!(link = %cfg.attach_point, "ospfv3 interface reached waiting");
    }

    // RFC 5187 §2.1: a restarting router announces itself before its first
    // Hello. Its neighbor table is empty, so the LSU goes to the link's group.
    if let Some((grace_period, reason)) = startup_grace {
        let payload = grace_payload(&cfg, local_router_id, grace_period, reason, 0);
        match socket.send_multicast(cfg.interface_id, &payload) {
            Ok(()) => info!(
                link = %cfg.attach_point, grace_period, reason,
                "ospfv3 graceful restart: grace-lsa sent at startup"
            ),
            Err(e) => {
                warn!(link = %cfg.attach_point, error = %e, "failed to send ospfv3 startup grace-lsa");
            }
        }
    }

    loop {
        // RFC 4222 prioritisation — see `ospf::link::run`'s note and ceiling.
        tokio::select! {
            biased;
            _ = hello_ticker.tick() => {
                send_hello(&socket, &cfg, local_router_id, &status);
            }
            result = socket.recv_packet() => {
                match result {
                    Ok((source, _)) if drops_non_link_local(&cfg, source) => {}
                    Ok((source, data)) => {
                        // Before the trailer check: another instance's packets on a
                        // shared link are routine and may use other keys (RFC 5838).
                        if let Some(received) =
                            packet::instance_id(&data).filter(|i| *i != cfg.instance_id)
                        {
                            debug!(
                                link = %cfg.attach_point, source = %source, received,
                                expected = cfg.instance_id, "ospfv3 packet instance id mismatch, dropping"
                            );
                            continue;
                        }
                        let (data, seq) = match packet::verify_trailer(&data, cfg.auth.as_ref(), source) {
                            Ok(verified) => verified,
                            Err(e) => {
                                warn!(link = %cfg.attach_point, source = %source, error = %e, "ospfv3 packet authentication failed");
                                continue;
                            }
                        };
                        match packet::decode(data) {
                            Ok(pkt) if !accept_crypto_sequence(&status, seq, &pkt) => {
                                warn!(
                                    link = %cfg.attach_point, neighbor = %packet::router_id(&pkt),
                                    "ospfv3 packet crypto sequence number not increasing, dropping"
                                );
                            }
                            Ok(pkt) => {
                                if !matches!(pkt, OspfPacket::Hello(_)) {
                                    note_alive(&status, packet::router_id(&pkt));
                                }
                                match pkt {
                                    OspfPacket::Hello(hello) => {
                                        let left_waiting = handle_hello(
                                            &socket, &cfg, local_router_id, &status, source, &hello,
                                            waiting, &mut warn_limiter,
                                        );
                                        if left_waiting {
                                            waiting = false;
                                        }
                                        advance_adjacencies(&socket, &cfg, local_router_id, &status);
                                    }
                                    OspfPacket::Dbd(dbd) => {
                                        if let Some(actions) = handle_dbd(
                                            &cfg, local_router_id, &status, &stores, &dbd, dbd_max_headers,
                                        )
                                        .await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, dbd.router_id, actions);
                                        }
                                    }
                                    OspfPacket::Lsr(lsr) => {
                                        if let Some(actions) =
                                            handle_lsr(&cfg, local_router_id, &status, &stores, &lsr).await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, lsr.router_id, actions);
                                        }
                                    }
                                    OspfPacket::Lsu(lsu) => {
                                        if lsu.discarded > 0
                                            && warn_limiter.allow(tokio::time::Instant::now().into_std())
                                        {
                                            warn!(
                                                link = %cfg.attach_point, neighbor = %lsu.router_id,
                                                discarded = lsu.discarded, error = ?lsu.last_error,
                                                "ospfv3 lsu: discarded LSAs that failed to decode"
                                            );
                                        }
                                        if let Some(actions) =
                                            handle_lsu(&cfg, local_router_id, &status, &stores, &lsu).await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, lsu.router_id, actions);
                                        }
                                    }
                                    OspfPacket::LsAck(ack) => {
                                        handle_lsack(&status, &ack);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(link = %cfg.attach_point, error = %e, "failed to decode ospfv3 packet");
                            }
                        }
                    }
                    Err(e) => warn!(link = %cfg.attach_point, error = %e, "ospfv3 recv error"),
                }
            }
            _ = dead_sweep.tick() => {
                expire_grace(&cfg, &status);
                sweep_dead_neighbors(&cfg, &status);
                if is_broadcast && !waiting {
                    run_election(&socket, &cfg, local_router_id, &status);
                    advance_adjacencies(&socket, &cfg, local_router_id, &status);
                }
            }
            () = tokio::time::sleep_until(wait_deadline), if waiting => {
                waiting = false;
                run_election(&socket, &cfg, local_router_id, &status);
                advance_adjacencies(&socket, &cfg, local_router_id, &status);
            }
            Some(cmd) = grace_rx.recv() => match cmd {
                // `LinkManager::flood_now`, RFC 6987 on-shutdown.
                GraceCmd::Resend => {
                    flood_full_neighbors(&socket, &cfg, local_router_id, &stores, &status, &mut last_flood_dest).await;
                }
                GraceCmd::Announce(grace_period) => {
                    send_grace_lsas(&socket, &cfg, local_router_id, &status, grace_period, lsa::RESTART_REASON_SOFTWARE, 0);
                }
                // RFC 5187 §2.3: restart mode ended, a MaxAge Grace-LSA.
                GraceCmd::Flush => {
                    send_grace_lsas(&socket, &cfg, local_router_id, &status, 0, lsa::RESTART_REASON_SOFTWARE, lsa::MAX_AGE);
                }
            },
            Some(address) = bfd_rx.recv() => kill_bfd_neighbor(&cfg, &status, address),
            Some(origins) = topology_rx.recv() => exit_grace_on_topology_change(&cfg, &status, &origins),
            _ = rxmt_sweep.tick() => {
                retransmit_pending(&socket, &cfg, local_router_id, &status);
                flush_pending_acks(&socket, &cfg, local_router_id, &status);
                flood_full_neighbors(&socket, &cfg, local_router_id, &stores, &status, &mut last_flood_dest).await;
            }
        }
    }
}

/// The three stores one link reads and writes (RFC 5340 §4.5.1): its area's,
/// its own link-local one and the AS-wide one.
struct Stores<'a> {
    area: &'a Mutex<Lsdb>,
    link: &'a Mutex<Lsdb>,
    as_scope: &'a Mutex<Lsdb>,
    /// A stub area's link never reads the AS-scope store.
    stub: bool,
}

impl Stores<'_> {
    /// Every LSA this link may summarize/flood.
    async fn all(&self) -> Vec<Arc<Lsa>> {
        let mut lsas = self.area.lock().await.all();
        lsas.extend(self.link.lock().await.all());
        if !self.stub {
            lsas.extend(self.as_scope.lock().await.all());
        }
        lsas
    }

    async fn headers(&self) -> Vec<LsaHeader> {
        let mut headers = self.area.lock().await.headers();
        headers.extend(self.link.lock().await.headers());
        if !self.stub {
            headers.extend(self.as_scope.lock().await.headers());
        }
        headers
    }
}

fn send_hello(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
) {
    let current = status.borrow();
    let neighbors: Vec<Ipv4Addr> = current
        .neighbors
        .iter()
        .filter(|(_, info)| info.state != NeighborState::Down)
        .map(|(id, _)| *id)
        .collect();
    let (designated_router, backup_designated_router) = match cfg.network_type {
        NetworkType::PointToPoint | NetworkType::PointToMultipoint => {
            (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
        }
        NetworkType::Broadcast | NetworkType::Hybrid => (
            current.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
            current.bdr.unwrap_or(Ipv4Addr::UNSPECIFIED),
        ),
    };
    drop(current);

    let pkt = packet::HelloPacket {
        router_id: local_router_id,
        area_id: cfg.area_id,
        interface_id: cfg.interface_id,
        router_priority: cfg.priority,
        options: link_options(cfg),
        hello_interval: cfg.hello_interval,
        dead_interval: cfg.dead_interval,
        designated_router,
        backup_designated_router,
        neighbors,
    };
    if let Err(e) = socket.send_multicast(cfg.interface_id, &packet::encode_hello(&pkt)) {
        warn!(link = %cfg.attach_point, error = %e, "failed to send ospfv3 hello");
    }
}

/// RFC 5340 §4.2.2: every packet is sent from a link-local address; anything
/// else is off-link or spoofed and is dropped (`debug!` only, #394).
fn drops_non_link_local(cfg: &LinkConfig, source: Ipv6Addr) -> bool {
    // A virtual link's packets come from the endpoint's global address,
    // and nothing else.
    if let Some(v) = cfg.virtual_link {
        let drop = source != v.neighbor;
        if drop {
            debug!(link = %cfg.attach_point, source = %source, "ospfv3 packet from other than the virtual neighbor, dropping");
        }
        return drop;
    }
    let drop = !source.is_unicast_link_local();
    if drop {
        debug!(link = %cfg.attach_point, source = %source, "ospfv3 packet from non-link-local source, dropping");
    }
    drop
}

/// `warn!` through the link's `WarnLimiter` (#394); a line that follows
/// dropped ones is preceded by a count of them.
macro_rules! warn_limited {
    ($limiter:expr, $($arg:tt)+) => {
        if $limiter.allow(Instant::now().into_std()) {
            let suppressed = $limiter.take_suppressed();
            if suppressed > 0 {
                warn!(suppressed, "ospfv3 hello warnings were rate limited");
            }
            warn!($($arg)+);
        }
    };
}

/// Returns whether this Hello caused a broadcast link to leave `Waiting`
/// early — mirrors `ospf::link::rx::handle_hello`'s shape, `source`/`address`
/// now `Ipv6Addr`, and records the neighbor's own `interface_id` from the
/// Hello (needed for SPF next-hop derivation, see `NeighborInfo`).
#[allow(clippy::too_many_arguments)]
fn handle_hello(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    source: Ipv6Addr,
    hello: &packet::HelloPacket,
    waiting: bool,
    limiter: &mut nos_ospf_common::ratelimit::WarnLimiter,
) -> bool {
    // A virtual link has exactly one neighbor: its endpoint.
    if cfg
        .virtual_link
        .is_some_and(|v| v.endpoint != hello.router_id)
    {
        return false;
    }
    if hello.area_id != cfg.area_id {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, area = %hello.area_id, expected = %cfg.area_id,
            "dropping ospfv3 hello with mismatched area"
        );
        return false;
    }

    // RFC 5340 §A.2 / RFC 2328 §10.5: the E-bit is clear exactly in a stub
    // area or NSSA, so both ends must agree on whether the area is one.
    if (hello.options & lsa::OPTION_E != 0) == cfg.stub {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, neighbor = %hello.router_id,
            "dropping ospfv3 hello with mismatched e-bit"
        );
        return false;
    }
    // RFC 3101 §2.1: the N-bit is set exactly in an NSSA.
    if (hello.options & lsa::OPTION_N != 0) != cfg.nssa {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, neighbor = %hello.router_id,
            "dropping ospfv3 hello with mismatched n-bit"
        );
        return false;
    }

    // RFC 5838 §2.4: an IPv4-unicast instance only forms adjacencies with
    // routers that set the AF-bit (the base IPv6 AF is exempt).
    if cfg.ipv4_af && hello.options & lsa::OPTION_AF == 0 {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, neighbor = %hello.router_id,
            "dropping ospfv3 hello without af-bit"
        );
        return false;
    }

    // RFC 5340 §4.2.2.1 / RFC 2328 §10.5 (#650): differing timers discard the Hello.
    if hello.hello_interval != cfg.hello_interval {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, hello_interval = hello.hello_interval,
            expected = cfg.hello_interval,
            "dropping ospfv3 hello with mismatched hello-interval"
        );
        return false;
    }
    if hello.dead_interval != cfg.dead_interval {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, dead_interval = hello.dead_interval,
            expected = cfg.dead_interval,
            "dropping ospfv3 hello with mismatched dead-interval"
        );
        return false;
    }

    // #957: a point-to-point / multipoint peer back under a new router ID from
    // the same address supersedes its old entry at once. Grace entries are
    // kept (RFC 5187); broadcast and hybrid never evict.
    if !elects_dr(cfg.network_type) {
        evict_same_address(cfg, status, source, hello.router_id);
    }

    // A segment peer cycling router-ids must not grow the table without bound
    // (#394); known neighbors keep refreshing at the cap.
    {
        let st = status.borrow();
        if !st.neighbors.contains_key(&hello.router_id)
            && st.neighbors.len() >= nos_ospf_common::ratelimit::MAX_NEIGHBORS_PER_LINK
        {
            drop(st);
            warn_limited!(
                limiter,
                link = %cfg.attach_point, neighbor = %hello.router_id,
                "ospfv3 neighbor limit reached, dropping hello"
            );
            return false;
        }
    }

    let saw_self = hello.neighbors.contains(&local_router_id);
    let old_state = status
        .borrow()
        .neighbors
        .get(&hello.router_id)
        .map_or(NeighborState::Down, |n| n.state);
    // RFC 5187 §3: a restarting neighbor's fresh Hellos don't list us yet —
    // that must not tear the adjacency down while we're helping it.
    let new_state = if !saw_self && in_grace(status, hello.router_id) {
        old_state
    } else {
        neighbor::step(old_state, neighbor::Event::HelloReceived { saw_self })
    };
    if old_state == NeighborState::Down && new_state == NeighborState::Init {
        info!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospfv3 neighbor state changed to init");
    }
    if old_state != NeighborState::TwoWay && new_state == NeighborState::TwoWay {
        info!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospfv3 neighbor reached two-way");
    }
    if old_state != NeighborState::Init
        && new_state == NeighborState::Init
        && old_state != NeighborState::Down
    {
        warn!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospfv3 neighbor adjacency torn down, back to init");
    }
    status.send_modify(|s| {
        let entry = s
            .neighbors
            .entry(hello.router_id)
            .or_insert_with(|| NeighborInfo {
                state: NeighborState::Down,
                priority: 0,
                declared_dr: Ipv4Addr::UNSPECIFIED,
                declared_bdr: Ipv4Addr::UNSPECIFIED,
                interface_id: hello.interface_id,
                last_hello_received: Instant::now(),
                last_heard: Instant::now(),
                address: source,
                adjacency: None,
                last_crypto_seq: HashMap::new(),
                grace_deadline: None,
                full_since: None,
            });
        entry.set_state(new_state);
        entry.priority = hello.router_priority;
        entry.declared_dr = hello.designated_router;
        entry.declared_bdr = hello.backup_designated_router;
        entry.interface_id = hello.interface_id;
        entry.last_hello_received = Instant::now();
        entry.last_heard = Instant::now();
        entry.address = source;
        if matches!(new_state, NeighborState::Down | NeighborState::Init) {
            entry.adjacency = None;
        }
    });

    match cfg.network_type {
        NetworkType::Broadcast | NetworkType::Hybrid
            if waiting && hello.designated_router == hello.router_id =>
        {
            run_election(socket, cfg, local_router_id, status);
            true
        }
        NetworkType::Broadcast | NetworkType::Hybrid if !waiting => {
            run_election(socket, cfg, local_router_id, status);
            false
        }
        // `last_heard` was refreshed above; the sweep expires it.
        NetworkType::Broadcast
        | NetworkType::Hybrid
        | NetworkType::PointToPoint
        | NetworkType::PointToMultipoint => false,
    }
}

fn advance_adjacencies(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
) {
    let snapshot = status.borrow().clone();
    let eligible: Vec<Ipv4Addr> = snapshot
        .neighbors
        .iter()
        .filter(|(id, info)| {
            info.state == NeighborState::TwoWay
                && info.adjacency.is_none()
                && should_form_adjacency(snapshot.interface_state, **id, snapshot.dr, snapshot.bdr)
        })
        .map(|(id, _)| *id)
        .collect();
    drop(snapshot);

    for neighbor_id in eligible {
        let Some(neighbor_addr) = status
            .borrow()
            .neighbors
            .get(&neighbor_id)
            .map(|n| n.address)
        else {
            continue;
        };
        let (adj, dbd) = start_negotiation(cfg, local_router_id);
        if let Err(e) =
            socket.send_unicast(neighbor_addr, cfg.interface_id, &packet::encode_dbd(&dbd))
        {
            warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 dbd");
        }
        let new_state = neighbor::step(NeighborState::TwoWay, neighbor::Event::AdjacencyEligible);
        info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 neighbor reached exstart");
        status.send_modify(|s| {
            if let Some(info) = s.neighbors.get_mut(&neighbor_id) {
                info.set_state(new_state);
                info.adjacency = Some(adj);
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_dbd(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    stores: &Stores<'_>,
    dbd: &DbdPacket,
    dbd_max_headers: usize,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&dbd.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };

    // RFC 2328 §10.6: only in ExStart/Exchange; the neighbor stays in ExStart.
    if matches!(old_state, NeighborState::ExStart | NeighborState::Exchange)
        && !exchange::mtu_acceptable(dbd.interface_mtu, cfg.mtu, cfg.mtu_ignore)
    {
        warn!(
            neighbor = %dbd.router_id, local_mtu = cfg.mtu, neighbor_mtu = dbd.interface_mtu, link = %cfg.attach_point,
            "ospfv3 dbd rejected, neighbor interface mtu exceeds ours"
        );
        return None;
    }

    // A MaxAge entry is only held to be flooded out; summarizing it would
    // invite an LSR that fails (BadLSReq) once it's evicted.
    let mut local_lsdb_headers = stores.headers().await;
    local_lsdb_headers.retain(|h| h.age < lsa::MAX_AGE);
    let params = exchange::Params {
        local_router_id,
        max_headers: dbd_max_headers,
        mtu: cfg.mtu,
        dbd_options: link_options(cfg),
        peer_opaque_capable: false,
        peer_oob_capable: false,
    };
    let actions = exchange::on_dbd_received(
        &mut adj,
        old_state,
        &params,
        dbd,
        &local_lsdb_headers,
        cfg.stub,
        cfg.nssa,
    );

    Some(finish_neighbor_event(
        cfg,
        local_router_id,
        status,
        dbd.router_id,
        old_state,
        adj,
        actions,
    ))
}

async fn handle_lsr(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    stores: &Stores<'_>,
    lsr: &LsrPacket,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&lsr.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };
    if !neighbor::exchange_or_later(old_state) {
        debug!(neighbor = %lsr.router_id, state = ?old_state, "ospfv3 lsr ignored below exchange");
        return None;
    }

    let actions = {
        let lsdb = stores.area.lock().await;
        let link_local_lsdb = stores.link.lock().await;
        let as_lsdb = stores.as_scope.lock().await;
        exchange::on_lsr_received(&mut adj, &lsdb, &link_local_lsdb, &as_lsdb, lsr, cfg.stub)
    };

    Some(finish_neighbor_event(
        cfg,
        local_router_id,
        status,
        lsr.router_id,
        old_state,
        adj,
        actions,
    ))
}

async fn handle_lsu(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    stores: &Stores<'_>,
    lsu: &LsuPacket,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&lsu.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };
    if !neighbor::exchange_or_later(old_state) {
        debug!(neighbor = %lsu.router_id, state = ?old_state, "ospfv3 lsu ignored below exchange");
        return None;
    }

    let (actions, newly_installed) = {
        let mut lsdb = stores.area.lock().await;
        let mut link_local_lsdb = stores.link.lock().await;
        let mut as_lsdb = stores.as_scope.lock().await;
        let result = exchange::on_lsu_received(
            &mut adj,
            &mut lsdb,
            &mut link_local_lsdb,
            &mut as_lsdb,
            lsu,
            // tokio's clock, so paused-time tests see MinLSArrival pass.
            tokio::time::Instant::now().into_std(),
            cfg.stub,
            cfg.nssa,
        );
        // A Grace-LSA is acted on at once and never held: a copy left in the
        // LSDB would be offered back to the restarted router and flooded to
        // us again. Removed under the same lock the install took (as v2).
        for l in &lsu.lsas {
            if matches!(l.body, LsaBody::Grace(_)) && result.1.contains(&l.header) {
                link_local_lsdb.remove(&l.header.key());
            }
        }
        // RFC 2328 §13.4: our own LSA, newer than ours, came back — the
        // originator goes above it at once (`install_self_originated`).
        for h in nos_ospf_common::lsa::reflected_self_lsas(&result.1, local_router_id) {
            let store = if lsa::is_link_local_scope(h.lsa_type) {
                &mut link_local_lsdb
            } else if lsa::is_as_scope(h.lsa_type) {
                &mut as_lsdb
            } else {
                &mut lsdb
            };
            if store.get(&h.key()).is_none() {
                continue;
            }
            store.mark_reflected(h.key());
            info!(
                link = %cfg.attach_point, neighbor = %lsu.router_id,
                lsa_type = h.lsa_type, link_state_id = %h.link_state_id,
                received_sequence_number = h.sequence_number,
                "ospfv3 self-originated lsa received with newer sequence, reoriginating"
            );
        }
        result
    };
    if adj.pending_acks_since.is_none() && !adj.pending_acks.is_empty() {
        adj.pending_acks_since = Some(std::time::Instant::now());
    }
    for header in &newly_installed {
        info!(
            link = %cfg.attach_point, neighbor = %lsu.router_id,
            lsa_type = header.lsa_type, link_state_id = %header.link_state_id,
            advertising_router = %header.advertising_router,
            "ospfv3 lsa installed"
        );
    }
    for grace in lsu
        .lsas
        .iter()
        .filter(|l| newly_installed.contains(&l.header))
    {
        let LsaBody::Grace(body) = grace.body else {
            continue;
        };
        let was = in_grace(status, grace.header.advertising_router);
        on_grace_lsa(cfg, status, &grace.header, body);
        // #1027 (as v2): changes pending before this grace began are not
        // "during" it (RFC 3623 §3.2 (c)).
        if !was && in_grace(status, grace.header.advertising_router) {
            stores.area.lock().await.forget_topology_changes();
            stores.as_scope.lock().await.forget_topology_changes();
        }
    }

    Some(finish_neighbor_event(
        cfg,
        local_router_id,
        status,
        lsu.router_id,
        old_state,
        adj,
        actions,
    ))
}

fn handle_lsack(status: &StatusHandle, ack: &LsAckPacket) {
    let Some(mut adj) = status
        .borrow()
        .neighbors
        .get(&ack.router_id)
        .filter(|n| neighbor::exchange_or_later(n.state))
        .and_then(|n| n.adjacency.clone())
    else {
        return;
    };
    exchange::on_lsack_received(&mut adj, &ack.lsa_headers);
    status.send_modify(|s| {
        if let Some(info) = s.neighbors.get_mut(&ack.router_id) {
            info.adjacency = Some(adj.clone());
        }
    });
}

fn finish_neighbor_event(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    neighbor_id: Ipv4Addr,
    old_state: NeighborState,
    mut adj: AdjacencyData,
    actions: Vec<exchange::Action>,
) -> Vec<exchange::Action> {
    let mut new_state = old_state;
    for action in &actions {
        if let exchange::Action::NeighborEvent(event) = action {
            new_state = neighbor::step(new_state, *event);
        }
    }

    let actions = if new_state == NeighborState::ExStart && old_state != NeighborState::ExStart {
        let (fresh_adj, negotiation_dbd) = start_negotiation(cfg, local_router_id);
        adj = fresh_adj;
        warn!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 neighbor sequence mismatch, restarting negotiation");
        vec![exchange::Action::SendDbd(negotiation_dbd)]
    } else {
        for action in &actions {
            if let exchange::Action::SendDbd(pkt) = action {
                adj.last_dbd_sent = Some(pkt.clone());
            }
        }
        // Past `Exchange`, only the slave's final reply can still be needed:
        // `exchange` resends it for the master's duplicate (RFC 2328 §10.6).
        // ponytail: kept until the next `ExStart`, not the RFC's
        // `RouterDeadInterval`; one packet, no timer.
        if adj.is_master && matches!(new_state, NeighborState::Loading | NeighborState::Full) {
            adj.last_dbd_sent = None;
        }
        actions
    };

    match (old_state, new_state) {
        (s, NeighborState::Exchange) if s != NeighborState::Exchange => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 neighbor reached exchange");
        }
        (s, NeighborState::Loading) if s != NeighborState::Loading => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 neighbor reached loading");
        }
        (s, NeighborState::Full) if s != NeighborState::Full => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 neighbor reached full");
            if in_grace(status, neighbor_id) {
                info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 helper: neighbor reformed, exiting grace early");
            }
        }
        _ => {}
    }

    status.send_modify(|s| {
        if let Some(info) = s.neighbors.get_mut(&neighbor_id) {
            info.set_state(new_state);
            info.adjacency = Some(adj.clone());
            if new_state == NeighborState::Full && old_state != NeighborState::Full {
                info.grace_deadline = None;
            }
        }
    });

    actions
}

/// Bytes of one packet's budget on this link left for entries: the effective
/// MTU minus IPv6 (40), the `OSPFv3` header (16), the LSU LSA count (4; slack
/// for LSR/LSAck) and the RFC 7166 trailer when the link is authenticated.
fn split_budget(cfg: &LinkConfig) -> usize {
    lsa_budget(cfg.mtu, trailer_len(cfg), 0)
}

fn trailer_len(cfg: &LinkConfig) -> usize {
    cfg.auth
        .as_ref()
        .map_or(0, packet::TrailerAuth::trailer_len)
}

/// `split_budget` for a bare `mtu`/`trailer`, with `extra` more bytes of
/// overhead subtracted (a Router-LSA's 20-byte header plus 4 of flags/options).
fn lsa_budget(mtu: u16, trailer: usize, extra: usize) -> usize {
    usize::from(mtu).saturating_sub(40 + 16 + 4 + extra + trailer)
}

/// Router-LSA links per fragment: each fragment must fit one packet on the
/// area's smallest-MTU link (an LSA floods on every link of the area). Never
/// splits a link (an over-budget one stays alone). `max_links` caps a
/// fragment (test-only). Always at least one, possibly empty, fragment.
fn split_router_links(
    links: &[RouterLsaLink],
    budget: usize,
    max_links: Option<usize>,
) -> Vec<Vec<RouterLsaLink>> {
    let mut out: Vec<Vec<RouterLsaLink>> = Vec::new();
    for chunk in nos_ospf_common::exchange::chunk_by_budget(links, budget, |_| 16) {
        match max_links {
            Some(m) => out.extend(chunk.chunks(m.max(1)).map(<[_]>::to_vec)),
            None => out.push(chunk.to_vec()),
        }
    }
    if out.is_empty() {
        out.push(Vec::new());
    }
    out
}

/// Cuts `items` to the link MTU and encodes each chunk as its own packet (the
/// socket signs each with its own trailer sequence). An oversize item goes
/// alone. Logs `ospfv3 lsu split` when an LSU needs more than one packet.
fn split_packets<T>(
    cfg: &LinkConfig,
    kind: &'static str,
    items: &[T],
    size_of: impl Fn(&T) -> usize,
    encode: impl Fn(&[T]) -> Vec<u8>,
) -> Vec<Vec<u8>> {
    let chunks = nos_ospf_common::exchange::chunk_by_budget(items, split_budget(cfg), size_of);
    if chunks.len() > 1 {
        // LSU is the headline split (the e2e anchor); LSR/LSAck are noise.
        if kind == "lsu" {
            info!(link = %cfg.attach_point, packets = chunks.len(), "ospfv3 lsu split");
        } else {
            debug!(link = %cfg.attach_point, packets = chunks.len(), "ospfv3 {kind} split");
        }
    }
    chunks.into_iter().map(encode).collect()
}

fn lsu_packets(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    lsas: &[Arc<crate::lsa::Lsa>],
) -> Vec<Vec<u8>> {
    split_packets(
        cfg,
        "lsu",
        lsas,
        // Header `length` is not reliable on a freshly built LSA.
        |l| crate::lsa::encode_lsa(l).len(),
        |c| {
            packet::encode_lsu(&LsuPacket {
                discarded: 0,
                last_error: None,
                router_id: local_router_id,
                area_id: cfg.area_id,
                lsas: c.iter().map(|l| (**l).clone()).collect(),
            })
        },
    )
}

fn lsr_packets(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    requests: &[crate::lsa::LsaKey],
) -> Vec<Vec<u8>> {
    split_packets(
        cfg,
        "lsr",
        requests,
        |_| crate::lsa::KEY_LEN,
        |c| {
            packet::encode_lsr(&LsrPacket {
                router_id: local_router_id,
                area_id: cfg.area_id,
                requests: c.to_vec(),
            })
        },
    )
}

fn lsack_packets(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    headers: &[crate::lsa::LsaHeader],
) -> Vec<Vec<u8>> {
    split_packets(
        cfg,
        "lsack",
        headers,
        |_| crate::lsa::LSA_HEADER_LEN,
        |c| {
            packet::encode_lsack(&LsAckPacket {
                router_id: local_router_id,
                area_id: cfg.area_id,
                lsa_headers: c.to_vec(),
            })
        },
    )
}

fn execute_actions(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    neighbor_id: Ipv4Addr,
    actions: Vec<exchange::Action>,
) {
    let Some(neighbor_addr) = status
        .borrow()
        .neighbors
        .get(&neighbor_id)
        .map(|n| n.address)
    else {
        return;
    };
    for action in actions {
        let (kind, payloads) = match action {
            exchange::Action::SendDbd(pkt) => {
                if !pkt.init && pkt.more {
                    info!(
                        link = %cfg.attach_point, neighbor = %neighbor_id,
                        dd_sequence_number = pkt.dd_sequence_number,
                        "ospfv3 dbd chunk sent, more remaining"
                    );
                }
                let copies = nos_ospf_common::dbd_fault::copies();
                if copies != 1 {
                    info!(link = %cfg.attach_point, neighbor = %neighbor_id, copies, "ospfv3 dbd fault injected");
                }
                ("dbd", vec![packet::encode_dbd(&pkt); copies])
            }
            exchange::Action::SendLsr(requests) => {
                ("lsr", lsr_packets(cfg, local_router_id, &requests))
            }
            exchange::Action::SendLsu(lsas) => ("lsu", lsu_packets(cfg, local_router_id, &lsas)),
            exchange::Action::SendLsAck(lsa_headers) => {
                ("lsack", lsack_packets(cfg, local_router_id, &lsa_headers))
            }
            exchange::Action::NeighborEvent(_) | exchange::Action::OobResyncStart => continue,
        };
        for payload in payloads {
            if let Err(e) = socket.send_unicast(neighbor_addr, cfg.interface_id, &payload) {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, kind, error = %e, "failed to send ospfv3 packet");
            }
        }
    }
}

/// RFC 2328 §13.5 delayed acknowledgment (as `ospf::link::flood`'s): sends
/// each neighbor's queued acks (`AdjacencyData::pending_acks`) as one
/// `LSAck` on the `RXMT_INTERVAL` sweep.
fn flush_pending_acks(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
) {
    let dest = current_dest(cfg, status);
    if dest != Dest::Unicast {
        flush_pending_acks_group(socket, cfg, local_router_id, status, dest);
        return;
    }
    let mut flushes = Vec::new();
    status.send_if_modified(|s| {
        for (neighbor_id, info) in &mut s.neighbors {
            let Some(adj) = &mut info.adjacency else {
                continue;
            };
            let held = adj.pending_acks_since;
            if let Some(action) = exchange::take_pending_acks(adj) {
                flushes.push((*neighbor_id, held, action));
            }
        }
        // Nothing here changes what origination snapshots.
        false
    });
    for (neighbor_id, held, action) in flushes {
        if let exchange::Action::SendLsAck(headers) = &action {
            info!(
                link = %cfg.attach_point, neighbor = %neighbor_id, acked = headers.len(),
                delayed_ms = held.map_or(0, |t| t.elapsed().as_millis()),
                "ospfv3 lsack sent"
            );
        }
        execute_actions(
            socket,
            cfg,
            local_router_id,
            status,
            neighbor_id,
            vec![action],
        );
    }
}

/// RFC 2328 §13.3 step 5 / §13.5 (RFC 5340 §4.5 keeps them): where this
/// link's flooded LSUs and delayed `LSAcks` go. Only broadcast links use a
/// group; the DR/Backup role picks which.
fn current_dest(cfg: &LinkConfig, status: &StatusHandle) -> Dest {
    flood_dest(
        elects_dr(cfg.network_type),
        matches!(
            status.borrow().interface_state,
            InterfaceState::Dr | InterfaceState::Backup
        ),
    )
}

/// Broadcast links: one deduplicated `LSAck` set for every neighbor's queue,
/// to the group `dest`. A failed group send warns once and falls back to a
/// unicast copy per adjacent neighbor.
fn flush_pending_acks_group(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    dest: Dest,
) {
    let mut taken = (Vec::new(), None);
    status.send_if_modified(|s| {
        taken = exchange::take_all_pending_acks(
            s.neighbors
                .values_mut()
                .filter_map(|n| n.adjacency.as_mut()),
        );
        false
    });
    let (headers, since) = taken;
    if headers.is_empty() {
        return;
    }
    info!(
        link = %cfg.attach_point, dest = %dest.as_str(), acked = headers.len(),
        delayed_ms = since.map_or(0, |t| t.elapsed().as_millis()),
        "ospfv3 lsack sent"
    );
    for payload in lsack_packets(cfg, local_router_id, &headers) {
        if let Err(e) = socket.send_flood(dest, Ipv6Addr::UNSPECIFIED, cfg.interface_id, &payload) {
            warn!(link = %cfg.attach_point, dest = %dest.as_str(), error = %e, "failed to multicast ospfv3 lsack, falling back to unicast");
            let targets: Vec<Ipv6Addr> = status
                .borrow()
                .neighbors
                .values()
                .filter(|n| n.adjacency.is_some())
                .map(|n| n.address)
                .collect();
            for addr in targets {
                let _ = socket.send_unicast(addr, cfg.interface_id, &payload);
            }
        }
    }
}

fn retransmit_pending(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
) {
    let snapshot = status.borrow().clone();
    for (neighbor_id, info) in &snapshot.neighbors {
        let Some(adj) = &info.adjacency else { continue };
        // ExStart, or Exchange as master: a slave answers only the master's
        // poll (RFC 2328 §10.8), its kept reply never goes out on a timer.
        if let (true, Some(dbd)) = (
            info.state == NeighborState::ExStart
                || (info.state == NeighborState::Exchange && adj.is_master),
            &adj.last_dbd_sent,
        ) && let Err(e) =
            socket.send_unicast(info.address, cfg.interface_id, &packet::encode_dbd(dbd))
        {
            warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 dbd");
        }
        if !matches!(
            info.state,
            NeighborState::Exchange | NeighborState::Loading | NeighborState::Full
        ) {
            continue;
        }
        if !adj.request_list.is_empty() {
            for payload in lsr_packets(cfg, local_router_id, &adj.request_list) {
                if let Err(e) = socket.send_unicast(info.address, cfg.interface_id, &payload) {
                    warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 lsr");
                }
            }
        }
        if !adj.retransmission_list.is_empty() {
            let lsas: Vec<_> = adj.retransmission_list.values().cloned().collect();
            for payload in lsu_packets(cfg, local_router_id, &lsas) {
                if let Err(e) = socket.send_unicast(info.address, cfg.interface_id, &payload) {
                    warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 lsu");
                }
            }
        }
    }
}

/// Mirrors `ospf::link::flood::flood_full_neighbors`'s `ponytail:` periodic-resend
/// design exactly, same rationale.
async fn flood_full_neighbors(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    stores: &Stores<'_>,
    status: &StatusHandle,
    last_dest: &mut Option<Dest>,
) {
    let dest = current_dest(cfg, status);
    if *last_dest != Some(dest) {
        *last_dest = Some(dest);
        info!(link = %cfg.attach_point, dest = %dest.as_str(), "ospfv3 lsu flood destination changed");
    }
    let full_neighbors: Vec<(Ipv4Addr, Ipv6Addr)> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, info)| info.state == NeighborState::Full)
        .map(|(id, info)| (*id, info.address))
        .collect();
    if full_neighbors.is_empty() {
        return;
    }
    let lsas = stores.all().await;
    if lsas.is_empty() {
        return;
    }
    let payloads = lsu_packets(cfg, local_router_id, &lsas);
    // Multicast (RFC 2328 §13.3 step 5): each chunk once to the group; a
    // send error falls back to the unicast loop for this pass. One signed
    // packet is valid for all receivers (the trailer binds only the source).
    if dest != Dest::Unicast {
        let sent = payloads.iter().all(|payload| {
            socket
                .send_flood(dest, Ipv6Addr::UNSPECIFIED, cfg.interface_id, payload)
                .map_err(|e| {
                    warn!(link = %cfg.attach_point, dest = %dest.as_str(), error = %e, "failed to multicast ospfv3 lsu, falling back to unicast");
                })
                .is_ok()
        });
        if sent {
            return;
        }
    }
    for (neighbor_id, neighbor_addr) in full_neighbors {
        for payload in &payloads {
            if let Err(e) = socket.send_unicast(neighbor_addr, cfg.interface_id, payload) {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 lsu");
            }
        }
    }
}

/// RFC 2328 §10.2 `KillNbr` for the neighbor at link-local `address`, because
/// BFD found its path down (mirrors `ospf::link::kill_bfd_neighbor`).
fn kill_bfd_neighbor(cfg: &LinkConfig, status: &StatusHandle, address: Ipv6Addr) {
    status.send_modify(|s| {
        for (id, info) in &mut s.neighbors {
            if info.address == address && info.state != NeighborState::Down {
                warn!(link = %cfg.attach_point, neighbor = %id, "bfd session down, killing ospfv3 neighbor");
                info.set_state(bfd::on_bfd_down(info.state));
                info.adjacency = None;
                clear_replay_state(info);
            }
        }
    });
}

/// RFC 4222 §2 recommendation 2 — mirrors `ospf::link::flood::note_alive`.
fn note_alive(status: &StatusHandle, router_id: Ipv4Addr) {
    let adjacent = status.borrow().neighbors.get(&router_id).is_some_and(|n| {
        matches!(
            n.state,
            NeighborState::ExStart
                | NeighborState::Exchange
                | NeighborState::Loading
                | NeighborState::Full
        )
    });
    if !adjacent {
        return;
    }
    let now = Instant::now();
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&router_id) {
            n.last_heard = now;
        }
    });
}

fn sweep_dead_neighbors(cfg: &LinkConfig, status: &StatusHandle) {
    let now = Instant::now();
    let dead_interval = std::time::Duration::from_secs(u64::from(cfg.dead_interval));
    let expired: Vec<Ipv4Addr> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, info)| {
            info.state != NeighborState::Down
                && info.grace_deadline.is_none()
                && now.duration_since(info.last_heard) >= dead_interval
        })
        .map(|(id, _)| *id)
        .collect();
    if !expired.is_empty() {
        for id in &expired {
            warn!(link = %cfg.attach_point, neighbor = %id, "ospfv3 neighbor state changed to down");
        }
        status.send_modify(|s| {
            for id in &expired {
                if let Some(info) = s.neighbors.get_mut(id) {
                    info.state =
                        neighbor::step(info.state, neighbor::Event::InactivityTimerExpired);
                    info.adjacency = None;
                    clear_replay_state(info);
                }
            }
        });
    }
    // A Down entry silent for a full dead interval has no use: free the slot
    // (#957; else forged router IDs pin the neighbor cap for good). One tick
    // after the Down step at the earliest, so both events are observable.
    let gone: Vec<Ipv4Addr> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(id, info)| {
            info.state == NeighborState::Down
                && info.grace_deadline.is_none()
                && !expired.contains(id)
                && now.duration_since(info.last_heard) >= dead_interval
        })
        .map(|(id, _)| *id)
        .collect();
    if gone.is_empty() {
        return;
    }
    status.send_modify(|s| {
        for id in &gone {
            s.neighbors.remove(id);
        }
    });
    for id in &gone {
        info!(link = %cfg.attach_point, neighbor = %id, "ospfv3 neighbor entry removed");
    }
}

/// Steps every live, non-grace entry at `source` under another router ID to
/// `Down`; the dead-neighbor sweep then removes it.
fn evict_same_address(cfg: &LinkConfig, status: &StatusHandle, source: Ipv6Addr, new_id: Ipv4Addr) {
    status.send_modify(|s| {
        for (id, info) in &mut s.neighbors {
            if *id != new_id
                && info.address == source
                && info.state != NeighborState::Down
                && info.grace_deadline.is_none()
            {
                warn!(
                    link = %cfg.attach_point, neighbor = %id, new_neighbor = %new_id, address = %source,
                    "ospfv3 neighbor evicted, same address new router id"
                );
                info.set_state(neighbor::step(info.state, neighbor::Event::InactivityTimerExpired));
                info.adjacency = None;
                clear_replay_state(info);
            }
        }
    });
}

fn in_grace(status: &StatusHandle, neighbor_id: Ipv4Addr) -> bool {
    status
        .borrow()
        .neighbors
        .get(&neighbor_id)
        .is_some_and(|n| n.grace_deadline.is_some())
}

/// RFC 5187 helper side: a Grace-LSA from a `Full` neighbor on this link
/// starts (or refreshes) its grace period; a `MaxAge` one — the restarting
/// router flushing it — ends it.
fn on_grace_lsa(cfg: &LinkConfig, status: &StatusHandle, header: &LsaHeader, body: GraceLsaBody) {
    let neighbor_id = header.advertising_router;
    let Some((state, deadline)) = status
        .borrow()
        .neighbors
        .get(&neighbor_id)
        .map(|n| (n.state, n.grace_deadline))
    else {
        return;
    };
    if header.age >= lsa::MAX_AGE {
        if deadline.is_some() {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 helper: grace-lsa flushed, exiting grace");
            status.send_modify(|s| {
                if let Some(n) = s.neighbors.get_mut(&neighbor_id) {
                    n.grace_deadline = None;
                }
            });
        }
        return;
    }
    if state != NeighborState::Full {
        warn!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospfv3 helper: ignoring grace-lsa from a neighbor that is not full");
        return;
    }
    // RFC 3623 §3.1: what the Grace-LSA has left (period minus age), capped.
    let Some(effective) = nos_ospf_common::lsa::helper_deadline_secs(
        body.grace_period,
        header.age,
        cfg.helper_max_grace_period,
    ) else {
        warn!(
            link = %cfg.attach_point, neighbor = %neighbor_id, grace_period = body.grace_period, age = header.age,
            "ospfv3 helper: no grace left, exiting grace"
        );
        if deadline.is_some() {
            status.send_modify(|s| {
                if let Some(n) = s.neighbors.get_mut(&neighbor_id) {
                    n.grace_deadline = None;
                }
            });
        }
        return;
    };
    if deadline.is_none() {
        info!(
            link = %cfg.attach_point, neighbor = %neighbor_id,
            grace_period = body.grace_period, restart_reason = body.restart_reason,
            effective_grace = effective,
            "ospfv3 helper: grace period entered"
        );
    }
    let deadline = Instant::now() + std::time::Duration::from_secs(u64::from(effective));
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&neighbor_id) {
            n.grace_deadline = Some(deadline);
        }
    });
}

/// RFC 3623 §3.2 item 3 strict LSA checking: `origins` are the routers whose
/// topology LSAs changed in this link's scope. A neighbor in grace ends it
/// when anyone but the neighbor itself changed one; it is then subject to the
/// ordinary inactivity timer again, restarted from now.
fn exit_grace_on_topology_change(cfg: &LinkConfig, status: &StatusHandle, origins: &[Ipv4Addr]) {
    let exiting: Vec<Ipv4Addr> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(id, n)| n.grace_deadline.is_some() && origins.iter().any(|o| o != *id))
        .map(|(id, _)| *id)
        .collect();
    if exiting.is_empty() {
        return;
    }
    let now = Instant::now();
    for id in &exiting {
        info!(link = %cfg.attach_point, neighbor = %id, "ospfv3 helper: topology change, exiting grace");
    }
    status.send_modify(|s| {
        for id in &exiting {
            if let Some(n) = s.neighbors.get_mut(id) {
                n.grace_deadline = None;
                n.last_heard = now;
            }
        }
    });
}

/// Ends every grace period whose deadline has passed; the neighbor is then
/// subject to the ordinary inactivity timer again, restarted from now.
fn expire_grace(cfg: &LinkConfig, status: &StatusHandle) {
    let now = Instant::now();
    let expired: Vec<Ipv4Addr> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, n)| n.grace_deadline.is_some_and(|d| d <= now))
        .map(|(id, _)| *id)
        .collect();
    for id in &expired {
        warn!(link = %cfg.attach_point, neighbor = %id, "ospfv3 helper: grace period expired");
    }
    if !expired.is_empty() {
        status.send_modify(|s| {
            for id in &expired {
                if let Some(n) = s.neighbors.get_mut(id) {
                    n.grace_deadline = None;
                    n.last_heard = now;
                }
            }
        });
    }
}

/// The LSU carrying this router's Grace-LSA (`age` `MaxAge` flushes it).
fn grace_payload(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    grace_period: u32,
    restart_reason: u8,
    age: u16,
) -> Vec<u8> {
    let grace = Lsa {
        header: LsaHeader {
            age,
            lsa_type: lsa::LSA_TYPE_GRACE,
            link_state_id: lsa::interface_id_key(cfg.interface_id),
            advertising_router: local_router_id,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Grace(GraceLsaBody {
            grace_period,
            restart_reason,
        }),
    };
    packet::encode_lsu(&LsuPacket {
        discarded: 0,
        last_error: None,
        router_id: local_router_id,
        area_id: cfg.area_id,
        lsas: vec![grace],
    })
}

/// RFC 5187 restarting side: one Grace-LSA to every `Full` neighbor on
/// this link (just before the process exits, or `age` `MaxAge` when restart
/// mode ends).
fn send_grace_lsas(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    grace_period: u32,
    restart_reason: u8,
    age: u16,
) {
    let payload = grace_payload(cfg, local_router_id, grace_period, restart_reason, age);
    let full: Vec<(Ipv4Addr, Ipv6Addr)> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, n)| n.state == NeighborState::Full)
        .map(|(id, n)| (*id, n.address))
        .collect();
    for (neighbor_id, address) in full {
        match socket.send_unicast(address, cfg.interface_id, &payload) {
            Ok(()) if age >= lsa::MAX_AGE => info!(
                link = %cfg.attach_point, neighbor = %neighbor_id,
                "ospfv3 graceful restart: grace-lsa flushed"
            ),
            Ok(()) => info!(
                link = %cfg.attach_point, neighbor = %neighbor_id, grace_period,
                "ospfv3 graceful restart: grace-lsa sent"
            ),
            Err(e) => {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospfv3 grace-lsa");
            }
        }
    }
}

fn run_election(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
) {
    let snapshot = status.borrow().clone();
    let self_candidate = election::Candidate {
        router_id: local_router_id,
        priority: cfg.priority,
        declared_dr: snapshot.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
        declared_bdr: snapshot.bdr.unwrap_or(Ipv4Addr::UNSPECIFIED),
    };
    let neighbor_candidates: Vec<election::Candidate> = snapshot
        .neighbors
        .iter()
        .filter(|(_, info)| {
            matches!(
                info.state,
                NeighborState::TwoWay
                    | NeighborState::ExStart
                    | NeighborState::Exchange
                    | NeighborState::Loading
                    | NeighborState::Full
            )
        })
        .map(|(id, info)| election::Candidate {
            router_id: *id,
            priority: info.priority,
            declared_dr: info.declared_dr,
            declared_bdr: info.declared_bdr,
        })
        .collect();
    let result = election::elect(self_candidate, &neighbor_candidates);

    let new_interface_state = if result.dr == Some(local_router_id) {
        InterfaceState::Dr
    } else if result.bdr == Some(local_router_id) {
        InterfaceState::Backup
    } else {
        InterfaceState::DrOther
    };

    // Re-logs whenever the reported role *or* the dr/bdr router-ids behind
    // it change — not just on an `InterfaceState` variant change. Mirrors
    // `ospf::link::rx::run_election`'s identical fix; see its own doc comment
    // for the full rationale (a router can stay `DrOther`/`Backup` across
    // more than one election pass while a neighbor's declared role is
    // still converging, which would otherwise freeze the log on a stale,
    // not-yet-converged dr/bdr pair).
    if (snapshot.interface_state, snapshot.dr, snapshot.bdr)
        != (new_interface_state, result.dr, result.bdr)
    {
        match new_interface_state {
            InterfaceState::Dr => {
                info!(link = %cfg.attach_point, dr = %local_router_id, "ospfv3 interface became dr");
            }
            InterfaceState::Backup => {
                info!(
                    link = %cfg.attach_point,
                    dr = %result.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    bdr = %local_router_id,
                    "ospfv3 interface became backup"
                );
            }
            InterfaceState::DrOther => {
                info!(
                    link = %cfg.attach_point,
                    dr = %result.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    bdr = %result.bdr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    "ospfv3 interface became dr-other"
                );
            }
            InterfaceState::Waiting | InterfaceState::PointToPoint => {
                unreachable!("election never produces Waiting/PointToPoint")
            }
        }
    }

    status.send_modify(|s| {
        s.dr = result.dr;
        s.bdr = result.bdr;
        s.interface_state = new_interface_state;
    });

    // RFC 5340 §A.1: only the DR and BDR listen on AllDRouters (FF02::6).
    let want = nos_ospf_common::drouters::wants_all_drouters(
        matches!(
            new_interface_state,
            InterfaceState::Dr | InterfaceState::Backup
        ),
        cfg.network_type == NetworkType::PointToPoint,
    );
    match socket.set_all_drouters(cfg.interface_id, want) {
        Ok(true) => {
            info!(link = %cfg.attach_point, joined = want, "ospfv3 all-drouters membership changed");
        }
        Ok(false) => {}
        // Membership did not change, so the next election pass retries.
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "ospfv3 all-drouters membership update failed");
        }
    }
}

/// What a link task is asked to do with Grace-LSAs and its LSDB.
#[derive(Debug, Clone, Copy)]
pub enum GraceCmd {
    /// Announce this grace period (seconds) to the `Full` neighbors.
    Announce(u32),
    /// Resend the LSDB to the `Full` neighbors now.
    Resend,
    /// Flush the Grace-LSA (restart mode ended, RFC 5187 §2.3).
    Flush,
}

struct LinkEntry {
    config: LinkConfig,
    task: JoinHandle<()>,
    status: watch::Receiver<LinkStatus>,
    /// Asks the link task to send or flush Grace-LSAs, or to resend its LSDB.
    grace_tx: mpsc::UnboundedSender<GraceCmd>,
    /// BFD found the path to this neighbor link-local address down.
    bfd_tx: mpsc::UnboundedSender<Ipv6Addr>,
    /// Routers whose topology LSAs changed in this link's scope (RFC 3623
    /// §3.2 item 3).
    topology_tx: mpsc::UnboundedSender<Vec<Ipv4Addr>>,
}

/// Owns every `OSPFv3` link's driver task for one `nos-ospfv3d` process, plus
/// its per-area LSDBs — mirrors `ospf::link::LinkManager` — and, unlike v2,
/// a store per *link* for RFC 5340 §4.5.1's link-local-scoped LSAs and one
/// AS-wide store for its AS-scoped ones.
pub struct LinkManager {
    links: Mutex<HashMap<String, LinkEntry>>,
    /// The attach-point links of the last `reconcile`; `apply_links` adds
    /// the resolved virtual links to them.
    physical: Mutex<Vec<LinkConfig>>,
    /// Configured virtual links (`set_virtual_links`, every resync).
    virtual_links: Mutex<Vec<VirtualLinkConfig>>,
    /// The virtual links §4.7 last found up (`resolve_virtual_links`).
    resolved_virtual: Mutex<Vec<LinkConfig>>,
    /// Area-scoped LSAs (Router/Network/Intra-Area-Prefix and their RFC
    /// 8362 counterparts), per area id, shared by every link in that area.
    lsdbs: Mutex<HashMap<Ipv4Addr, Arc<Mutex<Lsdb>>>>,
    /// Woken by every LSDB change; see `route_changed`.
    route_changed: Arc<tokio::sync::Notify>,
    /// Woken when a neighbor floods one of our own LSAs back newer
    /// (`Lsdb::mark_reflected`), so origination runs at once.
    reoriginate: Arc<tokio::sync::Notify>,
    /// Link-local-scoped LSAs (Link-LSA/E-Link-LSA), per attach point —
    /// exclusively that link's own, so a link's DBD summary/flood can never
    /// offer another link's Link-LSAs (RFC 5340 §4.5.1). SPF still merges
    /// every same-area link's store back in (`compute_routes`).
    link_local_lsdbs: Mutex<HashMap<String, Arc<Mutex<Lsdb>>>>,
    /// AS-scoped LSAs (AS-External-LSA/E-AS-External-LSA, `lsa::is_as_scope`)
    /// — one store for the whole router, read by every link whatever its
    /// area, so an ASBR's LSA learned in one area floods on into the others
    /// with no ABR code (v2 copies each Type-5 into every area instead).
    as_lsdb: Arc<Mutex<Lsdb>>,
    /// Raw (pre-policy) redistributed IPv6 prefixes from
    /// `Ospfv3Request::RedistributeRoutes`, and what passes
    /// `redistribute_policy` (re-derived on every update and resync). A
    /// non-empty filtered set makes this router an ASBR.
    redistribute_raw: Mutex<HashSet<Ipv6Net>>,
    redistribute_filtered: Mutex<HashSet<Ipv6Net>>,
    redistribute_policy: Mutex<Arc<CompiledPolicy>>,
    /// Link State IDs of prefix-keyed LSAs (Inter-Area-Prefix,
    /// AS-External), which are opaque in v3 (RFC 5340 §4.4.3.3/§4.4.3.5):
    /// one per `(legacy LS type, prefix)`, handed out from a monotonic
    /// counter (never reused) and pruned by `originate_all` once the prefix
    /// is no longer originated. A restart or re-advertise may hand out
    /// another ID; the stateless `withdraw_undesired` flushes the old one.
    lsids: Mutex<Lsids>,
    router_id: Mutex<Option<Ipv4Addr>>,
    /// `max-lsa`, shared with every store (`set_max_lsa`).
    max_lsa: Arc<AtomicU32>,
    /// Loopback (`Interface.ospfv3_profiles`) attach points' own prefixes,
    /// per area — no live `LinkConfig`/socket for these (see
    /// `reconcile.rs`'s "log-only" loopback handling), so threaded in
    /// directly, purely so `originate_intra_area_prefix_lsas` can advertise
    /// each one as part of this router's own router-referenced prefix set.
    loopback_prefixes: Mutex<HashMap<Ipv4Addr, Vec<(Ipv6Net, u16)>>>,
    age_multiplier: u16,
    /// `Some` only from `--dbd-max-headers` (test/debug); `None` derives it per link from its MTU.
    dbd_max_headers: Option<usize>,
    /// RFC 8362 Full mode: originate the extended (TLV) LSA set instead of
    /// the legacy one. ponytail: no Sparse mode. The other flavor's own LSAs
    /// (from before a toggle, or a previous incarnation) are prematurely aged
    /// on every origination tick (`withdraw_undesired`).
    extended_lsa: AtomicBool,
    /// RFC 5838 IPv4-unicast instance (`set_ipv4_af`): prefixes are in `lsa`'s shadow form.
    ipv4_af: AtomicBool,
    /// Test-only (`--originate-lsinfinity`): originate every Inter-Area-Prefix,
    /// Inter-Area-Router and AS-External LSA at `LSInfinity`, so the e2e can
    /// prove a receiver never installs one.
    originate_lsinfinity: AtomicBool,
    /// The one-time no-backbone `warn!` was logged and the state still holds.
    no_backbone_warned: AtomicBool,
    /// Each area's RFC 5340 §4.4.3.3 ranges `(cidr, advertise)`, replaced on
    /// every resync (`set_area_ranges`).
    area_ranges: std::sync::Mutex<HashMap<Ipv4Addr, Vec<(Ipv6Net, bool)>>>,
    /// Each stub area's `(import_summaries, default metric)` (`set_stub_areas`);
    /// an area missing here is a normal one.
    stub_areas: std::sync::Mutex<HashMap<Ipv4Addr, (bool, u32)>>,
    /// Each NSSA's settings (`set_nssa_areas`); an NSSA is in `stub_areas` too.
    nssa_areas: std::sync::Mutex<HashMap<Ipv4Addr, NssaSettings>>,
    /// The NSSAs this router translates Type-7s of (RFC 3101 §3.1, elected at
    /// the start of every origination tick) and what it translates, by prefix.
    nssa_translating: std::sync::Mutex<HashSet<Ipv4Addr>>,
    nssa_translated: std::sync::Mutex<HashMap<Ipv6Net, AsExternalLsaBody>>,
    /// Active advertised ranges and their metric, rewritten by every
    /// origination tick; `compute_routes` turns them into discard routes.
    active_ranges: std::sync::Mutex<HashMap<Ipv6Net, u32>>,
    /// Test-only (`--router-lsa-max-links`): cap links per Router-LSA fragment
    /// so the e2e splits a small router; `0` = unset.
    router_lsa_max_links: AtomicUsize,
    /// RFC 5187 grace period (seconds) to announce on a planned restart;
    /// `0` = graceful restart off.
    grace_period: AtomicU16,
    /// RFC 5187 restarting-router mode (`begin_restart`), mirrored in
    /// `restart_on` for the lock-free reads of the origination pass and the
    /// route push.
    restart: std::sync::Mutex<Option<restart::RestartState>>,
    restart_on: AtomicBool,
    /// Each attach point's `bfd` profile (`set_bfd`, every resync); a link
    /// missing here has no BFD.
    bfd: std::sync::Mutex<HashMap<String, BfdProfile>>,
    /// RFC 6987 stub router (`Ospfv3Instance.max_metric_*`), see
    /// `max_metric_active`.
    max_metric: std::sync::Mutex<MaxMetric>,
    /// SPF runs counted by `note_spf`, and the last one's start and duration.
    spf_runs: AtomicU64,
    last_spf: std::sync::Mutex<Option<(Instant, Duration)>>,
    opener: Opener,
    /// RFC 7166 §4.1 boot count, taken per authenticated link (re)start.
    boots: nos_ospf_common::boot::BootCounter,
}

/// RFC 6987 `MaxLinkMetric`.
const MAX_LINK_METRIC: u16 = 0xFFFF;

/// The longest RFC 6987 on-shutdown hold `Ospfv3Instance.max_metric_on_shutdown`
/// accepts (its garde range is 1-3); v3 flushes nothing on a clean stop, so
/// this is the whole shutdown delay.
const MAX_METRIC_SHUTDOWN_HOLD_MAX: std::time::Duration = std::time::Duration::from_secs(3);
const _: () = assert!(
    MAX_METRIC_SHUTDOWN_HOLD_MAX.as_secs() + 6 <= 9,
    "on-shutdown hold must fit nos-watchdogd's 10s kill budget, like nos-ospfd's"
);

/// RFC 6987 stub-router state. `std` mutex: never held across an await.
// Independent flags, each read on its own.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
struct MaxMetric {
    administrative: bool,
    /// On-shutdown hold, seconds (0 = off).
    on_shutdown: u8,
    /// End of the on-startup period, armed once by the first `set_max_metric`.
    until: Option<tokio::time::Instant>,
    /// The first `set_max_metric` call has happened.
    armed: bool,
    /// Respawned after a graceful restart (`boot::take_grace_marker`): the
    /// helpers kept the old topology, so on-startup is skipped.
    after_graceful_restart: bool,
    /// The on-shutdown hold is running (set by `max_metric_on_shutdown`).
    shutting_down: bool,
    /// The last state logged by `max_metric_tick`.
    logged: bool,
}

/// One NSSA's RFC 3101 settings, resolved from `Ospfv3Area`.
// Independent flags, each read on its own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NssaSettings {
    /// `NSSATranslatorRole` `Always`.
    pub translate_always: bool,
    /// RFC 3101 §2.7: as an ABR, originate a default NSSA-LSA into the area.
    pub default_originate: bool,
}

/// Every LS type this router originates in either RFC 8362 mode — the only
/// ones `withdraw_undesired` ever flushes (never a Grace-LSA).
const OWNED_TYPES: [u16; 16] = [
    lsa::LSA_TYPE_ROUTER,
    lsa::LSA_TYPE_NETWORK,
    lsa::LSA_TYPE_LINK,
    lsa::LSA_TYPE_INTRA_AREA_PREFIX,
    lsa::LSA_TYPE_INTER_AREA_PREFIX,
    lsa::LSA_TYPE_INTER_AREA_ROUTER,
    lsa::LSA_TYPE_AS_EXTERNAL,
    lsa::LSA_TYPE_E_ROUTER,
    lsa::LSA_TYPE_E_NETWORK,
    lsa::LSA_TYPE_E_LINK,
    lsa::LSA_TYPE_E_INTRA_AREA_PREFIX,
    lsa::LSA_TYPE_E_INTER_AREA_PREFIX,
    lsa::LSA_TYPE_E_INTER_AREA_ROUTER,
    lsa::LSA_TYPE_E_AS_EXTERNAL,
    lsa::LSA_TYPE_NSSA,
    lsa::LSA_TYPE_E_NSSA,
];

/// See `LinkManager::lsids`: `(ID, asked for since the last prune)` per key.
#[derive(Default)]
struct Lsids {
    map: HashMap<(u16, Ipv6Net), (Ipv4Addr, bool)>,
    next: u32,
}

/// The keys one origination tick originated, per store.
#[derive(Default)]
struct Originated {
    areas: HashMap<Ipv4Addr, HashSet<LsaKey>>,
    links: HashMap<String, HashSet<LsaKey>>,
    as_scope: HashSet<LsaKey>,
}

/// The LS types this router originates, per RFC 8362 mode.
struct LsaTypes {
    router: u16,
    network: u16,
    link: u16,
    intra_area_prefix: u16,
    inter_area_prefix: u16,
    inter_area_router: u16,
    as_external: u16,
    nssa: u16,
}

impl LsaTypes {
    fn new(extended: bool) -> Self {
        if extended {
            Self {
                router: lsa::LSA_TYPE_E_ROUTER,
                network: lsa::LSA_TYPE_E_NETWORK,
                link: lsa::LSA_TYPE_E_LINK,
                intra_area_prefix: lsa::LSA_TYPE_E_INTRA_AREA_PREFIX,
                inter_area_prefix: lsa::LSA_TYPE_E_INTER_AREA_PREFIX,
                inter_area_router: lsa::LSA_TYPE_E_INTER_AREA_ROUTER,
                as_external: lsa::LSA_TYPE_E_AS_EXTERNAL,
                nssa: lsa::LSA_TYPE_E_NSSA,
            }
        } else {
            Self {
                router: lsa::LSA_TYPE_ROUTER,
                network: lsa::LSA_TYPE_NETWORK,
                link: lsa::LSA_TYPE_LINK,
                intra_area_prefix: lsa::LSA_TYPE_INTRA_AREA_PREFIX,
                inter_area_prefix: lsa::LSA_TYPE_INTER_AREA_PREFIX,
                inter_area_router: lsa::LSA_TYPE_INTER_AREA_ROUTER,
                as_external: lsa::LSA_TYPE_AS_EXTERNAL,
                nssa: lsa::LSA_TYPE_NSSA,
            }
        }
    }
}

impl LinkManager {
    /// Switches between legacy and RFC 8362 extended LSA origination; takes
    /// effect at the next origination tick.
    pub fn set_ipv4_af(&self, ipv4: bool) {
        self.ipv4_af.store(ipv4, Ordering::Relaxed);
    }

    /// Whether this instance runs the IPv4 unicast address family.
    pub fn ipv4_af(&self) -> bool {
        self.ipv4_af.load(Ordering::Relaxed)
    }

    pub fn set_extended_lsa(&self, extended: bool) {
        self.extended_lsa.store(extended, Ordering::Relaxed);
    }

    /// The `bfd` profile of each attach point that has one, replaced on every
    /// resync. Registrations follow; a link never restarts for it.
    pub fn set_bfd(&self, wanted: HashMap<String, BfdProfile>) {
        *self.bfd.lock().unwrap() = wanted;
    }

    /// Every stub area's `(import_summaries, default metric)`, replaced on
    /// every resync; applied at the next origination tick.
    pub fn set_stub_areas(&self, stub: HashMap<Ipv4Addr, (bool, u32)>) {
        *self.stub_areas.lock().unwrap() = stub;
    }

    /// Every NSSA's settings, replaced on every resync (each is also in
    /// `set_stub_areas`).
    pub fn set_nssa_areas(&self, nssa: HashMap<Ipv4Addr, NssaSettings>) {
        *self.nssa_areas.lock().unwrap() = nssa;
    }

    #[cfg(test)]
    pub fn nssa_areas_for_test(&self) -> HashMap<Ipv4Addr, NssaSettings> {
        self.nssa_areas.lock().unwrap().clone()
    }

    #[cfg(test)]
    pub fn stub_areas_for_test(&self) -> HashMap<Ipv4Addr, (bool, u32)> {
        self.stub_areas.lock().unwrap().clone()
    }

    /// Every area's address ranges `(cidr, advertise)`, replaced on every
    /// resync; applied at the next origination tick.
    pub fn set_area_ranges(&self, ranges: HashMap<Ipv4Addr, Vec<(Ipv6Net, bool)>>) {
        *self.area_ranges.lock().unwrap() = ranges;
    }

    pub fn set_graceful_restart(&self, grace_period: Option<u16>) {
        self.grace_period
            .store(grace_period.unwrap_or(0), Ordering::Relaxed);
    }

    fn max_metric_state(&self) -> std::sync::MutexGuard<'_, MaxMetric> {
        self.max_metric
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Set once, before the first `set_max_metric`, when this process is the
    /// respawn of a graceful restart (`boot::take_grace_marker`).
    pub fn set_after_graceful_restart(&self, after: bool) {
        self.max_metric_state().after_graceful_restart = after;
    }

    /// RFC 6987 knobs, every resync. The first call (the first config
    /// resolution after start) arms the on-startup period, skipped after a
    /// graceful restart (RFC 6987 §3.2 (c)); later calls never re-arm it (it
    /// takes effect on the next start), and `None` ends a running one.
    pub fn set_max_metric(
        &self,
        on_startup: Option<u32>,
        on_shutdown: Option<u8>,
        administrative: bool,
    ) {
        let mut mm = self.max_metric_state();
        mm.administrative = administrative;
        mm.on_shutdown = on_shutdown.unwrap_or(0);
        if !mm.armed {
            mm.armed = true;
            match on_startup {
                Some(_) if mm.after_graceful_restart => {
                    info!("ospfv3 stub router on-startup skipped after graceful restart");
                }
                Some(secs) => {
                    mm.until =
                        Some(Instant::now() + std::time::Duration::from_secs(u64::from(secs)));
                }
                None => {}
            }
        } else if on_startup.is_none() {
            mm.until = None;
        }
    }

    /// RFC 6987: whether this router advertises itself as a stub router
    /// (max-metric links) — administratively, inside its on-startup period
    /// or during its on-shutdown hold. Logs a change (read once per
    /// origination tick).
    fn max_metric_tick(&self) -> bool {
        let mut mm = self.max_metric_state();
        let starting = mm.until.is_some_and(|t| Instant::now() < t);
        let active = mm.administrative || starting || mm.shutting_down;
        if active != mm.logged {
            mm.logged = active;
            let reason = if active && mm.administrative {
                "administrative"
            } else if active && mm.shutting_down {
                "on-shutdown"
            } else if active {
                "on-startup"
            } else if mm.until.take().is_some() {
                "expired"
            } else {
                "cleared"
            };
            info!(active, reason, "ospfv3 stub router max-metric changed");
        }
        active
    }

    /// RFC 6987 on-shutdown: re-originates the Router-LSAs with max-metric
    /// links, kicks them out and holds `on_shutdown` seconds so neighbors
    /// move traffic away before this process exits. Skipped when off, when
    /// max-metric is already active, and when no LSA actually changed.
    pub async fn max_metric_on_shutdown(&self) {
        let hold = {
            let mm = self.max_metric_state();
            let active = mm.administrative || mm.until.is_some_and(|t| Instant::now() < t);
            if active {
                0
            } else {
                mm.on_shutdown
            }
        };
        if hold == 0 {
            return;
        }
        self.max_metric_state().shutting_down = true;
        self.origination_pass().await;
        self.flood_now().await;
        tokio::time::sleep(
            std::time::Duration::from_secs(u64::from(hold)).min(MAX_METRIC_SHUTDOWN_HOLD_MAX),
        )
        .await;
    }

    /// Has every link resend its LSDB to its `Full` neighbors now.
    async fn flood_now(&self) {
        let senders: Vec<mpsc::UnboundedSender<GraceCmd>> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.grace_tx.clone())
            .collect();
        for tx in senders {
            let _ = tx.send(GraceCmd::Resend);
        }
    }

    /// What the last resync handed to the setters (`reconcile` tests).
    #[cfg(test)]
    pub(crate) fn extended_lsa(&self) -> bool {
        self.extended_lsa.load(Ordering::Relaxed)
    }

    /// The configured RFC 5187 grace period, seconds (0 = off).
    pub fn grace_period(&self) -> u16 {
        self.grace_period.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn bfd_wanted(&self) -> HashMap<String, BfdProfile> {
        self.bfd.lock().unwrap().clone()
    }

    #[cfg(test)]
    pub(crate) async fn redistribute_policy(&self) -> Arc<CompiledPolicy> {
        Arc::clone(&*self.redistribute_policy.lock().await)
    }

    /// The loopback prefixes of the last `reconcile`, per area.
    #[cfg(test)]
    pub(crate) async fn loopback_prefixes(&self) -> HashMap<Ipv4Addr, Vec<(Ipv6Net, u16)>> {
        self.loopback_prefixes.lock().await.clone()
    }

    fn lsa_types(&self) -> LsaTypes {
        LsaTypes::new(self.extended_lsa.load(Ordering::Relaxed))
    }

    /// Test-only: see the `originate_lsinfinity` field.
    pub fn set_originate_lsinfinity(&self, on: bool) {
        self.originate_lsinfinity.store(on, Ordering::Relaxed);
    }

    /// Test-only: see the `router_lsa_max_links` field.
    pub fn set_router_lsa_max_links(&self, max: Option<usize>) {
        self.router_lsa_max_links
            .store(max.unwrap_or(0), Ordering::Relaxed);
    }

    pub fn new(
        age_multiplier: u16,
        dbd_max_headers: Option<usize>,
        boots: nos_ospf_common::boot::BootCounter,
    ) -> Arc<Self> {
        Self::build(
            age_multiplier,
            dbd_max_headers,
            boots,
            Arc::new(|cfg: &LinkConfig, boot_count: u32| {
                let auth = cfg.auth.clone().map(|a| (a, cfg.link_local_address));
                if let Some(v) = cfg.virtual_link {
                    return OspfSocket::open_virtual(
                        &cfg.kernel_interface,
                        cfg.link_local_address,
                        v.neighbor,
                        auth,
                        cfg.instance_id,
                        boot_count,
                    )
                    .map(LinkSocket::Os);
                }
                OspfSocket::open(
                    &cfg.kernel_interface,
                    cfg.interface_id,
                    auth,
                    cfg.instance_id,
                    boot_count,
                )
                .map(LinkSocket::Os)
            }),
        )
    }

    /// `new` with the link sockets opened by `opener` — the in-memory wire in
    /// tests.
    pub fn with_opener(
        age_multiplier: u16,
        dbd_max_headers: Option<usize>,
        opener: Opener,
    ) -> Arc<Self> {
        Self::build(
            age_multiplier,
            dbd_max_headers,
            nos_ospf_common::boot::BootCounter::in_memory(),
            opener,
        )
    }

    fn build(
        age_multiplier: u16,
        dbd_max_headers: Option<usize>,
        boots: nos_ospf_common::boot::BootCounter,
        opener: Opener,
    ) -> Arc<Self> {
        let route_changed = Arc::new(tokio::sync::Notify::new());
        let reoriginate = Arc::new(tokio::sync::Notify::new());
        let manager = Arc::new(Self {
            links: Mutex::new(HashMap::new()),
            physical: Mutex::new(Vec::new()),
            virtual_links: Mutex::new(Vec::new()),
            resolved_virtual: Mutex::new(Vec::new()),
            lsdbs: Mutex::new(HashMap::new()),
            link_local_lsdbs: Mutex::new(HashMap::new()),
            as_lsdb: Arc::new(Mutex::new(
                Lsdb::with_notify(Arc::clone(&route_changed))
                    .with_reflect_notify(Arc::clone(&reoriginate)),
            )),
            route_changed,
            reoriginate,
            redistribute_raw: Mutex::new(HashSet::new()),
            redistribute_filtered: Mutex::new(HashSet::new()),
            redistribute_policy: Mutex::new(Arc::new(nos_rpl::ACCEPT_ALL.clone())),
            lsids: Mutex::new(Lsids::default()),
            router_id: Mutex::new(None),
            max_lsa: Arc::new(AtomicU32::new(nos_ospf_common::lsdb::DEFAULT_MAX_LSA)),
            loopback_prefixes: Mutex::new(HashMap::new()),
            age_multiplier,
            dbd_max_headers,
            extended_lsa: AtomicBool::new(false),
            ipv4_af: AtomicBool::new(false),
            originate_lsinfinity: AtomicBool::new(false),
            no_backbone_warned: AtomicBool::new(false),
            area_ranges: std::sync::Mutex::new(HashMap::new()),
            stub_areas: std::sync::Mutex::new(HashMap::new()),
            nssa_areas: std::sync::Mutex::new(HashMap::new()),
            nssa_translating: std::sync::Mutex::new(HashSet::new()),
            nssa_translated: std::sync::Mutex::new(HashMap::new()),
            active_ranges: std::sync::Mutex::new(HashMap::new()),
            max_metric: std::sync::Mutex::new(MaxMetric::default()),
            router_lsa_max_links: AtomicUsize::new(0),
            grace_period: AtomicU16::new(0),
            restart: std::sync::Mutex::new(None),
            restart_on: AtomicBool::new(false),
            bfd: std::sync::Mutex::new(HashMap::new()),
            spf_runs: AtomicU64::new(0),
            last_spf: std::sync::Mutex::new(None),
            opener,
            boots,
        });
        let background = Arc::clone(&manager);
        tokio::spawn(async move {
            let mut origination_tick = tokio::time::interval(ORIGINATION_INTERVAL);
            origination_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut age_tick = tokio::time::interval(AGE_TICK_INTERVAL);
            age_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = origination_tick.tick() => background.origination_pass().await,
                    // RFC 2328 §13.4: a neighbor flooded our own LSA back newer.
                    () = background.reoriginate.notified() => background.origination_pass().await,
                    _ = age_tick.tick() => {
                        background.age_lsdbs().await;
                    }
                }
            }
        });
        manager
    }

    async fn lsdb_for(&self, area_id: Ipv4Addr) -> Arc<Mutex<Lsdb>> {
        let mut stores = self.lsdbs.lock().await;
        if let Some(l) = stores.get(&area_id) {
            return Arc::clone(l);
        }
        let db = self.new_store().await;
        Arc::clone(
            stores
                .entry(area_id)
                .or_insert_with(|| Arc::new(Mutex::new(db))),
        )
    }

    /// An empty store wired to this manager's notifiers and, once the router
    /// ID is known, the `max-lsa` limit (#1146).
    async fn new_store(&self) -> Lsdb {
        let mut db = Lsdb::with_notify(Arc::clone(&self.route_changed))
            .with_reflect_notify(Arc::clone(&self.reoriginate));
        if let Some(id) = *self.router_id.lock().await {
            db.set_limit(id, Arc::clone(&self.max_lsa));
        }
        db
    }

    /// `max-lsa` (#1146), every resync; read per receive, so a link never
    /// restarts for it.
    pub fn set_max_lsa(&self, max_lsa: Option<u32>) {
        self.max_lsa.store(
            max_lsa.unwrap_or(nos_ospf_common::lsdb::DEFAULT_MAX_LSA),
            Ordering::Relaxed,
        );
    }

    async fn link_local_lsdb_for(&self, attach_point: &str) -> Arc<Mutex<Lsdb>> {
        let mut stores = self.link_local_lsdbs.lock().await;
        if let Some(l) = stores.get(attach_point) {
            return Arc::clone(l);
        }
        let db = self.new_store().await;
        Arc::clone(
            stores
                .entry(attach_point.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(db))),
        )
    }

    /// Every link-local store in `area_id`, tagged by attach point.
    async fn link_local_lsdbs_in(&self, area_id: Ipv4Addr) -> Vec<(String, Arc<Mutex<Lsdb>>)> {
        let attach_points: Vec<String> = self
            .links
            .lock()
            .await
            .values()
            .filter(|e| e.config.area_id == area_id)
            .map(|e| e.config.attach_point.clone())
            .collect();
        let stores = self.link_local_lsdbs.lock().await;
        attach_points
            .into_iter()
            .filter_map(|ap| stores.get(&ap).map(|s| (ap, Arc::clone(s))))
            .collect()
    }

    /// Ages every store — per-area and per-link alike (RFC 2328 §14 aging
    /// is scope-agnostic).
    async fn age_lsdbs(&self) {
        // RFC 3623 §3.2 item 3: tell the links which routers' topology LSAs
        // changed (before aging; aging never changes content). Area-scope
        // changes reach that area's links, AS-scope ones every link.
        let as_origins = self.as_lsdb.lock().await.take_topology_changes();
        let area_stores: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        let mut by_area = HashMap::new();
        let mut superseded = self.as_lsdb.lock().await.take_superseded_changes();
        for (area_id, lsdb) in area_stores {
            let mut db = lsdb.lock().await;
            superseded.extend(db.take_superseded_changes());
            by_area.insert(area_id, db.take_topology_changes());
        }
        for e in self.links.lock().await.values() {
            let mut origins = by_area.get(&e.config.area_id).cloned().unwrap_or_default();
            origins.extend(as_origins.iter().copied());
            if !origins.is_empty() {
                let _ = e.topology_tx.send(origins);
            }
        }
        let own = *self.router_id.lock().await;
        self.restart_tick(superseded.iter().any(|o| Some(*o) != own))
            .await;
        let hold: HashSet<Ipv4Addr> = self
            .links
            .lock()
            .await
            .values()
            .flat_map(|e| {
                e.status
                    .borrow()
                    .neighbors
                    .iter()
                    .filter(|(_, n)| n.grace_deadline.is_some())
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>()
            })
            .collect();
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        for (area_id, lsdb) in areas {
            let evicted = lsdb.lock().await.age_and_evict(self.age_multiplier, &hold);
            for key in evicted {
                info!(
                    area = %area_id, lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
                    advertising_router = %key.advertising_router,
                    "ospfv3 lsa maxage flushed"
                );
            }
        }
        let links: Vec<(String, Arc<Mutex<Lsdb>>)> = self
            .link_local_lsdbs
            .lock()
            .await
            .iter()
            .map(|(attach_point, lsdb)| (attach_point.clone(), Arc::clone(lsdb)))
            .collect();
        for (attach_point, lsdb) in links {
            let evicted = lsdb.lock().await.age_and_evict(self.age_multiplier, &hold);
            for key in evicted {
                info!(
                    link = %attach_point, lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
                    advertising_router = %key.advertising_router,
                    "ospfv3 lsa maxage flushed"
                );
            }
        }
        let evicted = self
            .as_lsdb
            .lock()
            .await
            .age_and_evict(self.age_multiplier, &hold);
        for key in evicted {
            info!(
                scope = "as", lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
                advertising_router = %key.advertising_router,
                "ospfv3 lsa maxage flushed"
            );
        }
    }

    /// RFC 5340 §3.1 / RFC 2328 §3.1: an ABR is attached to 2+ areas, one of
    /// them the backbone (a configured virtual link counts, #1159). B-bit and every summary
    /// follow this (#610).
    async fn is_backbone_abr(&self) -> bool {
        let areas = self.attached_areas().await;
        areas.len() >= 2 && areas.contains(&Ipv4Addr::UNSPECIFIED)
    }

    /// The areas this router has a live link or loopback in.
    async fn attached_areas(&self) -> HashSet<Ipv4Addr> {
        let mut areas: HashSet<Ipv4Addr> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.config.area_id)
            .collect();
        areas.extend(self.loopback_prefixes.lock().await.keys().copied());
        // RFC 5340 §4.7: a configured virtual link attaches us to the backbone.
        if !self.virtual_links.lock().await.is_empty() {
            areas.insert(Ipv4Addr::UNSPECIFIED);
        }
        areas
    }

    /// RFC 5340 §4.7: the transit-area first hops toward each configured
    /// virtual link's endpoint (`spf::Context::virtual_links`).
    async fn virtual_next_hops(&self, router_id: Ipv4Addr) -> Vec<spf::VirtualNextHops> {
        let configured = self.virtual_links.lock().await.clone();
        let mut out = Vec::new();
        for v in configured {
            let Some(lsdb) = self.lsdbs.lock().await.get(&v.transit_area).cloned() else {
                continue;
            };
            let mut lsas = lsdb.lock().await.all();
            for (_, link_lsdb) in self.link_local_lsdbs_in(v.transit_area).await {
                lsas.extend(link_lsdb.lock().await.all());
            }
            out.extend(spf::virtual_next_hops(router_id, &lsas, v.endpoint));
        }
        out
    }

    /// The Link State ID for a prefix-keyed LSA — see `lsids`.
    async fn lsid(&self, lsa_type: u16, prefix: Ipv6Net) -> Ipv4Addr {
        let mut lsids = self.lsids.lock().await;
        let Lsids { map, next } = &mut *lsids;
        let (id, used) = map.entry((lsa_type, prefix)).or_insert_with(|| {
            // ponytail: u32 wrap after 2^32 allocations is ignored.
            *next = next.wrapping_add(1);
            (lsa::interface_id_key(*next), false)
        });
        *used = true;
        *id
    }

    /// Drops the IDs of prefixes `lsid` was not asked for since the last
    /// prune (not originated this tick); the counter never goes back, so a
    /// live entry's ID is never handed out again.
    async fn prune_lsids(&self) {
        let mut lsids = self.lsids.lock().await;
        lsids.map.retain(|_, (_, used)| std::mem::take(used));
    }

    /// Recomputes and (re)installs this router's own Router-LSA per area —
    /// pure topology only, no addresses (see the module doc comment).
    async fn originate_router_lsas(&self, local_router_id: Ipv4Addr, done: &mut Originated) {
        let snapshot: Vec<(LinkConfig, LinkStatus)> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| (e.config.clone(), e.status.borrow().clone()))
            .collect();

        let mut by_area: HashMap<Ipv4Addr, Vec<(LinkConfig, LinkStatus)>> = HashMap::new();
        for (cfg, status) in snapshot {
            by_area.entry(cfg.area_id).or_default().push((cfg, status));
        }
        let loopback_areas: HashSet<Ipv4Addr> = self
            .loopback_prefixes
            .lock()
            .await
            .keys()
            .copied()
            .collect();
        let area_ids: HashSet<Ipv4Addr> = by_area.keys().copied().chain(loopback_areas).collect();

        // RFC 5340 §A.4.3: B while attached to 2+ areas (not `lsdbs.len()`,
        // which never shrinks), E while originating AS-External-LSAs — the
        // same set `originate_as_external_lsas` reads, so the bit and the
        // LSAs come and go in the same tick.
        let mut flags = 0;
        if self.is_backbone_abr().await {
            flags |= lsa::ROUTER_FLAG_B;
        }
        let asbr = !self.redistribute_filtered.lock().await.is_empty();
        let stub_areas = self.stub_areas.lock().unwrap().clone();
        let nssa_areas = self.nssa_areas.lock().unwrap().clone();
        let translating = !self.nssa_translating.lock().unwrap().is_empty();
        let types = self.lsa_types();
        let max_metric = self.max_metric_tick();
        // RFC 5340 §A.4.3: V in each transit area of a fully adjacent virtual
        // link.
        let virtual_transit: HashSet<Ipv4Addr> = by_area
            .values()
            .flatten()
            .filter_map(|(cfg, status)| {
                let v = cfg.virtual_link?;
                status
                    .neighbors
                    .values()
                    .any(|n| n.state == NeighborState::Full)
                    .then_some(v.transit_area)
            })
            .collect();
        debug_assert!(!lsa::is_link_local_scope(types.router));
        debug_assert!(!lsa::is_link_local_scope(types.network));
        for area_id in area_ids {
            let stub = stub_areas.contains_key(&area_id);
            let nssa_cfg = nssa_areas.get(&area_id);
            let nssa = nssa_cfg.is_some();
            // No AS-External-LSA reaches a stub area, so no ASBR there; an
            // NSSA's ASBR (NSSA-LSAs) is one, and its translator (RFC 3101
            // §3.1) is one in the normal areas. Nt: an ABR that always
            // translates (RFC 3101 A.2).
            let mut flags = match (stub, nssa) {
                (false, _) if asbr || translating => flags | lsa::ROUTER_FLAG_E,
                (true, true) if asbr => flags | lsa::ROUTER_FLAG_E,
                _ => flags,
            };
            if nssa_cfg.is_some_and(|c| c.translate_always) && flags & lsa::ROUTER_FLAG_B != 0 {
                flags |= lsa::ROUTER_FLAG_NT;
            }
            if virtual_transit.contains(&area_id) {
                flags |= lsa::ROUTER_FLAG_V;
            }
            let links = by_area.get(&area_id).cloned().unwrap_or_default();
            // ponytail: one AF per instance, read off the area's first link;
            // a loopback-only area's Router-LSA carries no AF-bit.
            let ipv4_af = links.first().is_some_and(|(c, _)| c.ipv4_af);
            let lsdb = self.lsdb_for(area_id).await;
            let mut lsdb = lsdb.lock().await;
            let done = done.areas.entry(area_id).or_default();

            // Smallest MTU of the area: the LSA floods on every link of it.
            let budget =
                links
                    .iter()
                    .map(|(c, _)| usize::from(c.mtu))
                    .min()
                    .map_or(usize::MAX, |mtu| {
                        let trailer = links.iter().map(|(c, _)| trailer_len(c)).max().unwrap_or(0);
                        lsa_budget(u16::try_from(mtu).unwrap_or(u16::MAX), trailer, 20 + 4)
                    });
            let max_links = match self.router_lsa_max_links.load(Ordering::Relaxed) {
                0 => None,
                m => Some(m),
            };
            let mut all_links = router_lsa_links(local_router_id, &links, max_metric);
            if links
                .iter()
                .any(|(c, _)| c.network_type == NetworkType::Hybrid)
            {
                let dr_view = router_lsa_targets(&lsdb, types.router, local_router_id);
                all_links.extend(hybrid_router_links(&links, &dr_view, max_metric));
            }
            let fragments = split_router_links(&all_links, budget, max_links);
            if fragments.len() > 1 {
                info!(area = %area_id, fragments = fragments.len(), "ospfv3 router-lsa split");
            }
            for (i, router_links) in fragments.into_iter().enumerate() {
                // Fragment 0 keeps the router id; 1, 2, ... follow (RFC 5340
                // §4.4.3.2). `lsids` only allocates prefix/external IDs.
                let id = if i == 0 {
                    local_router_id
                } else {
                    Ipv4Addr::from(u32::try_from(i).unwrap_or(u32::MAX))
                };
                done.insert(install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    types.router,
                    id,
                    LsaBody::Router(RouterLsaBody {
                        flags,
                        options: own_options(stub, nssa, ipv4_af),
                        links: router_links,
                    }),
                ));
            }

            for (cfg, status) in &links {
                if cfg.network_type != NetworkType::Broadcast
                    || status.interface_state != InterfaceState::Dr
                {
                    continue;
                }
                let full_neighbors: Vec<Ipv4Addr> = status
                    .neighbors
                    .iter()
                    .filter(|(_, n)| n.state == NeighborState::Full)
                    .map(|(id, _)| *id)
                    .collect();
                if full_neighbors.is_empty() {
                    continue;
                }
                let attached: Vec<Ipv4Addr> = std::iter::once(local_router_id)
                    .chain(full_neighbors)
                    .collect();
                done.insert(install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    types.network,
                    lsa::interface_id_key(cfg.interface_id),
                    LsaBody::Network(NetworkLsaBody {
                        options: own_options(stub, nssa, cfg.ipv4_af),
                        attached_routers: attached,
                    }),
                ));
            }
        }
    }

    /// One Link-LSA per live link, unconditionally (RFC 5340 §7.3) —
    /// advertises this router's own link-local address and configured
    /// prefix on that link. Link-local scoped, so it goes into that link's
    /// own store, never the area's (`LinkManager.link_local_lsdbs`).
    async fn originate_link_lsas(&self, local_router_id: Ipv4Addr, done: &mut Originated) {
        let snapshot: Vec<LinkConfig> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.config.clone())
            .collect();
        let types = self.lsa_types();
        debug_assert!(lsa::is_link_local_scope(types.link));
        // A virtual link has no Link-LSA: it is no link-local segment.
        for cfg in snapshot.into_iter().filter(|c| c.virtual_link.is_none()) {
            let lsdb = self.link_local_lsdb_for(&cfg.attach_point).await;
            let mut lsdb = lsdb.lock().await;
            let key = install_self_originated(
                &mut lsdb,
                local_router_id,
                types.link,
                lsa::interface_id_key(cfg.interface_id),
                LsaBody::Link(LinkLsaBody {
                    priority: cfg.priority,
                    options: own_options(cfg.stub, cfg.nssa, cfg.ipv4_af),
                    link_local_address: cfg.lsa_address(),
                    prefixes: cfg
                        .prefixes
                        .iter()
                        .map(|&prefix| LinkPrefixEntry { options: 0, prefix })
                        .collect(),
                }),
            );
            done.links.entry(cfg.attach_point).or_default().insert(key);
        }
    }

    /// This router's own Intra-Area-Prefix-LSA (referencing its own
    /// Router-LSA: every point-to-point link's own prefix, plus every
    /// loopback prefix) and, per broadcast link where a Network-LSA was
    /// actually originated, a second Intra-Area-Prefix-LSA referencing that
    /// Network-LSA with the link's own transit prefix.
    async fn originate_intra_area_prefix_lsas(
        &self,
        local_router_id: Ipv4Addr,
        done: &mut Originated,
    ) {
        let snapshot: Vec<(LinkConfig, LinkStatus)> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| (e.config.clone(), e.status.borrow().clone()))
            .collect();
        let mut by_area: HashMap<Ipv4Addr, Vec<(LinkConfig, LinkStatus)>> = HashMap::new();
        for (cfg, status) in snapshot {
            by_area.entry(cfg.area_id).or_default().push((cfg, status));
        }
        let loopback_prefixes = self.loopback_prefixes.lock().await.clone();
        let host_len = if self.ipv4_af() { 32 } else { 128 };
        let area_ids: HashSet<Ipv4Addr> = by_area
            .keys()
            .copied()
            .chain(loopback_prefixes.keys().copied())
            .collect();

        let types = self.lsa_types();
        debug_assert!(!lsa::is_link_local_scope(types.intra_area_prefix));
        for area_id in area_ids {
            let links = by_area.get(&area_id).cloned().unwrap_or_default();
            let lsdb = self.lsdb_for(area_id).await;
            let mut lsdb = lsdb.lock().await;
            let done = done.areas.entry(area_id).or_default();

            let mut router_prefixes: Vec<IntraAreaPrefixEntry> = links
                .iter()
                .filter(|(cfg, status)| {
                    cfg.virtual_link.is_none()
                        && (cfg.network_type != NetworkType::Broadcast
                            || !network_prefix_originated(status))
                })
                .flat_map(|(cfg, _)| {
                    let own = |options, prefix| IntraAreaPrefixEntry {
                        options,
                        metric: cfg.cost,
                        prefix,
                    };
                    if cfg.network_type == NetworkType::Hybrid {
                        // RFC 6845 §4.6.2: the address as a /128 (LA) as on
                        // point-to-multipoint, and the interface's prefix too.
                        let mut v: Vec<_> = cfg
                            .prefixes
                            .iter()
                            .map(|p| own(lsa::PREFIX_OPT_LA, cfg.host_prefix(p)))
                            .collect();
                        v.extend(cfg.prefixes.iter().map(|&p| own(0, p)));
                        v
                    } else if cfg.network_type == NetworkType::PointToMultipoint {
                        // RFC 5340 §4.4.3.9: the router's own address as a
                        // /128 host prefix (LA), not the subnet.
                        cfg.prefixes
                            .iter()
                            .map(|p| own(lsa::PREFIX_OPT_LA, cfg.host_prefix(p)))
                            .collect()
                    } else {
                        cfg.prefixes.iter().map(|&p| own(0, p)).collect::<Vec<_>>()
                    }
                })
                .collect();
            for (prefix, cost) in loopback_prefixes.get(&area_id).into_iter().flatten() {
                router_prefixes.push(IntraAreaPrefixEntry {
                    // RFC 5340 §A.4.1.1: a /128 loopback is a host address.
                    options: if prefix.prefix_len() == host_len {
                        lsa::PREFIX_OPT_LA
                    } else {
                        0
                    },
                    metric: *cost,
                    prefix: *prefix,
                });
            }
            if !router_prefixes.is_empty() {
                done.insert(install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    types.intra_area_prefix,
                    Ipv4Addr::UNSPECIFIED,
                    LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                        referenced_ls_type: types.router,
                        referenced_link_state_id: local_router_id,
                        referenced_advertising_router: local_router_id,
                        prefixes: router_prefixes,
                    }),
                ));
            }

            for (cfg, status) in &links {
                if cfg.network_type != NetworkType::Broadcast || !network_prefix_originated(status)
                {
                    continue;
                }
                let network_key = lsa::interface_id_key(cfg.interface_id);
                let prefixes = self.network_prefixes(cfg, status, local_router_id).await;
                done.insert(install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    types.intra_area_prefix,
                    network_key,
                    LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                        referenced_ls_type: types.network,
                        referenced_link_state_id: network_key,
                        referenced_advertising_router: local_router_id,
                        prefixes,
                    }),
                ));
            }
        }
    }

    /// RFC 5340 §4.4.3.9: the DR's Network-referenced prefixes, the union of
    /// its own and every `Full` neighbor's Link-LSA prefixes (NU/LA skipped),
    /// each truncated network once with the options OR-ed; own first, then
    /// neighbors by router ID.
    async fn network_prefixes(
        &self,
        cfg: &LinkConfig,
        status: &LinkStatus,
        local_router_id: Ipv4Addr,
    ) -> Vec<IntraAreaPrefixEntry> {
        let mut sources: Vec<(Ipv4Addr, Vec<LinkPrefixEntry>)> = vec![(
            local_router_id,
            cfg.prefixes
                .iter()
                .map(|&prefix| LinkPrefixEntry { options: 0, prefix })
                .collect(),
        )];
        let full: std::collections::BTreeSet<Ipv4Addr> = status
            .neighbors
            .iter()
            .filter(|(_, n)| n.state == NeighborState::Full)
            .map(|(id, _)| *id)
            .collect();
        let link_type = self.lsa_types().link;
        let lsdb = self.link_local_lsdb_for(&cfg.attach_point).await;
        let all = lsdb.lock().await.all();
        for id in full {
            for l in &all {
                if l.header.advertising_router == id
                    && l.header.lsa_type == link_type
                    && l.header.age < lsa::MAX_AGE
                    && let LsaBody::Link(body) = &l.body
                {
                    sources.push((id, body.prefixes.clone()));
                }
            }
        }
        merge_network_prefixes(&sources)
    }

    /// RFC 5340 §4.4.3.3/§4.4.3.4 (port of `ospf::link::
    /// originate_summary_lsas`, RFC 2328 §12.4.3): as a backbone-attached
    /// ABR, one Inter-Area-Prefix-LSA per prefix and one Inter-Area-Router-LSA
    /// per ASBR: the backbone's intra- and inter-area routes into every
    /// non-backbone area, a non-backbone area's intra-area routes into the
    /// backbone only, and nothing a destination area already reaches
    /// intra-area. Run after the intra-area passes, so this tick's own
    /// prefixes are summarized. Without the backbone: no summaries, one
    /// `warn!` while that lasts.
    /// Area ranges (§4.4.3.3, `nos_ospf_common::areas::apply_ranges`) fold
    /// a source area's intra-area prefixes into one LSA per range.
    /// `ponytail:` no up/down-bit loop prevention —
    /// `docs/protocols/ospf-internals.md`'s ABR ceilings.
    async fn originate_inter_area_lsas(&self, local_router_id: Ipv4Addr, done: &mut Originated) {
        let attached = self.attached_areas().await;
        let abr = self.is_backbone_abr().await;
        if abr || attached.len() < 2 {
            self.no_backbone_warned.store(false, Ordering::Relaxed);
        } else if !self.no_backbone_warned.swap(true, Ordering::Relaxed) {
            warn!("ospfv3 attached to 2+ areas without the backbone: not an ABR, no summaries");
        }
        if !abr {
            self.active_ranges.lock().unwrap().clear();
            return;
        }
        let ranges = self.area_ranges.lock().unwrap().clone();
        let mut active_ranges = HashMap::new();
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .filter(|(id, _)| attached.contains(id))
            .map(|(id, lsdb)| (*id, Arc::clone(lsdb)))
            .collect();
        // Per source area: what it offers, and its own intra-area view (what
        // a destination area reaches itself is never summarized into it).
        let mut views = Vec::new();
        // Distance only, so no virtual next hops: the far end of a virtual
        // link summarizes the backbone into its other areas.
        let ctx = |area_id: &Ipv4Addr| spf::Context {
            backbone: area_id.is_unspecified(),
            ..spf::Context::default()
        };
        for (area_id, lsdb) in &areas {
            let lsas = lsdb.lock().await.all();
            let area_ranges = ranges.get(area_id).map_or(&[][..], |r| &r[..]);
            let (prefixes, asbrs, own) = if area_id.is_unspecified() {
                let v = spf::backbone_view(local_router_id, &lsas, &ctx(area_id));
                let (mut prefixes, active) =
                    nos_ospf_common::areas::apply_ranges(&v.intra.prefixes, area_ranges);
                active_ranges.extend(active);
                prefixes.extend(v.inter_prefixes);
                let mut asbrs = v.intra.asbrs.clone();
                asbrs.extend(v.inter_asbrs);
                (prefixes, asbrs, v.intra)
            } else {
                let v = spf::intra_area_routes(local_router_id, &lsas, &ctx(area_id));
                let (prefixes, active) =
                    nos_ospf_common::areas::apply_ranges(&v.prefixes, area_ranges);
                active_ranges.extend(active);
                (prefixes, v.asbrs.clone(), v)
            };
            views.push((*area_id, prefixes, asbrs, own));
        }
        *self.active_ranges.lock().unwrap() = active_ranges;
        let types = self.lsa_types();
        let infinity = self.originate_lsinfinity.load(Ordering::Relaxed);
        let stub_areas = self.stub_areas.lock().unwrap().clone();
        let nssa_areas = self.nssa_areas.lock().unwrap().clone();
        for (dest, lsdb) in &areas {
            // RFC 5340 §4.4.3 / RFC 2328 §12.4.3.1: a stub area gets no
            // Inter-Area-Router-LSA, a totally stubby one no other
            // Inter-Area-Prefix-LSA than the default.
            let stub = stub_areas.get(dest).copied();
            // Cheapest over every source area; 24-bit metrics (LSInfinity
            // excluded).
            let mut prefixes: HashMap<Ipv6Net, u32> = HashMap::new();
            let mut asbrs: HashMap<Ipv4Addr, (u32, u32)> = HashMap::new();
            let own = views.iter().find(|v| v.0 == *dest).map(|v| &v.3);
            for (src, src_prefixes, src_asbrs, _) in &views {
                // The backbone feeds every area, a non-backbone area only
                // the backbone.
                if src == dest || (!src.is_unspecified() && !dest.is_unspecified()) {
                    continue;
                }
                if stub.is_some_and(|(import, _)| !import) {
                    continue;
                }
                for &(prefix, cost) in src_prefixes {
                    if own.is_some_and(|o| o.prefixes.iter().any(|(p, _)| *p == prefix)) {
                        continue;
                    }
                    let e = prefixes.entry(prefix).or_insert(cost);
                    *e = (*e).min(cost);
                }
                for &(asbr, cost, options) in src_asbrs {
                    if own.is_some_and(|o| o.asbrs.iter().any(|(id, _, _)| *id == asbr)) {
                        continue;
                    }
                    let e = asbrs.entry(asbr).or_insert((cost, options));
                    if cost < e.0 {
                        *e = (cost, options);
                    }
                }
            }
            if stub.is_some() {
                asbrs.clear();
            }
            // RFC 3101 §2.3: into an NSSA, only without summaries.
            if let Some((import, cost)) = stub
                && (!nssa_areas.contains_key(dest) || !import)
            {
                prefixes.insert(Ipv6Net::default(), cost);
            }
            let mut desired = Vec::new();
            for (prefix, metric) in prefixes.into_iter().filter(|(_, m)| *m < 0x00FF_FFFF) {
                let metric = if infinity { 0x00FF_FFFF } else { metric };
                let lsid = self.lsid(lsa::LSA_TYPE_INTER_AREA_PREFIX, prefix).await;
                desired.push((
                    types.inter_area_prefix,
                    lsid,
                    LsaBody::InterAreaPrefix(InterAreaPrefixLsaBody {
                        metric,
                        prefix_options: 0,
                        prefix,
                    }),
                ));
            }
            for (asbr, (metric, options)) in
                asbrs.into_iter().filter(|(_, (m, _))| *m < 0x00FF_FFFF)
            {
                let metric = if infinity { 0x00FF_FFFF } else { metric };
                desired.push((
                    types.inter_area_router,
                    asbr,
                    LsaBody::InterAreaRouter(InterAreaRouterLsaBody {
                        options,
                        metric,
                        destination_router_id: asbr,
                    }),
                ));
            }
            let mut lsdb = lsdb.lock().await;
            let done = done.areas.entry(*dest).or_default();
            for (lsa_type, lsid, body) in desired {
                done.insert(install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    lsa_type,
                    lsid,
                    body,
                ));
            }
        }
    }

    /// RFC 3101 §3.1/§3.2, the start of every tick: elects whether this
    /// router translates each NSSA's Type-7s, and keeps what it translates
    /// for `originate_as_external_lsas`.
    async fn elect_nssa_translators(&self, local_router_id: Ipv4Addr) {
        let nssas = self.nssa_areas.lock().unwrap().clone();
        let abr = self.is_backbone_abr().await;
        let mut roles = HashSet::new();
        let mut translated = HashMap::new();
        for (area_id, cfg) in &nssas {
            let lsdb = self.lsdbs.lock().await.get(area_id).cloned();
            let Some(lsdb) = lsdb else { continue };
            let lsas = lsdb.lock().await.all();
            if abr && spf::nssa_translator(local_router_id, &lsas, cfg.translate_always) {
                roles.insert(*area_id);
                translated.extend(spf::nssa_translations(local_router_id, &lsas));
            }
        }
        let changed = *self.nssa_translating.lock().unwrap() != roles;
        if changed {
            info!(areas = ?roles, "ospfv3 nssa translator role changed");
        }
        *self.nssa_translating.lock().unwrap() = roles;
        *self.nssa_translated.lock().unwrap() = translated;
    }

    /// RFC 3101 §2.3: an NSSA-LSA's forwarding address — the lowest address
    /// of this router's own links in the area, else a loopback prefix's.
    async fn nssa_forwarding_address(&self, area_id: Ipv4Addr) -> Option<Ipv6Addr> {
        let link = self
            .links
            .lock()
            .await
            .values()
            .filter(|e| e.config.area_id == area_id)
            .map(|e| e.config.primary().addr())
            .min();
        match link {
            Some(addr) => Some(addr),
            None => self
                .loopback_prefixes
                .lock()
                .await
                .get(&area_id)
                .and_then(|p| p.iter().map(|(net, _)| net.addr()).min()),
        }
    }

    /// RFC 5340 §4.4.3.5: one AS-External-LSA per redistributed IPv6 prefix
    /// (and per translated Type-7, RFC 3101 §3.2) into the AS-scope store —
    /// Type-1, metric `spf::EXTERNAL_METRIC`, no tag — and one NSSA-LSA per
    /// redistributed prefix into each NSSA (P-bit unless this router is an
    /// ABR, which translates for itself), plus an optional default.
    async fn originate_as_external_lsas(&self, local_router_id: Ipv4Addr, done: &mut Originated) {
        let redistributed: Vec<Ipv6Net> = self
            .redistribute_filtered
            .lock()
            .await
            .iter()
            .copied()
            .collect();
        let types = self.lsa_types();
        let metric = if self.originate_lsinfinity.load(Ordering::Relaxed) {
            0x00FF_FFFF
        } else {
            spf::EXTERNAL_METRIC
        };
        // The AS-scope store only floods on non-stub links: a router whose
        // every area is stub is no ASBR.
        let stub_areas = self.stub_areas.lock().unwrap().clone();
        let nssa_areas = self.nssa_areas.lock().unwrap().clone();
        let attached = self.attached_areas().await;
        let mut as_ext: HashMap<Ipv6Net, AsExternalLsaBody> =
            self.nssa_translated.lock().unwrap().clone();
        if attached.is_empty() || attached.iter().any(|a| !stub_areas.contains_key(a)) {
            for &prefix in &redistributed {
                as_ext.insert(
                    prefix,
                    AsExternalLsaBody {
                        type2: false,
                        metric,
                        prefix_options: 0,
                        prefix,
                        forwarding_address: None,
                        route_tag: None,
                        referenced_ls_type: 0,
                        referenced_link_state_id: None,
                    },
                );
            }
        }
        for (prefix, body) in as_ext {
            let lsid = self.lsid(lsa::LSA_TYPE_AS_EXTERNAL, prefix).await;
            done.as_scope.insert(install_self_originated(
                &mut *self.as_lsdb.lock().await,
                local_router_id,
                types.as_external,
                lsid,
                LsaBody::AsExternal(body),
            ));
        }

        let abr = self.is_backbone_abr().await;
        for (area_id, cfg) in &nssa_areas {
            if !attached.contains(area_id) {
                continue;
            }
            let fa = self.nssa_forwarding_address(*area_id).await;
            // RFC 3101 §2.3/§2.4: P only with a forwarding address, and not
            // from an ABR, which originates the AS-External-LSA itself.
            let options = if abr || fa.is_none() {
                0
            } else {
                lsa::PREFIX_OPT_P
            };
            let mut nssa_lsas: Vec<(Ipv6Net, u32, u8, Option<Ipv6Addr>)> = redistributed
                .iter()
                .map(|&p| (p, metric, options, fa))
                .collect();
            if abr && cfg.default_originate {
                let cost = stub_areas.get(area_id).map_or(1, |&(_, cost)| cost);
                nssa_lsas.push((Ipv6Net::default(), cost, 0, None));
            }
            let lsdb = self.lsdb_for(*area_id).await;
            let mut lsdb = lsdb.lock().await;
            let done = done.areas.entry(*area_id).or_default();
            for (prefix, metric, prefix_options, forwarding_address) in nssa_lsas {
                let lsid = self.lsid(lsa::LSA_TYPE_NSSA, prefix).await;
                done.insert(install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    types.nssa,
                    lsid,
                    LsaBody::AsExternal(AsExternalLsaBody {
                        type2: false,
                        metric,
                        prefix_options,
                        prefix,
                        forwarding_address,
                        route_tag: None,
                        referenced_ls_type: 0,
                        referenced_link_state_id: None,
                    }),
                ));
            }
        }
    }

    /// How many prefixes `nos-ribd` redistributes (before policy).
    pub async fn redistribute_raw_len(&self) -> usize {
        self.redistribute_raw.lock().await.len()
    }

    /// Applies one `Ospfv3Request::RedistributeRoutes` update (pushed by the
    /// owning `nos-ribd`) to the raw set and re-filters it. `OSPFv3` routes
    /// IPv6 only: `nos-ribd` sends no IPv4 prefix, and one is ignored.
    pub async fn apply_redistribute_update(&self, update: RedistributeUpdate) {
        {
            let mut raw = self.redistribute_raw.lock().await;
            let ipv4 = self.ipv4_af();
            let v6 = |prefix: IpNet| match prefix {
                IpNet::V6(p) if !ipv4 => Some(p.trunc()),
                IpNet::V4(p) if ipv4 => Some(lsa::v4_net_to_shadow(p.trunc())),
                _ => None,
            };
            match update {
                RedistributeUpdate::Full(routes) => {
                    *raw = routes.into_iter().filter_map(|r| v6(r.prefix)).collect();
                }
                RedistributeUpdate::Add(route) => raw.extend(v6(route.prefix)),
                RedistributeUpdate::Remove(prefix) => {
                    if let Some(p) = v6(prefix) {
                        raw.remove(&p);
                    }
                }
                // Staged by `server.rs` (`RedistributeUpdate::absorb`); only
                // the closing `Full` gets here.
                RedistributeUpdate::FullPart(_) => return,
            }
        }
        self.refilter_redistributed().await;
    }

    /// Sets the redistribute policy (every `reconcile.rs` resync) and
    /// re-filters, so a policy edit takes effect without waiting for a route
    /// change — `ospf::link::LinkManager::set_redistribute_policy`.
    pub async fn set_redistribute_policy(&self, policy: Arc<CompiledPolicy>) {
        *self.redistribute_policy.lock().await = policy;
        self.refilter_redistributed().await;
    }

    async fn refilter_redistributed(&self) {
        let policy = Arc::clone(&*self.redistribute_policy.lock().await);
        let raw = self.redistribute_raw.lock().await.clone();
        let ipv4 = self.ipv4_af();
        *self.redistribute_filtered.lock().await = raw
            .into_iter()
            .filter(|&p| passes_redistribute_policy(p, &policy, ipv4))
            .collect();
    }

    /// One origination tick: every pass, then RFC 2328 §13.4/§14.1 — every
    /// live LSA of ours this tick did not originate is prematurely aged
    /// (`withdraw_undesired`), like `ospf::link`'s pass. Stateless, so it
    /// covers a lost DR role or last `Full` neighbor (Network-LSA and its
    /// IAP), an emptied router IAP, a left area, a moved Link-LSA key, the
    /// other RFC 8362 flavor, and a previous incarnation's LSAs learned
    /// over DBD alike. Only the stores of links this tick saw are swept: a
    /// removed link's store has no neighbor to flood to.
    async fn origination_pass(&self) {
        // RFC 5187 §2.1: a restarting router originates nothing (the helpers
        // hold our old LSAs); `restart_tick` wakes this on exit.
        if self.restart_active() {
            return;
        }
        let Some(router_id) = *self.router_id.lock().await else {
            return;
        };
        // RFC 2328 §13.4: a reflected own LSA that no pass re-originated (a
        // type the daemon no longer advertises) is flushed afterwards.
        let mut stores: Vec<Arc<Mutex<Lsdb>>> = self.lsdbs.lock().await.values().cloned().collect();
        stores.extend(self.link_local_lsdbs.lock().await.values().cloned());
        stores.push(Arc::clone(&self.as_lsdb));
        let mut marked = Vec::new();
        for store in stores {
            let keys = store.lock().await.reflected_keys();
            marked.push((store, keys));
        }
        self.resolve_virtual_links(router_id).await;
        self.originate_all(router_id).await;
        for (store, keys) in marked {
            let mut lsdb = store.lock().await;
            for key in keys {
                if lsdb.take_reflected(&key) {
                    withdraw_self_originated(&mut lsdb, &key);
                }
            }
        }
    }

    async fn originate_all(&self, local_router_id: Ipv4Addr) {
        let mut done = Originated::default();
        self.elect_nssa_translators(local_router_id).await;
        self.originate_router_lsas(local_router_id, &mut done).await;
        self.originate_link_lsas(local_router_id, &mut done).await;
        self.originate_intra_area_prefix_lsas(local_router_id, &mut done)
            .await;
        self.originate_inter_area_lsas(local_router_id, &mut done)
            .await;
        self.originate_as_external_lsas(local_router_id, &mut done)
            .await;
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        let none = HashSet::new();
        for (area_id, lsdb) in areas {
            let desired = done.areas.get(&area_id).unwrap_or(&none);
            withdraw_undesired(&mut *lsdb.lock().await, local_router_id, desired);
        }
        for (attach_point, desired) in &done.links {
            let lsdb = self.link_local_lsdb_for(attach_point).await;
            withdraw_undesired(&mut *lsdb.lock().await, local_router_id, desired);
        }
        withdraw_undesired(
            &mut *self.as_lsdb.lock().await,
            local_router_id,
            &done.as_scope,
        );
        self.prune_lsids().await;
    }

    /// The config a running link was started with (`None` once stopped), so
    /// `reconcile` can keep a link whose lookups fail this pass.
    pub async fn running_config(&self, attach_point: &str) -> Option<LinkConfig> {
        let links = self.links.lock().await;
        let entry = links.get(attach_point)?;
        (!entry.task.is_finished()).then(|| entry.config.clone())
    }

    /// Diffs `desired` against currently-running links — mirrors
    /// `ospf::link::LinkManager::reconcile` exactly.
    pub async fn reconcile(
        self: &Arc<Self>,
        desired: Vec<LinkConfig>,
        desired_loopback_prefixes: HashMap<Ipv4Addr, Vec<(Ipv6Net, u16)>>,
        local_router_id: Ipv4Addr,
    ) {
        *self.router_id.lock().await = Some(local_router_id);
        self.as_lsdb
            .lock()
            .await
            .set_limit(local_router_id, Arc::clone(&self.max_lsa));
        *self.loopback_prefixes.lock().await = desired_loopback_prefixes;
        *self.physical.lock().await = desired;
        self.apply_links(local_router_id).await;
    }

    /// Configured virtual links, every resync; §4.7 brings each one up or
    /// down on the origination tick (`resolve_virtual_links`).
    pub async fn set_virtual_links(&self, virtual_links: Vec<VirtualLinkConfig>) {
        *self.virtual_links.lock().await = virtual_links;
    }

    /// RFC 5340 §4.7, after the transit areas' SPF (rerun here, on every
    /// origination tick): a virtual link whose endpoint is reachable and
    /// advertises a global address is up at the path's cost, else down. A
    /// change starts, restarts (address) or stops its link task; a cost
    /// change alone is applied in place.
    async fn resolve_virtual_links(&self, local_router_id: Ipv4Addr) {
        let configured = self.virtual_links.lock().await.clone();
        if !configured.is_empty() {
            // Backbone-attached as soon as one is configured.
            self.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
        }
        let physical = self.physical.lock().await.clone();
        let loopbacks = self.loopback_prefixes.lock().await.clone();
        let mut resolved = Vec::new();
        for v in &configured {
            let Some(lsdb) = self.lsdbs.lock().await.get(&v.transit_area).cloned() else {
                continue;
            };
            let mut lsas = lsdb.lock().await.all();
            for (_, link_lsdb) in self.link_local_lsdbs_in(v.transit_area).await {
                lsas.extend(link_lsdb.lock().await.all());
            }
            let own = loopbacks
                .get(&v.transit_area)
                .map_or(&[][..], Vec::as_slice);
            resolved.extend(resolve_virtual_link(
                v,
                local_router_id,
                &lsas,
                &physical,
                own,
            ));
        }
        let mut previous = self.resolved_virtual.lock().await;
        if *previous == resolved {
            return;
        }
        for r in &resolved {
            if !previous.iter().any(|p| same_but_cost(p, r))
                && let Some(v) = r.virtual_link
            {
                info!(
                    link = %r.attach_point, neighbor = %v.neighbor, local = %r.link_local_address, cost = r.cost,
                    "ospfv3 virtual link up"
                );
            }
        }
        for p in previous.iter() {
            if !resolved.iter().any(|r| r.attach_point == p.attach_point) {
                info!(link = %p.attach_point, "ospfv3 virtual link down");
            }
        }
        *previous = resolved;
        drop(previous);
        self.apply_links(local_router_id).await;
    }

    /// Diffs the attach-point links plus the resolved virtual links against
    /// the running ones (see `reconcile`).
    async fn apply_links(&self, local_router_id: Ipv4Addr) {
        let mut desired = self.physical.lock().await.clone();
        desired.extend(self.resolved_virtual.lock().await.iter().cloned());
        let mut links = self.links.lock().await;
        links.retain(|_, entry| !entry.task.is_finished());

        let current: HashMap<String, LinkConfig> = links
            .iter()
            .map(|(k, entry)| (k.clone(), entry.config.clone()))
            .collect();
        let desired_map: HashMap<String, LinkConfig> = desired
            .into_iter()
            .map(|c| (c.attach_point.clone(), c))
            .collect();
        let (to_stop, to_spawn) = diff_links(&current, &desired_map);

        for key in &to_stop {
            if let Some(entry) = links.remove(key) {
                info!(link = %key, "ospfv3 link stopped");
                entry.task.abort();
            }
        }
        // A cost-only change (a virtual link's SPF distance, a profile's
        // cost) is a Router-LSA metric, not a reason to restart the link.
        for (key, entry) in links.iter_mut() {
            if let Some(wanted) = desired_map.get(key) {
                if entry.config.cost != wanted.cost {
                    info!(link = %key, old = entry.config.cost, cost = wanted.cost, "ospfv3 link cost changed");
                }
                entry.config.cost = wanted.cost;
            }
        }
        for cfg in to_spawn {
            let key = cfg.attach_point.clone();
            let lsdb = self.lsdb_for(cfg.area_id).await;
            let link_local_lsdb = self.link_local_lsdb_for(&cfg.attach_point).await;
            let (status_tx, status_rx) = watch::channel(LinkStatus::new(cfg.network_type));
            let (grace_tx, grace_rx) = mpsc::unbounded_channel();
            let (bfd_tx, bfd_rx) = mpsc::unbounded_channel();
            let (topology_tx, topology_rx) = mpsc::unbounded_channel();
            // A fresh boot count per authenticated (re)start keeps RFC 7166
            // sequence numbers increasing across link and process restarts.
            let boot_count = if cfg.auth.is_some() {
                let n = self.boots.next();
                if let Some(w) = n.warning {
                    warn!(warning = %w, "ospfv3 boot count problem");
                }
                n.count
            } else {
                0
            };
            let task = tokio::spawn(run(
                (self.opener)(&cfg, boot_count),
                cfg.clone(),
                local_router_id,
                lsdb,
                link_local_lsdb,
                Arc::clone(&self.as_lsdb),
                status_tx,
                self.dbd_max_headers,
                grace_rx,
                self.startup_grace(),
                topology_rx,
                bfd_rx,
            ));
            links.insert(
                key,
                LinkEntry {
                    config: cfg,
                    task,
                    status: status_rx,
                    grace_tx,
                    bfd_tx,
                    topology_tx,
                },
            );
        }
    }

    /// Records one SPF run (#1439) for `show ospfv3`. `compute_routes` stays
    /// pure: `rib_push_client` calls this after the initial snapshot and
    /// after every change-triggered recomputation, never after the poll tick.
    pub fn note_spf(&self, duration: Duration) {
        self.spf_runs.fetch_add(1, Ordering::Relaxed);
        *self.last_spf.lock().unwrap() = Some((Instant::now(), duration));
    }

    /// `show ospfv3` (#1439): router id, ABR/ASBR role, SPF counters and one
    /// row per attached area. `lsa_count` is the area store only (no
    /// link-local or AS-scope LSAs).
    pub async fn instance_summary(&self) -> nos_proto::InstanceSummary {
        use nos_proto::{AreaSummary, AreaType};
        let router_id = *self.router_id.lock().await;
        let border = self.is_backbone_abr().await;
        let boundary = !self.redistribute_filtered.lock().await.is_empty();
        let mut ids: Vec<Ipv4Addr> = self.attached_areas().await.into_iter().collect();
        ids.sort();
        let snapshot: Vec<(Ipv4Addr, usize)> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| {
                let full = e
                    .status
                    .borrow()
                    .neighbors
                    .values()
                    .filter(|n| n.state == NeighborState::Full)
                    .count();
                (e.config.area_id, full)
            })
            .collect();
        let loopbacks: HashMap<Ipv4Addr, usize> = self
            .loopback_prefixes
            .lock()
            .await
            .iter()
            .map(|(a, v)| (*a, v.len()))
            .collect();
        let mut areas = Vec::new();
        for id in ids {
            let store = self.lsdbs.lock().await.get(&id).cloned();
            let lsa_count = match store {
                Some(s) => s.lock().await.all().len(),
                None => 0,
            };
            let here = snapshot.iter().filter(|(a, _)| *a == id);
            let links = here.clone().count() + loopbacks.get(&id).copied().unwrap_or(0);
            let full: usize = here.map(|(_, f)| *f).sum();
            let area_type = if self.nssa_areas.lock().unwrap().contains_key(&id) {
                AreaType::Nssa
            } else if self.stub_areas.lock().unwrap().contains_key(&id) {
                AreaType::Stub
            } else {
                AreaType::Normal
            };
            areas.push(AreaSummary {
                area_id: id,
                area_type,
                lsa_count: u32::try_from(lsa_count).unwrap_or(u32::MAX),
                interface_count: u32::try_from(links).unwrap_or(u32::MAX),
                full_neighbor_count: u32::try_from(full).unwrap_or(u32::MAX),
            });
        }
        let last = *self.last_spf.lock().unwrap();
        nos_proto::InstanceSummary {
            router_id,
            abr: border,
            asbr: boundary,
            spf_runs: self.spf_runs.load(Ordering::Relaxed),
            last_spf_age_secs: last.map(|(at, _)| at.elapsed().as_secs()),
            last_spf_duration_micros: last
                .map(|(_, d)| u64::try_from(d.as_micros()).unwrap_or(u64::MAX)),
            areas,
        }
    }

    pub async fn neighbor_summaries(&self) -> Vec<Ospfv3NeighborSummary> {
        self.links
            .lock()
            .await
            .values()
            .flat_map(to_neighbor_summaries)
            .collect()
    }

    /// `show ospfv3 route` (#1453): the computed routes sorted by prefix; a
    /// next hop's interface is the link whose ifindex it was learned on.
    pub async fn route_summaries(&self) -> Vec<Ospfv3RouteSummary> {
        let mut routes = self.compute_routes().await;
        routes.sort_by_key(|r| r.prefix);
        let devs: HashMap<u32, String> = self
            .links
            .lock()
            .await
            .values()
            .filter(|e| e.config.virtual_link.is_none())
            .map(|e| (e.config.interface_id, e.config.kernel_interface.clone()))
            .collect();
        routes
            .iter()
            .map(|r| {
                let (class, type2_cost, cost) = r.display_class();
                Ospfv3RouteSummary {
                    prefix: r.prefix.to_string(),
                    class,
                    cost,
                    type2_cost,
                    area: r.area,
                    next_hops: r
                        .next_hops
                        .iter()
                        .map(|(a, i)| match devs.get(i) {
                            Some(dev) => format!("{a} dev {dev}"),
                            None => a.to_string(),
                        })
                        .collect(),
                    advertising_router: r.advertising_router(),
                }
            })
            .collect()
    }

    /// `show ospfv3 interface` (#1438): one row per running link, sorted by
    /// name. A virtual link is not an attach point and is skipped.
    pub async fn interface_summaries(&self) -> Vec<Ospfv3InterfaceSummary> {
        let mut rows: Vec<_> = self
            .links
            .lock()
            .await
            .values()
            .filter(|e| e.config.virtual_link.is_none())
            .map(to_interface_summary)
            .collect();
        rows.sort_by(|a, b| a.link.cmp(&b.link));
        rows
    }

    /// Every installed LSA's header: the area stores' rows carry
    /// `link: None`, each link's own store's rows carry its attach point, and
    /// the AS-scope store's rows carry area `0.0.0.0` and `link: None`.
    pub async fn database_summaries(&self) -> Vec<Ospfv3LsaSummary> {
        let mut result = Vec::new();
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        for (area_id, lsdb) in areas {
            for lsa in lsdb.lock().await.all() {
                result.push(to_lsa_summary(area_id, None, &lsa.header, Some(&lsa.body)));
            }
        }
        let links: Vec<(String, Ipv4Addr)> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| (e.config.attach_point.clone(), e.config.area_id))
            .collect();
        for (attach_point, area_id) in links {
            let lsdb = self.link_local_lsdb_for(&attach_point).await;
            for header in lsdb.lock().await.headers() {
                result.push(to_lsa_summary(
                    area_id,
                    Some(attach_point.clone()),
                    &header,
                    None,
                ));
            }
        }
        for header in self.as_lsdb.lock().await.headers() {
            result.push(to_lsa_summary(Ipv4Addr::UNSPECIFIED, None, &header, None));
        }
        result
    }

    /// Woken (one stored permit) whenever any LSDB changes, so a consumer of
    /// `compute_routes` need not poll.
    pub fn route_changed(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.route_changed)
    }

    /// Runs `crate::spf::compute` against every area's current LSDB and
    /// merges the results — mirrors `ospf::link::LinkManager::compute_routes`.
    /// Each area's input is its area store plus every same-area link's own
    /// Link-LSAs: RFC 5340 §4.8.1 derives next hops from them, so SPF is the
    /// one reader that legitimately spans every link's link-local store.
    pub async fn compute_routes(&self) -> Vec<spf::RouteEntry> {
        let Some(router_id) = *self.router_id.lock().await else {
            return Vec::new();
        };
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        let mut merged: HashMap<Ipv6Net, spf::RouteEntry> = HashMap::new();
        let backbone_abr = self.is_backbone_abr().await;
        let virtual_hops = self.virtual_next_hops(router_id).await;
        // The prefixes whose route is the backbone's, which §16.3 may improve.
        let mut backbone_routes: HashSet<Ipv6Net> = HashSet::new();
        let mut transit: Vec<spf::RouteEntry> = Vec::new();
        for (area_id, lsdb) in areas {
            let mut lsas = lsdb.lock().await.all();
            for (_, link_lsdb) in self.link_local_lsdbs_in(area_id).await {
                lsas.extend(link_lsdb.lock().await.all());
            }
            // AS-External-LSAs are routed from every area (through an
            // intra-area ASBR or an Inter-Area-Router-LSA there); the cheapest
            // wins in the merge below.
            // (never a stub area's: RFC 5340 §4.4.3, its default is the route).
            let stub = self.stub_areas.lock().unwrap().contains_key(&area_id);
            let nssa = self.nssa_areas.lock().unwrap().contains_key(&area_id);
            // A Type-5 or Type-7 held from before the area changed kind is
            // no route there.
            lsas.retain(|l| lsa::in_area_scope(l.header.lsa_type, stub, nssa));
            if !stub {
                lsas.extend(self.as_lsdb.lock().await.all());
            }
            let backbone = area_id.is_unspecified();
            let ctx = spf::Context {
                backbone,
                skip_summaries: backbone_abr && !backbone,
                virtual_links: &virtual_hops,
            };
            if ctx.skip_summaries {
                transit.extend(spf::transit_summaries(router_id, &lsas));
            }
            for mut entry in spf::compute_in(router_id, &lsas, &ctx) {
                entry.area = area_id;
                let prefix = entry.prefix;
                match merged.get_mut(&prefix) {
                    Some(existing) if entry.rank() >= existing.rank() => continue,
                    Some(existing) => *existing = entry,
                    None => {
                        merged.insert(prefix, entry);
                    }
                }
                if backbone {
                    backbone_routes.insert(prefix);
                } else {
                    backbone_routes.remove(&prefix);
                }
            }
        }
        // RFC 2328 §16.3: a transit area may hold a shorter path to a
        // backbone destination than the backbone's own (virtual-link) path.
        for candidate in transit {
            if backbone_routes.contains(&candidate.prefix)
                && let Some(existing) = merged.get_mut(&candidate.prefix)
            {
                spf::apply_transit(existing, candidate);
            }
        }
        // RFC 5340 §4.4.3.3: a discard route per active advertised range,
        // unless SPF has a real route for exactly it.
        for (&range, &metric) in self.active_ranges.lock().unwrap().iter() {
            merged
                .entry(range)
                .or_insert_with(|| spf::RouteEntry::discard(range, metric));
        }
        merged.into_values().collect()
    }

    /// RFC 5187: when graceful restart is configured, has every link send
    /// a Grace-LSA to its `Full` neighbors (twice) and waits for them to go
    /// out. Called on a planned restart only, before `shutdown`.
    /// Returns whether a grace period was announced.
    pub async fn announce_graceful_restart(&self) -> bool {
        let grace_period = self.grace_period.load(Ordering::Relaxed);
        if grace_period == 0 {
            return false;
        }
        info!(
            grace_period,
            "ospfv3 graceful restart: announcing grace period before shutdown"
        );
        let senders: Vec<mpsc::UnboundedSender<GraceCmd>> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.grace_tx.clone())
            .collect();
        for _ in 0..2 {
            for tx in &senders {
                let _ = tx.send(GraceCmd::Announce(u32::from(grace_period)));
            }
            tokio::time::sleep(GRACE_SEND_WINDOW).await;
        }
        true
    }

    pub async fn shutdown(&self) {
        for (_, entry) in self.links.lock().await.drain() {
            entry.task.abort();
        }
    }
}

fn to_lsa_summary(
    area_id: Ipv4Addr,
    link: Option<String>,
    header: &LsaHeader,
    body: Option<&LsaBody>,
) -> Ospfv3LsaSummary {
    let (router_flags, virtual_links) = match body {
        Some(LsaBody::Router(r)) => (
            Some(r.flags),
            r.links
                .iter()
                .filter(|l| l.link_type == LINK_TYPE_VIRTUAL)
                .map(|l| l.neighbor_router_id)
                .collect(),
        ),
        _ => (None, Vec::new()),
    };
    Ospfv3LsaSummary {
        area_id,
        lsa_type: header.lsa_type,
        link_state_id: header.link_state_id,
        advertising_router: header.advertising_router,
        sequence_number: header.sequence_number,
        age: header.age,
        checksum: header.checksum,
        link,
        router_flags,
        virtual_links,
    }
}

fn to_interface_state(state: InterfaceState) -> LinkInterfaceState {
    match state {
        InterfaceState::PointToPoint => LinkInterfaceState::PointToPoint,
        InterfaceState::Waiting => LinkInterfaceState::Waiting,
        InterfaceState::Dr => LinkInterfaceState::Dr,
        InterfaceState::Backup => LinkInterfaceState::Backup,
        InterfaceState::DrOther => LinkInterfaceState::DrOther,
    }
}

fn to_neighbor_state(state: NeighborState) -> OspfNeighborState {
    match state {
        NeighborState::Down => OspfNeighborState::Down,
        NeighborState::Init => OspfNeighborState::Init,
        NeighborState::TwoWay => OspfNeighborState::TwoWay,
        NeighborState::ExStart => OspfNeighborState::ExStart,
        NeighborState::Exchange => OspfNeighborState::Exchange,
        NeighborState::Loading => OspfNeighborState::Loading,
        NeighborState::Full => OspfNeighborState::Full,
    }
}

fn to_interface_summary(entry: &LinkEntry) -> Ospfv3InterfaceSummary {
    let c = &entry.config;
    let status = entry.status.borrow();
    let count = |n| u32::try_from(n).unwrap_or(u32::MAX);
    Ospfv3InterfaceSummary {
        link: c.attach_point.clone(),
        kernel_interface: c.kernel_interface.clone(),
        interface_id: c.interface_id,
        area_id: c.area_id,
        address: c.link_local_address,
        network_type: c.network_type,
        state: to_interface_state(status.interface_state),
        cost: c.cost,
        hello_interval: c.hello_interval,
        dead_interval: c.dead_interval,
        retransmit_interval: u16::try_from(RXMT_INTERVAL.as_secs()).unwrap_or(u16::MAX),
        priority: c.priority,
        dr: status.dr,
        bdr: status.bdr,
        neighbor_count: count(status.neighbors.len()),
        full_neighbor_count: count(
            status
                .neighbors
                .values()
                .filter(|n| n.state == NeighborState::Full)
                .count(),
        ),
        mtu: c.mtu,
        mtu_ignore: c.mtu_ignore,
        prefixes: c.prefixes.iter().map(ToString::to_string).collect(),
    }
}

fn to_neighbor_summaries(entry: &LinkEntry) -> Vec<Ospfv3NeighborSummary> {
    let status = entry.status.borrow().clone();
    let interface_state = to_interface_state(status.interface_state);

    if status.neighbors.is_empty() {
        if elects_dr(entry.config.network_type) {
            return Vec::new();
        }
        return vec![Ospfv3NeighborSummary {
            link: entry.config.attach_point.clone(),
            area_id: entry.config.area_id,
            interface_state,
            neighbor_router_id: None,
            state: OspfNeighborState::Down,
            last_hello_secs: None,
            hello_interval: entry.config.hello_interval,
            dead_interval: entry.config.dead_interval,
            priority: entry.config.priority,
            neighbor_priority: None,
            dr: status.dr,
            bdr: status.bdr,
            address: None,
            role: None,
            dead_in_secs: None,
            uptime_secs: None,
        }];
    }

    status
        .neighbors
        .iter()
        .map(|(id, info)| Ospfv3NeighborSummary {
            link: entry.config.attach_point.clone(),
            area_id: entry.config.area_id,
            interface_state,
            neighbor_router_id: Some(*id),
            state: to_neighbor_state(info.state),
            last_hello_secs: Some(info.last_hello_received.elapsed().as_secs()),
            hello_interval: entry.config.hello_interval,
            dead_interval: entry.config.dead_interval,
            priority: entry.config.priority,
            neighbor_priority: Some(info.priority),
            dr: status.dr,
            bdr: status.bdr,
            address: Some(info.address),
            role: nos_proto::NeighborRole::of(*id, status.dr, status.bdr),
            dead_in_secs: Some(
                u64::from(entry.config.dead_interval)
                    .saturating_sub(info.last_heard.elapsed().as_secs()),
            ),
            uptime_secs: info.full_since.map(|t| t.elapsed().as_secs()),
        })
        .collect()
}

/// RFC 5340 §4.4.3.2: whether this router is adjacent to the segment's DR —
/// the DR neighbor is `Full`, or we are the DR and at least one neighbor is
/// `Full` (a graceful-restarting neighbor still counts, as on p2p).
/// ponytail: mirror of `ospf::link::originate::adjacent_to_dr`.
/// Broadcast and RFC 6845 hybrid both run the DR/BDR election.
const fn elects_dr(network_type: NetworkType) -> bool {
    matches!(network_type, NetworkType::Broadcast | NetworkType::Hybrid)
}

/// Per advertising router (other than `local`), the neighbors its
/// Router-LSA fragments in `lsdb` carry a point-to-point link to.
fn router_lsa_targets(
    lsdb: &Lsdb,
    router_type: u16,
    local: Ipv4Addr,
) -> HashMap<Ipv4Addr, HashSet<Ipv4Addr>> {
    let mut view: HashMap<Ipv4Addr, HashSet<Ipv4Addr>> = HashMap::new();
    for l in lsdb.all() {
        let h = &l.header;
        if h.lsa_type != router_type || h.advertising_router == local || h.age >= lsa::MAX_AGE {
            continue;
        }
        if let LsaBody::Router(b) = &l.body {
            view.entry(h.advertising_router).or_default().extend(
                b.links
                    .iter()
                    .filter(|x| x.link_type == LINK_TYPE_POINT_TO_POINT)
                    .map(|x| x.neighbor_router_id),
            );
        }
    }
    view
}

/// RFC 6845 §4.6: a hybrid link is described as point-to-multipoint, but a
/// DR lists every `Full` neighbor, and a non-DR lists nothing until it is
/// `Full` with a DR that agrees on its role, then every neighbor at 2-Way or
/// better that the DR's Router-LSA links to (`dr_view`, the DR itself
/// included). Cost: the interface's (no per-neighbor output cost yet).
fn hybrid_router_links(
    links: &[(LinkConfig, LinkStatus)],
    dr_view: &HashMap<Ipv4Addr, HashSet<Ipv4Addr>>,
    max_metric: bool,
) -> Vec<RouterLsaLink> {
    let mut result = Vec::new();
    for (cfg, status) in links {
        if cfg.network_type != NetworkType::Hybrid || cfg.virtual_link.is_some() {
            continue;
        }
        let Some(dr) = status.dr else { continue };
        let up = |n: &NeighborInfo| n.state == NeighborState::Full || n.grace_deadline.is_some();
        let mut peers: Vec<(&Ipv4Addr, &NeighborInfo)> =
            if status.interface_state == InterfaceState::Dr {
                status.neighbors.iter().filter(|(_, n)| up(n)).collect()
            } else {
                let agreed = status
                    .neighbors
                    .get(&dr)
                    .is_some_and(|n| up(n) && n.declared_dr == dr);
                let empty = HashSet::new();
                let theirs = dr_view.get(&dr).unwrap_or(&empty);
                if !agreed {
                    continue;
                }
                status
                    .neighbors
                    .iter()
                    .filter(|(id, n)| {
                        matches!(
                            n.state,
                            NeighborState::TwoWay
                                | NeighborState::ExStart
                                | NeighborState::Exchange
                                | NeighborState::Loading
                                | NeighborState::Full
                        ) && (**id == dr || theirs.contains(*id))
                    })
                    .collect()
            };
        peers.sort_by_key(|(id, _)| **id);
        for (id, info) in peers {
            result.push(RouterLsaLink {
                link_type: LINK_TYPE_POINT_TO_POINT,
                metric: if max_metric {
                    MAX_LINK_METRIC
                } else {
                    cfg.cost
                },
                interface_id: cfg.interface_id,
                neighbor_interface_id: info.interface_id,
                neighbor_router_id: *id,
            });
        }
    }
    result
}

/// `LinkManager::network_prefixes`' merge: skip NU/LA, dedupe on the
/// truncated network OR-ing the options, keep first-seen order.
fn merge_network_prefixes(
    sources: &[(Ipv4Addr, Vec<LinkPrefixEntry>)],
) -> Vec<IntraAreaPrefixEntry> {
    let mut out: Vec<IntraAreaPrefixEntry> = Vec::new();
    for e in sources.iter().flat_map(|(_, p)| p) {
        if e.options & (lsa::PREFIX_OPT_NU | lsa::PREFIX_OPT_LA) != 0 {
            continue;
        }
        let prefix = e.prefix.trunc();
        match out.iter_mut().find(|o| o.prefix == prefix) {
            Some(o) => o.options |= e.options,
            None => out.push(IntraAreaPrefixEntry {
                options: e.options,
                metric: 0,
                prefix,
            }),
        }
    }
    out
}

fn adjacent_to_dr(local_router_id: Ipv4Addr, status: &LinkStatus) -> bool {
    let up = |n: &NeighborInfo| n.state == NeighborState::Full || n.grace_deadline.is_some();
    match status.dr {
        None => false,
        Some(dr) if dr == local_router_id => status.neighbors.values().any(up),
        Some(dr) => status.neighbors.get(&dr).is_some_and(up),
    }
}

/// Whether the network-referenced Intra-Area-Prefix-LSA carries this
/// broadcast link's prefix: we are the DR with a `Full` neighbor. Exactly
/// complementary to the router-referenced LSA's broadcast prefixes
/// (RFC 5340 §4.4.3.9), so a segment prefix is never absent nor doubled.
fn network_prefix_originated(status: &LinkStatus) -> bool {
    status.interface_state == InterfaceState::Dr
        && status
            .neighbors
            .values()
            .any(|n| n.state == NeighborState::Full)
}

/// RFC 5340 §4.4.3.2's Router-LSA link entries for every currently-running
/// link in one area — one point-to-point entry per link with a fully adjacent
/// neighbor, one transit-network entry per broadcast link adjacent to its DR. Unlike
/// `ospf::link::originate::router_lsa_links`, never a stub-network entry: v3's
/// Router-LSA has nowhere to carry a prefix at all (see the module doc
/// comment) — every prefix instead comes from
/// `LinkManager::originate_intra_area_prefix_lsas`.
fn router_lsa_links(
    local_router_id: Ipv4Addr,
    links: &[(LinkConfig, LinkStatus)],
    max_metric: bool,
) -> Vec<RouterLsaLink> {
    // RFC 6987 §2: a stub router advertises every link at `MaxLinkMetric`.
    let metric_of = |cfg: &LinkConfig| {
        if max_metric {
            MAX_LINK_METRIC
        } else {
            cfg.cost
        }
    };
    let mut result = Vec::new();
    for (cfg, status) in links {
        // RFC 5340 §A.4.3: a type-4 link while the virtual neighbor is fully
        // adjacent, nothing else.
        if cfg.virtual_link.is_some() {
            if let Some((neighbor_id, info)) = status
                .neighbors
                .iter()
                .filter(|(_, n)| n.state == NeighborState::Full)
                .min_by_key(|(id, _)| **id)
            {
                result.push(RouterLsaLink {
                    link_type: LINK_TYPE_VIRTUAL,
                    metric: metric_of(cfg),
                    interface_id: cfg.interface_id,
                    neighbor_interface_id: info.interface_id,
                    neighbor_router_id: *neighbor_id,
                });
            }
            continue;
        }
        match cfg.network_type {
            NetworkType::PointToPoint | NetworkType::PointToMultipoint => {
                // RFC 5340 §4.4.3.2: only a fully adjacent neighbor (a
                // neighbor back in Init after a BFD kill must drop out, #463).
                // Lowest router ID: never depend on HashMap order (#957).
                // Point-to-multipoint (RFC 2328 §12.4.1.4 equivalent) lists
                // every such neighbor, point-to-point only the first.
                let mut full: Vec<_> = status
                    .neighbors
                    .iter()
                    .filter(|(_, n)| n.state == NeighborState::Full || n.grace_deadline.is_some())
                    .collect();
                full.sort_by_key(|(id, _)| **id);
                if cfg.network_type == NetworkType::PointToPoint {
                    full.truncate(1);
                }
                for (neighbor_id, info) in full {
                    result.push(RouterLsaLink {
                        link_type: LINK_TYPE_POINT_TO_POINT,
                        metric: metric_of(cfg),
                        interface_id: cfg.interface_id,
                        neighbor_interface_id: info.interface_id,
                        neighbor_router_id: *neighbor_id,
                    });
                }
            }
            // RFC 6845 §4.6: needs the DR's Router-LSA, see `hybrid_router_links`.
            NetworkType::Hybrid => {}
            NetworkType::Broadcast => {
                // RFC 5340 §4.4.3.2: the transit link only once adjacent to
                // the DR. The prefix meanwhile rides the router-referenced
                // Intra-Area-Prefix-LSA (`network_prefix_originated`).
                let Some(dr) = status
                    .dr
                    .filter(|_| adjacent_to_dr(local_router_id, status))
                else {
                    continue;
                };
                let dr_interface_id = if dr == local_router_id {
                    cfg.interface_id
                } else {
                    status.neighbors[&dr].interface_id
                };
                result.push(RouterLsaLink {
                    link_type: LINK_TYPE_TRANSIT_NETWORK,
                    metric: metric_of(cfg),
                    interface_id: cfg.interface_id,
                    neighbor_interface_id: dr_interface_id,
                    neighbor_router_id: dr,
                });
            }
        }
    }
    result
}

/// Installs a self-originated LSA if `body` actually changed since what's
/// held, bumping the sequence number by one (at `MAX_SEQUENCE_NUMBER` it
/// flushes the LSA instead and re-originates at `INITIAL_SEQUENCE_NUMBER`
/// once the flushed copy is evicted, never producing `0x8000_0000`) — mirrors
/// `ospf::link::originate::install_self_originated` exactly, minus the `options`
/// header field (v3's header carries none — see `lsa::LsaHeader`). Returns
/// the key, originated whether or not anything had to be reinstalled.
fn install_self_originated(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    lsa_type: u16,
    link_state_id: Ipv4Addr,
    body: LsaBody,
) -> LsaKey {
    let key = LsaKey {
        lsa_type,
        link_state_id,
        advertising_router: local_router_id,
    };
    let existing = lsdb.get(&key);
    let needs_refresh = existing
        .as_ref()
        .is_some_and(|e| e.header.age >= lsa::LS_REFRESH_TIME);
    // RFC 2328 §13.4: the held copy is a neighbor's newer instance of ours,
    // so go above it even with an unchanged body.
    let reflected = lsdb.take_reflected(&key);
    let sequence_number = match &existing {
        Some(e) if e.body == body && !needs_refresh && !reflected => return key,
        // RFC 2328 §12.1.6: flush at MaxSequenceNumber; once the held copy is
        // evicted the `None` arm restarts at `INITIAL_SEQUENCE_NUMBER`.
        Some(e) if e.header.sequence_number == lsa::MAX_SEQUENCE_NUMBER => {
            withdraw_self_originated(lsdb, &key);
            return key;
        }
        Some(e) => e.header.sequence_number + 1,
        None => lsa::INITIAL_SEQUENCE_NUMBER,
    };
    let mut lsa = Lsa {
        header: LsaHeader {
            age: 0,
            lsa_type,
            link_state_id,
            advertising_router: local_router_id,
            sequence_number,
            checksum: 0,
            length: 0,
        },
        body,
    };
    lsa::fill_checksum(&mut lsa);
    lsdb.install(lsa);
    info!(
        lsa_type, link_state_id = %link_state_id, advertising_router = %local_router_id,
        refreshed = needs_refresh, reflected,
        "ospfv3 lsa originated"
    );
    key
}

/// RFC 2328 §14.1 premature aging — `ospf::link::originate::withdraw_self_originated`:
/// flushes one of this router's own LSAs by reinstalling it at `MAX_AGE`
/// with its sequence number unchanged, so `lsa::is_newer`'s `MaxAge`
/// tie-break makes every neighbor accept it; `Lsdb`'s `MaxAge` hold keeps it
/// long enough for the periodic resend to carry it out. No-op (`false`) if
/// `key` isn't held or is already at `MAX_AGE`.
fn withdraw_self_originated(lsdb: &mut Lsdb, key: &LsaKey) -> bool {
    let Some(existing) = lsdb.get(key) else {
        return false;
    };
    if existing.header.age >= lsa::MAX_AGE {
        return false;
    }
    let mut flushed = (*existing).clone();
    flushed.header.age = lsa::MAX_AGE;
    lsdb.install(flushed);
    info!(
        lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
        advertising_router = %key.advertising_router,
        "ospfv3 lsa prematurely aged"
    );
    true
}

/// Withdraws every live LSA of `local_router_id`'s in `lsdb` of an
/// `OWNED_TYPES` type that is not in `desired`.
fn withdraw_undesired(lsdb: &mut Lsdb, local_router_id: Ipv4Addr, desired: &HashSet<LsaKey>) {
    let stale: Vec<LsaKey> = lsdb
        .headers()
        .into_iter()
        .filter(|h| {
            h.advertising_router == local_router_id
                && h.age < lsa::MAX_AGE
                && OWNED_TYPES.contains(&h.lsa_type)
        })
        .map(|h| h.key())
        .filter(|k| !desired.contains(k))
        .collect();
    for key in stale {
        withdraw_self_originated(lsdb, &key);
    }
}

/// Evaluates `prefix` against a redistribute `policy` —
/// `ospf::link::originate::passes_redistribute_policy` with an IPv6 prefix: a
/// redistribute policy has no `this.bgp.*` to read, so those are empty.
fn passes_redistribute_policy(prefix: Ipv6Net, policy: &CompiledPolicy, ipv4: bool) -> bool {
    let input = nos_rpl::Input {
        prefix: match lsa::shadow_to_v4_net(prefix).filter(|_| ipv4) {
            Some(v4) => IpNet::V4(v4),
            None => IpNet::V6(prefix),
        },
        bgp: nos_rpl::BgpInput {
            tag: 0,
            origin: nos_rpl::Origin::Igp,
            as_path: &[],
            as_path_segments: &[],
            local_pref: 0,
            med: None,
            next_hop: None,
            learned_via_ibgp: false,
            router_id: None,
            originator_id: None,
            cluster_list: &[],
            peer: None,
            peer_as: 0,
            communities: &[],
            extended_communities: &[],
            large_communities: &[],
            validation_state: nos_rpl::ValidationState::default(),
            rd: None,
            local_role: None,
            remote_role: None,
            otc: None,
        },
    };
    matches!(
        nos_rpl::vm::run(policy, &input),
        nos_rpl::Verdict::Accept { .. }
    )
}

fn diff_links(
    current: &HashMap<String, LinkConfig>,
    desired: &HashMap<String, LinkConfig>,
) -> (Vec<String>, Vec<LinkConfig>) {
    let mut to_stop = Vec::new();
    let mut to_spawn = Vec::new();

    for (key, running) in current {
        match desired.get(key) {
            None => to_stop.push(key.clone()),
            Some(wanted) if !same_but_cost(wanted, running) => {
                to_stop.push(key.clone());
                to_spawn.push(wanted.clone());
            }
            Some(_) => {}
        }
    }
    for (key, wanted) in desired {
        if !current.contains_key(key) {
            to_spawn.push(wanted.clone());
        }
    }

    (to_stop, to_spawn)
}

/// `nos-ospfv3d`'s side of `crate::bfd_client`: one session per neighbor at
/// 2-Way or later on a link with a `bfd` profile, between link-local
/// addresses (RFC 5882 §3.1) so the interface scopes the session.
impl Host for LinkManager {
    async fn target(&self) -> Target {
        let wanted = self.bfd.lock().unwrap().clone();
        let mut target = Target::new();
        if wanted.is_empty() {
            return target;
        }
        for entry in self.links.lock().await.values() {
            let Some(profile) = wanted.get(&entry.config.attach_point) else {
                continue;
            };
            for n in entry.status.borrow().neighbors.values() {
                if bfd::bfd_wanted(n.state) {
                    target.insert(
                        IpAddr::V6(n.address),
                        Want {
                            profile: profile.clone(),
                            local: Some(IpAddr::V6(entry.config.link_local_address)),
                            interface: Some(entry.config.kernel_interface.clone()),
                        },
                    );
                }
            }
        }
        target
    }

    async fn down(&self, peer: IpAddr, diag: BfdDiag) {
        let IpAddr::V6(peer) = peer else { return };
        info!(peer = %peer, diag = %diag, "ospfv3: bfd session down");
        for entry in self.links.lock().await.values() {
            let _ = entry.bfd_tx.send(peer);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn link(attach_point: &str, hello_interval: u16) -> LinkConfig {
        LinkConfig {
            attach_point: attach_point.to_string(),
            area_id: Ipv4Addr::UNSPECIFIED,
            hello_interval,
            dead_interval: 40,
            vrf: "vrf100".to_string(),
            kernel_interface: "eth0".to_string(),
            interface_id: 3,
            link_local_address: "fe80::1".parse().unwrap(),
            prefixes: vec!["2001:db8::/64".parse().unwrap()],
            cost: 1,
            network_type: NetworkType::PointToPoint,
            priority: 1,
            mtu: 1500,
            mtu_ignore: false,
            auth: None,
            instance_id: 0,
            helper_max_grace_period: 1800,
            stub: false,
            ipv4_af: false,
            nssa: false,
            virtual_link: None,
        }
    }

    fn external(i: u8) -> Arc<Lsa> {
        let mut l = Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: lsa::LSA_TYPE_AS_EXTERNAL,
                link_state_id: Ipv4Addr::new(0, 0, 0, i),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: i32::MIN + 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsaBody {
                type2: false,
                metric: 1,
                prefix_options: 0,
                prefix: Ipv6Net::new(
                    Ipv6Addr::new(0x2001, 0xdb8, u16::from(i), 0, 0, 0, 0, 0),
                    48,
                )
                .unwrap(),
                forwarding_address: None,
                route_tag: None,
                referenced_ls_type: 0,
                referenced_link_state_id: None,
            }),
        };
        lsa::fill_checksum(&mut l);
        Arc::new(l)
    }

    #[test]
    fn split_budget_subtracts_headers_and_trailer_and_saturates() {
        let mut cfg = link("eth0", 10);
        cfg.mtu = 200;
        assert_eq!(split_budget(&cfg), 200 - 60);
        cfg.auth = Some(trailer(b"k")); // 16 + 32
        assert_eq!(split_budget(&cfg), 200 - 60 - 48);
        cfg.mtu = 68;
        cfg.auth = None;
        assert_eq!(split_budget(&cfg), 8);
        cfg.mtu = 10;
        assert_eq!(split_budget(&cfg), 0);
    }

    fn rl(n: u32) -> RouterLsaLink {
        RouterLsaLink {
            link_type: LINK_TYPE_POINT_TO_POINT,
            metric: 1,
            interface_id: n,
            neighbor_interface_id: n,
            neighbor_router_id: Ipv4Addr::from(n),
        }
    }

    #[test]
    fn split_router_links_cuts_by_budget_and_cap() {
        let links: Vec<_> = (1..=5).map(rl).collect();
        let ids = |v: &[Vec<RouterLsaLink>]| -> Vec<Vec<u32>> {
            v.iter()
                .map(|c| c.iter().map(|l| l.interface_id).collect())
                .collect()
        };
        // Budget for two links: ceil(5/2) chunks, in order.
        assert_eq!(
            ids(&split_router_links(&links, 32, None)),
            [vec![1, 2], vec![3, 4], vec![5]]
        );
        // Everything fits: one chunk; the cap alone also splits.
        assert_eq!(ids(&split_router_links(&links, 1000, None)).len(), 1);
        assert_eq!(
            ids(&split_router_links(&links, 1000, Some(2))),
            [vec![1, 2], vec![3, 4], vec![5]]
        );
        assert_eq!(ids(&split_router_links(&links, 32, Some(1))).len(), 5);
        // A link over budget stays whole, alone.
        assert_eq!(
            ids(&split_router_links(&links[..2], 4, None)),
            [vec![1], vec![2]]
        );
        // No links: still one (empty) fragment 0.
        assert_eq!(split_router_links(&[], 32, None), [Vec::new()]);
    }

    #[test]
    fn lsa_budget_subtracts_lsa_header_and_trailer() {
        assert_eq!(lsa_budget(1500, 0, 24), 1500 - 60 - 24);
        assert_eq!(lsa_budget(1500, 48, 24), 1500 - 60 - 24 - 48);
        assert_eq!(lsa_budget(50, 0, 24), 0);
    }

    #[test]
    fn lsu_lsr_lsack_split_within_mtu_and_union_is_the_input() {
        let rid = Ipv4Addr::new(9, 9, 9, 9);
        for auth in [None, Some(trailer(b"k"))] {
            let mut cfg = link("eth0", 10);
            cfg.mtu = 200;
            cfg.auth = auth;
            let lsas: Vec<_> = (0..20).map(external).collect();
            let keys: Vec<_> = lsas.iter().map(|l| l.header.key()).collect();
            let headers: Vec<_> = lsas.iter().map(|l| l.header).collect();
            let lsu = lsu_packets(&cfg, rid, &lsas);
            let lsr = lsr_packets(&cfg, rid, &keys);
            let ack = lsack_packets(&cfg, rid, &headers);
            let trailer_len = cfg
                .auth
                .as_ref()
                .map_or(0, packet::TrailerAuth::trailer_len);
            for p in lsu.iter().chain(&lsr).chain(&ack) {
                assert!(p.len() + 40 + trailer_len <= 200, "{} bytes", p.len());
            }
            assert!(lsu.len() > 1 && lsr.len() > 1 && ack.len() > 1);
            let got: Vec<_> = lsu
                .iter()
                .flat_map(|p| packet::decode_lsu(p).unwrap().lsas)
                .collect();
            assert_eq!(got.len(), 20);
            assert!(got.iter().zip(&lsas).all(|(g, l)| g.body == l.body));
            let got: Vec<_> = lsr
                .iter()
                .flat_map(|p| packet::decode_lsr(p).unwrap().requests)
                .collect();
            assert_eq!(got, keys);
            let got: Vec<_> = ack
                .iter()
                .flat_map(|p| packet::decode_lsack(p).unwrap().lsa_headers)
                .collect();
            assert_eq!(got, headers);
        }
    }

    #[test]
    fn oversize_lsa_goes_alone_and_empty_sends_nothing() {
        let mut cfg = link("eth0", 10);
        cfg.mtu = 68;
        let rid = Ipv4Addr::LOCALHOST;
        let lsas = vec![external(1), external(2)];
        assert_eq!(lsu_packets(&cfg, rid, &lsas).len(), 2);
        assert_eq!(lsu_packets(&cfg, rid, &[]).len(), 0);
    }

    #[test]
    fn non_link_local_sources_are_dropped() {
        let cfg = link("eth0.0", 10);
        assert!(drops_non_link_local(&cfg, "2001:db8::2".parse().unwrap()));
        assert!(!drops_non_link_local(&cfg, "fe80::2".parse().unwrap()));
    }

    #[tokio::test(start_paused = true)]
    async fn handle_hello_caps_neighbors_but_keeps_refreshing_known_ones() {
        use nos_ospf_common::ratelimit::{WarnLimiter, MAX_NEIGHBORS_PER_LINK};
        let cfg = link("eth0.0", 10);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        let mut limiter = WarnLimiter::default();
        let first = Ipv4Addr::from(0x0901_0000);
        let hello = |n: u32| packet::HelloPacket {
            router_id: Ipv4Addr::from(0x0901_0000 + n),
            area_id: cfg.area_id,
            interface_id: 4,
            router_priority: 1,
            options: lsa::OPTION_E,
            hello_interval: cfg.hello_interval,
            dead_interval: cfg.dead_interval,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        };
        let send = |n: u32, limiter: &mut WarnLimiter| {
            handle_hello(
                &mem_socket(&cfg),
                &cfg,
                Ipv4Addr::new(1, 1, 1, 1),
                &status,
                Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0000_u128 + u128::from(n)),
                &hello(n),
                false,
                limiter,
            );
        };
        for n in 0..70 {
            send(n, &mut limiter);
        }
        assert_eq!(status.borrow().neighbors.len(), MAX_NEIGHBORS_PER_LINK);
        status.send_modify(|s| s.neighbors.get_mut(&first).unwrap().priority = 99);
        send(0, &mut limiter);
        assert_eq!(status.borrow().neighbors[&first].priority, 1);
        assert_eq!(limiter.take_suppressed(), 1);
        // #957: forged IDs do not pin the table; each goes Down after the dead
        // interval and its slot is freed on a later sweep.
        tokio::time::advance(std::time::Duration::from_secs(41)).await;
        sweep_dead_neighbors(&cfg, &status);
        assert_eq!(status.borrow().neighbors.len(), MAX_NEIGHBORS_PER_LINK);
        sweep_dead_neighbors(&cfg, &status);
        assert!(status.borrow().neighbors.is_empty());
        send(1000, &mut limiter);
        assert_eq!(status.borrow().neighbors.len(), 1);
        assert_eq!(limiter.take_suppressed(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn handle_hello_drops_mismatched_timers() {
        use nos_ospf_common::ratelimit::WarnLimiter;
        let cfg = link("eth0.0", 10);
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        let mut limiter = WarnLimiter::default();
        let hello = |hi: u16, di: u16| packet::HelloPacket {
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            area_id: cfg.area_id,
            interface_id: 4,
            router_priority: 1,
            options: lsa::OPTION_E,
            hello_interval: hi,
            dead_interval: di,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        };
        let mut send = |h: packet::HelloPacket| {
            handle_hello(
                &mem_socket(&cfg),
                &cfg,
                Ipv4Addr::new(1, 1, 1, 1),
                &status,
                Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0001_u128),
                &h,
                false,
                &mut limiter,
            );
        };
        send(hello(cfg.hello_interval + 1, cfg.dead_interval));
        send(hello(cfg.hello_interval, cfg.dead_interval + 1));
        for _ in 0..5 {
            send(hello(cfg.hello_interval + 1, cfg.dead_interval));
        }
        assert!(status.borrow().neighbors.is_empty());
        send(hello(cfg.hello_interval, cfg.dead_interval));
        assert_eq!(status.borrow().neighbors.len(), 1);
        // Burst of 5 warnings, the other two drops were rate limited.
        assert_eq!(limiter.take_suppressed(), 2);
    }

    /// RFC 5340 §A.2: the Hello's E bit must match the area's kind.
    #[tokio::test(start_paused = true)]
    async fn handle_hello_drops_mismatched_e_bit() {
        use nos_ospf_common::ratelimit::WarnLimiter;
        let hello = |cfg: &LinkConfig, options: u32| packet::HelloPacket {
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            area_id: cfg.area_id,
            interface_id: 4,
            router_priority: 1,
            options,
            hello_interval: cfg.hello_interval,
            dead_interval: cfg.dead_interval,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        };
        for (stub, options, accepted) in [
            (true, lsa::OPTION_E, false),
            (true, 0, true),
            (false, 0, false),
            (false, lsa::OPTION_E, true),
        ] {
            let cfg = LinkConfig {
                stub,
                ..link("eth0.0", 10)
            };
            let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
            handle_hello(
                &mem_socket(&cfg),
                &cfg,
                Ipv4Addr::new(1, 1, 1, 1),
                &status,
                Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0001_u128),
                &hello(&cfg, options),
                false,
                &mut WarnLimiter::default(),
            );
            assert_eq!(status.borrow().neighbors.len(), usize::from(accepted));
            // A stub link's own Hello/DBD options carry no E bit.
            assert_eq!(link_options(&cfg) & lsa::OPTION_E == 0, stub);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn running_config_follows_the_task() {
        let wire = Arc::new(wire::Wire::default());
        let a = router(&wire);
        let cfg = wired_link(1, NetworkType::PointToPoint);
        assert!(a.running_config(&cfg.attach_point).await.is_none());
        a.reconcile(vec![cfg.clone()], HashMap::new(), id(1)).await;
        assert_eq!(a.running_config(&cfg.attach_point).await, Some(cfg.clone()));
        a.reconcile(vec![], HashMap::new(), id(1)).await;
        assert!(a.running_config(&cfg.attach_point).await.is_none());
    }

    /// #1439: `instance_summary` of a fresh manager, then with two areas (one
    /// an NSSA), an ASBR role and one counted SPF run.
    #[tokio::test(start_paused = true)]
    async fn instance_summary_reports_role_areas_and_spf() {
        let wire = Arc::new(wire::Wire::default());
        let m = router(&wire);
        let fresh = m.instance_summary().await;
        assert_eq!(
            (fresh.router_id, fresh.abr, fresh.asbr, fresh.spf_runs),
            (None, false, false, 0)
        );
        assert_eq!(fresh.last_spf_age_secs, None);
        assert_eq!(fresh.areas.len(), 0);

        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        m.set_stub_areas(HashMap::from([(area1, (true, 1))]));
        m.set_nssa_areas(HashMap::from([(area1, NssaSettings::default())]));
        let prefix = |s: &str| (s.parse::<Ipv6Net>().unwrap(), 1);
        m.reconcile(
            vec![],
            HashMap::from([
                (Ipv4Addr::UNSPECIFIED, vec![prefix("2001:db8:9::/64")]),
                (area1, vec![prefix("2001:db8:a::/64")]),
            ]),
            id(1),
        )
        .await;
        m.originate_all(id(1)).await;
        m.apply_redistribute_update(RedistributeUpdate::Full(vec![
            nos_proto::RedistributedRoute {
                prefix: "2001:db8:ffff::/48".parse::<Ipv6Net>().unwrap().into(),
                gateway: "fe80::9".parse().unwrap(),
            },
        ]))
        .await;
        m.set_redistribute_policy(Arc::new(nos_rpl::ACCEPT_ALL.clone()))
            .await;
        m.note_spf(Duration::from_micros(250));
        tokio::time::advance(Duration::from_secs(7)).await;

        let s = m.instance_summary().await;
        assert_eq!(s.router_id, Some(id(1)));
        assert!(s.abr, "two areas incl. the backbone");
        assert!(s.asbr);
        assert_eq!((s.spf_runs, s.last_spf_age_secs), (1, Some(7)));
        assert_eq!(s.last_spf_duration_micros, Some(250));
        let rows: Vec<_> = s
            .areas
            .iter()
            .map(|a| (a.area_id, a.area_type, a.interface_count, a.lsa_count >= 1))
            .collect();
        assert_eq!(
            rows,
            [
                (Ipv4Addr::UNSPECIFIED, nos_proto::AreaType::Normal, 1, true),
                (area1, nos_proto::AreaType::Nssa, 1, true),
            ]
        );
    }

    #[test]
    fn interface_id_change_restarts() {
        let current = HashMap::from([("eth0.0".to_string(), link("eth0.0", 10))]);
        let (stop, spawn) = diff_links(&current, &current.clone());
        assert!(stop.is_empty() && spawn.is_empty());
        let mut recreated = link("eth0.0", 10);
        recreated.interface_id = 7;
        let (stop, spawn) = diff_links(
            &current,
            &HashMap::from([("eth0.0".to_string(), recreated)]),
        );
        assert_eq!((stop.len(), spawn.len()), (1, 1));
    }

    #[test]
    fn no_changes_produces_no_diff() {
        let mut current = HashMap::new();
        current.insert("eth0.0".to_string(), link("eth0.0", 10));
        let desired = current.clone();
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert_eq!(to_stop, [] as [String; 0]);
        assert_eq!(to_spawn, []);
    }

    #[test]
    fn new_link_is_spawned() {
        let current = HashMap::new();
        let mut desired = HashMap::new();
        desired.insert("eth0.0".to_string(), link("eth0.0", 10));
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert_eq!(to_stop, [] as [String; 0]);
        assert_eq!(to_spawn, vec![link("eth0.0", 10)]);
    }

    #[test]
    fn removed_link_is_stopped() {
        let mut current = HashMap::new();
        current.insert("eth0.0".to_string(), link("eth0.0", 10));
        let desired = HashMap::new();
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert_eq!(to_stop, vec!["eth0.0".to_string()]);
        assert_eq!(to_spawn, []);
    }

    #[test]
    fn changed_link_is_stopped_and_respawned() {
        let mut current = HashMap::new();
        current.insert("eth0.0".to_string(), link("eth0.0", 10));
        let mut desired = HashMap::new();
        desired.insert("eth0.0".to_string(), link("eth0.0", 5));
        let (to_stop, to_spawn) = diff_links(&current, &desired);
        assert_eq!(to_stop, vec!["eth0.0".to_string()]);
        assert_eq!(to_spawn, vec![link("eth0.0", 5)]);
    }

    #[test]
    fn at_bit_follows_auth_config() {
        let mut cfg = link("eth0.0", 10);
        assert_eq!(link_options(&cfg) & lsa::OPTION_AT, 0);
        cfg.auth = Some(packet::TrailerAuth {
            keys: vec![(1, packet::CryptoAlgorithm::HmacSha256, b"k".to_vec())],
            current_key_id: 1,
        });
        assert_ne!(link_options(&cfg) & lsa::OPTION_AT, 0);
        assert_ne!(link_options(&cfg) & lsa::OPTION_V6, 0);
    }

    #[test]
    fn crypto_sequence_must_strictly_increase_per_neighbor() {
        let neighbor = Ipv4Addr::new(9, 9, 9, 10);
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        status.neighbors.insert(
            neighbor,
            neighbor_info(NeighborState::Init, "fe80::2".parse().unwrap(), 4),
        );
        let (tx, _rx) = watch::channel(status);
        let mut hello = packet::HelloPacket {
            router_id: neighbor,
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_id: 4,
            router_priority: 1,
            options: lsa::OPTION_E,
            hello_interval: 10,
            dead_interval: 40,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: Vec::new(),
        };
        let pkt = OspfPacket::Hello(hello.clone());
        assert!(accept_crypto_sequence(&tx, None, &pkt));
        assert!(accept_crypto_sequence(&tx, Some(5), &pkt));
        assert!(!accept_crypto_sequence(&tx, Some(5), &pkt));
        assert!(!accept_crypto_sequence(&tx, Some(4), &pkt));
        assert!(accept_crypto_sequence(&tx, Some(6), &pkt));
        assert_eq!(
            tx.borrow().neighbors[&neighbor].last_crypto_seq[&packet::TYPE_HELLO],
            6
        );
        // A DBD has its own counter: seq 3 after Hello 6 is fresh, then a replay.
        let dbd = OspfPacket::Dbd(packet::DbdPacket {
            lls: None,
            router_id: neighbor,
            area_id: Ipv4Addr::UNSPECIFIED,
            options: 0,
            interface_mtu: 1500,
            init: false,
            resync: false,
            more: false,
            master: false,
            dd_sequence_number: 1,
            lsa_headers: Vec::new(),
        });
        assert!(accept_crypto_sequence(&tx, Some(3), &dbd));
        assert!(!accept_crypto_sequence(&tx, Some(3), &dbd));
        assert!(!accept_crypto_sequence(&tx, Some(6), &pkt));
        // An unknown neighbor is never dropped (no state yet).
        hello.router_id = Ipv4Addr::new(9, 9, 9, 11);
        assert!(accept_crypto_sequence(
            &tx,
            Some(1),
            &OspfPacket::Hello(hello)
        ));
    }

    #[test]
    fn point_to_point_neighbor_is_always_adjacency_eligible() {
        assert!(should_form_adjacency(
            InterfaceState::PointToPoint,
            Ipv4Addr::new(1, 1, 1, 1),
            None,
            None,
        ));
    }

    #[test]
    fn dr_other_pair_is_not_adjacency_eligible() {
        assert!(!should_form_adjacency(
            InterfaceState::DrOther,
            Ipv4Addr::new(1, 1, 1, 1),
            Some(Ipv4Addr::new(2, 2, 2, 2)),
            Some(Ipv4Addr::new(3, 3, 3, 3)),
        ));
    }

    #[test]
    fn set_state_tracks_full_since() {
        let mut n = neighbor_info(NeighborState::TwoWay, Ipv6Addr::LOCALHOST, 1);
        assert!(n.full_since.is_none());
        n.set_state(NeighborState::Full);
        let t = n.full_since.expect("set on entering Full");
        n.set_state(NeighborState::Full);
        assert_eq!(n.full_since, Some(t));
        n.set_state(NeighborState::Down);
        assert!(n.full_since.is_none());
    }

    #[test]
    fn down_clears_crypto_replay_state_init_keeps_it() {
        let mut n = neighbor_info(NeighborState::Init, Ipv6Addr::LOCALHOST, 1);
        n.last_crypto_seq.insert(packet::TYPE_HELLO, 99);
        clear_replay_state(&mut n);
        assert_eq!(n.last_crypto_seq.len(), 1);
        n.state = NeighborState::Down;
        clear_replay_state(&mut n);
        assert!(n.last_crypto_seq.is_empty());
    }

    fn neighbor_info(state: NeighborState, address: Ipv6Addr, interface_id: u32) -> NeighborInfo {
        NeighborInfo {
            state,
            priority: 1,
            declared_dr: Ipv4Addr::UNSPECIFIED,
            declared_bdr: Ipv4Addr::UNSPECIFIED,
            interface_id,
            last_hello_received: Instant::now(),
            last_heard: Instant::now(),
            address,
            adjacency: None,
            last_crypto_seq: HashMap::new(),
            grace_deadline: None,
            full_since: None,
        }
    }

    #[test]
    fn router_lsa_links_includes_p2p_link_with_a_neighbor() {
        let cfg = link("eth0.0", 10);
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
        status.neighbors.insert(
            neighbor_id,
            neighbor_info(NeighborState::Full, "fe80::2".parse().unwrap(), 7),
        );
        let links = router_lsa_links(Ipv4Addr::new(1, 1, 1, 1), &[(cfg.clone(), status)], false);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_type, LINK_TYPE_POINT_TO_POINT);
        assert_eq!(links[0].neighbor_router_id, neighbor_id);
        assert_eq!(links[0].neighbor_interface_id, 7);
        assert_eq!(links[0].interface_id, cfg.interface_id);
    }

    /// Point-to-multipoint lists every `Full` neighbor (not `Init`), point-to-point
    /// only the lowest router ID.
    #[test]
    fn router_lsa_links_p2mp_lists_every_full_neighbor() {
        let mut cfg = link("eth0.0", 10);
        let mut status = LinkStatus::new(NetworkType::PointToMultipoint);
        for (i, state) in [
            (12, NeighborState::Full),
            (10, NeighborState::Full),
            (11, NeighborState::Init),
        ] {
            status.neighbors.insert(
                Ipv4Addr::new(9, 9, 9, i),
                neighbor_info(state, "fe80::2".parse().unwrap(), u32::from(i)),
            );
        }
        let me = Ipv4Addr::new(1, 1, 1, 1);
        cfg.network_type = NetworkType::PointToMultipoint;
        let ids: Vec<_> = router_lsa_links(me, &[(cfg.clone(), status.clone())], false)
            .iter()
            .map(|l| l.neighbor_router_id)
            .collect();
        assert_eq!(
            ids,
            [Ipv4Addr::new(9, 9, 9, 10), Ipv4Addr::new(9, 9, 9, 12)]
        );
        cfg.network_type = NetworkType::PointToPoint;
        assert_eq!(router_lsa_links(me, &[(cfg, status)], false).len(), 1);
    }

    /// RFC 5340 §4.4.3.9: a point-to-multipoint link advertises its own
    /// address as a /128 with LA, not the subnet.
    #[tokio::test]
    async fn p2mp_link_advertises_its_address_as_a_host_prefix() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let mut cfg = link("eth0.0", 10);
        cfg.network_type = NetworkType::PointToMultipoint;
        cfg.prefixes = vec!["2001:db8::1/64".parse().unwrap()];
        manager
            .reconcile(vec![cfg.clone()], HashMap::new(), router_id)
            .await;
        manager.originate_all(router_id).await;
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_INTRA_AREA_PREFIX,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: router_id,
        };
        let installed = manager
            .lsdb_for(cfg.area_id)
            .await
            .lock()
            .await
            .get(&key)
            .unwrap();
        let LsaBody::IntraAreaPrefix(body) = &installed.body else {
            panic!("expected intra-area-prefix lsa")
        };
        assert_eq!(body.prefixes.len(), 1);
        assert_eq!(body.prefixes[0].prefix, "2001:db8::1/128".parse().unwrap());
        assert_eq!(body.prefixes[0].options, lsa::PREFIX_OPT_LA);
    }

    fn hybrid_link(
        role: InterfaceState,
        dr: Ipv4Addr,
        neighbors: &[(u8, NeighborState)],
    ) -> (LinkConfig, LinkStatus) {
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Hybrid;
        let mut status = LinkStatus::new(NetworkType::Hybrid);
        status.interface_state = role;
        status.dr = Some(dr);
        for (i, state) in neighbors {
            let id = Ipv4Addr::new(9, 9, 9, *i);
            let mut n = neighbor_info(*state, "fe80::2".parse().unwrap(), u32::from(*i));
            n.declared_dr = dr;
            status.neighbors.insert(id, n);
        }
        (cfg, status)
    }

    /// RFC 6845 §4.1/§4.3: hybrid runs the election like broadcast, starts in
    /// `Waiting`, and floods to the groups (a broadcast-model destination).
    #[test]
    fn hybrid_elects_and_floods_like_broadcast() {
        assert_eq!(
            LinkStatus::new(NetworkType::Hybrid).interface_state,
            InterfaceState::Waiting
        );
        assert!(elects_dr(NetworkType::Hybrid) && elects_dr(NetworkType::Broadcast));
        assert!(!elects_dr(NetworkType::PointToMultipoint));
        let (cfg, status) = hybrid_link(InterfaceState::Dr, ME, &[]);
        let (tx, _rx) = watch::channel(status);
        assert_eq!(current_dest(&cfg, &tx), Dest::AllSpfRouters);
    }

    /// RFC 6845 §4.6: a DR lists every `Full` neighbor, the cost is the
    /// interface's, and the broadcast arm adds no transit link.
    #[test]
    fn hybrid_router_links_dr_lists_every_full_neighbor() {
        let (cfg, status) = hybrid_link(
            InterfaceState::Dr,
            ME,
            &[
                (12, NeighborState::Full),
                (10, NeighborState::Full),
                (11, NeighborState::TwoWay),
            ],
        );
        let links = [(cfg, status)];
        assert_eq!(router_lsa_links(ME, &links, false), []);
        let got = hybrid_router_links(&links, &HashMap::new(), false);
        let ids: Vec<_> = got.iter().map(|l| l.neighbor_router_id).collect();
        assert_eq!(
            ids,
            [Ipv4Addr::new(9, 9, 9, 10), Ipv4Addr::new(9, 9, 9, 12)]
        );
        assert!(got.iter().all(|l| l.link_type == LINK_TYPE_POINT_TO_POINT));
        assert_eq!(got[0].metric, links[0].0.cost);
        assert_eq!(got[0].neighbor_interface_id, 10);
    }

    /// RFC 6845 §4.6: a non-DR needs a `Full`, agreeing DR, then lists the DR
    /// and the 2-Way-or-better neighbors the DR's Router-LSA links to.
    #[test]
    fn hybrid_router_links_non_dr_follows_the_drs_router_lsa() {
        let dr = Ipv4Addr::new(9, 9, 9, 10);
        let other = Ipv4Addr::new(9, 9, 9, 11);
        let stranger = Ipv4Addr::new(9, 9, 9, 12);
        let view = HashMap::from([(dr, HashSet::from([ME, other]))]);
        let nbrs = [
            (10, NeighborState::Full),
            (11, NeighborState::TwoWay),
            (12, NeighborState::TwoWay),
        ];
        let (cfg, status) = hybrid_link(InterfaceState::DrOther, dr, &nbrs);
        let ids = |l: Vec<RouterLsaLink>| -> Vec<Ipv4Addr> {
            l.iter().map(|x| x.neighbor_router_id).collect()
        };
        let got = ids(hybrid_router_links(
            &[(cfg.clone(), status.clone())],
            &view,
            false,
        ));
        assert_eq!(got, [dr, other], "{stranger} is not in the DR's LSA");
        // No DR LSA yet: only the DR itself (it is the adjacency).
        let got = ids(hybrid_router_links(
            &[(cfg.clone(), status.clone())],
            &HashMap::new(),
            false,
        ));
        assert_eq!(got, [dr]);
        // Not Full with the DR, or the DR disagrees on its role: nothing.
        let mut bad = status.clone();
        bad.neighbors.get_mut(&dr).unwrap().state = NeighborState::TwoWay;
        assert_eq!(
            hybrid_router_links(&[(cfg.clone(), bad)], &view, false),
            Vec::<RouterLsaLink>::new()
        );
        let mut bad = status;
        bad.neighbors.get_mut(&dr).unwrap().declared_dr = Ipv4Addr::UNSPECIFIED;
        assert_eq!(
            hybrid_router_links(&[(cfg, bad)], &view, false),
            Vec::<RouterLsaLink>::new()
        );
    }

    /// RFC 6845 §4.5/§4.6.2: no Network-LSA, and the Intra-Area-Prefix-LSA
    /// carries both the /128 (LA) and the interface prefix.
    #[tokio::test]
    async fn hybrid_originates_no_network_lsa_and_both_prefixes() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let mut cfg = link("eth0.0", 10);
        cfg.network_type = NetworkType::Hybrid;
        cfg.prefixes = vec!["2001:db8::1/64".parse().unwrap()];
        manager
            .reconcile(vec![cfg.clone()], HashMap::new(), router_id)
            .await;
        manager.originate_all(router_id).await;
        let lsdb = manager.lsdb_for(cfg.area_id).await;
        let lsdb = lsdb.lock().await;
        let types = manager.lsa_types();
        assert!(lsdb
            .all()
            .iter()
            .all(|l| l.header.lsa_type != types.network));
        let key = LsaKey {
            lsa_type: types.intra_area_prefix,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: router_id,
        };
        let installed = lsdb.get(&key).unwrap();
        let LsaBody::IntraAreaPrefix(body) = &installed.body else {
            panic!("expected intra-area-prefix lsa")
        };
        let got: Vec<_> = body
            .prefixes
            .iter()
            .map(|p| (p.prefix, p.options))
            .collect();
        assert_eq!(
            got,
            [
                ("2001:db8::1/128".parse().unwrap(), lsa::PREFIX_OPT_LA),
                ("2001:db8::1/64".parse().unwrap(), 0)
            ]
        );
    }

    #[tokio::test]
    async fn router_lsa_targets_collects_other_routers_point_to_point_links() {
        let mut db = Lsdb::new();
        let dr = Ipv4Addr::new(9, 9, 9, 10);
        let types =
            LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory()).lsa_types();
        let link_to = |id| RouterLsaLink {
            link_type: LINK_TYPE_POINT_TO_POINT,
            metric: 1,
            interface_id: 1,
            neighbor_interface_id: 2,
            neighbor_router_id: id,
        };
        install_self_originated(
            &mut db,
            dr,
            types.router,
            dr,
            LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: 0,
                links: vec![link_to(ME)],
            }),
        );
        install_self_originated(
            &mut db,
            ME,
            types.router,
            ME,
            LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: 0,
                links: vec![link_to(dr)],
            }),
        );
        let view = router_lsa_targets(&db, types.router, ME);
        assert_eq!(view, HashMap::from([(dr, HashSet::from([ME]))]));
    }

    /// RFC 6987 §2: a stub router advertises every link at `MaxLinkMetric`.
    #[test]
    fn router_lsa_links_use_max_metric_for_a_stub_router() {
        let cfg = link("eth0.0", 10);
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        status.neighbors.insert(
            Ipv4Addr::new(9, 9, 9, 10),
            neighbor_info(NeighborState::Full, "fe80::2".parse().unwrap(), 7),
        );
        let me = Ipv4Addr::new(1, 1, 1, 1);
        let normal = router_lsa_links(me, &[(cfg.clone(), status.clone())], false);
        let stub = router_lsa_links(me, &[(cfg.clone(), status)], true);
        assert_eq!(normal[0].metric, cfg.cost);
        assert_eq!(stub[0].metric, 0xFFFF);
    }

    /// RFC 6987 reasons: administrative, on-startup (expires), on-shutdown,
    /// each logged once through `max_metric_tick`.
    #[tokio::test(start_paused = true)]
    async fn max_metric_reasons_and_expiry() {
        let m = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        assert!(!m.max_metric_tick());
        m.set_max_metric(Some(10), None, false);
        assert!(m.max_metric_tick(), "on-startup");
        tokio::time::advance(std::time::Duration::from_secs(11)).await;
        assert!(!m.max_metric_tick(), "expired");
        // The period is armed once: a later config change never re-arms it.
        m.set_max_metric(Some(10), None, false);
        assert!(!m.max_metric_tick());
        m.set_max_metric(None, None, true);
        assert!(m.max_metric_tick(), "administrative");
        m.set_max_metric(None, None, false);
        assert!(!m.max_metric_tick(), "cleared");
    }

    /// RFC 6987 §3.2 (c): no on-startup after a graceful restart; the
    /// on-shutdown hold lasts its configured seconds.
    #[tokio::test(start_paused = true)]
    async fn max_metric_on_startup_is_skipped_after_graceful_restart() {
        let m = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        m.set_after_graceful_restart(true);
        m.set_max_metric(Some(10), Some(2), false);
        assert!(!m.max_metric_tick());

        let m = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        m.set_max_metric(None, Some(2), false);
        *m.router_id.lock().await = Some(Ipv4Addr::new(1, 1, 1, 1));
        let t = Instant::now();
        m.max_metric_on_shutdown().await;
        assert_eq!(Instant::now() - t, std::time::Duration::from_secs(2));
        assert!(m.max_metric_tick(), "stub router while shutting down");
    }

    /// #463, RFC 5340 §4.4.3.2: an Init neighbor is not fully adjacent.
    #[test]
    fn router_lsa_links_omits_p2p_link_until_full() {
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        status.neighbors.insert(
            Ipv4Addr::new(9, 9, 9, 10),
            neighbor_info(NeighborState::Init, "fe80::2".parse().unwrap(), 7),
        );
        let links = router_lsa_links(
            Ipv4Addr::new(1, 1, 1, 1),
            &[(link("eth0.0", 10), status)],
            false,
        );
        assert!(links.is_empty(), "{links:?}");
    }

    /// #957: with a stale Full entry and a live one, the lowest ID is named.
    #[test]
    fn router_lsa_links_names_the_lowest_full_router_id() {
        for _ in 0..8 {
            let mut status = LinkStatus::new(NetworkType::PointToPoint);
            for (id, state) in [
                (Ipv4Addr::new(9, 9, 9, 30), NeighborState::Full),
                (Ipv4Addr::new(9, 9, 9, 20), NeighborState::Full),
                (Ipv4Addr::new(9, 9, 9, 10), NeighborState::Init),
            ] {
                status
                    .neighbors
                    .insert(id, neighbor_info(state, "fe80::2".parse().unwrap(), 7));
            }
            let links = router_lsa_links(
                Ipv4Addr::new(1, 1, 1, 1),
                &[(link("eth0.0", 10), status)],
                false,
            );
            assert_eq!(links.len(), 1);
            assert_eq!(links[0].neighbor_router_id, Ipv4Addr::new(9, 9, 9, 20));
        }
    }

    const ME: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const PEER: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 10);

    fn bcast(dr: Option<Ipv4Addr>, neighbor: Option<NeighborState>) -> (LinkConfig, LinkStatus) {
        let mut cfg = link("bd1", 10);
        cfg.network_type = NetworkType::Broadcast;
        let mut status = LinkStatus::new(NetworkType::Broadcast);
        status.dr = dr;
        if dr == Some(ME) {
            status.interface_state = InterfaceState::Dr;
        }
        if let Some(state) = neighbor {
            status
                .neighbors
                .insert(PEER, neighbor_info(state, "fe80::2".parse().unwrap(), 7));
        }
        (cfg, status)
    }

    #[test]
    fn router_lsa_links_omit_broadcast_link_until_adjacent_to_dr() {
        // RFC 5340 §4.4.3.2 / RFC 2328 §12.4.1.2.
        let (cfg, status) = bcast(None, None);
        assert_eq!(router_lsa_links(ME, &[(cfg, status)], false), []);
        for state in [
            NeighborState::Init,
            NeighborState::TwoWay,
            NeighborState::ExStart,
            NeighborState::Exchange,
            NeighborState::Loading,
        ] {
            let (cfg, status) = bcast(Some(PEER), Some(state));
            assert_eq!(
                router_lsa_links(ME, &[(cfg, status)], false),
                [],
                "{state:?}"
            );
        }
        let (cfg, status) = bcast(Some(PEER), None);
        assert_eq!(router_lsa_links(ME, &[(cfg, status)], false), []);
        let (cfg, status) = bcast(Some(PEER), Some(NeighborState::Full));
        let links = router_lsa_links(ME, &[(cfg, status)], false);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].neighbor_interface_id, 7);
        assert_eq!(links[0].neighbor_router_id, PEER);
    }

    #[test]
    fn router_lsa_links_dr_needs_a_full_neighbor() {
        for neighbor in [None, Some(NeighborState::Loading)] {
            let (cfg, status) = bcast(Some(ME), neighbor);
            assert_eq!(router_lsa_links(ME, &[(cfg, status)], false), []);
        }
        let (cfg, status) = bcast(Some(ME), Some(NeighborState::Full));
        let links = router_lsa_links(ME, &[(cfg.clone(), status)], false);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].neighbor_interface_id, cfg.interface_id);
        assert_eq!(links[0].neighbor_router_id, ME);
    }

    #[test]
    fn network_prefix_originated_only_for_the_dr_with_a_full_neighbor() {
        for (dr, neighbor, want) in [
            (Some(ME), None, false),
            (Some(ME), Some(NeighborState::Loading), false),
            (Some(ME), Some(NeighborState::Full), true),
            (Some(PEER), Some(NeighborState::Full), false),
            (None, None, false),
        ] {
            let (_, status) = bcast(dr, neighbor);
            assert_eq!(
                network_prefix_originated(&status),
                want,
                "{dr:?} {neighbor:?}"
            );
        }
    }

    #[test]
    fn install_self_originated_first_install_uses_initial_sequence_number() {
        let mut lsdb = Lsdb::new();
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let body = LsaBody::Router(RouterLsaBody {
            flags: 0,
            options: 0,
            links: Vec::new(),
        });
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            body.clone(),
        );
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: local_router_id,
            advertising_router: local_router_id,
        };
        let installed = lsdb.get(&key).unwrap();
        assert_eq!(
            installed.header.sequence_number,
            lsa::INITIAL_SEQUENCE_NUMBER
        );
        assert_eq!(installed.body, body);
    }

    fn own_router_lsa(seq: i32) -> Lsa {
        let mut l = Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(1, 1, 1, 1),
                advertising_router: Ipv4Addr::new(1, 1, 1, 1),
                sequence_number: seq,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: 0,
                links: Vec::new(),
            }),
        };
        lsa::fill_checksum(&mut l);
        l
    }

    /// RFC 2328 §13.4: a reflected newer copy is re-originated above it even
    /// with an unchanged body; the mark is consumed (no storm), and at
    /// `MAX_SEQUENCE_NUMBER` the copy is flushed instead.
    #[test]
    fn install_self_originated_reoriginates_above_a_reflected_copy() {
        let me = Ipv4Addr::new(1, 1, 1, 1);
        let body = own_router_lsa(0).body;
        let key = own_router_lsa(0).header.key();
        let mut lsdb = Lsdb::new();
        let seq_after = |lsdb: &mut Lsdb| {
            install_self_originated(lsdb, me, lsa::LSA_TYPE_ROUTER, me, body.clone());
            lsdb.get(&key).unwrap().header.sequence_number
        };
        let base = lsa::INITIAL_SEQUENCE_NUMBER + 9;
        lsdb.install(own_router_lsa(base));
        assert_eq!(seq_after(&mut lsdb), base);
        lsdb.mark_reflected(key);
        assert_eq!(seq_after(&mut lsdb), base + 1);
        assert_eq!(seq_after(&mut lsdb), base + 1);

        let mut lsdb = Lsdb::new();
        lsdb.install(own_router_lsa(lsa::MAX_SEQUENCE_NUMBER));
        lsdb.mark_reflected(key);
        seq_after(&mut lsdb);
        assert_eq!(lsdb.get(&key).unwrap().header.age, lsa::MAX_AGE);
    }

    /// `max-lsa` (#1146): past the cap a new foreign LSA is neither held nor
    /// acknowledged, while the held one stays updatable.
    #[tokio::test(start_paused = true)]
    async fn handle_lsu_refuses_foreign_lsas_past_max_lsa() {
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
        let cfg = link("eth0.0", 10);
        let mut db = Lsdb::new();
        db.set_limit(Ipv4Addr::new(1, 1, 1, 1), Arc::new(AtomicU32::new(1)));
        let area = Mutex::new(db);
        let (link_store, as_scope) = (Mutex::new(Lsdb::new()), Mutex::new(Lsdb::new()));
        let stores = Stores {
            area: &area,
            link: &link_store,
            as_scope: &as_scope,
            stub: false,
        };
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        status.send_modify(|s| {
            let mut info = neighbor_info(NeighborState::Full, "fe80::2".parse().unwrap(), 7);
            info.adjacency = Some(AdjacencyData::default());
            s.neighbors.insert(neighbor_id, info);
        });
        let lsu = |lsas| LsuPacket {
            discarded: 0,
            last_error: None,
            router_id: neighbor_id,
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas,
        };
        let from = |n: u8, seq| {
            let mut l = own_router_lsa(seq);
            l.header.advertising_router = Ipv4Addr::new(n, n, n, n);
            l
        };
        let key = |n: u8| from(n, 0).header.key();
        let seq = lsa::INITIAL_SEQUENCE_NUMBER;
        handle_lsu(
            &cfg,
            Ipv4Addr::new(1, 1, 1, 1),
            &status,
            &stores,
            &lsu(vec![from(2, seq), from(3, seq)]),
        )
        .await;
        {
            let db = area.lock().await;
            assert!(db.get(&key(2)).is_some());
            assert!(db.get(&key(3)).is_none());
            assert_eq!(db.refused(), 1);
        }
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        handle_lsu(
            &cfg,
            Ipv4Addr::new(1, 1, 1, 1),
            &status,
            &stores,
            &lsu(vec![from(2, seq + 1)]),
        )
        .await;
        let held = area.lock().await.get(&key(2)).unwrap();
        assert_eq!(held.header.sequence_number, seq + 1);
    }

    /// A reflected own LSA is marked in the store it landed in and wakes the
    /// originator; a foreign one is not.
    #[tokio::test]
    async fn handle_lsu_marks_a_reflected_own_lsa_and_wakes_the_originator() {
        use futures::FutureExt as _;
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
        let cfg = link("eth0.0", 10);
        let n = Arc::new(tokio::sync::Notify::new());
        let area = Mutex::new(Lsdb::new().with_reflect_notify(Arc::clone(&n)));
        let (link_store, as_scope) = (Mutex::new(Lsdb::new()), Mutex::new(Lsdb::new()));
        let stores = Stores {
            area: &area,
            link: &link_store,
            as_scope: &as_scope,
            stub: false,
        };
        area.lock()
            .await
            .install(own_router_lsa(lsa::INITIAL_SEQUENCE_NUMBER));
        let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
        status.send_modify(|s| {
            let mut info = neighbor_info(NeighborState::Full, "fe80::2".parse().unwrap(), 7);
            info.adjacency = Some(AdjacencyData::default());
            s.neighbors.insert(neighbor_id, info);
        });
        let lsu = |lsas| LsuPacket {
            discarded: 0,
            last_error: None,
            router_id: neighbor_id,
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas,
        };
        let me = Ipv4Addr::new(1, 1, 1, 1);
        let mut foreign = own_router_lsa(lsa::INITIAL_SEQUENCE_NUMBER + 1);
        foreign.header.link_state_id = neighbor_id;
        foreign.header.advertising_router = neighbor_id;
        handle_lsu(&cfg, me, &status, &stores, &lsu(vec![foreign])).await;
        assert_eq!(area.lock().await.reflected_keys(), Vec::<LsaKey>::new());
        assert!(n.notified().now_or_never().is_none());

        let newer = own_router_lsa(lsa::INITIAL_SEQUENCE_NUMBER + 5);
        handle_lsu(&cfg, me, &status, &stores, &lsu(vec![newer.clone()])).await;
        assert_eq!(area.lock().await.reflected_keys(), vec![newer.header.key()]);
        assert!(n.notified().now_or_never().is_some());
    }

    #[test]
    fn install_self_originated_unchanged_body_is_a_no_op() {
        let mut lsdb = Lsdb::new();
        let local_router_id = Ipv4Addr::new(1, 1, 1, 1);
        let body = LsaBody::Router(RouterLsaBody {
            flags: 0,
            options: 0,
            links: Vec::new(),
        });
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            body.clone(),
        );
        install_self_originated(
            &mut lsdb,
            local_router_id,
            lsa::LSA_TYPE_ROUTER,
            local_router_id,
            body,
        );
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: local_router_id,
            advertising_router: local_router_id,
        };
        assert_eq!(
            lsdb.get(&key).unwrap().header.sequence_number,
            lsa::INITIAL_SEQUENCE_NUMBER
        );
    }

    #[test]
    fn install_self_originated_at_max_sequence_flushes_then_restarts_at_initial() {
        let mut lsdb = Lsdb::new();
        let id = Ipv4Addr::new(1, 1, 1, 1);
        let body = |flags| {
            LsaBody::Router(RouterLsaBody {
                flags,
                options: 0,
                links: Vec::new(),
            })
        };
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: id,
            advertising_router: id,
        };
        let install = |lsdb: &mut Lsdb, b| {
            install_self_originated(lsdb, id, lsa::LSA_TYPE_ROUTER, id, b);
        };
        lsdb.install(Lsa {
            header: LsaHeader {
                age: 100,
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: id,
                advertising_router: id,
                sequence_number: lsa::MAX_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: body(0),
        });
        // Unchanged body: still a no-op.
        install(&mut lsdb, body(0));
        assert_eq!(lsdb.get(&key).unwrap().header.age, 100);

        install(&mut lsdb, body(1));
        let flushed = lsdb.get(&key).unwrap();
        assert_eq!(flushed.header.sequence_number, lsa::MAX_SEQUENCE_NUMBER);
        assert_eq!(flushed.header.age, lsa::MAX_AGE);
        assert_eq!(flushed.body, body(0));

        for _ in 0..crate::lsdb::MAX_AGE_HOLD_TICKS - 1 {
            assert_eq!(lsdb.age_and_evict(1, &HashSet::new()), []);
            install(&mut lsdb, body(1));
            assert_eq!(
                lsdb.get(&key).unwrap().header.sequence_number,
                lsa::MAX_SEQUENCE_NUMBER
            );
        }
        assert_eq!(lsdb.age_and_evict(1, &HashSet::new()), vec![key]);

        install(&mut lsdb, body(1));
        let fresh = lsdb.get(&key).unwrap();
        assert_eq!(fresh.header.sequence_number, lsa::INITIAL_SEQUENCE_NUMBER);
        assert_eq!(fresh.header.age, 0);
        assert_eq!(fresh.body, body(1));
    }

    /// #157: only our own live LSAs of an owned type outside `desired` are
    /// flushed, with the sequence number unchanged.
    #[test]
    fn withdraw_undesired_flushes_only_undesired_own_lsas() {
        let me = Ipv4Addr::new(1, 1, 1, 1);
        let other = Ipv4Addr::new(2, 2, 2, 2);
        let lsa = |lsa_type, advertising_router, age| Lsa {
            header: LsaHeader {
                age,
                lsa_type,
                link_state_id: Ipv4Addr::new(0, 0, 0, 7),
                advertising_router,
                sequence_number: 5,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Grace(GraceLsaBody {
                grace_period: 1,
                restart_reason: lsa::RESTART_REASON_SOFTWARE,
            }),
        };
        let mut lsdb = Lsdb::new();
        let kept = lsa(lsa::LSA_TYPE_ROUTER, me, 1);
        let mut untouched = vec![
            kept.clone(),
            lsa(lsa::LSA_TYPE_NETWORK, other, 1),
            lsa(lsa::LSA_TYPE_GRACE, me, 1),
            lsa(lsa::LSA_TYPE_E_LINK, me, lsa::MAX_AGE),
        ];
        let flushed: Vec<Lsa> = OWNED_TYPES[1..]
            .iter()
            .filter(|t| **t != lsa::LSA_TYPE_E_LINK)
            .map(|t| lsa(*t, me, 1))
            .collect();
        for l in untouched.iter().chain(&flushed) {
            lsdb.install(l.clone());
        }
        withdraw_undesired(&mut lsdb, me, &HashSet::from([kept.header.key()]));
        for l in untouched.drain(..) {
            assert_eq!(lsdb.get(&l.header.key()).unwrap().header, l.header);
        }
        for l in flushed {
            let h = lsdb.get(&l.header.key()).unwrap().header;
            assert_eq!(
                (h.age, h.sequence_number),
                (lsa::MAX_AGE, 5),
                "{:#x}",
                h.lsa_type
            );
        }
    }

    fn age_of(lsdb: &Lsdb, lsa_type: u16, link_state_id: Ipv4Addr, me: Ipv4Addr) -> Option<u16> {
        lsdb.get(&LsaKey {
            lsa_type,
            link_state_id,
            advertising_router: me,
        })
        .map(|l| l.header.age)
    }

    /// #157: a router IAP with no p2p link or loopback left, and a Link-LSA
    /// whose interface id moved, are both flushed.
    #[tokio::test]
    async fn emptied_router_iap_and_moved_link_lsa_are_flushed() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let me = Ipv4Addr::new(1, 1, 1, 1);
        let p2p = link("eth0.0", 10);
        let mut bd = link("broadcast-domain:bd1", 10);
        bd.interface_id = 7;
        bd.network_type = NetworkType::Broadcast;
        manager
            .reconcile(vec![p2p.clone(), bd.clone()], HashMap::new(), me)
            .await;
        manager.originate_all(me).await;
        let area = manager.lsdb_for(p2p.area_id).await;
        let iap = || async {
            age_of(
                &*area.lock().await,
                lsa::LSA_TYPE_INTRA_AREA_PREFIX,
                Ipv4Addr::UNSPECIFIED,
                me,
            )
        };
        assert!(iap().await.unwrap() < lsa::MAX_AGE);

        let mut moved = bd.clone();
        moved.interface_id = 8;
        manager
            .reconcile(vec![moved.clone()], HashMap::new(), me)
            .await;
        manager.originate_all(me).await;
        // #958: the lone broadcast link, not adjacent to a DR, keeps its prefix
        // in the router IAP (RFC 5340 §4.4.3.9) — only the p2p one left it.
        assert!(iap().await.unwrap() < lsa::MAX_AGE);
        let store = manager.link_local_lsdb_for(&bd.attach_point).await;
        let store = store.lock().await;
        let link_age = |id| age_of(&store, lsa::LSA_TYPE_LINK, lsa::interface_id_key(id), me);
        assert_eq!(link_age(7), Some(lsa::MAX_AGE));
        assert!(link_age(8).unwrap() < lsa::MAX_AGE);
        let router = age_of(&*area.lock().await, lsa::LSA_TYPE_ROUTER, me, me);
        assert!(router.unwrap() < lsa::MAX_AGE);
        drop(store);

        // Nothing left at all: the router IAP is flushed.
        manager.reconcile(Vec::new(), HashMap::new(), me).await;
        manager.originate_all(me).await;
        assert_eq!(iap().await, Some(lsa::MAX_AGE));
    }

    async fn set_redist(m: &LinkManager, ps: &[u16]) {
        *m.redistribute_filtered.lock().await = ps.iter().map(|n| ext_prefix(*n)).collect();
    }

    async fn ext_lsid(m: &LinkManager, n: u16) -> Ipv4Addr {
        m.lsids.lock().await.map[&(lsa::LSA_TYPE_AS_EXTERNAL, ext_prefix(n))].0
    }

    fn ext_prefix(n: u16) -> Ipv6Net {
        format!("2001:db8:{n:x}::/48").parse().unwrap()
    }

    /// #685: `lsids` tracks the live prefix set (no growth under churn), two
    /// live prefixes never share an ID after a prune, and a re-advertised
    /// prefix gets a fresh ID while its old LSA is MaxAge-flushed.
    #[tokio::test]
    async fn lsids_are_pruned_and_never_reused() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let me = Ipv4Addr::new(1, 1, 1, 1);

        set_redist(&manager, &[1, 2]).await;
        manager.originate_all(me).await;
        let (id1, id2) = (ext_lsid(&manager, 1).await, ext_lsid(&manager, 2).await);
        assert_ne!(id1, id2);

        // Prefix 1 goes away; 3 arrives. len()+1 would hand 3 the ID of 2.
        set_redist(&manager, &[2, 3]).await;
        manager.originate_all(me).await;
        assert_eq!(manager.lsids.lock().await.map.len(), 2);
        assert_eq!(ext_lsid(&manager, 2).await, id2);
        let id3 = ext_lsid(&manager, 3).await;
        assert_ne!(id3, id2);
        assert_ne!(id3, id1);

        // Churn: the map stays bounded by the live set.
        for n in 10..60 {
            set_redist(&manager, &[2, n]).await;
            manager.originate_all(me).await;
            assert_eq!(manager.lsids.lock().await.map.len(), 2);
        }

        // Re-advertise 1: fresh ID, and the old LSA was flushed.
        set_redist(&manager, &[1]).await;
        manager.originate_all(me).await;
        assert_ne!(ext_lsid(&manager, 1).await, id1);
        let as_lsdb = manager.as_lsdb.lock().await;
        assert_eq!(
            age_of(&as_lsdb, lsa::LSA_TYPE_AS_EXTERNAL, id1, me),
            Some(lsa::MAX_AGE)
        );
    }

    #[tokio::test]
    async fn originate_link_lsas_installs_one_per_live_link() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let cfg = link("eth0.0", 10);
        manager
            .reconcile(vec![cfg.clone()], HashMap::new(), router_id)
            .await;
        // Link driver tasks are spawned but never reach a real socket in
        // this unit-test environment (no root/raw-socket access) — origin
        // uses `links` (the config map), not socket state, so this still
        // exercises the origination logic directly regardless.
        manager.originate_all(router_id).await;

        let lsdb = manager.link_local_lsdb_for(&cfg.attach_point).await;
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_LINK,
            link_state_id: lsa::interface_id_key(cfg.interface_id),
            advertising_router: router_id,
        };
        let installed = lsdb.lock().await.get(&key).unwrap();
        let LsaBody::Link(body) = &installed.body else {
            panic!("expected link lsa")
        };
        assert_eq!(body.link_local_address, cfg.link_local_address);
        assert_eq!(body.prefixes.len(), 1);
        assert_eq!(body.prefixes[0].prefix, cfg.prefixes[0]);
    }

    /// RFC 5340 §4.5.1 (#46): two links in one area each hold only their
    /// own Link-LSA, and the area store holds neither — so neither link's
    /// DBD summary/flood can ever offer the other's.
    #[tokio::test]
    async fn link_lsas_are_kept_per_link_not_per_area() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let eth = link("eth0.0", 10);
        let mut bd = link("broadcast-domain:bd1", 10);
        bd.interface_id = 7;
        bd.network_type = NetworkType::Broadcast;
        manager
            .reconcile(vec![eth.clone(), bd.clone()], HashMap::new(), router_id)
            .await;
        manager.originate_all(router_id).await;

        let key = |cfg: &LinkConfig| LsaKey {
            lsa_type: lsa::LSA_TYPE_LINK,
            link_state_id: lsa::interface_id_key(cfg.interface_id),
            advertising_router: router_id,
        };
        let eth_store = manager.link_local_lsdb_for(&eth.attach_point).await;
        let bd_store = manager.link_local_lsdb_for(&bd.attach_point).await;
        assert!(eth_store.lock().await.get(&key(&eth)).is_some());
        assert!(eth_store.lock().await.get(&key(&bd)).is_none());
        assert!(bd_store.lock().await.get(&key(&bd)).is_some());
        assert!(bd_store.lock().await.get(&key(&eth)).is_none());
        let area = manager.lsdb_for(eth.area_id).await;
        assert!(area.lock().await.get(&key(&eth)).is_none());
        assert!(area.lock().await.get(&key(&bd)).is_none());

        // `show ospfv3 database` still lists both, each tagged with its link.
        let mut rows: Vec<(u16, Option<String>)> = manager
            .database_summaries()
            .await
            .into_iter()
            .filter(|r| r.lsa_type == lsa::LSA_TYPE_LINK)
            .map(|r| (r.lsa_type, r.link))
            .collect();
        rows.sort();
        assert_eq!(
            rows,
            vec![
                (lsa::LSA_TYPE_LINK, Some(bd.attach_point.clone())),
                (lsa::LSA_TYPE_LINK, Some(eth.attach_point.clone())),
            ]
        );
    }

    /// SPF still sees a neighbor's Link-LSA once it lives in the link's own
    /// store: without it the next hop can't be derived and the route is
    /// silently dropped (`spf::no_link_lsa_for_neighbor_is_treated_as_unreachable`).
    #[tokio::test]
    async fn compute_routes_merges_link_local_stores_into_spf_input() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let root = Ipv4Addr::new(1, 1, 1, 1);
        let w = Ipv4Addr::new(2, 2, 2, 2);
        let cfg = link("eth0.0", 10);
        manager
            .reconcile(vec![cfg.clone()], HashMap::new(), root)
            .await;
        let header = |lsa_type, link_state_id, advertising_router| LsaHeader {
            age: 0,
            lsa_type,
            link_state_id,
            advertising_router,
            sequence_number: 1,
            checksum: 0,
            length: 0,
        };
        let p2p = |neighbor, own_if, neighbor_if| RouterLsaLink {
            link_type: LINK_TYPE_POINT_TO_POINT,
            metric: 1,
            interface_id: own_if,
            neighbor_interface_id: neighbor_if,
            neighbor_router_id: neighbor,
        };
        let router_lsa = |id, links| Lsa {
            header: header(lsa::LSA_TYPE_ROUTER, id, id),
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: 0,
                links,
            }),
        };
        let stub: Ipv6Net = "2001:db8:1::/64".parse().unwrap();
        let w_link_local: Ipv6Addr = "fe80::2".parse().unwrap();
        {
            let area = manager.lsdb_for(cfg.area_id).await;
            let mut area = area.lock().await;
            area.install(router_lsa(root, vec![p2p(w, cfg.interface_id, 2)]));
            area.install(router_lsa(w, vec![p2p(root, 2, cfg.interface_id)]));
            area.install(Lsa {
                header: header(lsa::LSA_TYPE_INTRA_AREA_PREFIX, Ipv4Addr::UNSPECIFIED, w),
                body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                    referenced_ls_type: lsa::LSA_TYPE_ROUTER,
                    referenced_link_state_id: w,
                    referenced_advertising_router: w,
                    prefixes: vec![IntraAreaPrefixEntry {
                        options: 0,
                        metric: 1,
                        prefix: stub,
                    }],
                }),
            });
        }
        assert_eq!(manager.compute_routes().await, []);

        // w's Link-LSA arrives on eth0.0 — into that link's own store.
        manager
            .link_local_lsdb_for(&cfg.attach_point)
            .await
            .lock()
            .await
            .install(Lsa {
                header: header(lsa::LSA_TYPE_LINK, lsa::interface_id_key(2), w),
                body: LsaBody::Link(LinkLsaBody {
                    priority: 1,
                    options: 0,
                    link_local_address: w_link_local,
                    prefixes: Vec::new(),
                }),
            });
        let routes = manager.compute_routes().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, stub);
        assert_eq!(routes[0].next_hop, w_link_local);
        // `show ospfv3 route` (#1453).
        let rows = manager.route_summaries().await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].prefix, "2001:db8:1::/64");
        assert_eq!(rows[0].class, nos_proto::RoutePathClass::IntraArea);
        assert_eq!(rows[0].area, cfg.area_id);
        assert_eq!(rows[0].advertising_router, Some(w));
        assert_eq!(
            rows[0].next_hops,
            [format!("fe80::2 dev {}", cfg.kernel_interface)]
        );
    }

    #[tokio::test]
    async fn extended_mode_originates_only_extended_lsas() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        manager.set_extended_lsa(true);
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let cfg = link("eth0.0", 10);
        manager
            .reconcile(vec![cfg.clone()], HashMap::new(), router_id)
            .await;
        manager.originate_all(router_id).await;

        let types: HashSet<u16> = manager
            .database_summaries()
            .await
            .iter()
            .map(|h| h.lsa_type)
            .collect();
        assert!(types.contains(&lsa::LSA_TYPE_E_ROUTER));
        assert!(types.contains(&lsa::LSA_TYPE_E_LINK));
        assert!(!types.contains(&lsa::LSA_TYPE_ROUTER));
        assert!(!types.contains(&lsa::LSA_TYPE_LINK));
        assert!(!types.contains(&lsa::LSA_TYPE_INTRA_AREA_PREFIX));
    }

    /// RFC 8362 mode switch (#149): the old flavor is prematurely aged with
    /// its sequence number unchanged while the new one is live, and
    /// switching back re-originates it at seq+1.
    #[tokio::test]
    async fn extended_mode_toggle_flushes_the_other_flavor() {
        const LEGACY: [u16; 3] = [
            lsa::LSA_TYPE_ROUTER,
            lsa::LSA_TYPE_LINK,
            lsa::LSA_TYPE_INTRA_AREA_PREFIX,
        ];
        const EXTENDED: [u16; 3] = [
            lsa::LSA_TYPE_E_ROUTER,
            lsa::LSA_TYPE_E_LINK,
            lsa::LSA_TYPE_E_INTRA_AREA_PREFIX,
        ];
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        manager
            .reconcile(vec![link("eth0.0", 10)], HashMap::new(), router_id)
            .await;
        let tick = || manager.originate_all(router_id);
        let by_type = || async {
            manager
                .database_summaries()
                .await
                .into_iter()
                .map(|s| (s.lsa_type, (s.sequence_number, s.age)))
                .collect::<HashMap<u16, (i32, u16)>>()
        };

        tick().await;
        let legacy = by_type().await;
        for t in LEGACY {
            assert!(legacy[&t].1 < lsa::MAX_AGE, "{t:#x} live");
        }

        manager.set_extended_lsa(true);
        tick().await;
        let db = by_type().await;
        for t in LEGACY {
            assert_eq!(db[&t], (legacy[&t].0, lsa::MAX_AGE), "{t:#x} flushed");
        }
        for t in EXTENDED {
            assert!(db[&t].1 < lsa::MAX_AGE, "{t:#x} live");
        }

        manager.set_extended_lsa(false);
        tick().await;
        let db = by_type().await;
        for t in LEGACY {
            assert_eq!(db[&t].0, legacy[&t].0 + 1, "{t:#x} re-originated");
            assert!(db[&t].1 < lsa::MAX_AGE, "{t:#x} live");
        }
        for t in EXTENDED {
            assert_eq!(db[&t].1, lsa::MAX_AGE, "{t:#x} flushed");
        }
    }

    /// #1157: toggling `extended-lsa` in an NSSA ages the other flavor of
    /// the NSSA-LSA (`0x2007` <-> `0xA027`) with its sequence number kept.
    #[tokio::test]
    async fn extended_mode_toggle_flushes_the_other_nssa_flavor() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        manager.set_stub_areas(HashMap::from([(area1, (true, 1))]));
        manager.set_nssa_areas(HashMap::from([(area1, NssaSettings::default())]));
        let cfg = LinkConfig {
            area_id: area1,
            stub: true,
            nssa: true,
            ..link("eth0.0", 10)
        };
        manager
            .reconcile(vec![cfg], HashMap::new(), router_id)
            .await;
        manager
            .apply_redistribute_update(RedistributeUpdate::Full(vec![
                nos_proto::RedistributedRoute {
                    prefix: IpNet::V6("2001:db8:e::/48".parse().unwrap()),
                    gateway: "2001:db8::99".parse().unwrap(),
                },
            ]))
            .await;
        let m = &manager;
        let age_of = |t: u16| async move {
            m.database_summaries()
                .await
                .into_iter()
                .find(|s| s.lsa_type == t)
                .map(|s| (s.sequence_number, s.age))
        };
        manager.originate_all(router_id).await;
        let legacy = age_of(lsa::LSA_TYPE_NSSA).await.unwrap();
        assert!(legacy.1 < lsa::MAX_AGE);
        assert!(age_of(lsa::LSA_TYPE_E_NSSA).await.is_none());

        manager.set_extended_lsa(true);
        manager.originate_all(router_id).await;
        assert_eq!(
            age_of(lsa::LSA_TYPE_NSSA).await,
            Some((legacy.0, lsa::MAX_AGE))
        );
        assert!(age_of(lsa::LSA_TYPE_E_NSSA).await.unwrap().1 < lsa::MAX_AGE);

        manager.set_extended_lsa(false);
        manager.originate_all(router_id).await;
        assert_eq!(age_of(lsa::LSA_TYPE_E_NSSA).await.unwrap().1, lsa::MAX_AGE);
        assert!(age_of(lsa::LSA_TYPE_NSSA).await.unwrap().1 < lsa::MAX_AGE);
    }

    #[tokio::test]
    async fn originate_intra_area_prefix_lsas_includes_loopback_for_area_with_no_live_link() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let area = Ipv4Addr::UNSPECIFIED;
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let stub: Ipv6Net = "2001:db8:9::/128".parse().unwrap();
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area, vec![(stub, 5)])]),
                router_id,
            )
            .await;
        manager.originate_all(router_id).await;

        let lsdb = manager.lsdb_for(area).await;
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_INTRA_AREA_PREFIX,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: router_id,
        };
        let installed = lsdb.lock().await.get(&key).unwrap();
        let LsaBody::IntraAreaPrefix(body) = &installed.body else {
            panic!("expected intra-area-prefix lsa")
        };
        assert_eq!(body.referenced_ls_type, lsa::LSA_TYPE_ROUTER);
        assert_eq!(body.prefixes.len(), 1);
        assert_eq!(body.prefixes[0].prefix, stub);
        assert_eq!(body.prefixes[0].metric, 5);
        // RFC 5340 A.4.1.1: a /128 loopback is flagged LA, a shorter one is not.
        assert_eq!(body.prefixes[0].options, lsa::PREFIX_OPT_LA);
    }

    /// RFC 5838: in an IPv4-unicast instance a /32 loopback is the host
    /// prefix (LA), and a link advertises its IPv4 address.
    #[tokio::test]
    async fn ipv4_af_loopback_is_la_and_link_lsa_carries_the_v4_address() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        manager.set_ipv4_af(true);
        let area = Ipv4Addr::UNSPECIFIED;
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let lo = lsa::v4_net_to_shadow("10.9.9.9/32".parse().unwrap());
        let cfg = LinkConfig {
            ipv4_af: true,
            prefixes: vec![lsa::v4_net_to_shadow("192.0.2.1/24".parse().unwrap())],
            ..link("eth0.0", 10)
        };
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area, vec![(lo, 5)])]),
                router_id,
            )
            .await;
        manager.originate_all(router_id).await;
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_INTRA_AREA_PREFIX,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: router_id,
        };
        let installed = manager.lsdb_for(area).await.lock().await.get(&key).unwrap();
        let LsaBody::IntraAreaPrefix(body) = &installed.body else {
            panic!("expected intra-area-prefix lsa")
        };
        let loopback = body.prefixes.iter().find(|p| p.prefix == lo).unwrap();
        assert_eq!(loopback.options, lsa::PREFIX_OPT_LA);
        assert_eq!(cfg.lsa_address(), cfg.primary().addr());
        assert_eq!(cfg.host_prefix(&cfg.prefixes[0]).prefix_len(), 32);
    }

    #[tokio::test]
    async fn loopback_subnet_prefix_has_no_la_bit() {
        let manager = LinkManager::new(1, None, nos_ospf_common::boot::BootCounter::in_memory());
        let area = Ipv4Addr::UNSPECIFIED;
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let net: Ipv6Net = "2001:db8:9::/64".parse().unwrap();
        manager
            .reconcile(
                Vec::new(),
                HashMap::from([(area, vec![(net, 5)])]),
                router_id,
            )
            .await;
        manager.originate_all(router_id).await;
        let lsdb = manager.lsdb_for(area).await;
        let key = LsaKey {
            lsa_type: lsa::LSA_TYPE_INTRA_AREA_PREFIX,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: router_id,
        };
        let installed = lsdb.lock().await.get(&key).unwrap();
        let LsaBody::IntraAreaPrefix(body) = &installed.body else {
            panic!("expected intra-area-prefix lsa")
        };
        assert_eq!(body.prefixes[0].options, 0);
    }

    fn grace_status(grace: Option<Instant>) -> StatusHandle {
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        let mut info = neighbor_info(NeighborState::Full, "fe80::2".parse().unwrap(), 4);
        info.adjacency = Some(start_negotiation(&link("eth0.0", 10), Ipv4Addr::new(1, 1, 1, 1)).0);
        info.grace_deadline = grace;
        status.neighbors.insert(Ipv4Addr::new(9, 9, 9, 10), info);
        watch::channel(status).0
    }

    fn state_of(status: &StatusHandle) -> NeighborState {
        status.borrow().neighbors[&Ipv4Addr::new(9, 9, 9, 10)].state
    }

    fn restarted_hello() -> packet::HelloPacket {
        packet::HelloPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 10),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_id: 4,
            router_priority: 1,
            options: lsa::OPTION_E,
            hello_interval: 10,
            dead_interval: 40,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: Vec::new(),
        }
    }

    #[tokio::test]
    async fn grace_holds_full_through_a_hello_that_does_not_list_us() {
        let cfg = link("eth0.0", 10);
        let me = Ipv4Addr::new(1, 1, 1, 1);
        for (grace, expected) in [
            (
                Some(Instant::now() + std::time::Duration::from_secs(60)),
                NeighborState::Full,
            ),
            (None, NeighborState::Init),
        ] {
            let status = grace_status(grace);
            handle_hello(
                &mem_socket(&cfg),
                &cfg,
                me,
                &status,
                "fe80::2".parse().unwrap(),
                &restarted_hello(),
                false,
                &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
            );
            assert_eq!(state_of(&status), expected);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn grace_suppresses_the_inactivity_timer_until_it_expires() {
        let cfg = link("eth0.0", 10);
        let status = grace_status(Some(Instant::now() + std::time::Duration::from_secs(60)));
        tokio::time::advance(std::time::Duration::from_secs(41)).await;
        sweep_dead_neighbors(&cfg, &status);
        assert_eq!(state_of(&status), NeighborState::Full);

        status.send_modify(|s| {
            for n in s.neighbors.values_mut() {
                n.grace_deadline = Some(Instant::now());
            }
        });
        expire_grace(&cfg, &status);
        assert!(!in_grace(&status, Ipv4Addr::new(9, 9, 9, 10)));
        // `expire_grace` restarts the inactivity clock.
        tokio::time::advance(std::time::Duration::from_secs(41)).await;
        sweep_dead_neighbors(&cfg, &status);
        assert_eq!(state_of(&status), NeighborState::Down);
        // Removed on a later tick, never in the one that stepped it Down.
        sweep_dead_neighbors(&cfg, &status);
        assert!(status.borrow().neighbors.is_empty());
    }

    /// A grace-held neighbor is never removed, even long silent.
    #[tokio::test(start_paused = true)]
    async fn grace_neighbor_is_never_removed() {
        let cfg = link("eth0.0", 10);
        let status = grace_status(Some(Instant::now() + std::time::Duration::from_secs(600)));
        status.send_modify(|s| {
            for n in s.neighbors.values_mut() {
                n.state = NeighborState::Down;
            }
        });
        tokio::time::advance(std::time::Duration::from_secs(100)).await;
        sweep_dead_neighbors(&cfg, &status);
        assert_eq!(status.borrow().neighbors.len(), 1);
    }

    fn hello_from(cfg: &LinkConfig, id: Ipv4Addr) -> packet::HelloPacket {
        packet::HelloPacket {
            router_id: id,
            area_id: cfg.area_id,
            interface_id: 4,
            router_priority: 1,
            options: lsa::OPTION_E,
            hello_interval: cfg.hello_interval,
            dead_interval: cfg.dead_interval,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        }
    }

    fn hello_in(cfg: &LinkConfig, status: &StatusHandle, source: &str, id: Ipv4Addr) {
        handle_hello(
            &mem_socket(cfg),
            cfg,
            Ipv4Addr::new(1, 1, 1, 1),
            status,
            source.parse().unwrap(),
            &hello_from(cfg, id),
            false,
            &mut nos_ospf_common::ratelimit::WarnLimiter::default(),
        );
    }

    /// #957: no shared deadline; the old ID dies on its own `last_heard` while
    /// the new one stays, then its entry is removed on a later tick.
    #[tokio::test(start_paused = true)]
    async fn old_p2p_neighbor_dies_on_its_own_last_heard() {
        let cfg = link("eth0.0", 10);
        let (old, new) = (Ipv4Addr::new(9, 9, 9, 10), Ipv4Addr::new(9, 9, 9, 11));
        let mut st = LinkStatus::new(NetworkType::PointToPoint);
        st.neighbors.insert(
            old,
            neighbor_info(NeighborState::Full, "fe80::2".parse().unwrap(), 4),
        );
        st.neighbors.insert(
            new,
            neighbor_info(NeighborState::Full, "fe80::3".parse().unwrap(), 4),
        );
        let (status, _rx) = watch::channel(st);
        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        status.send_modify(|s| s.neighbors.get_mut(&new).unwrap().last_heard = Instant::now());
        tokio::time::advance(std::time::Duration::from_secs(11)).await;
        sweep_dead_neighbors(&cfg, &status);
        assert_eq!(status.borrow().neighbors[&old].state, NeighborState::Down);
        assert_eq!(status.borrow().neighbors[&new].state, NeighborState::Full);
        sweep_dead_neighbors(&cfg, &status);
        assert!(!status.borrow().neighbors.contains_key(&old));
        assert!(status.borrow().neighbors.contains_key(&new));
    }

    #[tokio::test(start_paused = true)]
    async fn same_address_new_router_id_evicts_on_p2p_and_p2mp_not_broadcast() {
        let (old, new) = (Ipv4Addr::new(9, 9, 9, 10), Ipv4Addr::new(9, 9, 9, 11));
        for (nt, evicted) in [
            (NetworkType::PointToPoint, true),
            (NetworkType::PointToMultipoint, true),
            (NetworkType::Broadcast, false),
        ] {
            let mut cfg = link("eth0.0", 10);
            cfg.network_type = nt;
            let mut st = LinkStatus::new(nt);
            let mut info = neighbor_info(NeighborState::Full, "fe80::2".parse().unwrap(), 4);
            info.adjacency = Some(start_negotiation(&cfg, Ipv4Addr::new(1, 1, 1, 1)).0);
            st.neighbors.insert(old, info);
            let (status, _rx) = watch::channel(st);
            hello_in(&cfg, &status, "fe80::2", new);
            let s = status.borrow();
            assert_eq!(s.neighbors[&new].state, NeighborState::Init, "{nt:?}");
            if evicted {
                assert_eq!(s.neighbors[&old].state, NeighborState::Down, "{nt:?}");
                assert!(s.neighbors[&old].adjacency.is_none(), "{nt:?}");
            } else {
                assert_eq!(s.neighbors[&old].state, NeighborState::Full, "{nt:?}");
            }
        }
    }

    /// A restarting (grace) helper-mode neighbor is not evicted.
    #[tokio::test(start_paused = true)]
    async fn same_address_eviction_skips_a_grace_neighbor() {
        let cfg = link("eth0.0", 10);
        let status = grace_status(Some(Instant::now() + std::time::Duration::from_secs(60)));
        hello_in(&cfg, &status, "fe80::2", Ipv4Addr::new(9, 9, 9, 99));
        assert_eq!(state_of(&status), NeighborState::Full);
    }

    /// A BFD-killed neighbor (Init) goes Down on the dead interval, is removed after.
    #[tokio::test(start_paused = true)]
    async fn bfd_killed_neighbor_is_removed_once_idle() {
        let cfg = link("eth0.0", 10);
        let id = Ipv4Addr::new(9, 9, 9, 10);
        let mut st = LinkStatus::new(NetworkType::PointToPoint);
        st.neighbors.insert(
            id,
            neighbor_info(NeighborState::Full, "fe80::2".parse().unwrap(), 4),
        );
        let (status, _rx) = watch::channel(st);
        kill_bfd_neighbor(&cfg, &status, "fe80::2".parse().unwrap());
        assert_eq!(status.borrow().neighbors[&id].state, NeighborState::Down);
        sweep_dead_neighbors(&cfg, &status);
        assert!(status.borrow().neighbors.contains_key(&id));
        tokio::time::advance(std::time::Duration::from_secs(41)).await;
        sweep_dead_neighbors(&cfg, &status);
        sweep_dead_neighbors(&cfg, &status);
        assert!(status.borrow().neighbors.is_empty());
    }

    #[tokio::test]
    async fn grace_lsa_starts_helping_only_a_full_neighbor() {
        let cfg = link("eth0.0", 10);
        let header = LsaHeader {
            age: 1,
            lsa_type: lsa::LSA_TYPE_GRACE,
            link_state_id: lsa::interface_id_key(4),
            advertising_router: Ipv4Addr::new(9, 9, 9, 10),
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        };
        let body = GraceLsaBody {
            grace_period: 60,
            restart_reason: lsa::RESTART_REASON_SOFTWARE,
        };
        let status = grace_status(None);
        on_grace_lsa(&cfg, &status, &header, body);
        assert!(in_grace(&status, header.advertising_router));

        let flushed = LsaHeader {
            age: lsa::MAX_AGE,
            ..header
        };
        on_grace_lsa(&cfg, &status, &flushed, body);
        assert!(!in_grace(&status, header.advertising_router));

        status.send_modify(|s| {
            for n in s.neighbors.values_mut() {
                n.state = NeighborState::ExStart;
            }
        });
        on_grace_lsa(&cfg, &status, &header, body);
        assert!(!in_grace(&status, header.advertising_router));
    }

    fn grace_header(age: u16) -> LsaHeader {
        LsaHeader {
            age,
            lsa_type: lsa::LSA_TYPE_GRACE,
            link_state_id: lsa::interface_id_key(4),
            advertising_router: Ipv4Addr::new(9, 9, 9, 10),
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        }
    }

    fn grace_left(status: &StatusHandle) -> Option<std::time::Duration> {
        status.borrow().neighbors[&Ipv4Addr::new(9, 9, 9, 10)]
            .grace_deadline
            .map(|d| d - Instant::now())
    }

    /// RFC 3623 §3.1: the deadline is the period minus the LSA's age, capped.
    #[tokio::test(start_paused = true)]
    async fn grace_deadline_is_remaining_grace_capped() {
        let mut cfg = link("eth0.0", 10);
        let body = |grace_period| GraceLsaBody {
            grace_period,
            restart_reason: lsa::RESTART_REASON_SOFTWARE,
        };
        let secs = |s: &StatusHandle| grace_left(s).unwrap().as_secs();
        let status = grace_status(None);
        on_grace_lsa(&cfg, &status, &grace_header(100), body(120));
        assert_eq!(secs(&status), 20, "120 - 100");
        cfg.helper_max_grace_period = 30;
        let status = grace_status(None);
        on_grace_lsa(&cfg, &status, &grace_header(0), body(u32::MAX));
        assert_eq!(secs(&status), 30, "capped");
        // Nothing left: not entered; an already-helping neighbor leaves.
        let status = grace_status(None);
        on_grace_lsa(&cfg, &status, &grace_header(120), body(120));
        assert!(!in_grace(&status, Ipv4Addr::new(9, 9, 9, 10)));
        let status = grace_status(Some(Instant::now() + std::time::Duration::from_secs(60)));
        on_grace_lsa(&cfg, &status, &grace_header(120), body(120));
        assert!(!in_grace(&status, Ipv4Addr::new(9, 9, 9, 10)));
    }

    /// RFC 3623 §3.2 item 3: anyone but the restarter changing topology ends
    /// the helped neighbor's grace.
    #[tokio::test(start_paused = true)]
    async fn topology_change_by_a_third_router_ends_grace() {
        let cfg = link("eth0.0", 10);
        let restarter = Ipv4Addr::new(9, 9, 9, 10);
        let status = grace_status(Some(Instant::now() + std::time::Duration::from_secs(60)));
        exit_grace_on_topology_change(&cfg, &status, &[restarter]);
        assert!(in_grace(&status, restarter), "its own LSAs do not count");
        exit_grace_on_topology_change(&cfg, &status, &[]);
        assert!(in_grace(&status, restarter));
        exit_grace_on_topology_change(&cfg, &status, &[restarter, Ipv4Addr::new(3, 3, 3, 3)]);
        assert!(!in_grace(&status, restarter));
        assert_eq!(state_of(&status), NeighborState::Full);
    }

    /// An in-memory multi-access wire, mirroring `ospf::link`'s: every port
    /// on the same prefix hears every multicast, a unicast reaches only its
    /// destination, and an authenticated port signs like `OspfSocket` (#131).
    pub mod wire {
        use std::collections::HashSet;
        use std::net::Ipv6Addr;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        use ipnet::Ipv6Net;
        use tokio::sync::mpsc;

        use super::super::{LinkConfig, LinkSocket, Opener};
        use crate::packet::TrailerAuth;

        type Tx = mpsc::UnboundedSender<(Ipv6Addr, Vec<u8>)>;

        /// Where a send goes on the wire.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum To {
            /// `FF02::5`: every other port on the net.
            AllSpf,
            /// `FF02::6`: only ports that joined it.
            AllD,
            Unicast(Ipv6Addr),
        }

        #[derive(Default)]
        pub struct Wire {
            ports: Mutex<Vec<(Ipv6Net, Ipv6Addr, Tx)>>,
            /// Addresses whose sends are silently dropped (a dead neighbor).
            pub cut: Mutex<HashSet<Ipv6Addr>>,
            /// Addresses whose Hellos (type byte 1) alone are dropped.
            pub drop_hellos: Mutex<HashSet<Ipv6Addr>>,
            /// Per port address: is `FF02::6` currently joined.
            pub drouters: Mutex<std::collections::HashMap<Ipv6Addr, bool>>,
            /// Makes every `FF02::6` join/leave fail.
            pub fail_drouters: std::sync::atomic::AtomicBool,
            /// Every send as (sender, destination, OSPF packet type byte).
            pub sent: Mutex<Vec<(Ipv6Addr, To, u8)>>,
            /// Sender addresses whose `FF02::6` sends fail.
            pub fail_all_d: Mutex<HashSet<Ipv6Addr>>,
        }

        impl Wire {
            pub fn opener(self: &Arc<Self>) -> Opener {
                let wire = Arc::clone(self);
                Arc::new(move |cfg: &LinkConfig, _boot: u32| {
                    // A virtual link's ports share one net, whatever their addresses.
                    let net = if cfg.virtual_link.is_some() {
                        Ipv6Net::default()
                    } else {
                        cfg.prefixes[0].trunc()
                    };
                    let (tx, rx) = mpsc::unbounded_channel();
                    let mut ports = wire.ports.lock().unwrap();
                    ports.retain(|(_, a, _)| *a != cfg.link_local_address);
                    ports.push((net, cfg.link_local_address, tx));
                    Ok(LinkSocket::Mem(Port {
                        wire: Arc::clone(&wire),
                        net,
                        addr: cfg.link_local_address,
                        auth: cfg.auth.clone(),
                        instance_id: cfg.instance_id,
                        seq: AtomicU64::new(1),
                        rx: tokio::sync::Mutex::new(rx),
                    }))
                })
            }

            /// Delivers `payload` to `to` as if `from` had sent it (a forged,
            /// unauthenticated packet).
            pub fn inject(&self, from: Ipv6Addr, to: Ipv6Addr, payload: &[u8]) {
                for (_, addr, tx) in self.ports.lock().unwrap().iter() {
                    if *addr == to {
                        let _ = tx.send((from, payload.to_vec()));
                    }
                }
            }
        }

        pub struct Port {
            wire: Arc<Wire>,
            net: Ipv6Net,
            addr: Ipv6Addr,
            auth: Option<TrailerAuth>,
            instance_id: u8,
            seq: AtomicU64,
            rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Ipv6Addr, Vec<u8>)>>,
        }

        impl Port {
            pub fn set_all_drouters(&self, want: bool) -> std::io::Result<bool> {
                if self.wire.fail_drouters.load(Ordering::Relaxed) {
                    return Err(std::io::Error::other("injected"));
                }
                let prev = self.wire.drouters.lock().unwrap().insert(self.addr, want);
                Ok(prev.unwrap_or(false) != want)
            }

            pub fn send(&self, to: To, payload: &[u8]) -> std::io::Result<()> {
                if to == To::AllD && self.wire.fail_all_d.lock().unwrap().contains(&self.addr) {
                    return Err(std::io::Error::other("injected"));
                }
                if self.wire.cut.lock().unwrap().contains(&self.addr)
                    || (payload[1] == 1
                        && self.wire.drop_hellos.lock().unwrap().contains(&self.addr))
                {
                    return Ok(());
                }
                self.wire
                    .sent
                    .lock()
                    .unwrap()
                    .push((self.addr, to, payload[1]));
                let joined = self.wire.drouters.lock().unwrap().clone();
                let mut packet = payload.to_vec();
                crate::packet::set_instance_id(&mut packet, self.instance_id);
                if let Some(auth) = &self.auth {
                    auth.sign(
                        &mut packet,
                        self.seq.fetch_add(1, Ordering::Relaxed),
                        self.addr,
                    );
                }
                for (net, addr, tx) in self.wire.ports.lock().unwrap().iter() {
                    let hears = match to {
                        To::AllSpf => true,
                        To::AllD => joined.get(addr).copied().unwrap_or(false),
                        To::Unicast(d) => d == *addr,
                    };
                    if *net == self.net && *addr != self.addr && hears {
                        let _ = tx.send((self.addr, packet.clone()));
                    }
                }
                Ok(())
            }

            pub async fn recv(&self) -> std::io::Result<(Ipv6Addr, Vec<u8>)> {
                match self.rx.lock().await.recv().await {
                    Some(m) => Ok(m),
                    None => std::future::pending().await,
                }
            }
        }
    }

    fn mem_socket(cfg: &LinkConfig) -> LinkSocket {
        Arc::new(wire::Wire::default()).opener()(cfg, 0).unwrap()
    }

    fn joined(wire: &wire::Wire, n: u8) -> bool {
        let addr: Ipv6Addr = format!("fe80::{n}").parse().unwrap();
        wire.drouters
            .lock()
            .unwrap()
            .get(&addr)
            .copied()
            .unwrap_or(false)
    }

    fn router(wire: &Arc<wire::Wire>) -> Arc<LinkManager> {
        LinkManager::with_opener(1, None, wire.opener())
    }

    fn wired_link(n: u8, network_type: NetworkType) -> LinkConfig {
        LinkConfig {
            attach_point: format!("link-{n}"),
            link_local_address: format!("fe80::{n}").parse().unwrap(),
            prefixes: vec![format!("2001:db8::{n}/64").parse().unwrap()],
            interface_id: u32::from(n),
            network_type,
            ..link("unused", 10)
        }
    }

    fn id(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(n, n, n, n)
    }

    fn loopback(n: u8) -> HashMap<Ipv4Addr, Vec<(Ipv6Net, u16)>> {
        HashMap::from([(
            Ipv4Addr::UNSPECIFIED,
            vec![(format!("2001:db8:ff::{n}/128").parse().unwrap(), 1)],
        )])
    }

    async fn settle(secs: u64) {
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
    }

    /// #952: every address of a p2p link is advertised (Link-LSA, router
    /// IAP) and routed by the peer; dropping one withdraws its route.
    #[tokio::test(start_paused = true)]
    async fn every_address_of_a_link_is_advertised_and_withdrawn() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        let nets: Vec<Ipv6Net> = ["2001:db8::1/64", "2001:db8:b::1/64"]
            .iter()
            .map(|p| p.parse().unwrap())
            .collect();
        let mut la = wired_link(1, NetworkType::PointToPoint);
        la.prefixes = nets.clone();
        a.reconcile(vec![la.clone()], HashMap::new(), id(1)).await;
        b.reconcile(
            vec![wired_link(2, NetworkType::PointToPoint)],
            HashMap::new(),
            id(2),
        )
        .await;
        settle(60).await;
        let has =
            |routes: &[spf::RouteEntry], n: Ipv6Net| routes.iter().any(|r| r.prefix == n.trunc());
        let lsdb = a.link_local_lsdb_for(&la.attach_point).await;
        let link_key = LsaKey {
            lsa_type: lsa::LSA_TYPE_LINK,
            link_state_id: lsa::interface_id_key(la.interface_id),
            advertising_router: id(1),
        };
        let got = lsdb.lock().await.get(&link_key).unwrap();
        let LsaBody::Link(body) = &got.body else {
            panic!("link lsa")
        };
        assert_eq!(
            body.prefixes.iter().map(|p| p.prefix).collect::<Vec<_>>(),
            nets
        );
        let routes = b.compute_routes().await;
        assert!(has(&routes, nets[1]), "{routes:?}");

        // The address list is part of the wholesale-diffed LinkConfig.
        la.prefixes.truncate(1);
        a.reconcile(vec![la], HashMap::new(), id(1)).await;
        settle(120).await;
        let routes = b.compute_routes().await;
        assert!(!has(&routes, nets[1]), "{routes:?}");
    }

    /// #952: the DR's Network IAP is the union of its own and every Full
    /// neighbor's Link-LSA prefixes, so a non-DR's second address is routed
    /// by a third router on the segment.
    #[tokio::test(start_paused = true)]
    async fn dr_network_iap_carries_a_neighbors_extra_prefix() {
        let wire = Arc::new(wire::Wire::default());
        let rs = [router(&wire), router(&wire), router(&wire)];
        let extra: Ipv6Net = "2001:db8:c::2/64".parse().unwrap();
        for (i, r) in rs.iter().enumerate() {
            let n = u8::try_from(i).unwrap() + 1;
            let mut l = wired_link(n, NetworkType::Broadcast);
            l.priority = if n == 1 { 10 } else { 1 };
            if n == 2 {
                l.prefixes.push(extra);
            }
            r.reconcile(vec![l], HashMap::new(), id(n)).await;
        }
        settle(90).await;
        let routes = rs[2].compute_routes().await;
        assert!(
            routes.iter().any(|r| r.prefix == extra.trunc()),
            "{routes:?}"
        );
        let dr = rs[0].lsdb_for(Ipv4Addr::UNSPECIFIED).await;
        let found = dr.lock().await.all().iter().any(|l| {
            matches!(&l.body, LsaBody::IntraAreaPrefix(b)
                if b.referenced_ls_type == lsa::LSA_TYPE_NETWORK
                    && b.prefixes.iter().any(|p| p.prefix == extra.trunc()))
        });
        assert!(found);
    }

    #[test]
    fn merge_network_prefixes_dedupes_and_skips_nu_la() {
        let e = |options, p: &str| LinkPrefixEntry {
            options,
            prefix: p.parse().unwrap(),
        };
        let out = merge_network_prefixes(&[
            (
                id(1),
                vec![e(0, "2001:db8::1/64"), e(0, "2001:db8:1::1/64")],
            ),
            (
                id(2),
                vec![
                    e(lsa::PREFIX_OPT_NU, "2001:db8:2::2/64"),
                    e(lsa::PREFIX_OPT_LA, "2001:db8:3::2/128"),
                    e(lsa::PREFIX_OPT_DN, "2001:db8::2/64"),
                ],
            ),
        ]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].prefix, "2001:db8::/64".parse().unwrap());
        assert_eq!(out[0].options, lsa::PREFIX_OPT_DN);
        assert_eq!(out[1].prefix, "2001:db8:1::/64".parse().unwrap());
    }

    /// RFC 5340 §4.4.3.9 end to end (#958): over a broadcast segment the
    /// subnet's prefix is in A's LSDB at every sample — router-referenced
    /// until the DR has a Full neighbor, then network-referenced only — and
    /// the transit link appears only once adjacent to the DR.
    #[tokio::test(start_paused = true)]
    async fn broadcast_prefix_is_never_absent_while_the_transit_link_waits() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        let mut la = wired_link(1, NetworkType::Broadcast);
        la.priority = 10; // A is the DR, so its LSDB holds both flavours
        let prefix = la.prefixes[0];
        a.reconcile(vec![la.clone()], HashMap::new(), id(1)).await;
        b.reconcile(
            vec![wired_link(2, NetworkType::Broadcast)],
            HashMap::new(),
            id(2),
        )
        .await;
        let lsdb = a.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
        let prefixes_of = |key: LsaKey| {
            let lsdb = &lsdb;
            async move {
                match lsdb.lock().await.get(&key).as_deref().map(|l| &l.body) {
                    Some(LsaBody::IntraAreaPrefix(b)) => b
                        .prefixes
                        .iter()
                        .any(|p| p.prefix.trunc() == prefix.trunc()),
                    _ => false,
                }
            }
        };
        let router_ref = LsaKey {
            lsa_type: lsa::LSA_TYPE_INTRA_AREA_PREFIX,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: id(1),
        };
        let router_lsa = LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: id(1),
            advertising_router: id(1),
        };
        let network_ref = LsaKey {
            link_state_id: lsa::interface_id_key(la.interface_id),
            ..router_ref
        };
        let (mut saw_router_ref, mut last) = (false, (false, false, false));
        for t in 0..90 {
            settle(1).await;
            let (r, n) = (
                prefixes_of(router_ref).await,
                prefixes_of(network_ref).await,
            );
            let transit = match lsdb
                .lock()
                .await
                .get(&router_lsa)
                .as_deref()
                .map(|l| &l.body)
            {
                Some(LsaBody::Router(b)) => !b.links.is_empty(),
                _ => false,
            };
            if t > 3 {
                // Never absent (a swap may briefly show both: MinLSInterval
                // holds the router IAP update back); exact complements at rest.
                assert!(r || n, "t={t} router-ref={r} network-ref={n}");
            }
            saw_router_ref |= r;
            last = (r, n, transit);
        }
        assert!(saw_router_ref);
        assert_eq!(last, (false, true, true));
    }

    async fn pair(
        wire: &Arc<wire::Wire>,
        auth_a: Option<packet::TrailerAuth>,
        auth_b: Option<packet::TrailerAuth>,
    ) -> (Arc<LinkManager>, Arc<LinkManager>) {
        let (a, b) = (router(wire), router(wire));
        let mut la = wired_link(1, NetworkType::PointToPoint);
        la.auth = auth_a;
        let mut lb = wired_link(2, NetworkType::PointToPoint);
        lb.auth = auth_b;
        a.reconcile(vec![la], HashMap::new(), id(1)).await;
        b.reconcile(vec![lb], loopback(2), id(2)).await;
        settle(60).await;
        (a, b)
    }

    fn own_lsas(lsas: &[Ospfv3LsaSummary], who: Ipv4Addr) -> usize {
        lsas.iter().filter(|l| l.advertising_router == who).count()
    }

    /// RFC 5187 restarting router (#1163): nothing is originated while it
    /// waits; the timeout (or a topology change by a third router) ends it.
    #[tokio::test(start_paused = true)]
    async fn restart_mode_holds_origination_until_timeout_or_topology_change() {
        for topology in [false, true] {
            let wire = Arc::new(wire::Wire::default());
            let b = router(&wire);
            // No neighbors to wait for: not restart mode at all.
            b.begin_restart(
                std::collections::BTreeSet::new(),
                std::time::Duration::from_secs(30),
                true,
            );
            assert!(!b.restart_active());
            b.begin_restart([id(9)].into(), std::time::Duration::from_secs(30), true);
            assert!(b.restart_active());
            b.reconcile(
                vec![wired_link(2, NetworkType::PointToPoint)],
                loopback(2),
                id(2),
            )
            .await;
            settle(20).await;
            assert!(b.restart_active());
            assert_eq!(own_lsas(&b.database_summaries().await, id(2)), 0);
            if topology {
                b.restart_tick(true).await;
            } else {
                settle(20).await;
            }
            assert!(!b.restart_active());
            settle(5).await;
            assert!(own_lsas(&b.database_summaries().await, id(2)) > 0);
        }
    }

    /// A respawn (crash marker) ends restart mode `Complete` once its
    /// pre-restart neighbor is `Full` again; the helper's grace ends with it.
    #[tokio::test(start_paused = true)]
    async fn restart_mode_ends_when_the_neighbors_are_full_again() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = pair(&wire, None, None).await;
        b.set_graceful_restart(Some(120));
        assert_eq!(b.full_neighbor_ids().await, [id(1)].into());
        // SIGKILL: no announcement, the task just vanishes.
        b.shutdown().await;
        drop(b);
        settle(5).await;

        let b2 = router(&wire);
        b2.begin_restart([id(1)].into(), std::time::Duration::from_secs(100), true);
        assert_eq!(b2.startup_grace(), Some((100, lsa::RESTART_REASON_UNKNOWN)));
        b2.reconcile(
            vec![wired_link(2, NetworkType::PointToPoint)],
            loopback(2),
            id(2),
        )
        .await;
        settle(60).await;
        assert!(!b2.restart_active());
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );
        assert!(own_lsas(&b2.database_summaries().await, id(2)) > 0);
    }

    /// The startup Grace-LSA carries the restart reason; `MaxAge` flushes it.
    #[test]
    fn grace_lsa_carries_the_restart_reason() {
        let cfg = wired_link(1, NetworkType::PointToPoint);
        for (reason, age) in [
            (lsa::RESTART_REASON_UNKNOWN, 0),
            (lsa::RESTART_REASON_SOFTWARE, lsa::MAX_AGE),
        ] {
            let payload = grace_payload(&cfg, id(1), 60, reason, age);
            let lsu = packet::decode_lsu(&payload).unwrap();
            let l = &lsu.lsas[0];
            assert_eq!(l.header.age, age);
            let LsaBody::Grace(g) = &l.body else {
                panic!("not a grace lsa")
            };
            assert_eq!((g.grace_period, g.restart_reason), (60, reason));
        }
    }

    /// RFC 4222 §2 recommendation 2 — mirrors `ospf::link`'s test.
    async fn adjacency_survives_lost_hellos(network_type: NetworkType) {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        a.reconcile(vec![wired_link(1, network_type)], loopback(1), id(1))
            .await;
        b.reconcile(vec![wired_link(2, network_type)], loopback(2), id(2))
            .await;
        settle(60).await;
        assert_eq!(
            b.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );

        let full = b.neighbor_summaries().await;
        assert_eq!(full[0].address, Some("fe80::1".parse().unwrap()));
        assert!(full[0].uptime_secs.is_some());
        assert!(full[0].dead_in_secs.is_some_and(|d| d <= 40));

        let a_addr: Ipv6Addr = "fe80::1".parse().unwrap();
        wire.drop_hellos.lock().unwrap().insert(a_addr);
        settle(3 * 40).await;
        let n = b.neighbor_summaries().await;
        assert_eq!(n[0].state, OspfNeighborState::Full, "{n:?}");

        wire.cut.lock().unwrap().insert(a_addr);
        settle(40 + 2).await;
        // Down at the 40s sweep, its entry gone a tick later (#957).
        let n = b.neighbor_summaries().await;
        assert!(
            n.iter().all(|s| s.state == OspfNeighborState::Down),
            "{n:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn point_to_point_adjacency_survives_lost_hellos() {
        adjacency_survives_lost_hellos(NetworkType::PointToPoint).await;
    }

    #[tokio::test(start_paused = true)]
    async fn broadcast_adjacency_survives_lost_hellos() {
        adjacency_survives_lost_hellos(NetworkType::Broadcast).await;
    }

    #[test]
    fn note_alive_only_refreshes_an_adjacency() {
        let peer = Ipv4Addr::new(9, 9, 9, 9);
        for (state, refreshed) in [
            (NeighborState::Down, false),
            (NeighborState::Init, false),
            (NeighborState::TwoWay, false),
            (NeighborState::ExStart, true),
            (NeighborState::Full, true),
        ] {
            let mut info = neighbor_info(state, "fe80::2".parse().unwrap(), 2);
            let past = Instant::now()
                .checked_sub(std::time::Duration::from_secs(30))
                .unwrap();
            info.last_heard = past;
            info.last_hello_received = past;
            let mut s = LinkStatus::new(NetworkType::PointToPoint);
            s.neighbors.insert(peer, info);
            let (status, _rx) = watch::channel(s);
            note_alive(&status, peer);
            let n = status.borrow().neighbors[&peer].clone();
            assert_eq!(n.last_heard > past, refreshed, "{state:?}");
            assert_eq!(n.last_hello_received, past, "{state:?}");
        }
    }

    /// #288: a Full neighbor on a link with a `bfd` profile gets a session
    /// between link-local addresses on the link's interface; BFD reporting
    /// the path down kills the neighbor at once and the next Hello restores it.
    #[tokio::test(start_paused = true)]
    async fn bfd_down_kills_a_full_neighbor_at_once() {
        let wire = Arc::new(wire::Wire::default());
        let (a, _b) = pair(&wire, None, None).await;
        let state = || async { a.neighbor_summaries().await[0].state };
        assert_eq!(state().await, OspfNeighborState::Full);
        assert!(a.target().await.is_empty(), "no profile, no session");

        a.set_bfd(HashMap::from([(
            "link-1".to_string(),
            BfdProfile::default(),
        )]));
        let want = a.target().await;
        let peer: IpAddr = "fe80::2".parse().unwrap();
        assert_eq!(want.len(), 1);
        assert_eq!(want[&peer].local, Some("fe80::1".parse().unwrap()));
        assert!(want[&peer].interface.is_some());

        a.down("fe80::9".parse().unwrap(), BfdDiag::PathDown).await;
        settle(1).await;
        assert_eq!(state().await, OspfNeighborState::Full, "stranger");
        a.down(peer, BfdDiag::ControlDetectionTimeExpired).await;
        settle(1).await;
        assert_eq!(state().await, OspfNeighborState::Down);
        assert!(a.target().await.is_empty(), "deregistered below 2-Way");
        settle(60).await;
        assert_eq!(state().await, OspfNeighborState::Full, "Hello restores it");
    }

    #[tokio::test(start_paused = true)]
    async fn point_to_point_pair_reaches_full_and_routes_to_the_far_loopback() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = pair(&wire, None, None).await;
        let n = a.neighbor_summaries().await;
        assert_eq!(n[0].state, OspfNeighborState::Full, "{n:?}");
        // `show ospfv3` (#1439): one area, one interface, one Full neighbor.
        let inst = a.instance_summary().await;
        assert_eq!(inst.areas.len(), 1, "{inst:?}");
        assert_eq!(
            (
                inst.areas[0].interface_count,
                inst.areas[0].full_neighbor_count
            ),
            (1, 1)
        );
        assert!(inst.areas[0].lsa_count >= 2, "own and B's Router-LSA");
        let routes = a.compute_routes().await;
        let r = routes
            .iter()
            .find(|r| r.prefix == "2001:db8:ff::2/128".parse::<Ipv6Net>().unwrap())
            .unwrap_or_else(|| panic!("{routes:?}"));
        assert_eq!(r.next_hop, "fe80::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(r.interface_id, 1);
        // Link-LSAs are held per link, tagged with it.
        assert!(a
            .database_summaries()
            .await
            .iter()
            .any(|l| l.link.as_deref() == Some("link-1")));

        // RFC 8362 Full mode: both switch to the extended LSA set.
        a.set_extended_lsa(true);
        b.set_extended_lsa(true);
        settle(30).await;
        assert!(a
            .database_summaries()
            .await
            .iter()
            .any(|l| l.lsa_type == lsa::LSA_TYPE_E_ROUTER && l.advertising_router == id(2)));

        // Graceful restart: B helps A through a restart without dropping it.
        a.set_graceful_restart(Some(120));
        a.announce_graceful_restart().await;
        wire.cut.lock().unwrap().insert("fe80::1".parse().unwrap());
        settle(60).await;
        assert_eq!(
            b.neighbor_summaries().await[0].state,
            OspfNeighborState::Full,
            "helper keeps the restarting neighbor"
        );
        // Past the grace period it is finally declared dead.
        settle(120).await;
        assert_eq!(
            b.neighbor_summaries().await[0].state,
            OspfNeighborState::Down
        );
        a.shutdown().await;
    }

    /// RFC 3623 §3.2 item 3 end to end: B helps restarting A, then originates
    /// a new loopback (a topology change by a third party from A's view), so
    /// the grace ends early and the dead interval, not the 120 s grace,
    /// declares A down.
    #[tokio::test(start_paused = true)]
    async fn helper_leaves_grace_when_its_own_topology_changes() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = pair(&wire, None, None).await;
        a.set_graceful_restart(Some(120));
        a.announce_graceful_restart().await;
        wire.cut.lock().unwrap().insert("fe80::1".parse().unwrap());
        let mut lo = loopback(2);
        lo.get_mut(&Ipv4Addr::UNSPECIFIED)
            .unwrap()
            .push(("2001:db8:ee::2/128".parse().unwrap(), 1));
        b.reconcile(vec![wired_link(2, NetworkType::PointToPoint)], lo, id(2))
            .await;
        settle(80).await;
        assert_eq!(
            b.neighbor_summaries().await[0].state,
            OspfNeighborState::Down
        );
        a.shutdown().await;
    }

    /// a with `peers` point-to-point links, each to its own router on its own
    /// segment; `max_links` splits a's Router-LSA. Returns (a, peers).
    async fn star(
        wire: &Arc<wire::Wire>,
        peers: u8,
        max_links: usize,
        extended: bool,
    ) -> (Arc<LinkManager>, Vec<Arc<LinkManager>>) {
        let a = router(wire);
        a.set_router_lsa_max_links(Some(max_links));
        a.set_extended_lsa(extended);
        let seg = |n: u8, k: u8| LinkConfig {
            prefixes: vec![format!("2001:db8:{k}::{n}/64").parse().unwrap()],
            ..wired_link(n, NetworkType::PointToPoint)
        };
        let mut a_links = Vec::new();
        let mut bs = Vec::new();
        for k in 1..=peers {
            // a's side uses n = 100 + k, the peer n = 10 + k.
            a_links.push(seg(100 + k, k));
            let b = router(wire);
            b.set_extended_lsa(extended);
            b.reconcile(vec![seg(10 + k, k)], loopback(10 + k), id(10 + k))
                .await;
            bs.push(b);
        }
        a.reconcile(a_links, loopback(1), id(1)).await;
        settle(60).await;
        (a, bs)
    }

    /// Link State IDs of `of`'s live Router-LSAs of `ty` advertised by `adv`.
    async fn live_router_fragments(of: &LinkManager, ty: u16, adv: Ipv4Addr) -> Vec<Ipv4Addr> {
        let mut ids: Vec<_> = of
            .database_summaries()
            .await
            .into_iter()
            .filter(|h| h.lsa_type == ty && h.advertising_router == adv && h.age < lsa::MAX_AGE)
            .map(|h| h.link_state_id)
            .collect();
        ids.sort();
        ids
    }

    /// #853: 5 links, 2 per fragment -> 3 Router-LSAs (router id, 0.0.0.1,
    /// 0.0.0.2); a peer installs all of them and routes to every far
    /// loopback; shrinking the link set ages fragments 1 and 2.
    #[tokio::test(start_paused = true)]
    async fn router_lsa_splits_into_fragments_and_surplus_is_flushed() {
        for (extended, ty) in [
            (false, lsa::LSA_TYPE_ROUTER),
            (true, lsa::LSA_TYPE_E_ROUTER),
        ] {
            let wire = Arc::new(wire::Wire::default());
            let (a, bs) = star(&wire, 5, 2, extended).await;
            let mut want = vec![id(1), Ipv4Addr::new(0, 0, 0, 1), Ipv4Addr::new(0, 0, 0, 2)];
            want.sort();
            assert_eq!(live_router_fragments(&a, ty, id(1)).await, want);
            // A peer holds every fragment and reaches every other peer's loopback.
            assert_eq!(live_router_fragments(&bs[0], ty, id(1)).await, want);
            let routes = bs[0].compute_routes().await;
            for k in 12..=15u8 {
                let p: Ipv6Net = format!("2001:db8:ff::{k}/128").parse().unwrap();
                assert!(routes.iter().any(|r| r.prefix == p), "{k}: {routes:?}");
            }

            // Down to one link: fragments 1 and 2 are flushed, 0 stays live.
            a.reconcile(
                vec![LinkConfig {
                    prefixes: vec!["2001:db8:1::101/64".parse().unwrap()],
                    ..wired_link(101, NetworkType::PointToPoint)
                }],
                loopback(1),
                id(1),
            )
            .await;
            settle(10).await;
            assert_eq!(live_router_fragments(&a, ty, id(1)).await, [id(1)]);
        }
    }

    /// The Router-LSA `of` holds for `router` in `area`, if any.
    async fn router_flags(of: &LinkManager, area: Ipv4Addr, router: Ipv4Addr) -> Option<u8> {
        let lsdb = of.lsdb_for(area).await;
        let lsdb = lsdb.lock().await;
        lsdb.all().iter().find_map(|l| match &l.body {
            LsaBody::Router(r)
                if l.header.advertising_router == router && l.header.age < lsa::MAX_AGE =>
            {
                Some(r.flags)
            }
            _ => None,
        })
    }

    /// a (area 0) — b (areas 0 and 1, an ABR) — c (area 1, an ASBR): c's
    /// loopback reaches a as an inter-area route, its redistributed prefix as
    /// an external one through b's Inter-Area-Router-LSA (the AS-External-LSA
    /// crossing areas from the AS-scope store), B/E follow the roles, and
    /// both routes go once c stops advertising them.
    #[tokio::test(start_paused = true)]
    async fn abr_and_asbr_reach_across_areas() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b, c) = (router(&wire), router(&wire), router(&wire));
        let (area0, area1) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(0, 0, 0, 1));
        let seg = |n: u8, net: u8, area_id: Ipv4Addr| LinkConfig {
            area_id,
            prefixes: vec![format!("2001:db8:{net}::{n}/64").parse().unwrap()],
            ..wired_link(n, NetworkType::PointToPoint)
        };
        let loopback: Ipv6Net = "2001:db8:ff::3/128".parse().unwrap();
        let external: Ipv6Net = "2001:db8:e::/48".parse().unwrap();
        a.reconcile(vec![seg(1, 1, area0)], HashMap::new(), id(1))
            .await;
        b.reconcile(
            vec![seg(2, 1, area0), seg(3, 2, area1)],
            HashMap::new(),
            id(2),
        )
        .await;
        let c_link = vec![seg(4, 2, area1)];
        c.reconcile(
            c_link.clone(),
            HashMap::from([(area1, vec![(loopback, 1)])]),
            id(3),
        )
        .await;
        c.apply_redistribute_update(RedistributeUpdate::Full(vec![
            nos_proto::RedistributedRoute {
                prefix: IpNet::V6(external),
                gateway: "2001:db8:2::99".parse().unwrap(),
            },
            // OSPFv3 routes IPv6 only.
            nos_proto::RedistributedRoute {
                prefix: "192.0.2.0/24".parse().unwrap(),
                gateway: "10.0.0.1".parse().unwrap(),
            },
        ]))
        .await;
        settle(60).await;

        let routes = a.compute_routes().await;
        let route = |p: Ipv6Net| routes.iter().find(|r| r.prefix == p);
        let inter = route(loopback).unwrap_or_else(|| panic!("{routes:?}"));
        assert_eq!(inter.next_hop, "fe80::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(inter.metric, 3);
        let ext = route(external).unwrap_or_else(|| panic!("{routes:?}"));
        assert_eq!(ext.metric, 2 + spf::EXTERNAL_METRIC);
        assert_eq!(
            routes.len(),
            3,
            "the b–c link, the loopback, the external: {routes:?}"
        );
        assert_eq!(
            router_flags(&a, area0, id(2)).await,
            Some(lsa::ROUTER_FLAG_B)
        );
        assert_eq!(
            router_flags(&b, area1, id(3)).await,
            Some(lsa::ROUTER_FLAG_E)
        );
        assert_eq!(router_flags(&a, area0, id(1)).await, Some(0));
        let db = a.database_summaries().await;
        assert!(db.iter().any(|l| l.lsa_type == lsa::LSA_TYPE_AS_EXTERNAL
            && l.advertising_router == id(3)
            && l.area_id == area0
            && l.link.is_none()));
        assert!(db
            .iter()
            .any(|l| l.lsa_type == lsa::LSA_TYPE_INTER_AREA_ROUTER
                && l.advertising_router == id(2)
                && l.link_state_id == id(3)));

        c.reconcile(c_link, HashMap::new(), id(3)).await;
        c.apply_redistribute_update(RedistributeUpdate::Full(Vec::new()))
            .await;
        settle(30).await;
        let routes = a.compute_routes().await;
        assert!(
            routes
                .iter()
                .all(|r| r.prefix != loopback && r.prefix != external),
            "{routes:?}"
        );
        assert_eq!(router_flags(&b, area1, id(3)).await, Some(0));
    }

    // --- RFC 5340 §4.7 virtual links (#1158) ---

    fn vlink_config(endpoint: Ipv4Addr) -> VirtualLinkConfig {
        VirtualLinkConfig {
            transit_area: Ipv4Addr::new(0, 0, 0, 1),
            endpoint,
            hello_interval: 10,
            dead_interval: 40,
            auth: None,
        }
    }

    fn virtual_cfg(neighbor: &str) -> LinkConfig {
        LinkConfig {
            area_id: Ipv4Addr::UNSPECIFIED,
            cost: 7,
            virtual_link: Some(VirtualLinkEnd {
                transit_area: Ipv4Addr::new(0, 0, 0, 1),
                endpoint: id(3),
                neighbor: neighbor.parse().unwrap(),
            }),
            ..link("vlink", 10)
        }
    }

    /// A virtual link takes packets from its endpoint's global address only;
    /// every other link only from link-local ones.
    #[test]
    fn virtual_link_accepts_only_its_neighbor_address() {
        let cfg = virtual_cfg("2001:db8:ff::3");
        assert!(!drops_non_link_local(
            &cfg,
            "2001:db8:ff::3".parse().unwrap()
        ));
        assert!(drops_non_link_local(
            &cfg,
            "2001:db8:ff::4".parse().unwrap()
        ));
        assert!(drops_non_link_local(&cfg, "fe80::3".parse().unwrap()));
        assert!(drops_non_link_local(
            &link("eth0", 10),
            "2001:db8:ff::3".parse().unwrap()
        ));
    }

    /// A cost change keeps the link running; a new neighbor address restarts it.
    #[test]
    fn diff_ignores_cost_but_not_the_virtual_neighbor() {
        let running = virtual_cfg("2001:db8:ff::3");
        let current = HashMap::from([("vlink".to_string(), running.clone())]);
        let cheaper = LinkConfig {
            cost: 3,
            ..running.clone()
        };
        let (stop, spawn) = diff_links(&current, &HashMap::from([("vlink".to_string(), cheaper)]));
        assert_eq!((stop.len(), spawn.len()), (0, 0));
        let moved = virtual_cfg("2001:db8:ff::9");
        let (stop, spawn) = diff_links(&current, &HashMap::from([("vlink".to_string(), moved)]));
        assert_eq!((stop.len(), spawn.len()), (1, 1));
    }

    /// RFC 5340 §A.4.3: a type-4 link only while the virtual neighbor is Full.
    #[test]
    fn router_lsa_links_virtual_link_only_when_full() {
        let cfg = virtual_cfg("2001:db8:ff::3");
        let mut status = LinkStatus::new(NetworkType::PointToPoint);
        status.neighbors.insert(
            id(3),
            neighbor_info(NeighborState::Loading, "2001:db8:ff::3".parse().unwrap(), 9),
        );
        let links =
            |status: &LinkStatus| router_lsa_links(id(2), &[(cfg.clone(), status.clone())], false);
        assert_eq!(links(&status), []);
        status.neighbors.get_mut(&id(3)).unwrap().state = NeighborState::Full;
        assert_eq!(
            links(&status),
            [RouterLsaLink {
                link_type: LINK_TYPE_VIRTUAL,
                metric: 7,
                interface_id: 3,
                neighbor_interface_id: 9,
                neighbor_router_id: id(3),
            }]
        );
    }

    /// §4.7: up at the path's cost with the endpoint's LA address and our own
    /// loopback as source; down without a path, a loopback of ours or a
    /// transit-area link.
    #[tokio::test(start_paused = true)]
    async fn resolve_virtual_link_up_and_down() {
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let wire = Arc::new(wire::Wire::default());
        let (b, c) = (router(&wire), router(&wire));
        let seg = |n: u8| LinkConfig {
            area_id: area1,
            prefixes: vec![format!("2001:db8:2::{n}/64").parse().unwrap()],
            ..wired_link(n, NetworkType::PointToPoint)
        };
        let lo = |n: u8| {
            HashMap::from([(
                area1,
                vec![(format!("2001:db8:ff::{n}/128").parse().unwrap(), 1)],
            )])
        };
        b.reconcile(vec![seg(3)], lo(2), id(2)).await;
        c.reconcile(vec![seg(4)], lo(3), id(3)).await;
        settle(60).await;
        let lsas = b.lsdb_for(area1).await.lock().await.all();
        let physical = [seg(3)];
        let own = [("2001:db8:ff::2/128".parse::<Ipv6Net>().unwrap(), 1)];
        let up = resolve_virtual_link(&vlink_config(id(3)), id(2), &lsas, &physical, &own)
            .expect("endpoint reachable");
        assert_eq!(up.attach_point, "vlink-0.0.0.1-3.3.3.3");
        assert_eq!(up.area_id, Ipv4Addr::UNSPECIFIED);
        assert_eq!(up.cost, 1);
        assert_eq!(
            up.link_local_address,
            "2001:db8:ff::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            up.virtual_link.map(|v| v.neighbor),
            Some("2001:db8:ff::3".parse().unwrap())
        );
        assert_eq!(up.vrf, up.kernel_interface);
        assert!(up.mtu_ignore);
        // No such endpoint, no loopback of ours, no link in the transit area.
        assert!(
            resolve_virtual_link(&vlink_config(id(7)), id(2), &lsas, &physical, &own).is_none()
        );
        assert!(resolve_virtual_link(&vlink_config(id(3)), id(2), &lsas, &physical, &[]).is_none());
        assert!(resolve_virtual_link(&vlink_config(id(3)), id(2), &lsas, &[], &own).is_none());
    }

    /// RFC 5340 §4.7 over the in-memory wire: a (area 0) - b (areas 0 and 1)
    /// - c (area 1 only), loopbacks in area 1 for the endpoint addresses. The
    /// virtual link b-c comes up from area 1's SPF, reaches Full, puts a
    /// type-4 link in both area-0 Router-LSAs (seen at a) and V in both
    /// area-1 ones, and goes (type-4 link and V) when c drops its end.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::too_many_lines)]
    async fn virtual_link_reaches_full_with_v_bit_and_type_4_link() {
        let area1 = Ipv4Addr::new(0, 0, 0, 1);
        let wire = Arc::new(wire::Wire::default());
        let (a, b, c) = (router(&wire), router(&wire), router(&wire));
        let seg = |n: u8, net: u8, area_id: Ipv4Addr| LinkConfig {
            area_id,
            prefixes: vec![format!("2001:db8:{net}::{n}/64").parse().unwrap()],
            ..wired_link(n, NetworkType::PointToPoint)
        };
        let lo = |n: u8| {
            HashMap::from([(
                area1,
                vec![(format!("2001:db8:ff::{n}/128").parse().unwrap(), 1)],
            )])
        };
        a.reconcile(
            vec![seg(1, 1, Ipv4Addr::UNSPECIFIED)],
            HashMap::new(),
            id(1),
        )
        .await;
        b.set_virtual_links(vec![vlink_config(id(3))]).await;
        b.reconcile(
            vec![seg(2, 1, Ipv4Addr::UNSPECIFIED), seg(3, 2, area1)],
            lo(2),
            id(2),
        )
        .await;
        c.set_virtual_links(vec![vlink_config(id(2))]).await;
        c.reconcile(vec![seg(4, 2, area1)], lo(3), id(3)).await;
        settle(120).await;

        let vlink_state = |m: Arc<LinkManager>, name: &'static str| async move {
            m.neighbor_summaries()
                .await
                .into_iter()
                .find(|n| n.link == name)
                .map(|n| (n.area_id, n.state))
        };
        assert_eq!(
            vlink_state(Arc::clone(&b), "vlink-0.0.0.1-3.3.3.3").await,
            Some((Ipv4Addr::UNSPECIFIED, OspfNeighborState::Full))
        );
        assert_eq!(
            vlink_state(Arc::clone(&c), "vlink-0.0.0.1-2.2.2.2").await,
            Some((Ipv4Addr::UNSPECIFIED, OspfNeighborState::Full))
        );
        let at_a = |router: Ipv4Addr| {
            let a = Arc::clone(&a);
            async move {
                a.database_summaries().await.into_iter().find(|l| {
                    l.area_id.is_unspecified()
                        && l.lsa_type == lsa::LSA_TYPE_ROUTER
                        && l.advertising_router == router
                })
            }
        };
        assert_eq!(at_a(id(2)).await.unwrap().virtual_links, [id(3)]);
        assert_eq!(at_a(id(3)).await.unwrap().virtual_links, [id(2)]);
        for (m, router) in [(&b, id(2)), (&c, id(3))] {
            let flags = router_flags(m, area1, router).await.unwrap();
            assert_ne!(flags & lsa::ROUTER_FLAG_V, 0, "{router}");
        }
        // The backbone-less end is an ABR through its virtual link.
        assert_ne!(
            router_flags(&a, Ipv4Addr::UNSPECIFIED, id(3))
                .await
                .unwrap()
                & lsa::ROUTER_FLAG_B,
            0
        );

        // #1159, §16.1: c, attached to area 1 only, routes the backbone
        // (a-b's segment) through the virtual link, with b's transit next hop.
        let backbone_net: Ipv6Net = "2001:db8:1::/64".parse().unwrap();
        let route = |m: Arc<LinkManager>| async move {
            m.compute_routes()
                .await
                .into_iter()
                .find(|r| r.prefix == backbone_net)
        };
        let via = route(Arc::clone(&c)).await.expect("backbone route at c");
        assert_eq!(via.class, spf::PathClass::Intra);
        assert_eq!(via.next_hops.len(), 1);

        // c drops its end: b's virtual neighbor dies, V and the type-4 link go,
        // and c falls back to the area-1 summary (inter-area, not the backbone).
        c.set_virtual_links(Vec::new()).await;
        settle(120).await;
        let after = route(Arc::clone(&c)).await.expect("summary route at c");
        assert_eq!(after.class, spf::PathClass::Inter);
        let flags = router_flags(&b, area1, id(2)).await.unwrap();
        assert_eq!(flags & lsa::ROUTER_FLAG_V, 0);
        assert_eq!(
            at_a(id(2)).await.unwrap().virtual_links,
            Vec::<Ipv4Addr>::new()
        );
    }

    /// RFC 3101 (#1156) over the in-memory wire: a (area 0) — b (ABR) — c
    /// (NSSA area 1, ASBR). c's redistributed prefix is an NSSA-LSA with the
    /// P-bit and a forwarding address; b, the only ABR, translates it into
    /// its own AS-External-LSA that a routes (via b, with b's E-bit set);
    /// the AS-External-LSA never enters the NSSA, and both go when c stops
    /// redistributing.
    #[tokio::test(start_paused = true)]
    async fn nssa_lsa_is_translated_into_the_backbone() {
        nssa_translation(false).await;
    }

    /// The same with RFC 8362 full mode on every router (#1157): E-NSSA-LSA
    /// `0xA027` translated into an E-AS-External-LSA `0xC025`.
    #[tokio::test(start_paused = true)]
    async fn e_nssa_lsa_is_translated_into_the_backbone() {
        nssa_translation(true).await;
    }

    #[allow(clippy::too_many_lines)]
    async fn nssa_translation(extended: bool) {
        let (t7, t5) = if extended {
            (lsa::LSA_TYPE_E_NSSA, lsa::LSA_TYPE_E_AS_EXTERNAL)
        } else {
            (lsa::LSA_TYPE_NSSA, lsa::LSA_TYPE_AS_EXTERNAL)
        };
        let wire = Arc::new(wire::Wire::default());
        let (a, b, c) = (router(&wire), router(&wire), router(&wire));
        for r in [&a, &b, &c] {
            r.set_extended_lsa(extended);
        }
        let (area0, area1) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(0, 0, 0, 1));
        for r in [&b, &c] {
            r.set_stub_areas(HashMap::from([(area1, (true, 1))]));
            r.set_nssa_areas(HashMap::from([(area1, NssaSettings::default())]));
        }
        let seg = |n: u8, net: u8, area_id: Ipv4Addr| LinkConfig {
            area_id,
            stub: area_id == area1,
            nssa: area_id == area1,
            prefixes: vec![format!("2001:db8:{net}::{n}/64").parse().unwrap()],
            ..wired_link(n, NetworkType::PointToPoint)
        };
        let external: Ipv6Net = "2001:db8:e::/48".parse().unwrap();
        a.reconcile(vec![seg(1, 1, area0)], HashMap::new(), id(1))
            .await;
        b.reconcile(
            vec![seg(2, 1, area0), seg(3, 2, area1)],
            HashMap::new(),
            id(2),
        )
        .await;
        let c_link = vec![seg(4, 2, area1)];
        c.reconcile(c_link.clone(), HashMap::new(), id(3)).await;
        let redistribute = |routes: Vec<Ipv6Net>| {
            RedistributeUpdate::Full(
                routes
                    .into_iter()
                    .map(|p| nos_proto::RedistributedRoute {
                        prefix: IpNet::V6(p),
                        gateway: "2001:db8:2::99".parse().unwrap(),
                    })
                    .collect(),
            )
        };
        c.apply_redistribute_update(redistribute(vec![external]))
            .await;
        settle(60).await;

        let held = |db: Vec<Ospfv3LsaSummary>, lsa_type, adv| {
            db.iter()
                .filter(|l| l.lsa_type == lsa_type && l.advertising_router == adv)
                .filter(|l| l.age < lsa::MAX_AGE)
                .count()
        };
        // The backbone holds b's translation, no NSSA-LSA; the NSSA holds
        // c's NSSA-LSA and no AS-External-LSA.
        let db_a = a.database_summaries().await;
        assert_eq!(held(db_a.clone(), t5, id(2)), 1);
        assert_eq!(held(db_a.clone(), t5, id(3)), 0);
        assert_eq!(held(db_a, t7, id(3)), 0);
        let db_c = c.database_summaries().await;
        assert_eq!(held(db_c.clone(), t7, id(3)), 1);
        assert_eq!(held(db_c, t5, id(2)), 0);
        let type7 = b
            .lsdb_for(area1)
            .await
            .lock()
            .await
            .all()
            .into_iter()
            .find(|l| l.header.lsa_type == t7 && l.header.age < lsa::MAX_AGE)
            .expect("NSSA-LSA on b");
        let LsaBody::AsExternal(body) = &type7.body else {
            panic!("expected an external body")
        };
        assert_eq!(body.prefix_options, lsa::PREFIX_OPT_P);
        assert_eq!(
            body.forwarding_address,
            Some("2001:db8:2::4".parse().unwrap())
        );
        // a routes it through b; b routes it from the NSSA-LSA.
        let route = a
            .compute_routes()
            .await
            .into_iter()
            .find(|r| r.prefix == external)
            .expect("translated route on a");
        assert_eq!(route.next_hop, "fe80::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(route.class, spf::PathClass::External1);
        assert!(b
            .compute_routes()
            .await
            .iter()
            .any(|r| r.prefix == external));
        assert_eq!(
            router_flags(&a, area0, id(2)).await,
            Some(lsa::ROUTER_FLAG_B | lsa::ROUTER_FLAG_E)
        );
        assert_eq!(
            router_flags(&b, area1, id(3)).await,
            Some(lsa::ROUTER_FLAG_E)
        );

        // c stops redistributing: its NSSA-LSA is flushed and the route goes.
        c.apply_redistribute_update(redistribute(Vec::new())).await;
        settle(30).await;
        assert_eq!(held(c.database_summaries().await, t7, id(3)), 0);
        assert!(a
            .compute_routes()
            .await
            .iter()
            .all(|r| r.prefix != external));
    }

    /// RFC 3101 §2.1: the N-bit must match the link's NSSA-ness, with the
    /// E-bit clear in an NSSA.
    #[test]
    fn nssa_options_carry_the_n_bit_and_no_e_bit() {
        for (stub, nssa) in [(false, false), (true, false), (true, true)] {
            let o = own_options(stub, nssa, false);
            assert_eq!(o & lsa::OPTION_N != 0, nssa);
            assert_eq!(o & lsa::OPTION_E != 0, !stub);
            assert_ne!(o & lsa::OPTION_V6, 0);
        }
    }

    /// RFC 5340 §4.4.3: a (area 0, ASBR) — b (ABR) — c (area 1, stub). c
    /// learns the default (b's `stub_default_cost`) and a's loopback but no
    /// external; totally stubby it learns the default only. A stub/normal
    /// E-bit mismatch keeps the adjacency down.
    #[tokio::test(start_paused = true)]
    async fn stub_area_gets_default_and_no_externals() {
        let (area0, area1) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(0, 0, 0, 1));
        let loopback: Ipv6Net = "2001:db8:ff::1/128".parse().unwrap();
        let external: Ipv6Net = "2001:db8:e::/48".parse().unwrap();
        let default = Ipv6Net::default();
        let ext_update = RedistributeUpdate::Full(vec![nos_proto::RedistributedRoute {
            prefix: IpNet::V6(external),
            gateway: "2001:db8:1::99".parse().unwrap(),
        }]);
        for (import, c_stub) in [(true, true), (false, true), (true, false)] {
            let wire = Arc::new(wire::Wire::default());
            let (a, b, c) = (router(&wire), router(&wire), router(&wire));
            let seg = |n: u8, net: u8, area_id: Ipv4Addr, stub: bool| LinkConfig {
                area_id,
                stub,
                prefixes: vec![format!("2001:db8:{net}::{n}/64").parse().unwrap()],
                ..wired_link(n, NetworkType::PointToPoint)
            };
            a.reconcile(
                vec![seg(1, 1, area0, false)],
                HashMap::from([(area0, vec![(loopback, 1)])]),
                id(1),
            )
            .await;
            a.apply_redistribute_update(ext_update.clone()).await;
            for m in [&b, &c] {
                m.set_stub_areas(HashMap::from([(area1, (import, 7))]));
            }
            b.reconcile(
                vec![seg(2, 1, area0, false), seg(3, 2, area1, true)],
                HashMap::new(),
                id(2),
            )
            .await;
            c.reconcile(vec![seg(4, 2, area1, c_stub)], HashMap::new(), id(3))
                .await;
            settle(90).await;

            let routes = c.compute_routes().await;
            let has = |p: Ipv6Net| routes.iter().any(|r| r.prefix == p);
            if !c_stub {
                assert!(routes.is_empty(), "e-bit mismatch: {routes:?}");
                continue;
            }
            let d = routes
                .iter()
                .find(|r| r.prefix == default)
                .unwrap_or_else(|| panic!("{routes:?}"));
            assert_eq!(d.metric, 8, "link cost 1 + stub-default-cost 7");
            assert!(!has(external), "{routes:?}");
            assert_eq!(has(loopback), import, "{routes:?}");
            // The stub area's databases hold no AS-scope LSA at all.
            let db = c.database_summaries().await;
            assert!(db.iter().all(|l| !lsa::is_as_scope(l.lsa_type)), "{db:?}");
            // Back to a normal area: the default goes, the external arrives.
            for m in [&b, &c] {
                m.set_stub_areas(HashMap::new());
            }
            b.reconcile(
                vec![seg(2, 1, area0, false), seg(3, 2, area1, false)],
                HashMap::new(),
                id(2),
            )
            .await;
            c.reconcile(vec![seg(4, 2, area1, false)], HashMap::new(), id(3))
                .await;
            settle(90).await;
            let routes = c.compute_routes().await;
            assert!(routes.iter().any(|r| r.prefix == external), "{routes:?}");
            assert!(routes.iter().all(|r| r.prefix != default), "{routes:?}");
        }
    }

    /// #610: a (area 1, ASBR) — b (ABR) — c (ABR, area 0 between) — d
    /// (area 2): c passes b's backbone Inter-Area-Prefix/Router-LSAs on into
    /// area 2, so d routes to a's loopback and external prefix; a router in
    /// two non-backbone areas is no ABR.
    #[tokio::test(start_paused = true)]
    async fn abr_resummarizes_backbone_inter_area_routes() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b, c, d) = (router(&wire), router(&wire), router(&wire), router(&wire));
        let (area0, area1, area2) = (
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(0, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 2),
        );
        let seg = |n: u8, net: u8, area_id: Ipv4Addr| LinkConfig {
            area_id,
            prefixes: vec![format!("2001:db8:{net}::{n}/64").parse().unwrap()],
            ..wired_link(n, NetworkType::PointToPoint)
        };
        let loopback: Ipv6Net = "2001:db8:ff::1/128".parse().unwrap();
        let external: Ipv6Net = "2001:db8:e::/48".parse().unwrap();
        a.reconcile(
            vec![seg(1, 1, area1)],
            HashMap::from([(area1, vec![(loopback, 1)])]),
            id(1),
        )
        .await;
        a.apply_redistribute_update(RedistributeUpdate::Full(vec![
            nos_proto::RedistributedRoute {
                prefix: IpNet::V6(external),
                gateway: "2001:db8:1::99".parse().unwrap(),
            },
        ]))
        .await;
        b.reconcile(
            vec![seg(2, 1, area1), seg(3, 2, area0)],
            HashMap::new(),
            id(2),
        )
        .await;
        c.reconcile(
            vec![seg(4, 2, area0), seg(5, 3, area2)],
            HashMap::new(),
            id(3),
        )
        .await;
        d.reconcile(vec![seg(6, 3, area2)], HashMap::new(), id(4))
            .await;
        settle(90).await;

        let routes = d.compute_routes().await;
        let route = |p: Ipv6Net| routes.iter().find(|r| r.prefix == p);
        let inter = route(loopback).unwrap_or_else(|| panic!("{routes:?}"));
        assert_eq!(inter.next_hop, "fe80::5".parse::<Ipv6Addr>().unwrap());
        assert!(route(external).is_some(), "{routes:?}");
        let db = d.database_summaries().await;
        assert!(db
            .iter()
            .any(|l| l.lsa_type == lsa::LSA_TYPE_INTER_AREA_ROUTER
                && l.advertising_router == id(3)
                && l.link_state_id == id(1)));

        a.reconcile(vec![seg(1, 1, area1)], HashMap::new(), id(1))
            .await;
        a.apply_redistribute_update(RedistributeUpdate::Full(Vec::new()))
            .await;
        settle(60).await;
        let routes = d.compute_routes().await;
        assert!(
            routes
                .iter()
                .all(|r| r.prefix != loopback && r.prefix != external),
            "{routes:?}"
        );
    }

    /// #610: two non-backbone areas and no backbone: no B-bit, no summaries.
    #[tokio::test(start_paused = true)]
    async fn router_in_two_non_backbone_areas_is_no_abr() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        let (area1, area2) = (Ipv4Addr::new(0, 0, 0, 1), Ipv4Addr::new(0, 0, 0, 2));
        let seg = |n: u8, net: u8, area_id: Ipv4Addr| LinkConfig {
            area_id,
            prefixes: vec![format!("2001:db8:{net}::{n}/64").parse().unwrap()],
            ..wired_link(n, NetworkType::PointToPoint)
        };
        a.reconcile(
            vec![seg(1, 1, area1), seg(2, 2, area2)],
            HashMap::new(),
            id(1),
        )
        .await;
        b.reconcile(vec![seg(3, 1, area1)], HashMap::new(), id(2))
            .await;
        settle(60).await;
        assert_eq!(router_flags(&b, area1, id(1)).await, Some(0));
        assert!(b
            .database_summaries()
            .await
            .iter()
            .all(|l| l.lsa_type != lsa::LSA_TYPE_INTER_AREA_PREFIX));
    }

    fn trailer(key: &[u8]) -> packet::TrailerAuth {
        packet::TrailerAuth {
            keys: vec![(300, packet::CryptoAlgorithm::HmacSha256, key.to_vec())],
            current_key_id: 300,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn matching_trailer_auth_reaches_full_and_a_mismatch_never_does() {
        let wire = Arc::new(wire::Wire::default());
        let (a, _b) = pair(&wire, Some(trailer(b"k")), Some(trailer(b"k"))).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );
        let wire = Arc::new(wire::Wire::default());
        let (a, _b) = pair(&wire, Some(trailer(b"k")), Some(trailer(b"other"))).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Down
        );
        let wire = Arc::new(wire::Wire::default());
        let (a, _b) = pair(&wire, Some(trailer(b"k")), None).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Down
        );
    }

    #[tokio::test(start_paused = true)]
    async fn instance_id_must_match_to_reach_full() {
        for (ia, ib, want) in [
            (5, 5, OspfNeighborState::Full),
            (1, 0, OspfNeighborState::Down),
        ] {
            let wire = Arc::new(wire::Wire::default());
            let (a, b) = (router(&wire), router(&wire));
            let mut la = wired_link(1, NetworkType::PointToPoint);
            la.instance_id = ia;
            let mut lb = wired_link(2, NetworkType::PointToPoint);
            lb.instance_id = ib;
            a.reconcile(vec![la], HashMap::new(), id(1)).await;
            b.reconcile(vec![lb], loopback(2), id(2)).await;
            settle(60).await;
            assert_eq!(a.neighbor_summaries().await[0].state, want, "{ia}/{ib}");
        }
    }

    /// RFC 5838: an IPv4-unicast link needs the AF-bit on the other side too;
    /// an IPv6-AF side accepts either, but then never sees itself listed.
    #[tokio::test(start_paused = true)]
    async fn af_bit_must_match_on_an_ipv4_link() {
        for (a_af, b_af, want) in [
            (true, true, OspfNeighborState::Full),
            (true, false, OspfNeighborState::Down),
            (false, true, OspfNeighborState::Init),
            (false, false, OspfNeighborState::Full),
        ] {
            let wire = Arc::new(wire::Wire::default());
            let (a, b) = (router(&wire), router(&wire));
            let id_of = |af: bool| if af { 64 } else { 0 };
            let mut la = wired_link(1, NetworkType::PointToPoint);
            (la.ipv4_af, la.instance_id) = (a_af, id_of(a_af));
            let mut lb = wired_link(2, NetworkType::PointToPoint);
            (lb.ipv4_af, lb.instance_id) = (b_af, id_of(a_af));
            a.reconcile(vec![la], HashMap::new(), id(1)).await;
            b.reconcile(vec![lb], loopback(2), id(2)).await;
            settle(60).await;
            assert_eq!(a.neighbor_summaries().await[0].state, want, "{a_af}/{b_af}");
        }
    }

    /// Two instances (IPv6 id 0, IPv4 id 64) on one wire each reach Full with
    /// their own peer only.
    #[tokio::test(start_paused = true)]
    async fn two_instances_share_one_wire() {
        let wire = Arc::new(wire::Wire::default());
        let rs: Vec<_> = (0..4).map(|_| router(&wire)).collect();
        for (n, r) in rs.iter().enumerate() {
            let n = u8::try_from(n).unwrap() + 1;
            let mut l = wired_link(n, NetworkType::PointToPoint);
            if n > 2 {
                (l.ipv4_af, l.instance_id) = (true, 64);
            }
            r.reconcile(vec![l], loopback(n), id(n)).await;
        }
        settle(60).await;
        for r in &rs {
            let s = r.neighbor_summaries().await;
            assert_eq!(s.len(), 1, "only its own instance's peer");
            assert_eq!(s[0].state, OspfNeighborState::Full);
        }
    }

    /// #854: `FF02::6` is joined exactly while DR/Backup, idempotently, and a
    /// failed update is retried on the next pass.
    #[test]
    fn all_drouters_follows_the_election_role() {
        let wire = Arc::new(wire::Wire::default());
        let mut cfg = wired_link(1, NetworkType::Broadcast);
        let socket = wire.opener()(&cfg, 0).unwrap();
        let me = id(1);
        let status = watch::channel(LinkStatus::new(NetworkType::Broadcast)).0;

        wire.fail_drouters.store(true, Ordering::Relaxed);
        run_election(&socket, &cfg, me, &status);
        assert_eq!(status.borrow().interface_state, InterfaceState::Dr);
        assert!(!joined(&wire, 1), "failed join leaves it not joined");
        wire.fail_drouters.store(false, Ordering::Relaxed);
        run_election(&socket, &cfg, me, &status);
        assert!(joined(&wire, 1), "retried on the next pass");
        assert!(!socket.set_all_drouters(1, true).unwrap(), "idempotent");

        // Two higher-priority neighbours take DR and BDR: demoted, left.
        for (n, declares_dr) in [(2u8, true), (3, false)] {
            let mut info = neighbor_info(
                NeighborState::TwoWay,
                format!("fe80::{n}").parse().unwrap(),
                4,
            );
            info.priority = 100 + n;
            info.declared_dr = if declares_dr {
                id(n)
            } else {
                Ipv4Addr::UNSPECIFIED
            };
            info.declared_bdr = if declares_dr {
                Ipv4Addr::UNSPECIFIED
            } else {
                id(n)
            };
            status.send_modify(|s| {
                s.neighbors.insert(id(n), info);
            });
        }
        run_election(&socket, &cfg, me, &status);
        assert_eq!(status.borrow().interface_state, InterfaceState::DrOther);
        assert!(!joined(&wire, 1));

        // Never on point-to-point, whatever the role.
        cfg.network_type = NetworkType::PointToPoint;
        let p2p = Arc::new(wire::Wire::default());
        let socket = p2p.opener()(&cfg, 0).unwrap();
        let status = watch::channel(LinkStatus::new(NetworkType::PointToPoint)).0;
        run_election(&socket, &cfg, me, &status);
        assert_eq!(status.borrow().interface_state, InterfaceState::Dr);
        assert!(!joined(&p2p, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn broadcast_segment_elects_dr_and_bdr() {
        let wire = Arc::new(wire::Wire::default());
        let segment: Vec<_> = (1..=4).map(|_| router(&wire)).collect();
        for (i, r) in segment.iter().enumerate() {
            let n = u8::try_from(i + 1).unwrap();
            r.reconcile(
                vec![wired_link(n, NetworkType::Broadcast)],
                loopback(n),
                id(n),
            )
            .await;
        }
        settle(120).await;
        // Only the DR (4) and BDR (3) listen on FF02::6.
        assert_eq!(
            [1, 2, 3, 4].map(|n| joined(&wire, n)),
            [false, false, true, true]
        );
        let ifs = segment[0].interface_summaries().await;
        assert_eq!(ifs.len(), 1, "{ifs:?}");
        assert_eq!((ifs[0].dr, ifs[0].bdr), (Some(id(4)), Some(id(3))));
        assert_eq!((ifs[0].neighbor_count, ifs[0].full_neighbor_count), (3, 2));
        assert!(ifs[0].address.to_string().starts_with("fe80::"), "{ifs:?}");
        assert!(!ifs[0].prefixes.is_empty(), "{ifs:?}");
        let one = segment[0].neighbor_summaries().await;
        assert_eq!(one.len(), 3, "{one:?}");
        for n in &one {
            assert_eq!((n.dr, n.bdr), (Some(id(4)), Some(id(3))));
            let want = if n.neighbor_router_id == Some(id(2)) {
                OspfNeighborState::TwoWay
            } else {
                OspfNeighborState::Full
            };
            assert_eq!(n.state, want, "{n:?}");
        }
        let routes = segment[0].compute_routes().await;
        assert!(
            routes
                .iter()
                .any(|r| r.prefix == "2001:db8:ff::4/128".parse::<Ipv6Net>().unwrap()),
            "{routes:?}"
        );
        // A DR-other dying is swept off the segment (Down, then removed, #957).
        wire.cut.lock().unwrap().insert("fe80::2".parse().unwrap());
        settle(60).await;
        let one = segment[0].neighbor_summaries().await;
        assert!(
            one.iter().all(|n| n.neighbor_router_id != Some(id(2))),
            "{one:?}"
        );
    }

    /// #157: a DR that loses its only `Full` neighbor flushes its Network-LSA
    /// and the IAP referencing it, and keeps its Router-LSA.
    #[tokio::test(start_paused = true)]
    async fn dr_losing_its_last_full_neighbor_flushes_its_network_lsa() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = (router(&wire), router(&wire));
        a.reconcile(
            vec![wired_link(1, NetworkType::Broadcast)],
            loopback(1),
            id(1),
        )
        .await;
        let lb = wired_link(2, NetworkType::Broadcast);
        b.reconcile(vec![lb.clone()], loopback(2), id(2)).await;
        settle(120).await;
        let network_key = lsa::interface_id_key(lb.interface_id);
        let ages = || async {
            let area = b.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
            let area = area.lock().await;
            [
                age_of(&area, lsa::LSA_TYPE_NETWORK, network_key, id(2)),
                age_of(&area, lsa::LSA_TYPE_INTRA_AREA_PREFIX, network_key, id(2)),
                age_of(&area, lsa::LSA_TYPE_ROUTER, id(2), id(2)),
            ]
        };
        for age in ages().await {
            assert!(age.unwrap() < lsa::MAX_AGE, "live while Full");
        }

        wire.cut.lock().unwrap().insert("fe80::1".parse().unwrap());
        settle(43).await;
        let [network, iap, router] = ages().await;
        // Flushed, and maybe already evicted after its MaxAge hold.
        assert!(network.is_none_or(|a| a == lsa::MAX_AGE), "{network:?}");
        assert!(iap.is_none_or(|a| a == lsa::MAX_AGE), "{iap:?}");
        assert!(router.unwrap() < lsa::MAX_AGE);
    }

    #[tokio::test(start_paused = true)]
    async fn tiny_dbd_budget_still_reaches_full() {
        let wire = Arc::new(wire::Wire::default());
        let mk = || LinkManager::with_opener(1, Some(1), wire.opener());
        let (a, b) = (mk(), mk());
        let many = |n: u8| {
            HashMap::from([(
                Ipv4Addr::UNSPECIFIED,
                (0..3)
                    .map(|p| (format!("2001:db8:{n}:{p}::/64").parse().unwrap(), 1))
                    .collect(),
            )])
        };
        a.reconcile(vec![], many(1), id(1)).await;
        b.reconcile(vec![], many(2), id(2)).await;
        settle(3).await;
        a.reconcile(
            vec![wired_link(1, NetworkType::PointToPoint)],
            many(1),
            id(1),
        )
        .await;
        b.reconcile(
            vec![wired_link(2, NetworkType::PointToPoint)],
            many(2),
            id(2),
        )
        .await;
        settle(90).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );
        let routes = a.compute_routes().await;
        assert!(
            routes
                .iter()
                .any(|r| r.prefix == "2001:db8:2:2::/64".parse::<Ipv6Net>().unwrap()),
            "{routes:?}"
        );
    }

    /// #146: A hits `SeqNumberMismatch` on its own side (a `BadLSReq`) while
    /// Hellos keep both sides listed; B, still `Full`, must answer A's Init
    /// DBD with `SeqNumberMismatch` too, or A sits in `ExStart` for good.
    /// Renegotiation on the in-memory wire is near-instant, so only the end
    /// state is checked.
    #[tokio::test(start_paused = true)]
    async fn one_sided_seq_number_mismatch_renegotiates_back_to_full() {
        let wire = Arc::new(wire::Wire::default());
        let (a, b) = pair(&wire, None, None).await;
        assert_eq!(
            a.neighbor_summaries().await[0].state,
            OspfNeighborState::Full
        );

        // A forged LSR "from B" for an LSA A doesn't hold: BadLSReq on A only.
        let lsr = LsrPacket {
            router_id: id(2),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![LsaKey {
                lsa_type: lsa::LSA_TYPE_ROUTER,
                link_state_id: id(77),
                advertising_router: id(77),
            }],
        };
        wire.inject(
            "fe80::2".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            &packet::encode_lsr(&lsr),
        );
        settle(30).await;
        for (m, side) in [(&a, "a"), (&b, "b")] {
            assert_eq!(
                m.neighbor_summaries().await[0].state,
                OspfNeighborState::Full,
                "{side}"
            );
        }
    }

    #[test]
    fn only_the_slave_keeps_its_final_dbd_once_full() {
        let cfg = link("eth0.0", 10);
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
        for is_master in [false, true] {
            let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
            status.send_modify(|s| {
                let mut info =
                    neighbor_info(NeighborState::Exchange, "fe80::2".parse().unwrap(), 2);
                info.adjacency = Some(AdjacencyData::default());
                s.neighbors.insert(neighbor_id, info);
            });
            let (_, reply) = start_negotiation(&cfg, Ipv4Addr::new(9, 9, 9, 9));
            let adj = AdjacencyData {
                is_master,
                ..Default::default()
            };
            finish_neighbor_event(
                &cfg,
                Ipv4Addr::new(9, 9, 9, 9),
                &status,
                neighbor_id,
                NeighborState::Exchange,
                adj,
                vec![
                    exchange::Action::SendDbd(reply.clone()),
                    exchange::Action::NeighborEvent(neighbor::Event::ExchangeDone {
                        more_to_load: false,
                    }),
                ],
            );
            let s = status.borrow();
            let info = &s.neighbors[&neighbor_id];
            assert_eq!(info.state, NeighborState::Full);
            let kept = info.adjacency.as_ref().unwrap().last_dbd_sent.clone();
            assert_eq!(kept, (!is_master).then_some(reply), "is_master={is_master}");
        }
    }

    #[tokio::test]
    async fn retransmit_pending_resends_a_dbd_only_in_exstart_or_as_exchange_master() {
        let wire = Arc::new(wire::Wire::default());
        let cfg = wired_link(1, NetworkType::PointToPoint);
        let socket = (wire.opener())(&cfg, 0).unwrap();
        let LinkSocket::Mem(peer) =
            (wire.opener())(&wired_link(2, NetworkType::PointToPoint), 0).unwrap()
        else {
            unreachable!()
        };
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
        let (_, dbd) = start_negotiation(&cfg, Ipv4Addr::new(9, 9, 9, 9));
        for (state, is_master, sent) in [
            (NeighborState::Full, true, false),
            (NeighborState::Loading, true, false),
            (NeighborState::ExStart, false, true),
            (NeighborState::Exchange, false, false),
            (NeighborState::Exchange, true, true),
        ] {
            let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
            status.send_modify(|s| {
                let mut info = neighbor_info(state, "fe80::2".parse().unwrap(), 2);
                info.adjacency = Some(AdjacencyData {
                    is_master,
                    last_dbd_sent: Some(dbd.clone()),
                    ..Default::default()
                });
                s.neighbors.insert(neighbor_id, info);
            });
            retransmit_pending(&socket, &cfg, Ipv4Addr::new(9, 9, 9, 9), &status);
            let got = tokio::time::timeout(std::time::Duration::from_millis(20), peer.recv()).await;
            assert_eq!(got.is_ok(), sent, "{state:?} master={is_master}");
        }
    }

    /// RFC 2328 §10.7/§13/§13.7 (kept by RFC 5340): `LSR`, `LSU` and `LSAck` from
    /// a neighbor below Exchange are ignored; from Exchange they are handled.
    #[tokio::test]
    async fn lsr_lsu_lsack_ignored_below_exchange() {
        let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
        let cfg = link("eth0.0", 10);
        let (area, link_store, as_scope) = (
            Mutex::new(Lsdb::new()),
            Mutex::new(Lsdb::new()),
            Mutex::new(Lsdb::new()),
        );
        let stores = Stores {
            area: &area,
            link: &link_store,
            as_scope: &as_scope,
            stub: false,
        };
        let header = LsaHeader {
            age: 0,
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: neighbor_id,
            sequence_number: 0x8000_0001u32.cast_signed(),
            checksum: 1,
            length: 20,
        };
        for (state, handled) in [
            (NeighborState::ExStart, false),
            (NeighborState::Exchange, true),
        ] {
            let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
            status.send_modify(|s| {
                let mut info = neighbor_info(state, "fe80::2".parse().unwrap(), 7);
                let mut adj = AdjacencyData::default();
                adj.retransmission_list.insert(
                    header.key(),
                    Arc::new(Lsa {
                        header,
                        body: LsaBody::Opaque(vec![]),
                    }),
                );
                info.adjacency = Some(adj);
                s.neighbors.insert(neighbor_id, info);
            });
            let lsr = LsrPacket {
                router_id: neighbor_id,
                area_id: Ipv4Addr::UNSPECIFIED,
                requests: vec![],
            };
            let got = handle_lsr(&cfg, Ipv4Addr::new(1, 1, 1, 1), &status, &stores, &lsr).await;
            assert_eq!(got.is_some(), handled, "lsr {state:?}");
            let lsu = LsuPacket {
                discarded: 0,
                last_error: None,
                router_id: neighbor_id,
                area_id: Ipv4Addr::UNSPECIFIED,
                lsas: vec![],
            };
            let got = handle_lsu(&cfg, Ipv4Addr::new(1, 1, 1, 1), &status, &stores, &lsu).await;
            assert_eq!(got.is_some(), handled, "lsu {state:?}");
            handle_lsack(
                &status,
                &LsAckPacket {
                    router_id: neighbor_id,
                    area_id: Ipv4Addr::UNSPECIFIED,
                    lsa_headers: vec![header],
                },
            );
            let left = status.borrow().neighbors[&neighbor_id]
                .adjacency
                .as_ref()
                .unwrap()
                .retransmission_list
                .len();
            assert_eq!(left == 0, handled, "lsack {state:?}");
        }
    }

    // --- #879: multicast LSU flooding and delayed LSAck ---

    fn sent(wire: &wire::Wire, from: u8, ty: u8) -> Vec<wire::To> {
        let a: Ipv6Addr = format!("fe80::{from}").parse().unwrap();
        wire.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(f, _, t)| *f == a && *t == ty)
            .map(|(_, to, _)| *to)
            .collect()
    }

    /// Three routers on one broadcast net: 1 = DR, 2 = BDR, 3 = `DROther`.
    async fn trio(
        wire: &Arc<wire::Wire>,
        auth: Option<packet::TrailerAuth>,
    ) -> Vec<Arc<LinkManager>> {
        let mut out = Vec::new();
        for n in 1..=3u8 {
            let m = router(wire);
            let mut l = wired_link(n, NetworkType::Broadcast);
            l.priority = 4 - n;
            l.auth.clone_from(&auth);
            m.reconcile(vec![l], loopback(n), id(n)).await;
            out.push(m);
        }
        out
    }

    async fn heard(m: &LinkManager, router: Ipv4Addr) -> bool {
        m.database_summaries()
            .await
            .iter()
            .any(|l| l.advertising_router == router)
    }

    #[tokio::test(start_paused = true)]
    async fn drother_uses_all_drouters_and_dr_bdr_use_all_spf() {
        let wire = Arc::new(wire::Wire::default());
        let m = trio(&wire, None).await;
        settle(90).await;
        let c = sent(&wire, 3, 4);
        assert!(c.last() == Some(&wire::To::AllD), "{c:?}");
        assert!(sent(&wire, 3, 5).iter().all(|t| *t == wire::To::AllD));
        for n in [1, 2] {
            let s = sent(&wire, n, 4);
            assert!(s.last() == Some(&wire::To::AllSpf), "{n}: {s:?}");
        }
        assert!(heard(&m[0], id(3)).await && heard(&m[1], id(3)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn multicast_lsu_verifies_under_trailer_auth() {
        let wire = Arc::new(wire::Wire::default());
        let m = trio(&wire, Some(trailer(b"k"))).await;
        settle(90).await;
        let c = sent(&wire, 3, 4);
        assert!(c.last() == Some(&wire::To::AllD), "{c:?}");
        assert!(heard(&m[0], id(3)).await && heard(&m[1], id(3)).await);
        assert!(heard(&m[2], id(1)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn multicast_failure_falls_back_to_unicast() {
        let wire = Arc::new(wire::Wire::default());
        wire.fail_all_d
            .lock()
            .unwrap()
            .insert("fe80::3".parse().unwrap());
        let m = trio(&wire, None).await;
        settle(90).await;
        assert!(sent(&wire, 3, 4)
            .iter()
            .any(|t| matches!(t, wire::To::Unicast(_))));
        assert!(heard(&m[0], id(3)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn point_to_point_never_uses_a_group_for_lsu_or_ack() {
        let wire = Arc::new(wire::Wire::default());
        let (_a, _b) = pair(&wire, None, None).await;
        for n in [1, 2] {
            for ty in [4, 5] {
                let s = sent(&wire, n, ty);
                assert!(s.iter().all(|t| matches!(t, wire::To::Unicast(_))), "{s:?}");
            }
        }
        assert!(sent(&wire, 1, 4).len() > 1);
    }

    fn dr_status(state: InterfaceState, neighbors: &[u8]) -> StatusHandle {
        let mut s = LinkStatus::new(NetworkType::Broadcast);
        s.interface_state = state;
        for n in neighbors {
            let mut info = neighbor_info(
                NeighborState::Full,
                format!("fe80::{n}").parse().unwrap(),
                u32::from(*n),
            );
            info.adjacency = Some(AdjacencyData::default());
            s.neighbors.insert(id(*n), info);
        }
        watch::channel(s).0
    }

    fn header() -> crate::lsa::LsaHeader {
        crate::lsa::LsaHeader {
            age: 0,
            lsa_type: 0x2003,
            link_state_id: Ipv4Addr::new(1, 0, 0, 1),
            advertising_router: id(9),
            sequence_number: 1,
            checksum: 0,
            length: 20,
        }
    }

    fn queue_acks(status: &StatusHandle) {
        status.send_modify(|s| {
            for n in s.neighbors.values_mut() {
                n.adjacency.as_mut().unwrap().pending_acks = vec![header()];
            }
        });
    }

    #[tokio::test]
    async fn delayed_acks_are_one_deduplicated_group_set() {
        let wire = Arc::new(wire::Wire::default());
        let cfg = wired_link(1, NetworkType::Broadcast);
        let socket = wire.opener()(&cfg, 0).unwrap();
        let status = dr_status(InterfaceState::Dr, &[2, 3]);
        queue_acks(&status);
        flush_pending_acks(&socket, &cfg, id(1), &status);
        assert_eq!(sent(&wire, 1, 5), vec![wire::To::AllSpf]);
        flush_pending_acks(&socket, &cfg, id(1), &status);
        assert_eq!(sent(&wire, 1, 5).len(), 1);
    }

    #[tokio::test]
    async fn ack_group_failure_falls_back_to_unicast() {
        let wire = Arc::new(wire::Wire::default());
        wire.fail_all_d
            .lock()
            .unwrap()
            .insert("fe80::1".parse().unwrap());
        let cfg = wired_link(1, NetworkType::Broadcast);
        let socket = wire.opener()(&cfg, 0).unwrap();
        let status = dr_status(InterfaceState::DrOther, &[2]);
        queue_acks(&status);
        flush_pending_acks(&socket, &cfg, id(1), &status);
        assert_eq!(
            sent(&wire, 1, 5),
            vec![wire::To::Unicast("fe80::2".parse().unwrap())]
        );
    }

    #[tokio::test]
    async fn destination_is_reported_only_on_change() {
        let wire = Arc::new(wire::Wire::default());
        let cfg = wired_link(1, NetworkType::Broadcast);
        let socket = wire.opener()(&cfg, 0).unwrap();
        let status = dr_status(InterfaceState::Dr, &[]);
        let (a, l, s) = (
            Mutex::new(Lsdb::new()),
            Mutex::new(Lsdb::new()),
            Mutex::new(Lsdb::new()),
        );
        let stores = Stores {
            area: &a,
            link: &l,
            as_scope: &s,
            stub: false,
        };
        let mut last = None;
        flood_full_neighbors(&socket, &cfg, id(1), &stores, &status, &mut last).await;
        assert_eq!(last, Some(Dest::AllSpfRouters));
        status.send_modify(|s| s.interface_state = InterfaceState::DrOther);
        flood_full_neighbors(&socket, &cfg, id(1), &stores, &status, &mut last).await;
        assert_eq!(last, Some(Dest::AllDRouters));
    }

    #[tokio::test]
    async fn retransmission_resend_stays_unicast() {
        let wire = Arc::new(wire::Wire::default());
        let cfg = wired_link(1, NetworkType::Broadcast);
        let socket = wire.opener()(&cfg, 0).unwrap();
        let status = dr_status(InterfaceState::Dr, &[2]);
        let l = crate::lsa::Lsa {
            header: header(),
            body: crate::lsa::LsaBody::Opaque(vec![1, 2, 3, 4]),
        };
        status.send_modify(|s| {
            let adj = s
                .neighbors
                .values_mut()
                .next()
                .unwrap()
                .adjacency
                .as_mut()
                .unwrap();
            adj.retransmission_list.insert(l.header.key(), Arc::new(l));
        });
        retransmit_pending(&socket, &cfg, id(1), &status);
        assert_eq!(
            sent(&wire, 1, 4),
            vec![wire::To::Unicast("fe80::2".parse().unwrap())]
        );
    }
}
