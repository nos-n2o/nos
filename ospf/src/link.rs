//! One OSPF link's driver, plus `LinkManager` — the OSPF analogue of
//! `bgp::session::SessionManager`, much smaller since there's no shared
//! listener and no collision resolution: each link just owns its
//! own raw socket, neighbor FSM(s), RFC 2328 §9.4 DR/BDR election on a
//! `Broadcast` link, and — once a neighbor is eligible — RFC 2328
//! §10.6-10.8's DBD/LSR/LSU/LSAck adjacency-forming exchange
//! (`crate::exchange`).

mod flood;
mod grace;
mod originate;
mod rx;
use self::flood::{
    apply_dead_timer, flood_full_neighbors, flush_pending_acks, kill_bfd_neighbor, note_alive,
    retransmit_pending, sweep_dead_neighbors,
};
use self::grace::{expire_grace, send_grace_lsas};
use self::originate::local_subnet;
use self::rx::{
    accept_crypto_sequence, advance_adjacencies, execute_actions, handle_dbd, handle_hello,
    handle_lsack, handle_lsr, handle_lsu, initial_crypto_seq, run_election, send_hello,
    sync_all_drouters,
};

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::{IpNet, Ipv4Net};
use nos_proto::schema::BfdProfile;
use nos_proto::{
    BfdDiag, LinkInterfaceState, LsaSummary, NeighborSummary, NetworkType, OspfNeighborState,
    RedistributeUpdate,
};
use nos_rpl::CompiledPolicy;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use nos_ospf_common::drouters::Dest;

use crate::bfd;
use crate::bfd_client::{Host, Target, Want};
use crate::election::{self, Candidate};
use crate::exchange::{self, AdjacencyData};
use crate::lsa::{
    self, AsExternalLsaBody, GraceLsaBody, Lsa, LsaBody, LsaHeader, LsaKey, NetworkLsaBody,
    RouterLink, RouterLsaBody, SummaryLsaBody, LINK_TYPE_POINT_TO_POINT, LINK_TYPE_STUB_NETWORK,
    LINK_TYPE_TRANSIT_NETWORK, LINK_TYPE_VIRTUAL,
};
use crate::lsdb::{InstallOutcome, Lsdb};
use crate::neighbor::{self, NeighborState};
use crate::packet::{self, DbdPacket, LsAckPacket, LsrPacket, LsuPacket, OspfPacket, PacketError};
use crate::socket::OspfSocket;
use crate::spf;

/// What a link task sends and receives on: the real raw socket, or (in
/// tests) an in-memory wire — the one seam that lets `run` and
/// `LinkManager` be exercised without `CAP_NET_RAW` (#131).
pub enum LinkSocket {
    Os(OspfSocket),
    #[cfg(test)]
    Mem(tests::wire::Port),
}

impl LinkSocket {
    fn send_multicast(&self, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Os(s) => s.send_multicast(payload),
            #[cfg(test)]
            Self::Mem(p) => p.send(tests::wire::To::AllSpf, payload),
        }
    }

    fn send_all_drouters(&self, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Os(s) => s.send_all_drouters(payload),
            #[cfg(test)]
            Self::Mem(p) => p.send(tests::wire::To::AllD, payload),
        }
    }

    fn send_unicast(&self, dest: Ipv4Addr, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Os(s) => s.send_unicast(dest, payload),
            #[cfg(test)]
            Self::Mem(p) => p.send(tests::wire::To::Unicast(dest), payload),
        }
    }

    /// One flood-path send (`flood_dest`): the group, or `neighbor` directly.
    fn send_flood(&self, dest: Dest, neighbor: Ipv4Addr, payload: &[u8]) -> std::io::Result<()> {
        match dest {
            Dest::Unicast => self.send_unicast(neighbor, payload),
            Dest::AllSpfRouters => self.send_multicast(payload),
            Dest::AllDRouters => self.send_all_drouters(payload),
        }
    }

    /// Join/leave 224.0.0.6 (see `sync_all_drouters`); whether membership changed.
    fn set_all_drouters(&self, want: bool) -> std::io::Result<bool> {
        match self {
            Self::Os(s) => s.set_all_drouters(want),
            #[cfg(test)]
            Self::Mem(p) => p.set_all_drouters(want),
        }
    }

    async fn recv_packet(&self) -> std::io::Result<(Ipv4Addr, Vec<u8>)> {
        match self {
            Self::Os(s) => s.recv_packet().await,
            #[cfg(test)]
            Self::Mem(p) => p.recv().await,
        }
    }
}

/// Opens one link's socket — the real one in production, see `LinkSocket`.
pub type Opener = Arc<dyn Fn(&LinkConfig) -> std::io::Result<LinkSocket> + Send + Sync>;

/// RFC 2328 Appendix C.3's default `RxmtInterval` — how often an
/// unacknowledged LSR/LSU is resent.
///
/// # ponytail: fixed, not a per-`OspfProfile` config field
/// `hello_interval`/`dead_interval`/`priority` are all operator-tunable per
/// profile, but adding a matching `retransmit_interval` field would touch
/// schema/ops/diff/cli plumbing across ~7 files for a knob nothing in this
/// NOS's verification suite needs tuned. Upgrade to a real
/// `OspfProfile.retransmit_interval: Option<u16>` (mirroring
/// `hello_interval`'s exact pattern) if an operator ever needs to tune it.
const RXMT_INTERVAL: Duration = Duration::from_secs(5);

/// How often `LinkManager` recomputes and reinstalls this router's own
/// self-originated LSAs — independent of, and much more frequent than, the
/// 10s config-reapply tick, so a freshly-`Full` adjacency's Router-LSA
/// shows up quickly rather than waiting on the next config resync.
const ORIGINATION_INTERVAL: Duration = Duration::from_secs(2);

/// RFC 2328 §14: how often `LinkManager` ages every installed LSA by one
/// (simulated) second. Real wall-clock cadence — `age_multiplier` scales how
/// many simulated seconds each tick advances, not this tick's own rate, so
/// `age` stays a wire-correct simulated-seconds value regardless of what a
/// test harness sets the multiplier to.
const AGE_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// How long `LinkManager::shutdown` keeps the link tasks alive after
/// prematurely aging every self-originated LSA (RFC 2328 §14.1), so each
/// link's own `RXMT_INTERVAL` resend actually carries the `MaxAge` copies out
/// before the process exits: one resend period plus a second of margin.
/// With `max-metric router-lsa on-shutdown`'s hold (at most
/// `MAX_METRIC_SHUTDOWN_HOLD_MAX`) it must fit `nos-watchdogd`'s 10s
/// SIGINT-to-SIGKILL budget (`docs/architecture/supervision.md`) with a
/// second to spare for the exit — see the assertion below. The flush is kicked
/// out at once (`LinkCommand::FloodNow`), so the window buys one `RXMT_INTERVAL`
/// retransmission on top.
const PREMATURE_AGE_FLOOD_WINDOW: Duration = Duration::from_secs(6);

/// The longest RFC 6987 on-shutdown hold `OspfInstance.max_metric_on_shutdown`
/// accepts (its garde range is 1-3).
const MAX_METRIC_SHUTDOWN_HOLD_MAX: Duration = Duration::from_secs(3);
const _: () = assert!(
    MAX_METRIC_SHUTDOWN_HOLD_MAX.as_secs() + PREMATURE_AGE_FLOOD_WINDOW.as_secs() <= 9,
    "on-shutdown hold + flush window must fit nos-watchdogd's 10s kill budget"
);

/// How long `LinkManager::announce_graceful_restart` waits after each
/// Grace-LSA send before the next one (two sends) and before exiting —
/// enough for the link tasks to put them on the wire. ponytail: sent twice,
/// not retransmitted until acked; a lossless local link is the norm here.
const GRACE_SEND_WINDOW: Duration = Duration::from_millis(500);

/// One link's fully-resolved desired state — diffed wholesale by
/// `LinkManager::reconcile`, mirroring `bgp::session::ResolvedPeer`: any
/// field change (including a re-resolved `vrf`/`local_addr`, or a changed
/// `network_type`/`priority`) restarts the link.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkConfig {
    /// Display key, matching `reconcile::attach_points_for`'s existing
    /// `"<interface>.<tag>"`/`"broadcast-domain:<name>"` convention.
    pub attach_point: String,
    pub area_id: Ipv4Addr,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub vrf: String,
    pub local_addr: Ipv4Addr,
    /// This link's own subnet's prefix length — needed (alongside
    /// `local_addr`) to originate a real stub-network Router-LSA link for
    /// a point-to-point subnet, and a real `NetworkLsaBody.network_mask`
    /// for a broadcast one. See `crate::spf`.
    pub local_prefix_len: u8,
    /// This link's RFC 2328 §16 SPF cost — `OspfProfile.cost`, defaulting
    /// to `1` when unset (see `reconcile.rs`).
    pub cost: u16,
    /// The real Linux device this link's raw socket binds to — the
    /// specific L3 interface OSPF actually runs on: the physical/VLAN
    /// subinterface itself for a point-to-point attach point, or the
    /// `BroadcastDomain`'s own bridge (its SVI) for a broadcast one. Never
    /// the VRF device: OSPF's raw protocol-89 socket has no port/connection
    /// concept to demultiplex by, so a VRF-wide bind would also receive
    /// every *other* OSPF link's traffic in the same VRF, corrupting each
    /// link's own DBD/LSR/LSU sequence-number/role state — a real bug this
    /// field's introduction fixed (see `socket.rs`'s doc comment).
    pub kernel_interface: String,
    pub network_type: NetworkType,
    pub priority: u8,
    /// This link's effective MTU (`OspfProfile.mtu` if set, else the real
    /// resolved interface MTU, else 1500 — see `reconcile::
    /// resolve_effective_mtu`) — advertised in the wire's
    /// `DbdPacket.interface_mtu` field and used to size real RFC 2328 §10.8
    /// DBD pagination (`exchange::pop_chunk`'s `max_headers` budget) when
    /// `LinkManager.dbd_max_headers` has no explicit test override. See
    /// `docs/protocols/ospf-internals.md`'s "LSA exchange and the LSDB".
    pub mtu: u16,
    /// `mtu-ignore`: skip the RFC 2328 §10.6 DBD Interface MTU check.
    pub mtu_ignore: bool,
    /// The kernel device's ifindex from the `nos-interfaced` link stream (0 for
    /// a virtual link or before the stream's first snapshot). A recreated
    /// device gets a new one, which restarts the link (fresh raw socket).
    pub ifindex: u32,
    /// RFC 2328 Appendix D auth, resolved once per reconcile from
    /// `OspfProfile.auth` (see `reconcile.rs`). Fits this struct's existing
    /// "any field change restarts the link" rule with no special-casing —
    /// an auth/key change simply restarts the link task, which re-sends
    /// Hello with the new auth; a peer still on the old auth rejects it
    /// until it's updated too, which is exactly the desired match/mismatch
    /// behavior.
    pub auth: LinkAuthConfig,
    /// The link's area is a stub (RFC 2328 §3.6) or an NSSA: Hellos and DBDs
    /// go without the E-bit and a peer's must match, and AS-scope LSAs stay
    /// out of the exchange. Changing an area's type restarts its links.
    pub stub: bool,
    /// The link's area is an NSSA (RFC 3101, `stub` is set too): Hellos carry
    /// the N-bit and a peer's must match, and only here are Type-7s exchanged.
    pub nssa: bool,
    /// `Some` for an RFC 2328 §15 virtual link: area 0, unicast Hellos to
    /// `neighbor`, a type-4 Router-LSA link. Resolved from the transit area's
    /// SPF (§16.7, `resolve_virtual_link`), never from an attach point.
    pub virtual_link: Option<VirtualLinkEnd>,
}

/// A virtual link's transit area, far endpoint's router id and its address
/// in the transit area (where every packet is unicast to).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualLinkEnd {
    pub transit_area: Ipv4Addr,
    pub endpoint: Ipv4Addr,
    pub neighbor: Ipv4Addr,
}

/// One configured virtual link (`OspfArea.virtual_links`), before §16.7 has
/// resolved it to a `LinkConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct VirtualLinkConfig {
    pub transit_area: Ipv4Addr,
    pub endpoint: Ipv4Addr,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub auth: LinkAuthConfig,
}

/// RFC 2328 §16.7: `v` as a running link while its endpoint has an
/// intra-area path in the transit area (`lsas` is that area's LSDB), with the
/// path's distance as cost; `None` (down) otherwise. Our own address is that
/// of our transit-area link toward the first hop (`physical` are this
/// router's other links), the neighbor's the endpoint's on its Router-LSA.
fn resolve_virtual_link(
    v: &VirtualLinkConfig,
    local_router_id: Ipv4Addr,
    lsas: &[Arc<Lsa>],
    physical: &[LinkConfig],
) -> Option<LinkConfig> {
    let end = spf::virtual_link_endpoint(local_router_id, lsas, v.endpoint)?;
    let in_transit = || physical.iter().filter(|c| c.area_id == v.transit_area);
    let transit = in_transit()
        .find(|c| local_subnet(c).is_some_and(|n| n.contains(&end.next_hops[0])))
        .or_else(|| in_transit().next())?;
    Some(LinkConfig {
        attach_point: format!("vlink-{}-{}", v.transit_area, v.endpoint),
        area_id: Ipv4Addr::UNSPECIFIED,
        hello_interval: v.hello_interval,
        dead_interval: v.dead_interval,
        vrf: transit.vrf.clone(),
        local_addr: transit.local_addr,
        // RFC 2328 §10.5: a virtual link's Hello carries mask 0.
        local_prefix_len: 0,
        cost: u16::try_from(end.cost).unwrap_or(u16::MAX),
        kernel_interface: transit.vrf.clone(),
        network_type: NetworkType::PointToPoint,
        priority: 0,
        // ponytail: RFC 2328 A.3.3 wants Interface MTU 0 in a virtual link's
        // DBDs; we send the transit link's and skip the check instead.
        mtu: transit.mtu,
        mtu_ignore: true,
        ifindex: 0,
        auth: v.auth.clone(),
        stub: false,
        nssa: false,
        virtual_link: Some(VirtualLinkEnd {
            transit_area: v.transit_area,
            endpoint: v.endpoint,
            neighbor: end.address,
        }),
    })
}

/// RFC 2328 §8.2's receive demux, on the raw packet before it is decoded.
/// A virtual link takes only backbone packets from its endpoint. Another
/// area's link drops backbone packets: they are virtual-link traffic that
/// shares the transit link's addresses. Any other area mismatch goes on to
/// `handle_hello`'s warning.
fn accepts_packet(cfg: &LinkConfig, source: Ipv4Addr, data: &[u8]) -> bool {
    let backbone = packet::area_id(data) == Some(Ipv4Addr::UNSPECIFIED);
    match cfg.virtual_link {
        Some(v) => backbone && source == v.neighbor,
        None => !backbone || cfg.area_id.is_unspecified(),
    }
}

/// RFC 2328 §8.2: a packet's source must be on the receiving link's subnet.
/// A virtual link is already pinned to its endpoint by `accepts_packet`, and a
/// point-to-point link may be unnumbered (`/32` peers share no subnet).
/// Anything else off-subnet is dropped (#394).
fn source_on_link(cfg: &LinkConfig, source: Ipv4Addr) -> bool {
    cfg.virtual_link.is_some()
        || cfg.network_type == NetworkType::PointToPoint
        || local_subnet(cfg).is_some_and(|n| n.contains(&source))
}

/// One link's resolved OSPF authentication — `OspfProfile.auth` translated
/// into `packet.rs`'s own key-material shape.
#[derive(Debug, Clone, PartialEq)]
pub enum LinkAuthConfig {
    None,
    Simple {
        password: Vec<u8>,
    },
    /// `current_key_id` names which of `keys` actively signs outgoing
    /// packets — guaranteed present by `OspfProfile.auth`'s own commit-time
    /// validation (`valid_auth`: exactly one `is_current` key) by the time
    /// this is built in `reconcile.rs`.
    Crypto {
        keys: Vec<(u16, packet::CryptoAlgorithm, Vec<u8>)>,
        current_key_id: u16,
        /// RFC 7474 (`OspfProfile.extended_sequence_numbers`): `AuType` 3
        /// with a persisted-boot-count 64-bit sequence number.
        extended: bool,
    },
}

impl LinkAuthConfig {
    fn is_extended(&self) -> bool {
        matches!(self, LinkAuthConfig::Crypto { extended: true, .. })
    }

    /// Bytes the authentication trailer adds to every packet (RFC 5709 digest;
    /// Simple's password sits in the header, so 0).
    fn digest_len(&self) -> usize {
        match self {
            LinkAuthConfig::Crypto {
                keys,
                current_key_id,
                ..
            } => keys
                .iter()
                .find(|(id, _, _)| id == current_key_id)
                .map_or(0, |(_, alg, _)| alg.digest_len()),
            _ => 0,
        }
    }

    /// `source` is the received packet's IP source address (RFC 7474 binds
    /// the digest to it).
    fn as_policy(&self, source: Ipv4Addr) -> packet::AuthPolicy<'_> {
        match self {
            LinkAuthConfig::None => packet::AuthPolicy::None,
            LinkAuthConfig::Simple { password } => packet::AuthPolicy::Simple { password },
            LinkAuthConfig::Crypto { keys, extended, .. } => packet::AuthPolicy::Crypto {
                keys,
                extended: extended.then_some(source),
            },
        }
    }

    /// Builds what to sign an outgoing packet with, given this send's own
    /// crypto sequence number (only meaningful for `Crypto`).
    fn as_outgoing(&self, sequence: u64, local_addr: Ipv4Addr) -> packet::OutgoingAuth<'_> {
        match self {
            LinkAuthConfig::None => packet::OutgoingAuth::None,
            LinkAuthConfig::Simple { password } => packet::OutgoingAuth::Simple { password },
            LinkAuthConfig::Crypto {
                keys,
                current_key_id,
                extended,
            } => {
                let (key_id, algorithm, key) = keys
                    .iter()
                    .find(|(id, _, _)| id == current_key_id)
                    .expect("valid_auth guarantees current_key_id names a real key");
                packet::OutgoingAuth::Crypto {
                    key_id: *key_id,
                    algorithm: *algorithm,
                    key,
                    sequence,
                    extended: extended.then_some(local_addr),
                }
            }
        }
    }
}

/// RFC 2328 §9.1's interface states — see `nos_proto::LinkInterfaceState`,
/// which this mirrors one-to-one (kept as a separate type here, like
/// `bgp::status::PeerState` mirrors `nos_proto::bgp::BgpSessionState`, since
/// this crate's internal state isn't necessarily wire-serializable forever).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceState {
    PointToPoint,
    Waiting,
    Dr,
    Backup,
    DrOther,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NeighborInfo {
    pub state: NeighborState,
    pub priority: u8,
    pub declared_dr: Ipv4Addr,
    pub declared_bdr: Ipv4Addr,
    /// Reported only (`last_hello_secs`): when the last valid Hello arrived.
    pub last_hello_received: Instant,
    /// RFC 4222 §2 recommendation 2: when this neighbor was last heard from —
    /// a valid Hello, or any authenticated packet over its adjacency
    /// (`note_alive`). The inactivity timer runs off this, not the Hello time.
    pub last_heard: Instant,
    /// The neighbor's own IP address, as seen on the last Hello it sent —
    /// DBD/LSR/LSU/LSAck reply unicast to this, unlike Hello's multicast.
    pub address: Ipv4Addr,
    /// `Some` from `ExStart` onward; cleared whenever the neighbor drops
    /// back to `Init`/`Down` (RFC 2328: losing 2-way tears down any
    /// adjacency, forcing a fresh negotiation on reconnect).
    pub adjacency: Option<AdjacencyData>,
    /// RFC 2328 D.4.3's anti-replay crypto sequence number, last accepted
    /// from this neighbor — `None` until its first Crypto-authenticated
    /// packet. Only ever populated/checked when `LinkConfig.auth` is
    /// `Crypto`; see `run()`'s receive loop.
    ///
    /// Keyed by packet type under RFC 7474 (its replay rule is per type), by
    /// a single `0` slot under RFC 2328's classic `AuType` 2.
    pub last_crypto_seq: HashMap<u8, u64>,
    /// RFC 3623 helper mode: `Some` while this neighbor is restarting under
    /// a Grace-LSA it sent. Until then its adjacency is held through missing
    /// Hellos and Hellos that don't list us (see `in_grace`).
    pub grace_deadline: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinkStatus {
    pub interface_state: InterfaceState,
    /// Keyed by neighbor router-id. At most one entry on a point-to-point
    /// link; potentially many on a broadcast link.
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
                NetworkType::Broadcast => InterfaceState::Waiting,
            },
            neighbors: HashMap::new(),
            dr: None,
            bdr: None,
        }
    }
}

pub type StatusHandle = watch::Sender<LinkStatus>;

/// RFC 2328 §7.5/§10.4: on a broadcast link, a neighbor only proceeds
/// toward a full adjacency if this router or that neighbor is the elected
/// DR/BDR — every other pair (`DrOther`-`DrOther`) stays at `TwoWay`
/// forever. Point-to-point has no such restriction (`interface_state` is
/// always `PointToPoint`, so every neighbor is always eligible).
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

/// A sequence number unlikely to collide with whatever this router last
/// used with this neighbor (RFC 2328 §10.6 has no stronger requirement than
/// that). Kept in `link.rs`, not `exchange.rs`, so the DBD negotiation logic
/// stays free of wall-clock reads and fully unit-testable.
fn initial_dd_sequence_number() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |d| d.subsec_nanos())
}

/// Builds a fresh `AdjacencyData` plus the negotiation DBD to send —
/// used both when a neighbor first becomes adjacency-eligible and when a
/// `SeqNumberMismatch` forces negotiation to restart from scratch.
fn start_negotiation(cfg: &LinkConfig, local_router_id: Ipv4Addr) -> (AdjacencyData, DbdPacket) {
    let seed = initial_dd_sequence_number();
    let dbd = DbdPacket {
        router_id: local_router_id,
        area_id: cfg.area_id,
        interface_mtu: cfg.mtu,
        options: exchange::dbd_options(cfg.stub),
        init: true,
        more: true,
        master: true,
        dd_sequence_number: seed,
        lsa_headers: Vec::new(),
    };
    let adj = AdjacencyData {
        is_master: false, // resolved once the neighbor's own negotiation DBD arrives
        dd_sequence_number: seed,
        request_list: Vec::new(),
        retransmission_list: HashMap::new(),
        last_dbd_sent: Some(dbd.clone()),
        // Populated once real content starts flowing, in `exchange::
        // on_dbd_in_exstart` (this negotiation attempt itself always
        // carries no summary data, per RFC 2328 §10.6).
        summary_remaining: std::collections::VecDeque::new(),
        pending_acks: Vec::new(),
        pending_acks_since: None,
        opaque_capable: false, // learnt from the neighbor's DBD
        stub: cfg.stub,
        nssa: cfg.nssa,
    };
    (adj, dbd)
}

/// Runs until aborted (link removed from config, or process shutdown — see
/// `LinkManager`). Owns the raw socket, the Hello send ticker, and every
/// timer this link's network type needs.
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
    status: StatusHandle,
    dbd_max_headers: Option<usize>,
    boot_count: u32,
    mut commands: mpsc::UnboundedReceiver<LinkCommand>,
) {
    let socket = match socket {
        Ok(s) => s,
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "failed to open ospf raw socket");
            return;
        }
    };
    // `Some(n)` (from `--dbd-max-headers`, test/debug only) keeps that exact
    // override; `None` (the real default) derives the pagination budget
    // from this link's own effective MTU — see `exchange`'s module doc.
    let dbd_max_headers =
        dbd_max_headers.unwrap_or_else(|| exchange::mtu_based_max_headers(cfg.mtu));

    let mut hello_ticker =
        tokio::time::interval(Duration::from_secs(u64::from(cfg.hello_interval)));
    hello_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let is_broadcast = cfg.network_type == NetworkType::Broadcast;
    // RFC 2328 §9.5: several neighbors, no election — each one's dead timer is
    // tracked by the 1s sweep below instead of the single p2p deadline.
    let is_p2mp = cfg.network_type == NetworkType::PointToMultipoint;
    let mut p2p_dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
    // ponytail: a 1s periodic sweep, not N precise per-neighbor timers — a
    // broadcast link's dead-interval tracking only needs to be accurate to
    // about a second, and this avoids a dynamically-sized set of timers
    // growing/shrinking as neighbors come and go. Upgrade to a
    // `last_heard`-keyed min-heap (or per-neighbor spawned
    // timers) if sub-second precision on broadcast links ever matters.
    let mut dead_sweep = tokio::time::interval(Duration::from_secs(1));
    dead_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let wait_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
    let mut waiting = is_broadcast;
    let mut warn_limiter = nos_ospf_common::ratelimit::WarnLimiter::default();

    let mut rxmt_sweep = tokio::time::interval(RXMT_INTERVAL);
    rxmt_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // RFC 2328 D.4.3's outgoing crypto sequence number — only meaningful
    // when `cfg.auth` is `Crypto`, but harmless to always seed/advance.
    // Floored at wall-clock seconds so it never regresses across a link
    // restart (a fresh `next_crypto_seq` call always floors back up to
    // "now" if the in-memory counter would otherwise be behind).
    let mut next_seq = initial_crypto_seq(&cfg.auth, boot_count);
    let mut last_flood_dest: Option<Dest> = None;

    info!(link = %cfg.attach_point, vrf = %cfg.vrf, "ospf link driver started");
    if cfg.auth.is_extended() {
        info!(link = %cfg.attach_point, boot_count, "ospf link using rfc 7474 extended sequence numbers");
    }
    if is_broadcast {
        info!(link = %cfg.attach_point, "ospf interface reached waiting");
    }

    loop {
        // RFC 4222 §2 recommendation 1: Hello sends and receives first, the
        // 5s `rxmt_sweep` (LSDB lock + full-LSDB encode) last, and a queued
        // packet ahead of a dead timer that became ready in the same poll.
        // ponytail: `biased;` only orders arms that are already ready — it
        // doesn't preempt a running arm (a handler waiting on the LSDB lock
        // still delays the next Hello), and a sustained inbound queue runs the
        // timer arms late (harmless for the dead timers, see `note_alive`).
        // Upgrade to a separate Hello task or a high/low receive queue if a
        // large LSDB ever shows Hello starvation.
        tokio::select! {
            biased;
            _ = hello_ticker.tick() => {
                send_hello(&socket, &cfg, local_router_id, &status, &mut next_seq);
            }
            result = socket.recv_packet() => {
                match result {
                    Ok((source, data)) if !accepts_packet(&cfg, source, &data) => {}
                    Ok((source, _)) if !source_on_link(&cfg, source) => {
                        debug!(link = %cfg.attach_point, source = %source, "ospf packet from off-link source, dropping");
                    }
                    Ok((source, data)) => {
                        let policy = cfg.auth.as_policy(source);
                        match packet::decode(&data, &policy) {
                            Ok(pkt) if !accept_crypto_sequence(&cfg, &status, &data, &pkt) => {
                                warn!(
                                    link = %cfg.attach_point, neighbor = %packet::router_id(&pkt),
                                    "ospf packet crypto sequence number not increasing, dropping"
                                );
                            }
                            Ok(pkt) => {
                                if !matches!(pkt, OspfPacket::Hello(_)) {
                                    note_alive(&cfg, &status, packet::router_id(&pkt), &mut p2p_dead_deadline);
                                }
                                match pkt {
                                    OspfPacket::Hello(hello) => {
                                        let left_waiting = handle_hello(
                                            &cfg, local_router_id, &status, source, &hello,
                                            &mut p2p_dead_deadline, waiting, &mut warn_limiter,
                                        );
                                        if left_waiting {
                                            waiting = false;
                                        }
                                        if is_broadcast && !waiting {
                                            sync_all_drouters(&socket, &cfg, &status);
                                        }
                                        advance_adjacencies(&socket, &cfg, local_router_id, &status, &mut next_seq);
                                    }
                                    OspfPacket::Dbd(dbd) => {
                                        if let Some(actions) = handle_dbd(
                                            &cfg, local_router_id, &status, &lsdb, &link_local_lsdb, &dbd, dbd_max_headers,
                                        )
                                        .await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, dbd.router_id, actions, &mut next_seq);
                                        }
                                    }
                                    OspfPacket::Lsr(lsr) => {
                                        if let Some(actions) =
                                            handle_lsr(&cfg, local_router_id, &status, &lsdb, &link_local_lsdb, &lsr).await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, lsr.router_id, actions, &mut next_seq);
                                        }
                                    }
                                    OspfPacket::Lsu(lsu) => {
                                        if lsu.discarded > 0
                                            && warn_limiter.allow(tokio::time::Instant::now().into_std())
                                        {
                                            warn!(
                                                link = %cfg.attach_point, neighbor = %lsu.router_id,
                                                discarded = lsu.discarded, error = ?lsu.last_error,
                                                "ospf lsu: discarded LSAs that failed to decode"
                                            );
                                        }
                                        if let Some(actions) =
                                            handle_lsu(&cfg, local_router_id, &status, &lsdb, &link_local_lsdb, &lsu).await
                                        {
                                            execute_actions(&socket, &cfg, local_router_id, &status, lsu.router_id, actions, &mut next_seq);
                                        }
                                    }
                                    OspfPacket::LsAck(ack) => {
                                        handle_lsack(&status, &ack);
                                    }
                                }
                            }
                            Err(e) => match e {
                                PacketError::AuthTypeMismatch | PacketError::AuthFailed => {
                                    warn!(link = %cfg.attach_point, error = %e, "ospf packet authentication failed");
                                }
                                _ => {
                                    warn!(link = %cfg.attach_point, error = %e, "failed to decode ospf packet");
                                }
                            },
                        }
                    }
                    Err(e) => warn!(link = %cfg.attach_point, error = %e, "ospf recv error"),
                }
            }
            () = tokio::time::sleep_until(p2p_dead_deadline), if !is_broadcast && !is_p2mp => {
                apply_dead_timer(&cfg, &status);
                p2p_dead_deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
            }
            _ = dead_sweep.tick() => {
                expire_grace(&cfg, &status);
                if !is_broadcast && !is_p2mp {
                    continue;
                }
                sweep_dead_neighbors(&cfg, &status);
                if is_broadcast && !waiting {
                    run_election(&cfg, local_router_id, &status);
                    sync_all_drouters(&socket, &cfg, &status);
                    advance_adjacencies(&socket, &cfg, local_router_id, &status, &mut next_seq);
                }
            }
            () = tokio::time::sleep_until(wait_deadline), if waiting => {
                waiting = false;
                run_election(&cfg, local_router_id, &status);
                sync_all_drouters(&socket, &cfg, &status);
                advance_adjacencies(&socket, &cfg, local_router_id, &status, &mut next_seq);
            }
            Some(command) = commands.recv() => match command {
                LinkCommand::Grace(grace_period) => {
                    send_grace_lsas(&socket, &cfg, local_router_id, &status, grace_period, &mut next_seq);
                }
                LinkCommand::FloodNow => {
                    flood_full_neighbors(&socket, &cfg, local_router_id, &lsdb, &link_local_lsdb, &status, &mut next_seq, &mut last_flood_dest).await;
                }
                LinkCommand::BfdDown(address) => kill_bfd_neighbor(&cfg, &status, address),
            },
            _ = rxmt_sweep.tick() => {
                flush_pending_acks(&socket, &cfg, local_router_id, &status, &mut next_seq);
                retransmit_pending(&socket, &cfg, local_router_id, &status, &mut next_seq);
                flood_full_neighbors(&socket, &cfg, local_router_id, &lsdb, &link_local_lsdb, &status, &mut next_seq, &mut last_flood_dest).await;
            }
        }
    }
}

/// A request from `LinkManager` to one link task.
#[derive(Debug, Clone, Copy)]
pub enum LinkCommand {
    /// Send Grace-LSAs (the grace period, seconds).
    Grace(u32),
    /// Resend the LSDB to every `Full` neighbor now, not on the next
    /// `RXMT_INTERVAL` — the shutdown path only (`LinkManager::flood_now`).
    FloodNow,
    /// `nos-bfdd` reports the path to this neighbor address down (RFC 2328
    /// §10.2 `KillNbr`).
    BfdDown(Ipv4Addr),
}

struct LinkEntry {
    config: LinkConfig,
    task: JoinHandle<()>,
    status: watch::Receiver<LinkStatus>,
    commands: mpsc::UnboundedSender<LinkCommand>,
    /// RFC 5250 type-9 (link-local) LSAs heard on this link — dropped with
    /// the entry when the link stops or restarts.
    link_local_lsdb: Arc<Mutex<Lsdb>>,
}

/// Owns every OSPF link's driver task for one `nos-ospfd` process, plus its
/// per-area LSDBs. `reconcile` is the sole entry point, called by
/// `crate::reconcile::run` on every resync; it's idempotent and safe to
/// call repeatedly with the same desired state — mirrors
/// `bgp::session::SessionManager`.
pub struct LinkManager {
    links: Mutex<HashMap<String, LinkEntry>>,
    /// The attach-point links of the last `reconcile`; `apply_links` adds
    /// the resolved virtual links to them.
    physical: Mutex<Vec<LinkConfig>>,
    /// Configured virtual links (`set_virtual_links`, every resync).
    virtual_links: Mutex<Vec<VirtualLinkConfig>>,
    /// The virtual links §16.7 last found up (`resolve_virtual_links`).
    resolved_virtual: Mutex<Vec<LinkConfig>>,
    /// Partitioned by area, not a single flat map — `OspfArea` is already
    /// multi-valued in this NOS's config schema, so a flat LSDB would leak
    /// LSAs across areas the moment a second one is configured.
    lsdbs: Mutex<HashMap<Ipv4Addr, Arc<Mutex<Lsdb>>>>,
    /// Woken by every LSDB change; see `route_changed`.
    route_changed: Arc<tokio::sync::Notify>,
    /// Woken when a neighbor floods one of our own LSAs back newer
    /// (`Lsdb::mark_reflected`), so origination runs at once.
    reoriginate: Arc<tokio::sync::Notify>,
    /// Set on every `reconcile` call, read by the background origination
    /// task started in `new`.
    router_id: Mutex<Option<Ipv4Addr>>,
    /// Loopback (`Interface.ospf_profile`) attach points' own subnets, per
    /// area — these have no live `LinkConfig`/socket (see `reconcile.rs`'s
    /// "log-only" loopback handling), so they're threaded in here directly
    /// rather than through `links`, purely so `originate_router_lsas` can
    /// advertise a real stub-network link for each one. Replaced wholesale
    /// on every `reconcile` call, like every other desired-state field.
    stub_networks: Mutex<HashMap<Ipv4Addr, Vec<(Ipv4Net, u16)>>>,
    /// Scales `AGE_TICK_INTERVAL`'s per-tick age-increment — always `1` (one
    /// simulated second per real second) outside of `tools/verify-e2e.sh`'s
    /// `ospf-aging` phase, which needs RFC 2328 §14's 1800s/3600s timers to
    /// resolve in seconds rather than tens of minutes. See `main.rs`'s
    /// `--lsa-age-multiplier`.
    age_multiplier: u16,
    /// RFC 2328 §10.8's per-DBD-packet LSA-header budget override, passed
    /// down into every link's `run()`. `None` (the real production default)
    /// derives the budget per-link from that link's own effective MTU
    /// (`exchange::mtu_based_max_headers`); `Some(n)` — set only by
    /// `tools/verify-e2e.sh`'s `ospf-dbd-pagination` phase, test/debug only —
    /// forces every link to the same fixed value regardless of MTU, to
    /// force multi-packet pagination deterministically over a small lab
    /// LSDB. See `main.rs`'s `--dbd-max-headers`.
    dbd_max_headers: Option<usize>,
    /// Source of RFC 7474 boot counts, one per extended-auth link (re)start.
    boots: crate::boot::BootCounter,
    /// Raw (pre-policy) redistributed prefixes from `OspfRequest::
    /// RedistributeRoutes`. A `HashSet`, not a map — the `RedistributedRoute`
    /// gateway is never used: this router always originates with
    /// `forwarding_address = 0.0.0.0`, so a redistributed route's own next-hop
    /// always comes from SPF's own computed next-hop to the ASBR, never from
    /// the raw route's gateway (see `AsExternalLsaBody`'s doc comment).
    redistribute_raw: Mutex<HashSet<Ipv4Net>>,
    /// Policy-filtered set actually originated as Type-5 LSAs. Recomputed by
    /// `set_redistribute_policy`, called every resync from `reconcile.rs`,
    /// mirroring `bgp::BgpRib::set_redistribute_policy`'s "called
    /// unconditionally, re-filters eagerly" contract.
    redistribute_filtered: Mutex<HashSet<Ipv4Net>>,
    /// `(metric, e_type2)` put in the Type-5/Type-7 LSAs of `redistribute_filtered`
    /// (`OspfInstance.redistribute_metric`/`_type`, set every resync).
    redistribute_metric: Mutex<(u32, bool)>,
    /// Set by `shutdown`: stops the origination tick from reoriginating the
    /// LSAs it just flushed while their `MaxAge` copies are still being
    /// flooded (`PREMATURE_AGE_FLOOD_WINDOW`). Aging keeps running.
    shutting_down: AtomicBool,
    /// RFC 3623 grace period (seconds) to announce on a planned restart;
    /// `0` = graceful restart off.
    grace_period: AtomicU16,
    /// RFC 6860: hide transit-only networks (`OspfInstance.prefix_suppression`).
    /// An instance-wide atomic rather than a `LinkConfig` field, so a toggle
    /// re-originates on the next tick without restarting any link.
    prefix_suppression: AtomicBool,
    /// RFC 8770 host router (`OspfInstance.host_router`): the Router-LSA's
    /// H-bit, with max-metric transit links. An atomic like
    /// `prefix_suppression`.
    host_router: AtomicBool,
    /// RFC 7490 remote LFA (`OspfInstance.remote_lfa`): `compute_routes`
    /// looks for a tunnel backup where there is no basic LFA.
    remote_lfa: AtomicBool,
    /// Each area's last RFC 8770 state — (H-bit honoured, routers with the
    /// H-bit) — only to log a change.
    host_bit_state: Mutex<HashMap<Ipv4Addr, (bool, usize)>>,
    /// Set by `announce_graceful_restart`: `shutdown` then keeps every
    /// self-originated LSA instead of flushing it (RFC 3623 §2).
    restarting: AtomicBool,
    /// RFC 6987 stub router (`OspfInstance.max_metric_*`), see
    /// `max_metric_active`.
    max_metric: std::sync::Mutex<MaxMetric>,
    /// Each configured area's stub/range settings (`OspfArea`), replaced on
    /// every resync; an area missing here is a normal area with no range.
    area_settings: Mutex<HashMap<Ipv4Addr, AreaSettings>>,
    /// Active advertised area ranges and their metric, rewritten by every
    /// `originate_summary_lsas` pass — `compute_routes` turns them into
    /// discard routes.
    active_ranges: Mutex<HashMap<Ipv4Net, u32>>,
    /// Each NSSA's last translator election result (RFC 3101 §3.1), only to
    /// log a change.
    nssa_translating: Mutex<HashMap<Ipv4Addr, bool>>,
    /// Each attach point's `bfd` profile (`set_bfd`, every resync); a link
    /// missing here has no BFD.
    bfd: std::sync::Mutex<HashMap<String, BfdProfile>>,
    opener: Opener,
}

/// RFC 6987 stub-router state. `std` mutex: never held across an await.
// Independent flags, each read on its own.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
struct MaxMetric {
    administrative: bool,
    /// On-shutdown hold, seconds (0 = off).
    on_shutdown: u8,
    /// End of the on-startup period, armed once by the first `set_max_metric`.
    until: Option<Instant>,
    /// The first `set_max_metric` call has happened.
    armed: bool,
    /// Respawned after a graceful restart (`boot::take_grace_marker`): the
    /// helpers kept the old topology, so on-startup is skipped.
    after_graceful_restart: bool,
    /// The last state logged by `max_metric_tick`.
    logged: bool,
}

/// One area's RFC 2328 §3.5/§3.6 and RFC 3101 settings, resolved from
/// `OspfArea`.
// Independent config flags, each read on its own.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AreaSettings {
    /// No AS-external LSAs (a stub area or an NSSA); as an ABR of a stub
    /// area, originate a default Type-3 into it.
    pub stub: bool,
    /// An RFC 3101 NSSA (`stub` is set too): Type-7s instead of Type-5s, and
    /// a default Type-3 from an ABR only without `import_summaries`.
    pub nssa: bool,
    /// RFC 2328 Appendix C.2 `ImportSummaries`: `false` (totally stubby,
    /// NSSA no-summary) sends only the default Type-3 into the area.
    pub import_summaries: bool,
    /// RFC 3101 `NSSATranslatorRole` `Always` (else `Candidate`).
    pub nssa_translate_always: bool,
    /// RFC 3101 §2.7: as an ABR, originate a default Type-7 into the NSSA.
    pub nssa_default_originate: bool,
    /// `StubDefaultCost`.
    pub default_cost: u32,
    /// `(range, advertise)`, applied to this area's prefixes when summarized
    /// into the other areas.
    pub ranges: Vec<(Ipv4Net, bool)>,
}

impl LinkManager {
    pub fn new(
        age_multiplier: u16,
        dbd_max_headers: Option<usize>,
        boots: crate::boot::BootCounter,
    ) -> Arc<Self> {
        Self::with_opener(
            age_multiplier,
            dbd_max_headers,
            boots,
            Arc::new(|cfg: &LinkConfig| {
                if cfg.virtual_link.is_some() {
                    OspfSocket::open_virtual(&cfg.kernel_interface, cfg.local_addr)
                } else {
                    OspfSocket::open(&cfg.kernel_interface, cfg.local_addr)
                }
                .map(LinkSocket::Os)
            }),
        )
    }

    /// `new` with the link sockets opened by `opener` instead of as real raw
    /// sockets — the in-memory wire in tests.
    pub fn with_opener(
        age_multiplier: u16,
        dbd_max_headers: Option<usize>,
        boots: crate::boot::BootCounter,
        opener: Opener,
    ) -> Arc<Self> {
        let manager = Arc::new(Self {
            links: Mutex::new(HashMap::new()),
            physical: Mutex::new(Vec::new()),
            virtual_links: Mutex::new(Vec::new()),
            resolved_virtual: Mutex::new(Vec::new()),
            lsdbs: Mutex::new(HashMap::new()),
            route_changed: Arc::new(tokio::sync::Notify::new()),
            reoriginate: Arc::new(tokio::sync::Notify::new()),
            router_id: Mutex::new(None),
            stub_networks: Mutex::new(HashMap::new()),
            age_multiplier,
            dbd_max_headers,
            boots,
            redistribute_raw: Mutex::new(HashSet::new()),
            redistribute_filtered: Mutex::new(HashSet::new()),
            redistribute_metric: Mutex::new((spf::DEFAULT_EXTERNAL_METRIC, false)),
            shutting_down: AtomicBool::new(false),
            grace_period: AtomicU16::new(0),
            prefix_suppression: AtomicBool::new(false),
            host_router: AtomicBool::new(false),
            remote_lfa: AtomicBool::new(false),
            host_bit_state: Mutex::new(HashMap::new()),
            restarting: AtomicBool::new(false),
            max_metric: std::sync::Mutex::new(MaxMetric::default()),
            area_settings: Mutex::new(HashMap::new()),
            active_ranges: Mutex::new(HashMap::new()),
            nssa_translating: Mutex::new(HashMap::new()),
            bfd: std::sync::Mutex::new(HashMap::new()),
            opener,
        });
        let background = Arc::clone(&manager);
        // Runs for the process's lifetime — like every link driver task, it
        // ends only when the tokio runtime itself is torn down at process
        // exit, so there's nothing to abort on shutdown.
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

    /// The `bfd` profile of each attach point that has one, replaced on every
    /// resync. Registrations follow; a link never restarts for it.
    pub fn set_bfd(&self, wanted: HashMap<String, BfdProfile>) {
        *self.bfd.lock().unwrap() = wanted;
    }

    pub fn set_prefix_suppression(&self, on: bool) {
        self.prefix_suppression.store(on, Ordering::Relaxed);
    }

    pub fn set_host_router(&self, on: bool) {
        self.host_router.store(on, Ordering::Relaxed);
    }

    pub fn set_remote_lfa(&self, on: bool) {
        self.remote_lfa.store(on, Ordering::Relaxed);
    }

    pub async fn set_area_settings(&self, settings: HashMap<Ipv4Addr, AreaSettings>) {
        *self.area_settings.lock().await = settings;
    }

    /// `area_id`'s settings — a normal area's when not configured.
    async fn area(&self, area_id: Ipv4Addr) -> AreaSettings {
        self.area_settings
            .lock()
            .await
            .get(&area_id)
            .cloned()
            .unwrap_or_default()
    }

    /// RFC 2328 A.4.2's B-bit test: a link or loopback stub in 2+ areas (not
    /// `lsdbs.len()`, which never shrinks after leaving an area).
    async fn is_area_border_router(&self) -> bool {
        self.attached_areas().await.len() >= 2
    }

    /// RFC 2328 §16.2: an ABR attached to the backbone (a virtual link
    /// counts, #37 D5) examines only the backbone's summaries.
    async fn is_backbone_abr(&self) -> bool {
        let areas = self.attached_areas().await;
        areas.len() >= 2 && areas.contains(&Ipv4Addr::UNSPECIFIED)
    }

    /// Every area this router has a link or loopback stub in, plus the
    /// backbone while a virtual link is configured.
    async fn attached_areas(&self) -> HashSet<Ipv4Addr> {
        let mut areas: HashSet<Ipv4Addr> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.config.area_id)
            .collect();
        areas.extend(self.stub_networks.lock().await.keys().copied());
        // RFC 2328 §15: a configured virtual link attaches us to the backbone.
        if !self.virtual_links.lock().await.is_empty() {
            areas.insert(Ipv4Addr::UNSPECIFIED);
        }
        areas
    }

    /// RFC 2328 §16.7's first hops toward each configured virtual link's
    /// endpoint, from its transit area's current LSDB: the next hops of the
    /// backbone SPF's type-4 edges (`spf::Context`).
    async fn virtual_next_hops(&self, router_id: Ipv4Addr) -> Vec<spf::VirtualNextHops> {
        let configured = self.virtual_links.lock().await.clone();
        let mut out = Vec::new();
        for v in configured {
            let Some(lsdb) = self.lsdbs.lock().await.get(&v.transit_area).cloned() else {
                continue;
            };
            let lsas = lsdb.lock().await.all();
            if let Some(end) = spf::virtual_link_endpoint(router_id, &lsas, v.endpoint) {
                out.push(spf::VirtualNextHops {
                    endpoint: v.endpoint,
                    next_hops: end.next_hops,
                });
            }
        }
        out
    }

    /// RFC 3101 §2.3: a Type-7's forwarding address — one of this router's
    /// own addresses in the NSSA (the lowest link address, else a loopback
    /// stub's), so a translator can translate it. RFC 6860 §4.1: with prefix
    /// suppression the link addresses are hidden, so only a loopback's.
    async fn nssa_forwarding_address(&self, area_id: Ipv4Addr) -> Ipv4Addr {
        let suppressed = self.prefix_suppression.load(Ordering::Relaxed);
        let link = self
            .links
            .lock()
            .await
            .values()
            .filter(|e| e.config.area_id == area_id && !suppressed)
            .map(|e| e.config.local_addr)
            .min();
        match link {
            Some(addr) => addr,
            None => self
                .stub_networks
                .lock()
                .await
                .get(&area_id)
                .and_then(|stubs| stubs.iter().map(|(net, _)| net.addr()).min())
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Gets or creates the shared LSDB for `area_id`.
    async fn lsdb_for(&self, area_id: Ipv4Addr) -> Arc<Mutex<Lsdb>> {
        Arc::clone(self.lsdbs.lock().await.entry(area_id).or_insert_with(|| {
            Arc::new(Mutex::new(
                Lsdb::with_notify(Arc::clone(&self.route_changed))
                    .with_reflect_notify(Arc::clone(&self.reoriginate)),
            ))
        }))
    }

    /// RFC 2328 §14: ages every installed LSA, in every area, by one
    /// (simulated) second times `age_multiplier`, evicting anything that
    /// reaches `MAX_AGE`. Run every `AGE_TICK_INTERVAL`, independent of
    /// `originate_router_lsas` — aging is LSDB-wide, not per-link.
    async fn age_lsdbs(&self) {
        // RFC 3623 §3.1: a restarting neighbor's LSAs are kept until its grace
        // period ends.
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
        let mut stores: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        stores.extend(self.link_local_lsdbs().await);
        for (area_id, lsdb) in stores {
            let evicted = lsdb.lock().await.age_and_evict(self.age_multiplier, &hold);
            for key in evicted {
                info!(
                    area = %area_id, lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
                    advertising_router = %key.advertising_router,
                    "ospf lsa maxage flushed"
                );
            }
        }
    }

    /// Diffs `desired` against currently-running links by `attach_point`:
    /// links no longer desired, or whose resolved fields changed, are
    /// stopped (and, if still desired with new fields, respawned); newly
    /// desired links are spawned. A link whose driver task ended on its own
    /// (e.g. the raw socket failed to open) is treated as "not currently
    /// running" so this pass respawns it too — the same periodic re-apply
    /// tick that re-resolves a not-yet-ready VRF/interface also recovers
    /// from a transient socket failure this way.
    pub async fn reconcile(
        self: &Arc<Self>,
        desired: Vec<LinkConfig>,
        desired_stubs: HashMap<Ipv4Addr, Vec<(Ipv4Net, u16)>>,
        local_router_id: Ipv4Addr,
    ) {
        *self.router_id.lock().await = Some(local_router_id);
        *self.stub_networks.lock().await = desired_stubs;
        *self.physical.lock().await = desired;
        self.apply_links(local_router_id).await;
    }

    /// Configured virtual links, every resync; §16.7 brings each one up or
    /// down on the origination tick (`resolve_virtual_links`).
    pub async fn set_virtual_links(&self, virtual_links: Vec<VirtualLinkConfig>) {
        *self.virtual_links.lock().await = virtual_links;
    }

    /// RFC 2328 §16.7, after the transit areas' SPF (rerun here, on every
    /// origination tick): a virtual link whose endpoint is reachable is up
    /// at the path's cost, else down. A change starts, restarts (address)
    /// or stops its link task; a cost change alone is applied in place.
    async fn resolve_virtual_links(&self, local_router_id: Ipv4Addr) {
        let configured = self.virtual_links.lock().await.clone();
        if !configured.is_empty() {
            // Backbone-attached as soon as one is configured (#37 D5).
            self.lsdb_for(Ipv4Addr::UNSPECIFIED).await;
        }
        let physical = self.physical.lock().await.clone();
        let mut resolved = Vec::new();
        for v in &configured {
            let Some(lsdb) = self.lsdbs.lock().await.get(&v.transit_area).cloned() else {
                continue;
            };
            let lsas = lsdb.lock().await.all();
            resolved.extend(resolve_virtual_link(v, local_router_id, &lsas, &physical));
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
                    link = %r.attach_point, neighbor = %v.neighbor, local = %r.local_addr, cost = r.cost,
                    "ospf virtual link up"
                );
            }
        }
        for p in previous.iter() {
            if !resolved.iter().any(|r| r.attach_point == p.attach_point) {
                info!(link = %p.attach_point, "ospf virtual link down");
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
                info!(link = %key, "ospf link stopped");
                entry.task.abort();
            }
        }
        // A cost-only change (a virtual link's SPF distance, a profile's
        // cost) is a Router-LSA metric, not a reason to restart the link.
        for (key, entry) in links.iter_mut() {
            if let Some(wanted) = desired_map.get(key) {
                entry.config.cost = wanted.cost;
            }
        }
        for cfg in to_spawn {
            let key = cfg.attach_point.clone();
            let lsdb = self.lsdb_for(cfg.area_id).await;
            let (status_tx, status_rx) = watch::channel(LinkStatus::new(cfg.network_type));
            // A fresh boot count per (re)start keeps RFC 7474 sequence numbers
            // increasing across link restarts inside one process too.
            let boot_count = if cfg.auth.is_extended() {
                self.boots.next()
            } else {
                0
            };
            let (commands, commands_rx) = mpsc::unbounded_channel();
            let link_local_lsdb = Arc::new(Mutex::new(
                Lsdb::with_notify(Arc::clone(&self.route_changed))
                    .with_reflect_notify(Arc::clone(&self.reoriginate)),
            ));
            let task = tokio::spawn(run(
                (self.opener)(&cfg),
                cfg.clone(),
                local_router_id,
                lsdb,
                Arc::clone(&link_local_lsdb),
                status_tx,
                self.dbd_max_headers,
                boot_count,
                commands_rx,
            ));
            links.insert(
                key,
                LinkEntry {
                    config: cfg,
                    task,
                    status: status_rx,
                    commands,
                    link_local_lsdb,
                },
            );
        }
    }

    /// The loopback stub networks of the last `reconcile` (tests).
    #[cfg(test)]
    pub(crate) async fn stub_networks(&self) -> HashMap<Ipv4Addr, Vec<(Ipv4Net, u16)>> {
        self.stub_networks.lock().await.clone()
    }

    /// The config a running link was started with (`None` once stopped), so
    /// `reconcile` can keep a link whose VRF/address lookup fails this pass.
    pub async fn running_config(&self, attach_point: &str) -> Option<LinkConfig> {
        let links = self.links.lock().await;
        let entry = links.get(attach_point)?;
        (!entry.task.is_finished()).then(|| entry.config.clone())
    }

    /// Every currently-configured link's current neighbor summaries, for
    /// `server.rs`'s `OspfRequest::GetNeighbors` handler — backs `nos-cli`'s
    /// `show ospf neigh`. One row per point-to-point link (even with no
    /// neighbor yet); one row per currently-known neighbor on a broadcast
    /// link (zero if none yet).
    pub async fn neighbor_summaries(&self) -> Vec<NeighborSummary> {
        self.links
            .lock()
            .await
            .values()
            .flat_map(to_neighbor_summaries)
            .collect()
    }

    /// Every link's type-9 store, with the link's area.
    async fn link_local_lsdbs(&self) -> Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> {
        self.links
            .lock()
            .await
            .values()
            .map(|e| (e.config.area_id, Arc::clone(&e.link_local_lsdb)))
            .collect()
    }

    /// Every installed LSA's header, across every area and every link's
    /// type-9 store (listed under the link's area), for `server.rs`'s
    /// `OspfRequest::GetDatabase` handler — backs `nos-cli`'s
    /// `show ospf database`.
    pub async fn database_summaries(&self) -> Vec<LsaSummary> {
        let mut result = Vec::new();
        let mut stores: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(area_id, lsdb)| (*area_id, Arc::clone(lsdb)))
            .collect();
        stores.extend(self.link_local_lsdbs().await);
        for (area_id, lsdb) in &stores {
            for lsa in lsdb.lock().await.all() {
                let header = &lsa.header;
                let (external_metric, external_type2) = match &lsa.body {
                    LsaBody::AsExternal(e) => (Some(e.metric), e.e_type2),
                    _ => (None, false),
                };
                let (router_flags, virtual_links) = match &lsa.body {
                    LsaBody::Router(r) => (
                        Some(r.flags),
                        r.links
                            .iter()
                            .filter(|l| l.link_type == LINK_TYPE_VIRTUAL)
                            .map(|l| l.link_id)
                            .collect(),
                    ),
                    _ => (None, Vec::new()),
                };
                result.push(LsaSummary {
                    area_id: *area_id,
                    lsa_type: header.lsa_type,
                    link_state_id: header.link_state_id,
                    advertising_router: header.advertising_router,
                    sequence_number: header.sequence_number,
                    age: header.age,
                    checksum: header.checksum,
                    external_metric,
                    external_type2,
                    router_flags,
                    virtual_links,
                });
            }
        }
        result
    }

    /// Woken (one stored permit) whenever any LSDB changes, so a consumer of
    /// `compute_routes` need not poll.
    pub fn route_changed(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.route_changed)
    }

    /// Runs `crate::spf::compute` against every area's current LSDB and
    /// merges the results into one route set, for `crate::rib_push_client`.
    /// A router attached to 2+ areas (an ABR, see `originate_summary_lsas`)
    /// can now legitimately compute the same destination prefix from more
    /// than one area's own LSDB (e.g. via a summarized inter-area path in
    /// one area and a direct path in another) — keeps whichever is cheaper,
    /// and unions the next hops of an equal-cost pair (`spf::merge_equal`),
    /// the same tie-break `spf::insert_best` already applies within one
    /// area. Empty if `router_id` hasn't been set yet (before this
    /// instance's first `reconcile` call).
    pub async fn compute_routes(&self) -> Vec<spf::RouteEntry> {
        let Some(router_id) = *self.router_id.lock().await else {
            return Vec::new();
        };
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(id, lsdb)| (*id, Arc::clone(lsdb)))
            .collect();
        let backbone_abr = self.is_backbone_abr().await;
        let virtual_hops = self.virtual_next_hops(router_id).await;
        let mut merged: HashMap<Ipv4Net, spf::RouteEntry> = HashMap::new();
        // The prefixes whose route is the backbone's, which §16.3 may improve.
        let mut backbone_routes: HashSet<Ipv4Net> = HashSet::new();
        let mut transit: Vec<spf::RouteEntry> = Vec::new();
        for (area_id, lsdb) in areas {
            let backbone = area_id.is_unspecified();
            let mut lsas = lsdb.lock().await.all();
            // A Type-5 still held from before the area turned stub, or a
            // Type-7 from before it stopped being an NSSA (until it ages
            // out), is not a route there.
            let area = self.area(area_id).await;
            lsas.retain(|l| lsa::in_area_scope(l.header.lsa_type, area.stub, area.nssa));
            let state = (
                spf::host_bit_honoured(&lsas),
                spf::h_bit_routers(&lsas).len(),
            );
            if self.host_bit_state.lock().await.insert(area_id, state) != Some(state) {
                info!(area = %area_id, honoured = state.0, host_routers = state.1, "ospf host-bit state changed");
            }
            let ctx = spf::Context {
                backbone,
                skip_summaries: backbone_abr && !backbone,
                virtual_links: &virtual_hops,
                remote_lfa: self.remote_lfa.load(Ordering::Relaxed),
            };
            for entry in spf::compute_in(router_id, &lsas, &ctx) {
                let prefix = entry.prefix;
                match merged.get_mut(&prefix) {
                    None => {
                        merged.insert(prefix, entry);
                    }
                    Some(existing) => match spf::prefer(&entry, existing) {
                        std::cmp::Ordering::Less => *existing = entry,
                        std::cmp::Ordering::Equal => {
                            spf::merge_equal(existing, entry);
                            continue;
                        }
                        std::cmp::Ordering::Greater => continue,
                    },
                }
                if backbone {
                    backbone_routes.insert(prefix);
                } else {
                    backbone_routes.remove(&prefix);
                }
            }
            if ctx.skip_summaries {
                transit.extend(spf::transit_summaries(router_id, &lsas));
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
        // RFC 2328 §3.5: a discard route per active advertised range, so
        // traffic to an unused part of it is dropped here rather than looping
        // on a covering route — unless SPF has a real route for exactly it.
        for (&range, &metric) in self.active_ranges.lock().await.iter() {
            merged
                .entry(range)
                .or_insert_with(|| spf::RouteEntry::discard(range, metric));
        }
        merged.into_values().collect()
    }

    async fn send_to_links(&self, command: LinkCommand) {
        for entry in self.links.lock().await.values() {
            let _ = entry.commands.send(command);
        }
    }

    /// Has every link resend its LSDB to its `Full` neighbors now.
    async fn flood_now(&self) {
        self.send_to_links(LinkCommand::FloodNow).await;
    }

    /// Graceful shutdown: flushes every self-originated LSA (RFC 2328
    /// §14.1) — unless a graceful restart was announced, which must keep
    /// them (RFC 3623 §2) — and keeps the link tasks alive for `PREMATURE_AGE_FLOOD_WINDOW`
    /// so their periodic resend carries the `MaxAge` copies to every neighbor
    /// — which then drops this router's routes at once instead of only when
    /// its LSAs age out an hour later — then aborts every link task. Called
    /// once when `crate::reconcile::run`'s loop exits on shutdown.
    pub async fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        let restarting = self.restarting.load(Ordering::Relaxed);
        if !restarting {
            self.max_metric_on_shutdown().await;
        }
        let withdrawn = if restarting {
            0
        } else {
            self.withdraw_all_self_originated().await
        };
        if withdrawn > 0 {
            info!(
                withdrawn,
                "ospf flushing self-originated lsas before shutdown"
            );
            self.flood_now().await;
            tokio::time::sleep(PREMATURE_AGE_FLOOD_WINDOW).await;
        }
        for (_, entry) in self.links.lock().await.drain() {
            entry.task.abort();
        }
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

fn to_neighbor_summaries(entry: &LinkEntry) -> Vec<NeighborSummary> {
    let status = entry.status.borrow().clone();
    let interface_state = to_interface_state(status.interface_state);

    if status.neighbors.is_empty() {
        // A point-to-point link always reports a row, even with no
        // neighbor yet; a broadcast link has no single fixed peer to show
        // a placeholder for.
        if entry.config.network_type != NetworkType::PointToPoint {
            return Vec::new();
        }
        return vec![NeighborSummary {
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
        }];
    }

    status
        .neighbors
        .iter()
        .map(|(id, info)| NeighborSummary {
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
        })
        .collect()
}

/// Equal in every field but `cost`, which `apply_links` updates in place.
fn same_but_cost(a: &LinkConfig, b: &LinkConfig) -> bool {
    *a == LinkConfig {
        cost: a.cost,
        ..b.clone()
    }
}

/// Pure diffing, like `bgp::session::diff_peers`.
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

/// `nos-ospfd`'s side of `crate::bfd_client`: one session per neighbor at
/// 2-Way or later on a link with a `bfd` profile (on a broadcast link too,
/// not one per link).
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
                        IpAddr::V4(n.address),
                        Want {
                            profile: profile.clone(),
                            local: Some(IpAddr::V4(entry.config.local_addr)),
                            interface: None,
                        },
                    );
                }
            }
        }
        target
    }

    async fn down(&self, peer: IpAddr, diag: BfdDiag) {
        let IpAddr::V4(peer) = peer else { return };
        info!(peer = %peer, diag = %diag, "ospf: bfd session down");
        for entry in self.links.lock().await.values() {
            let _ = entry.commands.send(LinkCommand::BfdDown(peer));
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
