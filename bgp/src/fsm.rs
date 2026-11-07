//! RFC 4271 BGP finite state machine, restricted to the states that need
//! message exchange: `OpenSent`, `OpenConfirm`, `Established`. Idle/Connect/
//! Active remain `session.rs`'s existing retry-loop behavior (no task yet,
//! or a connect attempt in flight/backing off) — `fsm::run` is spawned only
//! once a `TcpStream` already exists, on both the active-connect success
//! path and the passive-accept path, replacing what used to be
//! `session::hold_until_closed`.
//!
//! `step` is the pure transition core (state + event -> next state +
//! actions), kept separate from the async orchestrator (`run`) so it can be
//! unit-tested directly without any I/O.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use nos_proto::{AddressFamily, NextHopMode, HOLD_TIME_FLOOR};

use crate::collision::{self, FsmCommand, PeerSlot};
use crate::gr::{self, Disconnect, PeerGr};
use crate::message::{
    self, BgpCodec, BgpMessage, CeaseSubcode, ErrorCode, FsmSubcode, MessageHeaderSubcode,
    NotificationMessage, OpenMessage, OpenMessageSubcode, RouteRefreshMessage,
    UpdateMessageSubcode, WireError,
};
use crate::rib::{OutboundUpdate, OutboxTx, SharedRib};
use crate::session::{LocalIdentity, PeerKind};
use crate::status::{PeerState, PeerStatus};

/// RFC 4760/8950 AFI values this crate understands.
const AFI_IPV4: u16 = 1;
const AFI_IPV6: u16 = 2;

/// Holds the peer down and queues the RFC 4486 Cease. Callers check
/// `max_prefix_held` first so only one Cease is ever queued.
pub(crate) fn trip_max_prefix(
    slot: &PeerSlot,
    family: AddressFamily,
    limit: nos_proto::BgpPrefixLimit,
) {
    slot.trip_max_prefix(limit.restart_interval);
    slot.send_command(FsmCommand::Cease {
        subcode: CeaseSubcode::MaximumPrefixesReached,
        data: message::encode_max_prefix_data(afi_of(family), safi_of(family), limit.limit),
    });
}

fn afi_of(family: AddressFamily) -> u16 {
    match family {
        AddressFamily::Ipv4Unicast
        | AddressFamily::Ipv4Flowspec
        | AddressFamily::Vpnv4Unicast
        | AddressFamily::RtConstraint => AFI_IPV4,
        AddressFamily::Ipv6Unicast | AddressFamily::Ipv6Flowspec | AddressFamily::Vpnv6Unicast => {
            AFI_IPV6
        }
        AddressFamily::L2vpnEvpn => message::AFI_L2VPN,
    }
}

/// The wire SAFI of `family`.
fn safi_of(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::Ipv4Unicast | AddressFamily::Ipv6Unicast => 1,
        AddressFamily::L2vpnEvpn => message::SAFI_EVPN,
        AddressFamily::Ipv4Flowspec | AddressFamily::Ipv6Flowspec => message::SAFI_FLOWSPEC,
        AddressFamily::Vpnv4Unicast | AddressFamily::Vpnv6Unicast => message::SAFI_VPN,
        AddressFamily::RtConstraint => message::SAFI_RTC,
    }
}

/// VPNv4/VPNv6 (SAFI 128).
pub(crate) fn is_vpn(family: AddressFamily) -> bool {
    matches!(
        family,
        AddressFamily::Vpnv4Unicast | AddressFamily::Vpnv6Unicast
    )
}

/// Unicast (SAFI 1) families: the only ones RFC 8950 Extended Next Hop and
/// RFC 7911 ADD-PATH apply to here.
fn is_unicast(family: AddressFamily) -> bool {
    safi_of(family) == 1
}

fn afi_of_addr(addr: IpAddr) -> u16 {
    match addr {
        IpAddr::V4(_) => AFI_IPV4,
        IpAddr::V6(_) => AFI_IPV6,
    }
}

/// The `AddressFamily` a `ROUTE_REFRESH`'s wire AFI names, if it's one this
/// crate understands.
fn family_of_afi(afi: u16) -> Option<AddressFamily> {
    match afi {
        AFI_IPV4 => Some(AddressFamily::Ipv4Unicast),
        AFI_IPV6 => Some(AddressFamily::Ipv6Unicast),
        _ => None,
    }
}

/// Builds the `MultiProtocol`/`ExtendedNextHop` capabilities this session's
/// own OPEN should advertise, from its peer-group's configured
/// `address_families` and this session's own transport AFI. RFC 8950: an AF
/// that doesn't match the transport family needs the Extended Next Hop
/// capability too, since its next-hop will be this session's own
/// (cross-family) local address; a same-family AF never needs it.
fn build_mp_capabilities(
    address_families: &[AddressFamily],
    transport_afi: u16,
) -> Vec<message::Capability> {
    let mut caps = Vec::new();
    for &af in address_families {
        let afi = afi_of(af);
        caps.push(message::Capability::MultiProtocol {
            afi,
            safi: safi_of(af),
        });
        // RFC 8950 is about unicast NLRI carried with a cross-family
        // next-hop; EVPN's and Flowspec's next-hop family is independent of
        // their NLRI.
        if is_unicast(af) && afi != transport_afi {
            caps.push(message::Capability::ExtendedNextHop {
                nlri_afi: afi,
                nlri_safi: 1,
                nh_afi: transport_afi,
            });
        }
    }
    caps
}

/// Negotiates which address families this session actually carries, from the
/// peer's OPEN capabilities and this session's own configured
/// `address_families`/transport AFI. Returns `(mp_bgp_negotiated,
/// negotiated_ipv4_unicast, negotiated_ipv6_unicast, negotiated_evpn)` — bools rather
/// than a generic set, since exactly two `AddressFamily` variants exist
/// today and this keeps `RemoteInfo`/`Action` cheaply `Copy`.
///
/// If the peer never sent any Multiprotocol Extensions capability at all
/// (`mp_bgp_negotiated == false`), only plain IPv4 unicast is possible, and
/// only when this session's own transport is IPv4 too — the legacy wire
/// format has no way to carry anything else. Otherwise, an AF is negotiated
/// only if both sides advertised it, and — when its family doesn't match the
/// transport family — only if the peer also advertised the matching
/// Extended Next Hop tuple.
fn negotiate_address_families(
    open: &OpenMessage,
    ctx: &NegotiationContext,
) -> (bool, bool, bool, bool) {
    let peer_mp: HashSet<(u16, u8)> = open
        .capabilities
        .iter()
        .filter_map(|c| match c {
            message::Capability::MultiProtocol { afi, safi } => Some((*afi, *safi)),
            _ => None,
        })
        .collect();
    let peer_ext_nh: HashSet<(u16, u16, u16)> = open
        .capabilities
        .iter()
        .filter_map(|c| match c {
            message::Capability::ExtendedNextHop {
                nlri_afi,
                nlri_safi,
                nh_afi,
            } => Some((*nlri_afi, *nlri_safi, *nh_afi)),
            _ => None,
        })
        .collect();
    let mp_bgp_negotiated = !peer_mp.is_empty();

    let configured = |afi: u16| {
        ctx.address_families
            .iter()
            .any(|af| is_unicast(*af) && afi_of(*af) == afi)
    };
    let negotiated = |afi: u16| -> bool {
        if !configured(afi) {
            return false;
        }
        if !mp_bgp_negotiated {
            return afi == AFI_IPV4 && ctx.transport_afi == AFI_IPV4;
        }
        peer_mp.contains(&(afi, 1))
            && (afi == ctx.transport_afi || peer_ext_nh.contains(&(afi, 1, ctx.transport_afi)))
    };
    // EVPN needs no Extended Next Hop tuple, and has no legacy (non-MP) form.
    let evpn = ctx.address_families.contains(&AddressFamily::L2vpnEvpn)
        && peer_mp.contains(&(message::AFI_L2VPN, message::SAFI_EVPN));
    (
        mp_bgp_negotiated,
        negotiated(AFI_IPV4),
        negotiated(AFI_IPV6),
        evpn,
    )
}

/// A non-unicast SAFI per AFI, `[ipv4, ipv6]`: negotiated when both sides
/// advertise the tuple. Like EVPN it needs no Extended Next Hop (its next-hop
/// family is independent of the transport) and has no legacy (non-MP) form.
fn negotiate_safi(
    open: &OpenMessage,
    ctx: &NegotiationContext,
    safi: u8,
    families: [AddressFamily; 2],
) -> [bool; 2] {
    let peer_has = |afi: u16| {
        open.capabilities.iter().any(|c| {
            matches!(c, message::Capability::MultiProtocol { afi: a, safi: s }
                if *a == afi && *s == safi)
        })
    };
    [AFI_IPV4, AFI_IPV6]
        .into_iter()
        .zip(families)
        .map(|(afi, af)| ctx.address_families.contains(&af) && peer_has(afi))
        .collect::<Vec<_>>()
        .try_into()
        .expect("two AFIs")
}

/// Flowspec (RFC 8955/8956) per AFI, `[ipv4, ipv6]`.
fn negotiate_flowspec(open: &OpenMessage, ctx: &NegotiationContext) -> [bool; 2] {
    negotiate_safi(
        open,
        ctx,
        message::SAFI_FLOWSPEC,
        [AddressFamily::Ipv4Flowspec, AddressFamily::Ipv6Flowspec],
    )
}

/// VPNv4/VPNv6 (RFC 4364/4659) per AFI, `[vpnv4, vpnv6]`.
fn negotiate_vpn(open: &OpenMessage, ctx: &NegotiationContext) -> [bool; 2] {
    negotiate_safi(
        open,
        ctx,
        message::SAFI_VPN,
        [AddressFamily::Vpnv4Unicast, AddressFamily::Vpnv6Unicast],
    )
}

/// RFC 4684 Route Target Constraint (AFI 1 / SAFI 132, IPv4 only; the
/// capability is the plain Multiprotocol one, section 5).
fn negotiate_rtc(open: &OpenMessage, ctx: &NegotiationContext) -> bool {
    negotiate_safi(
        open,
        ctx,
        message::SAFI_RTC,
        [AddressFamily::RtConstraint, AddressFamily::RtConstraint],
    )[0]
}

/// RFC 7911 §5, for one unicast family of one session: whether received
/// NLRI carry a Path Identifier (`rx`) and whether ours must (`tx`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct AddPathDir {
    rx: bool,
    tx: bool,
}

impl AddPathDir {
    fn as_str(self) -> &'static str {
        match (self.rx, self.tx) {
            (false, false) => "none",
            (true, false) => "receive",
            (false, true) => "send",
            (true, true) => "both",
        }
    }
}

/// RFC 7911 §5: per family (`[ipv4, ipv6]`), we receive path ids iff we
/// offered 1 or 3 and the peer 2 or 3, and send them iff we offered 2 or 3
/// and the peer 1 or 3. Only unicast (SAFI 1) tuples count, and only for a
/// family this session is configured with. A tuple with a Send/Receive value
/// outside 1..=3 makes the whole capability "not understood" (§4), so
/// nothing is negotiated.
fn negotiate_add_path(open: &OpenMessage, ctx: &NegotiationContext) -> [AddPathDir; 2] {
    let none = [AddPathDir::default(); 2];
    let Some(mode) = ctx.add_path else {
        return none;
    };
    let tuples: Vec<&message::AddPathTuple> = open
        .capabilities
        .iter()
        .filter_map(|c| match c {
            message::Capability::AddPath(tuples) => Some(tuples.iter()),
            _ => None,
        })
        .flatten()
        .collect();
    if tuples.iter().any(|t| !(1..=3).contains(&t.send_receive)) {
        return none;
    }
    let ours = mode.send_receive();
    let dir = |afi: u16| {
        let configured = ctx
            .address_families
            .iter()
            .any(|af| is_unicast(*af) && afi_of(*af) == afi);
        let theirs = tuples
            .iter()
            .rev()
            .find(|t| t.afi == afi && t.safi == 1)
            .map(|t| t.send_receive);
        match theirs {
            Some(theirs) if configured => AddPathDir {
                rx: ours & 1 != 0 && theirs & 2 != 0,
                tx: ours & 2 != 0 && theirs & 1 != 0,
            },
            _ => AddPathDir::default(),
        }
    };
    [dir(AFI_IPV4), dir(AFI_IPV6)]
}

/// RFC 4271's own suggested `ConnectRetryTimer` default. Replaces
/// `session.rs`'s previous placeholder (30s), which was explicitly
/// documented as standing in "until the BGP FSM exists." Used by
/// `reconcile::resync` as the fallback when a peer-group leaves
/// `connect_retry_time` unset.
pub const CONNECT_RETRY_TIME: Duration = Duration::from_secs(120);

/// The peer identity this connection is being validated against —
/// `expected_remote_as` is compared against the real ASN extracted from the
/// peer's OPEN (see `message::effective_remote_asn`). `local_hold_time`/
/// `keepalive_override` come from the peer's `BgpPeerGroup` (already
/// defaulted by `reconcile::resync` — see `nos_proto::HOLD_TIME_DEFAULT`).
pub struct PeerContext {
    pub remote_address: IpAddr,
    pub expected_remote_as: u32,
    pub local_hold_time: u16,
    pub keepalive_override: Option<u16>,
    /// The peer-group's MRAI; zero means unpaced (see `crate::mrai`).
    pub mrai: Duration,
    /// The peer-group's RFC 7313 §4 stale-route bound; zero disables it.
    pub route_refresh_stale_time: Duration,
    /// The peer-group's RFC 2439 flap damping, if enabled (see `crate::damping`).
    pub damping: Option<nos_proto::BgpDamping>,
    /// The peer-group's configured next-hop override, if any — `None` lets
    /// `crate::rib::build_advertisement` fall back to the eBGP/iBGP-dependent
    /// default.
    pub next_hop: Option<NextHopMode>,
    /// The peer-group's configured address families — independent of
    /// `remote_address`'s own family (RFC 8950), see
    /// `build_mp_capabilities`/`negotiate_address_families`.
    pub address_families: Vec<AddressFamily>,
    /// RFC 4456 route-reflector client — passed straight through to
    /// `crate::rib::BgpRib::peer_established`, no FSM-level effect.
    pub is_rr_client: bool,
    /// RFC 7947 route-server client — gates whether this session's own OPEN
    /// advertises the RFC 7911 ADD-PATH capability at all (see `run`) and is
    /// passed through to `BgpRib::peer_established`.
    pub is_rs_client: bool,
    /// This peer's resolved import policy — passed straight through to
    /// every `BgpRib::handle_update` call on this connection, no FSM-level
    /// effect. `deny-all` by default (see root `CLAUDE.md`'s "Default-deny
    /// rollout impact").
    pub import_policy: Arc<nos_rpl::CompiledPolicy>,
    /// Same default-deny semantics as `import_policy`, passed through to
    /// `BgpRib::peer_established` for advertisement instead of receipt.
    pub export_policy: Arc<nos_rpl::CompiledPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // each bool is an independently-negotiated capability
struct RemoteInfo {
    asn: u32,
    bgp_id: Ipv4Addr,
    mp_bgp_negotiated: bool,
    negotiated_ipv4_unicast: bool,
    negotiated_ipv6_unicast: bool,
    negotiated_evpn: bool,
    /// Flowspec negotiated, `[ipv4, ipv6]` (`negotiate_flowspec`).
    negotiated_flowspec: [bool; 2],
    /// VPNv4/VPNv6 negotiated, `[vpnv4, vpnv6]` (`negotiate_vpn`).
    negotiated_vpn: [bool; 2],
    /// RFC 4684 Route Target Constraint negotiated (`negotiate_rtc`).
    negotiated_rtc: bool,
    /// RFC 7911 ADD-PATH per family, `[ipv4, ipv6]` (`negotiate_add_path`).
    add_path: [AddPathDir; 2],
    /// The peer sent the four-octet AS capability (RFC 6793); `false` means
    /// 2-byte `AS_PATH` + `AS4_PATH` in both directions.
    four_octet_as: bool,
    /// The peer sent the RFC 8654 Extended Message capability (we always do).
    extended_message: bool,
    /// The peer sent the RFC 7313 Enhanced Route Refresh capability (we always do).
    enhanced_refresh: bool,
    /// The peer sent the RFC 2918 Route Refresh capability: without it we
    /// must never send it a `ROUTE_REFRESH`.
    route_refresh: bool,
    /// The peer's RFC 4724 graceful restart capability, if it sent one.
    gr: Option<PeerGr>,
    /// Our RFC 9234 role toward the peer, when both sides announced a legal
    /// pair (`negotiate_role`).
    role: Option<nos_proto::BgpRole>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    OpenSent,
    OpenConfirm(RemoteInfo),
    Established(RemoteInfo),
}

#[derive(Debug)]
enum Event {
    OpenReceived(OpenMessage),
    KeepaliveReceived,
    NotificationReceived(NotificationMessage),
    MalformedMessage(WireError),
    HoldTimerExpires,
    KeepaliveTimerExpires,
    TcpFailed,
    CollisionLost,
    /// UPDATE (or End-of-RIB) before Established: RFC 4271 §8.2.2 FSM error.
    UnexpectedUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    SendKeepalive,
    SendNotification(u8, u8),
    /// `Duration::ZERO` disarms the timer entirely (RFC 4271 allows a
    /// negotiated hold time of 0, meaning no keepalives and no expiry).
    ArmHoldTimer(Duration),
    ArmKeepaliveTimer(Duration),
    ReportEstablished {
        remote_asn: u32,
        remote_bgp_id: Ipv4Addr,
        mp_bgp_negotiated: bool,
        negotiated_ipv4_unicast: bool,
        negotiated_ipv6_unicast: bool,
        negotiated_evpn: bool,
        negotiated_flowspec: [bool; 2],
        negotiated_vpn: [bool; 2],
        negotiated_rtc: bool,
        add_path: [AddPathDir; 2],
        four_octet_as: bool,
        extended_message: bool,
        route_refresh: bool,
        enhanced_refresh: bool,
        gr: Option<PeerGr>,
        role: Option<nos_proto::BgpRole>,
    },
    Close,
}

struct NegotiationContext {
    expected_remote_as: u32,
    local_hold_time: u16,
    keepalive_override: Option<u16>,
    address_families: Vec<AddressFamily>,
    transport_afi: u16,
    /// The ADD-PATH mode this session offers (`ResolvedPeer::add_path`);
    /// `None` offers nothing, so the peer's capability is irrelevant.
    add_path: Option<nos_proto::BgpAddPath>,
    /// The RFC 9234 role this session announces (`ResolvedPeer::role`).
    role: Option<nos_proto::BgpRole>,
    /// RFC 9234 §4.2 strict mode: a peer with no Role capability is refused.
    strict_mode: bool,
}

/// RFC 9234 §4.2: the peer's Role must be our role's counterpart (Table 2).
/// `Err` is Role Mismatch; `Ok(None)` means no role negotiated (we have none,
/// or the peer sent none and strict mode is off).
fn negotiate_role(
    open: &OpenMessage,
    ctx: &NegotiationContext,
) -> Result<Option<nos_proto::BgpRole>, ()> {
    let Some(ours) = ctx.role else {
        return Ok(None);
    };
    match message::peer_role(open) {
        None if ctx.strict_mode => Err(()),
        None => Ok(None),
        Some(v) if nos_proto::BgpRole::from_wire(v) == Some(ours.counterpart()) => Ok(Some(ours)),
        Some(_) => Err(()),
    }
}

/// Pure state transition core — the unit-test surface for this module.
fn step(state: State, event: Event, ctx: &NegotiationContext) -> (Option<State>, Vec<Action>) {
    match (state, event) {
        (State::OpenSent, Event::OpenReceived(open)) => handle_open(&open, ctx),
        (State::OpenConfirm(remote), Event::KeepaliveReceived) => (
            Some(State::Established(remote)),
            vec![Action::ReportEstablished {
                remote_asn: remote.asn,
                remote_bgp_id: remote.bgp_id,
                mp_bgp_negotiated: remote.mp_bgp_negotiated,
                negotiated_ipv4_unicast: remote.negotiated_ipv4_unicast,
                negotiated_ipv6_unicast: remote.negotiated_ipv6_unicast,
                negotiated_evpn: remote.negotiated_evpn,
                negotiated_flowspec: remote.negotiated_flowspec,
                negotiated_vpn: remote.negotiated_vpn,
                negotiated_rtc: remote.negotiated_rtc,
                add_path: remote.add_path,
                four_octet_as: remote.four_octet_as,
                extended_message: remote.extended_message,
                route_refresh: remote.route_refresh,
                enhanced_refresh: remote.enhanced_refresh,
                gr: remote.gr,
                role: remote.role,
            }],
        ),
        (State::Established(remote), Event::KeepaliveReceived) => {
            (Some(State::Established(remote)), vec![])
        }
        (_, Event::HoldTimerExpires) => (
            None,
            vec![
                Action::SendNotification(ErrorCode::HoldTimerExpired as u8, 0),
                Action::Close,
            ],
        ),
        (_, Event::NotificationReceived(_) | Event::TcpFailed) => (None, vec![Action::Close]),
        (_, Event::CollisionLost) => (
            None,
            vec![
                Action::SendNotification(
                    ErrorCode::Cease as u8,
                    CeaseSubcode::ConnectionCollisionResolution as u8,
                ),
                Action::Close,
            ],
        ),
        (State::Established(remote), Event::KeepaliveTimerExpires) => (
            Some(State::Established(remote)),
            vec![Action::SendKeepalive],
        ),
        (_, Event::MalformedMessage(e)) => {
            let (code, subcode) = notification_for_wire_error(&e);
            (
                None,
                vec![Action::SendNotification(code, subcode), Action::Close],
            )
        }
        // Anything else (an OPEN arriving twice, a KeepaliveTimerExpires
        // while not yet Established, ...) is a protocol sequencing error.
        (state, _) => {
            let subcode = match state {
                State::OpenSent => FsmSubcode::UnexpectedInOpenSent,
                State::OpenConfirm(_) => FsmSubcode::UnexpectedInOpenConfirm,
                State::Established(_) => FsmSubcode::UnexpectedInEstablished,
            };
            (
                None,
                vec![
                    Action::SendNotification(ErrorCode::FiniteStateMachine as u8, subcode as u8),
                    Action::Close,
                ],
            )
        }
    }
}

fn handle_open(open: &OpenMessage, ctx: &NegotiationContext) -> (Option<State>, Vec<Action>) {
    if open.version != message::BGP_VERSION {
        return reject(OpenMessageSubcode::UnsupportedVersionNumber);
    }
    if open.my_as == message::AS_TRANS && message::four_octet_asn(open).is_none() {
        // AS_TRANS with no capability backing it is meaningless per RFC 6793.
        return reject(OpenMessageSubcode::BadPeerAs);
    }
    let remote_asn = message::effective_remote_asn(open);
    // RFC 7607: AS 0 is never valid, whatever the peer is expected to be.
    if remote_asn == 0 || remote_asn != ctx.expected_remote_as {
        return reject(OpenMessageSubcode::BadPeerAs);
    }
    if !message::is_valid_bgp_identifier(open.bgp_identifier) {
        return reject(OpenMessageSubcode::BadBgpIdentifier);
    }
    // RFC 4271 §6.2: a speaker MAY reject hold time 0; we do unless we configured 0 ourselves.
    if open.hold_time == 0 && ctx.local_hold_time != 0 {
        return reject(OpenMessageSubcode::UnacceptableHoldTime);
    }
    if open.hold_time != 0 && open.hold_time < HOLD_TIME_FLOOR {
        return reject(OpenMessageSubcode::UnacceptableHoldTime);
    }

    let negotiated_hold = ctx.local_hold_time.min(open.hold_time);
    // `keepalive_override` is only validated at commit time against the
    // locally-configured hold-time, not the negotiated one (negotiation
    // takes `min()` with a peer-proposed value the validator never sees) —
    // fall back to the RFC-suggested ratio whenever the override wouldn't
    // fit under what was actually negotiated. A negotiated hold time of 0
    // unconditionally disables keepalives, regardless of any override.
    let keepalive = if negotiated_hold == 0 {
        0
    } else {
        match ctx.keepalive_override {
            Some(k) if k < negotiated_hold => k,
            _ => negotiated_hold / 3,
        }
    };
    let (mp_bgp_negotiated, negotiated_ipv4_unicast, negotiated_ipv6_unicast, negotiated_evpn) =
        negotiate_address_families(open, ctx);
    let negotiated_flowspec = negotiate_flowspec(open, ctx);
    let vpn_afs = negotiate_vpn(open, ctx);
    let negotiated_rtc = negotiate_rtc(open, ctx);
    let add_path = negotiate_add_path(open, ctx);
    let Ok(role) = negotiate_role(open, ctx) else {
        return reject(OpenMessageSubcode::RoleMismatch);
    };
    let remote = RemoteInfo {
        role,
        asn: remote_asn,
        bgp_id: open.bgp_identifier,
        mp_bgp_negotiated,
        negotiated_ipv4_unicast,
        negotiated_ipv6_unicast,
        negotiated_evpn,
        negotiated_flowspec,
        negotiated_vpn: vpn_afs,
        negotiated_rtc,
        add_path,
        four_octet_as: message::four_octet_asn(open).is_some(),
        extended_message: open
            .capabilities
            .contains(&message::Capability::ExtendedMessage),
        enhanced_refresh: open
            .capabilities
            .contains(&message::Capability::EnhancedRouteRefresh),
        route_refresh: open
            .capabilities
            .contains(&message::Capability::RouteRefresh),
        gr: message::graceful_restart(open).map(PeerGr::from_cap),
    };
    (
        Some(State::OpenConfirm(remote)),
        vec![
            Action::SendKeepalive,
            Action::ArmHoldTimer(Duration::from_secs(u64::from(negotiated_hold))),
            Action::ArmKeepaliveTimer(Duration::from_secs(u64::from(keepalive))),
        ],
    )
}

fn reject(subcode: OpenMessageSubcode) -> (Option<State>, Vec<Action>) {
    (
        None,
        vec![
            Action::SendNotification(ErrorCode::OpenMessage as u8, subcode as u8),
            Action::Close,
        ],
    )
}

/// Maps a decode failure to the `(error_code, error_subcode)` pair its
/// NOTIFICATION should carry. Every case but `MalformedUpdate` is a Message
/// Header error (RFC 4271 §6.1); `MalformedUpdate` is the one case that
/// belongs to the UPDATE Message Error table (§6.3) instead.
fn notification_for_wire_error(e: &WireError) -> (u8, u8) {
    match e {
        WireError::BadMarker => (
            ErrorCode::MessageHeader as u8,
            MessageHeaderSubcode::ConnectionNotSynchronized as u8,
        ),
        WireError::BadLength(_)
        | WireError::Truncated
        | WireError::MalformedOpen
        | WireError::MalformedNotification
        | WireError::MalformedRouteRefresh
        | WireError::Io(_) => (
            ErrorCode::MessageHeader as u8,
            MessageHeaderSubcode::BadMessageLength as u8,
        ),
        WireError::MalformedUpdate => (
            ErrorCode::UpdateMessage as u8,
            UpdateMessageSubcode::MalformedAttributeList as u8,
        ),
    }
}

/// How one FSM session ended, for `session.rs` to log.
#[derive(Debug)]
pub enum FsmOutcome {
    TcpError,
    PeerClosed,
    NotificationSent {
        code: u8,
        subcode: u8,
    },
    NotificationReceived {
        code: u8,
        subcode: u8,
    },
    HoldTimerExpired,
    CollisionLost,
    /// RFC 4724 §4.2: a new connection from the peer replaced this one.
    GrReplaced,
}

/// How a session that ended with `outcome` counts for graceful restart.
/// `n_exchanged`: both sides advertised RFC 8538's N bit.
fn disconnect_kind(outcome: &FsmOutcome, n_exchanged: bool) -> Disconnect {
    match outcome {
        FsmOutcome::TcpError | FsmOutcome::PeerClosed | FsmOutcome::GrReplaced => {
            Disconnect::Transport
        }
        // RFC 8538 §4: hold-timer expiry is graceful once N is exchanged.
        FsmOutcome::HoldTimerExpired => {
            gr::notification_disconnect(ErrorCode::HoldTimerExpired as u8, 0, n_exchanged)
        }
        FsmOutcome::NotificationSent { code, subcode }
        | FsmOutcome::NotificationReceived { code, subcode } => {
            gr::notification_disconnect(*code, *subcode, n_exchanged)
        }
        FsmOutcome::CollisionLost => Disconnect::Hard,
    }
}

/// RFC 7854 section 4.9 reason for a session that ended with `outcome`.
/// ponytail: the NOTIFICATION PDU is rebuilt from code/subcode, so data (an
/// RFC 9003 shutdown text) is lost for reason 3; carry it in
/// `FsmOutcome::NotificationReceived` if a collector needs it.
fn bmp_down_reason(outcome: &FsmOutcome) -> crate::bmp::DownReason {
    use crate::bmp::DownReason;
    let pdu = |code: u8, subcode: u8| {
        crate::bmp::bgp_pdu(BgpMessage::Notification(NotificationMessage {
            error_code: code,
            error_subcode: subcode,
            data: Bytes::new(),
        }))
    };
    match outcome {
        FsmOutcome::NotificationSent { code, subcode } => {
            DownReason::LocalNotification(pdu(*code, *subcode))
        }
        FsmOutcome::HoldTimerExpired => {
            DownReason::LocalNotification(pdu(ErrorCode::HoldTimerExpired as u8, 0))
        }
        FsmOutcome::CollisionLost => DownReason::LocalNotification(pdu(
            ErrorCode::Cease as u8,
            CeaseSubcode::ConnectionCollisionResolution as u8,
        )),
        FsmOutcome::NotificationReceived { code, subcode } => {
            DownReason::RemoteNotification(pdu(*code, *subcode))
        }
        FsmOutcome::TcpError | FsmOutcome::PeerClosed | FsmOutcome::GrReplaced => {
            DownReason::RemoteClosed
        }
    }
}

/// Turns one inbound message into the `Event` to feed `step`, or handles it
/// here and returns `None`.
///
/// UPDATE and `ROUTE_REFRESH` bypass `step`'s transition table entirely — they
/// aren't part of the OpenSent/OpenConfirm/Established table and are
/// meaningful only once `Established` — so they are consumed here rather than
/// inside `run`'s `select!`, which only ever yields a value.
async fn classify_inbound(
    msg: BgpMessage,
    state: &State,
    peer: &PeerContext,
    remote_is_ibgp: bool,
    bgp_rib: &SharedRib,
    slot: &PeerSlot,
    refresh: &mut RefreshState,
) -> Option<Event> {
    match msg {
        BgpMessage::Open(open) => Some(Event::OpenReceived(open)),
        BgpMessage::Keepalive => Some(Event::KeepaliveReceived),
        BgpMessage::Notification(n) => Some(Event::NotificationReceived(n)),
        BgpMessage::Update(update) => {
            if let State::Established(remote) = state {
                // BMP pre-policy: the UPDATE as received, before the RIB lock.
                bgp_rib.bmp().route_pre(peer.remote_address, &update);
                let mut rib = bgp_rib.lock().await;
                rib.handle_update(
                    peer.remote_address,
                    remote_is_ibgp,
                    remote.bgp_id,
                    &update,
                    &slot.import_policy(),
                );
                // RFC 4486 §4: over a hard limit, hold the peer down and have
                // the command arm send the Cease. Once only: UPDATEs read
                // before that arm runs must not queue a second Cease, which
                // would outlive this session in the slot's channel.
                if let Some((family, limit, _)) = rib.check_max_prefix(peer.remote_address)
                    && !slot.max_prefix_held()
                {
                    trip_max_prefix(slot, family, limit);
                }
            } else {
                return Some(Event::UnexpectedUpdate);
            }
            None
        }
        BgpMessage::RouteRefresh(rr) => {
            resend_loc_rib(rr, state, peer, bgp_rib, refresh).await;
            None
        }
        BgpMessage::EndOfRib { afi, safi } => {
            if !matches!(state, State::Established(_)) {
                return Some(Event::UnexpectedUpdate);
            }
            bgp_rib.bmp().end_of_rib(peer.remote_address, afi, safi);
            if let Some(family) = gr::family_of(afi, safi) {
                bgp_rib.lock().await.end_of_rib(peer.remote_address, family);
            } else {
                debug!(
                    peer = %peer.remote_address, afi, safi,
                    "ignoring end-of-rib for an unknown family"
                );
            }
            None
        }
        BgpMessage::Unhandled { message_type, .. } => {
            debug!(
                peer = %peer.remote_address, message_type,
                "ignoring unrecognized bgp message type"
            );
            None
        }
    }
}

/// Per-session route-refresh state: RFC 7313 stale deadlines and the
/// peer-driven request limiter.
#[derive(Default)]
struct RefreshState {
    stale_until: HashMap<AddressFamily, Instant>,
    limiter: crate::refresh_limit::RefreshLimiter,
}

/// RFC 2918 inbound: re-send the Loc-RIB for the requested address family.
/// RFC 7313 `BoRR`/`EoRR` arm/cancel the family's stale timer in `stale_until`.
async fn resend_loc_rib(
    rr: RouteRefreshMessage,
    state: &State,
    peer: &PeerContext,
    bgp_rib: &SharedRib,
    refresh: &mut RefreshState,
) {
    if !matches!(state, State::Established(_)) {
        debug!(
            peer = %peer.remote_address,
            "ignoring route refresh received before session established"
        );
        return;
    }
    // A Flowspec, VPN or EVPN refresh names its own family (resent by
    // `resend_all`); any other SAFI keeps meaning unicast of its AFI.
    let family = if matches!(
        rr.safi,
        message::SAFI_FLOWSPEC | message::SAFI_VPN | message::SAFI_EVPN | message::SAFI_RTC
    ) {
        gr::family_of(rr.afi, rr.safi)
    } else {
        family_of_afi(rr.afi)
    };
    let Some(family) = family else {
        debug!(
            peer = %peer.remote_address, afi = rr.afi,
            "ignoring route-refresh for unrecognized afi"
        );
        return;
    };
    // RFC 7313: markers only mean something on a session that negotiated it.
    let State::Established(remote) = state else {
        return;
    };
    let mut rib = bgp_rib.lock().await;
    match rr.subtype {
        message::REFRESH_REQUEST => {
            if refresh.limiter.allow(Instant::now()) {
                rib.resend_all(peer.remote_address, family, remote.enhanced_refresh);
                info!(
                    peer = %peer.remote_address, afi = rr.afi,
                    "bgp: received route refresh, resending loc-rib"
                );
            } else {
                debug!(
                    peer = %peer.remote_address, afi = rr.afi,
                    "bgp: route refresh rate-limited, not resending"
                );
            }
        }
        message::REFRESH_BORR if remote.enhanced_refresh => {
            rib.begin_refresh_in(peer.remote_address, family);
            // RFC 7313 §4: bound how long the marks may wait for an EoRR; a
            // repeated BoRR restarts the timer.
            if !peer.route_refresh_stale_time.is_zero() {
                refresh
                    .stale_until
                    .insert(family, Instant::now() + peer.route_refresh_stale_time);
            }
            debug!(peer = %peer.remote_address, afi = rr.afi, "bgp: received BoRR");
        }
        message::REFRESH_EORR if remote.enhanced_refresh => {
            rib.end_refresh_in(peer.remote_address, family);
            rib.retention_eorr(peer.remote_address, family);
            refresh.stale_until.remove(&family);
            debug!(peer = %peer.remote_address, afi = rr.afi, "bgp: received EoRR");
        }
        subtype => debug!(
            peer = %peer.remote_address, subtype,
            "ignoring route-refresh with unusable subtype"
        ),
    }
}

/// RFC 2918 outbound: request a refresh for every address family this
/// session actually negotiated.
async fn send_route_refresh(
    writer: &mut FramedWrite<OwnedWriteHalf, BgpCodec>,
    state: &State,
    peer: &PeerContext,
) {
    let State::Established(remote) = state else {
        return;
    };
    if !remote.route_refresh {
        warn!(
            peer = %peer.remote_address,
            "route refresh not sent: the peer did not advertise the route refresh capability (rfc 2918)"
        );
        return;
    }
    let families = [
        remote.negotiated_ipv4_unicast.then_some((AFI_IPV4, 1)),
        remote.negotiated_ipv6_unicast.then_some((AFI_IPV6, 1)),
        remote.negotiated_vpn[0].then_some((AFI_IPV4, message::SAFI_VPN)),
        remote.negotiated_vpn[1].then_some((AFI_IPV6, message::SAFI_VPN)),
        remote
            .negotiated_evpn
            .then_some((message::AFI_L2VPN, message::SAFI_EVPN)),
        remote.negotiated_flowspec[0].then_some((AFI_IPV4, message::SAFI_FLOWSPEC)),
        remote.negotiated_flowspec[1].then_some((AFI_IPV6, message::SAFI_FLOWSPEC)),
        remote
            .negotiated_rtc
            .then_some((AFI_IPV4, message::SAFI_RTC)),
    ];
    for (afi, safi) in families.into_iter().flatten() {
        let _ = writer
            .send(BgpMessage::RouteRefresh(RouteRefreshMessage {
                afi,
                subtype: message::REFRESH_REQUEST,
                safi,
            }))
            .await;
    }
    info!(peer = %peer.remote_address, "bgp: sent route refresh request to peer");
}

/// RFC 4271 §6.8: an OPEN has just moved this connection to `OpenConfirm`,
/// so register its BGP Identifier with the peer's shared `PeerSlot` and apply
/// the verdict.
///
/// Returns `Some` replacement `(next_state, actions)` when this connection
/// *lost* — rewriting the transition into "send Cease, then close" — and
/// `None` when it may proceed, having published its newly-known remote
/// identity to the peer's status.
async fn apply_collision_verdict(
    remote: RemoteInfo,
    role: collision::Role,
    local: &LocalIdentity,
    slot: &PeerSlot,
    cease: Arc<Notify>,
) -> Option<(Option<State>, Vec<Action>)> {
    match slot
        .on_open(
            role,
            local.router_id,
            remote.bgp_id,
            cease,
            remote.gr.is_some_and(|g| g.restart),
        )
        .await
    {
        collision::Decision::Lose => Some((
            None,
            vec![
                Action::SendNotification(
                    ErrorCode::Cease as u8,
                    CeaseSubcode::ConnectionCollisionResolution as u8,
                ),
                Action::Close,
            ],
        )),
        // `on_open` only returns `Proceed` when no other connection for this
        // peer is already `Established` (see `collision::PeerSlot::on_open`),
        // so this is safe to write without an extra `is_established` race
        // check.
        collision::Decision::Proceed => {
            slot.status.send_modify(|s| {
                s.state = PeerState::OpenConfirm;
                s.remote_asn = Some(remote.asn);
                s.remote_bgp_id = Some(remote.bgp_id);
            });
            None
        }
    }
}

/// Drives one session's `OpenSent` -> `OpenConfirm` -> `Established` FSM
/// over an already-connected `stream`. The caller is responsible for
/// `PeerSlot::begin`/`clear` around this call — `run` only touches
/// `on_open`/`mark_established`, the transitions intrinsic to FSM progress.
///
/// `bgp_rib` is registered with a fresh outbound channel once the session
/// reaches `Established` (`Action::ReportEstablished`), fed real
/// `BgpMessage::Update`s back onto the wire from a dedicated `select!` arm,
/// and deregistered (`peer_disconnected`) at this function's single exit
/// point — but only if it actually registered, since `BgpRib` is keyed by
/// peer address and a collision loser shares one with its winner (see
/// `registered` below).
/// Logs a received NOTIFICATION; for a Cease/Administrative Shutdown or Reset
/// (RFC 9003) also the peer's shutdown communication, if it sent a valid one.
///
/// An RFC 8538 Hard Reset (Cease/9) is logged with the NOTIFICATION it wraps
/// (§6), whose shutdown communication is decoded the same way.
fn log_notification(peer: IpAddr, n: &NotificationMessage) {
    let cease = ErrorCode::Cease as u8;
    let shutdown_text = |code: u8, subcode: u8, data: &[u8]| {
        (code == cease && matches!(subcode, 2 | 4))
            .then(|| message::decode_shutdown_message(data))
            .flatten()
            .unwrap_or_default()
    };
    if n.error_code == cease
        && n.error_subcode == CeaseSubcode::HardReset as u8
        && n.data.len() >= 2
    {
        let (inner_code, inner_subcode) = (n.data[0], n.data[1]);
        info!(
            peer = %peer, code = n.error_code, subcode = n.error_subcode,
            hard_reset_code = inner_code, hard_reset_subcode = inner_subcode,
            shutdown_message = shutdown_text(inner_code, inner_subcode, &n.data[2..]),
            "received notification"
        );
        return;
    }
    info!(
        peer = %peer, code = n.error_code, subcode = n.error_subcode,
        shutdown_message = shutdown_text(n.error_code, n.error_subcode, &n.data),
        "received notification"
    );
}

type SessionReader = FramedRead<OwnedReadHalf, BgpCodec>;
type SessionWriter = FramedWrite<OwnedWriteHalf, BgpCodec>;

/// The per-session constants `run`'s helpers read (#425): split out so the
/// big arms of the event loop can live in their own functions.
#[derive(Clone, Copy)]
struct SessionCtx<'a> {
    peer: &'a PeerContext,
    slot: &'a Arc<PeerSlot>,
    bgp_rib: &'a Arc<SharedRib>,
    role: collision::Role,
    /// Our graceful restart Restart Time, `None` when it's off here.
    our_gr: Option<u16>,
    replaced: &'a Arc<Notify>,
    kind: PeerKind,
    remote_is_ibgp: bool,
    local_addr: Option<IpAddr>,
    outbox_tx: &'a OutboxTx,
    fd: RawFd,
}

impl SessionCtx<'_> {
    /// RFC 8538: both sides advertised the N bit (we always do with GR on).
    fn n_exchanged(&self, state: &State) -> bool {
        self.our_gr.is_some()
            && matches!(state, State::Established(r) if r.gr.is_some_and(|g| g.notification))
    }
}

/// Hold/keepalive timers and what was negotiated, owned by `run`.
struct Timers {
    /// Doubles, before negotiation, as the OpenSent-wait timer. A configured
    /// `local_hold_time` of 0 disarms it entirely, same as a negotiated hold
    /// time of 0 does later via `Action::ArmHoldTimer`.
    hold_period: Option<Duration>,
    hold_deadline: Option<Instant>,
    keepalive_period: Option<Duration>,
    keepalive_deadline: Option<Instant>,
    negotiated_hold_time: Option<u16>,
    negotiated_keepalive: Option<u16>,
}

impl Timers {
    fn new(local_hold_time: u16) -> Self {
        let hold_period = if local_hold_time == 0 {
            None
        } else {
            Some(Duration::from_secs(u64::from(local_hold_time)))
        };
        Self {
            hold_period,
            hold_deadline: hold_period.map(|p| Instant::now() + p),
            keepalive_period: None,
            keepalive_deadline: None,
            negotiated_hold_time: None,
            negotiated_keepalive: None,
        }
    }
}

/// Builds our OPEN, including every capability this session advertises.
async fn build_open_message(
    cx: &SessionCtx<'_>,
    local: &LocalIdentity,
    ctx: &NegotiationContext,
) -> OpenMessage {
    let SessionCtx {
        peer,
        slot,
        bgp_rib,
        our_gr,
        ..
    } = *cx;
    let mut open = message::build_open(
        slot.peer.open_as(local.asn),
        local.router_id,
        peer.local_hold_time,
    );
    open.capabilities.extend(build_mp_capabilities(
        &peer.address_families,
        ctx.transport_afi,
    ));
    open.capabilities.push(message::Capability::RouteRefresh);
    open.capabilities
        .push(message::Capability::EnhancedRouteRefresh);
    open.capabilities.push(message::Capability::ExtendedMessage);
    if let Some(mode) = ctx.add_path {
        // Only when configured (a route-server client defaults to
        // `Both`): unlike the other capabilities, it changes the NLRI
        // wire format of the whole session. One instance carries every
        // tuple (RFC 7911 §4).
        let tuples = peer
            .address_families
            .iter()
            .filter(|&&af| is_unicast(af))
            .map(|&af| message::AddPathTuple {
                afi: afi_of(af),
                safi: 1,
                send_receive: mode.send_receive(),
            })
            .collect();
        open.capabilities.push(message::Capability::AddPath(tuples));
    }
    if let Some(role) = ctx.role {
        open.capabilities
            .push(message::Capability::Role(role.wire()));
    }
    if let Some(time) = our_gr {
        // F = 1 only if this process already had a session with the
        // peer, or `nos-ribd` kept our routes across a restart; R = 1
        // while selection deferral is in progress (RFC 4724 §3).
        let (restarting, forwarding) = {
            let rib = bgp_rib.lock().await;
            (rib.deferring(), rib.gr_forwarding(peer.remote_address))
        };
        open.capabilities
            .push(message::Capability::GracefulRestart(gr::our_cap(
                time,
                &peer.address_families,
                restarting,
                forwarding,
            )));
    }
    open
}

/// Sends one outbound update through MRAI (the `outbox_rx` arm of `run`).
async fn send_outbound(
    writer: &mut SessionWriter,
    mrai: &mut crate::mrai::Mrai,
    update: OutboundUpdate,
) {
    // RFC 7313 EoRR and RFC 4724 End-of-RIB must follow every
    // route they close, so release anything MRAI holds first.
    if matches!(
        update,
        OutboundUpdate::RefreshMarker {
            subtype: message::REFRESH_EORR,
            ..
        } | OutboundUpdate::EndOfRib(_)
    ) {
        for held in mrai.drain() {
            if let Err(e) = writer.send(outbound_update_to_message(held)).await {
                warn!(error = %e, "could not send update");
            }
        }
    }
    if let Some(update) = mrai.push(update, Instant::now())
        && let Err(e) = writer.send(outbound_update_to_message(update)).await
    {
        warn!(error = %e, "could not send update");
    }
}

/// Once the outbox queue is empty, has the RIB re-send what it dropped (#395).
async fn resync_outbox(cx: &SessionCtx<'_>, rx: &mpsc::Receiver<OutboundUpdate>) {
    if !cx.outbox_tx.pending() || !rx.is_empty() {
        return;
    }
    cx.bgp_rib
        .lock()
        .await
        .drain_backlog(cx.peer.remote_address);
}

/// Purges the families whose RFC 7313 stale deadline passed.
async fn expire_stale(cx: &SessionCtx<'_>, stale_until: &mut HashMap<AddressFamily, Instant>) {
    let SessionCtx { peer, bgp_rib, .. } = *cx;
    let now = Instant::now();
    let expired: Vec<AddressFamily> = stale_until
        .iter()
        .filter(|(_, d)| **d <= now)
        .map(|(f, _)| *f)
        .collect();
    let mut rib = bgp_rib.lock().await;
    for family in expired {
        stale_until.remove(&family);
        warn!(
            peer = %peer.remote_address, afi = afi_of(family),
            "bgp: route refresh stale timer expired, purging stale routes"
        );
        rib.end_refresh_in(peer.remote_address, family);
    }
}

/// One `FsmCommand` taken off the slot's channel while `Established`.
/// `Some(outcome)` ends the session, `None` keeps the loop going.
async fn handle_command(
    cx: &SessionCtx<'_>,
    writer: &mut SessionWriter,
    state: &State,
    cmd: FsmCommand,
) -> Option<FsmOutcome> {
    let SessionCtx { peer, fd, .. } = *cx;
    // An in-place key update that the kernel refuses (e.g.
    // `EBUSY`: the peer still signs with a removed key)
    // falls back to a reset; the reconnect uses the new keys.
    let cmd = match cmd {
        FsmCommand::UpdateAo(delta) => {
            match crate::tcp::apply_ao_delta(fd, peer.remote_address, &delta, true) {
                Ok(()) => {
                    info!(
                        peer = %peer.remote_address,
                        added = delta.add.len(), removed = delta.remove.len(),
                        rnext = delta.rnext_recv_id,
                        "bgp tcp-ao keys updated in place"
                    );
                    return None;
                }
                Err(error) => {
                    warn!(
                        peer = %peer.remote_address, %error,
                        "failed to update tcp-ao keys in place, resetting session"
                    );
                    FsmCommand::Cease {
                        subcode: CeaseSubcode::OtherConfigurationChange,
                        data: Bytes::new(),
                    }
                }
            }
        }
        other => other,
    };
    match cmd {
        FsmCommand::UpdateAo(_) => unreachable!("handled above"),
        FsmCommand::SendRouteRefresh => {
            send_route_refresh(writer, state, peer).await;
            None
        }
        FsmCommand::Cease { .. } | FsmCommand::BfdDown { .. } => {
            let (subcode, data, force_hard) = match cmd {
                FsmCommand::Cease { subcode, data } => (subcode, data, false),
                FsmCommand::BfdDown { flush } => (CeaseSubcode::BfdDown, Bytes::new(), flush),
                _ => unreachable!("matched above"),
            };
            // RFC 8538 §5.1: with N, a reset meant to keep
            // nothing goes out as a Hard Reset around it.
            let hard_reset = gr::sends_hard_reset(subcode, cx.n_exchanged(state))
                || (force_hard && cx.n_exchanged(state));
            let (wire_subcode, data) = if hard_reset {
                (
                    CeaseSubcode::HardReset as u8,
                    message::encode_hard_reset(subcode as u8, &data),
                )
            } else {
                (subcode as u8, data)
            };
            let _ = writer
                .send(BgpMessage::Notification(NotificationMessage {
                    error_code: ErrorCode::Cease as u8,
                    error_subcode: wire_subcode,
                    data,
                }))
                .await;
            info!(
                peer = %peer.remote_address, subcode = subcode as u8, hard_reset,
                "sent cease notification"
            );
            Some(FsmOutcome::NotificationSent {
                code: ErrorCode::Cease as u8,
                subcode: wire_subcode,
            })
        }
    }
}

/// RFC 4271 §6.8 collision handling for an OPEN that reached `OpenConfirm`;
/// `Some` replaces the state `step` computed.
async fn collision_override(
    cx: &SessionCtx<'_>,
    local: &LocalIdentity,
    remote: RemoteInfo,
    cease: &Arc<Notify>,
) -> Option<(Option<State>, Vec<Action>)> {
    if cx.slot.max_prefix_held() {
        // RFC 4486 §4: a connection already in flight when the
        // peer tripped its maximum-prefix limit (the other side
        // of a collision) must not bring the session back.
        Some((
            None,
            vec![
                Action::SendNotification(
                    ErrorCode::Cease as u8,
                    CeaseSubcode::ConnectionRejected as u8,
                ),
                Action::Close,
            ],
        ))
    } else {
        apply_collision_verdict(remote, cx.role, local, cx.slot, cease.clone()).await
    }
}

/// `Action::ReportEstablished`: applies the negotiated capabilities to the
/// codec, registers the peer with the RIB and publishes the status.
#[allow(
    clippy::too_many_lines,
    reason = "one linear setup sequence per negotiated capability"
)]
async fn report_established(
    cx: &SessionCtx<'_>,
    reader: &mut SessionReader,
    writer: &mut SessionWriter,
    timers: &Timers,
    action: &Action,
) {
    let SessionCtx {
        peer,
        slot,
        bgp_rib,
        role,
        our_gr,
        replaced,
        kind,
        remote_is_ibgp,
        local_addr,
        outbox_tx,
        fd,
    } = *cx;
    let Action::ReportEstablished {
        remote_asn,
        remote_bgp_id,
        mp_bgp_negotiated,
        negotiated_ipv4_unicast,
        negotiated_ipv6_unicast,
        negotiated_evpn,
        negotiated_flowspec,
        negotiated_vpn,
        negotiated_rtc,
        add_path,
        four_octet_as,
        extended_message,
        route_refresh,
        enhanced_refresh,
        gr: remote_gr,
        role: negotiated_role,
    } = action
    else {
        unreachable!("called for ReportEstablished only")
    };
    // GR on here and the peer sent the capability.
    let gr_negotiated = our_gr.and(*remote_gr);
    slot.mark_established(role, gr_negotiated.is_some(), replaced.clone())
        .await;
    let mut negotiated_afs = HashSet::new();
    if *negotiated_ipv4_unicast {
        negotiated_afs.insert(AddressFamily::Ipv4Unicast);
    }
    if *negotiated_ipv6_unicast {
        negotiated_afs.insert(AddressFamily::Ipv6Unicast);
    }
    if *negotiated_evpn {
        negotiated_afs.insert(AddressFamily::L2vpnEvpn);
    }
    let non_unicast = [
        (negotiated_flowspec[0], AddressFamily::Ipv4Flowspec),
        (negotiated_flowspec[1], AddressFamily::Ipv6Flowspec),
        (negotiated_vpn[0], AddressFamily::Vpnv4Unicast),
        (negotiated_vpn[1], AddressFamily::Vpnv6Unicast),
        (*negotiated_rtc, AddressFamily::RtConstraint),
    ];
    negotiated_afs.extend(
        non_unicast
            .into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, af)| af),
    );
    info!(
        peer = %peer.remote_address,
        families = ?AddressFamily::ALL.into_iter().filter(|f| negotiated_afs.contains(f)).map(|f| f.as_str()).collect::<Vec<_>>(),
        "address families negotiated"
    );
    // RFC 7911 §5: each direction on its own — the
    // decoder reads ids only where we receive them, the
    // encoder (and the RIB) sends them only where we send.
    let unicast = [AddressFamily::Ipv4Unicast, AddressFamily::Ipv6Unicast];
    let mut rx_afis = HashSet::new();
    let mut tx_afis = HashSet::new();
    let mut add_path_tx = HashSet::new();
    for (family, dir) in unicast.into_iter().zip(*add_path) {
        if dir.rx {
            rx_afis.insert(afi_of(family));
        }
        if dir.tx {
            tx_afis.insert(afi_of(family));
            add_path_tx.insert(family);
        }
    }
    if slot.peer.add_path.is_some() {
        info!(
            peer = %peer.remote_address,
            ipv4 = add_path[0].as_str(),
            ipv6 = add_path[1].as_str(),
            "add-path negotiated"
        );
    }
    if let Some(ours) = negotiated_role {
        info!(
            peer = %peer.remote_address, local = ours.as_str(),
            remote = ours.counterpart().as_str(),
            "bgp role negotiated"
        );
    }
    // Must be set before any further UPDATE is
    // decoded/encoded on this connection — done here,
    // right after Established, the same point every
    // other negotiated-capability field is applied.
    reader.decoder_mut().add_path_afis = rx_afis;
    writer.encoder_mut().add_path_afis = tx_afis;
    reader.decoder_mut().two_octet_as = !*four_octet_as;
    writer.encoder_mut().two_octet_as = !*four_octet_as;
    reader.decoder_mut().extended = *extended_message;
    writer.encoder_mut().extended = *extended_message;
    info!(
        extended_message = *extended_message,
        "extended message negotiated"
    );
    if let Some(g) = gr_negotiated {
        info!(
            peer = %peer.remote_address, restart_time = g.time,
            notification = g.notification, restarting = g.restart,
            families = ?g.families(),
            "graceful restart negotiated"
        );
    }
    // `peer_established` queues the initial dump and,
    // toward a peer that did GR too, End-of-RIB (RFC
    // 4724 §2) — or both later, at the end of a
    // restarting process's selection deferral.
    let mut rib = bgp_rib.lock().await;
    rib.set_peer_gr(peer.remote_address, gr_negotiated);
    rib.set_peer_damping(peer.remote_address, peer.damping);
    rib.set_peer_soft_reconfig(peer.remote_address, slot.soft_reconfig());
    slot.set_refresh_caps(*route_refresh, *enhanced_refresh);
    info!(
        peer = %peer.remote_address, route_refresh = *route_refresh,
        enhanced_refresh = *enhanced_refresh, "route refresh capability"
    );
    rib.set_peer_max_prefix(peer.remote_address, slot.peer.maximum_prefix);
    rib.set_peer_asn(peer.remote_address, *remote_asn);
    rib.set_peer_evpn_import_policy(
        peer.remote_address,
        slot.evpn_import_policy(),
        remote_is_ibgp,
    );
    rib.set_peer_confed(peer.remote_address, kind == PeerKind::ConfedExternal);
    rib.set_peer_flowspec_validation(peer.remote_address, slot.peer.flowspec_validation);
    rib.set_peer_flowspec_policies(
        peer.remote_address,
        slot.flowspec_import_policy(),
        slot.peer.flowspec_export_policy.clone(),
    );
    rib.set_peer_local_as(
        peer.remote_address,
        slot.peer.local_as.filter(|_| kind == PeerKind::External),
    );
    rib.set_peer_role(peer.remote_address, slot.peer.role);
    rib.set_peer_role_negotiated(peer.remote_address, negotiated_role.is_some());
    rib.set_peer_enforce_first_as(
        peer.remote_address,
        slot.peer.enforce_first_as && !slot.peer.route_server_client,
    );
    rib.set_peer_add_path_send_count(peer.remote_address, slot.peer.add_path_send_count);
    rib.set_peer_rpki_state(
        peer.remote_address,
        slot.peer.announce_rpki_state && remote_is_ibgp,
    );
    rib.set_peer_blackhole(
        peer.remote_address,
        slot.peer.blackhole.clone().filter(|_| !remote_is_ibgp),
    );
    rib.peer_established(
        peer.remote_address,
        remote_is_ibgp,
        local_addr,
        negotiated_afs,
        *mp_bgp_negotiated,
        peer.next_hop,
        peer.is_rr_client,
        peer.is_rs_client,
        add_path_tx,
        peer.export_policy.clone(),
        outbox_tx.clone(),
    );
    slot.status.send_modify(|s| {
        s.state = PeerState::Established;
        s.remote_asn = Some(*remote_asn);
        s.remote_bgp_id = Some(*remote_bgp_id);
        s.established_since = Some(Instant::now());
        s.negotiated_hold_time = timers.negotiated_hold_time;
        s.negotiated_keepalive = timers.negotiated_keepalive;
        s.fd = Some(fd);
    });
    info!(
        peer = %peer.remote_address, remote_asn, remote_bgp_id = %remote_bgp_id,
        role = ?role, "bgp session established"
    );
}

/// Executes `step`'s actions in order; returns the Notification sent, if any,
/// and whether `ReportEstablished` registered the peer with the RIB.
async fn run_actions(
    cx: &SessionCtx<'_>,
    reader: &mut SessionReader,
    writer: &mut SessionWriter,
    timers: &mut Timers,
    actions: &[Action],
) -> (Option<(u8, u8)>, bool) {
    let mut notification_sent = None;
    let mut registered = false;
    for action in actions {
        match action {
            Action::SendKeepalive => {
                let _ = writer.send(BgpMessage::Keepalive).await;
            }
            Action::SendNotification(code, subcode) => {
                let _ = writer
                    .send(BgpMessage::Notification(NotificationMessage {
                        error_code: *code,
                        error_subcode: *subcode,
                        data: Bytes::new(),
                    }))
                    .await;
                notification_sent = Some((*code, *subcode));
                info!(
                    peer = %cx.peer.remote_address, code = *code, subcode = *subcode,
                    "sent notification"
                );
            }
            Action::ArmHoldTimer(d) => {
                timers.hold_period = if d.is_zero() { None } else { Some(*d) };
                timers.hold_deadline = timers.hold_period.map(|p| Instant::now() + p);
                // Always derived from a u16 (either the local config or
                // the peer's OPEN), so this never actually truncates.
                timers.negotiated_hold_time = Some(u16::try_from(d.as_secs()).unwrap_or(u16::MAX));
            }
            Action::ArmKeepaliveTimer(d) => {
                timers.keepalive_period = if d.is_zero() { None } else { Some(*d) };
                timers.keepalive_deadline = timers.keepalive_period.map(|p| Instant::now() + p);
                timers.negotiated_keepalive = Some(u16::try_from(d.as_secs()).unwrap_or(u16::MAX));
            }
            Action::ReportEstablished { .. } => {
                report_established(cx, reader, writer, timers, action).await;
                registered = true;
            }
            Action::Close => {}
        }
    }
    (notification_sent, registered)
}

#[allow(clippy::too_many_lines)] // the session loop is one select!; its arms already delegate to helpers
pub async fn run(
    stream: TcpStream,
    role: collision::Role,
    local: LocalIdentity,
    peer: PeerContext,
    slot: Arc<PeerSlot>,
    bgp_rib: Arc<SharedRib>,
) -> FsmOutcome {
    // Captured before `into_split()` consumes `stream`: this session's own
    // local address (of whatever family), used as next-hop-self for every
    // address family this session ends up carrying — including a family
    // that differs from this address's own (RFC 8950 cross-family
    // next-hop), which is exactly why this is no longer restricted to IPv4.
    let local_addr = stream.local_addr().ok().map(|addr| addr.ip());
    let local_port = stream.local_addr().map_or(0, |a| a.port());
    let remote_port = stream.peer_addr().map_or(0, |a| a.port());
    // Also captured here, for the same reason: `status.fd`, read on demand
    // for a `TCP_AO_INFO` getsockopt once this session reaches `Established`
    // (see `Action::ReportEstablished` below).
    let fd = stream.as_raw_fd();
    // RFC 5065: `Internal` is the member AS, in a confederation.
    let kind = slot.peer.kind(local.asn);
    let remote_is_ibgp = kind == PeerKind::Internal;
    let (outbox_tx, mut outbox_rx) =
        crate::rib::outbox_channel(peer.remote_address, crate::rib::OUTBOX_CAPACITY);
    let mut mrai = crate::mrai::Mrai::new(peer.mrai);
    // RFC 7313 §4 stale-route deadlines, per family; die with the session.
    let mut refresh = RefreshState::default();

    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, BgpCodec::default());
    let mut writer = FramedWrite::new(write_half, BgpCodec::default());

    let ctx = NegotiationContext {
        expected_remote_as: peer.expected_remote_as,
        local_hold_time: peer.local_hold_time,
        keepalive_override: peer.keepalive_override,
        address_families: peer.address_families.clone(),
        transport_afi: afi_of_addr(peer.remote_address),
        add_path: slot.peer.add_path,
        role: slot.peer.role,
        strict_mode: slot.peer.strict_mode,
    };

    let mut state = State::OpenSent;
    let mut timers = Timers::new(peer.local_hold_time);
    let cease = Arc::new(Notify::new());
    // RFC 4724 §4.2: notified when a new connection from the peer replaces
    // this one once it is `Established` (see `collision::PeerSlot`).
    let replaced = Arc::new(Notify::new());
    let cx = SessionCtx {
        peer: &peer,
        slot: &slot,
        bgp_rib: &bgp_rib,
        role,
        // Our graceful restart Restart Time, `None` when it's off here.
        our_gr: slot.peer.graceful_restart,
        replaced: &replaced,
        kind,
        remote_is_ibgp,
        local_addr,
        outbox_tx: &outbox_tx,
        fd,
    };

    // Guarded on `is_established` rather than written unconditionally: an
    // inbound connection can arrive for a peer that's already `Established`
    // via the other role (e.g. a flappy/misbehaving peer opening a second
    // TCP session) — such a connection is always going to lose the
    // collision at its first `on_open` below, and must never be allowed to
    // transiently overwrite the genuinely-established session's reported
    // status in the meantime.
    if !slot.is_established().await {
        slot.status.send_modify(|s| {
            *s = PeerStatus {
                state: PeerState::OpenSent,
                ..PeerStatus::default()
            }
        });
    }

    // Whether this connection ever registered itself with `bgp_rib`, i.e.
    // reached `Established` and ran `Action::ReportEstablished`.
    //
    // `BgpRib` is keyed by peer *address*, not by connection, so the exit
    // path below must not deregister a peer this connection never
    // registered: a collision loser (RFC 4271 §6.8) shares its peer address
    // with the connection that beat it, and tearing down the loser would
    // otherwise wipe the *winner's* `adj_rib_in` and — worse — its
    // `peer_outbox`, leaving a session that is still up but can never
    // advertise to that peer again.
    let mut registered = false;
    // The two OPENs, for the BMP Peer Up (#878).
    let open = build_open_message(&cx, &local, &ctx).await;
    let sent_open = open.clone();
    let mut recv_open = None;

    // Single exit point: every early-return case below (`break 'session
    // ...`) funnels through the same `bgp_rib.peer_disconnected` call after
    // this block, rather than returning directly.
    let outcome = 'session: {
        if writer.send(BgpMessage::Open(open)).await.is_err() {
            break 'session FsmOutcome::TcpError;
        }

        loop {
            let event = tokio::select! {
                msg = reader.next() => match msg {
                    Some(Ok(bgp_msg)) => {
                        // Any well-formed inbound message proves liveness —
                        // reset the hold timer regardless of type (RFC 4271 §4.4).
                        if let Some(period) = timers.hold_period {
                            timers.hold_deadline = Some(Instant::now() + period);
                        }
                        match classify_inbound(bgp_msg, &state, &peer, remote_is_ibgp, &bgp_rib, &slot, &mut refresh).await {
                            Some(event) => event,
                            None => continue,
                        }
                    }
                    Some(Err(WireError::Io(_))) => break 'session FsmOutcome::TcpError,
                    Some(Err(e)) => Event::MalformedMessage(e),
                    None => Event::TcpFailed,
                },
                () = sleep_until_opt(timers.hold_deadline) => Event::HoldTimerExpires,
                () = sleep_until_opt(timers.keepalive_deadline) => {
                    if let Some(period) = timers.keepalive_period {
                        timers.keepalive_deadline = Some(Instant::now() + period);
                    }
                    Event::KeepaliveTimerExpires
                }
                () = cease.notified() => Event::CollisionLost,
                () = replaced.notified(), if matches!(state, State::Established(_)) => {
                    info!(peer = %peer.remote_address, "bgp: session replaced by a new connection from the peer (graceful restart)");
                    break 'session FsmOutcome::GrReplaced;
                }
                Some(update) = outbox_rx.recv() => {
                    send_outbound(&mut writer, &mut mrai, update).await;
                    resync_outbox(&cx, &outbox_rx).await;
                    continue;
                }
                // Something was parked in the bounded outbox (#395); `Established`
                // only, before that the RIB knows no outbox for this session.
                () = outbox_tx.parked(), if matches!(state, State::Established(_)) => {
                    resync_outbox(&cx, &outbox_rx).await;
                    continue;
                }
                () = sleep_until_opt(refresh.stale_until.values().min().copied()) => {
                    expire_stale(&cx, &mut refresh.stale_until).await;
                    continue;
                }
                () = sleep_until_opt(mrai.deadline()) => {
                    for update in mrai.flush(Instant::now()) {
                        if let Err(e) = writer.send(outbound_update_to_message(update)).await {
                            warn!(error = %e, "could not send update");
                        }
                    }
                    continue;
                }
                // Guarded on `Established`: collision resolution always
                // happens before either side reaches it, so only the one
                // task that ever becomes canonical polls (and locks)
                // `slot`'s shared command receiver — the collision loser
                // never contends for it.
                Some(cmd) = slot.recv_command(), if matches!(state, State::Established(_)) => {
                    if let Some(outcome) = handle_command(&cx, &mut writer, &state, cmd).await {
                        break 'session outcome;
                    }
                    continue;
                }
            };

            let is_open_event = matches!(event, Event::OpenReceived(_));
            if let Event::OpenReceived(o) = &event {
                recv_open = Some(o.clone());
            }
            let notification_received = match &event {
                Event::NotificationReceived(n) => {
                    log_notification(peer.remote_address, n);
                    Some((n.error_code, n.error_subcode))
                }
                _ => None,
            };
            let (mut next_state, mut actions) = step(state, event, &ctx);

            // Only an OPEN can produce a collision (RFC 4271 §6.8).
            let reached_open_confirm = match (is_open_event, &next_state) {
                (true, Some(State::OpenConfirm(remote))) => Some(*remote),
                _ => None,
            };
            if let Some(remote) = reached_open_confirm
                && let Some((state, lost)) = collision_override(&cx, &local, remote, &cease).await
            {
                next_state = state;
                actions = lost;
            }

            let (notification_sent, newly_registered) =
                run_actions(&cx, &mut reader, &mut writer, &mut timers, &actions).await;
            registered |= newly_registered;
            if newly_registered
                && let (Some(State::Established(remote)), Some(sent), Some(recv)) =
                    (&next_state, Some(sent_open.clone()), recv_open.clone())
            {
                bgp_rib.bmp().peer_up(crate::bmp::PeerUpInfo {
                    peer: peer.remote_address,
                    asn: remote.asn,
                    bgp_id: remote.bgp_id,
                    two_octet_as: !remote.four_octet_as,
                    local: local_addr.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    local_port,
                    remote_port,
                    sent_open: crate::bmp::bgp_pdu(BgpMessage::Open(sent)),
                    recv_open: crate::bmp::bgp_pdu(BgpMessage::Open(recv)),
                    time: crate::bmp::now(),
                    add_path_afis: reader.decoder_mut().add_path_afis.clone(),
                });
            }

            if let Some(s) = next_state {
                state = s;
            } else if let Some((code, subcode)) = notification_received {
                break 'session FsmOutcome::NotificationReceived { code, subcode };
            } else if let Some(outcome) = event_outcome(&actions) {
                break 'session outcome;
            } else if let Some((code, subcode)) = notification_sent {
                break 'session FsmOutcome::NotificationSent { code, subcode };
            } else {
                break 'session FsmOutcome::PeerClosed;
            }
        }
    };

    if registered {
        // Only the session that reported Established owns the caps: a
        // collision loser ending must not clear the winner's.
        slot.set_refresh_caps(false, false);
        let kind = disconnect_kind(&outcome, cx.n_exchanged(&state));
        bgp_rib
            .bmp()
            .peer_down(peer.remote_address, &bmp_down_reason(&outcome));
        bgp_rib
            .lock()
            .await
            .peer_disconnected(peer.remote_address, kind);
    }
    outcome
}

/// Converts one outbound RIB decision into the real `BgpMessage::Update` to
/// send on the wire — the encode side of `crate::rib::BgpRib`'s per-peer
/// propagation decisions. `route.use_mp`/the withdraw's `bool` (set by
/// `crate::rib::build_advertisement`/`BgpRib` from the destination peer's
/// `mp_bgp_negotiated`) picks the legacy plain-NLRI encoding or
/// `MP_REACH_NLRI`/`MP_UNREACH_NLRI` — never derived from the prefix's own
/// family, since the same IPv4 prefix is encoded differently depending on
/// what the destination peer negotiated.
#[allow(clippy::too_many_lines, reason = "one arm per OutboundUpdate variant")]
fn outbound_update_to_message(update: OutboundUpdate) -> BgpMessage {
    match update {
        OutboundUpdate::Announce(route) if route.use_mp => {
            let path_ids = route.path_id.map_or_else(Vec::new, |id| vec![id]);
            let (prefix, next_hop) = (route.prefix, route.next_hop);
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                // The legacy next hop is unused: the real one lives in mp_reach.
                attributes: Some(advertised_attributes(
                    route,
                    Ipv4Addr::UNSPECIFIED,
                    Vec::new(),
                )),
                mp_reach: vec![message::MpReachNlri {
                    afi: afi_of_ipnet(prefix),
                    safi: 1,
                    next_hop,
                    nlri: vec![prefix],
                    nlri_path_ids: path_ids,
                    evpn: Vec::new(),
                    flowspec: Vec::new(),
                    vpn: Vec::new(),
                    rtc: Vec::new(),
                }],
                mp_unreach: Vec::new(),
                ..Default::default()
            })
        }
        OutboundUpdate::Announce(route) => {
            let path_ids = route.path_id.map_or_else(Vec::new, |id| vec![id]);
            let (prefix, next_hop) = (route.prefix, expect_ipv4_addr(route.next_hop));
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                nlri: vec![expect_ipv4_net(prefix)],
                nlri_path_ids: path_ids,
                attributes: Some(advertised_attributes(route, next_hop, Vec::new())),
                mp_reach: Vec::new(),
                mp_unreach: Vec::new(),
                ..Default::default()
            })
        }
        // RFC 8955 section 4: no next hop (`encode_mp_reach` writes length 0).
        OutboundUpdate::AnnounceFlowspec(f) => BgpMessage::Update(message::UpdateMessage {
            withdrawn_routes: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            attributes: Some(advertised_attributes(
                f.route,
                Ipv4Addr::UNSPECIFIED,
                f.ipv6_extended_communities,
            )),
            mp_reach: vec![message::MpReachNlri {
                afi: afi_of(f.family),
                safi: message::SAFI_FLOWSPEC,
                next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                evpn: Vec::new(),
                flowspec: vec![f.nlri],
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            mp_unreach: Vec::new(),
            ..Default::default()
        }),
        OutboundUpdate::WithdrawFlowspec(family, nlri) => {
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                attributes: None,
                mp_reach: Vec::new(),
                mp_unreach: vec![message::MpUnreachNlri {
                    afi: afi_of(family),
                    safi: message::SAFI_FLOWSPEC,
                    withdrawn: Vec::new(),
                    withdrawn_path_ids: Vec::new(),
                    evpn: Vec::new(),
                    flowspec: vec![nlri],
                    vpn: Vec::new(),
                    rtc: Vec::new(),
                }],
                ..Default::default()
            })
        }
        OutboundUpdate::AnnounceRtc(a) => {
            let (key, next_hop) = (a.key, a.route.next_hop);
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                attributes: Some(advertised_attributes(
                    a.route,
                    Ipv4Addr::UNSPECIFIED,
                    Vec::new(),
                )),
                mp_reach: vec![message::MpReachNlri {
                    afi: AFI_IPV4,
                    safi: message::SAFI_RTC,
                    next_hop,
                    nlri: Vec::new(),
                    nlri_path_ids: Vec::new(),
                    evpn: Vec::new(),
                    flowspec: Vec::new(),
                    vpn: Vec::new(),
                    rtc: vec![key],
                }],
                mp_unreach: Vec::new(),
                ..Default::default()
            })
        }
        OutboundUpdate::WithdrawRtc(key) => BgpMessage::Update(message::UpdateMessage {
            withdrawn_routes: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            attributes: None,
            mp_reach: Vec::new(),
            mp_unreach: vec![message::MpUnreachNlri {
                afi: AFI_IPV4,
                safi: message::SAFI_RTC,
                withdrawn: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                evpn: Vec::new(),
                flowspec: Vec::new(),
                vpn: Vec::new(),
                rtc: vec![key],
            }],
            ..Default::default()
        }),
        OutboundUpdate::AnnounceVpn(v) => {
            let ((rd, prefix), labels) = (v.key, v.labels);
            let next_hop = v.route.next_hop;
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                attributes: Some(advertised_attributes(
                    v.route,
                    Ipv4Addr::UNSPECIFIED,
                    Vec::new(),
                )),
                mp_reach: vec![message::MpReachNlri {
                    afi: afi_of_ipnet(prefix),
                    safi: message::SAFI_VPN,
                    next_hop,
                    nlri: Vec::new(),
                    nlri_path_ids: Vec::new(),
                    evpn: Vec::new(),
                    flowspec: Vec::new(),
                    vpn: vec![crate::vpn::VpnNlri { labels, rd, prefix }],
                    rtc: Vec::new(),
                }],
                mp_unreach: Vec::new(),
                ..Default::default()
            })
        }
        OutboundUpdate::WithdrawVpn((rd, prefix)) => BgpMessage::Update(message::UpdateMessage {
            withdrawn_routes: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            attributes: None,
            mp_reach: Vec::new(),
            mp_unreach: vec![message::MpUnreachNlri {
                afi: afi_of_ipnet(prefix),
                safi: message::SAFI_VPN,
                withdrawn: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                evpn: Vec::new(),
                flowspec: Vec::new(),
                vpn: vec![crate::vpn::VpnNlri {
                    labels: Vec::new(),
                    rd,
                    prefix,
                }],
                rtc: Vec::new(),
            }],
            ..Default::default()
        }),
        OutboundUpdate::Withdraw(prefix, use_mp, path_id) if use_mp => {
            let path_ids = path_id.map_or_else(Vec::new, |id| vec![id]);
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                attributes: None,
                mp_reach: Vec::new(),
                mp_unreach: vec![message::MpUnreachNlri {
                    afi: afi_of_ipnet(prefix),
                    safi: 1,
                    withdrawn: vec![prefix],
                    withdrawn_path_ids: path_ids,
                    evpn: Vec::new(),
                    flowspec: Vec::new(),
                    vpn: Vec::new(),
                    rtc: Vec::new(),
                }],
                ..Default::default()
            })
        }
        OutboundUpdate::EndOfRib(family) => {
            let (afi, safi) = gr::afi_safi(family);
            BgpMessage::EndOfRib { afi, safi }
        }
        OutboundUpdate::RefreshMarker { family, subtype } => {
            BgpMessage::RouteRefresh(RouteRefreshMessage {
                afi: afi_of(family),
                subtype,
                safi: safi_of(family),
            })
        }
        OutboundUpdate::AnnounceEvpn(route) => BgpMessage::Update(message::UpdateMessage {
            withdrawn_routes: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            attributes: Some(message::PathAttributes {
                origin: message::Origin::Igp,
                as_path: route.as_path,
                next_hop: Ipv4Addr::UNSPECIFIED, // unused: the real next-hop lives in mp_reach
                local_pref: route.local_pref,
                med: None,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
                otc: None,
                cluster_list: Vec::new(),
                communities: route.communities,
                extended_communities: route.extended_communities,
                large_communities: Vec::new(),
                ipv6_extended_communities: Vec::new(),
                pmsi: route.pmsi,
            }),
            mp_reach: vec![message::MpReachNlri {
                afi: message::AFI_L2VPN,
                safi: message::SAFI_EVPN,
                next_hop: route.next_hop,
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                evpn: vec![route.nlri],
                flowspec: Vec::new(),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            mp_unreach: Vec::new(),
            ..Default::default()
        }),
        OutboundUpdate::WithdrawEvpn(nlri) => BgpMessage::Update(message::UpdateMessage {
            withdrawn_routes: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            attributes: None,
            mp_reach: Vec::new(),
            mp_unreach: vec![message::MpUnreachNlri {
                afi: message::AFI_L2VPN,
                safi: message::SAFI_EVPN,
                withdrawn: Vec::new(),
                withdrawn_path_ids: Vec::new(),
                evpn: vec![nlri],
                flowspec: Vec::new(),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..Default::default()
        }),
        OutboundUpdate::Withdraw(prefix, _, path_id) => {
            let path_ids = path_id.map_or_else(Vec::new, |id| vec![id]);
            BgpMessage::Update(message::UpdateMessage {
                withdrawn_routes: vec![expect_ipv4_net(prefix)],
                withdrawn_path_ids: path_ids,
                nlri: Vec::new(),
                nlri_path_ids: Vec::new(),
                attributes: None,
                mp_reach: Vec::new(),
                mp_unreach: Vec::new(),
                ..Default::default()
            })
        }
    }
}

/// The path attributes of one advertised route; `next_hop` is the legacy
/// `NEXT_HOP`, only encoded with plain NLRI.
fn advertised_attributes(
    route: crate::rib::AdvertisedRoute,
    next_hop: Ipv4Addr,
    ipv6_extended_communities: Vec<[u8; 20]>,
) -> message::PathAttributes {
    message::PathAttributes {
        origin: route.origin,
        as_path: route.as_path,
        next_hop,
        local_pref: route.local_pref,
        med: route.med,
        originator_id: route.originator_id,
        cluster_list: route.cluster_list,
        communities: route.communities,
        extended_communities: route.extended_communities,
        large_communities: route.large_communities,
        ipv6_extended_communities,
        pmsi: None,
        atomic_aggregate: route.atomic_aggregate,
        aggregator: route.aggregator,
        otc: route.otc,
    }
}

fn afi_of_ipnet(net: ipnet::IpNet) -> u16 {
    match net {
        ipnet::IpNet::V4(_) => AFI_IPV4,
        ipnet::IpNet::V6(_) => AFI_IPV6,
    }
}

/// Only ever called for a `!use_mp` (legacy) `OutboundUpdate` — `BgpRib`
/// only sets `use_mp: false` for an `Ipv4Unicast` prefix/next-hop (see
/// `crate::rib::build_advertisement`), so the `V6` arm is unreachable.
fn expect_ipv4_net(net: ipnet::IpNet) -> ipnet::Ipv4Net {
    match net {
        ipnet::IpNet::V4(n) => n,
        ipnet::IpNet::V6(_) => {
            unreachable!("legacy OutboundUpdate only ever carries an IPv4 prefix")
        }
    }
}

fn expect_ipv4_addr(addr: IpAddr) -> Ipv4Addr {
    match addr {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => unreachable!("legacy OutboundUpdate only ever carries an IPv4 next-hop"),
    }
}

/// Reads the specific closing cause back out of the actions `step` produced,
/// for outcomes that need to be distinguished from a generic "we sent a
/// notification" (hold-timer expiry, collision loss, or the peer's own
/// NOTIFICATION) — everything else falls through to the caller's generic
/// classification.
fn event_outcome(actions: &[Action]) -> Option<FsmOutcome> {
    for action in actions {
        if let Action::SendNotification(code, subcode) = action {
            if *code == ErrorCode::HoldTimerExpired as u8 {
                return Some(FsmOutcome::HoldTimerExpired);
            }
            if *code == ErrorCode::Cease as u8
                && *subcode == CeaseSubcode::ConnectionCollisionResolution as u8
            {
                return Some(FsmOutcome::CollisionLost);
            }
        }
    }
    None
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(expected_remote_as: u32) -> NegotiationContext {
        NegotiationContext {
            expected_remote_as,
            local_hold_time: 90,
            keepalive_override: None,
            address_families: vec![AddressFamily::Ipv4Unicast],
            transport_afi: AFI_IPV4,
            add_path: None,
            role: None,
            strict_mode: false,
        }
    }

    fn ctx_with(
        expected_remote_as: u32,
        local_hold_time: u16,
        keepalive_override: Option<u16>,
    ) -> NegotiationContext {
        NegotiationContext {
            expected_remote_as,
            local_hold_time,
            keepalive_override,
            address_families: vec![AddressFamily::Ipv4Unicast],
            transport_afi: AFI_IPV4,
            add_path: None,
            role: None,
            strict_mode: false,
        }
    }

    fn valid_open(remote_as: u32, hold_time: u16) -> OpenMessage {
        message::build_open(remote_as, Ipv4Addr::new(2, 2, 2, 2), hold_time)
    }

    fn open_with_mp(afis: &[(u16, u8)]) -> OpenMessage {
        let mut open = valid_open(65002, 90);
        for &(afi, safi) in afis {
            open.capabilities
                .push(message::Capability::MultiProtocol { afi, safi });
        }
        open
    }

    fn ctx_with_afs(
        address_families: Vec<AddressFamily>,
        transport_afi: u16,
    ) -> NegotiationContext {
        NegotiationContext {
            address_families,
            transport_afi,
            ..ctx(65002)
        }
    }

    #[test]
    fn evpn_negotiated_only_when_both_sides_advertise_it() {
        let both = ctx_with_afs(
            vec![AddressFamily::Ipv4Unicast, AddressFamily::L2vpnEvpn],
            AFI_IPV4,
        );
        let peer = open_with_mp(&[(AFI_IPV4, 1), (message::AFI_L2VPN, message::SAFI_EVPN)]);
        assert_eq!(
            negotiate_address_families(&peer, &both),
            (true, true, false, true)
        );
        // Peer never offered it.
        let no_evpn = open_with_mp(&[(AFI_IPV4, 1)]);
        assert_eq!(
            negotiate_address_families(&no_evpn, &both),
            (true, true, false, false)
        );
        // We never configured it.
        let ipv4_only = ctx_with_afs(vec![AddressFamily::Ipv4Unicast], AFI_IPV4);
        assert_eq!(
            negotiate_address_families(&peer, &ipv4_only),
            (true, true, false, false)
        );
        // EVPN alone needs no Extended Next Hop, even over an IPv6 transport.
        let v6_transport = ctx_with_afs(vec![AddressFamily::L2vpnEvpn], AFI_IPV6);
        let evpn_only = open_with_mp(&[(message::AFI_L2VPN, message::SAFI_EVPN)]);
        assert_eq!(
            negotiate_address_families(&evpn_only, &v6_transport),
            (true, false, false, true)
        );
    }

    fn open_with_add_path(tuples: &[(u16, u8, u8)]) -> OpenMessage {
        let mut open = valid_open(65002, 90);
        open.capabilities.push(message::Capability::AddPath(
            tuples
                .iter()
                .map(|&(afi, safi, send_receive)| message::AddPathTuple {
                    afi,
                    safi,
                    send_receive,
                })
                .collect(),
        ));
        open
    }

    fn add_path_ctx(mode: Option<nos_proto::BgpAddPath>) -> NegotiationContext {
        NegotiationContext {
            add_path: mode,
            role: None,
            strict_mode: false,
            ..ctx_with_afs(
                vec![AddressFamily::Ipv4Unicast, AddressFamily::Ipv6Unicast],
                AFI_IPV4,
            )
        }
    }

    #[test]
    fn add_path_direction_follows_rfc7911_section5() {
        use nos_proto::BgpAddPath::{Both, Receive, Send};
        let dir = |rx, tx| AddPathDir { rx, tx };
        // Local mode x peer value (1 receive, 2 send, 3 both).
        let cases = [
            (Receive, 1, dir(false, false)),
            (Receive, 2, dir(true, false)),
            (Receive, 3, dir(true, false)),
            (Send, 1, dir(false, true)),
            (Send, 2, dir(false, false)),
            (Send, 3, dir(false, true)),
            (Both, 1, dir(false, true)),
            (Both, 2, dir(true, false)),
            (Both, 3, dir(true, true)),
        ];
        for (mode, peer, want) in cases {
            let open = open_with_add_path(&[(AFI_IPV4, 1, peer)]);
            assert_eq!(
                negotiate_add_path(&open, &add_path_ctx(Some(mode))),
                [want, AddPathDir::default()],
                "{mode:?} x {peer}"
            );
        }
    }

    #[test]
    fn add_path_ignores_safi2_bad_values_and_unconfigured_sessions() {
        let none = [AddPathDir::default(); 2];
        let both = Some(nos_proto::BgpAddPath::Both);
        // A multicast (SAFI 2) tuple is not unicast ADD-PATH.
        let multicast = open_with_add_path(&[(AFI_IPV4, 2, 3)]);
        assert_eq!(negotiate_add_path(&multicast, &add_path_ctx(both)), none);
        // A value of 4 makes the whole capability not understood.
        let bad = open_with_add_path(&[(AFI_IPV4, 1, 3), (AFI_IPV6, 1, 4)]);
        assert_eq!(negotiate_add_path(&bad, &add_path_ctx(both)), none);
        // No local mode: the peer's capability doesn't matter.
        let fine = open_with_add_path(&[(AFI_IPV4, 1, 3), (AFI_IPV6, 1, 3)]);
        assert_eq!(negotiate_add_path(&fine, &add_path_ctx(None)), none);
        let full = AddPathDir { rx: true, tx: true };
        assert_eq!(negotiate_add_path(&fine, &add_path_ctx(both)), [full, full]);
    }

    #[test]
    fn vpn_capability_is_afi_safi_128_without_extended_next_hop() {
        let vpn = [AddressFamily::Vpnv4Unicast, AddressFamily::Vpnv6Unicast];
        for transport in [AFI_IPV4, AFI_IPV6] {
            assert_eq!(
                build_mp_capabilities(&vpn, transport),
                vec![
                    message::Capability::MultiProtocol { afi: 1, safi: 128 },
                    message::Capability::MultiProtocol { afi: 2, safi: 128 },
                ]
            );
        }
        assert!(!is_unicast(vpn[0]) && !is_unicast(vpn[1]));
        // Graceful Restart lists them (#578).
        let cap = crate::gr::our_cap(60, &vpn, false, false);
        assert_eq!(cap.families.len(), 2);
        assert_eq!(
            PeerGr::from_cap(&cap).families(),
            vpn.to_vec(),
            "and recognises them back"
        );
        assert_eq!(crate::gr::afi_safi(vpn[0]), (1, 128));
        assert_eq!(crate::gr::afi_safi(vpn[1]), (2, 128));
    }

    #[test]
    fn vpn_negotiated_per_afi_only_when_both_sides_advertise_it() {
        let ctx = ctx_with_afs(
            vec![
                AddressFamily::Ipv4Unicast,
                AddressFamily::Vpnv4Unicast,
                AddressFamily::Vpnv6Unicast,
            ],
            AFI_IPV4,
        );
        let peer = open_with_mp(&[(AFI_IPV4, 1), (AFI_IPV4, 128)]);
        assert_eq!(negotiate_vpn(&peer, &ctx), [true, false]);
        // Unicast is untouched by a VPN tuple.
        assert_eq!(
            negotiate_address_families(&peer, &ctx),
            (true, true, false, false)
        );
        // Peer lacks it, or we never configured it.
        let plain = open_with_mp(&[(AFI_IPV4, 1)]);
        assert_eq!(negotiate_vpn(&plain, &ctx), [false, false]);
        let unicast_only = ctx_with_afs(vec![AddressFamily::Ipv4Unicast], AFI_IPV4);
        assert_eq!(negotiate_vpn(&peer, &unicast_only), [false, false]);
        // VPNv6 over an IPv4 transport needs no Extended Next Hop.
        let v6 = open_with_mp(&[(AFI_IPV6, 128), (AFI_IPV4, 128)]);
        assert_eq!(negotiate_vpn(&v6, &ctx), [true, true]);
        // A VPN-only session negotiates no unicast.
        let vpn_only = ctx_with_afs(vec![AddressFamily::Vpnv4Unicast], AFI_IPV6);
        assert_eq!(
            negotiate_address_families(&peer, &vpn_only),
            (true, false, false, false)
        );
        assert_eq!(negotiate_vpn(&peer, &vpn_only), [true, false]);
    }

    #[test]
    fn evpn_capability_is_sent_as_afi25_safi70_without_extended_next_hop() {
        let caps = build_mp_capabilities(&[AddressFamily::L2vpnEvpn], AFI_IPV6);
        assert_eq!(
            caps,
            vec![message::Capability::MultiProtocol {
                afi: message::AFI_L2VPN,
                safi: message::SAFI_EVPN
            }]
        );
    }

    #[test]
    fn flowspec_capability_is_afi_safi_133_without_extended_next_hop() {
        // Either AFI over either transport: no ENH tuple, never.
        for transport in [AFI_IPV4, AFI_IPV6] {
            let caps = build_mp_capabilities(
                &[AddressFamily::Ipv4Flowspec, AddressFamily::Ipv6Flowspec],
                transport,
            );
            assert_eq!(
                caps,
                vec![
                    message::Capability::MultiProtocol { afi: 1, safi: 133 },
                    message::Capability::MultiProtocol { afi: 2, safi: 133 },
                ]
            );
        }
    }

    #[test]
    fn flowspec_negotiated_per_afi_only_when_both_sides_advertise_it() {
        let ctx = ctx_with_afs(
            vec![
                AddressFamily::Ipv4Unicast,
                AddressFamily::Ipv4Flowspec,
                AddressFamily::Ipv6Flowspec,
            ],
            AFI_IPV4,
        );
        let peer = open_with_mp(&[(AFI_IPV4, 1), (AFI_IPV4, 133)]);
        assert_eq!(negotiate_flowspec(&peer, &ctx), [true, false]);
        // Unicast is untouched by a flowspec tuple, and flowspec alone does
        // not enable unicast.
        assert_eq!(
            negotiate_address_families(&peer, &ctx),
            (true, true, false, false)
        );
        let flowspec_only = ctx_with_afs(vec![AddressFamily::Ipv4Flowspec], AFI_IPV4);
        assert_eq!(
            negotiate_address_families(&peer, &flowspec_only),
            (true, false, false, false)
        );
        // We never configured it.
        let unicast_only = ctx_with_afs(vec![AddressFamily::Ipv4Unicast], AFI_IPV4);
        assert_eq!(negotiate_flowspec(&peer, &unicast_only), [false, false]);
        // IPv6 flowspec over an IPv4 transport needs no Extended Next Hop.
        let v6 = open_with_mp(&[(AFI_IPV6, 133)]);
        assert_eq!(negotiate_flowspec(&v6, &ctx), [false, true]);
    }

    #[test]
    fn valid_open_moves_to_open_confirm_and_arms_timers() {
        let (next, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 90)),
            &ctx(65002),
        );
        assert!(matches!(next, Some(State::OpenConfirm(_))));
        assert!(actions.contains(&Action::SendKeepalive));
        assert!(actions.contains(&Action::ArmHoldTimer(Duration::from_secs(90))));
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::from_secs(30))));
    }

    #[test]
    fn bad_version_is_rejected() {
        let mut open = valid_open(65002, 90);
        open.version = 3;
        let (next, actions) = step(State::OpenSent, Event::OpenReceived(open), &ctx(65002));
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::UnsupportedVersionNumber as u8
        )));
    }

    #[test]
    fn asn_mismatch_is_rejected() {
        let (next, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65099, 90)),
            &ctx(65002),
        );
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::BadPeerAs as u8
        )));
    }

    #[test]
    fn bad_bgp_identifier_is_rejected() {
        let mut open = valid_open(65002, 90);
        open.bgp_identifier = Ipv4Addr::UNSPECIFIED;
        let (next, actions) = step(State::OpenSent, Event::OpenReceived(open), &ctx(65002));
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::BadBgpIdentifier as u8
        )));
    }

    #[test]
    fn hold_time_of_one_or_two_is_rejected() {
        for bad in [1u16, 2u16] {
            let (next, actions) = step(
                State::OpenSent,
                Event::OpenReceived(valid_open(65002, bad)),
                &ctx(65002),
            );
            assert_eq!(next, None);
            assert!(actions.contains(&Action::SendNotification(
                ErrorCode::OpenMessage as u8,
                OpenMessageSubcode::UnacceptableHoldTime as u8
            )));
        }
    }

    #[test]
    fn remote_hold_zero_is_rejected_unless_local_is_zero() {
        let (next, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 0)),
            &ctx_with(65002, 90, None),
        );
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::UnacceptableHoldTime as u8
        )));
    }

    #[test]
    fn hold_time_zero_disables_both_timers() {
        let (next, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 0)),
            &ctx_with(65002, 0, None),
        );
        assert!(matches!(next, Some(State::OpenConfirm(_))));
        assert!(actions.contains(&Action::ArmHoldTimer(Duration::ZERO)));
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::ZERO)));
    }

    #[test]
    fn as_trans_without_capability_is_bad_peer_as() {
        let mut open = valid_open(65002, 90);
        open.my_as = message::AS_TRANS;
        open.capabilities.clear();
        let (next, actions) = step(State::OpenSent, Event::OpenReceived(open), &ctx(65002));
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::BadPeerAs as u8
        )));
    }

    #[test]
    fn as_zero_is_bad_peer_as_even_when_expected() {
        let (next, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(0, 90)),
            &ctx(0),
        );
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::BadPeerAs as u8
        )));
    }

    #[test]
    fn extended_message_follows_the_peers_capability() {
        let mut with_cap = valid_open(65002, 90);
        with_cap
            .capabilities
            .push(message::Capability::ExtendedMessage);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&with_cap, &ctx(65002)) else {
            panic!("expected OpenConfirm");
        };
        assert!(r.extended_message);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&valid_open(65002, 90), &ctx(65002))
        else {
            panic!("expected OpenConfirm");
        };
        assert!(!r.extended_message);
    }

    /// RFC 2918 §4: no `ROUTE_REFRESH` toward a peer that didn't advertise
    /// the capability (#17).
    #[test]
    fn route_refresh_follows_the_peers_capability() {
        let mut with_cap = valid_open(65002, 90);
        with_cap
            .capabilities
            .push(message::Capability::RouteRefresh);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&with_cap, &ctx(65002)) else {
            panic!("expected OpenConfirm");
        };
        assert!(r.route_refresh);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&valid_open(65002, 90), &ctx(65002))
        else {
            panic!("expected OpenConfirm");
        };
        assert!(!r.route_refresh);
    }

    #[test]
    fn four_octet_as_follows_the_peers_capability() {
        let with_cap = valid_open(65002, 90);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&with_cap, &ctx(65002)) else {
            panic!("expected OpenConfirm");
        };
        assert!(r.four_octet_as);
        let mut without = with_cap;
        without.capabilities.clear();
        let (Some(State::OpenConfirm(r)), _) = handle_open(&without, &ctx(65002)) else {
            panic!("expected OpenConfirm");
        };
        assert!(!r.four_octet_as);
    }

    #[test]
    fn keepalive_in_open_confirm_reaches_established() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
            mp_bgp_negotiated: false,
            negotiated_ipv4_unicast: true,
            negotiated_ipv6_unicast: false,
            negotiated_evpn: false,
            negotiated_flowspec: [false; 2],
            negotiated_vpn: [false; 2],
            negotiated_rtc: false,
            add_path: [AddPathDir::default(); 2],
            role: None,
            four_octet_as: true,
            extended_message: false,
            enhanced_refresh: false,
            route_refresh: false,
            gr: None,
        };
        let (next, actions) = step(
            State::OpenConfirm(remote),
            Event::KeepaliveReceived,
            &ctx(65002),
        );
        assert_eq!(next, Some(State::Established(remote)));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ReportEstablished { .. })));
    }

    #[test]
    fn hold_timer_expiry_closes_at_every_state() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
            mp_bgp_negotiated: false,
            negotiated_ipv4_unicast: true,
            negotiated_ipv6_unicast: false,
            negotiated_evpn: false,
            negotiated_flowspec: [false; 2],
            negotiated_vpn: [false; 2],
            negotiated_rtc: false,
            add_path: [AddPathDir::default(); 2],
            role: None,
            four_octet_as: true,
            extended_message: false,
            enhanced_refresh: false,
            route_refresh: false,
            gr: None,
        };
        for state in [
            State::OpenSent,
            State::OpenConfirm(remote),
            State::Established(remote),
        ] {
            let (next, actions) = step(state, Event::HoldTimerExpires, &ctx(65002));
            assert_eq!(next, None);
            assert!(actions.contains(&Action::SendNotification(
                ErrorCode::HoldTimerExpired as u8,
                0
            )));
        }
    }

    #[test]
    fn unexpected_message_uses_rfc6608_subcode_of_current_state() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
            mp_bgp_negotiated: false,
            negotiated_ipv4_unicast: true,
            negotiated_ipv6_unicast: false,
            negotiated_evpn: false,
            negotiated_flowspec: [false; 2],
            negotiated_vpn: [false; 2],
            negotiated_rtc: false,
            add_path: [AddPathDir::default(); 2],
            role: None,
            four_octet_as: true,
            extended_message: false,
            enhanced_refresh: false,
            route_refresh: false,
            gr: None,
        };
        for (state, event, subcode) in [
            (State::OpenSent, Event::KeepaliveReceived, 1),
            (State::OpenSent, Event::UnexpectedUpdate, 1),
            (State::OpenConfirm(remote), Event::UnexpectedUpdate, 2),
            (
                State::OpenConfirm(remote),
                Event::OpenReceived(valid_open(65002, 90)),
                2,
            ),
            (
                State::Established(remote),
                Event::OpenReceived(valid_open(65002, 90)),
                3,
            ),
        ] {
            let (next, actions) = step(state, event, &ctx(65002));
            assert_eq!(next, None);
            assert!(actions.contains(&Action::SendNotification(
                ErrorCode::FiniteStateMachine as u8,
                subcode
            )));
        }
    }

    #[test]
    fn notification_received_never_replies() {
        let (next, actions) = step(
            State::OpenSent,
            Event::NotificationReceived(NotificationMessage {
                error_code: 1,
                error_subcode: 1,
                data: Bytes::new(),
            }),
            &ctx(65002),
        );
        assert_eq!(next, None);
        assert_eq!(actions, vec![Action::Close]);
    }

    #[test]
    fn collision_lost_sends_cease() {
        let (next, actions) = step(State::OpenSent, Event::CollisionLost, &ctx(65002));
        assert_eq!(next, None);
        assert!(actions.contains(&Action::SendNotification(
            ErrorCode::Cease as u8,
            CeaseSubcode::ConnectionCollisionResolution as u8
        )));
    }

    #[test]
    fn established_keepalive_tick_stays_established_and_sends_keepalive() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
            mp_bgp_negotiated: false,
            negotiated_ipv4_unicast: true,
            negotiated_ipv6_unicast: false,
            negotiated_evpn: false,
            negotiated_flowspec: [false; 2],
            negotiated_vpn: [false; 2],
            negotiated_rtc: false,
            add_path: [AddPathDir::default(); 2],
            role: None,
            four_octet_as: true,
            extended_message: false,
            enhanced_refresh: false,
            route_refresh: false,
            gr: None,
        };
        let (next, actions) = step(
            State::Established(remote),
            Event::KeepaliveTimerExpires,
            &ctx(65002),
        );
        assert_eq!(next, Some(State::Established(remote)));
        assert_eq!(actions, vec![Action::SendKeepalive]);
    }

    #[test]
    fn established_keepalive_received_resets_nothing_but_stays_up() {
        let remote = RemoteInfo {
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
            mp_bgp_negotiated: false,
            negotiated_ipv4_unicast: true,
            negotiated_ipv6_unicast: false,
            negotiated_evpn: false,
            negotiated_flowspec: [false; 2],
            negotiated_vpn: [false; 2],
            negotiated_rtc: false,
            add_path: [AddPathDir::default(); 2],
            role: None,
            four_octet_as: true,
            extended_message: false,
            enhanced_refresh: false,
            route_refresh: false,
            gr: None,
        };
        let (next, actions) = step(
            State::Established(remote),
            Event::KeepaliveReceived,
            &ctx(65002),
        );
        assert_eq!(next, Some(State::Established(remote)));
        assert_eq!(actions, []);
    }

    #[test]
    fn non_default_local_hold_time_is_used_in_negotiation() {
        // Peer proposes 90s but we only proposed 30s locally — negotiated
        // hold must be the lower of the two.
        let (_, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 90)),
            &ctx_with(65002, 30, None),
        );
        assert!(actions.contains(&Action::ArmHoldTimer(Duration::from_secs(30))));
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::from_secs(10))));
    }

    #[test]
    fn handle_open_respects_keepalive_override() {
        let (_, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 90)),
            &ctx_with(65002, 90, Some(5)),
        );
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::from_secs(5))));
    }

    #[test]
    fn handle_open_falls_back_to_third_when_override_exceeds_negotiated_hold() {
        // Override 10 is valid against the locally-configured hold-time of
        // 90, but the peer only proposes 6s — negotiated_hold ends up
        // smaller than the override, which commit-time validation can't see
        // in advance, so the runtime must fall back to negotiated_hold / 3.
        let (_, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 6)),
            &ctx_with(65002, 90, Some(10)),
        );
        // negotiated_hold = min(90, 6) = 6; override (10) >= 6, so falls
        // back to negotiated_hold / 3 = 2.
        assert!(actions.contains(&Action::ArmHoldTimer(Duration::from_secs(6))));
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::from_secs(2))));
    }

    #[test]
    fn handle_open_negotiated_hold_zero_forces_keepalive_zero_even_with_override() {
        let (_, actions) = step(
            State::OpenSent,
            Event::OpenReceived(valid_open(65002, 0)),
            &ctx_with(65002, 0, Some(5)),
        );
        assert!(actions.contains(&Action::ArmHoldTimer(Duration::ZERO)));
        assert!(actions.contains(&Action::ArmKeepaliveTimer(Duration::ZERO)));
    }

    #[test]
    fn graceful_restart_follows_the_peers_capability() {
        let mut with_cap = valid_open(65002, 90);
        with_cap
            .capabilities
            .push(message::Capability::GracefulRestart(gr::our_cap(
                90,
                &[AddressFamily::Ipv4Unicast],
                true,
                true,
            )));
        let (Some(State::OpenConfirm(r)), _) = handle_open(&with_cap, &ctx(65002)) else {
            panic!("expected OpenConfirm");
        };
        let g = r.gr.unwrap();
        assert!(g.restart && g.notification && g.forwarding(AddressFamily::Ipv4Unicast));
        assert_eq!(g.time, 90);
        let (Some(State::OpenConfirm(r)), _) = handle_open(&valid_open(65002, 90), &ctx(65002))
        else {
            panic!("expected OpenConfirm");
        };
        assert!(r.gr.is_none());
    }

    /// TCP loss keeps routes; a NOTIFICATION only with N, never a Hard Reset.
    #[test]
    fn disconnect_kind_per_outcome() {
        use FsmOutcome::*;
        let hard = CeaseSubcode::HardReset as u8;
        for (outcome, n, want) in [
            (TcpError, false, Disconnect::Transport),
            (GrReplaced, true, Disconnect::Transport),
            (HoldTimerExpired, true, Disconnect::Graceful),
            (HoldTimerExpired, false, Disconnect::Hard),
            (
                NotificationSent {
                    code: 6,
                    subcode: 6,
                },
                true,
                Disconnect::Graceful,
            ),
            (
                NotificationReceived {
                    code: 6,
                    subcode: hard,
                },
                true,
                Disconnect::Hard,
            ),
            (
                NotificationReceived {
                    code: 6,
                    subcode: 6,
                },
                false,
                Disconnect::Hard,
            ),
        ] {
            assert_eq!(disconnect_kind(&outcome, n), want, "{outcome:?} n={n}");
        }
    }

    /// RFC 4486 §4: Cease/Maximum Number of Prefixes Reached carries
    /// `AFI(2) SAFI(1) limit(4)` for the family that tripped.
    #[test]
    fn max_prefix_cease_data_per_family() {
        let data = |f| message::encode_max_prefix_data(afi_of(f), safi_of(f), 1000).to_vec();
        assert_eq!(data(AddressFamily::Ipv4Unicast), [0, 1, 1, 0, 0, 3, 0xe8]);
        assert_eq!(data(AddressFamily::Ipv6Unicast), [0, 2, 1, 0, 0, 3, 0xe8]);
        assert_eq!(data(AddressFamily::L2vpnEvpn), [0, 25, 70, 0, 0, 3, 0xe8]);
    }

    #[test]
    fn role_pairs_and_strict_mode() {
        use nos_proto::BgpRole::{Customer, Peer, Provider, RouteServer, RouteServerClient};
        let all = [Provider, RouteServer, RouteServerClient, Customer, Peer];
        for ours in all {
            for theirs in all {
                let mut open = valid_open(65002, 90);
                open.capabilities
                    .push(message::Capability::Role(theirs.wire()));
                let c = NegotiationContext {
                    role: Some(ours),
                    ..ctx(65002)
                };
                let (state, actions) = handle_open(&open, &c);
                if theirs == ours.counterpart() {
                    assert!(matches!(state, Some(State::OpenConfirm(r)) if r.role == Some(ours)));
                } else {
                    assert!(state.is_none(), "{ours:?}/{theirs:?}");
                    assert_eq!(
                        actions[0],
                        Action::SendNotification(2, OpenMessageSubcode::RoleMismatch as u8)
                    );
                }
            }
        }
        // An unassigned wire value is never a legal pair.
        let mut open = valid_open(65002, 90);
        open.capabilities.push(message::Capability::Role(9));
        let c = NegotiationContext {
            role: Some(Peer),
            ..ctx(65002)
        };
        assert!(handle_open(&open, &c).0.is_none());
        // No Role from the peer: refused in strict mode, else no role negotiated.
        for (strict, ok) in [(true, false), (false, true)] {
            let c = NegotiationContext {
                role: Some(Provider),
                strict_mode: strict,
                ..ctx(65002)
            };
            let (state, _) = handle_open(&valid_open(65002, 90), &c);
            match state {
                Some(State::OpenConfirm(r)) => assert!(ok && r.role.is_none()),
                None => assert!(!ok),
                _ => panic!(),
            }
        }
        // We announce no role: the peer's is ignored.
        let mut open = valid_open(65002, 90);
        open.capabilities.push(message::Capability::Role(0));
        assert!(matches!(
            handle_open(&open, &ctx(65002)).0,
            Some(State::OpenConfirm(r)) if r.role.is_none()
        ));
    }
}

#[cfg(test)]
#[path = "fsm_tests.rs"]
mod io_tests;
