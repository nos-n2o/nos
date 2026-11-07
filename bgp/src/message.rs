//! RFC 4271 BGP-4 wire message format: header, OPEN, KEEPALIVE, NOTIFICATION,
//! UPDATE, plus the RFC 6793 four-octet AS number capability, RFC 4760
//! Multiprotocol Extensions (`MP_REACH_NLRI`/`MP_UNREACH_NLRI`, IPv6 unicast),
//! and RFC 8950 Extended Next Hop Encoding (a session's transport family is
//! independent of which address family/families it carries). This is BGP's
//! own wire contract with external routers, not an inter-NOS-daemon IPC
//! contract, so it lives here rather than in `nos-proto` (whose `IpcCodec` is
//! postcard-based and structurally incompatible with BGP's raw big-endian
//! format anyway).
//!
//! IPv4 unicast keeps its legacy plain-NLRI wire encoding
//! (`UpdateMessage::{withdrawn_routes,nlri}` + `PathAttributes::next_hop`) as
//! a fallback for peers that never negotiate any Multiprotocol Extensions
//! capability at all; any other family (and, once a peer does negotiate
//! MP-BGP, IPv4 unicast too — see `crate::rib::build_advertisement`) goes
//! through `UpdateMessage::{mp_reach,mp_unreach}` instead. Decodes
//! `ORIGIN`/`AS_PATH`/`NEXT_HOP`/`LOCAL_PREF`/`MULTI_EXIT_DISC`/
//! `MP_REACH_NLRI`/`MP_UNREACH_NLRI` path attributes and skips any other attribute type by
//! its declared length (never an error — the same philosophy
//! `parse_optional_parameters` already applies to unknown OPEN capabilities),
//! and, for a peer that never sent the four-octet AS capability
//! (`BgpCodec::two_octet_as`), speaks RFC 6793's transition encoding: 2-byte
//! `AS_PATH` with `AS_TRANS` plus `AS4_PATH` on send, `AS4_PATH` merged back
//! in on receipt (no `AGGREGATOR` attribute exists here, so no
//! `AS4_AGGREGATOR`). Any other/unknown message type
//! still decodes as `BgpMessage::Unhandled` so the codec never chokes on one
//! arriving.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, warn};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ipnet::{IpNet, Ipv4Net};
use tokio_util::codec::{Decoder, Encoder};

use crate::as_path::{AsPath, SegKind};
use crate::evpn::{self, EvpnNlri};
use crate::flowspec::{self, FlowSpec};
use crate::vpn::{self, VpnNlri};

pub const BGP_VERSION: u8 = 4;
const MARKER: [u8; 16] = [0xFF; 16];
const HEADER_LEN: usize = 19;
const MAX_MESSAGE_LEN: usize = 4096;
/// RFC 8654 §4: ceiling once both sides advertised the Extended Message
/// capability — never applies to OPEN or KEEPALIVE.
const MAX_EXTENDED_MESSAGE_LEN: usize = 65535;

/// RFC 6793 placeholder used in OPEN's 2-byte "My Autonomous System" field
/// whenever the real ASN doesn't fit in 2 bytes; the real value then travels
/// in the four-octet AS number capability instead.
pub const AS_TRANS: u16 = 23456;

/// RFC 1997 well-known communities (`0xFFFF_xxxx`).
pub const COMMUNITY_NO_EXPORT: u32 = 0xFFFF_FF01;
pub const COMMUNITY_NO_ADVERTISE: u32 = 0xFFFF_FF02;
pub const COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFF_FF03;
/// RFC 7999 `BLACKHOLE` (65535:666).
pub const COMMUNITY_BLACKHOLE: u32 = 0xFFFF_029A;
/// RFC 8326 `GRACEFUL_SHUTDOWN` (65535:0).
pub const COMMUNITY_GRACEFUL_SHUTDOWN: u32 = 0xFFFF_0000;

const TYPE_OPEN: u8 = 1;
const TYPE_UPDATE: u8 = 2;
const TYPE_NOTIFICATION: u8 = 3;
const TYPE_KEEPALIVE: u8 = 4;
const TYPE_ROUTE_REFRESH: u8 = 5;

const OPT_PARAM_CAPABILITIES: u8 = 2;
const CAP_FOUR_OCTET_ASN: u8 = 65;
/// RFC 4760 §8 Multiprotocol Extensions capability: `AFI(2) reserved(1)
/// SAFI(1)`.
const CAP_MULTIPROTOCOL: u8 = 1;
/// RFC 2918 §3 Route Refresh capability: no payload.
const CAP_ROUTE_REFRESH: u8 = 2;
/// RFC 7313 Enhanced Route Refresh capability: no payload.
const CAP_ENHANCED_ROUTE_REFRESH: u8 = 70;
/// RFC 8654 §3 Extended Message capability: no payload.
const CAP_EXTENDED_MESSAGE: u8 = 6;
/// RFC 8950 §3 Extended Next Hop Encoding capability: one or more `NLRI-AFI(2)
/// NLRI-SAFI(2) NextHop-AFI(2)` tuples — note the NLRI-SAFI field is 2 bytes
/// here, unlike `CAP_MULTIPROTOCOL`'s 1-byte SAFI.
const CAP_EXTENDED_NEXT_HOP: u8 = 5;
/// RFC 7911 §3 ADD-PATH capability: one or more `AFI(2) SAFI(1)
/// SendReceive(1)` tuples.
const CAP_ADD_PATH: u8 = 69;
/// RFC 4724 §3 Graceful Restart capability: `Restart Flags(4 bits) Restart
/// Time(12 bits)` then `AFI(2) SAFI(1) Flags(1)` tuples.
const CAP_GRACEFUL_RESTART: u8 = 64;
/// RFC 9234 §4.1 BGP Role capability: one octet.
const CAP_ROLE: u8 = 9;
/// RFC 4724 R bit / RFC 8538 §2 N bit, in the first 16 bits.
const GR_FLAG_RESTART: u16 = 0x8000;
const GR_FLAG_NOTIFICATION: u16 = 0x4000;
/// RFC 4724 F bit, in a tuple's flags octet.
const GR_FLAG_FORWARDING: u8 = 0x80;

/// AFI values this crate understands (RFC 4760's registry has many more).
pub(crate) const AFI_IPV4: u16 = 1;
pub(crate) const AFI_IPV6: u16 = 2;
/// RFC 7432 EVPN: AFI L2VPN (25) / SAFI EVPN (70).
pub(crate) const AFI_L2VPN: u16 = 25;
pub(crate) const SAFI_EVPN: u8 = 70;
/// RFC 4364 MPLS-labelled VPN unicast (VPNv4/VPNv6): SAFI 128.
pub(crate) const SAFI_VPN: u8 = 128;
/// RFC 4684 Route Target Constraint.
pub(crate) const SAFI_RTC: u8 = 132;
/// RFC 8955 Flow Specification: SAFI 133, and 134 with a Route Distinguisher.
pub(crate) const SAFI_FLOWSPEC: u8 = 133;
#[allow(dead_code, reason = "wired by #558")]
pub(crate) const SAFI_FLOWSPEC_VPN: u8 = 134;

const ATTR_ORIGIN: u8 = 1;
const ATTR_AS_PATH: u8 = 2;
const ATTR_NEXT_HOP: u8 = 3;
const ATTR_MULTI_EXIT_DISC: u8 = 4;
const ATTR_LOCAL_PREF: u8 = 5;
const ATTR_ATOMIC_AGGREGATE: u8 = 6;
const ATTR_AGGREGATOR: u8 = 7;
const ATTR_ORIGINATOR_ID: u8 = 9;
const ATTR_CLUSTER_LIST: u8 = 10;
const ATTR_MP_REACH_NLRI: u8 = 14;
const ATTR_MP_UNREACH_NLRI: u8 = 15;
/// RFC 1997 §3 standard community — a list of 4-byte values.
const ATTR_COMMUNITY: u8 = 8;
/// RFC 4360 §3 extended community — a list of 8-byte (type/subtype/value)
/// values.
const ATTR_EXTENDED_COMMUNITIES: u8 = 16;
/// RFC 8092 §3 large community — a list of 12-byte (3×u32) values.
const ATTR_LARGE_COMMUNITY: u8 = 32;
/// RFC 5701 IPv6 address specific extended community — a list of 20-byte
/// values (RFC 8956 section 6.1's IPv6 redirect lives here).
const ATTR_IPV6_EXTENDED_COMMUNITIES: u8 = 25;
const ATTR_PMSI_TUNNEL: u8 = 22;
/// RFC 9234 §4.1 Only to Customer (optional transitive, one ASN).
const ATTR_OTC: u8 = 35;
/// RFC 6793 §3: the real 4-byte path, carried beside a 2-byte `AS_PATH` to/from
/// a peer that never negotiated the four-octet AS capability.
const ATTR_AS4_PATH: u8 = 17;
/// RFC 6793 §3: the real 4-byte `AGGREGATOR`, beside a 2-byte one holding `AS_TRANS`.
const ATTR_AS4_AGGREGATOR: u8 = 18;
/// RFC 4271 §4.3 attribute flag bit indicating a 2-byte (rather than 1-byte)
/// attribute length field follows the type byte.
const ATTR_FLAG_EXTENDED_LENGTH: u8 = 0x10;
/// Well-known transitive, per RFC 4271 §5 — the flag value this
/// implementation always encodes for `ORIGIN`/`AS_PATH`/`NEXT_HOP`/`LOCAL_PREF`.
const ATTR_FLAG_WELL_KNOWN_TRANSITIVE: u8 = 0x40;
/// Optional non-transitive, per RFC 4760 §3 — `MP_REACH_NLRI`/
/// `MP_UNREACH_NLRI`'s own flag value (unlike the four well-known attributes
/// above).
const ATTR_FLAG_OPTIONAL_NON_TRANSITIVE: u8 = 0x80;
/// Optional transitive, per RFC 1997/4360/8092 §3 — all three community
/// attribute types' own flag value.
const ATTR_FLAG_OPTIONAL_TRANSITIVE: u8 = 0xC0;

/// Structural decode failures — the type byte itself is never rejected here
/// (an unknown type decodes as `BgpMessage::Unhandled`), only malformed
/// headers/bodies for the types this crate actually understands.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("bgp message marker is not all-ones")]
    BadMarker,
    #[error("bgp message length {0} out of the allowed range (19..=4096, or ..=65535 for UPDATE/NOTIFICATION/ROUTE-REFRESH once RFC 8654 is negotiated)")]
    BadLength(u16),
    #[error("bgp message body shorter than its declared field lengths")]
    Truncated,
    #[error("malformed OPEN message body")]
    MalformedOpen,
    #[error("malformed NOTIFICATION message body")]
    MalformedNotification,
    #[error("malformed UPDATE message body")]
    MalformedUpdate,
    #[error("malformed ROUTE-REFRESH message body")]
    MalformedRouteRefresh,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// RFC 4271 §6 error codes, used in NOTIFICATION's `error_code` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    MessageHeader = 1,
    OpenMessage = 2,
    UpdateMessage = 3,
    HoldTimerExpired = 4,
    FiniteStateMachine = 5,
    Cease = 6,
}

/// RFC 4271 §6.1 Message Header Error subcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageHeaderSubcode {
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    #[allow(dead_code)]
    // reserved for a future "reject unrecognized type" policy — see fsm.rs's Unhandled handling
    BadMessageType = 3,
}

/// RFC 4271 §6.2 OPEN Message Error subcodes (subcode 5, Authentication
/// Failure, is deprecated by RFC 4271 itself and omitted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMessageSubcode {
    UnsupportedVersionNumber = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    #[allow(dead_code)] // no optional parameters besides Capabilities are rejected yet
    UnsupportedOptionalParameter = 4,
    UnacceptableHoldTime = 6,
    /// RFC 9234 §6 Role Mismatch.
    RoleMismatch = 11,
}

/// RFC 4271 §6.3 UPDATE Message Error subcodes (only the one this crate's
/// parser can actually produce is modeled; the rest of the RFC 4271 table —
/// missing/invalid individual well-known attributes, invalid `NEXT_HOP`, etc.
/// — isn't distinguished from a generic malformed attribute list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMessageSubcode {
    MalformedAttributeList = 1,
}

/// RFC 6608 Finite State Machine Error subcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmSubcode {
    UnexpectedInOpenSent = 1,
    UnexpectedInOpenConfirm = 2,
    UnexpectedInEstablished = 3,
}

/// RFC 4486 Cease subcodes actually used by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeaseSubcode {
    #[allow(dead_code)] // generic fallback, not yet triggered by any code path
    Other = 0,
    MaximumPrefixesReached = 1,
    AdministrativeShutdown = 2,
    PeerDeconfigured = 3,
    AdministrativeReset = 4,
    ConnectionRejected = 5,
    OtherConfigurationChange = 6,
    ConnectionCollisionResolution = 7,
    /// RFC 4486 §4: an internal limit (a full outbox, #395) was hit.
    OutOfResources = 8,
    /// RFC 8538 §3: the data is a whole inner NOTIFICATION `code(1)
    /// subcode(1) data…` — a reset that keeps nothing, whatever N says.
    HardReset = 9,
    /// RFC 9384 §3: the session was closed because BFD declared the path down.
    BfdDown = 10,
}

/// RFC 8538 §3: a Hard Reset's data, wrapping Cease/`inner_subcode`.
pub fn encode_hard_reset(inner_subcode: u8, inner_data: &[u8]) -> Bytes {
    let mut data = Vec::with_capacity(2 + inner_data.len());
    data.push(ErrorCode::Cease as u8);
    data.push(inner_subcode);
    data.extend_from_slice(inner_data);
    Bytes::from(data)
}

/// RFC 9003 §2: the NOTIFICATION data of a Cease/Administrative Shutdown (2)
/// or Administrative Reset (4) is `length(1) || UTF-8 text`, at most 255
/// octets of text. Over-long text is cut on a character boundary.
pub fn encode_shutdown_message(text: &str) -> Bytes {
    let mut end = text.len().min(255);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut data = Vec::with_capacity(end + 1);
    data.push(u8::try_from(end).unwrap_or(u8::MAX));
    data.extend_from_slice(&text.as_bytes()[..end]);
    Bytes::from(data)
}

/// RFC 4486 §4: the NOTIFICATION data of a Cease/Maximum Number of Prefixes
/// Reached is `AFI(2) || SAFI(1) || upper bound(4)`.
pub fn encode_max_prefix_data(afi: u16, safi: u8, limit: u32) -> Bytes {
    let mut data = Vec::with_capacity(7);
    data.extend_from_slice(&afi.to_be_bytes());
    data.push(safi);
    data.extend_from_slice(&limit.to_be_bytes());
    Bytes::from(data)
}

/// The inverse of [`encode_shutdown_message`]; `None` if `data` isn't a
/// well-formed shutdown communication (empty, length mismatch, not UTF-8).
pub fn decode_shutdown_message(data: &[u8]) -> Option<String> {
    let (&len, text) = data.split_first()?;
    if usize::from(len) != text.len() {
        return None;
    }
    String::from_utf8(text.to_vec()).ok()
}

/// One OPEN capability this crate understands. An unrecognized capability
/// code (or one with an unexpected length) is silently dropped on decode,
/// same skip-by-length philosophy as an unknown path attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// RFC 6793 code 65.
    FourOctetAsn(u32),
    /// RFC 4760 code 1: this session can carry `afi`/`safi` NLRI.
    MultiProtocol { afi: u16, safi: u8 },
    /// RFC 8950 code 5: `nlri_afi`/`nlri_safi` NLRI may be advertised with a
    /// `nh_afi`-family next-hop (the cross-family case — same-family next-hop
    /// never needs this capability at all).
    ExtendedNextHop {
        nlri_afi: u16,
        nlri_safi: u16,
        nh_afi: u16,
    },
    /// RFC 2918 code 2: this session accepts `ROUTE_REFRESH` messages.
    RouteRefresh,
    /// RFC 7313 code 70: `ROUTE_REFRESH` may carry BoRR/EoRR subtypes.
    EnhancedRouteRefresh,
    /// RFC 8654 code 6: messages up to 65535 bytes (UPDATE, NOTIFICATION,
    /// ROUTE-REFRESH) when both sides advertise it.
    ExtendedMessage,
    /// RFC 7911 code 69: one or more AFI/SAFI ADD-PATH grants.
    AddPath(Vec<AddPathTuple>),
    /// RFC 4724 code 64 (with RFC 8538's N bit).
    GracefulRestart(GracefulRestartCap),
    /// RFC 9234 code 9: the sender's BGP Role (`BgpRole::wire`). An
    /// unassigned value is kept, so the receiver can tell "no role" from
    /// "an illegal one".
    Role(u8),
}

/// The peer's RFC 9234 Role capability value — the last one, if repeated.
pub fn peer_role(open: &OpenMessage) -> Option<u8> {
    open.capabilities.iter().rev().find_map(|c| match c {
        Capability::Role(r) => Some(*r),
        _ => None,
    })
}

/// The RFC 4724 Graceful Restart capability. No tuples means the speaker
/// only does the receiving side: its own routes aren't to be kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GracefulRestartCap {
    /// R: the sender has just restarted.
    pub restart: bool,
    /// N (RFC 8538): a NOTIFICATION other than a Hard Reset keeps routes.
    pub notification: bool,
    /// Restart Time, seconds (12 bits).
    pub time: u16,
    pub families: Vec<GrFamily>,
}

/// One `AFI SAFI Flags` tuple; `forwarding` is the F bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrFamily {
    pub afi: u16,
    pub safi: u8,
    pub forwarding: bool,
}

/// The peer's Graceful Restart capability — the last one, if it sent more
/// than one (RFC 4724 §3).
pub fn graceful_restart(open: &OpenMessage) -> Option<&GracefulRestartCap> {
    open.capabilities.iter().rev().find_map(|c| match c {
        Capability::GracefulRestart(gr) => Some(gr),
        _ => None,
    })
}

/// One RFC 7911 ADD-PATH grant: `afi`/`safi` NLRI may carry a 4-byte Path
/// Identifier, in the direction(s) `send_receive` names (1 = receive, 2 =
/// send, 3 = both — "send"/"receive" from the *advertiser's* perspective).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddPathTuple {
    pub afi: u16,
    pub safi: u8,
    pub send_receive: u8,
}

/// An OPEN message. See [`Capability`] for the capabilities this crate
/// builds/understands; `four_octet_asn`/`effective_remote_asn` read the
/// four-octet-ASN one back out regardless of which form the plain `my_as`
/// field arrived in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMessage {
    pub version: u8,
    pub my_as: u16,
    pub hold_time: u16,
    pub bgp_identifier: Ipv4Addr,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Bytes,
}

/// RFC 2918 `ROUTE_REFRESH`: `AFI(2) reserved(1) SAFI(1)`; RFC 7313 turns
/// the reserved octet into the message subtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    pub afi: u16,
    pub subtype: u8,
    pub safi: u8,
}

/// RFC 7313 §3.2 subtypes: 0 is the plain request, 1/2 bracket the refresh.
pub const REFRESH_REQUEST: u8 = 0;
pub const REFRESH_BORR: u8 = 1;
pub const REFRESH_EORR: u8 = 2;

/// RFC 4271 §4.3 `ORIGIN` path attribute values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

/// The legacy IPv4-unicast path attributes. `local_pref` is `Some` iff the
/// wire message actually carried a `LOCAL_PREF` attribute — this crate never
/// invents one on decode (`rib.rs` applies the RFC 4271 §5.1.5 default only
/// when propagating, not here). `next_hop` is only meaningful (and only ever
/// encoded) when the legacy `UpdateMessage::nlri` field is non-empty —
/// `ORIGIN`/`AS_PATH`/`LOCAL_PREF` are shared with any `mp_reach`/`mp_unreach`
/// batches in the same UPDATE (RFC 4760: only the next-hop moves into
/// `MP_REACH_NLRI` itself, everything else stays a regular path attribute).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAttributes {
    pub origin: Origin,
    /// Nearest hop first, segment types (`AS_SET`, RFC 5065 confederation
    /// segments) preserved.
    pub as_path: AsPath,
    pub next_hop: Ipv4Addr,
    pub local_pref: Option<u32>,
    /// `Some` iff the wire message carried `MULTI_EXIT_DISC` (RFC 4271
    /// §5.1.4) — this crate never invents one, same convention as
    /// `local_pref`.
    pub med: Option<u32>,
    /// RFC 4456 §5 `ORIGINATOR_ID` — set by the first route reflector to
    /// reflect this route, never overwritten by a later one. `Some` iff the
    /// wire message actually carried it.
    pub originator_id: Option<Ipv4Addr>,
    /// RFC 4456 §5 `CLUSTER_LIST` — one cluster-id prepended by each route
    /// reflector in the path, nearest first. Empty iff the wire message
    /// carried no `CLUSTER_LIST` at all (never reflected, or a reflector
    /// omitting it purely because a route with no prior list needed one).
    pub cluster_list: Vec<Ipv4Addr>,
    /// RFC 1997 `COMMUNITY` — each value packed `(AA << 16) | NN`. Empty iff
    /// the wire message carried no `COMMUNITY` attribute.
    pub communities: Vec<u32>,
    /// RFC 4360 `EXTENDED_COMMUNITIES` — each value is its 8 raw wire bytes
    /// read as one big-endian `u64` (type octet in the high byte). Empty iff
    /// the wire message carried no `EXTENDED_COMMUNITIES` attribute.
    pub extended_communities: Vec<u64>,
    /// RFC 8092 `LARGE_COMMUNITY` — global administrator, local data 1,
    /// local data 2. Empty iff the wire message carried no `LARGE_COMMUNITY`
    /// attribute.
    pub large_communities: Vec<(u32, u32, u32)>,
    /// RFC 5701 `IPV6_EXTENDED_COMMUNITIES`, 20 raw wire bytes each. Empty
    /// iff the wire message carried none.
    // ponytail: only Flowspec re-advertises them (#560); a unicast route
    // drops them on re-advertisement.
    pub ipv6_extended_communities: Vec<[u8; 20]>,
    /// RFC 6514 §5 PMSI Tunnel — carried on EVPN Type-3 routes (RFC 8365
    /// §8.2.1), which is where the VNI of an inclusive multicast route lives.
    pub pmsi: Option<Pmsi>,
    /// RFC 4271 §5.1.6 `ATOMIC_AGGREGATE` — only ever preserved in transit.
    pub atomic_aggregate: bool,
    /// RFC 4271 §5.1.7 `AGGREGATOR` (`AS4_AGGREGATOR` merged in, RFC 6793).
    pub aggregator: Option<Aggregator>,
    /// RFC 9234 §4.1 `OTC` (Only to Customer): the ASN that marked the route.
    pub otc: Option<u32>,
}

/// The AS and router-id of the speaker that formed an aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aggregator {
    pub asn: u32,
    pub router_id: Ipv4Addr,
}

/// An ingress-replication (tunnel type 6) PMSI Tunnel attribute, the only
/// kind EVPN/VXLAN uses: `vni` fills the label field, `tunnel_ip` is the VTEP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pmsi {
    pub vni: u32,
    pub tunnel_ip: IpAddr,
}

/// RFC 4760 `MP_REACH_NLRI`: one AFI/SAFI batch of announced routes sharing
/// one next-hop. `next_hop`'s family need not match `nlri`'s own family (RFC
/// 8950 cross-family next-hop) — that's purely a wire-level fact here; which
/// combinations are actually negotiated/allowed is `fsm.rs`'s job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReachNlri {
    pub afi: u16,
    pub safi: u8,
    pub next_hop: IpAddr,
    pub nlri: Vec<IpNet>,
    /// RFC 7911 ADD-PATH identifiers, aligned by index with `nlri`. Empty
    /// unless this AFI negotiated ADD-PATH on this session — never
    /// partially filled.
    pub nlri_path_ids: Vec<u32>,
    /// AFI 25 / SAFI 70 routes; `nlri` is empty for such a batch.
    pub evpn: Vec<EvpnNlri>,
    /// AFI 1|2 / SAFI 133 rules; `nlri` is empty for such a batch. RFC 8955
    /// section 4: the next hop is empty on the wire and ignored.
    pub flowspec: Vec<FlowSpec>,
    /// AFI 1|2 / SAFI 128 routes (one label each); `nlri` is empty for such
    /// a batch. Never carries a Path Identifier.
    pub vpn: Vec<VpnNlri>,
    /// AFI 1 / SAFI 132 membership (RFC 4684); `nlri` is empty for such a batch.
    pub rtc: Vec<RtcNlri>,
}

/// RFC 4760 `MP_UNREACH_NLRI`: one AFI/SAFI batch of withdrawn routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpUnreachNlri {
    pub afi: u16,
    pub safi: u8,
    pub withdrawn: Vec<IpNet>,
    /// RFC 7911 ADD-PATH identifiers, aligned by index with `withdrawn`.
    /// Empty unless this AFI negotiated ADD-PATH on this session.
    pub withdrawn_path_ids: Vec<u32>,
    /// AFI 25 / SAFI 70 routes; `withdrawn` is empty for such a batch.
    pub evpn: Vec<EvpnNlri>,
    /// AFI 1|2 / SAFI 133 rules; `withdrawn` is empty for such a batch.
    pub flowspec: Vec<FlowSpec>,
    /// AFI 1|2 / SAFI 128 routes (`labels` empty); `withdrawn` is empty for
    /// such a batch.
    pub vpn: Vec<VpnNlri>,
    /// AFI 1 / SAFI 132 membership; `withdrawn` is empty for such a batch.
    pub rtc: Vec<RtcNlri>,
}

/// An RFC 4271 UPDATE message. `withdrawn_routes`/`nlri`/`attributes.next_hop`
/// are the legacy IPv4-unicast-only fields (RFC 4271's base NLRI);
/// `mp_reach`/`mp_unreach` carry everything else, and — once a peer
/// negotiates MP-BGP at all — IPv4 unicast too (see
/// `crate::rib::build_advertisement`). `attributes` is `Some` iff `nlri` or
/// `mp_reach` is non-empty — a pure withdrawal carries no path attributes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpdateMessage {
    pub withdrawn_routes: Vec<Ipv4Net>,
    /// RFC 7911 ADD-PATH identifiers, aligned by index with
    /// `withdrawn_routes`. Empty unless IPv4 unicast negotiated ADD-PATH on
    /// this session.
    pub withdrawn_path_ids: Vec<u32>,
    pub nlri: Vec<Ipv4Net>,
    /// RFC 7911 ADD-PATH identifiers, aligned by index with `nlri`. Empty
    /// unless IPv4 unicast negotiated ADD-PATH on this session.
    pub nlri_path_ids: Vec<u32>,
    pub attributes: Option<PathAttributes>,
    pub mp_reach: Vec<MpReachNlri>,
    pub mp_unreach: Vec<MpUnreachNlri>,
    /// RFC 7606 treat-as-withdraw done by `parse_update`: how many announced
    /// prefixes it moved into the withdrawn lists (0 = not treated). Never
    /// on the wire; BMP statistics types 11/12 read it (#864).
    pub treat_as_withdraw_prefixes: u32,
}

/// A decoded BGP message.
// ponytail: `Update`'s `PathAttributes` (now carrying 3 community `Vec`s)
// outsizes the other variants; boxing it would touch every construction
// site for a one-off-per-message decode, not a hot repeated allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum BgpMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    Keepalive,
    Notification(NotificationMessage),
    RouteRefresh(RouteRefreshMessage),
    /// RFC 4724 §2 End-of-RIB: an UPDATE announcing and withdrawing nothing
    /// (IPv4 unicast), or carrying only an empty `MP_UNREACH_NLRI` for
    /// `afi`/`safi`. Decoded from the raw bytes, never from a parsed
    /// `UpdateMessage`, since an UPDATE whose attributes were discarded
    /// would look the same once parsed.
    EndOfRib {
        afi: u16,
        safi: u8,
    },
    /// Any message type this crate doesn't parse a body for (unknown to this
    /// implementation).
    Unhandled {
        message_type: u8,
        body: Bytes,
    },
}

/// Builds this instance's own OPEN, carrying only the four-octet AS number
/// capability — callers (`fsm.rs`) push any `MultiProtocol`/
/// `ExtendedNextHop` capabilities this peer's session needs onto
/// `capabilities` afterward, since that depends on peer-group config this
/// module has no business knowing about. Always populated once
/// 4-octet-capable, regardless of whether `my_as` needed `AS_TRANS` — RFC
/// 6793 §4.1 recommends always advertising the capability, since it also
/// governs how the peer's OPEN is interpreted, not just how this one is
/// represented.
pub fn build_open(local_asn: u32, router_id: Ipv4Addr, hold_time: u16) -> OpenMessage {
    let my_as = u16::try_from(local_asn).unwrap_or(AS_TRANS);
    OpenMessage {
        version: BGP_VERSION,
        my_as,
        hold_time,
        bgp_identifier: router_id,
        capabilities: vec![Capability::FourOctetAsn(local_asn)],
    }
}

/// The four-octet ASN carried in `open`'s capabilities, if any.
pub fn four_octet_asn(open: &OpenMessage) -> Option<u32> {
    open.capabilities.iter().find_map(|c| match c {
        Capability::FourOctetAsn(asn) => Some(*asn),
        _ => None,
    })
}

/// The peer's real ASN, whether carried in the plain 2-byte field or (when
/// present) the four-octet AS number capability — falling back to the plain
/// field is what gives interop with peers that never send capability 65.
pub fn effective_remote_asn(open: &OpenMessage) -> u32 {
    four_octet_asn(open).unwrap_or(u32::from(open.my_as))
}

/// Rejects the well-known non-unicast special cases; anything else is
/// accepted (no check against one specific expected identifier).
pub fn is_valid_bgp_identifier(id: Ipv4Addr) -> bool {
    !id.is_unspecified() && !id.is_broadcast() && !id.is_multicast()
}

/// RFC 4271 §5.1.3 / §6.3: a `NEXT_HOP` no speaker can forward to — the
/// unspecified, "this network" (`0/8`), loopback, multicast, class-E
/// (incl. broadcast) and IPv4-mapped addresses, or `own`, the receiving
/// session's local address. A link-local IPv6 next hop is valid (RFC 2545).
// ponytail: `own` is the session address only, not every local interface
// address; widening needs interface data from `nos-interfaced`.
pub fn next_hop_is_martian(nh: IpAddr, own: Option<IpAddr>) -> bool {
    if own == Some(nh) {
        return true;
    }
    match nh {
        IpAddr::V4(a) => {
            a.octets()[0] == 0 || a.is_loopback() || a.is_multicast() || a.octets()[0] >= 240
        }
        IpAddr::V6(a) => {
            a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.to_ipv4_mapped().is_some()
        }
    }
}

/// `add_path_afis` is empty by default (identical wire behavior to before
/// RFC 7911 support existed) and is set once, right after this session
/// reaches `Established` and negotiation is known — see
/// `fsm::run`'s `Action::ReportEstablished` handling. Only ever non-empty
/// for a `route_server_client` peer-group (see `docs/protocols/bgp-internals.md`'s "Route
/// reflection and route server" section for why ADD-PATH isn't advertised
/// unconditionally like this crate's other capabilities).
#[derive(Debug, Clone, Default)]
pub struct BgpCodec {
    pub add_path_afis: HashSet<u16>,
    /// True once the peer's OPEN lacked the four-octet AS capability (RFC 6793
    /// §4.2): `AS_PATH` is then 2-byte in both directions, with `AS4_PATH`
    /// carrying the real path. Set at the same point as `add_path_afis`.
    pub two_octet_as: bool,
    /// True once both sides advertised RFC 8654 Extended Message: UPDATE,
    /// NOTIFICATION and ROUTE-REFRESH may then be up to 65535 bytes. Set at the
    /// same point as `add_path_afis`.
    pub extended: bool,
}

impl BgpCodec {
    fn max_len(&self, message_type: u8) -> usize {
        // RFC 8654 §4: OPEN and KEEPALIVE stay at 4096 even when negotiated.
        if self.extended && message_type != TYPE_OPEN && message_type != TYPE_KEEPALIVE {
            MAX_EXTENDED_MESSAGE_LEN
        } else {
            MAX_MESSAGE_LEN
        }
    }
}

impl Decoder for BgpCodec {
    type Item = BgpMessage;
    type Error = WireError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BgpMessage>, WireError> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }
        if src[..16] != MARKER {
            return Err(WireError::BadMarker);
        }
        let length = u16::from_be_bytes([src[16], src[17]]);
        let message_type = src[18];
        if (length as usize) < HEADER_LEN || (length as usize) > self.max_len(message_type) {
            return Err(WireError::BadLength(length));
        }
        if src.len() < length as usize {
            src.reserve(length as usize - src.len());
            return Ok(None);
        }

        let mut frame = src.split_to(length as usize);
        frame.advance(HEADER_LEN);
        let body = frame;

        let message = match message_type {
            TYPE_OPEN => BgpMessage::Open(parse_open(&body)?),
            TYPE_UPDATE => match end_of_rib(&body) {
                Some((afi, safi)) => BgpMessage::EndOfRib { afi, safi },
                None => {
                    BgpMessage::Update(parse_update(&body, &self.add_path_afis, self.two_octet_as)?)
                }
            },
            TYPE_KEEPALIVE => {
                if !body.is_empty() {
                    return Err(WireError::BadLength(length));
                }
                BgpMessage::Keepalive
            }
            TYPE_NOTIFICATION => BgpMessage::Notification(parse_notification(&body)?),
            TYPE_ROUTE_REFRESH => BgpMessage::RouteRefresh(parse_route_refresh(&body)?),
            other => BgpMessage::Unhandled {
                message_type: other,
                body: body.freeze(),
            },
        };
        Ok(Some(message))
    }
}

impl Encoder<BgpMessage> for BgpCodec {
    type Error = WireError;

    fn encode(&mut self, item: BgpMessage, dst: &mut BytesMut) -> Result<(), WireError> {
        let (message_type, body) = match item {
            BgpMessage::Open(open) => (TYPE_OPEN, encode_open(&open)),
            BgpMessage::Update(update) => {
                // One UPDATE too big for this session's limit is split into
                // several (RFC 4271 §4.3 / RFC 8654): halve its largest NLRI
                // list until every piece fits.
                let max_body = self.max_len(TYPE_UPDATE) - HEADER_LEN;
                let mut pieces = Vec::new();
                split_update(&update, self.two_octet_as, max_body, &mut pieces)?;
                for body in pieces {
                    put_frame(dst, TYPE_UPDATE, &body);
                }
                return Ok(());
            }
            BgpMessage::Keepalive => (TYPE_KEEPALIVE, Vec::new()),
            BgpMessage::Notification(n) => (TYPE_NOTIFICATION, encode_notification(&n)),
            BgpMessage::RouteRefresh(rr) => (TYPE_ROUTE_REFRESH, encode_route_refresh(rr)),
            BgpMessage::EndOfRib { afi, safi } => (TYPE_UPDATE, encode_end_of_rib(afi, safi)),
            BgpMessage::Unhandled { message_type, body } => (message_type, body.to_vec()),
        };
        let total_len = HEADER_LEN + body.len();
        // Never send more than the peer will accept: 4096 unless RFC 8654 was
        // negotiated (and never for OPEN/KEEPALIVE).
        if total_len > self.max_len(message_type) {
            return Err(WireError::BadLength(
                u16::try_from(total_len).unwrap_or(u16::MAX),
            ));
        }
        put_frame(dst, message_type, &body);
        Ok(())
    }
}

/// Frame `body` (already checked against the session limit, so its length
/// fits a `u16`).
fn put_frame(dst: &mut BytesMut, message_type: u8, body: &[u8]) {
    let total_len = u16::try_from(HEADER_LEN + body.len()).unwrap_or(u16::MAX);
    dst.reserve(total_len as usize);
    dst.put_slice(&MARKER);
    dst.put_u16(total_len);
    dst.put_u8(message_type);
    dst.put_slice(body);
}

/// Which NLRI list of an UPDATE `split_update` halves.
enum SplitField {
    Withdrawn,
    Nlri,
    MpReachNlri(usize),
    MpReachEvpn(usize),
    MpReachFlowspec(usize),
    MpReachVpn(usize),
    MpReachRtc(usize),
    MpUnreachWithdrawn(usize),
    MpUnreachEvpn(usize),
    MpUnreachFlowspec(usize),
    MpUnreachVpn(usize),
    MpUnreachRtc(usize),
}

// Split `v` (and its aligned path ids, if any) at `mid`; returns the tails.
fn tail<T>(v: &mut Vec<T>, ids: &mut Vec<u32>, mid: usize) -> (Vec<T>, Vec<u32>) {
    let ids_tail = if ids.is_empty() {
        vec![]
    } else {
        ids.split_off(mid)
    };
    (v.split_off(mid), ids_tail)
}

/// Encode `update` into `out`, halving its largest NLRI list recursively until
/// every body is at most `max_body` bytes. The second half carries only that
/// list (plus the path attributes when it announces), so nothing is announced
/// or withdrawn twice. An UPDATE with nothing left to split is an error.
#[allow(clippy::too_many_lines, reason = "one arm per splittable NLRI list")]
fn split_update(
    update: &UpdateMessage,
    two_octet_as: bool,
    max_body: usize,
    out: &mut Vec<Vec<u8>>,
) -> Result<(), WireError> {
    let body = encode_update(update, two_octet_as);
    if body.len() <= max_body {
        out.push(body);
        return Ok(());
    }
    let mut lists = vec![
        (SplitField::Withdrawn, update.withdrawn_routes.len()),
        (SplitField::Nlri, update.nlri.len()),
    ];
    for (i, m) in update.mp_reach.iter().enumerate() {
        lists.push((SplitField::MpReachNlri(i), m.nlri.len()));
        lists.push((SplitField::MpReachEvpn(i), m.evpn.len()));
        lists.push((SplitField::MpReachFlowspec(i), m.flowspec.len()));
        lists.push((SplitField::MpReachVpn(i), m.vpn.len()));
        lists.push((SplitField::MpReachRtc(i), m.rtc.len()));
    }
    for (i, m) in update.mp_unreach.iter().enumerate() {
        lists.push((SplitField::MpUnreachWithdrawn(i), m.withdrawn.len()));
        lists.push((SplitField::MpUnreachEvpn(i), m.evpn.len()));
        lists.push((SplitField::MpUnreachFlowspec(i), m.flowspec.len()));
        lists.push((SplitField::MpUnreachVpn(i), m.vpn.len()));
        lists.push((SplitField::MpUnreachRtc(i), m.rtc.len()));
    }
    let (field, len) = lists
        .into_iter()
        .max_by_key(|(_, len)| *len)
        .expect("lists is never empty");
    if len < 2 {
        return Err(WireError::BadLength(
            u16::try_from(HEADER_LEN + body.len()).unwrap_or(u16::MAX),
        ));
    }
    let mid = len / 2;
    // `first` keeps everything but the tail of `field`; `second` is `field`'s
    // tail alone.
    let mut first = update.clone();
    let mut second = UpdateMessage {
        withdrawn_routes: vec![],
        withdrawn_path_ids: vec![],
        nlri: vec![],
        nlri_path_ids: vec![],
        attributes: None,
        mp_reach: vec![],
        mp_unreach: vec![],
        ..Default::default()
    };
    match field {
        SplitField::Withdrawn => {
            (second.withdrawn_routes, second.withdrawn_path_ids) = tail(
                &mut first.withdrawn_routes,
                &mut first.withdrawn_path_ids,
                mid,
            );
        }
        SplitField::Nlri => {
            (second.nlri, second.nlri_path_ids) =
                tail(&mut first.nlri, &mut first.nlri_path_ids, mid);
            second.attributes.clone_from(&first.attributes);
        }
        SplitField::MpReachNlri(i) => {
            let m = &mut first.mp_reach[i];
            let (nlri, ids) = tail(&mut m.nlri, &mut m.nlri_path_ids, mid);
            second.mp_reach.push(MpReachNlri {
                nlri,
                nlri_path_ids: ids,
                evpn: vec![],
                flowspec: vec![],
                vpn: vec![],
                rtc: vec![],
                ..m.clone()
            });
            second.attributes.clone_from(&first.attributes);
        }
        SplitField::MpReachEvpn(i) => {
            let m = &mut first.mp_reach[i];
            let evpn = m.evpn.split_off(mid);
            second.mp_reach.push(MpReachNlri {
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn,
                flowspec: vec![],
                vpn: vec![],
                rtc: vec![],
                ..m.clone()
            });
            second.attributes.clone_from(&first.attributes);
        }
        SplitField::MpReachFlowspec(i) => {
            let m = &mut first.mp_reach[i];
            let flowspec = m.flowspec.split_off(mid);
            second.mp_reach.push(MpReachNlri {
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn: vec![],
                flowspec,
                vpn: vec![],
                rtc: vec![],
                ..m.clone()
            });
            second.attributes.clone_from(&first.attributes);
        }
        SplitField::MpUnreachWithdrawn(i) => {
            let m = &mut first.mp_unreach[i];
            let (withdrawn, ids) = tail(&mut m.withdrawn, &mut m.withdrawn_path_ids, mid);
            second.mp_unreach.push(MpUnreachNlri {
                withdrawn,
                withdrawn_path_ids: ids,
                evpn: vec![],
                flowspec: vec![],
                vpn: vec![],
                rtc: vec![],
                ..m.clone()
            });
        }
        SplitField::MpUnreachEvpn(i) => {
            let m = &mut first.mp_unreach[i];
            let evpn = m.evpn.split_off(mid);
            second.mp_unreach.push(MpUnreachNlri {
                withdrawn: vec![],
                withdrawn_path_ids: vec![],
                evpn,
                flowspec: vec![],
                vpn: vec![],
                rtc: vec![],
                ..m.clone()
            });
        }
        SplitField::MpUnreachFlowspec(i) => {
            let m = &mut first.mp_unreach[i];
            let flowspec = m.flowspec.split_off(mid);
            second.mp_unreach.push(MpUnreachNlri {
                withdrawn: vec![],
                withdrawn_path_ids: vec![],
                evpn: vec![],
                flowspec,
                vpn: vec![],
                rtc: vec![],
                ..m.clone()
            });
        }
        SplitField::MpReachVpn(i) => {
            let m = &mut first.mp_reach[i];
            let vpn = m.vpn.split_off(mid);
            second.mp_reach.push(MpReachNlri {
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn: vec![],
                flowspec: vec![],
                vpn,
                rtc: vec![],
                ..m.clone()
            });
            second.attributes.clone_from(&first.attributes);
        }
        SplitField::MpUnreachVpn(i) => {
            let m = &mut first.mp_unreach[i];
            let vpn = m.vpn.split_off(mid);
            second.mp_unreach.push(MpUnreachNlri {
                withdrawn: vec![],
                withdrawn_path_ids: vec![],
                evpn: vec![],
                flowspec: vec![],
                vpn,
                rtc: vec![],
                ..m.clone()
            });
        }
        SplitField::MpReachRtc(i) => {
            let m = &mut first.mp_reach[i];
            let rtc = m.rtc.split_off(mid);
            second.mp_reach.push(MpReachNlri {
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn: vec![],
                flowspec: vec![],
                vpn: vec![],
                rtc,
                ..m.clone()
            });
            second.attributes.clone_from(&first.attributes);
        }
        SplitField::MpUnreachRtc(i) => {
            let m = &mut first.mp_unreach[i];
            let rtc = m.rtc.split_off(mid);
            second.mp_unreach.push(MpUnreachNlri {
                withdrawn: vec![],
                withdrawn_path_ids: vec![],
                evpn: vec![],
                flowspec: vec![],
                vpn: vec![],
                rtc,
                ..m.clone()
            });
        }
    }
    split_update(&first, two_octet_as, max_body, out)?;
    split_update(&second, two_octet_as, max_body, out)
}

/// RFC 4724 §2: the `(afi, safi)` an UPDATE body is the End-of-RIB of, if
/// it is one. IPv4 unicast's is the empty UPDATE (`00 00 00 00`), even on an
/// MP session; any other family's has no withdrawn routes, no NLRI, and
/// exactly one attribute, an `MP_UNREACH_NLRI` holding only `AFI SAFI` (in
/// either length form).
fn end_of_rib(body: &[u8]) -> Option<(u16, u8)> {
    if body == [0, 0, 0, 0] {
        return Some((AFI_IPV4, 1));
    }
    let (head, attrs) = body.split_at_checked(4)?;
    if head[..2] != [0, 0] || usize::from(u16::from_be_bytes([head[2], head[3]])) != attrs.len() {
        return None;
    }
    let value = match attrs {
        [flags, ATTR_MP_UNREACH_NLRI, 3, v @ ..] if flags & ATTR_FLAG_EXTENDED_LENGTH == 0 => v,
        [flags, ATTR_MP_UNREACH_NLRI, 0, 3, v @ ..] if flags & ATTR_FLAG_EXTENDED_LENGTH != 0 => v,
        _ => return None,
    };
    match value {
        [a, b, safi] => Some((u16::from_be_bytes([*a, *b]), *safi)),
        _ => None,
    }
}

fn encode_end_of_rib(afi: u16, safi: u8) -> Vec<u8> {
    if (afi, safi) == (AFI_IPV4, 1) {
        return vec![0, 0, 0, 0];
    }
    let [a, b] = afi.to_be_bytes();
    vec![
        0,
        0,
        0,
        6,
        ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
        ATTR_MP_UNREACH_NLRI,
        3,
        a,
        b,
        safi,
    ]
}

fn parse_open(body: &[u8]) -> Result<OpenMessage, WireError> {
    // version(1) + my_as(2) + hold_time(2) + bgp_identifier(4) + opt_param_len(1)
    if body.len() < 10 {
        return Err(WireError::MalformedOpen);
    }
    let version = body[0];
    let my_as = u16::from_be_bytes([body[1], body[2]]);
    let hold_time = u16::from_be_bytes([body[3], body[4]]);
    let bgp_identifier = Ipv4Addr::new(body[5], body[6], body[7], body[8]);
    // RFC 9072: `opt_param_len == 255` followed by a `255` type octet marks the
    // extended form — a 2-byte total length, then parameters with 2-byte lengths.
    let extended = body[9] == 255 && body.get(10) == Some(&255);
    let (opt_param_len, opt_params) = if extended {
        if body.len() < 13 {
            return Err(WireError::MalformedOpen);
        }
        (
            usize::from(u16::from_be_bytes([body[11], body[12]])),
            &body[13..],
        )
    } else {
        (usize::from(body[9]), &body[10..])
    };
    if opt_params.len() < opt_param_len {
        return Err(WireError::Truncated);
    }
    let capabilities = parse_optional_parameters(&opt_params[..opt_param_len], extended)?;

    Ok(OpenMessage {
        version,
        my_as,
        hold_time,
        bgp_identifier,
        capabilities,
    })
}

/// Walks every optional parameter, skipping each by its own declared length
/// (so a capability after an unrecognized parameter is still found),
/// collecting every capability from every Capabilities optional parameter
/// encountered (RFC 5492 allows more than one, though this crate always
/// encodes just one).
fn parse_optional_parameters(
    mut params: &[u8],
    extended: bool,
) -> Result<Vec<Capability>, WireError> {
    // RFC 9072: each parameter's length is 2 bytes in the extended form.
    let header = if extended { 3 } else { 2 };
    let mut capabilities = Vec::new();
    while !params.is_empty() {
        if params.len() < header {
            return Err(WireError::Truncated);
        }
        let param_type = params[0];
        let param_len = if extended {
            usize::from(u16::from_be_bytes([params[1], params[2]]))
        } else {
            usize::from(params[1])
        };
        if params.len() < header + param_len {
            return Err(WireError::Truncated);
        }
        let param_value = &params[header..header + param_len];
        if param_type == OPT_PARAM_CAPABILITIES {
            capabilities.extend(parse_capabilities(param_value)?);
        }
        params = &params[header + param_len..];
    }
    Ok(capabilities)
}

fn parse_capabilities(mut data: &[u8]) -> Result<Vec<Capability>, WireError> {
    let mut capabilities = Vec::new();
    while !data.is_empty() {
        if data.len() < 2 {
            return Err(WireError::Truncated);
        }
        let cap_code = data[0];
        let cap_len = data[1] as usize;
        if data.len() < 2 + cap_len {
            return Err(WireError::Truncated);
        }
        let cap_value = &data[2..2 + cap_len];
        match cap_code {
            CAP_ROLE if cap_len == 1 => capabilities.push(Capability::Role(cap_value[0])),
            CAP_FOUR_OCTET_ASN if cap_len == 4 => {
                capabilities.push(Capability::FourOctetAsn(u32::from_be_bytes(
                    cap_value.try_into().unwrap(),
                )));
            }
            CAP_MULTIPROTOCOL if cap_len == 4 => {
                let afi = u16::from_be_bytes([cap_value[0], cap_value[1]]);
                let safi = cap_value[3];
                capabilities.push(Capability::MultiProtocol { afi, safi });
            }
            CAP_ROUTE_REFRESH if cap_len == 0 => {
                capabilities.push(Capability::RouteRefresh);
            }
            CAP_ENHANCED_ROUTE_REFRESH if cap_len == 0 => {
                capabilities.push(Capability::EnhancedRouteRefresh);
            }
            CAP_EXTENDED_MESSAGE if cap_len == 0 => {
                capabilities.push(Capability::ExtendedMessage);
            }
            CAP_EXTENDED_NEXT_HOP if cap_len.is_multiple_of(6) => {
                for tuple in cap_value.as_chunks::<6>().0 {
                    capabilities.push(Capability::ExtendedNextHop {
                        nlri_afi: u16::from_be_bytes([tuple[0], tuple[1]]),
                        nlri_safi: u16::from_be_bytes([tuple[2], tuple[3]]),
                        nh_afi: u16::from_be_bytes([tuple[4], tuple[5]]),
                    });
                }
            }
            CAP_ADD_PATH if cap_len.is_multiple_of(4) => {
                let tuples = cap_value
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|tuple| AddPathTuple {
                        afi: u16::from_be_bytes([tuple[0], tuple[1]]),
                        safi: tuple[2],
                        send_receive: tuple[3],
                    })
                    .collect();
                capabilities.push(Capability::AddPath(tuples));
            }
            CAP_GRACEFUL_RESTART if cap_len >= 2 && (cap_len - 2).is_multiple_of(4) => {
                let head = u16::from_be_bytes([cap_value[0], cap_value[1]]);
                capabilities.push(Capability::GracefulRestart(GracefulRestartCap {
                    restart: head & GR_FLAG_RESTART != 0,
                    notification: head & GR_FLAG_NOTIFICATION != 0,
                    time: head & 0x0FFF,
                    families: cap_value[2..]
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|t| GrFamily {
                            afi: u16::from_be_bytes([t[0], t[1]]),
                            safi: t[2],
                            forwarding: t[3] & GR_FLAG_FORWARDING != 0,
                        })
                        .collect(),
                }));
            }
            // Unknown capability code, or a known one with an unexpected
            // length: skip by declared length, never an error.
            _ => {}
        }
        data = &data[2 + cap_len..];
    }
    Ok(capabilities)
}

fn parse_notification(body: &[u8]) -> Result<NotificationMessage, WireError> {
    if body.len() < 2 {
        return Err(WireError::MalformedNotification);
    }
    Ok(NotificationMessage {
        error_code: body[0],
        error_subcode: body[1],
        data: Bytes::copy_from_slice(&body[2..]),
    })
}

fn parse_route_refresh(body: &[u8]) -> Result<RouteRefreshMessage, WireError> {
    if body.len() < 4 {
        return Err(WireError::MalformedRouteRefresh);
    }
    Ok(RouteRefreshMessage {
        afi: u16::from_be_bytes([body[0], body[1]]),
        subtype: body[2],
        safi: body[3],
    })
}

fn encode_route_refresh(rr: RouteRefreshMessage) -> Vec<u8> {
    let mut body = Vec::with_capacity(4);
    body.extend_from_slice(&rr.afi.to_be_bytes());
    body.push(rr.subtype);
    body.push(rr.safi);
    body
}

fn encode_open(open: &OpenMessage) -> Vec<u8> {
    let mut cap_bytes = Vec::new();
    for cap in &open.capabilities {
        match cap {
            Capability::FourOctetAsn(asn) => {
                cap_bytes.push(CAP_FOUR_OCTET_ASN);
                cap_bytes.push(4);
                cap_bytes.extend_from_slice(&asn.to_be_bytes());
            }
            Capability::MultiProtocol { afi, safi } => {
                cap_bytes.push(CAP_MULTIPROTOCOL);
                cap_bytes.push(4);
                cap_bytes.extend_from_slice(&afi.to_be_bytes());
                cap_bytes.push(0); // reserved
                cap_bytes.push(*safi);
            }
            Capability::ExtendedNextHop {
                nlri_afi,
                nlri_safi,
                nh_afi,
            } => {
                cap_bytes.push(CAP_EXTENDED_NEXT_HOP);
                cap_bytes.push(6);
                cap_bytes.extend_from_slice(&nlri_afi.to_be_bytes());
                cap_bytes.extend_from_slice(&nlri_safi.to_be_bytes());
                cap_bytes.extend_from_slice(&nh_afi.to_be_bytes());
            }
            Capability::RouteRefresh => {
                cap_bytes.push(CAP_ROUTE_REFRESH);
                cap_bytes.push(0);
            }
            Capability::EnhancedRouteRefresh => {
                cap_bytes.push(CAP_ENHANCED_ROUTE_REFRESH);
                cap_bytes.push(0);
            }
            Capability::ExtendedMessage => {
                cap_bytes.push(CAP_EXTENDED_MESSAGE);
                cap_bytes.push(0);
            }
            Capability::GracefulRestart(gr) => {
                // At most 63 tuples fit the one-octet length; this crate
                // knows three families.
                let tuples = &gr.families[..gr.families.len().min(63)];
                cap_bytes.push(CAP_GRACEFUL_RESTART);
                cap_bytes.push(u8::try_from(2 + 4 * tuples.len()).unwrap_or(u8::MAX));
                let mut head = gr.time & 0x0FFF;
                if gr.restart {
                    head |= GR_FLAG_RESTART;
                }
                if gr.notification {
                    head |= GR_FLAG_NOTIFICATION;
                }
                cap_bytes.extend_from_slice(&head.to_be_bytes());
                for t in tuples {
                    cap_bytes.extend_from_slice(&t.afi.to_be_bytes());
                    cap_bytes.push(t.safi);
                    cap_bytes.push(if t.forwarding { GR_FLAG_FORWARDING } else { 0 });
                }
            }
            Capability::Role(r) => cap_bytes.extend_from_slice(&[CAP_ROLE, 1, *r]),
            Capability::AddPath(tuples) => {
                // A capability's length is one octet (RFC 5492), so 63 tuples
                // at most per instance; the code may repeat (RFC 5492 §4).
                for chunk in tuples.chunks(63) {
                    cap_bytes.push(CAP_ADD_PATH);
                    cap_bytes.push(u8::try_from(chunk.len() * 4).unwrap_or(u8::MAX));
                    for tuple in chunk {
                        cap_bytes.extend_from_slice(&tuple.afi.to_be_bytes());
                        cap_bytes.push(tuple.safi);
                        cap_bytes.push(tuple.send_receive);
                    }
                }
            }
        }
    }

    let mut opt_params = Vec::new();
    // RFC 9072: the extended form only when the parameter can't be 1-byte
    // length encoded. Its u16 lengths can't overflow: an OPEN is capped at
    // 4096 bytes by the codec.
    let extended = cap_bytes.len() > 255;
    if !cap_bytes.is_empty() {
        opt_params.push(OPT_PARAM_CAPABILITIES);
        if extended {
            opt_params.extend_from_slice(
                &u16::try_from(cap_bytes.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
        } else {
            opt_params.push(u8::try_from(cap_bytes.len()).unwrap_or(u8::MAX));
        }
        opt_params.extend_from_slice(&cap_bytes);
    }

    let mut body = Vec::with_capacity(13 + opt_params.len());
    body.push(open.version);
    body.extend_from_slice(&open.my_as.to_be_bytes());
    body.extend_from_slice(&open.hold_time.to_be_bytes());
    body.extend_from_slice(&open.bgp_identifier.octets());
    if extended {
        body.extend_from_slice(&[255, 255]);
        body.extend_from_slice(
            &u16::try_from(opt_params.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
    } else {
        body.push(u8::try_from(opt_params.len()).unwrap_or(u8::MAX));
    }
    body.extend_from_slice(&opt_params);
    body
}

fn encode_notification(n: &NotificationMessage) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + n.data.len());
    body.push(n.error_code);
    body.push(n.error_subcode);
    body.extend_from_slice(&n.data);
    body
}

/// RFC 4271 §4.3 prefix bit-packing: `prefix_len` (1 byte) followed by the
/// minimum number of whole octets needed to hold that many bits of the
/// address, zero-padded — optionally preceded by a 4-byte RFC 7911 ADD-PATH
/// Path Identifier when `with_ids` is set. Decodes a list that continues
/// until the byte slice is exhausted (both withdrawn-routes and NLRI use
/// this same encoding, with no count field of their own — the caller
/// already knows where the list ends). `afi` picks the address width (4
/// bytes for `AFI_IPV4`, 16 for `AFI_IPV6`) and the resulting prefix-length
/// cap (32/128); any other AFI is `MalformedUpdate` — this crate only
/// understands unicast IPv4/IPv6. Returns the path ids alongside the
/// prefixes, aligned by index — empty when `with_ids` is false.
fn decode_prefixes(
    afi: u16,
    mut data: &[u8],
    with_ids: bool,
) -> Result<(Vec<IpNet>, Vec<u32>), WireError> {
    let addr_bytes: usize = match afi {
        AFI_IPV4 => 4,
        AFI_IPV6 => 16,
        _ => return Err(WireError::MalformedUpdate),
    };
    let max_prefix_len = u8::try_from(addr_bytes * 8).unwrap();

    let mut prefixes = Vec::new();
    let mut path_ids = Vec::new();
    while !data.is_empty() {
        let path_id = if with_ids {
            if data.len() < 4 {
                return Err(WireError::MalformedUpdate);
            }
            let id = u32::from_be_bytes(data[..4].try_into().unwrap());
            data = &data[4..];
            id
        } else {
            0
        };
        if data.is_empty() {
            return Err(WireError::MalformedUpdate);
        }
        let prefix_len = data[0];
        if prefix_len > max_prefix_len {
            return Err(WireError::MalformedUpdate);
        }
        let byte_len = usize::from(prefix_len).div_ceil(8);
        if data.len() < 1 + byte_len {
            return Err(WireError::MalformedUpdate);
        }
        let mut octets = [0u8; 16];
        octets[..byte_len].copy_from_slice(&data[1..=byte_len]);
        let addr: IpAddr = if addr_bytes == 4 {
            Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).into()
        } else {
            Ipv6Addr::from(octets).into()
        };
        let net = IpNet::new(addr, prefix_len).map_err(|_| WireError::MalformedUpdate)?;
        prefixes.push(net);
        if with_ids {
            path_ids.push(path_id);
        }
        data = &data[1 + byte_len..];
    }
    Ok((prefixes, path_ids))
}

fn encode_prefix(net: IpNet, path_id: Option<u32>, out: &mut Vec<u8>) {
    if let Some(id) = path_id {
        out.extend_from_slice(&id.to_be_bytes());
    }
    let prefix_len = net.prefix_len();
    let byte_len = usize::from(prefix_len).div_ceil(8);
    out.push(prefix_len);
    match net.addr() {
        IpAddr::V4(a) => out.extend_from_slice(&a.octets()[..byte_len]),
        IpAddr::V6(a) => out.extend_from_slice(&a.octets()[..byte_len]),
    }
}

/// Encodes `nets`, attaching each corresponding entry of `path_ids` (must be
/// either empty — no ADD-PATH — or exactly `nets.len()` long) as a leading
/// Path Identifier per prefix.
fn encode_prefixes(nets: &[IpNet], path_ids: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, net) in nets.iter().enumerate() {
        encode_prefix(*net, path_ids.get(i).copied(), &mut out);
    }
    out
}

/// `decode_prefixes(AFI_IPV4, ...)` narrowed back to `Ipv4Net`, for the
/// legacy withdrawn-routes/NLRI fields — `decode_prefixes` with `afi ==
/// AFI_IPV4` only ever constructs `IpNet::V4`, so the `V6` arm is
/// unreachable.
fn decode_prefixes_v4(data: &[u8], with_ids: bool) -> Result<(Vec<Ipv4Net>, Vec<u32>), WireError> {
    let (nets, path_ids) = decode_prefixes(AFI_IPV4, data, with_ids)?;
    let nets = nets
        .into_iter()
        .map(|net| match net {
            IpNet::V4(n) => Ok(n),
            IpNet::V6(_) => Err(WireError::MalformedUpdate),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((nets, path_ids))
}

fn encode_prefixes_v4(nets: &[Ipv4Net], path_ids: &[u32]) -> Vec<u8> {
    let nets: Vec<IpNet> = nets.iter().copied().map(IpNet::V4).collect();
    encode_prefixes(&nets, path_ids)
}

/// Everything `parse_path_attributes` extracts from one UPDATE's attribute
/// list. The four legacy fields are each `Some`/non-empty only if the
/// message actually carried that attribute — callers decide mandatory-
/// attribute enforcement, since that depends on whether the UPDATE carries
/// any NLRI (legacy or `mp_reach`) at all.
#[derive(Default)]
struct ParsedAttributes {
    origin: Option<Origin>,
    as_path: Option<AsPath>,
    next_hop: Option<Ipv4Addr>,
    local_pref: Option<u32>,
    med: Option<u32>,
    originator_id: Option<Ipv4Addr>,
    cluster_list: Vec<Ipv4Addr>,
    communities: Vec<u32>,
    extended_communities: Vec<u64>,
    large_communities: Vec<(u32, u32, u32)>,
    ipv6_extended_communities: Vec<[u8; 20]>,
    pmsi: Option<Pmsi>,
    atomic_aggregate: bool,
    aggregator: Option<Aggregator>,
    otc: Option<u32>,
    mp_reach: Vec<MpReachNlri>,
    mp_unreach: Vec<MpUnreachNlri>,
    /// RFC 7606 treat-as-withdraw: an attribute's content was malformed.
    withdraw: bool,
}

/// Walks the TLV path-attribute list, decoding `ORIGIN`/`AS_PATH`/`NEXT_HOP`/
/// `LOCAL_PREF`/`MULTI_EXIT_DISC`/`ORIGINATOR_ID`/`CLUSTER_LIST`/
/// `COMMUNITY`/`EXTENDED_COMMUNITIES`/`LARGE_COMMUNITY`/`MP_REACH_NLRI`/
/// `MP_UNREACH_NLRI` and skipping anything else by its own declared length
/// (mirrors `parse_optional_parameters`'s handling of unknown OPEN
/// capabilities). `add_path_afis` is threaded down into
/// `MP_REACH_NLRI`/`MP_UNREACH_NLRI` decoding. With `two_octet_as`, `AS_PATH`
/// is read as 2-byte and merged with `AS4_PATH` per RFC 6793 §4.2.3; without
/// it a stray `AS4_PATH` is ignored.
/// Expected Optional|Transitive bits (0x80|0x40) per RFC 4271 §5 / RFC 7606
/// §3(c); `None` for types we do not know (never checked).
fn expected_flags(attr_type: u8) -> Option<u8> {
    match attr_type {
        ATTR_ORIGIN | ATTR_AS_PATH | ATTR_NEXT_HOP | ATTR_LOCAL_PREF | ATTR_ATOMIC_AGGREGATE => {
            Some(ATTR_FLAG_WELL_KNOWN_TRANSITIVE)
        }
        ATTR_MULTI_EXIT_DISC | ATTR_ORIGINATOR_ID | ATTR_CLUSTER_LIST | ATTR_MP_REACH_NLRI
        | ATTR_MP_UNREACH_NLRI => Some(ATTR_FLAG_OPTIONAL_NON_TRANSITIVE),
        ATTR_AGGREGATOR
        | ATTR_COMMUNITY
        | ATTR_EXTENDED_COMMUNITIES
        | ATTR_LARGE_COMMUNITY
        | ATTR_IPV6_EXTENDED_COMMUNITIES
        | ATTR_AS4_PATH
        | ATTR_AS4_AGGREGATOR
        | ATTR_PMSI_TUNNEL
        | ATTR_OTC => Some(ATTR_FLAG_OPTIONAL_TRANSITIVE),
        _ => None,
    }
}

/// `parse_path_attributes`' accumulator: the decoded fields plus the two
/// 4-octet carriers (RFC 6793) merged after the walk.
#[derive(Default)]
struct AttrAcc {
    out: ParsedAttributes,
    as4_path: Option<AsPath>,
    as4_aggregator: Option<Aggregator>,
}

/// Decodes one path attribute's `value` into `acc` — the per-type `match` of
/// `parse_path_attributes`, split out for length (#425). A malformed value
/// sets `acc.out.withdraw` (RFC 7606); only MP_* decode failures are errors.
fn parse_one_attribute(
    attr_type: u8,
    value: &[u8],
    add_path_afis: &HashSet<u16>,
    two_octet_as: bool,
    acc: &mut AttrAcc,
) -> Result<(), WireError> {
    match attr_type {
        ATTR_ORIGIN => {
            if value.len() != 1 {
                acc.out.withdraw = true;
                return Ok(());
            }
            match value[0] {
                0 => acc.out.origin = Some(Origin::Igp),
                1 => acc.out.origin = Some(Origin::Egp),
                2 => acc.out.origin = Some(Origin::Incomplete),
                _ => acc.out.withdraw = true,
            }
        }
        ATTR_AS_PATH => match parse_as_path(value, if two_octet_as { 2 } else { 4 }) {
            Ok(p) => acc.out.as_path = Some(p),
            Err(_) => acc.out.withdraw = true,
        },
        // RFC 7606 §7.11 / RFC 6793 §6: a malformed AS4_PATH, or one
        // carrying confederation segments, is discarded — the route
        // stays, with the 2-octet AS_PATH as received.
        ATTR_AS4_PATH if two_octet_as => match parse_as_path(value, 4) {
            Ok(p) if p.has_confed() => {
                debug!("discarding as4_path: it carries confederation segments");
            }
            Ok(p) => acc.as4_path = Some(p),
            Err(_) => debug!("discarding malformed as4_path"),
        },
        ATTR_NEXT_HOP => {
            if value.len() != 4 {
                acc.out.withdraw = true;
                return Ok(());
            }
            acc.out.next_hop = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
        }
        ATTR_LOCAL_PREF => {
            if value.len() != 4 {
                acc.out.withdraw = true;
                return Ok(());
            }
            acc.out.local_pref = Some(u32::from_be_bytes(value.try_into().unwrap()));
        }
        ATTR_MULTI_EXIT_DISC => {
            if value.len() != 4 {
                acc.out.withdraw = true;
                return Ok(());
            }
            acc.out.med = Some(u32::from_be_bytes(value.try_into().unwrap()));
        }
        ATTR_ORIGINATOR_ID => {
            if value.len() != 4 {
                acc.out.withdraw = true;
                return Ok(());
            }
            acc.out.originator_id = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
        }
        ATTR_CLUSTER_LIST => {
            if !value.len().is_multiple_of(4) {
                acc.out.withdraw = true;
                return Ok(());
            }
            acc.out.cluster_list = value
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                .collect();
        }
        ATTR_COMMUNITY => {
            if !value.len().is_multiple_of(4) {
                acc.out.withdraw = true;
                return Ok(());
            }
            acc.out.communities = value
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_be_bytes(*c))
                .collect();
        }
        ATTR_EXTENDED_COMMUNITIES => {
            if !value.len().is_multiple_of(8) {
                acc.out.withdraw = true;
                return Ok(());
            }
            acc.out.extended_communities = value
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| u64::from_be_bytes(*c))
                .collect();
        }
        ATTR_LARGE_COMMUNITY => {
            if !value.len().is_multiple_of(12) {
                acc.out.withdraw = true;
                return Ok(());
            }
            acc.out.large_communities = value
                .as_chunks::<12>()
                .0
                .iter()
                .map(|c| {
                    (
                        u32::from_be_bytes(c[0..4].try_into().unwrap()),
                        u32::from_be_bytes(c[4..8].try_into().unwrap()),
                        u32::from_be_bytes(c[8..12].try_into().unwrap()),
                    )
                })
                .collect();
        }
        // RFC 5701 section 3 / RFC 7606 section 7.15.
        ATTR_IPV6_EXTENDED_COMMUNITIES => match value.as_chunks::<20>() {
            (c, []) => acc.out.ipv6_extended_communities = c.to_vec(),
            _ => acc.out.withdraw = true,
        },
        // RFC 7606 §7.7/§7.8: a malformed one is discarded, not a withdraw.
        ATTR_ATOMIC_AGGREGATE => acc.out.atomic_aggregate = value.is_empty(),
        ATTR_AGGREGATOR => {
            acc.out.aggregator = match (value.len(), two_octet_as) {
                (6, true) => Some(Aggregator {
                    asn: u32::from(u16::from_be_bytes([value[0], value[1]])),
                    router_id: Ipv4Addr::new(value[2], value[3], value[4], value[5]),
                }),
                (8, false) => Some(Aggregator {
                    asn: u32::from_be_bytes(value[0..4].try_into().unwrap()),
                    router_id: Ipv4Addr::new(value[4], value[5], value[6], value[7]),
                }),
                _ => None,
            }
        }
        ATTR_AS4_AGGREGATOR if two_octet_as && value.len() == 8 => {
            acc.as4_aggregator = Some(Aggregator {
                asn: u32::from_be_bytes(value[0..4].try_into().unwrap()),
                router_id: Ipv4Addr::new(value[4], value[5], value[6], value[7]),
            });
        }
        ATTR_OTC => {
            let Ok(v) = <[u8; 4]>::try_from(value) else {
                acc.out.withdraw = true;
                return Ok(());
            };
            acc.out.otc = Some(u32::from_be_bytes(v));
        }
        ATTR_PMSI_TUNNEL => acc.out.pmsi = decode_pmsi(value),
        ATTR_MP_REACH_NLRI => acc
            .out
            .mp_reach
            .push(decode_mp_reach(value, add_path_afis)?),
        ATTR_MP_UNREACH_NLRI => acc
            .out
            .mp_unreach
            .push(decode_mp_unreach(value, add_path_afis)?),
        _ => {
            // Unknown attribute type: skip by declared length, never an
            // error — same philosophy as unrecognized OPEN capabilities.
        }
    }
    Ok(())
}

fn parse_path_attributes(
    mut data: &[u8],
    add_path_afis: &HashSet<u16>,
    two_octet_as: bool,
) -> Result<ParsedAttributes, WireError> {
    let mut acc = AttrAcc::default();
    // RFC 7606 §3(g): types already seen in this UPDATE.
    let mut seen = [false; 256];

    while !data.is_empty() {
        if data.len() < 2 {
            return Err(WireError::MalformedUpdate);
        }
        let flags = data[0];
        let attr_type = data[1];
        let (len, header_len) = if flags & ATTR_FLAG_EXTENDED_LENGTH != 0 {
            if data.len() < 4 {
                return Err(WireError::MalformedUpdate);
            }
            (usize::from(u16::from_be_bytes([data[2], data[3]])), 4)
        } else {
            if data.len() < 3 {
                return Err(WireError::MalformedUpdate);
            }
            (usize::from(data[2]), 3)
        };
        if data.len() < header_len + len {
            return Err(WireError::MalformedUpdate);
        }
        let value = &data[header_len..header_len + len];

        'attr: {
            let is_mp = matches!(attr_type, ATTR_MP_REACH_NLRI | ATTR_MP_UNREACH_NLRI);
            // RFC 7606 §3(c): flags conflicting with the type are a
            // treat-as-withdraw, or a reset for MP_* (no NLRI to withdraw).
            // Partial and Extended-Length are never checked.
            if let Some(want) = expected_flags(attr_type)
                && flags & (ATTR_FLAG_OPTIONAL_TRANSITIVE) != want
            {
                if is_mp {
                    return Err(WireError::MalformedUpdate);
                }
                acc.out.withdraw = true;
                break 'attr;
            }
            // RFC 7606 §3(g): a repeated MP_* resets the session; any other
            // repeat keeps the first occurrence and discards the rest.
            if std::mem::replace(&mut seen[usize::from(attr_type)], true) {
                if is_mp {
                    return Err(WireError::MalformedUpdate);
                }
                debug!(attr_type, "discarding duplicate path attribute");
                break 'attr;
            }
            parse_one_attribute(attr_type, value, add_path_afis, two_octet_as, &mut acc)?;
        }

        data = &data[header_len + len..];
    }

    let AttrAcc {
        mut out,
        as4_path,
        as4_aggregator,
    } = acc;
    // RFC 6793 §4.2.3, see `AsPath::merge_as4`.
    if let (Some(path), Some(as4)) = (out.as_path.as_mut(), as4_path) {
        path.merge_as4(&as4);
    }

    // RFC 6793 §4.2.3: AS4_AGGREGATOR replaces an AGGREGATOR holding AS_TRANS.
    if let (Some(agg), Some(as4)) = (out.aggregator.as_mut(), as4_aggregator)
        && agg.asn == u32::from(AS_TRANS)
    {
        *agg = as4;
    }

    Ok(out)
}

/// `flags(1) type(1) label(3) tunnel-id`; anything but ingress replication
/// (type 6) with a 4/16-byte tunnel id is ignored, never an error — the
/// attribute is optional and only EVPN Type-3 consumers look at it.
fn decode_pmsi(value: &[u8]) -> Option<Pmsi> {
    if value.len() < 5 || value[1] != 6 {
        return None;
    }
    let vni = u32::from_be_bytes([0, value[2], value[3], value[4]]);
    let tunnel_ip = match value.len() - 5 {
        4 => IpAddr::from(<[u8; 4]>::try_from(&value[5..]).ok()?),
        16 => IpAddr::from(<[u8; 16]>::try_from(&value[5..]).ok()?),
        _ => return None,
    };
    Some(Pmsi { vni, tunnel_ip })
}

fn encode_pmsi(p: &Pmsi) -> Vec<u8> {
    let mut v = vec![0, 6];
    v.extend_from_slice(&p.vni.to_be_bytes()[1..]);
    match p.tunnel_ip {
        IpAddr::V4(a) => v.extend_from_slice(&a.octets()),
        IpAddr::V6(a) => v.extend_from_slice(&a.octets()),
    }
    v
}

/// One RFC 4684 Route Target membership NLRI: a `bits`-long prefix (0, or
/// 32..=96) of `origin_as(4) || route target(8)`. `bits == 0` is the default
/// route ("send me everything"); for a partial prefix `rt` holds the first
/// `bits - 32` bits of the route target and the rest is zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RtcNlri {
    /// Origin AS (zero for the default route; ignored for filtering).
    pub origin_as: u32,
    /// The 8-octet route target extended community (type, subtype, value).
    pub rt: u64,
    /// Prefix length in bits: 0 or 32..=96.
    pub bits: u8,
}

impl RtcNlri {
    /// The 12 octets `origin_as || rt` with every bit past `bits` zeroed.
    fn masked(self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[..4].copy_from_slice(&self.origin_as.to_be_bytes());
        buf[4..].copy_from_slice(&self.rt.to_be_bytes());
        let bits = usize::from(self.bits);
        for (i, b) in buf.iter_mut().enumerate() {
            let keep = bits.saturating_sub(i * 8).min(8);
            *b &= if keep == 0 { 0 } else { 0xffu8 << (8 - keep) };
        }
        buf
    }

    /// A well-formed prefix length (RFC 4684 section 4).
    pub fn valid(self) -> bool {
        self.bits == 0 || (32..=96).contains(&self.bits)
    }
}

/// A run of RFC 4684 NLRIs: `len(1)` then `ceil(len/8)` prefix octets. A
/// length of 1..=31 or over 96, or a truncated entry, is malformed.
fn decode_rtc_nlris(mut data: &[u8]) -> Result<Vec<RtcNlri>, WireError> {
    let mut out = Vec::new();
    while let Some((&bits, rest)) = data.split_first() {
        let n = usize::from(bits).div_ceil(8);
        if (bits != 0 && !(32..=96).contains(&bits)) || rest.len() < n {
            return Err(WireError::MalformedUpdate);
        }
        let mut buf = [0u8; 12];
        buf[..n].copy_from_slice(&rest[..n]);
        let raw = RtcNlri {
            origin_as: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            rt: u64::from_be_bytes(buf[4..].try_into().expect("8 octets")),
            bits,
        };
        let m = raw.masked();
        out.push(RtcNlri {
            origin_as: u32::from_be_bytes([m[0], m[1], m[2], m[3]]),
            rt: u64::from_be_bytes(m[4..].try_into().expect("8 octets")),
            bits,
        });
        data = &rest[n..];
    }
    Ok(out)
}

fn encode_rtc_nlris(nlris: &[RtcNlri], out: &mut Vec<u8>) {
    // ponytail: an invalid length is skipped; only `rib::rtc` builds these
    // and it never produces one.
    for n in nlris.iter().filter(|n| n.valid()) {
        out.push(n.bits);
        out.extend_from_slice(&n.masked()[..usize::from(n.bits).div_ceil(8)]);
    }
}

/// RFC 4760 `MP_REACH_NLRI` value: `AFI(2) SAFI(1) NextHopLen(1)
/// NextHop(NextHopLen) SNPACount(1) SNPAs... NLRI...`. SNPAs are always
/// skipped by their own declared lengths (this crate never emits any, but
/// stays tolerant of a peer that does). `add_path_afis` decides whether this
/// batch's own `afi` carries a leading Path Identifier per NLRI entry.
fn decode_mp_reach(data: &[u8], add_path_afis: &HashSet<u16>) -> Result<MpReachNlri, WireError> {
    if data.len() < 5 {
        return Err(WireError::MalformedUpdate);
    }
    let afi = u16::from_be_bytes([data[0], data[1]]);
    let safi = data[2];
    let nh_len = data[3] as usize;
    if data.len() < 4 + nh_len + 1 {
        return Err(WireError::MalformedUpdate);
    }
    let next_hop: IpAddr = match nh_len {
        _ if safi == SAFI_VPN => vpn::decode_next_hop(afi, &data[4..4 + nh_len])?,
        4 => Ipv4Addr::new(data[4], data[5], data[6], data[7]).into(),
        // RFC 2545 §3: 32 = global address followed by link-local.
        // ponytail: the link-local is dropped, `next_hop` is a single address.
        16 | 32 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            Ipv6Addr::from(octets).into()
        }
        // RFC 8955 section 4: Flowspec carries no next hop (length 0) and
        // any value is ignored; keep the unspecified address of the AFI.
        0 if safi == SAFI_FLOWSPEC => match afi {
            AFI_IPV4 => Ipv4Addr::UNSPECIFIED.into(),
            AFI_IPV6 => Ipv6Addr::UNSPECIFIED.into(),
            _ => return Err(WireError::MalformedUpdate),
        },
        _ => return Err(WireError::MalformedUpdate),
    };
    let mut pos = 4 + nh_len;
    let snpa_count = data[pos];
    pos += 1;
    for _ in 0..snpa_count {
        if data.len() <= pos {
            return Err(WireError::MalformedUpdate);
        }
        let snpa_len = data[pos] as usize;
        pos += 1 + snpa_len;
        if data.len() < pos {
            return Err(WireError::MalformedUpdate);
        }
    }
    if (afi, safi) == (AFI_L2VPN, SAFI_EVPN) {
        return Ok(MpReachNlri {
            afi,
            safi,
            next_hop,
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            evpn: evpn::decode_nlris(&data[pos..])?,
            flowspec: Vec::new(),
            vpn: Vec::new(),
            rtc: Vec::new(),
        });
    }
    if safi == SAFI_RTC {
        return Ok(MpReachNlri {
            afi,
            safi,
            next_hop,
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            evpn: Vec::new(),
            flowspec: Vec::new(),
            vpn: Vec::new(),
            rtc: decode_rtc_nlris(&data[pos..])?,
        });
    }
    if safi == SAFI_FLOWSPEC {
        return Ok(MpReachNlri {
            afi,
            safi,
            next_hop,
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            evpn: Vec::new(),
            flowspec: decode_flowspec(afi, &data[pos..])?,
            vpn: Vec::new(),
            rtc: Vec::new(),
        });
    }
    // No ADD-PATH here: `add_path_afis` is keyed by AFI only, so consulting
    // it would misread IPv4/IPv6 unicast's negotiation as SAFI 128's.
    if safi == SAFI_VPN {
        return Ok(MpReachNlri {
            afi,
            safi,
            next_hop,
            nlri: Vec::new(),
            nlri_path_ids: Vec::new(),
            evpn: Vec::new(),
            flowspec: Vec::new(),
            vpn: vpn::decode_vpn_reach(afi, &data[pos..])?,
            rtc: Vec::new(),
        });
    }
    let (nlri, nlri_path_ids) = decode_prefixes(afi, &data[pos..], add_path_afis.contains(&afi))?;
    Ok(MpReachNlri {
        afi,
        safi,
        next_hop,
        nlri,
        nlri_path_ids,
        evpn: Vec::new(),
        flowspec: Vec::new(),
        vpn: Vec::new(),
        rtc: Vec::new(),
    })
}

/// RFC 4760 `MP_UNREACH_NLRI` value: `AFI(2) SAFI(1) WithdrawnNLRI...`.
/// `add_path_afis` decides whether this batch's own `afi` carries a leading
/// Path Identifier per withdrawn entry.
fn decode_mp_unreach(
    data: &[u8],
    add_path_afis: &HashSet<u16>,
) -> Result<MpUnreachNlri, WireError> {
    if data.len() < 3 {
        return Err(WireError::MalformedUpdate);
    }
    let afi = u16::from_be_bytes([data[0], data[1]]);
    let safi = data[2];
    if (afi, safi) == (AFI_L2VPN, SAFI_EVPN) {
        return Ok(MpUnreachNlri {
            afi,
            safi,
            withdrawn: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            evpn: evpn::decode_nlris(&data[3..])?,
            flowspec: Vec::new(),
            vpn: Vec::new(),
            rtc: Vec::new(),
        });
    }
    if safi == SAFI_RTC {
        return Ok(MpUnreachNlri {
            afi,
            safi,
            withdrawn: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            evpn: Vec::new(),
            flowspec: Vec::new(),
            vpn: Vec::new(),
            rtc: decode_rtc_nlris(&data[3..])?,
        });
    }
    if safi == SAFI_FLOWSPEC {
        return Ok(MpUnreachNlri {
            afi,
            safi,
            withdrawn: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            evpn: Vec::new(),
            flowspec: decode_flowspec(afi, &data[3..])?,
            vpn: Vec::new(),
            rtc: Vec::new(),
        });
    }
    if safi == SAFI_VPN {
        return Ok(MpUnreachNlri {
            afi,
            safi,
            withdrawn: Vec::new(),
            withdrawn_path_ids: Vec::new(),
            evpn: Vec::new(),
            flowspec: Vec::new(),
            vpn: vpn::decode_vpn_unreach(afi, &data[3..])?,
            rtc: Vec::new(),
        });
    }
    let (withdrawn, withdrawn_path_ids) =
        decode_prefixes(afi, &data[3..], add_path_afis.contains(&afi))?;
    Ok(MpUnreachNlri {
        afi,
        safi,
        withdrawn,
        withdrawn_path_ids,
        evpn: Vec::new(),
        flowspec: Vec::new(),
        vpn: Vec::new(),
        rtc: Vec::new(),
    })
}

/// A run of length-prefixed Flowspec NLRIs; any bad one (or an AFI other
/// than 1/2) makes the attribute malformed (RFC 7606 section 3(g): reset,
/// since an unparsable NLRI cannot be turned into a withdraw).
fn decode_flowspec(afi: u16, mut data: &[u8]) -> Result<Vec<FlowSpec>, WireError> {
    let afi = match afi {
        AFI_IPV4 => flowspec::Afi::V4,
        AFI_IPV6 => flowspec::Afi::V6,
        _ => return Err(WireError::MalformedUpdate),
    };
    let mut out = Vec::new();
    while !data.is_empty() {
        let (rule, used) = FlowSpec::decode(afi, data).map_err(|_| WireError::MalformedUpdate)?;
        out.push(rule);
        data = &data[used..];
    }
    Ok(out)
}

fn encode_flowspec(rules: &[FlowSpec], out: &mut Vec<u8>) {
    // ponytail: a rule that fails to encode (empty, >4095 octets) is
    // skipped; nothing originates Flowspec yet (#560 will).
    for r in rules {
        let mut one = Vec::new();
        if r.encode(&mut one).is_ok() {
            out.extend_from_slice(&one);
        }
    }
}

fn encode_mp_reach(mp: &MpReachNlri) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&mp.afi.to_be_bytes());
    out.push(mp.safi);
    // RFC 8955 section 4: Flowspec has no next hop, never a rewritten one.
    if mp.safi == SAFI_FLOWSPEC {
        out.push(0);
    } else if mp.safi == SAFI_VPN {
        vpn::encode_next_hop(mp.afi, mp.next_hop, &mut out);
    } else {
        match mp.next_hop {
            IpAddr::V4(a) => {
                out.push(4);
                out.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                out.push(16);
                out.extend_from_slice(&a.octets());
            }
        }
    }
    out.push(0); // SNPA count — this crate never advertises any.
    out.extend_from_slice(&encode_prefixes(&mp.nlri, &mp.nlri_path_ids));
    mp.evpn.iter().for_each(|n| evpn::encode_nlri(n, &mut out));
    encode_flowspec(&mp.flowspec, &mut out);
    vpn::encode_vpn_reach(&mp.vpn, &mut out);
    encode_rtc_nlris(&mp.rtc, &mut out);
    out
}

fn encode_mp_unreach(mp: &MpUnreachNlri) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&mp.afi.to_be_bytes());
    out.push(mp.safi);
    out.extend_from_slice(&encode_prefixes(&mp.withdrawn, &mp.withdrawn_path_ids));
    mp.evpn.iter().for_each(|n| evpn::encode_nlri(n, &mut out));
    encode_flowspec(&mp.flowspec, &mut out);
    vpn::encode_vpn_unreach(&mp.vpn, &mut out);
    encode_rtc_nlris(&mp.rtc, &mut out);
    out
}

/// Decodes `AS_PATH`/`AS4_PATH` segments (`segment_type(1) count(1)
/// count*width bytes`, `width` 2 or 4). An unknown segment type, an empty
/// segment (RFC 7606 §7.2) or AS 0 (RFC 7607) is malformed.
fn parse_as_path(mut data: &[u8], width: usize) -> Result<AsPath, WireError> {
    let mut path = AsPath::default();
    while !data.is_empty() {
        if data.len() < 2 {
            return Err(WireError::MalformedUpdate);
        }
        let kind = SegKind::from_wire(data[0]).ok_or(WireError::MalformedUpdate)?;
        let count = usize::from(data[1]);
        let segment_len = 2 + count * width;
        if count == 0 || data.len() < segment_len {
            return Err(WireError::MalformedUpdate);
        }
        let asns: Vec<u32> = data[2..segment_len]
            .chunks_exact(width)
            .map(|c| c.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
            .collect();
        if asns.contains(&0) {
            return Err(WireError::MalformedUpdate);
        }
        path.push_segment(kind, &asns);
        data = &data[segment_len..];
    }
    Ok(path)
}

/// Parses an UPDATE body: withdrawn-routes (u16 length + packed IPv4
/// prefixes), path attributes (u16 length + TLV list), then legacy NLRI
/// (everything remaining — RFC 4271 has no explicit NLRI length field, since
/// the outer message header's length already delimits it).
///
/// `ORIGIN`/`AS_PATH` must be present whenever any NLRI is being announced
/// (legacy `nlri` or an `MP_REACH_NLRI` batch), else `MalformedUpdate`.
/// `NEXT_HOP` is additionally mandatory only when the legacy `nlri` field
/// itself is non-empty — an MP-only announcement carries its next-hop inside
/// `MP_REACH_NLRI` instead and may omit the legacy attribute entirely. If
/// nothing is being announced (a pure withdrawal), `attributes` is `None`,
/// discarding any attributes present. `add_path_afis` (from the owning
/// `BgpCodec`) decides whether IPv4 unicast (legacy `withdrawn_routes`/
/// `nlri`) — and, per-batch, each `mp_reach`/`mp_unreach` entry's own AFI —
/// carries a leading RFC 7911 Path Identifier.
fn parse_update(
    body: &[u8],
    add_path_afis: &HashSet<u16>,
    two_octet_as: bool,
) -> Result<UpdateMessage, WireError> {
    if body.len() < 2 {
        return Err(WireError::MalformedUpdate);
    }
    let with_ids_v4 = add_path_afis.contains(&AFI_IPV4);
    let withdrawn_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let mut pos = 2;
    if body.len() < pos + withdrawn_len {
        return Err(WireError::MalformedUpdate);
    }
    let (withdrawn_routes, withdrawn_path_ids) =
        decode_prefixes_v4(&body[pos..pos + withdrawn_len], with_ids_v4)?;
    pos += withdrawn_len;

    if body.len() < pos + 2 {
        return Err(WireError::MalformedUpdate);
    }
    let attr_len = usize::from(u16::from_be_bytes([body[pos], body[pos + 1]]));
    pos += 2;
    if body.len() < pos + attr_len {
        return Err(WireError::MalformedUpdate);
    }
    let parsed = parse_path_attributes(&body[pos..pos + attr_len], add_path_afis, two_octet_as)?;
    pos += attr_len;

    let (nlri, nlri_path_ids) = decode_prefixes_v4(&body[pos..], with_ids_v4)?;

    let announcing = !nlri.is_empty() || !parsed.mp_reach.is_empty();
    // RFC 8955 section 10 / RFC 7606: an undecodable traffic-action community
    // on a Flowspec announcement is treat-as-withdraw.
    let bad_action = parsed.mp_reach.iter().any(|m| !m.flowspec.is_empty())
        && crate::flowspec_action::decode_actions(&parsed.extended_communities).is_err();
    let attributes = if announcing && !parsed.withdraw && !bad_action {
        // A missing mandatory attribute is treat-as-withdraw too (RFC 7606
        // §3(d)). NEXT_HOP is only mandatory with legacy NLRI: an MP-only
        // announcement carries its next-hop inside `MP_REACH_NLRI`.
        match (parsed.origin, parsed.as_path, parsed.next_hop) {
            (Some(origin), Some(as_path), next_hop) if next_hop.is_some() || nlri.is_empty() => {
                Some(PathAttributes {
                    origin,
                    as_path,
                    next_hop: next_hop.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    local_pref: parsed.local_pref,
                    med: parsed.med,
                    originator_id: parsed.originator_id,
                    cluster_list: parsed.cluster_list,
                    communities: parsed.communities,
                    extended_communities: parsed.extended_communities,
                    large_communities: parsed.large_communities,
                    ipv6_extended_communities: parsed.ipv6_extended_communities,
                    pmsi: parsed.pmsi,
                    atomic_aggregate: parsed.atomic_aggregate,
                    aggregator: parsed.aggregator,
                    otc: parsed.otc,
                })
            }
            _ => None,
        }
    } else {
        None
    };

    let mut update = UpdateMessage {
        withdrawn_routes,
        withdrawn_path_ids,
        nlri,
        nlri_path_ids,
        attributes,
        mp_reach: parsed.mp_reach,
        mp_unreach: parsed.mp_unreach,
        treat_as_withdraw_prefixes: 0,
    };
    // RFC 7606 §2 treat-as-withdraw: the announced routes are handled as if
    // listed as withdrawn (legacy NLRI -> Withdrawn Routes, each MP_REACH
    // batch -> an MP_UNREACH batch), and the attributes are dropped.
    if announcing && update.attributes.is_none() {
        warn!(
            "malformed UPDATE path attributes: treating announced routes as withdrawn (RFC 7606)"
        );
        let count = update.nlri.len()
            + update
                .mp_reach
                .iter()
                .map(|m| m.nlri.len() + m.evpn.len() + m.flowspec.len() + m.vpn.len() + m.rtc.len())
                .sum::<usize>();
        update.treat_as_withdraw_prefixes = u32::try_from(count).unwrap_or(u32::MAX);
        update.withdrawn_routes.append(&mut update.nlri);
        update.withdrawn_path_ids.append(&mut update.nlri_path_ids);
        let reach = std::mem::take(&mut update.mp_reach);
        update.mp_unreach.extend(reach.into_iter().map(|m| {
            MpUnreachNlri {
                afi: m.afi,
                safi: m.safi,
                withdrawn: m.nlri,
                withdrawn_path_ids: m.nlri_path_ids,
                evpn: m.evpn,
                flowspec: m.flowspec,
                vpn: m
                    .vpn
                    .into_iter()
                    .map(|n| VpnNlri {
                        labels: vec![],
                        ..n
                    })
                    .collect(),
                rtc: m.rtc,
            }
        }));
    }
    Ok(update)
}

fn encode_attribute(out: &mut Vec<u8>, flags: u8, attr_type: u8, value: &[u8]) {
    if let Ok(len) = u8::try_from(value.len()) {
        out.push(flags);
        out.push(attr_type);
        out.push(len);
    } else {
        out.push(flags | ATTR_FLAG_EXTENDED_LENGTH);
        out.push(attr_type);
        // Only reached for an attribute value over 255 bytes (a very long
        // AS_PATH) — still far under a whole message's 4096-byte cap (65535 with RFC 8654).
        out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    }
    out.extend_from_slice(value);
}

/// Encodes each segment with its own type byte. An empty path encodes as an
/// empty attribute value (no segments at all) — valid for, e.g., a route
/// redistributed straight to an iBGP peer, which never gets a local ASN
/// prepended. With `two_octet`, each ASN is 2 bytes and one that doesn't fit
/// becomes `AS_TRANS` (RFC 6793 §4.2.2).
fn encode_as_path(path: &AsPath, two_octet: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, asns) in path.segments() {
        out.push(kind as u8);
        // `AsPath` never holds a segment over 255 ASNs.
        out.push(u8::try_from(asns.len()).unwrap_or(u8::MAX));
        for asn in asns {
            if two_octet {
                let asn = u16::try_from(*asn).unwrap_or(AS_TRANS);
                out.extend_from_slice(&asn.to_be_bytes());
            } else {
                out.extend_from_slice(&asn.to_be_bytes());
            }
        }
    }
    out
}

/// `AGGREGATOR` (and, RFC 6793 §4.2.2, `AS4_AGGREGATOR`), split out of
/// `encode_path_attrs` for length (#425).
fn encode_aggregator(out: &mut Vec<u8>, agg: Aggregator, two_octet_as: bool) {
    let mut value = Vec::with_capacity(8);
    if two_octet_as {
        value.extend_from_slice(&u16::try_from(agg.asn).unwrap_or(AS_TRANS).to_be_bytes());
    } else {
        value.extend_from_slice(&agg.asn.to_be_bytes());
    }
    value.extend_from_slice(&agg.router_id.octets());
    encode_attribute(out, ATTR_FLAG_OPTIONAL_TRANSITIVE, ATTR_AGGREGATOR, &value);
    // RFC 6793 §4.2.2: the real AS rides along only when it was squashed.
    if two_octet_as && agg.asn > u32::from(u16::MAX) {
        let mut v = agg.asn.to_be_bytes().to_vec();
        v.extend_from_slice(&agg.router_id.octets());
        encode_attribute(out, ATTR_FLAG_OPTIONAL_TRANSITIVE, ATTR_AS4_AGGREGATOR, &v);
    }
}

/// The attributes `encode_attributes` writes from `UpdateMessage::attributes`
/// (everything but `PMSI_TUNNEL` and the `MP_*` batches), split out for
/// length (#425). `has_nlri` gates `NEXT_HOP`.
fn encode_path_attrs(
    out: &mut Vec<u8>,
    attrs: &PathAttributes,
    has_nlri: bool,
    two_octet_as: bool,
) {
    encode_attribute(
        out,
        ATTR_FLAG_WELL_KNOWN_TRANSITIVE,
        ATTR_ORIGIN,
        &[attrs.origin as u8],
    );
    encode_attribute(
        out,
        ATTR_FLAG_WELL_KNOWN_TRANSITIVE,
        ATTR_AS_PATH,
        &encode_as_path(&attrs.as_path, two_octet_as),
    );
    // RFC 6793 §4.2.2: the real path rides along only when some ASN was
    // squashed to AS_TRANS — without confederation segments (§6).
    if two_octet_as
        && attrs
            .as_path
            .flat()
            .iter()
            .any(|&a| a > u32::from(u16::MAX))
    {
        let mut as4 = attrs.as_path.clone();
        as4.strip_confed();
        encode_attribute(
            out,
            ATTR_FLAG_OPTIONAL_TRANSITIVE,
            ATTR_AS4_PATH,
            &encode_as_path(&as4, false),
        );
    }
    if has_nlri {
        encode_attribute(
            out,
            ATTR_FLAG_WELL_KNOWN_TRANSITIVE,
            ATTR_NEXT_HOP,
            &attrs.next_hop.octets(),
        );
    }
    if attrs.atomic_aggregate {
        encode_attribute(
            out,
            ATTR_FLAG_WELL_KNOWN_TRANSITIVE,
            ATTR_ATOMIC_AGGREGATE,
            &[],
        );
    }
    if let Some(agg) = attrs.aggregator {
        encode_aggregator(out, agg, two_octet_as);
    }
    if let Some(otc) = attrs.otc {
        encode_attribute(
            out,
            ATTR_FLAG_OPTIONAL_TRANSITIVE,
            ATTR_OTC,
            &otc.to_be_bytes(),
        );
    }
    if let Some(local_pref) = attrs.local_pref {
        encode_attribute(
            out,
            ATTR_FLAG_WELL_KNOWN_TRANSITIVE,
            ATTR_LOCAL_PREF,
            &local_pref.to_be_bytes(),
        );
    }
    if let Some(med) = attrs.med {
        encode_attribute(
            out,
            ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
            ATTR_MULTI_EXIT_DISC,
            &med.to_be_bytes(),
        );
    }
    if let Some(originator_id) = attrs.originator_id {
        encode_attribute(
            out,
            ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
            ATTR_ORIGINATOR_ID,
            &originator_id.octets(),
        );
    }
    if !attrs.cluster_list.is_empty() {
        let value: Vec<u8> = attrs
            .cluster_list
            .iter()
            .flat_map(Ipv4Addr::octets)
            .collect();
        encode_attribute(
            out,
            ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
            ATTR_CLUSTER_LIST,
            &value,
        );
    }
    if !attrs.communities.is_empty() {
        let value: Vec<u8> = attrs
            .communities
            .iter()
            .flat_map(|c| c.to_be_bytes())
            .collect();
        encode_attribute(out, ATTR_FLAG_OPTIONAL_TRANSITIVE, ATTR_COMMUNITY, &value);
    }
    if !attrs.extended_communities.is_empty() {
        let value: Vec<u8> = attrs
            .extended_communities
            .iter()
            .flat_map(|c| c.to_be_bytes())
            .collect();
        encode_attribute(
            out,
            ATTR_FLAG_OPTIONAL_TRANSITIVE,
            ATTR_EXTENDED_COMMUNITIES,
            &value,
        );
    }
    if !attrs.large_communities.is_empty() {
        let value: Vec<u8> = attrs
            .large_communities
            .iter()
            .flat_map(|(ga, l1, l2)| {
                ga.to_be_bytes()
                    .into_iter()
                    .chain(l1.to_be_bytes())
                    .chain(l2.to_be_bytes())
            })
            .collect();
        encode_attribute(
            out,
            ATTR_FLAG_OPTIONAL_TRANSITIVE,
            ATTR_LARGE_COMMUNITY,
            &value,
        );
    }
    if !attrs.ipv6_extended_communities.is_empty() {
        encode_attribute(
            out,
            ATTR_FLAG_OPTIONAL_TRANSITIVE,
            ATTR_IPV6_EXTENDED_COMMUNITIES,
            attrs.ipv6_extended_communities.as_flattened(),
        );
    }
}

/// Builds the whole path-attribute TLV list for one UPDATE: the legacy
/// `ORIGIN`/`AS_PATH`/(`NEXT_HOP`)/`LOCAL_PREF` attributes (`NEXT_HOP` only
/// when the legacy `nlri` field is non-empty), then one `MP_REACH_NLRI`/
/// `MP_UNREACH_NLRI` attribute per batch.
fn encode_attributes(update: &UpdateMessage, two_octet_as: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(attrs) = &update.attributes {
        encode_path_attrs(&mut out, attrs, !update.nlri.is_empty(), two_octet_as);
    }
    if let Some(pmsi) = update.attributes.as_ref().and_then(|a| a.pmsi.as_ref()) {
        encode_attribute(
            &mut out,
            ATTR_FLAG_OPTIONAL_TRANSITIVE,
            ATTR_PMSI_TUNNEL,
            &encode_pmsi(pmsi),
        );
    }
    for mp in &update.mp_reach {
        encode_attribute(
            &mut out,
            ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
            ATTR_MP_REACH_NLRI,
            &encode_mp_reach(mp),
        );
    }
    for mp in &update.mp_unreach {
        encode_attribute(
            &mut out,
            ATTR_FLAG_OPTIONAL_NON_TRANSITIVE,
            ATTR_MP_UNREACH_NLRI,
            &encode_mp_unreach(mp),
        );
    }
    out
}

/// Mirror image of `parse_update`. Byte lengths for the withdrawn-routes and
/// path-attributes sections always fit comfortably in a `u16` in practice —
/// the whole message is capped at `MAX_MESSAGE_LEN` (4096, or 65535 with RFC 8654) bytes by
/// `BgpCodec::encode`, which will itself reject the overall frame if
/// something pathological ever made it larger.
fn encode_update(update: &UpdateMessage, two_octet_as: bool) -> Vec<u8> {
    let mut body = Vec::new();

    let withdrawn = encode_prefixes_v4(&update.withdrawn_routes, &update.withdrawn_path_ids);
    body.extend_from_slice(
        &u16::try_from(withdrawn.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    body.extend_from_slice(&withdrawn);

    let attrs = encode_attributes(update, two_octet_as);
    body.extend_from_slice(&u16::try_from(attrs.len()).unwrap_or(u16::MAX).to_be_bytes());
    body.extend_from_slice(&attrs);

    body.extend_from_slice(&encode_prefixes_v4(&update.nlri, &update.nlri_path_ids));
    body
}

#[cfg(test)]
// Community/ASN values are conventionally written and read in decimal
// (`65000:100`) — hex/binary notation would make these test fixtures harder
// to read, not easier.
#[allow(clippy::decimal_bitwise_operands, clippy::identity_op)]
mod tests {
    use super::*;

    fn roundtrip(msg: BgpMessage) -> BgpMessage {
        let mut codec = BgpCodec::default();
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();
        codec.decode(&mut buf).unwrap().unwrap()
    }

    fn open_with_caps(n: u16) -> OpenMessage {
        let mut open = build_open(65001, Ipv4Addr::new(1, 1, 1, 1), 90);
        open.capabilities = (0..n)
            .map(|afi| Capability::MultiProtocol { afi, safi: 1 })
            .collect();
        open
    }

    #[test]
    fn open_over_255_bytes_uses_rfc9072_extended_form() {
        let open = open_with_caps(60); // 60 * 6 = 360 bytes of capabilities
        assert_eq!(encode_open(&open)[9..11], [255, 255]);
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn oversize_add_path_capability_is_split() {
        let tuples: Vec<_> = (0..100)
            .map(|afi| AddPathTuple {
                afi,
                safi: 1,
                send_receive: 3,
            })
            .collect();
        let mut open = open_with_caps(0);
        open.capabilities = vec![Capability::AddPath(tuples.clone())];
        let BgpMessage::Open(back) = roundtrip(BgpMessage::Open(open)) else {
            panic!("not an OPEN")
        };
        let got: Vec<_> = back
            .capabilities
            .into_iter()
            .flat_map(|c| match c {
                Capability::AddPath(t) => t,
                _ => vec![],
            })
            .collect();
        assert_eq!(got, tuples);
    }

    #[test]
    fn small_open_keeps_one_byte_length() {
        assert_ne!(encode_open(&open_with_caps(2))[9], 255);
    }

    #[test]
    fn parses_peer_extended_open_with_unknown_param() {
        let mut body = vec![4, 0xfd, 0xe9, 0, 90, 1, 1, 1, 1, 255, 255];
        // unknown param (type 9, 2-byte len 1) then Capabilities (Route Refresh)
        let params = [
            9,
            0,
            1,
            0xaa,
            OPT_PARAM_CAPABILITIES,
            0,
            2,
            CAP_ROUTE_REFRESH,
            0,
        ];
        body.extend_from_slice(&u16::try_from(params.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&params);
        assert_eq!(
            parse_open(&body).unwrap().capabilities,
            [Capability::RouteRefresh]
        );
    }

    fn as_path_update(as_path: Vec<u32>) -> UpdateMessage {
        UpdateMessage {
            withdrawn_routes: vec![],
            withdrawn_path_ids: vec![],
            nlri: vec!["10.0.0.0/8".parse().unwrap()],
            nlri_path_ids: vec![],
            attributes: Some(PathAttributes {
                origin: Origin::Igp,
                as_path: as_path.into(),
                next_hop: Ipv4Addr::new(192, 0, 2, 1),
                local_pref: None,
                med: None,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
                otc: None,
                cluster_list: vec![],
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                ipv6_extended_communities: Vec::new(),
                pmsi: None,
            }),
            mp_reach: vec![],
            mp_unreach: vec![],
            ..Default::default()
        }
    }

    fn unhandled(message_type: u8, body_len: usize) -> BgpMessage {
        BgpMessage::Unhandled {
            message_type,
            body: Bytes::from(vec![0u8; body_len]),
        }
    }

    fn encoded(msg: BgpMessage) -> Vec<u8> {
        let mut buf = BytesMut::new();
        BgpCodec::default().encode(msg, &mut buf).unwrap();
        buf.to_vec()
    }

    fn decoded(bytes: &[u8]) -> BgpMessage {
        let mut buf = BytesMut::from(bytes);
        BgpCodec::default().decode(&mut buf).unwrap().unwrap()
    }

    fn open_with_cap_bytes(cap: &[u8]) -> Vec<u8> {
        let mut body = vec![4, 0xfd, 0xe9, 0, 90, 1, 1, 1, 1];
        body.push(u8::try_from(cap.len() + 2).unwrap());
        body.push(OPT_PARAM_CAPABILITIES);
        body.push(u8::try_from(cap.len()).unwrap());
        body.extend_from_slice(cap);
        let mut msg = MARKER.to_vec();
        msg.extend_from_slice(
            &u16::try_from(HEADER_LEN + body.len())
                .unwrap()
                .to_be_bytes(),
        );
        msg.push(TYPE_OPEN);
        msg.extend_from_slice(&body);
        msg
    }

    /// RFC 4724 §3 / RFC 8538 §2: R=0, N=1, 120s, IPv4 unicast with F=1.
    #[test]
    fn graceful_restart_capability_wire_format() {
        let gr = GracefulRestartCap {
            restart: false,
            notification: true,
            time: 120,
            families: vec![GrFamily {
                afi: AFI_IPV4,
                safi: 1,
                forwarding: true,
            }],
        };
        let open = OpenMessage {
            capabilities: vec![Capability::GracefulRestart(gr.clone())],
            ..build_open(65001, Ipv4Addr::new(1, 1, 1, 1), 90)
        };
        let wire = encoded(BgpMessage::Open(open.clone()));
        assert!(wire.ends_with(&[0x40, 0x06, 0x40, 0x78, 0x00, 0x01, 0x01, 0x80]));
        assert_eq!(decoded(&wire), BgpMessage::Open(open));

        // R set, no tuples (receiving-speaker only), the 12-bit time.
        let BgpMessage::Open(o) = decoded(&open_with_cap_bytes(&[64, 2, 0x8F, 0xFF])) else {
            panic!("expected OPEN");
        };
        let gr = graceful_restart(&o).unwrap();
        assert!(gr.restart && !gr.notification);
        assert_eq!((gr.time, gr.families.len()), (4095, 0));

        // A bad length is skipped; of two, the last counts.
        let BgpMessage::Open(o) = decoded(&open_with_cap_bytes(&[
            64, 3, 0, 1, 2, 64, 2, 0, 30, 64, 6, 0, 60, 0, 2, 1, 0,
        ])) else {
            panic!("expected OPEN");
        };
        assert_eq!(o.capabilities.len(), 2);
        let gr = graceful_restart(&o).unwrap();
        assert_eq!(gr.time, 60);
        assert!(!gr.families[0].forwarding);
    }

    /// RFC 4724 §2: IPv4 unicast's End-of-RIB is the 23-byte empty UPDATE;
    /// any other family's an UPDATE with only an empty `MP_UNREACH_NLRI`,
    /// accepted in the extended-length form too.
    #[test]
    fn end_of_rib_wire_format() {
        let v4 = encoded(BgpMessage::EndOfRib {
            afi: AFI_IPV4,
            safi: 1,
        });
        assert_eq!(v4.len(), 23);
        assert_eq!(v4[HEADER_LEN..], [0, 0, 0, 0]);
        let v6 = encoded(BgpMessage::EndOfRib {
            afi: AFI_IPV6,
            safi: 1,
        });
        assert_eq!(v6.len(), 29);
        assert_eq!(v6[HEADER_LEN..], [0, 0, 0, 6, 0x80, 0x0F, 3, 0, 2, 1]);
        let evpn = encoded(BgpMessage::EndOfRib {
            afi: AFI_L2VPN,
            safi: SAFI_EVPN,
        });
        assert_eq!(evpn[HEADER_LEN + 7..], [0, 0x19, 0x46]);
        for wire in [&v4, &v6, &evpn] {
            assert!(matches!(decoded(wire), BgpMessage::EndOfRib { .. }));
        }
        assert_eq!(
            end_of_rib(&[0, 0, 0, 7, 0x90, 0x0F, 0, 3, 0, 2, 1]),
            Some((2, 1))
        );
        // An empty MP_UNREACH is an EoR; one withdrawing a prefix is not.
        assert_eq!(end_of_rib(&[0, 0, 0, 7, 0x80, 0x0F, 4, 0, 2, 1, 0]), None);
    }

    /// An UPDATE carrying attributes but no NLRI parses to an empty
    /// `UpdateMessage` — it must not read as IPv4's End-of-RIB, which would
    /// purge a restarting peer's stale routes.
    #[test]
    fn attribute_only_update_is_not_end_of_rib() {
        let body = [0, 0, 0, 4, 0x40, ATTR_ORIGIN, 1, 0];
        assert_eq!(end_of_rib(&body), None);
        let mut msg = MARKER.to_vec();
        msg.extend_from_slice(
            &u16::try_from(HEADER_LEN + body.len())
                .unwrap()
                .to_be_bytes(),
        );
        msg.push(TYPE_UPDATE);
        msg.extend_from_slice(&body);
        assert!(matches!(decoded(&msg), BgpMessage::Update(_)));
    }

    /// RFC 8538 §3: a Hard Reset's data is the whole Cease it wraps.
    #[test]
    fn hard_reset_wraps_the_inner_cease() {
        let data = encode_hard_reset(
            CeaseSubcode::AdministrativeShutdown as u8,
            &encode_shutdown_message("bye"),
        );
        assert_eq!(data[..], [6, 2, 3, b'b', b'y', b'e']);
        assert_eq!(decode_shutdown_message(&data[2..]).as_deref(), Some("bye"));
    }

    #[test]
    fn extended_message_capability_roundtrips() {
        let mut open = build_open(65001, Ipv4Addr::new(1, 1, 1, 1), 90);
        open.capabilities.push(Capability::ExtendedMessage);
        let BgpMessage::Open(back) = roundtrip(BgpMessage::Open(open)) else {
            panic!("expected OPEN");
        };
        assert!(back.capabilities.contains(&Capability::ExtendedMessage));
    }

    #[test]
    fn message_length_limit_follows_extended_negotiation() {
        // 5000 bytes: over 4096, under 65535.
        let mut plain = BgpCodec::default();
        assert!(plain
            .encode(unhandled(99, 5000), &mut BytesMut::new())
            .is_err());

        let mut ext = BgpCodec {
            extended: true,
            ..BgpCodec::default()
        };
        let mut buf = BytesMut::new();
        ext.encode(unhandled(99, 5000), &mut buf).unwrap();
        // A non-extended decoder refuses it, an extended one accepts it.
        assert!(matches!(
            BgpCodec::default().decode(&mut buf.clone()),
            Err(WireError::BadLength(_))
        ));
        assert!(matches!(
            ext.decode(&mut buf),
            Ok(Some(BgpMessage::Unhandled { .. }))
        ));
        // Never more than 65535, negotiated or not.
        assert!(ext
            .encode(unhandled(99, 65535), &mut BytesMut::new())
            .is_err());
        // OPEN and KEEPALIVE stay at 4096 even when negotiated.
        assert!(ext
            .encode(unhandled(TYPE_OPEN, 5000), &mut BytesMut::new())
            .is_err());
        assert!(ext
            .encode(unhandled(TYPE_KEEPALIVE, 5000), &mut BytesMut::new())
            .is_err());
    }

    fn decode_all(codec: &mut BgpCodec, buf: &mut BytesMut) -> Vec<BgpMessage> {
        let mut out = vec![];
        while let Some(m) = codec.decode(buf).unwrap() {
            out.push(m);
        }
        out
    }

    fn many_prefixes(n: u32) -> Vec<Ipv4Net> {
        (0..n)
            .map(|i| Ipv4Net::new(Ipv4Addr::from(0x0a00_0000 + (i << 8)), 24).unwrap())
            .collect()
    }

    #[test]
    fn oversize_update_is_split_to_the_session_limit() {
        let mut update = as_path_update(vec![65001]);
        update.nlri = many_prefixes(3000); // ~12 KB of NLRI
        update.withdrawn_routes = many_prefixes(10);

        let mut codec = BgpCodec::default();
        let mut buf = BytesMut::new();
        codec
            .encode(BgpMessage::Update(update.clone()), &mut buf)
            .unwrap();
        let msgs = decode_all(&mut codec, &mut buf);
        assert!(msgs.len() >= 3);
        let (mut nlri, mut withdrawn) = (0, 0);
        for m in &msgs {
            let BgpMessage::Update(u) = m else { panic!() };
            nlri += u.nlri.len();
            withdrawn += u.withdrawn_routes.len();
            if !u.nlri.is_empty() {
                assert!(u.attributes.is_some());
            }
        }
        assert_eq!((nlri, withdrawn), (3000, 10));

        // Negotiated: the same UPDATE fits in one message.
        let mut ext = BgpCodec {
            extended: true,
            ..BgpCodec::default()
        };
        let mut buf = BytesMut::new();
        ext.encode(BgpMessage::Update(update), &mut buf).unwrap();
        assert_eq!(decode_all(&mut ext, &mut buf).len(), 1);
    }

    #[test]
    fn oversize_mp_update_splits_and_unsplittable_update_errors() {
        let mut update = as_path_update(vec![65001]);
        update.nlri = vec![];
        update.mp_unreach = vec![MpUnreachNlri {
            afi: 2,
            safi: 1,
            withdrawn: (0..1000u128)
                .map(|i| IpNet::V6(ipnet::Ipv6Net::new(Ipv6Addr::from(i << 70), 64).unwrap()))
                .collect(),
            withdrawn_path_ids: vec![],
            evpn: vec![],
            flowspec: Vec::new(),
            vpn: Vec::new(),
            rtc: Vec::new(),
        }];
        let mut codec = BgpCodec::default();
        let mut buf = BytesMut::new();
        codec.encode(BgpMessage::Update(update), &mut buf).unwrap();
        let total: usize = decode_all(&mut codec, &mut buf)
            .iter()
            .map(|m| match m {
                BgpMessage::Update(u) => u.mp_unreach.iter().map(|m| m.withdrawn.len()).sum(),
                _ => 0,
            })
            .sum();
        assert_eq!(total, 1000);

        // One prefix but a >4096-byte AS_PATH: nothing to split.
        let huge = as_path_update((1..=2000).collect());
        assert!(BgpCodec::default()
            .encode(BgpMessage::Update(huge), &mut BytesMut::new())
            .is_err());
    }

    fn two_octet_codec() -> BgpCodec {
        BgpCodec {
            two_octet_as: true,
            ..BgpCodec::default()
        }
    }

    /// Path attribute type codes in `update`'s wire encoding.
    fn attr_types(update: &UpdateMessage, two_octet_as: bool) -> Vec<u8> {
        let mut data = &encode_attributes(update, two_octet_as)[..];
        let mut types = vec![];
        while !data.is_empty() {
            types.push(data[1]);
            let (len, hdr) = if data[0] & ATTR_FLAG_EXTENDED_LENGTH != 0 {
                (usize::from(u16::from_be_bytes([data[2], data[3]])), 4)
            } else {
                (usize::from(data[2]), 3)
            };
            data = &data[hdr + len..];
        }
        types
    }

    #[test]
    fn two_octet_peer_gets_as_trans_and_as4_path_and_roundtrips() {
        let update = as_path_update(vec![65001, 4_200_000_000, 65002]);
        assert_eq!(
            encode_as_path(&update.attributes.as_ref().unwrap().as_path, true),
            [2, 3, 0xFD, 0xE9, 0x5B, 0xA0, 0xFD, 0xEA]
        );
        assert!(attr_types(&update, true).contains(&ATTR_AS4_PATH));

        let mut codec = two_octet_codec();
        let mut buf = BytesMut::new();
        codec
            .encode(BgpMessage::Update(update.clone()), &mut buf)
            .unwrap();
        assert_eq!(
            codec.decode(&mut buf).unwrap().unwrap(),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn as_zero_in_as_path_is_malformed() {
        assert!(parse_as_path(&[2, 2, 0xFD, 0xE9, 0, 0], 2).is_err());
        assert!(parse_as_path(&[2, 1, 0, 0, 0, 0], 4).is_err());
        assert!(parse_as_path(&[2, 1, 0, 0, 0xFD, 0xE9], 4).is_ok());
    }

    #[test]
    fn two_octet_peer_with_only_small_asns_gets_no_as4_path() {
        let update = as_path_update(vec![65001, 65002]);
        assert!(!attr_types(&update, true).contains(&ATTR_AS4_PATH));
        // A 4-octet peer never gets one either.
        let big = as_path_update(vec![65001, 4_200_000_000]);
        assert!(!attr_types(&big, false).contains(&ATTR_AS4_PATH));
    }

    #[test]
    fn atomic_aggregate_and_aggregator_roundtrip_and_use_as4_aggregator_for_two_octet() {
        let mut update = as_path_update(vec![65001]);
        let agg = Aggregator {
            asn: 4_200_000_001,
            router_id: Ipv4Addr::new(192, 0, 2, 9),
        };
        {
            let a = update.attributes.as_mut().unwrap();
            a.atomic_aggregate = true;
            a.aggregator = Some(agg);
        }
        // Four-octet session: 8-byte AGGREGATOR, no AS4_AGGREGATOR.
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update.clone())
        );
        let types = attr_types(&update, false);
        assert!(types.contains(&ATTR_ATOMIC_AGGREGATE) && !types.contains(&ATTR_AS4_AGGREGATOR));
        // Two-octet session: AS_TRANS + AS4_AGGREGATOR, merged back on receipt.
        assert!(attr_types(&update, true).contains(&ATTR_AS4_AGGREGATOR));
        let mut codec = two_octet_codec();
        let mut buf = BytesMut::new();
        codec
            .encode(BgpMessage::Update(update.clone()), &mut buf)
            .unwrap();
        assert_eq!(
            codec.decode(&mut buf).unwrap().unwrap(),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn otc_roundtrips_and_bad_length_is_treat_as_withdraw() {
        let mut update = as_path_update(vec![65001]);
        update.attributes.as_mut().unwrap().otc = Some(65010);
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update.clone())
        );
        assert!(attr_types(&update, false).contains(&ATTR_OTC));
        update.attributes.as_mut().unwrap().otc = None;
        assert!(!attr_types(&update, false).contains(&ATTR_OTC));
        for len in [3usize, 5] {
            let mut attrs = Vec::new();
            encode_attribute(&mut attrs, 0x40, ATTR_ORIGIN, &[0]);
            encode_attribute(&mut attrs, 0x40, ATTR_AS_PATH, &[]);
            encode_attribute(&mut attrs, 0x40, ATTR_NEXT_HOP, &[192, 0, 2, 1]);
            encode_attribute(&mut attrs, 0xC0, ATTR_OTC, &vec![0; len]);
            let p = parse_path_attributes(&attrs, &HashSet::new(), false).unwrap();
            assert!(p.withdraw, "otc length {len}");
        }
    }

    #[test]
    fn ipv6_extended_communities_roundtrip_and_bad_length_is_treat_as_withdraw() {
        let mut update = as_path_update(vec![65001]);
        let mut c = [0u8; 20];
        c[1] = 0x0d;
        c[19] = 7;
        update
            .attributes
            .as_mut()
            .unwrap()
            .ipv6_extended_communities = vec![c, [1; 20]];
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update.clone())
        );
        assert!(attr_types(&update, false).contains(&ATTR_IPV6_EXTENDED_COMMUNITIES));
        update
            .attributes
            .as_mut()
            .unwrap()
            .ipv6_extended_communities = Vec::new();
        assert!(!attr_types(&update, false).contains(&ATTR_IPV6_EXTENDED_COMMUNITIES));
        for len in [19usize, 21] {
            let mut attrs = Vec::new();
            encode_attribute(&mut attrs, 0x40, ATTR_ORIGIN, &[0]);
            encode_attribute(&mut attrs, 0x40, ATTR_AS_PATH, &[]);
            encode_attribute(&mut attrs, 0x40, ATTR_NEXT_HOP, &[192, 0, 2, 1]);
            encode_attribute(
                &mut attrs,
                0xC0,
                ATTR_IPV6_EXTENDED_COMMUNITIES,
                &vec![0; len],
            );
            let p = parse_path_attributes(&attrs, &HashSet::new(), false).unwrap();
            assert!(p.withdraw, "length {len}");
        }
    }

    /// RFC 7606 section 3(d): a Flowspec announcement missing a mandatory
    /// attribute becomes a withdrawal of its rules.
    #[test]
    fn a_flowspec_announcement_without_origin_is_treat_as_withdraw() {
        let mut attrs = Vec::new();
        encode_attribute(&mut attrs, 0x40, ATTR_AS_PATH, &[]);
        let mut reach = Vec::new();
        encode_attribute(
            &mut reach,
            0x80,
            ATTR_MP_REACH_NLRI,
            &encode_mp_reach(&MpReachNlri {
                afi: AFI_IPV4,
                safi: SAFI_FLOWSPEC,
                next_hop: Ipv4Addr::UNSPECIFIED.into(),
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn: vec![],
                flowspec: flow_rules(flowspec::Afi::V4),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }),
        );
        attrs.extend(reach);
        let mut body = vec![0, 0];
        body.extend(u16::try_from(attrs.len()).unwrap().to_be_bytes());
        body.extend(attrs);
        let u = parse_update(&body, &HashSet::new(), false).unwrap();
        assert!(u.attributes.is_none() && u.mp_reach.is_empty());
        assert_eq!(u.mp_unreach[0].flowspec, flow_rules(flowspec::Afi::V4));
    }

    #[test]
    fn malformed_aggregate_attributes_are_discarded_not_withdrawn() {
        let mut attrs = Vec::new();
        encode_attribute(&mut attrs, 0x40, ATTR_ORIGIN, &[0]);
        encode_attribute(&mut attrs, 0x40, ATTR_AS_PATH, &[]);
        encode_attribute(&mut attrs, 0x40, ATTR_NEXT_HOP, &[192, 0, 2, 1]);
        encode_attribute(&mut attrs, 0x40, ATTR_ATOMIC_AGGREGATE, &[1]);
        encode_attribute(&mut attrs, 0xC0, ATTR_AGGREGATOR, &[0, 1, 2]);
        let p = parse_path_attributes(&attrs, &HashSet::new(), false).unwrap();
        assert!(!p.withdraw && !p.atomic_aggregate && p.aggregator.is_none());
    }

    #[test]
    fn as4_path_merges_per_rfc6793_only_when_two_octet() {
        // AS_PATH 65001 23456 65003 + AS4_PATH (real) 4200000000 65003:
        // the trailing 2 entries are replaced, the leading one kept.
        let mut attrs = Vec::new();
        encode_attribute(&mut attrs, 0x40, ATTR_ORIGIN, &[0]);
        encode_attribute(
            &mut attrs,
            0x40,
            ATTR_AS_PATH,
            &[2, 3, 0xFD, 0xE9, 0x5B, 0xA0, 0xFD, 0xEB],
        );
        encode_attribute(&mut attrs, 0x40, ATTR_NEXT_HOP, &[192, 0, 2, 1]);
        encode_attribute(
            &mut attrs,
            0xC0,
            ATTR_AS4_PATH,
            &encode_as_path(&vec![4_200_000_000, 65003].into(), false),
        );
        let merged = parse_path_attributes(&attrs, &HashSet::new(), true).unwrap();
        assert_eq!(
            merged.as_path,
            Some(vec![65001, 4_200_000_000, 65003].into())
        );

        // A longer AS4_PATH is ignored, leaving the 2-byte path as sent.
        let mut long = Vec::new();
        encode_attribute(&mut long, 0x40, ATTR_AS_PATH, &[2, 1, 0xFD, 0xE9]);
        encode_attribute(
            &mut long,
            0xC0,
            ATTR_AS4_PATH,
            &encode_as_path(&vec![1, 2].into(), false),
        );
        let ignored = parse_path_attributes(&long, &HashSet::new(), true).unwrap();
        assert_eq!(ignored.as_path, Some(vec![65001].into()));
    }

    fn with_as_path(as_path: &[u8], as4_path: Option<&[u8]>) -> Vec<u8> {
        let mut attrs = Vec::new();
        encode_attribute(&mut attrs, 0x40, ATTR_ORIGIN, &[0]);
        encode_attribute(&mut attrs, 0x40, ATTR_AS_PATH, as_path);
        encode_attribute(&mut attrs, 0x40, ATTR_NEXT_HOP, &[192, 0, 2, 1]);
        if let Some(v) = as4_path {
            encode_attribute(&mut attrs, 0xC0, ATTR_AS4_PATH, v);
        }
        attrs
    }

    #[test]
    fn mixed_segment_path_roundtrips_with_its_types() {
        let mut path = AsPath::default();
        path.push_segment(SegKind::ConfedSequence, &[65101, 65102]);
        path.push_segment(SegKind::Sequence, &[65003]);
        path.push_segment(SegKind::Set, &[1, 2]);
        let wire = encode_as_path(&path, false);
        assert_eq!(&wire[..2], [3, 2]);
        assert_eq!(parse_as_path(&wire, 4).unwrap(), path);
    }

    #[test]
    fn unknown_or_empty_as_path_segment_is_treat_as_withdraw() {
        for bad in [&[0u8, 1, 0xFD, 0xE9][..], &[5, 1, 0xFD, 0xE9], &[2, 0]] {
            let p = parse_path_attributes(&with_as_path(bad, None), &HashSet::new(), true).unwrap();
            assert!(p.withdraw, "{bad:?}");
        }
    }

    #[test]
    fn bad_as4_path_is_discarded_not_withdrawn() {
        // RFC 7606 §7.11: malformed (truncated), or carrying a confed segment.
        let as_path = [2, 2, 0xFD, 0xE9, 0x5B, 0xA0];
        for as4 in [&[2u8, 1, 0, 0][..], &[3, 1, 0, 0, 0xFD, 0xEA]] {
            let p =
                parse_path_attributes(&with_as_path(&as_path, Some(as4)), &HashSet::new(), true)
                    .unwrap();
            assert!(!p.withdraw);
            assert_eq!(p.as_path, Some(vec![65001, 23456].into()));
        }
    }

    #[test]
    fn as4_merge_keeps_a_leading_confed_segment() {
        // (65101) 65001 23456 + AS4_PATH 4200000000.
        let as_path = [3, 1, 0xFE, 0x4D, 2, 2, 0xFD, 0xE9, 0x5B, 0xA0];
        let as4 = encode_as_path(&vec![4_200_000_000].into(), false);
        let p = parse_path_attributes(&with_as_path(&as_path, Some(&as4)), &HashSet::new(), true)
            .unwrap();
        assert_eq!(
            format!("{:?}", p.as_path.unwrap()),
            "[(65101), 65001, 4200000000]"
        );
    }

    #[test]
    fn as4_path_toward_a_two_octet_peer_has_no_confed_segment() {
        let mut path = AsPath::from(vec![4_200_000_000]);
        path.prepend_confed_seq(65101);
        let mut update = as_path_update(vec![]);
        update.attributes.as_mut().unwrap().as_path = path;
        let mut codec = two_octet_codec();
        let mut buf = BytesMut::new();
        codec
            .encode(BgpMessage::Update(update.clone()), &mut buf)
            .unwrap();
        // An AS4_PATH with the confed segment would be discarded on receipt,
        // leaving AS_TRANS; the merged path coming back whole proves it had none.
        assert_eq!(
            codec.decode(&mut buf).unwrap().unwrap(),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn keepalive_roundtrips() {
        assert_eq!(roundtrip(BgpMessage::Keepalive), BgpMessage::Keepalive);
    }

    #[test]
    fn open_without_capability_roundtrips() {
        let open = OpenMessage {
            version: BGP_VERSION,
            my_as: 65001,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(1, 1, 1, 1),
            capabilities: vec![],
        };
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn open_with_four_octet_capability_roundtrips() {
        let open = build_open(4_200_000_000, Ipv4Addr::new(2, 2, 2, 2), 90);
        assert_eq!(open.my_as, AS_TRANS);
        assert_eq!(four_octet_asn(&open), Some(4_200_000_000));
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn open_with_multiprotocol_and_extended_next_hop_capabilities_roundtrips() {
        let mut open = build_open(65001, Ipv4Addr::new(3, 3, 3, 3), 90);
        open.capabilities.push(Capability::MultiProtocol {
            afi: AFI_IPV6,
            safi: 1,
        });
        open.capabilities.push(Capability::ExtendedNextHop {
            nlri_afi: AFI_IPV4,
            nlri_safi: 1,
            nh_afi: AFI_IPV6,
        });
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn open_with_evpn_capability_roundtrips() {
        let mut open = build_open(65001, Ipv4Addr::new(3, 3, 3, 3), 90);
        open.capabilities.push(Capability::MultiProtocol {
            afi: AFI_L2VPN,
            safi: SAFI_EVPN,
        });
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn build_open_uses_as_trans_boundary_correctly() {
        assert_eq!(build_open(65535, Ipv4Addr::LOCALHOST, 90).my_as, 65535);
        assert_eq!(build_open(65536, Ipv4Addr::LOCALHOST, 90).my_as, AS_TRANS);
        // Always advertised once 4-octet-capable, even when `my_as` didn't need AS_TRANS.
        assert_eq!(
            four_octet_asn(&build_open(65535, Ipv4Addr::LOCALHOST, 90)),
            Some(65535)
        );
    }

    #[test]
    fn effective_remote_asn_prefers_capability_over_plain_field() {
        let with_cap = OpenMessage {
            version: BGP_VERSION,
            my_as: AS_TRANS,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::LOCALHOST,
            capabilities: vec![Capability::FourOctetAsn(4_200_000_000)],
        };
        assert_eq!(effective_remote_asn(&with_cap), 4_200_000_000);

        let without_cap = OpenMessage {
            capabilities: vec![],
            ..with_cap
        };
        assert_eq!(effective_remote_asn(&without_cap), u32::from(AS_TRANS));
    }

    #[test]
    fn notification_roundtrips() {
        let n = NotificationMessage {
            error_code: 6,
            error_subcode: 7,
            data: Bytes::new(),
        };
        assert_eq!(
            roundtrip(BgpMessage::Notification(n.clone())),
            BgpMessage::Notification(n)
        );
    }

    #[test]
    fn route_refresh_roundtrips() {
        let rr = RouteRefreshMessage {
            subtype: REFRESH_BORR,
            afi: AFI_IPV6,
            safi: 1,
        };
        assert_eq!(
            roundtrip(BgpMessage::RouteRefresh(rr)),
            BgpMessage::RouteRefresh(rr)
        );
    }

    #[test]
    fn route_refresh_truncated_body_is_malformed() {
        let body = vec![0u8, 1u8, 0u8]; // 3 bytes, needs 4
        assert!(matches!(
            parse_route_refresh(&body),
            Err(WireError::MalformedRouteRefresh)
        ));
    }

    #[test]
    fn open_with_route_refresh_capability_roundtrips() {
        let mut open = build_open(65001, Ipv4Addr::new(4, 4, 4, 4), 90);
        open.capabilities.push(Capability::RouteRefresh);
        assert_eq!(
            roundtrip(BgpMessage::Open(open.clone())),
            BgpMessage::Open(open)
        );
    }

    #[test]
    fn unknown_type_decodes_as_unhandled() {
        match roundtrip(BgpMessage::Unhandled {
            message_type: 200, // not a type this crate understands
            body: Bytes::from_static(b"not parsed"),
        }) {
            BgpMessage::Unhandled { message_type, body } => {
                assert_eq!(message_type, 200);
                assert_eq!(&body[..], b"not parsed");
            }
            other => panic!("expected Unhandled, got {other:?}"),
        }
    }

    fn attrs(as_path: Vec<u32>, local_pref: Option<u32>) -> PathAttributes {
        PathAttributes {
            origin: Origin::Igp,
            as_path: as_path.into(),
            next_hop: Ipv4Addr::new(10, 0, 0, 1),
            local_pref,
            med: None,
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            cluster_list: vec![],
            communities: vec![],
            extended_communities: vec![],
            large_communities: vec![],
            ipv6_extended_communities: Vec::new(),
            pmsi: None,
        }
    }

    fn empty_update() -> UpdateMessage {
        UpdateMessage {
            withdrawn_routes: vec![],
            withdrawn_path_ids: vec![],
            nlri: vec![],
            nlri_path_ids: vec![],
            attributes: None,
            mp_reach: vec![],
            mp_unreach: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn update_announce_roundtrips() {
        let update = UpdateMessage {
            nlri: vec![
                "10.1.0.0/24".parse().unwrap(),
                "10.2.0.0/16".parse().unwrap(),
            ],
            attributes: Some(attrs(vec![65001, 65002], Some(200))),
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn update_with_communities_roundtrips() {
        let update = UpdateMessage {
            nlri: vec!["10.1.0.0/24".parse().unwrap()],
            attributes: Some(PathAttributes {
                communities: vec![(65000 << 16) | 100, 0xFFFF_FF01],
                extended_communities: vec![(0u64 << 56) | (2u64 << 48) | 100],
                large_communities: vec![(65000, 1, 1)],
                ipv6_extended_communities: Vec::new(),
                pmsi: None,
                ..attrs(vec![65001], Some(200))
            }),
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn update_withdraw_only_roundtrips_with_no_attributes() {
        let update = UpdateMessage {
            withdrawn_routes: vec!["10.1.0.0/24".parse().unwrap(), "0.0.0.0/0".parse().unwrap()],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn update_mixed_withdraw_and_announce_roundtrips() {
        let update = UpdateMessage {
            withdrawn_routes: vec!["192.168.1.0/24".parse().unwrap()],
            nlri: vec!["172.16.0.0/12".parse().unwrap()],
            attributes: Some(attrs(vec![], None)),
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn update_as_path_longer_than_one_segment_roundtrips() {
        let long_path: Vec<u32> = (1..=300).collect();
        let update = UpdateMessage {
            nlri: vec!["10.0.0.0/8".parse().unwrap()],
            attributes: Some(attrs(long_path, None)),
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn mp_reach_ipv6_announce_roundtrips() {
        // MP-only announcement (no legacy nlri): the legacy NEXT_HOP
        // attribute is never encoded, so it must round-trip as
        // UNSPECIFIED rather than whatever placeholder was passed in.
        let update = UpdateMessage {
            attributes: Some(PathAttributes {
                next_hop: Ipv4Addr::UNSPECIFIED,
                ..attrs(vec![65001], Some(150))
            }),
            mp_reach: vec![MpReachNlri {
                afi: AFI_IPV6,
                safi: 1,
                next_hop: "2001:db8::1".parse().unwrap(),
                nlri: vec!["2001:db8:1::/48".parse().unwrap(), "::/0".parse().unwrap()],
                nlri_path_ids: vec![],
                evpn: vec![],
                flowspec: Vec::new(),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn mp_reach_accepts_global_plus_link_local_next_hop() {
        // RFC 2545 §3: next-hop length 32 = global then link-local.
        let mut v = vec![0, 2, 1, 32];
        v.extend("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        v.extend("fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        v.extend([0, 48, 0x20, 0x01, 0x0d, 0xb8, 0, 1]); // 0 SNPAs, 2001:db8:1::/48
        let mp = decode_mp_reach(&v, &HashSet::new()).unwrap();
        assert_eq!(mp.next_hop, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(mp.nlri, vec!["2001:db8:1::/48".parse().unwrap()]);
    }

    #[test]
    fn mp_unreach_ipv6_withdraw_roundtrips() {
        let update = UpdateMessage {
            mp_unreach: vec![MpUnreachNlri {
                afi: AFI_IPV6,
                safi: 1,
                withdrawn: vec!["2001:db8:1::/48".parse().unwrap()],
                withdrawn_path_ids: vec![],
                evpn: vec![],
                flowspec: Vec::new(),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    fn evpn_routes() -> Vec<EvpnNlri> {
        let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];
        vec![
            EvpnNlri::MacIp {
                rd,
                esi: [0; 10],
                tag: 0,
                mac: [0xaa, 0xbb, 0xcc, 0, 0, 1],
                ip: Some("10.0.0.5".parse().unwrap()),
                labels: vec![10_000],
            },
            EvpnNlri::InclusiveMulticast {
                rd,
                tag: 0,
                origin: "192.0.2.1".parse().unwrap(),
            },
        ]
    }

    #[test]
    fn mp_reach_evpn_roundtrips_with_extended_communities() {
        // RT 65000:10000 (0x0002 type/subtype, 2-byte AS, 4-byte value).
        let rt = 0x0002_fde8_0000_2710_u64;
        let update = UpdateMessage {
            attributes: Some(PathAttributes {
                next_hop: Ipv4Addr::UNSPECIFIED,
                extended_communities: vec![rt],
                ..attrs(vec![65001], Some(100))
            }),
            mp_reach: vec![MpReachNlri {
                afi: AFI_L2VPN,
                safi: SAFI_EVPN,
                next_hop: "192.0.2.1".parse().unwrap(),
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn: evpn_routes(),
                flowspec: Vec::new(),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn mp_unreach_evpn_roundtrips() {
        let update = UpdateMessage {
            mp_unreach: vec![MpUnreachNlri {
                afi: AFI_L2VPN,
                safi: SAFI_EVPN,
                withdrawn: vec![],
                withdrawn_path_ids: vec![],
                evpn: evpn_routes(),
                flowspec: Vec::new(),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn mp_reach_l2vpn_with_other_safi_is_malformed() {
        // Only SAFI 70 is understood for AFI 25; anything else must not be
        // misread as a prefix list.
        let mut wire = Vec::new();
        wire.extend_from_slice(&AFI_L2VPN.to_be_bytes());
        wire.extend_from_slice(&[99, 4, 192, 0, 2, 1, 0]);
        assert!(decode_mp_reach(&wire, &HashSet::new()).is_err());
        // SAFI 128 is only AFI 1/2.
        wire[2] = 128;
        wire.splice(3..4, [12]);
        assert!(decode_mp_reach(&wire, &HashSet::new()).is_err());
    }

    /// `dst 192.0.2.0/24` (v4) and `dst 2001:db8::/32` (v6), RFC 8955 wire form.
    fn flow_rules(afi: flowspec::Afi) -> Vec<FlowSpec> {
        let wire: &[&[u8]] = match afi {
            flowspec::Afi::V4 => &[
                &[5, 1, 24, 192, 0, 2],
                &[11, 1, 24, 198, 51, 100, 3, 0x81, 6, 5, 0x81, 25],
            ],
            flowspec::Afi::V6 => &[&[7, 1, 32, 0, 0x20, 0x01, 0x0d, 0xb8]],
        };
        wire.iter()
            .map(|w| FlowSpec::decode(afi, w).unwrap().0)
            .collect()
    }

    #[test]
    fn mp_reach_flowspec_roundtrips_with_an_empty_next_hop() {
        for (afi, fa) in [(flowspec::Afi::V4, AFI_IPV4), (flowspec::Afi::V6, AFI_IPV6)] {
            let update = UpdateMessage {
                attributes: Some(PathAttributes {
                    next_hop: Ipv4Addr::UNSPECIFIED,
                    // traffic-rate 0 (discard)
                    extended_communities: vec![0x8006_0000_0000_0000],
                    ..attrs(vec![65001], Some(100))
                }),
                mp_reach: vec![MpReachNlri {
                    afi: fa,
                    safi: SAFI_FLOWSPEC,
                    next_hop: if fa == AFI_IPV4 {
                        Ipv4Addr::UNSPECIFIED.into()
                    } else {
                        Ipv6Addr::UNSPECIFIED.into()
                    },
                    nlri: vec![],
                    nlri_path_ids: vec![],
                    evpn: vec![],
                    flowspec: flow_rules(afi),
                    vpn: Vec::new(),
                    rtc: Vec::new(),
                }],
                ..empty_update()
            };
            let wire = encoded(BgpMessage::Update(update.clone()));
            // MP_REACH value: AFI SAFI then next-hop length 0.
            let [hi, lo] = fa.to_be_bytes();
            let needle = [hi, lo, SAFI_FLOWSPEC, 0, 0];
            assert!(wire.windows(5).any(|w| w == needle), "next hop length 0");
            assert_eq!(decoded(&wire), BgpMessage::Update(update));
        }
    }

    #[test]
    fn an_undecodable_action_community_is_treat_as_withdraw() {
        let update = |ec: u64| UpdateMessage {
            attributes: Some(PathAttributes {
                next_hop: Ipv4Addr::UNSPECIFIED,
                extended_communities: vec![ec],
                ..attrs(vec![65001], Some(100))
            }),
            mp_reach: vec![MpReachNlri {
                afi: AFI_IPV4,
                safi: SAFI_FLOWSPEC,
                next_hop: Ipv4Addr::UNSPECIFIED.into(),
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn: vec![],
                flowspec: flow_rules(flowspec::Afi::V4),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..empty_update()
        };
        // A NaN traffic-rate (RFC 8955 section 10): the rules are withdrawn.
        let bad = u64::from_be_bytes([0x80, 0x06, 0, 0, 0x7f, 0xc0, 0, 0]);
        let BgpMessage::Update(u) = decoded(&encoded(BgpMessage::Update(update(bad)))) else {
            panic!("an UPDATE");
        };
        assert!(u.attributes.is_none() && u.mp_reach.is_empty());
        assert_eq!(u.mp_unreach[0].flowspec, flow_rules(flowspec::Afi::V4));
        // The same rules with a sane rate stay announced.
        let BgpMessage::Update(u) =
            decoded(&encoded(BgpMessage::Update(update(0x8006_0000_0000_0000))))
        else {
            panic!("an UPDATE");
        };
        assert!(u.attributes.is_some() && u.mp_unreach.is_empty());
    }

    #[test]
    fn mp_unreach_flowspec_roundtrips() {
        let update = UpdateMessage {
            mp_unreach: vec![MpUnreachNlri {
                afi: AFI_IPV4,
                safi: SAFI_FLOWSPEC,
                withdrawn: vec![],
                withdrawn_path_ids: vec![],
                evpn: vec![],
                flowspec: flow_rules(flowspec::Afi::V4),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..empty_update()
        };
        assert_eq!(
            roundtrip(BgpMessage::Update(update.clone())),
            BgpMessage::Update(update)
        );
    }

    #[test]
    fn mp_reach_flowspec_ignores_a_stated_next_hop_and_rejects_bad_nlri() {
        // A 4-octet next hop is tolerated (and ignored by the RIB).
        let mut wire = vec![0, 1, SAFI_FLOWSPEC, 4, 192, 0, 2, 1, 0, 5, 1, 24, 192, 0, 2];
        let mp = decode_mp_reach(&wire, &HashSet::new()).unwrap();
        assert_eq!(mp.flowspec.len(), 1);
        assert_eq!(mp.nlri, vec![]);
        // Truncated: the NLRI claims 5 octets, 3 follow.
        wire.truncate(wire.len() - 3);
        assert!(decode_mp_reach(&wire, &HashSet::new()).is_err());
        // Zero next-hop length stays illegal for unicast.
        let unicast = [0, 1, 1, 0, 0, 24, 192, 0, 2];
        assert!(decode_mp_reach(&unicast, &HashSet::new()).is_err());
        // A flowspec AFI other than 1/2.
        assert!(decode_mp_reach(
            &[0, 25, SAFI_FLOWSPEC, 0, 0, 5, 1, 24, 192, 0, 2],
            &HashSet::new()
        )
        .is_err());
    }

    #[test]
    fn malformed_flowspec_nlri_makes_the_update_malformed() {
        let update = UpdateMessage {
            attributes: Some(attrs(vec![65001], Some(100))),
            mp_reach: vec![MpReachNlri {
                afi: AFI_IPV4,
                safi: SAFI_FLOWSPEC,
                next_hop: Ipv4Addr::UNSPECIFIED.into(),
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn: vec![],
                flowspec: flow_rules(flowspec::Afi::V4)[..1].to_vec(),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..empty_update()
        };
        let mut wire = encoded(BgpMessage::Update(update));
        // The last NLRI is `[5, 1, 24, 192, 0, 2]`: claim 6 octets, 5 follow.
        let at = wire.len() - 6;
        assert_eq!(wire[at], 5);
        wire[at] = 6;
        let mut buf = BytesMut::from(wire.as_slice());
        assert!(BgpCodec::default().decode(&mut buf).is_err());
    }

    #[test]
    fn flowspec_end_of_rib_bytes() {
        for afi in [AFI_IPV4, AFI_IPV6] {
            let wire = encoded(BgpMessage::EndOfRib {
                afi,
                safi: SAFI_FLOWSPEC,
            });
            assert_eq!(wire[HEADER_LEN + 7..], [0, afi.to_be_bytes()[1], 133]);
            assert_eq!(
                decoded(&wire),
                BgpMessage::EndOfRib {
                    afi,
                    safi: SAFI_FLOWSPEC
                }
            );
        }
    }

    #[test]
    fn oversized_flowspec_batches_split_to_fit() {
        let rules: Vec<FlowSpec> = (0..=255u8)
            .map(|i| {
                FlowSpec::decode(flowspec::Afi::V4, &[5, 1, 24, 10, i, 0])
                    .unwrap()
                    .0
            })
            .collect();
        let update = UpdateMessage {
            attributes: Some(attrs(vec![65001], Some(100))),
            mp_reach: vec![MpReachNlri {
                afi: AFI_IPV4,
                safi: SAFI_FLOWSPEC,
                next_hop: Ipv4Addr::UNSPECIFIED.into(),
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn: vec![],
                flowspec: rules,
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..empty_update()
        };
        let mut pieces = Vec::new();
        split_update(&update, false, 400, &mut pieces).unwrap();
        assert!(pieces.len() > 1);
        assert!(pieces.iter().all(|p| p.len() <= 400));
        let mut buf = BytesMut::new();
        for p in &pieces {
            put_frame(&mut buf, TYPE_UPDATE, p);
        }
        let mut codec = BgpCodec::default();
        let mut n = 0;
        while let Some(BgpMessage::Update(u)) = codec.decode(&mut buf).unwrap() {
            n += u.mp_reach.iter().map(|m| m.flowspec.len()).sum::<usize>();
        }
        assert_eq!(n, 256);
    }

    fn vpn_routes(n: u8) -> Vec<VpnNlri> {
        (0..n)
            .map(|i| VpnNlri {
                labels: vec![1000 + u32::from(i)],
                rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
                prefix: format!("10.{i}.0.0/16").parse().unwrap(),
            })
            .collect()
    }

    fn vpn_reach(afi: u16, next_hop: IpAddr, vpn: Vec<VpnNlri>) -> MpReachNlri {
        MpReachNlri {
            afi,
            safi: SAFI_VPN,
            next_hop,
            nlri: vec![],
            nlri_path_ids: vec![],
            evpn: vec![],
            flowspec: vec![],
            rtc: vec![],
            vpn,
        }
    }

    #[test]
    fn vpn_reach_and_unreach_roundtrip_for_both_afis() {
        let v6 = |i: u8| VpnNlri {
            labels: vec![7],
            rd: [0, 1, 10, 0, 0, 1, 0, i],
            prefix: format!("2001:db8:{i}::/48").parse().unwrap(),
        };
        let withdrawn = |afi, vpn: Vec<VpnNlri>| MpUnreachNlri {
            afi,
            safi: SAFI_VPN,
            withdrawn: vec![],
            withdrawn_path_ids: vec![],
            evpn: vec![],
            flowspec: vec![],
            rtc: vec![],
            vpn: vpn
                .into_iter()
                .map(|n| VpnNlri {
                    labels: vec![],
                    ..n
                })
                .collect(),
        };
        let batches = [
            vpn_reach(AFI_IPV4, Ipv4Addr::new(192, 0, 2, 1).into(), vpn_routes(3)),
            vpn_reach(AFI_IPV6, "2001:db8::1".parse().unwrap(), vec![v6(1), v6(2)]),
            // An IPv4 PE address on an AFI 2 batch rides IPv4-mapped.
            vpn_reach(AFI_IPV6, Ipv4Addr::new(192, 0, 2, 1).into(), vec![v6(3)]),
        ];
        for reach in batches {
            let mut update = UpdateMessage {
                attributes: Some(attrs(vec![65001], Some(100))),
                mp_reach: vec![reach.clone()],
                mp_unreach: vec![withdrawn(reach.afi, reach.vpn.clone())],
                ..empty_update()
            };
            update.attributes.as_mut().unwrap().next_hop = Ipv4Addr::UNSPECIFIED;
            assert_eq!(
                roundtrip(BgpMessage::Update(update.clone())),
                BgpMessage::Update(update)
            );
        }
    }

    #[test]
    fn vpn_decode_never_consults_add_path() {
        // IPv4 and IPv6 unicast negotiated ADD-PATH: SAFI 128 still has no
        // Path Identifier, in either direction.
        let mut update = UpdateMessage {
            attributes: Some(attrs(vec![65001], Some(100))),
            mp_reach: vec![vpn_reach(
                AFI_IPV4,
                Ipv4Addr::new(192, 0, 2, 1).into(),
                vpn_routes(2),
            )],
            ..empty_update()
        };
        update.attributes.as_mut().unwrap().next_hop = Ipv4Addr::UNSPECIFIED;
        let mut codec = BgpCodec {
            add_path_afis: HashSet::from([AFI_IPV4, AFI_IPV6]),
            ..BgpCodec::default()
        };
        let mut buf = BytesMut::new();
        codec
            .encode(BgpMessage::Update(update.clone()), &mut buf)
            .unwrap();
        assert_eq!(
            codec.decode(&mut buf).unwrap().unwrap(),
            BgpMessage::Update(update)
        );
        let un = decode_mp_unreach(
            &{
                let mut b = vec![0, 1, SAFI_VPN];
                vpn::encode_vpn_unreach(&vpn_routes(1), &mut b);
                b
            },
            &HashSet::from([AFI_IPV4]),
        )
        .unwrap();
        assert_eq!((un.vpn.len(), un.withdrawn_path_ids.len()), (1, 0));
    }

    #[test]
    fn vpn_next_hop_of_a_wrong_length_or_nlri_resets() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0, 1, SAFI_VPN, 10]);
        wire.extend_from_slice(&[0; 10]);
        wire.push(0);
        assert!(decode_mp_reach(&wire, &HashSet::new()).is_err());
        // A good next hop followed by a malformed NLRI is a reset, not a
        // treat-as-withdraw (RFC 7606 section 3(j)).
        let mut good = encode_mp_reach(&vpn_reach(
            AFI_IPV4,
            Ipv4Addr::new(192, 0, 2, 1).into(),
            vpn_routes(1),
        ));
        assert!(decode_mp_reach(&good, &HashSet::new()).is_ok());
        good.push(0xff);
        assert!(decode_mp_reach(&good, &HashSet::new()).is_err());
        let mut attrs_buf = Vec::new();
        encode_attribute(&mut attrs_buf, 0x40, ATTR_ORIGIN, &[0]);
        encode_attribute(&mut attrs_buf, 0x40, ATTR_AS_PATH, &[]);
        encode_attribute(&mut attrs_buf, 0x80, ATTR_MP_REACH_NLRI, &good);
        let mut body = vec![0, 0];
        body.extend(u16::try_from(attrs_buf.len()).unwrap().to_be_bytes());
        body.extend(attrs_buf);
        assert!(parse_update(&body, &HashSet::new(), false).is_err());
    }

    #[test]
    fn a_vpn_announcement_with_a_bad_attribute_is_treat_as_withdraw() {
        let mut attrs_buf = Vec::new();
        // Bad ORIGIN (value 9) is an attribute-level error.
        encode_attribute(&mut attrs_buf, 0x40, ATTR_ORIGIN, &[9]);
        encode_attribute(&mut attrs_buf, 0x40, ATTR_AS_PATH, &[]);
        encode_attribute(
            &mut attrs_buf,
            0x80,
            ATTR_MP_REACH_NLRI,
            &encode_mp_reach(&vpn_reach(
                AFI_IPV4,
                Ipv4Addr::new(192, 0, 2, 1).into(),
                vpn_routes(2),
            )),
        );
        let mut body = vec![0, 0];
        body.extend(u16::try_from(attrs_buf.len()).unwrap().to_be_bytes());
        body.extend(attrs_buf);
        let u = parse_update(&body, &HashSet::new(), false).unwrap();
        assert!(u.attributes.is_none() && u.mp_reach.is_empty());
        assert_eq!(u.mp_unreach[0].safi, SAFI_VPN);
        let want: Vec<VpnNlri> = vpn_routes(2)
            .into_iter()
            .map(|n| VpnNlri {
                labels: vec![],
                ..n
            })
            .collect();
        assert_eq!(u.mp_unreach[0].vpn, want);
    }

    #[test]
    fn oversized_vpn_batches_split_to_fit() {
        let routes: Vec<VpnNlri> = (0..400u16)
            .map(|i| VpnNlri {
                labels: vec![u32::from(i) + 16],
                rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
                prefix: format!("10.{}.{}.0/24", i / 256, i % 256).parse().unwrap(),
            })
            .collect();
        let update = UpdateMessage {
            attributes: Some(attrs(vec![65001], Some(100))),
            mp_reach: vec![vpn_reach(
                AFI_IPV4,
                Ipv4Addr::new(192, 0, 2, 1).into(),
                routes.clone(),
            )],
            mp_unreach: vec![MpUnreachNlri {
                afi: AFI_IPV4,
                safi: SAFI_VPN,
                withdrawn: vec![],
                withdrawn_path_ids: vec![],
                evpn: vec![],
                flowspec: vec![],
                rtc: vec![],
                vpn: routes
                    .iter()
                    .map(|n| VpnNlri {
                        labels: vec![],
                        ..n.clone()
                    })
                    .collect(),
            }],
            ..empty_update()
        };
        let mut pieces = Vec::new();
        split_update(&update, false, 4096 - HEADER_LEN, &mut pieces).unwrap();
        assert!(pieces.len() > 2);
        assert!(pieces.iter().all(|p| p.len() <= 4096 - HEADER_LEN));
        let mut buf = BytesMut::new();
        for p in &pieces {
            put_frame(&mut buf, TYPE_UPDATE, p);
        }
        let mut codec = BgpCodec::default();
        let (mut reach, mut unreach) = (Vec::new(), Vec::new());
        while let Some(BgpMessage::Update(u)) = codec.decode(&mut buf).unwrap() {
            reach.extend(u.mp_reach.into_iter().flat_map(|m| m.vpn));
            unreach.extend(u.mp_unreach.into_iter().flat_map(|m| m.vpn));
        }
        assert_eq!(reach, routes);
        assert_eq!(unreach.len(), 400);
    }

    #[test]
    fn mp_reach_evpn_with_truncated_nlri_is_malformed() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&AFI_L2VPN.to_be_bytes());
        wire.extend_from_slice(&[SAFI_EVPN, 4, 192, 0, 2, 1, 0, 3, 200]);
        assert!(decode_mp_reach(&wire, &HashSet::new()).is_err());
    }

    #[test]
    fn mp_reach_cross_family_next_hop_roundtrips() {
        // RFC 8950: IPv4 unicast NLRI carried over an IPv6 next-hop.
        let update = UpdateMessage {
            attributes: Some(PathAttributes {
                next_hop: Ipv4Addr::UNSPECIFIED,
                ..attrs(vec![], None)
            }),
            mp_reach: vec![MpReachNlri {
                afi: AFI_IPV4,
                safi: 1,
                next_hop: "2001:db8::1".parse().unwrap(),
                nlri: vec!["10.0.0.0/24".parse().unwrap()],
                nlri_path_ids: vec![],
                evpn: vec![],
                flowspec: Vec::new(),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..empty_update()
        };
        let rt = roundtrip(BgpMessage::Update(update.clone()));
        assert_eq!(rt, BgpMessage::Update(update));
        // MP-only announcement never encodes the legacy NEXT_HOP attribute.
        let BgpMessage::Update(u) = rt else {
            unreachable!()
        };
        assert_eq!(u.nlri, []);
        assert_eq!(
            u.mp_reach[0].next_hop,
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn update_with_unknown_attribute_is_skipped_by_length() {
        // withdrawn_routes length = 0
        let mut body = vec![0u8, 0u8];
        // path attributes: an unknown attribute (type 99) with 3 bytes of
        // junk, followed by the three mandatory attributes.
        let mut path_attrs = Vec::new();
        path_attrs.extend_from_slice(&[0x80, 99, 3, 0xAA, 0xBB, 0xCC]);
        path_attrs.extend_from_slice(&[0x40, ATTR_ORIGIN, 1, Origin::Igp as u8]);
        path_attrs.extend_from_slice(&[0x40, ATTR_AS_PATH, 0]);
        path_attrs.extend_from_slice(&[0x40, ATTR_NEXT_HOP, 4, 10, 0, 0, 1]);
        body.extend_from_slice(&u16::try_from(path_attrs.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&path_attrs);
        // nlri: 10.0.0.0/8
        body.extend_from_slice(&[8, 10]);

        let parsed = parse_update(&body, &HashSet::new(), false).unwrap();
        assert_eq!(parsed.nlri, vec!["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(
            parsed.attributes,
            Some(PathAttributes {
                origin: Origin::Igp,
                as_path: vec![].into(),
                next_hop: Ipv4Addr::new(10, 0, 0, 1),
                local_pref: None,
                med: None,
                originator_id: None,
                atomic_aggregate: false,
                aggregator: None,
                otc: None,
                cluster_list: vec![],
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                ipv6_extended_communities: Vec::new(),
                pmsi: None,
            })
        );
    }

    #[test]
    fn update_with_nlri_but_missing_mandatory_attribute_is_treated_as_withdraw() {
        // withdrawn_routes length = 0, path attributes length = 0 (no
        // ORIGIN/AS_PATH/NEXT_HOP at all), nlri = 10.0.0.0/8.
        let mut body = vec![0u8, 0u8, 0u8, 0u8];
        body.extend_from_slice(&[8, 10]);
        let u = parse_update(&body, &HashSet::new(), false).unwrap();
        assert!(u.nlri.is_empty() && u.attributes.is_none());
        assert_eq!(u.withdrawn_routes, vec!["10.0.0.0/8".parse().unwrap()]);
    }

    /// Body: no withdrawn routes, `attrs`, then legacy NLRI 10.0.0.0/8.
    fn body_with(attrs: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8, 0u8];
        body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
        body.extend_from_slice(attrs);
        body.extend_from_slice(&[8, 10]);
        body
    }

    fn valid_attrs() -> Vec<u8> {
        let mut a = vec![0x40, ATTR_ORIGIN, 1, 0, 0x40, ATTR_AS_PATH, 0];
        a.extend_from_slice(&[0x40, ATTR_NEXT_HOP, 4, 10, 0, 0, 1]);
        a
    }

    #[test]
    fn malformed_attribute_content_is_treated_as_withdraw_not_reset() {
        let mp_reach = {
            // AFI 2, SAFI 1, nh len 16 (2001:db8::1), reserved, 2001:db8:1::/48
            let mut v = vec![0, 2, 1, 16];
            v.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
            v.extend_from_slice(&[0, 48, 0x20, 0x01, 0x0d, 0xb8, 0, 1]);
            v
        };
        for bad in [
            &[0x40, ATTR_ORIGIN, 1, 9][..],             // bad ORIGIN value
            &[0xC0, ATTR_COMMUNITY, 3, 1, 2, 3][..],    // COMMUNITY length % 4
            &[0x80, ATTR_MULTI_EXIT_DISC, 2, 0, 0][..], // MED length
            &[0x40, ATTR_AS_PATH, 4, 2, 1, 0, 0][..],   // AS_PATH truncated segment
        ] {
            // `bad` first: a later duplicate of it would be discarded (§3(g)).
            let mut attrs = bad.to_vec();
            attrs.extend_from_slice(&valid_attrs());
            attrs.extend_from_slice(&[
                0x80,
                ATTR_MP_REACH_NLRI,
                u8::try_from(mp_reach.len()).unwrap(),
            ]);
            attrs.extend_from_slice(&mp_reach);
            let u = parse_update(&body_with(&attrs), &HashSet::new(), false).unwrap();
            assert_eq!(u.withdrawn_routes, vec!["10.0.0.0/8".parse().unwrap()]);
            assert!(u.nlri.is_empty() && u.mp_reach.is_empty() && u.attributes.is_none());
            assert_eq!(u.mp_unreach.len(), 1);
            assert_eq!(
                u.mp_unreach[0].withdrawn,
                vec!["2001:db8:1::/48".parse().unwrap()]
            );
            assert_eq!(
                u.treat_as_withdraw_prefixes, 2,
                "one legacy + one MP prefix"
            );
        }
    }

    fn body_attrs(extra: &[u8]) -> Result<ParsedAttributes, WireError> {
        let mut attrs = valid_attrs();
        attrs.extend_from_slice(extra);
        parse_path_attributes(&attrs, &HashSet::new(), false)
    }

    #[test]
    fn wrong_attribute_flags_are_treat_as_withdraw() {
        for bad in [
            &[0xC0, ATTR_ORIGIN, 1, 0][..], // optional well-known
            &[0x00, ATTR_ORIGIN, 1, 0][..], // not transitive
            &[0x40, ATTR_MULTI_EXIT_DISC, 4, 0, 0, 0, 1][..], // not optional
            &[0x80, ATTR_COMMUNITY, 4, 0, 0, 0, 1][..], // optional transitive lacks T
            &[0xC0, ATTR_MULTI_EXIT_DISC, 4, 0, 0, 0, 1][..], // non-transitive has T
        ] {
            assert!(body_attrs(bad).unwrap().withdraw, "{bad:?}");
        }
        // Partial (0x20) and Extended-Length (0x10) are never checked.
        let ok = body_attrs(&[0xE0, ATTR_COMMUNITY, 4, 0, 0, 0, 1]).unwrap();
        assert!(!ok.withdraw && ok.communities == vec![1]);
        let ok = body_attrs(&[0xD0, ATTR_COMMUNITY, 0, 4, 0, 0, 0, 1]).unwrap();
        assert!(!ok.withdraw && ok.communities == vec![1]);
        // Unknown type with odd flags is still skipped.
        assert!(!body_attrs(&[0x00, 99, 1, 7]).unwrap().withdraw);
        // MP_* with wrong flags: session reset.
        assert!(matches!(
            body_attrs(&[0x40, ATTR_MP_UNREACH_NLRI, 3, 0, 2, 1]),
            Err(WireError::MalformedUpdate)
        ));
    }

    #[test]
    fn duplicate_attribute_keeps_first_and_duplicate_mp_resets() {
        let p = body_attrs(&[
            0xC0,
            ATTR_COMMUNITY,
            4,
            0,
            0,
            0,
            1,
            0xC0,
            ATTR_COMMUNITY,
            4,
            0,
            0,
            0,
            2,
        ])
        .unwrap();
        assert_eq!(p.communities, vec![1]);
        assert!(!p.withdraw);
        for t in [ATTR_MP_REACH_NLRI, ATTR_MP_UNREACH_NLRI] {
            let mut a = Vec::new();
            for _ in 0..2 {
                encode_attribute(&mut a, 0x80, t, &[0, 2, 1]);
            }
            assert!(
                matches!(body_attrs(&a), Err(WireError::MalformedUpdate)),
                "type {t}"
            );
        }
    }

    #[test]
    fn malformed_attribute_framing_still_resets() {
        // Attribute claims 5 value bytes but only 1 remains.
        let attrs = [0x40, ATTR_ORIGIN, 5, 0];
        assert!(matches!(
            parse_update(&body_with(&attrs), &HashSet::new(), false),
            Err(WireError::MalformedUpdate)
        ));
    }

    #[test]
    fn as_zero_update_is_treated_as_withdraw() {
        let mut attrs = vec![
            0x40,
            ATTR_ORIGIN,
            1,
            0,
            0x40,
            ATTR_AS_PATH,
            6,
            2,
            1,
            0,
            0,
            0,
            0,
        ];
        attrs.extend_from_slice(&[0x40, ATTR_NEXT_HOP, 4, 10, 0, 0, 1]);
        let u = parse_update(&body_with(&attrs), &HashSet::new(), false).unwrap();
        assert!(u.nlri.is_empty() && u.attributes.is_none());
        assert_eq!(u.withdrawn_routes.len(), 1);
    }

    #[test]
    fn withdraw_carries_add_path_ids() {
        let add_path = HashSet::from([AFI_IPV4]);
        let mut attrs = valid_attrs();
        attrs.extend_from_slice(&[0x80, ATTR_COMMUNITY, 1, 0]);
        // ADD-PATH NLRI: path id 7, 10.0.0.0/8
        let mut body = vec![0u8, 0u8];
        body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&attrs);
        body.extend_from_slice(&[0, 0, 0, 7, 8, 10]);
        let u = parse_update(&body, &add_path, false).unwrap();
        assert_eq!(u.withdrawn_path_ids, vec![7]);
        assert_eq!(u.withdrawn_routes.len(), 1);
    }

    #[test]
    fn add_path_nlri_byte_vectors() {
        // RFC 7911 §3: path id (4 octets) before the length octet.
        let one = [0, 0, 0, 7, 24, 192, 0, 2];
        let net: IpNet = "192.0.2.0/24".parse().unwrap();
        assert_eq!(
            decode_prefixes(AFI_IPV4, &one, true).unwrap(),
            (vec![net], vec![7])
        );
        assert_eq!(encode_prefixes(&[net], &[7]), one);
        // Two paths of one prefix in one NLRI field.
        let two = [0, 0, 0, 1, 24, 203, 0, 113, 0, 0, 0, 2, 24, 203, 0, 113];
        let net: IpNet = "203.0.113.0/24".parse().unwrap();
        assert_eq!(
            decode_prefixes(AFI_IPV4, &two, true).unwrap(),
            (vec![net, net], vec![1, 2])
        );
        assert_eq!(encode_prefixes(&[net, net], &[1, 2]), two);
    }

    #[test]
    fn pure_withdrawal_with_bad_attribute_is_unchanged() {
        let mut body = vec![0u8, 2, 8, 10];
        let attrs = [0x80, ATTR_COMMUNITY, 1, 0];
        body.extend_from_slice(&[0, 4]);
        body.extend_from_slice(&attrs);
        let u = parse_update(&body, &HashSet::new(), false).unwrap();
        assert_eq!(u.withdrawn_routes, vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(u.attributes.is_none() && u.mp_unreach.is_empty());
    }

    #[test]
    fn update_with_out_of_range_prefix_length_is_malformed() {
        // withdrawn_routes: one entry with an invalid prefix length (33).
        let body = vec![0u8, 2u8, 33u8, 10u8];
        assert!(matches!(
            parse_update(&body, &HashSet::new(), false),
            Err(WireError::MalformedUpdate)
        ));
    }

    #[test]
    fn update_truncated_prefix_data_is_malformed() {
        // withdrawn_routes: declares a /24 (needs 3 octets) but only 1 byte
        // of address data follows before the section's declared length ends.
        let body = vec![0u8, 2u8, 24u8, 10u8];
        assert!(matches!(
            parse_update(&body, &HashSet::new(), false),
            Err(WireError::MalformedUpdate)
        ));
    }

    #[test]
    fn bad_marker_is_rejected() {
        let mut buf = BytesMut::new();
        buf.put_slice(&[0u8; 16]);
        buf.put_u16(19);
        buf.put_u8(4);
        let mut codec = BgpCodec::default();
        assert!(matches!(codec.decode(&mut buf), Err(WireError::BadMarker)));
    }

    #[test]
    fn length_below_header_is_rejected() {
        let mut buf = BytesMut::new();
        buf.put_slice(&MARKER);
        buf.put_u16(18);
        buf.put_u8(4);
        let mut codec = BgpCodec::default();
        assert!(matches!(
            codec.decode(&mut buf),
            Err(WireError::BadLength(18))
        ));
    }

    #[test]
    fn length_above_max_is_rejected() {
        let mut buf = BytesMut::new();
        buf.put_slice(&MARKER);
        buf.put_u16(4097);
        buf.put_u8(4);
        let mut codec = BgpCodec::default();
        assert!(matches!(
            codec.decode(&mut buf),
            Err(WireError::BadLength(4097))
        ));
    }

    #[test]
    fn partial_message_returns_none() {
        let mut buf = BytesMut::new();
        buf.put_slice(&MARKER);
        buf.put_u16(30);
        buf.put_u8(1);
        // Missing the rest of the OPEN body.
        let mut codec = BgpCodec::default();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn is_valid_bgp_identifier_rejects_special_cases() {
        assert!(!is_valid_bgp_identifier(Ipv4Addr::UNSPECIFIED));
        assert!(!is_valid_bgp_identifier(Ipv4Addr::BROADCAST));
        assert!(!is_valid_bgp_identifier(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_valid_bgp_identifier(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn pmsi_tunnel_round_trips_and_other_tunnel_types_are_ignored() {
        let p = Pmsi {
            vni: 10100,
            tunnel_ip: "192.0.2.1".parse().unwrap(),
        };
        assert_eq!(decode_pmsi(&encode_pmsi(&p)), Some(p));
        assert_eq!(decode_pmsi(&[0, 2, 0, 0, 1, 1, 2, 3, 4]), None);
    }
}

#[cfg(test)]
mod shutdown_message_tests {
    use super::*;

    #[test]
    fn round_trips() {
        let data = encode_shutdown_message("maintenance");
        assert_eq!(data[0], 11);
        assert_eq!(
            decode_shutdown_message(&data).as_deref(),
            Some("maintenance")
        );
    }

    #[test]
    fn truncates_on_a_char_boundary() {
        // 100 x 3-byte chars = 300 bytes; the cut must land on a boundary <= 255.
        let data = encode_shutdown_message(&"€".repeat(100));
        assert_eq!(usize::from(data[0]), 255);
        assert_eq!(decode_shutdown_message(&data), Some("€".repeat(85)));
    }

    #[test]
    fn malformed_is_rejected() {
        assert_eq!(decode_shutdown_message(&[]), None);
        assert_eq!(decode_shutdown_message(&[5, b'a']), None);
        assert_eq!(decode_shutdown_message(&[1, 0xff]), None);
    }

    #[test]
    fn role_capability_codec() {
        let mut open = build_open(65001, Ipv4Addr::new(1, 1, 1, 1), 90);
        open.capabilities.push(Capability::Role(3));
        let back = parse_open(&encode_open(&open)).unwrap();
        assert_eq!(peer_role(&back), Some(3));
        // On the wire: code 9, length 1, value.
        let mut open = build_open(65001, Ipv4Addr::new(1, 1, 1, 1), 90);
        open.capabilities = vec![Capability::Role(0)];
        assert_eq!(
            encode_open(&open)[9..],
            [5, OPT_PARAM_CAPABILITIES, 3, 9, 1, 0]
        );
        // Any other length is dropped as unknown (RFC 9234 §4.1: one octet).
        let mut body = encode_open(&open)[..9].to_vec();
        body.extend_from_slice(&[6, OPT_PARAM_CAPABILITIES, 4, 9, 2, 0, 0]);
        assert_eq!(parse_open(&body).unwrap().capabilities, []);
    }

    // --- boundary-length decoding (#359): hand-written buffers, exact vs one short ---

    const OPEN_FIXED: [u8; 9] = [4, 0xfd, 0xe9, 0, 90, 1, 1, 1, 1];

    fn open_body(tail: &[u8]) -> Vec<u8> {
        [&OPEN_FIXED[..], tail].concat()
    }

    #[test]
    fn open_fixed_part_boundary() {
        assert_eq!(parse_open(&open_body(&[0])).unwrap().capabilities, []);
        assert!(matches!(
            parse_open(&OPEN_FIXED),
            Err(WireError::MalformedOpen)
        ));
    }

    #[test]
    fn open_opt_param_len_255_needs_the_second_255_for_extended_form() {
        // 10 bytes, opt_param_len 255 and no octet 10: classic, 255 bytes missing.
        assert!(matches!(
            parse_open(&open_body(&[255])),
            Err(WireError::Truncated)
        ));
        // Non-255 next octet: classic form with exactly 255 parameter bytes
        // (one unknown parameter, type 9, 253 value bytes).
        let mut params = vec![9, 253];
        params.extend(vec![0; 253]);
        assert_eq!(params.len(), 255);
        let classic = open_body(&[&[255][..], &params].concat());
        assert_eq!(parse_open(&classic).unwrap().capabilities, []);
        // 255/255: extended, total length 0 in exactly 13 bytes; 12 is malformed.
        let extended = open_body(&[255, 255, 0, 0]);
        assert_eq!(parse_open(&extended).unwrap().capabilities, []);
        assert!(matches!(
            parse_open(&open_body(&[255, 255, 0])),
            Err(WireError::MalformedOpen)
        ));
    }

    #[test]
    fn open_optional_parameters_exact_vs_one_short() {
        // Parameter (type 9, len 0) exactly fills the declared 2 bytes.
        assert!(parse_open(&open_body(&[2, 9, 0])).is_ok());
        assert!(matches!(
            parse_open(&open_body(&[2, 9])),
            Err(WireError::Truncated)
        ));
        // Declared parameter length 1 with no value byte.
        assert!(matches!(
            parse_open(&open_body(&[2, 9, 1])),
            Err(WireError::Truncated)
        ));
        // A lone type octet is shorter than the parameter header.
        assert!(matches!(
            parse_open(&open_body(&[1, 9])),
            Err(WireError::Truncated)
        ));
    }

    #[test]
    fn capability_length_exact_vs_one_short() {
        assert_eq!(
            parse_capabilities(&[CAP_ROUTE_REFRESH, 0]).unwrap(),
            [Capability::RouteRefresh]
        );
        assert_eq!(
            parse_capabilities(&[CAP_FOUR_OCTET_ASN, 4, 0, 0, 0xfd, 0xe9]).unwrap(),
            [Capability::FourOctetAsn(65001)]
        );
        assert!(matches!(
            parse_capabilities(&[CAP_FOUR_OCTET_ASN, 4, 0, 0, 0xfd]),
            Err(WireError::Truncated)
        ));
        // A one-byte tail cannot hold code + length.
        assert!(matches!(
            parse_capabilities(&[CAP_ROUTE_REFRESH]),
            Err(WireError::Truncated)
        ));
        assert!(matches!(
            parse_capabilities(&[CAP_ROUTE_REFRESH, 0, CAP_ROUTE_REFRESH]),
            Err(WireError::Truncated)
        ));
    }

    #[test]
    fn known_capability_with_the_wrong_length_is_skipped_not_an_error() {
        for (code, len) in [
            (CAP_ROLE, 2),
            (CAP_FOUR_OCTET_ASN, 3),
            (CAP_MULTIPROTOCOL, 3),
            (CAP_ROUTE_REFRESH, 1),
            (CAP_ENHANCED_ROUTE_REFRESH, 1),
            (CAP_EXTENDED_MESSAGE, 1),
            (CAP_EXTENDED_NEXT_HOP, 5),
            (CAP_ADD_PATH, 5),
        ] {
            let mut v = vec![code, len];
            v.extend(vec![0; usize::from(len)]);
            assert_eq!(parse_capabilities(&v).unwrap(), [], "code {code} len {len}");
        }
    }

    #[test]
    fn graceful_restart_capability_length_must_be_2_plus_a_multiple_of_4() {
        let gr = |value: &[u8]| {
            let mut v = vec![CAP_GRACEFUL_RESTART, u8::try_from(value.len()).unwrap()];
            v.extend_from_slice(value);
            parse_capabilities(&v).unwrap()
        };
        // cap_len 2: header only, no families.
        assert_eq!(
            gr(&[0x00, 90]),
            [Capability::GracefulRestart(GracefulRestartCap {
                restart: false,
                notification: false,
                time: 90,
                families: vec![],
            })]
        );
        // cap_len 6: one family.
        assert_eq!(
            gr(&[0x00, 90, 0, 1, 1, 0x80]),
            [Capability::GracefulRestart(GracefulRestartCap {
                restart: false,
                notification: false,
                time: 90,
                families: vec![GrFamily {
                    afi: 1,
                    safi: 1,
                    forwarding: true,
                }],
            })]
        );
        // cap_len 0, 1, 3, 4, 5: not 2 + 4k, skipped.
        for n in [0, 1, 3, 4, 5] {
            assert_eq!(gr(&vec![0; n]), [], "cap_len {n}");
        }
    }

    fn attrs(data: &[u8]) -> Result<ParsedAttributes, WireError> {
        parse_path_attributes(data, &HashSet::new(), false)
    }

    #[test]
    fn attribute_header_boundary() {
        assert!(attrs(&[]).is_ok());
        // One byte, then flags+type without a length byte.
        assert!(matches!(attrs(&[0x40]), Err(WireError::MalformedUpdate)));
        assert!(matches!(
            attrs(&[0x40, ATTR_ORIGIN]),
            Err(WireError::MalformedUpdate)
        ));
        // Exact: header of 3, value of 1.
        assert_eq!(
            attrs(&[0x40, ATTR_ORIGIN, 1, 0]).unwrap().origin,
            Some(Origin::Igp)
        );
        assert!(matches!(
            attrs(&[0x40, ATTR_ORIGIN, 1]),
            Err(WireError::MalformedUpdate)
        ));
        // Extended length: header of 4.
        assert!(matches!(
            attrs(&[0x50, ATTR_ORIGIN, 0]),
            Err(WireError::MalformedUpdate)
        ));
        assert_eq!(
            attrs(&[0x50, ATTR_ORIGIN, 0, 1, 2]).unwrap().origin,
            Some(Origin::Incomplete)
        );
        assert!(matches!(
            attrs(&[0x50, ATTR_ORIGIN, 0, 1]),
            Err(WireError::MalformedUpdate)
        ));
        // Header only, zero-length value: framing is fine, content is not.
        assert!(attrs(&[0x50, ATTR_ORIGIN, 0, 0]).unwrap().withdraw);
    }

    #[test]
    fn origin_values_decode_and_3_is_treat_as_withdraw() {
        for (v, want) in [(0, Origin::Igp), (1, Origin::Egp), (2, Origin::Incomplete)] {
            let p = attrs(&[0x40, ATTR_ORIGIN, 1, v]).unwrap();
            assert_eq!(p.origin, Some(want));
            assert!(!p.withdraw);
        }
        let p = attrs(&[0x40, ATTR_ORIGIN, 1, 3]).unwrap();
        assert_eq!(p.origin, None);
        assert!(p.withdraw);
    }

    #[test]
    fn fixed_size_attributes_reject_one_byte_either_side() {
        for ty in [
            ATTR_NEXT_HOP,
            ATTR_LOCAL_PREF,
            ATTR_MULTI_EXIT_DISC,
            ATTR_ORIGINATOR_ID,
        ] {
            // The flags must match the RFC 7606 flag table or the attribute
            // is rejected for its flags, not its length.
            let f = expected_flags(ty).unwrap();
            let ok = attrs(&[f, ty, 4, 1, 2, 3, 4]).unwrap();
            assert!(!ok.withdraw, "type {ty}");
            assert!(attrs(&[f, ty, 3, 1, 2, 3]).unwrap().withdraw, "{ty}");
            assert!(attrs(&[f, ty, 5, 1, 2, 3, 4, 5]).unwrap().withdraw, "{ty}");
        }
    }

    fn mp_reach_hdr(nh_len: u8) -> Vec<u8> {
        vec![0, 1, 1, nh_len]
    }

    #[test]
    fn mp_reach_minimum_and_next_hop_boundaries() {
        let afis = HashSet::new();
        let d = |v: &[u8]| decode_mp_reach(v, &afis);
        assert!(matches!(d(&[0, 1, 1, 4]), Err(WireError::MalformedUpdate)));
        // 5 bytes with nh_len 0: unsupported next-hop length, never an index panic.
        assert!(matches!(
            d(&[0, 1, 1, 0, 0]),
            Err(WireError::MalformedUpdate)
        ));
        for nh_len in [4usize, 16, 32] {
            // exactly header + next hop + SNPA count
            let mut v = mp_reach_hdr(u8::try_from(nh_len).unwrap());
            v.extend(vec![0; nh_len]);
            v.push(0);
            let got = d(&v).unwrap();
            assert_eq!((got.afi, got.safi, got.nlri.len()), (1, 1, 0), "{nh_len}");
            v.pop();
            assert!(
                matches!(d(&v), Err(WireError::MalformedUpdate)),
                "one short, nh_len {nh_len}"
            );
        }
    }

    #[test]
    fn mp_reach_snpa_boundaries() {
        let afis = HashSet::new();
        let base = |snpa: &[u8]| {
            let mut v = mp_reach_hdr(4);
            v.extend([10, 0, 0, 1]);
            v.extend_from_slice(snpa);
            decode_mp_reach(&v, &afis)
        };
        // One SNPA announced but its length byte is missing.
        assert!(matches!(base(&[1]), Err(WireError::MalformedUpdate)));
        // Length byte present, empty SNPA, then one NLRI (10.1.0.0/16).
        let got = base(&[1, 0, 16, 10, 1]).unwrap();
        assert_eq!(got.nlri.len(), 1);
        // A 2-byte SNPA fitting exactly, then no NLRI, vs one byte short.
        assert_eq!(base(&[1, 2, 0xaa, 0xbb]).unwrap().nlri.len(), 0);
        assert!(matches!(
            base(&[1, 2, 0xaa]),
            Err(WireError::MalformedUpdate)
        ));
        // Two SNPAs, the second missing.
        assert!(matches!(base(&[2, 0]), Err(WireError::MalformedUpdate)));
    }

    const RT: u64 = 0x0002_FDE8_0000_0064; // 65000:100

    fn rtc(origin_as: u32, rt: u64, bits: u8) -> RtcNlri {
        RtcNlri {
            origin_as,
            rt,
            bits,
        }
    }

    #[test]
    fn rtc_nlri_round_trips_at_every_legal_length() {
        let all = [
            rtc(0, 0, 0),
            rtc(65001, 0, 32),
            rtc(65001, 0x0002_0000_0000_0000, 48),
            rtc(65001, RT, 96),
        ];
        let mut wire = Vec::new();
        encode_rtc_nlris(&all, &mut wire);
        // len + ceil(len/8) octets each: 1, 5, 7, 13.
        assert_eq!(wire.len(), 1 + 5 + 7 + 13);
        assert_eq!(decode_rtc_nlris(&wire).unwrap(), all);
    }

    #[test]
    fn rtc_trailing_bits_are_masked_on_decode_and_zeroed_on_encode() {
        // 33 bits: one bit of the route target survives, the rest is noise.
        let wire = [33, 0, 0, 0xfd, 0xe8, 0xff];
        assert_eq!(
            decode_rtc_nlris(&wire).unwrap(),
            [rtc(0xfde8, 0x8000_0000_0000_0000, 33)]
        );
        let mut out = Vec::new();
        encode_rtc_nlris(&[rtc(0xfde8, u64::MAX, 33)], &mut out);
        assert_eq!(out, [33, 0, 0, 0xfd, 0xe8, 0x80]);
    }

    #[test]
    fn rtc_bad_lengths_and_truncation_are_malformed() {
        for wire in [
            vec![1, 0],
            vec![31, 0, 0, 0, 0],
            vec![97; 14],
            vec![32, 0, 0, 0],
        ] {
            assert!(
                matches!(decode_rtc_nlris(&wire), Err(WireError::MalformedUpdate)),
                "{wire:?}"
            );
        }
        let mut out = Vec::new();
        encode_rtc_nlris(&[rtc(1, 1, 31), rtc(1, 1, 97)], &mut out);
        assert!(out.is_empty(), "invalid lengths are never encoded");
    }

    #[test]
    fn rtc_mp_reach_and_unreach_round_trip_with_either_next_hop() {
        for nh in ["192.0.2.1", "2001:db8::1"] {
            let next_hop: IpAddr = nh.parse().unwrap();
            let reach = MpReachNlri {
                afi: AFI_IPV4,
                safi: SAFI_RTC,
                next_hop,
                nlri: vec![],
                nlri_path_ids: vec![],
                evpn: vec![],
                flowspec: vec![],
                vpn: vec![],
                rtc: vec![rtc(65001, RT, 96), rtc(0, 0, 0)],
            };
            let back = decode_mp_reach(&encode_mp_reach(&reach), &HashSet::new()).unwrap();
            assert_eq!(back, reach);
            let un = MpUnreachNlri {
                afi: AFI_IPV4,
                safi: SAFI_RTC,
                withdrawn: vec![],
                withdrawn_path_ids: vec![],
                evpn: vec![],
                flowspec: vec![],
                vpn: vec![],
                rtc: reach.rtc.clone(),
            };
            let back = decode_mp_unreach(&encode_mp_unreach(&un), &HashSet::new()).unwrap();
            assert_eq!(back, un);
        }
    }

    #[test]
    fn an_oversized_rtc_update_is_split_not_dropped() {
        let rtc: Vec<_> = (0..400).map(|i| rtc(65001, RT + i, 96)).collect();
        let update = UpdateMessage {
            withdrawn_routes: vec![],
            withdrawn_path_ids: vec![],
            nlri: vec![],
            nlri_path_ids: vec![],
            attributes: None,
            mp_reach: vec![],
            mp_unreach: vec![MpUnreachNlri {
                afi: AFI_IPV4,
                safi: SAFI_RTC,
                withdrawn: vec![],
                withdrawn_path_ids: vec![],
                evpn: vec![],
                flowspec: vec![],
                vpn: vec![],
                rtc,
            }],
            ..Default::default()
        };
        let mut out = Vec::new();
        split_update(&update, false, 1000, &mut out).unwrap();
        assert!(out.len() > 1);
        let total: usize = out
            .iter()
            .map(|b| {
                let u = parse_update(b, &HashSet::new(), false).unwrap();
                u.mp_unreach.iter().map(|m| m.rtc.len()).sum::<usize>()
            })
            .sum();
        assert_eq!(total, 400);
    }
}
