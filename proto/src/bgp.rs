//! `nos-bgpd`'s IPC query protocol — backs `nos-cli`'s `show bgp brief`.
//! Mirrors `rib`/`interface`'s shape: a request/event pair framed by
//! `IpcCodec` over a Unix socket resolved via the watchdog broker
//! (`ServiceRef::BgpInstance`).

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// The FSM state a peer's session is in, as reported by `nos-bgpd`.
/// `Idle` covers everything before a TCP connection has even reached
/// `OpenSent` (no active/passive attempt has an OPEN in flight yet) — it is
/// not a real state in `nos-bgp::fsm`, which only models `OpenSent`/
/// `OpenConfirm`/`Established`, but is the natural "nothing established yet"
/// value to report over this protocol.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpSessionState {
    /// `Idle` (RFC 4271 section 8.2.2).
    Idle,
    /// `OpenSent`: our OPEN is sent, waiting for the peer's.
    OpenSent,
    /// `OpenConfirm`: OPENs exchanged, waiting for a KEEPALIVE.
    OpenConfirm,
    /// `Established`: UPDATEs may flow.
    Established,
}

/// One configured peer's one-line summary, for `show bgp brief`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerSummary {
    /// The peer's address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub remote_address: IpAddr,
    /// Name of the peer group the peer belongs to.
    pub peer_group: String,
    /// The peer (or its peer-group) is administratively shut.
    pub shutdown: bool,
    /// Known only once negotiated (i.e. at least `OpenConfirm`).
    pub remote_as: Option<u32>,
    /// BGP Identifier from the peer's OPEN (RFC 4271 section 4.2), once received.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub remote_bgp_id: Option<Ipv4Addr>,
    /// Session state.
    pub state: BgpSessionState,
    /// Seconds since the session reached `Established`. `None` unless
    /// `state == Established` — computed server-side from an `Instant`,
    /// which isn't itself meaningful to serialize across processes.
    pub uptime_secs: Option<u64>,
    /// Hold time agreed with the peer, in seconds (RFC 4271 section 4.2).
    pub negotiated_hold_time: Option<u16>,
    /// Keepalive interval in effect, in seconds.
    pub negotiated_keepalive: Option<u16>,
    /// RFC 5925 TCP-AO live per-connection state, from
    /// `getsockopt(TCP_AO_INFO)` — `Some` only for an `Established` session
    /// whose peer-group uses TCP-AO and whose readback succeeded just now;
    /// `None` for MD5/no-auth peers, a non-`Established` peer, or a readback
    /// that raced session teardown. Counters are since the kernel installed
    /// AO on *this* connection (reset on every reconnect, not cumulative
    /// across the peer's whole configured lifetime). `ao_current_key` is the
    /// `KeyID` signing outgoing segments right now (it follows the peer's
    /// `RNextKeyID`, RFC 5925 §7.5.2); `ao_rnext_key` is the `RecvID` of the key
    /// *this router* asks the peer to send with, not what the peer asked for.
    pub ao_current_key: Option<u8>,
    /// TCP-AO `RNextKeyID` the peer asks us to send (RFC 5925 section 3.1).
    pub ao_rnext_key: Option<u8>,
    /// Segments that passed TCP-AO verification.
    pub ao_packets_good: Option<u64>,
    /// Segments that failed TCP-AO verification.
    pub ao_packets_bad: Option<u64>,
    /// Segments dropped because no matching TCP-AO key was found.
    pub ao_packets_key_not_found: Option<u64>,
    /// Held down by an RFC 4486 maximum-prefix trip: no session is opened or
    /// accepted until `ClearPeer`, a shut/no-shut, or the restart interval.
    pub max_prefix_held: bool,
    /// Accepted (post-import-policy) prefixes from this peer per address
    /// family: ipv4, ipv6, l2vpn-evpn. `Some` only while `Established`.
    pub accepted_prefixes: Option<[u32; 3]>,
    /// The RFC 4724 graceful restart capability the peer last advertised,
    /// while this instance has graceful restart on. Kept after the session
    /// ends, so it shows while its routes are retained.
    pub graceful_restart: Option<GrSummary>,
    /// Routes from this peer kept as stale after a graceful restart, waiting
    /// for its End-of-RIB (also RFC 7313 enhanced route refresh's).
    pub stale_prefixes: u32,
}

/// A peer's RFC 4724 / RFC 8538 graceful restart capability.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrSummary {
    /// Its Restart Time, in seconds.
    pub restart_time: u16,
    /// RFC 8538 N bit: a NOTIFICATION other than a Hard Reset keeps routes.
    pub notification: bool,
    /// R bit: the peer has just restarted.
    pub restarting: bool,
    /// The families it keeps forwarding state for, and each one's F bit.
    pub families: Vec<(crate::AddressFamily, bool)>,
}

/// One received EVPN (RFC 7432) route, for `show bgp evpn`. `route` is the
/// NLRI rendered by `nos-bgpd` (`[2]:[65000:1]:[<esi>]:[<tag>]:...`) — nothing
/// downstream interprets it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvpnRouteSummary {
    /// The advertising peer.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub peer: IpAddr,
    /// EVPN route type (RFC 7432 section 7).
    pub route_type: u8,
    /// The NLRI rendered as text.
    pub route: String,
    /// The route's BGP next hop.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub next_hop: IpAddr,
    /// Extended communities rendered as `RT:65000:10000`, `encap:8`, ...
    pub extended_communities: Vec<String>,
    /// The `LOCAL_PREF` this route is ranked by (0 when RFC 8326 demoted it).
    pub local_pref: u32,
    /// Standard communities, packed `high << 16 | low`.
    pub communities: Vec<u32>,
}

/// IANA well-known community names (RFC 1997, 3765, 7611, 7999, 8326), the
/// one table `nos-bgpd`'s logs and `nos`'s `show` lines render with.
#[must_use]
pub fn community_name(c: u32) -> Option<&'static str> {
    Some(match c {
        0xFFFF_0000 => "graceful-shutdown",
        0xFFFF_0001 => "accept-own",
        0xFFFF_029A => "blackhole",
        0xFFFF_FF01 => "no-export",
        0xFFFF_FF02 => "no-advertise",
        0xFFFF_FF03 => "no-export-subconfed",
        0xFFFF_FF04 => "no-peer",
        _ => return None,
    })
}

/// Communities space-joined: a well-known one by name, any other `high:low`.
#[must_use]
pub fn fmt_communities(cs: &[u32]) -> String {
    cs.iter()
        .map(|&c| {
            community_name(c).map_or_else(|| format!("{}:{}", c >> 16, c & 0xFFFF), str::to_owned)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// One received Flowspec (RFC 8955) route, for `show bgp flowspec`. `nlri` is
/// the component list rendered by `nos-bgpd`; nothing downstream interprets it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowspecRouteSummary {
    /// The advertising peer.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub peer: IpAddr,
    /// The NLRI rendered as text (`dest 192.0.2.0/24 proto =6 dst-port =25`).
    pub nlri: String,
    /// Extended communities rendered as `traffic-rate:0:0`, ...
    pub extended_communities: Vec<String>,
    /// RFC 8955 section 6 validation: `valid`, or `invalid:<reason>` (for
    /// example `invalid:no-covering-unicast-route`).
    pub validity: String,
    /// The traffic actions decoded from the extended communities, one text
    /// each (`discard`, `redirect rt 65000:10`, `dscp 10`); a traffic-rate
    /// shadowed by an earlier one is suffixed `(ignored)`.
    pub actions: Vec<String>,
    /// For the selected copy of a rule only, its state in `nos-acld`:
    /// `installed`, `unsupported (<why>)`, `not-attached` (no `flowspec`
    /// device in this instance's table) or `unknown` (`nos-acld` did not
    /// answer); `None` for any other copy.
    pub dataplane: Option<String>,
}

/// One received VPN-IPv4/VPN-IPv6 path (RFC 4364/4659, SAFI 128), for
/// `show bgp vpnv4|vpnv6`. RD and Route Targets are rendered by `nos-bgpd`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VpnRouteSummary {
    /// The advertising peer.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub peer: IpAddr,
    /// The Route Distinguisher, `65001:1` or `192.0.2.1:7`.
    pub rd: String,
    /// The customer prefix, `10.10.0.0/24`.
    pub prefix: String,
    /// The MPLS label stack as received (RFC 8277), outermost first.
    pub labels: Vec<u32>,
    /// The BGP next hop (the egress PE).
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub next_hop: IpAddr,
    /// The Route Targets, `RT:65000:1`.
    pub route_targets: Vec<String>,
    /// The AS path as text (`65001 65002`).
    pub as_path: String,
    /// Effective `LOCAL_PREF`.
    pub local_pref: u32,
    /// This path is the best one for its (RD, prefix), the one reflected.
    pub best: bool,
    /// The Site of Origin the path carries (RFC 4364 section 7), `65001:77`.
    #[serde(default)]
    pub site_of_origin: Option<String>,
}

/// RFC 6811 origin validation state of a route, for `show bgp routes`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpkiValidationState {
    /// A covering VRP validates the origin AS.
    Valid,
    /// A covering VRP exists but none matches.
    Invalid,
    /// No covering VRP.
    NotFound,
}

/// One IPv4/IPv6 unicast route known to a BGP instance, for `show bgp routes`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BgpRouteSummary {
    /// The prefix, `192.0.2.0/24`.
    pub prefix: String,
    /// The advertising peer; `None` for a locally redistributed route.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub peer: Option<IpAddr>,
    /// The BGP next hop as received; `None` for a locally redistributed route.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub next_hop: Option<IpAddr>,
    /// The AS path as text (`65001 65002 {65003,65004}`); empty when local.
    pub as_path: String,
    /// RFC 6811 origin AS (`None` for a trailing `AS_SET`).
    pub origin_as: Option<u32>,
    /// Effective `LOCAL_PREF`.
    pub local_pref: u32,
    /// This path is the Loc-RIB best path for the prefix.
    pub best: bool,
    /// RFC 6811 origin validation state.
    pub validation_state: RpkiValidationState,
}

/// RFC 8210 session state of one configured RPKI cache, as seen by one
/// `nos-bgpd`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpkiSessionState {
    /// Not connected (or a lower-preference cache is in use).
    Idle,
    /// Connected, waiting for the first End of Data.
    Syncing,
    /// Holding a complete VRP set from this cache.
    Established,
}

/// One configured RPKI cache's status, for `show bgp rpki`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpkiCacheStatus {
    /// The cache's address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: IpAddr,
    /// The cache's RTR TCP port (RFC 8210).
    pub port: u16,
    /// Cache preference; the lowest is used first.
    pub preference: u8,
    /// Session state.
    pub state: RpkiSessionState,
    /// This cache's VRPs are the ones validating routes right now.
    pub active: bool,
    /// RTR protocol version negotiated (0 or 1).
    pub version: Option<u8>,
    /// RTR Session ID (RFC 8210 section 5.1), once received.
    pub session_id: Option<u16>,
    /// Latest RTR serial number applied.
    pub serial: Option<u32>,
    /// Validated ROA Payloads currently held from this cache.
    pub vrp_count: usize,
    /// Seconds since the last End of Data from this cache.
    pub last_update_secs: Option<u64>,
    /// The RTR session is configured with TCP-MD5 or TCP-AO (RFC 8210 §9);
    /// never the secret itself. Appended last: postcard is positional.
    #[serde(default)]
    pub authenticated: bool,
}

/// A single already-resolved winning route pushed by `nos-ribd` for
/// redistribution into BGP — not `PrefixRoutes`/`RouteEntry`'s
/// multi-candidate shape. `gateway` is carried for completeness only: the
/// BGP RIB engine always applies next-hop-self and never reads it. `prefix`
/// and `gateway` are always the same address family (v4/v6 alike, inferred
/// from `prefix`'s own `IpNet` variant — no separate AFI tag needed).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedistributedRoute {
    /// The redistributed prefix.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix: IpNet,
    /// Next-hop address of the redistributed route.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub gateway: IpAddr,
}

/// Sent by `nos-ribd` to `nos-bgpd` over a persistent, long-lived
/// connection (mirroring `LogRequest::Push`'s pattern): a `Full` snapshot on
/// connect, then incremental `Add`/`Remove` for each subsequent change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RedistributeUpdate {
    /// The complete set of redistributed routes, replacing any previous one.
    Full(Vec<RedistributedRoute>),
    /// One route added or changed.
    Add(RedistributedRoute),
    /// One route withdrawn.
    Remove(IpNet),
    /// A leading part of a `Full` too large for one frame: the receiver
    /// stages it and applies nothing until the closing `Full`. Appended
    /// (postcard indexes variants by position).
    FullPart(Vec<RedistributedRoute>),
}

/// Routes per `RedistributeUpdate` frame. A route encodes to at most ~40 B
/// (IPv6 prefix and gateway), so a chunk stays near 2.6 MiB, well under the
/// 16 MiB `MAX_FRAME` (pinned by a test).
pub const REDISTRIBUTE_CHUNK: usize = 65536;

/// The budget [`RedistributeUpdate::split`] uses: [`REDISTRIBUTE_CHUNK`], or
/// `NOS_REDISTRIBUTE_CHUNK` when set (a test hook, so tests and dev runs need
/// few routes). Not usable under the watchdog, which clears its children's
/// environment.
#[must_use]
pub fn redistribute_chunk() -> usize {
    parse_chunk(std::env::var("NOS_REDISTRIBUTE_CHUNK").ok().as_deref())
}

fn parse_chunk(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.trim().parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(REDISTRIBUTE_CHUNK)
}

impl RedistributeUpdate {
    /// [`Self::split_with`] at [`redistribute_chunk`].
    #[must_use]
    pub fn split(self) -> Vec<Self> {
        self.split_with(redistribute_chunk())
    }

    /// The requests to send for this update: anything but a `Full` over
    /// `chunk` routes is itself; that one becomes `FullPart`s closed by a
    /// `Full` holding the last chunk (see [`crate::chunk::split_full`]).
    #[must_use]
    pub fn split_with(self, chunk: usize) -> Vec<Self> {
        let Self::Full(routes) = self else {
            return vec![self];
        };
        let (parts, last) = crate::chunk::split_full(routes, chunk, |_| 1);
        let mut out: Vec<_> = parts.into_iter().map(Self::FullPart).collect();
        out.push(Self::Full(last));
        out
    }

    /// Receiver side of [`Self::split_with`]: stages a `FullPart` (returns
    /// `None`), folds the staged parts into the closing `Full`, passes
    /// `Add`/`Remove` through. The `usize` is the frames the update took (1
    /// when unchunked), for the receiver's log.
    pub fn absorb(
        self,
        staging: &mut crate::chunk::FullStaging<RedistributedRoute>,
    ) -> Option<(Self, usize)> {
        match self {
            Self::FullPart(r) => {
                staging.part(r);
                None
            }
            Self::Full(r) => {
                let (all, parts) = staging.close(r);
                Some((Self::Full(all), parts))
            }
            other => Some((other, 1)),
        }
    }
}

/// One VRF route `nos-ribd` exports as a VPN-IPv4/IPv6 route (RFC 4364
/// section 4.3.2). No next hop: `nos-bgpd` always sends next-hop-self, the
/// session's own address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnPrefix {
    /// The VRF's Route Distinguisher, as 8 wire bytes.
    pub rd: [u8; 8],
    /// The customer prefix.
    pub prefix: IpNet,
    /// The label stack, outermost first: today exactly the VRF label.
    pub labels: Vec<u32>,
    /// The export Route Targets as RFC 4360 extended communities.
    pub ext_communities: Vec<u64>,
}

/// `RedistributeVpnPrefixes`' payload: `Full` on connect, then `Add`/`Remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpnPrefixUpdate {
    /// The table's complete export set, replacing any previous one.
    Full(Vec<VpnPrefix>),
    /// One route added or changed (label or Route Targets).
    Add(VpnPrefix),
    /// One route no longer exported, by (RD, prefix).
    Remove([u8; 8], IpNet),
    /// A leading part of a `Full` too large for one frame (#791): the
    /// receiver stages it and applies nothing until the closing `Full`.
    /// Appended (postcard indexes variants by position).
    FullPart(Vec<VpnPrefix>),
}

impl VpnPrefixUpdate {
    /// The frames to send for this update: anything but a `Full` over
    /// `budget` encoded bytes is itself; that one becomes `FullPart`s closed
    /// by a `Full` holding the last chunk (see [`crate::chunk::split_full`]).
    /// Bytes, not routes: `ext_communities` (export RTs, Site of Origin) is unbounded.
    #[must_use]
    pub fn split_with(self, budget: usize) -> Vec<Self> {
        let Self::Full(routes) = self else {
            return vec![self];
        };
        let weight = |r: &VpnPrefix| postcard::to_allocvec(r).map_or(usize::MAX, |v| v.len());
        let (parts, last) = crate::chunk::split_full(routes, budget, weight);
        let mut out: Vec<_> = parts.into_iter().map(Self::FullPart).collect();
        out.push(Self::Full(last));
        out
    }

    /// Receiver side of [`Self::split_with`]: stages a `FullPart` (returns
    /// `None`), folds the staged parts into the closing `Full`, passes
    /// `Add`/`Remove` through. The `usize` is the frames the update took (1
    /// when unchunked), for the receiver's log.
    pub fn absorb(
        self,
        staging: &mut crate::chunk::FullStaging<VpnPrefix>,
    ) -> Option<(Self, usize)> {
        match self {
            Self::FullPart(r) => {
                staging.part(r);
                None
            }
            Self::Full(r) => {
                let (all, parts) = staging.close(r);
                Some((Self::Full(all), parts))
            }
            other => Some((other, 1)),
        }
    }
}

/// Messages sent from a client to one `nos-bgpd` instance's IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum BgpRequest {
    /// One-shot: every configured peer's current summary.
    GetSummary,
    /// Fire-and-forget, no reply — like `LogRequest::Push`, sent
    /// continuously over one long-lived connection from `nos-ribd`.
    RedistributeRoutes(RedistributeUpdate),
    /// Operator-triggered `clear bgp <instance> <peer> soft-in` — ask
    /// `peer`'s live session to send it an RFC 2918 `ROUTE_REFRESH`.
    SendRouteRefresh {
        /// The advertising peer.
        peer: IpAddr,
    },
    /// Removed in #723 (answered with `BgpEvent::Error`); the slot stays.
    /// Use `GetEvpnRoutesPage`.
    GetEvpnRoutes,
    /// Fire-and-forget, no reply: one `nos-fdbd`'s local MACs, originated as
    /// EVPN Type-2 (and its flood-list Type-3) routes. `domain` scopes a
    /// `Full`, since several domains feed one BGP instance (unlike
    /// `nos-ribd`, where table and instance are 1:1).
    RedistributeMacs {
        /// Broadcast domain the update belongs to.
        domain: String,
        /// The EVPN route change.
        update: crate::fdb::EvpnUpdate,
    },
    /// Operator-triggered `clear bgp <instance> <peer>`: release a peer held
    /// by its maximum-prefix limit, and reset its session if one is up
    /// (Cease/Administrative Reset). Replies `PeerCleared` or `PeerNotFound`.
    ClearPeer {
        /// The advertising peer.
        peer: IpAddr,
    },
    /// One-shot: every configured RPKI cache's RTR session (`show bgp rpki`).
    GetRpkiSummary,
    /// Fire-and-forget, no reply, `nos-ribd` only: one IP-VRF's best routes
    /// as EVPN Type-5 routes (`EvpnKey::IpPrefix`), originated into this
    /// (underlay) instance. `table` scopes a `Full`, like `RedistributeMacs`'s
    /// `domain`. A variant of its own, not `RedistributeMacs`, since only
    /// `ribd` may send it.
    RedistributeEvpnPrefixes {
        /// Routing table (IP-VRF) the update belongs to.
        table: String,
        /// The EVPN route change.
        update: crate::fdb::EvpnUpdate,
    },
    /// Removed in #722 (answered with `BgpEvent::Error`); the slot stays
    /// because postcard indexes by position. Use `GetRoutesPage`.
    GetRoutes,
    /// Removed in #723 (answered with `BgpEvent::Error`); the slot stays.
    /// Use `GetFlowspecRoutesPage`.
    GetFlowspecRoutes,
    /// Removed in #723 (answered with `BgpEvent::Error`); the slot stays.
    /// Use `GetVpnRoutesPage`.
    GetVpnRoutes {
        /// `Vpnv4Unicast` or `Vpnv6Unicast`; any other family has none.
        family: crate::AddressFamily,
        /// The Route Distinguisher text (`65001:1`) to filter on.
        rd: Option<String>,
    },
    /// Fire-and-forget, no reply, `nos-ribd` only: one VRF's best routes
    /// exported as VPN routes into this (underlay) instance. `table` scopes
    /// a `Full`, like `RedistributeEvpnPrefixes`.
    RedistributeVpnPrefixes {
        /// Routing table (VRF) the update belongs to.
        table: String,
        /// The export change.
        update: VpnPrefixUpdate,
    },
    /// One-shot: up to `limit` unicast routes strictly after `after` (`None`:
    /// from the start), in `(prefix, peer, path id)` order; answered by
    /// `BgpEvent::RoutesPage` (#722). `nos-bgpd` keeps a sorted key snapshot
    /// per connection (see `docs/ipc-protocols.md`) and clamps `limit` to
    /// [`BGP_PAGE_MAX`] (0 means the maximum).
    GetRoutesPage {
        /// Cursor: the last key of the previous page.
        after: Option<BgpRouteCursor>,
        /// Most routes wanted.
        limit: u32,
    },
    /// One-shot: up to `limit` received EVPN routes strictly after `after`,
    /// in `(peer, route text)` order; answered by `BgpEvent::EvpnRoutesPage`
    /// (#723). Same snapshot and clamping rules as `GetRoutesPage`.
    GetEvpnRoutesPage {
        /// Cursor: the last key of the previous page.
        after: Option<EvpnRouteCursor>,
        /// Most routes wanted.
        limit: u32,
    },
    /// One-shot: up to `limit` received Flowspec routes strictly after
    /// `after`, in `(peer, family, rule text)` order; answered by
    /// `BgpEvent::FlowspecRoutesPage` (#723).
    GetFlowspecRoutesPage {
        /// Cursor: the last key of the previous page.
        after: Option<FlowspecRouteCursor>,
        /// Most routes wanted.
        limit: u32,
    },
    /// One-shot: up to `limit` received VPN paths of `family` (only those of
    /// Route Distinguisher `rd` when set) strictly after `after`, in
    /// `(peer, RD, prefix)` order; answered by `BgpEvent::VpnRoutesPage`
    /// (#723). The snapshot is rebuilt when `family` or `rd` differ from the
    /// previous page request on the connection.
    GetVpnRoutesPage {
        /// `Vpnv4Unicast` or `Vpnv6Unicast`; any other family has none.
        family: crate::AddressFamily,
        /// The Route Distinguisher text (`65001:1`) to filter on.
        rd: Option<String>,
        /// Cursor: the last key of the previous page.
        after: Option<VpnRouteCursor>,
        /// Most paths wanted.
        limit: u32,
    },
    /// One-shot: every configured `bmp-station`'s connection state and frame
    /// counters (`show bgp bmp`, #864); answered by `BgpEvent::BmpStatus`
    /// (or `BgpEvent::Error` when `instance` is not this daemon's).
    ShowBmp {
        /// The BGP instance asked; a daemon of another instance refuses.
        instance: String,
    },
}

/// Most routes `nos-bgpd` returns in one page of any paged query, and the
/// default page size of `show bgp routes` and `GET /v1/bgp/routes`.
pub const BGP_PAGE_MAX: u32 = 1000;

/// Position in `show bgp routes`: the existing sort key of a path. `None`
/// peer (a locally redistributed route) sorts first. Its text form (REST
/// `after` / `pagination.next`) is opaque, see [`crate::page`].
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BgpRouteCursor {
    /// The prefix.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix: IpNet,
    /// The advertising peer; `None` for a locally redistributed route.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub peer: Option<IpAddr>,
    /// The RFC 7911 path id (0 without ADD-PATH).
    pub path_id: u32,
}

impl std::fmt::Display for BgpRouteCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::page::encode(self))
    }
}

impl std::str::FromStr for BgpRouteCursor {
    type Err = crate::page::BadCursor;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::page::decode(s)
    }
}

/// Position in `show bgp evpn`: the existing sort key of a route, the
/// advertising peer then the NLRI text. Opaque text form, see [`crate::page`].
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EvpnRouteCursor {
    /// The advertising peer.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub peer: IpAddr,
    /// The NLRI rendered as text (`EvpnRouteSummary::route`).
    pub route: String,
}

/// Position in `show bgp flowspec`: peer, address family text, rule text.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowspecRouteCursor {
    /// The advertising peer.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub peer: IpAddr,
    /// The address family, rendered as text.
    pub family: String,
    /// The rule rendered as text (`FlowspecRouteSummary::nlri`).
    pub nlri: String,
}

/// Position in `show bgp vpnv4|vpnv6`: peer, RD (8 wire bytes), prefix.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VpnRouteCursor {
    /// The advertising peer.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub peer: IpAddr,
    /// The Route Distinguisher in its 8-byte wire form.
    pub rd: [u8; 8],
    /// The customer prefix.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix: IpNet,
}

/// `Display`/`FromStr` of a cursor: its opaque text form.
macro_rules! cursor_text {
    ($($t:ty),*) => {$(
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&crate::page::encode(self))
            }
        }
        impl std::str::FromStr for $t {
            type Err = crate::page::BadCursor;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                crate::page::decode(s)
            }
        }
    )*};
}
cursor_text!(EvpnRouteCursor, FlowspecRouteCursor, VpnRouteCursor);

/// Messages sent from `nos-bgpd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum BgpEvent {
    /// Reply to the summary query: one entry per peer.
    Summary(Vec<PeerSummary>),
    /// Reply to `SendRouteRefresh`: the command was delivered to a live,
    /// `Established` session for that peer.
    RouteRefreshSent,
    /// Reply to `SendRouteRefresh`: no `Established` session with that peer
    /// exists right now. Reply to `ClearPeer`: that peer isn't configured.
    PeerNotFound,
    /// Unused since #723; the slot stays for the wire indexes.
    EvpnRoutes(Vec<EvpnRouteSummary>),
    /// Reply to `ClearPeer`.
    PeerCleared,
    /// Reply to `GetRpkiSummary`.
    RpkiSummary(Vec<RpkiCacheStatus>),
    /// Unused since #722; the slot stays for the wire indexes.
    Routes(Vec<BgpRouteSummary>),
    /// Unused since #723; the slot stays for the wire indexes.
    FlowspecRoutes(Vec<FlowspecRouteSummary>),
    /// Unused since #723; the slot stays for the wire indexes.
    VpnRoutes(Vec<VpnRouteSummary>),
    /// Reply to `GetRoutesPage`: routes in key order; `next` is the cursor of
    /// the following page, `None` on the last.
    RoutesPage {
        /// The page.
        routes: Vec<BgpRouteSummary>,
        /// Pass back as `after`; `None` when this was the last page.
        next: Option<BgpRouteCursor>,
    },
    /// A human-readable error (the removed unpaged queries answer with it).
    Error(String),
    /// Reply to `GetEvpnRoutesPage`.
    EvpnRoutesPage {
        /// The page.
        routes: Vec<EvpnRouteSummary>,
        /// Pass back as `after`; `None` when this was the last page.
        next: Option<EvpnRouteCursor>,
    },
    /// Reply to `GetFlowspecRoutesPage`.
    FlowspecRoutesPage {
        /// The page.
        routes: Vec<FlowspecRouteSummary>,
        /// Pass back as `after`; `None` when this was the last page.
        next: Option<FlowspecRouteCursor>,
    },
    /// Reply to `GetVpnRoutesPage`.
    VpnRoutesPage {
        /// The page.
        routes: Vec<VpnRouteSummary>,
        /// Pass back as `after`; `None` when this was the last page.
        next: Option<VpnRouteCursor>,
    },
    /// Reply to `SendRouteRefresh` for a peer with soft reconfiguration
    /// inbound: the import policy was re-evaluated locally against the
    /// retained routes (no Route Refresh sent). One entry per family with
    /// retention enabled, in `ReevalFamily` order.
    SoftInReevaluated {
        /// Per-family counts of the finished pass.
        families: Vec<FamilyReeval>,
    },
    /// Reply to `ShowBmp`: one entry per configured `bmp-station`.
    BmpStatus(Vec<BmpStationStatus>),
}

/// Connection state of one `bmp-station`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum BmpStationState {
    /// Dialing the collector.
    #[default]
    Connecting,
    /// The TCP session is up.
    Connected,
    /// Waiting out the reconnect delay after a failure.
    Backoff,
}

/// BMP messages sent to one station, by type, since its task started.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BmpFrameCounts {
    /// Initiation.
    pub initiation: u64,
    /// Peer Up.
    pub peer_up: u64,
    /// Peer Down.
    pub peer_down: u64,
    /// Route Monitoring, pre-policy.
    pub route_monitoring_pre: u64,
    /// Route Monitoring, post-policy.
    pub route_monitoring_post: u64,
    /// End-of-RIB markers (a Route Monitoring message with no routes), either
    /// stream; not counted in the two fields above.
    pub end_of_rib: u64,
    /// Statistics Report.
    pub stats: u64,
    /// Termination.
    pub termination: u64,
}

/// One `bmp-station`'s status, for `show bgp bmp`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BmpStationStatus {
    /// The `bmp-station` name.
    pub name: String,
    /// The collector's address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: IpAddr,
    /// The collector's TCP port.
    pub port: u16,
    /// Connection state.
    pub state: BmpStationState,
    /// Unix seconds the current connection came up; `None` unless connected.
    pub connected_since: Option<u64>,
    /// The policy view this station gets.
    pub monitor: crate::BmpMonitor,
    /// Seconds between Statistics Reports; `None` = none.
    pub statistics_interval: Option<u32>,
    /// Established peers reported to the station.
    pub peers_monitored: u32,
    /// Messages sent, by type.
    pub frames_sent: BmpFrameCounts,
    /// Queue overflows (each one resynchronised the station).
    pub overflows: u64,
    /// Dial attempts after the first (a lost or failed connection retried).
    pub reconnects: u64,
    /// Why the last dial or session failed.
    pub last_error: Option<String>,
}

/// Address family of a soft-reconfiguration re-evaluation. Variants are only
/// ever appended (postcard is positional); all are defined up front so the
/// later EVPN/Flowspec/VPN retention (#866) never changes the wire.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReevalFamily {
    /// IPv4 unicast.
    Ipv4Unicast,
    /// IPv6 unicast.
    Ipv6Unicast,
    /// L2VPN EVPN.
    L2vpnEvpn,
    /// IPv4 Flowspec.
    Ipv4Flowspec,
    /// IPv6 Flowspec.
    Ipv6Flowspec,
    /// `VPNv4`.
    Vpnv4,
    /// `VPNv6`.
    Vpnv6,
}

impl ReevalFamily {
    /// Kebab-case name, as in log lines and the REST reply.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4Unicast => "ipv4-unicast",
            Self::Ipv6Unicast => "ipv6-unicast",
            Self::L2vpnEvpn => "l2vpn-evpn",
            Self::Ipv4Flowspec => "ipv4-flowspec",
            Self::Ipv6Flowspec => "ipv6-flowspec",
            Self::Vpnv4 => "vpnv4",
            Self::Vpnv6 => "vpnv6",
        }
    }
}

impl std::fmt::Display for ReevalFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One family's result of a soft-reconfiguration re-evaluation.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyReeval {
    /// The family.
    pub family: ReevalFamily,
    /// Routes held pre-policy for the peer in this family.
    pub retained: u32,
    /// Of those, how many the import policy accepts.
    pub accepted: u32,
}

#[cfg(test)]
mod tests {
    #[test]
    fn community_names_and_joined_rendering() {
        use super::{community_name, fmt_communities};
        for (c, n) in [
            (0xFFFF_0000, "graceful-shutdown"),
            (0xFFFF_0001, "accept-own"),
            (0xFFFF_029A, "blackhole"),
            (0xFFFF_FF01, "no-export"),
            (0xFFFF_FF02, "no-advertise"),
            (0xFFFF_FF03, "no-export-subconfed"),
            (0xFFFF_FF04, "no-peer"),
        ] {
            assert_eq!(community_name(c), Some(n));
            assert_eq!(fmt_communities(&[c]), n);
        }
        assert_eq!(fmt_communities(&[0xFDE9_0064]), "65001:100");
        assert_eq!(fmt_communities(&[0xFFFF_0002]), "65535:2");
        assert_eq!(fmt_communities(&[]), "");
        assert_eq!(
            fmt_communities(&[0xFFFF_0000, 0xFDE9_0064]),
            "graceful-shutdown 65001:100"
        );
    }

    use super::*;
    use crate::chunk::FullStaging;
    use std::net::Ipv6Addr;

    fn route(i: u32) -> RedistributedRoute {
        let (prefix, gateway) = if i.is_multiple_of(2) {
            (
                IpNet::new(IpAddr::from(Ipv4Addr::from(i << 8)), 24).unwrap(),
                IpAddr::from([10, 0, 0, 1]),
            )
        } else {
            (
                IpNet::new(IpAddr::from(Ipv6Addr::from(u128::from(i) << 64)), 64).unwrap(),
                IpAddr::from(Ipv6Addr::LOCALHOST),
            )
        };
        RedistributedRoute { prefix, gateway }
    }

    fn routes(n: u32) -> Vec<RedistributedRoute> {
        (0..n).map(route).collect()
    }

    #[test]
    fn reeval_family_names_are_kebab_case() {
        assert_eq!(ReevalFamily::Ipv4Unicast.to_string(), "ipv4-unicast");
        assert_eq!(ReevalFamily::Vpnv6.to_string(), "vpnv6");
        assert!(ReevalFamily::Ipv4Unicast < ReevalFamily::Ipv6Unicast);
    }

    #[test]
    fn redistribute_chunk_reads_the_env_hook() {
        assert_eq!(parse_chunk(None), REDISTRIBUTE_CHUNK);
        assert_eq!(parse_chunk(Some("junk")), REDISTRIBUTE_CHUNK);
        assert_eq!(parse_chunk(Some("0")), REDISTRIBUTE_CHUNK);
        assert_eq!(parse_chunk(Some(" 64 ")), 64);
    }

    #[test]
    fn small_full_and_incrementals_are_not_split() {
        use RedistributeUpdate::{Add, Full, Remove};
        assert_eq!(Full(vec![]).split_with(3), [Full(vec![])]);
        assert_eq!(
            Full(routes(3)).split_with(3),
            [Full(routes(3))],
            "exact fit"
        );
        assert_eq!(Add(route(1)).split_with(1), [Add(route(1))]);
        let p = route(1).prefix;
        assert_eq!(Remove(p).split_with(1), [Remove(p)]);
    }

    #[test]
    fn a_big_full_is_cut_in_order_and_closed_by_a_full() {
        let frames = RedistributeUpdate::Full(routes(10)).split_with(3);
        assert_eq!(frames.len(), 4);
        let (last, parts) = frames.split_last().unwrap();
        assert_eq!(last, &RedistributeUpdate::Full(vec![route(9)]));
        let mut rejoined = Vec::new();
        for p in parts {
            let RedistributeUpdate::FullPart(r) = p else {
                panic!("{p:?}")
            };
            assert_eq!(r.len(), 3);
            rejoined.extend(r.iter().cloned());
        }
        rejoined.push(route(9));
        assert_eq!(rejoined, routes(10));
    }

    #[test]
    fn absorb_stages_parts_closes_with_the_full_and_passes_incrementals() {
        let mut st = FullStaging::default();
        let mut got = None;
        for f in RedistributeUpdate::Full(routes(10)).split_with(4) {
            assert!(got.is_none(), "nothing before the closing Full");
            got = f.absorb(&mut st);
        }
        // v4 and v6 entries both survive the round trip.
        assert_eq!(got, Some((RedistributeUpdate::Full(routes(10)), 3)));
        assert!(!st.is_staging());
        let add = RedistributeUpdate::Add(route(1));
        assert_eq!(add.clone().absorb(&mut st), Some((add, 1)));
        let small = RedistributeUpdate::Full(routes(2));
        assert_eq!(small.clone().absorb(&mut st), Some((small, 1)));
    }

    fn vpn(i: u8, rts: usize) -> VpnPrefix {
        VpnPrefix {
            rd: [0, 0, 0, 0, 0, 0, 0, 1],
            prefix: IpNet::new(IpAddr::from([10, i, 0, 0]), 24).unwrap(),
            labels: vec![1000],
            ext_communities: vec![u64::MAX; rts],
        }
    }

    /// #791: a VPN export `Full` is cut by encoded bytes, rejoins in order
    /// through `absorb`, and incrementals pass through untouched.
    #[test]
    fn vpn_full_splits_by_bytes_and_absorbs_back() {
        use VpnPrefixUpdate::{Add, Full, FullPart, Remove};
        let all: Vec<_> = (0..40).map(|i| vpn(i, usize::from(i % 5) * 4)).collect();
        let budget = 300;
        let frames = Full(all.clone()).split_with(budget);
        assert!(frames.len() > 2);
        let (last, parts) = frames.split_last().unwrap();
        assert!(matches!(last, Full(_)));
        assert!(parts.iter().all(|f| matches!(f, FullPart(_))));
        for f in &frames {
            let (Full(r) | FullPart(r)) = f else {
                unreachable!()
            };
            let bytes: usize = r
                .iter()
                .map(|v| postcard::to_allocvec(v).unwrap().len())
                .sum();
            assert!(bytes <= budget, "{bytes}");
        }
        let mut st = FullStaging::default();
        let mut got = None;
        for f in frames {
            assert!(got.is_none(), "nothing before the closing Full");
            got = f.absorb(&mut st);
        }
        let (u, n) = got.unwrap();
        assert_eq!(u, Full(all));
        assert!(n > 2);
        assert_eq!(Full(vec![]).split_with(1), [Full(vec![])]);
        assert_eq!(Add(vpn(1, 0)).split_with(1), [Add(vpn(1, 0))]);
        let rm = Remove([0; 8], vpn(1, 0).prefix);
        assert_eq!(rm.clone().split_with(1), std::slice::from_ref(&rm));
        assert_eq!(rm.clone().absorb(&mut st), Some((rm, 1)));
    }

    /// `FullPart` is appended: variants 0-2 keep their wire index.
    #[test]
    fn vpn_full_part_is_the_last_wire_variant() {
        let idx = |u: VpnPrefixUpdate| postcard::to_allocvec(&u).unwrap()[0];
        assert_eq!(idx(VpnPrefixUpdate::Full(vec![])), 0);
        assert_eq!(idx(VpnPrefixUpdate::Remove([0; 8], vpn(1, 0).prefix)), 2);
        assert_eq!(idx(VpnPrefixUpdate::FullPart(vec![])), 3);
    }

    /// A `Full` over `MAX_FRAME` is cut so every frame, at the production
    /// budget, still encodes.
    #[test]
    #[cfg_attr(miri, ignore = "encodes >16 MiB frames, minutes under the interpreter")]
    fn a_vpn_full_over_max_frame_splits_under_it() {
        use tokio_util::codec::Encoder;
        let all: Vec<_> = (0..=255).map(|i| vpn(i, 8000)).collect();
        let req = |u| BgpRequest::RedistributeVpnPrefixes {
            table: "red".into(),
            update: u,
        };
        let encode = |u| {
            crate::IpcCodec::<BgpRequest>::default().encode(req(u), &mut bytes::BytesMut::new())
        };
        assert!(encode(VpnPrefixUpdate::Full(all.clone())).is_err());
        let frames = VpnPrefixUpdate::Full(all).split_with(crate::fdb::EVPN_PUSH_BYTES);
        assert!(frames.len() > 1);
        for f in frames {
            assert!(encode(f).is_ok());
        }
    }

    /// A chunk of the widest routes (IPv6 prefix and gateway) fits one frame.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "serialises a full chunk, minutes under the interpreter"
    )]
    fn a_chunk_of_worst_case_routes_fits_max_frame() {
        let worst = RedistributedRoute {
            prefix: IpNet::new(IpAddr::from(Ipv6Addr::from(u128::MAX)), 128).unwrap(),
            gateway: IpAddr::from(Ipv6Addr::from(u128::MAX)),
        };
        let req = BgpRequest::RedistributeRoutes(RedistributeUpdate::Full(vec![
            worst;
            REDISTRIBUTE_CHUNK
        ]));
        let len = postcard::to_allocvec(&req).unwrap().len();
        assert!(len < crate::codec::MAX_FRAME / 4, "{len}");
    }
}
