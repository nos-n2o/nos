//! `nos-ospfd`'s IPC query protocol — backs `nos-cli`'s `show ospf neigh`/
//! `show ospf database`. Mirrors `bgp`'s shape: a request/event pair framed
//! by `IpcCodec` over a Unix socket resolved via the watchdog broker
//! (`ServiceRef::OspfInstance`).
//!
//! Neighbor establishment reaches the full RFC 2328 §10.5 ladder (`Down`
//! through `Full`), backed by a real per-area LSDB — see `docs/protocols/ospf-internals.md`.

use std::net::Ipv4Addr;

use nos_proto_derive::View;
use serde::{Deserialize, Serialize};

use crate::schema::NetworkType;

/// One neighbor's state, as reported by `nos-ospfd` — the full RFC 2328
/// §10.5 ladder. `Down` is an ongoing, valid state (no Hello received yet,
/// or the dead-interval expired) — a point-to-point link always reports at
/// least one row, even `Down`; a broadcast link reports one row per
/// currently-known neighbor (zero if none yet — there's no single fixed peer
/// to show a placeholder for on a multi-access segment).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfNeighborState {
    /// No Hellos received (RFC 2328 section 10.1).
    Down,
    /// A Hello was received but our router ID is not in it.
    Init,
    /// Bidirectional communication established.
    TwoWay,
    /// Negotiating master/slave and the initial DD sequence number.
    ExStart,
    /// Exchanging Database Description packets.
    Exchange,
    /// Requesting LSAs the neighbor has and we lack.
    Loading,
    /// Databases synchronised; the adjacency is complete.
    Full,
}

/// RFC 2328 §9.1's interface states, as they apply to this phase's Hello-only
/// scope: `PointToPoint` is fixed forever on a point-to-point link (no
/// election ever runs); a broadcast link starts `Waiting`, then becomes
/// `Dr`/`Backup`/`DrOther` once RFC 2328 §9.4 election runs (see
/// `ospf::election`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkInterfaceState {
    /// Point-to-point interface (RFC 2328 section 9.1).
    PointToPoint,
    /// Waiting to learn the DR/BDR.
    Waiting,
    /// This router is the Designated Router.
    Dr,
    /// This router is the Backup Designated Router.
    Backup,
    /// Neither DR nor BDR.
    DrOther,
}

/// A neighbor's role on a broadcast link (RFC 2328 section 9.4).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NeighborRole {
    /// Designated Router.
    Dr,
    /// Backup Designated Router.
    Bdr,
    /// Neither.
    DrOther,
}

impl NeighborRole {
    /// Role of `neighbor` given the link's elected DR/BDR; `None` when no
    /// DR is known (point-to-point, still waiting, or no neighbor yet).
    #[must_use]
    pub fn of(neighbor: Ipv4Addr, dr: Option<Ipv4Addr>, bdr: Option<Ipv4Addr>) -> Option<Self> {
        let dr = dr.filter(|d| !d.is_unspecified())?;
        Some(if neighbor == dr {
            Self::Dr
        } else if Some(neighbor) == bdr {
            Self::Bdr
        } else {
            Self::DrOther
        })
    }
}

#[cfg(test)]
mod role_tests {
    use super::*;

    #[test]
    fn neighbor_role_of() {
        let a = |n| Ipv4Addr::new(n, n, n, n);
        assert_eq!(
            NeighborRole::of(a(1), Some(a(1)), Some(a(2))),
            Some(NeighborRole::Dr)
        );
        assert_eq!(
            NeighborRole::of(a(2), Some(a(1)), Some(a(2))),
            Some(NeighborRole::Bdr)
        );
        assert_eq!(
            NeighborRole::of(a(3), Some(a(1)), None),
            Some(NeighborRole::DrOther)
        );
        assert_eq!(NeighborRole::of(a(3), None, Some(a(2))), None);
        assert_eq!(
            NeighborRole::of(a(3), Some(Ipv4Addr::UNSPECIFIED), None),
            None
        );
    }
}

/// One neighbor's summary row, for `show ospf neigh` — one row per
/// currently-known neighbor on a link (see `OspfNeighborState`'s doc
/// comment for point-to-point vs. broadcast row-count semantics).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, View)]
pub struct NeighborSummary {
    /// The attach point's display name, matching
    /// `reconcile::attach_points_for`'s existing `"<interface>.<tag>"`/
    /// `"broadcast-domain:<name>"` convention.
    #[view(brief, sort, order = 6)]
    pub link: String,
    /// Area the interface belongs to.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[view(header = "area", text, order = 10)]
    pub area_id: Ipv4Addr,
    /// State of the local interface.
    #[view(header = "if-state", text, order = 11)]
    pub interface_state: LinkInterfaceState,
    /// Known once at least one Hello has been received on this link.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, header = "neighbor-id", text, order = 0)]
    pub neighbor_router_id: Option<Ipv4Addr>,
    /// Neighbor state (RFC 2328 section 10.1).
    #[view(brief, text, order = 2)]
    pub state: OspfNeighborState,
    /// Seconds since the last Hello was received from this neighbor. `None`
    /// if none has ever been received.
    #[view(header = "last-hello", unit = secs, order = 12)]
    pub last_hello_secs: Option<u64>,
    /// `HelloInterval` in seconds (RFC 2328 section 9.5).
    #[view(unit = secs, order = 13)]
    pub hello_interval: u16,
    /// `RouterDeadInterval` in seconds.
    #[view(unit = secs, order = 14)]
    pub dead_interval: u16,
    /// This link's own configured Router Priority — mirrors how
    /// `hello_interval`/`dead_interval` already report the *local* link's
    /// config on every row.
    #[view(order = 15)]
    pub priority: u8,
    /// The remote neighbor's own decoded Router Priority. `None` if no
    /// Hello has been received from it yet.
    #[view(brief, header = "pri", order = 1)]
    pub neighbor_priority: Option<u8>,
    /// This link's currently elected DR/BDR — `None` on a point-to-point
    /// link (no election ever runs) or before a broadcast link's first
    /// election.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(text, order = 16)]
    pub dr: Option<Ipv4Addr>,
    /// Backup Designated Router on the link, if elected.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(text, order = 17)]
    pub bdr: Option<Ipv4Addr>,
    /// The neighbor's RFC 5613 LLS data. `None` when it sent no valid LLS
    /// block, or LLS is off on this link.
    #[serde(default)]
    #[view(nested, order = 18)]
    pub lls: Option<LlsSummary>,
    /// The neighbor's address on the link (its source address in Hello).
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, text, order = 5)]
    pub address: Option<Ipv4Addr>,
    /// The neighbor's role on a broadcast link; `None` without an election.
    #[serde(default)]
    #[view(brief, text, order = 3)]
    pub role: Option<NeighborRole>,
    /// Seconds until the neighbor is declared dead (dead interval minus time since last heard).
    #[serde(default)]
    #[view(brief, header = "dead", unit = secs, order = 4)]
    pub dead_in_secs: Option<u64>,
    /// Seconds since the adjacency reached Full; `None` before.
    #[serde(default)]
    #[view(brief, header = "uptime", unit = secs, order = 7)]
    pub uptime_secs: Option<u64>,
}

/// One running OSPF interface, for `show ospf interface` (#1438). Only links
/// that run are listed (a passive interface or one without an address has no
/// link, a virtual link is not an attach point).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, View)]
pub struct InterfaceSummary {
    /// The attach point's display name (`"<interface>.<tag>"` or
    /// `"broadcast-domain:<name>"`).
    #[view(brief, sort, header = "link", order = 0)]
    pub link: String,
    /// The kernel device the link runs on.
    #[view(brief, header = "device", text, order = 1)]
    pub kernel_interface: String,
    /// Area the interface belongs to.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[view(brief, header = "area", text, order = 2)]
    pub area_id: Ipv4Addr,
    /// The interface address, `"<address>/<prefix-len>"`.
    #[view(brief, header = "address", text, order = 3)]
    pub address: String,
    /// The RFC 2328 network type.
    #[view(brief, header = "type", text, order = 4)]
    pub network_type: NetworkType,
    /// State of the interface (RFC 2328 section 9.1).
    #[view(brief, header = "state", text, order = 5)]
    pub state: LinkInterfaceState,
    /// Interface output cost.
    #[view(brief, header = "cost", order = 6)]
    pub cost: u16,
    /// `HelloInterval` in seconds.
    #[view(brief, header = "hello", unit = secs, order = 7)]
    pub hello_interval: u16,
    /// `RouterDeadInterval` in seconds.
    #[view(brief, header = "dead", unit = secs, order = 8)]
    pub dead_interval: u16,
    /// `RxmtInterval` in seconds (the fixed protocol constant, not configurable).
    #[view(brief, header = "rxmt", unit = secs, order = 9)]
    pub retransmit_interval: u16,
    /// This link's configured Router Priority.
    #[view(order = 10)]
    pub priority: u8,
    /// The elected Designated Router, if any.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, header = "dr", text, order = 11)]
    pub dr: Option<Ipv4Addr>,
    /// The elected Backup Designated Router, if any.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, header = "bdr", text, order = 12)]
    pub bdr: Option<Ipv4Addr>,
    /// Known neighbors on the link.
    #[view(brief, header = "neighbors", unit = count, order = 13)]
    pub neighbor_count: u32,
    /// Neighbors that reached `Full`.
    #[view(brief, header = "full", unit = count, order = 14)]
    pub full_neighbor_count: u32,
    /// The link's MTU.
    #[view(order = 15)]
    pub mtu: u16,
    /// Whether the DBD MTU mismatch check is off.
    #[view(unit = bool, order = 16)]
    pub mtu_ignore: bool,
}

/// A neighbor's RFC 5613 Link-Local Signaling data (EOF TLV).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, View)]
pub struct LlsSummary {
    /// Raw Extended Options and Flags word.
    #[view(brief, text)]
    pub eof: u32,
    /// LSDB Resynchronization bit (RFC 4811), shown only.
    #[view(brief, unit = bool)]
    pub lr: bool,
    /// Restart Signal bit (RFC 4812), shown only.
    #[view(brief, unit = bool)]
    pub rs: bool,
}

/// One installed LSA's header fields, for `show ospf database` — never the
/// full LSA body, which this NOS has no operator-facing use for yet (no SPF
/// consumer to explain a route's ancestry).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LsaSummary {
    /// Area the LSA belongs to.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub area_id: Ipv4Addr,
    /// LS type (RFC 2328 section A.4.1).
    pub lsa_type: u8,
    /// Link State ID.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub link_state_id: Ipv4Addr,
    /// Advertising Router ID.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub advertising_router: Ipv4Addr,
    /// LS sequence number.
    pub sequence_number: i32,
    /// LS age in seconds.
    pub age: u16,
    /// LS checksum.
    pub checksum: u16,
    /// An AS-external/NSSA-external LSA's metric (low 24 bits); `None` for
    /// every other type.
    pub external_metric: Option<u32>,
    /// That LSA's E bit: a metric type 2 external.
    pub external_type2: bool,
    /// A Router-LSA's flags (RFC 2328 A.4.2: B 0x01, E 0x02, V 0x04, Nt
    /// 0x10, H 0x80); `None` for every other type.
    #[serde(default)]
    pub router_flags: Option<u8>,
    /// A Router-LSA's virtual links (type-4 links, RFC 2328 §12.4.1.3): the
    /// far endpoints' router ids.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub virtual_links: Vec<Ipv4Addr>,
}

/// How an OSPF route was learned (RFC 2328 section 11).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutePathClass {
    /// Inside the area.
    #[serde(rename = "intra-area")]
    IntraArea,
    /// Via an area border router (Summary-LSA).
    #[serde(rename = "inter-area")]
    InterArea,
    /// AS-external, metric type 1.
    #[serde(rename = "external-1")]
    External1,
    /// AS-external, metric type 2.
    #[serde(rename = "external-2")]
    External2,
}

/// One computed route, for `show ospf route` (#1453).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, View)]
pub struct RouteSummary {
    /// The destination, `"<address>/<prefix-len>"`.
    #[view(brief, sort, header = "prefix", order = 0)]
    pub prefix: String,
    /// How the route was learned.
    #[view(brief, header = "class", text, order = 1)]
    pub class: RoutePathClass,
    /// Cost to the destination (for an external-2 route: the internal distance
    /// to the advertising router).
    #[view(brief, header = "cost", order = 2)]
    pub cost: u32,
    /// An external-2 route's own metric.
    #[view(brief, header = "e2-cost", order = 3)]
    pub type2_cost: Option<u32>,
    /// Area the route was computed in.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[view(brief, header = "area", text, order = 4)]
    pub area: Ipv4Addr,
    /// Next hops, `"<address>"` or `"<address> dev <interface>"`.
    #[view(brief, header = "next-hops", text, order = 5)]
    pub next_hops: Vec<String>,
    /// The router the cost was built toward; `None` for a transit network or
    /// a discard route.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, header = "adv-router", text, order = 6)]
    pub advertising_router: Option<Ipv4Addr>,
}

/// Messages sent from a client to one `nos-ospfd` instance's IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum OspfRequest {
    /// One-shot: every configured link's current neighbor summary.
    GetNeighbors,
    /// One-shot: every installed LSA's header, across every area.
    GetDatabase,
    /// Fire-and-forget, no reply — sent continuously by `nos-ribd` over one
    /// long-lived connection, the OSPF-redistribution analogue of
    /// `BgpRequest::RedistributeRoutes`: this instance's ASBR-redistributed
    /// routes (e.g. `redistribute from static to ospf`), to be originated as
    /// real RFC 2328 AS-external-LSAs.
    RedistributeRoutes(crate::bgp::RedistributeUpdate),
    /// One-shot: the segment routing state (SRGBs, Prefix-SIDs, Adj-SIDs),
    /// local and received (#1382).
    GetSegmentRouting,
    /// One-shot: every running interface's summary (#1438).
    GetInterfaces,
    /// One-shot: the computed routes (#1453).
    GetRoutes,
}

/// Messages sent from `nos-ospfd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum OspfEvent {
    /// Reply with the neighbors.
    Neighbors(Vec<NeighborSummary>),
    /// Reply with the LSDB summary.
    Database(Vec<LsaSummary>),
    /// Reply with the segment routing state.
    SegmentRouting(SrSummary),
    /// Reply with the interfaces.
    Interfaces(Vec<InterfaceSummary>),
    /// Reply with the routes.
    Routes(Vec<RouteSummary>),
}

/// `show ospf segment-routing` (#1382): what this router advertises and what
/// it learned, over every area.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrSummary {
    /// Every router's first SRGB range, ours included.
    pub srgb: Vec<SrSrgb>,
    /// Every Prefix-SID.
    pub prefix_sids: Vec<SrPrefixSid>,
    /// Every Adj-SID.
    pub adj_sids: Vec<SrAdjSid>,
}

/// One router's SRGB range (RFC 8665 §3.2).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrSrgb {
    /// The advertising router.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub router: Ipv4Addr,
    /// First label of the range.
    pub base: u32,
    /// Number of labels.
    pub size: u32,
}

/// A Prefix-SID (RFC 8665 §5) a router advertises for one prefix.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrPrefixSid {
    /// The advertising router.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub router: Ipv4Addr,
    /// The prefix address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix: Ipv4Addr,
    /// The prefix length.
    pub prefix_len: u8,
    /// An index into the SRGB, or the label itself when `absolute`.
    pub value: u32,
    /// `value` is the label itself.
    pub absolute: bool,
    /// The label in the router's own SRGB, when it is known.
    pub label: Option<u32>,
}

/// An Adj-SID or LAN Adj-SID (RFC 8665 §6, §7) a router advertises.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrAdjSid {
    /// The advertising router.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub router: Ipv4Addr,
    /// The neighbour's router id (LAN Adj-SID); `None` on a point-to-point link.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub neighbor: Option<Ipv4Addr>,
    /// The Extended Link's Link ID.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub link_id: Ipv4Addr,
    /// The advertised label (absolute).
    pub label: u32,
}
