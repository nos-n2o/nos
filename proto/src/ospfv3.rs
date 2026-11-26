//! `nos-ospfv3d`'s IPC query protocol — backs `nos-cli`'s `show ospfv3
//! neigh`/`show ospfv3 database`. Mirrors `ospf`'s shape (`NeighborSummary`/
//! `LsaSummary`/`OspfRequest`/`OspfEvent`) — reuses `OspfNeighborState`/
//! `LinkInterfaceState` directly rather than duplicating them, since both are
//! already address-family-agnostic (RFC 5340 doesn't change the neighbor FSM
//! or interface-state ladder — see `nos_ospf_common::neighbor`/`election`'s
//! doc comments).

use std::net::{Ipv4Addr, Ipv6Addr};

use nos_proto_derive::View;
use serde::{Deserialize, Serialize};

use crate::ospf::{LinkInterfaceState, NeighborRole, OspfNeighborState};
use crate::schema::NetworkType;

/// One neighbor's summary row, for `show ospfv3 neigh` — mirrors
/// `ospf::NeighborSummary` exactly (nothing in it is an address field beyond
/// router-ids, so it needs no IPv6-specific fields either).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, View)]
pub struct Ospfv3NeighborSummary {
    /// The attach point's display name, matching `nos-ospfv3d`'s own
    /// `"<interface>.<tag>"`/`"broadcast-domain:<name>"` convention.
    #[view(brief, sort, order = 6)]
    pub link: String,
    /// Area the interface or LSA belongs to.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[view(header = "area", text, order = 10)]
    pub area_id: Ipv4Addr,
    /// State of the local interface.
    #[view(header = "if-state", text, order = 11)]
    pub interface_state: LinkInterfaceState,
    /// Neighbor's Router ID, once heard.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, header = "neighbor-id", text, order = 0)]
    pub neighbor_router_id: Option<Ipv4Addr>,
    /// Neighbor state (RFC 5340 section 4.2.1, as RFC 2328 section 10.1).
    #[view(brief, text, order = 2)]
    pub state: OspfNeighborState,
    /// Seconds since the last Hello from this neighbor.
    #[view(header = "last-hello", unit = secs, order = 12)]
    pub last_hello_secs: Option<u64>,
    /// `HelloInterval` in seconds.
    #[view(unit = secs, order = 13)]
    pub hello_interval: u16,
    /// `RouterDeadInterval` in seconds.
    #[view(unit = secs, order = 14)]
    pub dead_interval: u16,
    /// Our Router Priority on the link.
    #[view(order = 15)]
    pub priority: u8,
    /// Neighbor's Router Priority, once heard.
    #[view(brief, header = "pri", order = 1)]
    pub neighbor_priority: Option<u8>,
    /// Designated Router on the link, if elected.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(text, order = 16)]
    pub dr: Option<Ipv4Addr>,
    /// Backup Designated Router on the link, if elected.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(text, order = 17)]
    pub bdr: Option<Ipv4Addr>,
    /// The neighbor's address on the link (its source address in Hello).
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, text, order = 5)]
    pub address: Option<Ipv6Addr>,
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

/// One running `OSPFv3` interface, for `show ospfv3 interface` (#1438) —
/// mirrors `ospf::InterfaceSummary`, with the link-local address, the
/// Interface ID and the advertised prefixes.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, View)]
pub struct Ospfv3InterfaceSummary {
    /// The attach point's display name.
    #[view(brief, sort, header = "link", order = 0)]
    pub link: String,
    /// The kernel device the link runs on.
    #[view(brief, header = "device", text, order = 1)]
    pub kernel_interface: String,
    /// RFC 5340 Interface ID (the kernel ifindex).
    #[view(brief, header = "if-id", order = 2)]
    pub interface_id: u32,
    /// Area the interface belongs to.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[view(brief, header = "area", text, order = 3)]
    pub area_id: Ipv4Addr,
    /// The interface's link-local address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[view(brief, header = "address", text, order = 4)]
    pub address: Ipv6Addr,
    /// The RFC 2328 network type.
    #[view(brief, header = "type", text, order = 5)]
    pub network_type: NetworkType,
    /// State of the interface.
    #[view(brief, header = "state", text, order = 6)]
    pub state: LinkInterfaceState,
    /// Interface output cost.
    #[view(brief, header = "cost", order = 7)]
    pub cost: u16,
    /// `HelloInterval` in seconds.
    #[view(brief, header = "hello", unit = secs, order = 8)]
    pub hello_interval: u16,
    /// `RouterDeadInterval` in seconds.
    #[view(brief, header = "dead", unit = secs, order = 9)]
    pub dead_interval: u16,
    /// `RxmtInterval` in seconds (the fixed protocol constant, not configurable).
    #[view(brief, header = "rxmt", unit = secs, order = 10)]
    pub retransmit_interval: u16,
    /// This link's configured Router Priority.
    #[view(order = 11)]
    pub priority: u8,
    /// The elected Designated Router, if any.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, header = "dr", text, order = 12)]
    pub dr: Option<Ipv4Addr>,
    /// The elected Backup Designated Router, if any.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, header = "bdr", text, order = 13)]
    pub bdr: Option<Ipv4Addr>,
    /// Known neighbors on the link.
    #[view(brief, header = "neighbors", unit = count, order = 14)]
    pub neighbor_count: u32,
    /// Neighbors that reached `Full`.
    #[view(brief, header = "full", unit = count, order = 15)]
    pub full_neighbor_count: u32,
    /// The link's MTU.
    #[view(order = 16)]
    pub mtu: u16,
    /// Whether the DBD MTU mismatch check is off.
    #[view(unit = bool, order = 17)]
    pub mtu_ignore: bool,
    /// Every prefix the link advertises.
    #[view(text, order = 18)]
    pub prefixes: Vec<String>,
}

/// One installed LSA's header fields, for `show ospfv3 database` — mirrors
/// `ospf::LsaSummary`, with `lsa_type` widened to `u16`: RFC 5340's LS Type
/// word carries the U-bit/S2/S1 scope bits alongside the function code.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ospfv3LsaSummary {
    /// Area the interface or LSA belongs to.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub area_id: Ipv4Addr,
    /// LS type including the U/S2/S1 scope bits (RFC 5340 section A.4.2.1).
    pub lsa_type: u16,
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
    /// The owning link's attach point (same naming as
    /// `Ospfv3NeighborSummary.link`) for a link-local-scoped LSA (RFC 5340
    /// §4.5.1: Link-LSA/E-Link-LSA, held per link and never flooded past
    /// it); `None` for an area-scoped one.
    pub link: Option<String>,
    /// A Router-LSA's flags (RFC 5340 A.4.3: B 0x01, E 0x02, V 0x04, Nt
    /// 0x10); `None` for every other type.
    #[serde(default)]
    pub router_flags: Option<u8>,
    /// A Router-LSA's virtual links (type-4 links): the far endpoints'
    /// router ids.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub virtual_links: Vec<Ipv4Addr>,
}

/// One computed route, for `show ospfv3 route` (#1453); `ospf::RouteSummary`'s twin.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, View)]
pub struct Ospfv3RouteSummary {
    /// The destination, `"<address>/<prefix-len>"`.
    #[view(brief, sort, header = "prefix", order = 0)]
    pub prefix: String,
    /// How the route was learned.
    #[view(brief, header = "class", text, order = 1)]
    pub class: crate::ospf::RoutePathClass,
    /// Cost to the destination (external-2: the internal distance).
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
    /// The router the cost was built toward; `None` for a transit network.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, header = "adv-router", text, order = 6)]
    pub advertising_router: Option<Ipv4Addr>,
}

/// Messages sent from a client to one `nos-ospfv3d` instance's IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum Ospfv3Request {
    /// One-shot: every configured link's current neighbor summary.
    GetNeighbors,
    /// One-shot: every installed LSA's header, across every area.
    GetDatabase,
    /// Fire-and-forget, no reply — `OspfRequest::RedistributeRoutes`'s
    /// `OSPFv3` twin, sent by the owning table's `nos-ribd`: the IPv6 routes
    /// to originate as RFC 5340 AS-External-LSAs.
    RedistributeRoutes(crate::bgp::RedistributeUpdate),
    /// One-shot: every running interface's summary (#1438).
    GetInterfaces,
    /// One-shot: the computed routes (#1453).
    GetRoutes,
    /// One-shot: this instance's own summary (#1439).
    GetInstance,
}

/// Messages sent from `nos-ospfv3d` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum Ospfv3Event {
    /// Reply with the neighbors.
    Neighbors(Vec<Ospfv3NeighborSummary>),
    /// Reply with the LSDB summary.
    Database(Vec<Ospfv3LsaSummary>),
    /// Reply with the interfaces.
    Interfaces(Vec<Ospfv3InterfaceSummary>),
    /// Reply with the routes.
    Routes(Vec<Ospfv3RouteSummary>),
    /// Reply with the instance summary (the same type as `OSPFv2`'s).
    Instance(crate::InstanceSummary),
}
