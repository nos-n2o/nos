//! `nos-ospfv3d`'s IPC query protocol — backs `nos-cli`'s `show ospfv3
//! neigh`/`show ospfv3 database`. Mirrors `ospf`'s shape (`NeighborSummary`/
//! `LsaSummary`/`OspfRequest`/`OspfEvent`) — reuses `OspfNeighborState`/
//! `LinkInterfaceState` directly rather than duplicating them, since both are
//! already address-family-agnostic (RFC 5340 doesn't change the neighbor FSM
//! or interface-state ladder — see `nos_ospf_common::neighbor`/`election`'s
//! doc comments).

use std::net::Ipv4Addr;

use nos_proto_derive::View;
use serde::{Deserialize, Serialize};

use crate::ospf::{LinkInterfaceState, OspfNeighborState};

/// One neighbor's summary row, for `show ospfv3 neigh` — mirrors
/// `ospf::NeighborSummary` exactly (nothing in it is an address field beyond
/// router-ids, so it needs no IPv6-specific fields either).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, View)]
pub struct Ospfv3NeighborSummary {
    /// The attach point's display name, matching `nos-ospfv3d`'s own
    /// `"<interface>.<tag>"`/`"broadcast-domain:<name>"` convention.
    #[view(brief, sort)]
    pub link: String,
    /// Area the interface or LSA belongs to.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[view(brief, header = "area", text)]
    pub area_id: Ipv4Addr,
    /// State of the local interface.
    #[view(brief, header = "if-state", text)]
    pub interface_state: LinkInterfaceState,
    /// Neighbor's Router ID, once heard.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, header = "neighbor", text)]
    pub neighbor_router_id: Option<Ipv4Addr>,
    /// Neighbor state (RFC 5340 section 4.2.1, as RFC 2328 section 10.1).
    #[view(brief, text)]
    pub state: OspfNeighborState,
    /// Seconds since the last Hello from this neighbor.
    #[view(brief, header = "last-hello", unit = secs)]
    pub last_hello_secs: Option<u64>,
    /// `HelloInterval` in seconds.
    #[view(brief, unit = secs)]
    pub hello_interval: u16,
    /// `RouterDeadInterval` in seconds.
    #[view(brief, unit = secs)]
    pub dead_interval: u16,
    /// Our Router Priority on the link.
    #[view(brief)]
    pub priority: u8,
    /// Neighbor's Router Priority, once heard.
    #[view(brief)]
    pub neighbor_priority: Option<u8>,
    /// Designated Router on the link, if elected.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, text)]
    pub dr: Option<Ipv4Addr>,
    /// Backup Designated Router on the link, if elected.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[view(brief, text)]
    pub bdr: Option<Ipv4Addr>,
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
}

/// Messages sent from `nos-ospfv3d` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum Ospfv3Event {
    /// Reply with the neighbors.
    Neighbors(Vec<Ospfv3NeighborSummary>),
    /// Reply with the LSDB summary.
    Database(Vec<Ospfv3LsaSummary>),
}
