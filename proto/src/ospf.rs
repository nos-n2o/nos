//! `nos-ospfd`'s IPC query protocol — backs `nos-cli`'s `show ospf neigh`/
//! `show ospf database`. Mirrors `bgp`'s shape: a request/event pair framed
//! by `IpcCodec` over a Unix socket resolved via the watchdog broker
//! (`ServiceRef::OspfInstance`).
//!
//! Neighbor establishment reaches the full RFC 2328 §10.5 ladder (`Down`
//! through `Full`), backed by a real per-area LSDB — see `docs/protocols/ospf-internals.md`.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

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

/// One neighbor's summary row, for `show ospf neigh` — one row per
/// currently-known neighbor on a link (see `OspfNeighborState`'s doc
/// comment for point-to-point vs. broadcast row-count semantics).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NeighborSummary {
    /// The attach point's display name, matching
    /// `reconcile::attach_points_for`'s existing `"<interface>.<tag>"`/
    /// `"broadcast-domain:<name>"` convention.
    pub link: String,
    /// Area the interface belongs to.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub area_id: Ipv4Addr,
    /// State of the local interface.
    pub interface_state: LinkInterfaceState,
    /// Known once at least one Hello has been received on this link.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub neighbor_router_id: Option<Ipv4Addr>,
    /// Neighbor state (RFC 2328 section 10.1).
    pub state: OspfNeighborState,
    /// Seconds since the last Hello was received from this neighbor. `None`
    /// if none has ever been received.
    pub last_hello_secs: Option<u64>,
    /// `HelloInterval` in seconds (RFC 2328 section 9.5).
    pub hello_interval: u16,
    /// `RouterDeadInterval` in seconds.
    pub dead_interval: u16,
    /// This link's own configured Router Priority — mirrors how
    /// `hello_interval`/`dead_interval` already report the *local* link's
    /// config on every row.
    pub priority: u8,
    /// The remote neighbor's own decoded Router Priority. `None` if no
    /// Hello has been received from it yet.
    pub neighbor_priority: Option<u8>,
    /// This link's currently elected DR/BDR — `None` on a point-to-point
    /// link (no election ever runs) or before a broadcast link's first
    /// election.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub dr: Option<Ipv4Addr>,
    /// Backup Designated Router on the link, if elected.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub bdr: Option<Ipv4Addr>,
    /// The neighbor's RFC 5613 LLS data. `None` when it sent no valid LLS
    /// block, or LLS is off on this link.
    #[serde(default)]
    pub lls: Option<LlsSummary>,
}

/// A neighbor's RFC 5613 Link-Local Signaling data (EOF TLV).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlsSummary {
    /// Raw Extended Options and Flags word.
    pub eof: u32,
    /// LSDB Resynchronization bit (RFC 4811), shown only.
    pub lr: bool,
    /// Restart Signal bit (RFC 4812), shown only.
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
}

/// Messages sent from `nos-ospfd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum OspfEvent {
    /// Reply with the neighbors.
    Neighbors(Vec<NeighborSummary>),
    /// Reply with the LSDB summary.
    Database(Vec<LsaSummary>),
}
