//! `nos-lacpd`'s IPC query protocol — backs `nos-cli`'s `show lacp`. Mirrors
//! `bgp`/`ospf`'s shape: a one-shot `GetSummary` request/event pair framed
//! by `IpcCodec` over a Unix socket resolved via the watchdog broker
//! (`ServiceRef::Lacp` — a single, system-wide instance, so unlike
//! `BgpRequest`/`OspfRequest` there is no per-instance socket to pick
//! between).

use serde::{Deserialize, Serialize};

/// 802.1AX §6.4.12 Receive Machine states.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LacpReceiveState {
    /// `INITIALIZE` (IEEE 802.1AX section 6.4.12).
    Initialize,
    /// `PORT_DISABLED`.
    PortDisabled,
    /// `LACP_DISABLED`.
    LacpDisabled,
    /// `EXPIRED`.
    Expired,
    /// `DEFAULTED`.
    Defaulted,
    /// `CURRENT`.
    Current,
}

/// 802.1AX §6.4.15 Mux Machine states. `Distributing` is the only state in
/// which this port belongs in the aggregate's active-member set pushed to
/// `nos-interfaced` (`nos_proto::interface::LacpAggregateMembers`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LacpMuxState {
    /// `DETACHED` (IEEE 802.1AX section 6.4.15).
    Detached,
    /// `WAITING`.
    Waiting,
    /// `ATTACHED`.
    Attached,
    /// `COLLECTING`.
    Collecting,
    /// `DISTRIBUTING`.
    Distributing,
}

/// One member port's current LACP state, for `show lacp`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // wire status flags, one per fact
pub struct LacpPortStatus {
    /// Member port name.
    pub interface: String,
    /// Actor Port number (IEEE 802.1AX section 6.4.2).
    pub actor_port_number: u16,
    /// Receive machine state.
    pub receive_state: LacpReceiveState,
    /// Mux machine state.
    pub mux_state: LacpMuxState,
    /// The partner's system id as last heard; the administrative default
    /// (system all-zero, key 1, port 1, priorities 0xffff/0xff, as Linux
    /// `bond_3ad.c`) while `Defaulted` or before any LACPDU was received.
    /// Kept (not reset) while `Expired`.
    pub partner_system_id: Option<[u8; 6]>,
    /// Partner Operational Key; the administrative default (1) while defaulted.
    pub partner_key: Option<u16>,
    /// Partner Port number; the administrative default (1) while defaulted.
    pub partner_port_number: Option<u16>,
    /// This port's advertised Actor Port Priority.
    pub actor_port_priority: u16,
    /// This port's configured `lacp-mode` (`Actor_State.LACP_Activity`).
    pub mode: crate::schema::LacpMode,
    /// Partner System Priority; the administrative default (0xffff) while defaulted.
    pub partner_system_priority: Option<u16>,
    /// Partner Port Priority; the administrative default (0xff) while defaulted.
    pub partner_port_priority: Option<u16>,
    /// This port's Selection Logic outcome (`selection.rs`) — `true` iff it
    /// agrees with the aggregate's other `Current` ports on partner
    /// identity.
    pub selected: bool,
    /// The partner's advertised Synchronization bit on its most recent
    /// LACPDU.
    pub synchronized: bool,
    /// 802.1AX §6.4.17: this port's own side has been out of sync for a whole
    /// churn-detection time. A churned port is kept out of the bond.
    pub actor_churn: bool,
    /// Same, for the partner's advertised state.
    pub partner_churn: bool,
    /// The partner's last LACPDU had `Actor_State.Aggregation` clear: it
    /// treats this link as an Individual (non-aggregatable) one, so the port
    /// is never selected into the bond.
    pub individual: bool,
    /// LACPDUs dropped because their Version byte was neither 1 nor 2. In
    /// memory only: restarts at 0 with the port's link task. Last field:
    /// postcard is positional (daemons and CLI ship together).
    pub unsupported_version_pdus: u64,
    /// The partner's LACP version from its last LACPDU (appended, #892);
    /// `None` until one is received.
    pub partner_version: Option<u8>,
    /// The partner's advertised Port Algorithm, if any.
    pub partner_port_algorithm: Option<crate::schema::LacpPortAlgorithm>,
}

/// Whether both ends agreed on conversation-sensitive operation.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LacpAgreement {
    /// Not running version 2 with an algorithm, or nothing negotiated yet.
    NotApplicable,
    /// Both ends v2 with the same algorithm and matching digests.
    Agreed,
    /// v2 on both ends but algorithm or digest differ: plain hashing.
    Mismatch,
    /// The partner speaks version 1: plain hashing.
    V1Partner,
}

/// One `PortAggregate`'s LACP engine state, for `show lacp [<name>]`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortAggregateLacpSummary {
    /// Port aggregate name.
    pub aggregate: String,
    /// Actor System ID (MAC address).
    pub actor_system_id: [u8; 6],
    /// Actor Operational Key.
    pub actor_key: u16,
    /// The aggregate's advertised Actor System Priority.
    pub actor_system_priority: u16,
    /// The aggregate's configured `lacp-rate`.
    pub rate: crate::schema::LacpRate,
    /// The aggregate's configured `min-links`.
    pub min_links: u16,
    /// Whether enough ports are Distributing to meet `min_links`; `false`
    /// means the bond was emptied even though ports may be negotiating.
    pub min_links_met: bool,
    /// Member ports.
    pub ports: Vec<LacpPortStatus>,
    /// The configured `lacp-version` (appended, #892).
    pub version: crate::schema::LacpVersion,
    /// The configured `lacp-port-algorithm`.
    pub port_algorithm: crate::schema::LacpPortAlgorithm,
    /// Conversation-sensitive agreement with the partner.
    pub agreement: LacpAgreement,
    /// Conversations carried per member link, `(member, count)`.
    pub conversations_per_link: Vec<(String, u16)>,
}

/// Messages sent from a client to `nos-lacpd`'s IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index, so reordering breaks wire compatibility with
/// already-built binaries.
#[derive(Debug, Serialize, Deserialize)]
pub enum LacpRequest {
    /// One-shot: every `Lacp`-mode aggregate's current summary.
    GetSummary,
}

/// Messages sent from `nos-lacpd` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum LacpEvent {
    /// Reply with one entry per LACP aggregate.
    Summary(Vec<PortAggregateLacpSummary>),
}
