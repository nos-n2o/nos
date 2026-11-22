//! `nos-stpd`'s IPC query protocol — backs `show spanning-tree` and
//! `GET /v1/spanning-tree`. One-shot request/event pair framed by `IpcCodec`,
//! resolved through the broker (`ServiceRef::Stp`, a single instance), like
//! `lldp`.

use serde::{Deserialize, Serialize};

use crate::schema::StpMode;

/// IEEE 802.1Q 13.4 port role (the CIST's).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StpRole {
    /// Root port: best path toward the root bridge (IEEE 802.1D section 17.7).
    Root,
    /// Designated port: forwards toward the leaves.
    Designated,
    /// Alternate port: backup path to the root.
    Alternate,
    /// Backup port: redundant path to a segment we are designated on.
    Backup,
    /// Not participating in spanning tree.
    #[default]
    Disabled,
}

impl StpRole {
    /// The name shown by `show spanning-tree`.
    pub fn as_str(self) -> &'static str {
        match self {
            StpRole::Root => "root",
            StpRole::Designated => "designated",
            StpRole::Alternate => "alternate",
            StpRole::Backup => "backup",
            StpRole::Disabled => "disabled",
        }
    }
}

/// The port state as the core sees it (the kernel's `Blocking` is `Discarding`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StpState {
    /// Discarding (IEEE 802.1D section 17.4).
    #[default]
    Discarding,
    /// Learning MACs but not forwarding.
    Learning,
    /// Forwarding.
    Forwarding,
}

impl StpState {
    /// The name shown by `show spanning-tree`.
    pub fn as_str(self) -> &'static str {
        match self {
            StpState::Discarding => "discarding",
            StpState::Learning => "learning",
            StpState::Forwarding => "forwarding",
        }
    }
}

/// Per-port BPDU and event counters, named after RFC 4318 (`dot1dStpPort*`).
/// They count since the bridge was last (re)built; in `mode mstp` the MSTIs
/// share the CIST's counters (one BPDU carries them all).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StpPortCounters {
    /// Configuration BPDUs received.
    pub in_config_bpdu: u64,
    /// TCN BPDUs received.
    pub in_tcn_bpdu: u64,
    /// RST BPDUs received.
    pub in_rstp_bpdu: u64,
    /// MST BPDUs received.
    pub in_mst_bpdu: u64,
    /// Configuration BPDUs sent.
    pub out_config_bpdu: u64,
    /// TCN BPDUs sent.
    pub out_tcn_bpdu: u64,
    /// RST BPDUs sent.
    pub out_rstp_bpdu: u64,
    /// MST BPDUs sent.
    pub out_mst_bpdu: u64,
    /// Times the port switched between 802.1D and RSTP.
    pub protocol_migration: u64,
    /// Frames dropped as malformed BPDUs.
    pub invalid_bpdu: u64,
    /// BPDUs sent with the topology-change flag, and TCN BPDUs.
    pub tc_sent: u64,
    /// BPDUs received with the topology-change flag, and TCN BPDUs.
    pub tc_received: u64,
    /// Times the port entered forwarding.
    pub forward_transitions: u64,
}

/// What started a topology change.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StpTcCause {
    /// A port of this bridge started forwarding or stopped being edge.
    Local,
    /// A neighbour flagged one (a TC or TCN BPDU).
    Received,
}

/// Topology changes of one tree (RFC 4318 `TopChanges`, `TimeSinceTopologyChange`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StpTopology {
    /// Topology changes seen.
    pub count: u64,
    /// Seconds since the last change; `None` before the first.
    pub last_secs_ago: Option<u64>,
    /// The port the last change came in on, or started at.
    pub last_port: Option<String>,
    /// Cause of the most recent topology change.
    pub last_cause: Option<StpTcCause>,
}

/// One spanning-tree port. Bridge and port ids are display strings
/// (`8000.02:aa:bb:cc:dd:ee`, `128.1`), as `LldpNeighbor` does.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one independent flag per protection, reported as-is"
)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StpPortInfo {
    /// Port name.
    pub name: String,
    /// Port role.
    pub role: StpRole,
    /// Port state.
    pub state: StpState,
    /// Path cost this port adds to the root path.
    pub cost: u32,
    /// Port priority (IEEE 802.1D section 17.3.2).
    pub priority: u8,
    /// The designated bridge/port on this port's segment.
    pub designated_bridge: String,
    /// Designated Port ID on the segment.
    pub designated_port: String,
    /// `operEdge`: the port is an edge port right now.
    #[serde(default)]
    pub edge: bool,
    /// The protections configured on the port (`stp-port-profile`, #320).
    #[serde(default)]
    pub bpdu_guard: bool,
    /// BPDU filter is enabled.
    #[serde(default)]
    pub bpdu_filter: bool,
    /// Root guard is enabled.
    #[serde(default)]
    pub root_guard: bool,
    /// Loop guard is enabled.
    #[serde(default)]
    pub loop_guard: bool,
    /// Restricted TCN is enabled (IEEE 802.1Q section 13.25).
    #[serde(default)]
    pub restricted_tcn: bool,
    /// Root guard holds the port in Discarding: a superior BPDU keeps arriving.
    #[serde(default)]
    pub root_inconsistent: bool,
    /// Loop guard holds the port in Discarding: BPDUs stopped arriving.
    #[serde(default)]
    pub loop_inconsistent: bool,
    /// BPDU guard took the port down.
    #[serde(default)]
    pub err_disabled: bool,
    /// Seconds until an `err_disabled` port recovers; `None`: manual `clear`.
    #[serde(default)]
    pub err_recovery_secs: Option<u32>,
    /// `operPointToPointMAC`.
    #[serde(default)]
    pub point_to_point: bool,
    /// BPDU counters.
    #[serde(default)]
    pub counters: StpPortCounters,
}

/// One port in one spanning-tree instance of an MST region (#321).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one independent flag per fact, reported as-is"
)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StpInstancePort {
    /// Port name.
    pub name: String,
    /// Port role.
    pub role: StpRole,
    /// The state the kernel is given for this tree's domains (a boundary
    /// port's is the CIST's).
    pub state: StpState,
    /// The peer is outside the region: the instance follows the CIST here.
    pub boundary: bool,
    /// Rapid-PVST+: a BPDU named another VLAN than this tree's (PVID
    /// inconsistency); the port is blocked in this tree (#322).
    #[serde(default)]
    pub inconsistent: bool,
    /// Rapid-PVST+: the port talks 802.1D (PVST+) to its peer in this tree (#322).
    #[serde(default)]
    pub compat: bool,
    /// Port path cost.
    pub cost: u32,
    /// Port priority.
    pub priority: u8,
    /// Designated Bridge ID on the segment.
    pub designated_bridge: String,
    /// Designated Port ID on the segment.
    pub designated_port: String,
    /// `operEdge`.
    #[serde(default)]
    pub edge: bool,
    /// `operPointToPointMAC`.
    #[serde(default)]
    pub point_to_point: bool,
    /// BPDU counters.
    #[serde(default)]
    pub counters: StpPortCounters,
}

/// One tree of an MST region: instance 0 is the CIST.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StpInstance {
    /// Instance ID.
    pub id: u16,
    /// The VIDs mapped to this instance (`10,20-30`), derived from the
    /// broadcast domains' tags.
    pub vlans: String,
    /// The broadcast domains running in this instance.
    pub domains: Vec<String>,
    /// This bridge's Bridge ID.
    pub bridge_id: String,
    /// Root Bridge ID.
    pub root_id: String,
    /// Cost of the path to the root.
    pub root_path_cost: u32,
    /// `None` when this bridge is the root of the instance.
    pub root_port: Option<String>,
    /// Ports in the instance.
    pub ports: Vec<StpInstancePort>,
    /// Topology-change state.
    #[serde(default)]
    pub topology: StpTopology,
}

/// The MST region and its trees (`mode mstp`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StpMst {
    /// MST configuration name (IEEE 802.1Q section 13.8).
    pub region_name: String,
    /// MST revision level.
    pub revision: u16,
    /// The MST configuration digest, 32 hex digits.
    pub digest: String,
    /// MST `MaxHops`.
    pub max_hops: u8,
    /// Instance 0 (the CIST) first, then every configured MSTI.
    pub instances: Vec<StpInstance>,
}

/// `show spanning-tree`. `enabled: false` (mode neither `rstp` nor `mstp`)
/// leaves the rest at its default.
///
/// Fields are only ever appended.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StpSummary {
    /// Spanning tree is enabled.
    pub enabled: bool,
    /// Spanning-tree mode.
    pub mode: StpMode,
    /// This bridge's Bridge ID.
    pub bridge_id: String,
    /// Root Bridge ID.
    pub root_id: String,
    /// Cost of the path to the root.
    pub root_path_cost: u32,
    /// `None` when this bridge is the root.
    pub root_port: Option<String>,
    /// Hello Time in seconds.
    pub hello_time_secs: u8,
    /// Max Age in seconds.
    pub max_age_secs: u8,
    /// Forward Delay in seconds.
    pub forward_delay_secs: u8,
    /// Ports in the instance.
    pub ports: Vec<StpPortInfo>,
    /// The MST region and its trees; `None` outside `mode mstp` (#321).
    #[serde(default)]
    pub mst: Option<StpMst>,
    /// One tree per broadcast domain in `mode rapid-pvst` (#322); `id` is the
    /// domain's VLAN. Empty in the other modes.
    #[serde(default)]
    pub pvst: Vec<StpInstance>,
    /// The CIST's topology changes (`rstp`/`mstp`).
    #[serde(default)]
    pub topology: StpTopology,
}

impl Default for StpSummary {
    fn default() -> Self {
        StpSummary {
            enabled: false,
            mode: StpMode::Disabled,
            bridge_id: String::new(),
            root_id: String::new(),
            root_path_cost: 0,
            root_port: None,
            hello_time_secs: 0,
            max_age_secs: 0,
            forward_delay_secs: 0,
            ports: Vec::new(),
            mst: None,
            pvst: Vec::new(),
            topology: StpTopology::default(),
        }
    }
}

/// Messages sent from a client to `nos-stpd`. Append-only (postcard encodes
/// the variant index).
#[derive(Debug, Serialize, Deserialize)]
pub enum StpRequest {
    /// Query the bridge summary.
    GetSummary,
    /// 802.1Q `mcheck`: re-probe for RSTP on one port, or on all (`None`).
    Mcheck {
        /// Restrict to this interface; `None` means all.
        interface: Option<String>,
    },
    /// `clear spanning-tree err-disabled <port>` (#320): bring a port that
    /// BPDU guard shut down back up.
    ClearErrDisabled {
        /// Interface to act on.
        interface: String,
    },
}

/// Messages sent from `nos-stpd` to a query client.
#[allow(
    clippy::large_enum_variant,
    reason = "one-shot reply, the summary is the point"
)]
#[derive(Debug, Serialize, Deserialize)]
pub enum StpEvent {
    /// Reply to `GetSummary`.
    Summary(StpSummary),
    /// How many ports the `Mcheck` matched (0: no such interface).
    Mcheck {
        /// Number of ports whose counters were cleared.
        ports: u32,
    },
    /// Whether the `ClearErrDisabled` port was err-disabled.
    ErrDisabledCleared {
        /// Whether any counters were cleared.
        cleared: bool,
    },
}
