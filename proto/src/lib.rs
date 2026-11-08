//! Shared wire types, IPC codec and config schema for every NOS process.
#![warn(missing_docs)]

// `#[derive(Cli)]` emits `::nos_proto::…` paths, which must resolve here too.
extern crate self as nos_proto;

pub mod acl;
pub mod bfd;
pub mod bgp;
/// Watchdog endpoint broker: roles, service references and the watchdog wire types.
pub mod broker;
pub mod chunk;
pub mod cli;
/// IPC framing codec: 4-byte little-endian length prefix plus postcard payload.
pub mod codec;
pub mod config_path;
/// State derived from the config after an edit (routing-table cross references).
pub mod derive;
/// Config diffs between two configs, scoped per supervised daemon.
pub mod diff;
/// Help-topic and command-documentation wire types served by `nos-configd`.
pub mod docs;
pub mod evpn_id;
pub mod fdb;
/// Wire types spoken to and by `nos-interfaced`: status, requests, events.
pub mod interface;
/// Request, response and event types spoken to `nos-configd`.
pub mod ipc;
pub mod lacp;
pub mod lldp;
/// Wire types of `nos-logd`: levels, entries, requests.
pub mod log;
/// Config edit operations (`ConfigOp`) and their application to a `Config`.
pub mod ops;
pub mod ospf;
pub mod ospfv3;
/// Opaque keyset-pagination cursors shared by the paged queries (#714).
pub mod page;
pub mod paths;
/// Wire types spoken to and by `nos-ribd`: route sources, pushes, lookups.
pub mod rib;
/// The configuration schema: every object an operator can configure.
pub mod schema;
pub mod stp;
/// Field validators shared by the config ops.
pub mod validators;
pub mod version;
pub use version::VersionInfo;

pub use acl::{
    AclAttachment, AclDirection, AclEvent, AclRequest, AclRuleStatus, AclStatus, FlowBitOp,
    FlowComponent, FlowNumOp, FlowRule, FlowRuleAction, FlowspecRuleStatus, FlowspecSet,
};
pub use bfd::{
    BfdDiag, BfdEvent, BfdRequest, BfdSessionKind, BfdSessionView, BfdState, ReflectorDiscards,
    ReflectorView, SessionKey,
};
pub use bgp::{
    BgpEvent, BgpRequest, BgpRouteCursor, BgpRouteSummary, BgpSessionState, BmpFrameCounts,
    BmpStationState, BmpStationStatus, EvpnRouteCursor, EvpnRouteSummary, FamilyReeval,
    FlowspecRouteCursor, FlowspecRouteSummary, GrSummary, PeerSummary, RedistributeUpdate,
    RedistributedRoute, ReevalFamily, RpkiCacheStatus, RpkiSessionState, RpkiValidationState,
    VpnPrefix, VpnPrefixUpdate, VpnRouteCursor, VpnRouteSummary, BGP_PAGE_MAX,
};
pub use broker::{
    Role, ServiceRef, WatchdogEvent, WatchdogRequest, INVALID_CREDENTIALS, LOGIN_BUSY,
    SESSION_EXPIRED,
};
pub use codec::IpcCodec;
pub use derive::sync_routing_table_refs;
pub use diff::{
    diff_configs, diff_configs_for_role, ConfigDiff, DiffScope, DiffStatus, FieldDiff, SectionDiff,
};
pub use docs::{CommandDoc, Topic};
pub use fdb::{
    EsEntry, EvpnKey, EvpnRoute, EvpnUpdate, FdbEvent, FdbRequest, FdbTable, MacEntry, MacSource,
    NeighEntry,
};
pub use interface::{
    BfdAggregateMembers, BroadcastDomainStatus, InterfaceEvent, InterfaceRequest, InterfaceStatus,
    LacpAggregateMembers, LinkState, PortAggregateStatus, StpPortAssignment, StpPortState,
    SubinterfaceStatus,
};
pub use ipc::{Event, Request, TransactionBase, TransactionSnapshot};
pub use ipnet::IpNet;
pub use lacp::{
    LacpEvent, LacpMuxState, LacpPortStatus, LacpReceiveState, LacpRequest,
    PortAggregateLacpSummary,
};
pub use lldp::{LldpEvent, LldpLinkStats, LldpNeighbor, LldpRequest};
pub use log::{LogEntry, LogEvent, LogLevel, LogRequest};
pub use ops::{
    AdminOp, AsPathListOp, BfdProfileOp, BgpInstanceOp, BgpPeerGroupOp, BgpPeerOp,
    BroadcastDomainOp, CommunityAliasOp, CommunityGroupOp, ConfigOp, InterfaceOp, LldpOp,
    LoggingOp, OpError, OspfAreaOp, OspfInstanceOp, OspfProfileOp, Ospfv3AreaOp, Ospfv3InstanceOp,
    Ospfv3ProfileOp, PolicyDefinitionOp, PortAggregateOp, PortAggregateSubinterfaceOp,
    PrefixListOp, RoutingTableOp, StaticRouteOp, StaticRoutingInstanceOp, StpPortProfileOp,
    SubinterfaceOp, SwitchingProfileOp, UserOp,
};
pub use ospf::{
    LinkInterfaceState, LsaSummary, NeighborSummary, OspfEvent, OspfNeighborState, OspfRequest,
};
pub use ospfv3::{Ospfv3Event, Ospfv3LsaSummary, Ospfv3NeighborSummary, Ospfv3Request};
pub use paths::{
    DEFAULT_CONFIG_SOCKET, DEFAULT_LOG_SOCKET, DEFAULT_PKI_CA, DEFAULT_PKI_DIR,
    DEFAULT_WATCHDOG_SOCKET,
};
pub use rib::{
    BgpRoute, BgpRouteUpdate, EvpnRouteInfo, NextHop, OspfRoute, OspfRouteUpdate, PrefixRoutes,
    ResolvedNextHop, RibEvent, RibRequest, RouteEntry, RouteSourceKind, VpnPath, VpnRoute,
    VpnRouteInfo, VpnRouteUpdate, ROUTES_PAGE_MAX,
};
pub use schema::{
    loopback_table_name, parse_fingerprint, redact_at, AddressFamily, Admin, AdminKey, AsPathList,
    BfdAuth, BfdAuthMethod, BfdProfile, BgpAddPath, BgpAggregate, BgpAoAlgorithm, BgpAoKey,
    BgpAuth, BgpBlackhole, BgpConfederation, BgpDamping, BgpFlowspecValidation, BgpGracefulRestart,
    BgpInstance, BgpLocalAs, BgpMaximumPrefix, BgpPeer, BgpPeerGroup, BgpPrefixLimit, BgpRole,
    BgpShutdown, BmpMonitor, BmpMonitorOut, BmpStation, BroadcastDomain, CommunityAlias,
    CommunityGroup, Config, DfAlgorithm, EsRedundancy, Interface, InterfaceAddress, LacpMode,
    LacpRate, LldpDestination, LldpSettings, LoggingSettings, NetworkType, NextHopMode, OspfArea,
    OspfAreaRange, OspfAreaType, OspfAuth, OspfCryptoAlgorithm, OspfCryptoKey, OspfInstance,
    OspfProfile, OspfVirtualLink, Ospfv3Area, Ospfv3Instance, Ospfv3Profile, PolicyDefinition,
    PortAggregate, PortAggregateMode, PrefixList, PrefixListEntry, Redistribute,
    RedistributeSource, RedistributeTarget, RestApi, RoutingTable, RoutingTableEvpn,
    RoutingTableVpn, RpkiCache, SourceAddress, StaticRoute, StaticRoutingInstance, StpMode,
    Subinterface, SwitchingProfile, SwitchingProfileMember, SyslogFacility, SyslogServer,
    SyslogTls, SyslogTransport, User, VlanTag, CONNECT_RETRY_TIME_DEFAULT_SECS,
    DEAD_INTERVAL_DEFAULT, GR_RESTART_TIME_DEFAULT, GR_SELECTION_DEFERRAL_TIME_DEFAULT,
    GR_STALE_TIME_DEFAULT, HELLO_INTERVAL_DEFAULT, HOLD_TIME_DEFAULT, HOLD_TIME_FLOOR,
    LOOPBACK_PREFIX, PASSWORD_HASH_PREFIX, PRIORITY_DEFAULT, REST_API_PORT_DEFAULT,
    ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS, RPKI_RTR_PORT_DEFAULT,
};
pub use stp::{
    StpEvent, StpInstance, StpInstancePort, StpMst, StpPortCounters, StpPortInfo, StpRequest,
    StpRole, StpState, StpSummary, StpTcCause, StpTopology,
};
