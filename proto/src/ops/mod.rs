/// Edits to the admin keystore (`AdminOp`).
pub mod admin;
/// Edits to AS-path lists (`AsPathListOp`).
pub mod as_path_list;
/// Edits to BFD profiles (`BfdProfileOp`).
pub mod bfd_profile;
/// Edits to BGP instances (`BgpInstanceOp`).
pub mod bgp_instance;
/// Edits to BGP peers (`BgpPeerOp`).
pub mod bgp_peer;
/// Edits to BGP peer groups (`BgpPeerGroupOp`).
pub mod bgp_peer_group;
/// Edits to broadcast domains (`BroadcastDomainOp`).
pub mod broadcast_domain;
/// Edits to community aliases (`CommunityAliasOp`).
pub mod community_alias;
/// Edits to community groups (`CommunityGroupOp`).
pub mod community_group;
/// Edits to interfaces (`InterfaceOp`).
pub mod interface;
/// Edits to global LLDP settings (`LldpOp`).
pub mod lldp;
/// Edits to syslog servers (`LoggingOp`).
pub mod logging;
/// Edits to OSPF areas (`OspfAreaOp`).
pub mod ospf_area;
/// Edits to OSPF instances (`OspfInstanceOp`).
pub mod ospf_instance;
/// Edits to OSPF profiles (`OspfProfileOp`).
pub mod ospf_profile;
/// Edits to `OSPFv3` areas (`Ospfv3AreaOp`).
pub mod ospfv3_area;
/// Edits to `OSPFv3` instances (`Ospfv3InstanceOp`).
pub mod ospfv3_instance;
/// Edits to `OSPFv3` profiles (`Ospfv3ProfileOp`).
pub mod ospfv3_profile;
/// Edits to policy definitions (`PolicyDefinitionOp`).
pub mod policy_definition;
/// Edits to port aggregates (`PortAggregateOp`).
pub mod port_aggregate;
/// Edits to a port aggregate's LACP conversation map (`PortAggregateConversationOp`).
pub mod port_aggregate_conversation;
/// Edits to port-aggregate subinterfaces (`PortAggregateSubinterfaceOp`).
pub mod port_aggregate_subinterface;
/// Edits to prefix lists (`PrefixListOp`).
pub mod prefix_list;
/// Edits to routing tables (`RoutingTableOp`).
pub mod routing_table;
/// Edits to static routes (`StaticRouteOp`).
pub mod static_route;
/// Edits to static routing instances (`StaticRoutingInstanceOp`).
pub mod static_routing_instance;
/// Edits to STP port profiles (`StpPortProfileOp`).
pub mod stp_port_profile;
/// Edits to subinterfaces (`SubinterfaceOp`).
pub mod subinterface;
/// Edits to switching profiles (`SwitchingProfileOp`).
pub mod switching_profile;
/// Edits to local users (`UserOp`).
pub mod user;

pub use admin::AdminOp;
pub use as_path_list::AsPathListOp;
pub use bfd_profile::BfdProfileOp;
pub use bgp_instance::BgpInstanceOp;
pub use bgp_peer::BgpPeerOp;
pub use bgp_peer_group::BgpPeerGroupOp;
pub use broadcast_domain::BroadcastDomainOp;
pub use community_alias::CommunityAliasOp;
pub use community_group::CommunityGroupOp;
pub use interface::InterfaceOp;
pub use lldp::LldpOp;
pub use logging::LoggingOp;
pub use ospf_area::OspfAreaOp;
pub use ospf_instance::OspfInstanceOp;
pub use ospf_profile::OspfProfileOp;
pub use ospfv3_area::Ospfv3AreaOp;
pub use ospfv3_instance::Ospfv3InstanceOp;
pub use ospfv3_profile::Ospfv3ProfileOp;
pub use policy_definition::PolicyDefinitionOp;
pub use port_aggregate::PortAggregateOp;
pub use port_aggregate_conversation::PortAggregateConversationOp;
pub use port_aggregate_subinterface::PortAggregateSubinterfaceOp;
pub use prefix_list::PrefixListOp;
pub use routing_table::RoutingTableOp;
pub use static_route::StaticRouteOp;
pub use static_routing_instance::StaticRoutingInstanceOp;
pub use stp_port_profile::StpPortProfileOp;
pub use subinterface::SubinterfaceOp;
pub use switching_profile::SwitchingProfileOp;
pub use user::UserOp;

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::schema::{Config, PrefixListEntry};

/// A single edit applied to a transaction's in-progress config tree.
///
/// One variant per config section, plus one variant per top-level scalar
/// field. Adding a new named/keyed section follows the convention in
/// `proto/CLAUDE.md`'s "Adding a new config section": add a sibling
/// `<Section>Op` enum in `ops/<section>.rs`, then a new `ConfigOp` variant
/// wrapping it. A scalar field with a single possible edit (like
/// `hostname`) skips that — it gets one `ConfigOp` variant directly here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigOp {
    /// Delegates to a `BgpInstanceOp` edit.
    BgpInstance(BgpInstanceOp),
    /// Sets the router hostname.
    SetHostname(String),
    /// Delegates to a `BgpPeerGroupOp` edit.
    BgpPeerGroup(BgpPeerGroupOp),
    /// Delegates to a `BgpPeerOp` edit.
    BgpPeer(BgpPeerOp),
    /// Delegates to a `RoutingTableOp` edit.
    RoutingTable(RoutingTableOp),
    /// Delegates to a `StaticRoutingInstanceOp` edit.
    StaticRoutingInstance(StaticRoutingInstanceOp),
    /// Delegates to a `StaticRouteOp` edit.
    StaticRoute(StaticRouteOp),
    /// Delegates to a `InterfaceOp` edit.
    Interface(InterfaceOp),
    /// Delegates to a `PolicyDefinitionOp` edit.
    PolicyDefinition(PolicyDefinitionOp),
    /// Delegates to a `CommunityAliasOp` edit.
    CommunityAlias(CommunityAliasOp),
    /// Delegates to a `CommunityGroupOp` edit.
    CommunityGroup(CommunityGroupOp),
    /// Delegates to a `AsPathListOp` edit.
    AsPathList(AsPathListOp),
    /// Delegates to a `PrefixListOp` edit.
    PrefixList(PrefixListOp),
    /// Delegates to a `BroadcastDomainOp` edit.
    BroadcastDomain(BroadcastDomainOp),
    /// Delegates to a `SwitchingProfileOp` edit.
    SwitchingProfile(SwitchingProfileOp),
    /// Delegates to a `SubinterfaceOp` edit.
    Subinterface(SubinterfaceOp),
    /// Delegates to a `OspfInstanceOp` edit.
    OspfInstance(OspfInstanceOp),
    /// Delegates to a `OspfAreaOp` edit.
    OspfArea(OspfAreaOp),
    /// Delegates to a `OspfProfileOp` edit.
    OspfProfile(OspfProfileOp),
    /// Delegates to a `Ospfv3InstanceOp` edit.
    Ospfv3Instance(Ospfv3InstanceOp),
    /// Delegates to a `Ospfv3AreaOp` edit.
    Ospfv3Area(Ospfv3AreaOp),
    /// Delegates to a `Ospfv3ProfileOp` edit.
    Ospfv3Profile(Ospfv3ProfileOp),
    /// Delegates to a `PortAggregateOp` edit.
    PortAggregate(PortAggregateOp),
    /// Delegates to a `PortAggregateSubinterfaceOp` edit.
    PortAggregateSubinterface(PortAggregateSubinterfaceOp),
    /// Delegates to a `LldpOp` edit.
    Lldp(LldpOp),
    /// Delegates to a `UserOp` edit.
    User(UserOp),
    /// Delegates to a `LoggingOp` edit.
    Logging(LoggingOp),
    /// Delegates to a `BfdProfileOp` edit.
    BfdProfile(BfdProfileOp),
    /// Delegates to a `StpPortProfileOp` edit.
    StpPortProfile(StpPortProfileOp),
    /// Delegates to a `AdminOp` edit.
    Admin(AdminOp),
    /// Delegates to a `PortAggregateConversationOp` edit.
    PortAggregateConversation(PortAggregateConversationOp),
}

impl ConfigOp {
    /// The variant's name, for logs: unlike `{:?}` it never carries the
    /// payload, so a secret in an op cannot reach `nos-logd` through it.
    pub fn kind(&self) -> &'static str {
        match self {
            ConfigOp::BgpInstance(..) => "BgpInstance",
            ConfigOp::SetHostname(..) => "SetHostname",
            ConfigOp::BgpPeerGroup(..) => "BgpPeerGroup",
            ConfigOp::BgpPeer(..) => "BgpPeer",
            ConfigOp::RoutingTable(..) => "RoutingTable",
            ConfigOp::StaticRoutingInstance(..) => "StaticRoutingInstance",
            ConfigOp::StaticRoute(..) => "StaticRoute",
            ConfigOp::Interface(..) => "Interface",
            ConfigOp::PolicyDefinition(..) => "PolicyDefinition",
            ConfigOp::CommunityAlias(..) => "CommunityAlias",
            ConfigOp::CommunityGroup(..) => "CommunityGroup",
            ConfigOp::AsPathList(..) => "AsPathList",
            ConfigOp::PrefixList(..) => "PrefixList",
            ConfigOp::BroadcastDomain(..) => "BroadcastDomain",
            ConfigOp::SwitchingProfile(..) => "SwitchingProfile",
            ConfigOp::Subinterface(..) => "Subinterface",
            ConfigOp::OspfInstance(..) => "OspfInstance",
            ConfigOp::OspfArea(..) => "OspfArea",
            ConfigOp::OspfProfile(..) => "OspfProfile",
            ConfigOp::Ospfv3Instance(..) => "Ospfv3Instance",
            ConfigOp::Ospfv3Area(..) => "Ospfv3Area",
            ConfigOp::Ospfv3Profile(..) => "Ospfv3Profile",
            ConfigOp::PortAggregate(..) => "PortAggregate",
            ConfigOp::PortAggregateSubinterface(..) => "PortAggregateSubinterface",
            ConfigOp::Lldp(..) => "Lldp",
            ConfigOp::User(..) => "User",
            ConfigOp::Logging(..) => "Logging",
            ConfigOp::BfdProfile(..) => "BfdProfile",
            ConfigOp::StpPortProfile(..) => "StpPortProfile",
            ConfigOp::Admin(..) => "Admin",
            ConfigOp::PortAggregateConversation(..) => "PortAggregateConversation",
        }
    }

    /// Applies the op to `config` in place. Never runs `garde` validation —
    /// validation happens only at commit time. Only reports structural
    /// errors (e.g. setting a field on a name that doesn't exist).
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            ConfigOp::BgpInstance(op) => op.apply(config),
            ConfigOp::SetHostname(hostname) => {
                config.hostname.clone_from(hostname);
                Ok(())
            }
            ConfigOp::BgpPeerGroup(op) => op.apply(config),
            ConfigOp::BgpPeer(op) => op.apply(config),
            ConfigOp::RoutingTable(op) => op.apply(config),
            ConfigOp::StaticRoutingInstance(op) => op.apply(config),
            ConfigOp::StaticRoute(op) => op.apply(config),
            ConfigOp::Interface(op) => op.apply(config),
            ConfigOp::PolicyDefinition(op) => op.apply(config),
            ConfigOp::CommunityAlias(op) => op.apply(config),
            ConfigOp::CommunityGroup(op) => op.apply(config),
            ConfigOp::AsPathList(op) => op.apply(config),
            ConfigOp::PrefixList(op) => op.apply(config),
            ConfigOp::BroadcastDomain(op) => op.apply(config),
            ConfigOp::SwitchingProfile(op) => op.apply(config),
            ConfigOp::Subinterface(op) => op.apply(config),
            ConfigOp::OspfInstance(op) => op.apply(config),
            ConfigOp::OspfArea(op) => op.apply(config),
            ConfigOp::OspfProfile(op) => op.apply(config),
            ConfigOp::Ospfv3Instance(op) => op.apply(config),
            ConfigOp::Ospfv3Area(op) => op.apply(config),
            ConfigOp::Ospfv3Profile(op) => op.apply(config),
            ConfigOp::PortAggregate(op) => op.apply(config),
            ConfigOp::PortAggregateSubinterface(op) => op.apply(config),
            ConfigOp::Lldp(op) => op.apply(config),
            ConfigOp::User(op) => op.apply(config),
            ConfigOp::Logging(op) => op.apply(config),
            ConfigOp::BfdProfile(op) => op.apply(config),
            ConfigOp::StpPortProfile(op) => op.apply(config),
            ConfigOp::Admin(op) => op.apply(config),
            ConfigOp::PortAggregateConversation(op) => op.apply(config),
        }
    }
}

/// Why applying a `ConfigOp` failed; each variant names the object that was not found and the key looked up.
#[derive(Debug, Error)]
pub enum OpError {
    /// No BGP instance matches the given name.
    #[error("bgp instance '{0}' not found")]
    BgpInstanceNotFound(String),
    /// No BGP peer group matches the key (`instance`, `name`).
    #[error("peer-group '{name}' not found in bgp instance '{instance}'")]
    BgpPeerGroupNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
    },
    /// No BGP TCP-AO key matches the key (`instance`, `name`, `send_id`).
    #[error("ao key with send-id '{send_id}' not found in peer-group '{name}' of bgp instance '{instance}'")]
    BgpAoKeyNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
        /// TCP-AO `SendID` that was looked up.
        send_id: u8,
    },
    /// No BGP peer matches the key (`instance`, `remote_address`).
    #[error("peer '{remote_address}' not found in bgp instance '{instance}'")]
    BgpPeerNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Peer address that was looked up.
        remote_address: IpAddr,
    },
    /// No routing table matches the given name.
    #[error("routing table '{0}' not found")]
    RoutingTableNotFound(String),
    /// No static routing instance matches the given name.
    #[error("static routing instance '{0}' not found")]
    StaticRoutingInstanceNotFound(String),
    /// No static route matches the key (`instance`, `subnet`).
    #[error("route to '{subnet}' not found in static routing instance '{instance}'")]
    StaticRouteNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Route destination that was looked up.
        subnet: IpNet,
    },
    /// No interface matches the given name.
    #[error("interface '{0}' not found")]
    InterfaceNotFound(String),
    /// No interface address matches the key (`name`, `address`).
    #[error("address '{address}' not found on interface '{name}'")]
    InterfaceAddressNotFound {
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
        /// Address that was looked up.
        address: IpNet,
    },
    /// No policy definition matches the given name.
    #[error("policy definition '{0}' not found")]
    PolicyDefinitionNotFound(String),
    /// No syslog server matches the given name.
    #[error("syslog server '{0}' not found")]
    SyslogServerNotFound(String),
    /// No admin key matches the given label.
    #[error("admin key '{0}' not found")]
    AdminKeyNotFound(String),
    /// No user matches the given name.
    #[error("user '{0}' not found")]
    UserNotFound(String),
    /// No BFD profile matches the given name.
    #[error("bfd profile '{0}' not found")]
    BfdProfileNotFound(String),
    /// No STP port profile matches the given name.
    #[error("stp port profile '{0}' not found")]
    StpPortProfileNotFound(String),
    /// No LACP conversation range starts at `first` in the port aggregate.
    #[error("lacp conversation range starting at {first} not found in port aggregate '{name}'")]
    LacpConversationNotFound {
        /// Name of the port aggregate.
        name: String,
        /// First conversation id that was looked up.
        first: u16,
    },
    /// No community alias matches the given name.
    #[error("community alias '{0}' not found")]
    CommunityAliasNotFound(String),
    /// No community group matches the given name.
    #[error("community group '{0}' not found")]
    CommunityGroupNotFound(String),
    /// No community group member matches the key (`name`, `member`).
    #[error("member '{member}' not found in community group '{name}'")]
    CommunityGroupMemberNotFound {
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
        /// Member that was looked up.
        member: String,
    },
    /// No AS path list matches the given name.
    #[error("as-path list '{0}' not found")]
    AsPathListNotFound(String),
    /// No AS path list pattern matches the key (`name`, `pattern`).
    #[error("pattern '{pattern}' not found in as-path list '{name}'")]
    AsPathListPatternNotFound {
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
        /// AS-path pattern that was looked up.
        pattern: String,
    },
    /// No prefix list matches the given name.
    #[error("prefix list '{0}' not found")]
    PrefixListNotFound(String),
    /// No prefix list entry matches the key (`name`, `entry`).
    #[error("entry '{entry:?}' not found in prefix list '{name}'")]
    PrefixListEntryNotFound {
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
        /// Prefix-list entry that was looked up.
        entry: PrefixListEntry,
    },
    /// No broadcast domain matches the given name.
    #[error("broadcast domain '{0}' not found")]
    BroadcastDomainNotFound(String),
    /// No broadcast domain address matches the key (`name`, `address`).
    #[error("address '{address}' not found on broadcast domain '{name}'")]
    BroadcastDomainAddressNotFound {
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
        /// Address that was looked up.
        address: IpNet,
    },
    /// No broadcast domain route target matches the key (`name`, `route_target`).
    #[error("route target '{route_target}' not found on broadcast domain '{name}'")]
    BroadcastDomainRouteTargetNotFound {
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
        /// Route target that was looked up.
        route_target: String,
    },
    /// No switching profile matches the given name.
    #[error("switching profile '{0}' not found")]
    SwitchingProfileNotFound(String),
    /// No switching profile member matches the key (`name`, `broadcast_domain`).
    #[error("broadcast domain '{broadcast_domain}' not found in switching profile '{name}'")]
    SwitchingProfileMemberNotFound {
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
        /// Broadcast-domain member that was looked up.
        broadcast_domain: String,
    },
    /// No subinterface matches the key (`interface`, `tag`).
    #[error("subinterface with tag '{tag}' not found on interface '{interface}'")]
    SubinterfaceNotFound {
        /// Parent interface name that was looked up.
        interface: String,
        /// 802.1Q tag that was looked up.
        tag: u16,
    },
    /// No subinterface address matches the key (`interface`, `tag`, `address`).
    #[error("address '{address}' not found on subinterface '{interface}.{tag}'")]
    SubinterfaceAddressNotFound {
        /// Parent interface name that was looked up.
        interface: String,
        /// 802.1Q tag that was looked up.
        tag: u16,
        /// Address that was looked up.
        address: IpNet,
    },
    /// No OSPF instance matches the given name.
    #[error("ospf instance '{0}' not found")]
    OspfInstanceNotFound(String),
    /// No OSPF area matches the key (`instance`, `area_id`).
    #[error("ospf area '{area_id}' not found in ospf instance '{instance}'")]
    OspfAreaNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Area ID that was looked up.
        area_id: Ipv4Addr,
    },
    /// No OSPF profile matches the key (`instance`, `area_id`, `name`).
    #[error("ospf profile '{name}' not found in area '{area_id}' of ospf instance '{instance}'")]
    OspfProfileNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Area ID that was looked up.
        area_id: Ipv4Addr,
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
    },
    /// No OSPF crypto key matches the key (`instance`, `area_id`, `name`, `key_id`).
    #[error("crypto key with key-id '{key_id}' not found in ospf profile '{name}' (area '{area_id}' of ospf instance '{instance}')")]
    OspfCryptoKeyNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Area ID that was looked up.
        area_id: Ipv4Addr,
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
        /// Key ID that was looked up.
        key_id: u16,
    },
    /// No `OSPFv3` instance matches the given name.
    #[error("ospfv3 instance '{0}' not found")]
    Ospfv3InstanceNotFound(String),
    /// No `OSPFv3` area matches the key (`instance`, `area_id`).
    #[error("ospfv3 area '{area_id}' not found in ospfv3 instance '{instance}'")]
    Ospfv3AreaNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Area ID that was looked up.
        area_id: Ipv4Addr,
    },
    #[error(
        "ospfv3 profile '{name}' not found in area '{area_id}' of ospfv3 instance '{instance}'"
    )]
    /// No `OSPFv3` profile matches the key (`instance`, `area_id`, `name`).
    Ospfv3ProfileNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Area ID that was looked up.
        area_id: Ipv4Addr,
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
    },
    /// No `OSPFv3` crypto key matches the key (`instance`, `area_id`, `name`, `key_id`).
    #[error("crypto key with key-id '{key_id}' not found in ospfv3 profile '{name}' (area '{area_id}' of ospfv3 instance '{instance}')")]
    Ospfv3CryptoKeyNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Area ID that was looked up.
        area_id: Ipv4Addr,
        /// Name that was looked up (or the parent object that lacks the missing child).
        name: String,
        /// Key ID that was looked up.
        key_id: u16,
    },
    /// No port aggregate matches the given name.
    #[error("port aggregate '{0}' not found")]
    PortAggregateNotFound(String),
    /// No port aggregate subinterface matches the key (`port_aggregate`, `tag`).
    #[error("subinterface with tag '{tag}' not found on port aggregate '{port_aggregate}'")]
    PortAggregateSubinterfaceNotFound {
        /// Parent port-aggregate name that was looked up.
        port_aggregate: String,
        /// 802.1Q tag that was looked up.
        tag: u16,
    },
    #[error(
        "address '{address}' not found on port aggregate subinterface '{port_aggregate}.{tag}'"
    )]
    /// No port aggregate subinterface address matches the key (`port_aggregate`, `tag`, `address`).
    PortAggregateSubinterfaceAddressNotFound {
        /// Parent port-aggregate name that was looked up.
        port_aggregate: String,
        /// 802.1Q tag that was looked up.
        tag: u16,
        /// Address that was looked up.
        address: IpNet,
    },
    /// No OSPF area range matches the key (`instance`, `area_id`, `cidr`).
    #[error("range '{cidr}' not found in area '{area_id}' of ospf instance '{instance}'")]
    OspfAreaRangeNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Area ID that was looked up.
        area_id: Ipv4Addr,
        /// Range prefix that was looked up.
        cidr: ipnet::Ipv4Net,
    },
    #[error(
        "virtual link to '{router_id}' not found in area '{area_id}' of ospf instance '{instance}'"
    )]
    /// No OSPF virtual link matches the key (`instance`, `area_id`, `router_id`).
    OspfVirtualLinkNotFound {
        /// Name of the owning instance that was looked up.
        instance: String,
        /// Area ID that was looked up.
        area_id: Ipv4Addr,
        /// Remote router ID of the virtual link that was looked up.
        router_id: Ipv4Addr,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_hostname_updates_config() {
        let mut cfg = Config::default();
        ConfigOp::SetHostname("router1".to_string())
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.hostname, "router1");
    }

    #[test]
    fn kind_is_the_variant_name_without_payload() {
        assert_eq!(ConfigOp::SetHostname("h".into()).kind(), "SetHostname");
        let op = ConfigOp::Admin(AdminOp::SetKey {
            label: "l".into(),
            secret: "hunter2".into(),
        });
        assert_eq!(op.kind(), "Admin");
    }
}
