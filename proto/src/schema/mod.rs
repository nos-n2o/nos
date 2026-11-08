/// Access lists (`Acl`): ordered permit/deny rules attached to interfaces.
pub mod acl;
/// The admin keystore (`Admin`): labelled secrets other sections reference.
pub mod admin;
/// Named AS-path regex lists (`AsPathList`) that RPL scripts match against.
pub mod as_path_list;
/// BFD session parameter profiles (`BfdProfile`, RFC 5880).
pub mod bfd_profile;
/// A BGP speaker (`BgpInstance`): identity, peer-groups and peers.
pub mod bgp_instance;
/// A single BGP neighbor (`BgpPeer`), keyed by remote address.
pub mod bgp_peer;
/// Per-session BGP settings shared by their peers (`BgpPeerGroup`).
pub mod bgp_peer_group;
/// L2 segments (`BroadcastDomain`) with an optional SVI and VXLAN VNI.
pub mod broadcast_domain;
/// Named community values (`CommunityAlias`) for RPL scripts.
pub mod community_alias;
/// Named groups of community aliases (`CommunityGroup`) for RPL scripts.
pub mod community_group;
/// Interfaces and subinterfaces (`Interface`) with their L3 attachment points.
pub mod interface;
pub mod lldp;
pub mod logging;
/// `OSPFv2` areas (`OspfArea`): type, ranges, virtual links and interface profiles.
pub mod ospf_area;
/// An `OSPFv2` speaker (`OspfInstance`), one `nos-ospfd` process each.
pub mod ospf_instance;
/// `OSPFv2` interface profiles (`OspfProfile`): network type, timers, authentication.
pub mod ospf_profile;
/// `OSPFv3` areas (`Ospfv3Area`) and their interface profiles.
pub mod ospfv3_area;
/// An `OSPFv3` speaker (`Ospfv3Instance`), one `nos-ospfv3d` process each.
pub mod ospfv3_instance;
/// `OSPFv3` interface profiles (`Ospfv3Profile`): timers and RFC 7166 authentication.
pub mod ospfv3_profile;
/// Named RPL policy scripts (`PolicyDefinition`).
pub mod policy_definition;
/// Link aggregations (`PortAggregate`): static or LACP bonds, with an EVPN Ethernet Segment identity.
pub mod port_aggregate;
/// Named prefix match lists (`PrefixList`) for RPL scripts.
pub mod prefix_list;
/// Per-role visibility of secrets (`Config::for_role`, #384).
pub mod redact;
/// Routing tables / VRFs (`RoutingTable`) and the protocol instances bound to each.
pub mod routing_table;
pub mod sbfd;
pub mod spanning_tree;
/// One static route (`StaticRoute`) of a static routing instance.
pub mod static_route;
/// A named set of static routes (`StaticRoutingInstance`) bound to a routing table.
pub mod static_routing_instance;
pub mod stp_port_profile;
pub mod sugar;
/// VLAN membership profiles (`SwitchingProfile`) that interfaces attach.
pub mod switching_profile;
/// Local login users (`User`) with argon2id password hashes.
pub mod user;

pub use acl::{flowspec_points, Acl, AclAction, AclProtocol, AclRule, FlowspecPoint, PortRange};
pub use admin::{redact_at, Admin, AdminKey, SECRET_MAX_LEN};
pub use as_path_list::AsPathList;
pub use bfd_profile::{BfdAuth, BfdAuthMethod, BfdMode, BfdProfile, EchoMode};
pub use bgp_instance::{
    BgpAggregate, BgpConfederation, BgpGracefulRestart, BgpInstance, BmpMonitor, BmpMonitorOut,
    BmpStation, RpkiCache, GR_RESTART_TIME_DEFAULT, GR_SELECTION_DEFERRAL_TIME_DEFAULT,
    GR_STALE_TIME_DEFAULT, RPKI_RTR_PORT_DEFAULT,
};
pub use bgp_peer::BgpPeer;
pub use bgp_peer_group::{
    AddressFamily, BgpAddPath, BgpAoAlgorithm, BgpAoKey, BgpAuth, BgpBlackhole, BgpDamping,
    BgpFlowspecValidation, BgpLocalAs, BgpMaximumPrefix, BgpPeerGroup, BgpPrefixLimit, BgpRole,
    BgpShutdown, NextHopMode, SourceAddress, CONNECT_RETRY_TIME_DEFAULT_SECS, HOLD_TIME_DEFAULT,
    HOLD_TIME_FLOOR, ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS,
};
pub use broadcast_domain::BroadcastDomain;
pub use community_alias::CommunityAlias;
pub use community_group::CommunityGroup;
pub use interface::{
    loopback_table_name, Interface, InterfaceAddress, Subinterface, LOOPBACK_PREFIX,
};
pub use lldp::{LldpDestination, LldpSettings};
pub use logging::{
    parse_fingerprint, LoggingSettings, SyslogFacility, SyslogServer, SyslogTls, SyslogTransport,
};
pub use ospf_area::{OspfArea, OspfAreaRange, OspfAreaType, OspfVirtualLink};
pub use ospf_instance::OspfInstance;
pub use ospf_profile::{
    NetworkType, OspfAuth, OspfCryptoAlgorithm, OspfCryptoKey, OspfProfile, DEAD_INTERVAL_DEFAULT,
    HELLO_INTERVAL_DEFAULT, PRIORITY_DEFAULT,
};
pub use ospfv3_area::Ospfv3Area;
pub use ospfv3_instance::Ospfv3Instance;
pub use ospfv3_profile::Ospfv3Profile;
pub use policy_definition::PolicyDefinition;
pub use port_aggregate::{
    DfAlgorithm, EsRedundancy, LacpMode, LacpRate, PortAggregate, PortAggregateMode,
};
pub use prefix_list::{PrefixList, PrefixListEntry};
pub use routing_table::{
    Redistribute, RedistributeSource, RedistributeTarget, RestApi, RoutingTable, RoutingTableEvpn,
    RoutingTableVpn, REST_API_PORT_DEFAULT,
};
pub use sbfd::SbfdReflector;
pub use spanning_tree::{MstInstance, SpanningTree, StpForceVersion, StpMode, StpRegion};
pub use static_route::StaticRoute;
pub use static_routing_instance::StaticRoutingInstance;
pub use stp_port_profile::{EdgePort, LinkType, StpPortMstInstance, StpPortProfile};
pub use switching_profile::{SwitchingProfile, SwitchingProfileMember, VlanTag};
pub use user::{User, PASSWORD_HASH_PREFIX};

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::hostname_charset;
use nos_proto_derive::Cli;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
/// The whole device configuration: each field is one top-level section, and `validate` checks the cross-references between them.
pub struct Config {
    #[garde(
        dive,
        custom(|instances, _ctx: &Config| bgp_instance::valid_route_reflection_and_server(instances))
    )]
    #[cli(topic = BgpInstance, words = "bgp instance")]
    /// BGP speakers; each gets its own `nos-bgpd` process.
    pub bgp_instances: Vec<BgpInstance>,

    #[garde(
        dive,
        custom(|tables, ctx: &Config| routing_table::valid_redistribute_rules(tables, ctx))
    )]
    #[cli(topic = RoutingTable)]
    /// VRFs; each binds BGP, static, OSPF and `OSPFv3` instances and may pin the REST API.
    pub routing_tables: Vec<RoutingTable>,

    #[garde(dive)]
    #[cli(topic = OspfInstance, words = "ospf instance")]
    /// `OSPFv2` speakers; each gets its own `nos-ospfd` process.
    pub ospf_instances: Vec<OspfInstance>,

    #[garde(dive)]
    #[cli(topic = Ospfv3Instance, words = "ospfv3 instance")]
    /// `OSPFv3` speakers; each gets its own `nos-ospfv3d` process.
    pub ospfv3_instances: Vec<Ospfv3Instance>,

    #[garde(dive)]
    #[cli(topic = StaticRoutingInstance)]
    /// Static route sets, each attached to a routing table by name.
    pub static_routing_instances: Vec<StaticRoutingInstance>,

    #[garde(
        dive,
        custom(|interfaces, ctx: &Config| interface::valid_interfaces(interfaces, ctx))
    )]
    #[cli(topic = Interface, sugar = "{name}.{tag} => {name} subinterface {tag}")]
    /// Interfaces `nos-interfaced` configures; any interface not listed is left alone.
    pub interfaces: Vec<Interface>,

    #[garde(dive)]
    #[cli(topic = PolicyDefinition)]
    /// RPL scripts that peer-groups reference by name as import/export policy.
    pub policy_definitions: Vec<PolicyDefinition>,

    #[garde(dive)]
    #[cli(topic = CommunityAlias)]
    /// Named community literals that RPL scripts can use by name.
    pub community_aliases: Vec<CommunityAlias>,

    #[garde(dive)]
    #[cli(topic = CommunityGroup)]
    /// Named lists of community aliases that RPL scripts can use by name.
    pub community_groups: Vec<CommunityGroup>,

    #[garde(dive)]
    #[cli(topic = PrefixList)]
    /// Named prefix lists that RPL scripts match with `this.prefix in NAME`.
    pub prefix_lists: Vec<PrefixList>,

    #[garde(dive)]
    #[cli(topic = AsPathList)]
    /// Named AS-path regex lists that RPL scripts match with `this.bgp.as_path in NAME`.
    pub as_path_lists: Vec<AsPathList>,

    #[garde(
        dive,
        custom(|domains, ctx: &Config| broadcast_domain::valid_broadcast_domains(domains, ctx))
    )]
    #[cli(topic = BroadcastDomain, words = "broadcast domain")]
    /// L2 segments that switching profiles and EVPN VNIs refer to.
    pub broadcast_domains: Vec<BroadcastDomain>,

    #[garde(dive)]
    #[cli(topic = SwitchingProfile)]
    /// VLAN membership profiles an interface attaches with `switching-profile`.
    pub switching_profiles: Vec<SwitchingProfile>,

    #[garde(
        dive,
        custom(|aggregates, ctx: &Config| port_aggregate::valid_port_aggregates(aggregates, ctx))
    )]
    #[cli(topic = PortAggregate)]
    /// Link aggregations of physical ports (static or LACP).
    pub port_aggregates: Vec<PortAggregate>,

    #[serde(default = "default_hostname")]
    #[garde(length(min = 1, max = 253), custom(|h, _ctx: &Config| hostname_charset(h)))]
    #[cli(topic = Hostname)]
    /// System hostname: 1 to 253 characters, hostname charset only.
    pub hostname: String,

    /// System-wide LLDP timers and management address. `serde(default)` so
    /// on-disk config saved before this field existed still loads.
    #[serde(default)]
    #[garde(custom(|l: &LldpSettings, _ctx: &Config| l.check()))]
    #[cli(topic = Lldp)]
    pub lldp: LldpSettings,

    /// Log export (remote syslog). `serde(default)` so on-disk config saved
    /// before this field existed still loads.
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = Logging)]
    pub logging: LoggingSettings,

    /// Local users allowed to log in. `serde(default)` so on-disk config saved
    /// before this field existed still loads (`nos-configd` then seeds `admin`).
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = User)]
    pub users: Vec<User>,

    /// Named BFD parameter sets, referenced by `bfd <name>` from BGP
    /// peer-groups, OSPF/OSPFv3 profiles and static routes. `serde(default)`
    /// so on-disk config saved before this field existed still loads.
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = BfdProfile)]
    pub bfd_profiles: Vec<BfdProfile>,

    /// RFC 7880 S-BFD reflector. `serde(default)` so on-disk config saved
    /// before this field existed still loads.
    #[serde(default)]
    #[garde(custom(|r: &SbfdReflector, _ctx: &Config| r.check()))]
    #[cli(topic = SbfdReflector, words = "sbfd reflector")]
    pub sbfd_reflector: SbfdReflector,

    /// Bridge-wide spanning-tree parameters (inert until `nos-stpd`).
    /// `serde(default)` so on-disk config saved before this field existed
    /// still loads.
    #[serde(default)]
    #[garde(custom(|s: &SpanningTree, ctx: &Config| spanning_tree::valid_spanning_tree(s, ctx)))]
    #[cli(topic = SpanningTree, words = "spanning-tree")]
    pub spanning_tree: SpanningTree,

    /// Named spanning-tree port settings, referenced by `stp-port-profile`
    /// from interfaces and port aggregates.
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = StpPortProfile, words = "stp-port-profile")]
    pub stp_port_profiles: Vec<StpPortProfile>,

    /// Named, ordered access lists, attached to interfaces with `acl in` /
    /// `acl out`. `serde(default)` so on-disk config saved before this field
    /// existed still loads.
    #[serde(default)]
    #[garde(
        dive,
        custom(|a: &Vec<Acl>, ctx: &Config| acl::valid_acl_references(a, ctx)),
        custom(|a: &Vec<Acl>, ctx: &Config| acl::valid_flowspec_placements(a, ctx))
    )]
    #[cli(topic = Acl)]
    pub acls: Vec<Acl>,

    /// The keystore: secrets under a label, referenced by label from the
    /// sections that need a key. Not shown by `show config` unless asked
    /// (`show config admin`); values never leave the daemons in clear
    /// (logs, REST and `show` print `<hidden>`). `serde(default)` so on-disk
    /// config saved before this field existed still loads.
    #[serde(default)]
    #[garde(dive)]
    #[cli(topic = Admin)]
    pub admin: Admin,
}

impl Config {
    /// Whether `ip` lies on a subnet configured on an interface (or
    /// subinterface, or port-aggregate subinterface) in routing table
    /// `table`: the config-only "directly connected" test BFD clients use to
    /// choose single-hop (RFC 5881) over multihop (RFC 5883) sessions.
    /// ponytail: addresses learned outside the config (DHCP) are not seen.
    pub fn is_connected(&self, table: &str, ip: std::net::IpAddr) -> bool {
        let on = |rt: &Option<String>, addrs: &[interface::InterfaceAddress]| {
            rt.as_deref() == Some(table) && addrs.iter().any(|a| a.address.trunc().contains(&ip))
        };
        let subs = |subs: &[interface::Subinterface]| {
            subs.iter().any(|s| on(&s.routing_table, &s.addresses))
        };
        self.interfaces
            .iter()
            .any(|i| on(&i.routing_table, &i.addresses) || subs(&i.subinterfaces))
            || self.port_aggregates.iter().any(|a| subs(&a.subinterfaces))
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bgp_instances: Vec::new(),
            routing_tables: Vec::new(),
            ospf_instances: Vec::new(),
            ospfv3_instances: Vec::new(),
            static_routing_instances: Vec::new(),
            interfaces: Vec::new(),
            policy_definitions: Vec::new(),
            community_aliases: Vec::new(),
            community_groups: Vec::new(),
            as_path_lists: Vec::new(),
            prefix_lists: Vec::new(),
            broadcast_domains: Vec::new(),
            switching_profiles: Vec::new(),
            port_aggregates: Vec::new(),
            hostname: default_hostname(),
            lldp: LldpSettings::default(),
            logging: LoggingSettings::default(),
            users: Vec::new(),
            bfd_profiles: Vec::new(),
            sbfd_reflector: SbfdReflector::default(),
            spanning_tree: SpanningTree::default(),
            stp_port_profiles: Vec::new(),
            acls: Vec::new(),
            admin: Admin::default(),
        }
    }
}

fn default_hostname() -> String {
    "nos".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_means_inside_a_configured_subnet_of_the_table() {
        use interface::{Interface, InterfaceAddress, Subinterface};
        let addr = |a: &str| InterfaceAddress {
            address: a.parse().unwrap(),
            label: None,
        };
        let cfg = Config {
            interfaces: vec![
                Interface {
                    name: "eth1".into(),
                    subinterfaces: vec![Subinterface {
                        routing_table: Some("rt1".into()),
                        addresses: vec![addr("10.0.0.1/24")],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                Interface {
                    name: "loopback-rt1".into(),
                    routing_table: Some("rt1".into()),
                    addresses: vec![addr("1.1.1.1/32")],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let ip = |s: &str| s.parse().unwrap();
        assert!(cfg.is_connected("rt1", ip("10.0.0.2")));
        assert!(!cfg.is_connected("rt2", ip("10.0.0.2")), "other table");
        assert!(!cfg.is_connected("rt1", ip("10.0.1.2")));
        assert!(!cfg.is_connected("rt1", ip("1.1.1.2")), "loopback /32");
    }

    #[test]
    fn default_hostname_is_nos() {
        assert_eq!(Config::default().hostname, "nos");
    }

    #[test]
    fn valid_hostname_passes() {
        let cfg = Config {
            hostname: "router-1".to_string(),
            ..Default::default()
        };
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn lldp_settings_are_validated_at_config_level() {
        let mut cfg = Config::default();
        cfg.lldp.tx_interval_secs = Some(5);
        cfg.lldp.tx_hold = Some(3);
        cfg.validate_with(&cfg).unwrap();
        cfg.lldp.tx_interval_secs = Some(0);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn empty_hostname_fails_length() {
        let cfg = Config {
            hostname: String::new(),
            ..Default::default()
        };
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn hyphen_leading_hostname_fails_charset() {
        let cfg = Config {
            hostname: "-router".to_string(),
            ..Default::default()
        };
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
