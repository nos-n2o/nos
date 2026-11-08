use serde::{Deserialize, Serialize};

/// Identifies what one command documents, independent of any one client's
/// invocation syntax: one per config-tree node or field (its `#[cli(topic)]`,
/// see `crate::cli`), per sugar word, and per non-edit request. Purely
/// client-local mechanics (a shell's own navigation commands) have no `Topic`.
/// The text lives in `nos-config` (`Request::Describe`), for the CLI's
/// audience — the schema's doc comments are the REST API's.
macro_rules! topics {
    ($($(#[$m:meta])* $v:ident,)*) => {
        /// Identifies what one command documents; see the macro's docs above.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        /// Identifies what one command documents.
        pub enum Topic {
            $($(#[$m])* $v,)*
        }

        impl Topic {
            /// Every topic, in declaration order.
            pub const ALL: &'static [Topic] = &[$(Topic::$v),*];
        }
    };
}

topics! {
    /// `Request::Get`
    ShowRunningConfig,
    /// `Request::Save`
    Save,
    /// `Request::OpenTransaction`
    OpenTransaction,
    /// `Request::GetTransaction`
    GetTransaction,
    /// `Request::CommitTransaction`
    CommitTransaction,
    /// `Request::DiscardTransaction`
    DiscardTransaction,
    /// `Request::DiffTransaction`
    DiffTransaction,
    /// `Config.hostname`
    Hostname,
    /// `Config.users`
    User,
    /// `User.password`
    UserPassword,
    /// `Config.lldp`
    Lldp,
    /// `LldpSettings.tx_interval_secs`
    LldpTxInterval,
    /// `LldpSettings.tx_hold`
    LldpTxHold,
    /// `LldpSettings.management_addresses`
    LldpManagementAddress,
    /// `LldpSettings.system_description`
    LldpSystemDescription,
    /// `Config.admin`
    Admin,
    /// `Admin.keys`
    AdminKey,
    /// `AdminKey.secret`
    AdminKeySecret,
    /// `Config.logging`
    Logging,
    /// `LoggingSettings.syslog`
    LoggingSyslog,
    /// `SyslogServer.address`
    SyslogAddress,
    /// `SyslogServer.port`
    SyslogPort,
    /// `SyslogServer.transport`
    SyslogTransport,
    /// `SyslogServer.routing_table`
    SyslogRoutingTable,
    /// `SyslogServer.level`
    SyslogLevel,
    /// `SyslogServer.facility`
    SyslogFacility,
    /// `SyslogServer.tls`
    SyslogTls,
    /// `SyslogTls.trust_anchor`
    SyslogTlsTrustAnchor,
    /// `SyslogTls.fingerprint`
    SyslogTlsFingerprint,
    /// `SyslogTls.server_name`
    SyslogTlsServerName,
    /// `SyslogTls.allow_tls12`
    SyslogTlsAllowTls12,
    /// `Config.bgp_instances`
    BgpInstance,
    /// `BgpInstance.asn`
    BgpInstanceAsn,
    /// `BgpInstance.router_id`
    BgpInstanceRouterId,
    /// `BgpInstance.cluster_id`
    BgpInstanceClusterId,
    /// `BgpInstance.peer_groups`
    BgpPeerGroup,
    /// `BgpPeerGroup.remote_as`
    BgpPeerGroupRemoteAs,
    /// `BgpPeerGroup.source_address`
    BgpPeerGroupSourceAddress,
    /// `BgpPeerGroup.address_families`
    BgpPeerGroupAddressFamily,
    /// `BgpPeerGroup.hold_time`
    BgpPeerGroupHoldTime,
    /// `BgpPeerGroup.keepalive_interval`
    BgpPeerGroupKeepaliveInterval,
    /// `BgpPeerGroup.connect_retry_time`
    BgpPeerGroupConnectRetryTime,
    /// `BgpPeerGroup.mrai`
    BgpPeerGroupMrai,
    /// `BgpPeerGroup.max_hops`
    BgpPeerGroupMaxHops,
    /// `BgpPeerGroup.damping`
    BgpPeerGroupDamping,
    /// `BgpPeerGroup.auth`
    BgpPeerGroupAuth,
    /// `md5-password` sugar on `BgpPeerGroup.auth`
    BgpPeerGroupMd5Password,
    /// `ao-key` sugar on `BgpPeerGroup.auth`
    BgpPeerGroupAoKey,
    /// `BgpPeerGroup.next_hop`
    BgpPeerGroupNextHop,
    /// `BgpPeerGroup.route_reflector_client`
    BgpPeerGroupRouteReflectorClient,
    /// `BgpPeerGroup.route_server_client`
    BgpPeerGroupRouteServerClient,
    /// `BgpPeerGroup.import_policy`
    BgpPeerGroupImportPolicy,
    /// `BgpPeerGroup.export_policy`
    BgpPeerGroupExportPolicy,
    /// `BgpPeerGroup.evpn_import_policy`
    BgpPeerGroupEvpnImportPolicy,
    /// `BgpPeerGroup.enforce_first_as`
    BgpPeerGroupEnforceFirstAs,
    /// `BgpPeerGroup.flowspec_validation`
    BgpPeerGroupFlowspecValidation,
    /// `BgpPeerGroup.flowspec_import_policy`
    BgpPeerGroupFlowspecImportPolicy,
    /// `BgpPeerGroup.flowspec_export_policy`
    BgpPeerGroupFlowspecExportPolicy,
    /// `BgpPeerGroup.shutdown`
    BgpPeerGroupShutdown,
    /// `BgpInstance.peers`
    BgpPeer,
    /// `BgpPeer.shutdown`
    BgpPeerShutdown,
    /// `Config.routing_tables`
    RoutingTable,
    /// `RoutingTable.bgp_instance`
    RoutingTableBgpInstance,
    /// `RoutingTable.static_routing_instance`
    RoutingTableStaticRoutingInstance,
    /// `RoutingTable.ospf_instance`
    RoutingTableOspfInstance,
    /// `RoutingTable.ospfv3_instance`
    RoutingTableOspfv3Instance,
    /// `RoutingTable.redistribute`
    RoutingTableRedistribute,
    /// `RoutingTable.rest_api`
    RoutingTableRestApi,
    /// `RoutingTable.evpn`
    RoutingTableEvpn,
    /// `RoutingTableEvpn.l3_vni`
    RoutingTableEvpnL3Vni,
    /// `RoutingTableEvpn.rd`
    RoutingTableEvpnRd,
    /// `RoutingTableEvpn.route_targets_import`/`route_targets_export`
    RoutingTableEvpnRouteTarget,
    /// `RoutingTableEvpn.vtep_source`
    RoutingTableEvpnVtepSource,
    /// `RoutingTableEvpn.bgp_instance`
    RoutingTableEvpnBgpInstance,
    /// `RoutingTable.vpn`
    RoutingTableVpn,
    /// `RoutingTableVpn.rd`
    RoutingTableVpnRd,
    /// `RoutingTableVpn.route_targets_import`/`route_targets_export`
    RoutingTableVpnRouteTarget,
    /// `RoutingTableVpn.bgp_instance`
    RoutingTableVpnBgpInstance,
    /// `RoutingTableVpn.label`
    RoutingTableVpnLabel,
    /// `RoutingTableVpn.site_of_origin`
    RoutingTableVpnSiteOfOrigin,
    /// `Config.static_routing_instances`
    StaticRoutingInstance,
    /// `StaticRoutingInstance.routes`
    StaticRoute,
    /// `Config.interfaces`
    Interface,
    /// `Interface.addresses` (also a subinterface's)
    InterfaceAddress,
    /// `Interface.routing_table` (also a subinterface's)
    InterfaceRoutingTable,
    /// `Interface.ospf_profile` (also a subinterface's and a broadcast domain's)
    InterfaceOspfProfile,
    /// `Interface.ospfv3_profile` (also a subinterface's and a broadcast domain's)
    InterfaceOspfv3Profile,
    /// `Subinterface.bfd_unsolicited`
    InterfaceBfdUnsolicited,
    /// `Interface.switching_profile` (also a port aggregate's)
    InterfaceSwitchingProfile,
    /// `Interface.port_aggregate`
    InterfacePortAggregate,
    /// `Interface.mtu` (also a port aggregate's)
    InterfaceMtu,
    /// `Subinterface.mtu`
    SubinterfaceMtu,
    /// `Interface.lldp_transmit`
    InterfaceLldpTransmit,
    /// `Interface.lldp_receive`
    InterfaceLldpReceive,
    /// `Interface.lldp_destination`
    InterfaceLldpDestination,
    /// `Interface.subinterfaces` (also a port aggregate's)
    Subinterface,
    /// `Config.broadcast_domains`
    BroadcastDomain,
    /// `BroadcastDomain.addresses`
    BroadcastDomainAddress,
    /// `BroadcastDomain.routing_table`
    BroadcastDomainRoutingTable,
    /// `BroadcastDomain.vni`
    BroadcastDomainVni,
    /// `BroadcastDomain.rd`
    BroadcastDomainRd,
    /// `BroadcastDomain.route_targets_import`/`route_targets_export`
    BroadcastDomainRouteTarget,
    /// `BroadcastDomain.vtep_source`
    BroadcastDomainVtepSource,
    /// `BroadcastDomain.mac_redistribute`
    BroadcastDomainMacRedistribute,
    /// `BroadcastDomain.arp_redistribute`
    BroadcastDomainArpRedistribute,
    /// `BroadcastDomain.connected_redistribute`
    BroadcastDomainConnectedRedistribute,
    /// `BroadcastDomain.neigh_suppress`
    BroadcastDomainNeighSuppress,
    /// `BroadcastDomain.max_remote_macs`
    BroadcastDomainMaxRemoteMacs,
    /// `Config.switching_profiles`
    SwitchingProfile,
    /// `SwitchingProfile.members`
    SwitchingProfileMember,
    /// `Config.port_aggregates`
    PortAggregate,
    /// `PortAggregate.mode`
    PortAggregateMode,
    /// `PortAggregate.lacp_rate`
    PortAggregateLacpRate,
    /// `PortAggregate.esi`
    PortAggregateEsi,
    /// `PortAggregate.lacp_system_id`
    PortAggregateLacpSystemId,
    /// `PortAggregate.redundancy_mode`
    PortAggregateRedundancyMode,
    /// `PortAggregate.df_algorithm`
    PortAggregateDfAlgorithm,
    /// `Config.ospf_instances`
    OspfInstance,
    /// `OspfInstance.router_id`
    OspfInstanceRouterId,
    /// `OspfInstance.graceful_restart_grace_period`
    OspfInstanceGracefulRestart,
    /// `OspfInstance.prefix_suppression`
    OspfInstancePrefixSuppression,
    /// `OspfInstance.max_metric_on_startup`
    OspfInstanceMaxMetricOnStartup,
    /// `OspfInstance.max_metric_on_shutdown`
    OspfInstanceMaxMetricOnShutdown,
    /// `OspfInstance.max_metric_administrative`
    OspfInstanceMaxMetricAdministrative,
    /// `OspfInstance.host_router`
    OspfInstanceHostRouter,
    /// `OspfInstance.remote_lfa`
    OspfInstanceRemoteLfa,
    /// `OspfInstance.areas`
    OspfArea,
    /// `OspfArea.profiles`
    OspfProfile,
    /// `OspfProfile.hello_interval` (also `OSPFv3`'s)
    OspfProfileHelloInterval,
    /// `OspfProfile.dead_interval` (also `OSPFv3`'s)
    OspfProfileDeadInterval,
    /// `OspfProfile.cost` (also `OSPFv3`'s)
    OspfProfileCost,
    /// `OspfProfile.priority` (also `OSPFv3`'s)
    OspfProfilePriority,
    /// `OspfProfile.mtu` (also `OSPFv3`'s)
    OspfProfileMtu,
    /// `OspfProfile.mtu_ignore` (also `OSPFv3`'s)
    OspfProfileMtuIgnore,
    /// `OspfProfile.network_type` (also `OSPFv3`'s)
    OspfProfileNetworkType,
    /// `OspfProfile.extended_sequence_numbers`
    OspfProfileExtendedSequenceNumbers,
    /// `OspfProfile.auth`
    OspfProfileAuth,
    /// `simple-password` sugar on `OspfProfile.auth`
    OspfProfileSimplePassword,
    /// `crypto-key` sugar on `OspfProfile.auth`
    OspfProfileCryptoKey,
    /// `Config.ospfv3_instances`
    Ospfv3Instance,
    /// `Ospfv3Instance.router_id`
    Ospfv3InstanceRouterId,
    /// `Ospfv3Instance.extended_lsa`
    Ospfv3InstanceExtendedLsa,
    /// `Ospfv3Instance.graceful_restart_grace_period`
    Ospfv3InstanceGracefulRestart,
    /// `Ospfv3Instance.areas`
    Ospfv3Area,
    /// `Ospfv3Area.profiles`
    Ospfv3Profile,
    /// `Ospfv3Profile.auth`
    Ospfv3ProfileAuth,
    /// `crypto-key` sugar on `Ospfv3Profile.auth`
    Ospfv3ProfileCryptoKey,
    /// `Ospfv3Profile.instance_id`
    Ospfv3ProfileInstanceId,
    /// `Config.policy_definitions`
    PolicyDefinition,
    /// `PolicyDefinition.source`
    PolicyDefinitionSource,
    /// `Config.community_aliases`
    CommunityAlias,
    /// `CommunityAlias.value`
    CommunityAliasValue,
    /// `Config.community_groups`
    CommunityGroup,
    /// `CommunityGroup.members`
    CommunityGroupMember,
    /// `Config.prefix_lists`
    PrefixList,
    /// `PrefixList.entries`
    PrefixListEntry,
    /// `Config.as_path_lists`
    AsPathList,
    /// `AsPathList.patterns`
    AsPathListPattern,
    /// `BgpPeerGroup.maximum_prefix` and its per-family words
    BgpPeerGroupMaximumPrefix,
    /// `BgpPrefixLimit.limit`
    BgpPeerGroupMaximumPrefixLimit,
    /// `BgpPrefixLimit.warning_only`
    BgpPeerGroupMaximumPrefixWarningOnly,
    /// `BgpPrefixLimit.restart_interval`
    BgpPeerGroupMaximumPrefixRestartInterval,
    /// `clear bgp <instance> <peer>`
    BgpClearPeer,
    /// `BgpInstance.confederation`
    BgpInstanceConfederation,
    /// `BgpConfederation.identifier`
    BgpInstanceConfederationIdentifier,
    /// `BgpConfederation.peers`
    BgpInstanceConfederationPeer,
    /// `BgpInstance.bmp_stations`
    BgpInstanceBmpStation,
    /// `BmpStation.address`
    BgpInstanceBmpStationAddress,
    /// `BmpStation.port`
    BgpInstanceBmpStationPort,
    /// `BgpInstance.rpki_caches`
    BgpInstanceRpkiCache,
    /// `RpkiCache.port`
    BgpInstanceRpkiCachePort,
    /// `RpkiCache.preference`
    BgpInstanceRpkiCachePreference,
    /// `RpkiCache.auth`
    BgpInstanceRpkiCacheAuth,
    /// `md5-password` sugar on `RpkiCache.auth`
    BgpInstanceRpkiCacheMd5Password,
    /// `ao-key` sugar on `RpkiCache.auth`
    BgpInstanceRpkiCacheAoKey,
    /// `BgpInstance.aggregates`
    BgpInstanceAggregate,
    /// `BgpAggregate.as_set`
    BgpInstanceAggregateAsSet,
    /// `BgpAggregate.summary_only`
    BgpInstanceAggregateSummaryOnly,
    /// `OspfArea.area_type`
    OspfAreaType,
    /// `OspfArea.stub_default_cost`
    OspfAreaStubDefaultCost,
    /// `OspfArea.ranges`
    OspfAreaRange,
    /// `OspfAreaRange.not_advertise`
    OspfAreaRangeAdvertise,
    /// `OspfArea.virtual_links`
    OspfAreaVirtualLink,
    /// `OspfVirtualLink.hello_interval`
    OspfVirtualLinkHelloInterval,
    /// `OspfVirtualLink.dead_interval`
    OspfVirtualLinkDeadInterval,
    /// `OspfVirtualLink.auth`
    OspfVirtualLinkAuth,
    /// `simple-password` sugar on `OspfVirtualLink.auth`
    OspfVirtualLinkSimplePassword,
    /// `crypto-key` sugar on `OspfVirtualLink.auth`
    OspfVirtualLinkCryptoKey,
    /// `OspfArea.nssa_translate_always`
    OspfAreaNssaTranslateAlways,
    /// `OspfArea.nssa_default_originate`
    OspfAreaNssaDefaultOriginate,
    /// `BgpPeerGroup.announce_rpki_state`
    BgpPeerGroupAnnounceRpkiState,
    /// `BgpInstance.maximum_paths`
    BgpInstanceMaximumPaths,
    /// `BgpPeerGroup.route_refresh_stale_time`
    BgpPeerGroupRouteRefreshStaleTime,
    /// `BgpPeerGroup.local_as`
    BgpPeerGroupLocalAs,
    /// `BgpInstance.graceful_restart`
    BgpInstanceGracefulRestart,
    /// `BgpPeerGroup.add_path`
    BgpPeerGroupAddPath,
    /// `BgpPeerGroup.add_path_send_count`
    BgpPeerGroupAddPathSendCount,
    /// `BgpPeerGroup.role`
    BgpPeerGroupRole,
    /// `BgpPeerGroup.strict_mode`
    BgpPeerGroupStrictMode,
    /// `PortAggregate.min_links`
    PortAggregateMinLinks,
    /// `PortAggregate.bfd`
    PortAggregateBfd,
    /// `PortAggregate.bfd_peer`
    PortAggregateBfdPeer,
    /// `PortAggregate.lacp_system_priority`
    PortAggregateLacpSystemPriority,
    /// `Interface.lacp_port_priority`
    InterfaceLacpPortPriority,
    /// `Interface.lacp_mode`
    InterfaceLacpMode,
    /// `Config.bfd_profiles`
    BfdProfile,
    /// `BfdProfile.min_tx_interval`
    BfdProfileMinTx,
    /// `BfdProfile.min_rx_interval`
    BfdProfileMinRx,
    /// `BfdProfile.detect_multiplier`
    BfdProfileDetectMultiplier,
    /// `BfdProfile.passive`
    BfdProfilePassive,
    /// `BfdProfile.minimum_ttl`
    BfdProfileMinimumTtl,
    /// `BfdProfile.shutdown`
    BfdProfileShutdown,
    /// `BfdProfile.auth`
    BfdProfileAuth,
    /// `BfdProfile.echo_mode`
    BfdProfileEchoMode,
    /// `BfdProfile.echo_interval`
    BfdProfileEchoInterval,
    /// `BfdProfile.padded_pdu_size`
    BfdProfilePaddedPduSize,
    /// `BfdProfile.mode`
    BfdProfileMode,
    /// `BfdProfile.sbfd_remote_discriminator`
    BfdProfileSbfdRemoteDiscriminator,
    /// `Config.sbfd_reflector`
    SbfdReflector,
    /// `SbfdReflector.discriminators`
    SbfdReflectorDiscriminator,
    /// `SbfdReflector.allow_from`
    SbfdReflectorAllowFrom,
    /// The `bfd` reference on a peer-group, OSPF/OSPFv3 profile or static route
    BfdReference,
    /// `Config.spanning_tree`
    SpanningTree,
    /// `SpanningTree.mode`
    SpanningTreeMode,
    /// `SpanningTree.priority`
    SpanningTreePriority,
    /// `SpanningTree.hello_time`
    SpanningTreeHelloTime,
    /// `SpanningTree.max_age`
    SpanningTreeMaxAge,
    /// `SpanningTree.forward_delay`
    SpanningTreeForwardDelay,
    /// `SpanningTree.tx_hold_count`
    SpanningTreeTxHoldCount,
    /// `SpanningTree.max_hops`
    SpanningTreeMaxHops,
    /// `SpanningTree.force_version`
    SpanningTreeForceVersion,
    /// `SpanningTree.region`
    SpanningTreeRegion,
    /// `SpanningTree.mst_instances`
    SpanningTreeMstInstance,
    /// `MstInstance.priority`
    SpanningTreeMstInstancePriority,
    /// `Config.stp_port_profiles`
    StpPortProfile,
    /// `StpPortProfile.edge_port`
    StpPortProfileEdgePort,
    /// `StpPortProfile.link_type`
    StpPortProfileLinkType,
    /// `StpPortProfile.cost`
    StpPortProfileCost,
    /// `StpPortProfile.priority`
    StpPortProfilePriority,
    /// `StpPortProfile.bpdu_guard`
    StpPortProfileBpduGuard,
    /// `StpPortProfile.bpdu_guard_recovery`
    StpPortProfileBpduGuardRecovery,
    /// `StpPortProfile.bpdu_filter`
    StpPortProfileBpduFilter,
    /// `StpPortProfile.root_guard`
    StpPortProfileRootGuard,
    /// `StpPortProfile.loop_guard`
    StpPortProfileLoopGuard,
    /// `StpPortProfile.restricted_tcn`
    StpPortProfileRestrictedTcn,
    /// `StpPortProfile.mst_instances`
    StpPortProfileMstInstance,
    /// `StpPortMstInstance.cost`
    StpPortProfileMstInstanceCost,
    /// `StpPortMstInstance.priority`
    StpPortProfileMstInstancePriority,
    /// `Config.acls`
    Acl,
    /// `Acl.default_action`
    AclDefaultAction,
    /// `Acl.rules`
    AclRule,
    /// `AclRule.action`
    AclRuleAction,
    /// `AclRule.protocol`
    AclRuleProtocol,
    /// `AclRule.source`
    AclRuleSource,
    /// `AclRule.destination`
    AclRuleDestination,
    /// `AclRule.source_port`
    AclRuleSourcePort,
    /// `AclRule.destination_port`
    AclRuleDestinationPort,
    /// `AclRule.established`
    AclRuleEstablished,
    /// `AclRule.icmp_type`
    AclRuleIcmpType,
    /// `AclRule.icmp_code`
    AclRuleIcmpCode,
    /// `AclRule.log`
    AclRuleLog,
    /// `Interface.acl_in`
    InterfaceAclIn,
    /// `Interface.acl_out`
    InterfaceAclOut,
    /// `Interface.stp_port_profile`
    InterfaceStpPortProfile,
    /// `PortAggregate.stp_port_profile`
    PortAggregateStpPortProfile,
    /// `BroadcastDomain.stp_instance`
    BroadcastDomainStpInstance,
    /// `BroadcastDomain.stp_priority`
    BroadcastDomainStpPriority,
    /// `BroadcastDomain.stp_hello_time`
    BroadcastDomainStpHelloTime,
    /// `BroadcastDomain.stp_max_age`
    BroadcastDomainStpMaxAge,
    /// `BroadcastDomain.stp_forward_delay`
    BroadcastDomainStpForwardDelay,
    /// `SwitchingProfileMember.stp_cost`
    SwitchingProfileMemberStpCost,
    /// `SwitchingProfileMember.stp_priority`
    SwitchingProfileMemberStpPriority,
    /// `Interface.flowspec` (also `Subinterface`/`PortAggregate`)
    InterfaceFlowspec,
    /// `BgpPeerGroup.soft_reconfiguration_inbound`
    BgpPeerGroupSoftReconfigurationInbound,
    /// `BgpPeerGroup.graceful_shutdown`
    BgpPeerGroupGracefulShutdown,
    /// `BgpPeerGroup.graceful_shutdown_receive_disabled`
    BgpPeerGroupGracefulShutdownReceiveDisabled,
    /// `BgpPeerGroup.blackhole`
    BgpPeerGroupBlackhole,
    /// `BmpStation.monitor`
    BgpInstanceBmpStationMonitor,
    /// `BmpStation.statistics_interval`
    BgpInstanceBmpStationStatisticsInterval,
    /// `BmpStation.monitor_out`
    BgpInstanceBmpStationMonitorOut,
}

/// What an operation does, authored by `nos-config` and served to any client
/// over IPC (`Request::Describe` / `Event::Descriptions`). Deliberately has
/// no "usage" field — exact invocation syntax (argument order, keywords) is
/// specific to each client and doesn't belong here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandDoc {
    /// The topic this documentation belongs to.
    pub topic: Topic,
    /// One-line description.
    pub summary: String,
    /// Fuller explanation, including caveats or side effects.
    pub detail: String,
}
