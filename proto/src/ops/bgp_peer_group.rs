use serde::{Deserialize, Serialize};

use crate::schema::{
    AddressFamily, BgpAddPath, BgpAoKey, BgpAuth, BgpBlackhole, BgpDamping, BgpLocalAs,
    BgpPeerGroup, BgpPrefixLimit, BgpRole, BgpShutdown, Config, NextHopMode, SourceAddress,
};

use super::bgp_instance::find_instance_mut;
use super::OpError;

/// An edit to a single named `BgpPeerGroup` within a given BGP instance, in
/// a transaction's in-progress config. Applied without validation — `garde`
/// validation only runs at commit time, matching `BgpInstanceOp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpPeerGroupOp {
    /// Creates the peer-group with placeholder field values if it doesn't
    /// already exist by name within `instance`; no-op if it does. Backs
    /// `edit peer-group <name>`'s "create if missing, else navigate to it"
    /// semantics.
    Ensure {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the remote AS of the BGP peer group to `remote_as`.
    SetRemoteAs {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Remote AS number the session expects.
        remote_as: u32,
    },
    /// Sets the source address of the BGP peer group to `source`.
    SetSourceAddress {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Local address or interface the session binds to.
        source: SourceAddress,
    },
    /// Clears the source address of the BGP peer group so it reverts to the default.
    ClearSourceAddress {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Idempotent — no-op if `af` is already present.
    AddAddressFamily {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Address family (IPv4/IPv6 unicast, EVPN) the setting applies to.
        af: AddressFamily,
    },
    /// Idempotent — no-op if `af` is already absent.
    RemoveAddressFamily {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Address family (IPv4/IPv6 unicast, EVPN) the setting applies to.
        af: AddressFamily,
    },
    /// Deletes the BGP peer group and everything nested under it.
    Delete {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the hold time of the BGP peer group to `hold_time`.
    SetHoldTime {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// BGP hold time in seconds (RFC 4271 §4.2).
        hold_time: u16,
    },
    /// Clears the hold time of the BGP peer group so it reverts to the default.
    ClearHoldTime {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the keepalive interval of the BGP peer group to `keepalive_interval`.
    SetKeepaliveInterval {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Keepalive interval in seconds (RFC 4271 §4.4).
        keepalive_interval: u16,
    },
    /// Clears the keepalive interval of the BGP peer group so it reverts to the default.
    ClearKeepaliveInterval {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the connect retry time of the BGP peer group to `connect_retry_time`.
    SetConnectRetryTime {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// `ConnectRetry` timer in seconds (RFC 4271 §8.2.2).
        connect_retry_time: u16,
    },
    /// Clears the connect retry time of the BGP peer group so it reverts to the default.
    ClearConnectRetryTime {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the MRAI of the BGP peer group to `mrai`.
    SetMrai {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Minimum route advertisement interval in seconds (RFC 4271 §9.2.1.1).
        mrai: u16,
    },
    /// Clears the MRAI of the BGP peer group so it reverts to the default.
    ClearMrai {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the route refresh stale time of the BGP peer group to `seconds`.
    SetRouteRefreshStaleTime {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Route-refresh stale-route timeout in seconds (RFC 7313).
        seconds: u16,
    },
    /// Clears the route refresh stale time of the BGP peer group so it reverts to the default.
    ClearRouteRefreshStaleTime {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the RFC 7999 blackhole handling of the BGP peer group (see `BgpBlackhole`).
    SetBlackhole {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Name of the prefix-list bounding what the peers may blackhole.
        prefix_list: String,
    },
    /// Clears the blackhole handling of the BGP peer group.
    ClearBlackhole {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the damping of the BGP peer group to `damping`.
    SetDamping {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Route-flap damping parameters (RFC 2439).
        damping: BgpDamping,
    },
    /// Clears the damping of the BGP peer group so it reverts to the default.
    ClearDamping {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the max hops of the BGP peer group to `max_hops`.
    SetMaxHops {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Maximum TTL hops to the peer (eBGP multihop; 1 means directly connected).
        max_hops: u8,
    },
    /// Clears the max hops of the BGP peer group so it reverts to the default.
    ClearMaxHops {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets `auth` to a single MD5 password, replacing any TCP-AO keys
    /// (the two mechanisms are mutually exclusive — the kernel accepts only
    /// one per socket).
    SetMd5Auth {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Label of the admin key holding the TCP MD5 password (RFC 2385).
        key_ref: String,
    },
    /// Upserts one TCP-AO key by `send_id`. If `auth` isn't already `Ao`
    /// (unset, or `Md5`), starts a fresh key list with just this key.
    SetAoKey {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// TCP-AO key (RFC 5925) to store.
        key: BgpAoKey,
    },
    /// Removes one TCP-AO key by `send_id`. No-op if `auth` isn't `Ao` or
    /// the id isn't present — does not clear `auth` back to `None` even if
    /// the list becomes empty; commit-time validation rejects an empty
    /// `Ao` list, so an explicit `ClearAuth` is required for that case.
    RemoveAoKey {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// TCP-AO `SendID` (RFC 5925 §3.1), unique per peer group.
        send_id: u8,
    },
    /// Marks one existing TCP-AO key as the current key, clearing the flag
    /// on every other key in the list.
    SetAoCurrentKey {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// TCP-AO `SendID` (RFC 5925 §3.1), unique per peer group.
        send_id: u8,
    },
    /// Marks one existing TCP-AO key as the rnext key, clearing the flag on
    /// every other key in the list.
    SetAoRnextKey {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// TCP-AO `SendID` (RFC 5925 §3.1), unique per peer group.
        send_id: u8,
    },
    /// Unsets `auth` entirely, regardless of which mechanism was set.
    ClearAuth {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the next hop of the BGP peer group to `mode`.
    SetNextHop {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Next-hop handling: self, unchanged or default.
        mode: NextHopMode,
    },
    /// Clears the next hop of the BGP peer group so it reverts to the default.
    ClearNextHop {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Enables route reflector client on the BGP peer group.
    SetRouteReflectorClient {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// RFC 8097 `announce_rpki_state` on/off.
    SetAnnounceRpkiState {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// `true` turns the feature on, `false` turns it off.
        enabled: bool,
    },
    /// `soft_reconfiguration_inbound` on/off.
    SetSoftReconfigurationInbound {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// `true` turns the feature on, `false` turns it off.
        enabled: bool,
    },
    /// `graceful_shutdown` (RFC 8326 sender) on/off.
    SetGracefulShutdown {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// `true` turns the feature on, `false` turns it off.
        enabled: bool,
    },
    /// `graceful_shutdown_receive_disabled` on/off (`true` ignores 65535:0).
    SetGracefulShutdownReceiveDisabled {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// `true` turns the receiver side off, `false` back on.
        enabled: bool,
    },
    /// Clears the route reflector client of the BGP peer group so it reverts to the default.
    ClearRouteReflectorClient {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Enables route server client on the BGP peer group.
    SetRouteServerClient {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Clears the route server client of the BGP peer group so it reverts to the default.
    ClearRouteServerClient {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the import policy of the BGP peer group to `import_policy`.
    SetImportPolicy {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Name of the policy applied to routes received from the peer.
        import_policy: String,
    },
    /// Clears the import policy of the BGP peer group so it reverts to the default.
    ClearImportPolicy {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the export policy of the BGP peer group to `export_policy`.
    SetExportPolicy {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Name of the policy applied to routes sent to the peer.
        export_policy: String,
    },
    /// Clears the export policy of the BGP peer group so it reverts to the default.
    ClearExportPolicy {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Administratively shuts the whole peer-group (see `BgpShutdown`).
    SetShutdown {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Optional shutdown communication (RFC 8203) sent to the peer.
        message: Option<String>,
    },
    /// Clears the shutdown of the BGP peer group so it reverts to the default.
    ClearShutdown {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets one address family's RFC 4486 maximum-prefix limit.
    SetMaximumPrefix {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Address family the setting applies to.
        family: AddressFamily,
        /// Maximum number of prefixes accepted before the session is dropped.
        limit: BgpPrefixLimit,
    },
    /// Removes one address family's maximum-prefix limit (no-op if unset).
    ClearMaximumPrefix {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Address family the setting applies to.
        family: AddressFamily,
    },
    /// Sets the vendor `local-as` (see `BgpLocalAs`).
    SetLocalAs {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// AS number presented to the peer instead of the instance ASN.
        local_as: BgpLocalAs,
    },
    /// Clears the local AS of the BGP peer group so it reverts to the default.
    ClearLocalAs {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets RFC 7911 ADD-PATH (see `BgpAddPath`).
    SetAddPath {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Next-hop handling: self, unchanged or default.
        mode: BgpAddPath,
    },
    /// Clears the add path of the BGP peer group so it reverts to the default.
    ClearAddPath {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets RFC 7911 `add_path_send_count`.
    SetAddPathSendCount {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Maximum number of additional paths advertised per prefix (RFC 7911).
        count: u8,
    },
    /// Clears the add path send count of the BGP peer group so it reverts to the default.
    ClearAddPathSendCount {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the RFC 9234 role (see `BgpRole`).
    SetRole {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// BGP role (RFC 9234) of the session.
        role: BgpRole,
    },
    /// Clears the role of the BGP peer group so it reverts to the default.
    ClearRole {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the strict mode of the BGP peer group to `enabled`.
    SetStrictMode {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// `true` turns the feature on, `false` turns it off.
        enabled: bool,
    },
    /// Sets the EVPN import policy of the BGP peer group to `evpn_import_policy`.
    SetEvpnImportPolicy {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// Name of the policy applied to EVPN routes received from the peer.
        evpn_import_policy: String,
    },
    /// Clears the EVPN import policy of the BGP peer group (accept all).
    ClearEvpnImportPolicy {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the first-AS check of the BGP peer group (see `BgpPeerGroup::enforce_first_as`).
    SetEnforceFirstAs {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// `false` accepts a path whose first AS is not the peer's.
        enabled: bool,
    },
    /// Clears the first-AS check setting of the BGP peer group (back to on).
    ClearEnforceFirstAs {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
    },
    /// Sets the Flowspec import (`export: false`) or export policy of the
    /// BGP peer group; `None` clears it (accept all).
    SetFlowspecPolicy {
        /// Name of the BGP instance owning the target.
        instance: String,
        /// Name of the BGP peer group this op targets.
        name: String,
        /// `true` for `flowspec_export_policy`, `false` for `flowspec_import_policy`.
        export: bool,
        /// Name of the policy, or `None` to clear it.
        policy: Option<String>,
    },
}

impl BgpPeerGroupOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BgpPeerGroupOp::SetGracefulShutdown {
                instance,
                name,
                enabled,
            } => {
                find_group_mut(config, instance, name)?.graceful_shutdown = *enabled;
                Ok(())
            }
            BgpPeerGroupOp::SetGracefulShutdownReceiveDisabled {
                instance,
                name,
                enabled,
            } => {
                find_group_mut(config, instance, name)?.graceful_shutdown_receive_disabled =
                    *enabled;
                Ok(())
            }
            BgpPeerGroupOp::SetSoftReconfigurationInbound {
                instance,
                name,
                enabled,
            } => {
                find_group_mut(config, instance, name)?.soft_reconfiguration_inbound = *enabled;
                Ok(())
            }
            BgpPeerGroupOp::Ensure { .. }
            | BgpPeerGroupOp::SetMaximumPrefix { .. }
            | BgpPeerGroupOp::ClearMaximumPrefix { .. }
            | BgpPeerGroupOp::SetShutdown { .. }
            | BgpPeerGroupOp::ClearShutdown { .. }
            | BgpPeerGroupOp::SetRemoteAs { .. }
            | BgpPeerGroupOp::SetSourceAddress { .. }
            | BgpPeerGroupOp::ClearSourceAddress { .. }
            | BgpPeerGroupOp::AddAddressFamily { .. }
            | BgpPeerGroupOp::RemoveAddressFamily { .. }
            | BgpPeerGroupOp::Delete { .. }
            | BgpPeerGroupOp::SetHoldTime { .. }
            | BgpPeerGroupOp::ClearHoldTime { .. }
            | BgpPeerGroupOp::SetKeepaliveInterval { .. } => self.apply_part1(config),
            BgpPeerGroupOp::ClearKeepaliveInterval { .. }
            | BgpPeerGroupOp::SetConnectRetryTime { .. }
            | BgpPeerGroupOp::ClearConnectRetryTime { .. }
            | BgpPeerGroupOp::SetMrai { .. }
            | BgpPeerGroupOp::ClearMrai { .. }
            | BgpPeerGroupOp::SetRouteRefreshStaleTime { .. }
            | BgpPeerGroupOp::ClearRouteRefreshStaleTime { .. }
            | BgpPeerGroupOp::SetBlackhole { .. }
            | BgpPeerGroupOp::ClearBlackhole { .. }
            | BgpPeerGroupOp::SetDamping { .. }
            | BgpPeerGroupOp::ClearDamping { .. }
            | BgpPeerGroupOp::SetLocalAs { .. }
            | BgpPeerGroupOp::ClearLocalAs { .. }
            | BgpPeerGroupOp::SetAddPath { .. }
            | BgpPeerGroupOp::ClearAddPath { .. }
            | BgpPeerGroupOp::SetAddPathSendCount { .. }
            | BgpPeerGroupOp::SetRole { .. }
            | BgpPeerGroupOp::ClearRole { .. }
            | BgpPeerGroupOp::SetStrictMode { .. }
            | BgpPeerGroupOp::ClearAddPathSendCount { .. }
            | BgpPeerGroupOp::SetMaxHops { .. }
            | BgpPeerGroupOp::ClearMaxHops { .. } => self.apply_part2(config),
            BgpPeerGroupOp::SetMd5Auth { .. }
            | BgpPeerGroupOp::SetAoKey { .. }
            | BgpPeerGroupOp::RemoveAoKey { .. }
            | BgpPeerGroupOp::SetAoCurrentKey { .. }
            | BgpPeerGroupOp::SetAoRnextKey { .. }
            | BgpPeerGroupOp::ClearAuth { .. }
            | BgpPeerGroupOp::SetNextHop { .. }
            | BgpPeerGroupOp::ClearNextHop { .. }
            | BgpPeerGroupOp::SetAnnounceRpkiState { .. }
            | BgpPeerGroupOp::SetRouteReflectorClient { .. }
            | BgpPeerGroupOp::ClearRouteReflectorClient { .. }
            | BgpPeerGroupOp::SetRouteServerClient { .. }
            | BgpPeerGroupOp::ClearRouteServerClient { .. }
            | BgpPeerGroupOp::SetImportPolicy { .. }
            | BgpPeerGroupOp::ClearImportPolicy { .. }
            | BgpPeerGroupOp::SetExportPolicy { .. }
            | BgpPeerGroupOp::ClearExportPolicy { .. }
            | BgpPeerGroupOp::SetEvpnImportPolicy { .. }
            | BgpPeerGroupOp::ClearEvpnImportPolicy { .. }
            | BgpPeerGroupOp::SetEnforceFirstAs { .. }
            | BgpPeerGroupOp::ClearEnforceFirstAs { .. } => self.apply_part3(config),
            BgpPeerGroupOp::SetFlowspecPolicy {
                instance,
                name,
                export,
                policy,
            } => {
                let group = find_group_mut(config, instance, name)?;
                let slot = if *export {
                    &mut group.flowspec_export_policy
                } else {
                    &mut group.flowspec_import_policy
                };
                slot.clone_from(policy);
                Ok(())
            }
        }
    }

    /// Arms of `apply`, split out for length (#425); `apply` names every variant, so a
    /// new one still fails to compile until it is routed to a part.
    fn apply_part1(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BgpPeerGroupOp::Ensure { instance, name } => {
                let inst = find_instance_mut(config, instance)?;
                if !inst.peer_groups.iter().any(|g| &g.name == name) {
                    inst.peer_groups.push(BgpPeerGroup {
                        bfd: None,
                        name: name.clone(),
                        remote_as: 0,
                        source_address: None,
                        address_families: Vec::new(),
                        hold_time: None,
                        keepalive_interval: None,
                        connect_retry_time: None,
                        mrai: None,
                        route_refresh_stale_time: None,
                        damping: None,
                        max_hops: None,
                        auth: None,
                        next_hop: None,
                        route_reflector_client: false,
                        route_server_client: false,
                        import_policy: None,
                        export_policy: None,
                        evpn_import_policy: None,
                        enforce_first_as: None,
                        flowspec_validation: crate::schema::BgpFlowspecValidation::default(),
                        flowspec_import_policy: None,
                        flowspec_export_policy: None,
                        shutdown: None,
                        maximum_prefix: crate::schema::BgpMaximumPrefix::default(),
                        announce_rpki_state: false,
                        soft_reconfiguration_inbound: false,
                        graceful_shutdown: false,
                        graceful_shutdown_receive_disabled: false,
                        blackhole: None,
                        local_as: None,
                        add_path: None,
                        add_path_send_count: None,
                        role: None,
                        strict_mode: false,
                    });
                }
                Ok(())
            }
            BgpPeerGroupOp::SetMaximumPrefix {
                instance,
                name,
                family,
                limit,
            } => {
                *find_group_mut(config, instance, name)?
                    .maximum_prefix
                    .slot_mut(*family) = Some(*limit);
                Ok(())
            }
            BgpPeerGroupOp::ClearMaximumPrefix {
                instance,
                name,
                family,
            } => {
                *find_group_mut(config, instance, name)?
                    .maximum_prefix
                    .slot_mut(*family) = None;
                Ok(())
            }
            BgpPeerGroupOp::SetShutdown {
                instance,
                name,
                message,
            } => {
                find_group_mut(config, instance, name)?.shutdown = Some(BgpShutdown {
                    message: message.clone(),
                });
                Ok(())
            }
            BgpPeerGroupOp::ClearShutdown { instance, name } => {
                find_group_mut(config, instance, name)?.shutdown = None;
                Ok(())
            }
            BgpPeerGroupOp::SetRemoteAs {
                instance,
                name,
                remote_as,
            } => {
                find_group_mut(config, instance, name)?.remote_as = *remote_as;
                Ok(())
            }
            BgpPeerGroupOp::SetSourceAddress {
                instance,
                name,
                source,
            } => {
                find_group_mut(config, instance, name)?.source_address = Some(source.clone());
                Ok(())
            }
            BgpPeerGroupOp::ClearSourceAddress { instance, name } => {
                find_group_mut(config, instance, name)?.source_address = None;
                Ok(())
            }
            BgpPeerGroupOp::AddAddressFamily { instance, name, af } => {
                let group = find_group_mut(config, instance, name)?;
                if !group.address_families.contains(af) {
                    group.address_families.push(*af);
                }
                Ok(())
            }
            BgpPeerGroupOp::RemoveAddressFamily { instance, name, af } => {
                find_group_mut(config, instance, name)?
                    .address_families
                    .retain(|a| a != af);
                Ok(())
            }
            BgpPeerGroupOp::Delete { instance, name } => {
                let inst = find_instance_mut(config, instance)?;
                let before = inst.peer_groups.len();
                inst.peer_groups.retain(|g| &g.name != name);
                if inst.peer_groups.len() == before {
                    return Err(OpError::BgpPeerGroupNotFound {
                        instance: instance.clone(),
                        name: name.clone(),
                    });
                }
                Ok(())
            }
            BgpPeerGroupOp::SetHoldTime {
                instance,
                name,
                hold_time,
            } => {
                find_group_mut(config, instance, name)?.hold_time = Some(*hold_time);
                Ok(())
            }
            BgpPeerGroupOp::ClearHoldTime { instance, name } => {
                find_group_mut(config, instance, name)?.hold_time = None;
                Ok(())
            }
            BgpPeerGroupOp::SetKeepaliveInterval {
                instance,
                name,
                keepalive_interval,
            } => {
                find_group_mut(config, instance, name)?.keepalive_interval =
                    Some(*keepalive_interval);
                Ok(())
            }
            _ => unreachable!("routed by `apply`"),
        }
    }

    /// Arms of `apply`, split out for length (#425); `apply` names every variant, so a
    /// new one still fails to compile until it is routed to a part.
    fn apply_part2(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BgpPeerGroupOp::ClearKeepaliveInterval { instance, name } => {
                find_group_mut(config, instance, name)?.keepalive_interval = None;
                Ok(())
            }
            BgpPeerGroupOp::SetConnectRetryTime {
                instance,
                name,
                connect_retry_time,
            } => {
                find_group_mut(config, instance, name)?.connect_retry_time =
                    Some(*connect_retry_time);
                Ok(())
            }
            BgpPeerGroupOp::ClearConnectRetryTime { instance, name } => {
                find_group_mut(config, instance, name)?.connect_retry_time = None;
                Ok(())
            }
            BgpPeerGroupOp::SetMrai {
                instance,
                name,
                mrai,
            } => {
                find_group_mut(config, instance, name)?.mrai = Some(*mrai);
                Ok(())
            }
            BgpPeerGroupOp::ClearMrai { instance, name } => {
                find_group_mut(config, instance, name)?.mrai = None;
                Ok(())
            }
            BgpPeerGroupOp::SetRouteRefreshStaleTime {
                instance,
                name,
                seconds,
            } => {
                find_group_mut(config, instance, name)?.route_refresh_stale_time = Some(*seconds);
                Ok(())
            }
            BgpPeerGroupOp::ClearRouteRefreshStaleTime { instance, name } => {
                find_group_mut(config, instance, name)?.route_refresh_stale_time = None;
                Ok(())
            }
            BgpPeerGroupOp::SetBlackhole {
                instance,
                name,
                prefix_list,
            } => {
                find_group_mut(config, instance, name)?.blackhole = Some(BgpBlackhole {
                    prefix_list: prefix_list.clone(),
                });
                Ok(())
            }
            BgpPeerGroupOp::ClearBlackhole { instance, name } => {
                find_group_mut(config, instance, name)?.blackhole = None;
                Ok(())
            }
            BgpPeerGroupOp::SetDamping {
                instance,
                name,
                damping,
            } => {
                find_group_mut(config, instance, name)?.damping = Some(*damping);
                Ok(())
            }
            BgpPeerGroupOp::ClearDamping { instance, name } => {
                find_group_mut(config, instance, name)?.damping = None;
                Ok(())
            }
            BgpPeerGroupOp::SetLocalAs {
                instance,
                name,
                local_as,
            } => {
                find_group_mut(config, instance, name)?.local_as = Some(*local_as);
                Ok(())
            }
            BgpPeerGroupOp::ClearLocalAs { instance, name } => {
                find_group_mut(config, instance, name)?.local_as = None;
                Ok(())
            }
            BgpPeerGroupOp::SetAddPath {
                instance,
                name,
                mode,
            } => {
                find_group_mut(config, instance, name)?.add_path = Some(*mode);
                Ok(())
            }
            BgpPeerGroupOp::ClearAddPath { instance, name } => {
                find_group_mut(config, instance, name)?.add_path = None;
                Ok(())
            }
            BgpPeerGroupOp::SetAddPathSendCount {
                instance,
                name,
                count,
            } => {
                find_group_mut(config, instance, name)?.add_path_send_count = Some(*count);
                Ok(())
            }
            BgpPeerGroupOp::SetRole {
                instance,
                name,
                role,
            } => {
                find_group_mut(config, instance, name)?.role = Some(*role);
                Ok(())
            }
            BgpPeerGroupOp::ClearRole { instance, name } => {
                find_group_mut(config, instance, name)?.role = None;
                Ok(())
            }
            BgpPeerGroupOp::SetStrictMode {
                instance,
                name,
                enabled,
            } => {
                find_group_mut(config, instance, name)?.strict_mode = *enabled;
                Ok(())
            }
            BgpPeerGroupOp::ClearAddPathSendCount { instance, name } => {
                find_group_mut(config, instance, name)?.add_path_send_count = None;
                Ok(())
            }
            BgpPeerGroupOp::SetMaxHops {
                instance,
                name,
                max_hops,
            } => {
                find_group_mut(config, instance, name)?.max_hops = Some(*max_hops);
                Ok(())
            }
            BgpPeerGroupOp::ClearMaxHops { instance, name } => {
                find_group_mut(config, instance, name)?.max_hops = None;
                Ok(())
            }
            _ => unreachable!("routed by `apply`"),
        }
    }

    /// Arms of `apply`, split out for length (#425); `apply` names every variant, so a
    /// new one still fails to compile until it is routed to a part.
    fn apply_part3(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BgpPeerGroupOp::SetMd5Auth {
                instance,
                name,
                key_ref,
            } => {
                find_group_mut(config, instance, name)?.auth = Some(BgpAuth::Md5 {
                    key_ref: key_ref.clone(),
                });
                Ok(())
            }
            BgpPeerGroupOp::SetAoKey {
                instance,
                name,
                key,
            } => {
                let group = find_group_mut(config, instance, name)?;
                let keys = match &mut group.auth {
                    Some(BgpAuth::Ao { keys }) => keys,
                    Some(BgpAuth::Md5 { .. }) | None => {
                        group.auth = Some(BgpAuth::Ao { keys: Vec::new() });
                        let Some(BgpAuth::Ao { keys }) = &mut group.auth else {
                            unreachable!("just set to Ao above")
                        };
                        keys
                    }
                };
                match keys.iter_mut().find(|k| k.send_id == key.send_id) {
                    Some(existing) => *existing = key.clone(),
                    None => keys.push(key.clone()),
                }
                Ok(())
            }
            BgpPeerGroupOp::RemoveAoKey {
                instance,
                name,
                send_id,
            } => {
                if let Some(BgpAuth::Ao { keys }) =
                    &mut find_group_mut(config, instance, name)?.auth
                {
                    keys.retain(|k| k.send_id != *send_id);
                }
                Ok(())
            }
            BgpPeerGroupOp::SetAoCurrentKey {
                instance,
                name,
                send_id,
            } => set_ao_key_flag(config, instance, name, *send_id, |k, is_target| {
                k.is_current = is_target;
            }),
            BgpPeerGroupOp::SetAoRnextKey {
                instance,
                name,
                send_id,
            } => set_ao_key_flag(config, instance, name, *send_id, |k, is_target| {
                k.is_rnext = is_target;
            }),
            BgpPeerGroupOp::ClearAuth { instance, name } => {
                find_group_mut(config, instance, name)?.auth = None;
                Ok(())
            }
            BgpPeerGroupOp::SetNextHop {
                instance,
                name,
                mode,
            } => {
                find_group_mut(config, instance, name)?.next_hop = Some(*mode);
                Ok(())
            }
            BgpPeerGroupOp::ClearNextHop { instance, name } => {
                find_group_mut(config, instance, name)?.next_hop = None;
                Ok(())
            }
            BgpPeerGroupOp::SetAnnounceRpkiState {
                instance,
                name,
                enabled,
            } => {
                find_group_mut(config, instance, name)?.announce_rpki_state = *enabled;
                Ok(())
            }
            BgpPeerGroupOp::SetRouteReflectorClient { instance, name } => {
                find_group_mut(config, instance, name)?.route_reflector_client = true;
                Ok(())
            }
            BgpPeerGroupOp::ClearRouteReflectorClient { instance, name } => {
                find_group_mut(config, instance, name)?.route_reflector_client = false;
                Ok(())
            }
            BgpPeerGroupOp::SetRouteServerClient { instance, name } => {
                find_group_mut(config, instance, name)?.route_server_client = true;
                Ok(())
            }
            BgpPeerGroupOp::ClearRouteServerClient { instance, name } => {
                find_group_mut(config, instance, name)?.route_server_client = false;
                Ok(())
            }
            BgpPeerGroupOp::SetImportPolicy {
                instance,
                name,
                import_policy,
            } => {
                find_group_mut(config, instance, name)?.import_policy = Some(import_policy.clone());
                Ok(())
            }
            BgpPeerGroupOp::ClearImportPolicy { instance, name } => {
                find_group_mut(config, instance, name)?.import_policy = None;
                Ok(())
            }
            BgpPeerGroupOp::SetExportPolicy {
                instance,
                name,
                export_policy,
            } => {
                find_group_mut(config, instance, name)?.export_policy = Some(export_policy.clone());
                Ok(())
            }
            BgpPeerGroupOp::ClearExportPolicy { instance, name } => {
                find_group_mut(config, instance, name)?.export_policy = None;
                Ok(())
            }
            BgpPeerGroupOp::SetEvpnImportPolicy {
                instance,
                name,
                evpn_import_policy,
            } => {
                find_group_mut(config, instance, name)?.evpn_import_policy =
                    Some(evpn_import_policy.clone());
                Ok(())
            }
            BgpPeerGroupOp::SetEnforceFirstAs {
                instance,
                name,
                enabled,
            } => {
                find_group_mut(config, instance, name)?.enforce_first_as = Some(*enabled);
                Ok(())
            }
            BgpPeerGroupOp::ClearEnforceFirstAs { instance, name } => {
                find_group_mut(config, instance, name)?.enforce_first_as = None;
                Ok(())
            }
            BgpPeerGroupOp::ClearEvpnImportPolicy { instance, name } => {
                find_group_mut(config, instance, name)?.evpn_import_policy = None;
                Ok(())
            }
            _ => unreachable!("routed by `apply`"),
        }
    }
}

/// Shared body of `SetAoCurrentKey`/`SetAoRnextKey`: sets `set_flag(key,
/// true)` on the key matching `send_id` and `set_flag(key, false)` on every
/// other key in the same `Ao` list, enforcing "at most one key has this
/// flag" eagerly rather than deferring to commit-time validation.
fn set_ao_key_flag(
    config: &mut Config,
    instance: &str,
    name: &str,
    send_id: u8,
    set_flag: impl Fn(&mut BgpAoKey, bool),
) -> Result<(), OpError> {
    let group = find_group_mut(config, instance, name)?;
    let Some(BgpAuth::Ao { keys }) = &mut group.auth else {
        return Err(OpError::BgpAoKeyNotFound {
            instance: instance.to_string(),
            name: name.to_string(),
            send_id,
        });
    };
    if !keys.iter().any(|k| k.send_id == send_id) {
        return Err(OpError::BgpAoKeyNotFound {
            instance: instance.to_string(),
            name: name.to_string(),
            send_id,
        });
    }
    for key in keys.iter_mut() {
        set_flag(key, key.send_id == send_id);
    }
    Ok(())
}

fn find_group_mut<'a>(
    config: &'a mut Config,
    instance: &str,
    name: &str,
) -> Result<&'a mut BgpPeerGroup, OpError> {
    let inst = find_instance_mut(config, instance)?;
    inst.peer_groups
        .iter_mut()
        .find(|g| g.name == name)
        .ok_or_else(|| OpError::BgpPeerGroupNotFound {
            instance: instance.to_string(),
            name: name.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::schema::BgpInstance;

    use super::*;

    fn instance(name: &str, groups: Vec<BgpPeerGroup>) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: groups,
            peers: Vec::new(),
            cluster_id: None,
            maximum_paths: None,
            confederation: crate::schema::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            bmp_stations: Vec::new(),
            aggregates: Vec::new(),
            graceful_restart: crate::schema::BgpGracefulRestart::default(),
            routing_table: None,
            redistribute_policy: None,
        }
    }

    fn group(name: &str, remote_as: u32) -> BgpPeerGroup {
        BgpPeerGroup {
            bfd: None,
            name: name.to_string(),
            remote_as,
            source_address: None,
            address_families: vec![],
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
            mrai: None,
            route_refresh_stale_time: None,
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            route_reflector_client: false,
            route_server_client: false,
            import_policy: None,
            export_policy: None,
            evpn_import_policy: None,
            enforce_first_as: None,
            flowspec_validation: crate::schema::BgpFlowspecValidation::default(),
            flowspec_import_policy: None,
            flowspec_export_policy: None,
            shutdown: None,
            maximum_prefix: crate::schema::BgpMaximumPrefix::default(),
            announce_rpki_state: false,
            soft_reconfiguration_inbound: false,
            graceful_shutdown: false,
            graceful_shutdown_receive_disabled: false,
            blackhole: None,
            local_as: None,
            add_path: None,
            add_path_send_count: None,
            role: None,
            strict_mode: false,
        }
    }

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn ensure_creates_placeholder_when_missing() {
        let mut cfg = config_with(vec![instance("r1", vec![])]);
        BgpPeerGroupOp::Ensure {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        let inst = &cfg.bgp_instances[0];
        assert_eq!(inst.peer_groups.len(), 1);
        assert_eq!(inst.peer_groups[0].remote_as, 0);
        assert_eq!(inst.peer_groups[0].source_address, None);
        assert_eq!(inst.peer_groups[0].address_families, []);
        assert_eq!(inst.peer_groups[0].hold_time, None);
        assert_eq!(inst.peer_groups[0].keepalive_interval, None);
        assert_eq!(inst.peer_groups[0].connect_retry_time, None);
    }

    #[test]
    fn set_soft_reconfiguration_inbound_toggles_the_flag() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        for enabled in [true, false] {
            BgpPeerGroupOp::SetSoftReconfigurationInbound {
                instance: "r1".to_string(),
                name: "pg1".to_string(),
                enabled,
            }
            .apply(&mut cfg)
            .unwrap();
            assert_eq!(
                cfg.bgp_instances[0].peer_groups[0].soft_reconfiguration_inbound,
                enabled
            );
        }
    }

    #[test]
    fn set_and_clear_blackhole() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetBlackhole {
            instance: "r1".into(),
            name: "pg1".into(),
            prefix_list: "bh".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].blackhole,
            Some(BgpBlackhole {
                prefix_list: "bh".into()
            })
        );
        BgpPeerGroupOp::ClearBlackhole {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].blackhole, None);
    }

    #[test]
    fn graceful_shutdown_ops_toggle_their_flags() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        let (instance, name) = ("r1".to_string(), "pg1".to_string());
        BgpPeerGroupOp::SetGracefulShutdown {
            instance: instance.clone(),
            name: name.clone(),
            enabled: true,
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::SetGracefulShutdownReceiveDisabled {
            instance,
            name,
            enabled: true,
        }
        .apply(&mut cfg)
        .unwrap();
        let g = &cfg.bgp_instances[0].peer_groups[0];
        assert!(g.graceful_shutdown && g.graceful_shutdown_receive_disabled);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::Ensure {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups.len(), 1);
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].remote_as, 65001);
    }

    #[test]
    fn ensure_missing_instance_errors() {
        let mut cfg = config_with(vec![]);
        let err = BgpPeerGroupOp::Ensure {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpInstanceNotFound(n) if n == "r1"));
    }

    #[test]
    fn set_remote_as_updates_existing() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetRemoteAs {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            remote_as: 65002,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].remote_as, 65002);
    }

    #[test]
    fn set_remote_as_missing_group_errors() {
        let mut cfg = config_with(vec![instance("r1", vec![])]);
        let err = BgpPeerGroupOp::SetRemoteAs {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            remote_as: 65002,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(
            matches!(err, OpError::BgpPeerGroupNotFound { instance, name } if instance == "r1" && name == "pg1")
        );
    }

    #[test]
    fn set_and_clear_source_address() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        let source = SourceAddress::Interface {
            interface: "eth0".to_string(),
            label: None,
        };
        BgpPeerGroupOp::SetSourceAddress {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            source: source.clone(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].source_address,
            Some(source)
        );

        BgpPeerGroupOp::ClearSourceAddress {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].source_address, None);
    }

    #[test]
    fn set_and_clear_hold_time() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetHoldTime {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            hold_time: 30,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].hold_time, Some(30));

        BgpPeerGroupOp::ClearHoldTime {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].hold_time, None);
    }

    #[test]
    fn set_and_clear_next_hop() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetNextHop {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            mode: NextHopMode::Unchanged,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].next_hop,
            Some(NextHopMode::Unchanged)
        );

        BgpPeerGroupOp::ClearNextHop {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].next_hop, None);
    }

    #[test]
    fn set_and_clear_route_reflector_client() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetRouteReflectorClient {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.bgp_instances[0].peer_groups[0].route_reflector_client);

        BgpPeerGroupOp::ClearRouteReflectorClient {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(!cfg.bgp_instances[0].peer_groups[0].route_reflector_client);
    }

    #[test]
    fn set_and_clear_route_server_client() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetRouteServerClient {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.bgp_instances[0].peer_groups[0].route_server_client);

        BgpPeerGroupOp::ClearRouteServerClient {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(!cfg.bgp_instances[0].peer_groups[0].route_server_client);
    }

    #[test]
    fn set_and_clear_import_policy() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetImportPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            import_policy: "accept-all".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].import_policy.as_deref(),
            Some("accept-all")
        );

        BgpPeerGroupOp::ClearImportPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].import_policy, None);
    }

    #[test]
    fn set_and_clear_flowspec_policies() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        let op = |export, policy: Option<&str>| BgpPeerGroupOp::SetFlowspecPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            export,
            policy: policy.map(str::to_string),
        };
        op(false, Some("in")).apply(&mut cfg).unwrap();
        op(true, Some("out")).apply(&mut cfg).unwrap();
        let g = &cfg.bgp_instances[0].peer_groups[0];
        assert_eq!(g.flowspec_import_policy.as_deref(), Some("in"));
        assert_eq!(g.flowspec_export_policy.as_deref(), Some("out"));
        op(false, None).apply(&mut cfg).unwrap();
        let g = &cfg.bgp_instances[0].peer_groups[0];
        assert_eq!(g.flowspec_import_policy, None);
        assert_eq!(g.flowspec_export_policy.as_deref(), Some("out"));
        assert!(op(true, None).apply(&mut config_with(vec![])).is_err());
    }

    #[test]
    fn set_and_clear_evpn_import_policy() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetEvpnImportPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            evpn_import_policy: "rt-only".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0]
                .evpn_import_policy
                .as_deref(),
            Some("rt-only")
        );
        BgpPeerGroupOp::ClearEvpnImportPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].evpn_import_policy, None);
    }

    #[test]
    fn set_and_clear_enforce_first_as() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetEnforceFirstAs {
            instance: "r1".into(),
            name: "pg1".into(),
            enabled: false,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].enforce_first_as,
            Some(false)
        );
        BgpPeerGroupOp::ClearEnforceFirstAs {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].enforce_first_as, None);
    }

    #[test]
    fn set_and_clear_export_policy() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetExportPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            export_policy: "deny-all".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].export_policy.as_deref(),
            Some("deny-all")
        );

        BgpPeerGroupOp::ClearExportPolicy {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].export_policy, None);
    }

    #[test]
    fn set_and_clear_keepalive_interval() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetKeepaliveInterval {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            keepalive_interval: 10,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].keepalive_interval,
            Some(10)
        );

        BgpPeerGroupOp::ClearKeepaliveInterval {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].keepalive_interval, None);
    }

    #[test]
    fn set_and_clear_damping() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetDamping {
            instance: "r1".into(),
            name: "pg1".into(),
            damping: BgpDamping::default(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].damping,
            Some(BgpDamping::default())
        );
        BgpPeerGroupOp::ClearDamping {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].damping, None);
    }

    #[test]
    fn set_and_clear_local_as() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        let local_as = BgpLocalAs {
            asn: 65009,
            no_prepend: true,
            replace_as: false,
        };
        BgpPeerGroupOp::SetLocalAs {
            instance: "r1".into(),
            name: "pg1".into(),
            local_as,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].local_as, Some(local_as));
        BgpPeerGroupOp::ClearLocalAs {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].local_as, None);
    }

    #[test]
    fn set_and_clear_add_path() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAddPath {
            instance: "r1".into(),
            name: "pg1".into(),
            mode: BgpAddPath::Receive,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].add_path,
            Some(BgpAddPath::Receive)
        );
        BgpPeerGroupOp::ClearAddPath {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].add_path, None);
    }

    #[test]
    fn set_and_clear_add_path_send_count() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAddPathSendCount {
            instance: "r1".into(),
            name: "pg1".into(),
            count: 3,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].add_path_send_count,
            Some(3)
        );
        BgpPeerGroupOp::ClearAddPathSendCount {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].add_path_send_count,
            None
        );
    }

    #[test]
    fn set_and_clear_maximum_prefix_per_family() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        let lim = BgpPrefixLimit {
            limit: 2,
            warning_only: false,
            restart_interval: 0,
        };
        BgpPeerGroupOp::SetMaximumPrefix {
            instance: "r1".into(),
            name: "pg1".into(),
            family: AddressFamily::Ipv4Unicast,
            limit: lim,
        }
        .apply(&mut cfg)
        .unwrap();
        let m = cfg.bgp_instances[0].peer_groups[0].maximum_prefix;
        assert_eq!((m.ipv4, m.ipv6, m.l2vpn_evpn), (Some(lim), None, None));
        BgpPeerGroupOp::ClearMaximumPrefix {
            instance: "r1".into(),
            name: "pg1".into(),
            family: AddressFamily::Ipv4Unicast,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].maximum_prefix,
            crate::schema::BgpMaximumPrefix::default()
        );
    }

    #[test]
    fn set_and_clear_max_hops() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetMaxHops {
            instance: "r1".into(),
            name: "pg1".into(),
            max_hops: 1,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].max_hops, Some(1));
        BgpPeerGroupOp::ClearMaxHops {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].max_hops, None);
    }

    #[test]
    fn set_and_clear_mrai() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetMrai {
            instance: "r1".into(),
            name: "pg1".into(),
            mrai: 30,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].mrai, Some(30));
        BgpPeerGroupOp::ClearMrai {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].mrai, None);
    }

    #[test]
    fn set_and_clear_route_refresh_stale_time() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetRouteRefreshStaleTime {
            instance: "r1".into(),
            name: "pg1".into(),
            seconds: 5,
        }
        .apply(&mut cfg)
        .unwrap();
        let pg = |cfg: &Config| cfg.bgp_instances[0].peer_groups[0].route_refresh_stale_time;
        assert_eq!(pg(&cfg), Some(5));
        BgpPeerGroupOp::ClearRouteRefreshStaleTime {
            instance: "r1".into(),
            name: "pg1".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(pg(&cfg), None);
    }

    #[test]
    fn set_and_clear_connect_retry_time() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetConnectRetryTime {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            connect_retry_time: 45,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].connect_retry_time,
            Some(45)
        );

        BgpPeerGroupOp::ClearConnectRetryTime {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].connect_retry_time, None);
    }

    #[test]
    fn add_and_remove_address_family_are_idempotent() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        for _ in 0..2 {
            BgpPeerGroupOp::AddAddressFamily {
                instance: "r1".to_string(),
                name: "pg1".to_string(),
                af: AddressFamily::Ipv4Unicast,
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].address_families,
            vec![AddressFamily::Ipv4Unicast]
        );

        for _ in 0..2 {
            BgpPeerGroupOp::RemoveAddressFamily {
                instance: "r1".to_string(),
                name: "pg1".to_string(),
                af: AddressFamily::Ipv4Unicast,
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].address_families, []);
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = config_with(vec![instance(
            "r1",
            vec![group("pg1", 65001), group("pg2", 65002)],
        )]);
        BgpPeerGroupOp::Delete {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups.len(), 1);
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].name, "pg2");
    }

    #[test]
    fn delete_missing_group_errors() {
        let mut cfg = config_with(vec![instance("r1", vec![])]);
        let err = BgpPeerGroupOp::Delete {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(
            matches!(err, OpError::BgpPeerGroupNotFound { instance, name } if instance == "r1" && name == "pg1")
        );
    }

    use crate::schema::BgpAoAlgorithm;

    fn ao_key(send_id: u8) -> BgpAoKey {
        BgpAoKey {
            send_id,
            recv_id: send_id,
            algorithm: BgpAoAlgorithm::HmacSha1_96,
            key_ref: "secret".to_string(),
            is_current: false,
            is_rnext: false,
            exclude_options: false,
        }
    }

    #[test]
    fn set_md5_auth_sets_password() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetMd5Auth {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key_ref: "secret".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].auth,
            Some(BgpAuth::Md5 {
                key_ref: "secret".to_string()
            })
        );
    }

    #[test]
    fn set_md5_auth_replaces_existing_ao_keys() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::SetMd5Auth {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key_ref: "secret".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].auth,
            Some(BgpAuth::Md5 {
                key_ref: "secret".to_string()
            })
        );
    }

    #[test]
    fn set_ao_key_starts_fresh_list_from_none() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].auth,
            Some(BgpAuth::Ao {
                keys: vec![ao_key(1)]
            })
        );
    }

    #[test]
    fn set_ao_key_upserts_by_send_id() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        let mut updated = ao_key(1);
        updated.key_ref = "new-secret".to_string();
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: updated.clone(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].auth,
            Some(BgpAuth::Ao {
                keys: vec![updated]
            })
        );
    }

    #[test]
    fn remove_ao_key_removes_by_send_id() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(2),
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::RemoveAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 1,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].peer_groups[0].auth,
            Some(BgpAuth::Ao {
                keys: vec![ao_key(2)]
            })
        );
    }

    #[test]
    fn remove_ao_key_is_noop_when_not_ao() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::RemoveAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 1,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].auth, None);
    }

    #[test]
    fn set_ao_current_key_sets_only_the_target() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        for id in [1, 2] {
            BgpPeerGroupOp::SetAoKey {
                instance: "r1".to_string(),
                name: "pg1".to_string(),
                key: ao_key(id),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        BgpPeerGroupOp::SetAoCurrentKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 1,
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::SetAoCurrentKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 2,
        }
        .apply(&mut cfg)
        .unwrap();
        let Some(BgpAuth::Ao { keys }) = &cfg.bgp_instances[0].peer_groups[0].auth else {
            panic!("expected Ao auth");
        };
        assert!(!keys.iter().find(|k| k.send_id == 1).unwrap().is_current);
        assert!(keys.iter().find(|k| k.send_id == 2).unwrap().is_current);
    }

    #[test]
    fn set_ao_current_key_missing_id_errors() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetAoKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key: ao_key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        let err = BgpPeerGroupOp::SetAoCurrentKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 9,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpAoKeyNotFound { send_id, .. } if send_id == 9));
    }

    #[test]
    fn set_ao_current_key_when_no_auth_errors() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        let err = BgpPeerGroupOp::SetAoCurrentKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 1,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpAoKeyNotFound { .. }));
    }

    #[test]
    fn set_ao_rnext_key_sets_only_the_target() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        for id in [1, 2] {
            BgpPeerGroupOp::SetAoKey {
                instance: "r1".to_string(),
                name: "pg1".to_string(),
                key: ao_key(id),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        BgpPeerGroupOp::SetAoRnextKey {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            send_id: 2,
        }
        .apply(&mut cfg)
        .unwrap();
        let Some(BgpAuth::Ao { keys }) = &cfg.bgp_instances[0].peer_groups[0].auth else {
            panic!("expected Ao auth");
        };
        assert!(!keys.iter().find(|k| k.send_id == 1).unwrap().is_rnext);
        assert!(keys.iter().find(|k| k.send_id == 2).unwrap().is_rnext);
    }

    #[test]
    fn clear_auth_unsets_md5() {
        let mut cfg = config_with(vec![instance("r1", vec![group("pg1", 65001)])]);
        BgpPeerGroupOp::SetMd5Auth {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
            key_ref: "secret".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        BgpPeerGroupOp::ClearAuth {
            instance: "r1".to_string(),
            name: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peer_groups[0].auth, None);
    }
}
