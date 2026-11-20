use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::schema::{BroadcastDomain, Config, InterfaceAddress, SourceAddress};

use super::{add_ospfv3_profile, remove_ospfv3_profile, OpError};

/// An edit to a single named `BroadcastDomain` within a transaction's
/// in-progress config. Applied without validation, matching every other
/// `Op`. `addresses`/`routing_table` mirror `InterfaceOp`'s own address and
/// routing-table variants exactly — same upsert-by-address semantics for
/// `AddAddress`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BroadcastDomainOp {
    /// Creates the domain if it doesn't already exist; no-op if it does.
    /// Backs `edit broadcast-domain <name>`'s "create if missing, else
    /// navigate to it" semantics.
    Ensure {
        /// Name of the broadcast domain this op targets.
        name: String,
    },
    /// Upserts by address: if `address` is already present on the domain,
    /// this replaces its label rather than adding a duplicate.
    AddAddress {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Gateway address in CIDR notation of the domain's routed interface.
        address: IpNet,
        /// Optional label tagging the address.
        label: Option<String>,
    },
    /// Removes address `address` from the broadcast domain.
    RemoveAddress {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Gateway address in CIDR notation of the domain's routed interface.
        address: IpNet,
    },
    /// Sets the routing table of the broadcast domain to `routing_table`.
    SetRoutingTable {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Name of the routing table (VRF) to attach to.
        routing_table: String,
    },
    /// Clears the routing table of the broadcast domain so it reverts to the default.
    ClearRoutingTable {
        /// Name of the broadcast domain this op targets.
        name: String,
    },
    /// Sets the OSPF profile of the broadcast domain to `ospf_profile`.
    SetOspfProfile {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Name of the OSPF profile to attach.
        ospf_profile: String,
    },
    /// Clears the OSPF profile of the broadcast domain so it reverts to the default.
    ClearOspfProfile {
        /// Name of the broadcast domain this op targets.
        name: String,
    },
    /// Same shape as `SetOspfProfile`/`ClearOspfProfile`, joining `OSPFv3`
    /// (RFC 5340) instead.
    AddOspfv3Profile {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Name of the `OSPFv3` profile to attach.
        ospfv3_profile: String,
    },
    /// Detaches one `OSPFv3` profile from the broadcast domain (error when not attached).
    RemoveOspfv3Profile {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Name of the `OSPFv3` profile to detach.
        ospfv3_profile: String,
    },
    /// Deletes the broadcast domain and everything nested under it.
    Delete {
        /// Name of the broadcast domain this op targets.
        name: String,
    },
    /// EVPN/VXLAN (all appended after `Delete`: postcard indexes by position).
    SetVni {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// VXLAN network identifier (24 bits).
        vni: u32,
    },
    /// Clears the VNI of the broadcast domain so it reverts to the default.
    ClearVni {
        /// Name of the broadcast domain this op targets.
        name: String,
    },
    /// Sets the route distinguisher of the broadcast domain to `rd`.
    SetRd {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Route distinguisher in `ASN:NN` or `IP:NN` form.
        rd: String,
    },
    /// Clears the route distinguisher of the broadcast domain so it reverts to the default.
    ClearRd {
        /// Name of the broadcast domain this op targets.
        name: String,
    },
    /// Idempotent add of one Route Target to the import or export list.
    AddRouteTarget {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// `true` selects the import set, `false` the export set.
        import: bool,
        /// Route target in `ASN:NN` or `IP:NN` form.
        route_target: String,
    },
    /// Removes route target `import` from the broadcast domain.
    RemoveRouteTarget {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// `true` selects the import set, `false` the export set.
        import: bool,
        /// Route target in `ASN:NN` or `IP:NN` form.
        route_target: String,
    },
    /// Sets the VTEP source of the broadcast domain to `vtep_source`.
    SetVtepSource {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Local address or interface used as the VXLAN underlay source.
        vtep_source: SourceAddress,
    },
    /// Clears the VTEP source of the broadcast domain so it reverts to the default.
    ClearVtepSource {
        /// Name of the broadcast domain this op targets.
        name: String,
    },
    /// `redistribute from mac to bgp <bgp_instance>`.
    SetMacRedistribute {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Name of the BGP instance to bind.
        bgp_instance: String,
    },
    /// Clears the MAC redistribute of the broadcast domain so it reverts to the default.
    ClearMacRedistribute {
        /// Name of the broadcast domain this op targets.
        name: String,
    },
    /// `redistribute from arp to bgp <bgp_instance>` — appended: postcard
    /// indexes variants by position.
    SetArpRedistribute {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Name of the BGP instance to bind.
        bgp_instance: String,
    },
    /// Clears the ARP redistribute of the broadcast domain so it reverts to the default.
    ClearArpRedistribute {
        /// Name of the broadcast domain this op targets.
        name: String,
    },
    /// `redistribute from connected to bgp <bgp_instance>`.
    SetConnectedRedistribute {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// Name of the BGP instance to bind.
        bgp_instance: String,
    },
    /// Clears the connected redistribute of the broadcast domain so it reverts to the default.
    ClearConnectedRedistribute {
        /// Name of the broadcast domain this op targets.
        name: String,
    },
    /// `neigh-suppress` (ARP/ND suppression on the VXLAN bridge port).
    SetNeighSuppress {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// `true` turns the feature on, `false` turns it off.
        enabled: bool,
    },
    /// `max-remote-macs`: ceiling on installed remote MACs (`None` clears it).
    SetMaxRemoteMacs {
        /// Name of the broadcast domain this op targets.
        name: String,
        /// The ceiling, or `None` for unlimited.
        max: Option<u32>,
    },
}

impl BroadcastDomainOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BroadcastDomainOp::Ensure { .. }
            | BroadcastDomainOp::AddAddress { .. }
            | BroadcastDomainOp::RemoveAddress { .. }
            | BroadcastDomainOp::SetRoutingTable { .. }
            | BroadcastDomainOp::ClearRoutingTable { .. }
            | BroadcastDomainOp::SetOspfProfile { .. }
            | BroadcastDomainOp::ClearOspfProfile { .. }
            | BroadcastDomainOp::AddOspfv3Profile { .. }
            | BroadcastDomainOp::RemoveOspfv3Profile { .. }
            | BroadcastDomainOp::Delete { .. } => self.apply_part1(config),
            BroadcastDomainOp::SetVni { .. }
            | BroadcastDomainOp::ClearVni { .. }
            | BroadcastDomainOp::SetRd { .. }
            | BroadcastDomainOp::ClearRd { .. }
            | BroadcastDomainOp::AddRouteTarget { .. }
            | BroadcastDomainOp::RemoveRouteTarget { .. }
            | BroadcastDomainOp::SetVtepSource { .. }
            | BroadcastDomainOp::ClearVtepSource { .. }
            | BroadcastDomainOp::SetMacRedistribute { .. }
            | BroadcastDomainOp::ClearMacRedistribute { .. }
            | BroadcastDomainOp::SetArpRedistribute { .. }
            | BroadcastDomainOp::ClearArpRedistribute { .. }
            | BroadcastDomainOp::SetConnectedRedistribute { .. }
            | BroadcastDomainOp::ClearConnectedRedistribute { .. }
            | BroadcastDomainOp::SetNeighSuppress { .. }
            | BroadcastDomainOp::SetMaxRemoteMacs { .. } => self.apply_part2(config),
        }
    }

    /// Arms of `apply`, split out for length (#425); `apply` names every variant, so a
    /// new one still fails to compile until it is routed to a part.
    fn apply_part1(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BroadcastDomainOp::Ensure { name } => {
                if !config.broadcast_domains.iter().any(|d| &d.name == name) {
                    config.broadcast_domains.push(BroadcastDomain {
                        name: name.clone(),
                        addresses: Vec::new(),
                        routing_table: None,
                        ospf_profile: None,
                        ospfv3_profiles: Vec::new(),
                        vni: None,
                        rd: None,
                        route_targets_import: Vec::new(),
                        route_targets_export: Vec::new(),
                        vtep_source: None,
                        mac_redistribute: None,
                        arp_redistribute: None,
                        connected_redistribute: None,
                        neigh_suppress: false,
                        max_remote_macs: None,
                        stp_instance: None,
                        stp_priority: None,
                        stp_hello_time: None,
                        stp_max_age: None,
                        stp_forward_delay: None,
                    });
                }
                Ok(())
            }
            BroadcastDomainOp::AddAddress {
                name,
                address,
                label,
            } => {
                let domain = find_domain_mut(config, name)?;
                match domain.addresses.iter_mut().find(|a| &a.address == address) {
                    Some(existing) => existing.label.clone_from(label),
                    None => domain.addresses.push(InterfaceAddress {
                        address: *address,
                        label: label.clone(),
                    }),
                }
                Ok(())
            }
            BroadcastDomainOp::RemoveAddress { name, address } => {
                let domain = find_domain_mut(config, name)?;
                let before = domain.addresses.len();
                domain.addresses.retain(|a| &a.address != address);
                if domain.addresses.len() == before {
                    return Err(OpError::BroadcastDomainAddressNotFound {
                        name: name.clone(),
                        address: *address,
                    });
                }
                Ok(())
            }
            BroadcastDomainOp::SetRoutingTable {
                name,
                routing_table,
            } => {
                find_domain_mut(config, name)?.routing_table = Some(routing_table.clone());
                Ok(())
            }
            BroadcastDomainOp::ClearRoutingTable { name } => {
                find_domain_mut(config, name)?.routing_table = None;
                Ok(())
            }
            BroadcastDomainOp::SetOspfProfile { name, ospf_profile } => {
                find_domain_mut(config, name)?.ospf_profile = Some(ospf_profile.clone());
                Ok(())
            }
            BroadcastDomainOp::ClearOspfProfile { name } => {
                find_domain_mut(config, name)?.ospf_profile = None;
                Ok(())
            }
            BroadcastDomainOp::AddOspfv3Profile {
                name,
                ospfv3_profile,
            } => {
                add_ospfv3_profile(
                    &mut find_domain_mut(config, name)?.ospfv3_profiles,
                    ospfv3_profile,
                );
                Ok(())
            }
            BroadcastDomainOp::RemoveOspfv3Profile {
                name,
                ospfv3_profile,
            } => {
                remove_ospfv3_profile(
                    &mut find_domain_mut(config, name)?.ospfv3_profiles,
                    ospfv3_profile,
                )?;
                Ok(())
            }
            BroadcastDomainOp::Delete { name } => {
                let before = config.broadcast_domains.len();
                config.broadcast_domains.retain(|d| &d.name != name);
                if config.broadcast_domains.len() == before {
                    return Err(OpError::BroadcastDomainNotFound(name.clone()));
                }
                Ok(())
            }
            _ => unreachable!("routed by `apply`"),
        }
    }

    /// Arms of `apply`, split out for length (#425); `apply` names every variant, so a
    /// new one still fails to compile until it is routed to a part.
    fn apply_part2(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BroadcastDomainOp::SetVni { name, vni } => {
                find_domain_mut(config, name)?.vni = Some(*vni);
                Ok(())
            }
            BroadcastDomainOp::ClearVni { name } => {
                find_domain_mut(config, name)?.vni = None;
                Ok(())
            }
            BroadcastDomainOp::SetRd { name, rd } => {
                find_domain_mut(config, name)?.rd = Some(rd.clone());
                Ok(())
            }
            BroadcastDomainOp::ClearRd { name } => {
                find_domain_mut(config, name)?.rd = None;
                Ok(())
            }
            BroadcastDomainOp::AddRouteTarget {
                name,
                import,
                route_target,
            } => {
                let d = find_domain_mut(config, name)?;
                let list = if *import {
                    &mut d.route_targets_import
                } else {
                    &mut d.route_targets_export
                };
                if !list.contains(route_target) {
                    list.push(route_target.clone());
                }
                Ok(())
            }
            BroadcastDomainOp::RemoveRouteTarget {
                name,
                import,
                route_target,
            } => {
                let d = find_domain_mut(config, name)?;
                let list = if *import {
                    &mut d.route_targets_import
                } else {
                    &mut d.route_targets_export
                };
                let before = list.len();
                list.retain(|r| r != route_target);
                if list.len() == before {
                    return Err(OpError::BroadcastDomainRouteTargetNotFound {
                        name: name.clone(),
                        route_target: route_target.clone(),
                    });
                }
                Ok(())
            }
            BroadcastDomainOp::SetVtepSource { name, vtep_source } => {
                find_domain_mut(config, name)?.vtep_source = Some(vtep_source.clone());
                Ok(())
            }
            BroadcastDomainOp::ClearVtepSource { name } => {
                find_domain_mut(config, name)?.vtep_source = None;
                Ok(())
            }
            BroadcastDomainOp::SetMacRedistribute { name, bgp_instance } => {
                find_domain_mut(config, name)?.mac_redistribute = Some(bgp_instance.clone());
                Ok(())
            }
            BroadcastDomainOp::ClearMacRedistribute { name } => {
                find_domain_mut(config, name)?.mac_redistribute = None;
                Ok(())
            }
            BroadcastDomainOp::SetArpRedistribute { name, bgp_instance } => {
                find_domain_mut(config, name)?.arp_redistribute = Some(bgp_instance.clone());
                Ok(())
            }
            BroadcastDomainOp::ClearArpRedistribute { name } => {
                find_domain_mut(config, name)?.arp_redistribute = None;
                Ok(())
            }
            BroadcastDomainOp::SetConnectedRedistribute { name, bgp_instance } => {
                find_domain_mut(config, name)?.connected_redistribute = Some(bgp_instance.clone());
                Ok(())
            }
            BroadcastDomainOp::ClearConnectedRedistribute { name } => {
                find_domain_mut(config, name)?.connected_redistribute = None;
                Ok(())
            }
            BroadcastDomainOp::SetNeighSuppress { name, enabled } => {
                find_domain_mut(config, name)?.neigh_suppress = *enabled;
                Ok(())
            }
            BroadcastDomainOp::SetMaxRemoteMacs { name, max } => {
                find_domain_mut(config, name)?.max_remote_macs = *max;
                Ok(())
            }
            _ => unreachable!("routed by `apply`"),
        }
    }
}

fn find_domain_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut BroadcastDomain, OpError> {
    config
        .broadcast_domains
        .iter_mut()
        .find(|d| d.name == name)
        .ok_or_else(|| OpError::BroadcastDomainNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> BroadcastDomain {
        BroadcastDomain {
            ospfv3_profiles: Vec::new(),
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            vni: None,
            rd: None,
            route_targets_import: Vec::new(),
            route_targets_export: Vec::new(),
            vtep_source: None,
            mac_redistribute: None,
            arp_redistribute: None,
            connected_redistribute: None,
            neigh_suppress: false,
            max_remote_macs: None,
            stp_instance: None,
            stp_priority: None,
            stp_hello_time: None,
            stp_max_age: None,
            stp_forward_delay: None,
        }
    }

    fn addr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn set_neigh_suppress_toggles() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        let op = |enabled| BroadcastDomainOp::SetNeighSuppress {
            name: "bd1".to_string(),
            enabled,
        };
        op(true).apply(&mut cfg).unwrap();
        assert!(cfg.broadcast_domains[0].neigh_suppress);
        op(false).apply(&mut cfg).unwrap();
        assert!(!cfg.broadcast_domains[0].neigh_suppress);
    }

    #[test]
    fn set_max_remote_macs_sets_and_clears() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        let op = |max| BroadcastDomainOp::SetMaxRemoteMacs {
            name: "bd1".to_string(),
            max,
        };
        op(Some(5)).apply(&mut cfg).unwrap();
        assert_eq!(cfg.broadcast_domains[0].max_remote_macs, Some(5));
        op(None).apply(&mut cfg).unwrap();
        assert_eq!(cfg.broadcast_domains[0].max_remote_macs, None);
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        BroadcastDomainOp::Ensure {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains.len(), 1);
        assert_eq!(cfg.broadcast_domains[0].name, "bd1");
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        BroadcastDomainOp::Ensure {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains.len(), 1);
    }

    #[test]
    fn add_and_remove_address() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        BroadcastDomainOp::AddAddress {
            name: "bd1".to_string(),
            address: addr("10.0.0.1/24"),
            label: None,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains[0].addresses.len(), 1);

        BroadcastDomainOp::RemoveAddress {
            name: "bd1".to_string(),
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains[0].addresses, []);
    }

    #[test]
    fn add_address_upserts_label_on_existing_address() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        BroadcastDomainOp::AddAddress {
            name: "bd1".to_string(),
            address: addr("10.0.0.1/24"),
            label: Some("a".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        BroadcastDomainOp::AddAddress {
            name: "bd1".to_string(),
            address: addr("10.0.0.1/24"),
            label: Some("b".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains[0].addresses.len(), 1);
        assert_eq!(
            cfg.broadcast_domains[0].addresses[0].label.as_deref(),
            Some("b")
        );
    }

    #[test]
    fn remove_missing_address_errors() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        let err = BroadcastDomainOp::RemoveAddress {
            name: "bd1".to_string(),
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::BroadcastDomainAddressNotFound { name, address }
            if name == "bd1" && address == addr("10.0.0.1/24")
        ));
    }

    #[test]
    fn set_and_clear_routing_table() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        BroadcastDomainOp::SetRoutingTable {
            name: "bd1".to_string(),
            routing_table: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.broadcast_domains[0].routing_table.as_deref(),
            Some("rt1")
        );

        BroadcastDomainOp::ClearRoutingTable {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains[0].routing_table, None);
    }

    #[test]
    fn set_and_clear_ospf_profile() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        BroadcastDomainOp::SetOspfProfile {
            name: "bd1".to_string(),
            ospf_profile: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains[0].ospf_profile.as_deref(), Some("p1"));

        BroadcastDomainOp::ClearOspfProfile {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains[0].ospf_profile, None);
    }

    #[test]
    fn set_routing_table_missing_domain_errors() {
        let mut cfg = Config::default();
        let err = BroadcastDomainOp::SetRoutingTable {
            name: "bd1".to_string(),
            routing_table: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BroadcastDomainNotFound(n) if n == "bd1"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1"), domain("bd2")],
            ..Default::default()
        };
        BroadcastDomainOp::Delete {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.broadcast_domains.len(), 1);
        assert_eq!(cfg.broadcast_domains[0].name, "bd2");
    }

    #[test]
    fn delete_missing_domain_errors() {
        let mut cfg = Config::default();
        let err = BroadcastDomainOp::Delete {
            name: "bd1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BroadcastDomainNotFound(n) if n == "bd1"));
    }

    #[test]
    fn evpn_setters_and_route_target_lists() {
        let mut cfg = Config {
            broadcast_domains: vec![domain("bd1")],
            ..Default::default()
        };
        let n = || "bd1".to_string();
        for op in [
            BroadcastDomainOp::SetVni { name: n(), vni: 10 },
            BroadcastDomainOp::SetRd {
                name: n(),
                rd: "65000:1".to_string(),
            },
            BroadcastDomainOp::AddRouteTarget {
                name: n(),
                import: true,
                route_target: "65000:10".to_string(),
            },
            BroadcastDomainOp::AddRouteTarget {
                name: n(),
                import: true,
                route_target: "65000:10".to_string(),
            },
            BroadcastDomainOp::AddRouteTarget {
                name: n(),
                import: false,
                route_target: "65000:11".to_string(),
            },
            BroadcastDomainOp::SetMacRedistribute {
                name: n(),
                bgp_instance: "r1".to_string(),
            },
            BroadcastDomainOp::SetArpRedistribute {
                name: n(),
                bgp_instance: "r1".to_string(),
            },
            BroadcastDomainOp::SetConnectedRedistribute {
                name: n(),
                bgp_instance: "r1".to_string(),
            },
        ] {
            op.apply(&mut cfg).unwrap();
        }
        let d = &cfg.broadcast_domains[0];
        assert_eq!(d.vni, Some(10));
        assert_eq!(d.route_targets_import, ["65000:10"]);
        assert_eq!(d.route_targets_export, ["65000:11"]);
        assert_eq!(d.mac_redistribute.as_deref(), Some("r1"));
        assert_eq!(d.arp_redistribute.as_deref(), Some("r1"));
        assert_eq!(d.connected_redistribute.as_deref(), Some("r1"));

        let err = BroadcastDomainOp::RemoveRouteTarget {
            name: n(),
            import: false,
            route_target: "65000:10".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::BroadcastDomainRouteTargetNotFound { .. }
        ));
    }

    #[test]
    fn every_set_has_a_clear() {
        let mut cfg = Config::default();
        cfg.broadcast_domains.push(domain("bd1"));
        let n = || "bd1".to_string();
        let rt = |import| BroadcastDomainOp::AddRouteTarget {
            name: n(),
            import,
            route_target: "65000:1".to_string(),
        };
        for op in [
            BroadcastDomainOp::AddOspfv3Profile {
                name: n(),
                ospfv3_profile: "p3".to_string(),
            },
            BroadcastDomainOp::SetVni { name: n(), vni: 1 },
            BroadcastDomainOp::SetRd {
                name: n(),
                rd: "1.1.1.1:1".to_string(),
            },
            BroadcastDomainOp::SetVtepSource {
                name: n(),
                vtep_source: crate::schema::SourceAddress::Interface {
                    interface: "lo".to_string(),
                    label: None,
                },
            },
            rt(true),
            rt(true),
            rt(false),
        ] {
            op.apply(&mut cfg).unwrap();
        }
        let d = &cfg.broadcast_domains[0];
        assert_eq!(d.ospfv3_profiles, ["p3"]);
        assert_eq!(d.rd.as_deref(), Some("1.1.1.1:1"));
        assert!(d.vtep_source.is_some());
        assert_eq!(d.route_targets_import, ["65000:1"], "no duplicate");

        let remove_rt = |import| BroadcastDomainOp::RemoveRouteTarget {
            name: n(),
            import,
            route_target: "65000:1".to_string(),
        };
        for op in [
            BroadcastDomainOp::RemoveOspfv3Profile {
                name: n(),
                ospfv3_profile: "p3".to_string(),
            },
            BroadcastDomainOp::ClearVni { name: n() },
            BroadcastDomainOp::ClearRd { name: n() },
            BroadcastDomainOp::ClearVtepSource { name: n() },
            BroadcastDomainOp::ClearMacRedistribute { name: n() },
            BroadcastDomainOp::ClearArpRedistribute { name: n() },
            BroadcastDomainOp::ClearConnectedRedistribute { name: n() },
            remove_rt(true),
            remove_rt(false),
        ] {
            op.apply(&mut cfg).unwrap();
        }
        assert_eq!(cfg.broadcast_domains[0], domain("bd1"));
        assert!(matches!(
            BroadcastDomainOp::RemoveOspfv3Profile {
                name: n(),
                ospfv3_profile: "p3".to_string(),
            }
            .apply(&mut cfg),
            Err(OpError::Ospfv3ProfileNotAttached(_))
        ));
        assert!(matches!(
            BroadcastDomainOp::ClearVni {
                name: "nope".to_string()
            }
            .apply(&mut cfg),
            Err(OpError::BroadcastDomainNotFound(_))
        ));
    }
}
