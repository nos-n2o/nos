use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::schema::{Config, Interface, InterfaceAddress, Subinterface};

use super::interface::find_interface_mut;
use super::OpError;

/// An edit to a single `Subinterface` (keyed by `tag`) nested under a named
/// `Interface`, within a transaction's in-progress config. Applied without
/// validation — `garde` validation only runs at commit, matching every
/// other `Op`. `AddAddress`/`SetRoutingTable` upsert the subinterface entry
/// itself if it doesn't already exist (but require the parent `Interface`
/// to exist), the same cascading-create shape `InterfaceOp::Ensure`/
/// `AddAddress` already give the interface itself — this is what lets a
/// bare `edit interface eth0.100` followed by `set address ...` work in one
/// step, without a separate "create the subinterface" op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubinterfaceOp {
    /// Creates the subinterface if it doesn't already exist (creating its
    /// parent `Interface` too, if needed); no-op if it does. Backs
    /// `edit interface <name>.<tag>`'s "create if missing, else navigate to
    /// it" semantics.
    Ensure {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// Upserts by address, mirroring `InterfaceOp::AddAddress`.
    AddAddress {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Address in CIDR notation assigned to the subinterface.
        address: IpNet,
        /// Optional label tagging the address.
        label: Option<String>,
    },
    /// Removes address `address` from the subinterface.
    RemoveAddress {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Address in CIDR notation assigned to the subinterface.
        address: IpNet,
    },
    /// Sets the routing table of the subinterface to `routing_table`.
    SetRoutingTable {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Name of the routing table (VRF) to attach to.
        routing_table: String,
    },
    /// Clears the routing table of the subinterface so it reverts to the default.
    ClearRoutingTable {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// Upserts the subinterface entry (and its parent `Interface`), mirroring
    /// `SetRoutingTable`.
    SetOspfProfile {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Name of the OSPF profile to attach.
        ospf_profile: String,
    },
    /// Clears the OSPF profile of the subinterface so it reverts to the default.
    ClearOspfProfile {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// Same shape as `SetOspfProfile`/`ClearOspfProfile`, joining `OSPFv3`
    /// (RFC 5340) instead.
    SetOspfv3Profile {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Name of the `OSPFv3` profile to attach.
        ospfv3_profile: String,
    },
    /// Clears the `OSPFv3` profile of the subinterface so it reverts to the default.
    ClearOspfv3Profile {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// RFC 9468 unsolicited BFD under the named `BfdProfile`.
    SetBfdUnsolicited {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Unsolicited-BFD settings (RFC 9468).
        bfd_unsolicited: String,
    },
    /// Clears the BFD unsolicited of the subinterface so it reverts to the default.
    ClearBfdUnsolicited {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// Overrides the MTU of the subinterface's VLAN sub-link.
    SetMtu {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// MTU in bytes.
        mtu: u32,
    },
    /// Clears the MTU override so the sub-link follows its parent again.
    ClearMtu {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// Deletes the subinterface and everything nested under it.
    Delete {
        /// Name of the parent interface.
        interface: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
}

impl SubinterfaceOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            SubinterfaceOp::Ensure { interface, tag } => {
                ensure_subinterface_mut(config, interface, *tag)?;
                Ok(())
            }
            SubinterfaceOp::AddAddress {
                interface,
                tag,
                address,
                label,
            } => {
                let sub = ensure_subinterface_mut(config, interface, *tag)?;
                match sub.addresses.iter_mut().find(|a| &a.address == address) {
                    Some(existing) => existing.label.clone_from(label),
                    None => sub.addresses.push(InterfaceAddress {
                        address: *address,
                        label: label.clone(),
                    }),
                }
                Ok(())
            }
            SubinterfaceOp::RemoveAddress {
                interface,
                tag,
                address,
            } => {
                let sub = find_subinterface_mut(config, interface, *tag)?;
                let before = sub.addresses.len();
                sub.addresses.retain(|a| &a.address != address);
                if sub.addresses.len() == before {
                    return Err(OpError::SubinterfaceAddressNotFound {
                        interface: interface.clone(),
                        tag: *tag,
                        address: *address,
                    });
                }
                Ok(())
            }
            SubinterfaceOp::SetRoutingTable {
                interface,
                tag,
                routing_table,
            } => {
                ensure_subinterface_mut(config, interface, *tag)?.routing_table =
                    Some(routing_table.clone());
                Ok(())
            }
            SubinterfaceOp::ClearRoutingTable { interface, tag } => {
                find_subinterface_mut(config, interface, *tag)?.routing_table = None;
                Ok(())
            }
            SubinterfaceOp::SetOspfProfile {
                interface,
                tag,
                ospf_profile,
            } => {
                ensure_subinterface_mut(config, interface, *tag)?.ospf_profile =
                    Some(ospf_profile.clone());
                Ok(())
            }
            SubinterfaceOp::ClearOspfProfile { interface, tag } => {
                find_subinterface_mut(config, interface, *tag)?.ospf_profile = None;
                Ok(())
            }
            SubinterfaceOp::SetOspfv3Profile {
                interface,
                tag,
                ospfv3_profile,
            } => {
                ensure_subinterface_mut(config, interface, *tag)?.ospfv3_profile =
                    Some(ospfv3_profile.clone());
                Ok(())
            }
            SubinterfaceOp::ClearOspfv3Profile { interface, tag } => {
                find_subinterface_mut(config, interface, *tag)?.ospfv3_profile = None;
                Ok(())
            }
            SubinterfaceOp::SetBfdUnsolicited {
                interface,
                tag,
                bfd_unsolicited,
            } => {
                ensure_subinterface_mut(config, interface, *tag)?.bfd_unsolicited =
                    Some(bfd_unsolicited.clone());
                Ok(())
            }
            SubinterfaceOp::ClearBfdUnsolicited { interface, tag } => {
                find_subinterface_mut(config, interface, *tag)?.bfd_unsolicited = None;
                Ok(())
            }
            SubinterfaceOp::SetMtu {
                interface,
                tag,
                mtu,
            } => {
                ensure_subinterface_mut(config, interface, *tag)?.mtu = Some(*mtu);
                Ok(())
            }
            SubinterfaceOp::ClearMtu { interface, tag } => {
                find_subinterface_mut(config, interface, *tag)?.mtu = None;
                Ok(())
            }
            SubinterfaceOp::Delete { interface, tag } => {
                let iface = find_interface_mut(config, interface)?;
                let before = iface.subinterfaces.len();
                iface.subinterfaces.retain(|s| s.tag != *tag);
                if iface.subinterfaces.len() == before {
                    return Err(OpError::SubinterfaceNotFound {
                        interface: interface.clone(),
                        tag: *tag,
                    });
                }
                Ok(())
            }
        }
    }
}

fn find_subinterface_mut<'a>(
    config: &'a mut Config,
    interface: &str,
    tag: u16,
) -> Result<&'a mut Subinterface, OpError> {
    find_interface_mut(config, interface)?
        .subinterfaces
        .iter_mut()
        .find(|s| s.tag == tag)
        .ok_or_else(|| OpError::SubinterfaceNotFound {
            interface: interface.to_string(),
            tag,
        })
}

/// Finds the subinterface, creating it (and its parent `Interface`, via
/// `InterfaceOp::Ensure`-equivalent inline logic) if either is missing.
fn ensure_subinterface_mut<'a>(
    config: &'a mut Config,
    interface: &str,
    tag: u16,
) -> Result<&'a mut Subinterface, OpError> {
    if !config.interfaces.iter().any(|i| i.name == interface) {
        config.interfaces.push(Interface {
            acl_in: None,
            acl_out: None,
            flowspec: false,
            name: interface.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: None,
            switching_profile: None,
            port_aggregate: None,
            stp_port_profile: None,
            lacp_port_priority: None,
            lacp_link_number: None,
            lacp_mode: crate::schema::LacpMode::default(),
            mtu: None,
            lldp_transmit: false,
            lldp_receive: false,
            lldp_destination: crate::schema::LldpDestination::default(),
            subinterfaces: Vec::new(),
        });
    }
    let iface = find_interface_mut(config, interface)?;
    if !iface.subinterfaces.iter().any(|s| s.tag == tag) {
        iface.subinterfaces.push(Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            tag,
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: None,
            bfd_unsolicited: None,
        });
    }
    Ok(iface
        .subinterfaces
        .iter_mut()
        .find(|s| s.tag == tag)
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Interface, InterfaceAddress};

    fn interface(name: &str, subinterfaces: Vec<Subinterface>) -> Interface {
        Interface {
            acl_in: None,
            acl_out: None,
            flowspec: false,
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: None,
            switching_profile: None,
            port_aggregate: None,
            stp_port_profile: None,
            lacp_port_priority: None,
            lacp_link_number: None,
            lacp_mode: crate::schema::LacpMode::default(),
            mtu: None,
            lldp_transmit: false,
            lldp_receive: false,
            lldp_destination: crate::schema::LldpDestination::default(),
            subinterfaces,
        }
    }

    fn addr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn ensure_creates_subinterface_and_parent_when_both_missing() {
        let mut cfg = Config::default();
        SubinterfaceOp::Ensure {
            interface: "eth0".to_string(),
            tag: 100,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].name, "eth0");
        assert_eq!(cfg.interfaces[0].subinterfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].subinterfaces[0].tag, 100);
    }

    #[test]
    fn ensure_creates_subinterface_on_existing_parent() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0", vec![])],
            ..Default::default()
        };
        SubinterfaceOp::Ensure {
            interface: "eth0".to_string(),
            tag: 0,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].subinterfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].subinterfaces[0].tag, 0);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            interfaces: vec![interface(
                "eth0",
                vec![Subinterface {
                    mtu: None,
                    acl_in: None,
                    acl_out: None,
                    flowspec: false,
                    tag: 0,
                    addresses: vec![InterfaceAddress {
                        address: addr("10.0.0.1/24"),
                        label: None,
                    }],
                    routing_table: None,
                    ospf_profile: None,
                    ospfv3_profile: None,
                    bfd_unsolicited: None,
                }],
            )],
            ..Default::default()
        };
        SubinterfaceOp::Ensure {
            interface: "eth0".to_string(),
            tag: 0,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].subinterfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].subinterfaces[0].addresses.len(), 1);
    }

    #[test]
    fn add_address_cascades_interface_and_subinterface_creation() {
        let mut cfg = Config::default();
        SubinterfaceOp::AddAddress {
            interface: "eth0".to_string(),
            tag: 100,
            address: addr("10.0.0.1/24"),
            label: None,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].subinterfaces[0].tag, 100);
        assert_eq!(
            cfg.interfaces[0].subinterfaces[0].addresses[0].address,
            addr("10.0.0.1/24")
        );
    }

    #[test]
    fn add_address_upserts_label_on_existing_address() {
        let mut cfg = Config::default();
        SubinterfaceOp::AddAddress {
            interface: "eth0".to_string(),
            tag: 0,
            address: addr("10.0.0.1/24"),
            label: Some("a".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        SubinterfaceOp::AddAddress {
            interface: "eth0".to_string(),
            tag: 0,
            address: addr("10.0.0.1/24"),
            label: Some("b".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        let sub = &cfg.interfaces[0].subinterfaces[0];
        assert_eq!(sub.addresses.len(), 1);
        assert_eq!(sub.addresses[0].label.as_deref(), Some("b"));
    }

    #[test]
    fn remove_address_removes_existing() {
        let mut cfg = Config::default();
        SubinterfaceOp::AddAddress {
            interface: "eth0".to_string(),
            tag: 0,
            address: addr("10.0.0.1/24"),
            label: None,
        }
        .apply(&mut cfg)
        .unwrap();
        SubinterfaceOp::RemoveAddress {
            interface: "eth0".to_string(),
            tag: 0,
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].subinterfaces[0].addresses, []);
    }

    #[test]
    fn remove_address_missing_subinterface_errors() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0", vec![])],
            ..Default::default()
        };
        let err = SubinterfaceOp::RemoveAddress {
            interface: "eth0".to_string(),
            tag: 100,
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::SubinterfaceNotFound { interface, tag }
            if interface == "eth0" && tag == 100
        ));
    }

    #[test]
    fn remove_missing_address_errors() {
        let mut cfg = Config::default();
        SubinterfaceOp::Ensure {
            interface: "eth0".to_string(),
            tag: 0,
        }
        .apply(&mut cfg)
        .unwrap();
        let err = SubinterfaceOp::RemoveAddress {
            interface: "eth0".to_string(),
            tag: 0,
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::SubinterfaceAddressNotFound { interface, tag, address }
            if interface == "eth0" && tag == 0 && address == addr("10.0.0.1/24")
        ));
    }

    #[test]
    fn set_and_clear_routing_table() {
        let mut cfg = Config::default();
        SubinterfaceOp::SetRoutingTable {
            interface: "eth0".to_string(),
            tag: 0,
            routing_table: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.interfaces[0].subinterfaces[0].routing_table.as_deref(),
            Some("rt1")
        );

        SubinterfaceOp::ClearRoutingTable {
            interface: "eth0".to_string(),
            tag: 0,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].subinterfaces[0].routing_table, None);
    }

    #[test]
    fn set_and_clear_mtu() {
        let mut cfg = Config::default();
        SubinterfaceOp::SetMtu {
            interface: "eth0".to_string(),
            tag: 100,
            mtu: 9000,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].subinterfaces[0].mtu, Some(9000));
        SubinterfaceOp::ClearMtu {
            interface: "eth0".to_string(),
            tag: 100,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].subinterfaces[0].mtu, None);
    }

    #[test]
    fn set_and_clear_ospf_profile() {
        let mut cfg = Config::default();
        SubinterfaceOp::SetOspfProfile {
            interface: "eth0".to_string(),
            tag: 0,
            ospf_profile: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.interfaces[0].subinterfaces[0].ospf_profile.as_deref(),
            Some("p1")
        );

        SubinterfaceOp::ClearOspfProfile {
            interface: "eth0".to_string(),
            tag: 0,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].subinterfaces[0].ospf_profile, None);
    }

    #[test]
    fn clear_routing_table_missing_subinterface_errors() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0", vec![])],
            ..Default::default()
        };
        let err = SubinterfaceOp::ClearRoutingTable {
            interface: "eth0".to_string(),
            tag: 0,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::SubinterfaceNotFound { interface, tag }
            if interface == "eth0" && tag == 0
        ));
    }

    #[test]
    fn add_address_missing_parent_interface_still_cascades() {
        // Unlike InterfaceOp::AddAddress (which errors if the interface is
        // missing), SubinterfaceOp::AddAddress cascades parent creation the
        // same way SubinterfaceOp::Ensure does — see the type's doc comment.
        let mut cfg = Config::default();
        SubinterfaceOp::AddAddress {
            interface: "eth0".to_string(),
            tag: 0,
            address: addr("10.0.0.1/24"),
            label: None,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            interfaces: vec![interface(
                "eth0",
                vec![
                    Subinterface {
                        mtu: None,
                        acl_in: None,
                        acl_out: None,
                        flowspec: false,
                        tag: 0,
                        addresses: Vec::new(),
                        routing_table: None,
                        ospf_profile: None,
                        ospfv3_profile: None,
                        bfd_unsolicited: None,
                    },
                    Subinterface {
                        mtu: None,
                        acl_in: None,
                        acl_out: None,
                        flowspec: false,
                        tag: 100,
                        addresses: Vec::new(),
                        routing_table: None,
                        ospf_profile: None,
                        ospfv3_profile: None,
                        bfd_unsolicited: None,
                    },
                ],
            )],
            ..Default::default()
        };
        SubinterfaceOp::Delete {
            interface: "eth0".to_string(),
            tag: 100,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].subinterfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].subinterfaces[0].tag, 0);
    }

    #[test]
    fn delete_missing_subinterface_errors() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0", vec![])],
            ..Default::default()
        };
        let err = SubinterfaceOp::Delete {
            interface: "eth0".to_string(),
            tag: 0,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::SubinterfaceNotFound { interface, tag }
            if interface == "eth0" && tag == 0
        ));
    }

    #[test]
    fn delete_missing_interface_errors() {
        let mut cfg = Config::default();
        let err = SubinterfaceOp::Delete {
            interface: "eth0".to_string(),
            tag: 0,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::InterfaceNotFound(n) if n == "eth0"));
    }
}
