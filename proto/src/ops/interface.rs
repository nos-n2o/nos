use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::schema::{Config, Interface, InterfaceAddress, LldpDestination};

use super::OpError;

/// An edit to a single named `Interface` within a transaction's in-progress
/// config. Applied without validation — `garde` validation only runs at
/// commit time, matching every other `Op`. `addresses` has no `Ensure`/`SetX`
/// split since it's a plain list of scalars (not a keyed collection like
/// `StaticRoute`) — `AddAddress`/`RemoveAddress` mutate it directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceOp {
    /// Creates the interface if it doesn't already exist; no-op if it does.
    /// Backs `edit interface <name>`'s "create if missing, else navigate to
    /// it" semantics. A loopback interface is created the same way, simply
    /// by using a `loopback-<table>`-prefixed name (see
    /// `schema::LOOPBACK_PREFIX`) — there is no separate op for it.
    Ensure {
        /// Name of the interface this op targets.
        name: String,
    },
    /// Upserts by address: if `address` is already present on the
    /// interface, this replaces its label rather than adding a duplicate —
    /// re-running `set interface <name> address <addr> label <label>` is
    /// how a label is changed or cleared.
    AddAddress {
        /// Name of the interface this op targets.
        name: String,
        /// Address in CIDR notation assigned to the interface.
        address: IpNet,
        /// Optional label tagging the address.
        label: Option<String>,
    },
    /// Removes address `address` from the interface.
    RemoveAddress {
        /// Name of the interface this op targets.
        name: String,
        /// Address in CIDR notation assigned to the interface.
        address: IpNet,
    },
    /// Sets the routing table of the interface to `routing_table`.
    SetRoutingTable {
        /// Name of the interface this op targets.
        name: String,
        /// Name of the routing table (VRF) to attach to.
        routing_table: String,
    },
    /// Clears the routing table of the interface so it reverts to the default.
    ClearRoutingTable {
        /// Name of the interface this op targets.
        name: String,
    },
    /// Sets the MTU of the interface to `mtu`.
    SetMtu {
        /// Name of the interface this op targets.
        name: String,
        /// MTU in bytes applied to the kernel device.
        mtu: u32,
    },
    /// Clears the MTU of the interface so it reverts to the default.
    ClearMtu {
        /// Name of the interface this op targets.
        name: String,
    },
    /// `set`/`delete interface <name> lldp transmit` — one op with a flag
    /// rather than a `Set`/`Clear` pair, since a bool has no value to clear.
    SetLldpTransmit {
        /// Name of the interface this op targets.
        name: String,
        /// `true` enables the LLDP receive direction, `false` disables it.
        enabled: bool,
    },
    /// Sets the LLDP receive of the interface to `enabled`.
    SetLldpReceive {
        /// Name of the interface this op targets.
        name: String,
        /// `true` enables the LLDP receive direction, `false` disables it.
        enabled: bool,
    },
    /// Sets the LLDP destination of the interface to `destination`.
    SetLldpDestination {
        /// Name of the interface this op targets.
        name: String,
        /// Multicast destination MAC used for this interface's LLDPDUs.
        destination: LldpDestination,
    },
    /// Clears the LLDP destination of the interface so it reverts to the default.
    ClearLldpDestination {
        /// Name of the interface this op targets.
        name: String,
    },
    /// Sets the OSPF profile of the interface to `ospf_profile`.
    SetOspfProfile {
        /// Name of the interface this op targets.
        name: String,
        /// Name of the OSPF profile to attach.
        ospf_profile: String,
    },
    /// Clears the OSPF profile of the interface so it reverts to the default.
    ClearOspfProfile {
        /// Name of the interface this op targets.
        name: String,
    },
    /// Sets the `OSPFv3` profile of the interface to `ospfv3_profile`.
    SetOspfv3Profile {
        /// Name of the interface this op targets.
        name: String,
        /// Name of the `OSPFv3` profile to attach.
        ospfv3_profile: String,
    },
    /// Clears the `OSPFv3` profile of the interface so it reverts to the default.
    ClearOspfv3Profile {
        /// Name of the interface this op targets.
        name: String,
    },
    /// Sets the switching profile of the interface to `switching_profile`.
    SetSwitchingProfile {
        /// Name of the interface this op targets.
        name: String,
        /// Name of the switching profile.
        switching_profile: String,
    },
    /// Clears the switching profile of the interface so it reverts to the default.
    ClearSwitchingProfile {
        /// Name of the interface this op targets.
        name: String,
    },
    /// Enables port aggregate on the interface.
    SetPortAggregate {
        /// Name of the interface this op targets.
        name: String,
        /// Name of the port aggregate.
        port_aggregate: String,
    },
    /// Clears the port aggregate of the interface so it reverts to the default.
    ClearPortAggregate {
        /// Name of the interface this op targets.
        name: String,
    },
    /// Deletes the interface and everything nested under it.
    Delete {
        /// Name of the interface this op targets.
        name: String,
    },
    /// Appended (postcard indexes variants by position).
    SetLacpPortPriority {
        /// Name of the interface this op targets.
        name: String,
        /// Router priority for DR/BDR election (0 makes the router ineligible).
        priority: u16,
    },
    /// Appended (postcard indexes variants by position).
    ClearLacpPortPriority {
        /// Name of the interface this op targets.
        name: String,
    },
    /// Appended (postcard indexes variants by position).
    SetLacpMode {
        /// Name of the interface this op targets.
        name: String,
        /// Mode to select.
        mode: crate::schema::LacpMode,
    },
    /// Appended (postcard indexes variants by position).
    SetLacpLinkNumber {
        /// Name of the interface this op targets.
        name: String,
        /// LACP `Link_Number` (1-65535, unique within the aggregate).
        link_number: u16,
    },
    /// Appended (postcard indexes variants by position).
    ClearLacpLinkNumber {
        /// Name of the interface this op targets.
        name: String,
    },
}

impl InterfaceOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            InterfaceOp::Ensure { name } => {
                if !config.interfaces.iter().any(|i| &i.name == name) {
                    config.interfaces.push(Interface {
                        name: name.clone(),
                        ..Interface::default()
                    });
                }
                Ok(())
            }
            InterfaceOp::AddAddress {
                name,
                address,
                label,
            } => {
                let iface = find_interface_mut(config, name)?;
                match iface.addresses.iter_mut().find(|a| &a.address == address) {
                    Some(existing) => existing.label.clone_from(label),
                    None => iface.addresses.push(InterfaceAddress {
                        address: *address,
                        label: label.clone(),
                    }),
                }
                Ok(())
            }
            InterfaceOp::RemoveAddress { name, address } => {
                let iface = find_interface_mut(config, name)?;
                let before = iface.addresses.len();
                iface.addresses.retain(|a| &a.address != address);
                if iface.addresses.len() == before {
                    return Err(OpError::InterfaceAddressNotFound {
                        name: name.clone(),
                        address: *address,
                    });
                }
                Ok(())
            }
            InterfaceOp::SetRoutingTable {
                name,
                routing_table,
            } => {
                find_interface_mut(config, name)?.routing_table = Some(routing_table.clone());
                Ok(())
            }
            InterfaceOp::ClearRoutingTable { name } => {
                find_interface_mut(config, name)?.routing_table = None;
                Ok(())
            }
            InterfaceOp::SetMtu { name, mtu } => {
                find_interface_mut(config, name)?.mtu = Some(*mtu);
                Ok(())
            }
            InterfaceOp::ClearMtu { name } => {
                find_interface_mut(config, name)?.mtu = None;
                Ok(())
            }
            InterfaceOp::SetLldpTransmit { name, enabled } => {
                find_interface_mut(config, name)?.lldp_transmit = *enabled;
                Ok(())
            }
            InterfaceOp::SetLldpReceive { name, enabled } => {
                find_interface_mut(config, name)?.lldp_receive = *enabled;
                Ok(())
            }
            InterfaceOp::SetLldpDestination { name, destination } => {
                find_interface_mut(config, name)?.lldp_destination = *destination;
                Ok(())
            }
            InterfaceOp::ClearLldpDestination { name } => {
                find_interface_mut(config, name)?.lldp_destination = LldpDestination::default();
                Ok(())
            }
            InterfaceOp::SetOspfProfile { name, ospf_profile } => {
                find_interface_mut(config, name)?.ospf_profile = Some(ospf_profile.clone());
                Ok(())
            }
            InterfaceOp::ClearOspfProfile { name } => {
                find_interface_mut(config, name)?.ospf_profile = None;
                Ok(())
            }
            InterfaceOp::SetOspfv3Profile {
                name,
                ospfv3_profile,
            } => {
                find_interface_mut(config, name)?.ospfv3_profile = Some(ospfv3_profile.clone());
                Ok(())
            }
            InterfaceOp::ClearOspfv3Profile { name } => {
                find_interface_mut(config, name)?.ospfv3_profile = None;
                Ok(())
            }
            InterfaceOp::SetSwitchingProfile {
                name,
                switching_profile,
            } => {
                find_interface_mut(config, name)?.switching_profile =
                    Some(switching_profile.clone());
                Ok(())
            }
            InterfaceOp::ClearSwitchingProfile { name } => {
                find_interface_mut(config, name)?.switching_profile = None;
                Ok(())
            }
            InterfaceOp::SetPortAggregate {
                name,
                port_aggregate,
            } => {
                find_interface_mut(config, name)?.port_aggregate = Some(port_aggregate.clone());
                Ok(())
            }
            InterfaceOp::SetLacpPortPriority { name, priority } => {
                find_interface_mut(config, name)?.lacp_port_priority = Some(*priority);
                Ok(())
            }
            InterfaceOp::SetLacpLinkNumber { name, link_number } => {
                find_interface_mut(config, name)?.lacp_link_number = Some(*link_number);
                Ok(())
            }
            InterfaceOp::ClearLacpLinkNumber { name } => {
                find_interface_mut(config, name)?.lacp_link_number = None;
                Ok(())
            }
            InterfaceOp::SetLacpMode { name, mode } => {
                find_interface_mut(config, name)?.lacp_mode = *mode;
                Ok(())
            }
            InterfaceOp::ClearLacpPortPriority { name } => {
                find_interface_mut(config, name)?.lacp_port_priority = None;
                Ok(())
            }
            InterfaceOp::ClearPortAggregate { name } => {
                find_interface_mut(config, name)?.port_aggregate = None;
                Ok(())
            }
            InterfaceOp::Delete { name } => {
                let before = config.interfaces.len();
                config.interfaces.retain(|i| &i.name != name);
                if config.interfaces.len() == before {
                    return Err(OpError::InterfaceNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn find_interface_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut Interface, OpError> {
    config
        .interfaces
        .iter_mut()
        .find(|i| i.name == name)
        .ok_or_else(|| OpError::InterfaceNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str) -> Interface {
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
            subinterfaces: Vec::new(),
        }
    }

    fn addr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn iface_addr(s: &str) -> InterfaceAddress {
        InterfaceAddress {
            address: addr(s),
            label: None,
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        InterfaceOp::Ensure {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].name, "eth0");
        assert_eq!(cfg.interfaces[0].addresses, []);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            interfaces: vec![Interface {
                acl_in: None,
                acl_out: None,
                flowspec: false,
                ospfv3_profile: None,
                name: "eth0".to_string(),
                addresses: vec![iface_addr("10.0.0.1/24")],
                routing_table: None,
                ospf_profile: None,
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
            }],
            ..Default::default()
        };
        InterfaceOp::Ensure {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].addresses.len(), 1);
    }

    #[test]
    fn add_and_remove_address() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::AddAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
            label: None,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].addresses, vec![iface_addr("10.0.0.1/24")]);

        InterfaceOp::RemoveAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].addresses, []);
    }

    #[test]
    fn add_address_is_idempotent() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        for _ in 0..2 {
            InterfaceOp::AddAddress {
                name: "eth0".to_string(),
                address: addr("10.0.0.1/24"),
                label: None,
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.interfaces[0].addresses.len(), 1);
    }

    #[test]
    fn add_address_with_label() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::AddAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
            label: Some("mgmt".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.interfaces[0].addresses[0].label.as_deref(),
            Some("mgmt")
        );
    }

    #[test]
    fn add_address_upserts_label_on_existing_address() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::AddAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
            label: Some("a".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        InterfaceOp::AddAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
            label: Some("b".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].addresses.len(), 1);
        assert_eq!(cfg.interfaces[0].addresses[0].label.as_deref(), Some("b"));
    }

    #[test]
    fn remove_missing_address_errors() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        let err = InterfaceOp::RemoveAddress {
            name: "eth0".to_string(),
            address: addr("10.0.0.1/24"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::InterfaceAddressNotFound { name, address }
            if name == "eth0" && address == addr("10.0.0.1/24")
        ));
    }

    #[test]
    fn set_and_clear_routing_table() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::SetRoutingTable {
            name: "eth0".to_string(),
            routing_table: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].routing_table.as_deref(), Some("rt1"));

        InterfaceOp::ClearRoutingTable {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].routing_table, None);
    }

    #[test]
    fn set_lldp_transmit_and_receive_independently() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::SetLldpTransmit {
            name: "eth0".to_string(),
            enabled: true,
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.interfaces[0].lldp_transmit);
        assert!(!cfg.interfaces[0].lldp_receive);

        InterfaceOp::SetLldpReceive {
            name: "eth0".to_string(),
            enabled: true,
        }
        .apply(&mut cfg)
        .unwrap();
        InterfaceOp::SetLldpTransmit {
            name: "eth0".to_string(),
            enabled: false,
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(!cfg.interfaces[0].lldp_transmit);
        assert!(cfg.interfaces[0].lldp_receive);
    }

    #[test]
    fn set_and_clear_lldp_destination() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::SetLldpDestination {
            name: "eth0".to_string(),
            destination: LldpDestination::CustomerBridge,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.interfaces[0].lldp_destination,
            LldpDestination::CustomerBridge
        );
        InterfaceOp::ClearLldpDestination {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.interfaces[0].lldp_destination,
            LldpDestination::NearestBridge
        );
    }

    #[test]
    fn set_and_clear_mtu() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::SetMtu {
            name: "eth0".to_string(),
            mtu: 9000,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].mtu, Some(9000));

        InterfaceOp::ClearMtu {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].mtu, None);
    }

    #[test]
    fn set_and_clear_ospf_profile() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::SetOspfProfile {
            name: "eth0".to_string(),
            ospf_profile: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].ospf_profile.as_deref(), Some("p1"));

        InterfaceOp::ClearOspfProfile {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].ospf_profile, None);
    }

    #[test]
    fn set_and_clear_switching_profile() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::SetSwitchingProfile {
            name: "eth0".to_string(),
            switching_profile: "sp1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].switching_profile.as_deref(), Some("sp1"));

        InterfaceOp::ClearSwitchingProfile {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].switching_profile, None);
    }

    #[test]
    fn set_and_clear_lacp_port_priority() {
        let mut cfg = Config::default();
        let name = "eth1".to_string();
        InterfaceOp::Ensure { name: name.clone() }
            .apply(&mut cfg)
            .unwrap();
        InterfaceOp::SetLacpPortPriority {
            name: name.clone(),
            priority: 7,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].lacp_port_priority, Some(7));
        InterfaceOp::ClearLacpPortPriority { name }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.interfaces[0].lacp_port_priority, None);
    }

    #[test]
    fn set_lacp_mode() {
        let mut cfg = Config::default();
        let name = "eth1".to_string();
        InterfaceOp::Ensure { name: name.clone() }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.interfaces[0].lacp_mode, crate::schema::LacpMode::Active);
        InterfaceOp::SetLacpMode {
            name,
            mode: crate::schema::LacpMode::Passive,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.interfaces[0].lacp_mode,
            crate::schema::LacpMode::Passive
        );
    }

    #[test]
    fn set_and_clear_port_aggregate() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0")],
            ..Default::default()
        };
        InterfaceOp::SetPortAggregate {
            name: "eth0".to_string(),
            port_aggregate: "bond1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].port_aggregate.as_deref(), Some("bond1"));

        InterfaceOp::ClearPortAggregate {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].port_aggregate, None);
    }

    #[test]
    fn set_routing_table_missing_interface_errors() {
        let mut cfg = Config::default();
        let err = InterfaceOp::SetRoutingTable {
            name: "eth0".to_string(),
            routing_table: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::InterfaceNotFound(n) if n == "eth0"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            interfaces: vec![interface("eth0"), interface("eth1")],
            ..Default::default()
        };
        InterfaceOp::Delete {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].name, "eth1");
    }

    #[test]
    fn delete_missing_interface_errors() {
        let mut cfg = Config::default();
        let err = InterfaceOp::Delete {
            name: "eth0".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::InterfaceNotFound(n) if n == "eth0"));
    }

    #[test]
    fn set_and_clear_lacp_link_number() {
        let mut cfg = Config::default();
        let name = "eth1".to_string();
        InterfaceOp::Ensure { name: name.clone() }
            .apply(&mut cfg)
            .unwrap();
        InterfaceOp::SetLacpLinkNumber {
            name: name.clone(),
            link_number: 3,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.interfaces[0].lacp_link_number, Some(3));
        InterfaceOp::ClearLacpLinkNumber { name }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.interfaces[0].lacp_link_number, None);
    }
}
