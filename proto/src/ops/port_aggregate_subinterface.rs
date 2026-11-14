use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::schema::{Config, InterfaceAddress, Subinterface};

use super::OpError;

/// An edit to a single `Subinterface` (keyed by `tag`) nested under a named
/// `PortAggregate`, within a transaction's in-progress config — the
/// `PortAggregate` counterpart of `SubinterfaceOp`, which is hard-wired to
/// `Config.interfaces`. Same cascading-create shape: `AddAddress`/
/// `SetRoutingTable`/etc. upsert the subinterface entry (creating it, but
/// *not* its parent `PortAggregate` — unlike `SubinterfaceOp`, an aggregate
/// is never implicitly created by editing one of its subinterfaces, since
/// `mode` has no sensible implicit default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortAggregateSubinterfaceOp {
    /// Creates the port-aggregate subinterface if it does not exist (idempotent).
    Ensure {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// Adds address `address` to the port-aggregate subinterface.
    AddAddress {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Address in CIDR notation assigned to the subinterface.
        address: IpNet,
        /// Optional label tagging the address.
        label: Option<String>,
    },
    /// Removes address `address` from the port-aggregate subinterface.
    RemoveAddress {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Address in CIDR notation assigned to the subinterface.
        address: IpNet,
    },
    /// Sets the routing table of the port-aggregate subinterface to `routing_table`.
    SetRoutingTable {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Name of the routing table (VRF) to attach to.
        routing_table: String,
    },
    /// Clears the routing table of the port-aggregate subinterface so it reverts to the default.
    ClearRoutingTable {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// Sets the OSPF profile of the port-aggregate subinterface to `ospf_profile`.
    SetOspfProfile {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Name of the OSPF profile to attach.
        ospf_profile: String,
    },
    /// Clears the OSPF profile of the port-aggregate subinterface so it reverts to the default.
    ClearOspfProfile {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// Sets the `OSPFv3` profile of the port-aggregate subinterface to `ospfv3_profile`.
    SetOspfv3Profile {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// Name of the `OSPFv3` profile to attach.
        ospfv3_profile: String,
    },
    /// Clears the `OSPFv3` profile of the port-aggregate subinterface so it reverts to the default.
    ClearOspfv3Profile {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// Overrides the MTU of the port-aggregate subinterface's VLAN sub-link.
    SetMtu {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
        /// MTU in bytes.
        mtu: u32,
    },
    /// Clears the MTU override so the sub-link follows its parent again.
    ClearMtu {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
    /// Deletes the port-aggregate subinterface and everything nested under it.
    Delete {
        /// Name of the port aggregate.
        port_aggregate: String,
        /// 802.1Q VLAN tag identifying the subinterface on its parent.
        tag: u16,
    },
}

impl PortAggregateSubinterfaceOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            PortAggregateSubinterfaceOp::Ensure {
                port_aggregate,
                tag,
            } => {
                ensure_subinterface_mut(config, port_aggregate, *tag)?;
                Ok(())
            }
            PortAggregateSubinterfaceOp::AddAddress {
                port_aggregate,
                tag,
                address,
                label,
            } => {
                let sub = ensure_subinterface_mut(config, port_aggregate, *tag)?;
                match sub.addresses.iter_mut().find(|a| &a.address == address) {
                    Some(existing) => existing.label.clone_from(label),
                    None => sub.addresses.push(InterfaceAddress {
                        address: *address,
                        label: label.clone(),
                    }),
                }
                Ok(())
            }
            PortAggregateSubinterfaceOp::RemoveAddress {
                port_aggregate,
                tag,
                address,
            } => {
                let sub = find_subinterface_mut(config, port_aggregate, *tag)?;
                let before = sub.addresses.len();
                sub.addresses.retain(|a| &a.address != address);
                if sub.addresses.len() == before {
                    return Err(OpError::PortAggregateSubinterfaceAddressNotFound {
                        port_aggregate: port_aggregate.clone(),
                        tag: *tag,
                        address: *address,
                    });
                }
                Ok(())
            }
            PortAggregateSubinterfaceOp::SetRoutingTable {
                port_aggregate,
                tag,
                routing_table,
            } => {
                ensure_subinterface_mut(config, port_aggregate, *tag)?.routing_table =
                    Some(routing_table.clone());
                Ok(())
            }
            PortAggregateSubinterfaceOp::ClearRoutingTable {
                port_aggregate,
                tag,
            } => {
                find_subinterface_mut(config, port_aggregate, *tag)?.routing_table = None;
                Ok(())
            }
            PortAggregateSubinterfaceOp::SetOspfProfile {
                port_aggregate,
                tag,
                ospf_profile,
            } => {
                ensure_subinterface_mut(config, port_aggregate, *tag)?.ospf_profile =
                    Some(ospf_profile.clone());
                Ok(())
            }
            PortAggregateSubinterfaceOp::ClearOspfProfile {
                port_aggregate,
                tag,
            } => {
                find_subinterface_mut(config, port_aggregate, *tag)?.ospf_profile = None;
                Ok(())
            }
            PortAggregateSubinterfaceOp::SetOspfv3Profile {
                port_aggregate,
                tag,
                ospfv3_profile,
            } => {
                ensure_subinterface_mut(config, port_aggregate, *tag)?.ospfv3_profile =
                    Some(ospfv3_profile.clone());
                Ok(())
            }
            PortAggregateSubinterfaceOp::ClearOspfv3Profile {
                port_aggregate,
                tag,
            } => {
                find_subinterface_mut(config, port_aggregate, *tag)?.ospfv3_profile = None;
                Ok(())
            }
            PortAggregateSubinterfaceOp::SetMtu {
                port_aggregate,
                tag,
                mtu,
            } => {
                ensure_subinterface_mut(config, port_aggregate, *tag)?.mtu = Some(*mtu);
                Ok(())
            }
            PortAggregateSubinterfaceOp::ClearMtu {
                port_aggregate,
                tag,
            } => {
                find_subinterface_mut(config, port_aggregate, *tag)?.mtu = None;
                Ok(())
            }
            PortAggregateSubinterfaceOp::Delete {
                port_aggregate,
                tag,
            } => {
                let agg = find_aggregate_mut(config, port_aggregate)?;
                let before = agg.subinterfaces.len();
                agg.subinterfaces.retain(|s| s.tag != *tag);
                if agg.subinterfaces.len() == before {
                    return Err(OpError::PortAggregateSubinterfaceNotFound {
                        port_aggregate: port_aggregate.clone(),
                        tag: *tag,
                    });
                }
                Ok(())
            }
        }
    }
}

fn find_aggregate_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut crate::schema::PortAggregate, OpError> {
    config
        .port_aggregates
        .iter_mut()
        .find(|a| a.name == name)
        .ok_or_else(|| OpError::PortAggregateNotFound(name.to_string()))
}

fn find_subinterface_mut<'a>(
    config: &'a mut Config,
    port_aggregate: &str,
    tag: u16,
) -> Result<&'a mut Subinterface, OpError> {
    find_aggregate_mut(config, port_aggregate)?
        .subinterfaces
        .iter_mut()
        .find(|s| s.tag == tag)
        .ok_or_else(|| OpError::PortAggregateSubinterfaceNotFound {
            port_aggregate: port_aggregate.to_string(),
            tag,
        })
}

/// Finds the subinterface, creating it if missing — but requires the parent
/// `PortAggregate` to already exist (unlike `subinterface::ensure_subinterface_mut`,
/// which also cascade-creates the parent `Interface`).
fn ensure_subinterface_mut<'a>(
    config: &'a mut Config,
    port_aggregate: &str,
    tag: u16,
) -> Result<&'a mut Subinterface, OpError> {
    let agg = find_aggregate_mut(config, port_aggregate)?;
    if !agg.subinterfaces.iter().any(|s| s.tag == tag) {
        agg.subinterfaces.push(Subinterface {
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
    Ok(agg.subinterfaces.iter_mut().find(|s| s.tag == tag).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{PortAggregate, PortAggregateMode};

    fn aggregate(name: &str, subinterfaces: Vec<Subinterface>) -> PortAggregate {
        PortAggregate {
            acl_in: None,
            acl_out: None,
            flowspec: false,
            name: name.to_string(),
            mode: PortAggregateMode::Xor,
            lacp_rate: crate::schema::LacpRate::default(),
            esi: None,
            redundancy_mode: crate::schema::EsRedundancy::default(),
            df_algorithm: crate::schema::DfAlgorithm::default(),
            lacp_system_id: None,
            lacp_system_priority: None,
            lacp_version: crate::schema::LacpVersion::default(),
            lacp_port_algorithm: crate::schema::LacpPortAlgorithm::default(),
            lacp_conversation_map: Vec::new(),
            min_links: 1,
            bfd: None,
            bfd_peer: None,
            stp_port_profile: None,
            switching_profile: None,
            mtu: None,
            subinterfaces,
        }
    }

    fn addr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn ensure_creates_subinterface_on_existing_aggregate() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1", vec![])],
            ..Default::default()
        };
        PortAggregateSubinterfaceOp::Ensure {
            port_aggregate: "bond1".to_string(),
            tag: 100,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].subinterfaces.len(), 1);
        assert_eq!(cfg.port_aggregates[0].subinterfaces[0].tag, 100);
    }

    #[test]
    fn ensure_twice_does_not_duplicate_the_subinterface() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1", vec![])],
            ..Default::default()
        };
        for tag in [100, 100, 200] {
            PortAggregateSubinterfaceOp::Ensure {
                port_aggregate: "bond1".to_string(),
                tag,
            }
            .apply(&mut cfg)
            .unwrap();
        }
        let tags: Vec<u16> = cfg.port_aggregates[0]
            .subinterfaces
            .iter()
            .map(|s| s.tag)
            .collect();
        assert_eq!(tags, [100, 200]);
    }

    #[test]
    fn ensure_missing_aggregate_errors() {
        let mut cfg = Config::default();
        let err = PortAggregateSubinterfaceOp::Ensure {
            port_aggregate: "bond1".to_string(),
            tag: 100,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::PortAggregateNotFound(n) if n == "bond1"));
    }

    #[test]
    fn add_address_upserts_label_on_existing_address() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1", vec![])],
            ..Default::default()
        };
        PortAggregateSubinterfaceOp::AddAddress {
            port_aggregate: "bond1".to_string(),
            tag: 0,
            address: addr("10.0.0.1/24"),
            label: Some("a".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        PortAggregateSubinterfaceOp::AddAddress {
            port_aggregate: "bond1".to_string(),
            tag: 0,
            address: addr("10.0.0.1/24"),
            label: Some("b".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        let sub = &cfg.port_aggregates[0].subinterfaces[0];
        assert_eq!(sub.addresses.len(), 1);
        assert_eq!(sub.addresses[0].label.as_deref(), Some("b"));
    }

    #[test]
    fn remove_address_drops_only_that_address_and_missing_errors() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1", vec![])],
            ..Default::default()
        };
        for a in ["10.0.0.1/24", "10.0.1.1/24"] {
            PortAggregateSubinterfaceOp::AddAddress {
                port_aggregate: "bond1".to_string(),
                tag: 5,
                address: addr(a),
                label: None,
            }
            .apply(&mut cfg)
            .unwrap();
        }
        let remove = |cfg: &mut Config, a: &str| {
            PortAggregateSubinterfaceOp::RemoveAddress {
                port_aggregate: "bond1".to_string(),
                tag: 5,
                address: addr(a),
            }
            .apply(cfg)
        };
        remove(&mut cfg, "10.0.0.1/24").unwrap();
        let sub = &cfg.port_aggregates[0].subinterfaces[0];
        assert_eq!(sub.addresses.len(), 1);
        assert_eq!(sub.addresses[0].address, addr("10.0.1.1/24"));
        let err = remove(&mut cfg, "10.0.0.1/24").unwrap_err();
        assert!(matches!(
            err,
            OpError::PortAggregateSubinterfaceAddressNotFound { tag: 5, .. }
        ));
    }

    #[test]
    fn set_and_clear_mtu() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1", Vec::new())],
            ..Default::default()
        };
        PortAggregateSubinterfaceOp::SetMtu {
            port_aggregate: "bond1".to_string(),
            tag: 100,
            mtu: 9000,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].subinterfaces[0].mtu, Some(9000));
        PortAggregateSubinterfaceOp::ClearMtu {
            port_aggregate: "bond1".to_string(),
            tag: 100,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].subinterfaces[0].mtu, None);
    }

    #[test]
    fn set_and_clear_touch_only_the_tagged_subinterface() {
        let sub = |tag| Subinterface {
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
        };
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1", vec![sub(1), sub(2)])],
            ..Default::default()
        };
        let op = |cfg: &mut Config, f: fn(String, u16) -> PortAggregateSubinterfaceOp, tag| {
            f("bond1".to_string(), tag).apply(cfg)
        };
        let subs = |cfg: &Config| cfg.port_aggregates[0].subinterfaces.clone();
        op(
            &mut cfg,
            |p, t| PortAggregateSubinterfaceOp::SetRoutingTable {
                port_aggregate: p,
                tag: t,
                routing_table: "rt".to_string(),
            },
            2,
        )
        .unwrap();
        assert_eq!(subs(&cfg)[0].routing_table, None);
        assert_eq!(subs(&cfg)[1].routing_table.as_deref(), Some("rt"));
        op(
            &mut cfg,
            |p, t| PortAggregateSubinterfaceOp::SetRoutingTable {
                port_aggregate: p,
                tag: t,
                routing_table: "rt1".to_string(),
            },
            1,
        )
        .unwrap();
        // Clearing tag 2 leaves tag 1's value alone and is really stored.
        op(
            &mut cfg,
            |p, t| PortAggregateSubinterfaceOp::ClearRoutingTable {
                port_aggregate: p,
                tag: t,
            },
            2,
        )
        .unwrap();
        assert_eq!(subs(&cfg)[0].routing_table.as_deref(), Some("rt1"));
        assert_eq!(subs(&cfg)[1].routing_table, None);
        let err = op(
            &mut cfg,
            |p, t| PortAggregateSubinterfaceOp::ClearRoutingTable {
                port_aggregate: p,
                tag: t,
            },
            9,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::PortAggregateSubinterfaceNotFound { tag: 9, .. }
        ));
        assert_eq!(subs(&cfg).len(), 2);
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate(
                "bond1",
                vec![Subinterface {
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
                }],
            )],
            ..Default::default()
        };
        PortAggregateSubinterfaceOp::Delete {
            port_aggregate: "bond1".to_string(),
            tag: 100,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].subinterfaces, []);
    }

    #[test]
    fn delete_missing_subinterface_errors() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1", vec![])],
            ..Default::default()
        };
        let err = PortAggregateSubinterfaceOp::Delete {
            port_aggregate: "bond1".to_string(),
            tag: 0,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::PortAggregateSubinterfaceNotFound { port_aggregate, tag }
            if port_aggregate == "bond1" && tag == 0
        ));
    }
}
