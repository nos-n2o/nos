use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::schema::{
    Config, Redistribute, RedistributeTarget, RestApi, RoutingTable, RoutingTableEvpn, SshServer,
};

use super::OpError;

/// An edit to a single named `RoutingTable` within a transaction's
/// in-progress config. Applied without validation — `garde` validation only
/// runs at commit time, matching every other `Op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingTableOp {
    /// Creates the table if it doesn't already exist; no-op if it does.
    /// Backs `edit routing-table <name>`'s "create if missing, else
    /// navigate to it" semantics.
    Ensure {
        /// Name of the routing table this op targets.
        name: String,
    },
    /// Sets the BGP instance of the routing table to `bgp_instance`.
    SetBgpInstance {
        /// Name of the routing table this op targets.
        name: String,
        /// Name of the BGP instance to bind.
        bgp_instance: String,
    },
    /// Clears the BGP instance of the routing table so it reverts to the default.
    ClearBgpInstance {
        /// Name of the routing table this op targets.
        name: String,
    },
    /// Sets the static routing instance of the routing table to `static_routing_instance`.
    SetStaticRoutingInstance {
        /// Name of the routing table this op targets.
        name: String,
        /// Name of the static routing instance to bind.
        static_routing_instance: String,
    },
    /// Clears the static routing instance of the routing table so it reverts to the default.
    ClearStaticRoutingInstance {
        /// Name of the routing table this op targets.
        name: String,
    },
    /// Sets the redistribute of the routing table to `redistribute`.
    SetRedistribute {
        /// Name of the routing table this op targets.
        name: String,
        /// Which protocols are redistributed into the table.
        redistribute: Redistribute,
    },
    /// Removes the rule for exactly `(to, instance)`.
    ClearRedistribute {
        /// Name of the routing table this op targets.
        name: String,
        /// Destination protocol of the redistribution.
        to: RedistributeTarget,
        /// The `OSPFv3` instance the rule names (`None` = the unset rule).
        instance: Option<String>,
    },
    /// Deletes the routing table and everything nested under it.
    Delete {
        /// Name of the routing table this op targets.
        name: String,
    },
    /// Sets the OSPF instance of the routing table to `ospf_instance`.
    SetOspfInstance {
        /// Name of the routing table this op targets.
        name: String,
        /// Name of the OSPF instance to bind.
        ospf_instance: String,
    },
    /// Clears the OSPF instance of the routing table so it reverts to the default.
    ClearOspfInstance {
        /// Name of the routing table this op targets.
        name: String,
    },
    /// Idempotently makes the table claim one more `OSPFv3` instance.
    AddOspfv3Instance {
        /// Name of the routing table this op targets.
        name: String,
        /// Name of the `OSPFv3` instance to claim.
        ospfv3_instance: String,
    },
    /// Releases one `OSPFv3` instance (error when not claimed) and drops the
    /// redistribute rules naming it.
    RemoveOspfv3Instance {
        /// Name of the routing table this op targets.
        name: String,
        /// Name of the `OSPFv3` instance to release.
        ospfv3_instance: String,
    },
    /// Pins `nos-restd` to this table, listening on `address:port` in its VRF.
    SetRestApi {
        /// Name of the routing table this op targets.
        name: String,
        /// IP address of the entry.
        address: IpAddr,
        /// Port number or member port, per the op.
        port: u16,
    },
    /// Clears the REST API of the routing table so it reverts to the default.
    ClearRestApi {
        /// Name of the routing table this op targets.
        name: String,
    },
    /// Pins `nos-sshd` to this table, listening on `address:port` in its VRF.
    SetSshServer {
        /// Name of the routing table this op targets.
        name: String,
        /// IP address of the entry.
        address: IpAddr,
        /// Port number or member port, per the op.
        port: u16,
    },
    /// Clears the SSH server of the routing table so it reverts to the default.
    ClearSshServer {
        /// Name of the routing table this op targets.
        name: String,
    },
    /// Sets (replaces) the table's whole EVPN L3 VNI config.
    SetEvpn {
        /// Name of the routing table this op targets.
        name: String,
        /// EVPN settings of the table.
        evpn: RoutingTableEvpn,
    },
    /// Clears the EVPN of the routing table so it reverts to the default.
    ClearEvpn {
        /// Name of the routing table this op targets.
        name: String,
    },
    /// Sets (replaces) the table's whole L3VPN config.
    SetVpn {
        /// Name of the routing table this op targets.
        name: String,
        /// VPN settings of the table.
        vpn: crate::schema::RoutingTableVpn,
    },
    /// Clears the VPN of the routing table so it reverts to the default.
    ClearVpn {
        /// Name of the routing table this op targets.
        name: String,
    },
}

impl RoutingTableOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            RoutingTableOp::Ensure { name } => {
                if !config.routing_tables.iter().any(|t| &t.name == name) {
                    config.routing_tables.push(RoutingTable {
                        rest_api: None,
                        ssh_server: None,
                        evpn: crate::schema::RoutingTableEvpn::default(),
                        vpn: crate::schema::RoutingTableVpn::default(),
                        name: name.clone(),
                        bgp_instance: None,
                        ospf_instance: None,
                        ospfv3_instances: Vec::new(),
                        static_routing_instance: None,
                        redistribute: Vec::new(),
                    });
                }
                Ok(())
            }
            RoutingTableOp::SetBgpInstance { name, bgp_instance } => {
                find_table_mut(config, name)?.bgp_instance = Some(bgp_instance.clone());
                Ok(())
            }
            RoutingTableOp::ClearBgpInstance { name } => {
                find_table_mut(config, name)?.bgp_instance = None;
                Ok(())
            }
            RoutingTableOp::SetStaticRoutingInstance {
                name,
                static_routing_instance,
            } => {
                find_table_mut(config, name)?.static_routing_instance =
                    Some(static_routing_instance.clone());
                Ok(())
            }
            RoutingTableOp::ClearStaticRoutingInstance { name } => {
                find_table_mut(config, name)?.static_routing_instance = None;
                Ok(())
            }
            RoutingTableOp::SetRedistribute { name, redistribute } => {
                let rules = &mut find_table_mut(config, name)?.redistribute;
                match rules
                    .iter_mut()
                    .find(|r| r.to == redistribute.to && r.instance == redistribute.instance)
                {
                    Some(r) => *r = redistribute.clone(),
                    None => rules.push(redistribute.clone()),
                }
                Ok(())
            }
            RoutingTableOp::ClearRedistribute { name, to, instance } => {
                find_table_mut(config, name)?
                    .redistribute
                    .retain(|r| !(r.to == *to && r.instance == *instance));
                Ok(())
            }
            RoutingTableOp::Delete { name } => {
                let before = config.routing_tables.len();
                config.routing_tables.retain(|t| &t.name != name);
                if config.routing_tables.len() == before {
                    return Err(OpError::RoutingTableNotFound(name.clone()));
                }
                Ok(())
            }
            RoutingTableOp::SetOspfInstance {
                name,
                ospf_instance,
            } => {
                find_table_mut(config, name)?.ospf_instance = Some(ospf_instance.clone());
                Ok(())
            }
            RoutingTableOp::ClearOspfInstance { name } => {
                find_table_mut(config, name)?.ospf_instance = None;
                Ok(())
            }
            RoutingTableOp::AddOspfv3Instance {
                name,
                ospfv3_instance,
            } => {
                let list = &mut find_table_mut(config, name)?.ospfv3_instances;
                if !list.contains(ospfv3_instance) {
                    list.push(ospfv3_instance.clone());
                }
                Ok(())
            }
            RoutingTableOp::RemoveOspfv3Instance {
                name,
                ospfv3_instance,
            } => {
                let table = find_table_mut(config, name)?;
                let before = table.ospfv3_instances.len();
                table.ospfv3_instances.retain(|i| i != ospfv3_instance);
                if table.ospfv3_instances.len() == before {
                    return Err(OpError::Ospfv3InstanceNotClaimed(ospfv3_instance.clone()));
                }
                table
                    .redistribute
                    .retain(|r| r.instance.as_ref() != Some(ospfv3_instance));
                Ok(())
            }
            RoutingTableOp::SetRestApi {
                name,
                address,
                port,
            } => {
                find_table_mut(config, name)?.rest_api = Some(RestApi {
                    address: *address,
                    port: *port,
                });
                Ok(())
            }
            RoutingTableOp::ClearRestApi { name } => {
                find_table_mut(config, name)?.rest_api = None;
                Ok(())
            }
            RoutingTableOp::SetSshServer {
                name,
                address,
                port,
            } => {
                find_table_mut(config, name)?.ssh_server = Some(SshServer {
                    address: *address,
                    port: *port,
                });
                Ok(())
            }
            RoutingTableOp::ClearSshServer { name } => {
                find_table_mut(config, name)?.ssh_server = None;
                Ok(())
            }
            RoutingTableOp::SetEvpn { name, evpn } => {
                find_table_mut(config, name)?.evpn = evpn.clone();
                Ok(())
            }
            RoutingTableOp::ClearEvpn { name } => {
                find_table_mut(config, name)?.evpn = RoutingTableEvpn::default();
                Ok(())
            }
            RoutingTableOp::SetVpn { name, vpn } => {
                find_table_mut(config, name)?.vpn = vpn.clone();
                Ok(())
            }
            RoutingTableOp::ClearVpn { name } => {
                find_table_mut(config, name)?.vpn = crate::schema::RoutingTableVpn::default();
                Ok(())
            }
        }
    }
}

pub(crate) fn find_table_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut RoutingTable, OpError> {
    config
        .routing_tables
        .iter_mut()
        .find(|t| t.name == name)
        .ok_or_else(|| OpError::RoutingTableNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(name: &str) -> RoutingTable {
        RoutingTable {
            rest_api: None,
            ssh_server: None,
            evpn: crate::schema::RoutingTableEvpn::default(),
            vpn: crate::schema::RoutingTableVpn::default(),
            ospfv3_instances: Vec::new(),
            name: name.to_string(),
            bgp_instance: None,
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: Vec::new(),
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        RoutingTableOp::Ensure {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables.len(), 1);
        assert_eq!(cfg.routing_tables[0].name, "rt1");
        assert_eq!(cfg.routing_tables[0].bgp_instance, None);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            routing_tables: vec![RoutingTable {
                rest_api: None,
                ssh_server: None,
                evpn: crate::schema::RoutingTableEvpn::default(),
                vpn: crate::schema::RoutingTableVpn::default(),
                ospfv3_instances: Vec::new(),
                name: "rt1".to_string(),
                bgp_instance: Some("r1".to_string()),
                ospf_instance: None,
                static_routing_instance: None,
                redistribute: Vec::new(),
            }],
            ..Default::default()
        };
        RoutingTableOp::Ensure {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables.len(), 1);
        assert_eq!(cfg.routing_tables[0].bgp_instance.as_deref(), Some("r1"));
    }

    #[test]
    fn set_and_clear_bgp_instance() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetBgpInstance {
            name: "rt1".to_string(),
            bgp_instance: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].bgp_instance.as_deref(), Some("r1"));

        RoutingTableOp::ClearBgpInstance {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].bgp_instance, None);
    }

    #[test]
    fn set_and_clear_static_routing_instance() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetStaticRoutingInstance {
            name: "rt1".to_string(),
            static_routing_instance: "sri1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.routing_tables[0].static_routing_instance.as_deref(),
            Some("sri1")
        );

        RoutingTableOp::ClearStaticRoutingInstance {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].static_routing_instance, None);
    }

    #[test]
    fn set_and_clear_ospf_instance() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetOspfInstance {
            name: "rt1".to_string(),
            ospf_instance: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].ospf_instance.as_deref(), Some("o1"));

        RoutingTableOp::ClearOspfInstance {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].ospf_instance, None);
    }

    #[test]
    fn set_and_clear_rest_api() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetRestApi {
            name: "rt1".to_string(),
            address: "10.0.0.1".parse().unwrap(),
            port: 8080,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.routing_tables[0].rest_api,
            Some(RestApi {
                address: "10.0.0.1".parse().unwrap(),
                port: 8080
            })
        );

        RoutingTableOp::ClearRestApi {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].rest_api, None);
    }

    #[test]
    fn set_and_clear_ssh_server() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetSshServer {
            name: "rt1".to_string(),
            address: "10.0.0.1".parse().unwrap(),
            port: 22,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.routing_tables[0].ssh_server,
            Some(SshServer {
                address: "10.0.0.1".parse().unwrap(),
                port: 22
            })
        );
        RoutingTableOp::ClearSshServer {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].ssh_server, None);
    }

    #[test]
    fn set_and_clear_vpn() {
        let mut cfg = Config::default();
        RoutingTableOp::Ensure { name: "red".into() }
            .apply(&mut cfg)
            .unwrap();
        let vpn = crate::schema::RoutingTableVpn {
            rd: Some("65000:1".into()),
            label: Some(100),
            ..Default::default()
        };
        let set = RoutingTableOp::SetVpn {
            name: "red".into(),
            vpn: vpn.clone(),
        };
        set.apply(&mut cfg).unwrap();
        assert_eq!(cfg.routing_tables[0].vpn, vpn);
        RoutingTableOp::ClearVpn { name: "red".into() }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(
            cfg.routing_tables[0].vpn,
            crate::schema::RoutingTableVpn::default()
        );
        assert!(RoutingTableOp::ClearVpn {
            name: "nope".into()
        }
        .apply(&mut cfg)
        .is_err());
    }

    #[test]
    fn set_and_clear_evpn() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        let evpn = RoutingTableEvpn {
            l3_vni: Some(5000),
            ..Default::default()
        };
        RoutingTableOp::SetEvpn {
            name: "rt1".to_string(),
            evpn: evpn.clone(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].evpn, evpn);
        RoutingTableOp::ClearEvpn {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].evpn, RoutingTableEvpn::default());
    }

    #[test]
    fn set_and_clear_redistribute() {
        use crate::schema::{RedistributeSource, RedistributeTarget};

        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetRedistribute {
            name: "rt1".to_string(),
            redistribute: Redistribute {
                instance: None,
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
                metric: None,
                metric_type: None,
            },
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.routing_tables[0].redistribute,
            vec![Redistribute {
                instance: None,
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: None,
                metric: None,
                metric_type: None,
            }]
        );

        // A second target is added beside it; re-setting one replaces only it.
        for (to, policy) in [
            (RedistributeTarget::Ospf, None),
            (RedistributeTarget::Bgp, Some("p".to_string())),
        ] {
            RoutingTableOp::SetRedistribute {
                name: "rt1".to_string(),
                redistribute: Redistribute {
                    instance: None,
                    from: RedistributeSource::Static,
                    to,
                    policy,
                    metric: None,
                    metric_type: None,
                },
            }
            .apply(&mut cfg)
            .unwrap();
        }
        let rules = &cfg.routing_tables[0].redistribute;
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].policy.as_deref(), Some("p"));
        assert_eq!(rules[1].to, RedistributeTarget::Ospf);

        RoutingTableOp::ClearRedistribute {
            instance: None,
            name: "rt1".to_string(),
            to: RedistributeTarget::Bgp,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].redistribute.len(), 1);
        assert_eq!(
            cfg.routing_tables[0].redistribute[0].to,
            RedistributeTarget::Ospf
        );
    }

    #[test]
    fn add_remove_ospfv3_instance_and_cascade() {
        use crate::schema::{Redistribute, RedistributeTarget};
        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        let add = |i: &str| RoutingTableOp::AddOspfv3Instance {
            name: "rt1".to_string(),
            ospfv3_instance: i.to_string(),
        };
        add("o1").apply(&mut cfg).unwrap();
        add("o1").apply(&mut cfg).unwrap();
        add("o2").apply(&mut cfg).unwrap();
        assert_eq!(cfg.routing_tables[0].ospfv3_instances, ["o1", "o2"]);
        let rule = |instance: Option<&str>| RoutingTableOp::SetRedistribute {
            name: "rt1".to_string(),
            redistribute: Redistribute {
                to: RedistributeTarget::Ospfv3,
                instance: instance.map(str::to_string),
                ..Default::default()
            },
        };
        for i in [None, Some("o1"), Some("o2")] {
            rule(i).apply(&mut cfg).unwrap();
        }
        assert_eq!(cfg.routing_tables[0].redistribute.len(), 3);
        RoutingTableOp::ClearRedistribute {
            name: "rt1".to_string(),
            to: RedistributeTarget::Ospfv3,
            instance: Some("o2".to_string()),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].redistribute.len(), 2);
        // Releasing o1 drops the rule naming it, keeps the unset one.
        RoutingTableOp::RemoveOspfv3Instance {
            name: "rt1".to_string(),
            ospfv3_instance: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables[0].ospfv3_instances, ["o2"]);
        assert_eq!(cfg.routing_tables[0].redistribute.len(), 1);
        assert_eq!(cfg.routing_tables[0].redistribute[0].instance, None);
        let err = RoutingTableOp::RemoveOspfv3Instance {
            name: "rt1".to_string(),
            ospfv3_instance: "o1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::Ospfv3InstanceNotClaimed(n) if n == "o1"));
    }

    #[test]
    fn set_redistribute_with_policy() {
        use crate::schema::{RedistributeSource, RedistributeTarget};

        let mut cfg = Config {
            routing_tables: vec![table("rt1")],
            ..Default::default()
        };
        RoutingTableOp::SetRedistribute {
            name: "rt1".to_string(),
            redistribute: Redistribute {
                instance: None,
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: Some("p1".to_string()),
                metric: None,
                metric_type: None,
            },
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.routing_tables[0]
                .redistribute
                .first()
                .and_then(|r| r.policy.as_deref()),
            Some("p1")
        );
    }

    #[test]
    fn set_bgp_instance_missing_table_errors() {
        let mut cfg = Config::default();
        let err = RoutingTableOp::SetBgpInstance {
            name: "rt1".to_string(),
            bgp_instance: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::RoutingTableNotFound(n) if n == "rt1"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            routing_tables: vec![table("rt1"), table("rt2")],
            ..Default::default()
        };
        RoutingTableOp::Delete {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.routing_tables.len(), 1);
        assert_eq!(cfg.routing_tables[0].name, "rt2");
    }

    #[test]
    fn delete_missing_table_errors() {
        let mut cfg = Config::default();
        let err = RoutingTableOp::Delete {
            name: "rt1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::RoutingTableNotFound(n) if n == "rt1"));
    }
}
