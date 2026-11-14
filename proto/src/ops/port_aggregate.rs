use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::schema::{
    Config, DfAlgorithm, EsRedundancy, LacpPortAlgorithm, LacpRate, LacpVersion, PortAggregate,
    PortAggregateMode,
};

use super::OpError;

/// An edit to a single named `PortAggregate` within a transaction's
/// in-progress config. Applied without validation, matching every other
/// `Op`. No address/routing-table/ospf-profile variants — unlike
/// `BroadcastDomainOp`, `PortAggregate` has no flat L3 fields; that config
/// lives under its `subinterfaces` instead, edited via
/// `PortAggregateSubinterfaceOp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortAggregateOp {
    /// Creates the aggregate if it doesn't already exist (with `mode`);
    /// no-op if it does. Backs `edit port-aggregate <name>`'s "create if
    /// missing, else navigate to it" semantics.
    Ensure {
        /// Name of the port aggregate this op targets.
        name: String,
        /// Aggregation mode (static XOR or LACP).
        mode: PortAggregateMode,
    },
    /// Sets the switching profile of the port aggregate to `switching_profile`.
    SetSwitchingProfile {
        /// Name of the port aggregate this op targets.
        name: String,
        /// Name of the switching profile.
        switching_profile: String,
    },
    /// Clears the switching profile of the port aggregate so it reverts to the default.
    ClearSwitchingProfile {
        /// Name of the port aggregate this op targets.
        name: String,
    },
    /// Sets the MTU of the port aggregate to `mtu`.
    SetMtu {
        /// Name of the port aggregate this op targets.
        name: String,
        /// MTU in bytes applied to the bond device.
        mtu: u32,
    },
    /// Clears the MTU of the port aggregate so it reverts to the default.
    ClearMtu {
        /// Name of the port aggregate this op targets.
        name: String,
    },
    /// Sets the mode of the port aggregate to `mode`.
    SetMode {
        /// Name of the port aggregate this op targets.
        name: String,
        /// Aggregation mode (static XOR or LACP).
        mode: PortAggregateMode,
    },
    /// Sets the LACP rate of the port aggregate to `rate`.
    SetLacpRate {
        /// Name of the port aggregate this op targets.
        name: String,
        /// LACPDU rate: fast (1 s) or slow (30 s).
        rate: LacpRate,
    },
    /// Deletes the port aggregate and everything nested under it.
    Delete {
        /// Name of the port aggregate this op targets.
        name: String,
    },
    /// Sets the ESI of the port aggregate to `esi`.
    SetEsi {
        /// Name of the port aggregate this op targets.
        name: String,
        /// Ethernet segment identifier (10 bytes, hex).
        esi: String,
    },
    /// Clears the ESI of the port aggregate so it reverts to the default.
    ClearEsi {
        /// Name of the port aggregate this op targets.
        name: String,
    },
    /// Sets the LACP system ID of the port aggregate to `system_id`.
    SetLacpSystemId {
        /// Name of the port aggregate this op targets.
        name: String,
        /// LACP system ID (MAC address) used in negotiation.
        system_id: String,
    },
    /// Clears the LACP system ID of the port aggregate so it reverts to the default.
    ClearLacpSystemId {
        /// Name of the port aggregate this op targets.
        name: String,
    },
    /// Appended (postcard indexes variants by position).
    SetRedundancyMode {
        /// Name of the port aggregate this op targets.
        name: String,
        /// Aggregation mode (static XOR or LACP).
        mode: EsRedundancy,
    },
    /// Appended (postcard indexes variants by position).
    SetDfAlgorithm {
        /// Name of the port aggregate this op targets.
        name: String,
        /// HMAC/hash algorithm.
        algorithm: DfAlgorithm,
    },
    /// Appended (postcard indexes variants by position).
    SetLacpSystemPriority {
        /// Name of the port aggregate this op targets.
        name: String,
        /// Router priority for DR/BDR election (0 makes the router ineligible).
        priority: u16,
    },
    /// Appended (postcard indexes variants by position).
    ClearLacpSystemPriority {
        /// Name of the port aggregate this op targets.
        name: String,
    },
    /// Appended (postcard indexes variants by position).
    SetMinLinks {
        /// Name of the port aggregate this op targets.
        name: String,
        /// Minimum active members before the aggregate is up.
        min_links: u16,
    },
    /// Appended (postcard indexes variants by position).
    SetBfd {
        /// Name of the port aggregate this op targets.
        name: String,
        /// Name of the profile.
        profile: String,
    },
    /// Appended (postcard indexes variants by position).
    ClearBfd {
        /// Name of the port aggregate this op targets.
        name: String,
    },
    /// Appended (postcard indexes variants by position).
    SetBfdPeer {
        /// Name of the port aggregate this op targets.
        name: String,
        /// Address of the peer.
        peer: IpAddr,
    },
    /// Appended (postcard indexes variants by position).
    ClearBfdPeer {
        /// Name of the port aggregate this op targets.
        name: String,
    },
    /// Appended (postcard indexes variants by position).
    SetLacpVersion {
        /// Name of the port aggregate this op targets.
        name: String,
        /// LACP version to advertise.
        version: LacpVersion,
    },
    /// Appended (postcard indexes variants by position).
    SetLacpPortAlgorithm {
        /// Name of the port aggregate this op targets.
        name: String,
        /// Port algorithm mapping frames to conversations.
        algorithm: LacpPortAlgorithm,
    },
}

impl PortAggregateOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            PortAggregateOp::Ensure { name, mode } => {
                if !config.port_aggregates.iter().any(|a| &a.name == name) {
                    config.port_aggregates.push(PortAggregate {
                        acl_in: None,
                        acl_out: None,
                        flowspec: false,
                        name: name.clone(),
                        mode: *mode,
                        lacp_rate: LacpRate::default(),
                        esi: None,
                        redundancy_mode: EsRedundancy::default(),
                        df_algorithm: DfAlgorithm::default(),
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
                        subinterfaces: Vec::new(),
                    });
                }
                Ok(())
            }
            PortAggregateOp::SetSwitchingProfile {
                name,
                switching_profile,
            } => {
                find_aggregate_mut(config, name)?.switching_profile =
                    Some(switching_profile.clone());
                Ok(())
            }
            PortAggregateOp::ClearSwitchingProfile { name } => {
                find_aggregate_mut(config, name)?.switching_profile = None;
                Ok(())
            }
            PortAggregateOp::SetMtu { name, mtu } => {
                find_aggregate_mut(config, name)?.mtu = Some(*mtu);
                Ok(())
            }
            PortAggregateOp::ClearMtu { name } => {
                find_aggregate_mut(config, name)?.mtu = None;
                Ok(())
            }
            PortAggregateOp::SetMode { name, mode } => {
                find_aggregate_mut(config, name)?.mode = *mode;
                Ok(())
            }
            PortAggregateOp::SetLacpRate { name, rate } => {
                find_aggregate_mut(config, name)?.lacp_rate = *rate;
                Ok(())
            }
            PortAggregateOp::SetEsi { name, esi } => {
                find_aggregate_mut(config, name)?.esi = Some(esi.clone());
                Ok(())
            }
            PortAggregateOp::ClearEsi { name } => {
                find_aggregate_mut(config, name)?.esi = None;
                Ok(())
            }
            PortAggregateOp::SetLacpSystemId { name, system_id } => {
                find_aggregate_mut(config, name)?.lacp_system_id = Some(system_id.clone());
                Ok(())
            }
            PortAggregateOp::ClearLacpSystemId { name } => {
                find_aggregate_mut(config, name)?.lacp_system_id = None;
                Ok(())
            }
            PortAggregateOp::SetLacpSystemPriority { name, priority } => {
                find_aggregate_mut(config, name)?.lacp_system_priority = Some(*priority);
                Ok(())
            }
            PortAggregateOp::ClearLacpSystemPriority { name } => {
                find_aggregate_mut(config, name)?.lacp_system_priority = None;
                Ok(())
            }
            PortAggregateOp::SetMinLinks { name, min_links } => {
                find_aggregate_mut(config, name)?.min_links = *min_links;
                Ok(())
            }
            PortAggregateOp::SetBfd { name, profile } => {
                find_aggregate_mut(config, name)?.bfd = Some(profile.clone());
                Ok(())
            }
            PortAggregateOp::ClearBfd { name } => {
                find_aggregate_mut(config, name)?.bfd = None;
                Ok(())
            }
            PortAggregateOp::SetBfdPeer { name, peer } => {
                find_aggregate_mut(config, name)?.bfd_peer = Some(*peer);
                Ok(())
            }
            PortAggregateOp::ClearBfdPeer { name } => {
                find_aggregate_mut(config, name)?.bfd_peer = None;
                Ok(())
            }
            PortAggregateOp::SetRedundancyMode { name, mode } => {
                find_aggregate_mut(config, name)?.redundancy_mode = *mode;
                Ok(())
            }
            PortAggregateOp::SetDfAlgorithm { name, algorithm } => {
                find_aggregate_mut(config, name)?.df_algorithm = *algorithm;
                Ok(())
            }
            PortAggregateOp::SetLacpVersion { name, version } => {
                find_aggregate_mut(config, name)?.lacp_version = *version;
                Ok(())
            }
            PortAggregateOp::SetLacpPortAlgorithm { name, algorithm } => {
                find_aggregate_mut(config, name)?.lacp_port_algorithm = *algorithm;
                Ok(())
            }
            PortAggregateOp::Delete { name } => {
                let before = config.port_aggregates.len();
                config.port_aggregates.retain(|a| &a.name != name);
                if config.port_aggregates.len() == before {
                    return Err(OpError::PortAggregateNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

fn find_aggregate_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut PortAggregate, OpError> {
    config
        .port_aggregates
        .iter_mut()
        .find(|a| a.name == name)
        .ok_or_else(|| OpError::PortAggregateNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aggregate(name: &str) -> PortAggregate {
        PortAggregate {
            acl_in: None,
            acl_out: None,
            flowspec: false,
            name: name.to_string(),
            mode: PortAggregateMode::Xor,
            lacp_rate: LacpRate::default(),
            esi: None,
            redundancy_mode: EsRedundancy::default(),
            df_algorithm: DfAlgorithm::default(),
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
            subinterfaces: Vec::new(),
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config::default();
        PortAggregateOp::Ensure {
            name: "bond1".to_string(),
            mode: PortAggregateMode::Xor,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates.len(), 1);
        assert_eq!(cfg.port_aggregates[0].name, "bond1");
        assert_eq!(cfg.port_aggregates[0].mode, PortAggregateMode::Xor);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1")],
            ..Default::default()
        };
        PortAggregateOp::Ensure {
            name: "bond1".to_string(),
            mode: PortAggregateMode::Xor,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates.len(), 1);
    }

    #[test]
    fn set_and_clear_switching_profile() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1")],
            ..Default::default()
        };
        PortAggregateOp::SetSwitchingProfile {
            name: "bond1".to_string(),
            switching_profile: "sp1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.port_aggregates[0].switching_profile.as_deref(),
            Some("sp1")
        );

        PortAggregateOp::ClearSwitchingProfile {
            name: "bond1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].switching_profile, None);
    }

    #[test]
    fn set_and_clear_mode() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1")],
            ..Default::default()
        };
        PortAggregateOp::SetMode {
            name: "bond1".to_string(),
            mode: PortAggregateMode::Xor,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].mode, PortAggregateMode::Xor);
    }

    #[test]
    fn set_lacp_rate() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1")],
            ..Default::default()
        };
        assert_eq!(cfg.port_aggregates[0].lacp_rate, LacpRate::Slow);
        PortAggregateOp::SetLacpRate {
            name: "bond1".to_string(),
            rate: LacpRate::Fast,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].lacp_rate, LacpRate::Fast);
    }

    #[test]
    fn set_redundancy_mode() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1")],
            ..Default::default()
        };
        assert_eq!(
            cfg.port_aggregates[0].redundancy_mode,
            EsRedundancy::AllActive
        );
        PortAggregateOp::SetRedundancyMode {
            name: "bond1".to_string(),
            mode: EsRedundancy::SingleActive,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.port_aggregates[0].redundancy_mode,
            EsRedundancy::SingleActive
        );
    }

    #[test]
    fn set_min_links() {
        let mut cfg = Config::default();
        let name = "bond1".to_string();
        PortAggregateOp::Ensure {
            name: name.clone(),
            mode: PortAggregateMode::Lacp,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].min_links, 1);
        PortAggregateOp::SetMinLinks { name, min_links: 2 }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.port_aggregates[0].min_links, 2);
    }

    #[test]
    fn set_and_clear_lacp_system_priority() {
        let mut cfg = Config::default();
        let name = "bond1".to_string();
        PortAggregateOp::Ensure {
            name: name.clone(),
            mode: PortAggregateMode::Lacp,
        }
        .apply(&mut cfg)
        .unwrap();
        PortAggregateOp::SetLacpSystemPriority {
            name: name.clone(),
            priority: 100,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].lacp_system_priority, Some(100));
        PortAggregateOp::ClearLacpSystemPriority { name }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.port_aggregates[0].lacp_system_priority, None);
    }

    #[test]
    fn set_and_clear_esi_and_lacp_system_id() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1")],
            ..Default::default()
        };
        let name = "bond1".to_string();
        PortAggregateOp::SetEsi {
            name: name.clone(),
            esi: "00:11:22:33:44:55:66:77:88:99".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        PortAggregateOp::SetLacpSystemId {
            name: name.clone(),
            system_id: "02:00:00:00:00:01".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.port_aggregates[0].esi.is_some());
        assert!(cfg.port_aggregates[0].lacp_system_id.is_some());
        PortAggregateOp::ClearEsi { name: name.clone() }
            .apply(&mut cfg)
            .unwrap();
        PortAggregateOp::ClearLacpSystemId { name }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.port_aggregates[0].esi, None);
        assert_eq!(cfg.port_aggregates[0].lacp_system_id, None);
    }

    #[test]
    fn set_and_clear_mtu() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1")],
            ..Default::default()
        };
        PortAggregateOp::SetMtu {
            name: "bond1".to_string(),
            mtu: 9000,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].mtu, Some(9000));

        PortAggregateOp::ClearMtu {
            name: "bond1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].mtu, None);
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            port_aggregates: vec![aggregate("bond1"), aggregate("bond2")],
            ..Default::default()
        };
        PortAggregateOp::Delete {
            name: "bond1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates.len(), 1);
        assert_eq!(cfg.port_aggregates[0].name, "bond2");
    }

    #[test]
    fn delete_missing_errors() {
        let mut cfg = Config::default();
        let err = PortAggregateOp::Delete {
            name: "bond1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::PortAggregateNotFound(n) if n == "bond1"));
    }

    #[test]
    fn set_lacp_version_and_algorithm() {
        let mut cfg = Config::default();
        let name = "bond1".to_string();
        PortAggregateOp::Ensure {
            name: name.clone(),
            mode: PortAggregateMode::Lacp,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].lacp_version, LacpVersion::V2);
        PortAggregateOp::SetLacpVersion {
            name: name.clone(),
            version: LacpVersion::V1,
        }
        .apply(&mut cfg)
        .unwrap();
        PortAggregateOp::SetLacpPortAlgorithm {
            name,
            algorithm: LacpPortAlgorithm::SVlan,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.port_aggregates[0].lacp_version, LacpVersion::V1);
        assert_eq!(
            cfg.port_aggregates[0].lacp_port_algorithm,
            LacpPortAlgorithm::SVlan
        );
    }

    #[test]
    fn new_ops_roundtrip_through_postcard() {
        let op = PortAggregateOp::SetLacpPortAlgorithm {
            name: "b".into(),
            algorithm: LacpPortAlgorithm::CVlan,
        };
        let bytes = postcard::to_allocvec(&op).unwrap();
        assert_eq!(postcard::from_bytes::<PortAggregateOp>(&bytes).unwrap(), op);
    }
}
