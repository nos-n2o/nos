use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::schema::{Config, NetworkType, OspfCryptoKey, Ospfv3Profile};

use super::ospfv3_area::find_area_mut;
use super::OpError;

/// An edit to a single `Ospfv3Profile` (keyed by `name`, globally unique)
/// nested under a named `Ospfv3Area` of a named `Ospfv3Instance` — mirrors
/// `OspfProfileOp` exactly, minus `SetSimpleAuth` (RFC 7166 has no
/// simple-password mechanism — see `Ospfv3Profile`'s doc comment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ospfv3ProfileOp {
    /// Creates the `OSPFv3` profile if it does not exist (idempotent).
    Ensure {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
    },
    /// Deletes the `OSPFv3` profile and everything nested under it.
    Delete {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
    },
    /// Sets the hello interval of the `OSPFv3` profile to `hello_interval`.
    SetHelloInterval {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// Hello interval in seconds (RFC 2328 §9.5).
        hello_interval: u16,
    },
    /// Clears the hello interval of the `OSPFv3` profile so it reverts to the default.
    ClearHelloInterval {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
    },
    /// Sets the dead interval of the `OSPFv3` profile to `dead_interval`.
    SetDeadInterval {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// Router dead interval in seconds (RFC 2328 §9.5).
        dead_interval: u16,
    },
    /// Clears the dead interval of the `OSPFv3` profile so it reverts to the default.
    ClearDeadInterval {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
    },
    /// Sets the cost of the `OSPFv3` profile to `cost`.
    SetCost {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// Interface output cost (RFC 5340).
        cost: u16,
    },
    /// Clears the cost of the `OSPFv3` profile so it reverts to the default.
    ClearCost {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
    },
    /// Sets the priority of the `OSPFv3` profile to `priority`.
    SetPriority {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// Router priority for DR/BDR election (0 makes the router ineligible).
        priority: u8,
    },
    /// Clears the priority of the `OSPFv3` profile so it reverts to the default.
    ClearPriority {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
    },
    /// Sets the MTU of the `OSPFv3` profile to `mtu`.
    SetMtu {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// MTU advertised in database descriptions (RFC 5340).
        mtu: u16,
    },
    /// Toggles the RFC 2328 §10.6 DBD Interface MTU check.
    SetMtuIgnore {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// `true` turns the feature on, `false` turns it off.
        enabled: bool,
    },
    /// Clears the MTU of the `OSPFv3` profile so it reverts to the default.
    ClearMtu {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
    },
    /// Sets the network type of the `OSPFv3` profile to `network_type`.
    SetNetworkType {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// OSPF network type (point-to-point, broadcast, ...).
        network_type: NetworkType,
    },
    /// Clears the network type of the `OSPFv3` profile so it reverts to the default.
    ClearNetworkType {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
    },
    /// Upserts one RFC 7166 key by `key_id`, starting the list if `auth`
    /// was unset — mirrors `OspfProfileOp::SetCryptoKey`.
    SetCryptoKey {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// The authentication key entry.
        key: OspfCryptoKey,
    },
    /// Removes one key by `key_id`; no-op if absent, never clears `auth`
    /// back to `None` (an empty list is rejected at commit — use `ClearAuth`).
    RemoveCryptoKey {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// Key ID selecting the SA key (RFC 7166).
        key_id: u16,
    },
    /// Marks one existing key current, clearing the flag on every other.
    SetCryptoCurrentKey {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// Key ID selecting the SA key (RFC 7166).
        key_id: u16,
    },
    /// Clears the auth of the `OSPFv3` profile so it reverts to the default.
    ClearAuth {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
    },
    /// Sets (`Some`) or clears (`None`, meaning 0) the RFC 5340 Instance ID.
    SetInstanceId {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the `OSPFv3` profile this op targets.
        name: String,
        /// Instance ID (RFC 5838 multi-instance).
        instance_id: Option<u8>,
    },
}

impl Ospfv3ProfileOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            Ospfv3ProfileOp::Ensure { .. }
            | Ospfv3ProfileOp::Delete { .. }
            | Ospfv3ProfileOp::SetHelloInterval { .. }
            | Ospfv3ProfileOp::ClearHelloInterval { .. }
            | Ospfv3ProfileOp::SetDeadInterval { .. }
            | Ospfv3ProfileOp::ClearDeadInterval { .. }
            | Ospfv3ProfileOp::SetCost { .. }
            | Ospfv3ProfileOp::ClearCost { .. }
            | Ospfv3ProfileOp::SetPriority { .. }
            | Ospfv3ProfileOp::ClearPriority { .. }
            | Ospfv3ProfileOp::SetMtu { .. } => self.apply_part1(config),
            Ospfv3ProfileOp::SetMtuIgnore { .. }
            | Ospfv3ProfileOp::ClearMtu { .. }
            | Ospfv3ProfileOp::SetNetworkType { .. }
            | Ospfv3ProfileOp::ClearNetworkType { .. }
            | Ospfv3ProfileOp::SetCryptoKey { .. }
            | Ospfv3ProfileOp::RemoveCryptoKey { .. }
            | Ospfv3ProfileOp::SetCryptoCurrentKey { .. }
            | Ospfv3ProfileOp::ClearAuth { .. }
            | Ospfv3ProfileOp::SetInstanceId { .. } => self.apply_part2(config),
        }
    }

    /// Arms of `apply`, split out for length (#425); `apply` names every variant, so a
    /// new one still fails to compile until it is routed to a part.
    fn apply_part1(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            Ospfv3ProfileOp::Ensure {
                instance,
                area_id,
                name,
            } => {
                let area = find_area_mut(config, instance, *area_id)?;
                if !area.profiles.iter().any(|p| &p.name == name) {
                    area.profiles.push(Ospfv3Profile {
                        bfd: None,
                        name: name.clone(),
                        hello_interval: None,
                        dead_interval: None,
                        cost: None,
                        priority: None,
                        mtu: None,
                        mtu_ignore: false,
                        network_type: None,
                        auth: None,
                        instance_id: None,
                    });
                }
                Ok(())
            }
            Ospfv3ProfileOp::Delete {
                instance,
                area_id,
                name,
            } => {
                let area = find_area_mut(config, instance, *area_id)?;
                let before = area.profiles.len();
                area.profiles.retain(|p| &p.name != name);
                if area.profiles.len() == before {
                    return Err(OpError::Ospfv3ProfileNotFound {
                        instance: instance.clone(),
                        area_id: *area_id,
                        name: name.clone(),
                    });
                }
                Ok(())
            }
            Ospfv3ProfileOp::SetHelloInterval {
                instance,
                area_id,
                name,
                hello_interval,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.hello_interval =
                    Some(*hello_interval);
                Ok(())
            }
            Ospfv3ProfileOp::ClearHelloInterval {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.hello_interval = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetDeadInterval {
                instance,
                area_id,
                name,
                dead_interval,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.dead_interval =
                    Some(*dead_interval);
                Ok(())
            }
            Ospfv3ProfileOp::ClearDeadInterval {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.dead_interval = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetCost {
                instance,
                area_id,
                name,
                cost,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.cost = Some(*cost);
                Ok(())
            }
            Ospfv3ProfileOp::ClearCost {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.cost = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetPriority {
                instance,
                area_id,
                name,
                priority,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.priority = Some(*priority);
                Ok(())
            }
            Ospfv3ProfileOp::ClearPriority {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.priority = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetMtu {
                instance,
                area_id,
                name,
                mtu,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.mtu = Some(*mtu);
                Ok(())
            }
            _ => unreachable!("routed by `apply`"),
        }
    }

    /// Arms of `apply`, split out for length (#425); `apply` names every variant, so a
    /// new one still fails to compile until it is routed to a part.
    fn apply_part2(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            Ospfv3ProfileOp::SetMtuIgnore {
                instance,
                area_id,
                name,
                enabled,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.mtu_ignore = *enabled;
                Ok(())
            }
            Ospfv3ProfileOp::ClearMtu {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.mtu = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetNetworkType {
                instance,
                area_id,
                name,
                network_type,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.network_type =
                    Some(*network_type);
                Ok(())
            }
            Ospfv3ProfileOp::ClearNetworkType {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.network_type = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetCryptoKey {
                instance,
                area_id,
                name,
                key,
            } => {
                let keys = find_profile_mut(config, instance, *area_id, name)?
                    .auth
                    .get_or_insert_with(Vec::new);
                match keys.iter_mut().find(|k| k.key_id == key.key_id) {
                    Some(existing) => *existing = key.clone(),
                    None => keys.push(key.clone()),
                }
                Ok(())
            }
            Ospfv3ProfileOp::RemoveCryptoKey {
                instance,
                area_id,
                name,
                key_id,
            } => {
                if let Some(keys) = &mut find_profile_mut(config, instance, *area_id, name)?.auth {
                    keys.retain(|k| k.key_id != *key_id);
                }
                Ok(())
            }
            Ospfv3ProfileOp::SetCryptoCurrentKey {
                instance,
                area_id,
                name,
                key_id,
            } => {
                let not_found = || OpError::Ospfv3CryptoKeyNotFound {
                    instance: instance.clone(),
                    area_id: *area_id,
                    name: name.clone(),
                    key_id: *key_id,
                };
                let keys = find_profile_mut(config, instance, *area_id, name)?
                    .auth
                    .as_mut()
                    .ok_or_else(not_found)?;
                if !keys.iter().any(|k| k.key_id == *key_id) {
                    return Err(not_found());
                }
                for key in keys.iter_mut() {
                    key.is_current = key.key_id == *key_id;
                }
                Ok(())
            }
            Ospfv3ProfileOp::ClearAuth {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.auth = None;
                Ok(())
            }
            Ospfv3ProfileOp::SetInstanceId {
                instance,
                area_id,
                name,
                instance_id,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.instance_id = *instance_id;
                Ok(())
            }
            _ => unreachable!("routed by `apply`"),
        }
    }
}

fn find_profile_mut<'a>(
    config: &'a mut Config,
    instance: &str,
    area_id: Ipv4Addr,
    name: &str,
) -> Result<&'a mut Ospfv3Profile, OpError> {
    find_area_mut(config, instance, area_id)?
        .profiles
        .iter_mut()
        .find(|p| p.name == name)
        .ok_or_else(|| OpError::Ospfv3ProfileNotFound {
            instance: instance.to_string(),
            area_id,
            name: name.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Ospfv3Area, Ospfv3Instance};

    fn area_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn instance(name: &str, areas: Vec<Ospfv3Area>) -> Ospfv3Instance {
        Ospfv3Instance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas,
            routing_table: None,
            redistribute_policy: None,
            extended_lsa: false,
            graceful_restart_grace_period: None,
            graceful_restart_helper_max_grace_period: None,
        }
    }

    fn area(id: &str, profiles: Vec<Ospfv3Profile>) -> Ospfv3Area {
        Ospfv3Area {
            area_id: area_id(id),
            profiles,
        }
    }

    fn profile(name: &str) -> Ospfv3Profile {
        Ospfv3Profile {
            bfd: None,
            name: name.to_string(),
            hello_interval: None,
            dead_interval: None,
            cost: None,
            priority: None,
            mtu: None,
            mtu_ignore: false,
            network_type: None,
            auth: None,
            instance_id: None,
        }
    }

    fn key(key_id: u16) -> OspfCryptoKey {
        OspfCryptoKey {
            key_id,
            algorithm: crate::schema::OspfCryptoAlgorithm::HmacSha256,
            key: "secret".to_string(),
            is_current: false,
        }
    }

    #[test]
    fn crypto_key_ops_upsert_rotate_remove_and_clear() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        let common = ("o1".to_string(), area_id("0.0.0.0"), "p1".to_string());
        let (instance, area_id, name) = common.clone();
        Ospfv3ProfileOp::SetCryptoKey {
            instance,
            area_id,
            name,
            key: key(1),
        }
        .apply(&mut cfg)
        .unwrap();
        let (instance, area_id, name) = common.clone();
        Ospfv3ProfileOp::SetCryptoKey {
            instance,
            area_id,
            name,
            key: key(300),
        }
        .apply(&mut cfg)
        .unwrap();
        let (instance, area_id, name) = common.clone();
        Ospfv3ProfileOp::SetCryptoCurrentKey {
            instance,
            area_id,
            name,
            key_id: 300,
        }
        .apply(&mut cfg)
        .unwrap();
        let keys = cfg.ospfv3_instances[0].areas[0].profiles[0]
            .auth
            .clone()
            .unwrap();
        assert_eq!(keys.len(), 2);
        assert!(!keys[0].is_current && keys[1].is_current);

        let (instance, area_id, name) = common.clone();
        assert!(Ospfv3ProfileOp::SetCryptoCurrentKey {
            instance,
            area_id,
            name,
            key_id: 7,
        }
        .apply(&mut cfg)
        .is_err());

        let (instance, area_id, name) = common.clone();
        Ospfv3ProfileOp::RemoveCryptoKey {
            instance,
            area_id,
            name,
            key_id: 1,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospfv3_instances[0].areas[0].profiles[0]
                .auth
                .as_ref()
                .unwrap()
                .len(),
            1
        );

        let (instance, area_id, name) = common;
        Ospfv3ProfileOp::ClearAuth {
            instance,
            area_id,
            name,
        }
        .apply(&mut cfg)
        .unwrap();
        assert!(cfg.ospfv3_instances[0].areas[0].profiles[0].auth.is_none());
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![area("0.0.0.0", vec![])])],
            ..Default::default()
        };
        Ospfv3ProfileOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles.len(), 1);
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles[0].name, "p1");
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance(
                "o1",
                vec![area("0.0.0.0", vec![profile("p1"), profile("p2")])],
            )],
            ..Default::default()
        };
        Ospfv3ProfileOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles.len(), 1);
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles[0].name, "p2");
    }

    #[test]
    fn set_and_clear_hello_interval() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        Ospfv3ProfileOp::SetHelloInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            hello_interval: 5,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospfv3_instances[0].areas[0].profiles[0].hello_interval,
            Some(5)
        );

        Ospfv3ProfileOp::ClearHelloInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospfv3_instances[0].areas[0].profiles[0].hello_interval,
            None
        );
    }

    #[test]
    fn set_and_clear_cost() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        Ospfv3ProfileOp::SetCost {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            cost: 20,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles[0].cost, Some(20));

        Ospfv3ProfileOp::ClearCost {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances[0].areas[0].profiles[0].cost, None);
    }

    #[test]
    fn set_and_clear_network_type() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        Ospfv3ProfileOp::SetNetworkType {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            network_type: NetworkType::Broadcast,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospfv3_instances[0].areas[0].profiles[0].network_type,
            Some(NetworkType::Broadcast)
        );

        Ospfv3ProfileOp::ClearNetworkType {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospfv3_instances[0].areas[0].profiles[0].network_type,
            None
        );
    }
}
