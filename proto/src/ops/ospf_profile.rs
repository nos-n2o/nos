use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::schema::{Config, NetworkType, OspfAuth, OspfCryptoKey, OspfProfile};

use super::ospf_area::find_area_mut;
use super::OpError;

/// An edit to a single `OspfProfile` (keyed by `name`, globally unique) nested
/// under a named `OspfArea` of a named `OspfInstance`, within a transaction's
/// in-progress config. Applied without validation, matching every other
/// `Op`. Compound-keyed (`instance`, `area_id`, `name`) like `BgpPeerGroupOp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfProfileOp {
    /// Creates the profile if it doesn't already exist (the owning area
    /// must already exist); no-op if it does. Backs `edit ospf instance
    /// <name> area <area-id> profile <profile-name>`'s "create if missing,
    /// else navigate to it" semantics.
    Ensure {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
    },
    /// Deletes the OSPF profile and everything nested under it.
    Delete {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
    },
    /// Sets the hello interval of the OSPF profile to `hello_interval`.
    SetHelloInterval {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// Hello interval in seconds (RFC 2328 §9.5).
        hello_interval: u16,
    },
    /// Clears the hello interval of the OSPF profile so it reverts to the default.
    ClearHelloInterval {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
    },
    /// Sets the dead interval of the OSPF profile to `dead_interval`.
    SetDeadInterval {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// Router dead interval in seconds (RFC 2328 §9.5).
        dead_interval: u16,
    },
    /// Clears the dead interval of the OSPF profile so it reverts to the default.
    ClearDeadInterval {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
    },
    /// Sets the cost of the OSPF profile to `cost`.
    SetCost {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// Interface output cost (RFC 2328 §A.3.2).
        cost: u16,
    },
    /// Clears the cost of the OSPF profile so it reverts to the default.
    ClearCost {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
    },
    /// Sets the priority of the OSPF profile to `priority`.
    SetPriority {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// Router priority for DR/BDR election (0 makes the router ineligible).
        priority: u8,
    },
    /// Clears the priority of the OSPF profile so it reverts to the default.
    ClearPriority {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
    },
    /// Sets the MTU of the OSPF profile to `mtu`.
    SetMtu {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// MTU advertised in database descriptions (RFC 2328 §10.6).
        mtu: u16,
    },
    /// Toggles the RFC 2328 §10.6 DBD Interface MTU check.
    SetMtuIgnore {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// `true` turns the feature on, `false` turns it off.
        enabled: bool,
    },
    /// Clears the MTU of the OSPF profile so it reverts to the default.
    ClearMtu {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
    },
    /// Toggles RFC 7474 extended cryptographic sequence numbers.
    SetExtendedSequenceNumbers {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// `true` turns the feature on, `false` turns it off.
        enabled: bool,
    },
    /// Sets the network type of the OSPF profile to `network_type`.
    SetNetworkType {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// OSPF network type (point-to-point, broadcast, ...).
        network_type: NetworkType,
    },
    /// Clears the network type of the OSPF profile so it reverts to the default.
    ClearNetworkType {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
    },
    /// Sets `auth` to a simple password, replacing any crypto keys (RFC
    /// 2328's Simple and Cryptographic auth types are mutually exclusive).
    SetSimpleAuth {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// Label of the admin key holding the password.
        key: String,
    },
    /// Upserts one crypto key by `key_id`. If `auth` isn't already `Crypto`
    /// (unset, or `Simple`), starts a fresh key list with just this key.
    SetCryptoKey {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// The authentication key entry.
        key: OspfCryptoKey,
    },
    /// Removes one crypto key by `key_id`. No-op if `auth` isn't `Crypto` or
    /// the id isn't present — does not clear `auth` back to `None` even if
    /// the list becomes empty; commit-time validation rejects an empty
    /// `Crypto` list, so an explicit `ClearAuth` is required for that case.
    RemoveCryptoKey {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// Key ID selecting the cryptographic key (RFC 2328 App. D).
        key_id: u16,
    },
    /// Marks one existing crypto key as the current key, clearing the flag
    /// on every other key in the list.
    SetCryptoCurrentKey {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
        /// Key ID selecting the cryptographic key (RFC 2328 App. D).
        key_id: u16,
    },
    /// Unsets `auth` entirely, regardless of which mechanism was set.
    ClearAuth {
        /// Name of the OSPF instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// Name of the OSPF profile this op targets.
        name: String,
    },
}

impl OspfProfileOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            OspfProfileOp::Ensure { .. }
            | OspfProfileOp::Delete { .. }
            | OspfProfileOp::SetHelloInterval { .. }
            | OspfProfileOp::ClearHelloInterval { .. }
            | OspfProfileOp::SetDeadInterval { .. }
            | OspfProfileOp::ClearDeadInterval { .. }
            | OspfProfileOp::SetCost { .. }
            | OspfProfileOp::ClearCost { .. }
            | OspfProfileOp::SetPriority { .. }
            | OspfProfileOp::ClearPriority { .. }
            | OspfProfileOp::SetMtu { .. } => self.apply_part1(config),
            OspfProfileOp::SetMtuIgnore { .. }
            | OspfProfileOp::ClearMtu { .. }
            | OspfProfileOp::SetExtendedSequenceNumbers { .. }
            | OspfProfileOp::SetNetworkType { .. }
            | OspfProfileOp::ClearNetworkType { .. }
            | OspfProfileOp::SetSimpleAuth { .. }
            | OspfProfileOp::SetCryptoKey { .. }
            | OspfProfileOp::RemoveCryptoKey { .. }
            | OspfProfileOp::SetCryptoCurrentKey { .. }
            | OspfProfileOp::ClearAuth { .. } => self.apply_part2(config),
        }
    }

    /// Arms of `apply`, split out for length (#425); `apply` names every variant, so a
    /// new one still fails to compile until it is routed to a part.
    fn apply_part1(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            OspfProfileOp::Ensure {
                instance,
                area_id,
                name,
            } => {
                let area = find_area_mut(config, instance, *area_id)?;
                if !area.profiles.iter().any(|p| &p.name == name) {
                    area.profiles.push(OspfProfile {
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
                        extended_sequence_numbers: false,
                    });
                }
                Ok(())
            }
            OspfProfileOp::Delete {
                instance,
                area_id,
                name,
            } => {
                let area = find_area_mut(config, instance, *area_id)?;
                let before = area.profiles.len();
                area.profiles.retain(|p| &p.name != name);
                if area.profiles.len() == before {
                    return Err(OpError::OspfProfileNotFound {
                        instance: instance.clone(),
                        area_id: *area_id,
                        name: name.clone(),
                    });
                }
                Ok(())
            }
            OspfProfileOp::SetHelloInterval {
                instance,
                area_id,
                name,
                hello_interval,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.hello_interval =
                    Some(*hello_interval);
                Ok(())
            }
            OspfProfileOp::ClearHelloInterval {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.hello_interval = None;
                Ok(())
            }
            OspfProfileOp::SetDeadInterval {
                instance,
                area_id,
                name,
                dead_interval,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.dead_interval =
                    Some(*dead_interval);
                Ok(())
            }
            OspfProfileOp::ClearDeadInterval {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.dead_interval = None;
                Ok(())
            }
            OspfProfileOp::SetCost {
                instance,
                area_id,
                name,
                cost,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.cost = Some(*cost);
                Ok(())
            }
            OspfProfileOp::ClearCost {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.cost = None;
                Ok(())
            }
            OspfProfileOp::SetPriority {
                instance,
                area_id,
                name,
                priority,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.priority = Some(*priority);
                Ok(())
            }
            OspfProfileOp::ClearPriority {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.priority = None;
                Ok(())
            }
            OspfProfileOp::SetMtu {
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
            OspfProfileOp::SetMtuIgnore {
                instance,
                area_id,
                name,
                enabled,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.mtu_ignore = *enabled;
                Ok(())
            }
            OspfProfileOp::ClearMtu {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.mtu = None;
                Ok(())
            }
            OspfProfileOp::SetExtendedSequenceNumbers {
                instance,
                area_id,
                name,
                enabled,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.extended_sequence_numbers =
                    *enabled;
                Ok(())
            }
            OspfProfileOp::SetNetworkType {
                instance,
                area_id,
                name,
                network_type,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.network_type =
                    Some(*network_type);
                Ok(())
            }
            OspfProfileOp::ClearNetworkType {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.network_type = None;
                Ok(())
            }
            OspfProfileOp::SetSimpleAuth {
                instance,
                area_id,
                name,
                key,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.auth =
                    Some(OspfAuth::Simple { key: key.clone() });
                Ok(())
            }
            OspfProfileOp::SetCryptoKey {
                instance,
                area_id,
                name,
                key,
            } => {
                let profile = find_profile_mut(config, instance, *area_id, name)?;
                let keys = match &mut profile.auth {
                    Some(OspfAuth::Crypto { keys }) => keys,
                    Some(OspfAuth::Simple { .. }) | None => {
                        profile.auth = Some(OspfAuth::Crypto { keys: Vec::new() });
                        let Some(OspfAuth::Crypto { keys }) = &mut profile.auth else {
                            unreachable!("just set to Crypto above")
                        };
                        keys
                    }
                };
                match keys.iter_mut().find(|k| k.key_id == key.key_id) {
                    Some(existing) => *existing = key.clone(),
                    None => keys.push(key.clone()),
                }
                Ok(())
            }
            OspfProfileOp::RemoveCryptoKey {
                instance,
                area_id,
                name,
                key_id,
            } => {
                if let Some(OspfAuth::Crypto { keys }) =
                    &mut find_profile_mut(config, instance, *area_id, name)?.auth
                {
                    keys.retain(|k| k.key_id != *key_id);
                }
                Ok(())
            }
            OspfProfileOp::SetCryptoCurrentKey {
                instance,
                area_id,
                name,
                key_id,
            } => set_crypto_key_flag(config, instance, *area_id, name, *key_id),
            OspfProfileOp::ClearAuth {
                instance,
                area_id,
                name,
            } => {
                find_profile_mut(config, instance, *area_id, name)?.auth = None;
                Ok(())
            }
            _ => unreachable!("routed by `apply`"),
        }
    }
}

/// Shared body of `SetCryptoCurrentKey`: sets `is_current = true` on the key
/// matching `key_id` and `false` on every other key in the same `Crypto`
/// list — mirrors `bgp_peer_group::set_ao_key_flag`.
fn set_crypto_key_flag(
    config: &mut Config,
    instance: &str,
    area_id: Ipv4Addr,
    name: &str,
    key_id: u16,
) -> Result<(), OpError> {
    let profile = find_profile_mut(config, instance, area_id, name)?;
    let Some(OspfAuth::Crypto { keys }) = &mut profile.auth else {
        return Err(OpError::OspfCryptoKeyNotFound {
            instance: instance.to_string(),
            area_id,
            name: name.to_string(),
            key_id,
        });
    };
    if !keys.iter().any(|k| k.key_id == key_id) {
        return Err(OpError::OspfCryptoKeyNotFound {
            instance: instance.to_string(),
            area_id,
            name: name.to_string(),
            key_id,
        });
    }
    for key in keys.iter_mut() {
        key.is_current = key.key_id == key_id;
    }
    Ok(())
}

fn find_profile_mut<'a>(
    config: &'a mut Config,
    instance: &str,
    area_id: Ipv4Addr,
    name: &str,
) -> Result<&'a mut OspfProfile, OpError> {
    find_area_mut(config, instance, area_id)?
        .profiles
        .iter_mut()
        .find(|p| p.name == name)
        .ok_or_else(|| OpError::OspfProfileNotFound {
            instance: instance.to_string(),
            area_id,
            name: name.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{OspfArea, OspfInstance};

    fn area_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn instance(name: &str, areas: Vec<OspfArea>) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas,
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
            graceful_restart_helper_max_grace_period: None,
            prefix_suppression: false,
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
            host_router: false,
            remote_lfa: false,
            redistribute_metric: None,
            redistribute_metric_type: None,
        }
    }

    fn area(id: &str, profiles: Vec<OspfProfile>) -> OspfArea {
        OspfArea {
            area_id: area_id(id),
            area_type: crate::schema::OspfAreaType::Normal,
            stub_default_cost: None,
            ranges: Vec::new(),
            nssa_translate_always: false,
            nssa_default_originate: false,
            virtual_links: Vec::new(),
            profiles,
        }
    }

    fn profile(name: &str) -> OspfProfile {
        OspfProfile {
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
            extended_sequence_numbers: false,
        }
    }

    fn crypto_key(key_id: u16, is_current: bool) -> OspfCryptoKey {
        OspfCryptoKey {
            key_id,
            algorithm: crate::schema::OspfCryptoAlgorithm::HmacSha256,
            key: "secret".to_string(),
            is_current,
        }
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![])])],
            ..Default::default()
        };
        OspfProfileOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles.len(), 1);
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].name, "p1");
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles.len(), 1);
    }

    #[test]
    fn ensure_missing_area_errors() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![])],
            ..Default::default()
        };
        let err = OspfProfileOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::OspfAreaNotFound { instance, area_id }
            if instance == "o1" && area_id == self::area_id("0.0.0.0")
        ));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            ospf_instances: vec![instance(
                "o1",
                vec![area("0.0.0.0", vec![profile("p1"), profile("p2")])],
            )],
            ..Default::default()
        };
        OspfProfileOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles.len(), 1);
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].name, "p2");
    }

    #[test]
    fn delete_missing_profile_errors() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![])])],
            ..Default::default()
        };
        let err = OspfProfileOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::OspfProfileNotFound { instance, area_id, name }
            if instance == "o1" && area_id == self::area_id("0.0.0.0") && name == "p1"
        ));
    }

    #[test]
    fn set_and_clear_hello_interval() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetHelloInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            hello_interval: 5,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].hello_interval,
            Some(5)
        );

        OspfProfileOp::ClearHelloInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].hello_interval,
            None
        );
    }

    #[test]
    fn set_and_clear_dead_interval() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetDeadInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            dead_interval: 20,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].dead_interval,
            Some(20)
        );

        OspfProfileOp::ClearDeadInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].dead_interval,
            None
        );
    }

    #[test]
    fn set_hello_interval_missing_profile_errors() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![])])],
            ..Default::default()
        };
        let err = OspfProfileOp::SetHelloInterval {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            hello_interval: 5,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::OspfProfileNotFound { instance, area_id, name }
            if instance == "o1" && area_id == self::area_id("0.0.0.0") && name == "p1"
        ));
    }

    #[test]
    fn set_and_clear_cost() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetCost {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            cost: 20,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].cost, Some(20));

        OspfProfileOp::ClearCost {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].cost, None);
    }

    #[test]
    fn set_and_clear_priority() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetPriority {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            priority: 200,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].priority,
            Some(200)
        );

        OspfProfileOp::ClearPriority {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].priority, None);
    }

    #[test]
    fn set_and_clear_mtu() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetMtu {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            mtu: 1400,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].mtu, Some(1400));

        OspfProfileOp::ClearMtu {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].mtu, None);
    }

    #[test]
    fn set_and_clear_network_type() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetNetworkType {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            network_type: NetworkType::Broadcast,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].network_type,
            Some(NetworkType::Broadcast)
        );

        OspfProfileOp::ClearNetworkType {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].network_type,
            None
        );
    }

    #[test]
    fn set_simple_auth() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetSimpleAuth {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key: "abcdefgh".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].auth,
            Some(OspfAuth::Simple {
                key: "abcdefgh".to_string()
            })
        );
    }

    #[test]
    fn set_crypto_key_starts_fresh_list_over_simple_auth() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetSimpleAuth {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key: "abcdefgh".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        OspfProfileOp::SetCryptoKey {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key: crypto_key(1, true),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].auth,
            Some(OspfAuth::Crypto {
                keys: vec![crypto_key(1, true)]
            })
        );
    }

    #[test]
    fn set_crypto_key_upserts_by_key_id() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetCryptoKey {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key: crypto_key(1, true),
        }
        .apply(&mut cfg)
        .unwrap();
        let mut updated = crypto_key(1, true);
        updated.key = "newsecret".to_string();
        OspfProfileOp::SetCryptoKey {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key: updated.clone(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].auth,
            Some(OspfAuth::Crypto {
                keys: vec![updated]
            })
        );
    }

    #[test]
    fn remove_crypto_key() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetCryptoKey {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key: crypto_key(1, true),
        }
        .apply(&mut cfg)
        .unwrap();
        OspfProfileOp::RemoveCryptoKey {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key_id: 1,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].auth,
            Some(OspfAuth::Crypto { keys: vec![] })
        );
    }

    #[test]
    fn set_crypto_current_key_clears_flag_on_others() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetCryptoKey {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key: crypto_key(1, true),
        }
        .apply(&mut cfg)
        .unwrap();
        OspfProfileOp::SetCryptoKey {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key: crypto_key(2, false),
        }
        .apply(&mut cfg)
        .unwrap();
        OspfProfileOp::SetCryptoCurrentKey {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key_id: 2,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.ospf_instances[0].areas[0].profiles[0].auth,
            Some(OspfAuth::Crypto {
                keys: vec![crypto_key(1, false), crypto_key(2, true)]
            })
        );
    }

    #[test]
    fn set_crypto_current_key_missing_errors() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        let err = OspfProfileOp::SetCryptoCurrentKey {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key_id: 1,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::OspfCryptoKeyNotFound { .. }));
    }

    #[test]
    fn clear_auth() {
        let mut cfg = Config {
            ospf_instances: vec![instance("o1", vec![area("0.0.0.0", vec![profile("p1")])])],
            ..Default::default()
        };
        OspfProfileOp::SetSimpleAuth {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
            key: "abcdefgh".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        OspfProfileOp::ClearAuth {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
            name: "p1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospf_instances[0].areas[0].profiles[0].auth, None);
    }
}
