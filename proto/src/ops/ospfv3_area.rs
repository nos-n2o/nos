use std::net::Ipv4Addr;

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};

use crate::schema::{Config, Ospfv3Area, Ospfv3AreaRange};

use super::ospfv3_instance::find_instance_mut;
use super::OpError;

/// An edit to a single `Ospfv3Area` (keyed by `area_id`) nested under a
/// named `Ospfv3Instance`, within a transaction's in-progress config —
/// mirrors `OspfAreaOp` exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ospfv3AreaOp {
    /// Creates the `OSPFv3` area if it does not exist (idempotent).
    Ensure {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
    },
    /// Deletes the `OSPFv3` area and everything nested under it.
    Delete {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
    },
    /// Adds the RFC 5340 §4.4.3.3 range `cidr` to the area, or replaces its
    /// `not_advertise` (upsert).
    SetRange {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// The summarised prefix.
        cidr: Ipv6Net,
        /// Hide the covered prefixes from the other areas.
        not_advertise: bool,
    },
    /// Removes the range `cidr` from the area.
    RemoveRange {
        /// Name of the `OSPFv3` instance owning the target.
        instance: String,
        /// Area ID in dotted-quad form (`0.0.0.0` is the backbone).
        area_id: Ipv4Addr,
        /// The range's prefix.
        cidr: Ipv6Net,
    },
}

impl Ospfv3AreaOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            Ospfv3AreaOp::Ensure { instance, area_id } => {
                let inst = find_instance_mut(config, instance)?;
                if !inst.areas.iter().any(|a| &a.area_id == area_id) {
                    inst.areas.push(Ospfv3Area {
                        area_id: *area_id,
                        ..Default::default()
                    });
                }
                Ok(())
            }
            Ospfv3AreaOp::Delete { instance, area_id } => {
                let inst = find_instance_mut(config, instance)?;
                let before = inst.areas.len();
                inst.areas.retain(|a| &a.area_id != area_id);
                if inst.areas.len() == before {
                    return Err(OpError::Ospfv3AreaNotFound {
                        instance: instance.clone(),
                        area_id: *area_id,
                    });
                }
                Ok(())
            }
            Ospfv3AreaOp::SetRange {
                instance,
                area_id,
                cidr,
                not_advertise,
            } => {
                let ranges = &mut find_area_mut(config, instance, *area_id)?.ranges;
                let range = Ospfv3AreaRange {
                    cidr: *cidr,
                    not_advertise: *not_advertise,
                };
                match ranges.iter_mut().find(|r| r.cidr == *cidr) {
                    Some(r) => *r = range,
                    None => ranges.push(range),
                }
                Ok(())
            }
            Ospfv3AreaOp::RemoveRange {
                instance,
                area_id,
                cidr,
            } => {
                let ranges = &mut find_area_mut(config, instance, *area_id)?.ranges;
                let before = ranges.len();
                ranges.retain(|r| r.cidr != *cidr);
                if ranges.len() == before {
                    return Err(OpError::Ospfv3AreaRangeNotFound {
                        instance: instance.clone(),
                        area_id: *area_id,
                        cidr: *cidr,
                    });
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn find_area_mut<'a>(
    config: &'a mut Config,
    instance: &str,
    area_id: Ipv4Addr,
) -> Result<&'a mut Ospfv3Area, OpError> {
    find_instance_mut(config, instance)?
        .areas
        .iter_mut()
        .find(|a| a.area_id == area_id)
        .ok_or_else(|| OpError::Ospfv3AreaNotFound {
            instance: instance.to_string(),
            area_id,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Ospfv3Instance;

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
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
        }
    }

    fn area_id(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn ensure_creates_when_missing() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![])],
            ..Default::default()
        };
        Ospfv3AreaOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances[0].areas.len(), 1);
        assert_eq!(cfg.ospfv3_instances[0].areas[0].area_id, area_id("0.0.0.0"));
    }

    #[test]
    fn ensure_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = Ospfv3AreaOp::Ensure {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::Ospfv3InstanceNotFound(n) if n == "o1"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance(
                "o1",
                vec![
                    Ospfv3Area {
                        area_id: area_id("0.0.0.0"),
                        profiles: Vec::new(),
                        ranges: Vec::new(),
                    },
                    Ospfv3Area {
                        area_id: area_id("0.0.0.1"),
                        profiles: Vec::new(),
                        ranges: Vec::new(),
                    },
                ],
            )],
            ..Default::default()
        };
        Ospfv3AreaOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.ospfv3_instances[0].areas.len(), 1);
        assert_eq!(cfg.ospfv3_instances[0].areas[0].area_id, area_id("0.0.0.1"));
    }

    #[test]
    fn delete_missing_area_errors() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance("o1", vec![])],
            ..Default::default()
        };
        let err = Ospfv3AreaOp::Delete {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.0"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::Ospfv3AreaNotFound { instance, area_id }
            if instance == "o1" && area_id == self::area_id("0.0.0.0")
        ));
    }

    #[test]
    fn set_range_upserts_and_remove_range_errors_when_missing() {
        let mut cfg = Config {
            ospfv3_instances: vec![instance(
                "o1",
                vec![Ospfv3Area {
                    area_id: area_id("0.0.0.1"),
                    ..Default::default()
                }],
            )],
            ..Default::default()
        };
        let cidr: Ipv6Net = "2001:db8::/32".parse().unwrap();
        let set = |not_advertise| Ospfv3AreaOp::SetRange {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.1"),
            cidr,
            not_advertise,
        };
        set(false).apply(&mut cfg).unwrap();
        set(true).apply(&mut cfg).unwrap();
        let ranges = &cfg.ospfv3_instances[0].areas[0].ranges;
        assert_eq!(ranges.len(), 1);
        assert!(ranges[0].not_advertise);
        let remove = Ospfv3AreaOp::RemoveRange {
            instance: "o1".to_string(),
            area_id: area_id("0.0.0.1"),
            cidr,
        };
        remove.apply(&mut cfg).unwrap();
        assert!(matches!(
            remove.apply(&mut cfg),
            Err(OpError::Ospfv3AreaRangeNotFound { .. })
        ));
    }
}
