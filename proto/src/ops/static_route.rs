use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::schema::{Config, StaticRoute};

use super::static_routing_instance::find_static_routing_instance_mut;
use super::OpError;

/// An edit to a single `StaticRoute` (keyed by `subnet`) within a given
/// static routing instance. Unlike `StaticRoutingInstanceOp`, there's no
/// `Ensure`/`SetX` split — a route's only content is its gateway, so `Set`
/// is a single upsert, mirroring `BgpPeerOp`. Applied without validation,
/// matching every other `Op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaticRouteOp {
    /// Creates the route if missing, else repoints its gateway.
    Set {
        /// Name of the static routing instance owning the target.
        instance: String,
        /// Destination prefix of the route.
        subnet: IpNet,
        /// Next-hop gateway address.
        gateway: IpAddr,
    },
    /// Deletes the static route and everything nested under it.
    Delete {
        /// Name of the static routing instance owning the target.
        instance: String,
        /// Destination prefix of the route.
        subnet: IpNet,
    },
}

impl StaticRouteOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            StaticRouteOp::Set {
                instance,
                subnet,
                gateway,
            } => {
                let inst = find_static_routing_instance_mut(config, instance)?;
                match inst.routes.iter_mut().find(|r| &r.subnet == subnet) {
                    Some(route) => route.gateway = *gateway,
                    None => inst.routes.push(StaticRoute {
                        bfd: None,
                        subnet: *subnet,
                        gateway: *gateway,
                        ..StaticRoute::default()
                    }),
                }
                Ok(())
            }
            StaticRouteOp::Delete { instance, subnet } => {
                let inst = find_static_routing_instance_mut(config, instance)?;
                let before = inst.routes.len();
                inst.routes.retain(|r| &r.subnet != subnet);
                if inst.routes.len() == before {
                    return Err(OpError::StaticRouteNotFound {
                        instance: instance.clone(),
                        subnet: *subnet,
                    });
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::schema::StaticRoutingInstance;

    use super::*;

    fn instance(name: &str, routes: Vec<StaticRoute>) -> StaticRoutingInstance {
        StaticRoutingInstance {
            name: name.to_string(),
            routes,
        }
    }

    fn config_with(instances: Vec<StaticRoutingInstance>) -> Config {
        Config {
            static_routing_instances: instances,
            ..Default::default()
        }
    }

    fn subnet(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn set_creates_when_missing() {
        let mut cfg = config_with(vec![instance("sri1", vec![])]);
        StaticRouteOp::Set {
            instance: "sri1".to_string(),
            subnet: subnet("10.0.0.0/24"),
            gateway: addr("10.0.0.1"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.static_routing_instances[0].routes.len(), 1);
        assert_eq!(
            cfg.static_routing_instances[0].routes[0].gateway,
            addr("10.0.0.1")
        );
    }

    #[test]
    fn set_updates_existing() {
        let mut cfg = config_with(vec![instance(
            "sri1",
            vec![StaticRoute {
                bfd: None,
                subnet: subnet("10.0.0.0/24"),
                gateway: addr("10.0.0.1"),
                ..Default::default()
            }],
        )]);
        StaticRouteOp::Set {
            instance: "sri1".to_string(),
            subnet: subnet("10.0.0.0/24"),
            gateway: addr("10.0.0.2"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.static_routing_instances[0].routes.len(), 1);
        assert_eq!(
            cfg.static_routing_instances[0].routes[0].gateway,
            addr("10.0.0.2")
        );
    }

    #[test]
    fn set_missing_instance_errors() {
        let mut cfg = config_with(vec![]);
        let err = StaticRouteOp::Set {
            instance: "sri1".to_string(),
            subnet: subnet("10.0.0.0/24"),
            gateway: addr("10.0.0.1"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::StaticRoutingInstanceNotFound(n) if n == "sri1"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = config_with(vec![instance(
            "sri1",
            vec![StaticRoute {
                bfd: None,
                subnet: subnet("10.0.0.0/24"),
                gateway: addr("10.0.0.1"),
                ..Default::default()
            }],
        )]);
        StaticRouteOp::Delete {
            instance: "sri1".to_string(),
            subnet: subnet("10.0.0.0/24"),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.static_routing_instances[0].routes, []);
    }

    #[test]
    fn delete_missing_route_errors() {
        let mut cfg = config_with(vec![instance("sri1", vec![])]);
        let err = StaticRouteOp::Delete {
            instance: "sri1".to_string(),
            subnet: subnet("10.0.0.0/24"),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(
            err,
            OpError::StaticRouteNotFound { instance: i, subnet: s }
            if i == "sri1" && s == subnet("10.0.0.0/24")
        ));
    }
}
