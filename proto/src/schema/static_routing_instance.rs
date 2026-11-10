use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::{Config, StaticRoute};
use nos_proto_derive::Cli;

/// A named container of static routes. Carries no reference to any routing
/// table — only `RoutingTable.static_routing_instance` names it, never the
/// other way around.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct StaticRoutingInstance {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.static_routing_instances, |i| &i.name))
    )]
    #[cli(key)]
    /// Instance name, 1 to 64 characters (letters, digits, `_`, `-`), unique among static routing instances.
    pub name: String,

    #[garde(dive, custom(|routes, _ctx: &Config| unique_subnets(routes)))]
    #[cli(topic = StaticRoute)]
    /// Routes of this instance, keyed by destination prefix.
    pub routes: Vec<StaticRoute>,
}

/// No two routes within the same instance may share a subnet — see
/// `StaticRoute`'s doc comment on the ECMP simplification. Scoped to
/// `self.routes` only (not global), since this uniqueness is genuinely
/// per-parent, unlike peer-group name/peer-address uniqueness.
fn unique_subnets(routes: &[StaticRoute]) -> garde::Result {
    let mut seen: Vec<ipnet::IpNet> = Vec::new();
    for r in routes {
        if seen.contains(&r.subnet) {
            return Err(garde::Error::new(
                "must not repeat a subnet within the same static routing instance",
            ));
        }
        seen.push(r.subnet);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(subnet: &str, gateway: &str) -> StaticRoute {
        StaticRoute {
            bfd: None,
            subnet: subnet.parse().unwrap(),
            gateway: gateway.parse().unwrap(),
        }
    }

    fn config_with(instances: Vec<StaticRoutingInstance>) -> Config {
        Config {
            static_routing_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_instance_passes() {
        let cfg = config_with(vec![StaticRoutingInstance {
            name: "sri1".to_string(),
            routes: vec![route("10.0.0.0/24", "10.0.0.1")],
        }]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![
            StaticRoutingInstance {
                name: "sri1".to_string(),
                routes: Vec::new(),
            },
            StaticRoutingInstance {
                name: "sri1".to_string(),
                routes: Vec::new(),
            },
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_subnet_within_instance_fails() {
        let cfg = config_with(vec![StaticRoutingInstance {
            name: "sri1".to_string(),
            routes: vec![
                route("10.0.0.0/24", "10.0.0.1"),
                route("10.0.0.0/24", "10.0.0.2"),
            ],
        }]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn same_subnet_across_different_instances_passes() {
        let cfg = config_with(vec![
            StaticRoutingInstance {
                name: "sri1".to_string(),
                routes: vec![route("10.0.0.0/24", "10.0.0.1")],
            },
            StaticRoutingInstance {
                name: "sri2".to_string(),
                routes: vec![route("10.0.0.0/24", "10.0.0.2")],
            },
        ]);
        cfg.validate_with(&cfg).unwrap();
    }
}
