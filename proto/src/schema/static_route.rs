use std::net::IpAddr;

use garde::Validate;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::Config;
use crate::validators::{bfd_reference_valid, sbfd_peer_valid};
use nos_proto_derive::Cli;

/// A single static route within a `StaticRoutingInstance`.
///
/// Known simplification: exactly one gateway per subnet is supported — ECMP
/// (multiple gateways for one subnet) is not modeled in this iteration.
/// Per-instance uniqueness of `subnet` is enforced on the *parent's*
/// `routes` field (`static_routing_instance::unique_subnets`), not here — a
/// `StaticRoute` in isolation has no notion of which instance owns it under
/// garde's whole-`Config` validation context.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct StaticRoute {
    // Structurally valid by construction; per-instance uniqueness lives on
    // the owning `StaticRoutingInstance.routes` field instead.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// Destination prefix; the key within the instance.
    #[cfg_attr(feature = "arbitrary", arbitrary(with = crate::arbitrary_support::ip_net))]
    pub subnet: IpNet,

    #[garde(custom(gateway_matches_subnet_family(self.subnet)))]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(topic = StaticRoute)]
    /// Next-hop address, in the same family as `subnet`.
    pub gateway: IpAddr,

    /// Name of a `BfdProfile` to run BFD with; `None` runs no BFD.
    /// Inert until `nos-bfdd` exists.
    #[serde(default)]
    #[garde(
        custom(|b: &Option<String>, ctx: &Config| bfd_reference_valid(b.as_ref(), ctx)),
        custom(sbfd_peer(self.gateway))
    )]
    #[cli(topic = BfdReference)]
    pub bfd: Option<String>,
}

/// The placeholder a new `StaticRoute` starts from (`edit` on a missing one).
impl Default for StaticRoute {
    fn default() -> Self {
        StaticRoute {
            subnet: IpNet::default(),
            gateway: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            bfd: None,
        }
    }
}

fn sbfd_peer(gateway: IpAddr) -> impl FnOnce(&Option<String>, &Config) -> garde::Result {
    move |b, ctx| sbfd_peer_valid(b.as_ref(), gateway, ctx)
}

/// The gateway's address family must match the subnet's — unlike
/// `BgpPeerGroup`'s deliberately-independent `source_address`/
/// `address_families` (see its doc comment), this is a real routing
/// constraint, not a transport-vs-NLRI independence case.
fn gateway_matches_subnet_family(subnet: IpNet) -> impl FnOnce(&IpAddr, &Config) -> garde::Result {
    move |gateway, _ctx| match (subnet, gateway) {
        (IpNet::V4(_), IpAddr::V4(_)) | (IpNet::V6(_), IpAddr::V6(_)) => Ok(()),
        _ => Err(garde::Error::new(
            "gateway address family must match subnet address family",
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::schema::Config;

    use super::*;

    fn config_with(routes: Vec<StaticRoute>) -> Config {
        use crate::schema::StaticRoutingInstance;
        Config {
            static_routing_instances: vec![StaticRoutingInstance {
                name: "sri1".to_string(),
                routes,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn valid_ipv4_route_passes() {
        let route = StaticRoute {
            bfd: None,
            subnet: "10.0.0.0/24".parse().unwrap(),
            gateway: "10.0.0.1".parse().unwrap(),
        };
        let cfg = config_with(vec![route]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn valid_ipv6_route_passes() {
        let route = StaticRoute {
            bfd: None,
            subnet: "2001:db8::/32".parse().unwrap(),
            gateway: "2001:db8::1".parse().unwrap(),
        };
        let cfg = config_with(vec![route]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn sbfd_profile_on_an_ipv6_route_needs_a_remote_discriminator() {
        use crate::schema::{BfdMode, BfdProfile};
        let route = StaticRoute {
            bfd: Some("sb".into()),
            subnet: "2001:db8::/32".parse().unwrap(),
            gateway: "2001:db8::1".parse().unwrap(),
        };
        let mut cfg = config_with(vec![route]);
        cfg.bfd_profiles = vec![BfdProfile {
            name: "sb".into(),
            mode: BfdMode::Sbfd,
            ..Default::default()
        }];
        assert!(cfg.validate_with(&cfg).is_err());
        cfg.bfd_profiles[0].sbfd_remote_discriminator = Some("10.0.0.2".parse().unwrap());
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn mismatched_address_family_fails() {
        let route = StaticRoute {
            bfd: None,
            subnet: "10.0.0.0/24".parse().unwrap(),
            gateway: "2001:db8::1".parse().unwrap(),
        };
        let cfg = config_with(vec![route]);
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
