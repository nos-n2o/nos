use std::net::IpAddr;

use garde::Validate;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::Config;
use crate::validators::{bfd_reference_valid, sbfd_peer_valid};
use nos_proto_derive::Cli;

/// A single static route within a `StaticRoutingInstance`.
///
/// `gateway` is the first next hop and `next_hops` the others: the ECMP set
/// is both. `distance`/`tag` are per route, so every hop shares them.
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

    #[garde(
        custom(gateway_matches_subnet_family(self.subnet)),
        custom(blackhole_gateway(self.blackhole))
    )]
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

    /// Administrative distance (1 to 255) of this route against other
    /// sources; `None` keeps the source default (1).
    #[serde(default)]
    #[garde(custom(|d: &Option<u8>, _ctx: &Config| distance_valid(*d)))]
    #[cli(topic = StaticRouteDistance)]
    pub distance: Option<u8>,

    /// Opaque tag carried on the route (for policy matching); `None` sets
    /// none.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = StaticRouteTag)]
    pub tag: Option<u32>,

    /// Outgoing interface (or `<interface>.<tag>` subinterface) pinned for
    /// this route; required when `gateway` is an IPv6 link-local address.
    /// Must be in a routing table bound to this route's instance.
    #[serde(default)]
    #[garde(skip)] // needs the owning instance: checked by `StaticRoutingInstance.routes`
    #[cli(topic = StaticRouteInterface)]
    pub interface: Option<String>,

    /// Discard the traffic instead of forwarding it; `gateway` must then be
    /// the unspecified address (`0.0.0.0`/`::`). Excludes `bfd` and
    /// `interface`.
    #[serde(default)]
    #[garde(custom(blackhole_exclusive(self.bfd.is_some(), self.interface.is_some())))]
    #[cli(topic = StaticRouteBlackhole)]
    pub blackhole: bool,

    /// Further ECMP next hops besides `gateway`, keyed by gateway address;
    /// empty for a single-hop route and for a blackhole.
    #[serde(default)]
    #[garde(
        dive,
        custom(next_hops_valid(self.subnet, self.gateway, self.blackhole))
    )]
    #[cli(topic = StaticRouteNextHops)]
    pub next_hops: Vec<StaticNextHop>,
}

/// An additional gateway of a `StaticRoute` (see its `next_hops`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct StaticNextHop {
    #[garde(custom(gateway_specified))]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// Next-hop address, in the same family as the route's `subnet`; the key within `next_hops`.
    pub gateway: IpAddr,

    /// Outgoing interface pinned for this hop; required for an IPv6
    /// link-local gateway. Same rules as `StaticRoute.interface`.
    #[serde(default)]
    #[garde(skip)] // needs the owning instance: checked by `StaticRoutingInstance.routes`
    #[cli(topic = StaticRouteInterface)]
    pub interface: Option<String>,

    /// Name of a `BfdProfile` to run BFD with on this hop; `None` runs none.
    #[serde(default)]
    #[garde(
        custom(|b: &Option<String>, ctx: &Config| bfd_reference_valid(b.as_ref(), ctx)),
        custom(sbfd_peer(self.gateway))
    )]
    #[cli(topic = BfdReference)]
    pub bfd: Option<String>,
}

impl Default for StaticNextHop {
    fn default() -> Self {
        StaticNextHop {
            gateway: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            interface: None,
            bfd: None,
        }
    }
}

fn gateway_specified(g: &IpAddr, _ctx: &Config) -> garde::Result {
    if g.is_unspecified() {
        return Err(garde::Error::new(
            "next hop must not be the unspecified address",
        ));
    }
    Ok(())
}

/// Extra gateways: route's family, no repeats (nor the primary), none on a
/// blackhole.
fn next_hops_valid(
    subnet: IpNet,
    primary: IpAddr,
    blackhole: bool,
) -> impl FnOnce(&Vec<StaticNextHop>, &Config) -> garde::Result {
    move |hops, _ctx| {
        if blackhole && !hops.is_empty() {
            return Err(garde::Error::new("a blackhole route cannot have next-hops"));
        }
        let mut seen = vec![primary];
        for h in hops {
            if subnet.addr().is_ipv4() != h.gateway.is_ipv4() {
                return Err(garde::Error::new(
                    "next-hop address family must match subnet address family",
                ));
            }
            if seen.contains(&h.gateway) {
                return Err(garde::Error::new(
                    "next-hop repeats another gateway of the same route",
                ));
            }
            seen.push(h.gateway);
        }
        Ok(())
    }
}

/// The placeholder a new `StaticRoute` starts from (`edit` on a missing one).
impl Default for StaticRoute {
    fn default() -> Self {
        StaticRoute {
            subnet: IpNet::default(),
            gateway: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            bfd: None,
            distance: None,
            tag: None,
            interface: None,
            blackhole: false,
            next_hops: Vec::new(),
        }
    }
}

fn distance_valid(d: Option<u8>) -> garde::Result {
    if d == Some(0) {
        return Err(garde::Error::new("distance must be between 1 and 255"));
    }
    Ok(())
}

/// A blackhole route's gateway is the unspecified address; any other route's
/// is a real one.
fn blackhole_gateway(blackhole: bool) -> impl FnOnce(&IpAddr, &Config) -> garde::Result {
    move |gateway, _ctx| match (blackhole, gateway.is_unspecified()) {
        (true, false) => Err(garde::Error::new(
            "a blackhole route's gateway must be 0.0.0.0 or ::",
        )),
        (false, true) => Err(garde::Error::new(
            "gateway must not be the unspecified address unless blackhole is set",
        )),
        _ => Ok(()),
    }
}

fn blackhole_exclusive(bfd: bool, interface: bool) -> impl FnOnce(&bool, &Config) -> garde::Result {
    move |blackhole, _ctx| {
        if *blackhole && (bfd || interface) {
            return Err(garde::Error::new(
                "a blackhole route cannot also set bfd or interface",
            ));
        }
        Ok(())
    }
}

/// The routing table an interface name resolves to: `<interface>` is the
/// interface itself (or its untagged subinterface), `<interface>.<tag>` a
/// tagged subinterface.
fn table_of_interface<'a>(name: &str, ctx: &'a Config) -> Option<&'a String> {
    let (base, tag) = match name.split_once('.') {
        Some((b, t)) => (b, t.parse::<u16>().ok()?),
        None => (name, 0),
    };
    let i = ctx.interfaces.iter().find(|i| i.name == base)?;
    let sub = i.subinterfaces.iter().find(|s| s.tag == tag);
    match sub {
        Some(s) => s.routing_table.as_ref(),
        None if tag == 0 => i.routing_table.as_ref(),
        None => None,
    }
}

/// `route`'s `interface` and gateway rules, checked from the owning instance
/// (`instance`): the interface (or `<interface>.<tag>` subinterface) exists
/// and sits in a routing table bound to that instance; an IPv6 link-local
/// gateway needs one.
pub(crate) fn interface_valid(route: &StaticRoute, instance: &str, ctx: &Config) -> garde::Result {
    interface_ok(route.interface.as_ref(), route.gateway, instance, ctx)?;
    route
        .next_hops
        .iter()
        .try_for_each(|h| interface_ok(h.interface.as_ref(), h.gateway, instance, ctx))
}

fn interface_ok(
    interface: Option<&String>,
    gateway: IpAddr,
    instance: &str,
    ctx: &Config,
) -> garde::Result {
    let Some(name) = interface else {
        let link_local = matches!(gateway, IpAddr::V6(g) if g.is_unicast_link_local());
        return if link_local {
            Err(garde::Error::new(
                "an IPv6 link-local gateway needs an interface",
            ))
        } else {
            Ok(())
        };
    };
    let bound = table_of_interface(name, ctx).is_some_and(|t| {
        ctx.routing_tables
            .iter()
            .any(|rt| &rt.name == t && rt.static_routing_instance.as_deref() == Some(instance))
    });
    if bound {
        Ok(())
    } else {
        Err(garde::Error::new(format!(
            "interface '{name}' is not in a routing table bound to static routing instance '{instance}'"
        )))
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        };
        let cfg = config_with(vec![route]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    fn route(subnet: &str, gateway: &str) -> StaticRoute {
        StaticRoute {
            subnet: subnet.parse().unwrap(),
            gateway: gateway.parse().unwrap(),
            ..Default::default()
        }
    }

    fn ok(r: StaticRoute) -> bool {
        let cfg = config_with(vec![r]);
        cfg.validate_with(&cfg).is_ok()
    }

    #[test]
    fn distance_zero_is_rejected() {
        let mut r = route("10.0.0.0/24", "10.0.0.1");
        for (d, valid) in [(0, false), (1, true), (255, true)] {
            r.distance = Some(d);
            assert_eq!(ok(r.clone()), valid, "distance {d}");
        }
    }

    #[test]
    fn blackhole_rules() {
        let bh = |s: &str, g: &str| StaticRoute {
            blackhole: true,
            ..route(s, g)
        };
        assert!(ok(bh("10.0.0.0/24", "0.0.0.0")));
        assert!(ok(bh("2001:db8::/32", "::")));
        assert!(ok(StaticRoute {
            distance: Some(9),
            tag: Some(3),
            ..bh("10.0.0.0/24", "0.0.0.0")
        }));
        assert!(!ok(bh("10.0.0.0/24", "10.0.0.1")));
        assert!(!ok(bh("10.0.0.0/24", "::")));
        assert!(!ok(StaticRoute {
            bfd: Some("p".into()),
            ..bh("10.0.0.0/24", "0.0.0.0")
        }));
        assert!(!ok(StaticRoute {
            interface: Some("eth0".into()),
            ..bh("10.0.0.0/24", "0.0.0.0")
        }));
        // an unspecified gateway without blackhole
        assert!(!ok(route("10.0.0.0/24", "0.0.0.0")));
    }

    #[test]
    fn interface_must_be_bound_to_the_instance() {
        use crate::schema::{Interface, RoutingTable, Subinterface};
        let mut cfg = config_with(vec![]);
        cfg.interfaces = vec![
            Interface {
                name: "eth1".into(),
                subinterfaces: vec![
                    Subinterface {
                        tag: 10,
                        routing_table: Some("rt1".into()),
                        ..Default::default()
                    },
                    Subinterface {
                        tag: 20,
                        routing_table: Some("rt2".into()),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            Interface {
                name: "loopback-rt1".into(),
                routing_table: Some("rt1".into()),
                ..Default::default()
            },
        ];
        cfg.routing_tables = vec![
            RoutingTable {
                name: "rt1".into(),
                static_routing_instance: Some("sri1".into()),
                ..Default::default()
            },
            RoutingTable {
                name: "rt2".into(),
                ..Default::default()
            },
        ];
        let with = |gw: &str, ifc: Option<&str>| {
            let mut c = cfg.clone();
            c.static_routing_instances[0].routes = vec![StaticRoute {
                interface: ifc.map(Into::into),
                ..route("2001:db8::/32", gw)
            }];
            c.validate_with(&c).is_ok()
        };
        let ll = "fe80::1";
        assert!(!with(ll, None), "link-local needs an interface");
        assert!(with(ll, Some("eth1.10")));
        assert!(with(ll, Some("loopback-rt1")));
        assert!(!with(ll, Some("eth1.20")), "other table");
        assert!(!with(ll, Some("eth1.30")), "no such subinterface");
        assert!(!with(ll, Some("eth9")), "no such interface");
        assert!(!with(ll, Some("eth1.x")));
        assert!(with("2001:db8::1", None));
    }

    fn hop(g: &str) -> StaticNextHop {
        StaticNextHop {
            gateway: g.parse().unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn next_hop_rules() {
        let with = |s: &str, g: &str, hops: Vec<StaticNextHop>| StaticRoute {
            next_hops: hops,
            ..route(s, g)
        };
        assert!(ok(with(
            "10.0.0.0/24",
            "10.0.0.1",
            vec![hop("10.0.0.2"), hop("10.0.0.3")]
        )));
        assert!(ok(with(
            "2001:db8::/32",
            "2001:db8::1",
            vec![hop("2001:db8::2")]
        )));
        assert!(!ok(with(
            "10.0.0.0/24",
            "10.0.0.1",
            vec![hop("2001:db8::2")]
        )));
        assert!(!ok(with(
            "10.0.0.0/24",
            "10.0.0.1",
            vec![hop("10.0.0.2"), hop("10.0.0.2")]
        )));
        assert!(!ok(with("10.0.0.0/24", "10.0.0.1", vec![hop("10.0.0.1")])));
        assert!(!ok(with("10.0.0.0/24", "10.0.0.1", vec![hop("0.0.0.0")])));
        assert!(!ok(StaticRoute {
            blackhole: true,
            ..with("10.0.0.0/24", "0.0.0.0", vec![hop("10.0.0.2")])
        }));
        assert!(
            !ok(with("2001:db8::/32", "2001:db8::1", vec![hop("fe80::2")])),
            "link-local needs interface"
        );
        let mut bad_bfd = hop("10.0.0.2");
        bad_bfd.bfd = Some("missing".into());
        assert!(!ok(with("10.0.0.0/24", "10.0.0.1", vec![bad_bfd])));
    }

    #[test]
    fn next_hops_round_trip_and_default() {
        let r = StaticRoute {
            next_hops: vec![hop("10.0.0.2")],
            ..route("10.0.0.0/24", "10.0.0.1")
        };
        let b = postcard::to_allocvec(&r).unwrap();
        assert_eq!(postcard::from_bytes::<StaticRoute>(&b).unwrap(), r);
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<StaticRoute>(&j).unwrap(), r);
    }

    #[test]
    fn old_config_without_new_keys_loads_and_postcard_round_trips() {
        let r: StaticRoute =
            serde_json::from_str(r#"{"subnet":"10.0.0.0/24","gateway":"10.0.0.1"}"#).unwrap();
        assert_eq!(r, route("10.0.0.0/24", "10.0.0.1"));
        let full = StaticRoute {
            distance: Some(5),
            tag: Some(9),
            interface: Some("eth1".into()),
            ..r
        };
        let b = postcard::to_allocvec(&full).unwrap();
        assert_eq!(postcard::from_bytes::<StaticRoute>(&b).unwrap(), full);
    }
}
