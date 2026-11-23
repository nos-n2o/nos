use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::{Config, Ospfv3Area};
use nos_proto_derive::Cli;

/// A named `OSPFv3` (RFC 5340) instance — the IPv6 counterpart of
/// `OspfInstance`, kept as a fully parallel type rather than widened onto
/// it, since `OSPFv2` and `OSPFv3` are different wire protocols (different
/// packet/LSA formats) run by two independent daemons (`nos-ospfd`/
/// `nos-ospfv3d`) — see the `OSPFv3` Phase 1 plan. `router_id`/`area_id`
/// (on `Ospfv3Area`) stay `Ipv4Addr`: RFC 5340 keeps these as opaque 32-bit
/// identifiers, not real addresses, exactly like RFC 2328.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct Ospfv3Instance {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.ospfv3_instances, |i| &i.name))
    )]
    #[cli(key)]
    /// Instance name, 1 to 64 characters (letters, digits, `_`, `-`), unique among `OSPFv3` instances.
    pub name: String,

    // Ipv4Addr is structurally valid by construction; no additional garde rule needed.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(topic = Ospfv3InstanceRouterId)]
    /// 32-bit router id (RFC 5340 §2.1), written as an IPv4 dotted-quad.
    pub router_id: Ipv4Addr,

    /// This instance's `OSPFv3` areas, keyed by `area_id` — see `Ospfv3Area`.
    #[garde(dive, custom(|areas, _ctx: &Config| unique_area_ids(areas, self.router_id)))]
    #[cli(topic = Ospfv3Area)]
    pub areas: Vec<Ospfv3Area>,

    /// The name of the `RoutingTable` that claims this instance (i.e. the
    /// VRF it belongs to), mirrored from that table's `ospfv3_instance`
    /// field — same derived/read-only pattern as `OspfInstance.routing_table`
    /// (`crate::derive::sync_routing_table_refs`).
    #[garde(skip)]
    #[cli(hidden)]
    pub routing_table: Option<String>,

    /// The policy of the owning table's `redistribute … to ospfv3` rule,
    /// mirrored like `OspfInstance.redistribute_policy` (derived, read-only).
    #[serde(default)]
    #[garde(skip)]
    #[cli(hidden)]
    pub redistribute_policy: Option<String>,

    /// RFC 8362 Full mode: originate/consume the TLV-based extended LSAs
    /// (E-Router, E-Network, E-Link, E-Intra-Area-Prefix) instead of the
    /// RFC 5340 legacy set. Off by default; `#[serde(default)]` so configs
    /// saved before this field existed still load.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = Ospfv3InstanceExtendedLsa)]
    pub extended_lsa: bool,

    /// RFC 8362 Sparse mode: the RFC 5340 legacy LSAs carry topology and
    /// prefixes (so full-mode and legacy-only routers in the area still
    /// interoperate); E-LSAs from neighbors are merged into SPF. Mutually
    /// exclusive with `extended_lsa`. Off by default.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = Ospfv3InstanceExtendedLsaSparse, words = "extended-lsa-sparse")]
    pub extended_lsa_sparse: bool,

    /// RFC 5187 graceful restart: on a planned shutdown, send a Grace-LSA
    /// asking every `Full` neighbor to keep the adjacency (and this router's
    /// routes) for this many seconds while the daemon restarts. `None`
    /// (default) disables it. Helper mode needs no config — every instance
    /// always helps a restarting neighbor.
    // ponytail: capped at 1800s; RFC 5187 sets no ceiling, raise if asked.
    #[serde(default)]
    #[garde(range(min = 1, max = 1800))]
    #[cli(topic = Ospfv3InstanceGracefulRestart, words = "graceful-restart grace-period")]
    pub graceful_restart_grace_period: Option<u16>,

    /// RFC 5187 helper side: the longest grace period this router honours for
    /// a restarting neighbor, whatever the neighbor's Grace-LSA asks for
    /// (seconds, 1-3600). `None` means 1800. Helping always stops early on a
    /// topology change (strict LSA checking).
    #[serde(default)]
    #[garde(range(min = 1, max = 3600))]
    #[cli(topic = Ospfv3InstanceGracefulRestartHelperMaxGracePeriod, words = "graceful-restart helper max-grace-period")]
    pub graceful_restart_helper_max_grace_period: Option<u32>,

    /// RFC 6987 stub router for this many seconds (5-86400) after
    /// `nos-ospfv3d` starts: every transit and point-to-point link in its
    /// Router-LSA costs 65535, so traffic avoids the router while its routes
    /// converge; its own prefixes stay reachable. Takes effect on the next
    /// start, and is skipped after an RFC 5187 graceful restart. `None`
    /// (default) disables it, and ends a period that is still running.
    #[serde(default)]
    #[garde(range(min = 5, max = 86400))]
    #[cli(topic = Ospfv3InstanceMaxMetricOnStartup, words = "max-metric router-lsa on-startup")]
    pub max_metric_on_startup: Option<u32>,

    /// RFC 6987 stub router for this many seconds (1-3) when `nos-ospfv3d`
    /// stops (not on a graceful restart) before it exits, so traffic moves
    /// away first. At most 3s, inside `nos-watchdogd`'s 10s stop budget.
    /// `None` (default) disables it.
    #[serde(default)]
    #[garde(range(min = 1, max = 3))]
    #[cli(topic = Ospfv3InstanceMaxMetricOnShutdown, words = "max-metric router-lsa on-shutdown")]
    pub max_metric_on_shutdown: Option<u8>,

    /// RFC 6987 stub router until turned off: drains transit traffic before
    /// maintenance. Off by default.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = Ospfv3InstanceMaxMetricAdministrative, words = "max-metric router-lsa administrative")]
    pub max_metric_administrative: bool,

    /// LSDB overload limit (#1146): most LSAs not originated by this router
    /// that one store (area, AS scope, or one link's Link-LSAs) holds, 1 to
    /// 1000000. A new LSA past it is discarded and logged, never
    /// acknowledged; own and `MaxAge` LSAs do not count and no neighbor is
    /// reset. `None` means 100000.
    #[serde(default)]
    #[garde(range(min = 1, max = 1_000_000))]
    #[cli(topic = Ospfv3InstanceMaxLsa, words = "max-lsa")]
    pub max_lsa: Option<u32>,

    /// Reference bandwidth for the default link cost, Mbit/s, 1 to 4294967
    /// (as `OspfInstance.reference_bandwidth`): a link with no explicit
    /// profile `cost` costs `reference-bandwidth / link speed`, at least 1 and
    /// at most 65535; unknown speed costs 1. `None` means 10000 (10 Gbit/s).
    #[serde(default)]
    #[garde(range(min = 1, max = 4_294_967))]
    #[cli(topic = Ospfv3InstanceReferenceBandwidth, words = "reference-bandwidth")]
    pub reference_bandwidth: Option<u32>,

    /// RFC 5838 address family this instance routes: `ipv6-unicast`
    /// (default, instance IDs 0-31) or `ipv4-unicast` (instance IDs 64-95;
    /// every profile of the instance must then set one, and the AF-bit is
    /// set in its Hellos, DBDs and LSAs). IPv6/IPv4 multicast are not built.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = Ospfv3InstanceAddressFamily, words = "address-family")]
    pub address_family: Ospfv3AddressFamily,
}

/// An RFC 5838 §2.1 address family of an `Ospfv3Instance`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum Ospfv3AddressFamily {
    #[default]
    /// IPv6 unicast: the base `OSPFv3` AF, instance IDs 0 to 31.
    Ipv6Unicast,
    /// IPv4 unicast (RFC 5838): instance IDs 64 to 95.
    Ipv4Unicast,
}

impl Ospfv3AddressFamily {
    /// RFC 5838 §2.1's Instance ID range of this AF.
    pub const fn instance_ids(self) -> std::ops::RangeInclusive<u8> {
        match self {
            Ospfv3AddressFamily::Ipv6Unicast => 0..=31,
            Ospfv3AddressFamily::Ipv4Unicast => 64..=95,
        }
    }
}

/// Every profile's Instance ID (unset means 0) must lie in its instance's AF
/// range (RFC 5838 §2.1), so an IPv4-unicast instance needs an explicit one.
pub(crate) fn valid_address_families(instances: &[Ospfv3Instance]) -> garde::Result {
    for i in instances {
        if i.extended_lsa && i.extended_lsa_sparse {
            return Err(garde::Error::new(
                "extended-lsa and extended-lsa-sparse are mutually exclusive (RFC 8362 Full vs Sparse mode)",
            ));
        }
        if i.extended_lsa && i.address_family == Ospfv3AddressFamily::Ipv4Unicast {
            return Err(garde::Error::new(
                "extended-lsa (RFC 8362 Full mode) is not supported with an ipv4-unicast address-family; use extended-lsa-sparse",
            ));
        }
        let range = i.address_family.instance_ids();
        let bad = i
            .areas
            .iter()
            .flat_map(|a| &a.profiles)
            .any(|p| !range.contains(&p.instance_id.unwrap_or(0)));
        if bad {
            return Err(garde::Error::new(format!(
                "every profile's instance-id must be {}-{} for this instance's address-family (RFC 5838)",
                range.start(),
                range.end()
            )));
        }
    }
    Ok(())
}

/// The placeholder a new `Ospfv3Instance` starts from (`edit` on a missing one).
impl Default for Ospfv3Instance {
    fn default() -> Self {
        Ospfv3Instance {
            name: String::new(),
            router_id: Ipv4Addr::UNSPECIFIED,
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            extended_lsa: false,
            extended_lsa_sparse: false,
            graceful_restart_grace_period: None,
            graceful_restart_helper_max_grace_period: None,
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
            max_lsa: None,
            reference_bandwidth: None,
            address_family: Ospfv3AddressFamily::Ipv6Unicast,
        }
    }
}

/// No two areas within the same instance may share an `area_id` — mirrors
/// `ospf_instance::unique_area_ids` exactly.
fn unique_area_ids(areas: &[Ospfv3Area], router_id: Ipv4Addr) -> garde::Result {
    let mut seen: Vec<Ipv4Addr> = Vec::new();
    for a in areas {
        if seen.contains(&a.area_id) {
            return Err(garde::Error::new(
                "must not repeat an area id within the same ospfv3 instance",
            ));
        }
        seen.push(a.area_id);
        super::ospfv3_area::valid_area_settings(a)?;
        if a.virtual_links.iter().any(|v| v.router_id == router_id) {
            return Err(garde::Error::new(
                "a virtual link can't end at this instance's own router id",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use garde::Validate as _;

    use crate::schema::Config;

    use super::Ospfv3Instance;

    fn instance(name: &str) -> Ospfv3Instance {
        Ospfv3Instance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            extended_lsa: false,
            extended_lsa_sparse: false,
            graceful_restart_grace_period: None,
            graceful_restart_helper_max_grace_period: None,
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
            max_lsa: None,
            reference_bandwidth: None,
            address_family: crate::schema::Ospfv3AddressFamily::default(),
        }
    }

    fn config_with(instances: Vec<Ospfv3Instance>) -> Config {
        Config {
            ospfv3_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_instance_passes() {
        let cfg = config_with(vec![instance("default")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![instance("vrf-a"), instance("vrf-a")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_names_pass() {
        let cfg = config_with(vec![instance("vrf-a"), instance("vrf-b")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn sparse_and_full_extended_lsa_are_exclusive() {
        let with = |full, sparse| {
            let mut i = instance("o1");
            i.extended_lsa = full;
            i.extended_lsa_sparse = sparse;
            let cfg = config_with(vec![i]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(with(false, true));
        assert!(with(true, false));
        assert!(!with(true, true));
    }

    #[test]
    fn ipv4_unicast_refuses_full_extended_lsa() {
        let with = |full, sparse| {
            let mut i = instance("o1");
            i.address_family = super::Ospfv3AddressFamily::Ipv4Unicast;
            i.extended_lsa = full;
            i.extended_lsa_sparse = sparse;
            let cfg = config_with(vec![i]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(with(false, true));
        assert!(!with(true, false));
    }

    #[test]
    fn max_metric_ranges_are_enforced() {
        let with = |startup, shutdown| {
            let mut i = instance("o1");
            i.max_metric_on_startup = startup;
            i.max_metric_on_shutdown = shutdown;
            let cfg = Config {
                ospfv3_instances: vec![i],
                ..Default::default()
            };
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(with(Some(5), Some(1)));
        assert!(with(Some(86400), Some(3)));
        assert!(!with(Some(4), None));
        assert!(!with(None, Some(0)));
        assert!(!with(None, Some(4)));
    }
}
