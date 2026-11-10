use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::{Config, OspfArea};
use nos_proto_derive::Cli;

/// A named OSPF instance. Basic configuration only today — `router_id`, the
/// routing-table (VRF) association mirroring `BgpInstance`'s own minimal
/// shape, and `areas` (dotted-quad-keyed, see `OspfArea`). No interfaces
/// beyond what a nested area's profiles can be attached to yet, and no wire
/// protocol — this is a config-only skeleton, see `docs/protocols/ospf-internals.md`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
#[allow(clippy::struct_excessive_bools)] // one independent RFC knob per flag
pub struct OspfInstance {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.ospf_instances, |i| &i.name))
    )]
    #[cli(key)]
    /// Instance name, 1 to 64 characters (letters, digits, `_`, `-`), unique among `OSPFv2` instances.
    pub name: String,

    // Ipv4Addr is structurally valid by construction; no additional garde rule needed.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(topic = OspfInstanceRouterId)]
    /// OSPF router id (RFC 2328 §C.1), written as a dotted-quad.
    pub router_id: Ipv4Addr,

    /// This instance's OSPF areas, keyed by `area_id` — see `OspfArea`.
    #[garde(dive, custom(|areas, ctx: &Config| unique_area_ids(areas, self.router_id, ctx)))]
    #[cli(topic = OspfArea)]
    pub areas: Vec<OspfArea>,

    /// The name of the `RoutingTable` that claims this instance (i.e. the
    /// VRF it belongs to), mirrored from that table's `ospf_instance` field.
    /// Derived and read-only: never set by any `OspfInstanceOp`, recomputed
    /// by `nos-config` (`crate::derive::sync_routing_table_refs`) on every
    /// commit and on load, so an operator only ever edits the one
    /// authoritative reference (`RoutingTable.ospf_instance`). `nos-ospfd`
    /// reads this directly to resolve its own VRF without scanning every
    /// routing table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    #[cli(hidden)]
    pub routing_table: Option<String>,

    /// The name of the RPL policy filtering routes redistributed into this
    /// instance, mirrored from the owning `RoutingTable.redistribute.policy`
    /// (only when `redistribute.to == Ospf`). Derived and read-only, exactly
    /// like `routing_table` above: never set by any `OspfInstanceOp`,
    /// recomputed by `nos-config` (`crate::derive::sync_routing_table_refs`)
    /// on every commit and on load. `nos-ospfd` reads this directly to
    /// resolve its own redistribution policy without scanning every routing
    /// table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    #[cli(hidden)]
    pub redistribute_policy: Option<String>,

    /// `RoutingTable.redistribute.metric` mirrored like `redistribute_policy`
    /// (derived, read-only, hidden): the external metric `nos-ospfd` puts in
    /// the Type-5/Type-7 LSAs it originates (`None` = 20).
    #[serde(default)]
    #[garde(skip)]
    #[cli(hidden)]
    pub redistribute_metric: Option<u32>,

    /// `RoutingTable.redistribute.metric_type` mirrored like
    /// `redistribute_metric` (`None` = 1).
    #[serde(default)]
    #[garde(skip)]
    #[cli(hidden)]
    pub redistribute_metric_type: Option<u8>,

    /// RFC 3623 graceful restart: on a planned shutdown, send a Grace-LSA
    /// asking every `Full` neighbor to keep the adjacency (and this router's
    /// routes) for this many seconds while the daemon restarts. `None`
    /// (default) disables it. Helper mode needs no config — every instance
    /// always helps a restarting neighbor.
    // ponytail: capped at 1800s; RFC 3623 sets no ceiling, raise if asked.
    #[serde(default)]
    #[garde(range(min = 1, max = 1800))]
    #[cli(topic = OspfInstanceGracefulRestart, words = "graceful-restart grace-period")]
    pub graceful_restart_grace_period: Option<u16>,

    /// RFC 6860 prefix suppression: hide transit-only networks. Leaves every
    /// point-to-point link's subnet out of this router's Router-LSA and gives
    /// the Network-LSA it originates as DR a /32 mask, so other routers
    /// install no route to them. Loopbacks stay advertised. Off by default;
    /// `#[serde(default)]` so configs saved before this field existed still
    /// load.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfInstancePrefixSuppression)]
    pub prefix_suppression: bool,

    /// RFC 6987 stub router for this many seconds (5-86400) after
    /// `nos-ospfd` starts: every transit link in its Router-LSA costs 65535,
    /// so traffic avoids the router while its routes converge; its own
    /// prefixes stay reachable. Takes effect on the next start, and is
    /// skipped after an RFC 3623 graceful restart. `None` (default) disables
    /// it, and ends a period that is still running.
    #[serde(default)]
    #[garde(range(min = 5, max = 86400))]
    #[cli(topic = OspfInstanceMaxMetricOnStartup, words = "max-metric router-lsa on-startup")]
    pub max_metric_on_startup: Option<u32>,

    /// RFC 6987 stub router for this many seconds (1-3) when `nos-ospfd`
    /// stops (not on a graceful restart), before it withdraws its LSAs, so
    /// traffic moves away first. At most 3s: that plus the 6s withdrawal fits
    /// `nos-watchdogd`'s 10s stop budget. `None` (default) disables it.
    #[serde(default)]
    #[garde(range(min = 1, max = 3))]
    #[cli(topic = OspfInstanceMaxMetricOnShutdown, words = "max-metric router-lsa on-shutdown")]
    pub max_metric_on_shutdown: Option<u8>,

    /// RFC 6987 stub router until turned off — drains transit traffic before
    /// maintenance. Off by default.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfInstanceMaxMetricAdministrative, words = "max-metric router-lsa administrative")]
    pub max_metric_administrative: bool,

    /// RFC 8770 host router: sets the H-bit in this router's Router-LSA so
    /// the rest of the area never routes transit traffic through it, and
    /// advertises its transit links at 65535 for routers that don't honour
    /// the bit. Its own prefixes stay reachable. Refused with a
    /// `redistribute … to ospf` rule on its routing table (a host router is
    /// no ASBR). Off by default.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfInstanceHostRouter, words = "host-router")]
    pub host_router: bool,

    /// RFC 7490 remote loop-free alternates: for a destination with no basic
    /// LFA, a backup that tunnels (IP-in-IP) to a PQ node's loopback. Also
    /// makes this router's routing table decapsulate IP-in-IP from any
    /// source, so it can be another router's PQ node — enable it on every
    /// router of the area. Off by default.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfInstanceRemoteLfa, words = "remote-lfa")]
    pub remote_lfa: bool,
}

/// The placeholder a new `OspfInstance` starts from (`edit` on a missing one).
impl Default for OspfInstance {
    fn default() -> Self {
        OspfInstance {
            name: String::new(),
            router_id: Ipv4Addr::UNSPECIFIED,
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
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
}

/// No two areas within the same instance may share an `area_id` — mirrors
/// `static_routing_instance::unique_subnets`. Scoped to `self.areas` only
/// (per-instance, not global — unlike `OspfProfile.name`).
fn unique_area_ids(areas: &[OspfArea], router_id: Ipv4Addr, cfg: &Config) -> garde::Result {
    let mut seen: Vec<Ipv4Addr> = Vec::new();
    for a in areas {
        if seen.contains(&a.area_id) {
            return Err(garde::Error::new(
                "must not repeat an area id within the same ospf instance",
            ));
        }
        seen.push(a.area_id);
        super::ospf_area::valid_area_settings(a, cfg)?;
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

    use super::OspfInstance;

    fn instance(name: &str) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
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

    fn config_with(instances: Vec<OspfInstance>) -> Config {
        Config {
            ospf_instances: instances,
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
    fn max_metric_ranges_are_enforced() {
        let with = |startup, shutdown| {
            let mut i = instance("o1");
            i.max_metric_on_startup = startup;
            i.max_metric_on_shutdown = shutdown;
            let cfg = config_with(vec![i]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(with(Some(5), Some(1)));
        assert!(with(Some(86400), Some(3)));
        assert!(!with(Some(4), None));
        assert!(!with(Some(86401), None));
        assert!(!with(None, Some(0)));
        assert!(!with(None, Some(4)));
    }

    #[test]
    fn prefix_suppression_defaults_off_when_absent() {
        let i: OspfInstance = serde_json::from_str(
            r#"{"name":"o1","router_id":"1.1.1.1","areas":[],"routing_table":null,"redistribute_policy":null}"#,
        )
        .unwrap();
        assert!(!i.prefix_suppression);
    }
}
