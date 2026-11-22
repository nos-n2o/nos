use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use ipnet::Ipv4Net;

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

    /// RFC 3623 helper side: the longest grace period this router honours for
    /// a restarting neighbor, whatever the neighbor's Grace-LSA asks for
    /// (seconds, 1-3600). `None` means 1800. Helping always stops early on a
    /// topology change (strict LSA checking).
    #[serde(default)]
    #[garde(range(min = 1, max = 3600))]
    #[cli(topic = OspfInstanceGracefulRestartHelperMaxGracePeriod, words = "graceful-restart helper max-grace-period")]
    pub graceful_restart_helper_max_grace_period: Option<u32>,

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

    /// LSDB overload limit (#1146): most LSAs not originated by this router
    /// that one store (area, AS scope, or one link's Link-LSAs) holds, 1 to
    /// 1000000. A new LSA past it is discarded and logged, never
    /// acknowledged; own and `MaxAge` LSAs do not count and no neighbor is
    /// reset. `None` means 100000.
    #[serde(default)]
    #[garde(range(min = 1, max = 1_000_000))]
    #[cli(topic = OspfInstanceMaxLsa, words = "max-lsa")]
    pub max_lsa: Option<u32>,

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

    /// RFC 3630 traffic engineering: originate area-scope TE LSAs (opaque
    /// type 1): a Router Address LSA and a Link LSA per `Full`
    /// point-to-point or broadcast link. Advertisement only, no CSPF. Off by
    /// default.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfInstanceTrafficEngineering, words = "traffic-engineering")]
    pub traffic_engineering: bool,

    /// RFC 8665 segment routing: this router's SRGB and the Prefix-SIDs it
    /// advertises. Off by default.
    #[serde(default)]
    #[garde(custom(|s, ctx: &Config| valid_segment_routing(s, ctx)))]
    #[cli(topic = OspfInstanceSegmentRouting, words = "segment-routing")]
    pub segment_routing: SegmentRouting,

    /// RFC 7490 remote loop-free alternates: for a destination with no basic
    /// LFA, a backup that tunnels (IP-in-IP) to a PQ node's loopback. Also
    /// makes this router's routing table decapsulate IP-in-IP from any
    /// source, so it can be another router's PQ node — enable it on every
    /// router of the area. Off by default.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfInstanceRemoteLfa, words = "remote-lfa")]
    pub remote_lfa: bool,

    /// RFC 8405 SPF back-off timers; every field left unset keeps the RFC's
    /// recommended value. Re-read on every resync, no link restarts.
    #[serde(default)]
    #[garde(custom(|t, _ctx: &Config| valid_spf_throttle(t)))]
    #[cli(topic = OspfInstanceSpfThrottle, words = "spf-throttle")]
    pub spf_throttle: SpfThrottle,
}

/// First label of the SRGB when none is configured (the IANA/vendor
/// convention, clear of the VPN label allocator that starts at 1000).
pub const DEFAULT_SRGB_START: u32 = 16000;
/// Size of the SRGB when none is configured (16000-23999).
pub const DEFAULT_SRGB_RANGE: u32 = 8000;
/// Largest label an incoming MPLS packet may carry (`nos-ribd` refuses above).
pub const MAX_SRGB_LABEL: u32 = 1_048_574;

/// RFC 8665 segment routing of one OSPF instance (#1168): the router's SRGB
/// (a static label block, so every router can agree on it, RFC 8402) and the
/// Prefix-SIDs it originates. Only algorithm 0 (SPF).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct SegmentRouting {
    /// Advertise the SR-Algorithm and SID/Label Range TLVs in the Router
    /// Information LSA and the Prefix-SIDs below.
    #[serde(default)]
    #[cli(topic = OspfInstanceSegmentRoutingEnabled, words = "enabled")]
    pub enabled: bool,
    /// First label of the SRGB; `None` means 16000.
    #[serde(default)]
    #[cli(topic = OspfInstanceSegmentRoutingSrgbStart, words = "srgb start")]
    pub srgb_start: Option<u32>,
    /// Number of labels in the SRGB; `None` means 8000.
    #[serde(default)]
    #[cli(topic = OspfInstanceSegmentRoutingSrgbRange, words = "srgb range")]
    pub srgb_range: Option<u32>,
    /// Prefix-SIDs, keyed by host prefix.
    #[serde(default)]
    #[cli(topic = OspfInstanceSegmentRoutingPrefixSid, words = "prefix-sid")]
    pub prefix_sids: Vec<OspfPrefixSid>,
}

impl SegmentRouting {
    /// The effective SRGB as `(start, range)`.
    #[must_use]
    pub fn srgb(&self) -> (u32, u32) {
        (
            self.srgb_start.unwrap_or(DEFAULT_SRGB_START),
            self.srgb_range.unwrap_or(DEFAULT_SRGB_RANGE),
        )
    }
}

/// One RFC 8665 §5 Prefix-SID, keyed by its /32; the label other routers push
/// toward it is their view of our SRGB base plus `index`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct OspfPrefixSid {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// The host prefix (a /32, typically a loopback); the key.
    pub prefix: Ipv4Net,
    /// Index into the SRGB, below its range; unique among the SIDs.
    #[cli(topic = OspfPrefixSidIndex)]
    pub index: u32,
    /// NP-flag: the penultimate hop keeps the label instead of popping it
    /// (PHP is the default).
    #[serde(default)]
    #[cli(topic = OspfPrefixSidNoPhp, words = "no-php")]
    pub no_php: bool,
    /// E-flag: the penultimate hop swaps to explicit null. Needs `no-php`.
    #[serde(default)]
    #[cli(topic = OspfPrefixSidExplicitNull, words = "explicit-null")]
    pub explicit_null: bool,
}

/// SRGB inside the label space and clear of every `vpn.label`; Prefix-SIDs
/// /32, in range, no repeated prefix or index, `explicit-null` with `no-php`.
fn valid_segment_routing(s: &SegmentRouting, cfg: &Config) -> garde::Result {
    let (start, range) = s.srgb();
    if start < 16 || range == 0 || start.saturating_add(range - 1) > MAX_SRGB_LABEL {
        return Err(garde::Error::new(
            "the srgb must lie within labels 16 to 1048574",
        ));
    }
    let end = start + range - 1;
    if cfg
        .routing_tables
        .iter()
        .filter_map(|t| t.vpn.label)
        .any(|l| (start..=end).contains(&l))
    {
        return Err(garde::Error::new("the srgb covers a vpn label"));
    }
    for (i, p) in s.prefix_sids.iter().enumerate() {
        if p.prefix.prefix_len() != 32 {
            return Err(garde::Error::new("a prefix-sid prefix must be a /32"));
        }
        if p.index >= range {
            return Err(garde::Error::new(
                "a prefix-sid index must be inside the srgb",
            ));
        }
        if p.explicit_null && !p.no_php {
            return Err(garde::Error::new("explicit-null needs no-php"));
        }
        if s.prefix_sids[..i]
            .iter()
            .any(|o| o.prefix == p.prefix || o.index == p.index)
        {
            return Err(garde::Error::new(
                "prefix-sid prefixes and indexes must be unique",
            ));
        }
    }
    Ok(())
}

/// Per-instance RFC 8405 SPF throttle timers, milliseconds. `None` keeps the
/// default of `nos-ospfd` (initial 50, short 200, long 5000, holddown 10000,
/// time-to-learn 3000).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct SpfThrottle {
    /// Delay of the first change after a quiet period.
    #[serde(default)]
    #[cli(topic = OspfInstanceSpfThrottleInitial, words = "initial")]
    pub initial_ms: Option<u32>,
    /// Delay while changes keep arriving.
    #[serde(default)]
    #[cli(topic = OspfInstanceSpfThrottleShort, words = "short")]
    pub short_ms: Option<u32>,
    /// Delay once the churn outlasts `time_to_learn_ms`.
    #[serde(default)]
    #[cli(topic = OspfInstanceSpfThrottleLong, words = "long")]
    pub long_ms: Option<u32>,
    /// Time without a change that returns to the initial delay; non-zero.
    #[serde(default)]
    #[cli(topic = OspfInstanceSpfThrottleHolddown, words = "holddown")]
    pub holddown_ms: Option<u32>,
    /// How long the short delay lasts before the long one applies.
    #[serde(default)]
    #[cli(topic = OspfInstanceSpfThrottleTimeToLearn, words = "time-to-learn")]
    pub time_to_learn_ms: Option<u32>,
}

/// `initial <= short <= long` over the effective values (unset = default),
/// and a non-zero holddown.
fn valid_spf_throttle(t: &SpfThrottle) -> garde::Result {
    let (i, s, l) = (
        t.initial_ms.unwrap_or(50),
        t.short_ms.unwrap_or(200),
        t.long_ms.unwrap_or(5000),
    );
    if !(i <= s && s <= l) {
        return Err(garde::Error::new(
            "spf-throttle needs initial <= short <= long",
        ));
    }
    if t.holddown_ms == Some(0) {
        return Err(garde::Error::new("spf-throttle holddown must be above 0"));
    }
    Ok(())
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
            graceful_restart_helper_max_grace_period: None,
            prefix_suppression: false,
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
            max_lsa: None,
            host_router: false,
            traffic_engineering: false,
            segment_routing: SegmentRouting::default(),
            remote_lfa: false,
            redistribute_metric: None,
            redistribute_metric_type: None,
            spf_throttle: SpfThrottle::default(),
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

    use super::{OspfInstance, SegmentRouting, SpfThrottle};

    fn instance(name: &str) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
            graceful_restart_helper_max_grace_period: None,
            prefix_suppression: false,
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
            max_lsa: None,
            host_router: false,
            traffic_engineering: false,
            segment_routing: SegmentRouting::default(),
            remote_lfa: false,
            redistribute_metric: None,
            redistribute_metric_type: None,
            spf_throttle: SpfThrottle::default(),
        }
    }

    fn config_with(instances: Vec<OspfInstance>) -> Config {
        Config {
            ospf_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn spf_throttle_ordering_and_holddown_are_enforced() {
        let ok = |f: fn(&mut super::SpfThrottle)| {
            let mut i = instance("o1");
            f(&mut i.spf_throttle);
            let cfg = config_with(vec![i]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(ok(|t| t.initial_ms = Some(200)));
        assert!(!ok(|t| t.initial_ms = Some(201)));
        assert!(!ok(|t| t.long_ms = Some(100)));
        assert!(ok(|t| {
            t.short_ms = Some(10);
            t.initial_ms = Some(5);
        }));
        assert!(!ok(|t| t.holddown_ms = Some(0)));
        assert!(ok(|t| t.holddown_ms = Some(1)));
    }

    fn sid(p: &str, index: u32) -> super::OspfPrefixSid {
        super::OspfPrefixSid {
            prefix: p.parse().unwrap(),
            index,
            ..Default::default()
        }
    }

    #[test]
    fn segment_routing_rules() {
        let ok = |f: fn(&mut super::SegmentRouting), label: Option<u32>| {
            let mut i = instance("o1");
            f(&mut i.segment_routing);
            let mut cfg = config_with(vec![i]);
            if let Some(l) = label {
                cfg.routing_tables.push(crate::schema::RoutingTable {
                    name: "t".into(),
                    vpn: crate::schema::RoutingTableVpn {
                        label: Some(l),
                        ..Default::default()
                    },
                    ..Default::default()
                });
            }
            let r = cfg.validate_with(&cfg);
            r.is_ok() || !format!("{r:?}").contains("segment_routing")
        };
        assert!(ok(|_| {}, None));
        assert!(ok(
            |s| s.prefix_sids = vec![sid("1.1.1.1/32", 1), sid("2.2.2.2/32", 2)],
            None
        ));
        assert!(!ok(
            |s| s.prefix_sids = vec![sid("1.1.1.1/32", 1), sid("2.2.2.2/32", 1)],
            None
        ));
        assert!(!ok(
            |s| s.prefix_sids = vec![sid("1.1.1.1/32", 1), sid("1.1.1.1/32", 2)],
            None
        ));
        assert!(!ok(|s| s.prefix_sids = vec![sid("1.1.1.0/24", 1)], None));
        assert!(!ok(|s| s.prefix_sids = vec![sid("1.1.1.1/32", 8000)], None));
        assert!(!ok(
            |s| {
                let mut p = sid("1.1.1.1/32", 1);
                p.explicit_null = true;
                s.prefix_sids = vec![p];
            },
            None
        ));
        assert!(!ok(|s| s.srgb_start = Some(15), None));
        assert!(!ok(|s| s.srgb_range = Some(0), None));
        assert!(!ok(|s| s.srgb_start = Some(1_048_000), None));
        assert!(!ok(|_| {}, Some(16500)));
        assert!(ok(|_| {}, Some(1000)));
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
