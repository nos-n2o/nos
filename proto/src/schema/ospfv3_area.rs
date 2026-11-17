use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use ipnet::Ipv6Net;

use super::ospfv3_profile;
use super::{Config, OspfAreaType, Ospfv3Profile};
use nos_proto_derive::Cli;

/// One `OSPFv3` area within an `Ospfv3Instance`, keyed by its dotted-quad area
/// id — mirrors `OspfArea` exactly. Unique only within its owning instance,
/// enforced on the parent's `areas` field (`ospfv3_instance::unique_area_ids`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct Ospfv3Area {
    // Ipv4Addr is structurally valid by construction; uniqueness lives on
    // the owning Ospfv3Instance.areas field instead.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// Area id in dotted-quad form; 0.0.0.0 is the backbone.
    pub area_id: Ipv4Addr,

    #[garde(
        dive,
        custom(|profiles, _ctx: &Config| ospfv3_profile::valid_profile_timers(profiles))
    )]
    #[cli(topic = Ospfv3Profile)]
    /// Interface profiles declared in this area, referenced by an interface's `ospfv3` attachment.
    pub profiles: Vec<Ospfv3Profile>,

    /// RFC 5340 §4.4.3.3 address ranges, applied by an ABR to this area's own
    /// intra-area prefixes when summarizing them into its other areas: every
    /// covered prefix is suppressed, and an advertised range with at least
    /// one active component is sent as one Inter-Area-Prefix-LSA (metric =
    /// the largest component cost) and installed as a discard route on the
    /// ABR. Harmless on a router that is no ABR.
    #[serde(default)]
    #[garde(custom(|ranges, _ctx: &Config| valid_ranges(ranges)))]
    #[cli(topic = OspfAreaRange)]
    pub ranges: Vec<Ospfv3AreaRange>,

    /// RFC 5340 §4.4.3 / RFC 2328 §3.6 stub area (no AS-External-LSAs, E-bit
    /// clear) or totally stubby (an ABR also sends no Inter-Area-Prefix-LSA
    /// but its default). Every router on the area's links must agree, or
    /// their Hellos are dropped. The backbone can't be one; `Nssa` is not
    /// built for `OSPFv3` yet. Checked by `valid_area_settings`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaType)]
    pub area_type: OspfAreaType,

    /// The metric of the `::/0` default an ABR originates into a stub area
    /// (`None` means 1); only allowed on a stub area.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaStubDefaultCost)]
    pub stub_default_cost: Option<u16>,
}

/// `area_type`/`stub_default_cost` checks, run from the owning instance's
/// `areas` validator since the backbone rule is about the key.
pub(crate) fn valid_area_settings(area: &Ospfv3Area) -> garde::Result {
    if area.area_type.is_nssa() {
        return Err(garde::Error::new("nssa is not supported for ospfv3 yet"));
    }
    if area.area_type.is_stub() && area.area_id.is_unspecified() {
        return Err(garde::Error::new(
            "the backbone (0.0.0.0) can't be a stub area",
        ));
    }
    match area.stub_default_cost {
        Some(_) if !area.area_type.is_stub() => Err(garde::Error::new(
            "stub-default-cost is only allowed on a stub area",
        )),
        Some(0) => Err(garde::Error::new("stub-default-cost must be 1 or more")),
        _ => Ok(()),
    }
}

/// One RFC 5340 §4.4.3.3 area address range, keyed by `cidr`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct Ospfv3AreaRange {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// The summarised IPv6 prefix; the key.
    pub cidr: Ipv6Net,
    /// `DoNotAdvertise`: the covered prefixes are hidden from the other areas
    /// entirely. `false` (the default) advertises the range.
    #[serde(default)]
    #[cli(topic = OspfAreaRangeAdvertise)]
    pub not_advertise: bool,
}

/// Range cidrs are unique within an area (`ospf_area`'s rule).
fn valid_ranges(ranges: &[Ospfv3AreaRange]) -> garde::Result {
    for (i, r) in ranges.iter().enumerate() {
        if ranges[..i].iter().any(|o| o.cidr.trunc() == r.cidr.trunc()) {
            return Err(garde::Error::new(
                "range cidrs must be unique within an area",
            ));
        }
    }
    Ok(())
}

/// The placeholder a new `Ospfv3Area` starts from (`edit` on a missing one).
impl Default for Ospfv3Area {
    fn default() -> Self {
        Ospfv3Area {
            area_id: Ipv4Addr::UNSPECIFIED,
            profiles: Vec::new(),
            ranges: Vec::new(),
            area_type: OspfAreaType::Normal,
            stub_default_cost: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use garde::Validate as _;

    use crate::schema::{Config, Ospfv3Instance};

    use super::{Ospfv3Area, Ospfv3AreaRange};

    fn area(area_id: &str) -> Ospfv3Area {
        Ospfv3Area {
            area_id: area_id.parse().unwrap(),
            ..Default::default()
        }
    }

    fn instance(name: &str, areas: Vec<Ospfv3Area>) -> Ospfv3Instance {
        Ospfv3Instance {
            name: name.to_string(),
            router_id: "1.1.1.1".parse().unwrap(),
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

    fn config_with(instances: Vec<Ospfv3Instance>) -> Config {
        Config {
            ospfv3_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_area_passes() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0")])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_area_id_within_instance_fails() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0"), area("0.0.0.0")])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_range_cidr_fails() {
        let range = |c: &str| Ospfv3AreaRange {
            cidr: c.parse().unwrap(),
            not_advertise: false,
        };
        let mut a = area("0.0.0.1");
        a.ranges = vec![range("2001:db8::/32"), range("2001:db8:1::/48")];
        let cfg = config_with(vec![instance("r1", vec![a.clone()])]);
        cfg.validate_with(&cfg).unwrap();
        a.ranges.push(range("2001:db8::/32"));
        let cfg = config_with(vec![instance("r1", vec![a])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn stub_settings_are_checked() {
        use crate::schema::OspfAreaType;
        let check = |a: Ospfv3Area| {
            let cfg = config_with(vec![instance("r1", vec![a])]);
            cfg.validate_with(&cfg).is_ok()
        };
        let mut a = area("0.0.0.1");
        a.area_type = OspfAreaType::TotallyStubby;
        a.stub_default_cost = Some(5);
        assert!(check(a.clone()));
        a.stub_default_cost = Some(0);
        assert!(!check(a.clone()));
        a.stub_default_cost = None;
        a.area_type = OspfAreaType::Nssa;
        assert!(!check(a.clone()));
        let mut b = area("0.0.0.0");
        b.area_type = OspfAreaType::Stub;
        assert!(!check(b));
        let mut c = area("0.0.0.1");
        c.stub_default_cost = Some(5);
        assert!(!check(c));
    }

    #[test]
    fn distinct_area_ids_within_instance_pass() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0"), area("0.0.0.1")])]);
        cfg.validate_with(&cfg).unwrap();
    }
}
