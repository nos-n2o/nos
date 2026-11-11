use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use super::ospfv3_profile;
use super::{Config, Ospfv3Profile};
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
}

/// The placeholder a new `Ospfv3Area` starts from (`edit` on a missing one).
impl Default for Ospfv3Area {
    fn default() -> Self {
        Ospfv3Area {
            area_id: Ipv4Addr::UNSPECIFIED,
            profiles: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use garde::Validate as _;

    use crate::schema::{Config, Ospfv3Instance};

    use super::Ospfv3Area;

    fn area(area_id: &str) -> Ospfv3Area {
        Ospfv3Area {
            area_id: area_id.parse().unwrap(),
            profiles: Vec::new(),
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
    fn distinct_area_ids_within_instance_pass() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0"), area("0.0.0.1")])]);
        cfg.validate_with(&cfg).unwrap();
    }
}
