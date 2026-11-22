//! Seamless BFD reflector configuration (RFC 7880/7881): `Config.sbfd_reflector`.
//! The initiator side is a `BfdProfile` with `mode sbfd`.

use std::net::Ipv4Addr;

use ipnet::IpNet;
use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

/// The S-BFD reflector: answers probes whose Your Discriminator is one of
/// `discriminators`, on UDP 7784 in every routing table's VRF. Off while the
/// list is empty. Keeps no per-initiator state.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct SbfdReflector {
    /// Each an S-BFD discriminator (RFC 7880 §4.1), written as an IPv4
    /// address, the 32 bits of the value (`10.0.0.1` is 167772161).
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    #[cli(topic = SbfdReflectorDiscriminator, words = "discriminator")]
    pub discriminators: Vec<Ipv4Addr>,

    /// RFC 7881 §7 source filtering: when not empty only probes from these
    /// prefixes are answered. Empty accepts every non-martian source.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    #[cli(topic = SbfdReflectorAllowFrom, words = "allow-from")]
    #[cfg_attr(feature = "arbitrary", arbitrary(with = crate::arbitrary_support::vec_ip_net))]
    pub allow_from: Vec<IpNet>,
}

impl SbfdReflector {
    /// Commit-time validation (`Config.sbfd_reflector`'s `garde` custom check).
    pub(crate) fn check(&self) -> garde::Result {
        for (i, d) in self.discriminators.iter().enumerate() {
            if d.is_unspecified() {
                return Err(garde::Error::new(
                    "an S-BFD reflector discriminator must not be 0",
                ));
            }
            if self.discriminators[..i].contains(d) {
                return Err(garde::Error::new(format!(
                    "sbfd reflector discriminator {d} is listed twice"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Config;
    use garde::Validate;

    fn ok(discriminators: &[&str]) -> bool {
        let c = Config {
            sbfd_reflector: SbfdReflector {
                discriminators: discriminators.iter().map(|d| d.parse().unwrap()).collect(),
                allow_from: vec![],
            },
            ..Default::default()
        };
        c.validate_with(&c).is_ok()
    }

    #[test]
    fn discriminators_are_nonzero_and_unique() {
        assert!(ok(&[]));
        assert!(ok(&["10.0.0.1", "10.0.0.2"]));
        assert!(!ok(&["0.0.0.0"]));
        assert!(!ok(&["10.0.0.1", "10.0.0.1"]));
    }

    #[test]
    fn old_config_without_the_section_loads() {
        let mut v = serde_json::to_value(Config::default()).unwrap();
        v.as_object_mut().unwrap().remove("sbfd_reflector");
        let c: Config = serde_json::from_value(v).unwrap();
        assert_eq!(c.sbfd_reflector, SbfdReflector::default());
    }
}
