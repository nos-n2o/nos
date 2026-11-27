//! Seamless BFD reflector configuration (RFC 7880/7881): `Config.sbfd_reflector`.
//! The initiator side is a `BfdProfile` with `mode sbfd`.

use std::net::Ipv4Addr;

use ipnet::IpNet;
use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

use crate::schema::{BfdAuth, BfdAuthMethod};

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

    /// RFC 7880 §11: keys the reflector verifies an authenticated probe
    /// with (picked by Auth Key ID) and signs its reply with. Empty: A-bit
    /// probes are discarded. Unsigned probes are still answered. Keys are
    /// labels of the admin keystore, never inline secrets.
    #[serde(default)]
    #[cli(topic = SbfdReflectorAuth, words = "auth")]
    pub auth: Vec<SbfdReflectorKey>,
}

/// One key of the S-BFD reflector: a `BfdAuth` keyed by its Auth Key ID
/// (a list needs a key; `BfdAuth` in a profile is a single value).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct SbfdReflectorKey {
    /// Auth Key ID carried in each packet (RFC 5880 section 4.2/4.3); the list key.
    #[cli(key)]
    pub key_id: u8,
    /// Mechanism, which fixes the `AuthType` on the wire.
    #[cli(topic = SbfdReflectorAuth)]
    pub method: BfdAuthMethod,
    /// Label of the admin key holding the shared secret.
    #[cli(topic = SbfdReflectorAuth)]
    pub key: String,
}

impl SbfdReflectorKey {
    /// The same key as a profile's `BfdAuth`.
    #[must_use]
    pub fn as_auth(&self) -> BfdAuth {
        BfdAuth {
            key_id: self.key_id,
            method: self.method,
            key: self.key.clone(),
        }
    }
}

impl SbfdReflector {
    /// Commit-time validation (`Config.sbfd_reflector`'s `garde` custom check).
    pub(crate) fn check(&self, cfg: &crate::schema::Config) -> garde::Result {
        for (i, a) in self.auth.iter().enumerate() {
            super::bfd_profile::valid_auth(Some(&a.as_auth()), cfg)?;
            if self.auth[..i].iter().any(|b| b.key_id == a.key_id) {
                return Err(garde::Error::new(format!(
                    "sbfd reflector auth key id {} is listed twice",
                    a.key_id
                )));
            }
        }
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
                auth: vec![],
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

    #[test]
    fn auth_keys_must_exist_and_have_unique_ids() {
        let a = |id: u8, label: &str| SbfdReflectorKey {
            key_id: id,
            key: label.into(),
            ..Default::default()
        };
        let cfg = |auth: Vec<SbfdReflectorKey>, keys: bool| {
            let mut c = Config::default();
            c.sbfd_reflector.auth = auth;
            if keys {
                c.admin.keys = vec![crate::schema::AdminKey {
                    label: "k".into(),
                    secret: "kkk".into(),
                }];
            }
            c
        };
        let valid = |c: Config| c.validate_with(&c).is_ok();
        assert!(valid(cfg(vec![a(1, "k"), a(2, "k")], true)));
        assert!(!valid(cfg(vec![a(1, "nope")], true)), "dangling label");
        assert!(
            !valid(cfg(vec![a(1, "k"), a(1, "k")], true)),
            "duplicate key id"
        );
        assert!(
            !valid(cfg(vec![a(1, "k")], false)),
            "referenced key deleted"
        );
    }

    #[test]
    fn auth_round_trips_and_defaults_empty() {
        let r = SbfdReflector {
            auth: vec![SbfdReflectorKey {
                key_id: 3,
                key: "k".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let back: SbfdReflector =
            serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        let old: SbfdReflector =
            serde_json::from_str(r#"{"discriminators":[],"allow_from":[]}"#).unwrap();
        assert_eq!(old.auth.len(), 0);
    }
}
