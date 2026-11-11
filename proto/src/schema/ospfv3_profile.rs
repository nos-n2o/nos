use garde::Validate;
use serde::{Deserialize, Serialize};

use super::ospf_profile::valid_crypto_keys;
use super::{Config, NetworkType, OspfCryptoAlgorithm, OspfCryptoKey};
use crate::validators::bfd_reference_valid;
use nos_proto_derive::Cli;

use super::sugar;

/// A named `OSPFv3` profile, declared inside an area (`Ospfv3Area.profiles`)
/// but referenced by bare name from any L3 attach point's `ospfv3_profile`
/// field (`Interface`/`Subinterface`/`BroadcastDomain`) — mirrors
/// `OspfProfile` exactly, except that `auth` is RFC 7166's authentication
/// trailer (crypto only, no simple-password mechanism exists for `OSPFv3`),
/// so it's a bare key list rather than an `OspfAuth` enum. Reuses
/// `OspfProfile`'s `HELLO_INTERVAL_DEFAULT`/`DEAD_INTERVAL_DEFAULT`/
/// `PRIORITY_DEFAULT`/`NetworkType` directly — those defaults and the
/// point-to-point/broadcast distinction are unchanged by RFC 5340.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct Ospfv3Profile {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_name(n, ctx))
    )]
    #[cli(key)]
    /// Profile name, unique within its area.
    pub name: String,

    /// `None` defaults to `OspfProfile::HELLO_INTERVAL_DEFAULT` (10s).
    #[garde(skip)]
    #[cli(topic = OspfProfileHelloInterval)]
    pub hello_interval: Option<u16>,

    /// `None` defaults to `OspfProfile::DEAD_INTERVAL_DEFAULT` (40s). When
    /// both this and `hello_interval` are set, this must be strictly
    /// greater — checked one level up on `Ospfv3Area.profiles`, mirroring
    /// `ospf_profile::valid_profile_timers` exactly.
    #[garde(skip)]
    #[cli(topic = OspfProfileDeadInterval)]
    pub dead_interval: Option<u16>,

    /// RFC 5340 §4.8 SPF metric. `None` defaults to `1`; `0` is rejected.
    #[garde(custom(|c: &Option<u16>, _ctx: &Config| valid_cost(*c)))]
    #[cli(topic = OspfProfileCost)]
    pub cost: Option<u16>,

    /// `None` defaults to `1`. Governs RFC 5340 (via RFC 2328 §9.4) DR/BDR
    /// election eligibility on a `Broadcast` attach point.
    #[garde(skip)]
    #[cli(topic = OspfProfilePriority)]
    pub priority: Option<u8>,

    /// `None` resolves to the attach point's own real interface MTU,
    /// falling back to 1500 if unavailable — mirrors `OspfProfile.mtu`.
    #[garde(skip)]
    #[cli(topic = OspfProfileMtu)]
    pub mtu: Option<u16>,

    /// RFC 2328 §10.6 (RFC 5340 §4.2.1): skip the Interface MTU check on a received DBD. By
    /// default a neighbor advertising an MTU larger than this link's is
    /// stuck in `ExStart`; set this to form the adjacency anyway.
    #[garde(skip)]
    #[serde(default)]
    #[cli(topic = OspfProfileMtuIgnore, words = "mtu-ignore enable", alias = "mtu-ignore")]
    pub mtu_ignore: bool,

    /// `None` resolves per attach point, exactly like `OspfProfile.network_type`.
    #[garde(skip)]
    #[cli(topic = OspfProfileNetworkType)]
    pub network_type: Option<NetworkType>,

    /// RFC 7166 authentication trailer keys; `None` means unauthenticated.
    /// `key_id` is the 16-bit Security Association ID. HMAC-SHA only — RFC
    /// 7166 §4.3 defines no MD5 option. Same rotation model as
    /// `OspfAuth::Crypto` (`is_current` signs, every key verifies).
    #[garde(custom(|a: &Option<Vec<OspfCryptoKey>>, ctx: &Config| valid_auth(a.as_deref(), ctx)))]
    #[serde(default)]
    #[cli(topic = Ospfv3ProfileAuth, render = sugar::render_ospfv3_auth, sugar(word = "crypto-key", with = sugar::ospfv3_crypto_key, topic = Ospfv3ProfileCryptoKey))]
    pub auth: Option<Vec<OspfCryptoKey>>,

    /// Name of a `BfdProfile` to run BFD with; `None` runs no BFD.
    /// Inert until `nos-bfdd` exists.
    #[serde(default)]
    #[garde(custom(|b: &Option<String>, ctx: &Config| bfd_reference_valid(b.as_ref(), ctx)))]
    #[cli(topic = BfdReference)]
    pub bfd: Option<String>,

    /// RFC 5340 §A.3.1 Instance ID (header byte 14) this profile's links send
    /// and accept: a received packet carrying any other value is dropped.
    /// `None` means 0. Limited to 0-31, RFC 5838 §2.1's IPv6-unicast range.
    #[garde(custom(|i: &Option<u8>, _ctx: &Config| valid_instance_id(*i)))]
    #[serde(default)]
    #[cli(topic = Ospfv3ProfileInstanceId)]
    pub instance_id: Option<u8>,
}

fn valid_instance_id(id: Option<u8>) -> garde::Result {
    match id {
        Some(i) if i > 31 => Err(garde::Error::new(
            "instance-id must be between 0 and 31 (RFC 5838 IPv6 unicast)",
        )),
        _ => Ok(()),
    }
}

fn valid_auth(keys: Option<&[OspfCryptoKey]>, cfg: &Config) -> garde::Result {
    let Some(keys) = keys else { return Ok(()) };
    valid_crypto_keys(keys, cfg)?;
    if keys.iter().any(|k| k.algorithm == OspfCryptoAlgorithm::Md5) {
        return Err(garde::Error::new(
            "ospfv3 authentication supports hmac-sha keys only (RFC 7166 has no md5)",
        ));
    }
    Ok(())
}

fn valid_cost(cost: Option<u16>) -> garde::Result {
    match cost {
        Some(0) => Err(garde::Error::new("cost must be between 1 and 65535")),
        _ => Ok(()),
    }
}

/// Profile names are unique across the whole config — mirrors
/// `ospf_profile::unique_name` exactly, over `ospfv3_instances` instead.
fn unique_name(name: &str, ctx: &Config) -> garde::Result {
    crate::validators::unique_name_in(
        name,
        ctx.ospfv3_instances
            .iter()
            .flat_map(|i| &i.areas)
            .flat_map(|a| &a.profiles)
            .map(|x| x.name.as_str()),
    )
}

/// Mirrors `ospf_profile::valid_profile_timers` exactly.
pub(crate) fn valid_profile_timers(profiles: &[Ospfv3Profile]) -> garde::Result {
    for p in profiles {
        if p.network_type == Some(NetworkType::PointToMultipoint) {
            return Err(garde::Error::new(
                "point-to-multipoint is not supported for OSPFv3",
            ));
        }
        if let (Some(hello), Some(dead)) = (p.hello_interval, p.dead_interval)
            && dead <= hello
        {
            return Err(garde::Error::new(
                "dead-interval must be greater than hello-interval when both are set",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use garde::Validate as _;

    use crate::schema::{Config, Ospfv3Area, Ospfv3Instance};

    use super::{NetworkType, OspfCryptoAlgorithm, OspfCryptoKey, Ospfv3Profile};

    fn profile(name: &str) -> Ospfv3Profile {
        Ospfv3Profile {
            bfd: None,
            name: name.to_string(),
            hello_interval: None,
            dead_interval: None,
            cost: None,
            priority: None,
            mtu: None,
            mtu_ignore: false,
            network_type: None,
            auth: None,
            instance_id: None,
        }
    }

    fn crypto_key(key_id: u16, algorithm: OspfCryptoAlgorithm, is_current: bool) -> OspfCryptoKey {
        OspfCryptoKey {
            key_id,
            algorithm,
            key: "secret".to_string(),
            is_current,
        }
    }

    fn validate_auth(keys: Vec<OspfCryptoKey>) -> garde::Result {
        let mut p = profile("p1");
        p.auth = Some(keys);
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        cfg.validate_with(&cfg)
            .map_err(|_| garde::Error::new("invalid"))
    }

    #[test]
    fn valid_crypto_keys_pass_including_key_id_above_255() {
        let sha = OspfCryptoAlgorithm::HmacSha256;
        validate_auth(vec![crypto_key(1, sha, true), crypto_key(2, sha, false)]).unwrap();
        validate_auth(vec![crypto_key(300, OspfCryptoAlgorithm::HmacSha1, true)]).unwrap();
        validate_auth(vec![crypto_key(
            u16::MAX,
            OspfCryptoAlgorithm::HmacSha512,
            true,
        )])
        .unwrap();
    }

    #[test]
    fn invalid_crypto_keys_fail() {
        let sha = OspfCryptoAlgorithm::HmacSha256;
        assert!(validate_auth(Vec::new()).is_err());
        assert!(validate_auth(vec![crypto_key(1, sha, true), crypto_key(1, sha, false)]).is_err());
        assert!(validate_auth(vec![crypto_key(1, sha, false)]).is_err());
        assert!(validate_auth(vec![crypto_key(1, sha, true), crypto_key(2, sha, true)]).is_err());
        assert!(validate_auth(vec![crypto_key(1, OspfCryptoAlgorithm::Md5, true)]).is_err());
        // Dangling label and empty secret.
        let sha1 = OspfCryptoAlgorithm::HmacSha1;
        let mut k = crypto_key(1, sha1, true);
        k.key = "nope".to_string();
        assert!(validate_auth(vec![k.clone()]).is_err());
    }

    fn area(area_id: &str, profiles: Vec<Ospfv3Profile>) -> Ospfv3Area {
        Ospfv3Area {
            area_id: area_id.parse().unwrap(),
            profiles,
        }
    }

    fn instance(name: &str, areas: Vec<Ospfv3Area>) -> Ospfv3Instance {
        Ospfv3Instance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
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
            admin: keystore(),
            ..Default::default()
        }
    }

    fn keystore() -> crate::schema::Admin {
        let key = |l: &str, s: &str| crate::schema::AdminKey {
            label: l.to_string(),
            secret: s.to_string(),
        };
        crate::schema::Admin {
            keys: vec![key("secret", "s3cr3t")],
        }
    }

    #[test]
    fn valid_profile_passes() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area("0.0.0.0", vec![profile("p1")])],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_name_within_same_area_fails() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area("0.0.0.0", vec![profile("p1"), profile("p1")])],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_name_across_instances_fails() {
        let cfg = config_with(vec![
            instance("r1", vec![area("0.0.0.0", vec![profile("p1")])]),
            instance("r2", vec![area("0.0.0.0", vec![profile("p1")])]),
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_names_pass() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area("0.0.0.0", vec![profile("p1"), profile("p2")])],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    fn profile_with_timers(
        name: &str,
        hello_interval: Option<u16>,
        dead_interval: Option<u16>,
    ) -> Ospfv3Profile {
        Ospfv3Profile {
            bfd: None,
            name: name.to_string(),
            hello_interval,
            dead_interval,
            cost: None,
            priority: None,
            mtu: None,
            mtu_ignore: false,
            network_type: None,
            auth: None,
            instance_id: None,
        }
    }

    #[test]
    fn dead_interval_greater_than_hello_interval_passes() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area(
                "0.0.0.0",
                vec![profile_with_timers("p1", Some(10), Some(40))],
            )],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dead_interval_not_greater_than_hello_interval_fails() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area(
                "0.0.0.0",
                vec![profile_with_timers("p1", Some(10), Some(10))],
            )],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn zero_cost_fails() {
        let mut p = profile("p1");
        p.cost = Some(0);
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn instance_id_range() {
        for (id, ok) in [(0, true), (31, true), (32, false)] {
            let mut p = profile("p1");
            p.instance_id = Some(id);
            let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
            assert_eq!(cfg.validate_with(&cfg).is_ok(), ok, "instance-id {id}");
        }
    }

    #[test]
    fn either_network_type_passes() {
        for network_type in [NetworkType::PointToPoint, NetworkType::Broadcast] {
            let mut p = profile("p1");
            p.network_type = Some(network_type);
            let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
            cfg.validate_with(&cfg).unwrap();
        }
    }

    #[test]
    fn point_to_multipoint_is_refused() {
        let mut p = profile("p1");
        p.network_type = Some(NetworkType::PointToMultipoint);
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
