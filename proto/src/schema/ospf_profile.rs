use garde::Validate;
use serde::{Deserialize, Serialize};

use super::Config;
use crate::validators::bfd_reference_valid;
use nos_proto_derive::Cli;

use super::sugar;

/// This profile's own proposed Hello interval when left unset. RFC 2328
/// Appendix C.3's point-to-point/broadcast default — the only network type
/// this NOS models today (see `docs/protocols/ospf-internals.md`).
pub const HELLO_INTERVAL_DEFAULT: u16 = 10;

/// This profile's own proposed router dead interval when left unset. RFC
/// 2328 Appendix C.3's point-to-point/broadcast default.
pub const DEAD_INTERVAL_DEFAULT: u16 = 40;

/// This profile's own Router Priority when left unset. RFC 2328 Appendix
/// C.3's typical default. `0` is a legal, meaningful value too — it means
/// "never eligible to become DR/BDR" (see `ospf::election`) — so this is
/// only a default, never a floor.
pub const PRIORITY_DEFAULT: u8 = 1;

/// Which RFC 2328 network type an attach point using this profile runs.
/// `OspfProfile.network_type` is `Option` — see its doc comment for how an
/// unset value is resolved.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum NetworkType {
    /// Point-to-point link: no DR election.
    PointToPoint,
    /// Broadcast network: DR/BDR election.
    Broadcast,
    /// RFC 2328 §9.5: multicast Hello, no DR/BDR, one adjacency per
    /// discovered neighbor. `OSPFv2` only (rejected on an `Ospfv3Profile`).
    PointToMultipoint,
}

/// A profile's own authentication — RFC 2328 Appendix D. Mutually exclusive
/// mechanisms, mirroring `BgpAuth`'s exact shape (`schema::bgp_peer_group`).
/// Keys are labels of `Config.admin` keystore entries, never inline secrets.
/// `OspfProfile.auth == None` is RFC 2328's `AuType` 0 (Null) — no separate variant needed for it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum OspfAuth {
    /// RFC 2328 Appendix D.2 — a single up-to-8-byte plaintext password,
    /// carried directly in the OSPF header's 8-byte Authentication field.
    Simple {
        /// Label of the admin key holding the password (at most 8 bytes).
        key: String,
    },
    /// RFC 2328 Appendix D.3 / RFC 5709 — one or more keys, supporting
    /// rotation via `key_id`/`is_current`, mirroring `BgpAoKey`.
    Crypto {
        /// The keychain; `is_current` selects the signing key, the rest allow rotation.
        keys: Vec<OspfCryptoKey>,
    },
}

/// One cryptographic auth key, shared by `OspfProfile.auth` (RFC 2328 D.3)
/// and `Ospfv3Profile.auth` (RFC 7166). `key_id` is the wire Key ID — 16
/// bits, RFC 7166's Security Association ID width; RFC 7474's `AuType` 3 Key
/// ID is 32 bits, but RFC 2328's classic `AuType` 2 field is one octet, so
/// `valid_profile_timers` caps a non-extended `OSPFv2` key at 255 (the type
/// itself doesn't). `is_current` marks the key actively signing outgoing
/// packets (exactly one key must have this set) — every configured key is
/// still accepted on receive, looked up by the wire's own Key ID (RFC 2328
/// D.5), which is how graceful key rollover works without dropping the
/// adjacency.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
#[cli(no_default)]
pub struct OspfCryptoKey {
    #[cli(key)]
    /// Key id carried in the authentication trailer; the list key.
    pub key_id: u16,
    #[cli(topic = OspfProfileCryptoKey)]
    /// HMAC algorithm of this key.
    pub algorithm: OspfCryptoAlgorithm,
    #[cli(topic = OspfProfileCryptoKey)]
    /// Label of the admin key holding the shared secret.
    pub key: String,
    #[cli(topic = OspfProfileCryptoKey)]
    /// Whether this key signs outgoing packets.
    pub is_current: bool,
}

/// RFC 2328 Appendix D's original Cryptographic authentication (plain MD5)
/// plus RFC 5709's HMAC-SHA extension. The wire's `AuType` is `2` for all
/// five — there's no separate "algorithm" field on the wire, so `key_id`
/// alone must unambiguously determine which algorithm a receiver uses.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum OspfCryptoAlgorithm {
    /// Keyed MD5 (RFC 2328 Appendix D.3).
    Md5,
    /// HMAC-SHA-1 (RFC 5709).
    HmacSha1,
    /// HMAC-SHA-256 (RFC 5709).
    HmacSha256,
    /// HMAC-SHA-384 (RFC 5709).
    HmacSha384,
    /// HMAC-SHA-512 (RFC 5709).
    HmacSha512,
}

/// Maximum auth secret length this NOS accepts — mirrors
/// `bgp_peer_group::MAX_AUTH_KEY_LEN`'s role (no RFC-mandated cap; HMAC
/// itself accepts any key length).
pub(crate) const MAX_AUTH_KEY_LEN: usize = 80;

/// RFC 2328 Appendix D.3's classic `AuType` 2 Key ID is one octet on the
/// wire; only RFC 7474's `AuType` 3 (32-bit) and RFC 7166's SA ID (16-bit)
/// can carry more.
const CLASSIC_KEY_ID_MAX: u16 = 255;

/// The checks every crypto key list shares between `OspfAuth::Crypto` and
/// `Ospfv3Profile.auth`: non-empty, unique ids, key length, exactly one
/// current key.
pub(crate) fn valid_crypto_keys(keys: &[OspfCryptoKey], cfg: &Config) -> garde::Result {
    if keys.is_empty() {
        return Err(garde::Error::new(
            "crypto auth must have at least one key (or be cleared)",
        ));
    }
    let mut seen_key_ids: Vec<u16> = Vec::new();
    let mut current_count = 0;
    for key in keys {
        valid_key_ref(&key.key, cfg, MAX_AUTH_KEY_LEN, "crypto key")?;
        if seen_key_ids.contains(&key.key_id) {
            return Err(garde::Error::new(
                "crypto key-id must be unique within a profile",
            ));
        }
        seen_key_ids.push(key.key_id);
        if key.is_current {
            current_count += 1;
        }
    }
    if current_count != 1 {
        return Err(garde::Error::new(
            "crypto auth must have exactly one current key",
        ));
    }
    Ok(())
}

/// Simple password is a real 8-byte wire field (RFC 2328 D.2), not just a
/// convention.
const SIMPLE_PASSWORD_MAX_LEN: usize = 8;

/// The referenced admin secret must exist and be 1..=`max` bytes long.
fn valid_key_ref(label: &str, cfg: &Config, max: usize, what: &str) -> garde::Result {
    match cfg.key(label) {
        None => Err(garde::Error::new(format!(
            "{what} references unknown admin key '{label}'"
        ))),
        Some(s) if s.is_empty() || s.len() > max => Err(garde::Error::new(format!(
            "admin key '{label}' must be 1 to {max} bytes long to be used as a {what}"
        ))),
        Some(_) => Ok(()),
    }
}

pub(crate) fn valid_auth(auth: Option<&OspfAuth>, cfg: &Config) -> garde::Result {
    match auth {
        None => Ok(()),
        Some(OspfAuth::Simple { key }) => {
            valid_key_ref(key, cfg, SIMPLE_PASSWORD_MAX_LEN, "simple password")
        }
        Some(OspfAuth::Crypto { keys }) => valid_crypto_keys(keys, cfg),
    }
}

/// A named OSPF profile, declared inside an area (`OspfArea.profiles`) but
/// referenced by bare name from any L3 attach point's `ospf_profile` field
/// (`Interface`/`Subinterface`/`BroadcastDomain`) with no instance/area
/// qualifier — so, like `BgpPeerGroup.name`, its uniqueness is enforced
/// globally across the whole config, not just within its owning area.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct OspfProfile {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_name(n, ctx))
    )]
    #[cli(key)]
    /// Profile name, unique within its area.
    pub name: String,

    /// `None` defaults to `HELLO_INTERVAL_DEFAULT` (10s).
    #[garde(skip)]
    #[cli(topic = OspfProfileHelloInterval)]
    pub hello_interval: Option<u16>,

    /// `None` defaults to `DEAD_INTERVAL_DEFAULT` (40s). When both this and
    /// `hello_interval` are set, this must be strictly greater than
    /// `hello_interval` — checked one level up, on `OspfArea.profiles`,
    /// since garde's per-field `custom` closures can't see a sibling field
    /// (see `ospf_area.rs`, mirrors `bgp_peer_group`'s identical
    /// hold-time/keepalive-interval pattern).
    #[garde(skip)]
    #[cli(topic = OspfProfileDeadInterval)]
    pub dead_interval: Option<u16>,

    /// Interface cost, in the usual OSPF sense (lower is preferred by
    /// SPF). `None` defaults to `1` — a real behavioral consumer:
    /// `ospf::link::originate::router_lsa_links`/`originate_router_lsas` use it as
    /// this link's RFC 2328 §16 metric, and `ospf::spf::compute` sums it
    /// along the Dijkstra path. `0` is rejected (not a valid OSPF cost).
    #[garde(custom(|c: &Option<u16>, _ctx: &Config| valid_cost(*c)))]
    #[cli(topic = OspfProfileCost)]
    pub cost: Option<u16>,

    /// `None` defaults to `PRIORITY_DEFAULT` (1). Governs RFC 2328 §9.4
    /// DR/BDR election eligibility on a `Broadcast` attach point; sent on
    /// the wire (but functionally inert) on a `PointToPoint` one too.
    #[garde(skip)]
    #[cli(topic = OspfProfilePriority)]
    pub priority: Option<u8>,

    /// `None` resolves to the attach point's own real interface MTU (queried
    /// from `nos-interfaced`), falling back to 1500 if unavailable.
    /// Overrides what OSPF *believes* this link's MTU is — for the wire's
    /// `DbdPacket.interface_mtu` field and DBD pagination sizing — independent
    /// of the interface's real kernel MTU (mirrors real OSPF implementations'
    /// `mtu-bytes`-style override). See `docs/protocols/ospf-internals.md`'s "LSA exchange and the LSDB".
    #[garde(skip)]
    #[cli(topic = OspfProfileMtu)]
    pub mtu: Option<u16>,

    /// RFC 2328 §10.6: skip the Interface MTU check on a received DBD. By
    /// default a neighbor advertising an MTU larger than this link's is
    /// stuck in `ExStart`; set this to form the adjacency anyway.
    #[garde(skip)]
    #[serde(default)]
    #[cli(topic = OspfProfileMtuIgnore, words = "mtu-ignore enable", alias = "mtu-ignore")]
    pub mtu_ignore: bool,

    /// `None` resolves per attach point: a `Subinterface`/loopback
    /// `Interface` attach point defaults to `PointToPoint`, a
    /// `BroadcastDomain` one defaults to `Broadcast` — resolved by
    /// `ospf::reconcile`, not here, since one profile may be referenced by
    /// attach points of different kinds at once. Setting this explicitly
    /// overrides that default per attach point (e.g. forcing
    /// point-to-point behavior on a `BroadcastDomain` attach point, or
    /// vice versa) — never validated against the attach point's own kind,
    /// matching real OSPF's own allowance for this.
    #[garde(skip)]
    #[cli(topic = OspfProfileNetworkType)]
    pub network_type: Option<NetworkType>,

    /// `None` is RFC 2328 `AuType` 0 (Null) — no authentication.
    #[garde(custom(|a: &Option<OspfAuth>, ctx: &Config| valid_auth(a.as_ref(), ctx)))]
    #[cli(topic = OspfProfileAuth, render = sugar::render_ospf_auth, sugar(word = "simple-password", with = sugar::simple_password, topic = OspfProfileSimplePassword), sugar(word = "crypto-key", with = sugar::ospf_crypto_key, topic = OspfProfileCryptoKey))]
    pub auth: Option<OspfAuth>,

    /// Name of a `BfdProfile` to run BFD with; `None` runs no BFD.
    /// Inert until `nos-bfdd` exists.
    #[serde(default)]
    #[garde(custom(|b: &Option<String>, ctx: &Config| bfd_reference_valid(b.as_ref(), ctx)))]
    #[cli(topic = BfdReference)]
    pub bfd: Option<String>,

    /// RFC 7474: sign with `AuType` 3 — a 64-bit (persisted boot count :
    /// counter) sequence number and a digest bound to the IP source address —
    /// closing the replay window across router restarts. Only valid with
    /// `Crypto` auth using HMAC-SHA keys (no MD5); both ends of a link must
    /// agree, since `AuType` 3 and 2 don't interoperate. Checked one level
    /// up in `valid_profile_timers`, since it needs the sibling `auth`.
    #[garde(skip)]
    #[serde(default)]
    #[cli(topic = OspfProfileExtendedSequenceNumbers, words = "extended-sequence-numbers enable", alias = "extended-sequence-numbers")]
    pub extended_sequence_numbers: bool,
}

fn valid_cost(cost: Option<u16>) -> garde::Result {
    match cost {
        Some(0) => Err(garde::Error::new("cost must be between 1 and 65535")),
        _ => Ok(()),
    }
}

/// Profile names are unique across the whole config, not just within the
/// owning area — mirrors `bgp_peer_group::unique_name`, flattened one level
/// further (`ospf_instances -> areas -> profiles` instead of
/// `bgp_instances -> peer_groups`).
fn unique_name(name: &str, ctx: &Config) -> garde::Result {
    crate::validators::unique_name_in(
        name,
        ctx.ospf_instances
            .iter()
            .flat_map(|i| &i.areas)
            .flat_map(|a| &a.profiles)
            .map(|x| x.name.as_str()),
    )
}

/// Mirrors `bgp_peer_group::valid_peer_group_timers` exactly, one level
/// shallower (`OspfProfile` has no further-nested collection to skip over).
pub(crate) fn valid_profile_timers(profiles: &[OspfProfile]) -> garde::Result {
    for p in profiles {
        if p.extended_sequence_numbers {
            let ok = matches!(&p.auth, Some(OspfAuth::Crypto { keys })
                if keys.iter().all(|k| k.algorithm != OspfCryptoAlgorithm::Md5));
            if !ok {
                return Err(garde::Error::new(
                    "extended-sequence-numbers requires crypto auth with hmac-sha keys only",
                ));
            }
        } else if let Some(OspfAuth::Crypto { keys }) = &p.auth
            && keys.iter().any(|k| k.key_id > CLASSIC_KEY_ID_MAX)
        {
            return Err(garde::Error::new(
                "crypto key-id must be 0-255 unless extended-sequence-numbers is enabled",
            ));
        }
        valid_intervals(p.hello_interval, p.dead_interval)?;
    }
    Ok(())
}

/// Shared with `OspfVirtualLink`.
pub(crate) fn valid_intervals(hello: Option<u16>, dead: Option<u16>) -> garde::Result {
    match (hello, dead) {
        (Some(h), Some(d)) if d <= h => Err(garde::Error::new(
            "dead-interval must be greater than hello-interval when both are set",
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use garde::Validate as _;

    use crate::schema::{Config, OspfArea, OspfInstance};

    use super::{NetworkType, OspfAuth, OspfCryptoAlgorithm, OspfCryptoKey, OspfProfile};

    fn profile(name: &str) -> OspfProfile {
        OspfProfile {
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
            extended_sequence_numbers: false,
        }
    }

    fn area(area_id: &str, profiles: Vec<OspfProfile>) -> OspfArea {
        OspfArea {
            area_id: area_id.parse().unwrap(),
            area_type: crate::schema::OspfAreaType::Normal,
            stub_default_cost: None,
            ranges: Vec::new(),
            nssa_translate_always: false,
            nssa_default_originate: false,
            virtual_links: Vec::new(),
            profiles,
        }
    }

    fn instance(name: &str, areas: Vec<OspfArea>) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas,
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
            graceful_restart_helper_max_grace_period: None,
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
            admin: keystore(),
            ..Default::default()
        }
    }

    /// Admin keystore holding the labels these auth tests reference.
    fn keystore() -> crate::schema::Admin {
        let key = |l: &str, s: &str| crate::schema::AdminKey {
            label: l.to_string(),
            secret: s.to_string(),
        };
        crate::schema::Admin {
            keys: vec![
                key("secret", "s3cr3t"),
                key("k", "kk"),
                key("pw8", "abcdefgh"),
                key("pw9", "123456789"),
            ],
        }
    }

    #[test]
    fn extended_sequence_numbers_needs_hmac_sha_crypto() {
        let key = |algorithm| OspfAuth::Crypto {
            keys: vec![OspfCryptoKey {
                key_id: 1,
                algorithm,
                key: "k".to_string(),
                is_current: true,
            }],
        };
        let check = |auth: Option<OspfAuth>| {
            let mut p = profile("p1");
            p.extended_sequence_numbers = true;
            p.auth = auth;
            let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
            cfg.validate_with(&cfg)
        };
        assert!(check(None).is_err());
        assert!(check(Some(key(OspfCryptoAlgorithm::Md5))).is_err());
        assert!(check(Some(key(OspfCryptoAlgorithm::HmacSha256))).is_ok());
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
    fn duplicate_name_across_areas_fails() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![
                area("0.0.0.0", vec![profile("p1")]),
                area("0.0.0.1", vec![profile("p1")]),
            ],
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
    ) -> OspfProfile {
        OspfProfile {
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
            extended_sequence_numbers: false,
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
    fn either_timer_unset_passes() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area(
                "0.0.0.0",
                vec![profile_with_timers("p1", Some(10), None)],
            )],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn nonzero_cost_passes() {
        let mut p = profile("p1");
        p.cost = Some(10);
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn zero_cost_fails() {
        let mut p = profile("p1");
        p.cost = Some(0);
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn unset_cost_passes() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area("0.0.0.0", vec![profile("p1")])],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn any_priority_passes() {
        let mut p = profile("p1");
        p.priority = Some(0);
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn either_network_type_passes() {
        for network_type in [
            NetworkType::PointToPoint,
            NetworkType::Broadcast,
            NetworkType::PointToMultipoint,
        ] {
            let mut p = profile("p1");
            p.network_type = Some(network_type);
            let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
            cfg.validate_with(&cfg).unwrap();
        }
    }

    #[test]
    fn key_id_above_255_needs_extended_sequence_numbers() {
        let check = |key_id: u16, extended: bool| {
            let mut p = profile("p1");
            p.extended_sequence_numbers = extended;
            p.auth = Some(OspfAuth::Crypto {
                keys: vec![crypto_key(key_id, true)],
            });
            let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
            cfg.validate_with(&cfg)
        };
        assert!(check(255, false).is_ok());
        assert!(check(255, true).is_ok());
        assert!(check(256, false).is_err());
        assert!(check(256, true).is_ok());
        assert!(check(u16::MAX, true).is_ok());
    }

    fn crypto_key(key_id: u16, is_current: bool) -> OspfCryptoKey {
        OspfCryptoKey {
            key_id,
            algorithm: OspfCryptoAlgorithm::HmacSha256,
            key: "secret".to_string(),
            is_current,
        }
    }

    #[test]
    fn no_auth_passes() {
        let cfg = config_with(vec![instance(
            "r1",
            vec![area("0.0.0.0", vec![profile("p1")])],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn valid_simple_password_passes() {
        let mut p = profile("p1");
        p.auth = Some(OspfAuth::Simple {
            key: "pw8".to_string(),
        });
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn simple_password_over_8_bytes_fails() {
        let mut p = profile("p1");
        p.auth = Some(OspfAuth::Simple {
            key: "pw9".to_string(),
        });
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn unknown_labels_fail_naming_the_label() {
        for auth in [
            OspfAuth::Simple { key: "nope".into() },
            OspfAuth::Crypto {
                keys: vec![OspfCryptoKey {
                    key: "nope".into(),
                    ..crypto_key(1, true)
                }],
            },
        ] {
            let mut p = profile("p1");
            p.auth = Some(auth);
            let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
            let err = cfg.validate_with(&cfg).unwrap_err().to_string();
            assert!(err.contains("nope"), "{err}");
        }
    }

    #[test]
    fn crypto_secret_length_bounds() {
        // The keystore's own rules bound real secrets to 1..=80 bytes, so call
        // the helper directly with out-of-range ones.
        let with = |n: usize| {
            let cfg = Config {
                admin: crate::schema::Admin {
                    keys: vec![crate::schema::AdminKey {
                        label: "l".into(),
                        secret: "x".repeat(n),
                    }],
                },
                ..Default::default()
            };
            let key = OspfCryptoKey {
                key: "l".into(),
                ..crypto_key(1, true)
            };
            super::valid_crypto_keys(&[key], &cfg).is_ok()
        };
        assert!(with(80));
        assert!(!with(81));
        assert!(!with(0));
    }

    #[test]
    fn deleting_a_referenced_admin_key_fails_but_an_unreferenced_one_passes() {
        let mut p = profile("p1");
        p.auth = Some(OspfAuth::Simple { key: "pw8".into() });
        let mut cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        cfg.admin.keys.retain(|k| k.label != "k");
        cfg.validate_with(&cfg).unwrap();
        cfg.admin.keys.retain(|k| k.label != "pw8");
        let err = cfg.validate_with(&cfg).unwrap_err().to_string();
        assert!(err.contains("pw8"), "{err}");
    }

    #[test]
    fn debug_of_auth_shows_the_label_only() {
        let auth = OspfAuth::Simple { key: "lbl".into() };
        assert!(format!("{auth:?}").contains("lbl"));
        assert!(!format!("{:?}", keystore()).contains("abcdefgh"));
    }

    #[test]
    fn valid_crypto_keys_pass() {
        let mut p = profile("p1");
        p.auth = Some(OspfAuth::Crypto {
            keys: vec![crypto_key(1, true), crypto_key(2, false)],
        });
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn empty_crypto_keys_fails() {
        let mut p = profile("p1");
        p.auth = Some(OspfAuth::Crypto { keys: Vec::new() });
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_crypto_key_id_fails() {
        let mut p = profile("p1");
        p.auth = Some(OspfAuth::Crypto {
            keys: vec![crypto_key(1, true), crypto_key(1, false)],
        });
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn no_current_crypto_key_fails() {
        let mut p = profile("p1");
        p.auth = Some(OspfAuth::Crypto {
            keys: vec![crypto_key(1, false)],
        });
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn two_current_crypto_keys_fails() {
        let mut p = profile("p1");
        p.auth = Some(OspfAuth::Crypto {
            keys: vec![crypto_key(1, true), crypto_key(2, true)],
        });
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0", vec![p])])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
