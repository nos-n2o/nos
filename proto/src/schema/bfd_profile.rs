use std::net::Ipv4Addr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::Config;
use nos_proto_derive::Cli;

/// Default `min-tx-interval` and `min-rx-interval`, milliseconds.
pub const MIN_INTERVAL_DEFAULT: u32 = 300;
/// Default `detect-multiplier`: three missed packets declare the session Down.
pub const DETECT_MULTIPLIER_DEFAULT: u8 = 3;
/// Default `minimum-ttl`: single-hop BFD (RFC 5881 §5) is sent with TTL 255,
/// so 254 accepts one routed hop of slack.
pub const MINIMUM_TTL_DEFAULT: u8 = 254;
/// RFC 5880 carries intervals in microseconds as a `u32`: the largest whole
/// number of milliseconds that fits, so the daemon's ms-to-us conversion
/// cannot overflow.
pub const INTERVAL_MAX_MS: u32 = 4_294_967;
/// Smallest accepted transmit or receive interval, milliseconds.
pub const INTERVAL_MIN_MS: u32 = 10;
/// Default `echo-interval`, milliseconds.
pub const ECHO_INTERVAL_DEFAULT: u32 = 50;
/// `padded-pdu-size` bounds (RFC 9764): the smallest is a Control packet with
/// the largest RFC 5880 §6.7 auth section; the largest a jumbo frame's UDP
/// payload, which also bounds the receive buffer.
pub const PADDED_PDU_MIN: u16 = 24;
/// Largest accepted `padded-pdu-size`, bytes.
pub const PADDED_PDU_MAX: u16 = 9000;

/// A named set of BFD (RFC 5880) session parameters, referenced by bare name
/// from a BGP peer-group, an OSPF/OSPFv3 profile or a static route
/// (`bfd <name>`). Declaration only for now: no daemon consumes it yet, so
/// attaching one is inert.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct BfdProfile {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.bfd_profiles, |p| &p.name))
    )]
    #[cli(key)]
    /// Profile name, 1 to 64 characters (letters, digits, `_`, `-`), unique among BFD profiles; the key sessions reference.
    pub name: String,

    /// Desired minimum transmit interval, milliseconds.
    #[serde(default = "min_interval_default")]
    #[garde(range(min = INTERVAL_MIN_MS, max = INTERVAL_MAX_MS))]
    #[cli(topic = BfdProfileMinTx)]
    pub min_tx_interval: u32,

    /// Required minimum receive interval, milliseconds.
    #[serde(default = "min_interval_default")]
    #[garde(range(min = INTERVAL_MIN_MS, max = INTERVAL_MAX_MS))]
    #[cli(topic = BfdProfileMinRx)]
    pub min_rx_interval: u32,

    #[serde(default = "detect_multiplier_default")]
    #[garde(range(min = 1))]
    #[cli(topic = BfdProfileDetectMultiplier)]
    /// Detection multiplier (RFC 5880 §6.8.4): detection time is this times the negotiated interval. At least 1.
    pub detect_multiplier: u8,

    /// Passive role: wait for the peer's first packet instead of starting
    /// the session (RFC 5880 §6.1).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BfdProfilePassive, words = "passive enable", alias = "passive")]
    pub passive: bool,

    #[serde(default = "minimum_ttl_default")]
    #[garde(skip)]
    #[cli(topic = BfdProfileMinimumTtl)]
    /// Lowest received IP TTL / Hop Limit a session accepts (RFC 5881 §5 GTSM); lower packets are dropped.
    pub minimum_ttl: u8,

    /// Administratively down: sessions using this profile stay `AdminDown`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BfdProfileShutdown, words = "shutdown enable", alias = "shutdown")]
    pub shutdown: bool,

    /// `None` is RFC 5880 `AuthType` 0: no authentication. The key is a
    /// label of the admin keystore, never an inline secret.
    #[serde(default)]
    #[garde(custom(|a: &Option<BfdAuth>, ctx: &Config| valid_auth(a.as_ref(), ctx)))]
    #[cli(topic = BfdProfileAuth)]
    pub auth: Option<BfdAuth>,

    /// RFC 5880 §6.4 Echo function (single-hop sessions only).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BfdProfileEchoMode)]
    pub echo_mode: EchoMode,

    /// Echo transmit interval, and the Required Min Echo RX Interval this
    /// system advertises, milliseconds.
    #[serde(default = "echo_interval_default")]
    #[garde(range(min = INTERVAL_MIN_MS, max = INTERVAL_MAX_MS))]
    #[cli(topic = BfdProfileEchoInterval)]
    pub echo_interval: u32,

    /// RFC 9764: pad each Control packet's UDP payload with zeros to this
    /// many bytes, to test that the path carries packets that large. `None`
    /// sends the bare packet.
    #[serde(default)]
    #[garde(inner(range(min = PADDED_PDU_MIN, max = PADDED_PDU_MAX)))]
    #[cli(topic = BfdProfilePaddedPduSize)]
    pub padded_pdu_size: Option<u16>,

    /// `sbfd`: Seamless BFD initiator (RFC 7880/7881): probes a reflector
    /// that keeps no per-session state. Excludes `echo-mode`, `padded-pdu-size`
    /// and `auth` (not built for S-BFD yet).
    #[serde(default)]
    #[garde(custom(sbfd_compatible(self.echo_mode, self.padded_pdu_size.is_some(), self.auth.is_some())))]
    #[cli(topic = BfdProfileMode)]
    pub mode: BfdMode,

    /// RFC 7880 S-BFD discriminator of the remote entity, written as an IPv4
    /// address (the 32 bits). `None`: the peer's own IPv4 address.
    #[serde(default)]
    #[garde(inner(custom(nonzero_discriminator)))]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[cli(topic = BfdProfileSbfdRemoteDiscriminator)]
    pub sbfd_remote_discriminator: Option<Ipv4Addr>,
}

/// Which BFD a session runs: the classical RFC 5880 handshake, or the RFC
/// 7880 S-BFD initiator (Down/Up only, against a stateless reflector).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum BfdMode {
    #[default]
    /// Classical RFC 5880 asynchronous session with the three-way handshake.
    Async,
    /// S-BFD initiator (RFC 7880) probing a stateless reflector.
    Sbfd,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "garde hands the validator a reference"
)]
fn nonzero_discriminator(d: &Ipv4Addr, _ctx: &Config) -> garde::Result {
    if d.is_unspecified() {
        return Err(garde::Error::new("an S-BFD discriminator must not be 0"));
    }
    Ok(())
}

fn sbfd_compatible(
    echo: EchoMode,
    padded: bool,
    auth: bool,
) -> impl FnOnce(&BfdMode, &Config) -> garde::Result {
    move |mode, _ctx| {
        if *mode == BfdMode::Sbfd && (echo != EchoMode::Disabled || padded || auth) {
            return Err(garde::Error::new(
                "mode sbfd does not support echo-mode, padded-pdu-size or auth",
            ));
        }
        Ok(())
    }
}

/// Whether this system loops its own Echo packets through the peer (RFC 5880
/// §6.4). `Affiliated`: the Echo function runs alongside the Control session,
/// which then slows to one packet a second. `Unaffiliated` (RFC 9747): Echo
/// is the whole session, for a peer that runs no BFD at all.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum EchoMode {
    #[default]
    /// No Echo function.
    Disabled,
    /// Echo alongside a BFD session (RFC 5880 §6.4), which then slows its Control packets.
    Affiliated,
    /// Echo is the whole session, for a peer that runs no BFD (RFC 9747).
    Unaffiliated,
}

fn echo_interval_default() -> u32 {
    ECHO_INTERVAL_DEFAULT
}

fn min_interval_default() -> u32 {
    MIN_INTERVAL_DEFAULT
}
fn detect_multiplier_default() -> u8 {
    DETECT_MULTIPLIER_DEFAULT
}
fn minimum_ttl_default() -> u8 {
    MINIMUM_TTL_DEFAULT
}

/// The placeholder a new `BfdProfile` starts from (`edit` on a missing one).
impl Default for BfdProfile {
    fn default() -> Self {
        BfdProfile {
            name: String::new(),
            min_tx_interval: MIN_INTERVAL_DEFAULT,
            min_rx_interval: MIN_INTERVAL_DEFAULT,
            detect_multiplier: DETECT_MULTIPLIER_DEFAULT,
            passive: false,
            minimum_ttl: MINIMUM_TTL_DEFAULT,
            shutdown: false,
            auth: None,
            echo_mode: EchoMode::Disabled,
            echo_interval: ECHO_INTERVAL_DEFAULT,
            padded_pdu_size: None,
            mode: BfdMode::Async,
            sbfd_remote_discriminator: None,
        }
    }
}

/// RFC 5880 §4.2/§4.3 authentication section: the method picks the
/// `AuthType`, `key_id` is the wire Auth Key ID.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BfdAuth {
    #[cli(topic = BfdProfileAuth)]
    /// Auth Key ID carried in each packet (RFC 5880 §4.2/§4.3); both ends must agree.
    pub key_id: u8,
    #[cli(topic = BfdProfileAuth)]
    /// Mechanism, which fixes the `AuthType` on the wire.
    pub method: BfdAuthMethod,
    #[cli(topic = BfdProfileAuth)]
    /// Label of the admin key holding the shared secret.
    pub key: String,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
/// BFD authentication mechanism (RFC 5880 §4.2 and §4.3).
pub enum BfdAuthMethod {
    #[default]
    #[cli(words = "simple-password")]
    /// Clear-text password (`AuthType` 1).
    SimplePassword,
    #[cli(words = "keyed-md5")]
    /// Keyed MD5; the sequence number advances only occasionally.
    KeyedMd5,
    #[cli(words = "meticulous-md5")]
    /// Meticulous keyed MD5; the sequence number advances every packet.
    MeticulousMd5,
    #[cli(words = "keyed-sha1")]
    /// Keyed SHA1; the sequence number advances only occasionally.
    KeyedSha1,
    #[cli(words = "meticulous-sha1")]
    /// Meticulous keyed SHA1; the sequence number advances every packet.
    MeticulousSha1,
}

fn valid_auth(auth: Option<&BfdAuth>, cfg: &Config) -> garde::Result {
    let Some(a) = auth else { return Ok(()) };
    // RFC 5880 §4.2 (password 1..16 bytes), §4.3 (MD5 key 1..16, SHA1 1..20).
    let max = match a.method {
        BfdAuthMethod::SimplePassword | BfdAuthMethod::KeyedMd5 | BfdAuthMethod::MeticulousMd5 => {
            16
        }
        BfdAuthMethod::KeyedSha1 | BfdAuthMethod::MeticulousSha1 => 20,
    };
    let Some(secret) = cfg.key(&a.key) else {
        return Err(garde::Error::new(format!(
            "bfd auth references unknown admin key '{}'",
            a.key
        )));
    };
    if secret.is_empty() || secret.len() > max {
        return Err(garde::Error::new(format!(
            "admin key '{}' must be 1 to {max} bytes long to be used as a bfd auth key for this method",
            a.key
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::BgpPeerGroup;

    fn profile(name: &str) -> BfdProfile {
        BfdProfile {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Keystore holding the `k` label (3 bytes) the auth tests reference.
    fn keystore(secret: &str) -> crate::schema::Admin {
        crate::schema::Admin {
            keys: vec![crate::schema::AdminKey {
                label: "k".into(),
                secret: secret.into(),
            }],
        }
    }

    fn ok(p: BfdProfile) -> bool {
        let c = Config {
            bfd_profiles: vec![p],
            admin: keystore("kkk"),
            ..Default::default()
        };
        c.validate_with(&c).is_ok()
    }

    #[test]
    fn defaults() {
        let p = BfdProfile::default();
        assert_eq!(
            (
                p.min_tx_interval,
                p.min_rx_interval,
                p.detect_multiplier,
                p.minimum_ttl
            ),
            (300, 300, 3, 254)
        );
        assert!(ok(profile("fast")));
    }

    #[test]
    fn old_config_without_bfd_profiles_loads() {
        let mut v = serde_json::to_value(Config::default()).unwrap();
        v.as_object_mut().unwrap().remove("bfd_profiles");
        let c: Config = serde_json::from_value(v).unwrap();
        assert_eq!(c.bfd_profiles.len(), 0);
        let p: BfdProfile = serde_json::from_str(r#"{"name":"x"}"#).unwrap();
        assert_eq!(p, profile("x"));
    }

    #[test]
    fn ranges() {
        let mut p = profile("a");
        p.min_tx_interval = 9;
        assert!(!ok(p));
        let mut p = profile("a");
        p.min_rx_interval = INTERVAL_MAX_MS + 1;
        assert!(!ok(p));
        let mut p = profile("a");
        p.detect_multiplier = 0;
        assert!(!ok(p));
        let mut p = profile("a");
        p.min_tx_interval = 10;
        p.min_rx_interval = INTERVAL_MAX_MS;
        assert!(ok(p));
    }

    #[test]
    fn padded_pdu_size_range() {
        let with = |n| {
            let mut p = profile("a");
            p.padded_pdu_size = n;
            ok(p)
        };
        assert!(with(None) && with(Some(24)) && with(Some(9000)));
        assert!(!with(Some(23)) && !with(Some(9001)));
    }

    #[test]
    fn sbfd_mode_rules() {
        let with = |f: &dyn Fn(&mut BfdProfile)| {
            let mut p = profile("a");
            p.mode = BfdMode::Sbfd;
            f(&mut p);
            ok(p)
        };
        assert!(with(&|_| {}));
        assert!(with(
            &|p| p.sbfd_remote_discriminator = Some("10.0.0.2".parse().unwrap())
        ));
        assert!(!with(
            &|p| p.sbfd_remote_discriminator = Some(Ipv4Addr::UNSPECIFIED)
        ));
        assert!(!with(&|p| p.echo_mode = EchoMode::Affiliated));
        assert!(!with(&|p| p.padded_pdu_size = Some(100)));
        assert!(!with(&|p| {
            p.auth = Some(BfdAuth {
                key: "k".into(),
                ..Default::default()
            });
        }));
        // The same fields are fine on an async profile.
        let mut p = profile("a");
        p.padded_pdu_size = Some(100);
        assert!(ok(p));
    }

    #[test]
    fn auth_key_length_per_method() {
        let with = |method, len| {
            let mut p = profile("a");
            p.auth = Some(BfdAuth {
                key_id: 1,
                method,
                key: "k".into(),
            });
            let c = Config {
                bfd_profiles: vec![p],
                admin: keystore(&"x".repeat(len)),
                ..Default::default()
            };
            c.validate_with(&c).is_ok()
        };
        assert!(with(BfdAuthMethod::SimplePassword, 16));
        assert!(!with(BfdAuthMethod::SimplePassword, 17));
        assert!(!with(BfdAuthMethod::KeyedMd5, 0));
        assert!(!with(BfdAuthMethod::MeticulousMd5, 17));
        assert!(with(BfdAuthMethod::KeyedSha1, 20));
        assert!(!with(BfdAuthMethod::MeticulousSha1, 21));
    }

    #[test]
    fn auth_label_must_exist_and_a_referenced_key_cannot_be_deleted() {
        let mut p = profile("a");
        p.auth = Some(BfdAuth {
            key: "nope".into(),
            ..Default::default()
        });
        let c = Config {
            bfd_profiles: vec![p.clone()],
            admin: keystore("kkk"),
            ..Default::default()
        };
        let err = c.validate_with(&c).unwrap_err().to_string();
        assert!(err.contains("nope"), "{err}");
        p.auth.as_mut().unwrap().key = "k".into();
        let mut c = Config {
            bfd_profiles: vec![p],
            admin: keystore("kkk"),
            ..Default::default()
        };
        c.validate_with(&c).unwrap();
        c.admin.keys.clear();
        assert!(c.validate_with(&c).is_err());
    }

    #[test]
    fn debug_of_a_profile_never_shows_a_secret() {
        let c = Config {
            admin: keystore("s3cr3t"),
            bfd_profiles: vec![BfdProfile {
                auth: Some(BfdAuth {
                    key: "k".into(),
                    ..Default::default()
                }),
                ..profile("a")
            }],
            ..Default::default()
        };
        assert!(!format!("{c:?}").contains("s3cr3t"));
    }

    #[test]
    fn an_inline_key_from_an_old_config_is_just_an_unknown_label() {
        // Hard break (#510): the old inline secret now reads as a label.
        let a: BfdAuth =
            serde_json::from_str(r#"{"key_id":1,"method":"KeyedMd5","key":"hunter2"}"#).unwrap();
        let mut p = profile("a");
        p.auth = Some(a);
        assert!(!ok(p));
    }

    /// Errors reported on a `bfd` field when `v` is validated against `cfg`.
    fn bfd_errors<T: Validate<Context = Config>>(v: &T, cfg: &Config) -> Vec<String>
    where
        T::Context: Sized,
    {
        match v.validate_with(cfg) {
            Ok(()) => Vec::new(),
            Err(r) => r
                .iter()
                .filter(|(p, _)| p.to_string() == "bfd")
                .map(|(_, e)| e.to_string())
                .collect(),
        }
    }

    #[test]
    fn each_attach_point_reports_a_dangling_reference() {
        use crate::schema::{OspfProfile, Ospfv3Profile, StaticRoute};
        let bfd = Some("gone".to_string());
        let with_profile = Config {
            bfd_profiles: vec![profile("gone")],
            ..Default::default()
        };
        let without = Config::default();
        let pg = BgpPeerGroup {
            bfd: bfd.clone(),
            ..Default::default()
        };
        let ospf = OspfProfile {
            bfd: bfd.clone(),
            ..Default::default()
        };
        let ospfv3 = Ospfv3Profile {
            bfd: bfd.clone(),
            ..Default::default()
        };
        let route = StaticRoute {
            bfd,
            ..Default::default()
        };
        for (name, errs, ok) in [
            (
                "peer-group",
                bfd_errors(&pg, &without),
                bfd_errors(&pg, &with_profile),
            ),
            (
                "ospf",
                bfd_errors(&ospf, &without),
                bfd_errors(&ospf, &with_profile),
            ),
            (
                "ospfv3",
                bfd_errors(&ospfv3, &without),
                bfd_errors(&ospfv3, &with_profile),
            ),
            (
                "static",
                bfd_errors(&route, &without),
                bfd_errors(&route, &with_profile),
            ),
        ] {
            assert_eq!(errs, ["bfd profile 'gone' does not exist"], "{name}");
            assert!(ok.is_empty(), "{name}: {ok:?}");
        }
    }

    #[test]
    fn duplicate_name_rejected() {
        let c = Config {
            bfd_profiles: vec![profile("a"), profile("a")],
            ..Default::default()
        };
        assert!(c.validate_with(&c).is_err());
    }
}
