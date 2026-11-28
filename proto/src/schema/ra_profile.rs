//! Named IPv6 Router Advertisement settings (`ra-profile`), referenced by bare
//! name from an `Interface` or a `Subinterface`. Declaration only until
//! `nos-radvd` (radvd 2/3): attaching one is inert.
//!
//! Ranges and defaults: RFC 4861 s6.2.1; preference RFC 4191 s2.2; prefix
//! rules RFC 4862 s5.5.3; RDNSS/DNSSL RFC 8106 s5.

use std::net::IpAddr;

use garde::Validate;
use ipnet::Ipv6Net;
use nos_proto_derive::Cli;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::Config;

/// `MaxRtrAdvInterval` default, seconds (RFC 4861 s6.2.1).
pub const MAX_INTERVAL_DEFAULT: u32 = 600;
/// Smallest `MaxRtrAdvInterval`.
pub const MAX_INTERVAL_MIN: u32 = 4;
/// Largest `MaxRtrAdvInterval`.
pub const MAX_INTERVAL_MAX: u32 = 1800;
/// Largest explicit router lifetime (`AdvDefaultLifetime`).
pub const ROUTER_LIFETIME_MAX: u32 = 9000;
/// Largest `reachable-time`, milliseconds.
pub const REACHABLE_TIME_MAX: u32 = 3_600_000;
/// Default valid lifetime of an advertised prefix, seconds (30 days).
pub const VALID_LIFETIME_DEFAULT: u32 = 2_592_000;
/// Default preferred lifetime of an advertised prefix, seconds (7 days).
pub const PREFERRED_LIFETIME_DEFAULT: u32 = 604_800;
/// At most this many prefixes per profile.
pub const MAX_PREFIXES: usize = 8;
/// At most this many RDNSS addresses per profile.
pub const MAX_RDNSS: usize = 16;
/// At most this many DNSSL domains per profile.
pub const MAX_DNSSL: usize = 8;
/// The RA must fit the IPv6 minimum MTU (1280) minus the IPv6 header.
pub const MAX_RA_LEN: usize = 1280 - 40;

/// Default router preference (RFC 4191 s2.2).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum RaPreference {
    /// Hosts prefer other routers.
    Low,
    /// The default.
    #[default]
    Medium,
    /// Hosts prefer this router.
    High,
}

/// One advertised prefix (Prefix Information option, RFC 4861 s4.6.2).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct RaPrefix {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cfg_attr(feature = "arbitrary", arbitrary(with = crate::arbitrary_support::ipv6_net))]
    #[cli(key)]
    /// The IPv6 prefix; the key.
    pub prefix: Ipv6Net,
    #[serde(default = "yes")]
    #[cli(topic = RaPrefixOnLink)]
    /// On-link flag (L).
    pub on_link: bool,
    #[serde(default = "yes")]
    #[cli(topic = RaPrefixAutonomous)]
    /// Autonomous address configuration flag (A).
    pub autonomous: bool,
    #[serde(default = "valid_default")]
    #[cli(topic = RaPrefixValidLifetime)]
    /// Valid lifetime in seconds.
    pub valid_lifetime: u32,
    #[serde(default = "preferred_default")]
    #[cli(topic = RaPrefixPreferredLifetime)]
    /// Preferred lifetime in seconds, at most the valid lifetime.
    pub preferred_lifetime: u32,
}

fn yes() -> bool {
    true
}
fn valid_default() -> u32 {
    VALID_LIFETIME_DEFAULT
}
fn preferred_default() -> u32 {
    PREFERRED_LIFETIME_DEFAULT
}

impl Default for RaPrefix {
    fn default() -> Self {
        Self {
            prefix: Ipv6Net::default(),
            on_link: true,
            autonomous: true,
            valid_lifetime: VALID_LIFETIME_DEFAULT,
            preferred_lifetime: PREFERRED_LIFETIME_DEFAULT,
        }
    }
}

/// One advertised recursive DNS server (RFC 8106 s5.1).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct RaRdnss {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// The server's IPv6 address; the key.
    pub address: IpAddr,
    #[serde(default)]
    #[cli(topic = RaRdnssLifetime)]
    /// Lifetime in seconds; `None` is twice `max-interval`.
    pub lifetime: Option<u32>,
}

impl Default for RaRdnss {
    fn default() -> Self {
        Self {
            address: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            lifetime: None,
        }
    }
}

/// One advertised DNS search domain (RFC 8106 s5.2).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct RaDnssl {
    #[cli(key)]
    /// The domain name; the key.
    pub domain: String,
    #[serde(default)]
    #[cli(topic = RaDnsslLifetime)]
    /// Lifetime in seconds; `None` is twice `max-interval`.
    pub lifetime: Option<u32>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one independent on/off switch per RA flag, edited one by one"
)]
/// IPv6 Router Advertisement settings that an interface attaches by name.
pub struct RaProfile {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.ra_profiles, |p| &p.name)),
        custom(|n, ctx: &Config| valid_profile(n, ctx))
    )]
    #[cli(key)]
    /// Profile name, 1 to 64 characters (letters, digits, `_`, `-`), unique among RA profiles.
    pub name: String,

    #[serde(default = "max_interval_default")]
    #[garde(range(min = MAX_INTERVAL_MIN, max = MAX_INTERVAL_MAX))]
    #[cli(topic = RaProfileMaxInterval)]
    /// `MaxRtrAdvInterval` in seconds, 4..=1800.
    pub max_interval: u32,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RaProfileMinInterval)]
    /// `MinRtrAdvInterval` in seconds; `None` is a third of `max-interval` (at least 3).
    pub min_interval: Option<u32>,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RaProfileRouterLifetime)]
    /// Router lifetime in seconds; `None` is three times `max-interval`; 0 is "not a default router".
    pub router_lifetime: Option<u32>,

    #[serde(default = "hop_limit_default")]
    #[garde(skip)]
    #[cli(topic = RaProfileHopLimit)]
    /// Advertised current hop limit; 0 leaves it unspecified.
    pub hop_limit: u8,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RaProfileManaged, words = "managed enable", alias = "managed")]
    /// Managed address configuration flag (M).
    pub managed: bool,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RaProfileOtherConfig, words = "other-config enable", alias = "other-config")]
    /// Other configuration flag (O).
    pub other_config: bool,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RaProfilePreference)]
    /// Default router preference (RFC 4191).
    pub preference: RaPreference,

    #[serde(default)]
    #[garde(range(max = REACHABLE_TIME_MAX))]
    #[cli(topic = RaProfileReachableTime)]
    /// Advertised reachable time in milliseconds; 0 leaves it unspecified.
    pub reachable_time: u32,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RaProfileRetransTimer)]
    /// Advertised retransmit timer in milliseconds; 0 leaves it unspecified.
    pub retrans_timer: u32,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RaProfileAdvertiseMtu, words = "advertise-mtu enable", alias = "advertise-mtu")]
    /// Advertise the link's MTU option.
    pub advertise_mtu: bool,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RaProfilePrefix, words = "prefix")]
    /// Advertised prefixes.
    pub prefixes: Vec<RaPrefix>,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RaProfileRdnss, words = "rdnss")]
    /// Advertised recursive DNS servers.
    pub rdnss: Vec<RaRdnss>,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RaProfileDnssl, words = "dnssl")]
    /// Advertised DNS search domains.
    pub dnssl: Vec<RaDnssl>,
}

fn max_interval_default() -> u32 {
    MAX_INTERVAL_DEFAULT
}
fn hop_limit_default() -> u8 {
    64
}

/// The placeholder a new `RaProfile` starts from (`edit` on a missing one).
impl Default for RaProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            max_interval: MAX_INTERVAL_DEFAULT,
            min_interval: None,
            router_lifetime: None,
            hop_limit: 64,
            managed: false,
            other_config: false,
            preference: RaPreference::default(),
            reachable_time: 0,
            retrans_timer: 0,
            advertise_mtu: false,
            prefixes: Vec::new(),
            rdnss: Vec::new(),
            dnssl: Vec::new(),
        }
    }
}

/// Wire length of a DNSSL name list entry (RFC 1035 s3.1 labels + root).
fn encoded_len(domain: &str) -> usize {
    domain.trim_end_matches('.').len() + 2
}

impl RaProfile {
    /// Effective `MinRtrAdvInterval` in seconds.
    #[must_use]
    pub fn effective_min_interval(&self) -> u32 {
        self.min_interval
            .unwrap_or_else(|| (self.max_interval / 3).max(3))
    }

    /// Effective router lifetime in seconds.
    #[must_use]
    pub fn effective_router_lifetime(&self) -> u32 {
        self.router_lifetime.unwrap_or(3 * self.max_interval)
    }

    /// Upper bound of the RA's ICMPv6 payload in bytes: header, source link-layer
    /// address, MTU, then every prefix, RDNSS and DNSSL option (one option each).
    #[must_use]
    pub fn wire_len(&self) -> usize {
        let dnssl: usize = self
            .dnssl
            .iter()
            .map(|d| (8 + encoded_len(&d.domain)).div_ceil(8) * 8)
            .sum();
        16 + 8 + 8 + 32 * self.prefixes.len() + (8 + 16) * self.rdnss.len() + dnssl
    }
}

fn valid_label_domain(d: &str) -> bool {
    let d = d.strip_suffix('.').unwrap_or(d);
    !d.is_empty()
        && encoded_len(d) <= 255
        && d.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// Every cross-field and list rule of a profile. Looked up by name because a
/// field-level check cannot see its siblings.
fn valid_profile(name: &str, ctx: &Config) -> garde::Result {
    let Some(p) = ctx.ra_profiles.iter().find(|p| p.name == name) else {
        return Ok(());
    };
    let refuse = |why: String| Err(garde::Error::new(why));
    let max = p.max_interval;
    // 0.75 * max, rounded down, in integer arithmetic.
    let min_ceiling = max * 3 / 4;
    if p.min_interval.is_some_and(|m| m < 3 || m > min_ceiling) {
        return refuse(format!(
            "min-interval must be 3..={min_ceiling} (0.75 * max-interval)"
        ));
    }
    if p.router_lifetime
        .is_some_and(|l| l != 0 && !(max..=ROUTER_LIFETIME_MAX).contains(&l))
    {
        return refuse(format!(
            "router-lifetime must be 0 or {max}..={ROUTER_LIFETIME_MAX}"
        ));
    }
    if p.prefixes.len() > MAX_PREFIXES || p.rdnss.len() > MAX_RDNSS || p.dnssl.len() > MAX_DNSSL {
        return refuse(format!(
            "at most {MAX_PREFIXES} prefixes, {MAX_RDNSS} rdnss and {MAX_DNSSL} dnssl entries"
        ));
    }
    let lifetime_ok = |l: Option<u32>| l.is_none_or(|l| l == 0 || (max..=2 * max).contains(&l));
    for (i, x) in p.prefixes.iter().enumerate() {
        let net = x.prefix;
        if p.prefixes[..i].iter().any(|o| o.prefix == net) {
            return refuse(format!("prefix {net} is listed twice"));
        }
        let addr = net.addr();
        if addr.is_unspecified() || addr.is_multicast() || addr.is_unicast_link_local() {
            return refuse(format!(
                "prefix {net} must be a global or unique-local prefix"
            ));
        }
        if net != net.trunc() {
            return refuse(format!("prefix {net} has host bits set"));
        }
        if x.autonomous && net.prefix_len() != 64 {
            return refuse(format!("prefix {net} is autonomous and so must be a /64"));
        }
        if x.preferred_lifetime > x.valid_lifetime {
            return refuse(format!(
                "prefix {net}: preferred-lifetime exceeds valid-lifetime"
            ));
        }
    }
    for (i, r) in p.rdnss.iter().enumerate() {
        match r.address {
            IpAddr::V6(a) if !a.is_unspecified() && !a.is_multicast() => {}
            _ => {
                return refuse(format!(
                    "rdnss {} must be a unicast IPv6 address",
                    r.address
                ))
            }
        }
        if p.rdnss[..i].iter().any(|o| o.address == r.address) {
            return refuse(format!("rdnss {} is listed twice", r.address));
        }
        if !lifetime_ok(r.lifetime) {
            return refuse(format!(
                "rdnss {} lifetime must be 0 or {max}..={}",
                r.address,
                2 * max
            ));
        }
    }
    for (i, d) in p.dnssl.iter().enumerate() {
        if !valid_label_domain(&d.domain) {
            return refuse(format!("dnssl '{}' is not a valid domain name", d.domain));
        }
        if p.dnssl[..i].iter().any(|o| o.domain == d.domain) {
            return refuse(format!("dnssl '{}' is listed twice", d.domain));
        }
        if !lifetime_ok(d.lifetime) {
            return refuse(format!(
                "dnssl '{}' lifetime must be 0 or {max}..={}",
                d.domain,
                2 * max
            ));
        }
    }
    if p.wire_len() > MAX_RA_LEN {
        return refuse(format!(
            "the advertisement would be {} bytes, over the {MAX_RA_LEN} that fit the IPv6 minimum MTU",
            p.wire_len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(f: impl FnOnce(&mut RaProfile)) -> bool {
        let mut p = RaProfile {
            name: "p".into(),
            ..Default::default()
        };
        f(&mut p);
        let c = Config {
            ra_profiles: vec![p],
            ..Default::default()
        };
        c.validate_with(&c).is_ok()
    }

    fn pfx(s: &str) -> RaPrefix {
        RaPrefix {
            prefix: s.parse().unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn defaults_commit_and_round_trip() {
        assert!(ok(|_| {}));
        let p: RaProfile = serde_json::from_str(r#"{"name":"x"}"#).unwrap();
        assert_eq!(
            p,
            RaProfile {
                name: "x".into(),
                ..Default::default()
            }
        );
        let q: RaPrefix = serde_json::from_str(r#"{"prefix":"2001:db8::/64"}"#).unwrap();
        assert_eq!(q, pfx("2001:db8::/64"));
    }

    #[test]
    fn max_interval_range() {
        assert!(ok(|p| p.max_interval = 4));
        assert!(ok(|p| p.max_interval = 1800));
        assert!(!ok(|p| p.max_interval = 3));
        assert!(!ok(|p| p.max_interval = 1801));
    }

    #[test]
    fn min_interval_range() {
        assert!(ok(|p| p.min_interval = Some(3)));
        assert!(ok(|p| p.min_interval = Some(450))); // 0.75 * 600
        assert!(!ok(|p| p.min_interval = Some(2)));
        assert!(!ok(|p| p.min_interval = Some(451)));
        assert!(ok(|p| p.max_interval = 4)); // default min = 3 = 0.75 * 4
        assert_eq!(
            RaProfile {
                max_interval: 4,
                ..Default::default()
            }
            .effective_min_interval(),
            3
        );
        assert_eq!(RaProfile::default().effective_min_interval(), 200);
    }

    #[test]
    fn router_lifetime_range() {
        assert!(ok(|p| p.router_lifetime = Some(0)));
        assert!(ok(|p| p.router_lifetime = Some(600)));
        assert!(ok(|p| p.router_lifetime = Some(9000)));
        assert!(!ok(|p| p.router_lifetime = Some(599)));
        assert!(!ok(|p| p.router_lifetime = Some(9001)));
        assert_eq!(RaProfile::default().effective_router_lifetime(), 1800);
    }

    #[test]
    fn reachable_time_cap() {
        assert!(ok(|p| p.reachable_time = 3_600_000));
        assert!(!ok(|p| p.reachable_time = 3_600_001));
    }

    #[test]
    fn prefix_rules() {
        assert!(ok(|p| p.prefixes = vec![pfx("2001:db8::/64")]));
        assert!(!ok(
            |p| p.prefixes = vec![pfx("2001:db8::/64"), pfx("2001:db8::/64")]
        ));
        assert!(!ok(|p| p.prefixes = vec![pfx("fe80::/64")]));
        assert!(!ok(|p| p.prefixes = vec![pfx("ff02::/64")]));
        assert!(!ok(|p| p.prefixes = vec![pfx("::/64")]));
        assert!(!ok(|p| p.prefixes = vec![pfx("2001:db8::1/64")]));
        // /48 only without the autonomous flag.
        assert!(!ok(|p| p.prefixes = vec![pfx("2001:db8::/48")]));
        assert!(ok(|p| p.prefixes = vec![RaPrefix {
            autonomous: false,
            ..pfx("2001:db8::/48")
        }]));
        // preferred <= valid.
        assert!(ok(|p| p.prefixes = vec![RaPrefix {
            valid_lifetime: 10,
            preferred_lifetime: 10,
            ..pfx("2001:db8::/64")
        }]));
        assert!(!ok(|p| p.prefixes = vec![RaPrefix {
            valid_lifetime: 10,
            preferred_lifetime: 11,
            ..pfx("2001:db8::/64")
        }]));
    }

    #[test]
    fn rdnss_rules() {
        let r = |a: &str, l| RaRdnss {
            address: a.parse().unwrap(),
            lifetime: l,
        };
        assert!(ok(|p| p.rdnss = vec![r("2001:db8::53", None)]));
        assert!(ok(|p| p.rdnss = vec![r("fe80::1", Some(0))]));
        assert!(ok(|p| p.rdnss = vec![
            r("2001:db8::53", Some(600)),
            r("2001:db8::54", Some(1200))
        ]));
        assert!(!ok(|p| p.rdnss = vec![r("2001:db8::53", Some(599))]));
        assert!(!ok(|p| p.rdnss = vec![r("2001:db8::53", Some(1201))]));
        assert!(!ok(|p| p.rdnss = vec![r("::", None)]));
        assert!(!ok(|p| p.rdnss = vec![r("ff02::1", None)]));
        assert!(!ok(|p| p.rdnss = vec![r("192.0.2.1", None)]));
        assert!(!ok(
            |p| p.rdnss = vec![r("2001:db8::53", None), r("2001:db8::53", None)]
        ));
    }

    #[test]
    fn dnssl_rules() {
        let d = |s: &str, l| RaDnssl {
            domain: s.into(),
            lifetime: l,
        };
        assert!(ok(
            |p| p.dnssl = vec![d("example.com", None), d("lab.example.com.", Some(0))]
        ));
        assert!(!ok(|p| p.dnssl = vec![d("", None)]));
        assert!(!ok(|p| p.dnssl = vec![d("a..b", None)]));
        assert!(!ok(|p| p.dnssl = vec![d("-a.b", None)]));
        assert!(!ok(|p| p.dnssl = vec![d("a_b.c", None)]));
        assert!(!ok(|p| p.dnssl = vec![d(&"a".repeat(64), None)]));
        assert!(!ok(|p| p.dnssl = vec![d("a.com", Some(5))]));
    }

    #[test]
    fn list_caps_and_size() {
        let nets = |n: usize| -> Vec<RaPrefix> {
            (0..n)
                .map(|i| RaPrefix {
                    prefix: format!("2001:db8:{i:x}::/64").parse().unwrap(),
                    ..Default::default()
                })
                .collect()
        };
        assert!(ok(|p| p.prefixes = nets(8)));
        assert!(!ok(|p| p.prefixes = nets(9)));
        let dns = |n: usize| -> Vec<RaRdnss> {
            (0..n)
                .map(|i| RaRdnss {
                    address: format!("2001:db8::{:x}", i + 1).parse().unwrap(),
                    lifetime: None,
                })
                .collect()
        };
        assert!(ok(|p| p.rdnss = dns(16)));
        assert!(!ok(|p| p.rdnss = dns(17)));
        // Eight long domains overflow the 1240 byte budget.
        let long = |i: usize| RaDnssl {
            domain: format!(
                "{}.{}.{}.{}{i}",
                "a".repeat(60),
                "b".repeat(60),
                "c".repeat(60),
                "d".repeat(60)
            ),
            lifetime: None,
        };
        assert!(!ok(|p| p.dnssl = (0..8).map(long).collect()));
    }

    #[test]
    fn duplicate_names_are_refused() {
        let p = RaProfile {
            name: "p".into(),
            ..Default::default()
        };
        let c = Config {
            ra_profiles: vec![p.clone(), p],
            ..Default::default()
        };
        assert!(c.validate_with(&c).is_err());
    }
}
