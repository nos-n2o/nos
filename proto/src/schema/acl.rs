//! Named, ordered access lists (`acl`), attached to an interface with
//! `acl in <name>` / `acl out <name>`; `nos-acld` compiles them to tc.

use std::fmt;
use std::str::FromStr;

use garde::Validate;
use ipnet::IpNet;
use nos_proto_derive::Cli;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::interface::loopback_table_name;
use super::Config;
use crate::cli::{CliValue, Kind};
use crate::validators::unique_key_in;

/// What a matching rule (or the end of the list) does with the packet.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum AclAction {
    /// Let the packet through.
    Permit,
    /// Drop the packet.
    #[default]
    Deny,
}

/// The IP protocol a rule matches: a named one, or any other protocol number.
/// Text form `tcp`, `udp`, `icmp`, `icmpv6` or a number (`89`); the numbers
/// of the named protocols parse to the named variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclProtocol {
    /// TCP (6).
    Tcp,
    /// UDP (17).
    Udp,
    /// ICMP for IPv4 (1).
    Icmp,
    /// ICMP for IPv6 (58).
    Icmpv6,
    /// Any other IP protocol number (`89` is OSPF).
    Number(u8),
}

impl AclProtocol {
    /// The IP protocol number.
    pub fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp => 1,
            Self::Icmpv6 => 58,
            Self::Number(n) => n,
        }
    }
}

impl fmt::Display for AclProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::Icmp => f.write_str("icmp"),
            Self::Icmpv6 => f.write_str("icmpv6"),
            Self::Number(n) => write!(f, "{n}"),
        }
    }
}

impl FromStr for AclProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s {
            "tcp" | "6" => Self::Tcp,
            "udp" | "17" => Self::Udp,
            "icmp" | "1" => Self::Icmp,
            "icmpv6" | "58" => Self::Icmpv6,
            _ => Self::Number(s.parse().map_err(|_| {
                format!("protocol must be tcp, udp, icmp, icmpv6 or a number 0-255, not '{s}'")
            })?),
        })
    }
}

/// An inclusive TCP/UDP port range. Text form `80` (one port) or
/// `1024-65535`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    /// First port.
    pub start: u16,
    /// Last port; equal to `start` for a single port.
    pub end: u16,
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl FromStr for PortRange {
    type Err = String;

    /// Syntax only: `0` and `start > end` are refused at commit, with a
    /// message that names the rule.
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("port must be a number or a range like 1024-65535, not '{s}'");
        let (a, b) = s.split_once('-').unwrap_or((s, s));
        Ok(Self {
            start: a.parse().map_err(|_| bad())?,
            end: b.parse().map_err(|_| bad())?,
        })
    }
}

/// Serde and the CLI read both types as one text word.
macro_rules! text_scalar {
    ($($t:ty),*) => {$(
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
            }
        }
        impl CliValue for $t {
            fn kind() -> Kind {
                Kind::Str
            }
        }
    )*};
}
text_scalar!(AclProtocol, PortRange);

/// One match-and-act line of an `Acl`. A field left unset matches anything;
/// all set fields must match.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one independent on/off switch per match flag, edited one by one"
)]
pub struct AclRule {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n))
    )]
    #[cli(key)]
    /// Rule name, 1 to 64 characters (letters, digits, `_`, `-`), unique within the ACL; the key.
    pub name: String,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = AclRuleAction)]
    /// What to do with a packet that matches.
    pub action: AclAction,

    #[serde(default)]
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[cli(topic = AclRuleProtocol)]
    /// IP protocol to match: `tcp`, `udp`, `icmp`, `icmpv6` or a number; `None` matches any.
    pub protocol: Option<AclProtocol>,

    #[serde(default)]
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[cli(topic = AclRuleSource)]
    /// Source prefix; its family limits the rule to IPv4 or IPv6.
    pub source: Option<IpNet>,

    #[serde(default)]
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[cli(topic = AclRuleDestination)]
    /// Destination prefix, in the same family as `source`.
    pub destination: Option<IpNet>,

    #[serde(default)]
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[cli(topic = AclRuleSourcePort)]
    /// TCP/UDP source port or range (`80`, `1024-65535`).
    pub source_port: Option<PortRange>,

    #[serde(default)]
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[cli(topic = AclRuleDestinationPort)]
    /// TCP/UDP destination port or range.
    pub destination_port: Option<PortRange>,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = AclRuleEstablished)]
    /// Match TCP segments with ACK or RST set (stateless, not connection tracking).
    pub established: bool,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = AclRuleIcmpType, words = "icmp-type")]
    /// ICMP/ICMPv6 message type.
    pub icmp_type: Option<u8>,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = AclRuleIcmpCode, words = "icmp-code")]
    /// ICMP/ICMPv6 message code; needs `icmp-type`.
    pub icmp_code: Option<u8>,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = AclRuleLog)]
    /// Log the packets this rule matches.
    pub log: bool,
}

/// A named list of rules evaluated in order; the first match wins.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct Acl {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.acls, |a| &a.name))
    )]
    #[cli(key)]
    /// ACL name, 1 to 64 characters (letters, digits, `_`, `-`); the key.
    pub name: String,

    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = AclDefaultAction, words = "default-action")]
    /// What happens to IP packets no rule matches; `deny` unless set.
    pub default_action: AclAction,

    #[serde(default)]
    #[garde(dive, custom(|r: &Vec<AclRule>, _ctx: &Config| valid_rules(r)))]
    #[cli(topic = AclRule, words = "rule")]
    /// The rules, in evaluation order.
    pub rules: Vec<AclRule>,
}

fn valid_rules(rules: &[AclRule]) -> garde::Result {
    for (i, r) in rules.iter().enumerate() {
        if rules[..i].iter().any(|o| o.name == r.name) {
            return Err(garde::Error::new(format!(
                "rule '{}' is listed twice",
                r.name
            )));
        }
        crate::validators::no_normalized_collision(&r.name, rules.iter().map(|o| o.name.as_str()))?;
        valid_rule(r).map_err(|why| garde::Error::new(format!("rule '{}': {why}", r.name)))?;
    }
    Ok(())
}

fn valid_rule(r: &AclRule) -> Result<(), &'static str> {
    use AclProtocol::{Icmp, Icmpv6, Number, Tcp, Udp};
    if let Some(Number(1 | 6 | 17 | 58)) = r.protocol {
        return Err("use the name for protocol 1, 6, 17 and 58 (icmp, tcp, udp, icmpv6)");
    }
    if let (Some(s), Some(d)) = (r.source, r.destination)
        && s.addr().is_ipv4() != d.addr().is_ipv4()
    {
        return Err("source and destination must be in the same address family");
    }
    let v4 = r.source.or(r.destination).map(|n| n.addr().is_ipv4());
    match (r.protocol, v4) {
        (Some(Icmp), Some(false)) => return Err("icmp is IPv4: use icmpv6 with an IPv6 prefix"),
        (Some(Icmpv6), Some(true)) => return Err("icmpv6 is IPv6: use icmp with an IPv4 prefix"),
        _ => {}
    }
    let l4 = matches!(r.protocol, Some(Tcp | Udp));
    let icmp = matches!(r.protocol, Some(Icmp | Icmpv6));
    for p in [r.source_port, r.destination_port].into_iter().flatten() {
        if !l4 {
            return Err("ports need protocol tcp or udp");
        }
        if p.start == 0 || p.end == 0 {
            return Err("port 0 is not valid");
        }
        if p.start > p.end {
            return Err("port range start is above its end");
        }
    }
    if r.established && r.protocol != Some(Tcp) {
        return Err("established needs protocol tcp");
    }
    if (r.icmp_type.is_some() || r.icmp_code.is_some()) && !icmp {
        return Err("icmp-type and icmp-code need protocol icmp or icmpv6");
    }
    if r.icmp_code.is_some() && r.icmp_type.is_none() {
        return Err("icmp-code needs icmp-type");
    }
    Ok(())
}

/// `Config.acls`: every `acl in/out` must name an existing ACL, and only on
/// an interface or aggregate that can carry one. Wired here, not on the
/// attach fields, so the placement rules read together.
pub(crate) fn valid_acl_references(_acls: &[Acl], ctx: &Config) -> garde::Result {
    let known = |n: &Option<String>| match n {
        Some(n) if !ctx.acls.iter().any(|a| &a.name == n) => {
            Err(garde::Error::new(format!("acl '{n}' does not exist")))
        }
        _ => Ok(()),
    };
    for i in &ctx.interfaces {
        known(&i.acl_in)?;
        known(&i.acl_out)?;
        for s in &i.subinterfaces {
            known(&s.acl_in)?;
            known(&s.acl_out)?;
        }
        one_per_device(&i.name, [&i.acl_in, &i.acl_out], &i.subinterfaces)?;
        if i.acl_in.is_none() && i.acl_out.is_none() {
            continue;
        }
        let refuse = |why: &str| Err(garde::Error::new(format!("interface {}: {why}", i.name)));
        if loopback_table_name(&i.name).is_some() {
            return refuse("an acl cannot be attached to a loopback");
        }
        if i.port_aggregate.is_some() {
            return refuse(
                "an acl cannot be attached to a port aggregate member: attach it to the aggregate",
            );
        }
        if i.switching_profile.is_some() {
            return refuse("an acl cannot be attached to a switching-profile port");
        }
    }
    for a in &ctx.port_aggregates {
        known(&a.acl_in)?;
        known(&a.acl_out)?;
        for s in &a.subinterfaces {
            known(&s.acl_in)?;
            known(&s.acl_out)?;
        }
        one_per_device(&a.name, [&a.acl_in, &a.acl_out], &a.subinterfaces)?;
    }
    Ok(())
}

/// The untagged (tag 0) subinterface is its parent's own kernel device: one
/// ACL per direction there, set on either, not both.
fn one_per_device(
    name: &str,
    parent: [&Option<String>; 2],
    subs: &[super::Subinterface],
) -> garde::Result {
    for s in subs.iter().filter(|s| s.tag == 0) {
        for (dir, p, s) in [("in", parent[0], &s.acl_in), ("out", parent[1], &s.acl_out)] {
            if p.is_some() && s.is_some() {
                return Err(garde::Error::new(format!(
                    "{name}: acl {dir} is set on both the interface and its untagged subinterface, \
                     which are one device: keep one"
                )));
            }
        }
    }
    Ok(())
}

/// One device with `flowspec` set (#562): its parent `Interface` or
/// `PortAggregate` (`aggregate`), the subinterface tag (0: the parent
/// itself), and the routing table whose BGP instance's rules it enforces:
/// the subinterface's, the untagged subinterface's for the parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowspecPoint<'a> {
    /// The `Interface` or `PortAggregate` name.
    pub parent: &'a str,
    /// `parent` is a `PortAggregate`.
    pub aggregate: bool,
    /// Subinterface tag; 0 is the parent's own device.
    pub tag: u16,
    /// The owning routing table, if the device has one.
    pub table: Option<&'a str>,
}

impl FlowspecPoint<'_> {
    /// The device as the user names it: `parent` or `parent.tag`.
    #[must_use]
    pub fn device(&self) -> String {
        if self.tag == 0 {
            self.parent.to_string()
        } else {
            format!("{}.{}", self.parent, self.tag)
        }
    }
}

/// Every device with `flowspec` set, in config order.
#[must_use]
pub fn flowspec_points(cfg: &Config) -> Vec<FlowspecPoint<'_>> {
    let parents = cfg
        .interfaces
        .iter()
        .map(|i| (i.name.as_str(), false, i.flowspec, &i.subinterfaces[..]))
        .chain(
            cfg.port_aggregates
                .iter()
                .map(|a| (a.name.as_str(), true, a.flowspec, &a.subinterfaces[..])),
        );
    let mut out = Vec::new();
    for (parent, aggregate, own, subs) in parents {
        let point = |tag: u16| FlowspecPoint {
            parent,
            aggregate,
            tag,
            table: subs
                .iter()
                .find(|s| s.tag == tag)
                .and_then(|s| s.routing_table.as_deref()),
        };
        if own {
            out.push(point(0));
        }
        out.extend(subs.iter().filter(|s| s.flowspec).map(|s| point(s.tag)));
    }
    out
}

const FLOWSPEC_TWICE: &str = "flowspec is set on both the device and its untagged \
                              subinterface, which are one device: keep one";

/// `flowspec` placement (#562): the `acl in` rules (no loopback, aggregate
/// member or switching-profile port; not on both a parent and its untagged
/// subinterface), plus a routing table that a BGP instance uses.
pub(crate) fn valid_flowspec_placements(_acls: &[Acl], ctx: &Config) -> garde::Result {
    let refuse = |name: &str, why: &str| Err(garde::Error::new(format!("{name}: {why}")));
    let any = |own: bool, subs: &[super::Subinterface]| own || subs.iter().any(|s| s.flowspec);
    let twice = |own: bool, subs: &[super::Subinterface]| {
        own && subs.iter().any(|s| s.tag == 0 && s.flowspec)
    };
    for i in &ctx.interfaces {
        if !any(i.flowspec, &i.subinterfaces) {
            continue;
        }
        if loopback_table_name(&i.name).is_some() {
            return refuse(&i.name, "flowspec cannot be set on a loopback");
        }
        if i.port_aggregate.is_some() {
            return refuse(
                &i.name,
                "flowspec cannot be set on a port aggregate member: set it on the aggregate",
            );
        }
        if i.switching_profile.is_some() {
            return refuse(
                &i.name,
                "flowspec cannot be set on a switching-profile port",
            );
        }
        if twice(i.flowspec, &i.subinterfaces) {
            return refuse(&i.name, FLOWSPEC_TWICE);
        }
    }
    for a in &ctx.port_aggregates {
        if a.switching_profile.is_some() && any(a.flowspec, &a.subinterfaces) {
            return refuse(
                &a.name,
                "flowspec cannot be set on a switching-profile port",
            );
        }
        if twice(a.flowspec, &a.subinterfaces) {
            return refuse(&a.name, FLOWSPEC_TWICE);
        }
    }
    for p in flowspec_points(ctx) {
        let Some(table) = p.table else {
            return refuse(
                &p.device(),
                "flowspec needs a routing table (on the untagged subinterface for the device itself)",
            );
        };
        if !ctx
            .bgp_instances
            .iter()
            .any(|b| b.routing_table.as_deref() == Some(table))
        {
            return refuse(
                &p.device(),
                &format!("flowspec needs a bgp instance in routing table {table}"),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Interface, PortAggregate, Subinterface};

    fn rule(f: impl FnOnce(&mut AclRule)) -> AclRule {
        let mut r = AclRule {
            name: "r".into(),
            ..Default::default()
        };
        f(&mut r);
        r
    }

    fn ok(f: impl FnOnce(&mut AclRule)) -> bool {
        let c = Config {
            acls: vec![Acl {
                name: "A".into(),
                rules: vec![rule(f)],
                ..Default::default()
            }],
            ..Default::default()
        };
        c.validate_with(&c).is_ok()
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "assigned straight to Option fields"
    )]
    fn net(s: &str) -> Option<IpNet> {
        Some(s.parse().unwrap())
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "assigned straight to Option fields"
    )]
    fn port(a: u16, b: u16) -> Option<PortRange> {
        Some(PortRange { start: a, end: b })
    }

    #[test]
    fn a_full_acl_commits() {
        assert!(ok(|r| {
            r.protocol = Some(AclProtocol::Tcp);
            r.source = net("10.0.0.0/8");
            r.destination = net("192.0.2.0/24");
            r.source_port = port(1024, 65535);
            r.destination_port = port(179, 179);
            r.established = true;
            r.log = true;
        }));
        assert!(ok(|r| {
            r.protocol = Some(AclProtocol::Icmpv6);
            r.source = net("2001:db8::/32");
            r.icmp_type = Some(135);
            r.icmp_code = Some(0);
        }));
        assert!(ok(|r| r.protocol = Some(AclProtocol::Number(89))));
        assert!(ok(|_| {}));
    }

    #[test]
    fn family_rules() {
        assert!(!ok(|r| {
            r.source = net("10.0.0.0/8");
            r.destination = net("2001:db8::/32");
        }));
        assert!(!ok(|r| {
            r.protocol = Some(AclProtocol::Icmp);
            r.source = net("2001:db8::/32");
        }));
        assert!(!ok(|r| {
            r.protocol = Some(AclProtocol::Icmpv6);
            r.destination = net("10.0.0.0/8");
        }));
    }

    #[test]
    fn port_rules() {
        assert!(!ok(|r| r.destination_port = port(80, 80)));
        assert!(!ok(|r| {
            r.protocol = Some(AclProtocol::Icmp);
            r.source_port = port(80, 80);
        }));
        for bad in [port(0, 80), port(80, 0), port(90, 80)] {
            assert!(!ok(|r| {
                r.protocol = Some(AclProtocol::Udp);
                r.destination_port = bad;
            }));
        }
    }

    #[test]
    fn established_and_icmp_fields() {
        assert!(!ok(|r| r.established = true));
        assert!(!ok(|r| {
            r.protocol = Some(AclProtocol::Udp);
            r.established = true;
        }));
        assert!(!ok(|r| r.icmp_type = Some(8)));
        assert!(!ok(|r| {
            r.protocol = Some(AclProtocol::Tcp);
            r.icmp_code = Some(0);
        }));
        assert!(!ok(|r| {
            r.protocol = Some(AclProtocol::Icmp);
            r.icmp_code = Some(0);
        }));
    }

    #[test]
    fn named_protocol_numbers_use_the_name() {
        assert!(!ok(|r| r.protocol = Some(AclProtocol::Number(6))));
        assert!(!ok(|r| r.protocol = Some(AclProtocol::Number(58))));
    }

    #[test]
    fn names_are_checked_and_unique() {
        assert!(!ok(|r| r.name = "bad name".into()));
        assert!(!ok(|r| r.name = String::new()));
        let mut c = Config {
            acls: vec![Acl {
                name: "A".into(),
                rules: vec![rule(|_| {}), rule(|_| {})],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(c.validate_with(&c).is_err());
        c.acls[0].rules.pop();
        c.acls.push(c.acls[0].clone());
        assert!(c.validate_with(&c).is_err());
        c.acls[1].name = "bad name".into();
        assert!(c.validate_with(&c).is_err());
    }

    #[test]
    fn default_action_defaults_to_deny() {
        assert_eq!(Acl::default().default_action, AclAction::Deny);
        let a: Acl = serde_json::from_str(r#"{"name":"A"}"#).unwrap();
        assert_eq!(a.default_action, AclAction::Deny);
        assert_eq!(a.rules.len(), 0);
    }

    #[test]
    fn protocol_text_form() {
        for (s, p) in [
            ("tcp", AclProtocol::Tcp),
            ("udp", AclProtocol::Udp),
            ("icmp", AclProtocol::Icmp),
            ("icmpv6", AclProtocol::Icmpv6),
            ("89", AclProtocol::Number(89)),
        ] {
            assert_eq!(s.parse::<AclProtocol>().unwrap(), p);
            assert_eq!(p.to_string(), s);
            assert_eq!(serde_json::to_string(&p).unwrap(), format!("\"{s}\""));
            let bytes = postcard::to_allocvec(&p).unwrap();
            assert_eq!(postcard::from_bytes::<AclProtocol>(&bytes).unwrap(), p);
        }
        assert_eq!("6".parse::<AclProtocol>().unwrap(), AclProtocol::Tcp);
        assert_eq!("1".parse::<AclProtocol>().unwrap(), AclProtocol::Icmp);
        assert_eq!("17".parse::<AclProtocol>().unwrap(), AclProtocol::Udp);
        assert_eq!("58".parse::<AclProtocol>().unwrap(), AclProtocol::Icmpv6);
        assert!("256".parse::<AclProtocol>().is_err());
        assert!("ospf".parse::<AclProtocol>().is_err());
        assert_eq!(AclProtocol::Number(89).number(), 89);
        assert_eq!(AclProtocol::Tcp.number(), 6);
        assert_eq!(AclProtocol::Udp.number(), 17);
        assert_eq!(AclProtocol::Icmp.number(), 1);
        assert_eq!(AclProtocol::Icmpv6.number(), 58);
        assert!(serde_json::from_str::<AclProtocol>("\"x\"").is_err());
    }

    #[test]
    fn port_range_text_form() {
        for (s, p) in [("80", (80, 80)), ("1024-65535", (1024, 65535))] {
            let r = s.parse::<PortRange>().unwrap();
            assert_eq!((r.start, r.end), p);
            assert_eq!(r.to_string(), s);
            assert_eq!(serde_json::to_string(&r).unwrap(), format!("\"{s}\""));
            let bytes = postcard::to_allocvec(&r).unwrap();
            assert_eq!(postcard::from_bytes::<PortRange>(&bytes).unwrap(), r);
        }
        assert!("0".parse::<PortRange>().is_ok());
        for bad in ["", "-", "a", "1-", "70000", "1-2-3"] {
            assert!(bad.parse::<PortRange>().is_err(), "{bad}");
        }
    }

    #[test]
    fn scalars_are_cli_words() {
        assert!(matches!(AclProtocol::kind(), Kind::Str));
        assert!(matches!(PortRange::kind(), Kind::Str));
    }

    fn attach(f: impl FnOnce(&mut Config)) -> bool {
        let mut c = Config {
            acls: vec![Acl {
                name: "A".into(),
                ..Default::default()
            }],
            interfaces: vec![Interface {
                name: "eth0".into(),
                acl_in: Some("A".into()),
                acl_out: Some("A".into()),
                flowspec: false,
                ..Default::default()
            }],
            ..Default::default()
        };
        f(&mut c);
        c.validate_with(&c).is_ok()
    }

    #[test]
    fn attach_points() {
        assert!(attach(|_| {}));
        let sub = |c: &mut Config, name: &str| {
            c.interfaces[0].acl_in = None;
            c.interfaces[0].acl_out = None;
            c.interfaces[0].subinterfaces = vec![Subinterface {
                tag: 100,
                acl_out: Some(name.into()),
                flowspec: false,
                ..Default::default()
            }];
        };
        assert!(attach(|c| sub(c, "A")));
        assert!(!attach(|c| sub(c, "nope")));
        assert!(!attach(|c| c.interfaces[0].acl_in = Some("nope".into())));
        assert!(!attach(|c| c.interfaces[0].acl_out = Some("nope".into())));
        let agg = |c: &mut Config, name: &str| {
            c.port_aggregates = vec![PortAggregate {
                name: "bond0".into(),
                acl_in: Some(name.into()),
                subinterfaces: vec![Subinterface {
                    tag: 5,
                    acl_in: Some(name.into()),
                    ..Default::default()
                }],
                ..Default::default()
            }];
        };
        assert!(attach(|c| agg(c, "A")));
        assert!(!attach(|c| agg(c, "nope")));
        assert!(!attach(|c| {
            agg(c, "A");
            c.port_aggregates[0].subinterfaces[0].acl_in = Some("nope".into());
        }));
    }

    #[test]
    fn one_acl_per_direction_on_the_untagged_device() {
        let untagged = |c: &mut Config, tag: u16, out: bool| {
            let sub = Subinterface {
                tag,
                acl_in: (!out).then(|| "A".into()),
                acl_out: out.then(|| "A".into()),
                flowspec: false,
                ..Default::default()
            };
            c.interfaces[0].subinterfaces = vec![sub.clone()];
            c.port_aggregates = vec![PortAggregate {
                name: "agg".into(),
                acl_in: Some("A".into()),
                subinterfaces: vec![sub],
                ..Default::default()
            }];
        };
        assert!(!attach(|c| untagged(c, 0, false)));
        assert!(!attach(|c| untagged(c, 0, true)));
        assert!(attach(|c| untagged(c, 5, false)));
        assert!(!attach(|c| {
            untagged(c, 0, false);
            c.interfaces[0].acl_in = None;
        }));
        assert!(attach(|c| {
            untagged(c, 0, true);
            c.interfaces[0].acl_out = None;
        }));
    }

    #[test]
    fn attach_refused_where_it_cannot_apply() {
        use crate::schema::{RoutingTable, SwitchingProfile};
        let base = |c: &mut Config| {
            c.port_aggregates = vec![PortAggregate {
                name: "bond0".into(),
                ..Default::default()
            }];
            c.switching_profiles = vec![SwitchingProfile {
                name: "sp".into(),
                ..Default::default()
            }];
            c.routing_tables = vec![RoutingTable {
                name: "main".into(),
                ..Default::default()
            }];
        };
        // Each placement is valid without the ACL, so the ACL is what fails.
        let placed = |f: fn(&mut Interface), acl: bool| {
            attach(|c| {
                base(c);
                f(&mut c.interfaces[0]);
                if !acl {
                    c.interfaces[0].acl_in = None;
                    c.interfaces[0].acl_out = None;
                }
            })
        };
        let member: fn(&mut Interface) = |i| i.port_aggregate = Some("bond0".into());
        let switched: fn(&mut Interface) = |i| i.switching_profile = Some("sp".into());
        let loopback: fn(&mut Interface) = |i| i.name = "loopback-main".into();
        for f in [member, switched, loopback] {
            assert!(placed(f, false));
            assert!(!placed(f, true));
        }
    }

    /// #562: `eth0` (untagged in `rt1`, `.100` in `rt2`) and `bond0` (`.7`
    /// in `rt1`); `b1` runs in `rt1`.
    fn flowspec(f: impl FnOnce(&mut Config)) -> Result<(), String> {
        use crate::schema::{BgpInstance, RoutingTable};
        let sub = |tag, rt: &str| Subinterface {
            tag,
            routing_table: Some(rt.into()),
            ..Default::default()
        };
        let mut c = Config {
            routing_tables: vec![
                RoutingTable {
                    name: "rt1".into(),
                    bgp_instance: Some("b1".into()),
                    ..Default::default()
                },
                RoutingTable {
                    name: "rt2".into(),
                    ..Default::default()
                },
            ],
            bgp_instances: vec![BgpInstance {
                name: "b1".into(),
                routing_table: Some("rt1".into()),
                asn: 65000,
                ..Default::default()
            }],
            interfaces: vec![Interface {
                name: "eth0".into(),
                subinterfaces: vec![sub(0, "rt1"), sub(100, "rt2")],
                ..Default::default()
            }],
            port_aggregates: vec![PortAggregate {
                name: "bond0".into(),
                subinterfaces: vec![sub(7, "rt1")],
                ..Default::default()
            }],
            ..Default::default()
        };
        f(&mut c);
        c.validate_with(&c).map_err(|e| e.to_string())
    }

    #[test]
    fn flowspec_placement() {
        flowspec(|_| {}).unwrap();
        flowspec(|c| c.interfaces[0].flowspec = true).unwrap();
        flowspec(|c| c.interfaces[0].subinterfaces[0].flowspec = true).unwrap();
        flowspec(|c| c.port_aggregates[0].subinterfaces[0].flowspec = true).unwrap();
        let err = flowspec(|c| {
            c.interfaces[0].flowspec = true;
            c.interfaces[0].subinterfaces[0].flowspec = true;
        })
        .unwrap_err();
        assert!(err.contains("keep one"), "{err}");
        // rt2 has no BGP instance; the bond itself has no table.
        let err = flowspec(|c| c.interfaces[0].subinterfaces[1].flowspec = true).unwrap_err();
        assert!(
            err.contains("eth0.100: flowspec needs a bgp instance in routing table rt2"),
            "{err}"
        );
        let err = flowspec(|c| c.port_aggregates[0].flowspec = true).unwrap_err();
        assert!(
            err.contains("bond0: flowspec needs a routing table"),
            "{err}"
        );
        let err = flowspec(|c| {
            c.port_aggregates[0].subinterfaces.push(Subinterface {
                tag: 0,
                routing_table: Some("rt1".into()),
                flowspec: true,
                ..Default::default()
            });
            c.port_aggregates[0].flowspec = true;
        })
        .unwrap_err();
        assert!(err.contains("bond0: flowspec is set on both"), "{err}");
    }

    #[test]
    fn flowspec_refused_where_acl_is() {
        use crate::schema::SwitchingProfile;
        let sp = |c: &mut Config| {
            c.switching_profiles = vec![SwitchingProfile {
                name: "sp".into(),
                ..Default::default()
            }];
        };
        let refused = |f: fn(&mut Config), why: &str| {
            let err = flowspec(|c| {
                sp(c);
                f(c);
            })
            .unwrap_err();
            assert!(err.contains(why), "{err}");
        };
        refused(
            |c| {
                c.interfaces.push(Interface {
                    name: "loopback-rt1".into(),
                    flowspec: true,
                    ..Default::default()
                });
            },
            "loopback-rt1: flowspec cannot be set on a loopback",
        );
        refused(
            |c| {
                c.interfaces.push(Interface {
                    name: "eth1".into(),
                    port_aggregate: Some("bond0".into()),
                    flowspec: true,
                    ..Default::default()
                });
            },
            "eth1: flowspec cannot be set on a port aggregate member",
        );
        refused(
            |c| {
                c.interfaces.push(Interface {
                    name: "eth2".into(),
                    switching_profile: Some("sp".into()),
                    flowspec: true,
                    ..Default::default()
                });
            },
            "eth2: flowspec cannot be set on a switching-profile port",
        );
        refused(
            |c| {
                c.port_aggregates[0].switching_profile = Some("sp".into());
                c.port_aggregates[0].subinterfaces.clear();
                c.port_aggregates[0].flowspec = true;
            },
            "bond0: flowspec cannot be set on a switching-profile port",
        );
    }

    #[test]
    fn flowspec_points_name_their_device_and_table() {
        let mut c = Config::default();
        c.interfaces.push(Interface {
            name: "eth0".into(),
            flowspec: true,
            subinterfaces: vec![
                Subinterface {
                    tag: 0,
                    routing_table: Some("rt1".into()),
                    ..Default::default()
                },
                Subinterface {
                    tag: 5,
                    flowspec: true,
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        c.port_aggregates.push(PortAggregate {
            name: "agg".into(),
            flowspec: true,
            ..Default::default()
        });
        let shown: Vec<_> = flowspec_points(&c)
            .iter()
            .map(|p| (p.device(), p.aggregate, p.table))
            .collect();
        assert_eq!(
            shown,
            [
                ("eth0".to_string(), false, Some("rt1")),
                ("eth0.5".to_string(), false, None),
                ("agg".to_string(), true, None),
            ]
        );
    }
}
