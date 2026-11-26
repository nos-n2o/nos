//! `show acl`: the compiled ACL and the counters read from its attachments
//! as an [`AclStatus`] (pure).

use std::collections::BTreeMap;

use nos_proto::schema::AclAction;
use nos_proto::{AclAttachment, AclRuleStatus, AclStatus};

use crate::compile::{Compiled, DEFAULT_COOKIE, IMPLICIT_ND_COOKIE};
use crate::driver::Counter;

/// The `show acl` row of the implicit ND permit; user rule names cannot hold
/// spaces, so it never collides.
const IMPLICIT_ND_NAME: &str = "implicit nd permit";

/// Sums `counters` per cookie across every attachment, so a rule counts once
/// however many filters (family split, `established` pair, packed levels) and
/// devices it compiled to. A cookie no rule owns (a previous run's chain) is
/// ignored.
pub fn status(name: &str, c: &Compiled, attached: &[(AclAttachment, Vec<Counter>)]) -> AclStatus {
    let mut sums: BTreeMap<u32, (u64, u64)> = BTreeMap::new();
    for k in attached.iter().flat_map(|(_, k)| k) {
        let s = sums.entry(k.cookie).or_default();
        s.0 = s.0.saturating_add(k.packets);
        s.1 = s.1.saturating_add(k.bytes);
    }
    let level_of = |rule: usize| {
        c.levels
            .iter()
            .position(|l| l.filters.iter().any(|f| f.rule as usize == rule))
            .map(|l| u32::try_from(l).unwrap_or(u32::MAX))
    };
    let mut rules: Vec<AclRuleStatus> = c
        .rule_names
        .iter()
        .enumerate()
        .map(|(i, (rule, action))| {
            let cookie = u32::try_from(i).unwrap_or(u32::MAX);
            let (packets, bytes) = sums.get(&cookie).copied().unwrap_or_default();
            let dropped = if c.shadowed.contains(&cookie) {
                Some("shadowed")
            } else if c.trailing.contains(&cookie) {
                Some("trailing")
            } else {
                None
            };
            AclRuleStatus {
                name: rule.clone(),
                action: *action,
                dropped: dropped.map(Into::into),
                level: level_of(i),
                packets,
                bytes,
            }
        })
        .collect();
    if c.default_action == AclAction::Deny {
        let (packets, bytes) = sums.get(&IMPLICIT_ND_COOKIE).copied().unwrap_or_default();
        rules.push(AclRuleStatus {
            name: IMPLICIT_ND_NAME.into(),
            action: AclAction::Permit,
            dropped: (c.implicit == 0).then(|| "shadowed".into()),
            level: level_of(IMPLICIT_ND_COOKIE as usize),
            packets,
            bytes,
        });
    }
    let (default_packets, default_bytes) = sums.get(&DEFAULT_COOKIE).copied().unwrap_or_default();
    let mut attached: Vec<AclAttachment> = attached.iter().map(|(a, _)| a.clone()).collect();
    attached.sort();
    AclStatus {
        name: name.into(),
        default_action: c.default_action,
        default_packets,
        default_bytes,
        levels: u32::try_from(c.levels.len()).unwrap_or(u32::MAX),
        filters: u32::try_from(c.filters()).unwrap_or(u32::MAX),
        attached,
        rules,
    }
}

#[cfg(test)]
mod tests {
    use nos_proto::schema::{Acl, AclAction, AclProtocol, AclRule};
    use nos_proto::AclDirection;

    use super::*;
    use crate::compile::compile;

    fn rule(name: &str, action: AclAction, protocol: Option<AclProtocol>) -> AclRule {
        AclRule {
            name: name.into(),
            action,
            protocol,
            ..Default::default()
        }
    }

    fn at(interface: &str, direction: AclDirection) -> AclAttachment {
        AclAttachment {
            interface: interface.into(),
            direction,
        }
    }

    fn k(cookie: u32, packets: u64) -> Counter {
        Counter {
            cookie,
            packets,
            bytes: packets * 100,
        }
    }

    /// `a` icmp deny, `b` a copy of it (shadowed), `d` tcp deny, `c` any
    /// permit (trailing: the default is permit): one level holds a and d.
    fn acl() -> Compiled {
        let acl = Acl {
            name: "E".into(),
            default_action: AclAction::Permit,
            rules: vec![
                rule("a", AclAction::Deny, Some(AclProtocol::Icmp)),
                rule("b", AclAction::Deny, Some(AclProtocol::Icmp)),
                rule("d", AclAction::Deny, Some(AclProtocol::Tcp)),
                rule("c", AclAction::Permit, None),
            ],
        };
        compile(&acl).unwrap()
    }

    #[test]
    fn sums_every_filter_and_device_of_a_rule() {
        let c = acl();
        let s = status(
            "E",
            &c,
            &[
                (
                    at("eth1", AclDirection::Out),
                    // A rule's counters add up across its filters.
                    vec![k(0, 2), k(0, 3), k(2, 1), k(DEFAULT_COOKIE, 7), k(99, 50)],
                ),
                (
                    at("eth0", AclDirection::In),
                    vec![k(0, 10), k(DEFAULT_COOKIE, 1)],
                ),
            ],
        );
        assert_eq!(
            (s.name.as_str(), s.default_packets, s.default_bytes),
            ("E", 8, 800)
        );
        assert_eq!(s.default_action, AclAction::Permit);
        assert_eq!(
            s.attached,
            [at("eth0", AclDirection::In), at("eth1", AclDirection::Out)]
        );
        let got: Vec<_> = s
            .rules
            .iter()
            .map(|r| (r.name.as_str(), r.dropped.as_deref(), r.packets, r.bytes))
            .collect();
        assert_eq!(
            got,
            [
                ("a", None, 15, 1500),
                ("b", Some("shadowed"), 0, 0),
                ("d", None, 1, 100),
                ("c", Some("trailing"), 0, 0),
            ]
        );
        assert_eq!(s.rules[0].level, Some(0));
        assert_eq!(s.rules[1].level, None);
        assert_eq!((s.levels, s.filters), (1, 5));
    }

    #[test]
    fn a_deny_default_shows_the_implicit_nd_row() {
        let mut deny = Acl::default();
        deny.rules.push(rule("a", AclAction::Permit, None));
        let c = compile(&deny).unwrap();
        let s = status(
            "E",
            &c,
            &[(
                at("eth0", AclDirection::In),
                vec![k(IMPLICIT_ND_COOKIE, 4), k(IMPLICIT_ND_COOKIE, 1)],
            )],
        );
        let r = s.rules.last().unwrap();
        assert_eq!(
            (r.name.as_str(), r.action, r.packets, r.bytes, &r.dropped),
            (
                "implicit nd permit",
                AclAction::Permit,
                5,
                500,
                &Some("shadowed".into())
            )
        );
        // `a` permits everything: it shadows all four.
        assert_eq!((s.rules.len(), r.level), (2, None));
        let s = status("E", &compile(&Acl::default()).unwrap(), &[]);
        let r = s.rules.last().unwrap();
        assert_eq!((r.dropped.as_deref(), r.level), (None, Some(0)));
    }

    #[test]
    fn unattached_has_zero_counters_and_no_devices() {
        let s = status("E", &acl(), &[]);
        assert_eq!(s.attached.len(), 0);
        assert_eq!((s.default_packets, s.rules[0].packets), (0, 0));
        assert_eq!(s.rules.len(), 4);
    }
}
