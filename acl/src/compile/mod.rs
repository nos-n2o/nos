//! An `Acl` to tc flower filters (pure). A level is one flower priority per
//! family in the ACL's chain: tc walks the priorities in order. `optimize`
//! drops shadowed and trailing rules and packs pairwise disjoint rules into
//! one level, so the first matching level is the first matching user rule.

mod keys;
mod optimize;
mod rule;

pub(crate) use rule::LATER_FRAGMENT;

use nos_proto::schema::{Acl, AclAction};
use nos_tc::{FlowerKeys, Protocol};

/// The action cookie of the default-action filters; a rule's is its index.
pub const DEFAULT_COOKIE: u32 = u32::MAX;

/// The cookie of the implicit IPv6 ND permit filters (deny default only).
pub const IMPLICIT_ND_COOKIE: u32 = u32::MAX - 1;

/// One flower filter of a level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// `Ip` or `Ipv6`: the filter's family (its tc `protocol`).
    pub protocol: Protocol,
    pub keys: FlowerKeys,
    pub action: AclAction,
    /// The user rule's index in `Acl.rules` (the tc action cookie, read back
    /// by `show acl`'s counters, #543).
    pub rule: u32,
    /// The rule's `log`: a `sample` action precedes the verdict (#544).
    pub log: bool,
}

/// Filters that may share priorities: at most one of them matches a packet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Level {
    pub filters: Vec<Filter>,
}

/// What the driver installs in one chain: the levels in order, then a
/// keyless filter per family with `default_action`. Non-IP frames match no
/// filter and pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub levels: Vec<Level>,
    pub default_action: AclAction,
    /// User rules in the ACL, dropped ones included.
    pub rules: usize,
    /// Rules (indices into `Acl.rules`) no packet can reach because one
    /// earlier rule matches everything they do: no filter, counter reads 0.
    pub shadowed: Vec<u32>,
    /// Trailing rules whose action is the default's: no filter, counter 0.
    pub trailing: Vec<u32>,
    /// Implicit ND permit filters kept: 0 when the default is permit or a
    /// user rule shadows all four.
    pub implicit: usize,
    /// Name and action of every user rule, by index (`show acl`, #543).
    pub rule_names: Vec<(String, AclAction)>,
}

impl Compiled {
    /// Every filter, the two defaults included.
    pub fn filters(&self) -> usize {
        self.levels.iter().map(|l| l.filters.len()).sum::<usize>() + 2
    }

    /// Some filter samples to psample (a kept `log` rule).
    pub fn logs(&self) -> bool {
        self.levels.iter().flat_map(|l| &l.filters).any(|f| f.log)
    }
}

/// The tc priority of `level`'s `protocol` filters: two per level, because
/// the kernel refuses two protocols at one priority. The defaults sit at
/// `level == levels.len()`.
pub fn prio(level: usize, protocol: Protocol) -> u16 {
    let base = 2 * level + 1;
    let p = if protocol == Protocol::Ipv6 {
        base + 1
    } else {
        base
    };
    u16::try_from(p).expect("compile bounds the level count")
}

/// Most levels a chain holds: their priorities and the defaults' fit `u16`.
pub const MAX_LEVELS: usize = (u16::MAX as usize - 2) / 2;

/// Compiles `acl`. Fails only when it would not fit tc's priority space.
pub fn compile(acl: &Acl) -> Result<Compiled, String> {
    compile_within(acl, MAX_LEVELS)
}

/// [`compile`] with a lower level limit (tests of the failure path).
pub fn compile_within(acl: &Acl, max_levels: usize) -> Result<Compiled, String> {
    let p = optimize::pack(acl);
    if p.levels.len() > max_levels {
        return Err(format!(
            "{} levels, at most {max_levels} fit in tc's priorities",
            p.levels.len()
        ));
    }
    Ok(Compiled {
        rules: acl.rules.len(),
        levels: p.levels,
        default_action: acl.default_action,
        shadowed: p.shadowed,
        trailing: p.trailing,
        implicit: p.implicit,
        rule_names: acl
            .rules
            .iter()
            .map(|r| (r.name.clone(), r.action))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use nos_proto::schema::{AclProtocol, AclRule};

    use super::*;

    fn rule(name: &str, action: AclAction, protocol: Option<AclProtocol>) -> AclRule {
        AclRule {
            name: name.into(),
            action,
            protocol,
            ..Default::default()
        }
    }

    #[test]
    fn overlapping_rules_keep_their_order_then_defaults() {
        let acl = Acl {
            name: "A".into(),
            default_action: AclAction::Deny,
            rules: vec![
                rule("a", AclAction::Permit, Some(AclProtocol::Icmp)),
                rule("b", AclAction::Permit, None),
            ],
        };
        // b (any) overlaps a, but permit == ... deny default: both stay.
        let c = compile(&acl).unwrap();
        assert_eq!((c.rules, c.shadowed.len(), c.levels.len()), (2, 0, 2));
        assert_eq!(c.levels[0].filters.len(), 1);
        assert_eq!(c.levels[0].filters[0].rule, 0);
        assert_eq!(c.levels[1].filters.len(), 2);
        assert!(c.levels[1].filters.iter().all(|f| f.rule == 1));
        assert_eq!(c.default_action, AclAction::Deny);
        assert_eq!(c.filters(), 5);
        assert!(!c.logs());
    }

    #[test]
    fn a_kept_log_rule_logs_on_each_of_its_filters() {
        let mut logged = rule("l", AclAction::Deny, Some(AclProtocol::Tcp));
        logged.log = true;
        logged.established = true;
        let acl = Acl {
            name: "A".into(),
            default_action: AclAction::Permit,
            rules: vec![rule("a", AclAction::Deny, Some(AclProtocol::Icmp)), logged],
        };
        let c = compile(&acl).unwrap();
        assert!(c.logs());
        let f: Vec<_> = c.levels.iter().flat_map(|l| &l.filters).collect();
        // The ACK and RST filters of both families log, the ICMP one not.
        assert_eq!(f.iter().filter(|f| f.log).count(), 4);
        assert!(f.iter().all(|f| f.log == (f.rule == 1)));
    }

    #[test]
    fn dropped_rules_still_count_and_are_reported() {
        let acl = Acl {
            name: "A".into(),
            default_action: AclAction::Permit,
            rules: vec![
                rule("a", AclAction::Deny, Some(AclProtocol::Icmp)),
                rule("b", AclAction::Deny, Some(AclProtocol::Icmp)),
                rule("c", AclAction::Permit, None),
            ],
        };
        let c = compile(&acl).unwrap();
        assert_eq!(
            (c.rules, &c.shadowed[..], &c.trailing[..]),
            (3, &[1][..], &[2][..])
        );
        assert_eq!((c.levels.len(), c.filters()), (1, 3));
    }

    #[test]
    fn a_deny_default_adds_four_implicit_nd_filters() {
        let c = compile(&Acl::default()).unwrap();
        assert_eq!((c.levels.len(), c.implicit, c.filters()), (1, 4, 6));
        let types: Vec<_> = c.levels[0]
            .filters
            .iter()
            .map(|f| (f.rule, f.keys.icmp_type, f.action))
            .collect();
        let want: Vec<_> = (133..=136)
            .map(|t| (IMPLICIT_ND_COOKIE, Some(t), AclAction::Permit))
            .collect();
        assert_eq!(types, want);
        let permit = Acl {
            default_action: AclAction::Permit,
            ..Default::default()
        };
        let c = compile(&permit).unwrap();
        assert_eq!((c.levels.len(), c.implicit, c.filters()), (0, 0, 2));
    }

    #[test]
    fn an_earlier_icmpv6_rule_shadows_the_implicit_permit() {
        let mut deny135 = rule("d", AclAction::Deny, Some(AclProtocol::Icmpv6));
        deny135.icmp_type = Some(135);
        let acl = |rules| Acl {
            default_action: AclAction::Deny,
            rules,
            ..Default::default()
        };
        let all = acl(vec![rule(
            "p",
            AclAction::Permit,
            Some(AclProtocol::Icmpv6),
        )]);
        let c = compile(&all).unwrap();
        assert_eq!((c.implicit, c.levels.len(), c.filters()), (0, 1, 3));
        let c = compile(&acl(vec![deny135])).unwrap();
        // The explicit deny stays; 135 is dropped, the other three are
        // disjoint from it and share its level.
        assert_eq!((c.implicit, c.levels.len()), (3, 1));
        assert_eq!(c.levels[0].filters[0].rule, 0);
        assert!(c.levels[0]
            .filters
            .iter()
            .all(|f| f.rule == 0 || f.keys.icmp_type != Some(135)));
    }

    #[test]
    fn a_trailing_deny_that_meets_nd_is_kept_under_a_deny_default() {
        let acl = |p| Acl {
            default_action: AclAction::Deny,
            rules: vec![rule("d", AclAction::Deny, Some(p))],
            ..Default::default()
        };
        // Popped as the default's twin, it would let ND through.
        let c = compile(&acl(AclProtocol::Icmpv6)).unwrap();
        assert_eq!((c.trailing.len(), c.levels.len()), (0, 1));
        let c = compile(&acl(AclProtocol::Tcp)).unwrap();
        assert_eq!((c.trailing, c.implicit), (vec![0], 4));
    }

    #[test]
    fn priorities_split_families_and_stay_ordered() {
        assert_eq!(prio(0, Protocol::Ip), 1);
        assert_eq!(prio(0, Protocol::Ipv6), 2);
        assert_eq!(prio(1, Protocol::Ip), 3);
        assert_eq!(prio(MAX_LEVELS, Protocol::Ipv6), u16::MAX - 1);
    }

    #[test]
    fn too_many_levels_do_not_fit() {
        let chain = |n: u16| Acl {
            default_action: AclAction::Permit,
            rules: (0..n)
                .map(|i| AclRule {
                    action: AclAction::Deny,
                    destination_port: Some(nos_proto::schema::PortRange { start: 0, end: i }),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(compile_within(&chain(3), 3).unwrap().levels.len(), 3);
        assert!(compile_within(&chain(4), 3)
            .unwrap_err()
            .contains("at most 3"));
    }
}
