//! Shadow removal, trailing-default removal and level packing (pure).
//!
//! Safety: if two rules match one packet they overlap, so the later one sits
//! at a strictly higher level than the earlier; tc walks the levels in
//! priority order, so the first match is the first user rule. Rules of one
//! level are pairwise disjoint, so their order is irrelevant. `overlap` may
//! over-approximate (costs levels), never under-approximate (the proptest in
//! `tests/equivalence.rs` guards that).
//!
//! ponytail: O(n^2) overlap and containment tests; index by protocol/prefix
//! if ACLs reach thousands of rules.
//! ponytail: a rule is shadowed by one earlier rule only, not by a union of
//! them; box subtraction is the upgrade (exponential in the worst case).
//! ponytail: no cross-rule prefix merge (T6 b), so every filter keeps one
//! rule and counters stay exact.

use nos_proto::schema::{Acl, AclAction};

use super::keys::{contains, overlap};
use super::{rule, Filter, Level};

/// What the passes decided; indices are positions in `Acl.rules`.
pub(super) struct Packed {
    pub levels: Vec<Level>,
    pub shadowed: Vec<u32>,
    pub trailing: Vec<u32>,
    /// Implicit ND filters kept (0 unless the default is deny).
    pub implicit: usize,
}

/// A rule is a set of filters (family split, `established` pair).
fn overlaps(a: &[Filter], b: &[Filter]) -> bool {
    a.iter().any(|x| b.iter().any(|y| overlap(x, y)))
}

/// Every filter of `b` lies inside some filter of the one rule `a`.
fn covers(a: &[Filter], b: &[Filter]) -> bool {
    b.iter().all(|y| a.iter().any(|x| contains(x, y)))
}

pub(super) fn pack(acl: &Acl) -> Packed {
    let mut all: Vec<Vec<Filter>> = (0u32..)
        .zip(&acl.rules)
        .map(|(i, r)| rule::filters(r, i))
        .collect();
    let (mut kept, mut shadowed) = (Vec::<usize>::new(), Vec::<u32>::new());
    for (j, f) in all.iter().enumerate() {
        if kept.iter().any(|&k| covers(&all[k], f)) {
            shadowed.push(u32::try_from(j).expect("rule count fits u32"));
        } else {
            kept.push(j);
        }
    }
    // A `log` rule is observable, so it stays even when it equals the default.
    let deny = acl.default_action == AclAction::Deny;
    let nd = if deny {
        rule::implicit_nd()
    } else {
        Vec::new()
    };
    let mut trailing = Vec::new();
    while let Some(&last) = kept.last() {
        let r = &acl.rules[last];
        // A trailing deny that meets ND must stay: the implicit permit
        // follows it, and it would otherwise equal the default.
        if r.action != acl.default_action || r.log || (deny && overlaps(&all[last], &nd)) {
            break;
        }
        trailing.push(u32::try_from(last).expect("rule count fits u32"));
        kept.pop();
    }
    trailing.reverse();
    // The implicit ND permit is a synthetic last rule, minus the filters a
    // kept user rule already covers (an earlier explicit verdict wins).
    let nd: Vec<Filter> = nd
        .into_iter()
        .filter(|f| !kept.iter().any(|&k| all[k].iter().any(|x| contains(x, f))))
        .collect();
    let implicit = nd.len();
    if !nd.is_empty() {
        kept.push(all.len());
        all.push(nd);
    }
    let mut level_of: Vec<usize> = Vec::with_capacity(kept.len());
    let mut levels: Vec<Level> = Vec::new();
    for (n, &j) in kept.iter().enumerate() {
        let l = (0..n)
            .filter(|&m| overlaps(&all[kept[m]], &all[j]))
            .map(|m| level_of[m] + 1)
            .max()
            .unwrap_or(0);
        level_of.push(l);
        if levels.len() <= l {
            levels.resize_with(l + 1, Level::default);
        }
        levels[l].filters.extend(all[j].iter().cloned());
    }
    Packed {
        levels,
        shadowed,
        trailing,
        implicit,
    }
}

#[cfg(test)]
mod tests {
    use nos_proto::schema::{AclAction, AclProtocol, AclRule};
    use AclAction::{Deny, Permit};

    use super::*;

    fn r(name: &str, action: AclAction, f: impl FnOnce(&mut AclRule)) -> AclRule {
        let mut r = AclRule {
            name: name.into(),
            action,
            ..Default::default()
        };
        f(&mut r);
        r
    }

    fn acl(default_action: AclAction, rules: Vec<AclRule>) -> Acl {
        Acl {
            name: "A".into(),
            default_action,
            rules,
        }
    }

    fn dst(s: &str) -> impl FnOnce(&mut AclRule) + '_ {
        move |r| r.destination = Some(s.parse().unwrap())
    }

    /// The distinct user rules of each level, in order.
    fn rules_at(p: &Packed) -> Vec<Vec<u32>> {
        p.levels
            .iter()
            .map(|l| {
                let mut v: Vec<u32> = l.filters.iter().map(|f| f.rule).collect();
                v.dedup();
                v
            })
            .collect()
    }

    #[test]
    fn disjoint_rules_share_a_level() {
        let a = acl(
            Permit,
            vec![
                r("a", Deny, dst("10.0.0.0/25")),
                r("b", Deny, dst("10.0.0.128/25")),
                r("c", Deny, |r| r.protocol = Some(AclProtocol::Icmpv6)),
            ],
        );
        let p = pack(&a);
        assert_eq!(rules_at(&p), [[0, 1, 2]]);
        assert_eq!((p.shadowed.len(), p.trailing.len()), (0, 0));
    }

    #[test]
    fn a_rule_sits_one_level_above_the_highest_rule_it_overlaps() {
        // a, b and c nest (levels 0, 1, 2); d is IPv6 only (level 0); e
        // meets only c, so it goes to level 3 (not 1: the max rule).
        let tcp = |r: &mut AclRule| {
            r.protocol = Some(AclProtocol::Tcp);
            r.destination = Some("10.0.0.0/8".parse().unwrap());
        };
        let a = acl(
            Permit,
            vec![
                r("a", Deny, dst("10.0.0.0/25")),
                r("b", Permit, dst("10.0.0.0/24")),
                r("c", Deny, tcp),
                r("d", Deny, |r| r.protocol = Some(AclProtocol::Icmpv6)),
                r("e", Deny, dst("10.1.0.0/16")),
            ],
        );
        let p = pack(&a);
        assert_eq!((p.shadowed.len(), p.trailing.len()), (0, 0));
        assert_eq!(rules_at(&p), [vec![0, 3], vec![1], vec![2], vec![4]]);
    }

    #[test]
    fn contained_rules_are_shadowed_partial_and_union_cover_are_not() {
        let a = acl(
            Permit,
            vec![
                r("wide", Deny, dst("10.0.0.0/24")),
                r("inside", Permit, dst("10.0.0.0/26")),
                r("partial", Deny, dst("10.0.0.0/23")),
                r("halves-a", Deny, dst("10.0.2.0/25")),
                r("halves-b", Deny, dst("10.0.2.128/25")),
                r("union", Permit, dst("10.0.2.0/24")),
            ],
        );
        let p = pack(&a);
        // "union" is covered by two earlier rules, not one: kept (ponytail).
        assert_eq!(p.shadowed, [1]);
        assert_eq!(p.trailing, [5]);
    }

    #[test]
    fn an_established_rule_is_shadowed_only_when_both_boxes_are() {
        let est = |r: &mut AclRule| {
            r.protocol = Some(AclProtocol::Tcp);
            r.established = true;
        };
        let tcp = |r: &mut AclRule| r.protocol = Some(AclProtocol::Tcp);
        let covered = acl(Permit, vec![r("t", Deny, tcp), r("e", Deny, est)]);
        assert_eq!(pack(&covered).shadowed, [1]);
        let not = acl(Permit, vec![r("e", Deny, est), r("t", Deny, tcp)]);
        assert_eq!(pack(&not).shadowed.len(), 0);
        let twice = acl(Permit, vec![r("e", Deny, est), r("e2", Deny, est)]);
        assert_eq!(pack(&twice).shadowed, [1]);
    }

    #[test]
    fn trailing_rules_equal_to_the_default_are_popped_in_a_chain() {
        let a = acl(
            Permit,
            vec![
                r("keep", Permit, dst("10.0.0.0/24")),
                r("deny", Deny, dst("10.1.0.0/24")),
                r("p1", Permit, dst("10.2.0.0/24")),
                r("p2", Permit, |_| {}),
            ],
        );
        let p = pack(&a);
        assert_eq!(p.trailing, [2, 3]);
        // "keep" is not trailing (a deny follows it).
        assert_eq!(rules_at(&p), [[0, 1]]);
    }

    #[test]
    fn a_log_rule_is_never_trailing() {
        let a = acl(
            Permit,
            vec![
                r("deny", Deny, dst("10.1.0.0/24")),
                r("p", Permit, dst("10.2.0.0/24")),
                r("logged", Permit, |r| r.log = true),
            ],
        );
        let p = pack(&a);
        assert_eq!(p.trailing.len(), 0);
        assert_eq!(rules_at(&p), [vec![0, 1], vec![2]]);
    }

    #[test]
    fn shadowing_runs_before_trailing() {
        // The last rule is shadowed, so the one before it is the trailing one.
        let a = acl(
            Permit,
            vec![
                r("p", Permit, dst("10.0.0.0/24")),
                r("d", Deny, dst("10.0.0.0/25")),
            ],
        );
        let p = pack(&a);
        assert_eq!((p.shadowed, p.trailing), (vec![1], vec![0]));
        assert_eq!(p.levels.len(), 0);
    }
}
