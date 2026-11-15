//! The one adapter from schema types to `nos_rpl::Symbols`, shared by
//! `nos-config` commit-time validation (`policy_definition::valid_source`)
//! and `nos-bgpd` (`PolicyCache::resync`) so the two can never resolve a
//! name differently (#671).

use super::{AsPathList, CommunityAlias, CommunityGroup, PolicyDefinition, PrefixList};

/// Owned, pre-resolved buffers backing a `nos_rpl::Symbols` view (which only
/// borrows). An alias with an unparsable value is dropped; a group member
/// names an alias first, else is a `a:b` literal, else is dropped. Groups are
/// flat: a member is never itself another group.
pub struct PolicySymbols {
    aliases: Vec<(String, Vec<i64>)>,
    groups: Vec<(String, Vec<Vec<i64>>)>,
    prefix_lists: Vec<(String, Vec<nos_rpl::PrefixListEntry>)>,
    as_path_lists: Vec<(String, Vec<String>)>,
    policies: Vec<(String, String)>,
}

impl PolicySymbols {
    /// Resolves the five config sections into owned buffers.
    #[must_use]
    pub fn new(
        policies: &[PolicyDefinition],
        aliases: &[CommunityAlias],
        groups: &[CommunityGroup],
        prefix_lists: &[PrefixList],
        as_path_lists: &[AsPathList],
    ) -> Self {
        let resolve_member = |m: &str| -> Option<Vec<i64>> {
            aliases
                .iter()
                .find(|a| a.name == m)
                .and_then(|a| nos_rpl::parse_colon_literal(&a.value))
                .or_else(|| nos_rpl::parse_colon_literal(m))
        };
        PolicySymbols {
            aliases: aliases
                .iter()
                .filter_map(|a| nos_rpl::parse_colon_literal(&a.value).map(|p| (a.name.clone(), p)))
                .collect(),
            groups: groups
                .iter()
                .map(|g| {
                    (
                        g.name.clone(),
                        g.members.iter().filter_map(|m| resolve_member(m)).collect(),
                    )
                })
                .collect(),
            prefix_lists: prefix_lists
                .iter()
                .map(|pl| {
                    let entries = pl
                        .entries
                        .iter()
                        .map(|e| nos_rpl::PrefixListEntry {
                            cidr: e.cidr,
                            range: e.range,
                        })
                        .collect();
                    (pl.name.clone(), entries)
                })
                .collect(),
            as_path_lists: as_path_lists
                .iter()
                .map(|l| (l.name.clone(), l.patterns.clone()))
                .collect(),
            policies: policies
                .iter()
                .map(|p| (p.name.clone(), p.source.clone()))
                .collect(),
        }
    }

    /// Builds the borrowed `Symbols` view once and hands it to `f`; use it to
    /// compile several scripts against one table.
    pub fn with_symbols<R>(&self, f: impl FnOnce(&nos_rpl::Symbols<'_>) -> R) -> R {
        let aliases: Vec<(&str, &[i64])> = self
            .aliases
            .iter()
            .map(|(n, p)| (n.as_str(), p.as_slice()))
            .collect();
        let member_slices: Vec<Vec<&[i64]>> = self
            .groups
            .iter()
            .map(|(_, m)| m.iter().map(Vec::as_slice).collect())
            .collect();
        let groups: Vec<(&str, &[&[i64]])> = self
            .groups
            .iter()
            .zip(&member_slices)
            .map(|((n, _), s)| (n.as_str(), s.as_slice()))
            .collect();
        let prefix_lists: Vec<(&str, &[nos_rpl::PrefixListEntry])> = self
            .prefix_lists
            .iter()
            .map(|(n, e)| (n.as_str(), e.as_slice()))
            .collect();
        let pattern_refs: Vec<Vec<&str>> = self
            .as_path_lists
            .iter()
            .map(|(_, p)| p.iter().map(String::as_str).collect())
            .collect();
        let as_path_lists: Vec<(&str, &[&str])> = self
            .as_path_lists
            .iter()
            .zip(&pattern_refs)
            .map(|((n, _), p)| (n.as_str(), p.as_slice()))
            .collect();
        let policies: Vec<(&str, &str)> = self
            .policies
            .iter()
            .map(|(n, s)| (n.as_str(), s.as_str()))
            .collect();
        f(&nos_rpl::Symbols {
            aliases: &aliases,
            groups: &groups,
            prefix_lists: &prefix_lists,
            as_path_lists: &as_path_lists,
            policies: &policies,
        })
    }

    /// Compiles one script against this table.
    ///
    /// # Errors
    /// The `nos_rpl` compile error (syntax, undefined name, non-terminating path).
    pub fn compile(&self, source: &str) -> Result<nos_rpl::CompiledPolicy, nos_rpl::CompileError> {
        self.with_symbols(|s| nos_rpl::compile(source, s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Config;
    use garde::Validate;

    fn alias(name: &str, value: &str) -> CommunityAlias {
        CommunityAlias {
            name: name.into(),
            value: value.into(),
        }
    }

    fn sym(
        aliases: &[CommunityAlias],
        groups: &[CommunityGroup],
        policies: &[PolicyDefinition],
    ) -> PolicySymbols {
        PolicySymbols::new(policies, aliases, groups, &[], &[])
    }

    fn group(name: &str, members: &[&str]) -> CommunityGroup {
        CommunityGroup {
            name: name.into(),
            members: members.iter().map(|m| (*m).to_string()).collect(),
        }
    }

    fn uses_group(g: &str) -> String {
        format!("if this.bgp.communities.contains({g}):\n    reject\nelse:\n    accept\n")
    }

    #[test]
    fn group_member_alias_literal_and_bad() {
        let s = sym(
            &[alias("a", "65000:1")],
            &[group("g", &["a", "65000:2", "junk"])],
            &[],
        );
        s.compile(&uses_group("g")).unwrap();
        s.with_symbols(|v| {
            assert_eq!(v.groups[0].1, [&[65000, 1][..], &[65000, 2][..]]);
        });
    }

    #[test]
    fn unparsable_alias_dropped() {
        let s = sym(&[alias("a", "nope")], &[], &[]);
        s.with_symbols(|v| assert_eq!(v.aliases, []));
    }

    #[test]
    fn policy_lookup_and_undefined_name() {
        let p = PolicyDefinition {
            name: "p".into(),
            source: "accept\n".into(),
        };
        let s = sym(&[], &[], &[p]);
        s.compile("call p\naccept\n").unwrap();
        assert!(s.compile("call missing\naccept\n").is_err());
    }

    #[test]
    fn config_and_direct_entry_points_agree() {
        let cfg = Config {
            community_aliases: vec![alias("a", "65000:1")],
            community_groups: vec![group("g", &["a"])],
            ..Default::default()
        };
        let src = uses_group("g");
        let direct = PolicySymbols::new(
            &cfg.policy_definitions,
            &cfg.community_aliases,
            &cfg.community_groups,
            &cfg.prefix_lists,
            &cfg.as_path_lists,
        )
        .compile(&src);
        assert!(direct.is_ok());
        let mut c2 = cfg.clone();
        c2.policy_definitions = vec![PolicyDefinition {
            name: "p".into(),
            source: src,
        }];
        c2.validate_with(&c2).unwrap();
    }
}
