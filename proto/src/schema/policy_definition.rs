use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::Config;
use nos_proto_derive::Cli;

/// A named RPL script (see `docs/architecture/rpl.md`), referenced by name from a `BgpPeerGroup`'s `import_policy`/
/// `export_policy`. Only the source text crosses the wire/IPC — each
/// consumer (`nos-bgpd`) compiles and caches its own bytecode locally,
/// matching the existing "each daemon re-resolves its own state from config
/// diffs" idiom, rather than `nos-proto` carrying a bytecode wire format.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct PolicyDefinition {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| valid_name(n, ctx))
    )]
    #[cli(key)]
    /// Policy name, unique, and never the reserved `accept-all` or `deny-all`.
    pub name: String,

    #[garde(
        length(max = nos_rpl::MAX_SOURCE_LEN),
        custom(|src: &String, ctx: &Config| valid_source(src, ctx))
    )]
    #[cli(topic = PolicyDefinitionSource)]
    /// RPL source text, compiled at commit time and again by each consumer.
    pub source: String,
}

/// `"accept-all"`/`"deny-all"` are reserved system policies (see
/// `nos_rpl::ACCEPT_ALL_NAME`/`DENY_ALL_NAME`) — never stored as a
/// `PolicyDefinition`, so a user can't shadow or redefine either name.
fn valid_name(name: &String, ctx: &Config) -> garde::Result {
    if name == nos_rpl::ACCEPT_ALL_NAME || name == nos_rpl::DENY_ALL_NAME {
        return Err(garde::Error::new(format!(
            "'{name}' is a reserved system policy name"
        )));
    }
    unique_in(name, &ctx.policy_definitions, |p| &p.name)
}

/// Runs the real RPL compiler at commit time, so a syntactically or
/// semantically invalid policy is rejected before it ever reaches a
/// `nos-bgpd` instance — see root `CLAUDE.md`'s "Config schema changes".
/// `ctx`'s `community_aliases`/`community_groups`/`prefix_lists`/`as_path_lists` resolve any
/// bare-identifier reference the script makes — an undefined name surfaces
/// as an ordinary `CompileError` here, exactly like any other compile error,
/// which is this system's whole cross-reference-validation story for those
/// three sections (see their own schema modules' doc comments).
fn valid_source(source: &str, ctx: &Config) -> garde::Result {
    // Owned, pre-resolved buffers backing the `nos_rpl::Symbols` view below —
    // `Symbols` only borrows, so something has to own the resolved
    // alias/group member data for the duration of the `compile` call. Group
    // members that name an existing alias are resolved to that alias's
    // parts; groups are flat, so a member is never itself another group.
    let aliases: Vec<(&str, Vec<i64>)> = ctx
        .community_aliases
        .iter()
        .filter_map(|a| {
            nos_rpl::parse_colon_literal(&a.value).map(|parts| (a.name.as_str(), parts))
        })
        .collect();
    let alias_refs: Vec<(&str, &[i64])> = aliases.iter().map(|(n, p)| (*n, p.as_slice())).collect();

    let resolve_member = |m: &str| -> Option<Vec<i64>> {
        ctx.community_aliases
            .iter()
            .find(|a| a.name == m)
            .and_then(|a| nos_rpl::parse_colon_literal(&a.value))
            .or_else(|| nos_rpl::parse_colon_literal(m))
    };
    let groups: Vec<(&str, Vec<Vec<i64>>)> = ctx
        .community_groups
        .iter()
        .map(|g| {
            (
                g.name.as_str(),
                g.members.iter().filter_map(|m| resolve_member(m)).collect(),
            )
        })
        .collect();
    let group_member_slices: Vec<Vec<&[i64]>> = groups
        .iter()
        .map(|(_, members)| members.iter().map(Vec::as_slice).collect())
        .collect();
    let group_refs: Vec<(&str, &[&[i64]])> = groups
        .iter()
        .zip(&group_member_slices)
        .map(|((name, _), slices)| (*name, slices.as_slice()))
        .collect();

    let prefix_lists: Vec<(&str, Vec<nos_rpl::PrefixListEntry>)> = ctx
        .prefix_lists
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
            (pl.name.as_str(), entries)
        })
        .collect();
    let prefix_list_refs: Vec<(&str, &[nos_rpl::PrefixListEntry])> = prefix_lists
        .iter()
        .map(|(n, e)| (*n, e.as_slice()))
        .collect();

    let as_path_lists: Vec<(&str, Vec<&str>)> = ctx
        .as_path_lists
        .iter()
        .map(|l| {
            (
                l.name.as_str(),
                l.patterns.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let as_path_list_refs: Vec<(&str, &[&str])> = as_path_lists
        .iter()
        .map(|(n, p)| (*n, p.as_slice()))
        .collect();

    let policy_refs: Vec<(&str, &str)> = ctx
        .policy_definitions
        .iter()
        .map(|p| (p.name.as_str(), p.source.as_str()))
        .collect();
    let symbols = nos_rpl::Symbols {
        aliases: &alias_refs,
        groups: &group_refs,
        prefix_lists: &prefix_list_refs,
        as_path_lists: &as_path_list_refs,
        policies: &policy_refs,
    };

    nos_rpl::compile(source, &symbols)
        .map(|_| ())
        .map_err(|e| garde::Error::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(policies: Vec<PolicyDefinition>) -> Config {
        Config {
            policy_definitions: policies,
            ..Default::default()
        }
    }

    fn policy(name: &str, source: &str) -> PolicyDefinition {
        PolicyDefinition {
            name: name.to_string(),
            source: source.to_string(),
        }
    }

    #[test]
    fn valid_policy_passes() {
        let cfg = config_with(vec![policy("p1", "accept\n")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn oversize_source_fails() {
        let src = format!(
            "{}accept\n",
            "# pad\n".repeat(nos_rpl::MAX_SOURCE_LEN / 6 + 1)
        );
        let cfg = config_with(vec![policy("p1", &src)]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn invalid_source_fails() {
        let cfg = config_with(vec![policy("p1", "if this.prefix in :\n    accept\n")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn non_terminating_source_fails() {
        let cfg = config_with(vec![policy(
            "p1",
            "if this.bgp.local_pref < 100:\n    reject\n",
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![policy("p1", "accept\n"), policy("p1", "reject\n")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn reserved_name_accept_all_fails() {
        let cfg = config_with(vec![policy("accept-all", "accept\n")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn reserved_name_deny_all_fails() {
        let cfg = config_with(vec![policy("deny-all", "reject\n")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn script_referencing_community_alias_passes() {
        let cfg = Config {
            community_aliases: vec![crate::schema::CommunityAlias {
                name: "CUSTOMER_A".to_string(),
                value: "65000:100".to_string(),
            }],
            policy_definitions: vec![policy(
                "p1",
                "if this.bgp.communities.contains(CUSTOMER_A):\n    reject\nelse:\n    accept\n",
            )],
            ..Default::default()
        };
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn script_referencing_as_path_list_passes_and_undefined_fails() {
        let script = "if this.bgp.as_path in TRANSIT:\n    reject\nelse:\n    accept\n";
        let mut cfg = config_with(vec![policy("p", script)]);
        assert!(cfg.validate_with(&cfg).is_err());
        cfg.as_path_lists = vec![crate::schema::AsPathList {
            name: "TRANSIT".to_string(),
            patterns: vec!["_65009_".to_string()],
        }];
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn script_referencing_community_group_passes() {
        let cfg = Config {
            community_aliases: vec![crate::schema::CommunityAlias {
                name: "CUSTOMER_A".to_string(),
                value: "65000:100".to_string(),
            }],
            community_groups: vec![crate::schema::CommunityGroup {
                name: "CUSTOMERS".to_string(),
                members: vec!["CUSTOMER_A".to_string(), "65000:200".to_string()],
            }],
            policy_definitions: vec![policy(
                "p1",
                "if this.bgp.communities.contains(CUSTOMERS):\n    reject\nelse:\n    accept\n",
            )],
            ..Default::default()
        };
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn script_referencing_prefix_list_passes() {
        let cfg = Config {
            prefix_lists: vec![crate::schema::PrefixList {
                name: "BLOCKS".to_string(),
                entries: vec![crate::schema::PrefixListEntry {
                    cidr: "10.0.0.0/8".parse().unwrap(),
                    range: Some((24, 32)),
                }],
            }],
            policy_definitions: vec![policy(
                "p1",
                "if this.prefix in BLOCKS:\n    reject\nelse:\n    accept\n",
            )],
            ..Default::default()
        };
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn script_referencing_undefined_alias_fails() {
        let cfg = config_with(vec![policy(
            "p1",
            "if this.bgp.communities.contains(NOT_DEFINED):\n    accept\nelse:\n    reject\n",
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn script_referencing_undefined_prefix_list_fails() {
        let cfg = config_with(vec![policy(
            "p1",
            "if this.prefix in NOT_DEFINED:\n    accept\nelse:\n    reject\n",
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn call_chain_commits_and_bad_calls_fail() {
        let ok = config_with(vec![
            policy("a", "call b\naccept\n"),
            policy("b", "accept\n"),
        ]);
        ok.validate_with(&ok).unwrap();
        let missing = config_with(vec![policy("a", "call b\naccept\n")]);
        assert!(missing.validate_with(&missing).is_err());
        let cycle = config_with(vec![
            policy("a", "call b\naccept\n"),
            policy("b", "call a\naccept\n"),
        ]);
        let err = cycle.validate_with(&cycle).unwrap_err().to_string();
        assert!(err.contains("cycle"), "{err}");
    }
}
