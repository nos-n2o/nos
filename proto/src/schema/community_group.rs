use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::community_alias::valid_community_value;
use super::Config;
use nos_proto_derive::Cli;

/// A named, flat set of `community-alias` names and/or inline literals,
/// referenced by bare name from an RPL script the same way a
/// `CommunityAlias` is. `.contains(..)` matches if ANY member matches
/// (standard community-list OR semantics); `.add(..)`/`.remove(..)` apply to
/// every member. No nesting — a member must be an existing alias name or a
/// literal, never another group's name (not requested, see root
/// `CLAUDE.md`'s RPL section).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct CommunityGroup {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.community_groups, |g| &g.name))
    )]
    #[cli(key)]
    /// Group name, 1 to 64 characters (letters, digits, `_`, `-`), unique among groups.
    pub name: String,

    #[garde(custom(|m: &Vec<String>, ctx: &Config| valid_members(m, ctx)))]
    #[cli(topic = CommunityGroupMember)]
    /// Names of the `CommunityAlias` entries in the group; each must exist.
    pub members: Vec<String>,
}

fn valid_members(members: &[String], ctx: &Config) -> garde::Result {
    if members.is_empty() {
        return Err(garde::Error::new("must have at least one member"));
    }
    for m in members {
        let is_alias = ctx.community_aliases.iter().any(|a| &a.name == m);
        if !is_alias && valid_community_value(m).is_err() {
            return Err(garde::Error::new(format!(
                "member '{m}' is neither an existing community-alias nor a valid community literal"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::CommunityAlias;

    fn alias(name: &str, value: &str) -> CommunityAlias {
        CommunityAlias {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn group(name: &str, members: &[&str]) -> CommunityGroup {
        CommunityGroup {
            name: name.to_string(),
            members: members.iter().map(ToString::to_string).collect(),
        }
    }

    fn config_with(aliases: Vec<CommunityAlias>, groups: Vec<CommunityGroup>) -> Config {
        Config {
            community_aliases: aliases,
            community_groups: groups,
            ..Default::default()
        }
    }

    #[test]
    fn alias_and_literal_members_pass() {
        let cfg = config_with(
            vec![alias("CUSTOMER_A", "65000:100")],
            vec![group("CUSTOMERS", &["CUSTOMER_A", "65000:200"])],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn empty_members_fails() {
        let cfg = config_with(vec![], vec![group("EMPTY", &[])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn undefined_alias_member_fails() {
        let cfg = config_with(vec![], vec![group("CUSTOMERS", &["NOT_DEFINED"])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_group_name_fails() {
        let cfg = config_with(
            vec![],
            vec![
                group("CUSTOMERS", &["65000:100"]),
                group("CUSTOMERS", &["65000:200"]),
            ],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
