use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::Config;
use nos_proto_derive::Cli;

/// A named community value (standard/extended/large — inferred from
/// `value`'s own colon-literal shape, same as an inline literal in a
/// script), referenced by bare name from an RPL policy script's
/// `.contains(..)`/`.add(..)`/`.remove(..)` — see root `CLAUDE.md`'s RPL
/// section.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct CommunityAlias {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.community_aliases, |a| &a.name))
    )]
    #[cli(key)]
    /// Alias name, 1 to 64 characters (letters, digits, `_`, `-`), unique among aliases.
    pub name: String,

    #[garde(custom(|v: &String, _ctx: &Config| valid_community_value(v)))]
    #[cli(topic = CommunityAliasValue)]
    /// Colon-separated community literal such as `65000:100`.
    pub value: String,
}

/// `value` must be a bare colon-separated community literal (`65000:100`,
/// `0:2:100`, …) — the exact grammar `nos-rpl` accepts inline in a script.
/// Arity (2 parts for standard, 3 for extended/large) isn't checked here —
/// it's ambiguous until the alias is referenced from a specific field inside
/// a script, exactly like an inline literal today.
pub(crate) fn valid_community_value(value: &str) -> garde::Result {
    if nos_rpl::parse_colon_literal(value).is_none() {
        return Err(garde::Error::new(
            "must be a colon-separated community literal, e.g. 65000:100",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias(name: &str, value: &str) -> CommunityAlias {
        CommunityAlias {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn config_with(aliases: Vec<CommunityAlias>) -> Config {
        Config {
            community_aliases: aliases,
            ..Default::default()
        }
    }

    #[test]
    fn valid_alias_passes() {
        let cfg = config_with(vec![alias("CUSTOMER_A", "65000:100")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn three_part_value_passes() {
        let cfg = config_with(vec![alias("BLACKHOLE", "65000:1:2")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn non_literal_value_fails() {
        let cfg = config_with(vec![alias("BAD", "not-a-literal")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![
            alias("CUSTOMER_A", "65000:100"),
            alias("CUSTOMER_A", "65000:200"),
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
