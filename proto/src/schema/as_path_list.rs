use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::Config;
use nos_proto_derive::Cli;

/// A named set of AS-path regexes, referenced by bare name from an RPL
/// script's `this.bgp.as_path in NAME`. Each pattern is matched against the
/// path rendered as space-separated ASNs, with `_` as the Cisco-style
/// boundary (see `nos_rpl::AsPathRegexes`); the list matches if ANY pattern
/// does.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct AsPathList {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.as_path_lists, |l| &l.name))
    )]
    #[cli(key)]
    /// List name, 1 to 64 characters (letters, digits, `_`, `-`), unique among AS-path lists.
    pub name: String,

    #[garde(custom(|p: &Vec<String>, _ctx: &Config| valid_patterns(p)))]
    #[cli(topic = AsPathListPattern)]
    /// Regexes over the space-separated ASN path with `_` as boundary; a path matches when any one matches. Never empty.
    pub patterns: Vec<String>,
}

fn valid_patterns(patterns: &[String]) -> garde::Result {
    if patterns.is_empty() {
        return Err(garde::Error::new("must have at least one pattern"));
    }
    for p in patterns {
        nos_rpl::AsPathRegexes::new(&[p.as_str()]).map_err(garde::Error::new)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(name: &str, patterns: &[&str]) -> AsPathList {
        AsPathList {
            name: name.to_string(),
            patterns: patterns.iter().map(ToString::to_string).collect(),
        }
    }

    fn config_with(lists: Vec<AsPathList>) -> Config {
        Config {
            as_path_lists: lists,
            ..Default::default()
        }
    }

    #[test]
    fn valid_regexes_pass() {
        let cfg = config_with(vec![list("TRANSIT", &["^65001_", "_65009$"])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn empty_patterns_fails() {
        let cfg = config_with(vec![list("EMPTY", &[])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn invalid_regex_fails() {
        let cfg = config_with(vec![list("BAD", &["("])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_list_name_fails() {
        let cfg = config_with(vec![list("A", &["^1$"]), list("A", &["^2$"])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
