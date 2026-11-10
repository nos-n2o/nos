use garde::Validate;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::Config;
use nos_proto_derive::Cli;

use super::sugar;

/// One `prefix-list` entry. `range: None` means exact match — this exact
/// prefix+length only; `Some((min, max))` means "contained within `cidr`,
/// with the candidate's own length in `[min, max]`". Deliberately different
/// from the existing `this.prefix in <cidr>` operator, which stays
/// containment/orlonger-based for a bare CIDR — see root `CLAUDE.md`'s RPL
/// section.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct PrefixListEntry {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(topic = PrefixListEntry)]
    /// Base prefix of the entry.
    pub cidr: IpNet,
    #[cli(topic = PrefixListEntry, sugar(word = "orlonger", with = sugar::orlonger, topic = PrefixListEntry), sugar(word = "upto", with = sugar::upto, topic = PrefixListEntry))]
    /// Prefix-length range `(min, max)` that matches within `cidr`; `None` is an exact match.
    pub range: Option<(u8, u8)>,
}

/// A named set of prefix-match entries, referenced by bare name from an RPL
/// script's `this.prefix in NAME`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct PrefixList {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.prefix_lists, |p| &p.name))
    )]
    #[cli(key)]
    /// List name, 1 to 64 characters (letters, digits, `_`, `-`), unique among prefix lists.
    pub name: String,

    #[garde(custom(|e: &Vec<PrefixListEntry>, _ctx: &Config| valid_entries(e)))]
    #[cli(topic = PrefixListEntry)]
    /// Entries, any of which may match.
    pub entries: Vec<PrefixListEntry>,
}

/// An entry's address must be its network address (no host bits), range or not
/// (#669). A `range`, if set, may only narrow its own `cidr` — `min`/`max` must fall
/// within `[cidr.prefix_len(), cidr.max_prefix_len()]` and `min <= max`.
fn valid_entries(entries: &[PrefixListEntry]) -> garde::Result {
    if entries.is_empty() {
        return Err(garde::Error::new("must have at least one entry"));
    }
    for entry in entries {
        if entry.cidr != entry.cidr.trunc() {
            return Err(garde::Error::new(
                "entry must not have host bits set (write the network address, e.g. 10.0.0.0/8)",
            ));
        }
        if let Some((min, max)) = entry.range
            && (min < entry.cidr.prefix_len() || min > max || max > entry.cidr.max_prefix_len())
        {
            return Err(garde::Error::new(
                    "range must narrow the entry's cidr: cidr length <= min <= max <= address family's max length",
                ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cidr: &str, range: Option<(u8, u8)>) -> PrefixListEntry {
        PrefixListEntry {
            cidr: cidr.parse().unwrap(),
            range,
        }
    }

    fn list(name: &str, entries: Vec<PrefixListEntry>) -> PrefixList {
        PrefixList {
            name: name.to_string(),
            entries,
        }
    }

    fn config_with(lists: Vec<PrefixList>) -> Config {
        Config {
            prefix_lists: lists,
            ..Default::default()
        }
    }

    #[test]
    fn exact_entry_passes() {
        let cfg = config_with(vec![list("BLOCKS", vec![entry("10.0.0.0/8", None)])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn valid_range_entry_passes() {
        let cfg = config_with(vec![list(
            "BLOCKS",
            vec![entry("10.0.0.0/8", Some((24, 32)))],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn range_narrower_than_cidr_fails() {
        let cfg = config_with(vec![list(
            "BLOCKS",
            vec![entry("10.0.0.0/8", Some((4, 32)))],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn range_min_greater_than_max_fails() {
        let cfg = config_with(vec![list(
            "BLOCKS",
            vec![entry("10.0.0.0/8", Some((32, 24)))],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn range_exceeding_address_family_max_fails() {
        let cfg = config_with(vec![list(
            "BLOCKS",
            vec![entry("10.0.0.0/8", Some((24, 40)))],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn host_bits_fail_for_exact_and_range_entries() {
        for e in [
            entry("192.168.1.0/16", None),
            entry("192.168.1.0/16", Some((16, 24))),
            entry("2001:db8::1/32", None),
        ] {
            let cfg = config_with(vec![list("BLOCKS", vec![e])]);
            assert!(cfg.validate_with(&cfg).is_err());
        }
        let cfg = config_with(vec![list("BLOCKS", vec![entry("192.168.0.0/16", None)])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn empty_entries_fails() {
        let cfg = config_with(vec![list("EMPTY", vec![])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_list_name_fails() {
        let cfg = config_with(vec![
            list("BLOCKS", vec![entry("10.0.0.0/8", None)]),
            list("BLOCKS", vec![entry("172.16.0.0/12", None)]),
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }
}
