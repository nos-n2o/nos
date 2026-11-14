//! The lab id (#1049): `NOS_E2E_LAB=<k>`, `k` in {0, 1}, lets two labs from two
//! worktrees run on one docker host at once. `k=0` (the default, and what CI
//! uses) is byte-for-byte the historical lab. For `k>0` container, network and
//! volume names get an `l<k>-` prefix (at the `Dock` boundary, so phase literals
//! like `"router-a"` stay) and every explicitly-addressed docker network moves
//! to its own subnet (the `Addr` constants), because docker refuses two
//! networks with overlapping pools.

use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::sync::{Mutex, OnceLock};

/// Label on every container, network and volume a lab creates; `down` removes by it.
pub const LAB_LABEL: &str = "nos-e2e.lab";
/// Labs the host has slots for (`tools/ci/e2e-lab.sh`'s default `NOS_E2E_LABS`).
pub const LABS: u8 = 2;

/// Parses `NOS_E2E_LAB` (unset or empty is lab 0).
pub fn lab_from(v: Option<&str>) -> Result<u8, String> {
    match v.filter(|s| !s.is_empty()) {
        None => Ok(0),
        Some(s) => s
            .parse::<u8>()
            .ok()
            .filter(|k| *k < LABS)
            .ok_or_else(|| format!("NOS_E2E_LAB={s}: expected 0..{LABS}")),
    }
}

pub fn lab_env() -> Result<u8, String> {
    lab_from(std::env::var("NOS_E2E_LAB").ok().as_deref())
}

/// The process's lab; an invalid value reads as 0 here because `Dock::connect`
/// (the first thing every command does) rejects it.
pub fn lab() -> u8 {
    static LAB: OnceLock<u8> = OnceLock::new();
    *LAB.get_or_init(|| lab_env().unwrap_or(0))
}

/// `name` as docker knows it in lab `k`.
pub fn prefixed(k: u8, name: &str) -> String {
    if k == 0 {
        name.to_string()
    } else {
        format!("l{k}-{name}")
    }
}

/// The lab-0 address/subnet `s` as lab `k` addresses it. Second octets move by
/// 10 per lab (lab 1's `10.50` -> `10.60`, `10.51` -> `10.61`, so no lab's
/// networks meet another's); the CE-network blocks move one /16 and their
/// ULAs one nibble.
pub fn shift(s: &str, k: u8) -> String {
    if k == 0 {
        return s.to_string();
    }
    let k = u32::from(k);
    let rules: [(&str, String); 7] = [
        ("10.50.", format!("10.{}.", 50 + 10 * k)),
        ("10.51.", format!("10.{}.", 51 + 10 * k)),
        ("10.52.", format!("10.{}.", 52 + 10 * k)),
        ("fd00:10:50:", format!("fd00:10:{}:", 50 + 10 * k)),
        ("198.18.", format!("198.{}.", 18 + k)),
        ("fd18:", format!("fd{:x}:", 0x18 + 0x10 * k)),
        ("fd19:", format!("fd{:x}:", 0x19 + 0x10 * k)),
    ];
    for (from, to) in rules {
        if let Some(rest) = s.strip_prefix(from) {
            return format!("{to}{rest}");
        }
    }
    s.to_string()
}

/// A lab-0 address or subnet literal that reads as the running lab's. `Display`
/// (so `{IP_A}` works in `format!`) and `.s()` give the shifted text.
#[derive(Clone, Copy)]
pub struct Addr(pub &'static str);

impl Addr {
    /// The text for the running lab, `'static` (interned: a lab has a few dozen).
    pub fn s(self) -> &'static str {
        static CACHE: OnceLock<Mutex<HashMap<&'static str, &'static str>>> = OnceLock::new();
        let mut m = CACHE
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        m.entry(self.0)
            .or_insert_with(|| Box::leak(shift(self.0, lab()).into_boxed_str()))
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.s())
    }
}

impl Deref for Addr {
    type Target = str;
    fn deref(&self) -> &str {
        self.s()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::*;

    #[test]
    fn lab_parse() {
        assert_eq!(lab_from(None), Ok(0));
        assert_eq!(lab_from(Some("")), Ok(0));
        assert_eq!(lab_from(Some("1")), Ok(1));
        assert!(lab_from(Some("2")).is_err());
        assert!(lab_from(Some("x")).is_err());
    }

    #[test]
    fn names() {
        assert_eq!(prefixed(0, "router-a"), "router-a");
        assert_eq!(prefixed(1, "nos-verify-net"), "l1-nos-verify-net");
    }

    /// Lab 0 is today's lab: the golden values the phases were written against.
    #[test]
    fn lab0_is_todays_literals() {
        for (a, golden) in [
            (SUBNET, "10.50.0.0/24"),
            (SUBNET6, "fd00:10:50::/64"),
            (IP_A, "10.50.0.2"),
            (OSPF_FRR_SUBNET, "10.51.0.0/24"),
            (OSPFV3_A1_SUBNET, "10.52.0.0/24"),
            (OSPFV3_A1_SUBNET6, "fd19:3::/64"),
            (L3_SUBNET_A, "198.18.1.0/24"),
            (L3V6_SUBNET_A, "fd18:1::/64"),
        ] {
            assert_eq!(shift(a.0, 0), golden);
        }
    }

    /// Every docker network with explicit IPAM sits in a different subnet in
    /// lab 1 (docker refuses overlapping pools), by prefix at least.
    #[test]
    fn lab1_subnets_disjoint_from_lab0() {
        let subnets = [
            SUBNET,
            SUBNET6,
            OSPF_FRR_SUBNET,
            OSPFV3_A1_SUBNET,
            OSPFV3_A1_SUBNET6,
            L3_SUBNET_A,
            L3_SUBNET_B,
            L3V6_SUBNET_A,
            L3V6_SUBNET_B,
        ];
        let lab1: Vec<String> = subnets.iter().map(|a| shift(a.0, 1)).collect();
        // Every lab-0 subnet is its own /24 or /64, so inequality is disjointness.
        for b in &lab1 {
            assert!(
                subnets.iter().all(|a| a.0 != b),
                "lab 1 {b} is a lab 0 subnet"
            );
        }
        assert_eq!(shift("10.50.0.0/24", 1), "10.60.0.0/24");
        assert_eq!(shift("fd00:10:50::/64", 1), "fd00:10:60::/64");
        assert_eq!(shift("198.18.1.0/24", 1), "198.19.1.0/24");
        assert_eq!(shift("fd18:1::/64", 1), "fd28:1::/64");
        // Something outside every lab network stays put.
        assert_eq!(shift("192.0.2.1", 1), "192.0.2.1");
    }
}
