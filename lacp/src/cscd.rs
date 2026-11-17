//! Pure CSCD policy (#894): config + live Distributing set -> local
//! conversation map, the advertisement, and the agreement decision. No I/O.
//! Inherits #893's UNVERIFIED wire choices (see `conversation.rs`).

use std::collections::BTreeMap;

use nos_proto::{LacpPortAlgorithm, LacpVersion};

use crate::conversation::{ConversationMap, PortAlgorithm, CONVERSATIONS};
use crate::packet::ConvDigest;

/// The per-aggregate v2 settings, from config.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2Cfg {
    pub version: LacpVersion,
    pub algorithm: LacpPortAlgorithm,
    /// Explicit `(first, last, member)` ranges; empty = automatic.
    pub map: Vec<(u16, u16, String)>,
    /// `lacp-link-number` per member that has one.
    pub link_numbers: BTreeMap<String, u16>,
}

impl V2Cfg {
    pub fn version_pref(&self) -> u8 {
        match self.version {
            LacpVersion::V1 => 1,
            LacpVersion::V2 => 2,
        }
    }
}

/// What every link of the aggregate advertises (its own `Link_Number` is added
/// per link).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advert {
    pub algorithm: PortAlgorithm,
    /// The map digest, or why there is none.
    pub digest: Result<[u8; 16], &'static str>,
}

impl Default for Advert {
    fn default() -> Self {
        Self {
            algorithm: PortAlgorithm::Unspecified,
            digest: Err("unspecified"),
        }
    }
}

/// The partner's v2 view recorded from its last PDU (all `Copy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PartnerV2 {
    pub version: Option<u8>,
    pub algorithm: Option<PortAlgorithm>,
    pub digest: Option<ConvDigest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agreement {
    NotRequested,
    Agreed,
    Mismatch(&'static str),
    PartnerV1,
}

impl Agreement {
    /// `(state, reason)` for the log line.
    pub fn label(self) -> (&'static str, &'static str) {
        match self {
            Self::NotRequested => ("NotRequested", ""),
            Self::Agreed => ("Agreed", ""),
            Self::Mismatch(r) => ("Mismatch", r),
            Self::PartnerV1 => ("PartnerV1", ""),
        }
    }

    pub fn to_wire(self) -> nos_proto::LacpAgreement {
        match self {
            Self::NotRequested => nos_proto::LacpAgreement::NotApplicable,
            Self::Agreed => nos_proto::LacpAgreement::Agreed,
            Self::Mismatch(_) => nos_proto::LacpAgreement::Mismatch,
            Self::PartnerV1 => nos_proto::LacpAgreement::V1Partner,
        }
    }
}

pub fn wire_algorithm(a: LacpPortAlgorithm) -> PortAlgorithm {
    match a {
        LacpPortAlgorithm::Unspecified => PortAlgorithm::Unspecified,
        LacpPortAlgorithm::CVlan => PortAlgorithm::CVid,
        LacpPortAlgorithm::SVlan => PortAlgorithm::SVid,
    }
}

pub fn proto_algorithm(a: PortAlgorithm) -> Option<LacpPortAlgorithm> {
    match a {
        PortAlgorithm::Unspecified => Some(LacpPortAlgorithm::Unspecified),
        PortAlgorithm::CVid => Some(LacpPortAlgorithm::CVlan),
        PortAlgorithm::SVid => Some(LacpPortAlgorithm::SVlan),
        PortAlgorithm::Other(_) => None,
    }
}

/// Explicit map when configured, else `conversation -> active[c % n]` ordered
/// by `Link_Number` (open decision 2: every link needs an explicit number).
fn local_map(cfg: &V2Cfg, active: &[String]) -> Result<ConversationMap, &'static str> {
    let number = |n: &str| cfg.link_numbers.get(n).copied().ok_or("no-link-number");
    let mut map = ConversationMap::default();
    if !cfg.map.is_empty() {
        for (first, last, member) in &cfg.map {
            let link = number(member)?;
            for c in *first..=*last {
                map.set(c, link);
            }
        }
        return Ok(map);
    }
    let mut links = active
        .iter()
        .map(|n| number(n))
        .collect::<Result<Vec<u16>, _>>()?;
    links.sort_unstable();
    if links.is_empty() {
        return Err("no-active-links");
    }
    for c in 0..CONVERSATIONS {
        #[allow(clippy::cast_possible_truncation, reason = "c < 4096")]
        map.set(c as u16, links[c % links.len()]);
    }
    Ok(map)
}

/// The advertisement and (when there is one) the map behind it.
pub fn compute(cfg: &V2Cfg, active: &[String]) -> (Advert, Option<ConversationMap>) {
    let algorithm = wire_algorithm(cfg.algorithm);
    if cfg.algorithm == LacpPortAlgorithm::Unspecified {
        return (
            Advert {
                algorithm,
                digest: Err("unspecified"),
            },
            None,
        );
    }
    match local_map(cfg, active) {
        Ok(m) => (
            Advert {
                algorithm,
                digest: Ok(m.digest()),
            },
            Some(m),
        ),
        Err(e) => (
            Advert {
                algorithm,
                digest: Err(e),
            },
            None,
        ),
    }
}

/// One link's agreement with its partner.
pub fn agreement(local: &Advert, p: &PartnerV2) -> Agreement {
    if local.algorithm == PortAlgorithm::Unspecified {
        return Agreement::NotRequested;
    }
    match p.version {
        None => return Agreement::NotRequested,
        Some(1) => return Agreement::PartnerV1,
        Some(_) => {}
    }
    let mine = match local.digest {
        Ok(d) => d,
        Err(e) => return Agreement::Mismatch(e),
    };
    if p.algorithm != Some(local.algorithm) {
        return Agreement::Mismatch("algorithm");
    }
    match p.digest {
        None => Agreement::Mismatch("no-digest"),
        Some(d) if d.digest == mine => Agreement::Agreed,
        Some(_) => Agreement::Mismatch("digest"),
    }
}

/// All-or-nothing (open decision 3): `Agreed` only when every Distributing
/// link agrees; otherwise the first link that does not. No links = not requested.
pub fn overall<'a>(local: &Advert, partners: impl IntoIterator<Item = &'a PartnerV2>) -> Agreement {
    let mut result = None;
    for p in partners {
        match agreement(local, p) {
            Agreement::Agreed => result = result.or(Some(Agreement::Agreed)),
            other => return other,
        }
    }
    result.unwrap_or(Agreement::NotRequested)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(map: Vec<(u16, u16, &str)>, nums: &[(&str, u16)]) -> V2Cfg {
        V2Cfg {
            version: LacpVersion::V2,
            algorithm: LacpPortAlgorithm::CVlan,
            map: map.into_iter().map(|(a, b, m)| (a, b, m.into())).collect(),
            link_numbers: nums.iter().map(|(n, l)| ((*n).into(), *l)).collect(),
        }
    }

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| (*s).into()).collect()
    }

    #[test]
    fn automatic_map_is_mod_active_links_ordered_by_link_number() {
        let c = cfg(vec![], &[("a", 2), ("b", 1)]);
        // Input order must not matter.
        let m1 = local_map(&c, &names(&["a", "b"])).unwrap();
        let m2 = local_map(&c, &names(&["b", "a"])).unwrap();
        assert_eq!(m1, m2);
        assert_eq!(m1.link_of(0), Some(1));
        assert_eq!(m1.link_of(1), Some(2));
        assert_eq!(m1.link_of(4095), Some(2));
        let one = local_map(&c, &names(&["a"])).unwrap();
        assert_eq!(one.link_of(0), Some(2));
        assert_eq!(one.link_of(4095), Some(2));
    }

    #[test]
    fn automatic_map_errors() {
        let c = cfg(vec![], &[("a", 1)]);
        assert_eq!(local_map(&c, &[]), Err("no-active-links"));
        assert_eq!(local_map(&c, &names(&["x"])), Err("no-link-number"));
    }

    #[test]
    fn explicit_map_wins_and_leaves_the_rest_unassigned() {
        let c = cfg(vec![(0, 99, "a"), (4000, 4095, "b")], &[("a", 1), ("b", 2)]);
        let m = local_map(&c, &names(&["a"])).unwrap();
        assert_eq!(m.link_of(0), Some(1));
        assert_eq!(m.link_of(99), Some(1));
        assert_eq!(m.link_of(100), Some(0));
        assert_eq!(m.link_of(4095), Some(2));
        let bad = cfg(vec![(0, 1, "z")], &[]);
        assert_eq!(local_map(&bad, &[]), Err("no-link-number"));
    }

    #[test]
    fn unspecified_algorithm_has_no_digest() {
        let mut c = cfg(vec![], &[("a", 1)]);
        c.algorithm = LacpPortAlgorithm::Unspecified;
        let (adv, map) = compute(&c, &names(&["a"]));
        assert_eq!(adv, Advert::default());
        assert!(map.is_none());
    }

    #[test]
    fn agreement_table() {
        let c = cfg(vec![], &[("a", 1)]);
        let (adv, _) = compute(&c, &names(&["a"]));
        let d = adv.digest.unwrap();
        let v2 = |alg, digest: [u8; 16]| PartnerV2 {
            version: Some(2),
            algorithm: Some(alg),
            digest: Some(ConvDigest {
                link_number: 1,
                digest,
            }),
        };
        assert_eq!(
            agreement(&adv, &v2(PortAlgorithm::CVid, d)),
            Agreement::Agreed
        );
        assert_eq!(
            agreement(&adv, &v2(PortAlgorithm::SVid, d)),
            Agreement::Mismatch("algorithm")
        );
        assert_eq!(
            agreement(&adv, &v2(PortAlgorithm::CVid, [0; 16])),
            Agreement::Mismatch("digest")
        );
        let none = PartnerV2 {
            version: Some(2),
            algorithm: Some(PortAlgorithm::CVid),
            digest: None,
        };
        assert_eq!(agreement(&adv, &none), Agreement::Mismatch("no-digest"));
        let v1 = PartnerV2 {
            version: Some(1),
            ..PartnerV2::default()
        };
        assert_eq!(agreement(&adv, &v1), Agreement::PartnerV1);
        assert_eq!(
            agreement(&adv, &PartnerV2::default()),
            Agreement::NotRequested
        );
        let local_none = Advert::default();
        assert_eq!(
            agreement(&local_none, &v2(PortAlgorithm::CVid, d)),
            Agreement::NotRequested
        );
        let no_links = Advert {
            algorithm: PortAlgorithm::CVid,
            digest: Err("no-link-number"),
        };
        assert_eq!(
            agreement(&no_links, &v2(PortAlgorithm::CVid, d)),
            Agreement::Mismatch("no-link-number")
        );
    }

    #[test]
    fn overall_is_all_or_nothing() {
        let c = cfg(vec![], &[("a", 1)]);
        let (adv, _) = compute(&c, &names(&["a"]));
        let good = PartnerV2 {
            version: Some(2),
            algorithm: Some(PortAlgorithm::CVid),
            digest: Some(ConvDigest {
                link_number: 1,
                digest: adv.digest.unwrap(),
            }),
        };
        let bad = PartnerV2 {
            digest: None,
            ..good
        };
        assert_eq!(overall(&adv, [&good, &good]), Agreement::Agreed);
        assert_eq!(
            overall(&adv, [&good, &bad]),
            Agreement::Mismatch("no-digest")
        );
        assert_eq!(overall(&adv, []), Agreement::NotRequested);
    }

    #[test]
    fn wire_conversions() {
        assert_eq!(
            Agreement::Agreed.to_wire(),
            nos_proto::LacpAgreement::Agreed
        );
        assert_eq!(Agreement::Mismatch("x").label(), ("Mismatch", "x"));
        for a in [
            LacpPortAlgorithm::Unspecified,
            LacpPortAlgorithm::CVlan,
            LacpPortAlgorithm::SVlan,
        ] {
            assert_eq!(proto_algorithm(wire_algorithm(a)), Some(a));
        }
        assert_eq!(proto_algorithm(PortAlgorithm::Other([1; 4])), None);
        assert_eq!(V2Cfg::default().version_pref(), 1);
    }
}
