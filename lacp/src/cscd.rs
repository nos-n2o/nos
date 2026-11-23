//! Pure CSCD policy (#894, IEEE 802.1AX-2020 6.6): config -> administrative
//! conversation map and advertisement; `resolve` turns the Collecting ports'
//! partner TLVs into the agreement flags (p.99), `Link_Number` adoption (p.97)
//! and the per-link conversation masks. No I/O, no state machine (the five
//! Update Mask states collapse into one recompute, NOTE 2 p.102).

use std::collections::BTreeMap;

use nos_proto::interface::LACP_CONVERSATION_MASK_LEN;
use nos_proto::{LacpPortAlgorithm, LacpVersion};

use crate::conversation::{ConversationMap, PortAlgorithm, CONVERSATIONS};
use crate::packet::{ConvDigest, PortInfo};

/// The per-aggregate v2 settings, from config.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2Cfg {
    pub version: LacpVersion,
    pub algorithm: LacpPortAlgorithm,
    /// Explicit `(first, last, member)` ranges; empty = automatic.
    pub map: Vec<(u16, u16, String)>,
    /// `lacp-link-number` per member that has one (the `Admin_Link_Number`).
    pub link_numbers: BTreeMap<String, u16>,
    /// Every configured member, with or without a `lacp-link-number`.
    pub members: Vec<String>,
}

impl V2Cfg {
    pub fn version_pref(&self) -> u8 {
        match self.version {
            LacpVersion::V1 => 1,
            LacpVersion::V2 => 2,
        }
    }
}

/// What every link of the aggregate advertises. `algorithm` and `digest` come
/// from config only, never from link state; `link_numbers` is each member's
/// operational `Link_Number` (admin, or adopted from the partner).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advert {
    pub algorithm: PortAlgorithm,
    /// The map digest, or why there is none.
    pub digest: Result<[u8; 16], &'static str>,
    pub link_numbers: BTreeMap<String, u16>,
}

impl Default for Advert {
    fn default() -> Self {
        Self {
            algorithm: PortAlgorithm::Unspecified,
            digest: Err("unspecified"),
            link_numbers: BTreeMap::new(),
        }
    }
}

/// The partner's v2 view recorded from its last PDU (all `Copy`). A version-1
/// PDU carries no CSCD TLVs, so `algorithm`/`digest` stay `None`.
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

/// The administrative map (6.6.3.1): explicit ranges give `[member, then the
/// other links ascending]`, unlisted conversations have no link; automatic is
/// a full rotation over the configured `Link_Numbers` (conversation c starts at
/// `links[c % n]`), so a lost link only displaces its own conversations. Every
/// member needs an explicit number in automatic mode (open decision 2).
fn admin_map(cfg: &V2Cfg) -> Result<ConversationMap, &'static str> {
    let number = |n: &str| cfg.link_numbers.get(n).copied().ok_or("no-link-number");
    let mut links: Vec<u16> = cfg.link_numbers.values().copied().collect();
    links.sort_unstable();
    let mut map = ConversationMap::default();
    if !cfg.map.is_empty() {
        for (first, last, member) in &cfg.map {
            let n = number(member)?;
            let list: Vec<u16> = std::iter::once(n)
                .chain(links.iter().copied().filter(|l| *l != n))
                .collect();
            for c in *first..=*last {
                map.set_list(c, list.clone());
            }
        }
        return Ok(map);
    }
    if links.is_empty()
        || cfg
            .members
            .iter()
            .any(|m| !cfg.link_numbers.contains_key(m))
    {
        return Err("no-link-number");
    }
    for c in 0..CONVERSATIONS {
        let list = (0..links.len())
            .map(|k| links[(c + k) % links.len()])
            .collect();
        #[allow(clippy::cast_possible_truncation, reason = "c < 4096")]
        map.set_list(c as u16, list);
    }
    Ok(map)
}

/// The advertisement and (when there is one) the map behind it. Depends on
/// config only, so a link flap never changes it.
pub fn compute(cfg: &V2Cfg) -> (Advert, Option<ConversationMap>) {
    let algorithm = wire_algorithm(cfg.algorithm);
    let link_numbers = cfg.link_numbers.clone();
    let (digest, map) = if cfg.algorithm == LacpPortAlgorithm::Unspecified {
        (Err("unspecified"), None)
    } else {
        match admin_map(cfg) {
            Ok(m) => (Ok(m.digest()), Some(m)),
            Err(e) => (Err(e), None),
        }
    };
    (
        Advert {
            algorithm,
            digest,
            link_numbers,
        },
        map,
    )
}

/// Whether the partner's (system id, port id) is numerically lower than ours
/// (updateActiveLinks, p.97): the higher end adopts the lower end's numbers.
pub fn partner_is_lower(
    actor_system: (u16, [u8; 6]),
    actor_port: (u16, u16),
    p: &PortInfo,
) -> bool {
    (p.system_priority, p.system, p.port_priority, p.port)
        < (actor_system.0, actor_system.1, actor_port.0, actor_port.1)
}

/// One member port as [`resolve`] sees it.
#[derive(Debug, Clone)]
pub struct PortIn {
    pub name: String,
    /// Selected, partner synchronized and our mux Collecting or Distributing
    /// (`Active_LAG_Links`, p.93).
    pub collecting: bool,
    /// Mux `Distributing`: only these may receive steering (6.2.7, p.38).
    pub distributing: bool,
    pub partner_lower: bool,
    pub v2: PartnerV2,
}

/// One link's conversation mask for the push (conversation `c` is bit
/// `0x80 >> (c % 8)` of byte `c / 8`; NOS-internal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Steer {
    pub member: String,
    pub link_number: u16,
    pub mask: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Operational `Link_Number` per member with an administrative one.
    pub link_numbers: BTreeMap<String, u16>,
    /// `Discard_Wrong_Conversation` (p.99): no algorithm, digest or
    /// `Link_Number` differs over the Collecting ports.
    pub discard_wrong: bool,
    /// Display/log summary derived from the flags.
    pub agreement: Agreement,
    pub steer: Vec<Steer>,
}

/// The whole CSCD decision over the Collecting ports. Steering needs only a
/// map and a Collecting link (open decision 1 B); the collection filter
/// (`discard_wrong`) needs agreement.
pub fn resolve(
    cfg: &V2Cfg,
    advert: &Advert,
    map: Option<&ConversationMap>,
    ports: &[PortIn],
) -> Resolved {
    let mut out = Resolved {
        link_numbers: cfg.link_numbers.clone(),
        discard_wrong: false,
        agreement: Agreement::NotRequested,
        steer: Vec::new(),
    };
    if advert.algorithm == PortAlgorithm::Unspecified {
        return out;
    }
    let mine = match advert.digest {
        Ok(d) => d,
        Err(e) => {
            out.agreement = Agreement::Mismatch(e);
            return out;
        }
    };
    let coll: Vec<&PortIn> = ports.iter().filter(|p| p.collecting).collect();
    if coll.is_empty() {
        return out;
    }
    let v1 = coll.iter().any(|p| p.v2.version == Some(1));
    let differ_alg = coll
        .iter()
        .any(|p| p.v2.algorithm != Some(advert.algorithm));
    let no_digest = coll
        .iter()
        .any(|p| p.v2.digest.is_none_or(|d| d.link_number == 0));
    let differ_dig = coll
        .iter()
        .any(|p| p.v2.digest.is_some_and(|d| d.digest != mine));
    out.agreement = if v1 {
        Agreement::PartnerV1
    } else if differ_alg {
        Agreement::Mismatch("algorithm")
    } else if no_digest {
        Agreement::Mismatch("no-digest")
    } else if differ_dig {
        Agreement::Mismatch("digest")
    } else {
        Agreement::Agreed
    };
    out.discard_wrong = out.agreement == Agreement::Agreed;

    // `Link_Number` adoption (p.97), all-or-nothing so a swapped numbering
    // (every number moves) never trips over a half-applied state.
    if out.discard_wrong {
        let mut tentative = out.link_numbers.clone();
        for p in coll.iter().filter(|p| p.partner_lower) {
            if let Some(d) = p.v2.digest {
                tentative.insert(p.name.clone(), d.link_number);
            }
        }
        let mut seen: Vec<u16> = tentative.values().copied().collect();
        seen.sort_unstable();
        seen.dedup();
        if seen.len() == tentative.len() {
            out.link_numbers = tentative;
        }
    }

    let Some(map) = map else { return out };
    let mut by_number: BTreeMap<u16, usize> = BTreeMap::new();
    for (i, p) in coll.iter().enumerate() {
        if let Some(n) = out.link_numbers.get(&p.name) {
            by_number.entry(*n).or_insert(i);
        }
    }
    let mut masks: Vec<Vec<u8>> = vec![vec![0; LACP_CONVERSATION_MASK_LEN]; coll.len()];
    for c in 0..CONVERSATIONS {
        #[allow(clippy::cast_possible_truncation, reason = "c < 4096")]
        let list = map.list(c as u16);
        // First entry on a Collecting link wins; a 0 reached first = no link.
        let winner = list
            .iter()
            .take_while(|l| **l != 0)
            .find_map(|l| by_number.get(l));
        if let Some(&i) = winner
            && coll[i].distributing
        {
            masks[i][c / 8] |= 0x80 >> (c % 8);
        }
    }
    out.steer = coll
        .iter()
        .zip(masks)
        .filter(|(_, m)| m.iter().any(|b| *b != 0))
        .filter_map(|(p, mask)| {
            Some(Steer {
                member: p.name.clone(),
                link_number: *out.link_numbers.get(&p.name)?,
                mask,
            })
        })
        .collect();
    out
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
            members: nums.iter().map(|(n, _)| (*n).into()).collect(),
        }
    }

    fn partner(alg: PortAlgorithm, ln: u16, digest: [u8; 16]) -> PartnerV2 {
        PartnerV2 {
            version: Some(2),
            algorithm: Some(alg),
            digest: Some(ConvDigest {
                link_number: ln,
                digest,
            }),
        }
    }

    fn port(name: &str, coll: bool, dist: bool, lower: bool, v2: PartnerV2) -> PortIn {
        PortIn {
            name: name.into(),
            collecting: coll,
            distributing: dist,
            partner_lower: lower,
            v2,
        }
    }

    fn bit(mask: &[u8], c: usize) -> bool {
        mask[c / 8] & (0x80 >> (c % 8)) != 0
    }

    #[test]
    fn automatic_map_is_a_rotation_independent_of_input_order() {
        let c = cfg(vec![], &[("a", 2), ("b", 1), ("c", 3)]);
        let m = admin_map(&c).unwrap();
        assert_eq!(m.list(0), &[1, 2, 3]);
        assert_eq!(m.list(1), &[2, 3, 1]);
        assert_eq!(m.list(2), &[3, 1, 2]);
        assert_eq!(m.list(4095), &[1, 2, 3]); // 4095 % 3 == 0
        let mut c2 = c.clone();
        c2.members.reverse();
        assert_eq!(admin_map(&c2).unwrap(), m);
    }

    #[test]
    fn automatic_map_needs_a_number_on_every_member() {
        let mut c = cfg(vec![], &[("a", 1)]);
        c.members.push("b".into());
        assert_eq!(admin_map(&c), Err("no-link-number"));
        assert_eq!(admin_map(&cfg(vec![], &[])), Err("no-link-number"));
    }

    #[test]
    fn explicit_map_is_member_then_the_others_and_unlisted_has_no_link() {
        let c = cfg(
            vec![(0, 99, "b"), (4000, 4095, "a")],
            &[("a", 1), ("b", 2), ("c", 3)],
        );
        let m = admin_map(&c).unwrap();
        assert_eq!(m.list(0), &[2, 1, 3]);
        assert_eq!(m.list(99), &[2, 1, 3]);
        assert_eq!(m.list(100), &[] as &[u16]);
        assert_eq!(m.list(4095), &[1, 2, 3]);
        let bad = cfg(vec![(0, 1, "z")], &[]);
        assert_eq!(admin_map(&bad), Err("no-link-number"));
    }

    #[test]
    fn advert_ignores_link_state() {
        let c = cfg(vec![], &[("a", 1), ("b", 2)]);
        let (a1, _) = compute(&c);
        let (a2, _) = compute(&c);
        assert_eq!(a1, a2);
        assert!(a1.digest.is_ok());
        let mut u = c;
        u.algorithm = LacpPortAlgorithm::Unspecified;
        let (adv, map) = compute(&u);
        assert_eq!(adv.digest, Err("unspecified"));
        assert!(map.is_none());
    }

    fn two_link() -> (V2Cfg, Advert, ConversationMap) {
        let c = cfg(vec![], &[("a", 1), ("b", 2)]);
        let (adv, map) = compute(&c);
        (c, adv, map.unwrap())
    }

    #[test]
    fn vector_picks_the_first_collecting_link_and_only_displaced_move() {
        let (c, adv, map) = two_link();
        let d = adv.digest.unwrap();
        let p = partner(PortAlgorithm::CVid, 1, d);
        let both = [
            port("a", true, true, false, p),
            port("b", true, true, false, p),
        ];
        let r = resolve(&c, &adv, Some(&map), &both);
        assert!(r.discard_wrong);
        assert_eq!(r.agreement, Agreement::Agreed);
        let ma = &r.steer.iter().find(|s| s.member == "a").unwrap().mask;
        let mb = &r.steer.iter().find(|s| s.member == "b").unwrap().mask;
        // conversation 0 -> list [1,2] -> a; conversation 1 -> [2,1] -> b.
        assert!(bit(ma, 0) && !bit(ma, 1) && bit(mb, 1) && !bit(mb, 0));
        // b stops collecting: its conversations fall to a, a's stay put, and
        // the digest (config only) is unchanged.
        let down = [
            port("a", true, true, false, p),
            port("b", false, false, false, p),
        ];
        let r2 = resolve(&c, &adv, Some(&map), &down);
        assert_eq!(r2.steer.len(), 1);
        assert!(r2.steer[0].mask.iter().all(|b| *b == 0xff));
        assert_eq!(compute(&c).0.digest, adv.digest);
    }

    #[test]
    fn collecting_but_not_distributing_is_left_out_of_the_push() {
        let (c, adv, map) = two_link();
        let p = partner(PortAlgorithm::CVid, 1, adv.digest.unwrap());
        let ports = [
            port("a", true, true, false, p),
            port("b", true, false, false, p),
        ];
        let r = resolve(&c, &adv, Some(&map), &ports);
        let ma = &r.steer.iter().find(|s| s.member == "a").unwrap().mask;
        assert!(bit(ma, 0) && !bit(ma, 1)); // conversation 1 prefers b: not pushed
        assert!(r.steer.iter().all(|s| s.member != "b"));
    }

    #[test]
    fn no_collecting_link_means_no_steering() {
        let (c, adv, map) = two_link();
        let p = partner(PortAlgorithm::CVid, 1, adv.digest.unwrap());
        let r = resolve(&c, &adv, Some(&map), &[port("a", false, false, false, p)]);
        assert!(r.steer.is_empty() && !r.discard_wrong);
        assert_eq!(r.agreement, Agreement::NotRequested);
        let r = resolve(&c, &adv, Some(&map), &[]);
        assert_eq!(r.agreement, Agreement::NotRequested);
    }

    #[test]
    fn zero_in_the_list_means_no_link() {
        let (c, adv, _) = two_link();
        let mut map = ConversationMap::default();
        map.set_list(0, vec![0, 1]);
        map.set_list(1, vec![1]);
        let p = partner(PortAlgorithm::CVid, 1, adv.digest.unwrap());
        let r = resolve(&c, &adv, Some(&map), &[port("a", true, true, false, p)]);
        let ma = &r.steer[0].mask;
        assert!(!bit(ma, 0) && bit(ma, 1));
    }

    #[test]
    fn differ_flags_and_discard_wrong_truth_table() {
        let (c, adv, map) = two_link();
        let d = adv.digest.unwrap();
        let ok = partner(PortAlgorithm::CVid, 1, d);
        let case = |v2: PartnerV2| {
            let r = resolve(&c, &adv, Some(&map), &[port("a", true, true, false, v2)]);
            (r.agreement, r.discard_wrong, r.steer.is_empty())
        };
        assert_eq!(case(ok), (Agreement::Agreed, true, false));
        assert_eq!(
            case(partner(PortAlgorithm::SVid, 1, d)),
            (Agreement::Mismatch("algorithm"), false, false)
        );
        assert_eq!(
            case(partner(PortAlgorithm::Unspecified, 1, d)),
            (Agreement::Mismatch("algorithm"), false, false)
        );
        assert_eq!(
            case(partner(PortAlgorithm::CVid, 1, [0; 16])),
            (Agreement::Mismatch("digest"), false, false)
        );
        assert_eq!(
            case(partner(PortAlgorithm::CVid, 0, d)),
            (Agreement::Mismatch("no-digest"), false, false)
        );
        let none = PartnerV2 { digest: None, ..ok };
        assert_eq!(case(none).0, Agreement::Mismatch("no-digest"));
        let v1 = PartnerV2 {
            version: Some(1),
            ..PartnerV2::default()
        };
        assert_eq!(case(v1), (Agreement::PartnerV1, false, false));
    }

    #[test]
    fn any_one_differing_port_disables_the_filter_for_all() {
        let (c, adv, map) = two_link();
        let d = adv.digest.unwrap();
        let ports = [
            port("a", true, true, false, partner(PortAlgorithm::CVid, 1, d)),
            port(
                "b",
                true,
                true,
                false,
                partner(PortAlgorithm::CVid, 2, [9; 16]),
            ),
        ];
        let r = resolve(&c, &adv, Some(&map), &ports);
        assert!(!r.discard_wrong);
        assert_eq!(r.agreement, Agreement::Mismatch("digest"));
    }

    #[test]
    fn unspecified_or_broken_local_advert_never_steers() {
        let (mut c, _, _) = two_link();
        c.algorithm = LacpPortAlgorithm::Unspecified;
        let (adv, map) = compute(&c);
        let r = resolve(
            &c,
            &adv,
            map.as_ref(),
            &[port("a", true, true, false, PartnerV2::default())],
        );
        assert_eq!(
            (r.agreement, r.discard_wrong),
            (Agreement::NotRequested, false)
        );
        assert_eq!(r.steer, Vec::new());
        let mut bad = cfg(vec![], &[("a", 1)]);
        bad.members.push("b".into());
        let (adv, map) = compute(&bad);
        let r = resolve(&bad, &adv, map.as_ref(), &[]);
        assert_eq!(r.agreement, Agreement::Mismatch("no-link-number"));
    }

    #[test]
    fn link_numbers_are_adopted_only_when_agreed_and_partner_is_lower() {
        // Our admin numbers are swapped versus the partner's.
        let (c, adv, map) = two_link();
        let d = adv.digest.unwrap();
        let pa = partner(PortAlgorithm::CVid, 2, d); // partner calls our a "2"
        let pb = partner(PortAlgorithm::CVid, 1, d);
        let lower = [
            port("a", true, true, true, pa),
            port("b", true, true, true, pb),
        ];
        let r = resolve(&c, &adv, Some(&map), &lower);
        assert_eq!(r.link_numbers["a"], 2);
        assert_eq!(r.link_numbers["b"], 1);
        // Partner not lower: keep the admin numbers.
        let higher = [
            port("a", true, true, false, pa),
            port("b", true, true, false, pb),
        ];
        assert_eq!(resolve(&c, &adv, Some(&map), &higher).link_numbers["a"], 1);
        // A differing digest blocks adoption.
        let bad = [port(
            "a",
            true,
            true,
            true,
            partner(PortAlgorithm::CVid, 2, [1; 16]),
        )];
        assert_eq!(resolve(&c, &adv, Some(&map), &bad).link_numbers["a"], 1);
        // A clash (both ports would become 2) is refused as a whole.
        let clash = [
            port("a", true, true, true, pa),
            port("b", true, true, true, pa),
        ];
        let r = resolve(&c, &adv, Some(&map), &clash);
        assert_eq!((r.link_numbers["a"], r.link_numbers["b"]), (1, 2));
        // Stopped collecting: back to the administrative number.
        let stopped = [port("a", false, false, true, pa)];
        assert_eq!(resolve(&c, &adv, Some(&map), &stopped).link_numbers["a"], 1);
    }

    #[test]
    fn partner_lower_compares_system_then_port() {
        let mk = |prio, sys: u8, pport| PortInfo {
            system_priority: prio,
            system: [0, 0, 0, 0, 0, sys],
            port_priority: 0x8000,
            port: pport,
            ..PortInfo::ADMINISTRATIVE_DEFAULT
        };
        let me = (0x8000, [0, 0, 0, 0, 0, 5]);
        assert!(partner_is_lower(me, (0x8000, 1), &mk(0x8000, 4, 9)));
        assert!(!partner_is_lower(me, (0x8000, 1), &mk(0x8000, 6, 1)));
        assert!(partner_is_lower(me, (0x8000, 3), &mk(0x8000, 5, 2)));
        assert!(!partner_is_lower(me, (0x8000, 1), &mk(0x8000, 5, 1)));
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
