//! Router Solicitation / Advertisement codec (RFC 4861 s4.1, s4.2, s4.6,
//! RFC 4191 s2.1, RFC 8106 s5). Pure; every decoder reads untrusted bytes and
//! never panics. The `ICMPv6` checksum stays 0: the kernel fills it on a raw
//! `IPPROTO_ICMPV6` socket.

use std::net::{IpAddr, Ipv6Addr};

use nos_proto::schema::ra_profile::MAX_RA_LEN;
use nos_proto::schema::{RaPreference, RaProfile};

pub const TYPE_RS: u8 = 133;
pub const TYPE_RA: u8 = 134;
const OPT_SLLA: u8 = 1;
const OPT_PREFIX: u8 = 3;
const OPT_MTU: u8 = 5;
const OPT_RDNSS: u8 = 25;
const OPT_DNSSL: u8 = 31;
const RA_HEADER: usize = 16;
const RS_HEADER: usize = 8;
/// Options parsed per message; more are ignored (untrusted input).
const MAX_OPTIONS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("hop limit is not 255")]
    HopLimit,
    #[error("not a {0} message or code is not 0")]
    Type(&'static str),
    #[error("message too short")]
    Short,
    #[error("bad source address")]
    Source,
    #[error("option with length 0 or beyond the message")]
    Option,
    #[error("solicitation from the unspecified address carries a source link-layer address")]
    UnspecifiedWithSlla,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    #[error("advertisement is {0} bytes, over the {MAX_RA_LEN} byte limit")]
    TooLong(usize),
    #[error("invalid domain name '{0}'")]
    Domain(String),
}

/// One Prefix Information option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInfo {
    pub prefix: Ipv6Addr,
    pub len: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid: u32,
    pub preferred: u32,
}

/// A parsed Router Advertisement (ours or a foreign one).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ra {
    pub hop_limit: u8,
    pub managed: bool,
    pub other: bool,
    /// Raw 2-bit Prf field.
    pub prf: u8,
    pub router_lifetime: u16,
    pub reachable_ms: u32,
    pub retrans_ms: u32,
    pub mtu: Option<u32>,
    pub prefixes: Vec<PrefixInfo>,
}

/// What `build_ra` encodes: a profile resolved against the live link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaParams {
    pub profile: RaProfile,
    pub lladdr: Option<[u8; 6]>,
    /// The link MTU, advertised only when the profile asks for it.
    pub link_mtu: Option<u32>,
    /// Final RA (RFC 4861 s6.2.5): router lifetime 0.
    pub final_ra: bool,
}

/// RFC 4191 s2.1: high 01, medium 00, low 11 (10 is reserved, never sent).
pub fn prf_bits(p: RaPreference) -> u8 {
    match p {
        RaPreference::High => 0b01,
        RaPreference::Medium => 0b00,
        RaPreference::Low => 0b11,
    }
}

fn push_dnssl_names(out: &mut Vec<u8>, domain: &str) -> Result<(), BuildError> {
    let d = domain.trim_end_matches('.');
    if d.is_empty() || d.len() > 253 {
        return Err(BuildError::Domain(domain.to_string()));
    }
    for label in d.split('.') {
        let Ok(l) = u8::try_from(label.len()) else {
            return Err(BuildError::Domain(domain.to_string()));
        };
        if l == 0 || l > 63 {
            return Err(BuildError::Domain(domain.to_string()));
        }
        out.push(l);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn lifetime_or_default(l: Option<u32>, max_interval: u32) -> u32 {
    l.unwrap_or(2 * max_interval)
}

/// Encodes the RA. Options in order: SLLA, MTU, Prefix Information, RDNSS, DNSSL.
pub fn build_ra(p: &RaParams) -> Result<Vec<u8>, BuildError> {
    let prof = &p.profile;
    let lifetime = if p.final_ra {
        0
    } else {
        u16::try_from(prof.effective_router_lifetime()).unwrap_or(u16::MAX)
    };
    let mut o = Vec::with_capacity(128);
    o.extend_from_slice(&[TYPE_RA, 0, 0, 0, prof.hop_limit]);
    o.push(
        u8::from(prof.managed) << 7
            | u8::from(prof.other_config) << 6
            | prf_bits(prof.preference) << 3,
    );
    o.extend_from_slice(&lifetime.to_be_bytes());
    o.extend_from_slice(&prof.reachable_time.to_be_bytes());
    o.extend_from_slice(&prof.retrans_timer.to_be_bytes());
    if let Some(mac) = p.lladdr {
        o.extend_from_slice(&[OPT_SLLA, 1]);
        o.extend_from_slice(&mac);
    }
    if let (true, Some(mtu)) = (prof.advertise_mtu, p.link_mtu) {
        o.extend_from_slice(&[OPT_MTU, 1, 0, 0]);
        o.extend_from_slice(&mtu.to_be_bytes());
    }
    for x in &prof.prefixes {
        o.extend_from_slice(&[OPT_PREFIX, 4, x.prefix.prefix_len()]);
        o.push(u8::from(!x.off_link) << 7 | u8::from(!x.no_autonomous) << 6);
        o.extend_from_slice(&x.valid_lifetime.to_be_bytes());
        o.extend_from_slice(&x.preferred_lifetime.to_be_bytes());
        o.extend_from_slice(&[0; 4]);
        o.extend_from_slice(&x.prefix.trunc().addr().octets());
    }
    for r in &prof.rdnss {
        let IpAddr::V6(a) = r.address else { continue };
        o.extend_from_slice(&[OPT_RDNSS, 3, 0, 0]);
        o.extend_from_slice(&lifetime_or_default(r.lifetime, prof.max_interval).to_be_bytes());
        o.extend_from_slice(&a.octets());
    }
    for d in &prof.dnssl {
        let mut names = Vec::new();
        push_dnssl_names(&mut names, &d.domain)?;
        let total = (8 + names.len()).div_ceil(8) * 8;
        o.extend_from_slice(&[OPT_DNSSL, u8::try_from(total / 8).unwrap_or(255), 0, 0]);
        o.extend_from_slice(&lifetime_or_default(d.lifetime, prof.max_interval).to_be_bytes());
        o.extend_from_slice(&names);
        o.resize(o.len() + (total - 8 - names.len()), 0);
    }
    if o.len() > MAX_RA_LEN {
        return Err(BuildError::TooLong(o.len()));
    }
    Ok(o)
}

fn is_link_local(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

/// Walks the options of `data`, calling `f(type, body)` (body excludes the
/// 2-byte type/length header). A zero length or an overrun is an error.
fn options(data: &[u8], mut f: impl FnMut(u8, &[u8])) -> Result<(), DecodeError> {
    let mut rest = data;
    let mut n = 0;
    while !rest.is_empty() {
        if rest.len() < 2 || rest[1] == 0 {
            return Err(DecodeError::Option);
        }
        let len = usize::from(rest[1]) * 8;
        if len > rest.len() {
            return Err(DecodeError::Option);
        }
        n += 1;
        if n <= MAX_OPTIONS {
            f(rest[0], &rest[2..len]);
        }
        rest = &rest[len..];
    }
    Ok(())
}

/// A validated Router Solicitation (RFC 4861 s6.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rs {
    pub source_lladdr: Option<[u8; 6]>,
}

pub fn decode_rs(data: &[u8], src: Ipv6Addr, hop_limit: Option<u8>) -> Result<Rs, DecodeError> {
    if hop_limit != Some(255) {
        return Err(DecodeError::HopLimit);
    }
    if data.len() < RS_HEADER {
        return Err(DecodeError::Short);
    }
    if data[0] != TYPE_RS || data[1] != 0 {
        return Err(DecodeError::Type("router solicitation"));
    }
    if !src.is_unspecified() && !is_link_local(&src) {
        return Err(DecodeError::Source);
    }
    let mut slla = None;
    options(&data[RS_HEADER..], |t, b| {
        if t == OPT_SLLA && b.len() >= 6 {
            let mut m = [0u8; 6];
            m.copy_from_slice(&b[..6]);
            slla = Some(m);
        }
    })?;
    if src.is_unspecified() && slla.is_some() {
        return Err(DecodeError::UnspecifiedWithSlla);
    }
    Ok(Rs {
        source_lladdr: slla,
    })
}

/// Parses an RA body without checking the source or hop limit (our own
/// packets, for the s6.2.7 comparison).
pub fn parse_ra(data: &[u8]) -> Result<Ra, DecodeError> {
    if data.len() < RA_HEADER {
        return Err(DecodeError::Short);
    }
    if data[0] != TYPE_RA || data[1] != 0 {
        return Err(DecodeError::Type("router advertisement"));
    }
    let mut ra = Ra {
        hop_limit: data[4],
        managed: data[5] & 0x80 != 0,
        other: data[5] & 0x40 != 0,
        prf: (data[5] >> 3) & 3,
        router_lifetime: u16::from_be_bytes([data[6], data[7]]),
        reachable_ms: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        retrans_ms: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        ..Ra::default()
    };
    options(&data[RA_HEADER..], |t, b| match t {
        OPT_MTU if b.len() >= 6 => ra.mtu = Some(u32::from_be_bytes([b[2], b[3], b[4], b[5]])),
        OPT_PREFIX if b.len() >= 30 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[14..30]);
            ra.prefixes.push(PrefixInfo {
                prefix: Ipv6Addr::from(a),
                len: b[0],
                on_link: b[1] & 0x80 != 0,
                autonomous: b[1] & 0x40 != 0,
                valid: u32::from_be_bytes([b[2], b[3], b[4], b[5]]),
                preferred: u32::from_be_bytes([b[6], b[7], b[8], b[9]]),
            });
        }
        _ => {}
    })?;
    Ok(ra)
}

/// A validated foreign RA (RFC 4861 s6.1.2).
pub fn decode_ra(data: &[u8], src: Ipv6Addr, hop_limit: Option<u8>) -> Result<Ra, DecodeError> {
    if hop_limit != Some(255) {
        return Err(DecodeError::HopLimit);
    }
    if !is_link_local(&src) {
        return Err(DecodeError::Source);
    }
    parse_ra(data)
}

/// RFC 4861 s6.2.7: which advertised parameters of `foreign` disagree with
/// `own`. Zero (unspecified) values and absent options never conflict.
pub fn inconsistencies(own: &Ra, foreign: &Ra) -> Vec<&'static str> {
    let mut v = Vec::new();
    let differ = |a: u32, b: u32| a != 0 && b != 0 && a != b;
    if differ(own.hop_limit.into(), foreign.hop_limit.into()) {
        v.push("hop-limit");
    }
    if own.managed != foreign.managed {
        v.push("managed");
    }
    if own.other != foreign.other {
        v.push("other-config");
    }
    if differ(own.reachable_ms, foreign.reachable_ms) {
        v.push("reachable-time");
    }
    if differ(own.retrans_ms, foreign.retrans_ms) {
        v.push("retrans-timer");
    }
    if matches!((own.mtu, foreign.mtu), (Some(a), Some(b)) if a != b) {
        v.push("mtu");
    }
    for f in &foreign.prefixes {
        let clash = own.prefixes.iter().any(|o| {
            o.prefix == f.prefix
                && o.len == f.len
                && (o.valid != f.valid || o.preferred != f.preferred)
        });
        if clash {
            v.push("prefix-lifetime");
            break;
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::schema::{RaDnssl, RaPrefix, RaRdnss};

    fn ll(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n)
    }

    fn params(profile: RaProfile) -> RaParams {
        RaParams {
            profile,
            lladdr: Some([2, 0, 0, 0, 0, 1]),
            link_mtu: Some(1500),
            final_ra: false,
        }
    }

    fn profile() -> RaProfile {
        RaProfile {
            name: "p".into(),
            managed: true,
            advertise_mtu: true,
            prefixes: vec![RaPrefix {
                prefix: "2001:db8:1::/64".parse().unwrap(),
                ..RaPrefix::default()
            }],
            rdnss: vec![RaRdnss {
                address: "2001:db8::53".parse().unwrap(),
                lifetime: None,
            }],
            dnssl: vec![RaDnssl {
                domain: "example.com".into(),
                lifetime: Some(1200),
            }],
            ..RaProfile::default()
        }
    }

    #[test]
    fn header_and_options_bytes() {
        let b = build_ra(&params(profile())).unwrap();
        // type, code, checksum, hop limit 64, M flag, lifetime 1800 (3 x 600)
        assert_eq!(&b[..8], &[134, 0, 0, 0, 64, 0x80, 0x07, 0x08]);
        assert_eq!(&b[8..16], &[0; 8]);
        // SLLA
        assert_eq!(&b[16..24], &[1, 1, 2, 0, 0, 0, 0, 1]);
        // MTU
        assert_eq!(&b[24..32], &[5, 1, 0, 0, 0, 0, 5, 0xdc]);
        // Prefix: len 64, L+A, 30d valid, 7d preferred
        assert_eq!(&b[32..36], &[3, 4, 64, 0xc0]);
        assert_eq!(&b[36..40], &2_592_000u32.to_be_bytes());
        assert_eq!(&b[40..44], &604_800u32.to_be_bytes());
        assert_eq!(&b[48..52], &[0x20, 0x01, 0x0d, 0xb8]);
        // RDNSS: type 25, len 3, lifetime 1200 (2 x 600 default)
        assert_eq!(&b[64..68], &[25, 3, 0, 0]);
        assert_eq!(&b[68..72], &1200u32.to_be_bytes());
        // DNSSL: 7"example"3"com"0 = 13 bytes -> 8 + 13 -> 24 bytes, len 3
        assert_eq!(&b[88..92], &[31, 3, 0, 0]);
        assert_eq!(&b[96..109], b"\x07example\x03com\x00");
        assert_eq!(b.len(), 88 + 24);
        assert!(b[109..].iter().all(|&x| x == 0));
    }

    #[test]
    fn preference_encoding_never_reserved() {
        assert_eq!(prf_bits(RaPreference::High), 0b01);
        assert_eq!(prf_bits(RaPreference::Medium), 0b00);
        assert_eq!(prf_bits(RaPreference::Low), 0b11);
        for p in [RaPreference::High, RaPreference::Medium, RaPreference::Low] {
            assert_ne!(prf_bits(p), 0b10);
            let mut pr = profile();
            pr.preference = p;
            let ra = parse_ra(&build_ra(&params(pr)).unwrap()).unwrap();
            assert_eq!(ra.prf, prf_bits(p));
        }
    }

    #[test]
    fn final_ra_has_lifetime_zero() {
        let mut p = params(profile());
        p.final_ra = true;
        assert_eq!(parse_ra(&build_ra(&p).unwrap()).unwrap().router_lifetime, 0);
    }

    #[test]
    fn roundtrip_and_flags() {
        let ra = parse_ra(&build_ra(&params(profile())).unwrap()).unwrap();
        assert!(ra.managed && !ra.other);
        assert_eq!(ra.mtu, Some(1500));
        assert_eq!(ra.router_lifetime, 1800);
        assert_eq!(ra.prefixes.len(), 1);
        assert!(ra.prefixes[0].on_link && ra.prefixes[0].autonomous);
        assert_eq!(
            ra.prefixes[0].prefix,
            "2001:db8:1::".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn mtu_only_when_asked() {
        let mut pr = profile();
        pr.advertise_mtu = false;
        assert_eq!(parse_ra(&build_ra(&params(pr)).unwrap()).unwrap().mtu, None);
    }

    #[test]
    fn rejects_bad_dnssl_and_oversize() {
        let mut pr = profile();
        pr.dnssl[0].domain = format!("{}.com", "a".repeat(64));
        assert!(matches!(build_ra(&params(pr)), Err(BuildError::Domain(_))));
        let mut pr = profile();
        pr.dnssl[0].domain = "a..b".into();
        assert!(build_ra(&params(pr)).is_err());
        let mut pr = profile();
        pr.rdnss = vec![pr.rdnss[0]; 80];
        assert!(matches!(build_ra(&params(pr)), Err(BuildError::TooLong(_))));
    }

    #[test]
    fn rs_validation() {
        let rs = [133, 0, 0, 0, 0, 0, 0, 0];
        assert!(decode_rs(&rs, ll(1), Some(255)).is_ok());
        assert!(decode_rs(&rs, Ipv6Addr::UNSPECIFIED, Some(255)).is_ok());
        assert_eq!(decode_rs(&rs, ll(1), Some(254)), Err(DecodeError::HopLimit));
        assert_eq!(decode_rs(&rs, ll(1), None), Err(DecodeError::HopLimit));
        assert_eq!(
            decode_rs(&rs, "2001:db8::1".parse().unwrap(), Some(255)),
            Err(DecodeError::Source)
        );
        assert_eq!(
            decode_rs(&rs[..7], ll(1), Some(255)),
            Err(DecodeError::Short)
        );
        let mut bad = rs;
        bad[1] = 1;
        assert!(matches!(
            decode_rs(&bad, ll(1), Some(255)),
            Err(DecodeError::Type(_))
        ));
        bad = rs;
        bad[0] = 134;
        assert!(decode_rs(&bad, ll(1), Some(255)).is_err());
        // SLLA allowed from a link-local source, not from ::
        let mut with = rs.to_vec();
        with.extend_from_slice(&[1, 1, 2, 0, 0, 0, 0, 9]);
        assert_eq!(
            decode_rs(&with, ll(1), Some(255)).unwrap().source_lladdr,
            Some([2, 0, 0, 0, 0, 9])
        );
        assert_eq!(
            decode_rs(&with, Ipv6Addr::UNSPECIFIED, Some(255)),
            Err(DecodeError::UnspecifiedWithSlla)
        );
    }

    #[test]
    fn options_must_have_length_and_fit() {
        let mut rs = vec![133, 0, 0, 0, 0, 0, 0, 0];
        rs.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(decode_rs(&rs, ll(1), Some(255)), Err(DecodeError::Option));
        let mut rs = vec![133, 0, 0, 0, 0, 0, 0, 0];
        rs.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(decode_rs(&rs, ll(1), Some(255)), Err(DecodeError::Option));
        let mut rs = vec![133, 0, 0, 0, 0, 0, 0, 0];
        rs.push(1);
        assert_eq!(decode_rs(&rs, ll(1), Some(255)), Err(DecodeError::Option));
    }

    #[test]
    fn ra_validation() {
        let b = build_ra(&params(profile())).unwrap();
        assert!(decode_ra(&b, ll(1), Some(255)).is_ok());
        assert_eq!(decode_ra(&b, ll(1), Some(64)), Err(DecodeError::HopLimit));
        assert_eq!(
            decode_ra(&b, "2001:db8::1".parse().unwrap(), Some(255)),
            Err(DecodeError::Source)
        );
        assert_eq!(
            decode_ra(&b[..15], ll(1), Some(255)),
            Err(DecodeError::Short)
        );
        let mut t = b.clone();
        t[0] = 133;
        assert!(decode_ra(&t, ll(1), Some(255)).is_err());
        // truncated mid-option
        assert!(decode_ra(&b[..b.len() - 3], ll(1), Some(255)).is_err());
    }

    #[test]
    fn never_panics_on_garbage() {
        for n in 0..64usize {
            let v: Vec<u8> = (0..n)
                .map(|i| u8::try_from((i * 37 + 134) % 256).unwrap())
                .collect();
            let _ = decode_rs(&v, ll(1), Some(255));
            let _ = decode_ra(&v, ll(1), Some(255));
            let mut w = vec![134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            w.extend_from_slice(&v);
            let _ = decode_ra(&w, ll(1), Some(255));
        }
    }

    #[test]
    fn inconsistency_detection() {
        let own = parse_ra(&build_ra(&params(profile())).unwrap()).unwrap();
        assert_eq!(inconsistencies(&own, &own), Vec::<&str>::new());
        let mut f = own.clone();
        f.managed = false;
        f.hop_limit = 32;
        f.mtu = Some(1400);
        f.prefixes[0].valid = 1;
        assert_eq!(
            inconsistencies(&own, &f),
            vec!["hop-limit", "managed", "mtu", "prefix-lifetime"]
        );
        // unspecified values never conflict
        let mut f = own.clone();
        f.hop_limit = 0;
        f.mtu = None;
        assert_eq!(inconsistencies(&own, &f), Vec::<&str>::new());
    }
}
