//! SAFI 128 NLRI and next hop (RFC 4364 section 4.3, RFC 8277 section 2,
//! RFC 4659 section 3.2.1).
//!
//! NLRI: `length(1, bits) | labels (3 octets each: label<<4 | S) | RD(8) |
//! prefix (ceil(bits/8) octets)`. No Path Identifier ever precedes it: the
//! caller's ADD-PATH set is keyed by AFI only and must not be consulted for
//! SAFI 128. Any parse failure is `MalformedUpdate` (a session reset): RFC
//! 7606 section 3(j) only allows treat-as-withdraw for a fully parsed NLRI.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use super::{Rd, VpnNlri};
use crate::message::{WireError, AFI_IPV4, AFI_IPV6};

/// RFC 8277 section 2.4: the Compatibility field of a withdrawal.
const WITHDRAW_LABEL: u32 = 0x80_0000;
const RD_BITS: usize = 64;
const LABEL_BITS: usize = 24;

fn max_prefix_bits(afi: u16) -> Result<usize, WireError> {
    match afi {
        AFI_IPV4 => Ok(32),
        AFI_IPV6 => Ok(128),
        _ => Err(WireError::MalformedUpdate),
    }
}

/// One NLRI: a label stack ending at S=1 (reach), or the single fixed
/// Compatibility field of a `withdrawal`.
fn decode_one(
    afi: u16,
    mut data: &[u8],
    withdrawal: bool,
    add_path: bool,
) -> Result<(VpnNlri, usize), WireError> {
    let max_bits = max_prefix_bits(afi)?;
    // RFC 7911 section 3: the Path Identifier precedes the length octet.
    let (path_id, id_len) = if add_path {
        let id = data.get(..4).ok_or(WireError::MalformedUpdate)?;
        let id = u32::from_be_bytes(id.try_into().unwrap());
        data = &data[4..];
        (Some(id), 4)
    } else {
        (None, 0)
    };
    let bits = usize::from(*data.first().ok_or(WireError::MalformedUpdate)?);
    let total = 1 + bits.div_ceil(8);
    let body = data.get(1..total).ok_or(WireError::MalformedUpdate)?;
    let mut labels = Vec::new();
    let mut pos = 0;
    loop {
        // The label field must lie within the stated length, not merely the
        // octets present.
        if (pos + 3) * 8 > bits {
            return Err(WireError::MalformedUpdate);
        }
        let raw = u32::from_be_bytes([0, body[pos], body[pos + 1], body[pos + 2]]);
        pos += 3;
        if withdrawal {
            break;
        }
        labels.push(raw >> 4);
        if raw & 1 == 1 {
            break;
        }
    }
    let prefix_bits = (bits - pos * 8)
        .checked_sub(RD_BITS)
        .ok_or(WireError::MalformedUpdate)?;
    if prefix_bits > max_bits {
        return Err(WireError::MalformedUpdate);
    }
    let rd: Rd = body[pos..pos + 8].try_into().unwrap();
    pos += 8;
    let mut octets = [0u8; 16];
    let n = prefix_bits.div_ceil(8);
    octets[..n].copy_from_slice(&body[pos..pos + n]);
    let addr: IpAddr = if afi == AFI_IPV4 {
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).into()
    } else {
        Ipv6Addr::from(octets).into()
    };
    let prefix = IpNet::new(addr, u8::try_from(prefix_bits).unwrap())
        .map_err(|_| WireError::MalformedUpdate)?
        .trunc();
    Ok((
        VpnNlri {
            labels,
            rd,
            prefix,
            path_id,
        },
        total + id_len,
    ))
}

fn decode_all(
    afi: u16,
    mut data: &[u8],
    withdrawal: bool,
    add_path: bool,
) -> Result<Vec<VpnNlri>, WireError> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let (n, used) = decode_one(afi, data, withdrawal, add_path)?;
        out.push(n);
        data = &data[used..];
    }
    Ok(out)
}

/// A run of announced VPN NLRIs (each preceded by a 4-octet Path Identifier
/// when `add_path`, RFC 7911); the label stack ends at the first label with
/// S=1 (RFC 8277 section 2.3).
///
/// # Errors
/// `MalformedUpdate` for an AFI other than 1/2, a length that does not cover
/// the labels and RD, a missing S=1, a prefix longer than the AFI allows,
/// truncated octets or trailing bytes.
pub fn decode_vpn_reach(afi: u16, data: &[u8], add_path: bool) -> Result<Vec<VpnNlri>, WireError> {
    decode_all(afi, data, false, add_path)
}

/// A run of withdrawn VPN NLRIs: one Compatibility field whose value is
/// ignored (RFC 8277 section 2.4), so `labels` is empty.
///
/// # Errors
/// As [`decode_vpn_reach`].
pub fn decode_vpn_unreach(
    afi: u16,
    data: &[u8],
    add_path: bool,
) -> Result<Vec<VpnNlri>, WireError> {
    decode_all(afi, data, true, add_path)
}

fn encode_one(n: &VpnNlri, label_field: u32, out: &mut Vec<u8>) {
    if let Some(id) = n.path_id {
        out.extend_from_slice(&id.to_be_bytes());
    }
    let prefix_bits = usize::from(n.prefix.prefix_len());
    // At most 24 + 64 + 128 bits: fits the length octet.
    out.push(u8::try_from(LABEL_BITS + RD_BITS + prefix_bits).unwrap());
    out.extend_from_slice(&label_field.to_be_bytes()[1..]);
    out.extend_from_slice(&n.rd);
    let take = prefix_bits.div_ceil(8);
    match n.prefix.trunc().addr() {
        IpAddr::V4(a) => out.extend_from_slice(&a.octets()[..take]),
        IpAddr::V6(a) => out.extend_from_slice(&a.octets()[..take]),
    }
}

/// Appends announced NLRIs, always with exactly one label and S=1 (RFC 8277
/// section 2.2; the Multiple Labels capability is not advertised).
// ponytail: only `labels[0]` is sent; a label stack needs capability 8 (bgp/TODO.md).
pub fn encode_vpn_reach(nlris: &[VpnNlri], out: &mut Vec<u8>) {
    for n in nlris {
        debug_assert!(!n.labels.is_empty(), "a VPN announcement needs a label");
        let label = n.labels.first().copied().unwrap_or(0);
        encode_one(n, ((label & 0xf_ffff) << 4) | 1, out);
    }
}

/// Appends withdrawn NLRIs with the 0x800000 Compatibility field.
pub fn encode_vpn_unreach(nlris: &[VpnNlri], out: &mut Vec<u8>) {
    for n in nlris {
        encode_one(n, WITHDRAW_LABEL, out);
    }
}

/// The next hop of a SAFI 128 `MP_REACH_NLRI` (RFC 4364 section 4.3.2): an
/// 8-octet zero RD (a non-zero one is ignored) then the address. Accepts
/// 12 (RD + IPv4), 24 (RD + IPv6), 48 (RD + global + RD + link-local, the
/// link-local dropped) and, tolerantly, 4/16/32 without an RD. For AFI 2 an
/// IPv4-mapped IPv6 address (RFC 4659 section 3.2.1.2) is returned as IPv4.
///
/// # Errors
/// `MalformedUpdate` for any other length (RFC 7606 section 7.11).
pub fn decode_next_hop(afi: u16, nh: &[u8]) -> Result<IpAddr, WireError> {
    let addr = match nh.len() {
        4 => Ipv4Addr::from(<[u8; 4]>::try_from(nh).unwrap()).into(),
        12 => Ipv4Addr::from(<[u8; 4]>::try_from(&nh[8..]).unwrap()).into(),
        16 | 32 => v6(&nh[..16]),
        24 | 48 => v6(&nh[8..24]),
        _ => return Err(WireError::MalformedUpdate),
    };
    Ok(match addr {
        IpAddr::V6(a) if afi == AFI_IPV6 => a.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        _ => addr,
    })
}

fn v6(b: &[u8]) -> IpAddr {
    Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap()).into()
}

/// Appends a SAFI 128 next hop: 8 zero octets then the address; an IPv4
/// next hop of an AFI 2 batch is sent IPv4-mapped.
pub fn encode_next_hop(afi: u16, nh: IpAddr, out: &mut Vec<u8>) {
    let a = match nh {
        IpAddr::V4(a) if afi == AFI_IPV6 => {
            out.push(24);
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&a.to_ipv6_mapped().octets());
            return;
        }
        a => a,
    };
    match a {
        IpAddr::V4(a) => {
            out.push(12);
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(24);
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&a.octets());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RD: Rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 100];

    fn is_malformed<T: std::fmt::Debug>(r: Result<T, WireError>) {
        match r {
            Err(WireError::MalformedUpdate) => {}
            other => panic!("expected MalformedUpdate, got {other:?}"),
        }
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn route(labels: &[u32], prefix: &str) -> VpnNlri {
        VpnNlri {
            path_id: None,
            labels: labels.to_vec(),
            rd: RD,
            prefix: net(prefix),
        }
    }

    #[test]
    fn single_label_ipv4_vector() {
        // 10.1.0.0/16, label 100 (0x000640 | S): length 24+64+16 = 104.
        let mut want = vec![104, 0x00, 0x06, 0x41];
        want.extend_from_slice(&RD);
        want.extend_from_slice(&[10, 1]);
        let mut got = Vec::new();
        encode_vpn_reach(&[route(&[100], "10.1.0.0/16")], &mut got);
        assert_eq!(got, want);
        assert_eq!(
            decode_vpn_reach(AFI_IPV4, &want, false).unwrap(),
            vec![route(&[100], "10.1.0.0/16")]
        );
    }

    #[test]
    fn default_and_host_routes_have_the_rfc_8277_lengths() {
        for (p, afi, len) in [
            ("0.0.0.0/0", AFI_IPV4, 88),
            ("192.0.2.1/32", AFI_IPV4, 120),
            ("::/0", AFI_IPV6, 88),
            ("2001:db8::1/128", AFI_IPV6, 216),
        ] {
            let mut b = Vec::new();
            encode_vpn_reach(&[route(&[3], p)], &mut b);
            assert_eq!(b[0], len, "{p}");
            assert_eq!(
                decode_vpn_reach(afi, &b, false).unwrap(),
                vec![route(&[3], p)]
            );
        }
    }

    #[test]
    fn label_stacks_of_one_to_three_are_decoded_s_bit_driven() {
        for stack in [vec![5], vec![5, 6], vec![5, 6, 7]] {
            let mut b = vec![u8::try_from(24 * stack.len() + 64 + 8).unwrap()];
            for (i, l) in stack.iter().enumerate() {
                let s = u32::from(i + 1 == stack.len());
                b.extend_from_slice(&((l << 4) | s).to_be_bytes()[1..]);
            }
            b.extend_from_slice(&RD);
            b.push(10);
            let got = decode_vpn_reach(AFI_IPV4, &b, false).unwrap();
            assert_eq!(got, vec![route(&stack, "10.0.0.0/8")]);
        }
        // IPv6 stack of two.
        let mut b = vec![24 * 2 + 64 + 32];
        b.extend_from_slice(&[0, 0, 0x50, 0, 0, 0x61]);
        b.extend_from_slice(&RD);
        b.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(
            decode_vpn_reach(AFI_IPV6, &b, false).unwrap(),
            vec![route(&[5, 6], "2001:db8::/32")]
        );
    }

    #[test]
    fn several_nlris_in_one_run() {
        let v = vec![route(&[1], "10.0.0.0/8"), route(&[2], "172.16.0.0/12")];
        let mut b = Vec::new();
        encode_vpn_reach(&v, &mut b);
        assert_eq!(decode_vpn_reach(AFI_IPV4, &b, false).unwrap(), v);
        assert_eq!(decode_vpn_reach(AFI_IPV4, &[], false).unwrap(), vec![]);
    }

    #[test]
    fn malformed_reach_nlris_are_rejected() {
        let good = {
            let mut b = Vec::new();
            encode_vpn_reach(&[route(&[1], "10.0.0.0/8")], &mut b);
            b
        };
        let bad = |b: &[u8], afi| {
            is_malformed(decode_vpn_reach(afi, b, false));
        };
        // No S=1 anywhere before the bits run out.
        let mut no_s = good.clone();
        no_s[3] &= !1;
        bad(&no_s, AFI_IPV4);
        // Length shorter than label + RD.
        bad(&[80, 0, 0, 1], AFI_IPV4);
        bad(&[16, 0, 0, 1], AFI_IPV4);
        bad(&[0], AFI_IPV4);
        // Prefix longer than the AFI allows: 33 bits v4.
        let mut long = vec![24 + 64 + 33, 0, 0, 1];
        long.extend_from_slice(&RD);
        long.extend_from_slice(&[1, 2, 3, 4, 5]);
        bad(&long, AFI_IPV4);
        // ... but 33 bits is fine for IPv6.
        assert!(decode_vpn_reach(AFI_IPV6, &long, false).is_ok());
        // Truncated octets, trailing garbage, unknown AFI, missing length.
        bad(&good[..good.len() - 1], AFI_IPV4);
        let mut trail = good.clone();
        trail.push(0xff);
        bad(&trail, AFI_IPV4);
        bad(&good, 25);
        bad(&good[..1], AFI_IPV4);
    }

    #[test]
    fn host_bits_beyond_the_length_are_masked() {
        let mut b = vec![24 + 64 + 9, 0, 0, 1];
        b.extend_from_slice(&RD);
        b.extend_from_slice(&[10, 0xff]);
        assert_eq!(
            decode_vpn_reach(AFI_IPV4, &b, false).unwrap()[0].prefix,
            net("10.128.0.0/9")
        );
    }

    #[test]
    fn withdrawals_ignore_the_compatibility_value() {
        let w = route(&[], "10.1.0.0/16");
        let mut b = Vec::new();
        encode_vpn_unreach(&[route(&[77], "10.1.0.0/16")], &mut b);
        assert_eq!(&b[..4], &[24 + 64 + 16, 0x80, 0, 0]);
        assert_eq!(
            decode_vpn_unreach(AFI_IPV4, &b, false).unwrap(),
            vec![w.clone()]
        );
        // 0x000000, a real label with S=1, and 0x800000 all decode the same.
        for f in [[0, 0, 0], [0x00, 0x06, 0x41], [0x80, 0, 0]] {
            b[1..4].copy_from_slice(&f);
            assert_eq!(
                decode_vpn_unreach(AFI_IPV4, &b, false).unwrap(),
                vec![w.clone()]
            );
        }
        // Too short for the compatibility field + RD.
        is_malformed(decode_vpn_unreach(AFI_IPV4, &[16, 0x80, 0], false));
    }

    #[test]
    fn path_ids_precede_the_length_octet_and_round_trip() {
        for (afi, p) in [(AFI_IPV4, "10.1.0.0/16"), (AFI_IPV6, "2001:db8::/32")] {
            let mut n = route(&[100], p);
            n.path_id = Some(7);
            let mut reach = Vec::new();
            encode_vpn_reach(&[n.clone()], &mut reach);
            assert_eq!(&reach[..4], &[0, 0, 0, 7]);
            assert_eq!(
                decode_vpn_reach(afi, &reach, true).unwrap(),
                vec![n.clone()]
            );
            let mut w = n.clone();
            w.labels.clear();
            let mut unreach = Vec::new();
            encode_vpn_unreach(&[w.clone()], &mut unreach);
            assert_eq!(&unreach[..4], &[0, 0, 0, 7]);
            assert_eq!(decode_vpn_unreach(afi, &unreach, true).unwrap(), vec![w]);
            // Without negotiation the id is misread: never accepted silently.
            assert!(decode_vpn_reach(afi, &reach[..3], true).is_err());
        }
    }

    #[test]
    fn next_hop_forms() {
        let v4 = Ipv4Addr::new(192, 0, 2, 1);
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let with = |tail: &[u8]| {
            let mut x = vec![0u8; 8];
            x.extend_from_slice(tail);
            x
        };
        assert_eq!(
            decode_next_hop(AFI_IPV4, &with(&v4.octets())).ok(),
            Some(v4.into())
        );
        assert_eq!(
            decode_next_hop(AFI_IPV6, &with(&v6.octets())).ok(),
            Some(v6.into())
        );
        assert_eq!(
            decode_next_hop(AFI_IPV4, &with(&v6.octets())).ok(),
            Some(v6.into())
        );
        let mut nh48 = with(&v6.octets());
        nh48.extend_from_slice(&[0; 8]);
        nh48.extend_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(decode_next_hop(AFI_IPV6, &nh48).ok(), Some(v6.into()));
        // Tolerant forms without an RD.
        assert_eq!(
            decode_next_hop(AFI_IPV4, &v4.octets()).ok(),
            Some(v4.into())
        );
        assert_eq!(
            decode_next_hop(AFI_IPV6, &v6.octets()).ok(),
            Some(v6.into())
        );
        let mut nh32 = v6.octets().to_vec();
        nh32.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(decode_next_hop(AFI_IPV6, &nh32).ok(), Some(v6.into()));
        // A non-zero next-hop RD is ignored.
        let mut nonzero = with(&v4.octets());
        nonzero[7] = 9;
        assert_eq!(decode_next_hop(AFI_IPV4, &nonzero).ok(), Some(v4.into()));
        // IPv4-mapped IPv6 is the IPv4 PE address on AFI 2 only.
        let mapped = v4.to_ipv6_mapped().octets();
        assert_eq!(
            decode_next_hop(AFI_IPV6, &with(&mapped)).ok(),
            Some(v4.into())
        );
        assert_eq!(
            decode_next_hop(AFI_IPV4, &with(&mapped)).ok(),
            Some(v4.to_ipv6_mapped().into())
        );
        for len in [0, 1, 8, 13, 20, 40] {
            is_malformed(decode_next_hop(AFI_IPV4, &vec![0; len]));
        }
    }

    #[test]
    fn next_hop_encoding_round_trips_through_the_decoder() {
        let v4: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        for (afi, nh, len) in [
            (AFI_IPV4, v4, 12),
            (AFI_IPV6, v4, 24), // mapped
            (AFI_IPV6, v6, 24),
            (AFI_IPV4, v6, 24),
        ] {
            let mut b = Vec::new();
            encode_next_hop(afi, nh, &mut b);
            assert_eq!(usize::from(b[0]), len);
            assert_eq!(&b[1..9], &[0; 8]);
            assert_eq!(decode_next_hop(afi, &b[1..]).ok(), Some(nh));
        }
    }
}
