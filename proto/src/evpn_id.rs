//! EVPN Route Distinguisher / Route Target text <-> wire encodings (RFC 4364
//! §4.2, RFC 4360). Lives here, not in `nos-bgp`, because `nos-config`'s
//! commit-time validation and `nos-fdbd` both need it and `nos-proto` can't
//! depend on a daemon.
//!
//! Text forms: `asn:nn` (ASN <= 65535 -> type 0, 4-byte nn), `asn:nn` with a
//! 4-byte ASN (type 2, 2-byte nn), `a.b.c.d:nn` (type 1, 2-byte nn).

use std::net::Ipv4Addr;

/// `(admin, assigned)` split of `text`, parsed as either an IPv4 address or a
/// number, plus what the administrator field turned out to be.
enum Admin {
    Asn(u32),
    Ip(Ipv4Addr),
}

fn split(text: &str) -> Option<(Admin, u32)> {
    let (admin, assigned) = text.split_once(':')?;
    let assigned = assigned.parse().ok()?;
    let admin = match admin.parse::<Ipv4Addr>() {
        Ok(ip) => Admin::Ip(ip),
        Err(_) => Admin::Asn(admin.parse().ok()?),
    };
    Some((admin, assigned))
}

/// Encodes an RD in the 8-byte wire form (`bgp::evpn::Rd`).
#[must_use]
pub fn parse_rd(text: &str) -> Option<[u8; 8]> {
    let (admin, n) = split(text)?;
    let mut out = [0u8; 8];
    match admin {
        Admin::Asn(asn) if u16::try_from(asn).is_ok() => {
            out[2..4].copy_from_slice(&asn.to_be_bytes()[2..]);
            out[4..8].copy_from_slice(&n.to_be_bytes());
        }
        Admin::Asn(asn) => {
            out[1] = 2;
            out[2..6].copy_from_slice(&asn.to_be_bytes());
            out[6..8].copy_from_slice(&u16::try_from(n).ok()?.to_be_bytes());
        }
        Admin::Ip(ip) => {
            out[1] = 1;
            out[2..6].copy_from_slice(&ip.octets());
            out[6..8].copy_from_slice(&u16::try_from(n).ok()?.to_be_bytes());
        }
    }
    Some(out)
}

/// Encodes a Route Target as the `u64` extended community `bgp` stores
/// (8 big-endian wire bytes: type, subtype 0x02, 6-byte value).
#[must_use]
pub fn parse_rt(text: &str) -> Option<u64> {
    let (admin, n) = split(text)?;
    let mut b = [0u8, 0x02, 0, 0, 0, 0, 0, 0];
    match admin {
        Admin::Asn(asn) if u16::try_from(asn).is_ok() => {
            b[2..4].copy_from_slice(&asn.to_be_bytes()[2..]);
            b[4..8].copy_from_slice(&n.to_be_bytes());
        }
        Admin::Asn(asn) => {
            b[0] = 2;
            b[2..6].copy_from_slice(&asn.to_be_bytes());
            b[6..8].copy_from_slice(&u16::try_from(n).ok()?.to_be_bytes());
        }
        Admin::Ip(ip) => {
            b[0] = 1;
            b[2..6].copy_from_slice(&ip.octets());
            b[6..8].copy_from_slice(&u16::try_from(n).ok()?.to_be_bytes());
        }
    }
    Some(u64::from_be_bytes(b))
}

/// The Site of Origin (RFC 4364 section 7, subtype 0x03) with `rt`'s value:
/// same three types, same encoding, only the subtype differs.
#[must_use]
pub fn soo_from_rt(rt: u64) -> u64 {
    (rt & !(0xff << 48)) | (0x03 << 48)
}

/// Parses `asn:nn` / `a.b.c.d:nn` as a Site of Origin (see [`parse_rt`]).
#[must_use]
pub fn parse_soo(text: &str) -> Option<u64> {
    parse_rt(text).map(soo_from_rt)
}

/// RFC 7348 / RFC 8365 VXLAN Encapsulation extended community (type 0x03,
/// subtype 0x0c, tunnel type 8).
pub const ENCAP_VXLAN: u64 = 0x030c_0000_0000_0008;

/// RFC 7432 §7.8 Default Gateway extended community (type 0x03, subtype
/// 0x0d, all-zero value) — marks a Type-2 as the anycast gateway MAC/IP for
/// its subnet, so a remote PE knows it may proxy ARP/ND for it.
pub const DEFAULT_GATEWAY: u64 = 0x030d_0000_0000_0000;

/// An Ethernet Segment Identifier (RFC 7432 §5): a type byte + 9 value bytes.
pub type Esi = [u8; 10];

/// `N` colon-separated hex bytes (`00:11:22:...`), exactly two digits each.
fn parse_colon_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    let mut parts = text.split(':');
    for byte in &mut out {
        let p = parts.next()?;
        if p.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// An ESI in its text form, ten colon-separated hex bytes. All-zero is the
/// reserved "single-homed" ESI, so it is not a valid configured value.
#[must_use]
pub fn parse_esi(text: &str) -> Option<Esi> {
    parse_colon_hex(text).filter(|e: &Esi| e.iter().any(|b| *b != 0))
}

/// A unicast MAC address in its `aa:bb:cc:dd:ee:ff` text form.
#[must_use]
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    parse_colon_hex(text).filter(|m: &[u8; 6]| m[0] & 1 == 0)
}

/// Any MAC address (multicast and broadcast included) in its
/// `aa:bb:cc:dd:ee:ff` text form, for match keys such as an ACL's (#1595).
#[must_use]
pub fn parse_mac_any(text: &str) -> Option<[u8; 6]> {
    parse_colon_hex(text)
}

/// Renders an ESI as ten colon-separated hex octets (RFC 7432 section 5).
#[must_use]
pub fn format_esi(esi: &Esi) -> String {
    esi.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The ES-Import Route Target (RFC 7432 §7.6, type 0x06 subtype 0x02) an
/// Ethernet Segment route carries: the first six value bytes of the ESI.
#[must_use]
pub fn es_import_rt(esi: &Esi) -> u64 {
    let mut b = [0u8; 8];
    b[0] = 0x06;
    b[1] = 0x02;
    b[2..].copy_from_slice(&esi[1..7]);
    u64::from_be_bytes(b)
}

/// The ESI Label extended community (RFC 7432 §7.5, type 0x06 subtype 0x01) a
/// per-ES Ethernet A-D route carries. With VXLAN there is no ESI label
/// (RFC 8365 §8.3.1: local bias instead), so the label is zero and only the
/// flags octet matters: bit 0 is the Single-Active bit.
#[must_use]
pub fn esi_label_ext(single_active: bool) -> u64 {
    u64::from_be_bytes([0x06, 0x01, u8::from(single_active), 0, 0, 0, 0, 0])
}

/// The redundancy mode an ESI Label community announces: `Some(true)` for
/// single-active, `Some(false)` for all-active, `None` for any other community.
#[must_use]
pub fn parse_esi_label(c: u64) -> Option<bool> {
    let b = c.to_be_bytes();
    (b[0] == 0x06 && b[1] == 0x01).then_some(b[2] & 1 == 1)
}

/// RFC 8584 §2.2 DF Alg values.
pub const DF_ALG_MODULO: u8 = 0;
/// DF election algorithm code for Highest Random Weight (RFC 8584 section 3.2).
pub const DF_ALG_HRW: u8 = 1;

/// The DF Election extended community (RFC 8584 §2.2, type 0x06 subtype 0x06)
/// a Type-4 route carries: the DF Alg in the low 5 bits of octet 2, then a
/// 2-octet capability bitmap whose bit 1 (`0x4000`) is AC-DF.
#[must_use]
pub fn df_election_ext(alg: u8, ac_df: bool) -> u64 {
    let bitmap: u16 = if ac_df { 0x4000 } else { 0 };
    let b = bitmap.to_be_bytes();
    u64::from_be_bytes([0x06, 0x06, alg & 0x1f, b[0], b[1], 0, 0, 0])
}

/// `Some((alg, ac_df))` when `c` is a DF Election extended community.
#[must_use]
pub fn parse_df_election(c: u64) -> Option<(u8, bool)> {
    let b = c.to_be_bytes();
    (b[0] == 0x06 && b[1] == 0x06).then(|| (b[2] & 0x1f, b[3] & 0x40 != 0))
}

/// The MAC Mobility extended community (RFC 7432 §7.7, type 0x06 subtype
/// 0x00): a flags octet (bit 0 is the Sticky/static bit), a reserved octet,
/// then a 4-byte big-endian sequence number.
#[must_use]
pub fn mac_mobility_ext(seq: u32, sticky: bool) -> u64 {
    let s = seq.to_be_bytes();
    u64::from_be_bytes([0x06, 0x00, u8::from(sticky), 0, s[0], s[1], s[2], s[3]])
}

/// `Some((seq, sticky))` when `c` is a MAC Mobility extended community.
#[must_use]
pub fn parse_mac_mobility(c: u64) -> Option<(u32, bool)> {
    let b = c.to_be_bytes();
    (b[0] == 0x06 && b[1] == 0x00)
        .then(|| (u32::from_be_bytes([b[4], b[5], b[6], b[7]]), b[2] & 1 == 1))
}

/// The Router's MAC extended community (RFC 9135 §8.1, type 0x06 subtype
/// 0x03): the MAC an IP-VRF's Type-5 routes are to be bridged to on the far
/// side of the L3 VNI.
#[must_use]
pub fn router_mac_ext(mac: [u8; 6]) -> u64 {
    let mut b = [0x06, 0x03, 0, 0, 0, 0, 0, 0];
    b[2..].copy_from_slice(&mac);
    u64::from_be_bytes(b)
}

/// The MAC a Router's MAC extended community carries.
#[must_use]
pub fn parse_router_mac(c: u64) -> Option<[u8; 6]> {
    let b = c.to_be_bytes();
    (b[0] == 0x06 && b[1] == 0x03).then(|| [b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// `aa:bb:cc:dd:ee:ff`.
#[must_use]
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The kernel VXLAN device for `vni` — an L2 domain's (`nos-fdbd`) or an
/// IP-VRF's L3 VNI (`nos-ribd`) alike: a VNI is unique per netns, so the name
/// needs no registry (`vx16777215` is 10 chars, under `IFNAMSIZ`).
#[must_use]
pub fn vxlan_name(vni: u32) -> String {
    format!("vx{vni}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soo_has_the_rt_value_in_the_three_forms() {
        assert_eq!(parse_soo("65001:77"), Some(0x0003_fde9_0000_004d));
        assert_eq!(parse_soo("10.0.0.1:7"), Some(0x0103_0a00_0001_0007));
        assert_eq!(parse_soo("4200000000:9"), Some(0x0203_fa56_ea00_0009));
        assert_eq!(parse_soo("junk"), None);
        assert_eq!(
            soo_from_rt(parse_rt("65001:77").unwrap()),
            parse_soo("65001:77").unwrap()
        );
    }

    #[test]
    fn router_mac_round_trips_with_the_rfc_9135_layout() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(router_mac_ext(mac), 0x0603_0211_2233_4455);
        assert_eq!(parse_router_mac(router_mac_ext(mac)), Some(mac));
        assert_eq!(parse_router_mac(ENCAP_VXLAN), None);
        assert_eq!(parse_router_mac(esi_label_ext(true)), None);
        assert_eq!(format_mac(&mac), "02:11:22:33:44:55");
        assert_eq!(vxlan_name(5000), "vx5000");
    }

    #[test]
    fn default_gateway_is_distinct_from_encap_vxlan() {
        assert_eq!(DEFAULT_GATEWAY, 0x030d_0000_0000_0000);
        assert_ne!(DEFAULT_GATEWAY, ENCAP_VXLAN);
    }

    #[test]
    fn esi_label_carries_the_single_active_bit() {
        assert_eq!(esi_label_ext(false), 0x0601_0000_0000_0000);
        assert_eq!(esi_label_ext(true), 0x0601_0100_0000_0000);
        assert_eq!(parse_esi_label(esi_label_ext(true)), Some(true));
        assert_eq!(parse_esi_label(esi_label_ext(false)), Some(false));
        assert_eq!(parse_esi_label(ENCAP_VXLAN), None);
    }

    #[test]
    fn df_election_round_trips() {
        assert_eq!(df_election_ext(DF_ALG_HRW, true), 0x0606_0140_0000_0000);
        assert_eq!(df_election_ext(DF_ALG_MODULO, false), 0x0606_0000_0000_0000);
        for alg in [DF_ALG_MODULO, DF_ALG_HRW, 2] {
            for ac in [false, true] {
                assert_eq!(parse_df_election(df_election_ext(alg, ac)), Some((alg, ac)));
            }
        }
        assert_eq!(parse_df_election(esi_label_ext(true)), None);
        assert_eq!(parse_df_election(ENCAP_VXLAN), None);
    }

    #[test]
    fn mac_mobility_carries_sequence_and_sticky_bit() {
        assert_eq!(mac_mobility_ext(0, false), 0x0600_0000_0000_0000);
        assert_eq!(mac_mobility_ext(1, false), 0x0600_0000_0000_0001);
        assert_eq!(mac_mobility_ext(1, true), 0x0600_0100_0000_0001);
        assert_eq!(
            parse_mac_mobility(mac_mobility_ext(42, true)),
            Some((42, true))
        );
        assert_eq!(
            parse_mac_mobility(mac_mobility_ext(42, false)),
            Some((42, false))
        );
        assert_eq!(parse_mac_mobility(esi_label_ext(true)), None);
        assert_eq!(parse_mac_mobility(ENCAP_VXLAN), None);
    }

    #[test]
    fn rd_types() {
        assert_eq!(parse_rd("65000:1"), Some([0, 0, 0xfd, 0xe8, 0, 0, 0, 1]));
        assert_eq!(parse_rd("192.0.2.1:7"), Some([0, 1, 192, 0, 2, 1, 0, 7]));
        assert_eq!(
            parse_rd("4200000000:5"),
            Some([0, 2, 0xfa, 0x56, 0xea, 0, 0, 5])
        );
        assert_eq!(parse_rd("192.0.2.1:70000"), None);
        assert_eq!(parse_rd("nonsense"), None);
    }

    #[test]
    fn rt_matches_the_wire_bytes_bgp_prints() {
        // `RT:65000:10000` is what `bgp::evpn::format_ext_community` renders.
        assert_eq!(
            parse_rt("65000:10000"),
            Some(u64::from_be_bytes([0, 2, 0xfd, 0xe8, 0, 0, 0x27, 0x10]))
        );
        assert_eq!(
            parse_rt("192.0.2.1:7"),
            Some(u64::from_be_bytes([1, 2, 192, 0, 2, 1, 0, 7]))
        );
        assert_eq!(parse_rt("65000"), None);
    }

    #[test]
    fn esi_text_round_trips_and_rejects_bad_input() {
        let esi = parse_esi("00:11:22:33:44:55:66:77:88:99").unwrap();
        assert_eq!(
            esi,
            [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]
        );
        assert_eq!(format_esi(&esi), "00:11:22:33:44:55:66:77:88:99");
        assert_eq!(parse_esi("00:00:00:00:00:00:00:00:00:00"), None);
        assert_eq!(parse_esi("00:11:22"), None);
        assert_eq!(parse_esi("00:11:22:33:44:55:66:77:88:99:aa"), None);
        assert_eq!(parse_esi("0:11:22:33:44:55:66:77:88:99"), None);
    }

    #[test]
    fn mac_must_be_unicast() {
        assert_eq!(parse_mac("02:00:00:00:00:01"), Some([2, 0, 0, 0, 0, 1]));
        assert_eq!(parse_mac("01:80:c2:00:00:02"), None);
    }

    #[test]
    fn es_import_rt_is_esi_bytes_one_to_six() {
        let esi = parse_esi("00:11:22:33:44:55:66:77:88:99").unwrap();
        assert_eq!(
            es_import_rt(&esi),
            u64::from_be_bytes([6, 2, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        );
    }
}
