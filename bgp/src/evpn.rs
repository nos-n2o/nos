//! RFC 7432 / RFC 9136 EVPN NLRI (AFI 25, SAFI 70): the five route types'
//! wire format. Pure encode/decode — no I/O, no RIB state.
//!
//! Every NLRI on the wire is `route_type(1) length(1) body(length)`. Route
//! types this crate doesn't know are kept verbatim as [`EvpnNlri::Unknown`]
//! so they can still be stored, shown and withdrawn.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::message::WireError;

pub const ROUTE_ETHERNET_AD: u8 = 1;
pub const ROUTE_MAC_IP: u8 = 2;
pub const ROUTE_INCLUSIVE_MULTICAST: u8 = 3;
pub const ROUTE_ETHERNET_SEGMENT: u8 = 4;
pub const ROUTE_IP_PREFIX: u8 = 5;

/// Route Distinguisher (RFC 4364 §4.2), kept as its 8 raw wire bytes.
pub type Rd = [u8; 8];
/// Ethernet Segment Identifier (RFC 7432 §5), 10 raw wire bytes.
pub type Esi = [u8; 10];

/// One EVPN route's NLRI. Its identity in the RIB is [`EvpnNlri::route_key`].
/// `label`/`labels` hold the raw 24-bit field (a VNI for VXLAN, RFC 8365).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EvpnNlri {
    /// Type 1.
    EthernetAd {
        rd: Rd,
        esi: Esi,
        tag: u32,
        label: u32,
    },
    /// Type 2. `labels` holds one label, or two (MAC-VRF + IP-VRF).
    MacIp {
        rd: Rd,
        esi: Esi,
        tag: u32,
        mac: [u8; 6],
        ip: Option<IpAddr>,
        labels: Vec<u32>,
    },
    /// Type 3.
    InclusiveMulticast { rd: Rd, tag: u32, origin: IpAddr },
    /// Type 4.
    EthernetSegment { rd: Rd, esi: Esi, origin: IpAddr },
    /// Type 5 (RFC 9136).
    IpPrefix {
        rd: Rd,
        esi: Esi,
        tag: u32,
        prefix: IpNet,
        gateway: IpAddr,
        label: u32,
    },
    /// Any other route type, body untouched.
    Unknown { route_type: u8, body: Vec<u8> },
}

impl EvpnNlri {
    #[must_use]
    pub fn route_type(&self) -> u8 {
        match self {
            EvpnNlri::EthernetAd { .. } => ROUTE_ETHERNET_AD,
            EvpnNlri::MacIp { .. } => ROUTE_MAC_IP,
            EvpnNlri::InclusiveMulticast { .. } => ROUTE_INCLUSIVE_MULTICAST,
            EvpnNlri::EthernetSegment { .. } => ROUTE_ETHERNET_SEGMENT,
            EvpnNlri::IpPrefix { .. } => ROUTE_IP_PREFIX,
            EvpnNlri::Unknown { route_type, .. } => *route_type,
        }
    }

    /// The route distinguisher, when the type carries one (all known ones do).
    #[must_use]
    pub fn rd(&self) -> Option<Rd> {
        match self {
            EvpnNlri::EthernetAd { rd, .. }
            | EvpnNlri::MacIp { rd, .. }
            | EvpnNlri::InclusiveMulticast { rd, .. }
            | EvpnNlri::EthernetSegment { rd, .. }
            | EvpnNlri::IpPrefix { rd, .. } => Some(*rd),
            EvpnNlri::Unknown { .. } => None,
        }
    }

    /// The route's identity in a RIB: the NLRI with the fields RFC 7432 §7.1/
    /// §7.2 and RFC 9136 §3.1 call route *attributes* zeroed (Type-1's label,
    /// Type-2's ESI and labels, Type-5's ESI, gateway and label). A re-announce
    /// changing one of them is an implicit replace, and a withdrawal carrying
    /// different ones still removes the route.
    #[must_use]
    pub fn route_key(&self) -> EvpnNlri {
        let mut key = self.clone();
        match &mut key {
            EvpnNlri::EthernetAd { label, .. } => *label = 0,
            EvpnNlri::MacIp { esi, labels, .. } => {
                *esi = [0; 10];
                labels.clear();
            }
            EvpnNlri::IpPrefix {
                esi,
                gateway,
                label,
                prefix,
                ..
            } => {
                *esi = [0; 10];
                *label = 0;
                *gateway = match prefix {
                    IpNet::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
                    IpNet::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
                };
            }
            _ => {}
        }
        key
    }
}

/// `type:administrator:assigned` per RFC 4364 §4.2 (`65000:1`, `192.0.2.1:7`);
/// an unrecognised RD type falls back to hex.
#[must_use]
pub fn format_rd(rd: &Rd) -> String {
    let n16 = u16::from_be_bytes([rd[6], rd[7]]);
    match u16::from_be_bytes([rd[0], rd[1]]) {
        0 => format!(
            "{}:{}",
            u16::from_be_bytes([rd[2], rd[3]]),
            u32::from_be_bytes([rd[4], rd[5], rd[6], rd[7]])
        ),
        1 => format!("{}:{n16}", Ipv4Addr::new(rd[2], rd[3], rd[4], rd[5])),
        2 => format!("{}:{n16}", u32::from_be_bytes([rd[2], rd[3], rd[4], rd[5]])),
        _ => hex(rd),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

impl fmt::Display for EvpnNlri {
    /// `[type]:[rd]:...` in the style of other stacks' `show` output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.route_type())?;
        match self {
            EvpnNlri::EthernetAd {
                rd,
                esi,
                tag,
                label,
            } => {
                write!(f, ":[{}]:[{}]:[{tag}]:[{label}]", format_rd(rd), hex(esi))
            }
            EvpnNlri::MacIp {
                rd,
                esi,
                tag,
                mac,
                ip,
                labels,
            } => {
                write!(
                    f,
                    ":[{}]:[{}]:[{tag}]:[48]:[{}]",
                    format_rd(rd),
                    hex(esi),
                    hex(mac)
                )?;
                match ip {
                    Some(ip) => write!(f, ":[{ip}]")?,
                    None => write!(f, ":[]")?,
                }
                for l in labels {
                    write!(f, ":[{l}]")?;
                }
                Ok(())
            }
            EvpnNlri::InclusiveMulticast { rd, tag, origin } => {
                write!(f, ":[{}]:[{tag}]:[{origin}]", format_rd(rd))
            }
            EvpnNlri::EthernetSegment { rd, esi, origin } => {
                write!(f, ":[{}]:[{}]:[{origin}]", format_rd(rd), hex(esi))
            }
            EvpnNlri::IpPrefix {
                rd,
                esi,
                tag,
                prefix,
                gateway,
                label,
            } => write!(
                f,
                ":[{}]:[{}]:[{tag}]:[{prefix}]:[{gateway}]:[{label}]",
                format_rd(rd),
                hex(esi)
            ),
            EvpnNlri::Unknown { body, .. } => write!(f, ":[{}]", hex(body)),
        }
    }
}

// ---- decode ---------------------------------------------------------------

/// Bounds-checked cursor over one NLRI body.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.0.len() < n {
            return Err(WireError::InvalidNetworkField);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    /// A 3-byte MPLS label / VNI field.
    fn label(&mut self) -> Result<u32, WireError> {
        let b = self.array::<3>()?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
    /// An IP address of the given byte length (4 or 16).
    fn ip(&mut self, len: usize) -> Result<IpAddr, WireError> {
        match len {
            4 => Ok(Ipv4Addr::from(self.array::<4>()?).into()),
            16 => Ok(Ipv6Addr::from(self.array::<16>()?).into()),
            _ => Err(WireError::InvalidNetworkField),
        }
    }
    /// Every byte of the body must have been consumed.
    fn finish(&self) -> Result<(), WireError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(WireError::InvalidNetworkField)
        }
    }
}

/// Decodes a concatenated run of EVPN NLRIs (the tail of an `MP_REACH_NLRI` /
/// whole of an `MP_UNREACH_NLRI` for AFI 25 / SAFI 70).
///
/// # Errors
/// `InvalidNetworkField` on any truncated or inconsistent length.
pub fn decode_nlris(mut data: &[u8]) -> Result<Vec<EvpnNlri>, WireError> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 2 {
            return Err(WireError::InvalidNetworkField);
        }
        let (route_type, len) = (data[0], usize::from(data[1]));
        if data.len() < 2 + len {
            return Err(WireError::InvalidNetworkField);
        }
        out.push(decode_one(route_type, &data[2..2 + len])?);
        data = &data[2 + len..];
    }
    Ok(out)
}

fn decode_one(route_type: u8, body: &[u8]) -> Result<EvpnNlri, WireError> {
    let mut r = Reader(body);
    let nlri = match route_type {
        ROUTE_ETHERNET_AD => EvpnNlri::EthernetAd {
            rd: r.array()?,
            esi: r.array()?,
            tag: r.u32()?,
            label: r.label()?,
        },
        ROUTE_MAC_IP => {
            let (rd, esi, tag) = (r.array()?, r.array()?, r.u32()?);
            if r.u8()? != 48 {
                return Err(WireError::InvalidNetworkField);
            }
            let mac = r.array()?;
            let ip = match r.u8()? {
                0 => None,
                32 => Some(r.ip(4)?),
                128 => Some(r.ip(16)?),
                _ => return Err(WireError::InvalidNetworkField),
            };
            // One label, or two when an IP-VRF label follows the MAC-VRF one.
            let count = match r.0.len() {
                3 => 1,
                6 => 2,
                _ => return Err(WireError::InvalidNetworkField),
            };
            let labels = (0..count).map(|_| r.label()).collect::<Result<_, _>>()?;
            EvpnNlri::MacIp {
                rd,
                esi,
                tag,
                mac,
                ip,
                labels,
            }
        }
        ROUTE_INCLUSIVE_MULTICAST => {
            let (rd, tag) = (r.array()?, r.u32()?);
            let bits = r.u8()?;
            EvpnNlri::InclusiveMulticast {
                rd,
                tag,
                origin: r.ip(usize::from(bits) / 8)?,
            }
        }
        ROUTE_ETHERNET_SEGMENT => {
            let (rd, esi) = (r.array()?, r.array()?);
            let bits = r.u8()?;
            EvpnNlri::EthernetSegment {
                rd,
                esi,
                origin: r.ip(usize::from(bits) / 8)?,
            }
        }
        ROUTE_IP_PREFIX => {
            let (rd, esi, tag, plen) = (r.array()?, r.array()?, r.u32()?, r.u8()?);
            // RFC 9136 §3.1: the body is 34 (IPv4) or 58 (IPv6) bytes, so the
            // address family is implied by the total length.
            let addr_len = match body.len() {
                34 => 4,
                58 => 16,
                _ => return Err(WireError::InvalidNetworkField),
            };
            let prefix =
                IpNet::new(r.ip(addr_len)?, plen).map_err(|_| WireError::InvalidNetworkField)?;
            EvpnNlri::IpPrefix {
                rd,
                esi,
                tag,
                prefix,
                gateway: r.ip(addr_len)?,
                label: r.label()?,
            }
        }
        _ => {
            return Ok(EvpnNlri::Unknown {
                route_type,
                body: body.to_vec(),
            })
        }
    };
    r.finish()?;
    Ok(nlri)
}

// ---- encode ---------------------------------------------------------------

fn put_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(a) => out.extend_from_slice(&a.octets()),
        IpAddr::V6(a) => out.extend_from_slice(&a.octets()),
    }
}

fn put_label(out: &mut Vec<u8>, label: u32) {
    out.extend_from_slice(&label.to_be_bytes()[1..]);
}

/// IP-length-in-bits byte followed by the address.
fn put_ip_with_len(out: &mut Vec<u8>, ip: IpAddr) {
    out.push(if ip.is_ipv4() { 32 } else { 128 });
    put_ip(out, ip);
}

/// Appends `nlri` in wire form.
///
/// # Panics
/// Never for anything `decode_nlris` produces; a hand-built `MacIp` with a
/// label count other than 1 or 2 is a caller bug, as is an `IpPrefix` whose
/// `prefix`/`gateway` families differ.
pub fn encode_nlri(nlri: &EvpnNlri, out: &mut Vec<u8>) {
    let mut body = Vec::new();
    match nlri {
        EvpnNlri::EthernetAd {
            rd,
            esi,
            tag,
            label,
        } => {
            body.extend_from_slice(rd);
            body.extend_from_slice(esi);
            body.extend_from_slice(&tag.to_be_bytes());
            put_label(&mut body, *label);
        }
        EvpnNlri::MacIp {
            rd,
            esi,
            tag,
            mac,
            ip,
            labels,
        } => {
            assert!((1..=2).contains(&labels.len()), "MacIp needs 1 or 2 labels");
            body.extend_from_slice(rd);
            body.extend_from_slice(esi);
            body.extend_from_slice(&tag.to_be_bytes());
            body.push(48);
            body.extend_from_slice(mac);
            match ip {
                Some(ip) => put_ip_with_len(&mut body, *ip),
                None => body.push(0),
            }
            for l in labels {
                put_label(&mut body, *l);
            }
        }
        EvpnNlri::InclusiveMulticast { rd, tag, origin } => {
            body.extend_from_slice(rd);
            body.extend_from_slice(&tag.to_be_bytes());
            put_ip_with_len(&mut body, *origin);
        }
        EvpnNlri::EthernetSegment { rd, esi, origin } => {
            body.extend_from_slice(rd);
            body.extend_from_slice(esi);
            put_ip_with_len(&mut body, *origin);
        }
        EvpnNlri::IpPrefix {
            rd,
            esi,
            tag,
            prefix,
            gateway,
            label,
        } => {
            assert_eq!(
                prefix.addr().is_ipv4(),
                gateway.is_ipv4(),
                "IpPrefix families differ"
            );
            body.extend_from_slice(rd);
            body.extend_from_slice(esi);
            body.extend_from_slice(&tag.to_be_bytes());
            body.push(prefix.prefix_len());
            put_ip(&mut body, prefix.addr());
            put_ip(&mut body, *gateway);
            put_label(&mut body, *label);
        }
        EvpnNlri::Unknown { body: raw, .. } => body.extend_from_slice(raw),
    }
    out.push(nlri.route_type());
    out.push(u8::try_from(body.len()).expect("EVPN NLRI body fits in one length byte"));
    out.extend_from_slice(&body);
}

/// Renders an RFC 4360 / RFC 5668 / RFC 7432 extended community for `show`:
/// Route Target / Route Origin as `RT:65000:10000`, VXLAN-style Encapsulation
/// as `encap:8`, ES-Import as `ES-Import:…`, an ESI Label as
/// `esi-label:single-active|all-active`, the §7.8 Default Gateway flag as
/// `default-gw`, an RFC 8584 DF Election as `df-election:modulo|hrw|alg<N>`
/// (`,ac-df` when that capability is set), an RFC 9135 Router's MAC as
/// `rmac:aa:bb:cc:dd:ee:ff`; anything else as raw hex.
#[must_use]
pub fn format_ext_community(c: u64) -> String {
    let b = c.to_be_bytes();
    let kind = match b[1] {
        0x02 => Some("RT"),
        0x03 => Some("RO"),
        _ => None,
    };
    match (b[0], kind) {
        (0x00, Some(k)) => format!(
            "{k}:{}:{}",
            u16::from_be_bytes([b[2], b[3]]),
            u32::from_be_bytes([b[4], b[5], b[6], b[7]])
        ),
        (0x01, Some(k)) => format!(
            "{k}:{}:{}",
            Ipv4Addr::new(b[2], b[3], b[4], b[5]),
            u16::from_be_bytes([b[6], b[7]])
        ),
        (0x02, Some(k)) => format!(
            "{k}:{}:{}",
            u32::from_be_bytes([b[2], b[3], b[4], b[5]]),
            u16::from_be_bytes([b[6], b[7]])
        ),
        (0x03, _) if b[1] == 0x0c => format!("encap:{}", u16::from_be_bytes([b[6], b[7]])),
        // RFC 7432 §7.8: an all-zero-value flag, no fields to render.
        (0x03, _) if b[1] == 0x0d => "default-gw".to_string(),
        // RFC 7432 §7.6: the ESI's value bytes 1..7.
        (0x06, _) if b[1] == 0x02 => format!("ES-Import:{}", hex(&b[2..])),
        // RFC 7432 §7.5: the flags octet's bit 0 is Single-Active.
        (0x06, _) if b[1] == 0x01 => format!(
            "esi-label:{}",
            if b[2] & 1 == 1 {
                "single-active"
            } else {
                "all-active"
            }
        ),
        // RFC 9135 §8.1 Router's MAC.
        (0x06, _) if b[1] == 0x03 => format!(
            "rmac:{}",
            nos_proto::evpn_id::format_mac(&[b[2], b[3], b[4], b[5], b[6], b[7]])
        ),
        (0x06, _) if b[1] == 0x06 => {
            let alg = match b[2] & 0x1f {
                0 => "modulo".to_string(),
                1 => "hrw".to_string(),
                n => format!("alg{n}"),
            };
            let ac_df = if b[3] & 0x40 != 0 { ",ac-df" } else { "" };
            format!("df-election:{alg}{ac_df}")
        }
        _ => format!("0x{c:016x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RD: Rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1]; // 65000:1
    const ESI: Esi = [0; 10];

    fn samples() -> Vec<EvpnNlri> {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        vec![
            EvpnNlri::EthernetAd {
                rd: RD,
                esi: [1; 10],
                tag: 0xffff_ffff,
                label: 10_000,
            },
            EvpnNlri::MacIp {
                rd: RD,
                esi: ESI,
                tag: 0,
                mac: [0xaa, 0xbb, 0xcc, 0, 0, 1],
                ip: None,
                labels: vec![10_000],
            },
            EvpnNlri::MacIp {
                rd: RD,
                esi: ESI,
                tag: 0,
                mac: [0xaa, 0xbb, 0xcc, 0, 0, 1],
                ip: Some(v4),
                labels: vec![10_000],
            },
            EvpnNlri::MacIp {
                rd: RD,
                esi: ESI,
                tag: 0,
                mac: [1; 6],
                ip: Some(v6),
                labels: vec![10_000, 20_000],
            },
            EvpnNlri::InclusiveMulticast {
                rd: RD,
                tag: 0,
                origin: v4,
            },
            EvpnNlri::InclusiveMulticast {
                rd: RD,
                tag: 0,
                origin: v6,
            },
            EvpnNlri::EthernetSegment {
                rd: RD,
                esi: [7; 10],
                origin: v4,
            },
            EvpnNlri::IpPrefix {
                rd: RD,
                esi: ESI,
                tag: 0,
                prefix: "10.1.0.0/16".parse().unwrap(),
                gateway: v4,
                label: 5000,
            },
            EvpnNlri::IpPrefix {
                rd: RD,
                esi: ESI,
                tag: 0,
                prefix: "2001:db8:1::/48".parse().unwrap(),
                gateway: v6,
                label: 5000,
            },
            EvpnNlri::Unknown {
                route_type: 9,
                body: vec![1, 2, 3],
            },
        ]
    }

    #[test]
    fn every_route_type_roundtrips() {
        for n in samples() {
            let mut wire = Vec::new();
            encode_nlri(&n, &mut wire);
            assert_eq!(decode_nlris(&wire).unwrap(), vec![n]);
        }
    }

    #[test]
    fn concatenated_nlris_decode_in_order() {
        let all = samples();
        let mut wire = Vec::new();
        for n in &all {
            encode_nlri(n, &mut wire);
        }
        assert_eq!(decode_nlris(&wire).unwrap(), all);
    }

    #[test]
    fn type2_wire_layout_matches_rfc7432() {
        // MAC-only Type 2: 8 RD + 10 ESI + 4 tag + 1 + 6 MAC + 1 iplen + 3 label = 33.
        let mut wire = Vec::new();
        encode_nlri(&samples()[1], &mut wire);
        assert_eq!(&wire[..2], &[2, 33]);
        assert_eq!(wire.len(), 2 + 33);
        assert_eq!(&wire[2..10], &RD);
        assert_eq!(wire[24], 48); // MAC length in bits
        assert_eq!(wire[31], 0); // no IP
        assert_eq!(&wire[32..35], &[0, 0x27, 0x10]); // label 10000
    }

    /// RFC 9135 §5.1 symmetric IRB: Label1 the L2 VNI, Label2 the L3 VNI.
    #[test]
    fn type2_with_two_labels_matches_rfc9135() {
        let nlri = EvpnNlri::MacIp {
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            esi: [0; 10],
            tag: 0,
            mac: [0x02, 0x42, 0x0a, 0x48, 0x00, 0x14],
            ip: Some(Ipv4Addr::new(10, 72, 0, 20).into()),
            labels: vec![10_300, 5000],
        };
        let mut wire = Vec::new();
        encode_nlri(&nlri, &mut wire);
        #[rustfmt::skip]
        let expected = [
            0x02, 0x28,
            0x00, 0x00, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x01,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
            0x30, 0x02, 0x42, 0x0a, 0x48, 0x00, 0x14,
            0x20, 0x0a, 0x48, 0x00, 0x14,
            0x00, 0x28, 0x3c,
            0x00, 0x13, 0x88,
        ];
        assert_eq!(wire, expected);
        assert_eq!(decode_nlris(&wire).unwrap(), vec![nlri]);
    }

    #[test]
    fn route_key_drops_attributes_only() {
        let s = samples();
        for n in &s {
            let k = n.route_key();
            assert_eq!(k.route_type(), n.route_type());
            assert_eq!(k.rd(), n.rd());
            assert_eq!(k.route_key(), k);
        }
        let EvpnNlri::MacIp { labels, esi, .. } = s[1].route_key() else {
            panic!()
        };
        assert_eq!((labels, esi), (vec![], [0; 10]));
    }

    #[test]
    fn malformed_is_rejected() {
        let mut good = Vec::new();
        encode_nlri(&samples()[4], &mut good);
        // Truncated body, truncated header, length overrunning the buffer.
        assert!(decode_nlris(&good[..good.len() - 1]).is_err());
        assert!(decode_nlris(&[3]).is_err());
        // Trailing byte inside a body whose declared length includes it.
        let mut extra = good.clone();
        extra[1] += 1;
        extra.push(0);
        assert!(decode_nlris(&extra).is_err());
        // Type 2 with a MAC length other than 48, and with 2 stray label bytes.
        let mut bad_mac = Vec::new();
        encode_nlri(&samples()[1], &mut bad_mac);
        bad_mac[24] = 32;
        assert!(decode_nlris(&bad_mac).is_err());
        let mut bad_labels = Vec::new();
        encode_nlri(&samples()[1], &mut bad_labels);
        bad_labels[1] += 2;
        bad_labels.extend_from_slice(&[0, 0]);
        assert!(decode_nlris(&bad_labels).is_err());
        // Type 3 with an impossible IP length.
        let mut bad_ip = good.clone();
        bad_ip[2 + 12] = 24;
        assert!(decode_nlris(&bad_ip).is_err());
    }

    #[test]
    fn display_and_rd_formatting() {
        assert_eq!(format_rd(&RD), "65000:1");
        assert_eq!(format_rd(&[0, 1, 192, 0, 2, 1, 0, 7]), "192.0.2.1:7");
        assert_eq!(format_rd(&[0, 2, 0, 1, 0, 0, 0, 9]), "65536:9");
        assert_eq!(
            format_ext_community(0x0002_fde8_0000_2710),
            "RT:65000:10000"
        );
        assert_eq!(
            format_ext_community(0x0102_c000_0201_0007),
            "RT:192.0.2.1:7"
        );
        assert_eq!(format_ext_community(0x0203_0001_0000_0009), "RO:65536:9");
        assert_eq!(format_ext_community(0x030c_0000_0000_0008), "encap:8");
        assert_eq!(format_ext_community(0x030d_0000_0000_0000), "default-gw");
        assert_eq!(
            format_ext_community(0x0603_0211_2233_4455),
            "rmac:02:11:22:33:44:55"
        );
        assert_eq!(
            format_ext_community(0x0600_0000_0000_0001),
            "0x0600000000000001"
        );
        assert_eq!(
            format_ext_community(0x0601_0100_0000_0000),
            "esi-label:single-active"
        );
        assert_eq!(
            format_ext_community(0x0601_0000_0000_0000),
            "esi-label:all-active"
        );
        assert_eq!(
            format_ext_community(0x0606_0140_0000_0000),
            "df-election:hrw,ac-df"
        );
        assert_eq!(
            format_ext_community(0x0606_0000_0000_0000),
            "df-election:modulo"
        );
        assert_eq!(
            format_ext_community(0x0606_0200_0000_0000),
            "df-election:alg2"
        );
        assert_eq!(samples()[4].to_string(), "[3]:[65000:1]:[0]:[192.0.2.1]");
    }
}
