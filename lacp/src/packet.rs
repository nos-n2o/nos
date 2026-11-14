//! Hand-rolled LACPDU encode/decode — IEEE 802.1AX-2014 §6.4.2.3 (Figure
//! 6-2). Pure, no I/O, no `nos-proto` dependency, mirroring `ospf::packet`'s
//! shape. A version-1 LACPDU is exactly [`LACPDU_LEN`] bytes: fixed-size
//! Actor/Partner/Collector Information TLVs plus a Terminator TLV and
//! trailing reserved padding. A version-2 LACPDU (802.1AX-2014) carries more
//! TLVs after those, so `decode` takes anything at least that long and reads
//! only the fixed v1 offsets — nothing a parsing crate would buy.

use crate::conversation::{PortAlgorithm, MASK_BYTES};

const SUBTYPE_LACP: u8 = 0x01;
const VERSION_NUMBER: u8 = 0x01;

const TLV_TYPE_TERMINATOR: u8 = 0x00;
const TLV_TYPE_ACTOR: u8 = 0x01;
const TLV_TYPE_PARTNER: u8 = 0x02;
const TLV_TYPE_COLLECTOR: u8 = 0x03;

const ACTOR_PARTNER_INFO_LEN: u8 = 20;
const COLLECTOR_INFO_LEN: u8 = 16;

/// The LACPDU body's minimum on-wire length (Subtype through the trailing
/// Reserved field, 802.1AX Figure 6-2): what we send, and the least `decode`
/// accepts (a version-2 PDU is longer, its extra TLVs are ignored).
pub const LACPDU_LEN: usize = 110;

const SUBTYPE_MARKER: u8 = 0x02;
const TLV_MARKER_INFO: u8 = 0x01;
const TLV_MARKER_RESPONSE: u8 = 0x02;
const MARKER_INFO_LEN: u8 = 16;

/// A Marker PDU's requester fields (802.1AX §6.5.3.3) — exactly what a
/// Marker Response must echo back. We only ever respond, never generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marker {
    pub requester_port: u16,
    pub requester_system: [u8; 6],
    pub transaction_id: u32,
}

/// Decodes a Marker *request* (TLV 0x01); a Marker Response, a LACPDU or
/// anything short gives `None`. Like `decode`, reads fixed offsets only: the
/// length, version and terminator bytes are not validated (Linux sends 0x16
/// where the standard says 16).
pub fn decode_marker(data: &[u8]) -> Option<Marker> {
    if data.len() < 16 || data[0] != SUBTYPE_MARKER || data[2] != TLV_MARKER_INFO {
        return None;
    }
    Some(Marker {
        requester_port: u16::from_be_bytes([data[4], data[5]]),
        requester_system: data[6..12].try_into().unwrap(),
        transaction_id: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
    })
}

/// A clean Marker Response PDU (same 110-byte body as a LACPDU).
pub fn encode_marker_response(m: &Marker) -> Vec<u8> {
    let mut buf = Vec::with_capacity(LACPDU_LEN);
    buf.extend_from_slice(&[
        SUBTYPE_MARKER,
        VERSION_NUMBER,
        TLV_MARKER_RESPONSE,
        MARKER_INFO_LEN,
    ]);
    buf.extend_from_slice(&m.requester_port.to_be_bytes());
    buf.extend_from_slice(&m.requester_system);
    buf.extend_from_slice(&m.transaction_id.to_be_bytes());
    buf.resize(LACPDU_LEN, 0); // pad, terminator TLV and reserved are all zero
    buf
}

/// 802.1AX Table 6-4 Actor/Partner State bit positions (LSB-first).
pub mod state_bit {
    pub const ACTIVITY: u8 = 1 << 0;
    pub const TIMEOUT: u8 = 1 << 1;
    pub const AGGREGATION: u8 = 1 << 2;
    pub const SYNCHRONIZATION: u8 = 1 << 3;
    pub const COLLECTING: u8 = 1 << 4;
    pub const DISTRIBUTING: u8 = 1 << 5;
    pub const DEFAULTED: u8 = 1 << 6;
    pub const EXPIRED: u8 = 1 << 7;
}

/// One side's (Actor's or Partner's) Information TLV contents — identical
/// shape for both, per 802.1AX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortInfo {
    pub system_priority: u16,
    pub system: [u8; 6],
    pub key: u16,
    pub port_priority: u16,
    pub port: u16,
    pub state: u8,
}

impl PortInfo {
    /// The `Partner_Admin` defaults a Defaulted / never-heard port records
    /// (802.1AX `recordDefault`), the values Linux `bond_3ad.c`
    /// `ad_initialize_port` uses: `system_priority = 0xffff, key = 1,
    /// port_number = 1, port_priority = 0xff, port_state = 0`, system MAC zero.
    pub const ADMINISTRATIVE_DEFAULT: Self = Self {
        system_priority: 0xffff,
        system: [0; 6],
        key: 1,
        port_priority: 0xff,
        port: 1,
        state: 0,
    };

    pub fn has_state(&self, bit: u8) -> bool {
        self.state & bit != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lacpdu {
    pub actor: PortInfo,
    pub partner: PortInfo,
    /// 802.1AX's `Collector_Max_Delay` — advertised but never acted on by
    /// this implementation (no frame-collection/distribution delay logic;
    /// the kernel bond handles actual frame forwarding once a port is
    /// pushed into the active-member set). Round-tripped so a real partner
    /// switch sees a plausible, non-zero value.
    pub collector_max_delay: u16,
    /// Version-2 TLVs (`Some` = send/received as version 2). `None` encodes
    /// the unchanged 110-byte version-1 PDU. UNVERIFIED layout, see
    /// [`V2Tlvs`]; nothing sends v2 yet (#894 is parked).
    pub v2: Option<V2Tlvs>,
}

// ponytail: UNVERIFIED (#890): every number below is recollection of
// 802.1AX-2014, not read from the standard nor seen on the wire. The Length
// byte includes type+length, like v1.
const TLV_PORT_ALGORITHM: u8 = 4; // OUI(3) + id(1), length 6
const TLV_CONV_DIGEST: u8 = 5; // Link_Number(2) + MD5(16), length 20
const TLV_MASK_FIRST: u8 = 6; // masks 1..4 = types 6..9, 128 B each, length 130 (assumed)
const TLV_SERVICE_DIGEST: u8 = 10; // MD5(16), length 18 (assumed)
const V2_OFFSET: usize = 58; // right after the Collector TLV (assumed)

/// Port Conversation ID Digest TLV: `Link_Number` then MD5 (UNVERIFIED order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConvDigest {
    pub link_number: u16,
    pub digest: [u8; 16],
}

/// The version-2 TLVs, each independently optional (a missing mandatory
/// part means "no agreement" for #894).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct V2Tlvs {
    pub algorithm: Option<PortAlgorithm>,
    pub conv_digest: Option<ConvDigest>,
    pub masks: [Option<[u8; MASK_BYTES]>; 4],
    pub service_digest: Option<[u8; 16]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("LACPDU too short: expected at least {LACPDU_LEN}, got {0}")]
    WrongLength(usize),
    #[error("not an LACP slow-protocol frame (subtype {0:#04x})")]
    WrongSubtype(u8),
    #[error("unsupported LACPDU version {0}")]
    UnsupportedVersion(u8),
}

fn encode_port_info(buf: &mut Vec<u8>, tlv_type: u8, info: &PortInfo) {
    buf.push(tlv_type);
    buf.push(ACTOR_PARTNER_INFO_LEN);
    buf.extend_from_slice(&info.system_priority.to_be_bytes());
    buf.extend_from_slice(&info.system);
    buf.extend_from_slice(&info.key.to_be_bytes());
    buf.extend_from_slice(&info.port_priority.to_be_bytes());
    buf.extend_from_slice(&info.port.to_be_bytes());
    buf.push(info.state);
    buf.extend_from_slice(&[0u8; 3]); // reserved
}

pub fn encode(pdu: &Lacpdu) -> Vec<u8> {
    let mut buf = Vec::with_capacity(LACPDU_LEN);
    buf.push(SUBTYPE_LACP);
    buf.push(if pdu.v2.is_some() { 2 } else { VERSION_NUMBER });
    encode_port_info(&mut buf, TLV_TYPE_ACTOR, &pdu.actor);
    encode_port_info(&mut buf, TLV_TYPE_PARTNER, &pdu.partner);
    buf.push(TLV_TYPE_COLLECTOR);
    buf.push(COLLECTOR_INFO_LEN);
    buf.extend_from_slice(&pdu.collector_max_delay.to_be_bytes());
    buf.extend_from_slice(&[0u8; 12]); // reserved
    if let Some(v2) = &pdu.v2 {
        encode_v2(&mut buf, v2);
    }
    buf.push(TLV_TYPE_TERMINATOR);
    buf.push(0);
    buf.resize(buf.len().max(LACPDU_LEN), 0); // reserved
    buf
}

#[allow(clippy::cast_possible_truncation, reason = "i < 4")]
fn encode_v2(buf: &mut Vec<u8>, v2: &V2Tlvs) {
    if let Some(a) = v2.algorithm {
        buf.extend_from_slice(&[TLV_PORT_ALGORITHM, 6]);
        buf.extend_from_slice(&a.to_wire());
    }
    if let Some(d) = &v2.conv_digest {
        buf.extend_from_slice(&[TLV_CONV_DIGEST, 20]);
        buf.extend_from_slice(&d.link_number.to_be_bytes());
        buf.extend_from_slice(&d.digest);
    }
    for (i, m) in v2.masks.iter().enumerate() {
        if let Some(m) = m {
            buf.extend_from_slice(&[TLV_MASK_FIRST + i as u8, 130]);
            buf.extend_from_slice(m);
        }
    }
    if let Some(d) = &v2.service_digest {
        buf.extend_from_slice(&[TLV_SERVICE_DIGEST, 18]);
        buf.extend_from_slice(d);
    }
}

/// Walks the TLVs after the Collector block. Unknown types, and known types
/// with an unexpected length, are skipped by their length byte; a length that
/// overruns the frame (or is < 2) makes the whole block absent. Never panics.
fn decode_v2(data: &[u8]) -> Option<V2Tlvs> {
    let mut v2 = V2Tlvs::default();
    let mut off = V2_OFFSET;
    while off + 2 <= data.len() {
        let (ty, len) = (data[off], data[off + 1] as usize);
        if ty == TLV_TYPE_TERMINATOR {
            break;
        }
        if len < 2 || off + len > data.len() {
            return None;
        }
        let body = &data[off + 2..off + len];
        match (ty, body.len()) {
            (TLV_PORT_ALGORITHM, 4) => {
                v2.algorithm = Some(PortAlgorithm::from_wire(body.try_into().unwrap()));
            }
            (TLV_CONV_DIGEST, 18) => {
                v2.conv_digest = Some(ConvDigest {
                    link_number: u16::from_be_bytes([body[0], body[1]]),
                    digest: body[2..].try_into().unwrap(),
                });
            }
            (TLV_MASK_FIRST..=9, MASK_BYTES) => {
                v2.masks[(ty - TLV_MASK_FIRST) as usize] = Some(body.try_into().unwrap());
            }
            (TLV_SERVICE_DIGEST, 16) => v2.service_digest = Some(body.try_into().unwrap()),
            _ => {}
        }
        off += len;
    }
    Some(v2)
}

fn decode_port_info(buf: &[u8]) -> PortInfo {
    PortInfo {
        system_priority: u16::from_be_bytes([buf[0], buf[1]]),
        system: buf[2..8].try_into().unwrap(),
        key: u16::from_be_bytes([buf[8], buf[9]]),
        port_priority: u16::from_be_bytes([buf[10], buf[11]]),
        port: u16::from_be_bytes([buf[12], buf[13]]),
        state: buf[14],
        // buf[15..18] is reserved, ignored.
    }
}

/// Decodes a LACPDU body (the raw slow-protocol payload, Ethernet header
/// already stripped — see `socket::LacpSocket::recv`). Deliberately
/// tolerant of TLV type/length fields that don't match a real partner's own
/// implementation exactly (never rejects on those), since only the fixed
/// byte offsets are actually read — every real-world LACP implementation
/// sends this same fixed layout, and rejecting on cosmetic mismatches would
/// only make interop worse, not safer.
pub fn decode(data: &[u8]) -> Result<Lacpdu, PacketError> {
    if data.len() < LACPDU_LEN {
        return Err(PacketError::WrongLength(data.len()));
    }
    if data[0] != SUBTYPE_LACP {
        return Err(PacketError::WrongSubtype(data[0]));
    }
    // Version 2 only appends TLVs after the v1 layout, so 1 and 2 decode
    // identically; anything else is dropped (and counted by the caller).
    if !matches!(data[1], 1 | 2) {
        return Err(PacketError::UnsupportedVersion(data[1]));
    }
    // Layout (802.1AX Figure 6-2): Subtype(1) + Version(1) = 2, then each
    // TLV is `type(1) + length(1) + content`. Actor TLV content starts at
    // offset 4 (18 content bytes, its own trailing 3-byte reserved field
    // included but unread below); Partner TLV's header is at 22-23, its
    // content at 24; Collector TLV's header is at 42-43, its content
    // (`Collector_Max_Delay`) at 44.
    let actor = decode_port_info(&data[4..22]);
    let partner = decode_port_info(&data[24..42]);
    let collector_max_delay = u16::from_be_bytes([data[44], data[45]]);
    Ok(Lacpdu {
        actor,
        partner,
        collector_max_delay,
        v2: if data[1] == 2 { decode_v2(data) } else { None },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_info() -> PortInfo {
        PortInfo {
            system_priority: 32768,
            system: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            key: 7,
            port_priority: 32768,
            port: 1,
            state: state_bit::ACTIVITY | state_bit::AGGREGATION | state_bit::SYNCHRONIZATION,
        }
    }

    #[test]
    fn round_trips() {
        let pdu = Lacpdu {
            actor: sample_info(),
            partner: sample_info(),
            collector_max_delay: 0,
            v2: None,
        };
        let encoded = encode(&pdu);
        assert_eq!(encoded.len(), LACPDU_LEN);
        assert_eq!(decode(&encoded).unwrap(), pdu);
    }

    fn sample_pdu() -> Lacpdu {
        Lacpdu {
            actor: sample_info(),
            partner: sample_info(),
            collector_max_delay: 0,
            v2: None,
        }
    }

    #[test]
    fn short_is_rejected() {
        assert_eq!(decode(&[0u8; 50]), Err(PacketError::WrongLength(50)));
        let v1 = encode(&sample_pdu());
        assert_eq!(decode(&v1[..109]), Err(PacketError::WrongLength(109)));
    }

    fn full_v2() -> V2Tlvs {
        let mut mask = [0u8; MASK_BYTES];
        mask[0] = 0xa5;
        V2Tlvs {
            algorithm: Some(PortAlgorithm::CVid),
            conv_digest: Some(ConvDigest {
                link_number: 3,
                digest: [7; 16],
            }),
            masks: [
                Some(mask),
                Some([1; MASK_BYTES]),
                None,
                Some([2; MASK_BYTES]),
            ],
            service_digest: Some([9; 16]),
        }
    }

    fn v2_pdu() -> Lacpdu {
        Lacpdu {
            v2: Some(full_v2()),
            ..sample_pdu()
        }
    }

    #[test]
    fn v1_is_110_bytes_version_1_and_v2_none() {
        let b = encode(&sample_pdu());
        assert_eq!((b.len(), b[1]), (LACPDU_LEN, 1));
        assert_eq!(decode(&b).unwrap().v2, None);
        // version-2 PDU without TLVs: Some(empty), not an error
        let mut v2 = b.clone();
        v2[1] = 2;
        assert_eq!(decode(&v2).unwrap().v2, Some(V2Tlvs::default()));
    }

    #[test]
    fn srlinux_v1_goldens_decode_and_reencode() {
        for f in ["srlinux-v1-default.hex", "srlinux-v1-partner-insync.hex"] {
            let path = format!("{}/tests/golden/{f}", env!("CARGO_MANIFEST_DIR"));
            let hex = std::fs::read_to_string(path).unwrap();
            let hex = hex.trim();
            let frame: Vec<u8> = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            let pdu = decode(&frame[14..]).unwrap();
            assert_eq!(pdu.v2, None);
            assert_eq!(&encode(&pdu)[..], &frame[14..]);
        }
    }

    #[test]
    fn v2_round_trips() {
        let pdu = v2_pdu();
        assert_eq!(decode(&encode(&pdu)).unwrap(), pdu);
    }

    /// Documents the ASSUMED, UNVERIFIED v2 layout (#890 has no source). If a
    /// real capture contradicts this, this test is what must change.
    #[test]
    fn assumed_v2_layout() {
        let b = encode(&Lacpdu {
            v2: Some(V2Tlvs {
                algorithm: Some(PortAlgorithm::SVid),
                conv_digest: Some(ConvDigest {
                    link_number: 0x0102,
                    digest: [0xee; 16],
                }),
                ..V2Tlvs::default()
            }),
            ..sample_pdu()
        });
        assert_eq!(b[1], 2);
        assert_eq!(&b[58..64], &[4, 6, 0x00, 0x80, 0xc2, 2]);
        assert_eq!(&b[64..68], &[5, 20, 0x01, 0x02]);
        assert_eq!(&b[68..84], &[0xee; 16]);
        assert_eq!(&b[84..86], &[0, 0]); // terminator
        assert_eq!(b.len(), LACPDU_LEN);
    }

    #[test]
    fn unknown_and_other_length_tlvs_are_skipped() {
        let mut b = encode(&v2_pdu());
        // splice an unknown TLV (type 77, len 5) right after the Collector
        b.splice(58..58, [77, 5, 1, 2, 3]);
        assert_eq!(decode(&b).unwrap(), v2_pdu());
        // a known type with a wrong length is ignored, the rest survives
        let mut c = encode(&sample_pdu());
        c[1] = 2;
        c.splice(58..58, [TLV_PORT_ALGORITHM, 5, 0, 0x80, 0xc2]);
        assert_eq!(decode(&c).unwrap().v2, Some(V2Tlvs::default()));
    }

    #[test]
    fn overrunning_or_degenerate_length_drops_the_v2_block_only() {
        let base = sample_pdu();
        for tlv in [[4u8, 200], [4, 1], [4, 0]] {
            let mut b = encode(&v2_pdu());
            b.truncate(58);
            b.extend_from_slice(&tlv);
            b.resize(LACPDU_LEN, 0);
            let pdu = decode(&b).unwrap();
            assert_eq!(pdu.v2, None);
            assert_eq!(pdu.actor, base.actor);
            assert_eq!(pdu.partner, base.partner);
        }
    }

    #[test]
    fn truncation_and_byte_flips_never_panic() {
        let full = encode(&v2_pdu());
        for n in 0..=full.len() {
            let _ = decode(&full[..n]);
        }
        let mut seed = 0x1234_5678_u32;
        for _ in 0..5000 {
            let mut b = full.clone();
            for _ in 0..4 {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let i = 58 + (seed >> 8) as usize % (b.len() - 58);
                b[i] = (seed >> 24) as u8;
            }
            let pdu = decode(&b).unwrap();
            assert_eq!(pdu.actor, sample_info()); // v1 part intact
        }
    }

    #[test]
    fn other_versions_are_rejected() {
        for v in [0u8, 3, 255] {
            let mut b = encode(&sample_pdu());
            b[1] = v;
            assert_eq!(decode(&b), Err(PacketError::UnsupportedVersion(v)));
        }
    }

    #[test]
    fn wrong_subtype_is_rejected() {
        let mut buf = encode(&Lacpdu {
            actor: sample_info(),
            partner: sample_info(),
            collector_max_delay: 0,
            v2: None,
        });
        buf[0] = 0x02; // Marker protocol subtype, not LACP
        assert_eq!(decode(&buf), Err(PacketError::WrongSubtype(0x02)));
    }

    fn marker_pdu(tlv: u8, len_byte: u8) -> Vec<u8> {
        let mut b = vec![0u8; LACPDU_LEN];
        b[..4].copy_from_slice(&[0x02, 0x01, tlv, len_byte]);
        b[4..6].copy_from_slice(&7u16.to_be_bytes());
        b[6..12].copy_from_slice(&[2, 0, 0, 0, 0x0b, 7]);
        b[12..16].copy_from_slice(&0x4e4f_5359_u32.to_be_bytes());
        b
    }

    #[test]
    fn marker_response_echoes_requester() {
        let m = decode_marker(&marker_pdu(1, 0x16)).expect("linux-shaped marker");
        assert_eq!(m.requester_port, 7);
        let r = encode_marker_response(&m);
        assert_eq!(r.len(), LACPDU_LEN);
        assert_eq!(&r[..4], &[0x02, 0x01, 0x02, 0x10]);
        assert_eq!(&r[4..16], &marker_pdu(1, 0)[4..16]);
        assert!(r[16..].iter().all(|b| *b == 0));
    }

    #[test]
    fn decode_marker_ignores_responses_lacpdus_and_short() {
        assert_eq!(decode_marker(&marker_pdu(2, 0x10)), None);
        assert_eq!(decode_marker(&marker_pdu(1, 0x10)[..15]), None);
        let lacpdu = encode(&Lacpdu {
            actor: sample_info(),
            partner: sample_info(),
            collector_max_delay: 0,
            v2: None,
        });
        assert_eq!(decode_marker(&lacpdu), None);
    }

    #[test]
    fn state_bits_round_trip() {
        let info = sample_info();
        assert!(info.has_state(state_bit::ACTIVITY));
        assert!(!info.has_state(state_bit::COLLECTING));
    }
}
