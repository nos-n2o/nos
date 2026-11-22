//! RFC 2328 Link State Advertisements: the header shared by every LSA type
//! (Appendix A.4.1) plus the two bodies this NOS implements — Router-LSA
//! (Appendix A.4.2) and Network-LSA (Appendix A.4.3). Pure encode/decode, no
//! I/O, same style as `packet.rs`.
//!
//! Router-LSA link **metric** and the three link types (point-to-point,
//! transit-network, stub-network) are real inputs to `crate::spf`'s RFC
//! 2328 §16.1/§16.2 Dijkstra — self-originated LSAs (`crate::link`) send a
//! link's configured `OspfProfile.cost` and always advertise a stub-network
//! link for a point-to-point interface's own subnet, real transit-network
//! masks included.
//!
//! AS-external-LSA (type 5, Appendix A.4.5) is implemented for ASBR-only
//! redistribution (see `docs/protocols/ospf-internals.md`'s "ASBR and AS-external-LSA
//! origination"), and Summary-LSA (types 3/4, Appendix A.4.4) is implemented
//! for a real, 2-area-scoped ABR mechanism (see `docs/protocols/ospf-internals.md`'s "ABR and
//! Summary-LSA origination"), stub areas and area ranges (#35), and RFC 3101
//! NSSA-external (type 7, the Type-5 body) for NSSA areas — virtual links
//! remain out of scope.
//!
//! RFC 5250 opaque LSAs (types 9/10/11) are stored and flooded as raw bytes
//! (`LsaBody::Opaque`); only the RFC 3623 Grace-LSA is parsed.

use std::cmp::Ordering;
use std::net::Ipv4Addr;

use crate::packet::{read_ipv4, PacketError};

pub const LSA_TYPE_ROUTER: u8 = 1;
pub const LSA_TYPE_NETWORK: u8 = 2;
pub const LSA_TYPE_NETWORK_SUMMARY: u8 = 3;
pub const LSA_TYPE_ASBR_SUMMARY: u8 = 4;
pub const LSA_TYPE_AS_EXTERNAL: u8 = 5;
/// RFC 3101 NSSA-external-LSA: a Type-5 body, area-scoped, only ever held in
/// an NSSA.
pub const LSA_TYPE_NSSA_EXTERNAL: u8 = 7;
/// RFC 3101 §2.4: the P-bit in an LSA header's options — an NSSA ABR may
/// translate this Type-7 into a Type-5. Same bit as the Hello N-bit
/// (`packet::OPTION_NP`).
pub const OPTION_P: u8 = 0x08;
/// RFC 5250 opaque LSAs, by flooding scope: link-local (9), area (10), AS
/// (11). Held and flooded as raw bytes (`LsaBody::Opaque`), except the RFC
/// 3623 Grace-LSA (type 9, opaque type 3), decoded as `LsaBody::Grace`.
pub const LSA_TYPE_OPAQUE_LINK: u8 = 9;
pub const LSA_TYPE_OPAQUE_AREA: u8 = 10;
/// ponytail: held in the area store it arrived in, like a received Type-5 —
/// an ABR doesn't flood it on into its other areas. Add that with real
/// Type-5 cross-area flooding. Kept out of stub areas and NSSAs
/// (`is_as_scope`).
pub const LSA_TYPE_OPAQUE_AS: u8 = 11;
/// RFC 3623 Appendix A: the Grace-LSA's opaque type — the top octet of its
/// Link State ID, so the Link State ID is always `3.0.0.0` (opaque ID 0).
pub const OPAQUE_TYPE_GRACE: u8 = 3;
pub const GRACE_LINK_STATE_ID: Ipv4Addr = Ipv4Addr::new(OPAQUE_TYPE_GRACE, 0, 0, 0);
/// RFC 3623 Appendix A's Grace-LSA TLVs.
const TLV_GRACE_PERIOD: u16 = 1;
const TLV_RESTART_REASON: u16 = 2;
const TLV_INTERFACE_ADDRESS: u16 = 3;
/// RFC 3623 Appendix A: restart reason 1, "software restart".
pub const RESTART_REASON_SOFTWARE: u8 = 1;

/// RFC 7770 §2: the Router Information LSA's opaque type, so its Link State
/// ID (opaque ID 0) is `4.0.0.0`. nos originates it as type 10, per area.
pub const OPAQUE_TYPE_ROUTER_INFO: u8 = 4;
pub const ROUTER_INFO_LINK_STATE_ID: Ipv4Addr = Ipv4Addr::new(OPAQUE_TYPE_ROUTER_INFO, 0, 0, 0);
/// RFC 7770 §2.3: the Router Informational Capabilities TLV.
const TLV_RI_CAPABILITIES: u16 = 1;
/// RFC 7770 §2.4 capability bits, numbered from the most significant: bit 0
/// graceful-restart capable, bit 1 graceful-restart helper (RFC 3623), bit
/// 2 stub router support (RFC 6987), bit 7 host router support (RFC 8770).
pub const RI_CAP_GR_CAPABLE: u32 = 1 << 31;
pub const RI_CAP_GR_HELPER: u32 = 1 << 30;
pub const RI_CAP_STUB_ROUTER: u32 = 1 << 29;
pub const RI_CAP_HOST_ROUTER: u32 = 1 << 24;

/// RFC 3630 §2.1: the Traffic Engineering LSA's opaque type (1), so its Link
/// State IDs are `1.x.y.z`. Area scope (type 10). One top-level TLV per LSA
/// (§2.3.1): opaque ID 0 holds the Router Address TLV, ID `n >= 1` one Link
/// TLV (`te_link_state_id`).
pub const OPAQUE_TYPE_TE: u8 = 1;
const TLV_TE_ROUTER_ADDRESS: u16 = 1;
const TLV_TE_LINK: u16 = 2;
/// RFC 3630 §2.5 Link TLV sub-TLVs.
const TE_LINK_TYPE: u16 = 1;
const TE_LINK_ID: u16 = 2;
const TE_LOCAL_ADDR: u16 = 3;
const TE_REMOTE_ADDR: u16 = 4;
const TE_METRIC: u16 = 5;
const TE_MAX_BW: u16 = 6;
const TE_MAX_RESERVABLE_BW: u16 = 7;
const TE_UNRESERVED_BW: u16 = 8;
const TE_ADMIN_GROUP: u16 = 9;
/// RFC 3630 §2.5.1 link types.
pub const TE_LINK_POINT_TO_POINT: u8 = 1;
pub const TE_LINK_MULTI_ACCESS: u8 = 2;

/// The Router Address LSA's Link State ID (opaque type 1, ID 0).
pub const TE_ROUTER_ADDRESS_LINK_STATE_ID: Ipv4Addr = Ipv4Addr::new(OPAQUE_TYPE_TE, 0, 0, 0);

/// The Link State ID of the `n`th (`n >= 1`) Link TLV LSA.
pub fn te_link_state_id(n: u32) -> Ipv4Addr {
    let b = n.to_be_bytes();
    Ipv4Addr::new(OPAQUE_TYPE_TE, b[1], b[2], b[3])
}

/// One RFC 3630 Link TLV. Bandwidths are IEEE 754 single precision, bytes per
/// second (§2.5.6-8).
#[derive(Debug, Clone, PartialEq)]
pub struct TeLink {
    /// `TE_LINK_POINT_TO_POINT` or `TE_LINK_MULTI_ACCESS`.
    pub link_type: u8,
    /// The neighbor's router id (point-to-point) or the DR's interface address.
    pub link_id: Ipv4Addr,
    /// This router's interface address.
    pub local_addr: Ipv4Addr,
    /// The neighbor's interface address (point-to-point only).
    pub remote_addr: Option<Ipv4Addr>,
    /// TE metric, here the OSPF cost.
    pub metric: u32,
    /// Maximum bandwidth.
    pub max_bandwidth: f32,
    /// Maximum reservable bandwidth.
    pub max_reservable: f32,
    /// Unreserved bandwidth per priority 0-7.
    pub unreserved: [f32; 8],
    /// Administrative group bit mask.
    pub admin_group: u32,
}

/// A decoded TE LSA body.
#[derive(Debug, Clone, PartialEq)]
pub enum TeBody {
    /// The Router Address TLV: a stable, always-reachable address.
    RouterAddress(Ipv4Addr),
    /// A Link TLV.
    Link(TeLink),
}

/// A Router Address LSA body (RFC 3630 §2.4.1).
pub fn encode_te_router_address(addr: Ipv4Addr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    put_tlv(&mut buf, TLV_TE_ROUTER_ADDRESS, &addr.octets());
    buf
}

/// A Link LSA body (RFC 3630 §2.4.2).
pub fn encode_te_link(l: &TeLink) -> Vec<u8> {
    let mut sub = Vec::new();
    put_tlv(&mut sub, TE_LINK_TYPE, &[l.link_type]);
    put_tlv(&mut sub, TE_LINK_ID, &l.link_id.octets());
    put_tlv(&mut sub, TE_LOCAL_ADDR, &l.local_addr.octets());
    if let Some(r) = l.remote_addr {
        put_tlv(&mut sub, TE_REMOTE_ADDR, &r.octets());
    }
    put_tlv(&mut sub, TE_METRIC, &l.metric.to_be_bytes());
    put_tlv(&mut sub, TE_MAX_BW, &l.max_bandwidth.to_be_bytes());
    put_tlv(
        &mut sub,
        TE_MAX_RESERVABLE_BW,
        &l.max_reservable.to_be_bytes(),
    );
    let unreserved: Vec<u8> = l.unreserved.iter().flat_map(|f| f.to_be_bytes()).collect();
    put_tlv(&mut sub, TE_UNRESERVED_BW, &unreserved);
    put_tlv(&mut sub, TE_ADMIN_GROUP, &l.admin_group.to_be_bytes());
    let mut buf = Vec::with_capacity(sub.len() + 4);
    put_tlv(&mut buf, TLV_TE_LINK, &sub);
    buf
}

/// Splits a TLV run into `(type, value)`; `None` when a TLV overruns it.
fn tlvs(mut data: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let t = u16::from_be_bytes([data[0], data[1]]);
        let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        out.push((t, data.get(4..4 + len)?));
        data = data.get(4 + len.next_multiple_of(4)..).unwrap_or_default();
    }
    Some(out)
}

fn addr4(v: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(v).ok().map(Ipv4Addr::from)
}

fn f32_at(v: &[u8]) -> Option<f32> {
    <[u8; 4]>::try_from(v).ok().map(f32::from_be_bytes)
}

fn u32_at(v: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(v).ok().map(u32::from_be_bytes)
}

/// A received type 10 opaque type 1 LSA's first known top-level TLV. Unknown
/// top-level TLVs and Link sub-TLVs are skipped on decode (the LSA itself is
/// held and re-flooded as the raw bytes, so nothing is lost); `None` for
/// anything else or a malformed or incomplete body.
pub fn decode_te(lsa: &Lsa) -> Option<TeBody> {
    if lsa.header.lsa_type != LSA_TYPE_OPAQUE_AREA
        || opaque_type(lsa.header.link_state_id) != OPAQUE_TYPE_TE
    {
        return None;
    }
    let LsaBody::Opaque(body) = &lsa.body else {
        return None;
    };
    for (t, v) in tlvs(body)? {
        match t {
            TLV_TE_ROUTER_ADDRESS => return addr4(v).map(TeBody::RouterAddress),
            TLV_TE_LINK => {
                let (mut ty, mut id, mut local, mut remote) = (None, None, None, None);
                let (mut metric, mut max, mut resv, mut unres, mut admin) =
                    (None, None, None, None, None);
                for (st, sv) in tlvs(v)? {
                    match st {
                        TE_LINK_TYPE => ty = sv.first().copied(),
                        TE_LINK_ID => id = addr4(sv),
                        TE_LOCAL_ADDR => local = addr4(sv),
                        TE_REMOTE_ADDR => remote = addr4(sv),
                        TE_METRIC => metric = u32_at(sv),
                        TE_MAX_BW => max = f32_at(sv),
                        TE_MAX_RESERVABLE_BW => resv = f32_at(sv),
                        TE_UNRESERVED_BW if sv.len() == 32 => {
                            unres = Some(std::array::from_fn(|i| {
                                f32_at(&sv[4 * i..4 * i + 4]).unwrap_or(0.0)
                            }));
                        }
                        TE_ADMIN_GROUP => admin = u32_at(sv),
                        _ => {}
                    }
                }
                // RFC 3630 §2.5: only the type and the link id are mandatory;
                // the rest default to zero / absent.
                return Some(TeBody::Link(TeLink {
                    link_type: ty?,
                    link_id: id?,
                    local_addr: local.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    remote_addr: remote,
                    metric: metric.unwrap_or(0),
                    max_bandwidth: max.unwrap_or(0.0),
                    max_reservable: resv.unwrap_or(0.0),
                    unreserved: unres.unwrap_or([0.0; 8]),
                    admin_group: admin.unwrap_or(0),
                }));
            }
            _ => {}
        }
    }
    None
}

/// RFC 7684 §2: Extended Prefix (opaque type 7) and Extended Link (8) LSAs,
/// area scope (type 10). The opaque ID is the TLV's instance: each LSA holds
/// exactly one top-level TLV (type 1 in both), so a router allocates one ID
/// per prefix or link (`ext_state_id`).
pub const OPAQUE_TYPE_EXT_PREFIX: u8 = 7;
pub const OPAQUE_TYPE_EXT_LINK: u8 = 8;
const TLV_EXT_PREFIX: u16 = 1;
const TLV_EXT_LINK: u16 = 1;
/// RFC 7684 §2.1 Route Type: 0 unspecified, 1 intra-area, 3 inter-area, 5
/// external, 7 NSSA external.
pub const EXT_ROUTE_INTRA_AREA: u8 = 1;
/// RFC 7684 §2.1 flags: A (attach, prefix from another area) and N (node: a
/// host prefix naming the advertising router).
pub const EXT_PREFIX_FLAG_A: u8 = 0x80;
pub const EXT_PREFIX_FLAG_N: u8 = 0x40;

/// The Link State ID of the Extended Prefix (`opaque_type` 7) or Extended Link
/// (8) LSA with opaque ID `n`.
pub fn ext_state_id(opaque_type: u8, n: u32) -> Ipv4Addr {
    let b = n.to_be_bytes();
    Ipv4Addr::new(opaque_type, b[1], b[2], b[3])
}

/// One RFC 7684 §2.1 Extended Prefix TLV. IPv4 only (address family 0).
/// `sub_tlvs` is the verbatim, 4-byte-aligned sub-TLV run: unknown ones are
/// kept and re-flooded, the SR sub-TLVs (#1168) are built into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPrefix {
    pub route_type: u8,
    pub prefix: Ipv4Addr,
    pub prefix_len: u8,
    pub flags: u8,
    pub sub_tlvs: Vec<u8>,
}

/// One RFC 7684 §3.1 Extended Link TLV: the Router-LSA link it extends is
/// identified by type, Link ID and Link Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedLink {
    pub link_type: u8,
    pub link_id: Ipv4Addr,
    pub link_data: Ipv4Addr,
    pub sub_tlvs: Vec<u8>,
}

/// An Extended Prefix LSA body.
pub fn encode_extended_prefix(p: &ExtendedPrefix) -> Vec<u8> {
    let mut v = vec![p.route_type, p.prefix_len, 0, p.flags];
    // §2.1: the prefix in whole 32-bit words, so 0 octets for /0, else 4.
    if p.prefix_len > 0 {
        v.extend_from_slice(&p.prefix.octets());
    }
    v.extend_from_slice(&p.sub_tlvs);
    let mut buf = Vec::with_capacity(v.len() + 4);
    put_tlv(&mut buf, TLV_EXT_PREFIX, &v);
    buf
}

/// An Extended Link LSA body.
pub fn encode_extended_link(l: &ExtendedLink) -> Vec<u8> {
    let mut v = vec![l.link_type, 0, 0, 0];
    v.extend_from_slice(&l.link_id.octets());
    v.extend_from_slice(&l.link_data.octets());
    v.extend_from_slice(&l.sub_tlvs);
    let mut buf = Vec::with_capacity(v.len() + 4);
    put_tlv(&mut buf, TLV_EXT_LINK, &v);
    buf
}

/// The first top-level TLV of `tlv` type in a type 10 opaque LSA of `opaque`
/// type; `None` for anything else or a malformed run.
fn ext_tlv(lsa: &Lsa, opaque: u8, tlv: u16) -> Option<&[u8]> {
    if lsa.header.lsa_type != LSA_TYPE_OPAQUE_AREA
        || opaque_type(lsa.header.link_state_id) != opaque
    {
        return None;
    }
    let LsaBody::Opaque(body) = &lsa.body else {
        return None;
    };
    tlvs(body)?
        .into_iter()
        .find(|(t, _)| *t == tlv)
        .map(|(_, v)| v)
}

/// A received Extended Prefix LSA's TLV (RFC 7684 §2.1). `None` for a
/// non-IPv4 address family, a prefix length over 32, or a short or malformed
/// TLV or sub-TLV run.
pub fn decode_extended_prefix(lsa: &Lsa) -> Option<ExtendedPrefix> {
    let v = ext_tlv(lsa, OPAQUE_TYPE_EXT_PREFIX, TLV_EXT_PREFIX)?;
    let [route_type, prefix_len, af, flags, rest @ ..] = v else {
        return None;
    };
    if *af != 0 || *prefix_len > 32 {
        return None;
    }
    let (prefix, sub_tlvs) = if *prefix_len == 0 {
        (Ipv4Addr::UNSPECIFIED, rest)
    } else {
        (addr4(rest.get(..4)?)?, &rest[4..])
    };
    tlvs(sub_tlvs)?;
    Some(ExtendedPrefix {
        route_type: *route_type,
        prefix,
        prefix_len: *prefix_len,
        flags: *flags,
        sub_tlvs: sub_tlvs.to_vec(),
    })
}

/// A received Extended Link LSA's TLV (RFC 7684 §3.1); `None` when malformed.
pub fn decode_extended_link(lsa: &Lsa) -> Option<ExtendedLink> {
    let v = ext_tlv(lsa, OPAQUE_TYPE_EXT_LINK, TLV_EXT_LINK)?;
    let sub_tlvs = v.get(12..)?;
    tlvs(sub_tlvs)?;
    Some(ExtendedLink {
        link_type: v[0],
        link_id: addr4(&v[4..8])?,
        link_data: addr4(&v[8..12])?,
        sub_tlvs: sub_tlvs.to_vec(),
    })
}

/// An RI LSA body carrying only the Informational Capabilities TLV. Held as
/// `LsaBody::Opaque`, like any other opaque body.
pub fn encode_router_info(capabilities: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    put_tlv(&mut buf, TLV_RI_CAPABILITIES, &capabilities.to_be_bytes());
    buf
}

/// A received RI LSA's Informational Capabilities (RFC 7770 §2.3): a type
/// 10 or 11 opaque LSA of opaque type 4. Unknown TLVs are skipped; `None`
/// for anything else, a malformed body, or no capabilities TLV.
pub fn router_info_capabilities(lsa: &Lsa) -> Option<u32> {
    if !matches!(
        lsa.header.lsa_type,
        LSA_TYPE_OPAQUE_AREA | LSA_TYPE_OPAQUE_AS
    ) || opaque_type(lsa.header.link_state_id) != OPAQUE_TYPE_ROUTER_INFO
    {
        return None;
    }
    let LsaBody::Opaque(body) = &lsa.body else {
        return None;
    };
    let mut data = body.as_slice();
    while data.len() >= 4 {
        let t = u16::from_be_bytes([data[0], data[1]]);
        let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        let v = data.get(4..4 + len)?;
        if t == TLV_RI_CAPABILITIES {
            return (len >= 4).then(|| u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
        }
        data = data.get(4 + len.next_multiple_of(4)..).unwrap_or_default();
    }
    None
}

/// RFC 8665 §3.1/§3.2: the SR-Algorithm and SID/Label Range TLVs of the RI LSA.
const TLV_RI_SR_ALGORITHM: u16 = 8;
const TLV_RI_SID_LABEL_RANGE: u16 = 9;
/// RFC 8665 §2.3 sub-TLV of the SID/Label Range TLV: a label (length 3) or SID.
const SUB_SID_LABEL: u16 = 1;
/// RFC 8665 §5/§6/§7 sub-TLV types (Extended Prefix, Extended Link).
const SUB_PREFIX_SID: u16 = 2;
const SUB_ADJ_SID: u16 = 2;
const SUB_LAN_ADJ_SID: u16 = 3;
/// The only algorithm built: SPF.
pub const SR_ALGO_SPF: u8 = 0;
/// RFC 8665 §5 Prefix-SID flags: NP (no PHP), E (explicit null), V (value is
/// a label), L (local).
pub const PREFIX_SID_FLAG_NP: u8 = 0x40;
pub const PREFIX_SID_FLAG_E: u8 = 0x10;
const PREFIX_FLAG_V: u8 = 0x08;
const PREFIX_FLAG_L: u8 = 0x04;
/// RFC 8665 §6 Adj-SID flags: B (backup), V, L.
pub const ADJ_SID_FLAG_B: u8 = 0x80;
const ADJ_FLAG_V: u8 = 0x40;
const ADJ_FLAG_L: u8 = 0x20;

/// A router's RFC 8665 SR capability from its RI LSA: the algorithms and the
/// SRGB ranges `(first label, size)`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouterInfoSr {
    pub algorithms: Vec<u8>,
    pub srgb: Vec<(u32, u32)>,
}

/// An RI LSA body: the capabilities TLV, and when `srgb` is set the
/// SR-Algorithm (SPF only) and SID/Label Range TLVs.
pub fn encode_router_info_sr(capabilities: u32, srgb: Option<(u32, u32)>) -> Vec<u8> {
    let mut buf = encode_router_info(capabilities);
    if let Some((start, range)) = srgb {
        put_tlv(&mut buf, TLV_RI_SR_ALGORITHM, &[SR_ALGO_SPF]);
        let r = range.to_be_bytes();
        let mut v = vec![r[1], r[2], r[3], 0];
        put_tlv(&mut v, SUB_SID_LABEL, &start.to_be_bytes()[1..]);
        put_tlv(&mut buf, TLV_RI_SID_LABEL_RANGE, &v);
    }
    buf
}

/// A received RI LSA's SR TLVs; `None` for anything but a well-formed RI LSA
/// carrying an SR-Algorithm TLV. Ranges with a SID (not label) base, and a
/// malformed one, are skipped.
pub fn decode_router_info_sr(lsa: &Lsa) -> Option<RouterInfoSr> {
    if !matches!(
        lsa.header.lsa_type,
        LSA_TYPE_OPAQUE_AREA | LSA_TYPE_OPAQUE_AS
    ) || opaque_type(lsa.header.link_state_id) != OPAQUE_TYPE_ROUTER_INFO
    {
        return None;
    }
    let LsaBody::Opaque(body) = &lsa.body else {
        return None;
    };
    let mut sr = RouterInfoSr::default();
    let mut seen = false;
    for (t, v) in tlvs(body)? {
        if t == TLV_RI_SR_ALGORITHM {
            seen = true;
            sr.algorithms.extend_from_slice(v);
        } else if t == TLV_RI_SID_LABEL_RANGE && v.len() >= 4 {
            let size = u32::from_be_bytes([0, v[0], v[1], v[2]]);
            for (st, sv) in tlvs(&v[4..]).unwrap_or_default() {
                if st == SUB_SID_LABEL && sv.len() == 3 {
                    let first = u32::from_be_bytes([0, sv[0], sv[1], sv[2]]) & 0xF_FFFF;
                    sr.srgb.push((first, size));
                }
            }
        }
    }
    seen.then_some(sr)
}

/// One RFC 8665 §5 Prefix-SID: `value` is an index into the SRGB, or a label
/// when `absolute` (V and L flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixSid {
    pub flags: u8,
    pub algorithm: u8,
    pub value: u32,
    pub absolute: bool,
}

/// The Prefix-SID sub-TLV for `index` (V and L clear, algorithm SPF), NP set
/// by `no_php` and E by `explicit_null`.
pub fn encode_prefix_sid(index: u32, no_php: bool, explicit_null: bool) -> Vec<u8> {
    let mut flags = 0;
    if no_php {
        flags |= PREFIX_SID_FLAG_NP;
    }
    if explicit_null {
        flags |= PREFIX_SID_FLAG_E;
    }
    let mut v = vec![flags, 0, SR_ALGO_SPF, 0];
    v.extend_from_slice(&index.to_be_bytes());
    let mut buf = Vec::new();
    put_tlv(&mut buf, SUB_PREFIX_SID, &v);
    buf
}

/// The first well-formed Prefix-SID in an Extended Prefix TLV's sub-TLV run.
pub fn decode_prefix_sid(sub_tlvs: &[u8]) -> Option<PrefixSid> {
    tlvs(sub_tlvs)?.into_iter().find_map(|(t, v)| {
        if t != SUB_PREFIX_SID || v.len() < 7 {
            return None;
        }
        let absolute = v[0] & PREFIX_FLAG_V != 0 && v[0] & PREFIX_FLAG_L != 0;
        let value = if absolute {
            u32::from_be_bytes([0, v[4], v[5], v[6]]) & 0xF_FFFF
        } else {
            u32_at(v.get(4..8)?)?
        };
        Some(PrefixSid {
            flags: v[0],
            algorithm: v[2],
            value,
            absolute,
        })
    })
}

/// One RFC 8665 §6/§7 Adj-SID or LAN Adj-SID; `neighbor` is the LAN form's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdjSid {
    pub flags: u8,
    pub weight: u8,
    pub neighbor: Option<Ipv4Addr>,
    pub value: u32,
    pub absolute: bool,
}

/// An Adj-SID (`neighbor` None) or LAN Adj-SID sub-TLV carrying `label` (V and
/// L set, 3 octets).
pub fn encode_adj_sid(label: u32, weight: u8, backup: bool, neighbor: Option<Ipv4Addr>) -> Vec<u8> {
    let flags = ADJ_FLAG_V | ADJ_FLAG_L | if backup { ADJ_SID_FLAG_B } else { 0 };
    let mut v = vec![flags, 0, weight, 0];
    if let Some(n) = neighbor {
        v.extend_from_slice(&n.octets());
    }
    v.extend_from_slice(&label.to_be_bytes()[1..]);
    let mut buf = Vec::new();
    let t = if neighbor.is_some() {
        SUB_LAN_ADJ_SID
    } else {
        SUB_ADJ_SID
    };
    put_tlv(&mut buf, t, &v);
    buf
}

/// Every well-formed Adj-SID and LAN Adj-SID in an Extended Link TLV's
/// sub-TLV run; a malformed one is skipped.
pub fn decode_adj_sids(sub_tlvs: &[u8]) -> Vec<AdjSid> {
    let mut out = Vec::new();
    for (t, v) in tlvs(sub_tlvs).unwrap_or_default() {
        let lan = t == SUB_LAN_ADJ_SID;
        if (t != SUB_ADJ_SID && !lan) || v.len() < 4 {
            continue;
        }
        let (neighbor, rest) = if lan {
            match v.get(4..8).and_then(addr4) {
                Some(n) => (Some(n), &v[8..]),
                None => continue,
            }
        } else {
            (None, &v[4..])
        };
        let absolute = v[0] & ADJ_FLAG_V != 0 && v[0] & ADJ_FLAG_L != 0;
        let value = match (absolute, rest.len()) {
            (true, 3) => u32::from_be_bytes([0, rest[0], rest[1], rest[2]]) & 0xF_FFFF,
            (false, 4) => u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]),
            _ => continue,
        };
        out.push(AdjSid {
            flags: v[0],
            weight: v[2],
            neighbor,
            value,
            absolute,
        });
    }
    out
}

/// RFC 5250 §3: types 9-11. Only sent to a neighbor whose DBD set the O-bit.
pub fn is_opaque(lsa_type: u8) -> bool {
    matches!(
        lsa_type,
        LSA_TYPE_OPAQUE_LINK | LSA_TYPE_OPAQUE_AREA | LSA_TYPE_OPAQUE_AS
    )
}

/// AS flooding scope (Type-5, Type-11): never present in a stub area (RFC
/// 2328 §3.6, RFC 5250 §3).
pub fn is_as_scope(lsa_type: u8) -> bool {
    matches!(lsa_type, LSA_TYPE_AS_EXTERNAL | LSA_TYPE_OPAQUE_AS)
}

/// Whether an LSA of `lsa_type` belongs in an area of this kind: no AS-scope
/// LSA in a stub area or NSSA (`stub` is set for both), and a Type-7 only in
/// an NSSA (RFC 3101 §2.4).
pub fn in_area_scope(lsa_type: u8, stub: bool, nssa: bool) -> bool {
    nos_ospf_common::areas::in_area_scope(
        is_as_scope(lsa_type),
        lsa_type == LSA_TYPE_NSSA_EXTERNAL,
        stub,
        nssa,
    )
}

/// Type 9: held per link, never flooded past the link it arrived on.
pub fn is_link_local_scope(lsa_type: u8) -> bool {
    lsa_type == LSA_TYPE_OPAQUE_LINK
}

/// RFC 5250 §3: an opaque LSA's Link State ID is opaque type (top octet)
/// then a 24-bit opaque ID.
pub fn opaque_type(link_state_id: Ipv4Addr) -> u8 {
    link_state_id.octets()[0]
}

/// RFC 2328 §12.4.1's Router-LSA link types.
pub const LINK_TYPE_POINT_TO_POINT: u8 = 1;
pub const LINK_TYPE_TRANSIT_NETWORK: u8 = 2;
pub const LINK_TYPE_STUB_NETWORK: u8 = 3;
/// RFC 2328 §12.4.1.3: a virtual link, in the backbone's Router-LSA.
pub const LINK_TYPE_VIRTUAL: u8 = 4;

/// RFC 2328 A.4.2's Router-LSA flags: B (area border router), E (AS
/// boundary router) and V (endpoint of a fully adjacent virtual link, set in
/// the transit area's Router-LSA).
pub const ROUTER_FLAG_B: u8 = 0x01;
pub const ROUTER_FLAG_E: u8 = 0x02;
pub const ROUTER_FLAG_V: u8 = 0x04;
/// RFC 3101 A.2: Nt — an NSSA border router that always translates Type-7s.
pub const ROUTER_FLAG_NT: u8 = 0x10;
/// RFC 8770 §3: H — a host router, never used for transit.
pub const ROUTER_FLAG_H: u8 = 0x80;

pub const LSA_HEADER_LEN: usize = 20;
/// One Router-LSA link entry's wire length (Appendix A.4.2): Link ID (4) +
/// Link Data (4) + Type (1) + # TOS (1, always 0 — no TOS metrics) + metric
/// (2).
const ROUTER_LINK_LEN: usize = 12;

/// RFC 2328 §13.1's `MaxAge` (seconds) — an LSA at this age is being flushed
/// and, per §13.1's tie-break, always treated as the newer instance.
pub use nos_ospf_common::lsa::MAX_AGE;

/// RFC 2328 §14's `LSRefreshTime` (seconds) — a self-originated LSA is
/// reoriginated once its own age reaches this, even with unchanged content,
/// so it never reaches `MAX_AGE` while its originator is still alive.
pub const LS_REFRESH_TIME: u16 = 1800;

/// RFC 6987 §3 `MaxLinkMetric`: the cost a stub router gives its transit
/// (type 1/2) Router-LSA links. Not unreachable — a path through the router
/// is still used when it's the only one. RFC 5286's `LSInfinity`.
pub const MAX_LINK_METRIC: u16 = 0xFFFF;

/// RFC 2328 §12.4 / Appendix B's `MinLSInterval` — the minimum age a
/// self-originated instance must reach before it may be re-originated with
/// changed content (see `link::originate::install_self_originated`).
pub const MIN_LS_INTERVAL: u16 = 5;

/// RFC 2328 §12.1.6's `InitialSequenceNumber` — every self-originated LSA
/// starts here and increments by one on each refresh.
pub const INITIAL_SEQUENCE_NUMBER: i32 = i32::MIN + 1;

/// RFC 2328 §12.1.6's `MaxSequenceNumber` — an LSA that reaches it must be
/// flushed (prematurely aged) before being re-originated at
/// `INITIAL_SEQUENCE_NUMBER`; `0x8000_0000` in between is reserved and must
/// never be produced (see `link::originate::install_self_originated`).
pub const MAX_SEQUENCE_NUMBER: i32 = i32::MAX;

/// Identifies one LSA instance's slot in the database, independent of its
/// sequence number/age/checksum — RFC 2328 keys the LSDB by exactly these
/// three fields (§12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LsaKey {
    pub lsa_type: u8,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
}

/// RFC 2328 Appendix A.4.1's 20-byte common LSA header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaHeader {
    pub age: u16,
    pub options: u8,
    pub lsa_type: u8,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
    /// RFC 2328 §12.1.6: a signed 32-bit space, `MinSequenceNumber =
    /// 0x8000_0001` through `MaxSequenceNumber = 0x7fff_ffff` — stored as
    /// `i32` so plain integer comparison gives the correct "which is newer"
    /// ordering the RFC intends.
    pub sequence_number: i32,
    /// RFC 905 Annex B Fletcher checksum — *not* `packet::checksum`'s RFC
    /// 1071 sum used by the OSPF common header.
    pub checksum: u16,
    /// Total LSA length in bytes, header included.
    pub length: u16,
}

impl LsaHeader {
    pub fn key(&self) -> LsaKey {
        LsaKey {
            lsa_type: self.lsa_type,
            link_state_id: self.link_state_id,
            advertising_router: self.advertising_router,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLink {
    pub link_id: Ipv4Addr,
    pub link_data: Ipv4Addr,
    pub link_type: u8,
    pub metric: u16,
    /// RFC 2328 A.4.2 / RFC 4915 per-link TOS/MT entries (4 bytes each),
    /// kept verbatim so a foreign LSA re-floods byte-identical (§13.3).
    /// SPF ignores them (TOS 0 / MT-ID 0 only, RFC 2328 §16.3).
    pub tos: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsaBody {
    pub flags: u8,
    pub links: Vec<RouterLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLsaBody {
    pub network_mask: Ipv4Addr,
    pub attached_routers: Vec<Ipv4Addr>,
}

/// RFC 2328 Appendix A.4.5's AS-external-LSA body.
///
/// The E bit (metric word's top bit, A.4.5: Type-2) is carried in `e_type2`,
/// so a foreign LSA is re-flooded byte-identical (RFC 2328 §13); a nos-
/// originated one gets it from `redistribute ... metric-type`.
/// `ponytail:` `forwarding_address` is decoded faithfully but never
/// originated non-zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsExternalLsaBody {
    pub network_mask: Ipv4Addr,
    /// Low 24 bits only; the E bit lives in `e_type2`.
    pub metric: u32,
    /// RFC 2328 A.4.5 E bit: a Type-2 external metric.
    pub e_type2: bool,
    pub forwarding_address: Ipv4Addr,
    pub external_route_tag: u32,
    /// Trailing TOS/MT entries (A.4.5, 12 bytes each in RFC 2328: kept
    /// verbatim, multiple of 4), ignored by SPF.
    pub tos: Vec<u8>,
}

/// The 24-bit metric of an AS-external or Summary LSA (the E bit is split off
/// for the former — see `AsExternalLsaBody`).
const EXTERNAL_METRIC_MASK: u32 = 0x00FF_FFFF;

/// RFC 2328 Appendix A.4.4's Summary-LSA body — one wire shape backs both
/// `LSA_TYPE_NETWORK_SUMMARY` (type 3) and `LSA_TYPE_ASBR_SUMMARY` (type 4);
/// only `LsaHeader.lsa_type` plus `link_state_id`'s conventional meaning (a
/// network's address for type 3, the ASBR's own router-id for type 4, with
/// `network_mask` conventionally `0.0.0.0` for type 4) distinguish them —
/// mirrors RFC 2328 itself, which defines an identical wire format for both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryLsaBody {
    pub network_mask: Ipv4Addr,
    /// Low 24 bits only, reusing `EXTERNAL_METRIC_MASK` — RFC 2328 A.4.4's
    /// metric field is also a 24-bit value following a 1-byte TOS field.
    pub metric: u32,
    /// Trailing TOS/MT entries (A.4.4, 4 bytes each), kept verbatim and
    /// ignored by SPF.
    pub tos: Vec<u8>,
}

/// RFC 3623 Grace-LSA body: how long the restarting router asks its
/// neighbors to keep helping, why it restarts, and (optional on decode, always
/// sent) the interface address it was sent from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraceLsaBody {
    pub grace_period: u32,
    pub restart_reason: u8,
    pub interface_address: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaBody {
    Router(RouterLsaBody),
    Network(NetworkLsaBody),
    Summary(SummaryLsaBody),
    AsExternal(AsExternalLsaBody),
    /// Type 9, opaque type 3 only — see `LSA_TYPE_OPAQUE_LINK`.
    Grace(GraceLsaBody),
    /// Any other type 9/10/11 body, kept byte for byte so it re-encodes with
    /// the originator's checksum. Never parsed; SPF ignores it.
    Opaque(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Lsa {
    pub header: LsaHeader,
    pub body: LsaBody,
}

impl nos_ospf_common::lsa::LsaHeader for LsaHeader {
    type Key = LsaKey;
    fn key(&self) -> LsaKey {
        LsaHeader::key(self)
    }
    fn seq(&self) -> i32 {
        self.sequence_number
    }
    fn age(&self) -> u16 {
        self.age
    }
    fn set_age(&mut self, age: u16) {
        self.age = age;
    }
    fn checksum(&self) -> u16 {
        self.checksum
    }
    fn length(&self) -> u16 {
        self.length
    }
    fn advertising_router(&self) -> Ipv4Addr {
        self.advertising_router
    }
}

impl nos_ospf_common::lsa::Lsa for Lsa {
    type Header = LsaHeader;
    type Lls = crate::lls::Lls;
    fn header(&self) -> &LsaHeader {
        &self.header
    }
    fn header_mut(&mut self) -> &mut LsaHeader {
        &mut self.header
    }
    fn same_content(&self, other: &Self) -> bool {
        self.body == other.body
    }
    fn is_topology(&self) -> bool {
        (LSA_TYPE_ROUTER..=LSA_TYPE_AS_EXTERNAL).contains(&self.header.lsa_type)
    }
}

pub(crate) fn encode_lsa_header(buf: &mut Vec<u8>, header: &LsaHeader) {
    buf.extend_from_slice(&header.age.to_be_bytes());
    buf.push(header.options);
    buf.push(header.lsa_type);
    buf.extend_from_slice(&header.link_state_id.octets());
    buf.extend_from_slice(&header.advertising_router.octets());
    buf.extend_from_slice(&header.sequence_number.to_be_bytes());
    buf.extend_from_slice(&header.checksum.to_be_bytes());
    buf.extend_from_slice(&header.length.to_be_bytes());
}

pub(crate) fn decode_lsa_header(data: &[u8]) -> Result<LsaHeader, PacketError> {
    if data.len() < LSA_HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    Ok(LsaHeader {
        age: u16::from_be_bytes([data[0], data[1]]),
        options: data[2],
        lsa_type: data[3],
        link_state_id: read_ipv4(data, 4),
        advertising_router: read_ipv4(data, 8),
        sequence_number: i32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        checksum: u16::from_be_bytes([data[16], data[17]]),
        length: u16::from_be_bytes([data[18], data[19]]),
    })
}

pub(crate) fn encode_key(buf: &mut Vec<u8>, key: &LsaKey) {
    // RFC 2328 Appendix A.3.4's LS type field is nominally 32 bits wide but
    // only the low byte is ever non-zero.
    buf.extend_from_slice(&[0, 0, 0, key.lsa_type]);
    buf.extend_from_slice(&key.link_state_id.octets());
    buf.extend_from_slice(&key.advertising_router.octets());
}

pub(crate) const KEY_LEN: usize = 12;

pub(crate) fn decode_key(data: &[u8]) -> LsaKey {
    LsaKey {
        lsa_type: data[3],
        link_state_id: read_ipv4(data, 4),
        advertising_router: read_ipv4(data, 8),
    }
}

fn encode_body(body: &LsaBody) -> Vec<u8> {
    match body {
        LsaBody::Router(r) => {
            let mut buf = Vec::with_capacity(4 + r.links.len() * 12);
            buf.push(r.flags);
            buf.push(0); // reserved
            buf.extend_from_slice(
                &u16::try_from(r.links.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            for link in &r.links {
                buf.extend_from_slice(&link.link_id.octets());
                buf.extend_from_slice(&link.link_data.octets());
                buf.push(link.link_type);
                buf.push(u8::try_from(link.tos.len() / 4).unwrap_or(u8::MAX));
                buf.extend_from_slice(&link.metric.to_be_bytes());
                buf.extend_from_slice(&link.tos);
            }
            buf
        }
        LsaBody::Network(n) => {
            let mut buf = Vec::with_capacity(4 + n.attached_routers.len() * 4);
            buf.extend_from_slice(&n.network_mask.octets());
            for router in &n.attached_routers {
                buf.extend_from_slice(&router.octets());
            }
            buf
        }
        LsaBody::AsExternal(e) => {
            let mut buf = Vec::with_capacity(16);
            buf.extend_from_slice(&e.network_mask.octets());
            let word = (e.metric & EXTERNAL_METRIC_MASK) | (u32::from(e.e_type2) << 31);
            buf.extend_from_slice(&word.to_be_bytes());
            buf.extend_from_slice(&e.forwarding_address.octets());
            buf.extend_from_slice(&e.external_route_tag.to_be_bytes());
            buf.extend_from_slice(&e.tos);
            buf
        }
        LsaBody::Summary(s) => {
            let mut buf = Vec::with_capacity(8);
            buf.extend_from_slice(&s.network_mask.octets());
            buf.extend_from_slice(&(s.metric & EXTERNAL_METRIC_MASK).to_be_bytes());
            buf.extend_from_slice(&s.tos);
            buf
        }
        LsaBody::Grace(g) => {
            let mut buf = Vec::with_capacity(24);
            put_tlv(&mut buf, TLV_GRACE_PERIOD, &g.grace_period.to_be_bytes());
            put_tlv(&mut buf, TLV_RESTART_REASON, &[g.restart_reason]);
            if let Some(addr) = g.interface_address {
                put_tlv(&mut buf, TLV_INTERFACE_ADDRESS, &addr.octets());
            }
            buf
        }
        LsaBody::Opaque(bytes) => bytes.clone(),
    }
}

/// One RFC 3623 Appendix A TLV: type, length, value padded to 4 bytes.
fn put_tlv(buf: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    buf.extend_from_slice(&tlv_type.to_be_bytes());
    buf.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    buf.extend_from_slice(value);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

/// Unknown TLVs are skipped (RFC 3623 Appendix A); a missing Grace Period
/// or a wrongly-sized known one is malformed.
fn decode_grace(mut data: &[u8]) -> Result<LsaBody, PacketError> {
    let mut grace_period = None;
    let mut restart_reason = 0;
    let mut interface_address = None;
    while data.len() >= 4 {
        let t = u16::from_be_bytes([data[0], data[1]]);
        let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        let padded = 4 + len.next_multiple_of(4);
        let v = data.get(4..4 + len).ok_or(PacketError::TruncatedBody)?;
        match (t, len) {
            (TLV_GRACE_PERIOD, 4) => {
                grace_period = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
            }
            (TLV_RESTART_REASON, 1) => restart_reason = v[0],
            (TLV_INTERFACE_ADDRESS, 4) => interface_address = Some(read_ipv4(v, 0)),
            (TLV_GRACE_PERIOD | TLV_RESTART_REASON | TLV_INTERFACE_ADDRESS, _) => {
                return Err(PacketError::TruncatedBody);
            }
            _ => {}
        }
        data = data.get(padded..).unwrap_or_default();
    }
    Ok(LsaBody::Grace(GraceLsaBody {
        grace_period: grace_period.ok_or(PacketError::TruncatedBody)?,
        restart_reason,
        interface_address,
    }))
}

fn decode_body(header: &LsaHeader, data: &[u8]) -> Result<LsaBody, PacketError> {
    match header.lsa_type {
        LSA_TYPE_ROUTER => {
            if data.len() < 4 {
                return Err(PacketError::TruncatedBody);
            }
            let flags = data[0];
            let num_links = usize::from(u16::from_be_bytes([data[2], data[3]]));
            let mut rest = &data[4..];
            let mut links = Vec::with_capacity(num_links.min(rest.len() / ROUTER_LINK_LEN));
            for _ in 0..num_links {
                if rest.len() < ROUTER_LINK_LEN {
                    return Err(PacketError::TruncatedBody);
                }
                let tos_len = usize::from(rest[9]) * 4;
                let end = ROUTER_LINK_LEN + tos_len;
                if rest.len() < end {
                    return Err(PacketError::TruncatedBody);
                }
                links.push(RouterLink {
                    link_id: read_ipv4(rest, 0),
                    link_data: read_ipv4(rest, 4),
                    link_type: rest[8],
                    metric: u16::from_be_bytes([rest[10], rest[11]]),
                    tos: rest[ROUTER_LINK_LEN..end].to_vec(),
                });
                rest = &rest[end..];
            }
            if !rest.is_empty() {
                return Err(PacketError::TruncatedBody);
            }
            Ok(LsaBody::Router(RouterLsaBody { flags, links }))
        }
        LSA_TYPE_NETWORK => {
            if data.len() < 4 || !(data.len() - 4).is_multiple_of(4) {
                return Err(PacketError::TruncatedBody);
            }
            let network_mask = read_ipv4(data, 0);
            let attached_routers = data[4..]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                .collect();
            Ok(LsaBody::Network(NetworkLsaBody {
                network_mask,
                attached_routers,
            }))
        }
        LSA_TYPE_AS_EXTERNAL | LSA_TYPE_NSSA_EXTERNAL => {
            if data.len() < 16 || !data.len().is_multiple_of(4) {
                return Err(PacketError::TruncatedBody);
            }
            let network_mask = read_ipv4(data, 0);
            let word = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let metric = word & EXTERNAL_METRIC_MASK;
            let e_type2 = word & 0x8000_0000 != 0;
            let forwarding_address = read_ipv4(data, 8);
            let external_route_tag = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
            Ok(LsaBody::AsExternal(AsExternalLsaBody {
                network_mask,
                metric,
                e_type2,
                forwarding_address,
                external_route_tag,
                tos: data[16..].to_vec(),
            }))
        }
        LSA_TYPE_NETWORK_SUMMARY | LSA_TYPE_ASBR_SUMMARY => {
            if data.len() < 8 || !data.len().is_multiple_of(4) {
                return Err(PacketError::TruncatedBody);
            }
            let network_mask = read_ipv4(data, 0);
            let metric =
                u32::from_be_bytes([data[4], data[5], data[6], data[7]]) & EXTERNAL_METRIC_MASK;
            Ok(LsaBody::Summary(SummaryLsaBody {
                network_mask,
                metric,
                tos: data[8..].to_vec(),
            }))
        }
        LSA_TYPE_OPAQUE_LINK if opaque_type(header.link_state_id) == OPAQUE_TYPE_GRACE => {
            decode_grace(data)
        }
        t if is_opaque(t) => Ok(LsaBody::Opaque(data.to_vec())),
        other => Err(PacketError::UnknownLsaType(other)),
    }
}

/// Encodes `lsa`, overwriting `length`/`checksum` with freshly-computed
/// values (the caller's input header's own `length`/`checksum` are ignored,
/// mirroring `packet::encode_hello` filling in the checksum itself).
pub fn encode_lsa(lsa: &Lsa) -> Vec<u8> {
    let body = encode_body(&lsa.body);
    let total_len = LSA_HEADER_LEN + body.len();
    let mut header = lsa.header;
    header.length = u16::try_from(total_len).unwrap_or(u16::MAX);
    header.checksum = 0;

    let mut buf = Vec::with_capacity(total_len);
    encode_lsa_header(&mut buf, &header);
    buf.extend_from_slice(&body);

    let checksum = lsa_checksum(&buf[2..]);
    buf[16..18].copy_from_slice(&checksum.to_be_bytes());
    buf
}

/// Fills in `header.checksum`/`header.length` exactly as `encode_lsa` puts
/// them on the wire. A self-originated LSA is held locally with these set,
/// so it compares *equal* (`is_newer`) to the copy every neighbor decodes
/// and echoes back in its own periodic resend — with a zero checksum the
/// echo would always look newer and supersede the local instance, including
/// a prematurely aged one, undoing the flush.
pub fn fill_checksum(lsa: &mut Lsa) {
    let buf = encode_lsa(lsa);
    lsa.header.checksum = u16::from_be_bytes([buf[16], buf[17]]);
    lsa.header.length = u16::from_be_bytes([buf[18], buf[19]]);
}

/// Decodes one LSA from the start of `data` (which may contain more bytes
/// after it, e.g. a subsequent LSA in an LSU packet) — trusts the header's
/// own `length` field to find the end.
pub fn decode_lsa(data: &[u8]) -> Result<Lsa, PacketError> {
    let header = decode_lsa_header(data)?;
    let total_len = usize::from(header.length);
    if total_len < LSA_HEADER_LEN || data.len() < total_len {
        return Err(PacketError::TruncatedBody);
    }
    let computed = lsa_checksum(&data[2..total_len]);
    if computed != header.checksum {
        return Err(PacketError::BadChecksum);
    }
    let body = decode_body(&header, &data[LSA_HEADER_LEN..total_len])?;
    Ok(Lsa { header, body })
}

/// RFC 2328 §12.1.7 / RFC 905 Annex B's Fletcher checksum, computed over an
/// LSA starting at the `options` field (i.e. `without_age` excludes the
/// 2-byte `age` field that precedes it) through the end of the body. The
/// 2-byte checksum field embedded at offset 14 of `without_age` (offset 16 of
/// the full LSA) is treated as zero regardless of its actual contents, so
/// this same function both computes a fresh checksum (`encode_lsa`) and
/// validates an existing one (`decode_lsa`, by comparing against the wire
/// value) without the caller needing to zero anything first.
pub(crate) fn lsa_checksum(without_age: &[u8]) -> u16 {
    const CHECKSUM_OFFSET: usize = 14;
    let mut c0: i64 = 0;
    let mut c1: i64 = 0;
    for (i, &b) in without_age.iter().enumerate() {
        let b = if i == CHECKSUM_OFFSET || i == CHECKSUM_OFFSET + 1 {
            0
        } else {
            b
        };
        c0 += i64::from(b);
        c1 += c0;
    }
    c0 %= 255;
    // `c1` is only used mod 255 below, so it is not reduced here (a `%=` on it would be an equivalent mutant).
    let mut x =
        (i64::try_from(without_age.len() - CHECKSUM_OFFSET - 1).unwrap_or(0) * c0 - c1) % 255;
    if x <= 0 {
        x += 255;
    }
    let mut y = 510 - c0 - x;
    if y > 255 {
        y -= 255;
    }
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let (x, y) = (x as u8, y as u8);
    u16::from_be_bytes([x, y])
}

/// RFC 2328 §13.1 instance freshness (sequence, checksum, `MaxAge`, then
/// `MaxAgeDiff`); the rule lives in `nos_ospf_common::lsa::LsaHeader::is_newer`.
pub fn is_newer(a: &LsaHeader, b: &LsaHeader) -> Ordering {
    nos_ospf_common::lsa::LsaHeader::is_newer(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #382: no body length may panic, for any LSA type; an `Err` is fine.
    #[test]
    fn short_bodies_never_panic() {
        let mut header = router_lsa().header;
        for ty in 0..=16u8 {
            header.lsa_type = ty;
            for fill in [0x00u8, 0xff, 0x01] {
                for n in 0..=80 {
                    let _ = decode_body(&header, &vec![fill; n]);
                }
            }
        }
    }

    /// #644: TOS/MT entries on Router links, Summary and AS-External LSAs
    /// decode and re-encode byte for byte (checksum included).
    #[test]
    fn tos_entries_round_trip_verbatim() {
        let mut r = router_lsa();
        let LsaBody::Router(body) = &mut r.body else {
            unreachable!()
        };
        body.links[0].tos = vec![0, 0, 0, 5, 0x21, 0, 0, 9];
        body.links.push(RouterLink {
            link_id: Ipv4Addr::new(10, 0, 1, 1),
            link_data: Ipv4Addr::new(10, 0, 1, 2),
            link_type: 1,
            metric: 7,
            tos: Vec::new(),
        });
        let mut ext = router_lsa();
        ext.header.lsa_type = LSA_TYPE_AS_EXTERNAL;
        ext.body = LsaBody::AsExternal(AsExternalLsaBody {
            network_mask: Ipv4Addr::new(255, 255, 255, 0),
            metric: 3,
            e_type2: true,
            forwarding_address: Ipv4Addr::UNSPECIFIED,
            external_route_tag: 0,
            tos: vec![0x80, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0],
        });
        let mut sum = router_lsa();
        sum.header.lsa_type = LSA_TYPE_NETWORK_SUMMARY;
        sum.body = LsaBody::Summary(SummaryLsaBody {
            network_mask: Ipv4Addr::new(255, 255, 0, 0),
            metric: 1,
            tos: vec![0x10, 0, 0, 2],
        });
        for lsa in [r, ext, sum] {
            let wire = encode_lsa(&lsa);
            let back = decode_lsa(&wire).unwrap();
            assert_eq!(back.body, lsa.body);
            assert_eq!(encode_lsa(&back), wire);
        }
    }

    #[test]
    fn router_link_wire_layout_carries_tos_count() {
        // RFC 2328 A.4.2: link 1 has #TOS = 1 (one extra 4-byte entry).
        let mut body = vec![0, 0, 0, 1];
        body.extend_from_slice(&[10, 0, 0, 1, 255, 255, 255, 0, 3, 1, 0, 1, 0x05, 0, 0, 9]);
        let LsaBody::Router(r) = decode_body(&router_lsa().header, &body).unwrap() else {
            unreachable!()
        };
        assert_eq!(r.links[0].tos, [0x05, 0, 0, 9]);
        assert_eq!(r.links[0].metric, 1);
        // #TOS pointing past the end, or trailing junk, is malformed.
        body.truncate(body.len() - 1);
        assert!(decode_body(&router_lsa().header, &body).is_err());
        let mut junk = body.clone();
        junk.extend_from_slice(&[0, 0, 0, 0, 0]);
        assert!(decode_body(&router_lsa().header, &junk).is_err());
    }

    #[test]
    fn misaligned_tos_tail_is_truncated_body() {
        let mut h = router_lsa().header;
        h.lsa_type = LSA_TYPE_NETWORK_SUMMARY;
        assert_eq!(decode_body(&h, &[0; 11]), Err(PacketError::TruncatedBody));
        h.lsa_type = LSA_TYPE_AS_EXTERNAL;
        assert_eq!(decode_body(&h, &[0; 18]), Err(PacketError::TruncatedBody));
    }

    fn router_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                links: vec![RouterLink {
                    tos: Vec::new(),
                    link_id: Ipv4Addr::new(10, 0, 0, 1),
                    link_data: Ipv4Addr::new(255, 255, 255, 0),
                    link_type: 3,
                    metric: 1,
                }],
            }),
        }
    }

    fn network_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_NETWORK,
                link_state_id: Ipv4Addr::new(10, 0, 0, 1),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Network(NetworkLsaBody {
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                attached_routers: vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(9, 9, 9, 10)],
            }),
        }
    }

    #[test]
    fn router_lsa_round_trips() {
        let lsa = router_lsa();
        let encoded = encode_lsa(&lsa);
        let decoded = decode_lsa(&encoded).unwrap();
        assert_eq!(decoded.header.lsa_type, lsa.header.lsa_type);
        assert_eq!(decoded.header.link_state_id, lsa.header.link_state_id);
        assert_eq!(decoded.body, lsa.body);
    }

    /// RFC 2328 §12.4.1.3: a type-4 (virtual) link and the V bit survive the
    /// wire.
    #[test]
    fn virtual_link_router_lsa_round_trips() {
        let mut lsa = router_lsa();
        lsa.body = LsaBody::Router(RouterLsaBody {
            flags: ROUTER_FLAG_B | ROUTER_FLAG_V,
            links: vec![RouterLink {
                tos: Vec::new(),
                link_id: Ipv4Addr::new(9, 9, 9, 8),
                link_data: Ipv4Addr::new(203, 0, 113, 66),
                link_type: LINK_TYPE_VIRTUAL,
                metric: 7,
            }],
        });
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn router_lsa_with_no_links_round_trips() {
        let mut lsa = router_lsa();
        lsa.body = LsaBody::Router(RouterLsaBody {
            flags: 0,
            links: Vec::new(),
        });
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn network_lsa_round_trips() {
        let lsa = network_lsa();
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn corrupted_checksum_is_rejected() {
        let mut encoded = encode_lsa(&router_lsa());
        let last = encoded.len() - 1;
        encoded[last] ^= 0xff;
        assert_eq!(decode_lsa(&encoded), Err(PacketError::BadChecksum));
    }

    #[test]
    fn unknown_lsa_type_is_rejected() {
        let mut lsa = router_lsa();
        lsa.header.lsa_type = 6;
        let encoded = encode_lsa(&lsa);
        assert_eq!(decode_lsa(&encoded), Err(PacketError::UnknownLsaType(6)));
    }

    fn as_external_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_AS_EXTERNAL,
                link_state_id: Ipv4Addr::new(192, 0, 2, 0),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::AsExternal(AsExternalLsaBody {
                tos: Vec::new(),
                network_mask: Ipv4Addr::new(255, 255, 255, 0),
                metric: 20,
                e_type2: false,
                forwarding_address: Ipv4Addr::UNSPECIFIED,
                external_route_tag: 0,
            }),
        }
    }

    #[test]
    fn as_external_lsa_round_trips() {
        let lsa = as_external_lsa();
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    /// RFC 3101: a Type-7 is a Type-5 body; the header keeps its P-bit.
    #[test]
    fn nssa_external_lsa_round_trips_with_its_p_bit() {
        let mut lsa = as_external_lsa();
        lsa.header.lsa_type = LSA_TYPE_NSSA_EXTERNAL;
        lsa.header.options = OPTION_P;
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.header.options, OPTION_P);
        assert_eq!(decoded.header.lsa_type, LSA_TYPE_NSSA_EXTERNAL);
        assert_eq!(decoded.body, lsa.body);
    }

    /// A foreign Type-2 LSA (E bit set on the wire) decodes with `e_type2`,
    /// the metric still 20, and re-encodes byte-identical (same checksum) —
    /// RFC 2328 §13: flooded unchanged.
    #[test]
    fn as_external_lsa_e_bit_survives_decode_encode() {
        let header = LsaHeader {
            age: 0,
            options: 0,
            lsa_type: LSA_TYPE_AS_EXTERNAL,
            link_state_id: Ipv4Addr::new(192, 0, 2, 0),
            advertising_router: Ipv4Addr::new(9, 9, 9, 9),
            sequence_number: 0x8000_0001u32.cast_signed(),
            checksum: 0,
            length: u16::try_from(LSA_HEADER_LEN + 16).unwrap(),
        };
        let mut buf = Vec::new();
        encode_lsa_header(&mut buf, &header);
        buf.extend_from_slice(&Ipv4Addr::new(255, 255, 255, 0).octets());
        buf.extend_from_slice(&(0x0000_0014u32 | 0x8000_0000u32).to_be_bytes()); // metric=20, E-type bit set
        buf.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
        buf.extend_from_slice(&0u32.to_be_bytes());
        let checksum = lsa_checksum(&buf[2..]);
        buf[16..18].copy_from_slice(&checksum.to_be_bytes());

        let decoded = decode_lsa(&buf).unwrap();
        let LsaBody::AsExternal(e) = &decoded.body else {
            panic!("expected as-external lsa")
        };
        assert_eq!(e.metric, 20);
        assert!(e.e_type2);
        assert_eq!(encode_lsa(&decoded), buf);
    }

    fn summary_lsa(lsa_type: u8, link_state_id: Ipv4Addr, network_mask: Ipv4Addr) -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type,
                link_state_id,
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Summary(SummaryLsaBody {
                tos: Vec::new(),
                network_mask,
                metric: 20,
            }),
        }
    }

    #[test]
    fn summary_lsa_type3_round_trips() {
        let lsa = summary_lsa(
            LSA_TYPE_NETWORK_SUMMARY,
            Ipv4Addr::new(192, 0, 2, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        );
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn summary_lsa_type4_round_trips() {
        // Type 4's link_state_id is conventionally the ASBR's own router-id
        // and network_mask is conventionally unspecified — same body shape,
        // proving one decode_body arm correctly serves both type bytes.
        let lsa = summary_lsa(
            LSA_TYPE_ASBR_SUMMARY,
            Ipv4Addr::new(7, 7, 7, 7),
            Ipv4Addr::UNSPECIFIED,
        );
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
        assert_eq!(decoded.header.lsa_type, LSA_TYPE_ASBR_SUMMARY);
    }

    /// Mirrors `as_external_lsa_metric_e_type_bit_masked_on_decode`: hand-crafts
    /// raw wire bytes with a non-zero TOS byte in the metric word (bypassing
    /// `encode_body`'s own masking) to prove `decode_body` masks it off
    /// independently.
    #[test]
    fn summary_lsa_metric_tos_byte_masked_on_decode() {
        let header = LsaHeader {
            age: 0,
            options: 0,
            lsa_type: LSA_TYPE_NETWORK_SUMMARY,
            link_state_id: Ipv4Addr::new(192, 0, 2, 0),
            advertising_router: Ipv4Addr::new(9, 9, 9, 9),
            sequence_number: 0x8000_0001u32.cast_signed(),
            checksum: 0,
            length: u16::try_from(LSA_HEADER_LEN + 8).unwrap(),
        };
        let mut buf = Vec::new();
        encode_lsa_header(&mut buf, &header);
        buf.extend_from_slice(&Ipv4Addr::new(255, 255, 255, 0).octets());
        buf.extend_from_slice(&(0x0000_0014u32 | 0xFF00_0000u32).to_be_bytes()); // metric=20, TOS byte set
        let checksum = lsa_checksum(&buf[2..]);
        buf[16..18].copy_from_slice(&checksum.to_be_bytes());

        let decoded = decode_lsa(&buf).unwrap();
        let LsaBody::Summary(s) = decoded.body else {
            panic!("expected summary lsa")
        };
        assert_eq!(s.metric, 20);
    }

    fn grace_lsa(body: GraceLsaBody) -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0,
                lsa_type: LSA_TYPE_OPAQUE_LINK,
                link_state_id: GRACE_LINK_STATE_ID,
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: INITIAL_SEQUENCE_NUMBER,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Grace(body),
        }
    }

    #[test]
    fn grace_lsa_round_trips() {
        for interface_address in [None, Some(Ipv4Addr::new(10, 0, 0, 1))] {
            let lsa = grace_lsa(GraceLsaBody {
                grace_period: 120,
                restart_reason: RESTART_REASON_SOFTWARE,
                interface_address,
            });
            assert_eq!(decode_lsa(&encode_lsa(&lsa)).unwrap().body, lsa.body);
        }
    }

    /// A hand-built RFC 3623 Appendix A body, not our own encoder's output:
    /// Grace Period 60, Restart Reason 1 (padded), an unknown TLV 99 that
    /// must be skipped, then IP Interface Address 192.0.2.1.
    #[test]
    fn grace_lsa_decodes_rfc_3623_wire_bytes() {
        let body: [u8; 32] = [
            0, 1, 0, 4, 0, 0, 0, 60, // grace period
            0, 2, 0, 1, 1, 0, 0, 0, // restart reason + 3 pad
            0, 99, 0, 2, 0xaa, 0xbb, 0, 0, // unknown, skipped
            0, 3, 0, 4, 192, 0, 2, 1, // ip interface address
        ];
        let header = LsaHeader {
            length: u16::try_from(LSA_HEADER_LEN + body.len()).unwrap(),
            ..grace_lsa(GraceLsaBody {
                grace_period: 0,
                restart_reason: 0,
                interface_address: None,
            })
            .header
        };
        let mut buf = Vec::new();
        encode_lsa_header(&mut buf, &header);
        buf.extend_from_slice(&body);
        let checksum = lsa_checksum(&buf[2..]);
        buf[16..18].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            decode_lsa(&buf).unwrap().body,
            LsaBody::Grace(GraceLsaBody {
                grace_period: 60,
                restart_reason: 1,
                interface_address: Some(Ipv4Addr::new(192, 0, 2, 1)),
            })
        );
        // Our encoder produces the very same bytes for the known TLVs.
        let ours = encode_lsa(&grace_lsa(GraceLsaBody {
            grace_period: 60,
            restart_reason: 1,
            interface_address: Some(Ipv4Addr::new(192, 0, 2, 1)),
        }));
        assert_eq!(&ours[LSA_HEADER_LEN..], [&body[..16], &body[24..]].concat());
    }

    /// Every other opaque type, at every scope, round-trips byte for byte —
    /// including a body length that is not a multiple of 4 and a checksum
    /// nos could not have produced itself.
    #[test]
    fn opaque_lsas_round_trip_as_raw_bytes() {
        for lsa_type in [
            LSA_TYPE_OPAQUE_LINK,
            LSA_TYPE_OPAQUE_AREA,
            LSA_TYPE_OPAQUE_AS,
        ] {
            let lsa = Lsa {
                header: LsaHeader {
                    lsa_type,
                    link_state_id: Ipv4Addr::new(4, 0, 0, 7),
                    ..router_lsa().header
                },
                body: LsaBody::Opaque(vec![0, 1, 0, 3, 0xde, 0xad, 0xbe]),
            };
            let wire = encode_lsa(&lsa);
            let decoded = decode_lsa(&wire).unwrap();
            assert_eq!(decoded.body, lsa.body);
            assert_eq!(opaque_type(decoded.header.link_state_id), 4);
            assert_eq!(encode_lsa(&decoded), wire);
        }
        assert!(is_link_local_scope(LSA_TYPE_OPAQUE_LINK));
        assert!(!is_link_local_scope(LSA_TYPE_OPAQUE_AREA));
        assert!(!is_opaque(LSA_TYPE_AS_EXTERNAL));
    }

    /// RFC 7770 §2.3/§2.4: TLV type 1, length 4, bit 0 the MSB.
    #[test]
    fn router_info_body_is_one_capabilities_tlv() {
        assert_eq!(
            encode_router_info(RI_CAP_GR_HELPER),
            [0, 1, 0, 4, 0x40, 0, 0, 0]
        );
        assert_eq!(
            encode_router_info(RI_CAP_GR_CAPABLE | RI_CAP_GR_HELPER),
            [0, 1, 0, 4, 0xc0, 0, 0, 0]
        );
        assert_eq!(ROUTER_INFO_LINK_STATE_ID, Ipv4Addr::new(4, 0, 0, 0));
    }

    /// RFC 7770: the capabilities TLV is found past an unknown one, in a
    /// type 10 or 11 RI; a truncated TLV, another opaque type or a non-opaque
    /// LSA yields `None`. RFC 8770's bit 7 is `1 << 24`.
    #[test]
    fn router_info_capabilities_decodes_type_10_and_11() {
        let ri = |lsa_type, id: Ipv4Addr, body: Vec<u8>| Lsa {
            header: LsaHeader {
                lsa_type,
                link_state_id: id,
                ..router_lsa().header
            },
            body: LsaBody::Opaque(body),
        };
        let caps = RI_CAP_HOST_ROUTER | RI_CAP_GR_HELPER;
        let mut body = vec![0, 9, 0, 3, 1, 2, 3, 0];
        body.extend(encode_router_info(caps));
        for t in [LSA_TYPE_OPAQUE_AREA, LSA_TYPE_OPAQUE_AS] {
            let lsa = ri(t, ROUTER_INFO_LINK_STATE_ID, body.clone());
            assert_eq!(router_info_capabilities(&lsa), Some(caps));
        }
        assert_eq!(encode_router_info(RI_CAP_HOST_ROUTER)[4], 0x01);
        let truncated = ri(
            LSA_TYPE_OPAQUE_AREA,
            ROUTER_INFO_LINK_STATE_ID,
            vec![0, 1, 0, 4, 0],
        );
        assert_eq!(router_info_capabilities(&truncated), None);
        let other = ri(
            LSA_TYPE_OPAQUE_AREA,
            Ipv4Addr::new(8, 0, 0, 0),
            body.clone(),
        );
        assert_eq!(router_info_capabilities(&other), None);
        let link = ri(LSA_TYPE_OPAQUE_LINK, ROUTER_INFO_LINK_STATE_ID, body);
        assert_eq!(router_info_capabilities(&link), None);
        assert_eq!(router_info_capabilities(&router_lsa()), None);
    }

    #[test]
    fn higher_sequence_number_is_newer() {
        let a = router_lsa().header;
        let mut b = a;
        b.sequence_number += 1;
        assert_eq!(is_newer(&b, &a), Ordering::Greater);
        assert_eq!(is_newer(&a, &b), Ordering::Less);
    }

    #[test]
    fn equal_sequence_number_falls_back_to_checksum() {
        let a = router_lsa().header;
        let mut b = a;
        b.checksum += 1;
        assert_eq!(is_newer(&b, &a), Ordering::Greater);
    }

    #[test]
    fn max_age_is_always_newer_when_seq_and_checksum_tie() {
        let a = router_lsa().header;
        let mut b = a;
        b.age = MAX_AGE;
        assert_eq!(is_newer(&b, &a), Ordering::Greater);
        assert_eq!(is_newer(&a, &b), Ordering::Less);
    }

    #[test]
    fn identical_headers_are_equal() {
        let a = router_lsa().header;
        assert_eq!(is_newer(&a, &a), Ordering::Equal);
    }

    // ---- Known-answer checksums (#357) ----
    //
    // Each vector is a complete wire LSA whose checksum was produced by an
    // oracle that shares nothing with `lsa_checksum`: a throwaway script
    // that searches for the two check bytes (non-zero, RFC 905 Annex B)
    // making the *verification* running sums `(C0, C1)` over everything
    // after `age` come out `(0, 0)`. Per body kind, the seq number picks a
    // body whose `x = ((len-15)*C0 - C1) % 255` is positive / negative /
    // exactly zero (the `x <= 0` branch), and whose `y = 510 - C0 - x` is
    // exactly 255 (the `y > 255` boundary). `*_x_zero` have a 0xff check
    // byte, not 0x00, and `*_y_255` an `0xff` second byte, which a `<=`/`>=`
    // slip turns into `0x00`.
    // ponytail: hand-built vectors only; a real FRR/BIRD capture can be
    // appended as another row (needs a lab capture + provenance note).
    const KNOWN_ANSWERS: &[(&str, &str, u16)] = &[
        ("router_x_pos", "0001020101010101010101018000000199790030000000020a000001ffffff000300000a020202020a00010101000001", 0x9979),
        ("router_x_neg", "00010201010101010101010180000014738c0030000000020a000001ffffff000300000a020202020a00010101000001", 0x738c),
        ("router_x_zero", "000102010101010101010101800000cdff460030000000020a000001ffffff000300000a020202020a00010101000001", 0xff46),
        ("router_y_255", "000102010101010101010101800000878cff0030000000020a000001ffffff000300000a020202020a00010101000001", 0x8cff),
        ("network_x_pos", "000102020a00000101010101800000015de10020ffffff000101010102020202", 0x5de1),
        ("network_x_neg", "000102020a0000010101010180000040de210020ffffff000101010102020202", 0xde21),
        ("network_x_zero", "000102020a00000101010101800000afff900020ffffff000101010102020202", 0xff90),
        ("network_y_255", "000102020a000001010101018000001f21ff0020ffffff000101010102020202", 0x21ff),
        ("external_x_pos", "00010205c00002000101010180000002ab4b0024ffffff00800000140000000000000000", 0xab4b),
        ("external_x_neg", "00010205c00002000101010180000001ad4a0024ffffff00800000140000000000000000", 0xad4a),
        ("external_x_zero", "00010205c000020001010101800000d7ff210024ffffff00800000140000000000000000", 0xff21),
        ("external_y_255", "00010205c000020001010101800000b642ff0024ffffff00800000140000000000000000", 0x42ff),
        ("router_40_links_x_pos", "0001020103030303030303038000000108c001f8000000280a000001ffffff00030000010a010001ffffff00030000020a020001ffffff00030000030a030001ffffff00030000040a040001ffffff00030000050a050001ffffff00030000060a060001ffffff00030000070a070001ffffff00030000080a080001ffffff00030000090a090001ffffff000300000a0a0a0001ffffff000300000b0a0b0001ffffff000300000c0a0c0001ffffff000300000d0a0d0001ffffff000300000e0a0e0001ffffff000300000f0a0f0001ffffff00030000100a100001ffffff00030000110a110001ffffff00030000120a120001ffffff00030000130a130001ffffff00030000140a140001ffffff00030000150a150001ffffff00030000160a160001ffffff00030000170a170001ffffff00030000180a180001ffffff00030000190a190001ffffff000300001a0a1a0001ffffff000300001b0a1b0001ffffff000300001c0a1c0001ffffff000300001d0a1d0001ffffff000300001e0a1e0001ffffff000300001f0a1f0001ffffff00030000200a200001ffffff00030000210a210001ffffff00030000220a220001ffffff00030000230a230001ffffff00030000240a240001ffffff00030000250a250001ffffff00030000260a260001ffffff00030000270a270001ffffff0003000028", 0x08c0),
        ("router_40_links_x_neg", "000102010303030303030303800000c9768901f8000000280a000001ffffff00030000010a010001ffffff00030000020a020001ffffff00030000030a030001ffffff00030000040a040001ffffff00030000050a050001ffffff00030000060a060001ffffff00030000070a070001ffffff00030000080a080001ffffff00030000090a090001ffffff000300000a0a0a0001ffffff000300000b0a0b0001ffffff000300000c0a0c0001ffffff000300000d0a0d0001ffffff000300000e0a0e0001ffffff000300000f0a0f0001ffffff00030000100a100001ffffff00030000110a110001ffffff00030000120a120001ffffff00030000130a130001ffffff00030000140a140001ffffff00030000150a150001ffffff00030000160a160001ffffff00030000170a170001ffffff00030000180a180001ffffff00030000190a190001ffffff000300001a0a1a0001ffffff000300001b0a1b0001ffffff000300001c0a1c0001ffffff000300001d0a1d0001ffffff000300001e0a1e0001ffffff000300001f0a1f0001ffffff00030000200a200001ffffff00030000210a210001ffffff00030000220a220001ffffff00030000230a230001ffffff00030000240a240001ffffff00030000250a250001ffffff00030000260a260001ffffff00030000270a270001ffffff0003000028", 0x7689),
        ("router_40_links_x_zero", "00010201030303030303030380000005ffc401f8000000280a000001ffffff00030000010a010001ffffff00030000020a020001ffffff00030000030a030001ffffff00030000040a040001ffffff00030000050a050001ffffff00030000060a060001ffffff00030000070a070001ffffff00030000080a080001ffffff00030000090a090001ffffff000300000a0a0a0001ffffff000300000b0a0b0001ffffff000300000c0a0c0001ffffff000300000d0a0d0001ffffff000300000e0a0e0001ffffff000300000f0a0f0001ffffff00030000100a100001ffffff00030000110a110001ffffff00030000120a120001ffffff00030000130a130001ffffff00030000140a140001ffffff00030000150a150001ffffff00030000160a160001ffffff00030000170a170001ffffff00030000180a180001ffffff00030000190a190001ffffff000300001a0a1a0001ffffff000300001b0a1b0001ffffff000300001c0a1c0001ffffff000300001d0a1d0001ffffff000300001e0a1e0001ffffff000300001f0a1f0001ffffff00030000200a200001ffffff00030000210a210001ffffff00030000220a220001ffffff00030000230a230001ffffff00030000240a240001ffffff00030000250a250001ffffff00030000260a260001ffffff00030000270a270001ffffff0003000028", 0xffc4),
        ("router_40_links_y_255", "0001020103030303030303038000004089ff01f8000000280a000001ffffff00030000010a010001ffffff00030000020a020001ffffff00030000030a030001ffffff00030000040a040001ffffff00030000050a050001ffffff00030000060a060001ffffff00030000070a070001ffffff00030000080a080001ffffff00030000090a090001ffffff000300000a0a0a0001ffffff000300000b0a0b0001ffffff000300000c0a0c0001ffffff000300000d0a0d0001ffffff000300000e0a0e0001ffffff000300000f0a0f0001ffffff00030000100a100001ffffff00030000110a110001ffffff00030000120a120001ffffff00030000130a130001ffffff00030000140a140001ffffff00030000150a150001ffffff00030000160a160001ffffff00030000170a170001ffffff00030000180a180001ffffff00030000190a190001ffffff000300001a0a1a0001ffffff000300001b0a1b0001ffffff000300001c0a1c0001ffffff000300001d0a1d0001ffffff000300001e0a1e0001ffffff000300001f0a1f0001ffffff00030000200a200001ffffff00030000210a210001ffffff00030000220a220001ffffff00030000230a230001ffffff00030000240a240001ffffff00030000250a250001ffffff00030000260a260001ffffff00030000270a270001ffffff0003000028", 0x89ff),
    ];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 905 Annex B *verification*: running sums over every byte after
    /// `age`, checksum field included, both `mod 255`; zero iff the LSA is
    /// valid. A different formulation from `lsa_checksum` (which generates).
    fn fletcher_residue(wire: &[u8]) -> (u32, u32) {
        let (mut c0, mut c1) = (0u32, 0u32);
        for &b in &wire[2..] {
            c0 = (c0 + u32::from(b)) % 255;
            c1 = (c1 + c0) % 255;
        }
        (c0, c1)
    }

    #[test]
    fn known_answer_checksums_decode_and_re_encode_byte_for_byte() {
        for (name, hex, checksum) in KNOWN_ANSWERS {
            let wire = unhex(hex);
            assert_eq!(fletcher_residue(&wire), (0, 0), "{name}: bad vector");
            let lsa = decode_lsa(&wire).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(lsa.header.checksum, *checksum, "{name}");
            assert_eq!(usize::from(lsa.header.length), wire.len(), "{name}");
            assert_eq!(encode_lsa(&lsa), wire, "{name}");
        }
    }

    #[test]
    fn known_answer_lsa_with_one_flipped_byte_is_rejected() {
        for (name, hex, _) in KNOWN_ANSWERS {
            let wire = unhex(hex);
            // Every position after `age`, so an off-by-one in the summed
            // range or the checksum-field skip cannot hide.
            for at in 2..wire.len() {
                let mut bad = wire.clone();
                bad[at] ^= 0x01;
                let r = decode_lsa(&bad);
                if (16..18).contains(&at) {
                    assert_eq!(r, Err(PacketError::BadChecksum), "{name} @{at}");
                } else if (18..20).contains(&at) {
                    // Length: the checksum covers it, but a shorter value
                    // may be rejected as truncated first.
                    assert!(r.is_err(), "{name} @{at}");
                } else {
                    assert_eq!(r, Err(PacketError::BadChecksum), "{name} @{at}");
                }
            }
        }
    }

    /// The origination path: a locally built LSA gets exactly the known
    /// checksum and length from `fill_checksum`, and its encoding verifies.
    #[test]
    fn fill_checksum_stores_the_known_answer() {
        for (name, hex, checksum) in KNOWN_ANSWERS {
            let wire = unhex(hex);
            let mut lsa = decode_lsa(&wire).unwrap();
            lsa.header.checksum = 0;
            lsa.header.length = 0;
            fill_checksum(&mut lsa);
            assert_eq!(lsa.header.checksum, *checksum, "{name}");
            assert_eq!(usize::from(lsa.header.length), wire.len(), "{name}");
            assert_eq!(fletcher_residue(&encode_lsa(&lsa)), (0, 0), "{name}");
        }
    }

    /// `decode_lsa` uses the header's `length`, not the buffer's, so a
    /// trailing LSA in an LSU does not enter the checksum.
    #[test]
    fn checksum_ignores_bytes_after_the_lsa() {
        let (_, hex, checksum) = KNOWN_ANSWERS[0];
        let mut wire = unhex(hex);
        wire.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode_lsa(&wire).unwrap().header.checksum, checksum);
    }

    fn te_lsa(id: Ipv4Addr, body: Vec<u8>) -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                options: 0x20,
                lsa_type: LSA_TYPE_OPAQUE_AREA,
                link_state_id: id,
                advertising_router: Ipv4Addr::new(1, 1, 1, 1),
                sequence_number: i32::MIN + 1,
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Opaque(body),
        }
    }

    fn te_link() -> TeLink {
        TeLink {
            link_type: TE_LINK_POINT_TO_POINT,
            link_id: Ipv4Addr::new(2, 2, 2, 2),
            local_addr: Ipv4Addr::new(10, 0, 0, 1),
            remote_addr: Some(Ipv4Addr::new(10, 0, 0, 2)),
            metric: 10,
            max_bandwidth: 125_000_000.0,
            max_reservable: 100_000_000.0,
            unreserved: [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0],
            admin_group: 0xa5,
        }
    }

    #[test]
    fn te_router_address_and_link_round_trip() {
        let a = Ipv4Addr::new(192, 0, 2, 1);
        let lsa = te_lsa(TE_ROUTER_ADDRESS_LINK_STATE_ID, encode_te_router_address(a));
        assert_eq!(decode_te(&lsa), Some(TeBody::RouterAddress(a)));
        assert_eq!(opaque_type(te_link_state_id(0x0102_0304)), OPAQUE_TYPE_TE);
        assert_eq!(te_link_state_id(0x0002_0304), Ipv4Addr::new(1, 2, 3, 4));
        for remote in [Some(Ipv4Addr::new(10, 0, 0, 2)), None] {
            let l = TeLink {
                remote_addr: remote,
                ..te_link()
            };
            let lsa = te_lsa(te_link_state_id(1), encode_te_link(&l));
            assert_eq!(decode_te(&lsa), Some(TeBody::Link(l)));
        }
    }

    /// A sub-TLV this router doesn't know is skipped, the known ones still
    /// decode; a truncated body, a missing mandatory sub-TLV, another opaque
    /// type or scope decode to nothing.
    #[test]
    fn te_decode_skips_unknown_and_rejects_malformed() {
        let mut sub = Vec::new();
        put_tlv(&mut sub, 0x7000, &[1, 2, 3]);
        put_tlv(&mut sub, TE_LINK_TYPE, &[TE_LINK_MULTI_ACCESS]);
        put_tlv(&mut sub, TE_LINK_ID, &[9, 9, 9, 9]);
        let mut body = Vec::new();
        put_tlv(&mut body, 0x7001, &[0; 4]);
        put_tlv(&mut body, TLV_TE_LINK, &sub);
        let lsa = te_lsa(te_link_state_id(1), body);
        let Some(TeBody::Link(l)) = decode_te(&lsa) else {
            panic!("link expected")
        };
        assert_eq!(
            (l.link_type, l.link_id, l.metric),
            (2, Ipv4Addr::new(9, 9, 9, 9), 0)
        );
        assert_eq!(l.remote_addr, None);

        let good = encode_te_router_address(Ipv4Addr::LOCALHOST);
        assert_eq!(
            decode_te(&te_lsa(te_link_state_id(1), good[..6].to_vec())),
            None
        );
        let mut no_id = Vec::new();
        let mut s2 = Vec::new();
        put_tlv(&mut s2, TE_LINK_TYPE, &[1]);
        put_tlv(&mut no_id, TLV_TE_LINK, &s2);
        assert_eq!(decode_te(&te_lsa(te_link_state_id(1), no_id)), None);
        let mut other = te_lsa(Ipv4Addr::new(4, 0, 0, 0), good);
        assert_eq!(decode_te(&other), None);
        other.header.link_state_id = TE_ROUTER_ADDRESS_LINK_STATE_ID;
        other.header.lsa_type = LSA_TYPE_OPAQUE_LINK;
        assert_eq!(decode_te(&other), None);
        other.header.lsa_type = LSA_TYPE_OPAQUE_AREA;
        other.body = LsaBody::Opaque(Vec::new());
        assert_eq!(decode_te(&other), None);
    }

    fn ext_prefix() -> ExtendedPrefix {
        let mut sub = Vec::new();
        put_tlv(&mut sub, 0x7777, &[1, 2, 3]);
        ExtendedPrefix {
            route_type: EXT_ROUTE_INTRA_AREA,
            prefix: Ipv4Addr::new(192, 0, 2, 1),
            prefix_len: 32,
            flags: EXT_PREFIX_FLAG_N,
            sub_tlvs: sub,
        }
    }

    /// RFC 7684 §2.1/§3.1: both TLVs round-trip, unknown sub-TLV bytes kept
    /// verbatim; a /0 carries no address octets.
    #[test]
    fn extended_prefix_and_link_round_trip_keeping_unknown_sub_tlvs() {
        let p = ext_prefix();
        let id = ext_state_id(OPAQUE_TYPE_EXT_PREFIX, 3);
        assert_eq!(id, Ipv4Addr::new(7, 0, 0, 3));
        let lsa = te_lsa(id, encode_extended_prefix(&p));
        assert_eq!(decode_extended_prefix(&lsa), Some(p.clone()));
        let default = ExtendedPrefix {
            prefix: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
            sub_tlvs: Vec::new(),
            ..p
        };
        let body = encode_extended_prefix(&default);
        assert_eq!(body.len(), 8);
        assert_eq!(decode_extended_prefix(&te_lsa(id, body)), Some(default));

        let l = ExtendedLink {
            link_type: LINK_TYPE_POINT_TO_POINT,
            link_id: Ipv4Addr::new(2, 2, 2, 2),
            link_data: Ipv4Addr::new(10, 0, 0, 1),
            sub_tlvs: ext_prefix().sub_tlvs,
        };
        let id = ext_state_id(OPAQUE_TYPE_EXT_LINK, 1);
        let lsa = te_lsa(id, encode_extended_link(&l));
        assert_eq!(decode_extended_link(&lsa), Some(l));
        // The wrong decoder never reads the other type.
        assert_eq!(decode_extended_prefix(&lsa), None);
    }

    #[test]
    fn extended_decode_rejects_malformed() {
        let id = ext_state_id(OPAQUE_TYPE_EXT_PREFIX, 1);
        let good = encode_extended_prefix(&ext_prefix());
        let tlv = |v: &[u8]| {
            let mut b = Vec::new();
            put_tlv(&mut b, TLV_EXT_PREFIX, v);
            te_lsa(id, b)
        };
        // Truncations at every length never panic.
        for n in 0..good.len() {
            let _ = decode_extended_prefix(&te_lsa(id, good[..n].to_vec()));
        }
        assert_eq!(decode_extended_prefix(&tlv(&[1, 32, 0])), None);
        assert_eq!(decode_extended_prefix(&tlv(&[1, 32, 0, 0, 1, 2])), None);
        assert_eq!(
            decode_extended_prefix(&tlv(&[1, 33, 0, 0, 1, 2, 3, 4])),
            None
        );
        assert_eq!(
            decode_extended_prefix(&tlv(&[1, 32, 1, 0, 1, 2, 3, 4])),
            None
        );
        // A sub-TLV that overruns the value.
        assert_eq!(
            decode_extended_prefix(&tlv(&[1, 32, 0, 0, 1, 2, 3, 4, 0, 1, 0, 9])),
            None
        );
        let lid = ext_state_id(OPAQUE_TYPE_EXT_LINK, 1);
        let mut b = Vec::new();
        put_tlv(&mut b, TLV_EXT_LINK, &[1, 0, 0, 0, 1, 1, 1, 1]);
        assert_eq!(decode_extended_link(&te_lsa(lid, b)), None);
        assert_eq!(decode_extended_link(&te_lsa(lid, Vec::new())), None);
        let mut area = te_lsa(id, good);
        area.header.lsa_type = LSA_TYPE_OPAQUE_AS;
        assert_eq!(decode_extended_prefix(&area), None);
    }

    #[test]
    fn sr_tlvs_round_trip() {
        let body = encode_router_info_sr(RI_CAP_GR_HELPER, Some((16000, 8000)));
        let lsa = te_lsa(ROUTER_INFO_LINK_STATE_ID, body);
        assert_eq!(router_info_capabilities(&lsa), Some(RI_CAP_GR_HELPER));
        assert_eq!(
            decode_router_info_sr(&lsa),
            Some(RouterInfoSr {
                algorithms: vec![0],
                srgb: vec![(16000, 8000)]
            })
        );
        let plain = te_lsa(ROUTER_INFO_LINK_STATE_ID, encode_router_info_sr(1, None));
        assert_eq!(decode_router_info_sr(&plain), None);
        let other = te_lsa(ext_state_id(OPAQUE_TYPE_TE, 1), Vec::new());
        assert_eq!(decode_router_info_sr(&other), None);
        // Truncations never panic.
        let full = encode_router_info_sr(1, Some((16000, 8000)));
        for n in 0..full.len() {
            let _ = decode_router_info_sr(&te_lsa(ROUTER_INFO_LINK_STATE_ID, full[..n].to_vec()));
        }
    }

    #[test]
    fn prefix_sid_round_trips_inside_an_extended_prefix() {
        let sub = encode_prefix_sid(7, true, true);
        assert_eq!(sub.len(), 12);
        let sid = decode_prefix_sid(&sub).unwrap();
        assert_eq!(sid.value, 7);
        assert!(!sid.absolute);
        assert_eq!(sid.flags, PREFIX_SID_FLAG_NP | PREFIX_SID_FLAG_E);
        assert_eq!(sid.algorithm, SR_ALGO_SPF);
        let p = ExtendedPrefix {
            sub_tlvs: sub,
            ..ext_prefix()
        };
        let lsa = te_lsa(
            ext_state_id(OPAQUE_TYPE_EXT_PREFIX, 1),
            encode_extended_prefix(&p),
        );
        let got = decode_extended_prefix(&lsa).unwrap();
        assert_eq!(decode_prefix_sid(&got.sub_tlvs), Some(sid));
        assert_eq!(decode_prefix_sid(&ext_prefix().sub_tlvs), None);
        // An absolute (label) SID, and a short one.
        let mut abs = Vec::new();
        put_tlv(&mut abs, SUB_PREFIX_SID, &[0x0c, 0, 0, 0, 0x03, 0xe8, 0x80]);
        let s = decode_prefix_sid(&abs).unwrap();
        assert_eq!((s.absolute, s.value), (true, 0x3_e880 & 0xF_FFFF));
        let mut short = Vec::new();
        put_tlv(&mut short, SUB_PREFIX_SID, &[0, 0, 0, 0, 1]);
        assert_eq!(decode_prefix_sid(&short), None);
    }

    #[test]
    fn adj_sids_round_trip() {
        let mut run = encode_adj_sid(24001, 0, false, None);
        run.extend(encode_adj_sid(
            24002,
            3,
            true,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
        ));
        let got = decode_adj_sids(&run);
        assert_eq!(got.len(), 2);
        assert_eq!(
            (got[0].value, got[0].absolute, got[0].neighbor),
            (24001, true, None)
        );
        assert_eq!(got[1].neighbor, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(
            (got[1].weight, got[1].flags & ADJ_SID_FLAG_B),
            (3, ADJ_SID_FLAG_B)
        );
        // Wrong lengths are skipped, never panic.
        let mut bad = Vec::new();
        put_tlv(&mut bad, SUB_ADJ_SID, &[0x60, 0, 0, 0, 1]);
        put_tlv(&mut bad, SUB_LAN_ADJ_SID, &[0x60, 0, 0, 0, 1]);
        put_tlv(&mut bad, SUB_ADJ_SID, &[0x00, 0, 0, 0, 0, 0, 1]);
        assert_eq!(decode_adj_sids(&bad).len(), 0);
        assert_eq!(decode_adj_sids(&[0, 2, 0, 9]).len(), 0);
    }
}
