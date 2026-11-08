//! RFC 5340 Link State Advertisements — the header shared by every LSA type
//! (§A.4.2.1) plus the four bodies needed for Phase 1 single-area intra-area
//! routing: Router-LSA (§A.4.3), Network-LSA (§A.4.4), Link-LSA (§A.4.9), and
//! Intra-Area-Prefix-LSA (§A.4.10). Pure encode/decode, no I/O, same style as
//! `ospf::lsa` (RFC 2328's counterpart) — but the two crates' body shapes
//! diverge completely: v3 restructures prefix-carrying entirely out of
//! Router-/Network-LSA (which in v3 carry pure topology, no addresses at
//! all) and into the two new LSA types here. ABR/ASBR add Inter-Area-
//! Prefix-LSA (§A.4.5), Inter-Area-Router-LSA (§A.4.6) and AS-External-LSA
//! (§A.4.7). Out of scope: NSSA.
//!
//! The 20-byte common header (§A.4.2.1) is the same total length as v2's,
//! but its shape differs: v3 has no separate `options` byte in the header at
//! all (each body carries its own `Options` field instead) and widens the
//! 8-bit type byte into a 16-bit `LS Type` word carrying the U-bit (flood-
//! if-unknown), the S2/S1 scope bits, and a 13-bit function code — see the
//! `LSA_TYPE_*` constants' doc comments for the bit layout. The header's
//! Fletcher-16 checksum (RFC 905 Annex B, `lsa_checksum`) and freshness
//! tie-break (`is_newer`) are otherwise byte-for-byte identical to v2's,
//! since RFC 5340 keeps RFC 2328 §13.1's LSA-header semantics unchanged —
//! ported verbatim rather than reimplemented.

use std::cmp::Ordering;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::Ipv6Net;

use crate::packet::{read_ipv4, PacketError};

/// RFC 5340 §A.4.2.1's Options bits, shared by Router-/Network-/Link-LSA
/// bodies (Intra-Area-Prefix-LSA has none). `V6` must always be set (this
/// router participates in IPv6 topology); `R` must always be set on
/// self-origination (clearing it silently excludes this router from other
/// routers' SPF — RFC 5340 §4.8.1 — a real correctness trap if forgotten).
/// `E` (§A.2: AS-external-LSAs are flooded here) is set on every
/// self-originated Options word, since every area is a normal area (no stub
/// areas or NSSA in `OSPFv3` yet).
pub const OPTION_V6: u32 = 0x01;
pub const OPTION_E: u32 = 0x02;
pub const OPTION_R: u32 = 0x10;
/// RFC 7166 §2.1/§7 (IANA "`OSPFv3` Options (24 bits)"): every packet on this
/// link carries an authentication trailer. Set only in Hello/DBD; LSR/LSU/
/// `LSAck` have no Options field and inherit it from the link's config.
pub const OPTION_AT: u32 = 0x00_0400;

/// S2/S1 scope bits (bits 14-13): `01` = area scope. The U-bit (bit 15,
/// "flood even if unrecognized") is left clear on the RFC 5340 `LSA_TYPE_*`
/// constants below — every type this crate ever originates or requests is
/// known, so it never needs setting — and set on the RFC 8362 ones, per
/// that RFC.
const SCOPE_AREA: u16 = 0x2000;
/// S2/S1 scope bits: `00` = link-local scope.
const SCOPE_LINK_LOCAL: u16 = 0x0000;
/// S2/S1 scope bits: `10` = AS scope (flooded through every area).
const SCOPE_AS: u16 = 0x4000;

/// RFC 5340 §A.4.2.1 U-bit: "store and flood the LSA as if type understood".
const U_BIT: u16 = 0x8000;
/// Mask of the S2/S1 bits.
const SCOPE_MASK: u16 = SCOPE_AREA | SCOPE_AS;

/// RFC 5340 §A.4.2.1 S2/S1 `11`: "reserved". RFC 5340 §4.5 step (3) (LSU
/// receipt) discards such an LSA.
pub fn is_reserved_scope(lsa_type: u16) -> bool {
    lsa_type & SCOPE_MASK == SCOPE_MASK
}

/// RFC 5340 §2.9 / §4.5.1: the LSA's flooding scope as the router must treat
/// it. A recognized type, or an unrecognized one with the U-bit set, uses
/// its S2/S1 bits; an unrecognized type with the U-bit clear is treated as
/// link-local (never leaves the link it arrived on).
fn effective_scope(lsa_type: u16) -> u16 {
    if !is_known_type(lsa_type) && lsa_type & U_BIT == 0 {
        SCOPE_LINK_LOCAL
    } else {
        lsa_type & SCOPE_MASK
    }
}

/// RFC 5340 §4.5.1: whether `lsa_type`'s effective scope is AS — such an
/// LSA lives in `link.rs`'s one AS-wide store, not an area's.
pub fn is_as_scope(lsa_type: u16) -> bool {
    effective_scope(lsa_type) == SCOPE_AS
}

/// RFC 5340 §4.5.1 / §A.4.2.1: whether `lsa_type`'s effective scope is
/// link-local — such an LSA lives in its link's own store and is never
/// flooded past that link (`link.rs`'s per-link `Lsdb`). Includes
/// unrecognized types with the U-bit clear (§2.9).
pub fn is_link_local_scope(lsa_type: u16) -> bool {
    effective_scope(lsa_type) == SCOPE_LINK_LOCAL
}

/// Whether this crate understands `lsa_type` (RFC 5340, RFC 5187, RFC 8362).
/// Anything else decodes to `LsaBody::Opaque`: stored and flooded per
/// `effective_scope`, never used by SPF.
pub fn is_known_type(lsa_type: u16) -> bool {
    is_extended(lsa_type)
        || matches!(
            lsa_type,
            LSA_TYPE_ROUTER
                | LSA_TYPE_NETWORK
                | LSA_TYPE_INTER_AREA_PREFIX
                | LSA_TYPE_INTER_AREA_ROUTER
                | LSA_TYPE_AS_EXTERNAL
                | LSA_TYPE_LINK
                | LSA_TYPE_INTRA_AREA_PREFIX
                | LSA_TYPE_GRACE
        )
}

/// RFC 5340 §A.4.3 Router-LSA — area-scoped, function code 1.
pub const LSA_TYPE_ROUTER: u16 = SCOPE_AREA | 1;
/// RFC 5340 §A.4.4 Network-LSA — area-scoped, function code 2.
pub const LSA_TYPE_NETWORK: u16 = SCOPE_AREA | 2;
/// RFC 5340 §A.4.5 Inter-Area-Prefix-LSA — area-scoped, function code 3.
pub const LSA_TYPE_INTER_AREA_PREFIX: u16 = SCOPE_AREA | 3;
/// RFC 5340 §A.4.6 Inter-Area-Router-LSA — area-scoped, function code 4.
pub const LSA_TYPE_INTER_AREA_ROUTER: u16 = SCOPE_AREA | 4;
/// RFC 5340 §A.4.7 AS-External-LSA — AS-scoped, function code 5.
pub const LSA_TYPE_AS_EXTERNAL: u16 = SCOPE_AS | 5;
/// RFC 5340 §A.4.3 Router-LSA flags: B (area border router) and E (AS
/// boundary router).
pub const ROUTER_FLAG_B: u8 = 0x01;
pub const ROUTER_FLAG_E: u8 = 0x02;
/// RFC 5340 §A.4.1.1 `PrefixOptions`: NU (no unicast: not used in routing
/// calculations), LA (local address: a host address of the originator),
/// P (propagate, NSSA) and DN (down, PE-CE). Only NU is honoured on
/// receipt and only LA is originated; P/DN are never set.
pub const PREFIX_OPT_NU: u8 = 0x01;
pub const PREFIX_OPT_LA: u8 = 0x02;
pub const PREFIX_OPT_P: u8 = 0x08;
pub const PREFIX_OPT_DN: u8 = 0x10;
/// RFC 5340 §A.4.7 AS-External-LSA flag bits (first byte).
const EXTERNAL_FLAG_E: u8 = 0x04;
const EXTERNAL_FLAG_F: u8 = 0x02;
const EXTERNAL_FLAG_T: u8 = 0x01;
/// RFC 5340 §A.4.9 Link-LSA — link-local scoped (never flooded past the
/// originating link), function code 8.
pub const LSA_TYPE_LINK: u16 = SCOPE_LINK_LOCAL | 8;
/// RFC 5340 §A.4.10 Intra-Area-Prefix-LSA — area-scoped, function code 9.
pub const LSA_TYPE_INTRA_AREA_PREFIX: u16 = SCOPE_AREA | 9;
/// RFC 5187 §2 Grace-LSA — link-local scoped, function code 11. Link State
/// ID is the originating interface's Interface ID.
pub const LSA_TYPE_GRACE: u16 = SCOPE_LINK_LOCAL | 0x0B;
/// RFC 3623 Appendix A's Grace-LSA TLVs (reused unchanged by RFC 5187; the
/// IP-interface-address TLV is not used in `OSPFv3`).
const TLV_GRACE_PERIOD: u16 = 1;
const TLV_RESTART_REASON: u16 = 2;
/// RFC 3623 Appendix A: restart reason 1, "software restart".
pub const RESTART_REASON_SOFTWARE: u8 = 1;

/// RFC 8362 §3.1's extended LSAs (TLV bodies) — same information as the four
/// legacy types above, so they decode into the very same `LsaBody` variants
/// and only the wire encoding (chosen by the header's LS type) differs. The
/// U-bit is set on all four (§3.1) so a router that doesn't know them still
/// floods them; E-Link stays link-local scoped.
pub const LSA_TYPE_E_ROUTER: u16 = 0x8000 | SCOPE_AREA | 0x21;
pub const LSA_TYPE_E_NETWORK: u16 = 0x8000 | SCOPE_AREA | 0x22;
pub const LSA_TYPE_E_LINK: u16 = 0x8000 | SCOPE_LINK_LOCAL | 0x28;
pub const LSA_TYPE_E_INTRA_AREA_PREFIX: u16 = 0x8000 | SCOPE_AREA | 0x29;
/// RFC 8362 §4.5-4.7: the inter-area and AS-external E-LSAs. Their bodies are
/// TLVs only (no fixed part), one top-level TLV each.
pub const LSA_TYPE_E_INTER_AREA_PREFIX: u16 = 0x8000 | SCOPE_AREA | 0x23;
pub const LSA_TYPE_E_INTER_AREA_ROUTER: u16 = 0x8000 | SCOPE_AREA | 0x24;
pub const LSA_TYPE_E_AS_EXTERNAL: u16 = 0x8000 | SCOPE_AS | 0x25;

/// RFC 8362 §3.2's top-level TLV types (the only ones this crate uses).
const TLV_ROUTER_LINK: u16 = 1;
const TLV_ATTACHED_ROUTERS: u16 = 2;
const TLV_INTER_AREA_PREFIX: u16 = 3;
const TLV_INTER_AREA_ROUTER: u16 = 4;
const TLV_EXTERNAL_PREFIX: u16 = 5;
/// RFC 8362 §3.10's External-Prefix sub-TLVs (the IPv4 forwarding address,
/// type 2, is never decoded: IPv6-only routing).
const SUB_TLV_IPV6_FORWARDING_ADDRESS: u16 = 1;
const SUB_TLV_ROUTE_TAG: u16 = 3;
const TLV_INTRA_AREA_PREFIX: u16 = 6;
const TLV_IPV6_LINK_LOCAL: u16 = 7;

/// RFC 5340 §4.4.3.2's Router-LSA link types — identical values to
/// `OSPFv2`'s (RFC 5340 §A.4.3: "Values as in [OSPFV2]"). No stub-network
/// type in v3: a Router-LSA link never carries a prefix at all.
pub const LINK_TYPE_POINT_TO_POINT: u8 = 1;
pub const LINK_TYPE_TRANSIT_NETWORK: u8 = 2;

pub const LSA_HEADER_LEN: usize = 20;
/// One Router-LSA link entry's wire length (§A.4.3): Type(1) + Reserved(1) +
/// Metric(2) + Interface ID(4) + Neighbor Interface ID(4) + Neighbor Router
/// ID(4).
const ROUTER_LINK_LEN: usize = 16;

/// RFC 2328 §13.1's `MaxAge` (seconds, unchanged by RFC 5340) — an LSA at
/// this age is being flushed and, per §13.1's tie-break, always treated as
/// the newer instance.
pub use nos_ospf_common::lsa::MAX_AGE;

/// RFC 2328 §14's `LSRefreshTime` (seconds, unchanged by RFC 5340) — a
/// self-originated LSA is reoriginated once its own age reaches this, even
/// with unchanged content, so it never reaches `MAX_AGE` while its
/// originator is still alive.
pub const LS_REFRESH_TIME: u16 = 1800;

/// RFC 2328 §12.1.6's `InitialSequenceNumber` (unchanged by RFC 5340) —
/// every self-originated LSA starts here and increments by one on each
/// refresh.
pub const INITIAL_SEQUENCE_NUMBER: i32 = i32::MIN + 1;

/// RFC 2328 §12.1.6's `MaxSequenceNumber` — an LSA that reaches it must be
/// flushed (prematurely aged) before being re-originated at
/// `INITIAL_SEQUENCE_NUMBER`; `0x8000_0000` in between is reserved and must
/// never be produced (see `link::install_self_originated`).
pub const MAX_SEQUENCE_NUMBER: i32 = i32::MAX;

/// Identifies one LSA instance's slot in the database, independent of its
/// sequence number/age/checksum — RFC 5340 keeps RFC 2328 §12.2's keying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LsaKey {
    pub lsa_type: u16,
    /// An opaque 32-bit value, never a real address — for Router-/Network-
    /// LSA it's the DR's Interface ID (Network-LSA) or unused (Router-LSA,
    /// conventionally the originating router's own id repeated); for
    /// Link-LSA it's the originating interface's own Interface ID; for
    /// Intra-Area-Prefix-LSA it's an arbitrary disambiguator. Stored as
    /// `Ipv4Addr` purely to reuse the same 4-byte octet codec every other
    /// 32-bit identifier in this codebase already uses (`router_id`,
    /// `area_id`), matching v2's own `LsaKey.link_state_id` convention —
    /// never interpreted as a real address.
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
}

/// RFC 5340 §A.4.2.1's 20-byte common LSA header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaHeader {
    pub age: u16,
    /// The full 16-bit `LS Type` word — U-bit, S2/S1 scope, and 13-bit
    /// function code all packed together, matching the wire exactly (unlike
    /// v2, there's no separate `options` header field to split out).
    pub lsa_type: u16,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
    /// RFC 2328 §12.1.6 (unchanged by RFC 5340): `MinSequenceNumber =
    /// 0x8000_0001` through `MaxSequenceNumber = 0x7fff_ffff`, stored as
    /// `i32` so plain integer comparison gives the correct freshness order.
    pub sequence_number: i32,
    /// RFC 905 Annex B Fletcher checksum — identical algorithm to v2's LSA
    /// checksum, see `lsa_checksum`.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterLsaLink {
    pub link_type: u8,
    pub metric: u16,
    pub interface_id: u32,
    pub neighbor_interface_id: u32,
    pub neighbor_router_id: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsaBody {
    /// Top byte of the header word (RFC 5340 §A.4.3's Nt/x/V/E/B bits) —
    /// B (`ROUTER_FLAG_B`) while an ABR, E (`ROUTER_FLAG_E`) while an ASBR;
    /// no virtual links (V) or NSSA (Nt).
    pub flags: u8,
    /// Low 24 bits only.
    pub options: u32,
    pub links: Vec<RouterLsaLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLsaBody {
    /// Low 24 bits only.
    pub options: u32,
    pub attached_routers: Vec<Ipv4Addr>,
}

/// One prefix entry as carried by a Link-LSA (§A.4.9) — no metric, unlike
/// `IntraAreaPrefixEntry`, since a Link-LSA's prefixes aren't themselves SPF
/// inputs, only material `link::originate_intra_area_prefix_lsas` later
/// republishes with a real cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkPrefixEntry {
    pub options: u8,
    pub prefix: Ipv6Net,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLsaBody {
    pub priority: u8,
    /// Low 24 bits only.
    pub options: u32,
    pub link_local_address: Ipv6Addr,
    pub prefixes: Vec<LinkPrefixEntry>,
}

/// One prefix entry as carried by an Intra-Area-Prefix-LSA (§A.4.10) — real
/// SPF input, unlike `LinkPrefixEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntraAreaPrefixEntry {
    pub options: u8,
    pub metric: u16,
    pub prefix: Ipv6Net,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntraAreaPrefixLsaBody {
    /// §A.4.10: the full 16-bit LS Type of the referenced LSA — always
    /// `LSA_TYPE_ROUTER` (a router's own stub/loopback prefixes) or
    /// `LSA_TYPE_NETWORK` (a transit network's prefix) in this crate, never
    /// a bare function code.
    pub referenced_ls_type: u16,
    pub referenced_link_state_id: Ipv4Addr,
    pub referenced_advertising_router: Ipv4Addr,
    pub prefixes: Vec<IntraAreaPrefixEntry>,
}

/// RFC 5187 Grace-LSA body: how long the restarting router asks its
/// neighbors to keep helping, and why it restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraceLsaBody {
    pub grace_period: u32,
    pub restart_reason: u8,
}

/// RFC 5340 §A.4.5 Inter-Area-Prefix-LSA: one prefix an ABR summarizes into
/// another area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterAreaPrefixLsaBody {
    /// 24 bits.
    pub metric: u32,
    pub prefix_options: u8,
    pub prefix: Ipv6Net,
}

/// RFC 5340 §A.4.6 Inter-Area-Router-LSA: an ASBR an ABR makes reachable in
/// another area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterAreaRouterLsaBody {
    /// The ASBR's own Options, 24 bits.
    pub options: u32,
    /// 24 bits.
    pub metric: u32,
    pub destination_router_id: Ipv4Addr,
}

/// RFC 5340 §A.4.7 AS-External-LSA. Decoded faithfully; this router
/// originates Type-1 (`type2` clear) with no forwarding address, tag or
/// referenced LSA. In the RFC 8362 form there is no referenced LSA at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsExternalLsaBody {
    /// The E-bit: a Type-2 metric.
    pub type2: bool,
    /// 24 bits.
    pub metric: u32,
    pub prefix_options: u8,
    pub prefix: Ipv6Net,
    pub forwarding_address: Option<Ipv6Addr>,
    pub route_tag: Option<u32>,
    pub referenced_ls_type: u16,
    pub referenced_link_state_id: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaBody {
    Router(RouterLsaBody),
    Network(NetworkLsaBody),
    Link(LinkLsaBody),
    IntraAreaPrefix(IntraAreaPrefixLsaBody),
    Grace(GraceLsaBody),
    InterAreaPrefix(InterAreaPrefixLsaBody),
    InterAreaRouter(InterAreaRouterLsaBody),
    AsExternal(AsExternalLsaBody),
    /// A type this crate does not understand (RFC 5340 §2.9): the raw body,
    /// kept verbatim so the LSA re-floods with a valid checksum.
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
    fn header(&self) -> &LsaHeader {
        &self.header
    }
    fn header_mut(&mut self) -> &mut LsaHeader {
        &mut self.header
    }
}

pub(crate) fn encode_lsa_header(buf: &mut Vec<u8>, header: &LsaHeader) {
    buf.extend_from_slice(&header.age.to_be_bytes());
    buf.extend_from_slice(&header.lsa_type.to_be_bytes());
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
        lsa_type: u16::from_be_bytes([data[2], data[3]]),
        link_state_id: read_ipv4(data, 4),
        advertising_router: read_ipv4(data, 8),
        sequence_number: i32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        checksum: u16::from_be_bytes([data[16], data[17]]),
        length: u16::from_be_bytes([data[18], data[19]]),
    })
}

/// RFC 5340 §A.3.4's Link State Request entry: Reserved(16) + LS Type(16) +
/// Link State ID(32) + Advertising Router(32) — 12 bytes, same length as
/// v2's (whose LS Type field is only 1 byte wide but padded to the same
/// 4-byte word).
pub(crate) const KEY_LEN: usize = 12;

pub(crate) fn encode_key(buf: &mut Vec<u8>, key: &LsaKey) {
    buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
    buf.extend_from_slice(&key.lsa_type.to_be_bytes());
    buf.extend_from_slice(&key.link_state_id.octets());
    buf.extend_from_slice(&key.advertising_router.octets());
}

pub(crate) fn decode_key(data: &[u8]) -> LsaKey {
    LsaKey {
        lsa_type: u16::from_be_bytes([data[2], data[3]]),
        link_state_id: read_ipv4(data, 4),
        advertising_router: read_ipv4(data, 8),
    }
}

/// Bytes needed to hold a `/prefix_len` IPv6 prefix on the wire (RFC 5340
/// §A.4.1.1): `ceil(prefix_len / 32)` 32-bit words, zero-padded — never more
/// than 16 (the whole address) for any valid `prefix_len <= 128`.
fn prefix_wire_len(prefix_len: u8) -> usize {
    (usize::from(prefix_len).div_ceil(32)) * 4
}

fn encode_prefix(buf: &mut Vec<u8>, prefix: &Ipv6Net) {
    let truncated = prefix.trunc();
    let octets = truncated.addr().octets();
    buf.extend_from_slice(&octets[..prefix_wire_len(truncated.prefix_len())]);
}

fn decode_prefix(data: &[u8], prefix_len: u8) -> Result<(Ipv6Net, usize), PacketError> {
    if prefix_len > 128 {
        return Err(PacketError::TruncatedBody);
    }
    let wire_len = prefix_wire_len(prefix_len);
    if data.len() < wire_len {
        return Err(PacketError::TruncatedBody);
    }
    let mut octets = [0u8; 16];
    octets[..wire_len].copy_from_slice(&data[..wire_len]);
    let net =
        Ipv6Net::new(Ipv6Addr::from(octets), prefix_len).map_err(|_| PacketError::TruncatedBody)?;
    Ok((net, wire_len))
}

fn put_tlv(buf: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    buf.extend_from_slice(&tlv_type.to_be_bytes());
    buf.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    buf.extend_from_slice(value);
    buf.resize(buf.len().next_multiple_of(4), 0); // pad, not counted in Length
}

/// Splits `data` into RFC 8362 §3 `(type, value)` TLVs; padding is skipped
/// and unknown types are left for the caller to ignore.
fn split_tlvs(mut data: &[u8]) -> Result<Vec<(u16, &[u8])>, PacketError> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 {
            return Err(PacketError::TruncatedBody);
        }
        let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        if data.len() < 4 + len {
            return Err(PacketError::TruncatedBody);
        }
        out.push((u16::from_be_bytes([data[0], data[1]]), &data[4..4 + len]));
        data = &data[(4 + len.next_multiple_of(4)).min(data.len())..];
    }
    Ok(out)
}

/// Options word shared by every extended LSA's fixed part: one leading flag
/// byte (E-Router flags / E-Link priority / reserved) + 24-bit options.
fn fixed_word(first: u8, options: u32) -> [u8; 4] {
    let o = (options & 0x00FF_FFFF).to_be_bytes();
    [first, o[1], o[2], o[3]]
}

fn prefix_tlv_value(metric: u16, options: u8, prefix: &Ipv6Net) -> Vec<u8> {
    let mut v = vec![0, 0, 0, 0];
    v[2..4].copy_from_slice(&metric.to_be_bytes());
    v.extend_from_slice(&[prefix.trunc().prefix_len(), options, 0, 0]);
    encode_prefix(&mut v, prefix);
    v
}

/// Reads an Intra-Area-Prefix TLV value: `(metric, options, prefix)`.
fn parse_prefix_tlv(v: &[u8]) -> Result<(u16, u8, Ipv6Net), PacketError> {
    if v.len() < 8 {
        return Err(PacketError::TruncatedBody);
    }
    let metric = u16::from_be_bytes([v[2], v[3]]);
    let (prefix, _) = decode_prefix(&v[8..], v[4])?;
    Ok((metric, v[5], prefix))
}

fn is_extended(lsa_type: u16) -> bool {
    matches!(
        lsa_type,
        LSA_TYPE_E_ROUTER
            | LSA_TYPE_E_NETWORK
            | LSA_TYPE_E_LINK
            | LSA_TYPE_E_INTRA_AREA_PREFIX
            | LSA_TYPE_E_INTER_AREA_PREFIX
            | LSA_TYPE_E_INTER_AREA_ROUTER
            | LSA_TYPE_E_AS_EXTERNAL
    )
}

fn u24(word: u32) -> [u8; 3] {
    let b = (word & 0x00FF_FFFF).to_be_bytes();
    [b[1], b[2], b[3]]
}

fn read_u24(data: &[u8]) -> u32 {
    u32::from(data[0]) << 16 | u32::from(data[1]) << 8 | u32::from(data[2])
}

/// The shared `[flags, metric(24)][PrefixLength, PrefixOptions, word16]
/// [prefix]` layout of the Inter-Area-Prefix and AS-External bodies (§A.4.5,
/// §A.4.7) and of their RFC 8362 TLVs.
fn encode_metric_prefix(
    buf: &mut Vec<u8>,
    flags: u8,
    metric: u32,
    options: u8,
    word: u16,
    prefix: &Ipv6Net,
) {
    buf.push(flags);
    buf.extend_from_slice(&u24(metric));
    buf.extend_from_slice(&[prefix.trunc().prefix_len(), options]);
    buf.extend_from_slice(&word.to_be_bytes());
    encode_prefix(buf, prefix);
}

/// Inverse of `encode_metric_prefix`.
struct MetricPrefix {
    flags: u8,
    metric: u32,
    options: u8,
    word: u16,
    prefix: Ipv6Net,
    /// Bytes consumed.
    len: usize,
}

fn decode_metric_prefix(data: &[u8]) -> Result<MetricPrefix, PacketError> {
    if data.len() < 8 {
        return Err(PacketError::TruncatedBody);
    }
    let (prefix, len) = decode_prefix(&data[8..], data[4])?;
    Ok(MetricPrefix {
        flags: data[0],
        metric: read_u24(&data[1..4]),
        options: data[5],
        word: u16::from_be_bytes([data[6], data[7]]),
        prefix,
        len: 8 + len,
    })
}

fn inter_area_prefix(m: &MetricPrefix) -> LsaBody {
    LsaBody::InterAreaPrefix(InterAreaPrefixLsaBody {
        metric: m.metric,
        prefix_options: m.options,
        prefix: m.prefix,
    })
}

fn encode_inter_area_router(buf: &mut Vec<u8>, r: &InterAreaRouterLsaBody) {
    buf.push(0);
    buf.extend_from_slice(&u24(r.options));
    buf.push(0);
    buf.extend_from_slice(&u24(r.metric));
    buf.extend_from_slice(&r.destination_router_id.octets());
}

fn decode_inter_area_router(data: &[u8]) -> Result<LsaBody, PacketError> {
    if data.len() < 12 {
        return Err(PacketError::TruncatedBody);
    }
    Ok(LsaBody::InterAreaRouter(InterAreaRouterLsaBody {
        options: read_u24(&data[1..4]),
        metric: read_u24(&data[5..8]),
        destination_router_id: read_ipv4(data, 8),
    }))
}

fn read_ipv6(data: &[u8]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&data[..16]);
    Ipv6Addr::from(o)
}

/// The first `want` TLV of an RFC 8362 inter-area/external E-LSA body.
fn single_tlv(data: &[u8], want: u16) -> Result<&[u8], PacketError> {
    split_tlvs(data)?
        .into_iter()
        .find_map(|(t, v)| (t == want).then_some(v))
        .ok_or(PacketError::TruncatedBody)
}

fn decode_ext_external(data: &[u8]) -> Result<LsaBody, PacketError> {
    let v = single_tlv(data, TLV_EXTERNAL_PREFIX)?;
    let m = decode_metric_prefix(v)?;
    let mut forwarding_address = None;
    let mut route_tag = None;
    for (t, sv) in split_tlvs(&v[m.len..])? {
        match t {
            SUB_TLV_IPV6_FORWARDING_ADDRESS if sv.len() >= 16 => {
                forwarding_address = Some(read_ipv6(sv));
            }
            SUB_TLV_ROUTE_TAG if sv.len() >= 4 => {
                route_tag = Some(u32::from_be_bytes([sv[0], sv[1], sv[2], sv[3]]));
            }
            SUB_TLV_IPV6_FORWARDING_ADDRESS | SUB_TLV_ROUTE_TAG => {
                return Err(PacketError::TruncatedBody)
            }
            _ => {}
        }
    }
    Ok(LsaBody::AsExternal(AsExternalLsaBody {
        type2: m.flags & EXTERNAL_FLAG_E != 0,
        metric: m.metric,
        prefix_options: m.options,
        prefix: m.prefix,
        forwarding_address,
        route_tag,
        referenced_ls_type: 0,
        referenced_link_state_id: None,
    }))
}

fn encode_ext_body(body: &LsaBody) -> Vec<u8> {
    let mut buf = Vec::new();
    match body {
        LsaBody::Opaque(raw) => buf.extend_from_slice(raw),
        LsaBody::Router(r) => {
            buf.extend_from_slice(&fixed_word(r.flags, r.options));
            for l in &r.links {
                let mut v = vec![l.link_type, 0];
                v.extend_from_slice(&l.metric.to_be_bytes());
                v.extend_from_slice(&l.interface_id.to_be_bytes());
                v.extend_from_slice(&l.neighbor_interface_id.to_be_bytes());
                v.extend_from_slice(&l.neighbor_router_id.octets());
                put_tlv(&mut buf, TLV_ROUTER_LINK, &v);
            }
        }
        LsaBody::Network(n) => {
            buf.extend_from_slice(&fixed_word(0, n.options));
            if !n.attached_routers.is_empty() {
                let v: Vec<u8> = n
                    .attached_routers
                    .iter()
                    .flat_map(Ipv4Addr::octets)
                    .collect();
                put_tlv(&mut buf, TLV_ATTACHED_ROUTERS, &v);
            }
        }
        LsaBody::Link(l) => {
            buf.extend_from_slice(&fixed_word(l.priority, l.options));
            put_tlv(
                &mut buf,
                TLV_IPV6_LINK_LOCAL,
                &l.link_local_address.octets(),
            );
            for p in &l.prefixes {
                put_tlv(
                    &mut buf,
                    TLV_INTRA_AREA_PREFIX,
                    &prefix_tlv_value(0, p.options, &p.prefix),
                );
            }
        }
        LsaBody::IntraAreaPrefix(i) => {
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&i.referenced_ls_type.to_be_bytes());
            buf.extend_from_slice(&i.referenced_link_state_id.octets());
            buf.extend_from_slice(&i.referenced_advertising_router.octets());
            for p in &i.prefixes {
                put_tlv(
                    &mut buf,
                    TLV_INTRA_AREA_PREFIX,
                    &prefix_tlv_value(p.metric, p.options, &p.prefix),
                );
            }
        }
        LsaBody::Grace(g) => encode_grace(&mut buf, *g),
        LsaBody::InterAreaPrefix(p) => {
            let mut v = Vec::new();
            encode_metric_prefix(&mut v, 0, p.metric, p.prefix_options, 0, &p.prefix);
            put_tlv(&mut buf, TLV_INTER_AREA_PREFIX, &v);
        }
        LsaBody::InterAreaRouter(r) => {
            let mut v = Vec::new();
            encode_inter_area_router(&mut v, r);
            put_tlv(&mut buf, TLV_INTER_AREA_ROUTER, &v);
        }
        LsaBody::AsExternal(e) => {
            let flags = if e.type2 { EXTERNAL_FLAG_E } else { 0 };
            let mut v = Vec::new();
            encode_metric_prefix(&mut v, flags, e.metric, e.prefix_options, 0, &e.prefix);
            if let Some(fa) = e.forwarding_address {
                put_tlv(&mut v, SUB_TLV_IPV6_FORWARDING_ADDRESS, &fa.octets());
            }
            if let Some(tag) = e.route_tag {
                put_tlv(&mut v, SUB_TLV_ROUTE_TAG, &tag.to_be_bytes());
            }
            put_tlv(&mut buf, TLV_EXTERNAL_PREFIX, &v);
        }
    }
    buf
}

fn encode_grace(buf: &mut Vec<u8>, g: GraceLsaBody) {
    put_tlv(buf, TLV_GRACE_PERIOD, &g.grace_period.to_be_bytes());
    put_tlv(buf, TLV_RESTART_REASON, &[g.restart_reason]);
}

fn decode_grace(data: &[u8]) -> Result<LsaBody, PacketError> {
    let mut grace_period = None;
    let mut restart_reason = 0;
    for (t, v) in split_tlvs(data)? {
        match t {
            TLV_GRACE_PERIOD if v.len() == 4 => {
                grace_period = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
            }
            TLV_RESTART_REASON if v.len() == 1 => restart_reason = v[0],
            TLV_GRACE_PERIOD | TLV_RESTART_REASON => return Err(PacketError::TruncatedBody),
            _ => {}
        }
    }
    Ok(LsaBody::Grace(GraceLsaBody {
        grace_period: grace_period.ok_or(PacketError::TruncatedBody)?,
        restart_reason,
    }))
}

fn decode_ext_body(lsa_type: u16, data: &[u8]) -> Result<LsaBody, PacketError> {
    match lsa_type {
        LSA_TYPE_E_INTER_AREA_PREFIX => {
            let v = single_tlv(data, TLV_INTER_AREA_PREFIX)?;
            return Ok(inter_area_prefix(&decode_metric_prefix(v)?));
        }
        LSA_TYPE_E_INTER_AREA_ROUTER => {
            return decode_inter_area_router(single_tlv(data, TLV_INTER_AREA_ROUTER)?);
        }
        LSA_TYPE_E_AS_EXTERNAL => return decode_ext_external(data),
        _ => {}
    }
    let fixed_len = if lsa_type == LSA_TYPE_E_INTRA_AREA_PREFIX {
        12
    } else {
        4
    };
    if data.len() < fixed_len {
        return Err(PacketError::TruncatedBody);
    }
    let options = u32::from(data[1]) << 16 | u32::from(data[2]) << 8 | u32::from(data[3]);
    let tlvs = split_tlvs(&data[fixed_len..])?;
    match lsa_type {
        LSA_TYPE_E_ROUTER => {
            let mut links = Vec::new();
            for (t, v) in tlvs {
                if t != TLV_ROUTER_LINK {
                    continue;
                }
                if v.len() < ROUTER_LINK_LEN {
                    return Err(PacketError::TruncatedBody);
                }
                links.push(RouterLsaLink {
                    link_type: v[0],
                    metric: u16::from_be_bytes([v[2], v[3]]),
                    interface_id: u32::from_be_bytes([v[4], v[5], v[6], v[7]]),
                    neighbor_interface_id: u32::from_be_bytes([v[8], v[9], v[10], v[11]]),
                    neighbor_router_id: read_ipv4(v, 12),
                });
            }
            Ok(LsaBody::Router(RouterLsaBody {
                flags: data[0],
                options,
                links,
            }))
        }
        LSA_TYPE_E_NETWORK => {
            let mut attached_routers = Vec::new();
            for (t, v) in tlvs {
                if t == TLV_ATTACHED_ROUTERS {
                    if !v.len().is_multiple_of(4) {
                        return Err(PacketError::TruncatedBody);
                    }
                    attached_routers.extend(v.as_chunks::<4>().0.iter().map(|c| read_ipv4(c, 0)));
                }
            }
            Ok(LsaBody::Network(NetworkLsaBody {
                options,
                attached_routers,
            }))
        }
        LSA_TYPE_E_LINK => {
            let mut link_local_address = None;
            let mut prefixes = Vec::new();
            for (t, v) in tlvs {
                match t {
                    TLV_IPV6_LINK_LOCAL if v.len() >= 16 => {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(&v[..16]);
                        link_local_address = Some(Ipv6Addr::from(o));
                    }
                    TLV_IPV6_LINK_LOCAL => return Err(PacketError::TruncatedBody),
                    TLV_INTRA_AREA_PREFIX => {
                        let (_, options, prefix) = parse_prefix_tlv(v)?;
                        prefixes.push(LinkPrefixEntry { options, prefix });
                    }
                    _ => {}
                }
            }
            Ok(LsaBody::Link(LinkLsaBody {
                priority: data[0],
                options,
                link_local_address: link_local_address.ok_or(PacketError::TruncatedBody)?,
                prefixes,
            }))
        }
        _ => {
            let mut prefixes = Vec::new();
            for (t, v) in tlvs {
                if t == TLV_INTRA_AREA_PREFIX {
                    let (metric, options, prefix) = parse_prefix_tlv(v)?;
                    prefixes.push(IntraAreaPrefixEntry {
                        options,
                        metric,
                        prefix,
                    });
                }
            }
            Ok(LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                referenced_ls_type: u16::from_be_bytes([data[2], data[3]]),
                referenced_link_state_id: read_ipv4(data, 4),
                referenced_advertising_router: read_ipv4(data, 8),
                prefixes,
            }))
        }
    }
}

fn encode_body(lsa_type: u16, body: &LsaBody) -> Vec<u8> {
    if is_extended(lsa_type) {
        return encode_ext_body(body);
    }
    match body {
        LsaBody::Opaque(raw) => raw.clone(),
        LsaBody::Router(r) => {
            let mut buf = Vec::with_capacity(4 + r.links.len() * ROUTER_LINK_LEN);
            buf.push(r.flags);
            buf.extend_from_slice(&(r.options & 0x00FF_FFFF).to_be_bytes()[1..]);
            for link in &r.links {
                buf.push(link.link_type);
                buf.push(0); // reserved
                buf.extend_from_slice(&link.metric.to_be_bytes());
                buf.extend_from_slice(&link.interface_id.to_be_bytes());
                buf.extend_from_slice(&link.neighbor_interface_id.to_be_bytes());
                buf.extend_from_slice(&link.neighbor_router_id.octets());
            }
            buf
        }
        LsaBody::Network(n) => {
            let mut buf = Vec::with_capacity(4 + n.attached_routers.len() * 4);
            buf.push(0); // reserved
            buf.extend_from_slice(&(n.options & 0x00FF_FFFF).to_be_bytes()[1..]);
            for router in &n.attached_routers {
                buf.extend_from_slice(&router.octets());
            }
            buf
        }
        LsaBody::Link(l) => {
            let mut buf = Vec::with_capacity(20 + l.prefixes.len() * 20);
            buf.push(l.priority);
            buf.extend_from_slice(&(l.options & 0x00FF_FFFF).to_be_bytes()[1..]);
            buf.extend_from_slice(&l.link_local_address.octets());
            buf.extend_from_slice(
                &u32::try_from(l.prefixes.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            for p in &l.prefixes {
                let truncated = p.prefix.trunc();
                buf.push(truncated.prefix_len());
                buf.push(p.options);
                buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
                encode_prefix(&mut buf, &p.prefix);
            }
            buf
        }
        LsaBody::IntraAreaPrefix(i) => {
            let mut buf = Vec::with_capacity(12 + i.prefixes.len() * 20);
            buf.extend_from_slice(
                &u16::try_from(i.prefixes.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            buf.extend_from_slice(&i.referenced_ls_type.to_be_bytes());
            buf.extend_from_slice(&i.referenced_link_state_id.octets());
            buf.extend_from_slice(&i.referenced_advertising_router.octets());
            for p in &i.prefixes {
                let truncated = p.prefix.trunc();
                buf.push(truncated.prefix_len());
                buf.push(p.options);
                buf.extend_from_slice(&p.metric.to_be_bytes());
                encode_prefix(&mut buf, &p.prefix);
            }
            buf
        }
        LsaBody::Grace(g) => {
            let mut buf = Vec::new();
            encode_grace(&mut buf, *g);
            buf
        }
        LsaBody::InterAreaPrefix(p) => {
            let mut buf = Vec::new();
            encode_metric_prefix(&mut buf, 0, p.metric, p.prefix_options, 0, &p.prefix);
            buf
        }
        LsaBody::InterAreaRouter(r) => {
            let mut buf = Vec::new();
            encode_inter_area_router(&mut buf, r);
            buf
        }
        LsaBody::AsExternal(e) => {
            let mut flags = 0;
            if e.type2 {
                flags |= EXTERNAL_FLAG_E;
            }
            if e.forwarding_address.is_some() {
                flags |= EXTERNAL_FLAG_F;
            }
            if e.route_tag.is_some() {
                flags |= EXTERNAL_FLAG_T;
            }
            let mut buf = Vec::new();
            encode_metric_prefix(
                &mut buf,
                flags,
                e.metric,
                e.prefix_options,
                e.referenced_ls_type,
                &e.prefix,
            );
            if let Some(fa) = e.forwarding_address {
                buf.extend_from_slice(&fa.octets());
            }
            if let Some(tag) = e.route_tag {
                buf.extend_from_slice(&tag.to_be_bytes());
            }
            if e.referenced_ls_type != 0 {
                let id = e.referenced_link_state_id.unwrap_or(Ipv4Addr::UNSPECIFIED);
                buf.extend_from_slice(&id.octets());
            }
            buf
        }
    }
}

fn decode_body(lsa_type: u16, data: &[u8]) -> Result<LsaBody, PacketError> {
    match lsa_type {
        t if is_extended(t) => decode_ext_body(t, data),
        LSA_TYPE_ROUTER => {
            if data.len() < 4 {
                return Err(PacketError::TruncatedBody);
            }
            let flags = data[0];
            let options = u32::from(data[1]) << 16 | u32::from(data[2]) << 8 | u32::from(data[3]);
            let link_bytes = &data[4..];
            if !link_bytes.len().is_multiple_of(ROUTER_LINK_LEN) {
                return Err(PacketError::TruncatedBody);
            }
            let links = link_bytes
                .as_chunks::<ROUTER_LINK_LEN>()
                .0
                .iter()
                .map(|c| RouterLsaLink {
                    link_type: c[0],
                    metric: u16::from_be_bytes([c[2], c[3]]),
                    interface_id: u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
                    neighbor_interface_id: u32::from_be_bytes([c[8], c[9], c[10], c[11]]),
                    neighbor_router_id: read_ipv4(c, 12),
                })
                .collect();
            Ok(LsaBody::Router(RouterLsaBody {
                flags,
                options,
                links,
            }))
        }
        LSA_TYPE_NETWORK => {
            if data.len() < 4 || !(data.len() - 4).is_multiple_of(4) {
                return Err(PacketError::TruncatedBody);
            }
            let options = u32::from(data[1]) << 16 | u32::from(data[2]) << 8 | u32::from(data[3]);
            let attached_routers = data[4..]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                .collect();
            Ok(LsaBody::Network(NetworkLsaBody {
                options,
                attached_routers,
            }))
        }
        LSA_TYPE_LINK => {
            // priority/options (4) + link-local address (16) + prefix count (4);
            // the guard used to say 20 and the count read panicked on 20..24.
            if data.len() < 24 {
                return Err(PacketError::TruncatedBody);
            }
            let priority = data[0];
            let options = u32::from(data[1]) << 16 | u32::from(data[2]) << 8 | u32::from(data[3]);
            let mut addr_octets = [0u8; 16];
            addr_octets.copy_from_slice(&data[4..20]);
            let link_local_address = Ipv6Addr::from(addr_octets);
            let num_prefixes =
                usize::try_from(u32::from_be_bytes([data[20], data[21], data[22], data[23]]))
                    .unwrap_or(usize::MAX);
            let mut rest = &data[24..];
            let mut prefixes = Vec::with_capacity(num_prefixes.min(rest.len() / 4 + 1));
            for _ in 0..num_prefixes {
                if rest.len() < 4 {
                    return Err(PacketError::TruncatedBody);
                }
                let prefix_len = rest[0];
                let options = rest[1];
                let (prefix, consumed) = decode_prefix(&rest[4..], prefix_len)?;
                prefixes.push(LinkPrefixEntry { options, prefix });
                rest = &rest[4 + consumed..];
            }
            Ok(LsaBody::Link(LinkLsaBody {
                priority,
                options,
                link_local_address,
                prefixes,
            }))
        }
        LSA_TYPE_INTRA_AREA_PREFIX => {
            if data.len() < 12 {
                return Err(PacketError::TruncatedBody);
            }
            let num_prefixes = usize::from(u16::from_be_bytes([data[0], data[1]]));
            let referenced_ls_type = u16::from_be_bytes([data[2], data[3]]);
            let referenced_link_state_id = read_ipv4(data, 4);
            let referenced_advertising_router = read_ipv4(data, 8);
            let mut rest = &data[12..];
            let mut prefixes = Vec::with_capacity(num_prefixes.min(rest.len() / 4 + 1));
            for _ in 0..num_prefixes {
                if rest.len() < 4 {
                    return Err(PacketError::TruncatedBody);
                }
                let prefix_len = rest[0];
                let options = rest[1];
                let metric = u16::from_be_bytes([rest[2], rest[3]]);
                let (prefix, consumed) = decode_prefix(&rest[4..], prefix_len)?;
                prefixes.push(IntraAreaPrefixEntry {
                    options,
                    metric,
                    prefix,
                });
                rest = &rest[4 + consumed..];
            }
            Ok(LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                referenced_ls_type,
                referenced_link_state_id,
                referenced_advertising_router,
                prefixes,
            }))
        }
        LSA_TYPE_GRACE => decode_grace(data),
        LSA_TYPE_INTER_AREA_PREFIX => Ok(inter_area_prefix(&decode_metric_prefix(data)?)),
        LSA_TYPE_INTER_AREA_ROUTER => decode_inter_area_router(data),
        LSA_TYPE_AS_EXTERNAL => decode_as_external(data),
        _ => Ok(LsaBody::Opaque(data.to_vec())),
    }
}

/// RFC 5340 §A.4.7: the optional fields follow the prefix in F, T,
/// referenced-LS-type order.
fn decode_as_external(data: &[u8]) -> Result<LsaBody, PacketError> {
    let m = decode_metric_prefix(data)?;
    let mut at = m.len;
    let mut take = |n: usize| -> Result<&[u8], PacketError> {
        let field = data.get(at..at + n).ok_or(PacketError::TruncatedBody)?;
        at += n;
        Ok(field)
    };
    let forwarding_address = if m.flags & EXTERNAL_FLAG_F != 0 {
        Some(read_ipv6(take(16)?))
    } else {
        None
    };
    let route_tag = if m.flags & EXTERNAL_FLAG_T != 0 {
        let t = take(4)?;
        Some(u32::from_be_bytes([t[0], t[1], t[2], t[3]]))
    } else {
        None
    };
    let referenced_link_state_id = if m.word != 0 {
        Some(read_ipv4(take(4)?, 0))
    } else {
        None
    };
    Ok(LsaBody::AsExternal(AsExternalLsaBody {
        type2: m.flags & EXTERNAL_FLAG_E != 0,
        metric: m.metric,
        prefix_options: m.options,
        prefix: m.prefix,
        forwarding_address,
        route_tag,
        referenced_ls_type: m.word,
        referenced_link_state_id,
    }))
}

/// Encodes `lsa`, overwriting `length`/`checksum` with freshly-computed
/// values.
pub fn encode_lsa(lsa: &Lsa) -> Vec<u8> {
    let body = encode_body(lsa.header.lsa_type, &lsa.body);
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

/// Sets `lsa`'s `checksum`/`length` to what `encode_lsa` puts on the wire —
/// `ospf::lsa::fill_checksum`. A self-originated LSA is held this way so a
/// neighbor's echo of it ties with it (`is_newer`) instead of superseding it,
/// which would undo a premature aging (`link::withdraw_self_originated`).
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
    let body = decode_body(header.lsa_type, &data[LSA_HEADER_LEN..total_len])?;
    Ok(Lsa { header, body })
}

/// RFC 2328 §12.1.7 / RFC 905 Annex B's Fletcher checksum — byte-for-byte
/// identical algorithm to `ospf::lsa::lsa_checksum` (RFC 5340 keeps RFC
/// 2328 §13.1's LSA-header semantics unchanged); ported verbatim rather than
/// reimplemented. Computed over an LSA starting at the `lsa_type` field
/// (i.e. `without_age` excludes the 2-byte `age` field that precedes it)
/// through the end of the body, treating the embedded checksum field
/// (offset 14 of `without_age`) as zero regardless of its actual contents —
/// so this same function both computes a fresh checksum (`encode_lsa`) and
/// validates an existing one (`decode_lsa`).
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

/// Encodes a raw RFC 5340 Interface ID (or any other opaque 32-bit value —
/// a Network-LSA's own disambiguator, etc.) as the `Ipv4Addr`-shaped key
/// convention `LsaKey.link_state_id` uses throughout this crate — see
/// `LsaKey`'s own doc comment for why. Shared by `link.rs` (origination) and
/// `spf.rs` (next-hop derivation), the two places that need to move between
/// a raw `u32` interface id and this key shape.
pub fn interface_id_key(id: u32) -> Ipv4Addr {
    Ipv4Addr::from(id.to_be_bytes())
}

/// The inverse of `interface_id_key`.
pub fn key_to_interface_id(key: Ipv4Addr) -> u32 {
    u32::from_be_bytes(key.octets())
}

/// RFC 2328 §13.1's "which LSA instance is newer" (unchanged by RFC 5340):
/// higher sequence number wins, then higher checksum, then an instance at
/// `MAX_AGE` (being flushed) is always considered newer than one that isn't.
/// Delegates to the shared `nos_ospf_common::lsa::LsaHeader::is_newer`.
pub fn is_newer(a: &LsaHeader, b: &LsaHeader) -> Ordering {
    nos_ospf_common::lsa::LsaHeader::is_newer(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_tlv_metric_ignores_the_reserved_byte() {
        let prefix: Ipv6Net = "2001:db8::/64".parse().unwrap();
        let mut v = prefix_tlv_value(300, 0x2, &prefix);
        assert_eq!(parse_prefix_tlv(&v).unwrap(), (300, 0x2, prefix));
        v[1] = 0x7f;
        assert_eq!(parse_prefix_tlv(&v).unwrap().0, 300);
    }

    #[test]
    fn link_local_scope_is_only_the_two_link_lsa_types() {
        assert!(is_link_local_scope(LSA_TYPE_LINK));
        assert!(is_link_local_scope(LSA_TYPE_E_LINK));
        for t in [
            LSA_TYPE_ROUTER,
            LSA_TYPE_NETWORK,
            LSA_TYPE_INTRA_AREA_PREFIX,
            LSA_TYPE_E_ROUTER,
            LSA_TYPE_E_NETWORK,
            LSA_TYPE_E_INTRA_AREA_PREFIX,
        ] {
            assert!(!is_link_local_scope(t), "{t:#06x}");
        }
    }

    fn router_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Router(RouterLsaBody {
                flags: 0,
                options: OPTION_V6 | OPTION_R,
                links: vec![RouterLsaLink {
                    link_type: LINK_TYPE_POINT_TO_POINT,
                    metric: 1,
                    interface_id: 3,
                    neighbor_interface_id: 4,
                    neighbor_router_id: Ipv4Addr::new(9, 9, 9, 10),
                }],
            }),
        }
    }

    fn network_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: LSA_TYPE_NETWORK,
                link_state_id: Ipv4Addr::new(0, 0, 0, 3),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Network(NetworkLsaBody {
                options: OPTION_V6 | OPTION_R,
                attached_routers: vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(9, 9, 9, 10)],
            }),
        }
    }

    fn link_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: LSA_TYPE_LINK,
                link_state_id: Ipv4Addr::new(0, 0, 0, 3),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::Link(LinkLsaBody {
                priority: 1,
                options: OPTION_V6 | OPTION_R,
                link_local_address: "fe80::1".parse().unwrap(),
                prefixes: vec![LinkPrefixEntry {
                    options: 0,
                    prefix: "2001:db8:1::/64".parse().unwrap(),
                }],
            }),
        }
    }

    fn intra_area_prefix_lsa() -> Lsa {
        Lsa {
            header: LsaHeader {
                age: 0,
                lsa_type: LSA_TYPE_INTRA_AREA_PREFIX,
                link_state_id: Ipv4Addr::UNSPECIFIED,
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0,
                length: 0,
            },
            body: LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
                referenced_ls_type: LSA_TYPE_ROUTER,
                referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
                referenced_advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                prefixes: vec![IntraAreaPrefixEntry {
                    options: 0,
                    metric: 1,
                    prefix: "2001:db8:9::/128".parse().unwrap(),
                }],
            }),
        }
    }

    #[test]
    fn extended_lsas_round_trip_and_differ_from_legacy_wire_form() {
        for (mut lsa, e_type) in [
            (router_lsa(), LSA_TYPE_E_ROUTER),
            (network_lsa(), LSA_TYPE_E_NETWORK),
            (link_lsa(), LSA_TYPE_E_LINK),
            (intra_area_prefix_lsa(), LSA_TYPE_E_INTRA_AREA_PREFIX),
        ] {
            let legacy = encode_lsa(&lsa);
            lsa.header.lsa_type = e_type;
            let wire = encode_lsa(&lsa);
            assert_ne!(wire[20..], legacy[20..]);
            assert_eq!(wire.len() % 4, 0);
            let decoded = decode_lsa(&wire).unwrap();
            assert_eq!(decoded.header.lsa_type, e_type);
            assert_eq!(decoded.body, lsa.body);
        }
    }

    #[test]
    fn extended_lsa_skips_unknown_tlvs() {
        let mut lsa = network_lsa();
        lsa.header.lsa_type = LSA_TYPE_E_NETWORK;
        let mut wire = encode_lsa(&lsa);
        // Append an unknown TLV (type 99, 3 bytes + 1 pad) and re-checksum.
        wire.extend_from_slice(&[0, 99, 0, 3, 1, 2, 3, 0]);
        let len = u16::try_from(wire.len()).unwrap().to_be_bytes();
        wire[18..20].copy_from_slice(&len);
        let checksum = lsa_checksum(&wire[2..]);
        wire[16..18].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(decode_lsa(&wire).unwrap().body, lsa.body);
    }

    fn with_body(lsa_type: u16, body: LsaBody) -> Lsa {
        let mut lsa = router_lsa();
        lsa.header.lsa_type = lsa_type;
        lsa.body = body;
        lsa
    }

    #[allow(clippy::fn_params_excessive_bools)]
    fn external(type2: bool, fa: bool, tag: bool, referenced: bool) -> LsaBody {
        LsaBody::AsExternal(AsExternalLsaBody {
            type2,
            metric: 0x01_0203,
            prefix_options: 0,
            prefix: "2001:db8:5::/48".parse().unwrap(),
            forwarding_address: fa.then(|| "2001:db8::1".parse().unwrap()),
            route_tag: tag.then_some(0xdead_beef),
            referenced_ls_type: if referenced { LSA_TYPE_ROUTER } else { 0 },
            referenced_link_state_id: referenced.then_some(Ipv4Addr::new(0, 0, 0, 7)),
        })
    }

    #[test]
    fn inter_area_and_external_lsas_round_trip_in_both_forms() {
        let iap = LsaBody::InterAreaPrefix(InterAreaPrefixLsaBody {
            metric: 0x01_0000,
            prefix_options: 0,
            prefix: "2001:db8:9::/64".parse().unwrap(),
        });
        let iar = LsaBody::InterAreaRouter(InterAreaRouterLsaBody {
            options: OPTION_V6 | OPTION_E | OPTION_R,
            metric: 12,
            destination_router_id: Ipv4Addr::new(3, 3, 3, 3),
        });
        for (legacy, e_type, body) in [
            (
                LSA_TYPE_INTER_AREA_PREFIX,
                LSA_TYPE_E_INTER_AREA_PREFIX,
                iap,
            ),
            (
                LSA_TYPE_INTER_AREA_ROUTER,
                LSA_TYPE_E_INTER_AREA_ROUTER,
                iar,
            ),
            (
                LSA_TYPE_AS_EXTERNAL,
                LSA_TYPE_E_AS_EXTERNAL,
                external(true, true, true, false),
            ),
            (
                LSA_TYPE_AS_EXTERNAL,
                LSA_TYPE_E_AS_EXTERNAL,
                external(false, false, false, false),
            ),
        ] {
            for t in [legacy, e_type] {
                let wire = encode_lsa(&with_body(t, body.clone()));
                assert_eq!(wire.len() % 4, 0, "{t:#06x}");
                assert_eq!(decode_lsa(&wire).unwrap().body, body, "{t:#06x}");
            }
        }
        // Only the legacy form carries a referenced LSA.
        let body = external(false, false, true, true);
        let wire = encode_lsa(&with_body(LSA_TYPE_AS_EXTERNAL, body.clone()));
        assert_eq!(decode_lsa(&wire).unwrap().body, body);
    }

    #[test]
    fn scopes_of_the_new_types() {
        assert_eq!(LSA_TYPE_INTER_AREA_PREFIX, 0x2003);
        assert_eq!(LSA_TYPE_INTER_AREA_ROUTER, 0x2004);
        assert_eq!(LSA_TYPE_AS_EXTERNAL, 0x4005);
        assert_eq!(LSA_TYPE_E_INTER_AREA_PREFIX, 0xA023);
        assert_eq!(LSA_TYPE_E_INTER_AREA_ROUTER, 0xA024);
        assert_eq!(LSA_TYPE_E_AS_EXTERNAL, 0xC025);
        for t in [LSA_TYPE_AS_EXTERNAL, LSA_TYPE_E_AS_EXTERNAL] {
            assert!(is_as_scope(t) && !is_link_local_scope(t));
        }
        for t in [
            LSA_TYPE_INTER_AREA_PREFIX,
            LSA_TYPE_E_INTER_AREA_ROUTER,
            LSA_TYPE_ROUTER,
            LSA_TYPE_LINK,
        ] {
            assert!(!is_as_scope(t), "{t:#06x}");
        }
    }

    /// RFC 5340 §A.4.7's layout, pinned byte by byte with F and T set.
    #[test]
    fn as_external_wire_layout() {
        let wire = encode_lsa(&with_body(
            LSA_TYPE_AS_EXTERNAL,
            external(true, true, true, false),
        ));
        let mut want = vec![0x07, 0x01, 0x02, 0x03, 48, 0, 0, 0];
        want.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 5, 0, 0]);
        want.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        want.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&wire[LSA_HEADER_LEN..], &want[..]);
    }

    #[test]
    fn grace_lsa_round_trips_as_link_local_tlvs() {
        assert!(is_link_local_scope(LSA_TYPE_GRACE));
        let mut lsa = router_lsa();
        lsa.header.lsa_type = LSA_TYPE_GRACE;
        lsa.body = LsaBody::Grace(GraceLsaBody {
            grace_period: 120,
            restart_reason: RESTART_REASON_SOFTWARE,
        });
        let wire = encode_lsa(&lsa);
        // Two padded TLVs: Grace Period (4+4) and Restart Reason (4+1 → 8).
        assert_eq!(wire.len(), LSA_HEADER_LEN + 16);
        assert_eq!(
            &wire[LSA_HEADER_LEN..LSA_HEADER_LEN + 8],
            &[0, 1, 0, 4, 0, 0, 0, 120]
        );
        assert_eq!(decode_lsa(&wire).unwrap().body, lsa.body);
    }

    #[test]
    fn router_lsa_round_trips() {
        let lsa = router_lsa();
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.header.lsa_type, lsa.header.lsa_type);
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn router_lsa_with_no_links_round_trips() {
        let mut lsa = router_lsa();
        lsa.body = LsaBody::Router(RouterLsaBody {
            flags: 0,
            options: OPTION_V6,
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
    fn link_lsa_round_trips_with_one_prefix() {
        let lsa = link_lsa();
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn link_lsa_round_trips_with_no_prefixes() {
        let mut lsa = link_lsa();
        lsa.body = LsaBody::Link(LinkLsaBody {
            priority: 1,
            options: OPTION_V6,
            link_local_address: "fe80::1".parse().unwrap(),
            prefixes: Vec::new(),
        });
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn link_lsa_round_trips_with_non_aligned_prefix_length() {
        let mut lsa = link_lsa();
        lsa.body = LsaBody::Link(LinkLsaBody {
            priority: 1,
            options: OPTION_V6,
            link_local_address: "fe80::1".parse().unwrap(),
            prefixes: vec![LinkPrefixEntry {
                options: 0,
                // /48 needs 2 32-bit words (6 bytes -> padded to 8).
                prefix: "2001:db8:1::/48".parse().unwrap(),
            }],
        });
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn intra_area_prefix_lsa_round_trips() {
        let lsa = intra_area_prefix_lsa();
        let decoded = decode_lsa(&encode_lsa(&lsa)).unwrap();
        assert_eq!(decoded.body, lsa.body);
    }

    #[test]
    fn intra_area_prefix_lsa_round_trips_with_multiple_prefixes() {
        let mut lsa = intra_area_prefix_lsa();
        lsa.body = LsaBody::IntraAreaPrefix(IntraAreaPrefixLsaBody {
            referenced_ls_type: LSA_TYPE_NETWORK,
            referenced_link_state_id: Ipv4Addr::new(0, 0, 0, 3),
            referenced_advertising_router: Ipv4Addr::new(9, 9, 9, 9),
            prefixes: vec![
                IntraAreaPrefixEntry {
                    options: 0,
                    metric: 1,
                    prefix: "2001:db8:1::/64".parse().unwrap(),
                },
                IntraAreaPrefixEntry {
                    options: 0,
                    metric: 10,
                    prefix: "2001:db8:2::/64".parse().unwrap(),
                },
            ],
        });
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

    /// RFC 5340 §A.4.2.1 / §2.9: an unrecognized type decodes to its raw
    /// body and re-encodes byte for byte (so the checksum survives), with the
    /// scope its U/S2/S1 bits give.
    #[test]
    fn unknown_types_round_trip_with_effective_scope() {
        // (type, link-local, as)
        for (t, ll, a) in [
            (0xA0FFu16, false, false), // U=1, area
            (0xC0FF, false, true),     // U=1, AS
            (0x80FF, true, false),     // U=1, link-local
            (0x20FF, true, false),     // U=0, area bits: treated link-local
            (0x40FF, true, false),     // U=0, AS bits: treated link-local
        ] {
            assert!(!is_known_type(t));
            let mut lsa = router_lsa();
            lsa.header.lsa_type = t;
            lsa.body = LsaBody::Opaque(vec![1, 2, 3, 4, 5, 6, 7, 8]);
            let encoded = encode_lsa(&lsa);
            let decoded = decode_lsa(&encoded).unwrap();
            assert_eq!(decoded.body, lsa.body);
            assert_eq!(encode_lsa(&decoded), encoded, "{t:#06x}");
            assert_eq!(is_link_local_scope(t), ll, "{t:#06x}");
            assert_eq!(is_as_scope(t), a, "{t:#06x}");
        }
    }

    #[test]
    fn reserved_scope_is_flagged() {
        assert!(is_reserved_scope(0xE0FF));
        assert!(is_reserved_scope(0x60FF));
        assert!(!is_reserved_scope(LSA_TYPE_AS_EXTERNAL));
        assert!(!is_reserved_scope(LSA_TYPE_LINK));
    }

    #[test]
    fn every_known_constant_is_known() {
        for t in [
            LSA_TYPE_ROUTER,
            LSA_TYPE_NETWORK,
            LSA_TYPE_LINK,
            LSA_TYPE_GRACE,
            LSA_TYPE_AS_EXTERNAL,
            LSA_TYPE_E_ROUTER,
            LSA_TYPE_E_AS_EXTERNAL,
        ] {
            assert!(is_known_type(t));
        }
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
        ("router_x_pos", "00012001000000000101010180000001b2510028000000130100000a000000030000000402020202", 0xb251),
        ("router_x_neg", "00012001000000000101010180000005aa550028000000130100000a000000030000000402020202", 0xaa55),
        ("router_x_zero", "0001200100000000010101018000005affaa0028000000130100000a000000030000000402020202", 0xffaa),
        ("router_y_255", "000120010000000001010101800000af55ff0028000000130100000a000000030000000402020202", 0x55ff),
        ("network_x_pos", "000120020000000301010101800000017a9b0020000000130101010102020202", 0x7a9b),
        ("network_x_neg", "000120020000000301010101800000174eb10020000000130101010102020202", 0x4eb1),
        ("network_x_zero", "0001200200000003010101018000003effd80020000000130101010102020202", 0xffd8),
        ("network_y_255", "00012002000000030101010180000065b1ff0020000000130101010102020202", 0xb1ff),
        ("inter_area_prefix_x_pos", "00012003000000070101010180000001ecfd0024000000194000000020010db800010000", 0xecfd),
        ("inter_area_prefix_x_neg", "000120030000000701010101800000eb17e80024000000194000000020010db800010000", 0x17e8),
        ("inter_area_prefix_x_zero", "00012003000000070101010180000077ff740024000000194000000020010db800010000", 0xff74),
        ("inter_area_prefix_y_255", "00012003000000070101010180000003e8ff0024000000194000000020010db800010000", 0xe8ff),
        ("as_external_x_pos", "00014005000000090101010180000001686e0024040000143000000020010db800020000", 0x686e),
        ("as_external_x_neg", "000140050000000901010101800000d7ba450024040000143000000020010db800020000", 0xba45),
        ("as_external_x_zero", "00014005000000090101010180000035ffa20024040000143000000020010db800020000", 0xffa2),
        ("as_external_y_255", "0001400500000009010101018000009245ff0024040000143000000020010db800020000", 0x45ff),
        ("router_20_links_x_pos", "00012001000000000303030380000001559e01580000001301000001000000010000006402020202010000020000000200000065020202020100000300000003000000660202020201000004000000040000006702020202010000050000000500000068020202020100000600000006000000690202020201000007000000070000006a0202020201000008000000080000006b0202020201000009000000090000006c020202020100000a0000000a0000006d020202020100000b0000000b0000006e020202020100000c0000000c0000006f020202020100000d0000000d00000070020202020100000e0000000e00000071020202020100000f0000000f00000072020202020100001000000010000000730202020201000011000000110000007402020202010000120000001200000075020202020100001300000013000000760202020201000014000000140000007702020202", 0x559e),
        ("router_20_links_x_neg", "000120010000000003030303800000f46d9201580000001301000001000000010000006402020202010000020000000200000065020202020100000300000003000000660202020201000004000000040000006702020202010000050000000500000068020202020100000600000006000000690202020201000007000000070000006a0202020201000008000000080000006b0202020201000009000000090000006c020202020100000a0000000a0000006d020202020100000b0000000b0000006e020202020100000c0000000c0000006f020202020100000d0000000d00000070020202020100000e0000000e00000071020202020100000f0000000f00000072020202020100001000000010000000730202020201000011000000110000007402020202010000120000001200000075020202020100001300000013000000760202020201000014000000140000007702020202", 0x6d92),
        ("router_20_links_x_zero", "000120010000000003030303800000abff4901580000001301000001000000010000006402020202010000020000000200000065020202020100000300000003000000660202020201000004000000040000006702020202010000050000000500000068020202020100000600000006000000690202020201000007000000070000006a0202020201000008000000080000006b0202020201000009000000090000006c020202020100000a0000000a0000006d020202020100000b0000000b0000006e020202020100000c0000000c0000006f020202020100000d0000000d00000070020202020100000e0000000e00000071020202020100000f0000000f00000072020202020100001000000010000000730202020201000011000000110000007402020202010000120000001200000075020202020100001300000013000000760202020201000014000000140000007702020202", 0xff49),
        ("router_20_links_y_255", "0001200100000000030303038000006292ff01580000001301000001000000010000006402020202010000020000000200000065020202020100000300000003000000660202020201000004000000040000006702020202010000050000000500000068020202020100000600000006000000690202020201000007000000070000006a0202020201000008000000080000006b0202020201000009000000090000006c020202020100000a0000000a0000006d020202020100000b0000000b0000006e020202020100000c0000000c0000006f020202020100000d0000000d00000070020202020100000e0000000e00000071020202020100000f0000000f00000072020202020100001000000010000000730202020201000011000000110000007402020202010000120000001200000075020202020100001300000013000000760202020201000014000000140000007702020202", 0x92ff),
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

    #[test]
    fn split_tlvs_boundary_lengths() {
        // Empty value: 4-byte header only.
        assert_eq!(split_tlvs(&[0, 1, 0, 0]).unwrap(), [(1, &[][..])]);
        // Header cut short.
        assert_eq!(
            split_tlvs(&[0, 1, 0]).unwrap_err(),
            PacketError::TruncatedBody
        );
        // Value exactly fits (padded to 4 by the sender, tail padding optional).
        assert_eq!(
            split_tlvs(&[0, 1, 0, 2, 0xaa, 0xbb]).unwrap(),
            [(1, &[0xaa, 0xbb][..])]
        );
        assert_eq!(
            split_tlvs(&[0, 1, 0, 2, 0xaa]).unwrap_err(),
            PacketError::TruncatedBody
        );
        // Padding after a 1-byte value is skipped before the next TLV.
        assert_eq!(
            split_tlvs(&[0, 1, 0, 1, 0xaa, 0, 0, 0, 0, 2, 0, 0]).unwrap(),
            [(1, &[0xaa][..]), (2, &[][..])]
        );
    }

    #[test]
    fn options_bytes_land_in_the_right_place_and_order() {
        // Distinct bytes: options 0x01_0203 on every LSA that carries them.
        let LsaBody::Router(r) = decode_body(LSA_TYPE_ROUTER, &[0x80, 1, 2, 3]).unwrap() else {
            panic!("not a Router-LSA")
        };
        assert_eq!((r.flags, r.options, r.links.len()), (0x80, 0x01_0203, 0));
        let LsaBody::Network(n) = decode_body(LSA_TYPE_NETWORK, &[0, 1, 2, 3, 1, 1, 1, 1]).unwrap()
        else {
            panic!("not a Network-LSA")
        };
        assert_eq!(n.options, 0x01_0203);
        assert_eq!(n.attached_routers, [Ipv4Addr::new(1, 1, 1, 1)]);
        let mut link = [0u8; 24];
        link[0] = 5;
        link[1..4].copy_from_slice(&[1, 2, 3]);
        let LsaBody::Link(l) = decode_body(LSA_TYPE_LINK, &link).unwrap() else {
            panic!("not a Link-LSA")
        };
        assert_eq!((l.priority, l.options), (5, 0x01_0203));
    }

    #[test]
    fn network_lsa_length_is_4_plus_a_multiple_of_4() {
        let body = [0u8; 8];
        for (n, ok) in [
            (0, false),
            (3, false),
            (4, true),
            (5, false),
            (7, false),
            (8, true),
        ] {
            assert_eq!(
                decode_body(LSA_TYPE_NETWORK, &body[..n]).is_ok(),
                ok,
                "{n} bytes"
            );
        }
    }

    #[test]
    fn intra_area_prefix_lsa_boundaries() {
        let mut body = [0u8; 16];
        // 12 bytes, no prefixes: decodes; 11 does not.
        assert!(decode_body(LSA_TYPE_INTRA_AREA_PREFIX, &body[..12]).is_ok());
        assert_eq!(
            decode_body(LSA_TYPE_INTRA_AREA_PREFIX, &body[..11]).unwrap_err(),
            PacketError::TruncatedBody
        );
        // One announced prefix: 3 bytes behind the fixed part is short, 4 fits.
        body[1] = 1;
        assert_eq!(
            decode_body(LSA_TYPE_INTRA_AREA_PREFIX, &body[..15]).unwrap_err(),
            PacketError::TruncatedBody
        );
        let LsaBody::IntraAreaPrefix(p) =
            decode_body(LSA_TYPE_INTRA_AREA_PREFIX, &body[..16]).unwrap()
        else {
            panic!("not an Intra-Area-Prefix-LSA")
        };
        assert_eq!(p.prefixes.len(), 1);
    }

    /// #382: no body length may panic, for any LSA type (the decoder reads
    /// attacker-controlled bytes); an `Err` is fine.
    #[test]
    fn short_bodies_never_panic() {
        let types = (0..=0x2fu16)
            .chain([
                0x2001, 0x2002, 0x2003, 0x2004, 0x4005, 0x0008, 0x2009, 0x000B,
            ])
            .chain([LSA_TYPE_E_ROUTER, LSA_TYPE_E_NETWORK, LSA_TYPE_E_LINK])
            .chain([LSA_TYPE_E_INTRA_AREA_PREFIX, LSA_TYPE_E_INTER_AREA_PREFIX])
            .chain([LSA_TYPE_E_INTER_AREA_ROUTER, LSA_TYPE_E_AS_EXTERNAL]);
        for ty in types {
            for fill in [0x00u8, 0xff, 0x01] {
                for n in 0..=80 {
                    let _ = decode_body(ty, &vec![fill; n]);
                }
            }
        }
    }

    #[test]
    fn link_lsa_fixed_part_is_24_bytes() {
        // priority/options (4) + link-local address (16) + prefix count (4).
        let body = [0u8; 24];
        let LsaBody::Link(l) = decode_body(LSA_TYPE_LINK, &body).unwrap() else {
            panic!("not a Link-LSA")
        };
        assert_eq!(l.prefixes.len(), 0);
        // 20..=23 bytes used to index past the end (the guard said 20).
        for n in [0, 4, 19, 20, 23] {
            assert_eq!(
                decode_body(LSA_TYPE_LINK, &body[..n]).unwrap_err(),
                PacketError::TruncatedBody,
                "{n} bytes"
            );
        }
        // One announced prefix with no 4-byte entry behind it.
        let mut one = body;
        one[23] = 1;
        assert_eq!(
            decode_body(LSA_TYPE_LINK, &one).unwrap_err(),
            PacketError::TruncatedBody
        );
        assert_eq!(
            decode_body(LSA_TYPE_LINK, &[&one[..], &[0u8; 4]].concat())
                .map(|b| matches!(b, LsaBody::Link(l) if l.prefixes.len() == 1)),
            Ok(true)
        );
    }
}
