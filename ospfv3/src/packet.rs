//! RFC 5340 `OSPFv3` wire format — the common packet header (§A.3.1) shared
//! by every packet type, plus each type's own body: Hello (§A.3.2), Database
//! Description (§A.3.3), Link State Request (§A.3.4), Link State Update
//! (§A.3.5), and Link State Acknowledgment (§A.3.6). Pure encode/decode, no
//! I/O — `socket.rs` sends/receives the bytes this module produces/consumes.
//!
//! Two real, deliberate differences from `ospf::packet` (RFC 2328's
//! counterpart):
//!
//! - **Authentication is a trailer, not a header field.** RFC 5340's 16-byte
//!   header (vs. v2's 24-byte one) has no `AuType`/Authentication field;
//!   RFC 7166 instead appends an Authentication Trailer *after* the packet
//!   (outside its own `Length`) and announces it with the AT-bit in
//!   Hello/DBD Options (`lsa::OPTION_AT`). `TrailerAuth::sign`/
//!   `verify_trailer` are the counterpart of `ospf::packet`'s
//!   `OutgoingAuth`/`verify_auth`, kept separate from the per-type
//!   `encode_*`/`decode_*` since the trailer wraps an already-encoded packet.
//! - **No checksum computed or verified in software.** RFC 5340's checksum
//!   (§A.3.1) is the standard IPv6 upper-layer checksum — ones'-complement
//!   over an IPv6 pseudo-header (source/dest address, upper-layer length,
//!   next-header=89) plus the packet, the same construction UDP/TCP/ICMPv6
//!   use, **not** `ospf::packet::checksum`'s bare RFC 1071 sum (which only
//!   ever covered the OSPF bytes themselves — no pseudo-header, since v2
//!   rides directly on IPv4 with no pseudo-header convention for protocol
//!   89). Reimplementing the pseudo-header sum by hand here would need this
//!   module to know the packet's own source/destination — properly a
//!   transport-layer concern. Instead, `socket.rs` sets `IPV6_CHECKSUM` on
//!   the raw socket (the same kernel facility Linux already uses for
//!   `ICMPv6`), so the kernel fills the checksum in on send and verifies (and
//!   silently drops bad packets before delivery) on receive — this module
//!   never sees a checksum mismatch, and doesn't need to. `header.checksum`
//!   is always written as `0` on encode and left unvalidated on decode. On an
//!   authenticated link the kernel option is *not* set (RFC 7166 §2.2/§4.2:
//!   checksum omitted, field 0) and the digest covers the packet instead.

use std::net::{Ipv4Addr, Ipv6Addr};

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Digest;
use thiserror::Error;

use crate::lsa::{self, Lsa, LsaHeader, LsaKey};

pub const VERSION: u8 = 3;
pub const TYPE_HELLO: u8 = 1;
pub const TYPE_DBD: u8 = 2;
pub const TYPE_LSR: u8 = 3;
pub const TYPE_LSU: u8 = 4;
pub const TYPE_LSACK: u8 = 5;

const HEADER_LEN: usize = 16;
/// Offset of the §A.3.1 Instance ID in the common header, right after the
/// checksum (offset 12, kernel-filled).
const INSTANCE_ID_OFFSET: usize = 14;

/// The Instance ID of an encoded packet, `None` if it is shorter than a
/// header. The receiver drops a packet whose Instance ID isn't its link's
/// (RFC 5340 §A.3.1); `decode` leaves it alone, since it has no link.
pub fn instance_id(data: &[u8]) -> Option<u8> {
    (data.len() >= HEADER_LEN).then(|| data[INSTANCE_ID_OFFSET])
}

/// Stamps `id` into an encoded packet's header — `encode_*` always writes 0,
/// and `socket.rs` sets the link's own value just before sending.
pub fn set_instance_id(buf: &mut [u8], id: u8) {
    buf[INSTANCE_ID_OFFSET] = id;
}
/// Hello body length excluding the trailing neighbor list: Interface ID(4) +
/// Rtr Priority(1) + Options(3) + `HelloInterval`(2) + `RouterDeadInterval`(2)
/// + Designated Router(4) + Backup Designated Router(4).
const HELLO_BODY_FIXED_LEN: usize = 20;
/// DBD body length excluding the trailing LSA-header summary list:
/// Reserved(1) + Options(3) + Interface MTU(2) + Reserved(1) + Flags(1) + DD
/// sequence number(4).
const DBD_BODY_FIXED_LEN: usize = 12;

const DBD_FLAG_MASTER: u8 = 0x01;
const DBD_FLAG_MORE: u8 = 0x02;
const DBD_FLAG_INIT: u8 = 0x04;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("packet shorter than the 16-byte OSPFv3 header")]
    Truncated,
    #[error("not an OSPFv3 packet (version {0})")]
    BadVersion(u8),
    #[error("unrecognized OSPFv3 packet type {0}")]
    UnknownType(u8),
    #[error("packet body shorter than expected")]
    TruncatedBody,
    /// An LSA's own Fletcher-16 checksum (`lsa::lsa_checksum`) didn't match
    /// — unlike the OSPF packet header's checksum (kernel-verified via
    /// `IPV6_CHECKSUM`, see this module's doc comment), an LSA's checksum
    /// travels inside the packet body and is still validated in software,
    /// exactly like `ospf::packet::PacketError::BadChecksum`.
    #[error("lsa checksum mismatch")]
    BadChecksum,
    #[error("packet's AT-bit/trailer doesn't match this link's configured auth")]
    AuthTypeMismatch,
    #[error("authentication failed (unknown key-id or bad digest)")]
    AuthFailed,
}

/// RFC 7166 §4.3's HMAC-SHA family — no MD5 exists for `OSPFv3`. This
/// module's own mirror of `nos_proto::OspfCryptoAlgorithm` (converted in
/// `reconcile.rs`), like `ospf::packet::CryptoAlgorithm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

fn hmac<M: Mac + KeyInit>(ko: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <M as KeyInit>::new_from_slice(ko).expect("hmac accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_verify<M: Mac + KeyInit>(ko: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut mac = <M as KeyInit>::new_from_slice(ko).expect("hmac accepts a key of any length");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

impl CryptoAlgorithm {
    /// `L` in RFC 7166 §4.5 — the digest length.
    fn digest_len(self) -> usize {
        match self {
            CryptoAlgorithm::HmacSha1 => 20,
            CryptoAlgorithm::HmacSha256 => 32,
            CryptoAlgorithm::HmacSha384 => 48,
            CryptoAlgorithm::HmacSha512 => 64,
        }
    }

    /// RFC 7166 §4.4/§4.5 step 1: `Ks = key || Cryptographic Protocol ID`
    /// (the cross-protocol-attack mitigation `ospf::packet` has no
    /// counterpart of), then `Ko = H(Ks)` if longer than `L`, else `Ks`
    /// zero-padded to `L`.
    fn prepared_key(self, key: &[u8]) -> Vec<u8> {
        let mut ks = key.to_vec();
        ks.extend_from_slice(&CRYPTO_PROTOCOL_ID);
        let l = self.digest_len();
        if ks.len() > l {
            return match self {
                CryptoAlgorithm::HmacSha1 => sha1::Sha1::digest(&ks).to_vec(),
                CryptoAlgorithm::HmacSha256 => sha2::Sha256::digest(&ks).to_vec(),
                CryptoAlgorithm::HmacSha384 => sha2::Sha384::digest(&ks).to_vec(),
                CryptoAlgorithm::HmacSha512 => sha2::Sha512::digest(&ks).to_vec(),
            };
        }
        ks.resize(l, 0);
        ks
    }

    fn digest(self, ko: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            CryptoAlgorithm::HmacSha1 => hmac::<Hmac<sha1::Sha1>>(ko, data),
            CryptoAlgorithm::HmacSha256 => hmac::<Hmac<sha2::Sha256>>(ko, data),
            CryptoAlgorithm::HmacSha384 => hmac::<Hmac<sha2::Sha384>>(ko, data),
            CryptoAlgorithm::HmacSha512 => hmac::<Hmac<sha2::Sha512>>(ko, data),
        }
    }

    /// Constant-time check of `tag` against the digest of `data`.
    fn verify(self, ko: &[u8], data: &[u8], tag: &[u8]) -> bool {
        match self {
            CryptoAlgorithm::HmacSha1 => hmac_verify::<Hmac<sha1::Sha1>>(ko, data, tag),
            CryptoAlgorithm::HmacSha256 => hmac_verify::<Hmac<sha2::Sha256>>(ko, data, tag),
            CryptoAlgorithm::HmacSha384 => hmac_verify::<Hmac<sha2::Sha384>>(ko, data, tag),
            CryptoAlgorithm::HmacSha512 => hmac_verify::<Hmac<sha2::Sha512>>(ko, data, tag),
        }
    }
}

/// RFC 7166 §4.1's fixed trailer header: Authentication Type(2) + Auth Data
/// Len(2) + Reserved(2) + Security Association ID(2) + Cryptographic
/// Sequence Number(8); the digest follows.
const TRAILER_HEADER_LEN: usize = 16;
/// §4.1: the only defined Authentication Type, "HMAC Cryptographic
/// Authentication".
const AUTH_TYPE_HMAC: u16 = 1;
/// §7: `OSPFv3`'s Cryptographic Protocol ID, two octets.
const CRYPTO_PROTOCOL_ID: [u8; 2] = [0x00, 0x01];

/// One link's RFC 7166 keys — `Ospfv3Profile.auth` in this module's own
/// shape (`(sa_id, algorithm, secret)`; the SA ID is `key_id`). Every key
/// verifies, only `current_key_id` signs — the same rollover model as
/// `ospf::link::LinkAuthConfig::Crypto`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailerAuth {
    pub keys: Vec<(u16, CryptoAlgorithm, Vec<u8>)>,
    pub current_key_id: u16,
}

impl TrailerAuth {
    /// Bytes `sign` appends: trailer header plus the current key's digest.
    pub fn trailer_len(&self) -> usize {
        self.keys
            .iter()
            .find(|(id, _, _)| *id == self.current_key_id)
            .map_or(0, |(_, a, _)| TRAILER_HEADER_LEN + a.digest_len())
    }

    /// Appends the trailer to `packet` (an `encode_*` result, checksum 0),
    /// signing with the current key. `sequence` is this send's own strictly
    /// increasing number; `source` is the IPv6 address the packet leaves
    /// from, which `apad` binds into the digest (§4.5).
    pub fn sign(&self, packet: &mut Vec<u8>, sequence: u64, source: Ipv6Addr) {
        let (key_id, algorithm, key) = self
            .keys
            .iter()
            .find(|(id, _, _)| *id == self.current_key_id)
            .expect("valid_auth guarantees current_key_id names a real key");
        let l = u16::try_from(TRAILER_HEADER_LEN + algorithm.digest_len()).unwrap_or(u16::MAX);
        packet.extend_from_slice(&AUTH_TYPE_HMAC.to_be_bytes());
        packet.extend_from_slice(&l.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes()); // reserved
        packet.extend_from_slice(&key_id.to_be_bytes());
        packet.extend_from_slice(&sequence.to_be_bytes());
        let ko = algorithm.prepared_key(key);
        let digest = algorithm.digest(&ko, &digest_input(packet, *algorithm, source));
        packet.extend_from_slice(&digest);
    }
}

/// RFC 7166 §4.5's `Apad`: the 16-octet IPv6 source address followed by
/// `0x878FE1F3` repeated to the digest length — `ospf::packet::apad` with
/// RFC 7474's 4-byte IPv4 source replaced by the 16-byte IPv6 one.
fn apad(algorithm: CryptoAlgorithm, source: Ipv6Addr) -> Vec<u8> {
    let mut pad = Vec::with_capacity(algorithm.digest_len());
    pad.extend_from_slice(&source.octets());
    for _ in 0..(algorithm.digest_len() - 16) / 4 {
        pad.extend_from_slice(&0x878F_E1F3u32.to_be_bytes());
    }
    pad
}

/// §4.5: the packet and the trailer header, with `Apad` standing in the
/// Authentication Data field.
fn digest_input(
    packet_and_trailer_header: &[u8],
    algorithm: CryptoAlgorithm,
    source: Ipv6Addr,
) -> Vec<u8> {
    [packet_and_trailer_header, &apad(algorithm, source)].concat()
}

/// The AT-bit of a Hello/DBD's Options field; `None` for the other types
/// (no Options field — §2.1: they inherit the link's setting) or a body too
/// short to hold one (left for the body decoder to reject).
fn at_bit(data: &[u8]) -> Option<bool> {
    let options_at = match data[1] {
        TYPE_HELLO => HEADER_LEN + 5,
        TYPE_DBD => HEADER_LEN + 1,
        _ => return None,
    };
    let b = data.get(options_at..options_at + 3)?;
    let options = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
    Some(options & lsa::OPTION_AT != 0)
}

/// The counterpart of `TrailerAuth::sign` on receive, and of
/// `ospf::packet::verify_auth`: checks the AT-bit against the link's
/// configured `auth`, then (if authenticated) locates the trailer after the
/// header's `Length`, verifies the digest under the key the SA ID names, and
/// returns the packet proper (for `decode`) plus the trailer's sequence
/// number for `link.rs`'s anti-replay check. `source` is the received
/// packet's IPv6 source. Unauthenticated: the packet as-is and `None`.
pub fn verify_trailer<'a>(
    data: &'a [u8],
    auth: Option<&TrailerAuth>,
    source: Ipv6Addr,
) -> Result<(&'a [u8], Option<u64>), PacketError> {
    let at = if data.len() < HEADER_LEN {
        None // too short for anything; `decode` reports it
    } else {
        at_bit(data)
    };
    let Some(auth) = auth else {
        return if at == Some(true) {
            Err(PacketError::AuthTypeMismatch)
        } else {
            Ok((data, None))
        };
    };
    if data.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    if at == Some(false) {
        return Err(PacketError::AuthTypeMismatch);
    }
    let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if length < HEADER_LEN || data.len() < length {
        return Err(PacketError::TruncatedBody);
    }
    let trailer = &data[length..];
    if trailer.len() < TRAILER_HEADER_LEN
        || u16::from_be_bytes([trailer[0], trailer[1]]) != AUTH_TYPE_HMAC
    {
        return Err(PacketError::AuthTypeMismatch);
    }
    let auth_data_len = usize::from(u16::from_be_bytes([trailer[2], trailer[3]]));
    let sa_id = u16::from_be_bytes([trailer[6], trailer[7]]);
    let sequence = u64::from_be_bytes(
        trailer[8..16]
            .try_into()
            .expect("trailer header is 16 bytes"),
    );
    let Some((_, algorithm, key)) = auth.keys.iter().find(|(id, _, _)| *id == sa_id) else {
        return Err(PacketError::AuthFailed);
    };
    let digest_len = algorithm.digest_len();
    if auth_data_len != TRAILER_HEADER_LEN + digest_len || trailer.len() < auth_data_len {
        return Err(PacketError::TruncatedBody);
    }
    let signed_end = length + TRAILER_HEADER_LEN;
    let ko = algorithm.prepared_key(key);
    let input = digest_input(&data[..signed_end], *algorithm, source);
    if !algorithm.verify(&ko, &input, &data[signed_end..signed_end + digest_len]) {
        return Err(PacketError::AuthFailed);
    }
    Ok((&data[..length], Some(sequence)))
}

/// One Hello packet's contents (§A.3.2). `designated_router`/
/// `backup_designated_router`/`neighbors` are Router IDs, not addresses — a
/// real RFC 5340 simplification vs. v2, where they're the DR/BDR's own IPv4
/// address (see `nos_ospf_common::election`'s doc comment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub interface_id: u32,
    pub router_priority: u8,
    /// Low 24 bits only — see `lsa::OPTION_*`.
    pub options: u32,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub designated_router: Ipv4Addr,
    pub backup_designated_router: Ipv4Addr,
    pub neighbors: Vec<Ipv4Addr>,
}

/// One Database Description packet's contents (§A.3.3): the shared
/// `nos_ospf_common::exchange::Dbd`; `options` uses its low 24 bits only.
pub type DbdPacket = nos_ospf_common::exchange::Dbd<LsaHeader>;

/// One Link State Request packet's contents (§A.3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsrPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub requests: Vec<LsaKey>,
}

/// One Link State Update packet's contents (§A.3.5).
#[derive(Debug, Clone, PartialEq)]
pub struct LsuPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub lsas: Vec<Lsa>,
    /// LSAs skipped for a per-LSA error (checksum, body); never in `lsas`.
    pub discarded: usize,
    /// The most recent error behind `discarded`.
    pub last_error: Option<PacketError>,
}

/// One Link State Acknowledgment packet's contents (§A.3.6).
#[derive(Debug, Clone, PartialEq)]
pub struct LsAckPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub lsa_headers: Vec<LsaHeader>,
}

/// Any one `OSPFv3` packet, tagged by its common-header type byte.
#[derive(Debug, Clone, PartialEq)]
pub enum OspfPacket {
    Hello(HelloPacket),
    Dbd(DbdPacket),
    Lsr(LsrPacket),
    Lsu(LsuPacket),
    LsAck(LsAckPacket),
}

/// Encodes `pkt` as a Hello packet.
pub fn encode_hello(pkt: &HelloPacket) -> Vec<u8> {
    let mut body = Vec::with_capacity(HELLO_BODY_FIXED_LEN + pkt.neighbors.len() * 4);
    body.extend_from_slice(&pkt.interface_id.to_be_bytes());
    body.push(pkt.router_priority);
    body.extend_from_slice(&(pkt.options & 0x00FF_FFFF).to_be_bytes()[1..]);
    body.extend_from_slice(&pkt.hello_interval.to_be_bytes());
    body.extend_from_slice(&pkt.dead_interval.to_be_bytes());
    body.extend_from_slice(&pkt.designated_router.octets());
    body.extend_from_slice(&pkt.backup_designated_router.octets());
    for n in &pkt.neighbors {
        body.extend_from_slice(&n.octets());
    }
    encode_packet(TYPE_HELLO, pkt.router_id, pkt.area_id, &body)
}

/// Decodes a Hello packet, validating the common header first.
pub fn decode_hello(data: &[u8]) -> Result<HelloPacket, PacketError> {
    let (packet_type, router_id, area_id, body) = decode_header(data)?;
    if packet_type != TYPE_HELLO {
        return Err(PacketError::UnknownType(packet_type));
    }
    if body.len() < HELLO_BODY_FIXED_LEN {
        return Err(PacketError::TruncatedBody);
    }
    let interface_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let router_priority = body[4];
    let options = u32::from(body[5]) << 16 | u32::from(body[6]) << 8 | u32::from(body[7]);
    let hello_interval = u16::from_be_bytes([body[8], body[9]]);
    let dead_interval = u16::from_be_bytes([body[10], body[11]]);
    let designated_router = read_ipv4(body, 12);
    let backup_designated_router = read_ipv4(body, 16);

    let neighbor_bytes = &body[HELLO_BODY_FIXED_LEN..];
    if !neighbor_bytes.len().is_multiple_of(4) {
        return Err(PacketError::TruncatedBody);
    }
    let neighbors = neighbor_bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
        .collect();

    Ok(HelloPacket {
        router_id,
        area_id,
        interface_id,
        router_priority,
        options,
        hello_interval,
        dead_interval,
        designated_router,
        backup_designated_router,
        neighbors,
    })
}

/// Encodes `pkt` as a DBD packet.
pub fn encode_dbd(pkt: &DbdPacket) -> Vec<u8> {
    let mut body =
        Vec::with_capacity(DBD_BODY_FIXED_LEN + pkt.lsa_headers.len() * lsa::LSA_HEADER_LEN);
    body.push(0); // reserved
    body.extend_from_slice(&(pkt.options & 0x00FF_FFFF).to_be_bytes()[1..]);
    body.extend_from_slice(&pkt.interface_mtu.to_be_bytes());
    body.push(0); // reserved
    let mut flags = 0u8;
    if pkt.init {
        flags |= DBD_FLAG_INIT;
    }
    if pkt.more {
        flags |= DBD_FLAG_MORE;
    }
    if pkt.master {
        flags |= DBD_FLAG_MASTER;
    }
    body.push(flags);
    body.extend_from_slice(&pkt.dd_sequence_number.to_be_bytes());
    for header in &pkt.lsa_headers {
        lsa::encode_lsa_header(&mut body, header);
    }
    encode_packet(TYPE_DBD, pkt.router_id, pkt.area_id, &body)
}

/// Decodes a DBD packet, validating the common header first.
pub fn decode_dbd(data: &[u8]) -> Result<DbdPacket, PacketError> {
    let (packet_type, router_id, area_id, body) = decode_header(data)?;
    if packet_type != TYPE_DBD {
        return Err(PacketError::UnknownType(packet_type));
    }
    if body.len() < DBD_BODY_FIXED_LEN {
        return Err(PacketError::TruncatedBody);
    }
    let options = u32::from(body[1]) << 16 | u32::from(body[2]) << 8 | u32::from(body[3]);
    let interface_mtu = u16::from_be_bytes([body[4], body[5]]);
    let flags = body[7];
    let dd_sequence_number = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);

    let header_bytes = &body[DBD_BODY_FIXED_LEN..];
    if !header_bytes.len().is_multiple_of(lsa::LSA_HEADER_LEN) {
        return Err(PacketError::TruncatedBody);
    }
    let lsa_headers = header_bytes
        .as_chunks::<{ lsa::LSA_HEADER_LEN }>()
        .0
        .iter()
        .map(|c| lsa::decode_lsa_header(c))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(DbdPacket {
        lls: None,
        router_id,
        area_id,
        options,
        interface_mtu,
        init: flags & DBD_FLAG_INIT != 0,
        more: flags & DBD_FLAG_MORE != 0,
        master: flags & DBD_FLAG_MASTER != 0,
        dd_sequence_number,
        lsa_headers,
    })
}

/// Encodes `pkt` as an LSR packet.
pub fn encode_lsr(pkt: &LsrPacket) -> Vec<u8> {
    let mut body = Vec::with_capacity(pkt.requests.len() * lsa::KEY_LEN);
    for key in &pkt.requests {
        lsa::encode_key(&mut body, key);
    }
    encode_packet(TYPE_LSR, pkt.router_id, pkt.area_id, &body)
}

/// Decodes an LSR packet, validating the common header first.
pub fn decode_lsr(data: &[u8]) -> Result<LsrPacket, PacketError> {
    let (packet_type, router_id, area_id, body) = decode_header(data)?;
    if packet_type != TYPE_LSR {
        return Err(PacketError::UnknownType(packet_type));
    }
    if !body.len().is_multiple_of(lsa::KEY_LEN) {
        return Err(PacketError::TruncatedBody);
    }
    let requests = body
        .as_chunks::<{ lsa::KEY_LEN }>()
        .0
        .iter()
        .map(|c| lsa::decode_key(c))
        .collect();
    Ok(LsrPacket {
        router_id,
        area_id,
        requests,
    })
}

/// Encodes `pkt` as an LSU packet.
pub fn encode_lsu(pkt: &LsuPacket) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        &u32::try_from(pkt.lsas.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for l in &pkt.lsas {
        body.extend_from_slice(&lsa::encode_lsa(l));
    }
    encode_packet(TYPE_LSU, pkt.router_id, pkt.area_id, &body)
}

/// Decodes an LSU packet, validating the common header first.
pub fn decode_lsu(data: &[u8]) -> Result<LsuPacket, PacketError> {
    let (packet_type, router_id, area_id, body) = decode_header(data)?;
    if packet_type != TYPE_LSU {
        return Err(PacketError::UnknownType(packet_type));
    }
    if body.len() < 4 {
        return Err(PacketError::TruncatedBody);
    }
    let count = usize::try_from(u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
        .unwrap_or(usize::MAX);
    let mut rest = &body[4..];
    let mut lsas = Vec::with_capacity(count.min(rest.len() / lsa::LSA_HEADER_LEN + 1));
    let mut seen = 0;
    let mut discarded = 0;
    let mut last_error = None;
    while !rest.is_empty() {
        seen += 1;
        // An unframeable header ends the packet; any later per-LSA error only
        // skips that LSA (RFC 2328 §13 steps 1-2) so the sender retransmits
        // just it, not the whole LSU forever.
        let len = usize::from(lsa::decode_lsa_header(rest)?.length);
        if len < lsa::LSA_HEADER_LEN || len > rest.len() {
            return Err(PacketError::TruncatedBody);
        }
        match lsa::decode_lsa(&rest[..len]) {
            Ok(l) => lsas.push(l),
            Err(e) => {
                discarded += 1;
                last_error = Some(e);
            }
        }
        rest = &rest[len..];
    }
    if seen != count {
        return Err(PacketError::TruncatedBody);
    }
    Ok(LsuPacket {
        router_id,
        area_id,
        lsas,
        discarded,
        last_error,
    })
}

/// Encodes `pkt` as an `LSAck` packet.
pub fn encode_lsack(pkt: &LsAckPacket) -> Vec<u8> {
    let mut body = Vec::with_capacity(pkt.lsa_headers.len() * lsa::LSA_HEADER_LEN);
    for header in &pkt.lsa_headers {
        lsa::encode_lsa_header(&mut body, header);
    }
    encode_packet(TYPE_LSACK, pkt.router_id, pkt.area_id, &body)
}

/// Decodes an `LSAck` packet, validating the common header first.
pub fn decode_lsack(data: &[u8]) -> Result<LsAckPacket, PacketError> {
    let (packet_type, router_id, area_id, body) = decode_header(data)?;
    if packet_type != TYPE_LSACK {
        return Err(PacketError::UnknownType(packet_type));
    }
    if !body.len().is_multiple_of(lsa::LSA_HEADER_LEN) {
        return Err(PacketError::TruncatedBody);
    }
    let lsa_headers = body
        .as_chunks::<{ lsa::LSA_HEADER_LEN }>()
        .0
        .iter()
        .map(|c| lsa::decode_lsa_header(c))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LsAckPacket {
        router_id,
        area_id,
        lsa_headers,
    })
}

/// Encodes any `OSPFv3` packet by dispatching to its type's own encoder.
pub fn encode(pkt: &OspfPacket) -> Vec<u8> {
    match pkt {
        OspfPacket::Hello(p) => encode_hello(p),
        OspfPacket::Dbd(p) => encode_dbd(p),
        OspfPacket::Lsr(p) => encode_lsr(p),
        OspfPacket::Lsu(p) => encode_lsu(p),
        OspfPacket::LsAck(p) => encode_lsack(p),
    }
}

/// Decodes any `OSPFv3` packet by reading the common header's type byte and
/// dispatching to that type's own decoder.
pub fn decode(data: &[u8]) -> Result<OspfPacket, PacketError> {
    if data.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    match data[1] {
        TYPE_HELLO => decode_hello(data).map(OspfPacket::Hello),
        TYPE_DBD => decode_dbd(data).map(OspfPacket::Dbd),
        TYPE_LSR => decode_lsr(data).map(OspfPacket::Lsr),
        TYPE_LSU => decode_lsu(data).map(OspfPacket::Lsu),
        TYPE_LSACK => decode_lsack(data).map(OspfPacket::LsAck),
        other => Err(PacketError::UnknownType(other)),
    }
}

/// The `router_id` any `OspfPacket` variant carries.
pub fn router_id(pkt: &OspfPacket) -> Ipv4Addr {
    match pkt {
        OspfPacket::Hello(p) => p.router_id,
        OspfPacket::Dbd(p) => p.router_id,
        OspfPacket::Lsr(p) => p.router_id,
        OspfPacket::Lsu(p) => p.router_id,
        OspfPacket::LsAck(p) => p.router_id,
    }
}

/// The OSPF header type byte of `pkt` (RFC 5340 §A.3.1).
pub fn packet_type(pkt: &OspfPacket) -> u8 {
    match pkt {
        OspfPacket::Hello(_) => TYPE_HELLO,
        OspfPacket::Dbd(_) => TYPE_DBD,
        OspfPacket::Lsr(_) => TYPE_LSR,
        OspfPacket::Lsu(_) => TYPE_LSU,
        OspfPacket::LsAck(_) => TYPE_LSACK,
    }
}

/// Builds the 16-byte common header (§A.3.1) around `body`. The checksum
/// field is always written as `0` — see this module's own doc comment for
/// why (`socket.rs`'s `IPV6_CHECKSUM` sockopt handles it at the kernel
/// level).
fn encode_packet(packet_type: u8, router_id: Ipv4Addr, area_id: Ipv4Addr, body: &[u8]) -> Vec<u8> {
    let total_len = HEADER_LEN + body.len();
    let mut buf = Vec::with_capacity(total_len);
    buf.push(VERSION);
    buf.push(packet_type);
    // Always fits: `total_len` is `HEADER_LEN` plus a handful of entries,
    // nowhere near `u16::MAX`.
    buf.extend_from_slice(&u16::try_from(total_len).unwrap_or(u16::MAX).to_be_bytes());
    buf.extend_from_slice(&router_id.octets());
    buf.extend_from_slice(&area_id.octets());
    buf.extend_from_slice(&0u16.to_be_bytes()); // checksum, kernel-filled
    buf.push(0); // instance id, stamped per link by `set_instance_id`
    buf.push(0); // reserved
    buf.extend_from_slice(body);
    debug_assert_eq!(buf.len(), total_len);
    buf
}

/// Validates the common header's version and `Length`, returning
/// `(packet_type, router_id, area_id, body)` — the body bounded by `Length`,
/// so bytes after it (an RFC 7166 trailer, already verified by
/// `verify_trailer`) never reach a body decoder.
fn decode_header(data: &[u8]) -> Result<(u8, Ipv4Addr, Ipv4Addr, &[u8]), PacketError> {
    if data.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    let version = data[0];
    if version != VERSION {
        return Err(PacketError::BadVersion(version));
    }
    let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if length < HEADER_LEN || data.len() < length {
        return Err(PacketError::TruncatedBody);
    }
    let router_id = read_ipv4(data, 4);
    let area_id = read_ipv4(data, 8);
    Ok((data[1], router_id, area_id, &data[HEADER_LEN..length]))
}

pub(crate) fn read_ipv4(data: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LsaBody, RouterLsaBody, LSA_TYPE_ROUTER};
    use crate::packet;

    fn sample() -> HelloPacket {
        HelloPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_id: 3,
            router_priority: 1,
            options: lsa::OPTION_V6 | lsa::OPTION_R,
            hello_interval: 10,
            dead_interval: 40,
            designated_router: Ipv4Addr::new(9, 9, 9, 9),
            backup_designated_router: Ipv4Addr::new(9, 9, 9, 10),
            neighbors: vec![Ipv4Addr::new(9, 9, 9, 10)],
        }
    }

    fn sample_dbd() -> DbdPacket {
        DbdPacket {
            lls: None,
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            options: lsa::OPTION_V6 | lsa::OPTION_R,
            interface_mtu: 1500,
            init: true,
            more: true,
            master: true,
            dd_sequence_number: 42,
            lsa_headers: vec![LsaHeader {
                age: 1,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0x1234,
                length: 24,
            }],
        }
    }

    fn sample_lsr() -> LsrPacket {
        LsrPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            requests: vec![LsaKey {
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 10),
                advertising_router: Ipv4Addr::new(9, 9, 9, 10),
            }],
        }
    }

    fn sample_lsu() -> LsuPacket {
        LsuPacket {
            discarded: 0,
            last_error: None,
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsas: vec![Lsa {
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
                    options: lsa::OPTION_V6 | lsa::OPTION_R,
                    links: Vec::new(),
                }),
            }],
        }
    }

    fn sample_lsack() -> LsAckPacket {
        LsAckPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsa_headers: vec![LsaHeader {
                age: 1,
                lsa_type: LSA_TYPE_ROUTER,
                link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                sequence_number: 0x8000_0001u32.cast_signed(),
                checksum: 0x1234,
                length: 24,
            }],
        }
    }

    #[test]
    fn hello_round_trip_with_one_neighbor() {
        let pkt = sample();
        let decoded = decode_hello(&encode_hello(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hello_round_trip_with_no_neighbors() {
        let mut pkt = sample();
        pkt.neighbors = Vec::new();
        let decoded = decode_hello(&encode_hello(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hello_round_trip_preserves_dr_bdr_as_router_ids() {
        let pkt = sample();
        let decoded = decode_hello(&encode_hello(&pkt)).unwrap();
        assert_eq!(decoded.designated_router, pkt.designated_router);
        assert_eq!(
            decoded.backup_designated_router,
            pkt.backup_designated_router
        );
        assert_eq!(decoded.interface_id, pkt.interface_id);
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert_eq!(decode_hello(&[0u8; 10]), Err(PacketError::Truncated));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut encoded = encode_hello(&sample());
        encoded[0] = 2;
        assert_eq!(decode_hello(&encoded), Err(PacketError::BadVersion(2)));
    }

    #[test]
    fn wrong_type_is_rejected() {
        let mut encoded = encode_hello(&sample());
        encoded[1] = TYPE_DBD;
        assert_eq!(
            decode_hello(&encoded),
            Err(PacketError::UnknownType(TYPE_DBD))
        );
    }

    #[test]
    fn hello_truncated_body_is_rejected() {
        let mut encoded = encode_hello(&sample());
        encoded.truncate(HEADER_LEN + HELLO_BODY_FIXED_LEN + 2);
        assert_eq!(decode_hello(&encoded), Err(PacketError::TruncatedBody));
    }

    #[test]
    fn dbd_round_trips() {
        let pkt = sample_dbd();
        let decoded = decode_dbd(&encode_dbd(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn dbd_flags_are_independent() {
        let mut pkt = sample_dbd();
        pkt.init = false;
        pkt.more = true;
        pkt.master = false;
        let decoded = decode_dbd(&encode_dbd(&pkt)).unwrap();
        assert!(!decoded.init);
        assert!(decoded.more);
        assert!(!decoded.master);
    }

    #[test]
    fn lsr_round_trips() {
        let pkt = sample_lsr();
        let decoded = decode_lsr(&encode_lsr(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn lsu_round_trips() {
        let pkt = sample_lsu();
        let decoded = decode_lsu(&encode_lsu(&pkt)).unwrap();
        assert_eq!(decoded.router_id, pkt.router_id);
        assert_eq!(decoded.lsas.len(), pkt.lsas.len());
        assert_eq!(decoded.lsas[0].body, pkt.lsas[0].body);
    }

    fn lsu_good_bad_good(bad: Vec<u8>) -> Vec<u8> {
        let pkt = sample_lsu();
        let mut body = 3u32.to_be_bytes().to_vec();
        body.extend(lsa::encode_lsa(&pkt.lsas[0]));
        body.extend(bad);
        body.extend(lsa::encode_lsa(&pkt.lsas[0]));
        encode_packet(TYPE_LSU, pkt.router_id, pkt.area_id, &body)
    }

    /// Valid checksum, unparseable body (#645): discarded alone, counted.
    #[test]
    fn lsu_skips_a_malformed_body_lsa_and_counts_it() {
        let pkt = sample_lsu();
        let mut bad = lsa::encode_lsa(&pkt.lsas[0]);
        bad.push(0); // stray byte: not a whole number of 16-byte links
        let len = u16::try_from(bad.len()).unwrap();
        bad[18..20].copy_from_slice(&len.to_be_bytes());
        let sum = lsa::lsa_checksum(&bad[2..]);
        bad[16..18].copy_from_slice(&sum.to_be_bytes());
        let decoded = decode_lsu(&lsu_good_bad_good(bad)).unwrap();
        assert_eq!(decoded.lsas.len(), 2);
        assert_eq!(decoded.discarded, 1);
        assert_eq!(decoded.last_error, Some(PacketError::TruncatedBody));
    }

    #[test]
    fn lsu_counts_a_bad_checksum_lsa() {
        let pkt = sample_lsu();
        let mut bad = lsa::encode_lsa(&pkt.lsas[0]);
        bad[16] ^= 0xFF;
        let decoded = decode_lsu(&lsu_good_bad_good(bad)).unwrap();
        assert_eq!(decoded.lsas.len(), 2);
        assert_eq!(decoded.discarded, 1);
        assert_eq!(decoded.last_error, Some(PacketError::BadChecksum));
    }

    #[test]
    fn lsu_with_an_overlong_lsa_header_length_is_dropped_whole() {
        let pkt = sample_lsu();
        let mut bad = lsa::encode_lsa(&pkt.lsas[0]);
        bad[18..20].copy_from_slice(&0x7FFFu16.to_be_bytes());
        assert_eq!(
            decode_lsu(&lsu_good_bad_good(bad)),
            Err(PacketError::TruncatedBody)
        );
    }

    #[test]
    fn lsu_rejects_count_mismatch() {
        let mut encoded = encode_lsu(&sample_lsu());
        let last_idx = HEADER_LEN + 3;
        encoded[last_idx] = 3;
        assert_eq!(decode_lsu(&encoded), Err(PacketError::TruncatedBody));
    }

    #[test]
    fn lsack_round_trips() {
        let pkt = sample_lsack();
        let decoded = decode_lsack(&encode_lsack(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn dispatch_decodes_each_type_by_header_byte() {
        assert!(matches!(
            decode(&encode_hello(&sample())).unwrap(),
            OspfPacket::Hello(_)
        ));
        assert!(matches!(
            decode(&encode_dbd(&sample_dbd())).unwrap(),
            OspfPacket::Dbd(_)
        ));
        assert!(matches!(
            decode(&encode_lsr(&sample_lsr())).unwrap(),
            OspfPacket::Lsr(_)
        ));
        assert!(matches!(
            decode(&encode_lsu(&sample_lsu())).unwrap(),
            OspfPacket::Lsu(_)
        ));
        assert!(matches!(
            decode(&encode_lsack(&sample_lsack())).unwrap(),
            OspfPacket::LsAck(_)
        ));
    }

    #[test]
    fn dispatch_encode_round_trips_through_top_level_enum() {
        let pkt = OspfPacket::Dbd(sample_dbd());
        let decoded = decode(&encode(&pkt)).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn instance_id_round_trips() {
        let mut encoded = encode_hello(&sample());
        assert_eq!(instance_id(&encoded), Some(0));
        set_instance_id(&mut encoded, 31);
        assert_eq!(instance_id(&encoded), Some(31));
        assert_eq!(
            encoded[12..16],
            [0, 0, 31, 0],
            "checksum, instance id, reserved"
        );
        assert_eq!(decode(&encoded).unwrap(), OspfPacket::Hello(sample()));
        assert_eq!(instance_id(&encoded[..HEADER_LEN - 1]), None);
    }

    const SRC: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    fn auth() -> TrailerAuth {
        TrailerAuth {
            keys: vec![
                (300, CryptoAlgorithm::HmacSha256, b"secret".to_vec()),
                (2, CryptoAlgorithm::HmacSha1, b"other".to_vec()),
            ],
            current_key_id: 300,
        }
    }

    fn signed(pkt: &OspfPacket, sequence: u64) -> Vec<u8> {
        let mut buf = encode(pkt);
        auth().sign(&mut buf, sequence, SRC);
        buf
    }

    fn with_at(mut hello: HelloPacket) -> HelloPacket {
        hello.options |= lsa::OPTION_AT;
        hello
    }

    #[test]
    fn trailer_round_trips_every_packet_type_with_16_bit_sa_id() {
        let mut dbd = sample_dbd();
        dbd.options |= lsa::OPTION_AT;
        for pkt in [
            OspfPacket::Hello(with_at(sample())),
            OspfPacket::Dbd(dbd),
            OspfPacket::Lsr(sample_lsr()),
            OspfPacket::Lsu(sample_lsu()),
            OspfPacket::LsAck(sample_lsack()),
        ] {
            let wire = signed(&pkt, 42);
            let (inner, seq) = verify_trailer(&wire, Some(&auth()), SRC).unwrap();
            assert_eq!(seq, Some(42));
            assert_eq!(inner.len(), encode(&pkt).len());
            let decoded = decode(inner).unwrap();
            assert_eq!(packet::router_id(&decoded), packet::router_id(&pkt));
            if !matches!(pkt, OspfPacket::Lsu(_)) {
                assert_eq!(decoded, pkt);
            }
        }
    }

    #[test]
    fn trailer_layout_matches_rfc_7166_figure_3() {
        let pkt = OspfPacket::Hello(with_at(sample()));
        let wire = signed(&pkt, (7u64 << 32) | 9);
        let length = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
        let t = &wire[length..];
        assert_eq!(u16::from_be_bytes([t[0], t[1]]), AUTH_TYPE_HMAC);
        assert_eq!(u16::from_be_bytes([t[2], t[3]]), 16 + 32);
        assert_eq!(&t[4..6], &[0, 0]);
        assert_eq!(u16::from_be_bytes([t[6], t[7]]), 300);
        assert_eq!(&t[8..16], &[0, 0, 0, 7, 0, 0, 0, 9]);
        assert_eq!(t.len(), 16 + 32);
        // The checksum field stays zero (RFC 7166 §4.2).
        assert_eq!(&wire[12..14], &[0, 0]);
    }

    #[test]
    fn digest_is_hmac_of_packet_and_trailer_header_with_apad_under_protocol_id_key() {
        let pkt = OspfPacket::Hello(with_at(sample()));
        let wire = signed(&pkt, 1);
        let (signed_part, digest) = wire.split_at(wire.len() - 32);
        // §4.5 step 1: Ks = key || 0x0001, zero-padded to L = 32.
        let mut ko = b"secret".to_vec();
        ko.extend_from_slice(&[0x00, 0x01]);
        ko.resize(32, 0);
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&ko).unwrap();
        mac.update(signed_part);
        mac.update(&SRC.octets());
        mac.update(&[0x87, 0x8F, 0xE1, 0xF3].repeat(4));
        assert_eq!(digest, &mac.finalize().into_bytes()[..]);
    }

    #[test]
    fn long_key_is_hashed_down_to_digest_length() {
        let long = vec![b'k'; 40];
        let ko = CryptoAlgorithm::HmacSha256.prepared_key(&long);
        let mut ks = long;
        ks.extend_from_slice(&[0, 1]);
        assert_eq!(ko, sha2::Sha256::digest(&ks).to_vec());
        assert_eq!(CryptoAlgorithm::HmacSha1.prepared_key(b"abc"), {
            let mut k = b"abc\x00\x01".to_vec();
            k.resize(20, 0);
            k
        });
    }

    #[test]
    fn bad_key_digest_sequence_source_or_sa_id_fail() {
        let pkt = OspfPacket::Hello(with_at(sample()));
        let wire = signed(&pkt, 5);
        let wrong_key = TrailerAuth {
            keys: vec![(300, CryptoAlgorithm::HmacSha256, b"nope".to_vec())],
            current_key_id: 300,
        };
        assert_eq!(
            verify_trailer(&wire, Some(&wrong_key), SRC),
            Err(PacketError::AuthFailed)
        );
        let unknown_id = TrailerAuth {
            keys: vec![(1, CryptoAlgorithm::HmacSha256, b"secret".to_vec())],
            current_key_id: 1,
        };
        assert_eq!(
            verify_trailer(&wire, Some(&unknown_id), SRC),
            Err(PacketError::AuthFailed)
        );
        let other_src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        assert_eq!(
            verify_trailer(&wire, Some(&auth()), other_src),
            Err(PacketError::AuthFailed)
        );
        let n = wire.len();
        let mut tampered = wire.clone();
        tampered[n - 1] ^= 1; // digest
        assert_eq!(
            verify_trailer(&tampered, Some(&auth()), SRC),
            Err(PacketError::AuthFailed)
        );
        let mut tampered = wire.clone();
        tampered[n - 33] ^= 1; // sequence low bit
        assert_eq!(
            verify_trailer(&tampered, Some(&auth()), SRC),
            Err(PacketError::AuthFailed)
        );
        let mut tampered = wire;
        tampered[HEADER_LEN] ^= 1; // packet body
        assert_eq!(
            verify_trailer(&tampered, Some(&auth()), SRC),
            Err(PacketError::AuthFailed)
        );
    }

    #[test]
    fn at_bit_and_configured_auth_must_agree() {
        // AT set, link unauthenticated.
        let wire = signed(&OspfPacket::Hello(with_at(sample())), 1);
        assert_eq!(
            verify_trailer(&wire, None, SRC),
            Err(PacketError::AuthTypeMismatch)
        );
        // Link authenticated, Hello without the AT-bit.
        let wire = signed(&OspfPacket::Hello(sample()), 1);
        assert_eq!(
            verify_trailer(&wire, Some(&auth()), SRC),
            Err(PacketError::AuthTypeMismatch)
        );
        // Link authenticated, an LSR (no Options field) with no trailer.
        let wire = encode_lsr(&sample_lsr());
        assert_eq!(
            verify_trailer(&wire, Some(&auth()), SRC),
            Err(PacketError::AuthTypeMismatch)
        );
        // Unauthenticated both sides: passes through untouched.
        let wire = encode_hello(&sample());
        assert_eq!(verify_trailer(&wire, None, SRC), Ok((&wire[..], None)));
    }

    #[test]
    fn decode_ignores_bytes_after_length() {
        let mut wire = encode_hello(&sample());
        wire.extend_from_slice(&[0xAA; 7]);
        assert_eq!(decode_hello(&wire).unwrap(), sample());
        let mut short = encode_hello(&sample());
        short.pop();
        assert_eq!(decode_hello(&short), Err(PacketError::TruncatedBody));
    }

    /// Hand-written packet: 16-byte header (declared length = real length) + `body`.
    fn raw(ty: u8, body: &[u8]) -> Vec<u8> {
        let len = u16::try_from(HEADER_LEN + body.len()).unwrap();
        let mut v = vec![VERSION, ty];
        v.extend(len.to_be_bytes());
        v.extend([9, 9, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0]); // router, area, cksum/instance/rsvd
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn decode_header_boundary_length() {
        let pkt = raw(TYPE_HELLO, &[]);
        assert_eq!(pkt.len(), HEADER_LEN);
        assert_eq!(decode_header(&pkt).unwrap().3, &[] as &[u8]);
        assert_eq!(
            decode_header(&pkt[..HEADER_LEN - 1]),
            Err(PacketError::Truncated)
        );
        // Declared length below the header, and above the data.
        let mut bad = pkt.clone();
        bad[3] = u8::try_from(HEADER_LEN).unwrap() - 1;
        assert_eq!(decode_header(&bad), Err(PacketError::TruncatedBody));
        bad[3] = u8::try_from(HEADER_LEN).unwrap() + 1;
        assert_eq!(decode_header(&bad), Err(PacketError::TruncatedBody));
    }

    #[test]
    fn dbd_fixed_part_fields_and_flags() {
        // rsvd, options 0x01_0203, MTU 0x0405, rsvd, flags, DD sequence 0x0a0b0c0d.
        let body = |flags: u8| [0, 1, 2, 3, 4, 5, 0, flags, 0x0a, 0x0b, 0x0c, 0x0d];
        let d = decode_dbd(&raw(TYPE_DBD, &body(0x07))).unwrap();
        assert_eq!(
            (d.options, d.interface_mtu, d.dd_sequence_number),
            (0x01_0203, 0x0405, 0x0a0b_0c0d)
        );
        assert!(d.init && d.more && d.master);
        for (flags, want) in [
            (DBD_FLAG_INIT, (true, false, false)),
            (DBD_FLAG_MORE, (false, true, false)),
            (DBD_FLAG_MASTER, (false, false, true)),
            (0, (false, false, false)),
        ] {
            let d = decode_dbd(&raw(TYPE_DBD, &body(flags))).unwrap();
            assert_eq!((d.init, d.more, d.master), want, "flags {flags:#x}");
        }
    }

    #[test]
    fn dbd_body_exact_fixed_part_and_lsa_header_multiples() {
        let fixed = [0u8; DBD_BODY_FIXED_LEN];
        let got = decode_dbd(&raw(TYPE_DBD, &fixed)).unwrap();
        assert_eq!(got.lsa_headers.len(), 0);
        assert_eq!(
            decode_dbd(&raw(TYPE_DBD, &fixed[..DBD_BODY_FIXED_LEN - 1])),
            Err(PacketError::TruncatedBody)
        );
        let with_one = [&fixed[..], &[0u8; lsa::LSA_HEADER_LEN]].concat();
        assert_eq!(
            decode_dbd(&raw(TYPE_DBD, &with_one))
                .unwrap()
                .lsa_headers
                .len(),
            1
        );
        // One byte short of, and one byte past, a whole LSA header.
        assert_eq!(
            decode_dbd(&raw(TYPE_DBD, &with_one[..with_one.len() - 1])),
            Err(PacketError::TruncatedBody)
        );
        let mut over = with_one.clone();
        over.push(0);
        assert_eq!(
            decode_dbd(&raw(TYPE_DBD, &over)),
            Err(PacketError::TruncatedBody)
        );
    }

    // RFC 7166 section 4.1: the trailer starts at the header's Length; the
    // Length field is bounds-checked before it is trusted.
    fn signed_lsr(requests: usize) -> Vec<u8> {
        let mut lsr = sample_lsr();
        lsr.requests.truncate(requests);
        signed(&OspfPacket::Lsr(lsr), 3)
    }

    fn set_length(wire: &mut [u8], length: usize) {
        wire[2..4].copy_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    }

    #[test]
    fn trailer_length_field_boundary() {
        let wire = signed_lsr(1);
        let a = auth();
        for bad in [0, HEADER_LEN - 1, wire.len() + 1] {
            let mut w = wire.clone();
            set_length(&mut w, bad);
            assert_eq!(
                verify_trailer(&w, Some(&a), SRC),
                Err(PacketError::TruncatedBody),
                "length={bad}"
            );
        }
    }

    #[test]
    fn header_only_packet_with_trailer_verifies() {
        let wire = signed_lsr(0);
        assert_eq!(
            usize::from(u16::from_be_bytes([wire[2], wire[3]])),
            HEADER_LEN
        );
        assert_eq!(
            verify_trailer(&wire, Some(&auth()), SRC),
            Ok((&wire[..HEADER_LEN], Some(3)))
        );
    }

    #[test]
    fn short_trailer_is_auth_type_mismatch_and_digestless_is_truncated() {
        let wire = signed_lsr(1);
        let length = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
        // Fewer than the 16 trailer-header bytes (type bytes still present
        // for n >= 2): cannot be an authentication trailer.
        for n in [0, 2, TRAILER_HEADER_LEN - 1] {
            assert_eq!(
                verify_trailer(&wire[..length + n], Some(&auth()), SRC),
                Err(PacketError::AuthTypeMismatch),
                "trailer bytes={n}"
            );
        }
        // Right type, full header, digest missing.
        assert_eq!(
            verify_trailer(&wire[..length + TRAILER_HEADER_LEN], Some(&auth()), SRC),
            Err(PacketError::TruncatedBody)
        );
    }

    #[test]
    fn trailer_with_wrong_auth_type_is_auth_type_mismatch() {
        let wire = signed_lsr(1);
        let length = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
        for ty in [0u16, 2] {
            let mut w = wire.clone();
            w[length..length + 2].copy_from_slice(&ty.to_be_bytes());
            assert_eq!(
                verify_trailer(&w, Some(&auth()), SRC),
                Err(PacketError::AuthTypeMismatch),
                "type={ty}"
            );
        }
    }

    #[test]
    fn datagram_shorter_than_header_is_truncated_and_bare_header_has_no_trailer() {
        let wire = signed_lsr(0);
        for n in [0, 1, 2, 10, HEADER_LEN - 1] {
            assert_eq!(
                verify_trailer(&wire[..n], Some(&auth()), SRC),
                Err(PacketError::Truncated),
                "len={n}"
            );
            // No auth configured: handed to `decode` untouched.
            assert_eq!(
                verify_trailer(&wire[..n], None, SRC),
                Ok((&wire[..n], None))
            );
        }
        // Exactly the header, Length == HEADER_LEN, but no trailer after it.
        assert_eq!(
            verify_trailer(&wire[..HEADER_LEN], Some(&auth()), SRC),
            Err(PacketError::AuthTypeMismatch)
        );
    }
}
