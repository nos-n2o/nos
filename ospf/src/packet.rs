//! RFC 2328 `OSPFv2` wire format — the common packet header (Appendix A.3.1)
//! shared by every packet type, plus each type's own body: Hello (A.3.2),
//! Database Description (A.3.3), Link State Request (A.3.4), Link State
//! Update (A.3.5), and Link State Acknowledgment (A.3.6), plus RFC 2328
//! Appendix D authentication (Null/Simple/Cryptographic) and its RFC 5709
//! HMAC-SHA extension. Pure encode/decode, no I/O — `socket.rs` sends/
//! receives the bytes this module produces/consumes. Digest computation and
//! password/digest verification stay in this module (matching the wire
//! format they're part of), but RFC 2328's stateful anti-replay sequence
//! check does not — see `crypto_sequence`'s doc comment.

use std::net::Ipv4Addr;

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use thiserror::Error;

use crate::lsa::{self, Lsa, LsaHeader, LsaKey};

pub const VERSION: u8 = 2;
pub const TYPE_HELLO: u8 = 1;
pub const TYPE_DBD: u8 = 2;
pub const TYPE_LSR: u8 = 3;
pub const TYPE_LSU: u8 = 4;
pub const TYPE_LSACK: u8 = 5;

/// RFC 2328 Appendix D's `AuType` field values.
pub const AUTH_TYPE_NULL: u16 = 0;
pub const AUTH_TYPE_SIMPLE: u16 = 1;
pub const AUTH_TYPE_CRYPTO: u16 = 2;
/// RFC 7474's extended cryptographic authentication: 32-bit Key ID, a 64-bit
/// (boot count : sequence) number in the 8 octets after the packet, and the
/// IP source address folded into the digest's `Apad`.
pub const AUTH_TYPE_CRYPTO_EXT: u16 = 3;

/// RFC 2328 Appendix A.2's `E` (`ExternalRoutingCapability`) Options bit —
/// checked by `handle_hello`'s RFC 2328 §10.5 packet-validity check: clear
/// in a stub area or NSSA, set otherwise, and a peer's must match.
pub const OPTION_E: u8 = 0x02;
/// RFC 3101 §2.1's N-bit in Hellos: set exactly in an NSSA, and a peer's must
/// match. The same bit is the P-bit in an LSA header (`lsa::OPTION_P`).
pub const OPTION_N: u8 = 0x08;
/// RFC 5250 §3's `O` bit: "I store and flood opaque LSAs". Set in DBDs only
/// (it SHOULD NOT be set in Hellos), read from the peer's DBD.
pub const OPTION_O: u8 = 0x40;

const HEADER_LEN: usize = 24;
/// Hello body length excluding the trailing neighbor list: network mask,
/// hello-interval, options, router-priority, router-dead-interval,
/// designated-router, and backup-designated-router (4+2+1+1+4+4+4 bytes).
const HELLO_BODY_FIXED_LEN: usize = 20;
/// DBD body length excluding the trailing LSA-header summary list: interface
/// MTU, options, flags, DD sequence number (2+1+1+4 bytes).
const DBD_BODY_FIXED_LEN: usize = 8;

const DBD_FLAG_MASTER: u8 = 0x01;
const DBD_FLAG_MORE: u8 = 0x02;
const DBD_FLAG_INIT: u8 = 0x04;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("packet shorter than the 24-byte OSPF header")]
    Truncated,
    #[error("not an OSPFv2 packet (version {0})")]
    BadVersion(u8),
    #[error("unrecognized OSPF packet type {0}")]
    UnknownType(u8),
    #[error("unrecognized LSA type {0}")]
    UnknownLsaType(u8),
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("packet body shorter than expected")]
    TruncatedBody,
    #[error("packet's AuType doesn't match this link's configured auth")]
    AuthTypeMismatch,
    #[error("authentication failed (wrong password, unknown key-id, or bad digest)")]
    AuthFailed,
}

/// RFC 2328 Appendix D's original Cryptographic authentication (plain MD5)
/// plus RFC 5709's HMAC-SHA extension — every wire AuType-2 packet's
/// Authentication field carries only a Key ID, never an algorithm, so the
/// Key ID alone must determine it. This module's own mirror of
/// `nos_proto::OspfCryptoAlgorithm` — kept dependency-free of `nos-proto`
/// like the rest of this "pure, no I/O" wire-format module; `link.rs`
/// converts between the two at the config boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    /// RFC 2328 Appendix D.3/D.4.3: `MD5(packet || key)`, plain
    /// concatenation, not real HMAC. 16-byte digest.
    Md5,
    /// RFC 5709: real HMAC-SHA-1. 20-byte digest.
    HmacSha1,
    /// RFC 5709: real HMAC-SHA-256. 32-byte digest.
    HmacSha256,
    /// RFC 5709: real HMAC-SHA-384. 48-byte digest.
    HmacSha384,
    /// RFC 5709: real HMAC-SHA-512. 64-byte digest.
    HmacSha512,
}

impl CryptoAlgorithm {
    /// The digest length this algorithm produces — also the wire's Auth
    /// Data Length byte's expected value for a packet signed with it.
    pub(crate) fn digest_len(self) -> usize {
        match self {
            CryptoAlgorithm::Md5 => 16,
            CryptoAlgorithm::HmacSha1 => 20,
            CryptoAlgorithm::HmacSha256 => 32,
            CryptoAlgorithm::HmacSha384 => 48,
            CryptoAlgorithm::HmacSha512 => 64,
        }
    }

    /// Computes this algorithm's digest of `data` under `key`. `data` is
    /// the packet's own bytes (header, with `AuType`/Key ID/Auth Data
    /// Length/sequence number already filled in and checksum left at
    /// zero, plus body) — never the trailing digest itself.
    fn digest(self, data: &[u8], key: &[u8]) -> Vec<u8> {
        // HMAC's key-length handling (short keys zero-padded, long keys
        // hashed down first) means it's defined for every key length — the
        // `new_from_slice` calls below never actually fail.
        match self {
            CryptoAlgorithm::Md5 => {
                // RFC 2328 D.4.3 (a): "the 16 byte MD5 key is appended" — a
                // shorter key is zero-padded, a longer one truncated.
                let mut md5_key = [0u8; 16];
                let n = key.len().min(16);
                md5_key[..n].copy_from_slice(&key[..n]);
                // nosemgrep: rust.lang.security.insecure-hashes.insecure-hashes -- RFC 2328 Appendix D.3 cryptographic authentication is keyed MD5 by definition, a wire-compatibility requirement not a choice (RFC 5709 HMAC-SHA is the recommended alternative and already implemented above).
                let mut hasher = Md5::new();
                hasher.update(data);
                hasher.update(md5_key);
                hasher.finalize().to_vec()
            }
            CryptoAlgorithm::HmacSha1 => {
                let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key)
                    .expect("hmac accepts a key of any length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            CryptoAlgorithm::HmacSha256 => {
                let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key)
                    .expect("hmac accepts a key of any length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            CryptoAlgorithm::HmacSha384 => {
                let mut mac = Hmac::<sha2::Sha384>::new_from_slice(key)
                    .expect("hmac accepts a key of any length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            CryptoAlgorithm::HmacSha512 => {
                let mut mac = Hmac::<sha2::Sha512>::new_from_slice(key)
                    .expect("hmac accepts a key of any length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// What to sign an outgoing packet with, resolved once per link from its
/// `OspfProfile.auth` — plus, for `Crypto`, this send's own non-decreasing
/// sequence number (RFC 2328 D.4.3's anti-replay field), since that's
/// per-packet, not per-link-config.
pub enum OutgoingAuth<'a> {
    None,
    Simple {
        password: &'a [u8],
    },
    Crypto {
        key_id: u16,
        algorithm: CryptoAlgorithm,
        key: &'a [u8],
        /// `AuType` 2's 32-bit number (widened), or, with `extended`, RFC
        /// 7474's full 64-bit boot-count-and-counter value.
        sequence: u64,
        /// `Some(ip source address)` selects RFC 7474 (`AuType` 3).
        extended: Option<Ipv4Addr>,
    },
}

/// What to verify an incoming packet against. `Crypto` carries every
/// currently-configured key (`key_id`, algorithm, secret) — RFC 2328 D.3's
/// key-rotation model looks up by the *wire's own* Key ID, not any single
/// "current" key.
pub enum AuthPolicy<'a> {
    None,
    Simple {
        password: &'a [u8],
    },
    /// `Vec<u8>` (not `&[u8]`) per key so a caller can borrow this directly
    /// from its own owned key list (e.g. `link::LinkAuthConfig`) with no
    /// intermediate allocation.
    Crypto {
        keys: &'a [(u16, CryptoAlgorithm, Vec<u8>)],
        /// `Some(source)` requires RFC 7474 (`AuType` 3, digest bound to
        /// `source` — the received packet's IP source); `None` requires
        /// RFC 2328's `AuType` 2. A wire/config mismatch is an
        /// `AuthTypeMismatch`.
        extended: Option<Ipv4Addr>,
    },
}

/// One Hello packet's contents. `network_mask`/`options` back
/// `ospf::link::rx::handle_hello`'s RFC 2328 §10.5 packet-validity check — the
/// mask is ignored by that check on a point-to-point/virtual link (RFC 2328
/// §10.5), and `options` only ever carries the `E`-bit meaningfully today
/// (see `OPTION_E`). `router_priority`/`designated_router`/
/// `backup_designated_router` are real fields, used by `ospf::election`'s
/// DR/BDR election on a `Broadcast` link (sent, but functionally inert, on a
/// `PointToPoint` one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub network_mask: Ipv4Addr,
    pub hello_interval: u16,
    pub options: u8,
    pub dead_interval: u32,
    pub router_priority: u8,
    pub designated_router: Ipv4Addr,
    pub backup_designated_router: Ipv4Addr,
    /// Router IDs this Hello lists as neighbors it has heard from. RFC 2328's
    /// full neighbor list — collapsed to 0 or 1 entries on a point-to-point
    /// link (which has at most one neighbor), but honestly a full list for
    /// a broadcast link's potentially many neighbors.
    pub neighbors: Vec<Ipv4Addr>,
}

/// One Database Description packet's contents (RFC 2328 Appendix A.3.3):
/// the shared `nos_ospf_common::exchange::Dbd`, whose `options` carries v2's
/// 8-bit Options in its low byte.
pub type DbdPacket = nos_ospf_common::exchange::Dbd<LsaHeader>;

/// One Link State Request packet's contents (RFC 2328 Appendix A.3.4) — the
/// LSAs the sender is missing and wants a full copy of via LSU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsrPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub requests: Vec<LsaKey>,
}

/// One Link State Update packet's contents (RFC 2328 Appendix A.3.5) — real
/// LSAs being flooded or sent in response to an LSR.
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

/// One Link State Acknowledgment packet's contents (RFC 2328 Appendix
/// A.3.6) — explicit ack of one or more received LSAs, by header only.
#[derive(Debug, Clone, PartialEq)]
pub struct LsAckPacket {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub lsa_headers: Vec<LsaHeader>,
}

/// Any one OSPF packet, tagged by its common-header type byte — the
/// dispatch point `socket::recv_packet`'s bytes are decoded through.
#[derive(Debug, Clone, PartialEq)]
pub enum OspfPacket {
    Hello(HelloPacket),
    Dbd(DbdPacket),
    Lsr(LsrPacket),
    Lsu(LsuPacket),
    LsAck(LsAckPacket),
}

/// Encodes `pkt` as a Hello packet, computing and filling in the checksum.
pub fn encode_hello(pkt: &HelloPacket, auth: &OutgoingAuth<'_>) -> Vec<u8> {
    let mut body = Vec::with_capacity(HELLO_BODY_FIXED_LEN + pkt.neighbors.len() * 4);
    body.extend_from_slice(&pkt.network_mask.octets());
    body.extend_from_slice(&pkt.hello_interval.to_be_bytes());
    body.push(pkt.options);
    body.push(pkt.router_priority);
    body.extend_from_slice(&pkt.dead_interval.to_be_bytes());
    body.extend_from_slice(&pkt.designated_router.octets());
    body.extend_from_slice(&pkt.backup_designated_router.octets());
    for n in &pkt.neighbors {
        body.extend_from_slice(&n.octets());
    }
    encode_packet(TYPE_HELLO, pkt.router_id, pkt.area_id, &body, auth)
}

/// Decodes a Hello packet, validating the common header and auth first.
pub fn decode_hello(data: &[u8], auth: &AuthPolicy<'_>) -> Result<HelloPacket, PacketError> {
    let (packet_type, router_id, area_id) = decode_header(data)?;
    if packet_type != TYPE_HELLO {
        return Err(PacketError::UnknownType(packet_type));
    }
    let body = verify_auth(data, auth)?;
    if body.len() < HELLO_BODY_FIXED_LEN {
        return Err(PacketError::TruncatedBody);
    }
    let network_mask = read_ipv4(body, 0);
    let hello_interval = u16::from_be_bytes([body[4], body[5]]);
    let options = body[6];
    let router_priority = body[7];
    let dead_interval = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
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
        network_mask,
        hello_interval,
        options,
        dead_interval,
        router_priority,
        designated_router,
        backup_designated_router,
        neighbors,
    })
}

/// Encodes `pkt` as a DBD packet.
pub fn encode_dbd(pkt: &DbdPacket, auth: &OutgoingAuth<'_>) -> Vec<u8> {
    let mut body =
        Vec::with_capacity(DBD_BODY_FIXED_LEN + pkt.lsa_headers.len() * lsa::LSA_HEADER_LEN);
    body.extend_from_slice(&pkt.interface_mtu.to_be_bytes());
    body.push(pkt.options.to_be_bytes()[3]);
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
    encode_packet(TYPE_DBD, pkt.router_id, pkt.area_id, &body, auth)
}

/// Decodes a DBD packet, validating the common header and auth first.
pub fn decode_dbd(data: &[u8], auth: &AuthPolicy<'_>) -> Result<DbdPacket, PacketError> {
    let (packet_type, router_id, area_id) = decode_header(data)?;
    if packet_type != TYPE_DBD {
        return Err(PacketError::UnknownType(packet_type));
    }
    let body = verify_auth(data, auth)?;
    if body.len() < DBD_BODY_FIXED_LEN {
        return Err(PacketError::TruncatedBody);
    }
    let interface_mtu = u16::from_be_bytes([body[0], body[1]]);
    let options = u32::from(body[2]);
    let flags = body[3];
    let dd_sequence_number = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);

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
        router_id,
        area_id,
        interface_mtu,
        options,
        init: flags & DBD_FLAG_INIT != 0,
        more: flags & DBD_FLAG_MORE != 0,
        master: flags & DBD_FLAG_MASTER != 0,
        dd_sequence_number,
        lsa_headers,
    })
}

/// Encodes `pkt` as an LSR packet.
pub fn encode_lsr(pkt: &LsrPacket, auth: &OutgoingAuth<'_>) -> Vec<u8> {
    let mut body = Vec::with_capacity(pkt.requests.len() * lsa::KEY_LEN);
    for key in &pkt.requests {
        lsa::encode_key(&mut body, key);
    }
    encode_packet(TYPE_LSR, pkt.router_id, pkt.area_id, &body, auth)
}

/// Decodes an LSR packet, validating the common header and auth first.
pub fn decode_lsr(data: &[u8], auth: &AuthPolicy<'_>) -> Result<LsrPacket, PacketError> {
    let (packet_type, router_id, area_id) = decode_header(data)?;
    if packet_type != TYPE_LSR {
        return Err(PacketError::UnknownType(packet_type));
    }
    let body = verify_auth(data, auth)?;
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

/// RFC 2328 Appendix C.3's `InfTransDelay` — the estimated seconds it takes
/// an LSU to cross this link, added to every LSA's age on the way out
/// (§13.3) so ages keep advancing across hops even between age ticks.
/// `ponytail:` fixed, not a per-`OspfProfile` field — same reasoning as
/// `link::RXMT_INTERVAL`.
pub const INF_TRANS_DELAY: u16 = 1;

/// Encodes `pkt` as an LSU packet. Each LSA goes out with its age bumped by
/// `INF_TRANS_DELAY` (saturating at `MaxAge`, RFC 2328 §13.3) — only the
/// wire copy, the caller's LSDB instance is untouched; the LSA checksum
/// excludes the age field, so it's unaffected.
pub fn encode_lsu(pkt: &LsuPacket, auth: &OutgoingAuth<'_>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        &u32::try_from(pkt.lsas.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for l in &pkt.lsas {
        let mut delayed = l.clone();
        delayed.header.age = l
            .header
            .age
            .saturating_add(INF_TRANS_DELAY)
            .min(lsa::MAX_AGE);
        body.extend_from_slice(&lsa::encode_lsa(&delayed));
    }
    encode_packet(TYPE_LSU, pkt.router_id, pkt.area_id, &body, auth)
}

/// Decodes an LSU packet, validating the common header and auth first.
pub fn decode_lsu(data: &[u8], auth: &AuthPolicy<'_>) -> Result<LsuPacket, PacketError> {
    let (packet_type, router_id, area_id) = decode_header(data)?;
    if packet_type != TYPE_LSU {
        return Err(PacketError::UnknownType(packet_type));
    }
    let body = verify_auth(data, auth)?;
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
pub fn encode_lsack(pkt: &LsAckPacket, auth: &OutgoingAuth<'_>) -> Vec<u8> {
    let mut body = Vec::with_capacity(pkt.lsa_headers.len() * lsa::LSA_HEADER_LEN);
    for header in &pkt.lsa_headers {
        lsa::encode_lsa_header(&mut body, header);
    }
    encode_packet(TYPE_LSACK, pkt.router_id, pkt.area_id, &body, auth)
}

/// Decodes an `LSAck` packet, validating the common header and auth first.
pub fn decode_lsack(data: &[u8], auth: &AuthPolicy<'_>) -> Result<LsAckPacket, PacketError> {
    let (packet_type, router_id, area_id) = decode_header(data)?;
    if packet_type != TYPE_LSACK {
        return Err(PacketError::UnknownType(packet_type));
    }
    let body = verify_auth(data, auth)?;
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

/// Encodes any OSPF packet by dispatching to its type's own encoder.
pub fn encode(pkt: &OspfPacket, auth: &OutgoingAuth<'_>) -> Vec<u8> {
    match pkt {
        OspfPacket::Hello(p) => encode_hello(p, auth),
        OspfPacket::Dbd(p) => encode_dbd(p, auth),
        OspfPacket::Lsr(p) => encode_lsr(p, auth),
        OspfPacket::Lsu(p) => encode_lsu(p, auth),
        OspfPacket::LsAck(p) => encode_lsack(p, auth),
    }
}

/// Decodes any OSPF packet by reading the common header's type byte and
/// dispatching to that type's own decoder — the multiplexing point
/// `link.rs` uses on every `socket::recv_packet` payload once it speaks more
/// than Hello.
pub fn decode(data: &[u8], auth: &AuthPolicy<'_>) -> Result<OspfPacket, PacketError> {
    if data.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    match data[1] {
        TYPE_HELLO => decode_hello(data, auth).map(OspfPacket::Hello),
        TYPE_DBD => decode_dbd(data, auth).map(OspfPacket::Dbd),
        TYPE_LSR => decode_lsr(data, auth).map(OspfPacket::Lsr),
        TYPE_LSU => decode_lsu(data, auth).map(OspfPacket::Lsu),
        TYPE_LSACK => decode_lsack(data, auth).map(OspfPacket::LsAck),
        other => Err(PacketError::UnknownType(other)),
    }
}

/// The `router_id` any `OspfPacket` variant carries — every RFC 2328 packet
/// type's header includes it. A small pure accessor so a caller working
/// with the top-level enum (e.g. `link.rs`'s anti-replay check, which needs
/// the sender's identity for every packet type alike) doesn't need to
/// match all five variants itself.
pub fn router_id(pkt: &OspfPacket) -> Ipv4Addr {
    match pkt {
        OspfPacket::Hello(p) => p.router_id,
        OspfPacket::Dbd(p) => p.router_id,
        OspfPacket::Lsr(p) => p.router_id,
        OspfPacket::Lsu(p) => p.router_id,
        OspfPacket::LsAck(p) => p.router_id,
    }
}

/// The header's Area ID, peeked before decoding (no key needed): RFC 2328
/// §8.2's receive demux — a link drops another area's packet, which is how a
/// virtual link and the transit link it shares addresses with keep apart.
pub fn area_id(data: &[u8]) -> Option<Ipv4Addr> {
    let octets: [u8; 4] = data.get(8..12)?.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

/// Reads the wire crypto sequence number iff `data`'s `AuType` is Crypto (2)
/// and it's long enough to contain one — a raw peek needing no key
/// knowledge, used by `link.rs` for its own stateful RFC 2328 D.4.3
/// anti-replay bookkeeping (deliberately kept out of this module — see the
/// module doc comment on staying pure/stateless).
pub fn crypto_sequence(data: &[u8]) -> Option<u64> {
    if data.len() < HEADER_LEN {
        return None;
    }
    match u16::from_be_bytes([data[14], data[15]]) {
        AUTH_TYPE_CRYPTO => Some(u64::from(u32::from_be_bytes([
            data[20], data[21], data[22], data[23],
        ]))),
        AUTH_TYPE_CRYPTO_EXT => {
            let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
            let seq = data.get(length..length + 8)?;
            Some(u64::from_be_bytes(seq.try_into().ok()?))
        }
        _ => None,
    }
}

/// RFC 5709 §3.3's `Apad` — `0x878FE1F3` repeated to the hash length — that
/// stands in the trailer while the HMAC is computed. RFC 7474 replaces its
/// first four octets with the packet's IP source address (`source`).
fn apad(algorithm: CryptoAlgorithm, source: Option<Ipv4Addr>) -> Vec<u8> {
    let mut pad = Vec::with_capacity(algorithm.digest_len());
    let mut words = algorithm.digest_len() / 4;
    if let Some(source) = source {
        pad.extend_from_slice(&source.octets());
        words -= 1;
    }
    for _ in 0..words {
        pad.extend_from_slice(&0x878F_E1F3u32.to_be_bytes());
    }
    pad
}

/// RFC 7474's digest input: the packet and its 64-bit sequence number
/// followed by `Apad` with the IP source address.
fn ext_digest_input(
    packet_and_seq: &[u8],
    source: Ipv4Addr,
    algorithm: CryptoAlgorithm,
) -> Vec<u8> {
    [packet_and_seq, &apad(algorithm, Some(source))].concat()
}

/// `AuType` 2's digest over `data` (the packet): plain MD5 hashes the packet
/// then the key, the RFC 5709 HMAC-SHA family hashes the packet then `Apad`.
fn classic_digest(algorithm: CryptoAlgorithm, data: &[u8], key: &[u8]) -> Vec<u8> {
    match algorithm {
        CryptoAlgorithm::Md5 => algorithm.digest(data, key),
        _ => algorithm.digest(&[data, &apad(algorithm, None)].concat(), key),
    }
}

/// Builds the 24-byte common header (Appendix A.3.1) around `body`, fills in
/// the `AuType`/Authentication field for `auth`, and either computes the
/// checksum (Null/Simple) or appends a real digest and leaves the checksum
/// at zero (Crypto — RFC 2328 D.4.3: not calculated for this `AuType`).
/// Shared by every packet type's own `encode_*`.
fn encode_packet(
    packet_type: u8,
    router_id: Ipv4Addr,
    area_id: Ipv4Addr,
    body: &[u8],
    auth: &OutgoingAuth<'_>,
) -> Vec<u8> {
    let total_len = HEADER_LEN + body.len();
    let mut buf = Vec::with_capacity(total_len);
    buf.push(VERSION);
    buf.push(packet_type);
    // Always fits: `total_len` is `HEADER_LEN` plus a handful of entries,
    // nowhere near `u16::MAX`.
    buf.extend_from_slice(&u16::try_from(total_len).unwrap_or(u16::MAX).to_be_bytes());
    buf.extend_from_slice(&router_id.octets());
    buf.extend_from_slice(&area_id.octets());
    buf.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled in below
    match auth {
        OutgoingAuth::None => {
            buf.extend_from_slice(&AUTH_TYPE_NULL.to_be_bytes());
            buf.extend_from_slice(&[0u8; 8]);
        }
        OutgoingAuth::Simple { password } => {
            buf.extend_from_slice(&AUTH_TYPE_SIMPLE.to_be_bytes());
            let mut field = [0u8; 8];
            let n = password.len().min(8);
            field[..n].copy_from_slice(&password[..n]);
            buf.extend_from_slice(&field);
        }
        OutgoingAuth::Crypto {
            key_id,
            algorithm,
            extended: Some(_),
            ..
        } => {
            buf.extend_from_slice(&AUTH_TYPE_CRYPTO_EXT.to_be_bytes());
            buf.extend_from_slice(&u32::from(*key_id).to_be_bytes()); // 32-bit Key ID
            buf.extend_from_slice(&[0u8; 3]); // reserved
            buf.push(u8::try_from(algorithm.digest_len()).unwrap_or(0));
        }
        OutgoingAuth::Crypto {
            key_id, algorithm, ..
        } => {
            buf.extend_from_slice(&AUTH_TYPE_CRYPTO.to_be_bytes());
            buf.push(0); // reserved
            buf.push(0); // reserved
                         // One octet on the wire — `valid_profile_timers` caps a classic
                         // (non-extended) key-id at 255 at commit time.
            buf.push(u8::try_from(*key_id).expect("classic AuType key-id fits in one octet"));
            // Auth Data Length — the trailing digest's length, appended below.
            buf.push(u8::try_from(algorithm.digest_len()).unwrap_or(0));
            // Crypto sequence number — filled in properly below, once the
            // rest of the header/body bytes it must itself be part of the
            // signed content are already in place.
            buf.extend_from_slice(&[0u8; 4]);
        }
    }
    buf.extend_from_slice(body);
    debug_assert_eq!(buf.len(), total_len);

    match auth {
        OutgoingAuth::None | OutgoingAuth::Simple { .. } => {
            let sum = checksum(&buf);
            buf[12..14].copy_from_slice(&sum.to_be_bytes());
        }
        OutgoingAuth::Crypto {
            algorithm,
            key,
            sequence,
            extended: Some(source),
            ..
        } => {
            // RFC 7474: the 64-bit number follows the packet (outside the
            // OSPF length field) and is covered by the digest.
            buf.extend_from_slice(&sequence.to_be_bytes());
            let digest = algorithm.digest(&ext_digest_input(&buf, *source, *algorithm), key);
            buf.extend_from_slice(&digest);
        }
        OutgoingAuth::Crypto {
            algorithm,
            key,
            sequence,
            ..
        } => {
            // AuType 2 carries only 32 bits; the caller keeps it in range.
            buf[20..24]
                .copy_from_slice(&u32::try_from(*sequence).unwrap_or(u32::MAX).to_be_bytes());
            // Checksum field stays zero — not calculated for this AuType.
            let digest = classic_digest(*algorithm, &buf, key);
            buf.extend_from_slice(&digest);
        }
    }
    buf
}

/// Validates the common header's version and returns `(packet_type,
/// router_id, area_id)` — auth/checksum is deliberately not checked here:
/// each packet type's own `decode_*` checks its expected type first (via
/// `verify_auth`), so a packet of a different type never gets
/// misinterpreted as an auth failure. Shared by every packet type's own
/// `decode_*`.
fn decode_header(data: &[u8]) -> Result<(u8, Ipv4Addr, Ipv4Addr), PacketError> {
    if data.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    let version = data[0];
    if version != VERSION {
        return Err(PacketError::BadVersion(version));
    }
    let router_id = read_ipv4(data, 4);
    let area_id = read_ipv4(data, 8);
    Ok((data[1], router_id, area_id))
}

/// Verifies `data`'s `AuType` matches `auth` and its integrity (checksum for
/// Null/Simple, real digest for Crypto — RFC 2328 D.4.3/D.5), returning the
/// real body slice: `&data[HEADER_LEN..]` for Null/Simple (unchanged
/// behavior), or `&data[HEADER_LEN..length]` for Crypto, where `length` is
/// the wire's own packet-length field — the first place this module reads
/// it, since only a Crypto packet ever has trailing bytes (the digest)
/// beyond it. Shared by every packet type's own `decode_*`, called after
/// its own type check.
fn verify_auth<'a>(data: &'a [u8], auth: &AuthPolicy<'_>) -> Result<&'a [u8], PacketError> {
    let wire_auth_type = u16::from_be_bytes([data[14], data[15]]);
    match (wire_auth_type, auth) {
        (AUTH_TYPE_NULL, AuthPolicy::None) => {
            if checksum(data) != 0 {
                return Err(PacketError::BadChecksum);
            }
            Ok(&data[HEADER_LEN..])
        }
        (AUTH_TYPE_SIMPLE, AuthPolicy::Simple { password }) => {
            if checksum(data) != 0 {
                return Err(PacketError::BadChecksum);
            }
            let mut expected = [0u8; 8];
            let n = password.len().min(8);
            expected[..n].copy_from_slice(&password[..n]);
            if data[16..24] != expected {
                return Err(PacketError::AuthFailed);
            }
            Ok(&data[HEADER_LEN..])
        }
        (
            AUTH_TYPE_CRYPTO,
            AuthPolicy::Crypto {
                keys,
                extended: None,
            },
        ) => {
            let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
            if length < HEADER_LEN || data.len() < length {
                return Err(PacketError::TruncatedBody);
            }
            let key_id = u16::from(data[18]);
            let auth_data_len = usize::from(data[19]);
            let Some((_, algorithm, key)) = keys.iter().find(|(id, _, _)| *id == key_id) else {
                return Err(PacketError::AuthFailed);
            };
            if auth_data_len != algorithm.digest_len() || data.len() < length + auth_data_len {
                return Err(PacketError::TruncatedBody);
            }
            let expected = classic_digest(*algorithm, &data[..length], key);
            if data[length..length + auth_data_len] != expected[..] {
                return Err(PacketError::AuthFailed);
            }
            Ok(&data[HEADER_LEN..length])
        }
        (
            AUTH_TYPE_CRYPTO_EXT,
            AuthPolicy::Crypto {
                keys,
                extended: Some(source),
            },
        ) => {
            let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
            if length < HEADER_LEN || data.len() < length + 8 {
                return Err(PacketError::TruncatedBody);
            }
            let key_id = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
            let auth_data_len = usize::from(data[23]);
            let Some((_, algorithm, key)) = keys.iter().find(|(id, _, _)| u32::from(*id) == key_id)
            else {
                return Err(PacketError::AuthFailed);
            };
            let end = length + 8;
            if auth_data_len != algorithm.digest_len() || data.len() < end + auth_data_len {
                return Err(PacketError::TruncatedBody);
            }
            let expected =
                algorithm.digest(&ext_digest_input(&data[..end], *source, *algorithm), key);
            if data[end..end + auth_data_len] != expected[..] {
                return Err(PacketError::AuthFailed);
            }
            Ok(&data[HEADER_LEN..length])
        }
        _ => Err(PacketError::AuthTypeMismatch),
    }
}

pub(crate) fn read_ipv4(data: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    )
}

/// RFC 2328 Appendix D.4.3's checksum: the standard RFC 1071 ones-complement-
/// of-ones-complement-sum used by IP/TCP/ICMP (**not** `OSPFv3`'s Fletcher
/// checksum, and not the LSA checksum — see `lsa::lsa_checksum` — which uses
/// Fletcher/RFC 905 Annex B instead). The 8-byte Authentication field (bytes
/// 16..24) is always excluded from the sum, per RFC 2328 — this matters once
/// that field holds a real Simple-password value; for Null auth it's a
/// no-op, since those bytes are always zero anyway. Never called at all for
/// Crypto auth (see `verify_auth`/`encode_packet`) — RFC 2328 D.4.3 doesn't
/// compute this checksum for that `AuType`.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, remainder) = data.as_chunks::<2>();
    for (i, chunk) in chunks.iter().enumerate() {
        if (16..24).contains(&(i * 2)) {
            continue;
        }
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let [last] = remainder {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // Always fits: the loop above reduces `sum` until it's below 1 << 16.
    u16::try_from(sum).map_or(0, |s| !s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::{LsaBody, NetworkLsaBody, RouterLsaBody};

    fn sample() -> HelloPacket {
        HelloPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            network_mask: Ipv4Addr::new(255, 255, 255, 0),
            hello_interval: 10,
            options: OPTION_E,
            dead_interval: 40,
            router_priority: 1,
            designated_router: Ipv4Addr::new(9, 9, 9, 9),
            backup_designated_router: Ipv4Addr::new(9, 9, 9, 10),
            neighbors: vec![Ipv4Addr::new(9, 9, 9, 10)],
        }
    }

    fn sample_dbd() -> DbdPacket {
        DbdPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 1500,
            options: 0,
            init: true,
            more: true,
            master: true,
            dd_sequence_number: 42,
            lsa_headers: vec![LsaHeader {
                age: 1,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
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
                lsa_type: lsa::LSA_TYPE_ROUTER,
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
            lsas: vec![
                Lsa {
                    header: LsaHeader {
                        age: 0,
                        options: 0,
                        lsa_type: lsa::LSA_TYPE_ROUTER,
                        link_state_id: Ipv4Addr::new(9, 9, 9, 9),
                        advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                        sequence_number: 0x8000_0001u32.cast_signed(),
                        checksum: 0,
                        length: 0,
                    },
                    body: LsaBody::Router(RouterLsaBody {
                        flags: 0,
                        links: Vec::new(),
                    }),
                },
                Lsa {
                    header: LsaHeader {
                        age: 0,
                        options: 0,
                        lsa_type: lsa::LSA_TYPE_NETWORK,
                        link_state_id: Ipv4Addr::new(10, 0, 0, 1),
                        advertising_router: Ipv4Addr::new(9, 9, 9, 9),
                        sequence_number: 0x8000_0001u32.cast_signed(),
                        checksum: 0,
                        length: 0,
                    },
                    body: LsaBody::Network(NetworkLsaBody {
                        network_mask: Ipv4Addr::new(255, 255, 255, 0),
                        attached_routers: vec![Ipv4Addr::new(9, 9, 9, 9)],
                    }),
                },
            ],
        }
    }

    fn sample_lsack() -> LsAckPacket {
        LsAckPacket {
            router_id: Ipv4Addr::new(9, 9, 9, 9),
            area_id: Ipv4Addr::UNSPECIFIED,
            lsa_headers: vec![LsaHeader {
                age: 1,
                options: 0,
                lsa_type: lsa::LSA_TYPE_ROUTER,
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
        let encoded = encode_hello(&pkt, &OutgoingAuth::None);
        let decoded = decode_hello(&encoded, &AuthPolicy::None).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hello_round_trip_with_no_neighbors() {
        let mut pkt = sample();
        pkt.neighbors = Vec::new();
        let encoded = encode_hello(&pkt, &OutgoingAuth::None);
        let decoded = decode_hello(&encoded, &AuthPolicy::None).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hello_round_trip_with_two_neighbors() {
        let mut pkt = sample();
        pkt.neighbors = vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)];
        let encoded = encode_hello(&pkt, &OutgoingAuth::None);
        let decoded = decode_hello(&encoded, &AuthPolicy::None).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn hello_round_trip_preserves_dr_bdr_and_priority() {
        let pkt = sample();
        let decoded =
            decode_hello(&encode_hello(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded.router_priority, pkt.router_priority);
        assert_eq!(decoded.designated_router, pkt.designated_router);
        assert_eq!(
            decoded.backup_designated_router,
            pkt.backup_designated_router
        );
    }

    #[test]
    fn hello_corrupted_checksum_is_rejected() {
        let mut encoded = encode_hello(&sample(), &OutgoingAuth::None);
        let last = encoded.len() - 1;
        encoded[last] ^= 0xff;
        assert_eq!(
            decode_hello(&encoded, &AuthPolicy::None),
            Err(PacketError::BadChecksum)
        );
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert_eq!(
            decode_hello(&[0u8; 10], &AuthPolicy::None),
            Err(PacketError::Truncated)
        );
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut encoded = encode_hello(&sample(), &OutgoingAuth::None);
        encoded[0] = 3;
        // Corrupting the version also invalidates the checksum, but version
        // is checked first.
        assert_eq!(
            decode_hello(&encoded, &AuthPolicy::None),
            Err(PacketError::BadVersion(3))
        );
    }

    #[test]
    fn wrong_type_is_rejected() {
        let mut encoded = encode_hello(&sample(), &OutgoingAuth::None);
        encoded[1] = TYPE_DBD;
        assert_eq!(
            decode_hello(&encoded, &AuthPolicy::None),
            Err(PacketError::UnknownType(TYPE_DBD))
        );
    }

    #[test]
    fn hello_truncated_body_is_rejected() {
        let mut encoded = encode_hello(&sample(), &OutgoingAuth::None);
        // Recompute the checksum over a body truncated mid-neighbor-list so
        // BadChecksum doesn't mask the body-length check.
        encoded.truncate(HEADER_LEN + HELLO_BODY_FIXED_LEN + 2);
        encoded[12..14].copy_from_slice(&0u16.to_be_bytes());
        let sum = checksum(&encoded);
        encoded[12..14].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(
            decode_hello(&encoded, &AuthPolicy::None),
            Err(PacketError::TruncatedBody)
        );
    }

    #[test]
    fn dbd_round_trips() {
        let pkt = sample_dbd();
        let decoded =
            decode_dbd(&encode_dbd(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn dbd_round_trips_with_no_summary_entries() {
        let mut pkt = sample_dbd();
        pkt.lsa_headers = Vec::new();
        pkt.init = false;
        pkt.more = false;
        pkt.master = false;
        let decoded =
            decode_dbd(&encode_dbd(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn dbd_flags_are_independent() {
        let mut pkt = sample_dbd();
        pkt.init = false;
        pkt.more = true;
        pkt.master = false;
        let decoded =
            decode_dbd(&encode_dbd(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert!(!decoded.init);
        assert!(decoded.more);
        assert!(!decoded.master);
    }

    #[test]
    fn lsr_round_trips() {
        let pkt = sample_lsr();
        let decoded =
            decode_lsr(&encode_lsr(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn lsr_round_trips_with_multiple_requests() {
        let mut pkt = sample_lsr();
        pkt.requests.push(LsaKey {
            lsa_type: lsa::LSA_TYPE_NETWORK,
            link_state_id: Ipv4Addr::new(10, 0, 0, 1),
            advertising_router: Ipv4Addr::new(9, 9, 9, 10),
        });
        let decoded =
            decode_lsr(&encode_lsr(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn lsu_round_trips() {
        let pkt = sample_lsu();
        let decoded =
            decode_lsu(&encode_lsu(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded.router_id, pkt.router_id);
        assert_eq!(decoded.lsas.len(), pkt.lsas.len());
        assert_eq!(decoded.lsas[0].body, pkt.lsas[0].body);
        assert_eq!(decoded.lsas[1].body, pkt.lsas[1].body);
    }

    /// RFC 2328 §13 step 2: an unknown LSA type (6, MOSPF) between two good
    /// LSAs is dropped alone; the LSU and the other two survive.
    #[test]
    fn lsu_skips_an_unknown_lsa_type_and_keeps_the_rest() {
        let mut pkt = sample_lsu();
        let mut unknown = pkt.lsas[0].clone();
        unknown.header.lsa_type = 6;
        pkt.lsas.insert(1, unknown);
        let decoded =
            decode_lsu(&encode_lsu(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded.lsas.len(), 2);
        assert_eq!(decoded.lsas[0].body, pkt.lsas[0].body);
        assert_eq!(decoded.lsas[1].body, pkt.lsas[2].body);
    }

    /// RFC 2328 §13 step 1 (#644): a bad-checksum LSA is dropped alone.
    #[test]
    fn lsu_skips_a_bad_checksum_lsa_and_keeps_the_rest() {
        let pkt = sample_lsu();
        let mut encoded = encode_lsu(&pkt, &OutgoingAuth::None);
        let second = HEADER_LEN + 4 + lsa::encode_lsa(&pkt.lsas[0]).len();
        // Flip a body byte of the second LSA.
        encoded[second + lsa::LSA_HEADER_LEN] ^= 0x01;
        encoded[12..14].copy_from_slice(&0u16.to_be_bytes());
        let sum = checksum(&encoded);
        encoded[12..14].copy_from_slice(&sum.to_be_bytes());
        let decoded = decode_lsu(&encoded, &AuthPolicy::None).unwrap();
        assert_eq!(decoded.lsas.len(), pkt.lsas.len() - 1);
        assert_eq!(decoded.lsas[0].body, pkt.lsas[0].body);
        // An unusable header length (framing lost) still fails the LSU.
        let mut encoded = encode_lsu(&pkt, &OutgoingAuth::None);
        encoded[second + 18..second + 20].copy_from_slice(&5u16.to_be_bytes());
        encoded[12..14].copy_from_slice(&0u16.to_be_bytes());
        let sum = checksum(&encoded);
        encoded[12..14].copy_from_slice(&sum.to_be_bytes());
        assert!(decode_lsu(&encoded, &AuthPolicy::None).is_err());
    }

    /// An LSU of [good, X, good] where X is `bad` (its checksum recomputed by `fix`).
    fn lsu_good_bad_good(bad: Vec<u8>) -> Vec<u8> {
        let pkt = sample_lsu();
        let mut body = 3u32.to_be_bytes().to_vec();
        body.extend(lsa::encode_lsa(&pkt.lsas[0]));
        body.extend(bad);
        body.extend(lsa::encode_lsa(&pkt.lsas[1]));
        encode_packet(
            TYPE_LSU,
            pkt.router_id,
            pkt.area_id,
            &body,
            &OutgoingAuth::None,
        )
    }

    /// Valid checksum, unparseable body (#645): discarded alone, counted.
    #[test]
    fn lsu_skips_a_malformed_body_lsa_and_counts_it() {
        let pkt = sample_lsu();
        let mut bad = lsa::encode_lsa(&pkt.lsas[0]);
        bad[22..24].copy_from_slice(&3u16.to_be_bytes()); // 3 links, none present
        let sum = lsa::lsa_checksum(&bad[2..]);
        bad[16..18].copy_from_slice(&sum.to_be_bytes());
        let decoded = decode_lsu(&lsu_good_bad_good(bad), &AuthPolicy::None).unwrap();
        assert_eq!(decoded.lsas.len(), 2);
        assert_eq!(decoded.discarded, 1);
        assert_eq!(decoded.last_error, Some(PacketError::TruncatedBody));
    }

    #[test]
    fn lsu_counts_a_bad_checksum_lsa() {
        let pkt = sample_lsu();
        let mut bad = lsa::encode_lsa(&pkt.lsas[0]);
        bad[16] ^= 0xFF;
        let decoded = decode_lsu(&lsu_good_bad_good(bad), &AuthPolicy::None).unwrap();
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
            decode_lsu(&lsu_good_bad_good(bad), &AuthPolicy::None),
            Err(PacketError::TruncatedBody)
        );
    }

    /// RFC 2328 §13.3: the wire age is the stored age plus `InfTransDelay`,
    /// saturating at `MaxAge`; the checksum is unaffected.
    #[test]
    fn lsu_adds_inf_trans_delay_to_each_lsa_age() {
        let mut pkt = sample_lsu();
        pkt.lsas[0].header.age = 100;
        pkt.lsas[1].header.age = lsa::MAX_AGE;
        let decoded =
            decode_lsu(&encode_lsu(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded.lsas[0].header.age, 100 + INF_TRANS_DELAY);
        assert_eq!(decoded.lsas[1].header.age, lsa::MAX_AGE);
        // The stored instance is untouched.
        assert_eq!(pkt.lsas[0].header.age, 100);
        let undelayed = lsa::decode_lsa(&lsa::encode_lsa(&pkt.lsas[0])).unwrap();
        assert_eq!(decoded.lsas[0].header.checksum, undelayed.header.checksum);
    }

    #[test]
    fn lsu_round_trips_with_no_lsas() {
        let mut pkt = sample_lsu();
        pkt.lsas = Vec::new();
        let decoded =
            decode_lsu(&encode_lsu(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded.lsas, []);
    }

    #[test]
    fn lsu_rejects_count_mismatch() {
        let mut encoded = encode_lsu(&sample_lsu(), &OutgoingAuth::None);
        // Overstate the LSA count in the body without adding another LSA.
        let last_idx = HEADER_LEN + 3;
        encoded[last_idx] = 3;
        encoded[12..14].copy_from_slice(&0u16.to_be_bytes());
        let sum = checksum(&encoded);
        encoded[12..14].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(
            decode_lsu(&encoded, &AuthPolicy::None),
            Err(PacketError::TruncatedBody)
        );
    }

    #[test]
    fn lsack_round_trips() {
        let pkt = sample_lsack();
        let decoded =
            decode_lsack(&encode_lsack(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn lsack_round_trips_with_multiple_headers() {
        let mut pkt = sample_lsack();
        pkt.lsa_headers.push(LsaHeader {
            age: 2,
            options: 0,
            lsa_type: lsa::LSA_TYPE_NETWORK,
            link_state_id: Ipv4Addr::new(10, 0, 0, 1),
            advertising_router: Ipv4Addr::new(9, 9, 9, 9),
            sequence_number: 0x8000_0002u32.cast_signed(),
            checksum: 0x5678,
            length: 28,
        });
        let decoded =
            decode_lsack(&encode_lsack(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn dispatch_decodes_each_type_by_header_byte() {
        assert!(matches!(
            decode(
                &encode_hello(&sample(), &OutgoingAuth::None),
                &AuthPolicy::None
            )
            .unwrap(),
            OspfPacket::Hello(_)
        ));
        assert!(matches!(
            decode(
                &encode_dbd(&sample_dbd(), &OutgoingAuth::None),
                &AuthPolicy::None
            )
            .unwrap(),
            OspfPacket::Dbd(_)
        ));
        assert!(matches!(
            decode(
                &encode_lsr(&sample_lsr(), &OutgoingAuth::None),
                &AuthPolicy::None
            )
            .unwrap(),
            OspfPacket::Lsr(_)
        ));
        assert!(matches!(
            decode(
                &encode_lsu(&sample_lsu(), &OutgoingAuth::None),
                &AuthPolicy::None
            )
            .unwrap(),
            OspfPacket::Lsu(_)
        ));
        assert!(matches!(
            decode(
                &encode_lsack(&sample_lsack(), &OutgoingAuth::None),
                &AuthPolicy::None
            )
            .unwrap(),
            OspfPacket::LsAck(_)
        ));
    }

    #[test]
    fn dispatch_encode_round_trips_through_top_level_enum() {
        let pkt = OspfPacket::Dbd(sample_dbd());
        let decoded = decode(&encode(&pkt, &OutgoingAuth::None), &AuthPolicy::None).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn dispatch_rejects_unknown_type() {
        let mut encoded = encode_hello(&sample(), &OutgoingAuth::None);
        encoded[1] = 9;
        encoded[12..14].copy_from_slice(&0u16.to_be_bytes());
        let sum = checksum(&encoded);
        encoded[12..14].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(
            decode(&encoded, &AuthPolicy::None),
            Err(PacketError::UnknownType(9))
        );
    }

    #[test]
    fn simple_password_round_trips_and_checksum_excludes_it() {
        let auth = OutgoingAuth::Simple {
            password: b"hunter2",
        };
        let encoded = encode_hello(&sample(), &auth);
        // AuType is Simple (1), and the password sits in the wire cleartext
        // — the checksum still validates even though bytes 16..24 are now
        // non-zero, proving the checksum excludes them.
        assert_eq!(
            u16::from_be_bytes([encoded[14], encoded[15]]),
            AUTH_TYPE_SIMPLE
        );
        assert_eq!(&encoded[16..23], b"hunter2");
        let policy = AuthPolicy::Simple {
            password: b"hunter2",
        };
        let decoded = decode_hello(&encoded, &policy).unwrap();
        assert_eq!(decoded, sample());
    }

    #[test]
    fn simple_password_mismatch_is_rejected() {
        let auth = OutgoingAuth::Simple {
            password: b"hunter2",
        };
        let encoded = encode_hello(&sample(), &auth);
        let policy = AuthPolicy::Simple {
            password: b"wrongpw",
        };
        assert_eq!(
            decode_hello(&encoded, &policy),
            Err(PacketError::AuthFailed)
        );
    }

    #[test]
    fn auth_type_mismatch_is_rejected_both_directions() {
        let none_encoded = encode_hello(&sample(), &OutgoingAuth::None);
        let simple_policy = AuthPolicy::Simple { password: b"pw" };
        assert_eq!(
            decode_hello(&none_encoded, &simple_policy),
            Err(PacketError::AuthTypeMismatch)
        );

        let simple_encoded = encode_hello(&sample(), &OutgoingAuth::Simple { password: b"pw" });
        assert_eq!(
            decode_hello(&simple_encoded, &AuthPolicy::None),
            Err(PacketError::AuthTypeMismatch)
        );
    }

    #[test]
    fn crypto_md5_round_trips_and_checksum_is_zero() {
        let auth = OutgoingAuth::Crypto {
            key_id: 1,
            algorithm: CryptoAlgorithm::Md5,
            key: b"secret",
            sequence: 42,
            extended: None,
        };
        let encoded = encode_hello(&sample(), &auth);
        assert_eq!(u16::from_be_bytes([encoded[12], encoded[13]]), 0);
        assert_eq!(encoded.len(), HEADER_LEN + HELLO_BODY_FIXED_LEN + 4 + 16);
        let keys: &[(u16, CryptoAlgorithm, Vec<u8>)] =
            &[(1, CryptoAlgorithm::Md5, b"secret".to_vec())];
        let policy = AuthPolicy::Crypto {
            keys,
            extended: None,
        };
        let decoded = decode_hello(&encoded, &policy).unwrap();
        assert_eq!(decoded, sample());
    }

    #[test]
    fn crypto_hmac_sha256_round_trips_with_correct_digest_length() {
        let auth = OutgoingAuth::Crypto {
            key_id: 1,
            algorithm: CryptoAlgorithm::HmacSha256,
            key: b"secret",
            sequence: 1,
            extended: None,
        };
        let encoded = encode_dbd(&sample_dbd(), &auth);
        assert_eq!(
            encoded.len(),
            HEADER_LEN + DBD_BODY_FIXED_LEN + lsa::LSA_HEADER_LEN + 32
        );
        let keys: &[(u16, CryptoAlgorithm, Vec<u8>)] =
            &[(1, CryptoAlgorithm::HmacSha256, b"secret".to_vec())];
        let policy = AuthPolicy::Crypto {
            keys,
            extended: None,
        };
        let decoded = decode_dbd(&encoded, &policy).unwrap();
        assert_eq!(decoded, sample_dbd());
    }

    #[test]
    fn crypto_unknown_key_id_is_rejected() {
        let auth = OutgoingAuth::Crypto {
            key_id: 1,
            algorithm: CryptoAlgorithm::Md5,
            key: b"secret",
            sequence: 1,
            extended: None,
        };
        let encoded = encode_hello(&sample(), &auth);
        let keys: &[(u16, CryptoAlgorithm, Vec<u8>)] =
            &[(2, CryptoAlgorithm::Md5, b"secret".to_vec())];
        let policy = AuthPolicy::Crypto {
            keys,
            extended: None,
        };
        assert_eq!(
            decode_hello(&encoded, &policy),
            Err(PacketError::AuthFailed)
        );
    }

    #[test]
    fn crypto_wrong_key_is_rejected() {
        let auth = OutgoingAuth::Crypto {
            key_id: 1,
            algorithm: CryptoAlgorithm::Md5,
            key: b"secret",
            sequence: 1,
            extended: None,
        };
        let encoded = encode_hello(&sample(), &auth);
        let keys: &[(u16, CryptoAlgorithm, Vec<u8>)] =
            &[(1, CryptoAlgorithm::Md5, b"wrongkey".to_vec())];
        let policy = AuthPolicy::Crypto {
            keys,
            extended: None,
        };
        assert_eq!(
            decode_hello(&encoded, &policy),
            Err(PacketError::AuthFailed)
        );
    }

    #[test]
    fn crypto_sequence_peeks_wire_value() {
        let auth = OutgoingAuth::Crypto {
            key_id: 1,
            algorithm: CryptoAlgorithm::Md5,
            key: b"secret",
            sequence: 0x1234_5678,
            extended: None,
        };
        let encoded = encode_hello(&sample(), &auth);
        assert_eq!(crypto_sequence(&encoded), Some(0x1234_5678));
    }

    #[test]
    fn crypto_sequence_is_none_for_null_and_simple_auth() {
        assert_eq!(
            crypto_sequence(&encode_hello(&sample(), &OutgoingAuth::None)),
            None
        );
        assert_eq!(
            crypto_sequence(&encode_hello(
                &sample(),
                &OutgoingAuth::Simple { password: b"pw" }
            )),
            None
        );
    }

    const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    fn ext_keys() -> Vec<(u16, CryptoAlgorithm, Vec<u8>)> {
        vec![(1, CryptoAlgorithm::HmacSha256, b"secret".to_vec())]
    }

    fn ext_auth(sequence: u64) -> OutgoingAuth<'static> {
        OutgoingAuth::Crypto {
            key_id: 1,
            algorithm: CryptoAlgorithm::HmacSha256,
            key: b"secret",
            sequence,
            extended: Some(SRC),
        }
    }

    #[test]
    fn extended_round_trips_with_seq_after_packet_outside_length() {
        let seq = (7u64 << 32) | 9;
        let encoded = encode_hello(&sample(), &ext_auth(seq));
        let body = HEADER_LEN + HELLO_BODY_FIXED_LEN + 4;
        assert_eq!(
            u16::from_be_bytes([encoded[14], encoded[15]]),
            AUTH_TYPE_CRYPTO_EXT
        );
        // OSPF length excludes the 8-byte sequence and the digest.
        assert_eq!(
            usize::from(u16::from_be_bytes([encoded[2], encoded[3]])),
            body
        );
        assert_eq!(encoded.len(), body + 8 + 32);
        assert_eq!(crypto_sequence(&encoded), Some(seq));
        let keys = ext_keys();
        let policy = AuthPolicy::Crypto {
            keys: &keys,
            extended: Some(SRC),
        };
        assert_eq!(decode_hello(&encoded, &policy).unwrap(), sample());
    }

    #[test]
    fn extended_digest_is_bound_to_ip_source_and_sequence() {
        let keys = ext_keys();
        let encoded = encode_hello(&sample(), &ext_auth(5));
        let other = AuthPolicy::Crypto {
            keys: &keys,
            extended: Some(Ipv4Addr::new(10, 0, 0, 2)),
        };
        assert_eq!(decode_hello(&encoded, &other), Err(PacketError::AuthFailed));
        let mut tampered = encoded.clone();
        let n = HEADER_LEN + HELLO_BODY_FIXED_LEN + 4;
        tampered[n + 7] ^= 1; // flip the sequence's low bit
        let policy = AuthPolicy::Crypto {
            keys: &keys,
            extended: Some(SRC),
        };
        assert_eq!(
            decode_hello(&tampered, &policy),
            Err(PacketError::AuthFailed)
        );
    }

    #[test]
    fn extended_and_classic_crypto_do_not_interoperate() {
        let keys = ext_keys();
        let ext = encode_hello(&sample(), &ext_auth(1));
        let classic = AuthPolicy::Crypto {
            keys: &keys,
            extended: None,
        };
        assert_eq!(
            decode_hello(&ext, &classic),
            Err(PacketError::AuthTypeMismatch)
        );
        let plain = encode_hello(
            &sample(),
            &OutgoingAuth::Crypto {
                key_id: 1,
                algorithm: CryptoAlgorithm::HmacSha256,
                key: b"secret",
                sequence: 1,
                extended: None,
            },
        );
        let policy = AuthPolicy::Crypto {
            keys: &keys,
            extended: Some(SRC),
        };
        assert_eq!(
            decode_hello(&plain, &policy),
            Err(PacketError::AuthTypeMismatch)
        );
    }

    #[test]
    fn classic_key_id_255_round_trips() {
        let keys: Vec<(u16, CryptoAlgorithm, Vec<u8>)> =
            vec![(255, CryptoAlgorithm::HmacSha256, b"secret".to_vec())];
        let auth = OutgoingAuth::Crypto {
            key_id: 255,
            algorithm: CryptoAlgorithm::HmacSha256,
            key: b"secret",
            sequence: 1,
            extended: None,
        };
        let encoded = encode_hello(&sample(), &auth);
        assert_eq!(encoded[18], 255);
        let policy = AuthPolicy::Crypto {
            keys: &keys,
            extended: None,
        };
        assert_eq!(decode_hello(&encoded, &policy).unwrap(), sample());
    }

    #[test]
    fn hmac_sha256_digest_covers_packet_then_apad() {
        // RFC 5709 §3.3: HMAC(K, packet || Apad), Apad = 0x878FE1F3 x (L/4).
        let auth = OutgoingAuth::Crypto {
            key_id: 1,
            algorithm: CryptoAlgorithm::HmacSha256,
            key: b"secret",
            sequence: 1,
            extended: None,
        };
        let encoded = encode_hello(&sample(), &auth);
        let (packet, digest) = encoded.split_at(encoded.len() - 32);
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(packet);
        mac.update(&[0x87, 0x8F, 0xE1, 0xF3].repeat(8));
        assert_eq!(digest, &mac.finalize().into_bytes()[..]);
    }

    #[test]
    fn md5_key_is_zero_padded_or_truncated_to_16_bytes() {
        // RFC 2328 D.4.3 (a): MD5(packet || 16-byte key).
        let digest_for = |key: &[u8]| {
            let encoded = encode_hello(
                &sample(),
                &OutgoingAuth::Crypto {
                    key_id: 1,
                    algorithm: CryptoAlgorithm::Md5,
                    key,
                    sequence: 1,
                    extended: None,
                },
            );
            encoded[encoded.len() - 16..].to_vec()
        };
        let packet = {
            let e = encode_hello(
                &sample(),
                &OutgoingAuth::Crypto {
                    key_id: 1,
                    algorithm: CryptoAlgorithm::Md5,
                    key: b"secret",
                    sequence: 1,
                    extended: None,
                },
            );
            e[..e.len() - 16].to_vec()
        };
        // nosemgrep: rust.lang.security.insecure-hashes.insecure-hashes -- test verifies the RFC 2328 D.4.3 keyed-MD5 wire format itself, same wire-compatibility requirement as the production site above.
        let mut hasher = Md5::new();
        hasher.update(&packet);
        hasher.update(b"secret\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(digest_for(b"secret"), hasher.finalize().to_vec());
        // Bytes past the 16th don't matter.
        assert_eq!(
            digest_for(b"0123456789abcdefXYZ"),
            digest_for(b"0123456789abcdef")
        );
    }

    #[test]
    fn decode_header_boundary_length() {
        // Exactly HEADER_LEN bytes, version 2, type 1, router 1.1.1.1, area 0.0.0.2.
        let mut hdr = vec![VERSION, TYPE_HELLO, 0, 24, 1, 1, 1, 1, 0, 0, 0, 2];
        hdr.resize(HEADER_LEN, 0);
        assert_eq!(
            decode_header(&hdr),
            Ok((
                TYPE_HELLO,
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(0, 0, 0, 2)
            ))
        );
        assert_eq!(
            decode_header(&hdr[..HEADER_LEN - 1]),
            Err(PacketError::Truncated)
        );
        hdr[0] = 3;
        assert_eq!(decode_header(&hdr), Err(PacketError::BadVersion(3)));
    }

    // RFC 2328 Appendix D.4.3 (AuType 2) and RFC 7474 section 3 (AuType 3):
    // the header's Length field locates the digest, so it is bounds-checked
    // before it is trusted.
    const EXT_SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    type Keys = Vec<(u16, CryptoAlgorithm, Vec<u8>)>;

    fn crypto_wire(extended: bool, body: &[u8]) -> (Vec<u8>, Keys) {
        let algorithm = if extended {
            CryptoAlgorithm::HmacSha256
        } else {
            CryptoAlgorithm::Md5
        };
        let auth = OutgoingAuth::Crypto {
            key_id: 1,
            algorithm,
            key: b"secret",
            sequence: 7,
            extended: extended.then_some(EXT_SRC),
        };
        let wire = encode_packet(
            TYPE_HELLO,
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::UNSPECIFIED,
            body,
            &auth,
        );
        (wire, vec![(1, algorithm, b"secret".to_vec())])
    }

    fn set_length(wire: &mut [u8], length: usize) {
        wire[2..4].copy_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    }

    #[test]
    fn crypto_length_field_boundaries_both_arms() {
        for extended in [false, true] {
            let (wire, keys) = crypto_wire(extended, &[0u8; 8]);
            let policy = AuthPolicy::Crypto {
                keys: &keys,
                extended: extended.then_some(EXT_SRC),
            };
            // Header-only packet: Length == HEADER_LEN is the exact boundary.
            let (header_only, _) = crypto_wire(extended, &[]);
            assert_eq!(
                verify_auth(&header_only, &policy),
                Ok(&[][..]),
                "ext={extended}"
            );
            // Below the header, Length cannot locate a digest.
            for bad in [0, HEADER_LEN - 1] {
                let mut w = wire.clone();
                set_length(&mut w, bad);
                assert_eq!(
                    verify_auth(&w, &policy),
                    Err(PacketError::TruncatedBody),
                    "ext={extended} length={bad}"
                );
            }
            // Beyond the datagram.
            let mut w = wire.clone();
            set_length(&mut w, wire.len() + 1);
            assert_eq!(verify_auth(&w, &policy), Err(PacketError::TruncatedBody));
            // Length reaching exactly the end of the datagram leaves no digest.
            let mut w = wire.clone();
            set_length(&mut w, wire.len());
            assert_eq!(verify_auth(&w, &policy), Err(PacketError::TruncatedBody));
        }
    }

    #[test]
    fn crypto_digest_length_and_truncation_both_arms() {
        for extended in [false, true] {
            let (wire, keys) = crypto_wire(extended, &[0u8; 8]);
            let policy = AuthPolicy::Crypto {
                keys: &keys,
                extended: extended.then_some(EXT_SRC),
            };
            assert!(verify_auth(&wire, &policy).is_ok());
            let len_at = if extended { 23 } else { 19 };
            let digest_len = wire[len_at];
            for bad in [digest_len - 1, digest_len + 1] {
                let mut w = wire.clone();
                w[len_at] = bad;
                assert_eq!(verify_auth(&w, &policy), Err(PacketError::TruncatedBody));
            }
            let mut short = wire.clone();
            short.pop();
            assert_eq!(
                verify_auth(&short, &policy),
                Err(PacketError::TruncatedBody)
            );
            let mut flipped = wire.clone();
            *flipped.last_mut().unwrap() ^= 1;
            assert_eq!(verify_auth(&flipped, &policy), Err(PacketError::AuthFailed));
        }
    }

    #[test]
    fn crypto_datagram_must_hold_length_plus_trailer_before_key_lookup() {
        // No key matches, so a datagram that passes the size check reports
        // `AuthFailed` and one that does not reports `TruncatedBody`: this
        // pins the exact size boundary of each arm (the classic digest
        // follows Length directly; the extended arm has the 8-byte sequence
        // number first, RFC 7474 section 3).
        for (extended, tail) in [(false, 0usize), (true, 8)] {
            let (wire, _) = crypto_wire(extended, &[0u8; 8]);
            let length = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
            let policy = AuthPolicy::Crypto {
                keys: &[],
                extended: extended.then_some(EXT_SRC),
            };
            assert_eq!(
                verify_auth(&wire[..length + tail - 1], &policy),
                Err(PacketError::TruncatedBody),
                "ext={extended}"
            );
            assert_eq!(
                verify_auth(&wire[..length + tail], &policy),
                Err(PacketError::AuthFailed),
                "ext={extended}"
            );
        }
    }
}
