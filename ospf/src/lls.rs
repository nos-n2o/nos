//! RFC 5613 Link-Local Signaling: the LLS data block that follows a Hello or
//! DBD packet when its Options L-bit is set. Pure encode/decode; `packet.rs`
//! finds the block (after the packet, or after the authentication data) and
//! calls in here. A bad block never fails the packet: `decode` returns
//! `None` and the packet is processed without LLS (RFC 5613 section 2.2).

use crate::packet::{classic_digest, CryptoAlgorithm};

/// Extended Options and Flags: LSDB resynchronization (RFC 4811).
pub const EOF_LR: u32 = 0x1;
/// Extended Options and Flags: restart signal (RFC 4812).
pub const EOF_RS: u32 = 0x2;
/// TLV type 1: Extended Options and Flags.
pub const TLV_EOF: u16 = 1;
/// TLV type 2: Cryptographic Authentication (`OSPFv2` only).
pub const TLV_CA: u16 = 2;

/// The TLVs this router understands from (or puts into) an LLS block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lls {
    /// The Extended Options and Flags word (`EOF_LR`, `EOF_RS`).
    pub eof: Option<u32>,
}

/// What the CA-TLV is signed with: the carrying packet's key and algorithm
/// and its (32-bit) crypto sequence number (RFC 5613 section 2.5).
#[derive(Debug, Clone, Copy)]
pub struct LlsCrypto<'a> {
    pub algorithm: CryptoAlgorithm,
    pub key: &'a [u8],
    pub sequence: u32,
}

/// RFC 1071 checksum over the whole block (unlike `packet::checksum`, no
/// Authentication field is skipped).
fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, rest) = data.as_chunks::<2>();
    for c in chunks {
        sum += u32::from(u16::from_be_bytes(*c));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u16::try_from(sum).map_or(0, |s| !s)
}

/// Appends one TLV: type, unpadded length, value, zero padding to 32 bits.
fn push_tlv(buf: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    buf.extend_from_slice(&tlv_type.to_be_bytes());
    buf.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    buf.extend_from_slice(value);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

/// Encodes an LLS block. With `crypto` the CA-TLV goes last and the checksum
/// stays 0 (RFC 5613 section 2.2); otherwise the checksum is filled in.
pub fn encode(lls: &Lls, crypto: Option<LlsCrypto<'_>>) -> Vec<u8> {
    let mut b = vec![0u8; 4];
    if let Some(flags) = lls.eof {
        push_tlv(&mut b, TLV_EOF, &flags.to_be_bytes());
    }
    let mut digest_start = None;
    if let Some(c) = crypto {
        let mut value = c.sequence.to_be_bytes().to_vec();
        value.resize(4 + c.algorithm.digest_len(), 0);
        push_tlv(&mut b, TLV_CA, &value);
        digest_start = Some(b.len() - c.algorithm.digest_len());
    }
    let words = u16::try_from(b.len() / 4).unwrap_or(u16::MAX);
    b[2..4].copy_from_slice(&words.to_be_bytes());
    if let (Some(c), Some(start)) = (crypto, digest_start) {
        // The digest covers the block up to the AuthData, header length final.
        let digest = classic_digest(c.algorithm, &b[..start], c.key);
        b[start..].copy_from_slice(&digest);
    } else {
        let sum = inet_checksum(&b);
        b[0..2].copy_from_slice(&sum.to_be_bytes());
    }
    b
}

/// Decodes an LLS block (`block` may carry trailing bytes beyond its own
/// length). `crypto` is `Some` iff the carrying packet used classic
/// cryptographic authentication, which then requires a valid CA-TLV.
pub fn decode(block: &[u8], crypto: Option<LlsCrypto<'_>>) -> Option<Lls> {
    if block.len() < 4 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([block[2], block[3]])) * 4;
    if len < 4 || len > block.len() {
        return None;
    }
    let blk = &block[..len];
    if crypto.is_none() && inet_checksum(blk) != 0 {
        return None;
    }
    let mut eof = None;
    let mut ca_seen = false;
    let mut pos = 4;
    while pos < len {
        if pos + 4 > len {
            return None;
        }
        let tlv_type = u16::from_be_bytes([blk[pos], blk[pos + 1]]);
        let l = usize::from(u16::from_be_bytes([blk[pos + 2], blk[pos + 3]]));
        let value_end = pos + 4 + l;
        let next = pos + 4 + l.next_multiple_of(4);
        if next > len {
            return None;
        }
        let value = &blk[pos + 4..value_end];
        match tlv_type {
            TLV_EOF => {
                if l == 4 && eof.is_none() {
                    eof = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                }
            }
            TLV_CA => {
                if let Some(c) = crypto {
                    if next != len || l != 4 + c.algorithm.digest_len() {
                        return None;
                    }
                    let seq = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    let expected = classic_digest(c.algorithm, &blk[..pos + 8], c.key);
                    if seq != c.sequence || value[4..] != expected[..] {
                        return None;
                    }
                    ca_seen = true;
                }
            }
            _ => {}
        }
        pos = next;
    }
    if crypto.is_some() && !ca_seen {
        return None;
    }
    Some(Lls { eof })
}

#[cfg(test)]
mod tests {
    use md5::{Digest, Md5};

    use super::*;

    const KEY: &[u8] = b"secret";

    fn crypto(algorithm: CryptoAlgorithm) -> LlsCrypto<'static> {
        LlsCrypto {
            algorithm,
            key: KEY,
            sequence: 9,
        }
    }

    /// A Null/Simple block from raw TLVs, with a correct length and checksum.
    fn raw(tlvs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut b = vec![0u8; 4];
        for (t, v) in tlvs {
            push_tlv(&mut b, *t, v);
        }
        let words = u16::try_from(b.len() / 4).unwrap();
        b[2..4].copy_from_slice(&words.to_be_bytes());
        let sum = inet_checksum(&b);
        b[0..2].copy_from_slice(&sum.to_be_bytes());
        b
    }

    fn eof(flags: u32) -> Lls {
        Lls { eof: Some(flags) }
    }

    #[test]
    fn round_trip_with_and_without_eof() {
        for l in [Lls::default(), eof(0), eof(EOF_LR), eof(EOF_RS), eof(3)] {
            assert_eq!(decode(&encode(&l, None), None), Some(l.clone()));
            for a in [
                CryptoAlgorithm::Md5,
                CryptoAlgorithm::HmacSha1,
                CryptoAlgorithm::HmacSha512,
            ] {
                let c = crypto(a);
                assert_eq!(decode(&encode(&l, Some(c)), Some(c)), Some(l.clone()));
            }
        }
    }

    #[test]
    fn trailing_bytes_beyond_the_declared_length_are_ignored() {
        let mut b = encode(&eof(1), None);
        b.extend_from_slice(&[1, 2, 3]);
        assert_eq!(decode(&b, None), Some(eof(1)));
    }

    #[test]
    fn malformed_blocks_are_dropped() {
        let good = encode(&eof(1), None);
        assert_eq!(decode(&[0, 0, 0], None), None);
        assert_eq!(decode(&good[..good.len() - 4], None), None, "length > data");
        let mut bad_sum = good.clone();
        bad_sum[0] ^= 1;
        assert_eq!(decode(&bad_sum, None), None);
        // TLV length overruns the block.
        let mut b = raw(&[(TLV_EOF, &[0, 0, 0, 0])]);
        b[6..8].copy_from_slice(&40u16.to_be_bytes());
        let sum = {
            b[0..2].copy_from_slice(&[0, 0]);
            inet_checksum(&b)
        };
        b[0..2].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(decode(&b, None), None);
        // Header length of zero words.
        assert_eq!(decode(&[0xff, 0xff, 0, 0], None), None);
    }

    #[test]
    fn unknown_and_private_tlvs_are_skipped() {
        let b = raw(&[(3, &[1, 2, 3, 4]), (32768, &[9]), (TLV_EOF, &[0, 0, 0, 2])]);
        assert_eq!(decode(&b, None), Some(eof(2)));
    }

    #[test]
    fn padding_is_added_to_the_value_but_not_the_length_field() {
        for n in 1..=3usize {
            let b = raw(&[(0x8000, &vec![7u8; n]), (TLV_EOF, &[0, 0, 0, 1])]);
            assert_eq!(b.len(), 4 + 8 + 8, "n={n}");
            assert_eq!(usize::from(u16::from_be_bytes([b[6], b[7]])), n);
            assert_eq!(decode(&b, None), Some(eof(1)));
        }
    }

    #[test]
    fn eof_with_wrong_length_is_ignored_and_the_first_valid_one_wins() {
        let b = raw(&[
            (TLV_EOF, &[0, 0]),
            (TLV_EOF, &[0, 0, 0, 1]),
            (TLV_EOF, &[0, 0, 0, 2]),
        ]);
        assert_eq!(decode(&b, None), Some(eof(1)));
        let only_bad = raw(&[(TLV_EOF, &[0, 0, 0, 0, 0, 0, 0, 0])]);
        assert_eq!(decode(&only_bad, None), Some(Lls::default()));
    }

    #[test]
    fn ca_tlv_is_checked_under_crypto_only() {
        let c = crypto(CryptoAlgorithm::Md5);
        let good = encode(&eof(1), Some(c));
        // Checksum stays zero under crypto.
        assert_eq!(&good[0..2], &[0, 0]);
        // Missing CA under crypto.
        assert_eq!(decode(&encode(&eof(1), None), Some(c)), None);
        // Wrong sequence, wrong key, tampered digest.
        let mut other = c;
        other.sequence = 10;
        assert_eq!(decode(&good, Some(other)), None);
        other = c;
        other.key = b"other";
        assert_eq!(decode(&good, Some(other)), None);
        let mut b = good.clone();
        *b.last_mut().unwrap() ^= 1;
        assert_eq!(decode(&b, Some(c)), None);
        // CA-TLV not last (a private TLV after it).
        let mut b = good.clone();
        push_tlv(&mut b, 0x8000, &[0; 4]);
        let words = u16::try_from(b.len() / 4).unwrap();
        b[2..4].copy_from_slice(&words.to_be_bytes());
        assert_eq!(decode(&b, Some(c)), None);
        // A CA-TLV under Null/Simple is just an unknown TLV.
        let b = raw(&[(TLV_CA, &[0; 20]), (TLV_EOF, &[0, 0, 0, 1])]);
        assert_eq!(decode(&b, None), Some(eof(1)));
    }

    #[test]
    fn ca_digest_is_md5_of_the_block_up_to_authdata_then_the_key() {
        let b = encode(&eof(1), Some(crypto(CryptoAlgorithm::Md5)));
        let split = b.len() - 16;
        let mut key = [0u8; 16];
        key[..KEY.len()].copy_from_slice(KEY);
        let mut h = Md5::new();
        h.update(&b[..split]);
        h.update(key);
        assert_eq!(&b[split..], &h.finalize()[..]);
        // Header length covers the digest; CA-TLV: type 2, length 4 + 16, seq 9.
        assert_eq!(usize::from(u16::from_be_bytes([b[2], b[3]])) * 4, b.len());
        assert_eq!(&b[12..20], &[0, 2, 0, 20, 0, 0, 0, 9]);
    }
}
