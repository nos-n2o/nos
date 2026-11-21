//! Packet codec and the three RFC 2865/2866/3579 authenticators.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

/// Attribute type numbers used by the client.
pub mod attr {
    pub const USER_NAME: u8 = 1;
    pub const USER_PASSWORD: u8 = 2;
    pub const FILTER_ID: u8 = 11;
    pub const REPLY_MESSAGE: u8 = 18;
    pub const CLASS: u8 = 25;
    pub const NAS_IDENTIFIER: u8 = 32;
    pub const ACCT_STATUS_TYPE: u8 = 40;
    pub const ACCT_SESSION_ID: u8 = 44;
    pub const ACCT_SESSION_TIME: u8 = 46;
    pub const ACCT_TERMINATE_CAUSE: u8 = 49;
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;
}

const HEADER: usize = 20;
/// RFC 2865 §3: 20 to 4096 bytes.
const MAX_LEN: usize = 4096;
const MA_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    AccessRequest,
    AccessAccept,
    AccessReject,
    AccountingRequest,
    AccountingResponse,
    AccessChallenge,
}

impl Code {
    fn byte(self) -> u8 {
        match self {
            Code::AccessRequest => 1,
            Code::AccessAccept => 2,
            Code::AccessReject => 3,
            Code::AccountingRequest => 4,
            Code::AccountingResponse => 5,
            Code::AccessChallenge => 11,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => Code::AccessRequest,
            2 => Code::AccessAccept,
            3 => Code::AccessReject,
            4 => Code::AccountingRequest,
            5 => Code::AccountingResponse,
            11 => Code::AccessChallenge,
            _ => return None,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("packet shorter than its header or length field")]
    Truncated,
    #[error("unknown code {0}")]
    Code(u8),
    #[error("malformed attribute")]
    Attribute,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub code: Code,
    pub id: u8,
    pub authenticator: [u8; 16],
    pub attrs: Vec<(u8, Vec<u8>)>,
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    // nosemgrep: rust.lang.security.insecure-hashes.insecure-hashes -- RFC 2865/2866 mandate MD5
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hmac_md5(secret: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = Hmac::<Md5>::new_from_slice(secret).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// 16 random bytes (a Request Authenticator must be unpredictable).
pub fn random16() -> [u8; 16] {
    let mut b = [0; 16];
    getrandom::getrandom(&mut b).expect("the OS random source is available");
    b
}

/// RFC 2865 §5.2: `password` hidden under the secret and Request Authenticator,
/// zero-padded to a multiple of 16 bytes. At most 128 bytes (the caller checks).
pub fn hide_password(password: &[u8], secret: &[u8], ra: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev: Vec<u8> = ra.to_vec();
    for chunk in password.chunks(16) {
        let key = md5(&[secret, &prev]);
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        prev = block.iter().zip(key).map(|(p, k)| p ^ k).collect();
        out.extend_from_slice(&prev);
    }
    out
}

/// Inverse of [`hide_password`], trailing zero padding removed (a server's side).
pub fn unhide_password(hidden: &[u8], secret: &[u8], ra: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev = ra.to_vec();
    for c in hidden.chunks(16) {
        let key = md5(&[secret, &prev]);
        out.extend(c.iter().zip(key).map(|(a, b)| a ^ b));
        prev = c.to_vec();
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    out
}

impl Packet {
    pub fn attr(&self, ty: u8) -> Option<&[u8]> {
        self.attrs
            .iter()
            .find(|(t, _)| *t == ty)
            .map(|(_, v)| &v[..])
    }

    fn raw(&self, authenticator: &[u8; 16], ma: Option<&[u8; 16]>) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in &self.attrs {
            if *t == attr::MESSAGE_AUTHENTICATOR {
                continue;
            }
            body.push(*t);
            body.push(u8::try_from(v.len() + 2).expect("attribute fits in 253 bytes"));
            body.extend_from_slice(v);
        }
        if let Some(ma) = ma {
            body.extend_from_slice(&[attr::MESSAGE_AUTHENTICATOR, 18]);
            body.extend_from_slice(ma);
        }
        let mut out = vec![self.code.byte(), self.id];
        let len = u16::try_from(HEADER + body.len()).expect("under 4096");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(authenticator);
        out.extend_from_slice(&body);
        out
    }

    /// An Access-Request: random authenticator, the User-Password hidden under
    /// `secret`. `encode` adds the Message-Authenticator (RFC 3579 §3.2).
    pub fn access_request(id: u8, secret: &[u8], mut attrs: Vec<(u8, Vec<u8>)>) -> Self {
        let ra = random16();
        for (t, v) in &mut attrs {
            if *t == attr::USER_PASSWORD {
                *v = hide_password(v, secret, &ra);
            }
        }
        Packet {
            code: Code::AccessRequest,
            id,
            authenticator: ra,
            attrs,
        }
    }

    /// Wire form. `secret` signs the Message-Authenticator (Access-Request) or
    /// derives the Request Authenticator (Accounting-Request, RFC 2866 §3).
    pub fn encode(&self, secret: &[u8]) -> Vec<u8> {
        match self.code {
            Code::AccessRequest => {
                let zero = [0; MA_LEN];
                let ma = hmac_md5(secret, &self.raw(&self.authenticator, Some(&zero)));
                self.raw(&self.authenticator, Some(&ma))
            }
            Code::AccountingRequest => self.raw(&self.accounting_authenticator(secret), None),
            _ => self.raw(&self.authenticator, None),
        }
    }

    /// The Request Authenticator an Accounting-Request carries (a reply is checked against it).
    pub fn accounting_authenticator(&self, secret: &[u8]) -> [u8; 16] {
        md5(&[&self.raw(&[0; 16], None), secret])
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < HEADER {
            return Err(DecodeError::Truncated);
        }
        let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        if !(HEADER..=MAX_LEN).contains(&len) || len > buf.len() {
            return Err(DecodeError::Truncated);
        }
        let code = Code::from_byte(buf[0]).ok_or(DecodeError::Code(buf[0]))?;
        let mut attrs = Vec::new();
        let mut rest = &buf[HEADER..len];
        while !rest.is_empty() {
            let [t, l, ..] = *rest else {
                return Err(DecodeError::Attribute);
            };
            let l = usize::from(l);
            if l < 2 || l > rest.len() {
                return Err(DecodeError::Attribute);
            }
            attrs.push((t, rest[2..l].to_vec()));
            rest = &rest[l..];
        }
        Ok(Packet {
            code,
            id: buf[1],
            authenticator: buf[4..20].try_into().expect("16 bytes"),
            attrs,
        })
    }

    /// Whether `wire` is a genuine reply to the request that had Request
    /// Authenticator `ra` (RFC 2865 §3 Response Authenticator, and the
    /// Message-Authenticator when the reply carries one, RFC 3579 §3.2).
    pub fn reply_is_genuine(wire: &[u8], secret: &[u8], ra: &[u8; 16]) -> bool {
        let Ok(p) = Packet::decode(wire) else {
            return false;
        };
        let len = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
        let want = md5(&[&wire[..4], ra, &wire[HEADER..len], secret]);
        if want != p.authenticator {
            return false;
        }
        match p.attr(attr::MESSAGE_AUTHENTICATOR) {
            None => true,
            Some(got) => {
                // Over the reply with the Request Authenticator in the
                // authenticator field and the MA zeroed in place.
                let mut copy = wire[..len].to_vec();
                copy[4..20].copy_from_slice(ra);
                let Some(pos) = find_attr(&copy, attr::MESSAGE_AUTHENTICATOR) else {
                    return false;
                };
                copy[pos + 2..pos + 18].fill(0);
                hmac_md5(secret, &copy)[..] == *got
            }
        }
    }
}

fn find_attr(wire: &[u8], ty: u8) -> Option<usize> {
    let mut at = HEADER;
    while at + 2 <= wire.len() {
        let l = usize::from(wire[at + 1]);
        if l < 2 {
            return None;
        }
        if wire[at] == ty {
            return Some(at);
        }
        at += l;
    }
    None
}

/// Builds a reply the way a server does (tests, and stub servers).
pub fn make_reply(
    code: Code,
    req: &Packet,
    secret: &[u8],
    attrs: Vec<(u8, Vec<u8>)>,
    with_ma: bool,
) -> Vec<u8> {
    let reply = Packet {
        code,
        id: req.id,
        authenticator: req.authenticator,
        attrs,
    };
    let ma = with_ma.then(|| hmac_md5(secret, &reply.raw(&req.authenticator, Some(&[0; MA_LEN]))));
    let mut wire = reply.raw(&req.authenticator, ma.as_ref());
    let auth = md5(&[&wire, secret]);
    wire[4..20].copy_from_slice(&auth);
    wire
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"testing123";

    #[test]
    fn password_hiding_round_trips_across_blocks() {
        let ra = random16();
        for pw in [&b"x"[..], b"0123456789abcdef", b"0123456789abcdef0"] {
            let h = hide_password(pw, SECRET, &ra);
            assert_eq!(h.len() % 16, 0);
            assert_eq!(unhide_password(&h, SECRET, &ra), pw);
        }
    }

    #[test]
    fn access_request_round_trips_and_signs() {
        let p = Packet::access_request(
            7,
            SECRET,
            vec![
                (attr::USER_NAME, b"alice".to_vec()),
                (attr::USER_PASSWORD, b"pw".to_vec()),
            ],
        );
        let wire = p.encode(SECRET);
        let d = Packet::decode(&wire).unwrap();
        assert_eq!(
            (d.code, d.id, d.authenticator),
            (Code::AccessRequest, 7, p.authenticator)
        );
        assert_eq!(d.attr(attr::USER_NAME), Some(&b"alice"[..]));
        let mut z = wire.clone();
        let pos = find_attr(&z, attr::MESSAGE_AUTHENTICATOR).unwrap();
        z[pos + 2..pos + 18].fill(0);
        assert_eq!(hmac_md5(SECRET, &z)[..], wire[pos + 2..pos + 18]);
    }

    #[test]
    fn replies_are_verified() {
        let req = Packet::access_request(1, SECRET, vec![]);
        for ma in [false, true] {
            let wire = make_reply(
                Code::AccessAccept,
                &req,
                SECRET,
                vec![(attr::FILTER_ID, b"admin".to_vec())],
                ma,
            );
            assert!(Packet::reply_is_genuine(&wire, SECRET, &req.authenticator));
            assert!(!Packet::reply_is_genuine(
                &wire,
                b"other",
                &req.authenticator
            ));
            assert!(!Packet::reply_is_genuine(&wire, SECRET, &[9; 16]));
            let mut forged = wire.clone();
            let last = forged.len() - 1;
            forged[last] ^= 1;
            assert!(!Packet::reply_is_genuine(
                &forged,
                SECRET,
                &req.authenticator
            ));
        }
    }

    #[test]
    fn decode_rejects_garbage() {
        assert_eq!(Packet::decode(&[1; 5]), Err(DecodeError::Truncated));
        let mut w = Packet::access_request(1, SECRET, vec![]).encode(SECRET);
        w[0] = 99;
        assert_eq!(Packet::decode(&w), Err(DecodeError::Code(99)));
        let mut w = Packet {
            code: Code::AccessAccept,
            id: 1,
            authenticator: [0; 16],
            attrs: vec![(1, b"a".to_vec())],
        }
        .encode(SECRET);
        w[21] = 200;
        assert_eq!(Packet::decode(&w), Err(DecodeError::Attribute));
    }

    #[test]
    fn accounting_request_authenticator_is_derived() {
        let p = Packet {
            code: Code::AccountingRequest,
            id: 3,
            authenticator: [0; 16],
            attrs: vec![(attr::ACCT_STATUS_TYPE, vec![0, 0, 0, 1])],
        };
        let d = Packet::decode(&p.encode(SECRET)).unwrap();
        assert_eq!(d.authenticator, p.accounting_authenticator(SECRET));
    }
}
