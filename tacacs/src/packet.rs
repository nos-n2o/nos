//! Header, body obfuscation (RFC 8907 §4.5) and the six bodies the client and
//! the stub exchange. Only what a login needs: PAP, `service=nos` AV pairs.

use md5::{Digest, Md5};

/// PAP and CHAP are minor version 1 (RFC 8907 §4.1).
pub const VERSION_PAP: u8 = 0xc1;
pub const TYPE_AUTHEN: u8 = 1;
pub const TYPE_AUTHOR: u8 = 2;
pub const TYPE_ACCT: u8 = 3;
pub const HEADER: usize = 12;
/// A reply bigger than this is not a login reply; refuse to buffer it.
pub const MAX_BODY: usize = 8192;

const AUTHEN_LOGIN: u8 = 1;
const AUTHEN_TYPE_PAP: u8 = 2;
const AUTHEN_SVC_LOGIN: u8 = 1;
/// `TAC_PLUS_AUTHEN_METH_TACACSPLUS`.
const METHOD_TACACSPLUS: u8 = 6;
const PRIV_USER: u8 = 1;

pub const AUTHEN_PASS: u8 = 1;
pub const AUTHEN_FAIL: u8 = 2;
pub const AUTHOR_PASS_ADD: u8 = 1;
pub const AUTHOR_PASS_REPL: u8 = 2;
pub const AUTHOR_FAIL: u8 = 0x10;
pub const ACCT_SUCCESS: u8 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("malformed TACACS+ packet")]
pub struct DecodeError;

/// Accounting flags (RFC 8907 §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcctFlags {
    Start,
    Stop,
    Watchdog,
}

impl AcctFlags {
    pub fn byte(self) -> u8 {
        match self {
            AcctFlags::Start => 2,
            AcctFlags::Stop => 4,
            AcctFlags::Watchdog => 8,
        }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b & 0x0e {
            2 => AcctFlags::Start,
            4 => AcctFlags::Stop,
            8 => AcctFlags::Watchdog,
            _ => return None,
        })
    }
}

/// A decoded header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub ty: u8,
    pub seq: u8,
    pub session: u32,
    pub len: u32,
}

impl Header {
    pub fn decode(b: &[u8; HEADER]) -> Header {
        Header {
            version: b[0],
            ty: b[1],
            seq: b[2],
            session: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            len: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        }
    }
}

/// XORs `body` with the MD5 pseudo-pad (it is its own inverse).
fn crypt(body: &mut [u8], session: u32, key: &[u8], version: u8, seq: u8) {
    let mut prev: Vec<u8> = Vec::new();
    for chunk in body.chunks_mut(16) {
        let mut h = Md5::new();
        h.update(session.to_be_bytes());
        h.update(key);
        h.update([version, seq]);
        h.update(&prev);
        let pad = h.finalize();
        for (b, p) in chunk.iter_mut().zip(pad.iter()) {
            *b ^= p;
        }
        prev = pad.to_vec();
    }
}

/// Header plus the obfuscated `body`.
pub fn seal(version: u8, ty: u8, seq: u8, session: u32, key: &[u8], mut body: Vec<u8>) -> Vec<u8> {
    crypt(&mut body, session, key, version, seq);
    let mut out = vec![version, ty, seq, 0];
    out.extend(session.to_be_bytes());
    out.extend(u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend(body);
    out
}

/// De-obfuscates a received body in place.
pub fn open(h: &Header, key: &[u8], body: &mut [u8]) {
    crypt(body, h.session, key, h.version, h.seq);
}

pub fn session_id() -> u32 {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).expect("the OS random source is available");
    u32::from_be_bytes(b)
}

fn len8(n: usize) -> u8 {
    u8::try_from(n).unwrap_or(u8::MAX)
}

/// Reads length-prefixed fields off a body.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.0.len() < n {
            return Err(DecodeError);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<usize, DecodeError> {
        let b = self.take(2)?;
        Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
    fn string(&mut self, n: usize) -> Result<String, DecodeError> {
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    fn done(&self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError)
        }
    }
}

/// PAP START (§5.1): the password rides in `data`.
pub fn authen_start(user: &str, rem_addr: &str, password: &str) -> Vec<u8> {
    let port = "nos";
    let mut b = vec![
        AUTHEN_LOGIN,
        PRIV_USER,
        AUTHEN_TYPE_PAP,
        AUTHEN_SVC_LOGIN,
        len8(user.len()),
        len8(port.len()),
        len8(rem_addr.len()),
        len8(password.len()),
    ];
    for s in [user, port, rem_addr, password] {
        b.extend(s.as_bytes());
    }
    b
}

/// Parses a PAP START: `(user, password)`.
pub fn parse_authen_start(body: &[u8]) -> Result<(String, String), DecodeError> {
    let mut c = Cursor(body);
    let head = c.take(8)?;
    if head[2] != AUTHEN_TYPE_PAP {
        return Err(DecodeError);
    }
    let [user_len, port_len, addr_len, data_len] = [4, 5, 6, 7].map(|i| usize::from(head[i]));
    let user = c.string(user_len)?;
    c.take(port_len + addr_len)?;
    let pw = c.string(data_len)?;
    c.done()?;
    Ok((user, pw))
}

/// An authentication REPLY (§5.2).
pub fn authen_reply(status: u8, msg: &str) -> Vec<u8> {
    let mut b = vec![status, 0];
    b.extend(u16::try_from(msg.len()).unwrap_or(0).to_be_bytes());
    b.extend([0, 0]);
    b.extend(msg.as_bytes());
    b
}

/// The status byte of an authentication REPLY.
pub fn parse_authen_reply(body: &[u8]) -> Result<u8, DecodeError> {
    let mut c = Cursor(body);
    let status = c.u8()?;
    c.u8()?;
    let (m, d) = (c.u16()?, c.u16()?);
    c.take(m + d)?;
    c.done()?;
    Ok(status)
}

/// AV pairs as the wire's length bytes plus concatenated strings.
fn args_wire(args: &[String]) -> (Vec<u8>, Vec<u8>) {
    let lens = args.iter().map(|a| len8(a.len())).collect();
    let data = args.iter().flat_map(|a| a.bytes()).collect();
    (lens, data)
}

fn request_with_args(first: &[u8], user: &str, rem_addr: &str, args: &[String]) -> Vec<u8> {
    let port = "nos";
    let (lens, data) = args_wire(args);
    let mut b = first.to_vec();
    b.extend([
        len8(user.len()),
        len8(port.len()),
        len8(rem_addr.len()),
        len8(args.len()),
    ]);
    b.extend(lens);
    for s in [user, port, rem_addr] {
        b.extend(s.as_bytes());
    }
    b.extend(data);
    b
}

fn common_start() -> [u8; 4] {
    [
        METHOD_TACACSPLUS,
        PRIV_USER,
        AUTHEN_TYPE_PAP,
        AUTHEN_SVC_LOGIN,
    ]
}

/// Authorization REQUEST (§6.1).
pub fn author_request(user: &str, rem_addr: &str, args: &[String]) -> Vec<u8> {
    request_with_args(&common_start(), user, rem_addr, args)
}

/// Accounting REQUEST (§7.1).
pub fn acct_request(flags: AcctFlags, user: &str, rem_addr: &str, args: &[String]) -> Vec<u8> {
    let c = common_start();
    request_with_args(
        &[flags.byte(), c[0], c[1], c[2], c[3]],
        user,
        rem_addr,
        args,
    )
}

/// What the stub needs from an authorization or accounting request.
pub struct Request {
    /// Accounting flags, `None` for an authorization request.
    pub flags: Option<AcctFlags>,
    pub user: String,
    pub args: Vec<String>,
}

/// Parses an authorization (`acct == false`) or accounting request.
pub fn parse_request(body: &[u8], acct: bool) -> Result<Request, DecodeError> {
    let mut c = Cursor(body);
    let flags = if acct {
        Some(AcctFlags::from_byte(c.u8()?).ok_or(DecodeError)?)
    } else {
        None
    };
    c.take(4)?;
    let head = c.take(4)?;
    let [user_len, port_len, addr_len, n_args] = [0, 1, 2, 3].map(|i| usize::from(head[i]));
    let lens = c.take(n_args)?.to_vec();
    let user = c.string(user_len)?;
    c.take(port_len + addr_len)?;
    let args = lens
        .iter()
        .map(|l| c.string(usize::from(*l)))
        .collect::<Result<_, _>>()?;
    c.done()?;
    Ok(Request { flags, user, args })
}

/// Authorization RESPONSE (§6.2).
pub fn author_response(status: u8, args: &[String]) -> Vec<u8> {
    let (lens, data) = args_wire(args);
    let mut b = vec![status, len8(args.len()), 0, 0, 0, 0];
    b.extend(lens);
    b.extend(data);
    b
}

/// `(status, args)` of an authorization RESPONSE.
pub fn parse_author_response(body: &[u8]) -> Result<(u8, Vec<String>), DecodeError> {
    let mut c = Cursor(body);
    let (status, n) = (c.u8()?, usize::from(c.u8()?));
    let (m, d) = (c.u16()?, c.u16()?);
    let lens = c.take(n)?.to_vec();
    c.take(m + d)?;
    let args = lens
        .iter()
        .map(|l| c.string(usize::from(*l)))
        .collect::<Result<_, _>>()?;
    c.done()?;
    Ok((status, args))
}

/// Accounting REPLY (§7.2).
pub fn acct_reply(status: u8) -> Vec<u8> {
    vec![0, 0, 0, 0, status]
}

pub fn parse_acct_reply(body: &[u8]) -> Result<u8, DecodeError> {
    let mut c = Cursor(body);
    let (m, d) = (c.u16()?, c.u16()?);
    let status = c.u8()?;
    c.take(m + d)?;
    c.done()?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypt_roundtrips_and_depends_on_key() {
        let body: Vec<u8> = (0..70).collect();
        let wire = seal(VERSION_PAP, TYPE_AUTHEN, 1, 7, b"k", body.clone());
        let h = Header::decode(wire[..12].try_into().unwrap());
        assert_eq!((h.len, h.session, h.seq), (70, 7, 1));
        let mut b = wire[12..].to_vec();
        assert_ne!(b, body);
        open(&h, b"k", &mut b);
        assert_eq!(b, body);
        let mut b = wire[12..].to_vec();
        open(&h, b"other", &mut b);
        assert_ne!(b, body);
    }

    #[test]
    fn bodies_roundtrip() {
        let (u, p) = parse_authen_start(&authen_start("alice", "10.0.0.1", "pw")).unwrap();
        assert_eq!((u.as_str(), p.as_str()), ("alice", "pw"));
        assert_eq!(parse_authen_reply(&authen_reply(AUTHEN_PASS, "hi")), Ok(1));
        let args = vec!["service=nos".to_string(), "role=admin".to_string()];
        let r = parse_request(&author_request("alice", "ip", &args), false).unwrap();
        assert_eq!((r.user.as_str(), r.args.clone()), ("alice", args.clone()));
        let r = parse_request(&acct_request(AcctFlags::Stop, "bob", "ip", &args), true).unwrap();
        assert_eq!(r.flags, Some(AcctFlags::Stop));
        assert_eq!(
            parse_author_response(&author_response(AUTHOR_PASS_ADD, &args)),
            Ok((AUTHOR_PASS_ADD, args))
        );
        assert_eq!(parse_acct_reply(&acct_reply(ACCT_SUCCESS)), Ok(1));
        assert!(parse_authen_reply(&[1]).is_err());
        assert!(
            parse_authen_reply(&[1, 0, 0, 0, 0, 0, 9]).is_err(),
            "trailing byte"
        );
    }
}
