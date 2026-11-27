//! RFC 5880 §4.2-4.4 / §6.7 authentication: the wire section, the digests and
//! the per-session sequence state. Pure: the clock comes in as an argument.

use std::fmt;
use std::time::{Duration, Instant};

use md5::Md5;
use nos_proto::schema::{BfdAuth, BfdAuthMethod};
use sha1::{Digest, Sha1};
use thiserror::Error;

pub const FLAG_AUTH: u8 = 0x04;
/// Mandatory section length: the auth section starts here.
const HDR: usize = 24;
const MD5_SECTION: usize = 24;
const SHA1_SECTION: usize = 28;
/// How long an old key stays acceptable after a change, in detection times.
const OLD_KEY_DETECTIONS: u32 = 4;
/// §6.7.3: `AuthSeqKnown` is cleared after this many detection times of silence.
const SILENCE_DETECTIONS: u32 = 2;

/// A profile's `BfdAuth` with its admin-key label resolved to the secret
/// (#510). Runtime only: never serialized, `Debug` hides the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthKey {
    pub key_id: u8,
    pub method: BfdAuthMethod,
    secret: Vec<u8>,
}

impl AuthKey {
    pub fn new(a: &BfdAuth, secret: &str) -> Self {
        AuthKey {
            key_id: a.key_id,
            method: a.method,
            secret: secret.as_bytes().to_vec(),
        }
    }
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthKey")
            .field("key_id", &self.key_id)
            .field("method", &self.method)
            .field("secret", &"<hidden>")
            .finish()
    }
}

/// An authentication section as received: `data` is the password or the
/// digest, `raw` the whole packet (the digest is over it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSection {
    pub kind: u8,
    pub key_id: u8,
    /// 0 for simple password (no sequence number).
    pub seq: u32,
    pub data: Vec<u8>,
    pub raw: Vec<u8>,
}

/// Why a received packet failed §6.7.2 (it is dropped, not counted as heard).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("authentication configured but its admin key is not available")]
    NoKey,
    #[error("authentication bit set but no authentication configured")]
    Unexpected,
    #[error("authentication configured but the authentication bit is clear")]
    Missing,
    #[error("authentication type does not match")]
    TypeMismatch,
    #[error("key id does not match")]
    KeyIdMismatch,
    #[error("bad password")]
    BadPassword,
    #[error("bad digest")]
    BadDigest,
    #[error("sequence number outside the window")]
    Sequence,
}

const fn wire_type(m: BfdAuthMethod) -> u8 {
    match m {
        BfdAuthMethod::SimplePassword => 1,
        BfdAuthMethod::KeyedMd5 => 2,
        BfdAuthMethod::MeticulousMd5 => 3,
        BfdAuthMethod::KeyedSha1 => 4,
        BfdAuthMethod::MeticulousSha1 => 5,
    }
}

const fn meticulous(kind: u8) -> bool {
    matches!(kind, 3 | 5)
}

/// Parses the section after the mandatory header; `pkt` is the packet cut at
/// its length field. `None` for a malformed or unknown section.
pub fn parse(pkt: &[u8]) -> Option<AuthSection> {
    let sec = pkt.get(HDR..)?;
    let (&kind, &alen, &key_id) = (sec.first()?, sec.get(1)?, sec.get(2)?);
    if usize::from(alen) != sec.len() {
        return None;
    }
    let (seq, data) = match kind {
        1 if (4..=19).contains(&alen) => (0, sec.get(3..)?),
        2 | 3 if usize::from(alen) == MD5_SECTION => (
            u32::from_be_bytes(sec.get(4..8)?.try_into().ok()?),
            sec.get(8..)?,
        ),
        4 | 5 if usize::from(alen) == SHA1_SECTION => (
            u32::from_be_bytes(sec.get(4..8)?.try_into().ok()?),
            sec.get(8..)?,
        ),
        _ => return None,
    };
    Some(AuthSection {
        kind,
        key_id,
        seq,
        data: data.to_vec(),
        raw: pkt.to_vec(),
    })
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// §6.7.3/§6.7.4: the hash over `pkt` with the digest field (the last
/// 16/20 bytes) replaced by the secret padded with zeros.
fn digest(kind: u8, secret: &[u8], pkt: &[u8]) -> Vec<u8> {
    let n = if kind <= 3 { 16 } else { 20 };
    let mut buf = pkt.to_vec();
    let at = buf.len().saturating_sub(n);
    let field = &mut buf[at..];
    field.fill(0);
    let k = secret.len().min(n);
    field[..k].copy_from_slice(&secret[..k]);
    if kind <= 3 {
        Md5::digest(&buf).to_vec()
    } else {
        Sha1::digest(&buf).to_vec()
    }
}

/// Appends the authentication section for `cfg` to the 24-byte `hdr`.
pub fn sign(hdr: &[u8], cfg: &AuthKey, seq: u32) -> Vec<u8> {
    let kind = wire_type(cfg.method);
    let key = &cfg.secret[..];
    let mut b = hdr.to_vec();
    b[1] |= FLAG_AUTH;
    if kind == 1 {
        b.extend_from_slice(&[
            1,
            u8::try_from(3 + key.len()).unwrap_or(u8::MAX),
            cfg.key_id,
        ]);
        b.extend_from_slice(key);
    } else {
        let alen = if kind <= 3 { MD5_SECTION } else { SHA1_SECTION };
        b.extend_from_slice(&[kind, u8::try_from(alen).unwrap_or(u8::MAX), cfg.key_id, 0]);
        b.extend_from_slice(&seq.to_be_bytes());
        b.resize(HDR + alen, 0);
    }
    b[3] = u8::try_from(b.len()).unwrap_or(u8::MAX);
    if kind != 1 {
        let d = digest(kind, key, &b);
        let at = b.len() - d.len();
        b[at..].copy_from_slice(&d);
    }
    b
}

/// Does `seq` fall in the §6.7.3/§6.7.4 window after `rcv` (wrap-aware)?
fn seq_ok(kind: u8, rcv: u32, seq: u32, mult: u8) -> bool {
    let d = seq.wrapping_sub(rcv);
    let max = 3 * u32::from(mult);
    if meticulous(kind) {
        (1..=max).contains(&d)
    } else {
        d <= max
    }
}

/// §6.7.2 without state: the key of `keys` whose type, key id and digest (or
/// password) match `s`. No sequence check: the S-BFD reflector (RFC 7880 §11)
/// keeps none.
pub fn verify<'a>(
    s: &AuthSection,
    keys: impl IntoIterator<Item = &'a AuthKey>,
) -> Result<&'a AuthKey, AuthError> {
    let typed: Vec<&AuthKey> = keys
        .into_iter()
        .filter(|k| wire_type(k.method) == s.kind)
        .collect();
    if typed.is_empty() {
        return Err(AuthError::TypeMismatch);
    }
    let mut named = typed
        .into_iter()
        .filter(|k| k.key_id == s.key_id)
        .peekable();
    if named.peek().is_none() {
        return Err(AuthError::KeyIdMismatch);
    }
    named
        .find(|k| {
            let want = if s.kind == 1 {
                k.secret.clone()
            } else {
                digest(s.kind, &k.secret, &s.raw)
            };
            ct_eq(&want, &s.data)
        })
        .ok_or(if s.kind == 1 {
            AuthError::BadPassword
        } else {
            AuthError::BadDigest
        })
}

/// One session's authentication state.
#[derive(Debug)]
pub struct AuthState {
    cfg: Option<AuthKey>,
    /// The key before the last change and until when it is still accepted.
    old: Option<(AuthKey, Instant)>,
    rcv_seq: u32,
    seq_known: bool,
    last_ok: Option<Instant>,
    xmit_seq: u32,
    bumped: Instant,
}

impl AuthState {
    pub fn new(cfg: Option<AuthKey>, xmit_seq: u32, now: Instant) -> Self {
        AuthState {
            cfg,
            old: None,
            rcv_seq: 0,
            seq_known: false,
            last_ok: None,
            xmit_seq,
            bumped: now,
        }
    }

    pub fn cfg(&self) -> Option<&AuthKey> {
        self.cfg.as_ref()
    }

    /// A profile edit: the new key signs from now on, the old one is still
    /// accepted for 4 detection times so a peer applying the change a little
    /// later keeps the session Up. A method change opens a new sequence space.
    pub fn set(&mut self, cfg: Option<AuthKey>, now: Instant, detect: Duration) {
        if cfg == self.cfg {
            return;
        }
        let method = |c: &Option<AuthKey>| c.as_ref().map(|a| a.method);
        if method(&cfg) != method(&self.cfg) {
            self.seq_known = false;
        }
        self.old = match (&self.cfg, &cfg) {
            (Some(prev), Some(_)) => Some((prev.clone(), now + detect * OLD_KEY_DETECTIONS)),
            _ => None,
        };
        self.cfg = cfg;
    }

    /// §6.7.2 receive checks. `mult` is the packet's Detect Mult; `detect`
    /// the current detection time (silence of twice that forgets the sequence).
    pub fn check(
        &mut self,
        now: Instant,
        mult: u8,
        sec: Option<&AuthSection>,
        detect: Option<Duration>,
    ) -> Result<(), AuthError> {
        if let (Some(last), Some(d)) = (self.last_ok, detect)
            && now.saturating_duration_since(last) > d * SILENCE_DETECTIONS
        {
            self.seq_known = false;
        }
        let Some(cfg) = &self.cfg else {
            return if sec.is_some() {
                Err(AuthError::Unexpected)
            } else {
                Ok(())
            };
        };
        let Some(s) = sec else {
            return Err(AuthError::Missing);
        };
        let old = self.old.as_ref().filter(|(_, until)| *until > now);
        verify(s, std::iter::once(cfg).chain(old.map(|(k, _)| k)))?;
        if s.kind != 1 {
            if self.seq_known && !seq_ok(s.kind, self.rcv_seq, s.seq, mult) {
                return Err(AuthError::Sequence);
            }
            self.rcv_seq = s.seq;
            self.seq_known = true;
        }
        self.last_ok = Some(now);
        Ok(())
    }

    pub fn xmit_seq(&self) -> u32 {
        self.xmit_seq
    }

    /// The wire bytes of the 24-byte `hdr`: signed when authentication is on.
    /// Meticulous variants take a new sequence number per packet, keyed ones
    /// one per detection time (§6.7.3/§6.7.4).
    pub fn sign(&mut self, now: Instant, hdr: &[u8], detect: Option<Duration>) -> Vec<u8> {
        let Some(cfg) = &self.cfg else {
            return hdr.to_vec();
        };
        let kind = wire_type(cfg.method);
        if meticulous(kind)
            || now.saturating_duration_since(self.bumped)
                >= detect.unwrap_or(Duration::from_secs(1))
        {
            self.xmit_seq = self.xmit_seq.wrapping_add(1);
            self.bumped = now;
        }
        sign(hdr, cfg, self.xmit_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac_oracle::*;

    /// An independent digest: the RFC 5880 §6.7.3 recipe written out from
    /// the wire layout (offsets spelled out), not through `digest`.
    mod hmac_oracle {
        use md5::{Digest as _, Md5};
        use sha1::Sha1;

        pub fn oracle(sha1: bool, secret: &str, wire: &[u8]) -> Vec<u8> {
            let dlen = if sha1 { 20 } else { 16 };
            let mut msg = wire[..wire.len() - dlen].to_vec();
            let mut pad = secret.as_bytes().to_vec();
            pad.resize(dlen, 0);
            msg.extend(pad);
            if sha1 {
                Sha1::digest(&msg).to_vec()
            } else {
                Md5::digest(&msg).to_vec()
            }
        }
    }

    fn hdr() -> Vec<u8> {
        let mut h = vec![0x20, 0xc0, 3, 24];
        h.extend_from_slice(&[
            0, 0, 0, 1, 0, 0, 0, 2, 0, 4, 0x93, 0xe0, 0, 4, 0x93, 0xe0, 0, 0, 0, 0,
        ]);
        h
    }

    fn cfg(method: BfdAuthMethod, id: u8, key: &str) -> AuthKey {
        AuthKey::new(
            &BfdAuth {
                key_id: id,
                method,
                key: "label".into(),
            },
            key,
        )
    }

    use BfdAuthMethod::*;

    #[test]
    fn digests_match_the_independent_oracle() {
        for (m, sha1, secret) in [
            (KeyedMd5, false, "s3cret"),
            (MeticulousMd5, false, "0123456789abcdef"),
            (KeyedSha1, true, "s3cret"),
            (MeticulousSha1, true, "0123456789abcdefghij"),
        ] {
            let w = sign(&hdr(), &cfg(m, 7, secret), 0x0102_0304);
            assert_eq!(w.len(), 24 + if sha1 { 28 } else { 24 });
            assert_eq!(usize::from(w[3]), w.len());
            assert_eq!(w[1] & FLAG_AUTH, FLAG_AUTH);
            let n = if sha1 { 20 } else { 16 };
            assert_eq!(&w[w.len() - n..], oracle(sha1, secret, &w), "{m:?}");
            assert_eq!(&w[28..32], &[1, 2, 3, 4], "sequence number");
            assert_eq!(w[26], 7, "key id");
        }
    }

    #[test]
    fn simple_password_layout() {
        let w = sign(&hdr(), &cfg(SimplePassword, 3, "pw"), 0);
        assert_eq!(&w[24..], &[1, 5, 3, b'p', b'w']);
        assert_eq!(w[3], 29);
        let s = parse(&w).unwrap();
        assert_eq!((s.kind, s.key_id, s.data.as_slice()), (1, 3, &b"pw"[..]));
    }

    #[test]
    fn parse_rejects_malformed_sections() {
        let good = sign(&hdr(), &cfg(KeyedSha1, 1, "k"), 1);
        assert!(parse(&good).is_some());
        assert!(parse(&good[..good.len() - 1]).is_none(), "length mismatch");
        let mut bad = good.clone();
        bad[24] = 9;
        assert!(parse(&bad).is_none(), "unknown type");
        let mut bad = good.clone();
        bad[25] = 24;
        assert!(parse(&bad).is_none(), "md5 length on sha1 type");
        assert!(parse(&hdr()).is_none(), "no section");
        let pw = sign(&hdr(), &cfg(SimplePassword, 1, "x"), 0);
        assert!(parse(&pw[..26]).is_none(), "truncated");
    }

    fn state(m: BfdAuthMethod) -> AuthState {
        AuthState::new(Some(cfg(m, 1, "k")), 100, Instant::now())
    }

    fn rx(st: &mut AuthState, now: Instant, w: &[u8]) -> Result<(), AuthError> {
        st.check(now, 3, parse(w).as_ref(), Some(Duration::from_secs(1)))
    }

    #[test]
    fn auth_key_debug_hides_the_secret() {
        let k = cfg(KeyedMd5, 3, "hunter2");
        let d = format!("{k:?}");
        assert!(!d.contains("hunter2") && d.contains("hidden"), "{d}");
    }

    #[test]
    fn rejection_matrix() {
        let now = Instant::now();
        let w = |m, id, k: &str| sign(&hdr(), &cfg(m, id, k), 5);
        let mut st = state(MeticulousSha1);
        assert_eq!(rx(&mut st, now, &w(MeticulousSha1, 1, "k")), Ok(()));
        let mut st = state(MeticulousSha1);
        assert_eq!(rx(&mut st, now, &hdr()), Err(AuthError::Missing));
        assert_eq!(
            rx(&mut st, now, &w(KeyedSha1, 1, "k")),
            Err(AuthError::TypeMismatch)
        );
        assert_eq!(
            rx(&mut st, now, &w(MeticulousSha1, 2, "k")),
            Err(AuthError::KeyIdMismatch)
        );
        assert_eq!(
            rx(&mut st, now, &w(MeticulousSha1, 1, "x")),
            Err(AuthError::BadDigest)
        );
        let mut flipped = w(MeticulousSha1, 1, "k");
        flipped[5] ^= 1; // any covered byte
        assert_eq!(rx(&mut st, now, &flipped), Err(AuthError::BadDigest));
        let mut st = state(SimplePassword);
        assert_eq!(rx(&mut st, now, &w(SimplePassword, 1, "k")), Ok(()));
        assert_eq!(
            rx(&mut st, now, &w(SimplePassword, 1, "j")),
            Err(AuthError::BadPassword)
        );
        let mut none = AuthState::new(None, 0, now);
        assert_eq!(rx(&mut none, now, &hdr()), Ok(()));
        assert_eq!(
            rx(&mut none, now, &w(KeyedMd5, 1, "k")),
            Err(AuthError::Unexpected)
        );
    }

    #[test]
    fn replay_window_keyed_vs_meticulous() {
        let now = Instant::now();
        let at = |m, seq| sign(&hdr(), &cfg(m, 1, "k"), seq);
        // keyed: [rcv, rcv + 3*3]
        let mut st = state(KeyedMd5);
        assert_eq!(
            rx(&mut st, now, &at(KeyedMd5, 1000)),
            Ok(()),
            "unknown: any"
        );
        assert_eq!(rx(&mut st, now, &at(KeyedMd5, 1000)), Ok(()), "repeat ok");
        assert_eq!(rx(&mut st, now, &at(KeyedMd5, 1009)), Ok(()));
        assert_eq!(
            rx(&mut st, now, &at(KeyedMd5, 1019)),
            Err(AuthError::Sequence)
        );
        assert_eq!(
            rx(&mut st, now, &at(KeyedMd5, 1008)),
            Err(AuthError::Sequence),
            "old"
        );
        // meticulous: (rcv, rcv + 9]
        let mut st = state(MeticulousMd5);
        assert_eq!(rx(&mut st, now, &at(MeticulousMd5, 1000)), Ok(()));
        assert_eq!(
            rx(&mut st, now, &at(MeticulousMd5, 1000)),
            Err(AuthError::Sequence),
            "replay"
        );
        assert_eq!(
            rx(&mut st, now, &at(MeticulousMd5, 1010)),
            Err(AuthError::Sequence)
        );
        assert_eq!(rx(&mut st, now, &at(MeticulousMd5, 1009)), Ok(()));
        // u32 wrap
        let mut st = state(MeticulousSha1);
        assert_eq!(rx(&mut st, now, &at(MeticulousSha1, u32::MAX - 1)), Ok(()));
        assert_eq!(
            rx(&mut st, now, &at(MeticulousSha1, 2)),
            Ok(()),
            "wraps forward"
        );
        assert_eq!(
            rx(&mut st, now, &at(MeticulousSha1, u32::MAX)),
            Err(AuthError::Sequence)
        );
    }

    #[test]
    fn silence_forgets_the_sequence() {
        let now = Instant::now();
        let at = |seq| sign(&hdr(), &cfg(MeticulousSha1, 1, "k"), seq);
        let mut st = state(MeticulousSha1);
        assert_eq!(rx(&mut st, now, &at(1000)), Ok(()));
        assert_eq!(
            rx(&mut st, now + Duration::from_secs(1), &at(5000)),
            Err(AuthError::Sequence)
        );
        // more than 2 detection times (2 s) of silence: any sequence again
        assert_eq!(rx(&mut st, now + Duration::from_secs(3), &at(5000)), Ok(()));
    }

    #[test]
    fn tx_sequence_meticulous_every_packet_keyed_per_detection_time() {
        let t0 = Instant::now();
        let seq = |w: &[u8]| parse(w).unwrap().seq;
        let det = Some(Duration::from_secs(1));
        let mut met = AuthState::new(Some(cfg(MeticulousMd5, 1, "k")), 10, t0);
        let (first, second) = (met.sign(t0, &hdr(), det), met.sign(t0, &hdr(), det));
        assert_eq!((seq(&first), seq(&second)), (11, 12));
        let mut k = AuthState::new(Some(cfg(KeyedMd5, 1, "k")), 10, t0);
        let (first, second) = (
            k.sign(t0, &hdr(), det),
            k.sign(t0 + Duration::from_millis(500), &hdr(), det),
        );
        assert_eq!((seq(&first), seq(&second)), (10, 10));
        assert_eq!(seq(&k.sign(t0 + Duration::from_secs(1), &hdr(), det)), 11);
        let mut off = AuthState::new(None, 0, t0);
        assert_eq!(off.sign(t0, &hdr(), det), hdr());
    }

    #[test]
    fn key_rollover_accepts_the_old_key_for_four_detection_times() {
        let now = Instant::now();
        let det = Duration::from_secs(1);
        let old = |s| sign(&hdr(), &cfg(MeticulousSha1, 1, "old"), s);
        let new = |s| sign(&hdr(), &cfg(MeticulousSha1, 2, "new"), s);
        let mut st = AuthState::new(Some(cfg(MeticulousSha1, 1, "old")), 0, now);
        assert_eq!(rx(&mut st, now, &old(10)), Ok(()));
        st.set(Some(cfg(MeticulousSha1, 2, "new")), now, det);
        assert_eq!(rx(&mut st, now, &old(11)), Ok(()), "old key still accepted");
        assert_eq!(rx(&mut st, now, &new(12)), Ok(()));
        assert_eq!(
            rx(&mut st, now + Duration::from_secs(5), &old(13)),
            Err(AuthError::KeyIdMismatch)
        );
        assert_eq!(rx(&mut st, now + Duration::from_secs(5), &new(14)), Ok(()));
        // a secret-only change under the same id works too
        let mut st = AuthState::new(Some(cfg(KeyedMd5, 1, "a")), 0, now);
        st.set(Some(cfg(KeyedMd5, 1, "b")), now, det);
        assert_eq!(
            rx(&mut st, now, &sign(&hdr(), &cfg(KeyedMd5, 1, "a"), 1)),
            Ok(())
        );
        assert_eq!(
            rx(&mut st, now, &sign(&hdr(), &cfg(KeyedMd5, 1, "b"), 1)),
            Ok(())
        );
    }

    #[test]
    fn method_change_resets_the_sequence_space() {
        let now = Instant::now();
        let mut st = state(MeticulousMd5);
        assert_eq!(
            rx(
                &mut st,
                now,
                &sign(&hdr(), &cfg(MeticulousMd5, 1, "k"), 9000)
            ),
            Ok(())
        );
        st.set(
            Some(cfg(MeticulousSha1, 1, "k")),
            now,
            Duration::from_secs(1),
        );
        assert_eq!(
            rx(&mut st, now, &sign(&hdr(), &cfg(MeticulousSha1, 1, "k"), 5)),
            Ok(())
        );
    }
}
