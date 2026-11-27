//! Seamless BFD (RFC 7880, RFC 7881): the stateless reflector's decision
//! (`reflect`, pure) and the initiator's session (`Initiator`, pure, driven by
//! `run`). The reflector's counters and sockets are `reflector`/`socket`.
//!
//! - The initiator sends D=1 control packets to UDP 7784 from its own
//!   per-session socket and gets the reflection back there; Figure 4 of
//!   RFC 7880 has no Init state: Up on a reflected Up, Down on `AdminDown` or
//!   when the detection time passes without a reply.
//! - The reflector keeps nothing per initiator: one packet in, at most one out.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use nos_proto::schema::BfdProfile;
use nos_proto::{BfdDiag, BfdSessionKind, BfdState, SessionKey};
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use crate::auth::{self, AuthError, AuthKey, AuthState};
use crate::manager::ttl_ok;
use crate::packet::Packet;
use crate::session::{self, Status, Tx};
use crate::timers::SLOW_US;

/// RFC 7881 §2: the reflector's UDP port.
pub const PORT: u16 = 7784;
/// The Required Min RX Interval a reflector advertises (RFC 7880 §7.2.3):
/// the daemon's 10 ms floor, the real limit being the global rate limit.
pub const REFLECTOR_RX_US: u32 = 10_000;
const MS: u32 = 1000;
/// RFC 5880 §4.1 C bit: `nos-bfdd` is its own process.
const CPI: bool = true;

/// Why the reflector dropped a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    Malformed,
    SourcePort,
    Martian,
    Filtered,
    RateLimited,
    Authenticated,
    /// The A bit is set and a key matches, but the digest is wrong.
    AuthFailed,
    DemandClear,
    UnknownDiscriminator,
}

/// What the reflector answers for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub discriminators: Vec<u32>,
    pub allow_from: Vec<IpNet>,
    /// RFC 7880 §11 keys (resolved from the keystore), picked by Auth Key ID.
    pub keys: Vec<AuthKey>,
}

/// A reply and, for an authenticated probe, the key and sequence number it
/// is signed with (§11: the reflector reuses the received sequence number).
pub type Reply = (Packet, Option<(AuthKey, u32)>);

impl Policy {
    /// The wire bytes of a `reflect` reply.
    pub fn wire((p, sign): &Reply) -> Vec<u8> {
        match sign {
            Some((k, seq)) => auth::sign(&p.encode(), k, *seq),
            None => p.encode().to_vec(),
        }
    }
}

/// RFC 7881 §7: sources that must never be acted on or answered. A link-local
/// source is fine only towards a link-local destination (it is on-link).
pub fn is_martian(src: IpAddr, dst: IpAddr) -> bool {
    let link_local = |a: IpAddr| match a {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => a.segments()[0] & 0xffc0 == 0xfe80,
    };
    let reserved = match src {
        IpAddr::V4(a) => a.is_broadcast() || a.octets()[0] == 0 || a.octets()[0] >= 240,
        IpAddr::V6(_) => false,
    };
    src.is_unspecified()
        || src.is_multicast()
        || src.is_loopback()
        || reserved
        || (link_local(src) && !link_local(dst))
}

/// RFC 7880 §7.2: the reply to an S-BFD Control packet `p` that arrived from
/// `src` addressed to `dst`, or the reason it is dropped.
pub fn reflect(
    p: &Packet,
    src: SocketAddr,
    dst: IpAddr,
    policy: &Policy,
) -> Result<Reply, Discard> {
    // RFC 7881 §6: a probe from the reflector port is a reflection.
    if src.port() == PORT {
        return Err(Discard::SourcePort);
    }
    if is_martian(src.ip(), dst) {
        return Err(Discard::Martian);
    }
    if !policy.allow_from.is_empty() && !policy.allow_from.iter().any(|n| n.contains(&src.ip())) {
        return Err(Discard::Filtered);
    }
    // RFC 7880 §7.2.3.
    if !p.demand {
        return Err(Discard::DemandClear);
    }
    if !policy.discriminators.contains(&p.your_discriminator) {
        return Err(Discard::UnknownDiscriminator);
    }
    // RFC 7880 §11: the sequence number is not checked (no state), the key is
    // picked by type and Auth Key ID; unsigned probes are answered unsigned.
    let sign = match &p.auth {
        None => None,
        Some(sec) => {
            let k = auth::verify(sec, &policy.keys).map_err(|e| match e {
                AuthError::TypeMismatch | AuthError::KeyIdMismatch => Discard::Authenticated,
                _ => Discard::AuthFailed,
            })?;
            Some((k.clone(), sec.seq))
        }
    };
    let reply = Packet {
        diag: BfdDiag::NoDiagnostic.code(),
        // RFC 7880 §7.2.3: Up (AdminDown is only for an entity out of service).
        state: BfdState::Up,
        // RFC 5880 §6.5: the answer to a Poll is a Final.
        poll: false,
        final_: p.poll,
        control_plane_independent: CPI,
        demand: false,
        detect_mult: p.detect_mult,
        my_discriminator: p.your_discriminator,
        your_discriminator: p.my_discriminator,
        desired_min_tx: p.desired_min_tx,
        required_min_rx: REFLECTOR_RX_US,
        // No S-BFD Echo loopback (RFC 7880 §7.2.2 allows 0).
        required_min_echo_rx: 0,
        auth: None,
    };
    Ok((reply, sign))
}

/// The S-BFD discriminator an initiator probes for `peer` under `profile`:
/// the profile's, else the peer's own IPv4 address. `None` for an IPv6 peer
/// with neither.
pub fn remote_discriminator(peer: IpAddr, profile: &BfdProfile) -> Option<u32> {
    match (profile.sbfd_remote_discriminator, peer) {
        (Some(d), _) => Some(u32::from(d)),
        (None, IpAddr::V4(a)) => Some(u32::from(a)),
        (None, IpAddr::V6(_)) => None,
    }
}

/// An S-BFD initiator session (RFC 7880 §7.3), pure like `session::Core`.
#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent flags of one small state machine"
)]
pub struct Initiator {
    tx_us: u32,
    detect_mult: u8,
    shutdown: bool,
    local_disc: u32,
    remote_disc: Option<u32>,
    state: BfdState,
    diag: BfdDiag,
    /// The reflector's Required Min RX of the last reply.
    reflected_rx: u32,
    remote_cpi: bool,
    /// An `AdminDown` reply was seen: no faster than 1 s until an Up one.
    backoff: bool,
    last_rx: Instant,
    next_tx: Instant,
    /// The profile asks for authentication (§11); without its key nothing is
    /// sent (fail closed).
    auth_required: bool,
    auth: AuthState,
    /// The sequence numbers of the last `2 x detect_mult` probes: the
    /// permissible range of a reflected one (§11).
    sent_seqs: VecDeque<u32>,
    auth_failures: u64,
    /// Failures since the last good reply; the first of a run is `warn!`ed.
    auth_streak: bool,
    auth_note: Option<bool>,
}

impl Initiator {
    pub fn new(
        profile: &BfdProfile,
        key: Option<AuthKey>,
        local_disc: u32,
        remote_disc: Option<u32>,
        now: Instant,
    ) -> Self {
        let mut i = Initiator {
            tx_us: profile.min_tx_interval * MS,
            detect_mult: profile.detect_multiplier,
            shutdown: profile.shutdown,
            local_disc,
            remote_disc,
            state: BfdState::Down,
            diag: BfdDiag::NoDiagnostic,
            reflected_rx: 0,
            remote_cpi: false,
            backoff: false,
            last_rx: now,
            next_tx: now,
            auth_required: profile.auth.is_some(),
            auth: AuthState::new(key, session::rand_u32(), now),
            sent_seqs: VecDeque::new(),
            auth_failures: 0,
            auth_streak: false,
            auth_note: None,
        };
        i.settle(now);
        i
    }

    /// Whether packets go out at all.
    fn active(&self) -> bool {
        !self.shutdown
            && self.remote_disc.is_some()
            && (!self.auth_required || self.auth.cfg().is_some())
    }

    /// Keeps the state in line with `active` after a configuration change.
    fn settle(&mut self, now: Instant) {
        if self.shutdown {
            self.state = BfdState::AdminDown;
            self.diag = BfdDiag::AdministrativelyDown;
        } else if self.state == BfdState::AdminDown {
            self.state = BfdState::Down;
            self.diag = BfdDiag::NoDiagnostic;
        }
        if !self.active() {
            // Nothing to send: park the clock far away.
            self.next_tx = now + Duration::from_secs(3600);
        }
    }

    /// RFC 7880 §7.3.3: the larger of our interval and what the reflector
    /// asked for, at least 1 s after an `AdminDown` reply.
    fn interval_us(&self) -> u32 {
        let base = self.tx_us.max(self.reflected_rx);
        if self.backoff {
            base.max(SLOW_US)
        } else {
            base
        }
    }

    fn detect_us(&self) -> u64 {
        u64::from(self.detect_mult) * u64::from(self.interval_us())
    }

    pub fn status(&self) -> Status {
        Status {
            state: self.state,
            diag: self.diag,
            local_discriminator: self.local_disc,
            remote_discriminator: self.remote_disc.unwrap_or(0),
            tx_interval_us: self.interval_us(),
            detection_time_us: u32::try_from(self.detect_us()).unwrap_or(u32::MAX),
            control_plane_independent: self.state == BfdState::Up && CPI && self.remote_cpi,
            auth_method: self.auth.cfg().map(|k| k.method),
            auth_key_id: self.auth.cfg().map(|k| k.key_id),
            auth_failures: self.auth_failures,
            echo_active: false,
            echo_interval_us: 0,
            echo_only: false,
            tx_pdu_bytes: 0,
            kind: BfdSessionKind::SbfdInitiator,
            remote: None,
        }
    }

    /// RFC 7880 §7.3.2.
    fn packet(&self) -> Packet {
        Packet {
            diag: self.diag.code(),
            state: self.state,
            poll: false,
            final_: false,
            control_plane_independent: CPI,
            // Always 1: the packet comes from an initiator.
            demand: true,
            detect_mult: self.detect_mult,
            my_discriminator: self.local_disc,
            your_discriminator: self.remote_disc.unwrap_or(0),
            desired_min_tx: self.tx_us,
            required_min_rx: 0,
            required_min_echo_rx: 0,
            auth: None,
        }
    }

    /// Whether a new auth failure was counted since the last call, and if it
    /// is the first of a streak.
    pub fn take_auth_failure(&mut self) -> Option<bool> {
        self.auth_note.take()
    }

    /// §11: an authenticated profile takes only a reflection signed with its
    /// key whose sequence number is one of the recent probes'; an
    /// unauthenticated one takes none with the A bit.
    fn reply_authentic(&mut self, p: &Packet) -> bool {
        let ok = match (self.auth_required, &p.auth, self.auth.cfg()) {
            (false, None, _) => true,
            (true, Some(sec), Some(k)) => {
                auth::verify(sec, [k]).is_ok()
                    && (sec.kind == 1 || self.sent_seqs.contains(&sec.seq))
            }
            _ => false,
        };
        if ok {
            self.auth_streak = false;
        } else {
            self.auth_failures += 1;
            self.auth_note = Some(!self.auth_streak);
            self.auth_streak = true;
        }
        ok
    }

    /// A reply from the reflector. Whether the state changed.
    pub fn on_packet(&mut self, now: Instant, p: &Packet) -> bool {
        // RFC 7880 §7.1: a packet with D=1 is not a reflection; the rest must
        // be the answer to us.
        if !self.active()
            || p.demand
            || p.your_discriminator != self.local_disc
            || Some(p.my_discriminator) != self.remote_disc
        {
            return false;
        }
        if !self.reply_authentic(p) {
            return false;
        }
        match p.state {
            BfdState::Up => {
                self.backoff = false;
                self.note_reply(now, p);
                if self.state == BfdState::Up {
                    return false;
                }
                self.state = BfdState::Up;
                self.diag = BfdDiag::NoDiagnostic;
                true
            }
            BfdState::AdminDown => {
                // §7.3.3: not a loss of reachability, but slow down.
                self.backoff = true;
                self.note_reply(now, p);
                let was_up = self.state == BfdState::Up;
                self.state = BfdState::Down;
                self.diag = BfdDiag::NoDiagnostic;
                was_up
            }
            // A reflector never sends these.
            BfdState::Down | BfdState::Init => false,
        }
    }

    fn note_reply(&mut self, now: Instant, p: &Packet) {
        self.last_rx = now;
        self.reflected_rx = p.required_min_rx;
        self.remote_cpi = p.control_plane_independent;
    }

    /// The clock reached `deadline()`: detection expiry and periodic
    /// transmit. `rand_pct` is the §6.8.7 jitter draw.
    pub fn on_timer(&mut self, now: Instant, rand_pct: u32) -> Option<Packet> {
        if !self.active() {
            return None;
        }
        if self.state == BfdState::Up
            && now.saturating_duration_since(self.last_rx)
                >= Duration::from_micros(self.detect_us())
        {
            self.state = BfdState::Down;
            self.diag = BfdDiag::ControlDetectionTimeExpired;
            self.remote_cpi = false;
        }
        if now < self.next_tx {
            return None;
        }
        let max_pct = if self.detect_mult == 1 { 90 } else { 100 };
        let pct = u64::from(rand_pct.clamp(75, max_pct));
        self.next_tx = now + Duration::from_micros(u64::from(self.interval_us()) * pct / 100);
        Some(self.packet())
    }

    /// The wire bytes of a probe from `on_timer`: signed when the profile has a key.
    pub fn wire(&mut self, now: Instant, p: &Packet) -> Vec<u8> {
        let d = Some(Duration::from_micros(self.detect_us()));
        let b = self.auth.sign(now, &p.encode(), d);
        if self.auth.cfg().is_some() {
            self.sent_seqs.push_back(self.auth.xmit_seq());
            while self.sent_seqs.len() > 2 * usize::from(self.detect_mult) {
                self.sent_seqs.pop_front();
            }
        }
        b
    }

    /// A re-`Register` with a new profile or remote discriminator.
    pub fn update(
        &mut self,
        profile: &BfdProfile,
        key: Option<AuthKey>,
        remote_disc: Option<u32>,
        now: Instant,
    ) {
        let was_active = self.active();
        self.auth_required = profile.auth.is_some();
        self.auth
            .set(key, now, Duration::from_micros(self.detect_us()));
        self.tx_us = profile.min_tx_interval * MS;
        self.detect_mult = profile.detect_multiplier;
        if remote_disc != self.remote_disc {
            self.remote_disc = remote_disc;
            self.state = BfdState::Down;
            self.diag = BfdDiag::NoDiagnostic;
            self.reflected_rx = 0;
        }
        self.shutdown = profile.shutdown;
        self.settle(now);
        if self.active() && !was_active {
            self.next_tx = now;
            self.last_rx = now;
        }
    }

    pub fn deadline(&self) -> Instant {
        if self.state == BfdState::Up {
            self.next_tx
                .min(self.last_rx + Duration::from_micros(self.detect_us()))
        } else {
            self.next_tx
        }
    }
}

/// A decoded reflection and the TTL it arrived with.
pub type Reflection = (Packet, Option<u8>);

/// The transport of one initiator: the connected socket's send side, and the
/// replies it receives (with their TTL).
pub struct SbfdPath {
    pub tx: std::sync::Arc<dyn Tx>,
    pub rx: mpsc::Receiver<Reflection>,
    pub task: tokio::task::AbortHandle,
}

impl Drop for SbfdPath {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The initiator task. Ends when the manager drops its senders (or aborts it).
pub async fn run(
    key: SessionKey,
    mut core: Initiator,
    mut path: SbfdPath,
    mut min_ttl: u8,
    mut cmds: mpsc::Receiver<session::Cmd>,
    status: watch::Sender<Status>,
    counters: Arc<session::Stats>,
) {
    let mut last = core.status();
    loop {
        let deadline = tokio::time::Instant::from_std(core.deadline());
        let out = tokio::select! {
            p = path.rx.recv() => match p {
                Some((p, ttl)) => {
                    if ttl_ok(key.multihop, ttl, min_ttl) {
                        counters.count_rx();
                        core.on_packet(now(), &p);
                        match core.take_auth_failure() {
                            Some(true) => warn!(peer = %key.peer, "bfd sbfd reply discarded: auth"),
                            Some(false) => debug!(peer = %key.peer, "bfd sbfd reply discarded: auth"),
                            None => {}
                        }
                    } else {
                        debug!(peer = %key.peer, ttl = ?ttl, "bfd sbfd reply discarded: ttl");
                    }
                    None
                }
                None => break,
            },
            c = cmds.recv() => match c {
                Some((c, k)) => {
                    min_ttl = c.minimum_ttl;
                    core.update(&c, k, remote_discriminator(key.peer, &c), now());
                    None
                }
                None => break,
            },
            () = tokio::time::sleep_until(deadline) => core.on_timer(now(), session::jitter_pct()),
        };
        if let Some(p) = out {
            let wire = core.wire(now(), &p);
            match path.tx.send(&wire) {
                Ok(()) => counters.count_tx(),
                Err(e) => debug!(peer = %key.peer, error = %e, "bfd sbfd send failed"),
            }
        }
        let s = core.status();
        if s != last {
            if s.state != last.state {
                counters.on_transition(last.state, s.state, now());
                session::log_transition(&key, &s);
            }
            last = s;
            status.send_replace(s);
        }
    }
}

fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Warns once at start for a session that cannot run.
pub fn warn_no_discriminator(key: &SessionKey) {
    warn!(peer = %key.peer, table = %key.table, "bfd sbfd session needs sbfd-remote-discriminator for an IPv6 peer");
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISC: u32 = 0x0a00_0001;
    const MINE: u32 = 77;

    fn probe() -> Packet {
        Packet {
            diag: 0,
            state: BfdState::Down,
            poll: false,
            final_: false,
            control_plane_independent: true,
            demand: true,
            detect_mult: 3,
            my_discriminator: MINE,
            your_discriminator: DISC,
            desired_min_tx: 300_000,
            required_min_rx: 0,
            required_min_echo_rx: 0,
            auth: None,
        }
    }

    fn policy() -> Policy {
        Policy {
            discriminators: vec![DISC],
            allow_from: vec![],
            keys: vec![],
        }
    }

    fn src(s: &str, port: u16) -> SocketAddr {
        SocketAddr::new(s.parse().unwrap(), port)
    }

    fn dst() -> IpAddr {
        "10.0.0.2".parse().unwrap()
    }

    #[test]
    fn reply_fields_follow_rfc_7880_section_7_2_2() {
        let r = reflect(&probe(), src("10.0.0.1", 50000), dst(), &policy())
            .unwrap()
            .0;
        assert_eq!(r.state, BfdState::Up);
        assert!(!r.demand, "D=0 marks a reflection");
        assert_eq!(r.detect_mult, 3);
        assert_eq!(r.my_discriminator, DISC);
        assert_eq!(r.your_discriminator, MINE);
        assert_eq!(r.desired_min_tx, 300_000);
        assert_eq!(r.required_min_rx, REFLECTOR_RX_US);
        assert_eq!(r.required_min_echo_rx, 0);
        assert!(!r.poll && !r.final_);
        // The reply is a valid Control packet for the codec.
        assert_eq!(crate::packet::decode(&r.encode()), Ok(r));
    }

    #[test]
    fn a_poll_is_answered_with_a_final() {
        let r = reflect(
            &Packet {
                poll: true,
                ..probe()
            },
            src("10.0.0.1", 50000),
            dst(),
            &policy(),
        )
        .unwrap()
        .0;
        assert!(r.final_ && !r.poll);
    }

    #[test]
    fn every_discard_rule() {
        let from = src("10.0.0.1", 50000);
        let go = |p: Packet, s: SocketAddr, d: IpAddr, pol: &Policy| reflect(&p, s, d, pol);
        assert_eq!(
            go(probe(), src("10.0.0.1", PORT), dst(), &policy()),
            Err(Discard::SourcePort)
        );
        assert_eq!(
            go(
                Packet {
                    demand: false,
                    ..probe()
                },
                from,
                dst(),
                &policy()
            ),
            Err(Discard::DemandClear)
        );
        assert_eq!(
            go(
                Packet {
                    your_discriminator: DISC + 1,
                    ..probe()
                },
                from,
                dst(),
                &policy()
            ),
            Err(Discard::UnknownDiscriminator)
        );
        assert_eq!(
            go(probe(), from, dst(), &Policy::default()),
            Err(Discard::UnknownDiscriminator),
            "no discriminator configured"
        );
        let authed = Packet {
            auth: Some(crate::auth::AuthSection {
                kind: 2,
                key_id: 1,
                seq: 0,
                data: vec![],
                raw: vec![],
            }),
            ..probe()
        };
        assert_eq!(
            go(authed, from, dst(), &policy()),
            Err(Discard::Authenticated)
        );
        let only = Policy {
            allow_from: vec!["192.0.2.0/24".parse().unwrap()],
            ..policy()
        };
        assert_eq!(go(probe(), from, dst(), &only), Err(Discard::Filtered));
        assert!(go(probe(), src("192.0.2.9", 50000), dst(), &only).is_ok());
    }

    #[test]
    fn martian_sources() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for m in [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "0.1.2.3",
            "::",
            "::1",
            "ff02::1",
            "169.254.1.1",
            "fe80::1",
        ] {
            assert!(is_martian(ip(m), ip("10.0.0.2")), "{m}");
        }
        assert!(!is_martian(ip("10.0.0.1"), ip("10.0.0.2")));
        assert!(!is_martian(ip("2001:db8::1"), ip("2001:db8::2")));
        // On-link link-local to link-local is fine.
        assert!(!is_martian(ip("fe80::1"), ip("fe80::2")));
        assert!(!is_martian(ip("169.254.1.1"), ip("169.254.1.2")));
        assert_eq!(
            reflect(&probe(), src("127.0.0.1", 50000), dst(), &policy()),
            Err(Discard::Martian)
        );
    }

    #[test]
    fn remote_discriminator_defaults_to_the_ipv4_peer() {
        let mut p = BfdProfile::default();
        assert_eq!(
            remote_discriminator("10.0.0.2".parse().unwrap(), &p),
            Some(0x0a00_0002)
        );
        assert_eq!(
            remote_discriminator("2001:db8::2".parse().unwrap(), &p),
            None
        );
        p.sbfd_remote_discriminator = Some("10.9.9.9".parse().unwrap());
        assert_eq!(
            remote_discriminator("2001:db8::2".parse().unwrap(), &p),
            Some(0x0a09_0909)
        );
    }

    fn profile(tx: u32) -> BfdProfile {
        BfdProfile {
            min_tx_interval: tx,
            ..BfdProfile::default()
        }
    }

    fn reply(state: BfdState, rx: u32) -> Packet {
        Packet {
            state,
            demand: false,
            my_discriminator: DISC,
            your_discriminator: MINE,
            required_min_rx: rx,
            ..probe()
        }
    }

    #[test]
    fn initiator_packet_follows_rfc_7880_section_7_3_2() {
        let now = Instant::now();
        let mut i = Initiator::new(&profile(100), None, MINE, Some(DISC), now);
        let p = i.on_timer(now, 100).expect("the first packet goes at once");
        assert!(p.demand);
        assert_eq!(p.state, BfdState::Down);
        assert_eq!(p.my_discriminator, MINE);
        assert_eq!(p.your_discriminator, DISC);
        assert_eq!((p.required_min_rx, p.required_min_echo_rx), (0, 0));
        assert_eq!(p.desired_min_tx, 100_000);
        // No 1 s wait while Down: S-BFD removes the seam.
        assert_eq!(i.deadline() - now, Duration::from_millis(100));
        assert!(crate::packet::decode(&p.encode()).is_ok());
    }

    #[test]
    fn up_on_an_up_reply_and_down_on_silence() {
        let t0 = Instant::now();
        let mut i = Initiator::new(&profile(100), None, MINE, Some(DISC), t0);
        i.on_timer(t0, 100);
        assert!(i.on_packet(t0, &reply(BfdState::Up, REFLECTOR_RX_US)));
        assert_eq!(i.state, BfdState::Up);
        assert!(i.status().control_plane_independent);
        // tx = max(100 ms, 10 ms), detect = 3 x 100 ms.
        assert_eq!(i.status().detection_time_us, 300_000);
        assert!(!i.on_packet(t0, &reply(BfdState::Up, REFLECTOR_RX_US)));
        // Replies keep it up.
        let t1 = t0 + Duration::from_millis(250);
        i.on_packet(t1, &reply(BfdState::Up, REFLECTOR_RX_US));
        i.on_timer(t1 + Duration::from_millis(100), 100);
        assert_eq!(i.state, BfdState::Up);
        // Then silence.
        let t2 = t1 + Duration::from_millis(300);
        i.on_timer(t2, 100);
        assert_eq!(i.state, BfdState::Down);
        assert_eq!(i.diag, BfdDiag::ControlDetectionTimeExpired);
        assert!(!i.status().control_plane_independent);
        // And it keeps probing.
        assert!(i.on_timer(i.deadline(), 100).is_some());
    }

    #[test]
    fn the_reflected_required_min_rx_slows_the_probe() {
        let t0 = Instant::now();
        let mut i = Initiator::new(&profile(100), None, MINE, Some(DISC), t0);
        i.on_packet(t0, &reply(BfdState::Up, 500_000));
        assert_eq!(i.status().tx_interval_us, 500_000);
        assert_eq!(i.status().detection_time_us, 1_500_000);
    }

    #[test]
    fn admin_down_backs_off_to_a_second_without_a_failure_diag() {
        let t0 = Instant::now();
        let mut i = Initiator::new(&profile(100), None, MINE, Some(DISC), t0);
        i.on_packet(t0, &reply(BfdState::Up, REFLECTOR_RX_US));
        assert!(i.on_packet(t0, &reply(BfdState::AdminDown, REFLECTOR_RX_US)));
        assert_eq!(i.state, BfdState::Down);
        assert_eq!(i.diag, BfdDiag::NoDiagnostic, "reachability is not lost");
        assert_eq!(i.status().tx_interval_us, 1_000_000);
        // Still probing, at 1 s.
        let p = i.on_timer(i.deadline(), 100);
        assert!(p.is_some());
        assert!(i.deadline() - t0 >= Duration::from_secs(1));
        // An Up reply ends the back-off.
        i.on_packet(t0, &reply(BfdState::Up, REFLECTOR_RX_US));
        assert_eq!(i.status().tx_interval_us, 100_000);
    }

    #[test]
    fn replies_that_are_not_ours_are_discarded() {
        let t0 = Instant::now();
        let mut i = Initiator::new(&profile(100), None, MINE, Some(DISC), t0);
        let ok = reply(BfdState::Up, REFLECTOR_RX_US);
        for bad in [
            Packet {
                demand: true,
                ..ok.clone()
            },
            Packet {
                your_discriminator: MINE + 1,
                ..ok.clone()
            },
            Packet {
                my_discriminator: DISC + 1,
                ..ok.clone()
            },
            Packet {
                state: BfdState::Init,
                ..ok.clone()
            },
            Packet {
                state: BfdState::Down,
                ..ok.clone()
            },
        ] {
            assert!(!i.on_packet(t0, &bad));
            assert_eq!(i.state, BfdState::Down);
        }
        assert!(i.on_packet(t0, &ok));
    }

    #[test]
    fn shutdown_and_a_missing_discriminator_send_nothing() {
        let t0 = Instant::now();
        let mut down = profile(100);
        down.shutdown = true;
        let mut i = Initiator::new(&down, None, MINE, Some(DISC), t0);
        assert_eq!(i.state, BfdState::AdminDown);
        assert!(i.on_timer(t0 + Duration::from_secs(5), 100).is_none());
        assert!(!i.on_packet(t0, &reply(BfdState::Up, 0)));
        // Enabled again: probing resumes at once.
        i.update(&profile(100), None, Some(DISC), t0);
        assert_eq!(i.state, BfdState::Down);
        assert!(i.on_timer(t0, 100).is_some());

        let mut none = Initiator::new(&profile(100), None, MINE, None, t0);
        assert!(none.on_timer(t0, 100).is_none());
        // Naming one starts it.
        none.update(&profile(100), None, Some(DISC), t0);
        assert!(none.on_timer(t0, 100).is_some());
    }

    #[test]
    fn a_new_remote_discriminator_restarts_the_probe() {
        let t0 = Instant::now();
        let mut i = Initiator::new(&profile(100), None, MINE, Some(DISC), t0);
        i.on_packet(t0, &reply(BfdState::Up, REFLECTOR_RX_US));
        i.update(&profile(100), None, Some(DISC + 1), t0);
        assert_eq!(i.state, BfdState::Down);
        assert_eq!(i.on_timer(t0, 100).unwrap().your_discriminator, DISC + 1);
    }

    use nos_proto::schema::{BfdAuth, BfdAuthMethod};

    fn key(id: u8, secret: &str) -> AuthKey {
        AuthKey::new(
            &BfdAuth {
                key_id: id,
                method: BfdAuthMethod::KeyedSha1,
                key: "l".into(),
            },
            secret,
        )
    }

    fn keyed_policy() -> Policy {
        Policy {
            keys: vec![key(1, "secretA")],
            ..policy()
        }
    }

    fn signed_probe(k: &AuthKey, seq: u32) -> Packet {
        crate::packet::decode(&auth::sign(&probe().encode(), k, seq)).unwrap()
    }

    fn auth_profile(tx: u32) -> BfdProfile {
        BfdProfile {
            auth: Some(BfdAuth {
                key_id: 1,
                method: BfdAuthMethod::KeyedSha1,
                key: "l".into(),
            }),
            ..profile(tx)
        }
    }

    #[test]
    fn reflector_signs_the_reply_with_the_received_sequence_number() {
        let from = src("10.0.0.1", 50000);
        let reply = reflect(
            &signed_probe(&key(1, "secretA"), 0xdead_beef),
            from,
            dst(),
            &keyed_policy(),
        )
        .unwrap();
        let wire = Policy::wire(&reply);
        let sec = crate::packet::decode(&wire).unwrap().auth.unwrap();
        assert_eq!((sec.kind, sec.key_id, sec.seq), (4, 1, 0xdead_beef));
        assert!(auth::verify(&sec, &[key(1, "secretA")]).is_ok());
        // Unsigned probes are still answered, unsigned.
        let plain = reflect(&probe(), from, dst(), &keyed_policy()).unwrap();
        assert!(plain.1.is_none());
        assert!(crate::packet::decode(&Policy::wire(&plain))
            .unwrap()
            .auth
            .is_none());
        // Any old sequence number is fine: the reflector has no state.
        assert!(reflect(
            &signed_probe(&key(1, "secretA"), 1),
            from,
            dst(),
            &keyed_policy()
        )
        .is_ok());
    }

    #[test]
    fn reflector_auth_discards() {
        let from = src("10.0.0.1", 50000);
        let go = |k: &AuthKey| reflect(&signed_probe(k, 5), from, dst(), &keyed_policy());
        assert_eq!(go(&key(1, "other")).unwrap_err(), Discard::AuthFailed);
        assert_eq!(go(&key(2, "secretA")).unwrap_err(), Discard::Authenticated);
        let md5 = AuthKey::new(
            &BfdAuth {
                key_id: 1,
                method: BfdAuthMethod::KeyedMd5,
                key: "l".into(),
            },
            "secretA",
        );
        assert_eq!(go(&md5).unwrap_err(), Discard::Authenticated);
        assert_eq!(
            reflect(&signed_probe(&key(1, "secretA"), 5), from, dst(), &policy()).unwrap_err(),
            Discard::Authenticated,
            "no key configured"
        );
    }

    fn up_auth_initiator(t0: Instant, k: Option<AuthKey>) -> Initiator {
        Initiator::new(&auth_profile(100), k, MINE, Some(DISC), t0)
    }

    /// One probe through the real reflector and back.
    fn round_trip(i: &mut Initiator, now: Instant, pol: &Policy) -> Vec<u8> {
        let p = i.on_timer(now, 100).unwrap();
        let wire = i.wire(now, &p);
        let probe = crate::packet::decode(&wire).unwrap();
        let reply = reflect(&probe, src("10.0.0.1", 50000), dst(), pol).unwrap();
        Policy::wire(&reply)
    }

    #[test]
    fn initiator_signs_and_accepts_a_signed_reflection() {
        let t0 = Instant::now();
        let mut i = up_auth_initiator(t0, Some(key(1, "secretA")));
        let wire = round_trip(&mut i, t0, &keyed_policy());
        let reply = crate::packet::decode(&wire).unwrap();
        assert!(i.on_packet(t0, &reply));
        let st = i.status();
        assert_eq!(st.auth_method, Some(BfdAuthMethod::KeyedSha1));
        assert_eq!((st.auth_key_id, st.auth_failures), (Some(1), 0));
    }

    #[test]
    fn initiator_rejects_bad_missing_and_out_of_range_reflections() {
        let t0 = Instant::now();
        let k = key(1, "secretA");
        let mut i = up_auth_initiator(t0, Some(k.clone()));
        let wire = round_trip(&mut i, t0, &keyed_policy());
        let good = crate::packet::decode(&wire).unwrap();
        let seq = good.auth.as_ref().unwrap().seq;
        let unsigned = Packet {
            auth: None,
            ..good.clone()
        };
        assert!(!i.on_packet(t0, &unsigned));
        assert_eq!(i.take_auth_failure(), Some(true), "first of a streak");
        let bad = crate::packet::decode(&auth::sign(&good.encode(), &key(1, "nope"), seq)).unwrap();
        assert!(!i.on_packet(t0, &bad));
        assert_eq!(i.take_auth_failure(), Some(false), "same streak");
        let far = crate::packet::decode(&auth::sign(&good.encode(), &k, seq ^ 0x1000)).unwrap();
        assert!(!i.on_packet(t0, &far));
        assert_eq!(i.status().auth_failures, 3);
        assert_eq!(i.state, BfdState::Down);
        assert!(i.on_packet(t0, &good));
        // A reflection with the A bit on an unauthenticated profile.
        let mut plain = Initiator::new(&profile(100), None, MINE, Some(DISC), t0);
        assert!(!plain.on_packet(t0, &good));
        assert_eq!(plain.status().auth_failures, 1);
    }

    #[test]
    fn an_unresolved_key_sends_nothing_until_it_arrives() {
        let t0 = Instant::now();
        let mut i = up_auth_initiator(t0, None);
        assert!(i.on_timer(t0 + Duration::from_secs(5), 100).is_none());
        assert_eq!(i.status().auth_method, None);
        i.update(&auth_profile(100), Some(key(1, "secretA")), Some(DISC), t0);
        assert!(i.on_timer(t0, 100).is_some());
    }
}
