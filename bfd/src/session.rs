//! One BFD session: `Core` is the pure state (packets, timers and clock in,
//! packets out), `run` the tokio task that feeds it.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nos_proto::schema::{BfdAuthMethod, BfdProfile, EchoMode};

use nos_proto::{BfdDiag, BfdSessionKind, BfdState, SessionKey};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::auth::{AuthError, AuthKey, AuthState};
use crate::fsm::{self, Event};
use crate::packet::Packet;
use crate::timers::{Remote, Timers, SLOW_US};

/// A profile and its resolved auth key: what a session task is told (#510).
pub type Cmd = (BfdProfile, Option<AuthKey>);

/// Where a session's packets leave: one connected UDP socket for real, a
/// recorder in tests.
pub trait Tx: Send + Sync {
    fn send(&self, bytes: &[u8]) -> io::Result<()>;
}

/// The Echo transport of one session: where packets leave, the channel
/// returned sequence numbers arrive on, and the helper tasks to stop with it.
pub struct EchoPath {
    pub tx: Arc<dyn EchoTx>,
    pub rx: mpsc::Receiver<Looped>,
    pub tasks: Vec<tokio::task::AbortHandle>,
}

/// What came back through the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Looped {
    /// An affiliated Echo payload's sequence number.
    Seq(u32),
    /// An unaffiliated session's own Control packet (RFC 9747), with the
    /// state it carried.
    Control(BfdState),
}

/// The Tx of a session with no Control traffic (RFC 9747).
pub struct NoTx;

impl Tx for NoTx {
    fn send(&self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for EchoPath {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// What the rest of the daemon (and `show bfd sessions`) sees of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub state: BfdState,
    pub diag: BfdDiag,
    pub local_discriminator: u32,
    pub remote_discriminator: u32,
    pub tx_interval_us: u32,
    pub detection_time_us: u32,
    /// C bit at both ends (see `BfdEvent::State`).
    pub control_plane_independent: bool,
    /// The configured authentication (never the key).
    pub auth_method: Option<BfdAuthMethod>,
    pub auth_key_id: Option<u8>,
    /// Packets dropped by §6.7 authentication so far.
    pub auth_failures: u64,
    /// The Echo function is running (RFC 5880 §6.4).
    pub echo_active: bool,
    /// Negotiated Echo transmit interval, microseconds; 0 while inactive.
    pub echo_interval_us: u32,
    /// RFC 9747: Echo is the whole session, there is no Control traffic.
    pub echo_only: bool,
    /// RFC 9764 `padded-pdu-size`, 0 when not padded.
    pub tx_pdu_bytes: u32,
    pub kind: BfdSessionKind,
}

/// Where a session's Echo packets leave: the IP packet looped through the
/// neighbour (`socket::L2Echo` for real, a recorder in tests).
pub trait EchoTx: Send + Sync {
    /// Sends one Echo packet carrying `payload`.
    fn send(&self, payload: &[u8]) -> io::Result<()>;
}

/// The Echo function's running state.
#[derive(Debug)]
struct EchoRun {
    next_tx: Instant,
    /// The last time a returned echo (or the activation) was seen.
    last_ok: Instant,
    sent: u32,
    acked: u32,
}

/// RFC 5880 §4.1 C bit: `nos-bfdd` is its own process, so a `nos-bgpd`
/// restart does not stop its packets.
const LOCAL_CPI: bool = true;

#[derive(Debug)]
pub struct Core {
    profile: BfdProfile,
    state: BfdState,
    diag: BfdDiag,
    local_disc: u32,
    remote_disc: u32,
    /// The remote's Required Min RX; 0 silences us (§6.8.7). Starts at 1:
    /// nothing is known yet.
    remote_rx: u32,
    /// The C bit of the last packet received.
    remote_cpi: bool,
    /// The remote's Required Min Echo RX Interval; 0: it cannot loop echo.
    remote_echo_rx: u32,
    /// There is a transport for our own Echo packets (`run` sets it).
    echo_path: bool,
    echo: Option<EchoRun>,
    timers: Timers,
    auth: AuthState,
    auth_failures: u64,
}

const MS: u32 = 1000;

impl Core {
    pub fn new(profile: BfdProfile, key: Option<AuthKey>, local_disc: u32, now: Instant) -> Self {
        let timers = Timers::new(
            profile.min_tx_interval * MS,
            profile.min_rx_interval * MS,
            profile.detect_multiplier,
            now,
        );
        let auth = AuthState::new(key, rand_u32(), now);
        let mut core = Core {
            profile,
            state: BfdState::Down,
            diag: BfdDiag::NoDiagnostic,
            local_disc,
            remote_disc: 0,
            remote_rx: 1,
            remote_cpi: false,
            remote_echo_rx: 0,
            echo_path: false,
            echo: None,
            timers,
            auth,
            auth_failures: 0,
        };
        if core.profile.shutdown {
            core.apply(Event::AdminDown);
        }
        core
    }

    pub fn status(&self) -> Status {
        let (tx_interval_us, detection_time_us) = if self.unaffiliated() {
            let iv = self.echo_interval_us();
            (
                iv,
                iv.saturating_mul(u32::from(self.profile.detect_multiplier)),
            )
        } else {
            (
                self.timers.tx_interval_us(self.state).unwrap_or(SLOW_US),
                self.timers
                    .detection_time_us()
                    .map_or(0, |us| u32::try_from(us).unwrap_or(u32::MAX)),
            )
        };
        Status {
            state: self.state,
            diag: self.diag,
            local_discriminator: self.local_disc,
            remote_discriminator: self.remote_disc,
            tx_interval_us,
            detection_time_us,
            control_plane_independent: LOCAL_CPI && self.remote_cpi,
            auth_method: self.auth.cfg().map(|a| a.method),
            auth_key_id: self.auth.cfg().map(|a| a.key_id),
            auth_failures: self.auth_failures,
            echo_active: self.echo.is_some(),
            echo_interval_us: if self.echo.is_some() {
                self.echo_interval_us()
            } else {
                0
            },
            echo_only: self.unaffiliated(),
            tx_pdu_bytes: self.profile.padded_pdu_size.map_or(0, u32::from),
            kind: BfdSessionKind::Classical,
        }
    }

    /// Whether Echo packets can be sent at all (single-hop with a usable
    /// interface); without it the session never starts Echo.
    pub fn set_echo_path(&mut self, available: bool) {
        self.echo_path = available;
    }

    /// Echo runs while the Control session is Up, the profile asks for it
    /// and the remote advertised a nonzero Required Min Echo RX (§6.4).
    fn echo_wanted(&self) -> bool {
        self.echo_path
            && !self.profile.shutdown
            && match self.profile.echo_mode {
                EchoMode::Affiliated => self.state == BfdState::Up && self.remote_echo_rx > 0,
                EchoMode::Unaffiliated => true,
                EchoMode::Disabled => false,
            }
    }

    /// RFC 9747: the session is its own looped Control packets.
    fn unaffiliated(&self) -> bool {
        self.profile.echo_mode == EchoMode::Unaffiliated
    }

    /// Whether silence counts: an unaffiliated session only watches once Up
    /// (before that it just retries at one packet a second).
    fn watching(&self) -> bool {
        !self.unaffiliated() || self.state == BfdState::Up
    }

    /// max(our echo interval, the remote's Required Min Echo RX), microseconds;
    /// RFC 9747 §3: at most one packet a second until Up.
    fn echo_interval_us(&self) -> u32 {
        if self.watching() {
            (self.profile.echo_interval * MS).max(self.remote_echo_rx)
        } else {
            SLOW_US
        }
    }

    /// What we advertise as Desired Min TX: §6.8.3 keeps Control at one
    /// packet a second or slower while Echo runs.
    fn effective_tx(&self) -> u32 {
        let tx = self.profile.min_tx_interval * MS;
        if self.echo.is_some() {
            tx.max(SLOW_US)
        } else {
            tx
        }
    }

    /// Starts or stops Echo to match `echo_wanted`, moving the Control
    /// interval through a Poll sequence. Whether that opened one.
    fn sync_echo(&mut self, now: Instant) -> bool {
        let want = self.echo_wanted();
        if want == self.echo.is_some() {
            return false;
        }
        let was_polling = self.timers.poll();
        self.echo = want.then_some(EchoRun {
            next_tx: now,
            last_ok: now,
            sent: 0,
            acked: 0,
        });
        if self.unaffiliated() {
            return false; // no Control session to Poll
        }
        self.timers
            .change(self.effective_tx(), self.profile.min_rx_interval * MS);
        !was_polling && self.timers.poll()
    }

    /// The sequence number and payload of an echo to send now, if one is due.
    pub fn echo_due(&mut self, now: Instant) -> Option<(u32, Vec<u8>)> {
        let iv = Duration::from_micros(u64::from(self.echo_interval_us()));
        let e = self.echo.as_mut()?;
        if now < e.next_tx {
            return None;
        }
        e.sent = e.sent.wrapping_add(1);
        e.next_tx = now + iv;
        let seq = e.sent;
        let payload = if self.unaffiliated() {
            self.packet(false).encode().to_vec()
        } else {
            crate::echo::payload(self.local_disc, seq).to_vec()
        };
        Some((seq, payload))
    }

    /// Something came back: a not-yet-seen echo sequence we sent, or (RFC
    /// 9747) our own Control packet, whose state drives the §6.2 machine as
    /// if the peer had sent it.
    pub fn on_echo(&mut self, now: Instant, looped: Looped) {
        let Some(e) = self.echo.as_mut() else { return };
        match looped {
            Looped::Seq(seq) if seq > e.acked && seq <= e.sent => {
                e.acked = seq;
                e.last_ok = now;
            }
            Looped::Control(s) if self.profile.echo_mode == EchoMode::Unaffiliated => {
                e.last_ok = now;
                self.remote_disc = self.local_disc;
                if self.apply(Event::RxState(s)) && self.state == BfdState::Up {
                    // The 1 s pace of the climb ends; the provisioned one starts.
                    let iv = Duration::from_micros(u64::from(self.echo_interval_us()));
                    if let Some(e) = self.echo.as_mut() {
                        e.next_tx = now + iv;
                    }
                }
            }
            _ => {}
        }
    }

    fn echo_deadline(&self) -> Option<Instant> {
        let e = self.echo.as_ref()?;
        let detect = Duration::from_micros(
            u64::from(self.echo_interval_us()) * u64::from(self.profile.detect_multiplier),
        );
        Some(if self.watching() {
            e.next_tx.min(e.last_ok + detect)
        } else {
            e.next_tx
        })
    }

    fn echo_expired(&self, now: Instant) -> bool {
        self.echo.as_ref().is_some_and(|e| {
            self.watching()
                && now.saturating_duration_since(e.last_ok)
                    >= Duration::from_micros(
                        u64::from(self.echo_interval_us())
                            * u64::from(self.profile.detect_multiplier),
                    )
        })
    }

    fn detection_time(&self) -> Option<Duration> {
        self.timers.detection_time_us().map(Duration::from_micros)
    }

    /// RFC 5880 §6.7.2 for a decoded packet; call before `on_packet`. An
    /// `Err` packet must be dropped: it neither refreshes the detection timer
    /// nor moves the state.
    pub fn authenticate(&mut self, now: Instant, p: &Packet) -> Result<(), AuthError> {
        let r = if self.unkeyed() {
            Err(AuthError::NoKey)
        } else {
            self.auth
                .check(now, p.detect_mult, p.auth.as_ref(), self.detection_time())
        };
        if r.is_err() {
            self.auth_failures += 1;
        }
        r
    }

    /// The profile asks for authentication but its admin key could not be
    /// resolved (#510): fail closed, neither accept nor send anything.
    pub fn unkeyed(&self) -> bool {
        self.profile.auth.is_some() && self.auth.cfg().is_none()
    }

    /// The wire bytes of an outgoing packet, signed when auth is configured.
    pub fn sign(&mut self, now: Instant, p: &Packet) -> Vec<u8> {
        let d = self.detection_time();
        self.auth.sign(now, &p.encode(), d)
    }

    /// `sign`, then RFC 9764 §3: zero padding after the packet (and its auth
    /// section, which covers only the `length` bytes) up to `padded-pdu-size`.
    pub fn wire(&mut self, now: Instant, p: &Packet) -> Vec<u8> {
        let mut b = self.sign(now, p);
        if let Some(n) = self.profile.padded_pdu_size {
            b.resize(b.len().max(usize::from(n)), 0);
        }
        b
    }

    /// Applies one FSM event; whether the state changed.
    fn apply(&mut self, ev: Event) -> bool {
        let (next, diag) = fsm::step(self.state, ev);
        if let Some(d) = diag {
            self.diag = d;
        }
        let changed = next != self.state;
        self.state = next;
        if changed && !self.unaffiliated() {
            self.timers.on_state(next);
        }
        // §6.8.4: the remote is forgotten when it stops talking.
        if changed && ev == Event::DetectTimeout {
            self.remote_disc = 0;
        }
        changed
    }

    // ponytail: RFC 9747 says SHOULD authenticate; unaffiliated Control packets
    // go out unsigned (`sign` is only called for the Control path). Add the auth
    // section to the Echo payload if an operator needs it.
    fn packet(&self, final_: bool) -> Packet {
        // RFC 9747 §3: populated, never used by anyone; 1 s each.
        let (desired_min_tx, required_min_rx) = if self.unaffiliated() {
            (SLOW_US, SLOW_US)
        } else {
            self.timers.advertised(self.state)
        };
        Packet {
            diag: self.diag.code(),
            state: self.state,
            // P and F are never both set (§6.5).
            poll: self.timers.poll() && !final_,
            final_,
            control_plane_independent: LOCAL_CPI,
            demand: false,
            detect_mult: self.profile.detect_multiplier,
            my_discriminator: self.local_disc,
            your_discriminator: self.remote_disc,
            desired_min_tx,
            required_min_rx,
            required_min_echo_rx: if self.profile.echo_mode == EchoMode::Affiliated
                && !self.profile.shutdown
            {
                self.profile.echo_interval * MS
            } else {
                0
            },
            auth: None,
        }
    }

    /// A packet from the remote. The returned packet goes out at once: the
    /// Final answering a Poll, or the first packet of a new state.
    pub fn on_packet(&mut self, now: Instant, p: &Packet, rand_pct: u32) -> Option<Packet> {
        // §6.8.6: AdminDown discards everything; a nonzero Your Discriminator
        // must be ours.
        if self.state == BfdState::AdminDown
            || self.unaffiliated()
            || (p.your_discriminator != 0 && p.your_discriminator != self.local_disc)
        {
            return None;
        }
        self.remote_disc = p.my_discriminator;
        self.remote_rx = p.required_min_rx;
        self.remote_cpi = p.control_plane_independent;
        self.remote_echo_rx = p.required_min_echo_rx;
        let out = self.timers.on_rx(
            now,
            Remote {
                desired_min_tx: p.desired_min_tx,
                required_min_rx: p.required_min_rx,
                detect_mult: p.detect_mult,
            },
            p.poll,
            p.final_,
        );
        let changed = self.apply(Event::RxState(p.state));
        if p.state == BfdState::AdminDown {
            // The peer retired this session (#659): its discriminator is
            // stale, and a peer that comes back (or an unsolicited one,
            // RFC 9468) is only heard with Your Discriminator 0.
            self.remote_disc = 0;
        }
        let polled = self.sync_echo(now);
        if out.reply_final || changed || polled {
            self.timers.schedule_tx(now, self.state, rand_pct);
            return Some(self.packet(out.reply_final));
        }
        None
    }

    /// The clock reached `deadline()`: detection expiry and periodic transmit.
    pub fn on_timer(&mut self, now: Instant, rand_pct: u32) -> Option<Packet> {
        if self.unaffiliated() {
            if self.echo_expired(now) && self.apply(Event::EchoTimeout) {
                self.remote_disc = 0;
                // Back to at most one packet a second until Up again.
                if let Some(e) = self.echo.as_mut() {
                    e.next_tx = now + Duration::from_micros(u64::from(SLOW_US));
                }
            }
            self.sync_echo(now);
            // No Control packets; keep the unused Control clock from spinning.
            if self.timers.tx_due(now) {
                self.timers.schedule_tx(now, self.state, rand_pct);
            }
            return None;
        }
        let mut due = false;
        if matches!(self.state, BfdState::Init | BfdState::Up) && self.timers.detect_expired(now) {
            due = self.apply(Event::DetectTimeout);
        }
        if self.echo_expired(now) {
            due |= self.apply(Event::EchoTimeout);
        }
        let polled = self.sync_echo(now);
        if due || polled || self.timers.tx_due(now) {
            self.timers.schedule_tx(now, self.state, rand_pct);
            if fsm::may_transmit(self.profile.passive, self.remote_disc, self.remote_rx) {
                return Some(self.packet(false));
            }
        }
        None
    }

    /// A re-`Register` with a new profile: intervals go through Poll/Final
    /// (§6.5, no flap), `shutdown` through `AdminDown`. A packet goes out at
    /// once when that opened a Poll sequence or moved the state.
    pub fn update_profile(
        &mut self,
        profile: BfdProfile,
        key: Option<AuthKey>,
        now: Instant,
        rand_pct: u32,
    ) -> Option<Packet> {
        let was_polling = self.timers.poll();
        let was_down = profile.shutdown != self.profile.shutdown;
        self.timers.set_detect_mult(profile.detect_multiplier);
        let hold = self.detection_time().unwrap_or(Duration::from_secs(3));
        self.auth.set(key, now, hold);
        let shutdown = profile.shutdown;
        self.profile = profile;
        let moved = was_down
            && self.apply(if shutdown {
                Event::AdminDown
            } else {
                Event::AdminUp
            });
        self.sync_echo(now);
        self.timers
            .change(self.effective_tx(), self.profile.min_rx_interval * MS);
        if moved || (!was_polling && self.timers.poll()) {
            self.timers.schedule_tx(now, self.state, rand_pct);
            return Some(self.packet(false));
        }
        None
    }

    /// When `on_timer` next has work.
    pub fn deadline(&self) -> Instant {
        if self.unaffiliated() {
            return self.echo_deadline().unwrap_or(self.timers.next_tx());
        }
        let tx = self.timers.next_tx();
        let tx = match self.timers.detect_deadline() {
            Some(d) if matches!(self.state, BfdState::Init | BfdState::Up) => tx.min(d),
            _ => tx,
        };
        self.echo_deadline().map_or(tx, |e| tx.min(e))
    }
}

/// Cheap jitter source for §6.8.7 and the discriminator start: a fresh
/// `RandomState` is seeded from the OS per instance.
pub fn rand_u32() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    // ponytail: SipHash of nothing, not a CSPRNG; it seeds discriminators and
    // the auth XmitAuthSeq start, neither of which is a secret (the key is).
    // Swap for `getrandom` if they must be unguessable.
    #[allow(clippy::cast_possible_truncation, reason = "low half is enough")]
    let v = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish() as u32;
    v
}

/// Minimum gap between two `bfd auth failed` warnings of one session.
const AUTH_WARN_EVERY: Duration = Duration::from_secs(10);

pub(crate) fn jitter_pct() -> u32 {
    75 + rand_u32() % 26
}

fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// The session task. Ends when the manager drops its senders (or aborts it).
pub async fn run(
    key: SessionKey,
    mut core: Core,
    tx: Arc<dyn Tx>,
    mut echo: Option<EchoPath>,
    mut pkts: mpsc::Receiver<Packet>,
    mut cmds: mpsc::Receiver<Cmd>,
    status: watch::Sender<Status>,
) {
    core.set_echo_path(echo.is_some());
    let mut last = core.status();
    let mut last_warn: Option<Instant> = None;
    let mut too_big = false;
    loop {
        let deadline = tokio::time::Instant::from_std(core.deadline());
        let out = tokio::select! {
            p = pkts.recv() => match p {
                Some(p) => match core.authenticate(now(), &p) {
                    Ok(()) => core.on_packet(now(), &p, jitter_pct()),
                    Err(e) => {
                        // Rate-limited: a wrong key is a packet every interval.
                        if last_warn.is_none_or(|t| now() - t >= AUTH_WARN_EVERY) {
                            last_warn = Some(now());
                            warn!(peer = %key.peer, table = %key.table, reason = %e, "bfd auth failed");
                        }
                        None
                    }
                },
                None => break,
            },
            c = cmds.recv() => match c {
                Some((c, key)) => core.update_profile(c, key, now(), jitter_pct()),
                None => break,
            },
            () = tokio::time::sleep_until(deadline) => core.on_timer(now(), jitter_pct()),
            looped = async {
                match echo.as_mut() {
                    Some(e) => match e.rx.recv().await {
                        Some(l) => l,
                        None => std::future::pending().await,
                    },
                    None => std::future::pending().await,
                }
            } => {
                core.on_echo(now(), looped);
                None
            }
        };
        if let Some(p) = out.filter(|_| !core.unkeyed()) {
            if let Err(e) = tx.send(&core.wire(now(), &p)) {
                if e.raw_os_error() == Some(libc::EMSGSIZE) {
                    // RFC 9764: the padded packet does not fit the path; the
                    // session goes down by detection time. Once per session.
                    if !too_big {
                        too_big = true;
                        warn!(peer = %key.peer, size = core.status().tx_pdu_bytes, "bfd padded packet exceeds the path mtu");
                    }
                } else {
                    debug!(peer = %key.peer, error = %e, "bfd send failed");
                }
            } else {
                too_big = false;
            }
        }
        if let (Some((_, payload)), Some(e)) = (core.echo_due(now()), echo.as_ref())
            && let Err(err) = e.tx.send(&payload)
        {
            debug!(peer = %key.peer, error = %err, "bfd echo send failed");
        }
        let s = core.status();
        if s != last {
            if s.state != last.state {
                log_transition(&key, &s);
            }
            if s.echo_active != last.echo_active {
                if s.echo_active {
                    info!(peer = %key.peer, table = %key.table, interval_us = s.echo_interval_us, "bfd echo active");
                } else {
                    info!(peer = %key.peer, table = %key.table, "bfd echo inactive");
                }
            }
            last = s;
            status.send_replace(s);
        }
    }
}

pub(crate) fn log_transition(key: &SessionKey, s: &Status) {
    // RFC 7130 micro-BFD: the anchors the `micro-bfd` e2e phase waits for.
    if let (Some(aggregate), Some(member)) = (&key.aggregate, &key.interface) {
        match s.state {
            BfdState::Up => {
                info!(aggregate = %aggregate, member = %member, peer = %key.peer, "bfd session up");
            }
            BfdState::Down | BfdState::AdminDown => {
                info!(aggregate = %aggregate, member = %member, peer = %key.peer, diag = %s.diag, "bfd session down");
            }
            BfdState::Init => debug!(member = %member, peer = %key.peer, "bfd session init"),
        }
        return;
    }
    match s.state {
        BfdState::Up => info!(peer = %key.peer, table = %key.table, "bfd session up"),
        BfdState::Down | BfdState::AdminDown => {
            info!(peer = %key.peer, diag = %s.diag, table = %key.table, "bfd session down");
        }
        BfdState::Init => debug!(peer = %key.peer, "bfd session init"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test keystore: the secret of a label is the label text itself.
    fn rk(p: &BfdProfile) -> Option<AuthKey> {
        p.auth.as_ref().map(|a| AuthKey::new(a, &a.key))
    }

    fn core(p: BfdProfile, disc: u32, now: Instant) -> Core {
        let k = rk(&p);
        Core::new(p, k, disc, now)
    }
    use std::time::Duration;

    fn profile(tx: u32, rx: u32) -> BfdProfile {
        BfdProfile {
            name: "p".into(),
            min_tx_interval: tx,
            min_rx_interval: rx,
            ..BfdProfile::default()
        }
    }

    /// Two cores wired back to back; time only moves in `step`.
    struct Pair {
        a: Core,
        b: Core,
        now: Instant,
        /// Whether echo packets come back.
        echo_ok: bool,
    }

    impl Pair {
        fn new(pa: BfdProfile, pb: BfdProfile) -> Self {
            let now = Instant::now();
            Pair {
                a: core(pa, 1, now),
                b: core(pb, 2, now),
                now,
                echo_ok: true,
            }
        }

        /// Delivers `p` to `to` and everything the replies trigger.
        fn deliver(now: Instant, from_a: bool, a: &mut Core, b: &mut Core, p: Packet) {
            let mut next = Some((from_a, p));
            while let Some((from_a, p)) = next.take() {
                let (tx, rx) = if from_a {
                    (&mut *a, &mut *b)
                } else {
                    (&mut *b, &mut *a)
                };
                // Over the wire, auth section included.
                let wire = tx.wire(now, &p);
                let p = crate::packet::decode(&wire).expect("our own packet decodes");
                if rx.authenticate(now, &p).is_err() {
                    continue;
                }
                if let Some(reply) = rx.on_packet(now, &p, 100) {
                    next = Some((!from_a, reply));
                }
            }
        }

        /// Advances to the earlier deadline and runs it.
        fn step(&mut self) {
            let a_first = self.a.deadline() <= self.b.deadline();
            self.now = self.a.deadline().min(self.b.deadline());
            let (core, from_a) = if a_first {
                (&mut self.a, true)
            } else {
                (&mut self.b, false)
            };
            let out = core.on_timer(self.now, 100);
            if let Some((seq, _)) = core.echo_due(self.now)
                && self.echo_ok
            {
                core.on_echo(self.now, Looped::Seq(seq));
            }
            if let Some(p) = out {
                Self::deliver(self.now, from_a, &mut self.a, &mut self.b, p);
            }
        }

        fn run_until(&mut self, mut done: impl FnMut(&Pair) -> bool) {
            for _ in 0..200 {
                if done(self) {
                    return;
                }
                self.step();
            }
            panic!("not reached: a {:?} b {:?}", self.a.state, self.b.state);
        }
    }

    #[test]
    fn handshake_reaches_up_and_negotiates() {
        let mut p = Pair::new(profile(100, 100), profile(200, 150));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        let s = p.a.status();
        assert_eq!(s.local_discriminator, 1);
        assert_eq!(s.remote_discriminator, 2);
        // max(our 100 ms, their required rx 150 ms)
        assert_eq!(s.tx_interval_us, 150_000);
        // 3 x max(our rx 100 ms, their tx 200 ms)
        assert_eq!(s.detection_time_us, 600_000);
    }

    #[test]
    fn c_bit_is_reported_only_when_both_ends_set_it() {
        let mut p = Pair::new(profile(100, 100), profile(100, 100));
        assert!(!p.a.status().control_plane_independent, "nothing received");
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        assert!(p.a.status().control_plane_independent);
        p.a.remote_cpi = false; // a peer whose BFD shares fate with its control plane
        assert!(!p.a.status().control_plane_independent);
    }

    #[test]
    fn silence_takes_the_session_down_with_the_diag() {
        let mut p = Pair::new(profile(100, 100), profile(100, 100));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        // The link drops everything: only `a` keeps running.
        let t0 = p.now;
        for _ in 0..50 {
            p.now = p.a.deadline();
            p.a.on_timer(p.now, 100);
            if p.a.state == BfdState::Down {
                break;
            }
        }
        assert_eq!(p.a.diag, BfdDiag::ControlDetectionTimeExpired);
        assert_eq!(p.a.remote_disc, 0);
        assert!(p.now - t0 <= Duration::from_millis(400), "{:?}", p.now - t0);
    }

    #[test]
    fn reaching_up_poll_sequence_completes_on_both_sides() {
        let mut p = Pair::new(profile(100, 100), profile(100, 100));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        p.run_until(|p| !p.a.timers.poll() && !p.b.timers.poll());
        assert_eq!(p.a.status().tx_interval_us, 100_000);
        assert_eq!(p.b.status().tx_interval_us, 100_000);
    }

    #[test]
    fn up_transition_packet_carries_poll() {
        let now = Instant::now();
        let mut c = core(profile(100, 100), 1, now);
        let remote = Packet {
            state: BfdState::Init,
            my_discriminator: 2,
            your_discriminator: 1,
            ..c.packet(false)
        };
        let pkt = c
            .on_packet(now, &remote, 100)
            .expect("state change answers");
        assert_eq!(c.state, BfdState::Up);
        assert!(pkt.poll);
        assert_eq!(pkt.desired_min_tx, 100_000);
    }

    #[test]
    fn unaffiliated_up_sets_no_poll() {
        let mut c = core(
            BfdProfile {
                echo_mode: EchoMode::Unaffiliated,
                ..profile(100, 100)
            },
            1,
            Instant::now(),
        );
        c.apply(Event::RxState(BfdState::Init));
        assert_eq!(c.state, BfdState::Up);
        assert!(!c.timers.poll());
    }

    #[test]
    fn profile_edit_polls_without_flapping() {
        let mut p = Pair::new(profile(100, 100), profile(100, 100));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        let pkt =
            p.a.update_profile(profile(50, 50), rk(&profile(50, 50)), p.now, 100)
                .expect("poll starts at once");
        assert!(pkt.poll);
        assert_eq!(pkt.desired_min_tx, 50_000);
        // Still using the old interval until Final.
        assert_eq!(p.a.status().tx_interval_us, 100_000);
        Pair::deliver(p.now, true, &mut p.a, &mut p.b, pkt);
        assert!(!p.a.timers.poll(), "Final closed the sequence");
        assert_eq!(p.a.status().tx_interval_us, 100_000);
        assert_eq!(p.a.state, BfdState::Up);
        assert_eq!(p.b.state, BfdState::Up);
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn padding_is_zero_after_the_packet_and_ignored_by_the_peer() {
        let padded = |n, auth| BfdProfile {
            padded_pdu_size: Some(n),
            auth,
            ..profile(100, 100)
        };
        let now = Instant::now();
        let sha1 = Some(nos_proto::schema::BfdAuth {
            key_id: 1,
            method: BfdAuthMethod::KeyedSha1,
            key: "k".into(),
        });
        // Unauthenticated: 1500 bytes, the 24 real ones first.
        let mut c = core(padded(1500, None), 1, now);
        let p = c.on_timer(now, 100).expect("first packet");
        let w = c.wire(now, &p);
        assert_eq!(w.len(), 1500);
        assert!(w[24..].iter().all(|b| *b == 0));
        assert_eq!(crate::packet::decode(&w).unwrap().my_discriminator, 1);
        assert_eq!(c.status().tx_pdu_bytes, 1500);
        // Below the minimum (here 24 + the 28-byte SHA1 section): raised, not truncated.
        let mut c = core(padded(24, sha1.clone()), 1, now);
        let p = c.on_timer(now, 100).expect("first packet");
        assert_eq!(c.wire(now, &p).len(), 52);
        // Authenticated and padded: the digest covers `length` bytes only.
        let (mut a, mut b) = (
            core(padded(300, sha1.clone()), 1, now),
            core(padded(24, sha1), 2, now),
        );
        let p = a.on_timer(now, 100).expect("first packet");
        let w = a.wire(now, &p);
        assert_eq!(w.len(), 300);
        assert_eq!(w[3], 52, "length field excludes the padding");
        let d = crate::packet::decode(&w).unwrap();
        assert!(b.authenticate(now, &d).is_ok());
        // Nothing to pad by default.
        let mut c = core(profile(100, 100), 1, now);
        let p = c.on_timer(now, 100).expect("first packet");
        assert_eq!(c.wire(now, &p).len(), 24);
        assert_eq!(c.status().tx_pdu_bytes, 0);
    }

    fn echoing(tx: u32, rx: u32, echo_ms: u32) -> BfdProfile {
        BfdProfile {
            echo_mode: EchoMode::Affiliated,
            echo_interval: echo_ms,
            ..profile(tx, rx)
        }
    }

    fn echo_pair(pa: BfdProfile, pb: BfdProfile) -> Pair {
        let mut p = Pair::new(pa, pb);
        p.a.set_echo_path(true);
        p.b.set_echo_path(true);
        p
    }

    #[test]
    fn echo_starts_when_up_and_slows_control_to_one_second() {
        let mut p = echo_pair(echoing(100, 100, 50), echoing(100, 100, 80));
        p.run_until(|p| p.a.echo.is_some() && p.b.echo.is_some());
        p.run_until(|p| !p.a.timers.poll() && !p.b.timers.poll());
        let s = p.a.status();
        assert!(s.echo_active);
        // max(our 50 ms, their advertised 80 ms)
        assert_eq!(s.echo_interval_us, 80_000);
        assert_eq!(
            s.tx_interval_us, 1_000_000,
            "control >= 1 s while echo runs"
        );
        assert_eq!(p.a.state, BfdState::Up);
        // The packets advertise the same: Required Min Echo RX is ours.
        assert_eq!(p.a.packet(false).required_min_echo_rx, 50_000);
        // Echo keeps the session alive far past the control detection time.
        for _ in 0..100 {
            p.step();
        }
        assert_eq!((p.a.state, p.b.state), (BfdState::Up, BfdState::Up));
    }

    #[test]
    fn echo_needs_both_ends_and_the_path() {
        // The peer advertises 0: nothing to loop through it.
        let mut p = echo_pair(echoing(100, 100, 50), profile(100, 100));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        for _ in 0..20 {
            p.step();
        }
        assert!(p.a.echo.is_none());
        assert_eq!(p.b.packet(false).required_min_echo_rx, 0);
        // No transport: never starts, even with both asking.
        let mut p = Pair::new(echoing(100, 100, 50), echoing(100, 100, 50));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        for _ in 0..20 {
            p.step();
        }
        assert!(p.a.echo.is_none() && p.b.echo.is_none());
    }

    #[test]
    fn lost_echoes_take_the_session_down_with_diag_2_and_control_returns() {
        let mut p = echo_pair(echoing(100, 100, 50), echoing(100, 100, 50));
        p.run_until(|p| p.a.echo.is_some() && p.b.echo.is_some());
        p.run_until(|p| !p.a.timers.poll() && !p.b.timers.poll());
        p.echo_ok = false;
        let t0 = p.now;
        // (The test wire has no latency, so the handshake may re-Up inside the step.)
        p.run_until(|p| p.a.diag == BfdDiag::EchoFunctionFailed);
        // 3 x 50 ms plus one step of slack.
        assert!(p.now - t0 <= Duration::from_millis(250), "{:?}", p.now - t0);
        // Echo works again: the session settles Up and echoes again.
        p.echo_ok = true;
        p.run_until(|p| p.a.state == BfdState::Up && p.a.echo.is_some() && p.b.echo.is_some());
        for _ in 0..50 {
            p.step();
        }
        assert_eq!((p.a.state, p.b.state), (BfdState::Up, BfdState::Up));
    }

    #[test]
    fn echo_is_stopped_by_disabling_it_in_the_profile() {
        let mut p = echo_pair(echoing(100, 100, 50), echoing(100, 100, 50));
        p.run_until(|p| p.a.echo.is_some() && p.b.echo.is_some());
        p.run_until(|p| !p.a.timers.poll() && !p.b.timers.poll());
        let pkt =
            p.a.update_profile(profile(100, 100), rk(&profile(100, 100)), p.now, 100);
        assert!(p.a.echo.is_none());
        let pkt = pkt.expect("a Poll restores the control rate");
        assert!(pkt.poll && pkt.required_min_echo_rx == 0);
        assert_eq!(pkt.desired_min_tx, 100_000);
    }

    fn unaffiliated(echo_ms: u32) -> BfdProfile {
        BfdProfile {
            echo_mode: EchoMode::Unaffiliated,
            echo_interval: echo_ms,
            detect_multiplier: 3,
            ..profile(100, 100)
        }
    }

    /// An unaffiliated core whose echoes come back while `loop_ok`; returns
    /// the sent payloads' decoded packets by time.
    fn run_unaffiliated(
        c: &mut Core,
        now: &mut Instant,
        steps: usize,
        loop_ok: bool,
    ) -> Vec<(Instant, Packet)> {
        let mut sent = Vec::new();
        for _ in 0..steps {
            *now = c.deadline();
            assert!(c.on_timer(*now, 100).is_none(), "no Control packets");
            if let Some((_, pl)) = c.echo_due(*now) {
                let p = crate::packet::decode(&pl).expect("a Control packet");
                if loop_ok {
                    c.on_echo(*now, Looped::Control(p.state));
                }
                sent.push((*now, p));
            }
        }
        sent
    }

    #[test]
    fn unaffiliated_goes_up_on_looped_packets_then_down_with_diag_2() {
        let t0 = Instant::now();
        let mut now = t0;
        let mut c = core(unaffiliated(50), 7, t0);
        c.set_echo_path(true);
        let sent = run_unaffiliated(&mut c, &mut now, 8, true);
        assert_eq!(c.state, BfdState::Up, "Down -> Init -> Up on its own state");
        assert_eq!(c.remote_disc, 7, "Your Discriminator is the looped value");
        // The first packets: Down with Your Discriminator 0, then 1 s apart.
        let first = &sent[0].1;
        assert_eq!((first.state, first.your_discriminator), (BfdState::Down, 0));
        assert_eq!(sent[1].0 - sent[0].0, Duration::from_secs(1));
        assert_eq!(sent[2].0 - sent[1].0, Duration::from_millis(50), "Up now");
        // Mandatory fields are populated (RFC 9747 §3), echo RX is zero.
        let p = &sent[2].1;
        assert_eq!(p.my_discriminator, 7);
        assert_eq!(
            (p.desired_min_tx, p.required_min_rx),
            (1_000_000, 1_000_000)
        );
        assert_eq!(p.required_min_echo_rx, 0);
        assert_eq!(p.detect_mult, 3);
        // Once Up the provisioned interval applies.
        let up = sent
            .iter()
            .position(|(_, p)| p.state == BfdState::Up)
            .unwrap();
        assert_eq!(sent[up + 1].0 - sent[up].0, Duration::from_millis(50));
        let s = c.status();
        assert!(s.echo_only && s.echo_active);
        assert_eq!((s.tx_interval_us, s.detection_time_us), (50_000, 150_000));

        // Loop broken: Down after 3 x 50 ms, diag Echo Function Failed.
        run_unaffiliated(&mut c, &mut now, 20, false);
        assert_eq!(c.state, BfdState::Down);
        assert_eq!(c.diag, BfdDiag::EchoFunctionFailed);
        assert_eq!(c.remote_disc, 0);
        assert_eq!(c.status().tx_interval_us, 1_000_000, "back to 1 s");
        // And it recovers when packets return.
        run_unaffiliated(&mut c, &mut now, 8, true);
        assert_eq!(c.state, BfdState::Up);
    }

    #[test]
    fn unaffiliated_detects_within_interval_times_multiplier() {
        let mut now = Instant::now();
        let mut c = core(unaffiliated(50), 7, now);
        c.set_echo_path(true);
        run_unaffiliated(&mut c, &mut now, 8, true);
        assert_eq!(c.state, BfdState::Up);
        let t = now;
        while c.state == BfdState::Up {
            run_unaffiliated(&mut c, &mut now, 1, false);
        }
        assert!(now - t <= Duration::from_millis(200), "{:?}", now - t);
        assert!(now - t >= Duration::from_millis(100), "{:?}", now - t);
    }

    #[test]
    fn unaffiliated_ignores_control_and_needs_a_path() {
        let now = Instant::now();
        let mut c = core(unaffiliated(50), 7, now);
        let theirs = core(profile(100, 100), 9, now).packet(false);
        assert!(c.on_packet(now, &theirs, 100).is_none());
        assert_eq!(c.remote_disc, 0, "a peer's Control packet teaches nothing");
        // No transport: nothing is sent, nothing spins.
        c.on_timer(now, 100);
        assert!(c.echo.is_none() && c.echo_due(now).is_none());
        assert!(c.deadline() > now);
        // A looped state from nowhere moves nothing without Echo running.
        c.on_echo(now, Looped::Control(BfdState::Init));
        assert_eq!(c.state, BfdState::Down);
    }

    fn authed(key: &str, id: u8) -> BfdProfile {
        use nos_proto::schema::BfdAuth;
        BfdProfile {
            auth: Some(BfdAuth {
                key_id: id,
                method: BfdAuthMethod::MeticulousSha1,
                key: key.into(),
            }),
            ..profile(100, 100)
        }
    }

    #[test]
    fn a_profile_whose_key_is_missing_is_unkeyed_and_rejects_everything() {
        let now = Instant::now();
        let prof = authed("gone", 1);
        let mut c = Core::new(prof.clone(), None, 1, now);
        assert!(c.unkeyed());
        let pkt = core(profile(100, 100), 2, now).packet(false);
        assert_eq!(c.authenticate(now, &pkt), Err(AuthError::NoKey));
        assert_eq!(c.status().auth_failures, 1);
        // The key shows up with an edit: keyed again.
        c.update_profile(prof.clone(), rk(&prof), now, 100);
        assert!(!c.unkeyed());
    }

    #[test]
    fn matching_keys_reach_up_and_a_key_change_does_not_flap() {
        let mut p = Pair::new(authed("a", 1), authed("a", 1));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        assert_eq!(p.a.status().auth_failures, 0);
        assert_eq!(p.a.status().auth_key_id, Some(1));
        // Both ends switch at once (new id and secret); the old key covers
        // whatever crosses on the wire meanwhile.
        let pa =
            p.a.update_profile(authed("b", 2), rk(&authed("b", 2)), p.now, 100);
        let pb =
            p.b.update_profile(authed("b", 2), rk(&authed("b", 2)), p.now, 100);
        for (from_a, pkt) in [(true, pa), (false, pb)] {
            if let Some(pkt) = pkt {
                Pair::deliver(p.now, from_a, &mut p.a, &mut p.b, pkt);
            }
        }
        for _ in 0..30 {
            p.step();
            assert_eq!((p.a.state, p.b.state), (BfdState::Up, BfdState::Up));
        }
        assert_eq!(p.a.status().auth_key_id, Some(2));
    }

    #[test]
    fn mismatched_keys_never_come_up_and_are_counted() {
        let mut p = Pair::new(authed("a", 1), authed("b", 1));
        for _ in 0..50 {
            p.step();
        }
        assert_eq!((p.a.state, p.b.state), (BfdState::Down, BfdState::Down));
        assert!(p.a.status().auth_failures > 0);
        assert_eq!(p.a.remote_disc, 0, "a dropped packet teaches nothing");
    }

    #[test]
    fn auth_on_one_side_only_stays_down() {
        let mut p = Pair::new(authed("a", 1), profile(100, 100));
        for _ in 0..50 {
            p.step();
        }
        assert_eq!((p.a.state, p.b.state), (BfdState::Down, BfdState::Down));
        assert!(p.a.status().auth_failures > 0 && p.b.status().auth_failures > 0);
    }

    #[test]
    fn shutdown_goes_admin_down_and_back() {
        let mut p = Pair::new(profile(100, 100), profile(100, 100));
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
        let mut down = profile(100, 100);
        down.shutdown = true;
        let pkt =
            p.a.update_profile(down.clone(), rk(&down), p.now, 100)
                .unwrap();
        assert_eq!(pkt.state, BfdState::AdminDown);
        assert_eq!(p.a.diag, BfdDiag::AdministrativelyDown);
        Pair::deliver(p.now, true, &mut p.a, &mut p.b, pkt);
        assert_eq!(p.b.state, BfdState::Down);
        assert_eq!(p.b.diag, BfdDiag::NeighborSignaledSessionDown);
        assert_eq!(
            p.b.packet(false).your_discriminator,
            0,
            "stale remote forgotten"
        );
        // AdminDown ignores the peer; removal brings it back to Down.
        assert!(p.a.on_packet(p.now, &p.b.packet(false), 100).is_none());
        p.a.update_profile(profile(100, 100), rk(&profile(100, 100)), p.now, 100);
        assert_eq!(p.a.state, BfdState::Down);
        p.run_until(|p| p.a.state == BfdState::Up && p.b.state == BfdState::Up);
    }

    #[test]
    fn started_in_shutdown_and_passive() {
        let mut sd = profile(100, 100);
        sd.shutdown = true;
        let c = core(sd, 7, Instant::now());
        assert_eq!(c.state, BfdState::AdminDown);

        let mut passive = profile(100, 100);
        passive.passive = true;
        let now = Instant::now();
        let mut c = core(passive, 7, now);
        assert!(c.on_timer(now, 100).is_none(), "passive stays silent");
        // Learning the remote discriminator ends the silence.
        let first = core(profile(100, 100), 9, now).packet(false);
        let reply = c.on_packet(now, &first, 100).expect("state moved");
        assert_eq!(reply.your_discriminator, 9);
    }

    #[test]
    fn foreign_discriminator_is_dropped() {
        let now = Instant::now();
        let mut c = core(profile(100, 100), 7, now);
        let mut p = core(profile(100, 100), 9, now).packet(false);
        p.your_discriminator = 8;
        assert!(c.on_packet(now, &p, 100).is_none());
        assert_eq!(c.remote_disc, 0);
    }

    #[test]
    fn remote_min_rx_zero_silences_us() {
        let now = Instant::now();
        let mut c = core(profile(100, 100), 7, now);
        let mut p = core(profile(100, 100), 9, now).packet(false);
        p.required_min_rx = 0;
        c.on_packet(now, &p, 100);
        assert!(c.on_timer(now + Duration::from_secs(5), 100).is_none());
    }
}
