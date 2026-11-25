//! RFC 5880 §6.8.1-§6.8.4 interval negotiation, §6.8.7 jitter and §6.5
//! Poll/Final, pure: `now` and the random draw are arguments.

use std::time::{Duration, Instant};

use nos_proto::BfdState;

/// §6.8.3: while not Up, transmit no faster than once a second.
pub const SLOW_US: u32 = 1_000_000;

/// What the remote last told us, microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Remote {
    pub desired_min_tx: u32,
    pub required_min_rx: u32,
    pub detect_mult: u8,
}

/// Outcome of a received packet for the caller to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxOutcome {
    /// The packet had P set: answer at once with F set (§6.5).
    pub reply_final: bool,
}

#[derive(Debug, Clone)]
pub struct Timers {
    desired_min_tx: u32,
    required_min_rx: u32,
    detect_mult: u8,
    /// A changed (tx, rx) advertised with P=1 and not yet confirmed by F.
    pending: Option<(u32, u32)>,
    /// The 1 s not-Up floor was the Desired Min TX in force: set at creation
    /// and on leaving Up, cleared on reaching Up (which opens the Poll).
    floored: bool,
    remote: Option<Remote>,
    last_rx: Instant,
    next_tx: Instant,
}

impl Timers {
    /// `desired_min_tx`/`required_min_rx` in microseconds (`ms * 1000`; the
    /// profile's `INTERVAL_MAX_MS` keeps that inside `u32`).
    pub fn new(desired_min_tx: u32, required_min_rx: u32, detect_mult: u8, now: Instant) -> Self {
        Timers {
            desired_min_tx,
            required_min_rx,
            detect_mult,
            pending: None,
            floored: true,
            remote: None,
            last_rx: now,
            next_tx: now,
        }
    }

    /// What the remote last told us.
    pub fn remote(&self) -> Option<Remote> {
        self.remote
    }

    /// Starts a Poll sequence for new local intervals (§6.5, §6.8.3): they
    /// are advertised at once but only take effect locally on Final.
    pub fn change(&mut self, desired_min_tx: u32, required_min_rx: u32) {
        let new = (desired_min_tx, required_min_rx);
        let current = self
            .pending
            .unwrap_or((self.desired_min_tx, self.required_min_rx));
        if new != current {
            self.pending = Some(new);
        }
    }

    /// The session state changed. Reaching Up lifts the 1 s floor, which
    /// is a Desired Min TX change: open a Poll sequence for it (§6.8.3).
    /// Leaving Up restores the floor and drops the moot Up-time sequence.
    pub fn on_state(&mut self, state: BfdState) {
        if state == BfdState::Up {
            if self.floored && self.desired_min_tx < SLOW_US {
                self.pending
                    .get_or_insert((self.desired_min_tx, self.required_min_rx));
            }
            // We transmit at the configured rate at once (the remote's
            // detection time already follows the advertised value, so
            // holding 1 s until Final would flap it); Final only closes
            // the sequence.
            self.floored = false;
        } else {
            self.floored = true;
            if self.pending == Some((self.desired_min_tx, self.required_min_rx)) {
                self.pending = None;
            }
        }
    }

    /// A profile edit of the detect multiplier (advertised in every packet,
    /// no Poll sequence needed: it only scales the remote's detection time).
    pub fn set_detect_mult(&mut self, detect_mult: u8) {
        self.detect_mult = detect_mult;
    }

    /// P bit for the next packets: set while a sequence is open.
    pub fn poll(&self) -> bool {
        self.pending.is_some()
    }

    /// The (Desired Min TX, Required Min RX) to put in a packet. Desired Min
    /// TX is raised to 1 s while the session is not Up (§6.8.3).
    pub fn advertised(&self, state: BfdState) -> (u32, u32) {
        let (tx, rx) = self
            .pending
            .unwrap_or((self.desired_min_tx, self.required_min_rx));
        (floor(tx, state), rx)
    }

    /// Records a received packet; applies a pending change on Final.
    pub fn on_rx(&mut self, now: Instant, remote: Remote, poll: bool, final_: bool) -> RxOutcome {
        self.remote = Some(remote);
        self.last_rx = now;
        if final_ && let Some((tx, rx)) = self.pending.take() {
            self.desired_min_tx = tx;
            self.required_min_rx = rx;
        }
        RxOutcome { reply_final: poll }
    }

    /// §6.8.2: max(local desired min TX, remote required min RX), at least
    /// 1 s while not Up. `None` until a packet told us the remote's values.
    pub fn tx_interval_us(&self, state: BfdState) -> Option<u32> {
        let r = self.remote?;
        Some(floor(self.desired_min_tx.max(r.required_min_rx), state))
    }

    /// §6.8.4: remote detect mult x max(local required min RX, remote
    /// desired min TX), in microseconds. `None` until a packet arrived.
    pub fn detection_time_us(&self) -> Option<u64> {
        let r = self.remote?;
        Some(u64::from(r.detect_mult) * u64::from(self.required_min_rx.max(r.desired_min_tx)))
    }

    /// Whether the detection time has elapsed since the last packet.
    pub fn detect_expired(&self, now: Instant) -> bool {
        self.detection_time_us().is_some_and(|us| {
            now.saturating_duration_since(self.last_rx) >= Duration::from_micros(us)
        })
    }

    /// Schedules the next transmission (§6.8.7). Before any packet arrived
    /// the interval is the slow one. `rand_pct` is the caller's draw; it is
    /// clamped to 75..=100, or 75..=90 when our detect mult is 1.
    pub fn schedule_tx(&mut self, now: Instant, state: BfdState, rand_pct: u32) -> Instant {
        let base = self.tx_interval_us(state).unwrap_or(SLOW_US);
        let max_pct = if self.detect_mult == 1 { 90 } else { 100 };
        let pct = u64::from(rand_pct.clamp(75, max_pct));
        self.next_tx = now + Duration::from_micros(u64::from(base) * pct / 100);
        self.next_tx
    }

    /// When the detection time runs out, `None` until a packet arrived.
    pub fn detect_deadline(&self) -> Option<Instant> {
        Some(self.last_rx + Duration::from_micros(self.detection_time_us()?))
    }

    /// When the next transmission is due.
    pub fn next_tx(&self) -> Instant {
        self.next_tx
    }

    pub fn tx_due(&self, now: Instant) -> bool {
        now >= self.next_tx
    }
}

fn floor(tx: u32, state: BfdState) -> u32 {
    if state == BfdState::Up {
        tx
    } else {
        tx.max(SLOW_US)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: Remote = Remote {
        desired_min_tx: 200_000,
        required_min_rx: 500_000,
        detect_mult: 4,
    };

    fn t(now: Instant) -> Timers {
        Timers::new(300_000, 400_000, 3, now)
    }

    /// Up with the reaching-Up Poll sequence answered: no floor, no pending.
    fn settled(now: Instant, mult: u8) -> Timers {
        let mut x = Timers::new(300_000, 400_000, mult, now);
        x.on_state(BfdState::Up);
        x.on_rx(now, R, false, true);
        x
    }

    #[test]
    fn interval_negotiation() {
        let now = Instant::now();
        assert_eq!(t(now).tx_interval_us(BfdState::Up), None);
        let x = settled(now, 3);
        // max(local desired 300k, remote required 500k)
        assert_eq!(x.tx_interval_us(BfdState::Up), Some(500_000));
        // detect = 4 x max(local required 400k, remote desired 200k)
        assert_eq!(x.detection_time_us(), Some(1_600_000));
    }

    #[test]
    fn slow_while_not_up() {
        let now = Instant::now();
        let mut x = t(now);
        x.on_rx(now, R, false, false);
        for s in [BfdState::Down, BfdState::Init, BfdState::AdminDown] {
            assert_eq!(x.tx_interval_us(s), Some(SLOW_US));
            assert_eq!(x.advertised(s).0, SLOW_US);
        }
        assert_eq!(x.advertised(BfdState::Up), (300_000, 400_000));
    }

    #[test]
    fn jitter_bounds() {
        let now = Instant::now();
        let mut x = settled(now, 3);
        let at = |x: &mut Timers, p| x.schedule_tx(now, BfdState::Up, p) - now;
        assert_eq!(at(&mut x, 75), Duration::from_millis(375));
        assert_eq!(at(&mut x, 100), Duration::from_millis(500));
        assert_eq!(at(&mut x, 10), Duration::from_millis(375));
        assert_eq!(at(&mut x, 999), Duration::from_millis(500));
        let mut one = settled(now, 1);
        assert_eq!(at(&mut one, 100), Duration::from_millis(450));
        assert_eq!(at(&mut one, 75), Duration::from_millis(375));
    }

    #[test]
    fn unknown_remote_transmits_slowly() {
        let now = Instant::now();
        let mut x = t(now);
        assert_eq!(
            x.schedule_tx(now, BfdState::Down, 100) - now,
            Duration::from_secs(1)
        );
        assert!(!x.tx_due(now));
        assert!(x.tx_due(now + Duration::from_secs(1)));
    }

    #[test]
    fn detection_expiry() {
        let now = Instant::now();
        let mut x = t(now);
        assert!(!x.detect_expired(now + Duration::from_secs(60)));
        x.on_rx(now, R, false, false);
        assert!(!x.detect_expired(now + Duration::from_micros(1_599_999)));
        assert!(x.detect_expired(now + Duration::from_millis(1600)));
    }

    #[test]
    fn poll_final_cycle() {
        let now = Instant::now();
        let mut x = settled(now, 3);
        assert!(!x.poll());
        x.change(100_000, 150_000);
        assert!(x.poll());
        // Advertised at once (Up: no floor), but not in use yet.
        assert_eq!(x.advertised(BfdState::Up), (100_000, 150_000));
        assert_eq!(x.tx_interval_us(BfdState::Up), Some(500_000));
        assert_eq!(x.detection_time_us(), Some(1_600_000));
        // A packet without F does not end it.
        x.on_rx(now, R, false, false);
        assert!(x.poll());
        // Final applies it.
        x.on_rx(now, R, false, true);
        assert!(!x.poll());
        assert_eq!(x.advertised(BfdState::Up), (100_000, 150_000));
        assert_eq!(x.detection_time_us(), Some(4 * 200_000));
    }

    #[test]
    fn reaching_up_polls_to_lift_the_floor() {
        let now = Instant::now();
        let mut x = t(now);
        x.on_rx(now, R, false, false);
        x.on_state(BfdState::Up);
        assert!(x.poll());
        // P=1 packets carry the configured value, used at once (the remote's
        // detection time follows it; 1 s until Final would flap it).
        assert_eq!(x.advertised(BfdState::Up), (300_000, 400_000));
        assert_eq!(x.tx_interval_us(BfdState::Up), Some(500_000));
        // A user change mid-sequence replaces the pending pair.
        x.change(200_000, 400_000);
        assert_eq!(x.advertised(BfdState::Up), (200_000, 400_000));
        x.on_rx(now, R, false, true);
        assert!(!x.poll());
        assert_eq!(x.tx_interval_us(BfdState::Up), Some(500_000));
        assert_eq!(x.advertised(BfdState::Up), (200_000, 400_000));
        // Up -> Down drops a still-open Up-time sequence; Up again reopens.
        x.on_state(BfdState::Down);
        assert_eq!(x.tx_interval_us(BfdState::Down), Some(SLOW_US));
        x.on_state(BfdState::Up);
        assert!(x.poll());
        x.on_state(BfdState::Down);
        assert!(!x.poll());
    }

    #[test]
    fn slow_configured_interval_opens_no_poll() {
        let now = Instant::now();
        let mut x = Timers::new(2_000_000, 400_000, 3, now);
        x.on_rx(now, R, false, false);
        x.on_state(BfdState::Up);
        assert!(!x.poll());
        assert_eq!(x.tx_interval_us(BfdState::Up), Some(2_000_000));
    }

    #[test]
    fn reverting_a_change_closes_nothing_new() {
        let now = Instant::now();
        let mut x = t(now);
        x.change(300_000, 400_000);
        assert!(!x.poll());
    }

    #[test]
    fn deadlines() {
        let now = Instant::now();
        let mut x = t(now);
        assert_eq!(x.detect_deadline(), None);
        x.on_rx(now, R, false, false);
        assert_eq!(x.detect_deadline(), Some(now + Duration::from_millis(1600)));
        // The multiplier we advertise scales the remote's timer, not ours.
        x.set_detect_mult(1);
        assert_eq!(x.detect_deadline(), Some(now + Duration::from_millis(1600)));
        assert_eq!(x.next_tx(), now);
    }

    #[test]
    fn incoming_poll_is_answered_with_final() {
        let now = Instant::now();
        let mut x = t(now);
        assert!(x.on_rx(now, R, true, false).reply_final);
        assert!(!x.on_rx(now, R, false, false).reply_final);
    }
}
