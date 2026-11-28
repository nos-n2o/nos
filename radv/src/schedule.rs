//! RA timing (RFC 4861 s6.2.4, s6.2.6, constants s10). Pure: `now` is passed
//! in and randomness is a tiny xorshift the caller seeds.

use std::time::{Duration, Instant};

/// `MAX_INITIAL_RTR_ADVERT_INTERVAL`.
pub const MAX_INITIAL_INTERVAL: Duration = Duration::from_secs(16);
/// `MAX_INITIAL_RTR_ADVERTISEMENTS`.
pub const MAX_INITIAL_ADVERTISEMENTS: u8 = 3;
/// `MIN_DELAY_BETWEEN_RAS`.
pub const MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(3);
/// `MAX_RA_DELAY_TIME`.
pub const MAX_RA_DELAY: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
pub struct Schedule {
    min: Duration,
    max: Duration,
    sent_initial: u8,
    next: Instant,
    reply_at: Option<Instant>,
    last_sent: Option<Instant>,
    rng: u64,
}

impl Schedule {
    /// First RA is due at `now`.
    pub fn new(min: Duration, max: Duration, now: Instant, seed: u64) -> Self {
        Self {
            min,
            max,
            sent_initial: 0,
            next: now,
            reply_at: None,
            last_sent: None,
            rng: seed | 1,
        }
    }

    fn rand_between(&mut self, lo: Duration, hi: Duration) -> Duration {
        // xorshift64
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        if hi <= lo {
            return lo;
        }
        let span = u64::try_from(hi.saturating_sub(lo).as_millis())
            .unwrap_or(u64::MAX - 1)
            .max(1);
        lo + Duration::from_millis(self.rng % (span + 1))
    }

    /// Restarts the initial burst (a reopened socket) with the first RA due now.
    pub fn restart(&mut self, now: Instant) {
        self.sent_initial = 0;
        self.next = now;
        self.reply_at = None;
    }

    /// New interval bounds (profile change); the next RA is due now.
    pub fn reconfigure(&mut self, min: Duration, max: Duration, now: Instant) {
        self.min = min;
        self.max = max;
        self.next = now;
    }

    /// A valid RS arrived: answer after a random 0..=0.5 s; a pending reply
    /// absorbs further solicitations.
    pub fn on_rs(&mut self, now: Instant) {
        if self.reply_at.is_none() {
            let d = self.rand_between(Duration::ZERO, MAX_RA_DELAY);
            self.reply_at = Some(now + d);
        }
    }

    /// An RA left: schedules the next unsolicited one.
    pub fn on_sent(&mut self, now: Instant) {
        self.last_sent = Some(now);
        self.reply_at = None;
        self.sent_initial = self.sent_initial.saturating_add(1);
        let max = if self.sent_initial <= MAX_INITIAL_ADVERTISEMENTS {
            self.max.min(MAX_INITIAL_INTERVAL)
        } else {
            self.max
        };
        let lo = self.min.min(max);
        self.next = now + self.rand_between(lo, max);
    }

    /// A send failed (link down): try again after `delay`.
    pub fn retry(&mut self, now: Instant, delay: Duration) {
        self.reply_at = None;
        self.next = now + delay;
    }

    /// When the next RA may leave: the earlier of the unsolicited timer and a
    /// pending reply, but never within `MIN_DELAY_BETWEEN_RAS` of the last.
    pub fn deadline(&self) -> Instant {
        let want = self.reply_at.map_or(self.next, |r| r.min(self.next));
        self.last_sent
            .map_or(want, |l| want.max(l + MIN_DELAY_BETWEEN_RAS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(now: Instant) -> Schedule {
        Schedule::new(Duration::from_secs(200), Duration::from_secs(600), now, 42)
    }

    #[test]
    fn first_is_immediate_then_three_within_16s() {
        let t0 = Instant::now();
        let mut s = s(t0);
        assert_eq!(s.deadline(), t0);
        let mut now = t0;
        for _ in 0..3 {
            s.on_sent(now);
            let d = s.deadline();
            assert!(d - now <= MAX_INITIAL_INTERVAL, "initial interval");
            assert!(d - now >= MIN_DELAY_BETWEEN_RAS);
            now = d;
        }
        s.on_sent(now);
        let d = s.deadline() - now;
        assert!(d >= Duration::from_secs(200) && d <= Duration::from_secs(600));
    }

    #[test]
    fn rs_reply_is_delayed_at_most_half_a_second_and_coalesced() {
        let t0 = Instant::now();
        let mut s = s(t0);
        s.on_sent(t0);
        let now = t0 + Duration::from_secs(10);
        s.on_rs(now);
        let first = s.deadline();
        assert!(first >= now && first - now <= MAX_RA_DELAY);
        s.on_rs(now + Duration::from_millis(100));
        assert_eq!(s.deadline(), first, "pending reply absorbs further RSs");
        s.on_sent(first);
        assert!(s.deadline() > first + Duration::from_secs(1));
    }

    #[test]
    fn rs_right_after_an_ra_waits_for_the_minimum_spacing() {
        let t0 = Instant::now();
        let mut s = s(t0);
        s.on_sent(t0);
        s.on_rs(t0 + Duration::from_millis(10));
        assert!(s.deadline() >= t0 + MIN_DELAY_BETWEEN_RAS);
    }

    #[test]
    fn retry_and_reconfigure_move_the_deadline() {
        let t0 = Instant::now();
        let mut s = s(t0);
        s.retry(t0, Duration::from_secs(1));
        assert_eq!(s.deadline(), t0 + Duration::from_secs(1));
        s.reconfigure(Duration::from_secs(3), Duration::from_secs(4), t0);
        assert_eq!(s.deadline(), t0);
        s.on_sent(t0);
        s.restart(t0 + Duration::from_secs(5));
        assert_eq!(s.deadline(), t0 + Duration::from_secs(5));
    }
}
