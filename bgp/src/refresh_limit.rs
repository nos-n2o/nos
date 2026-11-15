//! Per-session limiter for peer-driven ROUTE-REFRESH requests (#396): each
//! one resends the whole Loc-RIB, so an unthrottled peer is a CPU/bandwidth
//! amplifier. Hard-coded (no knob): per address family, burst 2, one token back per 10 s.

use std::time::Duration;

use tokio::time::Instant;

const BURST: u32 = 2;
const REFILL: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct RefreshLimiter {
    tokens: u32,
    /// Start of the refill period in progress (meaningful below `BURST`).
    since: Option<Instant>,
}

impl Default for RefreshLimiter {
    fn default() -> Self {
        Self {
            tokens: BURST,
            since: None,
        }
    }
}

impl RefreshLimiter {
    /// Takes a token if one is available at `now`.
    pub fn allow(&mut self, now: Instant) -> bool {
        if let Some(since) = self.since {
            let periods = now.saturating_duration_since(since).as_secs() / REFILL.as_secs();
            let earned = u32::try_from(periods).unwrap_or(u32::MAX);
            if earned > 0 {
                self.tokens = self.tokens.saturating_add(earned).min(BURST);
                self.since = (self.tokens < BURST).then(|| since + REFILL * earned);
            }
        }
        if self.tokens == 0 {
            return false;
        }
        if self.tokens == BURST {
            self.since = Some(now);
        }
        self.tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_deny_then_refill() {
        let t0 = Instant::now();
        let mut l = RefreshLimiter::default();
        assert!(l.allow(t0));
        assert!(l.allow(t0));
        assert!(!l.allow(t0), "third in a burst is denied");
        assert!(!l.allow(t0 + Duration::from_secs(9)));
        assert!(l.allow(t0 + Duration::from_secs(10)));
        assert!(!l.allow(t0 + Duration::from_secs(11)));
        assert!(l.allow(t0 + Duration::from_secs(20)));
        // Long idle refills only up to the burst.
        let later = t0 + Duration::from_secs(1000);
        assert!(l.allow(later) && l.allow(later) && !l.allow(later));
    }
}
