//! SPF throttling with exponential back-off, RFC 8405 section 4: the
//! `QUIET` / `SHORT_WAIT` / `LONG_WAIT` machine. Pure, driven by an injected
//! `Instant`; `nos-ospf`'s route-push client asks it how long to wait after
//! each LSDB change before running SPF (#1138).

use std::time::{Duration, Instant};

/// The RFC 8405 timers. `Default` is the RFC's recommended set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timers {
    /// Delay of the first change after a quiet period.
    pub initial: Duration,
    /// Delay while changes keep arriving, until `time_to_learn` passes.
    pub short: Duration,
    /// Delay once the churn outlasts `time_to_learn`.
    pub long: Duration,
    /// Time with no change that returns the machine to `Quiet`.
    pub holddown: Duration,
    /// How long `ShortWait` lasts before escalating to `LongWait`.
    pub time_to_learn: Duration,
}

impl Default for Timers {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(50),
            short: Duration::from_millis(200),
            long: Duration::from_millis(5000),
            holddown: Duration::from_millis(10_000),
            time_to_learn: Duration::from_millis(3000),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Quiet,
    ShortWait,
    LongWait,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Quiet => "quiet",
            State::ShortWait => "short_wait",
            State::LongWait => "long_wait",
        }
    }
}

#[derive(Debug)]
pub struct SpfThrottle {
    timers: Timers,
    state: State,
    last_change: Option<Instant>,
    learn_start: Option<Instant>,
}

impl SpfThrottle {
    pub fn new(timers: Timers) -> Self {
        Self {
            timers,
            state: State::Quiet,
            last_change: None,
            learn_start: None,
        }
    }

    /// Registers a change at `now` and returns how long to wait before
    /// running SPF, plus the state that delay was chosen in.
    pub fn on_change(&mut self, now: Instant) -> (Duration, State) {
        if self
            .last_change
            .is_some_and(|t| now.saturating_duration_since(t) >= self.timers.holddown)
        {
            self.state = State::Quiet;
        }
        let in_state = self.state;
        let delay = match self.state {
            State::Quiet => {
                self.state = State::ShortWait;
                self.learn_start = Some(now);
                self.timers.initial
            }
            State::ShortWait => {
                let learned = self
                    .learn_start
                    .is_some_and(|t| now.saturating_duration_since(t) >= self.timers.time_to_learn);
                if learned {
                    self.state = State::LongWait;
                    self.timers.long
                } else {
                    self.timers.short
                }
            }
            State::LongWait => self.timers.long,
        };
        self.last_change = Some(now);
        (delay, in_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn quiet_short_long_quiet() {
        let t0 = Instant::now();
        let mut t = SpfThrottle::new(Timers::default());
        assert_eq!(t.on_change(t0), (ms(50), State::Quiet));
        assert_eq!(t.on_change(t0 + ms(100)), (ms(200), State::ShortWait));
        // exactly time_to_learn after the first change escalates
        assert_eq!(t.on_change(t0 + ms(3000)), (ms(5000), State::ShortWait));
        assert_eq!(t.state, State::LongWait);
        assert_eq!(t.on_change(t0 + ms(4000)), (ms(5000), State::LongWait));
        // just under holddown since the last change: still long
        assert_eq!(t.on_change(t0 + ms(13_999)), (ms(5000), State::LongWait));
        // holddown (10 s) of silence: back to quiet
        assert_eq!(t.on_change(t0 + ms(23_999)), (ms(50), State::Quiet));
    }

    #[test]
    fn holddown_expiry_from_short_wait() {
        let t0 = Instant::now();
        let mut t = SpfThrottle::new(Timers::default());
        t.on_change(t0);
        assert_eq!(t.on_change(t0 + ms(9_999)), (ms(200), State::ShortWait));
        // 10 s after the previous change: quiet again
        assert_eq!(t.on_change(t0 + ms(19_999)), (ms(50), State::Quiet));
    }

    #[test]
    fn custom_timers_are_used() {
        let t0 = Instant::now();
        let mut t = SpfThrottle::new(Timers {
            initial: ms(1),
            ..Timers::default()
        });
        assert_eq!(t.on_change(t0).0, ms(1));
    }
}
