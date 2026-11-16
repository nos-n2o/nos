//! Daemon liveness (#1150): the broker records each `Heartbeat`, the supervisor
//! kills a child whose beats stop.
//!
//! ponytail: a process-global map keyed by the certificate identity (role,
//! name), which the broker peer and the `ProcessSpec` already share; one
//! watchdog per process, so no plumbing through `Ctx`/`instances`. Upgrade to
//! an injected registry if a test ever needs two watchdogs in one process.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

fn beats() -> &'static Mutex<HashMap<(String, String), Instant>> {
    static BEATS: OnceLock<Mutex<HashMap<(String, String), Instant>>> = OnceLock::new();
    BEATS.get_or_init(Mutex::default)
}

/// Notes a beat from `role`/`name`.
pub fn record(role: &str, name: &str) {
    beats()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert((role.into(), name.into()), Instant::now());
}

/// Forgets `role`/`name`: a new spawn is exempt until it beats for the first time.
pub fn forget(role: &str, name: &str) {
    beats()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&(role.into(), name.into()));
}

/// The last beat of `role`/`name` since its spawn, if any.
pub fn last(role: &str, name: &str) -> Option<Instant> {
    beats()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&(role.into(), name.into()))
        .copied()
}

/// Missed: it has beaten at least once and not for longer than `timeout`.
#[must_use]
pub fn missed(last: Option<Instant>, now: Instant, timeout: Duration) -> bool {
    last.is_some_and(|t| now.duration_since(t) > timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn only_a_started_then_silent_child_is_missed() {
        let t = Duration::from_secs(20);
        assert!(!missed(None, Instant::now(), t), "never beat: exempt");
        record("hbtest", "a");
        tokio::time::advance(Duration::from_secs(19)).await;
        assert!(!missed(last("hbtest", "a"), Instant::now(), t));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(missed(last("hbtest", "a"), Instant::now(), t));
        record("hbtest", "a");
        assert!(
            !missed(last("hbtest", "a"), Instant::now(), t),
            "beat again"
        );
        forget("hbtest", "a");
        assert_eq!(last("hbtest", "a"), None);
    }
}
