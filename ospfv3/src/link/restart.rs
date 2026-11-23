//! RFC 5187 restarting-router mode (#1163), the v3 twin of
//! `ospf::link::grace`'s: entered by a respawn that found a restart marker
//! (planned: written at SIGTERM; unplanned: the running marker a crash left),
//! it holds origination and the first route push until every pre-restart
//! `Full` neighbor is `Full` again (`nos_ospf_common::restart::exit_reason`).

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use nos_ospf_common::restart;
use tokio::time::Instant;
use tracing::info;

use super::{GraceCmd, LinkManager, NeighborState};

/// What restart mode waits for.
#[derive(Debug)]
pub(super) struct RestartState {
    expected: BTreeSet<Ipv4Addr>,
    deadline: Instant,
    /// RFC 5187 §2 restart reason for the Grace-LSA sent at startup.
    reason: u8,
}

impl LinkManager {
    /// Enters restart mode for at most `remaining`, until every `expected`
    /// neighbor (`Full` when the previous process stopped) is `Full` again.
    /// `unplanned`: the previous process crashed, so the Grace-LSA each link
    /// sends before its first Hello says "unknown" instead of "software
    /// restart". No neighbors, no restart mode.
    pub fn begin_restart(
        &self,
        expected: BTreeSet<Ipv4Addr>,
        remaining: Duration,
        unplanned: bool,
    ) {
        if expected.is_empty() {
            return;
        }
        info!(
            neighbors = expected.len(),
            remaining_secs = remaining.as_secs(),
            unplanned,
            "ospfv3 restart mode: entered"
        );
        *self
            .restart
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(RestartState {
            expected,
            deadline: Instant::now() + remaining,
            reason: if unplanned {
                crate::lsa::RESTART_REASON_UNKNOWN
            } else {
                crate::lsa::RESTART_REASON_SOFTWARE
            },
        });
        self.restart_on.store(true, Ordering::Relaxed);
    }

    /// Whether restart mode is still on.
    pub fn restart_active(&self) -> bool {
        self.restart_on.load(Ordering::Relaxed)
    }

    /// `(grace period seconds, reason)` for the Grace-LSA a link sends before
    /// its first Hello; `None` outside restart mode.
    pub(super) fn startup_grace(&self) -> Option<(u32, u8)> {
        let guard = self
            .restart
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = guard.as_ref()?;
        let left = state.deadline.saturating_duration_since(Instant::now());
        // A zero period would read as "flush": at least one second.
        let secs = u32::try_from(left.as_secs()).unwrap_or(u32::MAX).max(1);
        Some((secs, state.reason))
    }

    /// Router ids of every neighbor `Full` on any link now.
    pub async fn full_neighbor_ids(&self) -> BTreeSet<Ipv4Addr> {
        self.links
            .lock()
            .await
            .values()
            .flat_map(|e| {
                e.status
                    .borrow()
                    .neighbors
                    .iter()
                    .filter(|(_, n)| n.state == NeighborState::Full)
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Ends restart mode when `restart::exit_reason` says so (1 s aging tick):
    /// flushes the Grace-LSA (§2.3) and wakes the origination pass; the route
    /// push then sends its first `Full`. `topology_changed`: strict LSA
    /// checking saw a router other than us change an installed LSA.
    pub async fn restart_tick(&self, topology_changed: bool) {
        if !self.restart_active() {
            return;
        }
        let full = self.full_neighbor_ids().await;
        let reason = {
            let mut guard = self
                .restart
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(state) = guard.as_ref() else {
                return;
            };
            let Some(reason) = restart::exit_reason(
                &state.expected,
                &full,
                Instant::now() >= state.deadline,
                topology_changed,
            ) else {
                return;
            };
            *guard = None;
            reason
        };
        self.restart_on.store(false, Ordering::Relaxed);
        info!(reason = %reason.as_str(), "ospfv3 restart mode: exited");
        let senders: Vec<_> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.grace_tx.clone())
            .collect();
        for tx in senders {
            let _ = tx.send(GraceCmd::Flush);
        }
        self.reoriginate.notify_one();
    }
}
