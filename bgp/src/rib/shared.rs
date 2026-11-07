//! The one shared `BgpRib`, behind a mutex whose write guard bumps a
//! generation counter on release (#420). The route-push tasks
//! (`rib_push_client`, `fdb_push_client`) wait on it instead of polling.
//!
//! One `watch<u64>` rather than a `Notify`: three push tasks share it, and a
//! `Notify` wakes one waiter (`notify_one`) or loses an edge when none is
//! waiting (`notify_waiters`); a watch generation does neither and coalesces
//! bursts. Bumping from the guard covers every mutation path of `BgpRib`
//! (UPDATE handling, redistribute, EVPN, GR, config) without a hook per call
//! site.

// ponytail: any `&mut` access bumps, including mutations that cannot change
// the push snapshots (per-peer settings); a spurious wake costs one snapshot
// + diff. Narrow to the real bump points if profiling ever shows it.

use std::ops::{Deref, DerefMut};

use tokio::sync::{watch, Mutex, MutexGuard};

use super::BgpRib;

pub struct SharedRib {
    inner: Mutex<BgpRib>,
    changed: watch::Sender<u64>,
    /// The BMP exporter's hub (#878): the sessions reach it through the one
    /// handle they all share.
    bmp: std::sync::Arc<crate::bmp::Hub>,
}

impl SharedRib {
    pub fn new(mut rib: BgpRib) -> Self {
        let bmp = crate::bmp::Hub::new();
        rib.set_bmp(bmp.clone());
        Self {
            inner: Mutex::new(rib),
            changed: watch::channel(0).0,
            bmp,
        }
    }

    /// The BMP hub of this instance.
    pub fn bmp(&self) -> &std::sync::Arc<crate::bmp::Hub> {
        &self.bmp
    }

    pub async fn lock(&self) -> RibGuard<'_> {
        RibGuard {
            guard: self.inner.lock().await,
            changed: &self.changed,
            dirty: false,
        }
    }

    /// A receiver whose `changed()` resolves after any mutation of the RIB.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }
}

pub struct RibGuard<'a> {
    guard: MutexGuard<'a, BgpRib>,
    changed: &'a watch::Sender<u64>,
    dirty: bool,
}

impl Deref for RibGuard<'_> {
    type Target = BgpRib;
    fn deref(&self) -> &BgpRib {
        &self.guard
    }
}

impl DerefMut for RibGuard<'_> {
    fn deref_mut(&mut self) -> &mut BgpRib {
        self.dirty = true;
        &mut self.guard
    }
}

impl Drop for RibGuard<'_> {
    fn drop(&mut self) {
        if self.dirty {
            self.changed.send_modify(|g| *g = g.wrapping_add(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bumps_on_mutable_access_only() {
        let shared = SharedRib::new(BgpRib::new());
        let mut rx = shared.subscribe();
        let _ = shared.lock().await.push_snapshot();
        assert!(!rx.has_changed().unwrap(), "read-only access must not bump");
        shared.lock().await.set_routing_table(Some("rt1".into()));
        assert!(rx.has_changed().unwrap());
        rx.changed().await.unwrap();
        assert!(!rx.has_changed().unwrap());
    }

    /// The VPN push (`vpn_push_client`) re-imports on this wake, so a change
    /// of `maximum-paths` alone must bump the generation.
    #[tokio::test]
    async fn a_maximum_paths_change_wakes_the_pushes() {
        let shared = SharedRib::new(BgpRib::new());
        let rx = shared.subscribe();
        shared.lock().await.set_maximum_paths(Some(2));
        assert!(rx.has_changed().unwrap());
    }
}
