//! The per-scope Link State Database — installed-LSA store keyed by the LSA
//! header's key, generic over the family's `Lsa`. Pure data structure, no
//! I/O; the daemons' `link.rs` drive when LSAs get installed (self-origination
//! or received via LSU) and read (DBD summary lists, LSR responses), holding
//! it behind an `Arc<tokio::sync::Mutex<_>>`. RFC 5340 keeps RFC 2328
//! §13/§14's install/age/evict semantics unchanged, so both daemons share this.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::lsa::{Lsa, LsaHeader, MAX_AGE};

/// The key type of `L`'s header.
pub type Key<L> = <<L as Lsa>::Header as LsaHeader>::Key;

/// RFC 2328 §13 step 5a / Appendix B's `MinLSArrival` — a newer instance of
/// an LSA received via flooding within this long of the previous received
/// instance is discarded (`InstallOutcome::TooSoon`), not installed and not
/// acknowledged, so a flapping originator can't drive reflood storms.
pub const MIN_LS_ARRIVAL: Duration = Duration::from_secs(1);

/// How many `age_and_evict` ticks an entry sits at `MAX_AGE` before it's
/// evicted. RFC 2328 §14 removes a `MaxAge` LSA once it's off every neighbor's
/// retransmission list; the daemons have no such signal (flooding is a
/// periodic full resend, `link::RXMT_INTERVAL` = 5s), so a bounded hold —
/// long enough for one resend tick plus margin — is what lets a flushed LSA
/// actually reach the neighbors before it disappears locally.
pub const MAX_AGE_HOLD_TICKS: u16 = 7;

pub struct Lsdb<L: Lsa> {
    entries: HashMap<Key<L>, Arc<L>>,
    /// Ticks each entry has already spent at `MAX_AGE` — see
    /// `MAX_AGE_HOLD_TICKS`.
    max_age_ticks: HashMap<Key<L>, u16>,
    /// Fired on every change that can alter SPF input (install, remove,
    /// evict) so `rib_push_client` recomputes at once instead of on its poll.
    notify: Option<Arc<tokio::sync::Notify>>,
    /// When each key's current instance was last accepted via flooding
    /// (`install_received`) — see `MIN_LS_ARRIVAL`. Self-originated installs
    /// don't record here: they're paced by `MinLSInterval` instead.
    last_received: HashMap<Key<L>, Instant>,
    /// Own LSAs a neighbor flooded back newer than ours (RFC 2328 §13.4) —
    /// see `mark_reflected`.
    reflected: HashSet<Key<L>>,
    /// Woken by `mark_reflected` so the originator runs at once.
    reflect_notify: Option<Arc<tokio::sync::Notify>>,
    /// Advertising routers whose topology LSA changed since the last
    /// `take_topology_changes` — see `Lsa::is_topology`.
    topology_changes: HashSet<Ipv4Addr>,
}

impl<L: Lsa> Default for Lsdb<L> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            max_age_ticks: HashMap::new(),
            notify: None,
            last_received: HashMap::new(),
            reflected: HashSet::new(),
            reflect_notify: None,
            topology_changes: HashSet::new(),
        }
    }
}

impl<L: Lsa> std::fmt::Debug for Lsdb<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lsdb")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// No prior instance existed.
    Installed,
    /// A newer instance replaced an older one.
    Superseded,
    /// The given instance wasn't newer than what's already held — RFC 2328
    /// §13's "database copy is more recent or the same" case.
    Rejected,
    /// Newer, but received less than `MIN_LS_ARRIVAL` after the held
    /// instance was — RFC 2328 §13 step 5a: discard without acknowledging.
    TooSoon,
}

impl<L: Lsa> Lsdb<L> {
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty LSDB that wakes `notify` whenever its contents change.
    pub fn with_notify(notify: Arc<tokio::sync::Notify>) -> Self {
        Self {
            notify: Some(notify),
            ..Self::default()
        }
    }

    /// Wakes `notify` whenever an own LSA is marked reflected.
    #[must_use]
    pub fn with_reflect_notify(mut self, notify: Arc<tokio::sync::Notify>) -> Self {
        self.reflect_notify = Some(notify);
        self
    }

    /// RFC 2328 §13.4: records that the held instance of `key`, one of this
    /// router's own LSAs, is a neighbor's newer copy, and wakes the
    /// originator. The next origination of `key` (`take_reflected`) goes
    /// above it regardless of body or `MinLSInterval`; a mark nobody takes
    /// (`reflected_keys`) is an LSA this router no longer originates.
    pub fn mark_reflected(&mut self, key: Key<L>) {
        self.reflected.insert(key);
        if let Some(n) = &self.reflect_notify {
            n.notify_one();
        }
    }

    /// Whether `key` was marked reflected, clearing the mark.
    pub fn take_reflected(&mut self, key: &Key<L>) -> bool {
        self.reflected.remove(key)
    }

    /// Every mark currently set. An origination pass snapshots these before
    /// it runs and `take_reflected`s them after: a mark it left is a key no
    /// pass originated, i.e. an LSA this router no longer advertises.
    pub fn reflected_keys(&self) -> Vec<Key<L>> {
        self.reflected.iter().copied().collect()
    }

    /// RFC 3623 §3.2 (c): the advertising routers whose topology LSAs changed
    /// (new, different body, or flushed) since the last call, clearing the set.
    pub fn take_topology_changes(&mut self) -> Vec<Ipv4Addr> {
        self.topology_changes.drain().collect()
    }

    /// Records `lsa`'s origin when installing it over `old` is a topology change.
    fn note_topology(&mut self, lsa: &L, old: Option<&L>) {
        let flush = lsa.header().age() >= MAX_AGE;
        let changed = lsa.is_topology()
            && match old {
                None => !flush,
                Some(o) => !o.same_content(lsa) || (flush && o.header().age() < MAX_AGE),
            };
        if changed {
            self.topology_changes
                .insert(lsa.header().advertising_router());
        }
    }

    fn kick(&self) {
        if let Some(n) = &self.notify {
            n.notify_one();
        }
    }

    /// Installs `lsa` if it's newer than (or new relative to) what's held —
    /// see `LsaHeader::is_newer`.
    pub fn install(&mut self, lsa: L) -> InstallOutcome {
        let key = lsa.header().key();
        match self.entries.get(&key) {
            Some(existing) if lsa.header().is_newer(existing.header()) != Ordering::Greater => {
                InstallOutcome::Rejected
            }
            Some(existing) => {
                let existing = Arc::clone(existing);
                self.note_topology(&lsa, Some(&existing));
                // A fresh instance restarts the MaxAge hold; a flushed one
                // (same sequence, age now MaxAge) starts it.
                self.max_age_ticks.remove(&key);
                self.entries.insert(key, Arc::new(lsa));
                self.kick();
                InstallOutcome::Superseded
            }
            None => {
                self.note_topology(&lsa, None);
                self.entries.insert(key, Arc::new(lsa));
                self.kick();
                InstallOutcome::Installed
            }
        }
    }

    /// `install` for an instance received via flooding, paced by
    /// `MIN_LS_ARRIVAL`: a newer instance arriving within it of the last one
    /// accepted for the same key is `TooSoon` and left uninstalled — the
    /// sender's retransmission brings it back after `RxmtInterval`.
    pub fn install_received(&mut self, lsa: L, now: Instant) -> InstallOutcome {
        let key = lsa.header().key();
        let too_soon = self
            .last_received
            .get(&key)
            .is_some_and(|last| now.duration_since(*last) < MIN_LS_ARRIVAL);
        let newer = self
            .entries
            .get(&key)
            .is_none_or(|existing| lsa.header().is_newer(existing.header()) == Ordering::Greater);
        if too_soon && newer {
            return InstallOutcome::TooSoon;
        }
        let outcome = self.install(lsa);
        if outcome != InstallOutcome::Rejected {
            self.last_received.insert(key, now);
        }
        outcome
    }

    /// Drops `key` outright — a received Grace-LSA, acted on and never held.
    pub fn remove(&mut self, key: &Key<L>) {
        self.entries.remove(key);
        self.kick();
        self.max_age_ticks.remove(key);
        self.last_received.remove(key);
        self.reflected.remove(key);
    }

    pub fn get(&self, key: &Key<L>) -> Option<Arc<L>> {
        self.entries.get(key).cloned()
    }

    /// Every installed LSA's header — the source of a DBD summary list.
    pub fn headers(&self) -> Vec<L::Header> {
        self.entries.values().map(|l| *l.header()).collect()
    }

    /// Every installed LSA — used by the daemons' periodic full-LSDB resend
    /// to `Full` neighbors.
    pub fn all(&self) -> Vec<Arc<L>> {
        self.entries.values().cloned().collect()
    }

    /// RFC 2328 §14: ages every installed LSA by `delta` (saturating at
    /// `MAX_AGE`) and evicts any entry that has sat at `MAX_AGE` for
    /// `MAX_AGE_HOLD_TICKS` ticks — whether it aged out naturally or was
    /// prematurely aged (§14.1) — returning the evicted keys so the caller
    /// can log them. The hold is what gives the periodic resend a chance to
    /// carry the `MaxAge` copy to every neighbor first.
    ///
    /// An LSA whose advertising router is in `hold` (a neighbor in its grace
    /// period, RFC 3623 / RFC 5187) is aged no further than just below
    /// `MaxAge`: the helper keeps the restarting router's LSAs until grace
    /// ends. A copy already at `MaxAge` (one the restarter flushed itself) is
    /// evicted as usual.
    pub fn age_and_evict(&mut self, delta: u16, hold: &HashSet<Ipv4Addr>) -> Vec<Key<L>> {
        let mut evicted = Vec::new();
        let max_age_ticks = &mut self.max_age_ticks;
        let last_received = &mut self.last_received;
        self.entries.retain(|key, lsa| {
            if lsa.header().age() >= MAX_AGE {
                let ticks = max_age_ticks.entry(*key).or_insert(0);
                *ticks += 1;
                if *ticks >= MAX_AGE_HOLD_TICKS {
                    max_age_ticks.remove(key);
                    last_received.remove(key);
                    evicted.push(*key);
                    return false;
                }
                return true;
            }
            let mut aged = lsa.header().age().saturating_add(delta).min(MAX_AGE);
            if aged >= MAX_AGE && hold.contains(&lsa.header().advertising_router()) {
                aged = MAX_AGE - 1;
            }
            if aged != lsa.header().age() {
                let mut updated = (**lsa).clone();
                updated.header_mut().set_age(aged);
                *lsa = Arc::new(updated);
            }
            true
        });
        if !evicted.is_empty() {
            self.kick();
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;

    use super::*;
    use crate::lsa::test_lsa::{lsa, L};

    type Db = Lsdb<L>;

    fn with(id: u32, seq: i32, checksum: u16, age: u16) -> L {
        L(crate::lsa::test_lsa::H {
            id,
            seq,
            age,
            checksum,
        })
    }

    #[test]
    fn topology_changes_follow_content_not_refreshes() {
        let mut db = Db::new();
        let origin = Ipv4Addr::from(9);
        db.install(with(9, 1, 5, 0));
        assert_eq!(db.take_topology_changes(), vec![origin], "new LSA");
        assert!(db.take_topology_changes().is_empty(), "drained once");
        db.install(with(9, 2, 5, 0));
        assert!(db.take_topology_changes().is_empty(), "identical refresh");
        db.install(with(9, 3, 6, 0));
        db.install(with(9, 4, 7, 0));
        assert_eq!(
            db.take_topology_changes(),
            vec![origin],
            "changed, deduplicated"
        );
        db.install(with(9, 4, 7, MAX_AGE));
        assert_eq!(db.take_topology_changes(), vec![origin], "flush");
        db.install(with(0, 1, 5, 0));
        assert!(db.take_topology_changes().is_empty(), "not a topology LSA");
    }

    fn key() -> u32 {
        lsa(1).header().key()
    }

    #[test]
    fn first_install_is_installed() {
        let mut db = Db::new();
        assert_eq!(db.install(lsa(1)), InstallOutcome::Installed);
        assert!(db.get(&key()).is_some());
    }

    #[test]
    fn newer_instance_supersedes() {
        let mut db = Db::new();
        db.install(lsa(1));
        assert_eq!(db.install(lsa(2)), InstallOutcome::Superseded);
        assert_eq!(db.get(&key()).unwrap().header().seq(), 2);
    }

    #[test]
    fn older_instance_is_rejected() {
        let mut db = Db::new();
        db.install(lsa(2));
        assert_eq!(db.install(lsa(1)), InstallOutcome::Rejected);
        assert_eq!(db.get(&key()).unwrap().header().seq(), 2);
    }

    #[test]
    fn unknown_key_returns_none() {
        let db = Db::new();
        assert!(db.get(&key()).is_none());
    }

    #[test]
    fn headers_and_all_reflect_installed_entries() {
        let mut db = Db::new();
        db.install(lsa(1));
        assert_eq!(db.headers().len(), 1);
        assert_eq!(db.headers()[0].key(), key());
        assert_eq!(db.all().len(), 1);
        assert!(format!("{db:?}").contains("entries"));
    }

    #[test]
    fn age_and_evict_increments_age_without_eviction() {
        let mut db = Db::new();
        db.install(lsa(1));
        let evicted = db.age_and_evict(100, &HashSet::new());
        assert_eq!(evicted, Vec::<u32>::new());
        assert_eq!(db.get(&key()).unwrap().header().age(), 100);
    }

    /// Ticks until `age_and_evict` reports an eviction, or `None` if it never
    /// does within `MAX_AGE_HOLD_TICKS + 1` ticks.
    fn ticks_until_evicted(db: &mut Db, delta: u16) -> Option<u16> {
        (1..=MAX_AGE_HOLD_TICKS + 1).find(|_| !db.age_and_evict(delta, &HashSet::new()).is_empty())
    }

    #[test]
    fn age_and_evict_holds_at_max_age_then_evicts() {
        let mut db = Db::new();
        db.install(lsa(1));
        // Saturates at MAX_AGE on the first tick, then is held for the flood window.
        assert_eq!(
            db.age_and_evict(MAX_AGE, &HashSet::new()),
            Vec::<u32>::new()
        );
        assert_eq!(db.get(&key()).unwrap().header().age(), MAX_AGE);
        assert_eq!(ticks_until_evicted(&mut db, 1), Some(MAX_AGE_HOLD_TICKS));
        assert!(db.get(&key()).is_none());
    }

    #[test]
    fn age_and_evict_only_evicts_crossed_entries() {
        let mut db = Db::new();
        let mut stale = lsa(1);
        stale.0.id = 1;
        stale.0.age = MAX_AGE;
        db.install(stale.clone());
        db.install(lsa(1));

        assert_eq!(ticks_until_evicted(&mut db, 10), Some(MAX_AGE_HOLD_TICKS));
        assert!(db.get(&stale.header().key()).is_none());
        assert_eq!(
            db.get(&key()).unwrap().header().age(),
            10 * MAX_AGE_HOLD_TICKS
        );
    }

    #[test]
    fn superseding_a_max_age_entry_restarts_its_hold() {
        let mut db = Db::new();
        let mut flushed = lsa(1);
        flushed.0.age = MAX_AGE;
        db.install(flushed);
        for _ in 0..MAX_AGE_HOLD_TICKS - 1 {
            assert_eq!(db.age_and_evict(1, &HashSet::new()), Vec::<u32>::new());
        }
        assert_eq!(db.install(lsa(2)), InstallOutcome::Superseded);
        assert_eq!(db.age_and_evict(1, &HashSet::new()), Vec::<u32>::new());
        assert_eq!(db.get(&key()).unwrap().header().age(), 1);
    }

    #[test]
    fn age_and_evict_holds_a_router_in_grace() {
        let mut db = Db::new();
        db.install(lsa(1));
        let in_grace = HashSet::from([lsa(1).header().advertising_router()]);
        assert_eq!(db.age_and_evict(MAX_AGE, &in_grace), Vec::<u32>::new());
        assert_eq!(db.get(&key()).unwrap().header().age(), MAX_AGE - 1);
        // Grace over: it reaches MaxAge and is evicted after the usual hold.
        assert_eq!(db.age_and_evict(1, &HashSet::new()), Vec::<u32>::new());
        assert_eq!(ticks_until_evicted(&mut db, 1), Some(MAX_AGE_HOLD_TICKS));
    }

    /// A copy the restarter already flushed (at `MaxAge`) is not held.
    #[test]
    fn age_and_evict_does_not_hold_a_flushed_copy() {
        let mut db = Db::new();
        let mut flushed = lsa(1);
        flushed.0.age = MAX_AGE;
        db.install(flushed);
        let in_grace = HashSet::from([lsa(1).header().advertising_router()]);
        let evicted = (0..MAX_AGE_HOLD_TICKS).any(|_| !db.age_and_evict(1, &in_grace).is_empty());
        assert!(evicted);
    }

    /// RFC 2328 §13 step 5a: a newer instance within `MIN_LS_ARRIVAL` of the
    /// last received one is `TooSoon` and leaves the held one untouched; at
    /// or past it, it supersedes as usual.
    #[test]
    fn install_received_paces_newer_instances_by_min_ls_arrival() {
        let mut db = Db::new();
        let t0 = Instant::now();
        assert_eq!(db.install_received(lsa(1), t0), InstallOutcome::Installed);
        assert_eq!(
            db.install_received(lsa(2), t0 + MIN_LS_ARRIVAL / 2),
            InstallOutcome::TooSoon
        );
        assert_eq!(db.get(&key()).unwrap().header().seq(), 1);
        // A duplicate is still just rejected, never `TooSoon`.
        assert_eq!(
            db.install_received(lsa(1), t0 + MIN_LS_ARRIVAL / 2),
            InstallOutcome::Rejected
        );
        assert_eq!(
            db.install_received(lsa(2), t0 + MIN_LS_ARRIVAL),
            InstallOutcome::Superseded
        );
        assert_eq!(db.get(&key()).unwrap().header().seq(), 2);
        // The pacing clock restarts from the accepted instance.
        assert_eq!(
            db.install_received(lsa(3), t0 + MIN_LS_ARRIVAL + MIN_LS_ARRIVAL / 2),
            InstallOutcome::TooSoon
        );
    }

    /// A self-originated install never records an arrival, so a received
    /// newer instance right after it isn't paced against it.
    #[test]
    fn install_received_is_not_paced_against_a_local_install() {
        let mut db = Db::new();
        let t0 = Instant::now();
        db.install(lsa(1));
        assert_eq!(db.install_received(lsa(2), t0), InstallOutcome::Superseded);
    }

    /// `remove` forgets the pacing clock too.
    #[test]
    fn remove_clears_pacing() {
        let mut db = Db::new();
        let t0 = Instant::now();
        db.install_received(lsa(1), t0);
        db.remove(&key());
        assert_eq!(db.install_received(lsa(2), t0), InstallOutcome::Installed);
    }

    #[tokio::test]
    async fn reflected_marks_are_taken_once_drained_and_wake_the_originator() {
        let n = Arc::new(tokio::sync::Notify::new());
        let mut db = Db::new().with_reflect_notify(Arc::clone(&n));
        db.install(lsa(1));
        assert!(!db.take_reflected(&key()));
        db.mark_reflected(key());
        assert!(n.notified().now_or_never().is_some());
        assert!(db.take_reflected(&key()));
        assert!(!db.take_reflected(&key()));
        db.mark_reflected(key());
        assert_eq!(db.reflected_keys(), vec![key()]);
        db.mark_reflected(key());
        db.remove(&key());
        assert!(!db.take_reflected(&key()));
    }

    /// Every change that can alter SPF input wakes the notify; a rejected
    /// install does not.
    #[tokio::test]
    async fn changes_notify_and_rejects_do_not() {
        let n = Arc::new(tokio::sync::Notify::new());
        let mut db = Db::with_notify(Arc::clone(&n));
        let fired = |n: &tokio::sync::Notify| n.notified().now_or_never().is_some();
        db.install(lsa(2));
        assert!(fired(&n));
        db.install(lsa(3));
        assert!(fired(&n));
        db.install(lsa(1));
        assert!(!fired(&n));
        db.remove(&key());
        assert!(fired(&n));
    }
}
