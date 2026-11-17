//! RFC 4271 §9.2.1.1 `MinRouteAdvertisementInterval`, per peer and per
//! destination: once a prefix has been advertised to a peer, a *changed*
//! advertisement for it waits until `interval` after the previous one, and
//! only the latest is sent (a flap collapses to its final state). A first
//! advertisement is never delayed, so a session's initial table dump goes out
//! at once; withdrawals are exempt.

use std::collections::HashMap;
use std::time::Duration;

use ipnet::IpNet;
use tokio::time::Instant;

use crate::rib::{AdvertisedRoute, OutboundUpdate};

type Key = (IpNet, Option<u32>);

pub struct Mrai {
    interval: Duration,
    last_sent: HashMap<Key, Instant>,
    pending: HashMap<Key, (AdvertisedRoute, Instant)>,
    /// Lower bound on the earliest `pending` due time; may be stale-early
    /// after a withdrawal (a harmless spurious wakeup), never late.
    next_due: Option<Instant>,
}

impl Mrai {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_sent: HashMap::new(),
            pending: HashMap::new(),
            next_due: None,
        }
    }

    /// Returns the update to send now, or `None` if it was held back.
    pub fn push(&mut self, update: OutboundUpdate, now: Instant) -> Option<OutboundUpdate> {
        if self.interval.is_zero() {
            return Some(update);
        }
        match update {
            OutboundUpdate::Announce(route) => {
                let key = (route.prefix, route.path_id);
                match self.last_sent.get(&key) {
                    Some(&sent) if now < sent + self.interval => {
                        let due = sent + self.interval;
                        self.next_due = Some(self.next_due.map_or(due, |d| d.min(due)));
                        self.pending.insert(key, (route, due));
                        None
                    }
                    _ => {
                        self.pending.remove(&key);
                        self.last_sent.insert(key, now);
                        Some(OutboundUpdate::Announce(route))
                    }
                }
            }
            OutboundUpdate::Withdraw(prefix, mp, path_id) => {
                self.pending.remove(&(prefix, path_id));
                Some(OutboundUpdate::Withdraw(prefix, mp, path_id))
            }
            other => Some(other),
        }
    }

    /// Everything held, regardless of its due time.
    pub fn drain(&mut self) -> Vec<OutboundUpdate> {
        self.next_due = None;
        self.pending
            .drain()
            .map(|(_, (route, _))| OutboundUpdate::Announce(route))
            .collect()
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.next_due
    }

    /// Everything whose interval has elapsed.
    pub fn flush(&mut self, now: Instant) -> Vec<OutboundUpdate> {
        let mut out = Vec::new();
        let mut next = None;
        self.pending.retain(|key, (route, due)| {
            if *due <= now {
                self.last_sent.insert(*key, now);
                out.push(OutboundUpdate::Announce(route.clone()));
                false
            } else {
                next = Some(next.map_or(*due, |n: Instant| n.min(*due)));
                true
            }
        });
        self.next_due = next;
        // ponytail: full scan; a stale entry (older than `interval`) can never
        // delay anything, so this bounds `last_sent` — use a due-ordered queue
        // if flushes over a full-table `last_sent` ever show up in a profile.
        let interval = self.interval;
        self.last_sent.retain(|_, sent| now < *sent + interval);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Origin;

    fn route(prefix: &str, med: u32) -> OutboundUpdate {
        OutboundUpdate::Announce(AdvertisedRoute {
            prefix: prefix.parse().unwrap(),
            as_path: vec![].into(),
            next_hop: "192.0.2.1".parse().unwrap(),
            local_pref: None,
            med: Some(med),
            origin: Origin::Igp,
            use_mp: false,
            originator_id: None,
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            unknown: std::sync::Arc::default(),
            cluster_list: vec![],
            communities: vec![],
            extended_communities: vec![],
            large_communities: vec![],
            path_id: None,
        })
    }

    #[test]
    fn zero_interval_passes_everything_through() {
        let mut m = Mrai::new(Duration::ZERO);
        let t = Instant::now();
        assert!(m.push(route("10.0.0.0/8", 1), t).is_some());
        assert!(m.push(route("10.0.0.0/8", 2), t).is_some());
        assert_eq!(m.deadline(), None);
    }

    #[test]
    fn flap_collapses_to_latest_and_first_is_immediate() {
        let mut m = Mrai::new(Duration::from_secs(30));
        let t = Instant::now();
        assert!(m.push(route("10.0.0.0/8", 1), t).is_some());
        // a different prefix is unaffected
        assert!(m.push(route("11.0.0.0/8", 1), t).is_some());
        assert!(m
            .push(route("10.0.0.0/8", 2), t + Duration::from_secs(1))
            .is_none());
        assert!(m
            .push(route("10.0.0.0/8", 3), t + Duration::from_secs(2))
            .is_none());
        assert_eq!(m.deadline(), Some(t + Duration::from_secs(30)));
        assert_eq!(m.flush(t + Duration::from_secs(29)), []);
        assert_eq!(
            m.flush(t + Duration::from_secs(30)),
            vec![route("10.0.0.0/8", 3)]
        );
        assert_eq!(m.deadline(), None);
    }

    #[test]
    fn withdraw_is_immediate_and_cancels_pending() {
        let mut m = Mrai::new(Duration::from_secs(30));
        let t = Instant::now();
        let p: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(m.push(route("10.0.0.0/8", 1), t).is_some());
        assert!(m.push(route("10.0.0.0/8", 2), t).is_none());
        let w = OutboundUpdate::Withdraw(p, false, None);
        assert_eq!(m.push(w.clone(), t), Some(w));
        assert_eq!(m.flush(t + Duration::from_secs(30)), []);
    }
}
