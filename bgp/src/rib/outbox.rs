//! The bounded per-peer outbox (#395). The RIB sends under its mutex and must
//! never block, while a peer that stops reading stalls `fsm::run`'s drain of
//! the channel; so the channel is bounded and what does not fit is
//! *coalesced*: an `Announce`/`Withdraw` only marks its prefix dirty, and
//! once the FSM has emptied the queue `BgpRib::drain_backlog` re-sends the
//! *current* state of each dirty prefix. EVPN NLRIs coalesce the same way,
//! resynced from `evpn_adj_rib_out` (#764). Memory is bounded by the table
//! size, like Adj-RIB-Out itself.
//!
//! Invariant: while a backlog exists, every new item joins it, so a later
//! item never overtakes a lost one.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ipnet::IpNet;
use tokio::sync::{mpsc, Notify};
use tracing::{info, warn};

use super::{
    build_advertisement, family_of, message, BgpRib, FlowspecKey, OutboundUpdate, VpnFlowKey,
};
use crate::evpn::EvpnNlri;
use crate::vpn::VpnKey;

/// Queued updates per peer. Steady state needs far less; a full-table dump
/// overflows it by design and is handled by the backlog.
pub const OUTBOX_CAPACITY: usize = 8192;

/// Prefixes re-evaluated per `drain_backlog` call, so one call cannot refill
/// a drained queue (ADD-PATH may emit several paths per prefix; the surplus
/// just goes back to the backlog).
const DRAIN_BATCH: usize = OUTBOX_CAPACITY / 2;

/// What did not fit in the channel.
#[derive(Debug, Default)]
pub(super) struct Backlog {
    /// Prefixes whose latest `Announce`/`Withdraw` was dropped.
    dirty: HashSet<IpNet>,
    /// ADD-PATH ids whose `Withdraw` was dropped; `add_path_sent` already
    /// forgot them, so only this remembers the peer still holds them.
    lost_ids: HashMap<IpNet, HashSet<u32>>,
    /// Ordered, deduplicated `EndOfRib`/`RefreshMarker`s.
    markers: Vec<OutboundUpdate>,
    /// EVPN NLRIs whose latest update was dropped.
    evpns: HashSet<EvpnNlri>,
    /// Flowspec rules whose latest update was dropped.
    flows: HashSet<FlowspecKey>,
    /// VPN Flowspec rules whose latest update was dropped.
    vpn_flows: HashSet<VpnFlowKey>,
    /// VPN keys whose latest update was dropped.
    vpns: HashSet<VpnKey<IpNet>>,
    /// RT-Constraint keys whose latest update was dropped.
    rtcs: HashSet<super::RtcKey>,
    /// Prefixes re-sent so far in this overflow episode (for the log).
    drained: usize,
}

impl Backlog {
    fn is_empty(&self) -> bool {
        self.dirty.is_empty()
            && self.flows.is_empty()
            && self.vpn_flows.is_empty()
            && self.vpns.is_empty()
            && self.rtcs.is_empty()
            && self.markers.is_empty()
            && self.evpns.is_empty()
    }

    fn push(&mut self, update: OutboundUpdate) {
        match update {
            OutboundUpdate::Announce(route) => {
                self.dirty.insert(route.prefix);
            }
            OutboundUpdate::Withdraw(prefix, _, path_id) => {
                self.dirty.insert(prefix);
                if let Some(id) = path_id {
                    self.lost_ids.entry(prefix).or_default().insert(id);
                }
            }
            OutboundUpdate::AnnounceEvpn(adv) => {
                self.evpns.insert(adv.nlri);
            }
            OutboundUpdate::WithdrawEvpn(nlri) => {
                self.evpns.insert(nlri);
            }
            OutboundUpdate::AnnounceFlowspec(adv) => {
                self.flows.insert((adv.family, adv.nlri));
            }
            OutboundUpdate::WithdrawFlowspec(family, nlri) => {
                self.flows.insert((family, nlri));
            }
            OutboundUpdate::AnnounceVpnFlowspec(rd, adv) => {
                self.vpn_flows.insert((adv.family, (rd, adv.nlri)));
            }
            OutboundUpdate::WithdrawVpnFlowspec(k) => {
                self.vpn_flows.insert(k);
            }
            OutboundUpdate::AnnounceVpn(adv) => {
                self.vpns.insert(adv.key);
            }
            OutboundUpdate::WithdrawVpn(key) => {
                self.vpns.insert(key);
            }
            OutboundUpdate::AnnounceRtc(adv) => {
                self.rtcs.insert(adv.key);
            }
            OutboundUpdate::WithdrawRtc(key) => {
                self.rtcs.insert(key);
            }
            marker @ (OutboundUpdate::RefreshMarker { .. } | OutboundUpdate::EndOfRib(_)) => {
                if !self.markers.contains(&marker) {
                    self.markers.push(marker);
                }
            }
        }
    }

    /// Folds in `newer`, which was parked after `self` was taken.
    fn merge(&mut self, newer: Backlog) {
        self.dirty.extend(newer.dirty);
        self.flows.extend(newer.flows);
        self.vpn_flows.extend(newer.vpn_flows);
        self.vpns.extend(newer.vpns);
        self.rtcs.extend(newer.rtcs);
        for (prefix, ids) in newer.lost_ids {
            self.lost_ids.entry(prefix).or_default().extend(ids);
        }
        for m in newer.markers {
            if !self.markers.contains(&m) {
                self.markers.push(m);
            }
        }
        self.evpns.extend(newer.evpns);
        self.drained += newer.drained;
    }
}

struct Inner {
    peer: IpAddr,
    tx: mpsc::Sender<OutboundUpdate>,
    /// Mirrors `!backlog.is_empty()` so the fast path takes no lock.
    pending: AtomicBool,
    /// Fired when something is parked, for the FSM's drain.
    wake: Notify,
    backlog: Mutex<Backlog>,
}

/// The RIB's end of a peer's outbox; the only way to send to a peer.
#[derive(Clone)]
pub struct OutboxTx(Arc<Inner>);

pub fn channel(peer: IpAddr, capacity: usize) -> (OutboxTx, mpsc::Receiver<OutboundUpdate>) {
    let (tx, rx) = mpsc::channel(capacity);
    let inner = Inner {
        peer,
        tx,
        pending: AtomicBool::new(false),
        wake: Notify::new(),
        backlog: Mutex::new(Backlog::default()),
    };
    (OutboxTx(Arc::new(inner)), rx)
}

impl OutboxTx {
    /// Queues `update`, or parks it in the backlog when the queue is full or
    /// a backlog already exists.
    pub fn send(&self, update: OutboundUpdate) {
        let update = if self.pending() {
            update
        } else {
            match self.0.tx.try_send(update) {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => return,
                Err(mpsc::error::TrySendError::Full(update)) => update,
            }
        };
        let mut backlog = self.0.backlog.lock().expect("never held across a panic");
        if backlog.is_empty() {
            warn!(peer = %self.0.peer, "bgp: outbox full, coalescing");
        }
        backlog.push(update);
        self.0.pending.store(true, Ordering::Release);
        drop(backlog);
        self.0.wake.notify_one();
    }

    /// Whether anything is parked.
    pub fn pending(&self) -> bool {
        self.0.pending.load(Ordering::Acquire)
    }

    /// Resolves when something was parked (a stored permit counts).
    pub async fn parked(&self) {
        self.0.wake.notified().await;
    }

    fn take(&self) -> Backlog {
        let mut backlog = self.0.backlog.lock().expect("never held across a panic");
        self.0.pending.store(false, Ordering::Release);
        std::mem::take(&mut *backlog)
    }

    /// Puts back what `take` returned (oldest first) and whatever was parked since.
    fn restore(&self, old: Backlog) {
        let mut backlog = self.0.backlog.lock().expect("never held across a panic");
        let newer = std::mem::replace(&mut *backlog, old);
        backlog.merge(newer);
        let pending = !backlog.is_empty();
        self.0.pending.store(pending, Ordering::Release);
        drop(backlog);
        if pending {
            self.0.wake.notify_one();
        }
    }
}

/// An outbox with room for any test's traffic.
#[cfg(test)]
pub fn test_channel() -> (OutboxTx, mpsc::Receiver<OutboundUpdate>) {
    channel(std::net::Ipv4Addr::UNSPECIFIED.into(), OUTBOX_CAPACITY)
}

impl BgpRib {
    /// Re-sends the current state of what `peer`'s outbox dropped. Call when
    /// its queue is empty; at most `DRAIN_BATCH` prefixes per call, the
    /// outbox re-arms itself until the backlog is gone.
    pub fn drain_backlog(&mut self, peer: IpAddr) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        if self.deferring() {
            return; // the end of the deferral re-sends everything
        }
        let tx = outbox.tx.clone();
        let mut backlog = tx.take();
        let (lead, trail): (Vec<_>, Vec<_>) = std::mem::take(&mut backlog.markers)
            .into_iter()
            .partition(|m| {
                matches!(
                    m,
                    OutboundUpdate::RefreshMarker {
                        subtype: message::REFRESH_BORR,
                        ..
                    }
                )
            });
        for m in lead {
            tx.send(m);
        }
        let batch: Vec<IpNet> = backlog.dirty.iter().take(DRAIN_BATCH).copied().collect();
        for prefix in &batch {
            backlog.dirty.remove(prefix);
            let lost = backlog.lost_ids.remove(prefix);
            self.resync_prefix(peer, *prefix, lost.as_ref());
        }
        backlog.drained += batch.len();
        // ponytail: every lost rule at once, not batched (Flowspec tables are
        // small); batch like `dirty` if one ever overflows the queue alone.
        for k in std::mem::take(&mut backlog.flows) {
            self.sync_flow_to(peer, &k, true);
        }
        for k in std::mem::take(&mut backlog.vpn_flows) {
            self.sync_vpn_flow_to(peer, &k, true);
        }
        // Membership first: it gates what the VPN/EVPN resync may send.
        for k in std::mem::take(&mut backlog.rtcs) {
            self.sync_rtc_to(peer, &k, true);
        }
        // Batched like `dirty`: a reflector's VPN table can be a full one.
        let vpns: Vec<_> = backlog.vpns.iter().take(DRAIN_BATCH).copied().collect();
        for k in &vpns {
            backlog.vpns.remove(k);
            self.sync_vpn_to(peer, k, true);
        }
        backlog.drained += vpns.len();
        // Batched like `dirty`: a Type-5 burst can be a full table (#764).
        let evpns: Vec<_> = backlog.evpns.iter().take(DRAIN_BATCH).cloned().collect();
        for nlri in &evpns {
            backlog.evpns.remove(nlri);
            let update = match self.evpn_adj_rib_out.get(&peer).and_then(|s| s.get(nlri)) {
                Some(adv) => OutboundUpdate::AnnounceEvpn(adv.clone()),
                // Withdrawing an unknown route is legal, as in `resync_prefix`.
                None => OutboundUpdate::WithdrawEvpn(nlri.clone()),
            };
            tx.send(update);
        }
        backlog.drained += evpns.len();
        if backlog.dirty.is_empty() && backlog.vpns.is_empty() && backlog.evpns.is_empty() {
            for m in trail {
                tx.send(m);
            }
            info!(%peer, prefixes = backlog.drained, "bgp: outbox backlog drained");
            backlog.drained = 0;
        } else {
            backlog.markers = trail;
        }
        tx.restore(backlog);
    }

    /// Brings `peer` in line with the current state of `prefix`, whatever
    /// messages for it were lost: unlike `fan_out`, an ineligible prefix is
    /// withdrawn even if `adj_rib_out` does not list it (withdrawing an
    /// unknown route is legal BGP).
    fn resync_prefix(&mut self, peer: IpAddr, prefix: IpNet, lost: Option<&HashSet<u32>>) {
        let outbox = &self.peer_outboxes[&peer];
        let (tx, mp) = (outbox.tx.clone(), outbox.mp_bgp_negotiated);
        if outbox.add_path_tx.contains(&family_of(prefix)) {
            self.propagate_add_path(prefix, Some(peer));
            let live = self.add_path_sent.get(&(peer, prefix));
            for id in lost.into_iter().flatten() {
                if !live.is_some_and(|s| s.values().any(|(i, _)| i == id)) {
                    tx.send(OutboundUpdate::Withdraw(prefix, mp, Some(*id)));
                }
            }
            return;
        }
        let adv = (!self.suppressed_by_aggregate(prefix))
            .then(|| self.loc_rib.get(&prefix))
            .flatten()
            .and_then(|route| {
                build_advertisement(
                    prefix,
                    route,
                    peer,
                    outbox,
                    self.local_asn,
                    self.source_is_rr_client(route),
                    self.cluster_id,
                    None,
                )
            });
        if let Some(adv) = adv {
            tx.send(OutboundUpdate::Announce(adv));
            self.adj_rib_out.entry(peer).or_default().insert(prefix);
        } else {
            if let Some(sent) = self.adj_rib_out.get_mut(&peer) {
                sent.remove(&prefix);
            }
            tx.send(OutboundUpdate::Withdraw(prefix, mp, None));
        }
    }
}
