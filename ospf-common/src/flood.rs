//! Pure RFC 2328 §13.3 flooding and §13.5 acknowledgment decisions, shared by
//! `nos-ospf` and `nos-ospfv3` (#1516). No I/O: the daemon feeds the receiving
//! link's neighbors in, sends what comes out and MTU-splits it with
//! `exchange::chunk_by_budget`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use crate::drouters::{flood_dest, Dest};
use crate::exchange::{AdjacencyData, Rxmt};
use crate::lsa::{Lsa, LsaHeader};
use crate::neighbor::NeighborState;

/// Per-link facts for one call.
#[derive(Clone, Copy, Debug)]
pub struct LinkFlood {
    pub broadcast: bool,
    pub we_are_dr: bool,
    pub we_are_bdr: bool,
}

/// The LSA arrived on THIS link (`None` at the call: not received here, or
/// self-originated).
#[derive(Clone, Copy, Debug)]
pub struct Receipt {
    pub from: Ipv4Addr,
    pub from_dr_or_bdr: bool,
}

/// One neighbor of the link, as flooding sees it.
pub struct Peer<'a, L: Lsa> {
    pub id: Ipv4Addr,
    pub state: NeighborState,
    pub adj: &'a mut AdjacencyData<L>,
}

/// One LSU to send: `to` are the neighbors whose retransmission list grew
/// (retransmissions are always unicast, §13.6).
#[derive(Debug, PartialEq)]
pub struct FloodOut<L: Lsa> {
    pub dest: Dest,
    pub to: Vec<Ipv4Addr>,
    pub lsa: Arc<L>,
}

/// §13.3 steps 1 to 5 for one link; mutates the request and retransmission
/// lists. `None`: nothing was added to any list (step 2) or step 3/4
/// suppressed the send (the lists are still updated, as the RFC requires).
///
/// ponytail: request lists hold keys without the requested instance, so
/// step 1b's "the new LSA is less recent, skip the peer" cannot be decided.
/// The request is dropped and the peer served from the retransmission list:
/// the instance we hold is at least as new as the one requested.
pub fn flood_on_link<L: Lsa>(
    lsa: &Arc<L>,
    rx: Option<Receipt>,
    link: LinkFlood,
    peers: &mut [Peer<'_, L>],
    now: Instant,
) -> Option<FloodOut<L>> {
    let key = lsa.header().key();
    let mut to = Vec::new();
    for p in peers.iter_mut() {
        if p.state < NeighborState::Exchange {
            continue;
        }
        if matches!(p.state, NeighborState::Exchange | NeighborState::Loading) {
            p.adj.request_list.retain(|k| *k != key);
        }
        if rx.is_some_and(|r| r.from == p.id) {
            continue;
        }
        p.adj.retransmission_list.insert(
            key,
            Rxmt {
                lsa: Arc::clone(lsa),
                last_sent: now,
            },
        );
        to.push(p.id);
    }
    if to.is_empty() {
        return None;
    }
    if link.broadcast && rx.is_some_and(|r| r.from_dr_or_bdr) {
        return None;
    }
    if link.broadcast && rx.is_some() && link.we_are_bdr {
        return None;
    }
    Some(FloodOut {
        dest: flood_dest(link.broadcast, link.we_are_dr || link.we_are_bdr),
        to,
        lsa: Arc::clone(lsa),
    })
}

/// Merges single-LSA floods sharing `(dest, to)` into one LSU batch (the
/// daemon then MTU-splits it). First-seen order is kept.
pub fn merge_floods<L: Lsa>(outs: Vec<FloodOut<L>>) -> Vec<(Dest, Vec<Ipv4Addr>, Vec<Arc<L>>)> {
    let mut index: HashMap<(Dest, Vec<Ipv4Addr>), usize> = HashMap::new();
    let mut merged: Vec<(Dest, Vec<Ipv4Addr>, Vec<Arc<L>>)> = Vec::new();
    for o in outs {
        if let Some(&i) = index.get(&(o.dest, o.to.clone())) {
            merged[i].2.push(o.lsa);
        } else {
            index.insert((o.dest, o.to.clone()), merged.len());
            merged.push((o.dest, o.to, vec![o.lsa]));
        }
    }
    merged
}

/// §13.5 Table 19 rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxVerdict {
    /// New, and flooded back out the receiving link (the flood is the ack).
    NewerFloodedBack,
    /// New, not flooded back.
    Newer,
    /// Duplicate treated as an implied ack (§13 step 7a).
    DuplicateImplied,
    /// Duplicate, not an implied ack.
    Duplicate,
    /// `MaxAge` with no database copy and no pending request (§13 step 4).
    MaxAgeNoCopy,
    /// Our copy is more recent (§13 step 8): no ack.
    DbNewer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckAction {
    None,
    Delayed,
    Direct,
}

/// §13.5 Table 19. `from_dr` only matters when `we_are_backup`.
#[must_use]
pub const fn ack_action(v: RxVerdict, we_are_backup: bool, from_dr: bool) -> AckAction {
    let backup_delayed = if we_are_backup && !from_dr {
        AckAction::None
    } else {
        AckAction::Delayed
    };
    match v {
        RxVerdict::NewerFloodedBack | RxVerdict::DbNewer => AckAction::None,
        RxVerdict::Newer => backup_delayed,
        RxVerdict::DuplicateImplied => {
            if we_are_backup && from_dr {
                AckAction::Delayed
            } else {
                AckAction::None
            }
        }
        RxVerdict::Duplicate | RxVerdict::MaxAgeNoCopy => AckAction::Direct,
    }
}

/// Would `flood_on_link` send this LSA back out the receiving link (steps 2
/// to 4), decided before the event is consumed. `other_adjacent`: some
/// neighbor other than the sender is `>= Exchange`.
///
/// ponytail: ignores step 1b's request-list suppression; a wrong "flooded
/// back" only drops one ack, which the sender's retransmission re-asks with a
/// direct ack.
#[must_use]
pub const fn floods_back(rx: Receipt, link: LinkFlood, other_adjacent: bool) -> bool {
    link.broadcast && other_adjacent && !rx.from_dr_or_bdr && !link.we_are_bdr
}

#[cfg(test)]
mod tests;
