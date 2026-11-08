//! RFC 2328 §10.6-10.8's Database Description negotiation and summary-list
//! exchange, unchanged by RFC 5340 beyond the LSA header it carries — shared
//! by `nos-ospf` and `nos-ospfv3`. Pure with respect to I/O (no sockets, no
//! timers), but — unlike `neighbor::step` — mutates the `AdjacencyData` it's
//! given directly, since that data (request/retransmission lists) is built
//! up incrementally across many packets rather than swapped wholesale.
//!
//! Real RFC 2328 §10.8 pagination: the local LSDB summary is chunked into
//! `max_headers`-sized pieces, one chunk per DD sequence number, each acked
//! before the next is sent, in both directions. `max_headers` is derived per
//! link from its effective MTU (`mtu_based_max_headers`) unless a daemon's
//! `--dbd-max-headers` test/debug flag overrides it.
//!
//! Also the LSR/LSU/LSAck handling (RFC 2328 §10.7, §13, §13.5). Where the
//! families differ (stub/NSSA scope, opaque LSAs, store routing, the Grace
//! exemption, the DBD Options value, the header overhead) the daemon passes
//! a closure or a `Params`/`Stores` value.

use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use crate::lsa::{Lsa, LsaHeader, MAX_AGE};
use crate::lsdb::{InstallOutcome, Key, Lsdb};
use crate::neighbor::{Event, NeighborState};

/// The LSA header's wire length, identical in RFC 2328 and RFC 5340.
pub const LSA_HEADER_LEN: usize = 20;

/// Fixed per-DBD-packet LSA-header budget used as `--dbd-max-headers`'s
/// default when a test/debug run wants a fixed override rather than the real
/// MTU-derived one (`mtu_based_max_headers`).
pub const DEFAULT_DBD_MAX_HEADERS: usize = 64;

/// How many LSA headers fit in one DBD packet on a link of this MTU: the MTU
/// minus `overhead` (IP header + OSPF header + fixed DBD body: v2 20+24+8, v3
/// 40+16+12), over `LSA_HEADER_LEN` — floored at 1 so a tiny MTU still makes
/// progress.
pub fn mtu_based_max_headers(mtu: u16, overhead: usize) -> usize {
    (mtu as usize)
        .saturating_sub(overhead)
        .checked_div(LSA_HEADER_LEN)
        .unwrap_or(0)
        .max(1)
}

/// Receive buffer for one OSPF packet: the largest IP datagram.
pub const RECV_BUF_LEN: usize = 65_535;

/// `recv` with `MSG_TRUNC` returns the datagram's real length: `true` when it
/// did not fit the `cap`-byte buffer, so the bytes held are a cut-off packet.
pub fn truncated(n: usize, cap: usize) -> bool {
    n > cap
}

/// Splits `items` into consecutive chunks whose summed `size_of` stays within
/// `budget` bytes (greedy, order kept). Every chunk holds at least one item, so
/// an item larger than the budget travels alone (RFC 2328 §13.3: the kernel
/// then fragments it); empty input gives no chunks.
pub fn chunk_by_budget<T>(items: &[T], budget: usize, size_of: impl Fn(&T) -> usize) -> Vec<&[T]> {
    let mut chunks = Vec::new();
    let (mut start, mut used) = (0, 0);
    for (i, item) in items.iter().enumerate() {
        let size = size_of(item);
        if i > start && used + size > budget {
            chunks.push(&items[start..i]);
            (start, used) = (i, 0);
        }
        used += size;
    }
    if start < items.len() {
        chunks.push(&items[start..]);
    }
    chunks
}

/// RFC 2328 §10.6 (RFC 5340 §4.2.1 keeps it): a DBD whose Interface MTU
/// exceeds this link's effective MTU is rejected, since the neighbor could send
/// DBDs we can't receive whole. Smaller, equal and 0 (not advertised) are fine,
/// and `ignore` (`mtu-ignore`) skips the check.
pub fn mtu_acceptable(neighbor_mtu: u16, local_mtu: u16, ignore: bool) -> bool {
    ignore || neighbor_mtu <= local_mtu
}

/// One Database Description packet's contents (RFC 2328 A.3.3, RFC 5340
/// A.3.3), wire-agnostic: each daemon's `packet.rs` aliases it and keeps the
/// codec. `options` is v2's 8-bit or v3's 24-bit Options field.
#[derive(Debug, Clone, PartialEq)]
pub struct Dbd<H> {
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub interface_mtu: u16,
    pub options: u32,
    /// "I"nit bit: this is the first packet in the exchange.
    pub init: bool,
    /// "M"ore bit: the sender has more summary list entries to send.
    pub more: bool,
    /// "MS" bit: the sender considers itself master for this exchange.
    pub master: bool,
    pub dd_sequence_number: u32,
    pub lsa_headers: Vec<H>,
}

/// One neighbor's DBD/LSR/LSU exchange state, from `ExStart` onward.
// Independent flags, each read on its own.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq)]
pub struct AdjacencyData<L: Lsa> {
    pub is_master: bool,
    pub dd_sequence_number: u32,
    /// LSAs this router still needs a full copy of via LSR/LSU.
    pub request_list: Vec<Key<L>>,
    /// LSAs sent via LSU, awaiting an `LSAck` — resent by `link.rs`'s
    /// retransmit sweep until acked.
    pub retransmission_list: HashMap<Key<L>, Arc<L>>,
    /// The most recent DBD this router sent this neighbor (negotiation
    /// packet, poll, or reply) — resent by `link.rs`'s retransmit sweep
    /// until superseded by the next stage of the exchange. Necessary
    /// because the two sides' Hello-driven `TwoWay`/`ExStart` transitions
    /// aren't synchronized: whichever side reaches `ExStart` first sends a
    /// negotiation packet the other side isn't ready to receive yet, so
    /// without a resend that first packet is silently dropped forever.
    pub last_dbd_sent: Option<Dbd<L::Header>>,
    /// RFC 2328 §10.8: local LSDB headers not yet sent to this neighbor —
    /// seeded once from a full LSDB snapshot at `ExStart` exit, then drained
    /// `max_headers` at a time (`pop_chunk`), one chunk per DD sequence
    /// number, until empty.
    pub summary_remaining: VecDeque<L::Header>,
    /// RFC 2328 §13.5 delayed acknowledgment: headers of LSAs received from
    /// this neighbor and not yet acknowledged. The daemon's
    /// `on_lsu_received` appends here instead of answering each LSU with its
    /// own `LSAck`; `link.rs`'s `RXMT_INTERVAL` sweep (`flush_pending_acks`,
    /// via `take_pending_acks`) sends them as one packet.
    pub pending_acks: Vec<L::Header>,
    /// When `pending_acks` last went from empty to non-empty — purely for
    /// the "how long was this batch held" figure the flush logs.
    pub pending_acks_since: Option<Instant>,
    /// RFC 5250 §3 (v2 only): the neighbor's DBD set the O-bit, so it may be
    /// sent opaque LSAs. Learnt in `ExStart` (`Params::peer_opaque_capable`).
    pub opaque_capable: bool,
    /// v2 only: the link is in a stub area (RFC 2328 §3.6) or an NSSA.
    pub stub: bool,
    /// v2 only: the link is in an NSSA (RFC 3101).
    pub nssa: bool,
}

// By hand: a derive would demand `L: Default`.
impl<L: Lsa> Default for AdjacencyData<L> {
    fn default() -> Self {
        Self {
            is_master: false,
            dd_sequence_number: 0,
            request_list: Vec::new(),
            retransmission_list: HashMap::new(),
            last_dbd_sent: None,
            summary_remaining: VecDeque::new(),
            pending_acks: Vec::new(),
            pending_acks_since: None,
            opaque_capable: false,
            stub: false,
            nssa: false,
        }
    }
}

/// One effect `link.rs` must carry out — sending a packet, or feeding an
/// `Event` back into `neighbor::step`.
#[derive(Debug, Clone, PartialEq)]
pub enum Action<L: Lsa> {
    SendDbd(Dbd<L::Header>),
    SendLsr(Vec<Key<L>>),
    SendLsu(Vec<Arc<L>>),
    SendLsAck(Vec<L::Header>),
    NeighborEvent(Event),
}

/// The per-call values `on_dbd_received` needs from the daemon's link.
#[derive(Debug, Clone, Copy)]
pub struct Params {
    pub local_router_id: Ipv4Addr,
    /// LSA headers per DBD (`mtu_based_max_headers` or the test override).
    pub max_headers: usize,
    /// The link's effective MTU, sent as Interface MTU.
    pub mtu: u16,
    /// The Options field of every DBD we send on this link.
    pub dbd_options: u32,
    /// v2: the received DBD set the O-bit (RFC 5250 §3); v3: always false.
    pub peer_opaque_capable: bool,
}

/// Pops up to `max` headers off the front of `remaining` for the next DBD
/// packet, returning the chunk plus whether any remain after it (the `more`
/// bit). `VecDeque::pop_front` keeps this O(chunk size) per call.
fn pop_chunk<H>(remaining: &mut VecDeque<H>, max: usize) -> (Vec<H>, bool) {
    let chunk: Vec<H> = std::iter::from_fn(|| remaining.pop_front())
        .take(max)
        .collect();
    (chunk, !remaining.is_empty())
}

/// Handles one received DBD packet, given `state` (the neighbor's state
/// *before* this packet — `link.rs` applies any resulting `NeighborEvent`
/// via `neighbor::step` itself and passes the pre-transition state in on
/// the next call), driving RFC 2328 §10.6's master/slave negotiation
/// (`ExStart`) and §10.8's summary exchange (`Exchange`). The neighbor is
/// `dbd.router_id`.
///
/// `local_lsdb_headers` is a snapshot the caller takes from its LSDB before
/// calling this — kept out of this function's own state so it stays free of
/// any lock/await. `in_scope` says whether a header may be exchanged on this
/// link at all (v2: stub/NSSA, `lsa::in_area_scope`; v3: always); a DBD
/// listing one that isn't is `SeqNumberMismatch`, and it is never summarized.
/// `is_opaque` keeps opaque LSAs out of the summary for a neighbor that is
/// not opaque-capable (v3: never opaque).
pub fn on_dbd_received<L, FS, FO>(
    adj: &mut AdjacencyData<L>,
    state: NeighborState,
    p: &Params,
    dbd: &Dbd<L::Header>,
    local_lsdb_headers: &[L::Header],
    in_scope: FS,
    is_opaque: FO,
) -> Vec<Action<L>>
where
    L: Lsa,
    FS: Fn(&L::Header) -> bool,
    FO: Fn(&L::Header) -> bool,
{
    // RFC 2328 §10.6: an AS-external LSA listed on a stub area's link (or a
    // Type-7 outside an NSSA) means the two databases can't agree — restart
    // the exchange.
    if matches!(state, NeighborState::ExStart | NeighborState::Exchange)
        && dbd.lsa_headers.iter().any(|h| !in_scope(h))
    {
        return vec![Action::NeighborEvent(Event::SeqNumberMismatch)];
    }
    match state {
        NeighborState::ExStart => {
            on_dbd_in_exstart(adj, p, dbd, local_lsdb_headers, &in_scope, &is_opaque)
        }
        NeighborState::Exchange => on_dbd_in_exchange(adj, p, dbd, local_lsdb_headers),
        NeighborState::Loading | NeighborState::Full => on_dbd_in_loading_or_full(adj, dbd),
        // `Down`/`Init`/`TwoWay`: no adjacency exists yet to receive a DBD
        // for in the first place.
        NeighborState::Down | NeighborState::Init | NeighborState::TwoWay => Vec::new(),
    }
}

/// RFC 2328 §10.6, a DBD received in `Loading`/`Full`:
/// - I-bit set: `SeqNumberMismatch`. Hello alone doesn't catch a peer that
///   hit `SeqNumberMismatch` on its own side (`BadLSReq`, an out-of-sequence
///   DBD, a packet lost in an auth key-change window) while Hellos still
///   list both routers: it sits in `ExStart` sending Init DBDs, and ignoring
///   them would leave it there for good. This also covers a graceful-restart
///   helper whose neighbor restarted while still `Full`.
/// - We are the slave and this is the master's duplicate of its last poll:
///   resend our last DBD. Without it, a lost final reply leaves the master
///   stuck in `Exchange` while we are already `Full`.
/// - Anything else (the master's duplicate, other strays): discarded.
fn on_dbd_in_loading_or_full<L: Lsa>(
    adj: &AdjacencyData<L>,
    dbd: &Dbd<L::Header>,
) -> Vec<Action<L>> {
    if dbd.init {
        return vec![Action::NeighborEvent(Event::SeqNumberMismatch)];
    }
    if !adj.is_master && dbd.master && dbd.dd_sequence_number == adj.dd_sequence_number {
        return adj
            .last_dbd_sent
            .clone()
            .map(Action::SendDbd)
            .into_iter()
            .collect();
    }
    Vec::new()
}

fn on_dbd_in_exstart<L: Lsa>(
    adj: &mut AdjacencyData<L>,
    p: &Params,
    dbd: &Dbd<L::Header>,
    local_lsdb_headers: &[L::Header],
    in_scope: &impl Fn(&L::Header) -> bool,
    is_opaque: &impl Fn(&L::Header) -> bool,
) -> Vec<Action<L>> {
    let is_negotiation_attempt = dbd.init && dbd.more && dbd.master;

    match dbd.router_id.cmp(&p.local_router_id) {
        Ordering::Greater => {
            // Neighbor has the higher router-id: it is master, we are
            // slave. Accept either its genuine negotiation attempt
            // (I=1,M=1,MS=1) or its poll (I=0,MS=1, `more` either way) as
            // the trigger. The two sides' Hello-driven ExStart entry isn't
            // synchronized: if the master sent its attempt before we reached
            // 2-Way with it, `handle_dbd` had no adjacency to receive it into
            // and dropped it (and every retransmitted copy, since the master
            // only ever resends its latest packet). The only packet we ever
            // get is then its reply to our own late attempt; waiting for the
            // original would wait forever (found by the `ospf-dr` e2e
            // scenario: a third router joining a converged DR/BDR pair).
            let is_master_reply = !dbd.init && dbd.master;
            if !is_negotiation_attempt && !is_master_reply {
                return Vec::new();
            }
            adj.is_master = false;
            seed_summary(adj, p, local_lsdb_headers, in_scope, is_opaque);
            // Real content always starts with *our* reply (RFC 2328 §10.6) —
            // correct whether `dbd` is the bare attempt (no headers) or the
            // master's poll arriving first.
            let (reply, done) = slave_process_poll(adj, p, dbd, local_lsdb_headers);
            let mut actions = vec![
                Action::SendDbd(reply),
                Action::NeighborEvent(Event::NegotiationDone),
            ];
            if done {
                actions.push(Action::NeighborEvent(Event::ExchangeDone {
                    more_to_load: !adj.request_list.is_empty(),
                }));
            }
            actions
        }
        Ordering::Less => {
            // We have the higher router-id: we are master. Accept either the
            // neighbor's negotiation attempt or its reply (MS bit clear) —
            // RFC 2328 §10.6 allows either, and the reply matters for the
            // same unsynchronized-ExStart reason as above: the neighbor,
            // already past ExStart, never resends its attempt.
            if !is_negotiation_attempt && dbd.master {
                return Vec::new();
            }
            adj.is_master = true;
            seed_summary(adj, p, local_lsdb_headers, in_scope, is_opaque);
            if is_negotiation_attempt {
                // The bare handshake only. RFC 2328 §10.8: the master's own
                // content only starts once the slave's real reply arrives;
                // sending our first chunk now would race the slave's
                // identically-numbered reply instead of following it. Our
                // negotiation packet keeps being retransmitted
                // (`last_dbd_sent`) until superseded.
                return vec![Action::NeighborEvent(Event::NegotiationDone)];
            }
            // `dbd` is the neighbor's reply, arriving before any bare
            // attempt: process it like a normal in-`Exchange` reply.
            let (maybe_poll, done) = master_process_reply(adj, p, dbd, local_lsdb_headers);
            let mut actions = Vec::new();
            if let Some(poll) = maybe_poll {
                actions.push(Action::SendDbd(poll));
            }
            actions.push(Action::NeighborEvent(Event::NegotiationDone));
            if done {
                actions.push(Action::NeighborEvent(Event::ExchangeDone {
                    more_to_load: !adj.request_list.is_empty(),
                }));
            }
            actions
        }
        // Equal router-ids can't happen on a real network (every router-id
        // is required to be unique) — nothing sensible to negotiate.
        Ordering::Equal => Vec::new(),
    }
}

/// Records whether the neighbor is opaque-capable and seeds the summary list
/// with every in-scope header — without opaque LSAs for a neighbor that
/// isn't (RFC 5250 §3).
fn seed_summary<L: Lsa>(
    adj: &mut AdjacencyData<L>,
    p: &Params,
    local_lsdb_headers: &[L::Header],
    in_scope: &impl Fn(&L::Header) -> bool,
    is_opaque: &impl Fn(&L::Header) -> bool,
) {
    adj.opaque_capable = p.peer_opaque_capable;
    adj.summary_remaining = local_lsdb_headers
        .iter()
        .filter(|h| (adj.opaque_capable || !is_opaque(h)) && in_scope(h))
        .copied()
        .collect();
}

/// The slave's side of one round: adopt the sender's sequence number,
/// extend the request list from its chunk, and reply with our own next
/// chunk. Shared by `on_dbd_in_exstart` (the first round, where the sequence
/// number is adopted unconditionally — the master is authoritative) and
/// `on_dbd_in_exchange` (later rounds, already validated). Returns the reply
/// plus whether both sides are now out of data (§10.8's termination test).
fn slave_process_poll<L: Lsa>(
    adj: &mut AdjacencyData<L>,
    p: &Params,
    dbd: &Dbd<L::Header>,
    local_lsdb_headers: &[L::Header],
) -> (Dbd<L::Header>, bool) {
    adj.dd_sequence_number = dbd.dd_sequence_number;
    adj.request_list
        .extend(compute_request_list(&dbd.lsa_headers, local_lsdb_headers));
    let (chunk, more) = pop_chunk(&mut adj.summary_remaining, p.max_headers);
    let reply = Dbd {
        router_id: p.local_router_id,
        area_id: dbd.area_id,
        interface_mtu: p.mtu,
        options: p.dbd_options,
        init: false,
        more,
        master: false,
        dd_sequence_number: adj.dd_sequence_number,
        lsa_headers: chunk,
    };
    let done = !dbd.more && !more;
    (reply, done)
}

/// The master's side of one round: extend the request list from the
/// slave's reply, then — unless both sides are now out of data — advance
/// the sequence number and pop our own next chunk to poll with (an empty
/// chunk still polls, to let the slave send its next one). Returns the next
/// poll (`None` once done) plus whether both sides are now done.
fn master_process_reply<L: Lsa>(
    adj: &mut AdjacencyData<L>,
    p: &Params,
    dbd: &Dbd<L::Header>,
    local_lsdb_headers: &[L::Header],
) -> (Option<Dbd<L::Header>>, bool) {
    adj.request_list
        .extend(compute_request_list(&dbd.lsa_headers, local_lsdb_headers));
    if !dbd.more && adj.summary_remaining.is_empty() {
        return (None, true);
    }
    adj.dd_sequence_number = adj.dd_sequence_number.wrapping_add(1);
    let (chunk, more) = pop_chunk(&mut adj.summary_remaining, p.max_headers);
    let poll = Dbd {
        router_id: p.local_router_id,
        area_id: dbd.area_id,
        interface_mtu: p.mtu,
        options: p.dbd_options,
        init: false,
        more,
        master: true,
        dd_sequence_number: adj.dd_sequence_number,
        lsa_headers: chunk,
    };
    (Some(poll), false)
}

fn on_dbd_in_exchange<L: Lsa>(
    adj: &mut AdjacencyData<L>,
    p: &Params,
    dbd: &Dbd<L::Header>,
    local_lsdb_headers: &[L::Header],
) -> Vec<Action<L>> {
    // A negotiation-shaped packet (I=1,M=1,MS=1) here means the peer is
    // still retransmitting its very first message; the two sides'
    // retransmit timers race independently, so this is an expected,
    // harmless duplicate, not a restart (a genuine restart is caught via
    // Hello). Treating it as `SeqNumberMismatch` would make both sides
    // re-pick sequence numbers in lockstep forever.
    if dbd.init && dbd.more && dbd.master {
        return Vec::new();
    }

    if adj.is_master {
        // Expect the slave's reply to our last poll: same sequence number,
        // MS bit clear.
        if dbd.dd_sequence_number != adj.dd_sequence_number || dbd.master {
            return vec![Action::NeighborEvent(Event::SeqNumberMismatch)];
        }
        let (maybe_poll, done) = master_process_reply(adj, p, dbd, local_lsdb_headers);
        let mut actions = Vec::new();
        if let Some(poll) = maybe_poll {
            actions.push(Action::SendDbd(poll));
        }
        if done {
            actions.push(Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: !adj.request_list.is_empty(),
            }));
        }
        actions
    } else {
        // Expect the master's next poll: MS bit set, sequence number one
        // past the last one we accepted.
        if !dbd.master || dbd.dd_sequence_number != adj.dd_sequence_number.wrapping_add(1) {
            return vec![Action::NeighborEvent(Event::SeqNumberMismatch)];
        }
        let (reply, done) = slave_process_poll(adj, p, dbd, local_lsdb_headers);
        let mut actions = vec![Action::SendDbd(reply)];
        if done {
            actions.push(Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: !adj.request_list.is_empty(),
            }));
        }
        actions
    }
}

/// RFC 2328 §13.5: takes every queued ack for this neighbor as one `LSAck`
/// to send now — `None` if nothing is pending. Called by `link.rs` on every
/// `RXMT_INTERVAL` sweep.
pub fn take_pending_acks<L: Lsa>(adj: &mut AdjacencyData<L>) -> Option<Action<L>> {
    if adj.pending_acks.is_empty() {
        return None;
    }
    adj.pending_acks_since = None;
    Some(Action::SendLsAck(std::mem::take(&mut adj.pending_acks)))
}

/// RFC 2328 §13.5 on a broadcast link: drains every neighbor's queued acks
/// into one set for a single multicast `LSAck`, deduplicated by exact header
/// (the same LSA instance heard from two neighbors is acked once), plus the
/// oldest `pending_acks_since` among the drained queues. Empty set when
/// nothing is pending.
// ponytail: `contains` dedupe is O(n^2); the ack batch per 5s tick is a handful.
pub fn take_all_pending_acks<'a, L: Lsa + 'a>(
    adjs: impl Iterator<Item = &'a mut AdjacencyData<L>>,
) -> (Vec<L::Header>, Option<Instant>) {
    let (mut all, mut since): (Vec<L::Header>, Option<Instant>) = (Vec::new(), None);
    for adj in adjs {
        if adj.pending_acks.is_empty() {
            continue;
        }
        since = match (since, adj.pending_acks_since.take()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        for h in adj.pending_acks.drain(..) {
            if !all.contains(&h) {
                all.push(h);
            }
        }
    }
    (all, since)
}

/// Handles one received `LSAck`'s headers: RFC 2328 §10.9 — stop
/// retransmitting whatever it acknowledges.
pub fn on_lsack_received<L: Lsa>(adj: &mut AdjacencyData<L>, acked: &[L::Header]) {
    for header in acked {
        // §13.7: only an ack of the very same instance counts; one for an
        // older or newer instance leaves the entry to be retransmitted.
        if adj
            .retransmission_list
            .get(&header.key())
            .is_some_and(|l| l.header().is_newer(header) == std::cmp::Ordering::Equal)
        {
            adj.retransmission_list.remove(&header.key());
        }
    }
}

/// Which store a received LSA belongs in (`on_lsu_received`'s `scope`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Area,
    /// v2 type 9 (RFC 5250), v3 Link-LSA (RFC 5340 §4.5.1): this link's
    /// own store, so no other link floods it.
    LinkLocal,
    /// v3 only (RFC 5340 §4.5.1): the router's one AS-scope store.
    As,
}

/// The stores one link's LSU lands in. v2 has no AS-scope store (`None`).
pub struct Stores<'a, L: Lsa> {
    pub area: &'a mut Lsdb<L>,
    pub link_local: &'a mut Lsdb<L>,
    pub as_scope: Option<&'a mut Lsdb<L>>,
}

/// Handles one received LSR: looks every requested key up in `stores`, in
/// order (a key lives in only one). A key held nowhere is RFC 2328 §10.7's
/// `BadLSReq`: the databases have diverged, so negotiation restarts
/// (`SeqNumberMismatch`) rather than sending a partial answer. Otherwise
/// sends everything found as one LSU and keeps it on the retransmission list
/// until acked (`on_lsack_received`).
pub fn on_lsr_received<L: Lsa>(
    adj: &mut AdjacencyData<L>,
    stores: &[&Lsdb<L>],
    requests: &[Key<L>],
) -> Vec<Action<L>> {
    let mut found = Vec::with_capacity(requests.len());
    for key in requests {
        match stores.iter().find_map(|s| s.get(key)) {
            Some(l) => found.push(l),
            None => return vec![Action::NeighborEvent(Event::SeqNumberMismatch)],
        }
    }
    if found.is_empty() {
        return Vec::new();
    }
    for l in &found {
        adj.retransmission_list.insert(l.header().key(), l.clone());
    }
    vec![Action::SendLsu(found)]
}

/// Handles one received LSU (RFC 2328 §13): installs every carried LSA into
/// the store `scope` picks, clears now-satisfied requests, and queues an ack
/// for every LSA, newer or not (an ack for a stale instance still stops the
/// sender retransmitting it). Fires `LoadingDone` once the request list is
/// empty. Returns the actions plus the headers *actually*
/// installed/superseded, so the daemon logs nothing for the duplicates its
/// own periodic resend produces.
///
/// - `discard`: dropped, neither installed nor acked (§13 step 3; v2: out of
///   stub/NSSA scope, v3: S2/S1 reserved).
/// - `exempt_max_age`: skips §13 step 4 (v3 Grace-LSA: never held, and its
///   `MaxAge` copy is what ends a grace).
///
/// Acks are delayed (§13.5): queued on `adj.pending_acks` for the daemon's
/// `RXMT_INTERVAL` sweep (`take_pending_acks`), never returned as
/// `SendLsAck`. `ponytail:` the RFC's direct-ack cases key off "was this LSA
/// flooded back out", which periodic-resend flooding has no equivalent of,
/// so every ack is delayed.
pub fn on_lsu_received<L, FS, FD, FE>(
    adj: &mut AdjacencyData<L>,
    stores: &mut Stores<'_, L>,
    lsas: &[L],
    now: Instant,
    scope: FS,
    discard: FD,
    exempt_max_age: FE,
) -> (Vec<Action<L>>, Vec<L::Header>)
where
    L: Lsa,
    FS: Fn(&L::Header) -> Scope,
    FD: Fn(&L::Header) -> bool,
    FE: Fn(&L::Header) -> bool,
{
    let mut newly_installed = Vec::new();
    // Hash view of the request list: O(list + LSAs) per LSU, not O(LSAs x list).
    // Keys leave it as they're satisfied; one `retain` at the end keeps the Vec's order.
    let mut pending: std::collections::HashSet<Key<L>> = adj.request_list.iter().copied().collect();
    for l in lsas {
        let h = *l.header();
        if discard(&h) {
            continue;
        }
        let store = match scope(&h) {
            Scope::Area => &mut *stores.area,
            Scope::LinkLocal => &mut *stores.link_local,
            Scope::As => {
                // A caller bug (v2 never says `As`): drop unacked rather
                // than crash the daemon.
                debug_assert!(stores.as_scope.is_some(), "Scope::As without an AS store");
                let Some(s) = stores.as_scope.as_deref_mut() else {
                    continue;
                };
                s
            }
        };
        let key = h.key();
        // §13 step 4: a MaxAge instance of an LSA held nowhere here is acked
        // and discarded, unless this adjacency requested it. Without this,
        // two routers each holding a flushed copy for `MAX_AGE_HOLD_TICKS`
        // would reinstall each other's echo forever.
        if h.age() >= MAX_AGE
            && !exempt_max_age(&h)
            && store.get(&key).is_none()
            && !pending.contains(&key)
        {
            adj.pending_acks.push(h);
            continue;
        }
        match store.install_received(l.clone(), now) {
            // §13 step 5a (`MinLSArrival`): neither acked nor answering a
            // request; the sender's retransmission brings it back.
            InstallOutcome::TooSoon => continue,
            InstallOutcome::Rejected => {}
            InstallOutcome::Installed | InstallOutcome::Superseded => newly_installed.push(h),
        }
        adj.pending_acks.push(h);
        pending.remove(&key);
    }
    if pending.len() != adj.request_list.len() {
        adj.request_list.retain(|k| pending.contains(k));
    }
    let mut actions = Vec::new();
    if adj.request_list.is_empty() {
        actions.push(Action::NeighborEvent(Event::LoadingDone));
    }
    (actions, newly_installed)
}

/// RFC 2328 §10.8: request any LSA the neighbor's summary lists that this
/// router either doesn't have, or holds an older instance of.
fn compute_request_list<H: LsaHeader>(neighbor_headers: &[H], local_headers: &[H]) -> Vec<H::Key> {
    let local: std::collections::HashMap<H::Key, &H> =
        local_headers.iter().map(|h| (h.key(), h)).collect();
    neighbor_headers
        .iter()
        .filter(|nh| match local.get(&nh.key()) {
            None => true,
            Some(lh) => nh.is_newer(lh) == Ordering::Greater,
        })
        .map(LsaHeader::key)
        .collect()
}

#[cfg(test)]
mod tests;
