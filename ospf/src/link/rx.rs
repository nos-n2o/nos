//! Hello/DBD/LSR/LSU/LSAck receive handling, crypto sequence numbers and the DR/BDR election driver.
//! Moved verbatim out of `link.rs`.

use nos_ospf_common::ratelimit::{WarnLimiter, MAX_NEIGHBORS_PER_LINK};

use super::grace::{enter_lls_grace, in_grace, on_grace_lsa};
use super::originate::local_netmask;
use super::{
    debug, election, exchange, info, lsa, neighbor, packet, should_form_adjacency,
    start_negotiation, warn, AdjacencyData, Candidate, DbdPacket, Duration, HashMap, Instant,
    InterfaceState, Ipv4Addr, LinkAuthConfig, LinkConfig, LinkSocket, Lls, LsAckPacket, LsaBody,
    Lsdb, LsrPacket, LsuPacket, Mutex, NeighborInfo, NeighborState, NetworkType, OspfPacket,
    StatusHandle, SystemTime, UNIX_EPOCH,
};
use crate::lls;

/// `warn!` through the link's `WarnLimiter` (#394): a peer sending bad Hellos
/// must not turn them into unbounded log lines. A line that follows dropped
/// ones is preceded by a count of them.
macro_rules! warn_limited {
    ($limiter:expr, $($arg:tt)+) => {
        if $limiter.allow(Instant::now().into_std()) {
            let suppressed = $limiter.take_suppressed();
            if suppressed > 0 {
                warn!(suppressed, "ospf hello warnings were rate limited");
            }
            warn!($($arg)+);
        }
    };
}

/// Wall-clock unix-seconds floor for the outgoing crypto sequence number —
/// mirrors `initial_dd_sequence_number`'s use of `SystemTime`, but must
/// specifically never regress (RFC 2328 D.4.3's anti-replay guarantee),
/// which subsec-nanos-based randomness doesn't provide. Only used for the
/// classic `AuType` 2; RFC 7474 links use the persisted boot count instead.
pub(super) fn crypto_seq_floor() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(u64::from(u32::MAX)))
}

/// The starting outgoing sequence: RFC 7474's `boot_count << 32` (counter
/// 0), or the classic wall-clock floor.
pub(super) fn initial_crypto_seq(auth: &LinkAuthConfig, boot_count: u32) -> u64 {
    if auth.is_extended() {
        u64::from(boot_count) << 32
    } else {
        crypto_seq_floor()
    }
}

/// Bumps `counter` to the next value to sign an outgoing packet with. RFC
/// 7474: one past the previous value — the low 32 bits carry into the boot
/// count on wrap, keeping the 64-bit value strictly increasing (u64 overflow
/// is unreachable). Classic: whichever is larger of one past the previous
/// value or the wall-clock floor, non-decreasing even across a link restart.
pub(super) fn next_crypto_seq(counter: &mut u64, auth: &LinkAuthConfig) -> u64 {
    *counter = if auth.is_extended() {
        *counter + 1
    } else {
        counter.saturating_add(1).max(crypto_seq_floor())
    };
    *counter
}

/// Bytes of one packet's budget on this link left for entries: the effective
/// MTU minus IP (20), OSPF header (24), the crypto digest and `extra` (LSU's
/// 4-byte count; 0 for LSR/LSAck).
fn split_budget(cfg: &LinkConfig, extra: usize) -> usize {
    usize::from(cfg.mtu).saturating_sub(20 + 24 + cfg.auth.digest_len() + extra)
}

/// Splits `entries` into MTU-sized chunks and encodes each as its own signed
/// packet (fresh crypto sequence per chunk). Empty input yields no packets.
/// Logs `ospf <kind> split packets=<n>` when more than one results.
pub(super) fn encode_split<T>(
    cfg: &LinkConfig,
    next_seq: &mut u64,
    kind: &'static str,
    entries: &[T],
    extra: usize,
    size_of: impl Fn(&T) -> usize,
    encode: impl Fn(&[T], &packet::OutgoingAuth<'_>) -> Vec<u8>,
) -> Vec<Vec<u8>> {
    let chunks =
        nos_ospf_common::exchange::chunk_by_budget(entries, split_budget(cfg, extra), size_of);
    if chunks.len() > 1 {
        // LSU is the headline split (the e2e anchor); LSR/LSAck are noise.
        if kind == "lsu" {
            info!(link = %cfg.attach_point, packets = chunks.len(), "ospf lsu split");
        } else {
            debug!(link = %cfg.attach_point, packets = chunks.len(), "ospf {kind} split");
        }
    }
    chunks
        .into_iter()
        .map(|chunk| {
            let auth = cfg
                .auth
                .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
            encode(chunk, &auth)
        })
        .collect()
}

pub(super) fn split_lsr(
    cfg: &LinkConfig,
    next_seq: &mut u64,
    router_id: Ipv4Addr,
    requests: &[crate::lsa::LsaKey],
) -> Vec<Vec<u8>> {
    // RFC 2328 §A.3.4: type, id and advertising router, 4 bytes each.
    encode_split(
        cfg,
        next_seq,
        "lsr",
        requests,
        0,
        |_| 12,
        |c, auth| {
            let requests = c.to_vec();
            packet::encode_lsr(
                &LsrPacket {
                    router_id,
                    area_id: cfg.area_id,
                    requests,
                },
                auth,
            )
        },
    )
}

pub(super) fn split_lsu(
    cfg: &LinkConfig,
    next_seq: &mut u64,
    router_id: Ipv4Addr,
    lsas: &[crate::lsa::Lsa],
) -> Vec<Vec<u8>> {
    encode_split(
        cfg,
        next_seq,
        "lsu",
        lsas,
        4,
        |l| usize::from(l.header.length),
        |c, auth| {
            let lsas = c.to_vec();
            packet::encode_lsu(
                &LsuPacket {
                    discarded: 0,
                    last_error: None,
                    router_id,
                    area_id: cfg.area_id,
                    lsas,
                },
                auth,
            )
        },
    )
}

pub(super) fn split_lsack(
    cfg: &LinkConfig,
    next_seq: &mut u64,
    router_id: Ipv4Addr,
    headers: &[crate::lsa::LsaHeader],
) -> Vec<Vec<u8>> {
    encode_split(
        cfg,
        next_seq,
        "lsack",
        headers,
        0,
        |_| 20,
        |c, auth| {
            let lsa_headers = c.to_vec();
            packet::encode_lsack(
                &LsAckPacket {
                    router_id,
                    area_id: cfg.area_id,
                    lsa_headers,
                },
                auth,
            )
        },
    )
}

/// RFC 2328 D.4.3's anti-replay check: `true` if this packet should be
/// dispatched, `false` if it must be silently dropped instead. Always `true`
/// when `cfg.auth` isn't `Crypto` (nothing to check) or this is the first
/// packet ever seen from this neighbor (no entry yet — `handle_hello`
/// creates it). Kept in `link.rs`, not `packet.rs`: this is stateful
/// per-neighbor bookkeeping, and `link.rs` already owns all such state (see
/// `packet::crypto_sequence`'s doc comment).
pub(super) fn accept_crypto_sequence(
    cfg: &LinkConfig,
    status: &StatusHandle,
    data: &[u8],
    pkt: &OspfPacket,
) -> bool {
    if !matches!(cfg.auth, LinkAuthConfig::Crypto { .. }) {
        return true;
    }
    let Some(seq) = packet::crypto_sequence(data) else {
        return true;
    };
    let router_id = packet::router_id(pkt);
    let slot = if cfg.auth.is_extended() { data[1] } else { 0 };
    let last_seq = status
        .borrow()
        .neighbors
        .get(&router_id)
        .and_then(|n| n.last_crypto_seq.get(&slot).copied());
    // RFC 2328 D.4.3 drops only a number *less than* the stored one (equal
    // is accepted: two packets sent in one tick may share it); RFC 7474 §3
    // requires strictly greater per packet type. Our sender stays strictly
    // increasing either way.
    let replay = |last: u64| {
        if cfg.auth.is_extended() {
            seq <= last
        } else {
            seq < last
        }
    };
    if last_seq.is_some_and(replay) {
        return false;
    }
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&router_id) {
            n.last_crypto_seq.insert(slot, seq);
        }
    });
    true
}

/// RFC 2328 A.3.2: the DR/BDR Hello field is the elected router's interface
/// address on this segment; internal state is router-ID keyed.
pub(super) fn dr_wire_addr(
    elected: Option<Ipv4Addr>,
    local_router_id: Ipv4Addr,
    local_addr: Ipv4Addr,
    neighbors: &HashMap<Ipv4Addr, NeighborInfo>,
) -> Ipv4Addr {
    match elected {
        Some(id) if id == local_router_id => local_addr,
        Some(id) => neighbors
            .get(&id)
            .map_or(Ipv4Addr::UNSPECIFIED, |n| n.address),
        None => Ipv4Addr::UNSPECIFIED,
    }
}

/// Inverse of `dr_wire_addr`: a received DR/BDR address back to a router ID
/// (`source`/`sender_id` is the Hello's sender), `UNSPECIFIED` if unknown.
pub(super) fn resolve_declared(
    addr: Ipv4Addr,
    source: Ipv4Addr,
    sender_id: Ipv4Addr,
    local_router_id: Ipv4Addr,
    local_addr: Ipv4Addr,
    neighbors: &HashMap<Ipv4Addr, NeighborInfo>,
) -> Ipv4Addr {
    if addr.is_unspecified() {
        Ipv4Addr::UNSPECIFIED
    } else if addr == source {
        sender_id
    } else if addr == local_addr {
        local_router_id
    } else {
        neighbors
            .iter()
            .find(|(_, n)| n.address == addr)
            .map_or(Ipv4Addr::UNSPECIFIED, |(id, _)| *id)
    }
}

pub(super) fn send_hello(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
) {
    send_hello_eof(socket, cfg, local_router_id, status, next_seq, 0);
}

/// `send_hello` with an RFC 5613 EOF word: `lls::EOF_RS` for the last Hello of
/// a planned restart (RFC 4812).
pub(super) fn send_hello_eof(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
    eof: u32,
) {
    let current = status.borrow();
    let neighbors: Vec<Ipv4Addr> = current
        .neighbors
        .iter()
        .filter(|(_, info)| info.state != NeighborState::Down)
        .map(|(id, _)| *id)
        .collect();
    // Designated/backup-designated router are only meaningful once an
    // election has run — always unspecified on a point-to-point link, since
    // no election ever runs there (RFC 2328 §10.5).
    let (designated_router, backup_designated_router) = match cfg.network_type {
        NetworkType::PointToPoint | NetworkType::PointToMultipoint => {
            (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
        }
        // RFC 2328 A.3.2: the fields carry interface addresses, not router IDs.
        NetworkType::Broadcast | NetworkType::Hybrid => (
            dr_wire_addr(
                current.dr,
                local_router_id,
                cfg.local_addr,
                &current.neighbors,
            ),
            dr_wire_addr(
                current.bdr,
                local_router_id,
                cfg.local_addr,
                &current.neighbors,
            ),
        ),
    };
    drop(current);

    let pkt = packet::HelloPacket {
        lls: cfg.lls_active().then_some(Lls {
            eof: Some(eof | own_lr(cfg)),
        }),
        router_id: local_router_id,
        area_id: cfg.area_id,
        network_mask: local_netmask(cfg),
        hello_interval: cfg.hello_interval,
        options: hello_options(cfg),
        dead_interval: u32::from(cfg.dead_interval),
        router_priority: cfg.priority,
        designated_router,
        backup_designated_router,
        neighbors,
    };
    let auth = cfg
        .auth
        .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
    let encoded = packet::encode_hello(&pkt, &auth);
    // RFC 2328 §9.5: a virtual link's Hellos are unicast to its endpoint.
    let sent = match cfg.virtual_link {
        Some(v) => socket.send_unicast(v.neighbor, &encoded),
        None => socket.send_multicast(&encoded),
    };
    if let Err(e) = sent {
        warn!(link = %cfg.attach_point, error = %e, "failed to send ospf hello");
    }
}

/// The Hello options for a link's area: E outside a stub area/NSSA (RFC 2328
/// §3.6), N in an NSSA (RFC 3101 §2.1).
/// Encodes a DBD built by `exchange` (which does not know the link config),
/// adding the RFC 5613 LLS block when `cfg.lls_active()`.
///
/// RFC 4811 §2.1: every DBD of an LR-capable router carries the LR bit.
pub(super) fn encode_dbd_for(
    cfg: &LinkConfig,
    dbd: &DbdPacket,
    auth: &packet::OutgoingAuth<'_>,
) -> Vec<u8> {
    if cfg.lls_active() {
        let mut d = dbd.clone();
        d.lls = Some(Lls {
            eof: Some(own_lr(cfg)),
        });
        packet::encode_dbd(&d, auth)
    } else {
        packet::encode_dbd(dbd, auth)
    }
}

/// The LR bit we advertise (RFC 4811 §2.1): on every real link with LLS.
fn own_lr(cfg: &LinkConfig) -> u32 {
    if cfg.virtual_link.is_some() {
        0
    } else {
        lls::EOF_LR
    }
}

/// The peer's EOF word, 0 when LLS is inactive on this link, the peer sent
/// none, or the link is virtual (RFC 4811/4812 act on real links only).
fn peer_eof(cfg: &LinkConfig, lls: Option<&Lls>) -> u32 {
    if cfg.virtual_link.is_some() || !cfg.lls_active() {
        return 0;
    }
    lls.and_then(|l| l.eof).unwrap_or(0)
}

/// Records the peer's LLS block on `info` (dropped when LLS is not active),
/// logging once per change.
fn note_lls(cfg: &LinkConfig, id: Ipv4Addr, info: &mut NeighborInfo, lls: Option<&Lls>) {
    let new = if cfg.lls_active() { lls.cloned() } else { None };
    if info.lls == new {
        return;
    }
    if let Some(l) = &new {
        info!(
            link = %cfg.attach_point, neighbor = %id, eof = l.eof.unwrap_or(0),
            "ospf lls received"
        );
    }
    info.lls = new;
}

pub(super) fn hello_options(cfg: &LinkConfig) -> u8 {
    match (cfg.stub, cfg.nssa) {
        (_, true) => packet::OPTION_N,
        (true, false) => 0,
        (false, false) => packet::OPTION_E,
    }
}

/// Returns whether this Hello caused a broadcast link to leave `Waiting`
/// early (RFC 2328's "`BackupSeen`" shortcut — a neighbor already declaring
/// itself DR means the election result is already knowable).
#[allow(clippy::too_many_arguments)]
#[allow(
    clippy::too_many_lines,
    reason = "one Hello validation + neighbor update sequence"
)]
pub(super) fn handle_hello(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    source: Ipv4Addr,
    hello: &packet::HelloPacket,
    waiting: bool,
    limiter: &mut WarnLimiter,
) -> bool {
    // RFC 2328 §10.5's packet-validity check precedes any neighbor event —
    // a mismatched area/timer/mask/E-bit is logged and dropped, not fed into
    // the FSM (a peer with different timers would otherwise be accepted and
    // the adjacency would flap at whichever dead interval is shorter).
    if hello.area_id != cfg.area_id {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, area = %hello.area_id, expected = %cfg.area_id,
            "dropping ospf hello with mismatched area"
        );
        return false;
    }
    if hello.hello_interval != cfg.hello_interval {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, hello_interval = hello.hello_interval, expected = cfg.hello_interval,
            "dropping ospf hello with mismatched hello-interval"
        );
        return false;
    }
    if hello.dead_interval != u32::from(cfg.dead_interval) {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, dead_interval = hello.dead_interval, expected = cfg.dead_interval,
            "dropping ospf hello with mismatched dead-interval"
        );
        return false;
    }
    // NetworkMask is meaningless on point-to-point, point-to-multipoint and
    // virtual links (RFC 2328 §10.5) — `Broadcast` is the only network type
    // it's checked on.
    if cfg.network_type == NetworkType::Broadcast {
        let expected_mask = local_netmask(cfg);
        if hello.network_mask != expected_mask {
            warn_limited!(
            limiter,
                link = %cfg.attach_point, network_mask = %hello.network_mask, expected = %expected_mask,
                "dropping ospf hello with mismatched network mask"
            );
            return false;
        }
    }
    // RFC 2328 §10.5: the E-bit is clear exactly in a stub area, so both
    // ends must agree on whether the area is one.
    if (hello.options & packet::OPTION_E != 0) == cfg.stub {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, neighbor = %hello.router_id,
            "dropping ospf hello with mismatched e-bit"
        );
        return false;
    }
    // RFC 3101 §2.1: the N-bit is set exactly in an NSSA.
    if (hello.options & packet::OPTION_N != 0) != cfg.nssa {
        warn_limited!(
            limiter,
            link = %cfg.attach_point, neighbor = %hello.router_id,
            "dropping ospf hello with mismatched n-bit"
        );
        return false;
    }

    // #956: a point-to-point / multipoint peer back under a new router ID from
    // the same address supersedes its old entry at once. Grace entries are
    // kept (RFC 3623); broadcast never evicts.
    if cfg.network_type != NetworkType::Broadcast {
        evict_same_address(cfg, status, source, hello.router_id);
    }

    // A segment peer cycling router-ids must not grow the table without bound
    // (#394); known neighbors keep refreshing at the cap.
    {
        let known = status.borrow().neighbors.contains_key(&hello.router_id);
        if !known && status.borrow().neighbors.len() >= MAX_NEIGHBORS_PER_LINK {
            warn_limited!(
                limiter,
                link = %cfg.attach_point, neighbor = %hello.router_id,
                "ospf neighbor limit reached, dropping hello"
            );
            return false;
        }
    }

    let saw_self = hello.neighbors.contains(&local_router_id);
    // RFC 4812: a Full neighbor announcing a restart is helped like an
    // RFC 3623 one, before its (now one-way) Hello is evaluated below.
    if peer_eof(cfg, hello.lls.as_ref()) & lls::EOF_RS != 0 {
        enter_lls_grace(cfg, status, hello.router_id);
    }
    let old_state = status
        .borrow()
        .neighbors
        .get(&hello.router_id)
        .map_or(NeighborState::Down, |n| n.state);
    // RFC 3623 §3.1: a restarting neighbor's fresh Hellos don't list us yet —
    // that must not tear the adjacency down while we're helping it.
    let new_state = if !saw_self && in_grace(status, hello.router_id) {
        old_state
    } else {
        neighbor::step(old_state, neighbor::Event::HelloReceived { saw_self })
    };
    if old_state == NeighborState::Down && new_state == NeighborState::Init {
        info!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospf neighbor state changed to init");
    }
    if old_state != NeighborState::TwoWay && new_state == NeighborState::TwoWay {
        info!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospf neighbor reached two-way");
    }
    if old_state != NeighborState::Init
        && new_state == NeighborState::Init
        && old_state != NeighborState::Down
    {
        warn!(link = %cfg.attach_point, neighbor = %hello.router_id, "ospf neighbor adjacency torn down, back to init");
    }
    let (dr_id, bdr_id) = {
        let current = status.borrow();
        let resolve = |a| {
            resolve_declared(
                a,
                source,
                hello.router_id,
                local_router_id,
                cfg.local_addr,
                &current.neighbors,
            )
        };
        (
            resolve(hello.designated_router),
            resolve(hello.backup_designated_router),
        )
    };
    status.send_modify(|s| {
        let entry = s
            .neighbors
            .entry(hello.router_id)
            .or_insert_with(|| NeighborInfo {
                state: NeighborState::Down,
                lls: None,
                priority: 0,
                declared_dr: Ipv4Addr::UNSPECIFIED,
                declared_bdr: Ipv4Addr::UNSPECIFIED,
                last_hello_received: Instant::now(),
                last_heard: Instant::now(),
                address: source,
                adjacency: None,
                last_crypto_seq: HashMap::new(),
                grace_deadline: None,
                oob_deadline: None,
                full_since: None,
            });
        note_lls(cfg, hello.router_id, entry, hello.lls.as_ref());
        entry.set_state(new_state);
        entry.priority = hello.router_priority;
        entry.declared_dr = dr_id;
        entry.declared_bdr = bdr_id;
        entry.last_hello_received = Instant::now();
        entry.last_heard = Instant::now();
        entry.address = source;
        if matches!(new_state, NeighborState::Down | NeighborState::Init) {
            entry.adjacency = None;
        }
    });

    match cfg.network_type {
        NetworkType::Broadcast | NetworkType::Hybrid
            if waiting
                && (hello.designated_router == source
                    || hello.backup_designated_router == source) =>
        {
            run_election(cfg, local_router_id, status);
            true
        }
        NetworkType::Broadcast | NetworkType::Hybrid if !waiting => {
            run_election(cfg, local_router_id, status);
            false
        }
        // `last_heard` was refreshed above; the sweep expires it.
        NetworkType::Broadcast
        | NetworkType::Hybrid
        | NetworkType::PointToPoint
        | NetworkType::PointToMultipoint => false,
    }
}

/// Scans every `TwoWay` neighbor with no adjacency yet and, for each one
/// now eligible (`should_form_adjacency`), starts RFC 2328 §10.6
/// negotiation: sends the initial negotiation DBD and moves it to
/// `ExStart`. Called after anything that could change eligibility — a
/// fresh `TwoWay`, or a completed election.
pub(super) fn advance_adjacencies(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
) {
    let snapshot = status.borrow().clone();
    let eligible: Vec<Ipv4Addr> = snapshot
        .neighbors
        .iter()
        .filter(|(id, info)| {
            info.state == NeighborState::TwoWay
                && info.adjacency.is_none()
                && should_form_adjacency(snapshot.interface_state, **id, snapshot.dr, snapshot.bdr)
        })
        .map(|(id, _)| *id)
        .collect();
    drop(snapshot);

    for neighbor_id in eligible {
        let Some(neighbor_addr) = status
            .borrow()
            .neighbors
            .get(&neighbor_id)
            .map(|n| n.address)
        else {
            continue;
        };
        let (adj, dbd) = start_negotiation(cfg, local_router_id);
        let auth = cfg
            .auth
            .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
        if let Err(e) = socket.send_unicast(neighbor_addr, &encode_dbd_for(cfg, &dbd, &auth)) {
            warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf dbd");
        }
        let new_state = neighbor::step(NeighborState::TwoWay, neighbor::Event::AdjacencyEligible);
        info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached exstart");
        status.send_modify(|s| {
            if let Some(info) = s.neighbors.get_mut(&neighbor_id) {
                info.set_state(new_state);
                info.adjacency = Some(adj);
            }
        });
    }
}

/// Puts the neighbor at `ExStart` on a fresh out-of-band adjacency, bounded by
/// the dead interval (RFC 4811 §2.4).
pub(super) fn mark_oob_started(
    cfg: &LinkConfig,
    status: &StatusHandle,
    neighbor_id: Ipv4Addr,
    adj: &AdjacencyData,
) {
    let deadline = Instant::now() + Duration::from_secs(u64::from(cfg.dead_interval));
    info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf lls resync started");
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&neighbor_id) {
            n.set_state(NeighborState::ExStart);
            n.adjacency = Some(adj.clone());
            n.oob_deadline = Some(deadline);
        }
    });
}

/// RFC 4811 §2.6: starts an out-of-band resync with every `Full` neighbor
/// that announced LR (`oob-resync`): our DBDs carry the R bit from now on.
pub(super) fn start_oob_resync(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
) {
    let targets: Vec<(Ipv4Addr, Ipv4Addr)> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, n)| {
            n.state == NeighborState::Full && peer_eof(cfg, n.lls.as_ref()) & lls::EOF_LR != 0
        })
        .map(|(id, n)| (*id, n.address))
        .collect();
    for (id, addr) in targets {
        let (mut adj, mut dbd) = start_negotiation(cfg, local_router_id);
        adj.oob_resync = true;
        dbd.resync = true;
        adj.last_dbd_sent = Some(dbd.clone());
        mark_oob_started(cfg, status, id, &adj);
        let auth = cfg
            .auth
            .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
        if let Err(e) = socket.send_unicast(addr, &encode_dbd_for(cfg, &dbd, &auth)) {
            warn!(link = %cfg.attach_point, neighbor = %id, error = %e, "failed to send ospf dbd");
        }
    }
}

/// RFC 4811 §2.4: an out-of-band resync that has not reached `Full` within
/// the dead interval falls back to the legacy resync (`OOBResync` cleared,
/// negotiation restarted at `ExStart`).
pub(super) fn expire_oob_resync(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
) {
    let now = Instant::now();
    let expired: Vec<(Ipv4Addr, Ipv4Addr)> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, n)| n.oob_deadline.is_some_and(|d| d <= now))
        .map(|(id, n)| (*id, n.address))
        .collect();
    for (id, addr) in expired {
        warn!(link = %cfg.attach_point, neighbor = %id, "ospf lls resync timed out, falling back to legacy resync");
        let (adj, dbd) = start_negotiation(cfg, local_router_id);
        let auth = cfg
            .auth
            .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
        if let Err(e) = socket.send_unicast(addr, &encode_dbd_for(cfg, &dbd, &auth)) {
            warn!(link = %cfg.attach_point, neighbor = %id, error = %e, "failed to send ospf dbd");
        }
        status.send_modify(|s| {
            if let Some(n) = s.neighbors.get_mut(&id) {
                n.set_state(NeighborState::ExStart);
                n.adjacency = Some(adj);
                n.oob_deadline = None;
            }
        });
    }
}

/// Handles one received DBD packet against the sending neighbor's current
/// adjacency data, returning the actions `execute_actions` still needs to
/// carry out (sends). Returns `None` if the neighbor is unknown or has no
/// adjacency in progress.
pub(super) async fn handle_dbd(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    lsdb: &Mutex<Lsdb>,
    link_local_lsdb: &Mutex<Lsdb>,
    dbd: &DbdPacket,
    dbd_max_headers: usize,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&dbd.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };
    if cfg.lls_active() {
        status.send_if_modified(|s| {
            s.neighbors.get_mut(&dbd.router_id).is_some_and(|n| {
                let before = n.lls.clone();
                note_lls(cfg, dbd.router_id, n, dbd.lls.as_ref());
                n.lls != before
            })
        });
    }

    // RFC 2328 §10.6: only in ExStart/Exchange; the neighbor stays in ExStart.
    if matches!(old_state, NeighborState::ExStart | NeighborState::Exchange)
        && !exchange::mtu_acceptable(dbd.interface_mtu, cfg.mtu, cfg.mtu_ignore)
    {
        warn!(
            neighbor = %dbd.router_id, local_mtu = cfg.mtu, neighbor_mtu = dbd.interface_mtu, link = %cfg.attach_point,
            "ospf dbd rejected, neighbor interface mtu exceeds ours"
        );
        return None;
    }

    // A MaxAge entry is never offered in the summary: it may be evicted
    // (`Lsdb::MAX_AGE_HOLD_TICKS`) before the neighbor's LSR for it lands,
    // which would read as `BadLSReq` and restart the adjacency for nothing.
    // The flood sink still carries the flush to an already-`Full` neighbor.
    let mut local_lsdb_headers = lsdb.lock().await.headers();
    local_lsdb_headers.extend(link_local_lsdb.lock().await.headers());
    local_lsdb_headers.retain(|h| h.age < lsa::MAX_AGE);
    let params = exchange::Params {
        local_router_id,
        max_headers: dbd_max_headers,
        mtu: cfg.mtu,
        dbd_options: exchange::dbd_options(cfg.stub),
        peer_opaque_capable: exchange::peer_opaque_capable(dbd),
        peer_oob_capable: peer_eof(cfg, dbd.lls.as_ref()) & lls::EOF_LR != 0,
    };
    let mut old_state = old_state;
    let mut actions =
        exchange::on_dbd_received(&mut adj, old_state, &params, dbd, &local_lsdb_headers);
    if actions.contains(&exchange::Action::OobResyncStart) {
        // RFC 4811 §2.4: a Full neighbor opened an out-of-band resync. Restart
        // at ExStart with OOBResync set and process this DBD as RFC 2328 says;
        // the neighbor stays advertised (`NeighborInfo::counts_as_full`).
        let (mut fresh, mut negotiation) = start_negotiation(cfg, local_router_id);
        fresh.oob_resync = true;
        negotiation.resync = true;
        fresh.last_dbd_sent = Some(negotiation.clone());
        adj = fresh;
        old_state = NeighborState::ExStart;
        mark_oob_started(cfg, status, dbd.router_id, &adj);
        let mut next =
            exchange::on_dbd_received(&mut adj, old_state, &params, dbd, &local_lsdb_headers);
        next.insert(0, exchange::Action::SendDbd(negotiation));
        actions = next;
    }

    Some(finish_neighbor_event(
        cfg,
        local_router_id,
        status,
        dbd.router_id,
        old_state,
        adj,
        actions,
    ))
}

/// Handles one received LSR packet, looking up every requested LSA in
/// `lsdb`. Returns `None` if the neighbor is unknown or has no adjacency in
/// progress.
pub(super) async fn handle_lsr(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    lsdb: &Mutex<Lsdb>,
    link_local_lsdb: &Mutex<Lsdb>,
    lsr: &LsrPacket,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&lsr.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };
    if !neighbor::exchange_or_later(old_state) {
        tracing::debug!(neighbor = %lsr.router_id, state = ?old_state, "ospf lsr ignored below exchange");
        return None;
    }

    let actions = {
        let lsdb = lsdb.lock().await;
        let link_local_lsdb = link_local_lsdb.lock().await;
        exchange::on_lsr_received(&mut adj, &lsdb, &link_local_lsdb, lsr)
    };

    Some(finish_neighbor_event(
        cfg,
        local_router_id,
        status,
        lsr.router_id,
        old_state,
        adj,
        actions,
    ))
}

/// Handles one received LSU packet, installing every carried LSA into
/// `lsdb`. Returns `None` if the neighbor is unknown or has no adjacency in
/// progress.
pub(super) async fn handle_lsu(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    lsdb: &Mutex<Lsdb>,
    link_local_lsdb: &Mutex<Lsdb>,
    lsu: &LsuPacket,
    link_id: u32,
) -> Option<Vec<exchange::Action>> {
    let (old_state, mut adj) = {
        let snapshot = status.borrow();
        let neighbor = snapshot.neighbors.get(&lsu.router_id)?;
        (neighbor.state, neighbor.adjacency.clone()?)
    };
    if !neighbor::exchange_or_later(old_state) {
        tracing::debug!(neighbor = %lsu.router_id, state = ?old_state, "ospf lsu ignored below exchange");
        return None;
    }

    let ack = super::flood::ack_ctx(cfg, status, lsu.router_id);
    let origin = nos_ospf_common::lsdb::Origin {
        link: link_id,
        neighbor: lsu.router_id,
    };
    let (actions, newly_installed) = {
        let mut lsdb = lsdb.lock().await;
        let mut link_local_lsdb = link_local_lsdb.lock().await;
        let result = exchange::on_lsu_received(
            &mut adj,
            &mut lsdb,
            &mut link_local_lsdb,
            lsu,
            // tokio's clock, so paused-time tests see MinLSArrival pass.
            tokio::time::Instant::now().into_std(),
            Some(origin),
            ack,
        );
        // A Grace-LSA is acted on at once and never held, even in the link
        // store (RFC 3623), so it is never offered back to the restarted
        // router. Removed under the same lock the install took.
        for l in &lsu.lsas {
            if matches!(l.body, LsaBody::Grace(_)) && result.1.contains(&l.header) {
                link_local_lsdb.remove(&l.header.key());
            }
        }
        // RFC 2328 §13.4: our own LSA, newer than ours, came back — the
        // originator goes above it at once (`install_self_originated`).
        for h in nos_ospf_common::lsa::reflected_self_lsas(&result.1, local_router_id) {
            let store = if lsa::is_link_local_scope(h.lsa_type) {
                &mut *link_local_lsdb
            } else {
                &mut *lsdb
            };
            if store.get(&h.key()).is_none() {
                continue;
            }
            store.mark_reflected(h.key());
            info!(
                link = %cfg.attach_point, neighbor = %lsu.router_id,
                lsa_type = h.lsa_type, link_state_id = %h.link_state_id,
                received_sequence_number = h.sequence_number,
                "ospf self-originated lsa received with newer sequence, reoriginating"
            );
        }
        result
    };
    if adj.pending_acks_since.is_none() && !adj.pending_acks.is_empty() {
        adj.pending_acks_since = Some(std::time::Instant::now());
    }
    for header in &newly_installed {
        info!(
            link = %cfg.attach_point, neighbor = %lsu.router_id,
            lsa_type = header.lsa_type, link_state_id = %header.link_state_id,
            advertising_router = %header.advertising_router, age = header.age,
            "ospf lsa installed"
        );
    }
    for grace in lsu
        .lsas
        .iter()
        .filter(|l| newly_installed.contains(&l.header))
    {
        if let LsaBody::Grace(body) = grace.body {
            let was = in_grace(status, grace.header.advertising_router);
            on_grace_lsa(cfg, status, &grace.header, body);
            // #1027: a change installed before this grace began, still waiting
            // for the aging tick, is not "during" it (§3.2 (c)): without this a
            // third router's LSA from just before the restart ends the grace.
            if !was && in_grace(status, grace.header.advertising_router) {
                lsdb.lock().await.forget_topology_changes();
            }
        }
    }

    Some(finish_neighbor_event(
        cfg,
        local_router_id,
        status,
        lsu.router_id,
        old_state,
        adj,
        actions,
    ))
}

/// Handles one received `LSAck` packet: retransmission-list bookkeeping, plus
/// `exchange::lsack_hint` (#1626) for an ack of a newer instance of our own LSA.
pub(super) async fn handle_lsack(
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    lsdb: &Mutex<Lsdb>,
    link_local_lsdb: &Mutex<Lsdb>,
    ack: &LsAckPacket,
) -> Option<Vec<exchange::Action>> {
    let mut adj = status
        .borrow()
        .neighbors
        .get(&ack.router_id)
        .filter(|n| neighbor::exchange_or_later(n.state))
        .and_then(|n| n.adjacency.clone())?;
    exchange::on_lsack_received(&mut adj, &ack.lsa_headers);
    let actions = {
        let lsdb = lsdb.lock().await;
        let link_local = link_local_lsdb.lock().await;
        nos_ospf_common::exchange::lsack_hint(
            &mut adj,
            &[&*lsdb, &*link_local],
            local_router_id,
            &ack.lsa_headers,
            tokio::time::Instant::now().into_std(),
        )
    };
    status.send_modify(|s| {
        if let Some(info) = s.neighbors.get_mut(&ack.router_id) {
            info.adjacency = Some(adj);
        }
    });
    Some(actions)
}

/// Applies any `NeighborEvent`s in `actions` to `old_state` via
/// `neighbor::step`, logs state-transition milestones, and — if the result
/// is a `SeqNumberMismatch`-triggered restart back to `ExStart` — replaces
/// `actions` with a fresh negotiation DBD instead of replaying whatever the
/// caller computed (mirroring `advance_adjacencies`'s own negotiation
/// start). Shared tail of `handle_dbd`/`handle_lsr`/`handle_lsu`.
pub(super) fn finish_neighbor_event(
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    neighbor_id: Ipv4Addr,
    old_state: NeighborState,
    mut adj: AdjacencyData,
    actions: Vec<exchange::Action>,
) -> Vec<exchange::Action> {
    let mut new_state = old_state;
    for action in &actions {
        if let exchange::Action::NeighborEvent(event) = action {
            new_state = neighbor::step(new_state, *event);
        }
    }

    let actions = if new_state == NeighborState::ExStart && old_state != NeighborState::ExStart {
        let (fresh_adj, negotiation_dbd) = start_negotiation(cfg, local_router_id);
        adj = fresh_adj;
        warn!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor sequence mismatch, restarting negotiation");
        vec![exchange::Action::SendDbd(negotiation_dbd)]
    } else {
        for action in &actions {
            if let exchange::Action::SendDbd(pkt) = action {
                adj.last_dbd_sent = Some(pkt.clone());
            }
        }
        // Past `Exchange`, only the slave's final reply can still be needed:
        // `exchange` resends it for the master's duplicate (RFC 2328 §10.6).
        // ponytail: kept until the next `ExStart`, not the RFC's
        // `RouterDeadInterval`; one packet, no timer.
        if adj.is_master && matches!(new_state, NeighborState::Loading | NeighborState::Full) {
            adj.last_dbd_sent = None;
        }
        actions
    };

    match (old_state, new_state) {
        (s, NeighborState::Exchange) if s != NeighborState::Exchange => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached exchange");
        }
        (s, NeighborState::Loading) if s != NeighborState::Loading => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached loading");
        }
        (s, NeighborState::Full) if s != NeighborState::Full => {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf neighbor reached full");
            if in_grace(status, neighbor_id) {
                info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf helper: neighbor reformed, exiting grace early");
            }
        }
        _ => {}
    }

    status.send_modify(|s| {
        if let Some(info) = s.neighbors.get_mut(&neighbor_id) {
            info.set_state(new_state);
            if new_state == NeighborState::Full && old_state != NeighborState::Full {
                info.grace_deadline = None;
                // RFC 4811 §2.2: reaching Full ends the out-of-band resync.
                if adj.oob_resync {
                    adj.oob_resync = false;
                    info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf lls resync complete");
                }
            }
            if !adj.oob_resync {
                info.oob_deadline = None;
            }
            info.adjacency = Some(adj.clone());
        }
    });

    actions
}

/// Carries out the I/O side of an `exchange::Action` list — sending
/// packets. `NeighborEvent` is already applied to state by the caller.
pub(super) fn execute_actions(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    neighbor_id: Ipv4Addr,
    actions: Vec<exchange::Action>,
    next_seq: &mut u64,
) {
    let Some(neighbor_addr) = status
        .borrow()
        .neighbors
        .get(&neighbor_id)
        .map(|n| n.address)
    else {
        return;
    };
    for action in actions {
        // Each packet sent gets its own crypto sequence number — RFC 2328
        // D.4.3's non-decreasing guarantee is per packet, not per action
        // batch. LSR/LSU/LSAck are split to the link MTU, one signed packet
        // per chunk (`encode_split`).
        let (kind, payloads) = match action {
            exchange::Action::SendDbd(pkt) => {
                // A genuine mid-pagination continuation chunk (not the
                // initial empty negotiation attempt, which also always has
                // `more: true`) — the anchor `tools/verify-e2e.sh`'s
                // `ospf-dbd-pagination` phase greps for.
                if !pkt.init && pkt.more {
                    info!(
                        link = %cfg.attach_point, neighbor = %neighbor_id,
                        dd_sequence_number = pkt.dd_sequence_number,
                        "ospf dbd chunk sent, more remaining"
                    );
                }
                let auth = cfg
                    .auth
                    .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
                let copies = nos_ospf_common::dbd_fault::copies();
                if copies != 1 {
                    info!(link = %cfg.attach_point, neighbor = %neighbor_id, copies, "ospf dbd fault injected");
                }
                ("dbd", vec![encode_dbd_for(cfg, &pkt, &auth); copies])
            }
            exchange::Action::SendLsr(requests) => {
                ("lsr", split_lsr(cfg, next_seq, local_router_id, &requests))
            }
            exchange::Action::SendLsu(lsas) => {
                let lsas: Vec<_> = lsas.iter().map(|l| (**l).clone()).collect();
                ("lsu", split_lsu(cfg, next_seq, local_router_id, &lsas))
            }
            exchange::Action::SendLsAck(lsa_headers) => (
                "lsack",
                split_lsack(cfg, next_seq, local_router_id, &lsa_headers),
            ),
            exchange::Action::NeighborEvent(_) | exchange::Action::OobResyncStart => continue,
        };
        for payload in payloads {
            if let Err(e) = socket.send_unicast(neighbor_addr, &payload) {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, kind, error = %e, "failed to send ospf packet");
            }
        }
    }
}

/// RFC 2328 §8.2: only the DR and BDR listen on `AllDRouters` (224.0.0.6),
/// never on a point-to-point link. Run after every election pass, so a failed
/// join is retried (`sync` is idempotent and quiet when nothing changes).
pub(super) fn sync_all_drouters(socket: &LinkSocket, cfg: &LinkConfig, status: &StatusHandle) {
    let want = nos_ospf_common::drouters::wants_all_drouters(
        matches!(
            status.borrow().interface_state,
            InterfaceState::Dr | InterfaceState::Backup
        ),
        cfg.network_type != NetworkType::Broadcast,
    );
    match socket.set_all_drouters(want) {
        Ok(true) => {
            info!(link = %cfg.attach_point, joined = want, "ospf all-drouters membership changed");
        }
        Ok(false) => {}
        Err(e) => {
            warn!(link = %cfg.attach_point, error = %e, "ospf all-drouters membership change failed");
        }
    }
}

/// Broadcast only. Runs RFC 2328 §9.4 election (`election::elect`) over
/// every 2-Way-or-better neighbor, updates `status.dr`/`bdr`/
/// `interface_state`, and logs exactly once per role transition.
pub(super) fn run_election(cfg: &LinkConfig, local_router_id: Ipv4Addr, status: &StatusHandle) {
    let snapshot = status.borrow().clone();
    let self_candidate = Candidate {
        router_id: local_router_id,
        priority: cfg.priority,
        declared_dr: snapshot.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
        declared_bdr: snapshot.bdr.unwrap_or(Ipv4Addr::UNSPECIFIED),
    };
    let neighbor_candidates: Vec<Candidate> = snapshot
        .neighbors
        .iter()
        // RFC 2328 §9.4: every neighbor at 2-Way *or better* is eligible —
        // not just exactly `TwoWay`. A neighbor that has since progressed
        // to `ExStart`/`Exchange`/`Loading`/`Full` is still on the segment
        // and must stay in the DR/BDR candidate pool; excluding it here
        // once adjacency starts forming would make this router think it's
        // alone and incorrectly elect itself.
        .filter(|(_, info)| {
            matches!(
                info.state,
                NeighborState::TwoWay
                    | NeighborState::ExStart
                    | NeighborState::Exchange
                    | NeighborState::Loading
                    | NeighborState::Full
            )
        })
        .map(|(id, info)| Candidate {
            router_id: *id,
            priority: info.priority,
            declared_dr: info.declared_dr,
            declared_bdr: info.declared_bdr,
        })
        .collect();
    let result = election::elect(self_candidate, &neighbor_candidates);

    let new_interface_state = if result.dr == Some(local_router_id) {
        InterfaceState::Dr
    } else if result.bdr == Some(local_router_id) {
        InterfaceState::Backup
    } else {
        InterfaceState::DrOther
    };

    // Re-logs whenever the reported role *or* the dr/bdr router-ids behind
    // it change — not just on an `InterfaceState` variant change. A router
    // can stay `DrOther` (or `Backup`) across more than one election pass
    // while a neighbor's own declared role is still converging (RFC 2328
    // §9.4's own "recompute twice" refinement, which `election.rs`'s
    // single-pass simplification defers to a later Hello-driven rerun
    // instead) — without this, the log would freeze on that first,
    // not-yet-converged dr/bdr pair even though `status.send_modify` below
    // keeps the real state (and thus real adjacency-eligibility decisions)
    // correct throughout.
    if (snapshot.interface_state, snapshot.dr, snapshot.bdr)
        != (new_interface_state, result.dr, result.bdr)
    {
        match new_interface_state {
            InterfaceState::Dr => {
                info!(link = %cfg.attach_point, dr = %local_router_id, "ospf interface became dr");
            }
            InterfaceState::Backup => {
                info!(
                    link = %cfg.attach_point,
                    dr = %result.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    bdr = %local_router_id,
                    "ospf interface became backup"
                );
            }
            InterfaceState::DrOther => {
                info!(
                    link = %cfg.attach_point,
                    dr = %result.dr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    bdr = %result.bdr.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    "ospf interface became dr-other"
                );
            }
            InterfaceState::Waiting | InterfaceState::PointToPoint => {
                unreachable!("election never produces Waiting/PointToPoint")
            }
        }
    }

    status.send_modify(|s| {
        s.dr = result.dr;
        s.bdr = result.bdr;
        s.interface_state = new_interface_state;
    });
}

/// Steps every live, non-grace entry at `source` under another router ID to
/// `Down`; the dead-neighbor sweep then removes it.
fn evict_same_address(cfg: &LinkConfig, status: &StatusHandle, source: Ipv4Addr, new_id: Ipv4Addr) {
    status.send_modify(|s| {
        for (id, info) in &mut s.neighbors {
            if *id != new_id
                && info.address == source
                && info.state != NeighborState::Down
                && info.grace_deadline.is_none()
            {
                warn!(
                    link = %cfg.attach_point, neighbor = %id, replaced_by = %new_id,
                    "ospf neighbor evicted, same source address under a new router id"
                );
                info.set_state(neighbor::step(
                    info.state,
                    neighbor::Event::InactivityTimerExpired,
                ));
                info.adjacency = None;
                super::flood::clear_replay_state(info);
            }
        }
    });
}
