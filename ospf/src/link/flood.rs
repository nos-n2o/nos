//! Acks, retransmission, reliable flooding and the neighbor liveness timers.
//! Moved verbatim out of `link.rs`.

use super::rx::split_lsack;
use super::rx::{execute_actions, next_crypto_seq, split_lsr, split_lsu};
use std::collections::HashMap;
use std::sync::Arc;

use nos_ospf_common::flood::{flood_on_link, merge_floods, LinkFlood, Peer, Receipt};
use nos_ospf_common::lsdb::{FloodEvent, InstallOutcome};

use super::{
    bfd, exchange, info, lsa, neighbor, warn, Dest, Duration, Instant, InterfaceState, Ipv4Addr,
    LinkConfig, LinkSocket, Lsa, NeighborInfo, NeighborState, NetworkType, StatusHandle,
};

/// RFC 2328 §13.3 step 5 / §13.5: where this link's flooded LSUs and delayed
/// `LSAcks` go right now. Only broadcast links use a group; the DR/Backup role
/// picks which.
fn current_dest(cfg: &LinkConfig, status: &StatusHandle) -> Dest {
    nos_ospf_common::drouters::flood_dest(
        cfg.network_type == NetworkType::Broadcast,
        matches!(
            status.borrow().interface_state,
            InterfaceState::Dr | InterfaceState::Backup
        ),
    )
}

/// RFC 2328 §13.5 delayed acknowledgment: sends each neighbor's queued acks
/// (`AdjacencyData::pending_acks`, filled by `on_lsu_received`) as one
/// `LSAck`. Runs on the 1 s `ACK_INTERVAL` tick: the RFC requires the delay
/// to stay below `RxmtInterval`.
pub(super) fn flush_pending_acks(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
) {
    let dest = current_dest(cfg, status);
    if dest != Dest::Unicast {
        flush_pending_acks_group(socket, cfg, local_router_id, status, next_seq, dest);
        return;
    }
    let mut flushes = Vec::new();
    status.send_if_modified(|s| {
        for (neighbor_id, info) in &mut s.neighbors {
            let Some(adj) = &mut info.adjacency else {
                continue;
            };
            let held = adj.pending_acks_since;
            if let Some(action) = exchange::take_pending_acks(adj) {
                flushes.push((*neighbor_id, held, action));
            }
        }
        // Nothing here changes what `originate_router_lsas` snapshots.
        false
    });
    for (neighbor_id, held, action) in flushes {
        if let exchange::Action::SendLsAck(headers) = &action {
            info!(
                link = %cfg.attach_point, neighbor = %neighbor_id, acked = headers.len(),
                delayed_ms = held.map_or(0, |t| t.elapsed().as_millis()),
                "ospf lsack sent"
            );
        }
        execute_actions(
            socket,
            cfg,
            local_router_id,
            status,
            neighbor_id,
            vec![action],
            next_seq,
        );
    }
}

/// Broadcast links: one deduplicated `LSAck` set for every neighbor's queue,
/// to the group `dest`. A failed group send warns once and falls back to a
/// unicast copy per adjacent neighbor, so acks are never lost to it.
fn flush_pending_acks_group(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
    dest: Dest,
) {
    let mut taken = (Vec::new(), None);
    status.send_if_modified(|s| {
        taken = exchange::take_all_pending_acks(
            s.neighbors
                .values_mut()
                .filter_map(|n| n.adjacency.as_mut()),
        );
        false
    });
    let (headers, since) = taken;
    if headers.is_empty() {
        return;
    }
    info!(
        link = %cfg.attach_point, dest = %dest.as_str(), acked = headers.len(),
        delayed_ms = since.map_or(0, |t| t.elapsed().as_millis()),
        "ospf lsack sent"
    );
    for payload in split_lsack(cfg, next_seq, local_router_id, &headers) {
        if let Err(e) = socket.send_flood(dest, Ipv4Addr::UNSPECIFIED, &payload) {
            warn!(link = %cfg.attach_point, dest = %dest.as_str(), error = %e, "failed to multicast ospf lsack, falling back to unicast");
            let targets: Vec<Ipv4Addr> = status
                .borrow()
                .neighbors
                .values()
                .filter(|n| n.adjacency.is_some())
                .map(|n| n.address)
                .collect();
            for addr in targets {
                let _ = socket.send_unicast(addr, &payload);
            }
        }
    }
}

/// Resends every neighbor's last-sent DBD (if any — see `AdjacencyData::
/// last_dbd_sent`'s doc comment for why this is necessary, not just a
/// reliability nicety), its request list and the retransmission-list entries
/// older than `RXMT_INTERVAL` (RFC 2328 §13.6, `due_retransmissions`, unicast).
pub(super) fn retransmit_pending(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    next_seq: &mut u64,
) {
    let now = tokio::time::Instant::now().into_std();
    let mut due: HashMap<Ipv4Addr, Vec<Lsa>> = HashMap::new();
    status.send_if_modified(|s| {
        for (id, info) in &mut s.neighbors {
            if !matches!(
                info.state,
                NeighborState::Exchange | NeighborState::Loading | NeighborState::Full
            ) {
                continue;
            }
            if let Some(adj) = &mut info.adjacency {
                let lsas = exchange::due_retransmissions(adj, now, super::RXMT_INTERVAL);
                if !lsas.is_empty() {
                    due.insert(*id, lsas.iter().map(|l| (**l).clone()).collect());
                }
            }
        }
        false
    });
    let snapshot = status.borrow().clone();
    for (neighbor_id, info) in &snapshot.neighbors {
        let Some(adj) = &info.adjacency else { continue };
        // ExStart, or Exchange as master: a slave answers only the master's
        // poll (RFC 2328 §10.8), its kept reply never goes out on a timer.
        if let (true, Some(dbd)) = (
            info.state == NeighborState::ExStart
                || (info.state == NeighborState::Exchange && adj.is_master),
            &adj.last_dbd_sent,
        ) {
            let auth = cfg
                .auth
                .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
            if let Err(e) =
                socket.send_unicast(info.address, &super::rx::encode_dbd_for(cfg, dbd, &auth))
            {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf dbd");
            }
        }
        if !matches!(
            info.state,
            NeighborState::Exchange | NeighborState::Loading | NeighborState::Full
        ) {
            continue;
        }
        for payload in split_lsr(cfg, next_seq, local_router_id, &adj.request_list) {
            if let Err(e) = socket.send_unicast(info.address, &payload) {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf lsr");
            }
        }
        let retransmit = due.remove(neighbor_id).unwrap_or_default();
        for payload in split_lsu(cfg, next_seq, local_router_id, &retransmit) {
            if let Err(e) = socket.send_unicast(info.address, &payload) {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf lsu");
            }
        }
    }
}

/// Logs the flood destination once per change (`ospf lsu flood destination
/// changed`, asserted by `nos-e2e ospf-dr`); also run on the ack tick so a
/// role change is reported without waiting for the next flood.
pub(super) fn note_flood_dest(
    cfg: &LinkConfig,
    status: &StatusHandle,
    last_dest: &mut Option<Dest>,
) -> Dest {
    let dest = current_dest(cfg, status);
    if *last_dest != Some(dest) {
        *last_dest = Some(dest);
        info!(link = %cfg.attach_point, dest = %dest.as_str(), "ospf lsu flood destination changed");
    }
    dest
}

fn link_flood(cfg: &LinkConfig, s: &super::LinkStatus) -> LinkFlood {
    LinkFlood {
        broadcast: cfg.network_type == NetworkType::Broadcast,
        we_are_dr: s.interface_state == InterfaceState::Dr,
        we_are_bdr: s.interface_state == InterfaceState::Backup,
    }
}

/// RFC 2328 §13.5 context for an LSU received from `from` on this link.
pub(super) fn ack_ctx(cfg: &LinkConfig, status: &StatusHandle, from: Ipv4Addr) -> exchange::AckCtx {
    let s = status.borrow();
    exchange::AckCtx {
        link: link_flood(cfg, &s),
        rx: Receipt {
            from,
            from_dr_or_bdr: s.dr == Some(from) || s.bdr == Some(from),
        },
        other_adjacent: s
            .neighbors
            .iter()
            .any(|(id, n)| *id != from && neighbor::exchange_or_later(n.state)),
    }
}

/// Every LSA of a store as a synthetic flood event (lag recovery only).
pub(super) fn as_events(lsas: Vec<Arc<Lsa>>) -> Vec<FloodEvent<Lsa>> {
    lsas.into_iter()
        .map(|lsa| FloodEvent {
            lsa,
            origin: None,
            outcome: InstallOutcome::Installed,
        })
        .collect()
}

/// RFC 2328 §13.3: floods each event's LSA out this link. Adds it to the
/// retransmission list of every neighbor `>= Exchange` (but the sender) and
/// sends at once, MTU-split: to the group on broadcast links (unicast
/// fallback if the group send fails), unicast otherwise. Opaque LSAs go
/// unicast to O-bit neighbors only (RFC 5250 §3). `link_id` is this link's
/// `Origin.link`.
#[allow(
    clippy::too_many_arguments,
    reason = "the link task's own state, passed through"
)]
pub(super) fn flood_events(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    link_id: u32,
    status: &StatusHandle,
    events: &[FloodEvent<Lsa>],
    next_seq: &mut u64,
    last_dest: &mut Option<Dest>,
) {
    note_flood_dest(cfg, status, last_dest);
    let now = tokio::time::Instant::now().into_std();
    let mut outs = Vec::new();
    let mut addrs: HashMap<Ipv4Addr, Ipv4Addr> = HashMap::new();
    status.send_if_modified(|s| {
        let link = link_flood(cfg, s);
        let (dr, bdr) = (s.dr, s.bdr);
        addrs.extend(s.neighbors.iter().map(|(id, n)| (*id, n.address)));
        for ev in events {
            let ty = ev.lsa.header.lsa_type;
            if !lsa::in_area_scope(ty, cfg.stub, cfg.nssa) {
                continue;
            }
            let opaque = lsa::is_opaque(ty);
            let rx = ev.origin.filter(|o| o.link == link_id).map(|o| Receipt {
                from: o.neighbor,
                from_dr_or_bdr: dr == Some(o.neighbor) || bdr == Some(o.neighbor),
            });
            let mut peers: Vec<Peer<'_, Lsa>> = s
                .neighbors
                .iter_mut()
                .filter_map(|(id, n)| {
                    let state = n.state;
                    let adj = n.adjacency.as_mut()?;
                    (!opaque || adj.opaque_capable).then_some(Peer {
                        id: *id,
                        state,
                        adj,
                    })
                })
                .collect();
            if let Some(mut out) = flood_on_link(&ev.lsa, rx, link, &mut peers, now) {
                if opaque {
                    out.dest = Dest::Unicast;
                }
                outs.push(out);
            }
        }
        // Nothing here changes what `originate_router_lsas` snapshots.
        false
    });
    for (dest, to, lsas) in merge_floods(outs) {
        let lsas: Vec<Lsa> = lsas.iter().map(|l| (**l).clone()).collect();
        let mut sent_group = dest != Dest::Unicast;
        if sent_group {
            for payload in split_lsu(cfg, next_seq, local_router_id, &lsas) {
                if let Err(e) = socket.send_flood(dest, Ipv4Addr::UNSPECIFIED, &payload) {
                    warn!(link = %cfg.attach_point, dest = %dest.as_str(), error = %e, "failed to multicast ospf lsu, falling back to unicast");
                    sent_group = false;
                    break;
                }
            }
        }
        if !sent_group {
            for payload in split_lsu(cfg, next_seq, local_router_id, &lsas) {
                for addr in to.iter().filter_map(|id| addrs.get(id)) {
                    if let Err(e) = socket.send_unicast(*addr, &payload) {
                        warn!(link = %cfg.attach_point, error = %e, "failed to send ospf lsu");
                    }
                }
            }
        }
        info!(
            link = %cfg.attach_point, dest = %dest.as_str(), neighbors = to.len(), lsas = lsas.len(),
            "ospf lsu flooded"
        );
    }
}

/// A neighbor gone `Down` forgets its crypto sequence numbers (#612): a
/// restarted peer may legitimately reseed below the stored value, and RFC
/// 7474 §1 / RFC 7166 keep this state per adjacency. `Init` keeps it (a live
/// neighbor mid-handshake).
pub(super) fn clear_replay_state(info: &mut NeighborInfo) {
    if info.state == NeighborState::Down {
        info.last_crypto_seq.clear();
    }
}

/// RFC 2328 §10.2 `KillNbr` for the neighbor at `address`, because BFD found
/// its path down. The next Hello brings it back through Init; nothing waits
/// on BFD to form an adjacency.
pub(super) fn kill_bfd_neighbor(cfg: &LinkConfig, status: &StatusHandle, address: Ipv4Addr) {
    status.send_modify(|s| {
        for (id, info) in &mut s.neighbors {
            if info.address == address && info.state != NeighborState::Down {
                warn!(link = %cfg.attach_point, neighbor = %id, "bfd session down, killing ospf neighbor");
                info.set_state(bfd::on_bfd_down(info.state));
                info.adjacency = None;
                clear_replay_state(info);
            }
        }
    });
}

/// RFC 4222 §2 recommendation 2: an authenticated non-Hello packet from a
/// neighbor we have an adjacency with (`ExStart` or later) proves it alive,
/// so it restarts the inactivity timer like a Hello would. Hellos keep their
/// own refresh in `handle_hello`, which only happens once they pass its
/// checks. ponytail: counts any destination, not only unicast / `AllSPFRouters`
/// on point-to-point as the RFC words it — `recv_packet` doesn't return the
/// destination (that needs `IP_PKTINFO`), and nos sends these unicast anyway.
pub(super) fn note_alive(status: &StatusHandle, router_id: Ipv4Addr) {
    let adjacent = status.borrow().neighbors.get(&router_id).is_some_and(|n| {
        matches!(
            n.state,
            NeighborState::ExStart
                | NeighborState::Exchange
                | NeighborState::Loading
                | NeighborState::Full
        )
    });
    if !adjacent {
        return;
    }
    let now = Instant::now();
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&router_id) {
            n.last_heard = now;
        }
    });
}

/// Every network type. Ages out any neighbor whose `last_heard` is
/// older than `cfg.dead_interval` — see `run()`'s `ponytail:` note on why
/// this is a periodic sweep rather than per-neighbor timers.
pub(super) fn sweep_dead_neighbors(cfg: &LinkConfig, status: &StatusHandle) {
    let now = Instant::now();
    let dead_interval = Duration::from_secs(u64::from(cfg.dead_interval));
    let expired: Vec<Ipv4Addr> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, info)| {
            info.state != NeighborState::Down
                && info.grace_deadline.is_none()
                && now.duration_since(info.last_heard) >= dead_interval
        })
        .map(|(id, _)| *id)
        .collect();
    if !expired.is_empty() {
        for _ in &expired {
            warn!(link = %cfg.attach_point, "ospf neighbor state changed to down");
        }
        status.send_modify(|s| {
            for id in &expired {
                if let Some(info) = s.neighbors.get_mut(id) {
                    info.state =
                        neighbor::step(info.state, neighbor::Event::InactivityTimerExpired);
                    info.adjacency = None;
                    clear_replay_state(info);
                }
            }
        });
    }
    // A Down entry silent for a full dead interval has no use: free the slot
    // (#956; else forged router IDs pin the neighbor cap for good).
    let gone: Vec<Ipv4Addr> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, info)| {
            info.state == NeighborState::Down
                && info.grace_deadline.is_none()
                && now.duration_since(info.last_heard) >= dead_interval
        })
        .map(|(id, _)| *id)
        .collect();
    if gone.is_empty() {
        return;
    }
    status.send_modify(|s| {
        for id in &gone {
            s.neighbors.remove(id);
        }
    });
    for id in &gone {
        info!(link = %cfg.attach_point, neighbor = %id, "ospf neighbor entry removed");
    }
}
