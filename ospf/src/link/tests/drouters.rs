//! #855: 224.0.0.6 is joined exactly while DR/Backup.
use super::*;
use rx::sync_all_drouters;
use std::sync::atomic::Ordering;

fn joined(wire: &wire::Wire, n: u8) -> bool {
    wire.drouters
        .lock()
        .unwrap()
        .get(&Ipv4Addr::new(10, 0, 0, n))
        .copied()
        .unwrap_or(false)
}

fn neighbor(status: &StatusHandle, n: u8, priority: u8, dr: bool) {
    let mut info = neighbor_info(NeighborState::TwoWay, Ipv4Addr::new(10, 0, 0, n));
    info.priority = priority;
    if dr {
        info.declared_dr = id(n);
    } else {
        info.declared_bdr = id(n);
    }
    status.send_modify(|s| {
        s.neighbors.insert(id(n), info);
    });
}

fn pass(socket: &LinkSocket, cfg: &LinkConfig, status: &StatusHandle) {
    run_election(cfg, id(1), status);
    sync_all_drouters(socket, cfg, status);
}

#[test]
fn follows_the_election_role_and_retries_failures() {
    let wire = Arc::new(wire::Wire::default());
    let cfg = wired_link([10, 0, 0, 1], 24, NetworkType::Broadcast);
    let socket = wire.opener()(&cfg).unwrap();
    let status = watch::channel(LinkStatus::new(NetworkType::Broadcast)).0;

    // Waiting: no election yet, so no join.
    sync_all_drouters(&socket, &cfg, &status);
    assert!(!joined(&wire, 1));

    wire.fail_drouters.store(true, Ordering::Relaxed);
    pass(&socket, &cfg, &status);
    assert_eq!(status.borrow().interface_state, InterfaceState::Dr);
    assert!(!joined(&wire, 1), "failed join is not recorded");
    wire.fail_drouters.store(false, Ordering::Relaxed);
    pass(&socket, &cfg, &status);
    assert!(joined(&wire, 1), "retried on the next pass");
    assert!(!socket.set_all_drouters(true).unwrap(), "idempotent");

    // Higher-priority DR and BDR appear: demoted, left.
    neighbor(&status, 2, 100, true);
    neighbor(&status, 3, 99, false);
    pass(&socket, &cfg, &status);
    assert_eq!(status.borrow().interface_state, InterfaceState::DrOther);
    assert!(!joined(&wire, 1));

    // The BDR disappears: promoted to Backup, joined again.
    status.send_modify(|s| {
        s.neighbors.remove(&id(3));
    });
    pass(&socket, &cfg, &status);
    assert_eq!(status.borrow().interface_state, InterfaceState::Backup);
    assert!(joined(&wire, 1));
}

#[test]
fn never_on_point_to_point_or_multipoint() {
    for nt in [NetworkType::PointToPoint, NetworkType::PointToMultipoint] {
        let wire = Arc::new(wire::Wire::default());
        let cfg = wired_link([10, 0, 0, 1], 24, nt);
        let socket = wire.opener()(&cfg).unwrap();
        let status = watch::channel(LinkStatus::new(nt)).0;
        status.send_modify(|s| s.interface_state = InterfaceState::Dr);
        sync_all_drouters(&socket, &cfg, &status);
        assert!(!joined(&wire, 1));
    }
}

/// #608: Hello DR/BDR fields are interface addresses (RFC 2328 A.3.2) even
/// when router IDs differ from them.
#[test]
fn wire_fields_are_interface_addresses_not_router_ids() {
    use rx::{dr_wire_addr, resolve_declared};
    let local_id = id(1);
    let local_addr = Ipv4Addr::new(10, 0, 0, 1);
    let peer_addr = Ipv4Addr::new(10, 0, 0, 2);
    let mut n = HashMap::new();
    n.insert(id(2), neighbor_info(NeighborState::TwoWay, peer_addr));
    let un = Ipv4Addr::UNSPECIFIED;

    assert_eq!(
        dr_wire_addr(Some(local_id), local_id, local_addr, &n),
        local_addr
    );
    assert_eq!(
        dr_wire_addr(Some(id(2)), local_id, local_addr, &n),
        peer_addr
    );
    assert_eq!(dr_wire_addr(Some(id(9)), local_id, local_addr, &n), un);
    assert_eq!(dr_wire_addr(None, local_id, local_addr, &n), un);

    let res = |a, src, sender| resolve_declared(a, src, sender, local_id, local_addr, &n);
    // Sender declares itself (its own address, a different router ID).
    assert_eq!(res(peer_addr, peer_addr, id(2)), id(2));
    assert_eq!(res(local_addr, peer_addr, id(2)), local_id);
    let third = Ipv4Addr::new(10, 0, 0, 3);
    assert_eq!(res(third, peer_addr, id(2)), un, "unknown address");
    assert_eq!(res(un, peer_addr, id(2)), un);
    // A third known neighbor, declared by the sender.
    n.insert(id(3), neighbor_info(NeighborState::TwoWay, third));
    assert_eq!(
        resolve_declared(third, peer_addr, id(2), local_id, local_addr, &n),
        id(3)
    );
}
