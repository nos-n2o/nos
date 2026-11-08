//! Port Role Selection machine, 13.36 (Figure 13-19). One per bridge.

use super::{InfoIs, Role};
use crate::actions::{Action, Event};
use crate::bridge::Bridge;
use crate::vector::{PortId, PriorityVector};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    InitBridge,
    RoleSelection,
}

pub fn step(b: &mut Bridge) -> bool {
    match b.prs {
        State::InitBridge => {
            // updtRolesDisabledTree
            for p in &mut b.ports {
                p.selected_role = Role::Disabled;
                p.reselect = true;
            }
            b.prs = State::RoleSelection;
            true
        }
        State::RoleSelection if b.ports.iter().any(|p| p.reselect) => {
            role_selection(b);
            true
        }
        State::RoleSelection => false,
    }
}

fn role_selection(b: &mut Bridge) {
    b.ports.iter_mut().for_each(|p| p.reselect = false); // clearReselectTree
    updt_roles_tree(b);
    // setSelectedTree: only when nothing asked to reselect meanwhile.
    if !b.ports.iter().any(|p| p.reselect) {
        b.ports.iter_mut().for_each(|p| p.selected = true);
    }
}

/// 13.30 `updtRolesTree` for the CIST.
fn updt_roles_tree(b: &mut Bridge) {
    let me = b.id;
    let zero = PortId::from_u16(0);
    let mut best = PriorityVector {
        root: me,
        root_path_cost: 0,
        designated_bridge: me,
        designated_port: zero,
        bridge_port: zero,
    };
    let mut root_port = None;
    for (i, p) in b.ports.iter().enumerate() {
        if p.info_is == InfoIs::Received
            && !p.port_priority.designated_bridge.same_address(&me)
            && !p.prot.root_guard
        {
            let mut v = p.port_priority;
            v.root_path_cost = v.root_path_cost.saturating_add(p.path_cost);
            if v.better_than(&best) {
                best = v;
                root_port = Some(i);
            }
        }
    }
    let root_times = match root_port {
        Some(i) => {
            let mut t = b.ports[i].port_times;
            t.message_age = t.message_age.saturating_add(1);
            t
        }
        None => b.bridge_times,
    };
    if (best.root, root_port) != (b.root_id, b.root_port) {
        b.actions.push(Action::Log(Event::RootChanged {
            root: best.root,
            root_port,
        }));
    }
    b.root_port = root_port;
    b.root_id = best.root;
    b.root_times = root_times;
    for (i, p) in b.ports.iter_mut().enumerate() {
        p.designated_priority = PriorityVector {
            root: best.root,
            root_path_cost: best.root_path_cost,
            designated_bridge: me,
            designated_port: p.port_id,
            bridge_port: p.port_id,
        };
        p.designated_times = root_times;
        // Root guard: a root-guarded port that would have been the Root Port
        // is root-inconsistent (and ends up Alternate below).
        let would_be_root = p.prot.root_guard
            && p.info_is == InfoIs::Received
            && !p.port_priority.designated_bridge.same_address(&me)
            && {
                let mut v = p.port_priority;
                v.root_path_cost = v.root_path_cost.saturating_add(p.path_cost);
                v.better_than(&best)
            };
        if would_be_root != p.root_inconsistent {
            p.root_inconsistent = would_be_root;
            b.actions.push(Action::Log(Event::RootInconsistent {
                port: i,
                on: would_be_root,
            }));
        }
        match p.info_is {
            InfoIs::Disabled => p.selected_role = Role::Disabled,
            InfoIs::Aged if p.loop_inconsistent => {
                p.selected_role = Role::Alternate;
                p.updt_info = false;
            }
            InfoIs::Aged => {
                p.selected_role = Role::Designated;
                p.updt_info = true;
            }
            InfoIs::Mine => {
                p.selected_role = Role::Designated;
                if p.port_priority != p.designated_priority || p.port_times != p.designated_times {
                    p.updt_info = true;
                }
            }
            InfoIs::Received => {
                if root_port == Some(i) {
                    p.selected_role = Role::Root;
                    p.updt_info = false;
                } else if p.designated_priority.worse_than(&p.port_priority) {
                    p.selected_role = if p.port_priority.designated_bridge.same_address(&me) {
                        Role::Backup
                    } else {
                        Role::Alternate
                    };
                    p.updt_info = false;
                } else {
                    p.selected_role = Role::Designated;
                    p.updt_info = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::tests::bridge;

    fn received(b: &mut Bridge, port: usize, root: u8, cost: u32, desig: u8) {
        let p = &mut b.ports[port];
        p.info_is = InfoIs::Received;
        p.port_priority = PriorityVector {
            root: crate::machines::tests::bid(root),
            root_path_cost: cost,
            designated_bridge: crate::machines::tests::bid(desig),
            designated_port: PortId::new(128, 1).unwrap(),
            bridge_port: p.port_id,
        };
        p.port_times = p.designated_times;
        p.reselect = true;
        p.selected = false;
    }

    #[test]
    fn init_bridge_disables_everything_then_selects() {
        let mut b = bridge(5);
        b.prs = State::InitBridge;
        assert!(step(&mut b));
        assert!(b
            .ports
            .iter()
            .all(|p| p.reselect && p.selected_role == Role::Disabled));
        assert_eq!(b.prs, State::RoleSelection);
        assert!(step(&mut b));
        assert!(b.ports.iter().all(|p| p.selected && !p.reselect));
        assert!(!step(&mut b));
    }

    #[test]
    fn lone_bridge_is_root_with_designated_ports() {
        let mut b = bridge(5);
        for p in &mut b.ports {
            p.info_is = InfoIs::Aged;
            p.reselect = true;
        }
        assert!(step(&mut b));
        assert_eq!(b.root_port, None);
        assert!(b
            .ports
            .iter()
            .all(|p| p.selected_role == Role::Designated && p.updt_info));
    }

    #[test]
    fn best_received_path_is_root_port_others_alternate_or_designated() {
        let mut b = bridge(5);
        received(&mut b, 0, 1, 10, 2); // via port 0: cost 10 + path_cost
        received(&mut b, 1, 1, 10, 3); // same cost, worse designated bridge => alternate
        b.ports[2].info_is = InfoIs::Aged;
        b.ports[2].reselect = true;
        assert!(step(&mut b));
        assert_eq!(b.root_port, Some(0));
        assert_eq!(b.ports[0].selected_role, Role::Root);
        assert_eq!(b.ports[1].selected_role, Role::Alternate);
        assert_eq!(b.ports[2].selected_role, Role::Designated);
        assert_eq!(
            b.ports[2].designated_priority.root,
            crate::machines::tests::bid(1)
        );
        assert_eq!(b.root_times.message_age, 1);
    }

    #[test]
    fn own_mac_with_another_priority_is_not_a_root_port_candidate() {
        // 13.30 updtRolesTree compares the designated bridge by address only.
        let mut b = bridge(5);
        let mut mine = b.id;
        mine = crate::vector::BridgeId::new(4096, 0, mine.mac()).unwrap();
        b.ports[0].info_is = InfoIs::Received;
        b.ports[0].port_priority = PriorityVector {
            root: crate::machines::tests::bid(1),
            root_path_cost: 0,
            designated_bridge: mine,
            designated_port: b.ports[1].port_id,
            bridge_port: b.ports[0].port_id,
        };
        b.ports[0].reselect = true;
        assert!(step(&mut b));
        assert_eq!(b.root_port, None);
    }

    #[test]
    fn own_bpdu_on_second_port_makes_a_backup() {
        let mut b = bridge(1);
        // Root is us: port 1 hears port 0's BPDU.
        b.ports[0].info_is = InfoIs::Mine;
        b.ports[0].port_priority = PriorityVector {
            root: b.id,
            root_path_cost: 0,
            designated_bridge: b.id,
            designated_port: b.ports[0].port_id,
            bridge_port: b.ports[0].port_id,
        };
        b.ports[1].info_is = InfoIs::Received;
        b.ports[1].port_priority = PriorityVector {
            root: b.id,
            root_path_cost: 0,
            designated_bridge: b.id,
            designated_port: b.ports[0].port_id,
            bridge_port: b.ports[1].port_id,
        };
        b.ports[1].reselect = true;
        assert!(step(&mut b));
        assert_eq!(b.ports[1].selected_role, Role::Backup);
        assert_eq!(b.ports[0].selected_role, Role::Designated);
    }

    #[test]
    fn better_designated_info_on_mine_port_is_updated() {
        let mut b = bridge(1);
        b.ports[0].info_is = InfoIs::Mine;
        b.ports[0].port_times.hello = 9; // differs from designatedTimes
        b.ports[0].reselect = true;
        assert!(step(&mut b));
        assert!(b.ports[0].updt_info);
    }
}
