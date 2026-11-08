//! Port Information machine, 13.34 (Figure 13-18).
//!
//! The standard's RECEIVE state is followed by one of five outcome states; all
//! are modelled as real states so each diagram edge is one `step`.

use super::Role;
use super::{
    better_or_same_info, rcv_info, record_agreement, record_dispute, record_proposal, set_tc_flags,
    updt_rcvd_info_while, InfoIs, RcvdInfo,
};
use crate::actions::{Action, Event};
use crate::bridge::Bridge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disabled,
    Aged,
    Update,
    Current,
    Receive,
    SuperiorDesignated,
    RepeatedDesignated,
    InferiorDesignated,
    NotDesignated,
    Other,
}

pub fn enter(b: &mut Bridge, i: usize, s: State) {
    let rstp = b.rstp_version;
    let p = &mut b.ports[i];
    p.pim = s;
    match s {
        State::Disabled => {
            p.rcvd_msg = false;
            p.proposing = false;
            p.proposed = false;
            p.agree = false;
            p.agreed = false;
            p.rcvd_info_while = 0;
            p.info_is = InfoIs::Disabled;
            p.reselect = true;
            p.selected = false;
            // A link flap clears loop-inconsistency (decision 4 of #320).
            if std::mem::take(&mut p.loop_inconsistent) {
                b.actions
                    .push(Action::Log(Event::LoopInconsistent { port: i, on: false }));
            }
        }
        State::Aged => {
            // Loop guard: a Root/Alternate port that lost its BPDUs must not
            // become Designated; PRS holds it as Alternate until one arrives.
            if p.prot.loop_guard
                && matches!(p.role, Role::Root | Role::Alternate | Role::Backup)
                && !p.loop_inconsistent
            {
                p.loop_inconsistent = true;
                b.actions
                    .push(Action::Log(Event::LoopInconsistent { port: i, on: true }));
            }
            p.info_is = InfoIs::Aged;
            p.reselect = true;
            p.selected = false;
        }
        State::Update => {
            p.proposing = false;
            p.proposed = false;
            p.agreed = p.agreed && better_or_same_info(p, InfoIs::Mine);
            p.synced = p.synced && p.agreed;
            p.port_priority = p.designated_priority;
            p.port_times = p.designated_times;
            p.updt_info = false;
            p.info_is = InfoIs::Mine;
            p.new_info = true;
            if std::mem::take(&mut p.loop_inconsistent) {
                p.reselect = true;
                p.selected = false;
                b.actions
                    .push(Action::Log(Event::LoopInconsistent { port: i, on: false }));
            }
        }
        State::Current => {}
        State::Receive => p.rcvd_info = rcv_info(p),
        State::SuperiorDesignated => {
            p.agreed = false;
            p.proposing = false;
            // ponytail: not in the standard's list; fresh superior info needs a fresh sync/agreement cycle.
            p.agree = false;
            record_proposal(p);
            set_tc_flags(p);
            p.port_priority = p.msg_priority;
            p.port_times = p.msg_times;
            updt_rcvd_info_while(p);
            p.info_is = InfoIs::Received;
            p.reselect = true;
            p.selected = false;
            p.rcvd_msg = false;
        }
        State::RepeatedDesignated => {
            record_proposal(p);
            set_tc_flags(p);
            updt_rcvd_info_while(p);
            p.rcvd_msg = false;
        }
        State::InferiorDesignated => {
            record_dispute(p);
            p.rcvd_msg = false;
        }
        State::NotDesignated => {
            record_agreement(rstp, p);
            set_tc_flags(p);
            p.rcvd_msg = false;
        }
        State::Other => p.rcvd_msg = false,
    }
}

pub fn step(b: &mut Bridge, i: usize) -> bool {
    let p = &b.ports[i];
    let next = match p.pim {
        _ if !p.port_enabled && p.info_is != InfoIs::Disabled => State::Disabled,
        State::Disabled if p.rcvd_msg => State::Disabled,
        State::Disabled if p.port_enabled => State::Aged,
        State::Aged if p.selected && p.updt_info => State::Update,
        // Loop guard: a BPDU is back, let it be judged like on a fresh port.
        State::Aged if p.loop_inconsistent && p.rcvd_msg => State::Update,
        State::Update => State::Current,
        State::Current if p.selected && p.updt_info => State::Update,
        State::Current
            if p.info_is == InfoIs::Received
                && p.rcvd_info_while == 0
                && !p.updt_info
                && !p.rcvd_msg =>
        {
            State::Aged
        }
        State::Current if p.rcvd_msg && !p.updt_info => State::Receive,
        State::Receive => match p.rcvd_info {
            RcvdInfo::SuperiorDesignated => State::SuperiorDesignated,
            RcvdInfo::RepeatedDesignated => State::RepeatedDesignated,
            RcvdInfo::InferiorDesignated => State::InferiorDesignated,
            RcvdInfo::InferiorRootAlternate => State::NotDesignated,
            RcvdInfo::Other => State::Other,
        },
        State::SuperiorDesignated
        | State::RepeatedDesignated
        | State::InferiorDesignated
        | State::NotDesignated
        | State::Other => State::Current,
        _ => return false,
    };
    enter(b, i, next);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpdu::Bpdu;
    use crate::machines::tests::{bridge, msg};

    fn current(b: &mut Bridge) {
        b.ports[0].port_enabled = true;
        b.ports[0].pim = State::Current;
        b.ports[0].info_is = InfoIs::Mine;
    }

    #[test]
    fn disabled_to_aged_to_update_to_current() {
        let mut b = bridge(1);
        b.ports[0].port_enabled = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].pim, State::Aged);
        assert_eq!(b.ports[0].info_is, InfoIs::Aged);
        assert!(!step(&mut b, 0), "AGED waits for selected && updtInfo");
        b.ports[0].selected = true;
        b.ports[0].updt_info = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].pim, State::Update);
        assert_eq!(
            (
                b.ports[0].info_is,
                b.ports[0].updt_info,
                b.ports[0].new_info
            ),
            (InfoIs::Mine, false, true)
        );
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].pim, State::Current);
    }

    #[test]
    fn disabled_drops_pending_message() {
        let mut b = bridge(1);
        b.ports[0].rcvd_msg = true;
        assert!(step(&mut b, 0));
        assert!(!b.ports[0].rcvd_msg);
    }

    #[test]
    fn any_state_to_disabled_when_port_goes_down() {
        let mut b = bridge(1);
        current(&mut b);
        b.ports[0].port_enabled = false;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].pim, State::Disabled);
        assert_eq!(b.ports[0].info_is, InfoIs::Disabled);
    }

    #[test]
    fn current_to_update_and_to_aged() {
        let mut b = bridge(1);
        current(&mut b);
        b.ports[0].selected = true;
        b.ports[0].updt_info = true;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].pim, State::Update);
        current(&mut b);
        b.ports[0].info_is = InfoIs::Received;
        b.ports[0].rcvd_info_while = 0;
        assert!(step(&mut b, 0));
        assert_eq!(b.ports[0].pim, State::Aged);
    }

    fn receive(b: &mut Bridge, m: Bpdu) -> State {
        current(b);
        b.ports[0].msg = Some(m);
        b.ports[0].rcvd_msg = true;
        assert!(step(b, 0));
        assert_eq!(b.ports[0].pim, State::Receive);
        assert!(step(b, 0));
        let s = b.ports[0].pim;
        assert!(step(b, 0));
        assert_eq!(b.ports[0].pim, State::Current);
        assert!(!b.ports[0].rcvd_msg);
        s
    }

    #[test]
    fn receive_superior() {
        let mut b = bridge(5);
        let s = receive(
            &mut b,
            msg(1, 0, 1, 1, crate::bpdu::PortRole::Designated, 0),
        );
        assert_eq!(s, State::SuperiorDesignated);
        let p = &b.ports[0];
        assert_eq!(p.info_is, InfoIs::Received);
        assert!(p.reselect && !p.selected);
        assert_eq!(p.port_priority.root.mac()[5], 1);
        assert!(p.rcvd_info_while > 0);
    }

    #[test]
    fn receive_repeated_then_inferior() {
        let mut b = bridge(5);
        receive(
            &mut b,
            msg(1, 0, 1, 1, crate::bpdu::PortRole::Designated, 0),
        );
        let again = msg(1, 0, 1, 1, crate::bpdu::PortRole::Designated, 0);
        assert_eq!(receive(&mut b, again), State::RepeatedDesignated);
        b.ports[0].info_is = InfoIs::Received;
        // Same root, other designated bridge, worse cost.
        let worse = msg(1, 7, 3, 1, crate::bpdu::PortRole::Designated, 0);
        assert_eq!(receive(&mut b, worse), State::InferiorDesignated);
    }

    #[test]
    fn receive_same_sender_changed_info_is_superior() {
        let mut b = bridge(5);
        receive(
            &mut b,
            msg(1, 0, 1, 1, crate::bpdu::PortRole::Designated, 0),
        );
        // Its cost grew: worse, but the same designated bridge/port => accepted.
        let grew = msg(1, 9, 1, 1, crate::bpdu::PortRole::Designated, 0);
        assert_eq!(receive(&mut b, grew), State::SuperiorDesignated);
    }

    /// `msg(1, 0, 1, 1, Designated)` with the sender's priorities replaced.
    fn msg_with(bridge: crate::vector::BridgeId, port: crate::vector::PortId) -> Bpdu {
        let Bpdu::Rst(mut pr) = msg(1, 0, 1, 1, crate::bpdu::PortRole::Designated, 0) else {
            unreachable!()
        };
        pr.bridge = bridge;
        pr.port = port;
        Bpdu::Rst(pr)
    }

    #[test]
    fn receive_sender_priority_change_is_the_same_sender() {
        use crate::vector::{BridgeId, PortId};
        // 13.29 rcvInfo: sender identity is address + port number.
        let mut b = bridge(5);
        receive(
            &mut b,
            msg(1, 0, 1, 1, crate::bpdu::PortRole::Designated, 0),
        );
        b.ports[0].info_is = InfoIs::Received;
        let worse_bridge = BridgeId::new(36864, 0, [0, 0, 0, 0, 0, 1]).unwrap();
        let same_port = PortId::new(128, 1).unwrap();
        assert_eq!(
            receive(&mut b, msg_with(worse_bridge, same_port)),
            State::SuperiorDesignated
        );
        assert_eq!(b.ports[0].port_priority.designated_bridge, worse_bridge);
        // Same number, worse port priority.
        let worse_port = PortId::new(144, 1).unwrap();
        assert_eq!(
            receive(&mut b, msg_with(worse_bridge, worse_port)),
            State::SuperiorDesignated
        );
        assert_eq!(b.ports[0].port_priority.designated_port, worse_port);
        // A different MAC is a different sender: worse stays inferior.
        let other = BridgeId::new(36864, 0, [0, 0, 0, 0, 0, 3]).unwrap();
        assert_eq!(
            receive(&mut b, msg_with(other, worse_port)),
            State::InferiorDesignated
        );
    }

    #[test]
    fn receive_root_role_worse_is_not_designated_and_records_agreement() {
        let mut b = bridge(1);
        let flags = crate::bpdu::Flags::AGREEMENT;
        let m = msg(1, 40, 7, 1, crate::bpdu::PortRole::Root, flags);
        b.ports[0].proposing = true;
        assert_eq!(receive(&mut b, m), State::NotDesignated);
        assert!(b.ports[0].agreed && !b.ports[0].proposing);
    }

    #[test]
    fn receive_other() {
        let mut b = bridge(5);
        // A Root-role message better than our port priority is nonsense.
        let m = msg(0, 0, 0, 1, crate::bpdu::PortRole::Root, 0);
        assert_eq!(receive(&mut b, m), State::Other);
    }

    #[test]
    fn update_keeps_agreed_only_if_info_not_worse() {
        let mut b = bridge(1);
        let p = &mut b.ports[0];
        p.info_is = InfoIs::Mine;
        p.port_priority = p.designated_priority;
        p.agreed = true;
        p.synced = true;
        p.proposing = true;
        enter(&mut b, 0, State::Update);
        assert!(b.ports[0].agreed && b.ports[0].synced && !b.ports[0].proposing);
        let p = &mut b.ports[0];
        p.info_is = InfoIs::Aged;
        enter(&mut b, 0, State::Update);
        assert!(!b.ports[0].agreed && !b.ports[0].synced);
    }
}
