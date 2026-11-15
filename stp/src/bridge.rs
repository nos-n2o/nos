//! Bridge-wide state and the "run every machine until quiescent" driver.
//!
//! Time only enters through [`Bridge::tick`] (once per second, the granularity
//! of every 13.22 timer); the host feeds `portEnabled`, `operPointToPoint`,
//! `operEdge` (admin) and received BPDUs, then drains [`Bridge::take_actions`].

use crate::actions::{Action, Event};
use crate::bpdu::Bpdu;
use crate::machines::{
    bdm, pim, ppm, prs, prt, prx, pst, ptx, tcm, Port, Protections, Role, Times,
};
use crate::timers::Timers;
use crate::vector::{BridgeId, PortId, PriorityVector};

/// Hard cap on full machine passes in one `run` (non-convergence = a bug).
const MAX_PASSES: usize = 1000;

#[derive(Debug, Clone, Copy)]
pub struct PortParams {
    pub id: PortId,
    pub path_cost: u32,
    pub admin_edge: bool,
    pub auto_edge: bool,
}

pub struct Bridge {
    pub id: BridgeId,
    pub timers: Timers,
    /// `BridgeTimes`: this bridge's own timers, message age 0.
    pub bridge_times: Times,
    /// `rootTimes`: the root's timers as learnt (== `bridge_times` at the root).
    pub root_times: Times,
    /// `rstpVersion`: false forces STP compatibility (`force-version`, #319).
    pub rstp_version: bool,
    pub ports: Vec<Port>,
    /// Index of the Root Port, `None` when this bridge is the root.
    pub root_port: Option<usize>,
    /// Identifier of the root bridge as currently computed (this bridge when it is the root).
    pub root_id: BridgeId,
    pub prs: prs::State,
    pub(crate) actions: Vec<Action>,
}

impl Bridge {
    /// BEGIN: every machine in its initial state, all ports disabled.
    pub fn new(id: BridgeId, timers: Timers, ports: &[PortParams]) -> Self {
        let times = Times {
            message_age: 0,
            max_age: timers.max_age,
            hello: timers.hello,
            forward_delay: timers.forward_delay,
        };
        let pv = PriorityVector {
            root: id,
            root_path_cost: 0,
            designated_bridge: id,
            designated_port: PortId::from_u16(0),
            bridge_port: PortId::from_u16(0),
        };
        let mut b = Bridge {
            id,
            timers,
            bridge_times: times,
            root_times: times,
            rstp_version: true,
            ports: ports
                .iter()
                .map(|p| Port::new(p.id, p.path_cost, p.admin_edge, p.auto_edge, pv, times))
                .collect(),
            root_port: None,
            root_id: id,
            prs: prs::State::InitBridge,
            actions: Vec::new(),
        };
        for i in 0..b.ports.len() {
            b.init_port(i);
        }
        b.run();
        b
    }

    /// BEGIN for one port: every port machine in its initial state.
    fn init_port(&mut self, i: usize) {
        let b = self;
        prx::enter(b, i, prx::State::Discard);
        pim::enter(b, i, pim::State::Disabled);
        prt::enter(b, i, prt::State::InitPort);
        pst::enter(b, i, pst::State::Discarding);
        tcm::enter(b, i, tcm::State::Inactive);
        ppm::enter(b, i, ppm::State::CheckingRstp);
        ptx::enter(b, i, ptx::State::TransmitInit);
        let s = if b.ports[i].admin_edge {
            bdm::State::Edge
        } else {
            bdm::State::NotEdge
        };
        bdm::enter(b, i, s);
    }

    /// A new port, disabled and discarding; returns its index (#662).
    pub fn add_port(&mut self, p: PortParams) -> usize {
        let pv = PriorityVector {
            root: self.id,
            root_path_cost: 0,
            designated_bridge: self.id,
            designated_port: PortId::from_u16(0),
            bridge_port: PortId::from_u16(0),
        };
        self.ports.push(Port::new(
            p.id,
            p.path_cost,
            p.admin_edge,
            p.auto_edge,
            pv,
            self.bridge_times,
        ));
        let i = self.ports.len() - 1;
        self.init_port(i);
        self.run();
        i
    }

    /// New Port Identifier (priority) for `port`; re-runs role selection.
    pub fn set_port_priority(&mut self, port: usize, id: PortId) {
        let p = &mut self.ports[port];
        p.port_id = id;
        p.reselect = true;
        p.selected = false;
        self.run();
    }

    /// Admin and auto edge of `port` (BDM reads both on every pass).
    pub fn set_edge(&mut self, port: usize, admin: bool, auto: bool) {
        let p = &mut self.ports[port];
        p.admin_edge = admin;
        p.auto_edge = auto;
        self.run();
    }

    /// New bridge timers: the root's too while this bridge is the root.
    pub fn set_timers(&mut self, timers: Timers) {
        self.timers = timers;
        let times = Times {
            message_age: 0,
            max_age: timers.max_age,
            hello: timers.hello,
            forward_delay: timers.forward_delay,
        };
        self.bridge_times = times;
        if self.root_port.is_none() {
            self.root_times = times;
        }
        for p in &mut self.ports {
            p.reselect = true;
            p.selected = false;
        }
        self.run();
    }

    pub fn take_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    /// One second elapsed.
    pub fn tick(&mut self) {
        self.ports.iter_mut().for_each(Port::tick);
        for i in 0..self.ports.len() {
            match self.ports[i].err_remaining {
                Some(1) => self.clear_err_disabled(i),
                Some(n) => self.ports[i].err_remaining = Some(n - 1),
                None => {}
            }
        }
        self.run();
    }

    /// Install a port's protections (#320); call before the port comes up.
    pub fn set_protections(&mut self, port: usize, prot: Protections) {
        let p = &mut self.ports[port];
        p.prot = prot;
        p.reselect = true;
        self.run();
    }

    /// Whether BPDU guard holds `port` down, and the seconds to automatic
    /// recovery (`Some(None)`: manual `clear`).
    pub fn err_disabled(&self, port: usize) -> Option<Option<u32>> {
        let p = &self.ports[port];
        p.err_disabled.then_some(p.err_remaining)
    }

    /// Put `port` back in the err-disabled state it had before the bridge was
    /// rebuilt (a plan change must not recover it).
    pub fn restore_err_disabled(&mut self, port: usize, remaining: Option<u32>) {
        let p = &mut self.ports[port];
        p.err_disabled = true;
        p.err_remaining = remaining;
        self.refresh_enabled(port);
    }

    /// Lift err-disable (recovery timer, `clear`, guard removed). The link
    /// comes back through the host's `set_port_enabled`.
    pub fn clear_err_disabled(&mut self, port: usize) {
        let p = &mut self.ports[port];
        if std::mem::take(&mut p.err_disabled) {
            p.err_remaining = None;
            self.actions.push(Action::ErrRecover { port });
            self.refresh_enabled(port);
        }
    }

    pub fn receive(&mut self, port: usize, bpdu: Bpdu) {
        let p = &mut self.ports[port];
        if p.prot.bpdu_filter || p.err_disabled {
            return;
        }
        if p.prot.bpdu_guard && p.oper_edge && p.port_enabled {
            p.err_disabled = true;
            p.err_remaining = p.prot.recovery;
            self.actions.push(Action::ErrDisable { port });
            self.refresh_enabled(port);
            return;
        }
        p.rcvd = Some(bpdu);
        p.rcvd_bpdu = true;
        self.run();
    }

    pub fn set_port_enabled(&mut self, port: usize, up: bool) {
        self.ports[port].link_up = up;
        self.refresh_enabled(port);
    }

    /// `portEnabled` is the host's link state unless BPDU guard holds the port.
    fn refresh_enabled(&mut self, port: usize) {
        let p = &mut self.ports[port];
        p.port_enabled = p.link_up && !p.err_disabled;
        self.run();
    }

    pub fn set_oper_point_to_point(&mut self, port: usize, p2p: bool) {
        self.ports[port].oper_point_to_point = p2p;
        self.run();
    }

    pub fn set_path_cost(&mut self, port: usize, cost: u32) {
        self.ports[port].path_cost = cost;
        self.ports[port].reselect = true;
        self.run();
    }

    /// Change the bridge identifier (priority) and re-run role selection.
    pub fn set_bridge_id(&mut self, id: BridgeId) {
        self.id = id;
        for p in &mut self.ports {
            p.reselect = true;
            p.selected = false;
        }
        self.run();
    }

    /// `forceVersion` (13.7): `false` is 802.1D, no RSTP BPDU is ever sent.
    /// Restarts the PPM machines, so call it before the ports come up.
    pub fn set_rstp_version(&mut self, rstp: bool) {
        self.rstp_version = rstp;
        for i in 0..self.ports.len() {
            ppm::enter(self, i, ppm::State::CheckingRstp);
        }
        self.run();
    }

    /// Management `mcheck` (13.7): probe `port` for RSTP again. A peer that
    /// still sends STP BPDUs moves it straight back after Migrate Time.
    pub fn mcheck(&mut self, port: usize) {
        self.ports[port].mcheck = true;
        self.run();
    }

    pub fn role(&self, port: usize) -> Role {
        self.ports[port].role
    }

    pub fn port_state(&self, port: usize) -> crate::actions::PortState {
        use crate::actions::PortState;
        let p = &self.ports[port];
        if p.forwarding {
            PortState::Forwarding
        } else if p.learning {
            PortState::Learning
        } else {
            PortState::Discarding
        }
    }

    /// Run every machine until a full pass changes nothing.
    pub fn run(&mut self) {
        for _ in 0..MAX_PASSES {
            let mut changed = prs::step(self);
            for i in 0..self.ports.len() {
                changed |= prx::step(self, i);
                changed |= ppm::step(self, i);
                changed |= bdm::step(self, i);
                changed |= pim::step(self, i);
                changed |= prt::step(self, i);
                changed |= pst::step(self, i);
                changed |= tcm::step(self, i);
                changed |= ptx::step(self, i);
            }
            if !changed {
                return;
            }
        }
        debug_assert!(false, "state machines did not reach quiescence");
        self.actions.push(Action::Log(Event::NotQuiescent));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpdu::{raw_secs, Flags, Params};
    use crate::machines::tests::{bid, bridge};

    #[test]
    fn legacy_config_bpdu_puts_only_that_port_in_stp_mode() {
        let mut b = bridge(5);
        b.set_port_enabled(0, true);
        b.set_port_enabled(1, true);
        for _ in 0..3 {
            b.tick(); // Migrate Time: CHECKING_RSTP -> SENSING
        }
        let config = Bpdu::Config(Params {
            flags: Flags::default(),
            root: bid(1),
            root_path_cost: 0,
            bridge: bid(1),
            port: PortId::new(128, 1).unwrap(),
            message_age: 0,
            max_age: raw_secs(20),
            hello_time: raw_secs(2),
            forward_delay: raw_secs(15),
        });
        b.receive(0, config);
        assert_eq!(b.role(0), Role::Root);
        assert!(!b.ports[0].send_rstp, "port 0 talks STP to a legacy peer");
        assert!(b.ports[1].send_rstp, "port 1 is unaffected");
    }

    fn edge_bridge(prot: Protections) -> Bridge {
        let mut b = bridge(5);
        b.ports[0].admin_edge = true;
        b.set_protections(0, prot);
        bdm_edge(&mut b);
        b.set_port_enabled(0, true);
        b
    }

    fn bdm_edge(b: &mut Bridge) {
        bdm::enter(b, 0, bdm::State::Edge);
    }

    fn superior(b: &mut Bridge, port: usize) {
        b.receive(port, crate::machines::tests::rst(b, port, false));
    }

    #[test]
    fn bpdu_guard_err_disables_an_edge_port_and_it_recovers() {
        let prot = Protections {
            bpdu_guard: true,
            recovery: Some(3),
            ..Default::default()
        };
        let mut b = edge_bridge(prot);
        b.take_actions();
        superior(&mut b, 0);
        assert!(b.take_actions().contains(&Action::ErrDisable { port: 0 }));
        assert!(b.ports[0].link_up, "the host's view of the link is kept");
        assert_eq!(b.err_disabled(0), Some(Some(3)));
        assert!(!b.ports[0].port_enabled);
        b.set_port_enabled(0, true);
        assert!(!b.ports[0].port_enabled, "a link event cannot lift it");
        b.tick();
        b.tick();
        assert!(b.err_disabled(0).is_some());
        b.tick();
        assert_eq!(b.err_disabled(0), None);
        assert!(b.take_actions().contains(&Action::ErrRecover { port: 0 }));
        b.set_port_enabled(0, true);
        assert!(b.ports[0].port_enabled);
    }

    #[test]
    fn bpdu_guard_without_recovery_waits_for_clear_and_ignores_non_edge() {
        let prot = Protections {
            bpdu_guard: true,
            ..Default::default()
        };
        let mut b = edge_bridge(prot);
        superior(&mut b, 0);
        for _ in 0..50 {
            b.tick();
        }
        assert_eq!(b.err_disabled(0), Some(None));
        b.clear_err_disabled(0);
        assert_eq!(b.err_disabled(0), None);
        assert!(b.ports[0].port_enabled, "the link never went down");
        // A port that is not operEdge is not guarded (port 1 has no edge).
        b.set_protections(1, prot);
        b.set_port_enabled(1, true);
        superior(&mut b, 1);
        assert_eq!(b.err_disabled(1), None);
    }

    #[test]
    fn bpdu_filter_drops_both_directions() {
        let prot = Protections {
            bpdu_filter: true,
            ..Default::default()
        };
        let mut b = bridge(5);
        b.set_protections(0, prot);
        b.set_port_enabled(0, true);
        for _ in 0..5 {
            b.tick();
        }
        assert!(!b
            .take_actions()
            .iter()
            .any(|a| matches!(a, Action::Transmit { port: 0, .. })));
        superior(&mut b, 0);
        assert_eq!(b.root_port, None, "the BPDU was not processed");
    }

    #[test]
    fn root_guard_keeps_a_superior_port_out_of_root() {
        let mut b = bridge(5);
        b.set_protections(
            0,
            Protections {
                root_guard: true,
                ..Default::default()
            },
        );
        b.set_port_enabled(0, true);
        b.set_port_enabled(1, true);
        superior(&mut b, 0);
        assert_eq!(b.root_port, None);
        assert_eq!(b.role(0), Role::Alternate);
        assert!(b.ports[0].root_inconsistent);
        assert!(b
            .take_actions()
            .contains(&Action::Log(Event::RootInconsistent { port: 0, on: true })));
        // The same BPDU on an unguarded port wins the root.
        superior(&mut b, 1);
        assert_eq!(b.root_port, Some(1));
        // Silence ages the info out and the port is consistent again.
        for _ in 0..8 {
            b.tick();
        }
        assert!(!b.ports[0].root_inconsistent);
    }

    #[test]
    fn loop_guard_holds_a_port_whose_bpdus_stop_until_one_returns() {
        let mut b = bridge(5);
        b.set_protections(
            0,
            Protections {
                loop_guard: true,
                ..Default::default()
            },
        );
        b.set_port_enabled(0, true);
        superior(&mut b, 0);
        assert_eq!(b.role(0), Role::Root);
        for _ in 0..8 {
            b.tick(); // 3 * hello of silence
        }
        assert!(b.ports[0].loop_inconsistent);
        assert_eq!(b.role(0), Role::Alternate);
        assert_eq!(b.port_state(0), crate::actions::PortState::Discarding);
        for _ in 0..60 {
            b.tick();
        }
        assert_eq!(b.role(0), Role::Alternate, "stays held while silent");
        superior(&mut b, 0);
        assert!(!b.ports[0].loop_inconsistent);
        assert_eq!(b.role(0), Role::Root);
        // A link flap also clears it.
        for _ in 0..8 {
            b.tick();
        }
        assert!(b.ports[0].loop_inconsistent);
        b.set_port_enabled(0, false);
        assert!(!b.ports[0].loop_inconsistent);
    }

    #[test]
    fn without_loop_guard_a_silent_port_becomes_designated() {
        let mut b = bridge(5);
        b.set_port_enabled(0, true);
        superior(&mut b, 0);
        for _ in 0..8 {
            b.tick();
        }
        assert_eq!(b.role(0), Role::Designated);
    }

    #[test]
    fn restricted_tcn_stops_propagation_of_a_received_tc() {
        let tc = |b: &Bridge| {
            let Bpdu::Rst(mut p) = crate::machines::tests::rst(b, 0, false) else {
                unreachable!()
            };
            p.flags = p.flags.with(Flags::TC, true);
            Bpdu::Rst(p)
        };
        for restricted in [false, true] {
            let mut b = bridge(5);
            b.set_protections(
                0,
                Protections {
                    restricted_tcn: restricted,
                    ..Default::default()
                },
            );
            b.set_port_enabled(0, true);
            b.set_port_enabled(1, true);
            for _ in 0..40 {
                b.tick();
            }
            b.take_actions();
            let m = tc(&b);
            b.receive(0, m);
            let flushed = b
                .take_actions()
                .iter()
                .any(|a| matches!(a, Action::FlushFdb { port: 1 }));
            assert_eq!(flushed, !restricted, "restricted={restricted}");
        }
    }

    #[test]
    fn nothing_is_sent_on_a_down_port() {
        let mut b = bridge(5);
        b.tick();
        assert!(!b
            .take_actions()
            .iter()
            .any(|a| matches!(a, Action::Transmit { .. })));
    }
}
