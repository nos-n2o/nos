//! IEEE 802.1Q-2022 clause 13 CIST state machines (pure; no I/O, no clock).
//!
//! One module per machine. Each exposes `step(&mut Bridge, port) -> bool` (one
//! transition, `true` if anything changed) and `enter`/`begin` for state entry.
//! The shared per-port variables (13.27) and procedures (13.30) live here.
//! A [`Bridge`] is one tree: the CIST, or an MSTI (`crate::mst`).
#![allow(clippy::struct_excessive_bools)] // 13.27 is a list of booleans

pub mod bdm;
pub mod pim;
pub mod ppm;
pub mod prs;
pub mod prt;
pub mod prx;
pub mod pst;
pub mod ptx;
pub mod tcm;

use crate::actions::Action;
use crate::bpdu::{raw_secs, secs, Bpdu, Flags, Params, PortRole};
use crate::bridge::Bridge;
use crate::vector::{BridgeId, PortId, PriorityVector};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Disabled,
    Root,
    Designated,
    Alternate,
    Backup,
}

/// 13.27 `infoIs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoIs {
    Mine,
    Aged,
    Received,
    Disabled,
}

/// 13.27 `rcvdInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcvdInfo {
    SuperiorDesignated,
    RepeatedDesignated,
    InferiorDesignated,
    InferiorRootAlternate,
    Other,
}

/// Timer parameters carried in a BPDU / held per port (whole seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Times {
    pub message_age: u8,
    pub max_age: u8,
    pub hello: u8,
    pub forward_delay: u8,
}

impl Times {
    fn from_params(p: &Params) -> Self {
        Times {
            message_age: secs(p.message_age),
            max_age: secs(p.max_age),
            // ponytail: a Hello Time of 0 would age info out instantly, clamp to 1 s.
            hello: secs(p.hello_time).max(1),
            forward_delay: secs(p.forward_delay),
        }
    }
}

/// The port protections of an `stp-port-profile` (#320). `restricted_role` /
/// `restricted_tcn` are 802.1Q 13.25; the rest are vendor-style and live in
/// `Bridge::receive`, `transmit` and the PIM/PRS machines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Protections {
    /// An `operEdge` port that receives a BPDU is err-disabled.
    pub bpdu_guard: bool,
    /// Seconds before an err-disabled port recovers; `None`: manual.
    pub recovery: Option<u32>,
    /// No BPDU is sent or processed on this port.
    pub bpdu_filter: bool,
    /// `restrictedRole`: never the Root Port.
    pub root_guard: bool,
    /// A Root/Alternate port whose BPDUs stop arriving stays Discarding.
    pub loop_guard: bool,
    /// `restrictedTcn`: a TC received here is not propagated.
    pub restricted_tcn: bool,
}

/// Per-port variables (13.27) and machine states.
pub struct Port {
    pub prot: Protections,
    /// Root guard holds the port as Alternate (a superior BPDU keeps arriving).
    pub root_inconsistent: bool,
    /// Loop guard holds the port as Alternate (BPDUs stopped arriving).
    pub loop_inconsistent: bool,
    /// What the host last said about the link, whatever err-disable did.
    pub link_up: bool,
    /// BPDU guard shut the port; only `Bridge::clear_err_disabled` (or the
    /// recovery timer) lifts it.
    pub err_disabled: bool,
    /// Seconds to automatic recovery; `None`: manual.
    pub err_remaining: Option<u32>,
    // Host inputs.
    pub port_id: PortId,
    pub path_cost: u32,
    pub port_enabled: bool,
    pub oper_point_to_point: bool,
    pub admin_edge: bool,
    pub auto_edge: bool,
    /// Management `mcheck` (`Bridge::mcheck`).
    pub mcheck: bool,
    // Machine variables.
    pub oper_edge: bool,
    pub agree: bool,
    pub agreed: bool,
    pub designated_priority: PriorityVector,
    pub designated_times: Times,
    pub disputed: bool,
    pub fdb_flush: bool,
    pub forward: bool,
    pub forwarding: bool,
    pub info_is: InfoIs,
    pub learn: bool,
    pub learning: bool,
    pub msg_priority: PriorityVector,
    pub msg_times: Times,
    pub new_info: bool,
    pub port_priority: PriorityVector,
    pub port_times: Times,
    pub proposed: bool,
    pub proposing: bool,
    pub rcvd_bpdu: bool,
    pub rcvd_info: RcvdInfo,
    pub rcvd_msg: bool,
    pub rcvd_rstp: bool,
    pub rcvd_stp: bool,
    pub rcvd_tc: bool,
    pub rcvd_tc_ack: bool,
    pub rcvd_tcn: bool,
    pub re_root: bool,
    pub reselect: bool,
    pub role: Role,
    pub selected_role: Role,
    pub selected: bool,
    pub send_rstp: bool,
    pub sync: bool,
    pub synced: bool,
    pub tc_ack: bool,
    pub tc_prop: bool,
    pub tx_count: u8,
    pub updt_info: bool,
    /// 13.22 timers, seconds.
    pub edge_delay_while: u8,
    pub fd_while: u8,
    pub hello_when: u8,
    pub mdelay_while: u8,
    pub rb_while: u8,
    pub rcvd_info_while: u8,
    pub rr_while: u8,
    pub tc_while: u8,
    // Machine states.
    pub prx: prx::State,
    pub pim: pim::State,
    pub prt: prt::State,
    pub pst: pst::State,
    pub tcm: tcm::State,
    pub ppm: ppm::State,
    pub ptx: ptx::State,
    pub bdm: bdm::State,
    /// The BPDU the host delivered, until PRX consumes it.
    pub(crate) rcvd: Option<Bpdu>,
    /// The BPDU PIM is judging (set by PRX).
    pub(crate) msg: Option<Bpdu>,
}

impl Port {
    pub(crate) fn new(
        port_id: PortId,
        path_cost: u32,
        admin_edge: bool,
        auto_edge: bool,
        bridge_priority: PriorityVector,
        times: Times,
    ) -> Self {
        Port {
            prot: Protections::default(),
            root_inconsistent: false,
            loop_inconsistent: false,
            err_disabled: false,
            err_remaining: None,
            link_up: false,
            port_id,
            path_cost,
            port_enabled: false,
            oper_point_to_point: true,
            admin_edge,
            auto_edge,
            mcheck: false,
            oper_edge: admin_edge,
            agree: false,
            agreed: false,
            designated_priority: bridge_priority,
            designated_times: times,
            disputed: false,
            fdb_flush: false,
            forward: false,
            forwarding: false,
            info_is: InfoIs::Disabled,
            learn: false,
            learning: false,
            msg_priority: bridge_priority,
            msg_times: times,
            new_info: false,
            port_priority: bridge_priority,
            port_times: times,
            proposed: false,
            proposing: false,
            rcvd_bpdu: false,
            rcvd_info: RcvdInfo::Other,
            rcvd_msg: false,
            rcvd_rstp: false,
            rcvd_stp: false,
            rcvd_tc: false,
            rcvd_tc_ack: false,
            rcvd_tcn: false,
            re_root: false,
            reselect: false,
            role: Role::Disabled,
            selected_role: Role::Disabled,
            selected: false,
            send_rstp: true,
            sync: false,
            synced: false,
            tc_ack: false,
            tc_prop: false,
            tx_count: 0,
            updt_info: false,
            edge_delay_while: 0,
            fd_while: 0,
            hello_when: 0,
            mdelay_while: 0,
            rb_while: 0,
            rcvd_info_while: 0,
            rr_while: 0,
            tc_while: 0,
            prx: prx::State::Discard,
            pim: pim::State::Disabled,
            prt: prt::State::InitPort,
            pst: pst::State::Discarding,
            tcm: tcm::State::Inactive,
            ppm: ppm::State::CheckingRstp,
            ptx: ptx::State::TransmitInit,
            bdm: bdm::State::NotEdge,
            rcvd: None,
            msg: None,
        }
    }

    /// Decrement the 13.22 timers (once per second).
    pub(crate) fn tick(&mut self) {
        for t in [
            &mut self.edge_delay_while,
            &mut self.fd_while,
            &mut self.hello_when,
            &mut self.mdelay_while,
            &mut self.rb_while,
            &mut self.rcvd_info_while,
            &mut self.rr_while,
            &mut self.tc_while,
        ] {
            *t = t.saturating_sub(1);
        }
        // Port Timers SM decrements txCount once per second (802.1D-2004 17.19.44 /
        // 802.1Q 13.25; same as mstpd's PTSM_tick), it is not reset (#695).
        self.tx_count = self.tx_count.saturating_sub(1);
    }
}

// ---- 13.28 / 13.30 shared conditions and procedures ----

/// `FwdDelay` / `MaxAge` / `HelloTime` / `EdgeDelay` (the bridge's current root times).
pub(crate) fn fwd_delay(b: &Bridge) -> u8 {
    b.root_times.forward_delay
}
pub(crate) fn max_age(b: &Bridge) -> u8 {
    b.root_times.max_age
}
pub(crate) fn hello(b: &Bridge) -> u8 {
    b.root_times.hello
}
pub(crate) fn edge_delay(b: &Bridge, i: usize) -> u8 {
    if b.ports[i].oper_point_to_point {
        b.timers.migrate_time
    } else {
        max_age(b)
    }
}

/// 13.28 `allSynced` (CIST): every port is selected, in its selected role, up
/// to date, and either synced or the Root Port (which has nothing to sync).
pub(crate) fn all_synced(b: &Bridge) -> bool {
    b.ports.iter().all(|p| {
        p.selected
            && p.role == p.selected_role
            && !p.updt_info
            && (p.synced || p.role == Role::Root)
    })
}

/// 13.28 `reRooted`: no *other* port has a running `rrWhile`.
pub(crate) fn re_rooted(b: &Bridge, i: usize) -> bool {
    b.ports
        .iter()
        .enumerate()
        .all(|(j, p)| j == i || p.rr_while == 0)
}

/// 13.30 `setSyncTree`. Also clears `synced`: with `sync && synced` already true
/// a Designated port would neither discard (needs `!synced`) nor ever clear
/// `sync` (`DESIGNATED_SYNCED` needs `!synced`), and it would stall for good.
pub(crate) fn set_sync_tree(b: &mut Bridge) {
    for p in &mut b.ports {
        p.sync = true;
        p.synced = false;
    }
}

pub(crate) fn set_re_root_tree(b: &mut Bridge) {
    b.ports.iter_mut().for_each(|p| p.re_root = true);
}

/// Every other port gets `tcProp` (the caller checks `restrictedTcn`).
pub(crate) fn set_tc_prop_tree(b: &mut Bridge, i: usize) {
    for (j, p) in b.ports.iter_mut().enumerate() {
        if j != i {
            p.tc_prop = true;
        }
    }
}

pub(crate) fn new_tc_while(b: &mut Bridge, i: usize) {
    let (hello, age, fd) = (hello(b), max_age(b), fwd_delay(b));
    let p = &mut b.ports[i];
    if p.tc_while == 0 {
        if p.send_rstp {
            p.tc_while = hello + 1;
            p.new_info = true;
        } else {
            p.tc_while = age.saturating_add(fd);
        }
    }
}

/// 13.30 `betterorsameInfo`.
pub(crate) fn better_or_same_info(p: &Port, new: InfoIs) -> bool {
    match new {
        InfoIs::Received => {
            p.info_is == InfoIs::Received && !p.msg_priority.worse_than(&p.port_priority)
        }
        InfoIs::Mine => {
            p.info_is == InfoIs::Mine && !p.designated_priority.worse_than(&p.port_priority)
        }
        _ => false,
    }
}

/// The Params and role of the BPDU PIM is judging (`None` for TCN).
pub(crate) fn msg_params(p: &Port) -> Option<(Params, PortRole)> {
    match p.msg? {
        Bpdu::Config(pr) => Some((pr, PortRole::Designated)),
        Bpdu::Rst(pr) => Some((pr, pr.flags.role())),
        Bpdu::Tcn => None,
    }
}

/// 13.30 `rcvInfo`: fills `msgPriority`/`msgTimes` and classifies the BPDU.
pub(crate) fn rcv_info(p: &mut Port) -> RcvdInfo {
    let Some((pr, role)) = msg_params(p) else {
        return RcvdInfo::Other;
    };
    p.msg_priority = PriorityVector::from_bpdu(&pr, p.port_id);
    p.msg_times = Times::from_params(&pr);
    match role {
        PortRole::Designated => {
            // Sender identity is bridge address + port number; a priority
            // change is the same sender with new info (13.29 rcvInfo).
            let same_sender = p
                .msg_priority
                .designated_bridge
                .same_address(&p.port_priority.designated_bridge)
                && p.msg_priority
                    .designated_port
                    .same_number(&p.port_priority.designated_port);
            let same_all = p.msg_priority == p.port_priority && p.msg_times == p.port_times;
            if p.msg_priority.better_than(&p.port_priority) || (same_sender && !same_all) {
                RcvdInfo::SuperiorDesignated
            } else if same_all {
                RcvdInfo::RepeatedDesignated
            } else {
                RcvdInfo::InferiorDesignated
            }
        }
        PortRole::Root | PortRole::AlternateBackup
            if !p.msg_priority.better_than(&p.port_priority) =>
        {
            RcvdInfo::InferiorRootAlternate
        }
        _ => RcvdInfo::Other,
    }
}

/// 13.30 `recordProposal`.
pub(crate) fn record_proposal(p: &mut Port) {
    if let Some((pr, PortRole::Designated)) = msg_params(p)
        && pr.flags.has(Flags::PROPOSAL)
    {
        p.proposed = true;
    }
}

/// 13.30 `recordAgreement`.
pub(crate) fn record_agreement(rstp_version: bool, p: &mut Port) {
    let agreement = matches!(p.msg, Some(Bpdu::Rst(pr)) if pr.flags.has(Flags::AGREEMENT));
    if rstp_version && p.oper_point_to_point && agreement {
        p.agreed = true;
        p.proposing = false;
    } else {
        p.agreed = false;
    }
}

/// 13.30 `recordDispute`: a Learning flag from an inferior Designated sender.
pub(crate) fn record_dispute(p: &mut Port) {
    if matches!(p.msg, Some(Bpdu::Rst(pr)) if pr.flags.has(Flags::LEARNING)) {
        p.disputed = true;
        p.agreed = false;
    }
}

/// 13.30 `setTcFlags`.
pub(crate) fn set_tc_flags(p: &mut Port) {
    match p.msg {
        Some(Bpdu::Config(pr)) => {
            p.rcvd_tc |= pr.flags.has(Flags::TC);
            p.rcvd_tc_ack |= pr.flags.has(Flags::TC_ACK);
        }
        Some(Bpdu::Rst(pr)) => p.rcvd_tc |= pr.flags.has(Flags::TC),
        _ => {}
    }
}

/// 13.30 `updtRcvdInfoWhile`.
pub(crate) fn updt_rcvd_info_while(p: &mut Port) {
    p.rcvd_info_while = if p.port_times.message_age < p.port_times.max_age {
        p.port_times.hello.saturating_mul(3)
    } else {
        0
    };
}

#[derive(Clone, Copy)]
pub(crate) enum Tx {
    Config,
    Rst,
    Tcn,
}

/// The BPDU `txConfig` / `txRstp` / `txTcn` would send on port `i` now.
pub(crate) fn build(b: &Bridge, i: usize, kind: Tx) -> Bpdu {
    let id: BridgeId = b.id;
    let p = &b.ports[i];
    let dt = p.designated_times;
    let tc = Flags::default().with(Flags::TC, p.tc_while != 0);
    let params = |flags| Params {
        flags,
        root: p.designated_priority.root,
        root_path_cost: p.designated_priority.root_path_cost,
        bridge: id,
        port: p.port_id,
        message_age: raw_secs(dt.message_age),
        max_age: raw_secs(dt.max_age),
        hello_time: raw_secs(dt.hello),
        forward_delay: raw_secs(dt.forward_delay),
    };
    match kind {
        Tx::Tcn => Bpdu::Tcn,
        Tx::Config => Bpdu::Config(params(tc.with(Flags::TC_ACK, p.tc_ack))),
        Tx::Rst => {
            let role = match p.role {
                Role::Root => PortRole::Root,
                Role::Designated => PortRole::Designated,
                Role::Alternate | Role::Backup => PortRole::AlternateBackup,
                Role::Disabled => PortRole::Unknown,
            };
            Bpdu::Rst(params(
                tc.with_role(role)
                    .with(Flags::PROPOSAL, p.proposing)
                    .with(Flags::LEARNING, p.learning)
                    .with(Flags::FORWARDING, p.forwarding)
                    .with(Flags::AGREEMENT, p.agree),
            ))
        }
    }
}

/// 13.30 `txConfig` / `txRstp` / `txTcn`.
pub(crate) fn transmit(b: &mut Bridge, i: usize, kind: Tx) {
    if b.ports[i].prot.bpdu_filter {
        return;
    }
    let bpdu = build(b, i, kind);
    b.actions.push(Action::Transmit { port: i, bpdu });
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::bridge::PortParams;
    use crate::timers::Timers;

    pub fn bid(mac: u8) -> BridgeId {
        BridgeId::new(32768, 0, [0, 0, 0, 0, 0, mac]).unwrap()
    }

    /// A bridge with three disabled ports (numbers 1..=3, cost 20 000).
    pub fn bridge(mac: u8) -> Bridge {
        let ports: Vec<_> = (1..=3)
            .map(|n| PortParams {
                id: PortId::new(128, n).unwrap(),
                path_cost: 20_000,
                admin_edge: false,
                auto_edge: false,
            })
            .collect();
        Bridge::new(bid(mac), Timers::default(), &ports)
    }

    /// An RST BPDU as if sent by `bridge_mac`'s port `port_no` (default timers).
    pub fn msg(
        root: u8,
        cost: u32,
        bridge_mac: u8,
        port_no: u16,
        role: PortRole,
        flags: u8,
    ) -> Bpdu {
        Bpdu::Rst(Params {
            flags: Flags(flags).with_role(role),
            root: bid(root),
            root_path_cost: cost,
            bridge: bid(bridge_mac),
            port: PortId::new(128, port_no).unwrap(),
            message_age: 0,
            max_age: raw_secs(20),
            hello_time: raw_secs(2),
            forward_delay: raw_secs(15),
        })
    }

    /// A Designated RST BPDU from the (better) root bridge 0.
    pub fn rst(_b: &Bridge, _port: usize, proposal: bool) -> Bpdu {
        msg(
            0,
            0,
            0,
            1,
            PortRole::Designated,
            if proposal { Flags::PROPOSAL } else { 0 },
        )
    }
}
