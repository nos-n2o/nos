//! The core hosted on real ports: turns the core's [`Action`]s into the three
//! things the daemon does (send a BPDU, push kernel states, flush an FDB) and
//! into the log lines the e2e phase anchors on. No I/O, no clock.
//!
//! In mode `mstp` the CIST bridge is accompanied by one bridge per MSTI
//! ([`crate::mst`]); the kernel state of a domain's port is the state of the
//! tree its `stp-instance` names, pushed whenever it differs from the last push.

use std::collections::HashMap;

use nos_proto::{
    StpInstance, StpInstancePort, StpMode, StpMst, StpPortAssignment, StpPortCounters, StpPortInfo,
    StpRole, StpState, StpSummary, StpTcCause, StpTopology,
};
use tracing::{error, info, warn};

use crate::actions::{Action, Event, PortState};
use crate::bpdu::{Bpdu, Flags, MstBpdu, Rx};
use crate::bridge::{Bridge, PortParams};
use crate::events;
use crate::identity;
use crate::machines::{build, Role, Tx};
use crate::mst::{self, digest, vidmap, Edge, Mst, PortMst};
use crate::ports::{self, Plan, PortCfg};
use crate::vector::{BridgeId, IdError, PortId};
use nos_proto::schema::EdgePort;

/// What the daemon must do after a call into the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// Encode and send on port `port` (index into the plan).
    Tx { port: usize, bpdu: Bpdu },
    /// Like `Tx`, a version 3 BPDU (CIST plus the MSTI messages).
    TxMst { port: usize, bpdu: Box<MstBpdu> },
    /// Kernel states to push to `nos-interfaced`.
    States(Vec<StpPortAssignment>),
    /// `(port, domain)` pairs to flush.
    Flush(Vec<(String, String)>),
    /// Take `port`'s link down (`true`) or back up (`false`) in `nos-interfaced`.
    ErrDisabled { port: String, disabled: bool },
}

pub struct Engine {
    /// The Rapid-PVST+ tree this engine runs (labels its log lines).
    domain: Option<String>,
    mac: [u8; 6],
    /// The plan last built or applied in place.
    plan: Plan,
    bridge: Bridge,
    /// One slot per port ever planned since the last rebuild; the slot index
    /// is the core's port index. A removed port keeps its slot (`gone`).
    ports: Vec<PortCfg>,
    /// The Port Identifier number of each slot, stable while the port stays.
    numbers: Vec<u16>,
    gone: Vec<bool>,
    mst: Option<Mst>,
    /// The last state pushed per `(tree, port)`.
    pushed: HashMap<(u16, usize), PortState>,
    /// Per port, shared by the CIST and the MSTIs (one BPDU carries them all).
    counters: Vec<StpPortCounters>,
    /// Seconds since the engine was built: the clock of `tc` (one `tick` each).
    uptime: u64,
    /// Topology changes per tree (0: the CIST).
    tc: HashMap<u16, Tc>,
}

/// One tree's topology-change record.
#[derive(Default)]
struct Tc {
    count: u64,
    /// `uptime` of the last counted change, the port it came in on or started
    /// at, and whether a neighbour sent it.
    last: Option<(u64, usize, StpTcCause)>,
    /// `uptime` of the last received flag per port: a neighbour repeats the
    /// flag every hello for a while, which is one change.
    rx_at: HashMap<usize, u64>,
}

/// A change within this many seconds of the last one flagged on the same
/// port is the same episode (the longest flag run is `max_age + forward_delay`
/// for an 802.1D sender, whose hello gap is `hello`: 3 hellos of silence end it).
const EPISODE_HELLOS: u64 = 3;

fn stp_role(r: Role) -> StpRole {
    match r {
        Role::Root => StpRole::Root,
        Role::Designated => StpRole::Designated,
        Role::Alternate => StpRole::Alternate,
        Role::Backup => StpRole::Backup,
        Role::Disabled => StpRole::Disabled,
    }
}

fn stp_state(s: PortState) -> StpState {
    match s {
        PortState::Discarding => StpState::Discarding,
        PortState::Learning => StpState::Learning,
        PortState::Forwarding => StpState::Forwarding,
    }
}

fn tc_of(p: &crate::bpdu::Params) -> u64 {
    u64::from(p.flags.has(Flags::TC))
}

fn count_rx(c: &mut StpPortCounters, rx: &Rx) {
    match rx {
        Rx::Plain(Bpdu::Config(p)) => {
            c.in_config_bpdu += 1;
            c.tc_received += tc_of(p);
        }
        Rx::Plain(Bpdu::Rst(p)) => {
            c.in_rstp_bpdu += 1;
            c.tc_received += tc_of(p);
        }
        Rx::Plain(Bpdu::Tcn) => {
            c.in_tcn_bpdu += 1;
            c.tc_received += 1;
        }
        Rx::Mst(m) => {
            c.in_mst_bpdu += 1;
            c.tc_received += tc_of(&m.params);
        }
    }
}

fn count_tx(c: &mut StpPortCounters, bpdu: &Bpdu) {
    match bpdu {
        Bpdu::Config(p) => {
            c.out_config_bpdu += 1;
            c.tc_sent += tc_of(p);
        }
        Bpdu::Rst(p) => {
            c.out_rstp_bpdu += 1;
            c.tc_sent += tc_of(p);
        }
        Bpdu::Tcn => {
            c.out_tcn_bpdu += 1;
            c.tc_sent += 1;
        }
    }
}

/// The MSTI bridges follow the `Edge` of each port: a boundary port runs none.
fn sync_mst(cist: &Bridge, mst: &mut Mst) {
    for i in 0..cist.ports.len() {
        if !cist.ports[i].port_enabled {
            mst.edge[i] = Edge::Unknown;
        }
        let want = cist.ports[i].port_enabled && !matches!(mst.edge[i], Edge::Boundary(_));
        for m in &mut mst.instances {
            if m.bridge.ports[i].link_up != want {
                m.bridge.set_port_enabled(i, want);
            }
        }
    }
}

/// The Port Identifier number of each of `names`: a name in `prev` keeps its
/// number, a new one takes the lowest number nobody holds.
fn allocate(names: &[&str], prev: &HashMap<String, u16>) -> Vec<u16> {
    let mut used = std::collections::HashSet::new();
    let mut out: Vec<Option<u16>> = names
        .iter()
        .map(|n| prev.get(*n).copied().filter(|&v| used.insert(v)))
        .collect();
    let mut next = 1u16;
    for slot in out.iter_mut().filter(|s| s.is_none()) {
        while used.contains(&next) {
            next += 1;
        }
        used.insert(next);
        *slot = Some(next);
    }
    out.into_iter().flatten().collect()
}

fn port_params(p: &PortCfg, number: u16) -> Result<PortParams, IdError> {
    Ok(PortParams {
        id: PortId::new(p.priority, number)?,
        path_cost: crate::link::path_cost(p.cost, crate::link::LinkInfo::default()),
        admin_edge: p.edge == EdgePort::Admin,
        auto_edge: p.edge == EdgePort::Auto,
    })
}

/// A plan change only a rebuilt bridge can take (#662).
#[derive(Debug, PartialEq, Eq)]
pub struct Rebuild;

impl Engine {
    /// A bridge with every port disabled; the returned outputs are its
    /// initial (blocking) states.
    pub fn new(plan: &Plan, mac: [u8; 6]) -> Result<(Self, Vec<Out>), IdError> {
        Self::new_keeping(plan, mac, &HashMap::new())
    }

    /// Like [`Engine::new`], a port named in `prev` keeps its number (#662).
    pub fn new_keeping(
        plan: &Plan,
        mac: [u8; 6],
        prev: &HashMap<String, u16>,
    ) -> Result<(Self, Vec<Out>), IdError> {
        let names: Vec<&str> = plan.ports.iter().map(|p| p.name.as_str()).collect();
        let numbers = allocate(&names, prev);
        let params = plan
            .ports
            .iter()
            .zip(&numbers)
            .map(|(p, &n)| port_params(p, n))
            .collect::<Result<Vec<_>, IdError>>()?;
        let mut bridge = Bridge::new(
            BridgeId::new(plan.priority, plan.ext, mac)?,
            plan.timers,
            &params,
        );
        bridge.set_rstp_version(plan.rstp_version);
        for (i, p) in plan.ports.iter().enumerate() {
            bridge.set_protections(i, p.prot);
        }
        let mst = match &plan.mst {
            Some(m) => {
                let cfgs: Vec<Vec<PortMst>> = plan.ports.iter().map(|p| p.mst.clone()).collect();
                let mst = Mst::new(m, mac, plan.timers, &params, cfgs)?;
                info!(
                    name = %m.name,
                    revision = m.revision,
                    digest = %digest::hex(&m.digest),
                    instances = m.instances.len(),
                    "{}",
                    events::MST_CONFIGURATION
                );
                Some(mst)
            }
            None => None,
        };
        let mut e = Engine {
            domain: plan.domain.clone(),
            mac,
            plan: plan.clone(),
            bridge,
            ports: plan.ports.clone(),
            numbers,
            gone: vec![false; plan.ports.len()],
            mst,
            pushed: HashMap::new(),
            counters: vec![StpPortCounters::default(); plan.ports.len()],
            uptime: 0,
            tc: HashMap::new(),
        };
        // A fresh bridge is its own root; the core only reports changes.
        e.log_root(e.bridge.root_id);
        let out = e.drain();
        Ok((e, out))
    }

    /// Whether slot `port` is a live port (not removed by an in-place update).
    pub fn is_live(&self, port: usize) -> bool {
        !self.gone[port]
    }

    /// Port number of each live port, to carry over a rebuild.
    pub fn numbers(&self) -> HashMap<String, u16> {
        (0..self.ports.len())
            .filter(|&i| !self.gone[i])
            .map(|i| (self.ports[i].name.clone(), self.numbers[i]))
            .collect()
    }

    /// The slot of live port `name`.
    pub fn live_slot(&self, name: &str) -> Option<usize> {
        (0..self.ports.len()).find(|&i| !self.gone[i] && self.ports[i].name == name)
    }

    /// Apply `plan` to the running bridge without restarting the protocol:
    /// bridge priority, timers, per-port cost/priority/edge/protections and
    /// ports added or removed. `Err(Rebuild)` for anything structural (mode,
    /// force-version, MSTP, Rapid-PVST+; `Pvst::apply_plan` calls this per tree); nothing has changed then.
    pub fn apply_plan(&mut self, plan: &Plan) -> Result<Vec<Out>, Rebuild> {
        let old = &self.plan;
        if self.mst.is_some()
            || plan.mst.is_some()
            || plan.pvst.is_some()
            || old.pvst.is_some()
            || plan.rstp_version != old.rstp_version
            || plan.ext != old.ext
            || plan.domain != old.domain
        {
            return Err(Rebuild);
        }
        let live: HashMap<String, u16> = self.numbers();
        let kept: Vec<Option<usize>> = plan.ports.iter().map(|p| self.live_slot(&p.name)).collect();
        let names: Vec<&str> = plan.ports.iter().map(|p| p.name.as_str()).collect();
        let numbers = allocate(&names, &live);
        let mut news = Vec::new();
        for ((cfg, slot), &n) in plan.ports.iter().zip(&kept).zip(&numbers) {
            let params = port_params(cfg, n).map_err(|_| Rebuild)?;
            if slot.is_none() {
                news.push((cfg.clone(), params, n));
            }
        }
        if plan.priority != old.priority {
            let id = BridgeId::new(plan.priority, plan.ext, self.mac).map_err(|_| Rebuild)?;
            self.bridge.set_bridge_id(id);
        }
        if plan.timers != old.timers {
            self.bridge.set_timers(plan.timers);
        }
        for i in 0..self.ports.len() {
            if !self.gone[i] && !plan.ports.iter().any(|p| p.name == self.ports[i].name) {
                // Err-disabled: release first so `nos-interfaced` is told.
                self.bridge.clear_err_disabled(i);
                self.bridge.set_port_enabled(i, false);
                self.gone[i] = true;
            }
        }
        for (cfg, slot) in plan.ports.iter().zip(&kept) {
            let Some(&i) = slot.as_ref() else { continue };
            let was = std::mem::replace(&mut self.ports[i], cfg.clone());
            if was.priority != cfg.priority {
                let id = PortId::new(cfg.priority, self.numbers[i]).map_err(|_| Rebuild)?;
                self.bridge.set_port_priority(i, id);
            }
            if was.edge != cfg.edge {
                self.bridge
                    .set_edge(i, cfg.edge == EdgePort::Admin, cfg.edge == EdgePort::Auto);
            }
            if was.prot != cfg.prot {
                self.bridge.set_protections(i, cfg.prot);
                if !cfg.prot.bpdu_guard {
                    self.bridge.clear_err_disabled(i);
                }
            }
            if was.domains != cfg.domains {
                // The new domains need their state pushed.
                self.pushed.retain(|&(_, p), _| p != i);
            }
        }
        for (cfg, params, number) in news {
            let i = self.bridge.add_port(params);
            debug_assert_eq!(i, self.ports.len());
            self.ports.push(cfg);
            self.numbers.push(number);
            self.gone.push(false);
            self.counters.push(StpPortCounters::default());
        }
        self.plan = plan.clone();
        Ok(self.drain())
    }

    /// `mcheck` on the named port, or on every port (`None`); how many ports
    /// matched.
    pub fn mcheck(&mut self, interface: Option<&str>) -> (u32, Vec<Out>) {
        let mut n = 0;
        for i in 0..self.ports.len() {
            if !self.gone[i] && interface.is_none_or(|name| name == self.ports[i].name) {
                self.bridge.mcheck(i);
                n += 1;
            }
        }
        (n, self.drain())
    }

    /// Err-disabled ports and their seconds to recovery (`None`: manual).
    pub fn err_disabled(&self) -> Vec<(String, Option<u32>)> {
        (0..self.ports.len())
            .filter(|&i| !self.gone[i])
            .filter_map(|i| Some((self.ports[i].name.clone(), self.bridge.err_disabled(i)?)))
            .collect()
    }

    /// Keep a port err-disabled across a bridge rebuild; false when the new
    /// plan no longer has the port or its guard.
    pub fn restore_err_disabled(&mut self, name: &str, remaining: Option<u32>) -> bool {
        let Some(i) = self
            .live_slot(name)
            .filter(|&i| self.ports[i].prot.bpdu_guard)
        else {
            return false;
        };
        // The new `bpdu-guard-recovery` wins: unset makes it manual.
        let remaining = self.ports[i]
            .prot
            .recovery
            .map(|r| remaining.map_or(r, |old| old.min(r)));
        self.bridge.restore_err_disabled(i, remaining);
        true
    }

    /// `clear spanning-tree err-disabled`: whether `name` was err-disabled.
    pub fn clear_err_disabled(&mut self, name: &str) -> (bool, Vec<Out>) {
        let Some(i) = self.live_slot(name) else {
            return (false, Vec::new());
        };
        let was = self.bridge.err_disabled(i).is_some();
        self.bridge.clear_err_disabled(i);
        (was, self.drain())
    }

    /// A frame on `port` that did not decode as a BPDU.
    pub fn note_invalid(&mut self, port: usize) {
        self.counters[port].invalid_bpdu += 1;
    }

    /// A topology change of `tree` seen on `port`: counted once per episode
    /// when a neighbour sent it (see [`EPISODE_HELLOS`]).
    fn note_tc(&mut self, tree: u16, port: usize, received: bool) {
        let window = EPISODE_HELLOS * u64::from(self.bridge.root_times.hello.max(1));
        let now = self.uptime;
        let tc = self.tc.entry(tree).or_default();
        if received
            && tc
                .rx_at
                .insert(port, now)
                .is_some_and(|t| now - t <= window)
        {
            return;
        }
        tc.count += 1;
        let cause = if received {
            StpTcCause::Received
        } else {
            StpTcCause::Local
        };
        tc.last = Some((now, port, cause));
        let name = &self.ports[port].name;
        let cause = if received { "received" } else { "local" };
        let msg = events::TOPOLOGY_CHANGE;
        match (&self.domain, tree) {
            (Some(d), _) => info!(domain = %d, port = %name, cause = %cause, "{}", msg),
            (None, 0) => info!(port = %name, cause = %cause, "{}", msg),
            (None, t) => info!(msti = t, port = %name, cause = %cause, "{}", msg),
        }
    }

    fn topology(&self, tree: u16) -> StpTopology {
        let Some(tc) = self.tc.get(&tree) else {
            return StpTopology::default();
        };
        StpTopology {
            count: tc.count,
            last_secs_ago: tc.last.map(|(at, ..)| self.uptime - at),
            last_port: tc.last.map(|(_, p, _)| self.ports[p].name.clone()),
            last_cause: tc.last.map(|(.., c)| c),
        }
    }

    pub fn ports(&self) -> &[PortCfg] {
        &self.ports
    }

    /// The CIST state of `port` (a Rapid-PVST+ tree's only state).
    pub fn port_state(&self, port: usize) -> PortState {
        self.bridge.port_state(port)
    }

    fn log_root(&self, root: BridgeId) {
        if let Some(d) = &self.domain {
            info!(domain = %d, root = %identity::show_ext(&root), "{}", events::PVST_ROOT_CHANGED);
        } else {
            info!(root = %identity::show(&root), "{}", events::ROOT_CHANGED);
        }
    }

    fn log_state(&self, port: usize, state: PortState) {
        let name = &self.ports[port].name;
        if let Some(d) = &self.domain {
            info!(domain = %d, port = %name, state = ?state, "{}", events::PVST_PORT_STATE_CHANGED);
        } else {
            info!(port = %name, state = ?state, "{}", events::PORT_STATE_CHANGED);
        }
    }

    fn log_role(&self, port: usize, role: Role) {
        let name = &self.ports[port].name;
        if let Some(d) = &self.domain {
            info!(domain = %d, port = %name, role = ?role, "{}", events::PVST_PORT_ROLE_CHANGED);
        } else {
            info!(port = %name, role = ?role, "{}", events::PORT_ROLE_CHANGED);
        }
    }

    /// The bridge as one Rapid-PVST+ tree of `show spanning-tree domain`.
    pub fn tree_view(&self, vid: u16) -> StpInstance {
        let b = &self.bridge;
        let root_cost = b.root_port.map_or(0, |i| {
            b.ports[i]
                .port_priority
                .root_path_cost
                .saturating_add(b.ports[i].path_cost)
        });
        StpInstance {
            id: vid,
            vlans: vid.to_string(),
            domains: self.domain.iter().cloned().collect(),
            bridge_id: identity::show_ext(&b.id),
            root_id: identity::show_ext(&b.root_id),
            root_path_cost: root_cost,
            root_port: b.root_port.map(|i| self.ports[i].name.clone()),
            ports: self
                .ports
                .iter()
                .enumerate()
                .filter(|(i, _)| !self.gone[*i])
                .map(|(i, cfg)| {
                    let p = &b.ports[i];
                    let (designated_bridge, designated_port) = if p.role == Role::Disabled {
                        (String::new(), String::new())
                    } else {
                        let dp = p.port_priority.designated_port;
                        (
                            identity::show_ext(&p.port_priority.designated_bridge),
                            format!("{}.{}", dp.priority(), dp.number()),
                        )
                    };
                    StpInstancePort {
                        name: cfg.name.clone(),
                        role: stp_role(p.role),
                        state: stp_state(b.port_state(i)),
                        boundary: false,
                        inconsistent: false,
                        compat: p.port_enabled && !p.send_rstp,
                        cost: p.path_cost,
                        priority: p.port_id.priority(),
                        designated_bridge,
                        designated_port,
                        edge: p.oper_edge,
                        point_to_point: p.oper_point_to_point,
                        counters: self.counters[i],
                    }
                })
                .collect(),
            topology: self.topology(0),
        }
    }

    fn mst_plan(&self) -> Option<&mst::MstPlan> {
        self.mst.as_ref().map(|m| &m.plan)
    }

    /// The state the kernel gets for `tree` on `port`: a boundary port's
    /// MSTIs follow the CIST.
    fn effective(&self, tree: u16, port: usize) -> PortState {
        match self.mst.as_ref().filter(|_| tree != 0) {
            Some(m) if !matches!(m.edge[port], Edge::Boundary(_)) => m
                .instances
                .iter()
                .find(|i| i.id == tree)
                .map_or(PortState::Discarding, |i| i.bridge.port_state(port)),
            _ => self.bridge.port_state(port),
        }
    }

    /// One tree of the summary: the CIST (`tree` 0) or an MSTI.
    fn instance_view(&self, tree: u16, plan: &mst::MstPlan) -> StpInstance {
        let b = match tree {
            0 => &self.bridge,
            t => {
                &self
                    .mst
                    .as_ref()
                    .and_then(|m| m.instances.iter().find(|i| i.id == t))
                    .expect("a planned instance")
                    .bridge
            }
        };
        let root_cost = b.root_port.map_or(0, |i| {
            b.ports[i]
                .port_priority
                .root_path_cost
                .saturating_add(b.ports[i].path_cost)
        });
        let mut domains: Vec<String> = plan
            .domains
            .iter()
            .filter(|d| d.2 == tree)
            .map(|d| d.0.clone())
            .collect();
        domains.sort();
        StpInstance {
            id: tree,
            vlans: vidmap::ranges(&plan.domains, tree),
            domains,
            bridge_id: identity::show(&b.id),
            root_id: identity::show(&b.root_id),
            root_path_cost: root_cost,
            root_port: b.root_port.map(|i| self.ports[i].name.clone()),
            ports: self
                .ports
                .iter()
                .enumerate()
                .map(|(i, cfg)| {
                    let boundary = self
                        .mst
                        .as_ref()
                        .is_some_and(|m| matches!(m.edge[i], Edge::Boundary(_)));
                    // A boundary port has no MSTI information: show the CIST's.
                    let src = if boundary { &self.bridge } else { b };
                    let p = &src.ports[i];
                    let (designated_bridge, designated_port) = if p.role == Role::Disabled {
                        (String::new(), String::new())
                    } else {
                        let dp = p.port_priority.designated_port;
                        (
                            identity::show(&p.port_priority.designated_bridge),
                            format!("{}.{}", dp.priority(), dp.number()),
                        )
                    };
                    StpInstancePort {
                        name: cfg.name.clone(),
                        role: stp_role(p.role),
                        state: stp_state(self.effective(tree, i)),
                        boundary,
                        inconsistent: false,
                        compat: false,
                        cost: b.ports[i].path_cost,
                        priority: b.ports[i].port_id.priority(),
                        designated_bridge,
                        designated_port,
                        edge: p.oper_edge,
                        point_to_point: b.ports[i].oper_point_to_point,
                        counters: self.counters[i],
                    }
                })
                .collect(),
            topology: self.topology(tree),
        }
    }

    /// The live view `show spanning-tree` serves.
    pub fn summary(&self) -> StpSummary {
        let b = &self.bridge;
        let root_cost = b.root_port.map_or(0, |i| {
            b.ports[i]
                .port_priority
                .root_path_cost
                .saturating_add(b.ports[i].path_cost)
        });
        StpSummary {
            enabled: true,
            mode: if self.mst.is_some() {
                StpMode::Mstp
            } else {
                StpMode::Rstp
            },
            bridge_id: identity::show(&b.id),
            root_id: identity::show(&b.root_id),
            root_path_cost: root_cost,
            root_port: b.root_port.map(|i| self.ports[i].name.clone()),
            hello_time_secs: b.root_times.hello,
            max_age_secs: b.root_times.max_age,
            forward_delay_secs: b.root_times.forward_delay,
            ports: self
                .ports
                .iter()
                .enumerate()
                .filter(|(i, _)| !self.gone[*i])
                .map(|(i, cfg)| {
                    let p = &b.ports[i];
                    let (designated_bridge, designated_port) = if p.role == Role::Disabled {
                        (String::new(), String::new())
                    } else {
                        let dp = p.port_priority.designated_port;
                        (
                            identity::show(&p.port_priority.designated_bridge),
                            format!("{}.{}", dp.priority(), dp.number()),
                        )
                    };
                    StpPortInfo {
                        name: cfg.name.clone(),
                        role: stp_role(p.role),
                        state: stp_state(b.port_state(i)),
                        cost: p.path_cost,
                        priority: cfg.priority,
                        designated_bridge,
                        designated_port,
                        edge: p.oper_edge,
                        bpdu_guard: cfg.prot.bpdu_guard,
                        bpdu_filter: cfg.prot.bpdu_filter,
                        root_guard: cfg.prot.root_guard,
                        loop_guard: cfg.prot.loop_guard,
                        restricted_tcn: cfg.prot.restricted_tcn,
                        root_inconsistent: p.root_inconsistent,
                        loop_inconsistent: p.loop_inconsistent,
                        err_disabled: p.err_disabled,
                        err_recovery_secs: p.err_remaining,
                        point_to_point: p.oper_point_to_point,
                        counters: self.counters[i],
                    }
                })
                .collect(),
            pvst: Vec::new(),
            topology: self.topology(0),
            mst: self.mst.as_ref().map(|m| {
                let ids = std::iter::once(0).chain(m.instances.iter().map(|i| i.id));
                StpMst {
                    region_name: m.plan.name.clone(),
                    revision: m.plan.revision,
                    digest: digest::hex(&m.plan.digest),
                    max_hops: m.plan.max_hops,
                    instances: ids.map(|t| self.instance_view(t, &m.plan)).collect(),
                }
            }),
        }
    }

    pub fn receive(&mut self, port: usize, bpdu: Bpdu) -> Vec<Out> {
        self.receive_rx(port, Rx::Plain(bpdu))
    }

    /// A BPDU as decoded from the wire. A version 3 BPDU from a bridge in the
    /// same region also feeds the MSTIs; anything else makes the port a
    /// boundary port.
    pub fn receive_rx(&mut self, port: usize, rx: Rx) -> Vec<Out> {
        count_rx(&mut self.counters[port], &rx);
        let p = &self.bridge.ports[port];
        let ignored = p.prot.bpdu_filter || p.err_disabled;
        let (cist, msti) = match rx {
            Rx::Plain(b) => {
                if !ignored {
                    self.set_edge(port, Edge::Boundary("plain-bpdu"));
                }
                (b, None)
            }
            Rx::Mst(m) => {
                let flat = Bpdu::Rst(mst::flat(&m));
                match self.mst.as_ref().map(|s| mst::mismatch(&s.id, &m.config)) {
                    Some(why) if !ignored => {
                        self.set_edge(port, why.map_or(Edge::Internal, Edge::Boundary));
                        (flat, why.is_none().then_some(m))
                    }
                    _ => (flat, None),
                }
            }
        };
        self.bridge.receive(port, cist);
        if let (Some(m), Some(mst)) = (msti, self.mst.as_mut())
            && !self.bridge.ports[port].err_disabled
        {
            sync_mst(&self.bridge, mst);
            mst.receive(port, &m);
        }
        self.drain()
    }

    fn set_edge(&mut self, port: usize, edge: Edge) {
        let Some(m) = self.mst.as_mut() else { return };
        if m.edge[port] == edge {
            return;
        }
        m.edge[port] = edge;
        let name = &self.ports[port].name;
        match edge {
            Edge::Boundary(reason) => {
                info!(port = %name, reason = %reason, "{}", events::MST_BOUNDARY_PORT);
            }
            Edge::Internal => {
                info!(port = %name, digest = %digest::hex(&m.id.digest), "{}", events::MST_REGION_MATCH);
            }
            Edge::Unknown => {}
        }
    }

    /// `portEnabled`, `operPointToPoint` and the path cost of one port.
    pub fn set_link(&mut self, port: usize, enabled: bool, p2p: bool, cost: u32) -> Vec<Out> {
        self.bridge.set_path_cost(port, cost);
        self.bridge.set_oper_point_to_point(port, p2p);
        self.bridge.set_port_enabled(port, enabled);
        if let Some(m) = self.mst.as_mut() {
            for inst in &mut m.instances {
                let own = m.port_cfg[port].iter().find(|c| c.id == inst.id);
                inst.bridge
                    .set_path_cost(port, own.and_then(|c| c.cost).unwrap_or(cost));
                inst.bridge.set_oper_point_to_point(port, p2p);
            }
        }
        self.drain()
    }

    /// One second elapsed.
    pub fn tick(&mut self) -> Vec<Out> {
        self.uptime += 1;
        self.bridge.tick();
        if let Some(m) = self.mst.as_mut() {
            m.instances.iter_mut().for_each(|i| i.bridge.tick());
        }
        self.drain()
    }

    fn drain(&mut self) -> Vec<Out> {
        if let Some(m) = self.mst.as_mut() {
            sync_mst(&self.bridge, m);
        }
        let mut out = Vec::new();
        // CIST Transmit of each port, held back while an MST BPDU can carry it.
        let mut cist_tx = HashMap::new();
        for action in self.bridge.take_actions() {
            match action {
                Action::Transmit { port, bpdu } => match bpdu {
                    Bpdu::Rst(p) if self.mst.is_some() => {
                        cist_tx.insert(port, p);
                    }
                    bpdu => {
                        count_tx(&mut self.counters[port], &bpdu);
                        out.push(Out::Tx { port, bpdu });
                    }
                },
                Action::SetPortState { port, state } => {
                    if state == PortState::Forwarding {
                        self.counters[port].forward_transitions += 1;
                    }
                    self.log_state(port, state);
                }
                Action::FlushFdb { port } => {
                    let f = ports::flushes(&self.ports[port], self.mst_plan(), 0);
                    out.push(Out::Flush(f));
                }
                Action::Log(Event::RoleChanged { port, to, .. }) => self.log_role(port, to),
                Action::Log(Event::ProtocolMigrated { port, rstp }) => {
                    let name = &self.ports[port].name;
                    self.counters[port].protocol_migration += 1;
                    match (&self.domain, rstp) {
                        (Some(d), true) => {
                            info!(domain = %d, port = %name, "{}", events::PVST_PORT_MIGRATED_RSTP);
                        }
                        (Some(d), false) => {
                            info!(domain = %d, port = %name, "{}", events::PVST_PORT_MIGRATED_STP);
                        }
                        (None, true) => info!(port = %name, "{}", events::PORT_MIGRATED_RSTP),
                        (None, false) => info!(port = %name, "{}", events::PORT_MIGRATED_STP),
                    }
                }
                Action::Log(Event::RootChanged { root, .. }) => self.log_root(root),
                Action::Log(Event::TopologyChange { port, received }) => {
                    self.note_tc(0, port, received);
                }
                Action::ErrDisable { port } => {
                    let name = self.ports[port].name.clone();
                    warn!(port = %name, reason = %"bpdu-guard", "{}", events::PORT_ERR_DISABLED);
                    out.push(Out::ErrDisabled {
                        port: name,
                        disabled: true,
                    });
                }
                Action::ErrRecover { port } => {
                    let name = self.ports[port].name.clone();
                    info!(port = %name, "{}", events::PORT_ERR_RECOVERED);
                    out.push(Out::ErrDisabled {
                        port: name,
                        disabled: false,
                    });
                }
                Action::Log(Event::RootInconsistent { port, on }) => {
                    let name = &self.ports[port].name;
                    if on {
                        warn!(port = %name, "{}", events::PORT_ROOT_INCONSISTENT);
                    } else {
                        info!(port = %name, "{}", events::PORT_ROOT_CONSISTENT);
                    }
                }
                Action::Log(Event::LoopInconsistent { port, on }) => {
                    let name = &self.ports[port].name;
                    if on {
                        warn!(port = %name, "{}", events::PORT_LOOP_INCONSISTENT);
                    } else {
                        info!(port = %name, "{}", events::PORT_LOOP_CONSISTENT);
                    }
                }
                Action::Log(Event::NotQuiescent) => {
                    error!("{}", events::NOT_QUIESCENT);
                }
            }
        }
        self.drain_mst(&mut out, cist_tx);
        let states = self.diff_states();
        if !states.is_empty() {
            out.push(Out::States(states));
        }
        out
    }

    /// The MSTI bridges' actions: flushes, logs, and the triggers for one
    /// MST BPDU per port (ponytail: the MSTIs' own `txHoldCount` limits are
    /// not summed, a burst can exceed the CIST's by the number of MSTIs).
    fn drain_mst(&mut self, out: &mut Vec<Out>, mut cist_tx: HashMap<usize, crate::bpdu::Params>) {
        let Some(m) = self.mst.as_mut() else { return };
        let mut triggers = Vec::new();
        let mut changes = Vec::new();
        for inst in &mut m.instances {
            for action in inst.bridge.take_actions() {
                match action {
                    Action::Transmit { port, .. } => triggers.push(port),
                    Action::FlushFdb { port } => {
                        let f = ports::flushes(&self.ports[port], Some(&m.plan), inst.id);
                        if !f.is_empty() {
                            out.push(Out::Flush(f));
                        }
                    }
                    Action::Log(Event::RoleChanged { port, to, .. }) => {
                        info!(port = %self.ports[port].name, msti = inst.id, role = ?to, "{}", events::MSTI_PORT_ROLE_CHANGED);
                    }
                    Action::Log(Event::RootChanged { root, .. }) => {
                        info!(msti = inst.id, root = %identity::show(&root), "{}", events::MSTI_ROOT_CHANGED);
                    }
                    Action::Log(Event::TopologyChange { port, received }) => {
                        changes.push((inst.id, port, received));
                    }
                    Action::Log(Event::NotQuiescent) => {
                        error!(msti = inst.id, "{}", events::NOT_QUIESCENT);
                    }
                    _ => {}
                }
            }
        }
        for (tree, port, received) in changes {
            self.note_tc(tree, port, received);
        }
        let Some(m) = self.mst.as_mut() else { return };
        for port in triggers {
            let p = &self.bridge.ports[port];
            if p.send_rstp
                && p.port_enabled
                && !p.prot.bpdu_filter
                && let Bpdu::Rst(params) = build(&self.bridge, port, Tx::Rst)
            {
                cist_tx.entry(port).or_insert(params);
            }
        }
        let mut sends: Vec<_> = cist_tx.into_iter().collect();
        sends.sort_by_key(|&(port, _)| port);
        for (port, params) in sends {
            let bpdu = Box::new(m.tx(port, &params, self.bridge.id));
            let c = &mut self.counters[port];
            c.out_mst_bpdu += 1;
            c.tc_sent += tc_of(&bpdu.params);
            out.push(Out::TxMst { port, bpdu });
        }
    }

    fn trees(&self) -> Vec<u16> {
        std::iter::once(0)
            .chain(
                self.mst
                    .iter()
                    .flat_map(|m| m.instances.iter().map(|i| i.id)),
            )
            .collect()
    }

    /// Every `(port, domain)` state as it is now, for the periodic re-push:
    /// a push that `nos-interfaced` overwrote with a stale resync is healed
    /// by the next one (it only writes states that differ).
    pub fn all_states(&self) -> Vec<Out> {
        let states: Vec<_> = self
            .trees()
            .into_iter()
            .flat_map(|t| {
                (0..self.ports.len())
                    .filter(|&i| !self.gone[i])
                    .flat_map(move |i| {
                        ports::assignments(&self.ports[i], self.mst_plan(), t, self.effective(t, i))
                    })
            })
            .collect();
        if states.is_empty() {
            Vec::new()
        } else {
            vec![Out::States(states)]
        }
    }

    /// Kernel states that changed since the last push, for every tree.
    fn diff_states(&mut self) -> Vec<StpPortAssignment> {
        let trees = self.trees();
        let mut states = Vec::new();
        for tree in trees {
            for i in (0..self.ports.len()).filter(|&i| !self.gone[i]) {
                let now = self.effective(tree, i);
                if self.pushed.insert((tree, i), now) == Some(now) {
                    continue;
                }
                let a = ports::assignments(&self.ports[i], self.mst_plan(), tree, now);
                if tree != 0 {
                    let domains: Vec<_> = a.iter().map(|a| a.domain.as_str()).collect();
                    info!(
                        port = %self.ports[i].name,
                        msti = tree,
                        state = ?now,
                        domains = %domains.join(","),
                        "{}",
                        events::MSTI_PORT_STATE_CHANGED
                    );
                }
                states.extend(a);
            }
        }
        states
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timers::Timers;

    fn plan() -> Plan {
        let port = |n: &str| PortCfg {
            name: n.into(),
            domains: vec!["d1".into(), "d2".into()],
            priority: 128,
            cost: None,
            edge: EdgePort::Disabled,
            link_type: nos_proto::schema::LinkType::Auto,
            prot: crate::machines::Protections::default(),
            mst: Vec::new(),
            members: Vec::new(),
        };
        Plan {
            priority: 32768,
            rstp_version: true,
            timers: Timers::default(),
            ports: vec![port("eth1"), port("eth2")],
            mst: None,
            ext: 0,
            domain: None,
            pvst: None,
        }
    }

    #[test]
    fn starts_blocking_then_a_lone_root_forwards_and_hellos() {
        let (mut e, init) = Engine::new(&plan(), [2, 0, 0, 0, 0, 1]).unwrap();
        let Some(Out::States(s)) = init.iter().find(|o| matches!(o, Out::States(_))) else {
            panic!("no initial states: {init:?}");
        };
        assert_eq!(s.len(), 4, "two ports times two domains");
        assert!(s
            .iter()
            .all(|a| a.state == nos_proto::StpPortState::Blocking));

        let out = e.set_link(0, true, true, 20_000);
        assert!(
            out.iter().any(|o| matches!(o, Out::Tx { port: 0, .. })),
            "an enabled designated port announces itself: {out:?}"
        );
        // Alone on the segment: the port reaches forwarding after the delays.
        let mut forwarding = false;
        for _ in 0..40 {
            for o in e.tick() {
                if let Out::States(s) = o {
                    forwarding |= s
                        .iter()
                        .any(|a| a.state == nos_proto::StpPortState::Forwarding);
                }
            }
        }
        assert!(forwarding);
        assert_eq!(e.bridge.port_state(0), PortState::Forwarding);
        assert_eq!(e.bridge.port_state(1), PortState::Discarding);

        let s = e.summary();
        assert!(s.enabled && s.root_port.is_none() && s.root_path_cost == 0);
        assert_eq!(s.root_id, s.bridge_id, "a lone bridge is its own root");
        assert_eq!(
            (s.ports[0].role, s.ports[0].state),
            (StpRole::Designated, StpState::Forwarding)
        );
        assert_eq!(s.ports[0].designated_bridge, s.bridge_id);
        assert_eq!(s.ports[0].designated_port, "128.1");
        assert_eq!(s.ports[1].role, StpRole::Disabled);
        assert_eq!(s.ports[1].designated_bridge, "");
    }

    #[test]
    fn mcheck_counts_matching_ports() {
        let (mut e, _) = Engine::new(&plan(), [2, 0, 0, 0, 0, 1]).unwrap();
        assert_eq!(e.mcheck(None).0, 2);
        assert_eq!(e.mcheck(Some("eth2")).0, 1);
        assert_eq!(e.mcheck(Some("nope")).0, 0);
    }

    #[test]
    fn forced_stp_never_transmits_rstp() {
        let mut p = plan();
        p.rstp_version = false;
        let (mut e, _) = Engine::new(&p, [2, 0, 0, 0, 0, 1]).unwrap();
        let mut out = e.set_link(0, true, true, 20_000);
        for _ in 0..5 {
            out.extend(e.tick());
        }
        let sent: Vec<_> = out
            .iter()
            .filter_map(|o| match o {
                Out::Tx { bpdu, .. } => Some(bpdu),
                _ => None,
            })
            .collect();
        assert_ne!(sent.len(), 0);
        assert!(
            sent.iter().all(|b| matches!(b, Bpdu::Config(_))),
            "{sent:?}"
        );
    }

    #[test]
    fn bpdu_guard_pushes_err_disable_and_clear_lifts_it() {
        let mut p = plan();
        p.ports[0].edge = EdgePort::Admin;
        p.ports[0].prot.bpdu_guard = true;
        let (mut e, _) = Engine::new(&p, [2, 0, 0, 0, 0, 1]).unwrap();
        e.set_link(0, true, true, 20_000);
        let bpdu = crate::machines::tests::rst(&e.bridge, 0, false);
        let out = e.receive(0, bpdu);
        assert!(out.contains(&Out::ErrDisabled {
            port: "eth1".into(),
            disabled: true
        }));
        assert_eq!(e.err_disabled(), [("eth1".to_string(), None)]);
        let s = e.summary();
        assert!(s.ports[0].err_disabled && s.ports[0].bpdu_guard);
        assert!(!e.clear_err_disabled("eth2").0);
        let (was, out) = e.clear_err_disabled("eth1");
        assert!(was);
        assert!(out.contains(&Out::ErrDisabled {
            port: "eth1".into(),
            disabled: false
        }));
        // A rebuilt bridge keeps the port down while the guard is configured.
        let (mut e2, _) = Engine::new(&p, [2, 0, 0, 0, 0, 1]).unwrap();
        assert!(e2.restore_err_disabled("eth1", Some(5)));
        assert_eq!(
            e2.err_disabled(),
            [("eth1".to_string(), None)],
            "recovery is unset in the new plan, so the port waits for clear"
        );
        assert!(!e2.restore_err_disabled("eth2", None), "no guard on eth2");
        p.ports[0].prot.recovery = Some(60);
        let (mut e3, _) = Engine::new(&p, [2, 0, 0, 0, 0, 1]).unwrap();
        assert!(e3.restore_err_disabled("eth1", Some(5)));
        assert_eq!(e3.err_disabled(), [("eth1".to_string(), Some(5))]);
        assert!(e3.restore_err_disabled("eth1", None));
        assert_eq!(e3.err_disabled(), [("eth1".to_string(), Some(60))]);
    }

    #[test]
    fn all_states_repeats_every_domain_state_for_the_periodic_push() {
        let (e, _) = Engine::new(&plan(), [2, 0, 0, 0, 0, 1]).unwrap();
        let [Out::States(s)] = &e.all_states()[..] else {
            panic!("one States output");
        };
        assert_eq!(s.len(), 4, "two ports times two domains");
        assert!(s
            .iter()
            .all(|a| a.state == nos_proto::StpPortState::Blocking));
    }

    fn peer(flags: u8) -> Rx {
        use crate::bpdu::PortRole;
        Rx::Plain(crate::machines::tests::msg(
            0,
            0,
            0,
            1,
            PortRole::Designated,
            flags,
        ))
    }

    /// Port 0 up under a better root that hellos every 2 s, until forwarding.
    fn follower() -> Engine {
        let (mut e, _) = Engine::new(&plan(), [2, 0, 0, 0, 0, 1]).unwrap();
        e.set_link(0, true, true, 20_000);
        for t in 0..40 {
            if t % 2 == 0 {
                e.receive_rx(0, peer(0));
            }
            e.tick();
        }
        e
    }

    #[test]
    fn counters_count_each_bpdu_kind_and_event() {
        let mut e = follower();
        let c = e.summary().ports[0].counters;
        assert_eq!(c.in_rstp_bpdu, 20);
        assert_eq!(c.forward_transitions, 1);
        assert_eq!(c.tc_received, 0);
        assert_eq!(e.summary().ports[1].counters, StpPortCounters::default());
        e.receive_rx(0, peer(crate::bpdu::Flags::TC));
        let Rx::Plain(Bpdu::Rst(p)) = peer(0) else {
            unreachable!()
        };
        e.receive(0, Bpdu::Config(p));
        e.receive(0, Bpdu::Tcn);
        e.note_invalid(0);
        let mst = Rx::Mst(MstBpdu {
            params: p,
            config: crate::bpdu::MstConfigId {
                name: [0; 32],
                revision: 0,
                digest: [0; 16],
            },
            internal_cost: 0,
            bridge: p.bridge,
            remaining_hops: 20,
            mstis: Vec::new(),
        });
        e.receive_rx(0, mst);
        let c = e.summary().ports[0].counters;
        assert_eq!(
            (
                c.in_rstp_bpdu,
                c.in_config_bpdu,
                c.in_tcn_bpdu,
                c.in_mst_bpdu
            ),
            (21, 1, 1, 1)
        );
        assert_eq!((c.tc_received, c.invalid_bpdu), (2, 1));
        let v = e.tree_view(10);
        assert_eq!(v.ports[0].counters, c);
        assert!(v.ports[0].point_to_point && !v.ports[0].edge);
        assert_eq!(v.topology, e.summary().topology);
        assert!(c.protocol_migration >= 1, "a Config BPDU migrates to STP");
        let mut sent = StpPortCounters::default();
        count_tx(&mut sent, &Bpdu::Tcn);
        count_tx(&mut sent, &Bpdu::Config(p));
        count_tx(&mut sent, &Bpdu::Rst(p));
        assert_eq!(
            (
                sent.out_tcn_bpdu,
                sent.out_config_bpdu,
                sent.out_rstp_bpdu,
                sent.tc_sent
            ),
            (1, 1, 1, 1)
        );
    }

    #[test]
    fn topology_change_is_attributed_and_counted_once_per_episode() {
        let mut e = follower();
        let t = e.summary().topology;
        assert_eq!((t.count, t.last_cause), (1, Some(StpTcCause::Local)));
        assert_eq!(t.last_port.as_deref(), Some("eth1"));
        e.tick();
        e.receive_rx(0, peer(crate::bpdu::Flags::TC));
        let t = e.summary().topology;
        assert_eq!((t.count, t.last_cause), (2, Some(StpTcCause::Received)));
        assert_eq!(
            (t.last_port.as_deref(), t.last_secs_ago),
            (Some("eth1"), Some(0))
        );
        // The neighbour repeats the flag every hello: still one change.
        for _ in 0..3 {
            e.tick();
            e.tick();
            e.receive_rx(0, peer(crate::bpdu::Flags::TC));
        }
        assert_eq!(e.summary().topology.count, 2);
        // Silence ends the episode; the next flag is a new change.
        for _ in 0..8 {
            e.tick();
        }
        e.receive_rx(0, peer(crate::bpdu::Flags::TC));
        let t = e.summary().topology;
        assert_eq!(t.count, 3);
        e.tick();
        assert_eq!(e.summary().topology.last_secs_ago, Some(1));
    }

    #[test]
    fn rejects_an_out_of_range_priority() {
        let mut p = plan();
        p.priority = 100;
        assert!(Engine::new(&p, [2; 6]).is_err());
    }

    fn named(names: &[&str]) -> Plan {
        let mut p = plan();
        p.ports = names
            .iter()
            .map(|n| PortCfg {
                name: (*n).into(),
                ..plan().ports[0].clone()
            })
            .collect();
        p
    }

    fn number(e: &Engine, name: &str) -> u16 {
        e.numbers()[name]
    }

    #[test]
    fn a_plan_edit_keeps_port_numbers_and_forwarding_ports() {
        let mac = [2, 0, 0, 0, 0, 1];
        let (mut e, _) = Engine::new(&named(&["eth1", "eth3"]), mac).unwrap();
        e.set_link(0, true, true, 20_000);
        e.set_link(1, true, true, 20_000);
        for _ in 0..40 {
            e.tick();
        }
        assert_eq!(e.port_state(0), PortState::Forwarding);

        // eth2 joins between them, eth1 gets another priority and cost.
        let mut p = named(&["eth1", "eth2", "eth3"]);
        p.ports[0].priority = 64;
        p.ports[0].cost = Some(500);
        p.priority = 4096;
        p.timers.forward_delay = 10;
        e.apply_plan(&p).unwrap();
        assert_eq!(number(&e, "eth1"), 1);
        assert_eq!(number(&e, "eth3"), 2, "eth3 keeps its number");
        assert_eq!(number(&e, "eth2"), 3, "a new port takes a free number");
        assert_eq!(e.port_state(0), PortState::Forwarding);
        assert_eq!(e.port_state(1), PortState::Forwarding);
        assert_eq!(e.summary().ports.len(), 3);
        assert_eq!(e.summary().bridge_id, identity::show(&e.bridge.id));
        assert_eq!(e.bridge.id.priority(), 4096);

        // eth3 leaves: its slot stays, hidden; eth2 keeps number 3.
        e.apply_plan(&named(&["eth1", "eth2"])).unwrap();
        assert_eq!(e.summary().ports.len(), 2);
        assert!(!e.is_live(1) && e.live_slot("eth3").is_none());
        assert_eq!(number(&e, "eth2"), 3);
        assert_eq!(e.port_state(0), PortState::Forwarding);
        // and returns in a new slot, taking the lowest free number.
        e.apply_plan(&named(&["eth1", "eth2", "eth3"])).unwrap();
        assert_eq!(number(&e, "eth3"), 2);
        assert_eq!(e.live_slot("eth3"), Some(3));
    }

    #[test]
    fn a_structural_change_asks_for_a_rebuild() {
        let (mut e, _) = Engine::new(&plan(), [2, 0, 0, 0, 0, 1]).unwrap();
        let mut p = plan();
        p.rstp_version = false;
        assert_eq!(e.apply_plan(&p), Err(Rebuild));
        let mut p = plan();
        p.domain = Some("d".into());
        assert_eq!(e.apply_plan(&p), Err(Rebuild));
        assert_eq!(e.apply_plan(&plan()), Ok(Vec::new()));
    }

    #[test]
    fn allocation_keeps_known_names_and_fills_gaps() {
        let prev = HashMap::from([("b".to_string(), 2), ("c".to_string(), 3)]);
        assert_eq!(allocate(&["a", "b", "c", "d"], &prev), [1, 2, 3, 4]);
        assert_eq!(allocate(&["b", "d"], &prev), [2, 1]);
    }
}
