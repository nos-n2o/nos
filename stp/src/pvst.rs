//! Rapid-PVST+ (#322): one RSTP [`Engine`] per broadcast domain, each over the
//! ports that are members of the domain, with the VLAN as the bridge id's
//! system id extension. Pure: the daemon owns the sockets and feeds frames in.
//!
//! - The BPDU of a tagged member travels on its `ethX.<tag>` sub-link (the
//!   kernel adds the tag), an untagged member's on the link itself, where the
//!   native rule also sends and accepts the IEEE group (see [`tx_wires`]).
//! - A BPDU whose Originating VLAN TLV names another VLAN than the tree's
//!   blocks that port in that tree until a consistent BPDU arrives or 3 hellos
//!   pass in silence; it stays out of the RSTP machines, like a guard.
//! - A plain PVST+ peer (Config/TCN BPDUs) needs no code here: the tree's
//!   port migrates to 802.1D on its own (#319), in that tree only.
//! - ponytail: one engine per tree numbers its ports 1..n, so a port's id
//!   differs between trees; harmless, ids are only compared within a tree.

use std::collections::HashMap;

use nos_proto::schema::VlanTag;
use nos_proto::{StpMode, StpPortAssignment, StpPortState, StpState, StpSummary};
use tracing::{info, warn};

use crate::bpdu::Bpdu;
use crate::engine::{Engine, Out, Rebuild};
use crate::events;
use crate::identity;
use crate::ports::{self, Plan, TreePlan};
use crate::vector::{BridgeId, IdError};

/// What the daemon must do: an engine output tagged with its tree.
pub type Outs = Vec<(usize, Out)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// 802.3 + SNAP to `01:00:0c:cc:cc:cd` ([`crate::sstp`]).
    Sstp,
    /// 802.3 + LLC to `01:80:c2:00:00:00` ([`crate::bpdu`]).
    Ieee,
}

/// The frames sent per BPDU: an untagged member (the native VLAN) also sends
/// the IEEE form, which is all an 802.1Q neighbour's CST understands.
pub fn tx_wires(tag: VlanTag) -> &'static [Wire] {
    match tag {
        VlanTag::Untagged => &[Wire::Sstp, Wire::Ieee],
        VlanTag::Dot1q(_) => &[Wire::Sstp],
    }
}

/// An IEEE BPDU is the native domain's; on a tagged member it is ignored.
pub fn accepts(tag: VlanTag, wire: Wire) -> bool {
    wire == Wire::Sstp || tag == VlanTag::Untagged
}

/// The kernel device carrying a member's BPDUs.
pub fn link_name(port: &str, tag: VlanTag) -> String {
    match tag {
        VlanTag::Untagged => port.to_string(),
        VlanTag::Dot1q(v) => format!("{port}.{v}"),
    }
}

pub struct Tree {
    pub domain: String,
    pub vid: u16,
    /// The tag of each engine port.
    pub tags: Vec<VlanTag>,
    engine: Engine,
    /// PVID-inconsistent ports.
    blocked: Vec<bool>,
    /// Seconds since a BPDU last arrived on a port.
    quiet: Vec<u32>,
    hello: u32,
    /// Removed by an in-place update: a hidden slot (no ticks, states or
    /// summary entry) that keeps every `(tree, port)` index valid (#1122).
    gone: bool,
}

impl Tree {
    fn build(
        tp: &TreePlan,
        mac: [u8; 6],
        prev: &HashMap<String, u16>,
    ) -> Result<(Tree, Vec<Out>), IdError> {
        let (engine, init) = Engine::new_keeping(&tp.plan, mac, prev)?;
        let n = tp.plan.ports.len();
        let tree = Tree {
            domain: tp.domain.clone(),
            vid: tp.vid,
            tags: tp.tags.clone(),
            engine,
            blocked: vec![false; n],
            quiet: vec![0; n],
            hello: u32::from(tp.plan.timers.hello),
            gone: false,
        };
        Ok((tree, init))
    }

    pub fn is_gone(&self) -> bool {
        self.gone
    }

    /// Whether `tp` needs a fresh engine: the VLAN (bridge-id extension) or a
    /// kept member's tag changed.
    fn restarts(&self, tp: &TreePlan) -> bool {
        tp.vid != self.vid
            || (0..self.tags.len()).any(|j| {
                self.engine.is_live(j)
                    && tp
                        .plan
                        .ports
                        .iter()
                        .position(|p| p.name == self.engine.ports()[j].name)
                        .is_some_and(|k| tp.tags[k] != self.tags[j])
            })
    }

    /// Grow the per-slot vectors for the members an in-place update added.
    fn grow(&mut self, tp: &TreePlan) {
        for j in self.tags.len()..self.engine.ports().len() {
            let name = &self.engine.ports()[j].name;
            let k = tp.plan.ports.iter().position(|p| &p.name == name);
            self.tags.push(k.map_or(VlanTag::Untagged, |k| tp.tags[k]));
        }
        self.blocked.resize(self.tags.len(), false);
        self.quiet.resize(self.tags.len(), 0);
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    fn assignment(&self, j: usize) -> StpPortAssignment {
        let state = if self.blocked[j] {
            StpPortState::Blocking
        } else {
            ports::kernel_state(self.engine.port_state(j))
        };
        StpPortAssignment {
            port: self.engine.ports()[j].name.clone(),
            domain: self.domain.clone(),
            state,
        }
    }

    fn unblock(&mut self, j: usize, why: &str) -> Out {
        self.blocked[j] = false;
        info!(domain = %self.domain, port = %self.engine.ports()[j].name, reason = %why, "{}", events::PVID_CONSISTENT);
        Out::States(vec![self.assignment(j)])
    }
}

pub struct Pvst {
    trees: Vec<Tree>,
    priority: u16,
    mac: [u8; 6],
    rstp_version: bool,
    ext: u16,
}

impl Pvst {
    /// Every tree with all ports disabled; the outputs are the initial
    /// (blocking) states.
    pub fn new(plan: &Plan, mac: [u8; 6]) -> Result<(Self, Outs), IdError> {
        let mut trees = Vec::new();
        let mut outs = Vec::new();
        for (t, tp) in plan.pvst.iter().flatten().enumerate() {
            let (tree, init) = Tree::build(tp, mac, &HashMap::default())?;
            trees.push(tree);
            outs.extend(init.into_iter().map(|o| (t, o)));
        }
        Ok((
            Pvst {
                trees,
                priority: plan.priority,
                mac,
                rstp_version: plan.rstp_version,
                ext: plan.ext,
            },
            outs,
        ))
    }

    /// Apply a changed plan without restarting the other trees (#1122): each
    /// tree takes `Engine::apply_plan`; a VLAN or member-tag change restarts
    /// only that tree (port numbers kept); a new domain appends a tree; a
    /// removed one becomes a hidden `gone` slot. Also returns the trees whose
    /// engine is fresh (the daemon resets their link state). `Err(Rebuild)`
    /// for a top-level change; trees already edited stay, the caller rebuilds.
    pub fn apply_plan(&mut self, plan: &Plan) -> Result<(Outs, Vec<usize>), Rebuild> {
        let Some(new) = plan.pvst.as_ref() else {
            return Err(Rebuild);
        };
        if plan.rstp_version != self.rstp_version || plan.ext != self.ext {
            return Err(Rebuild);
        }
        self.priority = plan.priority;
        let (mut outs, mut restarted) = (Vec::new(), Vec::new());
        for t in 0..self.trees.len() {
            if self.trees[t].gone {
                continue;
            }
            let Some(tp) = new.iter().find(|tp| tp.domain == self.trees[t].domain) else {
                self.trees[t].gone = true;
                continue;
            };
            let tree = &mut self.trees[t];
            if tree.restarts(tp) {
                let prev = tree.engine.numbers();
                let (fresh, init) = Tree::build(tp, self.mac, &prev).map_err(|_| Rebuild)?;
                *tree = fresh;
                outs.extend(init.into_iter().map(|o| (t, o)));
                restarted.push(t);
            } else {
                let o = tree.engine.apply_plan(&tp.plan)?;
                tree.grow(tp);
                outs.extend(self.wrap(t, o));
            }
        }
        for tp in new {
            if self.trees.iter().any(|t| !t.gone && t.domain == tp.domain) {
                continue;
            }
            let (tree, init) =
                Tree::build(tp, self.mac, &HashMap::default()).map_err(|_| Rebuild)?;
            self.trees.push(tree);
            let t = self.trees.len() - 1;
            outs.extend(init.into_iter().map(|o| (t, o)));
        }
        Ok((outs, restarted))
    }

    pub fn trees(&self) -> &[Tree] {
        &self.trees
    }

    /// A frame of port `j` of tree `t` that did not decode.
    pub fn note_invalid(&mut self, t: usize, j: usize) {
        self.trees[t].engine.note_invalid(j);
    }

    /// Port `j` of tree `t` by name, if it is a member.
    pub fn locate(&self, t: usize, port: &str) -> Option<usize> {
        self.trees[t]
            .engine
            .ports()
            .iter()
            .position(|p| p.name == port)
    }

    /// Outputs of tree `t` with a PVID-blocked port forced to Blocking.
    fn wrap(&self, t: usize, outs: Vec<Out>) -> Outs {
        let tree = &self.trees[t];
        outs.into_iter()
            .map(|o| match o {
                Out::States(mut list) => {
                    for a in &mut list {
                        let blocked = tree
                            .engine
                            .ports()
                            .iter()
                            .position(|p| p.name == a.port)
                            .is_some_and(|j| tree.blocked[j]);
                        if blocked {
                            a.state = StpPortState::Blocking;
                        }
                    }
                    (t, Out::States(list))
                }
                o => (t, o),
            })
            .collect()
    }

    pub fn set_link(&mut self, t: usize, j: usize, enabled: bool, p2p: bool, cost: u32) -> Outs {
        let outs = self.trees[t].engine.set_link(j, enabled, p2p, cost);
        self.wrap(t, outs)
    }

    /// A BPDU of port `j` of tree `t`; `pvid` is the sender's Originating
    /// VLAN TLV, `None` from an IEEE frame or an older PVST+.
    pub fn receive(&mut self, t: usize, j: usize, bpdu: Bpdu, pvid: Option<u16>) -> Outs {
        let tree = &mut self.trees[t];
        tree.quiet[j] = 0;
        let mut outs = Vec::new();
        if let Some(got) = pvid.filter(|&p| p != tree.vid) {
            if !tree.blocked[j] {
                tree.blocked[j] = true;
                warn!(
                    domain = %tree.domain,
                    port = %tree.engine.ports()[j].name,
                    expected = tree.vid,
                    got,
                    "{}",
                    events::PVID_INCONSISTENT
                );
                outs.push(Out::States(vec![tree.assignment(j)]));
            }
            return self.wrap(t, outs);
        }
        if tree.blocked[j] {
            outs.push(tree.unblock(j, "bpdu"));
        }
        outs.extend(tree.engine.receive(j, bpdu));
        self.wrap(t, outs)
    }

    /// One second elapsed.
    pub fn tick(&mut self) -> Outs {
        let mut all = Vec::new();
        for t in 0..self.trees.len() {
            let tree = &mut self.trees[t];
            if tree.gone {
                continue;
            }
            let mut outs = tree.engine.tick();
            for j in 0..tree.blocked.len() {
                if !tree.blocked[j] {
                    continue;
                }
                tree.quiet[j] += 1;
                if tree.quiet[j] >= 3 * tree.hello {
                    outs.push(tree.unblock(j, "silence"));
                }
            }
            all.extend(self.wrap(t, outs));
        }
        all
    }

    /// Every state as it is now, for the periodic re-push.
    pub fn all_states(&self) -> Outs {
        (0..self.trees.len())
            .filter(|&t| !self.trees[t].gone)
            .flat_map(|t| self.wrap(t, self.trees[t].engine.all_states()))
            .collect()
    }

    pub fn summary(&self) -> StpSummary {
        let id = BridgeId::new(self.priority, 0, self.mac)
            .map_or_else(|_| String::new(), |id| identity::show(&id));
        StpSummary {
            enabled: true,
            mode: StpMode::RapidPvst,
            bridge_id: id.clone(),
            root_id: id,
            pvst: self
                .trees
                .iter()
                .filter(|tree| !tree.gone)
                .map(|tree| {
                    let mut v = tree.engine.tree_view(tree.vid);
                    for (j, p) in v.ports.iter_mut().enumerate() {
                        if tree.blocked[j] {
                            p.inconsistent = true;
                            p.state = StpState::Discarding;
                        }
                    }
                    v
                })
                .collect(),
            ..StpSummary::default()
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bpdu::{Flags, Params};
    use crate::ports::{Member, PortCfg, TreePlan};
    use crate::timers::Timers;
    use crate::vector::PortId;
    use nos_proto::schema::{EdgePort, LinkType};
    use StpPortState::{Blocking, Forwarding};

    fn port(name: &str, tag: VlanTag, domain: &str, cost: Option<u32>) -> PortCfg {
        PortCfg {
            name: name.into(),
            domains: vec![domain.into()],
            priority: 128,
            cost,
            edge: EdgePort::Disabled,
            link_type: LinkType::Auto,
            prot: crate::machines::Protections::default(),
            mst: Vec::new(),
            members: vec![Member {
                domain: domain.into(),
                tag,
                cost,
                priority: None,
            }],
        }
    }

    /// Trees `bd1` (VLAN 10) and `bd2` (VLAN 20) over `eth1`/`eth2`, both
    /// tagged; `costs` is the per-tree cost of eth1 and eth2.
    pub(crate) fn plan(prio: [u16; 2], costs: [[Option<u32>; 2]; 2]) -> Plan {
        let tree = |i: usize, d: &str, vid: u16| {
            let tag = VlanTag::Dot1q(vid);
            TreePlan {
                domain: d.into(),
                vid,
                plan: Box::new(Plan {
                    priority: prio[i],
                    rstp_version: true,
                    timers: Timers::default(),
                    ports: vec![
                        port("eth1", tag, d, costs[i][0]),
                        port("eth2", tag, d, costs[i][1]),
                    ],
                    mst: None,
                    ext: vid,
                    domain: Some(d.into()),
                    pvst: None,
                }),
                tags: vec![tag, tag],
            }
        };
        Plan {
            priority: 32768,
            rstp_version: true,
            timers: Timers::default(),
            ports: Vec::new(),
            mst: None,
            ext: 0,
            domain: None,
            pvst: Some(vec![tree(0, "bd1", 10), tree(1, "bd2", 20)]),
        }
    }

    /// Two bridges joined by eth1-eth1 and eth2-eth2.
    struct Net {
        b: [Pvst; 2],
        /// Last pushed kernel state of `(bridge, port, domain)`.
        pushed: HashMap<(usize, String, String), StpPortState>,
        queue: Vec<(usize, usize, usize, Bpdu)>,
    }

    impl Net {
        fn new(a: &Plan, b: &Plan) -> Net {
            let (pa, oa) = Pvst::new(a, [2, 0, 0, 0, 0, 1]).unwrap();
            let (pb, ob) = Pvst::new(b, [2, 0, 0, 0, 0, 2]).unwrap();
            let mut n = Net {
                b: [pa, pb],
                pushed: HashMap::new(),
                queue: Vec::new(),
            };
            n.handle(0, oa);
            n.handle(1, ob);
            for i in 0..2 {
                for t in 0..2 {
                    for j in 0..2 {
                        let cost = crate::link::path_cost(
                            n.b[i].trees[t].engine().ports()[j].cost,
                            crate::link::LinkInfo::default(),
                        );
                        let o = n.b[i].set_link(t, j, true, true, cost);
                        n.handle(i, o);
                    }
                }
            }
            n
        }

        fn handle(&mut self, from: usize, outs: Outs) {
            for (t, o) in outs {
                match o {
                    Out::Tx { port, bpdu } => self.queue.push((from, t, port, bpdu)),
                    Out::States(list) => {
                        for a in list {
                            self.pushed.insert((from, a.port, a.domain), a.state);
                        }
                    }
                    _ => {}
                }
            }
        }

        fn settle(&mut self) {
            while !self.queue.is_empty() {
                let (from, t, j, bpdu) = self.queue.remove(0);
                let to = 1 - from;
                let vid = self.b[from].trees[t].vid;
                let o = self.b[to].receive(t, j, bpdu, Some(vid));
                self.handle(to, o);
            }
        }

        fn run(&mut self, secs: u32) {
            self.settle();
            for _ in 0..secs {
                for i in 0..2 {
                    let o = self.b[i].tick();
                    self.handle(i, o);
                }
                self.settle();
            }
        }

        fn state(&self, bridge: usize, port: &str, domain: &str) -> StpPortState {
            self.pushed[&(bridge, port.to_string(), domain.to_string())]
        }
    }

    #[test]
    fn two_trees_elect_different_roots_and_block_different_links() {
        // bd1: bridge 0 is the root, so bridge 1 blocks its expensive eth1;
        // bd2: bridge 1 is the root, so bridge 0 blocks its expensive eth2.
        let a = plan([4096, 32768], [[None, None], [None, Some(100_000)]]);
        let b = plan([32768, 4096], [[Some(100_000), None], [None, None]]);
        let mut n = Net::new(&a, &b);
        n.run(40);
        assert_eq!(n.state(1, "eth1", "bd1"), Blocking);
        assert_eq!(n.state(1, "eth2", "bd1"), Forwarding);
        assert_eq!(n.state(0, "eth2", "bd2"), Blocking);
        assert_eq!(n.state(0, "eth1", "bd2"), Forwarding);
        for p in ["eth1", "eth2"] {
            assert_eq!(n.state(0, p, "bd1"), Forwarding, "root forwards everywhere");
            assert_eq!(n.state(1, p, "bd2"), Forwarding, "root forwards everywhere");
        }
        let s = n.b[0].summary();
        assert_eq!(s.mode, StpMode::RapidPvst);
        let bd1 = &s.pvst[0];
        assert_eq!((bd1.id, bd1.root_port.clone()), (10, None));
        assert_eq!(bd1.bridge_id, bd1.root_id, "bridge 0 roots VLAN 10");
        // priority 4096 + VLAN 10 is 0x100a on the wire
        assert!(bd1.bridge_id.starts_with("100a."), "{}", bd1.bridge_id);
        assert_ne!(s.pvst[1].bridge_id, s.pvst[1].root_id);
        assert_eq!(s.pvst[1].root_port.as_deref(), Some("eth1"));
    }

    fn up(p: &mut Pvst) {
        for t in 0..p.trees.len() {
            for j in 0..2 {
                p.set_link(t, j, true, true, 20_000);
            }
        }
    }

    fn numbers(p: &Pvst, t: usize) -> HashMap<String, u16> {
        p.trees[t].engine().numbers()
    }

    #[test]
    fn an_edit_of_one_tree_leaves_the_other_alone() {
        let a = plan([32768; 2], [[None; 2]; 2]);
        let (mut p, _) = Pvst::new(&a, [2; 6]).unwrap();
        up(&mut p);
        let before = numbers(&p, 1);
        let state1 = p.trees[1].engine().port_state(0);
        let mut b = a.clone();
        let t0 = &mut b.pvst.as_mut().unwrap()[0].plan;
        t0.priority = 4096;
        t0.ports[0].cost = Some(500);
        t0.ports[0].priority = 64;
        let (outs, restarted) = p.apply_plan(&b).unwrap();
        assert_eq!(restarted, Vec::<usize>::new());
        assert!(outs.iter().all(|(t, _)| *t == 0), "only bd1 speaks");
        assert!(p.trees[0]
            .engine()
            .tree_view(10)
            .bridge_id
            .starts_with("100a."));
        assert_eq!(numbers(&p, 1), before);
        assert_eq!(
            p.trees[1].engine().port_state(0),
            state1,
            "bd2 keeps its machines"
        );
    }

    #[test]
    fn a_tree_is_added_then_removed_as_a_hidden_slot() {
        let a = plan([32768; 2], [[None; 2]; 2]);
        let (mut p, _) = Pvst::new(&a, [2; 6]).unwrap();
        up(&mut p);
        let mut b = a.clone();
        let mut extra = b.pvst.as_ref().unwrap()[0].clone();
        extra.domain = "bd3".into();
        extra.vid = 30;
        extra.plan.ext = 30;
        extra.plan.domain = Some("bd3".into());
        let tag = VlanTag::Dot1q(30);
        extra.tags = vec![tag; 2];
        b.pvst.as_mut().unwrap().push(extra);
        let (outs, _) = p.apply_plan(&b).unwrap();
        assert_eq!(p.trees.len(), 3);
        assert!(outs.iter().any(|(t, _)| *t == 2), "initial states of bd3");
        assert_eq!(p.summary().pvst.len(), 3);
        // Remove bd2: slot 1 stays, hidden.
        b.pvst.as_mut().unwrap().remove(1);
        p.apply_plan(&b).unwrap();
        assert_eq!(p.trees.len(), 3);
        assert!(p.trees[1].is_gone());
        assert_eq!(p.summary().pvst.len(), 2);
        assert!(p.tick().iter().all(|(t, _)| *t != 1));
        assert!(p.all_states().iter().all(|(t, _)| *t != 1));
        // Bringing the domain back appends a fresh tree.
        p.apply_plan(&a).unwrap();
        assert_eq!(p.trees.len(), 4);
        assert!(p.trees[2].is_gone() && !p.trees[3].is_gone());
    }

    #[test]
    fn a_tag_or_vlan_change_restarts_only_that_tree_keeping_its_numbers() {
        let a = plan([32768; 2], [[None; 2]; 2]);
        let (mut p, _) = Pvst::new(&a, [2; 6]).unwrap();
        up(&mut p);
        // A member added to bd1 takes number 3; the numbers survive a restart.
        let mut b = a.clone();
        let t0 = &mut b.pvst.as_mut().unwrap()[0];
        let mut eth3 = t0.plan.ports[0].clone();
        eth3.name = "eth3".into();
        t0.plan.ports.insert(0, eth3);
        t0.tags.insert(0, VlanTag::Dot1q(10));
        p.apply_plan(&b).unwrap();
        let nums = numbers(&p, 0);
        assert_eq!(nums["eth3"], 3);
        let other = numbers(&p, 1);
        let mut c = b.clone();
        let t0 = &mut c.pvst.as_mut().unwrap()[0];
        t0.tags[1] = VlanTag::Untagged;
        let (_, restarted) = p.apply_plan(&c).unwrap();
        assert_eq!(restarted, vec![0]);
        assert_eq!(numbers(&p, 0), nums);
        assert_eq!(numbers(&p, 1), other);
        assert_eq!(p.trees[0].tags[1], VlanTag::Untagged);
        // A VLAN change restarts too.
        let mut d = c.clone();
        let t0 = &mut d.pvst.as_mut().unwrap()[0];
        t0.vid = 11;
        t0.plan.ext = 11;
        assert_eq!(p.apply_plan(&d).unwrap().1, vec![0]);
        assert_eq!(p.trees[0].vid, 11);
    }

    #[test]
    fn a_top_level_change_needs_a_rebuild() {
        let a = plan([32768; 2], [[None; 2]; 2]);
        let (mut p, _) = Pvst::new(&a, [2; 6]).unwrap();
        let mut b = a.clone();
        b.rstp_version = false;
        assert!(p.apply_plan(&b).is_err());
        b = a.clone();
        b.pvst = None;
        assert!(p.apply_plan(&b).is_err());
    }

    fn rst(vid_priority: u16) -> Bpdu {
        let root = BridgeId::new(vid_priority, 10, [2, 0, 0, 0, 0, 9]).unwrap();
        Bpdu::Rst(Params {
            flags: Flags(0x3c),
            root,
            root_path_cost: 0,
            bridge: root,
            port: PortId::new(128, 1).unwrap(),
            message_age: 0,
            max_age: 20 << 8,
            hello_time: 2 << 8,
            forward_delay: 15 << 8,
        })
    }

    fn states(outs: &Outs) -> Vec<StpPortAssignment> {
        outs.iter()
            .filter_map(|(_, o)| match o {
                Out::States(s) => Some(s.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    #[test]
    fn a_pvid_mismatch_blocks_once_and_a_matching_bpdu_clears_it() {
        let (mut p, _) = Pvst::new(&plan([32768; 2], [[None; 2]; 2]), [2; 6]).unwrap();
        p.set_link(0, 0, true, true, 20_000);
        let first = p.receive(0, 0, rst(4096), Some(99));
        let s = states(&first);
        assert_eq!(s.len(), 1);
        assert_eq!(
            (s[0].port.as_str(), s[0].domain.as_str(), s[0].state),
            ("eth1", "bd1", StpPortState::Blocking)
        );
        assert!(p.summary().pvst[0].ports[0].inconsistent);
        assert!(
            !p.summary().pvst[1].ports[0].inconsistent,
            "other trees are untouched"
        );
        assert!(
            states(&p.receive(0, 0, rst(4096), Some(99))).is_empty(),
            "logged and pushed once"
        );
        // The engine never saw the BPDU: no root changed.
        assert_eq!(p.summary().pvst[0].root_port, None);
        // A consistent BPDU clears the block and reaches the machines.
        let back = p.receive(0, 0, rst(4096), Some(10));
        assert!(states(&back).iter().any(|a| a.port == "eth1"));
        assert!(!p.summary().pvst[0].ports[0].inconsistent);
        assert_eq!(p.summary().pvst[0].root_port.as_deref(), Some("eth1"));
    }

    #[test]
    fn silence_clears_a_pvid_block_after_three_hellos() {
        let (mut p, _) = Pvst::new(&plan([32768; 2], [[None; 2]; 2]), [2; 6]).unwrap();
        p.set_link(0, 0, true, true, 20_000);
        p.receive(0, 0, rst(4096), Some(99));
        for _ in 0..5 {
            p.tick();
        }
        assert!(p.summary().pvst[0].ports[0].inconsistent);
        p.tick();
        assert!(!p.summary().pvst[0].ports[0].inconsistent, "3 x 2 s passed");
    }

    #[test]
    fn an_old_pvst_peer_flips_only_its_own_tree() {
        let (mut p, _) = Pvst::new(&plan([32768; 2], [[None; 2]; 2]), [2; 6]).unwrap();
        for t in 0..2 {
            p.set_link(t, 0, true, true, 20_000);
        }
        let Bpdu::Rst(params) = rst(4096) else {
            unreachable!()
        };
        for _ in 0..4 {
            p.tick(); // Migrate Time: PPM starts by checking for RSTP
        }
        p.receive(0, 0, Bpdu::Config(params), Some(10));
        let s = p.summary();
        assert!(s.pvst[0].ports[0].compat, "bd1 talks 802.1D to this peer");
        assert!(!s.pvst[1].ports[0].compat, "bd2 still talks RSTP");
    }

    #[test]
    fn the_native_rule_sends_both_forms_and_hears_ieee_only_untagged() {
        assert_eq!(tx_wires(VlanTag::Untagged), [Wire::Sstp, Wire::Ieee]);
        assert_eq!(tx_wires(VlanTag::Dot1q(10)), [Wire::Sstp]);
        assert!(accepts(VlanTag::Untagged, Wire::Ieee));
        assert!(accepts(VlanTag::Untagged, Wire::Sstp));
        assert!(accepts(VlanTag::Dot1q(10), Wire::Sstp));
        assert!(!accepts(VlanTag::Dot1q(10), Wire::Ieee));
        assert_eq!(link_name("eth1", VlanTag::Dot1q(10)), "eth1.10");
        assert_eq!(link_name("eth1", VlanTag::Untagged), "eth1");
    }

    #[test]
    fn the_bridge_id_carries_the_vlan_as_its_extension() {
        let id = BridgeId::new(4096, 10, [2, 0, 0, 0, 0, 1]).unwrap();
        assert_eq!(id.to_bytes(), [0x10, 0x0a, 2, 0, 0, 0, 0, 1]);
        let id = BridgeId::new(32768, 1, [2, 0, 0, 0, 0, 1]).unwrap();
        assert_eq!(id.to_bytes(), [0x80, 0x01, 2, 0, 0, 0, 0, 1]);
    }
}
