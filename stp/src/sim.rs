//! Deterministic multi-bridge simulator (test-only).
//!
//! N [`Bridge`]s joined by in-memory links (two ends = point-to-point, more =
//! shared segment). Frames are delivered instantly and in order; time only
//! moves when [`Sim::tick`] is called. To read a failing scenario: print
//! [`Sim::dump`] (role/state per port) after the `run` that did not converge.

use std::fmt::Write;

use crate::actions::{Action, PortState};
use crate::bpdu::Bpdu;
use crate::bridge::{Bridge, PortParams};
use crate::machines::Role;
use crate::timers::Timers;
use crate::vector::{BridgeId, PortId};

pub struct Link {
    /// (bridge, port) pairs.
    pub ends: Vec<(usize, usize)>,
    pub up: bool,
}

pub struct Sim {
    pub bridges: Vec<Bridge>,
    pub links: Vec<Link>,
    pub secs: u32,
    pub flushes: usize,
}

/// A link between the listed bridges with the given path cost on every end.
#[derive(Debug, Clone)]
pub struct Spec {
    pub ends: Vec<usize>,
    pub cost: u32,
}

pub fn p2p(a: usize, b: usize) -> Spec {
    Spec {
        ends: vec![a, b],
        cost: 20_000,
    }
}

fn find(p: &mut [usize], x: usize) -> usize {
    if p[x] != x {
        let r = find(p, p[x]);
        p[x] = r;
    }
    p[x]
}

impl Sim {
    /// Bridge `i` has priority `prios[i]` and MAC `i + 1`; ports are numbered in link order.
    pub fn new(prios: &[u16], specs: &[Spec]) -> Self {
        let mut params: Vec<Vec<PortParams>> = vec![Vec::new(); prios.len()];
        let mut links = Vec::new();
        for s in specs {
            let mut ends = Vec::new();
            for &b in &s.ends {
                let n = u16::try_from(params[b].len() + 1).unwrap();
                params[b].push(PortParams {
                    id: PortId::new(128, n).unwrap(),
                    path_cost: s.cost,
                    admin_edge: false,
                    auto_edge: false,
                });
                ends.push((b, params[b].len() - 1));
            }
            links.push(Link { ends, up: true });
        }
        let bridges = prios
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                let mac = [0, 0, 0, 0, 0, u8::try_from(i + 1).unwrap()];
                Bridge::new(
                    BridgeId::new(p, 0, mac).unwrap(),
                    Timers::default(),
                    &params[i],
                )
            })
            .collect();
        Sim {
            bridges,
            links,
            secs: 0,
            flushes: 0,
        }
    }

    /// Bring every link up (BEGIN is done, ports are administratively down until now).
    pub fn start(&mut self) {
        for l in 0..self.links.len() {
            self.set_link(l, true);
        }
    }

    pub fn set_link(&mut self, l: usize, up: bool) {
        self.links[l].up = up;
        let p2p = self.links[l].ends.len() == 2;
        for k in 0..self.links[l].ends.len() {
            let (b, p) = self.links[l].ends[k];
            self.bridges[b].set_oper_point_to_point(p, p2p);
            self.bridges[b].set_port_enabled(p, up);
            self.settle();
        }
    }

    /// Deliver queued BPDUs until the network is silent.
    pub fn settle(&mut self) {
        for _ in 0..100_000 {
            let mut sent = false;
            for i in 0..self.bridges.len() {
                for a in self.bridges[i].take_actions() {
                    match a {
                        Action::Transmit { port, bpdu } => {
                            sent = true;
                            self.deliver(i, port, &bpdu);
                        }
                        Action::FlushFdb { .. } => self.flushes += 1,
                        Action::SetPortState { .. }
                        | Action::ErrDisable { .. }
                        | Action::ErrRecover { .. }
                        | Action::Log(_) => {}
                    }
                }
            }
            if !sent {
                return;
            }
        }
        panic!("BPDU storm: the network never went silent\n{}", self.dump());
    }

    fn deliver(&mut self, from: usize, port: usize, bpdu: &Bpdu) {
        let ends = self
            .links
            .iter()
            .find(|l| l.ends.contains(&(from, port)))
            .filter(|l| l.up)
            .map(|l| l.ends.clone())
            .unwrap_or_default();
        for (j, q) in ends.into_iter().filter(|&e| e != (from, port)) {
            self.bridges[j].receive(q, *bpdu);
        }
    }

    pub fn tick(&mut self) {
        self.secs += 1;
        self.bridges.iter_mut().for_each(Bridge::tick);
        self.settle();
    }

    pub fn run(&mut self, secs: u32) {
        for _ in 0..secs {
            self.tick();
        }
    }

    /// One root everywhere, every port settled (Root/Designated Forwarding,
    /// Alternate/Backup/Disabled Discarding) and the forwarding links a tree.
    /// The tree test matters: while stale root info circulates after a cut
    /// (count to infinity, until its message age hits max age) every port
    /// looks settled.
    pub fn converged(&self) -> bool {
        let roots: Vec<_> = self.bridges.iter().map(|b| b.root_id).collect();
        roots.windows(2).all(|w| w[0] == w[1])
            && self.is_spanning_tree()
            && self.bridges.iter().all(|b| {
                (0..b.ports.len()).all(|p| {
                    let want = match b.role(p) {
                        Role::Root | Role::Designated => PortState::Forwarding,
                        _ => PortState::Discarding,
                    };
                    b.ports[p].selected && b.port_state(p) == want
                })
            })
    }

    /// Ticks until converged, `None` if it does not within `max`.
    pub fn converge(&mut self, max: u32) -> Option<u32> {
        let t0 = self.secs;
        for _ in 0..=max {
            if self.converged() {
                return Some(self.secs - t0);
            }
            self.tick();
        }
        None
    }

    /// Links whose every up end is Forwarding.
    pub fn active_links(&self) -> Vec<usize> {
        (0..self.links.len())
            .filter(|&l| {
                let k = &self.links[l];
                k.up && k
                    .ends
                    .iter()
                    .all(|&(b, p)| self.bridges[b].port_state(p) == PortState::Forwarding)
            })
            .collect()
    }

    pub fn blocking_ports(&self) -> usize {
        self.bridges
            .iter()
            .flat_map(|b| (0..b.ports.len()).map(move |p| (b, p)))
            .filter(|&(b, p)| matches!(b.role(p), Role::Alternate | Role::Backup))
            .count()
    }

    /// True when the active links connect all bridges without a cycle.
    pub fn is_spanning_tree(&self) -> bool {
        let n = self.bridges.len();
        let mut parent: Vec<usize> = (0..n).collect();
        let mut joins = 0;
        for l in self.active_links() {
            let e = &self.links[l].ends;
            for k in &e[1..] {
                let (a, b) = (find(&mut parent, e[0].0), find(&mut parent, k.0));
                if a == b {
                    return false;
                }
                parent[a] = b;
                joins += 1;
            }
        }
        joins == n - 1
    }

    pub fn dump(&self) -> String {
        let mut s = String::new();
        for (i, b) in self.bridges.iter().enumerate() {
            writeln!(
                s,
                "bridge {i} root-port {:?} root {:?}",
                b.root_port,
                b.root_id.mac()
            )
            .unwrap();
            for p in 0..b.ports.len() {
                writeln!(s, "  port {p}: {:?} {:?}", b.role(p), b.port_state(p)).unwrap();
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(s: &Sim, b: usize, p: usize) -> Role {
        s.bridges[b].role(p)
    }

    fn started(prios: &[u16], links: &[Spec]) -> Sim {
        let mut s = Sim::new(prios, links);
        s.start();
        s
    }

    #[test]
    fn two_bridges_p2p_converge_without_waiting_for_forward_delay() {
        let mut s = started(&[4096, 32768], &[p2p(0, 1)]);
        let t = s.converge(60).unwrap_or_else(|| panic!("{}", s.dump()));
        assert!(t < 2 * 2, "proposal/agreement took {t} s\n{}", s.dump());
        assert_eq!(role(&s, 0, 0), Role::Designated);
        assert_eq!(role(&s, 1, 0), Role::Root);
    }

    #[test]
    fn triangle_blocks_exactly_one_port() {
        let mut s = started(&[4096, 32768, 36864], &[p2p(0, 1), p2p(1, 2), p2p(0, 2)]);
        let t = s.converge(60).unwrap_or_else(|| panic!("{}", s.dump()));
        assert!(t < 15, "{t} s\n{}", s.dump());
        assert_eq!(s.blocking_ports(), 1, "{}", s.dump());
        assert!(s.is_spanning_tree(), "{}", s.dump());
        // 1 and 2 reach the root directly; the 1-2 link is the one that blocks.
        assert_eq!(role(&s, 2, 0), Role::Alternate, "{}", s.dump());
    }

    #[test]
    fn square_with_redundant_link() {
        // 0-1, 1-2, 2-3, 3-0 plus the diagonal 0-2.
        let mut s = started(
            &[4096, 8192, 12288, 16384],
            &[p2p(0, 1), p2p(1, 2), p2p(2, 3), p2p(3, 0), p2p(0, 2)],
        );
        s.converge(60).unwrap_or_else(|| panic!("{}", s.dump()));
        assert!(s.is_spanning_tree(), "{}", s.dump());
        assert_eq!(s.blocking_ports(), 2, "two independent loops\n{}", s.dump());
    }

    #[test]
    fn lowering_a_priority_moves_the_root() {
        let mut s = started(&[4096, 32768, 32768], &[p2p(0, 1), p2p(1, 2), p2p(0, 2)]);
        s.converge(60).unwrap();
        s.bridges[2].set_bridge_id(BridgeId::new(0, 0, [0, 0, 0, 0, 0, 3]).unwrap());
        s.settle();
        s.converge(60).unwrap_or_else(|| panic!("{}", s.dump()));
        assert!(s.bridges.iter().all(|b| b.root_id.priority() == 0));
        assert_eq!(s.bridges[2].root_port, None);
        assert!(s.is_spanning_tree(), "{}", s.dump());
    }

    #[test]
    fn upstream_priority_worsening_reaches_downstream_without_waiting() {
        // #661: a changed sender priority is the same sender, so the worse
        // vector replaces the stored one at the next BPDU, not at rcvdInfoWhile.
        let mut s = started(&[4096, 32768], &[p2p(0, 1)]);
        s.converge(60).unwrap();
        s.bridges[0].set_bridge_id(BridgeId::new(8192, 0, [0, 0, 0, 0, 0, 1]).unwrap());
        s.settle();
        assert_eq!(s.bridges[1].root_id.priority(), 8192, "{}", s.dump());
    }

    #[test]
    fn link_cut_reconverges_over_the_alternate() {
        let mut s = started(&[4096, 32768, 36864], &[p2p(0, 1), p2p(1, 2), p2p(0, 2)]);
        s.converge(60).unwrap();
        s.set_link(2, false); // 0-2: bridge 2's root port
        let t = s.converge(60).unwrap_or_else(|| panic!("{}", s.dump()));
        assert!(t < 15, "failover waited for timers: {t} s\n{}", s.dump());
        assert_eq!(role(&s, 2, 0), Role::Root, "{}", s.dump());
        assert!(s.flushes > 0, "topology change flushed the FDB");
        s.set_link(2, true);
        s.converge(60).unwrap_or_else(|| panic!("{}", s.dump()));
        assert!(s.is_spanning_tree(), "{}", s.dump());
    }

    #[test]
    fn shared_segment_falls_back_to_forward_delay() {
        // Three bridges on one shared medium: no point-to-point handshake.
        let mut s = started(
            &[4096, 32768, 36864],
            &[Spec {
                ends: vec![0, 1, 2],
                cost: 20_000,
            }],
        );
        s.run(3);
        assert!(
            !s.converged(),
            "shared medium must not converge at once\n{}",
            s.dump()
        );
        let t = s.converge(200).unwrap_or_else(|| panic!("{}", s.dump()));
        let fd = u32::from(Timers::default().forward_delay);
        assert!(t + 3 >= fd, "converged in {t} s, before forward delay");
        assert_eq!(role(&s, 0, 0), Role::Designated);
        assert_eq!(role(&s, 1, 0), Role::Root);
        assert_eq!(role(&s, 2, 0), Role::Root);
    }

    fn legacy(s: &mut Sim, b: usize) {
        s.bridges[b].set_rstp_version(false);
    }

    #[test]
    fn forced_stp_bridge_interoperates_and_never_sends_rstp() {
        let mut s = Sim::new(&[4096, 32768, 36864], &[p2p(0, 1), p2p(1, 2), p2p(0, 2)]);
        legacy(&mut s, 1);
        s.start();
        let t = s.converge(120).unwrap_or_else(|| panic!("{}", s.dump()));
        assert!(
            s.is_spanning_tree() && s.blocking_ports() == 1,
            "{t} s\n{}",
            s.dump()
        );
        assert!(s.bridges[1].ports.iter().all(|p| !p.send_rstp));
        // The RSTP neighbours heard its Config BPDUs and fell back on that port only.
        assert!(!s.bridges[0].ports[0].send_rstp, "{}", s.dump());
        assert!(s.bridges[0].ports[1].send_rstp, "{}", s.dump());
    }

    #[test]
    fn legacy_topology_change_goes_through_tcn_and_flushes() {
        let mut s = Sim::new(&[4096, 32768, 36864], &[p2p(0, 1), p2p(1, 2), p2p(0, 2)]);
        for b in 0..3 {
            legacy(&mut s, b);
        }
        s.start();
        s.converge(120).unwrap_or_else(|| panic!("{}", s.dump()));
        s.run(10);
        let before = s.flushes;
        s.set_link(2, false); // bridge 2's root port: its alternate takes over
        s.converge(200).unwrap_or_else(|| panic!("{}", s.dump()));
        assert!(s.flushes > before, "TC reached the bridges' FDBs");
        assert!(s.is_spanning_tree(), "{}", s.dump());
        s.run(60);
        assert!(s.converged(), "{}", s.dump());
    }

    #[test]
    fn mcheck_probes_rstp_and_a_legacy_peer_pulls_the_port_back() {
        let mut s = started(&[4096, 32768], &[p2p(0, 1)]);
        legacy(&mut s, 0);
        s.converge(120).unwrap_or_else(|| panic!("{}", s.dump()));
        assert!(!s.bridges[1].ports[0].send_rstp);
        s.bridges[1].mcheck(0);
        assert!(s.bridges[1].ports[0].send_rstp, "mcheck restarts in RSTP");
        s.run(10); // the legacy peer keeps sending Config BPDUs
        assert!(!s.bridges[1].ports[0].send_rstp);
        // The peer upgrades; the next mcheck sticks.
        s.bridges[0].set_rstp_version(true);
        s.run(5);
        s.bridges[1].mcheck(0);
        s.run(10);
        assert!(s.bridges[1].ports[0].send_rstp);
        assert!(s.converged(), "{}", s.dump());
    }

    mod random {
        use super::*;
        use proptest::prelude::*;

        /// A connected random graph: a random tree plus extra (possibly parallel) links.
        fn graph() -> impl Strategy<Value = (Vec<u16>, Vec<Spec>)> {
            (4usize..=8).prop_flat_map(|n| {
                (
                    proptest::collection::vec(0u16..16, n),
                    proptest::collection::vec(any::<prop::sample::Index>(), n - 1),
                    proptest::collection::vec((0..n, 0..n), 0..6),
                    proptest::collection::vec(1u32..200_000, 16),
                )
                    .prop_map(move |(prios, parents, extra, costs)| {
                        let mut pairs: Vec<(usize, usize)> = parents
                            .iter()
                            .enumerate()
                            .map(|(i, p)| (p.index(i + 1), i + 1))
                            .collect();
                        pairs.extend(extra.into_iter().filter(|(a, b)| a != b));
                        let specs = pairs
                            .into_iter()
                            .enumerate()
                            .map(|(k, (a, b))| Spec {
                                ends: vec![a, b],
                                cost: costs[k % costs.len()],
                            })
                            .collect();
                        (prios.into_iter().map(|p| p * 4096).collect(), specs)
                    })
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn random_graphs_converge_to_a_spanning_tree(g in graph()) {
                let (prios, specs) = g;
                let mut s = started(&prios, &specs);
                prop_assert!(s.converge(200).is_some(), "{}", s.dump());
                s.run(60);
                prop_assert!(s.converged(), "unstable after converging\n{}", s.dump());
                // The root is the lowest bridge ID (MAC = index + 1 breaks priority ties).
                let want = s.bridges.iter().map(|b| b.id).min().unwrap();
                prop_assert!(s.bridges.iter().all(|b| b.root_id == want), "{}", s.dump());
                for b in &s.bridges {
                    let roots = (0..b.ports.len()).filter(|&p| b.role(p) == Role::Root).count();
                    prop_assert_eq!(roots, usize::from(b.id != want));
                }
            }

            #[test]
            fn a_cut_link_still_leaves_a_spanning_tree(g in graph(), cut in any::<prop::sample::Index>()) {
                let (prios, specs) = g;
                let mut s = started(&prios, &specs);
                prop_assert!(s.converge(200).is_some());
                let l = cut.index(s.links.len());
                // Skip cuts that disconnect the graph (a tree edge with no redundancy).
                let mut t = started(&prios, &specs);
                t.links[l].up = false;
                let n = t.bridges.len();
                let mut seen = vec![false; n];
                let mut stack = vec![0];
                while let Some(x) = stack.pop() {
                    if std::mem::replace(&mut seen[x], true) { continue; }
                    for k in t.links.iter().filter(|k| k.up) {
                        let e: Vec<_> = k.ends.iter().map(|e| e.0).collect();
                        if e.contains(&x) { stack.extend(e); }
                    }
                }
                if !seen.iter().all(|&v| v) {
                    return Ok(()); // the cut partitions the graph: nothing to span
                }
                s.set_link(l, false);
                prop_assert!(s.converge(200).is_some(), "{}", s.dump());
                prop_assert!(s.is_spanning_tree(), "{}", s.dump());
            }
        }
    }
}
