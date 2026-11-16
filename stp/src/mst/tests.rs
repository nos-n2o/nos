use std::collections::{HashMap, VecDeque};

use nos_proto::schema::{EdgePort, LinkType};
use nos_proto::StpPortState::{Blocking, Forwarding};
use nos_proto::{StpPortState, StpRole, StpState};

use super::*;
use crate::bpdu::{decode_any, encode, encode_mst};
use crate::engine::{Engine, Out};
use crate::machines::Protections;
use crate::ports::{Plan, PortCfg};

fn port(name: &str, mst: Vec<PortMst>) -> PortCfg {
    PortCfg {
        name: name.into(),
        domains: vec!["d1".into(), "d2".into()],
        priority: 128,
        cost: None,
        edge: EdgePort::Disabled,
        link_type: LinkType::Auto,
        prot: Protections::default(),
        mst,
        members: Vec::new(),
    }
}

fn mst_plan(revision: u16, prio1: u16, prio2: u16) -> MstPlan {
    let domains = vec![("d1".into(), 10, 1), ("d2".into(), 20, 2)];
    MstPlan {
        name: "lab".into(),
        revision,
        digest: digest::digest(&vidmap::table(&domains)),
        max_hops: 20,
        instances: vec![(1, prio1), (2, prio2)],
        domains,
    }
}

fn plan(priority: u16, mst: MstPlan, costs: [Vec<PortMst>; 2]) -> Plan {
    let [c0, c1] = costs;
    Plan {
        priority,
        rstp_version: true,
        timers: Timers::default(),
        ports: vec![port("eth1", c0), port("eth2", c1)],
        mst: Some(mst),
        ext: 0,
        domain: None,
        pvst: None,
    }
}

fn expensive(id: u16) -> Vec<PortMst> {
    vec![PortMst {
        id,
        cost: Some(100_000),
        priority: 128,
    }]
}

/// Two engines joined by two links (port i to port i).
struct Net {
    e: [Engine; 2],
    /// Last pushed kernel state of `(engine, port, domain)`.
    kernel: HashMap<(usize, String, String), StpPortState>,
}

impl Net {
    fn new(a: &Plan, b: &Plan) -> Net {
        let (ea, oa) = Engine::new(a, [2, 0, 0, 0, 0, 1]).unwrap();
        let (eb, ob) = Engine::new(b, [2, 0, 0, 0, 0, 2]).unwrap();
        let mut n = Net {
            e: [ea, eb],
            kernel: HashMap::new(),
        };
        n.pump([oa, ob]);
        for i in 0..2 {
            for side in 0..2 {
                let o = n.e[side].set_link(i, true, true, 2_000);
                let mut outs = [Vec::new(), Vec::new()];
                outs[side] = o;
                n.pump(outs);
            }
        }
        n
    }

    fn pump(&mut self, outs: [Vec<Out>; 2]) {
        let mut q = VecDeque::new();
        let handle = |side: usize, outs: Vec<Out>, q: &mut VecDeque<_>, net: &mut Net| {
            for o in outs {
                match o {
                    Out::Tx { port, bpdu } => {
                        q.push_back((1 - side, port, decode_any(&encode(&bpdu)).unwrap()));
                    }
                    Out::TxMst { port, bpdu } => {
                        q.push_back((1 - side, port, decode_any(&encode_mst(&bpdu)).unwrap()));
                    }
                    Out::States(list) => {
                        for a in list {
                            net.kernel.insert((side, a.port, a.domain), a.state);
                        }
                    }
                    Out::Flush(_) | Out::ErrDisabled { .. } => {}
                }
            }
        };
        for (side, o) in outs.into_iter().enumerate() {
            handle(side, o, &mut q, self);
        }
        for _ in 0..100_000 {
            let Some((to, port, rx)) = q.pop_front() else {
                return;
            };
            let o = self.e[to].receive_rx(port, rx);
            handle(to, o, &mut q, self);
        }
        panic!("BPDU exchange did not settle");
    }

    fn run(&mut self, secs: u32) {
        for _ in 0..secs {
            let o = [self.e[0].tick(), self.e[1].tick()];
            self.pump(o);
        }
    }

    fn state(&self, side: usize, port: &str, domain: &str) -> StpPortState {
        self.kernel[&(side, port.to_string(), domain.to_string())]
    }

    fn tree(&self, side: usize, id: u16) -> nos_proto::StpInstance {
        let s = self.e[side].summary();
        s.mst
            .unwrap()
            .instances
            .into_iter()
            .find(|i| i.id == id)
            .unwrap()
    }
}

fn two_trees() -> Net {
    // A: CIST root, root of MSTI 1; B: root of MSTI 2. B's eth1 is expensive
    // in MSTI 1 and A's eth1 in MSTI 2, so each tree blocks the other link.
    Net::new(
        &plan(4096, mst_plan(1, 4096, 32768), [expensive(2), vec![]]),
        &plan(32768, mst_plan(1, 32768, 4096), [expensive(1), vec![]]),
    )
}

#[test]
fn each_msti_blocks_its_own_link_and_the_domain_follows_its_tree() {
    let mut n = two_trees();
    n.run(60);
    let (a1, a2) = (n.tree(0, 1), n.tree(0, 2));
    let (b1, b2) = (n.tree(1, 1), n.tree(1, 2));
    assert_eq!(
        (a1.root_port.as_deref(), a1.root_id == a1.bridge_id),
        (None, true)
    );
    assert_eq!(
        (b2.root_port.as_deref(), b2.root_id == b2.bridge_id),
        (None, true)
    );
    assert_eq!(b1.root_port.as_deref(), Some("eth2"));
    assert_eq!(a2.root_port.as_deref(), Some("eth2"));
    let port = |t: &nos_proto::StpInstance, name: &str| {
        t.ports.iter().find(|p| p.name == name).unwrap().clone()
    };
    assert_eq!(
        (port(&b1, "eth1").role, port(&b1, "eth1").state),
        (StpRole::Alternate, StpState::Discarding)
    );
    assert_eq!(port(&a2, "eth1").state, StpState::Discarding);
    assert_eq!(port(&b1, "eth2").state, StpState::Forwarding);
    assert!(!port(&b1, "eth1").boundary);
    assert_eq!(
        (a1.vlans.as_str(), a1.domains.clone()),
        ("10", vec!["d1".to_string()])
    );

    // The kernel states: MSTI 1 owns d1, MSTI 2 owns d2.
    assert_eq!(n.state(1, "eth1", "d1"), Blocking);
    assert_eq!(n.state(1, "eth2", "d1"), Forwarding);
    assert_eq!(n.state(1, "eth1", "d2"), Forwarding);
    assert_eq!(n.state(1, "eth2", "d2"), Forwarding);
    assert_eq!(n.state(0, "eth1", "d2"), Blocking);
    assert_eq!(n.state(0, "eth2", "d2"), Forwarding);
    assert_eq!(n.state(0, "eth1", "d1"), Forwarding);

    // The CIST has one root and blocks one link too (B's eth2: the higher
    // designated port number).
    let s = n.e[1].summary();
    assert_eq!(s.root_port.as_deref(), Some("eth1"));
    assert_eq!(n.e[0].summary().root_port, None);
    assert_eq!(s.mode, nos_proto::StpMode::Mstp);
}

#[test]
fn a_different_revision_makes_every_port_a_boundary_port() {
    let mut n = Net::new(
        &plan(4096, mst_plan(1, 4096, 32768), [expensive(2), vec![]]),
        &plan(32768, mst_plan(2, 32768, 4096), [expensive(1), vec![]]),
    );
    n.run(60);
    for side in 0..2 {
        for id in [1, 2] {
            assert!(
                n.tree(side, id).ports.iter().all(|p| p.boundary),
                "{side} {id}"
            );
        }
    }
    // One CIST: B blocks eth2 for every domain, nothing is blocked on eth1.
    for d in ["d1", "d2"] {
        assert_eq!(n.state(1, "eth2", d), Blocking, "{d}");
        assert_eq!(n.state(1, "eth1", d), Forwarding, "{d}");
        assert_eq!(n.state(0, "eth1", d), Forwarding, "{d}");
        assert_eq!(n.state(0, "eth2", d), Forwarding, "{d}");
    }
    assert!(matches!(
        n.e[0].summary().mst.unwrap().instances[1].ports[0].state,
        StpState::Forwarding
    ));
}

#[test]
fn restoring_the_revision_rejoins_the_region() {
    let mut n = Net::new(
        &plan(4096, mst_plan(1, 4096, 32768), [expensive(2), vec![]]),
        &plan(32768, mst_plan(2, 32768, 4096), [expensive(1), vec![]]),
    );
    n.run(20);
    // B is rebuilt with the same revision (what a plan change does).
    let (eb, ob) = Engine::new(
        &plan(32768, mst_plan(1, 32768, 4096), [expensive(1), vec![]]),
        [2, 0, 0, 0, 0, 2],
    )
    .unwrap();
    n.e[1] = eb;
    n.pump([Vec::new(), ob]);
    for i in 0..2 {
        let o = n.e[1].set_link(i, true, true, 2_000);
        n.pump([Vec::new(), o]);
    }
    n.run(60);
    assert!(n.tree(1, 1).ports.iter().all(|p| !p.boundary));
    assert_eq!(n.state(1, "eth1", "d1"), StpPortState::Blocking);
}

#[test]
fn name_and_digest_mismatches_are_told_apart() {
    let id = |name: &str, rev, digest| {
        let mut p = mst_plan(rev, 4096, 4096);
        p.name = name.into();
        p.digest = digest;
        p.config_id()
    };
    let base = id("lab", 1, [7; 16]);
    assert_eq!(mismatch(&base, &base), None);
    assert_eq!(mismatch(&base, &id("lab2", 1, [7; 16])), Some("name"));
    assert_eq!(mismatch(&base, &id("lab", 2, [7; 16])), Some("revision"));
    assert_eq!(mismatch(&base, &id("lab", 1, [8; 16])), Some("digest"));
}

#[test]
fn a_plain_rstp_peer_makes_the_port_a_boundary_port() {
    let (mut e, _) = Engine::new(
        &plan(32768, mst_plan(1, 32768, 32768), [vec![], vec![]]),
        [2, 0, 0, 0, 0, 1],
    )
    .unwrap();
    e.set_link(0, true, true, 2_000);
    e.receive(0, crate::machines::tests::rst(&e_bridge_stub(), 0, false));
    let s = e.summary().mst.unwrap();
    assert!(s.instances[1].ports[0].boundary);
    assert!(!s.instances[1].ports[1].boundary, "eth2 heard nothing");
}

fn e_bridge_stub() -> Bridge {
    crate::machines::tests::bridge(1)
}

#[test]
fn remaining_hops_become_message_age() {
    let m = |hops| MstBpdu {
        params: Params {
            flags: Flags::default(),
            root: BridgeId::new(4096, 0, [1; 6]).unwrap(),
            root_path_cost: 0,
            bridge: BridgeId::new(4096, 0, [1; 6]).unwrap(),
            port: PortId::new(128, 3).unwrap(),
            message_age: 0,
            max_age: raw_secs(20),
            hello_time: raw_secs(2),
            forward_delay: raw_secs(15),
        },
        config: mst_plan(1, 0, 0).config_id(),
        internal_cost: 0,
        bridge: BridgeId::new(4096, 0, [1; 6]).unwrap(),
        remaining_hops: 20,
        mstis: vec![MstiMsg {
            flags: Flags::default(),
            regional_root: BridgeId::new(4096, 1, [9; 6]).unwrap(),
            internal_cost: 40,
            bridge_priority: 0x80,
            port_priority: 0x90,
            remaining_hops: hops,
        }],
    };
    let age = |hops| {
        let b = m(hops);
        let p = msti_params(&b, &b.mstis[0], 20).unwrap();
        (secs(p.message_age), secs(p.max_age))
    };
    assert_eq!(age(20), (0, 20), "the MSTI root's own message");
    assert_eq!(age(19), (1, 20));
    assert_eq!(age(0), (20, 20), "aged: the core drops it");
    let b = m(7);
    let p = msti_params(&b, &b.mstis[0], 20).unwrap();
    // Designated bridge: the message's priority and MSTID with the CIST MAC.
    assert_eq!(p.bridge, BridgeId::new(32768, 1, [1; 6]).unwrap());
    assert_eq!((p.port.priority(), p.port.number()), (0x90, 3));
    assert_eq!(p.root_path_cost, 40);
}

// In-place edits (#1123).

impl Net {
    fn apply(&mut self, side: usize, p: &Plan) {
        let o = self.e[side].apply_plan(p).expect("applied in place");
        let mut outs = [Vec::new(), Vec::new()];
        outs[side] = o;
        self.pump(outs);
    }

    /// `(port, state)` of the CIST, to prove it was left alone.
    fn cist(&self, side: usize) -> Vec<(String, StpState)> {
        self.e[side]
            .summary()
            .ports
            .iter()
            .map(|p| (p.name.clone(), p.state))
            .collect()
    }

    fn numbers(&self, side: usize, id: u16) -> Vec<String> {
        self.tree(side, id)
            .ports
            .iter()
            .map(|p| p.designated_port.clone())
            .collect()
    }
}

fn b_plan(mst: MstPlan, costs: [Vec<PortMst>; 2]) -> Plan {
    plan(32768, mst, costs)
}

#[test]
fn an_instance_priority_and_a_port_cost_change_in_place() {
    let mut n = two_trees();
    n.run(60);
    let (cist, nums, tree1) = (n.cist(1), n.numbers(1, 1), n.tree(1, 1));
    assert_eq!(tree1.ports[0].cost, 100_000);
    // MSTI 2 loses B's root claim; MSTI 1's eth1 cost on B drops to default.
    n.apply(1, &b_plan(mst_plan(1, 32768, 61440), [vec![], vec![]]));
    n.run(30);
    assert_eq!(n.cist(1), cist, "the CIST is untouched");
    assert_eq!(n.numbers(1, 1), nums, "port numbers are stable");
    assert!(n.tree(1, 2).bridge_id.starts_with("f000"));
    assert_ne!(n.tree(1, 2).root_id, n.tree(1, 2).bridge_id);
    assert_eq!(n.tree(1, 1).ports[0].cost, 2_000);
}

#[test]
fn an_instance_is_added_and_removed_in_place() {
    let mut n = two_trees();
    n.run(60);
    let cist = n.cist(1);
    let mut m = mst_plan(1, 32768, 4096);
    m.instances.push((3, 8192));
    n.apply(1, &b_plan(m, [expensive(1), vec![]]));
    n.run(60);
    let t3 = n.tree(1, 3);
    assert_eq!(t3.root_id, t3.bridge_id, "alone in its own instance");
    assert!(t3.ports.iter().all(|p| p.state == StpState::Forwarding));
    assert_eq!(n.cist(1), cist);
    // Removed again: the instance is gone, the others stay as they were.
    n.apply(1, &b_plan(mst_plan(1, 32768, 4096), [expensive(1), vec![]]));
    assert_eq!(n.e[1].summary().mst.unwrap().instances.len(), 3);
    assert_eq!(n.state(1, "eth1", "d1"), Blocking);
    assert_eq!(n.state(1, "eth2", "d1"), Forwarding);
    assert_eq!(n.cist(1), cist);
}

#[test]
fn a_revision_change_in_place_resets_the_edges_and_leaves_the_cist() {
    let mut n = two_trees();
    n.run(60);
    let cist = n.cist(1);
    n.apply(1, &b_plan(mst_plan(2, 32768, 4096), [expensive(1), vec![]]));
    assert!(n.tree(1, 1).ports.iter().all(|p| !p.boundary), "Unknown");
    assert_eq!(n.cist(1), cist);
    n.run(60);
    assert!(n.tree(1, 1).ports.iter().all(|p| p.boundary));
    // And back: the region re-forms without a restart.
    n.apply(1, &b_plan(mst_plan(1, 32768, 4096), [expensive(1), vec![]]));
    n.run(60);
    assert!(n.tree(1, 1).ports.iter().all(|p| !p.boundary));
    assert_eq!(n.state(1, "eth1", "d1"), Blocking);
}

#[test]
fn a_domain_moving_between_instances_is_pushed_again() {
    let mut n = two_trees();
    n.run(60);
    assert_eq!(n.state(1, "eth1", "d2"), Forwarding);
    // d2 joins MSTI 1 on both bridges (a new digest, the same region).
    let remap = |prio1, prio2| {
        let domains = vec![("d1".into(), 10, 1), ("d2".into(), 20, 1)];
        MstPlan {
            digest: digest::digest(&vidmap::table(&domains)),
            domains,
            ..mst_plan(1, prio1, prio2)
        }
    };
    n.apply(0, &plan(4096, remap(4096, 32768), [expensive(2), vec![]]));
    n.apply(1, &b_plan(remap(32768, 4096), [expensive(1), vec![]]));
    n.run(60);
    assert_eq!(n.state(1, "eth1", "d2"), Blocking, "d2 follows MSTI 1");
    assert_eq!(n.state(1, "eth2", "d2"), Forwarding);
}

#[test]
fn a_port_added_and_removed_reaches_every_instance() {
    let mut n = two_trees();
    n.run(60);
    let mut p = b_plan(mst_plan(1, 32768, 4096), [expensive(1), vec![]]);
    p.ports.push(port("eth3", vec![]));
    n.apply(1, &p);
    for id in [1, 2] {
        assert_eq!(n.tree(1, id).ports.len(), 3, "msti {id}");
    }
    assert_eq!(n.tree(1, 1).ports[2].name, "eth3");
    p.ports.pop();
    n.apply(1, &p);
    assert_eq!(n.tree(1, 1).ports.len(), 2);
    assert_eq!(n.state(1, "eth2", "d1"), Forwarding);
}

#[test]
fn switching_mstp_on_or_off_still_asks_for_a_rebuild() {
    let mut n = two_trees();
    let mut off = b_plan(mst_plan(1, 32768, 4096), [vec![], vec![]]);
    off.mst = None;
    assert_eq!(n.e[1].apply_plan(&off), Err(crate::engine::Rebuild));
}
