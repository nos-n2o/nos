use std::collections::BTreeMap;

use nos_proto::{FlowComponent, FlowNumOp, FlowRule, FlowRuleAction, FlowspecSet, LinkState};

use crate::driver::{Call, NoopDriver};
use crate::engine::Engine;
use crate::link_client::LinkTable;
use crate::plan::Plan;

fn links(l: &[(&str, u32)]) -> LinkTable {
    LinkTable {
        known: true,
        links: l
            .iter()
            .map(|(name, ifindex)| {
                let s = LinkState {
                    name: (*name).into(),
                    ifindex: *ifindex,
                    admin_up: true,
                    carrier: true,
                    port_aggregate: None,
                };
                ((*name).to_string(), s)
            })
            .collect(),
    }
}

/// A drop rule on protocol `proto`, named by it.
fn rule(proto: u64) -> FlowRule {
    FlowRule {
        flow: format!("proto ={proto}"),
        ipv6: false,
        components: vec![FlowComponent::Protocol(vec![FlowNumOp {
            and: false,
            lt: false,
            gt: false,
            eq: true,
            value: proto,
        }])],
        actions: vec![FlowRuleAction::RateBytes(0.0)],
    }
}

fn unsupported() -> FlowRule {
    FlowRule {
        flow: "len =64".into(),
        ipv6: false,
        components: vec![FlowComponent::PacketLen(vec![])],
        actions: vec![],
    }
}

fn set(instance: &str, devices: &[&str], rules: Vec<FlowRule>) -> FlowspecSet {
    FlowspecSet {
        instance: instance.into(),
        table: None,
        devices: devices.iter().map(|d| (*d).to_string()).collect(),
        rules,
    }
}

fn take(e: &mut Engine<NoopDriver>) -> Vec<Call> {
    std::mem::take(&mut e.driver_mut().calls)
}

fn put(ifindex: u32, prio: u16, cookie: u32) -> Call {
    Call::Flowspec(ifindex, prio, Some(cookie))
}

fn clear(ifindex: u32, prio: u16) -> Call {
    Call::Flowspec(ifindex, prio, None)
}

/// An engine past its first pass on `eth0` (4) and `eth1` (5).
fn ready() -> Engine<NoopDriver> {
    let mut e = Engine::new(NoopDriver::default());
    e.sync(&Plan::default(), &links(&[("eth0", 4), ("eth1", 5)]));
    take(&mut e);
    e
}

#[test]
fn rules_wait_for_the_link_table_then_go_in_order() {
    let mut e = Engine::new(NoopDriver::default());
    e.push_flowspec(set("b1", &["eth0"], vec![rule(6), unsupported(), rule(17)]));
    assert_eq!(take(&mut e), []);
    e.sync(&Plan::default(), &links(&[("eth0", 4)]));
    // The unsupported rule takes no priority; cookies are rule indices.
    assert_eq!(take(&mut e), [put(4, 10, 0), put(4, 11, 2)]);
    let shown = e.show_flowspec();
    let got: Vec<_> = shown
        .iter()
        .map(|s| {
            (
                s.instance.as_str(),
                s.flow.as_str(),
                s.unsupported.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("b1", "proto =6", None),
            ("b1", "len =64", Some("packet length: no flower key")),
            ("b1", "proto =17", None),
        ]
    );
    assert_eq!(shown[0].actions, ["rate 0 bytes/s"]);
    // A second pass changes nothing.
    e.sync(&Plan::default(), &links(&[("eth0", 4)]));
    assert_eq!(take(&mut e), []);
}

#[test]
fn a_snapshot_rewrites_only_what_changed_and_empty_clears() {
    let mut e = ready();
    e.push_flowspec(set("b1", &["eth0"], vec![rule(6), rule(17), rule(1)]));
    take(&mut e);
    e.push_flowspec(set("b1", &["eth0"], vec![rule(6), rule(47)]));
    assert_eq!(take(&mut e), [put(4, 11, 1), clear(4, 12)]);
    // Moving to eth1 clears eth0.
    e.push_flowspec(set("b1", &["eth1"], vec![rule(6), rule(47)]));
    assert_eq!(
        take(&mut e),
        [clear(4, 10), clear(4, 11), put(5, 10, 0), put(5, 11, 1)]
    );
    e.push_flowspec(set("b1", &[], vec![]));
    assert_eq!(take(&mut e), [clear(5, 10), clear(5, 11)]);
    assert_eq!(e.show_flowspec(), []);
    assert_eq!(
        e.driver().flowspec,
        BTreeMap::from([(4, BTreeMap::new()), (5, BTreeMap::new())])
    );
}

#[test]
fn instances_stack_in_name_order_up_to_the_cap() {
    let mut e = ready();
    e.push_flowspec(set("b2", &["eth0"], vec![rule(6)]));
    e.push_flowspec(set("b1", &["eth0"], vec![rule(17)]));
    // b1 now comes first: both priorities change hands.
    assert_eq!(take(&mut e), [put(4, 10, 0), put(4, 10, 0), put(4, 11, 0)]);
    let many: Vec<FlowRule> = (0..90).map(rule).collect();
    e.push_flowspec(set("b2", &["eth0"], many));
    let shown = e.show_flowspec();
    assert_eq!(shown.len(), 91);
    let capped: Vec<_> = shown
        .iter()
        .filter(|s| s.unsupported.is_some())
        .map(|s| {
            (
                s.instance.as_str(),
                s.flow.as_str(),
                s.unsupported.as_deref(),
            )
        })
        .collect();
    assert_eq!(capped, [("b2", "proto =89", Some("rule cap"))]);
    assert_eq!(e.driver().flowspec[&4].len(), 90);
}

#[test]
fn a_previous_run_is_swept_and_a_refusal_retried() {
    let mut d = NoopDriver::default();
    d.flowspec.insert(4, BTreeMap::from([(10, 7), (12, 7)]));
    let mut e = Engine::new(d);
    e.push_flowspec(set("b1", &["eth0"], vec![rule(6)]));
    e.driver_mut().fail_flowspec = true;
    e.sync(&Plan::default(), &links(&[("eth0", 4)]));
    // Prio 10 refused (left unknown), 12 cleared.
    assert_eq!(take(&mut e), [put(4, 10, 0), clear(4, 12)]);
    e.sync(&Plan::default(), &links(&[("eth0", 4)]));
    assert_eq!(take(&mut e), [put(4, 10, 0)]);
    e.sync(&Plan::default(), &links(&[("eth0", 4)]));
    assert_eq!(take(&mut e), []);
}

#[test]
fn absent_and_vanished_devices_cost_no_calls() {
    let mut e = ready();
    e.push_flowspec(set("b1", &["eth9", "eth0"], vec![rule(6)]));
    assert_eq!(take(&mut e), [put(4, 10, 0)]);
    // eth0 is gone (ifindex changed): its state is dropped, then eth0 is new.
    e.sync(&Plan::default(), &links(&[("eth0", 8)]));
    assert_eq!(take(&mut e), [put(8, 10, 0)]);
    // The device left: forgotten, no call.
    e.sync(&Plan::default(), &links(&[]));
    assert_eq!(take(&mut e), []);
}

#[test]
fn show_sums_counters() {
    let mut e = ready();
    e.push_flowspec(set("b1", &["eth0", "eth1"], vec![rule(6), rule(17)]));
    take(&mut e);
    e.driver_mut().flowspec_counts = BTreeMap::from([
        (
            4,
            BTreeMap::from([(10, (3, 300)), (11, (1, 10)), (50, (9, 9))]),
        ),
        (5, BTreeMap::from([(10, (2, 200))])),
    ]);
    let shown = e.show_flowspec();
    assert_eq!(
        shown
            .iter()
            .map(|s| (s.packets, s.bytes))
            .collect::<Vec<_>>(),
        [(5, 500), (1, 10)]
    );
    e.driver_mut().fail_counters = true;
    assert_eq!(e.show_flowspec()[0].packets, 0);
}

/// #562: a pushed instance with no devices of its own reaches the
/// `flowspec` devices the plan gives it (an aggregate through its bond); a
/// rule no device holds shows `not attached`.
#[test]
fn the_plan_attaches_an_instance_to_its_flowspec_devices() {
    use crate::plan::Device;
    let mut table = links(&[("eth0", 4), ("bond7", 6)]);
    table.links.get_mut("bond7").unwrap().port_aggregate = Some("agg".into());
    let mut e = Engine::new(NoopDriver::default());
    e.sync(&Plan::default(), &table);
    e.push_flowspec(set("b1", &[], vec![rule(6)]));
    assert_eq!(take(&mut e), []);
    assert_eq!(
        e.show_flowspec()[0].unsupported.as_deref(),
        Some("not attached")
    );
    let mut plan = Plan::default();
    plan.flowspec.insert(
        ("b1".into(), None),
        vec![
            Device::Kernel("eth0".into()),
            Device::Aggregate {
                name: "agg".into(),
                tag: 0,
            },
            Device::Aggregate {
                name: "gone".into(),
                tag: 3,
            },
        ],
    );
    plan.flowspec
        .insert(("b2".into(), None), vec![Device::Kernel("eth0".into())]);
    e.sync(&plan, &table);
    assert_eq!(take(&mut e), [put(6, 10, 0), put(4, 10, 0)]);
    assert_eq!(e.show_flowspec()[0].unsupported, None);
    // The flag goes: the rules come off.
    e.sync(&Plan::default(), &table);
    assert_eq!(take(&mut e), [clear(6, 10), clear(4, 10)]);
}

/// #1083: the instance's own table and a VRF of it side by side; each set
/// has its own devices, shares a device's band, and clears alone.
#[test]
fn an_instances_table_and_vrf_sets_are_independent() {
    let mut e = ready();
    let vrf = |devices: &[&str], rules| FlowspecSet {
        table: Some("rt2".into()),
        ..set("b1", devices, rules)
    };
    e.push_flowspec(set("b1", &["eth0"], vec![rule(6)]));
    e.push_flowspec(vrf(&["eth1"], vec![rule(17)]));
    take(&mut e);
    // Same device: the band is shared, `None` first.
    e.push_flowspec(vrf(&["eth0"], vec![rule(17)]));
    let c = take(&mut e);
    assert!(c.contains(&put(4, 11, 0)), "{c:?}");
    assert!(c.contains(&clear(5, 10)), "{c:?}");
    let rows = e.show_flowspec();
    let got: Vec<_> = rows
        .iter()
        .map(|r| (r.table.as_deref(), &*r.flow))
        .collect();
    assert_eq!(got, [(None, "proto =6"), (Some("rt2"), "proto =17")]);
    // Clearing the VRF set leaves the table's rule alone.
    e.push_flowspec(vrf(&[], vec![]));
    assert_eq!(take(&mut e), [clear(4, 11)]);
    assert_eq!(e.show_flowspec().len(), 1);
}
