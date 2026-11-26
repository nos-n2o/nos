use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use nos_proto::schema::{Acl, AclAction, AclRule};
use nos_proto::LinkState;

use super::*;
use crate::compile::compile;
use crate::driver::{Call, NoopDriver, ACL_CHAIN_A as A, ACL_CHAIN_B as B};
use crate::plan::Attachment;

use Direction::{In, Out};

fn link(name: &str, ifindex: u32, aggregate: Option<&str>) -> LinkState {
    LinkState {
        name: name.into(),
        ifindex,
        admin_up: true,
        carrier: true,
        port_aggregate: aggregate.map(Into::into),
    }
}

fn links(l: &[LinkState]) -> LinkTable {
    LinkTable {
        known: true,
        links: l.iter().map(|l| (l.name.clone(), l.clone())).collect(),
    }
}

fn compiled(rules: usize) -> Arc<Compiled> {
    let acl = Acl {
        name: "E".into(),
        default_action: AclAction::Permit,
        rules: vec![AclRule::default(); rules],
    };
    Arc::new(compile(&acl).unwrap())
}

fn plan(acl: &Arc<Compiled>, at: &[(Device, Direction)]) -> Plan {
    Plan {
        acls: BTreeMap::from([("E".to_string(), acl.clone())]),
        attachments: at
            .iter()
            .map(|(device, dir)| Attachment {
                device: device.clone(),
                dir: *dir,
                acl: "E".into(),
            })
            .collect(),
        flowspec: BTreeMap::new(),
    }
}

fn eth(n: &str) -> Device {
    Device::Kernel(n.into())
}

/// No driver call.
const NONE: Vec<Call> = Vec::new();

/// The calls since the last `take`.
fn take(e: &mut Engine<NoopDriver>) -> Vec<Call> {
    std::mem::take(&mut e.driver_mut().calls)
}

#[test]
fn nothing_happens_before_the_link_table_is_known() {
    let mut e = Engine::new(NoopDriver::default());
    e.sync(
        &plan(&compiled(1), &[(eth("eth0"), In)]),
        &LinkTable::default(),
    );
    assert_eq!(e.driver().calls, NONE);
}

#[test]
fn attach_update_alternates_chains_then_detach() {
    let mut e = Engine::new(NoopDriver::default());
    let l = links(&[link("eth0", 4, None)]);
    let one = compiled(1);
    e.sync(&plan(&one, &[(eth("eth0"), In)]), &l);
    assert_eq!(
        take(&mut e),
        [Call::Install(4, In, A), Call::Switch(4, In, A)]
    );

    // Same ACL (another Arc, equal value): nothing to do.
    e.sync(&plan(&compiled(1), &[(eth("eth0"), In)]), &l);
    assert_eq!(take(&mut e), NONE);

    e.sync(&plan(&compiled(2), &[(eth("eth0"), In)]), &l);
    assert_eq!(
        take(&mut e),
        [
            Call::Install(4, In, B),
            Call::Switch(4, In, B),
            Call::Flush(4, In, A)
        ]
    );
    e.sync(&plan(&one, &[(eth("eth0"), In)]), &l);
    assert_eq!(
        take(&mut e),
        [
            Call::Install(4, In, A),
            Call::Switch(4, In, A),
            Call::Flush(4, In, B)
        ]
    );

    e.sync(&plan(&one, &[]), &l);
    assert_eq!(take(&mut e), [Call::Detach(4, In)]);
    assert!(e.live().is_empty());
}

#[test]
fn a_log_sample_names_the_installed_device_acl_and_rule() {
    let mut e = Engine::new(NoopDriver::default());
    let l = links(&[link("eth0", 4, None)]);
    let acl = Acl {
        name: "E".into(),
        default_action: AclAction::Permit,
        rules: vec![AclRule {
            name: "l".into(),
            action: AclAction::Deny,
            log: true,
            ..Default::default()
        }],
    };
    let logged = Arc::new(compile(&acl).unwrap());
    e.sync(&plan(&compiled(1), &[(eth("eth0"), In)]), &l);
    assert!(!e.logs());
    e.sync(&plan(&logged, &[(eth("eth0"), In)]), &l);
    assert!(e.logs());
    let names = |n: &str| Some(("eth0".to_string(), "E".to_string(), n.to_string()));
    assert_eq!(e.log_target(4, In, 0), names("l"));
    assert_eq!(e.log_target(4, In, 1), None, "past the rules");
    assert_eq!(e.log_target(4, Out, 0), None, "other direction");
    assert_eq!(e.log_target(5, In, 0), None, "other device");
}

#[test]
fn an_absent_device_waits_for_its_link() {
    let mut e = Engine::new(NoopDriver::default());
    let p = plan(&compiled(1), &[(eth("eth1"), Out)]);
    e.sync(&p, &links(&[link("eth0", 4, None)]));
    e.sync(&p, &links(&[link("eth0", 4, None)]));
    assert_eq!(take(&mut e), NONE);
    assert!(e.pending.contains(&("eth1".to_string(), Out)));
    e.sync(&p, &links(&[link("eth1", 5, None)]));
    assert_eq!(
        take(&mut e),
        [Call::Install(5, Out, A), Call::Switch(5, Out, A)]
    );
    assert!(e.pending.is_empty());

    // Gone: the kernel took the filters with it, so no call; back with a
    // new ifindex: a fresh install.
    e.sync(&p, &links(&[]));
    assert_eq!(take(&mut e), NONE);
    assert!(e.live().is_empty());
    e.sync(&p, &links(&[link("eth1", 9, None)]));
    assert_eq!(
        take(&mut e),
        [Call::Install(9, Out, A), Call::Switch(9, Out, A)]
    );
}

#[test]
fn an_aggregate_resolves_through_its_bond() {
    let mut e = Engine::new(NoopDriver::default());
    let agg = |tag| Device::Aggregate {
        name: "agg".into(),
        tag,
    };
    let p = plan(&compiled(1), &[(agg(0), In), (agg(7), Out)]);
    e.sync(&p, &links(&[link("bond1.7", 6, None)]));
    assert_eq!(take(&mut e), NONE);
    assert!(e.pending.contains(&("agg".to_string(), In)));
    assert!(e.pending.contains(&("agg.7".to_string(), Out)));
    e.sync(
        &p,
        &links(&[link("bond1", 5, Some("agg")), link("bond1.7", 6, None)]),
    );
    assert_eq!(
        take(&mut e),
        [
            Call::Install(5, In, A),
            Call::Switch(5, In, A),
            Call::Install(6, Out, A),
            Call::Switch(6, Out, A),
        ]
    );
}

#[test]
fn a_previous_run_is_adopted_replaced_or_removed() {
    let mut driver = NoopDriver::default();
    driver.live.insert((4, In), B);
    driver.live.insert((5, Out), A);
    let mut e = Engine::new(driver);
    let l = links(&[link("eth0", 4, None), link("eth1", 5, None)]);
    e.sync(&plan(&compiled(1), &[(eth("eth0"), In)]), &l);
    assert_eq!(
        take(&mut e),
        [
            Call::Detach(5, Out),
            Call::Install(4, In, A),
            Call::Switch(4, In, A),
            Call::Flush(4, In, B),
        ]
    );
    // The sweep runs once.
    e.sync(&plan(&compiled(1), &[(eth("eth0"), In)]), &l);
    assert_eq!(take(&mut e), NONE);
}

#[test]
fn a_half_failed_switch_points_back_at_the_old_chain() {
    let mut e = Engine::new(NoopDriver::default());
    let l = links(&[link("eth0", 4, None)]);
    e.sync(&plan(&compiled(1), &[(eth("eth0"), In)]), &l);
    take(&mut e);
    e.driver_mut().fail_switch = Some(true);
    let two = plan(&compiled(2), &[(eth("eth0"), In)]);
    e.sync(&two, &l);
    assert_eq!(
        take(&mut e),
        [
            Call::Install(4, In, B),
            Call::Switch(4, In, B),
            Call::Switch(4, In, A),
            Call::Flush(4, In, B)
        ]
    );
    assert_eq!(e.driver_mut().live[&(4, In)], A);
    assert_eq!(e.live()[&("eth0".to_string(), In)], A);
    // Retried on the next pass.
    e.sync(&two, &l);
    assert_eq!(e.driver_mut().live[&(4, In)], B);
}

#[test]
fn a_failed_first_switch_detaches() {
    let mut e = Engine::new(NoopDriver::default());
    let l = links(&[link("eth0", 4, None)]);
    e.driver_mut().fail_switch = Some(true);
    e.sync(&plan(&compiled(1), &[(eth("eth0"), In)]), &l);
    assert_eq!(
        take(&mut e),
        [
            Call::Install(4, In, A),
            Call::Switch(4, In, A),
            Call::Detach(4, In)
        ]
    );
    assert!(e.live().is_empty());
    assert!(e.driver_mut().live.is_empty());
}

#[test]
fn a_refused_install_keeps_the_live_chain() {
    let mut e = Engine::new(NoopDriver::default());
    let l = links(&[link("eth0", 4, None)]);
    e.sync(&plan(&compiled(1), &[(eth("eth0"), In)]), &l);
    take(&mut e);
    e.driver_mut().fail_install = true;
    let two = plan(&compiled(2), &[(eth("eth0"), In)]);
    e.sync(&two, &l);
    assert_eq!(
        take(&mut e),
        [Call::Install(4, In, B), Call::Flush(4, In, B)]
    );
    assert_eq!(e.live()[&("eth0".to_string(), In)], A);
    // Retried on the next pass.
    e.sync(&two, &l);
    assert_eq!(
        take(&mut e),
        [
            Call::Install(4, In, B),
            Call::Switch(4, In, B),
            Call::Flush(4, In, A)
        ]
    );
}

#[test]
fn an_acl_without_a_compile_leaves_the_device_alone() {
    let mut e = Engine::new(NoopDriver::default());
    let l = links(&[link("eth0", 4, None)]);
    e.sync(&plan(&compiled(1), &[(eth("eth0"), In)]), &l);
    take(&mut e);
    let mut p = plan(&compiled(2), &[(eth("eth0"), In)]);
    p.acls.clear();
    e.sync(&p, &l);
    assert_eq!(take(&mut e), NONE);
    assert_eq!(e.live().len(), 1);
}

#[tokio::test]
async fn run_applies_changes_and_leaves_filters_on_shutdown() {
    let (plan_tx, plan_rx) = watch::channel(None);
    let (links_tx, links_rx) = watch::channel(LinkTable::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let engine = Arc::new(Mutex::new(Engine::new(NoopDriver::default())));
    let task = tokio::spawn(run(engine.clone(), plan_rx, links_rx, stop_rx, false));
    plan_tx
        .send(Some(plan(&compiled(1), &[(eth("eth0"), In)])))
        .unwrap();
    links_tx.send(links(&[link("eth0", 4, None)])).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    stop_tx.send(true).unwrap();
    task.await.unwrap().unwrap();
    let e = engine.lock().unwrap();
    let calls = &e.driver().calls;
    assert!(calls.contains(&Call::Switch(4, In, A)), "{calls:?}");
    assert!(
        !calls.iter().any(|c| matches!(c, Call::Detach(..))),
        "{calls:?}"
    );
    assert_eq!(e.live().len(), 1);
}

#[tokio::test]
async fn run_fails_when_its_inputs_close() {
    let (plan_tx, plan_rx) = watch::channel(None);
    let (links_tx, links_rx) = watch::channel(LinkTable::default());
    let (_stop_tx, stop_rx) = watch::channel(false);
    let engine = Arc::new(Mutex::new(Engine::new(NoopDriver::default())));
    let task = tokio::spawn(run(
        engine.clone(),
        plan_rx,
        links_rx.clone(),
        stop_rx,
        false,
    ));
    drop(plan_tx);
    assert!(task.await.unwrap().is_err());
    assert_eq!(engine.lock().unwrap().driver().calls, NONE);
    let (_p, plan_rx) = watch::channel(None);
    let (_s, stop_rx) = watch::channel(false);
    let task = tokio::spawn(run(engine, plan_rx, links_rx, stop_rx, false));
    drop(links_tx);
    assert!(task.await.unwrap().is_err());
}

fn counts(e: &mut Engine<NoopDriver>, ifindex: u32, dir: Direction, c: &[(u32, u64)]) {
    let v = c
        .iter()
        .map(|&(cookie, packets)| crate::driver::Counter {
            cookie,
            packets,
            bytes: packets * 10,
        })
        .collect();
    e.driver_mut().counts.insert((ifindex, dir), v);
}

#[test]
fn show_sums_the_live_chains_and_lists_unattached_acls() {
    let mut e = Engine::new(NoopDriver::default());
    let l = links(&[link("eth0", 4, None), link("eth1", 5, None)]);
    let acl = compiled(1);
    let mut p = plan(&acl, &[(eth("eth0"), In), (eth("eth1"), Out)]);
    p.acls.insert("U".into(), acl.clone());
    e.sync(&p, &l);
    counts(
        &mut e,
        4,
        In,
        &[(0, 3), (crate::compile::DEFAULT_COOKIE, 1)],
    );
    counts(&mut e, 5, Out, &[(0, 4)]);

    let all = e.show(None);
    assert_eq!(
        all.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["E", "U"]
    );
    assert_eq!(all[0].rules[0].packets, 7);
    assert_eq!(all[0].default_packets, 1);
    assert_eq!(
        all[0].attached,
        [
            AclAttachment {
                interface: "eth0".into(),
                direction: AclDirection::In
            },
            AclAttachment {
                interface: "eth1".into(),
                direction: AclDirection::Out
            },
        ]
    );
    assert_eq!(all[1].attached.len(), 0);
    assert_eq!(all[1].rules[0].packets, 0);

    assert_eq!(e.show(Some("U")).len(), 1);
    assert_eq!(e.show(Some("nope")).len(), 0);

    // A device whose dump fails is skipped.
    e.driver_mut().fail_counters = true;
    let s = &e.show(Some("E"))[0];
    assert_eq!((s.attached.len(), s.rules[0].packets), (0, 0));
}

#[test]
fn a_chain_adopted_from_a_previous_run_is_not_attributed() {
    let mut driver = NoopDriver::default();
    driver.live.insert((4, In), A);
    let mut e = Engine::new(driver);
    // No ACL attaches it: it is swept and detached, never shown.
    e.sync(&plan(&compiled(1), &[]), &links(&[link("eth0", 4, None)]));
    assert_eq!(e.show(None)[0].attached.len(), 0);
}

#[test]
fn clear_reinstalls_on_the_idle_chain_and_switches() {
    let mut e = Engine::new(NoopDriver::default());
    let l = links(&[link("eth0", 4, None), link("eth1", 5, None)]);
    e.sync(
        &plan(&compiled(1), &[(eth("eth0"), In), (eth("eth1"), Out)]),
        &l,
    );
    take(&mut e);
    assert_eq!(e.clear_counters(Some("NOPE")), (false, 0));
    assert_eq!(take(&mut e), NONE);

    assert_eq!(e.clear_counters(Some("E")), (true, 2));
    assert_eq!(
        take(&mut e),
        [
            Call::Install(4, In, B),
            Call::Switch(4, In, B),
            Call::Flush(4, In, A),
            Call::Install(5, Out, B),
            Call::Switch(5, Out, B),
            Call::Flush(5, Out, A),
        ]
    );
    // No name: every ACL again, back on chain A.
    assert_eq!(e.clear_counters(None), (true, 2));
    assert_eq!(e.live()[&("eth0".to_string(), In)], A);
}

#[test]
fn clearing_an_unattached_acl_is_found_with_no_attachments() {
    let mut e = Engine::new(NoopDriver::default());
    e.sync(&plan(&compiled(1), &[]), &links(&[]));
    take(&mut e);
    assert_eq!(e.clear_counters(Some("E")), (true, 0));
    assert_eq!(take(&mut e), NONE);
}

#[test]
fn a_refused_clear_keeps_the_live_chain_and_is_not_counted() {
    let mut e = Engine::new(NoopDriver::default());
    let l = links(&[link("eth0", 4, None)]);
    e.sync(&plan(&compiled(1), &[(eth("eth0"), In)]), &l);
    e.driver_mut().fail_install = true;
    assert_eq!(e.clear_counters(None), (true, 0));
    assert_eq!(e.live()[&("eth0".to_string(), In)], A);
}
