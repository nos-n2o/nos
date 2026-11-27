//! `LinuxDriver` against the real kernel, `tc` as the oracle: needs
//! `CAP_NET_ADMIN`, so run it in a throwaway netns:
//! `unshare -Urn cargo test -p nos-acl --test kernel -- --ignored`.
#![allow(
    clippy::disallowed_types,
    reason = "test code: `ip`/`tc` are the independent oracle for the driver (#228)"
)]

use std::process::Command;

use nos_acl::compile::compile;
use nos_acl::driver::{Direction, Driver, LinuxDriver, ACL_CHAIN_A, ACL_CHAIN_B};
use nos_acl::flowspec;
use nos_proto::schema::{Acl, AclAction, AclProtocol, AclRule, PortRange};
use nos_proto::{FlowComponent, FlowNumOp, FlowRule, FlowRuleAction};

fn run(args: &[&str]) -> String {
    let o = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn idx(name: &str) -> u32 {
    run(&["ip", "-o", "link", "show", name])
        .split(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

fn show(dev: &str, hook: &str, chain: u32) -> String {
    run(&[
        "tc",
        "filter",
        "show",
        "dev",
        dev,
        hook,
        "chain",
        &chain.to_string(),
    ])
}

fn acl(rules: Vec<AclRule>) -> Acl {
    Acl {
        name: "E".into(),
        default_action: AclAction::Permit,
        rules,
    }
}

#[test]
#[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
fn attach_replace_detach_leave_foreign_filters() {
    run(&["ip", "link", "add", "acl0", "type", "dummy"]);
    run(&["ip", "link", "set", "acl0", "up"]);
    let i = idx("acl0");
    // A foreign owner's clsact and prio-1 filter (as nos-interfaced's BPDU trap).
    run(&["tc", "qdisc", "add", "dev", "acl0", "clsact"]);
    run(&[
        "tc", "filter", "add", "dev", "acl0", "ingress", "prio", "1", "protocol", "arp", "flower",
        "action", "drop",
    ]);
    let mut d = LinuxDriver;
    assert_eq!(d.live_chain(i, Direction::In).unwrap(), None);

    let deny_bgp = AclRule {
        name: "d-bgp".into(),
        action: AclAction::Deny,
        protocol: Some(AclProtocol::Tcp),
        destination_port: Some(PortRange {
            start: 179,
            end: 179,
        }),
        ..Default::default()
    };
    let established = AclRule {
        name: "est".into(),
        action: AclAction::Permit,
        protocol: Some(AclProtocol::Tcp),
        source: Some("10.0.0.0/8".parse().unwrap()),
        source_port: Some(PortRange {
            start: 1000,
            end: 2000,
        }),
        established: true,
        ..Default::default()
    };
    let one = compile(&acl(vec![deny_bgp.clone()])).unwrap();
    d.install(i, Direction::In, ACL_CHAIN_A, &one).unwrap();
    d.switch(i, Direction::In, ACL_CHAIN_A, None).unwrap();
    let entry = show("acl0", "ingress", 0);
    assert!(
        entry.contains("pref 100") && entry.contains("goto chain 1000"),
        "{entry}"
    );
    let chain = show("acl0", "ingress", ACL_CHAIN_A);
    assert!(
        chain.contains("dst_port 179") && chain.contains("drop"),
        "{chain}"
    );
    assert_eq!(d.live_chain(i, Direction::In).unwrap(), Some(ACL_CHAIN_A));

    let frags = AclRule {
        name: "frags".into(),
        action: AclAction::Deny,
        fragments: true,
        ..Default::default()
    };
    let two = compile(&acl(vec![established, deny_bgp.clone(), frags])).unwrap();
    d.install(i, Direction::In, ACL_CHAIN_B, &two).unwrap();
    d.switch(i, Direction::In, ACL_CHAIN_B, Some(ACL_CHAIN_A))
        .unwrap();
    d.flush(i, Direction::In, ACL_CHAIN_A).unwrap();
    assert!(show("acl0", "ingress", 0).contains("goto chain 1001"));
    assert_eq!(show("acl0", "ingress", ACL_CHAIN_A), "");
    let chain = show("acl0", "ingress", ACL_CHAIN_B);
    assert!(
        chain.contains("tcp_flags 0x10/10") && chain.contains("tcp_flags 0x4/4"),
        "{chain}"
    );
    assert!(chain.contains("src_port 1000-2000"), "{chain}");
    assert!(chain.contains("ip_flags frag/nofirstfrag"), "{chain}");
    assert_eq!(d.live_chain(i, Direction::In).unwrap(), Some(ACL_CHAIN_B));
    // Flushing an empty chain again is fine.
    d.flush(i, Direction::In, ACL_CHAIN_A).unwrap();

    // Egress is independent. A `log` rule samples, then drops (#544); the
    // install checks the kernel passes the cookie to psample.
    let logged = compile(&acl(vec![AclRule {
        log: true,
        ..deny_bgp
    }]))
    .unwrap();
    d.install(i, Direction::Out, ACL_CHAIN_A, &logged).unwrap();
    d.switch(i, Direction::Out, ACL_CHAIN_A, None).unwrap();
    assert!(show("acl0", "egress", 0).contains("goto chain 1000"));
    let chain = show("acl0", "egress", ACL_CHAIN_A);
    assert!(
        chain.contains("sample rate 1/100 group 5132115 trunc_size 128") && chain.contains("drop"),
        "{chain}"
    );
    d.detach(i, Direction::Out).unwrap();
    assert_eq!(show("acl0", "egress", 0), "");

    d.detach(i, Direction::In).unwrap();
    let left = show("acl0", "ingress", 0);
    assert!(
        left.contains("pref 1 ") && !left.contains("pref 100"),
        "{left}"
    );
    assert_eq!(show("acl0", "ingress", ACL_CHAIN_B), "");
    assert_eq!(d.live_chain(i, Direction::In).unwrap(), None);
    // Detaching twice is fine; the qdisc stays.
    d.detach(i, Direction::In).unwrap();
    assert!(run(&["tc", "qdisc", "show", "dev", "acl0"]).contains("clsact"));
    run(&["ip", "link", "del", "acl0"]);
}

fn eq(value: u64) -> FlowNumOp {
    FlowNumOp {
        and: false,
        lt: false,
        gt: false,
        eq: true,
        value,
    }
}

fn flow(components: Vec<FlowComponent>, actions: Vec<FlowRuleAction>) -> FlowRule {
    FlowRule {
        flow: "f".into(),
        ipv6: false,
        components,
        actions,
    }
}

/// Flowspec rules (#561) sit at prios 10.. beside a foreign prio-1 filter
/// and the ACL's prio-100 entry, and a terminal rule's exit chain follows
/// the live ACL chain.
#[test]
#[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
fn flowspec_rules_sit_between_foreign_filters_and_the_acl() {
    run(&["ip", "link", "add", "fs0", "type", "dummy"]);
    run(&["ip", "link", "set", "fs0", "up"]);
    let i = idx("fs0");
    run(&["tc", "qdisc", "add", "dev", "fs0", "clsact"]);
    run(&[
        "tc", "filter", "add", "dev", "fs0", "ingress", "prio", "1", "protocol", "arp", "flower",
        "action", "drop",
    ]);
    let mut d = LinuxDriver;
    let acl_one = compile(&acl(vec![AclRule {
        name: "d".into(),
        action: AclAction::Deny,
        protocol: Some(AclProtocol::Udp),
        ..Default::default()
    }]))
    .unwrap();
    d.install(i, Direction::In, ACL_CHAIN_A, &acl_one).unwrap();
    d.switch(i, Direction::In, ACL_CHAIN_A, None).unwrap();
    let exit = show("fs0", "ingress", flowspec::EXIT_CHAIN);
    assert!(exit.contains("goto chain 1000"), "{exit}");

    let drop = flow(
        vec![
            FlowComponent::Source {
                prefix: "10.0.0.0/8".parse().unwrap(),
                offset: 0,
            },
            FlowComponent::DstPort(vec![eq(80)]),
        ],
        vec![FlowRuleAction::RateBytes(0.0)],
    );
    let police = flow(
        vec![FlowComponent::Protocol(vec![eq(17)])],
        vec![
            FlowRuleAction::RateBytes(125_000.0),
            FlowRuleAction::Dscp(10),
            FlowRuleAction::TrafficAction {
                sample: false,
                terminal: true,
            },
        ],
    );
    let stop = flow(
        vec![FlowComponent::Dscp(vec![eq(46)])],
        vec![FlowRuleAction::RatePackets(100.0)],
    );
    for (n, r) in [drop, police, stop].iter().enumerate() {
        let l = flowspec::lower(r).unwrap();
        let prio = flowspec::PRIO_FIRST + u16::try_from(n).unwrap();
        d.flowspec_set(i, prio, Some((u32::try_from(n).unwrap(), &l)))
            .unwrap();
    }
    let chain0 = show("fs0", "ingress", 0);
    for want in [
        "pref 1 ",
        "pref 10 ",
        "dst_port 80",
        "pref 11 ",
        "police",
        "pedit",
        "csum",
        "pref 12 ",
        "goto chain 999",
        "pref 100 ",
    ] {
        assert!(chain0.contains(want), "{want}: {chain0}");
    }
    assert_eq!(d.flowspec_prios(i).unwrap(), [10, 11, 12]);
    let counts = d.flowspec_counters(i).unwrap();
    assert_eq!(counts.keys().copied().collect::<Vec<_>>(), [10, 11, 12]);

    // A new ACL chain moves the exit with it.
    d.install(i, Direction::In, ACL_CHAIN_B, &acl_one).unwrap();
    d.switch(i, Direction::In, ACL_CHAIN_B, Some(ACL_CHAIN_A))
        .unwrap();
    assert!(show("fs0", "ingress", flowspec::EXIT_CHAIN).contains("goto chain 1001"));

    d.flowspec_set(i, 11, None).unwrap();
    assert_eq!(d.flowspec_prios(i).unwrap(), [10, 12]);
    // Clearing an empty priority is fine.
    d.flowspec_set(i, 11, None).unwrap();
    d.detach(i, Direction::In).unwrap();
    assert_eq!(show("fs0", "ingress", flowspec::EXIT_CHAIN), "");
    d.flowspec_set(i, 10, None).unwrap();
    d.flowspec_set(i, 12, None).unwrap();
    let left = show("fs0", "ingress", 0);
    assert!(
        left.contains("pref 1 ") && !left.contains("pref 10 ") && !left.contains("pref 100"),
        "{left}"
    );
    run(&["ip", "link", "del", "fs0"]);
}

/// A flood through a `log` rule (#699): about one packet in `SAMPLE_RATE`
/// reaches psample, while the verdict counts every packet exactly.
#[test]
#[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
fn a_flood_through_a_log_rule_is_sampled_sparsely_and_still_counted() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const SENT: u64 = 3000;

    run(&["ip", "link", "set", "lo", "up"]);
    run(&[
        "ip",
        "link",
        "add",
        "v0",
        "address",
        "02:00:00:00:00:01",
        "type",
        "veth",
        "peer",
        "name",
        "v1",
        "address",
        "02:00:00:00:00:02",
    ]);
    run(&["ip", "link", "set", "v0", "up"]);
    run(&["ip", "link", "set", "v1", "up"]);
    run(&["ip", "addr", "add", "192.0.2.1/24", "dev", "v0"]);
    run(&[
        "ip",
        "neigh",
        "add",
        "192.0.2.9",
        "lladdr",
        "02:00:00:00:00:02",
        "dev",
        "v0",
        "nud",
        "permanent",
    ]);
    let i = idx("v1");
    let logged = compile(&acl(vec![AclRule {
        name: "flood".into(),
        action: AclAction::Deny,
        protocol: Some(AclProtocol::Udp),
        log: true,
        ..Default::default()
    }]))
    .unwrap();
    let mut d = LinuxDriver;
    d.install(i, Direction::In, ACL_CHAIN_A, &logged).unwrap();
    d.switch(i, Direction::In, ACL_CHAIN_A, None).unwrap();

    let p = nos_tc::psample().unwrap();
    let mut socket = nos_tc::SampleSocket::open(&p).unwrap();
    let samples = Arc::new(AtomicUsize::new(0));
    let n = samples.clone();
    std::thread::spawn(move || loop {
        if let Ok(v) = socket.recv() {
            n.fetch_add(v.len(), Ordering::Relaxed);
        }
    });

    let sock = std::net::UdpSocket::bind("192.0.2.1:0").unwrap();
    for _ in 0..SENT {
        sock.send_to(b"flood", ("192.0.2.9", 5000)).unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(1000));

    let got = samples.load(Ordering::Relaxed);
    assert!((5..=150).contains(&got), "{got} samples of {SENT}");
    let rows = d.counters(i, Direction::In, ACL_CHAIN_A).unwrap();
    let decided: u64 = rows
        .iter()
        .filter(|c| c.cookie == 0)
        .map(|c| c.packets)
        .sum();
    assert_eq!(decided, SENT, "{rows:?}");
}
