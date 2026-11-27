//! Against the real kernel: needs `CAP_NET_ADMIN` in the current netns, and
//! `ip` (the independent oracle), so run it in a throwaway one:
//! `unshare -Urn cargo test -p nos-nexthop --test kernel -- --ignored`.
#![allow(
    clippy::disallowed_types,
    reason = "test code: `ip` is the independent oracle for the netlink encoder (#228)"
)]

use std::process::Command;

use nos_nexthop::{dump, send, Gateway, Group, Nexthop};

fn ip(args: &[&str]) -> String {
    let o = Command::new("ip").args(args).output().unwrap();
    assert!(
        o.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn up_dummy() -> u32 {
    ip(&["link", "set", "lo", "up"]);
    // The tests share one netns: the second caller finds d0 already there.
    let _ = Command::new("ip")
        .args(["link", "add", "d0", "type", "dummy"])
        .output();
    ip(&["link", "set", "d0", "up"]);
    let _ = Command::new("ip")
        .args(["addr", "add", "10.0.0.2/24", "dev", "d0"])
        .output();
    ip(&["-o", "link", "show", "d0"])
        .split(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

fn gw(id: u32, a: &str, oif: u32) -> Gateway {
    Gateway {
        id,
        gateway: a.parse().unwrap(),
        oif: Some(oif),
        onlink: false,
        labels: vec![],
        fdb: false,
        replace: true,
    }
}

#[test]
#[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
fn gateways_groups_replace_delete_and_dump_agree_with_ip() {
    let d0 = up_dummy();
    // gateway + oif + onlink (the gateway is off-subnet, so onlink is needed)
    let mut a = gw(1, "10.0.0.7", d0);
    send(&Nexthop::Gateway(a.clone()), 0).unwrap();
    a.id = 2;
    a.gateway = "192.0.2.1".parse().unwrap();
    a.onlink = true;
    send(&Nexthop::Gateway(a.clone()), 0).unwrap();
    // A group, weights 1 and 3, then replaced in place by another member list.
    send(
        &Nexthop::Group(Group {
            id: 10,
            members: vec![(1, 1), (2, 3)],
            fdb: false,
        }),
        0,
    )
    .unwrap();
    let shown = ip(&["-d", "nexthop", "show", "id", "10"]);
    assert!(
        shown.contains("1,3/2,1") || shown.contains("1/2,3"),
        "{shown}"
    );
    let recs = dump(0..=100).unwrap();
    assert_eq!(recs.len(), 3);
    let g = recs.iter().find(|r| r.id == 10).unwrap();
    assert_eq!(g.group, Some(vec![(1, 1), (2, 3)]));
    let r2 = recs.iter().find(|r| r.id == 2).unwrap();
    assert!(r2.onlink && r2.oif == Some(d0));
    assert_eq!(r2.gateway, Some("192.0.2.1".parse().unwrap()));
    send(
        &Nexthop::Group(Group {
            id: 10,
            members: vec![(1, 1)],
            fdb: false,
        }),
        0,
    )
    .unwrap();
    assert_eq!(
        dump(10..=10).unwrap()[0].group,
        Some(vec![(1, 1)]),
        "replaced in place"
    );
    // The range filter hides the rest.
    assert_eq!(dump(50..=60).unwrap(), vec![]);
    // Kernel-proven (Linux 7.2): an IPv6 route cannot use an IPv4-gateway
    // nexthop, alone or through a group.
    for nhid in ["1", "10"] {
        let o = Command::new("ip")
            .args(["-6", "route", "add", "2001:db8::/64", "nhid", nhid])
            .output()
            .unwrap();
        assert!(!o.status.success());
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("IPv4 nexthop"),
            "{}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    for id in [10, 2, 1] {
        send(&Nexthop::Delete { id }, 0).unwrap();
    }
    assert!(send(&Nexthop::Delete { id: 1 }, 0).is_err());
    send(&Nexthop::Delete { id: 1 }, 2).unwrap();
    assert_eq!(dump(0..=u32::MAX).unwrap(), vec![]);
}

#[test]
#[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
fn fdb_gateways_and_groups_and_ipv6() {
    send(
        &Nexthop::Gateway(Gateway::fdb(1, "10.50.0.11".parse().unwrap())),
        0,
    )
    .unwrap();
    send(
        &Nexthop::Gateway(Gateway::fdb(2, "fd00:10:50::a".parse().unwrap())),
        0,
    )
    .unwrap();
    // The same id again is a replace, not an error.
    send(
        &Nexthop::Gateway(Gateway::fdb(1, "10.50.0.11".parse().unwrap())),
        0,
    )
    .unwrap();
    send(
        &Nexthop::Group(Group {
            id: 3,
            members: vec![(1, 1)],
            fdb: true,
        }),
        0,
    )
    .unwrap();
    let recs = dump(1..=3).unwrap();
    assert!(recs.iter().all(|r| r.fdb));
    assert_eq!(recs.len(), 3);
    assert!(ip(&["nexthop", "show"]).contains("fdb"));
    for id in [3, 1, 2] {
        send(&Nexthop::Delete { id }, 0).unwrap();
    }
}

/// Needs the `mpls_iptunnel` module; skips (loudly) when it is absent.
#[test]
#[ignore = "talks to the kernel; needs CAP_NET_ADMIN and mpls_iptunnel"]
fn an_mpls_encap_gateway_round_trips() {
    let d0 = up_dummy();
    let mut g = gw(1, "10.0.0.7", d0);
    g.labels = vec![100, 200];
    if let Err(e) = send(&Nexthop::Gateway(g), 0) {
        eprintln!("SKIPPED: mpls encap unavailable: {e}");
        return;
    }
    let shown = ip(&["-d", "nexthop", "show", "id", "1"]);
    assert!(shown.contains("100/200"), "{shown}");
    assert_eq!(dump(1..=1).unwrap()[0].labels, vec![100, 200]);
    send(&Nexthop::Delete { id: 1 }, 0).unwrap();
}
