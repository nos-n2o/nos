//! Goldens of the flat `show` views migrated onto the view engine (#1423).
//! Goldens are in `tests/goldens/`; edit them by hand from the failing diff.

use nos_cli::view::{render, render_detail, to_value};
use nos_proto::schema::AclAction;
use nos_proto::view::view_of;
use nos_proto::{
    AclAttachment, AclDirection, AclRuleStatus, AclStatus, DfAlgorithm, EsEntry, FdbTable,
    FlowspecRuleStatus, LinkInterfaceState, LldpLinkStats, LlsSummary, MacEntry, MacSource,
    NeighEntry, NeighborSummary, OspfNeighborState, Ospfv3NeighborSummary, RpkiCacheStatus,
    RpkiSessionState,
};
use std::net::Ipv4Addr;

fn check(name: &str, got: &str) {
    let path = format!("{}/tests/goldens/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    let want = std::fs::read_to_string(&path).unwrap();
    assert_eq!(want, format!("{got}\n"), "golden {name}");
}

const BAD: &str = "x\nFORGED\u{1b}[2J";

fn acl(name: &str, attached: bool) -> AclStatus {
    AclStatus {
        name: name.into(),
        default_action: AclAction::Deny,
        default_packets: 1500,
        default_bytes: 2_000_000,
        levels: 2,
        filters: 5,
        attached: if attached {
            vec![
                AclAttachment {
                    interface: "eth1".into(),
                    direction: AclDirection::In,
                },
                AclAttachment {
                    interface: "eth1".into(),
                    direction: AclDirection::Out,
                },
            ]
        } else {
            vec![]
        },
        rules: vec![
            AclRuleStatus {
                name: "r10".into(),
                action: AclAction::Permit,
                dropped: None,
                level: Some(0),
                packets: 12,
                bytes: 3400,
            },
            AclRuleStatus {
                name: "r20".into(),
                action: AclAction::Deny,
                dropped: Some("shadowed".into()),
                level: None,
                packets: 0,
                bytes: 0,
            },
        ],
    }
}

#[test]
fn acl_views() {
    check("acl_empty", &render(&Vec::<AclStatus>::new(), "no acls"));
    check("acl_populated", &render(&acl("EDGE", true), ""));
    check("acl_unattached", &render(&acl("LAB", false), ""));
    check("acl_forged", &render(&acl(BAD, true), ""));
}

fn flow(f: &str, table: Option<&str>, unsupported: Option<&str>) -> FlowspecRuleStatus {
    FlowspecRuleStatus {
        instance: "b1".into(),
        table: table.map(Into::into),
        flow: f.into(),
        actions: vec!["discard".into(), "rate 0".into()],
        unsupported: unsupported.map(Into::into),
        packets: 7,
        bytes: 9000,
    }
}

#[test]
fn flowspec_views() {
    check(
        "flowspec_populated",
        &render(
            &vec![
                flow("dst 192.0.2.0/24", None, None),
                flow("src 10.0.0.0/8", Some("rt1"), Some("sample")),
            ],
            "",
        ),
    );
    check(
        "flowspec_forged",
        &render(&vec![flow(BAD, Some(BAD), Some(BAD))], ""),
    );
}

fn lldp(i: &str) -> LldpLinkStats {
    LldpLinkStats {
        interface: i.into(),
        frames_out: 10,
        frames_in: 9,
        frames_in_errors: 1,
        frames_discarded: 2,
        tlvs_discarded: 3,
        tlvs_unrecognized: 4,
        ageouts: 5,
        too_many_neighbors: 6,
    }
}

#[test]
fn lldp_views() {
    check(
        "lldp_statistics_empty",
        &render(&Vec::<LldpLinkStats>::new(), "no lldp links"),
    );
    check(
        "lldp_statistics_populated",
        &render(&vec![lldp("eth1"), lldp("eth0")], ""),
    );
    check("lldp_statistics_forged", &render(&vec![lldp(BAD)], ""));
}

fn rpki(pref: u8, full: bool) -> RpkiCacheStatus {
    RpkiCacheStatus {
        address: "192.0.2.5".parse().unwrap(),
        port: 323,
        preference: pref,
        state: if full {
            RpkiSessionState::Established
        } else {
            RpkiSessionState::Idle
        },
        active: full,
        version: full.then_some(1),
        session_id: full.then_some(77),
        serial: full.then_some(9),
        vrp_count: 1234,
        last_update_secs: full.then_some(125),
        authenticated: full,
    }
}

#[test]
fn rpki_views() {
    check(
        "rpki_populated",
        &render(&vec![rpki(20, false), rpki(10, true)], ""),
    );
}

fn nbr(link: &str) -> NeighborSummary {
    NeighborSummary {
        link: link.into(),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_state: LinkInterfaceState::PointToPoint,
        neighbor_router_id: None,
        state: OspfNeighborState::Down,
        last_hello_secs: None,
        hello_interval: 10,
        dead_interval: 40,
        priority: 1,
        neighbor_priority: None,
        dr: None,
        bdr: None,
        lls: None,
        address: None,
        role: None,
        dead_in_secs: None,
        uptime_secs: None,
    }
}

fn nbr_up(link: &str) -> NeighborSummary {
    NeighborSummary {
        interface_state: LinkInterfaceState::Backup,
        neighbor_router_id: Some("9.9.9.10".parse().unwrap()),
        state: OspfNeighborState::TwoWay,
        last_hello_secs: Some(3),
        neighbor_priority: Some(200),
        dr: Some("9.9.9.10".parse().unwrap()),
        bdr: Some("1.1.1.1".parse().unwrap()),
        lls: Some(LlsSummary {
            eof: 3,
            lr: true,
            rs: true,
        }),
        address: Some("10.0.0.9".parse().unwrap()),
        role: Some(nos_proto::NeighborRole::Dr),
        dead_in_secs: Some(37),
        uptime_secs: Some(125),
        ..nbr(link)
    }
}

#[test]
fn ospf_views() {
    check(
        "ospf_neighbors_populated",
        &render(&vec![nbr_up("eth1.0"), nbr("eth0.0")], ""),
    );
    check("ospf_neighbors_forged", &render(&vec![nbr(BAD)], ""));
    let v3: Vec<Ospfv3NeighborSummary> = vec![Ospfv3NeighborSummary {
        link: "eth0.0".into(),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_state: LinkInterfaceState::DrOther,
        neighbor_router_id: Some("2.2.2.2".parse().unwrap()),
        state: OspfNeighborState::Full,
        last_hello_secs: Some(1),
        hello_interval: 10,
        dead_interval: 40,
        priority: 1,
        neighbor_priority: Some(1),
        dr: Some("3.3.3.3".parse().unwrap()),
        bdr: None,
        address: Some("fe80::2".parse().unwrap()),
        role: Some(nos_proto::NeighborRole::DrOther),
        dead_in_secs: Some(38),
        uptime_secs: Some(3600),
    }];
    check("ospfv3_neighbors_populated", &render(&v3, ""));
}

fn fdb() -> FdbTable {
    FdbTable {
        domain: "bd".into(),
        vni: 100,
        bridge: Some("br100".into()),
        vxlan: None,
        macs: vec![
            MacEntry {
                mac: "02:00:00:00:00:01".into(),
                source: MacSource::Local,
                vtep: None,
                vteps: vec![],
                esi: Some("00:11:22:33:44:55:66:77:88:99".into()),
            },
            MacEntry {
                mac: "02:00:00:00:00:02".into(),
                source: MacSource::Remote,
                vtep: Some("192.0.2.9".parse().unwrap()),
                vteps: vec!["192.0.2.9".parse().unwrap(), "192.0.2.10".parse().unwrap()],
                esi: None,
            },
        ],
        neighbours: vec![NeighEntry {
            ip: "10.0.0.9".parse().unwrap(),
            mac: "02:00:00:00:00:02".into(),
            source: MacSource::Remote,
            vtep: Some("192.0.2.9".parse().unwrap()),
        }],
        flood: vec!["192.0.2.9".parse().unwrap()],
        segments: vec![EsEntry {
            esi: "00:11:22:33:44:55:66:77:88:99".into(),
            port: "bond1".into(),
            designated_forwarder: true,
            pes: vec!["192.0.2.1".parse().unwrap(), "192.0.2.9".parse().unwrap()],
            ad_pes: vec!["192.0.2.9".parse().unwrap()],
            up: true,
            single_active: false,
            df_algorithm: DfAlgorithm::Modulo,
            local_bias: false,
        }],
        neigh_suppress: true,
    }
}

#[test]
fn fdb_views() {
    check("fdb_populated", &render(&fdb(), ""));
    let mut empty = fdb();
    empty.macs.clear();
    empty.neighbours.clear();
    empty.flood.clear();
    empty.segments.clear();
    check("fdb_empty", &render(&empty, ""));
    let mut forged = fdb();
    forged.domain = BAD.into();
    forged.macs[0].mac = BAD.into();
    check("fdb_forged", &render(&forged, ""));
}

#[test]
fn version_block() {
    let v = nos_proto::version::VersionInfo {
        version: "0.1.0".into(),
        revision: "abc1234".into(),
    };
    check("version", &render(&v, ""));
}

/// The "no field silently missing" property: every non-hidden field of a
/// fully populated sample shows in the detail render.
#[test]
fn detail_shows_every_field() {
    fn all<T: serde::Serialize + nos_proto::view::ViewValue>(sample: &T) {
        let node = view_of::<T>().unwrap();
        let d = render_detail(node, &to_value(sample));
        for f in node.details() {
            assert!(d.contains(f.header), "{} missing in\n{d}", f.header);
        }
    }
    all(&acl("EDGE", true));
    all(&flow("f", Some("rt1"), Some("x")));
    all(&lldp("eth0"));
    all(&rpki(1, true));
    all(&nbr_up("eth0"));
    all(&fdb());
}
