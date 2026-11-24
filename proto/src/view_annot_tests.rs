//! The `#[view]` annotations of the flat reply types (#1426): every key
//! matches the JSON of a sample (both ways, nested included) and the postcard
//! bytes are the golden ones, so the annotation changed no wire format.

use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;

use crate::bgp::RpkiSessionState;
use crate::bgp::{BmpFrameCounts, BmpStationState, BmpStationStatus, RpkiCacheStatus};
use crate::fdb::{EsEntry, FdbTable, MacEntry, MacSource, NeighEntry};
use crate::ospf::{LinkInterfaceState, LlsSummary, NeighborSummary, OspfNeighborState};
use crate::ospfv3::Ospfv3NeighborSummary;
use crate::schema::AclAction;
use crate::view::{assert_keys_match, view_of, ViewValue};
use crate::{
    AclAttachment, AclDirection, AclRuleStatus, AclStatus, BmpMonitor, DfAlgorithm,
    FlowspecRuleStatus, LldpLinkStats, VersionInfo,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        write!(s, "{x:02x}").unwrap();
        s
    })
}

/// Keys match both ways, and the postcard bytes equal `golden` (hex).
fn check<T: Serialize + ViewValue>(sample: &T, golden: &str) {
    let node = view_of::<T>().expect("a View struct");
    assert_keys_match(node, &serde_json::to_value(sample).unwrap());
    assert_eq!(hex(&postcard::to_allocvec(sample).unwrap()), golden);
}

#[test]
fn acl_status() {
    check(
        &AclStatus {
            name: "in".into(),
            default_action: AclAction::Deny,
            default_packets: 1,
            default_bytes: 2,
            levels: 3,
            filters: 4,
            attached: vec![AclAttachment {
                interface: "eth1".into(),
                direction: AclDirection::In,
            }],
            rules: vec![AclRuleStatus {
                name: "r1".into(),
                action: AclAction::Permit,
                dropped: Some("shadowed".into()),
                level: Some(7),
                packets: 5,
                bytes: 6,
            }],
        },
        "02696e01010203040104657468310001027231000108736861646f77656401070506",
    );
}

#[test]
fn flowspec_rule_status() {
    check(
        &FlowspecRuleStatus {
            instance: "b".into(),
            table: Some("rt1".into()),
            flow: "dst 10.0.0.0/8".into(),
            actions: vec!["discard".into()],
            unsupported: None,
            packets: 8,
            bytes: 9,
        },
        "016201037274310e6473742031302e302e302e302f38010764697363617264000809",
    );
}

#[test]
fn lldp_link_stats() {
    check(
        &LldpLinkStats {
            interface: "eth0".into(),
            frames_out: 1,
            frames_in: 2,
            frames_in_errors: 3,
            frames_discarded: 4,
            tlvs_discarded: 5,
            tlvs_unrecognized: 6,
            ageouts: 7,
            too_many_neighbors: 8,
        },
        "04657468300102030405060708",
    );
}

#[test]
fn rpki_cache_status() {
    check(
        &RpkiCacheStatus {
            address: ip("192.0.2.1"),
            port: 323,
            preference: 1,
            state: RpkiSessionState::Established,
            active: true,
            version: Some(1),
            session_id: Some(9),
            serial: Some(100),
            vrp_count: 42,
            last_update_secs: Some(30),
            authenticated: true,
        },
        "00c0000201c3020102010101010901642a011e01",
    );
}

#[test]
fn bmp_station_status() {
    check(
        &BmpStationStatus {
            name: "s1".into(),
            address: ip("2001:db8::1"),
            port: 11019,
            state: BmpStationState::Connected,
            connected_since: Some(1_700_000_000),
            monitor: BmpMonitor::PostPolicy,
            statistics_interval: Some(60),
            peers_monitored: 2,
            frames_sent: BmpFrameCounts {
                initiation: 1,
                peer_up: 2,
                peer_down: 3,
                route_monitoring_pre: 4,
                route_monitoring_post: 5,
                end_of_rib: 6,
                stats: 7,
                termination: 8,
            },
            overflows: 1,
            reconnects: 2,
            last_error: Some("refused".into()),
        },
        "0273310120010db80000000000000000000000018b56010180e2cfaa0600013c0201020304050607080102010772656675736564",
    );
}

#[test]
fn fdb_table() {
    check(
        &FdbTable {
            domain: "d1".into(),
            vni: 100,
            bridge: Some("br100".into()),
            vxlan: Some("vx100".into()),
            macs: vec![MacEntry {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                source: MacSource::Remote,
                vtep: Some(ip("10.0.0.1")),
                vteps: vec![ip("10.0.0.1"), ip("10.0.0.2")],
                esi: Some("00:11:22:33:44:55:66:77:88:99".into()),
            }],
            neighbours: vec![NeighEntry {
                ip: ip("10.1.0.5"),
                mac: "aa:bb:cc:dd:ee:ff".into(),
                source: MacSource::Local,
                vtep: None,
            }],
            flood: vec![ip("10.0.0.1")],
            segments: vec![EsEntry {
                esi: "00:11:22:33:44:55:66:77:88:99".into(),
                port: "bond0".into(),
                designated_forwarder: true,
                pes: vec![ip("10.0.0.1")],
                ad_pes: vec![ip("10.0.0.2")],
                up: true,
                single_active: false,
                df_algorithm: DfAlgorithm::Hrw,
                local_bias: true,
            }],
            neigh_suppress: true,
        },
        "026431640105627231303001057678313030011161613a62623a63633a64643a65653a66660101000a00000102000a000001000a000002011d30303a31313a32323a33333a34343a35353a36363a37373a38383a393901000a0100051161613a62623a63633a64643a65653a6666000001000a000001011d30303a31313a32323a33333a34343a35353a36363a37373a38383a393905626f6e64300101000a00000101000a0000020100010101",
    );
}

fn ospf_row() -> NeighborSummary {
    NeighborSummary {
        link: "eth0.0".into(),
        area_id: Ipv4Addr::new(0, 0, 0, 1),
        interface_state: LinkInterfaceState::Dr,
        neighbor_router_id: Some(Ipv4Addr::new(2, 2, 2, 2)),
        state: OspfNeighborState::Full,
        last_hello_secs: Some(3),
        hello_interval: 10,
        dead_interval: 40,
        priority: 1,
        neighbor_priority: Some(1),
        dr: Some(Ipv4Addr::new(1, 1, 1, 1)),
        bdr: None,
        lls: Some(LlsSummary {
            eof: 3,
            lr: true,
            rs: false,
        }),
    }
}

#[test]
fn ospf_neighbor_summary() {
    check(
        &ospf_row(),
        "06657468302e30000000010201020202020601030a2801010101010101010001030100",
    );
}

#[test]
fn ospfv3_neighbor_summary() {
    let r = ospf_row();
    check(
        &Ospfv3NeighborSummary {
            link: r.link,
            area_id: r.area_id,
            interface_state: r.interface_state,
            neighbor_router_id: r.neighbor_router_id,
            state: r.state,
            last_hello_secs: r.last_hello_secs,
            hello_interval: r.hello_interval,
            dead_interval: r.dead_interval,
            priority: r.priority,
            neighbor_priority: r.neighbor_priority,
            dr: r.dr,
            bdr: r.bdr,
        },
        "06657468302e30000000010201020202020601030a28010101010101010100",
    );
}

#[test]
fn version_info() {
    check(
        &VersionInfo {
            version: "1.2.3".into(),
            revision: "abc1234".into(),
        },
        "05312e322e330761626331323334",
    );
}

#[test]
fn brief_columns_follow_the_decisions() {
    let cols = |n: &crate::view::Node| n.columns().iter().map(|f| f.key).collect::<Vec<_>>();
    let lldp = view_of::<LldpLinkStats>().unwrap();
    assert_eq!(cols(lldp).len(), 9, "all seven counters plus interface");
    assert!(cols(view_of::<NeighborSummary>().unwrap()).contains(&"lls"));
    let bmp = view_of::<BmpStationStatus>().unwrap();
    for k in ["frames_sent", "last_error", "connected_since"] {
        assert!(!cols(bmp).contains(&k), "{k} is detail only");
    }
    assert_eq!(
        cols(view_of::<VersionInfo>().unwrap()),
        ["version", "revision"]
    );
}
