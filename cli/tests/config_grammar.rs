//! The config grammar's regression suite (#109): every `edit`/`set`/`delete`
//! line the legacy hand-written parser was tested with, and a filled-in line
//! for every one of its help rows, with the `EditTransactionPath` writes (and
//! navigation) the tree grammar must produce for it — recorded, in
//! `config_corpus.jsonl`, while the legacy parser still existed and agreed
//! on the resulting `Config`. Lines the legacy parser couldn't parse must
//! still be rejected everywhere.

use nos_cli::config_grammar;
use nos_proto::schema::*;
use nos_proto::{config_path, Config};
use serde_json::Value;

fn populated() -> Config {
    let pg = BgpPeerGroup {
        name: "PG1".into(),
        remote_as: 65001,
        ..Default::default()
    };
    let bgp = |name: &str| BgpInstance {
        name: name.into(),
        asn: 65000,
        router_id: "1.1.1.1".parse().unwrap(),
        peer_groups: vec![pg.clone()],
        peers: vec![BgpPeer {
            remote_address: "192.0.2.1".parse().unwrap(),
            peer_group: "PG1".into(),
            shutdown: None,
        }],
        ..Default::default()
    };
    let area = OspfArea {
        area_id: "0.0.0.0".parse().unwrap(),
        area_type: nos_proto::OspfAreaType::Normal,
        stub_default_cost: None,
        nssa_translate_always: false,
        nssa_default_originate: false,
        ranges: Vec::new(),
        virtual_links: Vec::new(),
        profiles: vec![OspfProfile {
            name: "p1".into(),
            ..Default::default()
        }],
    };
    let area3 = Ospfv3Area {
        area_id: "0.0.0.0".parse().unwrap(),
        profiles: vec![Ospfv3Profile {
            name: "p1".into(),
            ..Default::default()
        }],
    };
    let iface = |name: &str| Interface {
        name: name.into(),
        subinterfaces: vec![Subinterface::default()],
        ..Default::default()
    };
    Config {
        bgp_instances: vec![bgp("R1"), bgp("r1")],
        routing_tables: vec![RoutingTable {
            name: "rt1".into(),
            ..Default::default()
        }],
        ospf_instances: vec![OspfInstance {
            name: "o1".into(),
            areas: vec![area],
            ..Default::default()
        }],
        ospfv3_instances: vec![Ospfv3Instance {
            name: "o1".into(),
            areas: vec![area3],
            ..Default::default()
        }],
        static_routing_instances: vec![StaticRoutingInstance {
            name: "sri1".into(),
            routes: vec![StaticRoute {
                bfd: None,
                subnet: "10.0.0.0/24".parse().unwrap(),
                gateway: "10.0.0.254".parse().unwrap(),
            }],
        }],
        interfaces: vec![
            iface("eth0"),
            iface("eth1"),
            Interface {
                name: "loopback-rt1".into(),
                ..Default::default()
            },
        ],
        policy_definitions: vec![PolicyDefinition {
            name: "p1".into(),
            source: "accept\n".into(),
        }],
        community_aliases: vec![CommunityAlias {
            name: "CUSTOMER_A".into(),
            value: "65000:1".into(),
        }],
        community_groups: vec![CommunityGroup {
            name: "CUSTOMERS".into(),
            members: vec!["CUSTOMER_A".into()],
        }],
        prefix_lists: vec![PrefixList {
            name: "BLOCKS".into(),
            entries: vec![PrefixListEntry {
                cidr: "10.0.0.0/8".parse().unwrap(),
                range: Some((24, 32)),
            }],
        }],
        as_path_lists: vec![AsPathList {
            name: "TRANSIT".into(),
            patterns: vec!["^65001_".into()],
        }],
        broadcast_domains: vec![BroadcastDomain {
            name: "bd1".into(),
            ..Default::default()
        }],
        switching_profiles: vec![SwitchingProfile {
            name: "sp1".into(),
            ..Default::default()
        }],
        port_aggregates: vec![PortAggregate {
            name: "bond1".into(),
            ..Default::default()
        }],
        users: vec![User {
            name: "alice".into(),
            password: "x".into(),
        }],
        ..Default::default()
    }
}

/// Every navigation position the populated fixture has, as REST segments.
fn positions(doc: &Value) -> Vec<Vec<String>> {
    let mut out = vec![vec![]];
    let mut i = 0;
    while i < out.len() {
        let here = out[i].clone();
        if let Ok(Value::Object(obj)) = config_path::get(doc, &here) {
            for (field, v) in obj {
                let Value::Array(items) = v else { continue };
                for item in items {
                    let Value::Object(e) = item else { continue };
                    let Some(key) = config_path::key_field(e.keys().map(String::as_str)) else {
                        continue;
                    };
                    let key = e[key]
                        .as_str()
                        .map_or_else(|| e[key].to_string(), str::to_string);
                    let mut p = here.clone();
                    p.push(config_path::field_segment(field, true));
                    p.push(key);
                    out.push(p);
                }
            }
        }
        i += 1;
    }
    out
}

#[test]
fn every_corpus_line_makes_its_recorded_edit() {
    let populated = serde_json::to_value(populated()).unwrap();
    let empty = serde_json::to_value(Config::default()).unwrap();
    let everywhere = positions(&populated);
    let (mut edits, mut rejected) = (0, 0);
    let mut failures = Vec::new();
    for entry in include_str!("config_corpus.jsonl").lines() {
        let entry: Value = serde_json::from_str(entry).unwrap();
        let line = entry["line"].as_str().unwrap();
        if entry["rejected"] == Value::Bool(true) {
            for at in &everywhere {
                if config_grammar::parse(line, at, &populated).is_some() {
                    failures.push(format!("/{}: accepts '{line}'", at.join("/")));
                }
            }
            rejected += 1;
            continue;
        }
        let doc = if entry["fixture"] == "empty" {
            &empty
        } else {
            &populated
        };
        let at: Vec<String> = serde_json::from_value(entry["at"].clone()).unwrap();
        match config_grammar::parse(line, &at, doc) {
            Some(edit) => {
                let got = serde_json::json!({ "writes": edit.writes, "navigate": edit.navigate });
                let want =
                    serde_json::json!({ "writes": entry["writes"], "navigate": entry["navigate"] });
                if got != want {
                    failures.push(format!(
                        "/{}: '{line}'\n  want {want}\n  got  {got}",
                        at.join("/")
                    ));
                }
                // And the writes apply, like nos-configd applies them.
                let mut applied = doc.clone();
                for (path, value) in edit.writes {
                    config_path::set(&mut applied, &path, value).unwrap();
                }
                serde_json::from_value::<Config>(applied).unwrap();
            }
            None => failures.push(format!("/{}: rejects '{line}'", at.join("/"))),
        }
        edits += 1;
    }
    println!(
        "{edits} edits, {rejected} rejected lines, {} failures",
        failures.len()
    );
    assert!(edits > 300 && rejected > 10);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The writes a line typed at the root makes, as JSON, or `None` if it's rejected.
fn writes(line: &str, doc: &Value) -> Option<Value> {
    config_grammar::parse(line, &[], doc).map(|e| serde_json::json!(e.writes))
}

/// #35: the stub/range fields of an OSPF area are reachable from the CLI.
#[test]
fn ospf_area_type_and_range() {
    let doc = serde_json::to_value(populated()).unwrap();
    let area = |line: &str| -> nos_proto::OspfArea {
        let w = writes(line, &doc).unwrap_or_else(|| panic!("rejected: {line}"));
        let mut applied = doc.clone();
        for pair in w.as_array().unwrap() {
            let path: Vec<String> = serde_json::from_value(pair[0].clone()).unwrap();
            config_path::set(&mut applied, &path, pair[1].clone()).unwrap();
        }
        let cfg: Config = serde_json::from_value(applied).unwrap();
        cfg.ospf_instances[0].areas[0].clone()
    };
    let at = "set ospf instance o1 area 0.0.0.0";
    assert_eq!(
        area(&format!("{at} area-type totally-stubby")).area_type,
        nos_proto::OspfAreaType::TotallyStubby
    );
    assert_eq!(
        area(&format!("{at} range 10.1.0.0/16 not-advertise")).ranges,
        [nos_proto::OspfAreaRange {
            cidr: "10.1.0.0/16".parse().unwrap(),
            not_advertise: true
        }]
    );
    let links = area(&format!("{at} virtual-link 2.2.2.2 hello-interval 5")).virtual_links;
    assert_eq!(links[0].router_id.to_string(), "2.2.2.2");
    assert_eq!(links[0].hello_interval, Some(5));
}

/// #25: a routing table's EVPN L3 VNI is reachable from the CLI.
#[test]
fn routing_table_evpn() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    let rt = "set routing-table rt1 evpn";
    for line in [
        format!("{rt} l3-vni 5000"),
        format!("{rt} rd 65000:5000"),
        format!("{rt} route-target import 65000:5000"),
        format!("{rt} route-target export 65000:5000"),
        format!("{rt} vtep-source interface eth0"),
        format!("{rt} bgp-instance r1"),
    ] {
        let w = writes(&line, &doc).unwrap_or_else(|| panic!("rejected: {line}"));
        for pair in w.as_array().unwrap() {
            let path: Vec<String> = serde_json::from_value(pair[0].clone()).unwrap();
            config_path::set(&mut doc, &path, pair[1].clone()).unwrap();
        }
    }
    let cfg: Config = serde_json::from_value(doc).unwrap();
    assert_eq!(
        cfg.routing_tables[0].evpn,
        RoutingTableEvpn {
            l3_vni: Some(5000),
            rd: Some("65000:5000".into()),
            route_targets_import: vec!["65000:5000".into()],
            route_targets_export: vec!["65000:5000".into()],
            vtep_source: Some(SourceAddress::Interface {
                interface: "eth0".into(),
                label: None
            }),
            bgp_instance: Some("r1".into()),
        }
    );
}

/// #576: a routing table's L3VPN identity is reachable from the CLI.
#[test]
fn routing_table_vpn() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    let rt = "set routing-table rt1 vpn";
    for line in [
        format!("{rt} rd 65000:1"),
        format!("{rt} route-target import 65000:1"),
        format!("{rt} route-target export 65000:1"),
        format!("{rt} bgp-instance r1"),
        format!("{rt} label 100"),
        format!("{rt} site-of-origin 65001:77"),
    ] {
        let w = writes(&line, &doc).unwrap_or_else(|| panic!("rejected: {line}"));
        for pair in w.as_array().unwrap() {
            let path: Vec<String> = serde_json::from_value(pair[0].clone()).unwrap();
            config_path::set(&mut doc, &path, pair[1].clone()).unwrap();
        }
    }
    let cfg: Config = serde_json::from_value(doc).unwrap();
    assert_eq!(
        cfg.routing_tables[0].vpn,
        nos_proto::RoutingTableVpn {
            rd: Some("65000:1".into()),
            route_targets_import: vec!["65000:1".into()],
            route_targets_export: vec!["65000:1".into()],
            bgp_instance: Some("r1".into()),
            label: Some(100),
            site_of_origin: Some("65001:77".into()),
        }
    );
}

/// #120: absolute forms that #109 made work; pinned so they stay.
#[test]
fn absolute_peer_group_field_and_policy_definition_deletes() {
    let doc = serde_json::to_value(populated()).unwrap();
    for field in ["hold-time", "import-policy"] {
        let line = format!("delete bgp instance r1 peer-group PG1 {field}");
        assert_eq!(
            writes(&line, &doc),
            Some(serde_json::json!([[
                ["bgp-instance", "r1", "peer-group", "PG1", field],
                null
            ]])),
            "{line}"
        );
    }
    assert_eq!(
        writes("delete policy-definition p1", &doc),
        // The list is rewritten without it (the fixture's only one).
        Some(serde_json::json!([[["policy-definition"], []]]))
    );
}

/// #120: `ao-key <send-id> exclude-options` sets that one key's flag,
/// `delete … exclude-options` clears it, and an unknown send-id is refused.
#[test]
fn ao_key_exclude_options() {
    let key = |send_id, exclude_options| BgpAoKey {
        send_id,
        recv_id: send_id,
        algorithm: BgpAoAlgorithm::HmacSha1_96,
        key_ref: "k".into(),
        is_current: send_id == 1,
        is_rnext: false,
        exclude_options,
    };
    let with_keys = |second_excluded| {
        let mut cfg = populated();
        cfg.bgp_instances[1].peer_groups[0].auth = Some(BgpAuth::Ao {
            keys: vec![key(1, false), key(2, second_excluded)],
        });
        serde_json::to_value(&cfg).unwrap()
    };
    let flags_after = |line: &str, doc: &Value| -> Vec<bool> {
        let w = writes(line, doc).unwrap_or_else(|| panic!("rejected: {line}"));
        let BgpAuth::Ao { keys } = serde_json::from_value(w[0][1].clone()).unwrap() else {
            panic!("not ao: {w}")
        };
        keys.iter().map(|k| k.exclude_options).collect()
    };
    let pg = "bgp instance r1 peer-group PG1";
    assert_eq!(
        flags_after(
            &format!("set {pg} ao-key 2 exclude-options"),
            &with_keys(false)
        ),
        [false, true]
    );
    assert_eq!(
        flags_after(
            &format!("delete {pg} ao-key 2 exclude-options"),
            &with_keys(true)
        ),
        [false, false]
    );
    assert_eq!(
        writes(
            &format!("set {pg} ao-key 9 exclude-options"),
            &with_keys(false)
        ),
        None
    );
}

/// #79: per-family maximum-prefix, set and deleted from inside a peer-group.
#[test]
fn maximum_prefix_per_family() {
    let doc = serde_json::to_value(populated()).unwrap();
    let at: Vec<String> = ["bgp-instance", "R1", "peer-group", "PG1"]
        .map(String::from)
        .to_vec();
    let path = |af: &str| {
        serde_json::json!([
            "bgp-instance",
            "R1",
            "peer-group",
            "PG1",
            "maximum-prefix",
            af
        ])
    };
    let w =
        |line: &str| config_grammar::parse(line, &at, &doc).map(|e| serde_json::json!(e.writes));
    assert_eq!(
        w("set maximum-prefix ipv4 limit 2 warning-only restart-interval 5"),
        Some(serde_json::json!([[
            path("ipv4"),
            {"limit": 2, "warning_only": true, "restart_interval": 5}
        ]]))
    );
    assert_eq!(
        w("set maximum-prefix l2vpn-evpn limit 9"),
        Some(serde_json::json!([[
            path("l2vpn-evpn"),
            {"limit": 9, "warning_only": false, "restart_interval": 0}
        ]]))
    );
    assert_eq!(
        w("delete maximum-prefix ipv6"),
        Some(serde_json::json!([[path("ipv6"), null]]))
    );
}

/// #15: an RFC 5065 confederation, built and torn down from the root.
#[test]
fn confederation_identifier_and_peers() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    let run = |line: &str, doc: &mut Value| {
        let edit = config_grammar::parse(line, &[], doc).unwrap_or_else(|| panic!("{line}"));
        for (path, value) in edit.writes {
            config_path::set(doc, &path, value).unwrap();
        }
    };
    for line in [
        "set bgp instance R1 confederation identifier 65100",
        "set bgp instance R1 confederation peer 65102",
        "set bgp instance R1 confederation peer 65103",
        "delete bgp instance R1 confederation peer 65103",
    ] {
        run(line, &mut doc);
    }
    let cfg: Config = serde_json::from_value(doc.clone()).unwrap();
    assert_eq!(
        cfg.bgp_instances[0].confederation,
        BgpConfederation {
            identifier: Some(65100),
            peers: vec![65102],
        }
    );
    run("delete bgp instance R1 confederation peer 65102", &mut doc);
    run("delete bgp instance R1 confederation identifier", &mut doc);
    let cfg: Config = serde_json::from_value(doc).unwrap();
    assert_eq!(
        cfg.bgp_instances[0].confederation,
        BgpConfederation::default()
    );
}

/// #12: graceful restart is on by default; `disable` and each timer are set
/// and deleted on their own.
#[test]
fn graceful_restart_disable_and_timers() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    let run = |line: &str, doc: &mut Value| {
        let edit = config_grammar::parse(line, &[], doc).unwrap_or_else(|| panic!("{line}"));
        for (path, value) in edit.writes {
            config_path::set(doc, &path, value).unwrap();
        }
    };
    run("set bgp instance R1 graceful-restart disable", &mut doc);
    run(
        "set bgp instance R1 graceful-restart restart-time 60",
        &mut doc,
    );
    let cfg: Config = serde_json::from_value(doc.clone()).unwrap();
    let gr = cfg.bgp_instances[0].graceful_restart;
    assert!(gr.disabled);
    assert_eq!(gr.restart_time, Some(60));
    run("delete bgp instance R1 graceful-restart disable", &mut doc);
    run(
        "delete bgp instance R1 graceful-restart restart-time",
        &mut doc,
    );
    let cfg: Config = serde_json::from_value(doc).unwrap();
    assert_eq!(
        cfg.bgp_instances[0].graceful_restart,
        nos_proto::BgpGracefulRestart::default()
    );
}

/// #17: RPKI caches, keyed by address, with a default port and preference.
#[test]
fn rpki_cache_list() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    let run = |line: &str, doc: &mut Value| {
        let edit = config_grammar::parse(line, &[], doc).unwrap_or_else(|| panic!("{line}"));
        for (path, value) in edit.writes {
            config_path::set(doc, &path, value).unwrap();
        }
    };
    for line in [
        "set bgp instance R1 rpki-cache 192.0.2.50 port 3323",
        "set bgp instance R1 rpki-cache 192.0.2.50 preference 1",
        "set bgp instance R1 rpki-cache 192.0.2.51",
        "delete bgp instance R1 rpki-cache 192.0.2.51",
    ] {
        run(line, &mut doc);
    }
    let cfg: Config = serde_json::from_value(doc).unwrap();
    assert_eq!(
        cfg.bgp_instances[0].rpki_caches,
        vec![nos_proto::RpkiCache {
            address: "192.0.2.50".parse().unwrap(),
            port: 3323,
            preference: 1,
            auth: None,
        }]
    );
}

/// #78: aggregates, keyed by prefix, with their two flags.
#[test]
fn aggregate_address_list() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    for line in [
        "set bgp instance R1 aggregate-address 198.51.0.0/16",
        "set bgp instance R1 aggregate-address 198.51.0.0/16 summary-only",
        "set bgp instance R1 aggregate-address 10.0.0.0/8 as-set",
        "delete bgp instance R1 aggregate-address 10.0.0.0/8",
    ] {
        let edit = config_grammar::parse(line, &[], &doc).unwrap_or_else(|| panic!("{line}"));
        for (path, value) in edit.writes {
            config_path::set(&mut doc, &path, value).unwrap();
        }
    }
    let cfg: Config = serde_json::from_value(doc).unwrap();
    assert_eq!(
        cfg.bgp_instances[0].aggregates,
        vec![nos_proto::BgpAggregate {
            prefix: "198.51.0.0/16".parse().unwrap(),
            as_set: false,
            summary_only: true,
        }]
    );
}

/// STP 1/7 (#317): the spanning-tree singleton, its MST instance list and the
/// port profile, driven through the same grammar as everything else.
#[test]
fn spanning_tree_and_port_profile() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    let run = |line: &str, doc: &mut Value| {
        let edit = config_grammar::parse(line, &[], doc).unwrap_or_else(|| panic!("{line}"));
        for (path, value) in edit.writes {
            config_path::set(doc, &path, value).unwrap();
        }
    };
    run("set spanning-tree mode rapid-pvst", &mut doc);
    run("set spanning-tree priority 4096", &mut doc);
    run("set spanning-tree region name lab", &mut doc);
    run("set spanning-tree mst-instance 5 priority 8192", &mut doc);
    run("set stp-port-profile edge edge-port admin", &mut doc);
    run("set stp-port-profile edge bpdu-guard", &mut doc);
    run(
        "set stp-port-profile edge mst-instance 5 cost 100",
        &mut doc,
    );
    let cfg: Config = serde_json::from_value(doc).unwrap();
    let st = &cfg.spanning_tree;
    assert_eq!(st.mode, nos_proto::schema::StpMode::RapidPvst);
    assert_eq!((st.priority, st.region.name.as_str()), (4096, "lab"));
    assert_eq!(
        (st.mst_instances[0].id, st.mst_instances[0].priority),
        (5, 8192)
    );
    let p = &cfg.stp_port_profiles[0];
    assert_eq!(p.edge_port, nos_proto::schema::EdgePort::Admin);
    assert!(p.bpdu_guard);
    assert_eq!(p.mst_instances[0].cost, Some(100));
}

/// #540: an ACL is built, ordered and attached through the same grammar, and
/// `show config` prints it back in the order it evaluates.
#[test]
fn acl_rules_order_and_attach() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    let run = |line: &str, doc: &mut Value| {
        let edit = config_grammar::parse(line, &[], doc).unwrap_or_else(|| panic!("{line}"));
        for (path, value) in edit.writes {
            config_path::set_at(doc, &path, value, edit.position.as_ref()).unwrap();
        }
    };
    run("set acl EDGE default-action permit", &mut doc);
    run("set acl EDGE rule r0 action deny", &mut doc);
    run("set acl EDGE rule r0 protocol 89", &mut doc);
    run("set acl EDGE rule r1 action permit", &mut doc);
    run("set acl EDGE rule r1 protocol tcp", &mut doc);
    run("set acl EDGE rule r1 destination-port 179", &mut doc);
    run("set acl EDGE rule r1 source-port 1024-65535", &mut doc);
    run("set acl EDGE rule r2 before r0", &mut doc);
    run("set acl EDGE rule r2 protocol icmp", &mut doc);
    run("set acl EDGE rule r2 icmp-type 8", &mut doc);
    run("set interface eth0 acl in EDGE", &mut doc);
    run("set interface eth0 acl out EDGE", &mut doc);
    let cfg: Config = serde_json::from_value(doc.clone()).unwrap();
    let acl = &cfg.acls[0];
    assert_eq!(acl.default_action, AclAction::Permit);
    let names: Vec<_> = acl.rules.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["r2", "r0", "r1"]);
    assert_eq!(acl.rules[1].protocol, Some(AclProtocol::Number(89)));
    assert_eq!(acl.rules[2].protocol, Some(AclProtocol::Tcp));
    let port = |start, end| Some(PortRange { start, end });
    assert_eq!(acl.rules[2].destination_port, port(179, 179));
    assert_eq!(acl.rules[2].source_port, port(1024, 65535));
    let eth0 = cfg.interfaces.iter().find(|i| i.name == "eth0").unwrap();
    assert_eq!(eth0.acl_in.as_deref(), Some("EDGE"));
    assert_eq!(eth0.acl_out.as_deref(), Some("EDGE"));

    let shown = nos_proto::cli::render::render_root(&doc)
        .into_iter()
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n");
    let pos = |n: &str| {
        shown
            .find(&format!("rule {n}"))
            .unwrap_or_else(|| panic!("{n}"))
    };
    assert!(pos("r2") < pos("r0") && pos("r0") < pos("r1"), "{shown}");
    assert!(shown.contains("protocol 89") && shown.contains("destination-port 179"));

    // The reference slots complete like every other one (`bfd`,
    // `stp-port-profile`): the words, not the referenced names.
    let words: Vec<&str> = "set interface eth0 acl".split_whitespace().collect();
    let offered: Vec<String> = config_grammar::complete(&words, &[], &doc)
        .into_iter()
        .map(|c| c.word)
        .collect();
    assert!(offered.contains(&"in".to_string()) && offered.contains(&"out".to_string()));
}

/// #562: `flowspec` is a bare flag on an interface, a subinterface and a port
/// aggregate, and `show config` prints it back.
#[test]
fn flowspec_flag() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    for line in [
        "set interface eth0 flowspec",
        "set interface eth0 subinterface 100 flowspec",
        "set port-aggregate agg0 flowspec",
    ] {
        let edit = config_grammar::parse(line, &[], &doc).unwrap_or_else(|| panic!("{line}"));
        for (path, value) in edit.writes {
            config_path::set_at(&mut doc, &path, value, edit.position.as_ref()).unwrap();
        }
    }
    let cfg: Config = serde_json::from_value(doc.clone()).unwrap();
    let eth0 = cfg.interfaces.iter().find(|i| i.name == "eth0").unwrap();
    assert!(eth0.flowspec);
    assert!(eth0
        .subinterfaces
        .iter()
        .any(|s| s.tag == 100 && s.flowspec));
    assert!(cfg
        .port_aggregates
        .iter()
        .any(|a| a.name == "agg0" && a.flowspec));
    let shown = nos_proto::cli::render::render_root(&doc)
        .into_iter()
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(shown.contains("flowspec"), "{shown}");
}

/// #842: a subinterface's MTU override is set like any field.
#[test]
fn subinterface_mtu() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    let edit = config_grammar::parse("set interface eth0 subinterface 100 mtu 9000", &[], &doc)
        .expect("set mtu");
    for (path, value) in edit.writes {
        config_path::set_at(&mut doc, &path, value, edit.position.as_ref()).unwrap();
    }
    let cfg: Config = serde_json::from_value(doc.clone()).unwrap();
    let eth0 = cfg.interfaces.iter().find(|i| i.name == "eth0").unwrap();
    assert!(eth0
        .subinterfaces
        .iter()
        .any(|s| s.tag == 100 && s.mtu == Some(9000)));
    let shown = nos_proto::cli::render::render_root(&doc)
        .into_iter()
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(shown.contains("mtu 9000"), "{shown}");
}

/// #878: BMP stations, keyed by name; the port has no default.
#[test]
fn bmp_station_list() {
    let mut doc = serde_json::to_value(populated()).unwrap();
    for line in [
        "set bgp instance R1 bmp-station s1 address 192.0.2.60",
        "set bgp instance R1 bmp-station s1 port 5000",
        "set bgp instance R1 bmp-station s1 monitor pre-policy",
        "set bgp instance R1 bmp-station s1 statistics-interval 30",
        "set bgp instance R1 bmp-station s1 monitor-out both",
        "set bgp instance R1 bmp-station s2 address 192.0.2.61",
        "delete bgp instance R1 bmp-station s2",
    ] {
        let edit = config_grammar::parse(line, &[], &doc).unwrap_or_else(|| panic!("{line}"));
        for (path, value) in edit.writes {
            config_path::set(&mut doc, &path, value).unwrap();
        }
    }
    let cfg: Config = serde_json::from_value(doc).unwrap();
    assert_eq!(
        cfg.bgp_instances[0].bmp_stations,
        vec![nos_proto::BmpStation {
            name: "s1".into(),
            address: "192.0.2.60".parse().unwrap(),
            port: 5000,
            monitor: nos_proto::BmpMonitor::PrePolicy,
            statistics_interval: Some(30),
            monitor_out: nos_proto::BmpMonitorOut::Both,
        }]
    );
}

#[test]
fn lacp_v2_knobs_and_conversation_map() {
    let mut doc = serde_json::to_value(Config {
        port_aggregates: vec![PortAggregate {
            name: "bond1".into(),
            ..Default::default()
        }],
        interfaces: vec![Interface {
            name: "eth1".into(),
            ..Default::default()
        }],
        ..Default::default()
    })
    .unwrap();
    for line in [
        "set port-aggregate bond1 lacp-version 1",
        "set port-aggregate bond1 lacp-port-algorithm c-vlan",
        "set port-aggregate bond1 lacp-conversation-map 0 last 99",
        "set port-aggregate bond1 lacp-conversation-map 0 member eth1",
        "set port-aggregate bond1 lacp-conversation-map 100 last 200",
        "delete port-aggregate bond1 lacp-conversation-map 100",
        "set interface eth1 lacp-link-number 4",
    ] {
        let edit = config_grammar::parse(line, &[], &doc).unwrap_or_else(|| panic!("{line}"));
        for (path, value) in edit.writes {
            config_path::set(&mut doc, &path, value).unwrap();
        }
    }
    let cfg: Config = serde_json::from_value(doc).unwrap();
    let a = &cfg.port_aggregates[0];
    assert_eq!(a.lacp_version, LacpVersion::V1);
    assert_eq!(a.lacp_port_algorithm, LacpPortAlgorithm::CVlan);
    assert_eq!(
        a.lacp_conversation_map,
        vec![ConversationRange {
            first: 0,
            last: 99,
            member: "eth1".into()
        }]
    );
    assert_eq!(cfg.interfaces[0].lacp_link_number, Some(4));
}
