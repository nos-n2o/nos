//! Drives `nos_cli::actions::handle_action` — every shell action — against
//! fake daemons over real TLS sockets (#131): a stateful fake `nos-configd`,
//! a fake broker, and one canned fake per queried daemon.

#![allow(
    unsafe_code,
    reason = "edition 2024: set_var is unsafe; tests set EDITOR/PATH on purpose"
)]
#![allow(clippy::excessive_nesting, clippy::match_wildcard_for_single_variants)]

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::{commit, discard, leave_open, run, serve, serve_with, snapshot, Lab};
use nos_cli::actions;
use nos_cli::session::{self, Mode};
use nos_pki::testing::shared;
use nos_proto::{
    BfdEvent, BfdRequest, BgpEvent, BgpRequest, CommandDoc, ConfigDiff, Event, FdbEvent,
    FdbRequest, InterfaceEvent, InterfaceRequest, LacpEvent, LacpRequest, LldpEvent, LldpRequest,
    LogEvent, LogRequest, OspfEvent, OspfRequest, Ospfv3Event, Ospfv3Request, Request, RibEvent,
    RibRequest, ServiceRef, StpEvent, StpRequest, StpSummary, Topic, WatchdogEvent,
    WatchdogRequest,
};

/// A `nos-configd` that keeps one in-progress config and applies edits to it.
fn fake_configd(path: &Path) {
    let running = common::base_running();
    let txn = Arc::new(Mutex::new(running.clone()));
    serve("configd", "", path, move |req: Request| {
        let mut cfg = txn.lock().unwrap();
        vec![match req {
            Request::Get | Request::Subscribe => Event::Config(running.clone()),
            Request::Save => Event::Saved,
            Request::OpenTransaction { name, .. } | Request::GetTransaction { name } => {
                Event::Transaction(snapshot(&name, &cfg))
            }
            Request::ApplyOp { name, op, .. } => match op.apply(&mut cfg) {
                Ok(()) => Event::Transaction(snapshot(&name, &cfg)),
                Err(e) => Event::Error(e.to_string()),
            },
            Request::EditTransactionPath {
                path,
                value,
                position,
                ..
            } => {
                let mut doc = serde_json::to_value(&*cfg).unwrap();
                let done = match value {
                    Some(v) => nos_proto::config_path::set_at(
                        &mut doc,
                        &path,
                        serde_json::from_str(&v).unwrap(),
                        position.as_ref(),
                    ),
                    None => nos_proto::config_path::remove(&mut doc, &path),
                };
                match done
                    .map_err(|e| e.to_string())
                    .and_then(|()| serde_json::from_value(doc).map_err(|e| e.to_string()))
                {
                    Ok(new) => {
                        *cfg = new;
                        Event::TransactionEdit {
                            generation: 1,
                            dirty: true,
                            value: None,
                        }
                    }
                    Err(e) => Event::Error(e),
                }
            }
            Request::CommitTransaction { name, .. } if name == "refused" => {
                Event::Error("invalid".to_string())
            }
            Request::CommitTransaction { .. } => Event::Committed { warnings: vec![] },
            Request::DiscardTransaction { .. } => Event::Discarded,
            Request::DiffTransaction { name } if name == "unchanged" => {
                Event::Diff(ConfigDiff::default())
            }
            Request::DiffTransaction { .. } => Event::Diff(nos_proto::diff_configs(&running, &cfg)),
            Request::Describe { topic } => Event::Description(CommandDoc {
                topic,
                summary: format!("{topic:?} summary"),
                detail: String::new(),
            }),
            other => Event::Error(format!("unexpected {other:?}")),
        }]
    });
}

fn lab() -> Lab {
    shared().install("user", "admin");
    let dir = tempfile::tempdir().unwrap();
    let sock = |n: &str| dir.path().join(format!("{n}.sock"));
    let config = sock("config");
    fake_configd(&config);

    let mut endpoints: HashMap<String, PathBuf> = HashMap::new();
    for (service, role, name) in [
        ("rib", "ribd", "rt1"),
        ("fdb", "fdbd", "bd1"),
        ("interfaces", "interfaced", ""),
        ("lacp", "lacpd", ""),
        ("lldp", "lldpd", ""),
        ("stp", "stpd", ""),
        ("bfd", "bfdd", ""),
        ("log", "logd", ""),
        ("bgp", "bgpd", "b1"),
        ("ospf", "ospfd", "o1"),
        ("ospfv3", "ospfv3d", "v3"),
    ] {
        let path = sock(service);
        endpoints.insert(service.to_string(), path.clone());
        match service {
            "rib" => serve(role, name, &path, |r: RibRequest| {
                vec![match r {
                    RibRequest::Lookup { .. } => RibEvent::NoMatch,
                    _ => RibEvent::RoutesPage {
                        routes: Vec::new(),
                        next: None,
                    },
                }]
            }),
            "fdb" => serve(role, name, &path, |_: FdbRequest| {
                vec![FdbEvent::Table(nos_proto::FdbTable {
                    domain: "bd1".to_string(),
                    vni: 1,
                    bridge: None,
                    vxlan: None,
                    macs: Vec::new(),
                    neighbours: Vec::new(),
                    flood: Vec::new(),
                    segments: Vec::new(),
                    neigh_suppress: false,
                })]
            }),
            "interfaces" => serve(role, name, &path, |r: InterfaceRequest| {
                vec![match r {
                    InterfaceRequest::GetInterfaces => InterfaceEvent::Interfaces(Vec::new()),
                    InterfaceRequest::GetPortAggregates => {
                        InterfaceEvent::PortAggregates(Vec::new())
                    }
                    _ => InterfaceEvent::NotFound,
                }]
            }),
            "lacp" => serve(role, name, &path, |_: LacpRequest| {
                vec![LacpEvent::Summary(Vec::new())]
            }),
            "lldp" => serve(role, name, &path, |_: LldpRequest| {
                vec![LldpEvent::Neighbors(Vec::new())]
            }),
            "stp" => serve(role, name, &path, |_: StpRequest| {
                vec![StpEvent::Summary(StpSummary::default())]
            }),
            "bfd" => serve(role, name, &path, |_: BfdRequest| {
                vec![BfdEvent::Sessions(Vec::new())]
            }),
            // A tail replies once, then the fake closes the stream.
            "log" => serve_with(role, name, &path, true, |_: LogRequest| {
                vec![LogEvent::Logs(Vec::new())]
            }),
            "bgp" => serve(role, name, &path, |r: BgpRequest| {
                vec![match r {
                    BgpRequest::GetEvpnRoutesPage { .. } => BgpEvent::EvpnRoutesPage {
                        routes: Vec::new(),
                        next: None,
                    },
                    BgpRequest::GetFlowspecRoutesPage { .. } => BgpEvent::FlowspecRoutesPage {
                        routes: Vec::new(),
                        next: None,
                    },
                    BgpRequest::GetVpnRoutesPage { .. } => BgpEvent::VpnRoutesPage {
                        routes: Vec::new(),
                        next: None,
                    },
                    BgpRequest::GetRpkiSummary => BgpEvent::RpkiSummary(Vec::new()),
                    BgpRequest::ShowBmp { .. } => BgpEvent::BmpStatus(Vec::new()),
                    BgpRequest::GetRoutesPage { .. } => BgpEvent::RoutesPage {
                        routes: Vec::new(),
                        next: None,
                    },
                    // 192.0.2.9 is a peer-group keeping its received routes.
                    BgpRequest::SendRouteRefresh { peer } if peer.to_string() == "192.0.2.9" => {
                        BgpEvent::SoftInReevaluated {
                            families: vec![nos_proto::FamilyReeval {
                                family: nos_proto::ReevalFamily::Ipv4Unicast,
                                retained: 2,
                                accepted: 1,
                            }],
                        }
                    }
                    BgpRequest::SendRouteRefresh { .. } => BgpEvent::RouteRefreshSent,
                    BgpRequest::ClearPeer { .. } => BgpEvent::PeerCleared,
                    _ => BgpEvent::Summary(Vec::new()),
                }]
            }),
            "ospf" => serve(role, name, &path, |r: OspfRequest| {
                vec![match r {
                    OspfRequest::GetDatabase => OspfEvent::Database(Vec::new()),
                    _ => OspfEvent::Neighbors(Vec::new()),
                }]
            }),
            _ => serve(role, name, &path, |r: Ospfv3Request| {
                vec![match r {
                    Ospfv3Request::GetDatabase => Ospfv3Event::Database(Vec::new()),
                    _ => Ospfv3Event::Neighbors(Vec::new()),
                }]
            }),
        }
    }
    let config_path = config.clone();
    serve(
        "watchdog",
        "",
        &sock("watchdog"),
        move |r: WatchdogRequest| {
            let WatchdogRequest::ResolveEndpoint { service } = r else {
                return vec![WatchdogEvent::NotAvailable];
            };
            let key = match service {
                ServiceRef::Config => return vec![WatchdogEvent::Endpoint(config_path.clone())],
                ServiceRef::RibTable(t) if t == "rt1" => "rib",
                ServiceRef::FdbDomain(_) => "fdb",
                ServiceRef::Interfaces => "interfaces",
                ServiceRef::Lacp => "lacp",
                ServiceRef::Lldp => "lldp",
                ServiceRef::Stp => "stp",
                ServiceRef::Bfd => "bfd",
                ServiceRef::Log => "log",
                ServiceRef::BgpInstance(_) => "bgp",
                ServiceRef::OspfInstance(_) => "ospf",
                ServiceRef::Ospfv3Instance(_) => "ospfv3",
                _ => return vec![WatchdogEvent::NotAvailable],
            };
            vec![WatchdogEvent::Endpoint(endpoints[key].clone())]
        },
    );
    Lab {
        config,
        watchdog: sock("watchdog"),
        docs: Arc::new(Mutex::new(HashMap::new())),
        _dir: dir,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_show_command_runs_against_its_daemon() {
    let lab = lab();
    let (mode, exited) = run(
        &lab,
        Mode::Operational,
        &[
            "help",
            "show config",
            "show config admin",
            "show route rt1",
            "show route rt1 10.0.0.1",
            "show route gone",
            "show fdb bd1",
            "show interface",
            "show interface eth9",
            "show port-aggregate",
            "show port-aggregate bond9",
            "show lacp",
            "show lacp bond9",
            "show lldp neighbors",
            "show spanning-tree",
            "show spanning-tree detail",
            "show spanning-tree instance 1 detail",
            "show spanning-tree domain bd1 detail",
            "show bfd sessions",
            "show bfd sessions 192.0.2.1",
            "show log",
            "show log configd --follow",
            "show bgp brief",
            "show bgp evpn",
            "show bgp flowspec",
            "show bgp flowspec",
            "show bgp rpki",
            "show bgp bmp",
            "show bgp vpnv4",
            "show bgp vpnv6 rd 65001:1",
            "show ospf neigh",
            "show ospf database",
            "show ospfv3 neigh",
            "show ospfv3 database",
            "clear bgp b1 192.0.2.2 soft-in",
            "clear bgp b1 192.0.2.9 soft-in",
            "clear bgp nope 192.0.2.2 soft-in",
            "clear bgp b1 192.0.2.2",
            "save",
            "not a command",
        ],
        leave_open,
    )
    .await;
    assert_eq!(mode, Mode::Operational);
    assert!(!exited);
    // Docs are fetched lazily and cached once.
    assert!(!lab.docs.lock().unwrap().is_empty());
    let (_, exited) = run(&lab, Mode::Operational, &["exit"], leave_open).await;
    assert!(exited);

    assert_eq!(
        actions::resolve_config_socket(&lab.watchdog).await,
        lab.config
    );
    let missing = lab.config.with_file_name("none.sock");
    assert_eq!(
        actions::resolve_config_socket(&missing).await,
        PathBuf::from(nos_proto::DEFAULT_CONFIG_SOCKET)
    );
    let doc = actions::doc_for_blocking(&lab.config, &lab.docs, Topic::Save);
    assert!(doc.summary.contains("summary"));

    // The prompt's hostname follows the running config.
    let hostname = Arc::new(Mutex::new("nos".to_string()));
    let repainted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&repainted);
    let task = tokio::spawn(actions::subscribe_hostname_task(
        lab.config.clone(),
        Arc::clone(&hostname),
        move || flag.store(true, std::sync::atomic::Ordering::Relaxed),
    ));
    for _ in 0..100 {
        if *hostname.lock().unwrap() == "r1" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    task.abort();
    assert_eq!(*hostname.lock().unwrap(), "r1");
    assert!(repainted.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configuration_session_edits_commits_and_leaves() {
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::set_var("EDITOR", "true") };
    let lab = lab();
    let (mode, _) = run(
        &lab,
        Mode::Operational,
        &[
            "configure t1",
            "help",
            "edit bgp instance b1",
            "set asn 65001",
            "show this",
            "diff",
            "up",
            "edit policy-definition p1",
            "set source line 1 accept",
            "set source line 9 reject",
            "set source line 0 reject",
            "show source",
            "edit source",
            "set source line 2 bogus-statement",
            "delete source line 2",
            "delete source line 9",
            "top",
            "set not-a-field 1",
            "commit",
        ],
        leave_open,
    )
    .await;
    assert_eq!(mode, Mode::Operational, "commit returns to operational");

    // A refused commit leaves the transaction open.
    let (mode, _) = run(
        &lab,
        Mode::Operational,
        &["configure refused", "commit"],
        leave_open,
    )
    .await;
    assert!(
        matches!(mode, Mode::Configuration { ref transaction, .. } if transaction == "refused")
    );

    // exit with uncommitted changes asks what to do.
    for ask in [discard, commit, leave_open] {
        let (mode, _) = run(
            &lab,
            Mode::Operational,
            &["configure t2", "set hostname other", "exit"],
            ask,
        )
        .await;
        assert_eq!(mode, Mode::Operational);
    }
    let (mode, _) = run(
        &lab,
        Mode::Operational,
        &["configure unchanged from blank", "diff", "discard"],
        leave_open,
    )
    .await;
    assert_eq!(mode, Mode::Operational);
    let (mode, _) = run(
        &lab,
        Mode::Operational,
        &["configure resumed from current", "abort"],
        leave_open,
    )
    .await;
    assert_eq!(mode, Mode::Operational);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_with_a_position_and_move_reorder_a_list() {
    let lab = lab();
    let (mode, _) = run(
        &lab,
        Mode::Operational,
        &[
            "configure tpos",
            "set bgp instance b1 peer-group a",
            "set bgp instance b1 peer-group b",
            "set bgp instance b1 peer-group c",
            "move bgp instance b1 peer-group c first",
            "set bgp instance b1 peer-group a after b",
            "move bgp instance b1 peer-group nope last",
            "set bgp instance b1 peer-group b before zz",
        ],
        leave_open,
    )
    .await;
    assert!(matches!(mode, Mode::Configuration { .. }));
    let snap = nos_cli::client::get_transaction(&lab.config, "tpos")
        .await
        .unwrap();
    let names: Vec<_> = snap.config.bgp_instances[0]
        .peer_groups
        .iter()
        .map(|g| g.name.as_str())
        .collect();
    assert_eq!(names, ["c", "b", "a"]);
}

#[test]
fn navigation_keeps_transaction_and_dirtiness() {
    let deep = Mode::Configuration {
        transaction: "t1".to_string(),
        path: session::Path::from(vec!["bgp-instance".to_string(), "i".to_string()]),
        dirty: true,
    };
    assert_eq!(actions::current_transaction(&deep), "t1");
    assert_eq!(
        actions::current_path(&deep).segments(),
        ["bgp-instance", "i"]
    );
    let top = actions::navigate_top(&deep);
    assert!(matches!(top, Mode::Configuration { ref path, dirty: true, .. } if path.is_root()));
    let doc = actions::unavailable_doc(Topic::Save);
    assert!(doc.summary.contains("could not reach nos-configd"));
}
