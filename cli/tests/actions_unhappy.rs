//! The arms `actions.rs` never reaches (#345): a watchdog that has nothing
//! to resolve, daemons that fail or answer with data, a `nos-configd` that
//! errors, the policy/editor paths against a populated running config.
//!
//! Asserts on the `Mode` each action returns and, where an edit lands, on
//! the transaction as `nos-configd` holds it; what is printed is proven
//! reachable by coverage, not captured (#345, decision 1). This is a test
//! binary of its own because `EDITOR` is process-global.

#![allow(
    unsafe_code,
    reason = "edition 2024: set_var is unsafe; tests set EDITOR/PATH on purpose"
)]
#![allow(clippy::excessive_nesting, clippy::match_wildcard_for_single_variants)]

mod common;

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::{base_running, commit, discard, leave_open, run, serve, serve_with, snapshot, Lab};
use nos_cli::actions::{self, LeaveChoice};
use nos_cli::session::{self, Mode};
use nos_pki::testing::shared;
use nos_proto::{
    BfdEvent, BfdRequest, BgpEvent, BgpRequest, CommandDoc, Config, ConfigDiff, Event, FdbRequest,
    InterfaceEvent, InterfaceRequest, InterfaceStatus, LacpEvent, LacpRequest, LldpEvent,
    LldpRequest, LogEntry, LogEvent, LogLevel, LogRequest, OspfEvent, OspfRequest, Ospfv3Event,
    Ospfv3Request, PrefixRoutes, Request, RibEvent, RibRequest, ServiceRef, StpEvent, StpRequest,
    StpSummary, WatchdogEvent, WatchdogRequest,
};

/// What the fake watchdog does with `ResolveEndpoint`.
#[derive(Clone, Copy, PartialEq)]
enum Wd {
    /// Every service resolves to its fake daemon.
    Resolves,
    /// Every service but `Config` is `NotAvailable`.
    NotAvailable,
    /// Every service resolves to a socket nobody listens on.
    Dangling,
    /// The watchdog socket itself does not exist.
    Dead,
}

/// What each fake daemon does with its request.
#[derive(Clone, Copy, PartialEq)]
enum Daemons {
    /// Closes the connection after reading the request.
    Closed,
    /// Answers with data: a hit, a found interface, ports, a known peer.
    Populated,
}

fn prefix_routes() -> PrefixRoutes {
    PrefixRoutes {
        prefix: "10.0.0.0/24".parse().unwrap(),
        candidates: vec![nos_proto::RouteEntry {
            gateways: vec!["10.0.0.1".parse().unwrap()],
            source: nos_proto::RouteSourceKind::Static,
            backup: None,
            discard: false,
            evpn: None,
            backup_tunnel: false,
            mpls_labels: vec![],
            vpn: vec![],
            blackhole: false,
        }],
    }
}

fn interface_status() -> InterfaceStatus {
    InterfaceStatus {
        link_local_address: None,
        name: "eth0".to_string(),
        addresses: Vec::new(),
        routing_table: None,
        switching_profile: None,
        port_aggregate: None,
        mtu: 1500,
        subinterfaces: Vec::new(),
        err_disabled: false,
    }
}

fn lacp_summary(name: &str) -> nos_proto::PortAggregateLacpSummary {
    nos_proto::PortAggregateLacpSummary {
        aggregate: name.to_string(),
        actor_system_id: [2, 0, 0, 0, 0, 1],
        actor_key: 1,
        actor_system_priority: 32768,
        rate: nos_proto::LacpRate::Fast,
        min_links: 1,
        min_links_met: true,
        ports: Vec::new(),
        version: nos_proto::LacpVersion::V1,
        port_algorithm: nos_proto::LacpPortAlgorithm::Unspecified,
        agreement: nos_proto::LacpAgreement::NotApplicable,
        conversations_per_link: Vec::new(),
    }
}

fn log_entry() -> LogEntry {
    LogEntry {
        timestamp_ms: 1,
        level: LogLevel::Info,
        source: "nos-configd".to_string(),
        target: "t".to_string(),
        message: "hello".to_string(),
        fields: Vec::new(),
    }
}

/// What the fake `nos-configd` is like.
#[derive(Clone, Copy, PartialEq)]
enum Configd {
    /// The base config plus one of every policy object.
    Healthy,
    /// Fails every request.
    Broken,
    /// Answers, but has no protocol instance and no policy at all.
    Bare,
}

/// A `nos-configd` keeping one in-progress config. A transaction named
/// `missing` fails every request, `noapply` fails only edits, `flaky` fails
/// every second `GetTransaction` (so a fetch works and the next one fails).
fn fake_configd(path: &Path, kind: Configd) {
    let broken = kind == Configd::Broken;
    let mut doc = serde_json::to_value(base_running()).unwrap();
    doc["community_aliases"] = serde_json::json!([{"name": "CUST", "value": "65000:100"}]);
    doc["community_groups"] =
        serde_json::json!([{"name": "GROUP", "members": ["CUST", "65000:1"]}]);
    doc["prefix_lists"] = serde_json::json!([{"name": "BLOCKS", "entries": [
        {"cidr": "10.0.0.0/8", "range": [24, 32]},
        {"cidr": "192.0.2.0/24", "range": null}]}]);
    doc["as_path_lists"] = serde_json::json!([{"name": "TRANSIT", "patterns": ["^65001$"]}]);
    doc["policy_definitions"] = serde_json::json!([{"name": "p1", "source": "reject\n"}]);
    let mut running: Config = serde_json::from_value(doc).unwrap();
    if kind == Configd::Bare {
        running = Config {
            hostname: "r1".to_string(),
            ..Config::default()
        };
    }
    let gets = std::sync::atomic::AtomicUsize::new(0);
    let txn = Arc::new(Mutex::new(running.clone()));
    serve("configd", "", path, move |req: Request| {
        let mut cfg = txn.lock().unwrap();
        let named = |n: &str| broken || n == "missing";
        vec![match req {
            _ if broken && !matches!(req, Request::Describe { .. }) => {
                Event::Error("configd is down".to_string())
            }
            Request::Describe { topic } if broken => {
                let _ = topic;
                Event::Error("configd is down".to_string())
            }
            Request::Get | Request::Subscribe => Event::Config(running.clone()),
            Request::Save => Event::Saved,
            Request::OpenTransaction { name, .. } if name == "unopenable" => {
                Event::Error("cannot open".to_string())
            }
            Request::GetTransaction { name }
                if name == "flaky"
                    && gets.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 2 == 1 =>
            {
                Event::Error("flaked".to_string())
            }
            Request::OpenTransaction { name, .. } | Request::GetTransaction { name }
                if named(&name) =>
            {
                Event::Error(format!("no transaction '{name}'"))
            }
            Request::OpenTransaction { name, .. } | Request::GetTransaction { name } => {
                Event::Transaction(snapshot(&name, &cfg))
            }
            Request::ApplyOp { name, .. } if named(&name) || name == "noapply" => {
                Event::Error("no".to_string())
            }
            Request::ApplyOp { name, op, .. } => match op.apply(&mut cfg) {
                Ok(()) => Event::Transaction(snapshot(&name, &cfg)),
                Err(e) => Event::Error(e.to_string()),
            },
            Request::EditTransactionPath { name, .. } if named(&name) => {
                Event::Error("no".to_string())
            }
            Request::EditTransactionPath { path, value, .. } => {
                if value.as_deref().is_some_and(|v| v.contains("FAIL")) {
                    Event::Error("refused by the fake".to_string())
                } else {
                    let mut doc = serde_json::to_value(&*cfg).unwrap();
                    let done = match value {
                        Some(v) => nos_proto::config_path::set(
                            &mut doc,
                            &path,
                            serde_json::from_str(&v).unwrap(),
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
            }
            Request::CommitTransaction { name, .. } if named(&name) || name == "refused" => {
                Event::Error("invalid".to_string())
            }
            Request::CommitTransaction { .. } => Event::Committed { warnings: vec![] },
            Request::DiscardTransaction { name, .. } if named(&name) => {
                Event::Error("no".to_string())
            }
            Request::DiscardTransaction { .. } => Event::Discarded,
            Request::DiffTransaction { name } if named(&name) => Event::Error("no".to_string()),
            Request::DiffTransaction { .. } => Event::Diff(ConfigDiff::default()),
            Request::Describe { topic } => Event::Description(CommandDoc {
                topic,
                summary: format!("{topic:?} summary"),
                detail: String::new(),
            }),
            other => Event::Error(format!("unexpected {other:?}")),
        }]
    });
}

/// A lab whose watchdog, daemons and `nos-configd` behave as asked.
#[allow(
    clippy::too_many_lines,
    reason = "fixture builder: one linear block per fake daemon"
)]
fn world(wd: Wd, daemons: Daemons, configd: Configd) -> Lab {
    shared().install("user", "admin");
    let dir = tempfile::tempdir().unwrap();
    let sock = |n: &str| dir.path().join(format!("{n}.sock"));
    let config = sock("config");
    fake_configd(&config, configd);

    let closed = daemons == Daemons::Closed;
    let mut endpoints: HashMap<&'static str, PathBuf> = HashMap::new();
    if wd == Wd::Resolves {
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
            endpoints.insert(service, path.clone());
            match service {
                "rib" if closed => serve_with(role, name, &path, true, |_: RibRequest| {
                    Vec::<RibEvent>::new()
                }),
                "rib" => serve(role, name, &path, |r: RibRequest| {
                    vec![match r {
                        RibRequest::Lookup { .. } => RibEvent::Match(prefix_routes()),
                        _ => RibEvent::RoutesPage {
                            routes: vec![prefix_routes()],
                            next: None,
                        },
                    }]
                }),
                "fdb" => serve_with(role, name, &path, true, |_: FdbRequest| {
                    Vec::<nos_proto::FdbEvent>::new()
                }),
                "interfaces" if closed => {
                    serve_with(role, name, &path, true, |_: InterfaceRequest| {
                        Vec::<InterfaceEvent>::new()
                    });
                }
                "interfaces" => serve(role, name, &path, |r: InterfaceRequest| {
                    vec![match r {
                        InterfaceRequest::GetInterfaces => {
                            InterfaceEvent::Interfaces(vec![interface_status()])
                        }
                        InterfaceRequest::GetInterface { name } if name == "eth0" => {
                            InterfaceEvent::Interface(interface_status())
                        }
                        InterfaceRequest::GetPortAggregates => {
                            InterfaceEvent::PortAggregates(Vec::new())
                        }
                        InterfaceRequest::GetPortAggregate { name } if name == "bond0" => {
                            InterfaceEvent::PortAggregate(nos_proto::PortAggregateStatus {
                                name: "bond0".to_string(),
                                mode: nos_proto::PortAggregateMode::Xor,
                                switching_profile: None,
                                mtu: 1500,
                                subinterfaces: Vec::new(),
                                link_local_address: None,
                                bond_name: None,
                                err_disabled: false,
                            })
                        }
                        _ => InterfaceEvent::NotFound,
                    }]
                }),
                "lacp" if closed => serve_with(role, name, &path, true, |_: LacpRequest| {
                    Vec::<LacpEvent>::new()
                }),
                "lacp" => serve(role, name, &path, |_: LacpRequest| {
                    vec![LacpEvent::Summary(vec![lacp_summary("bond0")])]
                }),
                "lldp" if closed => serve_with(role, name, &path, true, |_: LldpRequest| {
                    Vec::<LldpEvent>::new()
                }),
                "lldp" => serve(role, name, &path, |r: LldpRequest| {
                    vec![match r {
                        LldpRequest::GetNeighbors => LldpEvent::Neighbors(Vec::new()),
                        LldpRequest::GetStatistics => LldpEvent::Statistics(Vec::new()),
                    }]
                }),
                "stp" if closed => serve_with(role, name, &path, true, |_: StpRequest| {
                    Vec::<StpEvent>::new()
                }),
                "stp" => serve(role, name, &path, |r: StpRequest| {
                    vec![match r {
                        StpRequest::Mcheck { interface } => StpEvent::Mcheck {
                            ports: if interface.as_deref() == Some("none") {
                                0
                            } else {
                                2
                            },
                        },
                        StpRequest::ClearErrDisabled { interface } => {
                            StpEvent::ErrDisabledCleared {
                                cleared: interface == "eth0",
                            }
                        }
                        _ => StpEvent::Summary(StpSummary::default()),
                    }]
                }),
                "bfd" if closed => serve_with(role, name, &path, true, |_: BfdRequest| {
                    Vec::<BfdEvent>::new()
                }),
                "bfd" => serve(role, name, &path, |r: BfdRequest| {
                    vec![match r {
                        BfdRequest::GetReflector => BfdEvent::Reflector(nos_proto::ReflectorView {
                            discriminators: vec![1],
                            received: 0,
                            replied: 0,
                            discarded: nos_proto::ReflectorDiscards::default(),
                        }),
                        _ => BfdEvent::Sessions(Vec::new()),
                    }]
                }),
                "log" if closed => serve_with(role, name, &path, true, |_: LogRequest| {
                    Vec::<LogEvent>::new()
                }),
                // The tail's source picks the stream: an error, one line, or none.
                "log" => serve_with(role, name, &path, true, |r: LogRequest| match r {
                    LogRequest::Tail { source } => match source.as_deref() {
                        Some("boom") => vec![LogEvent::Error("boom".to_string())],
                        Some("line") => vec![
                            LogEvent::Logs(vec![log_entry()]),
                            LogEvent::Line(log_entry()),
                        ],
                        _ => Vec::new(),
                    },
                    _ => vec![LogEvent::Logs(vec![log_entry()])],
                }),
                "bgp" if closed => serve_with(role, name, &path, true, |_: BgpRequest| {
                    Vec::<BgpEvent>::new()
                }),
                "bgp" => serve(role, name, &path, |r: BgpRequest| {
                    let known =
                        |p: std::net::IpAddr| p == "192.0.2.2".parse::<std::net::IpAddr>().unwrap();
                    vec![match r {
                        BgpRequest::SendRouteRefresh { peer } if known(peer) => {
                            BgpEvent::RouteRefreshSent
                        }
                        BgpRequest::ClearPeer { peer } if known(peer) => BgpEvent::PeerCleared,
                        BgpRequest::SendRouteRefresh { .. } | BgpRequest::ClearPeer { .. } => {
                            BgpEvent::PeerNotFound
                        }
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
                            routes: vec![nos_proto::BgpRouteSummary {
                                prefix: "192.0.2.0/24".into(),
                                peer: None,
                                next_hop: None,
                                as_path: String::new(),
                                origin_as: None,
                                local_pref: 100,
                                best: true,
                                validation_state: nos_proto::RpkiValidationState::NotFound,
                            }],
                            next: None,
                        },
                        _ => BgpEvent::Summary(Vec::new()),
                    }]
                }),
                "ospf" if closed => serve_with(role, name, &path, true, |_: OspfRequest| {
                    Vec::<OspfEvent>::new()
                }),
                "ospf" => serve(role, name, &path, |r: OspfRequest| {
                    vec![match r {
                        OspfRequest::GetDatabase => OspfEvent::Database(Vec::new()),
                        _ => OspfEvent::Neighbors(Vec::new()),
                    }]
                }),
                _ if closed => serve_with(role, name, &path, true, |_: Ospfv3Request| {
                    Vec::<Ospfv3Event>::new()
                }),
                _ => serve(role, name, &path, |r: Ospfv3Request| {
                    vec![match r {
                        Ospfv3Request::GetDatabase => Ospfv3Event::Database(Vec::new()),
                        _ => Ospfv3Event::Neighbors(Vec::new()),
                    }]
                }),
            }
        }
    }

    let watchdog = sock("watchdog");
    let nobody = sock("nobody");
    if wd != Wd::Dead {
        let config_path = config.clone();
        serve("watchdog", "", &watchdog, move |r: WatchdogRequest| {
            let WatchdogRequest::ResolveEndpoint { service } = r else {
                return vec![WatchdogEvent::NotAvailable];
            };
            if matches!(service, ServiceRef::Config) && wd != Wd::NotAvailable {
                return vec![WatchdogEvent::Endpoint(config_path.clone())];
            }
            let key = match (&service, wd) {
                (_, Wd::NotAvailable) => return vec![WatchdogEvent::NotAvailable],
                (_, Wd::Dangling) => return vec![WatchdogEvent::Endpoint(nobody.clone())],
                (ServiceRef::RibTable(t), _) if t == "rt1" => "rib",
                (ServiceRef::FdbDomain(_), _) => "fdb",
                (ServiceRef::Interfaces, _) => "interfaces",
                (ServiceRef::Lacp, _) => "lacp",
                (ServiceRef::Lldp, _) => "lldp",
                (ServiceRef::Stp, _) => "stp",
                (ServiceRef::Bfd, _) => "bfd",
                (ServiceRef::Log, _) => "log",
                (ServiceRef::BgpInstance(_), _) => "bgp",
                (ServiceRef::OspfInstance(_), _) => "ospf",
                (ServiceRef::Ospfv3Instance(_), _) => "ospfv3",
                _ => return vec![WatchdogEvent::NotAvailable],
            };
            vec![WatchdogEvent::Endpoint(endpoints[key].clone())]
        });
    }
    Lab {
        config,
        watchdog,
        docs: Arc::new(Mutex::new(HashMap::new())),
        _dir: dir,
    }
}

fn configuration(transaction: &str, path: &[&str], dirty: bool) -> Mode {
    Mode::Configuration {
        transaction: transaction.to_string(),
        path: session::Path::from(path.iter().map(ToString::to_string).collect::<Vec<_>>()),
        dirty,
    }
}

/// Every operational query and clear command, in one list.
const QUERIES: &[&str] = &[
    "show route rt1",
    "show route rt1 10.0.0.1",
    "show fdb bd1",
    "show interface",
    "show interface eth0",
    "show port-aggregate",
    "show port-aggregate bond0",
    "show lacp",
    "show lacp bond0",
    "show lacp bond9",
    "show lldp neighbors",
    "show lldp neighbors detail",
    "show lldp statistics",
    "show bfd sessions",
    "show bfd reflector",
    "show spanning-tree",
    "show spanning-tree instance 1",
    "show spanning-tree mst-config",
    "show spanning-tree domain bd1",
    "show spanning-tree detail",
    "show log",
    "show log configd --follow",
    "show bgp brief",
    "show bgp evpn",
    "show bgp flowspec",
    "show bgp rpki",
    "show bgp bmp",
    "show bgp vpnv4",
    "show bgp vpnv6 rd 65001:1",
    "show ospf neigh",
    "show ospf database",
    "show ospfv3 neigh",
    "show ospfv3 database",
    "clear spanning-tree detected-protocols",
    "clear spanning-tree detected-protocols interface eth0",
    "clear spanning-tree detected-protocols interface none",
    "clear spanning-tree err-disabled eth0",
    "clear spanning-tree err-disabled eth1",
    "clear bgp b1 192.0.2.2",
    "clear bgp b1 192.0.2.2 soft-in",
    "clear bgp b1 192.0.2.3",
    "clear bgp b1 192.0.2.3 soft-in",
];

async fn every_query_returns_to_the_prompt(lab: &Lab) {
    let (mode, exited) = run(lab, Mode::Operational, QUERIES, leave_open).await;
    assert_eq!(mode, Mode::Operational);
    assert!(!exited);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_is_running() {
    let lab = world(Wd::NotAvailable, Daemons::Populated, Configd::Healthy);
    every_query_returns_to_the_prompt(&lab).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watchdog_is_unreachable() {
    let lab = world(Wd::Dead, Daemons::Populated, Configd::Healthy);
    every_query_returns_to_the_prompt(&lab).await;
    let lab = world(Wd::Dangling, Daemons::Populated, Configd::Healthy);
    every_query_returns_to_the_prompt(&lab).await;
    // Both ways the broker can fail to name nos-configd fall back to the default.
    for wd in [Wd::NotAvailable, Wd::Dead] {
        let lab = world(wd, Daemons::Closed, Configd::Healthy);
        assert_eq!(
            actions::resolve_config_socket(&lab.watchdog).await,
            PathBuf::from(nos_proto::DEFAULT_CONFIG_SOCKET)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemons_hang_up_on_every_query() {
    let lab = world(Wd::Resolves, Daemons::Closed, Configd::Healthy);
    every_query_returns_to_the_prompt(&lab).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemons_answer_with_data() {
    let lab = world(Wd::Resolves, Daemons::Populated, Configd::Healthy);
    every_query_returns_to_the_prompt(&lab).await;
    // A tail that fails, one that streams a line then ends, one that just ends.
    let (mode, _) = run(
        &lab,
        Mode::Operational,
        &[
            "show log boom --follow",
            "show log line --follow",
            "show log quiet --follow",
            "show log configd",
        ],
        leave_open,
    )
    .await;
    assert_eq!(mode, Mode::Operational);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configd_is_down_for_every_operational_command() {
    let lab = world(Wd::Resolves, Daemons::Populated, Configd::Broken);
    let (mode, _) = run(
        &lab,
        Mode::Operational,
        &[
            "help",
            "show config",
            "show config admin",
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
            "clear bgp b1 192.0.2.2",
            "save",
            "configure t1",
        ],
        leave_open,
    )
    .await;
    assert_eq!(
        mode,
        Mode::Operational,
        "an unopenable transaction stays out"
    );
    // The docs fall back to the placeholder rather than failing.
    let doc = actions::doc_for(&lab.config, &lab.docs, nos_proto::Topic::Save).await;
    assert!(doc.summary.contains("could not reach nos-configd"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_flow_errors_keep_the_mode() {
    let lab = world(Wd::Resolves, Daemons::Populated, Configd::Healthy);

    // Opening: refused, and resuming with and without an explicit base.
    for (line, want_open) in [
        ("configure unopenable", false),
        ("configure resumed", true),
        ("configure resumed from blank", true),
    ] {
        let (mode, _) = run(&lab, Mode::Operational, &[line], leave_open).await;
        assert_eq!(
            matches!(mode, Mode::Configuration { .. }),
            want_open,
            "{line}"
        );
    }

    // Everything against a transaction the daemon does not know.
    let missing = configuration("missing", &[], true);
    let (mode, _) = run(
        &lab,
        missing.clone(),
        &[
            "show this",
            "diff",
            "commit",
            "discard",
            "help",
            "set hostname other",
            "set bogus",
            "edit bgp instance b1",
            "show source",
            "edit source",
            "set source line 1 accept",
            "delete source line 1",
        ],
        leave_open,
    )
    .await;
    assert_eq!(mode, missing, "a failed edit leaves the position alone");

    let inside = configuration("missing", &["policy-definition", "p1"], true);
    let (mode, _) = run(
        &lab,
        inside.clone(),
        &[
            "show source",
            "edit source",
            "set source line 1 accept",
            "delete source line 1",
        ],
        leave_open,
    )
    .await;
    assert_eq!(mode, inside);

    // Leaving: a refused commit keeps the mode, a failed discard still leaves.
    let (mode, _) = run(&lab, configuration("refused", &[], true), &["exit"], commit).await;
    assert!(matches!(mode, Mode::Configuration { .. }));
    let (mode, _) = run(
        &lab,
        configuration("missing", &[], true),
        &["exit"],
        discard,
    )
    .await;
    assert_eq!(mode, Mode::Operational);
    let (mode, _) = run(&lab, configuration("t", &[], false), &["exit"], commit).await;
    assert_eq!(mode, Mode::Operational, "nothing pending: no question");
    let _ = LeaveChoice::LeaveOpen;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_edit_lands_where_the_grammar_says() {
    let lab = world(Wd::Resolves, Daemons::Populated, Configd::Healthy);
    let inside = configuration("t1", &["bgp-instance", "b1"], false);

    // A write the daemon refuses part-way leaves the position.
    let (mode, _) = run(&lab, inside.clone(), &["set hostname FAIL"], leave_open).await;
    assert_eq!(mode, inside);

    // The re-read after the writes fails (every 2nd `flaky` read): the
    // write landed, so the shell stays put and is dirty.
    let flaky = world(Wd::Resolves, Daemons::Populated, Configd::Healthy);
    let at = configuration("flaky", &["bgp-instance", "b1"], false);
    let (mode, _) = run(&flaky, at, &["set hostname h2"], leave_open).await;
    assert_eq!(mode, configuration("flaky", &["bgp-instance", "b1"], true));

    // Deleting the object we stand in moves us up out of it.
    let (mode, _) = run(&lab, inside, &["delete"], leave_open).await;
    let Mode::Configuration { path, .. } = mode else {
        panic!("still configuring");
    };
    assert!(
        path.segments().len() < 2,
        "left the deleted instance: {path:?}"
    );

    // A policy-source line out of range, and the append position.
    let policy = configuration("t2", &["policy-definition", "p1"], false);
    let (mode, _) = run(
        &lab,
        policy,
        &[
            "set source line 0 accept",
            "set source line 9 accept",
            "delete source line 0",
            "delete source line 9",
            "set source line 2 accept",
            "delete source line 2",
            "show source",
        ],
        leave_open,
    )
    .await;
    assert!(matches!(mode, Mode::Configuration { .. }));
}

/// A shell script at `dir/name` that is run as `$EDITOR file`.
fn editor(dir: &Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_str().unwrap().to_string()
}

async fn policy_source(lab: &Lab) -> String {
    let snap = nos_cli::client::get_transaction(&lab.config, "t")
        .await
        .unwrap();
    snap.config
        .policy_definitions
        .iter()
        .find(|p| p.name == "p1")
        .unwrap()
        .source
        .clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_source_is_edited_in_an_external_editor() {
    let lab = world(Wd::Resolves, Daemons::Populated, Configd::Healthy);
    let tools = tempfile::tempdir().unwrap();
    let policy = configuration("t", &["policy-definition", "p1"], false);

    // Rewrites its argument to a policy that uses every kind of symbol.
    let good = editor(
        tools.path(),
        "good",
        r#"cat > "$1" <<'EOF'
if this.bgp.communities.contains(CUST):
    reject
if this.bgp.communities.contains(GROUP):
    reject
if this.prefix in BLOCKS:
    reject
if this.bgp.as_path in TRANSIT:
    reject
accept
EOF"#,
    );
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::set_var("EDITOR", &good) };
    let (mode, _) = run(&lab, policy.clone(), &["edit source"], leave_open).await;
    assert!(matches!(mode, Mode::Configuration { .. }));
    assert!(
        policy_source(&lab).await.contains("TRANSIT"),
        "edit applied"
    );

    // A script that does not compile is discarded.
    let bad = editor(tools.path(), "bad", r#"echo 'this is not rpl' > "$1""#);
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::set_var("EDITOR", &bad) };
    let (_, _) = run(&lab, policy.clone(), &["edit source"], leave_open).await;
    assert!(
        policy_source(&lab).await.contains("TRANSIT"),
        "edit discarded"
    );

    // An editor that fails, and one that cannot be started.
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::set_var("EDITOR", "false") };
    let (mode, _) = run(&lab, policy.clone(), &["edit source"], leave_open).await;
    assert!(matches!(mode, Mode::Configuration { .. }));
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::set_var("EDITOR", "/nonexistent/editor") };
    let (mode, _) = run(&lab, policy.clone(), &["edit source"], leave_open).await;
    assert!(matches!(mode, Mode::Configuration { .. }));

    // The transaction vanishes while the editor runs: nothing is applied.
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::set_var("EDITOR", &good) };
    let flaky = world(Wd::Resolves, Daemons::Populated, Configd::Healthy);
    let flaky_policy = configuration("flaky", &["policy-definition", "p1"], false);
    let (mode, _) = run(&flaky, flaky_policy.clone(), &["edit source"], leave_open).await;
    assert_eq!(mode, flaky_policy);

    // An editor value with arguments: the argument precedes the file path.
    let argv = tools.path().join("argv");
    let rec = editor(
        tools.path(),
        "rec",
        &format!(
            r#"echo "$1" > {a}; echo "$2" >> {a}; echo 'accept' > "$2""#,
            a = argv.display()
        ),
    );
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::set_var("EDITOR", format!("{rec} --flag")) };
    let _ = run(&lab, policy.clone(), &["edit source"], leave_open).await;
    let rec_out = std::fs::read_to_string(&argv).unwrap();
    assert!(rec_out.starts_with("--flag\n/"), "{rec_out}");

    // An unparsable value discards the edit without running anything.
    std::fs::remove_file(&argv).unwrap();
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::set_var("EDITOR", format!("{rec} \"unbalanced")) };
    let (mode, _) = run(&lab, policy.clone(), &["edit source"], leave_open).await;
    assert!(matches!(mode, Mode::Configuration { .. }));
    assert!(!argv.exists());

    // The fallbacks: no $EDITOR means $VISUAL, then vim (absent here: an error).
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::remove_var("EDITOR") };
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::set_var("VISUAL", "true") };
    let (_, _) = run(&lab, policy.clone(), &["edit source"], leave_open).await;
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::remove_var("VISUAL") };
    // SAFETY: test-only env mutation; these tests run in one serial test body.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only env mutation, serial test body
    unsafe { std::env::set_var("PATH", tools.path()) };
    let (mode, _) = run(&lab, policy, &["edit source"], leave_open).await;
    assert!(matches!(mode, Mode::Configuration { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uncompilable_line_edits_are_staged_with_a_warning() {
    let lab = world(Wd::Resolves, Daemons::Populated, Configd::Healthy);
    let policy = configuration("t", &["policy-definition", "p1"], false);
    let (mode, _) = run(
        &lab,
        policy,
        &[
            "set source line 1 if NOT_DEFINED:",
            "set source line 2 accept",
        ],
        leave_open,
    )
    .await;
    assert!(matches!(mode, Mode::Configuration { dirty: true, .. }));
    assert!(policy_source(&lab).await.contains("NOT_DEFINED"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_protocol_instances_are_configured() {
    let lab = world(Wd::Resolves, Daemons::Populated, Configd::Bare);
    let (mode, _) = run(
        &lab,
        Mode::Operational,
        &[
            "",
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
            "clear bgp b1 192.0.2.2",
        ],
        leave_open,
    )
    .await;
    assert_eq!(mode, Mode::Operational);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_staged_edit_the_daemon_refuses_keeps_the_mode() {
    let lab = world(Wd::Resolves, Daemons::Populated, Configd::Healthy);
    let policy = configuration("noapply", &["policy-definition", "p1"], false);
    let (mode, _) = run(
        &lab,
        policy.clone(),
        &[
            "set source line 1 accept",
            "set source line 1 if NOT_DEFINED:",
        ],
        leave_open,
    )
    .await;
    assert_eq!(mode, policy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_transaction_vanishes_between_fetch_and_compile() {
    let lab = world(Wd::Resolves, Daemons::Populated, Configd::Healthy);
    let policy = configuration("flaky", &["policy-definition", "p1"], false);
    // fetch_policy_source works, compile_against_transaction's fetch fails.
    let (mode, _) = run(
        &lab,
        policy.clone(),
        &["set source line 1 accept"],
        leave_open,
    )
    .await;
    assert_eq!(mode, policy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn docs_are_fetched_on_a_miss_and_degrade_when_configd_is_down() {
    // A topic no other test of this binary has fetched.
    let topic = nos_proto::Topic::ALL[0];
    let lab = world(Wd::Resolves, Daemons::Populated, Configd::Healthy);
    let doc = actions::doc_for_blocking(&lab.config, &lab.docs, topic);
    assert!(doc.summary.contains("summary"));
    assert!(lab.docs.lock().unwrap().contains_key(&topic));
    let down = world(Wd::Resolves, Daemons::Populated, Configd::Broken);
    let doc = actions::doc_for_blocking(&down.config, &down.docs, topic);
    assert!(doc.summary.contains("could not reach nos-configd"));
    assert!(
        down.docs.lock().unwrap().is_empty(),
        "a failure is not cached"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hostname_task_keeps_retrying_an_absent_configd() {
    // nosemgrep: rust.lang.security.temp-dir.temp-dir -- socket path that must not exist
    let missing = std::env::temp_dir().join("nos-345-no-such-configd.sock");
    let hostname = Arc::new(Mutex::new("nos".to_string()));
    let task = tokio::spawn(actions::subscribe_hostname_task(
        missing,
        Arc::clone(&hostname),
        || {},
    ));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!task.is_finished(), "retries instead of giving up");
    task.abort();
    assert_eq!(*hostname.lock().unwrap(), "nos");
}
