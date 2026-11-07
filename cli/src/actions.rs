//! What each resolved shell action does — every `show`, the transaction
//! flow, policy-source editing and `help` — kept out of `main.rs`'s reedline
//! loop so it can be driven against fake daemons in tests (#131). Output goes
//! to stdout/stderr, as before.

use std::collections::HashMap;
use std::io::{self, IsTerminal as _, Write as _};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use nos_proto::{
    CommandDoc, ConfigOp, Event, LogEvent, PolicyDefinitionOp, ServiceRef, Topic,
    DEFAULT_CONFIG_SOCKET,
};

use crate::session::{self, Mode, Resolved};
use crate::spec::{self, Doc};
use crate::{
    acl_client, bfd_client, bgp_client, client, fdb_client, format, interface_client, lacp_client,
    lldp_client, log_client, ospf_client, ospfv3_client, rib_client, stp_client, watchdog_client,
};

/// Per-session cache of operation documentation fetched from `nos-configd`,
/// keyed by `Topic` — populated lazily, at most once per topic per session
/// (see `doc_for`/`doc_for_blocking`), never bulk-fetched up front.
pub type DocCache = Arc<Mutex<HashMap<Topic, CommandDoc>>>;

/// Extracts the current transaction name — only ever called on a `Resolved`
/// variant that `session::resolve` only produces from `Mode::Configuration`.
pub fn current_transaction(mode: &Mode) -> String {
    match mode {
        Mode::Configuration { transaction, .. } => transaction.clone(),
        Mode::Operational => {
            unreachable!("resolve() only yields this action in Configuration mode")
        }
    }
}

pub fn current_path(mode: &Mode) -> session::Path {
    match mode {
        Mode::Configuration { path, .. } => path.clone(),
        Mode::Operational => {
            unreachable!("resolve() only yields this action in Configuration mode")
        }
    }
}

/// What the REPL loop should do after handling one resolved action.
pub enum Outcome {
    Continue(Mode),
    Exit,
}

/// Cache-first lookup for a topic's documentation, from a synchronous
/// context (reedline's `Completer`/`Menu` callbacks aren't `async`). Blocks
/// on one IPC round trip only on a cache miss — see `DocCache`.
pub fn doc_for_blocking(socket: &Path, cache: &DocCache, topic: Topic) -> CommandDoc {
    if let Some(doc) = cache.lock().unwrap().get(&topic) {
        return doc.clone();
    }
    let fetched = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(client::describe(socket, topic))
    });
    match fetched {
        Ok(doc) => {
            cache.lock().unwrap().insert(topic, doc.clone());
            doc
        }
        Err(_) => unavailable_doc(topic),
    }
}

/// Cache-first lookup for a topic's documentation, from an `async` context
/// (used by `print_help`, which can simply `.await` rather than block).
pub async fn doc_for(socket: &Path, cache: &DocCache, topic: Topic) -> CommandDoc {
    if let Some(doc) = cache.lock().unwrap().get(&topic) {
        return doc.clone();
    }
    match client::describe(socket, topic).await {
        Ok(doc) => {
            cache.lock().unwrap().insert(topic, doc.clone());
            doc
        }
        Err(_) => unavailable_doc(topic),
    }
}

pub fn unavailable_doc(topic: Topic) -> CommandDoc {
    let text = "description unavailable — could not reach nos-configd".to_string();
    CommandDoc {
        topic,
        summary: text.clone(),
        detail: text,
    }
}

/// Resolves nos-configd's address via nos-watchdogd's broker, once at
/// startup. On any failure (broker unreachable, or it reports the service as
/// unavailable) falls back to the conventional default socket path and warns
/// — preserving the shell's existing resilience property that startup never
/// blocks or fails just because a daemon is briefly unreachable.
pub async fn resolve_config_socket(watchdog_socket: &Path) -> PathBuf {
    match watchdog_client::resolve(watchdog_socket, ServiceRef::Config).await {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!(
                "warning: nos-watchdogd reports nos-configd as unavailable; falling back to {DEFAULT_CONFIG_SOCKET}"
            );
            PathBuf::from(DEFAULT_CONFIG_SOCKET)
        }
        Err(e) => {
            eprintln!(
                "warning: could not resolve nos-configd via nos-watchdogd ({e}); falling back to {DEFAULT_CONFIG_SOCKET}"
            );
            PathBuf::from(DEFAULT_CONFIG_SOCKET)
        }
    }
}

/// Holds a long-lived `Request::Subscribe` connection for the shell's whole
/// lifetime, keeping `hostname` current and triggering an in-place prompt
/// repaint (via `RepaintSignal`) whenever it changes — including while the
/// shell is idle at the prompt, not just on the next command. Reconnects on
/// a fixed 1s delay after any disconnect/error; this is nos-cli's first
/// long-lived connection, so unlike every one-shot `client::*` call (which
/// simply reports its own error per command), leaving this unattended would
/// otherwise freeze the prompt's hostname for the rest of the session after
/// a daemon restart.
pub async fn subscribe_hostname_task(
    socket: PathBuf,
    hostname: Arc<Mutex<String>>,
    notify_repaint: impl Fn() + Send + 'static,
) {
    loop {
        if let Ok(mut reader) = client::subscribe(&socket).await {
            while let Some(Ok(Event::Config(cfg))) = reader.next().await {
                let mut guard = hostname.lock().unwrap();
                if *guard != cfg.hostname {
                    *guard = cfg.hostname;
                    drop(guard);
                    notify_repaint();
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaveChoice {
    Commit,
    Discard,
    LeaveOpen,
}

/// `ask_leave` answers the commit/discard/leave-open question on `exit` with
/// uncommitted changes — a stdin prompt in `main.rs`, a canned answer in
/// tests.
pub async fn handle_action(
    action: Resolved,
    mode: Mode,
    socket: &Path,
    watchdog_socket: &Path,
    doc_cache: &DocCache,
    ask_leave: fn(&str) -> LeaveChoice,
) -> Outcome {
    match action {
        Resolved::Nothing => Outcome::Continue(mode),
        Resolved::Help => {
            print_help(&mode, socket, doc_cache).await;
            Outcome::Continue(mode)
        }
        Resolved::ExitShell => Outcome::Exit,
        Resolved::LeaveConfigPrompt => {
            Outcome::Continue(handle_leave_prompt(mode, socket, ask_leave).await)
        }
        Resolved::NavigateTop => Outcome::Continue(navigate_top(&mode)),
        Resolved::Navigate(path) => Outcome::Continue(navigate_to(&mode, path)),
        Resolved::SaveRunningConfig => {
            save_running_config(socket).await;
            Outcome::Continue(mode)
        }
        Resolved::OpenTransaction {
            name,
            base,
            explicit_base,
        } => Outcome::Continue(open_transaction(socket, name, base, explicit_base).await),
        Resolved::ConfigEdit(line) => Outcome::Continue(config_edit(mode, socket, &line).await),
        Resolved::Commit => Outcome::Continue(commit(mode, socket).await),
        Resolved::Discard => Outcome::Continue(discard(mode, socket).await),
        Resolved::EditPolicySource { name } => {
            Outcome::Continue(edit_policy_source(mode, socket, name).await)
        }
        Resolved::ShowPolicySource { name } => {
            show_policy_source(&mode, socket, &name).await;
            Outcome::Continue(mode)
        }
        Resolved::SetPolicySourceLine { name, line, text } => {
            let mode = edit_policy_source_line(mode, socket, name, |lines| {
                if line == 0 {
                    return Err("line numbers start at 1".to_string());
                }
                if line <= lines.len() {
                    lines[line - 1] = text;
                } else if line == lines.len() + 1 {
                    lines.push(text);
                } else {
                    return Err(format!(
                        "line {line} is out of range (source has {} lines; use {} to append)",
                        lines.len(),
                        lines.len() + 1
                    ));
                }
                Ok(())
            })
            .await;
            Outcome::Continue(mode)
        }
        Resolved::DeletePolicySourceLine { name, line } => {
            let mode = edit_policy_source_line(mode, socket, name, |lines| {
                if line == 0 || line > lines.len() {
                    return Err(format!(
                        "line {line} is out of range (source has {} lines)",
                        lines.len()
                    ));
                }
                lines.remove(line - 1);
                Ok(())
            })
            .await;
            Outcome::Continue(mode)
        }
        Resolved::Diff => {
            diff(&mode, socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowVersion => {
            println!("{}", version_line());
            Outcome::Continue(mode)
        }
        Resolved::Error(msg) => {
            eprintln!("error: {msg}");
            Outcome::Continue(mode)
        }
        action @ (Resolved::ShowRunningConfig
        | Resolved::ShowAdminConfig
        | Resolved::ShowTransaction
        | Resolved::ShowRoute { .. }
        | Resolved::ShowFdb { .. }
        | Resolved::ShowInterface { .. }
        | Resolved::ShowPortAggregate { .. }
        | Resolved::ShowLacp { .. }
        | Resolved::ShowLldpNeighbors { .. }
        | Resolved::ShowLldpStatistics
        | Resolved::ShowAcl { .. }
        | Resolved::ShowSpanningTree
        | Resolved::ShowSpanningTreeInstance { .. }
        | Resolved::ShowSpanningTreeMstConfig
        | Resolved::ShowSpanningTreeDomain { .. }
        | Resolved::ShowSpanningTreeDetail { .. }
        | Resolved::ShowBfdReflector
        | Resolved::ShowBfdSessions { .. }
        | Resolved::ShowLog { .. }
        | Resolved::ShowBgpBrief
        | Resolved::ShowBgpEvpn
        | Resolved::ShowBgpFlowspec
        | Resolved::ShowBgpRpki
        | Resolved::ShowBgpBmp
        | Resolved::ShowBgpVpn { .. }
        | Resolved::ShowBgpRoutes
        | Resolved::ShowOspfNeigh
        | Resolved::ShowOspfDatabase
        | Resolved::ShowOspfv3Neigh
        | Resolved::ShowOspfv3Database
        | Resolved::ClearBgpSoftIn { .. }
        | Resolved::ClearBgpPeer { .. }
        | Resolved::ClearStpMcheck { .. }
        | Resolved::ClearStpErrDisabled { .. }) => {
            run_query(action, mode, socket, watchdog_socket).await
        }
    }
}

/// `show version`'s one line.
fn version_line() -> String {
    format!(
        "nos {} ({})",
        nos_proto::version::VERSION,
        nos_proto::version::REVISION
    )
}

/// The `show`/`clear` actions of `handle_action`, split out for length
/// (#425); `handle_action` names every variant routed here.
async fn run_query(action: Resolved, mode: Mode, socket: &Path, watchdog_socket: &Path) -> Outcome {
    match action {
        Resolved::ShowRunningConfig => {
            show_running_config(socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowAdminConfig => {
            match client::fetch_running_config(socket).await {
                Ok(cfg) => println!("{}", format::render_admin_config(&cfg)),
                Err(e) => eprintln!("error: {e}"),
            }
            Outcome::Continue(mode)
        }
        Resolved::ShowTransaction => {
            show_transaction(&mode, socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowRoute { table, address } => {
            show_route(watchdog_socket, &table, address).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowFdb { domain } => {
            show_fdb(watchdog_socket, &domain).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowInterface { name } => {
            show_interface(watchdog_socket, name.as_deref()).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowPortAggregate { name } => {
            show_port_aggregate(watchdog_socket, name.as_deref()).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowLacp { name } => {
            show_lacp(watchdog_socket, name.as_deref()).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowLldpNeighbors { detail } => {
            show_lldp_neighbors(watchdog_socket, detail).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowLldpStatistics => {
            show_lldp_statistics(watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowAcl { name } => {
            show_acl(watchdog_socket, name.as_deref()).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowSpanningTree => {
            show_spanning_tree(watchdog_socket, SpanningTreeView::Summary).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowSpanningTreeInstance { id } => {
            show_spanning_tree(watchdog_socket, SpanningTreeView::Instance(id)).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowSpanningTreeMstConfig => {
            show_spanning_tree(watchdog_socket, SpanningTreeView::MstConfig).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowSpanningTreeDomain { domain } => {
            show_spanning_tree(watchdog_socket, SpanningTreeView::Domain(domain)).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowSpanningTreeDetail { instance, domain } => {
            show_spanning_tree(
                watchdog_socket,
                SpanningTreeView::Detail { instance, domain },
            )
            .await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBfdReflector => {
            show_bfd_reflector(watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBfdSessions { peer } => {
            show_bfd_sessions(watchdog_socket, peer).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowLog { source, follow } => {
            show_log(watchdog_socket, source, follow).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpBrief => {
            show_bgp_brief(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpEvpn => {
            show_bgp_evpn(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpFlowspec => {
            show_bgp_flowspec(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpRoutes => {
            show_bgp_routes(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpRpki => {
            show_bgp_rpki(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpBmp => {
            show_bgp_bmp(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpVpn { family, rd } => {
            show_bgp_vpn(socket, watchdog_socket, family, rd.as_deref()).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfNeigh => {
            show_ospf_neigh(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfDatabase => {
            show_ospf_database(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfv3Neigh => {
            show_ospfv3_neigh(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfv3Database => {
            show_ospfv3_database(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ClearBgpSoftIn { instance, peer } => {
            clear_bgp(socket, watchdog_socket, &instance, peer, true).await;
            Outcome::Continue(mode)
        }
        Resolved::ClearBgpPeer { instance, peer } => {
            clear_bgp(socket, watchdog_socket, &instance, peer, false).await;
            Outcome::Continue(mode)
        }
        Resolved::ClearStpMcheck { interface } => {
            clear_stp_mcheck(watchdog_socket, interface).await;
            Outcome::Continue(mode)
        }
        Resolved::ClearStpErrDisabled { interface } => {
            clear_stp_err_disabled(watchdog_socket, interface).await;
            Outcome::Continue(mode)
        }
        _ => unreachable!("routed by handle_action"),
    }
}

async fn handle_leave_prompt(
    mode: Mode,
    socket: &Path,
    ask_leave: fn(&str) -> LeaveChoice,
) -> Mode {
    let transaction = current_transaction(&mode);
    let dirty = matches!(&mode, Mode::Configuration { dirty: true, .. });
    if !dirty {
        return Mode::Operational;
    }
    match ask_leave(&transaction) {
        LeaveChoice::Commit => match client::commit_transaction(socket, &transaction).await {
            Ok(warnings) => {
                print_committed(&transaction, &warnings);
                Mode::Operational
            }
            Err(e) => {
                eprintln!("error: {e} (transaction left open — fix and retry)");
                mode
            }
        },
        LeaveChoice::Discard => {
            if let Err(e) = client::discard_transaction(socket, &transaction).await {
                eprintln!("error: {e}");
            }
            Mode::Operational
        }
        LeaveChoice::LeaveOpen => {
            println!(
                "transaction '{transaction}' left open on the daemon — resume with 'configure {transaction}'"
            );
            Mode::Operational
        }
    }
}

pub fn navigate_top(mode: &Mode) -> Mode {
    let transaction = current_transaction(mode);
    let dirty = matches!(mode, Mode::Configuration { dirty: true, .. });
    Mode::Configuration {
        transaction,
        path: session::Path::root(),
        dirty,
    }
}

pub fn navigate_to(mode: &Mode, path: session::Path) -> Mode {
    let transaction = current_transaction(mode);
    let dirty = matches!(mode, Mode::Configuration { dirty: true, .. });
    Mode::Configuration {
        transaction,
        path,
        dirty,
    }
}

async fn show_running_config(socket: &Path) {
    match client::fetch_running_config(socket).await {
        Ok(cfg) => println!("{}", format::render_config(&cfg)),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn show_transaction(mode: &Mode, socket: &Path) {
    let transaction = current_transaction(mode);
    let path = current_path(mode);
    match client::get_transaction(socket, &transaction).await {
        Ok(snap) => println!("{}", format::render_transaction(&snap, &path)),
        Err(e) => eprintln!("error: {e}"),
    }
}

/// Resolves `table`'s nos-ribd instance fresh (not cached — tables come and
/// go during a session) via the watchdog broker, then queries it either for
/// the whole table (`address: None`) or a longest-prefix-match lookup.
async fn show_route(watchdog_socket: &Path, table: &str, address: Option<std::net::IpAddr>) {
    let rib_socket = match watchdog_client::resolve(
        watchdog_socket,
        nos_proto::ServiceRef::RibTable(table.to_string()),
    )
    .await
    {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!("routing table '{table}' is not running");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    match address {
        None => {
            if let Some(label) = rib_client::get_vpn_label(&rib_socket).await {
                println!("VPN label: {label}");
            }
            // Each page prints as it arrives; an empty table is one empty page.
            let mut any = false;
            let walked = rib_client::for_each_routes_page(&rib_socket, |page| {
                if !page.is_empty() {
                    any = true;
                    println!("{}", format::render_prefix_routes(page));
                }
            })
            .await;
            match walked {
                Ok(()) if !any => println!("{}", format::render_prefix_routes(&[])),
                Ok(()) => {}
                Err(e) => eprintln!("error: {e}"),
            }
        }
        Some(addr) => match rib_client::lookup(&rib_socket, addr).await {
            Ok(Some(matched)) => println!("{}", format::render_prefix_routes(&[matched])),
            Ok(None) => println!("no route matches {addr}"),
            Err(e) => eprintln!("error: {e}"),
        },
    }
}

/// Resolves the domain's `nos-fdbd` instance (one per domain that has a VNI)
/// via the watchdog broker and prints its forwarding database.
async fn show_fdb(watchdog_socket: &Path, domain: &str) {
    let fdb_socket = match watchdog_client::resolve(
        watchdog_socket,
        nos_proto::ServiceRef::FdbDomain(domain.to_string()),
    )
    .await
    {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!("nos-fdbd is not running for broadcast domain '{domain}' (needs a vni)");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    match fdb_client::get_table(&fdb_socket).await {
        Ok(t) => println!("{}", format::render_fdb_table(&t)),
        Err(e) => eprintln!("error: {e}"),
    }
}

/// Resolves the single `nos-interfaced` instance fresh (not cached — it's
/// still just one dial per command, matching `show_route`'s convention) via
/// the watchdog broker, then queries it either for every interface
/// (`name: None`) or one named interface.
async fn show_interface(watchdog_socket: &Path, name: Option<&str>) {
    let interface_socket =
        match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Interfaces).await {
            Ok(Some(path)) => path,
            Ok(None) => {
                eprintln!("nos-interfaced is not running");
                return;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return;
            }
        };

    match name {
        None => match interface_client::get_interfaces(&interface_socket).await {
            Ok(statuses) => println!("{}", format::render_interface_statuses(&statuses)),
            Err(e) => eprintln!("error: {e}"),
        },
        Some(name) => match interface_client::get_interface(&interface_socket, name).await {
            Ok(Some(status)) => println!("{}", format::render_interface_statuses(&[status])),
            Ok(None) => println!("interface '{name}' not found"),
            Err(e) => eprintln!("error: {e}"),
        },
    }
}

/// Same resolution and shape as `show_interface`, against `nos-interfaced`'s
/// port-aggregate query instead.
async fn show_lacp(watchdog_socket: &Path, name: Option<&str>) {
    let lacp_socket =
        match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Lacp).await {
            Ok(Some(path)) => path,
            Ok(None) => {
                eprintln!("nos-lacpd is not running");
                return;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return;
            }
        };

    match lacp_client::get_summary(&lacp_socket).await {
        Ok(summaries) => match name {
            None => println!("{}", format::render_lacp_summaries(&summaries)),
            Some(name) => {
                let one: Vec<_> = summaries
                    .into_iter()
                    .filter(|s| s.aggregate == name)
                    .collect();
                if one.is_empty() {
                    println!("lacp port aggregate '{name}' not found");
                } else {
                    println!("{}", format::render_lacp_summaries(&one));
                }
            }
        },
        Err(e) => eprintln!("error: {e}"),
    }
}

/// `nos-lldpd`'s socket via the broker, or `None` after printing why not.
async fn resolve_lldp(watchdog_socket: &Path) -> Option<std::path::PathBuf> {
    match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Lldp).await {
        Ok(Some(path)) => Some(path),
        Ok(None) => {
            eprintln!("nos-lldpd is not running");
            None
        }
        Err(e) => {
            eprintln!("error: {e}");
            None
        }
    }
}

/// Same resolution and shape as `show_lacp`, against `nos-lldpd`'s neighbor
/// query.
async fn show_lldp_neighbors(watchdog_socket: &Path, detail: bool) {
    let Some(lldp_socket) = resolve_lldp(watchdog_socket).await else {
        return;
    };
    match lldp_client::get_neighbors(&lldp_socket).await {
        Ok(neighbors) if detail => {
            println!("{}", format::render_lldp_neighbors_detail(&neighbors));
        }
        Ok(neighbors) => println!("{}", format::render_lldp_neighbors(&neighbors)),
        Err(e) => eprintln!("error: {e}"),
    }
}

/// `nos-bfdd`'s socket via the broker, or `None` after printing why not.
async fn resolve_bfd(watchdog_socket: &Path) -> Option<std::path::PathBuf> {
    match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Bfd).await {
        Ok(Some(path)) => Some(path),
        Ok(None) => {
            eprintln!("nos-bfdd is not running");
            None
        }
        Err(e) => {
            eprintln!("error: {e}");
            None
        }
    }
}

async fn show_bfd_sessions(watchdog_socket: &Path, peer: Option<std::net::IpAddr>) {
    let Some(bfd_socket) = resolve_bfd(watchdog_socket).await else {
        return;
    };
    match bfd_client::get_sessions(&bfd_socket, peer).await {
        Ok(sessions) => println!("{}", format::render_bfd_sessions(&sessions)),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn show_bfd_reflector(watchdog_socket: &Path) {
    let Some(bfd_socket) = resolve_bfd(watchdog_socket).await else {
        return;
    };
    match bfd_client::get_reflector(&bfd_socket).await {
        Ok(view) => println!("{}", format::render_bfd_reflector(&view)),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn clear_stp_mcheck(watchdog_socket: &Path, interface: Option<String>) {
    let socket = match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Stp).await {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!("nos-stpd is not running");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    match stp_client::mcheck(&socket, interface.clone()).await {
        Ok(0) => eprintln!(
            "error: {} is not a spanning-tree port",
            interface.as_deref().unwrap_or("any interface")
        ),
        Ok(n) => println!("mcheck sent to {n} port(s)"),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn clear_stp_err_disabled(watchdog_socket: &Path, interface: String) {
    let socket = match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Stp).await {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!("nos-stpd is not running");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    match stp_client::clear_err_disabled(&socket, interface.clone()).await {
        Ok(true) => println!("{interface} is up again"),
        Ok(false) => eprintln!("error: {interface} is not err-disabled"),
        Err(e) => eprintln!("error: {e}"),
    }
}

/// Which rendering of `nos-stpd`'s summary a `show spanning-tree ...` prints.
enum SpanningTreeView {
    Summary,
    Instance(u16),
    MstConfig,
    Domain(String),
    Detail {
        instance: Option<u16>,
        domain: Option<String>,
    },
}

async fn show_spanning_tree(watchdog_socket: &Path, view: SpanningTreeView) {
    let socket = match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Stp).await {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!("nos-stpd is not running");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    match stp_client::get_summary(&socket).await {
        Ok(s) => println!(
            "{}",
            match view {
                SpanningTreeView::Summary => format::render_spanning_tree(&s),
                SpanningTreeView::Instance(id) => format::render_stp_instance(&s, id),
                SpanningTreeView::MstConfig => format::render_mst_config(&s),
                SpanningTreeView::Domain(d) => format::render_stp_domain(&s, &d),
                SpanningTreeView::Detail { instance, domain } =>
                    format::render_stp_detail(&s, instance, domain.as_deref()),
            }
        ),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn show_acl(watchdog_socket: &Path, name: Option<&str>) {
    let acl_socket =
        match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Acl).await {
            Ok(Some(path)) => path,
            Ok(None) => {
                eprintln!("nos-acld is not running");
                return;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return;
            }
        };
    match acl_client::show(&acl_socket, name).await {
        Ok(acls) if acls.is_empty() && name.is_some() => {
            println!("acl '{}' not found", name.unwrap_or_default());
        }
        Ok(acls) => println!("{}", format::render_acls(&acls)),
        Err(e) => eprintln!("error: {e}"),
    }
    if name.is_none() {
        match acl_client::show_flowspec(&acl_socket).await {
            Ok(rules) if rules.is_empty() => {}
            Ok(rules) => println!("{}", format::render_flowspec_rules(&rules)),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

async fn show_lldp_statistics(watchdog_socket: &Path) {
    let Some(lldp_socket) = resolve_lldp(watchdog_socket).await else {
        return;
    };
    match lldp_client::get_statistics(&lldp_socket).await {
        Ok(stats) => println!("{}", format::render_lldp_statistics(&stats)),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn show_port_aggregate(watchdog_socket: &Path, name: Option<&str>) {
    let interface_socket =
        match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Interfaces).await {
            Ok(Some(path)) => path,
            Ok(None) => {
                eprintln!("nos-interfaced is not running");
                return;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return;
            }
        };

    match name {
        None => match interface_client::get_port_aggregates(&interface_socket).await {
            Ok(statuses) => println!("{}", format::render_port_aggregate_statuses(&statuses)),
            Err(e) => eprintln!("error: {e}"),
        },
        Some(name) => match interface_client::get_port_aggregate(&interface_socket, name).await {
            Ok(Some(status)) => println!("{}", format::render_port_aggregate_statuses(&[status])),
            Ok(None) => println!("port aggregate '{name}' not found"),
            Err(e) => eprintln!("error: {e}"),
        },
    }
}

/// Resolves the single `nos-logd` instance fresh (not cached, matching
/// `show_route`/`show_interface`'s convention) via the watchdog broker, then
/// either prints a one-shot buffer snapshot or streams a live tail until the
/// user presses Ctrl-C or the connection is lost.
async fn show_log(watchdog_socket: &Path, source: Option<String>, follow: bool) {
    let log_socket = match watchdog_client::resolve(watchdog_socket, ServiceRef::Log).await {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!("nos-logd is not running");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if !follow {
        match log_client::get_logs(&log_socket, source, None).await {
            Ok(logs) => println!("{}", format::render_log_entries(&logs)),
            Err(e) => eprintln!("error: {e}"),
        }
        return;
    }

    let mut reader = match log_client::tail(&log_socket, source).await {
        Ok(reader) => reader,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    println!("-- following nos-logd, press Ctrl-C to stop --");
    loop {
        tokio::select! {
            event = reader.next() => match event {
                Some(Ok(LogEvent::Logs(logs))) => println!("{}", format::render_log_entries(&logs)),
                Some(Ok(LogEvent::Line(entry))) => println!("{}", format::render_log_entry(&entry)),
                Some(Ok(LogEvent::Error(msg))) => {
                    eprintln!("error: {msg}");
                    break;
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    break;
                }
                None => {
                    eprintln!("connection to nos-logd closed");
                    break;
                }
            },
            _ = tokio::signal::ctrl_c() => {
                println!();
                break;
            }
        }
    }
}

/// Router-wide, no instance argument: fetches the running config fresh (like
/// every other one-shot command) for the list of configured `BgpInstance`s,
/// resolves each one's `nos-bgpd` via the watchdog broker, and queries each
/// independently — an unreachable instance prints its own line rather than
/// aborting the whole command, matching `show_route`/`show_interface`'s
/// per-command resolve-then-query shape.
async fn show_bgp_brief(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.bgp_instances.is_empty() {
        println!("no bgp instances configured");
        return;
    }

    for instance in &cfg.bgp_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::BgpInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(bgp_socket)) => match bgp_client::get_summary(&bgp_socket).await {
                Ok(peers) => println!("{}", format::render_bgp_summary(&instance.name, &peers)),
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// Prints a paged `show bgp ...` walk as the pages arrive: the instance
/// header once ahead of the first non-empty page, each page's lines, and the
/// "no routes" text only when nothing came.
struct PagedOut<'a> {
    instance: &'a str,
    any: bool,
}

impl<'a> PagedOut<'a> {
    fn new(instance: &'a str) -> Self {
        Self {
            instance,
            any: false,
        }
    }

    fn page(&mut self, empty: bool, lines: impl FnOnce() -> String) {
        if empty {
            return;
        }
        if !self.any {
            println!("{}", format::render_bgp_routes_header(self.instance));
        }
        self.any = true;
        println!("{}", lines());
    }

    fn finish<E: std::fmt::Display>(self, walked: Result<(), E>, none: &str) {
        match walked {
            Ok(()) if !self.any => println!("{none}"),
            Ok(()) => {}
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show bgp evpn` — same shape as `show_bgp_brief`, asking each instance
/// for its received EVPN routes instead of its peer summaries.
async fn show_bgp_evpn(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.bgp_instances.is_empty() {
        println!("no bgp instances configured");
        return;
    }

    for instance in &cfg.bgp_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::BgpInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(bgp_socket)) => {
                let mut out = PagedOut::new(&instance.name);
                let walked = bgp_client::for_each_evpn_routes_page(&bgp_socket, |page| {
                    out.page(page.is_empty(), || format::render_bgp_evpn_lines(page));
                })
                .await;
                out.finish(walked, &format::render_bgp_evpn(&instance.name, &[]));
            }
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show bgp flowspec` — same shape as `show_bgp_evpn`.
async fn show_bgp_flowspec(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.bgp_instances.is_empty() {
        println!("no bgp instances configured");
        return;
    }

    for instance in &cfg.bgp_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::BgpInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(bgp_socket)) => {
                let mut out = PagedOut::new(&instance.name);
                let walked = bgp_client::for_each_flowspec_routes_page(&bgp_socket, |page| {
                    out.page(page.is_empty(), || format::render_bgp_flowspec_lines(page));
                })
                .await;
                out.finish(walked, &format::render_bgp_flowspec(&instance.name, &[]));
            }
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show bgp vpnv4|vpnv6 [rd <rd>]` — same shape as `show_bgp_evpn`.
async fn show_bgp_vpn(
    config_socket: &Path,
    watchdog_socket: &Path,
    family: nos_proto::AddressFamily,
    rd: Option<&str>,
) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.bgp_instances.is_empty() {
        println!("no bgp instances configured");
        return;
    }

    for instance in &cfg.bgp_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::BgpInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(bgp_socket)) => {
                let mut out = PagedOut::new(&instance.name);
                let walked =
                    bgp_client::for_each_vpn_routes_page(&bgp_socket, family, rd, |page| {
                        out.page(page.is_empty(), || format::render_bgp_vpn_lines(page));
                    })
                    .await;
                out.finish(walked, &format::render_bgp_vpn(&instance.name, family, &[]));
            }
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show bgp routes` — same shape as `show_bgp_evpn`.
async fn show_bgp_routes(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    if cfg.bgp_instances.is_empty() {
        println!("no bgp instances configured");
        return;
    }
    for instance in &cfg.bgp_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::BgpInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(bgp_socket)) => {
                let mut out = PagedOut::new(&instance.name);
                let walked = bgp_client::for_each_routes_page(&bgp_socket, |page| {
                    out.page(page.is_empty(), || format::render_bgp_route_lines(page));
                })
                .await;
                out.finish(walked, &format::render_bgp_routes(&instance.name, &[]));
            }
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show bgp rpki` — same shape as `show_bgp_evpn`.
async fn show_bgp_rpki(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    if cfg.bgp_instances.is_empty() {
        println!("no bgp instances configured");
        return;
    }
    for instance in &cfg.bgp_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::BgpInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(bgp_socket)) => match bgp_client::get_rpki_summary(&bgp_socket).await {
                Ok(caches) => println!("{}", format::render_bgp_rpki(&instance.name, &caches)),
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show bgp bmp` — same shape as `show_bgp_evpn`.
async fn show_bgp_bmp(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    if cfg.bgp_instances.is_empty() {
        println!("no bgp instances configured");
        return;
    }
    for instance in &cfg.bgp_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::BgpInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(bgp_socket)) => match bgp_client::get_bmp_status(&bgp_socket).await {
                Ok(stations) => println!("{}", format::render_bgp_bmp(&instance.name, &stations)),
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show ospf neigh` — fetches the running config for the list of
/// `OspfInstance`s, resolves each one's `nos-ospfd` via the watchdog broker,
/// and queries each independently — mirrors `show_bgp_brief` exactly,
/// including its per-instance "not running" handling.
async fn show_ospf_neigh(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.ospf_instances.is_empty() {
        println!("no ospf instances configured");
        return;
    }

    for instance in &cfg.ospf_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::OspfInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(ospf_socket)) => match ospf_client::get_neighbors(&ospf_socket).await {
                Ok(neighbors) => {
                    println!(
                        "{}",
                        format::render_ospf_neighbors(&instance.name, &neighbors)
                    );
                }
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("ospf instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show ospf database` — mirrors `show_ospf_neigh` exactly, one instance at
/// a time, reporting a not-running instance individually rather than
/// aborting the whole command.
async fn show_ospf_database(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.ospf_instances.is_empty() {
        println!("no ospf instances configured");
        return;
    }

    for instance in &cfg.ospf_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::OspfInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(ospf_socket)) => match ospf_client::get_database(&ospf_socket).await {
                Ok(entries) => {
                    println!("{}", format::render_ospf_database(&instance.name, &entries));
                }
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("ospf instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show ospfv3 neigh` — mirrors `show_ospf_neigh` exactly, over every
/// configured `Ospfv3Instance`.
async fn show_ospfv3_neigh(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.ospfv3_instances.is_empty() {
        println!("no ospfv3 instances configured");
        return;
    }

    for instance in &cfg.ospfv3_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::Ospfv3Instance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(ospfv3_socket)) => match ospfv3_client::get_neighbors(&ospfv3_socket).await {
                Ok(neighbors) => {
                    println!(
                        "{}",
                        format::render_ospfv3_neighbors(&instance.name, &neighbors)
                    );
                }
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("ospfv3 instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show ospfv3 database` — mirrors `show_ospf_database` exactly, over every
/// configured `Ospfv3Instance`.
async fn show_ospfv3_database(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.ospfv3_instances.is_empty() {
        println!("no ospfv3 instances configured");
        return;
    }

    for instance in &cfg.ospfv3_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::Ospfv3Instance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(ospfv3_socket)) => match ospfv3_client::get_database(&ospfv3_socket).await {
                Ok(entries) => {
                    println!(
                        "{}",
                        format::render_ospfv3_database(&instance.name, &entries)
                    );
                }
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("ospfv3 instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `clear bgp <instance> <peer> [soft-in]`. Targets one named instance
/// (errors clearly if it isn't in the running config), unlike
/// `show_bgp_brief`'s all-instances loop.
async fn clear_bgp(
    config_socket: &Path,
    watchdog_socket: &Path,
    instance: &str,
    peer: IpAddr,
    soft_in: bool,
) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    if !cfg.bgp_instances.iter().any(|i| i.name == instance) {
        eprintln!("error: no bgp instance named '{instance}' in the running config");
        return;
    }

    match watchdog_client::resolve(
        watchdog_socket,
        nos_proto::ServiceRef::BgpInstance(instance.to_string()),
    )
    .await
    {
        Ok(Some(bgp_socket)) if soft_in => {
            match bgp_client::send_route_refresh(&bgp_socket, peer).await {
                Ok(bgp_client::SoftIn::RefreshSent) => {
                    println!("route refresh requested for {peer}");
                }
                Ok(bgp_client::SoftIn::Reevaluated(families)) => {
                    println!("re-evaluated import policy for {peer}:");
                    for f in families {
                        println!(
                            "  {}: {} retained, {} accepted",
                            f.family, f.retained, f.accepted
                        );
                    }
                }
                Ok(bgp_client::SoftIn::NotFound) => {
                    eprintln!("error: no established session with {peer} on '{instance}'");
                }
                Err(e) => eprintln!("error: {e}"),
            }
        }
        Ok(Some(bgp_socket)) => match bgp_client::clear_peer(&bgp_socket, peer).await {
            Ok(true) => println!("cleared {peer}"),
            Ok(false) => eprintln!("error: no peer {peer} on '{instance}'"),
            Err(e) => eprintln!("error: {e}"),
        },
        Ok(None) => println!("bgp instance '{instance}' is not running"),
        Err(e) => eprintln!("error: {e}"),
    }
}

/// Whether to emit ANSI color/highlight codes for `diff`: only when stdout
/// is an actual terminal, and never when `NO_COLOR` is set (the informal
/// but widely-honored convention — <https://no-color.org>).
fn use_color() -> bool {
    io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

async fn diff(mode: &Mode, socket: &Path) {
    let transaction = current_transaction(mode);
    match client::diff_transaction(socket, &transaction).await {
        Ok(d) if d.is_empty() => println!("no changes"),
        Ok(d) => println!("{}", format::render_diff(&d, use_color())),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn save_running_config(socket: &Path) {
    match client::save_running_config(socket).await {
        Ok(()) => println!("configuration saved"),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn open_transaction(
    socket: &Path,
    name: String,
    base: nos_proto::TransactionBase,
    explicit_base: bool,
) -> Mode {
    match client::open_transaction(socket, &name, base).await {
        Ok(snap) => {
            if snap.resumed && explicit_base {
                println!(
                    "note: transaction '{name}' already exists with pending changes; resuming it and ignoring 'from ...'"
                );
            } else if snap.resumed {
                println!("resuming transaction '{name}'");
            }
            Mode::Configuration {
                transaction: name,
                path: session::Path::root(),
                dirty: snap.dirty,
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            Mode::Operational
        }
    }
}

async fn apply_op(mode: Mode, socket: &Path, op: ConfigOp) -> Mode {
    let transaction = current_transaction(&mode);
    let path = current_path(&mode);
    match client::apply_op(socket, &transaction, op).await {
        Ok(snap) => Mode::Configuration {
            transaction,
            path,
            dirty: snap.dirty,
        },
        Err(e) => {
            eprintln!("error: {e}");
            mode
        }
    }
}

/// An `edit`/`set`/`delete` line: resolved by `config_grammar` against the
/// transaction's config at the current position, then sent as
/// `EditTransactionPath` writes. Lands where the grammar navigates (`edit`,
/// bare `delete`), else stays — moving up if the position was just deleted.
async fn config_edit(mode: Mode, socket: &Path, line: &str) -> Mode {
    let transaction = current_transaction(&mode);
    let path = current_path(&mode);
    let snap = match client::get_transaction(socket, &transaction).await {
        Ok(snap) => snap,
        Err(e) => {
            eprintln!("error: {e}");
            return mode;
        }
    };
    let doc = serde_json::to_value(&snap.config).expect("a config serializes");
    let Some(edit) = crate::config_grammar::parse(line, path.segments(), &doc) else {
        eprintln!("error: '{line}' is not a valid edit here (press ? to see what fits)");
        return mode;
    };
    let mut dirty = snap.dirty;
    for (write_path, value) in edit.writes {
        match client::edit_transaction_path(
            socket,
            &transaction,
            write_path,
            Some(value.to_string()),
            edit.position.clone(),
        )
        .await
        {
            Ok(d) => dirty = d,
            Err(e) => {
                eprintln!("error: {e}");
                return mode;
            }
        }
    }
    let mut path = edit.navigate.map_or(path, session::Path::from);
    // One read after the writes (#774): does the position still exist?
    let snap = match client::get_transaction(socket, &transaction).await {
        Ok(snap) => snap,
        Err(e) => {
            eprintln!("error: {e}");
            return Mode::Configuration {
                transaction,
                path,
                dirty,
            };
        }
    };
    let doc = serde_json::to_value(&snap.config).expect("a config serializes");
    while nos_proto::config_path::get(&doc, path.segments()).is_err() {
        path = path.up();
    }
    Mode::Configuration {
        transaction,
        path,
        dirty: snap.dirty,
    }
}

/// Fetches the current transaction's source for `name` — `None` only on a
/// connection/IPC error (already reported to stderr), not on the policy
/// merely not existing (its source is just `""` then, since this is only
/// ever called while navigated into it, which requires it to exist).
async fn fetch_policy_source(socket: &Path, transaction: &str, name: &str) -> Option<String> {
    match client::get_transaction(socket, transaction).await {
        Ok(snap) => Some(
            snap.config
                .policy_definitions
                .iter()
                .find(|p| p.name == name)
                .map_or_else(String::new, |p| p.source.clone()),
        ),
        Err(e) => {
            eprintln!("error: {e}");
            None
        }
    }
}

/// Stages a new, already-compile-checked source for `name` — the check that
/// ran before this call is advisory/fast-feedback only; `nos-configd`'s
/// commit-time validation (via `PolicyDefinition`'s garde validator) stays
/// the authoritative gate, unchanged.
async fn apply_policy_source(mode: Mode, socket: &Path, name: String, source: String) -> Mode {
    apply_op(
        mode,
        socket,
        ConfigOp::PolicyDefinition(PolicyDefinitionOp::SetSource { name, source }),
    )
    .await
}

/// Creates the scratch file `edit_in_external_editor` hands the editor —
/// factored out so its security property (unpredictable name, `O_EXCL`
/// creation, mode `0600`, since `/tmp` is shared between users — see #100)
/// is directly unit-testable without spawning a real editor.
pub fn new_policy_tempfile() -> std::io::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix("nos-policy-")
        .suffix(".rpl")
        .tempfile()
}

/// Opens `$EDITOR` (else `$VISUAL`, else `vim`; a value may carry arguments) on a temp file pre-filled with `source`
/// — see root `CLAUDE.md`'s "nos-cli editing UX". `None` means no editor
/// could be spawned at all (already reported to stderr); the caller should
/// point the user at `show source`/`set source line <n> <text>` instead.
/// The editor argv: the first of `$EDITOR`, `$VISUAL` that is non-blank
/// (else `vim`), split into shell-style words without invoking a shell.
fn editor_command(editor: Option<String>, visual: Option<String>) -> Result<Vec<String>, String> {
    let pick = [("EDITOR", editor), ("VISUAL", visual)]
        .into_iter()
        .find_map(|(n, v)| v.filter(|v| !v.trim().is_empty()).map(|v| (n, v)));
    let Some((name, value)) = pick else {
        return Ok(vec!["vim".to_string()]);
    };
    match shlex::split(&value) {
        Some(w) if !w.is_empty() => Ok(w),
        _ => Err(format!("${name} ({value:?}) is not a valid command line")),
    }
}

#[allow(
    clippy::disallowed_types,
    reason = "the one CLI exception (#228): launching the user's $EDITOR"
)]
fn edit_in_external_editor(source: &str) -> Option<String> {
    let words = match editor_command(std::env::var("EDITOR").ok(), std::env::var("VISUAL").ok()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: {e}; edit discarded");
            return None;
        }
    };
    let editor = words.join(" ");
    let Ok(mut file) = new_policy_tempfile() else {
        eprintln!("error: could not create a temp file for editing");
        return None;
    };
    if file.write_all(source.as_bytes()).is_err() {
        eprintln!("error: could not create a temp file for editing");
        return None;
    }
    let path = file.path();
    // `file` (a `NamedTempFile`) is deleted on drop, on every return path
    // below — no manual `remove_file` needed.
    match std::process::Command::new(&words[0])
        .args(&words[1..])
        .arg(path)
        .status()
    {
        Ok(status) if status.success() => std::fs::read_to_string(path).ok(),
        Ok(_) => {
            eprintln!("editor '{editor}' exited with an error; edit discarded");
            None
        }
        Err(e) => {
            eprintln!(
                "error: could not run editor '{editor}' ({e}) — use 'show source' and 'set source line <n> <text>' instead"
            );
            None
        }
    }
}

/// Compiles `source` against the current transaction's `community_aliases`/
/// `community_groups`/`prefix_lists`, so this advisory client-side check
/// (see `edit_policy_source`/`edit_policy_source_line`) doesn't spuriously
/// reject a script that references a real alias/group/prefix-list — the
/// authoritative gate stays `nos-configd`'s commit-time validation,
/// unchanged. `None` only on a connection/IPC error (already reported to
/// stderr), matching `fetch_policy_source`.
async fn compile_against_transaction(
    socket: &Path,
    transaction: &str,
    source: &str,
) -> Option<Result<(), nos_rpl::CompileError>> {
    let snap = match client::get_transaction(socket, transaction).await {
        Ok(snap) => snap,
        Err(e) => {
            eprintln!("error: {e}");
            return None;
        }
    };
    let cfg = &snap.config;

    // Owned, pre-resolved buffers backing the `nos_rpl::Symbols` view below
    // — see `nos_proto::schema::policy_definition::valid_source`/
    // `nos_bgp::policy::PolicyCache::resync` for the same adapter, written
    // once per consumer per this codebase's usual `to_policy_input`-style
    // idiom rather than shared.
    let alias_parts: Vec<(&str, Vec<i64>)> = cfg
        .community_aliases
        .iter()
        .filter_map(|a| {
            nos_rpl::parse_colon_literal(&a.value).map(|parts| (a.name.as_str(), parts))
        })
        .collect();
    let alias_refs: Vec<(&str, &[i64])> = alias_parts
        .iter()
        .map(|(n, p)| (*n, p.as_slice()))
        .collect();

    let resolve_member = |m: &str| -> Option<Vec<i64>> {
        cfg.community_aliases
            .iter()
            .find(|a| a.name == m)
            .and_then(|a| nos_rpl::parse_colon_literal(&a.value))
            .or_else(|| nos_rpl::parse_colon_literal(m))
    };
    let group_parts: Vec<(&str, Vec<Vec<i64>>)> = cfg
        .community_groups
        .iter()
        .map(|g| {
            (
                g.name.as_str(),
                g.members.iter().filter_map(|m| resolve_member(m)).collect(),
            )
        })
        .collect();
    let group_member_slices: Vec<Vec<&[i64]>> = group_parts
        .iter()
        .map(|(_, members)| members.iter().map(Vec::as_slice).collect())
        .collect();
    let group_refs: Vec<(&str, &[&[i64]])> = group_parts
        .iter()
        .zip(&group_member_slices)
        .map(|((name, _), slices)| (*name, slices.as_slice()))
        .collect();

    let prefix_list_entries: Vec<(&str, Vec<nos_rpl::PrefixListEntry>)> = cfg
        .prefix_lists
        .iter()
        .map(|pl| {
            let entries = pl
                .entries
                .iter()
                .map(|e| nos_rpl::PrefixListEntry {
                    cidr: e.cidr,
                    range: e.range,
                })
                .collect();
            (pl.name.as_str(), entries)
        })
        .collect();
    let prefix_list_refs: Vec<(&str, &[nos_rpl::PrefixListEntry])> = prefix_list_entries
        .iter()
        .map(|(n, e)| (*n, e.as_slice()))
        .collect();

    let as_path_lists: Vec<(&str, Vec<&str>)> = cfg
        .as_path_lists
        .iter()
        .map(|l| {
            (
                l.name.as_str(),
                l.patterns.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let as_path_list_refs: Vec<(&str, &[&str])> = as_path_lists
        .iter()
        .map(|(n, p)| (*n, p.as_slice()))
        .collect();

    let policy_refs: Vec<(&str, &str)> = cfg
        .policy_definitions
        .iter()
        .map(|p| (p.name.as_str(), p.source.as_str()))
        .collect();
    let symbols = nos_rpl::Symbols {
        aliases: &alias_refs,
        groups: &group_refs,
        prefix_lists: &prefix_list_refs,
        as_path_lists: &as_path_list_refs,
        policies: &policy_refs,
    };

    Some(nos_rpl::compile(source, &symbols).map(|_| ()))
}

async fn edit_policy_source(mode: Mode, socket: &Path, name: String) -> Mode {
    let transaction = current_transaction(&mode);
    let Some(current) = fetch_policy_source(socket, &transaction, &name).await else {
        return mode;
    };
    let Some(edited) = edit_in_external_editor(&current) else {
        return mode;
    };
    match compile_against_transaction(socket, &transaction, &edited).await {
        Some(Ok(())) => apply_policy_source(mode, socket, name, edited).await,
        Some(Err(e)) => {
            eprintln!("policy did not compile, edit discarded: {e}");
            mode
        }
        None => mode,
    }
}

async fn show_policy_source(mode: &Mode, socket: &Path, name: &str) {
    let transaction = current_transaction(mode);
    if let Some(source) = fetch_policy_source(socket, &transaction, name).await {
        println!("{}", format::render_policy_source(&source));
    }
}

/// Shared by `set source line <n> <text>`/`delete source line <n>`: applies
/// `edit` to the current source's lines (1-indexed, matching `show
/// source`'s display), stages it, and warns if it doesn't compile (unlike
/// `edit source`, which discards a script that doesn't). `edit` reports an out-of-range line
/// itself, so both callers can just describe their own bounds rule.
async fn edit_policy_source_line(
    mode: Mode,
    socket: &Path,
    name: String,
    edit: impl FnOnce(&mut Vec<String>) -> Result<(), String>,
) -> Mode {
    let transaction = current_transaction(&mode);
    let Some(current) = fetch_policy_source(socket, &transaction, &name).await else {
        return mode;
    };
    let mut lines: Vec<String> = current.lines().map(str::to_string).collect();
    if let Err(e) = edit(&mut lines) {
        eprintln!("error: {e}");
        return mode;
    }
    let mut new_source = lines.join("\n");
    if !new_source.is_empty() {
        new_source.push('\n');
    }
    // Staged even when it doesn't compile, so a multi-line script can be
    // built a line at a time (#120); commit still refuses it until fixed.
    match compile_against_transaction(socket, &transaction, &new_source).await {
        Some(Ok(())) => apply_policy_source(mode, socket, name, new_source).await,
        Some(Err(e)) => {
            eprintln!(
                "warning: policy does not compile yet: {e} (commit will refuse it until fixed)"
            );
            apply_policy_source(mode, socket, name, new_source).await
        }
        None => mode,
    }
}

/// Confirmation line, then one `warning:` line per commit warning on stderr.
fn print_committed(transaction: &str, warnings: &[String]) {
    println!("transaction '{transaction}' committed");
    for w in warnings {
        eprintln!("warning: {w}");
    }
}

async fn commit(mode: Mode, socket: &Path) -> Mode {
    let transaction = current_transaction(&mode);
    match client::commit_transaction(socket, &transaction).await {
        Ok(warnings) => {
            print_committed(&transaction, &warnings);
            Mode::Operational
        }
        Err(e) => {
            eprintln!("error: {e} (transaction left open — fix and retry)");
            mode
        }
    }
}

async fn discard(mode: Mode, socket: &Path) -> Mode {
    let transaction = current_transaction(&mode);
    match client::discard_transaction(socket, &transaction).await {
        Ok(()) => {
            println!("transaction '{transaction}' discarded");
            Mode::Operational
        }
        Err(e) => {
            eprintln!("error: {e}");
            mode
        }
    }
}

/// Lists every command valid in `mode` right now — the same filtering (and,
/// for server-backed commands, the same lazily-fetched, session-cached
/// text) that the live `?` key's brief mode uses. Equivalent to pressing
/// `?` on an empty line.
async fn print_help(mode: &Mode, socket: &Path, cache: &DocCache) {
    println!("Available commands:");
    for command in spec::COMMAND_SPECS {
        if !spec::availability_matches(command.availability, mode) {
            continue;
        }
        let summary = match &command.doc {
            Doc::Local { summary, .. } => (*summary).to_string(),
            Doc::FromConfig(topic) => doc_for(socket, cache, *topic).await.summary,
        };
        println!("  {:<45} {}", command.usage, summary);
    }
    // Config edits, from the schema's tree: relative to where you are, in
    // the tree's order (grouped by object).
    let Mode::Configuration {
        transaction, path, ..
    } = mode
    else {
        return;
    };
    let doc = match client::get_transaction(socket, transaction).await {
        Ok(snap) => serde_json::to_value(&snap.config).expect("a config serializes"),
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    for (usage, topic) in crate::config_grammar::usages(path.segments(), &doc) {
        let summary = match topic {
            Some(topic) => doc_for(socket, cache, topic).await.summary,
            None => String::new(),
        };
        println!("  {usage:<45} {summary}");
    }
}

#[cfg(test)]
mod tempfile_tests {
    #[test]
    fn editor_command_picks_and_splits() {
        let s = |v: &str| Some(v.to_string());
        let w = |v: &[&str]| Ok(v.iter().map(ToString::to_string).collect::<Vec<_>>());
        assert_eq!(super::editor_command(s("a"), s("b")), w(&["a"]));
        assert_eq!(super::editor_command(s("  "), s("b")), w(&["b"]));
        assert_eq!(super::editor_command(None, None), w(&["vim"]));
        assert_eq!(
            super::editor_command(s("emacsclient -t"), None),
            w(&["emacsclient", "-t"])
        );
        assert_eq!(
            super::editor_command(s("\"my editor\" --f 'a b'"), None),
            w(&["my editor", "--f", "a b"])
        );
        let e = super::editor_command(s("a \"b"), None).unwrap_err();
        assert!(e.contains("$EDITOR"), "{e}");
        let e = super::editor_command(None, s("'x")).unwrap_err();
        assert!(e.contains("$VISUAL"), "{e}");
    }

    use super::new_policy_tempfile;

    #[test]
    fn version_line_names_version_and_revision() {
        let l = super::version_line();
        assert!(l.starts_with("nos "), "{l}");
        assert!(
            l.contains(nos_proto::version::VERSION) && l.ends_with(')'),
            "{l}"
        );
    }

    /// The security property #100 fixed: an unpredictable name (not a
    /// pid-based `/tmp/nos-policy-<pid>.rpl`) created with mode 0600, so a
    /// symlink or a pre-created file at a guessed path can't be used to
    /// hijack the edit.
    #[test]
    fn new_policy_tempfile_is_unpredictable_and_owner_only() {
        let a = new_policy_tempfile().expect("create temp file a");
        let b = new_policy_tempfile().expect("create temp file b");
        assert_ne!(
            a.path(),
            b.path(),
            "two calls must not reuse the same predictable path"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in [&a, &b] {
                let mode = f
                    .as_file()
                    .metadata()
                    .expect("stat temp file")
                    .permissions()
                    .mode();
                assert_eq!(
                    mode & 0o777,
                    0o600,
                    "temp file must be created owner-read/write only"
                );
            }
        }
    }
}
