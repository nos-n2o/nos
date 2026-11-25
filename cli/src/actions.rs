//! What each resolved shell action does — every `show`, the transaction
//! flow, policy-source editing and `help` — kept out of `main.rs`'s reedline
//! loop so it can be driven against fake daemons in tests (#131). Output goes
//! to stdout/stderr, as before.

use std::collections::HashMap;
use std::io::{self, IsTerminal as _};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use nos_proto::{
    CommandDoc, ConfigOp, Event, LogEntry, LogEvent, LogLevel, PolicyDefinitionOp, Request,
    ServiceRef, Topic, DEFAULT_CONFIG_SOCKET,
};

use crate::session::{self, Mode, Resolved};
use crate::spec::{self, Doc};
use crate::{
    acl_client, bfd_client, bgp_client, client, fdb_client, format, interface_client, lacp_client,
    lldp_client, log_client, ospf_client, ospfv3_client, rib_client, stp_client, view,
    watchdog_client,
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
                "warning: could not resolve nos-configd via nos-watchdogd ({}); falling back to {DEFAULT_CONFIG_SOCKET}",
                format::sanitize(&e.to_string())
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
    unsaved: Arc<std::sync::atomic::AtomicBool>,
    notify_repaint: impl Fn() + Send + 'static,
) {
    use std::sync::atomic::Ordering::Relaxed;
    loop {
        if let Ok(mut reader) = client::subscribe(&socket).await {
            while let Some(Ok(event)) = reader.next().await {
                match event {
                    Event::Config(cfg) => {
                        let mut guard = hostname.lock().unwrap();
                        if *guard != cfg.hostname {
                            *guard = cfg.hostname;
                            drop(guard);
                            notify_repaint();
                        }
                    }
                    // The live `*` of the prompt (#1139), also while idle.
                    Event::SaveStatus { unsaved: now } => {
                        if unsaved.swap(now, Relaxed) != now {
                            notify_repaint();
                        }
                    }
                    _ => break,
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
#[allow(clippy::too_many_lines, reason = "one arm per action")]
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
        Resolved::ShowHistory => {
            show_history(socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowConfigDiff { from, to } => {
            show_config_diff(socket, from, to).await;
            Outcome::Continue(mode)
        }
        action @ (Resolved::ShowAaaUsers
        | Resolved::AllocateAaaUser { .. }
        | Resolved::ClearAaaUser { .. }) => {
            aaa_users(socket, action).await;
            Outcome::Continue(mode)
        }
        Resolved::Rollback { n } => {
            rollback(socket, n).await;
            Outcome::Continue(mode)
        }
        Resolved::OpenTransaction {
            name,
            base,
            explicit_base,
        } => Outcome::Continue(open_transaction(socket, name, base, explicit_base).await),
        Resolved::ConfigEdit(line) => Outcome::Continue(config_edit(mode, socket, &line).await),
        Resolved::Commit => Outcome::Continue(commit(mode, socket, None).await),
        Resolved::CommitConfirmed { minutes } => {
            // 10 minutes is RFC 6241's default.
            let secs = minutes.unwrap_or(10).saturating_mul(60);
            Outcome::Continue(commit(mode, socket, Some(secs)).await)
        }
        Resolved::ConfirmCommit => {
            match client::confirm_commit(socket).await {
                Ok(_) => println!("commit confirmed"),
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            }
            Outcome::Continue(mode)
        }
        Resolved::CancelCommit => {
            match client::cancel_commit(socket).await {
                Ok(_) => println!("pending commit rolled back"),
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            }
            Outcome::Continue(mode)
        }
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
            emit(&nos_proto::version::VersionInfo::current(), "");
            Outcome::Continue(mode)
        }
        Resolved::Error(msg) => {
            eprintln!("error: {}", format::sanitize(&msg));
            Outcome::Continue(mode)
        }
        action @ (Resolved::ShowRunningConfig
        | Resolved::ShowAdminConfig
        | Resolved::ShowConfigPath(_)
        | Resolved::ShowTransaction
        | Resolved::ShowRoute { .. }
        | Resolved::ShowFdb { .. }
        | Resolved::ShowInterface { .. }
        | Resolved::ShowInterfaceBrief
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
        | Resolved::ShowBgpSummary { .. }
        | Resolved::ShowBgpEvpn
        | Resolved::ShowBgpFlowspec { .. }
        | Resolved::ShowBgpRpki
        | Resolved::ShowBgpBmp
        | Resolved::ShowBgpVpn { .. }
        | Resolved::ShowBgpRoutes
        | Resolved::ShowOspfNeigh
        | Resolved::ShowOspfInterface
        | Resolved::ShowOspfDatabase { .. }
        | Resolved::ShowOspfSegmentRouting
        | Resolved::ShowOspfv3Neigh
        | Resolved::ShowOspfv3Interface
        | Resolved::ShowOspfv3Database { .. }
        | Resolved::ClearBgpSoftIn { .. }
        | Resolved::ClearBgpPeer { .. }
        | Resolved::ClearStpMcheck { .. }
        | Resolved::ClearStpErrDisabled { .. }) => {
            run_query(action, mode, socket, watchdog_socket).await
        }
    }
}

/// The `show`/`clear` actions of `handle_action`, split out for length
/// (#425); `handle_action` names every variant routed here.
#[allow(clippy::too_many_lines, reason = "one arm per query command")]
async fn run_query(action: Resolved, mode: Mode, socket: &Path, watchdog_socket: &Path) -> Outcome {
    match action {
        Resolved::ShowRunningConfig => {
            show_running_config(socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowConfigPath(path) => {
            show_config_path(socket, &path).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowAdminConfig => {
            match client::fetch_running_config(socket).await {
                Ok(cfg) => println!("{}", format::render_admin_config(&cfg)),
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
        Resolved::ShowFdb { domain, mac } => {
            show_fdb(socket, watchdog_socket, domain.as_deref(), mac.as_deref()).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowInterfaceBrief => {
            show_interface_brief(watchdog_socket).await;
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
        Resolved::ShowLacp { name, detail } => {
            show_lacp(watchdog_socket, name.as_deref(), detail).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowLldpNeighbors { detail, interface } => {
            show_lldp_neighbors(watchdog_socket, detail, interface.as_deref()).await;
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
        Resolved::ShowBfdSessions { peer, detail } => {
            if let Some(r) = bfd_sessions_reply(watchdog_socket, peer).await {
                if detail {
                    emit_detail(&r, "no bfd sessions");
                } else {
                    emit(&r, "no bfd sessions");
                }
            }
            Outcome::Continue(mode)
        }
        Resolved::ShowLog {
            source,
            follow,
            last,
            level,
            needle,
        } => {
            show_log(watchdog_socket, source, follow, last, level, needle).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpSummary { instance } => {
            show_bgp_summary(socket, watchdog_socket, instance.as_deref()).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpEvpn => {
            show_bgp_evpn(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpFlowspec { family, vrf } => {
            show_bgp_flowspec(socket, watchdog_socket, family, vrf.as_deref()).await;
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
        Resolved::ShowOspfInterface => {
            show_ospf_interface(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfv3Interface => {
            show_ospfv3_interface(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfSegmentRouting => {
            show_ospf_segment_routing(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfDatabase {
            lsa_type,
            adv_router,
        } => {
            show_ospf_database(
                socket,
                watchdog_socket,
                lsa_type.as_deref(),
                adv_router.as_deref(),
            )
            .await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfv3Neigh => {
            show_ospfv3_neigh(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfv3Database {
            lsa_type,
            adv_router,
        } => {
            show_ospfv3_database(
                socket,
                watchdog_socket,
                lsa_type.as_deref(),
                adv_router.as_deref(),
            )
            .await;
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
            Ok((warnings, unsaved)) => {
                print_committed(&transaction, &warnings, unsaved);
                Mode::Operational
            }
            Err(e) => {
                eprintln!(
                    "error: {} (transaction left open — fix and retry)",
                    format::sanitize(&e.to_string())
                );
                mode
            }
        },
        LeaveChoice::Discard => {
            if let Err(e) = client::discard_transaction(socket, &transaction).await {
                eprintln!("error: {}", format::sanitize(&e.to_string()));
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
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
    }
}

async fn show_config_path(socket: &Path, path: &str) {
    let words: Vec<&str> = path.split_whitespace().collect();
    match client::fetch_running_config(socket).await {
        Ok(cfg) => match format::render_config_path(&cfg, &words) {
            Ok(text) => println!("{text}"),
            Err(e) => eprintln!("error: {e}"),
        },
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
    }
}

async fn show_transaction(mode: &Mode, socket: &Path) {
    let transaction = current_transaction(mode);
    let path = current_path(mode);
    match client::get_transaction(socket, &transaction).await {
        Ok(snap) => println!("{}", format::render_transaction(&snap, &path)),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            }
        }
        Some(addr) => match rib_client::lookup(&rib_socket, addr).await {
            Ok(Some(matched)) => println!("{}", format::render_prefix_routes(&[matched])),
            Ok(None) => println!("no route matches {}", format::sanitize(&addr.to_string())),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        },
    }
}

/// Resolves the domain's `nos-fdbd` instance (one per domain that has a VNI)
/// via the watchdog broker and fetches its forwarding database.
async fn fdb_table(
    watchdog_socket: &Path,
    domain: &str,
) -> Result<Option<nos_proto::FdbTable>, String> {
    let fdb_socket = match watchdog_client::resolve(
        watchdog_socket,
        nos_proto::ServiceRef::FdbDomain(domain.to_string()),
    )
    .await
    {
        Ok(Some(path)) => path,
        Ok(None) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    fdb_client::get_table(&fdb_socket)
        .await
        .map(Some)
        .map_err(|e| e.to_string())
}

/// `show fdb [<domain>] [mac <mac>]`. A named domain without a MAC prints its
/// full block; every other form is the flat table across domains (#1464).
async fn show_fdb(
    config_socket: &Path,
    watchdog_socket: &Path,
    domain: Option<&str>,
    mac: Option<&str>,
) {
    let domains: Vec<String> = match domain {
        Some(d) => vec![d.to_string()],
        None => match client::fetch_running_config(config_socket).await {
            Ok(cfg) => cfg
                .broadcast_domains
                .iter()
                .filter(|d| d.vni.is_some())
                .map(|d| d.name.clone())
                .collect(),
            Err(e) => {
                eprintln!("error: {}", format::sanitize(&e.to_string()));
                return;
            }
        },
    };
    if let (Some(d), None) = (domain, mac) {
        match fdb_table(watchdog_socket, d).await {
            Ok(Some(t)) => emit(&t, ""),
            Ok(None) => eprintln!(
                "nos-fdbd is not running for broadcast domain '{}' (needs a vni)",
                format::sanitize(d)
            ),
            Err(e) => eprintln!("error: {}", format::sanitize(&e)),
        }
        return;
    }
    let mut macs = Vec::new();
    let mut neighbours = Vec::new();
    for d in &domains {
        match fdb_table(watchdog_socket, d).await {
            Ok(Some(t)) => {
                let mut rows: Vec<_> = t
                    .macs
                    .into_iter()
                    .filter(|e| mac.is_none_or(|m| e.mac == m))
                    .collect();
                rows.sort_by(|a, b| a.mac.cmp(&b.mac));
                macs.extend(rows.into_iter().map(|e| (d.clone(), e)));
                if let Some(m) = mac {
                    neighbours.extend(
                        t.neighbours
                            .into_iter()
                            .filter(|n| n.mac == m)
                            .map(|n| (d.clone(), n)),
                    );
                }
            }
            Ok(None) => eprintln!(
                "fdb domain '{}': nos-fdbd is not running",
                format::sanitize(d)
            ),
            Err(e) => eprintln!(
                "fdb domain '{}': {}",
                format::sanitize(d),
                format::sanitize(&e)
            ),
        }
    }
    println!("{}", format::render_fdb_flat(&macs, &neighbours, mac));
}

/// Resolves the single `nos-interfaced` instance fresh (not cached — it's
/// still just one dial per command, matching `show_route`'s convention) via
/// the watchdog broker, then queries it either for every interface
/// (`name: None`) or one named interface.
async fn show_interface(watchdog_socket: &Path, name: Option<&str>) {
    let Some(interface_socket) = resolve_interfaced(watchdog_socket).await else {
        return;
    };

    match name {
        None => match interface_client::get_interfaces(&interface_socket).await {
            Ok(statuses) => println!("{}", format::render_interface_details(&statuses)),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        },
        Some(name) => match interface_client::get_interface(&interface_socket, name).await {
            Ok(Some(status)) => println!("{}", format::render_interface_detail(&status)),
            Ok(None) => println!("interface '{name}' not found"),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        },
    }
}

/// One watchdog resolution of `nos-interfaced`, reporting why on `None`.
async fn resolve_interfaced(watchdog_socket: &Path) -> Option<std::path::PathBuf> {
    match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Interfaces).await {
        Ok(Some(path)) => Some(path),
        Ok(None) => {
            eprintln!("nos-interfaced is not running");
            None
        }
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
            None
        }
    }
}

/// `show interface brief`: one resolution, then the interface and the
/// port-aggregate queries.
async fn show_interface_brief(watchdog_socket: &Path) {
    let Some(socket) = resolve_interfaced(watchdog_socket).await else {
        return;
    };
    let both = async {
        let interfaces = interface_client::get_interfaces(&socket).await?;
        let aggregates = interface_client::get_port_aggregates(&socket).await?;
        Ok::<_, interface_client::InterfaceClientError>((interfaces, aggregates))
    };
    match both.await {
        Ok((i, a)) => println!("{}", format::render_interface_brief(&i, &a)),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
    }
}

/// Same resolution and shape as `show_interface`, against `nos-interfaced`'s
/// port-aggregate query instead.
async fn show_lacp(watchdog_socket: &Path, name: Option<&str>, detail: bool) {
    let lacp_socket =
        match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Lacp).await {
            Ok(Some(path)) => path,
            Ok(None) => {
                eprintln!("nos-lacpd is not running");
                return;
            }
            Err(e) => {
                eprintln!("error: {}", format::sanitize(&e.to_string()));
                return;
            }
        };

    let render = |s: &[nos_proto::PortAggregateLacpSummary]| {
        if detail {
            format::render_lacp_detail(s)
        } else {
            format::render_lacp_tables(s)
        }
    };
    match lacp_client::get_summary(&lacp_socket).await {
        Ok(summaries) => match name {
            None => println!("{}", render(&summaries)),
            Some(name) => {
                let one: Vec<_> = summaries
                    .into_iter()
                    .filter(|s| s.aggregate == name)
                    .collect();
                if one.is_empty() {
                    println!("lacp port aggregate '{name}' not found");
                } else {
                    println!("{}", render(&one));
                }
            }
        },
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
            None
        }
    }
}

/// Same resolution and shape as `show_lacp`, against `nos-lldpd`'s neighbor
/// query.
async fn show_lldp_neighbors(watchdog_socket: &Path, detail: bool, interface: Option<&str>) {
    let Some(lldp_socket) = resolve_lldp(watchdog_socket).await else {
        return;
    };
    match lldp_client::get_neighbors(&lldp_socket).await {
        Ok(neighbors) if interface.is_some() => {
            let i = interface.unwrap_or_default();
            let kept = filter_lldp_interface(neighbors, i);
            if kept.is_empty() {
                println!("no lldp neighbors on '{}'", format::sanitize(i));
            } else if detail {
                println!("{}", format::render_lldp_neighbors_detail(&kept));
            } else {
                println!("{}", format::render_lldp_neighbors(&kept));
            }
        }
        Ok(neighbors) if detail => {
            println!("{}", format::render_lldp_neighbors_detail(&neighbors));
        }
        Ok(neighbors) => println!("{}", format::render_lldp_neighbors(&neighbors)),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
    }
}

/// The neighbors heard on `interface` (exact match on `local_interface`).
fn filter_lldp_interface(
    neighbors: Vec<nos_proto::LldpNeighbor>,
    interface: &str,
) -> Vec<nos_proto::LldpNeighbor> {
    neighbors
        .into_iter()
        .filter(|n| n.local_interface == interface)
        .collect()
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
            None
        }
    }
}

/// The single output point of a view-driven `show` (#1422): `| json`
/// (#1415) and the jq filter (#1420) branch here, off `view::to_value`.
fn emit<T: serde::Serialize + nos_proto::view::ViewValue>(reply: &T, empty: &str) {
    println!("{}", view::render(reply, empty));
}

/// `emit` for a `detail` form: one block per element.
fn emit_detail<T: serde::Serialize + nos_proto::view::ViewValue>(reply: &T, empty: &str) {
    println!("{}", view::render_detail_list(reply, empty));
}

async fn bfd_sessions_reply(
    watchdog_socket: &Path,
    peer: Option<std::net::IpAddr>,
) -> Option<Vec<nos_proto::BfdSessionView>> {
    let bfd_socket = resolve_bfd(watchdog_socket).await?;
    match bfd_client::get_sessions(&bfd_socket, peer).await {
        Ok(sessions) => Some(sessions),
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
            None
        }
    }
}

async fn show_bfd_reflector(watchdog_socket: &Path) {
    let Some(bfd_socket) = resolve_bfd(watchdog_socket).await else {
        return;
    };
    match bfd_client::get_reflector(&bfd_socket).await {
        Ok(view) => println!("{}", format::render_bfd_reflector(&view)),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
            return;
        }
    };
    match stp_client::mcheck(&socket, interface.clone()).await {
        Ok(0) => eprintln!(
            "error: {} is not a spanning-tree port",
            interface.as_deref().unwrap_or("any interface")
        ),
        Ok(n) => println!("mcheck sent to {n} port(s)"),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
            return;
        }
    };
    match stp_client::clear_err_disabled(&socket, interface.clone()).await {
        Ok(true) => println!("{interface} is up again"),
        Ok(false) => eprintln!("error: {interface} is not err-disabled"),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
                eprintln!("error: {}", format::sanitize(&e.to_string()));
                return;
            }
        };
    match acl_client::show(&acl_socket, name).await {
        Ok(acls) if acls.is_empty() && name.is_some() => {
            println!("acl '{}' not found", name.unwrap_or_default());
        }
        Ok(acls) if acls.is_empty() => println!("no acls"),
        Ok(acls) => emit(&acls, "no acls"),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
    }
    if name.is_none() {
        match acl_client::show_flowspec(&acl_socket).await {
            Ok(rules) if rules.is_empty() => {}
            Ok(rules) => {
                println!("flowspec rules:");
                emit(&rules, "");
            }
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

async fn show_lldp_statistics(watchdog_socket: &Path) {
    let Some(lldp_socket) = resolve_lldp(watchdog_socket).await else {
        return;
    };
    match lldp_client::get_statistics(&lldp_socket).await {
        Ok(stats) => emit(&stats, "no lldp links"),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
                eprintln!("error: {}", format::sanitize(&e.to_string()));
                return;
            }
        };

    match name {
        None => match interface_client::get_port_aggregates(&interface_socket).await {
            Ok(statuses) => println!("{}", format::render_port_aggregate_statuses(&statuses)),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        },
        Some(name) => match interface_client::get_port_aggregate(&interface_socket, name).await {
            Ok(Some(status)) => println!("{}", format::render_port_aggregate_statuses(&[status])),
            Ok(None) => println!("port aggregate '{name}' not found"),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        },
    }
}

/// Resolves the single `nos-logd` instance fresh (not cached, matching
/// `show_route`/`show_interface`'s convention) via the watchdog broker, then
/// either prints a one-shot buffer snapshot or streams a live tail until the
/// user presses Ctrl-C or the connection is lost.
async fn show_log(
    watchdog_socket: &Path,
    source: Option<String>,
    follow: bool,
    last: Option<usize>,
    level: Option<LogLevel>,
    needle: Option<String>,
) {
    if last == Some(0) {
        eprintln!("error: last must be at least 1");
        return;
    }
    let n = last.unwrap_or(DEFAULT_LOG_LAST);
    let filtered = level.is_some() || needle.is_some();
    let log_socket = match watchdog_client::resolve(watchdog_socket, ServiceRef::Log).await {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!("nos-logd is not running");
            return;
        }
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
            return;
        }
    };

    if !follow {
        // Unfiltered: the daemon caps the reply. Filtered: fetch all, filter,
        // then trim, so `last 20 level error` returns 20 errors.
        let limit = (!filtered).then_some(n);
        match log_client::get_logs(&log_socket, source, limit).await {
            Ok(logs) => {
                let logs = if filtered {
                    let kept = logs
                        .into_iter()
                        .filter(|e| wanted(e, level, needle.as_deref()))
                        .collect();
                    trim(kept, n)
                } else {
                    logs
                };
                println!("{}", format::render_log_entries(&logs));
            }
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
        return;
    }

    let mut reader = match log_client::tail(&log_socket, source).await {
        Ok(reader) => reader,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
            return;
        }
    };
    println!("-- following nos-logd, press Ctrl-C to stop --");
    loop {
        tokio::select! {
            event = reader.next() => match event {
                Some(Ok(LogEvent::Logs(logs))) => {
                    let kept = logs.into_iter().filter(|e| wanted(e, level, needle.as_deref())).collect();
                    println!("{}", format::render_log_entries(&trim(kept, n)));
                }
                Some(Ok(LogEvent::Line(entry))) => {
                    if wanted(&entry, level, needle.as_deref()) {
                        println!("{}", format::render_log_entry(&entry));
                    }
                }
                Some(Ok(LogEvent::Error(msg))) => {
                    eprintln!("error: {}", format::sanitize(&msg));
                    break;
                }
                Some(Err(e)) => {
                    eprintln!("error: {}", format::sanitize(&e.to_string()));
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

/// `show log` shows this many entries unless `last <n>` says otherwise.
const DEFAULT_LOG_LAST: usize = 200;

/// Level (minimum severity) and `match` (case-insensitive, over the rendered
/// line the user sees: time, level name and all).
fn wanted(entry: &LogEntry, level: Option<LogLevel>, needle: Option<&str>) -> bool {
    entry.matches(level, None)
        && needle.is_none_or(|n| {
            format::render_log_entry(entry)
                .to_lowercase()
                .contains(&n.to_lowercase())
        })
}

/// The last `n` entries.
fn trim(mut entries: Vec<LogEntry>, n: usize) -> Vec<LogEntry> {
    entries.drain(..entries.len().saturating_sub(n));
    entries
}

/// Fetches the running config fresh (like every other one-shot command) for
/// the list of configured `BgpInstance`s (only `instance` when given),
/// resolves each one's `nos-bgpd` via the watchdog broker, and queries each
/// independently — an unreachable instance prints its own line rather than
/// aborting the whole command, matching `show_route`/`show_interface`'s
/// per-command resolve-then-query shape.
async fn show_bgp_summary(config_socket: &Path, watchdog_socket: &Path, only: Option<&str>) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
            return;
        }
    };

    if cfg.bgp_instances.is_empty() {
        println!("no bgp instances configured");
        return;
    }

    if let Some(n) = only
        && !cfg.bgp_instances.iter().any(|i| i.name == n)
    {
        eprintln!("bgp instance '{}' not found", format::sanitize_line(n));
        return;
    }
    for instance in cfg
        .bgp_instances
        .iter()
        .filter(|i| only.is_none_or(|n| i.name == n))
    {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::BgpInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(bgp_socket)) => match bgp_client::get_summary(&bgp_socket).await {
                Ok(peers) => {
                    let name = format::sanitize_line(&instance.name);
                    println!(
                        "bgp instance {name}, router-id {}, AS {}",
                        instance.router_id, instance.asn
                    );
                    emit(&peers, &format!("bgp instance {name}: no peers configured"));
                }
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            },
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show bgp evpn` — same shape as `show_bgp_summary`, asking each instance
/// for its received EVPN routes instead of its peer summaries.
async fn show_bgp_evpn(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show bgp flowspec` — same shape as `show_bgp_evpn`.
async fn show_bgp_flowspec(
    config_socket: &Path,
    watchdog_socket: &Path,
    family: Option<nos_proto::AddressFamily>,
    vrf: Option<&str>,
) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
                    bgp_client::for_each_flowspec_routes_page(&bgp_socket, family, vrf, |page| {
                        out.page(page.is_empty(), || format::render_bgp_flowspec_lines(page));
                    })
                    .await;
                out.finish(walked, &format::render_bgp_flowspec(&instance.name, &[]));
            }
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show bgp routes` — same shape as `show_bgp_evpn`.
async fn show_bgp_routes(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show bgp rpki` — same shape as `show_bgp_evpn`.
async fn show_bgp_rpki(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
                Ok(caches) if caches.is_empty() => {
                    println!("bgp instance {}: no rpki caches", instance.name);
                }
                Ok(caches) => {
                    println!("bgp instance {}:", instance.name);
                    emit(&caches, "");
                }
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            },
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show bgp bmp` — same shape as `show_bgp_evpn`.
async fn show_bgp_bmp(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            Ok(Some(bgp_socket)) => match bgp_client::get_bmp_status(&bgp_socket, &instance.name)
                .await
            {
                Ok(stations) => println!("{}", format::render_bgp_bmp(&instance.name, &stations)),
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            },
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show ospf neigh` — fetches the running config for the list of
/// `OspfInstance`s, resolves each one's `nos-ospfd` via the watchdog broker,
/// and queries each independently — mirrors `show_bgp_summary` exactly,
/// including its per-instance "not running" handling.
async fn show_ospf_neigh(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
                Ok(neighbors) if neighbors.is_empty() => {
                    println!("ospf instance {}: no ospf links configured", instance.name);
                }
                Ok(neighbors) => {
                    println!("ospf instance {}:", instance.name);
                    emit(&neighbors, "");
                }
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            },
            Ok(None) => println!("ospf instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show ospf interface` (#1438): per instance, the running interfaces.
async fn show_ospf_interface(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            Ok(Some(socket)) => match ospf_client::get_interfaces(&socket).await {
                Ok(interfaces) => {
                    println!("ospf instance {}:", instance.name);
                    emit(&interfaces, "no ospf interfaces running");
                }
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            },
            Ok(None) => println!("ospf instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show ospfv3 interface` (#1438): per instance, the running interfaces.
async fn show_ospfv3_interface(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            Ok(Some(socket)) => match ospfv3_client::get_interfaces(&socket).await {
                Ok(interfaces) => {
                    println!("ospfv3 instance {}:", instance.name);
                    emit(&interfaces, "no ospfv3 interfaces running");
                }
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            },
            Ok(None) => println!("ospfv3 instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// Validate `show ospf[v3] database [<type> [<adv-router>]]`'s arguments
/// before any daemon is queried.
fn parse_db_filter<T>(
    lsa_type: Option<&str>,
    adv_router: Option<&str>,
    parse_type: fn(&str) -> Result<T, String>,
) -> Result<(Option<T>, Option<std::net::Ipv4Addr>), String> {
    let ty = lsa_type.map(parse_type).transpose()?;
    let router = adv_router
        .map(|r| {
            r.parse()
                .map_err(|_| format!("invalid advertising router '{r}' (an IPv4 router id)"))
        })
        .transpose()?;
    Ok((ty, router))
}

/// `show ospf database` — mirrors `show_ospf_neigh` exactly, one instance at
/// a time, reporting a not-running instance individually rather than
/// aborting the whole command.
async fn show_ospf_database(
    config_socket: &Path,
    watchdog_socket: &Path,
    lsa_type: Option<&str>,
    adv_router: Option<&str>,
) {
    let filter = match parse_db_filter(lsa_type, adv_router, format::parse_ospf_lsa_type) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e));
            return;
        }
    };
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
                    let text = if filter == (None, None) {
                        format::render_ospf_database(&instance.name, &entries)
                    } else {
                        let kept = format::filter_ospf_database(&entries, filter.0, filter.1);
                        format::render_ospf_database_filtered(&instance.name, &kept)
                    };
                    println!("{text}");
                }
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            },
            Ok(None) => println!("ospf instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show ospf segment-routing` (#1382) — mirrors `show_ospf_database`.
async fn show_ospf_segment_routing(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            Ok(Some(ospf_socket)) => match ospf_client::get_segment_routing(&ospf_socket).await {
                Ok(sr) => println!(
                    "{}",
                    format::render_ospf_segment_routing(&instance.name, &sr)
                ),
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            },
            Ok(None) => println!("ospf instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show ospfv3 neigh` — mirrors `show_ospf_neigh` exactly, over every
/// configured `Ospfv3Instance`.
async fn show_ospfv3_neigh(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
                Ok(neighbors) if neighbors.is_empty() => {
                    println!(
                        "ospfv3 instance {}: no ospfv3 links configured",
                        instance.name
                    );
                }
                Ok(neighbors) => {
                    println!("ospfv3 instance {}:", instance.name);
                    emit(&neighbors, "");
                }
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            },
            Ok(None) => println!("ospfv3 instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `show ospfv3 database` — mirrors `show_ospf_database` exactly, over every
/// configured `Ospfv3Instance`.
async fn show_ospfv3_database(
    config_socket: &Path,
    watchdog_socket: &Path,
    lsa_type: Option<&str>,
    adv_router: Option<&str>,
) {
    let filter = match parse_db_filter(lsa_type, adv_router, format::parse_ospfv3_lsa_type) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e));
            return;
        }
    };
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
                    let text = if filter == (None, None) {
                        format::render_ospfv3_database(&instance.name, &entries)
                    } else {
                        let kept = format::filter_ospfv3_database(&entries, filter.0, filter.1);
                        format::render_ospfv3_database_filtered(&instance.name, &kept)
                    };
                    println!("{text}");
                }
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            },
            Ok(None) => println!("ospfv3 instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        }
    }
}

/// `clear bgp <instance> <peer> [soft-in]`. Targets one named instance
/// (errors clearly if it isn't in the running config), unlike
/// `show_bgp_summary`'s all-instances loop.
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
                Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
            }
        }
        Ok(Some(bgp_socket)) => match bgp_client::clear_peer(&bgp_socket, peer).await {
            Ok(true) => println!("cleared {peer}"),
            Ok(false) => eprintln!("error: no peer {peer} on '{instance}'"),
            Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
        },
        Ok(None) => println!("bgp instance '{instance}' is not running"),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
    }
}

/// Whether to emit ANSI color/highlight codes for `diff`: only when stdout
/// is an actual terminal, and never when `NO_COLOR` is set (the informal
/// but widely-honored convention — <https://no-color.org>).
#[allow(clippy::disallowed_methods, reason = "NO_COLOR convention")]
fn use_color() -> bool {
    io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

async fn diff(mode: &Mode, socket: &Path) {
    let transaction = current_transaction(mode);
    match client::diff_transaction(socket, &transaction).await {
        Ok(d) if d.is_empty() => println!("no changes"),
        Ok(d) => println!("{}", format::render_diff(&d, use_color())),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
    }
}

/// `show aaa users`, `allocate aaa user`, `clear aaa user` (#1374): admin-only requests to
/// `nos-configd`; the daemon's refusal text is printed as is.
async fn aaa_users(socket: &Path, action: Resolved) {
    let (req, name) = match action {
        Resolved::AllocateAaaUser { name } => (
            Request::AdminAllocateExternalUser { name: name.clone() },
            name,
        ),
        Resolved::ClearAaaUser { name } => {
            (Request::ClearExternalUser { name: name.clone() }, name)
        }
        _ => (Request::ListExternalUsers, String::new()),
    };
    let clear = matches!(req, Request::ClearExternalUser { .. });
    match client::external_users(socket, req).await {
        Ok(Event::ExternalUsers(l)) if l.is_empty() => println!("no external users"),
        Ok(Event::ExternalUsers(l)) => {
            println!("{}", format::render_aaa_users(&l));
        }
        Ok(Event::ExternalUser { uid }) if clear => {
            println!("{name}: entry removed, uid {uid} stays reserved");
        }
        Ok(Event::ExternalUser { uid }) => println!("{name}: uid {uid}"),
        Ok(_) => eprintln!("error: unexpected reply"),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn show_history(socket: &Path) {
    match client::list_history(socket).await {
        Ok(h) if h.is_empty() => println!("no history yet"),
        Ok(h) => {
            println!(
                "{:>5}  {:<20}  {:<10}  actor",
                "index", "replaced (UTC)", "kind"
            );
            for e in h {
                println!(
                    "{:>5}  {:<20}  {:<10}  {}",
                    e.index,
                    format::utc(e.time),
                    e.kind,
                    e.actor
                );
            }
        }
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
    }
}

/// `show configuration diff <from> [<to>]`. Two reads, no lock: a commit landing
/// between them shifts the indexes (documented, #1416).
async fn show_config_diff(socket: &Path, from: u32, to: u32) {
    let res = async {
        let old = client::get_history_config(socket, from).await?;
        let new = client::get_history_config(socket, to).await?;
        Ok::<_, client::ClientError>(diff_text(&old, &new, use_color()))
    }
    .await;
    match res {
        Ok(t) => println!("{t}"),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
    }
}

/// The rendered diff from `old` to `new`, or `no changes`.
pub fn diff_text(old: &nos_proto::Config, new: &nos_proto::Config, color: bool) -> String {
    let d = nos_proto::diff_configs(old, new);
    if d.is_empty() {
        "no changes".to_string()
    } else {
        format::render_diff(&d, color)
    }
}

async fn rollback(socket: &Path, n: u32) {
    match client::rollback(socket, n).await {
        Ok((warnings, unsaved)) => {
            let note = if unsaved { " (not saved)" } else { "" };
            println!("rolled back {n} commit(s){note}");
            for w in warnings {
                eprintln!("warning: {}", format::sanitize(&w));
            }
        }
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
    }
}

async fn save_running_config(socket: &Path) {
    match client::save_running_config(socket).await {
        Ok(()) => println!("configuration saved"),
        Err(e) => eprintln!("error: {}", format::sanitize(&e.to_string())),
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
                eprintln!("error: {}", format::sanitize(&e.to_string()));
                return mode;
            }
        }
    }
    let mut path = edit.navigate.map_or(path, session::Path::from);
    // One read after the writes (#774): does the position still exist?
    let snap = match client::get_transaction(socket, &transaction).await {
        Ok(snap) => snap,
        Err(e) => {
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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

/// Edits `source` in the built-in editor (`crate::editor`; see root
/// `CLAUDE.md`'s "nos-cli editing UX"). `None` means cancelled or the editor
/// could not run (reported to stderr); the caller applies nothing.
fn edit_source_text(source: &str) -> Option<String> {
    match crate::editor::edit(source) {
        Ok(edited) => edited,
        Err(e) => {
            eprintln!(
                "error: {e}; edit discarded; use 'show source' and 'set source line <n> <text>'"
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
    let Some(edited) = edit_source_text(&current) else {
        return mode;
    };
    match compile_against_transaction(socket, &transaction, &edited).await {
        Some(Ok(())) => apply_policy_source(mode, socket, name, edited).await,
        Some(Err(e)) => {
            eprintln!(
                "policy did not compile, edit discarded: {}",
                format::sanitize(&e.to_string())
            );
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
        eprintln!("error: {}", format::sanitize(&e));
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
                "warning: policy does not compile yet: {} (commit will refuse it until fixed)",
                format::sanitize(&e.to_string())
            );
            apply_policy_source(mode, socket, name, new_source).await
        }
        None => mode,
    }
}

/// Confirmation line, then one `warning:` line per commit warning on stderr.
fn print_committed(transaction: &str, warnings: &[String], unsaved: bool) {
    let note = if unsaved { " (not saved)" } else { "" };
    println!("transaction '{transaction}' committed{note}");
    for w in warnings {
        eprintln!("warning: {}", format::sanitize(w));
    }
}

async fn commit(mode: Mode, socket: &Path, confirm_secs: Option<u32>) -> Mode {
    let transaction = current_transaction(&mode);
    match client::commit_confirmed(socket, &transaction, confirm_secs).await {
        Ok((warnings, unsaved)) => {
            print_committed(&transaction, &warnings, unsaved);
            if let Some(s) = confirm_secs {
                println!(
                    "rolls back in {} min unless confirmed: `commit` or `commit confirm` (admin)",
                    s / 60
                );
            }
            Mode::Operational
        }
        Err(e) => {
            eprintln!(
                "error: {} (transaction left open — fix and retry)",
                format::sanitize(&e.to_string())
            );
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
            eprintln!("error: {}", format::sanitize(&e.to_string()));
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
mod log_filter_tests {
    use super::*;

    fn entry(level: LogLevel, msg: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: 1_700_000_000_123,
            level,
            source: "nos-ribd[rt1]".into(),
            target: "nos_rib".into(),
            message: msg.into(),
            fields: vec![("peer".into(), "192.0.2.9".into())],
        }
    }

    #[test]
    fn wanted_level_is_a_minimum() {
        let e = entry(LogLevel::Warn, "x");
        assert!(wanted(&e, None, None));
        assert!(wanted(&e, Some(LogLevel::Info), None));
        assert!(wanted(&e, Some(LogLevel::Warn), None));
        assert!(!wanted(&e, Some(LogLevel::Error), None));
    }

    #[test]
    fn wanted_needle_covers_the_rendered_line() {
        let e = entry(LogLevel::Warn, "Session Established");
        // timestamp text, level name, source, message (any case), field value
        for n in [
            "2023-11-14T22:13:20",
            "warn",
            "RIBD[rt1]",
            "established",
            "192.0.2.9",
        ] {
            assert!(wanted(&e, None, Some(n)), "{n}");
        }
        assert!(!wanted(&e, None, Some("nosuchthing")));
        assert!(!wanted(&e, Some(LogLevel::Error), Some("warn")));
    }

    #[test]
    fn trim_keeps_the_last_n() {
        let es: Vec<_> = (0..5)
            .map(|i| entry(LogLevel::Info, &i.to_string()))
            .collect();
        let msgs = |v: Vec<LogEntry>| v.into_iter().map(|e| e.message).collect::<Vec<_>>();
        assert_eq!(msgs(trim(es.clone(), 2)), ["3", "4"]);
        assert_eq!(msgs(trim(es.clone(), 9)).len(), 5);
        assert_eq!(trim(es, 0).len(), 0);
    }
}

#[cfg(test)]
mod diff_text_tests {
    use super::diff_text;
    use nos_proto::Config;

    fn cfg(h: &str) -> Config {
        Config {
            hostname: h.into(),
            ..Config::default()
        }
    }

    #[test]
    fn direction_and_empty() {
        let (a, b) = (cfg("old"), cfg("new"));
        let t = diff_text(&a, &b, false);
        assert!(t.find("old").unwrap() < t.find("new").unwrap(), "{t}");
        let r = diff_text(&b, &a, false);
        assert!(r.find("new").unwrap() < r.find("old").unwrap(), "{r}");
        assert_eq!(diff_text(&a, &a, false), "no changes");
    }
}

#[cfg(test)]
mod lldp_filter_tests {
    use super::filter_lldp_interface;
    use nos_proto::LldpNeighbor;

    fn n(i: &str) -> LldpNeighbor {
        LldpNeighbor {
            local_interface: i.into(),
            ..Default::default()
        }
    }

    #[test]
    fn keeps_only_the_exact_interface() {
        let all = vec![n("eth0"), n("eth1"), n("eth0\nFORGED")];
        assert_eq!(filter_lldp_interface(all.clone(), "eth0").len(), 1);
        assert_eq!(filter_lldp_interface(all, "eth9").len(), 0);
    }
}
