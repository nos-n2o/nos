use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use ipnet::{IpNet, Ipv6Net};
use nos_proto::{DiffScope, Event, NetworkType, OspfCryptoAlgorithm, ServiceRef};
use nos_rpl::CompiledPolicy;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::interface_client;
use crate::link::{LinkConfig, LinkManager, DEFAULT_HELPER_MAX_GRACE_PERIOD};
use crate::link_client::{self, Gate, LinkTable};
use crate::packet;
use nos_daemon::config;
use nos_daemon::watchdog;

/// Fixed reconnect delay — same cadence as every other config-subscribing
/// consumer in this codebase, `ospf::reconcile::RECONNECT_DELAY` included.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// How often to re-apply desired state even without a new config diff —
/// same reasoning/cadence as `ospf::reconcile::REAPPLY_INTERVAL`: a link's
/// VRF/local-address/link-local-address readiness is an external condition
/// no config commit signals.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

/// Coalesces a burst of link events (a veth delete/create pair) into one resync.
const LINK_DEBOUNCE: Duration = Duration::from_millis(200);

/// What `resync` remembers between passes (owned by `run`, single task).
#[derive(Default)]
struct State {
    /// Kernel devices of every attach point resolved by the last resync, before
    /// gating: an absent device that returns must still be watched.
    watched: HashSet<String>,
    /// Gate of each watched device as of the last resync.
    signature: Vec<(String, Gate)>,
    /// Links skipped for a down kernel device, with the reason (log on change).
    down: HashMap<String, &'static str>,
    /// Links kept on their running values despite a failed lookup.
    degraded: HashSet<String>,
}

/// Gates of `watched` in `table`, sorted: the resync trigger compares these.
fn signature(table: &LinkTable, watched: &HashSet<String>) -> Vec<(String, Gate)> {
    let mut sig: Vec<_> = watched
        .iter()
        .map(|n| (n.clone(), link_client::gate(table, n)))
        .collect();
    sig.sort_by(|a, b| a.0.cmp(&b.0));
    sig
}

struct Ctx {
    config_socket: PathBuf,
    watchdog_socket: PathBuf,
    instance: String,
    links: Arc<LinkManager>,
    routing_table_tx: watch::Sender<Option<String>>,
    link_rx: watch::Receiver<LinkTable>,
}

/// Runs until `shutdown` fires — mirrors `ospf::reconcile::run` exactly,
/// subscribed to `Ospfv3Instances` instead of `OspfInstances`.
pub async fn run(
    config_socket: PathBuf,
    watchdog_socket: PathBuf,
    instance: String,
    links: Arc<LinkManager>,
    routing_table_tx: watch::Sender<Option<String>>,
    link_rx: watch::Receiver<LinkTable>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ctx = Ctx {
        config_socket,
        watchdog_socket,
        instance,
        links,
        routing_table_tx,
        link_rx,
    };
    let mut state = State::default();
    let mut link_open = true;
    while !*shutdown.borrow() {
        match config::subscribe_diff(
            &ctx.config_socket,
            vec![DiffScope::Ospfv3Instances, DiffScope::Admin],
        )
        .await
        {
            Ok(mut reader) => {
                info!(instance = %ctx.instance, "connected to nos-configd diff stream");
                let mut reapply = tokio::time::interval(REAPPLY_INTERVAL);
                reapply.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                reapply.tick().await;
                resync(&mut ctx, &mut state).await;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => resync(&mut ctx, &mut state).await,
                            Some(Ok(_)) => {}
                            Some(Err(e)) => {
                                warn!(error = %e, "error reading diff stream, reconnecting");
                                break;
                            }
                            None => {
                                warn!("diff stream closed, reconnecting");
                                break;
                            }
                        },
                        _ = reapply.tick() => resync(&mut ctx, &mut state).await,
                        changed = ctx.link_rx.changed(), if link_open => {
                            if changed.is_err() {
                                link_open = false;
                                continue;
                            }
                            tokio::time::sleep(LINK_DEBOUNCE).await;
                            let table = ctx.link_rx.borrow_and_update().clone();
                            if signature(&table, &state.watched) != state.signature {
                                resync(&mut ctx, &mut state).await;
                            }
                        }
                        _ = shutdown.changed() => break,
                    }
                }
            }
            Err(e) => warn!(
                error = %e,
                socket = %ctx.config_socket.display(),
                "failed to connect to nos-configd"
            ),
        }

        if *shutdown.borrow() {
            break;
        }
        if wait_or_shutdown(RECONNECT_DELAY, &mut shutdown).await {
            break;
        }
    }

    ctx.links.shutdown().await;
    info!(instance = %ctx.instance, "reconciliation loop stopped");
}

/// RFC 3623 helper cap on a neighbor's grace period, seconds
/// (`graceful-restart helper max-grace-period`, default 1800).
fn helper_cap(cfg: &nos_proto::Config, instance: &str) -> u32 {
    cfg.ospfv3_instances
        .iter()
        .find(|i| i.name == instance)
        .and_then(|i| i.graceful_restart_helper_max_grace_period)
        .unwrap_or(DEFAULT_HELPER_MAX_GRACE_PERIOD)
}

/// What one resync pass reads (shared, immutable).
#[derive(Clone, Copy)]
struct Env<'a> {
    cfg: &'a nos_proto::Config,
    watchdog_socket: &'a Path,
    instance: &'a str,
    links: &'a LinkManager,
    table: &'a LinkTable,
    state: &'a State,
}

/// What one resync pass accumulates.
struct Wanted {
    watched: HashSet<String>,
    next_down: HashMap<String, &'static str>,
    next_degraded: HashSet<String>,
    desired_links: Vec<LinkConfig>,
    bfd_wants: HashMap<String, nos_proto::schema::BfdProfile>,
    desired_loopback_prefixes: HashMap<std::net::Ipv4Addr, Vec<(Ipv6Net, u16)>>,
}

/// One profile of one area, with the values every attach point shares.
struct ProfileCtx<'a> {
    area: &'a nos_proto::Ospfv3Area,
    profile: &'a nos_proto::schema::Ospfv3Profile,
    hello_interval: u16,
    dead_interval: u16,
    priority: u8,
    cost: u16,
    auth: Option<packet::TrailerAuth>,
}

/// The `subinterface` attach points of one profile, split out of `resync` for
/// length (#425).
async fn resolve_subinterface_links(env: &Env<'_>, d: &mut Wanted, pc: &ProfileCtx<'_>) {
    let Env {
        cfg,
        watchdog_socket,
        instance,
        links,
        table,
        state,
        ..
    } = *env;
    let Wanted {
        watched,
        next_down,
        next_degraded,
        desired_links,
        bfd_wants,
        ..
    } = d;
    let ProfileCtx {
        area,
        profile,
        hello_interval,
        dead_interval,
        priority,
        cost,
        ..
    } = pc;
    let hello_interval = *hello_interval;
    let dead_interval = *dead_interval;
    let priority = *priority;
    let cost = *cost;
    for attach in subinterface_attach_points(cfg, &profile.name) {
        let link_name = attach.display_name();
        let Some(routing_table) = &attach.routing_table else {
            warn!(
                instance = %instance, link = %link_name,
                "ospfv3 profile attached to a subinterface with no routing-table, skipping"
            );
            continue;
        };
        let kernel_interface = subinterface_kernel_interface(&attach.interface, attach.tag);
        watched.insert(kernel_interface.clone());
        let Some(ifindex) = gate_link(state, next_down, table, &link_name, &kernel_interface)
        else {
            continue;
        };
        let vrf = resolve_vrf(watchdog_socket, routing_table).await;
        let link = resolve_local_address(watchdog_socket, &attach.interface, attach.tag).await;
        let running = if attach.has_address {
            links.running_config(&link_name).await
        } else {
            None
        };
        let resolved = Resolved {
            vrf,
            link,
            kernel_interface: Some(kernel_interface),
        };
        let Some((m, fell_back)) = merge_running(resolved, running.as_ref()) else {
            warn!(instance = %instance, link = %link_name, "ospfv3 link's vrf/local address not resolvable yet");
            continue;
        };
        let Some(interface_id) = pick_interface_id(ifindex, &m.kernel_interface, running.as_ref())
        else {
            warn!(instance = %instance, link = %link_name, kernel_interface = %m.kernel_interface, "ospfv3 link's kernel interface not present yet");
            continue;
        };
        note_fallback(state, next_degraded, &link_name, &fell_back);
        if let Some(p) = bfd_profile(cfg, profile.bfd.as_deref()) {
            bfd_wants.insert(link_name.clone(), p);
        }
        desired_links.push(LinkConfig {
            attach_point: link_name,
            area_id: area.area_id,
            hello_interval,
            dead_interval,
            vrf: m.vrf,
            kernel_interface: m.kernel_interface,
            interface_id,
            link_local_address: m.link_local_address,
            prefix: m.prefix,
            cost,
            network_type: profile.network_type.unwrap_or(NetworkType::PointToPoint),
            priority,
            mtu: resolve_effective_mtu(profile, m.mtu),
            mtu_ignore: profile.mtu_ignore,
            auth: pc.auth.clone(),
            instance_id: profile.instance_id.unwrap_or(0),
            helper_max_grace_period: helper_cap(cfg, instance),
        });
    }
}

/// The `loopback` attach points of one profile, split out of `resync` for
/// length (#425).
async fn resolve_loopback_links(env: &Env<'_>, d: &mut Wanted, pc: &ProfileCtx<'_>) {
    let Env {
        cfg,
        watchdog_socket,
        instance,
        ..
    } = *env;
    let Wanted {
        desired_loopback_prefixes,
        ..
    } = d;
    let ProfileCtx {
        area,
        profile,
        cost,
        ..
    } = pc;
    let cost = *cost;
    for attach in loopback_attach_points(cfg, &profile.name) {
        let Some(prefix) = resolve_loopback_prefix(watchdog_socket, &attach.interface).await else {
            warn!(
                instance = %instance, interface = %attach.interface,
                "ospfv3 loopback prefix not resolvable yet"
            );
            continue;
        };
        desired_loopback_prefixes
            .entry(area.area_id)
            .or_default()
            .push((prefix, cost));
    }
}

/// The `broadcast_domain` attach points of one profile, split out of `resync` for
/// length (#425).
async fn resolve_broadcast_domain_links(env: &Env<'_>, d: &mut Wanted, pc: &ProfileCtx<'_>) {
    let Env {
        cfg,
        watchdog_socket,
        instance,
        links,
        table,
        state,
        ..
    } = *env;
    let Wanted {
        watched,
        next_down,
        next_degraded,
        desired_links,
        bfd_wants,
        ..
    } = d;
    let ProfileCtx {
        area,
        profile,
        hello_interval,
        dead_interval,
        priority,
        cost,
        ..
    } = pc;
    let hello_interval = *hello_interval;
    let dead_interval = *dead_interval;
    let priority = *priority;
    let cost = *cost;
    for attach in broadcast_domain_attach_points(cfg, &profile.name) {
        let link_name = attach.display_name();
        let Some(routing_table) = &attach.routing_table else {
            warn!(
                instance = %instance, link = %link_name,
                "ospfv3 profile attached to a broadcast domain with no routing-table, skipping"
            );
            continue;
        };
        let vrf = resolve_vrf(watchdog_socket, routing_table).await;
        let bridge = resolve_broadcast_domain(watchdog_socket, &attach.name).await;
        let running = if attach.has_address {
            links.running_config(&link_name).await
        } else {
            None
        };
        let (link, bridge_name) = match bridge {
            Some((l, b)) => (Some(l), Some(b)),
            None => (None, None),
        };
        let resolved = Resolved {
            vrf,
            link,
            kernel_interface: bridge_name,
        };
        let Some((m, fell_back)) = merge_running(resolved, running.as_ref()) else {
            warn!(instance = %instance, link = %link_name, "ospfv3 link's vrf/local address/bridge not resolvable yet");
            continue;
        };
        watched.insert(m.kernel_interface.clone());
        let Some(ifindex) = gate_link(state, next_down, table, &link_name, &m.kernel_interface)
        else {
            continue;
        };
        let Some(interface_id) = pick_interface_id(ifindex, &m.kernel_interface, running.as_ref())
        else {
            warn!(instance = %instance, link = %link_name, kernel_interface = %m.kernel_interface, "ospfv3 link's kernel bridge not present yet");
            continue;
        };
        note_fallback(state, next_degraded, &link_name, &fell_back);
        if let Some(p) = bfd_profile(cfg, profile.bfd.as_deref()) {
            bfd_wants.insert(link_name.clone(), p);
        }
        desired_links.push(LinkConfig {
            attach_point: link_name,
            area_id: area.area_id,
            hello_interval,
            dead_interval,
            vrf: m.vrf,
            kernel_interface: m.kernel_interface,
            interface_id,
            link_local_address: m.link_local_address,
            prefix: m.prefix,
            cost,
            network_type: profile.network_type.unwrap_or(NetworkType::Broadcast),
            priority,
            mtu: resolve_effective_mtu(profile, None),
            mtu_ignore: profile.mtu_ignore,
            auth: pc.auth.clone(),
            instance_id: profile.instance_id.unwrap_or(0),
            helper_max_grace_period: helper_cap(cfg, instance),
        });
    }
}

async fn resync(ctx: &mut Ctx, state: &mut State) {
    let Ctx {
        config_socket,
        watchdog_socket,
        instance,
        links,
        routing_table_tx,
        link_rx,
    } = &*ctx;
    let table = link_rx.borrow().clone();
    let watched = HashSet::new();
    let next_down: HashMap<String, &'static str> = HashMap::new();
    let next_degraded = HashSet::new();
    let cfg = match config::fetch_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
            return;
        }
    };

    let Some(own) = cfg.ospfv3_instances.iter().find(|i| i.name == *instance) else {
        warn!(instance = %instance, "own ospfv3 instance missing from running config");
        let _ = routing_table_tx.send(None);
        return;
    };
    let _ = routing_table_tx.send(own.routing_table.clone());
    info!(
        instance = %instance,
        router_id = %own.router_id,
        routing_table = ?own.routing_table,
        area_count = own.areas.len(),
        extended_lsa = own.extended_lsa,
        graceful_restart_grace_period = ?own.graceful_restart_grace_period,
        redistribute_policy = ?own.redistribute_policy,
        "ospfv3 instance config resolved"
    );
    links.set_extended_lsa(own.extended_lsa);
    links.set_graceful_restart(own.graceful_restart_grace_period);

    let env = Env {
        cfg: &cfg,
        watchdog_socket,
        instance,
        links,
        table: &table,
        state,
    };
    let mut wanted = Wanted {
        watched,
        next_down,
        next_degraded,
        desired_links: Vec::new(),
        bfd_wants: HashMap::new(),
        desired_loopback_prefixes: HashMap::new(),
    };

    for area in &own.areas {
        info!(
            instance = %instance,
            area = %area.area_id,
            profile_count = area.profiles.len(),
            "ospfv3 area resolved"
        );
        for profile in &area.profiles {
            let interfaces = attach_points_for(&cfg, &profile.name);
            info!(
                instance = %instance,
                area = %area.area_id,
                profile = %profile.name,
                interfaces = ?interfaces,
                cost = ?profile.cost,
                "ospfv3 profile resolved"
            );

            let hello_interval = profile
                .hello_interval
                .unwrap_or(nos_proto::HELLO_INTERVAL_DEFAULT);
            let dead_interval = profile
                .dead_interval
                .unwrap_or(nos_proto::DEAD_INTERVAL_DEFAULT);
            let priority = profile.priority.unwrap_or(nos_proto::PRIORITY_DEFAULT);
            let cost = profile.cost.unwrap_or(1);
            // Fail closed: a dangling label (commit validation prevents it)
            // must never start the link unauthenticated.
            let auth = match resolve_auth(profile, &cfg) {
                Ok(a) => a,
                Err(label) => {
                    error!(instance = %instance, profile = %profile.name, label = %label, "ospfv3 profile references an unknown admin key, not starting its links");
                    continue;
                }
            };
            let pc = ProfileCtx {
                area,
                profile,
                hello_interval,
                dead_interval,
                priority,
                cost,
                auth,
            };
            resolve_subinterface_links(&env, &mut wanted, &pc).await;
            resolve_loopback_links(&env, &mut wanted, &pc).await;
            resolve_broadcast_domain_links(&env, &mut wanted, &pc).await;
        }
    }

    links
        .set_redistribute_policy(resolve_redistribute_policy(
            &cfg,
            own.redistribute_policy.as_deref(),
        ))
        .await;
    let Wanted {
        watched,
        next_down,
        next_degraded,
        desired_links,
        bfd_wants,
        desired_loopback_prefixes,
    } = wanted;
    links.set_bfd(bfd_wants);
    links
        .reconcile(desired_links, desired_loopback_prefixes, own.router_id)
        .await;
    state.signature = signature(&table, &watched);
    state.watched = watched;
    state.down = next_down;
    state.degraded = next_degraded;
}

/// The named BFD profile (validation guarantees it exists).
fn bfd_profile(
    cfg: &nos_proto::Config,
    name: Option<&str>,
) -> Option<nos_proto::schema::BfdProfile> {
    let name = name?;
    cfg.bfd_profiles.iter().find(|p| p.name == name).cloned()
}

/// What a resync resolved for one attach point, each `None` when the lookup
/// failed this pass.
struct Resolved {
    vrf: Option<String>,
    link: Option<ResolvedLink>,
    kernel_interface: Option<String>,
}

struct Merged {
    vrf: String,
    link_local_address: Ipv6Addr,
    prefix: Ipv6Net,
    mtu: Option<u32>,
    kernel_interface: String,
}

/// Fills every unresolved value from the running link (a lookup against a
/// restarting `nos-interfaced`/`nos-ribd` must not tear a link down). The
/// names of what fell back are returned; `None` when something is still
/// missing (no running link to fall back on).
fn merge_running(r: Resolved, running: Option<&LinkConfig>) -> Option<(Merged, Vec<&'static str>)> {
    let mut fell_back = Vec::new();
    let vrf = if let Some(v) = r.vrf {
        v
    } else {
        fell_back.push("vrf");
        running?.vrf.clone()
    };
    let (link_local_address, prefix, mtu) = if let Some(l) = r.link {
        (l.link_local_address, l.prefix, Some(l.mtu))
    } else {
        fell_back.push("address");
        let c = running?;
        // The running effective MTU stands in for an unresolved parent MTU
        // (a profile override still wins in `resolve_effective_mtu`).
        (c.link_local_address, c.prefix, Some(u32::from(c.mtu)))
    };
    let kernel_interface = if let Some(k) = r.kernel_interface {
        k
    } else {
        fell_back.push("bridge");
        running?.kernel_interface.clone()
    };
    Some((
        Merged {
            vrf,
            link_local_address,
            prefix,
            mtu,
            kernel_interface,
        },
        fell_back,
    ))
}

/// The RFC 5340 Interface ID: the stream's ifindex, else (ungated, 0) a local
/// `if_nametoindex`, else the running link's.
fn pick_interface_id(
    ifindex: u32,
    kernel_interface: &str,
    running: Option<&LinkConfig>,
) -> Option<u32> {
    if ifindex != 0 {
        return Some(ifindex);
    }
    kernel_ifindex(kernel_interface).or_else(|| running.map(|c| c.interface_id))
}

/// Applies the link stream's verdict on `kernel_interface` to `link`: `None`
/// (skip, so `reconcile` aborts it) when it is down, else its ifindex (0
/// ungated). Logs on transitions only.
fn gate_link(
    state: &State,
    next_down: &mut HashMap<String, &'static str>,
    table: &LinkTable,
    link: &str,
    kernel_interface: &str,
) -> Option<u32> {
    match link_client::gate(table, kernel_interface) {
        Gate::Down(reason) => {
            if state.down.get(link) != Some(&reason) {
                warn!(link = %link, reason = %reason, "ospfv3 link kernel interface down");
            }
            next_down.insert(link.to_string(), reason);
            None
        }
        Gate::Up(ifindex) => {
            if state.down.contains_key(link) {
                info!(link = %link, ifindex, "ospfv3 link kernel interface up");
            }
            Some(ifindex)
        }
        Gate::Ungated => Some(0),
    }
}

/// Warns once per transition into "kept on the running link's values".
fn note_fallback(
    state: &State,
    next: &mut HashSet<String>,
    link: &str,
    fell_back: &[&'static str],
) {
    if fell_back.is_empty() {
        return;
    }
    if !state.degraded.contains(link) {
        warn!(link = %link, missing = %fell_back.join("|"), "ospfv3 link resolution failed, keeping running link");
    }
    next.insert(link.to_string());
}

/// Compiles the mirrored `Ospfv3Instance.redistribute_policy` (`None` =
/// `accept-all`) — a copy of `ospf::reconcile::resolve_redistribute_policy`.
/// `ponytail:` the third copy (`nos-ospfd` and `nos-bgpd` hold the others,
/// per the star-dependency rule); move it into a shared crate if a fourth
/// appears.
fn resolve_redistribute_policy(
    cfg: &nos_proto::Config,
    redistribute_policy_name: Option<&str>,
) -> Arc<CompiledPolicy> {
    let Some(name) = redistribute_policy_name else {
        return Arc::new(nos_rpl::ACCEPT_ALL.clone());
    };
    if name == nos_rpl::ACCEPT_ALL_NAME {
        return Arc::new(nos_rpl::ACCEPT_ALL.clone());
    }
    if name == nos_rpl::DENY_ALL_NAME {
        return Arc::new(nos_rpl::DENY_ALL.clone());
    }
    let Some(def) = cfg.policy_definitions.iter().find(|p| p.name == name) else {
        // Can't happen in practice — commit-time validation already
        // guarantees this reference exists — but the field is still a plain
        // `Option<String>` on the wire.
        return Arc::new(nos_rpl::DENY_ALL.clone());
    };

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

    match nos_rpl::compile(&def.source, &symbols) {
        Ok(compiled) => Arc::new(compiled),
        Err(_) => Arc::new(nos_rpl::DENY_ALL.clone()), // unreachable post-commit-validation
    }
}

/// Every L3 attach point referencing `profile` by name — mirrors
/// `ospf::reconcile::attach_points_for` exactly, checking `ospfv3_profile`
/// instead of `ospf_profile`.
fn attach_points_for(cfg: &nos_proto::Config, profile: &str) -> Vec<String> {
    let mut points = Vec::new();
    for iface in &cfg.interfaces {
        if iface.ospfv3_profile.as_deref() == Some(profile) {
            points.push(iface.name.clone());
        }
        for sub in &iface.subinterfaces {
            if sub.ospfv3_profile.as_deref() == Some(profile) {
                points.push(format!("{}.{}", iface.name, sub.tag));
            }
        }
    }
    for domain in &cfg.broadcast_domains {
        if domain.ospfv3_profile.as_deref() == Some(profile) {
            points.push(format!("broadcast-domain:{}", domain.name));
        }
    }
    points
}

struct SubinterfaceAttachPoint {
    interface: String,
    tag: u16,
    routing_table: Option<String>,
    /// The config still gives it an IPv6 address: a failed lookup then keeps
    /// the running link, else the attach point is gone as far as we know.
    has_address: bool,
}

impl SubinterfaceAttachPoint {
    fn display_name(&self) -> String {
        format!("{}.{}", self.interface, self.tag)
    }
}

fn subinterface_attach_points(
    cfg: &nos_proto::Config,
    profile: &str,
) -> Vec<SubinterfaceAttachPoint> {
    let mut points = Vec::new();
    for iface in &cfg.interfaces {
        for sub in &iface.subinterfaces {
            if sub.ospfv3_profile.as_deref() == Some(profile) {
                points.push(SubinterfaceAttachPoint {
                    interface: iface.name.clone(),
                    tag: sub.tag,
                    routing_table: sub.routing_table.clone(),
                    has_address: sub.addresses.iter().any(|a| a.address.addr().is_ipv6()),
                });
            }
        }
    }
    points
}

struct BroadcastDomainAttachPoint {
    name: String,
    routing_table: Option<String>,
    /// As `SubinterfaceAttachPoint::has_address`.
    has_address: bool,
}

impl BroadcastDomainAttachPoint {
    fn display_name(&self) -> String {
        format!("broadcast-domain:{}", self.name)
    }
}

fn broadcast_domain_attach_points(
    cfg: &nos_proto::Config,
    profile: &str,
) -> Vec<BroadcastDomainAttachPoint> {
    cfg.broadcast_domains
        .iter()
        .filter(|d| d.ospfv3_profile.as_deref() == Some(profile))
        .map(|d| BroadcastDomainAttachPoint {
            name: d.name.clone(),
            routing_table: d.routing_table.clone(),
            has_address: d.addresses.iter().any(|a| a.address.addr().is_ipv6()),
        })
        .collect()
}

struct LoopbackAttachPoint {
    interface: String,
}

fn loopback_attach_points(cfg: &nos_proto::Config, profile: &str) -> Vec<LoopbackAttachPoint> {
    cfg.interfaces
        .iter()
        .filter(|i| {
            nos_proto::loopback_table_name(&i.name).is_some()
                && i.ospfv3_profile.as_deref() == Some(profile)
        })
        .map(|i| LoopbackAttachPoint {
            interface: i.name.clone(),
        })
        .collect()
}

async fn resolve_vrf(watchdog_socket: &Path, table: &str) -> Option<String> {
    let socket =
        watchdog::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string())).await?;
    crate::rib_client::get_vrf_name(&socket).await
}

/// A link's resolved IPv6 addressing — link-local (Hello/Link-LSA source)
/// and the global/ULA prefix configured on it — plus its real interface
/// MTU.
struct ResolvedLink {
    link_local_address: Ipv6Addr,
    prefix: Ipv6Net,
    mtu: u32,
}

/// Resolves a subinterface's link-local address (populated by
/// `nos-interfaced`'s Linux driver purely by observing the kernel — see
/// `nos_proto::SubinterfaceStatus.link_local_address`'s doc comment) and its
/// configured global/ULA prefix, by asking `nos-interfaced` directly.
/// `None` covers every "not resolvable yet" case uniformly, retried by the
/// caller's periodic re-apply tick.
async fn resolve_local_address(
    watchdog_socket: &Path,
    interface: &str,
    tag: u16,
) -> Option<ResolvedLink> {
    let socket = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_interface(&socket, interface).await?;
    let mtu = status.mtu;
    let sub = status.subinterfaces.into_iter().find(|s| s.tag == tag)?;
    let link_local_address = sub.link_local_address?;
    let prefix = sub.addresses.into_iter().find_map(|a| match a.address {
        IpNet::V6(v6) => Some(v6),
        IpNet::V4(_) => None,
    })?;
    Some(ResolvedLink {
        link_local_address,
        prefix,
        mtu,
    })
}

const DEFAULT_OSPF_MTU: u16 = 1500;

/// Translates `Ospfv3Profile.auth` into `packet::TrailerAuth` — mirrors
/// `ospf::reconcile::resolve_auth`. `current_key_id` needs no fallback:
/// commit-time validation guarantees exactly one `is_current` key, and no
/// MD5 key (`packet::CryptoAlgorithm` has no such arm).
fn resolve_auth(
    profile: &nos_proto::Ospfv3Profile,
    cfg: &nos_proto::Config,
) -> Result<Option<packet::TrailerAuth>, String> {
    let Some(keys) = profile.auth.as_ref() else {
        return Ok(None);
    };
    let mut resolved = Vec::new();
    for k in keys {
        let algorithm = match k.algorithm {
            OspfCryptoAlgorithm::Md5 => continue,
            OspfCryptoAlgorithm::HmacSha1 => packet::CryptoAlgorithm::HmacSha1,
            OspfCryptoAlgorithm::HmacSha256 => packet::CryptoAlgorithm::HmacSha256,
            OspfCryptoAlgorithm::HmacSha384 => packet::CryptoAlgorithm::HmacSha384,
            OspfCryptoAlgorithm::HmacSha512 => packet::CryptoAlgorithm::HmacSha512,
        };
        let secret = cfg.key(&k.key).ok_or_else(|| k.key.clone())?;
        resolved.push((k.key_id, algorithm, secret.as_bytes().to_vec()));
    }
    Ok(Some(packet::TrailerAuth {
        keys: resolved,
        current_key_id: keys.iter().find(|k| k.is_current).map_or(0, |k| k.key_id),
    }))
}

/// Mirrors `ospf::reconcile::resolve_effective_mtu` exactly.
fn resolve_effective_mtu(profile: &nos_proto::Ospfv3Profile, resolved_mtu: Option<u32>) -> u16 {
    profile.mtu.unwrap_or_else(|| {
        resolved_mtu
            .and_then(|m| u16::try_from(m).ok())
            .unwrap_or(DEFAULT_OSPF_MTU)
    })
}

/// Resolves a loopback (`Interface.ospfv3_profile`) attach point's own
/// IPv6 prefix — feeds `LinkManager`'s loopback-prefix map, since a
/// loopback has no live link/socket to carry it through `LinkConfig` (no
/// Hello is ever sent from it — see `link.rs`'s module doc comment).
async fn resolve_loopback_prefix(watchdog_socket: &Path, interface: &str) -> Option<Ipv6Net> {
    let socket = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_interface(&socket, interface).await?;
    status.addresses.into_iter().find_map(|a| match a.address {
        IpNet::V6(v6) => Some(v6),
        IpNet::V4(_) => None,
    })
}

/// Resolves a broadcast domain's own SVI link-local address, its IPv6
/// prefix, and its real kernel bridge device name — mirrors
/// `ospf::reconcile::resolve_broadcast_domain`'s shape.
async fn resolve_broadcast_domain(
    watchdog_socket: &Path,
    domain: &str,
) -> Option<(ResolvedLink, String)> {
    let socket = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_broadcast_domain(&socket, domain).await?;
    let bridge_name = status.bridge_name?;
    let link_local_address = status.link_local_address?;
    let prefix = status.addresses.into_iter().find_map(|a| match a.address {
        IpNet::V6(v6) => Some(v6),
        IpNet::V4(_) => None,
    })?;
    Some((
        ResolvedLink {
            link_local_address,
            prefix,
            // A broadcast domain's own bridge has no separate MTU concept
            // in this schema (see `nos_proto::BroadcastDomainStatus`) —
            // `resolve_effective_mtu` always falls back to
            // `DEFAULT_OSPF_MTU` for this attach-point kind, matching
            // `ospf::reconcile`'s identical `None` here.
            mtu: 0,
        },
        bridge_name,
    ))
}

fn subinterface_kernel_interface(interface: &str, tag: u16) -> String {
    if tag == 0 {
        interface.to_string()
    } else {
        format!("{interface}.{tag}")
    }
}

/// Resolves a kernel interface's ifindex, doubling as this link's RFC 5340
/// Interface ID (see `LinkConfig.interface_id`'s doc comment) — a local
/// `libc` call, not an IPC round trip: every daemon in this NOS shares one
/// network namespace, so `nos-ospfv3d` can read the kernel's own interface
/// table directly, the same way `nos-interfaced`'s Linux driver does.
/// `None` if the interface doesn't exist in the netns yet (an ordinary
/// transient condition, not an error — retried by the caller's periodic
/// re-apply tick).
fn kernel_ifindex(name: &str) -> Option<u32> {
    nos_l2_socket::if_index(name)
        .ok()
        .and_then(|i| u32::try_from(i).ok())
}

/// Local copy of `nos-watchdog::supervisor::wait_or_shutdown` — not
/// imported, per the star-dependency rule.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod resync_tests;

#[cfg(test)]
mod tests {
    use nos_proto::{BroadcastDomain, Config, Interface, Subinterface};

    use std::collections::{HashMap, HashSet};

    use super::attach_points_for;
    use super::broadcast_domain_attach_points;
    use super::loopback_attach_points;
    use super::subinterface_attach_points;
    use super::*;
    use crate::link_client::apply;

    fn interface(name: &str, ospfv3_profile: Option<&str>) -> Interface {
        Interface {
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: ospfv3_profile.map(str::to_string),
            switching_profile: None,
            port_aggregate: None,
            lacp_port_priority: None,
            lacp_mode: nos_proto::LacpMode::default(),
            mtu: None,
            lldp_transmit: false,
            lldp_receive: false,
            lldp_destination: nos_proto::LldpDestination::default(),
            subinterfaces: Vec::new(),
            ..Default::default()
        }
    }

    #[test]
    fn finds_loopback_interface_attachment() {
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("p1"))],
            ..Default::default()
        };
        assert_eq!(attach_points_for(&cfg, "p1"), vec!["loopback-rt1"]);
    }

    #[test]
    fn finds_subinterface_attachment() {
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            tag: 100,
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: Some("p1".to_string()),
            bfd_unsolicited: None,
        }];
        let cfg = Config {
            interfaces: vec![iface],
            ..Default::default()
        };
        assert_eq!(attach_points_for(&cfg, "p1"), vec!["eth0.100"]);
    }

    #[test]
    fn finds_broadcast_domain_attachment() {
        let cfg = Config {
            broadcast_domains: vec![BroadcastDomain {
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: None,
                ospfv3_profile: Some("p1".to_string()),
                vni: None,
                rd: None,
                route_targets_import: Vec::new(),
                route_targets_export: Vec::new(),
                vtep_source: None,
                mac_redistribute: None,
                arp_redistribute: None,
                connected_redistribute: None,
                neigh_suppress: false,
                max_remote_macs: None,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(attach_points_for(&cfg, "p1"), vec!["broadcast-domain:bd1"]);
    }

    #[test]
    fn ignores_attachments_to_other_profiles() {
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("other"))],
            ..Default::default()
        };
        assert_eq!(attach_points_for(&cfg, "p1"), [] as [String; 0]);
    }

    #[test]
    fn subinterface_attach_points_finds_routing_table() {
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            tag: 0,
            addresses: Vec::new(),
            routing_table: Some("rt1".to_string()),
            ospf_profile: None,
            ospfv3_profile: Some("p1".to_string()),
            bfd_unsolicited: None,
        }];
        let cfg = Config {
            interfaces: vec![iface],
            ..Default::default()
        };
        let points = subinterface_attach_points(&cfg, "p1");
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].display_name(), "eth0.0");
        assert_eq!(points[0].routing_table.as_deref(), Some("rt1"));
    }

    #[test]
    fn broadcast_domain_attach_points_finds_routing_table() {
        let cfg = Config {
            broadcast_domains: vec![BroadcastDomain {
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: Some("rt1".to_string()),
                ospf_profile: None,
                ospfv3_profile: Some("p1".to_string()),
                vni: None,
                rd: None,
                route_targets_import: Vec::new(),
                route_targets_export: Vec::new(),
                vtep_source: None,
                mac_redistribute: None,
                arp_redistribute: None,
                connected_redistribute: None,
                neigh_suppress: false,
                max_remote_macs: None,
                ..Default::default()
            }],
            ..Default::default()
        };
        let points = broadcast_domain_attach_points(&cfg, "p1");
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].display_name(), "broadcast-domain:bd1");
        assert_eq!(points[0].routing_table.as_deref(), Some("rt1"));
    }

    #[test]
    fn loopback_attach_points_finds_loopback_interface() {
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("p1"))],
            ..Default::default()
        };
        let points = loopback_attach_points(&cfg, "p1");
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].interface, "loopback-rt1");
    }

    fn running() -> LinkConfig {
        LinkConfig {
            attach_point: "eth0.0".into(),
            area_id: std::net::Ipv4Addr::UNSPECIFIED,
            hello_interval: 10,
            dead_interval: 40,
            vrf: "vrf-run".into(),
            kernel_interface: "br-run".into(),
            interface_id: 3,
            link_local_address: "fe80::1".parse().unwrap(),
            prefix: "2001:db8::1/64".parse().unwrap(),
            cost: 1,
            network_type: nos_proto::NetworkType::Broadcast,
            priority: 1,
            mtu: 9000,
            mtu_ignore: false,
            auth: None,
            instance_id: 0,
            helper_max_grace_period: 1800,
        }
    }

    fn resolved() -> Resolved {
        Resolved {
            vrf: Some("vrf-new".into()),
            link: Some(ResolvedLink {
                link_local_address: "fe80::2".parse().unwrap(),
                prefix: "2001:db8::2/64".parse().unwrap(),
                mtu: 1500,
            }),
            kernel_interface: Some("br-new".into()),
        }
    }

    #[test]
    fn merge_running_table() {
        let run = running();
        let (m, fb) = merge_running(resolved(), Some(&run)).unwrap();
        assert_eq!(fb, [] as [&str; 0]);
        assert_eq!((m.vrf.as_str(), m.mtu), ("vrf-new", Some(1500)));
        let none = Resolved {
            vrf: None,
            link: None,
            kernel_interface: None,
        };
        let (m, fb) = merge_running(none, Some(&run)).unwrap();
        assert_eq!(fb, ["vrf", "address", "bridge"]);
        assert_eq!(
            (
                m.vrf.as_str(),
                m.link_local_address,
                m.kernel_interface.as_str(),
                m.mtu
            ),
            ("vrf-run", run.link_local_address, "br-run", Some(9000))
        );
        let only_vrf = || Resolved {
            vrf: None,
            ..resolved()
        };
        assert_eq!(
            merge_running(only_vrf(), Some(&run)).unwrap().0.vrf,
            "vrf-run"
        );
        assert!(merge_running(only_vrf(), None).is_none());
    }

    #[test]
    fn interface_id_prefers_stream_then_running() {
        let run = running();
        assert_eq!(pick_interface_id(7, "nope0", Some(&run)), Some(7));
        assert_eq!(pick_interface_id(0, "nope0", Some(&run)), Some(3));
        assert_eq!(pick_interface_id(0, "nope0", None), None);
    }

    #[test]
    fn gate_link_logs_state_and_skips_down() {
        let mut t = LinkTable::default();
        let st = State::default();
        let mut down = HashMap::new();
        assert_eq!(gate_link(&st, &mut down, &t, "l", "a"), Some(0));
        let ev = |up: bool| nos_proto::LinkState {
            name: "a".into(),
            ifindex: 5,
            admin_up: true,
            carrier: up,
            port_aggregate: None,
        };
        apply(
            &mut t,
            nos_proto::InterfaceEvent::LinkSnapshot {
                observed: true,
                links: vec![ev(true)],
            },
        );
        assert_eq!(gate_link(&st, &mut down, &t, "l", "a"), Some(5));
        apply(&mut t, nos_proto::InterfaceEvent::LinkChanged(ev(false)));
        assert_eq!(gate_link(&st, &mut down, &t, "l", "a"), None);
        assert_eq!(down.get("l"), Some(&"no-carrier"));
    }

    #[test]
    fn attach_points_know_whether_the_config_has_an_address() {
        let addr = nos_proto::InterfaceAddress {
            address: "2001:db8::1/64".parse().unwrap(),
            label: None,
        };
        let v4 = nos_proto::InterfaceAddress {
            address: "10.0.0.1/24".parse().unwrap(),
            label: None,
        };
        let sub = |tag, addresses| Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            tag,
            addresses,
            routing_table: Some("rt1".into()),
            ospf_profile: None,
            ospfv3_profile: Some("p1".into()),
            bfd_unsolicited: None,
        };
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![sub(0, vec![addr]), sub(1, vec![v4])];
        let cfg = Config {
            interfaces: vec![iface],
            ..Default::default()
        };
        let pts = subinterface_attach_points(&cfg, "p1");
        assert_eq!((pts[0].has_address, pts[1].has_address), (true, false));
    }

    #[test]
    fn signature_only_covers_watched_devices() {
        let mut t = LinkTable::default();
        let ev = |n: &str, up: bool| nos_proto::LinkState {
            name: n.into(),
            ifindex: 1,
            admin_up: up,
            carrier: up,
            port_aggregate: None,
        };
        apply(
            &mut t,
            nos_proto::InterfaceEvent::LinkSnapshot {
                observed: true,
                links: vec![ev("a", true), ev("x", true)],
            },
        );
        let watched = HashSet::from(["a".to_string()]);
        let before = signature(&t, &watched);
        apply(
            &mut t,
            nos_proto::InterfaceEvent::LinkChanged(ev("x", false)),
        );
        assert_eq!(signature(&t, &watched), before);
        apply(
            &mut t,
            nos_proto::InterfaceEvent::LinkChanged(ev("a", false)),
        );
        assert_eq!(
            signature(&t, &watched),
            [("a".to_string(), Gate::Down("admin-down"))]
        );
    }
}
