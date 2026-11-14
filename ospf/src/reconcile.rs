use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use ipnet::Ipv4Net;
use nos_proto::{DiffScope, Event, NetworkType, OspfAuth, OspfCryptoAlgorithm, ServiceRef};
use nos_rpl::CompiledPolicy;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::interface_client;
use crate::link::{
    AreaSettings, LinkAuthConfig, LinkConfig, LinkManager, VirtualLinkConfig,
    DEFAULT_HELPER_MAX_GRACE_PERIOD,
};
use crate::link_client::{self, Gate, LinkTable};
use crate::packet;
use crate::rib_client;
use nos_daemon::config;
use nos_daemon::watchdog;

/// Fixed reconnect delay for the config subscription, matching every other
/// config-subscribing consumer in this codebase (`nos-bgp`/`nos-rib`/
/// `nos-interface`'s own `reconcile::RECONNECT_DELAY`).
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// How often to re-apply desired state even without a new config diff —
/// needed because a link's VRF/local-address readiness (the owning
/// `nos-ribd`/`nos-interfaced` having resolved it) is an external condition
/// no config commit signals, same as `nos-bgp`'s own `reconcile::
/// REAPPLY_INTERVAL`.
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

/// Runs until `shutdown` fires. Subscribes to `OspfInstances` diffs purely as
/// a resync trigger — the actual state always comes from a fresh
/// `fetch_config` call, plus a periodic tick independent of any config
/// change, plus a change of a watched device's link state.
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
            vec![DiffScope::OspfInstances, DiffScope::Admin],
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
    cfg.ospf_instances
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
    desired_stubs: HashMap<Ipv4Addr, Vec<(Ipv4Net, u16)>>,
}

/// One profile of one area, with the values every attach point shares.
struct ProfileCtx<'a> {
    area: &'a nos_proto::OspfArea,
    profile: &'a nos_proto::schema::OspfProfile,
    hello_interval: u16,
    dead_interval: u16,
    priority: u8,
    auth: LinkAuthConfig,
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
        auth,
        ..
    } = pc;
    let hello_interval = *hello_interval;
    let dead_interval = *dead_interval;
    let priority = *priority;
    for attach in subinterface_attach_points(cfg, &profile.name) {
        let link_name = attach.display_name();
        let Some(routing_table) = &attach.routing_table else {
            // Can't happen in practice —
            // `valid_subinterface_ospf_profile_requires_routing_table`
            // already enforces this at commit time — but the field
            // is still `Option` on the wire.
            warn!(
                instance = %instance, link = %link_name,
                "ospf profile attached to a subinterface with no routing-table, skipping"
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
        let addr = resolve_local_address(watchdog_socket, &attach.interface, attach.tag).await;
        let running = if attach.has_address {
            links.running_config(&link_name).await
        } else {
            None
        };
        let resolved = Resolved {
            vrf,
            local_addr: addr.as_ref().map(|a| a.0),
            local_prefix_len: addr.as_ref().map(|a| a.1),
            mtu: addr.as_ref().map(|a| a.2),
            kernel_interface: Some(kernel_interface),
        };
        let Some((m, fell_back)) = merge_running(resolved, running.as_ref()) else {
            warn!(instance = %instance, link = %link_name, "ospf link's vrf/local address not resolvable yet");
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
            local_addr: m.local_addr,
            local_prefix_len: m.local_prefix_len,
            cost: profile.cost.unwrap_or(1),
            kernel_interface: m.kernel_interface,
            network_type: profile.network_type.unwrap_or(NetworkType::PointToPoint),
            priority,
            mtu: resolve_effective_mtu(profile, m.mtu),
            mtu_ignore: profile.mtu_ignore,
            ifindex,
            auth: auth.clone(),
            stub: area.area_type.is_stub(),
            nssa: area.area_type.is_nssa(),
            virtual_link: None,
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
    let Wanted { desired_stubs, .. } = d;
    let ProfileCtx { area, profile, .. } = pc;
    for attach in loopback_attach_points(cfg, &profile.name) {
        let Some((addr, prefix_len)) =
            resolve_loopback_prefix(watchdog_socket, &attach.interface).await
        else {
            warn!(
                instance = %instance, interface = %attach.interface,
                "ospf loopback stub network not resolvable yet"
            );
            continue;
        };
        if let Ok(subnet) = Ipv4Net::new(addr, prefix_len) {
            desired_stubs
                .entry(area.area_id)
                .or_default()
                .push((subnet, profile.cost.unwrap_or(1)));
        }
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
        auth,
        ..
    } = pc;
    let hello_interval = *hello_interval;
    let dead_interval = *dead_interval;
    let priority = *priority;
    for attach in broadcast_domain_attach_points(cfg, &profile.name) {
        let link_name = attach.display_name();
        let Some(routing_table) = &attach.routing_table else {
            // Can't happen in practice —
            // `broadcast_domain::valid_broadcast_domains` already
            // enforces this at commit time — but the field is
            // still `Option` on the wire.
            warn!(
                instance = %instance, link = %link_name,
                "ospf profile attached to a broadcast domain with no routing-table, skipping"
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
        let resolved = Resolved {
            vrf,
            local_addr: bridge.as_ref().map(|b| b.0),
            local_prefix_len: bridge.as_ref().map(|b| b.1),
            mtu: None,
            kernel_interface: bridge.map(|b| b.2),
        };
        let Some((m, fell_back)) = merge_running(resolved, running.as_ref()) else {
            warn!(instance = %instance, link = %link_name, "ospf link's vrf/local address/bridge not resolvable yet");
            continue;
        };
        watched.insert(m.kernel_interface.clone());
        let Some(ifindex) = gate_link(state, next_down, table, &link_name, &m.kernel_interface)
        else {
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
            local_addr: m.local_addr,
            local_prefix_len: m.local_prefix_len,
            cost: profile.cost.unwrap_or(1),
            kernel_interface: m.kernel_interface,
            network_type: profile.network_type.unwrap_or(NetworkType::Broadcast),
            priority,
            mtu: resolve_effective_mtu(profile, None),
            mtu_ignore: profile.mtu_ignore,
            ifindex,
            auth: auth.clone(),
            stub: area.area_type.is_stub(),
            nssa: area.area_type.is_nssa(),
            virtual_link: None,
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

    let Some(own) = cfg.ospf_instances.iter().find(|i| i.name == *instance) else {
        // The watchdog would be tearing this process down anyway if the
        // instance were genuinely removed from config.
        warn!(instance = %instance, "own ospf instance missing from running config");
        let _ = routing_table_tx.send(None);
        return;
    };
    let _ = routing_table_tx.send(own.routing_table.clone());
    info!(
        instance = %instance,
        router_id = %own.router_id,
        routing_table = ?own.routing_table,
        area_count = own.areas.len(),
        graceful_restart_grace_period = ?own.graceful_restart_grace_period,
        graceful_restart_helper_max_grace_period = ?own.graceful_restart_helper_max_grace_period,
        prefix_suppression = own.prefix_suppression,
        max_metric_on_startup = ?own.max_metric_on_startup,
        max_metric_on_shutdown = ?own.max_metric_on_shutdown,
        max_metric_administrative = own.max_metric_administrative,
        host_router = own.host_router,
        remote_lfa = own.remote_lfa,
        "ospf instance config resolved"
    );
    links.set_graceful_restart(own.graceful_restart_grace_period);
    links.set_prefix_suppression(own.prefix_suppression);
    links.set_host_router(own.host_router);
    links.set_remote_lfa(own.remote_lfa);
    links.set_max_metric(
        own.max_metric_on_startup,
        own.max_metric_on_shutdown,
        own.max_metric_administrative,
    );
    links
        .set_virtual_links(virtual_links(&own.areas, &cfg))
        .await;
    links.set_area_settings(area_settings(&own.areas)).await;

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
        desired_stubs: HashMap::new(),
    };
    for area in &own.areas {
        info!(
            instance = %instance,
            area = %area.area_id,
            profile_count = area.profiles.len(),
            "ospf area resolved"
        );
        for profile in &area.profiles {
            let interfaces = attach_points_for(&cfg, &profile.name);
            info!(
                instance = %instance,
                area = %area.area_id,
                profile = %profile.name,
                interfaces = ?interfaces,
                cost = ?profile.cost,
                "ospf profile resolved"
            );

            let hello_interval = profile
                .hello_interval
                .unwrap_or(nos_proto::HELLO_INTERVAL_DEFAULT);
            let dead_interval = profile
                .dead_interval
                .unwrap_or(nos_proto::DEAD_INTERVAL_DEFAULT);
            let priority = profile.priority.unwrap_or(nos_proto::PRIORITY_DEFAULT);
            // Fail closed: a dangling label (commit validation prevents it)
            // must never start the link unauthenticated.
            let auth = match resolve_auth(
                profile.auth.as_ref(),
                profile.extended_sequence_numbers,
                &cfg,
            ) {
                Ok(a) => a,
                Err(label) => {
                    error!(instance = %instance, profile = %profile.name, label = %label, "ospf profile references an unknown admin key, not starting its links");
                    continue;
                }
            };
            let pc = ProfileCtx {
                area,
                profile,
                hello_interval,
                dead_interval,
                priority,
                auth,
            };
            resolve_subinterface_links(&env, &mut wanted, &pc).await;
            resolve_loopback_links(&env, &mut wanted, &pc).await;
            resolve_broadcast_domain_links(&env, &mut wanted, &pc).await;
        }
    }

    let redistribute_policy = resolve_redistribute_policy(&cfg, own.redistribute_policy.as_deref());
    links.set_redistribute_policy(redistribute_policy).await;
    links
        .set_redistribute_metric(own.redistribute_metric, own.redistribute_metric_type)
        .await;

    let Wanted {
        watched,
        next_down,
        next_degraded,
        desired_links,
        bfd_wants,
        desired_stubs,
    } = wanted;
    links.set_bfd(bfd_wants);
    links
        .reconcile(desired_links, desired_stubs, own.router_id)
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
    local_addr: Option<Ipv4Addr>,
    local_prefix_len: Option<u8>,
    /// The parent interface's real MTU (point-to-point only).
    mtu: Option<u32>,
    kernel_interface: Option<String>,
}

struct Merged {
    vrf: String,
    local_addr: Ipv4Addr,
    local_prefix_len: u8,
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
    let (local_addr, local_prefix_len) =
        if let (Some(a), Some(p)) = (r.local_addr, r.local_prefix_len) {
            (a, p)
        } else {
            fell_back.push("address");
            let c = running?;
            (c.local_addr, c.local_prefix_len)
        };
    let kernel_interface = if let Some(k) = r.kernel_interface {
        k
    } else {
        fell_back.push("bridge");
        running?.kernel_interface.clone()
    };
    // The running effective MTU stands in for an unresolved parent MTU
    // (a profile override still wins in `resolve_effective_mtu`).
    let mtu = r.mtu.or_else(|| running.map(|c| u32::from(c.mtu)));
    Some((
        Merged {
            vrf,
            local_addr,
            local_prefix_len,
            mtu,
            kernel_interface,
        },
        fell_back,
    ))
}

/// Applies the link stream's verdict on `kernel_interface` to `link`: `None`
/// (skip, so `apply_links` aborts it: RFC 2328 §9.3 `InterfaceDown`) when it is
/// down, else its ifindex (0 ungated). Logs on transitions only.
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
                warn!(link = %link, reason = %reason, "ospf link kernel interface down");
            }
            next_down.insert(link.to_string(), reason);
            None
        }
        Gate::Up(ifindex) => {
            if state.down.contains_key(link) {
                info!(link = %link, ifindex, "ospf link kernel interface up");
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
        warn!(link = %link, missing = %fell_back.join("|"), "ospf link resolution failed, keeping running link");
    }
    next.insert(link.to_string());
}

/// Every area's RFC 2328 §15 virtual links (the area is the transit area),
/// with the Appendix C.3 defaults for unset timers.
fn virtual_links(areas: &[nos_proto::OspfArea], cfg: &nos_proto::Config) -> Vec<VirtualLinkConfig> {
    areas
        .iter()
        .flat_map(|a| {
            a.virtual_links.iter().filter_map(|v| {
                Some(VirtualLinkConfig {
                transit_area: a.area_id,
                endpoint: v.router_id,
                hello_interval: v
                    .hello_interval
                    .unwrap_or(nos_proto::HELLO_INTERVAL_DEFAULT),
                dead_interval: v.dead_interval.unwrap_or(nos_proto::DEAD_INTERVAL_DEFAULT),
                auth: resolve_auth(v.auth.as_ref(), false, cfg)
                    .map_err(|label| error!(label = %label, endpoint = %v.router_id, "ospf virtual link references an unknown admin key, not starting it"))
                    .ok()?,
                })
            })
        })
        .collect()
}

/// Each area's RFC 2328 §3.5/§3.6 and RFC 3101 settings, for `LinkManager`'s
/// summary/external origination and discard routes.
fn area_settings(areas: &[nos_proto::OspfArea]) -> HashMap<Ipv4Addr, AreaSettings> {
    areas
        .iter()
        .map(|a| {
            let settings = AreaSettings {
                stub: a.area_type.is_stub(),
                nssa: a.area_type.is_nssa(),
                import_summaries: a.area_type.import_summaries(),
                nssa_translate_always: a.nssa_translate_always,
                nssa_default_originate: a.nssa_default_originate,
                default_cost: u32::from(a.stub_default_cost.unwrap_or(1)),
                ranges: a
                    .ranges
                    .iter()
                    .map(|r| (r.cidr, !r.not_advertise))
                    .collect(),
            };
            (a.area_id, settings)
        })
        .collect()
}

/// Resolves the mirrored `OspfInstance.redistribute_policy` field to a
/// compiled policy. Unlike `bgp::policy::PolicyCache` (which caches many
/// policies for many peer-groups), `OspfInstance.redistribute_policy` is
/// exactly one policy per instance — compiling fresh every resync tick (the
/// same cadence every other resolution in this function already runs at)
/// needs no cache-invalidation logic; add a cache only if profiling ever
/// shows this compile step matters.
///
/// `None` resolves to `accept-all`, matching `bgp::reconcile::resync`'s own
/// precedent — redistribution is already opt-in via the `Redistribute`
/// rule's existence, unlike peer import/export policy's deny-all default.
///
/// `ponytail:` this duplicates `bgp::policy::PolicyCache::resync`'s
/// `Symbols`-building logic rather than sharing it — expected, not an
/// oversight, per the star-dependency rule (components share only
/// `nos-proto`, never each other's code).
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

/// Every L3 attach point (loopback interface name, `<interface>.<tag>`
/// subinterface, or `broadcast-domain:<name>`) currently referencing
/// `profile` by name, across the whole running config. Purely a display
/// helper for the log line above — `cfg` already carries every interface
/// and broadcast domain from the same `fetch_config` call, so no extra IPC
/// round trip is needed to resolve it.
fn attach_points_for(cfg: &nos_proto::Config, profile: &str) -> Vec<String> {
    let mut points = Vec::new();
    for iface in &cfg.interfaces {
        if iface.ospf_profile.as_deref() == Some(profile) {
            points.push(iface.name.clone());
        }
        for sub in &iface.subinterfaces {
            if sub.ospf_profile.as_deref() == Some(profile) {
                points.push(format!("{}.{}", iface.name, sub.tag));
            }
        }
    }
    for domain in &cfg.broadcast_domains {
        if domain.ospf_profile.as_deref() == Some(profile) {
            points.push(format!("broadcast-domain:{}", domain.name));
        }
    }
    points
}

/// One `Subinterface.ospf_profile` attach point, with enough structure to
/// resolve and build a `LinkConfig`. Point-to-point only this phase (see
/// `docs/protocols/ospf-internals.md`) — loopback and `BroadcastDomain` attach points stay
/// log-only, handled entirely by `attach_points_for` above.
struct SubinterfaceAttachPoint {
    interface: String,
    tag: u16,
    routing_table: Option<String>,
    /// The config still gives it an IPv4 address: a failed lookup then keeps
    /// the running link, else the attach point is gone as far as we know.
    has_address: bool,
}

impl SubinterfaceAttachPoint {
    /// Matches `attach_points_for`'s existing `"<interface>.<tag>"`
    /// convention.
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
            if sub.ospf_profile.as_deref() == Some(profile) {
                points.push(SubinterfaceAttachPoint {
                    interface: iface.name.clone(),
                    tag: sub.tag,
                    routing_table: sub.routing_table.clone(),
                    has_address: sub.addresses.iter().any(|a| a.address.addr().is_ipv4()),
                });
            }
        }
    }
    points
}

/// One `BroadcastDomain.ospf_profile` attach point, with enough structure to
/// resolve and build a `LinkConfig`.
struct BroadcastDomainAttachPoint {
    name: String,
    routing_table: Option<String>,
    /// As `SubinterfaceAttachPoint::has_address`.
    has_address: bool,
}

impl BroadcastDomainAttachPoint {
    /// Matches `attach_points_for`'s existing `"broadcast-domain:<name>"`
    /// convention.
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
        .filter(|d| d.ospf_profile.as_deref() == Some(profile))
        .map(|d| BroadcastDomainAttachPoint {
            name: d.name.clone(),
            routing_table: d.routing_table.clone(),
            has_address: d.addresses.iter().any(|a| a.address.addr().is_ipv4()),
        })
        .collect()
}

/// One loopback (`Interface.ospf_profile`) attach point — unlike a
/// `Subinterface`/`BroadcastDomain` attach point, this carries no
/// `routing_table` of its own to resolve a VRF from (a loopback's `Interface.
/// routing_table` field only matters for the L3 driver, not OSPF, which just
/// needs the interface's own subnet — see `loopback_attach_points`).
struct LoopbackAttachPoint {
    interface: String,
}

/// Every `Interface.ospf_profile` attach point (a loopback, per
/// `nos_proto::loopback_table_name`) referencing `profile` — these have no
/// live link/socket (see `docs/protocols/ospf-internals.md`'s "log-only" note), just a
/// stub-network subnet for `LinkManager::stub_networks`.
fn loopback_attach_points(cfg: &nos_proto::Config, profile: &str) -> Vec<LoopbackAttachPoint> {
    cfg.interfaces
        .iter()
        .filter(|i| {
            nos_proto::loopback_table_name(&i.name).is_some()
                && i.ospf_profile.as_deref() == Some(profile)
        })
        .map(|i| LoopbackAttachPoint {
            interface: i.name.clone(),
        })
        .collect()
}

/// Resolves `table`'s Linux VRF interface name by asking the owning
/// `nos-ribd` instance directly over IPC (see `crate::rib_client`),
/// resolved via the watchdog broker — never derived locally. `None` covers
/// every "not answerable yet" case uniformly (broker doesn't know that
/// table, connect failure, rib hasn't created a VRF yet), retried by the
/// caller's periodic re-apply tick. Mirrors `nos-bgp`'s own
/// `reconcile::resolve_vrf`.
async fn resolve_vrf(watchdog_socket: &Path, table: &str) -> Option<String> {
    let socket =
        watchdog::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string())).await?;
    rib_client::get_vrf_name(&socket).await
}

/// Resolves a subinterface's tag-0-or-tagged local IPv4 address, its real
/// subnet prefix length, and its parent interface's real MTU, by asking
/// `nos-interfaced` directly (resolved via the watchdog broker's
/// `ServiceRef::Interfaces`, mirroring `resolve_vrf`'s `ServiceRef::RibTable`
/// and `nos-ribd` query). The prefix length feeds
/// `link::LinkConfig::local_prefix_len`, needed to originate a real
/// stub-network Router-LSA link for this subnet (see `crate::spf`); the MTU
/// feeds `LinkConfig::mtu` (see `resolve_effective_mtu`) — MTU is a
/// physical-interface-level property (`InterfaceStatus.mtu`), not a
/// per-subinterface one, so it's read from the same already-fetched
/// `InterfaceStatus` rather than a separate query. `None` covers every "not
/// resolvable right now" case uniformly, retried by the caller's periodic
/// re-apply tick.
async fn resolve_local_address(
    watchdog_socket: &Path,
    interface: &str,
    tag: u16,
) -> Option<(Ipv4Addr, u8, u32)> {
    let socket = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_interface(&socket, interface).await?;
    let mtu = status.mtu;
    let sub = status.subinterfaces.into_iter().find(|s| s.tag == tag)?;
    let net = sub.addresses.into_iter().next()?.address;
    match net.addr() {
        std::net::IpAddr::V4(v4) => Some((v4, net.prefix_len(), mtu)),
        std::net::IpAddr::V6(_) => None,
    }
}

/// Linux's own default MTU, used as the ultimate fallback when neither an
/// `OspfProfile.mtu` override nor a real resolved interface MTU is
/// available (a broadcast-domain bridge attach point, which has no
/// per-domain MTU of its own — see root `CLAUDE.md`'s scope note on this).
const DEFAULT_OSPF_MTU: u16 = 1500;

/// Resolves the effective MTU OSPF uses for a link — for the wire's
/// `DbdPacket.interface_mtu` field and DBD pagination sizing (see
/// `docs/protocols/ospf-internals.md`'s "LSA exchange and the LSDB") — as `profile.mtu` if set, else
/// `resolved_mtu` (the link's real interface MTU, when one exists), else
/// `DEFAULT_OSPF_MTU`.
fn resolve_effective_mtu(profile: &nos_proto::OspfProfile, resolved_mtu: Option<u32>) -> u16 {
    profile.mtu.unwrap_or_else(|| {
        resolved_mtu
            .and_then(|m| u16::try_from(m).ok())
            .unwrap_or(DEFAULT_OSPF_MTU)
    })
}

/// Resolves a loopback (`Interface.ospf_profile`) attach point's own
/// address *and* prefix length the same way `resolve_local_address` does,
/// but reading `InterfaceStatus.addresses` directly (a loopback's L3 config
/// is flat, no subinterface lookup) — feeds `LinkManager`'s `stub_networks`
/// map, since a loopback has no live link/socket of its own to carry this
/// through `LinkConfig` (see `docs/protocols/ospf-internals.md`'s "log-only" loopback note).
async fn resolve_loopback_prefix(
    watchdog_socket: &Path,
    interface: &str,
) -> Option<(Ipv4Addr, u8)> {
    let socket = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_interface(&socket, interface).await?;
    let net = status.addresses.into_iter().next()?.address;
    match net.addr() {
        std::net::IpAddr::V4(v4) => Some((v4, net.prefix_len())),
        std::net::IpAddr::V6(_) => None,
    }
}

/// Resolves a broadcast domain's own SVI local IPv4 address *and* its real
/// kernel bridge device name (`nos-ospfd`'s socket binds to the bridge
/// itself — the L3 attach point for this domain — never the shared VRF
/// device; see `link::LinkConfig::kernel_interface`'s doc comment) from one
/// `GetBroadcastDomain` query, asking `nos-interfaced` directly the same
/// way `resolve_local_address` does. `None` covers every "not resolvable
/// right now" case uniformly (including the bridge not created yet),
/// retried by the caller's periodic re-apply tick.
async fn resolve_broadcast_domain(
    watchdog_socket: &Path,
    domain: &str,
) -> Option<(Ipv4Addr, u8, String)> {
    let socket = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let status = interface_client::get_broadcast_domain(&socket, domain).await?;
    let bridge_name = status.bridge_name?;
    let net = status.addresses.into_iter().next()?.address;
    match net.addr() {
        std::net::IpAddr::V4(v4) => Some((v4, net.prefix_len(), bridge_name)),
        std::net::IpAddr::V6(_) => None,
    }
}

/// A `Subinterface` attach point's real kernel device name — the untagged
/// case shares the physical link itself; a real VLAN tag gets its own
/// `<interface>.<tag>` sub-interface (see root `CLAUDE.md`'s "L2 switching"
/// section). Pure — no IPC needed, since this is exactly the naming
/// convention `nos-interfaced`'s own driver already uses.
fn subinterface_kernel_interface(interface: &str, tag: u16) -> String {
    if tag == 0 {
        interface.to_string()
    } else {
        format!("{interface}.{tag}")
    }
}

/// Translates `OspfProfile.auth` into `link::LinkAuthConfig` — pure, no I/O,
/// resolving each admin-key label against the fetched `Config`; `Err(label)`
/// is a dangling label, which the caller treats as "do not start the link".
/// Commit validation already guarantees every label exists.
/// `current_key_id` is safe to pull from whichever key has `is_current` set
/// without a fallback: `OspfProfile`'s own commit-time validation
/// (`schema::ospf_profile::valid_auth`) already guarantees exactly one does
/// whenever `auth` is `Crypto`.
fn resolve_auth(
    auth: Option<&OspfAuth>,
    extended: bool,
    cfg: &nos_proto::Config,
) -> Result<LinkAuthConfig, String> {
    let secret = |label: &str| {
        cfg.key(label)
            .map(|s| s.as_bytes().to_vec())
            .ok_or_else(|| label.to_string())
    };
    Ok(match auth {
        None => LinkAuthConfig::None,
        Some(OspfAuth::Simple { key }) => LinkAuthConfig::Simple {
            password: secret(key)?,
        },
        Some(OspfAuth::Crypto { keys }) => {
            let current_key_id = keys.iter().find(|k| k.is_current).map_or(0, |k| k.key_id);
            LinkAuthConfig::Crypto {
                keys: keys
                    .iter()
                    .map(|k| Ok((k.key_id, resolve_algorithm(k.algorithm), secret(&k.key)?)))
                    .collect::<Result<_, String>>()?,
                current_key_id,
                extended,
            }
        }
    })
}

fn resolve_algorithm(algorithm: OspfCryptoAlgorithm) -> packet::CryptoAlgorithm {
    match algorithm {
        OspfCryptoAlgorithm::Md5 => packet::CryptoAlgorithm::Md5,
        OspfCryptoAlgorithm::HmacSha1 => packet::CryptoAlgorithm::HmacSha1,
        OspfCryptoAlgorithm::HmacSha256 => packet::CryptoAlgorithm::HmacSha256,
        OspfCryptoAlgorithm::HmacSha384 => packet::CryptoAlgorithm::HmacSha384,
        OspfCryptoAlgorithm::HmacSha512 => packet::CryptoAlgorithm::HmacSha512,
    }
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

    use std::net::Ipv4Addr;

    use super::attach_points_for;
    use super::broadcast_domain_attach_points;
    use super::loopback_attach_points;
    use super::subinterface_attach_points;
    use super::{merge_running, signature, HashSet, Resolved};
    use crate::link::LinkConfig;
    use crate::link_client::{apply, Gate, LinkTable};

    fn interface(name: &str, ospf_profile: Option<&str>) -> Interface {
        Interface {
            ospfv3_profile: None,
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: ospf_profile.map(str::to_string),
            switching_profile: None,
            port_aggregate: None,
            lacp_port_priority: None,
            lacp_link_number: None,
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
            ospfv3_profile: None,
            bfd_unsolicited: None,
            tag: 100,
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: Some("p1".to_string()),
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
                ospfv3_profile: None,
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
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: Some("p1".to_string()),
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
            ospfv3_profile: None,
            bfd_unsolicited: None,
            tag: 0,
            addresses: Vec::new(),
            routing_table: Some("rt1".to_string()),
            ospf_profile: Some("p1".to_string()),
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
    fn subinterface_attach_points_ignores_loopback_and_broadcast_domain() {
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("p1"))],
            broadcast_domains: vec![BroadcastDomain {
                ospfv3_profile: None,
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
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: Some("p1".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(subinterface_attach_points(&cfg, "p1").is_empty());
    }

    #[test]
    fn broadcast_domain_attach_points_finds_routing_table() {
        let cfg = Config {
            broadcast_domains: vec![BroadcastDomain {
                ospfv3_profile: None,
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
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: Some("rt1".to_string()),
                ospf_profile: Some("p1".to_string()),
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

    #[test]
    fn loopback_attach_points_ignores_subinterface_and_broadcast_domain() {
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            ospfv3_profile: None,
            bfd_unsolicited: None,
            tag: 0,
            addresses: Vec::new(),
            routing_table: Some("rt1".to_string()),
            ospf_profile: Some("p1".to_string()),
        }];
        let cfg = Config {
            interfaces: vec![iface],
            broadcast_domains: vec![BroadcastDomain {
                ospfv3_profile: None,
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
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: Some("p1".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(loopback_attach_points(&cfg, "p1").is_empty());
    }

    #[test]
    fn broadcast_domain_attach_points_ignores_loopback_and_subinterface() {
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            ospfv3_profile: None,
            bfd_unsolicited: None,
            tag: 0,
            addresses: Vec::new(),
            routing_table: Some("rt1".to_string()),
            ospf_profile: Some("p1".to_string()),
        }];
        let cfg = Config {
            interfaces: vec![interface("loopback-rt1", Some("p1")), iface],
            ..Default::default()
        };
        assert!(broadcast_domain_attach_points(&cfg, "p1").is_empty());
    }

    fn running() -> LinkConfig {
        LinkConfig {
            attach_point: "eth0.0".into(),
            area_id: Ipv4Addr::UNSPECIFIED,
            hello_interval: 10,
            dead_interval: 40,
            vrf: "vrf-run".into(),
            local_addr: Ipv4Addr::new(10, 0, 0, 1),
            local_prefix_len: 24,
            cost: 1,
            kernel_interface: "br-run".into(),
            network_type: nos_proto::NetworkType::Broadcast,
            priority: 1,
            mtu: 9000,
            mtu_ignore: false,
            ifindex: 3,
            auth: crate::link::LinkAuthConfig::None,
            stub: false,
            nssa: false,
            virtual_link: None,
            helper_max_grace_period: 1800,
        }
    }

    fn resolved() -> Resolved {
        Resolved {
            vrf: Some("vrf-new".into()),
            local_addr: Some(Ipv4Addr::new(10, 0, 0, 2)),
            local_prefix_len: Some(30),
            mtu: Some(1500),
            kernel_interface: Some("br-new".into()),
        }
    }

    #[test]
    fn merge_running_table() {
        let run = running();
        let (m, fb) = merge_running(resolved(), Some(&run)).unwrap();
        assert_eq!(fb, [] as [&str; 0]);
        assert_eq!(
            (m.vrf.as_str(), m.local_prefix_len, m.mtu),
            ("vrf-new", 30, Some(1500))
        );
        let none = Resolved {
            vrf: None,
            local_addr: None,
            local_prefix_len: None,
            mtu: None,
            kernel_interface: None,
        };
        let (m, fb) = merge_running(none, Some(&run)).unwrap();
        assert_eq!(fb, ["vrf", "address", "bridge"]);
        assert_eq!(
            (
                m.vrf.as_str(),
                m.local_addr,
                m.kernel_interface.as_str(),
                m.mtu
            ),
            ("vrf-run", run.local_addr, "br-run", Some(9000))
        );
        let only_vrf = Resolved {
            vrf: None,
            ..resolved()
        };
        assert_eq!(
            merge_running(only_vrf, Some(&run)).unwrap().0.vrf,
            "vrf-run"
        );
        let only_vrf = Resolved {
            vrf: None,
            ..resolved()
        };
        assert!(merge_running(only_vrf, None).is_none());
    }

    #[test]
    fn attach_points_know_whether_the_config_has_an_address() {
        let addr = nos_proto::InterfaceAddress {
            address: "10.0.0.1/24".parse().unwrap(),
            label: None,
        };
        let mut iface = interface("eth0", None);
        iface.subinterfaces = vec![
            Subinterface {
                mtu: None,
                acl_in: None,
                acl_out: None,
                flowspec: false,
                ospfv3_profile: None,
                bfd_unsolicited: None,
                tag: 0,
                addresses: vec![addr],
                routing_table: Some("rt1".into()),
                ospf_profile: Some("p1".into()),
            },
            Subinterface {
                mtu: None,
                acl_in: None,
                acl_out: None,
                flowspec: false,
                ospfv3_profile: None,
                bfd_unsolicited: None,
                tag: 1,
                addresses: Vec::new(),
                routing_table: Some("rt1".into()),
                ospf_profile: Some("p1".into()),
            },
        ];
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
