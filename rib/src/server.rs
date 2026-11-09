use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener};
use nos_proto::{
    BgpRoute, BgpRouteUpdate, EvpnRouteInfo, EvpnUpdate, IpNet, IpcCodec, NextHop, OspfRoute,
    OspfRouteUpdate, PrefixRoutes, RibEvent, RibRequest, Role, RouteEntry, RouteSourceKind,
    VpnRoute, VpnRouteInfo, VpnRouteUpdate, ROUTES_PAGE_MAX,
};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

use crate::driver::RibDriver;
use crate::evpn::EvpnState;
use crate::reconcile::KernelGate;
use crate::rib::{BestPathChange, Rib, RibEntry, RouteSource};

/// Shared, read-only context every connection dispatches against: the
/// table's in-memory `Rib` (for `GetRoutes`/`Lookup`) and the driver
/// backing this instance (for `GetVrfName`, which asks the driver directly
/// rather than caching the answer — see `RibDriver::vrf_name`).
struct Context {
    table: String,
    rib: Arc<RwLock<Rib>>,
    kernel: Arc<KernelGate>,
    driver: Arc<dyn RibDriver>,
}

/// Binds `listen_socket` and spawns the IPC accept loop for route queries.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    table: String,
    rib: Arc<RwLock<Rib>>,
    kernel: Arc<KernelGate>,
    driver: Arc<dyn RibDriver>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(table = %table, socket = %listen_socket.display(), "RIB IPC server listening");
    let ctx = Arc::new(Context {
        table,
        rib,
        kernel,
        driver,
    });
    Ok(tokio::spawn(accept_loop(listener, ctx)))
}

/// Who may send what. Route pushes are the sensitive part — they become
/// kernel routes — so each is reserved for the one daemon family that owns
/// that source. No wildcard arm: a new request must be classified.
// ponytail: role-level only. `bgpd/r2` could still push into `rt1`; binding
// an instance to its table needs a config lookup — add it if that matters.
fn allowed(role: Role, req: &RibRequest) -> bool {
    match req {
        RibRequest::GetRoutes
        | RibRequest::GetRoutesPage { .. }
        | RibRequest::Lookup { .. }
        | RibRequest::GetVpnLabel => {
            matches!(role, Role::User | Role::Restd)
        }
        // `ribd`/`fdbd` name a loopback VTEP's device (`lo<table id>`) of
        // the underlay table.
        // `logd` scopes a syslog collector's socket into its table's VRF.
        RibRequest::GetVrfName | RibRequest::GetTableId => matches!(
            role,
            Role::User
                | Role::Logd
                | Role::Restd
                | Role::Interfaced
                | Role::Bgpd
                | Role::Ospfd
                | Role::Ospfv3d
                | Role::Ribd
                | Role::Fdbd
                | Role::Bfdd
        ),
        // `BgpRouteCount`: a restarted `nos-bgpd`'s graceful-restart check.
        RibRequest::PushBgpRoutes(_)
        | RibRequest::PushEvpnRoutes(_)
        | RibRequest::PushVpnRoutes(_)
        | RibRequest::BgpRouteCount => role == Role::Bgpd,
        // `nos-ospfv3d` shares the OSPF route source: its SPF results are
        // pushed with the same request.
        RibRequest::PushOspfRoutes(_) => matches!(role, Role::Ospfd | Role::Ospfv3d),
        // `ResolveNextHop`: `nos-bgpd` resolving its VPN PE next hops.
        RibRequest::IgpCosts | RibRequest::ResolveNextHop { .. } => {
            matches!(role, Role::User | Role::Restd | Role::Bgpd)
        }
        // Symmetric IRB: the `nos-fdbd` of a domain whose SVI is in this table.
        RibRequest::GetEvpnIrb => role == Role::Fdbd,
    }
}

async fn accept_loop(listener: Listener, ctx: Arc<Context>) {
    loop {
        match listener.accept().await {
            Ok(incoming) => {
                tokio::spawn(serve(incoming, ctx.clone()));
            }
            Err(e) => {
                error!(table = %ctx.table, error = %e, "RIB IPC accept loop terminated");
                break;
            }
        }
    }
}

async fn serve(incoming: Incoming, ctx: Arc<Context>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, name, ctx).await,
        Err(e) => debug!(table = %ctx.table, error = %e, "RIB IPC handshake refused"),
    }
}

async fn handle_connection(stream: nos_pki::Stream, role: Role, name: String, ctx: Arc<Context>) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<RibRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<RibEvent>::default());
    let mut staging = FullStaging::default();

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(req) if !allowed(role, &req) => {
                warn!(
                    table = %ctx.table, role = role.as_str(), name = %name,
                    "RIB request refused: this role may not send it"
                );
                break;
            }
            Ok(req) => match staging.absorb(&ctx.table, req) {
                Some(req) => dispatch(&ctx, req).await,
                None => None,
            },
            Err(e) => {
                warn!(table = %ctx.table, error = %e, "RIB IPC read error");
                break;
            }
        };
        if let Some(event) = event
            && writer.send(event).await.is_err()
        {
            break;
        }
    }
}

/// One connection's chunked BGP/EVPN/VPN/OSPF `Full` snapshot in progress
/// (`BgpRouteUpdate::FullPart`s, see `BgpRouteUpdate::frames`): nothing
/// reaches the `Rib` until the closing `Full`, so the table never shows half
/// a snapshot, and a connection lost mid-snapshot simply drops it.
#[derive(Default)]
struct FullStaging {
    bgp: nos_proto::chunk::FullStaging<BgpRoute>,
    evpn: nos_proto::chunk::FullStaging<nos_proto::EvpnRoute>,
    vpn: nos_proto::chunk::FullStaging<VpnRoute>,
    ospf: nos_proto::chunk::FullStaging<OspfRoute>,
}

impl FullStaging {
    /// Stages every `FullPart` of a `PushBgpRoutes`/`PushEvpnRoutes`/
    /// `PushVpnRoutes`/`PushOspfRoutes` and folds
    /// the staged routes into the closing `Full` (`None`: a part, nothing to
    /// dispatch yet); any other request passes through.
    fn absorb(&mut self, table: &str, req: RibRequest) -> Option<RibRequest> {
        let updates = match req {
            RibRequest::PushBgpRoutes(u) => u,
            RibRequest::PushEvpnRoutes(u) => {
                let (u, parts) = u.absorb(&mut self.evpn)?;
                if parts > 1
                    && let EvpnUpdate::Full(r) = &u
                {
                    info!(
                        table = %table,
                        routes = r.len(),
                        parts,
                        "assembled chunked evpn route snapshot"
                    );
                }
                return Some(RibRequest::PushEvpnRoutes(u));
            }
            RibRequest::PushVpnRoutes(updates) => {
                let mut out = Vec::with_capacity(updates.len());
                for update in updates {
                    match update {
                        VpnRouteUpdate::FullPart(routes) => self.vpn.part(routes),
                        VpnRouteUpdate::Full(routes) if self.vpn.is_staging() => {
                            let (all, parts) = self.vpn.close(routes);
                            info!(
                                table = %table,
                                routes = all.len(),
                                parts,
                                "assembled chunked vpn route snapshot"
                            );
                            out.push(VpnRouteUpdate::Full(all));
                        }
                        update => out.push(update),
                    }
                }
                return Some(RibRequest::PushVpnRoutes(out));
            }
            RibRequest::PushOspfRoutes(updates) => {
                let mut out = Vec::with_capacity(updates.len());
                for update in updates {
                    match update {
                        OspfRouteUpdate::FullPart(routes) => self.ospf.part(routes),
                        OspfRouteUpdate::Full(routes) if self.ospf.is_staging() => {
                            let (all, parts) = self.ospf.close(routes);
                            info!(
                                table = %table,
                                routes = all.len(),
                                parts,
                                "assembled chunked ospf route snapshot"
                            );
                            out.push(OspfRouteUpdate::Full(all));
                        }
                        update => out.push(update),
                    }
                }
                return Some(RibRequest::PushOspfRoutes(out));
            }
            req => return Some(req),
        };
        let mut out = Vec::with_capacity(updates.len());
        for update in updates {
            match update {
                BgpRouteUpdate::FullPart(routes) => self.bgp.part(routes),
                BgpRouteUpdate::Full(routes) if self.bgp.is_staging() => {
                    let (all, parts) = self.bgp.close(routes);
                    info!(
                        table = %table,
                        routes = all.len(),
                        parts,
                        "assembled chunked bgp route snapshot"
                    );
                    out.push(BgpRouteUpdate::Full(all));
                }
                update => out.push(update),
            }
        }
        Some(RibRequest::PushBgpRoutes(out))
    }
}

/// Byte budget of one `RoutesPage`: half the codec's `MAX_FRAME`.
const PAGE_BYTES: usize = nos_proto::codec::MAX_FRAME / 2;

/// One `RoutesPage` reply: at most `limit` (0 or over [`ROUTES_PAGE_MAX`]:
/// the maximum) prefixes, cut early once their encoding passes `budget`
/// bytes (a page always holds at least one prefix, so a walk advances).
fn routes_page(rib: &Rib, after: Option<IpNet>, limit: u32, budget: usize) -> RibEvent {
    let limit = match limit {
        0 => ROUTES_PAGE_MAX,
        n => n.min(ROUTES_PAGE_MAX),
    };
    let (page, mut more) = rib.routes_page(after, limit as usize);
    let mut routes = Vec::with_capacity(page.len());
    let mut bytes = 0;
    for (prefix, candidates) in page {
        let pr = to_prefix_routes(prefix, &candidates, rib);
        bytes += pr.wire_len();
        if bytes > budget && !routes.is_empty() {
            more = true;
            break;
        }
        routes.push(pr);
    }
    let next = more.then(|| routes.last().map(|r| r.prefix)).flatten();
    RibEvent::RoutesPage { routes, next }
}

async fn dispatch(ctx: &Context, req: RibRequest) -> Option<RibEvent> {
    trace!(table = %ctx.table, request = ?req, "serving RIB query");
    match req {
        RibRequest::GetRoutes => Some(RibEvent::Error(
            "GetRoutes removed, use GetRoutesPage".to_string(),
        )),
        RibRequest::GetRoutesPage { after, limit } => {
            let guard = ctx.rib.read().await;
            Some(routes_page(&guard, after, limit, PAGE_BYTES))
        }
        RibRequest::Lookup { addr } => {
            let guard = ctx.rib.read().await;
            Some(match guard.lookup(addr) {
                Some((prefix, candidates)) => {
                    RibEvent::Match(to_prefix_routes(prefix, &candidates, &guard))
                }
                None => RibEvent::NoMatch,
            })
        }
        RibRequest::GetVrfName => Some(RibEvent::VrfName(ctx.driver.vrf_name(&ctx.table).await)),
        RibRequest::GetTableId => Some(RibEvent::TableId(ctx.driver.table_id(&ctx.table).await)),
        RibRequest::PushBgpRoutes(updates) => {
            apply_bgp_route_update(ctx, updates).await;
            None
        }
        RibRequest::PushOspfRoutes(updates) => {
            apply_ospf_route_update(ctx, updates).await;
            None
        }
        RibRequest::IgpCosts => Some(RibEvent::IgpCosts(ctx.rib.read().await.igp_costs())),
        RibRequest::BgpRouteCount => Some(RibEvent::BgpRouteCount(
            ctx.rib.read().await.count_source(RouteSource::Bgp),
        )),
        RibRequest::PushEvpnRoutes(update) => {
            apply_evpn_route_update(
                &ctx.table,
                &ctx.rib,
                &ctx.kernel,
                ctx.driver.as_ref(),
                update,
            )
            .await;
            None
        }
        RibRequest::GetEvpnIrb => Some(RibEvent::EvpnIrb(ctx.rib.read().await.evpn.irb())),
        RibRequest::PushVpnRoutes(updates) => {
            apply_vpn_route_update(ctx, updates).await;
            None
        }
        // ponytail: CLI only; REST `GET /v1/routes/<t>` does not show the label.
        RibRequest::GetVpnLabel => Some(RibEvent::VpnLabel(ctx.rib.read().await.vpn_label)),
        RibRequest::ResolveNextHop { addrs } => {
            let guard = ctx.rib.read().await;
            Some(RibEvent::NextHops(
                addrs.into_iter().map(|a| guard.resolve(a)).collect(),
            ))
        }
    }
}

/// A pushed VPN route as a `Rib` candidate.
fn vpn_entry(r: &VpnRoute) -> RibEntry {
    RibEntry {
        prefix: r.prefix,
        next_hops: r
            .paths
            .iter()
            .map(|p| NextHop {
                gateway: p.gateway,
                interface_id: p.interface_id,
                labels: p.labels.clone(),
            })
            .collect(),
        source: RouteSource::Vpn,
        backup: None,
        backup_interface_id: None,
        backup_tunnel: false,
    }
}

/// The PE and RD of each of `r`'s paths, in next-hop order.
fn vpn_info(r: &VpnRoute) -> Vec<VpnRouteInfo> {
    r.paths
        .iter()
        .map(|p| VpnRouteInfo {
            pe_next_hop: p.pe_next_hop,
            rd: p.rd.clone(),
        })
        .collect()
}

/// Applies one batch of VPN routes imported by the underlay `nos-bgpd` —
/// the `Vpn`-source twin of `apply_bgp_route_update` (`Full` replaces only
/// the `Vpn` candidates, so a CE-facing instance's `Bgp` routes in the same
/// table are untouched). A `Vpn` winner is installed as a labelled route;
/// a changed label or PE resolution is a changed winner (`apply_delta`).
async fn apply_vpn_route_update(ctx: &Context, updates: Vec<VpnRouteUpdate>) {
    let gate = ctx.kernel.lock().await;
    let mut guard = ctx.rib.write().await;
    let mut deltas: HashMap<IpNet, Option<RibEntry>> = HashMap::new();
    let mut full_replace = false;
    for update in updates {
        let (prefix, change) = match update {
            VpnRouteUpdate::Full(routes) => {
                guard.vpn_info = routes.iter().map(|r| (r.prefix, vpn_info(r))).collect();
                guard.replace_source(RouteSource::Vpn, routes.iter().map(vpn_entry));
                full_replace = true;
                continue;
            }
            VpnRouteUpdate::Add(r) => {
                guard.vpn_info.insert(r.prefix, vpn_info(&r));
                (r.prefix, guard.upsert_and_diff(vpn_entry(&r)))
            }
            VpnRouteUpdate::Remove(prefix) => {
                guard.vpn_info.remove(&prefix);
                (prefix, guard.remove_and_diff(&prefix, RouteSource::Vpn))
            }
            // Staged by `FullStaging::absorb` before dispatch.
            VpnRouteUpdate::FullPart(_) => continue,
        };
        match change {
            BestPathChange::Unchanged => {}
            BestPathChange::Installed(e) => {
                deltas.insert(prefix, Some(e));
            }
            BestPathChange::Removed => {
                deltas.insert(prefix, None);
            }
        }
    }
    let result = if full_replace {
        let routes = guard.best_routes_for_kernel();
        drop(guard);
        let r = ctx.driver.apply(&ctx.table, &routes).await;
        if ctx.kernel.source_done(&gate, RouteSource::Vpn) {
            ctx.kernel
                .release_hold(
                    &ctx.table,
                    &ctx.rib,
                    &gate,
                    ctx.driver.as_ref(),
                    "all sources re-pushed",
                )
                .await;
        }
        r
    } else {
        drop(guard);
        if deltas.is_empty() {
            return;
        }
        ctx.driver.apply_delta(&ctx.table, &deltas).await
    };
    if let Err(e) = result {
        error!(table = %ctx.table, error = %e, "failed to apply vpn-pushed routes to kernel");
        ctx.kernel.mark_dirty();
    }
    drop(gate);
}

/// Applies one push of received Type-5 routes. `Full` keeps the raw set
/// (`EvpnState.received`), rebuilds the `Evpn` candidates and resyncs the
/// kernel (devices, remote VTEPs, every route). `Add`/`Remove` (#763) recompute
/// only the touched prefix (`Rib::apply_evpn_diff`): the devices are synced
/// only when the remote VTEP set changed, the routes through `apply_delta`.
pub(crate) async fn apply_evpn_route_update(
    table: &str,
    rib: &RwLock<Rib>,
    kernel: &KernelGate,
    driver: &dyn RibDriver,
    update: EvpnUpdate,
) {
    let gate = kernel.lock().await;
    let (key, route) = match update {
        EvpnUpdate::Full(routes) => {
            {
                let mut guard = rib.write().await;
                guard.evpn.received = routes.into_iter().map(|r| (r.key.clone(), r)).collect();
                guard.refresh_evpn();
            }
            crate::reconcile::apply_to_kernel(table, rib, kernel, &gate, driver).await;
            if kernel.source_done(&gate, RouteSource::Evpn) {
                kernel
                    .release_hold(table, rib, &gate, driver, "all sources re-pushed")
                    .await;
            }
            return;
        }
        EvpnUpdate::Add(r) => (r.key.clone(), Some(r)),
        EvpnUpdate::Remove(key) => (key, None),
        // Staged by the connection handler (`FullStaging::absorb`).
        EvpnUpdate::FullPart(_) => return,
    };
    let (change, first_sync) = {
        let mut guard = rib.write().await;
        let change = guard.apply_evpn_diff(&key, route);
        // The bridge never built yet: its Router's MAC is still unknown.
        (
            change,
            guard.evpn.local.is_some() && guard.evpn.rmac.is_none(),
        )
    };
    let Some((prefix, change, remotes_changed)) = change else {
        return;
    };
    if remotes_changed || first_sync {
        crate::reconcile::sync_l3vni(table, rib, &gate, driver).await;
    }
    let delta = match change {
        BestPathChange::Unchanged => return,
        BestPathChange::Installed(e) => Some(e),
        BestPathChange::Removed => None,
    };
    let deltas = HashMap::from([(prefix, delta)]);
    // On failure, `run` re-applies the whole table at once.
    if let Err(e) = driver.apply_delta(table, &deltas).await {
        error!(table = %table, error = %e, "failed to apply evpn route delta to kernel");
        kernel.mark_dirty();
    }
}

/// Applies one batch of BGP-pushed route updates (one poll tick's worth,
/// see `nos_proto::rib::RibRequest::PushBgpRoutes`) to the shared `Rib`,
/// independent of `crate::reconcile::resync`'s own periodic apply — safe
/// because the two writers only ever touch disjoint `RouteSource`
/// candidates (see `Rib::replace_source`'s doc comment). `Full` (rare —
/// only on BGP connect/reconnect/withdraw) goes through the driver's full
/// dump-diff-converge `apply`, since it replaces the whole `Bgp`-sourced
/// set at once. `Add`/`Remove` (the frequent per-route hot path) instead
/// recompute only the touched prefix's winning route (`Rib::upsert_and_diff`/
/// `remove_and_diff`) and, only for a prefix whose winner actually changed,
/// queue a delta applied directly via `apply_delta` — never a whole-table
/// recompute or a fresh kernel dump for an incremental push.
async fn apply_bgp_route_update(ctx: &Context, updates: Vec<BgpRouteUpdate>) {
    let gate = ctx.kernel.lock().await;
    let mut guard = ctx.rib.write().await;
    let mut deltas: HashMap<IpNet, Option<RibEntry>> = HashMap::new();
    let mut full_replace = false;

    for update in updates {
        match update {
            BgpRouteUpdate::Full(routes) => {
                guard.replace_source(RouteSource::Bgp, routes.into_iter().map(bgp_entry));
                full_replace = true;
            }
            BgpRouteUpdate::Add(r) => {
                let prefix = r.prefix;
                match guard.upsert_and_diff(bgp_entry(r)) {
                    BestPathChange::Unchanged => {}
                    BestPathChange::Installed(e) => {
                        deltas.insert(prefix, Some(e));
                    }
                    BestPathChange::Removed => {
                        deltas.insert(prefix, None);
                    }
                }
            }
            // Staged by `FullStaging::absorb` before dispatch.
            BgpRouteUpdate::FullPart(_) => {}
            BgpRouteUpdate::Remove(prefix) => {
                match guard.remove_and_diff(&prefix, RouteSource::Bgp) {
                    BestPathChange::Unchanged => {}
                    BestPathChange::Installed(e) => {
                        deltas.insert(prefix, Some(e));
                    }
                    BestPathChange::Removed => {
                        deltas.insert(prefix, None);
                    }
                }
            }
        }
    }

    if full_replace {
        let routes = guard.best_routes_for_kernel();
        drop(guard);
        info!(table = %ctx.table, prefixes = routes.len(), "applying bgp-pushed routes to kernel");
        if let Err(e) = ctx.driver.apply(&ctx.table, &routes).await {
            error!(table = %ctx.table, error = %e, "failed to apply bgp-pushed routes to kernel");
            ctx.kernel.mark_dirty();
        }
        if ctx.kernel.source_done(&gate, RouteSource::Bgp) {
            ctx.kernel
                .release_hold(
                    &ctx.table,
                    &ctx.rib,
                    &gate,
                    ctx.driver.as_ref(),
                    "all sources re-pushed",
                )
                .await;
        }
    } else {
        drop(guard);
        if !deltas.is_empty() {
            info!(table = %ctx.table, changed = deltas.len(), "applying bgp route deltas to kernel");
            if let Err(e) = ctx.driver.apply_delta(&ctx.table, &deltas).await {
                error!(table = %ctx.table, error = %e, "failed to apply bgp route deltas to kernel");
                ctx.kernel.mark_dirty();
            }
        }
    }
}

/// Applies one batch of OSPF-pushed route updates to the shared `Rib` — the
/// OSPF analogue of `apply_bgp_route_update` above, identical shape (`Full`
/// goes through the driver's full `apply`, `Add`/`Remove` recompute only the
/// touched prefix's winner and `apply_delta` just that), since the two
/// writers only ever touch disjoint `RouteSource` candidates.
async fn apply_ospf_route_update(ctx: &Context, updates: Vec<OspfRouteUpdate>) {
    let gate = ctx.kernel.lock().await;
    let mut guard = ctx.rib.write().await;
    let mut deltas: HashMap<IpNet, Option<RibEntry>> = HashMap::new();
    let mut full_replace = false;

    for update in updates {
        match update {
            OspfRouteUpdate::Full(routes) => {
                guard.set_ospf_metrics(routes.iter().map(|r| (r.prefix, r.metric)));
                guard.replace_source(RouteSource::Ospf, routes.into_iter().map(ospf_entry));
                full_replace = true;
            }
            // Staged by `FullStaging::absorb` before dispatch.
            OspfRouteUpdate::FullPart(_) => {}
            OspfRouteUpdate::Add(r) => {
                guard.set_ospf_metric(r.prefix, Some(r.metric));
                let prefix = r.prefix;
                match guard.upsert_and_diff(ospf_entry(r)) {
                    BestPathChange::Unchanged => {}
                    BestPathChange::Installed(e) => {
                        deltas.insert(prefix, Some(e));
                    }
                    BestPathChange::Removed => {
                        deltas.insert(prefix, None);
                    }
                }
            }
            OspfRouteUpdate::Remove(prefix) => {
                guard.set_ospf_metric(prefix, None);
                match guard.remove_and_diff(&prefix, RouteSource::Ospf) {
                    BestPathChange::Unchanged => {}
                    BestPathChange::Installed(e) => {
                        deltas.insert(prefix, Some(e));
                    }
                    BestPathChange::Removed => {
                        deltas.insert(prefix, None);
                    }
                }
            }
        }
    }

    if full_replace {
        let routes = guard.best_routes_for_kernel();
        drop(guard);
        info!(table = %ctx.table, prefixes = routes.len(), "applying ospf-pushed routes to kernel");
        if let Err(e) = ctx.driver.apply(&ctx.table, &routes).await {
            error!(table = %ctx.table, error = %e, "failed to apply ospf-pushed routes to kernel");
            ctx.kernel.mark_dirty();
        }
        if ctx.kernel.source_done(&gate, RouteSource::Ospf) {
            ctx.kernel
                .release_hold(
                    &ctx.table,
                    &ctx.rib,
                    &gate,
                    ctx.driver.as_ref(),
                    "all sources re-pushed",
                )
                .await;
        }
    } else {
        drop(guard);
        if !deltas.is_empty() {
            info!(table = %ctx.table, changed = deltas.len(), "applying ospf route deltas to kernel");
            if let Err(e) = ctx.driver.apply_delta(&ctx.table, &deltas).await {
                error!(table = %ctx.table, error = %e, "failed to apply ospf route deltas to kernel");
                ctx.kernel.mark_dirty();
            }
        }
    }
}

/// A pushed BGP route as a `Rib` candidate: an RFC 7999 blackhole (`discard`)
/// has no next hop and no backup — see `RibEntry::is_discard`.
fn bgp_entry(r: BgpRoute) -> RibEntry {
    RibEntry {
        prefix: r.prefix,
        next_hops: if r.discard {
            Vec::new()
        } else {
            r.next_hops.into_iter().map(|h| (h, None).into()).collect()
        },
        source: RouteSource::Bgp,
        backup: r.backup_next_hop.filter(|_| !r.discard),
        backup_interface_id: None,
        backup_tunnel: false,
    }
}

/// A pushed OSPF route as a `Rib` candidate: a discard route is one with no
/// next hop (and so no backup) — see `RibEntry::is_discard`.
fn ospf_entry(r: OspfRoute) -> RibEntry {
    RibEntry {
        prefix: r.prefix,
        next_hops: if r.discard {
            Vec::new()
        } else {
            r.next_hops.into_iter().map(Into::into).collect()
        },
        source: RouteSource::Ospf,
        backup: r.backup_next_hop.or(r.backup_tunnel).filter(|_| !r.discard),
        backup_interface_id: r.backup_interface_id,
        backup_tunnel: r.backup_next_hop.is_none() && r.backup_tunnel.is_some() && !r.discard,
    }
}

fn to_prefix_routes(prefix: nos_proto::IpNet, candidates: &[RibEntry], rib: &Rib) -> PrefixRoutes {
    let (evpn, vpn_info) = (&rib.evpn, &rib.vpn_info);
    PrefixRoutes {
        prefix,
        candidates: candidates
            .iter()
            .map(|e| RouteEntry {
                gateways: e.next_hops.iter().map(|h| h.gateway).collect(),
                source: to_source_kind(e.source),
                backup: e.backup,
                discard: e.is_discard(),
                // A BGP discard is an RFC 7999 blackhole; an OSPF ABR's is not.
                blackhole: e.is_discard() && e.source == RouteSource::Bgp,
                evpn: evpn_info(e, evpn),
                backup_tunnel: e.backup_tunnel,
                mpls_labels: e.next_hops.iter().map(|h| h.labels.clone()).collect(),
                vpn: if e.source == RouteSource::Vpn {
                    vpn_info.get(&prefix).cloned().unwrap_or_default()
                } else {
                    Vec::new()
                },
            })
            .collect(),
    }
}

/// `show route`'s view of an `Evpn` candidate: its VTEP, that PE's Router's
/// MAC and the L3 VNI.
fn evpn_info(e: &RibEntry, evpn: &EvpnState) -> Option<EvpnRouteInfo> {
    let vtep = e.next_hops.first()?.gateway;
    (e.source == RouteSource::Evpn).then(|| EvpnRouteInfo {
        vtep,
        router_mac: evpn
            .remotes
            .get(&vtep)
            .map(nos_proto::evpn_id::format_mac)
            .unwrap_or_default(),
        vni: evpn.local.as_ref().map_or(0, |l| l.vni),
    })
}

pub(crate) fn to_source_kind(source: RouteSource) -> RouteSourceKind {
    match source {
        RouteSource::Static => RouteSourceKind::Static,
        RouteSource::Bgp => RouteSourceKind::Bgp,
        RouteSource::Ospf => RouteSourceKind::Ospf,
        RouteSource::Connected => RouteSourceKind::Connected,
        RouteSource::Evpn => RouteSourceKind::Evpn,
        RouteSource::Vpn => RouteSourceKind::Vpn,
    }
}

#[cfg(test)]
mod authz_tests {
    use super::*;

    #[test]
    fn a_discard_ospf_route_has_no_next_hop() {
        let route = OspfRoute {
            prefix: "10.9.0.0/16".parse().unwrap(),
            next_hops: vec![("10.0.0.1".parse().unwrap(), None)],
            backup_next_hop: Some("10.0.0.2".parse().unwrap()),
            backup_interface_id: None,
            metric: 3,
            discard: true,
            backup_tunnel: None,
        };
        let entry = ospf_entry(route.clone());
        assert!(entry.is_discard());
        assert_eq!(entry.backup, None);
        assert!(to_prefix_routes(entry.prefix, &[entry], &Rib::new()).candidates[0].discard);
        assert!(!ospf_entry(OspfRoute {
            discard: false,
            ..route
        })
        .is_discard());
    }

    #[test]
    fn a_remote_lfa_becomes_a_tunnel_backup() {
        let pq: std::net::IpAddr = "10.255.0.4".parse().unwrap();
        let entry = ospf_entry(OspfRoute {
            prefix: "10.255.0.2/32".parse().unwrap(),
            next_hops: vec![("10.1.2.2".parse().unwrap(), None)],
            backup_next_hop: None,
            backup_interface_id: None,
            metric: 2,
            discard: false,
            backup_tunnel: Some(pq),
        });
        assert_eq!((entry.backup, entry.backup_tunnel), (Some(pq), true));
        let shown = to_prefix_routes(entry.prefix, &[entry], &Rib::new());
        assert!(shown.candidates[0].backup_tunnel);
    }

    /// `backup_tunnel` needs a tunnel target, no plain backup next hop and no
    /// discard: each condition alone must be enough to clear it (#364).
    #[test]
    fn a_tunnel_backup_needs_all_three_conditions() {
        let route = |backup_next_hop, backup_tunnel, discard| OspfRoute {
            prefix: "10.255.0.2/32".parse().unwrap(),
            next_hops: vec![("10.1.2.2".parse().unwrap(), None)],
            backup_next_hop,
            backup_interface_id: None,
            metric: 2,
            discard,
            backup_tunnel,
        };
        let ip: std::net::IpAddr = "10.255.0.4".parse().unwrap();
        assert!(ospf_entry(route(None, Some(ip), false)).backup_tunnel);
        assert!(!ospf_entry(route(None, None, false)).backup_tunnel);
        assert!(!ospf_entry(route(Some(ip), None, false)).backup_tunnel);
        assert!(!ospf_entry(route(Some(ip), Some(ip), false)).backup_tunnel);
        assert!(!ospf_entry(route(None, Some(ip), true)).backup_tunnel);
    }

    /// RFC 7999: a BGP discard has no hop or backup and is reported as a
    /// blackhole; an OSPF ABR discard is a plain discard.
    #[test]
    fn a_bgp_discard_is_a_blackhole_and_an_ospf_one_is_not() {
        let b = bgp_entry(BgpRoute {
            prefix: "198.51.100.7/32".parse().unwrap(),
            next_hops: vec![],
            backup_next_hop: Some("10.0.0.9".parse().unwrap()),
            discard: true,
        });
        assert!(b.is_discard() && b.backup.is_none());
        let normal = bgp_entry(BgpRoute {
            prefix: "198.51.100.8/32".parse().unwrap(),
            next_hops: vec!["10.0.0.2".parse().unwrap()],
            backup_next_hop: None,
            discard: false,
        });
        assert!(!normal.is_discard());
        let o = ospf_entry(OspfRoute {
            prefix: "10.2.0.0/24".parse().unwrap(),
            next_hops: vec![],
            metric: 1,
            discard: true,
            backup_next_hop: None,
            backup_tunnel: None,
            backup_interface_id: None,
        });
        let rib = Rib::new();
        let flags = |e: RibEntry| {
            let c = &to_prefix_routes(e.prefix, &[e], &rib).candidates[0];
            (c.discard, c.blackhole)
        };
        assert_eq!(flags(b), (true, true));
        assert_eq!(flags(normal), (false, false));
        assert_eq!(flags(o), (true, false));
    }

    #[test]
    fn an_evpn_candidate_shows_its_router_mac_and_vni() {
        let vtep: std::net::IpAddr = "10.50.0.3".parse().unwrap();
        let entry = RibEntry {
            prefix: "10.2.0.0/24".parse().unwrap(),
            next_hops: vec![(vtep, None).into()],
            source: RouteSource::Evpn,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
        };
        let evpn = EvpnState {
            remotes: [(vtep, [2, 0, 0, 0, 0, 3])].into(),
            ..EvpnState::default()
        };
        let mut rib = Rib::new();
        rib.evpn = evpn;
        let shown = to_prefix_routes(entry.prefix, &[entry], &rib);
        let info = shown.candidates[0].evpn.as_ref().unwrap();
        assert_eq!(shown.candidates[0].source, RouteSourceKind::Evpn);
        assert_eq!(
            (info.vtep, info.router_mac.as_str()),
            (vtep, "02:00:00:00:00:03")
        );
    }

    #[test]
    fn only_the_owning_daemon_family_may_push_routes() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &RibRequest::PushBgpRoutes(vec![])),
                role == Role::Bgpd
            );
            assert_eq!(
                allowed(
                    role,
                    &RibRequest::PushOspfRoutes(vec![OspfRouteUpdate::FullPart(vec![])])
                ),
                matches!(role, Role::Ospfd | Role::Ospfv3d)
            );
            assert_eq!(
                allowed(role, &RibRequest::PushEvpnRoutes(EvpnUpdate::Full(vec![]))),
                role == Role::Bgpd
            );
            assert_eq!(
                allowed(role, &RibRequest::PushVpnRoutes(vec![])),
                role == Role::Bgpd
            );
        }
    }

    #[test]
    fn next_hop_resolution_is_for_bgpd_and_readers_only() {
        for role in Role::ALL {
            let expected = matches!(role, Role::User | Role::Restd | Role::Bgpd);
            let req = RibRequest::ResolveNextHop { addrs: vec![] };
            assert_eq!(allowed(role, &req), expected, "{role:?}");
        }
    }

    /// Every kernel write fails.
    struct FailingDriver;

    #[async_trait::async_trait]
    impl RibDriver for FailingDriver {
        async fn apply(
            &self,
            _: &str,
            _: &HashMap<IpNet, RibEntry>,
        ) -> Result<(), crate::driver::DriverError> {
            Err(crate::driver::DriverError::Other("boom".into()))
        }
        async fn apply_delta(
            &self,
            _: &str,
            _: &HashMap<IpNet, Option<RibEntry>>,
        ) -> Result<(), crate::driver::DriverError> {
            Err(crate::driver::DriverError::Other("boom".into()))
        }
        async fn teardown(&self, _: &str) -> Result<(), crate::driver::DriverError> {
            Ok(())
        }
        async fn vrf_name(&self, _: &str) -> Option<String> {
            None
        }
        async fn table_id(&self, _: &str) -> Option<u32> {
            None
        }
    }

    /// #653: a failed full apply or delta, from any producer, marks the gate dirty.
    #[tokio::test]
    async fn a_failed_kernel_write_marks_the_gate_dirty() {
        let ctx = Context {
            table: "t".to_string(),
            rib: Arc::new(RwLock::new(Rib::new())),
            kernel: Arc::default(),
            driver: Arc::new(FailingDriver),
        };
        let dirty = |ctx: &Context| ctx.kernel.take_dirty_for_test();
        let d = FailingDriver;
        assert!(d.teardown("t").await.is_ok());
        assert_eq!((d.vrf_name("t").await, d.table_id("t").await), (None, None));
        let r = |p: &str| BgpRoute {
            prefix: p.parse().unwrap(),
            next_hops: vec!["10.0.0.2".parse().unwrap()],
            backup_next_hop: None,
            discard: false,
        };
        apply_bgp_route_update(&ctx, vec![BgpRouteUpdate::Add(r("10.1.0.0/24"))]).await;
        assert!(dirty(&ctx));
        apply_bgp_route_update(&ctx, vec![BgpRouteUpdate::Full(vec![])]).await;
        assert!(dirty(&ctx));
        let o = OspfRoute {
            prefix: "10.2.0.0/24".parse().unwrap(),
            next_hops: vec![],
            metric: 1,
            discard: true,
            backup_next_hop: None,
            backup_tunnel: None,
            backup_interface_id: None,
        };
        apply_ospf_route_update(&ctx, vec![OspfRouteUpdate::Add(o)]).await;
        assert!(dirty(&ctx));
        apply_ospf_route_update(&ctx, vec![OspfRouteUpdate::Full(vec![])]).await;
        assert!(dirty(&ctx));
        apply_vpn_route_update(&ctx, vec![VpnRouteUpdate::Add(vpn_route("10.3.0.0/24", 1))]).await;
        assert!(dirty(&ctx));
        apply_vpn_route_update(&ctx, vec![VpnRouteUpdate::Full(vec![])]).await;
        assert!(dirty(&ctx));
    }

    fn vpn_path(rd: &str, label: u32) -> nos_proto::VpnPath {
        nos_proto::VpnPath {
            pe_next_hop: "192.0.2.3".parse().unwrap(),
            rd: rd.to_string(),
            gateway: "10.0.0.3".parse().unwrap(),
            interface_id: None,
            labels: vec![label],
        }
    }

    fn vpn_route(prefix: &str, label: u32) -> VpnRoute {
        VpnRoute {
            prefix: prefix.parse().unwrap(),
            paths: vec![vpn_path("65001:1", label)],
        }
    }

    /// #594: the same PE under two RDs with different labels is two next
    /// hops of one candidate, each with its own labels, PE and RD.
    #[test]
    fn a_multi_path_vpn_route_keeps_one_hop_per_path() {
        let r = VpnRoute {
            prefix: "10.1.0.0/24".parse().unwrap(),
            paths: vec![vpn_path("65001:1", 100), vpn_path("65001:2", 200)],
        };
        let e = vpn_entry(&r);
        let labels: Vec<_> = e.next_hops.iter().map(|h| h.labels.clone()).collect();
        assert_eq!(labels, vec![vec![100], vec![200]]);
        assert_eq!(e.next_hops[0].gateway, e.next_hops[1].gateway);
        let mut rib = Rib::new();
        rib.vpn_info.insert(r.prefix, vpn_info(&r));
        let shown = &to_prefix_routes(r.prefix, &[e], &rib).candidates[0];
        assert_eq!(shown.mpls_labels, labels);
        let rds: Vec<_> = shown.vpn.iter().map(|v| v.rd.as_str()).collect();
        assert_eq!(rds, ["65001:1", "65001:2"]);
    }

    #[tokio::test]
    async fn vpn_pushes_land_as_the_vpn_source_and_show_their_pe() {
        let ctx = Context {
            table: "red".to_string(),
            rib: Arc::new(RwLock::new(Rib::new())),
            kernel: Arc::default(),
            driver: Arc::new(crate::driver::NoopRibDriver::default()),
        };
        let a = vpn_route("10.1.0.0/24", 100);
        let b = vpn_route("10.2.0.0/24", 200);
        apply_vpn_route_update(&ctx, vec![VpnRouteUpdate::Full(vec![a.clone()])]).await;
        apply_vpn_route_update(
            &ctx,
            vec![VpnRouteUpdate::Add(b), VpnRouteUpdate::Remove(a.prefix)],
        )
        .await;
        // A delta that changes nothing in the kernel is a no-op.
        apply_vpn_route_update(&ctx, vec![VpnRouteUpdate::Remove(a.prefix)]).await;
        let Some(RibEvent::RoutesPage { routes, next: None }) = dispatch(
            &ctx,
            RibRequest::GetRoutesPage {
                after: None,
                limit: 0,
            },
        )
        .await
        else {
            panic!("no routes");
        };
        assert_eq!(routes.len(), 1);
        let c = &routes[0].candidates[0];
        assert_eq!(
            (c.source, c.mpls_labels.clone()),
            (RouteSourceKind::Vpn, vec![vec![200]])
        );
        assert_eq!(c.vpn[0].rd, "65001:1");
        let Some(RibEvent::NextHops(hops)) = dispatch(
            &ctx,
            RibRequest::ResolveNextHop {
                addrs: vec!["10.2.0.1".parse().unwrap()],
            },
        )
        .await
        else {
            panic!("no next hops");
        };
        // A Vpn route never resolves a next hop.
        assert_eq!(hops, vec![None]);
        ctx.rib.write().await.vpn_label = Some(1000);
        assert!(matches!(
            dispatch(&ctx, RibRequest::GetVpnLabel).await,
            Some(RibEvent::VpnLabel(Some(1000)))
        ));
    }

    fn static_rib(n: u8) -> Rib {
        let mut rib = Rib::new();
        for i in 0..n {
            rib.insert(RibEntry {
                prefix: format!("10.0.{i}.0/24").parse().unwrap(),
                next_hops: vec![("10.9.9.9".parse().unwrap(), None).into()],
                source: RouteSource::Static,
                backup: None,
                backup_interface_id: None,
                backup_tunnel: false,
            });
        }
        rib
    }

    fn page_of(e: RibEvent) -> (Vec<String>, Option<String>) {
        let RibEvent::RoutesPage { routes, next } = e else {
            panic!("not a page");
        };
        (
            routes.iter().map(|r| r.prefix.to_string()).collect(),
            next.map(|n| n.to_string()),
        )
    }

    #[test]
    fn routes_pages_walk_the_table_by_cursor() {
        let rib = static_rib(5);
        let (p, next) = page_of(routes_page(&rib, None, 2, usize::MAX));
        assert_eq!(
            (p.as_slice(), next.as_deref()),
            (
                &["10.0.0.0/24".into(), "10.0.1.0/24".into()][..],
                Some("10.0.1.0/24")
            )
        );
        let (p, next) = page_of(routes_page(&rib, "10.0.1.0/24".parse().ok(), 2, usize::MAX));
        assert_eq!((p.len(), next.as_deref()), (2, Some("10.0.3.0/24")));
        // The last, short page ends the walk; limit 0 means the maximum.
        let (p, next) = page_of(routes_page(&rib, "10.0.3.0/24".parse().ok(), 0, usize::MAX));
        assert_eq!((p, next), (vec!["10.0.4.0/24".to_string()], None));
    }

    #[test]
    fn a_byte_budget_cuts_a_page_but_always_advances() {
        let rib = static_rib(5);
        // A 1-byte budget still returns one prefix and a cursor.
        let (p, next) = page_of(routes_page(&rib, None, 100, 1));
        assert_eq!((p.len(), next.as_deref()), (1, Some("10.0.0.0/24")));
        let one = rib.routes_page(None, 1).0;
        let len = to_prefix_routes(one[0].0, &one[0].1, &rib).wire_len();
        let (p, next) = page_of(routes_page(&rib, None, 100, len * 2));
        assert_eq!((p.len(), next.as_deref()), (2, Some("10.0.1.0/24")));
    }

    #[tokio::test]
    async fn the_removed_get_routes_answers_with_an_error() {
        let ctx = Context {
            table: "t".to_string(),
            rib: Arc::new(RwLock::new(Rib::new())),
            kernel: Arc::default(),
            driver: Arc::new(crate::driver::NoopRibDriver::default()),
        };
        assert!(matches!(
            dispatch(&ctx, RibRequest::GetRoutes).await,
            Some(RibEvent::Error(m)) if m.contains("GetRoutesPage")
        ));
    }

    #[test]
    fn route_queries_are_for_people_and_the_rest_api() {
        for role in Role::ALL {
            let expected = matches!(role, Role::User | Role::Restd);
            assert_eq!(allowed(role, &RibRequest::GetRoutes), expected, "{role:?}");
            let page = RibRequest::GetRoutesPage {
                after: None,
                limit: 1,
            };
            assert_eq!(allowed(role, &page), expected, "{role:?}");
            assert_eq!(
                allowed(role, &RibRequest::GetVpnLabel),
                expected,
                "{role:?}"
            );
        }
        // The daemons that resolve a VRF (or a loopback VTEP) through this instance.
        for role in [
            Role::Interfaced,
            Role::Bgpd,
            Role::Ospfd,
            Role::Ospfv3d,
            Role::Ribd,
            Role::Fdbd,
            Role::Logd,
            Role::Bfdd,
        ] {
            assert!(allowed(role, &RibRequest::GetVrfName), "{role:?}");
        }
        assert!(!allowed(Role::Lacpd, &RibRequest::GetVrfName));
    }

    #[test]
    fn igp_costs_are_for_bgpd_and_readers_only() {
        for role in Role::ALL {
            let expected = matches!(role, Role::User | Role::Restd | Role::Bgpd);
            assert_eq!(allowed(role, &RibRequest::IgpCosts), expected, "{role:?}");
        }
    }

    #[test]
    fn evpn_irb_is_for_fdbd_only_and_none_before_the_router_mac() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &RibRequest::GetEvpnIrb),
                role == Role::Fdbd,
                "{role:?}"
            );
        }
        assert_eq!(EvpnState::default().irb(), None);
    }

    #[test]
    fn bgp_route_count_is_for_bgpd_only() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &RibRequest::BgpRouteCount),
                role == Role::Bgpd,
                "{role:?}"
            );
        }
    }
}
