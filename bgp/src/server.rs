use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::chunk::FullStaging;
use nos_proto::{
    BgpEvent, BgpRequest, EvpnRoute, EvpnUpdate, IpcCodec, RedistributeUpdate, Role, VpnPrefix,
    VpnPrefixUpdate,
};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, trace, warn};

use crate::collision::FsmCommand;
use crate::page::{Snapshot, PAGE_BYTES};
use crate::rib::EvpnSource;
use crate::session::{SessionManager, VpnAsk, VpnSnapshot};

/// Binds `listen_socket` and spawns the IPC accept loop for session
/// summaries.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
/// `watchdog_socket` resolves `nos-acld` for `show bgp flowspec`.
pub fn start(
    listen_socket: &Path,
    instance: String,
    sessions: Arc<SessionManager>,
    identity: &Identity,
    watchdog_socket: PathBuf,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(instance = %instance, socket = %listen_socket.display(), "BGP IPC server listening");
    let ctx = Arc::new((instance, sessions, watchdog_socket));
    Ok(tokio::spawn(accept_loop(listener, ctx)))
}

/// What every connection needs: the instance name, the sessions, the
/// watchdog socket.
type Ctx = Arc<(String, Arc<SessionManager>, PathBuf)>;

/// Session queries and `clear bgp` are for people (and `Restd` on their
/// behalf); the redistribution feed is `nos-ribd`'s alone. No wildcard arm.
fn allowed(role: Role, req: &BgpRequest) -> bool {
    match req {
        BgpRequest::GetSummary
        | BgpRequest::GetEvpnRoutes
        | BgpRequest::GetFlowspecRoutes
        | BgpRequest::GetVpnRoutes { .. }
        | BgpRequest::SendRouteRefresh { .. }
        | BgpRequest::ClearPeer { .. }
        | BgpRequest::GetRoutes
        | BgpRequest::GetRoutesPage { .. }
        | BgpRequest::GetEvpnRoutesPage { .. }
        | BgpRequest::GetFlowspecRoutesPage { .. }
        | BgpRequest::GetVpnRoutesPage { .. }
        | BgpRequest::GetRpkiSummary
        | BgpRequest::ShowBmp { .. } => {
            matches!(role, Role::User | Role::Restd)
        }
        BgpRequest::RedistributeRoutes(_)
        | BgpRequest::RedistributeEvpnPrefixes { .. }
        | BgpRequest::RedistributeVpnPrefixes { .. } => role == Role::Ribd,
        BgpRequest::RedistributeMacs { .. } => role == Role::Fdbd,
    }
}

async fn accept_loop(listener: Listener, ctx: Ctx) {
    loop {
        let incoming = listener.accept_resilient().await;
        tokio::spawn(serve(incoming, ctx.clone()));
    }
}

/// Handles one connection for its whole lifetime. `GetSummary` sends one
/// reply per request; `RedistributeRoutes` (sent continuously by `nos-ribd`
/// over one long-lived connection, mirroring `nos-logd`'s handling of
/// `LogRequest::Push`) gets no reply at all, so the loop just keeps reading
/// further requests on the same connection.
async fn serve(incoming: Incoming, ctx: Ctx) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, name, ctx).await,
        Err(e) => debug!(instance = %ctx.0, error = %e, "BGP IPC handshake refused"),
    }
}

/// One sorted key snapshot per paged query kind, dropped with the connection.
#[derive(Default)]
struct Snapshots {
    routes: Snapshot<nos_proto::BgpRouteCursor>,
    evpn: Snapshot<crate::rib::EvpnKey>,
    flowspec: Snapshot<crate::rib::FlowKey>,
    vpn: VpnSnapshot,
}

impl Snapshots {
    /// The reply to a paged query (#722, #723); `None` for any other request.
    async fn page(
        &mut self,
        req: &BgpRequest,
        sessions: &SessionManager,
        watchdog_socket: &Path,
    ) -> Option<BgpEvent> {
        Some(match req {
            BgpRequest::GetRoutesPage { after, limit } => {
                let (routes, next) = sessions
                    .route_page(&mut self.routes, after.as_ref(), *limit, PAGE_BYTES)
                    .await;
                BgpEvent::RoutesPage { routes, next }
            }
            BgpRequest::GetEvpnRoutesPage { after, limit } => {
                let (routes, next) = sessions
                    .evpn_page(&mut self.evpn, after.as_ref(), *limit, PAGE_BYTES)
                    .await;
                BgpEvent::EvpnRoutesPage { routes, next }
            }
            BgpRequest::GetFlowspecRoutesPage { after, limit } => {
                let acld = crate::acl_push_client::show(watchdog_socket).await;
                let (routes, next) = sessions
                    .flowspec_page(
                        &mut self.flowspec,
                        after.as_ref(),
                        *limit,
                        PAGE_BYTES,
                        acld.as_deref(),
                    )
                    .await;
                BgpEvent::FlowspecRoutesPage { routes, next }
            }
            BgpRequest::GetVpnRoutesPage {
                family,
                rd,
                after,
                limit,
            } => {
                let ask = VpnAsk {
                    family: *family,
                    rd: rd.as_deref(),
                    after: after.as_ref(),
                    limit: *limit,
                };
                let (routes, next) = sessions.vpn_page(&mut self.vpn, &ask, PAGE_BYTES).await;
                BgpEvent::VpnRoutesPage { routes, next }
            }
            _ => return None,
        })
    }
}

async fn handle_connection(stream: Stream, role: Role, name: String, ctx: Ctx) {
    let (instance, sessions, watchdog_socket) = &*ctx;
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<BgpRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<BgpEvent>::default());

    let mut snapshots = Snapshots::default();
    let mut evpn = EvpnStaging::default();
    let mut redistribute = FullStaging::default();
    let mut vpn = VpnStaging::default();
    while let Some(msg) = reader.next().await {
        let req = match msg {
            Ok(req) => req,
            Err(e) => {
                warn!(instance = %instance, error = %e, "BGP IPC read error");
                break;
            }
        };
        if !allowed(role, &req) {
            warn!(
                instance = %instance, role = role.as_str(), name = %name,
                "BGP request refused: this role may not send it"
            );
            break;
        }
        trace!(instance = %instance, request = ?req, "serving BGP query");
        if let Some(event) = snapshots.page(&req, sessions, watchdog_socket).await {
            if writer.send(event).await.is_err() {
                break;
            }
            continue;
        }
        match req {
            BgpRequest::GetSummary => {
                let event = BgpEvent::Summary(sessions.peer_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            BgpRequest::GetRoutes
            | BgpRequest::GetEvpnRoutes
            | BgpRequest::GetFlowspecRoutes
            | BgpRequest::GetVpnRoutes { .. } => {
                let event = BgpEvent::Error("removed (#722, #723): use GetRoutesPage, GetEvpnRoutesPage, GetFlowspecRoutesPage or GetVpnRoutesPage".into());
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            // Answered above, through the connection's snapshots.
            BgpRequest::GetRoutesPage { .. }
            | BgpRequest::GetEvpnRoutesPage { .. }
            | BgpRequest::GetFlowspecRoutesPage { .. }
            | BgpRequest::GetVpnRoutesPage { .. } => {}
            BgpRequest::GetRpkiSummary => {
                let event = BgpEvent::RpkiSummary(sessions.rpki_summaries().await);
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            BgpRequest::ShowBmp { instance: asked } => {
                let event = if asked == *instance {
                    BgpEvent::BmpStatus(sessions.bmp_status())
                } else {
                    BgpEvent::Error(format!("this is bgp instance {instance}, not {asked}"))
                };
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            BgpRequest::RedistributeRoutes(update) => {
                // Only the closing `Full` is applied: `BgpRib` diffs the
                // whole raw set, so half a snapshot would withdraw the rest.
                if let Some((update, parts)) = update.absorb(&mut redistribute) {
                    if parts > 1
                        && let RedistributeUpdate::Full(r) = &update
                    {
                        info!(
                            instance = %instance, routes = r.len(), parts,
                            "assembled chunked redistribute snapshot"
                        );
                    }
                    sessions.apply_redistribute_update(update).await;
                }
            }
            BgpRequest::RedistributeMacs { domain, update } => {
                let source = EvpnSource::Domain(domain.clone());
                if let Some(update) = evpn.absorb(instance, &source, update) {
                    sessions.apply_evpn_local(&domain, update).await;
                }
            }
            BgpRequest::RedistributeEvpnPrefixes { table, update } => {
                let source = EvpnSource::Table(table.clone());
                if let Some(update) = evpn.absorb(instance, &source, update) {
                    sessions.apply_evpn_prefixes(&table, update).await;
                }
            }
            BgpRequest::RedistributeVpnPrefixes { table, update } => {
                if let Some(update) = vpn.absorb(instance, &table, update) {
                    sessions.apply_vpn_prefixes(&table, update).await;
                }
            }
            BgpRequest::SendRouteRefresh { peer } => {
                let event = match sessions.soft_in_local(peer).await {
                    Some(Ok(families)) => BgpEvent::SoftInReevaluated { families },
                    Some(Err(why)) => {
                        BgpEvent::Error(format!("re-evaluation superseded/aborted: {why}"))
                    }
                    None => {
                        if sessions
                            .send_command(peer, FsmCommand::SendRouteRefresh)
                            .await
                        {
                            BgpEvent::RouteRefreshSent
                        } else {
                            BgpEvent::PeerNotFound
                        }
                    }
                };
                if writer.send(event).await.is_err() {
                    break;
                }
            }
            BgpRequest::ClearPeer { peer } => {
                let event = if sessions.clear_peer(peer).await {
                    BgpEvent::PeerCleared
                } else {
                    BgpEvent::PeerNotFound
                };
                if writer.send(event).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// One connection's chunked `RedistributeMacs`/`RedistributeEvpnPrefixes`
/// `Full`s in progress (#724), one per `EvpnSource`: a domain and a table may
/// share a name, so they never share a buffer. Nothing reaches
/// `apply_evpn_source` until the closing `Full` (applied once: it diffs
/// against the old set, so a lone part would withdraw the rest); a connection
/// lost mid-snapshot drops it and the sender resends a whole `Full`.
#[derive(Default)]
struct EvpnStaging(HashMap<EvpnSource, FullStaging<EvpnRoute>>);

impl EvpnStaging {
    /// `None` while `update` is a `FullPart`; otherwise the update to apply
    /// (a closing `Full` holding every staged route, in order).
    fn absorb(
        &mut self,
        instance: &str,
        source: &EvpnSource,
        update: EvpnUpdate,
    ) -> Option<EvpnUpdate> {
        let mut staging = self.0.remove(source).unwrap_or_default();
        let absorbed = update.absorb(&mut staging);
        // Still mid-snapshot after a part, or an incremental in between.
        if staging.is_staging() {
            self.0.insert(source.clone(), staging);
        }
        let (update, parts) = absorbed?;
        if parts > 1
            && let EvpnUpdate::Full(r) = &update
        {
            let (kind, name) = match source {
                EvpnSource::Domain(n) => ("domain", n),
                EvpnSource::Table(n) => ("table", n),
            };
            info!(
                source = %format_args!("{kind}:{name}"),
                routes = r.len(),
                parts,
                instance = %instance,
                "assembled chunked evpn route snapshot"
            );
        }
        Some(update)
    }
}

/// One connection's chunked `RedistributeVpnPrefixes` `Full`s in progress
/// (#791), one per table: `apply_vpn_prefixes` replaces the table's whole
/// export set on `Full`, so a lone part would withdraw the rest. Dropped with
/// the connection; `nos-ribd` resends a whole `Full` on reconnect.
#[derive(Default)]
struct VpnStaging(HashMap<String, FullStaging<VpnPrefix>>);

impl VpnStaging {
    /// `None` while `update` is a `FullPart`; otherwise the update to apply.
    fn absorb(
        &mut self,
        instance: &str,
        table: &str,
        update: VpnPrefixUpdate,
    ) -> Option<VpnPrefixUpdate> {
        let mut staging = self.0.remove(table).unwrap_or_default();
        let absorbed = update.absorb(&mut staging);
        if staging.is_staging() {
            self.0.insert(table.to_string(), staging);
        }
        let (update, parts) = absorbed?;
        if parts > 1
            && let VpnPrefixUpdate::Full(r) = &update
        {
            info!(
                table = %table, routes = r.len(), parts, instance = %instance,
                "assembled chunked vpn export snapshot"
            );
        }
        Some(update)
    }
}

#[cfg(test)]
mod staging_tests {
    use super::*;

    fn route(i: u8) -> EvpnRoute {
        EvpnRoute {
            key: nos_proto::EvpnKey::Mac {
                rd: [0; 8],
                mac: [0, 0, 0, 0, 0, i],
            },
            vni: 10,
            next_hop: [10, 0, 0, 1].into(),
            ext_communities: vec![u64::MAX; 20],
            esi: nos_proto::fdb::Esi::default(),
            l3_vni: None,
        }
    }

    fn routes(r: std::ops::Range<u8>) -> Vec<EvpnRoute> {
        r.map(route).collect()
    }

    #[test]
    fn a_domain_and_a_table_of_the_same_name_stage_apart() {
        let mut st = EvpnStaging::default();
        let dom = || EvpnSource::Domain("x".into());
        let tab = || EvpnSource::Table("x".into());
        let part = |r| EvpnUpdate::FullPart(r);
        assert_eq!(st.absorb("r1", &dom(), part(routes(0..2))), None);
        assert_eq!(st.absorb("r1", &tab(), part(routes(10..11))), None);
        assert_eq!(st.absorb("r1", &dom(), part(routes(2..3))), None);
        // Incrementals pass through without touching either buffer.
        let add = EvpnUpdate::Add(route(99));
        assert_eq!(st.absorb("r1", &dom(), add.clone()), Some(add));
        assert_eq!(
            st.absorb("r1", &tab(), EvpnUpdate::Full(routes(11..12))),
            Some(EvpnUpdate::Full(routes(10..12)))
        );
        assert_eq!(
            st.absorb("r1", &dom(), EvpnUpdate::Full(routes(3..4))),
            Some(EvpnUpdate::Full(routes(0..4)))
        );
        assert!(st.0.is_empty(), "closed buffers are dropped");
        // A plain `Full` with nothing staged passes through unchanged.
        assert_eq!(
            st.absorb("r1", &tab(), EvpnUpdate::Full(routes(5..6))),
            Some(EvpnUpdate::Full(routes(5..6)))
        );
    }

    #[test]
    fn a_split_full_reassembles_and_a_dropped_connection_discards() {
        let all = routes(0..40);
        let mut st = EvpnStaging::default();
        let src = || EvpnSource::Table("tenant".into());
        let mut frames = EvpnUpdate::Full(all.clone()).split_with(1024);
        let last = frames.pop().unwrap();
        assert!(frames.len() > 1);
        for f in frames.clone() {
            assert_eq!(st.absorb("r1", &src(), f), None);
        }
        assert_eq!(
            st.absorb("r1", &src(), last.clone()),
            Some(EvpnUpdate::Full(all))
        );
        // Mid-snapshot connection loss: a new connection starts empty.
        for f in frames {
            st.absorb("r1", &src(), f);
        }
        drop(st);
        let mut fresh = EvpnStaging::default();
        assert_eq!(fresh.absorb("r1", &src(), last.clone()), Some(last));
    }
}

#[cfg(test)]
mod vpn_staging_tests {
    use super::*;

    fn route(i: u8) -> VpnPrefix {
        VpnPrefix {
            rd: [0; 8],
            prefix: nos_proto::IpNet::new([10, i, 0, 0].into(), 24).unwrap(),
            labels: vec![1000],
            ext_communities: vec![u64::MAX; 20],
        }
    }

    fn routes(r: std::ops::Range<u8>) -> Vec<VpnPrefix> {
        r.map(route).collect()
    }

    /// A chunk is gated exactly like the `Full` it belongs to.
    #[test]
    fn a_vpn_export_part_is_ribd_only() {
        for role in Role::ALL {
            let req = BgpRequest::RedistributeVpnPrefixes {
                table: "red".to_string(),
                update: VpnPrefixUpdate::FullPart(vec![]),
            };
            assert_eq!(allowed(role, &req), role == Role::Ribd, "{role:?}");
        }
    }

    #[test]
    fn tables_stage_apart_and_a_dropped_connection_discards() {
        use VpnPrefixUpdate::{Add, Full, FullPart};
        let mut st = VpnStaging::default();
        assert_eq!(st.absorb("r1", "red", FullPart(routes(0..2))), None);
        assert_eq!(st.absorb("r1", "blue", FullPart(routes(10..11))), None);
        // Incrementals pass through without touching either buffer.
        assert_eq!(st.absorb("r1", "red", Add(route(99))), Some(Add(route(99))));
        assert_eq!(
            st.absorb("r1", "blue", Full(routes(11..12))),
            Some(Full(routes(10..12)))
        );
        assert_eq!(
            st.absorb("r1", "red", Full(routes(2..3))),
            Some(Full(routes(0..3)))
        );
        assert!(st.0.is_empty(), "closed buffers are dropped");
        st.absorb("r1", "red", FullPart(routes(0..2)));
        drop(st);
        let mut fresh = VpnStaging::default();
        assert_eq!(
            fresh.absorb("r1", "red", Full(routes(2..3))),
            Some(Full(routes(2..3)))
        );
    }
}

#[cfg(test)]
mod authz_tests {
    use super::*;

    #[test]
    fn only_ribd_feeds_redistribution_and_only_people_query() {
        for role in Role::ALL {
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::RedistributeRoutes(nos_proto::RedistributeUpdate::Full(vec![]))
                ),
                role == Role::Ribd,
                "{role:?} redistribute"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::RedistributeMacs {
                        domain: "bd1".to_string(),
                        update: nos_proto::EvpnUpdate::Full(vec![])
                    }
                ),
                role == Role::Fdbd,
                "{role:?} redistribute macs"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::RedistributeEvpnPrefixes {
                        table: "tenant".to_string(),
                        update: nos_proto::EvpnUpdate::Full(vec![])
                    }
                ),
                role == Role::Ribd,
                "{role:?} redistribute evpn prefixes"
            );
            // #724: a chunk is gated exactly like the `Full` it belongs to.
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::RedistributeMacs {
                        domain: "bd1".to_string(),
                        update: nos_proto::EvpnUpdate::FullPart(vec![])
                    }
                ),
                role == Role::Fdbd,
                "{role:?} redistribute macs part"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::RedistributeEvpnPrefixes {
                        table: "tenant".to_string(),
                        update: nos_proto::EvpnUpdate::FullPart(vec![])
                    }
                ),
                role == Role::Ribd,
                "{role:?} redistribute evpn prefixes part"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::RedistributeVpnPrefixes {
                        table: "red".to_string(),
                        update: nos_proto::VpnPrefixUpdate::Full(vec![])
                    }
                ),
                role == Role::Ribd,
                "{role:?} redistribute vpn prefixes"
            );
            assert_eq!(
                allowed(role, &BgpRequest::GetSummary),
                matches!(role, Role::User | Role::Restd),
                "{role:?} summary"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::ClearPeer {
                        peer: "10.0.0.1".parse().unwrap()
                    }
                ),
                matches!(role, Role::User | Role::Restd),
                "{role:?} clear peer"
            );
            assert_eq!(
                allowed(role, &BgpRequest::GetRpkiSummary),
                matches!(role, Role::User | Role::Restd),
                "{role:?} rpki summary"
            );
            assert_eq!(
                allowed(role, &BgpRequest::GetRoutes),
                matches!(role, Role::User | Role::Restd),
                "{role:?} routes"
            );
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::GetRoutesPage {
                        after: None,
                        limit: 10
                    }
                ),
                matches!(role, Role::User | Role::Restd),
                "{role:?} routes page"
            );
            assert_eq!(
                allowed(role, &BgpRequest::GetEvpnRoutes),
                matches!(role, Role::User | Role::Restd),
                "{role:?} evpn routes"
            );
            assert_eq!(
                allowed(role, &BgpRequest::GetFlowspecRoutes),
                matches!(role, Role::User | Role::Restd),
                "{role:?} flowspec routes"
            );
            for req in [
                BgpRequest::GetEvpnRoutesPage {
                    after: None,
                    limit: 10,
                },
                BgpRequest::GetFlowspecRoutesPage {
                    after: None,
                    limit: 10,
                },
                BgpRequest::GetVpnRoutesPage {
                    family: nos_proto::AddressFamily::Vpnv4Unicast,
                    rd: None,
                    after: None,
                    limit: 10,
                },
            ] {
                assert_eq!(
                    allowed(role, &req),
                    matches!(role, Role::User | Role::Restd),
                    "{role:?} {req:?}"
                );
            }
            assert_eq!(
                allowed(
                    role,
                    &BgpRequest::GetVpnRoutes {
                        family: nos_proto::AddressFamily::Vpnv4Unicast,
                        rd: None
                    }
                ),
                matches!(role, Role::User | Role::Restd),
                "{role:?} vpn routes"
            );
        }
    }
}
