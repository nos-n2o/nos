//! Read-only endpoints: one per `nos-cli` `show` command, returning the
//! daemon's own reply payload as JSON.

use std::net::IpAddr;

use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::Json;
use futures::{Stream, StreamExt};
use nos_proto::{
    AclEvent, AclRequest, AclStatus, BfdEvent, BfdRequest, BfdSessionView, BgpEvent, BgpRequest,
    Config, EvpnRouteSummary, FdbEvent, FdbRequest, FdbTable, FlowspecRouteSummary,
    FlowspecRuleStatus, InterfaceEvent, InterfaceRequest, InterfaceStatus, LacpEvent, LacpRequest,
    LldpEvent, LldpLinkStats, LldpNeighbor, LldpRequest, LogEntry, LogEvent, LogRequest,
    LsaSummary, NeighborSummary, OspfEvent, OspfRequest, Ospfv3Event, Ospfv3LsaSummary,
    Ospfv3NeighborSummary, Ospfv3Request, PeerSummary, PortAggregateLacpSummary,
    PortAggregateStatus, PrefixRoutes, ReflectorView, RibEvent, RibRequest, ServiceRef, StpEvent,
    StpInstance, StpMst, StpPortCounters, StpRequest, StpSummary, VersionInfo, BGP_PAGE_MAX,
    ROUTES_PAGE_MAX,
};
use serde::{Deserialize, Serialize};

use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::ipc::{unexpected, Daemons};

#[utoipa::path(get, path = "/v1/version", tag = "show", summary = "Build version and revision of nos-restd", responses((status = 200, body = VersionInfo)))]
pub async fn version() -> Json<VersionInfo> {
    Json(VersionInfo::current())
}

#[utoipa::path(get, path = "/v1/config", tag = "show", summary = "Running config", responses((status = 200, body = Config)))]
pub async fn config(State(d): State<Daemons>) -> ApiResult<Json<serde_json::Value>> {
    // Secrets (admin keys, user password hashes) leave the daemons as `<hidden>`.
    Ok(Json(d.running_config().await?.redacted()))
}

/// Pagination of a listing endpoint (#713; the convention #714 reuses): the
/// page size served and the cursor to pass back as `?after=`, `null` on the
/// last page. Keyset paging without a snapshot: a listing that changes
/// mid-walk never loops or repeats an item, but may miss or include a
/// concurrent change.
#[derive(Serialize, ToSchema)]
pub struct Pagination {
    /// The page size that applied (the requested `limit`, clamped).
    limit: u32,
    /// Cursor of the next page, `null` on the last page.
    next: Option<String>,
}

/// One page of `GET /v1/routes/{table}`.
#[derive(Serialize, ToSchema)]
pub struct RoutesPage {
    /// Prefixes in ascending CIDR order, each with its candidates best to worst.
    items: Vec<PrefixRoutes>,
    pagination: Pagination,
}

#[derive(Deserialize)]
pub struct PageQuery {
    after: Option<String>,
    limit: Option<u32>,
}

#[utoipa::path(get, path = "/v1/routes/{table}", tag = "show", summary = "One page of a table's routes, best to worst per prefix", description = "Pages of prefixes in ascending CIDR order; follow `pagination.next` as `?after=` until it is null. The table is not snapshotted: a walk may miss or include routes that change meanwhile, but never loops or repeats a prefix.", params(("table" = String, Path, description = "routing table name"), ("after" = Option<String>, Query, description = "cursor: the previous page's pagination.next (a prefix such as 10.0.0.0/8)"), ("limit" = Option<u32>, Query, description = "page size, 1 to 1000 (default 1000)")), responses((status = 200, body = RoutesPage), (status = 400, body = ErrorBody, description = "after is not a prefix"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn routes(
    State(d): State<Daemons>,
    Path(table): Path<String>,
    Query(q): Query<PageQuery>,
) -> ApiResult<Json<RoutesPage>> {
    let after = q
        .after
        .map(|a| {
            a.parse()
                .map_err(|_| ApiError::BadRequest(format!("after '{a}' is not a prefix")))
        })
        .transpose()?;
    let limit = q.limit.unwrap_or(ROUTES_PAGE_MAX).clamp(1, ROUTES_PAGE_MAX);
    match d
        .service(
            ServiceRef::RibTable(table),
            RibRequest::GetRoutesPage { after, limit },
        )
        .await?
    {
        RibEvent::RoutesPage { routes, next } => Ok(Json(RoutesPage {
            items: routes,
            pagination: Pagination {
                limit,
                next: next.map(|n| n.to_string()),
            },
        })),
        RibEvent::Error(e) => Err(ApiError::BadGateway(e)),
        other => Err(unexpected("nos-ribd", &other)),
    }
}

#[utoipa::path(get, path = "/v1/fdb/{domain}", tag = "show", summary = "A broadcast domain's forwarding database: local and EVPN-learned MACs, flood list", params(("domain" = String, Path, description = "broadcast domain name")), responses((status = 200, body = FdbTable), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn fdb(
    State(d): State<Daemons>,
    Path(domain): Path<String>,
) -> ApiResult<Json<FdbTable>> {
    match d
        .service(ServiceRef::FdbDomain(domain), FdbRequest::GetMacs)
        .await?
    {
        FdbEvent::Table(t) => Ok(Json(t)),
    }
}

/// Longest-prefix-match lookup for one address.
#[utoipa::path(get, path = "/v1/routes/{table}/{addr}", tag = "show", summary = "Longest-prefix-match lookup", params(("table" = String, Path, description = "routing table name"), ("addr" = String, Path, description = "destination address")), responses((status = 200, body = PrefixRoutes), (status = 404, body = ErrorBody, description = "no route covers the address"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn route_lookup(
    State(d): State<Daemons>,
    Path((table, addr)): Path<(String, IpAddr)>,
) -> ApiResult<Json<PrefixRoutes>> {
    match d
        .service(ServiceRef::RibTable(table), RibRequest::Lookup { addr })
        .await?
    {
        RibEvent::Match(r) => Ok(Json(r)),
        RibEvent::NoMatch => Err(ApiError::NotFound(format!("no route covers {addr}"))),
        RibEvent::Error(e) => Err(ApiError::BadGateway(e)),
        other => Err(unexpected("nos-ribd", &other)),
    }
}

#[utoipa::path(get, path = "/v1/interfaces", tag = "show", summary = "Every interface", responses((status = 200, body = Vec<InterfaceStatus>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn interfaces(State(d): State<Daemons>) -> ApiResult<Json<Vec<InterfaceStatus>>> {
    match d
        .service(ServiceRef::Interfaces, InterfaceRequest::GetInterfaces)
        .await?
    {
        InterfaceEvent::Interfaces(v) => Ok(Json(v)),
        other => Err(unexpected("nos-interfaced", &other)),
    }
}

#[utoipa::path(get, path = "/v1/interfaces/{name}", tag = "show", summary = "One interface", params(("name" = String, Path, description = "interface name")), responses((status = 200, body = InterfaceStatus), (status = 404, body = ErrorBody), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn interface(
    State(d): State<Daemons>,
    Path(name): Path<String>,
) -> ApiResult<Json<InterfaceStatus>> {
    match d
        .service(
            ServiceRef::Interfaces,
            InterfaceRequest::GetInterface { name: name.clone() },
        )
        .await?
    {
        InterfaceEvent::Interface(v) => Ok(Json(v)),
        InterfaceEvent::NotFound => Err(ApiError::NotFound(format!("no interface '{name}'"))),
        other => Err(unexpected("nos-interfaced", &other)),
    }
}

#[utoipa::path(get, path = "/v1/port-aggregates", tag = "show", summary = "Every port aggregate", responses((status = 200, body = Vec<PortAggregateStatus>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn port_aggregates(
    State(d): State<Daemons>,
) -> ApiResult<Json<Vec<PortAggregateStatus>>> {
    match d
        .service(ServiceRef::Interfaces, InterfaceRequest::GetPortAggregates)
        .await?
    {
        InterfaceEvent::PortAggregates(v) => Ok(Json(v)),
        other => Err(unexpected("nos-interfaced", &other)),
    }
}

#[utoipa::path(get, path = "/v1/port-aggregates/{name}", tag = "show", summary = "One port aggregate", params(("name" = String, Path, description = "port aggregate name")), responses((status = 200, body = PortAggregateStatus), (status = 404, body = ErrorBody), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn port_aggregate(
    State(d): State<Daemons>,
    Path(name): Path<String>,
) -> ApiResult<Json<PortAggregateStatus>> {
    match d
        .service(
            ServiceRef::Interfaces,
            InterfaceRequest::GetPortAggregate { name: name.clone() },
        )
        .await?
    {
        InterfaceEvent::PortAggregate(v) => Ok(Json(v)),
        InterfaceEvent::NotFound => Err(ApiError::NotFound(format!("no port-aggregate '{name}'"))),
        other => Err(unexpected("nos-interfaced", &other)),
    }
}

async fn lacp_summary(d: &Daemons) -> ApiResult<Vec<PortAggregateLacpSummary>> {
    match d.service(ServiceRef::Lacp, LacpRequest::GetSummary).await? {
        LacpEvent::Summary(v) => Ok(v),
    }
}

#[utoipa::path(get, path = "/v1/lacp", tag = "show", summary = "LACP state of every aggregate", responses((status = 200, body = Vec<PortAggregateLacpSummary>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn lacp(State(d): State<Daemons>) -> ApiResult<Json<Vec<PortAggregateLacpSummary>>> {
    Ok(Json(lacp_summary(&d).await?))
}

#[utoipa::path(get, path = "/v1/lacp/{name}", tag = "show", summary = "LACP state of one aggregate", params(("name" = String, Path, description = "port aggregate name")), responses((status = 200, body = PortAggregateLacpSummary), (status = 404, body = ErrorBody), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn lacp_one(
    State(d): State<Daemons>,
    Path(name): Path<String>,
) -> ApiResult<Json<PortAggregateLacpSummary>> {
    lacp_summary(&d)
        .await?
        .into_iter()
        .find(|a| a.aggregate == name)
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("no lacp aggregate '{name}'")))
}

async fn acls(d: &Daemons, name: Option<String>) -> ApiResult<Vec<AclStatus>> {
    match d
        .service(ServiceRef::Acl, AclRequest::Show { name })
        .await?
    {
        AclEvent::Acls(v) => Ok(v),
        other @ (AclEvent::Ack | AclEvent::Flowspec(_)) => Err(unexpected("nos-acld", &other)),
    }
}

#[utoipa::path(get, path = "/v1/flowspec", tag = "show", summary = "Every flowspec rule nos-acld holds: installed or why not, with packet and byte counters", responses((status = 200, body = Vec<FlowspecRuleStatus>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn flowspec_rules(State(d): State<Daemons>) -> ApiResult<Json<Vec<FlowspecRuleStatus>>> {
    match d.service(ServiceRef::Acl, AclRequest::ShowFlowspec).await? {
        AclEvent::Flowspec(v) => Ok(Json(v)),
        other @ (AclEvent::Ack | AclEvent::Acls(_)) => Err(unexpected("nos-acld", &other)),
    }
}

#[utoipa::path(get, path = "/v1/acl", tag = "show", summary = "Every ACL: attachments and per-rule packet and byte counters", responses((status = 200, body = Vec<AclStatus>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn acl_list(State(d): State<Daemons>) -> ApiResult<Json<Vec<AclStatus>>> {
    Ok(Json(acls(&d, None).await?))
}

#[utoipa::path(get, path = "/v1/acl/{name}", tag = "show", summary = "One ACL with its counters", params(("name" = String, Path, description = "ACL name")), responses((status = 200, body = AclStatus), (status = 404, body = ErrorBody), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn acl_one(
    State(d): State<Daemons>,
    Path(name): Path<String>,
) -> ApiResult<Json<AclStatus>> {
    one_acl(acls(&d, Some(name.clone())).await?, &name).map(Json)
}

/// The reply to a named query holds the ACL, or nothing when it is unknown.
fn one_acl(found: Vec<AclStatus>, name: &str) -> ApiResult<AclStatus> {
    found
        .into_iter()
        .find(|a| a.name == name)
        .ok_or_else(|| ApiError::NotFound(format!("no acl '{name}'")))
}

#[utoipa::path(get, path = "/v1/lldp/neighbors", tag = "show", summary = "Every LLDP neighbor", responses((status = 200, body = Vec<LldpNeighbor>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn lldp_neighbors(State(d): State<Daemons>) -> ApiResult<Json<Vec<LldpNeighbor>>> {
    match d
        .service(ServiceRef::Lldp, LldpRequest::GetNeighbors)
        .await?
    {
        LldpEvent::Neighbors(v) => Ok(Json(v)),
        other @ LldpEvent::Statistics(_) => Err(unexpected("nos-lldpd", &other)),
    }
}

#[utoipa::path(get, path = "/v1/spanning-tree", tag = "show", summary = "The spanning-tree bridge and every port's role and state (`enabled: false` when the mode is neither rstp nor mstp)", responses((status = 200, body = StpSummary), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn spanning_tree(State(d): State<Daemons>) -> ApiResult<Json<StpSummary>> {
    stp_summary(&d).await.map(Json)
}

async fn stp_summary(d: &Daemons) -> ApiResult<StpSummary> {
    match d.service(ServiceRef::Stp, StpRequest::GetSummary).await? {
        StpEvent::Summary(s) => Ok(s),
        other @ (StpEvent::Mcheck { .. } | StpEvent::ErrDisabledCleared { .. }) => {
            Err(crate::ipc::unexpected("nos-stpd", &other))
        }
    }
}

#[utoipa::path(get, path = "/v1/spanning-tree/instance/{id}", tag = "show", summary = "One spanning-tree instance of the MST region (0 is the CIST)", params(("id" = u16, Path, description = "MST instance id")), responses((status = 200, body = StpInstance), (status = 404, body = ErrorBody, description = "spanning tree is not in mode mstp, or no such instance"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn spanning_tree_instance(
    State(d): State<Daemons>,
    Path(id): Path<u16>,
) -> ApiResult<Json<StpInstance>> {
    stp_summary(&d)
        .await?
        .mst
        .and_then(|m| m.instances.into_iter().find(|i| i.id == id))
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("no spanning-tree instance {id}")))
}

#[utoipa::path(get, path = "/v1/spanning-tree/domain/{name}", tag = "show", summary = "One broadcast domain's Rapid-PVST+ tree", params(("name" = String, Path, description = "Broadcast domain name")), responses((status = 200, body = StpInstance), (status = 404, body = ErrorBody, description = "spanning tree is not in mode rapid-pvst, or the domain has no tree"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn spanning_tree_domain(
    State(d): State<Daemons>,
    Path(name): Path<String>,
) -> ApiResult<Json<StpInstance>> {
    stp_summary(&d)
        .await?
        .pvst
        .into_iter()
        .find(|i| i.domains.contains(&name))
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("no spanning-tree tree for domain {name}")))
}

/// One row of `GET /v1/spanning-tree/counters`: a port's RFC 4318 counters
/// in one tree. Outside Rapid-PVST+ the counters belong to the port (the
/// CIST and every MSTI share them), so `tree` is `cist`.
#[derive(Debug, Serialize, ToSchema)]
pub struct StpCounterRow {
    /// `cist`, or the broadcast domain's name in `mode rapid-pvst`.
    pub tree: String,
    pub port: String,
    pub counters: StpPortCounters,
}

fn stp_counter_rows(s: &StpSummary) -> Vec<StpCounterRow> {
    let row = |tree: &str, port: &str, counters| StpCounterRow {
        tree: tree.into(),
        port: port.into(),
        counters,
    };
    let mut rows: Vec<_> = s
        .ports
        .iter()
        .map(|p| row("cist", &p.name, p.counters))
        .collect();
    for t in &s.pvst {
        rows.extend(
            t.ports
                .iter()
                .map(|p| row(&t.domains.join(","), &p.name, p.counters)),
        );
    }
    rows
}

#[utoipa::path(get, path = "/v1/spanning-tree/counters", tag = "show", summary = "Every spanning-tree port's BPDU and topology-change counters (RFC 4318 names), one row per port and tree", responses((status = 200, body = Vec<StpCounterRow>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn spanning_tree_counters(
    State(d): State<Daemons>,
) -> ApiResult<Json<Vec<StpCounterRow>>> {
    stp_summary(&d)
        .await
        .map(|s| stp_counter_rows(&s))
        .map(Json)
}

#[utoipa::path(get, path = "/v1/spanning-tree/mst-config", tag = "show", summary = "The MST region name, revision, digest and the instance to VLAN map", responses((status = 200, body = StpMst), (status = 404, body = ErrorBody, description = "spanning tree is not in mode mstp"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn spanning_tree_mst_config(State(d): State<Daemons>) -> ApiResult<Json<StpMst>> {
    stp_summary(&d)
        .await?
        .mst
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("spanning tree is not in mode mstp".into()))
}

#[utoipa::path(get, path = "/v1/lldp/statistics", tag = "show", summary = "Every LLDP-enabled interface's IEEE 802.1AB counters", responses((status = 200, body = Vec<LldpLinkStats>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn lldp_statistics(State(d): State<Daemons>) -> ApiResult<Json<Vec<LldpLinkStats>>> {
    match d
        .service(ServiceRef::Lldp, LldpRequest::GetStatistics)
        .await?
    {
        LldpEvent::Statistics(v) => Ok(Json(v)),
        other @ LldpEvent::Neighbors(_) => Err(unexpected("nos-lldpd", &other)),
    }
}

#[derive(Deserialize)]
pub struct BfdQuery {
    peer: Option<String>,
}

#[utoipa::path(get, path = "/v1/bfd/sessions", tag = "show", summary = "Every BFD session, or those to one peer", params(("peer" = Option<String>, Query, description = "only sessions to this peer address")), responses((status = 200, body = Vec<BfdSessionView>), (status = 400, body = ErrorBody, description = "peer is not an IP address"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bfd_sessions(
    State(d): State<Daemons>,
    Query(q): Query<BfdQuery>,
) -> ApiResult<Json<Vec<BfdSessionView>>> {
    let peer = q
        .peer
        .map(|p| {
            p.parse::<IpAddr>()
                .map_err(|_| ApiError::BadRequest(format!("peer '{p}' is not an IP address")))
        })
        .transpose()?;
    match d
        .service(ServiceRef::Bfd, BfdRequest::GetSessions { peer })
        .await?
    {
        BfdEvent::Sessions(v) => Ok(Json(v)),
        other => Err(unexpected("nos-bfdd", &other)),
    }
}

#[utoipa::path(get, path = "/v1/bfd/reflector", tag = "show", summary = "The S-BFD reflector's discriminators and counters", responses((status = 200, body = ReflectorView), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bfd_reflector(State(d): State<Daemons>) -> ApiResult<Json<ReflectorView>> {
    match d.service(ServiceRef::Bfd, BfdRequest::GetReflector).await? {
        BfdEvent::Reflector(v) => Ok(Json(v)),
        other => Err(unexpected("nos-bfdd", &other)),
    }
}

#[derive(Deserialize)]
pub struct LogQuery {
    source: Option<String>,
    limit: Option<usize>,
}

/// One-shot buffer snapshot (`show log`); there is no `--follow` equivalent yet.
#[utoipa::path(get, path = "/v1/logs", tag = "show", summary = "Log buffer snapshot", params(("source" = Option<String>, Query, description = "only entries from this source"), ("limit" = Option<usize>, Query, description = "most recent N entries")), responses((status = 200, body = Vec<LogEntry>), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn logs(
    State(d): State<Daemons>,
    Query(q): Query<LogQuery>,
) -> ApiResult<Json<Vec<LogEntry>>> {
    match d
        .service(
            ServiceRef::Log,
            LogRequest::GetLogs {
                source: q.source,
                limit: q.limit,
            },
        )
        .await?
    {
        LogEvent::Logs(v) => Ok(Json(v)),
        LogEvent::Error(e) => Err(ApiError::BadGateway(e)),
        other @ LogEvent::Line(_) => Err(unexpected("nos-logd", &other)),
    }
}

/// Named so `#[utoipa::path]` can take them as a `body` (it cannot parse nested generics).
pub type BgpSummaryReport = Vec<InstanceReport<Vec<PeerSummary>>>;
pub type BgpEvpnReport = Vec<InstanceReport<BgpEvpnPage>>;
/// `GET /v1/bgp/flowspec`.
pub type BgpFlowspecReport = Vec<InstanceReport<BgpFlowspecPage>>;
/// `GET /v1/bgp/vpnv4` and `/v1/bgp/vpnv6`.
pub type BgpVpnReport = Vec<InstanceReport<BgpVpnPage>>;
pub type BgpRoutesReport = Vec<InstanceReport<BgpRoutesPage>>;
pub type BgpRpkiReport = Vec<InstanceReport<Vec<nos_proto::RpkiCacheStatus>>>;
/// `GET /v1/bgp/bmp`.
pub type BgpBmpReport = Vec<InstanceReport<Vec<nos_proto::BmpStationStatus>>>;
pub type OspfNeighborsReport = Vec<InstanceReport<Vec<NeighborSummary>>>;
pub type OspfDatabaseReport = Vec<InstanceReport<Vec<LsaSummary>>>;
pub type Ospfv3NeighborsReport = Vec<InstanceReport<Vec<Ospfv3NeighborSummary>>>;
pub type Ospfv3DatabaseReport = Vec<InstanceReport<Vec<Ospfv3LsaSummary>>>;

#[derive(Deserialize)]
pub struct FollowQuery {
    source: Option<String>,
    limit: Option<usize>,
}

/// `show log --follow`: a Server-Sent Events stream. The buffer as it stands
/// (trimmed to the most recent `limit`, if given) is sent first, then each new
/// entry as it is logged, until the client disconnects. Every entry is a `log`
/// event whose data is the JSON `LogEntry`; a daemon-side failure is an `error`
/// event with the message as data.
#[utoipa::path(
    get, path = "/v1/logs/follow", tag = "show", summary = "Follow the log (Server-Sent Events)",
    params(
        ("source" = Option<String>, Query, description = "only entries from this source"),
        ("limit" = Option<usize>, Query, description = "trim the initial backlog to the most recent N entries")
    ),
    responses(
        (status = 200, content_type = "text/event-stream", body = String,
         description = "`event: log` per entry, data = a JSON LogEntry"),
        (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")
    )
)]
pub async fn logs_follow(
    State(d): State<Daemons>,
    Query(q): Query<FollowQuery>,
) -> ApiResult<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>> {
    let (reader, writer) = d
        .open_stream::<_, LogEvent>(ServiceRef::Log, LogRequest::Tail { source: q.source })
        .await?;
    let mut backlog_limit = q.limit;
    let events = reader.flat_map(move |item| {
        let entries: Vec<SseEvent> = match item {
            Ok(LogEvent::Logs(mut v)) => {
                if let Some(n) = backlog_limit.take() {
                    v.drain(..v.len().saturating_sub(n));
                }
                v.iter().filter_map(log_event).collect()
            }
            Ok(LogEvent::Line(e)) => log_event(&e).into_iter().collect(),
            Ok(LogEvent::Error(m)) => vec![SseEvent::default().event("error").data(m)],
            Err(e) => vec![SseEvent::default().event("error").data(e.to_string())],
        };
        futures::stream::iter(entries.into_iter().map(Ok))
    });
    // Holding the write half until the stream is dropped keeps the daemon's
    // side of the tail subscription open.
    let events = events.map(move |e| {
        let _keep_open = &writer;
        e
    });
    Ok(Sse::new(events).keep_alive(KeepAlive::default()))
}

fn log_event(entry: &LogEntry) -> Option<SseEvent> {
    SseEvent::default().event("log").json_data(entry).ok()
}

/// One instance's answer to a router-wide query: its payload, or why it has none.
#[derive(Serialize, ToSchema)]
pub struct InstanceReport<T> {
    pub instance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Asks every named instance's daemon the same question, like `nos-cli`'s
/// router-wide `show bgp brief`: an instance whose daemon isn't reachable
/// gets an `error` entry instead of failing the whole query.
async fn per_instance<Req, Ev, T>(
    d: &Daemons,
    names: Vec<String>,
    service: impl Fn(String) -> ServiceRef,
    request: impl Fn() -> Req,
    extract: impl Fn(Ev) -> Option<T>,
) -> Vec<InstanceReport<T>>
where
    Req: Serialize,
    Ev: serde::de::DeserializeOwned,
{
    let mut out = Vec::new();
    for instance in names {
        let reply = d
            .service::<_, Ev>(service(instance.clone()), request())
            .await;
        let (result, error) = match reply {
            Ok(ev) => match extract(ev) {
                Some(t) => (Some(t), None),
                None => (None, Some("unexpected reply".to_string())),
            },
            Err(ApiError::Unavailable(_)) => (None, Some("not running".to_string())),
            Err(e) => {
                tracing::warn!(error = ?e, %instance, "instance query failed");
                (None, Some("daemon error".to_string()))
            }
        };
        out.push(InstanceReport {
            instance,
            result,
            error,
        });
    }
    out
}

#[utoipa::path(get, path = "/v1/bgp/summary", tag = "show", summary = "BGP session summary, per instance", responses((status = 200, body = BgpSummaryReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_summary(State(d): State<Daemons>) -> ApiResult<Json<BgpSummaryReport>> {
    let names = d.bgp_instance_names().await?;
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::BgpInstance,
            || BgpRequest::GetSummary,
            |e| match e {
                BgpEvent::Summary(v) => Some(v),
                _ => None,
            },
        )
        .await,
    ))
}

/// One page of one instance's `GET /v1/bgp/evpn`.
#[derive(Serialize, ToSchema)]
pub struct BgpEvpnPage {
    /// Routes in (peer, route text) order.
    items: Vec<EvpnRouteSummary>,
    pagination: Pagination,
}

/// One page of one instance's `GET /v1/bgp/flowspec`.
#[derive(Serialize, ToSchema)]
pub struct BgpFlowspecPage {
    /// Rules in (peer, family, rule text) order.
    items: Vec<FlowspecRouteSummary>,
    pagination: Pagination,
}

/// One page of one instance's `GET /v1/bgp/vpnv4` or `/v1/bgp/vpnv6`.
#[derive(Serialize, ToSchema)]
pub struct BgpVpnPage {
    /// Paths in (peer, route distinguisher, prefix) order.
    items: Vec<nos_proto::VpnRouteSummary>,
    pagination: Pagination,
}

/// The instances a paged BGP query asks and its page size. `after`/`limit`
/// without `instance` is `400`; an unknown `instance` is `404`.
async fn bgp_page_scope(d: &Daemons, q: &BgpPageQuery) -> ApiResult<(Vec<String>, u32)> {
    if q.instance.is_none() && (q.after.is_some() || q.limit.is_some()) {
        return Err(ApiError::BadRequest(
            "pagination requires ?instance=".to_string(),
        ));
    }
    let mut names: Vec<String> = d.bgp_instance_names().await?;
    if let Some(want) = &q.instance {
        names.retain(|n| n == want);
        if names.is_empty() {
            return Err(ApiError::NotFound(format!("no bgp instance '{want}'")));
        }
    }
    Ok((
        names,
        q.limit.unwrap_or(BGP_PAGE_MAX).clamp(1, BGP_PAGE_MAX),
    ))
}

/// Parses the opaque `after` cursor of a paged BGP query.
fn bgp_after<C: std::str::FromStr>(after: Option<&str>) -> ApiResult<Option<C>> {
    after
        .map(|a| {
            a.parse()
                .map_err(|_| ApiError::BadRequest(format!("after '{a}' is not a cursor")))
        })
        .transpose()
}

#[utoipa::path(get, path = "/v1/bgp/evpn", tag = "show", summary = "One page of received EVPN routes, per instance", description = "Each instance's `result` is `{items, pagination}`. Without `instance`, every instance's FIRST page is returned (`pagination.next` is non-null when more exist); `after` and `limit` then need `?instance=`. Continue with `?instance=<name>&after=<pagination.next>` until it is null. `after` is an opaque cursor: pass it back verbatim. The daemon keeps a sorted key snapshot per connection, so entries added mid-walk appear on the next walk; a walk never repeats or loops.", params(("instance" = Option<String>, Query, description = "only this BGP instance; required with after or limit"), ("after" = Option<String>, Query, description = "cursor: the previous page's pagination.next (opaque)"), ("limit" = Option<u32>, Query, description = "page size, 1 to 1000 (default 1000)")), responses((status = 200, body = BgpEvpnReport), (status = 400, body = ErrorBody, description = "after is not a cursor, or after/limit without instance"), (status = 404, body = ErrorBody, description = "no such bgp instance"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_evpn(
    State(d): State<Daemons>,
    Query(q): Query<BgpPageQuery>,
) -> ApiResult<Json<BgpEvpnReport>> {
    let (names, limit) = bgp_page_scope(&d, &q).await?;
    let after: Option<nos_proto::EvpnRouteCursor> = bgp_after(q.after.as_deref())?;
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::BgpInstance,
            || BgpRequest::GetEvpnRoutesPage {
                after: after.clone(),
                limit,
            },
            |e| match e {
                BgpEvent::EvpnRoutesPage { routes, next } => Some(BgpEvpnPage {
                    items: routes,
                    pagination: Pagination {
                        limit,
                        next: next.map(|n| n.to_string()),
                    },
                }),
                _ => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/bgp/flowspec", tag = "show", summary = "One page of received Flowspec routes, per instance", description = "Each instance's `result` is `{items, pagination}`. Without `instance`, every instance's FIRST page is returned (`pagination.next` is non-null when more exist); `after` and `limit` then need `?instance=`. Continue with `?instance=<name>&after=<pagination.next>` until it is null. `after` is an opaque cursor: pass it back verbatim. The daemon keeps a sorted key snapshot per connection, so entries added mid-walk appear on the next walk; a walk never repeats or loops.", params(("instance" = Option<String>, Query, description = "only this BGP instance; required with after or limit"), ("after" = Option<String>, Query, description = "cursor: the previous page's pagination.next (opaque)"), ("limit" = Option<u32>, Query, description = "page size, 1 to 1000 (default 1000)")), responses((status = 200, body = BgpFlowspecReport), (status = 400, body = ErrorBody, description = "after is not a cursor, or after/limit without instance"), (status = 404, body = ErrorBody, description = "no such bgp instance"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_flowspec(
    State(d): State<Daemons>,
    Query(q): Query<BgpPageQuery>,
) -> ApiResult<Json<BgpFlowspecReport>> {
    let (names, limit) = bgp_page_scope(&d, &q).await?;
    let after: Option<nos_proto::FlowspecRouteCursor> = bgp_after(q.after.as_deref())?;
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::BgpInstance,
            || BgpRequest::GetFlowspecRoutesPage {
                after: after.clone(),
                limit,
            },
            |e| match e {
                BgpEvent::FlowspecRoutesPage { routes, next } => Some(BgpFlowspecPage {
                    items: routes,
                    pagination: Pagination {
                        limit,
                        next: next.map(|n| n.to_string()),
                    },
                }),
                _ => None,
            },
        )
        .await,
    ))
}

#[derive(Deserialize)]
pub struct VpnPageQuery {
    rd: Option<String>,
    instance: Option<String>,
    after: Option<String>,
    limit: Option<u32>,
}

#[utoipa::path(get, path = "/v1/bgp/vpnv4", tag = "show", summary = "One page of received VPN-IPv4 routes (SAFI 128), per instance, optionally of one Route Distinguisher", description = "Each instance's `result` is `{items, pagination}`. Without `instance`, every instance's FIRST page is returned (`pagination.next` is non-null when more exist); `after` and `limit` then need `?instance=`. Continue with `?instance=<name>&after=<pagination.next>` until it is null. `after` is an opaque cursor: pass it back verbatim. The daemon keeps a sorted key snapshot per connection, so entries added mid-walk appear on the next walk; a walk never repeats or loops. `rd` filters every page the same way; a walk must keep it constant.", params(("rd" = Option<String>, Query, description = "only routes with this Route Distinguisher (65001:1)"), ("instance" = Option<String>, Query, description = "only this BGP instance; required with after or limit"), ("after" = Option<String>, Query, description = "cursor: the previous page's pagination.next (opaque)"), ("limit" = Option<u32>, Query, description = "page size, 1 to 1000 (default 1000)")), responses((status = 200, body = BgpVpnReport), (status = 400, body = ErrorBody, description = "rd is not a Route Distinguisher, after is not a cursor, or after/limit without instance"), (status = 404, body = ErrorBody, description = "no such bgp instance"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_vpnv4(
    State(d): State<Daemons>,
    Query(q): Query<VpnPageQuery>,
) -> ApiResult<Json<BgpVpnReport>> {
    bgp_vpn(&d, nos_proto::AddressFamily::Vpnv4Unicast, q).await
}

#[utoipa::path(get, path = "/v1/bgp/vpnv6", tag = "show", summary = "One page of received VPN-IPv6 routes (SAFI 128), per instance, optionally of one Route Distinguisher", description = "Each instance's `result` is `{items, pagination}`. Without `instance`, every instance's FIRST page is returned (`pagination.next` is non-null when more exist); `after` and `limit` then need `?instance=`. Continue with `?instance=<name>&after=<pagination.next>` until it is null. `after` is an opaque cursor: pass it back verbatim. The daemon keeps a sorted key snapshot per connection, so entries added mid-walk appear on the next walk; a walk never repeats or loops. `rd` filters every page the same way; a walk must keep it constant.", params(("rd" = Option<String>, Query, description = "only routes with this Route Distinguisher (65001:1)"), ("instance" = Option<String>, Query, description = "only this BGP instance; required with after or limit"), ("after" = Option<String>, Query, description = "cursor: the previous page's pagination.next (opaque)"), ("limit" = Option<u32>, Query, description = "page size, 1 to 1000 (default 1000)")), responses((status = 200, body = BgpVpnReport), (status = 400, body = ErrorBody, description = "rd is not a Route Distinguisher, after is not a cursor, or after/limit without instance"), (status = 404, body = ErrorBody, description = "no such bgp instance"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_vpnv6(
    State(d): State<Daemons>,
    Query(q): Query<VpnPageQuery>,
) -> ApiResult<Json<BgpVpnReport>> {
    bgp_vpn(&d, nos_proto::AddressFamily::Vpnv6Unicast, q).await
}

async fn bgp_vpn(
    d: &Daemons,
    family: nos_proto::AddressFamily,
    q: VpnPageQuery,
) -> ApiResult<Json<BgpVpnReport>> {
    if let Some(rd) = q.rd.as_deref()
        && nos_proto::evpn_id::parse_rd(rd).is_none()
    {
        return Err(ApiError::BadRequest(format!(
            "rd '{rd}' is not a Route Distinguisher"
        )));
    }
    let scope = BgpPageQuery {
        instance: q.instance,
        after: q.after,
        limit: q.limit,
    };
    let (names, limit) = bgp_page_scope(d, &scope).await?;
    let after: Option<nos_proto::VpnRouteCursor> = bgp_after(scope.after.as_deref())?;
    Ok(Json(
        per_instance(
            d,
            names,
            ServiceRef::BgpInstance,
            || BgpRequest::GetVpnRoutesPage {
                family,
                rd: q.rd.clone(),
                after,
                limit,
            },
            |e| match e {
                BgpEvent::VpnRoutesPage { routes, next } => Some(BgpVpnPage {
                    items: routes,
                    pagination: Pagination {
                        limit,
                        next: next.map(|n| n.to_string()),
                    },
                }),
                _ => None,
            },
        )
        .await,
    ))
}

/// One page of one instance's `GET /v1/bgp/routes`.
#[derive(Serialize, ToSchema)]
pub struct BgpRoutesPage {
    /// Paths in (prefix, peer, path id) order, locally redistributed first per prefix.
    items: Vec<nos_proto::BgpRouteSummary>,
    pagination: Pagination,
}

#[derive(Deserialize)]
pub struct BgpPageQuery {
    instance: Option<String>,
    after: Option<String>,
    limit: Option<u32>,
}

#[utoipa::path(get, path = "/v1/bgp/routes", tag = "show", summary = "One page of IPv4/IPv6 unicast routes with RPKI origin validation state, per instance", description = "Each instance's `result` is `{items, pagination}`. Without `instance`, every instance's FIRST page is returned (`pagination.next` is non-null when more exist); `after` and `limit` then need `?instance=`. Continue with `?instance=<name>&after=<pagination.next>` until it is null. `after` is an opaque cursor: pass it back verbatim. The daemon keeps a sorted key snapshot per connection, so routes added mid-walk appear on the next walk; a walk never repeats or loops.", params(("instance" = Option<String>, Query, description = "only this BGP instance; required with after or limit"), ("after" = Option<String>, Query, description = "cursor: the previous page's pagination.next (opaque)"), ("limit" = Option<u32>, Query, description = "page size, 1 to 1000 (default 1000)")), responses((status = 200, body = BgpRoutesReport), (status = 400, body = ErrorBody, description = "after is not a cursor, or after/limit without instance"), (status = 404, body = ErrorBody, description = "no such bgp instance"), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_routes(
    State(d): State<Daemons>,
    Query(q): Query<BgpPageQuery>,
) -> ApiResult<Json<BgpRoutesReport>> {
    let (names, limit) = bgp_page_scope(&d, &q).await?;
    let after: Option<nos_proto::BgpRouteCursor> = bgp_after(q.after.as_deref())?;
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::BgpInstance,
            || BgpRequest::GetRoutesPage { after, limit },
            |e| match e {
                BgpEvent::RoutesPage { routes, next } => Some(BgpRoutesPage {
                    items: routes,
                    pagination: Pagination {
                        limit,
                        next: next.map(|n| n.to_string()),
                    },
                }),
                _ => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/bgp/rpki", tag = "show", summary = "RPKI cache sessions (RFC 8210), per instance", responses((status = 200, body = BgpRpkiReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_rpki(State(d): State<Daemons>) -> ApiResult<Json<BgpRpkiReport>> {
    let names = d.bgp_instance_names().await?;
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::BgpInstance,
            || BgpRequest::GetRpkiSummary,
            |e| match e {
                BgpEvent::RpkiSummary(v) => Some(v),
                _ => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/bgp/bmp", tag = "show", summary = "BMP station connections and frame counters (RFC 7854), per instance", responses((status = 200, body = BgpBmpReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn bgp_bmp(State(d): State<Daemons>) -> ApiResult<Json<BgpBmpReport>> {
    let names = d.bgp_instance_names().await?;
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::BgpInstance,
            || BgpRequest::ShowBmp,
            |e| match e {
                BgpEvent::BmpStatus(v) => Some(v),
                _ => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/ospf/neighbors", tag = "show", summary = "OSPF neighbors, per instance", responses((status = 200, body = OspfNeighborsReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn ospf_neighbors(State(d): State<Daemons>) -> ApiResult<Json<OspfNeighborsReport>> {
    let names = d.ospf_instance_names().await?;
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::OspfInstance,
            || OspfRequest::GetNeighbors,
            |e| match e {
                OspfEvent::Neighbors(v) => Some(v),
                OspfEvent::Database(_) => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/ospf/database", tag = "show", summary = "OSPF LSDB summary, per instance", responses((status = 200, body = OspfDatabaseReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn ospf_database(State(d): State<Daemons>) -> ApiResult<Json<OspfDatabaseReport>> {
    let names = d.ospf_instance_names().await?;
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::OspfInstance,
            || OspfRequest::GetDatabase,
            |e| match e {
                OspfEvent::Database(v) => Some(v),
                OspfEvent::Neighbors(_) => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/ospfv3/neighbors", tag = "show", summary = "OSPFv3 neighbors, per instance", responses((status = 200, body = Ospfv3NeighborsReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn ospfv3_neighbors(State(d): State<Daemons>) -> ApiResult<Json<Ospfv3NeighborsReport>> {
    let names = d.ospfv3_instance_names().await?;
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::Ospfv3Instance,
            || Ospfv3Request::GetNeighbors,
            |e| match e {
                Ospfv3Event::Neighbors(v) => Some(v),
                Ospfv3Event::Database(_) => None,
            },
        )
        .await,
    ))
}

#[utoipa::path(get, path = "/v1/ospfv3/database", tag = "show", summary = "OSPFv3 LSDB summary, per instance", responses((status = 200, body = Ospfv3DatabaseReport), (status = 503, body = ErrorBody, description = "a daemon this query needs is not running")))]
pub async fn ospfv3_database(State(d): State<Daemons>) -> ApiResult<Json<Ospfv3DatabaseReport>> {
    let names = d.ospfv3_instance_names().await?;
    Ok(Json(
        per_instance(
            &d,
            names,
            ServiceRef::Ospfv3Instance,
            || Ospfv3Request::GetDatabase,
            |e| match e {
                Ospfv3Event::Database(v) => Some(v),
                Ospfv3Event::Neighbors(_) => None,
            },
        )
        .await,
    ))
}

#[cfg(test)]
mod acl_tests {
    use nos_proto::schema::AclAction;

    use super::*;

    fn acl(name: &str) -> AclStatus {
        AclStatus {
            name: name.into(),
            default_action: AclAction::Deny,
            default_packets: 0,
            default_bytes: 0,
            levels: 0,
            filters: 2,
            attached: vec![],
            rules: vec![],
        }
    }

    #[test]
    fn a_wrong_acld_reply_is_a_bad_gateway() {
        assert!(matches!(
            unexpected("nos-acld", &AclEvent::Ack),
            ApiError::BadGateway(m) if m == "nos-acld sent an unexpected reply: Ack"
        ));
    }

    #[test]
    fn a_named_acl_is_found_or_is_a_404() {
        assert_eq!(one_acl(vec![acl("EDGE")], "EDGE").unwrap().name, "EDGE");
        assert!(matches!(
            one_acl(vec![], "EDGE"),
            Err(ApiError::NotFound(m)) if m == "no acl 'EDGE'"
        ));
    }
}
