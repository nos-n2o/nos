//! Typed fakes of the four services every daemon dials. State sits behind
//! `Arc<Mutex<..>>`, so a test edits it between resyncs.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use futures::stream::BoxStream;
use futures::StreamExt;
use ipnet::IpNet;
use nos_proto::rib::EvpnIrb;
use nos_proto::{
    BroadcastDomainStatus, Config, ConfigDiff, Event, InterfaceEvent, InterfaceRequest,
    InterfaceStatus, LinkState, PortAggregateStatus, Request, RibEvent, RibRequest, ServiceRef,
    WatchdogEvent, WatchdogRequest,
};
use tokio::sync::broadcast;

use crate::{serve, Reply, Server};

type Shared<T> = Arc<Mutex<T>>;

/// Every item a broadcast channel carries from now on, mapped to an event.
fn feed<T: Clone + Send + 'static, E: 'static>(
    tx: &broadcast::Sender<T>,
    f: fn(T) -> E,
) -> BoxStream<'static, E> {
    futures::stream::unfold(tx.subscribe(), |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(v) => return Some((v, rx)),
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
    .map(f)
    .boxed()
}

// ---------------------------------------------------------------- configd

struct ConfigdState {
    config: Config,
    gets: usize,
}

/// `nos-configd` (identity `configd/`): `Get` and `SubscribeDiff`.
pub struct FakeConfigd {
    server: Server<Request>,
    state: Shared<ConfigdState>,
    diffs: broadcast::Sender<ConfigDiff>,
}

impl FakeConfigd {
    pub fn new(path: &Path, config: Config) -> Self {
        let state = Arc::new(Mutex::new(ConfigdState { config, gets: 0 }));
        let (diffs, _) = broadcast::channel(64);
        let (s, d) = (state.clone(), diffs.clone());
        let server = serve(path, "configd", "", move |req: &Request| match req {
            Request::Get => {
                let mut s = s.lock().unwrap();
                s.gets += 1;
                Reply::One(Event::Config(s.config.clone()))
            }
            Request::UserExists { name } => Reply::One(Event::UserExists(
                s.lock()
                    .unwrap()
                    .config
                    .users
                    .iter()
                    .any(|u| &u.name == name),
            )),
            Request::ListBgpInstances => Reply::One(Event::InstanceNames(
                s.lock()
                    .unwrap()
                    .config
                    .bgp_instances
                    .iter()
                    .map(|i| i.name.clone())
                    .collect(),
            )),
            Request::ListOspfInstances => Reply::One(Event::InstanceNames(
                s.lock()
                    .unwrap()
                    .config
                    .ospf_instances
                    .iter()
                    .map(|i| i.name.clone())
                    .collect(),
            )),
            Request::ListOspfv3Instances => Reply::One(Event::InstanceNames(
                s.lock()
                    .unwrap()
                    .config
                    .ospfv3_instances
                    .iter()
                    .map(|i| i.name.clone())
                    .collect(),
            )),
            Request::GetRestApi { table } => Reply::One(Event::RestApi(
                s.lock()
                    .unwrap()
                    .config
                    .routing_tables
                    .iter()
                    .find(|t| &t.name == table)
                    .and_then(|t| t.rest_api.clone()),
            )),
            Request::SubscribeDiff { .. } => Reply::Stream(
                vec![Event::Diff(ConfigDiff::default())],
                feed(&d, Event::Diff),
            ),
            _ => Reply::One(Event::Error("unsupported".into())),
        });
        Self {
            server,
            state,
            diffs,
        }
    }
    pub fn path(&self) -> &Path {
        &self.server.path
    }
    pub fn set_config(&self, config: Config) {
        self.state.lock().unwrap().config = config;
    }
    pub fn config(&self) -> Config {
        self.state.lock().unwrap().config.clone()
    }
    /// How many `Request::Get` were answered.
    pub fn gets(&self) -> usize {
        self.state.lock().unwrap().gets
    }
    /// Broadcast to every open `SubscribeDiff` stream.
    pub fn push_diff(&self, diff: ConfigDiff) {
        let _ = self.diffs.send(diff);
    }
    /// Ends every stream, forcing subscribers to reconnect.
    pub fn close_stream(&self) {
        self.server.close_connections();
    }
    pub fn connections(&self) -> usize {
        self.server.connections()
    }
}

// --------------------------------------------------------------- watchdog

#[derive(Default)]
struct WatchdogState {
    services: HashMap<ServiceRef, PathBuf>,
    resolved: Vec<ServiceRef>,
}

/// The watchdog broker (identity `watchdog/`): `ResolveEndpoint` only. An
/// unknown service is `NotAvailable`, like the real broker.
pub struct FakeWatchdog {
    server: Server<WatchdogRequest>,
    state: Shared<WatchdogState>,
}

impl FakeWatchdog {
    pub fn new(path: &Path) -> Self {
        let state = Shared::<WatchdogState>::default();
        let s = state.clone();
        let server = serve(
            path,
            "watchdog",
            "",
            move |req: &WatchdogRequest| match req {
                WatchdogRequest::ResolveEndpoint { service } => {
                    let mut s = s.lock().unwrap();
                    s.resolved.push(service.clone());
                    Reply::One(
                        s.services
                            .get(service)
                            .map_or(WatchdogEvent::NotAvailable, |p| {
                                WatchdogEvent::Endpoint(p.clone())
                            }),
                    )
                }
                _ => Reply::Close,
            },
        );
        Self { server, state }
    }
    pub fn path(&self) -> &Path {
        &self.server.path
    }
    pub fn set(&self, service: ServiceRef, path: PathBuf) {
        self.state.lock().unwrap().services.insert(service, path);
    }
    pub fn remove(&self, service: &ServiceRef) {
        self.state.lock().unwrap().services.remove(service);
    }
    /// Every service asked about so far, in order.
    pub fn resolutions(&self) -> Vec<ServiceRef> {
        self.state.lock().unwrap().resolved.clone()
    }
}

// ------------------------------------------------------------------- ribd

struct RibdState {
    vrf_name: Option<String>,
    table_id: Option<u32>,
    igp_costs: Vec<(IpNet, u32)>,
    bgp_route_count: u32,
    evpn_irb: Option<EvpnIrb>,
}

/// One `nos-ribd` (identity `ribd/<table>`).
pub struct FakeRibd {
    server: Server<RibRequest>,
    state: Shared<RibdState>,
}

impl FakeRibd {
    pub fn new(path: &Path, table: &str) -> Self {
        let state = Arc::new(Mutex::new(RibdState {
            vrf_name: None,
            table_id: None,
            igp_costs: vec![],
            bgp_route_count: 0,
            evpn_irb: None,
        }));
        let s = state.clone();
        let server = serve(path, "ribd", table, move |req: &RibRequest| {
            let s = s.lock().unwrap();
            match req {
                RibRequest::GetVrfName => Reply::One(RibEvent::VrfName(s.vrf_name.clone())),
                RibRequest::GetTableId => Reply::One(RibEvent::TableId(s.table_id)),
                RibRequest::IgpCosts => Reply::One(RibEvent::IgpCosts(s.igp_costs.clone())),
                RibRequest::BgpRouteCount => Reply::One(RibEvent::BgpRouteCount(s.bgp_route_count)),
                RibRequest::GetEvpnIrb => Reply::One(RibEvent::EvpnIrb(s.evpn_irb.clone())),
                RibRequest::GetRoutes => Reply::One(RibEvent::Error("GetRoutes removed".into())),
                RibRequest::GetRoutesPage { .. } => Reply::One(RibEvent::RoutesPage {
                    routes: vec![],
                    next: None,
                }),
                RibRequest::Lookup { .. } => Reply::One(RibEvent::NoMatch),
                RibRequest::GetVpnLabel => Reply::One(RibEvent::VpnLabel(None)),
                RibRequest::ResolveNextHop { addrs } => {
                    Reply::One(RibEvent::NextHops(vec![None; addrs.len()]))
                }
                RibRequest::PushBgpRoutes(_)
                | RibRequest::PushOspfRoutes(_)
                | RibRequest::PushEvpnRoutes(_)
                | RibRequest::PushVpnRoutes(_) => Reply::None,
            }
        });
        Self { server, state }
    }
    pub fn path(&self) -> &Path {
        &self.server.path
    }
    pub fn set_vrf_name(&self, v: Option<String>) {
        self.state.lock().unwrap().vrf_name = v;
    }
    pub fn set_table_id(&self, v: Option<u32>) {
        self.state.lock().unwrap().table_id = v;
    }
    pub fn set_igp_costs(&self, v: Vec<(IpNet, u32)>) {
        self.state.lock().unwrap().igp_costs = v;
    }
    pub fn set_bgp_route_count(&self, v: u32) {
        self.state.lock().unwrap().bgp_route_count = v;
    }
    pub fn set_evpn_irb(&self, v: Option<EvpnIrb>) {
        self.state.lock().unwrap().evpn_irb = v;
    }
    /// Drains the `Push{Bgp,Ospf,Evpn}Routes` requests received.
    pub fn take_pushed(&self) -> Vec<RibRequest> {
        self.server
            .take_seen()
            .into_iter()
            .filter(|r| {
                matches!(
                    r,
                    RibRequest::PushBgpRoutes(_)
                        | RibRequest::PushOspfRoutes(_)
                        | RibRequest::PushEvpnRoutes(_)
                )
            })
            .collect()
    }
    pub fn connections(&self) -> usize {
        self.server.connections()
    }
    /// Drops every live connection, as a restarted `nos-ribd` would.
    pub fn close_connections(&self) {
        self.server.close_connections();
    }
}

// ------------------------------------------------------------- interfaced

#[derive(Default)]
struct InterfacedState {
    interfaces: BTreeMap<String, InterfaceStatus>,
    domains: BTreeMap<String, BroadcastDomainStatus>,
    aggregates: BTreeMap<String, PortAggregateStatus>,
    observed: bool,
    links: Vec<LinkState>,
}

/// `nos-interfaced` (identity `interfaced/`).
pub struct FakeInterfaced {
    server: Server<InterfaceRequest>,
    state: Shared<InterfacedState>,
    link_changes: broadcast::Sender<LinkState>,
}

fn found<T: Clone>(
    m: &BTreeMap<String, T>,
    name: &str,
    f: fn(T) -> InterfaceEvent,
) -> Reply<InterfaceEvent> {
    Reply::One(m.get(name).cloned().map_or(InterfaceEvent::NotFound, f))
}

impl FakeInterfaced {
    pub fn new(path: &Path) -> Self {
        let state = Shared::<InterfacedState>::default();
        let (link_changes, _) = broadcast::channel(64);
        let (s, lc) = (state.clone(), link_changes.clone());
        let server = serve(path, "interfaced", "", move |req: &InterfaceRequest| {
            let s = s.lock().unwrap();
            match req {
                InterfaceRequest::GetInterfaces => Reply::One(InterfaceEvent::Interfaces(
                    s.interfaces.values().cloned().collect(),
                )),
                InterfaceRequest::GetInterface { name } => {
                    found(&s.interfaces, name, InterfaceEvent::Interface)
                }
                InterfaceRequest::GetBroadcastDomain { name } => {
                    found(&s.domains, name, InterfaceEvent::BroadcastDomain)
                }
                InterfaceRequest::GetPortAggregates => Reply::One(InterfaceEvent::PortAggregates(
                    s.aggregates.values().cloned().collect(),
                )),
                InterfaceRequest::GetPortAggregate { name } => {
                    found(&s.aggregates, name, InterfaceEvent::PortAggregate)
                }
                InterfaceRequest::SubscribeLinks => Reply::Stream(
                    vec![InterfaceEvent::LinkSnapshot {
                        observed: s.observed,
                        links: s.links.clone(),
                    }],
                    feed(&lc, InterfaceEvent::LinkChanged),
                ),
                InterfaceRequest::PushLacpMembers(_)
                | InterfaceRequest::PushLacpConversations(_)
                | InterfaceRequest::PushBfdMembers(_)
                | InterfaceRequest::SetStpPortStates(_)
                | InterfaceRequest::FlushFdb { .. }
                | InterfaceRequest::SetErrDisabled { .. } => Reply::None,
            }
        });
        Self {
            server,
            state,
            link_changes,
        }
    }
    pub fn path(&self) -> &Path {
        &self.server.path
    }
    pub fn set_interface(&self, i: InterfaceStatus) {
        self.state
            .lock()
            .unwrap()
            .interfaces
            .insert(i.name.clone(), i);
    }
    pub fn remove_interface(&self, name: &str) {
        self.state.lock().unwrap().interfaces.remove(name);
    }
    pub fn set_broadcast_domain(&self, name: &str, d: BroadcastDomainStatus) {
        self.state.lock().unwrap().domains.insert(name.into(), d);
    }
    pub fn remove_broadcast_domain(&self, name: &str) {
        self.state.lock().unwrap().domains.remove(name);
    }
    pub fn set_port_aggregate(&self, name: &str, a: PortAggregateStatus) {
        self.state.lock().unwrap().aggregates.insert(name.into(), a);
    }
    pub fn remove_port_aggregate(&self, name: &str) {
        self.state.lock().unwrap().aggregates.remove(name);
    }
    /// The `LinkSnapshot` a new `SubscribeLinks` opens with.
    pub fn set_links(&self, observed: bool, links: Vec<LinkState>) {
        let mut s = self.state.lock().unwrap();
        s.observed = observed;
        s.links = links;
    }
    /// Updates the snapshot and sends `LinkChanged` to open subscribers.
    pub fn push_link(&self, link: LinkState) {
        let mut s = self.state.lock().unwrap();
        s.links.retain(|l| l.name != link.name);
        s.links.push(link.clone());
        let _ = self.link_changes.send(link);
    }
    /// Drains `PushLacpMembers`/`PushBfdMembers`/`SetStpPortStates`/
    /// `FlushFdb`/`SetErrDisabled` received.
    pub fn take_pushed(&self) -> Vec<InterfaceRequest> {
        self.server
            .take_seen()
            .into_iter()
            .filter(is_push)
            .collect()
    }
    pub fn connections(&self) -> usize {
        self.server.connections()
    }
    /// Drops every live connection (link subscribers resubscribe).
    pub fn close_connections(&self) {
        self.server.close_connections();
    }
}

fn is_push(r: &InterfaceRequest) -> bool {
    matches!(
        r,
        InterfaceRequest::PushLacpMembers(_)
            | InterfaceRequest::PushLacpConversations(_)
            | InterfaceRequest::PushBfdMembers(_)
            | InterfaceRequest::SetStpPortStates(_)
            | InterfaceRequest::FlushFdb { .. }
            | InterfaceRequest::SetErrDisabled { .. }
    )
}

// ------------------------------------------------------------------ Fakes

/// Which services [`Fakes::start`] brings up.
#[allow(clippy::large_enum_variant, reason = "test fixture, built once")]
pub enum Fake {
    Configd(Config),
    Watchdog,
    /// One `nos-ribd` for this routing table.
    Ribd(String),
    Interfaced,
}

/// A directory of fakes sharing one watchdog. The watchdog resolves exactly
/// the started services; any other is `NotAvailable` with no socket, which
/// is how a test reaches a daemon's "unreachable" branches.
pub struct Fakes {
    dir: tempfile::TempDir,
    pub configd: Option<FakeConfigd>,
    pub watchdog: Option<FakeWatchdog>,
    pub ribd: BTreeMap<String, FakeRibd>,
    pub interfaced: Option<FakeInterfaced>,
}

impl Fakes {
    pub fn start(which: &[Fake]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut f = Fakes {
            dir,
            configd: None,
            watchdog: None,
            ribd: BTreeMap::new(),
            interfaced: None,
        };
        let mut services = vec![];
        for w in which {
            match w {
                Fake::Configd(c) => {
                    let p = f.dir.path().join("config.sock");
                    f.configd = Some(FakeConfigd::new(&p, c.clone()));
                    services.push((ServiceRef::Config, p));
                }
                Fake::Watchdog => {
                    f.watchdog = Some(FakeWatchdog::new(&f.watchdog_socket()));
                }
                Fake::Ribd(t) => {
                    let p = f.rib_socket(t);
                    f.ribd.insert(t.clone(), FakeRibd::new(&p, t));
                    services.push((ServiceRef::RibTable(t.clone()), p));
                }
                Fake::Interfaced => {
                    let p = f.interface_socket();
                    f.interfaced = Some(FakeInterfaced::new(&p));
                    services.push((ServiceRef::Interfaces, p));
                }
            }
        }
        if let Some(w) = &f.watchdog {
            for (s, p) in services {
                w.set(s, p);
            }
        }
        f
    }
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }
    pub fn config_socket(&self) -> PathBuf {
        self.dir().join("config.sock")
    }
    pub fn watchdog_socket(&self) -> PathBuf {
        self.dir().join("watchdog.sock")
    }
    pub fn rib_socket(&self, table: &str) -> PathBuf {
        self.dir().join(format!("rib-{table}.sock"))
    }
    pub fn interface_socket(&self) -> PathBuf {
        self.dir().join("interfaced.sock")
    }
}
