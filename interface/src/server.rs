use std::path::Path;
use std::sync::Arc;

use futures::{Sink, SinkExt, Stream as FStream, StreamExt};
use nos_pki::{Identity, Incoming, Listener, Stream};
use nos_proto::{
    BroadcastDomainStatus, InterfaceEvent, InterfaceRequest, InterfaceStatus, IpcCodec,
    PortAggregateStatus, Role, SubinterfaceStatus,
};
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, trace, warn};

use crate::driver::links::LinkEvent;
use crate::driver::{InterfaceDriver, LinkWatch};
use crate::state::{BroadcastDomainState, InterfaceState, Interfaces, PortAggregateState};

/// Bundles this instance's shared in-memory state (for the read-only query
/// kinds) and its driver (so a `PushLacpMembers` push can apply the newly
/// gated interfaces to the kernel immediately) — mirrors `nos-ribd`'s own
/// `Context`.
struct Context {
    interfaces: Arc<RwLock<Interfaces>>,
    driver: Arc<dyn InterfaceDriver>,
}

/// Binds `listen_socket` and spawns the IPC accept loop for interface
/// queries.
///
/// Returns a `JoinHandle` the caller must keep alive for the server to run.
pub fn start(
    listen_socket: &Path,
    interfaces: Arc<RwLock<Interfaces>>,
    driver: Arc<dyn InterfaceDriver>,
    identity: &Identity,
) -> std::io::Result<JoinHandle<()>> {
    let listener = identity.listen(listen_socket)?;
    info!(socket = %listen_socket.display(), "interface IPC server listening");
    let ctx = Arc::new(Context { interfaces, driver });
    Ok(tokio::spawn(accept_loop(listener, ctx)))
}

/// Status queries: people, the REST API on their behalf, and the routing
/// daemons that resolve an interface's address (`nos-bgpd`'s `source-address`,
/// the OSPF daemons' link addressing, `nos-fdbd`'s VTEP address and bridge,
/// `nos-ribd`'s connected prefixes from every applied address — `GetInterfaces`
/// plus `GetBroadcastDomain` per SVI). The LACP member push rewrites kernel
/// bond membership, so it is `nos-lacpd`'s alone (and the micro-BFD Up set
/// push `nos-bfdd`'s alone, and the bridge-port state/flush writes `nos-stpd`'s,
/// which also gets the link stream for carrier events, as does `nos-acld`
/// for device existence). No wildcard arm: a new
/// request must be classified.
fn allowed(role: Role, req: &InterfaceRequest) -> bool {
    match req {
        // `nos-stpd` reads the err-disabled flag back on a restart (#697):
        // the two list queries only.
        InterfaceRequest::GetInterfaces | InterfaceRequest::GetPortAggregates => {
            matches!(
                role,
                Role::User
                    | Role::Restd
                    | Role::Bgpd
                    | Role::Ribd
                    | Role::Ospfd
                    | Role::Ospfv3d
                    | Role::Fdbd
                    | Role::Stpd
            )
        }
        InterfaceRequest::GetInterface { .. }
        | InterfaceRequest::GetBroadcastDomain { .. }
        | InterfaceRequest::GetPortAggregate { .. } => {
            matches!(
                role,
                Role::User
                    | Role::Restd
                    | Role::Bgpd
                    | Role::Ribd
                    | Role::Ospfd
                    | Role::Ospfv3d
                    | Role::Fdbd
            )
        }
        InterfaceRequest::PushLacpMembers(_) => role == Role::Lacpd,
        InterfaceRequest::PushBfdMembers(_) => role == Role::Bfdd,
        InterfaceRequest::SubscribeLinks => {
            matches!(role, Role::Ospfd | Role::Ospfv3d | Role::Stpd | Role::Acld)
        }
        InterfaceRequest::SetStpPortStates(_)
        | InterfaceRequest::FlushFdb { .. }
        | InterfaceRequest::SetErrDisabled { .. } => role == Role::Stpd,
    }
}

async fn accept_loop(listener: Listener, ctx: Arc<Context>) {
    loop {
        let incoming = listener.accept_resilient().await;
        tokio::spawn(serve(incoming, ctx.clone()));
    }
}

async fn serve(incoming: Incoming, ctx: Arc<Context>) {
    match incoming.handshake_as(Role::parse).await {
        Ok((stream, role, name)) => handle_connection(stream, role, name, ctx).await,
        Err(e) => debug!(error = %e, "interface IPC handshake refused"),
    }
}

async fn handle_connection(stream: Stream, role: Role, name: String, ctx: Arc<Context>) {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IpcCodec::<InterfaceRequest>::default());
    let mut writer = FramedWrite::new(write_half, IpcCodec::<InterfaceEvent>::default());

    while let Some(msg) = reader.next().await {
        let event = match msg {
            Ok(req) if !allowed(role, &req) => {
                warn!(
                    role = role.as_str(), name = %name,
                    "interface request refused: this role may not send it"
                );
                break;
            }
            Ok(InterfaceRequest::SubscribeLinks) => {
                debug!(role = role.as_str(), name = %name, "link subscriber connected");
                stream_links(&mut reader, &mut writer, || ctx.driver.watch_links()).await;
                break;
            }
            Ok(req) => dispatch(&ctx, req).await,
            Err(e) => {
                warn!(error = %e, "interface IPC read error");
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

async fn dispatch(ctx: &Context, req: InterfaceRequest) -> Option<InterfaceEvent> {
    trace!(request = ?req, "serving interface query");
    match req {
        InterfaceRequest::GetInterfaces => {
            let guard = ctx.interfaces.read().await;
            Some(InterfaceEvent::Interfaces(
                guard.all().into_iter().map(to_status).collect(),
            ))
        }
        InterfaceRequest::GetInterface { name } => {
            let guard = ctx.interfaces.read().await;
            Some(match guard.get(&name) {
                Some(iface) => InterfaceEvent::Interface(to_status(iface.clone())),
                None => InterfaceEvent::NotFound,
            })
        }
        InterfaceRequest::GetBroadcastDomain { name } => {
            let guard = ctx.interfaces.read().await;
            Some(match guard.get_domain(&name) {
                Some(domain) => InterfaceEvent::BroadcastDomain(to_domain_status(domain.clone())),
                None => InterfaceEvent::NotFound,
            })
        }
        InterfaceRequest::GetPortAggregates => {
            let guard = ctx.interfaces.read().await;
            Some(InterfaceEvent::PortAggregates(
                guard
                    .all_port_aggregates()
                    .into_iter()
                    .map(to_port_aggregate_status)
                    .collect(),
            ))
        }
        InterfaceRequest::GetPortAggregate { name } => {
            let guard = ctx.interfaces.read().await;
            Some(match guard.get_port_aggregate(&name) {
                Some(agg) => InterfaceEvent::PortAggregate(to_port_aggregate_status(agg.clone())),
                None => InterfaceEvent::NotFound,
            })
        }
        InterfaceRequest::PushLacpMembers(msg) => {
            apply_lacp_push(ctx, msg).await;
            None
        }
        InterfaceRequest::PushBfdMembers(msg) => {
            let updated = ctx
                .interfaces
                .write()
                .await
                .set_bfd_up_members(&msg.aggregate, msg.up_members);
            apply_pushed(ctx, updated).await;
            None
        }
        InterfaceRequest::SetStpPortStates(assignments) => {
            let writes = ctx
                .interfaces
                .write()
                .await
                .set_stp_port_states(assignments);
            for (port, state) in writes {
                if let Err(e) = ctx.driver.set_bridge_port_state(&port, state).await {
                    warn!(port = ?port, error = %e, "failed to set bridge port state");
                }
            }
            None
        }
        InterfaceRequest::SetErrDisabled { port, disabled } => {
            let (iface, agg) = ctx
                .interfaces
                .write()
                .await
                .set_err_disabled(&port, disabled);
            info!(port = %port, disabled, "err-disabled changed");
            if let Some(i) = iface
                && let Err(e) = ctx.driver.apply(&i).await
            {
                warn!(interface = %port, error = %e, "failed to apply err-disabled");
            }
            if let Some(a) = agg
                && let Err(e) = ctx.driver.ensure_port_aggregate(&a).await
            {
                warn!(port_aggregate = %port, error = %e, "failed to apply err-disabled");
            }
            None
        }
        InterfaceRequest::FlushFdb { port, domain } => {
            let target = ctx.interfaces.read().await.bridge_port(&port, &domain);
            match target {
                Some(p) => {
                    if let Err(e) = ctx.driver.flush_bridge_port(&p).await {
                        warn!(port = ?p, error = %e, "failed to flush bridge port");
                    }
                }
                None => {
                    debug!(port = %port, domain = %domain, "flush for a port that is not a bridge member");
                }
            }
            None
        }
        // Streaming: `handle_connection` owns the connection for it.
        InterfaceRequest::SubscribeLinks => None,
    }
}

/// Serves one `SubscribeLinks`: the snapshot, then every change, until the
/// client writes anything (it must not) or closes, or a write fails. After a
/// lag it sends a fresh snapshot rather than leave a silent gap.
async fn stream_links<R, W>(reader: &mut R, writer: &mut W, watch: impl Fn() -> LinkWatch)
where
    R: FStream + Unpin,
    W: Sink<InterfaceEvent> + Unpin,
{
    let first = watch();
    let mut rx = first.rx;
    let snapshot = InterfaceEvent::LinkSnapshot {
        observed: first.observed,
        links: first.links,
    };
    if writer.send(snapshot).await.is_err() {
        return;
    }
    loop {
        let event = tokio::select! {
            ev = async {
                match rx.as_mut() {
                    Some(r) => Some(r.recv().await),
                    None => std::future::pending().await,
                }
            } => ev.expect("only Some arm completes"),
            _ = reader.next() => return,
        };
        let out = match event {
            Ok(LinkEvent::Changed(l)) => InterfaceEvent::LinkChanged(l),
            Ok(LinkEvent::Removed(name)) => InterfaceEvent::LinkRemoved { name },
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "link subscriber lagged, resending snapshot");
                let w = watch();
                rx = w.rx;
                InterfaceEvent::LinkSnapshot {
                    observed: w.observed,
                    links: w.links,
                }
            }
            Err(broadcast::error::RecvError::Closed) => {
                rx = None;
                continue;
            }
        };
        if writer.send(out).await.is_err() {
            return;
        }
    }
}

/// Applies one `nos-lacpd` push: replaces the aggregate's active-member set
/// and immediately re-`apply`s every affected interface, rather than
/// waiting for the periodic re-apply tick — mirrors `nos-ribd`'s
/// `apply_bgp_route_update`'s immediate-apply precedent.
async fn apply_lacp_push(ctx: &Context, msg: nos_proto::LacpAggregateMembers) {
    let updated = ctx
        .interfaces
        .write()
        .await
        .set_lacp_active_members(&msg.aggregate, msg.active_members);
    apply_pushed(ctx, updated).await;
}

async fn apply_pushed(ctx: &Context, updated: Vec<InterfaceState>) {
    for iface in updated {
        if let Err(e) = ctx.driver.apply(&iface).await {
            warn!(interface = %iface.name, error = %e, "failed to apply pushed enslavement");
        }
    }
}

/// Effective sub-link MTU: the override, else the parent's.
fn sub_status(s: crate::state::SubinterfaceState, parent_mtu: u32) -> SubinterfaceStatus {
    SubinterfaceStatus {
        tag: s.tag,
        addresses: s.addresses,
        routing_table: s.routing_table,
        mtu: s.mtu.unwrap_or(parent_mtu),
        link_local_address: s.link_local_address,
    }
}

fn to_status(iface: InterfaceState) -> InterfaceStatus {
    let mtu = iface.mtu.unwrap_or(crate::driver::DEFAULT_MTU);
    InterfaceStatus {
        name: iface.name,
        addresses: iface.addresses,
        routing_table: iface.routing_table,
        switching_profile: iface.switching_profile,
        port_aggregate: iface.port_aggregate,
        mtu,
        subinterfaces: iface
            .subinterfaces
            .into_iter()
            .map(|s| sub_status(s, mtu))
            .collect(),
        // A loopback interface's own flat L3 config has no live link-local
        // Hello exchange to source (see `InterfaceState`'s doc comment) —
        // never populated for this attach-point kind.
        link_local_address: None,
        err_disabled: iface.stp.err_disabled,
    }
}

fn to_domain_status(domain: BroadcastDomainState) -> BroadcastDomainStatus {
    BroadcastDomainStatus {
        name: domain.name,
        addresses: domain.addresses,
        routing_table: domain.routing_table,
        bridge_name: domain.bridge_name,
        link_local_address: domain.link_local_address,
    }
}

fn to_port_aggregate_status(agg: PortAggregateState) -> PortAggregateStatus {
    let mtu = agg.mtu.unwrap_or(crate::driver::DEFAULT_MTU);
    PortAggregateStatus {
        name: agg.name,
        mode: agg.mode,
        switching_profile: agg.switching_profile,
        mtu,
        subinterfaces: agg
            .subinterfaces
            .into_iter()
            .map(|s| sub_status(s, mtu))
            .collect(),
        link_local_address: agg.link_local_address,
        bond_name: agg.bond_name,
        err_disabled: agg.stp.err_disabled,
    }
}

#[cfg(test)]
mod mtu_tests {
    use super::*;
    use crate::state::SubinterfaceState;

    #[test]
    fn sub_status_mtu_is_override_else_parent() {
        let sub = |mtu| SubinterfaceState {
            tag: 100,
            addresses: Vec::new(),
            routing_table: None,
            mtu,
            link_local_address: None,
        };
        assert_eq!(sub_status(sub(None), 9000).mtu, 9000);
        assert_eq!(sub_status(sub(Some(1400)), 9000).mtu, 1400);
    }
}

#[cfg(test)]
mod authz_tests {
    use super::*;

    #[test]
    fn only_lacpd_may_rewrite_bond_membership() {
        let push = InterfaceRequest::PushLacpMembers(nos_proto::LacpAggregateMembers {
            aggregate: String::new(),
            active_members: Vec::new(),
        });
        for role in Role::ALL {
            assert_eq!(allowed(role, &push), role == Role::Lacpd, "{role:?} push");
            let query = matches!(
                role,
                Role::User
                    | Role::Restd
                    | Role::Bgpd
                    | Role::Ribd
                    | Role::Ospfd
                    | Role::Ospfv3d
                    | Role::Fdbd
            );
            assert_eq!(
                allowed(role, &InterfaceRequest::GetInterfaces),
                query || role == Role::Stpd,
                "{role:?} query"
            );
            assert_eq!(
                allowed(role, &InterfaceRequest::GetPortAggregates),
                query || role == Role::Stpd,
                "{role:?} aggregates query"
            );
            assert_eq!(
                allowed(
                    role,
                    &InterfaceRequest::GetInterface {
                        name: String::new()
                    }
                ),
                query,
                "{role:?} single query"
            );
            assert_eq!(
                allowed(
                    role,
                    &InterfaceRequest::GetPortAggregate {
                        name: String::new()
                    }
                ),
                query,
                "{role:?} single aggregate query"
            );
            assert_eq!(
                allowed(
                    role,
                    &InterfaceRequest::GetBroadcastDomain {
                        name: String::new()
                    }
                ),
                query,
                "{role:?} domain query"
            );
        }
        // nos-ribd derives connected prefixes from both, and nothing else.
        assert!(allowed(Role::Ribd, &InterfaceRequest::GetInterfaces));
        assert!(!allowed(Role::Ribd, &push));
    }

    #[test]
    fn only_bfdd_may_push_bfd_members() {
        let push = InterfaceRequest::PushBfdMembers(nos_proto::BfdAggregateMembers {
            aggregate: String::new(),
            up_members: Vec::new(),
        });
        for role in Role::ALL {
            assert_eq!(allowed(role, &push), role == Role::Bfdd, "{role:?}");
        }
    }

    #[test]
    fn only_the_routing_daemons_stpd_and_acld_may_subscribe_to_links() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &InterfaceRequest::SubscribeLinks),
                matches!(role, Role::Ospfd | Role::Ospfv3d | Role::Stpd | Role::Acld),
                "{role:?} subscribe"
            );
        }
    }

    #[test]
    fn only_stpd_may_write_bridge_port_state() {
        let set = InterfaceRequest::SetStpPortStates(Vec::new());
        let flush = InterfaceRequest::FlushFdb {
            port: String::new(),
            domain: String::new(),
        };
        let err = InterfaceRequest::SetErrDisabled {
            port: String::new(),
            disabled: true,
        };
        for role in Role::ALL {
            assert_eq!(allowed(role, &err), role == Role::Stpd, "{role:?} err");
            assert_eq!(allowed(role, &set), role == Role::Stpd, "{role:?} set");
            assert_eq!(allowed(role, &flush), role == Role::Stpd, "{role:?} flush");
        }
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use crate::driver::links::LinkHub;
    use futures::channel::mpsc;
    use nos_proto::LinkState;

    fn l(name: &str, up: bool) -> LinkState {
        LinkState {
            name: name.into(),
            ifindex: 1,
            admin_up: up,
            carrier: up,
            port_aggregate: None,
        }
    }

    type Req = Result<InterfaceRequest, std::io::Error>;

    #[tokio::test]
    async fn snapshot_then_changes_then_eof_ends() {
        let hub = Arc::new(LinkHub::new(16));
        hub.upsert(l("a", true));
        let (req_tx, mut req_rx) = mpsc::unbounded::<Req>();
        let (mut ev_tx, mut ev_rx) = mpsc::unbounded::<InterfaceEvent>();
        let h = hub.clone();
        let task = tokio::spawn(async move {
            stream_links(&mut req_rx, &mut ev_tx, || h.watch()).await;
        });
        let first = ev_rx.next().await.unwrap();
        assert!(
            matches!(first, InterfaceEvent::LinkSnapshot { observed: true, links } if links == vec![l("a", true)])
        );
        hub.upsert(l("a", false));
        assert!(
            matches!(ev_rx.next().await.unwrap(), InterfaceEvent::LinkChanged(s) if s == l("a", false))
        );
        hub.remove("a");
        assert!(
            matches!(ev_rx.next().await.unwrap(), InterfaceEvent::LinkRemoved { name } if name == "a")
        );
        drop(req_tx);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn lag_sends_fresh_snapshot() {
        let hub = Arc::new(LinkHub::new(1));
        let (_req_tx, mut req_rx) = mpsc::unbounded::<Req>();
        let (mut ev_tx, mut ev_rx) = mpsc::unbounded::<InterfaceEvent>();
        let h = hub.clone();
        let task = tokio::spawn(async move {
            stream_links(&mut req_rx, &mut ev_tx, || h.watch()).await;
        });
        assert!(matches!(
            ev_rx.next().await.unwrap(),
            InterfaceEvent::LinkSnapshot { .. }
        ));
        // Single-threaded runtime: the task cannot poll until we yield.
        for n in ["a", "b", "c"] {
            hub.upsert(l(n, true));
        }
        let mut last = None;
        while let Ok(Some(ev)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), ev_rx.next()).await
        {
            last = Some(ev);
        }
        match last.unwrap() {
            InterfaceEvent::LinkSnapshot { links, .. } => assert_eq!(links, hub.watch().links),
            other => panic!("expected snapshot, got {other:?}"),
        }
        task.abort();
    }

    #[tokio::test]
    async fn unobserved_sends_snapshot_then_waits() {
        let (req_tx, mut req_rx) = mpsc::unbounded::<Req>();
        let (mut ev_tx, mut ev_rx) = mpsc::unbounded::<InterfaceEvent>();
        let task = tokio::spawn(async move {
            stream_links(&mut req_rx, &mut ev_tx, || LinkWatch {
                observed: false,
                links: vec![],
                rx: None,
            })
            .await;
        });
        assert!(matches!(
            ev_rx.next().await.unwrap(),
            InterfaceEvent::LinkSnapshot {
                observed: false,
                ..
            }
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!task.is_finished());
        drop(req_tx);
        task.await.unwrap();
    }
}
