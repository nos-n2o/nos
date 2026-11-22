//! The persistent push connection to `nos-interfaced`
//! (`SetStpPortStates`, `FlushFdb`), fire-and-forget like
//! `lacp::interface_client`: every pushed state is cached and the whole cache
//! is resent on each fresh connection.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use futures::SinkExt;
use nos_proto::{
    InterfaceEvent, InterfaceRequest, IpcCodec, Role, ServiceRef, StpPortAssignment, StpPortState,
};
use tokio::sync::{mpsc, watch};
use tokio_util::codec::FramedWrite;
use tracing::{info, warn};

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

type Writer = FramedWrite<tokio::io::WriteHalf<nos_pki::Stream>, IpcCodec<InterfaceRequest>>;

#[derive(Debug)]
pub enum Push {
    States(Vec<StpPortAssignment>),
    Flush(Vec<(String, String)>),
    ErrDisabled { port: String, disabled: bool },
}

/// How long a restarting `nos-stpd` keeps asking `nos-interfaced` which ports
/// it holds err-disabled before giving up (#697).
pub const READ_BACK_BUDGET: Duration = Duration::from_secs(10);

/// The ports `nos-interfaced` holds err-disabled (interfaces and port
/// aggregates), or `None` when it stays unreachable for [`READ_BACK_BUDGET`]:
/// the caller then releases nothing (fail closed).
pub async fn read_err_disabled(watchdog_socket: &std::path::Path) -> Option<HashSet<String>> {
    let deadline = tokio::time::Instant::now() + READ_BACK_BUDGET;
    loop {
        if let Some(held) = try_read(watchdog_socket).await {
            return Some(held);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

async fn try_read(watchdog_socket: &std::path::Path) -> Option<HashSet<String>> {
    let socket =
        nos_daemon::watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let ifaces =
        nos_daemon::ipc::one_shot(&socket, Role::Interfaced, InterfaceRequest::GetInterfaces)
            .await?;
    let aggs = nos_daemon::ipc::one_shot(
        &socket,
        Role::Interfaced,
        InterfaceRequest::GetPortAggregates,
    )
    .await?;
    held_names(&ifaces, &aggs)
}

/// The names flagged `err_disabled` in the two replies; `None` on any other
/// reply.
fn held_names(ifaces: &InterfaceEvent, aggs: &InterfaceEvent) -> Option<HashSet<String>> {
    let (InterfaceEvent::Interfaces(i), InterfaceEvent::PortAggregates(a)) = (ifaces, aggs) else {
        return None;
    };
    Some(
        i.iter()
            .filter(|s| s.err_disabled)
            .map(|s| s.name.clone())
            .chain(a.iter().filter(|s| s.err_disabled).map(|s| s.name.clone()))
            .collect(),
    )
}

/// Runs for the process's lifetime.
pub async fn run(
    watchdog_socket: PathBuf,
    mut rx: mpsc::Receiver<Push>,
    mut shutdown: watch::Receiver<bool>,
) {
    // ponytail: entries of ports that left the plan stay until restart; the
    // resend of a stale (port, domain) is ignored by nos-interfaced.
    let mut cache: HashMap<(String, String), StpPortState> = HashMap::new();
    // Ports BPDU guard holds down; resent on reconnect like the states.
    let mut err_disabled: HashSet<String> = HashSet::new();
    let mut writer: Option<Writer> = None;

    loop {
        if writer.is_none() {
            let Some(socket) = nos_daemon::watchdog::resolve_with_retry(
                &watchdog_socket,
                ServiceRef::Interfaces,
                &mut shutdown,
            )
            .await
            else {
                return;
            };
            match nos_pki::connect(&socket, Role::Interfaced, "").await {
                Ok(stream) => {
                    let (_r, w) = tokio::io::split(stream);
                    let mut w = FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default());
                    if send_all(&mut w, &cache, &err_disabled).await.is_ok() {
                        info!("stp connected to nos-interfaced, resent cached port states");
                        writer = Some(w);
                    }
                }
                Err(e) => warn!(error = %e, "failed to connect to nos-interfaced, retrying"),
            }
            if writer.is_none() {
                tokio::select! {
                    () = tokio::time::sleep(RECONNECT_DELAY) => {}
                    _ = shutdown.changed() => if *shutdown.borrow() { return },
                }
                continue;
            }
        }

        tokio::select! {
            msg = rx.recv() => {
                let Some(msg) = msg else { return };
                let Some(w) = writer.as_mut() else { continue };
                let sent = match msg {
                    Push::States(list) => {
                        for a in &list {
                            cache.insert((a.port.clone(), a.domain.clone()), a.state);
                        }
                        w.send(InterfaceRequest::SetStpPortStates(list)).await
                    }
                    Push::Flush(list) => flush_all(w, list).await,
                    Push::ErrDisabled { port, disabled } => {
                        if disabled {
                            err_disabled.insert(port.clone());
                        } else {
                            err_disabled.remove(&port);
                        }
                        w.send(InterfaceRequest::SetErrDisabled { port, disabled })
                            .await
                    }
                };
                if sent.is_err() {
                    writer = None;
                }
            }
            _ = shutdown.changed() => if *shutdown.borrow() { return },
        }
    }
}

async fn send_all(
    w: &mut Writer,
    cache: &HashMap<(String, String), StpPortState>,
    err_disabled: &HashSet<String>,
) -> std::io::Result<()> {
    for port in err_disabled {
        w.send(InterfaceRequest::SetErrDisabled {
            port: port.clone(),
            disabled: true,
        })
        .await?;
    }
    if cache.is_empty() {
        return Ok(());
    }
    w.send(InterfaceRequest::SetStpPortStates(to_assignments(cache)))
        .await
}

fn to_assignments(cache: &HashMap<(String, String), StpPortState>) -> Vec<StpPortAssignment> {
    cache
        .iter()
        .map(|((port, domain), state)| StpPortAssignment {
            port: port.clone(),
            domain: domain.clone(),
            state: *state,
        })
        .collect()
}

async fn flush_all(w: &mut Writer, list: Vec<(String, String)>) -> std::io::Result<()> {
    for (port, domain) in list {
        w.send(InterfaceRequest::FlushFdb { port, domain }).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_names_unions_interfaces_and_aggregates() {
        use nos_proto::{InterfaceStatus, PortAggregateStatus};
        let i = |n: &str, d| InterfaceStatus {
            name: n.into(),
            addresses: vec![],
            routing_table: None,
            switching_profile: None,
            port_aggregate: None,
            mtu: 1500,
            subinterfaces: vec![],
            link_local_address: None,
            err_disabled: d,
            speed_mbps: None,
        };
        let a = |n: &str, d| PortAggregateStatus {
            name: n.into(),
            mode: nos_proto::PortAggregateMode::Xor,
            switching_profile: None,
            mtu: 1500,
            subinterfaces: vec![],
            link_local_address: None,
            bond_name: None,
            err_disabled: d,
            steering: Vec::new(),
            speed_mbps: None,
        };
        let held = held_names(
            &InterfaceEvent::Interfaces(vec![i("eth1", true), i("eth2", false)]),
            &InterfaceEvent::PortAggregates(vec![a("bond1", true), a("bond2", false)]),
        )
        .unwrap();
        assert_eq!(
            held,
            HashSet::from(["eth1".to_string(), "bond1".to_string()])
        );
        assert!(held_names(&InterfaceEvent::NotFound, &InterfaceEvent::NotFound).is_none());
    }

    #[test]
    fn cache_resends_every_domain_of_a_port() {
        let mut c = HashMap::new();
        c.insert(
            ("eth1".to_string(), "d1".to_string()),
            StpPortState::Blocking,
        );
        c.insert(
            ("eth1".to_string(), "d2".to_string()),
            StpPortState::Forwarding,
        );
        let mut a = to_assignments(&c);
        a.sort_by(|x, y| x.domain.cmp(&y.domain));
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].state, StpPortState::Blocking);
        assert_eq!(a[1].domain, "d2");
    }
}
