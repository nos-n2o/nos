//! `nos-interfaced`'s kernel link table (`SubscribeLinks`), the source of
//! `portEnabled`. Reimplemented per crate, like every other client (star
//! dependency graph); same shape as `ospf::link_client`.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{InterfaceEvent, InterfaceRequest, IpcCodec, LinkState, Role, ServiceRef};
use tokio::sync::watch;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{info, warn};

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// The table as last streamed. Kept when the stream drops: a lost stream says
/// nothing about the links.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LinkTable {
    /// At least one `LinkSnapshot` seen; false (never connected) means no gating.
    pub snapshot: bool,
    /// False when the driver does not watch the kernel (noop): no gating.
    pub observed: bool,
    pub links: HashMap<String, LinkState>,
    /// Per name, how many times its device was removed or added (a snapshot
    /// counts as both): a socket opened under another epoch is bound to a dead
    /// device. Survives the table coalescing a `LinkRemoved` + `LinkAdded`.
    pub epochs: HashMap<String, u64>,
}

impl LinkTable {
    pub fn epoch(&self, name: &str) -> u64 {
        self.epochs.get(name).copied().unwrap_or(0)
    }
    fn bump(&mut self, name: &str) {
        *self.epochs.entry(name.to_string()).or_default() += 1;
    }
}

/// What the table says about one kernel device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// No usable information: trust the socket.
    Ungated,
    Up,
    /// `absent`, `admin-down` or `no-carrier`.
    Down(&'static str),
}

pub fn gate(table: &LinkTable, name: &str) -> Gate {
    if !table.snapshot || !table.observed {
        return Gate::Ungated;
    }
    match table.links.get(name) {
        None => Gate::Down("absent"),
        Some(l) => l.down_reason().map_or(Gate::Up, Gate::Down),
    }
}

/// Folds one event into the table; true when anything changed.
pub fn apply(table: &mut LinkTable, event: InterfaceEvent) -> bool {
    match event {
        InterfaceEvent::LinkSnapshot { observed, links } => {
            let links: HashMap<_, _> = links.into_iter().map(|l| (l.name.clone(), l)).collect();
            // A resync may have swallowed deletes: every socket is suspect.
            let names: std::collections::HashSet<String> =
                table.links.keys().chain(links.keys()).cloned().collect();
            for n in names {
                table.bump(&n);
            }
            table.snapshot = true;
            table.observed = observed;
            table.links = links;
            true
        }
        InterfaceEvent::LinkAdded(l) => {
            table.bump(&l.name);
            table.links.insert(l.name.clone(), l);
            true
        }
        InterfaceEvent::LinkChanged(l) => table.links.insert(l.name.clone(), l.clone()) != Some(l),
        InterfaceEvent::LinkRemoved { name } => {
            table.bump(&name);
            table.links.remove(&name);
            true
        }
        _ => false,
    }
}

/// Runs until `shutdown` fires: resolves `nos-interfaced`, streams its links.
pub async fn run(
    watchdog_socket: std::path::PathBuf,
    tx: watch::Sender<LinkTable>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        if let Some(socket) =
            nos_daemon::watchdog::resolve_once(&watchdog_socket, &ServiceRef::Interfaces).await
        {
            tokio::select! {
                () = stream(&socket, &tx) => {}
                _ = shutdown.changed() => break,
            }
        }
        tokio::select! {
            () = tokio::time::sleep(RECONNECT_DELAY) => {}
            _ = shutdown.changed() => {}
        }
    }
}

/// One connection's lifetime; returns when it ends (table kept).
async fn stream(socket: &Path, tx: &watch::Sender<LinkTable>) {
    let Ok(conn) = nos_pki::connect(socket, Role::Interfaced, "").await else {
        return;
    };
    let (r, w) = tokio::io::split(conn);
    let mut reader = FramedRead::new(r, IpcCodec::<InterfaceEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default());
    if writer.send(InterfaceRequest::SubscribeLinks).await.is_err() {
        return;
    }
    info!("stp link stream connected");
    while let Some(Ok(event)) = reader.next().await {
        tx.send_if_modified(|t| apply(t, event));
    }
    warn!("stp link stream lost, keeping last link table");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ls(name: &str, admin_up: bool, carrier: bool) -> LinkState {
        LinkState {
            name: name.into(),
            ifindex: 1,
            admin_up,
            carrier,
            port_aggregate: None,
        }
    }

    fn snap(links: Vec<LinkState>) -> InterfaceEvent {
        InterfaceEvent::LinkSnapshot {
            observed: true,
            links,
        }
    }

    #[test]
    fn apply_events() {
        let mut t = LinkTable::default();
        assert!(apply(&mut t, snap(vec![ls("a", true, true)])));
        assert_eq!(t.epoch("a"), 1);
        // A re-snapshot always counts: sockets are reopened.
        assert!(apply(&mut t, snap(vec![ls("a", true, true)])));
        assert_eq!(t.epoch("a"), 2);
        assert!(apply(
            &mut t,
            InterfaceEvent::LinkChanged(ls("a", true, false))
        ));
        assert!(!apply(
            &mut t,
            InterfaceEvent::LinkChanged(ls("a", true, false))
        ));
        assert!(apply(
            &mut t,
            InterfaceEvent::LinkRemoved { name: "a".into() }
        ));
        assert_eq!(
            t.epoch("a"),
            3,
            "LinkChanged keeps the epoch, removal bumps"
        );
        assert!(apply(
            &mut t,
            InterfaceEvent::LinkAdded(ls("a", true, true))
        ));
        assert_eq!(t.epoch("a"), 4);
        assert!(t.links.contains_key("a"));
        assert!(!apply(&mut t, InterfaceEvent::NotFound));
    }

    #[test]
    fn gate_table() {
        let mut t = LinkTable::default();
        assert_eq!(gate(&t, "a"), Gate::Ungated);
        apply(
            &mut t,
            snap(vec![
                ls("up", true, true),
                ls("adm", false, false),
                ls("nc", true, false),
            ]),
        );
        assert_eq!(gate(&t, "up"), Gate::Up);
        assert_eq!(gate(&t, "adm"), Gate::Down("admin-down"));
        assert_eq!(gate(&t, "nc"), Gate::Down("no-carrier"));
        assert_eq!(gate(&t, "gone"), Gate::Down("absent"));
        t.observed = false;
        assert_eq!(gate(&t, "gone"), Gate::Ungated);
    }
}
