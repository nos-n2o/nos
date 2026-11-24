//! `nos-interfaced`'s kernel link table (`SubscribeLinks`): which devices
//! exist, their ifindex, and which one is a `PortAggregate`'s bond.
//! Reimplemented per crate (star dependency graph), like `stp::link_client`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{InterfaceEvent, InterfaceRequest, IpcCodec, LinkState, Role, ServiceRef};
use tokio::sync::watch;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{info, warn};

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// The table as last streamed, kept when the stream drops.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LinkTable {
    /// A `LinkSnapshot` seen and its driver watches the kernel (not noop):
    /// until then nothing is known and nothing is applied.
    pub known: bool,
    pub links: HashMap<String, LinkState>,
}

impl LinkTable {
    /// The bond of port aggregate `aggregate`.
    pub fn bond(&self, aggregate: &str) -> Option<&str> {
        self.links
            .values()
            .find(|l| l.port_aggregate.as_deref() == Some(aggregate))
            .map(|l| l.name.as_str())
    }
}

/// Folds one event into the table; true when anything changed.
pub fn apply(table: &mut LinkTable, event: InterfaceEvent) -> bool {
    match event {
        InterfaceEvent::LinkSnapshot { observed, links } => {
            let links: HashMap<_, _> = links.into_iter().map(|l| (l.name.clone(), l)).collect();
            let changed = table.known != observed || table.links != links;
            table.known = observed;
            table.links = links;
            changed
        }
        InterfaceEvent::LinkAdded(l) | InterfaceEvent::LinkChanged(l) => {
            table.links.insert(l.name.clone(), l.clone()) != Some(l)
        }
        InterfaceEvent::LinkRemoved { name } => table.links.remove(&name).is_some(),
        _ => false,
    }
}

/// Runs until `shutdown` fires: resolves `nos-interfaced`, streams its links.
pub async fn run(
    watchdog_socket: PathBuf,
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
    info!("acl link stream connected");
    while let Some(Ok(event)) = reader.next().await {
        tx.send_if_modified(|t| apply(t, event));
    }
    warn!("acl link stream lost, keeping last link table");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ls(name: &str, aggregate: Option<&str>) -> LinkState {
        LinkState {
            name: name.into(),
            ifindex: 1,
            admin_up: true,
            carrier: true,
            port_aggregate: aggregate.map(Into::into),
        }
    }

    #[test]
    fn apply_events() {
        let mut t = LinkTable::default();
        let snap = |observed, links| InterfaceEvent::LinkSnapshot { observed, links };
        assert!(!apply(&mut t, snap(false, vec![])));
        assert!(apply(&mut t, snap(true, vec![ls("a", None)])));
        assert!(t.known);
        assert!(!apply(&mut t, snap(true, vec![ls("a", None)])));
        assert!(apply(
            &mut t,
            InterfaceEvent::LinkChanged(ls("bond1", Some("agg")))
        ));
        assert!(!apply(
            &mut t,
            InterfaceEvent::LinkChanged(ls("bond1", Some("agg")))
        ));
        assert_eq!(t.bond("agg"), Some("bond1"));
        assert_eq!(t.bond("other"), None);
        assert!(apply(
            &mut t,
            InterfaceEvent::LinkRemoved { name: "a".into() }
        ));
        assert!(!apply(
            &mut t,
            InterfaceEvent::LinkRemoved { name: "a".into() }
        ));
        assert!(!apply(&mut t, InterfaceEvent::NotFound));
    }
}
