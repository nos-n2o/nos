use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nos_proto::{InterfaceEvent, InterfaceRequest, IpcCodec, LinkState, Role, ServiceRef};
use tokio::sync::watch;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{info, warn};

use nos_daemon::watchdog;

/// Fixed reconnect delay, like every other reconnect loop here.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// `nos-interfaced`'s kernel link table as last streamed (`SubscribeLinks`).
/// Kept when the stream drops: a lost stream says nothing about the links.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LinkTable {
    /// At least one `LinkSnapshot` seen; false (never connected) means no gating.
    pub snapshot: bool,
    pub connected: bool,
    /// False when the driver does not watch the kernel (noop): no gating.
    pub observed: bool,
    pub links: HashMap<String, LinkState>,
}

/// What the table says about one kernel device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// No usable information: run the link as before (ifindex unknown).
    Ungated,
    Up(u32),
    /// `absent`, `admin-down` or `no-carrier`.
    Down(&'static str),
}

pub fn gate(table: &LinkTable, name: &str) -> Gate {
    if !table.snapshot || !table.observed {
        return Gate::Ungated;
    }
    match table.links.get(name) {
        None => Gate::Down("absent"),
        Some(l) => l.down_reason().map_or(Gate::Up(l.ifindex), Gate::Down),
    }
}

/// Folds one event into the table; true when anything changed.
pub fn apply(table: &mut LinkTable, event: InterfaceEvent) -> bool {
    match event {
        InterfaceEvent::LinkSnapshot { observed, links } => {
            let links: HashMap<_, _> = links.into_iter().map(|l| (l.name.clone(), l)).collect();
            let changed = !table.snapshot || table.observed != observed || table.links != links;
            table.snapshot = true;
            table.observed = observed;
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
    watchdog_socket: std::path::PathBuf,
    tx: watch::Sender<LinkTable>,
    mut shutdown: watch::Receiver<bool>,
) {
    while !*shutdown.borrow() {
        if let Some(socket) =
            watchdog::resolve_once(&watchdog_socket, &ServiceRef::Interfaces).await
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
pub async fn stream(socket: &Path, tx: &watch::Sender<LinkTable>) {
    let Ok(conn) = nos_pki::connect(socket, Role::Interfaced, "").await else {
        return;
    };
    let (r, w) = tokio::io::split(conn);
    let mut reader = FramedRead::new(r, IpcCodec::<InterfaceEvent>::default());
    let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceRequest>::default());
    if writer.send(InterfaceRequest::SubscribeLinks).await.is_err() {
        return;
    }
    info!("{} link stream connected", crate::DAEMON);
    tx.send_if_modified(|t| !std::mem::replace(&mut t.connected, true));
    while let Some(Ok(event)) = reader.next().await {
        tx.send_if_modified(|t| apply(t, event));
    }
    warn!(
        "{} link stream lost, keeping last link table",
        crate::DAEMON
    );
    tx.send_if_modified(|t| std::mem::replace(&mut t.connected, false));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ls(name: &str, ifindex: u32, admin_up: bool, carrier: bool) -> LinkState {
        LinkState {
            name: name.into(),
            ifindex,
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
        assert!(apply(&mut t, snap(vec![ls("a", 1, true, true)])));
        assert!(!apply(&mut t, snap(vec![ls("a", 1, true, true)])));
        assert!(apply(
            &mut t,
            InterfaceEvent::LinkChanged(ls("b", 2, true, true))
        ));
        assert!(!apply(
            &mut t,
            InterfaceEvent::LinkChanged(ls("b", 2, true, true))
        ));
        assert!(apply(
            &mut t,
            InterfaceEvent::LinkRemoved { name: "b".into() }
        ));
        assert!(!apply(
            &mut t,
            InterfaceEvent::LinkRemoved { name: "b".into() }
        ));
        assert!(apply(&mut t, snap(vec![])));
        assert!(t.links.is_empty());
        assert!(!apply(&mut t, InterfaceEvent::NotFound));
    }

    #[test]
    fn gate_table() {
        let mut t = LinkTable::default();
        assert_eq!(gate(&t, "a"), Gate::Ungated);
        apply(
            &mut t,
            snap(vec![
                ls("up", 7, true, true),
                ls("adm", 8, false, false),
                ls("nc", 9, true, false),
            ]),
        );
        assert_eq!(gate(&t, "up"), Gate::Up(7));
        assert_eq!(gate(&t, "adm"), Gate::Down("admin-down"));
        assert_eq!(gate(&t, "nc"), Gate::Down("no-carrier"));
        assert_eq!(gate(&t, "gone"), Gate::Down("absent"));
        t.observed = false;
        assert_eq!(gate(&t, "gone"), Gate::Ungated);
    }

    #[tokio::test]
    async fn stream_keeps_table_on_loss_and_replaces_on_reconnect() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        let listener = nos_pki::testing::shared()
            .identity("interfaced", "")
            .listen(&path)
            .unwrap();
        let (tx, rx) = watch::channel(LinkTable::default());
        let server = tokio::spawn(async move {
            for links in [
                vec![ls("a", 1, true, true), ls("b", 2, true, true)],
                vec![ls("a", 1, true, true)],
            ] {
                let (s, _) = listener.accept().await.unwrap().handshake().await.unwrap();
                let (r, w) = tokio::io::split(s);
                let mut reader = FramedRead::new(r, IpcCodec::<InterfaceRequest>::default());
                let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceEvent>::default());
                assert!(matches!(
                    reader.next().await,
                    Some(Ok(InterfaceRequest::SubscribeLinks))
                ));
                writer.send(snap(links)).await.unwrap();
            }
        });
        stream(&path, &tx).await;
        {
            let t = rx.borrow();
            assert!(!t.connected && t.snapshot);
            assert_eq!(t.links.len(), 2);
        }
        stream(&path, &tx).await;
        server.await.unwrap();
        assert_eq!(rx.borrow().links.len(), 1);
    }
}
