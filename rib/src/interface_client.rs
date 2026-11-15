use std::net::IpAddr;
use std::path::Path;

use nos_daemon::ipc::one_shot;
use nos_proto::{
    BroadcastDomainStatus, InterfaceEvent, InterfaceRequest, InterfaceStatus, PortAggregateStatus,
    RibEvent, RibRequest, Role, ServiceRef, SourceAddress, LOOPBACK_PREFIX,
};

/// One-shot queries of `nos-interfaced` for the addresses it applied — the
/// input to `reconcile::connected_entries`. Best-effort like
/// `nos-bgp`'s `interface_client`: "no answer" (not up yet, refused, a
/// malformed reply) is a normal transient condition, and the caller keeps
/// its previous `Connected` set until the next resync.
async fn query(interface_socket: &Path, request: InterfaceRequest) -> Option<InterfaceEvent> {
    one_shot(interface_socket, Role::Interfaced, request).await
}

/// Every interface as `nos-interfaced` currently sees it.
pub async fn get_interfaces(interface_socket: &Path) -> Option<Vec<InterfaceStatus>> {
    match query(interface_socket, InterfaceRequest::GetInterfaces).await? {
        InterfaceEvent::Interfaces(list) => Some(list),
        _ => None,
    }
}

/// Every port aggregate, for its subinterfaces' addresses.
pub async fn get_port_aggregates(interface_socket: &Path) -> Option<Vec<PortAggregateStatus>> {
    match query(interface_socket, InterfaceRequest::GetPortAggregates).await? {
        InterfaceEvent::PortAggregates(list) => Some(list),
        _ => None,
    }
}

/// One broadcast domain's SVI addressing.
pub async fn get_broadcast_domain(
    interface_socket: &Path,
    name: &str,
) -> Option<BroadcastDomainStatus> {
    let request = InterfaceRequest::GetBroadcastDomain {
        name: name.to_string(),
    };
    match query(interface_socket, request).await? {
        InterfaceEvent::BroadcastDomain(status) => Some(status),
        _ => None,
    }
}

/// The kernel name of routing table `table`'s loopback device: `lo<table
/// id>`, the id being that table's own `nos-ribd`'s (`RibRequest::GetTableId`).
async fn loopback_device(watchdog_socket: &Path, table: &str) -> Option<String> {
    let sock = nos_daemon::watchdog::resolve_once(
        watchdog_socket,
        &ServiceRef::RibTable(table.to_string()),
    )
    .await?;
    match one_shot(&sock, Role::Ribd, RibRequest::GetTableId).await? {
        RibEvent::TableId(Some(id)) => Some(format!("lo{id}")),
        _ => None,
    }
}

/// An L3 VNI's VTEP: the address `source` names (IPv4 preferred) and the
/// kernel device carrying it — the VXLAN device's underlay, which it must be
/// bound through when the address sits in a VRF. `underlay_table` is the
/// routing table owning the underlay BGP instance (a `Loopback` source is
/// `loopback-<underlay_table>`). Duplicates `nos-fdbd`'s
/// (sharing needs a common crate, out of #418's scope).
pub async fn resolve_vtep(
    watchdog_socket: &Path,
    underlay_table: Option<&str>,
    source: &SourceAddress,
) -> Option<(IpAddr, String)> {
    let (interface, label, loopback) = match source {
        SourceAddress::Interface { interface, label } => (interface.clone(), label, false),
        SourceAddress::Loopback { label } => {
            (format!("{LOOPBACK_PREFIX}{}", underlay_table?), label, true)
        }
    };
    let device = if loopback {
        loopback_device(watchdog_socket, underlay_table?).await?
    } else {
        interface.clone()
    };
    let sock = nos_daemon::watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await?;
    let InterfaceEvent::Interface(status) =
        query(&sock, InterfaceRequest::GetInterface { name: interface }).await?
    else {
        return None;
    };
    // A loopback carries its addresses flat; any other interface's live under
    // its untagged (tag 0) subinterface.
    let addresses = if loopback {
        status.addresses
    } else {
        status
            .subinterfaces
            .into_iter()
            .find(|s| s.tag == 0)?
            .addresses
    };
    let mut ips: Vec<IpAddr> = addresses
        .into_iter()
        .filter(|a| label.is_none() || a.label == *label)
        .map(|a| a.address.addr())
        .collect();
    ips.sort_by_key(IpAddr::is_ipv6);
    ips.into_iter().next().map(|ip| (ip, device))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use nos_proto::IpcCodec;
    use tokio_util::codec::{FramedRead, FramedWrite};

    fn serve_once(
        path: &Path,
        reply: impl Fn(InterfaceRequest) -> InterfaceEvent + Send + 'static,
    ) {
        let listener = nos_pki::testing::shared()
            .identity("interfaced", "")
            .listen(path)
            .unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap().handshake().await.unwrap();
            let (r, w) = tokio::io::split(stream);
            let mut reader = FramedRead::new(r, IpcCodec::<InterfaceRequest>::default());
            let mut writer = FramedWrite::new(w, IpcCodec::<InterfaceEvent>::default());
            if let Some(Ok(req)) = reader.next().await {
                let _ = writer.send(reply(req)).await;
            }
        });
    }

    #[tokio::test]
    async fn interfaces_and_domain_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        serve_once(&path, |_| InterfaceEvent::Interfaces(vec![]));
        assert_eq!(get_interfaces(&path).await, Some(vec![]));

        let path = tmp.path().join("interface-pa.sock");
        serve_once(&path, |_| InterfaceEvent::PortAggregates(vec![]));
        assert_eq!(get_port_aggregates(&path).await, Some(vec![]));

        let path = tmp.path().join("interface2.sock");
        serve_once(&path, |req| match req {
            InterfaceRequest::GetBroadcastDomain { name } => {
                InterfaceEvent::BroadcastDomain(BroadcastDomainStatus {
                    name,
                    addresses: vec![],
                    routing_table: Some("rt1".into()),
                    link_local_address: None,
                    bridge_name: None,
                    mtu: None,
                })
            }
            _ => InterfaceEvent::NotFound,
        });
        let domain = get_broadcast_domain(&path, "bd1").await.unwrap();
        assert_eq!(domain.name, "bd1");
    }

    #[tokio::test]
    async fn not_found_and_unreachable_are_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        serve_once(&path, |_| InterfaceEvent::NotFound);
        assert_eq!(get_broadcast_domain(&path, "bd1").await, None);
        assert_eq!(get_interfaces(&tmp.path().join("missing.sock")).await, None);
    }
}
