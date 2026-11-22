use std::path::Path;

use nos_daemon::ipc::one_shot;
use nos_proto::{BroadcastDomainStatus, InterfaceEvent, InterfaceRequest, InterfaceStatus, Role};

/// One-shot query of `nos-interfaced` for one named interface's reconciled
/// addresses.
///
/// Best-effort by design, like `crate::rib_client::get_vrf_name`: this is
/// polled on every reconcile pass (see `crate::reconcile`), and "no answer
/// yet" (refused, not configured yet, unexpected or malformed reply) is a
/// normal, recurring condition the caller just retries next tick. Only a
/// well-formed `InterfaceEvent::Interface` reply is distinguished from that.
pub async fn get_interface(interface_socket: &Path, name: &str) -> Option<InterfaceStatus> {
    let req = InterfaceRequest::GetInterface {
        name: name.to_string(),
    };
    match one_shot(interface_socket, Role::Interfaced, req).await {
        Some(InterfaceEvent::Interface(status)) => Some(status),
        _ => None,
    }
}

/// One-shot query of `nos-interfaced` for one named broadcast domain's
/// reconciled SVI addresses. Best-effort, mirrors `get_interface` exactly.
pub async fn get_broadcast_domain(
    interface_socket: &Path,
    name: &str,
) -> Option<BroadcastDomainStatus> {
    let req = InterfaceRequest::GetBroadcastDomain {
        name: name.to_string(),
    };
    match one_shot(interface_socket, Role::Interfaced, req).await {
        Some(InterfaceEvent::BroadcastDomain(status)) => Some(status),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use nos_proto::InterfaceAddress;
    use nos_proto::IpcCodec;
    use tokio_util::codec::{FramedRead, FramedWrite};

    fn serve_once(
        path: &Path,
        reply: impl Fn(InterfaceRequest) -> Option<InterfaceEvent> + Send + 'static,
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
            if let Some(Ok(req)) = reader.next().await
                && let Some(event) = reply(req)
            {
                let _ = writer.send(event).await;
            }
        });
    }

    #[tokio::test]
    async fn returns_status_on_well_formed_reply() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        serve_once(&path, |_req| {
            Some(InterfaceEvent::Interface(InterfaceStatus {
                link_local_address: None,
                name: "eth0".to_string(),
                addresses: vec![InterfaceAddress {
                    address: "10.0.0.1/24".parse().unwrap(),
                    label: None,
                }],
                routing_table: None,
                switching_profile: None,
                port_aggregate: None,
                mtu: 1500,
                subinterfaces: vec![],
                err_disabled: false,
                speed_mbps: None,
            }))
        });

        let status = get_interface(&path, "eth0").await.unwrap();
        assert_eq!(status.name, "eth0");
    }

    #[tokio::test]
    async fn returns_none_when_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        serve_once(&path, |_req| Some(InterfaceEvent::NotFound));

        assert_eq!(get_interface(&path, "eth0").await, None);
    }

    #[tokio::test]
    async fn returns_none_when_connection_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.sock");

        assert_eq!(get_interface(&path, "eth0").await, None);
    }

    #[tokio::test]
    async fn broadcast_domain_returns_status_on_well_formed_reply() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        serve_once(&path, |_req| {
            Some(InterfaceEvent::BroadcastDomain(BroadcastDomainStatus {
                link_local_address: None,
                name: "bd1".to_string(),
                addresses: vec![InterfaceAddress {
                    address: "10.0.0.1/24".parse().unwrap(),
                    label: None,
                }],
                routing_table: Some("rt1".to_string()),
                bridge_name: Some("br1".to_string()),
                mtu: None,
                speed_mbps: None,
            }))
        });

        let status = get_broadcast_domain(&path, "bd1").await.unwrap();
        assert_eq!(status.name, "bd1");
        assert_eq!(status.routing_table.as_deref(), Some("rt1"));
    }

    #[tokio::test]
    async fn broadcast_domain_returns_none_when_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("interface.sock");
        serve_once(&path, |_req| Some(InterfaceEvent::NotFound));

        assert_eq!(get_broadcast_domain(&path, "bd1").await, None);
    }

    #[tokio::test]
    async fn broadcast_domain_returns_none_when_connection_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.sock");

        assert_eq!(get_broadcast_domain(&path, "bd1").await, None);
    }
}
