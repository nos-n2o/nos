use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nos_proto::ServiceRef;
use tokio::sync::RwLock;
use tracing::debug;

/// Cheap-`Clone` handle (like `nos-config`'s `ConfigStore`) over the live
/// mapping from routing-table/BGP-instance name to its `nos-ribd`/`nos-bgpd`
/// instance's IPC socket. Updated by `instances::manage` as instances are
/// spawned/stopped, and read by `broker::start` to answer `ResolveEndpoint`
/// requests.
#[derive(Clone, Default)]
pub struct EndpointRegistry {
    rib_tables: Arc<RwLock<HashMap<String, PathBuf>>>,
    bgp_instances: Arc<RwLock<HashMap<String, PathBuf>>>,
    ospf_instances: Arc<RwLock<HashMap<String, PathBuf>>>,
    ospfv3_instances: Arc<RwLock<HashMap<String, PathBuf>>>,
    fdb_domains: Arc<RwLock<HashMap<String, PathBuf>>>,
}

/// Which of the registry's per-name maps an endpoint belongs to — one per
/// daemon family that `instances::manage` spawns per named config object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    RibTable,
    BgpInstance,
    OspfInstance,
    Ospfv3Instance,
    FdbDomain,
}

impl EndpointKind {
    fn label(self) -> &'static str {
        match self {
            EndpointKind::RibTable => "rib table",
            EndpointKind::BgpInstance => "bgp instance",
            EndpointKind::OspfInstance => "ospf instance",
            EndpointKind::Ospfv3Instance => "ospfv3 instance",
            EndpointKind::FdbDomain => "fdb domain",
        }
    }
}

impl EndpointRegistry {
    fn map(&self, kind: EndpointKind) -> &RwLock<HashMap<String, PathBuf>> {
        match kind {
            EndpointKind::RibTable => &self.rib_tables,
            EndpointKind::BgpInstance => &self.bgp_instances,
            EndpointKind::OspfInstance => &self.ospf_instances,
            EndpointKind::Ospfv3Instance => &self.ospfv3_instances,
            EndpointKind::FdbDomain => &self.fdb_domains,
        }
    }

    pub async fn set(&self, kind: EndpointKind, name: &str, socket: PathBuf) {
        debug!(
            kind = kind.label(), name = %name, socket = %socket.display(),
            "registered endpoint"
        );
        self.map(kind)
            .write()
            .await
            .insert(name.to_string(), socket);
    }

    pub async fn remove(&self, kind: EndpointKind, name: &str) {
        debug!(kind = kind.label(), name = %name, "removed endpoint");
        self.map(kind).write().await.remove(name);
    }

    /// Resolves `service` to its current socket path, if known.
    /// `config_socket`/`interfaces_socket`/`log_socket`/`lacp_socket`/
    /// `lldp_socket`/`bfd_socket` are always resolvable — the watchdog is told them
    /// directly via its own `--config-socket`/`--interfaced-listen-socket`/
    /// `--log-socket`/`--lacpd-listen-socket`/`--lldpd-listen-socket`/`--bfdd-listen-socket` args, so
    /// none needs to be tracked in the map (there's exactly one
    /// `nos-configd`, one `nos-interfaced`, one `nos-logd`, one `nos-lacpd`,
    /// and one `nos-lldpd`, unlike `RibTable`/`BgpInstance`, which are keyed
    /// by name because there can be many).
    #[allow(
        clippy::too_many_arguments,
        reason = "one fixed socket per singleton daemon; a struct is a follow-up refactor"
    )]
    pub async fn resolve(
        &self,
        service: &ServiceRef,
        config_socket: &Path,
        interfaces_socket: &Path,
        log_socket: &Path,
        lacp_socket: &Path,
        lldp_socket: &Path,
        bfd_socket: &Path,
        stp_socket: &Path,
        acl_socket: &Path,
        radv_socket: &Path,
    ) -> Option<PathBuf> {
        let (kind, name) = match service {
            ServiceRef::Config => return Some(config_socket.to_path_buf()),
            ServiceRef::Interfaces => return Some(interfaces_socket.to_path_buf()),
            ServiceRef::Log => return Some(log_socket.to_path_buf()),
            ServiceRef::Lacp => return Some(lacp_socket.to_path_buf()),
            ServiceRef::Lldp => return Some(lldp_socket.to_path_buf()),
            ServiceRef::Bfd => return Some(bfd_socket.to_path_buf()),
            ServiceRef::Stp => return Some(stp_socket.to_path_buf()),
            ServiceRef::Acl => return Some(acl_socket.to_path_buf()),
            ServiceRef::Radv => return Some(radv_socket.to_path_buf()),
            ServiceRef::RibTable(name) => (EndpointKind::RibTable, name),
            ServiceRef::BgpInstance(name) => (EndpointKind::BgpInstance, name),
            ServiceRef::OspfInstance(name) => (EndpointKind::OspfInstance, name),
            ServiceRef::Ospfv3Instance(name) => (EndpointKind::Ospfv3Instance, name),
            ServiceRef::FdbDomain(name) => (EndpointKind::FdbDomain, name),
        };
        self.map(kind).read().await.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG_SOCKET: &str = "/run/nos/config.sock";
    const INTERFACES_SOCKET: &str = "/run/nos/interface.sock";
    const LOG_SOCKET: &str = "/run/nos/log.sock";
    const LACP_SOCKET: &str = "/run/nos/lacp.sock";
    const LLDP_SOCKET: &str = "/run/nos/lldp.sock";
    const BFD_SOCKET: &str = "/run/nos/bfd.sock";
    const STP_SOCKET: &str = "/run/nos/stp.sock";
    const ACL_SOCKET: &str = "/run/nos/acl.sock";
    const RADV_SOCKET: &str = "/run/nos/radv.sock";

    #[tokio::test]
    async fn config_always_resolves() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        let lacp_socket = Path::new(LACP_SOCKET);
        let lldp_socket = Path::new(LLDP_SOCKET);
        let bfd_socket = Path::new(BFD_SOCKET);
        let stp_socket = Path::new(STP_SOCKET);
        let acl_socket = Path::new(ACL_SOCKET);
        let radv_socket = Path::new(RADV_SOCKET);
        assert_eq!(
            registry
                .resolve(
                    &ServiceRef::Config,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            Some(config_socket.to_path_buf())
        );
    }

    #[tokio::test]
    async fn bfd_always_resolves() {
        let registry = EndpointRegistry::default();
        let p = |s| Path::new(s);
        assert_eq!(
            registry
                .resolve(
                    &ServiceRef::Bfd,
                    p(CONFIG_SOCKET),
                    p(INTERFACES_SOCKET),
                    p(LOG_SOCKET),
                    p(LACP_SOCKET),
                    p(LLDP_SOCKET),
                    p(BFD_SOCKET),
                    p(STP_SOCKET),
                    p(ACL_SOCKET),
                    p(RADV_SOCKET)
                )
                .await,
            Some(PathBuf::from(BFD_SOCKET))
        );
    }

    #[tokio::test]
    async fn acl_always_resolves() {
        let registry = EndpointRegistry::default();
        let p = |s| Path::new(s);
        assert_eq!(
            registry
                .resolve(
                    &ServiceRef::Acl,
                    p(CONFIG_SOCKET),
                    p(INTERFACES_SOCKET),
                    p(LOG_SOCKET),
                    p(LACP_SOCKET),
                    p(LLDP_SOCKET),
                    p(BFD_SOCKET),
                    p(STP_SOCKET),
                    p(ACL_SOCKET),
                    p(RADV_SOCKET)
                )
                .await,
            Some(PathBuf::from(ACL_SOCKET))
        );
    }

    #[tokio::test]
    async fn interfaces_always_resolves() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        let lacp_socket = Path::new(LACP_SOCKET);
        let lldp_socket = Path::new(LLDP_SOCKET);
        let bfd_socket = Path::new(BFD_SOCKET);
        let stp_socket = Path::new(STP_SOCKET);
        let acl_socket = Path::new(ACL_SOCKET);
        let radv_socket = Path::new(RADV_SOCKET);
        assert_eq!(
            registry
                .resolve(
                    &ServiceRef::Interfaces,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            Some(interfaces_socket.to_path_buf())
        );
    }

    #[tokio::test]
    async fn log_always_resolves() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        let lacp_socket = Path::new(LACP_SOCKET);
        let lldp_socket = Path::new(LLDP_SOCKET);
        let bfd_socket = Path::new(BFD_SOCKET);
        let stp_socket = Path::new(STP_SOCKET);
        let acl_socket = Path::new(ACL_SOCKET);
        let radv_socket = Path::new(RADV_SOCKET);
        assert_eq!(
            registry
                .resolve(
                    &ServiceRef::Log,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            Some(log_socket.to_path_buf())
        );
    }

    #[tokio::test]
    async fn lacp_always_resolves() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        let lacp_socket = Path::new(LACP_SOCKET);
        let lldp_socket = Path::new(LLDP_SOCKET);
        let bfd_socket = Path::new(BFD_SOCKET);
        let stp_socket = Path::new(STP_SOCKET);
        let acl_socket = Path::new(ACL_SOCKET);
        let radv_socket = Path::new(RADV_SOCKET);
        assert_eq!(
            registry
                .resolve(
                    &ServiceRef::Lacp,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            Some(lacp_socket.to_path_buf())
        );
    }

    #[tokio::test]
    async fn rib_table_resolves_after_set_and_not_after_remove() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        let lacp_socket = Path::new(LACP_SOCKET);
        let lldp_socket = Path::new(LLDP_SOCKET);
        let bfd_socket = Path::new(BFD_SOCKET);
        let stp_socket = Path::new(STP_SOCKET);
        let acl_socket = Path::new(ACL_SOCKET);
        let radv_socket = Path::new(RADV_SOCKET);
        let service = ServiceRef::RibTable("rt1".to_string());

        assert_eq!(
            registry
                .resolve(
                    &service,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            None
        );

        registry
            .set(
                EndpointKind::RibTable,
                "rt1",
                PathBuf::from("/run/nos/rib-rt1.sock"),
            )
            .await;
        assert_eq!(
            registry
                .resolve(
                    &service,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            Some(PathBuf::from("/run/nos/rib-rt1.sock"))
        );

        registry.remove(EndpointKind::RibTable, "rt1").await;
        assert_eq!(
            registry
                .resolve(
                    &service,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            None
        );
    }

    #[tokio::test]
    async fn bgp_instance_resolves_after_set_and_not_after_remove() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        let lacp_socket = Path::new(LACP_SOCKET);
        let lldp_socket = Path::new(LLDP_SOCKET);
        let bfd_socket = Path::new(BFD_SOCKET);
        let stp_socket = Path::new(STP_SOCKET);
        let acl_socket = Path::new(ACL_SOCKET);
        let radv_socket = Path::new(RADV_SOCKET);
        let service = ServiceRef::BgpInstance("r1".to_string());

        assert_eq!(
            registry
                .resolve(
                    &service,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            None
        );

        registry
            .set(
                EndpointKind::BgpInstance,
                "r1",
                PathBuf::from("/run/nos/bgp-r1.sock"),
            )
            .await;
        assert_eq!(
            registry
                .resolve(
                    &service,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            Some(PathBuf::from("/run/nos/bgp-r1.sock"))
        );

        registry.remove(EndpointKind::BgpInstance, "r1").await;
        assert_eq!(
            registry
                .resolve(
                    &service,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            None
        );
    }

    #[tokio::test]
    async fn ospf_instance_resolves_after_set_and_not_after_remove() {
        let registry = EndpointRegistry::default();
        let config_socket = Path::new(CONFIG_SOCKET);
        let interfaces_socket = Path::new(INTERFACES_SOCKET);
        let log_socket = Path::new(LOG_SOCKET);
        let lacp_socket = Path::new(LACP_SOCKET);
        let lldp_socket = Path::new(LLDP_SOCKET);
        let bfd_socket = Path::new(BFD_SOCKET);
        let stp_socket = Path::new(STP_SOCKET);
        let acl_socket = Path::new(ACL_SOCKET);
        let radv_socket = Path::new(RADV_SOCKET);
        let service = ServiceRef::OspfInstance("o1".to_string());

        assert_eq!(
            registry
                .resolve(
                    &service,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            None
        );

        registry
            .set(
                EndpointKind::OspfInstance,
                "o1",
                PathBuf::from("/run/nos/ospf-o1.sock"),
            )
            .await;
        assert_eq!(
            registry
                .resolve(
                    &service,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            Some(PathBuf::from("/run/nos/ospf-o1.sock"))
        );

        registry.remove(EndpointKind::OspfInstance, "o1").await;
        assert_eq!(
            registry
                .resolve(
                    &service,
                    config_socket,
                    interfaces_socket,
                    log_socket,
                    lacp_socket,
                    lldp_socket,
                    bfd_socket,
                    stp_socket,
                    acl_socket,
                    radv_socket
                )
                .await,
            None
        );
    }
}
