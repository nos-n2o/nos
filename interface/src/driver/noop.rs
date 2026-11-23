use async_trait::async_trait;
use tracing::debug;

use nos_proto::StpPortState;

use super::{steering::SteeringState, BridgePortRef, DriverError, InterfaceDriver, LinkWatch};
use crate::state::{BroadcastDomainState, InterfaceState, PortAggregateState};

/// Platform-agnostic default: logs the state that would be applied but
/// never touches the OS network stack. Preserves today's placeholder
/// behavior for non-Linux hosts and for tests.
pub struct NoopInterfaceDriver;

#[async_trait]
impl InterfaceDriver for NoopInterfaceDriver {
    async fn apply(&self, desired: &InterfaceState) -> Result<(), DriverError> {
        debug!(
            interface = %desired.name,
            addresses = ?desired.addresses,
            routing_table = ?desired.routing_table,
            subinterfaces = ?desired.subinterfaces,
            "would apply interface configuration (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn remove(&self, name: &str) -> Result<(), DriverError> {
        debug!(
            interface = %name,
            "would remove interface configuration (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn ensure_broadcast_domain(
        &self,
        desired: &BroadcastDomainState,
    ) -> Result<String, DriverError> {
        debug!(
            domain = %desired.name,
            addresses = ?desired.addresses,
            routing_table = ?desired.routing_table,
            "would ensure broadcast domain bridge (noop driver — no OS effect)"
        );
        Ok(format!("noop-br-{}", desired.name))
    }

    async fn remove_broadcast_domain(&self, domain: &str) -> Result<(), DriverError> {
        debug!(
            domain = %domain,
            "would remove broadcast domain bridge (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn ensure_port_aggregate(
        &self,
        desired: &PortAggregateState,
    ) -> Result<String, DriverError> {
        debug!(
            port_aggregate = %desired.name,
            mode = ?desired.mode,
            "would ensure port aggregate bond (noop driver — no OS effect)"
        );
        Ok(format!("noop-bond-{}", desired.name))
    }

    async fn remove_port_aggregate(&self, name: &str) -> Result<(), DriverError> {
        debug!(
            port_aggregate = %name,
            "would remove port aggregate bond (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn link_local_address(&self, _kernel_interface: &str) -> Option<std::net::Ipv6Addr> {
        None
    }

    async fn bridge_mtu(&self, _kernel_interface: &str) -> Option<u32> {
        None
    }

    async fn link_speed_mbps(&self, _kernel_interface: &str) -> Option<u32> {
        None
    }

    async fn set_bridge_port_state(
        &self,
        port: &BridgePortRef,
        state: StpPortState,
    ) -> Result<(), DriverError> {
        debug!(
            port = ?port,
            state = ?state,
            "would set bridge port state (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn flush_bridge_port(&self, port: &BridgePortRef) -> Result<(), DriverError> {
        debug!(port = ?port, "would flush bridge port (noop driver — no OS effect)");
        Ok(())
    }

    async fn apply_conversation_steering(
        &self,
        desired: &SteeringState,
    ) -> Result<(), DriverError> {
        debug!(
            aggregate = %desired.aggregate,
            links = desired.links.len(),
            "would apply conversation steering (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn steering_stats(&self, _aggregate: &str) -> Vec<nos_proto::LacpLinkSteering> {
        Vec::new()
    }

    async fn set_mpls_input(&self, name: &str, enabled: bool) -> Result<(), DriverError> {
        debug!(interface = %name, enabled, "would set mpls input (noop driver — no OS effect)");
        Ok(())
    }

    fn watch_links(&self) -> LinkWatch {
        LinkWatch {
            observed: false,
            links: Vec::new(),
            rx: None,
        }
    }
}
