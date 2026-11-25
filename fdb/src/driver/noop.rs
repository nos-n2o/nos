use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::info;

use super::{DriverError, FdbDriver, Mac};

/// Log-only backend (`--driver noop`): no OS effect, no local MAC feed.
pub struct NoopFdbDriver;

#[async_trait]
impl FdbDriver for NoopFdbDriver {
    async fn ensure_vxlan(
        &self,
        vni: u32,
        vtep: IpAddr,
        underlay: &str,
        bridge: &str,
        neigh_suppress: bool,
    ) -> Result<(), DriverError> {
        info!(vni, vtep = %vtep, underlay = %underlay, bridge = %bridge, neigh_suppress, "noop driver: ensure vxlan");
        Ok(())
    }
    async fn remove_vxlan(&self, vni: u32) -> Result<(), DriverError> {
        info!(vni, "noop driver: remove vxlan");
        Ok(())
    }
    async fn set_remote_mac(&self, _: u32, _: Mac, _: IpAddr) -> Result<(), DriverError> {
        Ok(())
    }
    async fn del_remote_mac(&self, _: u32, _: Mac, _: IpAddr) -> Result<(), DriverError> {
        Ok(())
    }
    async fn set_remote_mac_group(&self, _: u32, _: Mac, _: &[IpAddr]) -> Result<(), DriverError> {
        Ok(())
    }
    async fn del_remote_mac_group(&self, _: u32, _: Mac) -> Result<(), DriverError> {
        Ok(())
    }
    async fn set_segment_mac(&self, _: &str, _: Mac, _: bool) -> Result<(), DriverError> {
        Ok(())
    }
    async fn del_segment_mac(&self, _: &str, _: Mac) -> Result<(), DriverError> {
        Ok(())
    }
    async fn add_flood(&self, _: u32, _: IpAddr) -> Result<(), DriverError> {
        Ok(())
    }
    async fn del_flood(&self, _: u32, _: IpAddr) -> Result<(), DriverError> {
        Ok(())
    }
    async fn local_macs(&self, _: &str, _: u32) -> Result<BTreeMap<Mac, String>, DriverError> {
        Ok(BTreeMap::new())
    }
    async fn local_mac_ages(&self, _: &str, _: u32) -> Result<BTreeMap<Mac, u32>, DriverError> {
        Ok(BTreeMap::new())
    }
    async fn set_port_flood(
        &self,
        port: &str,
        unicast: bool,
        bum: bool,
    ) -> Result<(), DriverError> {
        info!(port = %port, unicast, bum, "noop driver: set port flood");
        Ok(())
    }
    async fn set_segment_filter(
        &self,
        port: &str,
        bit: u16,
        df_filter: bool,
    ) -> Result<(), DriverError> {
        info!(port = %port, bit, df_filter, "noop driver: set segment filter");
        Ok(())
    }
    async fn clear_segment_filter(&self, _: &str) -> Result<(), DriverError> {
        Ok(())
    }
    async fn set_local_bias(&self, _: u32, _: &BTreeMap<IpAddr, u16>) -> Result<(), DriverError> {
        Ok(())
    }
    async fn set_port_forwarding(&self, port: &str, forwarding: bool) -> Result<(), DriverError> {
        info!(port = %port, forwarding, "noop driver: set port forwarding");
        Ok(())
    }
    async fn port_up(&self, _: &str) -> Result<bool, DriverError> {
        Ok(true)
    }
    async fn local_neighbours(&self, _: &str) -> Result<BTreeSet<(Mac, IpAddr)>, DriverError> {
        Ok(BTreeSet::new())
    }
    async fn bridge_mac(&self, _: &str) -> Result<Mac, DriverError> {
        Ok([0x02, 0, 0, 0, 0, 0xfe])
    }
    async fn set_neigh(&self, _: &str, _: Mac, _: IpAddr) -> Result<(), DriverError> {
        Ok(())
    }
    async fn del_neigh(&self, _: &str, _: Mac, _: IpAddr) -> Result<(), DriverError> {
        Ok(())
    }
    fn watch_neigh(&self) -> Option<mpsc::Receiver<()>> {
        None
    }
}
