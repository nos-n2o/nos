use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use nos_proto::{IlmRoute, IpNet};
use tracing::debug;

use super::{mpls, DriverError, Mpls, RibDriver};
use crate::evpn::{L3Vni, Mac};
use crate::rib::RibEntry;

/// Placeholder driver, matching the original (pre-driver) behavior of this
/// crate: logs the routes it would install, never touches the kernel or any
/// file. Default off-Linux, and available everywhere via `--driver noop`.
/// Records each table's MPLS label (`sync_mpls`) for tests.
#[derive(Debug, Default)]
pub struct NoopRibDriver {
    mpls: Mutex<HashMap<String, u32>>,
    ilm: Mutex<HashMap<String, Vec<IlmRoute>>>,
}

impl NoopRibDriver {
    /// The ILM set `sync_ilm` last got for `table_name`.
    pub fn ilm_routes(&self, table_name: &str) -> Vec<IlmRoute> {
        self.ilm
            .lock()
            .unwrap()
            .get(table_name)
            .cloned()
            .unwrap_or_default()
    }

    /// The label `sync_mpls` last set for `table_name`.
    pub fn mpls_label(&self, table_name: &str) -> Option<u32> {
        self.mpls.lock().unwrap().get(table_name).copied()
    }
}

#[async_trait]
impl RibDriver for NoopRibDriver {
    async fn apply(
        &self,
        table_name: &str,
        best_routes: &HashMap<IpNet, RibEntry>,
    ) -> Result<(), DriverError> {
        debug!(
            table = %table_name,
            prefixes = best_routes.len(),
            labelled = best_routes.values().flat_map(|e| &e.next_hops).filter(|h| !h.labels.is_empty()).count(),
            "would install routes into a kernel VRF/table (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn apply_delta(
        &self,
        table_name: &str,
        changes: &HashMap<IpNet, Option<RibEntry>>,
    ) -> Result<(), DriverError> {
        debug!(
            table = %table_name,
            changed = changes.len(),
            "would apply route deltas to a kernel VRF/table (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn teardown(&self, table_name: &str) -> Result<(), DriverError> {
        debug!(
            table = %table_name,
            "would tear down the kernel VRF/table (noop driver — no OS effect)"
        );
        Ok(())
    }

    async fn vrf_name(&self, _table_name: &str) -> Option<String> {
        None
    }

    async fn table_id(&self, _table_name: &str) -> Option<u32> {
        None
    }

    async fn sync_l3vni(
        &self,
        table_name: &str,
        l3: Option<&L3Vni>,
        remotes: &BTreeMap<IpAddr, Mac>,
    ) -> Result<Option<Mac>, DriverError> {
        if l3.is_some() {
            debug!(
                table = %table_name,
                remotes = remotes.len(),
                "would build the l3 vni devices (noop driver — no OS effect)"
            );
        }
        Ok(None)
    }

    async fn sync_ilm(&self, table_name: &str, routes: &[IlmRoute]) -> Result<(), DriverError> {
        routes.iter().try_for_each(mpls::check_ilm)?;
        debug!(table = %table_name, routes = routes.len(), "would install mpls ilm routes (noop driver — no OS effect)");
        self.ilm
            .lock()
            .unwrap()
            .insert(table_name.to_string(), routes.to_vec());
        Ok(())
    }

    async fn sync_mpls(&self, table_name: &str, m: Option<&Mpls>) -> Result<(), DriverError> {
        let mut labels = self.mpls.lock().unwrap();
        match m {
            Some(m) => {
                mpls::check_label(m.label)?;
                debug!(table = %table_name, label = m.label, "would install the mpls pop route (noop driver — no OS effect)");
                labels.insert(table_name.to_string(), m.label);
            }
            None => {
                labels.remove(table_name);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_the_label_and_refuses_a_reserved_one() {
        let d = NoopRibDriver::default();
        let m = |label| Mpls {
            label,
            underlay: None,
        };
        d.sync_mpls("red", Some(&m(1000))).await.unwrap();
        assert_eq!(d.mpls_label("red"), Some(1000));
        assert!(d.sync_mpls("red", Some(&m(3))).await.is_err());
        assert_eq!(d.mpls_label("red"), Some(1000));
        d.sync_mpls("red", None).await.unwrap();
        assert_eq!(d.mpls_label("red"), None);
    }
}
