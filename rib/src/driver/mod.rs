use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use async_trait::async_trait;
use nos_proto::IpNet;
use thiserror::Error;

use crate::evpn::{L3Vni, Mac};
use crate::rib::RibEntry;

pub mod linux;
pub mod mpls;
pub mod noop;
pub mod route_channel;
pub mod table_registry;

pub use linux::LinuxRibDriver;
pub use mpls::Mpls;
pub use noop::NoopRibDriver;

/// Errors from applying `Rib` state to a real (or simulated) OS backend.
/// Never fatal to the daemon — every call site logs and keeps running, the
/// same resilience philosophy as a failed config fetch (see
/// `reconcile::resync`).
#[derive(Debug, Error)]
pub enum DriverError {
    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),
    #[error("table-id registry error: {0}")]
    Registry(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

/// Applies one routing table's computed best-path state to the OS (or a
/// stand-in). One instance lives for the process lifetime, shared as
/// `Arc<dyn RibDriver>` between `reconcile::run` and `server::start`.
/// Implementations own all "current vs desired" diffing internally (e.g.
/// dumping live kernel routes and computing an add/remove patch) — callers
/// always pass full desired state, never a precomputed patch, mirroring the
/// existing full-rebuild pattern in `rib::build_from_config`.
#[async_trait]
pub trait RibDriver: Send + Sync {
    /// Ensures a kernel VRF/table for `table_name` exists — allocating and
    /// persisting a fresh id on first use, or reusing the previously-
    /// persisted one across restarts — and installs the *winning* route
    /// per prefix from `best_routes` into it. `Rib`'s multi-candidate view
    /// stays a `show route` query-serving concern, never installed
    /// wholesale.
    async fn apply(
        &self,
        table_name: &str,
        best_routes: &HashMap<IpNet, RibEntry>,
    ) -> Result<(), DriverError>;

    /// Applies only these per-prefix deltas directly — `Some(entry)`
    /// installs/replaces that prefix's kernel route, `None` removes it —
    /// using the driver's own record of what it last installed rather than
    /// a fresh kernel dump. Callers only ever include a prefix here when
    /// its *winner* actually changed (see `Rib::upsert_and_diff`/
    /// `remove_and_diff`). This is the hot path for incremental BGP
    /// pushes; `apply`'s full dump-diff-converge remains the correctness
    /// backstop that keeps a driver's internal bookkeeping honest
    /// (periodic reconcile, initial apply, and any `Full` snapshot).
    async fn apply_delta(
        &self,
        table_name: &str,
        changes: &HashMap<IpNet, Option<RibEntry>>,
    ) -> Result<(), DriverError>;

    /// Startup hold (#654): while `on`, `apply` only adds and replaces, and
    /// leaves kernel routes it has no desired slot for (a crashed
    /// predecessor's `Bgp`/`Ospf` routes, not yet re-pushed) in place. The
    /// next `apply` after `keep_stale(false)` removes what is still stale.
    /// The default does nothing.
    fn keep_stale(&self, _on: bool) {}

    /// Deletes every route in `table_name`'s kernel table and the VRF
    /// device itself. Leaves any persisted table-id registry entry
    /// untouched, so a later `apply` for the same `table_name` (an
    /// ordinary restart, not necessarily a real removal — see
    /// `reconcile::run`) recreates the exact same VRF name.
    async fn teardown(&self, table_name: &str) -> Result<(), DriverError>;

    /// Current VRF interface name for `table_name`, if one has been
    /// allocated/created — backs `RibRequest::GetVrfName`. `None` for
    /// `NoopRibDriver` (no real VRF ever exists), or if `apply` hasn't
    /// successfully run yet. Read-only — never allocates.
    async fn vrf_name(&self, table_name: &str) -> Option<String>;

    /// Current kernel table id for `table_name`, if one has been
    /// allocated — backs `RibRequest::GetTableId`. `None` for
    /// `NoopRibDriver`, or if `apply` hasn't successfully run yet.
    /// Read-only — never allocates.
    async fn table_id(&self, table_name: &str) -> Option<u32>;

    /// Brings `table_name`'s EVPN L3 VNI devices in line with `l3`: a bridge
    /// `brv<vni>` in the table's VRF holding `vx<vni>` (`None` deletes both),
    /// and, per remote VTEP in `remotes`, the permanent neighbour (`<vtep>
    /// lladdr <rmac>` on the bridge) and FDB entry (`<rmac> dst <vtep>` on the
    /// VXLAN device) its `Evpn` routes are reached through. Returns our
    /// Router's MAC (the bridge's address), `None` when there is no L3 VNI.
    /// Must run before `apply` installs the table's `Evpn` routes, which
    /// leave through the bridge. The default builds nothing.
    /// RFC 7490 remote LFA: with `enabled`, ensures `table_name`'s IP-in-IP
    /// device (`rlfa<table-id>`), which carries this table's tunnel backups
    /// out and decapsulates other routers' into the table; without, deletes
    /// it. Must run before `apply` installs a `backup_tunnel` route. The
    /// default builds nothing.
    async fn sync_tunnel(&self, _table_name: &str, _enabled: bool) -> Result<(), DriverError> {
        Ok(())
    }

    async fn sync_l3vni(
        &self,
        _table_name: &str,
        _l3: Option<&L3Vni>,
        _remotes: &BTreeMap<IpAddr, Mac>,
    ) -> Result<Option<Mac>, DriverError> {
        Ok(None)
    }

    /// L3VPN (#581): with `mpls`, ensures the `AF_MPLS` route `<label> dev
    /// <vrf>` (pop, IP lookup in this table) and the `net.mpls` sysctls it
    /// needs, and records the underlay that `apply` resolves a labelled
    /// route's PE next hop in; `None` removes the route. An `Err` means the
    /// label cannot be forwarded, so the caller must not advertise it. Must
    /// run before `apply` installs a labelled (`Vpn`) route. The default
    /// builds nothing.
    async fn sync_mpls(&self, _table_name: &str, _mpls: Option<&Mpls>) -> Result<(), DriverError> {
        Ok(())
    }
}
