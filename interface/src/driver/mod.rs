//! Applies an interface's desired state to the real OS (or a stand-in).
//!
//! `nos-interfaced` never creates interfaces (see `CLAUDE.md`'s scope
//! section) — a driver only ever configures ones that already exist in the
//! netns. `NoopInterfaceDriver` (today's log-only behavior) is the
//! platform-agnostic default; `LinuxInterfaceDriver` is the real `rtnetlink`
//! implementation, selected via `--driver` in `main.rs`. This split exists
//! so a future non-Linux/hardware backend can be added without touching
//! `state.rs`/`reconcile.rs`.

pub mod bridge_registry;
pub mod links;
pub mod linux;
pub mod mpls_input;
pub mod noop;
pub mod ownership;
pub mod port_aggregate_registry;
pub mod rib_client;
pub mod steering;

use async_trait::async_trait;
use thiserror::Error;

pub use links::LinkWatch;
pub use linux::LinuxInterfaceDriver;
pub use noop::NoopInterfaceDriver;
pub use steering::SteeringState;

use nos_proto::{StpPortState, VlanTag};

use crate::state::{BroadcastDomainState, InterfaceState, PortAggregateState};

/// Result of asking "what is this link's master?" of something that can fail
/// to answer. `NotConfigured` (nothing wanted: un-enslave) must never be
/// confused with `Unknown` (could not find out: leave the link as it is, the
/// 10s re-apply tick retries) (#615).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    NotConfigured,
    Found(T),
    Unknown,
}

/// The MTU enforced on a link (or bond) whose `mtu` is unset — so `delete
/// … mtu` really puts the link back, and `show interface` reports the truth.
pub const DEFAULT_MTU: u32 = 1500;

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),
    #[error("i/o error opening netlink connection: {0}")]
    Io(#[from] std::io::Error),
    #[error("created loopback device {0} but could not find it afterwards")]
    LoopbackNotFound(String),
    #[error("created link {0} but could not find it afterwards")]
    LinkNotFoundAfterCreate(String),
    #[error("{0}")]
    Other(String),
}

/// One bridge port, as the config names it: the `Interface` or
/// `PortAggregate` `name`, and the `tag` it has in the domain's switching
/// profile (`Untagged` = the link itself, `Dot1q(n)` = its `<name>.<n>`
/// sub-link). The driver resolves the kernel link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgePortRef {
    pub name: String,
    pub aggregate: bool,
    pub tag: VlanTag,
}

/// One instance lives for the process lifetime, constructed in `main.rs`
/// from the `--driver` flag and shared as `Arc<dyn InterfaceDriver>` with
/// `reconcile::run`. Implementations own all "current vs desired" diffing
/// internally (e.g. dumping live kernel addresses, computing add/remove) —
/// callers always pass full desired state, never a precomputed patch,
/// mirroring the existing full-rebuild pattern in `state::build_from_config`.
#[async_trait]
pub trait InterfaceDriver: Send + Sync {
    /// Applies `desired`'s addresses, admin-up state, and (if
    /// `desired.routing_table` is set) VRF enslavement. The VRF's Linux
    /// interface name is resolved by the driver itself, by asking the
    /// owning `nos-ribd` instance over IPC (see `linux::LinuxInterfaceDriver`
    /// and `rib_client`) — "not resolvable yet" (that table's `nos-ribd`
    /// isn't running, or hasn't created its VRF yet) is an expected,
    /// transient condition, not an error: the driver silently leaves
    /// enslavement as-is and relies on the caller's periodic re-apply to
    /// retry.
    async fn apply(&self, desired: &InterfaceState) -> Result<(), DriverError>;

    /// Called once per resync for every interface name present in the
    /// *previous* resync's `Interfaces` but absent from the current one
    /// (removed from config outright). Un-enslaves from any VRF and
    /// removes any addresses previously applied; a no-op if the interface
    /// no longer exists in the netns. For a loopback name (see
    /// `nos_proto::loopback_table_name`), also deletes the kernel device
    /// this driver created for it — `name` alone is always sufficient to
    /// recompute what that device is.
    async fn remove(&self, name: &str) -> Result<(), DriverError>;

    /// Ensures a bridge device exists for `desired.name` (a `BroadcastDomain`
    /// name), creating it if missing, then reconciles `desired.addresses`
    /// and (if `desired.routing_table` is set) VRF enslavement onto the
    /// bridge device itself — the same two-step reconciliation `apply` does
    /// for a physical/loopback link, making the bridge an SVI (switch
    /// virtual interface). Called once per configured `BroadcastDomain` on
    /// every resync, independent of whether any interface currently
    /// references it — same "create eagerly from config" pattern as
    /// `nos-ribd`'s VRF-per-`RoutingTable`. Must complete (or at least be
    /// attempted) before any interface's `apply` in the same resync, since
    /// `apply` enslaves into this bridge by name. Returns the bridge's real
    /// kernel device name — `nos-ospfd` needs this (via
    /// `InterfaceRequest::GetBroadcastDomain`) to bind its raw socket to the
    /// domain's own bridge rather than the shared VRF device.
    async fn ensure_broadcast_domain(
        &self,
        desired: &BroadcastDomainState,
    ) -> Result<String, DriverError>;

    /// Called once per resync for every `BroadcastDomain` name present in
    /// the previous resync but absent from the current one (removed from
    /// config outright) - deletes the bridge device. A no-op if no bridge
    /// was ever created for `domain`.
    async fn remove_broadcast_domain(&self, domain: &str) -> Result<(), DriverError>;

    /// Ensures a bond device exists for `desired.name` (a `PortAggregate`
    /// name), creating it if missing with `desired.mode`, then reconciles
    /// its own `switching_profile`/`mtu`/`subinterfaces` onto the bond
    /// device itself — the exact same reconciliation `apply` does for a
    /// physical interface, since a `PortAggregate` has the identical config
    /// surface. Called once per configured `PortAggregate` on every resync,
    /// after every `ensure_broadcast_domain` call (a bond's own
    /// `switching_profile` may enslave it into a bridge that must already
    /// exist) and before any interface's `apply` (a member interface
    /// enslaves into this bond by name). Returns the bond's real kernel
    /// device name.
    async fn ensure_port_aggregate(
        &self,
        desired: &PortAggregateState,
    ) -> Result<String, DriverError>;

    /// Called once per resync for every `PortAggregate` name present in the
    /// previous resync but absent from the current one (removed from config
    /// outright) - deletes the bond device. A no-op if no bond was ever
    /// created for `name`.
    async fn remove_port_aggregate(&self, name: &str) -> Result<(), DriverError>;

    /// Best-effort query of `kernel_interface`'s current kernel-assigned
    /// IPv6 link-local address (`fe80::/10` scope) — a pure read, never a
    /// write, since NOS never touches kernel-auto-assigned addresses (see
    /// `apply`'s address-reconciliation doc comment). `None` if the
    /// interface doesn't exist yet or has no such address assigned yet.
    /// Called by `state::build_from_config` after `apply`/
    /// `ensure_broadcast_domain`, purely to surface it on
    /// `InterfaceStatus`/`SubinterfaceStatus`/`BroadcastDomainStatus` for a
    /// consumer with no kernel access of its own (`nos-ospfv3d`, sourcing
    /// RFC 5340 Hello/Link-LSA traffic from it).
    async fn link_local_address(&self, kernel_interface: &str) -> Option<std::net::Ipv6Addr>;

    /// Makes the kernel accept (`enabled`) or drop MPLS-labelled packets
    /// arriving on `name` (`net.mpls.conf.<name>.input`, #1380). Read first,
    /// written only when different. Called on every resync for every
    /// configured interface: `false` reverts only a knob this process set
    /// (an unconfigured value the operator wrote is left alone). A device
    /// without an MPLS conf directory is skipped (warned when `enabled`).
    async fn set_mpls_input(&self, name: &str, enabled: bool) -> Result<(), DriverError>;

    /// Observed kernel `IFLA_MTU` of `kernel_interface` (a bridge): a pure
    /// read; the kernel derives it from the bridge's ports. `None` = not
    /// resolvable now (retried on the next resync).
    async fn bridge_mtu(&self, kernel_interface: &str) -> Option<u32>;

    /// Observed kernel link speed of `kernel_interface` in Mbit/s, a pure
    /// read sampled per query. `None` = unknown (`-1`, `0`, unreadable).
    async fn link_speed_mbps(&self, kernel_interface: &str) -> Option<u32>;

    /// Observed admin/oper state of kernel device `kernel_interface`, sampled
    /// per query. `None` = nothing observed (noop).
    async fn link_oper(&self, kernel_interface: &str) -> Option<nos_proto::LinkOper>;

    /// Kernel `IFLA_STATS64` counters of `kernel_interface`, a pure read
    /// sampled per query, never cached. `None` = noop or the read failed.
    async fn link_counters(&self, kernel_interface: &str) -> Option<nos_proto::LinkCounters>;

    /// Puts one bridge port in `state` right now (`InterfaceRequest::
    /// SetStpPortStates`). The port must exist and be a bridge port. A
    /// resync keeps the state through `InterfaceState.stp`.
    async fn set_bridge_port_state(
        &self,
        port: &BridgePortRef,
        state: StpPortState,
    ) -> Result<(), DriverError>;

    /// Flushes the dynamic FDB entries learned on one bridge port
    /// (`InterfaceRequest::FlushFdb`).
    async fn flush_bridge_port(&self, port: &BridgePortRef) -> Result<(), DriverError>;

    /// Makes the tc steering of `desired.aggregate` exactly `desired`
    /// (#895): the whole set, empty `links` removes everything this driver
    /// installed for it. Idempotent; installs and removals are ordered so a
    /// conversation is never collectable on two links (`steering::plan`).
    async fn apply_conversation_steering(&self, desired: &SteeringState)
        -> Result<(), DriverError>;

    /// Installed steering of `aggregate` with its tc counters, per member.
    async fn steering_stats(&self, aggregate: &str) -> Vec<nos_proto::LacpLinkSteering>;

    /// Snapshot of the kernel's link table plus a receiver for later changes,
    /// for `InterfaceRequest::SubscribeLinks`. The noop driver reports
    /// `observed: false` and never fires.
    fn watch_links(&self) -> LinkWatch;
}
