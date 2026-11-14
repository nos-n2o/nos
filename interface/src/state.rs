use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

use nos_proto::{
    loopback_table_name, Config, InterfaceAddress, PortAggregateMode, StpMode, StpPortAssignment,
    StpPortState, VlanTag,
};
use tracing::{debug, trace, warn};

use crate::driver::{BridgePortRef, InterfaceDriver};

/// One subinterface's desired state, mirroring `nos_proto::Subinterface`.
/// `tag == 0` is the untagged/native case, applied directly to the physical
/// (or loopback) link; `1..=4094` is realized as its own
/// `<interface>.<tag>` kernel sub-interface.
#[derive(Debug, Clone, PartialEq)]
pub struct SubinterfaceState {
    pub tag: u16,
    pub addresses: Vec<InterfaceAddress>,
    pub routing_table: Option<String>,
    /// Configured per-subinterface MTU override; `None` follows the parent.
    pub mtu: Option<u32>,
    /// This subinterface's own kernel device's observed IPv6 link-local
    /// address — see `nos_proto::SubinterfaceStatus.link_local_address`'s
    /// doc comment. Queried via `driver.link_local_address` after `apply`,
    /// against the same kernel device name `apply`/`reconcile_addresses`
    /// use (the physical interface itself for `tag == 0`, else
    /// `<interface>.<tag>`).
    pub link_local_address: Option<Ipv6Addr>,
}

/// A `BroadcastDomain`'s desired state, mirroring `nos_proto::BroadcastDomain`
/// — same flat L3 shape as a loopback `Interface`, since a domain's own
/// bridge has no VLAN/tag concept of its own.
#[derive(Debug, Clone, PartialEq)]
pub struct BroadcastDomainState {
    pub name: String,
    pub addresses: Vec<InterfaceAddress>,
    pub routing_table: Option<String>,
    /// The real kernel bridge device name, filled in from
    /// `driver.ensure_broadcast_domain`'s return value after construction —
    /// `None` on the value passed *into* that call (the driver is what
    /// determines it), `Some` once known.
    pub bridge_name: Option<String>,
    /// This domain's own bridge device's observed IPv6 link-local address —
    /// see `SubinterfaceState.link_local_address`'s doc comment. `None`
    /// until `bridge_name` itself is known (queried against it once it is).
    pub link_local_address: Option<Ipv6Addr>,
}

/// What spanning tree wants of one port (an interface or an aggregate): the
/// fail-safe applies exactly while `on`, and `states` is the last state
/// `nos-stpd` pushed per broadcast domain (absent = still blocking).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StpPorts {
    pub on: bool,
    /// BPDU guard shut the port (`SetErrDisabled`): the link stays down.
    pub err_disabled: bool,
    pub states: HashMap<String, StpPortState>,
}

/// One interface's desired state, as reconciled from the running config.
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceState {
    pub name: String,
    /// Populated only for a loopback interface (flat L3 config, unchanged);
    /// empty for every other interface, whose L3 config lives in
    /// `subinterfaces` instead — schema validation already guarantees this
    /// split (`valid_addressing_split`).
    pub addresses: Vec<InterfaceAddress>,
    pub routing_table: Option<String>,
    /// The raw `Interface.switching_profile` name, same shape as
    /// `routing_table` — for status display.
    pub switching_profile: Option<String>,
    /// `switching_profile` resolved to its `SwitchingProfile`'s member
    /// list — pure local config, unlike `routing_table`'s VRF name, so no
    /// cross-daemon IPC is needed to resolve it here; the driver interprets
    /// each `(domain, tag)` pair directly. Empty if `switching_profile` is
    /// unset (or names a profile that doesn't exist, which commit-time
    /// validation already prevents).
    pub switching_profile_members: Vec<(String, VlanTag)>,
    /// The raw `Interface.port_aggregate` name, same shape as
    /// `switching_profile` — resolved to a real bond device name by the
    /// driver itself (via its own port-aggregate-id registry), not here,
    /// mirroring `routing_table`'s VRF-name resolution.
    pub port_aggregate: Option<String>,
    /// Whether this interface should actually be enslaved into
    /// `port_aggregate`'s bond device right now. Always `true` when
    /// `port_aggregate` is set on a `Xor`-mode aggregate (unconditional,
    /// unchanged from before this field existed). For a `Lacp`-mode
    /// aggregate, `true` only once `nos-lacpd` has pushed this interface
    /// into `Interfaces.lacp_active_members` for it — see
    /// `Interfaces::set_lacp_active_members`. Meaningless when
    /// `port_aggregate` is `None`.
    pub port_aggregate_active: bool,
    /// The configured MTU; `None` means `driver::DEFAULT_MTU` (1500),
    /// enforced by the driver, except on a bond member, whose MTU its bond
    /// sets. A link-layer property of the physical (or loopback) interface
    /// itself, applying to every one of `subinterfaces` uniformly (a VLAN
    /// sub-link has no MTU of its own).
    pub mtu: Option<u32>,
    /// This (non-loopback) interface's per-tag L3 subinterfaces — see
    /// `SubinterfaceState`. Empty for a loopback interface.
    pub subinterfaces: Vec<SubinterfaceState>,
    /// Spanning-tree view of this interface's bridge ports.
    pub stp: StpPorts,
}

/// A `PortAggregate`'s desired state, mirroring `nos_proto::PortAggregate` —
/// the same config surface as a physical `InterfaceState` (no flat
/// `addresses`/`routing_table` — all L3 config lives under
/// `subinterfaces`), plus `mode`.
#[derive(Debug, Clone, PartialEq)]
pub struct PortAggregateState {
    pub name: String,
    pub mode: PortAggregateMode,
    pub switching_profile: Option<String>,
    pub switching_profile_members: Vec<(String, VlanTag)>,
    pub mtu: Option<u32>,
    pub subinterfaces: Vec<SubinterfaceState>,
    /// The real kernel bond device name, filled in from
    /// `driver.ensure_port_aggregate`'s return value after construction —
    /// mirrors `BroadcastDomainState.bridge_name`.
    pub bond_name: Option<String>,
    /// This bond's own kernel device's observed IPv6 link-local address —
    /// see `SubinterfaceState.link_local_address`'s doc comment. `None`
    /// until `bond_name` itself is known.
    pub link_local_address: Option<Ipv6Addr>,
    /// `PortAggregate.bfd` is set: a member is only enslaved while
    /// `nos-bfdd` reports its micro-BFD session Up (`bfd_up_members`).
    pub bfd: bool,
    /// Spanning-tree view of this aggregate's bridge ports.
    pub stp: StpPorts,
}

/// Every configured interface's desired state, rebuilt wholesale on every
/// resync (see `crate::reconcile`) — mirrors `nos-rib`'s `Rib`.
#[derive(Debug, Clone, Default)]
pub struct Interfaces {
    by_name: HashMap<String, InterfaceState>,
    /// Every `BroadcastDomain`'s desired state as of the last resync —
    /// queryable over IPC (`InterfaceRequest::GetBroadcastDomain`), mirrors
    /// `by_name`'s role for interfaces.
    by_domain: HashMap<String, BroadcastDomainState>,
    /// Every `BroadcastDomain` name configured as of the last resync —
    /// tracked so the next resync can diff for domains removed from config
    /// and call `driver.remove_broadcast_domain`, the same "previous vs
    /// current, call remove for what's gone" shape `by_name` itself already
    /// uses for interfaces.
    domains: HashSet<String>,
    /// Every `PortAggregate`'s desired state as of the last resync —
    /// queryable over IPC, mirrors `by_domain`'s role for broadcast domains.
    by_port_aggregate: HashMap<String, PortAggregateState>,
    /// Every `PortAggregate` name configured as of the last resync — same
    /// removal-diffing role as `domains`.
    port_aggregates: HashSet<String>,
    /// The most recently pushed active-member set (`nos_proto::
    /// LacpAggregateMembers`) for each `Lacp`-mode `PortAggregate`, keyed by
    /// aggregate name — see `InterfaceState.port_aggregate_active`. Unlike
    /// every other field here, this is **not** rebuilt by
    /// `build_from_config` (it isn't derived from `Config` at all) —
    /// carried forward unchanged from `previous` on every ordinary resync,
    /// so an unrelated config change never reverts a negotiated bond back
    /// to "nothing enslaved". A fresh `Interfaces::new()` has an empty map,
    /// which is the deliberate fail-safe default: nothing is enslaved into
    /// a `Lacp`-mode bond until the first real push arrives.
    lacp_active_members: HashMap<String, Vec<String>>,
    /// The most recently pushed micro-BFD Up set (`InterfaceRequest::
    /// PushBfdMembers`) per aggregate with `bfd`; carried forward by
    /// `build_from_config` like `lacp_active_members`. No push = no member
    /// Up (fail closed).
    bfd_up_members: HashMap<String, Vec<String>>,
    /// `spanning-tree mode` is not `disabled` as of the last resync.
    stp_on: bool,
    /// The last state `nos-stpd` pushed per `(port, domain)`; carried forward
    /// by `build_from_config` like `lacp_active_members`, so a resync never
    /// resets a port the daemon has opened.
    stp_port_states: HashMap<(String, String), StpPortState>,
    /// Ports `nos-stpd` err-disabled (#320); carried forward like
    /// `stp_port_states`, so a resync never brings such a link back up.
    err_disabled: HashSet<String>,
}

impl Interfaces {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<&InterfaceState> {
        self.by_name.get(name)
    }

    pub fn get_domain(&self, name: &str) -> Option<&BroadcastDomainState> {
        self.by_domain.get(name)
    }

    pub fn get_port_aggregate(&self, name: &str) -> Option<&PortAggregateState> {
        self.by_port_aggregate.get(name)
    }

    /// Every port aggregate, ordered by name — for serving an unfiltered
    /// `show port-aggregate` query.
    pub fn all_port_aggregates(&self) -> Vec<PortAggregateState> {
        let mut aggregates: Vec<PortAggregateState> =
            self.by_port_aggregate.values().cloned().collect();
        aggregates.sort_by(|a, b| a.name.cmp(&b.name));
        aggregates
    }

    /// Every interface, ordered by name — for serving an unfiltered
    /// `show interface` query.
    pub fn all(&self) -> Vec<InterfaceState> {
        let mut interfaces: Vec<InterfaceState> = self.by_name.values().cloned().collect();
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        interfaces
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Applies a fresh `nos-lacpd` push (`InterfaceRequest::PushLacpMembers`)
    /// — replaces `aggregate`'s active-member set and recomputes
    /// `port_aggregate_active` for every currently-known interface that
    /// references it, returning those interfaces' updated state so the
    /// caller can `driver.apply` them immediately rather than waiting for
    /// the next periodic resync (mirrors `nos-ribd`'s BGP-route-push
    /// immediate-apply precedent).
    pub fn set_lacp_active_members(
        &mut self,
        aggregate: &str,
        active_members: Vec<String>,
    ) -> Vec<InterfaceState> {
        self.lacp_active_members
            .insert(aggregate.to_string(), active_members);
        self.recompute_members(aggregate)
    }

    /// Applies a fresh `nos-bfdd` push (`InterfaceRequest::PushBfdMembers`):
    /// same shape as `set_lacp_active_members`, over the micro-BFD Up set.
    pub fn set_bfd_up_members(
        &mut self,
        aggregate: &str,
        up_members: Vec<String>,
    ) -> Vec<InterfaceState> {
        self.bfd_up_members
            .insert(aggregate.to_string(), up_members);
        self.recompute_members(aggregate)
    }

    /// The bridge port `port` (an interface or an aggregate) has in `domain`,
    /// if its switching profile makes it a member.
    pub fn bridge_port(&self, port: &str, domain: &str) -> Option<BridgePortRef> {
        let (aggregate, members) = match self.by_name.get(port) {
            Some(i) => (false, &i.switching_profile_members),
            None => (
                true,
                &self.by_port_aggregate.get(port)?.switching_profile_members,
            ),
        };
        let tag = members.iter().find(|(d, _)| d == domain)?.1;
        Some(BridgePortRef {
            name: port.to_string(),
            aggregate,
            tag,
        })
    }

    /// Applies a `nos-stpd` push (`InterfaceRequest::SetStpPortStates`):
    /// remembers every state, and returns the ports to write now. Nothing to
    /// write while spanning tree is off, or for a `(port, domain)` that is not
    /// a bridge port.
    pub fn set_stp_port_states(
        &mut self,
        assignments: Vec<StpPortAssignment>,
    ) -> Vec<(BridgePortRef, StpPortState)> {
        let mut writes = Vec::new();
        for a in assignments {
            let stp = match self.by_name.get_mut(&a.port) {
                Some(i) => Some(&mut i.stp),
                None => self.by_port_aggregate.get_mut(&a.port).map(|g| &mut g.stp),
            };
            if let Some(stp) = stp {
                stp.states.insert(a.domain.clone(), a.state);
            }
            let port = self.bridge_port(&a.port, &a.domain);
            self.stp_port_states.insert((a.port, a.domain), a.state);
            if let Some(p) = port.filter(|_| self.stp_on) {
                writes.push((p, a.state));
            }
        }
        writes
    }

    /// Applies a `nos-stpd` push (`InterfaceRequest::SetErrDisabled`) and
    /// returns the updated state of the port (an interface or an aggregate)
    /// for the caller to apply at once.
    pub fn set_err_disabled(
        &mut self,
        port: &str,
        disabled: bool,
    ) -> (Option<InterfaceState>, Option<PortAggregateState>) {
        if disabled {
            self.err_disabled.insert(port.to_string());
        } else {
            self.err_disabled.remove(port);
        }
        if let Some(i) = self.by_name.get_mut(port) {
            i.stp.err_disabled = disabled;
            return (Some(i.clone()), None);
        }
        if let Some(a) = self.by_port_aggregate.get_mut(port) {
            a.stp.err_disabled = disabled;
            return (None, Some(a.clone()));
        }
        (None, None)
    }

    /// Takes over `current` (a set that changed while a resync was building
    /// this value) and returns the ports whose flag differs, for the caller
    /// to apply again.
    pub fn adopt_err_disabled(
        &mut self,
        current: &HashSet<String>,
    ) -> (Vec<InterfaceState>, Vec<PortAggregateState>) {
        let changed: Vec<String> = self
            .err_disabled
            .symmetric_difference(current)
            .cloned()
            .collect();
        let (mut ifaces, mut aggs) = (Vec::new(), Vec::new());
        for port in changed {
            match self.set_err_disabled(&port, current.contains(&port)) {
                (Some(i), _) => ifaces.push(i),
                (_, Some(a)) => aggs.push(a),
                _ => {}
            }
        }
        (ifaces, aggs)
    }

    /// The ports `nos-stpd` holds down.
    pub fn err_disabled_ports(&self) -> &HashSet<String> {
        &self.err_disabled
    }

    /// Whether spanning tree is on (`spanning-tree mode` not `disabled`).
    pub fn stp_on(&self) -> bool {
        self.stp_on
    }

    /// Recomputes `port_aggregate_active` of every member of `aggregate`
    /// from both pushed sets (never from one half alone).
    fn recompute_members(&mut self, aggregate: &str) -> Vec<InterfaceState> {
        let (mode, bfd) = self
            .by_port_aggregate
            .get(aggregate)
            .map_or((PortAggregateMode::Xor, false), |a| (a.mode, a.bfd));
        let mut updated = Vec::new();
        for state in self.by_name.values_mut() {
            if state.port_aggregate.as_deref() == Some(aggregate) {
                state.port_aggregate_active = member_active(
                    mode,
                    bfd,
                    &self.lacp_active_members,
                    &self.bfd_up_members,
                    aggregate,
                    &state.name,
                );
                updated.push(state.clone());
            }
        }
        updated
    }
}

/// Ensures every configured broadcast domain's bridge through `driver`, split
/// out of `build_from_config` for length (#425).
async fn ensure_broadcast_domains(
    cfg: &Config,
    driver: &dyn InterfaceDriver,
) -> HashMap<String, BroadcastDomainState> {
    let mut by_domain = HashMap::with_capacity(cfg.broadcast_domains.len());
    for domain in &cfg.broadcast_domains {
        let mut state = BroadcastDomainState {
            name: domain.name.clone(),
            addresses: domain.addresses.clone(),
            routing_table: domain.routing_table.clone(),
            bridge_name: None,
            link_local_address: None,
        };
        match driver.ensure_broadcast_domain(&state).await {
            Ok(bridge_name) => {
                state.link_local_address = driver.link_local_address(&bridge_name).await;
                state.bridge_name = Some(bridge_name);
            }
            Err(e) => {
                warn!(domain = %state.name, error = %e, "failed to ensure broadcast domain bridge");
            }
        }
        by_domain.insert(state.name.clone(), state);
    }
    by_domain
}

/// Builds a fresh `Interfaces` from a freshly fetched `Config`, applying
/// each interface's desired state via `driver` along the way, and calling
/// `driver.remove` for every interface present in `previous` but absent
/// from `cfg` (removed from config outright). Broadcast domain bridges are
/// reconciled first, in the same pass — an interface's switching-profile
/// enslavement below resolves each bridge by name, so it must already
/// exist (or the driver treats it as the ordinary transient
/// not-ready-yet case and retries on the next resync).
pub async fn build_from_config(
    cfg: &Config,
    driver: &dyn InterfaceDriver,
    previous: &Interfaces,
) -> Interfaces {
    let stp_on = cfg.spanning_tree.mode != StpMode::Disabled;
    let port_stp = |port: &str| StpPorts {
        on: stp_on,
        err_disabled: previous.err_disabled.contains(port),
        states: previous
            .stp_port_states
            .iter()
            .filter(|((p, _), _)| p == port)
            .map(|((_, d), s)| (d.clone(), *s))
            .collect(),
    };
    let by_domain = ensure_broadcast_domains(cfg, driver).await;
    let domains: HashSet<String> = cfg
        .broadcast_domains
        .iter()
        .map(|d| d.name.clone())
        .collect();
    for gone in previous
        .domains
        .iter()
        .filter(|name| !domains.contains(name.as_str()))
    {
        debug!(domain = %gone, "broadcast domain removed from config, cleaning up");
        if let Err(e) = driver.remove_broadcast_domain(gone).await {
            warn!(domain = %gone, error = %e, "failed to clean up removed broadcast domain");
        }
    }

    let mut by_port_aggregate = HashMap::with_capacity(cfg.port_aggregates.len());
    for agg in &cfg.port_aggregates {
        let switching_profile_members =
            resolve_switching_profile_members(cfg, agg.switching_profile.as_deref());
        let subinterfaces = build_subinterfaces(driver, &agg.name, &agg.subinterfaces).await;
        let mut state = PortAggregateState {
            name: agg.name.clone(),
            mode: agg.mode,
            switching_profile: agg.switching_profile.clone(),
            switching_profile_members,
            mtu: agg.mtu,
            subinterfaces,
            bond_name: None,
            link_local_address: None,
            bfd: agg.bfd.is_some(),
            stp: port_stp(&agg.name),
        };
        match driver.ensure_port_aggregate(&state).await {
            Ok(bond_name) => {
                state.link_local_address = driver.link_local_address(&bond_name).await;
                state.bond_name = Some(bond_name);
            }
            Err(e) => {
                warn!(port_aggregate = %state.name, error = %e, "failed to ensure port aggregate bond");
            }
        }
        by_port_aggregate.insert(state.name.clone(), state);
    }
    let port_aggregates: HashSet<String> =
        cfg.port_aggregates.iter().map(|a| a.name.clone()).collect();
    for gone in previous
        .port_aggregates
        .iter()
        .filter(|name| !port_aggregates.contains(name.as_str()))
    {
        debug!(port_aggregate = %gone, "port aggregate removed from config, cleaning up");
        if let Err(e) = driver.remove_port_aggregate(gone).await {
            warn!(port_aggregate = %gone, error = %e, "failed to clean up removed port aggregate");
        }
    }

    let mut by_name = HashMap::with_capacity(cfg.interfaces.len());
    for iface in &cfg.interfaces {
        let switching_profile_members =
            resolve_switching_profile_members(cfg, iface.switching_profile.as_deref());
        let subinterfaces = build_subinterfaces(driver, &iface.name, &iface.subinterfaces).await;
        let port_aggregate_active = resolve_port_aggregate_active(
            cfg,
            iface.port_aggregate.as_deref(),
            &iface.name,
            &previous.lacp_active_members,
            &previous.bfd_up_members,
        );
        let state = InterfaceState {
            name: iface.name.clone(),
            addresses: iface.addresses.clone(),
            // A loopback's table is its name (`loopback-<table>`): the VRF the
            // driver enslaves it into, whatever the field says, so status
            // consumers (ribd's connected routes, `show interface`) agree.
            routing_table: loopback_table_name(&iface.name)
                .map(str::to_string)
                .or_else(|| iface.routing_table.clone()),
            switching_profile: iface.switching_profile.clone(),
            switching_profile_members,
            port_aggregate: iface.port_aggregate.clone(),
            port_aggregate_active,
            mtu: iface.mtu,
            subinterfaces,
            stp: port_stp(&iface.name),
        };
        trace!(
            interface = %state.name,
            addresses = ?state.addresses,
            routing_table = ?state.routing_table,
            switching_profile_members = ?state.switching_profile_members,
            port_aggregate = ?state.port_aggregate,
            port_aggregate_active = state.port_aggregate_active,
            subinterfaces = ?state.subinterfaces,
            "applying interface state"
        );
        if let Err(e) = driver.apply(&state).await {
            warn!(interface = %state.name, error = %e, "failed to apply interface configuration");
        }
        by_name.insert(state.name.clone(), state);
    }

    let current: HashSet<&str> = by_name.keys().map(String::as_str).collect();
    for gone in previous
        .all()
        .iter()
        .map(|i| i.name.clone())
        .filter(|name| !current.contains(name.as_str()))
    {
        debug!(interface = %gone, "interface removed from config, cleaning up");
        if let Err(e) = driver.remove(&gone).await {
            warn!(interface = %gone, error = %e, "failed to clean up removed interface");
        }
    }

    Interfaces {
        by_name,
        by_domain,
        domains,
        by_port_aggregate,
        port_aggregates,
        lacp_active_members: previous.lacp_active_members.clone(),
        bfd_up_members: previous.bfd_up_members.clone(),
        stp_on,
        stp_port_states: previous.stp_port_states.clone(),
        err_disabled: previous.err_disabled.clone(),
    }
}

/// Whether `iface_name` should actually be enslaved into `port_aggregate`
/// right now: `lacp_ok && bfd_ok`. Unconditional for a `Xor`-mode aggregate
/// (or one not found in `cfg`, which commit-time validation should already
/// prevent) without `bfd`. See `member_active` and
/// `InterfaceState.port_aggregate_active`.
fn resolve_port_aggregate_active(
    cfg: &Config,
    port_aggregate: Option<&str>,
    iface_name: &str,
    lacp_active_members: &HashMap<String, Vec<String>>,
    bfd_up_members: &HashMap<String, Vec<String>>,
) -> bool {
    let Some(name) = port_aggregate else {
        return false;
    };
    let agg = cfg.port_aggregates.iter().find(|a| a.name == name);
    member_active(
        agg.map_or(PortAggregateMode::Xor, |a| a.mode),
        agg.is_some_and(|a| a.bfd.is_some()),
        lacp_active_members,
        bfd_up_members,
        name,
        iface_name,
    )
}

/// `lacp_ok && bfd_ok`: `lacp_ok` is true for `Xor`, else the member is in
/// the last `nos-lacpd` set; `bfd_ok` is true without `bfd`, else the member
/// is in the last `nos-bfdd` Up set (no push yet = not Up).
fn member_active(
    mode: PortAggregateMode,
    bfd: bool,
    lacp_active_members: &HashMap<String, Vec<String>>,
    bfd_up_members: &HashMap<String, Vec<String>>,
    aggregate: &str,
    member: &str,
) -> bool {
    let listed = |m: &HashMap<String, Vec<String>>| {
        m.get(aggregate)
            .is_some_and(|members| members.iter().any(|x| x == member))
    };
    let lacp_ok = mode != PortAggregateMode::Lacp || listed(lacp_active_members);
    let bfd_ok = !bfd || listed(bfd_up_members);
    lacp_ok && bfd_ok
}

/// Resolves a `switching_profile` name (if set) to its `SwitchingProfile`'s
/// member list — shared by an `Interface`'s own resolution and a
/// `PortAggregate`'s own (a bond can be trunked into a broadcast domain the
/// same way a physical interface can).
fn resolve_switching_profile_members(
    cfg: &Config,
    switching_profile: Option<&str>,
) -> Vec<(String, VlanTag)> {
    switching_profile
        .and_then(|name| cfg.switching_profiles.iter().find(|p| p.name == name))
        .map(|p| {
            p.members
                .iter()
                .map(|m| (m.broadcast_domain.clone(), m.tag))
                .collect()
        })
        .unwrap_or_default()
}

/// Builds `SubinterfaceState`s for `subs`, keyed off `base_name` (an
/// `Interface`'s or `PortAggregate`'s own name) for the tag>0
/// `<base_name>.<tag>` kernel device naming convention — shared by both,
/// since a bond's own VLAN sub-links are named identically to a physical
/// interface's.
async fn build_subinterfaces(
    driver: &dyn InterfaceDriver,
    base_name: &str,
    subs: &[nos_proto::Subinterface],
) -> Vec<SubinterfaceState> {
    let mut subinterfaces = Vec::with_capacity(subs.len());
    for s in subs {
        let kernel_interface = if s.tag == 0 {
            base_name.to_string()
        } else {
            format!("{base_name}.{}", s.tag)
        };
        subinterfaces.push(SubinterfaceState {
            tag: s.tag,
            addresses: s.addresses.clone(),
            routing_table: s.routing_table.clone(),
            mtu: s.mtu,
            link_local_address: driver.link_local_address(&kernel_interface).await,
        });
    }
    subinterfaces
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use nos_proto::Interface;

    use super::*;
    use crate::driver::{DriverError, NoopInterfaceDriver};

    fn cfg(interfaces: Vec<Interface>) -> Config {
        Config {
            interfaces,
            ..Default::default()
        }
    }

    fn interface(name: &str) -> Interface {
        Interface {
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: None,
            switching_profile: None,
            port_aggregate: None,
            lacp_port_priority: None,
            lacp_link_number: None,
            lacp_mode: nos_proto::LacpMode::default(),
            mtu: None,
            lldp_transmit: false,
            lldp_receive: false,
            lldp_destination: nos_proto::LldpDestination::default(),
            subinterfaces: Vec::new(),
            ..Default::default()
        }
    }

    /// Records every `apply`/`remove` call it receives, for asserting on
    /// what `build_from_config` did without needing to observe log output.
    #[derive(Debug, Clone, PartialEq)]
    enum Call {
        Apply(String),
        Remove(String),
        EnsureDomain(BroadcastDomainState),
        RemoveDomain(String),
        EnsurePortAggregate(PortAggregateState),
        RemovePortAggregate(String),
    }

    #[derive(Default)]
    struct RecordingDriver {
        calls: Mutex<Vec<Call>>,
    }

    #[async_trait]
    impl InterfaceDriver for RecordingDriver {
        async fn apply(&self, desired: &InterfaceState) -> Result<(), DriverError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Apply(desired.name.clone()));
            Ok(())
        }

        async fn remove(&self, name: &str) -> Result<(), DriverError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Remove(name.to_string()));
            Ok(())
        }

        async fn ensure_broadcast_domain(
            &self,
            desired: &BroadcastDomainState,
        ) -> Result<String, DriverError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::EnsureDomain(desired.clone()));
            Ok(format!("recording-br-{}", desired.name))
        }

        async fn remove_broadcast_domain(&self, domain: &str) -> Result<(), DriverError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::RemoveDomain(domain.to_string()));
            Ok(())
        }

        async fn ensure_port_aggregate(
            &self,
            desired: &PortAggregateState,
        ) -> Result<String, DriverError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::EnsurePortAggregate(desired.clone()));
            Ok(format!("recording-bond-{}", desired.name))
        }

        async fn remove_port_aggregate(&self, name: &str) -> Result<(), DriverError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::RemovePortAggregate(name.to_string()));
            Ok(())
        }

        async fn link_local_address(&self, _kernel_interface: &str) -> Option<Ipv6Addr> {
            None
        }

        async fn set_bridge_port_state(
            &self,
            _port: &crate::driver::BridgePortRef,
            _state: StpPortState,
        ) -> Result<(), DriverError> {
            Ok(())
        }

        async fn flush_bridge_port(
            &self,
            _port: &crate::driver::BridgePortRef,
        ) -> Result<(), DriverError> {
            Ok(())
        }

        fn watch_links(&self) -> crate::driver::LinkWatch {
            crate::driver::LinkWatch {
                observed: false,
                links: Vec::new(),
                rx: None,
            }
        }
    }

    #[tokio::test]
    async fn build_from_config_with_no_interfaces_is_empty() {
        let interfaces =
            build_from_config(&cfg(vec![]), &NoopInterfaceDriver, &Interfaces::new()).await;
        assert!(interfaces.is_empty());
    }

    /// #117: a loopback's routing table is the one its name implies, even
    /// with the field unset — that's the VRF the driver enslaves it into.
    #[tokio::test]
    async fn loopback_routing_table_comes_from_its_name() {
        let interfaces = build_from_config(
            &cfg(vec![interface("loopback-rt1"), interface("eth0")]),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;
        assert_eq!(
            interfaces
                .get("loopback-rt1")
                .unwrap()
                .routing_table
                .as_deref(),
            Some("rt1")
        );
        assert_eq!(interfaces.get("eth0").unwrap().routing_table, None);
    }

    #[tokio::test]
    async fn build_from_config_maps_each_interface() {
        let iface_addr = InterfaceAddress {
            address: "10.0.0.1/24".parse().unwrap(),
            label: None,
        };
        let mut iface = interface("eth0");
        iface.subinterfaces = vec![nos_proto::Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            tag: 0,
            addresses: vec![iface_addr.clone()],
            routing_table: Some("rt1".to_string()),
            ospf_profile: None,
            ospfv3_profile: None,
            bfd_unsolicited: None,
        }];
        let interfaces =
            build_from_config(&cfg(vec![iface]), &NoopInterfaceDriver, &Interfaces::new()).await;
        let iface = interfaces.get("eth0").unwrap();
        assert_eq!(iface.subinterfaces.len(), 1);
        assert_eq!(iface.subinterfaces[0].tag, 0);
        assert_eq!(iface.subinterfaces[0].addresses, vec![iface_addr]);
        assert_eq!(iface.subinterfaces[0].routing_table.as_deref(), Some("rt1"));
    }

    #[tokio::test]
    async fn build_from_config_maps_tagged_subinterface_untouched() {
        let mut iface = interface("eth0");
        iface.subinterfaces = vec![nos_proto::Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            tag: 300,
            addresses: Vec::new(),
            routing_table: Some("rt1".to_string()),
            ospf_profile: None,
            ospfv3_profile: None,
            bfd_unsolicited: None,
        }];
        let interfaces =
            build_from_config(&cfg(vec![iface]), &NoopInterfaceDriver, &Interfaces::new()).await;
        let iface = interfaces.get("eth0").unwrap();
        assert_eq!(iface.subinterfaces.len(), 1);
        assert_eq!(iface.subinterfaces[0].tag, 300);
        assert_eq!(iface.subinterfaces[0].routing_table.as_deref(), Some("rt1"));
    }

    #[tokio::test]
    async fn get_missing_interface_is_none() {
        let interfaces =
            build_from_config(&cfg(vec![]), &NoopInterfaceDriver, &Interfaces::new()).await;
        assert!(interfaces.get("eth0").is_none());
    }

    #[tokio::test]
    async fn all_is_sorted_by_name() {
        let interfaces = build_from_config(
            &cfg(vec![interface("eth1"), interface("eth0")]),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;
        let all = interfaces.all();
        let names: Vec<&str> = all.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["eth0", "eth1"]);
    }

    #[tokio::test]
    async fn apply_is_called_for_every_configured_interface() {
        let driver = RecordingDriver::default();
        build_from_config(
            &cfg(vec![interface("eth0"), interface("eth1")]),
            &driver,
            &Interfaces::new(),
        )
        .await;
        let calls = driver.calls.lock().unwrap().clone();
        assert!(calls.contains(&Call::Apply("eth0".to_string())));
        assert!(calls.contains(&Call::Apply("eth1".to_string())));
    }

    #[tokio::test]
    async fn remove_is_called_for_interface_dropped_from_config() {
        let driver = RecordingDriver::default();
        let previous = build_from_config(
            &cfg(vec![interface("eth0"), interface("eth1")]),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;

        build_from_config(&cfg(vec![interface("eth0")]), &driver, &previous).await;

        let calls = driver.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                Call::Apply("eth0".to_string()),
                Call::Remove("eth1".to_string())
            ]
        );
    }

    #[tokio::test]
    async fn switching_profile_resolves_to_member_list() {
        let mut iface = interface("eth0");
        iface.switching_profile = Some("sp1".to_string());
        let mut config = cfg(vec![iface]);
        config.switching_profiles = vec![nos_proto::SwitchingProfile {
            name: "sp1".to_string(),
            members: vec![nos_proto::SwitchingProfileMember {
                broadcast_domain: "bd1".to_string(),
                tag: VlanTag::Dot1q(100),
                ..Default::default()
            }],
        }];
        let interfaces = build_from_config(&config, &NoopInterfaceDriver, &Interfaces::new()).await;
        let iface = interfaces.get("eth0").unwrap();
        assert_eq!(
            iface.switching_profile_members,
            vec![("bd1".to_string(), VlanTag::Dot1q(100))]
        );
    }

    #[tokio::test]
    async fn unset_switching_profile_resolves_to_empty_members() {
        let interfaces = build_from_config(
            &cfg(vec![interface("eth0")]),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;
        assert_eq!(
            interfaces.get("eth0").unwrap().switching_profile_members,
            [] as [(std::string::String, nos_proto::VlanTag); 0]
        );
    }

    #[tokio::test]
    async fn ensure_broadcast_domain_is_called_for_every_configured_domain() {
        let driver = RecordingDriver::default();
        let mut config = cfg(vec![]);
        config.broadcast_domains = vec![
            nos_proto::BroadcastDomain {
                name: "bd1".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: None,
                ospfv3_profile: None,
                vni: None,
                rd: None,
                route_targets_import: Vec::new(),
                route_targets_export: Vec::new(),
                vtep_source: None,
                mac_redistribute: None,
                arp_redistribute: None,
                connected_redistribute: None,
                neigh_suppress: false,
                max_remote_macs: None,
                ..Default::default()
            },
            nos_proto::BroadcastDomain {
                name: "bd2".to_string(),
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: None,
                ospfv3_profile: None,
                vni: None,
                rd: None,
                route_targets_import: Vec::new(),
                route_targets_export: Vec::new(),
                vtep_source: None,
                mac_redistribute: None,
                arp_redistribute: None,
                connected_redistribute: None,
                neigh_suppress: false,
                max_remote_macs: None,
                ..Default::default()
            },
        ];
        build_from_config(&config, &driver, &Interfaces::new()).await;
        let calls = driver.calls.lock().unwrap().clone();
        assert!(calls
            .iter()
            .any(|c| matches!(c, Call::EnsureDomain(d) if d.name == "bd1")));
        assert!(calls
            .iter()
            .any(|c| matches!(c, Call::EnsureDomain(d) if d.name == "bd2")));
    }

    #[tokio::test]
    async fn broadcast_domain_addresses_and_routing_table_are_threaded_through() {
        let driver = RecordingDriver::default();
        let mut config = cfg(vec![]);
        let addr = InterfaceAddress {
            address: "10.0.0.1/24".parse().unwrap(),
            label: None,
        };
        config.broadcast_domains = vec![nos_proto::BroadcastDomain {
            name: "bd1".to_string(),
            addresses: vec![addr.clone()],
            routing_table: Some("rt1".to_string()),
            ospf_profile: None,
            ospfv3_profile: None,
            vni: None,
            rd: None,
            route_targets_import: Vec::new(),
            route_targets_export: Vec::new(),
            vtep_source: None,
            mac_redistribute: None,
            arp_redistribute: None,
            connected_redistribute: None,
            neigh_suppress: false,
            max_remote_macs: None,
            ..Default::default()
        }];
        build_from_config(&config, &driver, &Interfaces::new()).await;
        let calls = driver.calls.lock().unwrap().clone();
        assert!(calls.contains(&Call::EnsureDomain(BroadcastDomainState {
            name: "bd1".to_string(),
            addresses: vec![addr],
            routing_table: Some("rt1".to_string()),
            bridge_name: None,
            link_local_address: None,
        })));
    }

    #[tokio::test]
    async fn get_domain_returns_configured_domain() {
        let mut config = cfg(vec![]);
        let addr = InterfaceAddress {
            address: "10.0.0.1/24".parse().unwrap(),
            label: None,
        };
        config.broadcast_domains = vec![nos_proto::BroadcastDomain {
            name: "bd1".to_string(),
            addresses: vec![addr.clone()],
            routing_table: Some("rt1".to_string()),
            ospf_profile: None,
            ospfv3_profile: None,
            vni: None,
            rd: None,
            route_targets_import: Vec::new(),
            route_targets_export: Vec::new(),
            vtep_source: None,
            mac_redistribute: None,
            arp_redistribute: None,
            connected_redistribute: None,
            neigh_suppress: false,
            max_remote_macs: None,
            ..Default::default()
        }];
        let interfaces = build_from_config(&config, &NoopInterfaceDriver, &Interfaces::new()).await;
        let domain = interfaces.get_domain("bd1").unwrap();
        assert_eq!(domain.addresses, vec![addr]);
        assert_eq!(domain.routing_table.as_deref(), Some("rt1"));
    }

    #[tokio::test]
    async fn get_domain_missing_domain_is_none() {
        let interfaces =
            build_from_config(&cfg(vec![]), &NoopInterfaceDriver, &Interfaces::new()).await;
        assert!(interfaces.get_domain("bd1").is_none());
    }

    #[tokio::test]
    async fn remove_broadcast_domain_is_called_for_domain_dropped_from_config() {
        let driver = RecordingDriver::default();
        let mut config_with_domain = cfg(vec![]);
        config_with_domain.broadcast_domains = vec![nos_proto::BroadcastDomain {
            name: "bd1".to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: None,
            vni: None,
            rd: None,
            route_targets_import: Vec::new(),
            route_targets_export: Vec::new(),
            vtep_source: None,
            mac_redistribute: None,
            arp_redistribute: None,
            connected_redistribute: None,
            neigh_suppress: false,
            max_remote_macs: None,
            ..Default::default()
        }];
        let previous = build_from_config(&config_with_domain, &driver, &Interfaces::new()).await;

        build_from_config(&cfg(vec![]), &driver, &previous).await;

        let calls = driver.calls.lock().unwrap().clone();
        assert!(calls.contains(&Call::RemoveDomain("bd1".to_string())));
    }

    fn aggregate(name: &str) -> nos_proto::PortAggregate {
        nos_proto::PortAggregate {
            name: name.to_string(),
            mode: nos_proto::PortAggregateMode::Xor,
            lacp_rate: nos_proto::LacpRate::default(),
            esi: None,
            redundancy_mode: nos_proto::EsRedundancy::default(),
            df_algorithm: nos_proto::DfAlgorithm::default(),
            lacp_system_id: None,
            lacp_system_priority: None,
            lacp_version: nos_proto::LacpVersion::default(),
            lacp_port_algorithm: nos_proto::LacpPortAlgorithm::default(),
            lacp_conversation_map: Vec::new(),
            min_links: 1,
            bfd: None,
            bfd_peer: None,
            switching_profile: None,
            mtu: None,
            subinterfaces: Vec::new(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn ensure_port_aggregate_is_called_for_every_configured_aggregate() {
        let driver = RecordingDriver::default();
        let mut config = cfg(vec![]);
        config.port_aggregates = vec![aggregate("bond1")];
        build_from_config(&config, &driver, &Interfaces::new()).await;
        let calls = driver.calls.lock().unwrap().clone();
        assert!(calls
            .iter()
            .any(|c| matches!(c, Call::EnsurePortAggregate(a) if a.name == "bond1")));
    }

    #[tokio::test]
    async fn get_port_aggregate_returns_configured_aggregate() {
        let mut config = cfg(vec![]);
        config.port_aggregates = vec![aggregate("bond1")];
        let interfaces = build_from_config(&config, &NoopInterfaceDriver, &Interfaces::new()).await;
        let agg = interfaces.get_port_aggregate("bond1").unwrap();
        assert_eq!(agg.mode, nos_proto::PortAggregateMode::Xor);
    }

    #[tokio::test]
    async fn remove_port_aggregate_is_called_for_aggregate_dropped_from_config() {
        let driver = RecordingDriver::default();
        let mut config_with_aggregate = cfg(vec![]);
        config_with_aggregate.port_aggregates = vec![aggregate("bond1")];
        let previous = build_from_config(&config_with_aggregate, &driver, &Interfaces::new()).await;

        build_from_config(&cfg(vec![]), &driver, &previous).await;

        let calls = driver.calls.lock().unwrap().clone();
        assert!(calls.contains(&Call::RemovePortAggregate("bond1".to_string())));
    }

    #[tokio::test]
    async fn interface_port_aggregate_is_threaded_through() {
        let mut iface = interface("eth0");
        iface.port_aggregate = Some("bond1".to_string());
        let interfaces =
            build_from_config(&cfg(vec![iface]), &NoopInterfaceDriver, &Interfaces::new()).await;
        assert_eq!(
            interfaces.get("eth0").unwrap().port_aggregate.as_deref(),
            Some("bond1")
        );
    }

    fn cfg_with_aggregate(mode: PortAggregateMode, member: Interface) -> Config {
        let mut config = cfg(vec![member]);
        config.port_aggregates = vec![nos_proto::PortAggregate {
            name: "bond1".to_string(),
            mode,
            lacp_rate: nos_proto::LacpRate::default(),
            esi: None,
            redundancy_mode: nos_proto::EsRedundancy::default(),
            df_algorithm: nos_proto::DfAlgorithm::default(),
            lacp_system_id: None,
            lacp_system_priority: None,
            lacp_version: nos_proto::LacpVersion::default(),
            lacp_port_algorithm: nos_proto::LacpPortAlgorithm::default(),
            lacp_conversation_map: Vec::new(),
            min_links: 1,
            bfd: None,
            bfd_peer: None,
            switching_profile: None,
            mtu: None,
            subinterfaces: Vec::new(),
            ..Default::default()
        }];
        config
    }

    #[tokio::test]
    async fn xor_mode_member_is_active_unconditionally() {
        let mut iface = interface("eth0");
        iface.port_aggregate = Some("bond1".to_string());
        let interfaces = build_from_config(
            &cfg_with_aggregate(PortAggregateMode::Xor, iface),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;
        assert!(interfaces.get("eth0").unwrap().port_aggregate_active);
    }

    #[tokio::test]
    async fn lacp_mode_member_is_inactive_until_pushed() {
        let mut iface = interface("eth0");
        iface.port_aggregate = Some("bond1".to_string());
        let interfaces = build_from_config(
            &cfg_with_aggregate(PortAggregateMode::Lacp, iface),
            &NoopInterfaceDriver,
            &Interfaces::new(),
        )
        .await;
        assert!(!interfaces.get("eth0").unwrap().port_aggregate_active);
    }

    #[tokio::test]
    async fn set_lacp_active_members_activates_pushed_interface() {
        let mut iface = interface("eth0");
        iface.port_aggregate = Some("bond1".to_string());
        let config = cfg_with_aggregate(PortAggregateMode::Lacp, iface);
        let mut interfaces =
            build_from_config(&config, &NoopInterfaceDriver, &Interfaces::new()).await;

        let updated = interfaces.set_lacp_active_members("bond1", vec!["eth0".to_string()]);

        assert_eq!(updated.len(), 1);
        assert!(updated[0].port_aggregate_active);
        assert!(interfaces.get("eth0").unwrap().port_aggregate_active);
    }

    #[tokio::test]
    async fn lacp_active_members_survive_an_unrelated_resync() {
        let mut iface = interface("eth0");
        iface.port_aggregate = Some("bond1".to_string());
        let config = cfg_with_aggregate(PortAggregateMode::Lacp, iface);
        let mut previous =
            build_from_config(&config, &NoopInterfaceDriver, &Interfaces::new()).await;
        previous.set_lacp_active_members("bond1", vec!["eth0".to_string()]);

        let interfaces = build_from_config(&config, &NoopInterfaceDriver, &previous).await;

        assert!(interfaces.get("eth0").unwrap().port_aggregate_active);
    }

    fn bfd_config(mode: PortAggregateMode) -> Config {
        let mut iface = interface("eth0");
        iface.port_aggregate = Some("bond1".to_string());
        let mut config = cfg_with_aggregate(mode, iface);
        config.port_aggregates[0].bfd = Some("fast".to_string());
        config
    }

    #[test]
    fn member_active_truth_table() {
        let set = |v: &[&str]| {
            HashMap::from([("b".to_string(), v.iter().map(ToString::to_string).collect())])
        };
        let none = HashMap::new();
        let (xor, lacp) = (PortAggregateMode::Xor, PortAggregateMode::Lacp);
        let m = |mode, bfd, l: &HashMap<_, _>, b: &HashMap<_, _>| {
            member_active(mode, bfd, l, b, "b", "e")
        };
        // no bfd: today's rule
        assert!(m(xor, false, &none, &none));
        assert!(!m(lacp, false, &none, &none));
        assert!(m(lacp, false, &set(&["e"]), &none));
        // bfd up / down / no push
        assert!(m(xor, true, &none, &set(&["e"])));
        assert!(!m(xor, true, &none, &set(&["x"])));
        assert!(!m(xor, true, &none, &none));
        // both must hold
        assert!(m(lacp, true, &set(&["e"]), &set(&["e"])));
        assert!(!m(lacp, true, &set(&["e"]), &none));
        assert!(!m(lacp, true, &none, &set(&["e"])));
    }

    #[tokio::test]
    async fn bfd_member_waits_for_push_and_survives_resync() {
        let config = bfd_config(PortAggregateMode::Xor);
        let mut interfaces =
            build_from_config(&config, &NoopInterfaceDriver, &Interfaces::new()).await;
        assert!(!interfaces.get("eth0").unwrap().port_aggregate_active);

        let updated = interfaces.set_bfd_up_members("bond1", vec!["eth0".to_string()]);
        assert!(updated[0].port_aggregate_active);

        let interfaces = build_from_config(&config, &NoopInterfaceDriver, &interfaces).await;
        assert!(interfaces.get("eth0").unwrap().port_aggregate_active);
    }

    #[tokio::test]
    async fn setters_recompute_from_both_sets() {
        let config = bfd_config(PortAggregateMode::Lacp);
        let mut interfaces =
            build_from_config(&config, &NoopInterfaceDriver, &Interfaces::new()).await;
        interfaces.set_bfd_up_members("bond1", vec!["eth0".to_string()]);
        assert!(!interfaces.get("eth0").unwrap().port_aggregate_active);
        interfaces.set_lacp_active_members("bond1", vec!["eth0".to_string()]);
        assert!(interfaces.get("eth0").unwrap().port_aggregate_active);
        interfaces.set_bfd_up_members("bond1", Vec::new());
        assert!(!interfaces.get("eth0").unwrap().port_aggregate_active);
    }
    /// `eth0` trunked untagged into `bd1`, plus `bond1` carrying `bd1` tagged.
    fn stp_config(mode: StpMode) -> Config {
        let mut eth0 = interface("eth0");
        eth0.switching_profile = Some("sp1".to_string());
        let mut config = cfg(vec![eth0]);
        config.spanning_tree.mode = mode;
        config.switching_profiles = vec![nos_proto::SwitchingProfile {
            name: "sp1".to_string(),
            members: vec![nos_proto::SwitchingProfileMember {
                broadcast_domain: "bd1".to_string(),
                tag: VlanTag::Untagged,
                ..Default::default()
            }],
        }];
        config
    }

    fn assignment(port: &str, domain: &str, state: StpPortState) -> StpPortAssignment {
        StpPortAssignment {
            port: port.to_string(),
            domain: domain.to_string(),
            state,
        }
    }

    #[tokio::test]
    async fn the_failsafe_applies_exactly_when_the_mode_is_not_disabled() {
        for (mode, on) in [
            (StpMode::Rstp, true),
            (StpMode::Mstp, true),
            (StpMode::RapidPvst, true),
            (StpMode::Disabled, false),
        ] {
            let interfaces =
                build_from_config(&stp_config(mode), &NoopInterfaceDriver, &Interfaces::new())
                    .await;
            assert_eq!(interfaces.get("eth0").unwrap().stp.on, on, "{mode:?}");
            assert_eq!(interfaces.stp_on(), on, "{mode:?}");
        }
        // The #317 default is rstp: an untouched config blocks new ports.
        let default = Config::default();
        assert_eq!(default.spanning_tree.mode, StpMode::Rstp);
    }

    #[tokio::test]
    async fn err_disabled_survives_a_resync_until_lifted() {
        let config = stp_config(StpMode::Rstp);
        let mut interfaces =
            build_from_config(&config, &NoopInterfaceDriver, &Interfaces::new()).await;
        let (iface, agg) = interfaces.set_err_disabled("eth0", true);
        assert!(iface.unwrap().stp.err_disabled && agg.is_none());
        assert_eq!(interfaces.set_err_disabled("nope", true), (None, None));
        let mut interfaces = build_from_config(&config, &NoopInterfaceDriver, &interfaces).await;
        assert!(interfaces.get("eth0").unwrap().stp.err_disabled);
        interfaces.set_err_disabled("eth0", false);
        let mut interfaces = build_from_config(&config, &NoopInterfaceDriver, &interfaces).await;
        assert!(!interfaces.get("eth0").unwrap().stp.err_disabled);
        // A resync that raced a push adopts the live set and re-applies.
        let live: HashSet<String> = ["eth0".to_string()].into();
        let (ifaces, aggs) = interfaces.adopt_err_disabled(&live);
        assert_eq!(ifaces.len(), 1);
        assert!(ifaces[0].stp.err_disabled && aggs.is_empty());
        let (again, _) = interfaces.adopt_err_disabled(&live);
        assert_eq!(again.len(), 0);
    }

    #[tokio::test]
    async fn a_pushed_port_state_survives_a_resync_and_is_written_only_while_on() {
        let config = stp_config(StpMode::Rstp);
        let mut interfaces =
            build_from_config(&config, &NoopInterfaceDriver, &Interfaces::new()).await;
        assert!(interfaces.get("eth0").unwrap().stp.states.is_empty());

        let writes = interfaces.set_stp_port_states(vec![
            assignment("eth0", "bd1", StpPortState::Forwarding),
            // not a member of bd2, and unknown port: remembered, never written
            assignment("eth0", "bd2", StpPortState::Learning),
            assignment("nope", "bd1", StpPortState::Learning),
        ]);
        assert_eq!(
            writes,
            vec![(
                BridgePortRef {
                    name: "eth0".to_string(),
                    aggregate: false,
                    tag: VlanTag::Untagged
                },
                StpPortState::Forwarding
            )]
        );

        let interfaces = build_from_config(&config, &NoopInterfaceDriver, &interfaces).await;
        assert_eq!(
            interfaces.get("eth0").unwrap().stp.states.get("bd1"),
            Some(&StpPortState::Forwarding)
        );

        // Off: the push is remembered but nothing is written.
        let off = stp_config(StpMode::Disabled);
        let mut interfaces = build_from_config(&off, &NoopInterfaceDriver, &interfaces).await;
        let writes =
            interfaces.set_stp_port_states(vec![assignment("eth0", "bd1", StpPortState::Blocking)]);
        assert_eq!(writes, Vec::new());
    }
}
