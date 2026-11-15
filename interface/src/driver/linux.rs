use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{DefaultNla, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
use nos_proto::{
    loopback_table_name, InterfaceAddress, IpNet, PortAggregateMode, ServiceRef, StpPortState,
    VlanTag,
};
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage, AddressScope};
use rtnetlink::packet_route::link::{
    BondMode, InfoBridgePort, InfoKind, InfoPortData, InfoPortKind, LinkAttribute, LinkFlags,
    LinkInfo, LinkMessage, LinkProtoInfoBridge,
};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{Handle, LinkBond, LinkBridge, LinkDummy, LinkUnspec, LinkVlan, MulticastGroup};
use tracing::{debug, info, trace, warn};

use nos_tc::{Action, ActionKind, Filter, FlowerKeys, Hook, Kind, Protocol, Request, Verdict};

use super::links::{self, Delta, LinkHub};
use super::{
    bridge_registry, port_aggregate_registry, rib_client, BridgePortRef, DriverError,
    InterfaceDriver, LinkWatch, Lookup, DEFAULT_MTU,
};
use crate::state::{
    BroadcastDomainState, InterfaceState, PortAggregateState, StpPorts, SubinterfaceState,
};
use nos_daemon::watchdog;

/// Both `Xor` and `Lacp` create the kernel bond in the same
/// `BalanceXor` mode — **never** `BondMode::Ieee8023Ad`. The kernel's own
/// 802.3ad bonding mode intercepts slow-protocol (ethertype `0x8809`)
/// frames on every slave via its own `rx_handler` before userspace ever
/// sees them, which would silently starve `nos-lacpd`'s raw `AF_PACKET`
/// sockets of every LACPDU it needs to run its own real negotiation. The
/// `PortAggregateMode` distinction only changes which control plane
/// decides which members are actually enslaved (unconditionally here vs.
/// gated on `nos-lacpd`'s push, see `InterfaceState.port_aggregate_active`)
/// — never the kernel driver's own bonding algorithm.
fn bond_mode_of(mode: PortAggregateMode) -> BondMode {
    match mode {
        PortAggregateMode::Xor | PortAggregateMode::Lacp => BondMode::BalanceXor,
    }
}

/// errno(3) `ENODEV` — the kernel's reply to a targeted `RTM_GETLINK`
/// lookup (`match_name`/`match_index`) for a link that doesn't exist.
const ENODEV: i32 = 19;
const ENOENT: i32 = 2;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
/// Writing a bridge port's state while its device is down.
const ENETDOWN: i32 = 100;
/// Deleting a filter that isn't there: `ENOENT`, or `EINVAL` when the device
/// has no filter chain at all yet.
const NO_FILTER: &[i32] = &[ENOENT, EINVAL, ENODEV];

/// The STP BPDU trap (`docs/internals/stp.md`): a `BR_NO_STP` bridge floods
/// the BPDU group MAC, so every bridge port gets an ingress `flower dst_mac
/// <group> action drop` at this one priority. The drop happens after the
/// `ETH_P_ALL` packet tap, so `nos-stpd` still sees every BPDU.
const TRAP_PRIO: u16 = 1;
/// Every trapped destination with its filter handle: the IEEE 802.1D/Q BPDU
/// group address (STP, RSTP, MSTP), then Cisco's SSTP (per-VLAN STP).
const TRAPPED: [(u32, [u8; 6]); 2] = [
    (1, [0x01, 0x80, 0xc2, 0, 0, 0]),
    (2, [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd]),
];
/// Protocol 802.2: every BPDU (IEEE or SSTP) is an 802.3 frame with an LLC
/// header, and a frame carrying a VLAN tag reads as `ETH_P_8021Q` to the
/// classifier, so the trap never drops the tagged SSTP of a trunk's
/// sub-links on their parent port (#322); the sub-link itself sees the tag
/// already removed.
const TRAP_PROTOCOL: Protocol = Protocol::Llc802_2;

/// `flower dst_mac <dst_mac> action drop` (exact, no mask) on `ifindex`'s
/// ingress.
fn bpdu_trap(ifindex: u32, handle: u32, dst_mac: [u8; 6]) -> Request {
    Request::AddFilter(Filter {
        ifindex,
        hook: Hook::Ingress,
        chain: 0,
        prio: TRAP_PRIO,
        protocol: TRAP_PROTOCOL,
        handle,
        kind: Kind::Flower(FlowerKeys {
            eth_dst: Some((dst_mac, None)),
            ..FlowerKeys::default()
        }),
        actions: vec![Action::new(ActionKind::Gact(Verdict::Shot))],
        replace: false,
    })
}

/// `IFLA_BRPORT_STATE` / `IFLA_BRPORT_FLUSH`, sent as raw attributes.
const IFLA_BRPORT_STATE: u16 = 1;
const IFLA_BRPORT_FLUSH: u16 = 24;
const BR_STATE_DISABLED: u8 = 0;
const BR_STATE_LEARNING: u8 = 2;
const BR_STATE_FORWARDING: u8 = 3;

/// The kernel state `state` is written as. **Blocking is written as DISABLED**:
/// on a `BR_NO_STP` bridge the kernel's `br_port_state_selection` turns a
/// BLOCKING port straight back into FORWARDING (every port is designated), but
/// leaves DISABLED ones alone — a disabled port neither learns nor forwards,
/// the same data plane as blocking, and `ETH_P_ALL` taps still see its frames
/// (`docs/internals/stp.md`).
fn kernel_state(state: StpPortState) -> u8 {
    match state {
        StpPortState::Blocking => BR_STATE_DISABLED,
        StpPortState::Learning => BR_STATE_LEARNING,
        StpPortState::Forwarding => BR_STATE_FORWARDING,
    }
}

/// The `IFLA_BRPORT_STATE` the link dump carries, if it is a bridge port.
fn observed_port_state(link: &LinkMessage) -> Option<u8> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::LinkInfo(infos) => infos.iter().find_map(|i| match i {
            LinkInfo::PortData(InfoPortData::BridgePort(ports)) => {
                ports.iter().find_map(|p| match p {
                    InfoBridgePort::State(s) => Some(u8::from(*s)),
                    _ => None,
                })
            }
            _ => None,
        }),
        _ => None,
    })
}

/// Whether `link` is a port spanning tree may touch: enslaved to a bridge, and
/// never a VXLAN device — the VTEP of a VNI domain belongs to `nos-fdbd`.
fn is_stp_port(link: &LinkMessage) -> bool {
    let infos = link.attributes.iter().find_map(|a| match a {
        LinkAttribute::LinkInfo(infos) => Some(infos),
        _ => None,
    });
    infos.is_some_and(|infos| {
        infos
            .iter()
            .any(|i| matches!(i, LinkInfo::PortKind(InfoPortKind::Bridge)))
            && !infos
                .iter()
                .any(|i| matches!(i, LinkInfo::Kind(InfoKind::Vxlan)))
    })
}

/// The `<link>` or `<link>.<tag>` name `port` has in the kernel, given its
/// parent link's name.
fn port_link_name(parent: &str, tag: VlanTag) -> String {
    match tag {
        VlanTag::Untagged => parent.to_string(),
        VlanTag::Dot1q(id) => format!("{parent}.{id}"),
    }
}

/// What this process has done to the kernel for spanning tree, by ifindex —
/// the only ports it may undo when spanning tree goes off (`nos-fdbd` also
/// disables ports, for single-active segments, and must not be fought).
#[derive(Default)]
struct StpMemory {
    /// Ports with the BPDU trap installed.
    trapped: HashSet<u32>,
    /// Ports this driver wrote a non-forwarding state to.
    held: HashSet<u32>,
}

impl<T> Lookup<T> {
    fn map<U>(self, f: impl FnOnce(T) -> U) -> Lookup<U> {
        match self {
            Lookup::Found(v) => Lookup::Found(f(v)),
            Lookup::NotConfigured => Lookup::NotConfigured,
            Lookup::Unknown => Lookup::Unknown,
        }
    }
}

/// The one master a physical link gets, by precedence VRF > bond > bridge.
/// A higher-precedence `Unknown` is returned as is, never falling through to
/// a lower master: that would enslave the link to the wrong one or
/// un-enslave it (#615).
fn pick_master(
    vrf: Lookup<String>,
    bond: Lookup<String>,
    bridge: Lookup<String>,
) -> (Lookup<String>, MasterKind) {
    match (vrf, bond) {
        (Lookup::NotConfigured, Lookup::NotConfigured) => (bridge, MasterKind::Bridge),
        (Lookup::NotConfigured, bond) => (bond, MasterKind::Bond),
        (vrf, _) => (vrf, MasterKind::Vrf),
    }
}

/// Which kind of thing `reconcile_master` is enslaving a link into — picks
/// only the log wording, see its doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MasterKind {
    Vrf,
    Bridge,
    /// A `PortAggregate`'s bond device — enslavement is the same generic
    /// `IFLA_MASTER` operation as `Vrf`/`Bridge`, just a different kind of
    /// master link.
    Bond,
}

/// What a tag>0 `<interface>.<tag>` sub-link should be enslaved to — an L2
/// switching-profile `Dot1q` member (`Bridge`) or an L3 `Subinterface`
/// (`Vrf`). Commit-time validation
/// (`valid_subinterface_and_switching_profile_tags`) guarantees a given tag
/// is claimed by at most one of the two, so `reconcile_tagged_subinterfaces`
/// never has to choose between them for the same tag.
enum TaggedMaster {
    /// A domain name, resolved to its bridge the same way as an `Untagged`
    /// member on the physical link itself.
    Bridge(String),
    /// A routing table name (VRF assignment) and this subinterface's own
    /// addresses. `routing_table: None` still creates/addresses the
    /// sub-link, just with no master enslavement — mirrors the physical
    /// link's own "addresses with no VRF" case.
    Vrf {
        routing_table: Option<String>,
        addresses: Vec<InterfaceAddress>,
        /// Per-subinterface MTU override; `None` follows the parent.
        mtu: Option<u32>,
    },
}

/// A sub-link's wanted MTU: its override, else the parent's wanted MTU
/// (`None` for a bond member with no `mtu`, which is left alone).
fn sub_link_mtu(over: Option<u32>, parent: Option<u32>) -> Option<u32> {
    over.or(parent)
}

/// Kernel device name for a loopback interface's routing table, mirroring
/// `nos-ribd`'s `vrf<table_id>` VRF naming — the loopback's own config name
/// (`loopback-<table>`) is never used as the kernel name, same reasoning.
fn loopback_ifname(table_id: u32) -> String {
    format!("lo{table_id}")
}

/// Extracts a link's kernel interface name, if it has one (every real link
/// does; this is just the `Option` `find_map` requires).
fn link_name(link: &LinkMessage) -> Option<&str> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::IfName(name) => Some(name.as_str()),
        _ => None,
    })
}

/// The MTU to set on `link` so it has `want`, or `None` if it already does
/// (so the set, and its log line, happen only on a real change).
fn mtu_change(link: &LinkMessage, want: u32) -> Option<u32> {
    let current = link.attributes.iter().find_map(|a| match a {
        LinkAttribute::Mtu(mtu) => Some(*mtu),
        _ => None,
    });
    (current != Some(want)).then_some(want)
}

/// Real `rtnetlink`-backed driver. `nos-interfaced` never creates ordinary
/// interfaces (see `CLAUDE.md`'s scope section) — every operation here
/// configures an interface that must already exist in the netns. The one
/// deliberate, narrow exception is a loopback interface (an `Interface`
/// named `loopback-<table>`, see `nos_proto::loopback_table_name`): its
/// kernel device (a `dummy` link named `lo<table_id>`, since Linux only
/// ever has one real `lo` per netns) is created and destroyed by this
/// driver.
pub struct LinuxInterfaceDriver {
    /// Kernel link table fed by `run_link_watcher`.
    links: Arc<LinkHub>,
    handle: Handle,
    watchdog_socket: PathBuf,
    /// This driver's own private persisted domain-name -> bridge-id map —
    /// see `bridge_registry` module docs. Never read by any other process.
    bridge_registry_path: PathBuf,
    /// This driver's own private persisted aggregate-name -> bond-id map —
    /// see `port_aggregate_registry` module docs. Never read by any other
    /// process.
    port_aggregate_registry_path: PathBuf,
    stp: Mutex<StpMemory>,
}

impl LinuxInterfaceDriver {
    pub fn new(
        watchdog_socket: PathBuf,
        bridge_registry_path: PathBuf,
        port_aggregate_registry_path: PathBuf,
    ) -> Result<Self, DriverError> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        nos_log_client::spawn_critical("rtnetlink-connection", connection);
        let links = Arc::new(LinkHub::new(links::HUB_CAPACITY));
        tokio::spawn(run_link_watcher(links.clone()));
        Ok(Self {
            links,
            handle,
            watchdog_socket,
            bridge_registry_path,
            port_aggregate_registry_path,
            stp: Mutex::new(StpMemory::default()),
        })
    }

    /// One `RTM_SETLINK` in the `AF_BRIDGE` family carrying `attr` under
    /// `IFLA_PROTINFO` (`bridge link set dev <port> state ..`). Not the
    /// `RTM_NEWLINK` slave-data path: that one accepts `IFLA_BRPORT_STATE` and
    /// silently ignores DISABLED (same finding as `nos-fdbd`'s
    /// `set_port_forwarding`).
    async fn set_port_attr(&self, index: u32, attr: DefaultNla) -> Result<(), DriverError> {
        let mut msg = LinkMessage::default();
        msg.header.interface_family = AddressFamily::Bridge;
        msg.header.index = index;
        msg.attributes.push(LinkAttribute::ProtoInfoBridge(vec![
            LinkProtoInfoBridge::Other(attr),
        ]));
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::SetLink(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut response = self.handle.clone().request(req)?;
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload
                && e.raw_code() != 0
            {
                return Err(rtnetlink::Error::NetlinkError(e).into());
            }
        }
        Ok(())
    }

    async fn tc(&self, req: Request, tolerate: &'static [i32]) -> Result<(), DriverError> {
        tokio::task::spawn_blocking(move || nos_tc::send(&req, tolerate))
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
            .map_err(|e| DriverError::Other(format!("tc request failed: {e}")))
    }

    /// The kernel link of `port`, if it exists.
    async fn find_port_link(
        &self,
        port: &BridgePortRef,
    ) -> Result<Option<LinkMessage>, DriverError> {
        let parent = if port.aggregate {
            let Lookup::Found(id) = port_aggregate_registry::lookup_port_aggregate_id(
                &self.port_aggregate_registry_path,
                &port.name,
            ) else {
                return Ok(None);
            };
            port_aggregate_registry::port_aggregate_ifname(id)
        } else {
            port.name.clone()
        };
        self.find_link(&port_link_name(&parent, port.tag)).await
    }

    /// Writes `want` to the bridge port `link` unless it already is in that
    /// state. A down device refuses (`ENETDOWN`) but is already DISABLED, and
    /// the next resync after it comes up catches it.
    async fn write_port_state(
        &self,
        name: &str,
        link: &LinkMessage,
        want: StpPortState,
        failsafe: bool,
    ) -> Result<(), DriverError> {
        let index = link.header.index;
        let kernel = kernel_state(want);
        if observed_port_state(link) == Some(kernel) {
            return Ok(());
        }
        match self
            .set_port_attr(index, DefaultNla::new(IFLA_BRPORT_STATE, vec![kernel]))
            .await
        {
            Err(DriverError::Netlink(e)) if is_enetdown(&e) => {
                debug!(interface = %name, "bridge port is down, state left for the next resync");
                return Ok(());
            }
            r => r?,
        }
        {
            let mut mem = self.stp.lock().unwrap();
            if want == StpPortState::Forwarding {
                mem.held.remove(&index);
            } else {
                mem.held.insert(index);
            }
        }
        if failsafe {
            info!(interface = %name, "bridge port enslaved blocking");
        } else {
            info!(interface = %name, state = ?want, "bridge port state set");
        }
        Ok(())
    }

    /// Spanning tree's view of the link `name`: `domain` is the domain it
    /// should be a bridge port of, if any. While `stp.on`, installs the BPDU
    /// trap and writes the pushed state — Blocking until `nos-stpd` pushes
    /// one. Off, or not a bridge port, undoes only what this process did.
    async fn reconcile_stp_port(
        &self,
        name: &str,
        domain: Option<&str>,
        stp: &StpPorts,
    ) -> Result<(), DriverError> {
        let Some(link) = self.find_link(name).await? else {
            return Ok(());
        };
        let index = link.header.index;
        let Some(domain) = domain.filter(|_| is_stp_port(&link)) else {
            return self.stp_release(name, index).await;
        };
        if !stp.on {
            self.remove_trap(name, index).await?;
            let held = self.stp.lock().unwrap().held.contains(&index);
            if held && observed_port_state(&link) != Some(BR_STATE_FORWARDING) {
                self.set_port_attr(
                    index,
                    DefaultNla::new(IFLA_BRPORT_STATE, vec![BR_STATE_FORWARDING]),
                )
                .await?;
                info!(interface = %name, "bridge port forwarding restored");
            }
            self.stp.lock().unwrap().held.remove(&index);
            return Ok(());
        }
        // The trap first: no BPDU is flooded by a port we are about to open.
        self.install_trap(name, index).await?;
        let pushed = stp.states.get(domain).copied();
        self.write_port_state(
            name,
            &link,
            pushed.unwrap_or(StpPortState::Blocking),
            pushed.is_none(),
        )
        .await
    }

    /// `name` is not (or no longer) a bridge port: drop what was installed.
    async fn stp_release(&self, name: &str, index: u32) -> Result<(), DriverError> {
        self.stp.lock().unwrap().held.remove(&index);
        self.remove_trap(name, index).await
    }

    async fn install_trap(&self, name: &str, index: u32) -> Result<(), DriverError> {
        self.tc(Request::Clsact { ifindex: index }, &[EEXIST])
            .await?;
        for (handle, dst_mac) in TRAPPED {
            self.tc(bpdu_trap(index, handle, dst_mac), &[]).await?;
        }
        if self.stp.lock().unwrap().trapped.insert(index) {
            info!(interface = %name, "bpdu trap installed");
        }
        Ok(())
    }

    async fn remove_trap(&self, name: &str, index: u32) -> Result<(), DriverError> {
        if !self.stp.lock().unwrap().trapped.remove(&index) {
            return Ok(());
        }
        for (handle, _) in TRAPPED {
            let del = Request::DelFilter {
                ifindex: index,
                hook: Hook::Ingress,
                chain: 0,
                prio: TRAP_PRIO,
                protocol: TRAP_PROTOCOL,
                handle,
            };
            self.tc(del, NO_FILTER).await?;
        }
        info!(interface = %name, "bpdu trap removed");
        Ok(())
    }

    /// `.match_name()` performs a targeted (non-dump) `RTM_GETLINK`
    /// lookup — for a name that doesn't exist, the kernel replies with an
    /// `ENODEV` netlink error rather than an empty result, so that specific
    /// error must be translated back to `Ok(None)` here; any other error is
    /// a real failure and propagates.
    async fn find_link(&self, name: &str) -> Result<Option<LinkMessage>, DriverError> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match links.try_next().await {
            Ok(link) => Ok(link),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -ENODEV => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Resolves `table_name`'s Linux VRF interface name by asking the
    /// owning `nos-ribd` instance directly over IPC (see
    /// `super::rib_client`) — never derived locally, since allocation is
    /// entirely internal to that daemon's driver. `None` covers every
    /// "not answerable yet" case uniformly (broker doesn't know that
    /// table, connect failure, rib hasn't created a VRF yet): all
    /// expected, transient conditions, retried automatically by the
    /// caller's periodic re-apply tick.
    async fn resolve_vrf_name(&self, table_name: &str) -> Lookup<String> {
        let socket = watchdog::resolve_once(
            &self.watchdog_socket,
            &ServiceRef::RibTable(table_name.to_string()),
        )
        .await;
        let Some(socket) = socket else {
            debug!(table = %table_name, "routing table's nos-ribd instance not resolvable yet");
            return Lookup::Unknown;
        };
        if let Some(name) = rib_client::get_vrf_name(&socket).await {
            return Lookup::Found(name);
        }
        debug!(table = %table_name, "routing table's nos-ribd has no vrf allocated yet");
        Lookup::Unknown
    }

    /// `resolve_vrf_name` for an optional table: no table = `NotConfigured`.
    async fn vrf_lookup(&self, table_name: Option<&str>) -> Lookup<String> {
        match table_name {
            Some(t) => self.resolve_vrf_name(t).await,
            None => Lookup::NotConfigured,
        }
    }

    /// Resolves `table_name`'s allocated kernel table id, symmetric to
    /// `resolve_vrf_name` — same broker-resolve-then-query pattern, same
    /// "`None` is normal/transient" contract.
    async fn resolve_table_id(&self, table_name: &str) -> Option<u32> {
        let socket = watchdog::resolve_once(
            &self.watchdog_socket,
            &ServiceRef::RibTable(table_name.to_string()),
        )
        .await;
        let Some(socket) = socket else {
            debug!(table = %table_name, "routing table's nos-ribd instance not resolvable yet");
            return None;
        };
        let id = rib_client::get_table_id(&socket).await;
        if id.is_none() {
            debug!(table = %table_name, "routing table's nos-ribd has no table id allocated yet");
        }
        id
    }

    /// Ensures a `dummy` kernel device named `name` exists (creating it if
    /// missing) — the only place this driver ever creates a link, scoped
    /// strictly to loopback interfaces (see the struct doc comment).
    async fn ensure_loopback_link(&self, name: &str) -> Result<LinkMessage, DriverError> {
        if let Some(link) = self.find_link(name).await? {
            return Ok(link);
        }
        self.handle
            .link()
            .add(LinkDummy::new(name).build())
            .execute()
            .await?;
        info!(device = %name, "created loopback device");
        self.find_link(name)
            .await?
            .ok_or_else(|| DriverError::LoopbackNotFound(name.to_string()))
    }

    async fn reconcile_addresses(
        &self,
        interface: &str,
        index: u32,
        desired: &[InterfaceAddress],
    ) -> Result<(), DriverError> {
        // ponytail: label is stored in config but never applied to the
        // kernel (no `ip addr ... label` call) — upgrade when a consumer
        // needs it.
        let desired: Vec<IpNet> = desired.iter().map(|a| a.address).collect();
        let desired = &desired[..];
        let mut observed: Vec<(IpNet, AddressMessage)> = Vec::new();
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        while let Some(msg) = addrs.try_next().await? {
            // Never touch kernel-auto-assigned addresses (IPv6 link-local
            // and friends) — NOS only owns globally/host-scoped addresses
            // it put there itself.
            if msg.header.scope == AddressScope::Link {
                continue;
            }
            let Some(ip) = msg.attributes.iter().find_map(|a| match a {
                AddressAttribute::Address(ip) => Some(*ip),
                _ => None,
            }) else {
                continue;
            };
            let Ok(net) = IpNet::new(ip, msg.header.prefix_len) else {
                continue;
            };
            observed.push((net, msg));
        }

        let observed_keys: Vec<IpNet> = observed.iter().map(|(net, _)| *net).collect();
        let (to_add, to_remove) = diff_addresses(&observed_keys, desired);

        // Removes first: a prefix-length change on the same IPv6 address
        // ("add /48, remove /64") otherwise hits EEXIST on the add and the
        // remove never runs (#655). A failing op is logged and skipped, never
        // aborting the rest of the link's reconcile; the 10 s resync retries.
        for net in to_remove {
            if let Some((_, msg)) = observed.iter().find(|(o, _)| *o == net) {
                match self.handle.address().del(msg.clone()).execute().await {
                    Ok(()) => {
                        info!(interface = %interface, address = %net, "removed interface address");
                    }
                    Err(e) => {
                        warn!(interface = %interface, address = %net, error = %e, "failed to remove interface address");
                    }
                }
            }
        }
        for net in to_add {
            match self
                .handle
                .address()
                .add(index, net.addr(), net.prefix_len())
                .execute()
                .await
            {
                Ok(()) => info!(interface = %interface, address = %net, "added interface address"),
                Err(e) => {
                    warn!(interface = %interface, address = %net, error = %e, "failed to add interface address");
                }
            }
        }
        Ok(())
    }

    /// `master_ifname` is looked up purely by name — never by any numeric id
    /// — matching the correction to this plan: nos-interfaced is only ever
    /// told a master interface (VRF or broadcast-domain bridge) *name* over
    /// IPC or local lookup, and links to it by finding a kernel link with
    /// that exact name. Shared by both VRF enslavement (`apply`) and
    /// broadcast-domain bridge enslavement (`apply`'s untagged case,
    /// `reconcile_vlan_members`'s tagged sub-interfaces) — the underlying
    /// Linux operation (`IFLA_MASTER`) is identical either way. `kind`
    /// picks the log wording only (`"vrf"` preserves
    /// `tools/verify-bgp.sh`'s existing "enslaved interface to vrf" grep
    /// exactly; `"bridge"` is the new broadcast-domain case).
    async fn reconcile_master_lookup(
        &self,
        interface: &str,
        link: &LinkMessage,
        master: Lookup<String>,
        kind: MasterKind,
    ) -> Result<(), DriverError> {
        match master {
            Lookup::Unknown => {
                debug!(interface = %interface, kind = ?kind, "master unknown, leaving enslavement unchanged");
                Ok(())
            }
            Lookup::Found(name) => {
                self.reconcile_master(interface, link, Some(&name), kind)
                    .await
            }
            Lookup::NotConfigured => self.reconcile_master(interface, link, None, kind).await,
        }
    }

    async fn reconcile_master(
        &self,
        interface: &str,
        link: &LinkMessage,
        master_ifname: Option<&str>,
        kind: MasterKind,
    ) -> Result<(), DriverError> {
        let index = link.header.index;
        let current_master = link.attributes.iter().find_map(|a| match a {
            LinkAttribute::Controller(idx) => Some(*idx),
            _ => None,
        });

        let desired_master = match master_ifname {
            Some(name) => {
                let Some(master_link) = self.find_link(name).await? else {
                    // Expected/transient: the target VRF/bridge hasn't been
                    // created yet (or it was just torn down). Leave
                    // enslavement untouched; the periodic re-apply tick
                    // retries.
                    debug!(master = %name, "master interface not present yet, leaving enslavement unchanged");
                    return Ok(());
                };
                Some(master_link.header.index)
            }
            None => None,
        };

        match (current_master, desired_master) {
            (Some(current), Some(want)) if current == want => {}
            (None, None) => {}
            (_, Some(want)) => {
                if kind == MasterKind::Bond {
                    // Unlike bridge/VRF enslavement, Linux bonding refuses to
                    // enslave a link that's administratively up ("Device can
                    // not be enslaved while up") — bring it down first; the
                    // caller's own trailing `up` (apply's final
                    // LinkUnspec::up()) brings it back.
                    self.handle
                        .link()
                        .set(LinkUnspec::new_with_index(index).down().build())
                        .execute()
                        .await?;
                }
                self.handle
                    .link()
                    .set(LinkUnspec::new_with_index(index).controller(want).build())
                    .execute()
                    .await?;
                match kind {
                    MasterKind::Vrf => info!(
                        interface = %interface,
                        vrf = %master_ifname.unwrap_or_default(),
                        "enslaved interface to vrf"
                    ),
                    MasterKind::Bridge => info!(
                        interface = %interface,
                        bridge = %master_ifname.unwrap_or_default(),
                        "enslaved interface to bridge"
                    ),
                    MasterKind::Bond => info!(
                        interface = %interface,
                        bond = %master_ifname.unwrap_or_default(),
                        "enslaved interface to bond"
                    ),
                }
            }
            (Some(_), None) => {
                self.handle
                    .link()
                    .set(LinkUnspec::new_with_index(index).nocontroller().build())
                    .execute()
                    .await?;
                info!(interface = %interface, "removed interface from master enslavement");
            }
        }
        Ok(())
    }

    /// Reconciles `interface`'s tag>0 sub-interfaces — one per `Dot1q`
    /// switching-profile member (`TaggedMaster::Bridge`) or per `tag > 0`
    /// `Subinterface` (`TaggedMaster::Vrf`) — against `desired`, keyed by
    /// tag. Creates missing ones, deletes stale ones (a tag no longer
    /// desired by either kind), and enslaves/addresses each per its
    /// `TaggedMaster`. Sub-interface naming: `<interface>.<tag>`, the
    /// standard Linux VLAN sub-interface convention — found on relist by
    /// matching that prefix rather than a targeted lookup, since there's no
    /// single kernel call for "every link whose name starts with X". A
    /// single scan over the *union* of both kinds' tags is required —
    /// scanning each kind separately would see the other kind's live
    /// sub-link as stale and delete it.
    async fn reconcile_tagged_subinterfaces(
        &self,
        interface: &str,
        physical_index: u32,
        desired: &[(u16, TaggedMaster)],
        parent_mtu: Option<u32>,
        stp: &StpPorts,
    ) -> Result<(), DriverError> {
        let prefix = format!("{interface}.");
        let desired_tags: Vec<u16> = desired.iter().map(|(tag, _)| *tag).collect();

        if !desired.is_empty()
            && let Some(parent) = self.find_link(interface).await?
            && parent_needs_up(parent.header.flags, stp.err_disabled)
        {
            self.handle
                .link()
                .set(LinkUnspec::new_with_index(physical_index).up().build())
                .execute()
                .await?;
            info!(interface = %interface, "brought parent link up for vlan sub-interfaces");
        }

        // The kernel never lets a VLAN device exceed its lower device, so the
        // parent is raised before any sub-link is created or resized.
        if !desired.is_empty()
            && let Some(parent) = self.find_link(interface).await?
            && let Some(mtu) = parent_mtu.and_then(|want| mtu_change(&parent, want))
        {
            self.handle
                .link()
                .set(LinkUnspec::new_with_index(physical_index).mtu(mtu).build())
                .execute()
                .await?;
            info!(interface = %interface, mtu, "set parent mtu before vlan sub-interfaces");
        }

        let mut links = self.handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            let Some(name) = link_name(&link) else {
                continue;
            };
            let Some(tag) = name
                .strip_prefix(&prefix)
                .and_then(|t| t.parse::<u16>().ok())
            else {
                continue;
            };
            if !desired_tags.contains(&tag) {
                self.handle.link().del(link.header.index).execute().await?;
                info!(interface = %interface, sub_interface = %name, "deleted vlan sub-interface");
            }
        }

        for (tag, master) in desired {
            let subname = format!("{prefix}{tag}");
            let sub_link = if let Some(link) = self.find_link(&subname).await? {
                link
            } else {
                self.handle
                    .link()
                    .add(LinkVlan::new(&subname, physical_index, *tag).build())
                    .execute()
                    .await?;
                info!(interface = %interface, sub_interface = %subname, tag, "created vlan sub-interface");
                self.find_link(&subname)
                    .await?
                    .ok_or_else(|| DriverError::LinkNotFoundAfterCreate(subname.clone()))?
            };

            let over = match master {
                TaggedMaster::Vrf { mtu, .. } => *mtu,
                TaggedMaster::Bridge(_) => None,
            };
            if let Some(mtu) =
                sub_link_mtu(over, parent_mtu).and_then(|want| mtu_change(&sub_link, want))
            {
                self.handle
                    .link()
                    .set(
                        LinkUnspec::new_with_index(sub_link.header.index)
                            .mtu(mtu)
                            .build(),
                    )
                    .execute()
                    .await?;
                info!(interface = %interface, sub_interface = %subname, mtu, "applied sub-interface mtu");
            }

            match master {
                TaggedMaster::Bridge(domain) => {
                    let bridge_ifname =
                        bridge_registry::lookup_bridge_id(&self.bridge_registry_path, domain)
                            .map(bridge_registry::bridge_ifname);
                    self.reconcile_master_lookup(
                        &subname,
                        &sub_link,
                        bridge_ifname,
                        MasterKind::Bridge,
                    )
                    .await?;
                }
                TaggedMaster::Vrf {
                    routing_table,
                    addresses,
                    ..
                } => {
                    let vrf_ifname = self.vrf_lookup(routing_table.as_deref()).await;
                    self.reconcile_master_lookup(&subname, &sub_link, vrf_ifname, MasterKind::Vrf)
                        .await?;
                    self.reconcile_addresses(&subname, sub_link.header.index, addresses)
                        .await?;
                }
            }

            match self
                .handle
                .link()
                .set(
                    LinkUnspec::new_with_index(sub_link.header.index)
                        .up()
                        .build(),
                )
                .execute()
                .await
            {
                // An err-disabled parent stays down: leave the sub-link for
                // the next resync instead of failing `apply` every tick.
                Err(e) if is_enetdown(&e) => {
                    debug!(interface = %interface, sub_interface = %subname, "parent link is down, sub-interface left for the next resync");
                }
                r => r?,
            }
            // Up means the kernel opened the port: close it again at once.
            let domain = match master {
                TaggedMaster::Bridge(domain) => Some(domain.as_str()),
                TaggedMaster::Vrf { .. } => None,
            };
            self.reconcile_stp_port(&subname, domain, stp).await?;
        }
        Ok(())
    }

    /// Reconciles a link's addresses, master enslavement (VRF, bridge, or
    /// bond — at most one applies, by construction), and tag>0 VLAN
    /// sub-interfaces from its `subinterfaces`/`switching_profile_members` —
    /// the shared body of `apply`'s physical-interface case and
    /// `ensure_port_aggregate`'s own reconciliation, since a `PortAggregate`
    /// has the identical (non-loopback) config surface as a physical
    /// `Interface`. `name` is the real kernel link name (an interface's own
    /// config name, or a bond's registry-allocated ifname).
    /// `port_aggregate`, if set, names the `PortAggregate` `name` should be
    /// enslaved into — only ever passed by `apply` for a member interface;
    /// `ensure_port_aggregate` always passes `None`, since a bond never
    /// nests into another bond. `port_aggregate_active` gates whether that
    /// enslavement actually happens right now (see
    /// `InterfaceState.port_aggregate_active`); ignored when
    /// `port_aggregate` is `None`.
    #[allow(
        clippy::too_many_arguments,
        reason = "one reconciliation shared by interfaces and aggregates"
    )]
    async fn reconcile_physical_link(
        &self,
        name: &str,
        link: &LinkMessage,
        switching_profile_members: &[(String, VlanTag)],
        port_aggregate: Option<&str>,
        port_aggregate_active: bool,
        subinterfaces: &[SubinterfaceState],
        parent_mtu: Option<u32>,
        stp: &StpPorts,
    ) -> Result<(), DriverError> {
        let index = link.header.index;

        // All (tag-0) L3 config lives in `subinterfaces` — see
        // `schema::valid_addressing_split`/`PortAggregate`'s own doc
        // comment.
        let tag0 = subinterfaces.iter().find(|s| s.tag == 0);
        let physical_addresses: &[InterfaceAddress] =
            tag0.map_or(&[][..], |s| s.addresses.as_slice());
        self.reconcile_addresses(name, index, physical_addresses)
            .await?;

        let vrf_ifname = self
            .vrf_lookup(tag0.and_then(|s| s.routing_table.as_deref()))
            .await;
        // At most one of a VRF/bond/`Untagged`-bridge master can apply to
        // the same link — commit-time validation
        // (`valid_subinterface_and_switching_profile_tags`,
        // `valid_port_aggregate_membership`) rejects any of the three
        // colliding, since the link has only one master.
        let bond_ifname = match port_aggregate.filter(|_| port_aggregate_active) {
            Some(name) => port_aggregate_registry::lookup_port_aggregate_id(
                &self.port_aggregate_registry_path,
                name,
            )
            .map(port_aggregate_registry::port_aggregate_ifname),
            None => Lookup::NotConfigured,
        };
        let untagged_bridge = match switching_profile_members
            .iter()
            .find(|(_, tag)| *tag == VlanTag::Untagged)
        {
            Some((domain, _)) => {
                bridge_registry::lookup_bridge_id(&self.bridge_registry_path, domain)
                    .map(bridge_registry::bridge_ifname)
            }
            None => Lookup::NotConfigured,
        };
        let (master, master_kind) = pick_master(vrf_ifname, bond_ifname, untagged_bridge);
        self.reconcile_master_lookup(name, link, master, master_kind)
            .await?;
        // Fail-safe, as soon as the enslaved port exists: before the caller's
        // trailing `up` where the link is still down (the kernel keeps it
        // DISABLED until then), else right after the enslavement.
        self.reconcile_stp_port(name, untagged_domain(switching_profile_members), stp)
            .await?;

        // Union of L2 dot1q switching-profile members and L3 subinterfaces
        // (tag>0) — commit-time validation guarantees the two sets of tags
        // are disjoint, so each tag appears in at most one of the two.
        let mut tagged: Vec<(u16, TaggedMaster)> = switching_profile_members
            .iter()
            .filter_map(|(domain, tag)| match tag {
                VlanTag::Dot1q(id) => Some((*id, TaggedMaster::Bridge(domain.clone()))),
                VlanTag::Untagged => None,
            })
            .collect();
        tagged.extend(subinterfaces.iter().filter(|s| s.tag > 0).map(|s| {
            (
                s.tag,
                TaggedMaster::Vrf {
                    routing_table: s.routing_table.clone(),
                    addresses: s.addresses.clone(),
                    mtu: s.mtu,
                },
            )
        }));
        self.reconcile_tagged_subinterfaces(name, index, &tagged, parent_mtu, stp)
            .await?;
        Ok(())
    }
}

/// The kernel refuses to open a VLAN device over a down lower device, so an
/// admin-down parent must be raised before its sub-links, unless BPDU guard
/// is holding it down on purpose.
fn parent_needs_up(flags: LinkFlags, err_disabled: bool) -> bool {
    !flags.contains(LinkFlags::Up) && !err_disabled
}

fn is_enetdown(e: &rtnetlink::Error) -> bool {
    matches!(e, rtnetlink::Error::NetlinkError(m) if m.raw_code() == -ENETDOWN)
}

/// The domain a link is an `Untagged` member of, if any.
fn untagged_domain(members: &[(String, VlanTag)]) -> Option<&str> {
    members
        .iter()
        .find(|(_, tag)| *tag == VlanTag::Untagged)
        .map(|(domain, _)| domain.as_str())
}

#[async_trait]
impl InterfaceDriver for LinuxInterfaceDriver {
    async fn apply(&self, desired: &InterfaceState) -> Result<(), DriverError> {
        let loopback_table = loopback_table_name(&desired.name);

        // Unset means 1500, enforced — except on a bond member, whose MTU the
        // bonding driver sets from its bond's.
        let want = desired
            .mtu
            .or(desired.port_aggregate.is_none().then_some(DEFAULT_MTU));
        let link = if let Some(table_name) = loopback_table {
            let Some(table_id) = self.resolve_table_id(table_name).await else {
                debug!(interface = %desired.name, table = %table_name, "table id not resolvable yet");
                return Ok(());
            };
            self.ensure_loopback_link(&loopback_ifname(table_id))
                .await?
        } else {
            let Some(link) = self.find_link(&desired.name).await? else {
                // nos-interfaced never creates ordinary interfaces — this
                // is a normal, expected condition for a not-yet-present
                // interface, not an error.
                debug!(interface = %desired.name, "interface not present in netns yet");
                return Ok(());
            };
            link
        };
        let index = link.header.index;

        if let Some(table_name) = loopback_table {
            // A loopback interface carries its flat L3 config directly
            // (`desired.addresses`/`routing_table`) — it never has
            // `subinterfaces`/`switching_profile`/`port_aggregate`, so
            // there's nothing for `reconcile_physical_link` to share here.
            self.reconcile_addresses(&desired.name, index, &desired.addresses)
                .await?;
            let vrf_ifname = self.resolve_vrf_name(table_name).await;
            self.reconcile_master_lookup(&desired.name, &link, vrf_ifname, MasterKind::Vrf)
                .await?;
        } else {
            self.reconcile_physical_link(
                &desired.name,
                &link,
                &desired.switching_profile_members,
                desired.port_aggregate.as_deref(),
                desired.port_aggregate_active,
                &desired.subinterfaces,
                want,
                &desired.stp,
            )
            .await?;
        }

        let mut link_set = LinkUnspec::new_with_index(index);
        link_set = if desired.stp.err_disabled {
            link_set.down()
        } else {
            link_set.up()
        };
        if let Some(mtu) = want.and_then(|want| mtu_change(&link, want)) {
            link_set = link_set.mtu(mtu);
            info!(interface = %desired.name, mtu, "applied interface mtu");
        }
        self.handle.link().set(link_set.build()).execute().await?;
        trace!(interface = %desired.name, "ensuring interface administratively up");
        if loopback_table.is_none() {
            // Up means the kernel opened a freshly enslaved port: close it.
            self.reconcile_stp_port(
                &desired.name,
                untagged_domain(&desired.switching_profile_members),
                &desired.stp,
            )
            .await?;
        }
        Ok(())
    }

    async fn remove(&self, name: &str) -> Result<(), DriverError> {
        if let Some(table_name) = loopback_table_name(name) {
            let Some(table_id) = self.resolve_table_id(table_name).await else {
                debug!(interface = %name, table = %table_name, "table id not resolvable yet, nothing to remove");
                return Ok(());
            };
            let kernel_name = loopback_ifname(table_id);
            let Some(link) = self.find_link(&kernel_name).await? else {
                debug!(interface = %name, device = %kernel_name, "loopback device not present, nothing to remove");
                return Ok(());
            };
            self.reconcile_addresses(&kernel_name, link.header.index, &[])
                .await?;
            self.handle.link().del(link.header.index).execute().await?;
            info!(interface = %name, device = %kernel_name, "deleted loopback device");
            return Ok(());
        }

        let Some(link) = self.find_link(name).await? else {
            debug!(interface = %name, "interface not present in netns, nothing to remove");
            return Ok(());
        };
        self.reconcile_tagged_subinterfaces(
            name,
            link.header.index,
            &[],
            None,
            &StpPorts::default(),
        )
        .await?;
        self.reconcile_addresses(name, link.header.index, &[])
            .await?;
        self.reconcile_master(name, &link, None, MasterKind::Vrf)
            .await?;
        self.stp_release(name, link.header.index).await?;
        Ok(())
    }

    /// Ensures a bridge device named from `desired.name`'s persisted bridge
    /// id (see `bridge_registry`) exists — find-or-create, same shape as
    /// `ensure_loopback_link`/`nos-ribd`'s `ensure_vrf` — then reconciles
    /// `desired.addresses`/`routing_table` directly onto that bridge device,
    /// the same two calls `apply` makes for a physical/loopback link's own
    /// L3 config, making the bridge an SVI.
    async fn ensure_broadcast_domain(
        &self,
        desired: &BroadcastDomainState,
    ) -> Result<String, DriverError> {
        let bridge_id =
            bridge_registry::ensure_bridge_id(&self.bridge_registry_path, &desired.name)?;
        let ifname = bridge_registry::bridge_ifname(bridge_id);
        let link = if let Some(link) = self.find_link(&ifname).await? {
            link
        } else {
            self.handle
                .link()
                .add(
                    LinkBridge::new(&ifname)
                        .address(random_local_mac().to_vec())
                        .build(),
                )
                .execute()
                .await?;
            info!(domain = %desired.name, bridge = %ifname, "created broadcast domain bridge");
            self.find_link(&ifname)
                .await?
                .ok_or_else(|| DriverError::LinkNotFoundAfterCreate(ifname.clone()))?
        };

        self.reconcile_addresses(&ifname, link.header.index, &desired.addresses)
            .await?;
        let vrf_ifname = self.vrf_lookup(desired.routing_table.as_deref()).await;
        self.reconcile_master_lookup(&ifname, &link, vrf_ifname, MasterKind::Vrf)
            .await?;

        self.handle
            .link()
            .set(LinkUnspec::new_with_index(link.header.index).up().build())
            .execute()
            .await?;
        Ok(ifname)
    }

    /// Deletes `domain`'s bridge device, if one was ever created for it.
    /// Never touches the bridge-id registry entry — same reasoning as
    /// `nos-ribd`'s VRF teardown: a later restart (or the domain being
    /// re-added) recreates the identically-named bridge.
    async fn remove_broadcast_domain(&self, domain: &str) -> Result<(), DriverError> {
        let Lookup::Found(bridge_id) =
            bridge_registry::lookup_bridge_id(&self.bridge_registry_path, domain)
        else {
            debug!(domain = %domain, "no bridge id allocated, nothing to tear down");
            return Ok(());
        };
        let ifname = bridge_registry::bridge_ifname(bridge_id);
        if let Some(link) = self.find_link(&ifname).await? {
            self.handle.link().del(link.header.index).execute().await?;
            info!(domain = %domain, bridge = %ifname, "deleted broadcast domain bridge");
        }
        Ok(())
    }

    /// Ensures a bond device named from `desired.name`'s persisted bond id
    /// (see `port_aggregate_registry`) exists — find-or-create, same shape
    /// as `ensure_broadcast_domain`'s bridge — then reconciles the bond's
    /// own `switching_profile`/`mtu`/`subinterfaces` via the same
    /// `reconcile_physical_link` helper `apply` uses for a physical
    /// interface, since the config surface is identical.
    async fn ensure_port_aggregate(
        &self,
        desired: &PortAggregateState,
    ) -> Result<String, DriverError> {
        let bond_id = port_aggregate_registry::ensure_port_aggregate_id(
            &self.port_aggregate_registry_path,
            &desired.name,
        )?;
        let ifname = port_aggregate_registry::port_aggregate_ifname(bond_id);
        // Before the bond exists, so its first link event already names it.
        self.links.set_port_aggregate(&ifname, Some(&desired.name));
        let link = if let Some(link) = self.find_link(&ifname).await? {
            link
        } else {
            self.handle
                .link()
                .add(
                    LinkBond::new(&ifname)
                        .mode(bond_mode_of(desired.mode))
                        .build(),
                )
                .execute()
                .await?;
            info!(port_aggregate = %desired.name, bond = %ifname, mode = ?desired.mode, "created port aggregate bond");
            self.find_link(&ifname)
                .await?
                .ok_or_else(|| DriverError::LinkNotFoundAfterCreate(ifname.clone()))?
        };
        let index = link.header.index;

        self.reconcile_physical_link(
            &ifname,
            &link,
            &desired.switching_profile_members,
            None,
            true,
            &desired.subinterfaces,
            Some(desired.mtu.unwrap_or(DEFAULT_MTU)),
            &desired.stp,
        )
        .await?;

        let mut link_set = LinkUnspec::new_with_index(index);
        link_set = if desired.stp.err_disabled {
            link_set.down()
        } else {
            link_set.up()
        };
        if let Some(mtu) = mtu_change(&link, desired.mtu.unwrap_or(DEFAULT_MTU)) {
            link_set = link_set.mtu(mtu);
            info!(port_aggregate = %desired.name, mtu, "applied port aggregate mtu");
        }
        self.handle.link().set(link_set.build()).execute().await?;
        self.reconcile_stp_port(
            &ifname,
            untagged_domain(&desired.switching_profile_members),
            &desired.stp,
        )
        .await?;
        Ok(ifname)
    }

    /// Deletes `name`'s bond device, if one was ever created for it. Never
    /// touches the port-aggregate-id registry entry — same reasoning as
    /// `remove_broadcast_domain`.
    async fn remove_port_aggregate(&self, name: &str) -> Result<(), DriverError> {
        let Lookup::Found(bond_id) = port_aggregate_registry::lookup_port_aggregate_id(
            &self.port_aggregate_registry_path,
            name,
        ) else {
            debug!(port_aggregate = %name, "no port aggregate id allocated, nothing to tear down");
            return Ok(());
        };
        let ifname = port_aggregate_registry::port_aggregate_ifname(bond_id);
        if let Some(link) = self.find_link(&ifname).await? {
            self.handle.link().del(link.header.index).execute().await?;
            info!(port_aggregate = %name, bond = %ifname, "deleted port aggregate bond");
        }
        self.links.set_port_aggregate(&ifname, None);
        Ok(())
    }

    async fn link_local_address(&self, kernel_interface: &str) -> Option<Ipv6Addr> {
        let link = self.find_link(kernel_interface).await.ok()??;
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(link.header.index)
            .execute();
        while let Ok(Some(msg)) = addrs.try_next().await {
            if msg.header.scope != AddressScope::Link {
                continue;
            }
            if let Some(IpAddr::V6(addr)) = msg.attributes.iter().find_map(|a| match a {
                AddressAttribute::Address(ip) => Some(*ip),
                _ => None,
            }) {
                return Some(addr);
            }
        }
        None
    }

    async fn bridge_mtu(&self, kernel_interface: &str) -> Option<u32> {
        let link = self.find_link(kernel_interface).await.ok()??;
        link.attributes.iter().find_map(|a| match a {
            LinkAttribute::Mtu(mtu) => Some(*mtu),
            _ => None,
        })
    }

    async fn set_bridge_port_state(
        &self,
        port: &BridgePortRef,
        state: StpPortState,
    ) -> Result<(), DriverError> {
        let link = self
            .find_port_link(port)
            .await?
            .filter(is_stp_port)
            .ok_or_else(|| DriverError::Other(format!("{port:?} is not a bridge port")))?;
        let name = link_name(&link).unwrap_or_default().to_string();
        self.write_port_state(&name, &link, state, false).await
    }

    async fn flush_bridge_port(&self, port: &BridgePortRef) -> Result<(), DriverError> {
        let link = self
            .find_port_link(port)
            .await?
            .filter(is_stp_port)
            .ok_or_else(|| DriverError::Other(format!("{port:?} is not a bridge port")))?;
        // `IFLA_BRPORT_FLUSH` is a flag attribute: no payload.
        self.set_port_attr(
            link.header.index,
            DefaultNla::new(IFLA_BRPORT_FLUSH, vec![]),
        )
        .await?;
        debug!(interface = %link_name(&link).unwrap_or_default(), "bridge port fdb flushed");
        Ok(())
    }

    fn watch_links(&self) -> LinkWatch {
        self.links.watch()
    }
}

/// Feeds `hub` from `RTMGRP_LINK` (subscribe first, dump second) and a 30 s
/// re-dump. Runs for the process lifetime; the table is warm before any
/// subscriber. ponytail: the re-dump is the only recovery from ENOBUFS and
/// from a dump overtaking a queued event; upgrade to a sequence-checked dump.
async fn run_link_watcher(hub: Arc<LinkHub>) {
    loop {
        match rtnetlink::new_multicast_connection(&[MulticastGroup::Link]) {
            Ok((connection, handle, mut messages)) => {
                tokio::spawn(connection);
                let mut tick = tokio::time::interval(Duration::from_secs(30));
                loop {
                    tokio::select! {
                        msg = messages.next() => match msg {
                            Some((m, _)) => match links::decode(m.payload) {
                                Some(Delta::Upsert(l)) => hub.upsert(l),
                                Some(Delta::Remove(n)) => hub.remove(&n),
                                None => {}
                            },
                            None => break,
                        },
                        // The first tick fires at once: the initial dump.
                        _ = tick.tick() => dump_links(&handle, &hub).await,
                    }
                }
                warn!("link watcher netlink stream ended, reconnecting");
            }
            Err(e) => warn!(error = %e, "link watcher could not open netlink, retrying"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// A failed dump keeps the old table (no flap to empty).
async fn dump_links(handle: &Handle, hub: &LinkHub) {
    let mut stream = handle.link().get().execute();
    let mut all = Vec::new();
    loop {
        match stream.try_next().await {
            Ok(Some(m)) => all.extend(links::link_state(&m)),
            Ok(None) => break,
            Err(e) => {
                warn!(error = %e, "link dump failed, keeping previous table");
                return;
            }
        }
    }
    hub.replace_all(all);
}

/// Pure, netlink-free: `desired`/`observed` are both plain address lists —
/// no kernel involved, so this is directly unit-testable.
/// A random locally administered unicast MAC. Fixed on the bridge at creation
/// so it never auto-follows its lowest port: `nos-fdbd` enslaves `vx<vni>`
/// moments after the bridge exists, and the address change flushes the SVI's
/// neighbours and leaves hosts holding a stale gateway MAC (#812).
// ponytail: `RandomState` is per-process random, not cryptographic; only
// uniqueness between routers matters (46 random bits).
fn random_local_mac() -> [u8; 6] {
    use std::hash::{BuildHasher, Hasher};
    let r = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
        .to_be_bytes();
    [(r[0] & 0xfc) | 0x02, r[1], r[2], r[3], r[4], r[5]]
}

fn diff_addresses(observed: &[IpNet], desired: &[IpNet]) -> (Vec<IpNet>, Vec<IpNet>) {
    let to_add = desired
        .iter()
        .filter(|d| !observed.contains(d))
        .copied()
        .collect();
    let to_remove = observed
        .iter()
        .filter(|o| !desired.contains(o))
        .copied()
        .collect();
    (to_add, to_remove)
}

#[cfg(test)]
mod tests {
    #[test]
    fn bridge_mac_is_local_unicast_and_varies() {
        let a = super::random_local_mac();
        assert_eq!(a[0] & 0b11, 0b10, "locally administered, unicast");
        assert_ne!(a, super::random_local_mac());
    }

    use super::*;

    fn f(n: &str) -> Lookup<String> {
        Lookup::Found(n.into())
    }

    #[test]
    fn pick_master_precedence_and_unknown_never_falls_through() {
        use Lookup::{NotConfigured as N, Unknown as U};
        // Each kind alone: Found / NotConfigured / Unknown.
        assert_eq!(pick_master(f("v"), N, N), (f("v"), MasterKind::Vrf));
        assert_eq!(pick_master(N, f("b"), N), (f("b"), MasterKind::Bond));
        assert_eq!(pick_master(N, N, f("br")), (f("br"), MasterKind::Bridge));
        assert_eq!(pick_master(N, N, N), (N, MasterKind::Bridge));
        assert_eq!(pick_master(U, N, N), (U, MasterKind::Vrf));
        assert_eq!(pick_master(N, U, N), (U, MasterKind::Bond));
        assert_eq!(pick_master(N, N, U), (U, MasterKind::Bridge));
        // Higher precedence wins; Unknown above a Found is not skipped past.
        assert_eq!(pick_master(f("v"), f("b"), f("br")).1, MasterKind::Vrf);
        assert_eq!(pick_master(U, f("b"), f("br")), (U, MasterKind::Vrf));
        assert_eq!(pick_master(N, U, f("br")), (U, MasterKind::Bond));
        assert_eq!(pick_master(N, f("b"), U), (f("b"), MasterKind::Bond));
    }

    #[test]
    fn parent_is_raised_only_when_down_and_not_err_disabled() {
        assert!(parent_needs_up(LinkFlags::empty(), false));
        assert!(!parent_needs_up(LinkFlags::empty(), true));
        assert!(!parent_needs_up(LinkFlags::Up, false));
        assert!(!parent_needs_up(LinkFlags::Up, true));
    }

    #[test]
    fn enetdown_is_recognised_only_for_that_netlink_errno() {
        use netlink_packet_core::ErrorMessage;
        use std::num::NonZeroI32;
        let nl = |code: i32| {
            let mut m = ErrorMessage::default();
            m.code = NonZeroI32::new(code);
            rtnetlink::Error::NetlinkError(m)
        };
        assert!(is_enetdown(&nl(-ENETDOWN)));
        assert!(!is_enetdown(&nl(-ENODEV)));
        assert!(!is_enetdown(&rtnetlink::Error::RequestFailed));
    }

    #[test]
    fn mtu_change_only_when_the_link_differs() {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkAttribute::Mtu(9000));
        assert_eq!(mtu_change(&link, 1500), Some(1500));
        assert_eq!(mtu_change(&link, 9000), None);
    }

    #[test]
    fn sub_link_mtu_prefers_the_override() {
        assert_eq!(sub_link_mtu(Some(1400), Some(9000)), Some(1400));
        assert_eq!(sub_link_mtu(None, Some(9000)), Some(9000));
        assert_eq!(sub_link_mtu(None, None), None);
    }

    fn link_with(infos: Vec<LinkInfo>) -> LinkMessage {
        let mut link = LinkMessage::default();
        link.attributes.push(LinkAttribute::LinkInfo(infos));
        link
    }

    #[test]
    fn blocking_is_written_as_disabled_the_only_state_that_sticks_without_stp() {
        assert_eq!(kernel_state(StpPortState::Blocking), BR_STATE_DISABLED);
        assert_eq!(kernel_state(StpPortState::Learning), BR_STATE_LEARNING);
        assert_eq!(kernel_state(StpPortState::Forwarding), BR_STATE_FORWARDING);
    }

    #[test]
    fn only_bridge_ports_other_than_vxlan_are_stp_ports() {
        let bridge_port = vec![LinkInfo::PortKind(InfoPortKind::Bridge)];
        assert!(is_stp_port(&link_with(bridge_port.clone())));
        assert!(!is_stp_port(&LinkMessage::default()));
        assert!(!is_stp_port(&link_with(vec![LinkInfo::PortKind(
            InfoPortKind::Bond
        )])));
        // The VTEP of a VNI domain is a bridge port too, and never ours.
        let mut vtep = bridge_port;
        vtep.push(LinkInfo::Kind(InfoKind::Vxlan));
        assert!(!is_stp_port(&link_with(vtep)));
    }

    #[test]
    fn the_observed_state_is_read_from_the_port_data() {
        assert_eq!(observed_port_state(&LinkMessage::default()), None);
        let link = link_with(vec![
            LinkInfo::PortKind(InfoPortKind::Bridge),
            LinkInfo::PortData(InfoPortData::BridgePort(vec![InfoBridgePort::State(
                rtnetlink::packet_route::link::BridgePortState::Forwarding,
            )])),
        ]);
        assert_eq!(observed_port_state(&link), Some(BR_STATE_FORWARDING));
    }

    #[test]
    fn a_tagged_member_is_its_sub_link() {
        assert_eq!(port_link_name("eth1", VlanTag::Untagged), "eth1");
        assert_eq!(port_link_name("bond3", VlanTag::Dot1q(100)), "bond3.100");
        assert_eq!(untagged_domain(&[("a".into(), VlanTag::Dot1q(5))]), None);
        assert_eq!(
            untagged_domain(&[
                ("a".into(), VlanTag::Dot1q(5)),
                ("b".into(), VlanTag::Untagged)
            ]),
            Some("b")
        );
    }

    #[test]
    fn loopback_ifname_formats_from_id() {
        assert_eq!(loopback_ifname(100), "lo100");
    }

    #[test]
    fn diff_addresses_computes_add_and_remove() {
        let observed = vec![
            "10.0.0.1/24".parse().unwrap(),
            "10.0.0.9/24".parse().unwrap(),
        ];
        let desired = vec![
            "10.0.0.1/24".parse().unwrap(),
            "10.0.0.2/24".parse().unwrap(),
        ];
        let (to_add, to_remove) = diff_addresses(&observed, &desired);
        assert_eq!(to_add, vec!["10.0.0.2/24".parse().unwrap()]);
        assert_eq!(to_remove, vec!["10.0.0.9/24".parse().unwrap()]);
    }

    #[test]
    fn diff_addresses_prefix_length_change_is_remove_plus_add() {
        // #655: same host address, new prefix length — both sides non-empty,
        // so `reconcile_addresses` must remove before it adds.
        for (old, new) in [
            ("2001:db8::1/64", "2001:db8::1/48"),
            ("10.0.0.1/24", "10.0.0.1/16"),
        ] {
            let (old, new): (nos_proto::IpNet, nos_proto::IpNet) =
                (old.parse().unwrap(), new.parse().unwrap());
            let (to_add, to_remove) = diff_addresses(&[old], &[new]);
            assert_eq!((to_add, to_remove), (vec![new], vec![old]));
        }
    }

    #[test]
    fn diff_addresses_no_change_when_equal() {
        let addrs = vec!["10.0.0.1/24".parse().unwrap()];
        let (to_add, to_remove) = diff_addresses(&addrs, &addrs);
        assert_eq!(to_add, [] as [nos_proto::IpNet; 0]);
        assert_eq!(to_remove, [] as [nos_proto::IpNet; 0]);
    }

    #[test]
    fn diff_addresses_empty_desired_removes_everything() {
        let observed = vec!["10.0.0.1/24".parse().unwrap()];
        let (to_add, to_remove) = diff_addresses(&observed, &[]);
        assert_eq!(to_add, [] as [nos_proto::IpNet; 0]);
        assert_eq!(to_remove, observed);
    }

    #[test]
    fn diff_addresses_empty_observed_adds_everything() {
        let desired = vec!["10.0.0.1/24".parse().unwrap()];
        let (to_add, to_remove) = diff_addresses(&[], &desired);
        assert_eq!(to_add, desired);
        assert_eq!(to_remove, [] as [nos_proto::IpNet; 0]);
    }

    /// Against the real kernel: needs `CAP_NET_ADMIN` in the current netns and
    /// `ip`/`bridge`/`tc` as the independent oracle, so run it in a throwaway
    /// one: `unshare -Urn cargo test -p nos-interface stp_kernel -- --ignored`.
    #[tokio::test]
    #[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
    #[allow(
        clippy::disallowed_types,
        reason = "test code: ip/bridge/tc are the independent oracle for the netlink writes (#228)"
    )]
    async fn stp_kernel_blocks_traps_and_restores_a_bridge_port() {
        let run = |cmd: &str| {
            let o = std::process::Command::new("sh")
                .args(["-c", cmd])
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "{cmd}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        run(
            "ip link add br0 type bridge stp_state 0; ip link add va type veth peer name vb; \
             ip link set va master br0; ip link set br0 up; ip link set va up; ip link set vb up",
        );
        let dir = tempfile::tempdir().unwrap();
        let driver = LinuxInterfaceDriver::new(
            dir.path().join("w.sock"),
            dir.path().join("bridges"),
            dir.path().join("aggregates"),
        )
        .unwrap();
        let mut stp = StpPorts {
            on: true,
            ..Default::default()
        };
        driver
            .reconcile_stp_port("va", Some("bd"), &stp)
            .await
            .unwrap();
        assert!(run("bridge link show dev va").contains("state disabled"));
        let filters = run("tc filter show dev va ingress");
        assert!(
            filters.contains("01:80:c2:00:00:00") && filters.contains("drop"),
            "{filters}"
        );
        assert!(filters.contains("01:00:0c:cc:cc:cd"), "{filters}");
        // A second pass changes nothing.
        driver
            .reconcile_stp_port("va", Some("bd"), &stp)
            .await
            .unwrap();

        let port = BridgePortRef {
            name: "va".into(),
            aggregate: false,
            tag: VlanTag::Untagged,
        };
        for (state, shown) in [
            (StpPortState::Learning, "state learning"),
            (StpPortState::Forwarding, "state forwarding"),
            (StpPortState::Blocking, "state disabled"),
        ] {
            driver.set_bridge_port_state(&port, state).await.unwrap();
            assert!(run("bridge link show dev va").contains(shown), "{shown}");
        }
        driver.flush_bridge_port(&port).await.unwrap();

        // The pushed state survives the next resync; off restores forwarding.
        stp.states.insert("bd".into(), StpPortState::Forwarding);
        driver
            .reconcile_stp_port("va", Some("bd"), &stp)
            .await
            .unwrap();
        assert!(run("bridge link show dev va").contains("state forwarding"));
        driver
            .set_bridge_port_state(&port, StpPortState::Blocking)
            .await
            .unwrap();
        stp.on = false;
        driver
            .reconcile_stp_port("va", Some("bd"), &stp)
            .await
            .unwrap();
        assert!(run("bridge link show dev va").contains("state forwarding"));
        assert!(!run("tc filter show dev va ingress").contains("drop"));
        // Not a bridge port: refused.
        run("ip link set va nomaster");
        assert!(driver
            .set_bridge_port_state(&port, StpPortState::Blocking)
            .await
            .is_err());
    }

    /// #338/#355: an admin-down parent is raised before its tagged sub-links
    /// (the e2e topology cannot control that precondition), unless BPDU guard
    /// holds it down. Run like the test above.
    #[tokio::test]
    #[ignore = "talks to the kernel; needs CAP_NET_ADMIN"]
    #[allow(
        clippy::disallowed_types,
        reason = "test code: ip is the independent oracle for the netlink writes (#228)"
    )]
    async fn tagged_subinterfaces_raise_an_admin_down_parent() {
        let run = |cmd: &str| {
            let o = std::process::Command::new("sh")
                .args(["-c", cmd])
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "{cmd}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        run("ip link add pa type veth peer name pb; ip link set pb up");
        let dir = tempfile::tempdir().unwrap();
        let driver = LinuxInterfaceDriver::new(
            dir.path().join("w.sock"),
            dir.path().join("bridges"),
            dir.path().join("aggregates"),
        )
        .unwrap();
        let desired = [(
            10u16,
            TaggedMaster::Vrf {
                routing_table: None,
                addresses: vec![],
                mtu: None,
            },
        )];
        let index = driver.find_link("pa").await.unwrap().unwrap().header.index;
        let is_up =
            |dev: &str| run(&format!("ip -o link show {dev}")).contains("<BROADCAST,MULTICAST,UP");
        let flags = |dev: &str| run(&format!("ip -o link show {dev}"));

        // BPDU guard holds the parent down: it stays down, the sub-link is made.
        let held = StpPorts {
            err_disabled: true,
            ..Default::default()
        };
        driver
            .reconcile_tagged_subinterfaces("pa", index, &desired, None, &held)
            .await
            .unwrap();
        assert!(!is_up("pa"), "{}", flags("pa"));
        assert!(!is_up("pa.10"), "{}", flags("pa.10"));

        // Otherwise the parent is raised, then the sub-link.
        driver
            .reconcile_tagged_subinterfaces("pa", index, &desired, None, &StpPorts::default())
            .await
            .unwrap();
        assert!(is_up("pa"), "{}", flags("pa"));
        assert!(is_up("pa.10"), "{}", flags("pa.10"));
    }
}
