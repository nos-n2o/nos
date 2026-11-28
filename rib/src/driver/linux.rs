use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use futures::{stream, StreamExt as _, TryStreamExt as _};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST,
};
use nos_nexthop::{Gateway, Group, Nexthop, NexthopRecord};
use nos_proto::evpn_id::{format_mac, vxlan_name};
use nos_proto::{IlmRoute, IpNet, NextHop};
use rtnetlink::packet_route::link::{InfoData, InfoVxlan, LinkAttribute, LinkInfo, LinkMessage};
use rtnetlink::packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use rtnetlink::packet_route::route::{
    MplsLabel, RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteNextHopFlags,
    RouteProtocol, RouteScope, RouteType,
};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{
    Handle, LinkBridge, LinkIpIp, LinkUnspec, LinkVrf, LinkVxlan, RouteMessageBuilder,
    RouteNextHopBuilder,
};
use tracing::{debug, info, trace, warn};

use super::mpls::{self, Mpls, Sysctl};
use super::nexthop_groups::{GroupKey, NexthopTable};
use super::route_channel::RouteChannel;
use super::{table_registry, DriverError, RibDriver};
use crate::evpn::{L3Vni, Mac};
use crate::rib::{RibEntry, RouteSource};

/// errno(3) `ENODEV` — the kernel's reply to a targeted `RTM_GETLINK`
/// lookup (`match_name`/`match_index`) for a link that doesn't exist.
const ENODEV: i32 = 19;
/// errno(3) `ENOENT`: deleting a neighbour/FDB entry that is already gone.
const ENOENT: i32 = 2;
/// errno(3) `ESRCH`: deleting a route that is already gone.
const ESRCH: i32 = 3;
/// RFC 7348's IANA VXLAN port, as `nos-fdbd`'s devices use.
const VXLAN_PORT: u16 = 4789;

/// The L3 VNI devices this process built for one table (by table id).
#[derive(Debug, Clone)]
struct L3State {
    vni: u32,
    bridge: u32,
    /// The underlay's master (its VRF) when the VXLAN device was brought up:
    /// the kernel binds the tunnel's socket to the VRF only on open, so a
    /// change means a reopen — `nos-fdbd`'s `bound_master` rule.
    bound_master: Option<u32>,
    remotes: BTreeMap<IpAddr, Mac>,
}

/// The MPLS pop route `sync_mpls` installed for one table (by table id).
#[derive(Debug, Clone, Copy)]
struct MplsState {
    label: u32,
    vrf: u32,
    /// The underlay VRF's ifindex: a labelled route's PE next hop without
    /// an ifindex is looked up there (`egress_of`).
    underlay_vrf: Option<u32>,
}

/// RFC 7490 remote LFA's IP-in-IP device for one table (`rlfa252` at most).
fn tunnel_name(table_id: u32) -> String {
    format!("rlfa{table_id}")
}

/// The tunnel device's only address. An interface with no IPv4 address fails
/// every `rp_filter` check (strict or loose), so decapsulated packets would be
/// dropped; RFC 7600's IPv4 dummy address, host scope, is never picked as a
/// source. ponytail: strict `rp_filter` (1) still drops them — loose (2, what
/// distributions default to) or off is required on PQ nodes.
const TUNNEL_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 8);
/// `RT_SCOPE_HOST`.
const SCOPE_HOST: u8 = 254;
/// Underlay MTU 1500 minus the outer IPv4 header.
const TUNNEL_MTU: u32 = 1480;

/// The L3 VNI's bridge: `brv16777215` is 11 chars, under `IFNAMSIZ`.
fn bridge_name(vni: u32) -> String {
    format!("brv{vni}")
}

fn master_of(link: &LinkMessage) -> Option<u32> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::Controller(i) => Some(*i),
        _ => None,
    })
}

fn link_mac(link: &LinkMessage) -> Option<Mac> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::Address(b) => Mac::try_from(b.as_slice()).ok(),
        _ => None,
    })
}

fn vxlan_matches(link: &LinkMessage, vni: u32, vtep: IpAddr, underlay: u32) -> bool {
    let local = match vtep {
        IpAddr::V4(a) => InfoVxlan::Local(a),
        IpAddr::V6(a) => InfoVxlan::Local6(a),
    };
    link.attributes.iter().any(|a| match a {
        LinkAttribute::LinkInfo(infos) => infos.iter().any(|i| match i {
            LinkInfo::Data(InfoData::Vxlan(v)) => {
                v.contains(&InfoVxlan::Id(vni))
                    && v.contains(&local)
                    && v.contains(&InfoVxlan::Link(underlay))
            }
            _ => false,
        }),
        _ => false,
    })
}

/// `<vtep> lladdr <rmac>` on the L3 bridge: permanent and `extern_learn`, so
/// the kernel neither ages nor probes it.
fn remote_neigh_msg(bridge: u32, vtep: IpAddr, rmac: Mac) -> NeighbourMessage {
    let mut m = NeighbourMessage::default();
    m.header.family = match vtep {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    m.header.ifindex = bridge;
    m.header.state = NeighbourState::Permanent;
    m.header.flags = NeighbourFlags::ExtLearned;
    m.attributes = vec![
        NeighbourAttribute::LinkLayerAddress(rmac.to_vec()),
        NeighbourAttribute::Destination(NeighbourAddress::from(vtep)),
    ];
    m
}

/// `<rmac> dst <vtep> vni <vni> via <underlay>` on the VXLAN device, also
/// filed in the bridge's table (`self master extern_learn`, as `nos-fdbd`'s
/// remote MACs). `via` is required with the underlay in a VRF, else the kernel
/// looks the VTEP up in the main table.
fn remote_fdb_msg(
    vxlan: u32,
    underlay: u32,
    rmac: Mac,
    vtep: IpAddr,
    vni: u32,
) -> NeighbourMessage {
    let mut m = NeighbourMessage::default();
    m.header.family = AddressFamily::Bridge;
    m.header.ifindex = vxlan;
    m.header.state = NeighbourState::Permanent;
    m.header.flags = NeighbourFlags::Own
        .union(NeighbourFlags::Controller)
        .union(NeighbourFlags::ExtLearned);
    m.attributes = vec![
        NeighbourAttribute::LinkLayerAddress(rmac.to_vec()),
        NeighbourAttribute::Destination(NeighbourAddress::from(vtep)),
        NeighbourAttribute::Vni(vni),
        NeighbourAttribute::IfIndex(underlay),
    ];
    m
}

// ponytail: fixed fan-out bound rather than a `--driver` flag — nothing in
// the bench-bgp kernel-install report suggests 64 is the wrong number.
// Upgrade to real rtnetlink-level batching if concurrency alone stops
// closing the gap to BIRD/FRR/GoBGP.
const MAX_CONCURRENT_ROUTE_OPS: usize = 64;

/// Kernel route priority (metric) of a backup route. Primaries use the
/// default (0, which the kernel reports as 0 for IPv4 and 1024 for IPv6), so
/// the backup must sit above that per family (an IPv6 backup at 1000 would
/// beat its own primary); the kernel keeps both routes in the FIB and falls
/// to this one the moment the primary is withdrawn — no netlink round trip
/// needed at failover time.
const BACKUP_METRIC_V4: u32 = 1000;
const BACKUP_METRIC_V6: u32 = 2000;

/// Runs every op to completion, at most `MAX_CONCURRENT_ROUTE_OPS` at once,
/// and returns every error — one failure never cancels the rest (#139).
async fn drain<E>(ops: impl IntoIterator<Item = impl Future<Output = Result<(), E>>>) -> Vec<E> {
    stream::iter(ops)
        .buffer_unordered(MAX_CONCURRENT_ROUTE_OPS)
        .filter_map(|r| async move { r.err() })
        .collect()
        .await
}

/// The shadow entry after an install: unset when the add was deferred or
/// skipped (no `l3` bridge / tunnel device / resolved hop yet), so a retry
/// of the same entry is not a no-op (#686).
fn shadow_after_install(sent: bool, new: &Hops) -> Option<Hops> {
    sent.then(|| new.clone())
}

/// One kernel route of a prefix: `false` is the primary, `true` its backup.
type Slot = (IpNet, bool);

/// The kernel routes one winning entry wants: its primary (every
/// equal-cost next hop, each with the labels it pushes), plus its backup.
fn slots(prefix: IpNet, entry: &RibEntry) -> Vec<(Slot, Hops)> {
    let mut out = vec![((prefix, false), entry.next_hops.clone())];
    if let Some(backup) = entry.backup {
        out.push((
            (prefix, true),
            vec![(backup, entry.backup_interface_id).into()],
        ));
    }
    out
}

/// One slot's next hops, each a gateway, (when known) the local kernel
/// interface it's reachable over and the MPLS labels it pushes (empty: plain
/// IP) — see `RibEntry::next_hops`. Two or more are one `RTA_MULTIPATH`
/// route; none is a discard (`RTN_BLACKHOLE`) route.
type Hops = Vec<NextHop>;

/// What a slot is compared by: its sorted `(gateway, ifindex, labels)`
/// triples. The ifindex is set only for a link-local IPv6 gateway (#618): the
/// same fe80 address on two links is two different next hops, while for any
/// other gateway the kernel's Oif is derived (underlay/VRF) and stays out.
/// The same gateway with two label stacks stays two hops, and a label-only
/// change is a changed route (replace).
type Key = Vec<(IpAddr, Option<u32>, Vec<u32>)>;

/// `entry` with each pinned hop leaving over its link's ifindex (`ifindexes`
/// by link name); unpinned hops stay as they are.
fn pin_interface(entry: &RibEntry, ifindexes: &HashMap<&str, u32>) -> RibEntry {
    let mut e = entry.clone();
    for hop in &mut e.next_hops {
        if let Some(i) = entry.interfaces.get(&hop.gateway) {
            hop.interface_id = ifindexes.get(i.as_str()).copied();
        }
    }
    e
}

fn is_link_local(gateway: IpAddr) -> bool {
    matches!(gateway, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80)
}

/// The interface a key carries for `gateway`: only a link-local one's.
fn key_ifindex(gateway: IpAddr, ifindex: Option<u32>) -> Option<u32> {
    ifindex.filter(|_| is_link_local(gateway))
}

fn key(hops: &[NextHop]) -> Key {
    let mut out: Key = hops
        .iter()
        .map(|h| {
            (
                h.gateway,
                key_ifindex(h.gateway, h.interface_id),
                h.labels.clone(),
            )
        })
        .collect();
    out.sort_unstable();
    out
}

/// What one slot needs to go from the `old` key (what the kernel has) to the
/// `new` one (what is wanted).
#[derive(Debug, PartialEq, Eq)]
enum SlotOp {
    Keep,
    Remove,
    Add,
    /// Both exist with a different key: one `NLM_F_REPLACE` request, never a
    /// delete then an add (make-before-break, #598).
    Replace,
}

/// How a slot's kernel route is expressed: its own gateways (`Inline`, one or
/// `RTA_MULTIPATH`) or `RTA_NH_ID` of a nexthop group (`Group`, #1587). Part of
/// what a slot is compared by, so a route an older version left inline is
/// migrated by one atomic replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Inline,
    Group,
}

/// What `slot_op` and `diff_routes` compare: the hops and how they are installed.
type Shape = (Key, Form);

fn form_of(gid: Option<u32>) -> Form {
    if gid.is_some() {
        Form::Group
    } else {
        Form::Inline
    }
}

/// What `add_route` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placed {
    /// Deferred or skipped: nothing is in the kernel.
    Skipped,
    Inline,
    /// Installed as `RTA_NH_ID` of this group.
    Group(u32),
}

impl Placed {
    fn sent(self) -> bool {
        self != Self::Skipped
    }
    fn gid(self) -> Option<u32> {
        match self {
            Self::Group(g) => Some(g),
            _ => None,
        }
    }
}

/// `LinuxRibDriver::form_for` without the driver.
fn form(disabled: bool, rejected: &HashSet<Key>, hops: &[NextHop], backup: bool) -> Form {
    if backup || disabled || hops.len() < 2 {
        return Form::Inline;
    }
    let k = key(hops);
    // A repeated hop would be one nexthop twice in a group.
    if k.windows(2).any(|w| w[0] == w[1]) || rejected.contains(&k) {
        return Form::Inline;
    }
    Form::Group
}

fn slot_op<T: PartialEq>(old: Option<&T>, new: Option<&T>) -> SlotOp {
    match (old, new) {
        (None, None) => SlotOp::Keep,
        (Some(_), None) => SlotOp::Remove,
        (None, Some(_)) => SlotOp::Add,
        (Some(o), Some(n)) if o == n => SlotOp::Keep,
        (Some(_), Some(_)) => SlotOp::Replace,
    }
}

/// The gateways of `hops` in order, comma-joined for a log line.
fn show_gateways<'a>(gateways: impl IntoIterator<Item = &'a IpAddr>) -> String {
    gateways
        .into_iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Real Linux backend: creates a VRF device + kernel routing table per
/// routing table name (via `table_registry`'s persisted id allocation) and
/// installs the winning route per prefix into it.
pub struct LinuxRibDriver {
    handle: Handle,
    /// Dedicated, genuinely pipelined channel for route add/del — see
    /// `route_channel` module docs for why `handle` above (an ordinary
    /// `rtnetlink::Handle`) isn't used for this. Link/VRF management and
    /// route dumps stay on `handle`.
    route_channel: RouteChannel,
    registry_path: PathBuf,
    /// This driver's own record of what it last installed per table id —
    /// lets `apply_delta` add/remove exactly what changed without a fresh
    /// kernel dump. Kept honest by `reconcile_routes` (used by `apply`/
    /// `teardown`), which always sets it to the just-converged desired
    /// state; `apply_delta` is the only other writer, and only for
    /// prefixes it just itself installed/removed. A `std::sync::Mutex`,
    /// since every critical section here is a quick synchronous map
    /// read/write, never held across an `.await`. The `Option<u32>`
    /// alongside each gateway is from `RibEntry::next_hops`, needed to
    /// reconstruct a matching `RTM_DELROUTE` for a link-local IPv6 gateway
    /// on the `apply_delta` removal path (see `add_route`'s doc comment).
    installed: Mutex<HashMap<u32, HashMap<Slot, Hops>>>,
    /// Per table id: the L3 VNI devices `sync_l3vni` built.
    l3: Mutex<HashMap<u32, L3State>>,
    /// Per table id: the ifindex of the remote LFA device `sync_tunnel` built.
    tunnels: Mutex<HashMap<u32, u32>>,
    /// Per table id: the MPLS pop route `sync_mpls` installed.
    mpls: Mutex<HashMap<u32, MplsState>>,
    /// Per table id: the ILM entries `sync_ilm` last installed, by label.
    ilm: Mutex<HashMap<u32, BTreeMap<u32, Hops>>>,
    sysctl: Sysctl,
    /// Startup hold (#654): `apply` leaves kernel routes it has no desired
    /// slot for alone (see `RibDriver::keep_stale`).
    keep_stale: AtomicBool,
    /// Per table id: the nexthop objects (#1587) and which slot uses which.
    nexthops: Mutex<HashMap<u32, NexthopTable>>,
    /// Held while a group is reserved and created, so two routes sharing a
    /// hop set create it once.
    create_lock: tokio::sync::Mutex<()>,
    /// The kernel has no nexthop objects (`EOPNOTSUPP`/`ENOSYS`), or the test
    /// flag `--inline-multipath`: every route installs inline. Lives for the
    /// process.
    groups_disabled: AtomicBool,
    /// Hop sets the kernel refused as a group (`EINVAL`): inline for those.
    rejected: Mutex<HashSet<Key>>,
}

impl LinuxRibDriver {
    pub fn new(registry_path: PathBuf) -> Result<Self, DriverError> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        nos_log_client::spawn_critical("rtnetlink-connection", connection);
        let route_channel = RouteChannel::new()?;
        Ok(Self {
            handle,
            route_channel,
            registry_path,
            installed: Mutex::new(HashMap::new()),
            l3: Mutex::new(HashMap::new()),
            tunnels: Mutex::new(HashMap::new()),
            mpls: Mutex::new(HashMap::new()),
            ilm: Mutex::new(HashMap::new()),
            sysctl: Sysctl::default(),
            keep_stale: AtomicBool::new(false),
            nexthops: Mutex::new(HashMap::new()),
            create_lock: tokio::sync::Mutex::new(()),
            groups_disabled: AtomicBool::new(false),
            rejected: Mutex::new(HashSet::new()),
        })
    }

    /// Installs every multipath route inline, as before nexthop groups
    /// (test-only, e2e `ecmp-nexthop-groups` creates inline routes to migrate).
    pub fn disable_nexthop_groups(&self) {
        self.groups_disabled.store(true, Ordering::SeqCst);
    }

    /// Undoes `disable_nexthop_groups` (test-only: SIGUSR1 in a `dev-args` build).
    #[cfg(feature = "dev-args")]
    pub fn enable_nexthop_groups(&self) {
        self.groups_disabled.store(false, Ordering::SeqCst);
    }

    /// How `hops` at a slot want to be installed: a group for a primary
    /// multipath route unless groups are off or this hop set was refused.
    fn form_for(&self, hops: &[NextHop], backup: bool) -> Form {
        let disabled = self.groups_disabled.load(Ordering::SeqCst);
        form(disabled, &self.rejected.lock().unwrap(), hops, backup)
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

    /// Resolves each entry's pinned `interface` name to its ifindex (the
    /// hops' `interface_id`, so the link-local/`RTA_OIF` path takes over). An
    /// entry whose link does not exist yet is left out and reported as an
    /// error, so the caller `mark_dirty`s and retries on the next tick (#686).
    // ponytail: per hop, the slot key ignores the ifindex of a non-link-local
    // gateway, so re-pinning such a hop to another interface alone does not
    // re-install.
    async fn resolve_pinned<'a>(
        &self,
        entries: impl Iterator<Item = (IpNet, &'a RibEntry)>,
    ) -> (HashMap<IpNet, RibEntry>, Option<DriverError>) {
        let mut out = HashMap::new();
        let mut err = None;
        for (prefix, entry) in entries {
            let mut ifindexes = HashMap::new();
            let mut missing = None;
            for name in entry.interfaces.values() {
                if ifindexes.contains_key(name.as_str()) {
                    continue;
                }
                match self.find_link(name).await {
                    Ok(Some(link)) => {
                        ifindexes.insert(name.as_str(), link.header.index);
                    }
                    other => {
                        warn!(%prefix, interface = %name, "static route interface not found, install deferred");
                        missing = Some(other.err().unwrap_or_else(|| {
                            DriverError::Other(format!("interface {name} not found"))
                        }));
                        break;
                    }
                }
            }
            if missing.is_some() {
                err = missing;
            } else {
                out.insert(prefix, pin_interface(entry, &ifindexes));
            }
        }
        (out, err)
    }

    /// Sends one raw `RTM_NEWNEIGH`/`RTM_DELNEIGH` (an FDB entry needs flags
    /// `NeighbourAddRequest` doesn't offer). A delete of an absent entry
    /// (`ENOENT`) counts as done.
    async fn neigh(&self, msg: NeighbourMessage, delete: bool) -> Result<(), DriverError> {
        let (payload, flags) = if delete {
            (RouteNetlinkMessage::DelNeighbour(msg), 0)
        } else {
            (
                RouteNetlinkMessage::NewNeighbour(msg),
                NLM_F_CREATE | NLM_F_REPLACE,
            )
        };
        let mut req = NetlinkMessage::from(payload);
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
        let mut response = self.handle.clone().request(req)?;
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                if e.raw_code() == 0 || (delete && e.raw_code() == -ENOENT) {
                    continue;
                }
                return Err(rtnetlink::Error::NetlinkError(e).into());
            }
        }
        Ok(())
    }

    /// The bridge, the VXLAN device on it, and the per-VTEP entries of
    /// `l3` — see `RibDriver::sync_l3vni`. `prev` is what was built last.
    async fn build_l3vni(
        &self,
        vrf: u32,
        l3: &L3Vni,
        remotes: &BTreeMap<IpAddr, Mac>,
        prev: Option<&L3State>,
    ) -> Result<(Mac, L3State), DriverError> {
        let missing = |what: String| DriverError::Other(format!("{what} does not exist (yet)"));
        let (br_name, vx_name) = (bridge_name(l3.vni), vxlan_name(l3.vni));

        let bridge = if let Some(l) = self.find_link(&br_name).await? {
            l
        } else {
            self.handle
                .link()
                .add(LinkBridge::new(&br_name).build())
                .execute()
                .await?;
            info!(bridge = %br_name, vni = l3.vni, "created l3 vni bridge");
            self.find_link(&br_name)
                .await?
                .ok_or_else(|| missing(br_name.clone()))?
        };
        let br = bridge.header.index;
        if master_of(&bridge) != Some(vrf) {
            self.handle
                .link()
                .set(LinkUnspec::new_with_index(br).controller(vrf).build())
                .execute()
                .await?;
        }
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(br).up().build())
            .execute()
            .await?;

        let underlay = self
            .find_link(&l3.underlay)
            .await?
            .ok_or_else(|| missing(format!("underlay {}", l3.underlay)))?;
        let (underlay_idx, underlay_master) = (underlay.header.index, master_of(&underlay));
        let mut vx = self.find_link(&vx_name).await?;
        if let Some(l) = &vx {
            if !vxlan_matches(l, l3.vni, l3.vtep, underlay_idx) {
                info!(vxlan = %vx_name, vni = l3.vni, "l3 vni vxlan device drifted, recreating");
                self.handle.link().del(l.header.index).execute().await?;
                vx = None;
            } else if prev.map(|p| p.bound_master) != Some(underlay_master) {
                self.handle
                    .link()
                    .set(LinkUnspec::new_with_index(l.header.index).down().build())
                    .execute()
                    .await?;
                info!(vxlan = %vx_name, vni = l3.vni, "l3 vni vxlan device reopened in its underlay's vrf");
            }
        }
        let vx = if let Some(l) = vx {
            l
        } else {
            let b = LinkVxlan::new(&vx_name, l3.vni)
                .dev(underlay_idx)
                .port(VXLAN_PORT)
                .learning(false);
            let b = match l3.vtep {
                IpAddr::V4(a) => b.local(a),
                IpAddr::V6(a) => b.local6(a),
            };
            self.handle.link().add(b.build()).execute().await?;
            info!(vxlan = %vx_name, vni = l3.vni, vtep = %l3.vtep, underlay = %l3.underlay, "created l3 vni vxlan device");
            self.find_link(&vx_name)
                .await?
                .ok_or_else(|| missing(vx_name.clone()))?
        };
        let vx_idx = vx.header.index;
        if master_of(&vx) != Some(br) {
            self.handle
                .link()
                .set(LinkUnspec::new_with_index(vx_idx).controller(br).build())
                .execute()
                .await?;
        }
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(vx_idx).up().build())
            .execute()
            .await?;
        // Read after enslaving: a bridge without an assigned address takes
        // its lowest port's.
        let rmac = self
            .find_link(&br_name)
            .await?
            .as_ref()
            .and_then(link_mac)
            .ok_or_else(|| missing(format!("{br_name}'s address")))?;

        let old = prev.map_or_default(|p| p.remotes.clone());
        for (vtep, mac) in &old {
            if remotes.get(vtep) != Some(mac) {
                self.neigh(remote_neigh_msg(br, *vtep, *mac), true).await?;
                self.neigh(
                    remote_fdb_msg(vx_idx, underlay_idx, *mac, *vtep, l3.vni),
                    true,
                )
                .await?;
                info!(vni = l3.vni, vtep = %vtep, rmac = %format_mac(mac), "evpn remote vtep removed");
            }
        }
        // Re-asserted every pass (cheap, a handful of VTEPs), so a recreated
        // device is healed.
        for (vtep, mac) in remotes {
            self.neigh(remote_neigh_msg(br, *vtep, *mac), false).await?;
            self.neigh(
                remote_fdb_msg(vx_idx, underlay_idx, *mac, *vtep, l3.vni),
                false,
            )
            .await?;
            if old.get(vtep) != Some(mac) {
                info!(vni = l3.vni, vtep = %vtep, rmac = %format_mac(mac), "evpn remote vtep installed");
            }
        }
        Ok((
            rmac,
            L3State {
                vni: l3.vni,
                bridge: br,
                bound_master: underlay_master,
                remotes: remotes.clone(),
            },
        ))
    }

    /// Deletes an L3 VNI's VXLAN device and bridge (their neighbours, FDB
    /// entries and the routes through the bridge go with them).
    async fn remove_l3vni(&self, vni: u32) -> Result<(), DriverError> {
        for name in [vxlan_name(vni), bridge_name(vni)] {
            if let Some(l) = self.find_link(&name).await? {
                self.handle.link().del(l.header.index).execute().await?;
            }
        }
        info!(vni, bridge = %bridge_name(vni), vxlan = %vxlan_name(vni), "deleted l3 vni devices");
        Ok(())
    }

    /// Deletes `table_id`'s remote LFA device, if any (its tunnel backups go
    /// with it).
    async fn remove_tunnel(&self, table_id: u32) -> Result<(), DriverError> {
        self.tunnels.lock().unwrap().remove(&table_id);
        let name = tunnel_name(table_id);
        if let Some(link) = self.find_link(&name).await? {
            self.handle.link().del(link.header.index).execute().await?;
            info!(device = %name, table_id, "deleted remote lfa tunnel device");
        }
        Ok(())
    }

    /// Ensures the VRF device for `table_id` exists and is up, returning
    /// its ifindex.
    async fn ensure_vrf(&self, vrf_ifname: &str, table_id: u32) -> Result<u32, DriverError> {
        let index = if let Some(link) = self.find_link(vrf_ifname).await? {
            link.header.index
        } else {
            self.handle
                .link()
                .add(LinkVrf::new(vrf_ifname, table_id).build())
                .execute()
                .await?;
            let index = self
                .find_link(vrf_ifname)
                .await?
                .map(|link| link.header.index)
                .ok_or_else(|| {
                    DriverError::Registry(std::io::Error::other(format!(
                        "created VRF {vrf_ifname} but could not find it afterwards"
                    )))
                })?;
            info!(vrf = %vrf_ifname, table_id, "created VRF device");
            index
        };
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await?;
        trace!(vrf = %vrf_ifname, index, "ensured VRF link is up");
        Ok(index)
    }

    /// Dumps every route currently installed in kernel table `table_id`,
    /// across both address families, keeping the raw `RouteMessage`
    /// alongside its extracted `(prefix, gateways)` so a later deletion can
    /// reuse the exact message the kernel gave us (the safest way to make
    /// sure `RTM_DELROUTE` matches the entry we mean).
    async fn dump_routes(
        &self,
        table_id: u32,
        groups: &HashMap<u32, Key>,
    ) -> Result<Vec<(Slot, Key, Option<u32>, RouteMessage)>, DriverError> {
        let mut out = Vec::new();
        let table_id_u8 =
            u8::try_from(table_id).expect("table ids are always <= MAX_TABLE_ID (252)");

        let v4_filter = RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(table_id)
            .build();
        let mut v4 = self.handle.route().get(v4_filter).execute();
        while let Some(route) = v4.try_next().await? {
            if route.header.table == table_id_u8
                && let Some((slot, key, gid)) = extract(&route, groups)
            {
                out.push((slot, key, gid, route));
            }
        }

        let v6_filter = RouteMessageBuilder::<Ipv6Addr>::new()
            .table_id(table_id)
            .build();
        let mut v6 = self.handle.route().get(v6_filter).execute();
        while let Some(route) = v6.try_next().await? {
            if route.header.table == table_id_u8
                && let Some((slot, key, gid)) = extract(&route, groups)
            {
                out.push((slot, key, gid, route));
            }
        }

        Ok(out)
    }

    /// A hop's interface id, when given, becomes its `RTA_OIF` —
    /// **required**, not optional, for an IPv6 gateway that's link-local
    /// (`fe80::/10`): Linux's `RTM_NEWROUTE` rejects such a route with
    /// `EINVAL` unless an outgoing interface is given alongside the
    /// gateway, since a link-local address is only meaningful relative to
    /// a specific link and the kernel has no other way to resolve which
    /// one. `nos-ospfv3d`'s own SPF next-hops are always link-local (RFC
    /// 5340 §4.8) and always carry a `Some` here; every other route source
    /// passes `None` and needs none. Two or more hops are one
    /// `RTA_MULTIPATH` (ECMP) route. `backup` installs it at
    /// the family's backup metric instead of the default priority.
    ///
    /// `replace` swaps the slot's installed route in one atomic request
    /// instead of adding. Returns `false` when nothing was sent (the route is
    /// deferred or skipped), so a caller replacing must remove the old one.
    #[allow(
        clippy::too_many_arguments,
        reason = "one install request; a struct would only rename the arguments"
    )]
    async fn add_route(
        &self,
        table_id: u32,
        prefix: IpNet,
        hops: &[NextHop],
        source: Option<RouteSource>,
        backup: bool,
        tunnel: bool,
        replace: bool,
    ) -> Result<Placed, DriverError> {
        let want_group = self.form_for(hops, backup) == Form::Group;
        let gateway = show_gateways(hops.iter().map(|h| &h.gateway));
        // An `Evpn` route leaves `onlink` through the L3 VNI's bridge: its
        // gateway is the remote VTEP, resolved by `sync_l3vni`'s neighbour.
        // A remote LFA backup leaves `onlink` through the table's IP-in-IP
        // device, which takes the gateway (the PQ node) as the outer
        // destination and looks it up in the VRF. A labelled (VPN) route's
        // hops each leave `onlink` over the underlay interface their PE
        // resolved to: the gateway is not reachable inside this VRF.
        let evpn = source == Some(RouteSource::Evpn);
        let tunnel = tunnel && backup;
        let labelled = !backup && hops.iter().any(|h| !h.labels.is_empty());
        let mut hops = hops.to_vec();
        let shared_dev = if evpn {
            let Some(bridge) = self.l3.lock().unwrap().get(&table_id).map(|s| s.bridge) else {
                debug!(%prefix, table_id, "l3 vni bridge not built yet, evpn route deferred");
                return Ok(Placed::Skipped);
            };
            Some(bridge)
        } else if tunnel {
            let Some(dev) = self.tunnels.lock().unwrap().get(&table_id).copied() else {
                debug!(%prefix, table_id, "remote lfa tunnel device not built yet, backup deferred");
                return Ok(Placed::Skipped);
            };
            Some(dev)
        } else {
            None
        };
        if let Some(dev) = shared_dev {
            for hop in &mut hops {
                hop.interface_id = Some(dev);
            }
        }
        // #623: an unlabelled IPv6 route over IPv4 gateways (RFC 4798) would
        // be an IPv4-mapped `RTA_GATEWAY`, which the kernel accepts but
        // resolves with IPv6 neighbour discovery for `::ffff:a.b.c.d`: on
        // Ethernet nobody answers (e2e `bgp-v6-over-v4`'s probe), so the
        // traffic is lost. Only MPLS-encapsulated (`labelled`) and shared-
        // device (EVPN, tunnel) routes use the mapped gateway.
        // ponytail: the warned set grows with the prefixes seen (no pruning).
        if !labelled
            && shared_dev.is_none()
            && prefix.addr().is_ipv6()
            && !hops.is_empty()
            && hops.iter().all(|h| h.gateway.is_ipv4())
        {
            static WARNED: std::sync::Mutex<Option<HashSet<IpNet>>> = std::sync::Mutex::new(None);
            let first = WARNED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_or_insert_with(HashSet::new)
                .insert(prefix);
            if first {
                warn!(%prefix, %gateway, table_id, "ipv6 route over an ipv4 next hop not installed: the kernel cannot forward it over ethernet");
            }
            return Ok(Placed::Skipped);
        }
        if labelled {
            let mut devs = Vec::with_capacity(hops.len());
            for hop in &hops {
                devs.push(match hop.interface_id {
                    Some(dev) => Some(dev),
                    None => self.egress_of(table_id, hop.gateway).await,
                });
            }
            let (kept, unresolved) = mpls::onlink_hops(hops, &devs);
            if kept.is_empty() {
                warn!(%prefix, %gateway, table_id, "labelled route skipped: next hop unresolved");
                return Ok(Placed::Skipped);
            }
            for gw in unresolved {
                warn!(%prefix, gateway = %gw, table_id, "labelled next hop skipped: unresolved");
            }
            hops = kept;
        }
        let onlink = labelled || shared_dev.is_some();
        let mut gid = None;
        if want_group && hops.len() >= 2 {
            gid = self.ensure_group(table_id, prefix, &hops, onlink).await?;
        }
        let route = match gid {
            Some(g) => group_route(prefix, table_id, g),
            None => build_route(prefix, &hops, table_id, backup, onlink),
        };
        let Some(route) = route else {
            warn!(%prefix, %gateway, table_id, "route prefix/gateway address family mismatch, skipping");
            return Ok(Placed::Skipped);
        };
        let mut sent = self
            .put_route(route.clone(), replace, (prefix, &gateway, table_id, backup))
            .await;
        if gid.is_some()
            && let Err(DriverError::Netlink(rtnetlink::Error::NetlinkError(m))) = &sent
            && m.code.is_some_and(|c| c.get() == -EINVAL)
        {
            // The kernel took the group but not a route over it (e.g. an IPv6
            // route over an IPv4-mapped gateway): this hop set goes inline.
            self.reject(&hops, &std::io::Error::from_raw_os_error(EINVAL));
            gid = None;
            sent = match build_route(prefix, &hops, table_id, backup, onlink) {
                Some(r) => {
                    self.put_route(r, replace, (prefix, &gateway, table_id, backup))
                        .await
                }
                None => Ok(()),
            };
        }
        sent.inspect_err(|e| {
            warn!(%prefix, %gateway, table_id, backup, replace, error = %e, "failed to add route");
        })?;
        if labelled {
            let labels: Vec<_> = hops.iter().map(|h| &h.labels).collect();
            let gateway = show_gateways(hops.iter().map(|h| &h.gateway));
            let interfaces: Vec<_> = hops.iter().filter_map(|h| h.interface_id).collect();
            match gid {
                Some(g) => {
                    info!(%prefix, labels = ?labels, %gateway, interfaces = ?interfaces, table_id, replaced = replace, nexthop_group = g, "installed labelled route");
                }
                None => {
                    info!(%prefix, labels = ?labels, %gateway, interfaces = ?interfaces, table_id, replaced = replace, "installed labelled route");
                }
            }
        } else {
            let discard = hops.is_empty();
            let interfaces: Vec<_> = hops.iter().filter_map(|h| h.interface_id).collect();
            match gid {
                Some(g) => {
                    info!(%prefix, %gateway, next_hops = hops.len(), table_id, source = ?source, backup, discard, tunnel, replaced = replace, interfaces = ?interfaces, nexthop_group = g, "added route");
                }
                None => {
                    info!(%prefix, %gateway, next_hops = hops.len(), table_id, source = ?source, backup, discard, tunnel, replaced = replace, interfaces = ?interfaces, "added route");
                }
            }
        }
        Ok(gid.map_or(Placed::Inline, Placed::Group))
    }

    /// Sends one route: a replace, or an add that replaces a foreign route
    /// (another protocol) holding the slot once (#1514).
    async fn put_route(
        &self,
        route: RouteMessage,
        replace: bool,
        (prefix, gateway, table_id, backup): (IpNet, &str, u32, bool),
    ) -> Result<(), DriverError> {
        if replace {
            return self.route_channel.replace(route).await;
        }
        match self.route_channel.add(route.clone()).await {
            Err(e) if is_eexist(&e) => {
                warn!(%prefix, %gateway, table_id, backup, "replaced foreign route");
                self.route_channel.replace(route).await
            }
            other => other,
        }
    }

    /// The ifindex `gateway` leaves over in this table's underlay (`ip route
    /// get <gateway> vrf <underlay>`), `None` when unknown or unreachable. A
    /// PE on a connected prefix comes from `nos-bgpd` without one.
    // ponytail: one lookup per labelled route install; cache per gateway if
    // VPN tables grow to many thousands of routes.
    async fn egress_of(&self, table_id: u32, gateway: IpAddr) -> Option<u32> {
        let state = self
            .mpls
            .lock()
            .unwrap()
            .get(&table_id)
            .map(|s| s.underlay_vrf);
        let underlay = match state {
            Some(u) => u?,
            // No L3VPN here (an OSPF Prefix-SID route, #1383): the gateway is
            // an IGP neighbour inside the table's own VRF.
            None => {
                self.find_link(&table_registry::vrf_ifname(table_id))
                    .await
                    .ok()??
                    .header
                    .index
            }
        };
        self.egress_in(underlay, gateway).await
    }

    /// `egress_of` in an explicit VRF.
    async fn egress_in(&self, underlay: u32, gateway: IpAddr) -> Option<u32> {
        let mut m = RouteMessage::default();
        let (family, len, dst) = match gateway {
            IpAddr::V4(a) => (AddressFamily::Inet, 32, RouteAddress::from(a)),
            IpAddr::V6(a) => (AddressFamily::Inet6, 128, RouteAddress::from(a)),
        };
        m.header.address_family = family;
        m.header.destination_prefix_length = len;
        m.attributes = vec![
            RouteAttribute::Destination(dst),
            RouteAttribute::Oif(underlay),
        ];
        // A destination makes this a lookup, not a dump.
        let route = self
            .handle
            .route()
            .get(m)
            .execute()
            .try_next()
            .await
            .ok()??;
        route
            .attributes
            .iter()
            .find_map(|a| match a {
                RouteAttribute::Oif(i) => Some(*i),
                _ => None,
            })
            .filter(|i| *i != underlay)
    }

    /// Deletes one route directly from `(prefix, gateway, table_id,
    /// priority)`, without a kernel dump — the standard, sufficient way to
    /// identify a route for `RTM_DELROUTE` (the same key fields `ip route
    /// del ... table ... metric ...` uses). Used by `apply_delta`'s
    /// shadow-state-driven fast path; `reconcile_routes`'s full dump-diff
    /// path still reuses the exact dumped `RouteMessage` instead, since it
    /// already has it on hand. A hop's interface id has the same load-bearing role
    /// for a link-local IPv6 gateway as `add_route`'s own doc comment
    /// describes.
    async fn remove_route(
        &self,
        table_id: u32,
        prefix: IpNet,
        hops: &[NextHop],
        backup: bool,
        gid: Option<u32>,
    ) -> Result<(), DriverError> {
        let key = key(hops);
        let gateway = show_gateways(key.iter().map(|(gw, _, _)| gw));
        // No encap or onlink in the request: the kernel matches on what is
        // given, and duplicate gateways of a multipath route still match.
        let bare: Hops = hops
            .iter()
            .map(|h| (h.gateway, h.interface_id).into())
            .collect();
        let route = match gid {
            Some(g) => group_route(prefix, table_id, g),
            None => build_route(prefix, &bare, table_id, backup, false),
        };
        let Some(route) = route else {
            warn!(%prefix, %gateway, table_id, "route prefix/gateway address family mismatch, skipping");
            return Ok(());
        };
        self.route_channel.del(route).await.inspect_err(|e| {
            warn!(%prefix, %gateway, table_id, backup, error = %e, "failed to remove route");
        })?;
        log_removed(prefix, &key, table_id, backup);
        Ok(())
    }

    /// Installs `hops` at a slot: a replace when the slot holds `old` (its
    /// install request replaces the kernel route in one step), then removes
    /// `old` itself only if the install was deferred and left it behind.
    /// Returns whether the new route is in the kernel.
    async fn install(
        &self,
        table_id: u32,
        prefix: IpNet,
        hops: &[NextHop],
        old: Option<(&Hops, Option<u32>)>,
        (source, backup, tunnel): (Option<RouteSource>, bool, bool),
    ) -> Result<Placed, DriverError> {
        let placed = self
            .add_route(
                table_id,
                prefix,
                hops,
                source,
                backup,
                tunnel,
                old.is_some(),
            )
            .await?;
        if let (false, Some((old, gid))) = (placed.sent(), old) {
            self.remove_route(table_id, prefix, old, backup, gid)
                .await?;
        }
        Ok(placed)
    }

    /// Applies only `changes` directly against the kernel, using
    /// `self.installed` (not a kernel dump) to know each prefix's previous
    /// gateway — the hot path for incremental per-prefix BGP pushes. See
    /// `RibDriver::apply_delta`'s doc comment.
    async fn apply_delta_impl(
        &self,
        table_id: u32,
        changes: &HashMap<IpNet, Option<RibEntry>>,
    ) -> Result<(), DriverError> {
        type Slots = HashMap<Slot, Hops>;
        type Olds = HashMap<Slot, (Hops, Option<u32>)>;
        self.ensure_nh_table(table_id).await;
        let mut items: Vec<(IpNet, Olds, Slots, Option<RouteSource>, bool)> = {
            let installed = self.installed.lock().unwrap();
            let nexthops = self.nexthops.lock().unwrap();
            let table_installed = installed.get(&table_id);
            let table_groups = nexthops.get(&table_id);
            changes
                .iter()
                .map(|(prefix, new)| {
                    let old: Olds = [false, true]
                        .into_iter()
                        .filter_map(|b| {
                            let slot = (*prefix, b);
                            let gid = table_groups.and_then(|t| t.slot_gid(&slot));
                            table_installed
                                .and_then(|m| m.get(&slot))
                                .map(|hops| (slot, (hops.clone(), gid)))
                        })
                        .collect();
                    let source = new.as_ref().map(|e| e.source);
                    let tunnel = new.as_ref().is_some_and(|e| e.backup_tunnel);
                    let new: Slots = new
                        .as_ref()
                        .map_or_default(|e| slots(*prefix, e).into_iter().collect());
                    (*prefix, old, new, source, tunnel)
                })
                .collect()
        };

        // The shadow state follows each op as it succeeds, so a failed one
        // leaves its slot as the kernel still has it.
        let set = |slot: Slot, hops: Option<Hops>, gid: Option<u32>| {
            let mut installed = self.installed.lock().unwrap();
            let table_installed = installed.entry(table_id).or_default();
            match hops {
                Some(hops) => table_installed.insert(slot, hops),
                None => table_installed.remove(&slot),
            };
            if let Some(t) = self.nexthops.lock().unwrap().get_mut(&table_id) {
                t.set_slot(slot, gid);
            }
        };
        let mut want: HashMap<Slot, Option<GroupKey>> = HashMap::new();
        for (_, old, new, source, _) in &items {
            for (slot, (_, gid)) in old {
                if gid.is_some() && !slot.1 {
                    let key = self
                        .repoint_key(table_id, *slot, new.get(slot), *source)
                        .await;
                    want.insert(*slot, key);
                }
            }
        }
        let replaced = self.replace_groups(table_id, &want).await;
        for (_, old, new, _, _) in &mut items {
            let moved: Vec<Slot> = old
                .iter()
                .filter(|(s, (_, g))| {
                    g.is_some_and(|g| replaced.iter().any(|(r, _)| *r == g))
                        && want.contains_key(*s)
                })
                .map(|(s, _)| *s)
                .collect();
            for slot in moved {
                let gid = old.remove(&slot).and_then(|(_, g)| g);
                if let Some(hops) = new.remove(&slot) {
                    set(slot, Some(hops), gid);
                }
            }
        }
        let errors = drain(items.into_iter().map(
            |(prefix, old, new, source, tunnel)| async move {
                // A changed slot is replaced in place (make-before-break), a
                // vanished one removed, a new one added.
                let mut result = Ok(());
                let all: BTreeSet<Slot> = old.keys().chain(new.keys()).copied().collect();
                for slot in all {
                    let (o, n) = (old.get(&slot), new.get(&slot));
                    let old_shape = o.map(|(h, g)| (key(h), form_of(*g)));
                    let new_shape = n.map(|h| (key(h), self.form_for(h, slot.1)));
                    let op = slot_op(old_shape.as_ref(), new_shape.as_ref());
                    let step = match (op, o, n) {
                        (SlotOp::Remove, Some((o, g)), _) => self
                            .remove_route(table_id, prefix, o, slot.1, *g)
                            .await
                            .map(|()| (None, None)),
                        (SlotOp::Add | SlotOp::Replace, o, Some(n)) => self
                            .install(
                                table_id,
                                prefix,
                                n,
                                o.map(|(h, g)| (h, *g)),
                                (source, slot.1, tunnel),
                            )
                            .await
                            .map(|placed| (shadow_after_install(placed.sent(), n), placed.gid())),
                        (_, o, n) => Ok((n.cloned(), o.and_then(|(_, g)| *g))),
                    };
                    match step {
                        Ok((hops, gid)) => set(slot, hops, gid),
                        Err(e) => result = result.and(Err(e)),
                    }
                }
                result
            },
        ))
        .await;
        self.collect_garbage(table_id).await;
        errors.into_iter().next().map_or(Ok(()), Err)
    }

    /// The group key slot `slot` wants when it can follow a group replace
    /// (#1588): a plain (unlabelled, non-EVPN) primary multipath route.
    async fn repoint_key(
        &self,
        table_id: u32,
        slot: Slot,
        hops: Option<&Hops>,
        source: Option<RouteSource>,
    ) -> Option<GroupKey> {
        let h = hops?;
        let plain = self.form_for(h, slot.1) == Form::Group
            && source != Some(RouteSource::Evpn)
            && h.iter()
                .all(|x| x.labels.is_empty() && x.gateway.is_ipv4() == slot.0.addr().is_ipv4());
        if !plain {
            return None;
        }
        self.member_key(table_id, slot.0, h, false).await
    }

    /// Replaces in place every group `want` moves as a whole to one new hop
    /// set (`NexthopTable::plan_repoints`, #1588): one nexthop replace
    /// instead of a route replace per prefix, make-before-break. Returns each
    /// replaced group; a failed replace leaves its routes to the per-slot path.
    // ponytail: plain (unlabelled, non-EVPN) primaries only.
    async fn replace_groups(
        &self,
        table_id: u32,
        want: &HashMap<Slot, Option<GroupKey>>,
    ) -> Vec<(u32, usize)> {
        let repoints = {
            let tables = self.nexthops.lock().unwrap();
            tables
                .get(&table_id)
                .map_or_default(|t| t.plan_repoints(want))
        };
        let mut done = Vec::new();
        for (gid, key) in repoints {
            let _create = self.create_lock.lock().await;
            let plan = {
                let mut tables = self.nexthops.lock().unwrap();
                tables.get_mut(&table_id).and_then(|t| t.reserve_hops(&key))
            };
            let Some(plan) = plan else { continue };
            let mut created = Vec::new();
            let mut result = Ok(());
            for (id, (gateway, oif, onlink, labels)) in &plan.new_hops {
                let nh = Nexthop::Gateway(Gateway {
                    id: *id,
                    gateway: *gateway,
                    oif: *oif,
                    onlink: *onlink,
                    labels: labels.clone(),
                    fdb: false,
                    replace: true,
                });
                result = nh_send(nh, 0).await;
                if result.is_err() {
                    break;
                }
                created.push(*id);
            }
            if result.is_ok() {
                result = nh_send(
                    Nexthop::Group(Group {
                        id: gid,
                        members: plan.members.iter().map(|m| (*m, 1)).collect(),
                        fdb: false,
                    }),
                    0,
                )
                .await;
            }
            if let Err(e) = result {
                warn!(id = gid, table_id, error = %e, "cannot replace nexthop group, moving its routes one by one");
                if let Some(t) = self.nexthops.lock().unwrap().get_mut(&table_id) {
                    t.forget(&plan);
                }
                for id in created {
                    let _ = nh_send(Nexthop::Delete { id }, ENOENT).await;
                }
                continue;
            }
            if let Some(t) = self.nexthops.lock().unwrap().get_mut(&table_id) {
                t.repoint(gid, key.clone(), plan.members.clone());
            }
            let slots = want
                .keys()
                .filter(|s| {
                    self.nexthops
                        .lock()
                        .unwrap()
                        .get(&table_id)
                        .and_then(|t| t.slot_gid(s))
                        == Some(gid)
                })
                .count();
            info!(
                id = gid,
                members = key.len(),
                slots,
                table_id,
                "replaced nexthop group"
            );
            done.push((gid, slots));
        }
        done
    }

    /// Diffs `best_routes` against what's actually installed in
    /// `table_id`'s kernel table and adds/removes to converge, reusing the
    /// exact dumped `RouteMessage` for any removal.
    #[allow(
        clippy::too_many_lines,
        reason = "one dump-diff-converge pass: remove, add, shadow rebuild"
    )]
    async fn reconcile_routes(
        &self,
        table_id: u32,
        best_routes: &HashMap<IpNet, RibEntry>,
        keep_stale: bool,
    ) -> Result<(), DriverError> {
        // What the kernel has of ours, nexthops first: a route over a group
        // reads as that group's key, and the table adopts the objects (a
        // restarted `nos-ribd` finds its own groups instead of recreating them).
        let records = self.nh_dump(table_id).await;
        let group_keys = group_keys(&records);
        {
            let mut tables = self.nexthops.lock().unwrap();
            let t = tables
                .entry(table_id)
                .or_insert_with(|| NexthopTable::new(table_id));
            t.seed(&records);
        }
        let observed = self.dump_routes(table_id, &group_keys).await?;
        let observed_map: HashMap<Slot, Shape> = observed
            .iter()
            .map(|(slot, key, gid, _)| (*slot, (key.clone(), form_of(*gid))))
            .collect();
        let observed_gid: HashMap<Slot, u32> = observed
            .iter()
            .filter_map(|(slot, _, gid, _)| Some((*slot, (*gid)?)))
            .collect();
        let desired_full: HashMap<Slot, Hops> = best_routes
            .iter()
            .flat_map(|(prefix, entry)| slots(*prefix, entry))
            .collect();
        let desired: HashMap<Slot, Shape> = desired_full
            .iter()
            .map(|(slot, hops)| (*slot, (key(hops), self.form_for(hops, slot.1))))
            .collect();

        // The kernel refuses a delete naming both `RTA_NH_ID` and a gateway
        // (what a dump of a group route carries): delete those by id alone.
        let observed_map = {
            let mut m = observed_map;
            if observed_gid.is_empty() {
                m
            } else {
                // The kernel's groups are the truth for the planner.
                if let Some(t) = self.nexthops.lock().unwrap().get_mut(&table_id) {
                    t.reset_slots(observed_gid.clone(), []);
                }
                let mut want: HashMap<Slot, Option<GroupKey>> = HashMap::new();
                for slot in observed_gid.keys().filter(|s| !s.1) {
                    let source = best_routes.get(&slot.0).map(|e| e.source);
                    let key = self
                        .repoint_key(table_id, *slot, desired_full.get(slot), source)
                        .await;
                    want.insert(*slot, key);
                }
                let replaced = self.replace_groups(table_id, &want).await;
                for slot in observed_gid.keys().filter(|s| want.contains_key(*s)) {
                    let hit = self
                        .nexthops
                        .lock()
                        .unwrap()
                        .get(&table_id)
                        .and_then(|t| t.slot_gid(slot));
                    if hit.is_some_and(|g| replaced.iter().any(|(r, _)| *r == g))
                        && let Some(d) = desired.get(slot)
                    {
                        m.insert(*slot, d.clone());
                    }
                }
                m
            }
        };
        let observed_by_slot: HashMap<Slot, RouteMessage> = observed
            .iter()
            .map(|(slot, _, gid, message)| {
                let by_id = gid.and_then(|g| group_route(slot.0, table_id, g));
                (*slot, by_id.unwrap_or_else(|| message.clone()))
            })
            .collect();

        let (to_add, mut to_remove) = diff_routes(&observed_map, &desired);
        // Routes the startup hold leaves in the kernel: their groups stay.
        let mut stale_groups = Vec::new();
        if keep_stale {
            // Only a slot we re-add (changed hops) goes: EEXIST otherwise.
            stale_groups.extend(
                to_remove
                    .iter()
                    .filter(|(slot, _)| !desired.contains_key(slot))
                    .filter_map(|(slot, _)| observed_gid.get(slot).copied()),
            );
            to_remove.retain(|(slot, _)| desired.contains_key(slot));
        }
        debug!(
            table_id,
            to_add = to_add.len(),
            to_remove = to_remove.len(),
            "reconciling kernel routes"
        );

        // Remove before add: `to_add`/`to_remove` can share the same prefix
        // with a different gateway (an operator changed a static route's
        // next hop) — adding the new route while the kernel still has the
        // old one for that exact prefix fails with EEXIST (`rtnetlink`'s
        // route add uses NLM_F_CREATE | NLM_F_EXCL), so the stale entry
        // must be gone first. Within each phase, up to
        // MAX_CONCURRENT_ROUTE_OPS requests are in flight at once, sent
        // over the dedicated `route_channel` (see its module docs) — a
        // plain `rtnetlink::Handle` dispatches one request at a time
        // regardless of client-side concurrency, so it isn't used here.
        // Both phases run every op even if some fail (#139): one bad route
        // must not hold back every other one, nor the add phase.
        // A slot in both lists changed shape: replaced in one request, so its
        // delete is skipped (#598).
        let replaced: HashSet<Slot> = to_add
            .iter()
            .map(|(slot, _)| *slot)
            .filter(|slot| slot_op(observed_map.get(slot), desired.get(slot)) == SlotOp::Replace)
            .collect();
        let to_remove: Vec<_> = to_remove
            .into_iter()
            .filter(|(slot, _)| !replaced.contains(slot))
            .collect();
        let remove_failed = drain(to_remove.into_iter().map(|((prefix, backup), (key, _))| {
            let message = observed_by_slot.get(&(prefix, backup)).cloned();
            let gateway = show_gateways(key.iter().map(|(gw, _, _)| gw));
            async move {
                if let Some(mut message) = message {
                    // The kernel answers ESRCH to a delete that carries
                    // RTNH_F_ONLINK, which an `Evpn`, tunnel or labelled
                    // route dumps with (a multipath one's per-hop flag is
                    // accepted, #594's spike).
                    message.header.flags.remove(RouteFlags::Onlink);
                    if let Err(e) = self.route_channel.del(message).await {
                        warn!(%prefix, %gateway, table_id, backup, error = %e, "failed to remove route");
                        return Err(((prefix, backup), key, e));
                    }
                    log_removed(prefix, &key, table_id, backup);
                }
                Ok(())
            }
        }))
        .await;

        let placed = std::sync::Mutex::new(Vec::new());
        let placed_ref = &placed;
        let add_failed = drain(to_add.into_iter().map(|(slot, _)| {
            let source = best_routes.get(&slot.0).map(|e| e.source);
            let tunnel = best_routes.get(&slot.0).is_some_and(|e| e.backup_tunnel);
            let want = desired_full.get(&slot).cloned().unwrap_or_default();
            let gone = replaced.contains(&slot).then(|| {
                (
                    observed_by_slot.get(&slot).cloned(),
                    observed_map[&slot].0.clone(),
                )
            });
            async move {
                let replace = gone.is_some();
                let put = self
                    .add_route(table_id, slot.0, &want, source, slot.1, tunnel, replace)
                    .await
                    .map_err(|e| (slot, e))?;
                placed_ref.lock().unwrap().push((slot, put));
                // Deferred or skipped: the old route is still there, drop it.
                match gone {
                    Some((Some(mut message), key)) if !put.sent() => {
                        message.header.flags.remove(RouteFlags::Onlink);
                        self.route_channel
                            .del(message)
                            .await
                            .map_err(|e| (slot, e))?;
                        log_removed(slot.0, &key, table_id, slot.1);
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
        }))
        .await;

        // Seed/correct `apply_delta`'s shadow state from this ground truth
        // (an empty `desired` on `teardown` correctly clears it): `desired`,
        // except where an op failed and the kernel keeps what it had.
        let mut installed = desired_full;
        // The group each installed route uses: what was added, or what a kept
        // route already had.
        let mut gids: HashMap<Slot, u32> = observed_gid
            .iter()
            .filter(|(slot, _)| desired.get(slot) == observed_map.get(slot))
            .map(|(slot, gid)| (*slot, *gid))
            .collect();
        for (slot, put) in placed.into_inner().unwrap() {
            gids.remove(&slot);
            match put {
                // A deferred or skipped add is not in the kernel (#686).
                Placed::Skipped => {
                    installed.remove(&slot);
                }
                Placed::Inline => {}
                Placed::Group(g) => {
                    gids.insert(slot, g);
                }
            }
        }
        let mut first_error = None;
        for (slot, e) in add_failed {
            // A failed replace leaves what the kernel had (like a failed
            // delete below); a failed add leaves nothing.
            gids.remove(&slot);
            match replaced.contains(&slot).then(|| &observed_map[&slot]) {
                Some((key, _)) => {
                    if let Some(g) = observed_gid.get(&slot) {
                        gids.insert(slot, *g);
                    }
                    installed.insert(slot, hops_of(key))
                }
                None => installed.remove(&slot),
            };
            first_error.get_or_insert(e);
        }
        for (slot, key, e) in remove_failed {
            if let Some(g) = observed_gid.get(&slot) {
                gids.insert(slot, *g);
            }
            installed.insert(slot, hops_of(&key));
            first_error.get_or_insert(e);
        }
        self.installed.lock().unwrap().insert(table_id, installed);
        if let Some(t) = self.nexthops.lock().unwrap().get_mut(&table_id) {
            t.reset_slots(gids, stale_groups);
        }
        self.collect_garbage(table_id).await;
        first_error.map_or(Ok(()), Err)
    }
}

#[async_trait]
impl RibDriver for LinuxRibDriver {
    async fn apply(
        &self,
        table_name: &str,
        best_routes: &HashMap<IpNet, RibEntry>,
    ) -> Result<(), DriverError> {
        debug!(table = %table_name, routes = best_routes.len(), "applying routes to kernel");
        let table_id = table_registry::ensure_table_id(&self.registry_path, table_name)?;
        let vrf_ifname = table_registry::vrf_ifname(table_id);
        self.ensure_vrf(&vrf_ifname, table_id).await?;
        let (resolved, pending) = self
            .resolve_pinned(best_routes.iter().map(|(p, e)| (*p, e)))
            .await;
        self.reconcile_routes(table_id, &resolved, self.keep_stale.load(Ordering::SeqCst))
            .await?;
        pending.map_or(Ok(()), Err)
    }

    fn keep_stale(&self, on: bool) {
        self.keep_stale.store(on, Ordering::SeqCst);
    }

    #[allow(unsafe_code, reason = "if_indextoname(3) FFI")]
    fn interface_name(&self, ifindex: u32) -> Option<String> {
        let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
        // SAFETY: `buf` is IF_NAMESIZE bytes as if_indextoname(3) requires; on
        // success it holds a NUL-terminated name.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- if_indextoname(3) FFI, audited above
        let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
        if p.is_null() {
            return None;
        }
        // SAFETY: non-null return: `buf` is NUL-terminated.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- NUL-terminated by if_indextoname
        let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
        Some(name.to_string_lossy().into_owned())
    }

    async fn apply_delta(
        &self,
        table_name: &str,
        changes: &HashMap<IpNet, Option<RibEntry>>,
    ) -> Result<(), DriverError> {
        debug!(table = %table_name, changed = changes.len(), "applying route deltas to kernel");
        let table_id = table_registry::ensure_table_id(&self.registry_path, table_name)?;
        let vrf_ifname = table_registry::vrf_ifname(table_id);
        self.ensure_vrf(&vrf_ifname, table_id).await?;
        let (resolved, pending) = self
            .resolve_pinned(changes.iter().filter_map(|(p, e)| Some((*p, e.as_ref()?))))
            .await;
        // A removal passes through; an unresolved change is left out.
        let changes: HashMap<_, _> = changes
            .iter()
            .filter_map(|(p, e)| match e {
                None => Some((*p, None)),
                Some(_) => resolved.get(p).map(|r| (*p, Some(r.clone()))),
            })
            .collect();
        self.apply_delta_impl(table_id, &changes).await?;
        pending.map_or(Ok(()), Err)
    }

    async fn teardown(&self, table_name: &str) -> Result<(), DriverError> {
        let Some(table_id) = table_registry::lookup_table_id(&self.registry_path, table_name)
        else {
            debug!(table = %table_name, "no table id allocated, nothing to tear down");
            return Ok(());
        };
        self.remove_pop_route(table_name, table_id).await?;
        self.sync_ilm(table_name, &[]).await?;
        self.reconcile_routes(table_id, &HashMap::new(), false)
            .await?;
        let l3 = self.l3.lock().unwrap().remove(&table_id);
        if let Some(l3) = l3 {
            self.remove_l3vni(l3.vni).await?;
        }
        self.remove_tunnel(table_id).await?;

        let vrf_ifname = table_registry::vrf_ifname(table_id);
        if let Some(link) = self.find_link(&vrf_ifname).await? {
            self.handle.link().del(link.header.index).execute().await?;
            info!(vrf = %vrf_ifname, table_id, "deleted VRF device");
        }
        Ok(())
    }

    async fn vrf_name(&self, table_name: &str) -> Option<String> {
        table_registry::lookup_table_id(&self.registry_path, table_name)
            .map(table_registry::vrf_ifname)
    }

    async fn table_id(&self, table_name: &str) -> Option<u32> {
        table_registry::lookup_table_id(&self.registry_path, table_name)
    }

    async fn sync_tunnel(&self, table_name: &str, enabled: bool) -> Result<(), DriverError> {
        let table_id = table_registry::ensure_table_id(&self.registry_path, table_name)?;
        if !enabled {
            return self.remove_tunnel(table_id).await;
        }
        let vrf = self
            .ensure_vrf(&table_registry::vrf_ifname(table_id), table_id)
            .await?;
        let name = tunnel_name(table_id);
        let index = if let Some(link) = self.find_link(&name).await? {
            link.header.index
        } else {
            // NBMA ipip (no remote): the outer destination is each route's
            // gateway, and `dev <vrf>` makes the outer lookup use the VRF's
            // table. An `external` (collect_md) device would look it up in
            // main instead — see #187's kernel spike.
            self.handle
                .link()
                .add(
                    LinkIpIp::new(&name)
                        .dev(vrf)
                        .controller(vrf)
                        .mtu(TUNNEL_MTU)
                        .build(),
                )
                .execute()
                .await?;
            let index = self
                .find_link(&name)
                .await?
                .map(|l| l.header.index)
                .ok_or_else(|| DriverError::Other(format!("{name} does not exist (yet)")))?;
            info!(device = %name, table_id, "created remote lfa tunnel device");
            index
        };
        let mut add = self
            .handle
            .address()
            .add(index, IpAddr::V4(TUNNEL_ADDRESS), 32)
            .replace();
        add.message_mut().header.scope = SCOPE_HOST.into();
        add.execute().await?;
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await?;
        self.tunnels.lock().unwrap().insert(table_id, index);
        Ok(())
    }

    async fn sync_l3vni(
        &self,
        table_name: &str,
        l3: Option<&L3Vni>,
        remotes: &BTreeMap<IpAddr, Mac>,
    ) -> Result<Option<Mac>, DriverError> {
        let table_id = table_registry::ensure_table_id(&self.registry_path, table_name)?;
        let mut prev = self.l3.lock().unwrap().get(&table_id).cloned();
        // Gone, or now another VNI: the old devices go first.
        if let Some(p) = prev.take_if(|p| l3.is_none_or(|l| l.vni != p.vni)) {
            self.l3.lock().unwrap().remove(&table_id);
            self.remove_l3vni(p.vni).await?;
        }
        let Some(l3) = l3 else {
            return Ok(None);
        };
        let vrf = self
            .ensure_vrf(&table_registry::vrf_ifname(table_id), table_id)
            .await?;
        let (rmac, state) = self.build_l3vni(vrf, l3, remotes, prev.as_ref()).await?;
        self.l3.lock().unwrap().insert(table_id, state);
        Ok(Some(rmac))
    }

    async fn sync_mpls(&self, table_name: &str, m: Option<&Mpls>) -> Result<(), DriverError> {
        let Some(m) = m else {
            return match table_registry::lookup_table_id(&self.registry_path, table_name) {
                Some(table_id) => self.remove_pop_route(table_name, table_id).await,
                None => Ok(()),
            };
        };
        mpls::check_label(m.label)?;
        let table_id = table_registry::ensure_table_id(&self.registry_path, table_name)?;
        let vrf_name = table_registry::vrf_ifname(table_id);
        let vrf = self.ensure_vrf(&vrf_name, table_id).await?;
        self.sysctl.ensure_platform_labels(m.label)?;
        let underlay_vrf = match &m.underlay {
            Some(u) => self.underlay_vrf(u).await?,
            None => None,
        };

        // Converge the AF_MPLS routes into our VRF: a stale label (a changed
        // `vpn.label`, or one left by a previous run) goes first, then ours.
        let mut existing = Vec::new();
        let mut dump = self
            .handle
            .route()
            .get(RouteMessageBuilder::<MplsLabel>::new().build())
            .execute();
        while let Some(route) = dump.try_next().await? {
            if let Some(pop) = mpls::pop_route_of(&route) {
                existing.push(pop);
            }
        }
        for (label, _) in existing
            .iter()
            .filter(|(l, oif)| *oif == Some(vrf) && *l != m.label)
        {
            self.del_pop_route(*label, vrf).await?;
            info!(table = %table_name, vrf = %vrf_name, label, "removed mpls pop route");
        }
        if !existing.contains(&(m.label, Some(vrf))) {
            self.handle
                .route()
                .add(mpls::pop_route_msg(m.label, vrf))
                .replace()
                .execute()
                .await?;
            info!(table = %table_name, vrf = %vrf_name, label = m.label, "installed mpls pop route");
        }
        self.mpls.lock().unwrap().insert(
            table_id,
            MplsState {
                label: m.label,
                vrf,
                underlay_vrf,
            },
        );
        Ok(())
    }

    async fn sync_ilm(&self, table_name: &str, routes: &[IlmRoute]) -> Result<(), DriverError> {
        routes.iter().try_for_each(mpls::check_ilm)?;
        let table_id = if routes.is_empty() {
            match table_registry::lookup_table_id(&self.registry_path, table_name) {
                Some(id) => id,
                None => return Ok(()),
            }
        } else {
            table_registry::ensure_table_id(&self.registry_path, table_name)?
        };
        let vrf_name = table_registry::vrf_ifname(table_id);
        let vrf = if routes.is_empty() {
            match self.find_link(&vrf_name).await? {
                Some(l) => l.header.index,
                None => return Ok(()),
            }
        } else {
            self.ensure_vrf(&vrf_name, table_id).await?
        };
        if let Some(max) = routes.iter().map(|r| r.label).max() {
            self.sysctl.ensure_platform_labels(max)?;
        }

        // Resolve every hop's egress; an entry with none resolvable waits.
        let mut want: BTreeMap<u32, Hops> = BTreeMap::new();
        for r in routes {
            let mut hops = Vec::new();
            for h in &r.hops {
                let dev = match h.interface_id {
                    Some(d) => Some(d),
                    None => self.egress_in(vrf, h.gateway).await,
                };
                match dev {
                    Some(d) => hops.push(NextHop {
                        interface_id: Some(d),
                        ..h.clone()
                    }),
                    None => {
                        warn!(label = r.label, gateway = %h.gateway, table = %table_name, "mpls ilm next hop skipped: unresolved");
                    }
                }
            }
            if hops.is_empty() && !r.hops.is_empty() {
                continue;
            }
            want.insert(r.label, hops);
        }

        // What of ours is in the kernel: our protocol, leaving over this
        // VRF's interfaces (AF_MPLS is per netns, shared by every table).
        let mut owned = HashSet::from([vrf]);
        let mut links = self.handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            if master_of(&link) == Some(vrf) {
                owned.insert(link.header.index);
            }
        }
        let mut present = BTreeSet::new();
        let mut dump = self
            .handle
            .route()
            .get(RouteMessageBuilder::<MplsLabel>::new().build())
            .execute();
        while let Some(route) = dump.try_next().await? {
            if let Some((label, oifs)) = mpls::ilm_of(&route)
                && oifs.iter().any(|o| owned.contains(o))
            {
                present.insert(label);
            }
        }
        let shadow = self
            .ilm
            .lock()
            .unwrap()
            .remove(&table_id)
            .unwrap_or_default();
        let mut done = BTreeMap::new();
        for label in present.iter().filter(|l| !want.contains_key(l)) {
            self.del_pop_route(*label, vrf).await?;
            info!(table = %table_name, label, "removed mpls ilm route");
        }
        let mut first_err = None;
        for (label, hops) in want {
            if present.contains(&label) && shadow.get(&label) == Some(&hops) {
                done.insert(label, hops);
                continue;
            }
            let msg = mpls::ilm_route_msg(
                &IlmRoute {
                    label,
                    hops: hops.clone(),
                },
                vrf,
            );
            match self.handle.route().add(msg).replace().execute().await {
                Ok(()) => {
                    let out: Vec<_> = hops.iter().map(|h| &h.labels).collect();
                    let gateway = show_gateways(hops.iter().map(|h| &h.gateway));
                    info!(table = %table_name, label, out = ?out, %gateway, "installed mpls ilm route");
                    done.insert(label, hops);
                }
                Err(e) => {
                    warn!(table = %table_name, label, error = %e, "failed to install mpls ilm route");
                    first_err.get_or_insert(e);
                }
            }
        }
        self.ilm.lock().unwrap().insert(table_id, done);
        first_err.map_or(Ok(()), |e| Err(e.into()))
    }
}

/// errno(3) `EINVAL`: the kernel refuses this nexthop combination.
const EINVAL: i32 = 22;
/// errno(3) `ENOSYS`.
const ENOSYS: i32 = 38;
/// errno(3) `EOPNOTSUPP`.
const EOPNOTSUPP: i32 = 95;

/// Runs one blocking `nos-nexthop` request on the blocking pool.
async fn nh_send(nh: Nexthop, tolerate: i32) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || nos_nexthop::send(&nh, tolerate))
        .await
        .map_err(std::io::Error::other)?
}

/// The route key each group of a nexthop dump stands for (members' gateway,
/// link-local oif and labels, as `key()` makes them): what `extract_route`
/// reads an `RTA_NH_ID` route as.
fn group_keys(records: &[NexthopRecord]) -> HashMap<u32, Key> {
    let hops: HashMap<u32, &NexthopRecord> = records
        .iter()
        .filter(|r| r.gateway.is_some() && !r.fdb)
        .map(|r| (r.id, r))
        .collect();
    records
        .iter()
        .filter_map(|r| {
            let mut k: Key = r
                .group
                .as_ref()?
                .iter()
                .map(|(id, _)| {
                    let h = hops.get(id)?;
                    let gw = unmap(h.gateway?);
                    Some((gw, key_ifindex(gw, h.oif), h.labels.clone()))
                })
                .collect::<Option<_>>()?;
            k.sort_unstable();
            Some((r.id, k))
        })
        .collect()
}

/// An IPv4-mapped IPv6 gateway as the IPv4 one it stands for.
fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// `prefix via nexthop <gid>`: no gateway, oif, multipath or encap of its own.
/// Also what a delete of such a route needs (the kernel refuses a delete that
/// names a gateway for a route using a nexthop object).
fn group_route(prefix: IpNet, table_id: u32, gid: u32) -> Option<RouteMessage> {
    let mut route = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(prefix.addr(), prefix.prefix_len())
        .ok()?
        .table_id(table_id)
        .protocol(NOS_RTPROT)
        .build();
    route.header.scope = RouteScope::Universe;
    route.attributes.push(RouteAttribute::NhId(gid));
    Some(route)
}

impl LinuxRibDriver {
    /// The nexthop objects of `table_id`'s id range, as the kernel has them. A
    /// kernel that cannot list them has no nexthop objects: groups are off.
    async fn nh_dump(&self, table_id: u32) -> Vec<NexthopRecord> {
        let range = NexthopTable::new(table_id).range();
        match tokio::task::spawn_blocking(move || nos_nexthop::dump(range)).await {
            Ok(Ok(records)) => records,
            other => {
                let e = match other {
                    Ok(r) => r.err().map(|e| e.to_string()),
                    Err(e) => Some(e.to_string()),
                };
                warn!(table_id, error = ?e, "cannot list nexthops, installing multipath routes inline");
                self.disable_nexthop_groups();
                Vec::new()
            }
        }
    }

    /// Makes sure `table_id` has a `NexthopTable`: seeded from the kernel, so
    /// ids of objects an earlier `nos-ribd` left are not handed out again.
    async fn ensure_nh_table(&self, table_id: u32) {
        if self.nexthops.lock().unwrap().contains_key(&table_id) {
            return;
        }
        let records = self.nh_dump(table_id).await;
        let mut tables = self.nexthops.lock().unwrap();
        tables.entry(table_id).or_insert_with(|| {
            let mut t = NexthopTable::new(table_id);
            t.seed(&records);
            t
        });
    }

    /// The sorted group key of `hops` for a route to `prefix`: each member's
    /// egress is looked up now. `None`: a member has no egress (recorded as
    /// not groupable).
    async fn member_key(
        &self,
        table_id: u32,
        prefix: IpNet,
        hops: &[NextHop],
        onlink: bool,
    ) -> Option<GroupKey> {
        let mapped = map_hops(prefix.addr().is_ipv4(), hops);
        let mut members: GroupKey = Vec::with_capacity(hops.len());
        for (h, m) in hops.iter().zip(&mapped) {
            // A nexthop object has no table to resolve its gateway in: the
            // egress is looked up in this table's VRF now.
            let oif = match h.interface_id {
                Some(o) => Some(o),
                None => self.egress_of(table_id, h.gateway).await,
            };
            let Some(oif) = oif else {
                self.reject(hops, &std::io::Error::other("no egress for a member"));
                return None;
            };
            members.push((m.gateway, Some(oif), onlink, m.labels.clone()));
        }
        members.sort();
        Some(members)
    }

    /// The group of `hops` for a route to `prefix`, created with its hop
    /// nexthops when missing. `None` means install inline: no resolvable
    /// egress, out of ids, or a kernel answer that refuses groups (recorded).
    async fn ensure_group(
        &self,
        table_id: u32,
        prefix: IpNet,
        hops: &[NextHop],
        onlink: bool,
    ) -> Result<Option<u32>, DriverError> {
        let Some(members) = self.member_key(table_id, prefix, hops, onlink).await else {
            return Ok(None);
        };
        let _create = self.create_lock.lock().await;
        self.ensure_nh_table(table_id).await;
        let plan = {
            let mut tables = self.nexthops.lock().unwrap();
            tables.get_mut(&table_id).and_then(|t| t.ensure(&members))
        };
        let Some(plan) = plan else {
            self.reject(hops, &std::io::Error::other("nexthop ids exhausted"));
            return Ok(None);
        };
        let mut created = Vec::new();
        let mut result = Ok(());
        for (id, (gateway, oif, onlink, labels)) in &plan.new_hops {
            let nh = Nexthop::Gateway(Gateway {
                id: *id,
                gateway: *gateway,
                oif: *oif,
                onlink: *onlink,
                labels: labels.clone(),
                fdb: false,
                replace: true,
            });
            result = nh_send(nh, 0).await;
            if result.is_err() {
                break;
            }
            created.push(*id);
        }
        if result.is_ok() && plan.new_group {
            let nh = Nexthop::Group(Group {
                id: plan.group,
                members: plan.members.iter().map(|m| (*m, 1)).collect(),
                fdb: false,
            });
            result = nh_send(nh, 0).await;
            if result.is_ok() {
                info!(
                    id = plan.group,
                    members = plan.members.len(),
                    table_id,
                    "installed nexthop group"
                );
            }
        }
        let Err(e) = result else {
            return Ok(Some(plan.group));
        };
        if let Some(t) = self.nexthops.lock().unwrap().get_mut(&table_id) {
            t.forget(&plan);
        }
        for id in created {
            let _ = nh_send(Nexthop::Delete { id }, ENOENT).await;
        }
        if e.raw_os_error()
            .is_some_and(|c| matches!(c, EOPNOTSUPP | ENOSYS))
        {
            warn!(table_id, error = %e, "kernel has no nexthop groups, installing multipath routes inline");
            self.disable_nexthop_groups();
            Ok(None)
        } else if e.raw_os_error() == Some(EINVAL) || e.kind() == std::io::ErrorKind::InvalidInput {
            self.reject(hops, &e);
            Ok(None)
        } else {
            Err(DriverError::Registry(e))
        }
    }

    /// Remembers that `hops` cannot be a group (refused, no egress, no ids): they
    /// install inline, and a later pass does not try again (no replace loop).
    fn reject(&self, hops: &[NextHop], e: &std::io::Error) {
        let k = key(hops);
        if self.rejected.lock().unwrap().insert(k.clone()) {
            let gateway = show_gateways(k.iter().map(|(gw, _, _)| gw));
            warn!(%gateway, error = %e, "no nexthop group for these hops, installing them inline");
        }
    }

    /// Deletes the groups, then the hop nexthops, nothing of ours uses
    /// (deleting a nexthop deletes the routes using it, so this runs after a
    /// pass has removed or replaced its routes).
    async fn collect_garbage(&self, table_id: u32) {
        let (groups, hops) = {
            let mut tables = self.nexthops.lock().unwrap();
            match tables.get_mut(&table_id) {
                Some(t) => t.take_unreferenced(),
                None => return,
            }
        };
        for id in groups.iter().chain(&hops) {
            if let Err(e) = nh_send(Nexthop::Delete { id: *id }, ENOENT).await {
                warn!(id, table_id, error = %e, "failed to remove nexthop");
            } else if groups.contains(id) {
                info!(id, table_id, "removed nexthop group");
            }
        }
    }
}

impl LinuxRibDriver {
    /// The ifindex of `underlay`'s VRF device, `None` before its `nos-ribd`
    /// created it (the next `sync_mpls` tries again).
    async fn underlay_vrf(&self, underlay: &str) -> Result<Option<u32>, DriverError> {
        let Some(id) = table_registry::lookup_table_id(&self.registry_path, underlay) else {
            return Ok(None);
        };
        Ok(self
            .find_link(&table_registry::vrf_ifname(id))
            .await?
            .map(|l| l.header.index))
    }

    /// Deletes one `AF_MPLS` route; one already gone counts as done.
    async fn del_pop_route(&self, label: u32, vrf: u32) -> Result<(), DriverError> {
        match self
            .handle
            .route()
            .del(mpls::pop_route_msg(label, vrf))
            .execute()
            .await
        {
            Err(rtnetlink::Error::NetlinkError(e))
                if e.raw_code() == -ESRCH || e.raw_code() == -ENOENT =>
            {
                Ok(())
            }
            r => r.map_err(Into::into),
        }
    }

    /// Removes the pop route `sync_mpls` installed for `table_id`, if any.
    async fn remove_pop_route(&self, table_name: &str, table_id: u32) -> Result<(), DriverError> {
        let Some(st) = self.mpls.lock().unwrap().remove(&table_id) else {
            return Ok(());
        };
        self.del_pop_route(st.label, st.vrf).await?;
        info!(table = %table_name, vrf = %table_registry::vrf_ifname(table_id), label = st.label, "removed mpls pop route");
        Ok(())
    }
}

/// The kernel refused an add because the slot is taken (`EEXIST`).
fn is_eexist(e: &DriverError) -> bool {
    matches!(e, DriverError::Netlink(rtnetlink::Error::NetlinkError(m))
        if m.code.is_some_and(|c| c.get() == -17))
}

/// Private `rtm_protocol` stamped on every route NOS installs, and the only one
/// it ever dumps or deletes: a route of any other protocol (an operator's
/// `proto boot`, a kernel route) in a NOS table is left alone (#1514). 200 is
/// free in iproute2's `rt_protos` and the kernel needs no registration.
pub const NOS_RTPROT: RouteProtocol = RouteProtocol::Other(200);

/// Extracts `((prefix, is_backup), key)` from a dumped `RouteMessage`: the
/// sorted `(gateway, link-local ifindex, labels)` triples (`Key`), or `None` for a route we don't
/// manage (no gateway — e.g. a kernel-internal entry a VRF device creates on
/// its own, or an unsupported address family like MPLS). An ECMP route has no
/// `RTA_GATEWAY` of its own: its gateways are inside `RTA_MULTIPATH`, one per
/// next hop, each with its own `RTA_ENCAP` — missing that would make a
/// multipath route look unmanaged, re-added (EEXIST) on every `apply` and
/// never deleted. A single-hop route's labels are the route-level encap. A
/// missing `Destination` attribute means the default route (kernel omits it
/// for 0/0), so it falls back to the family's unspecified address. A
/// blackhole is a managed discard slot (empty key). Only a route with
/// `NOS_RTPROT`, the protocol `build_route` gives every route, is ours: an
/// operator's `ip route add …` (`RTPROT_BOOT`) or a VRF recipe's `unreachable
/// default metric …` is left alone.
// ponytail: kernels before 4.11 dump IPv6 ECMP siblings as separate routes,
// not one `RTA_MULTIPATH`; merge siblings per slot here if one must be
// supported.
/// A `RTM_F_CLONED` entry is a kernel exception (e.g. the PMTU a tunnel
/// learned), dumped beside the route it belongs to: never a route of ours.
#[cfg(test)]
fn extract_route(route: &RouteMessage) -> Option<(Slot, Key)> {
    extract(route, &HashMap::new()).map(|(slot, key, _)| (slot, key))
}

/// `extract_route`, and the nexthop group of a route installed as `RTA_NH_ID`
/// (#1587): its key is the group's (`groups`, from `group_keys`); a route over
/// a group not in `groups` (another daemon's, or a vanished one) is not ours.
/// The kernel's compat mode also dumps such a route's gateways: the id wins.
fn extract(route: &RouteMessage, groups: &HashMap<u32, Key>) -> Option<(Slot, Key, Option<u32>)> {
    if route.header.protocol != NOS_RTPROT || route.header.flags.contains(RouteFlags::Cloned) {
        return None;
    }
    let nh_id = route.attributes.iter().find_map(|a| match a {
        RouteAttribute::NhId(id) => Some(*id),
        _ => None,
    });
    let from_group = match nh_id {
        Some(id) => Some(groups.get(&id)?.clone()),
        None => None,
    };
    // `build_route` sends a VPNv6 route to an IPv4 PE through its IPv4-mapped
    // address; the desired state says IPv4.
    let gateway_of = |attrs: &[RouteAttribute]| {
        attrs.iter().find_map(|attr| match attr {
            RouteAttribute::Gateway(addr) => route_address_to_ip(addr).map(|ip| match ip {
                IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
                IpAddr::V4(_) => ip,
            }),
            _ => None,
        })
    };
    let mut key: Key = match route.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::MultiPath(hops) => Some(hops),
        _ => None,
    }) {
        _ if from_group.is_some() => from_group.unwrap_or_default(),
        Some(hops) => hops
            .iter()
            .filter_map(|hop| {
                let gw = gateway_of(&hop.attributes)?;
                Some((
                    gw,
                    key_ifindex(gw, Some(hop.interface_index)),
                    mpls::labels_of(&hop.attributes),
                ))
            })
            .collect(),
        None => gateway_of(&route.attributes)
            .map(|gw| {
                let oif = route.attributes.iter().find_map(|a| match a {
                    RouteAttribute::Oif(i) => Some(*i),
                    _ => None,
                });
                (gw, key_ifindex(gw, oif), mpls::labels_of(&route.attributes))
            })
            .into_iter()
            .collect(),
    };
    let discard = route.header.kind == RouteType::BlackHole;
    if key.is_empty() && !discard {
        return None;
    }
    key.sort_unstable();

    let destination = route
        .attributes
        .iter()
        .find_map(|attr| match attr {
            RouteAttribute::Destination(addr) => route_address_to_ip(addr),
            _ => None,
        })
        .unwrap_or(match route.header.address_family {
            AddressFamily::Inet => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            AddressFamily::Inet6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            _ => return None,
        });

    let backup = route.attributes.iter().any(|attr| {
        matches!(
            attr,
            RouteAttribute::Priority(BACKUP_METRIC_V4 | BACKUP_METRIC_V6)
        )
    });

    IpNet::new(destination, route.header.destination_prefix_length)
        .ok()
        .map(|prefix| ((prefix, backup), key, nh_id))
}

/// The hops a dumped `key` stands for (an interface only for a link-local
/// gateway).
fn hops_of(key: &Key) -> Hops {
    key.iter()
        .map(|(gateway, ifindex, labels)| NextHop {
            gateway: *gateway,
            interface_id: *ifindex,
            labels: labels.clone(),
        })
        .collect()
}

/// The "removed route" log line, or "removed labelled route" (each hop's
/// labels, in `key` order) for one that pushed labels.
fn log_removed(prefix: IpNet, key: &Key, table_id: u32, backup: bool) {
    let gateway = show_gateways(key.iter().map(|(gw, _, _)| gw));
    if key.iter().all(|(_, _, l)| l.is_empty()) {
        let discard = key.is_empty();
        info!(%prefix, %gateway, table_id, backup, discard, "removed route");
    } else {
        let labels: Vec<_> = key.iter().map(|(_, _, l)| l).collect();
        info!(%prefix, labels = ?labels, %gateway, table_id, "removed labelled route");
    }
}

// A VPNv6 route (RFC 4659) leaves toward IPv4 PEs: the kernel refuses an
// IPv6 route with `RTA_VIA` ("IPv6 does not support RTA_VIA"), but takes
// the IPv4-mapped gateway (`via ::ffff:a.b.c.d`) and sends the labelled
// packet to the PE's IPv4 neighbour. `extract_route` maps it back.
fn map_hops(v4: bool, hops: &[NextHop]) -> Hops {
    if v4 || hops.is_empty() || !hops.iter().all(|h| h.gateway.is_ipv4()) {
        return hops.to_vec();
    }
    hops.iter()
        .map(|h| match h.gateway {
            IpAddr::V4(a) => NextHop {
                gateway: IpAddr::V6(a.to_ipv6_mapped()),
                ..h.clone()
            },
            IpAddr::V6(_) => h.clone(),
        })
        .collect()
}

/// Builds the `RouteMessage` for one kernel route, `None` on a
/// prefix/gateway address-family mismatch (or a backup with no hop). No hop
/// is a discard (`RTN_BLACKHOLE`) route, one is `RTA_GATEWAY` (+ `RTA_OIF`),
/// two or more are `RTA_MULTIPATH`. `backup` sets the family's backup metric.
/// A hop's labels are an MPLS encap pushing them: the route-level `RTA_ENCAP`
/// for one hop, each `RTA_MULTIPATH` next hop's own for several. `onlink` is
/// `RTNH_F_ONLINK`, on the header for one hop and per next hop for several
/// (the kernel ignores the header's for a multipath route).
fn build_route(
    prefix: IpNet,
    hops: &[NextHop],
    table_id: u32,
    backup: bool,
    onlink: bool,
) -> Option<RouteMessage> {
    let v4 = prefix.addr().is_ipv4();
    let mapped = map_hops(v4, hops);
    let hops = &mapped[..];
    if (backup && hops.is_empty()) || hops.iter().any(|h| h.gateway.is_ipv4() != v4) {
        return None;
    }
    let mut builder = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(prefix.addr(), prefix.prefix_len())
        .ok()?
        .table_id(table_id)
        .protocol(NOS_RTPROT);
    if hops.is_empty() {
        builder = builder.kind(RouteType::BlackHole);
    } else if let [hop] = hops {
        builder = builder.gateway(hop.gateway).ok()?;
        if let Some(interface_id) = hop.interface_id {
            builder = builder.output_interface(interface_id);
        }
        builder = builder.output_mpls(mpls::stack(&hop.labels));
    } else {
        let family = if v4 {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };
        let next_hops = hops
            .iter()
            .map(|h| {
                let nh = RouteNextHopBuilder::new(family).via(h.gateway).ok()?;
                let mut nh = match h.interface_id {
                    Some(index) => nh.interface(index),
                    None => nh,
                }
                .build();
                nh.attributes.extend(mpls::hop_encap(&h.labels));
                if onlink {
                    nh.flags.insert(RouteNextHopFlags::Onlink);
                }
                Some(nh)
            })
            .collect::<Option<Vec<_>>>()?;
        builder = builder.multipath(next_hops);
    }
    if backup {
        builder = builder.priority(if v4 {
            BACKUP_METRIC_V4
        } else {
            BACKUP_METRIC_V6
        });
    }
    let mut route = builder.build();
    if onlink && hops.len() == 1 {
        route.header.flags.insert(RouteFlags::Onlink);
    }
    Some(route)
}

fn route_address_to_ip(addr: &RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(addr) => Some(IpAddr::V4(*addr)),
        RouteAddress::Inet6(addr) => Some(IpAddr::V6(*addr)),
        _ => None,
    }
}

/// Route keys + the gateway(s) each should have (or currently has).
type RouteChanges<K, V> = Vec<(K, V)>;

/// Pure diff, no `rtnetlink` types in its signature: which prefixes need a
/// route added, and which need one removed, to bring `observed` in line
/// with `desired`. A prefix present in both with *different* gateways is
/// reported in both lists (remove the stale one, add the correct one).
fn diff_routes<K: Copy + Eq + std::hash::Hash, V: Clone + PartialEq>(
    observed: &HashMap<K, V>,
    desired: &HashMap<K, V>,
) -> (RouteChanges<K, V>, RouteChanges<K, V>) {
    let mut to_add = Vec::new();
    let mut to_remove = Vec::new();

    for (prefix, gateway) in desired {
        if observed.get(prefix) != Some(gateway) {
            to_add.push((*prefix, gateway.clone()));
        }
    }
    for (prefix, gateway) in observed {
        if desired.get(prefix) != Some(gateway) {
            to_remove.push((*prefix, gateway.clone()));
        }
    }

    (to_add, to_remove)
}

#[cfg(test)]
mod tests {
    #[test]
    fn deferred_install_leaves_slot_unset() {
        let hops: super::Hops = super::Hops::default();
        assert_eq!(super::shadow_after_install(false, &hops), None);
        assert_eq!(super::shadow_after_install(true, &hops), Some(hops.clone()));
    }

    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn k(hops: &[(&str, &[u32])]) -> Key {
        let mut k: Key = hops
            .iter()
            .map(|(g, l)| (addr(g), None, l.to_vec()))
            .collect();
        k.sort_unstable();
        k
    }

    #[test]
    fn a_pinned_interface_sets_the_oif_of_a_link_local_route() {
        let entry = RibEntry {
            prefix: net("2001:db8:9::/48"),
            next_hops: vec![plain("fe80::1")],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: [(addr("fe80::1"), "eth1".to_string())].into(),
        };
        let pinned = pin_interface(&entry, &HashMap::from([("eth1", 7)]));
        assert_eq!(pinned.next_hops[0].interface_id, Some(7));
        let msg = build_route(pinned.prefix, &pinned.next_hops, 100, false, false).unwrap();
        assert_eq!(
            hops_of(&extract_route(&wire(&msg)).unwrap().1)[0].interface_id,
            Some(7)
        );
    }

    #[test]
    fn each_hop_is_pinned_to_its_own_link() {
        let entry = RibEntry {
            prefix: net("2001:db8:9::/48"),
            next_hops: vec![plain("fe80::1"), plain("fe80::2"), plain("fe80::3")],
            source: RouteSource::Static,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: [
                (addr("fe80::1"), "eth0".to_string()),
                (addr("fe80::2"), "eth1".to_string()),
            ]
            .into(),
        };
        let pinned = pin_interface(&entry, &HashMap::from([("eth0", 7), ("eth1", 9)]));
        let oifs: Vec<_> = pinned.next_hops.iter().map(|h| h.interface_id).collect();
        assert_eq!(oifs, [Some(7), Some(9), None]);
        let msg = build_route(pinned.prefix, &pinned.next_hops, 100, false, false).unwrap();
        let back: Vec<_> = hops_of(&extract_route(&wire(&msg)).unwrap().1)
            .iter()
            .map(|h| h.interface_id)
            .collect();
        assert!(back.contains(&Some(7)) && back.contains(&Some(9)));
    }

    #[test]
    fn slot_op_replaces_instead_of_remove_then_add() {
        let one = k(&[("10.0.0.1", &[])]);
        let two = k(&[("10.0.0.1", &[]), ("10.0.0.2", &[])]);
        let labelled = k(&[("10.0.0.1", &[16])]);
        let other = k(&[("10.0.0.9", &[])]);
        let discard: Key = Vec::new();
        assert_eq!(slot_op::<Key>(None, None), SlotOp::Keep);
        assert_eq!(slot_op(Some(&one), None), SlotOp::Remove);
        assert_eq!(slot_op(None, Some(&one)), SlotOp::Add);
        assert_eq!(slot_op(Some(&one), Some(&one)), SlotOp::Keep);
        // shrink, grow, label-only, gateway change, discard <-> gateway
        assert_eq!(slot_op(Some(&two), Some(&one)), SlotOp::Replace);
        assert_eq!(slot_op(Some(&one), Some(&two)), SlotOp::Replace);
        assert_eq!(slot_op(Some(&one), Some(&labelled)), SlotOp::Replace);
        assert_eq!(slot_op(Some(&one), Some(&other)), SlotOp::Replace);
        assert_eq!(slot_op(Some(&discard), Some(&one)), SlotOp::Replace);
        assert_eq!(slot_op(Some(&one), Some(&discard)), SlotOp::Replace);
        // a discard route installed from nothing is an add, not a replace
        assert_eq!(slot_op(None, Some(&discard)), SlotOp::Add);
    }

    #[test]
    fn hops_of_round_trips_a_key() {
        let key = k(&[("10.0.0.1", &[16, 17]), ("10.0.0.2", &[])]);
        assert_eq!(super::key(&hops_of(&key)), key);
    }

    /// #618: the same fe80 gateway on two links is two next hops (a replace),
    /// a global gateway's interface is not part of the key, and a dump reads
    /// the link-local ifindex back (single-hop Oif and multipath).
    #[test]
    fn a_link_local_next_hop_move_is_a_replace() {
        let ll = |oif| key(&[hop("fe80::1", Some(oif), &[])]);
        assert_ne!(ll(10), ll(20));
        assert_eq!(slot_op(Some(&ll(10)), Some(&ll(20))), SlotOp::Replace);
        assert_eq!(slot_op(Some(&ll(10)), Some(&ll(10))), SlotOp::Keep);
        let global = |oif| key(&[hop("2001:db8::1", Some(oif), &[])]);
        assert_eq!(global(10), global(20));

        let p = net("2001:db8:1::/64");
        let single = build_route(p, &[hop("fe80::1", Some(20), &[])], 100, false, false).unwrap();
        assert_eq!(extract_route(&wire(&single)), Some(((p, false), ll(20))));
        // a dump on the stale interface differs from the desired key
        let (_, dumped) = extract_route(&wire(&single)).unwrap();
        assert_eq!(slot_op(Some(&dumped), Some(&ll(10))), SlotOp::Replace);
        assert_eq!(hops_of(&dumped)[0].interface_id, Some(20));

        let hops = vec![hop("fe80::1", Some(10), &[]), hop("fe80::1", Some(20), &[])];
        let multi = build_route(p, &hops, 100, false, false).unwrap();
        assert_eq!(extract_route(&wire(&multi)), Some(((p, false), key(&hops))));
    }

    #[test]
    fn drain_runs_every_op_past_a_failure() {
        let ran = std::sync::atomic::AtomicUsize::new(0);
        let errors = futures::executor::block_on(drain((0..200).map(|i| {
            let ran = &ran;
            async move {
                ran.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if i % 50 == 0 {
                    Err(i)
                } else {
                    Ok(())
                }
            }
        })));
        assert_eq!(ran.into_inner(), 200);
        let mut errors = errors;
        errors.sort_unstable();
        assert_eq!(errors, vec![0, 50, 100, 150]);
    }

    #[test]
    fn identical_state_has_nothing_to_do() {
        let mut m = HashMap::new();
        m.insert(net("10.0.0.0/24"), addr("10.0.0.1"));
        let (add, remove) = diff_routes(&m, &m);
        assert_eq!(add, [] as [(ipnet::IpNet, std::net::IpAddr); 0]);
        assert_eq!(remove, [] as [(ipnet::IpNet, std::net::IpAddr); 0]);
    }

    #[test]
    fn missing_route_is_added() {
        let observed = HashMap::new();
        let mut desired = HashMap::new();
        desired.insert(net("10.0.0.0/24"), addr("10.0.0.1"));

        let (add, remove) = diff_routes(&observed, &desired);
        assert_eq!(add, vec![(net("10.0.0.0/24"), addr("10.0.0.1"))]);
        assert_eq!(remove, [] as [(ipnet::IpNet, std::net::IpAddr); 0]);
    }

    #[test]
    fn stale_route_is_removed() {
        let mut observed = HashMap::new();
        observed.insert(net("10.0.0.0/24"), addr("10.0.0.1"));
        let desired = HashMap::new();

        let (add, remove) = diff_routes(&observed, &desired);
        assert_eq!(add, [] as [(ipnet::IpNet, std::net::IpAddr); 0]);
        assert_eq!(remove, vec![(net("10.0.0.0/24"), addr("10.0.0.1"))]);
    }

    #[test]
    fn backup_slot_is_independent_of_primary() {
        let p = net("10.0.0.0/24");
        let observed = HashMap::from([((p, false), addr("10.0.0.1"))]);
        let desired = HashMap::from([
            ((p, false), addr("10.0.0.1")),
            ((p, true), addr("10.0.0.2")),
        ]);
        let (add, remove) = diff_routes(&observed, &desired);
        assert_eq!(add, vec![((p, true), addr("10.0.0.2"))]);
        assert_eq!(remove, [] as [((ipnet::IpNet, bool), std::net::IpAddr); 0]);

        // Backup vanishing removes only the backup.
        let (add, remove) = diff_routes(&desired, &observed);
        assert_eq!(add, [] as [((ipnet::IpNet, bool), std::net::IpAddr); 0]);
        assert_eq!(remove, vec![((p, true), addr("10.0.0.2"))]);
    }

    fn hop(gw: &str, oif: Option<u32>, labels: &[u32]) -> NextHop {
        NextHop {
            gateway: addr(gw),
            interface_id: oif,
            labels: labels.to_vec(),
        }
    }

    fn plain(gw: &str) -> NextHop {
        hop(gw, None, &[])
    }

    /// What the kernel hands back: the message emitted to bytes and parsed
    /// again, so a next hop's encap decodes as a dump's does (opaque without
    /// a route-level `RTA_ENCAP_TYPE`).
    fn wire(route: &RouteMessage) -> RouteMessage {
        use netlink_packet_core::{Emitable as _, Parseable as _};
        let mut buf = vec![0; route.buffer_len()];
        route.emit(&mut buf);
        RouteMessage::parse(buf.as_slice()).unwrap()
    }

    #[test]
    fn slots_lists_backup_after_primary() {
        let p = net("10.0.0.0/24");
        let entry = RibEntry {
            prefix: p,
            next_hops: vec![plain("10.0.0.1")],
            source: RouteSource::Ospf,
            backup: Some(addr("10.0.0.2")),
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        };
        assert_eq!(
            slots(p, &entry),
            vec![
                ((p, false), vec![plain("10.0.0.1")]),
                ((p, true), vec![plain("10.0.0.2")]),
            ]
        );
    }

    #[test]
    fn ecmp_route_round_trips_through_multipath() {
        let p = net("203.0.113.80/32");
        let hops = vec![plain("10.0.0.9"), hop("10.0.0.2", Some(7), &[])];
        let route = build_route(p, &hops, 100, false, false).unwrap();
        assert!(!route
            .attributes
            .iter()
            .any(|a| matches!(a, RouteAttribute::Gateway(_))));
        let Some(RouteAttribute::MultiPath(nh)) = route
            .attributes
            .iter()
            .find(|a| matches!(a, RouteAttribute::MultiPath(_)))
        else {
            panic!("no RTA_MULTIPATH: {route:?}");
        };
        assert_eq!(nh[1].interface_index, 7);
        assert!(!nh[1].flags.contains(RouteNextHopFlags::Onlink));
        // What a dump of it gives back: both gateways, sorted, primary slot.
        assert_eq!(
            extract_route(&wire(&route)),
            Some((
                (p, false),
                vec![
                    (addr("10.0.0.2"), None, vec![]),
                    (addr("10.0.0.9"), None, vec![])
                ]
            ))
        );
    }

    #[test]
    fn ipv6_ecmp_route_round_trips_through_multipath() {
        let p = net("2001:db8:80::/48");
        let hops = vec![plain("2001:db8::9"), plain("2001:db8::2")];
        let route = build_route(p, &hops, 100, false, false).unwrap();
        assert_eq!(
            extract_route(&wire(&route)),
            Some((
                (p, false),
                vec![
                    (addr("2001:db8::2"), None, vec![]),
                    (addr("2001:db8::9"), None, vec![])
                ]
            ))
        );
    }

    /// #594: a labelled multipath route carries each hop's encap and
    /// `RTNH_F_ONLINK` on the next hop (not the header), the same gateway
    /// twice with two label stacks stays two hops, and a dump reads every
    /// hop's labels back.
    #[test]
    fn a_labelled_multipath_route_pushes_per_hop_labels_and_reads_them_back() {
        let p = net("10.2.0.0/24");
        let hops = vec![
            hop("10.0.0.3", Some(4), &[200]),
            hop("10.0.0.2", Some(4), &[100]),
            hop("10.0.0.2", Some(4), &[300, 16]),
        ];
        let route = build_route(p, &hops, 100, false, true).unwrap();
        assert!(!route.header.flags.contains(RouteFlags::Onlink));
        let Some(RouteAttribute::MultiPath(nh)) = route
            .attributes
            .iter()
            .find(|a| matches!(a, RouteAttribute::MultiPath(_)))
        else {
            panic!("no RTA_MULTIPATH: {route:?}");
        };
        assert!(nh
            .iter()
            .all(|h| h.flags.contains(RouteNextHopFlags::Onlink)));
        assert!(!route
            .attributes
            .iter()
            .any(|a| matches!(a, RouteAttribute::Encap(_))));
        let want = vec![
            (addr("10.0.0.2"), None, vec![100]),
            (addr("10.0.0.2"), None, vec![300, 16]),
            (addr("10.0.0.3"), None, vec![200]),
        ];
        assert_eq!(key(&hops), want);
        assert_eq!(extract_route(&route), Some(((p, false), want.clone())));
        assert_eq!(extract_route(&wire(&route)), Some(((p, false), want)));
    }

    /// #594: a `VPNv6` multipath route toward IPv4 PEs maps every gateway,
    /// and reads back as the IPv4 gateways with their labels.
    #[test]
    fn a_vpnv6_multipath_route_maps_every_ipv4_gateway() {
        let p = net("fd18:2::/64");
        let hops = vec![
            hop("10.50.0.3", Some(4), &[1000]),
            hop("10.50.0.4", Some(5), &[2000]),
        ];
        let route = build_route(p, &hops, 100, false, true).unwrap();
        assert_eq!(extract_route(&wire(&route)), Some(((p, false), key(&hops))));
        // Mixed families are still a mismatch.
        let mixed = vec![plain("10.50.0.3"), plain("fd18::1")];
        assert!(build_route(p, &mixed, 100, false, false).is_none());
    }

    /// #623: `build_route` writes an IPv6 route over an IPv4 gateway as the
    /// IPv4-mapped `RTA_GATEWAY` with `RTNH_F_ONLINK` and its oif (the path
    /// of EVPN and labelled routes; `add_route` refuses it when unlabelled),
    /// and a dump reads the IPv4 gateway back (no churn in `diff_routes`).
    #[test]
    fn an_ipv6_route_over_an_ipv4_gateway_round_trips_onlink() {
        let p = net("2001:db8:210::/48");
        let hops = vec![hop("10.50.0.6", Some(4), &[])];
        let route = build_route(p, &hops, 100, false, true).unwrap();
        assert!(route.header.flags.contains(RouteFlags::Onlink));
        assert!(route.attributes.iter().any(|a| matches!(
            a,
            RouteAttribute::Gateway(RouteAddress::Inet6(g)) if *g == "::ffff:10.50.0.6".parse::<Ipv6Addr>().unwrap()
        )));
        let want = Some(((p, false), key(&hops)));
        assert_eq!(extract_route(&wire(&route)), want);
    }

    #[test]
    fn a_cloned_exception_is_not_a_route() {
        let p = net("10.62.0.2/32");
        let mut route = build_route(p, &[plain("10.62.0.4")], 100, false, false).unwrap();
        assert!(extract_route(&route).is_some());
        route.header.flags.insert(RouteFlags::Cloned);
        assert_eq!(extract_route(&route), None);
    }

    #[test]
    fn single_hop_route_uses_rta_gateway() {
        let p = net("10.0.0.0/24");
        let route = build_route(p, &[plain("10.0.0.1")], 100, true, false).unwrap();
        assert_eq!(
            extract_route(&route),
            Some(((p, true), vec![(addr("10.0.0.1"), None, vec![])]))
        );
        assert!(!route.header.flags.contains(RouteFlags::Onlink));
        let onlink = build_route(p, &[plain("10.0.0.1")], 100, false, true).unwrap();
        assert!(onlink.header.flags.contains(RouteFlags::Onlink));
        assert!(build_route(p, &[plain("2001:db8::1")], 100, false, false).is_none());
        assert!(build_route(p, &[], 100, true, false).is_none());
    }

    #[test]
    fn discard_route_round_trips_as_a_managed_blackhole() {
        let p = net("10.9.0.0/16");
        let route = build_route(p, &[], 100, false, false).unwrap();
        assert_eq!(route.header.kind, RouteType::BlackHole);
        assert!(!route
            .attributes
            .iter()
            .any(|a| matches!(a, RouteAttribute::Gateway(_) | RouteAttribute::Oif(_))));
        assert_eq!(extract_route(&route), Some(((p, false), vec![])));
        // An operator's own blackhole (iproute2's default `proto boot`) is
        // not ours, so never deleted.
        let mut foreign = route;
        foreign.header.protocol = RouteProtocol::Boot;
        assert_eq!(extract_route(&foreign), None);
    }

    #[test]
    fn only_nos_protocol_routes_are_extracted() {
        let p = net("10.9.0.0/16");
        let hops = [plain("10.0.0.1"), plain("10.0.0.2")];
        for built in [
            build_route(p, &[plain("10.0.0.1")], 100, false, false).unwrap(),
            build_route(p, &hops, 100, false, false).unwrap(),
            build_route(p, &[], 100, false, false).unwrap(),
            build_route(p, &[plain("10.0.0.1")], 100, true, false).unwrap(),
        ] {
            assert_eq!(built.header.protocol, NOS_RTPROT);
            let mut route = wire(&built);
            assert!(extract_route(&route).is_some());
            for other in [
                RouteProtocol::Boot,
                RouteProtocol::Static,
                RouteProtocol::Ospf,
                RouteProtocol::Kernel,
            ] {
                route.header.protocol = other;
                assert_eq!(extract_route(&route), None);
            }
        }
    }

    #[test]
    fn eexist_is_recognised() {
        use netlink_packet_core::ErrorMessage;
        let mut m = ErrorMessage::default();
        m.code = std::num::NonZeroI32::new(-17);
        assert!(is_eexist(&DriverError::Netlink(
            rtnetlink::Error::NetlinkError(m.clone())
        )));
        m.code = std::num::NonZeroI32::new(-1);
        assert!(!is_eexist(&DriverError::Netlink(
            rtnetlink::Error::NetlinkError(m)
        )));
        assert!(!is_eexist(&DriverError::Other(String::new())));
    }

    #[test]
    fn discard_slot_differs_from_a_gateway_route() {
        let p = net("10.9.0.0/16");
        let observed = HashMap::from([((p, false), vec![addr("10.0.0.1")])]);
        let desired = HashMap::from([((p, false), Vec::<IpAddr>::new())]);
        let (add, remove) = diff_routes(&observed, &desired);
        assert_eq!(add, vec![((p, false), vec![])]);
        assert_eq!(remove, vec![((p, false), vec![addr("10.0.0.1")])]);
    }

    #[test]
    fn changed_gateway_is_removed_and_readded() {
        let mut observed = HashMap::new();
        observed.insert(net("10.0.0.0/24"), addr("10.0.0.1"));
        let mut desired = HashMap::new();
        desired.insert(net("10.0.0.0/24"), addr("10.0.0.2"));

        let (add, remove) = diff_routes(&observed, &desired);
        assert_eq!(add, vec![(net("10.0.0.0/24"), addr("10.0.0.2"))]);
        assert_eq!(remove, vec![(net("10.0.0.0/24"), addr("10.0.0.1"))]);
    }

    #[test]
    fn a_labelled_route_pushes_its_labels_and_reads_them_back() {
        for (p, gw) in [
            ("10.2.0.0/24", "10.0.0.2"),
            ("2001:db8:2::/48", "2001:db8::2"),
        ] {
            let p = net(p);
            let route = build_route(p, &[hop(gw, Some(4), &[2000])], 100, false, true).unwrap();
            assert_eq!(
                extract_route(&wire(&route)),
                Some(((p, false), vec![(addr(gw), None, vec![2000])]))
            );
        }
    }

    /// #582: a `VPNv6` route toward an IPv4 PE is an `RTA_GATEWAY` of the
    /// IPv4-mapped address (the kernel has no `RTA_VIA` for IPv6) that reads
    /// back as the IPv4 gateway, so the dump-diff sees no change.
    #[test]
    fn a_vpnv6_route_to_an_ipv4_pe_uses_the_mapped_gateway_and_reads_back_as_ipv4() {
        let p = net("fd18:2::/64");
        let hops = [hop("10.50.0.3", Some(4), &[1000])];
        let route = build_route(p, &hops, 100, false, true).unwrap();
        let gateways: Vec<_> = route
            .attributes
            .iter()
            .filter_map(|a| match a {
                RouteAttribute::Gateway(RouteAddress::Inet6(g)) => Some(*g),
                _ => None,
            })
            .collect();
        assert_eq!(
            gateways,
            vec!["::ffff:10.50.0.3".parse::<Ipv6Addr>().unwrap()]
        );
        assert_eq!(
            extract_route(&route),
            Some(((p, false), vec![(addr("10.50.0.3"), None, vec![1000])]))
        );
        // Removal builds the same message from the IPv4 gateway, no labels.
        assert!(build_route(p, &[plain("10.50.0.3")], 100, false, false).is_some());
        // An IPv6 gateway stays as it is.
        let v6 = build_route(p, &[plain("fd18::1")], 100, false, false).unwrap();
        assert_eq!(
            extract_route(&v6),
            Some(((p, false), vec![(addr("fd18::1"), None, vec![])]))
        );
    }

    #[test]
    fn a_label_only_change_is_a_remove_and_an_add() {
        let p = net("10.2.0.0/24");
        let entry = |labels: &[u32]| RibEntry {
            prefix: p,
            next_hops: vec![hop("10.0.0.2", None, labels)],
            source: RouteSource::Vpn,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interfaces: BTreeMap::new(),
        };
        let keyed = |e: &RibEntry| -> HashMap<Slot, Key> {
            slots(p, e).iter().map(|(s, h)| (*s, key(h))).collect()
        };
        let (old, new) = (keyed(&entry(&[1000])), keyed(&entry(&[2000])));
        let (add, remove) = diff_routes(&old, &new);
        assert_eq!(
            add,
            vec![((p, false), vec![(addr("10.0.0.2"), None, vec![2000])])]
        );
        assert_eq!(
            remove,
            vec![((p, false), vec![(addr("10.0.0.2"), None, vec![1000])])]
        );
        assert_eq!(diff_routes(&old, &old), (vec![], vec![]));
        // An entry's hop order is not a change; one hop's labels are.
        let two = |a: &[u32], b: &[u32]| [hop("10.0.0.2", None, a), hop("10.0.0.2", Some(4), b)];
        assert_eq!(key(&two(&[1], &[2])), key(&two(&[2], &[1])));
        assert_ne!(key(&two(&[1], &[2])), key(&two(&[1], &[3])));
    }

    // ---- nexthop groups (#1587) ----

    fn hop2(gw: &str, oif: Option<u32>, labels: &[u32]) -> NextHop {
        NextHop {
            gateway: addr(gw),
            interface_id: oif,
            labels: labels.to_vec(),
        }
    }

    fn rec(id: u32, gw: &str, oif: u32, labels: &[u32]) -> NexthopRecord {
        NexthopRecord {
            id,
            gateway: Some(addr(gw)),
            oif: Some(oif),
            labels: labels.to_vec(),
            ..Default::default()
        }
    }

    fn grp(id: u32, members: &[u32]) -> NexthopRecord {
        NexthopRecord {
            id,
            group: Some(members.iter().map(|m| (*m, 1)).collect()),
            ..Default::default()
        }
    }

    #[test]
    fn a_dumped_group_reads_as_the_key_of_its_hops() {
        let hops = [
            hop2("10.0.0.2", Some(3), &[200]),
            hop2("10.0.0.1", Some(2), &[100, 101]),
        ];
        let records = [
            rec(11, "10.0.0.2", 3, &[200]),
            rec(10, "10.0.0.1", 2, &[100, 101]),
            grp(12, &[11, 10]),
            // a group with a member that is not listed is skipped
            grp(13, &[10, 99]),
        ];
        let keys = group_keys(&records);
        assert_eq!(keys.get(&12), Some(&key(&hops)));
        assert!(!keys.contains_key(&13) && !keys.contains_key(&10));
    }

    #[test]
    fn a_group_key_drops_the_oif_but_keeps_a_link_local_one() {
        let records = [
            rec(1, "fe80::1", 7, &[]),
            rec(2, "2001:db8::1", 8, &[]),
            grp(3, &[1, 2]),
        ];
        let want = key(&[
            hop2("fe80::1", Some(7), &[]),
            hop2("2001:db8::1", None, &[]),
        ]);
        assert_eq!(group_keys(&records).get(&3), Some(&want));
    }

    #[test]
    fn a_vpnv6_group_reads_back_as_the_ipv4_pe() {
        let records = [
            rec(1, "::ffff:10.0.0.1", 2, &[100]),
            rec(2, "::ffff:10.0.0.2", 2, &[100]),
            grp(3, &[1, 2]),
        ];
        let want = key(&[
            hop2("10.0.0.1", None, &[100]),
            hop2("10.0.0.2", None, &[100]),
        ]);
        assert_eq!(group_keys(&records).get(&3), Some(&want));
    }

    #[test]
    fn a_group_route_is_the_prefix_and_an_id() {
        let p = net("10.9.0.0/16");
        let route = group_route(p, 100, 0x6400_0001).unwrap();
        let groups = HashMap::from([(
            0x6400_0001,
            key(&[hop2("10.0.0.1", None, &[]), hop2("10.0.0.2", None, &[])]),
        )]);
        let (slot, k, gid) = extract(&wire(&route), &groups).unwrap();
        assert_eq!((slot, gid), ((p, false), Some(0x6400_0001)));
        assert_eq!(k.len(), 2);
        assert!(!route
            .attributes
            .iter()
            .any(|a| matches!(a, RouteAttribute::Gateway(_) | RouteAttribute::MultiPath(_))));
        // A route over a group that is not ours (or gone) is not ours.
        assert_eq!(extract(&wire(&route), &HashMap::new()), None);
    }

    #[test]
    fn the_nh_id_wins_over_the_gateways_the_kernel_dumps_beside_it() {
        let p = net("10.9.0.0/16");
        let mut route = group_route(p, 100, 5).unwrap();
        route
            .attributes
            .push(RouteAttribute::Gateway(RouteAddress::from(Ipv4Addr::new(
                10, 0, 0, 9,
            ))));
        let want = key(&[hop2("10.0.0.1", None, &[]), hop2("10.0.0.2", None, &[])]);
        let (_, k, gid) = extract(&route, &HashMap::from([(5, want.clone())])).unwrap();
        assert_eq!((k, gid), (want, Some(5)));
    }

    #[test]
    fn the_same_hops_in_another_form_are_a_replace() {
        let k = key(&[hop2("10.0.0.1", None, &[]), hop2("10.0.0.2", None, &[])]);
        let inline: Shape = (k.clone(), Form::Inline);
        let group: Shape = (k, Form::Group);
        assert_eq!(slot_op(Some(&inline), Some(&group)), SlotOp::Replace);
        assert_eq!(slot_op(Some(&group), Some(&inline)), SlotOp::Replace);
        assert_eq!(slot_op(Some(&group), Some(&group)), SlotOp::Keep);
        // the dump diff reports it on both sides, `reconcile_routes` replaces
        let slot: Slot = (net("10.9.0.0/16"), false);
        let (add, remove) = diff_routes(
            &HashMap::from([(slot, inline)]),
            &HashMap::from([(slot, group)]),
        );
        assert_eq!((add.len(), remove.len()), (1, 1));
    }

    #[test]
    fn only_a_primary_multipath_route_is_a_group() {
        let two = [hop2("10.0.0.1", None, &[]), hop2("10.0.0.2", None, &[])];
        let none = HashSet::new();
        assert_eq!(form(false, &none, &two, false), Form::Group);
        assert_eq!(form(false, &none, &two, true), Form::Inline);
        assert_eq!(form(false, &none, &two[..1], false), Form::Inline);
        assert_eq!(form(false, &none, &[], false), Form::Inline);
        assert_eq!(form(true, &none, &two, false), Form::Inline);
        // the same gateway twice cannot be a group
        let dup = [two[0].clone(), two[0].clone()];
        assert_eq!(form(false, &none, &dup, false), Form::Inline);
        // a refused hop set goes inline, another set does not
        let refused = HashSet::from([key(&two)]);
        assert_eq!(form(false, &refused, &two, false), Form::Inline);
        let other = [hop2("10.0.0.1", None, &[]), hop2("10.0.0.3", None, &[])];
        assert_eq!(form(false, &refused, &other, false), Form::Group);
        // labels make another hop set
        let labelled = [hop2("10.0.0.1", None, &[1]), hop2("10.0.0.2", None, &[])];
        assert_eq!(form(false, &refused, &labelled, false), Form::Group);
    }

    #[test]
    fn a_v6_route_over_v4_hops_maps_the_gateways() {
        let hops = [
            hop2("10.0.0.1", None, &[100]),
            hop2("10.0.0.2", None, &[100]),
        ];
        let mapped = map_hops(false, &hops);
        assert_eq!(mapped[0].gateway, addr("::ffff:10.0.0.1"));
        assert_eq!(map_hops(true, &hops), hops.to_vec());
        assert_eq!(
            map_hops(false, &[hop2("2001:db8::1", None, &[])])[0].gateway,
            addr("2001:db8::1")
        );
    }
}
