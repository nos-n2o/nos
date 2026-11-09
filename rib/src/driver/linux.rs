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
use nos_proto::evpn_id::{format_mac, vxlan_name};
use nos_proto::{IpNet, NextHop};
use rtnetlink::packet_route::link::{InfoData, InfoVxlan, LinkAttribute, LinkInfo, LinkMessage};
use rtnetlink::packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use rtnetlink::packet_route::route::{
    MplsLabel, RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteNextHopFlags,
    RouteProtocol, RouteType,
};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{
    Handle, LinkBridge, LinkIpIp, LinkUnspec, LinkVrf, LinkVxlan, RouteMessageBuilder,
    RouteNextHopBuilder,
};
use tracing::{debug, info, trace, warn};

use super::mpls::{self, Mpls, Sysctl};
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

/// Drops slots whose add was deferred or skipped from a seeded shadow map.
fn unset_deferred(installed: &mut HashMap<Slot, Hops>, deferred: &[Slot]) {
    for slot in deferred {
        installed.remove(slot);
    }
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

/// What a slot is compared by: its sorted `(gateway, labels)` pairs, since a
/// dumped route carries no `interface_id` of ours to compare. The same
/// gateway with two label stacks stays two hops, and a label-only change is
/// a changed route (remove, then add).
type Key = Vec<(IpAddr, Vec<u32>)>;

fn key(hops: &[NextHop]) -> Key {
    let mut out: Key = hops.iter().map(|h| (h.gateway, h.labels.clone())).collect();
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

fn slot_op(old: Option<&Key>, new: Option<&Key>) -> SlotOp {
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
    sysctl: Sysctl,
    /// Underlay interfaces whose `net.mpls.conf.<if>.input` could not be
    /// set, warned about once each.
    input_warned: Mutex<HashSet<String>>,
    /// Startup hold (#654): `apply` leaves kernel routes it has no desired
    /// slot for alone (see `RibDriver::keep_stale`).
    keep_stale: AtomicBool,
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
            sysctl: Sysctl::default(),
            input_warned: Mutex::new(HashSet::new()),
            keep_stale: AtomicBool::new(false),
        })
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

        let old = prev.map(|p| p.remotes.clone()).unwrap_or_default();
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
    ) -> Result<Vec<(Slot, Key, RouteMessage)>, DriverError> {
        let mut out = Vec::new();
        let table_id_u8 =
            u8::try_from(table_id).expect("table ids are always <= MAX_TABLE_ID (252)");

        let v4_filter = RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(table_id)
            .build();
        let mut v4 = self.handle.route().get(v4_filter).execute();
        while let Some(route) = v4.try_next().await? {
            if route.header.table == table_id_u8
                && let Some((slot, key)) = extract_route(&route)
            {
                out.push((slot, key, route));
            }
        }

        let v6_filter = RouteMessageBuilder::<Ipv6Addr>::new()
            .table_id(table_id)
            .build();
        let mut v6 = self.handle.route().get(v6_filter).execute();
        while let Some(route) = v6.try_next().await? {
            if route.header.table == table_id_u8
                && let Some((slot, key)) = extract_route(&route)
            {
                out.push((slot, key, route));
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
    ) -> Result<bool, DriverError> {
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
                return Ok(false);
            };
            Some(bridge)
        } else if tunnel {
            let Some(dev) = self.tunnels.lock().unwrap().get(&table_id).copied() else {
                debug!(%prefix, table_id, "remote lfa tunnel device not built yet, backup deferred");
                return Ok(false);
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
                return Ok(false);
            }
            for gw in unresolved {
                warn!(%prefix, gateway = %gw, table_id, "labelled next hop skipped: unresolved");
            }
            hops = kept;
        }
        let onlink = labelled || shared_dev.is_some();
        let Some(route) = build_route(prefix, &hops, table_id, backup, onlink) else {
            warn!(%prefix, %gateway, table_id, "route prefix/gateway address family mismatch, skipping");
            return Ok(false);
        };
        let sent = if replace {
            self.route_channel.replace(route).await
        } else {
            self.route_channel.add(route).await
        };
        sent.inspect_err(|e| {
            warn!(%prefix, %gateway, table_id, backup, replace, error = %e, "failed to add route");
        })?;
        if labelled {
            let labels: Vec<_> = hops.iter().map(|h| &h.labels).collect();
            let gateway = show_gateways(hops.iter().map(|h| &h.gateway));
            let interfaces: Vec<_> = hops.iter().filter_map(|h| h.interface_id).collect();
            info!(%prefix, labels = ?labels, %gateway, interfaces = ?interfaces, table_id, replaced = replace, "installed labelled route");
        } else {
            let discard = hops.is_empty();
            info!(%prefix, %gateway, next_hops = hops.len(), table_id, source = ?source, backup, discard, tunnel, replaced = replace, "added route");
        }
        Ok(true)
    }

    /// The ifindex `gateway` leaves over in this table's underlay (`ip route
    /// get <gateway> vrf <underlay>`), `None` when unknown or unreachable. A
    /// PE on a connected prefix comes from `nos-bgpd` without one.
    // ponytail: one lookup per labelled route install; cache per gateway if
    // VPN tables grow to many thousands of routes.
    async fn egress_of(&self, table_id: u32, gateway: IpAddr) -> Option<u32> {
        let underlay = self.mpls.lock().unwrap().get(&table_id)?.underlay_vrf?;
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
    ) -> Result<(), DriverError> {
        let key = key(hops);
        let gateway = show_gateways(key.iter().map(|(gw, _)| gw));
        // No encap or onlink in the request: the kernel matches on what is
        // given, and duplicate gateways of a multipath route still match.
        let bare: Hops = hops
            .iter()
            .map(|h| (h.gateway, h.interface_id).into())
            .collect();
        let Some(route) = build_route(prefix, &bare, table_id, backup, false) else {
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
        old: Option<&Hops>,
        (source, backup, tunnel): (Option<RouteSource>, bool, bool),
    ) -> Result<bool, DriverError> {
        let sent = self
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
        if let (false, Some(old)) = (sent, old) {
            self.remove_route(table_id, prefix, old, backup).await?;
        }
        Ok(sent)
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
        let items: Vec<(IpNet, Slots, Slots, Option<RouteSource>, bool)> = {
            let installed = self.installed.lock().unwrap();
            let table_installed = installed.get(&table_id);
            changes
                .iter()
                .map(|(prefix, new)| {
                    let old: Slots = [false, true]
                        .into_iter()
                        .filter_map(|b| {
                            let slot = (*prefix, b);
                            table_installed
                                .and_then(|m| m.get(&slot))
                                .map(|hops| (slot, hops.clone()))
                        })
                        .collect();
                    let source = new.as_ref().map(|e| e.source);
                    let tunnel = new.as_ref().is_some_and(|e| e.backup_tunnel);
                    let new: Slots = new
                        .as_ref()
                        .map(|e| slots(*prefix, e).into_iter().collect())
                        .unwrap_or_default();
                    (*prefix, old, new, source, tunnel)
                })
                .collect()
        };

        // The shadow state follows each op as it succeeds, so a failed one
        // leaves its slot as the kernel still has it.
        let set = |slot: Slot, hops: Option<Hops>| {
            let mut installed = self.installed.lock().unwrap();
            let table_installed = installed.entry(table_id).or_default();
            match hops {
                Some(hops) => table_installed.insert(slot, hops),
                None => table_installed.remove(&slot),
            };
        };
        let errors = drain(items.into_iter().map(
            |(prefix, old, new, source, tunnel)| async move {
                // A changed slot is replaced in place (make-before-break), a
                // vanished one removed, a new one added.
                let mut result = Ok(());
                let all: BTreeSet<Slot> = old.keys().chain(new.keys()).copied().collect();
                for slot in all {
                    let (o, n) = (old.get(&slot), new.get(&slot));
                    let op = slot_op(o.map(|h| key(h)).as_ref(), n.map(|h| key(h)).as_ref());
                    let step = match (op, o, n) {
                        (SlotOp::Remove, Some(o), _) => self
                            .remove_route(table_id, prefix, o, slot.1)
                            .await
                            .map(|()| None),
                        (SlotOp::Add | SlotOp::Replace, o, Some(n)) => self
                            .install(table_id, prefix, n, o, (source, slot.1, tunnel))
                            .await
                            .map(|sent| shadow_after_install(sent, n)),
                        (_, _, n) => Ok(n.cloned()),
                    };
                    match step {
                        Ok(hops) => set(slot, hops),
                        Err(e) => result = result.and(Err(e)),
                    }
                }
                result
            },
        ))
        .await;
        errors.into_iter().next().map_or(Ok(()), Err)
    }

    /// Diffs `best_routes` against what's actually installed in
    /// `table_id`'s kernel table and adds/removes to converge, reusing the
    /// exact dumped `RouteMessage` for any removal.
    async fn reconcile_routes(
        &self,
        table_id: u32,
        best_routes: &HashMap<IpNet, RibEntry>,
        keep_stale: bool,
    ) -> Result<(), DriverError> {
        let observed = self.dump_routes(table_id).await?;
        let observed_map: HashMap<Slot, Key> = observed
            .iter()
            .map(|(slot, key, _)| (*slot, key.clone()))
            .collect();
        let desired_full: HashMap<Slot, Hops> = best_routes
            .iter()
            .flat_map(|(prefix, entry)| slots(*prefix, entry))
            .collect();
        let desired: HashMap<Slot, Key> = desired_full
            .iter()
            .map(|(slot, hops)| (*slot, key(hops)))
            .collect();

        let observed_by_slot: HashMap<Slot, RouteMessage> = observed
            .iter()
            .map(|(slot, _, message)| (*slot, message.clone()))
            .collect();

        let (to_add, mut to_remove) = diff_routes(&observed_map, &desired);
        if keep_stale {
            // Only a slot we re-add (changed hops) goes: EEXIST otherwise.
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
        // A slot in both lists changed key: replaced in one request, so its
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
        let remove_failed = drain(to_remove.into_iter().map(|((prefix, backup), key)| {
            let message = observed_by_slot.get(&(prefix, backup)).cloned();
            let gateway = show_gateways(key.iter().map(|(gw, _)| gw));
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

        let deferred = std::sync::Mutex::new(Vec::new());
        let deferred_ref = &deferred;
        let add_failed = drain(to_add.into_iter().map(|(slot, _)| {
            let source = best_routes.get(&slot.0).map(|e| e.source);
            let tunnel = best_routes.get(&slot.0).is_some_and(|e| e.backup_tunnel);
            let want = desired_full.get(&slot).cloned().unwrap_or_default();
            let gone = replaced.contains(&slot).then(|| {
                (
                    observed_by_slot.get(&slot).cloned(),
                    observed_map[&slot].clone(),
                )
            });
            async move {
                let replace = gone.is_some();
                let sent = self
                    .add_route(table_id, slot.0, &want, source, slot.1, tunnel, replace)
                    .await
                    .map_err(|e| (slot, e))?;
                if !sent {
                    deferred_ref.lock().unwrap().push(slot);
                }
                // Deferred or skipped: the old route is still there, drop it.
                match gone {
                    Some((Some(mut message), key)) if !sent => {
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
        // A deferred or skipped add is not in the kernel (#686).
        unset_deferred(&mut installed, &deferred.into_inner().unwrap());
        let mut first_error = None;
        for (slot, e) in add_failed {
            // A failed replace leaves what the kernel had (like a failed
            // delete below); a failed add leaves nothing.
            match replaced.contains(&slot).then(|| &observed_map[&slot]) {
                Some(key) => installed.insert(slot, hops_of(key)),
                None => installed.remove(&slot),
            };
            first_error.get_or_insert(e);
        }
        for (slot, key, e) in remove_failed {
            installed.insert(slot, hops_of(&key));
            first_error.get_or_insert(e);
        }
        self.installed.lock().unwrap().insert(table_id, installed);
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
        self.reconcile_routes(
            table_id,
            best_routes,
            self.keep_stale.load(Ordering::SeqCst),
        )
        .await
    }

    fn keep_stale(&self, on: bool) {
        self.keep_stale.store(on, Ordering::SeqCst);
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
        self.apply_delta_impl(table_id, changes).await
    }

    async fn teardown(&self, table_name: &str) -> Result<(), DriverError> {
        let Some(table_id) = table_registry::lookup_table_id(&self.registry_path, table_name)
        else {
            debug!(table = %table_name, "no table id allocated, nothing to tear down");
            return Ok(());
        };
        self.remove_pop_route(table_name, table_id).await?;
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
        if let Some(u) = underlay_vrf {
            self.enable_input(u).await?;
        }

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

    /// `net.mpls.conf.<if>.input = 1` on every interface of the underlay
    /// VRF, so labelled packets from the other PEs are accepted. One that
    /// cannot be set is warned about once, not fatal: it may face no PE.
    // ponytail: every underlay interface, never a CE-facing one (those are in
    // the customer VRF); an explicit per-interface `mpls` knob is the clean model.
    async fn enable_input(&self, underlay_vrf: u32) -> Result<(), DriverError> {
        let mut links = self.handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            if master_of(&link) != Some(underlay_vrf) {
                continue;
            }
            let Some(name) = link.attributes.iter().find_map(|a| match a {
                LinkAttribute::IfName(n) => Some(n.clone()),
                _ => None,
            }) else {
                continue;
            };
            match self.sysctl.ensure_input(&name) {
                Ok(()) => {
                    self.input_warned.lock().unwrap().remove(&name);
                }
                Err(e) => {
                    if self.input_warned.lock().unwrap().insert(name.clone()) {
                        warn!(interface = %name, error = %e, "mpls input not enabled on an underlay interface");
                    }
                }
            }
        }
        Ok(())
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

/// Extracts `((prefix, is_backup), key)` from a dumped `RouteMessage`: the
/// sorted `(gateway, labels)` pairs (`Key`), or `None` for a route we don't
/// manage (no gateway — e.g. a kernel-internal entry a VRF device creates on
/// its own, or an unsupported address family like MPLS). An ECMP route has no
/// `RTA_GATEWAY` of its own: its gateways are inside `RTA_MULTIPATH`, one per
/// next hop, each with its own `RTA_ENCAP` — missing that would make a
/// multipath route look unmanaged, re-added (EEXIST) on every `apply` and
/// never deleted. A single-hop route's labels are the route-level encap. A
/// missing `Destination` attribute means the default route (kernel omits it
/// for 0/0), so it falls back to the family's unspecified address. A
/// blackhole is a managed discard slot (empty key) only with `RTPROT_STATIC`,
/// the protocol `build_route` gives every route: an operator's `ip route add
/// blackhole` (`RTPROT_BOOT`) or a VRF recipe's `unreachable default metric
/// …` is left alone.
// ponytail: kernels before 4.11 dump IPv6 ECMP siblings as separate routes,
// not one `RTA_MULTIPATH`; merge siblings per slot here if one must be
// supported.
/// A `RTM_F_CLONED` entry is a kernel exception (e.g. the PMTU a tunnel
/// learned), dumped beside the route it belongs to: never a route of ours.
fn extract_route(route: &RouteMessage) -> Option<(Slot, Key)> {
    if route.header.flags.contains(RouteFlags::Cloned) {
        return None;
    }
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
        Some(hops) => hops
            .iter()
            .filter_map(|hop| {
                Some((
                    gateway_of(&hop.attributes)?,
                    mpls::labels_of(&hop.attributes),
                ))
            })
            .collect(),
        None => gateway_of(&route.attributes)
            .map(|gw| (gw, mpls::labels_of(&route.attributes)))
            .into_iter()
            .collect(),
    };
    let discard =
        route.header.kind == RouteType::BlackHole && route.header.protocol == RouteProtocol::Static;
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
        .map(|prefix| ((prefix, backup), key))
}

/// The hops a dumped `key` stands for (no interface: a dump carries none of
/// ours).
fn hops_of(key: &Key) -> Hops {
    key.iter()
        .map(|(gateway, labels)| NextHop {
            gateway: *gateway,
            interface_id: None,
            labels: labels.clone(),
        })
        .collect()
}

/// The "removed route" log line, or "removed labelled route" (each hop's
/// labels, in `key` order) for one that pushed labels.
fn log_removed(prefix: IpNet, key: &Key, table_id: u32, backup: bool) {
    let gateway = show_gateways(key.iter().map(|(gw, _)| gw));
    if key.iter().all(|(_, l)| l.is_empty()) {
        let discard = key.is_empty();
        info!(%prefix, %gateway, table_id, backup, discard, "removed route");
    } else {
        let labels: Vec<_> = key.iter().map(|(_, l)| l).collect();
        info!(%prefix, labels = ?labels, %gateway, table_id, "removed labelled route");
    }
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
    // A VPNv6 route (RFC 4659) leaves toward IPv4 PEs: the kernel refuses an
    // IPv6 route with `RTA_VIA` ("IPv6 does not support RTA_VIA"), but takes
    // the IPv4-mapped gateway (`via ::ffff:a.b.c.d`) and sends the labelled
    // packet to the PE's IPv4 neighbour. `extract_route` maps it back.
    let mapped;
    let hops = if !v4 && !hops.is_empty() && hops.iter().all(|h| h.gateway.is_ipv4()) {
        mapped = hops
            .iter()
            .map(|h| match h.gateway {
                IpAddr::V4(a) => NextHop {
                    gateway: IpAddr::V6(a.to_ipv6_mapped()),
                    ..h.clone()
                },
                IpAddr::V6(_) => h.clone(),
            })
            .collect::<Hops>();
        &mapped[..]
    } else {
        hops
    };
    if (backup && hops.is_empty()) || hops.iter().any(|h| h.gateway.is_ipv4() != v4) {
        return None;
    }
    let mut builder = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(prefix.addr(), prefix.prefix_len())
        .ok()?
        .table_id(table_id);
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
        let slot = ("10.0.0.0/8".parse().unwrap(), false);
        let other = ("10.1.0.0/16".parse().unwrap(), false);
        let mut m = std::collections::HashMap::from([(slot, hops.clone()), (other, hops)]);
        super::unset_deferred(&mut m, &[slot]);
        assert!(!m.contains_key(&slot) && m.contains_key(&other));
    }

    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn k(hops: &[(&str, &[u32])]) -> Key {
        let mut k: Key = hops.iter().map(|(g, l)| (addr(g), l.to_vec())).collect();
        k.sort_unstable();
        k
    }

    #[test]
    fn slot_op_replaces_instead_of_remove_then_add() {
        let one = k(&[("10.0.0.1", &[])]);
        let two = k(&[("10.0.0.1", &[]), ("10.0.0.2", &[])]);
        let labelled = k(&[("10.0.0.1", &[16])]);
        let other = k(&[("10.0.0.9", &[])]);
        let discard: Key = Vec::new();
        assert_eq!(slot_op(None, None), SlotOp::Keep);
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
                vec![(addr("10.0.0.2"), vec![]), (addr("10.0.0.9"), vec![])]
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
                vec![(addr("2001:db8::2"), vec![]), (addr("2001:db8::9"), vec![])]
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
            (addr("10.0.0.2"), vec![100]),
            (addr("10.0.0.2"), vec![300, 16]),
            (addr("10.0.0.3"), vec![200]),
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
            Some(((p, true), vec![(addr("10.0.0.1"), vec![])]))
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
                Some(((p, false), vec![(addr(gw), vec![2000])]))
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
            Some(((p, false), vec![(addr("10.50.0.3"), vec![1000])]))
        );
        // Removal builds the same message from the IPv4 gateway, no labels.
        assert!(build_route(p, &[plain("10.50.0.3")], 100, false, false).is_some());
        // An IPv6 gateway stays as it is.
        let v6 = build_route(p, &[plain("fd18::1")], 100, false, false).unwrap();
        assert_eq!(
            extract_route(&v6),
            Some(((p, false), vec![(addr("fd18::1"), vec![])]))
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
        };
        let keyed = |e: &RibEntry| -> HashMap<Slot, Key> {
            slots(p, e).iter().map(|(s, h)| (*s, key(h))).collect()
        };
        let (old, new) = (keyed(&entry(&[1000])), keyed(&entry(&[2000])));
        let (add, remove) = diff_routes(&old, &new);
        assert_eq!(
            add,
            vec![((p, false), vec![(addr("10.0.0.2"), vec![2000])])]
        );
        assert_eq!(
            remove,
            vec![((p, false), vec![(addr("10.0.0.2"), vec![1000])])]
        );
        assert_eq!(diff_routes(&old, &old), (vec![], vec![]));
        // An entry's hop order is not a change; one hop's labels are.
        let two = |a: &[u32], b: &[u32]| [hop("10.0.0.2", None, a), hop("10.0.0.2", Some(4), b)];
        assert_eq!(key(&two(&[1], &[2])), key(&two(&[2], &[1])));
        assert_ne!(key(&two(&[1], &[2])), key(&two(&[1], &[3])));
    }
}
