//! The real backend: a VXLAN device per domain plus its bridge FDB, over
//! `rtnetlink`. Idempotent throughout — see `FdbDriver`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{
    DefaultNla, Emitable, NetlinkMessage, NetlinkPayload, Nla, NlasIterator, NLA_F_NESTED,
    NLA_TYPE_MASK, NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST,
};
use rtnetlink::packet_route::link::{
    InfoBridgePort, InfoData, InfoPortData, InfoPortKind, InfoVxlan, LinkAttribute, LinkFlags,
    LinkInfo, LinkMessage, LinkProtoInfoBridge,
};
use rtnetlink::packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{Handle, LinkUnspec, LinkVxlan, MulticastGroup};
use tokio::sync::mpsc;
use tracing::{debug, info};

use nos_tc::{Action, ActionKind, Filter, FlowerKeys, Hook, Kind, Protocol, Request, Verdict};

use super::nexthop::{self, Nexthop};
use super::{is_local_mac, is_local_neigh, vxlan_name, DriverError, FdbDriver, Mac, VXLAN_PORT};

/// Local bias (RFC 8365 §8.3.1, `docs/protocols/evpn-vxlan.md`): the bridge
/// only sees the inner frame, so the *outer* source of a core-origin BUM
/// frame is classified by `flower` on the VXLAN device's ingress
/// (`enc_src_ip`) into `skb->mark`, and `fw` + `gact drop` on a segment
/// port's egress acts on the mark. The top byte of every mark set here:
/// any other mark is not ours.
const MARK_MAGIC: u32 = 0xE500_0000;
/// What `skbedit` may change: the magic byte and the segment bitmap, never
/// the middle byte (left for anything else using marks).
const MARK_MASK: u32 = 0xFF00_FFFF;
/// The filter priorities: peers first, the catch-all after them (the first
/// match wins); on a port the local-bias drop, then the DF drop.
const PRIO_FIRST: u16 = 1;
const PRIO_SECOND: u16 = 2;
/// The multicast bit of the destination MAC: broadcast, IPv4 and IPv6
/// multicast, i.e. the multi-destination frames local bias is about.
const MCAST_MAC: [u8; 6] = [1, 0, 0, 0, 0, 0];

/// `flower dst_mac <mcast> [enc_src_ip <src>] action skbedit mark
/// <MARK_MAGIC | bits>/MARK_MASK pipe` on the VXLAN device's ingress. No
/// `src` is the catch-all: every core-origin BUM frame, magic byte alone.
fn mark_filter(ifindex: u32, prio: u16, handle: u32, src: Option<IpAddr>, bits: u16) -> Request {
    Request::AddFilter(Filter {
        ifindex,
        hook: Hook::Ingress,
        chain: 0,
        prio,
        protocol: Protocol::All,
        handle,
        kind: Kind::Flower(FlowerKeys {
            eth_dst: Some((MCAST_MAC, Some(MCAST_MAC))),
            enc_src_ip: src,
            ..FlowerKeys::default()
        }),
        actions: vec![Action::new(ActionKind::Skbedit {
            mark: MARK_MAGIC | u32::from(bits),
            mask: MARK_MASK,
            verdict: Verdict::Pipe,
        })],
        replace: false,
    })
}

/// `fw handle <MARK_MAGIC | bits>/<magic byte | bits> action drop` on a
/// port's egress: drops a frame whose mark has all of `bits` set (and the
/// magic byte); `bits == 0` drops every marked frame. The head's mask is
/// fixed by its first filter, one per priority (hence two priorities).
fn drop_marked(ifindex: u32, prio: u16, bits: u16) -> Request {
    Request::AddFilter(Filter {
        ifindex,
        hook: Hook::Egress,
        chain: 0,
        prio,
        protocol: Protocol::All,
        handle: MARK_MAGIC | u32::from(bits),
        kind: Kind::Fw {
            mask: 0xFF00_0000 | u32::from(bits),
        },
        actions: vec![Action::new(ActionKind::Gact(Verdict::Shot))],
        replace: false,
    })
}

/// Removes `handle` (or, with `handle == 0`, every filter) at `prio`.
fn delete_filter(ifindex: u32, hook: Hook, prio: u16, handle: u32) -> Request {
    Request::DelFilter {
        ifindex,
        hook,
        chain: 0,
        prio,
        protocol: Protocol::All,
        handle,
    }
}

/// errno(3) values the kernel answers a missing object with.
const ENODEV: i32 = 19;
const ENOENT: i32 = 2;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
/// Deleting a filter (or a whole priority) that isn't there: `ENOENT`, or
/// `EINVAL` when the device has no filter chain at all yet.
const NO_FILTER: &[i32] = &[ENOENT, EINVAL];
/// `NDA_NH_ID`: the FDB entry points at a nexthop (group) instead of a `dst`.
const NDA_NH_ID: u16 = 13;
/// Nexthop ids are `vni << 8 | slot`, so the per-domain `nos-fdbd` processes
/// sharing a network namespace never collide (ids are namespace-wide).
/// `ponytail:` 255 nexthops + groups per domain, and they are only deleted
/// with the domain; a few dozen PEs and distinct PE sets are the ceiling.
const NH_SLOTS: u32 = 255;

/// The nexthop objects this process created for one VNI.
#[derive(Default)]
struct NhState {
    slots: u32,
    gateways: HashMap<IpAddr, u32>,
    groups: HashMap<Vec<IpAddr>, u32>,
}

/// `NDA_FDB_EXT_ATTRS` (nested) and its `NFEA_ACTIVITY_NOTIFY` (u8): an FDB
/// entry that tracks activity. `FDB_NOTIFY_INACTIVE_BIT` is set until a frame
/// from the entry's port is seen, and set again once none was for the
/// bridge's ageing time (`br_fdb_update`/`br_fdb_cleanup`).
const NDA_FDB_EXT_ATTRS: u16 = 14;
const NFEA_ACTIVITY_NOTIFY: u8 = 1;
const FDB_NOTIFY_BIT: u8 = 1;
const FDB_NOTIFY_INACTIVE_BIT: u8 = 2;

/// `IFLA_BRPORT_STATE` and the two bridge-port states used (`BR_STATE_*`).
const IFLA_BRPORT_STATE: u16 = 1;
const BR_STATE_DISABLED: u8 = 0;
const BR_STATE_FORWARDING: u8 = 3;

/// `FRA_TUN_ID`, sent raw: `netlink-packet-route` types it as a `u32`, the
/// kernel reads a big-endian `u64`.
const FRA_TUN_ID: u16 = 12;
/// The metadata rule's `tun_id` is `METADATA_TUN_ID | vni`: above 32 bits, so no
/// VXLAN/Geneve VNI or GRE key ever equals it, and one rule per domain.
const METADATA_TUN_ID: u64 = 0xE5 << 32;
/// Where the metadata rule sits; it is `nop`, so the position changes nothing.
const METADATA_RULE_PREF: u32 = 32741;

/// The never-matching `tun_id` fib rule that keeps the kernel's
/// `ip_tunnel_collect_metadata()` on (#460): without it a classic `vx<vni>`
/// attaches no tunnel info, so the local-bias `flower enc_src_ip` filters
/// never match. A flower `enc_*` filter alone does not turn it on (7.2.11).
fn metadata_rule(vni: u32) -> RuleMessage {
    let mut m = RuleMessage::default();
    m.header.family = AddressFamily::Inet;
    m.header.action = RuleAction::Nop;
    m.attributes
        .push(RuleAttribute::Priority(METADATA_RULE_PREF));
    m.attributes.push(RuleAttribute::Other(DefaultNla::new(
        FRA_TUN_ID,
        (METADATA_TUN_ID | u64::from(vni)).to_be_bytes().to_vec(),
    )));
    m
}

pub struct LinuxFdbDriver {
    handle: Handle,
    /// `vni -> ifindex` of the vxlan devices `ensure_vxlan` last saw, so the
    /// per-MAC calls don't each pay a link lookup.
    ifindex: Mutex<HashMap<u32, u32>>,
    /// `vni -> ifindex` of each device's underlay, which every remote entry
    /// must name (`NDA_IFINDEX`, `bridge fdb ... via`): without it the kernel
    /// resolves the remote VTEP in the *main* table, and with the underlay in a
    /// VRF the route isn't there (`tx_carrier_errors`, nothing ever sent).
    underlay: Mutex<HashMap<u32, u32>>,
    /// `vni ->` the FDB nexthops and groups created for it (see `NhState`).
    nexthops: Mutex<HashMap<u32, NhState>>,
    /// `vni ->` the underlay's master (its VRF) when this process brought the
    /// device up. The kernel binds the VXLAN socket to that VRF only when the
    /// device opens, so an underlay that joined its VRF later leaves an
    /// unbound socket: entries without a `via` (FDB nexthop groups) are then
    /// looked up in the main table and dropped (`ENETUNREACH`,
    /// `tx_carrier_errors`). A change, or no record, reopens the device.
    bound_master: Mutex<HashMap<u32, Option<u32>>>,
    /// `vni ->` how many per-peer local-bias filters this process wrote on its
    /// ingress (handles `1..=n`).
    bias: Mutex<HashMap<u32, usize>>,
}

impl LinuxFdbDriver {
    pub fn new() -> Result<Self, DriverError> {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| DriverError::Other(e.to_string()))?;
        nos_log_client::spawn_critical("rtnetlink-connection", connection);
        Ok(Self {
            handle,
            ifindex: Mutex::new(HashMap::new()),
            underlay: Mutex::new(HashMap::new()),
            nexthops: Mutex::new(HashMap::new()),
            bound_master: Mutex::new(HashMap::new()),
            bias: Mutex::new(HashMap::new()),
        })
    }

    /// `ip link set dev <port> type bridge_slave ..`: an `RTM_NEWLINK` (not
    /// SETLINK — only the newlink path reaches the master's
    /// `slave_changelink`) carrying the port data. Only the bridge's own ports
    /// accept it (EOPNOTSUPP otherwise), so a port that isn't enslaved yet is
    /// an error the tick retries.
    async fn set_bridge_port(
        &self,
        index: u32,
        attrs: Vec<InfoBridgePort>,
    ) -> Result<(), DriverError> {
        let mut msg = LinkMessage::default();
        msg.header.index = index;
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::PortKind(InfoPortKind::Bridge),
            LinkInfo::PortData(InfoPortData::BridgePort(attrs)),
        ]));
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
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

    /// The name of the link with `index` (`None` if it vanished meanwhile).
    /// The bridge's local MACs: `(port name, seconds since last frame)`.
    async fn local_entries(
        &self,
        bridge: &str,
        vni: u32,
    ) -> Result<BTreeMap<Mac, (String, Option<u32>)>, DriverError> {
        let bridge_idx = self
            .find_link(bridge)
            .await?
            .ok_or_else(|| DriverError::Other(format!("bridge {bridge} does not exist yet")))?
            .header
            .index;
        let vxlan_idx = self.ifindex.lock().unwrap().get(&vni).copied();
        let mut dump = self
            .handle
            .neighbours()
            .get()
            .set_address_family(AddressFamily::Bridge)
            .execute();
        let mut out = BTreeMap::new();
        let mut names: HashMap<u32, String> = HashMap::new();
        while let Some(m) = dump.try_next().await? {
            let mut mac = None;
            let mut master = None;
            for a in &m.attributes {
                match a {
                    NeighbourAttribute::LinkLayerAddress(b) => {
                        mac = Mac::try_from(b.as_slice()).ok();
                    }
                    NeighbourAttribute::Controller(i) => master = Some(*i),
                    _ => {}
                }
            }
            let Some(mac) = mac else { continue };
            if is_local_mac(
                mac,
                m.header.state == NeighbourState::Permanent,
                m.header.flags.contains(NeighbourFlags::ExtLearned),
                fdb_activity(&m),
                m.header.ifindex,
                master,
                bridge_idx,
                vxlan_idx,
            ) {
                let port = m.header.ifindex;
                if let std::collections::hash_map::Entry::Vacant(v) = names.entry(port)
                    && let Some(name) = self.link_name(port).await?
                {
                    v.insert(name);
                }
                out.insert(
                    mac,
                    (
                        names.get(&port).cloned().unwrap_or_default(),
                        used_of(&m).map(used_secs),
                    ),
                );
            }
        }
        Ok(out)
    }

    async fn link_name(&self, index: u32) -> Result<Option<String>, DriverError> {
        let mut links = self.handle.link().get().match_index(index).execute();
        match links.try_next().await {
            Ok(link) => Ok(link.and_then(|l| {
                l.attributes.into_iter().find_map(|a| match a {
                    LinkAttribute::IfName(n) => Some(n),
                    _ => None,
                })
            })),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -ENODEV => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn bridge_index(&self, bridge: &str) -> Result<u32, DriverError> {
        Ok(self
            .find_link(bridge)
            .await?
            .ok_or_else(|| DriverError::Other(format!("bridge {bridge} does not exist yet")))?
            .header
            .index)
    }

    fn via(&self, vni: u32) -> u32 {
        self.underlay
            .lock()
            .unwrap()
            .get(&vni)
            .copied()
            .unwrap_or(0)
    }

    async fn vxlan_index(&self, vni: u32) -> Result<u32, DriverError> {
        if let Some(idx) = self.ifindex.lock().unwrap().get(&vni) {
            return Ok(*idx);
        }
        let link = self
            .find_link(&vxlan_name(vni))
            .await?
            .ok_or_else(|| DriverError::Other(format!("{} does not exist", vxlan_name(vni))))?;
        self.ifindex.lock().unwrap().insert(vni, link.header.index);
        Ok(link.header.index)
    }

    /// Runs one tc request on a blocking thread (`nos_tc::send` blocks).
    async fn tc(&self, req: Request, tolerate: &'static [i32]) -> Result<(), DriverError> {
        tokio::task::spawn_blocking(move || nos_tc::send(&req, tolerate))
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
            .map_err(|e| DriverError::Other(format!("tc request failed: {e}")))
    }

    /// Removes every filter at `prio`; nothing there is fine.
    async fn tc_flush(&self, ifindex: u32, hook: Hook, prio: u16) -> Result<(), DriverError> {
        self.tc(delete_filter(ifindex, hook, prio, 0), NO_FILTER)
            .await
    }

    /// Adds (`present`) or removes `vni`'s metadata rule; already so is fine.
    async fn metadata_rule(&self, vni: u32, present: bool) -> Result<(), DriverError> {
        let (res, tolerate) = if present {
            let mut req = self.handle.rule().add();
            *req.message_mut() = metadata_rule(vni);
            (req.execute().await, EEXIST)
        } else {
            (
                self.handle.rule().del(metadata_rule(vni)).execute().await,
                ENOENT,
            )
        };
        match res {
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -tolerate => Ok(()),
            r => r.map_err(Into::into),
        }
    }

    /// Runs one nexthop request on a blocking thread (see `nexthop`).
    async fn nexthop(&self, nh: Nexthop, tolerate: i32) -> Result<(), DriverError> {
        tokio::task::spawn_blocking(move || nexthop::send(&nh, tolerate))
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
            .map_err(|e| DriverError::Other(format!("nexthop request failed: {e}")))
    }

    /// The id the next nexthop of `vni` will get. Only committed once the
    /// kernel accepted it, so a failed request wastes no slot.
    fn next_nexthop_id(&self, vni: u32) -> Result<u32, DriverError> {
        let slot = self
            .nexthops
            .lock()
            .unwrap()
            .get(&vni)
            .map_or(0, |s| s.slots)
            + 1;
        if slot > NH_SLOTS {
            return Err(DriverError::Other(format!(
                "vni {vni} is out of nexthop ids ({NH_SLOTS})"
            )));
        }
        Ok(vni << 8 | slot)
    }

    fn commit_nexthop(&self, vni: u32, f: impl FnOnce(&mut NhState)) {
        let mut all = self.nexthops.lock().unwrap();
        let state = all.entry(vni).or_default();
        state.slots += 1;
        f(state);
    }

    /// The id of the FDB group over `vteps`, creating its member nexthops and
    /// the group itself first when this is a new set.
    async fn ensure_group(&self, vni: u32, vteps: &[IpAddr]) -> Result<u32, DriverError> {
        let mut key = vteps.to_vec();
        key.sort();
        key.dedup();
        if let Some(id) = self
            .nexthops
            .lock()
            .unwrap()
            .get(&vni)
            .and_then(|s| s.groups.get(&key))
        {
            return Ok(*id);
        }
        let mut members = Vec::new();
        for vtep in &key {
            let known = self
                .nexthops
                .lock()
                .unwrap()
                .get(&vni)
                .and_then(|s| s.gateways.get(vtep))
                .copied();
            let id = if let Some(id) = known {
                id
            } else {
                let id = self.next_nexthop_id(vni)?;
                self.nexthop(Nexthop::Gateway { id, gateway: *vtep }, 0)
                    .await?;
                self.commit_nexthop(vni, |s| {
                    s.gateways.insert(*vtep, id);
                });
                id
            };
            members.push(id);
        }
        let id = self.next_nexthop_id(vni)?;
        self.nexthop(Nexthop::Group { id, members }, 0).await?;
        self.commit_nexthop(vni, |s| {
            s.groups.insert(key, id);
        });
        Ok(id)
    }

    /// Sends one raw `RTM_NEWNEIGH`/`RTM_DELNEIGH`. `tolerate` is an errno
    /// (negated, as the kernel reports it) that counts as success.
    async fn neigh(
        &self,
        msg: NeighbourMessage,
        delete: bool,
        flags: u16,
        tolerate: i32,
    ) -> Result<(), DriverError> {
        let payload = if delete {
            RouteNetlinkMessage::DelNeighbour(msg)
        } else {
            RouteNetlinkMessage::NewNeighbour(msg)
        };
        let mut req = NetlinkMessage::from(payload);
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
        let mut response = self.handle.clone().request(req)?;
        while let Some(m) = response.next().await {
            if let NetlinkPayload::Error(e) = m.payload {
                if e.raw_code() == -tolerate {
                    continue;
                }
                return Err(rtnetlink::Error::NetlinkError(e).into());
            }
        }
        Ok(())
    }
}

fn master_of(link: &LinkMessage) -> Option<u32> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::Controller(i) => Some(*i),
        _ => None,
    })
}

/// `IFLA_BRPORT_NEIGH_SUPPRESS` as the link dump reports it (`false` when the
/// link isn't a bridge port yet — the kernel default).
fn neigh_suppressed(link: &LinkMessage) -> bool {
    link.attributes
        .iter()
        .filter_map(|a| match a {
            LinkAttribute::LinkInfo(infos) => Some(infos),
            _ => None,
        })
        .flatten()
        .filter_map(|i| match i {
            LinkInfo::PortData(InfoPortData::BridgePort(attrs)) => Some(attrs),
            _ => None,
        })
        .flatten()
        .any(|a| matches!(a, InfoBridgePort::NeighSupress(true)))
}

/// `IFLA_BRPORT_LEARNING` as the link dump reports it (`true` — the kernel
/// default — when the dump carries no port data, as for a just-enslaved link).
fn port_learning(link: &LinkMessage) -> bool {
    !link
        .attributes
        .iter()
        .filter_map(|a| match a {
            LinkAttribute::LinkInfo(infos) => Some(infos),
            _ => None,
        })
        .flatten()
        .filter_map(|i| match i {
            LinkInfo::PortData(InfoPortData::BridgePort(attrs)) => Some(attrs),
            _ => None,
        })
        .flatten()
        .any(|a| matches!(a, InfoBridgePort::Learning(false)))
}

/// A segment pin (`set_segment_mac`): a static bridge FDB entry on `port`
/// that tracks activity, starting inactive unless `active`.
fn segment_mac_msg(port: u32, mac: Mac, active: bool) -> NeighbourMessage {
    let mut m = NeighbourMessage::default();
    m.header.family = AddressFamily::Bridge;
    m.header.ifindex = port;
    m.header.state = NeighbourState::Noarp;
    m.header.flags = NeighbourFlags::Controller;
    let bits = if active {
        FDB_NOTIFY_BIT
    } else {
        FDB_NOTIFY_BIT | FDB_NOTIFY_INACTIVE_BIT
    };
    // One nested NFEA_ACTIVITY_NOTIFY (u8, padded): the kernel insists on
    // NLA_F_NESTED (`nla_parse_nested`).
    m.attributes = vec![
        NeighbourAttribute::LinkLayerAddress(mac.to_vec()),
        NeighbourAttribute::Other(DefaultNla::new(
            NDA_FDB_EXT_ATTRS | NLA_F_NESTED,
            vec![5, 0, NFEA_ACTIVITY_NOTIFY, 0, bits, 0, 0, 0],
        )),
    ];
    m
}

/// Kernel `USER_HZ`: the unit of `NDA_CACHEINFO` times.
const USER_HZ: u32 = 100;

/// `NDA_CACHEINFO` ticks to whole seconds.
fn used_secs(ticks: u32) -> u32 {
    ticks / USER_HZ
}

/// The `used` field of the entry's `NDA_CACHEINFO`, when it carries one.
fn used_of(m: &NeighbourMessage) -> Option<u32> {
    m.attributes.iter().find_map(|a| match a {
        NeighbourAttribute::CacheInfo(c) => Some(c.used),
        _ => None,
    })
}

/// `Some(active)` for an FDB entry that tracks activity, `None` otherwise.
fn fdb_activity(m: &NeighbourMessage) -> Option<bool> {
    m.attributes.iter().find_map(|a| match a {
        NeighbourAttribute::Other(n) if n.kind() & NLA_TYPE_MASK == NDA_FDB_EXT_ATTRS => {
            let mut buf = vec![0; n.buffer_len()];
            n.emit(&mut buf);
            NlasIterator::new(&buf[4..])
                .filter_map(Result::ok)
                .find(|b| b.kind() == u16::from(NFEA_ACTIVITY_NOTIFY))
                .and_then(|b| b.value().first().copied())
                .map(|bits| bits & FDB_NOTIFY_INACTIVE_BIT == 0)
        }
        _ => None,
    })
}

fn link_mac(link: &LinkMessage) -> Option<Mac> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::Address(b) => Mac::try_from(b.as_slice()).ok(),
        _ => None,
    })
}

fn neigh_address(a: &NeighbourAddress) -> Option<IpAddr> {
    match a {
        NeighbourAddress::Inet(a) => Some(IpAddr::V4(*a)),
        NeighbourAddress::Inet6(a) => Some(IpAddr::V6(*a)),
        _ => None,
    }
}

/// One IP neighbour on the bridge `ifindex` (its SVI's ARP/ND table).
fn ip_neigh_msg(ifindex: u32, mac: Mac, ip: IpAddr) -> NeighbourMessage {
    let mut m = NeighbourMessage::default();
    m.header.family = match ip {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    m.header.ifindex = ifindex;
    m.header.state = NeighbourState::Permanent;
    m.header.flags = NeighbourFlags::ExtLearned;
    m.attributes = vec![
        NeighbourAttribute::LinkLayerAddress(mac.to_vec()),
        NeighbourAttribute::Destination(NeighbourAddress::from(ip)),
    ];
    m
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

/// A remote MAC's FDB entry pointing at nexthop group `nhid`. `NDA_NH_ID` is
/// exclusive with a `dst`, `vni` and `via`: the nexthops carry the VTEPs.
fn fdb_group_msg(ifindex: u32, mac: Mac, nhid: u32) -> NeighbourMessage {
    let mut m = NeighbourMessage::default();
    m.header.family = AddressFamily::Bridge;
    m.header.ifindex = ifindex;
    m.header.state = NeighbourState::Permanent;
    m.header.flags = REMOTE_MAC;
    m.attributes = vec![NeighbourAttribute::LinkLayerAddress(mac.to_vec())];
    if nhid != 0 {
        m.attributes.push(NeighbourAttribute::Other(DefaultNla::new(
            NDA_NH_ID,
            nhid.to_ne_bytes().to_vec(),
        )));
    }
    m
}

/// One FDB entry on the vxlan device `ifindex`. `master` also files it in the
/// bridge's own table (with `extern_learn`, so the bridge neither ages nor
/// relearns it); without it, it's a vxlan-only entry (the flood list). `via`
/// is the underlay's ifindex the remote VTEP is reached through.
fn fdb_msg(
    ifindex: u32,
    via: u32,
    mac: Mac,
    dst: IpAddr,
    vni: u32,
    flags: NeighbourFlags,
) -> NeighbourMessage {
    let mut m = NeighbourMessage::default();
    m.header.family = AddressFamily::Bridge;
    m.header.ifindex = ifindex;
    m.header.state = NeighbourState::Permanent;
    m.header.flags = flags;
    m.attributes = vec![
        NeighbourAttribute::LinkLayerAddress(mac.to_vec()),
        NeighbourAttribute::Destination(NeighbourAddress::from(dst)),
        NeighbourAttribute::Vni(vni),
        NeighbourAttribute::IfIndex(via),
    ];
    m
}

const REMOTE_MAC: NeighbourFlags = NeighbourFlags::Own
    .union(NeighbourFlags::Controller)
    .union(NeighbourFlags::ExtLearned);

#[async_trait]
impl FdbDriver for LinuxFdbDriver {
    async fn ensure_vxlan(
        &self,
        vni: u32,
        vtep: IpAddr,
        underlay: &str,
        bridge: &str,
        neigh_suppress: bool,
    ) -> Result<(), DriverError> {
        let bridge_idx = self
            .find_link(bridge)
            .await?
            .ok_or_else(|| DriverError::Other(format!("bridge {bridge} does not exist yet")))?
            .header
            .index;
        let underlay_link = self
            .find_link(underlay)
            .await?
            .ok_or_else(|| DriverError::Other(format!("underlay {underlay} does not exist yet")))?;
        let underlay_idx = underlay_link.header.index;
        let underlay_master = master_of(&underlay_link);
        let name = vxlan_name(vni);

        let mut link = self.find_link(&name).await?;
        if let Some(l) = &link {
            if !vxlan_matches(l, vni, vtep, underlay_idx) {
                info!(vxlan = %name, vni, vtep = %vtep, "vxlan device drifted, recreating");
                self.handle.link().del(l.header.index).execute().await?;
                link = None;
            } else if self.bound_master.lock().unwrap().get(&vni) != Some(&underlay_master) {
                // Reopening the socket is enough, and keeps every entry: a
                // down flushes only non-permanent VXLAN entries, and the bridge
                // keeps extern-learned ones.
                self.handle
                    .link()
                    .set(LinkUnspec::new_with_index(l.header.index).down().build())
                    .execute()
                    .await?;
                info!(vxlan = %name, vni, "vxlan device reopened in its underlay's vrf");
            }
        }
        let link = if let Some(l) = link {
            l
        } else {
            let b = LinkVxlan::new(&name, vni)
                .dev(underlay_idx)
                .port(VXLAN_PORT)
                .learning(false);
            let b = match vtep {
                IpAddr::V4(a) => b.local(a),
                IpAddr::V6(a) => b.local6(a),
            };
            self.handle.link().add(b.build()).execute().await?;
            info!(vxlan = %name, vni, vtep = %vtep, underlay = %underlay, "created vxlan device");
            self.find_link(&name).await?.ok_or_else(|| {
                DriverError::Other(format!("created {name} but could not find it"))
            })?
        };
        let idx = link.header.index;
        if master_of(&link) != Some(bridge_idx) {
            self.handle
                .link()
                .set(
                    LinkUnspec::new_with_index(idx)
                        .controller(bridge_idx)
                        .build(),
                )
                .execute()
                .await?;
            info!(vxlan = %name, bridge = %bridge, "enslaved vxlan device to bridge");
        }
        // Read back every tick, so a recreated port is healed and unsetting
        // works too. A just-enslaved link's dump carried no port data: off.
        // ponytail: the same flag suppresses IPv6 ND, untested end to end, and a
        // proxied NA's Router flag isn't signalled (no RFC 9047 community).
        if neigh_suppressed(&link) != neigh_suppress {
            self.set_bridge_port(idx, vec![InfoBridgePort::NeighSupress(neigh_suppress)])
                .await?;
            info!(vxlan = %name, suppress = neigh_suppress, "vxlan neigh suppression set");
        }
        // RFC 7432 §9.2: remote MACs come from the control plane only. With
        // bridge-port learning on, a CE's broadcast another segment PE floods
        // here would move the CE's segment pin behind this port.
        if port_learning(&link) {
            self.set_bridge_port(idx, vec![InfoBridgePort::Learning(false)])
                .await?;
            info!(vxlan = %name, "vxlan port learning disabled");
        }
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).up().build())
            .execute()
            .await?;
        self.bound_master
            .lock()
            .unwrap()
            .insert(vni, underlay_master);
        self.ifindex.lock().unwrap().insert(vni, idx);
        self.underlay.lock().unwrap().insert(vni, underlay_idx);
        Ok(())
    }

    async fn remove_vxlan(&self, vni: u32) -> Result<(), DriverError> {
        self.bound_master.lock().unwrap().remove(&vni);
        self.bias.lock().unwrap().remove(&vni);
        self.ifindex.lock().unwrap().remove(&vni);
        self.underlay.lock().unwrap().remove(&vni);
        // Best effort, like the nexthops below: a nop rule left behind only
        // keeps tunnel metadata collection on.
        let _ = self.metadata_rule(vni, false).await;
        if let Some(l) = self.find_link(&vxlan_name(vni)).await? {
            self.handle.link().del(l.header.index).execute().await?;
            info!(vxlan = %vxlan_name(vni), "deleted vxlan device");
        }
        // The nexthops outlive the device; groups first, then what they hold.
        let state = self.nexthops.lock().unwrap().remove(&vni);
        for id in state.into_iter().flat_map(|s| {
            let groups = s.groups.into_values().collect::<Vec<_>>();
            groups.into_iter().chain(s.gateways.into_values())
        }) {
            // Best effort: the kernel already dropped whatever went with them.
            let _ = self.nexthop(Nexthop::Delete { id }, ENOENT).await;
        }
        Ok(())
    }

    async fn set_remote_mac(&self, vni: u32, mac: Mac, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, self.via(vni), mac, vtep, vni, REMOTE_MAC);
        self.neigh(msg, false, NLM_F_CREATE | NLM_F_REPLACE, 0)
            .await
    }

    async fn del_remote_mac(&self, vni: u32, mac: Mac, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, self.via(vni), mac, vtep, vni, REMOTE_MAC);
        self.neigh(msg, true, 0, ENOENT).await
    }

    async fn set_remote_mac_group(
        &self,
        vni: u32,
        mac: Mac,
        vteps: &[IpAddr],
    ) -> Result<(), DriverError> {
        let nhid = self.ensure_group(vni, vteps).await?;
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_group_msg(idx, mac, nhid);
        // A REPLACE does not turn a `dst` entry into a nexthop one (or the
        // reverse): the kernel keeps the old form. Delete first.
        self.neigh(msg.clone(), true, 0, ENOENT).await?;
        self.neigh(msg, false, NLM_F_CREATE | NLM_F_REPLACE, 0)
            .await
    }

    async fn del_remote_mac_group(&self, vni: u32, mac: Mac) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        self.neigh(fdb_group_msg(idx, mac, 0), true, 0, ENOENT)
            .await
    }

    async fn set_segment_mac(&self, port: &str, mac: Mac, active: bool) -> Result<(), DriverError> {
        let idx = self.bridge_index(port).await?;
        self.neigh(
            segment_mac_msg(idx, mac, active),
            false,
            NLM_F_CREATE | NLM_F_REPLACE,
            0,
        )
        .await
    }

    async fn del_segment_mac(&self, port: &str, mac: Mac) -> Result<(), DriverError> {
        // ponytail: deletes whatever the bridge holds for `mac` on `port`, so
        // an entry relearned there meanwhile goes too — one flood until the
        // next frame relearns it.
        let idx = self.bridge_index(port).await?;
        self.neigh(segment_mac_msg(idx, mac, false), true, 0, ENOENT)
            .await
    }

    async fn add_flood(&self, vni: u32, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, self.via(vni), [0; 6], vtep, vni, NeighbourFlags::Own);
        // APPEND: the all-zero MAC carries one destination per remote VTEP,
        // and `NeighbourAddRequest` offers no way to set it. An identical
        // destination already present is left alone by the kernel.
        self.neigh(msg, false, NLM_F_CREATE | NLM_F_APPEND, 0).await
    }

    async fn del_flood(&self, vni: u32, vtep: IpAddr) -> Result<(), DriverError> {
        let idx = self.vxlan_index(vni).await?;
        let msg = fdb_msg(idx, self.via(vni), [0; 6], vtep, vni, NeighbourFlags::Own);
        self.neigh(msg, true, 0, ENOENT).await
    }

    async fn set_port_flood(
        &self,
        port: &str,
        unicast: bool,
        bum: bool,
    ) -> Result<(), DriverError> {
        let link = self
            .find_link(port)
            .await?
            .ok_or_else(|| DriverError::Other(format!("port {port} does not exist yet")))?;
        // `ip link set dev <port> type bridge_slave flood .. mcast_flood ..
        // bcast_flood ..`.
        self.set_bridge_port(
            link.header.index,
            vec![
                InfoBridgePort::UnicastFlood(unicast),
                InfoBridgePort::MulticastFlood(bum),
                InfoBridgePort::BroadcastFlood(bum),
            ],
        )
        .await
    }

    async fn set_segment_filter(
        &self,
        port: &str,
        bit: u16,
        df_filter: bool,
    ) -> Result<(), DriverError> {
        let ifindex = self.bridge_index(port).await?;
        self.tc(Request::Clsact { ifindex }, &[EEXIST]).await?;
        self.tc(drop_marked(ifindex, PRIO_FIRST, bit), &[]).await?;
        if df_filter {
            self.tc(drop_marked(ifindex, PRIO_SECOND, 0), &[]).await
        } else {
            self.tc_flush(ifindex, Hook::Egress, PRIO_SECOND).await
        }
    }

    async fn clear_segment_filter(&self, port: &str) -> Result<(), DriverError> {
        let Some(link) = self.find_link(port).await? else {
            return Ok(());
        };
        let ifindex = link.header.index;
        self.tc_flush(ifindex, Hook::Egress, PRIO_FIRST).await?;
        self.tc_flush(ifindex, Hook::Egress, PRIO_SECOND).await
    }

    async fn set_local_bias(
        &self,
        vni: u32,
        peers: &BTreeMap<IpAddr, u16>,
    ) -> Result<(), DriverError> {
        let ifindex = self.vxlan_index(vni).await?;
        if peers.is_empty() {
            self.tc_flush(ifindex, Hook::Ingress, PRIO_FIRST).await?;
            self.tc_flush(ifindex, Hook::Ingress, PRIO_SECOND).await?;
            self.bias.lock().unwrap().remove(&vni);
            return self.metadata_rule(vni, false).await;
        }
        // Before the marking: an `enc_src_ip` match needs tunnel metadata.
        self.metadata_rule(vni, true).await?;
        self.tc(Request::Clsact { ifindex }, &[EEXIST]).await?;
        let before = self.bias.lock().unwrap().get(&vni).copied();
        if before.is_none() {
            // A first call in this process: whatever an earlier one (killed
            // before it cleaned up) left under a handle we no longer know goes.
            self.tc_flush(ifindex, Hook::Ingress, PRIO_FIRST).await?;
        }
        // Handle n is the n-th peer in address order; a peer set that changed
        // overwrites in place, so the marking is never absent in between.
        for (n, (peer, bit)) in (1u32..).zip(peers) {
            self.tc(mark_filter(ifindex, PRIO_FIRST, n, Some(*peer), *bit), &[])
                .await?;
        }
        let kept = u32::try_from(peers.len()).unwrap_or(u32::MAX);
        let had = u32::try_from(before.unwrap_or(0)).unwrap_or(u32::MAX);
        for handle in (kept + 1)..=had {
            self.tc(
                delete_filter(ifindex, Hook::Ingress, PRIO_FIRST, handle),
                NO_FILTER,
            )
            .await?;
        }
        // The catch-all: every other core-origin BUM frame, magic byte only.
        self.tc(mark_filter(ifindex, PRIO_SECOND, 1, None, 0), &[])
            .await?;
        self.bias.lock().unwrap().insert(vni, peers.len());
        Ok(())
    }

    async fn set_port_forwarding(&self, port: &str, forwarding: bool) -> Result<(), DriverError> {
        let link = self
            .find_link(port)
            .await?
            .ok_or_else(|| DriverError::Other(format!("port {port} does not exist yet")))?;
        // `bridge link set dev <port> state 0|3`: an RTM_SETLINK in the
        // AF_BRIDGE family carrying the port data under IFLA_PROTINFO. Not the
        // slave-data path `set_port_flood` uses — that one accepts
        // IFLA_BRPORT_STATE and silently ignores it. The block is DISABLED, not
        // BLOCKING: with the bridge's STP off the kernel's
        // `br_port_state_selection` turns every other port straight back to
        // forwarding (a BLOCKING write is undone at once), but skips disabled
        // ones. A disabled port drops frames in both directions.
        let state = if forwarding {
            BR_STATE_FORWARDING
        } else {
            BR_STATE_DISABLED
        };
        let mut msg = LinkMessage::default();
        msg.header.interface_family = AddressFamily::Bridge;
        msg.header.index = link.header.index;
        msg.attributes.push(LinkAttribute::ProtoInfoBridge(vec![
            LinkProtoInfoBridge::Other(DefaultNla::new(IFLA_BRPORT_STATE, vec![state])),
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

    async fn port_up(&self, port: &str) -> Result<bool, DriverError> {
        Ok(self
            .find_link(port)
            .await?
            .is_some_and(|l| l.header.flags.contains(LinkFlags::LowerUp)))
    }

    async fn local_macs(
        &self,
        bridge: &str,
        vni: u32,
    ) -> Result<BTreeMap<Mac, String>, DriverError> {
        let e = self.local_entries(bridge, vni).await?;
        Ok(e.into_iter().map(|(m, (port, _))| (m, port)).collect())
    }

    async fn local_mac_ages(
        &self,
        bridge: &str,
        vni: u32,
    ) -> Result<BTreeMap<Mac, u32>, DriverError> {
        let e = self.local_entries(bridge, vni).await?;
        Ok(e.into_iter()
            .filter_map(|(m, (_, a))| a.map(|a| (m, a)))
            .collect())
    }

    async fn local_neighbours(&self, bridge: &str) -> Result<BTreeSet<(Mac, IpAddr)>, DriverError> {
        let bridge_idx = self.bridge_index(bridge).await?;
        let mut out = BTreeSet::new();
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut dump = self
                .handle
                .neighbours()
                .get()
                .set_address_family(family)
                .execute();
            while let Some(m) = dump.try_next().await? {
                let mut mac = None;
                let mut ip = None;
                for a in &m.attributes {
                    match a {
                        NeighbourAttribute::LinkLayerAddress(b) => {
                            mac = Mac::try_from(b.as_slice()).ok();
                        }
                        NeighbourAttribute::Destination(d) => ip = neigh_address(d),
                        _ => {}
                    }
                }
                let (Some(mac), Some(ip)) = (mac, ip) else {
                    continue;
                };
                let usable = matches!(
                    m.header.state,
                    NeighbourState::Reachable
                        | NeighbourState::Stale
                        | NeighbourState::Delay
                        | NeighbourState::Probe
                        | NeighbourState::Permanent
                );
                if is_local_neigh(
                    mac,
                    ip,
                    usable,
                    m.header.flags.contains(NeighbourFlags::ExtLearned),
                    m.header.ifindex,
                    bridge_idx,
                ) {
                    out.insert((mac, ip));
                }
            }
        }
        Ok(out)
    }

    async fn bridge_mac(&self, bridge: &str) -> Result<Mac, DriverError> {
        self.find_link(bridge)
            .await?
            .as_ref()
            .and_then(link_mac)
            .ok_or_else(|| DriverError::Other(format!("bridge {bridge} has no MAC yet")))
    }

    async fn set_neigh(&self, bridge: &str, mac: Mac, ip: IpAddr) -> Result<(), DriverError> {
        let msg = ip_neigh_msg(self.bridge_index(bridge).await?, mac, ip);
        self.neigh(msg, false, NLM_F_CREATE | NLM_F_REPLACE, 0)
            .await
    }

    async fn del_neigh(&self, bridge: &str, mac: Mac, ip: IpAddr) -> Result<(), DriverError> {
        let msg = ip_neigh_msg(self.bridge_index(bridge).await?, mac, ip);
        self.neigh(msg, true, 0, ENOENT).await
    }

    fn watch_neigh(&self) -> Option<mpsc::Receiver<()>> {
        let (conn, _handle, mut messages) =
            rtnetlink::new_multicast_connection(&[MulticastGroup::Neigh, MulticastGroup::Link])
                .ok()?;
        nos_log_client::spawn_critical("rtnetlink-connection", conn);
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            while let Some((msg, _)) = messages.next().await {
                // Bridge FDB (MACs) and ARP/ND (IP neighbours) alike, and a
                // link changing state (an Ethernet Segment's carrier).
                let relevant = match &msg.payload {
                    NetlinkPayload::InnerMessage(
                        RouteNetlinkMessage::NewNeighbour(n) | RouteNetlinkMessage::DelNeighbour(n),
                    ) => matches!(
                        n.header.family,
                        AddressFamily::Bridge | AddressFamily::Inet | AddressFamily::Inet6
                    ),
                    NetlinkPayload::InnerMessage(
                        RouteNetlinkMessage::NewLink(_) | RouteNetlinkMessage::DelLink(_),
                    ) => true,
                    _ => false,
                };
                if relevant && !super::wake(&tx) {
                    break;
                }
            }
            debug!("neighbour notification stream ended");
        });
        Some(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_metadata_rule_is_a_nop_on_a_64_bit_big_endian_tun_id() {
        let m = metadata_rule(10100);
        assert_eq!(m.header.family, AddressFamily::Inet);
        assert_eq!(m.header.action, RuleAction::Nop);
        assert_eq!(m.attributes[0], RuleAttribute::Priority(METADATA_RULE_PREF));
        let RuleAttribute::Other(n) = &m.attributes[1] else {
            panic!("no tun_id");
        };
        let mut buf = vec![0; n.buffer_len()];
        n.emit(&mut buf);
        // len 12, FRA_TUN_ID, then 0x000000E5_00002774 in network order.
        assert_eq!(buf, [12, 0, 12, 0, 0, 0, 0, 0xE5, 0, 0, 0x27, 0x74]);
    }

    #[test]
    fn a_segment_pin_carries_and_reads_back_its_activity() {
        assert_eq!(
            fdb_activity(&segment_mac_msg(3, [0; 6], false)),
            Some(false)
        );
        assert_eq!(fdb_activity(&segment_mac_msg(3, [0; 6], true)), Some(true));
        assert_eq!(fdb_activity(&NeighbourMessage::default()), None);
        // The wire form the kernel parses: nested flag, then one u8 NLA.
        let NeighbourAttribute::Other(n) = &segment_mac_msg(3, [0; 6], false).attributes[1] else {
            panic!("no ext attrs");
        };
        let mut buf = vec![0; n.buffer_len()];
        n.emit(&mut buf);
        assert_eq!(buf, [12, 0, 14, 0x80, 5, 0, 1, 0, 3, 0, 0, 0]);
    }

    #[test]
    fn port_learning_defaults_on_and_reads_the_flag() {
        let port = |attrs| {
            let mut l = LinkMessage::default();
            l.attributes
                .push(LinkAttribute::LinkInfo(vec![LinkInfo::PortData(
                    InfoPortData::BridgePort(attrs),
                )]));
            l
        };
        assert!(port_learning(&LinkMessage::default()));
        assert!(port_learning(&port(vec![InfoBridgePort::Learning(true)])));
        assert!(!port_learning(&port(vec![InfoBridgePort::Learning(false)])));
    }

    #[test]
    fn neigh_suppressed_reads_the_bridge_port_flag() {
        let port = |attrs| {
            let mut l = LinkMessage::default();
            l.attributes.push(LinkAttribute::LinkInfo(vec![
                LinkInfo::PortKind(InfoPortKind::Bridge),
                LinkInfo::PortData(InfoPortData::BridgePort(attrs)),
            ]));
            l
        };
        assert!(!neigh_suppressed(&LinkMessage::default()));
        assert!(!neigh_suppressed(&port(vec![InfoBridgePort::Learning(
            false
        )])));
        assert!(!neigh_suppressed(&port(vec![
            InfoBridgePort::NeighSupress(false)
        ])));
        assert!(neigh_suppressed(&port(vec![
            InfoBridgePort::Learning(false),
            InfoBridgePort::NeighSupress(true),
        ])));
    }

    #[test]
    fn used_ticks_become_seconds() {
        assert_eq!(used_secs(0), 0);
        assert_eq!(used_secs(99), 0);
        assert_eq!(used_secs(100), 1);
        assert_eq!(used_secs(12345), 123);
        assert_eq!(used_secs(u32::MAX), 42_949_672);
    }

    #[test]
    fn used_of_reads_the_cacheinfo() {
        let mut m = NeighbourMessage::default();
        assert_eq!(used_of(&m), None);
        let mut b = vec![0u8; 16];
        b[4..8].copy_from_slice(&500u32.to_ne_bytes());
        let info = rtnetlink::packet_route::neighbour::NeighbourCacheInfo::parse(&b).unwrap();
        m.attributes.push(NeighbourAttribute::CacheInfo(info));
        assert_eq!(used_of(&m), Some(500));
    }
}
