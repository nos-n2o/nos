use garde::Validate;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::validators::{
    bfd_reference_valid, ospf_profile_reference_valid, ospfv3_profile_reference_valid,
    routing_table_reference_valid, stp_port_profile_reference_valid, unique_addresses,
    unique_key_in,
};

use super::{Config, LldpDestination, VlanTag};
use nos_proto_derive::Cli;

use super::sugar;

/// Any `Interface.name` starting with this prefix is a loopback interface
/// for the routing table named by the rest of the string (e.g.
/// `loopback-rt1` is a loopback for routing table `rt1`) — see
/// `loopback_table_name`. There is no separate "kind" field: identity is
/// carried entirely by the name, which also means the existing
/// `Interface.name` uniqueness check already guarantees at most one
/// loopback per routing table, for free.
pub const LOOPBACK_PREFIX: &str = "loopback-";

/// Extracts the target routing table name from a loopback interface name,
/// or `None` if `name` isn't a loopback (doesn't start with
/// `LOOPBACK_PREFIX`, or has nothing after it). Shared by `nos-config`'s
/// commit-time validation (below) and `nos-interfaced`'s Linux driver,
/// which both need the identical rule.
pub fn loopback_table_name(name: &str) -> Option<&str> {
    name.strip_prefix(LOOPBACK_PREFIX).filter(|t| !t.is_empty())
}

/// One address on an interface, with an optional label. The label is
/// stored from commit time onward but not yet applied to the kernel by any
/// driver (no `ip addr ... label` call) — schema/plumbing only for now.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Cli, Default)]
pub struct InterfaceAddress {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// Address with prefix length, e.g. `192.0.2.1/24`; the key.
    pub address: IpNet,
    #[cli(topic = InterfaceAddress)]
    /// Optional label to pick this address by, e.g. from a BGP source address; not yet applied to the kernel.
    pub label: Option<String>,
}

/// One VLAN-scoped L3 attachment point on a physical `Interface`. `tag == 0`
/// is the untagged/native case — what used to be `Interface.addresses`/
/// `routing_table` directly, before L3 config moved under per-tag
/// subinterfaces. `1..=4094` is a real 802.1q tag, realized by
/// `nos-interfaced`'s Linux driver as its own `<interface>.<tag>` kernel
/// sub-interface (the same convention already used for a `Dot1q`
/// switching-profile member). A tag used by a `Subinterface` here and a tag
/// used by the same interface's `switching_profile` (an `Untagged` member
/// claims tag 0, a `Dot1q(n)` member claims tag `n`) must be disjoint — see
/// `valid_subinterface_and_switching_profile_tags`. Loopback interfaces
/// never have any `Subinterface`s — see `valid_addressing_split`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct Subinterface {
    #[garde(custom(|t: &u16, _ctx: &Config| valid_subinterface_tag(*t)))]
    #[cli(key)]
    /// 802.1Q VLAN id of the subinterface; 0 is the untagged attachment.
    pub tag: u16,

    #[garde(custom(|addrs, _ctx: &Config| unique_addresses(addrs)))]
    #[cli(topic = InterfaceAddress)]
    /// Addresses on this subinterface, no duplicates.
    pub addresses: Vec<InterfaceAddress>,

    #[garde(custom(|rt: &Option<String>, ctx: &Config| routing_table_reference_valid(rt.as_ref(), ctx)))]
    #[cli(topic = InterfaceRoutingTable)]
    /// Routing table (VRF) the subinterface joins, if any.
    pub routing_table: Option<String>,

    /// If set, names an `OspfProfile` this subinterface joins OSPF under.
    /// Requires `routing_table` also set on this same subinterface — OSPF
    /// has no meaning without an L3/VRF context, see
    /// `valid_subinterface_ospf_profile_requires_routing_table`.
    #[garde(custom(|p: &Option<String>, ctx: &Config| ospf_profile_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = InterfaceOspfProfile, words = "ospf")]
    pub ospf_profile: Option<String>,

    /// Same shape as `ospf_profile`, joining `OSPFv3` (RFC 5340) instead — a
    /// separate field, not a widened `ospf_profile`, so one subinterface can
    /// run v2 and v3 simultaneously (real dual-stack routers do this
    /// routinely). Also requires `routing_table` set on this same
    /// subinterface — see `valid_subinterface_ospf_profile_requires_routing_table`.
    #[garde(custom(|p: &Option<String>, ctx: &Config| ospfv3_profile_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = InterfaceOspfv3Profile, words = "ospfv3")]
    pub ospfv3_profile: Option<String>,

    /// Overrides the MTU of this VLAN sub-link, in bytes. `None` follows the
    /// parent's MTU. Must not exceed the parent's effective MTU and is
    /// rejected on tag 0 (the physical link itself) — see
    /// `valid_subinterface_mtus`.
    #[serde(default)]
    #[garde(custom(|m: &Option<u32>, _ctx: &Config| valid_mtu(*m)))]
    #[cli(topic = SubinterfaceMtu, words = "mtu")]
    pub mtu: Option<u32>,

    /// RFC 9468: names a `BfdProfile` for the passive sessions created by
    /// unsolicited BFD Control packets (Your Discriminator 0) on this
    /// subinterface. Requires `routing_table` on the same subinterface: the
    /// VRF decides the socket.
    #[serde(default)]
    #[garde(custom(|p: &Option<String>, ctx: &Config| bfd_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = InterfaceBfdUnsolicited, words = "bfd-unsolicited")]
    pub bfd_unsolicited: Option<String>,

    /// Names an `Acl` filtering IP packets arriving on this subinterface; the
    /// placement rules are `acl::valid_acl_references`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceAclIn, words = "acl in")]
    pub acl_in: Option<String>,

    /// Names an `Acl` filtering IP packets leaving this subinterface.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceAclOut, words = "acl out")]
    pub acl_out: Option<String>,

    /// Applies the flowspec rules of the BGP instance owning this device's
    /// routing table to the IP packets arriving here (RFC 8955 section 5:
    /// ingress only); placement rules are `acl::valid_flowspec_placements`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceFlowspec, words = "flowspec")]
    pub flowspec: bool,
}

fn valid_subinterface_tag(tag: u16) -> garde::Result {
    if tag > 4094 {
        return Err(garde::Error::new(
            "subinterface tag must be between 0 and 4094",
        ));
    }
    Ok(())
}

/// No two subinterfaces of the same physical interface may share a tag —
/// mirrors `switching_profile::unique_broadcast_domains`. Scoped to
/// `self.subinterfaces` only.
fn unique_subinterface_tags(subinterfaces: &[Subinterface]) -> garde::Result {
    let mut seen: Vec<u16> = Vec::new();
    for sub in subinterfaces {
        if seen.contains(&sub.tag) {
            return Err(garde::Error::new(
                "must not repeat a tag among the same interface's subinterfaces",
            ));
        }
        seen.push(sub.tag);
    }
    Ok(())
}

/// A subinterface's `ospf_profile`, if set, requires `routing_table` also
/// set on the *same* subinterface — OSPF has no meaning without an L3/VRF
/// context. Mirrors `valid_addressing_split`'s equivalent check on a
/// loopback `Interface`.
fn valid_subinterface_ospf_profile_requires_routing_table(
    subinterfaces: &[Subinterface],
) -> garde::Result {
    for sub in subinterfaces {
        if sub.ospf_profile.is_some() && sub.routing_table.is_none() {
            return Err(garde::Error::new(
                "ospf profile requires a routing-table on the same subinterface",
            ));
        }
        if sub.ospfv3_profile.is_some() && sub.routing_table.is_none() {
            return Err(garde::Error::new(
                "ospfv3 profile requires a routing-table on the same subinterface",
            ));
        }
        if sub.bfd_unsolicited.is_some() && sub.routing_table.is_none() {
            return Err(garde::Error::new(
                "bfd unsolicited requires a routing-table on the same subinterface",
            ));
        }
    }
    Ok(())
}

/// Umbrella validator for `Interface.subinterfaces` combining the two
/// cross-field checks above — see each for details. `pub(crate)` since
/// `PortAggregate.subinterfaces` (same type, same rules) reuses this
/// verbatim.
pub(crate) fn valid_subinterface_list(subinterfaces: &[Subinterface]) -> garde::Result {
    unique_subinterface_tags(subinterfaces)?;
    valid_subinterface_ospf_profile_requires_routing_table(subinterfaces)?;
    Ok(())
}

/// Effective MTU of a link with no explicit `mtu` (Linux's default).
pub(crate) const DEFAULT_MTU: u32 = 1500;

/// A subinterface `mtu` override must be on a real VLAN (tag != 0) and not
/// exceed the parent's effective MTU (`mtu`, else 1500): the kernel refuses a
/// VLAN MTU above its lower device. Also catches lowering the parent below an
/// existing override. `pub(crate)` since `PortAggregate` reuses it.
pub(crate) fn valid_subinterface_mtus(
    subinterfaces: &[Subinterface],
    parent_mtu: Option<u32>,
) -> garde::Result {
    let parent = parent_mtu.unwrap_or(DEFAULT_MTU);
    for sub in subinterfaces {
        let Some(m) = sub.mtu else { continue };
        if sub.tag == 0 {
            return Err(garde::Error::new(
                "mtu cannot be set on the untagged subinterface (tag 0): set the parent's mtu",
            ));
        }
        if m > parent {
            return Err(garde::Error::new(format!(
                "subinterface {} mtu {m} exceeds the parent's mtu {parent}",
                sub.tag
            )));
        }
    }
    Ok(())
}

/// A named network interface. For a loopback interface (see
/// `LOOPBACK_PREFIX`), `addresses`/`routing_table` carry its (flat) L3
/// config directly, exactly as before this type gained subinterfaces — a
/// loopback has no VLAN/dot1q concept, so there's nothing for per-tag
/// addressing to buy it. For every other (physical) interface, `addresses`
/// must be empty and `routing_table` must be unset: all of its L3 config
/// lives under `subinterfaces` instead, tag 0 for the untagged/native case
/// (what used to be these same flat fields) — see `valid_addressing_split`.
///
/// `switching_profile`, if set, names a `SwitchingProfile` trunking this
/// interface into one or more `BroadcastDomain`s — unchanged, still a
/// physical-interface-level field regardless of `subinterfaces`. A tag
/// claimed by an L2 `switching_profile` member and a tag claimed by an L3
/// `Subinterface` are mutually exclusive on the same interface: Linux only
/// allows one master device per link (physical or per-tag sub-link), and an
/// L2 member wants that link's master to be the domain's bridge while an L3
/// subinterface wants it to be a VRF. See
/// `valid_subinterface_and_switching_profile_tags`, wired one level up on
/// `Config.interfaces` (`valid_interfaces`) since it needs to see sibling
/// fields — the same reason `RoutingTable`'s redistribute rule is wired on
/// `Config.routing_tables`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct Interface {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| interface_name_valid(n, ctx))
    )]
    #[cli(key)]
    /// Kernel interface name; `loopback-<table>` is a routing table's loopback.
    pub name: String,

    #[garde(custom(|addrs, _ctx: &Config| unique_addresses(addrs)))]
    #[cli(topic = InterfaceAddress)]
    /// Addresses on the link itself (the loopback case); a physical interface carries L3 config on subinterfaces.
    pub addresses: Vec<InterfaceAddress>,

    #[garde(custom(|rt: &Option<String>, ctx: &Config| routing_table_reference_valid(rt.as_ref(), ctx)))]
    #[cli(topic = InterfaceRoutingTable)]
    /// Routing table (VRF) the link joins, if any.
    pub routing_table: Option<String>,

    /// If set, names an `OspfProfile` this loopback interface joins OSPF
    /// under. Requires `routing_table` also set — see
    /// `valid_addressing_split`. Unused (must be unset) on a physical
    /// interface — its OSPF attachment lives on a `Subinterface` instead,
    /// like `routing_table`.
    #[garde(custom(|p: &Option<String>, ctx: &Config| ospf_profile_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = InterfaceOspfProfile, words = "ospf")]
    pub ospf_profile: Option<String>,

    /// Same shape as `ospf_profile`, joining `OSPFv3` (RFC 5340) instead — see
    /// `Subinterface.ospfv3_profile`'s doc comment for why this is a
    /// separate field rather than a widened `ospf_profile`.
    #[garde(custom(|p: &Option<String>, ctx: &Config| ospfv3_profile_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = InterfaceOspfv3Profile, words = "ospfv3")]
    pub ospfv3_profile: Option<String>,

    #[garde(custom(|sp: &Option<String>, ctx: &Config| switching_profile_reference_valid(sp.as_ref(), ctx)))]
    #[cli(topic = InterfaceSwitchingProfile)]
    /// `SwitchingProfile` that makes this interface an L2 switch port.
    pub switching_profile: Option<String>,

    /// If set, names a `PortAggregate` this interface is a static bonded
    /// member of. Mutually exclusive with `switching_profile` and a non-empty
    /// `subinterfaces` — a bonded slave, like a VRF- or bridge-enslaved link,
    /// can only have one Linux master device. See
    /// `valid_port_aggregate_membership`.
    #[garde(custom(|pa: &Option<String>, ctx: &Config| port_aggregate_reference_valid(pa.as_ref(), ctx)))]
    #[cli(topic = InterfacePortAggregate)]
    pub port_aggregate: Option<String>,

    /// Names an `StpPortProfile` for this link as a spanning-tree port. Inert
    /// until `nos-stpd`; refused on a bond member (the STP port is the bond).
    #[serde(default)]
    #[garde(custom(|p: &Option<String>, ctx: &Config| stp_port_profile_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = InterfaceStpPortProfile, words = "stp-port-profile")]
    pub stp_port_profile: Option<String>,

    /// Names an `Acl` filtering IP packets arriving on this link; the placement
    /// rules are `acl::valid_acl_references`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceAclIn, words = "acl in")]
    pub acl_in: Option<String>,

    /// Names an `Acl` filtering IP packets leaving this link.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceAclOut, words = "acl out")]
    pub acl_out: Option<String>,

    /// Applies the flowspec rules of the BGP instance owning this device's
    /// routing table to the IP packets arriving here (RFC 8955 section 5:
    /// ingress only); placement rules are `acl::valid_flowspec_placements`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceFlowspec, words = "flowspec")]
    pub flowspec: bool,

    /// The LACP Actor Port Priority `nos-lacpd` advertises for this link
    /// (802.1AX); `None` = 32768. Lower is higher priority. Only meaningful
    /// while `port_aggregate` names a `Lacp`-mode aggregate; ignored (not
    /// rejected) otherwise.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceLacpPortPriority)]
    pub lacp_port_priority: Option<u16>,

    /// This link's LACP Activity (`Passive` = never speaks first). Only
    /// meaningful while `port_aggregate` names a `Lacp`-mode aggregate;
    /// ignored (not rejected) otherwise.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceLacpMode, words = "lacp mode")]
    pub lacp_mode: crate::schema::LacpMode,

    /// The link's MTU, in bytes. A link-layer property of the physical (or
    /// loopback) interface itself — unlike `addresses`/`routing_table`, it's
    /// not part of the loopback/physical addressing split (see
    /// `valid_addressing_split`): a VLAN `Subinterface` follows this
    /// value unless it sets its own (smaller) `mtu`. `None` leaves whatever MTU the
    /// kernel link already has untouched (`nos-interfaced`'s Linux driver
    /// never resets it to a default) rather than forcing 1500.
    #[garde(custom(|m: &Option<u32>, _ctx: &Config| valid_mtu(*m)))]
    #[cli(topic = InterfaceMtu)]
    pub mtu: Option<u32>,

    /// Whether `nos-lldpd` transmits LLDPDUs (IEEE 802.1AB) on this link.
    /// Physical interfaces only — see `valid_lldp_physical_only`. `serde(default)`
    /// so on-disk config saved before this field existed still loads.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceLldpTransmit, words = "lldp transmit")]
    pub lldp_transmit: bool,

    /// Whether `nos-lldpd` receives and records neighbors' LLDPDUs on this
    /// link. Independent of `lldp_transmit`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceLldpReceive, words = "lldp receive")]
    pub lldp_receive: bool,

    /// Which 802.1AB destination group this link's LLDPDUs use. Both ends
    /// must agree. Physical interfaces only — see `valid_lldp_physical_only`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceLldpDestination, words = "lldp destination")]
    pub lldp_destination: LldpDestination,

    #[garde(dive, custom(|subs, _ctx: &Config| valid_subinterface_list(subs)))]
    #[cli(
        topic = Subinterface,
        sugar(word = "address", with = sugar::untagged_address, topic = InterfaceAddress),
        sugar(word = "routing-table", with = sugar::untagged_routing_table, topic = InterfaceRoutingTable),
        sugar(word = "ospf", with = sugar::untagged_ospf, topic = InterfaceOspfProfile),
        sugar(word = "ospfv3", with = sugar::untagged_ospfv3, topic = InterfaceOspfv3Profile)
    )]
    /// L3 attachment points of a physical interface, one per VLAN tag.
    pub subinterfaces: Vec<Subinterface>,
}

/// RFC 791's IPv4 minimum through Linux's practical link-layer ceiling.
pub(crate) fn valid_mtu(mtu: Option<u32>) -> garde::Result {
    match mtu {
        Some(m) if !(68..=65535).contains(&m) => {
            Err(garde::Error::new("mtu must be between 68 and 65535"))
        }
        _ => Ok(()),
    }
}

/// Combines interface-name uniqueness (existing) with rejecting a literal
/// `.` (reserved for `<interface>.<tag>` subinterface addressing) and, for a
/// loopback name, checking its target routing table actually exists — one
/// closure rather than stacking three `custom(...)` attributes, matching the
/// pattern used where a field needs more than one rule (e.g.
/// `BgpPeerGroup.auth`'s `valid_auth`).
fn interface_name_valid(name: &String, ctx: &Config) -> garde::Result {
    unique_key_in(name, &ctx.interfaces, |i| &i.name)?;
    if name.contains('.') {
        return Err(garde::Error::new(
            "interface name must not contain '.' (reserved for subinterface addressing, e.g. eth0.100)",
        ));
    }
    if let Some(table) = loopback_table_name(name) {
        // The kernel device is `lo<table_id>`, so the name is not a netdev name.
        if !ctx.routing_tables.iter().any(|t| t.name == table) {
            return Err(garde::Error::new(
                "loopback interface's routing table does not exist",
            ));
        }
    } else {
        // ponytail: `<name>.<tag>` subinterface length is not checked (Subinterface does not see its parent's name); the driver surfaces the kernel error.
        crate::validators::device_name(name)?;
    }
    Ok(())
}

/// If set, `switching_profile` must name an existing `SwitchingProfile`.
/// `pub(crate)` since `PortAggregate` (a bond can also be trunked into a
/// broadcast domain) reuses this verbatim.
pub(crate) fn switching_profile_reference_valid(
    switching_profile: Option<&String>,
    ctx: &Config,
) -> garde::Result {
    let Some(name) = switching_profile else {
        return Ok(());
    };
    if !ctx.switching_profiles.iter().any(|p| &p.name == name) {
        return Err(garde::Error::new(
            "referenced switching profile does not exist",
        ));
    }
    Ok(())
}

/// If set, `port_aggregate` must name an existing `PortAggregate`.
fn port_aggregate_reference_valid(port_aggregate: Option<&String>, ctx: &Config) -> garde::Result {
    let Some(name) = port_aggregate else {
        return Ok(());
    };
    if !ctx.port_aggregates.iter().any(|a| &a.name == name) {
        return Err(garde::Error::new(
            "referenced port aggregate does not exist",
        ));
    }
    Ok(())
}

/// Enforces the split between loopback and physical interfaces described on
/// `Interface`'s doc comment: a loopback interface must have no
/// `subinterfaces` (its L3 config stays flat), while a physical interface
/// must have empty `addresses` and no `routing_table` (its L3 config must
/// live under `subinterfaces` instead, tag 0 for the untagged/native case).
fn valid_addressing_split(interfaces: &[Interface]) -> garde::Result {
    for iface in interfaces {
        if loopback_table_name(&iface.name).is_some() {
            if !iface.subinterfaces.is_empty() {
                return Err(garde::Error::new(
                    "loopback interface must not have subinterfaces",
                ));
            }
            if iface.ospf_profile.is_some() && iface.routing_table.is_none() {
                return Err(garde::Error::new(
                    "ospf profile requires a routing-table on the same interface",
                ));
            }
            if iface.ospfv3_profile.is_some() && iface.routing_table.is_none() {
                return Err(garde::Error::new(
                    "ospfv3 profile requires a routing-table on the same interface",
                ));
            }
        } else if !iface.addresses.is_empty()
            || iface.routing_table.is_some()
            || iface.ospf_profile.is_some()
            || iface.ospfv3_profile.is_some()
        {
            return Err(garde::Error::new(
                "physical interface must configure addresses/routing-table/ospf-profile on a subinterface (e.g. '.0'), not directly on the interface",
            ));
        }
    }
    Ok(())
}

/// A tag claimed by a `Subinterface` (L3) and a tag claimed by the same
/// interface's `switching_profile` (L2 — an `Untagged` member claims tag 0,
/// a `Dot1q(n)` member claims tag `n`) are mutually exclusive on the same
/// interface — see `Interface`'s doc comment. Generalizes the previous
/// `routing_table` + `Untagged`-member-only rule to every tag, now that L3
/// config lives per-subinterface rather than flat on `Interface`. Wired on
/// `Config.interfaces` rather than a per-field closure, since this needs to
/// see two sibling fields of the same `Interface` at once.
pub(crate) fn valid_subinterface_and_switching_profile_tags(
    interfaces: &[Interface],
    ctx: &Config,
) -> garde::Result {
    for iface in interfaces {
        if iface.subinterfaces.is_empty() {
            continue;
        }
        let Some(profile_name) = &iface.switching_profile else {
            continue;
        };
        let Some(profile) = ctx
            .switching_profiles
            .iter()
            .find(|p| &p.name == profile_name)
        else {
            continue;
        };
        for sub in &iface.subinterfaces {
            let collides = profile.members.iter().any(|m| match m.tag {
                VlanTag::Untagged => sub.tag == 0,
                VlanTag::Dot1q(n) => sub.tag == n,
            });
            if collides {
                return Err(garde::Error::new(format!(
                    "subinterface tag {} conflicts with a switching-profile member using the same tag",
                    sub.tag
                )));
            }
        }
    }
    Ok(())
}

/// An interface with `port_aggregate` set can't also carry a
/// `switching_profile` or any `subinterfaces` — like VRF/bridge enslavement,
/// bond enslavement claims the link's one Linux master, so there's nothing
/// left for an L2 trunk or a per-tag VLAN sub-link to attach to.
fn valid_port_aggregate_membership(interfaces: &[Interface]) -> garde::Result {
    for iface in interfaces {
        if iface.port_aggregate.is_none() {
            continue;
        }
        if iface.switching_profile.is_some() {
            return Err(garde::Error::new(
                "an interface in a port aggregate must not also have a switching-profile",
            ));
        }
        if iface.stp_port_profile.is_some() {
            return Err(garde::Error::new(
                "an interface in a port aggregate must not have its own stp-port-profile: the spanning-tree port is the aggregate",
            ));
        }
        if !iface.subinterfaces.is_empty() {
            return Err(garde::Error::new(
                "an interface in a port aggregate must not also have subinterfaces",
            ));
        }
    }
    Ok(())
}

/// LLDP runs on a physical link — a loopback has no wire to speak it on.
fn valid_lldp_physical_only(interfaces: &[Interface]) -> garde::Result {
    for iface in interfaces {
        let configured = iface.lldp_transmit
            || iface.lldp_receive
            || iface.lldp_destination != LldpDestination::default();
        if configured && loopback_table_name(&iface.name).is_some() {
            return Err(garde::Error::new(
                "lldp can only be configured on a physical interface, not a loopback",
            ));
        }
    }
    Ok(())
}

/// Umbrella `Config.interfaces`-level validator combining the cross-field
/// checks above — see each for details.
pub(crate) fn valid_interfaces(interfaces: &[Interface], ctx: &Config) -> garde::Result {
    valid_addressing_split(interfaces)?;
    for iface in interfaces {
        valid_subinterface_mtus(&iface.subinterfaces, iface.mtu)?;
    }
    valid_subinterface_and_switching_profile_tags(interfaces, ctx)?;
    valid_port_aggregate_membership(interfaces)?;
    valid_lldp_physical_only(interfaces)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::schema::{Config, RoutingTable};

    use super::*;

    fn interface(name: &str, addresses: &[&str], routing_table: Option<&str>) -> Interface {
        Interface {
            acl_in: None,
            acl_out: None,
            flowspec: false,
            ospfv3_profile: None,
            name: name.to_string(),
            addresses: addresses
                .iter()
                .map(|a| InterfaceAddress {
                    address: a.parse().unwrap(),
                    label: None,
                })
                .collect(),
            routing_table: routing_table.map(str::to_string),
            ospf_profile: None,
            switching_profile: None,
            port_aggregate: None,
            stp_port_profile: None,
            lacp_port_priority: None,
            lacp_mode: crate::schema::LacpMode::default(),
            mtu: None,
            lldp_transmit: false,
            lldp_receive: false,
            lldp_destination: crate::schema::LldpDestination::default(),
            subinterfaces: Vec::new(),
        }
    }

    /// A physical (non-loopback) interface with L3 config on its tag-0
    /// subinterface, mirroring what `interface(...)` used to build directly
    /// on `Interface` before the addressing split.
    fn physical_with_l3(name: &str, addresses: &[&str], routing_table: Option<&str>) -> Interface {
        let mut iface = interface(name, &[], None);
        iface.subinterfaces = vec![Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            ospfv3_profile: None,
            bfd_unsolicited: None,
            tag: 0,
            addresses: addresses
                .iter()
                .map(|a| InterfaceAddress {
                    address: a.parse().unwrap(),
                    label: None,
                })
                .collect(),
            routing_table: routing_table.map(str::to_string),
            ospf_profile: None,
        }];
        iface
    }

    fn table(name: &str) -> RoutingTable {
        RoutingTable {
            rest_api: None,
            evpn: crate::schema::RoutingTableEvpn::default(),
            vpn: crate::schema::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: name.to_string(),
            bgp_instance: None,
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: Vec::new(),
        }
    }

    fn config_with(interfaces: Vec<Interface>, tables: Vec<RoutingTable>) -> Config {
        Config {
            interfaces,
            routing_tables: tables,
            ..Default::default()
        }
    }

    #[test]
    fn subinterface_mtu_override_rules() {
        let with = |parent: Option<u32>, tag: u16, mtu: Option<u32>| {
            let mut iface = physical_with_l3("eth0", &[], None);
            iface.mtu = parent;
            iface.subinterfaces = vec![Subinterface {
                tag,
                mtu,
                ..Default::default()
            }];
            let cfg = config_with(vec![iface], vec![]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(with(None, 100, None), "no override");
        assert!(with(Some(9000), 100, Some(9000)), "equal to parent");
        assert!(with(None, 100, Some(1400)), "below default parent");
        assert!(!with(None, 100, Some(9000)), "above default 1500 parent");
        assert!(!with(Some(9000), 100, Some(9001)), "above parent");
        assert!(!with(Some(9000), 0, Some(1500)), "tag 0 rejected");
        assert!(!with(Some(9000), 100, Some(10)), "below 68");
        // Lowering the parent below an existing override is rejected too.
        assert!(!with(Some(1400), 100, Some(1500)));
    }

    #[test]
    fn valid_interface_with_no_associations_passes() {
        let cfg = config_with(vec![interface("eth0", &[], None)], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn valid_physical_interface_with_addresses_and_routing_table_passes() {
        let cfg = config_with(
            vec![physical_with_l3(
                "eth0",
                &["10.0.0.1/24", "2001:db8::1/64"],
                Some("rt1"),
            )],
            vec![table("rt1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_interface_name_fails() {
        let cfg = config_with(
            vec![interface("eth0", &[], None), interface("eth0", &[], None)],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dotted_interface_name_fails() {
        let cfg = config_with(vec![interface("eth0.100", &[], None)], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_address_on_same_subinterface_fails() {
        let cfg = config_with(
            vec![physical_with_l3(
                "eth0",
                &["10.0.0.1/24", "10.0.0.1/24"],
                None,
            )],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn same_address_on_different_interfaces_passes() {
        let cfg = config_with(
            vec![
                physical_with_l3("eth0", &["10.0.0.1/24"], None),
                physical_with_l3("eth1", &["10.0.0.1/24"], None),
            ],
            vec![],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dangling_routing_table_reference_on_subinterface_fails() {
        let cfg = config_with(
            vec![physical_with_l3("eth0", &[], Some("does-not-exist"))],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn multiple_interfaces_may_share_a_routing_table() {
        let cfg = config_with(
            vec![
                physical_with_l3("eth0", &[], Some("rt1")),
                physical_with_l3("eth1", &[], Some("rt1")),
            ],
            vec![table("rt1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn loopback_name_with_existing_table_passes() {
        let cfg = config_with(
            vec![interface("loopback-rt1", &[], None)],
            vec![table("rt1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn loopback_name_with_missing_table_fails() {
        let cfg = config_with(vec![interface("loopback-rt1", &[], None)], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn loopback_prefix_with_empty_suffix_is_not_a_loopback() {
        // "loopback-" alone has nothing after the prefix, so it's treated
        // as an ordinary interface name — no routing table required.
        let cfg = config_with(vec![interface("loopback-", &[], None)], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn physical_interface_name_unaffected_by_loopback_check() {
        let cfg = config_with(vec![interface("eth0", &[], None)], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_loopback_name_rejected_by_existing_uniqueness() {
        // Two interfaces targeting the same table via the naming
        // convention would need the identical name, already rejected by
        // ordinary name uniqueness — no separate "one loopback per table"
        // validator needed.
        let cfg = config_with(
            vec![
                interface("loopback-rt1", &[], None),
                interface("loopback-rt1", &[], None),
            ],
            vec![table("rt1")],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn loopback_table_name_parses_prefix() {
        assert_eq!(loopback_table_name("loopback-rt1"), Some("rt1"));
        assert_eq!(loopback_table_name("loopback-"), None);
        assert_eq!(loopback_table_name("eth0"), None);
        assert_eq!(loopback_table_name("loopback"), None);
    }

    #[test]
    fn duplicate_address_different_label_still_conflicts() {
        let mut iface = interface("eth0", &[], None);
        iface.subinterfaces = vec![Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            ospfv3_profile: None,
            bfd_unsolicited: None,
            tag: 0,
            addresses: vec![
                InterfaceAddress {
                    address: "10.0.0.1/24".parse().unwrap(),
                    label: Some("a".to_string()),
                },
                InterfaceAddress {
                    address: "10.0.0.1/24".parse().unwrap(),
                    label: Some("b".to_string()),
                },
            ],
            routing_table: None,
            ospf_profile: None,
        }];
        let cfg = config_with(vec![iface], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn loopback_with_subinterfaces_fails() {
        let mut iface = interface("loopback-rt1", &[], None);
        iface.subinterfaces = vec![Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            ospfv3_profile: None,
            bfd_unsolicited: None,
            tag: 100,
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
        }];
        let cfg = config_with(vec![iface], vec![table("rt1")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn physical_interface_with_flat_address_fails() {
        let cfg = config_with(vec![interface("eth0", &["10.0.0.1/24"], None)], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn physical_interface_with_flat_routing_table_fails() {
        let cfg = config_with(
            vec![interface("eth0", &[], Some("rt1"))],
            vec![table("rt1")],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_subinterface_tag_fails() {
        let mut iface = interface("eth0", &[], None);
        iface.subinterfaces = vec![
            Subinterface {
                mtu: None,
                acl_in: None,
                acl_out: None,
                flowspec: false,
                ospfv3_profile: None,
                bfd_unsolicited: None,
                tag: 100,
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: None,
            },
            Subinterface {
                mtu: None,
                acl_in: None,
                acl_out: None,
                flowspec: false,
                ospfv3_profile: None,
                bfd_unsolicited: None,
                tag: 100,
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: None,
            },
        ];
        let cfg = config_with(vec![iface], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn subinterface_tag_4095_fails() {
        let mut iface = interface("eth0", &[], None);
        iface.subinterfaces = vec![Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            ospfv3_profile: None,
            bfd_unsolicited: None,
            tag: 4095,
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
        }];
        let cfg = config_with(vec![iface], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn subinterface_tag_boundary_values_pass() {
        let mut iface = interface("eth0", &[], None);
        iface.subinterfaces = vec![
            Subinterface {
                mtu: None,
                acl_in: None,
                acl_out: None,
                flowspec: false,
                ospfv3_profile: None,
                bfd_unsolicited: None,
                tag: 0,
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: None,
            },
            Subinterface {
                mtu: None,
                acl_in: None,
                acl_out: None,
                flowspec: false,
                ospfv3_profile: None,
                bfd_unsolicited: None,
                tag: 4094,
                addresses: Vec::new(),
                routing_table: None,
                ospf_profile: None,
            },
        ];
        let cfg = config_with(vec![iface], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    fn profile(
        name: &str,
        members: Vec<crate::schema::SwitchingProfileMember>,
    ) -> crate::schema::SwitchingProfile {
        crate::schema::SwitchingProfile {
            name: name.to_string(),
            members,
        }
    }

    fn member(broadcast_domain: &str, tag: VlanTag) -> crate::schema::SwitchingProfileMember {
        crate::schema::SwitchingProfileMember {
            broadcast_domain: broadcast_domain.to_string(),
            tag,
            ..Default::default()
        }
    }

    fn domain(name: &str) -> crate::schema::BroadcastDomain {
        crate::schema::BroadcastDomain {
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
            stp_instance: None,
            stp_priority: None,
            stp_hello_time: None,
            stp_max_age: None,
            stp_forward_delay: None,
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
        }
    }

    #[test]
    fn valid_switching_profile_reference_passes() {
        let mut iface = interface("eth0", &[], None);
        iface.switching_profile = Some("sp1".to_string());
        let mut cfg = config_with(vec![iface], vec![]);
        cfg.switching_profiles = vec![profile("sp1", vec![])];
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dangling_switching_profile_reference_fails() {
        let mut iface = interface("eth0", &[], None);
        iface.switching_profile = Some("does-not-exist".to_string());
        let cfg = config_with(vec![iface], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn subinterface_tag_0_with_untagged_switching_profile_member_fails() {
        let mut iface = physical_with_l3("eth0", &[], Some("rt1"));
        iface.switching_profile = Some("sp1".to_string());
        let mut cfg = config_with(vec![iface], vec![table("rt1")]);
        cfg.broadcast_domains = vec![domain("bd1")];
        cfg.switching_profiles = vec![profile("sp1", vec![member("bd1", VlanTag::Untagged)])];
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn subinterface_tag_matching_dot1q_member_fails() {
        let mut iface = physical_with_l3("eth0", &[], Some("rt1"));
        iface.switching_profile = Some("sp1".to_string());
        iface.subinterfaces[0].tag = 100;
        let mut cfg = config_with(vec![iface], vec![table("rt1")]);
        cfg.broadcast_domains = vec![domain("bd1")];
        cfg.switching_profiles = vec![profile("sp1", vec![member("bd1", VlanTag::Dot1q(100))])];
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn subinterface_tag_0_with_dot1q_only_switching_profile_passes() {
        let mut iface = physical_with_l3("eth0", &[], Some("rt1"));
        iface.switching_profile = Some("sp1".to_string());
        let mut cfg = config_with(vec![iface], vec![table("rt1")]);
        cfg.broadcast_domains = vec![domain("bd1")];
        cfg.switching_profiles = vec![profile("sp1", vec![member("bd1", VlanTag::Dot1q(100))])];
        cfg.validate_with(&cfg).unwrap();
    }

    fn config_with_ospf_profile(interfaces: Vec<Interface>, tables: Vec<RoutingTable>) -> Config {
        use crate::schema::{OspfArea, OspfInstance, OspfProfile};
        Config {
            interfaces,
            routing_tables: tables,
            ospf_instances: vec![OspfInstance {
                name: "r1".to_string(),
                router_id: "1.1.1.1".parse().unwrap(),
                areas: vec![OspfArea {
                    area_id: "0.0.0.0".parse().unwrap(),
                    area_type: crate::schema::OspfAreaType::Normal,
                    stub_default_cost: None,
                    ranges: Vec::new(),
                    nssa_translate_always: false,
                    nssa_default_originate: false,
                    virtual_links: Vec::new(),
                    profiles: vec![OspfProfile {
                        bfd: None,
                        name: "p1".to_string(),
                        hello_interval: None,
                        dead_interval: None,
                        cost: None,
                        priority: None,
                        mtu: None,
                        mtu_ignore: false,
                        network_type: None,
                        auth: None,
                        extended_sequence_numbers: false,
                    }],
                }],
                routing_table: None,
                redistribute_policy: None,
                graceful_restart_grace_period: None,
                prefix_suppression: false,
                max_metric_on_startup: None,
                max_metric_on_shutdown: None,
                max_metric_administrative: false,
                host_router: false,
                remote_lfa: false,
                redistribute_metric: None,
                redistribute_metric_type: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn valid_ospf_profile_on_subinterface_with_routing_table_passes() {
        let iface = physical_with_l3("eth0", &[], Some("rt1"));
        let mut cfg = config_with_ospf_profile(vec![iface], vec![table("rt1")]);
        cfg.interfaces[0].subinterfaces[0].ospf_profile = Some("p1".to_string());
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dangling_ospf_profile_reference_on_subinterface_fails() {
        let iface = physical_with_l3("eth0", &[], Some("rt1"));
        let mut cfg = config_with_ospf_profile(vec![iface], vec![table("rt1")]);
        cfg.interfaces[0].subinterfaces[0].ospf_profile = Some("does-not-exist".to_string());
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ospf_profile_on_subinterface_without_routing_table_fails() {
        let iface = physical_with_l3("eth0", &[], None);
        let mut cfg = config_with_ospf_profile(vec![iface], vec![]);
        cfg.interfaces[0].subinterfaces[0].ospf_profile = Some("p1".to_string());
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn valid_ospf_profile_on_loopback_with_routing_table_passes() {
        let iface = interface("loopback-rt1", &[], Some("rt1"));
        let mut cfg = config_with_ospf_profile(vec![iface], vec![table("rt1")]);
        cfg.interfaces[0].ospf_profile = Some("p1".to_string());
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn ospf_profile_on_loopback_without_routing_table_fails() {
        let iface = interface("loopback-rt1", &[], None);
        let mut cfg = config_with_ospf_profile(vec![iface], vec![table("rt1")]);
        cfg.interfaces[0].ospf_profile = Some("p1".to_string());
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ospf_profile_on_physical_interface_flat_fails() {
        let mut iface = interface("eth0", &[], None);
        iface.ospf_profile = Some("p1".to_string());
        let cfg = config_with_ospf_profile(vec![iface], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    fn aggregate(name: &str) -> crate::schema::PortAggregate {
        crate::schema::PortAggregate {
            acl_in: None,
            acl_out: None,
            flowspec: false,
            name: name.to_string(),
            mode: crate::schema::PortAggregateMode::Xor,
            lacp_rate: crate::schema::LacpRate::default(),
            esi: None,
            redundancy_mode: crate::schema::EsRedundancy::default(),
            df_algorithm: crate::schema::DfAlgorithm::default(),
            lacp_system_id: None,
            lacp_system_priority: None,
            min_links: 1,
            bfd: None,
            bfd_peer: None,
            stp_port_profile: None,
            switching_profile: None,
            mtu: None,
            subinterfaces: Vec::new(),
        }
    }

    #[test]
    fn valid_port_aggregate_reference_passes() {
        let mut iface = interface("eth0", &[], None);
        iface.port_aggregate = Some("bond1".to_string());
        let mut cfg = config_with(vec![iface], vec![]);
        cfg.port_aggregates = vec![aggregate("bond1")];
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dangling_port_aggregate_reference_fails() {
        let mut iface = interface("eth0", &[], None);
        iface.port_aggregate = Some("does-not-exist".to_string());
        let cfg = config_with(vec![iface], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn port_aggregate_member_with_switching_profile_fails() {
        let mut iface = interface("eth0", &[], None);
        iface.port_aggregate = Some("bond1".to_string());
        iface.switching_profile = Some("sp1".to_string());
        let mut cfg = config_with(vec![iface], vec![]);
        cfg.port_aggregates = vec![aggregate("bond1")];
        cfg.switching_profiles = vec![profile("sp1", vec![])];
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn port_aggregate_member_with_stp_port_profile_fails() {
        let mut iface = interface("eth0", &[], None);
        iface.port_aggregate = Some("bond1".to_string());
        let mut cfg = config_with(vec![iface], vec![]);
        cfg.port_aggregates = vec![aggregate("bond1")];
        cfg.stp_port_profiles = vec![crate::schema::StpPortProfile {
            name: "edge".into(),
            ..Default::default()
        }];
        cfg.validate_with(&cfg).unwrap();
        cfg.interfaces[0].stp_port_profile = Some("edge".into());
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn stp_port_profile_reference_must_exist_and_is_inert_without_switching() {
        let mut cfg = config_with(vec![interface("eth0", &[], None)], vec![]);
        cfg.interfaces[0].stp_port_profile = Some("edge".into());
        assert!(cfg.validate_with(&cfg).is_err(), "unknown profile");
        cfg.stp_port_profiles = vec![crate::schema::StpPortProfile {
            name: "edge".into(),
            ..Default::default()
        }];
        cfg.validate_with(&cfg).unwrap();
        // deleting the profile again fails the interface under its own path
        cfg.stp_port_profiles.clear();
        let err = cfg.validate_with(&cfg).unwrap_err().to_string();
        assert!(err.contains("interfaces[0].stp_port_profile"), "{err}");
    }

    #[test]
    fn lldp_on_physical_interface_passes() {
        let mut iface = interface("eth0", &[], None);
        iface.lldp_transmit = true;
        iface.lldp_receive = true;
        let cfg = config_with(vec![iface], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn lldp_on_loopback_fails() {
        for (tx, rx) in [(true, false), (false, true)] {
            let mut iface = interface("loopback-rt1", &[], None);
            iface.lldp_transmit = tx;
            iface.lldp_receive = rx;
            let cfg = config_with(vec![iface], vec![table("rt1")]);
            assert!(cfg.validate_with(&cfg).is_err());
        }
    }

    #[test]
    fn lldp_destination_on_loopback_fails() {
        let mut iface = interface("loopback-rt1", &[], None);
        iface.lldp_destination = LldpDestination::CustomerBridge;
        let cfg = config_with(vec![iface], vec![table("rt1")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn port_aggregate_member_with_subinterfaces_fails() {
        let mut iface = physical_with_l3("eth0", &[], Some("rt1"));
        iface.port_aggregate = Some("bond1".to_string());
        let mut cfg = config_with(vec![iface], vec![table("rt1")]);
        cfg.port_aggregates = vec![aggregate("bond1")];
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn bfd_unsolicited_needs_a_profile_and_a_routing_table() {
        let sub = |rt: Option<&str>| Subinterface {
            routing_table: rt.map(str::to_string),
            bfd_unsolicited: Some("fast".into()),
            ..Subinterface::default()
        };
        let build = |rt: Option<&str>, profile: bool| {
            let mut iface = interface("eth0", &[], None);
            iface.subinterfaces = vec![sub(rt)];
            let mut cfg = config_with(vec![iface], vec![table("rt1")]);
            if profile {
                cfg.bfd_profiles = vec![crate::schema::BfdProfile {
                    name: "fast".into(),
                    ..Default::default()
                }];
            }
            cfg
        };
        let ok = build(Some("rt1"), true);
        assert!(ok.validate_with(&ok).is_ok());
        let no_table = build(None, true);
        assert!(no_table.validate_with(&no_table).is_err());
        let no_profile = build(Some("rt1"), false);
        let err = no_profile
            .validate_with(&no_profile)
            .unwrap_err()
            .to_string();
        assert!(err.contains("bfd profile 'fast' does not exist"), "{err}");
    }

    #[test]
    fn names_follow_charset_and_device_length() {
        let ok = |ifaces: Vec<Interface>, tables: Vec<RoutingTable>| {
            let cfg = config_with(ifaces, tables);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(ok(vec![interface("eth0", &[], None)], vec![]));
        assert!(ok(vec![interface("abcdefghijklmno", &[], None)], vec![]));
        assert!(!ok(vec![interface("abcdefghijklmnop", &[], None)], vec![]));
        assert!(!ok(vec![interface("-eth0", &[], None)], vec![]));
        assert!(!ok(vec![interface("../x", &[], None)], vec![]));
        assert!(!ok(vec![], vec![table("a b")]));
        // `loopback-<table>` is not a netdev name (`lo<id>`), so it may exceed 15.
        assert!(ok(
            vec![interface("loopback-a-long-table-name", &[], None)],
            vec![table("a-long-table-name")]
        ));
    }
}
