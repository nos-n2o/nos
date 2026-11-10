use std::net::IpAddr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::{bfd_reference_valid, stp_port_profile_reference_valid, unique_key_in};

use super::interface::{
    switching_profile_reference_valid, valid_mtu, valid_subinterface_list, valid_subinterface_mtus,
};
use super::{Config, EdgePort, StpMode, Subinterface, VlanTag};
use nos_proto_derive::Cli;

/// How a `PortAggregate`'s member set is decided. Both variants create the
/// *same* underlying kernel bond device (`BondMode::BalanceXor` — see
/// `interface::driver::linux::bond_mode_of`'s doc comment for why `Lacp`
/// does **not** map to the kernel's own `Ieee8023Ad` bonding mode); the
/// difference is only which control plane decides which members are
/// actually enslaved into it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub enum PortAggregateMode {
    /// Static: every member named by an `Interface.port_aggregate`
    /// reference is enslaved unconditionally, no negotiation.
    #[default]
    Xor,
    /// Dynamic: membership is negotiated by `nos-lacpd` (real IEEE 802.1AX
    /// LACPDU exchange and Actor/Partner state machines, see `lacp/
    /// CLAUDE.md`), which pushes its currently-negotiated active-member set
    /// to `nos-interfaced` — a member interface is only enslaved once
    /// `nos-lacpd` confirms it, and is released again if negotiation lapses
    /// (partner LACPDUs stop, link goes down, etc).
    Lacp,
}

/// How often this end asks its LACP partner to send LACPDUs (802.1AX's
/// `LACP_Timeout`), and therefore how long it waits before declaring the
/// partner gone: `Slow` is every 30s (90s to detect loss), `Fast` every 1s
/// (3s to detect loss). Only meaningful for a `Lacp`-mode aggregate. Like
/// Linux bonding's `lacp_rate`, it's a request to the partner — each end
/// transmits at the rate the *other* end asks for.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum LacpRate {
    #[default]
    /// Ask the partner to send LACPDUs every 30 seconds.
    Slow,
    /// Ask the partner to send LACPDUs every second.
    Fast,
}

/// A member port's 802.1AX `LACP_Activity`: `Active` ports send LACPDUs
/// whenever the link is up; `Passive` ones stay silent until they hear an
/// `Active` partner (two `Passive` ends never form a bundle).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum LacpMode {
    #[default]
    /// Send LACPDUs whenever the link is up.
    Active,
    /// Stay silent until a partner's LACPDU is heard.
    Passive,
}

/// How the PEs sharing an Ethernet Segment (`PortAggregate.esi`) divide the
/// traffic (RFC 7432 §8.5): `AllActive` lets every PE forward unicast to the
/// segment and only the Designated Forwarder flood BUM; `SingleActive` lets
/// only the Designated Forwarder forward anything, the others' ports being
/// blocked outright. Announced to the other PEs in the per-ES Ethernet A-D
/// route's ESI Label community. Only meaningful with an `esi`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum EsRedundancy {
    #[default]
    /// Every PE of the segment forwards unicast; only the DF floods BUM.
    AllActive,
    /// Only the Designated Forwarder forwards at all.
    SingleActive,
}

/// The RFC 8584 Designated Forwarder election algorithm this PE asks for on
/// an Ethernet Segment, advertised in its Type-4 route's DF Election extended
/// community. `Hrw` only takes effect when every PE on the segment advertises
/// it; otherwise every PE falls back to `Modulo` (RFC 8584 §2.2.3).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum DfAlgorithm {
    /// RFC 7432 §8.5 service carving: `VNI mod N` over the ordered PEs.
    #[default]
    Modulo,
    /// RFC 8584 §3 Highest Random Weight.
    Hrw,
}

/// A named Linux bonding device, statically (`Xor`) or LACP-negotiated
/// (`Lacp`). Same
/// config surface as a *physical* `Interface` (never a loopback — bonding a
/// loopback makes no sense): `switching_profile`/`mtu`/`subinterfaces`, all
/// validated by the exact same helpers `Interface` uses, plus `mode`/
/// `lacp_rate`. All L3
/// config (addresses/routing-table/OSPF) lives under `subinterfaces` (tag 0
/// for the untagged/native case), exactly like a physical `Interface` — a
/// `PortAggregate` never gets the loopback-style flat `addresses`/
/// `routing_table` fields, since there's no "loopback bond" concept. An
/// `Interface` becomes a bonded member by setting its own `port_aggregate`
/// field to this aggregate's name — the same reference-by-name shape
/// `Interface.switching_profile` already uses for L2 trunk membership —
/// rather than this type holding a member list itself.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct PortAggregate {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| port_aggregate_name_valid(n, ctx))
    )]
    #[cli(key)]
    /// Bond name, 1 to 64 characters (letters, digits, `_`, `-`), unique among interfaces and aggregates.
    pub name: String,

    #[garde(skip)]
    #[cli(topic = PortAggregateMode)]
    /// Static bond or LACP (802.1AX) with its negotiation parameters.
    pub mode: PortAggregateMode,

    /// See [`LacpRate`]. `#[serde(default)]` so a config persisted before
    /// this field existed still loads.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = PortAggregateLacpRate)]
    pub lacp_rate: LacpRate,

    /// The Ethernet Segment this bond attaches to (EVPN multi-homing, RFC
    /// 7432): ten colon-separated hex bytes. Set the same value on every PE
    /// the customer device is dual-homed to. `nos-fdbd` puts it on the Type-2
    /// routes for MACs learned on this bond and elects a Designated Forwarder
    /// among the PEs that share it.
    #[serde(default)]
    #[garde(custom(|v: &Option<String>, _ctx: &Config| valid_esi(v.as_deref())))]
    #[cli(topic = PortAggregateEsi)]
    pub esi: Option<String>,

    /// See [`EsRedundancy`]. `#[serde(default)]` so a config persisted before
    /// this field existed still loads (as all-active, what it always was).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = PortAggregateRedundancyMode)]
    pub redundancy_mode: EsRedundancy,

    /// See [`DfAlgorithm`]. `#[serde(default)]` so a config persisted before
    /// this field existed still loads (as modulo, what it always was).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = PortAggregateDfAlgorithm)]
    pub df_algorithm: DfAlgorithm,

    /// Overrides `nos-lacpd`'s derived LACP Actor System ID for this bond, so
    /// two PEs sharing an ESI can present the same actor to the customer
    /// device. Only meaningful for a `Lacp`-mode aggregate.
    #[serde(default)]
    #[garde(custom(|v: &Option<String>, _ctx: &Config| valid_lacp_system_id(v.as_deref())))]
    #[cli(topic = PortAggregateLacpSystemId)]
    pub lacp_system_id: Option<String>,

    /// The LACP Actor System Priority `nos-lacpd` advertises for this bond
    /// (802.1AX); `None` = 32768. Lower is higher priority. Only meaningful
    /// for a `Lacp`-mode aggregate; ignored (not rejected) otherwise.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = PortAggregateLacpSystemPriority)]
    pub lacp_system_priority: Option<u16>,

    /// Minimum number of member ports that must be `Distributing` for the
    /// bond to carry traffic: below it `nos-lacpd` pushes an empty active
    /// set, so the kernel bond holds no member, while the ports keep
    /// negotiating and the bond refills as soon as the count is met. 0 and 1
    /// behave the same (any Distributing port is enough). Only meaningful
    /// for a `Lacp`-mode aggregate; ignored (not rejected) otherwise, and not
    /// checked against the member count, which lives on the `Interface`s.
    #[serde(default = "default_min_links")]
    #[garde(skip)]
    #[cli(topic = PortAggregateMinLinks, words = "min-links")]
    pub min_links: u16,

    /// Name of a `BfdProfile`: runs one micro-BFD session (RFC 7130) per
    /// member link, and a member is only enslaved while its session is Up.
    /// Needs `bfd_peer`. `#[serde(default)]` so older configs still load.
    #[serde(default)]
    #[garde(custom(|b: &Option<String>, ctx: &Config| bfd_reference_valid(b.as_ref(), ctx)))]
    #[cli(topic = PortAggregateBfd, words = "bfd")]
    pub bfd: Option<String>,

    /// The peer's L3 address the micro-BFD sessions are sent to (RFC 7130
    /// uses the peer's address, not a link-local group). Must be of the
    /// family of an address on this bond's tag-0 subinterface (the session
    /// source). Ignored without `bfd`.
    #[serde(default)]
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[cli(topic = PortAggregateBfdPeer, words = "bfd-peer")]
    pub bfd_peer: Option<IpAddr>,

    /// Names an `StpPortProfile` for this bond as a spanning-tree port.
    /// Inert until `nos-stpd`. An ESI aggregate needs one with
    /// `edge-port admin` and `bpdu-guard` (see `valid_port_aggregates`).
    #[serde(default)]
    #[garde(custom(|p: &Option<String>, ctx: &Config| stp_port_profile_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = PortAggregateStpPortProfile, words = "stp-port-profile")]
    pub stp_port_profile: Option<String>,

    /// Names an `Acl` filtering IP packets arriving on this bond; the placement
    /// rules are `acl::valid_acl_references`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = InterfaceAclIn, words = "acl in")]
    pub acl_in: Option<String>,

    /// Names an `Acl` filtering IP packets leaving this bond.
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

    /// Names a `SwitchingProfile` trunking this bond into one or more
    /// `BroadcastDomain`s — same field, same meaning, as
    /// `Interface.switching_profile`.
    #[garde(custom(|sp: &Option<String>, ctx: &Config| switching_profile_reference_valid(sp.as_ref(), ctx)))]
    #[cli(topic = InterfaceSwitchingProfile)]
    pub switching_profile: Option<String>,

    #[garde(custom(|m: &Option<u32>, _ctx: &Config| valid_mtu(*m)))]
    #[cli(topic = InterfaceMtu)]
    /// Bond MTU in bytes; `None` keeps the kernel default.
    pub mtu: Option<u32>,

    /// This bond's own per-tag L3 attachment points — same type and same
    /// tag-0-is-untagged/native convention as `Interface.subinterfaces`.
    #[garde(dive, custom(|subs, _ctx: &Config| valid_subinterface_list(subs)))]
    #[cli(topic = Subinterface)]
    pub subinterfaces: Vec<Subinterface>,
}

fn default_min_links() -> u16 {
    1
}

// Not derived: `min_links` defaults to 1, not 0, so a blank entry reads like a
// config persisted before the field existed.
impl Default for PortAggregate {
    fn default() -> Self {
        Self {
            acl_in: None,
            acl_out: None,
            flowspec: false,
            name: String::new(),
            mode: PortAggregateMode::default(),
            lacp_rate: LacpRate::default(),
            esi: None,
            redundancy_mode: EsRedundancy::default(),
            df_algorithm: DfAlgorithm::default(),
            lacp_system_id: None,
            lacp_system_priority: None,
            min_links: default_min_links(),
            bfd: None,
            bfd_peer: None,
            stp_port_profile: None,
            switching_profile: None,
            mtu: None,
            subinterfaces: Vec::new(),
        }
    }
}

fn valid_esi(esi: Option<&str>) -> garde::Result {
    match esi {
        Some(e) if crate::evpn_id::parse_esi(e).is_none() => Err(garde::Error::new(
            "esi must be ten colon-separated hex bytes, not all zero (00:11:22:33:44:55:66:77:88:99)",
        )),
        _ => Ok(()),
    }
}

fn valid_lacp_system_id(id: Option<&str>) -> garde::Result {
    match id {
        Some(m) if crate::evpn_id::parse_mac(m).is_none() => Err(garde::Error::new(
            "lacp-system-id must be a unicast MAC address (02:00:00:00:00:01)",
        )),
        _ => Ok(()),
    }
}

fn port_aggregate_name_valid(name: &String, ctx: &Config) -> garde::Result {
    unique_key_in(name, &ctx.port_aggregates, |a| &a.name)?;
    if name.contains('.') {
        return Err(garde::Error::new(
            "port aggregate name must not contain '.' (reserved for subinterface addressing, e.g. bond1.100)",
        ));
    }
    Ok(())
}

/// `Config.port_aggregates`-level validator: the same subinterface/
/// switching-profile tag-collision rule
/// `interface::valid_subinterface_and_switching_profile_tags` enforces on an
/// `Interface` — Linux only allows one master device per link, whether that
/// link is a physical interface or a bond. (The other half of that
/// interface-level validator, `valid_addressing_split`, has no counterpart
/// here — `PortAggregate` has no loopback-style flat L3 fields to keep
/// disjoint from `subinterfaces` in the first place.)
pub(crate) fn valid_port_aggregates(aggregates: &[PortAggregate], ctx: &Config) -> garde::Result {
    // A redundancy mode is a property of the Ethernet Segment.
    for agg in aggregates {
        valid_subinterface_mtus(&agg.subinterfaces, agg.mtu)?;
        if agg.redundancy_mode == EsRedundancy::SingleActive && agg.esi.is_none() {
            return Err(garde::Error::new(format!(
                "port aggregate {} is single-active but has no esi",
                agg.name
            )));
        }
        if agg.df_algorithm != DfAlgorithm::Modulo && agg.esi.is_none() {
            return Err(garde::Error::new(format!(
                "port aggregate {} sets a df-algorithm but has no esi",
                agg.name
            )));
        }
    }
    // A multi-homed segment must never join the spanning tree as a root or
    // transit port: the other PE's BPDUs would block it. An admin edge port
    // with bpdu-guard makes a stray BPDU a visible err-disable instead.
    if ctx.spanning_tree.mode != StpMode::Disabled {
        for agg in aggregates.iter().filter(|a| a.esi.is_some()) {
            let profile = agg
                .stp_port_profile
                .as_ref()
                .and_then(|n| ctx.stp_port_profiles.iter().find(|p| &p.name == n));
            if !profile.is_some_and(|p| p.edge_port == EdgePort::Admin && p.bpdu_guard) {
                return Err(garde::Error::new(format!(
                    "port aggregate {} has an esi: it needs an stp-port-profile with edge-port admin and bpdu-guard (or spanning-tree mode disabled)",
                    agg.name
                )));
            }
        }
    }
    // One aggregate per Ethernet Segment on a PE: two bonds claiming the same
    // ESI would make `nos-fdbd` unable to tell which port a MAC was learned on.
    for (i, agg) in aggregates.iter().enumerate() {
        if let Some(esi) = &agg.esi
            && aggregates[..i].iter().any(|o| o.esi.as_ref() == Some(esi))
        {
            return Err(garde::Error::new(format!(
                "esi {esi} is used by more than one port aggregate"
            )));
        }
    }
    for agg in aggregates {
        if agg.bfd.is_some() {
            let Some(peer) = agg.bfd_peer else {
                return Err(garde::Error::new(format!(
                    "port aggregate {} sets bfd but has no bfd-peer",
                    agg.name
                )));
            };
            let has_source = agg
                .subinterfaces
                .iter()
                .filter(|s| s.tag == 0)
                .flat_map(|s| &s.addresses)
                .any(|a| a.address.addr().is_ipv4() == peer.is_ipv4());
            if !has_source {
                return Err(garde::Error::new(format!(
                    "port aggregate {} bfd-peer {peer} needs an address of the same family on its untagged subinterface",
                    agg.name
                )));
            }
        }
    }
    for agg in aggregates {
        if agg.subinterfaces.is_empty() {
            continue;
        }
        let Some(profile_name) = &agg.switching_profile else {
            continue;
        };
        let Some(profile) = ctx
            .switching_profiles
            .iter()
            .find(|p| &p.name == profile_name)
        else {
            continue;
        };
        for sub in &agg.subinterfaces {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{InterfaceAddress, StpPortProfile};

    fn aggregate(name: &str) -> PortAggregate {
        PortAggregate {
            acl_in: None,
            acl_out: None,
            flowspec: false,
            name: name.to_string(),
            mode: PortAggregateMode::Xor, // arbitrary — mode has no bearing on the validators tested here
            lacp_rate: LacpRate::default(),
            esi: None,
            redundancy_mode: EsRedundancy::default(),
            df_algorithm: DfAlgorithm::default(),
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

    /// Spanning tree off: the ESI/guard rule has its own tests below.
    fn config_with(aggregates: Vec<PortAggregate>) -> Config {
        let mut c = Config {
            port_aggregates: aggregates,
            ..Default::default()
        };
        c.spanning_tree.mode = StpMode::Disabled;
        c
    }

    const ESI: &str = "00:11:22:33:44:55:66:77:88:99";

    fn esi_config(profile: Option<StpPortProfile>, mode: StpMode) -> Config {
        let mut a = aggregate("bond1");
        a.esi = Some(ESI.to_string());
        a.stp_port_profile = profile.as_ref().map(|p| p.name.clone());
        let mut c = config_with(vec![a]);
        c.spanning_tree.mode = mode;
        c.stp_port_profiles = profile.into_iter().collect();
        c
    }

    fn guard(edge_port: EdgePort, bpdu_guard: bool) -> StpPortProfile {
        StpPortProfile {
            name: "guard".into(),
            edge_port,
            bpdu_guard,
            ..Default::default()
        }
    }

    #[test]
    fn esi_aggregate_needs_an_admin_edge_bpdu_guard_profile() {
        let ok = |p, m| {
            let c = esi_config(p, m);
            c.validate_with(&c).is_ok()
        };
        assert!(ok(Some(guard(EdgePort::Admin, true)), StpMode::Rstp));
        assert!(ok(Some(guard(EdgePort::Admin, true)), StpMode::Mstp));
        // no profile / not admin edge / no bpdu-guard
        assert!(!ok(None, StpMode::Rstp));
        assert!(!ok(Some(guard(EdgePort::Auto, true)), StpMode::Rstp));
        assert!(!ok(Some(guard(EdgePort::Admin, false)), StpMode::RapidPvst));
        // spanning tree off: no requirement
        assert!(ok(None, StpMode::Disabled));
    }

    #[test]
    fn unknown_or_deleted_profile_is_refused_per_user() {
        let mut a = aggregate("bond1");
        a.stp_port_profile = Some("gone".into());
        let c = config_with(vec![a]);
        let err = c.validate_with(&c).unwrap_err().to_string();
        assert!(err.contains("port_aggregates[0].stp_port_profile"), "{err}");
    }

    #[test]
    fn valid_aggregate_passes() {
        let cfg = config_with(vec![aggregate("bond1")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![aggregate("bond1"), aggregate("bond1")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dotted_name_fails() {
        let cfg = config_with(vec![aggregate("bond1.100")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn esi_must_parse_and_be_unique() {
        let mut a = aggregate("bond1");
        a.esi = Some("00:11:22:33:44:55:66:77:88:99".to_string());
        config_with(vec![a.clone()])
            .validate_with(&config_with(vec![a.clone()]))
            .unwrap();

        let mut bad = a.clone();
        bad.esi = Some("00:11".to_string());
        let cfg = config_with(vec![bad]);
        assert!(cfg.validate_with(&cfg).is_err());

        let mut b = aggregate("bond2");
        b.esi = a.esi.clone();
        let cfg = config_with(vec![a, b]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn single_active_needs_an_esi() {
        let mut a = aggregate("bond1");
        a.redundancy_mode = EsRedundancy::SingleActive;
        let cfg = config_with(vec![a.clone()]);
        assert!(cfg.validate_with(&cfg).is_err());
        a.esi = Some("00:11:22:33:44:55:66:77:88:99".to_string());
        let cfg = config_with(vec![a]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn df_algorithm_needs_an_esi() {
        let mut a = aggregate("bond1");
        a.df_algorithm = DfAlgorithm::Hrw;
        let cfg = config_with(vec![a.clone()]);
        assert!(cfg.validate_with(&cfg).is_err());
        a.esi = Some("00:11:22:33:44:55:66:77:88:99".to_string());
        let cfg = config_with(vec![a]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn lacp_system_id_must_be_a_unicast_mac() {
        let mut a = aggregate("bond1");
        a.lacp_system_id = Some("02:00:00:00:00:01".to_string());
        let cfg = config_with(vec![a.clone()]);
        cfg.validate_with(&cfg).unwrap();
        a.lacp_system_id = Some("01:00:00:00:00:01".to_string());
        let cfg = config_with(vec![a]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn invalid_mtu_fails() {
        let mut agg = aggregate("bond1");
        agg.mtu = Some(10);
        let cfg = config_with(vec![agg]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn subinterface_mtu_above_bond_mtu_fails() {
        let mut agg = aggregate("bond1");
        agg.mtu = Some(9000);
        agg.subinterfaces = vec![crate::schema::Subinterface {
            tag: 100,
            mtu: Some(9000),
            ..Default::default()
        }];
        let cfg = config_with(vec![agg.clone()]);
        cfg.validate_with(&cfg).unwrap();
        agg.subinterfaces[0].mtu = Some(9001);
        let cfg = config_with(vec![agg]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn valid_subinterface_with_routing_table_passes() {
        let mut agg = aggregate("bond1");
        agg.subinterfaces = vec![crate::schema::Subinterface {
            mtu: None,
            acl_in: None,
            acl_out: None,
            flowspec: false,
            tag: 0,
            addresses: vec![InterfaceAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                label: None,
            }],
            routing_table: Some("rt1".to_string()),
            ospf_profile: None,
            ospfv3_profile: None,
            bfd_unsolicited: None,
        }];
        let mut cfg = config_with(vec![agg]);
        cfg.routing_tables = vec![crate::schema::RoutingTable {
            rest_api: None,
            evpn: crate::schema::RoutingTableEvpn::default(),
            vpn: crate::schema::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: "rt1".to_string(),
            bgp_instance: None,
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: Vec::new(),
        }];
        cfg.validate_with(&cfg).unwrap();
    }

    fn bfd_aggregate(addr: Option<&str>, peer: Option<&str>) -> Config {
        let mut a = aggregate("bond1");
        a.bfd = Some("fast".into());
        a.bfd_peer = peer.map(|p| p.parse().unwrap());
        if let Some(addr) = addr {
            a.subinterfaces = vec![crate::schema::Subinterface {
                mtu: None,
                acl_in: None,
                acl_out: None,
                flowspec: false,
                tag: 0,
                addresses: vec![InterfaceAddress {
                    address: addr.parse().unwrap(),
                    label: None,
                }],
                routing_table: None,
                ospf_profile: None,
                ospfv3_profile: None,
                bfd_unsolicited: None,
            }];
        }
        let mut cfg = config_with(vec![a]);
        cfg.bfd_profiles = vec![crate::schema::BfdProfile {
            name: "fast".into(),
            ..Default::default()
        }];
        cfg
    }

    #[test]
    fn bfd_needs_peer_source_address_and_profile() {
        let ok = bfd_aggregate(Some("10.0.0.1/31"), Some("10.0.0.2"));
        ok.validate_with(&ok).unwrap();
        let v6 = bfd_aggregate(Some("2001:db8::1/64"), Some("2001:db8::2"));
        v6.validate_with(&v6).unwrap();
        for bad in [
            bfd_aggregate(Some("10.0.0.1/31"), None),
            bfd_aggregate(None, Some("10.0.0.2")),
            bfd_aggregate(Some("10.0.0.1/31"), Some("2001:db8::2")),
        ] {
            assert!(bad.validate_with(&bad).is_err());
        }
        let mut unknown = bfd_aggregate(Some("10.0.0.1/31"), Some("10.0.0.2"));
        unknown.bfd_profiles.clear();
        assert!(unknown.validate_with(&unknown).is_err());
    }

    #[test]
    fn bfd_on_an_aggregate_without_members_is_accepted() {
        // Members live on the `Interface`s; the aggregate itself never checks them.
        let cfg = bfd_aggregate(Some("10.0.0.1/31"), Some("10.0.0.2"));
        cfg.validate_with(&cfg).unwrap();
    }
}
