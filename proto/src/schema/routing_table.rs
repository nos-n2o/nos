use std::net::IpAddr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::unique_key_in;

use super::{Config, SourceAddress};
use nos_proto_derive::Cli;

/// The source side of a `Redistribute` rule. Only `Static` exists today —
/// see `Redistribute`'s doc comment for why this is an enum rather than a
/// bare marker.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub enum RedistributeSource {
    #[default]
    /// Locally configured static routes.
    Static,
}

impl RedistributeSource {
    /// The CLI spelling of the source.
    pub fn as_str(&self) -> &'static str {
        match self {
            RedistributeSource::Static => "static",
        }
    }
}

impl std::fmt::Display for RedistributeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The target side of a `Redistribute` rule — `Bgp`, `Ospf` or `Ospfv3`. See
/// `Redistribute`'s doc comment.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub enum RedistributeTarget {
    #[default]
    /// Redistribute into a BGP instance.
    Bgp,
    /// Redistribute into an `OSPFv2` instance.
    Ospf,
    /// Appended last: postcard encodes variants by index.
    Ospfv3,
}

impl RedistributeTarget {
    /// The CLI spelling of the target.
    pub fn as_str(&self) -> &'static str {
        match self {
            RedistributeTarget::Bgp => "bgp",
            RedistributeTarget::Ospf => "ospf",
            RedistributeTarget::Ospfv3 => "ospfv3",
        }
    }
}

impl std::fmt::Display for RedistributeTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `redistribute bgp`). The table holds a list keyed by `to`
/// `redistribute from static to bgp`). The table holds a list keyed by `to`
/// (at most one rule per target), so static routes can feed BGP, OSPF and
/// `OSPFv3` at once; an `Option<Redistribute>` from before the list is still
/// read from disk (`deserialize_redistribute`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct Redistribute {
    #[cli(topic = RoutingTableRedistribute)]
    /// Protocol the redistributed routes come from.
    pub from: RedistributeSource,
    #[cli(key)]
    /// Protocol receiving the routes; the key, so at most one rule per target.
    pub to: RedistributeTarget,
    /// Names a `PolicyDefinition` (or the built-in `accept-all`/`deny-all`)
    /// to filter redistributed routes through before they reach BGP.
    /// Unlike `BgpPeerGroup.import_policy`/`export_policy`, `None` here
    /// means **accept-all**, not `deny-all` — redistribution has no
    /// filtering today, and defaulting to deny-all would silently break
    /// every existing `redistribute from static to bgp` config.
    #[cli(topic = RoutingTableRedistribute)]
    pub policy: Option<String>,
    /// OSPF external metric (1..=16777215) for the AS-external-LSAs this
    /// rule originates; `None` = 20. Only valid with `to ospf`.
    #[serde(default)]
    #[cli(topic = RoutingTableRedistribute)]
    pub metric: Option<u32>,
    /// OSPF external metric type, 1 or 2 (RFC 2328 §16.4); `None` = 1. Only
    /// valid with `to ospf`.
    #[serde(default)]
    #[cli(topic = RoutingTableRedistribute)]
    pub metric_type: Option<u8>,
}

/// Where `nos-restd` listens for a routing table: one specific address
/// inside the table's VRF. There is deliberately no wildcard — an
/// unauthenticated management API must be pinned to one reachable address.
/// Whether the address is actually configured on an interface in the VRF is
/// operational state, not validated at commit: `nos-restd` retries the bind.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct RestApi {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(topic = RoutingTableRestApi)]
    /// Address the REST listener binds inside the VRF; no wildcard.
    pub address: IpAddr,
    #[cli(topic = RoutingTableRestApi)]
    /// TCP port of the REST listener.
    pub port: u16,
}

/// The placeholder a new `RestApi` starts from (`edit` on a missing one).
impl Default for RestApi {
    fn default() -> Self {
        RestApi {
            address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port: REST_API_PORT_DEFAULT,
        }
    }
}

/// Default `RestApi.port` when `nos-cli` is given none.
pub const REST_API_PORT_DEFAULT: u16 = 8080;

fn rest_api_valid(rest_api: Option<&RestApi>) -> garde::Result {
    let Some(r) = rest_api else {
        return Ok(());
    };
    if r.address.is_unspecified() || r.address.is_multicast() {
        return Err(garde::Error::new(
            "rest api address must be a specific unicast address",
        ));
    }
    if r.port == 0 {
        return Err(garde::Error::new("rest api port must be 1-65535"));
    }
    Ok(())
}

/// An IP-VRF's EVPN L3 VNI (RFC 9136 Type-5 routes, RFC 9135 symmetric
/// IRB in its "interface-less" form): `nos-ribd` creates `vx<l3_vni>` on a
/// bridge `brv<l3_vni>` in this table's VRF, originates every best route of
/// the table as a Type-5 into `bgp_instance` (the underlay instance, never
/// the table's own) and installs the Type-5 routes it receives back.
///
/// A plain struct with optional fields rather than an `Option<…>` (like
/// `Config.lldp`): the CLI then reaches every field on its own (`set
/// routing-table t evpn l3-vni 5000`, `… evpn route-target import <rt>`),
/// which an optional struct, set in one line, can't do for its lists.
/// Setting `l3_vni` turns it on; every other field requires it — see
/// `valid_table_evpn`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct RoutingTableEvpn {
    /// The L3 VNI (1-16777215), unique across every table and broadcast domain.
    #[cli(topic = RoutingTableEvpnL3Vni)]
    pub l3_vni: Option<u32>,
    /// Route Distinguisher of every Type-5 route this table originates.
    #[cli(topic = RoutingTableEvpnRd)]
    pub rd: Option<String>,
    /// A received Type-5 route must carry one of these to be installed.
    #[serde(default)]
    #[cli(topic = RoutingTableEvpnRouteTarget, words = "route-target import")]
    pub route_targets_import: Vec<String>,
    /// Attached to every Type-5 route this table originates.
    #[serde(default)]
    #[cli(topic = RoutingTableEvpnRouteTarget, words = "route-target export")]
    pub route_targets_export: Vec<String>,
    /// The VTEP address, resolved at runtime by `nos-ribd`. `Loopback` is the
    /// loopback of the routing table owning `bgp_instance`.
    #[cli(topic = RoutingTableEvpnVtepSource)]
    pub vtep_source: Option<SourceAddress>,
    /// The underlay BGP instance the Type-5 routes are exchanged over.
    #[cli(topic = RoutingTableEvpnBgpInstance)]
    pub bgp_instance: Option<String>,
}

/// A VRF's L3VPN identity (RFC 4364 VPNv4/VPNv6): the RD and route targets
/// of the routes this table exports into / imports from the VPN address
/// families of `bgp_instance` (the underlay instance, never the table's
/// own), plus an optional static MPLS label. Unset (all default) means the
/// table is not a VPN; any field requires the others, see `valid_table_vpn`.
/// No daemon consumes it yet (later sub-issues of #573).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct RoutingTableVpn {
    /// Route Distinguisher prepended to every exported prefix.
    #[cli(topic = RoutingTableVpnRd)]
    pub rd: Option<String>,
    /// A received VPN route must carry one of these to be imported.
    #[serde(default)]
    #[cli(topic = RoutingTableVpnRouteTarget, words = "route-target import")]
    pub route_targets_import: Vec<String>,
    /// Attached to every VPN route this table exports.
    #[serde(default)]
    #[cli(topic = RoutingTableVpnRouteTarget, words = "route-target export")]
    pub route_targets_export: Vec<String>,
    /// The underlay BGP instance the VPN routes are exchanged over.
    #[cli(topic = RoutingTableVpnBgpInstance)]
    pub bgp_instance: Option<String>,
    /// Static MPLS label (16-1048575) for this VRF's exported routes.
    #[cli(topic = RoutingTableVpnLabel)]
    pub label: Option<u32>,
    /// Site of Origin (RFC 4364 section 7): attached to every route this
    /// table exports; a received route carrying it is not imported here.
    #[serde(default)]
    #[cli(topic = RoutingTableVpnSiteOfOrigin, words = "site-of-origin")]
    pub site_of_origin: Option<String>,
}

/// A named routing table, optionally associated with one BGP instance and
/// one static routing instance. The reference lives only on the table —
/// `BgpInstance`/`StaticRoutingInstance` have no notion of which table(s)
/// reference them.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct RoutingTable {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_key_in(n, &ctx.routing_tables, |t| &t.name))
    )]
    #[cli(key)]
    /// Table name, 1 to 64 characters; also the VRF name.
    pub name: String,

    #[garde(custom(|bi: &Option<String>, ctx: &Config| bgp_instance_reference_valid(bi.as_ref(), ctx)))]
    #[cli(topic = RoutingTableBgpInstance)]
    /// BGP instance bound to this table, if any.
    pub bgp_instance: Option<String>,

    #[garde(custom(|sri: &Option<String>, ctx: &Config| static_routing_instance_reference_valid(sri.as_ref(), ctx)))]
    #[cli(topic = RoutingTableStaticRoutingInstance)]
    /// Static routing instance bound to this table, if any.
    pub static_routing_instance: Option<String>,

    #[garde(custom(|oi: &Option<String>, ctx: &Config| ospf_instance_reference_valid(oi.as_ref(), ctx)))]
    #[cli(topic = RoutingTableOspfInstance)]
    /// `OSPFv2` instance bound to this table, if any.
    pub ospf_instance: Option<String>,

    /// Same shape as `ospf_instance`, associating this table with an
    /// `Ospfv3Instance` (RFC 5340) instead — a separate field, not a
    /// widened `ospf_instance`, since `nos-ospfd`/`nos-ospfv3d` are two
    /// independent daemons that can both legitimately claim the same table
    /// (dual-stack OSPF on one VRF).
    #[garde(custom(|oi: &Option<String>, ctx: &Config| ospfv3_instance_reference_valid(oi.as_ref(), ctx)))]
    #[cli(topic = RoutingTableOspfv3Instance)]
    pub ospfv3_instance: Option<String>,

    /// `#[garde(skip)]`: the cross-field constraint (the referenced
    /// `bgp_instance`/`static_routing_instance` must actually be set on this
    /// same table) can't live in a per-field closure — garde's per-field
    /// `custom` closures can't see a sibling field — so it's wired one level
    /// up, on `Config.routing_tables` (`valid_redistribute_rules`), the same
    /// reason `BgpPeerGroup`'s timer check is wired on `BgpInstance.peer_groups`.
    #[serde(default, deserialize_with = "deserialize_redistribute")]
    #[garde(skip)]
    #[cli(topic = RoutingTableRedistribute)]
    pub redistribute: Vec<Redistribute>,

    /// Pins a `nos-restd` to this table: it listens on `rest_api.address`
    /// inside this table's VRF. `serde(default)` so on-disk config saved
    /// before this field existed still loads.
    #[serde(default)]
    #[garde(custom(|r: &Option<RestApi>, _ctx: &Config| rest_api_valid(r.as_ref())))]
    #[cli(topic = RoutingTableRestApi)]
    pub rest_api: Option<RestApi>,

    /// EVPN IP-VRF: this table's L3 VNI. `serde(default)` like `rest_api`.
    /// `#[garde(skip)]`: checked by `valid_table_evpn` (it needs the other
    /// tables and the broadcast domains).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RoutingTableEvpn)]
    pub evpn: RoutingTableEvpn,

    /// L3VPN identity (RD, route targets, underlay instance, label).
    /// `serde(default)` like `evpn`; `#[garde(skip)]`: checked by
    /// `valid_table_vpn` (it needs the other tables).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = RoutingTableVpn)]
    pub vpn: RoutingTableVpn,
}

/// If set, `bgp_instance` must name an existing `BgpInstance` (cf.
/// `bgp_peer::peer_group_exists`), and at most one routing table may claim a
/// given instance at a time. A second table naming the same instance makes
/// *both* references invalid — this mirrors `bgp_peer_group::unique_name`'s
/// approach of scoring every occurrence rather than privileging a "first"
/// owner, since garde's validation context is fixed to `&Config` for the
/// whole dive chain.
fn bgp_instance_reference_valid(bgp_instance: Option<&String>, ctx: &Config) -> garde::Result {
    let Some(name) = bgp_instance else {
        return Ok(());
    };
    if !ctx.bgp_instances.iter().any(|i| &i.name == name) {
        return Err(garde::Error::new("referenced bgp instance does not exist"));
    }
    let claims = ctx
        .routing_tables
        .iter()
        .filter(|t| t.bgp_instance.as_deref() == Some(name.as_str()))
        .count();
    if claims > 1 {
        return Err(garde::Error::new(
            "bgp instance is already associated with another routing table",
        ));
    }
    Ok(())
}

/// Same shape as `bgp_instance_reference_valid`, checked against
/// `ctx.ospf_instances` instead.
fn ospf_instance_reference_valid(ospf_instance: Option<&String>, ctx: &Config) -> garde::Result {
    let Some(name) = ospf_instance else {
        return Ok(());
    };
    if !ctx.ospf_instances.iter().any(|i| &i.name == name) {
        return Err(garde::Error::new("referenced ospf instance does not exist"));
    }
    let claims = ctx
        .routing_tables
        .iter()
        .filter(|t| t.ospf_instance.as_deref() == Some(name.as_str()))
        .count();
    if claims > 1 {
        return Err(garde::Error::new(
            "ospf instance is already associated with another routing table",
        ));
    }
    Ok(())
}

/// Same shape as `ospf_instance_reference_valid`, checked against
/// `ctx.ospfv3_instances` instead.
fn ospfv3_instance_reference_valid(
    ospfv3_instance: Option<&String>,
    ctx: &Config,
) -> garde::Result {
    let Some(name) = ospfv3_instance else {
        return Ok(());
    };
    if !ctx.ospfv3_instances.iter().any(|i| &i.name == name) {
        return Err(garde::Error::new(
            "referenced ospfv3 instance does not exist",
        ));
    }
    let claims = ctx
        .routing_tables
        .iter()
        .filter(|t| t.ospfv3_instance.as_deref() == Some(name.as_str()))
        .count();
    if claims > 1 {
        return Err(garde::Error::new(
            "ospfv3 instance is already associated with another routing table",
        ));
    }
    Ok(())
}

/// Same shape as `bgp_instance_reference_valid`, checked against
/// `ctx.static_routing_instances` instead.
fn static_routing_instance_reference_valid(
    static_routing_instance: Option<&String>,
    ctx: &Config,
) -> garde::Result {
    let Some(name) = static_routing_instance else {
        return Ok(());
    };
    if !ctx.static_routing_instances.iter().any(|i| &i.name == name) {
        return Err(garde::Error::new(
            "referenced static routing instance does not exist",
        ));
    }
    let claims = ctx
        .routing_tables
        .iter()
        .filter(|t| t.static_routing_instance.as_deref() == Some(name.as_str()))
        .count();
    if claims > 1 {
        return Err(garde::Error::new(
            "static routing instance is already associated with another routing table",
        ));
    }
    Ok(())
}

/// Cross-field check for the whole `routing_tables` list — garde's per-field
/// `custom` closures only ever see `(field_value, &Config)`, never a sibling
/// field on the same struct, so `redistribute`'s constraint on
/// `bgp_instance`/`static_routing_instance` must be wired here instead of on
/// `RoutingTable.redistribute` itself (mirrors
/// `bgp_peer_group::valid_peer_group_timers`'s technique).
///
/// `from: Static` requires `static_routing_instance` to be set; `to: Bgp`
/// requires `bgp_instance` to be set. Checked only at commit time, never in
/// `RoutingTableOp::apply`.
pub(crate) fn valid_redistribute_rules(tables: &[RoutingTable], ctx: &Config) -> garde::Result {
    for table in tables {
        for (i, rule) in table.redistribute.iter().enumerate() {
            if table.redistribute[..i].iter().any(|r| r.to == rule.to) {
                return Err(garde::Error::new("duplicate redistribute target"));
            }
            valid_redistribute_rule(table, rule, ctx)?;
        }
    }
    for table in tables {
        valid_table_evpn(table, ctx)?;
        valid_table_vpn(table, ctx)?;
    }
    Ok(())
}

/// Accepts the list, a single object or null (the pre-list `Option` shape) in
/// YAML/JSON; postcard is not self-describing, so it reads the plain `Vec`.
fn deserialize_redistribute<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<Redistribute>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Shim {
        Many(Vec<Redistribute>),
        One(Redistribute),
        None(()),
    }
    if !d.is_human_readable() {
        return Vec::deserialize(d);
    }
    Ok(match Shim::deserialize(d)? {
        Shim::Many(v) => v,
        Shim::One(r) => vec![r],
        Shim::None(()) => Vec::new(),
    })
}

fn valid_redistribute_rule(
    table: &RoutingTable,
    redistribute: &Redistribute,
    ctx: &Config,
) -> garde::Result {
    {
        if redistribute.from == RedistributeSource::Static
            && table.static_routing_instance.is_none()
        {
            return Err(garde::Error::new(
                "redistribute from static requires static-routing-instance to be set",
            ));
        }
        if redistribute.to == RedistributeTarget::Bgp && table.bgp_instance.is_none() {
            return Err(garde::Error::new(
                "redistribute to bgp requires bgp-instance to be set",
            ));
        }
        if redistribute.to == RedistributeTarget::Ospf && table.ospf_instance.is_none() {
            return Err(garde::Error::new(
                "redistribute to ospf requires ospf-instance to be set",
            ));
        }
        // RFC 8770 §3: a host router is no ASBR.
        if redistribute.to == RedistributeTarget::Ospf
            && ctx
                .ospf_instances
                .iter()
                .any(|i| table.ospf_instance.as_ref() == Some(&i.name) && i.host_router)
        {
            return Err(garde::Error::new(
                "redistribute to ospf is not allowed on an ospf instance with host-router set",
            ));
        }
        if redistribute.to == RedistributeTarget::Ospfv3 && table.ospfv3_instance.is_none() {
            return Err(garde::Error::new(
                "redistribute to ospfv3 requires ospfv3-instance to be set",
            ));
        }
        redistribute_policy_reference_valid(redistribute.policy.as_ref(), ctx)?;
        if (redistribute.metric.is_some() || redistribute.metric_type.is_some())
            && redistribute.to != RedistributeTarget::Ospf
        {
            return Err(garde::Error::new(
                "redistribute metric/metric-type apply to 'to ospf' only",
            ));
        }
        if redistribute
            .metric
            .is_some_and(|m| !(1..=0x00ff_ffff).contains(&m))
        {
            return Err(garde::Error::new(
                "redistribute metric must be between 1 and 16777215",
            ));
        }
        if redistribute
            .metric_type
            .is_some_and(|t| !(1..=2).contains(&t))
        {
            return Err(garde::Error::new("redistribute metric-type must be 1 or 2"));
        }
    }
    Ok(())
}

/// A table's `vpn` (RFC 4364): unset when default; otherwise an RD, at least
/// one export RT, an existing underlay `bgp_instance` that isn't the table's
/// own, a label in the MPLS unicast range (16-1048575, RFC 3032) used by no
/// other table, and an RD (compared as 8 bytes) used by no other table's
/// `vpn.rd` or `evpn.rd` (an RD names one VRF, section 4.2; EVPN Type-5 shares
/// the namespace on the wire).
fn valid_table_vpn(table: &RoutingTable, ctx: &Config) -> garde::Result {
    let err = |m: &str| Err(garde::Error::new(m.to_string()));
    let v = &table.vpn;
    if *v == RoutingTableVpn::default() {
        return Ok(());
    }
    let Some(rd) = v.rd.as_deref().and_then(crate::evpn_id::parse_rd) else {
        return err("vpn needs an rd, asn:nn or a.b.c.d:nn");
    };
    let mut rts = v.route_targets_import.iter().chain(&v.route_targets_export);
    if rts.any(|r| crate::evpn_id::parse_rt(r).is_none()) {
        return err("vpn route-target must be asn:nn or a.b.c.d:nn");
    }
    if v.route_targets_export.is_empty() {
        return err("vpn needs at least one export route-target");
    }
    if v.site_of_origin
        .as_deref()
        .is_some_and(|s| crate::evpn_id::parse_rt(s).is_none())
    {
        return err("vpn site-of-origin must be asn:nn or a.b.c.d:nn");
    }
    let Some(instance) = &v.bgp_instance else {
        return err("vpn needs a bgp-instance");
    };
    if !ctx.bgp_instances.iter().any(|i| &i.name == instance) {
        return err("vpn bgp-instance does not exist");
    }
    if table.bgp_instance.as_ref() == Some(instance) {
        return err("vpn bgp-instance must be the underlay's, not this table's own");
    }
    let others = || ctx.routing_tables.iter().filter(|t| t.name != table.name);
    if let Some(label) = v.label {
        if !(16..=0x000f_ffff).contains(&label) {
            return err("vpn label must be between 16 and 1048575");
        }
        if others().any(|t| t.vpn.label == Some(label)) {
            return err("vpn label is already used by another routing table");
        }
    }
    let rd_of = |s: &Option<String>| s.as_deref().and_then(crate::evpn_id::parse_rd);
    if others().any(|t| rd_of(&t.vpn.rd) == Some(rd) || rd_of(&t.evpn.rd) == Some(rd)) {
        return err("vpn rd is already used by another routing table");
    }
    Ok(())
}

/// A table's `evpn`: nothing but an L3 VNI turns it on, and with one it
/// needs well-formed RD/RTs (an RD and an export RT at least: every best route
/// is originated), a VTEP source, and an existing underlay `bgp_instance`
/// that isn't the table's own (the overlay's VRF must differ from the
/// underlay's); the L3 VNI is used by no other table or broadcast domain
/// (`vx<vni>` is one device per network namespace, shared with `nos-fdbd`).
fn valid_table_evpn(table: &RoutingTable, ctx: &Config) -> garde::Result {
    let err = |m: &str| Err(garde::Error::new(m.to_string()));
    let e = &table.evpn;
    let Some(vni) = e.l3_vni else {
        if *e != RoutingTableEvpn::default() {
            return err("evpn rd, route-targets, vtep-source and bgp-instance require an l3-vni");
        }
        return Ok(());
    };
    if !(1..=0x00ff_ffff).contains(&vni) {
        return err("evpn l3-vni must be between 1 and 16777215");
    }
    if e.rd.as_deref().and_then(crate::evpn_id::parse_rd).is_none() {
        return err("evpn needs an rd, asn:nn or a.b.c.d:nn");
    }
    let mut rts = e.route_targets_import.iter().chain(&e.route_targets_export);
    if rts.any(|r| crate::evpn_id::parse_rt(r).is_none()) {
        return err("evpn route-target must be asn:nn or a.b.c.d:nn");
    }
    if e.route_targets_export.is_empty() {
        return err("evpn needs at least one export route-target");
    }
    if e.vtep_source.is_none() {
        return err("evpn needs a vtep-source");
    }
    let Some(instance) = &e.bgp_instance else {
        return err("evpn needs a bgp-instance");
    };
    if !ctx.bgp_instances.iter().any(|i| &i.name == instance) {
        return err("evpn bgp-instance does not exist");
    }
    if table.bgp_instance.as_ref() == Some(instance) {
        return err("evpn bgp-instance must be the underlay's, not this table's own");
    }
    let tables = ctx
        .routing_tables
        .iter()
        .filter(|t| t.evpn.l3_vni == Some(vni))
        .count();
    let domains = ctx
        .broadcast_domains
        .iter()
        .filter(|d| d.vni == Some(vni))
        .count();
    if tables + domains > 1 {
        return err("evpn l3-vni is already used by another routing table or broadcast domain");
    }
    Ok(())
}

/// Same shape as `bgp_peer_group::policy_reference_valid`: `None` or the
/// built-in `accept-all`/`deny-all` names are always valid, anything else
/// must match a real `PolicyDefinition`.
fn redistribute_policy_reference_valid(name: Option<&String>, ctx: &Config) -> garde::Result {
    let Some(name) = name else {
        return Ok(());
    };
    if name == nos_rpl::ACCEPT_ALL_NAME || name == nos_rpl::DENY_ALL_NAME {
        return Ok(());
    }
    if ctx.policy_definitions.iter().any(|p| &p.name == name) {
        Ok(())
    } else {
        Err(garde::Error::new("referenced policy does not exist"))
    }
}

#[cfg(test)]
mod tests {
    use crate::schema::{BgpInstance, Config, OspfInstance, StaticRoutingInstance};

    use super::*;

    fn table(name: &str, bgp_instance: Option<&str>, sri: Option<&str>) -> RoutingTable {
        RoutingTable {
            rest_api: None,
            evpn: crate::schema::RoutingTableEvpn::default(),
            vpn: RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: name.to_string(),
            bgp_instance: bgp_instance.map(str::to_string),
            ospf_instance: None,
            static_routing_instance: sri.map(str::to_string),
            redistribute: Vec::new(),
        }
    }

    fn ospf_instance(name: &str) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
            areas: Vec::new(),
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
        }
    }

    fn instance(name: &str) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: Vec::new(),
            peers: Vec::new(),
            cluster_id: None,
            maximum_paths: None,
            confederation: crate::schema::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            bmp_stations: Vec::new(),
            aggregates: Vec::new(),
            graceful_restart: crate::schema::BgpGracefulRestart::default(),
            routing_table: None,
            redistribute_policy: None,
        }
    }

    fn static_instance(name: &str) -> StaticRoutingInstance {
        StaticRoutingInstance {
            name: name.to_string(),
            routes: Vec::new(),
        }
    }

    fn config_with(
        tables: Vec<RoutingTable>,
        instances: Vec<BgpInstance>,
        static_instances: Vec<StaticRoutingInstance>,
    ) -> Config {
        Config {
            routing_tables: tables,
            bgp_instances: instances,
            static_routing_instances: static_instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_table_with_no_associations_passes() {
        let cfg = config_with(vec![table("rt1", None, None)], vec![], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn valid_table_with_both_associations_passes() {
        let cfg = config_with(
            vec![table("rt1", Some("r1"), Some("sri1"))],
            vec![instance("r1")],
            vec![static_instance("sri1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_table_name_fails() {
        let cfg = config_with(
            vec![table("rt1", None, None), table("rt1", None, None)],
            vec![],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dangling_bgp_instance_reference_fails() {
        let cfg = config_with(
            vec![table("rt1", Some("does-not-exist"), None)],
            vec![],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dangling_static_routing_instance_reference_fails() {
        let cfg = config_with(
            vec![table("rt1", None, Some("does-not-exist"))],
            vec![],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn two_tables_claiming_same_bgp_instance_fails() {
        let cfg = config_with(
            vec![
                table("rt1", Some("r1"), None),
                table("rt2", Some("r1"), None),
            ],
            vec![instance("r1")],
            vec![],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn two_tables_claiming_same_static_routing_instance_fails() {
        let cfg = config_with(
            vec![
                table("rt1", None, Some("sri1")),
                table("rt2", None, Some("sri1")),
            ],
            vec![],
            vec![static_instance("sri1")],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_tables_claiming_distinct_instances_pass() {
        let cfg = config_with(
            vec![
                table("rt1", Some("r1"), Some("sri1")),
                table("rt2", Some("r2"), Some("sri2")),
            ],
            vec![instance("r1"), instance("r2")],
            vec![static_instance("sri1"), static_instance("sri2")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn valid_table_with_ospf_association_passes() {
        let mut cfg = config_with(vec![table("rt1", None, None)], vec![], vec![]);
        cfg.routing_tables[0].ospf_instance = Some("o1".to_string());
        cfg.ospf_instances = vec![ospf_instance("o1")];
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dangling_ospf_instance_reference_fails() {
        let mut cfg = config_with(vec![table("rt1", None, None)], vec![], vec![]);
        cfg.routing_tables[0].ospf_instance = Some("does-not-exist".to_string());
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn two_tables_claiming_same_ospf_instance_fails() {
        let mut cfg = config_with(
            vec![table("rt1", None, None), table("rt2", None, None)],
            vec![],
            vec![],
        );
        cfg.routing_tables[0].ospf_instance = Some("o1".to_string());
        cfg.routing_tables[1].ospf_instance = Some("o1".to_string());
        cfg.ospf_instances = vec![ospf_instance("o1")];
        assert!(cfg.validate_with(&cfg).is_err());
    }

    fn redistribute() -> Redistribute {
        Redistribute {
            from: RedistributeSource::Static,
            to: RedistributeTarget::Bgp,
            policy: None,
            metric: None,
            metric_type: None,
        }
    }

    #[test]
    fn duplicate_redistribute_target_fails() {
        let mut rt = table("rt1", Some("r1"), Some("sri1"));
        rt.redistribute = vec![redistribute(), redistribute()];
        let cfg = config_with(
            vec![rt],
            vec![instance("r1")],
            vec![static_instance("sri1")],
        );
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn redistribute_reads_old_shapes_and_postcard_round_trips() {
        let rule = serde_json::json!({"from": "Static", "to": "Ospf", "policy": null});
        let parse = |v: serde_json::Value| {
            let mut j = serde_json::to_value(table("rt1", None, None)).unwrap();
            j["redistribute"] = v;
            serde_json::from_value::<RoutingTable>(j)
                .unwrap()
                .redistribute
        };
        assert_eq!(parse(rule.clone())[0].to, RedistributeTarget::Ospf);
        assert_eq!(parse(serde_json::Value::Null).len(), 0);
        assert_eq!(parse(serde_json::json!([rule.clone(), rule])).len(), 2);

        let mut rt = table("rt1", None, None);
        rt.redistribute = vec![redistribute()];
        let bytes = postcard::to_allocvec(&rt).unwrap();
        assert_eq!(postcard::from_bytes::<RoutingTable>(&bytes).unwrap(), rt);
    }

    #[test]
    fn redistribute_with_both_associations_passes() {
        let mut rt = table("rt1", Some("r1"), Some("sri1"));
        rt.redistribute = vec![redistribute()];
        let cfg = config_with(
            vec![rt],
            vec![instance("r1")],
            vec![static_instance("sri1")],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn redistribute_without_static_routing_instance_fails() {
        let mut rt = table("rt1", Some("r1"), None);
        rt.redistribute = vec![redistribute()];
        let cfg = config_with(vec![rt], vec![instance("r1")], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn redistribute_without_bgp_instance_fails() {
        let mut rt = table("rt1", None, Some("sri1"));
        rt.redistribute = vec![redistribute()];
        let cfg = config_with(vec![rt], vec![], vec![static_instance("sri1")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn redistribute_without_ospf_instance_fails() {
        let mut rt = table("rt1", None, Some("sri1"));
        rt.redistribute = vec![Redistribute {
            to: RedistributeTarget::Ospf,
            ..redistribute()
        }];
        let cfg = config_with(vec![rt], vec![], vec![static_instance("sri1")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn redistribute_to_ospf_with_ospf_instance_passes() {
        let mut rt = table("rt1", None, Some("sri1"));
        rt.ospf_instance = Some("o1".to_string());
        rt.redistribute = vec![Redistribute {
            to: RedistributeTarget::Ospf,
            ..redistribute()
        }];
        let mut cfg = config_with(vec![rt], vec![], vec![static_instance("sri1")]);
        cfg.ospf_instances = vec![ospf_instance("o1")];
        cfg.validate_with(&cfg).unwrap();
        // RFC 8770 §3: not with a host router.
        cfg.ospf_instances[0].host_router = true;
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn redistribute_to_ospfv3_requires_ospfv3_instance() {
        let mut rt = table("rt1", None, Some("sri1"));
        rt.redistribute = vec![Redistribute {
            to: RedistributeTarget::Ospfv3,
            ..redistribute()
        }];
        let cfg = config_with(vec![rt.clone()], vec![], vec![static_instance("sri1")]);
        assert!(cfg.validate_with(&cfg).is_err());
        rt.ospfv3_instance = Some("o1".to_string());
        let mut cfg = config_with(vec![rt], vec![], vec![static_instance("sri1")]);
        cfg.ospfv3_instances = vec![crate::schema::Ospfv3Instance {
            name: "o1".to_string(),
            ..Default::default()
        }];
        cfg.validate_with(&cfg).unwrap();
    }

    fn config_with_policy(
        rt: RoutingTable,
        policies: Vec<crate::schema::PolicyDefinition>,
    ) -> Config {
        let mut cfg = config_with(
            vec![rt],
            vec![instance("r1")],
            vec![static_instance("sri1")],
        );
        cfg.policy_definitions = policies;
        cfg
    }

    fn ospf_metric_config(
        metric: Option<u32>,
        metric_type: Option<u8>,
        to: RedistributeTarget,
    ) -> Config {
        let mut rt = table("rt1", Some("r1"), Some("sri1"));
        rt.ospf_instance = Some("o1".to_string());
        rt.redistribute = vec![Redistribute {
            to,
            metric,
            metric_type,
            ..redistribute()
        }];
        let mut cfg = config_with(
            vec![rt],
            vec![instance("r1")],
            vec![static_instance("sri1")],
        );
        cfg.ospf_instances = vec![ospf_instance("o1")];
        cfg
    }

    #[test]
    fn redistribute_metric_validation() {
        let ospf = RedistributeTarget::Ospf;
        let ok = |m, t, to| {
            let cfg = ospf_metric_config(m, t, to);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(ok(None, None, ospf));
        assert!(ok(Some(1), Some(1), ospf));
        assert!(ok(Some(0x00ff_ffff), Some(2), ospf));
        assert!(!ok(Some(0), None, ospf));
        assert!(!ok(Some(0x0100_0000), None, ospf));
        assert!(!ok(None, Some(0), ospf));
        assert!(!ok(None, Some(3), ospf));
        // `to bgp` has no such knob.
        assert!(!ok(Some(5), None, RedistributeTarget::Bgp));
        assert!(!ok(None, Some(2), RedistributeTarget::Bgp));
    }

    #[test]
    fn redistribute_without_metric_fields_still_deserializes() {
        let r: Redistribute =
            serde_json::from_str(r#"{"from":"Static","to":"Ospf","policy":null}"#).unwrap();
        assert_eq!((r.metric, r.metric_type), (None, None));
    }

    #[test]
    fn redistribute_with_no_policy_passes() {
        let mut rt = table("rt1", Some("r1"), Some("sri1"));
        rt.redistribute = vec![redistribute()];
        let cfg = config_with_policy(rt, vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn redistribute_with_existing_policy_passes() {
        let mut rt = table("rt1", Some("r1"), Some("sri1"));
        rt.redistribute = vec![Redistribute {
            policy: Some("p1".to_string()),
            ..redistribute()
        }];
        let cfg = config_with_policy(
            rt,
            vec![crate::schema::PolicyDefinition {
                name: "p1".to_string(),
                source: "accept\n".to_string(),
            }],
        );
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn redistribute_with_dangling_policy_fails() {
        let mut rt = table("rt1", Some("r1"), Some("sri1"));
        rt.redistribute = vec![Redistribute {
            policy: Some("does-not-exist".to_string()),
            ..redistribute()
        }];
        let cfg = config_with_policy(rt, vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    fn evpn() -> RoutingTableEvpn {
        RoutingTableEvpn {
            l3_vni: Some(5000),
            rd: Some("65000:5000".to_string()),
            route_targets_import: vec!["65000:5000".to_string()],
            route_targets_export: vec!["65000:5000".to_string()],
            vtep_source: Some(SourceAddress::Interface {
                interface: "eth0".to_string(),
                label: None,
            }),
            bgp_instance: Some("r1".to_string()),
        }
    }

    #[test]
    fn evpn_table_validation() {
        let tenant = |e: RoutingTableEvpn| {
            let mut t = table("tenant", None, None);
            t.evpn = e;
            t
        };
        let cfg = config_with(
            vec![table("rt1", Some("r1"), None), tenant(evpn())],
            vec![instance("r1")],
            vec![],
        );
        cfg.validate_with(&cfg).unwrap();

        for mutate in [
            (|e: &mut RoutingTableEvpn| e.l3_vni = Some(0)) as fn(&mut RoutingTableEvpn),
            |e| e.l3_vni = Some(1 << 24),
            |e| e.l3_vni = None,
            |e| e.rd = Some("junk".to_string()),
            |e| e.rd = None,
            |e| e.route_targets_import = vec!["65000".to_string()],
            |e| e.route_targets_export.clear(),
            |e| e.vtep_source = None,
            |e| e.bgp_instance = Some("nope".to_string()),
            |e| e.bgp_instance = None,
        ] {
            let mut e = evpn();
            mutate(&mut e);
            let mut bad = cfg.clone();
            bad.routing_tables[1] = tenant(e);
            assert!(bad.validate_with(&bad).is_err());
        }

        // The table's own instance can't be its underlay.
        let mut own = cfg.clone();
        own.routing_tables[0].evpn = evpn();
        own.routing_tables.pop();
        assert!(own.validate_with(&own).is_err());

        // An L3 VNI colliding with another table's or a domain's VNI.
        let mut twice = cfg.clone();
        let mut second = tenant(evpn());
        second.name = "tenant2".to_string();
        twice.routing_tables.push(second);
        assert!(twice.validate_with(&twice).is_err());
        let mut with_domain = cfg.clone();
        with_domain.broadcast_domains = vec![crate::schema::BroadcastDomain {
            name: "bd1".to_string(),
            vni: Some(5000),
            ..Default::default()
        }];
        assert!(with_domain.validate_with(&with_domain).is_err());
    }

    fn vpn() -> RoutingTableVpn {
        RoutingTableVpn {
            rd: Some("65000:1".to_string()),
            route_targets_import: vec!["65000:1".to_string()],
            route_targets_export: vec!["65000:1".to_string()],
            bgp_instance: Some("r1".to_string()),
            label: Some(100),
            site_of_origin: None,
        }
    }

    #[test]
    fn vpn_table_validation() {
        let red = |v: RoutingTableVpn| {
            let mut t = table("red", None, None);
            t.vpn = v;
            t
        };
        let cfg = config_with(
            vec![table("rt1", Some("r1"), None), red(vpn())],
            vec![instance("r1")],
            vec![],
        );
        cfg.validate_with(&cfg).unwrap();

        // Unset passes; an export-only spoke (no import RT, no label) passes.
        let mut spoke = vpn();
        spoke.route_targets_import.clear();
        spoke.label = None;
        for v in [RoutingTableVpn::default(), spoke] {
            let mut ok = cfg.clone();
            ok.routing_tables[1] = red(v);
            ok.validate_with(&ok).unwrap();
        }

        for mutate in [
            (|v: &mut RoutingTableVpn| v.rd = Some("junk".to_string())) as fn(&mut RoutingTableVpn),
            |v| v.rd = None,
            |v| v.route_targets_import = vec!["65000".to_string()],
            |v| v.route_targets_export.clear(),
            |v| v.bgp_instance = None,
            |v| v.bgp_instance = Some("nope".to_string()),
            |v| v.label = Some(0),
            |v| v.label = Some(15),
            |v| v.label = Some(1_048_576),
            |v| v.site_of_origin = Some("junk".to_string()),
            |v| v.site_of_origin = Some("70000:70000".to_string()),
        ] {
            let mut v = vpn();
            mutate(&mut v);
            let mut bad = cfg.clone();
            bad.routing_tables[1] = red(v);
            assert!(bad.validate_with(&bad).is_err());
        }
        // A SoO may equal an RT; all three forms parse.
        for soo in ["65000:1", "10.0.0.1:7", "4200000000:9"] {
            let mut ok = cfg.clone();
            ok.routing_tables[1].vpn.site_of_origin = Some(soo.to_string());
            ok.validate_with(&ok).unwrap();
        }
        for l in [16, 1_048_575] {
            let mut ok = cfg.clone();
            ok.routing_tables[1].vpn.label = Some(l);
            ok.validate_with(&ok).unwrap();
        }

        // The table's own instance can't be its underlay.
        let mut own = cfg.clone();
        own.routing_tables[0].vpn = vpn();
        own.routing_tables.pop();
        assert!(own.validate_with(&own).is_err());

        // Label / RD collisions with another table (RD compared as bytes).
        let other = |rd: &str, label: u32| {
            let mut t = red(RoutingTableVpn {
                rd: Some(rd.to_string()),
                label: Some(label),
                ..vpn()
            });
            t.name = "blue".to_string();
            t
        };
        for (rd, label) in [("65000:2", 100), ("65000:1", 101)] {
            let mut bad = cfg.clone();
            bad.routing_tables.push(other(rd, label));
            assert!(bad.validate_with(&bad).is_err(), "{rd} {label}");
        }
        let mut fine = cfg.clone();
        fine.routing_tables.push(other("65000:2", 101));
        fine.validate_with(&fine).unwrap();

        // Same RD as another table's evpn.rd collides; as its own does not.
        let mut with_evpn = fine.clone();
        with_evpn.routing_tables[0].evpn.rd = Some("65000:2".to_string());
        assert!(with_evpn.validate_with(&with_evpn).is_err());
        let mut same = cfg.clone();
        same.routing_tables[1].evpn = RoutingTableEvpn {
            rd: Some("65000:1".to_string()),
            ..evpn()
        };
        same.validate_with(&same).unwrap();
    }

    #[test]
    fn vpn_postcard_round_trip() {
        let v = vpn();
        let bytes = postcard::to_allocvec(&v).unwrap();
        assert_eq!(postcard::from_bytes::<RoutingTableVpn>(&bytes).unwrap(), v);
    }

    #[test]
    fn redistribute_with_builtin_policy_names_passes() {
        for name in [nos_rpl::ACCEPT_ALL_NAME, nos_rpl::DENY_ALL_NAME] {
            let mut rt = table("rt1", Some("r1"), Some("sri1"));
            rt.redistribute = vec![Redistribute {
                policy: Some(name.to_string()),
                ..redistribute()
            }];
            let cfg = config_with_policy(rt, vec![]);
            cfg.validate_with(&cfg).unwrap();
        }
    }
}
