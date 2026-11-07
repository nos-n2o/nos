use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::validators::{
    ospf_profile_reference_valid, ospfv3_profile_reference_valid, routing_table_reference_valid,
    unique_addresses, unique_in,
};

use super::spanning_tree::{valid_bridge_priority, valid_timers};
use super::{Config, InterfaceAddress, SourceAddress};
use nos_proto_derive::Cli;

/// A named L2 broadcast domain. `SwitchingProfile` references it for L2
/// membership; `addresses`/`routing_table` independently make the domain's
/// own bridge device an SVI (switch virtual interface) — a routed L3
/// attachment point for the domain as a whole, the same flat shape as a
/// loopback `Interface`'s L3 config (no VLAN/tag concept applies to a
/// domain's own bridge, so there's nothing for per-tag addressing to buy
/// it). The bridge device and whatever interfaces are enslaved into it as L2
/// members are separate Linux links, so there is no conflict between this
/// and any member's own VRF assignment.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
pub struct BroadcastDomain {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_in(n, &ctx.broadcast_domains, |d| &d.name))
    )]
    #[cli(key)]
    /// Domain name, 1 to 64 characters (letters, digits, `_`, `-`), unique among broadcast domains.
    pub name: String,

    #[garde(custom(|addrs, _ctx: &Config| unique_addresses(addrs)))]
    #[cli(topic = BroadcastDomainAddress)]
    /// Addresses of the domain's bridge device (SVI); empty for a pure L2 domain.
    pub addresses: Vec<InterfaceAddress>,

    #[garde(custom(|rt: &Option<String>, ctx: &Config| routing_table_reference_valid(rt.as_ref(), ctx)))]
    #[cli(topic = BroadcastDomainRoutingTable)]
    /// Routing table (VRF) the bridge device joins, if any.
    pub routing_table: Option<String>,

    /// If set, names an `OspfProfile` this domain's own SVI joins OSPF
    /// under. Requires `routing_table` also set on this same domain — see
    /// `valid_broadcast_domains`.
    #[garde(custom(|p: &Option<String>, ctx: &Config| ospf_profile_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = InterfaceOspfProfile, words = "ospf")]
    pub ospf_profile: Option<String>,

    /// Same shape as `ospf_profile`, joining `OSPFv3` (RFC 5340) instead — see
    /// `Subinterface.ospfv3_profile`'s doc comment for why this is a
    /// separate field rather than a widened `ospf_profile`.
    #[garde(custom(|p: &Option<String>, ctx: &Config| ospfv3_profile_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = InterfaceOspfv3Profile, words = "ospfv3")]
    pub ospfv3_profile: Option<String>,

    /// EVPN/VXLAN: the domain's VXLAN Network Identifier. Setting it makes
    /// `nos-watchdogd` run a `nos-fdbd` for this domain. Everything below
    /// requires it — see `valid_broadcast_domains`.
    #[garde(custom(|v: &Option<u32>, _ctx: &Config| valid_vni(*v)))]
    #[cli(topic = BroadcastDomainVni)]
    pub vni: Option<u32>,

    /// EVPN Route Distinguisher, `asn:nn` or `a.b.c.d:nn`.
    #[garde(custom(|v: &Option<String>, _ctx: &Config| valid_rd(v.as_deref())))]
    #[cli(topic = BroadcastDomainRd)]
    pub rd: Option<String>,

    /// Route Targets a received EVPN route must carry (any one) to be
    /// installed into this domain's FDB.
    #[serde(default)]
    #[garde(custom(|v: &Vec<String>, _ctx: &Config| valid_rts(v)))]
    #[cli(topic = BroadcastDomainRouteTarget, words = "route-target import")]
    pub route_targets_import: Vec<String>,

    /// Route Targets attached to every EVPN route this domain originates.
    #[serde(default)]
    #[garde(custom(|v: &Vec<String>, _ctx: &Config| valid_rts(v)))]
    #[cli(topic = BroadcastDomainRouteTarget, words = "route-target export")]
    pub route_targets_export: Vec<String>,

    /// The VTEP address (VXLAN local endpoint), resolved at runtime by
    /// `nos-fdbd` over IPC to `nos-interfaced` — never here, like
    /// `BgpPeerGroup.source_address`. `Loopback` means the loopback of the
    /// routing table owning `mac_redistribute`'s BGP instance.
    #[garde(skip)]
    #[cli(topic = BroadcastDomainVtepSource)]
    pub vtep_source: Option<SourceAddress>,

    /// `redistribute from mac to bgp <instance>`: the BGP instance this
    /// domain's local MACs are originated into as EVPN Type-2 routes (and
    /// whose received EVPN routes are installed into the domain's FDB).
    #[garde(custom(|v: &Option<String>, ctx: &Config| bgp_instance_exists(v.as_ref(), ctx)))]
    #[cli(topic = BroadcastDomainMacRedistribute, words = "redistribute from mac to bgp", alias = "redistribute from mac", alias = "redistribute")]
    pub mac_redistribute: Option<String>,

    /// `redistribute from arp to bgp <instance>`: local ARP/ND neighbours on
    /// the domain's bridge are also originated as Type-2 routes carrying the
    /// IP. Must name the same instance as `mac_redistribute`.
    #[garde(custom(|v: &Option<String>, ctx: &Config| bgp_instance_exists(v.as_ref(), ctx)))]
    #[cli(topic = BroadcastDomainArpRedistribute, words = "redistribute from arp to bgp", alias = "redistribute from arp")]
    pub arp_redistribute: Option<String>,

    /// `redistribute from connected to bgp <instance>`: the domain's own
    /// (SVI) `addresses` are originated as Type-2 routes carrying the
    /// bridge's MAC. Must name the same instance as `mac_redistribute`.
    #[garde(custom(|v: &Option<String>, ctx: &Config| bgp_instance_exists(v.as_ref(), ctx)))]
    #[cli(topic = BroadcastDomainConnectedRedistribute, words = "redistribute from connected to bgp", alias = "redistribute from connected")]
    pub connected_redistribute: Option<String>,

    /// ARP/ND suppression: `nos-fdbd` sets `IFLA_BRPORT_NEIGH_SUPPRESS` on the
    /// domain's VXLAN bridge port, so the bridge answers an ARP request or
    /// IPv6 NS itself whenever it holds the target's binding (every remote
    /// Type-2 carrying an IP is installed as one) instead of flooding it
    /// over the fabric. Gratuitous ARP is then no longer flooded to the
    /// VXLAN port either. Off by default; requires a `vni`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BroadcastDomainNeighSuppress, words = "neigh-suppress")]
    pub neigh_suppress: bool,

    /// Ceiling on the remote MAC entries `nos-fdbd` installs for this domain
    /// from received EVPN routes; beyond it the lowest MAC addresses win.
    /// `None`: unlimited. Requires a `vni`.
    #[serde(default)]
    #[garde(range(min = 1))]
    #[cli(topic = BroadcastDomainMaxRemoteMacs, words = "max-remote-macs")]
    pub max_remote_macs: Option<u32>,

    /// The MST instance (`spanning-tree mst-instance`) this domain's VLAN
    /// belongs to under `mode mstp`. `None`: the CIST. Inert until `nos-stpd`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BroadcastDomainStpInstance, words = "stp-instance")]
    pub stp_instance: Option<u16>,

    /// Per-VLAN bridge priority under `mode rapid-pvst`; `None` inherits
    /// `spanning-tree priority`. A multiple of 4096.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BroadcastDomainStpPriority, words = "stp-priority")]
    pub stp_priority: Option<u16>,

    /// Per-VLAN timers under `mode rapid-pvst`; `None` inherits the global
    /// one. The 802.1Q 13.25 relations are checked on the effective set.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BroadcastDomainStpHelloTime, words = "stp-hello-time")]
    pub stp_hello_time: Option<u8>,
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BroadcastDomainStpMaxAge, words = "stp-max-age")]
    /// Max Age in seconds for this domain's bridge; `None` uses the spanning-tree default.
    pub stp_max_age: Option<u8>,
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BroadcastDomainStpForwardDelay, words = "stp-forward-delay")]
    /// Forward Delay in seconds for this domain's bridge; `None` uses the spanning-tree default.
    pub stp_forward_delay: Option<u8>,
}

fn valid_vni(vni: Option<u32>) -> garde::Result {
    match vni {
        Some(v) if !(1..=0x00ff_ffff).contains(&v) => {
            Err(garde::Error::new("vni must be between 1 and 16777215"))
        }
        _ => Ok(()),
    }
}

fn valid_rd(rd: Option<&str>) -> garde::Result {
    match rd {
        Some(r) if crate::evpn_id::parse_rd(r).is_none() => Err(garde::Error::new(
            "rd must be asn:nn or a.b.c.d:nn (nn fits 16 bits unless a 2-byte asn)",
        )),
        _ => Ok(()),
    }
}

fn valid_rts(rts: &[String]) -> garde::Result {
    match rts.iter().find(|r| crate::evpn_id::parse_rt(r).is_none()) {
        Some(_) => Err(garde::Error::new(
            "route-target must be asn:nn or a.b.c.d:nn",
        )),
        None => Ok(()),
    }
}

fn bgp_instance_exists(name: Option<&String>, ctx: &Config) -> garde::Result {
    match name {
        Some(n) if !ctx.bgp_instances.iter().any(|i| &i.name == n) => {
            Err(garde::Error::new("referenced bgp instance does not exist"))
        }
        _ => Ok(()),
    }
}

/// A domain's spanning-tree settings: its MST instance must exist, its
/// priority is a multiple of 4096, and its effective timers (its own, else
/// the global ones) obey 802.1Q 13.25.
fn valid_domain_stp(d: &BroadcastDomain, ctx: &Config) -> garde::Result {
    let g = &ctx.spanning_tree;
    if let Some(id) = d.stp_instance
        && !g.mst_instances.iter().any(|m| m.id == id)
    {
        return Err(garde::Error::new(format!(
            "broadcast domain {}: stp-instance {id} is not defined under spanning-tree",
            d.name
        )));
    }
    if let Some(p) = d.stp_priority {
        valid_bridge_priority(p, "stp-priority")?;
    }
    if d.stp_hello_time.is_some() || d.stp_max_age.is_some() || d.stp_forward_delay.is_some() {
        valid_timers(
            d.stp_hello_time.unwrap_or(g.hello_time),
            d.stp_max_age.unwrap_or(g.max_age),
            d.stp_forward_delay.unwrap_or(g.forward_delay),
            &format!("broadcast domain {}", d.name),
        )?;
    }
    Ok(())
}

/// `ospf_profile`/`ospfv3_profile`, if set, require `routing_table` also set
/// on the same domain — mirrors `interface::valid_addressing_split`'s
/// equivalent check. Wired one level up on `Config.broadcast_domains`
/// (alongside the field-level `dive`) since it needs to see a sibling field.
pub(crate) fn valid_broadcast_domains(domains: &[BroadcastDomain], ctx: &Config) -> garde::Result {
    for d in domains {
        symmetric_irb_instance(d, ctx)?;
        valid_domain_stp(d, ctx)?;
        if d.ospf_profile.is_some() && d.routing_table.is_none() {
            return Err(garde::Error::new(
                "ospf profile requires a routing-table on the same broadcast domain",
            ));
        }
        if d.ospfv3_profile.is_some() && d.routing_table.is_none() {
            return Err(garde::Error::new(
                "ospfv3 profile requires a routing-table on the same broadcast domain",
            ));
        }
        if d.vni.is_none()
            && (d.rd.is_some()
                || !d.route_targets_import.is_empty()
                || !d.route_targets_export.is_empty()
                || d.vtep_source.is_some()
                || d.mac_redistribute.is_some()
                || d.arp_redistribute.is_some()
                || d.connected_redistribute.is_some()
                || d.neigh_suppress
                || d.max_remote_macs.is_some())
        {
            return Err(garde::Error::new(
                "rd, route-targets, vtep-source, redistribute, neigh-suppress and max-remote-macs require a vni on the same broadcast domain",
            ));
        }
        if d.mac_redistribute.is_some() && (d.rd.is_none() || d.vtep_source.is_none()) {
            return Err(garde::Error::new(
                "redistribute mac requires an rd and a vtep-source on the same broadcast domain",
            ));
        }
        // One EVPN target per domain: fdbd originates everything into it.
        for extra in [&d.arp_redistribute, &d.connected_redistribute] {
            if extra.is_some() && extra != &d.mac_redistribute {
                return Err(garde::Error::new(
                    "redistribute arp/connected must name the same bgp instance as redistribute mac",
                ));
            }
        }
    }
    Ok(())
}

/// RFC 9135 symmetric IRB: an EVPN domain whose SVI is in an IP-VRF (a
/// routing table with an L3 VNI) sends that L3 VNI on its MAC+IP routes, so
/// the table must exchange it over the instance the domain redistributes into
/// — otherwise the remote IP-VRF never hears those routes.
fn symmetric_irb_instance(d: &BroadcastDomain, ctx: &Config) -> garde::Result {
    let (Some(_), Some(instance), Some(table)) = (d.vni, &d.mac_redistribute, &d.routing_table)
    else {
        return Ok(());
    };
    let Some(rt) = ctx
        .routing_tables
        .iter()
        .find(|rt| &rt.name == table && rt.evpn.l3_vni.is_some())
    else {
        return Ok(());
    };
    if rt.evpn.bgp_instance.as_ref() == Some(instance) {
        return Ok(());
    }
    Err(garde::Error::new(format!(
        "broadcast domain {} redistributes into bgp instance {instance}, but its svi's routing table {table} exchanges its l3 vni over {}: symmetric irb needs the same instance",
        d.name,
        rt.evpn.bgp_instance.as_deref().unwrap_or("no instance"),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::RoutingTable;

    fn domain(name: &str) -> BroadcastDomain {
        BroadcastDomain {
            ospfv3_profile: None,
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
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
        }
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

    fn config_with(domains: Vec<BroadcastDomain>, tables: Vec<RoutingTable>) -> Config {
        Config {
            broadcast_domains: domains,
            routing_tables: tables,
            ..Default::default()
        }
    }

    #[test]
    fn each_evpn_field_alone_requires_a_vni() {
        let cfg = Config::default();
        let set: [fn(&mut BroadcastDomain); 8] = [
            |d| d.rd = Some("65000:1".to_string()),
            |d| d.route_targets_import = vec!["65000:1".to_string()],
            |d| d.route_targets_export = vec!["65000:1".to_string()],
            |d| d.vtep_source = Some(SourceAddress::Loopback { label: None }),
            |d| d.mac_redistribute = Some("r1".to_string()),
            |d| d.arp_redistribute = Some("r1".to_string()),
            |d| d.connected_redistribute = Some("r1".to_string()),
            |d| d.neigh_suppress = true,
        ];
        for (i, f) in set.iter().enumerate() {
            let mut d = domain("bd1");
            f(&mut d);
            // The vni rule itself fires (not a later, differently-worded one).
            let err = valid_broadcast_domains(&[d.clone()], &cfg).unwrap_err();
            assert!(
                err.to_string().contains("require a vni"),
                "field {i}: {err}"
            );
        }
        // With a vni the non-redistribute fields stand alone.
        for f in [&set[0], &set[1], &set[2], &set[3], &set[7]] {
            let mut d = domain("bd1");
            d.vni = Some(100);
            f(&mut d);
            assert!(valid_broadcast_domains(&[d], &cfg).is_ok());
        }
        // `redistribute mac` needs an rd and a vtep-source; arp/connected the same target.
        let mut d = domain("bd1");
        d.vni = Some(100);
        d.mac_redistribute = Some("r1".to_string());
        assert!(valid_broadcast_domains(&[d.clone()], &cfg).is_err());
        d.rd = Some("65000:1".to_string());
        assert!(valid_broadcast_domains(&[d.clone()], &cfg).is_err());
        d.vtep_source = Some(SourceAddress::Loopback { label: None });
        assert!(valid_broadcast_domains(&[d.clone()], &cfg).is_ok());
        d.arp_redistribute = Some("r2".to_string());
        assert!(valid_broadcast_domains(&[d.clone()], &cfg).is_err());
        d.arp_redistribute = Some("r1".to_string());
        d.connected_redistribute = Some("r1".to_string());
        assert!(valid_broadcast_domains(&[d], &cfg).is_ok());
    }

    #[test]
    fn valid_domain_passes() {
        let cfg = config_with(vec![domain("bd1")], vec![]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![domain("bd1"), domain("bd1")], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn empty_name_fails() {
        let mut d = domain("bd1");
        d.name = String::new();
        let cfg = config_with(vec![d], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn valid_addresses_and_routing_table_pass() {
        let mut d = domain("bd1");
        d.addresses = vec![InterfaceAddress {
            address: "10.0.0.1/24".parse().unwrap(),
            label: None,
        }];
        d.routing_table = Some("rt1".to_string());
        let cfg = config_with(vec![d], vec![table("rt1")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_address_fails() {
        let mut d = domain("bd1");
        d.addresses = vec![
            InterfaceAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                label: None,
            },
            InterfaceAddress {
                address: "10.0.0.1/24".parse().unwrap(),
                label: None,
            },
        ];
        let cfg = config_with(vec![d], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn dangling_routing_table_reference_fails() {
        let mut d = domain("bd1");
        d.routing_table = Some("does-not-exist".to_string());
        let cfg = config_with(vec![d], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    fn config_with_ospf(domains: Vec<BroadcastDomain>, tables: Vec<RoutingTable>) -> Config {
        use crate::schema::{OspfArea, OspfInstance, OspfProfile};
        Config {
            broadcast_domains: domains,
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
    fn valid_ospf_profile_with_routing_table_passes() {
        let mut d = domain("bd1");
        d.routing_table = Some("rt1".to_string());
        d.ospf_profile = Some("p1".to_string());
        let cfg = config_with_ospf(vec![d], vec![table("rt1")]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dangling_ospf_profile_reference_fails() {
        let mut d = domain("bd1");
        d.routing_table = Some("rt1".to_string());
        d.ospf_profile = Some("does-not-exist".to_string());
        let cfg = config_with_ospf(vec![d], vec![table("rt1")]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ospf_profile_without_routing_table_fails() {
        let mut d = domain("bd1");
        d.ospf_profile = Some("p1".to_string());
        let cfg = config_with_ospf(vec![d], vec![]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    fn evpn_domain() -> BroadcastDomain {
        let mut d = domain("bd1");
        d.vni = Some(10100);
        d.rd = Some("65000:1".to_string());
        d.route_targets_import = vec!["65000:10100".to_string()];
        d.route_targets_export = vec!["65000:10100".to_string()];
        d.vtep_source = Some(SourceAddress::Loopback { label: None });
        d.mac_redistribute = Some("r1".to_string());
        d
    }

    fn config_with_instance(d: BroadcastDomain) -> Config {
        use crate::schema::BgpInstance;
        let mut cfg = config_with(vec![d], vec![]);
        cfg.bgp_instances = vec![BgpInstance {
            name: "r1".to_string(),
            router_id: "1.1.1.1".parse().unwrap(),
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
        }];
        cfg
    }

    #[test]
    fn evpn_domain_passes() {
        let cfg = config_with_instance(evpn_domain());
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn arp_and_connected_must_follow_mac_redistribute() {
        let mut d = evpn_domain();
        d.arp_redistribute = Some("r1".to_string());
        d.connected_redistribute = Some("r1".to_string());
        let cfg = config_with_instance(d.clone());
        cfg.validate_with(&cfg).unwrap();

        // Without `redistribute from mac` (or naming another instance) they are refused.
        for mutate in [
            (|d: &mut BroadcastDomain| d.mac_redistribute = None) as fn(&mut BroadcastDomain),
            |d| d.mac_redistribute = Some("r2".to_string()),
        ] {
            let mut bad = d.clone();
            mutate(&mut bad);
            let mut cfg = config_with_instance(bad);
            let mut second = cfg.bgp_instances[0].clone();
            second.name = "r2".to_string();
            cfg.bgp_instances.push(second);
            assert!(cfg.validate_with(&cfg).is_err());
        }
    }

    #[test]
    fn evpn_fields_without_vni_fail() {
        let mut d = evpn_domain();
        d.vni = None;
        let cfg = config_with_instance(d);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn neigh_suppress_requires_vni() {
        let mut d = evpn_domain();
        d.neigh_suppress = true;
        let cfg = config_with_instance(d.clone());
        cfg.validate_with(&cfg).unwrap();
        d.vni = None;
        d.rd = None;
        d.route_targets_import.clear();
        d.route_targets_export.clear();
        d.vtep_source = None;
        d.mac_redistribute = None;
        let cfg = config_with_instance(d);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn redistribute_without_rd_fails() {
        let mut d = evpn_domain();
        d.rd = None;
        let cfg = config_with_instance(d);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    /// `bd1` (redistributing into r1) with its SVI in `tenant`, an IP-VRF
    /// whose L3 VNI rides `tenant_instance`; r2 exists too.
    fn irb_config(tenant_instance: &str, l3_vni: Option<u32>) -> Config {
        let mut d = evpn_domain();
        d.routing_table = Some("tenant".to_string());
        let mut cfg = config_with_instance(d);
        let mut r2 = cfg.bgp_instances[0].clone();
        r2.name = "r2".to_string();
        cfg.bgp_instances.push(r2);
        let mut underlay = table("underlay");
        underlay.bgp_instance = Some("r1".to_string());
        let mut tenant = table("tenant");
        tenant.evpn = crate::schema::RoutingTableEvpn {
            l3_vni,
            rd: Some("65000:5000".to_string()),
            route_targets_import: vec!["65000:5000".to_string()],
            route_targets_export: vec!["65000:5000".to_string()],
            vtep_source: Some(SourceAddress::Loopback { label: None }),
            bgp_instance: Some(tenant_instance.to_string()),
        };
        cfg.routing_tables = vec![underlay, tenant];
        cfg
    }

    #[test]
    fn symmetric_irb_needs_the_domain_and_table_on_one_instance() {
        let cfg = irb_config("r1", Some(5000));
        cfg.validate_with(&cfg).unwrap();

        let cfg = irb_config("r2", Some(5000));
        let err = cfg.validate_with(&cfg).unwrap_err().to_string();
        assert!(
            err.contains("bd1") && err.contains("tenant") && err.contains("r2"),
            "{err}"
        );

        // No L3 VNI on the table: asymmetric, any instance.
        let mut cfg = irb_config("r2", None);
        cfg.routing_tables[1].evpn = crate::schema::RoutingTableEvpn::default();
        cfg.validate_with(&cfg).unwrap();

        // A domain without a vni (and so no EVPN) isn't concerned.
        let mut cfg = irb_config("r2", Some(5000));
        let d = &mut cfg.broadcast_domains[0];
        *d = BroadcastDomain {
            routing_table: d.routing_table.clone(),
            ..domain("bd1")
        };
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn bad_vni_rd_rt_and_dangling_instance_fail() {
        for mutate in [
            (|d: &mut BroadcastDomain| d.vni = Some(0)) as fn(&mut BroadcastDomain),
            |d| d.vni = Some(1 << 24),
            |d| d.rd = Some("junk".to_string()),
            |d| d.route_targets_import = vec!["65000".to_string()],
            |d| d.mac_redistribute = Some("nope".to_string()),
            |d| d.arp_redistribute = Some("nope".to_string()),
            |d| d.connected_redistribute = Some("nope".to_string()),
        ] {
            let mut d = evpn_domain();
            mutate(&mut d);
            let cfg = config_with_instance(d);
            assert!(cfg.validate_with(&cfg).is_err());
        }
    }

    #[test]
    fn domain_stp_settings_are_checked() {
        use crate::schema::MstInstance;
        let ok = |f: &dyn Fn(&mut BroadcastDomain), mst: bool| {
            let mut d = domain("bd1");
            f(&mut d);
            let mut cfg = config_with(vec![d], vec![]);
            if mst {
                cfg.spanning_tree.mst_instances = vec![MstInstance {
                    id: 5,
                    ..Default::default()
                }];
            }
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(ok(&|d| d.stp_instance = Some(5), true));
        assert!(!ok(&|d| d.stp_instance = Some(5), false));
        assert!(ok(&|d| d.stp_priority = Some(4096), false));
        assert!(!ok(&|d| d.stp_priority = Some(4000), false));
        // effective timers: own max-age 30 with the global forward-delay 15
        assert!(!ok(&|d| d.stp_max_age = Some(30), false));
        assert!(ok(
            &|d| {
                d.stp_max_age = Some(30);
                d.stp_forward_delay = Some(20);
            },
            false
        ));
        assert!(!ok(&|d| d.stp_hello_time = Some(10), false));
    }
}
