//! VRF export (RFC 4364 section 4.3.2, #580): this table's `vpn` config
//! resolved (`VrfExport`) and which of its best routes are exported as VPN
//! routes (`originated`). Pure; the label comes from
//! `driver::table_registry::ensure_label`, the push is `vpn_client.rs`'s.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use nos_proto::evpn_id::{parse_rd, parse_rt, parse_soo};
use nos_proto::{Config, IpNet, VpnPrefix};

use crate::rib::{RibEntry, RouteSource};

/// One table's resolved `RoutingTable.vpn`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfExport {
    pub rd: [u8; 8],
    /// Export Route Targets as extended communities.
    pub export: Vec<u64>,
    /// The table's Site of Origin (RFC 4364 section 7), attached beside the RTs.
    pub soo: Option<u64>,
    /// The underlay instance, `vpn.bgp_instance` (never `table.bgp_instance`).
    pub bgp_instance: String,
    /// That instance's routing table: where MPLS arrives and leaves.
    pub underlay: Option<String>,
    pub label: u32,
}

/// What `table` needs before it can export: `None` without a `vpn.rd` and
/// `vpn.bgp_instance` (commit validation guarantees a parsable RD). The
/// explicit `vpn.label` wins; otherwise `allocate` is asked, with every
/// explicit label of the config to stay clear of. `Err` is the allocator's.
pub fn resolve<E>(
    cfg: &Config,
    table: &str,
    allocate: impl FnOnce(&HashSet<u32>) -> Result<u32, E>,
) -> Result<Option<VrfExport>, E> {
    let Some(v) = cfg
        .routing_tables
        .iter()
        .find(|t| t.name == table)
        .map(|t| &t.vpn)
    else {
        return Ok(None);
    };
    let (Some(rd), Some(bgp_instance)) = (v.rd.as_deref().and_then(parse_rd), &v.bgp_instance)
    else {
        return Ok(None);
    };
    let label = if let Some(l) = v.label {
        l
    } else {
        let reserved = cfg
            .routing_tables
            .iter()
            .filter_map(|t| t.vpn.label)
            .collect();
        allocate(&reserved)?
    };
    Ok(Some(VrfExport {
        rd,
        export: v
            .route_targets_export
            .iter()
            .filter_map(|r| parse_rt(r))
            .collect(),
        bgp_instance: bgp_instance.clone(),
        underlay: cfg
            .bgp_instances
            .iter()
            .find(|i| &i.name == bgp_instance)
            .and_then(|i| i.routing_table.clone()),
        label,
        soo: v.site_of_origin.as_deref().and_then(parse_soo),
    }))
}

/// One VPN route per best route of the table, except the loop guard's
/// `Vpn` (imported) ones and `Evpn` ones (no EVPN/VPN stitching): when the
/// best route of a prefix is imported, nothing is exported for it.
// ponytail: no RPL policy here; `nos-bgpd`'s export policy edits the RTs/SoO after.
pub fn originated<S: BuildHasher>(
    best: &HashMap<IpNet, RibEntry, S>,
    vrf: &VrfExport,
) -> Vec<VpnPrefix> {
    best.values()
        .filter(|e| !matches!(e.source, RouteSource::Vpn | RouteSource::Evpn))
        .map(|e| VpnPrefix {
            rd: vrf.rd,
            prefix: e.prefix,
            labels: vec![vrf.label],
            ext_communities: vrf.export.iter().copied().chain(vrf.soo).collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::{RoutingTable, RoutingTableVpn};

    fn cfg(label: Option<u32>, rd: Option<&str>) -> Config {
        Config {
            routing_tables: vec![
                RoutingTable {
                    name: "red".into(),
                    vpn: RoutingTableVpn {
                        rd: rd.map(Into::into),
                        route_targets_import: vec![],
                        route_targets_export: vec!["65000:1".into(), "junk".into()],
                        bgp_instance: Some("core".into()),
                        label,
                        site_of_origin: Some("65001:77".into()),
                    },
                    ..RoutingTable::default()
                },
                RoutingTable {
                    name: "blue".into(),
                    vpn: RoutingTableVpn {
                        label: Some(1000),
                        ..RoutingTableVpn::default()
                    },
                    ..RoutingTable::default()
                },
            ],
            ..Config::default()
        }
    }

    type R = Result<Option<VrfExport>, ()>;

    #[test]
    fn resolve_uses_the_explicit_label_or_allocates_clear_of_every_explicit_one() {
        let got: R = resolve(&cfg(Some(77), Some("65000:1")), "red", |_| panic!());
        let got = got.unwrap().unwrap();
        assert_eq!(got.label, 77);
        assert_eq!(got.rd, parse_rd("65000:1").unwrap());
        assert_eq!(got.export, vec![parse_rt("65000:1").unwrap()]);
        assert_eq!(got.soo, parse_soo("65001:77"));
        assert_eq!(got.bgp_instance, "core");
        assert_eq!(got.underlay, None, "no such instance in the config");
        let got: R = resolve(&cfg(None, Some("65000:1")), "red", |reserved| {
            assert!(reserved.contains(&1000));
            Ok(1001)
        });
        assert_eq!(got.unwrap().unwrap().label, 1001);
        assert_eq!(
            resolve(&cfg(None, Some("65000:1")), "red", |_| Err(())),
            Err(())
        );
    }

    #[test]
    fn resolve_is_idle_without_rd_instance_or_table() {
        let none: R = resolve(&cfg(None, None), "red", |_| panic!());
        assert_eq!(none, Ok(None));
        let none: R = resolve(&cfg(None, Some("65000:1")), "blue", |_| panic!());
        assert_eq!(none, Ok(None), "no rd, no bgp instance");
        let none: R = resolve(&cfg(None, Some("65000:1")), "green", |_| panic!());
        assert_eq!(none, Ok(None));
    }

    #[test]
    fn originated_skips_imported_and_evpn_routes() {
        let entry = |p: &str, source| RibEntry {
            prefix: p.parse().unwrap(),
            next_hops: vec![("10.1.0.1".parse().unwrap(), None).into()],
            source,
            backup: None,
            backup_interface_id: None,
            backup_tunnel: false,
            distance: None,
            tag: None,
            interface: None,
        };
        let best: HashMap<IpNet, RibEntry> = [
            entry("10.1.0.0/24", RouteSource::Connected),
            entry("10.2.0.0/24", RouteSource::Static),
            entry("10.3.0.0/24", RouteSource::Bgp),
            entry("10.4.0.0/24", RouteSource::Ospf),
            entry("10.5.0.0/24", RouteSource::Vpn),
            entry("10.6.0.0/24", RouteSource::Evpn),
        ]
        .into_iter()
        .map(|e| (e.prefix, e))
        .collect();
        let vrf = VrfExport {
            rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
            export: vec![7],
            soo: parse_soo("65001:77"),
            bgp_instance: "core".into(),
            underlay: None,
            label: 1000,
        };
        let mut out = originated(&best, &vrf);
        out.sort_by_key(|r| r.prefix);
        let prefixes: Vec<String> = out.iter().map(|r| r.prefix.to_string()).collect();
        assert_eq!(
            prefixes,
            ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24"]
        );
        assert!(out.iter().all(|r| r.rd == vrf.rd
            && r.labels == [1000]
            && r.ext_communities == [7, parse_soo("65001:77").unwrap()]));
        let plain = VrfExport { soo: None, ..vrf };
        assert!(originated(&best, &plain)
            .iter()
            .all(|r| r.ext_communities == [7]));
    }
}
