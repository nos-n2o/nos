use crate::schema::{Config, RedistributeTarget};

/// Recomputes every `BgpInstance.routing_table`/`redistribute_policy` from
/// the authoritative `RoutingTable.bgp_instance`/`redistribute` references.
/// Pure and synchronous, like `ops::apply`/`diff::diff_*` — call this on any
/// `Config` that is about to become "running" (see `nos-config`'s
/// `ConfigStore::new` and `commit_transaction`), never on a transaction's
/// in-progress config.
///
/// `RoutingTable.bgp_instance`'s own `garde` validation already guarantees
/// at most one table claims a given instance at commit time, so this never
/// has to arbitrate a conflict — it just clears every instance's mirror and
/// re-populates it from whichever single claim exists, if any.
pub fn sync_routing_table_refs(config: &mut Config) {
    for instance in &mut config.bgp_instances {
        instance.routing_table = None;
        instance.redistribute_policy = None;
    }
    for instance in &mut config.ospf_instances {
        instance.routing_table = None;
        instance.redistribute_policy = None;
        instance.redistribute_metric = None;
        instance.redistribute_metric_type = None;
    }
    for instance in &mut config.ospfv3_instances {
        instance.routing_table = None;
        instance.redistribute_policy = None;
    }
    for table in &config.routing_tables {
        if let Some(bgp_instance) = &table.bgp_instance
            && let Some(instance) = config
                .bgp_instances
                .iter_mut()
                .find(|i| &i.name == bgp_instance)
        {
            instance.routing_table = Some(table.name.clone());
            instance.redistribute_policy = table
                .redistribute
                .iter()
                .find(|r| r.to == RedistributeTarget::Bgp)
                .and_then(|r| r.policy.clone());
        }
        if let Some(ospf_instance) = &table.ospf_instance
            && let Some(instance) = config
                .ospf_instances
                .iter_mut()
                .find(|i| &i.name == ospf_instance)
        {
            instance.routing_table = Some(table.name.clone());
            instance.redistribute_policy = table
                .redistribute
                .iter()
                .find(|r| r.to == RedistributeTarget::Ospf)
                .and_then(|r| r.policy.clone());
            let ospf_rule = table
                .redistribute
                .iter()
                .find(|r| r.to == RedistributeTarget::Ospf);
            instance.redistribute_metric = ospf_rule.and_then(|r| r.metric);
            instance.redistribute_metric_type = ospf_rule.and_then(|r| r.metric_type);
        }
        if let Some(ospfv3_instance) = &table.ospfv3_instance
            && let Some(instance) = config
                .ospfv3_instances
                .iter_mut()
                .find(|i| &i.name == ospfv3_instance)
        {
            instance.routing_table = Some(table.name.clone());
            instance.redistribute_policy = table
                .redistribute
                .iter()
                .find(|r| r.to == RedistributeTarget::Ospfv3)
                .and_then(|r| r.policy.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::schema::{BgpInstance, OspfInstance, RoutingTable};

    fn instance(name: &str) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
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

    fn ospf_instance(name: &str) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            areas: Vec::new(),
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
            graceful_restart_helper_max_grace_period: None,
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

    fn table(name: &str, bgp_instance: Option<&str>) -> RoutingTable {
        RoutingTable {
            rest_api: None,
            evpn: crate::schema::RoutingTableEvpn::default(),
            vpn: crate::schema::RoutingTableVpn::default(),
            ospfv3_instance: None,
            name: name.to_string(),
            bgp_instance: bgp_instance.map(str::to_string),
            ospf_instance: None,
            static_routing_instance: None,
            redistribute: Vec::new(),
        }
    }

    fn table_with_ospf(name: &str, ospf_instance: Option<&str>) -> RoutingTable {
        RoutingTable {
            ospf_instance: ospf_instance.map(str::to_string),
            ..table(name, None)
        }
    }

    fn table_with_redistribute(
        name: &str,
        bgp_instance: Option<&str>,
        policy: Option<&str>,
    ) -> RoutingTable {
        use crate::schema::{Redistribute, RedistributeSource};

        RoutingTable {
            redistribute: vec![Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Bgp,
                policy: policy.map(str::to_string),
                metric: None,
                metric_type: None,
            }],
            ..table(name, bgp_instance)
        }
    }

    fn table_with_ospf_redistribute(
        name: &str,
        ospf_instance: Option<&str>,
        policy: Option<&str>,
    ) -> RoutingTable {
        use crate::schema::{Redistribute, RedistributeSource};

        RoutingTable {
            redistribute: vec![Redistribute {
                from: RedistributeSource::Static,
                to: RedistributeTarget::Ospf,
                policy: policy.map(str::to_string),
                metric: None,
                metric_type: None,
            }],
            ..table_with_ospf(name, ospf_instance)
        }
    }

    #[test]
    fn claimed_instance_gets_mirrored_reference() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1")],
            routing_tables: vec![table("rt1", Some("r1"))],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.bgp_instances[0].routing_table.as_deref(), Some("rt1"));
    }

    #[test]
    fn unclaimed_instance_stays_none() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1")],
            routing_tables: vec![table("rt1", None)],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.bgp_instances[0].routing_table, None);
    }

    #[test]
    fn stale_reference_is_cleared_when_claim_is_removed() {
        let mut cfg = Config {
            bgp_instances: vec![BgpInstance {
                routing_table: Some("stale".to_string()),
                ..instance("r1")
            }],
            routing_tables: vec![table("rt1", None)],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.bgp_instances[0].routing_table, None);
    }

    #[test]
    fn reassigned_claim_updates_the_mirror() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1")],
            routing_tables: vec![table("rt1", None), table("rt2", Some("r1"))],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.bgp_instances[0].routing_table.as_deref(), Some("rt2"));
    }

    #[test]
    fn redistribute_to_bgp_mirrors_policy_name() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1")],
            routing_tables: vec![table_with_redistribute("rt1", Some("r1"), Some("p1"))],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(
            cfg.bgp_instances[0].redistribute_policy.as_deref(),
            Some("p1")
        );
    }

    #[test]
    fn no_redistribute_rule_stays_none() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1")],
            routing_tables: vec![table("rt1", Some("r1"))],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.bgp_instances[0].redistribute_policy, None);
    }

    #[test]
    fn stale_redistribute_policy_is_cleared_when_claim_is_removed() {
        let mut cfg = Config {
            bgp_instances: vec![BgpInstance {
                redistribute_policy: Some("stale".to_string()),
                ..instance("r1")
            }],
            routing_tables: vec![table("rt1", None)],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.bgp_instances[0].redistribute_policy, None);
    }

    #[test]
    fn claimed_ospf_instance_gets_mirrored_reference() {
        let mut cfg = Config {
            ospf_instances: vec![ospf_instance("o1")],
            routing_tables: vec![table_with_ospf("rt1", Some("o1"))],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.ospf_instances[0].routing_table.as_deref(), Some("rt1"));
    }

    #[test]
    fn stale_ospf_reference_is_cleared_when_claim_is_removed() {
        let mut cfg = Config {
            ospf_instances: vec![OspfInstance {
                routing_table: Some("stale".to_string()),
                ..ospf_instance("o1")
            }],
            routing_tables: vec![table_with_ospf("rt1", None)],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.ospf_instances[0].routing_table, None);
    }

    #[test]
    fn redistribute_to_ospf_mirrors_policy_name() {
        let mut cfg = Config {
            ospf_instances: vec![ospf_instance("o1")],
            routing_tables: vec![table_with_ospf_redistribute("rt1", Some("o1"), Some("p1"))],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(
            cfg.ospf_instances[0].redistribute_policy.as_deref(),
            Some("p1")
        );
    }

    #[test]
    fn two_rules_mirror_into_their_own_instances() {
        let mut table = table_with_ospf_redistribute("rt1", Some("o1"), Some("po"));
        table.bgp_instance = Some("b1".to_string());
        table
            .redistribute
            .extend(table_with_redistribute("rt1", Some("b1"), Some("pb")).redistribute);
        let mut cfg = Config {
            bgp_instances: vec![instance("b1")],
            ospf_instances: vec![ospf_instance("o1")],
            routing_tables: vec![table],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(
            cfg.bgp_instances[0].redistribute_policy.as_deref(),
            Some("pb")
        );
        assert_eq!(
            cfg.ospf_instances[0].redistribute_policy.as_deref(),
            Some("po")
        );
    }

    #[test]
    fn redistribute_to_ospf_mirrors_metric_and_clears_it() {
        let mut table = table_with_ospf_redistribute("rt1", Some("o1"), None);
        table.redistribute[0].metric = Some(50);
        table.redistribute[0].metric_type = Some(2);
        let mut cfg = Config {
            ospf_instances: vec![ospf_instance("o1")],
            routing_tables: vec![table],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.ospf_instances[0].redistribute_metric, Some(50));
        assert_eq!(cfg.ospf_instances[0].redistribute_metric_type, Some(2));
        cfg.routing_tables[0].redistribute.clear();
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.ospf_instances[0].redistribute_metric, None);
        assert_eq!(cfg.ospf_instances[0].redistribute_metric_type, None);
    }

    #[test]
    fn stale_ospf_redistribute_policy_is_cleared_when_claim_is_removed() {
        let mut cfg = Config {
            ospf_instances: vec![OspfInstance {
                redistribute_policy: Some("stale".to_string()),
                ..ospf_instance("o1")
            }],
            routing_tables: vec![table_with_ospf("rt1", None)],
            ..Default::default()
        };
        sync_routing_table_refs(&mut cfg);
        assert_eq!(cfg.ospf_instances[0].redistribute_policy, None);
    }
}
