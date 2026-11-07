use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use ipnet::IpNet;

use crate::schema::{BgpAggregate, BgpGracefulRestart, BgpInstance, BmpStation, Config, RpkiCache};

use super::OpError;

/// An edit to a single named `BgpInstance` within a transaction's in-progress
/// config. Applied without validation — `garde` validation only runs at
/// commit time, matching the daemon's existing edit/commit split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpInstanceOp {
    /// Creates the instance with placeholder field values if it doesn't
    /// already exist by name; no-op if it does. Backs `edit bgp instance
    /// <name>`'s "create if missing, else navigate to it" semantics.
    Ensure {
        /// Name of the BGP instance this op targets.
        name: String,
    },
    /// Sets the AS number of the BGP instance to `asn`.
    SetAsn {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Autonomous system number (4 bytes, RFC 6793).
        asn: u32,
    },
    /// Sets the router ID of the BGP instance to `router_id`.
    SetRouterId {
        /// Name of the BGP instance this op targets.
        name: String,
        /// BGP identifier (RFC 4271 §4.2).
        router_id: Ipv4Addr,
    },
    /// Sets the cluster ID of the BGP instance to `cluster_id`.
    SetClusterId {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Route-reflector cluster ID (RFC 4456).
        cluster_id: Ipv4Addr,
    },
    /// Clears the cluster ID of the BGP instance so it reverts to the default.
    ClearClusterId {
        /// Name of the BGP instance this op targets.
        name: String,
    },
    /// Deletes the BGP instance and everything nested under it.
    Delete {
        /// Name of the BGP instance this op targets.
        name: String,
    },
    /// RFC 5065: makes the instance a confederation member.
    SetConfederationIdentifier {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Confederation identifier (RFC 5065) shown to external peers.
        identifier: u32,
    },
    /// Clears the confederation of the BGP instance so it reverts to the default.
    ClearConfederation {
        /// Name of the BGP instance this op targets.
        name: String,
    },
    /// Adds another member AS; no-op if already listed. Refused at commit
    /// until an identifier is set too.
    AddConfederationPeer {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Autonomous system number (4 bytes, RFC 6793).
        asn: u32,
    },
    /// Removes confederation peer `asn` from the BGP instance.
    RemoveConfederationPeer {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Autonomous system number (4 bytes, RFC 6793).
        asn: u32,
    },
    /// RFC 8210: adds an RPKI cache, or replaces the one with that address.
    SetRpkiCache {
        /// Name of the BGP instance this op targets.
        name: String,
        /// RPKI cache (RTR, RFC 8210) definition.
        cache: RpkiCache,
    },
    /// Removes RPKI cache `address` from the BGP instance.
    RemoveRpkiCache {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Address of the RPKI cache.
        address: IpAddr,
    },
    /// RFC 7854: adds a BMP station, or replaces the one with that name.
    SetBmpStation {
        /// Name of the BGP instance this op targets.
        name: String,
        /// BMP station definition.
        station: BmpStation,
    },
    /// Removes BMP station `station_name` from the BGP instance.
    RemoveBmpStation {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Name of the BMP station.
        station_name: String,
    },
    /// BGP multipath: how many equal paths' next hops to install.
    SetMaximumPaths {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Maximum number of equal-cost paths installed.
        maximum_paths: u8,
    },
    /// Clears the maximum paths of the BGP instance so it reverts to the default.
    ClearMaximumPaths {
        /// Name of the BGP instance this op targets.
        name: String,
    },
    /// RFC 4271 §9.2.2.2: adds an aggregate, or replaces the one with that
    /// prefix.
    SetAggregate {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Aggregate route definition.
        aggregate: BgpAggregate,
    },
    /// Removes aggregate `prefix` from the BGP instance.
    RemoveAggregate {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Aggregate prefix.
        prefix: IpNet,
    },
    /// RFC 4724 / RFC 8538: replaces the whole graceful-restart setting
    /// (`BgpGracefulRestart::default()` puts it back on with default timers).
    SetGracefulRestart {
        /// Name of the BGP instance this op targets.
        name: String,
        /// Graceful-restart parameters.
        graceful_restart: BgpGracefulRestart,
    },
}

impl BgpInstanceOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BgpInstanceOp::Ensure { name } => {
                if !config.bgp_instances.iter().any(|i| &i.name == name) {
                    config.bgp_instances.push(BgpInstance {
                        name: name.clone(),
                        router_id: Ipv4Addr::UNSPECIFIED,
                        asn: 0,
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
                    });
                }
                Ok(())
            }
            BgpInstanceOp::SetAsn { name, asn } => {
                find_instance_mut(config, name)?.asn = *asn;
                Ok(())
            }
            BgpInstanceOp::SetRouterId { name, router_id } => {
                find_instance_mut(config, name)?.router_id = *router_id;
                Ok(())
            }
            BgpInstanceOp::SetClusterId { name, cluster_id } => {
                find_instance_mut(config, name)?.cluster_id = Some(*cluster_id);
                Ok(())
            }
            BgpInstanceOp::ClearClusterId { name } => {
                find_instance_mut(config, name)?.cluster_id = None;
                Ok(())
            }
            BgpInstanceOp::SetMaximumPaths {
                name,
                maximum_paths,
            } => {
                find_instance_mut(config, name)?.maximum_paths = Some(*maximum_paths);
                Ok(())
            }
            BgpInstanceOp::ClearMaximumPaths { name } => {
                find_instance_mut(config, name)?.maximum_paths = None;
                Ok(())
            }
            BgpInstanceOp::SetConfederationIdentifier { name, identifier } => {
                find_instance_mut(config, name)?.confederation.identifier = Some(*identifier);
                Ok(())
            }
            BgpInstanceOp::ClearConfederation { name } => {
                find_instance_mut(config, name)?.confederation =
                    crate::schema::BgpConfederation::default();
                Ok(())
            }
            BgpInstanceOp::AddConfederationPeer { name, asn } => {
                let c = &mut find_instance_mut(config, name)?.confederation;
                if !c.peers.contains(asn) {
                    c.peers.push(*asn);
                }
                Ok(())
            }
            BgpInstanceOp::RemoveConfederationPeer { name, asn } => {
                find_instance_mut(config, name)?
                    .confederation
                    .peers
                    .retain(|p| p != asn);
                Ok(())
            }
            BgpInstanceOp::SetRpkiCache { name, cache } => {
                let caches = &mut find_instance_mut(config, name)?.rpki_caches;
                match caches.iter_mut().find(|c| c.address == cache.address) {
                    Some(c) => *c = cache.clone(),
                    None => caches.push(cache.clone()),
                }
                Ok(())
            }
            BgpInstanceOp::RemoveRpkiCache { name, address } => {
                find_instance_mut(config, name)?
                    .rpki_caches
                    .retain(|c| c.address != *address);
                Ok(())
            }
            BgpInstanceOp::SetBmpStation { name, station } => {
                let stations = &mut find_instance_mut(config, name)?.bmp_stations;
                match stations.iter_mut().find(|s| s.name == station.name) {
                    Some(s) => *s = station.clone(),
                    None => stations.push(station.clone()),
                }
                Ok(())
            }
            BgpInstanceOp::RemoveBmpStation { name, station_name } => {
                find_instance_mut(config, name)?
                    .bmp_stations
                    .retain(|s| s.name != *station_name);
                Ok(())
            }
            BgpInstanceOp::SetAggregate { name, aggregate } => {
                let aggregates = &mut find_instance_mut(config, name)?.aggregates;
                match aggregates.iter_mut().find(|a| a.prefix == aggregate.prefix) {
                    Some(a) => *a = aggregate.clone(),
                    None => aggregates.push(aggregate.clone()),
                }
                Ok(())
            }
            BgpInstanceOp::RemoveAggregate { name, prefix } => {
                find_instance_mut(config, name)?
                    .aggregates
                    .retain(|a| a.prefix != *prefix);
                Ok(())
            }
            BgpInstanceOp::SetGracefulRestart {
                name,
                graceful_restart,
            } => {
                find_instance_mut(config, name)?.graceful_restart = *graceful_restart;
                Ok(())
            }
            BgpInstanceOp::Delete { name } => {
                let before = config.bgp_instances.len();
                config.bgp_instances.retain(|i| &i.name != name);
                if config.bgp_instances.len() == before {
                    return Err(OpError::BgpInstanceNotFound(name.clone()));
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn find_instance_mut<'a>(
    config: &'a mut Config,
    name: &str,
) -> Result<&'a mut BgpInstance, OpError> {
    config
        .bgp_instances
        .iter_mut()
        .find(|i| i.name == name)
        .ok_or_else(|| OpError::BgpInstanceNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn,
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

    #[test]
    fn set_graceful_restart_replaces_and_default_clears() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        let off = BgpGracefulRestart {
            disabled: true,
            ..Default::default()
        };
        let op = |g| BgpInstanceOp::SetGracefulRestart {
            name: "r1".to_string(),
            graceful_restart: g,
        };
        op(off).apply(&mut cfg).unwrap();
        assert_eq!(cfg.bgp_instances[0].graceful_restart, off);
        op(BgpGracefulRestart::default()).apply(&mut cfg).unwrap();
        assert_eq!(
            cfg.bgp_instances[0].graceful_restart.enabled_restart_time(),
            Some(120)
        );
    }

    #[test]
    fn ensure_creates_placeholder_when_missing() {
        let mut cfg = Config::default();
        BgpInstanceOp::Ensure {
            name: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances.len(), 1);
        assert_eq!(cfg.bgp_instances[0].name, "r1");
        assert_eq!(cfg.bgp_instances[0].router_id, Ipv4Addr::UNSPECIFIED);
        assert_eq!(cfg.bgp_instances[0].asn, 0);
    }

    #[test]
    fn ensure_is_noop_when_present() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        BgpInstanceOp::Ensure {
            name: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances.len(), 1);
        assert_eq!(cfg.bgp_instances[0].asn, 65000);
    }

    #[test]
    fn set_asn_updates_existing() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        BgpInstanceOp::SetAsn {
            name: "r1".to_string(),
            asn: 65001,
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].asn, 65001);
    }

    #[test]
    fn set_asn_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = BgpInstanceOp::SetAsn {
            name: "r1".to_string(),
            asn: 65001,
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpInstanceNotFound(n) if n == "r1"));
    }

    #[test]
    fn set_router_id_updates_existing() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        BgpInstanceOp::SetRouterId {
            name: "r1".to_string(),
            router_id: Ipv4Addr::new(10, 0, 0, 1),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].router_id, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn confederation_ops() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65101)],
            ..Default::default()
        };
        let name = "r1".to_string();
        for op in [
            BgpInstanceOp::AddConfederationPeer {
                name: name.clone(),
                asn: 65102,
            },
            BgpInstanceOp::AddConfederationPeer {
                name: name.clone(),
                asn: 65102,
            },
            BgpInstanceOp::SetConfederationIdentifier {
                name: name.clone(),
                identifier: 65100,
            },
            BgpInstanceOp::AddConfederationPeer {
                name: name.clone(),
                asn: 65103,
            },
            BgpInstanceOp::RemoveConfederationPeer {
                name: name.clone(),
                asn: 65103,
            },
        ] {
            op.apply(&mut cfg).unwrap();
        }
        assert_eq!(
            cfg.bgp_instances[0].confederation,
            crate::schema::BgpConfederation {
                identifier: Some(65100),
                peers: vec![65102],
            }
        );
        BgpInstanceOp::ClearConfederation { name }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].confederation,
            crate::schema::BgpConfederation::default()
        );
    }

    #[test]
    fn rpki_cache_ops_upsert_by_address() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        let cache = |port| RpkiCache {
            address: "192.0.2.9".parse().unwrap(),
            port,
            preference: 1,
            auth: None,
        };
        for port in [323, 8282] {
            BgpInstanceOp::SetRpkiCache {
                name: "r1".into(),
                cache: cache(port),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.bgp_instances[0].rpki_caches, vec![cache(8282)]);
        BgpInstanceOp::RemoveRpkiCache {
            name: "r1".into(),
            address: "192.0.2.9".parse().unwrap(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].rpki_caches, []);
    }

    #[test]
    fn bmp_station_ops_upsert_by_name() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        let station = |port| BmpStation {
            name: "s".into(),
            address: "192.0.2.9".parse().unwrap(),
            port,
            ..Default::default()
        };
        for port in [5000, 5001] {
            BgpInstanceOp::SetBmpStation {
                name: "r1".into(),
                station: station(port),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.bgp_instances[0].bmp_stations, vec![station(5001)]);
        BgpInstanceOp::RemoveBmpStation {
            name: "r1".into(),
            station_name: "s".into(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].bmp_stations, []);
    }

    #[test]
    fn aggregate_ops_upsert_by_prefix() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        let agg = |summary_only| BgpAggregate {
            prefix: "198.51.0.0/16".parse().unwrap(),
            as_set: false,
            summary_only,
        };
        for summary_only in [false, true] {
            BgpInstanceOp::SetAggregate {
                name: "r1".into(),
                aggregate: agg(summary_only),
            }
            .apply(&mut cfg)
            .unwrap();
        }
        assert_eq!(cfg.bgp_instances[0].aggregates, vec![agg(true)]);
        BgpInstanceOp::RemoveAggregate {
            name: "r1".into(),
            prefix: "198.51.0.0/16".parse().unwrap(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].aggregates, []);
    }

    #[test]
    fn set_and_clear_cluster_id() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000)],
            ..Default::default()
        };
        BgpInstanceOp::SetClusterId {
            name: "r1".to_string(),
            cluster_id: Ipv4Addr::new(1, 2, 3, 4),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(
            cfg.bgp_instances[0].cluster_id,
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );

        BgpInstanceOp::ClearClusterId {
            name: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].cluster_id, None);
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = Config {
            bgp_instances: vec![instance("r1", 65000), instance("r2", 65001)],
            ..Default::default()
        };
        BgpInstanceOp::Delete {
            name: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances.len(), 1);
        assert_eq!(cfg.bgp_instances[0].name, "r2");
    }

    #[test]
    fn delete_missing_instance_errors() {
        let mut cfg = Config::default();
        let err = BgpInstanceOp::Delete {
            name: "r1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpInstanceNotFound(n) if n == "r1"));
    }
}
