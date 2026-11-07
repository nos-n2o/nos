use std::net::IpAddr;

use garde::Validate;
use serde::{Deserialize, Serialize};

use super::bgp_peer_group::{valid_shutdown, BgpShutdown};
use super::Config;
use nos_proto_derive::Cli;

use super::sugar;

/// Associates a remote address with a peer-group, by name — the bulk of
/// session config (remote-as, source-address, address-families) lives on
/// the referenced `BgpPeerGroup`, not here.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct BgpPeer {
    #[garde(custom(|addr, ctx: &Config| unique_remote_address(addr, ctx)))]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// Neighbor address; the key, unique across every BGP instance.
    pub remote_address: IpAddr,

    #[garde(custom(|name, ctx: &Config| peer_group_exists(name, ctx)))]
    #[cli(topic = BgpPeer)]
    /// Name of the `BgpPeerGroup` that supplies this peer's settings; must exist.
    pub peer_group: String,

    /// Overrides the peer-group's own `shutdown` — see `BgpShutdown`.
    #[garde(custom(|s: &Option<BgpShutdown>, _ctx: &Config| valid_shutdown(s.as_ref())))]
    #[cli(topic = BgpPeerShutdown, render = sugar::render_shutdown, sugar(word = "shutdown", with = sugar::shutdown, topic = BgpPeerShutdown))]
    pub shutdown: Option<BgpShutdown>,
}

/// The placeholder a new `BgpPeer` starts from (`edit` on a missing one).
impl Default for BgpPeer {
    fn default() -> Self {
        BgpPeer {
            remote_address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            peer_group: String::new(),
            shutdown: None,
        }
    }
}

/// Peer remote-addresses are unique across the whole config — see
/// `bgp_peer_group::unique_name` for why this is scoped globally rather
/// than per-instance.
fn unique_remote_address(addr: &IpAddr, ctx: &Config) -> garde::Result {
    let count = ctx
        .bgp_instances
        .iter()
        .flat_map(|i| &i.peers)
        .filter(|p| &p.remote_address == addr)
        .count();
    if count > 1 {
        return Err(garde::Error::new("must be unique"));
    }
    Ok(())
}

fn peer_group_exists(name: &str, ctx: &Config) -> garde::Result {
    let exists = ctx
        .bgp_instances
        .iter()
        .flat_map(|i| &i.peer_groups)
        .any(|g| g.name == name);
    if exists {
        Ok(())
    } else {
        Err(garde::Error::new("referenced peer-group does not exist"))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::schema::{BgpInstance, BgpPeerGroup, Config};

    use super::*;
    use crate::schema::bgp_peer_group::AddressFamily;

    fn instance(name: &str, groups: Vec<BgpPeerGroup>, peers: Vec<BgpPeer>) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: groups,
            peers,
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

    fn group(name: &str) -> BgpPeerGroup {
        BgpPeerGroup {
            bfd: None,
            name: name.to_string(),
            remote_as: 65001,
            source_address: None,
            address_families: vec![AddressFamily::Ipv4Unicast],
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
            mrai: None,
            route_refresh_stale_time: None,
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            route_reflector_client: false,
            route_server_client: false,
            import_policy: None,
            export_policy: None,
            evpn_import_policy: None,
            enforce_first_as: None,
            flowspec_validation: crate::schema::BgpFlowspecValidation::default(),
            flowspec_import_policy: None,
            flowspec_export_policy: None,
            shutdown: None,
            maximum_prefix: crate::schema::BgpMaximumPrefix::default(),
            announce_rpki_state: false,
            soft_reconfiguration_inbound: false,
            graceful_shutdown: false,
            graceful_shutdown_receive_disabled: false,
            blackhole: None,
            local_as: None,
            add_path: None,
            add_path_send_count: None,
            role: None,
            strict_mode: false,
        }
    }

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_peer_passes() {
        let peer = BgpPeer {
            remote_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_group: "pg1".to_string(),
            shutdown: None,
        };
        let cfg = config_with(vec![instance("r1", vec![group("pg1")], vec![peer])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn dangling_peer_group_reference_fails() {
        let peer = BgpPeer {
            remote_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_group: "does-not-exist".to_string(),
            shutdown: None,
        };
        let cfg = config_with(vec![instance("r1", vec![group("pg1")], vec![peer])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_remote_address_fails_across_different_instances() {
        let peer_a = BgpPeer {
            remote_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_group: "pg1".to_string(),
            shutdown: None,
        };
        let peer_b = BgpPeer {
            remote_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_group: "pg2".to_string(),
            shutdown: None,
        };
        let cfg = config_with(vec![
            instance("r1", vec![group("pg1")], vec![peer_a]),
            instance("r2", vec![group("pg2")], vec![peer_b]),
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    /// RFC 8950: a peer's own IP version is independent of the address
    /// families exchanged over its peer-group's session.
    #[test]
    fn ipv6_peer_referencing_ipv4_address_family_group_passes() {
        let peer = BgpPeer {
            remote_address: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
            peer_group: "pg1".to_string(),
            shutdown: None,
        };
        let cfg = config_with(vec![instance("r1", vec![group("pg1")], vec![peer])]);
        cfg.validate_with(&cfg).unwrap();
    }
}
