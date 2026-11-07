use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::schema::{BgpPeer, BgpShutdown, Config};

use super::bgp_instance::find_instance_mut;
use super::OpError;

/// An edit to a single `BgpPeer` (keyed by `remote_address`) within a given
/// BGP instance. Unlike `BgpPeerGroupOp`, there's no `Ensure`/`SetX` split —
/// a peer's only content is its association to a peer-group, so `Set` is a
/// single upsert. Applied without validation, matching every other `Op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpPeerOp {
    /// Creates the peer if missing, else repoints it to `peer_group`.
    Set {
        /// Name of the BGP instance the peer belongs to.
        instance: String,
        /// Address of the remote peer, which identifies it within the instance.
        remote_address: IpAddr,
        /// Name of the peer group the peer belongs to.
        peer_group: String,
    },
    /// Deletes the BGP peer and everything nested under it.
    Delete {
        /// Name of the BGP instance the peer belongs to.
        instance: String,
        /// Address of the remote peer, which identifies it within the instance.
        remote_address: IpAddr,
    },
    /// Administratively shuts this one peer, overriding its peer-group's own
    /// `shutdown` (see `BgpShutdown`). The peer must already exist.
    SetShutdown {
        /// Name of the BGP instance the peer belongs to.
        instance: String,
        /// Address of the remote peer, which identifies it within the instance.
        remote_address: IpAddr,
        /// Optional shutdown communication (RFC 8203) sent to the peer.
        message: Option<String>,
    },
    /// Clears the shutdown of the BGP peer so it reverts to the default.
    ClearShutdown {
        /// Name of the BGP instance the peer belongs to.
        instance: String,
        /// Address of the remote peer, which identifies it within the instance.
        remote_address: IpAddr,
    },
}

impl BgpPeerOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        match self {
            BgpPeerOp::Set {
                instance,
                remote_address,
                peer_group,
            } => {
                let inst = find_instance_mut(config, instance)?;
                match inst
                    .peers
                    .iter_mut()
                    .find(|p| &p.remote_address == remote_address)
                {
                    Some(peer) => peer.peer_group.clone_from(peer_group),
                    None => inst.peers.push(BgpPeer {
                        remote_address: *remote_address,
                        peer_group: peer_group.clone(),
                        shutdown: None,
                    }),
                }
                Ok(())
            }
            BgpPeerOp::SetShutdown {
                instance,
                remote_address,
                message,
            } => {
                find_peer_mut(config, instance, remote_address)?.shutdown = Some(BgpShutdown {
                    message: message.clone(),
                });
                Ok(())
            }
            BgpPeerOp::ClearShutdown {
                instance,
                remote_address,
            } => {
                find_peer_mut(config, instance, remote_address)?.shutdown = None;
                Ok(())
            }
            BgpPeerOp::Delete {
                instance,
                remote_address,
            } => {
                let inst = find_instance_mut(config, instance)?;
                let before = inst.peers.len();
                inst.peers.retain(|p| &p.remote_address != remote_address);
                if inst.peers.len() == before {
                    return Err(OpError::BgpPeerNotFound {
                        instance: instance.clone(),
                        remote_address: *remote_address,
                    });
                }
                Ok(())
            }
        }
    }
}

fn find_peer_mut<'a>(
    config: &'a mut Config,
    instance: &str,
    remote_address: &IpAddr,
) -> Result<&'a mut BgpPeer, OpError> {
    find_instance_mut(config, instance)?
        .peers
        .iter_mut()
        .find(|p| &p.remote_address == remote_address)
        .ok_or_else(|| OpError::BgpPeerNotFound {
            instance: instance.to_string(),
            remote_address: *remote_address,
        })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::schema::BgpInstance;

    use super::*;

    fn instance(name: &str, peers: Vec<BgpPeer>) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: Vec::new(),
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

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            ..Default::default()
        }
    }

    fn addr(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn set_creates_when_missing() {
        let mut cfg = config_with(vec![instance("r1", vec![])]);
        BgpPeerOp::Set {
            instance: "r1".to_string(),
            remote_address: addr(192, 0, 2, 1),
            peer_group: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peers.len(), 1);
        assert_eq!(cfg.bgp_instances[0].peers[0].peer_group, "pg1");
    }

    #[test]
    fn set_updates_existing() {
        let mut cfg = config_with(vec![instance(
            "r1",
            vec![BgpPeer {
                remote_address: addr(192, 0, 2, 1),
                peer_group: "pg1".to_string(),
                shutdown: None,
            }],
        )]);
        BgpPeerOp::Set {
            instance: "r1".to_string(),
            remote_address: addr(192, 0, 2, 1),
            peer_group: "pg2".to_string(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peers.len(), 1);
        assert_eq!(cfg.bgp_instances[0].peers[0].peer_group, "pg2");
    }

    #[test]
    fn set_missing_instance_errors() {
        let mut cfg = config_with(vec![]);
        let err = BgpPeerOp::Set {
            instance: "r1".to_string(),
            remote_address: addr(192, 0, 2, 1),
            peer_group: "pg1".to_string(),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(matches!(err, OpError::BgpInstanceNotFound(n) if n == "r1"));
    }

    #[test]
    fn delete_removes_existing() {
        let mut cfg = config_with(vec![instance(
            "r1",
            vec![BgpPeer {
                remote_address: addr(192, 0, 2, 1),
                peer_group: "pg1".to_string(),
                shutdown: None,
            }],
        )]);
        BgpPeerOp::Delete {
            instance: "r1".to_string(),
            remote_address: addr(192, 0, 2, 1),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.bgp_instances[0].peers, []);
    }

    #[test]
    fn delete_missing_peer_errors() {
        let mut cfg = config_with(vec![instance("r1", vec![])]);
        let err = BgpPeerOp::Delete {
            instance: "r1".to_string(),
            remote_address: addr(192, 0, 2, 1),
        }
        .apply(&mut cfg)
        .unwrap_err();
        assert!(
            matches!(err, OpError::BgpPeerNotFound { instance, remote_address } if instance == "r1" && remote_address == addr(192, 0, 2, 1))
        );
    }
}
