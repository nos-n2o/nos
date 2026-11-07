//! The RIB side of BMP Route Monitoring (#864): the post-policy tap gate and
//! the read access the station task's initial dump needs. The tap itself sits
//! at the Adj-RIB-In mutation sites (`learn_prefix`, `remove_path`, the
//! soft-reconfiguration `settle`); this file only gates and reads.

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use nos_proto::AddressFamily;

use super::{BgpRib, RibRoute};
use crate::bmp::Hub;

/// The hub, when some station wants the post-policy stream: the one check a
/// tap site makes (an atomic load), so an unmonitored RIB does no work.
pub(super) fn tap(bmp: Option<&Arc<Hub>>) -> Option<&Hub> {
    bmp.map(|h| &**h).filter(|h| h.post_enabled())
}

impl BgpRib {
    /// Attaches the BMP hub whose post-policy stream this RIB feeds.
    pub fn set_bmp(&mut self, hub: Arc<Hub>) {
        self.bmp = Some(hub);
    }

    /// Prefix keys a station dump walks: the stored Adj-RIB-In (post-policy)
    /// or the retained pre-policy routes.
    pub fn bmp_keys(&self, peer: IpAddr, post: bool) -> Vec<IpNet> {
        self.bmp_table(peer, post)
            .map(|t| t.keys().copied().collect())
            .unwrap_or_default()
    }

    fn bmp_table(&self, peer: IpAddr, post: bool) -> Option<&super::adj_in::PeerTable> {
        if post {
            self.adj_rib_in.get(&peer)
        } else {
            self.retained.tables.get(&peer)
        }
    }

    /// The current paths of `prefixes` (one with an id per ADD-PATH path); a
    /// prefix withdrawn since the key snapshot yields nothing.
    pub fn bmp_paths(
        &self,
        peer: IpAddr,
        post: bool,
        prefixes: &[IpNet],
    ) -> Vec<(IpNet, u32, RibRoute)> {
        let Some(table) = self.bmp_table(peer, post) else {
            return Vec::new();
        };
        prefixes
            .iter()
            .filter_map(|p| table.get(p).map(|paths| (p, paths)))
            .flat_map(|(p, paths)| paths.iter().map(move |(id, r)| (*p, *id, r.clone())))
            .collect()
    }

    /// The unicast AFIs `peer` negotiated: one End-of-RIB each.
    pub fn bmp_families(&self, peer: IpAddr) -> Vec<u16> {
        let Some(o) = self.peer_outboxes.get(&peer) else {
            return Vec::new();
        };
        [
            (AddressFamily::Ipv4Unicast, crate::message::AFI_IPV4),
            (AddressFamily::Ipv6Unicast, crate::message::AFI_IPV6),
        ]
        .into_iter()
        .filter(|(f, _)| o.negotiated_afs.contains(f))
        .map(|(_, afi)| afi)
        .collect()
    }
}
