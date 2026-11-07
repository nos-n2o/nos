//! The RIB side of BMP Route Monitoring (#864): the post-policy tap gate and
//! the read access the station task's initial dump needs. The tap itself sits
//! at the Adj-RIB-In mutation sites (`learn_prefix`, `remove_path`, the
//! soft-reconfiguration `settle`); this file only gates and reads.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use nos_proto::AddressFamily;

use super::{BgpRib, FlowspecKey};
use crate::bmp::{monitor, Hub};
use crate::evpn::EvpnNlri;
use crate::message::UpdateMessage;
use crate::vpn::VpnKey;

/// The hub, when some station wants the post-policy stream: the one check a
/// tap site makes (an atomic load), so an unmonitored RIB does no work.
pub(super) fn tap(bmp: Option<&Arc<Hub>>) -> Option<&Hub> {
    bmp.map(|h| &**h).filter(|h| h.post_enabled())
}

/// One dumped item's identity: a snapshot of these is what a chunked dump
/// walks, re-reading the current value of each per chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BmpKey {
    Prefix(IpNet),
    Evpn(EvpnNlri),
    Flow(FlowspecKey),
    Vpn(VpnKey<IpNet>),
}

impl BgpRib {
    /// Attaches the BMP hub whose post-policy stream this RIB feeds.
    pub fn set_bmp(&mut self, hub: Arc<Hub>) {
        self.bmp = Some(hub);
    }

    /// Keys a station dump walks, every family: the stored Adj-RIB-In
    /// (post-policy) or the retained raw routes (pre-policy; EVPN's held
    /// routes are already raw, so its pre-policy set is held plus rejected).
    pub(crate) fn bmp_keys(&self, peer: IpAddr, post: bool) -> Vec<BmpKey> {
        let mut out: Vec<BmpKey> = Vec::new();
        let unicast = if post {
            self.adj_rib_in.get(&peer)
        } else {
            self.retained.tables.get(&peer)
        };
        out.extend(
            unicast
                .into_iter()
                .flat_map(|t| t.keys().map(|k| BmpKey::Prefix(*k))),
        );
        let held = self
            .evpn_adj_rib_in
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::keys);
        let rejected = self
            .retained
            .evpn
            .get(&peer)
            .into_iter()
            .flat_map(HashMap::keys);
        out.extend(
            held.chain(rejected.filter(|_| !post))
                .map(|k| BmpKey::Evpn(k.clone())),
        );
        let flow = if post {
            self.flowspec_adj_rib_in.get(&peer)
        } else {
            self.retained.flow.get(&peer)
        };
        out.extend(
            flow.into_iter()
                .flat_map(|t| t.keys().map(|k| BmpKey::Flow(k.clone()))),
        );
        let vpn = if post {
            self.vpn_adj_rib_in.get(&peer)
        } else {
            self.retained.vpn.get(&peer)
        };
        out.extend(
            vpn.into_iter()
                .flat_map(|t| t.keys().map(|k| BmpKey::Vpn(*k))),
        );
        out
    }

    /// The current value of each key as the UPDATE announcing it (one per
    /// ADD-PATH path; `add_path` is the session's set of AFIs carrying ids). A
    /// key withdrawn since the snapshot yields nothing.
    pub(crate) fn bmp_updates(
        &self,
        peer: IpAddr,
        post: bool,
        keys: &[BmpKey],
        add_path: &HashSet<u16>,
    ) -> Vec<UpdateMessage> {
        let mut out = Vec::new();
        for key in keys {
            match key {
                BmpKey::Prefix(p) => {
                    let table = if post {
                        self.adj_rib_in.get(&peer)
                    } else {
                        self.retained.tables.get(&peer)
                    };
                    let ap = add_path.contains(&monitor::afi_of(*p));
                    for (id, r) in table.and_then(|t| t.get(p)).into_iter().flatten() {
                        out.push(monitor::rib_route_to_update(*p, *id, r, ap));
                    }
                }
                BmpKey::Evpn(k) => {
                    let held = self.evpn_adj_rib_in.get(&peer).and_then(|t| t.get(k));
                    let rejected = (!post)
                        .then(|| self.retained.evpn.get(&peer).and_then(|t| t.get(k)))
                        .flatten();
                    out.extend(held.or(rejected).map(monitor::evpn_to_update));
                }
                BmpKey::Flow(k) => {
                    let table = if post {
                        self.flowspec_adj_rib_in.get(&peer)
                    } else {
                        self.retained.flow.get(&peer)
                    };
                    out.extend(
                        table
                            .and_then(|t| t.get(k))
                            .map(monitor::flowspec_to_update),
                    );
                }
                BmpKey::Vpn(k) => {
                    let table = if post {
                        self.vpn_adj_rib_in.get(&peer)
                    } else {
                        self.retained.vpn.get(&peer)
                    };
                    out.extend(
                        table
                            .and_then(|t| t.get(k))
                            .map(|r| monitor::vpn_to_update(k, r)),
                    );
                }
            }
        }
        out
    }

    /// The families `peer` negotiated, one End-of-RIB each (RT-Constraint is
    /// not monitored).
    pub(crate) fn bmp_families(&self, peer: IpAddr) -> Vec<(u16, u8)> {
        let Some(o) = self.peer_outboxes.get(&peer) else {
            return Vec::new();
        };
        AddressFamily::ALL
            .into_iter()
            .filter(|f| *f != AddressFamily::RtConstraint && o.negotiated_afs.contains(f))
            .map(crate::gr::afi_safi)
            .collect()
    }
}
