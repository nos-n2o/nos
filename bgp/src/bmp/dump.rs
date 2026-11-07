//! The initial Adj-RIB-In dump of a freshly connected station (#864): per
//! Established peer and wanted stream, the stored routes as Route Monitoring
//! (post-policy from `adj_rib_in`, pre-policy from the soft-reconfiguration
//! retention), then a per-family End-of-RIB.
//!
//! Chunked, never one pass under the RIB lock: a key snapshot, then
//! `DUMP_CHUNK` prefixes per lock hold, re-reading the current paths of each
//! (a prefix withdrawn since is skipped). Between chunks the station queue is
//! drained, so an event older than a chunk is followed by the later event that
//! produced the chunk's state and the collector converges on the RIB.

use tokio::net::tcp::OwnedWriteHalf;
use tracing::{debug, info, warn};

use super::monitor::{afi_of, end_of_rib, rib_route_to_update, route_monitoring};
use super::DUMP_CHUNK;
use super::{drain, now, send, stream, Ended, Hub, PeerUpInfo, Scope, Shared, StationCfg};
use crate::rib::SharedRib;

/// Dumps every peer in `peers`; `Some` ends the session.
pub(super) async fn run(
    hub: &Hub,
    cfg: &StationCfg,
    shared: &Shared,
    wr: &mut OwnedWriteHalf,
    peers: &[PeerUpInfo],
    scope: &Scope,
) -> Option<Ended> {
    let rib = hub.rib()?;
    for info in peers {
        for post in [false, true] {
            if cfg.wants(post) {
                let ended = one_stream(hub, &rib, (cfg, shared, scope), wr, info, post).await;
                if ended.is_some() {
                    return ended;
                }
            }
        }
    }
    None
}

async fn one_stream(
    hub: &Hub,
    rib: &SharedRib,
    (cfg, shared, scope): (&StationCfg, &Shared, &Scope),
    wr: &mut OwnedWriteHalf,
    info: &PeerUpInfo,
    post: bool,
) -> Option<Ended> {
    let peer = info.peer;
    let (keys, families) = {
        let rib = rib.lock().await;
        let keys = (post || rib.soft_reconfig_enabled(peer)).then(|| rib.bmp_keys(peer, post));
        (keys, rib.bmp_families(peer))
    };
    let mut routes = 0usize;
    if let Some(keys) = keys {
        for chunk in keys.chunks(DUMP_CHUNK) {
            if !hub.session_alive(info) {
                debug!(station = %cfg.name, peer = %peer, "bmp dump aborted: the peer went down");
                return None;
            }
            let paths = rib.lock().await.bmp_paths(peer, post, chunk);
            for (prefix, id, route) in &paths {
                let add_path = info.add_path_afis.contains(&afi_of(*prefix));
                let update = rib_route_to_update(*prefix, *id, route, add_path);
                for f in route_monitoring(scope, info, post, &update, now()) {
                    if !send(wr, &f).await {
                        return Some(Ended::Lost);
                    }
                    routes += 1;
                }
            }
            if let Some(ended) = drain(wr, cfg, shared).await {
                return Some(ended);
            }
            tokio::task::yield_now().await;
        }
        info!(peer = %peer, stream = %stream(post), routes, station = %cfg.name, "bmp rib dump sent");
    } else {
        warn!(
            peer = %peer, reason = "soft-reconfiguration inbound is off", station = %cfg.name,
            "bmp pre-policy dump skipped"
        );
    }
    if !hub.session_alive(info) {
        return None;
    }
    for afi in families {
        if !send(wr, &end_of_rib(scope, info, post, afi, 1)).await {
            return Some(Ended::Lost);
        }
    }
    info!(peer = %peer, stream = %stream(post), station = %cfg.name, "bmp end-of-rib sent");
    None
}
