//! The initial Adj-RIB-In dump of a freshly connected station (#864): per
//! Established peer and wanted stream, the stored routes as Route Monitoring
//! (post-policy from `adj_rib_in`, pre-policy from the soft-reconfiguration
//! retention), then a per-family End-of-RIB (every negotiated family but RT-Constraint).
//!
//! Chunked, never one pass under the RIB lock: a key snapshot, then
//! `DUMP_CHUNK` prefixes per lock hold, re-reading the current paths of each
//! (a prefix withdrawn since is skipped). Between chunks the station queue is
//! drained, so an event older than a chunk is followed by the later event that
//! produced the chunk's state and the collector converges on the RIB.

use tokio::net::tcp::OwnedWriteHalf;
use tracing::{debug, info, warn};

use bytes::{Bytes, BytesMut};
use nos_proto::BmpMonitorOut;
use tokio_util::codec::Encoder;

use super::bgp_pdu;
use super::monitor::{encode_plain, end_of_rib, out_frames, route_monitoring};
use super::DUMP_CHUNK;
use super::{drain, now, send, send_as, stream, Ended, Hub, PeerUpInfo, Scope, Shared, StationCfg};
use crate::fsm::outbound_update_to_message;
use crate::message::{BgpCodec, BgpMessage};
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
        if cfg.monitor_out != BmpMonitorOut::None {
            let ended = out_dump(hub, &rib, (cfg, shared, scope), wr, info).await;
            if ended.is_some() {
                return ended;
            }
        }
    }
    None
}

/// The Adj-RIB-Out dump of one peer (RFC 8671): what it is sent now, rebuilt
/// from the RIB under one lock hold (O = 1), then an O = 1 End-of-RIB per
/// family of each stream. A live change racing the snapshot is queued behind
/// it and replays idempotently. ponytail: an MRAI-held change shows as
/// current state here and is sent again when released.
async fn out_dump(
    hub: &Hub,
    rib: &SharedRib,
    (cfg, shared, scope): (&StationCfg, &Shared, &Scope),
    wr: &mut OwnedWriteHalf,
    info: &PeerUpInfo,
) -> Option<Ended> {
    let (want_pre, want_post) = (cfg.monitor_out.wants(false), cfg.monitor_out.wants(true));
    let (snap, families) = {
        let mut rib = rib.lock().await;
        (
            rib.bmp_out_snapshot(info.peer, want_post, want_pre),
            rib.bmp_families(info.peer),
        )
    };
    let mut codec = BgpCodec {
        add_path_afis: snap.tx_afis,
        two_octet_as: info.two_octet_as,
        ..Default::default()
    };
    let mut frames: Vec<(Bytes, bool)> = Vec::new(); // (frame, post)
    let mut buf = BytesMut::new();
    for u in snap.post {
        let _ = codec.encode(outbound_update_to_message(u), &mut buf);
    }
    let a = info.two_octet_as;
    frames.extend(
        out_frames(scope, info, true, a, &buf, now())
            .into_iter()
            .map(|f| (f, true)),
    );
    let post_n = frames.len();
    let mut pre_buf = BytesMut::new();
    for u in &snap.pre {
        pre_buf.extend_from_slice(&encode_plain(u));
    }
    frames.extend(
        out_frames(scope, info, false, false, &pre_buf, now())
            .into_iter()
            .map(|f| (f, false)),
    );
    let pre_n = frames.len() - post_n;
    for (i, (f, _)) in frames.iter().enumerate() {
        if !hub.session_alive(info) {
            return None;
        }
        if !send(wr, shared, f).await {
            return Some(Ended::Lost);
        }
        if i % DUMP_CHUNK == DUMP_CHUNK - 1 {
            if let Some(ended) = drain(wr, cfg, shared).await {
                return Some(ended);
            }
            tokio::task::yield_now().await;
        }
    }
    for post in [false, true]
        .into_iter()
        .filter(|p| cfg.monitor_out.wants(*p))
    {
        for &(afi, safi) in &families {
            // Pre-policy Out is unicast only.
            if !post && safi != 1 {
                continue;
            }
            let pdu = bgp_pdu(BgpMessage::EndOfRib { afi, safi });
            let a = if post { a } else { false };
            for f in out_frames(scope, info, post, a, &pdu, now()) {
                if !send_as(wr, shared, &f, true).await {
                    return Some(Ended::Lost);
                }
            }
        }
    }
    info!(peer = %info.peer, pre = pre_n, post = post_n, station = %cfg.name, "bmp adj-rib-out dump sent");
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
            let updates = rib
                .lock()
                .await
                .bmp_updates(peer, post, chunk, &info.add_path_afis);
            for update in &updates {
                for f in route_monitoring(scope, info, post, update, now()) {
                    if !send(wr, shared, &f).await {
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
    for (afi, safi) in families {
        if !send_as(wr, shared, &end_of_rib(scope, info, post, afi, safi), true).await {
            return Some(Ended::Lost);
        }
    }
    info!(peer = %peer, stream = %stream(post), station = %cfg.name, "bmp end-of-rib sent");
    None
}
