//! BMP Statistics Reports (#864, RFC 7854 section 4.8): the codec and the
//! station's per-interval report.

use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::net::tcp::OwnedWriteHalf;
use tracing::info;

use super::{frame, lock, now, send, Hub, PeerUpInfo, Scope, Shared, StationCfg};

pub(super) const TYPE_STATS: u8 = 1;

/// One statistic of a Statistics Report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stat {
    /// A 32-bit counter (type, value).
    Counter(u16, u32),
    /// A 64-bit gauge (type, value).
    Gauge(u16, u64),
    /// A per-AFI/SAFI 64-bit gauge (type, afi, safi, value).
    AfiSafi(u16, u16, u8, u64),
}

/// A Statistics Report for one peer: per-peer header (L = 0), the count, then
/// each statistic as type, length, value.
pub fn stats_report(scope: &Scope, p: &PeerUpInfo, stats: &[Stat], ts: Duration) -> Bytes {
    let mut b = BytesMut::new();
    p.put_header(&mut b, scope, ts, (false, false, false)); // O = 0 (RFC 8671 section 6)
    b.put_u32(u32::try_from(stats.len()).unwrap_or(u32::MAX));
    for s in stats {
        match *s {
            Stat::Counter(t, v) => {
                b.put_u16(t);
                b.put_u16(4);
                b.put_u32(v);
            }
            Stat::Gauge(t, v) => {
                b.put_u16(t);
                b.put_u16(8);
                b.put_u64(v);
            }
            Stat::AfiSafi(t, afi, safi, v) => {
                b.put_u16(t);
                b.put_u16(11);
                b.put_u16(afi);
                b.put_u8(safi);
                b.put_u64(v);
            }
        }
    }
    frame(TYPE_STATS, &b)
}

/// Sends one report per Established peer, all read under a single RIB lock
/// hold. `false` when the collector stalled.
pub(super) async fn send_reports(
    hub: &Hub,
    cfg: &StationCfg,
    shared: &Shared,
    scope: &Scope,
    wr: &mut OwnedWriteHalf,
) -> bool {
    let Some(rib) = hub.rib() else {
        return true;
    };
    let peers: Vec<PeerUpInfo> = lock(&hub.state).registry.values().cloned().collect();
    let reports: Vec<(PeerUpInfo, Vec<Stat>)> = {
        let rib = rib.lock().await;
        let loc = rib.loc_totals();
        peers
            .into_iter()
            .map(|p| {
                let s = rib.bmp_stats(p.peer, loc, cfg.monitor_out);
                (p, s)
            })
            .collect()
    };
    for (p, s) in &reports {
        if !send(wr, shared, &stats_report(scope, p, s, now())).await {
            return false;
        }
        info!(peer = %p.peer, stats = s.len(), station = %cfg.name, "bmp statistics sent");
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_per_stat_kind() {
        let p = PeerUpInfo {
            peer: "192.0.2.1".parse().unwrap(),
            asn: 1,
            bgp_id: [1, 1, 1, 1].into(),
            two_octet_as: true,
            local: "192.0.2.2".parse().unwrap(),
            local_port: 179,
            remote_port: 1,
            sent_open: Bytes::new(),
            recv_open: Bytes::new(),
            time: Duration::ZERO,
            add_path_afis: std::collections::HashSet::default(),
        };
        let m = stats_report(
            &Scope::default(),
            &p,
            &[
                Stat::Counter(0, 7),
                Stat::Gauge(7, 1 << 33),
                Stat::AfiSafi(9, 2, 1, 5),
            ],
            Duration::from_secs(9),
        );
        assert_eq!(m[0], 3);
        assert_eq!(m[5], 1, "type Statistics Report");
        assert_eq!(
            u32::from_be_bytes(m[1..5].try_into().unwrap()) as usize,
            m.len()
        );
        assert_eq!(m[7] & 0x40, 0, "L flag clear");
        assert_eq!(m[7] & 0x10, 0, "O flag clear: Statistics are never Out");
        let b = &m[6 + 42..];
        assert_eq!(&b[..4], &3u32.to_be_bytes(), "count");
        assert_eq!(&b[4..12], &[0, 0, 0, 4, 0, 0, 0, 7], "counter");
        assert_eq!(&b[12..16], &[0, 7, 0, 8]);
        assert_eq!(&b[16..24], &(1u64 << 33).to_be_bytes(), "gauge");
        assert_eq!(&b[24..31], &[0, 9, 0, 11, 0, 2, 1]);
        assert_eq!(&b[31..], &5u64.to_be_bytes());
    }
}
