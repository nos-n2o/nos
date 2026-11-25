//! Per-peer message counters and session history (#1441). They live on the
//! `PeerSlot`, not in `PeerStatus` (which `reset_status_if_not_established`
//! clears at every session end): cumulative until a config change replaces
//! the slot.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

use nos_proto::{MessageCounts, NotificationInfo, ResetReason};
use tokio::time::Instant;

use crate::fsm::FsmOutcome;
use crate::message::BgpMessage;

#[derive(Default)]
struct Dir {
    open: AtomicU64,
    update: AtomicU64,
    notification: AtomicU64,
    keepalive: AtomicU64,
    route_refresh: AtomicU64,
}

/// A message's type, without its payload.
#[derive(Clone, Copy)]
pub enum MsgKind {
    Open,
    Update,
    Notification,
    Keepalive,
    RouteRefresh,
}

impl MsgKind {
    pub fn of(m: &BgpMessage) -> Self {
        // End-of-RIB is an UPDATE on the wire.
        match m {
            BgpMessage::Open(_) => Self::Open,
            BgpMessage::Update(_) | BgpMessage::EndOfRib { .. } => Self::Update,
            BgpMessage::Keepalive => Self::Keepalive,
            BgpMessage::Notification(_) => Self::Notification,
            BgpMessage::RouteRefresh(_) => Self::RouteRefresh,
        }
    }
}

impl Dir {
    fn count(&self, k: MsgKind) {
        let c = match k {
            MsgKind::Open => &self.open,
            MsgKind::Update => &self.update,
            MsgKind::Keepalive => &self.keepalive,
            MsgKind::Notification => &self.notification,
            MsgKind::RouteRefresh => &self.route_refresh,
        };
        c.fetch_add(1, Relaxed);
    }

    fn snapshot(&self) -> MessageCounts {
        MessageCounts {
            open: self.open.load(Relaxed),
            update: self.update.load(Relaxed),
            notification: self.notification.load(Relaxed),
            keepalive: self.keepalive.load(Relaxed),
            route_refresh: self.route_refresh.load(Relaxed),
        }
    }
}

type Notif = Mutex<Option<(u8, u8, Instant)>>;

/// What `to_peer_summary` reads.
pub struct CountersSnapshot {
    pub received: MessageCounts,
    pub sent: MessageCounts,
    pub last_sent: Option<NotificationInfo>,
    pub last_received: Option<NotificationInfo>,
    pub last_reset: Option<ResetReason>,
    pub flaps: u64,
}

#[derive(Default)]
pub struct PeerCounters {
    received: Dir,
    sent: Dir,
    flaps: AtomicU64,
    notif_sent: Notif,
    notif_received: Notif,
    reset: Mutex<Option<ResetReason>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn info(n: &Notif) -> Option<NotificationInfo> {
    lock(n).map(|(code, subcode, at)| NotificationInfo {
        code,
        subcode,
        seconds_ago: Instant::now().saturating_duration_since(at).as_secs(),
    })
}

impl PeerCounters {
    pub fn count_received(&self, m: &BgpMessage) {
        self.received.count(MsgKind::of(m));
    }

    pub fn count_sent(&self, k: MsgKind) {
        self.sent.count(k);
    }

    pub fn note_notification(&self, sent: bool, code: u8, subcode: u8) {
        let n = if sent {
            &self.notif_sent
        } else {
            &self.notif_received
        };
        *lock(n) = Some((code, subcode, Instant::now()));
    }

    /// An `Established` session ended.
    pub fn note_reset(&self, outcome: &FsmOutcome) {
        self.flaps.fetch_add(1, Relaxed);
        *lock(&self.reset) = Some(match outcome {
            FsmOutcome::TcpError => ResetReason::TcpError,
            FsmOutcome::PeerClosed => ResetReason::PeerClosed,
            FsmOutcome::NotificationSent { .. } => ResetReason::NotificationSent,
            FsmOutcome::NotificationReceived { .. } => ResetReason::NotificationReceived,
            FsmOutcome::HoldTimerExpired => ResetReason::HoldTimerExpired,
            FsmOutcome::CollisionLost => ResetReason::CollisionLost,
            FsmOutcome::GrReplaced => ResetReason::GrReplaced,
        });
    }

    pub fn snapshot(&self) -> CountersSnapshot {
        CountersSnapshot {
            received: self.received.snapshot(),
            sent: self.sent.snapshot(),
            last_sent: info(&self.notif_sent),
            last_received: info(&self.notif_received),
            last_reset: *lock(&self.reset),
            flaps: self.flaps.load(Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{NotificationMessage, RouteRefreshMessage};

    #[test]
    fn counts_every_type_and_end_of_rib_is_an_update() {
        let c = PeerCounters::default();
        c.count_sent(MsgKind::Keepalive);
        c.count_sent(MsgKind::of(&BgpMessage::EndOfRib { afi: 1, safi: 1 }));
        c.count_received(&BgpMessage::Notification(NotificationMessage {
            error_code: 6,
            error_subcode: 9,
            data: bytes::Bytes::new(),
        }));
        c.count_received(&BgpMessage::RouteRefresh(RouteRefreshMessage {
            afi: 1,
            subtype: 0,
            safi: 1,
        }));
        let s = c.snapshot();
        assert_eq!((s.sent.keepalive, s.sent.update), (1, 1));
        assert_eq!((s.received.notification, s.received.route_refresh), (1, 1));
        assert_eq!(s.received.open + s.sent.open, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn notification_age_and_reset() {
        let c = PeerCounters::default();
        assert!(c.snapshot().last_sent.is_none());
        c.note_notification(true, 6, 9);
        tokio::time::advance(std::time::Duration::from_secs(7)).await;
        c.note_reset(&FsmOutcome::HoldTimerExpired);
        let s = c.snapshot();
        let n = s.last_sent.unwrap();
        assert_eq!((n.code, n.subcode, n.seconds_ago), (6, 9, 7));
        assert!(s.last_received.is_none());
        assert_eq!(
            (s.flaps, s.last_reset),
            (1, Some(ResetReason::HoldTimerExpired))
        );
    }
}
