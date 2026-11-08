//! RFC 3623 graceful restart and RFC 6987 max-metric.
//! Moved verbatim out of `link.rs`.

use super::rx::next_crypto_seq;
use super::{
    info, lsa, packet, warn, Duration, GraceLsaBody, Instant, Ipv4Addr, LinkCommand, LinkConfig,
    LinkManager, LinkSocket, Lsa, LsaBody, LsaHeader, LsuPacket, MaxMetric, NeighborState,
    Ordering, StatusHandle, GRACE_SEND_WINDOW, MAX_METRIC_SHUTDOWN_HOLD_MAX,
};

pub(super) fn in_grace(status: &StatusHandle, neighbor_id: Ipv4Addr) -> bool {
    status
        .borrow()
        .neighbors
        .get(&neighbor_id)
        .is_some_and(|n| n.grace_deadline.is_some())
}

/// RFC 3623 helper side: a Grace-LSA from a `Full` neighbor on this link
/// starts (or, idempotently, refreshes) its grace period; a `MaxAge` one —
/// the restarting router flushing it — ends it. Matched on the advertising
/// router id, which is how neighbors are keyed here (the IP Interface
/// Address TLV only matters where neighbors are keyed by address).
///
/// ponytail: no RFC 3623 §3.2 (c) strict LSA checking — helping goes on
/// through a topology change. Add it if a real topology change during a
/// restart matters: with periodic full resend, "an LSA flooded to the
/// restarter changed" means any type 1-5 content change in this area from
/// anyone but the restarter.
pub(super) fn on_grace_lsa(
    cfg: &LinkConfig,
    status: &StatusHandle,
    header: &LsaHeader,
    body: GraceLsaBody,
) {
    let neighbor_id = header.advertising_router;
    let Some((state, deadline)) = status
        .borrow()
        .neighbors
        .get(&neighbor_id)
        .map(|n| (n.state, n.grace_deadline))
    else {
        return;
    };
    if header.age >= lsa::MAX_AGE {
        if deadline.is_some() {
            info!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf helper: grace-lsa flushed, exiting grace");
            status.send_modify(|s| {
                if let Some(n) = s.neighbors.get_mut(&neighbor_id) {
                    n.grace_deadline = None;
                }
            });
        }
        return;
    }
    if state != NeighborState::Full {
        warn!(link = %cfg.attach_point, neighbor = %neighbor_id, "ospf helper: ignoring grace-lsa from a neighbor that is not full");
        return;
    }
    if deadline.is_none() {
        info!(
            link = %cfg.attach_point, neighbor = %neighbor_id,
            grace_period = body.grace_period, restart_reason = body.restart_reason,
            "ospf helper: grace period entered"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(u64::from(body.grace_period));
    status.send_modify(|s| {
        if let Some(n) = s.neighbors.get_mut(&neighbor_id) {
            n.grace_deadline = Some(deadline);
        }
    });
}

/// Ends every grace period whose deadline has passed; the neighbor is then
/// subject to the ordinary inactivity timer again, restarted from now.
pub(super) fn expire_grace(cfg: &LinkConfig, status: &StatusHandle) {
    let now = Instant::now();
    let expired: Vec<Ipv4Addr> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, n)| n.grace_deadline.is_some_and(|d| d <= now))
        .map(|(id, _)| *id)
        .collect();
    for id in &expired {
        warn!(link = %cfg.attach_point, neighbor = %id, "ospf helper: grace period expired");
    }
    if !expired.is_empty() {
        status.send_modify(|s| {
            for id in &expired {
                if let Some(n) = s.neighbors.get_mut(id) {
                    n.grace_deadline = None;
                    n.last_heard = now;
                }
            }
        });
    }
}

/// RFC 3623's restarting side: one Grace-LSA (type 9, opaque type 3) unicast
/// to every `Full` neighbor on this link, just before the process exits.
/// Never installed locally.
pub(super) fn send_grace_lsas(
    socket: &LinkSocket,
    cfg: &LinkConfig,
    local_router_id: Ipv4Addr,
    status: &StatusHandle,
    grace_period: u32,
    next_seq: &mut u64,
) {
    let grace = Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
            lsa_type: lsa::LSA_TYPE_OPAQUE_LINK,
            link_state_id: lsa::GRACE_LINK_STATE_ID,
            advertising_router: local_router_id,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Grace(GraceLsaBody {
            grace_period,
            restart_reason: lsa::RESTART_REASON_SOFTWARE,
            interface_address: Some(cfg.local_addr),
        }),
    };
    let auth = cfg
        .auth
        .as_outgoing(next_crypto_seq(next_seq, &cfg.auth), cfg.local_addr);
    let payload = packet::encode_lsu(
        &LsuPacket {
            discarded: 0,
            last_error: None,
            router_id: local_router_id,
            area_id: cfg.area_id,
            lsas: vec![grace],
        },
        &auth,
    );
    let full: Vec<(Ipv4Addr, Ipv4Addr)> = status
        .borrow()
        .neighbors
        .iter()
        .filter(|(_, n)| n.state == NeighborState::Full)
        .map(|(id, n)| (*id, n.address))
        .collect();
    for (neighbor_id, address) in full {
        match socket.send_unicast(address, &payload) {
            Ok(()) => info!(
                link = %cfg.attach_point, neighbor = %neighbor_id, grace_period,
                "ospf graceful restart: grace-lsa sent"
            ),
            Err(e) => {
                warn!(link = %cfg.attach_point, neighbor = %neighbor_id, error = %e, "failed to send ospf grace-lsa");
            }
        }
    }
}

impl LinkManager {
    pub fn set_graceful_restart(&self, grace_period: Option<u16>) {
        self.grace_period
            .store(grace_period.unwrap_or(0), Ordering::Relaxed);
    }

    pub(super) fn max_metric_state(&self) -> std::sync::MutexGuard<'_, MaxMetric> {
        self.max_metric
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Set once, before the first `set_max_metric`, when this process is the
    /// respawn of a graceful restart (`boot::take_grace_marker`).
    pub fn set_after_graceful_restart(&self, after: bool) {
        self.max_metric_state().after_graceful_restart = after;
    }

    /// RFC 6987 knobs, every resync. The first call (the first config
    /// resolution after start) arms the on-startup period — skipped after a
    /// graceful restart; later calls never re-arm it (it takes effect on the
    /// next start), and `None` ends a running one.
    pub fn set_max_metric(
        &self,
        on_startup: Option<u32>,
        on_shutdown: Option<u8>,
        administrative: bool,
    ) {
        let mut mm = self.max_metric_state();
        mm.administrative = administrative;
        mm.on_shutdown = on_shutdown.unwrap_or(0);
        if !mm.armed {
            mm.armed = true;
            match on_startup {
                Some(_) if mm.after_graceful_restart => {
                    info!("ospf stub router on-startup skipped after graceful restart");
                }
                Some(secs) => {
                    mm.until = Some(Instant::now() + Duration::from_secs(u64::from(secs)));
                }
                None => {}
            }
        } else if on_startup.is_none() {
            mm.until = None;
        }
    }

    /// RFC 6987: whether this router advertises itself as a stub router
    /// (max-metric transit links) — administratively, or still inside its
    /// on-startup period — or as an RFC 8770 host router, whose transit
    /// links are always at max metric.
    pub fn max_metric_active(&self) -> bool {
        let mm = self.max_metric_state();
        mm.administrative
            || mm.until.is_some_and(|t| Instant::now() < t)
            || self.host_router.load(Ordering::Relaxed)
    }

    /// `max_metric_active`, logging a change (read once per origination tick).
    pub(super) fn max_metric_tick(&self) -> bool {
        let mut mm = self.max_metric_state();
        let starting = mm.until.is_some_and(|t| Instant::now() < t);
        let active = mm.administrative || starting;
        if active != mm.logged {
            mm.logged = active;
            let reason = if active && mm.administrative {
                "administrative"
            } else if active {
                "on-startup"
            } else if mm.until.take().is_some() {
                "expired"
            } else {
                "cleared"
            };
            info!(active, reason, "ospf stub router max-metric changed");
        }
        active
    }

    /// RFC 6987 on-shutdown: re-originates the Router-LSAs with max-metric
    /// transit links, kicks them out and holds `on_shutdown` seconds so
    /// neighbors move traffic away before the flush. Skipped when off, when
    /// max-metric is already active (neighbors already avoid us), and when
    /// `MinLSInterval` holds the Router-LSA back (it changed under 5s ago).
    pub(super) async fn max_metric_on_shutdown(&self) {
        let hold = self.max_metric_state().on_shutdown;
        if hold == 0 || self.max_metric_active() {
            return;
        }
        let Some(router_id) = *self.router_id.lock().await else {
            return;
        };
        if !self.originate_router_lsas_with(router_id, true).await {
            info!("ospf stub router on-shutdown skipped, router-lsa unchanged or changed too recently");
            return;
        }
        info!(
            active = true,
            reason = "on-shutdown",
            "ospf stub router max-metric changed"
        );
        self.flood_now().await;
        tokio::time::sleep(Duration::from_secs(u64::from(hold)).min(MAX_METRIC_SHUTDOWN_HOLD_MAX))
            .await;
    }

    /// The configured RFC 3623 grace period, seconds (0 = off).
    pub fn grace_period(&self) -> u16 {
        self.grace_period.load(Ordering::Relaxed)
    }

    /// RFC 3623: when graceful restart is configured, has every link send a
    /// Grace-LSA to its `Full` neighbors (twice) and waits for them to go
    /// out, then makes `shutdown` keep this router's LSAs. Called on a
    /// planned restart (SIGTERM) only, before `shutdown`.
    pub async fn announce_graceful_restart(&self) {
        let grace_period = self.grace_period.load(Ordering::Relaxed);
        if grace_period == 0 {
            return;
        }
        info!(
            grace_period,
            "ospf graceful restart: announcing grace period before shutdown"
        );
        self.restarting.store(true, Ordering::Relaxed);
        for _ in 0..2 {
            self.send_to_links(LinkCommand::Grace(u32::from(grace_period)))
                .await;
            tokio::time::sleep(GRACE_SEND_WINDOW).await;
        }
    }
}
