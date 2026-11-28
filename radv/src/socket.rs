//! The real-kernel half of a link: the raw socket, the select loop, the
//! sends. Only a privileged kernel exercises it (`nos-e2e radv`), so like the
//! other `socket.rs` files it is excluded from coverage; everything it decides
//! with lives, tested, in `link`, `packet` and `schedule`.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use nos_radv_socket::{is_link_down, RaSocket, ALL_NODES};
use tokio::sync::watch;
use tokio::time::sleep_until;
use tracing::{debug, info, warn};

use crate::link::{handle_rx, link_facts, needs_reopen, LinkConfig, LogBucket, Reopen};
use crate::link_client::LinkTable;
use crate::packet::{self, Ra, RaParams};
use crate::schedule::Schedule;

/// Retry for a send that found the link down or the link-local address still
/// tentative.
const RETRY: Duration = Duration::from_secs(1);
/// `MAX_FINAL_RTR_ADVERTISEMENTS`.
const FINAL_COUNT: u8 = 3;
/// Spacing of the final RAs. ponytail: 1 s, not the 3 s `MIN_DELAY_BETWEEN_RAS`,
/// so a removal finishes inside the reconcile stop grace; raise both together.
const FINAL_SPACING: Duration = Duration::from_secs(1);
const SYS_CLASS_NET: &str = "/sys/class/net";

/// What a send attempt came to.
enum Sent {
    Ok(Ra),
    /// Link down or no usable source address yet: retry soon.
    Retry,
    /// Cannot be built; retrying is pointless until the config changes.
    Unbuildable,
}

fn send_ra(socket: &RaSocket, cfg: &LinkConfig, final_ra: bool) -> Sent {
    let (lladdr, link_mtu) = link_facts(Path::new(SYS_CLASS_NET), &cfg.interface);
    let params = RaParams {
        profile: cfg.profile.clone(),
        lladdr,
        link_mtu,
        final_ra,
    };
    let pkt = match packet::build_ra(&params) {
        Ok(p) => p,
        Err(e) => {
            warn!(interface = %cfg.interface, error = %e, "cannot build router advertisement");
            return Sent::Unbuildable;
        }
    };
    match socket.send_to(ALL_NODES, &pkt) {
        Ok(()) => packet::parse_ra(&pkt).map_or(Sent::Retry, Sent::Ok),
        Err(e) => {
            // EADDRNOTAVAIL: link-local still tentative (DAD).
            if is_link_down(&e) || e.raw_os_error() == Some(99) {
                debug!(interface = %cfg.interface, error = %e, "router advertisement not sent");
            } else {
                warn!(interface = %cfg.interface, error = %e, "failed to send router advertisement");
            }
            Sent::Retry
        }
    }
}

fn log_sent(cfg: &LinkConfig, ra: &Ra, final_ra: bool, info_level: bool) {
    let (managed, other, lifetime, prefixes) =
        (ra.managed, ra.other, ra.router_lifetime, ra.prefixes.len());
    if final_ra {
        info!(interface = %cfg.interface, managed, other, lifetime, prefixes, "router advertisement final");
    } else if info_level {
        info!(interface = %cfg.interface, managed, other, lifetime, prefixes, "router advertisement sent");
    } else {
        debug!(interface = %cfg.interface, managed, other, lifetime, prefixes, "router advertisement sent");
    }
}

/// Applies [`needs_reopen`]; true when a fresh socket was opened (the caller
/// restarts the initial burst).
fn follow_link(
    interface: &str,
    table: &LinkTable,
    socket: &mut Option<RaSocket>,
    opened_epoch: &mut u64,
) -> bool {
    match needs_reopen(*opened_epoch, socket.is_some(), table, interface) {
        Reopen::Keep => false,
        Reopen::Close => {
            *socket = None;
            info!(interface = %interface, "radv socket closed, device gone");
            false
        }
        Reopen::Open => {
            *socket = None;
            let epoch = table.epoch(interface);
            match RaSocket::open(interface) {
                Ok(s) => {
                    *socket = Some(s);
                    *opened_epoch = epoch;
                    info!(interface = %interface, "radv socket reopened");
                    true
                }
                Err(e) => {
                    warn!(interface = %interface, error = %e, "radv socket reopen failed");
                    false
                }
            }
        }
    }
}

fn seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |d| u64::try_from(d.as_nanos()).unwrap_or(1))
        ^ u64::from(std::process::id()).rotate_left(32)
}

/// Runs one link until `stop` fires. `Err` only when the socket cannot be
/// opened; reconcile respawns a link that ended on its own.
pub async fn run(
    mut cfg_rx: watch::Receiver<LinkConfig>,
    mut stop: watch::Receiver<bool>,
    mut links: watch::Receiver<LinkTable>,
) -> io::Result<()> {
    let mut cfg = cfg_rx.borrow_and_update().clone();
    let mut opened_epoch = links.borrow().epoch(&cfg.interface);
    let mut socket = Some(RaSocket::open(&cfg.interface)?);
    let (min, max) = cfg.intervals();
    let now = Instant::now();
    let mut sched = Schedule::new(min, max, now, seed());
    let mut info_bucket = LogBucket::new(now);
    let mut warn_bucket = LogBucket::new(now);
    let mut own: Option<Ra> = None;
    // The first RA after (re)start and the one a config change triggers are
    // logged at `info` whatever the bucket says.
    let mut force_log = true;
    info!(interface = %cfg.interface, "radv link started");

    let result = loop {
        tokio::select! {
            _ = stop.changed() => break Ok(()),
            Ok(()) = cfg_rx.changed() => {
                cfg = cfg_rx.borrow_and_update().clone();
                let (min, max) = cfg.intervals();
                sched.reconfigure(min, max, Instant::now());
                force_log = true;
                info!(interface = %cfg.interface, "router advertisement settings changed");
            }
            Ok(()) = links.changed() => {
                let table = links.borrow_and_update().clone();
                if follow_link(&cfg.interface, &table, &mut socket, &mut opened_epoch) {
                    sched.restart(Instant::now());
                    force_log = true;
                }
            }
            () = sleep_until(tokio::time::Instant::from_std(sched.deadline())) => {
                let now = Instant::now();
                if socket.is_none() {
                    let table = links.borrow().clone();
                    if follow_link(&cfg.interface, &table, &mut socket, &mut opened_epoch) {
                        force_log = true;
                    }
                }
                let outcome = socket.as_ref().map_or(Sent::Retry, |s| send_ra(s, &cfg, false));
                match outcome {
                    Sent::Ok(ra) => {
                        let lvl = force_log || info_bucket.take(now);
                        force_log = false;
                        log_sent(&cfg, &ra, false, lvl);
                        own = Some(ra);
                        sched.on_sent(now);
                    }
                    Sent::Retry => sched.retry(now, RETRY),
                    Sent::Unbuildable => sched.retry(now, Duration::from_secs(u64::from(cfg.profile.max_interval))),
                }
            }
            rx = async {
                match &socket {
                    Some(s) => s.recv().await,
                    None => std::future::pending().await,
                }
            } => match rx {
                Ok(rx) => {
                    if handle_rx(&cfg, own.as_ref(), &rx, Instant::now(), &mut info_bucket, &mut warn_bucket) {
                        sched.on_rs(Instant::now());
                    }
                }
                Err(e) => {
                    // The device went away under the socket: `follow_link` reopens it.
                    debug!(interface = %cfg.interface, error = %e, "router advertisement receive failed");
                    socket = None;
                    sched.retry(Instant::now(), RETRY);
                }
            },
        }
    };

    // s6.2.5: tell hosts we stopped being a router.
    if let Some(socket) = &socket {
        for i in 0..FINAL_COUNT {
            if i > 0 {
                tokio::time::sleep(FINAL_SPACING).await;
            }
            if let Sent::Ok(ra) = send_ra(socket, &cfg, true) {
                log_sent(&cfg, &ra, true, true);
            }
        }
    }
    info!(interface = %cfg.interface, "radv link stopped");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::schema::RaProfile;
    use nos_proto::{InterfaceEvent as E, LinkState};

    #[test]
    fn follow_link_survives_a_failed_reopen() {
        let mut table = LinkTable::default();
        crate::link_client::apply(
            &mut table,
            E::LinkAdded(LinkState {
                name: "nos-no-such0".into(),
                ifindex: 3,
                admin_up: true,
                carrier: true,
                port_aggregate: None,
            }),
        );
        let mut socket = None;
        let mut epoch = 0;
        assert!(!follow_link(
            "nos-no-such0",
            &table,
            &mut socket,
            &mut epoch
        ));
        assert!(socket.is_none());
    }

    #[tokio::test]
    async fn run_fails_when_the_device_is_missing() {
        let cfg = LinkConfig {
            interface: "nos-no-such0".into(),
            profile: RaProfile {
                max_interval: 30,
                ..RaProfile::default()
            },
        };
        assert_eq!(
            cfg.intervals(),
            (Duration::from_secs(10), Duration::from_secs(30))
        );
        let (_c, cfg_rx) = watch::channel(cfg);
        let (_s, stop_rx) = watch::channel(false);
        let (_l, links_rx) = watch::channel(LinkTable::default());
        let e = run(cfg_rx, stop_rx, links_rx).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }
}
