//! One advertising link: a raw socket, the RFC 4861 s6.2.4 schedule, RS
//! replies, foreign-RA checks (s6.1.2, s6.2.7) and the final lifetime-0 RAs
//! (s6.2.5). Mirrors `nos-lldp`'s `link.rs` shape.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use nos_proto::schema::RaProfile;
use nos_radv_socket::{is_link_down, RaSocket, ALL_NODES};
use tokio::sync::watch;
use tokio::time::sleep_until;
use tracing::{debug, info, warn};

use crate::link_client::{gate, Gate, LinkTable};
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
/// `info` logs per link back to back; one credit returns per `LOG_CREDIT_EVERY`.
const LOG_CREDIT_MAX: u8 = 5;
const LOG_CREDIT_EVERY: Duration = Duration::from_secs(10);
const SYS_CLASS_NET: &str = "/sys/class/net";

/// What a link task needs; reconcile compares it to decide between an
/// in-place update and a stop.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkConfig {
    /// Kernel device the socket binds to (`eth1`, `eth1.100`).
    pub interface: String,
    pub profile: RaProfile,
}

impl LinkConfig {
    fn intervals(&self) -> (Duration, Duration) {
        (
            Duration::from_secs(u64::from(self.profile.effective_min_interval())),
            Duration::from_secs(u64::from(self.profile.max_interval)),
        )
    }
}

/// Token bucket for per-link `info` logs, so a hostile segment cannot flood
/// `nos-logd`.
pub struct LogBucket {
    credit: u8,
    last: Instant,
}

impl LogBucket {
    pub fn new(now: Instant) -> Self {
        Self {
            credit: LOG_CREDIT_MAX,
            last: now,
        }
    }

    pub fn take(&mut self, now: Instant) -> bool {
        let n = now.saturating_duration_since(self.last).as_secs() / LOG_CREDIT_EVERY.as_secs();
        if n > 0 {
            self.credit = u8::try_from(n)
                .unwrap_or(u8::MAX)
                .saturating_add(self.credit)
                .min(LOG_CREDIT_MAX);
            self.last += LOG_CREDIT_EVERY * u32::try_from(n).unwrap_or(u32::MAX);
        }
        if self.credit == 0 {
            return false;
        }
        self.credit -= 1;
        true
    }
}

/// `aa:bb:cc:dd:ee:ff` -> bytes.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.trim().split(':');
    for b in &mut out {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn read_sys(sys: &Path, interface: &str, file: &str) -> Option<String> {
    std::fs::read_to_string(sys.join(interface).join(file)).ok()
}

/// Source link-layer address and MTU of the device, read per send so a change
/// is picked up.
pub fn link_facts(sys: &Path, interface: &str) -> (Option<[u8; 6]>, Option<u32>) {
    (
        read_sys(sys, interface, "address").and_then(|s| parse_mac(&s)),
        read_sys(sys, interface, "mtu").and_then(|s| s.trim().parse().ok()),
    )
}

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

/// What a link-table update means for one link's socket.
#[derive(Debug, PartialEq, Eq)]
enum Reopen {
    Keep,
    Close,
    Open,
}

fn needs_reopen(opened_epoch: u64, has_socket: bool, table: &LinkTable, name: &str) -> Reopen {
    if gate(table, name) == Gate::Down("absent") {
        if has_socket {
            Reopen::Close
        } else {
            Reopen::Keep
        }
    } else if !has_socket || table.epoch(name) != opened_epoch {
        Reopen::Open
    } else {
        Reopen::Keep
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

/// Handles one received message; true when it was a valid RS.
fn handle_rx(
    cfg: &LinkConfig,
    own: Option<&Ra>,
    rx: &nos_radv_socket::Received,
    now: Instant,
    info_bucket: &mut LogBucket,
    warn_bucket: &mut LogBucket,
) -> bool {
    match rx.data.first() {
        Some(&packet::TYPE_RS) => match packet::decode_rs(&rx.data, rx.src, rx.hop_limit) {
            Ok(_) => {
                debug!(interface = %cfg.interface, source = %rx.src, "router solicitation received");
                true
            }
            Err(e) => {
                debug!(interface = %cfg.interface, source = %rx.src, error = %e, "dropping router solicitation");
                false
            }
        },
        Some(&packet::TYPE_RA) => {
            match packet::decode_ra(&rx.data, rx.src, rx.hop_limit) {
                Ok(ra) => {
                    let (managed, other, lifetime) = (ra.managed, ra.other, ra.router_lifetime);
                    if info_bucket.take(now) {
                        info!(interface = %cfg.interface, source = %rx.src, lifetime, managed, other, "foreign router advertisement");
                    } else {
                        debug!(interface = %cfg.interface, source = %rx.src, lifetime, managed, other, "foreign router advertisement");
                    }
                    let conflicts = own
                        .map(|o| packet::inconsistencies(o, &ra))
                        .unwrap_or_default();
                    if !conflicts.is_empty() {
                        let what = conflicts.join(",");
                        if warn_bucket.take(now) {
                            warn!(interface = %cfg.interface, source = %rx.src, what = %what, "inconsistent router advertisement");
                        } else {
                            debug!(interface = %cfg.interface, source = %rx.src, what = %what, "inconsistent router advertisement");
                        }
                    }
                }
                Err(e) => {
                    debug!(interface = %cfg.interface, source = %rx.src, error = %e, "dropping router advertisement");
                }
            }
            false
        }
        _ => false,
    }
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
    use nos_proto::{InterfaceEvent as E, LinkState};

    #[test]
    fn mac_parsing() {
        assert_eq!(
            parse_mac("02:00:00:aa:bb:0f\n"),
            Some([2, 0, 0, 0xaa, 0xbb, 0x0f])
        );
        assert_eq!(parse_mac("02:00:00:aa:bb"), None);
        assert_eq!(parse_mac("02:00:00:aa:bb:cc:dd"), None);
        assert_eq!(parse_mac("zz:00:00:aa:bb:cc"), None);
    }

    #[test]
    fn link_facts_read_sysfs() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("eth1");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("address"), "02:00:00:00:00:07\n").unwrap();
        std::fs::write(dir.join("mtu"), "1400\n").unwrap();
        assert_eq!(
            link_facts(tmp.path(), "eth1"),
            (Some([2, 0, 0, 0, 0, 7]), Some(1400))
        );
        assert_eq!(link_facts(tmp.path(), "nope"), (None, None));
    }

    #[test]
    fn log_bucket_refills() {
        let t0 = Instant::now();
        let mut b = LogBucket::new(t0);
        for _ in 0..5 {
            assert!(b.take(t0));
        }
        assert!(!b.take(t0));
        assert!(b.take(t0 + Duration::from_secs(10)));
        assert!(!b.take(t0 + Duration::from_secs(10)));
    }

    #[test]
    fn needs_reopen_cases() {
        let ls = |ifindex| LinkState {
            name: "eth1".into(),
            ifindex,
            admin_up: true,
            carrier: true,
            port_aggregate: None,
        };
        let mut t = LinkTable::default();
        assert_eq!(needs_reopen(0, true, &t, "eth1"), Reopen::Keep);
        crate::link_client::apply(
            &mut t,
            E::LinkSnapshot {
                observed: true,
                links: vec![ls(2)],
            },
        );
        let e = t.epoch("eth1");
        assert_eq!(needs_reopen(e, true, &t, "eth1"), Reopen::Keep);
        assert_eq!(needs_reopen(e, false, &t, "eth1"), Reopen::Open);
        crate::link_client::apply(
            &mut t,
            E::LinkRemoved {
                name: "eth1".into(),
            },
        );
        assert_eq!(needs_reopen(e, true, &t, "eth1"), Reopen::Close);
        assert_eq!(needs_reopen(e, false, &t, "eth1"), Reopen::Keep);
        crate::link_client::apply(&mut t, E::LinkAdded(ls(9)));
        assert_eq!(needs_reopen(e, true, &t, "eth1"), Reopen::Open);
    }

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

    fn rx(data: Vec<u8>, src: &str, hop: Option<u8>) -> nos_radv_socket::Received {
        nos_radv_socket::Received {
            src: src.parse().unwrap(),
            hop_limit: hop,
            data,
        }
    }

    #[test]
    fn handle_rx_classifies() {
        let cfg = LinkConfig {
            interface: "eth1".into(),
            profile: RaProfile::default(),
        };
        let t = Instant::now();
        let (mut a, mut b) = (LogBucket::new(t), LogBucket::new(t));
        let rs = vec![133, 0, 0, 0, 0, 0, 0, 0];
        assert!(handle_rx(
            &cfg,
            None,
            &rx(rs.clone(), "fe80::1", Some(255)),
            t,
            &mut a,
            &mut b
        ));
        assert!(!handle_rx(
            &cfg,
            None,
            &rx(rs, "fe80::1", Some(1)),
            t,
            &mut a,
            &mut b
        ));
        let params = RaParams {
            profile: RaProfile::default(),
            lladdr: None,
            link_mtu: None,
            final_ra: false,
        };
        let ra = packet::build_ra(&params).unwrap();
        let own = packet::parse_ra(&ra).unwrap();
        let foreign = RaProfile {
            managed: true,
            ..RaProfile::default()
        };
        let other = packet::build_ra(&RaParams {
            profile: foreign,
            ..params
        })
        .unwrap();
        assert!(!handle_rx(
            &cfg,
            Some(&own),
            &rx(other, "fe80::2", Some(255)),
            t,
            &mut a,
            &mut b
        ));
        assert!(!handle_rx(
            &cfg,
            Some(&own),
            &rx(ra, "fe80::2", Some(3)),
            t,
            &mut a,
            &mut b
        ));
        assert!(!handle_rx(
            &cfg,
            None,
            &rx(vec![1, 2], "fe80::2", Some(255)),
            t,
            &mut a,
            &mut b
        ));
    }
}
