//! One LLDP-enabled interface's transmit/receive task — the LLDP counterpart
//! of `nos-lacp`'s `link.rs` `run()` shape.
//!
//! The transmit interval and advertised TTL come from `LinkConfig`
//! (`lldp tx-interval`/`tx-hold`, defaulting to the 802.1AB 30s × 4 = 120s).

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::time::sleep_until;
use tracing::{debug, info, trace, warn};

use nos_proto::LldpLinkStats;

use crate::link_client::{gate, Gate, LinkTable};
use crate::neighbor::{NeighborTable, Update, MAX_NEIGHBORS_PER_LINK};
use crate::packet::{
    self, Capabilities, Id, LinkAggregation, Lldpdu, ManagementAddress, OrgTlvs, CAP_BRIDGE,
    CAP_ROUTER, CHASSIS_SUBTYPE_MAC, PORT_SUBTYPE_IF_NAME,
};
use crate::socket::{self, LldpSocket};

/// How soon to retry a periodic transmit that found the link down.
const LINK_DOWN_RETRY: Duration = Duration::from_secs(1);

/// 802.1AB `txFastInit`: frames sent at `msgFastTx` spacing after the link
/// starts (which every local change causes, see `reconcile`) or a new
/// neighbor is learned.
const TX_FAST_INIT: u8 = 4;
/// 802.1AB `msgFastTx`: the spacing of those fast-start frames.
const MSG_FAST_TX: Duration = Duration::from_secs(1);
/// 802.1AB `txCreditMax`: at most this many frames back to back; one credit
/// comes back per second.
const TX_CREDIT_MAX: u8 = 5;

/// Neighbor learned/removed events logged at `info` back to back per link;
/// beyond that they go to `debug` (a hostile or flapping peer must not flood
/// nos-logd). One `info` credit comes back per `LOG_CREDIT_EVERY`.
const LOG_CREDIT_MAX: u8 = 5;
const LOG_CREDIT_EVERY: Duration = Duration::from_secs(10);

const SYS_CLASS_NET: &str = "/sys/class/net";

/// Everything a link task needs; also what `reconcile` compares to decide
/// whether a running link must be restarted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent per-link knobs, compared as a whole
pub struct LinkConfig {
    pub interface: String,
    pub transmit: bool,
    pub receive: bool,
    /// Advertised as the System Name TLV (the configured hostname).
    pub system_name: String,
    /// Advertised as the System Description TLV (`lldp system-description`).
    pub system_description: String,
    /// This machine's chassis identity — see `reconcile::local_system_id`.
    pub chassis_mac: [u8; 6],
    /// `msgTxInterval`: how often to transmit.
    pub tx_interval: Duration,
    /// The TTL advertised in every LLDPDU (`msgTxHold × msgTxInterval`).
    pub ttl_secs: u16,
    /// Each advertised in its own Management Address TLV.
    pub management_addresses: Vec<IpAddr>,
    /// Whether the interface is a bridge port (has a switching profile), which
    /// sets the Bridge bit in *enabled* capabilities.
    pub bridge: bool,
    /// The 802.1AB destination group this link speaks on.
    pub destination: [u8; 6],
    /// 802.1 VLAN Name TLVs: each `Dot1q` switching-profile member's tag and
    /// broadcast domain, by tag.
    pub vlan_names: Vec<(u16, String)>,
    /// Whether the interface is a port-aggregate member, so it sends a Link
    /// Aggregation TLV (its state is read from the kernel per transmit).
    pub aggregated: bool,
    /// 802.3 Maximum Frame Size: the effective MTU plus the Ethernet header
    /// and FCS.
    pub max_frame_size: u16,
}

/// One LLDP-enabled interface's live state: its neighbors and its 802.1AB
/// §9.2.6 counters (`stats.interface` is left empty; the map key names it).
#[derive(Default)]
pub struct Port {
    pub neighbors: NeighborTable,
    pub stats: LldpLinkStats,
}

/// Every LLDP-enabled interface's `Port`, keyed by interface name. Shared with
/// `server.rs` so `show lldp neighbors`/`statistics` read live state. A std
/// mutex, never held across an `.await`. An entry outlives its link task (the
/// counters survive a link restart); `reconcile` removes it when LLDP is
/// turned off on the interface.
pub type SharedPorts = Arc<Mutex<HashMap<String, Port>>>;

/// Token bucket for the per-link `info` neighbor logs (`LOG_CREDIT_MAX`
/// burst, one credit per `LOG_CREDIT_EVERY`).
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

    /// Refills for the time elapsed, then spends one credit if there is one.
    fn take(&mut self, now: Instant) -> bool {
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

fn chassis_id(cfg: &LinkConfig) -> Id {
    Id {
        subtype: CHASSIS_SUBTYPE_MAC,
        value: cfg.chassis_mac.to_vec(),
    }
}

/// The Link Aggregation TLV of a port-aggregate member: capable, and enabled
/// with the bond's ifIndex while the kernel has it enslaved (`<sys>/<if>/master`
/// is then a symlink to the bond's sysfs directory). For a `Lacp` aggregate
/// `nos-interfaced` only enslaves negotiated members, so "has a master" is
/// "aggregated now". `sys` is `/sys/class/net` outside tests.
pub fn read_aggregation(sys: &Path, interface: &str) -> LinkAggregation {
    let bond = std::fs::read_to_string(sys.join(interface).join("master/ifindex"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    LinkAggregation {
        capable: true,
        enabled: bond.is_some(),
        port_id: bond.unwrap_or(0),
    }
}

/// The LLDPDU this link advertises. `resolve` gives the ifIndex of the
/// interface carrying a management address, if any — looked up per transmit
/// so an address applied or moved after the link started is picked up, like
/// `aggregation` (`read_aggregation`, `None` for a non-member).
pub fn local_pdu(
    cfg: &LinkConfig,
    resolve: impl Fn(IpAddr) -> Option<u32>,
    aggregation: Option<LinkAggregation>,
) -> Lldpdu {
    Lldpdu {
        chassis_id: chassis_id(cfg),
        port_id: Id {
            subtype: PORT_SUBTYPE_IF_NAME,
            value: cfg.interface.as_bytes().to_vec(),
        },
        ttl: cfg.ttl_secs,
        port_description: Some(cfg.interface.clone()),
        system_name: Some(cfg.system_name.clone()),
        system_description: Some(cfg.system_description.clone()),
        capabilities: Some(Capabilities {
            supported: CAP_ROUTER | CAP_BRIDGE,
            enabled: CAP_ROUTER | if cfg.bridge { CAP_BRIDGE } else { 0 },
        }),
        management_addresses: cfg
            .management_addresses
            .iter()
            .map(|&address| ManagementAddress {
                address,
                if_index: resolve(address),
            })
            .collect(),
        org: OrgTlvs {
            vlan_names: cfg.vlan_names.clone(),
            link_aggregation: aggregation,
            max_frame_size: Some(cfg.max_frame_size),
            ..OrgTlvs::default()
        },
    }
}

/// A shutdown LLDPDU (802.1AB): identity only, TTL 0, telling
/// neighbors to forget us immediately instead of waiting out the TTL.
fn shutdown_pdu(cfg: &LinkConfig) -> Lldpdu {
    Lldpdu {
        ttl: 0,
        port_description: None,
        system_name: None,
        system_description: None,
        capabilities: None,
        management_addresses: Vec::new(),
        org: OrgTlvs::default(),
        ..local_pdu(cfg, |_| None, None)
    }
}

/// Sends `pdu`, returning `false` only if the link was down. A link that comes
/// up just after its task starts (`nos-interfaced` admin-ups it on its own
/// schedule) would otherwise cost a whole `TX_INTERVAL` before the first
/// advertisement — the caller retries after `LINK_DOWN_RETRY` instead. Only a
/// frame that actually left counts towards `frames_out`.
fn send(socket: &LldpSocket, interface: &str, ports: &SharedPorts, pdu: &Lldpdu) -> bool {
    match socket.send(&packet::encode(pdu)) {
        Ok(()) => {
            trace!(interface = %interface, ttl = pdu.ttl, "lldpdu sent");
            ports
                .lock()
                .unwrap()
                .entry(interface.to_string())
                .or_default()
                .stats
                .frames_out += 1;
            true
        }
        Err(e) if socket::is_link_down(&e) => {
            debug!(interface = %interface, error = %e, "link down, lldpdu not sent");
            false
        }
        Err(e) => {
            warn!(interface = %interface, error = %e, "failed to send lldpdu");
            true
        }
    }
}

/// Decodes and records one received LLDPDU. Returns `true` iff it introduced a
/// *new* neighbor — the caller answers that with a fast-start burst so a peer
/// that came up after us learns us without waiting out our 30s timer. Only new
/// neighbors trigger it, so two systems settle after one burst rather than
/// ping-ponging.
fn handle_rx(
    cfg: &LinkConfig,
    ports: &SharedPorts,
    payload: &[u8],
    now: Instant,
    bucket: &mut LogBucket,
) -> bool {
    let decoded = packet::decode_counted(payload);
    let mut ports_guard = ports.lock().unwrap();
    let entry = ports_guard.entry(cfg.interface.clone()).or_default();
    let (pdu, tlvs) = match decoded {
        Ok(decoded) => decoded,
        Err(e) => {
            entry.stats.frames_in_errors += 1;
            entry.stats.frames_discarded += 1;
            drop(ports_guard);
            debug!(interface = %cfg.interface, error = %e, "dropping malformed lldpdu");
            return false;
        }
    };
    // Our own frame reflected back (looped cable, port mirror).
    if pdu.chassis_id == chassis_id(cfg) {
        return false;
    }
    entry.stats.frames_in += 1;
    entry.stats.tlvs_discarded += tlvs.discarded;
    entry.stats.tlvs_unrecognized += tlvs.unrecognized;
    let chassis = pdu.chassis_display();
    let port = pdu.port_display();
    let system_name = pdu.system_name.clone().unwrap_or_default();
    let system_description = pdu.system_description.clone().unwrap_or_default();
    let ttl = pdu.ttl;
    let management_addresses = pdu
        .management_addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let capabilities = pdu.enabled_capability_names().join(",");
    let max_frame_size = pdu
        .org
        .max_frame_size
        .map_or_else(|| "-".to_string(), |s| s.to_string());
    let vlans = pdu
        .org
        .vlan_names
        .iter()
        .map(|(vid, name)| format!("{vid}:{name}"))
        .collect::<Vec<_>>()
        .join(",");
    let aggregation = aggregation_display(pdu.org.link_aggregation);
    let med = crate::med::display(crate::med::to_proto(&pdu.org).as_ref());
    let update = entry.neighbors.apply(pdu, now);
    if let Update::TableFull { .. } = update {
        entry.stats.too_many_neighbors += 1;
        entry.stats.frames_discarded += 1;
    }
    drop(ports_guard);
    match update {
        Update::New => {
            // Same fields either way; `debug` once the link's burst is spent.
            macro_rules! learned {
                ($lvl:ident) => {
                    $lvl!(
                        interface = %cfg.interface, chassis_id = %chassis, port_id = %port,
                        system_name = %system_name, system_description = %system_description,
                        ttl, management_addresses = %management_addresses,
                        capabilities = %capabilities, max_frame_size = %max_frame_size,
                        vlans = %vlans, aggregation = %aggregation, med = %med,
                        "lldp neighbor learned"
                    )
                };
            }
            if bucket.take(now) {
                learned!(info);
            } else {
                learned!(debug);
            }
            true
        }
        Update::Removed => {
            if bucket.take(now) {
                info!(
                    interface = %cfg.interface, chassis_id = %chassis, port_id = %port,
                    reason = "shutdown", "lldp neighbor removed"
                );
            } else {
                debug!(
                    interface = %cfg.interface, chassis_id = %chassis, port_id = %port,
                    reason = "shutdown", "lldp neighbor removed"
                );
            }
            false
        }
        // A hostile segment must not flood the log through nos-logd: warn on
        // the first refusal since the table last had room, debug after.
        Update::TableFull { first: true } => {
            warn!(
                interface = %cfg.interface, chassis_id = %chassis, port_id = %port,
                limit = MAX_NEIGHBORS_PER_LINK, "lldp neighbor table full, dropping new neighbor"
            );
            false
        }
        Update::TableFull { first: false } => {
            debug!(
                interface = %cfg.interface, chassis_id = %chassis, port_id = %port,
                "lldp neighbor table full, dropping new neighbor"
            );
            false
        }
        Update::Refreshed | Update::Ignored => false,
    }
}

/// A Link Aggregation TLV for logs: `enabled/<port id>`, `capable`, or `-`.
fn aggregation_display(agg: Option<LinkAggregation>) -> String {
    match agg {
        Some(a) if a.enabled => format!("enabled/{}", a.port_id),
        Some(a) if a.capable => "capable".to_string(),
        _ => "-".to_string(),
    }
}

fn expire(cfg: &LinkConfig, ports: &SharedPorts, now: Instant) {
    let gone = ports
        .lock()
        .unwrap()
        .get_mut(&cfg.interface)
        .map_or_default(|p| {
            let gone = p.neighbors.expire(now);
            p.stats.ageouts += gone.len() as u64;
            gone
        });
    for pdu in gone {
        info!(
            interface = %cfg.interface, chassis_id = %pdu.chassis_display(),
            port_id = %pdu.port_display(), reason = "expired", "lldp neighbor removed"
        );
    }
}

fn next_expiry(cfg: &LinkConfig, ports: &SharedPorts) -> Option<Instant> {
    ports
        .lock()
        .unwrap()
        .get(&cfg.interface)
        .and_then(|p| p.neighbors.next_expiry())
}

/// 802.1AB §9.2.5.19-21 credit refill: one credit per whole second since
/// `last`, capped at `TX_CREDIT_MAX`. `last` advances by the seconds counted,
/// so a fraction carries over.
fn refill_credit(credit: &mut u8, last: &mut Instant, now: Instant) {
    let secs = now.saturating_duration_since(*last).as_secs();
    if secs > 0 {
        *credit = u8::try_from(secs)
            .unwrap_or(u8::MAX)
            .saturating_add(*credit)
            .min(TX_CREDIT_MAX);
        *last += Duration::from_secs(secs);
    }
}

/// Books one sent frame: spends a credit and a fast-start frame, and returns
/// when the next one is due — `MSG_FAST_TX` while the burst lasts, then
/// `tx_interval`. The caller checks the credit is non-zero first.
fn spend_tx(credit: &mut u8, fast: &mut u8, tx_interval: Duration, now: Instant) -> Instant {
    *credit = credit.saturating_sub(1);
    *fast = fast.saturating_sub(1);
    now + if *fast > 0 { MSG_FAST_TX } else { tx_interval }
}

/// What a link-table update means for the socket of one link (#1431).
#[derive(Debug, PartialEq, Eq)]
enum Reopen {
    Keep,
    /// The device is gone: drop the socket, keep the task.
    Close,
    /// A socket opened under another epoch, or none yet: (re)open it.
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

/// Why a link's neighbors are forgotten while its device stays: 802.1AB
/// portEnabled false on carrier loss or admin-down (#1519).
fn flush_reason(g: Gate) -> Option<&'static str> {
    match g {
        Gate::Down(r @ ("no-carrier" | "admin-down")) => Some(r),
        _ => None,
    }
}

/// Applies [`needs_reopen`]; true when a fresh socket was opened (the caller
/// restarts the fast-start burst). A closed or failed open leaves `socket`
/// `None`, retried on the next link event or transmit tick.
fn follow_link(
    cfg: &LinkConfig,
    ports: &SharedPorts,
    table: &LinkTable,
    socket: &mut Option<LldpSocket>,
    opened_epoch: &mut u64,
) -> bool {
    let clear = || {
        if let Some(port) = ports.lock().unwrap().get_mut(&cfg.interface) {
            port.neighbors = NeighborTable::default();
        }
    };
    if let Some(reason) = flush_reason(gate(table, &cfg.interface)) {
        // The non-empty guard makes this fire once per up-to-down transition.
        if let Some(port) = ports.lock().unwrap().get_mut(&cfg.interface)
            && !port.neighbors.is_empty()
        {
            port.neighbors = NeighborTable::default();
            info!(interface = %cfg.interface, reason, "lldp neighbors flushed");
        }
    }
    match needs_reopen(*opened_epoch, socket.is_some(), table, &cfg.interface) {
        Reopen::Keep => false,
        Reopen::Close => {
            // Neighbor TTLs mean nothing on a dead link.
            *socket = None;
            clear();
            info!(interface = %cfg.interface, "lldp socket closed, device gone");
            false
        }
        Reopen::Open => {
            *socket = None;
            clear();
            let epoch = table.epoch(&cfg.interface);
            match socket::open(&cfg.interface, cfg.destination) {
                Ok(s) => {
                    *socket = Some(s);
                    *opened_epoch = epoch;
                    info!(interface = %cfg.interface, "lldp socket reopened");
                    true
                }
                Err(e) => {
                    warn!(interface = %cfg.interface, error = %e, "lldp socket reopen failed");
                    false
                }
            }
        }
    }
}

/// Runs one interface's LLDP until `stop` fires (or its sender is dropped).
/// Returns `Err` only when the socket can't be opened or a read fails hard —
/// `reconcile` respawns a link that ended on its own.
pub async fn run(
    cfg: LinkConfig,
    ports: SharedPorts,
    mut stop: watch::Receiver<bool>,
    mut links: watch::Receiver<LinkTable>,
) -> io::Result<()> {
    // Listed (with its counters, kept across restarts) even before the socket
    // opens; the neighbor table starts empty.
    ports
        .lock()
        .unwrap()
        .entry(cfg.interface.clone())
        .or_default()
        .neighbors = NeighborTable::default();
    // Read before the open: a bump racing it only causes a spare reopen.
    let mut opened_epoch = links.borrow().epoch(&cfg.interface);
    let mut socket = Some(socket::open(&cfg.interface, cfg.destination)?);
    info!(
        interface = %cfg.interface, transmit = cfg.transmit, receive = cfg.receive,
        tx_interval_secs = cfg.tx_interval.as_secs(), ttl_secs = cfg.ttl_secs,
        "lldp link started"
    );

    // A (re)started link is 802.1AB's "somethingChangedLocal": it opens with
    // a fast-start burst, the first frame right away.
    let mut next_tx = Instant::now();
    let mut tx_fast = TX_FAST_INIT;
    let (mut tx_credit, mut last_refill) = (TX_CREDIT_MAX, Instant::now());
    let mut log_bucket = LogBucket::new(Instant::now());

    let result = loop {
        // Never leave an elapsed deadline armed: `expire` moves it forward by
        // removing the entry it belonged to, and with no entries the branch is
        // disabled by its guard.
        let deadline = next_expiry(&cfg, &ports);
        tokio::select! {
            _ = stop.changed() => break Ok(()),
            Ok(()) = links.changed() => {
                let table = links.borrow_and_update().clone();
                if follow_link(&cfg, &ports, &table, &mut socket, &mut opened_epoch) && cfg.transmit {
                    tx_fast = TX_FAST_INIT;
                    next_tx = Instant::now();
                }
            }
            () = sleep_until(tokio::time::Instant::from_std(next_tx)), if cfg.transmit => {
                let now = Instant::now();
                if socket.is_none() {
                    let table = links.borrow().clone();
                    if follow_link(&cfg, &ports, &table, &mut socket, &mut opened_epoch) {
                        tx_fast = TX_FAST_INIT;
                    }
                }
                refill_credit(&mut tx_credit, &mut last_refill, now);
                // Out of credit, or the link is down: nothing spent, retry in
                // a second (credit comes back at that rate too).
                next_tx = now + LINK_DOWN_RETRY;
                // ponytail: a LACP membership change is advertised on the next
                // transmit (<= tx-interval), not as somethingChangedLocal; watch
                // the master link if anyone needs it faster.
                let aggregation = cfg.aggregated.then(|| read_aggregation(Path::new(SYS_CLASS_NET), &cfg.interface));
                if let (true, Some(socket)) = (tx_credit > 0, &socket)
                    && send(socket, &cfg.interface, &ports, &local_pdu(&cfg, nos_l2_socket::ifindex_of_address, aggregation))
                {
                    if tx_fast > 0 {
                        debug!(interface = %cfg.interface, remaining = tx_fast - 1, "lldp fast-start tx");
                    }
                    next_tx = spend_tx(&mut tx_credit, &mut tx_fast, cfg.tx_interval, now);
                }
            }
            frame = async {
                match &socket {
                    Some(s) => s.recv().await,
                    None => std::future::pending().await,
                }
            }, if cfg.receive => match frame {
                Ok(payload) => {
                    if handle_rx(&cfg, &ports, &payload, Instant::now(), &mut log_bucket) && cfg.transmit {
                        tx_fast = TX_FAST_INIT;
                        next_tx = Instant::now();
                    }
                }
                // The recv path saw the device recreated before the link
                // table did: drop the socket, `follow_link` reopens it.
                // ponytail: a receive-only link retries on link events only.
                Err(e) if e.kind() == io::ErrorKind::NotConnected => socket = None,
                Err(e) => break Err(e),
            },
            () = sleep_until(tokio::time::Instant::from_std(deadline.unwrap_or_else(Instant::now))),
                if deadline.is_some() =>
            {
                expire(&cfg, &ports, Instant::now());
            }
        }
    };

    if let (true, Some(socket)) = (cfg.transmit, &socket) {
        send(socket, &cfg.interface, &ports, &shutdown_pdu(&cfg));
    }
    if let Some(port) = ports.lock().unwrap().get_mut(&cfg.interface) {
        port.neighbors = NeighborTable::default();
    }
    info!(interface = %cfg.interface, "lldp link stopped");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mac_last: u8) -> LinkConfig {
        LinkConfig {
            interface: "eth1".to_string(),
            transmit: true,
            receive: true,
            system_name: format!("router-{mac_last}"),
            system_description: "nos".to_string(),
            chassis_mac: [2, 0, 0, 0, 0, mac_last],
            tx_interval: Duration::from_secs(30),
            ttl_secs: 120,
            management_addresses: Vec::new(),
            bridge: false,
            destination: nos_proto::LldpDestination::default().mac(),
            vlan_names: Vec::new(),
            aggregated: false,
            max_frame_size: 1518,
        }
    }

    #[test]
    fn needs_reopen_cases() {
        use nos_proto::{InterfaceEvent as E, LinkState};
        let ls = |ifindex| LinkState {
            name: "eth1".into(),
            ifindex,
            admin_up: true,
            carrier: true,
            port_aggregate: None,
        };
        let mut t = LinkTable::default();
        // No snapshot yet: nothing is known, keep the socket.
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
        assert_eq!(
            needs_reopen(t.epoch("eth1"), true, &t, "eth1"),
            Reopen::Keep
        );
    }

    #[test]
    fn follow_link_clears_neighbors_and_survives_a_failed_reopen() {
        use nos_proto::{InterfaceEvent as E, LinkState};
        let mut c = cfg(1);
        c.interface = "nos-no-such0".into();
        let ports = SharedPorts::default();
        let mut table = LinkTable::default();
        crate::link_client::apply(
            &mut table,
            E::LinkAdded(LinkState {
                name: c.interface.clone(),
                ifindex: 3,
                admin_up: true,
                carrier: true,
                port_aggregate: None,
            }),
        );
        let mut socket = None;
        let mut epoch = 0;
        // No socket yet and the device is there: reopen is tried, fails (no
        // such interface), the task carries on with `None`.
        assert!(!follow_link(&c, &ports, &table, &mut socket, &mut epoch));
        assert!(socket.is_none());
        assert_eq!(epoch, 0);
        // Device gone and no socket: nothing to do.
        crate::link_client::apply(
            &mut table,
            E::LinkSnapshot {
                observed: true,
                links: vec![],
            },
        );
        assert!(!follow_link(&c, &ports, &table, &mut socket, &mut epoch));
    }

    #[test]
    fn flush_reason_cases() {
        assert_eq!(flush_reason(Gate::Down("no-carrier")), Some("no-carrier"));
        assert_eq!(flush_reason(Gate::Down("admin-down")), Some("admin-down"));
        assert_eq!(flush_reason(Gate::Down("absent")), None);
        assert_eq!(flush_reason(Gate::Up), None);
        assert_eq!(flush_reason(Gate::Ungated), None);
    }

    #[test]
    fn follow_link_flushes_on_carrier_loss_and_admin_down_only() {
        use nos_proto::{InterfaceEvent as E, LinkState};
        let (me, peer) = (cfg(1), cfg(2));
        let ports = shared();
        let ls = |admin_up, carrier| LinkState {
            name: me.interface.clone(),
            ifindex: 3,
            admin_up,
            carrier,
            port_aggregate: None,
        };
        let mut table = LinkTable::default();
        let learn = || {
            rx(&me, &ports, &frame_from(&peer, 120), Instant::now());
        };
        let empty = || {
            let g = ports.lock().unwrap();
            g[&me.interface].neighbors.is_empty()
        };
        let (mut socket, mut epoch) = (None, 0);
        // Carrier lost: flushed, a second pass is a no-op.
        crate::link_client::apply(&mut table, E::LinkAdded(ls(true, false)));
        learn();
        assert!(!empty());
        follow_link(&me, &ports, &table, &mut socket, &mut epoch);
        assert!(empty());
        follow_link(&me, &ports, &table, &mut socket, &mut epoch);
        assert!(empty());
        // Carrier back: nothing is cleared by the gate itself.
        crate::link_client::apply(&mut table, E::LinkAdded(ls(true, true)));
        learn();
        follow_link(&me, &ports, &table, &mut socket, &mut epoch);
        // (a reopen on the new epoch may clear; only the down cases are asserted)
        learn();
        // Admin down: flushed.
        crate::link_client::apply(&mut table, E::LinkAdded(ls(false, true)));
        assert!(!empty());
        follow_link(&me, &ports, &table, &mut socket, &mut epoch);
        assert!(empty());
    }

    /// `handle_rx` with a fresh log bucket.
    fn rx(me: &LinkConfig, n: &SharedPorts, payload: &[u8], now: Instant) -> bool {
        handle_rx(me, n, payload, now, &mut LogBucket::new(now))
    }

    #[test]
    fn log_bucket_allows_a_burst_then_suppresses_then_refills() {
        let t0 = Instant::now();
        let mut b = LogBucket::new(t0);
        for _ in 0..LOG_CREDIT_MAX {
            assert!(b.take(t0));
        }
        assert!(!b.take(t0));
        assert!(!b.take(t0 + Duration::from_secs(9)));
        assert!(b.take(t0 + Duration::from_secs(10)));
        assert!(!b.take(t0 + Duration::from_secs(10)));
        // A long idle refills to the cap, never beyond.
        let later = t0 + Duration::from_secs(10_000);
        for _ in 0..LOG_CREDIT_MAX {
            assert!(b.take(later));
        }
        assert!(!b.take(later));
    }

    #[test]
    fn flapping_neighbor_is_still_recorded_when_logs_are_suppressed() {
        let (me, peer) = (cfg(1), cfg(2));
        let n = shared();
        let now = Instant::now();
        let mut bucket = LogBucket::new(now);
        for _ in 0..20 {
            assert!(handle_rx(
                &me,
                &n,
                &frame_from(&peer, 120),
                now,
                &mut bucket
            ));
            assert!(!handle_rx(&me, &n, &frame_from(&peer, 0), now, &mut bucket));
        }
        assert_eq!(bucket.credit, 0);
        assert!(handle_rx(
            &me,
            &n,
            &frame_from(&peer, 120),
            now,
            &mut bucket
        ));
        assert_eq!(
            n.lock().unwrap()["eth1"]
                .neighbors
                .snapshot("eth1", now)
                .len(),
            1
        );
    }

    #[test]
    fn system_description_defaults_to_nos_and_reaches_the_wire() {
        let mut c = cfg(1);
        let wire = |c: &LinkConfig| {
            packet::decode(&packet::encode(&local_pdu(c, |_| None, None)))
                .unwrap()
                .system_description
        };
        assert_eq!(wire(&c).as_deref(), Some("nos"));
        c.system_description = "edge router".to_string();
        assert_eq!(wire(&c).as_deref(), Some("edge router"));
    }

    fn shared() -> SharedPorts {
        Arc::new(Mutex::new(HashMap::new()))
    }

    fn frame_from(peer: &LinkConfig, ttl: u16) -> Vec<u8> {
        let mut pdu = local_pdu(peer, |_| None, None);
        pdu.ttl = ttl;
        packet::encode(&pdu)
    }

    #[test]
    fn local_pdu_round_trips_and_carries_our_identity() {
        let c = cfg(1);
        let pdu = packet::decode(&packet::encode(&local_pdu(&c, |_| None, None))).unwrap();
        assert_eq!(pdu.chassis_display(), "02:00:00:00:00:01");
        assert_eq!(pdu.port_display(), "eth1");
        assert_eq!(pdu.system_name.as_deref(), Some("router-1"));
        assert_eq!(pdu.ttl, 120);
    }

    #[test]
    fn timers_management_address_and_bridge_bit_reach_the_wire() {
        let mut c = cfg(1);
        c.ttl_secs = 15;
        let (on_if, nowhere): (IpAddr, IpAddr) =
            ("10.0.0.1".parse().unwrap(), "192.0.2.1".parse().unwrap());
        c.management_addresses = vec![on_if, nowhere];
        // Only the first is on an interface (ifIndex 7).
        let resolve = |a| (a == on_if).then_some(7);
        let pdu = packet::decode(&packet::encode(&local_pdu(&c, resolve, None))).unwrap();
        assert_eq!(pdu.ttl, 15);
        assert_eq!(
            pdu.management_addresses,
            [
                ManagementAddress {
                    address: on_if,
                    if_index: Some(7)
                },
                ManagementAddress {
                    address: nowhere,
                    if_index: None
                },
            ]
        );
        // Router only, until the interface is a bridge port.
        assert_eq!(pdu.enabled_capability_names(), ["router"]);
        assert_eq!(pdu.capabilities.unwrap().supported, CAP_ROUTER | CAP_BRIDGE);
        c.bridge = true;
        let pdu = packet::decode(&packet::encode(&local_pdu(&c, resolve, None))).unwrap();
        assert_eq!(pdu.enabled_capability_names(), ["bridge", "router"]);
    }

    #[test]
    fn org_tlvs_reach_the_wire() {
        let mut c = cfg(1);
        let pdu = packet::decode(&packet::encode(&local_pdu(&c, |_| None, None))).unwrap();
        assert_eq!(
            pdu.org,
            OrgTlvs {
                max_frame_size: Some(1518),
                ..OrgTlvs::default()
            }
        );
        c.vlan_names = vec![(100, "bd-x".to_string())];
        c.max_frame_size = 9018;
        let agg = LinkAggregation {
            capable: true,
            enabled: true,
            port_id: 12,
        };
        let pdu = packet::decode(&packet::encode(&local_pdu(&c, |_| None, Some(agg)))).unwrap();
        assert_eq!(pdu.org.vlan_names, c.vlan_names);
        assert_eq!(pdu.org.max_frame_size, Some(9018));
        assert_eq!(pdu.org.link_aggregation, Some(agg));
        assert_eq!(aggregation_display(Some(agg)), "enabled/12");
        assert_eq!(aggregation_display(None), "-");
    }

    #[test]
    fn aggregation_is_read_from_the_master_link() {
        let sys = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(sys.path().join("eth2")).unwrap();
        let not_enslaved = read_aggregation(sys.path(), "eth2");
        assert_eq!(
            not_enslaved,
            LinkAggregation {
                capable: true,
                enabled: false,
                port_id: 0
            }
        );
        assert_eq!(aggregation_display(Some(not_enslaved)), "capable");
        // The kernel's `master` is a symlink to the bond's directory.
        std::fs::create_dir_all(sys.path().join("bond1")).unwrap();
        std::fs::write(sys.path().join("bond1/ifindex"), "7\n").unwrap();
        std::os::unix::fs::symlink(sys.path().join("bond1"), sys.path().join("eth2/master"))
            .unwrap();
        assert_eq!(
            read_aggregation(sys.path(), "eth2"),
            LinkAggregation {
                capable: true,
                enabled: true,
                port_id: 7
            }
        );
    }

    #[test]
    fn shutdown_pdu_has_ttl_zero_and_only_mandatory_tlvs() {
        let mut c = cfg(1);
        c.management_addresses = vec!["10.0.0.1".parse().unwrap()];
        let pdu = packet::decode(&packet::encode(&shutdown_pdu(&c))).unwrap();
        assert_eq!(pdu.ttl, 0);
        assert_eq!(pdu.management_addresses, []);
        assert_eq!(pdu.org, OrgTlvs::default());
        assert_eq!(pdu.system_name, None);
        assert_eq!(pdu.chassis_display(), "02:00:00:00:00:01");
    }

    #[test]
    fn only_a_new_neighbor_asks_for_an_immediate_reply() {
        let (me, peer) = (cfg(1), cfg(2));
        let n = shared();
        let now = Instant::now();
        assert!(rx(&me, &n, &frame_from(&peer, 120), now));
        // The same neighbor again is a refresh: no reply, so no ping-pong.
        assert!(!rx(&me, &n, &frame_from(&peer, 120), now));
        assert_eq!(
            n.lock().unwrap()["eth1"]
                .neighbors
                .snapshot("eth1", now)
                .len(),
            1
        );
    }

    #[test]
    fn shutdown_frame_removes_the_neighbor_immediately() {
        let (me, peer) = (cfg(1), cfg(2));
        let n = shared();
        let now = Instant::now();
        rx(&me, &n, &frame_from(&peer, 120), now);
        assert!(!rx(&me, &n, &frame_from(&peer, 0), now));
        assert_eq!(
            n.lock().unwrap()["eth1"].neighbors.snapshot("eth1", now),
            []
        );
    }

    #[test]
    fn own_reflected_frame_and_garbage_are_ignored() {
        let me = cfg(1);
        let n = shared();
        let now = Instant::now();
        assert!(!rx(&me, &n, &frame_from(&me, 120), now));
        assert!(!rx(&me, &n, &[0xff, 0xff, 0x01], now));
        assert_eq!(
            n.lock().unwrap()["eth1"].neighbors.snapshot("eth1", now),
            []
        );
    }

    #[test]
    fn fast_start_bursts_at_one_second_then_falls_back_to_tx_interval() {
        let (mut credit, mut fast) = (TX_CREDIT_MAX, TX_FAST_INIT);
        let (now, interval) = (Instant::now(), Duration::from_secs(30));
        for _ in 1..TX_FAST_INIT {
            assert_eq!(
                spend_tx(&mut credit, &mut fast, interval, now),
                now + MSG_FAST_TX
            );
        }
        // The last fast frame schedules the normal interval.
        assert_eq!(
            spend_tx(&mut credit, &mut fast, interval, now),
            now + interval
        );
        assert_eq!((credit, fast), (TX_CREDIT_MAX - TX_FAST_INIT, 0));
        // Neither counter underflows.
        spend_tx(&mut credit, &mut fast, interval, now);
        spend_tx(&mut credit, &mut fast, interval, now);
        assert_eq!((credit, fast), (0, 0));
    }

    #[test]
    fn credit_refills_one_per_whole_second_up_to_the_cap() {
        let start = Instant::now();
        let (mut credit, mut last) = (0, start);
        refill_credit(&mut credit, &mut last, start + Duration::from_millis(900));
        assert_eq!((credit, last), (0, start));
        // 2.5s: two credits, the half second carries over.
        refill_credit(&mut credit, &mut last, start + Duration::from_millis(2500));
        assert_eq!((credit, last), (2, start + Duration::from_secs(2)));
        refill_credit(&mut credit, &mut last, start + Duration::from_secs(3));
        assert_eq!(credit, 3);
        refill_credit(&mut credit, &mut last, start + Duration::from_secs(3600));
        assert_eq!(credit, TX_CREDIT_MAX);
    }

    #[test]
    fn expire_drops_lapsed_neighbors_only() {
        let (me, peer) = (cfg(1), cfg(2));
        let n = shared();
        let now = Instant::now();
        rx(&me, &n, &frame_from(&peer, 10), now);
        expire(&me, &n, now + Duration::from_secs(5));
        assert_eq!(
            n.lock().unwrap()["eth1"]
                .neighbors
                .snapshot("eth1", now)
                .len(),
            1
        );
        expire(&me, &n, now + Duration::from_secs(10));
        assert_eq!(
            n.lock().unwrap()["eth1"].neighbors.snapshot("eth1", now),
            []
        );
        assert_eq!(next_expiry(&me, &n), None);
        assert_eq!(n.lock().unwrap()["eth1"].stats.ageouts, 1);
    }

    #[test]
    fn receive_counters() {
        let me = cfg(1);
        let n = shared();
        let now = Instant::now();
        rx(&me, &n, &frame_from(&cfg(2), 120), now); // valid
        rx(&me, &n, &[0xff, 0xff, 0x01], now); // garbage
        rx(&me, &n, &frame_from(&me, 120), now); // our own, not counted
                                                 // Fill the table, then one more new neighbor is refused.
        for i in 3..=u8::try_from(MAX_NEIGHBORS_PER_LINK + 2).unwrap() {
            rx(&me, &n, &frame_from(&cfg(i), 120), now);
        }
        let stats = n.lock().unwrap()["eth1"].stats.clone();
        assert_eq!(
            stats,
            LldpLinkStats {
                frames_in: u64::try_from(MAX_NEIGHBORS_PER_LINK).unwrap() + 1,
                frames_in_errors: 1,
                frames_discarded: 2,
                too_many_neighbors: 1,
                ..LldpLinkStats::default()
            }
        );
    }
}
