//! Steady-state loop: subscribes to `Interfaces`/`Hostname`/`Lldp`/`SwitchingProfiles`/`PortAggregates` diffs purely
//! as a resync trigger, always re-fetching the whole config — same shape as
//! `nos-lacp`'s `reconcile::run`. Runs one `link::run` task per interface with
//! `lldp transmit` and/or `lldp receive` set, restarting a link whose flags, timers,
//! destination group or advertised identity changed and respawning one that ended on its own.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{Config, DiffScope, Event, Interface, VlanTag};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::link::{self, LinkConfig, SharedPorts};
use crate::packet;

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Same justification as `nos-lacp`'s: cheap insurance against a missed diff,
/// and what retries a link whose interface didn't exist yet when it was first
/// configured.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

/// How long a stopping link gets to send its shutdown LLDPDU before it is
/// aborted.
const STOP_GRACE: Duration = Duration::from_secs(2);

struct LinkHandle {
    cfg: LinkConfig,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl LinkHandle {
    async fn stop(mut self) {
        let _ = self.stop.send(true);
        if tokio::time::timeout(STOP_GRACE, &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
    }
}

struct Links {
    ports: SharedPorts,
    handles: HashMap<String, LinkHandle>,
}

impl Links {
    async fn reconcile(&mut self, desired: Vec<LinkConfig>) {
        let stale: Vec<String> = self
            .handles
            .iter()
            .filter(|(name, h)| {
                h.task.is_finished()
                    || desired.iter().find(|d| &d.interface == *name) != Some(&h.cfg)
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in stale {
            if let Some(handle) = self.handles.remove(&name) {
                handle.stop().await;
            }
        }
        // LLDP turned off on an interface: drop its counters too (a restart
        // keeps them).
        self.ports
            .lock()
            .unwrap()
            .retain(|name, _| desired.iter().any(|d| &d.interface == name));
        for cfg in desired {
            if !self.handles.contains_key(&cfg.interface) {
                let handle = self.spawn(cfg);
                self.handles.insert(handle.cfg.interface.clone(), handle);
            }
        }
    }

    fn spawn(&self, cfg: LinkConfig) -> LinkHandle {
        let (stop, stop_rx) = watch::channel(false);
        let ports = self.ports.clone();
        let link_cfg = cfg.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = link::run(link_cfg.clone(), ports, stop_rx).await {
                warn!(interface = %link_cfg.interface, error = %e, "lldp link ended");
            }
        });
        LinkHandle { cfg, stop, task }
    }

    async fn shutdown(&mut self) {
        for (_, handle) in self.handles.drain() {
            handle.stop().await;
        }
    }
}

/// Every interface that should currently be running LLDP.
fn desired_links(cfg: &Config, chassis_mac: [u8; 6]) -> Vec<LinkConfig> {
    cfg.interfaces
        .iter()
        .filter(|i| i.lldp_transmit || i.lldp_receive)
        .map(|i| LinkConfig {
            interface: i.name.clone(),
            transmit: i.lldp_transmit,
            receive: i.lldp_receive,
            system_name: cfg.hostname.clone(),
            system_description: cfg.lldp.effective_system_description().to_string(),
            chassis_mac,
            tx_interval: Duration::from_secs(u64::from(cfg.lldp.effective_interval_secs())),
            ttl_secs: cfg.lldp.effective_ttl_secs(),
            management_addresses: cfg.lldp.management_addresses.clone(),
            bridge: i.switching_profile.is_some(),
            destination: i.lldp_destination.mac(),
            vlan_names: vlan_names(cfg, i),
            aggregated: i.port_aggregate.is_some(),
            max_frame_size: max_frame_size(cfg, i),
        })
        .collect()
}

/// One (tag, broadcast domain) per `Dot1q` member of the interface's switching
/// profile, by tag. An `Untagged` member has no VLAN id in this model (a
/// bridge per domain, not a VLAN-aware one), so it gets no VLAN Name TLV.
fn vlan_names(cfg: &Config, i: &Interface) -> Vec<(u16, String)> {
    let Some(profile) = i
        .switching_profile
        .as_ref()
        .and_then(|name| cfg.switching_profiles.iter().find(|p| &p.name == name))
    else {
        return Vec::new();
    };
    let mut names: Vec<(u16, String)> = profile
        .members
        .iter()
        .filter_map(|m| match m.tag {
            VlanTag::Dot1q(tag) => Some((
                tag,
                packet::truncate_at_char(&m.broadcast_domain, packet::MAX_VLAN_NAME).to_string(),
            )),
            VlanTag::Untagged => None,
        })
        .collect();
    names.sort();
    names
}

/// The effective MTU plus the Ethernet header and FCS (18). A bond member's
/// MTU is its bond's (the bonding driver sets it); unset means Linux's 1500,
/// which `nos-interfaced` enforces.
fn max_frame_size(cfg: &Config, i: &Interface) -> u16 {
    const DEFAULT_MTU: u32 = 1500;
    let mtu = match &i.port_aggregate {
        Some(name) => cfg
            .port_aggregates
            .iter()
            .find(|a| &a.name == name)
            .and_then(|a| a.mtu),
        None => i.mtu,
    };
    u16::try_from(mtu.unwrap_or(DEFAULT_MTU) + 18).unwrap_or(u16::MAX)
}

pub async fn run(config_socket: PathBuf, ports: SharedPorts, mut shutdown: watch::Receiver<bool>) {
    // Switching profiles (VLAN names) and port aggregates (a member's MTU)
    // feed the org TLVs.
    let scopes = vec![
        DiffScope::Interfaces,
        DiffScope::Hostname,
        DiffScope::Lldp,
        DiffScope::SwitchingProfiles,
        DiffScope::PortAggregates,
    ];
    let chassis_mac = local_system_id();
    let mut links = Links {
        ports,
        handles: HashMap::new(),
    };

    while !*shutdown.borrow() {
        match nos_daemon::config::subscribe_diff(&config_socket, scopes.clone()).await {
            Ok(mut reader) => {
                info!(socket = %config_socket.display(), "connected to nos-configd diff stream");
                let mut reapply = tokio::time::interval(REAPPLY_INTERVAL);
                reapply.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                reapply.tick().await;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &mut links, chassis_mac).await;
                            }
                            Some(Ok(_)) => {}
                            Some(Err(e)) => {
                                warn!(error = %e, "error reading diff stream, reconnecting");
                                break;
                            }
                            None => {
                                warn!(socket = %config_socket.display(), "diff stream closed, reconnecting");
                                break;
                            }
                        },
                        _ = reapply.tick() => {
                            resync(&config_socket, &mut links, chassis_mac).await;
                        }
                        _ = shutdown.changed() => break,
                    }
                }
            }
            Err(e) => warn!(
                error = %e,
                socket = %config_socket.display(),
                "failed to connect to nos-configd"
            ),
        }

        if *shutdown.borrow() {
            break;
        }
        if wait_or_shutdown(RECONNECT_DELAY, &mut shutdown).await {
            break;
        }
    }

    links.shutdown().await;
    info!("lldp reconciliation loop stopped");
}

async fn resync(config_socket: &Path, links: &mut Links, chassis_mac: [u8; 6]) {
    let cfg = match nos_daemon::config::fetch_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
            return;
        }
    };
    let desired = desired_links(&cfg, chassis_mac);
    let count = desired.len();
    links.reconcile(desired).await;
    debug!(count, "reconciled lldp links");
}

/// This machine's chassis identity: a locally-administered unicast MAC derived
/// from stable per-machine identity (hostname + machine-id), the same scheme
/// as `nos-lacp`'s Actor System ID. `ponytail:` two machines sharing both
/// (e.g. cloned images with the default hostname) would collide and ignore
/// each other as "our own frame"; upgrade path is a persisted random id file.
fn local_system_id() -> [u8; 6] {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    derive_system_id(
        read("/proc/sys/kernel/hostname").trim(),
        read("/etc/machine-id").trim(),
    )
}

fn derive_system_id(hostname: &str, machine_id: &str) -> [u8; 6] {
    // FNV-1a — no dependency needed for a non-cryptographic 48-bit spread.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in hostname.bytes().chain([0]).chain(machine_id.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let b = hash.to_be_bytes();
    // 0x02: locally administered, unicast.
    [0x02, b[3], b[4], b[5], b[6], b[7]]
}

/// Local copy of `nos-watchdog::supervisor::wait_or_shutdown` — not imported,
/// per the star-dependency rule.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::Interface;

    fn iface(name: &str, tx: bool, rx: bool) -> Interface {
        Interface {
            name: name.to_string(),
            addresses: Vec::new(),
            routing_table: None,
            ospf_profile: None,
            ospfv3_profile: None,
            switching_profile: None,
            port_aggregate: None,
            lacp_port_priority: None,
            lacp_link_number: None,
            lacp_mode: nos_proto::LacpMode::default(),
            mtu: None,
            lldp_transmit: tx,
            lldp_receive: rx,
            lldp_destination: nos_proto::LldpDestination::default(),
            subinterfaces: Vec::new(),
            ..Default::default()
        }
    }

    #[test]
    fn only_lldp_enabled_interfaces_get_a_link_carrying_hostname_and_flags() {
        let cfg = Config {
            hostname: "router-a".to_string(),
            interfaces: vec![
                iface("eth0", false, false),
                iface("eth1", true, false),
                iface("eth2", false, true),
                iface("eth3", true, true),
            ],
            ..Default::default()
        };
        let links = desired_links(&cfg, [2, 0, 0, 0, 0, 1]);
        let names: Vec<_> = links.iter().map(|l| l.interface.as_str()).collect();
        assert_eq!(names, ["eth1", "eth2", "eth3"]);
        assert!(links[0].transmit && !links[0].receive);
        assert!(!links[1].transmit && links[1].receive);
        assert!(links.iter().all(|l| l.system_name == "router-a"));
    }

    #[test]
    fn a_hostname_or_flag_change_makes_the_link_config_differ() {
        let mut cfg = Config {
            hostname: "a".to_string(),
            interfaces: vec![iface("eth1", true, true)],
            ..Default::default()
        };
        let before = desired_links(&cfg, [2, 0, 0, 0, 0, 1]);
        cfg.hostname = "b".to_string();
        assert_ne!(before, desired_links(&cfg, [2, 0, 0, 0, 0, 1]));
        cfg.hostname = "a".to_string();
        cfg.interfaces[0].lldp_receive = false;
        assert_ne!(before, desired_links(&cfg, [2, 0, 0, 0, 0, 1]));
    }

    #[test]
    fn timers_management_address_bridge_and_destination_flow_into_the_link() {
        let mut bridged = iface("eth1", true, true);
        bridged.switching_profile = Some("sp1".to_string());
        bridged.lldp_destination = nos_proto::LldpDestination::CustomerBridge;
        let mut cfg = Config {
            interfaces: vec![bridged, iface("eth2", true, true)],
            ..Default::default()
        };
        cfg.lldp.tx_interval_secs = Some(5);
        cfg.lldp.tx_hold = Some(3);
        cfg.lldp.management_addresses = vec!["10.0.0.1".parse().unwrap()];
        let before = desired_links(&cfg, [2, 0, 0, 0, 0, 1]);
        assert_eq!(before[0].tx_interval, Duration::from_secs(5));
        assert_eq!(before[0].ttl_secs, 15);
        assert_eq!(
            before[0].management_addresses,
            ["10.0.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(before[0].bridge && !before[1].bridge);
        assert_eq!(before[0].destination[5], 0x00);
        assert_eq!(before[1].destination[5], 0x0E);
        // Any of them changing restarts the link.
        cfg.lldp.tx_hold = None;
        assert_ne!(before, desired_links(&cfg, [2, 0, 0, 0, 0, 1]));
        assert_eq!(before[0].system_description, "nos");
        let mut changed = cfg.clone();
        changed.lldp.system_description = Some("edge".to_string());
        let after = desired_links(&changed, [2, 0, 0, 0, 0, 1]);
        assert_eq!(after[0].system_description, "edge");
        assert_ne!(desired_links(&cfg, [2, 0, 0, 0, 0, 1]), after);
    }

    #[test]
    fn vlan_names_aggregation_and_max_frame_size_flow_into_the_link() {
        use nos_proto::{PortAggregate, SwitchingProfile, SwitchingProfileMember};
        let member = |bd: &str, tag| SwitchingProfileMember {
            broadcast_domain: bd.to_string(),
            tag,
            ..Default::default()
        };
        let mut trunk = iface("eth1", true, true);
        trunk.switching_profile = Some("sp1".to_string());
        trunk.mtu = Some(9000);
        let mut bonded = iface("eth2", true, true);
        bonded.port_aggregate = Some("po1".to_string());
        let mut cfg = Config {
            interfaces: vec![trunk, bonded, iface("eth3", true, true)],
            switching_profiles: vec![SwitchingProfile {
                name: "sp1".to_string(),
                members: vec![
                    member(&"z".repeat(40), VlanTag::Dot1q(300)),
                    member("bd-x", VlanTag::Dot1q(100)),
                    member("bd-native", VlanTag::Untagged),
                ],
            }],
            port_aggregates: vec![PortAggregate {
                name: "po1".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let links = desired_links(&cfg, [2, 0, 0, 0, 0, 1]);
        // By tag, untagged skipped, names cut at 32 bytes.
        assert_eq!(
            links[0].vlan_names,
            [(100, "bd-x".to_string()), (300, "z".repeat(32))]
        );
        assert_eq!(links[0].max_frame_size, 9018);
        assert!(!links[0].aggregated && links[1].aggregated);
        // A member's MTU is its bond's, 1500 by default.
        assert_eq!(links[1].max_frame_size, 1518);
        assert_eq!(links[2].max_frame_size, 1518);
        assert_eq!(links[2].vlan_names, Vec::<(u16, String)>::new());
        cfg.port_aggregates[0].mtu = Some(2000);
        assert_eq!(
            desired_links(&cfg, [2, 0, 0, 0, 0, 1])[1].max_frame_size,
            2018
        );
    }

    #[test]
    fn system_id_is_stable_distinct_and_locally_administered_unicast() {
        let a = derive_system_id("router-a", "m1");
        assert_eq!(a, derive_system_id("router-a", "m1"));
        assert_ne!(a, derive_system_id("router-b", "m1"));
        assert_eq!(a[0], 0x02);
    }
}
