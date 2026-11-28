//! Steady-state loop: subscribes to `Interfaces`/`RaProfiles` diffs purely as a
//! resync trigger and re-fetches the whole config (`nos-lldp`'s shape). One
//! `link::run` task per attach point. A profile edit is pushed into the running
//! task (it re-advertises at once); a removed attach point stops the task,
//! which sends the final lifetime-0 RAs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{Config, DiffScope, Event};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::link::LinkConfig;
use crate::link_client::LinkTable;
use crate::socket;

const RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// Cheap insurance against a missed diff; also retries a link whose device did
/// not exist yet.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);
/// Covers `FINAL_COUNT` RAs one second apart.
const STOP_GRACE: Duration = Duration::from_secs(5);

struct LinkHandle {
    cfg: LinkConfig,
    cfg_tx: watch::Sender<LinkConfig>,
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
    link_table: watch::Receiver<LinkTable>,
    handles: HashMap<String, LinkHandle>,
}

impl Links {
    async fn reconcile(&mut self, desired: Vec<LinkConfig>) {
        let stale: Vec<String> = self
            .handles
            .iter()
            .filter(|(name, h)| {
                h.task.is_finished() || !desired.iter().any(|d| &d.interface == *name)
            })
            .map(|(name, _)| name.clone())
            .collect();
        // Concurrently: each stop may take a few seconds of final RAs.
        let stopping: Vec<_> = stale
            .iter()
            .filter_map(|n| self.handles.remove(n))
            .map(LinkHandle::stop)
            .collect();
        futures::future::join_all(stopping).await;
        for cfg in desired {
            match self.handles.get_mut(&cfg.interface) {
                Some(h) if h.cfg != cfg => {
                    h.cfg = cfg.clone();
                    let _ = h.cfg_tx.send(cfg);
                }
                Some(_) => {}
                None => {
                    let handle = self.spawn(cfg);
                    self.handles.insert(handle.cfg.interface.clone(), handle);
                }
            }
        }
    }

    fn spawn(&self, cfg: LinkConfig) -> LinkHandle {
        let (stop, stop_rx) = watch::channel(false);
        let (cfg_tx, cfg_rx) = watch::channel(cfg.clone());
        let links = self.link_table.clone();
        let name = cfg.interface.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = socket::run(cfg_rx, stop_rx, links).await {
                warn!(interface = %name, error = %e, "radv link ended");
            }
        });
        LinkHandle {
            cfg,
            cfg_tx,
            stop,
            task,
        }
    }

    async fn shutdown(&mut self) {
        let all: Vec<_> = self.handles.drain().map(|(_, h)| h.stop()).collect();
        futures::future::join_all(all).await;
    }
}

/// The kernel device of a subinterface attach point: tag 0 is the physical link
/// itself, a VLAN tag its `<interface>.<tag>` device (as `nos-interfaced` names it).
fn kernel_name(interface: &str, tag: u16) -> String {
    if tag == 0 {
        interface.to_string()
    } else {
        format!("{interface}.{tag}")
    }
}

/// Every attach point whose profile exists. The first attachment of a device wins.
pub fn desired_links(cfg: &Config) -> Vec<LinkConfig> {
    let mut out: Vec<LinkConfig> = Vec::new();
    let mut add = |device: String, profile: Option<&String>| {
        let Some(name) = profile else { return };
        let Some(p) = cfg.ra_profiles.iter().find(|p| &p.name == name) else {
            return;
        };
        if !out.iter().any(|l| l.interface == device) {
            out.push(LinkConfig {
                interface: device,
                profile: p.clone(),
            });
        }
    };
    for i in &cfg.interfaces {
        add(i.name.clone(), i.ra_profile.as_ref());
        for s in &i.subinterfaces {
            add(kernel_name(&i.name, s.tag), s.ra_profile.as_ref());
        }
    }
    out
}

pub async fn run(
    config_socket: PathBuf,
    links: watch::Receiver<LinkTable>,
    mut shutdown: watch::Receiver<bool>,
) {
    let scopes = vec![DiffScope::Interfaces, DiffScope::RaProfiles];
    let mut links = Links {
        link_table: links,
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
                            Some(Ok(Event::Diff(_))) => resync(&config_socket, &mut links).await,
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
                        _ = reapply.tick() => resync(&config_socket, &mut links).await,
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
        tokio::select! {
            () = sleep(RECONNECT_DELAY) => {}
            _ = shutdown.changed() => {}
        }
    }

    links.shutdown().await;
    info!("radv reconciliation loop stopped");
}

async fn resync(config_socket: &Path, links: &mut Links) {
    let cfg = match nos_daemon::config::fetch_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
            return;
        }
    };
    let desired = desired_links(&cfg);
    let count = desired.len();
    links.reconcile(desired).await;
    debug!(count, "reconciled radv links");
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::schema::RaProfile;
    use nos_proto::{Interface, Subinterface};

    fn prof(name: &str) -> RaProfile {
        RaProfile {
            name: name.into(),
            ..RaProfile::default()
        }
    }

    #[test]
    fn attach_points_become_links() {
        let cfg = Config {
            ra_profiles: vec![prof("lan")],
            interfaces: vec![
                Interface {
                    name: "eth0".into(),
                    ra_profile: Some("lan".into()),
                    ..Default::default()
                },
                Interface {
                    name: "eth1".into(),
                    subinterfaces: vec![
                        Subinterface {
                            tag: 0,
                            ra_profile: Some("lan".into()),
                            ..Default::default()
                        },
                        Subinterface {
                            tag: 100,
                            ra_profile: Some("lan".into()),
                            ..Default::default()
                        },
                        Subinterface {
                            tag: 200,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
                Interface {
                    name: "eth2".into(),
                    ra_profile: Some("missing".into()),
                    ..Default::default()
                },
                Interface {
                    name: "eth3".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let names: Vec<_> = desired_links(&cfg)
            .into_iter()
            .map(|l| l.interface)
            .collect();
        assert_eq!(names, ["eth0", "eth1", "eth1.100"]);
    }

    #[test]
    fn a_device_is_attached_once() {
        let cfg = Config {
            ra_profiles: vec![prof("a"), prof("b")],
            interfaces: vec![Interface {
                name: "eth0".into(),
                ra_profile: Some("a".into()),
                subinterfaces: vec![Subinterface {
                    tag: 0,
                    ra_profile: Some("b".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let d = desired_links(&cfg);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].profile.name, "a");
    }
}
