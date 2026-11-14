use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{DiffScope, Event};
use tokio::sync::{watch, RwLock};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::driver::InterfaceDriver;
use crate::state::{build_from_config, Interfaces};
use nos_daemon::config;

/// Fixed reconnect delay for the config subscription, matching
/// `nos-rib`'s `reconcile::RECONNECT_DELAY`/`nos-watchdog`'s
/// `bgp_instances::RECONNECT_DELAY` for consistency across the codebase's
/// config-subscribing consumers.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// How often to re-apply desired state even without a new config diff.
/// Needed because `nos-interfaced` depends on an external, non-config
/// condition — the owning `nos-ribd` instance having allocated/created its
/// VRF, reported over IPC (see `driver::linux`) — that no config commit
/// ever signals; this is what makes that dependency eventually converge.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

/// Runs until `shutdown` fires. Subscribes to `Interfaces`, `BroadcastDomains`,
/// `SwitchingProfiles`, and `PortAggregates` diffs purely as an edge
/// trigger: every `Event::Diff` received (including the first, synthesized
/// one) causes a full `resync` — a fresh `Request::Get` plus a from-scratch
/// `Interfaces` rebuild — rather than incremental diff application, since
/// `SectionDiff`/`FieldDiff` only carry pre-formatted display strings, not
/// structured data (mirrors `nos-rib`'s `reconcile::run`). `BroadcastDomains`/
/// `SwitchingProfiles`/`PortAggregates` are included so a domain/profile/
/// aggregate-only edit (no `Interface` object itself touched) still
/// triggers a resync — otherwise a newly added `BroadcastDomain`/
/// `PortAggregate` wouldn't get its bridge/bond created until some
/// unrelated interface change happened to resync anyway. A periodic tick
/// alongside the diff stream also triggers `resync`, independent of any
/// config change — see `REAPPLY_INTERVAL`.
pub async fn run(
    config_socket: PathBuf,
    interfaces: Arc<RwLock<Interfaces>>,
    driver: Arc<dyn InterfaceDriver>,
    mut shutdown: watch::Receiver<bool>,
) {
    let scopes = vec![
        DiffScope::Interfaces,
        DiffScope::BroadcastDomains,
        DiffScope::SwitchingProfiles,
        DiffScope::PortAggregates,
        DiffScope::SpanningTree,
    ];
    while !*shutdown.borrow() {
        match config::subscribe_diff(&config_socket, scopes.clone()).await {
            Ok(mut reader) => {
                info!(socket = %config_socket.display(), "connected to nos-configd diff stream");
                let mut reapply = tokio::time::interval(REAPPLY_INTERVAL);
                reapply.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Consume the immediate first tick: the diff stream's own
                // synthesized first `Event::Diff` already triggers a
                // resync, so this would otherwise be a redundant duplicate.
                reapply.tick().await;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &interfaces, driver.as_ref()).await;
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
                            resync(&config_socket, &interfaces, driver.as_ref()).await;
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

    info!("reconciliation loop stopped");
}

async fn resync(
    config_socket: &Path,
    interfaces: &Arc<RwLock<Interfaces>>,
    driver: &dyn InterfaceDriver,
) {
    match config::fetch_config(config_socket).await {
        Ok(cfg) => {
            let previous = interfaces.read().await.clone();
            let mut new_interfaces = build_from_config(&cfg, driver, &previous).await;
            debug!(count = cfg.interfaces.len(), "reconciled interfaces");
            // A push (lacpd, bfdd, stpd) may have landed while the build ran:
            // `live` holds the newest, so it wins and is re-applied (#617).
            let mut live = interfaces.write().await;
            let adopted = new_interfaces.adopt_pushed(&live);
            *live = new_interfaces;
            drop(live);
            for i in adopted.interfaces {
                if let Err(e) = driver.apply(&i).await {
                    warn!(interface = %i.name, error = %e, "failed to re-apply pushed state");
                }
            }
            for a in adopted.aggregates {
                if let Err(e) = driver.ensure_port_aggregate(&a).await {
                    warn!(port_aggregate = %a.name, error = %e, "failed to re-apply err-disabled");
                }
            }
            for (port, state) in adopted.stp_writes {
                if let Err(e) = driver.set_bridge_port_state(&port, state).await {
                    warn!(port = ?port, error = %e, "failed to re-apply bridge port state");
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
        }
    }
}

/// Local copy of `nos-watchdog::supervisor::wait_or_shutdown` — not
/// imported, per the star-dependency rule.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}
