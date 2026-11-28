//! Steady-state loop: subscribes to `Interfaces`/`PortAggregates` diffs
//! purely as a resync trigger, always re-fetching the whole config — same
//! shape as `interface::reconcile::run`/`ospf::reconcile`. Filters
//! `cfg.port_aggregates` for `mode == Lacp`, resolves each one's member
//! set from `cfg.interfaces` (`port_aggregate == Some(name)`), and drives
//! one `AggregateManager` per currently-configured `Lacp`-mode aggregate.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{DiffScope, Event, PortAggregateMode};
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::aggregate::{AggregateManager, PortNumbers, DEFAULT_PRIORITY};
use crate::cscd::V2Cfg;
use crate::interface_client::LacpPush;
use crate::link_client::LinkTable;

/// Every currently-configured `Lacp`-mode aggregate's manager, shared with
/// `server.rs` so `show lacp` can read live state.
pub type SharedAggregates = Arc<Mutex<HashMap<String, Arc<AggregateManager>>>>;

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Same justification as `interface::reconcile::REAPPLY_INTERVAL`: cheap
/// insurance against a missed diff, even though this daemon has no
/// external-readiness dependency the way `nos-interfaced`/`nos-ribd` do.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

pub async fn run(
    config_socket: PathBuf,
    aggregates: SharedAggregates,
    push_tx: mpsc::Sender<LacpPush>,
    links: watch::Receiver<LinkTable>,
    mut shutdown: watch::Receiver<bool>,
) {
    let scopes = vec![DiffScope::Interfaces, DiffScope::PortAggregates];
    let mut next_key: u16 = 1;
    let port_numbers = PortNumbers::default();

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
                                resync(&config_socket, &aggregates, &mut next_key, &push_tx, &port_numbers, &links).await;
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
                            resync(&config_socket, &aggregates, &mut next_key, &push_tx, &port_numbers, &links).await;
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

    for (_, agg) in aggregates.lock().unwrap().drain() {
        agg.shutdown();
    }
    info!("lacp reconciliation loop stopped");
}

async fn resync(
    config_socket: &Path,
    aggregates: &SharedAggregates,
    next_key: &mut u16,
    push_tx: &mpsc::Sender<LacpPush>,
    port_numbers: &PortNumbers,
    links: &watch::Receiver<LinkTable>,
) {
    let cfg = match nos_daemon::config::fetch_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
            return;
        }
    };

    let lacp_aggregates: Vec<&nos_proto::PortAggregate> = cfg
        .port_aggregates
        .iter()
        .filter(|a| a.mode == PortAggregateMode::Lacp)
        .collect();
    let lacp_names: Vec<&str> = lacp_aggregates.iter().map(|a| a.name.as_str()).collect();

    // No `.await` past this point: the lock is a plain std mutex.
    let mut aggregates = aggregates.lock().unwrap();

    let gone: Vec<String> = aggregates
        .keys()
        .filter(|name| !lacp_names.contains(&name.as_str()))
        .cloned()
        .collect();
    for name in gone {
        if let Some(agg) = aggregates.remove(&name) {
            agg.shutdown();
        }
    }

    for agg_cfg in &lacp_aggregates {
        let name = agg_cfg.name.as_str();
        let manager = aggregates
            .entry(name.to_string())
            .or_insert_with(|| {
                let key = *next_key;
                *next_key += 1;
                AggregateManager::new(
                    name,
                    key,
                    push_tx.clone(),
                    port_numbers.clone(),
                    links.clone(),
                )
            })
            .clone();
        let members: Vec<(String, u16, nos_proto::LacpMode)> = cfg
            .interfaces
            .iter()
            .filter(|i| i.port_aggregate.as_deref() == Some(name))
            .map(|i| {
                (
                    i.name.clone(),
                    i.lacp_port_priority.unwrap_or(DEFAULT_PRIORITY),
                    i.lacp_mode,
                )
            })
            .collect();
        // Config validation guarantees it parses; a bad value can only mean a
        // hand-edited file, which falls back to the derived id.
        let system_id = agg_cfg
            .lacp_system_id
            .as_deref()
            .and_then(nos_proto::evpn_id::parse_mac);
        let member_count = members.len();
        let v2 = V2Cfg {
            version: agg_cfg.lacp_version,
            algorithm: agg_cfg.lacp_port_algorithm,
            map: agg_cfg
                .lacp_conversation_map
                .iter()
                .map(|r| (r.first, r.last, r.member.clone()))
                .collect(),
            link_numbers: cfg
                .interfaces
                .iter()
                .filter(|i| i.port_aggregate.as_deref() == Some(name))
                .filter_map(|i| Some((i.name.clone(), i.lacp_link_number?)))
                .collect(),
            members: members.iter().map(|m| m.0.clone()).collect(),
        };
        let fallback: HashMap<String, (bool, u16)> = cfg
            .interfaces
            .iter()
            .filter(|i| i.port_aggregate.as_deref() == Some(name))
            .map(|i| {
                (
                    i.name.clone(),
                    (i.lacp_fallback, i.lacp_fallback_timeout.unwrap_or(30)),
                )
            })
            .collect();
        manager.reconcile_v2(
            members,
            agg_cfg.lacp_rate,
            system_id,
            agg_cfg.lacp_system_priority.unwrap_or(DEFAULT_PRIORITY),
            agg_cfg.min_links,
            &v2,
            &fallback,
        );
        if usize::from(agg_cfg.min_links) > member_count {
            warn!(
                aggregate = name,
                min_links = agg_cfg.min_links,
                members = member_count,
                "lacp min-links exceeds the configured member count, the bond stays empty"
            );
        }
    }

    debug!(count = lacp_names.len(), "reconciled lacp aggregates");
}

/// Local copy of `nos-watchdog::supervisor::wait_or_shutdown` — not
/// imported, per the star-dependency rule.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}
