use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nos_proto::{DiffScope, Event, ServiceRef, SourceAddress, LOOPBACK_PREFIX};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::bfd_client;
use crate::fsm;
use crate::interface_client;
use crate::policy::PolicyCache;
use crate::rib_client;
use crate::session::{LocalIdentity, ResolvedAuth, ResolvedPeer, SessionManager, VrfRequirement};
use nos_daemon::config;
use nos_daemon::watchdog;

/// Fixed reconnect delay for the config subscription, matching every other
/// config-subscribing consumer in this codebase (`nos-rib`/`nos-interface`'s
/// `reconcile::RECONNECT_DELAY`, `nos-watchdog`'s `bgp_instances::RECONNECT_DELAY`).
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// How often to re-apply desired state even without a new config diff —
/// needed because VRF readiness (the owning `nos-ribd` instance having
/// created its VRF) is an external condition no config commit signals, same
/// as `nos-interface`'s `reconcile::REAPPLY_INTERVAL`.
const REAPPLY_INTERVAL: Duration = Duration::from_secs(10);

/// Runs until `shutdown` fires. Subscribes to `BgpInstances`/`RoutingTables`
/// diffs purely as a resync trigger (mirrors `nos-rib`/`nos-interface`'s
/// reconcile loops) — the actual state always comes from a fresh
/// `fetch_config` call, plus a periodic tick independent of any config
/// change.
pub async fn run(
    config_socket: PathBuf,
    watchdog_socket: PathBuf,
    instance: String,
    sessions: Arc<SessionManager>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut policy_cache = PolicyCache::default();
    // Whether the graceful-restart startup check (`restart_check`) is done.
    let mut restart_decided = false;
    while !*shutdown.borrow() {
        match config::subscribe_diff(
            &config_socket,
            vec![
                DiffScope::BgpInstances,
                DiffScope::RoutingTables,
                DiffScope::BroadcastDomains,
                DiffScope::PolicyDefinitions,
                DiffScope::CommunityAliases,
                DiffScope::CommunityGroups,
                DiffScope::PrefixLists,
                DiffScope::AsPathLists,
                DiffScope::BfdProfiles,
                DiffScope::Admin,
            ],
        )
        .await
        {
            Ok(mut reader) => {
                info!(instance = %instance, "connected to nos-configd diff stream");
                let mut reapply = tokio::time::interval(REAPPLY_INTERVAL);
                reapply.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // The diff stream's own synthesized first event already
                // triggers a resync below — skip the immediate first tick
                // so it isn't a redundant duplicate.
                reapply.tick().await;
                loop {
                    tokio::select! {
                        event = reader.next() => match event {
                            Some(Ok(Event::Diff(_))) => {
                                resync(&config_socket, &watchdog_socket, &instance, &sessions, &mut policy_cache, &mut restart_decided).await;
                            }
                            Some(Ok(_)) => {}
                            Some(Err(e)) => {
                                warn!(error = %e, "error reading diff stream, reconnecting");
                                break;
                            }
                            None => {
                                warn!("diff stream closed, reconnecting");
                                break;
                            }
                        },
                        _ = reapply.tick() => {
                            resync(&config_socket, &watchdog_socket, &instance, &sessions, &mut policy_cache, &mut restart_decided).await;
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

    sessions.shutdown().await;
    info!(instance = %instance, "reconciliation loop stopped");
}

/// The configured peers, each joined with its peer-group's settings, split
/// out of `resync` for length (#425).
fn resolve_peers(
    own: &nos_proto::BgpInstance,
    source_addrs: &HashMap<&str, Vec<IpAddr>>,
    policy_cache: &mut PolicyCache,
    cfg: &nos_proto::Config,
) -> Vec<ResolvedPeer> {
    let mut peers: Vec<ResolvedPeer> = Vec::new();
    for peer in &own.peers {
        let Some(group) = own.peer_groups.iter().find(|g| g.name == peer.peer_group) else {
            continue;
        };
        let source_address = source_addrs.get(group.name.as_str()).and_then(|addrs| {
            addrs
                .iter()
                .find(|a| a.is_ipv4() == peer.remote_address.is_ipv4())
                .copied()
        });
        peers.push(ResolvedPeer {
            remote_address: peer.remote_address,
            source_address,
            remote_as: group.remote_as,
            peer_group: peer.peer_group.clone(),
            hold_time: group.hold_time.unwrap_or(nos_proto::HOLD_TIME_DEFAULT),
            keepalive_interval: group.keepalive_interval,
            connect_retry_time: group
                .connect_retry_time
                .map_or(fsm::CONNECT_RETRY_TIME, |s| {
                    Duration::from_secs(u64::from(s))
                }),
            mrai: Duration::from_secs(u64::from(group.mrai.unwrap_or(0))),
            route_refresh_stale_time: Duration::from_secs(u64::from(
                group
                    .route_refresh_stale_time
                    .unwrap_or(nos_proto::ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS),
            )),
            damping: group.damping,
            max_hops: group.max_hops,
            auth: group
                .auth
                .as_ref()
                .and_then(|a| ResolvedAuth::resolve(a, cfg)),
            next_hop: group.next_hop,
            address_families: group.address_families.clone(),
            route_reflector_client: group.route_reflector_client,
            route_server_client: group.route_server_client,
            import_policy: policy_cache.resolve(group.import_policy.as_deref()),
            export_policy: policy_cache.resolve(group.export_policy.as_deref()),
            evpn_import_policy: group
                .evpn_import_policy
                .as_deref()
                .map(|n| policy_cache.resolve(Some(n))),
            flowspec_import_policy: group
                .flowspec_import_policy
                .as_deref()
                .map(|n| policy_cache.resolve(Some(n))),
            flowspec_export_policy: group
                .flowspec_export_policy
                .as_deref()
                .map(|n| policy_cache.resolve(Some(n))),
            shutdown: peer.shutdown.clone().or_else(|| group.shutdown.clone()),
            maximum_prefix: group.maximum_prefix,
            announce_rpki_state: group.announce_rpki_state,
            soft_reconfiguration_inbound: group.soft_reconfiguration_inbound,
            blackhole: group.blackhole.as_ref().map(|b| {
                Arc::new(
                    cfg.prefix_lists
                        .iter()
                        .filter(|l| l.name == b.prefix_list)
                        .flat_map(|l| &l.entries)
                        .map(|e| nos_rpl::PrefixListEntry {
                            cidr: e.cidr,
                            range: e.range,
                        })
                        .collect(),
                )
            }),
            local_as: group.local_as,
            enforce_first_as: group.enforce_first_as.unwrap_or(true),
            flowspec_validation: group.flowspec_validation,
            add_path: group.effective_add_path(),
            add_path_send_count: group.effective_add_path_send_count(),
            role: group.role,
            strict_mode: group.strict_mode,
            confed_id: own.confederation.identifier,
            confed_member: own.confederation.is_member(group.remote_as),
            graceful_restart: own.graceful_restart.enabled_restart_time(),
        });
    }
    peers
}

/// Each peer's RFC 8326 knobs from its group. Kept out of `ResolvedPeer` so
/// toggling them never resets a session; only peers with a knob on appear.
pub(crate) fn gs_knobs(own: &nos_proto::BgpInstance) -> HashMap<IpAddr, crate::rib::GsKnobs> {
    own.peers
        .iter()
        .filter_map(|peer| {
            let g = own.peer_groups.iter().find(|g| g.name == peer.peer_group)?;
            let k = crate::rib::GsKnobs {
                send: g.graceful_shutdown,
                receive_off: g.graceful_shutdown_receive_disabled,
            };
            (k != crate::rib::GsKnobs::default()).then_some((peer.remote_address, k))
        })
        .collect()
}

async fn resync(
    config_socket: &Path,
    watchdog_socket: &Path,
    instance: &str,
    sessions: &Arc<SessionManager>,
    policy_cache: &mut PolicyCache,
    restart_decided: &mut bool,
) {
    let cfg = match config::fetch_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(error = %e, "failed to fetch running config, keeping previous state");
            return;
        }
    };

    policy_cache.resync(
        &cfg.policy_definitions,
        &cfg.community_aliases,
        &cfg.community_groups,
        &cfg.prefix_lists,
        &cfg.as_path_lists,
    );

    let Some(own) = cfg.bgp_instances.iter().find(|i| i.name == instance) else {
        // The watchdog would be tearing this process down anyway if the
        // instance were genuinely removed from config.
        error!(instance = %instance, "own bgp instance missing from running config");
        return;
    };

    let resolved = match &own.routing_table {
        Some(table) => resolve_vrf(watchdog_socket, table).await,
        None => None,
    };
    let mut vrf = classify_vrf(own.routing_table.as_ref(), resolved);
    match &vrf {
        VrfRequirement::Invalid => error!(
            instance = %instance,
            "BGP instance has no owning routing table, refusing to open any session"
        ),
        VrfRequirement::Pending => debug!(
            instance = %instance,
            table = ?own.routing_table,
            "routing table's vrf not resolvable yet"
        ),
        VrfRequirement::Resolved(name) => {
            debug!(instance = %instance, vrf = %name, "resolved bgp instance's vrf");
        }
    }

    // One `nos-interfaced` query per peer-group that configures a
    // source-address (not per peer) — every peer in the group shares the
    // same reference, so this avoids a redundant round trip per peer.
    let mut source_addrs: HashMap<&str, Vec<IpAddr>> = HashMap::new();
    for group in &own.peer_groups {
        if let Some(source) = &group.source_address {
            let addrs =
                resolve_source_address(watchdog_socket, own.routing_table.as_deref(), source).await;
            if addrs.is_empty() {
                debug!(
                    peer_group = %group.name,
                    "peer-group source-address not resolvable yet"
                );
            } else {
                info!(
                    peer_group = %group.name,
                    addresses = ?addrs,
                    "resolved peer-group source-address"
                );
            }
            source_addrs.insert(group.name.as_str(), addrs);
        }
    }

    let peers = resolve_peers(own, &source_addrs, policy_cache, &cfg);

    let local = LocalIdentity {
        asn: own.asn,
        router_id: own.router_id,
        cluster_id: own.cluster_id.unwrap_or(own.router_id),
        confed_id: own.confederation.identifier,
    };

    // Unlike `import_policy`/`export_policy`, `None` here means accept-all,
    // not deny-all — redistribution has no filtering unless a policy is
    // explicitly configured (see `nos_proto::Redistribute.policy`'s doc
    // comment), so the default is resolved here rather than by
    // `PolicyCache::resolve` (whose `None => deny_all` stays correct for its
    // only other caller, peer import/export).
    let redistribute_policy = match own.redistribute_policy.as_deref() {
        None => Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        Some(name) => policy_cache.resolve(Some(name)),
    };

    // The broadcast domains that `redistribute from mac to bgp` this instance
    // — the ones whose `nos-fdbd` gets every received EVPN route.
    let mut fdb_domains: Vec<String> = cfg
        .broadcast_domains
        .iter()
        .filter(|d| d.vni.is_some() && d.mac_redistribute.as_deref() == Some(instance))
        .map(|d| d.name.clone())
        .collect();
    // The IP-VRFs whose `evpn` rides this (underlay) instance — fed every
    // received Type-5 route.
    let mut evpn_tables: Vec<String> = cfg
        .routing_tables
        .iter()
        .filter(|t| t.evpn.l3_vni.is_some() && t.evpn.bgp_instance.as_deref() == Some(instance))
        .map(|t| t.name.clone())
        .collect();
    // The VRFs whose `vpn` rides this (underlay) instance (RFC 4364 import).
    let mut vpn_vrfs = crate::vpn::VrfSet::from_config(&cfg, instance);
    // RFC 4684: our membership is every import RT of this instance.
    let mut rtc_membership = crate::rib::rtc_membership(&cfg, instance);

    let mut routing_table = own.routing_table.clone();
    if !*restart_decided {
        *restart_decided = restart_check(watchdog_socket, own, &vrf, &peers, sessions).await;
    }
    if !*restart_decided {
        // Until it is decided, no session starts and nothing is pushed, so
        // a restarted process can't empty `nos-ribd` before it knows.
        vrf = VrfRequirement::Pending;
        routing_table = None;
        fdb_domains.clear();
        evpn_tables.clear();
        vpn_vrfs = crate::vpn::VrfSet::default();
        rtc_membership.clear();
    }

    // After the restart decision: `routing_table` is cleared until then.
    sessions.set_bfd_targets(match (&vrf, &routing_table) {
        (VrfRequirement::Resolved(_), Some(table)) => {
            bfd_target(&cfg, own, table.clone(), &source_addrs)
        }
        _ => bfd_client::Target::default(),
    });
    sessions.set_maximum_paths(own.maximum_paths).await;
    sessions.set_graceful_shutdown(gs_knobs(own)).await;
    sessions
        .set_gr_stale_time(own.graceful_restart.stale_time())
        .await;
    sessions
        .reconcile(
            vrf,
            routing_table,
            local,
            peers,
            redistribute_policy,
            fdb_domains,
            evpn_tables,
            &own.rpki_caches,
            crate::rpki::resolve_auths(&own.rpki_caches, &cfg),
        )
        .await;
    let table_rd = own.routing_table.as_ref().and_then(|t| {
        cfg.routing_tables
            .iter()
            .find(|r| &r.name == t)
            .and_then(|r| r.vpn.rd.as_deref())
            .and_then(nos_proto::evpn_id::parse_rd)
    });
    sessions
        .set_bmp_stations(&own.bmp_stations, own.routing_table.clone(), table_rd)
        .await;
    // After `reconcile`, which sets the local ASN/router-id the AGGREGATOR
    // attribute carries.
    sessions.set_aggregates(own.aggregates.clone()).await;
    sessions.set_vpn_vrfs(vpn_vrfs).await;
    sessions.set_rtc_membership(rtc_membership).await;
}

/// The BFD sessions `own`'s peers want: a non-shut peer whose peer-group
/// names a `bfd` profile. The profile is not part of `ResolvedPeer`, so
/// adding or removing `bfd` never resets a session.
///
/// A peer is multihop (RFC 5883) when its peer-group has `max-hops` > 1 or
/// the address is on no connected subnet of the table in the config
/// (`Config::is_connected`); `local` is the peer-group's `source-address`
/// when it resolved. ponytail: a peer reached over a connected subnet that is
/// not in the config (DHCP) is registered multihop, which still works.
fn bfd_target(
    cfg: &nos_proto::Config,
    own: &nos_proto::BgpInstance,
    table: String,
    source_addrs: &HashMap<&str, Vec<IpAddr>>,
) -> bfd_client::Target {
    let mut peers = HashMap::new();
    for peer in &own.peers {
        let Some(group) = own.peer_groups.iter().find(|g| g.name == peer.peer_group) else {
            continue;
        };
        let Some(name) = &group.bfd else { continue };
        if peer.shutdown.is_some() || group.shutdown.is_some() {
            continue;
        }
        if let Some(profile) = cfg.bfd_profiles.iter().find(|p| &p.name == name) {
            let local = source_addrs.get(group.name.as_str()).and_then(|a| {
                a.iter()
                    .find(|a| a.is_ipv4() == peer.remote_address.is_ipv4())
                    .copied()
            });
            peers.insert(
                peer.remote_address,
                bfd_client::Want {
                    profile: profile.clone(),
                    multihop: group.max_hops.is_some_and(|h| h > 1)
                        || !cfg.is_connected(&table, peer.remote_address),
                    local,
                },
            );
        }
    }
    bfd_client::Target { table, peers }
}

/// RFC 4724 §4.1, once per process before any session starts: if graceful
/// restart is on and the owning `nos-ribd` still holds BGP routes (a
/// restarted `nos-bgpd`, `nos-ribd` kept running), our forwarding state was
/// preserved — start selection deferral. `false` (retry next pass) while the
/// VRF or the count isn't answerable yet.
async fn restart_check(
    watchdog_socket: &Path,
    own: &nos_proto::BgpInstance,
    vrf: &VrfRequirement,
    peers: &[ResolvedPeer],
    sessions: &SessionManager,
) -> bool {
    let Some(restart_time) = own.graceful_restart.enabled_restart_time() else {
        return true;
    };
    let (VrfRequirement::Resolved(_), Some(table)) = (vrf, &own.routing_table) else {
        return matches!(vrf, VrfRequirement::Invalid);
    };
    let Some(socket) =
        watchdog::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.clone())).await
    else {
        return false;
    };
    let Some(routes) = rib_client::get_bgp_route_count(&socket).await else {
        debug!(table = %table, "bgp route count not answerable yet");
        return false;
    };
    if routes > 0 {
        let peers = peers
            .iter()
            .filter(|p| p.shutdown.is_none())
            .map(|p| p.remote_address);
        sessions
            .begin_deferral(
                routes,
                restart_time,
                own.graceful_restart.selection_deferral_time(),
                peers,
            )
            .await;
    }
    true
}

/// Resolves `table`'s Linux VRF interface name by asking the owning
/// `nos-ribd` instance directly over IPC (see `crate::rib_client`),
/// resolved via the watchdog broker — never derived locally. `None` covers
/// every "not answerable yet" case uniformly (broker doesn't know that
/// table, connect failure, rib hasn't created a VRF yet), all retried by
/// the caller's periodic re-apply tick.
async fn resolve_vrf(watchdog_socket: &Path, table: &str) -> Option<String> {
    let socket =
        watchdog::resolve_once(watchdog_socket, &ServiceRef::RibTable(table.to_string())).await?;
    rib_client::get_vrf_name(&socket).await
}

/// Resolves a peer-group's `SourceAddress` reference to every candidate
/// local address (both families — the caller picks the one matching each
/// peer's own remote-address family), querying `nos-interfaced` directly
/// (resolved via the watchdog broker's `ServiceRef::Interfaces`, mirroring
/// `resolve_vrf`'s `ServiceRef::RibTable` + `nos-ribd` query). An empty
/// result covers every "not resolvable right now" case uniformly
/// (`nos-interfaced` unreachable, the referenced interface not configured
/// yet, no address under the requested label, or — for `Loopback` — this
/// instance having no owning routing table to derive the loopback's name
/// from) — retried by the caller's periodic re-apply tick, same as
/// `resolve_vrf`.
async fn resolve_source_address(
    watchdog_socket: &Path,
    own_routing_table: Option<&str>,
    source: &SourceAddress,
) -> Vec<IpAddr> {
    let (interface, label, is_loopback) = match source {
        SourceAddress::Interface { interface, label } => (interface.clone(), label.clone(), false),
        SourceAddress::Loopback { label } => {
            let Some(table) = own_routing_table else {
                warn!(
                    "peer-group's source-address is loopback but this instance has no owning \
                     routing table to derive it from"
                );
                return Vec::new();
            };
            (format!("{LOOPBACK_PREFIX}{table}"), label.clone(), true)
        }
    };
    let Some(socket) = watchdog::resolve_once(watchdog_socket, &ServiceRef::Interfaces).await
    else {
        return Vec::new();
    };
    let Some(status) = interface_client::get_interface(&socket, &interface).await else {
        return Vec::new();
    };
    // A loopback interface still carries its addresses flat (`status.addresses`,
    // unchanged); every other interface's addresses live under its tag-0
    // (untagged/native) subinterface instead — see
    // `schema::valid_addressing_split`.
    let addresses = if is_loopback {
        status.addresses
    } else {
        status
            .subinterfaces
            .into_iter()
            .find(|s| s.tag == 0)
            .map(|s| s.addresses)
            .unwrap_or_default()
    };
    addresses
        .into_iter()
        .filter(|a| label.is_none() || a.label == label)
        .map(|a| a.address.addr())
        .collect()
}

/// Pure classification of the three-way VRF requirement (see
/// `session::VrfRequirement`) from a `BgpInstance`'s reflexive
/// `routing_table` reference and, if set, that table's resolved VRF name.
fn classify_vrf(routing_table: Option<&String>, resolved: Option<String>) -> VrfRequirement {
    match routing_table {
        None => VrfRequirement::Invalid,
        Some(_) => match resolved {
            Some(name) => VrfRequirement::Resolved(name),
            None => VrfRequirement::Pending,
        },
    }
}

/// Local copy of `nos-watchdog::supervisor::wait_or_shutdown` — not
/// imported, per the star-dependency rule.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a non-shut peer in a peer-group naming a known profile is
    /// registered; multihop when `max-hops` > 1 or off every connected subnet.
    #[test]
    fn bfd_target_picks_guarded_peers_and_their_hop_mode() {
        let own: nos_proto::BgpInstance = serde_json::from_value(serde_json::json!({
            "name": "r1", "asn": 65001, "router_id": "1.1.1.1",
            "peers": [
                {"remote_address": "10.0.0.1", "peer_group": "g"},
                {"remote_address": "10.0.0.2", "peer_group": "plain"},
                {"remote_address": "10.0.0.3", "peer_group": "far"},
                {"remote_address": "2.2.2.2", "peer_group": "g"},
            ],
            "peer_groups": [
                {"name": "g", "remote_as": 65002, "address_families": [], "route_reflector_client": false, "route_server_client": false, "bfd": "fast"},
                {"name": "plain", "remote_as": 65002, "address_families": [], "route_reflector_client": false, "route_server_client": false},
                {"name": "far", "remote_as": 65002, "address_families": [], "route_reflector_client": false, "route_server_client": false, "bfd": "fast", "max_hops": 5},
            ],
        }))
        .unwrap();
        let cfg = nos_proto::Config {
            bfd_profiles: vec![nos_proto::schema::BfdProfile {
                name: "fast".into(),
                ..Default::default()
            }],
            interfaces: vec![nos_proto::Interface {
                name: "eth1".into(),
                subinterfaces: vec![nos_proto::schema::interface::Subinterface {
                    routing_table: Some("rt1".into()),
                    addresses: vec![nos_proto::schema::interface::InterfaceAddress {
                        address: "10.0.0.254/24".parse().unwrap(),
                        label: None,
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let src: HashMap<&str, Vec<IpAddr>> =
            HashMap::from([("g", vec!["1.1.1.1".parse().unwrap()])]);
        let t = bfd_target(&cfg, &own, "rt1".into(), &src);
        let hop = |p: &str| {
            let w = &t.peers[&p.parse::<IpAddr>().unwrap()];
            (w.multihop, w.local)
        };
        assert_eq!(t.peers.len(), 3, "the unguarded peer-group is left out");
        assert_eq!(hop("10.0.0.1"), (false, Some("1.1.1.1".parse().unwrap())));
        assert_eq!(hop("10.0.0.3"), (true, None), "max-hops 5");
        assert_eq!(hop("2.2.2.2"), (true, Some("1.1.1.1".parse().unwrap())));
        let none = nos_proto::Config::default();
        assert!(bfd_target(&none, &own, "rt1".into(), &src).peers.is_empty());
    }

    #[test]
    fn no_owning_table_is_invalid() {
        assert_eq!(classify_vrf(None, None), VrfRequirement::Invalid);
    }

    #[test]
    fn owning_table_with_no_resolved_vrf_is_pending() {
        let table = "rt1".to_string();
        assert_eq!(classify_vrf(Some(&table), None), VrfRequirement::Pending);
    }

    #[test]
    fn owning_table_with_resolved_vrf_is_resolved() {
        let table = "rt1".to_string();
        assert_eq!(
            classify_vrf(Some(&table), Some("vrf100".to_string())),
            VrfRequirement::Resolved("vrf100".to_string())
        );
    }
}

#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod resync_tests;
