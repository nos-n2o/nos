//! Every phase, by its command-line name, and the CI groups that chain them.

mod acl;
mod bfd;
mod bfd_auth;
mod bfd_echo;
mod bgp;
mod bmp;
mod drivers;
mod ospf;
mod pki;

use anyhow::bail;

use crate::router::log;
use crate::world::World;

/// Runs one phase (or `up`) by name.
pub async fn run(name: &str, w: &mut World) -> anyhow::Result<()> {
    log(format!("=== {name} ==="));
    match name {
        "up" => {
            // NOS_E2E_WATCHDOG_ARGS: space-separated extra nos-watchdogd args
            // (dhat output paths for `mem-wave`, #767).
            let extra = std::env::var("NOS_E2E_WATCHDOG_ARGS").unwrap_or_default();
            w.up(&extra.split_whitespace().collect::<Vec<_>>()).await
        }
        "established" => bgp::established(w).await,
        "reconnect" => bgp::reconnect(w).await,
        "collision" => bgp::collision(w).await,
        "redistribute" => bgp::redistribute_phase(w).await,
        "bgp-graceful-restart" => bgp::bgp_graceful_restart(w).await,
        "ribd-crash-hold" => bgp::ribd_crash_hold(w).await,
        "bgp-routes-paging" => bgp::bgp_routes_paging(w).await,
        "bgp-push-chunked" => bgp::bgp_push_chunked(w).await,
        "bgp-gr-frr" => bgp::bgp_gr_frr(w).await,
        "soft-reconfig-frr" => bgp::soft_reconfig_frr(w).await,
        "bfd" => bfd::bfd(w).await,
        "bgp-bfd" => bfd::bgp_bfd(w).await,
        "bfd-auth" => bfd_auth::bfd_auth(w).await,
        "bfd-padded" => bfd::bfd_padded(w).await,
        "bfd-sbfd" => bfd::bfd_sbfd(w).await,
        "bfd-echo" => bfd_echo::bfd_echo(w).await,
        "bfd-echo-unaffiliated" => bfd_echo::bfd_echo_unaffiliated(w).await,
        "bfd-unsolicited" => bfd::bfd_unsolicited(w).await,
        "auth" => bgp::auth(w).await,
        "ao" => bgp::ao(w).await,
        "gtsm" => bgp::gtsm(w).await,
        "policy" => bgp::policy(w).await,
        "redistribute-policy" => bgp::redistribute_policy(w).await,
        "communities" => bgp::communities(w).await,
        "blackhole" => bgp::blackhole(w).await,
        "mrai" => bgp::mrai(w).await,
        "damping" => bgp::damping(w).await,
        "aggregate" => bgp::aggregate(w).await,
        "shutdown" => bgp::shutdown(w).await,
        "reflector" => bgp::reflector(w).await,
        "route-server" => bgp::route_server(w).await,
        "bgp-multipath" => bgp::bgp_multipath(w).await,
        "as4" => bgp::as4(w).await,
        "malformed-update" => bgp::malformed_update(w).await,
        "maximum-prefix" => bgp::maximum_prefix(w).await,
        "add-path" => bgp::add_path(w).await,
        "route-refresh-stale" => bgp::route_refresh_stale(w).await,
        "confederation" => bgp::confederation(w).await,
        "local-as" => bgp::local_as(w).await,
        "bgp-role" => bgp::bgp_role(w).await,
        "rpki" => bgp::rpki(w).await,
        "bmp" => bmp::bmp(w).await,
        "evpn" => bgp::evpn(w).await,
        "flowspec" => bgp::flowspec(w).await,
        "vpn" => bgp::vpn(w).await,
        "vpn-export" => bgp::vpn_export(w).await,
        "vpn-export-chunked" => bgp::vpn_export_chunked(w).await,
        "vpn-dataplane" => bgp::vpn_dataplane(w).await,
        "vpn-v6" => bgp::vpn_v6(w).await,
        "vpn-multipath" => bgp::vpn_multipath(w).await,
        "evpn-fdb" => bgp::evpn_fdb(w).await,
        "rtc" => bgp::rtc(w).await,
        "evpn-esi" => bgp::evpn_esi(w).await,
        "evpn-dataplane" => bgp::evpn_dataplane(w).await,
        "evpn-single-active" => bgp::evpn_single_active(w).await,
        "evpn-v6" => bgp::evpn_v6(w).await,
        "evpn-l3" => bgp::evpn_l3(w).await,
        "evpn-l3-chunked" => bgp::evpn_l3_chunked(w).await,
        "loopback" => drivers::loopback(w).await,
        "routes-paging" => drivers::routes_paging(w).await,
        "mtu" => drivers::mtu(w).await,
        "port-aggregate" => drivers::port_aggregate(w).await,
        "lacp" => drivers::lacp(w).await,
        "micro-bfd" => drivers::micro_bfd(w).await,
        "lldp" => drivers::lldp(w).await,
        "l2-socket-race" => drivers::l2_socket_race(w).await,
        "switching" => drivers::switching(w).await,
        "stp-failsafe" => drivers::stp_failsafe(w).await,
        "stp-legacy" => drivers::stp_legacy(w).await,
        "stp-protections" => drivers::stp_protections(w).await,
        "stp-mstp" => drivers::stp_mstp(w).await,
        "stp-pvst" => drivers::stp_pvst(w).await,
        "stp" => drivers::stp(w).await,
        "svi" => drivers::svi(w).await,
        "routed-subinterface" => drivers::routed_subinterface(w).await,
        "source-address" => drivers::source_address(w).await,
        "rest" => drivers::rest(w).await,
        "acl" => acl::acl(w).await,
        "flowspec-dataplane" => acl::flowspec_dataplane(w).await,
        "syslog" => drivers::syslog(w).await,
        "ospf" => ospf::ospf_phase(w).await,
        "ospf-p2mp" => ospf::ospf_p2mp(w).await,
        "asbr" => ospf::asbr_phase(w).await,
        "ospf-dr" => ospf::ospf_dr(w).await,
        "ospf-spf" => ospf::ospf_spf(w).await,
        "next-hop-reachability" => bgp::next_hop_reachability(w).await,
        "ospf-lfa" => ospf::ospf_lfa(w).await,
        "ospf-stub-router" => ospf::ospf_stub_router(w).await,
        "ospf-host-router" => ospf::ospf_host_router(w).await,
        "ospf-prefix-suppression" => ospf::ospf_prefix_suppression(w).await,
        "abr" => ospf::abr(w).await,
        "ospf-aging" => ospf::ospf_aging(w).await,
        "ospf-auth" => ospf::ospf_auth(w).await,
        "ospf-mtu-mismatch" => ospf::ospf_mtu_mismatch(w).await,
        "ospf-bfd" => ospf::ospf_bfd(w).await,
        "ospf-graceful-restart" => ospf::ospf_graceful_restart(w).await,
        "ospf-dbd-pagination" => ospf::ospf_dbd_pagination(w).await,
        "ospf-mtu-pagination" => ospf::ospf_mtu_pagination(w).await,
        "ospf-push-chunked" => ospf::ospf_push_chunked(w).await,
        "ospf-stub" => ospf::ospf_stub(w).await,
        "ospf-nssa" => ospf::ospf_nssa(w).await,
        "ospf-external-flood" => ospf::ospf_external_flood(w).await,
        "ospf-virtual-link" => ospf::ospf_virtual_link(w).await,
        "ospf-opaque" => ospf::ospf_opaque(w).await,
        "ospfv3" => ospf::ospfv3_phase(w).await,
        "ospfv3-asbr" => ospf::ospfv3_asbr(w).await,
        "ospfv3-abr" => ospf::ospfv3_abr(w).await,
        "ospfv3-lsinfinity" => ospf::ospfv3_lsinfinity(w).await,
        "ospfv3-lsinfinity-asbr" => ospf::ospfv3_lsinfinity_asbr(w).await,
        "ospfv3-graceful-restart" => ospf::ospfv3_graceful_restart(w).await,
        "ospfv3-auth" => ospf::ospfv3_auth(w).await,
        "ospfv3-mtu-mismatch" => ospf::ospfv3_mtu_mismatch(w).await,
        "ospfv3-instance-id" => ospf::ospfv3_instance_id(w).await,
        "ospfv3-p2p-rid-change" => ospf::ospfv3_p2p_rid_change(w).await,
        "ospfv3-bfd" => ospf::ospfv3_bfd(w).await,
        "ospfv3-dr" => ospf::ospfv3_dr(w).await,
        "ospfv3-lfa" => ospf::ospfv3_lfa(w).await,
        "ospfv3-flush" => ospf::ospfv3_flush(w).await,
        "ospfv3-mtu-pagination" => ospf::ospfv3_mtu_pagination(w).await,
        "ospfv3-router-lsa-split" => ospf::ospfv3_router_lsa_split(w).await,
        "ospf-remote-lfa" => ospf::ospf_remote_lfa(w).await,
        "pki" => pki::pki(w).await,
        "pki-crl" => pki::pki_crl(w).await,
        "pki-rotation" => pki::pki_rotation(w).await,
        "logd-memory" => crate::logd_mem::phase(w).await,
        "config-mem" => crate::logd_mem::config_phase(w).await,
        other => bail!("unknown phase '{other}'"),
    }
}

/// The self-contained CI groups: each starts its own routers and tears them
/// down on exit (unless `VERIFY_E2E_KEEP=1`).
pub fn group(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "base" => &[
            "up",
            "established",
            "reconnect",
            "collision",
            "shutdown",
            "redistribute",
            "bgp-graceful-restart",
            "ribd-crash-hold",
            "bgp-routes-paging",
            "bgp-push-chunked",
            "auth",
            "ao",
            "gtsm",
        ],
        "drivers" => &[
            "up",
            "established",
            "loopback",
            "routes-paging",
            "mtu",
            "port-aggregate",
            "lacp",
            "micro-bfd",
            "lldp",
            "l2-socket-race",
            "switching",
            "stp-failsafe",
            "stp",
            "stp-legacy",
            "stp-protections",
            "stp-mstp",
            "stp-pvst",
            "svi",
            "routed-subinterface",
            "source-address",
            "rest",
            "syslog",
            "acl",
            "flowspec-dataplane",
        ],
        "rpl" => &[
            "up",
            "established",
            "redistribute",
            "policy",
            "redistribute-policy",
            "communities",
            "blackhole",
            "mrai",
            "damping",
            "aggregate",
        ],
        "ospf-suite" => &[
            "up",
            "established",
            "ospf",
            "ospf-p2mp",
            "asbr",
            "ospf-dr",
            "ospf-spf",
            "next-hop-reachability",
            "ospf-lfa",
            "ospf-stub-router",
            "ospf-host-router",
            "ospf-prefix-suppression",
            "abr",
            "ospf-auth",
            "ospf-mtu-mismatch",
            "ospf-bfd",
            "ospf-graceful-restart",
            "ospf-aging",
            "ospf-dbd-pagination",
            "ospf-mtu-pagination",
            "ospf-push-chunked",
            "ospfv3-lsinfinity",
            "ospfv3-lsinfinity-asbr",
            "ospf-stub",
            "ospf-nssa",
            "ospf-external-flood",
            "ospf-virtual-link",
            "ospf-opaque",
            "ospfv3",
            "ospfv3-asbr",
            "ospfv3-abr",
            "ospfv3-graceful-restart",
            "ospfv3-auth",
            "ospfv3-mtu-mismatch",
            "ospfv3-instance-id",
            "ospfv3-p2p-rid-change",
            "ospfv3-bfd",
            "ospfv3-dr",
            "ospfv3-lfa",
            "ospfv3-flush",
            "ospfv3-mtu-pagination",
            "ospfv3-router-lsa-split",
            "ospf-remote-lfa",
        ],
        "multi" => &[
            "as4",
            "malformed-update",
            "maximum-prefix",
            "add-path",
            "route-refresh-stale",
            "confederation",
            "local-as",
            "bgp-role",
            "rpki",
            "bmp",
            "evpn",
            "flowspec",
            "vpn",
            "vpn-export",
            "vpn-export-chunked",
            "vpn-dataplane",
            "vpn-v6",
            "vpn-multipath",
            "vpn-multipath",
            "evpn-fdb",
            "rtc",
            "evpn-esi",
            "evpn-dataplane",
            "evpn-single-active",
            "evpn-v6",
            "evpn-l3",
            "evpn-l3-chunked",
            "reflector",
            "route-server",
            "bgp-multipath",
            "bgp-gr-frr",
            "soft-reconfig-frr",
            "bfd",
            "bgp-bfd",
            "bfd-auth",
            "bfd-padded",
            "bfd-sbfd",
            "bfd-echo",
            "bfd-echo-unaffiliated",
            "bfd-unsolicited",
        ],
        // Self-contained like `ospf-aging`: it needs its own short-lived
        // certificates, so it restarts the routers with them.
        "pki-suite" => &["up", "established", "pki", "pki-rotation"],
        // Slow (20-40 min, 30,000 logins): its own CI job, off the fast pki-suite (#677).
        "pki-crl" => &["up", "established", "pki-crl"],
        // Not run by CI (minutes of runtime, memory thresholds are the flakiest
        // class): `cargo run -p nos-e2e -- logd-memory-lab` by hand (#756).
        "logd-memory-lab" => &["up", "established", "logd-memory"],
        // Same: `cargo run -p nos-e2e -- config-memory-lab` by hand (#776).
        "config-memory-lab" => &["up", "established", "config-mem"],
        _ => return None,
    })
}

/// `all`: every phase in sequence, leaving the containers up for inspection.
pub const ALL: &[&str] = &[
    "up",
    "established",
    "reconnect",
    "collision",
    "shutdown",
    "redistribute",
    "bgp-graceful-restart",
    "ribd-crash-hold",
    "bgp-routes-paging",
    "bgp-push-chunked",
    "auth",
    "ao",
    "gtsm",
    "loopback",
    "routes-paging",
    "mtu",
    "port-aggregate",
    "lacp",
    "micro-bfd",
    "lldp",
    "l2-socket-race",
    "switching",
    "stp-failsafe",
    "stp",
    "stp-legacy",
    "stp-protections",
    "stp-mstp",
    "stp-pvst",
    "svi",
    "routed-subinterface",
    "source-address",
    "rest",
    "syslog",
    "acl",
    "flowspec-dataplane",
    "policy",
    "redistribute-policy",
    "communities",
    "blackhole",
    "mrai",
    "damping",
    "aggregate",
    "evpn",
    "flowspec",
    "vpn",
    "vpn-export",
    "vpn-export-chunked",
    "vpn-dataplane",
    "vpn-v6",
    "vpn-multipath",
    "evpn-fdb",
    "rtc",
    "evpn-esi",
    "evpn-dataplane",
    "evpn-single-active",
    "evpn-v6",
    "evpn-l3",
    "evpn-l3-chunked",
    "reflector",
    "route-server",
    "bgp-multipath",
    "bgp-gr-frr",
    "soft-reconfig-frr",
    "bfd",
    "bgp-bfd",
    "bfd-auth",
    "bfd-padded",
    "bfd-sbfd",
    "bfd-echo",
    "bfd-echo-unaffiliated",
    "bfd-unsolicited",
    "as4",
    "malformed-update",
    "maximum-prefix",
    "add-path",
    "route-refresh-stale",
    "confederation",
    "local-as",
    "bgp-role",
    "rpki",
    "bmp",
    "ospf",
    "ospf-p2mp",
    "asbr",
    "ospf-dr",
    "ospf-spf",
    "next-hop-reachability",
    "ospf-lfa",
    "ospf-stub-router",
    "ospf-host-router",
    "ospf-prefix-suppression",
    "abr",
    "ospf-auth",
    "ospf-mtu-mismatch",
    "ospf-bfd",
    "ospf-graceful-restart",
    "ospf-aging",
    "ospf-dbd-pagination",
    "ospf-mtu-pagination",
    "ospf-push-chunked",
    "ospfv3-lsinfinity",
    "ospfv3-lsinfinity-asbr",
    "ospf-stub",
    "ospf-nssa",
    "ospf-external-flood",
    "ospf-virtual-link",
    "ospf-opaque",
    "ospfv3",
    "ospfv3-asbr",
    "ospfv3-abr",
    "ospfv3-graceful-restart",
    "ospfv3-auth",
    "ospfv3-mtu-mismatch",
    "ospfv3-instance-id",
    "ospfv3-p2p-rid-change",
    "ospfv3-bfd",
    "ospfv3-dr",
    "ospfv3-lfa",
    "ospfv3-flush",
    "ospfv3-mtu-pagination",
    "ospfv3-router-lsa-split",
    "ospf-remote-lfa",
    "pki",
    "pki-rotation",
    "pki-crl",
    "logd-memory",
    "config-mem",
];

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = include_str!("../../../../docs/e2e-phases.md");

    /// Add new groups here. (`run`'s match is not introspectable, so a name in
    /// `ALL` that `run` does not dispatch only fails when run: "unknown phase".)
    const GROUPS: [&str; 9] = [
        "base",
        "drivers",
        "rpl",
        "ospf-suite",
        "multi",
        "pki-suite",
        "pki-crl",
        "logd-memory-lab",
        "config-memory-lab",
    ];

    struct Row {
        phase: String,
        groups: Vec<String>,
        requires: Vec<String>,
    }

    /// The table rows of `docs/e2e-phases.md`: lines starting with ``| ` ``.
    fn rows() -> Vec<Row> {
        let list = |cell: &str| -> Vec<String> {
            cell.split(',')
                .map(|s| s.trim().trim_matches('`').to_owned())
                .filter(|s| !s.is_empty() && s != "-" && s != "self-contained")
                .collect()
        };
        DOC.lines()
            .take_while(|l| !l.starts_with("## ")) // the phase table precedes every section
            .filter(|l| l.starts_with("| `"))
            .map(|l| {
                let cells: Vec<&str> = l.trim_matches('|').split('|').map(str::trim).collect();
                assert_eq!(cells.len(), 5, "row needs 5 cells: {l}");
                Row {
                    phase: cells[0].trim_matches('`').to_owned(),
                    groups: list(cells[2]),
                    requires: list(cells[3]),
                }
            })
            .collect()
    }

    #[test]
    fn doc_table_matches_registry() {
        let rows = rows();
        let names: Vec<&str> = rows.iter().map(|r| r.phase.as_str()).collect();
        for p in ALL {
            assert!(names.contains(p), "docs/e2e-phases.md has no row for `{p}`");
        }
        for n in &names {
            assert!(
                ALL.contains(n),
                "docs/e2e-phases.md row `{n}` is not in phases::ALL"
            );
        }
        assert_eq!(
            names, ALL,
            "table order must equal phases::ALL order (or a row is duplicated)"
        );

        for g in GROUPS {
            let members = group(g).unwrap_or_else(|| panic!("group `{g}` missing"));
            for m in members {
                assert!(ALL.contains(m), "group `{g}` member `{m}` is not in ALL");
            }
        }
        for (i, r) in rows.iter().enumerate() {
            let mut want: Vec<&str> = GROUPS
                .into_iter()
                .filter(|g| group(g).is_some_and(|m| m.contains(&r.phase.as_str())))
                .collect();
            let mut have: Vec<&str> = r.groups.iter().map(String::as_str).collect();
            want.sort_unstable();
            have.sort_unstable();
            assert_eq!(have, want, "Groups cell of `{}`", r.phase);
            for q in &r.requires {
                let at = ALL.iter().position(|p| p == q);
                assert!(
                    at.is_some_and(|at| at < i),
                    "`{}` requires `{q}`, which must be in ALL before it",
                    r.phase
                );
            }
        }
    }
}
