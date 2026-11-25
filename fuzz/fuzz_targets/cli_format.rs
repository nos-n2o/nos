#![no_main]
//! Every `nos-cli` `format::render_*` on arbitrary daemon replies: none may panic (#1216).
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use nos_cli::format as f;
use nos_proto as p;

#[derive(Arbitrary, Debug)]
enum Input {
    Sub(p::SubinterfaceStatus),
    If(p::InterfaceStatus),
    Ifs(Vec<p::InterfaceStatus>),
    Agg(p::PortAggregateStatus),
    Aggs(Vec<p::PortAggregateStatus>),
    Lldp(Vec<p::LldpNeighbor>),
    LldpDetail(Vec<p::LldpNeighbor>),
    LldpStats(Vec<p::LldpLinkStats>),
    BfdReflector(p::ReflectorView),
    BfdSessions(Vec<p::BfdSessionView>),
    Acls(Vec<p::AclStatus>),
    Flowspec(Vec<p::FlowspecRuleStatus>),
    Stp(p::StpSummary, u16, String, bool, bool),
    Lacp(Vec<p::PortAggregateLacpSummary>),
    Utc(u64),
    Log(p::LogEntry),
    Logs(Vec<p::LogEntry>),
    Routes(Vec<p::PrefixRoutes>),
    BgpSummary(String, Vec<p::PeerSummary>),
    Evpn(String, Vec<p::EvpnRouteSummary>),
    Vpn(String, p::AddressFamily, Vec<p::VpnRouteSummary>),
    FlowRoutes(String, Vec<p::FlowspecRouteSummary>),
    BgpRoutes(String, Vec<p::BgpRouteSummary>),
    Rpki(String, Vec<p::RpkiCacheStatus>),
    Bmp(String, Vec<p::BmpStationStatus>),
    Ospf(String, Vec<p::NeighborSummary>, Vec<p::LsaSummary>),
    Ospfv3(
        String,
        Vec<p::Ospfv3NeighborSummary>,
        Vec<p::Ospfv3LsaSummary>,
    ),
    Config(p::Config),
    Transaction(p::TransactionSnapshot, Vec<String>),
    Source(String),
    Fdb(p::FdbTable),
    FdbFlat(
        Vec<(String, p::MacEntry)>,
        Vec<(String, p::NeighEntry)>,
        Option<String>,
    ),
    Diff(p::ConfigDiff, bool),
}

/// No control character other than `\n`/`\t` may reach the terminal (#1365).
fn is_bad(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

fuzz_target!(|input: Input| {
    let mut outs: Vec<String> = Vec::new();
    // `render_diff(_, true)` adds its own SGR codes: strip them before checking.
    let mut diff_color = false;
    match input {
        Input::Sub(x) => outs.push(f::render_subinterface_status(&x)),
        Input::If(x) => outs.push(f::render_interface_detail(&x)),
        Input::Ifs(x) => outs.push(f::render_interface_details(&x)),
        Input::Agg(x) => outs.push(f::render_port_aggregate_status(&x)),
        Input::Aggs(x) => outs.push(f::render_port_aggregate_statuses(&x)),
        Input::Lldp(x) => outs.extend([
            f::render_lldp_neighbors(&x),
            f::render_lldp_neighbors_detail(&x),
        ]),
        Input::LldpStats(x) => outs.push(nos_cli::view::render(&x, "")),
        Input::LldpDetail(x) => outs.push(f::render_lldp_neighbors_detail(&x)),
        Input::BfdReflector(x) => outs.push(f::render_bfd_reflector(&x)),
        Input::BfdSessions(x) => outs.push(f::render_bfd_sessions(&x)),
        Input::Acls(x) => outs.push(nos_cli::view::render(&x, "")),
        Input::Flowspec(x) => outs.push(nos_cli::view::render(&x, "")),
        Input::Stp(s, id, dom, has_id, has_dom) => {
            outs.push(f::render_spanning_tree(&s));
            outs.push(f::render_stp_domain(&s, &dom));
            outs.push(f::render_mst_config(&s));
            outs.push(f::render_stp_instance(&s, id));
            outs.push(f::render_stp_detail(
                &s,
                has_id.then_some(id),
                has_dom.then_some(dom.as_str()),
            ));
        }
        Input::Lacp(x) => {
            outs.push(f::render_lacp_tables(&x));
            outs.push(f::render_lacp_detail(&x));
        }
        Input::Utc(x) => outs.push(f::utc(x)),
        Input::Log(x) => outs.push(f::render_log_entry(&x)),
        Input::Logs(x) => outs.push(f::render_log_entries(&x)),
        Input::Routes(x) => outs.push(f::render_prefix_routes(&x)),
        Input::BgpSummary(i, x) => outs.push(f::render_bgp_summary(&i, &x)),
        Input::Evpn(i, x) => {
            outs.extend([f::render_bgp_evpn(&i, &x), f::render_bgp_evpn_lines(&x)])
        }
        Input::Vpn(i, fam, x) => {
            outs.extend([f::render_bgp_vpn(&i, fam, &x), f::render_bgp_vpn_lines(&x)])
        }
        Input::FlowRoutes(i, x) => outs.extend([
            f::render_bgp_flowspec(&i, &x),
            f::render_bgp_flowspec_lines(&x),
        ]),
        Input::BgpRoutes(i, x) => outs.extend([
            f::render_bgp_routes(&i, &x),
            f::render_bgp_routes_header(&i),
            f::render_bgp_route_lines(&x),
        ]),
        Input::Rpki(_, x) => outs.push(nos_cli::view::render(&x, "")),
        Input::Bmp(i, x) => outs.push(f::render_bgp_bmp(&i, &x)),
        Input::Ospf(i, n, d) => outs.extend([
            nos_cli::view::render(&n, ""),
            f::render_ospf_database(&i, &d),
        ]),
        Input::Ospfv3(i, n, d) => outs.extend([
            nos_cli::view::render(&n, ""),
            f::render_ospfv3_database(&i, &d),
        ]),
        Input::Config(c) => {
            outs.push(f::render_config(&c));
            outs.push(f::render_admin_config(&c));
        }
        Input::Transaction(t, path) => outs.push(f::render_transaction(&t, &path.into())),
        Input::Source(s) => outs.push(f::render_policy_source(&s)),
        Input::Fdb(x) => outs.push(nos_cli::view::render(&x, "")),
        Input::FdbFlat(m, n, mac) => outs.push(f::render_fdb_flat(&m, &n, mac.as_deref())),
        Input::Diff(d, color) => {
            diff_color = color;
            outs.push(f::render_diff(&d, color));
        }
    }
    for out in outs {
        let out = if diff_color {
            [
                "\x1b[31m",
                "\x1b[32m",
                "\x1b[1;4m",
                "\x1b[22;24m",
                "\x1b[0m",
            ]
            .iter()
            .fold(out, |acc, c| acc.replace(c, ""))
        } else {
            out
        };
        assert!(!out.chars().any(is_bad), "raw control char in {out:?}");
    }
});
