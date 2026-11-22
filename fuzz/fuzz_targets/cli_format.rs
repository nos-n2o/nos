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
    Diff(p::ConfigDiff, bool),
}

fuzz_target!(|input: Input| {
    match input {
        Input::Sub(x) => drop(f::render_subinterface_status(&x)),
        Input::If(x) => drop(f::render_interface_status(&x)),
        Input::Ifs(x) => drop(f::render_interface_statuses(&x)),
        Input::Agg(x) => drop(f::render_port_aggregate_status(&x)),
        Input::Aggs(x) => drop(f::render_port_aggregate_statuses(&x)),
        Input::Lldp(x) => drop((
            f::render_lldp_neighbors(&x),
            f::render_lldp_neighbors_detail(&x),
        )),
        Input::LldpStats(x) => drop(f::render_lldp_statistics(&x)),
        Input::LldpDetail(x) => drop(f::render_lldp_neighbors(&x)),
        Input::BfdReflector(x) => drop(f::render_bfd_reflector(&x)),
        Input::BfdSessions(x) => drop(f::render_bfd_sessions(&x)),
        Input::Acls(x) => drop(f::render_acls(&x)),
        Input::Flowspec(x) => drop(f::render_flowspec_rules(&x)),
        Input::Stp(s, id, dom, has_id, has_dom) => {
            f::render_spanning_tree(&s);
            f::render_stp_domain(&s, &dom);
            f::render_mst_config(&s);
            f::render_stp_instance(&s, id);
            f::render_stp_detail(&s, has_id.then_some(id), has_dom.then_some(dom.as_str()));
        }
        Input::Lacp(x) => drop(f::render_lacp_summaries(&x)),
        Input::Utc(x) => drop(f::utc(x)),
        Input::Log(x) => drop(f::render_log_entry(&x)),
        Input::Logs(x) => drop(f::render_log_entries(&x)),
        Input::Routes(x) => drop(f::render_prefix_routes(&x)),
        Input::BgpSummary(i, x) => drop(f::render_bgp_summary(&i, &x)),
        Input::Evpn(i, x) => drop((f::render_bgp_evpn(&i, &x), f::render_bgp_evpn_lines(&x))),
        Input::Vpn(i, fam, x) => {
            drop((f::render_bgp_vpn(&i, fam, &x), f::render_bgp_vpn_lines(&x)))
        }
        Input::FlowRoutes(i, x) => drop((
            f::render_bgp_flowspec(&i, &x),
            f::render_bgp_flowspec_lines(&x),
        )),
        Input::BgpRoutes(i, x) => drop((
            f::render_bgp_routes(&i, &x),
            f::render_bgp_routes_header(&i),
            f::render_bgp_route_lines(&x),
        )),
        Input::Rpki(i, x) => drop(f::render_bgp_rpki(&i, &x)),
        Input::Bmp(i, x) => drop(f::render_bgp_bmp(&i, &x)),
        Input::Ospf(i, n, d) => drop((
            f::render_ospf_neighbors(&i, &n),
            f::render_ospf_database(&i, &d),
        )),
        Input::Ospfv3(i, n, d) => drop((
            f::render_ospfv3_neighbors(&i, &n),
            f::render_ospfv3_database(&i, &d),
        )),
        Input::Config(c) => {
            f::render_config(&c);
            f::render_admin_config(&c);
        }
        Input::Transaction(t, path) => drop(f::render_transaction(&t, &path.into())),
        Input::Source(s) => drop(f::render_policy_source(&s)),
        Input::Fdb(x) => drop(f::render_fdb_table(&x)),
        Input::Diff(d, color) => drop(f::render_diff(&d, color)),
    }
});
