use std::fmt::Write as _;
use std::net::Ipv4Addr;

use nos_proto::{
    BgpSessionState, Config, ConfigDiff, DiffStatus, EvpnRouteSummary, FieldDiff,
    FlowspecRouteSummary, InterfaceAddress, InterfaceStatus, LacpMuxState, LacpRate,
    LacpReceiveState, LinkOper, LogEntry, LogLevel, LsaSummary, Ospfv3LsaSummary, PeerSummary,
    PortAggregateLacpSummary, PortAggregateStatus, PrefixRoutes, RouteSourceKind, SectionDiff,
    SubinterfaceStatus, TransactionSnapshot,
};
use time::OffsetDateTime;

use nos_proto::cli::render;

use crate::session::Path;

use std::borrow::Cow;

use crate::table::{human_duration, table, Col};

/// One STP port row (the three port types share these fields) plus its flags.
macro_rules! stp_row {
    ($p:expr, $flags:expr) => {{
        let p = $p;
        (
            vec![
                p.name.clone(),
                p.role.as_str().to_string(),
                p.state.as_str().to_string(),
                p.cost.to_string(),
                p.priority.to_string(),
                if p.designated_bridge.is_empty() {
                    "-".to_string()
                } else {
                    format!("{} {}", p.designated_bridge, p.designated_port)
                },
            ],
            $flags,
        )
    }};
}

fn aggregate_mode_word(m: nos_proto::PortAggregateMode) -> &'static str {
    match m {
        nos_proto::PortAggregateMode::Xor => "xor",
        nos_proto::PortAggregateMode::Lacp => "lacp",
    }
}

fn bmp_state_word(s: nos_proto::BmpStationState) -> &'static str {
    match s {
        nos_proto::BmpStationState::Connecting => "connecting",
        nos_proto::BmpStationState::Connected => "connected",
        nos_proto::BmpStationState::Backoff => "backoff",
    }
}

fn bmp_monitor_word(m: nos_proto::BmpMonitor) -> &'static str {
    match m {
        nos_proto::BmpMonitor::PostPolicy => "post-policy",
        nos_proto::BmpMonitor::PrePolicy => "pre-policy",
        nos_proto::BmpMonitor::Both => "both",
    }
}

/// Escape a daemon-supplied string for the terminal (#1365): every control
/// char (C0 incl. ESC, DEL, C1) except `\n` and `\t`, and the bidi/zero-width
/// format chars that reorder or hide text, becomes a visible `\xNN` /
/// `\u{NNNN}`. Borrows when already clean. A literal `\x1b` sent by a peer is
/// indistinguishable from an escaped ESC (accepted, display-only).
pub fn sanitize(s: &str) -> Cow<'_, str> {
    escape(s, false)
}

/// `sanitize` for a value inside a one-record-per-line renderer: `\n` is
/// escaped too, so a multi-line value cannot forge a row.
pub fn sanitize_line(s: &str) -> Cow<'_, str> {
    escape(s, true)
}

fn needs_escape(c: char, line: bool) -> bool {
    match c {
        '\t' => false,
        '\n' => line,
        _ => {
            c.is_control()
                || matches!(c, '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
        }
    }
}

fn escape(s: &str, line: bool) -> Cow<'_, str> {
    if !s.chars().any(|c| needs_escape(c, line)) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if !needs_escape(c, line) {
            out.push(c);
        } else if c == '\n' {
            out.push_str("\\n");
        } else if (c as u32) <= 0xFF {
            let _ = write!(out, "\\x{:02x}", c as u32);
        } else {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        }
    }
    Cow::Owned(out)
}

fn format_address(addr: &InterfaceAddress) -> String {
    match &addr.label {
        Some(label) => format!("{} (label {})", addr.address, sanitize_line(label)),
        None => addr.address.to_string(),
    }
}

/// Render one subinterface's daemon-reported status — the wire twin of
/// `render_subinterface`.
pub fn render_subinterface_status(status: &SubinterfaceStatus) -> String {
    sanitize(&render_subinterface_status_raw(status)).into_owned()
}

fn render_subinterface_status_raw(status: &SubinterfaceStatus) -> String {
    let addresses = if status.addresses.is_empty() {
        "none".to_string()
    } else {
        status
            .addresses
            .iter()
            .map(format_address)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let routing_table = sanitize_line(status.routing_table.as_deref().unwrap_or("unset"));
    format!(
        "subinterface {}: address [{addresses}], routing-table {routing_table}, mtu {}",
        status.tag, status.mtu
    )
}

/// `show interface <name>`: a hand-written link-state header, then the view
/// engine's detail block of the status.
pub fn render_interface_detail(status: &InterfaceStatus) -> String {
    sanitize(&render_interface_detail_raw(status)).into_owned()
}

/// Bare `show interface`: the detail of every interface, blank-line separated.
pub fn render_interface_details(statuses: &[InterfaceStatus]) -> String {
    if statuses.is_empty() {
        return "no interfaces".to_string();
    }
    let all = statuses
        .iter()
        .map(render_interface_detail)
        .collect::<Vec<_>>()
        .join("\n\n");
    sanitize(&all).into_owned()
}

/// `eth0 is up, oper up (last change 2d03h ago)`; `-` when unobserved.
fn interface_header(name: &str, link: Option<&LinkOper>) -> String {
    let name = sanitize_line(name);
    let Some(l) = link else {
        return format!("{name} is -, oper -");
    };
    let admin = if l.down_reason.as_deref() == Some("absent") {
        "absent"
    } else if l.admin_up {
        "up"
    } else {
        "administratively down"
    };
    let oper = if l.oper_up { "up" } else { "down" };
    let mut notes = Vec::new();
    if let Some(r) = &l.down_reason {
        notes.push(sanitize_line(r).into_owned());
    }
    if let Some(secs) = l.last_change_secs {
        notes.push(format!("last change {} ago", human_duration(secs)));
    }
    if notes.is_empty() {
        format!("{name} is {admin}, oper {oper}")
    } else {
        format!("{name} is {admin}, oper {oper} ({})", notes.join(", "))
    }
}

fn address_strings(v: &serde_json::Value) -> serde_json::Value {
    let list: Vec<InterfaceAddress> = serde_json::from_value(v.clone()).unwrap_or_default();
    if list.is_empty() {
        return serde_json::Value::Null;
    }
    list.iter().map(format_address).collect()
}

fn render_interface_detail_raw(status: &InterfaceStatus) -> String {
    let mut value = crate::view::to_value(status);
    // The engine prints an array of objects as JSON: hand it display strings.
    let mut link_local = value["link_local_address"].clone();
    value["addresses"] = address_strings(&value["addresses"]);
    if let Some(subs) = value["subinterfaces"].as_array_mut() {
        for sub in subs {
            if link_local.is_null() {
                link_local = sub["link_local_address"].clone();
            }
            sub["addresses"] = address_strings(&sub["addresses"]);
        }
    }
    value["link_local_address"] = link_local;
    let head = interface_header(&status.name, status.link.as_ref());
    match nos_proto::view::view_of::<InterfaceStatus>() {
        Some(node) => format!("{head}\n{}", crate::view::render_detail(node, &value)),
        None => head,
    }
}

fn brief_row(
    name: String,
    link: Option<&LinkOper>,
    speed_mbps: Option<u32>,
    mtu: u32,
    vrf: Option<&str>,
    member: Option<&str>,
    addresses: &[InterfaceAddress],
) -> Vec<String> {
    let (admin, oper) = match link {
        None => ("-".to_string(), "-".to_string()),
        Some(l) => {
            let oper = if l.oper_up { "up" } else { "down" };
            (
                (if l.admin_up { "up" } else { "down" }).to_string(),
                match &l.down_reason {
                    Some(r) => format!("{oper} ({r})"),
                    None => oper.to_string(),
                },
            )
        }
    };
    let dash = |s: Option<&str>| s.map_or("-".to_string(), str::to_string);
    vec![
        name,
        admin,
        oper,
        speed_mbps.map_or("-".to_string(), |n| format!("{n} Mb/s")),
        mtu.to_string(),
        dash(vrf),
        dash(member),
        if addresses.is_empty() {
            "-".to_string()
        } else {
            addresses
                .iter()
                .map(format_address)
                .collect::<Vec<_>>()
                .join(", ")
        },
    ]
}

/// Rows of one device: the device itself (merged with its untagged tag-0
/// sub-link, which carries the L3 config of the same kernel device), then one
/// row per tagged subinterface as `<name>.<tag>`.
fn brief_rows(
    name: &str,
    link: Option<&LinkOper>,
    speed_mbps: Option<u32>,
    mtu: u32,
    flat: (Option<&str>, &[InterfaceAddress]),
    member: Option<&str>,
    subs: &[SubinterfaceStatus],
) -> Vec<Vec<String>> {
    let tag0 = subs.iter().find(|s| s.tag == 0);
    let mut addresses = flat.1.to_vec();
    if let Some(t) = tag0 {
        addresses.extend(t.addresses.iter().cloned());
    }
    let vrf = flat
        .0
        .or_else(|| tag0.and_then(|t| t.routing_table.as_deref()));
    let mut rows = vec![brief_row(
        name.to_string(),
        link,
        speed_mbps,
        mtu,
        vrf,
        member,
        &addresses,
    )];
    for s in subs.iter().filter(|s| s.tag != 0) {
        rows.push(brief_row(
            format!("{name}.{}", s.tag),
            s.link.as_ref(),
            None,
            s.mtu,
            s.routing_table.as_deref(),
            None,
            &s.addresses,
        ));
    }
    rows
}

/// `show interface brief`: one table of every interface, tagged
/// subinterface and port aggregate.
pub fn render_interface_brief(
    interfaces: &[InterfaceStatus],
    aggregates: &[PortAggregateStatus],
) -> String {
    let mut rows = Vec::new();
    for i in interfaces {
        rows.extend(brief_rows(
            &i.name,
            i.link.as_ref(),
            i.speed_mbps,
            i.mtu,
            (i.routing_table.as_deref(), &i.addresses),
            i.port_aggregate.as_deref(),
            &i.subinterfaces,
        ));
    }
    for a in aggregates {
        rows.extend(brief_rows(
            &a.name,
            a.link.as_ref(),
            a.speed_mbps,
            a.mtu,
            (None, &[]),
            None,
            &a.subinterfaces,
        ));
    }
    if rows.is_empty() {
        return "no interfaces".to_string();
    }
    let cols = [
        Col::left("Interface"),
        Col::left("Admin"),
        Col::left("Oper"),
        Col::right("Speed"),
        Col::right("MTU"),
        Col::left("VRF"),
        Col::left("Member"),
        Col::left("Addresses"),
    ];
    sanitize(&table(&cols, &rows)).into_owned()
}

/// Render one port aggregate's daemon-reported status — the `PortAggregate`
/// counterpart of `render_interface_detail`.
pub fn render_port_aggregate_status(status: &PortAggregateStatus) -> String {
    sanitize(&render_port_aggregate_status_raw(status)).into_owned()
}

fn render_port_aggregate_status_raw(status: &PortAggregateStatus) -> String {
    let switching_profile = status.switching_profile.as_deref().unwrap_or("unset");
    let mut lines = vec![format!(
        "port-aggregate {}: mode {}, switching-profile {}, mtu {}",
        sanitize_line(&status.name),
        aggregate_mode_word(status.mode),
        sanitize_line(switching_profile),
        status.mtu
    )];
    if status.err_disabled {
        lines.push("  Err-disabled: yes".to_string());
    }
    for sub in &status.subinterfaces {
        lines.push(format!("  {}", render_subinterface_status(sub)));
    }
    lines.join("\n")
}

/// Render every port aggregate's daemon-reported status, one per line — used
/// for both `show port-aggregate` (many entries) and `show port-aggregate
/// <name>` (one).
pub fn render_port_aggregate_statuses(statuses: &[PortAggregateStatus]) -> String {
    sanitize(&render_port_aggregate_statuses_raw(statuses)).into_owned()
}

fn render_port_aggregate_statuses_raw(statuses: &[PortAggregateStatus]) -> String {
    if statuses.is_empty() {
        return "no port aggregates".to_string();
    }
    statuses
        .iter()
        .map(render_port_aggregate_status)
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.map(|b| format!("{b:02x}")).join(":")
}

fn render_lacp_port(port: &nos_proto::LacpPortStatus) -> String {
    let receive = match port.receive_state {
        LacpReceiveState::Initialize => "initialize",
        LacpReceiveState::PortDisabled => "port-disabled",
        LacpReceiveState::LacpDisabled => "lacp-disabled",
        LacpReceiveState::Expired => "expired",
        LacpReceiveState::Defaulted => "defaulted",
        LacpReceiveState::Current => "current",
    };
    let mux = match port.mux_state {
        LacpMuxState::Detached => "detached",
        LacpMuxState::Waiting => "waiting",
        LacpMuxState::Attached => "attached",
        LacpMuxState::Collecting => "collecting",
        LacpMuxState::Distributing => "distributing",
    };
    // Defaulted, or never heard (Expired with the all-zero system): the
    // daemon reports the administrative default, shown as no partner.
    let defaulted = port.receive_state == nos_proto::LacpReceiveState::Defaulted
        || port.partner_system_id.is_none_or(|s| s == [0; 6]);
    let partner = match (port.partner_system_id, port.partner_key) {
        _ if defaulted => "partner none (defaulted)".to_string(),
        (Some(system), Some(key)) => format!(
            "partner {} key {key} port {}",
            format_mac(system),
            port.partner_port_number.unwrap_or(0)
        ),
        _ => "partner none".to_string(),
    };
    let mode = match port.mode {
        nos_proto::LacpMode::Active => "active",
        nos_proto::LacpMode::Passive => "passive",
    };
    let partner_priority = match (port.partner_system_priority, port.partner_port_priority) {
        (Some(system), Some(port)) => format!(", partner priority {system}/{port}"),
        _ => String::new(),
    };
    let individual = if port.individual {
        ", individual (partner not aggregatable)"
    } else {
        ""
    };
    format!(
        "  {}: port {}, receive {receive}, mux {mux}, {partner}, selected {}, synchronized {}, churn {}, port priority {}{partner_priority}, mode {mode}{individual}, unsupported-version PDUs {}",
        sanitize_line(&port.interface),
        port.actor_port_number,
        yes_no(port.selected),
        yes_no(port.synchronized),
        match (port.actor_churn, port.partner_churn) {
            (false, false) => "none",
            (true, false) => "actor",
            (false, true) => "partner",
            (true, true) => "actor+partner",
        },
        port.actor_port_priority,
        port.unsupported_version_pdus,
    )
}

/// Render `nos-lldpd`'s neighbor table, for `show lldp neighbors`.
pub fn render_lldp_neighbors(neighbors: &[nos_proto::LldpNeighbor]) -> String {
    sanitize(&render_lldp_neighbors_raw(neighbors)).into_owned()
}

fn render_lldp_neighbors_raw(neighbors: &[nos_proto::LldpNeighbor]) -> String {
    if neighbors.is_empty() {
        return "no lldp neighbors".to_string();
    }
    neighbors
        .iter()
        .map(|n| {
            let capabilities = if n.capabilities.is_empty() {
                "none".to_string()
            } else {
                sanitize_line(&n.capabilities.join(",")).into_owned()
            };
            let description = n
                .port_description
                .as_deref()
                .filter(|d| *d != n.port_id)
                .map_or_else(String::new, |d| format!(" ({})", sanitize_line(d)));
            let management = if n.management_addresses.is_empty() {
                String::new()
            } else {
                format!(
                    ", management {}",
                    sanitize_line(&n.management_addresses.join(","))
                )
            };
            format!(
                "{}: neighbor {}, chassis {}, port {}{description}, capabilities {capabilities}{management}, ttl {}s",
                sanitize_line(&n.local_interface),
                sanitize_line(n.system_name.as_deref().unwrap_or("unnamed")),
                sanitize_line(&n.chassis_id),
                sanitize_line(&n.port_id),
                n.ttl_remaining_secs,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render `nos-lldpd`'s neighbor table one block per neighbor, for `show lldp
/// neighbors detail`: every field, the optional ones only when sent.
pub fn render_lldp_neighbors_detail(neighbors: &[nos_proto::LldpNeighbor]) -> String {
    sanitize(&render_lldp_neighbors_detail_raw(neighbors)).into_owned()
}

fn render_lldp_neighbors_detail_raw(neighbors: &[nos_proto::LldpNeighbor]) -> String {
    if neighbors.is_empty() {
        return "no lldp neighbors".to_string();
    }
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    neighbors
        .iter()
        .map(|n| {
            let mut lines = vec![
                format!(
                    "{}: neighbor {}",
                    sanitize_line(&n.local_interface),
                    sanitize_line(n.system_name.as_deref().unwrap_or("unnamed"))
                ),
                format!("  chassis {}", sanitize_line(&n.chassis_id)),
                format!("  port {}", sanitize_line(&n.port_id)),
            ];
            let mut opt = |label: &str, value: Option<String>| {
                if let Some(v) = value {
                    lines.push(format!("  {label} {}", sanitize_line(&v)));
                }
            };
            opt("port-description", n.port_description.clone());
            opt("system-description", n.system_description.clone());
            opt(
                "capabilities",
                (!n.capabilities.is_empty()).then(|| n.capabilities.join(",")),
            );
            opt(
                "management",
                (!n.management_addresses.is_empty()).then(|| n.management_addresses.join(",")),
            );
            opt(
                "vlans",
                (!n.vlan_names.is_empty()).then(|| {
                    n.vlan_names
                        .iter()
                        .map(|v| format!("{} ({})", v.id, v.name))
                        .collect::<Vec<_>>()
                        .join(", ")
                }),
            );
            opt("port-vlan-id", n.port_vlan_id.map(|v| v.to_string()));
            opt(
                "aggregation",
                n.link_aggregation.map(|a| match (a.enabled, a.capable) {
                    (true, _) => format!("aggregated, port id {}", a.port_id),
                    (false, true) => "capable, not aggregated".to_string(),
                    (false, false) => "not capable".to_string(),
                }),
            );
            opt("max-frame-size", n.max_frame_size.map(|s| s.to_string()));
            opt(
                "mac/phy",
                n.mac_phy.map(|m| {
                    format!(
                        "autoneg supported {}, enabled {}, advertised 0x{:04x}, mau-type {}",
                        yes_no(m.autoneg_supported),
                        yes_no(m.autoneg_enabled),
                        m.advertised,
                        m.mau_type
                    )
                }),
            );
            lines.push(format!("  ttl {}s", n.ttl_remaining_secs));
            lines.join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render the S-BFD reflector, for `show bfd reflector`: its discriminators
/// (as the IPv4 addresses they are configured as) and the counters.
pub fn render_bfd_reflector(v: &nos_proto::ReflectorView) -> String {
    sanitize(&render_bfd_reflector_raw(v)).into_owned()
}

fn render_bfd_reflector_raw(v: &nos_proto::ReflectorView) -> String {
    if v.discriminators.is_empty() {
        return "sbfd reflector: off (no discriminator configured)".to_string();
    }
    let d = &v.discarded;
    let reasons: Vec<String> = [
        ("malformed", d.malformed),
        ("source-port-7784", d.source_port),
        ("martian-source", d.martian),
        ("not-in-allow-from", d.filtered),
        ("rate-limited", d.rate_limited),
        ("authenticated", d.authenticated),
        ("demand-bit-clear", d.demand_clear),
        ("unknown-discriminator", d.unknown_discriminator),
    ]
    .iter()
    .filter(|(_, n)| *n > 0)
    .map(|(r, n)| format!("{r} {n}"))
    .collect();
    let discriminators: Vec<String> = v
        .discriminators
        .iter()
        .map(|d| std::net::Ipv4Addr::from(*d).to_string())
        .collect();
    let dropped = if reasons.is_empty() {
        "none".to_string()
    } else {
        reasons.join(", ")
    };
    format!(
        "sbfd reflector: discriminators {}\nreceived {}, replied {}, dropped: {dropped}",
        discriminators.join(" "),
        v.received,
        v.replied
    )
}

/// Render `nos-stpd`'s summary, for `show spanning-tree`: the bridge/root
/// block, then one row per port.
pub fn render_spanning_tree(s: &nos_proto::StpSummary) -> String {
    sanitize(&render_spanning_tree_raw(s)).into_owned()
}

fn render_spanning_tree_raw(s: &nos_proto::StpSummary) -> String {
    if !s.enabled {
        return "spanning-tree is disabled".to_string();
    }
    if s.mode == nos_proto::StpMode::RapidPvst {
        let rows: Vec<Vec<String>> = s
            .pvst
            .iter()
            .map(|t| {
                vec![
                    t.domains.join(","),
                    t.id.to_string(),
                    t.root_id.clone(),
                    t.root_port
                        .as_deref()
                        .unwrap_or("(this bridge is the root)")
                        .to_string(),
                ]
            })
            .collect();
        let mut lines = vec![
            format!("mode {}", mode_word(s.mode)),
            format!(
                "bridge id {} (priority; each VLAN adds its id)",
                s.bridge_id
            ),
        ];
        if !rows.is_empty() {
            lines.push(String::new());
            lines.push(table(
                &[
                    Col::left("Domain"),
                    Col::right("VLAN"),
                    Col::left("Root id"),
                    Col::left("Root port"),
                ],
                &rows,
            ));
        }
        return lines.join("\n");
    }
    let root = match &s.root_port {
        Some(p) => format!("root port {p}, cost {}", s.root_path_cost),
        None => "this bridge is the root".to_string(),
    };
    let mut lines = vec![
        format!("mode {}", mode_word(s.mode)),
        format!("bridge id {}", s.bridge_id),
        format!("root id   {} ({root})", s.root_id),
        format!(
            "hello {}s, max age {}s, forward delay {}s",
            s.hello_time_secs, s.max_age_secs, s.forward_delay_secs
        ),
    ];
    if s.ports.is_empty() {
        lines.push("no spanning-tree ports".to_string());
        return lines.join("\n");
    }
    lines.push(String::new());
    lines.push(stp_port_table(
        s.ports.iter().map(|p| stp_row!(p, stp_flags(p))).collect(),
    ));
    lines.join("\n")
}

/// The shared STP port table; a `Flags` column only when some port has one.
fn stp_port_table(rows: Vec<(Vec<String>, String)>) -> String {
    let flagged = rows.iter().any(|(_, f)| !f.is_empty());
    let mut cols = vec![
        Col::left("Name"),
        Col::left("Role"),
        Col::left("State"),
        Col::right("Cost"),
        Col::right("Prio"),
        Col::left("Designated"),
    ];
    if flagged {
        cols.push(Col::left("Flags"));
    }
    let rows: Vec<Vec<String>> = rows
        .into_iter()
        .map(|(mut r, f)| {
            if flagged {
                r.push(f);
            }
            r
        })
        .collect();
    table(&cols, &rows)
}

fn mode_word(m: nos_proto::StpMode) -> &'static str {
    match m {
        nos_proto::StpMode::Mstp => "mstp",
        nos_proto::StpMode::RapidPvst => "rapid-pvst",
        _ => "rstp",
    }
}

const NOT_MSTP: &str = "spanning-tree is not in mode mstp";

/// `show spanning-tree domain <bd>`: one Rapid-PVST+ tree.
pub fn render_stp_domain(s: &nos_proto::StpSummary, domain: &str) -> String {
    sanitize(&render_stp_domain_raw(s, domain)).into_owned()
}

fn render_stp_domain_raw(s: &nos_proto::StpSummary, domain: &str) -> String {
    if s.mode != nos_proto::StpMode::RapidPvst {
        return "spanning-tree is not in mode rapid-pvst".to_string();
    }
    let Some(i) = s
        .pvst
        .iter()
        .find(|i| i.domains.iter().any(|d| d == domain))
    else {
        return format!("no spanning-tree tree for domain {domain}");
    };
    let root = match &i.root_port {
        Some(p) => format!("root port {p}, cost {}", i.root_path_cost),
        None => "this bridge is the root".to_string(),
    };
    let lines = [
        format!("domain    {domain}"),
        format!("vlan      {}", i.vlans),
        format!("bridge id {}", i.bridge_id),
        format!("root id   {} ({root})", i.root_id),
        String::new(),
        stp_port_table(
            i.ports
                .iter()
                .map(|p| {
                    let mut f = Vec::new();
                    if p.compat {
                        f.push("Compat");
                    }
                    if p.inconsistent {
                        f.push("PVID-inconsistent");
                    }
                    stp_row!(p, f.join(" "))
                })
                .collect(),
        ),
    ];
    lines.join("\n")
}

/// `show spanning-tree mst-config`: the region identity, then the VLAN map.
pub fn render_mst_config(s: &nos_proto::StpSummary) -> String {
    sanitize(&render_mst_config_raw(s)).into_owned()
}

fn render_mst_config_raw(s: &nos_proto::StpSummary) -> String {
    let Some(m) = &s.mst else {
        return NOT_MSTP.to_string();
    };
    let lines = [
        format!("name     {}", m.region_name),
        format!("revision {}", m.revision),
        format!("digest   {}", m.digest),
        format!("max hops {}", m.max_hops),
        String::new(),
        table(
            &[
                Col::right("Instance"),
                Col::left("VLANs"),
                Col::left("Domains"),
            ],
            &m.instances
                .iter()
                .map(|i| {
                    vec![
                        i.id.to_string(),
                        if i.vlans.is_empty() { "-" } else { &i.vlans }.to_string(),
                        if i.domains.is_empty() {
                            "-".to_string()
                        } else {
                            i.domains.join(",")
                        },
                    ]
                })
                .collect::<Vec<_>>(),
        ),
    ];
    lines.join("\n")
}

/// `show spanning-tree instance <id>`: one tree's root and ports.
pub fn render_stp_instance(s: &nos_proto::StpSummary, id: u16) -> String {
    sanitize(&render_stp_instance_raw(s, id)).into_owned()
}

fn render_stp_instance_raw(s: &nos_proto::StpSummary, id: u16) -> String {
    let Some(m) = &s.mst else {
        return NOT_MSTP.to_string();
    };
    let Some(i) = m.instances.iter().find(|i| i.id == id) else {
        return format!("no spanning-tree instance {id}");
    };
    let root = match &i.root_port {
        Some(p) => format!("root port {p}, cost {}", i.root_path_cost),
        None => "this bridge is the root".to_string(),
    };
    let lines = [
        format!(
            "instance {} ({})",
            i.id,
            if i.id == 0 { "CIST" } else { "MSTI" }
        ),
        format!(
            "vlans     {}",
            if i.vlans.is_empty() { "-" } else { &i.vlans }
        ),
        format!("bridge id {}", i.bridge_id),
        format!("root id   {} ({root})", i.root_id),
        String::new(),
        stp_port_table(
            i.ports
                .iter()
                .map(|p| stp_row!(p, if p.boundary { "Boundary" } else { "" }.to_string()))
                .collect(),
        ),
    ];
    lines.join("\n")
}

/// `last change 12s ago via eth1 (received)`, or `no change yet`.
fn stp_topology_line(t: &nos_proto::StpTopology) -> String {
    let last = match (t.last_secs_ago, &t.last_port, t.last_cause) {
        (Some(ago), Some(port), Some(cause)) => format!(
            "last change {ago}s ago via {port} ({})",
            match cause {
                nos_proto::StpTcCause::Local => "local",
                nos_proto::StpTcCause::Received => "received",
            }
        ),
        _ => "no change yet".to_string(),
    };
    format!("topology changes {}, {last}", t.count)
}

/// One port's detail block: operational status, then the RFC 4318 counters.
fn stp_port_detail(
    name: &str,
    edge: bool,
    p2p: bool,
    extra: &str,
    c: &nos_proto::StpPortCounters,
) -> Vec<String> {
    let extra = if extra.is_empty() {
        String::new()
    } else {
        format!(", {extra}")
    };
    vec![
        format!(
            "{name}: edge {}, point-to-point {}{extra}",
            yes_no(edge),
            yes_no(p2p)
        ),
        format!(
            "  in:  config {}, tcn {}, rstp {}, mst {}",
            c.in_config_bpdu, c.in_tcn_bpdu, c.in_rstp_bpdu, c.in_mst_bpdu
        ),
        format!(
            "  out: config {}, tcn {}, rstp {}, mst {}",
            c.out_config_bpdu, c.out_tcn_bpdu, c.out_rstp_bpdu, c.out_mst_bpdu
        ),
        format!(
            "  topology-change sent {}, received {}; protocol-migration {}; invalid-bpdu {}; forward-transitions {}",
            c.tc_sent, c.tc_received, c.protocol_migration, c.invalid_bpdu, c.forward_transitions
        ),
    ]
}

/// The detail block of one tree, behind a blank line (and a title when
/// several trees follow each other).
fn stp_instance_detail(i: &nos_proto::StpInstance, title: bool) -> Vec<String> {
    let mut lines = vec![String::new()];
    if title {
        lines.push(format!("domain {}", i.domains.join(",")));
    }
    lines.push(stp_topology_line(&i.topology));
    for p in &i.ports {
        let extra: Vec<&str> = [
            (p.boundary, "boundary"),
            (p.compat, "compat"),
            (p.inconsistent, "pvid-inconsistent"),
        ]
        .into_iter()
        .filter_map(|(on, name)| on.then_some(name))
        .collect();
        lines.extend(stp_port_detail(
            &p.name,
            p.edge,
            p.point_to_point,
            &extra.join(", "),
            &p.counters,
        ));
    }
    lines
}

/// `show spanning-tree [instance <id> | domain <bd>] detail`: the same tables
/// as without `detail`, then the topology changes and the counters.
pub fn render_stp_detail(
    s: &nos_proto::StpSummary,
    instance: Option<u16>,
    domain: Option<&str>,
) -> String {
    sanitize(&render_stp_detail_raw(s, instance, domain)).into_owned()
}

fn render_stp_detail_raw(
    s: &nos_proto::StpSummary,
    instance: Option<u16>,
    domain: Option<&str>,
) -> String {
    let mut out = if let Some(d) = domain {
        render_stp_domain(s, d)
    } else if let Some(id) = instance {
        render_stp_instance(s, id)
    } else {
        render_spanning_tree(s)
    };
    let mut tail = Vec::new();
    if let Some(id) = instance {
        for i in s
            .mst
            .iter()
            .flat_map(|m| &m.instances)
            .filter(|i| i.id == id)
        {
            tail.extend(stp_instance_detail(i, false));
        }
    } else if let Some(d) = domain {
        for i in s.pvst.iter().filter(|i| i.domains.iter().any(|n| n == d)) {
            tail.extend(stp_instance_detail(i, false));
        }
    } else if s.mode == nos_proto::StpMode::RapidPvst {
        for i in &s.pvst {
            tail.extend(stp_instance_detail(i, true));
        }
    } else if s.enabled {
        tail.push(String::new());
        tail.push(stp_topology_line(&s.topology));
        for p in &s.ports {
            tail.extend(stp_port_detail(
                &p.name,
                p.edge,
                p.point_to_point,
                &stp_flags(p),
                &p.counters,
            ));
        }
    }
    for line in tail {
        out.push('\n');
        out.push_str(&line);
    }
    out
}

/// The port-protection column of `show spanning-tree` (#320): what is
/// configured, then what is holding the port right now.
fn stp_flags(p: &nos_proto::StpPortInfo) -> String {
    let mut f = Vec::new();
    for (on, name) in [
        (p.edge, "Edge"),
        (p.bpdu_guard, "BpduGuard"),
        (p.bpdu_filter, "BpduFilter"),
        (p.root_guard, "RootGuard"),
        (p.loop_guard, "LoopGuard"),
        (p.restricted_tcn, "RestrictedTcn"),
        (p.root_inconsistent, "Root-inconsistent"),
        (p.loop_inconsistent, "Loop-inconsistent"),
    ] {
        if on {
            f.push(name.to_string());
        }
    }
    if p.err_disabled {
        f.push(match p.err_recovery_secs {
            Some(n) => format!("Err-disabled (recovers in {n}s)"),
            None => "Err-disabled (manual clear)".to_string(),
        });
    }
    f.join(",")
}

#[cfg(test)]
mod stp_tests {
    use super::render_spanning_tree;
    use nos_proto::{StpPortInfo, StpRole, StpState, StpSummary};

    #[test]
    fn spanning_tree_disabled_root_and_non_root() {
        assert_eq!(
            render_spanning_tree(&StpSummary::default()),
            "spanning-tree is disabled"
        );
        let mut s = StpSummary {
            enabled: true,
            bridge_id: "8000.02:00:00:00:00:02".into(),
            root_id: "8000.02:00:00:00:00:01".into(),
            root_path_cost: 20000,
            root_port: Some("eth1".into()),
            hello_time_secs: 2,
            max_age_secs: 20,
            forward_delay_secs: 15,
            ..StpSummary::default()
        };
        s.ports = vec![
            StpPortInfo {
                name: "eth1".into(),
                role: StpRole::Root,
                state: StpState::Forwarding,
                cost: 20000,
                priority: 128,
                designated_bridge: "8000.02:00:00:00:00:01".into(),
                designated_port: "128.1".into(),
                ..StpPortInfo::default()
            },
            StpPortInfo {
                name: "eth2".into(),
                ..StpPortInfo::default()
            },
        ];
        s.ports[1].root_guard = true;
        s.ports[1].err_disabled = true;
        s.ports[1].err_recovery_secs = Some(12);
        let flagged = render_spanning_tree(&s);
        assert!(flagged.contains("Designated"), "{flagged}");
        assert!(flagged.lines().any(|l| l.ends_with("  Flags")), "{flagged}");
        assert!(flagged.contains("RootGuard,Err-disabled (recovers in 12s)"));
        s.ports[1] = StpPortInfo::default();
        let out = render_spanning_tree(&s);
        assert!(out.contains("root id   8000.02:00:00:00:00:01 (root port eth1, cost 20000)"));
        assert!(
            out.contains("eth1  root      forwarding  20000   128"),
            "{out}"
        );
        assert!(out.contains("8000.02:00:00:00:00:01 128.1"));
        assert!(out.lines().last().unwrap().ends_with("  -"));
        s.root_port = None;
        assert!(render_spanning_tree(&s).contains("(this bridge is the root)"));
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

/// The version-2 line of `show lacp`: algorithm, agreement, per-link conversation counts.
fn render_lacp_v2(s: &PortAggregateLacpSummary) -> String {
    use nos_proto::{LacpAgreement, LacpPortAlgorithm};
    let algorithm = match s.port_algorithm {
        LacpPortAlgorithm::Unspecified => "unspecified",
        LacpPortAlgorithm::CVlan => "c-vlan",
        LacpPortAlgorithm::SVlan => "s-vlan",
    };
    let agreement = match s.agreement {
        LacpAgreement::NotApplicable => "not-applicable",
        LacpAgreement::Agreed => "agreed",
        LacpAgreement::Mismatch => "mismatch",
        LacpAgreement::V1Partner => "v1-partner",
    };
    let mut line = format!("  version 2, algorithm {algorithm}, agreement {agreement}");
    if !s.conversations_per_link.is_empty() {
        let per_link: Vec<String> = s
            .conversations_per_link
            .iter()
            .map(|(m, n)| format!("{m} {n}"))
            .collect();
        line = format!("{line}, conversations {}", per_link.join(", "));
    }
    line
}

/// Render `nos-lacpd`'s per-aggregate LACP state, for `show lacp`.
pub fn render_lacp_summaries(summaries: &[PortAggregateLacpSummary]) -> String {
    sanitize(&render_lacp_summaries_raw(summaries)).into_owned()
}

fn render_lacp_summaries_raw(summaries: &[PortAggregateLacpSummary]) -> String {
    if summaries.is_empty() {
        return "no lacp port aggregates".to_string();
    }
    summaries
        .iter()
        .map(|s| {
            let rate = match s.rate {
                LacpRate::Slow => "slow",
                LacpRate::Fast => "fast",
            };
            let mut lines = vec![format!(
                "lacp {}: system {}, key {}, rate {rate}, system priority {}",
                s.aggregate,
                format_mac(s.actor_system_id),
                s.actor_key,
                s.actor_system_priority
            )];
            if s.min_links > 1 {
                lines.push(format!(
                    "  min-links {}: {}",
                    s.min_links,
                    if s.min_links_met {
                        "met"
                    } else {
                        "not met, bond emptied"
                    }
                ));
            }
            if s.ports.is_empty() {
                lines.push("  no member ports".to_string());
            }
            // Version-1 output stays byte-identical to before #865.
            if s.version == nos_proto::LacpVersion::V2 {
                lines.push(render_lacp_v2(s));
            }
            lines.extend(s.ports.iter().map(render_lacp_port));
            lines.join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_log_level(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "TRACE",
        LogLevel::Debug => "DEBUG",
        LogLevel::Info => "INFO",
        LogLevel::Warn => "WARN",
        LogLevel::Error => "ERROR",
    }
}

/// `YYYY-MM-DD HH:MM:SS` (UTC) of Unix `secs`, or the number when out of range.
pub fn utc(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
        .map_or_else(
            || secs.to_string(),
            |dt| {
                format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                    dt.year(),
                    u8::from(dt.month()),
                    dt.day(),
                    dt.hour(),
                    dt.minute(),
                    dt.second()
                )
            },
        )
}

/// Render one log entry as one line: `<timestamp> <LEVEL> <source> <target>: <message> {fields}`.
pub fn render_log_entry(entry: &LogEntry) -> String {
    sanitize(&render_log_entry_raw(entry)).into_owned()
}

fn render_log_entry_raw(entry: &LogEntry) -> String {
    let timestamp = i64::try_from(entry.timestamp_ms)
        .ok()
        .and_then(|ms| OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).ok())
        .map_or_else(
            || entry.timestamp_ms.to_string(),
            |dt| {
                format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                    dt.year(),
                    u8::from(dt.month()),
                    dt.day(),
                    dt.hour(),
                    dt.minute(),
                    dt.second(),
                    dt.millisecond()
                )
            },
        );
    let base = format!(
        "{timestamp} {:>5} {} {}: {}",
        render_log_level(entry.level),
        sanitize_line(&entry.source),
        sanitize_line(&entry.target),
        sanitize_line(&entry.message)
    );
    if entry.fields.is_empty() {
        return base;
    }
    let fields = entry
        .fields
        .iter()
        .map(|(k, v)| format!("{}={}", sanitize_line(k), sanitize_line(v)))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{base} ({fields})")
}

/// Render a buffer of log entries, one per line, in the order given (already
/// oldest-first from `nos-logd`) — used for both `show log` (a snapshot) and
/// each streamed line of `show log --follow`.
pub fn render_log_entries(entries: &[LogEntry]) -> String {
    sanitize(&render_log_entries_raw(entries)).into_owned()
}

fn render_log_entries_raw(entries: &[LogEntry]) -> String {
    if entries.is_empty() {
        return "no log entries".to_string();
    }
    entries
        .iter()
        .map(render_log_entry)
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_route_source(source: RouteSourceKind) -> &'static str {
    match source {
        RouteSourceKind::Static => "static",
        RouteSourceKind::Bgp => "bgp",
        RouteSourceKind::Ospf => "ospf",
        RouteSourceKind::Connected => "connected",
        RouteSourceKind::Evpn => "evpn",
        RouteSourceKind::Vpn => "vpn",
    }
}

/// Render one prefix's candidate routes, best (winner, marked `*`) to worst,
/// one line per candidate. Used for both `show route <table>` (many entries)
/// and `show route <table> <address>` (one entry, wrapped in a slice).
pub fn render_prefix_routes(entries: &[PrefixRoutes]) -> String {
    sanitize(&render_prefix_routes_raw(entries)).into_owned()
}

fn render_prefix_routes_raw(entries: &[PrefixRoutes]) -> String {
    if entries.is_empty() {
        return "no routes".to_string();
    }
    let mut lines = Vec::new();
    for entry in entries {
        lines.push(format!("{}", entry.prefix));
        for (i, candidate) in entry.candidates.iter().enumerate() {
            let marker = if i == 0 { "*" } else { " " };
            let backup = candidate.backup.map_or_else(String::new, |b| {
                let tunnel = if candidate.backup_tunnel {
                    "tunnel "
                } else {
                    ""
                };
                format!(" backup {tunnel}{b}")
            });
            let via = if candidate.blackhole {
                "discard (blackhole)".to_string()
            } else if candidate.discard {
                "discard".to_string()
            } else {
                // A `Vpn` hop shows its own PE, RD and labels.
                let gateways = candidate
                    .gateways
                    .iter()
                    .enumerate()
                    .map(|(i, gw)| match candidate.vpn.get(i) {
                        Some(v) => {
                            let labels = candidate
                                .mpls_labels
                                .get(i)
                                .into_iter()
                                .flatten()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join("/");
                            format!("{gw} pe {} rd {} label {labels}", v.pe_next_hop, v.rd)
                        }
                        None => gw.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let evpn = candidate.evpn.as_ref().map_or_else(String::new, |e| {
                    format!(" rmac {} vni {}", e.router_mac, e.vni)
                });
                format!("via {gateways}{evpn}")
            };
            lines.push(format!(
                "  {marker} {via} [{}]{backup}",
                render_route_source(candidate.source)
            ));
        }
    }
    lines.join("\n")
}

fn render_bgp_session_state(state: BgpSessionState) -> &'static str {
    match state {
        BgpSessionState::Idle => "Idle",
        BgpSessionState::OpenSent => "OpenSent",
        BgpSessionState::OpenConfirm => "OpenConfirm",
        BgpSessionState::Established => "Established",
    }
}

/// Render one BGP instance's peer summaries, one line per peer — used for
/// `show bgp brief`.
pub fn render_bgp_summary(instance: &str, peers: &[PeerSummary]) -> String {
    sanitize(&render_bgp_summary_raw(instance, peers)).into_owned()
}

fn render_bgp_summary_raw(instance: &str, peers: &[PeerSummary]) -> String {
    if peers.is_empty() {
        return format!(
            "bgp instance {}: no peers configured",
            sanitize_line(instance)
        );
    }
    let mut lines = vec![format!("bgp instance {}:", sanitize_line(instance))];
    for peer in peers {
        let remote_as = peer
            .remote_as
            .map_or_else(|| "-".to_string(), |asn| asn.to_string());
        let uptime = peer
            .uptime_secs
            .map_or_else(|| "-".to_string(), human_duration);
        let hold_time = peer
            .negotiated_hold_time
            .map_or_else(|| "-".to_string(), |h| h.to_string());
        let ao = match (peer.ao_current_key, peer.ao_rnext_key) {
            (Some(current), Some(rnext)) => format!(
                " ao-current {current} ao-rnext {rnext} ao-good {} ao-bad {} ao-no-key {}",
                peer.ao_packets_good.unwrap_or(0),
                peer.ao_packets_bad.unwrap_or(0),
                peer.ao_packets_key_not_found.unwrap_or(0),
            ),
            _ => String::new(),
        };
        let mut counts = String::new();
        for (af, n) in ["v4", "v6", "evpn"]
            .iter()
            .zip(peer.accepted_prefixes.unwrap_or_default())
        {
            if n > 0 {
                let _ = write!(counts, " {af} {n}");
            }
        }
        let prefixes = if counts.is_empty() {
            String::new()
        } else {
            format!(" prefixes{counts}")
        };
        // RFC 4724 / RFC 8538: the peer's restart time, N, and the families
        // it keeps forwarding state for (F).
        let gr = match &peer.graceful_restart {
            Some(g) if peer.state == BgpSessionState::Established => {
                let f: Vec<&str> = g
                    .families
                    .iter()
                    .filter(|(_, f)| *f)
                    .map(|(af, _)| af.as_str())
                    .collect();
                format!(
                    " gr {}s{}{}",
                    g.restart_time,
                    if g.notification { " N" } else { "" },
                    if f.is_empty() {
                        String::new()
                    } else {
                        format!(" F:{}", f.join(","))
                    }
                )
            }
            _ => String::new(),
        };
        lines.push(format!(
            "  {} AS {remote_as} peer-group {} {} uptime {uptime} hold-time {hold_time}{ao}{}{gr}",
            peer.remote_address,
            sanitize_line(&peer.peer_group),
            if peer.shutdown {
                "Idle (shutdown)".to_string()
            } else if peer.max_prefix_held {
                "Idle (max-prefix)".to_string()
            } else if peer.stale_prefixes > 0 && peer.state != BgpSessionState::Established {
                format!("Idle (gr-stale {})", peer.stale_prefixes)
            } else {
                render_bgp_session_state(peer.state).to_string()
            },
            prefixes,
        ));
    }
    lines.join("\n")
}

/// Render one BGP instance's received EVPN routes, one line per route — used
/// for `show bgp evpn`.
pub fn render_bgp_evpn(instance: &str, routes: &[EvpnRouteSummary]) -> String {
    sanitize(&render_bgp_evpn_raw(instance, routes)).into_owned()
}

fn render_bgp_evpn_raw(instance: &str, routes: &[EvpnRouteSummary]) -> String {
    if routes.is_empty() {
        return format!("bgp instance {instance}: no evpn routes");
    }
    format!(
        "{}\n{}",
        render_bgp_routes_header(instance),
        render_bgp_evpn_lines(routes)
    )
}

/// One line per EVPN route (no header), so a page renders on its own.
pub fn render_bgp_evpn_lines(routes: &[EvpnRouteSummary]) -> String {
    sanitize(&render_bgp_evpn_lines_raw(routes)).into_owned()
}

fn render_bgp_evpn_lines_raw(routes: &[EvpnRouteSummary]) -> String {
    routes
        .iter()
        .map(|r| {
            format!(
                "  from {} next-hop {} {} [{}] local-pref {} communities [{}]",
                r.peer,
                r.next_hop,
                r.route,
                r.extended_communities.join(" "),
                r.local_pref,
                nos_proto::bgp::fmt_communities(&r.communities)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render one BGP instance's received VPN paths of `family`, one line per
/// path, `>` marking the best per (RD, prefix) — used for `show bgp
/// vpnv4|vpnv6`.
pub fn render_bgp_vpn(
    instance: &str,
    family: nos_proto::AddressFamily,
    routes: &[nos_proto::VpnRouteSummary],
) -> String {
    sanitize(&render_bgp_vpn_raw(instance, family, routes)).into_owned()
}

fn render_bgp_vpn_raw(
    instance: &str,
    family: nos_proto::AddressFamily,
    routes: &[nos_proto::VpnRouteSummary],
) -> String {
    if routes.is_empty() {
        return format!("bgp instance {instance}: no {family} routes");
    }
    format!(
        "{}\n{}",
        render_bgp_routes_header(instance),
        render_bgp_vpn_lines(routes)
    )
}

/// One line per VPN path (no header), so a page renders on its own.
pub fn render_bgp_vpn_lines(routes: &[nos_proto::VpnRouteSummary]) -> String {
    sanitize(&render_bgp_vpn_lines_raw(routes)).into_owned()
}

fn render_bgp_vpn_lines_raw(routes: &[nos_proto::VpnRouteSummary]) -> String {
    routes
        .iter()
        .map(|r| {
            let labels: Vec<String> = r.labels.iter().map(u32::to_string).collect();
            let mut line = format!(
                "  {} rd {} {}{} label {} next-hop {} from {} [{}]",
                if r.best { ">" } else { " " },
                r.rd,
                r.path_id
                    .map_or(String::new(), |id| format!("path-id {id} ")),
                r.prefix,
                labels.join("/"),
                r.next_hop,
                r.peer,
                r.route_targets.join(" ")
            );
            if let Some(soo) = &r.site_of_origin {
                line.push_str(" soo ");
                line.push_str(soo);
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render one BGP instance's received Flowspec rules, one line per rule —
/// used for `show bgp flowspec`.
pub fn render_bgp_flowspec(instance: &str, routes: &[FlowspecRouteSummary]) -> String {
    sanitize(&render_bgp_flowspec_raw(instance, routes)).into_owned()
}

fn render_bgp_flowspec_raw(instance: &str, routes: &[FlowspecRouteSummary]) -> String {
    if routes.is_empty() {
        return format!("bgp instance {instance}: no flowspec routes");
    }
    format!(
        "{}\n{}",
        render_bgp_routes_header(instance),
        render_bgp_flowspec_lines(routes)
    )
}

/// One line per Flowspec rule (no header), so a page renders on its own.
pub fn render_bgp_flowspec_lines(routes: &[FlowspecRouteSummary]) -> String {
    sanitize(&render_bgp_flowspec_lines_raw(routes)).into_owned()
}

fn render_bgp_flowspec_lines_raw(routes: &[FlowspecRouteSummary]) -> String {
    routes
        .iter()
        .map(|r| {
            let mut line = format!(
                "  from {} {}{} [{}] {} actions: {}",
                r.peer,
                r.rd.as_ref()
                    .map_or(String::new(), |rd| format!("rd {rd} ")),
                r.path_id
                    .map_or(String::new(), |id| format!("path-id {id} "))
                    + &r.nlri,
                r.extended_communities.join(" "),
                r.validity,
                if r.actions.is_empty() {
                    "none".to_string()
                } else {
                    r.actions.join(", ")
                }
            );
            if let Some(d) = &r.dataplane {
                // The selected copy: what nos-acld made of it (#562).
                line.push_str(" dataplane: ");
                line.push_str(d);
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One BGP instance's unicast routes, one line per path — `show bgp routes`.
pub fn render_bgp_routes(instance: &str, routes: &[nos_proto::BgpRouteSummary]) -> String {
    sanitize(&render_bgp_routes_raw(instance, routes)).into_owned()
}

fn render_bgp_routes_raw(instance: &str, routes: &[nos_proto::BgpRouteSummary]) -> String {
    if routes.is_empty() {
        return format!("bgp instance {instance}: no routes");
    }
    format!(
        "{}\n{}",
        render_bgp_routes_header(instance),
        render_bgp_route_lines(routes)
    )
}

/// The `show bgp routes` header, printed once ahead of the pages.
pub fn render_bgp_routes_header(instance: &str) -> String {
    sanitize(&render_bgp_routes_header_raw(instance)).into_owned()
}

fn render_bgp_routes_header_raw(instance: &str) -> String {
    format!("bgp instance {instance}:")
}

/// One line per route (no header), so a page renders on its own: the lines
/// have no column widths that depend on the whole table.
pub fn render_bgp_route_lines(routes: &[nos_proto::BgpRouteSummary]) -> String {
    sanitize(&render_bgp_route_lines_raw(routes)).into_owned()
}

fn render_bgp_route_lines_raw(routes: &[nos_proto::BgpRouteSummary]) -> String {
    use nos_proto::RpkiValidationState as S;
    let opt = |v: Option<String>| v.unwrap_or_else(|| "-".to_string());
    routes
        .iter()
        .flat_map(|r| {
            let state = match r.validation_state {
                S::Valid => "valid",
                S::Invalid => "invalid",
                S::NotFound => "not-found",
            };
            let row = format!(
                "  {} {} from {} next-hop {} as-path [{}] origin-as {} local-pref {} {}",
                if r.best { ">" } else { " " },
                r.prefix,
                r.peer.map_or("local".to_string(), |p| p.to_string()),
                opt(r.next_hop.map(|p| p.to_string())),
                r.as_path,
                opt(r.origin_as.map(|a| a.to_string())),
                r.local_pref,
                state
            );
            let attrs = r.unknown_attributes.iter().map(|a| {
                format!(
                    "      attr {} flags=0x{:02x} len={} {}",
                    a.attr_type,
                    a.flags,
                    a.value.len() / 2,
                    a.value
                )
            });
            std::iter::once(row).chain(attrs)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One BGP instance's BMP stations, two lines each — `show bgp bmp`.
pub fn render_bgp_bmp(instance: &str, stations: &[nos_proto::BmpStationStatus]) -> String {
    sanitize(&render_bgp_bmp_raw(instance, stations)).into_owned()
}

fn render_bgp_bmp_raw(instance: &str, stations: &[nos_proto::BmpStationStatus]) -> String {
    if stations.is_empty() {
        return format!("bgp instance {instance}: no bmp stations");
    }
    let mut lines = vec![format!("bgp instance {instance}:")];
    for s in stations {
        let f = &s.frames_sent;
        lines.push(format!(
            "  {} {}:{} {} monitor {} statistics {} peers {} overflows {} reconnects {}{}",
            s.name,
            s.address,
            s.port,
            bmp_state_word(s.state),
            bmp_monitor_word(s.monitor),
            s.statistics_interval
                .map_or_else(|| "-".to_string(), |i| format!("{i}s")),
            s.peers_monitored,
            s.overflows,
            s.reconnects,
            s.last_error.as_ref().map_or_else(String::new, |e| format!(
                " last-error \"{}\"",
                sanitize_line(e)
            )),
        ));
        lines.push(format!(
            "    sent: initiation {} peer-up {} peer-down {} route-monitoring pre {} post {} end-of-rib {} stats {} termination {}",
            f.initiation,
            f.peer_up,
            f.peer_down,
            f.route_monitoring_pre,
            f.route_monitoring_post,
            f.end_of_rib,
            f.stats,
            f.termination,
        ));
    }
    lines.join("\n")
}

fn render_ip_or_dash(addr: Option<Ipv4Addr>) -> String {
    addr.map_or_else(|| "-".to_string(), |a| a.to_string())
}

/// `OSPFv2` LS type name (RFC 2328 A.4.1, RFC 5250 opaque); unknown = the number.
pub fn ospf_lsa_type_name(t: u8) -> Cow<'static, str> {
    match t {
        1 => "router".into(),
        2 => "network".into(),
        3 => "summary".into(),
        4 => "asbr-summary".into(),
        5 => "external".into(),
        7 => "nssa".into(),
        9 => "opaque-link".into(),
        10 => "opaque-area".into(),
        11 => "opaque-as".into(),
        n => n.to_string().into(),
    }
}

const OSPF_TYPE_NAMES: &str =
    "router, network, summary, asbr-summary, external, nssa, opaque-link, opaque-area, opaque-as";

/// A `show ospf database <type>` argument: a type name or a decimal number.
pub fn parse_ospf_lsa_type(s: &str) -> Result<u8, String> {
    let l = s.to_ascii_lowercase();
    (0..=u8::MAX)
        .find(|&t| ospf_lsa_type_name(t) == l)
        .or_else(|| l.parse().ok())
        .ok_or_else(|| {
            format!(
                "unknown LSA type '{}' (use {OSPF_TYPE_NAMES} or a number)",
                sanitize_line(s)
            )
        })
}

/// Router-LSA flags as `B`/`E`/`V` letters (Nt/H are not shown).
fn router_flag_letters(flags: Option<u8>) -> String {
    let f = flags.unwrap_or(0);
    [(0x01, "B"), (0x02, "E"), (0x04, "V")]
        .iter()
        .filter(|(bit, _)| f & bit != 0)
        .map(|(_, l)| *l)
        .collect::<Vec<_>>()
        .join(",")
}

fn lsa_info(parts: &[String]) -> String {
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(" ")
    }
}

fn router_info(flags: Option<u8>, vlinks: &[Ipv4Addr]) -> Vec<String> {
    let mut parts = Vec::new();
    let letters = router_flag_letters(flags);
    if !letters.is_empty() {
        parts.push(letters);
    }
    parts.extend(vlinks.iter().map(|v| format!("vlink {v}")));
    parts
}

fn ospf_info(lsa: &LsaSummary) -> String {
    let mut parts = Vec::new();
    if let Some(m) = lsa.external_metric {
        let e = if lsa.external_type2 { "E2" } else { "E1" };
        parts.push(format!("metric {m} {e}"));
    }
    parts.extend(router_info(lsa.router_flags, &lsa.virtual_links));
    lsa_info(&parts)
}

/// Keep the LSAs of one type and/or one advertising router.
pub fn filter_ospf_database(
    entries: &[LsaSummary],
    ty: Option<u8>,
    router: Option<Ipv4Addr>,
) -> Vec<LsaSummary> {
    entries
        .iter()
        .filter(|l| ty.is_none_or(|t| l.lsa_type == t))
        .filter(|l| router.is_none_or(|r| l.advertising_router == r))
        .cloned()
        .collect()
}

const DB_COLS_HEAD: [Col; 7] = [
    Col::left("Area"),
    Col::left("Type"),
    Col::left("Link-State-ID"),
    Col::left("Adv-Router"),
    Col::right("Seq"),
    Col::right("Age"),
    Col::right("Checksum"),
];

/// Render one OSPF instance's installed-LSA headers as a table, for
/// `show ospf database`. Empty means nothing installed.
pub fn render_ospf_database(instance: &str, entries: &[LsaSummary]) -> String {
    sanitize(&render_ospf_database_raw(instance, entries, false)).into_owned()
}

/// `render_ospf_database` over a list already narrowed by
/// `filter_ospf_database`: empty means "no LSAs match".
pub fn render_ospf_database_filtered(instance: &str, entries: &[LsaSummary]) -> String {
    sanitize(&render_ospf_database_raw(instance, entries, true)).into_owned()
}

fn db_wrap(
    proto: &str,
    instance: &str,
    filtered: bool,
    rows: &[Vec<String>],
    cols: &[Col],
) -> String {
    let instance = sanitize_line(instance);
    if rows.is_empty() {
        let what = if filtered {
            "no LSAs match"
        } else {
            "no LSAs installed"
        };
        return format!("{proto} instance {instance}: {what}");
    }
    format!("{proto} instance {instance}:\n{}", table(cols, rows))
}

fn render_ospf_database_raw(instance: &str, entries: &[LsaSummary], filtered: bool) -> String {
    let mut cols = DB_COLS_HEAD.to_vec();
    cols.push(Col::left("Info"));
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|l| {
            vec![
                l.area_id.to_string(),
                ospf_lsa_type_name(l.lsa_type).into_owned(),
                l.link_state_id.to_string(),
                l.advertising_router.to_string(),
                format!("0x{:08x}", l.sequence_number),
                l.age.to_string(),
                format!("0x{:04x}", l.checksum),
                ospf_info(l),
            ]
        })
        .collect();
    db_wrap("ospf", instance, filtered, &rows, &cols)
}

/// `show ospf segment-routing` (#1382): one line per SRGB, Prefix-SID and
/// Adj-SID.
pub fn render_ospf_segment_routing(instance: &str, sr: &nos_proto::SrSummary) -> String {
    let dash = |l: Option<u32>| l.map_or_else(|| "-".to_string(), |l| l.to_string());
    let mut lines = vec![format!("ospf instance {instance}:")];
    for s in &sr.srgb {
        lines.push(format!(
            "  srgb router {} range {}-{}",
            s.router,
            s.base,
            s.base + s.size.saturating_sub(1)
        ));
    }
    for p in &sr.prefix_sids {
        lines.push(format!(
            "  prefix-sid router {} prefix {}/{} {} {} label {}",
            p.router,
            p.prefix,
            p.prefix_len,
            if p.absolute { "label" } else { "index" },
            p.value,
            dash(p.label),
        ));
    }
    for a in &sr.adj_sids {
        lines.push(format!(
            "  adj-sid router {} link {} neighbor {} label {}",
            a.router,
            a.link_id,
            render_ip_or_dash(a.neighbor),
            a.label
        ));
    }
    if lines.len() == 1 {
        lines[0] = format!("ospf instance {instance}: no segment routing state");
    }
    sanitize(&lines.join("\n")).into_owned()
}

const OSPFV3_TYPES: &[(u16, &str)] = &[
    (0x2001, "router"),
    (0x2002, "network"),
    (0x2003, "inter-area-prefix"),
    (0x2004, "inter-area-router"),
    (0x4005, "as-external"),
    (0x2007, "nssa"),
    (0x0008, "link"),
    (0x2009, "intra-area-prefix"),
    (0x000b, "grace"),
    (0xa021, "e-router"),
    (0xa022, "e-network"),
    (0xa023, "e-inter-area-prefix"),
    (0xa024, "e-inter-area-router"),
    (0xc025, "e-as-external"),
    (0xa027, "e-nssa"),
    (0x8028, "e-link"),
    (0xa029, "e-intra-area-prefix"),
];

/// `OSPFv3` LS type name from its function code (RFC 5340 A.4.2.1, RFC 8362
/// E-LSAs, RFC 5187 grace); unknown = `0x%04x`.
pub fn ospfv3_lsa_type_name(t: u16) -> Cow<'static, str> {
    match OSPFV3_TYPES.iter().find(|(c, _)| *c == t) {
        Some((_, n)) => (*n).into(),
        None => format!("0x{t:04x}").into(),
    }
}

/// A `show ospfv3 database <type>` argument: a type name, a decimal number or
/// `0x` hex.
pub fn parse_ospfv3_lsa_type(s: &str) -> Result<u16, String> {
    let l = s.to_ascii_lowercase();
    OSPFV3_TYPES
        .iter()
        .find(|(_, n)| *n == l)
        .map(|(c, _)| *c)
        .or_else(|| match l.strip_prefix("0x") {
            Some(h) => u16::from_str_radix(h, 16).ok(),
            None => l.parse().ok(),
        })
        .ok_or_else(|| {
            let names: Vec<&str> = OSPFV3_TYPES.iter().map(|(_, n)| *n).collect();
            format!(
                "unknown LSA type '{}' (use {}, a number or 0x hex)",
                sanitize_line(s),
                names.join(", ")
            )
        })
}

/// Keep the LSAs of one type and/or one advertising router.
pub fn filter_ospfv3_database(
    entries: &[Ospfv3LsaSummary],
    ty: Option<u16>,
    router: Option<Ipv4Addr>,
) -> Vec<Ospfv3LsaSummary> {
    entries
        .iter()
        .filter(|l| ty.is_none_or(|t| l.lsa_type == t))
        .filter(|l| router.is_none_or(|r| l.advertising_router == r))
        .cloned()
        .collect()
}

/// Render one `Ospfv3Instance`'s installed-LSA headers as a table, for
/// `show ospfv3 database`: `render_ospf_database` plus a `Link` column.
pub fn render_ospfv3_database(instance: &str, entries: &[Ospfv3LsaSummary]) -> String {
    sanitize(&render_ospfv3_database_raw(instance, entries, false)).into_owned()
}

/// `render_ospfv3_database` over a list already narrowed by
/// `filter_ospfv3_database`: empty means "no LSAs match".
pub fn render_ospfv3_database_filtered(instance: &str, entries: &[Ospfv3LsaSummary]) -> String {
    sanitize(&render_ospfv3_database_raw(instance, entries, true)).into_owned()
}

fn render_ospfv3_database_raw(
    instance: &str,
    entries: &[Ospfv3LsaSummary],
    filtered: bool,
) -> String {
    let mut cols = DB_COLS_HEAD.to_vec();
    cols.push(Col::left("Link"));
    cols.push(Col::left("Info"));
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|l| {
            vec![
                l.area_id.to_string(),
                ospfv3_lsa_type_name(l.lsa_type).into_owned(),
                l.link_state_id.to_string(),
                l.advertising_router.to_string(),
                format!("0x{:08x}", l.sequence_number),
                l.age.to_string(),
                format!("0x{:04x}", l.checksum),
                l.link.clone().unwrap_or_else(|| "-".into()),
                lsa_info(&router_info(l.router_flags, &l.virtual_links)),
            ]
        })
        .collect();
    db_wrap("ospfv3", instance, filtered, &rows, &cols)
}

/// Render a full running-config snapshot as human-readable text: the
/// generated `nos_proto::cli::render` hierarchy, only what is configured.
pub fn render_config(config: &Config) -> String {
    sanitize(&render_config_raw(config)).into_owned()
}

fn render_config_raw(config: &Config) -> String {
    let mut doc = serde_json::to_value(config).unwrap_or_default();
    // The keystore is a section of its own: `show config admin` (#507).
    doc["admin"] = serde_json::to_value(nos_proto::Admin::default()).unwrap_or_default();
    let text = render::indent(&render::render_root(&doc));
    if text.is_empty() {
        "nothing configured".to_string()
    } else {
        text
    }
}

/// `show config <path>` (#1459): the running config scoped to the object the
/// `edit` words name. `Err`: the words name no object.
pub fn render_config_path(config: &Config, words: &[&str]) -> Result<String, String> {
    let doc = serde_json::to_value(config).unwrap_or_default();
    let segs = crate::config_grammar::resolve_path(words, &doc)
        .ok_or_else(|| format!("no such object: {}", sanitize(&words.join(" "))))?;
    let text = render::render_at(&doc, &segs).map_or_else(
        || "nothing configured here".to_string(),
        |lines| render::indent(&lines),
    );
    Ok(sanitize(&text).into_owned())
}

/// `show config admin`: the keystore, secrets as `<hidden>`.
pub fn render_admin_config(config: &Config) -> String {
    sanitize(&render_admin_config_raw(config)).into_owned()
}

fn render_admin_config_raw(config: &Config) -> String {
    let doc = serde_json::to_value(config).unwrap_or_default();
    if config.admin.keys.is_empty() {
        return "no admin keys configured".to_string();
    }
    render::render_at(&doc, &["admin".to_string()])
        .map_or_else(String::new, |lines| render::indent(&lines))
}

/// Render a transaction's in-progress config, scoped to the current
/// navigation position: the whole config at the root, else the object the
/// position names (headed by its own words).
pub fn render_transaction(snapshot: &TransactionSnapshot, path: &Path) -> String {
    sanitize(&render_transaction_raw(snapshot, path)).into_owned()
}

fn render_transaction_raw(snapshot: &TransactionSnapshot, path: &Path) -> String {
    if path.segments().is_empty() {
        let header = if snapshot.dirty {
            format!("transaction '{}' (uncommitted changes):", snapshot.name)
        } else {
            format!("transaction '{}':", snapshot.name)
        };
        return format!("{header}\n{}", render_config(&snapshot.config));
    }
    serde_json::to_value(&snapshot.config)
        .ok()
        .and_then(|doc| render::render_at(&doc, path.segments()))
        .map_or_else(
            || "nothing configured here".to_string(),
            |lines| render::indent(&lines),
        )
}

/// Render policy source with `cat -n`-style line numbers, so `set source
/// line <n> ...`/`delete source line <n>` can be given without re-reading
/// the source in an editor first.
pub fn render_policy_source(source: &str) -> String {
    sanitize(&render_policy_source_raw(source)).into_owned()
}

fn render_policy_source_raw(source: &str) -> String {
    if source.is_empty() {
        return "(empty)".to_string();
    }
    source
        .lines()
        .enumerate()
        .map(|(i, line)| format!("{:4}  {line}", i + 1))
        .collect::<Vec<_>>()
        .join("\n")
}

// ANSI SGR codes for `render_diff`. Hand-rolled rather than pulling in a
// color crate — this is the only place in `nos-cli` that needs color, and
// keeping the base color active while toggling bold/underline (via `22;24`,
// which turns those off without a full reset) lets a diff line's word-level
// highlight nest inside its red/green without ever losing that color.
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const EMPH_ON: &str = "\x1b[1;4m";
const EMPH_OFF: &str = "\x1b[22;24m";
const RESET: &str = "\x1b[0m";

/// Renders the structural difference between the running config and a
/// transaction's in-progress config, computed server-side by `nos-config`
/// (see `nos_proto::diff_configs`). `nos-cli`'s only job here is turning
/// that structured diff into colored, highlighted terminal text — with just
/// enough unmodified context (an unstyled section header) that a changed
/// field can always be traced back to the section it lives in.
pub fn render_diff(diff: &ConfigDiff, color: bool) -> String {
    // No `..`: a new `ConfigDiff` section is a compile error here, not a
    // silently missing part of `diff`.
    let ConfigDiff {
        hostname,
        bgp_instances,
        routing_tables,
        ospf_instances,
        ospfv3_instances,
        static_routing_instances,
        interfaces,
        policy_definitions,
        community_aliases,
        community_groups,
        as_path_lists,
        prefix_lists,
        broadcast_domains,
        switching_profiles,
        port_aggregates,
        lldp,
        users,
        logging,
        login_policy,
        aaa,
        bfd_profiles,
        sbfd_reflector,
        spanning_tree,
        stp_port_profiles,
        acls,
        admin,
    } = diff;
    let mut lines = Vec::new();

    if let Some(field) = hostname {
        render_field_diff(&mut lines, field, "", color);
    }
    for field in lldp
        .iter()
        .chain(logging)
        .chain(login_policy)
        .chain(aaa)
        .chain(sbfd_reflector)
        .chain(spanning_tree)
        .chain(admin)
    {
        render_field_diff(&mut lines, field, "", color);
    }

    for sections in [
        users,
        bgp_instances,
        routing_tables,
        ospf_instances,
        ospfv3_instances,
        static_routing_instances,
        interfaces,
        port_aggregates,
        broadcast_domains,
        switching_profiles,
        policy_definitions,
        community_aliases,
        community_groups,
        as_path_lists,
        prefix_lists,
        bfd_profiles,
        stp_port_profiles,
        acls,
    ] {
        for section in sections {
            render_section(&mut lines, section, 0, color);
        }
    }

    lines.join("\n")
}

/// Renders one `SectionDiff` at `depth` levels of nesting (2 spaces per
/// level, matching the existing single-level indent), then recurses into
/// its `subsections` one level deeper.
fn render_section(lines: &mut Vec<String>, section: &SectionDiff, depth: usize, color: bool) {
    let indent = "  ".repeat(depth);
    let header = format!("{indent}{}:", sanitize(&section.header));
    match section.status {
        // The section itself didn't change — only shown so a reader can
        // tell which section its changed fields (below) belong to.
        DiffStatus::Modified => lines.push(context_line(&header)),
        DiffStatus::Added => lines.push(added_line(&header, color)),
        DiffStatus::Removed => lines.push(removed_line(&header, color)),
    }
    let field_indent = "  ".repeat(depth + 1);
    for field in &section.fields {
        render_field_diff(lines, field, &field_indent, color);
    }
    for subsection in &section.subsections {
        render_section(lines, subsection, depth + 1, color);
    }
}

fn render_field_diff(lines: &mut Vec<String>, field: &FieldDiff, indent: &str, color: bool) {
    // Values are escaped before the SGR codes go on: this renderer's output
    // legitimately contains ESC, so it has no final `sanitize` pass (#1365).
    let label = sanitize(&field.label);
    let old = field.old.as_deref().map(sanitize);
    let new = field.new.as_deref().map(sanitize);
    match (&old, &new) {
        (Some(old), Some(new)) => {
            let (old_h, new_h) = highlight(old, new, color);
            lines.push(removed_line(&format!("{indent}{label}: {old_h}"), color));
            lines.push(added_line(&format!("{indent}{label}: {new_h}"), color));
        }
        (None, Some(new)) => {
            lines.push(added_line(&format!("{indent}{label}: {new}"), color));
        }
        (Some(old), None) => {
            lines.push(removed_line(&format!("{indent}{label}: {old}"), color));
        }
        (None, None) => {}
    }
}

fn context_line(text: &str) -> String {
    format!("  {text}")
}

fn added_line(text: &str, color: bool) -> String {
    styled_line('+', GREEN, text, color)
}

fn removed_line(text: &str, color: bool) -> String {
    styled_line('-', RED, text, color)
}

/// Marks every line of `text`, so a multi-line value (a policy's source)
/// stays readable as part of the diff.
fn styled_line(marker: char, code: &str, text: &str, color: bool) -> String {
    // Callers always pass at least a label, so `lines()` is never empty.
    text.lines()
        .map(|line| {
            if color {
                format!("{marker} {code}{line}{RESET}")
            } else {
                format!("{marker} {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Highlights only the substring that actually differs between `old` and
/// `new` (a simple common-prefix/common-suffix split, not a full LCS/Myers
/// diff — config field values are short atomic strings like hostnames,
/// ASNs, and IPs, not prose). Returns plain, unmarked strings when `color`
/// is off.
fn highlight(old: &str, new: &str, color: bool) -> (String, String) {
    if !color {
        return (old.to_string(), new.to_string());
    }
    let old_chars: Vec<char> = old.chars().collect();
    let new_chars: Vec<char> = new.chars().collect();
    let (prefix, suffix) = common_affixes(&old_chars, &new_chars);
    (
        emphasize_middle(&old_chars, prefix, suffix),
        emphasize_middle(&new_chars, prefix, suffix),
    )
}

/// Common prefix/suffix character counts between `a` and `b`, capped so
/// they never overlap.
fn common_affixes(a: &[char], b: &[char]) -> (usize, usize) {
    let limit = a.len().min(b.len());
    let prefix = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
    let max_suffix = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let suffix = max_suffix.min(limit - prefix);
    (prefix, suffix)
}

fn emphasize_middle(chars: &[char], prefix: usize, suffix: usize) -> String {
    let end = chars.len() - suffix;
    let head: String = chars[..prefix].iter().collect();
    let mid: String = chars[prefix..end].iter().collect();
    let tail: String = chars[end..].iter().collect();
    if mid.is_empty() {
        return format!("{head}{tail}");
    }
    format!("{head}{EMPH_ON}{mid}{EMPH_OFF}{tail}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_formats_a_unix_time() {
        assert_eq!(utc(1_700_000_000), "2023-11-14 22:13:20");
        assert_eq!(utc(u64::MAX), u64::MAX.to_string());
    }

    use std::net::Ipv4Addr;

    use nos_proto::SectionDiff;

    use super::*;

    #[test]
    fn discard_route_renders_as_discard() {
        let routes = [PrefixRoutes {
            prefix: "203.0.113.120/29".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec![],
                source: nos_proto::RouteSourceKind::Ospf,
                backup: None,
                discard: true,
                evpn: None,
                backup_tunnel: false,
                mpls_labels: vec![],
                vpn: vec![],
                blackhole: false,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "203.0.113.120/29\n  * discard [ospf]"
        );
    }

    #[test]
    fn bgp_blackhole_renders_as_blackhole() {
        let routes = [PrefixRoutes {
            prefix: "198.51.100.7/32".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec![],
                source: nos_proto::RouteSourceKind::Bgp,
                backup: None,
                discard: true,
                evpn: None,
                backup_tunnel: false,
                mpls_labels: vec![],
                vpn: vec![],
                blackhole: true,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "198.51.100.7/32\n  * discard (blackhole) [bgp]"
        );
    }

    #[test]
    fn evpn_route_renders_its_router_mac_and_vni() {
        let routes = [PrefixRoutes {
            prefix: "10.2.0.0/24".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec!["10.50.0.3".parse().unwrap()],
                source: nos_proto::RouteSourceKind::Evpn,
                backup: None,
                discard: false,
                evpn: Some(nos_proto::EvpnRouteInfo {
                    vtep: "10.50.0.3".parse().unwrap(),
                    router_mac: "02:00:00:00:00:03".to_string(),
                    vni: 5000,
                }),
                backup_tunnel: false,
                mpls_labels: vec![],
                vpn: vec![],
                blackhole: false,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "10.2.0.0/24\n  * via 10.50.0.3 rmac 02:00:00:00:00:03 vni 5000 [evpn]"
        );
    }

    #[test]
    fn vpn_route_renders_its_pe_rd_and_labels() {
        let routes = [PrefixRoutes {
            prefix: "10.10.0.0/24".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec!["10.0.0.3".parse().unwrap()],
                source: nos_proto::RouteSourceKind::Vpn,
                backup: None,
                discard: false,
                evpn: None,
                backup_tunnel: false,
                mpls_labels: vec![vec![100, 7]],
                vpn: vec![nos_proto::VpnRouteInfo {
                    pe_next_hop: "192.0.2.3".parse().unwrap(),
                    rd: "65001:1".to_string(),
                }],
                blackhole: false,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "10.10.0.0/24\n  * via 10.0.0.3 pe 192.0.2.3 rd 65001:1 label 100/7 [vpn]"
        );
    }

    /// #594: each next hop of a multipath `Vpn` candidate shows its own PE,
    /// RD and labels, the same gateway twice included.
    #[test]
    fn a_multipath_vpn_route_renders_each_hop_with_its_labels() {
        let info = |rd: &str| nos_proto::VpnRouteInfo {
            pe_next_hop: "192.0.2.3".parse().unwrap(),
            rd: rd.to_string(),
        };
        let routes = [PrefixRoutes {
            prefix: "10.10.0.0/24".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec!["10.0.0.3".parse().unwrap(), "10.0.0.3".parse().unwrap()],
                source: nos_proto::RouteSourceKind::Vpn,
                backup: None,
                discard: false,
                evpn: None,
                backup_tunnel: false,
                mpls_labels: vec![vec![100], vec![200]],
                vpn: vec![info("65001:1"), info("65001:2")],
                blackhole: false,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "10.10.0.0/24\n  * via 10.0.0.3 pe 192.0.2.3 rd 65001:1 label 100, \
             10.0.0.3 pe 192.0.2.3 rd 65001:2 label 200 [vpn]"
        );
    }

    #[test]
    fn ecmp_route_renders_every_gateway_on_one_line() {
        let routes = [PrefixRoutes {
            prefix: "203.0.113.80/32".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec!["10.0.0.2".parse().unwrap(), "10.0.1.2".parse().unwrap()],
                source: nos_proto::RouteSourceKind::Ospf,
                backup: Some("10.0.1.3".parse().unwrap()),
                discard: false,
                evpn: None,
                backup_tunnel: false,
                mpls_labels: vec![],
                vpn: vec![],
                blackhole: false,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "203.0.113.80/32\n  * via 10.0.0.2, 10.0.1.2 [ospf] backup 10.0.1.3"
        );
    }

    #[test]
    fn remote_lfa_backup_renders_as_a_tunnel() {
        let routes = [PrefixRoutes {
            prefix: "203.0.113.80/32".parse().unwrap(),
            candidates: vec![nos_proto::RouteEntry {
                gateways: vec!["10.0.0.2".parse().unwrap()],
                source: nos_proto::RouteSourceKind::Ospf,
                backup: Some("203.0.113.84".parse().unwrap()),
                discard: false,
                evpn: None,
                backup_tunnel: true,
                mpls_labels: vec![],
                vpn: vec![],
                blackhole: false,
            }],
        }];
        assert_eq!(
            render_prefix_routes(&routes),
            "203.0.113.80/32\n  * via 10.0.0.2 [ospf] backup tunnel 203.0.113.84"
        );
    }

    fn field(label: &str, old: Option<&str>, new: Option<&str>) -> FieldDiff {
        FieldDiff {
            label: label.to_string(),
            old: old.map(str::to_string),
            new: new.map(str::to_string),
        }
    }

    #[test]
    fn render_diff_hostname_change_no_color() {
        let diff = ConfigDiff {
            hostname: Some(field("hostname", Some("router-a"), Some("router-b"))),
            bgp_instances: vec![],
            ..Default::default()
        };
        assert_eq!(
            render_diff(&diff, false),
            "- hostname: router-a\n+ hostname: router-b"
        );
    }

    #[test]
    fn render_diff_shows_l2_and_policy_sections() {
        let base = nos_proto::Config::default();
        let mut candidate = base.clone();
        candidate
            .broadcast_domains
            .push(nos_proto::BroadcastDomain {
                name: "blue".into(),
                ..Default::default()
            });
        candidate
            .switching_profiles
            .push(nos_proto::SwitchingProfile {
                name: "trunk".into(),
                ..Default::default()
            });
        candidate
            .policy_definitions
            .push(nos_proto::PolicyDefinition {
                name: "p1".into(),
                source: "if this.prefix in 10.0.0.0/8:\n    reject\naccept\n".into(),
            });
        let out = render_diff(&nos_proto::diff_configs(&base, &candidate), false);
        for want in [
            "+ broadcast domain blue:",
            "+ switching-profile trunk:",
            "+ policy-definition p1:",
            "+   source: if this.prefix in 10.0.0.0/8:\n+     reject\n+ accept",
        ] {
            assert!(out.contains(want), "{want:?} missing from:\n{out}");
        }
    }

    #[test]
    fn render_diff_modified_section_shows_unstyled_header_as_context() {
        let diff = ConfigDiff {
            hostname: None,
            bgp_instances: vec![SectionDiff {
                header: "bgp instance r1".to_string(),
                name: "r1".to_string(),
                status: DiffStatus::Modified,
                fields: vec![field("asn", Some("65000"), Some("65001"))],
                subsections: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(
            render_diff(&diff, false),
            "  bgp instance r1:\n-   asn: 65000\n+   asn: 65001"
        );
    }

    #[test]
    fn render_diff_added_section_marks_every_line() {
        let diff = ConfigDiff {
            hostname: None,
            bgp_instances: vec![SectionDiff {
                header: "bgp instance r1".to_string(),
                name: "r1".to_string(),
                status: DiffStatus::Added,
                fields: vec![
                    field("router-id", None, Some("1.1.1.1")),
                    field("asn", None, Some("65000")),
                ],
                subsections: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(
            render_diff(&diff, false),
            "+ bgp instance r1:\n+   router-id: 1.1.1.1\n+   asn: 65000"
        );
    }

    #[test]
    fn render_diff_removed_section_marks_every_line() {
        let diff = ConfigDiff {
            hostname: None,
            bgp_instances: vec![SectionDiff {
                header: "bgp instance r1".to_string(),
                name: "r1".to_string(),
                status: DiffStatus::Removed,
                fields: vec![field("asn", Some("65000"), None)],
                subsections: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(
            render_diff(&diff, false),
            "- bgp instance r1:\n-   asn: 65000"
        );
    }

    #[test]
    fn highlight_marks_only_differing_middle() {
        let (old, new) = highlight("65000", "65001", true);
        assert_eq!(old, format!("6500{EMPH_ON}0{EMPH_OFF}"));
        assert_eq!(new, format!("6500{EMPH_ON}1{EMPH_OFF}"));
    }

    #[test]
    fn highlight_handles_pure_suffix_addition() {
        let (old, new) = highlight("ab", "abc", true);
        assert_eq!(old, "ab");
        assert_eq!(new, format!("ab{EMPH_ON}c{EMPH_OFF}"));
    }

    #[test]
    fn highlight_without_color_is_plain() {
        let (old, new) = highlight("65000", "65001", false);
        assert_eq!(old, "65000");
        assert_eq!(new, "65001");
    }

    fn log_entry(source: &str, message: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: 0,
            level: LogLevel::Info,
            source: source.to_string(),
            target: "nos_rib::reconcile".to_string(),
            message: message.to_string(),
            fields: vec![("table".to_string(), "rt1".to_string())],
        }
    }

    #[test]
    fn render_log_entries_empty_buffer() {
        assert_eq!(render_log_entries(&[]), "no log entries");
    }

    #[test]
    fn render_log_entry_includes_timestamp_level_source_and_fields() {
        let rendered = render_log_entry(&log_entry("nos-ribd[rt1]", "resynced"));
        assert_eq!(
            rendered,
            "1970-01-01T00:00:00.000Z  INFO nos-ribd[rt1] nos_rib::reconcile: resynced (table=rt1)"
        );
    }

    #[test]
    fn render_log_entries_joins_multiple_lines() {
        let entries = vec![log_entry("a", "one"), log_entry("b", "two")];
        let rendered = render_log_entries(&entries);
        assert_eq!(rendered.lines().count(), 2);
    }

    #[test]
    fn render_diff_nested_subsection_indents_one_level_deeper() {
        let diff = ConfigDiff {
            hostname: None,
            bgp_instances: vec![SectionDiff {
                header: "bgp instance r1".to_string(),
                name: "r1".to_string(),
                status: DiffStatus::Modified,
                fields: vec![],
                subsections: vec![SectionDiff {
                    header: "peer-group pg1".to_string(),
                    name: "pg1".to_string(),
                    status: DiffStatus::Modified,
                    fields: vec![field("remote-as", Some("65001"), Some("65002"))],
                    subsections: vec![],
                }],
            }],
            ..Default::default()
        };
        assert_eq!(
            render_diff(&diff, false),
            "  bgp instance r1:\n    peer-group pg1:\n-     remote-as: 65001\n+     remote-as: 65002"
        );
    }

    fn idle_peer(addr: &str) -> PeerSummary {
        PeerSummary {
            remote_address: addr.parse().unwrap(),
            peer_group: "pg1".to_string(),
            remote_as: None,
            remote_bgp_id: None,
            state: BgpSessionState::Idle,
            uptime_secs: None,
            negotiated_hold_time: None,
            negotiated_keepalive: None,
            shutdown: false,
            ao_current_key: None,
            ao_rnext_key: None,
            ao_packets_good: None,
            ao_packets_bad: None,
            ao_packets_key_not_found: None,
            max_prefix_held: false,
            accepted_prefixes: None,
            graceful_restart: None,
            stale_prefixes: 0,
        }
    }

    #[test]
    fn render_bgp_summary_shows_max_prefix_hold_and_prefix_counts() {
        let mut held = idle_peer("10.0.0.1");
        held.max_prefix_held = true;
        let mut up = idle_peer("10.0.0.2");
        up.state = BgpSessionState::Established;
        up.accepted_prefixes = Some([3, 0, 2]);
        assert_eq!(
            render_bgp_summary("r1", &[held, up]),
            "bgp instance r1:\n  10.0.0.1 AS - peer-group pg1 Idle (max-prefix) uptime - hold-time -\n  \
             10.0.0.2 AS - peer-group pg1 Established uptime - hold-time - prefixes v4 3 evpn 2"
        );
    }

    #[test]
    fn render_bgp_summary_shows_graceful_restart() {
        let mut stale = idle_peer("10.0.0.1");
        stale.stale_prefixes = 4;
        let mut up = idle_peer("10.0.0.2");
        up.state = BgpSessionState::Established;
        up.graceful_restart = Some(nos_proto::GrSummary {
            restart_time: 120,
            notification: true,
            restarting: false,
            families: vec![
                (nos_proto::AddressFamily::Ipv4Unicast, true),
                (nos_proto::AddressFamily::Ipv6Unicast, false),
            ],
        });
        assert_eq!(
            render_bgp_summary("r1", &[stale, up]),
            "bgp instance r1:\n  10.0.0.1 AS - peer-group pg1 Idle (gr-stale 4) uptime - hold-time -\n  \
             10.0.0.2 AS - peer-group pg1 Established uptime - hold-time - gr 120s N F:ipv4"
        );
    }

    #[test]
    fn render_bgp_bmp_lists_two_lines_per_station() {
        use nos_proto::{BmpFrameCounts, BmpMonitor, BmpStationState, BmpStationStatus};
        assert_eq!(
            render_bgp_bmp("r1", &[]),
            "bgp instance r1: no bmp stations"
        );
        let s = BmpStationStatus {
            name: "c1".into(),
            address: "192.0.2.9".parse().unwrap(),
            port: 11019,
            state: BmpStationState::Backoff,
            connected_since: None,
            monitor: BmpMonitor::Both,
            statistics_interval: Some(60),
            peers_monitored: 2,
            frames_sent: BmpFrameCounts {
                route_monitoring_pre: 4,
                ..Default::default()
            },
            overflows: 1,
            reconnects: 3,
            last_error: Some("refused".into()),
        };
        let out = render_bgp_bmp("r1", &[s]);
        assert!(out.contains("c1 192.0.2.9:11019 backoff monitor both statistics 60s peers 2 overflows 1 reconnects 3 last-error \"refused\""));
        assert!(out.contains("route-monitoring pre 4 post 0 end-of-rib 0"));
    }

    #[test]
    fn render_bgp_routes_marks_best_and_state() {
        use nos_proto::{BgpRouteSummary, RpkiValidationState as S};
        assert_eq!(render_bgp_routes("r1", &[]), "bgp instance r1: no routes");
        let r = |peer: Option<&str>, best, state| BgpRouteSummary {
            prefix: "192.0.2.0/24".to_string(),
            peer: peer.map(|p| p.parse().unwrap()),
            next_hop: peer.map(|p| p.parse().unwrap()),
            as_path: "65001 65002".to_string(),
            origin_as: Some(65002),
            local_pref: 100,
            best,
            validation_state: state,
            unknown_attributes: vec![],
        };
        let local = BgpRouteSummary {
            as_path: String::new(),
            origin_as: None,
            ..r(None, false, S::NotFound)
        };
        assert_eq!(
            render_bgp_routes(
                "r1",
                &[
                    r(Some("10.0.0.2"), true, S::Valid),
                    r(Some("10.0.0.3"), false, S::Invalid),
                    local
                ]
            ),
            "bgp instance r1:\n  > 192.0.2.0/24 from 10.0.0.2 next-hop 10.0.0.2 as-path [65001 65002] origin-as 65002 local-pref 100 valid\n    192.0.2.0/24 from 10.0.0.3 next-hop 10.0.0.3 as-path [65001 65002] origin-as 65002 local-pref 100 invalid\n    192.0.2.0/24 from local next-hop - as-path [] origin-as - local-pref 100 not-found"
        );
    }

    #[test]
    fn render_bgp_routes_lists_unknown_attributes_under_their_row() {
        use nos_proto::{BgpRouteSummary, RpkiValidationState as S, UnknownAttributeSummary as U};
        let r = |unknown_attributes| BgpRouteSummary {
            prefix: "192.0.2.0/24".to_string(),
            peer: None,
            next_hop: None,
            as_path: String::new(),
            origin_as: None,
            local_pref: 100,
            best: true,
            validation_state: S::Valid,
            unknown_attributes,
        };
        let u = |attr_type, flags, value: &str| U {
            attr_type,
            flags,
            value: value.into(),
        };
        let row =
            "  > 192.0.2.0/24 from local next-hop - as-path [] origin-as - local-pref 100 valid";
        assert_eq!(render_bgp_route_lines(&[r(vec![])]), row);
        assert_eq!(
            render_bgp_route_lines(&[r(vec![u(0xfe, 0xe0, "deadbeef"), u(7, 0xc0, "")]), r(vec![])]),
            format!("{row}\n      attr 254 flags=0xe0 len=4 deadbeef\n      attr 7 flags=0xc0 len=0 \n{row}")
        );
    }

    #[test]
    fn render_bgp_vpn_marks_the_best_path() {
        let family = nos_proto::AddressFamily::Vpnv4Unicast;
        assert_eq!(
            render_bgp_vpn("r1", family, &[]),
            "bgp instance r1: no vpnv4 routes"
        );
        let r = |best, labels: Vec<u32>| nos_proto::VpnRouteSummary {
            peer: "10.0.0.3".parse().unwrap(),
            rd: "65001:1".into(),
            prefix: "10.10.0.0/24".into(),
            labels,
            next_hop: "10.0.0.3".parse().unwrap(),
            route_targets: vec!["RT:65000:1".into()],
            as_path: "65001".into(),
            local_pref: 100,
            best,
            site_of_origin: None,
            path_id: None,
        };
        assert_eq!(
            render_bgp_vpn("r1", family, &[r(true, vec![100]), r(false, vec![16, 17])]),
            "bgp instance r1:\n  > rd 65001:1 10.10.0.0/24 label 100 next-hop 10.0.0.3 from 10.0.0.3 [RT:65000:1]\n    rd 65001:1 10.10.0.0/24 label 16/17 next-hop 10.0.0.3 from 10.0.0.3 [RT:65000:1]"
        );
    }

    #[test]
    fn render_bgp_vpn_shows_the_site_of_origin() {
        let r = nos_proto::VpnRouteSummary {
            peer: "10.0.0.3".parse().unwrap(),
            rd: "65001:1".into(),
            prefix: "10.10.0.0/24".into(),
            labels: vec![100],
            next_hop: "10.0.0.3".parse().unwrap(),
            route_targets: vec!["RT:65000:1".into()],
            as_path: String::new(),
            local_pref: 100,
            best: true,
            site_of_origin: Some("65001:77".into()),
            path_id: None,
        };
        assert!(
            render_bgp_vpn("r1", nos_proto::AddressFamily::Vpnv4Unicast, &[r])
                .ends_with("[RT:65000:1] soo 65001:77")
        );
    }

    #[test]
    fn render_bgp_evpn_lists_one_route_per_line() {
        assert_eq!(
            render_bgp_evpn("r1", &[]),
            "bgp instance r1: no evpn routes"
        );
        let route = EvpnRouteSummary {
            peer: "10.0.0.2".parse().unwrap(),
            route_type: 3,
            route: "[3]:[65000:1]:[0]:[192.0.2.1]".to_string(),
            next_hop: "192.0.2.1".parse().unwrap(),
            extended_communities: vec!["RT:65000:10000".to_string(), "encap:8".to_string()],
            local_pref: 0,
            communities: vec![0xFFFF_0000, 0xFDE9_0064],
        };
        assert_eq!(
            render_bgp_evpn("r1", &[route]),
            "bgp instance r1:\n  from 10.0.0.2 next-hop 192.0.2.1 [3]:[65000:1]:[0]:[192.0.2.1] [RT:65000:10000 encap:8] local-pref 0 communities [graceful-shutdown 65001:100]"
        );
    }

    #[test]
    fn render_bgp_flowspec_lists_one_rule_per_line() {
        assert_eq!(
            render_bgp_flowspec("r1", &[]),
            "bgp instance r1: no flowspec routes"
        );
        let route = FlowspecRouteSummary {
            peer: "10.0.0.2".parse().unwrap(),
            nlri: "dest 192.0.2.0/24 proto =6 dst-port =25".to_string(),
            extended_communities: vec!["traffic-rate:0:0".to_string()],
            validity: "invalid:no-covering-unicast-route".to_string(),
            actions: vec!["discard".to_string()],
            dataplane: None,
            family: "ipv4-flowspec".into(),
            rd: None,
            path_id: None,
        };
        assert_eq!(
            render_bgp_flowspec("r1", std::slice::from_ref(&route)),
            "bgp instance r1:\n  from 10.0.0.2 dest 192.0.2.0/24 proto =6 dst-port =25 [traffic-rate:0:0] invalid:no-covering-unicast-route actions: discard"
        );
        let bare = FlowspecRouteSummary {
            validity: "valid".to_string(),
            actions: vec![],
            ..route.clone()
        };
        assert!(render_bgp_flowspec("r1", &[bare]).ends_with("valid actions: none"));
        let copy = FlowspecRouteSummary {
            path_id: Some(7),
            ..route.clone()
        };
        assert!(render_bgp_flowspec("r1", &[copy]).contains("from 10.0.0.2 path-id 7 dest "));
        let best = FlowspecRouteSummary {
            dataplane: Some("installed".to_string()),
            ..route
        };
        assert!(
            render_bgp_flowspec("r1", &[best]).ends_with("actions: discard dataplane: installed")
        );
    }

    #[test]
    fn render_bgp_summary_empty_list() {
        assert_eq!(
            render_bgp_summary("r1", &[]),
            "bgp instance r1: no peers configured"
        );
    }

    #[test]
    fn render_bgp_summary_one_established_peer_shows_uptime_and_hold_time() {
        let mut peer = idle_peer("10.0.0.1");
        peer.remote_as = Some(65002);
        peer.state = BgpSessionState::Established;
        peer.uptime_secs = Some(3725);
        peer.negotiated_hold_time = Some(90);
        assert_eq!(
            render_bgp_summary("r1", &[peer]),
            "bgp instance r1:\n  10.0.0.1 AS 65002 peer-group pg1 Established uptime 1h02m hold-time 90"
        );
    }

    #[test]
    fn render_bgp_summary_idle_peer_shows_dashes() {
        assert_eq!(
            render_bgp_summary("r1", &[idle_peer("10.0.0.1")]),
            "bgp instance r1:\n  10.0.0.1 AS - peer-group pg1 Idle uptime - hold-time -"
        );
    }

    #[test]
    fn render_bgp_summary_with_ao_info_appends_key_and_counters() {
        let mut peer = idle_peer("10.0.0.1");
        peer.remote_as = Some(65002);
        peer.state = BgpSessionState::Established;
        peer.uptime_secs = Some(5);
        peer.negotiated_hold_time = Some(90);
        peer.ao_current_key = Some(1);
        peer.ao_rnext_key = Some(2);
        peer.ao_packets_good = Some(42);
        peer.ao_packets_bad = Some(1);
        peer.ao_packets_key_not_found = Some(0);
        assert_eq!(
            render_bgp_summary("r1", &[peer]),
            "bgp instance r1:\n  10.0.0.1 AS 65002 peer-group pg1 Established uptime 5s \
             hold-time 90 ao-current 1 ao-rnext 2 ao-good 42 ao-bad 1 ao-no-key 0"
        );
    }

    #[test]
    fn render_ospf_segment_routing_lines() {
        let ip = |n: u8| std::net::Ipv4Addr::new(n, n, n, n);
        let sr = nos_proto::SrSummary {
            srgb: vec![nos_proto::SrSrgb {
                router: ip(1),
                base: 16000,
                size: 8000,
            }],
            prefix_sids: vec![nos_proto::SrPrefixSid {
                router: ip(1),
                prefix: ip(1),
                prefix_len: 32,
                value: 1,
                absolute: false,
                label: Some(16001),
            }],
            adj_sids: vec![nos_proto::SrAdjSid {
                router: ip(1),
                neighbor: None,
                link_id: ip(2),
                label: 24000,
            }],
        };
        let out = render_ospf_segment_routing("o1", &sr);
        assert!(
            out.contains("srgb router 1.1.1.1 range 16000-23999"),
            "{out}"
        );
        assert!(
            out.contains("prefix 1.1.1.1/32 index 1 label 16001"),
            "{out}"
        );
        assert!(
            out.contains("adj-sid router 1.1.1.1 link 2.2.2.2 neighbor - label 24000"),
            "{out}"
        );
        assert!(
            render_ospf_segment_routing("o1", &nos_proto::SrSummary::default())
                .contains("no segment routing")
        );
    }

    #[test]
    fn render_ospf_database_empty_list() {
        assert_eq!(
            render_ospf_database("o1", &[]),
            "ospf instance o1: no LSAs installed"
        );
    }

    #[test]
    fn render_ospf_database_one_lsa() {
        let lsa = LsaSummary {
            area_id: "0.0.0.0".parse().unwrap(),
            lsa_type: 1,
            link_state_id: "1.1.1.1".parse().unwrap(),
            advertising_router: "1.1.1.1".parse().unwrap(),
            sequence_number: 0x8000_0001u32.cast_signed(),
            age: 42,
            external_metric: None,
            external_type2: false,
            checksum: 0xabcd,
            router_flags: Some(0),
            virtual_links: Vec::new(),
        };
        let out = render_ospf_database("o1", &[lsa]);
        assert!(out.starts_with("ospf instance o1:\nArea "), "{out}");
        assert!(out.contains("router  1.1.1.1"), "{out}");
        assert!(out.contains("0x80000001"), "{out}");
    }

    fn v2(t: u8, rid: &str) -> LsaSummary {
        LsaSummary {
            area_id: Ipv4Addr::UNSPECIFIED,
            lsa_type: t,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: rid.parse().unwrap(),
            sequence_number: 1,
            age: 1,
            checksum: 1,
            external_metric: None,
            external_type2: false,
            router_flags: None,
            virtual_links: Vec::new(),
        }
    }

    #[test]
    fn ospf_lsa_type_names_and_parse() {
        assert_eq!(ospf_lsa_type_name(5), "external");
        assert_eq!(ospf_lsa_type_name(99), "99");
        assert_eq!(parse_ospf_lsa_type("Router"), Ok(1));
        assert_eq!(parse_ospf_lsa_type("opaque-as"), Ok(11));
        assert_eq!(parse_ospf_lsa_type("42"), Ok(42));
        let e = parse_ospf_lsa_type("bogus\n").unwrap_err();
        assert!(e.contains("asbr-summary") && !e.contains('\n'), "{e}");
    }

    #[test]
    fn ospfv3_lsa_type_names_and_parse() {
        assert_eq!(ospfv3_lsa_type_name(0x2001), "router");
        assert_eq!(ospfv3_lsa_type_name(0xa029), "e-intra-area-prefix");
        assert_eq!(ospfv3_lsa_type_name(0x1234), "0x1234");
        assert_eq!(parse_ospfv3_lsa_type("LINK"), Ok(8));
        assert_eq!(parse_ospfv3_lsa_type("0x2001"), Ok(0x2001));
        assert_eq!(parse_ospfv3_lsa_type("8193"), Ok(0x2001));
        assert!(parse_ospfv3_lsa_type("nope").is_err());
        assert!(parse_ospfv3_lsa_type("0xzz").is_err());
    }

    #[test]
    fn ospf_database_info_cell() {
        let mut ext = v2(5, "1.1.1.1");
        ext.external_metric = Some(20);
        ext.external_type2 = true;
        let mut rtr = v2(1, "1.1.1.1");
        rtr.router_flags = Some(0x07 | 0x10);
        rtr.virtual_links = vec!["3.3.3.3".parse().unwrap()];
        assert_eq!(ospf_info(&ext), "metric 20 E2");
        assert_eq!(ospf_info(&rtr), "B,E,V vlink 3.3.3.3");
        assert_eq!(ospf_info(&v2(2, "1.1.1.1")), "-");
    }

    #[test]
    fn ospf_database_filter() {
        let all = [v2(1, "1.1.1.1"), v2(2, "1.1.1.1"), v2(1, "2.2.2.2")];
        let r1: Ipv4Addr = "1.1.1.1".parse().unwrap();
        assert_eq!(filter_ospf_database(&all, None, None).len(), 3);
        assert_eq!(filter_ospf_database(&all, Some(1), None).len(), 2);
        assert_eq!(filter_ospf_database(&all, None, Some(r1)).len(), 2);
        assert_eq!(filter_ospf_database(&all, Some(1), Some(r1)).len(), 1);
        assert_eq!(
            render_ospf_database_filtered("o", &filter_ospf_database(&all, Some(9), None)),
            "ospf instance o: no LSAs match"
        );
    }

    #[test]
    fn ospf_database_cannot_forge_rows() {
        let mut l = Ospfv3LsaSummary {
            area_id: Ipv4Addr::UNSPECIFIED,
            lsa_type: 8,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: Ipv4Addr::UNSPECIFIED,
            sequence_number: 1,
            age: 1,
            checksum: 1,
            link: Some("eth0\n0.0.0.0 forged\x1b[31m".into()),
            router_flags: None,
            virtual_links: Vec::new(),
        };
        l.link_state_id = Ipv4Addr::UNSPECIFIED;
        let out = render_ospfv3_database("v3\nforged", &[l]);
        assert_eq!(out.lines().count(), 4, "{out}");
        assert!(!out.contains('\x1b'), "{out}");
    }

    #[test]
    fn render_lldp_neighbors_empty_and_populated() {
        assert_eq!(render_lldp_neighbors(&[]), "no lldp neighbors");
        let neighbor = nos_proto::LldpNeighbor {
            local_interface: "eth1".to_string(),
            chassis_id: "02:00:00:00:00:02".to_string(),
            port_id: "eth1".to_string(),
            port_description: Some("uplink".to_string()),
            system_name: Some("router-b".to_string()),
            system_description: None,
            capabilities: vec!["router".to_string()],
            management_addresses: Vec::new(),
            ttl_remaining_secs: 117,
            ..Default::default()
        };
        assert_eq!(
            render_lldp_neighbors(std::slice::from_ref(&neighbor)),
            "eth1: neighbor router-b, chassis 02:00:00:00:00:02, port eth1 (uplink), capabilities router, ttl 117s"
        );
        let with_mgmt = nos_proto::LldpNeighbor {
            management_addresses: vec!["10.0.0.2".to_string(), "2001:db8::2".to_string()],
            ..neighbor
        };
        assert!(render_lldp_neighbors(&[with_mgmt])
            .contains("capabilities router, management 10.0.0.2,2001:db8::2, ttl 117s"));
    }

    #[test]
    fn render_lldp_neighbors_detail_prints_only_what_was_sent() {
        assert_eq!(render_lldp_neighbors_detail(&[]), "no lldp neighbors");
        let bare = nos_proto::LldpNeighbor {
            local_interface: "eth1".to_string(),
            chassis_id: "02:00:00:00:00:02".to_string(),
            port_id: "eth1".to_string(),
            ttl_remaining_secs: 117,
            ..Default::default()
        };
        assert_eq!(
            render_lldp_neighbors_detail(std::slice::from_ref(&bare)),
            "eth1: neighbor unnamed\n  chassis 02:00:00:00:00:02\n  port eth1\n  ttl 117s"
        );
        let full = nos_proto::LldpNeighbor {
            system_name: Some("router-b".to_string()),
            capabilities: vec!["bridge".to_string(), "router".to_string()],
            vlan_names: vec![nos_proto::lldp::LldpVlanName {
                id: 100,
                name: "bd-x".to_string(),
            }],
            port_vlan_id: Some(1),
            link_aggregation: Some(nos_proto::lldp::LldpLinkAggregation {
                capable: true,
                enabled: true,
                port_id: 7,
            }),
            max_frame_size: Some(9018),
            mac_phy: Some(nos_proto::lldp::LldpMacPhy {
                autoneg_supported: true,
                autoneg_enabled: false,
                advertised: 0x6c01,
                mau_type: 30,
            }),
            ..bare
        };
        let out = render_lldp_neighbors_detail(&[full]);
        for line in [
            "eth1: neighbor router-b",
            "  capabilities bridge,router",
            "  vlans 100 (bd-x)",
            "  port-vlan-id 1",
            "  aggregation aggregated, port id 7",
            "  max-frame-size 9018",
            "  mac/phy autoneg supported yes, enabled no, advertised 0x6c01, mau-type 30",
        ] {
            assert!(
                out.lines().any(|l| l == line),
                "{line:?} missing from:\n{out}"
            );
        }
    }

    #[test]
    fn render_bfd_reflector_off_and_counting() {
        use nos_proto::{ReflectorDiscards, ReflectorView};
        let mut v = ReflectorView {
            discriminators: vec![],
            received: 0,
            replied: 0,
            discarded: ReflectorDiscards::default(),
        };
        assert_eq!(
            render_bfd_reflector(&v),
            "sbfd reflector: off (no discriminator configured)"
        );
        v.discriminators = vec![0x0a00_0002];
        v.received = 5;
        v.replied = 3;
        assert!(render_bfd_reflector(&v).ends_with("received 5, replied 3, dropped: none"));
        v.discarded.unknown_discriminator = 2;
        v.discarded.martian = 1;
        let out = render_bfd_reflector(&v);
        assert!(
            out.starts_with("sbfd reflector: discriminators 10.0.0.2\n"),
            "{out}"
        );
        assert!(
            out.ends_with("dropped: martian-source 1, unknown-discriminator 2"),
            "{out}"
        );
    }

    #[test]
    fn render_lacp_summaries_empty() {
        assert_eq!(render_lacp_summaries(&[]), "no lacp port aggregates");
    }

    #[test]
    fn render_lacp_summaries_shows_identity_rate_and_each_port() {
        let summary = PortAggregateLacpSummary {
            aggregate: "bond1".to_string(),
            actor_system_id: [2, 0, 0, 0, 0, 0xab],
            actor_key: 7,
            actor_system_priority: 100,
            rate: LacpRate::Fast,
            min_links: 2,
            min_links_met: false,
            ports: vec![
                nos_proto::LacpPortStatus {
                    interface: "eth1".to_string(),
                    actor_port_number: 4,
                    receive_state: LacpReceiveState::Current,
                    mux_state: LacpMuxState::Distributing,
                    partner_system_id: Some([2, 0, 0, 0, 0, 1]),
                    partner_key: Some(3),
                    partner_port_number: Some(9),
                    actor_port_priority: 50,
                    mode: nos_proto::LacpMode::Passive,
                    partner_system_priority: Some(200),
                    partner_port_priority: Some(60),
                    selected: true,
                    synchronized: true,
                    actor_churn: false,
                    partner_churn: false,
                    individual: false,
                    unsupported_version_pdus: 0,
                    partner_version: None,
                    partner_port_algorithm: None,
                },
                nos_proto::LacpPortStatus {
                    interface: "eth2".to_string(),
                    actor_port_number: 5,
                    receive_state: LacpReceiveState::Defaulted,
                    mux_state: LacpMuxState::Detached,
                    partner_system_id: None,
                    partner_key: None,
                    partner_port_number: None,
                    actor_port_priority: 32768,
                    mode: nos_proto::LacpMode::Active,
                    partner_system_priority: None,
                    partner_port_priority: None,
                    selected: false,
                    synchronized: false,
                    actor_churn: false,
                    partner_churn: true,
                    individual: true,
                    unsupported_version_pdus: 3,
                    partner_version: None,
                    partner_port_algorithm: None,
                },
            ],
            version: nos_proto::LacpVersion::V1,
            port_algorithm: nos_proto::LacpPortAlgorithm::Unspecified,
            agreement: nos_proto::LacpAgreement::NotApplicable,
            conversations_per_link: Vec::new(),
        };
        let out = render_lacp_summaries(&[summary]);
        assert!(out.contains(
            "lacp bond1: system 02:00:00:00:00:ab, key 7, rate fast, system priority 100"
        ));
        assert!(out.contains("  min-links 2: not met, bond emptied"));
        assert!(out.contains("churn partner, port priority 32768, mode active, individual (partner not aggregatable), unsupported-version PDUs 3"), "{out}");
        assert!(out.contains("eth1: port 4, receive current, mux distributing, partner 02:00:00:00:00:01 key 3 port 9, selected yes, synchronized yes, churn none, port priority 50, partner priority 200/60, mode passive, unsupported-version PDUs 0"));
        assert!(out.contains("eth2: port 5, receive defaulted, mux detached, partner none (defaulted), selected no, synchronized no, churn partner"));
    }

    fn addr(a: &str, label: Option<&str>) -> InterfaceAddress {
        InterfaceAddress {
            address: a.parse().unwrap(),
            label: label.map(str::to_string),
        }
    }

    fn sub_status(tag: u16, addresses: Vec<InterfaceAddress>) -> SubinterfaceStatus {
        SubinterfaceStatus {
            mtu: 1500,
            tag,
            addresses,
            routing_table: (tag == 0).then(|| "rt1".to_string()),
            link_local_address: None,
            link: None,
        }
    }

    fn oper(admin_up: bool, oper_up: bool, reason: Option<&str>, age: Option<u64>) -> LinkOper {
        LinkOper {
            admin_up,
            oper_up,
            down_reason: reason.map(str::to_string),
            last_change_secs: age,
            counters: None,
        }
    }

    fn iface(name: &str) -> InterfaceStatus {
        InterfaceStatus {
            name: name.to_string(),
            addresses: vec![addr("10.9.0.1/32", None)],
            routing_table: None,
            switching_profile: Some("trunk".to_string()),
            port_aggregate: None,
            mtu: 1500,
            subinterfaces: vec![
                sub_status(0, vec![addr("10.0.0.1/24", None)]),
                sub_status(5, Vec::new()),
            ],
            link_local_address: None,
            err_disabled: false,
            speed_mbps: Some(1000),
            link: Some(oper(true, true, None, Some(2 * 86400 + 3 * 3600))),
        }
    }

    fn agg() -> PortAggregateStatus {
        PortAggregateStatus {
            name: "bond1".to_string(),
            mode: nos_proto::PortAggregateMode::Xor,
            switching_profile: None,
            mtu: 9000,
            subinterfaces: vec![sub_status(0, Vec::new())],
            link_local_address: None,
            bond_name: None,
            err_disabled: false,
            steering: Vec::new(),
            speed_mbps: None,
            link: None,
        }
    }

    #[test]
    fn render_port_aggregate_statuses_golden() {
        assert_eq!(render_port_aggregate_statuses(&[]), "no port aggregates");
        assert_eq!(
            render_port_aggregate_statuses(std::slice::from_ref(&agg())),
            "port-aggregate bond1: mode xor, switching-profile unset, mtu 9000\n  \
             subinterface 0: address [none], routing-table rt1, mtu 1500"
        );
        let held = PortAggregateStatus {
            err_disabled: true,
            ..agg()
        };
        assert!(render_port_aggregate_status(&held).contains("\n  Err-disabled: yes"));
    }

    #[test]
    fn interface_detail_header_variants() {
        let hdr = |link| {
            let st = InterfaceStatus {
                link,
                ..iface("eth0")
            };
            render_interface_detail(&st)
                .lines()
                .next()
                .unwrap()
                .to_string()
        };
        assert_eq!(
            hdr(Some(oper(true, true, None, Some(2 * 86400 + 3 * 3600)))),
            "eth0 is up, oper up (last change 2d03h00m ago)"
        );
        assert_eq!(
            hdr(Some(oper(false, false, Some("admin-down"), None))),
            "eth0 is administratively down, oper down (admin-down)"
        );
        assert_eq!(
            hdr(Some(oper(true, false, Some("no-carrier"), None))),
            "eth0 is up, oper down (no-carrier)"
        );
        assert_eq!(hdr(None), "eth0 is -, oper -");
    }

    #[test]
    fn interface_detail_body_golden() {
        let mut st = iface("eth0");
        st.subinterfaces[1].link_local_address = Some("fe80::1".parse().unwrap());
        let out = render_interface_detail(&st);
        assert!(
            out.starts_with("eth0 is up, oper up (last change 2d03h00m ago)\n"),
            "{out}"
        );
        assert!(out.contains("10.9.0.1/32"), "{out}");
        assert!(!out.contains("\"address\""), "no JSON leaks: {out}");
        assert!(out.contains("1000 Mb/s"), "{out}");
        // link-local comes from the first subinterface that has one
        assert!(out.matches("fe80::1").count() >= 1, "{out}");
        assert!(out.contains("10.0.0.1/24"), "{out}");
    }

    #[test]
    fn interface_detail_counters() {
        let mut st = iface("eth0");
        let mut l = oper(true, true, None, Some(5));
        l.counters = Some(nos_proto::LinkCounters {
            rx_packets: 1_234_567,
            rx_bytes: 840_300_000,
            rx_errors: 0,
            rx_dropped: 3,
            tx_packets: 12,
            tx_bytes: 2_500_000_000,
            tx_errors: 0,
            tx_dropped: 0,
        });
        st.link = Some(l);
        let out = render_interface_detail(&st);
        assert!(out.contains("MB") && out.contains("GB"), "{out}");
        st.link.as_mut().unwrap().counters = None;
        let out = render_interface_detail(&st);
        assert!(!out.contains("MB"), "{out}");
        st.link = None;
        assert!(render_interface_detail(&st).contains("oper -"));
    }

    #[test]
    fn bare_show_interface_is_every_detail() {
        assert_eq!(render_interface_details(&[]), "no interfaces");
        let out = render_interface_details(&[iface("eth0"), iface("eth1")]);
        assert_eq!(out.matches("\n\neth1 is up").count(), 1, "{out}");
    }

    #[test]
    fn interface_brief_golden() {
        assert_eq!(render_interface_brief(&[], &[]), "no interfaces");
        let mut down = iface("eth1");
        down.link = Some(oper(true, false, Some("no-carrier"), None));
        down.speed_mbps = None;
        down.subinterfaces = Vec::new();
        down.port_aggregate = Some("bond1".to_string());
        down.addresses = Vec::new();
        let mut unobserved = iface("lo");
        unobserved.link = None;
        unobserved.subinterfaces = Vec::new();
        let mut bond = agg();
        bond.link = Some(oper(true, true, None, Some(1)));
        bond.subinterfaces
            .push(sub_status(7, vec![addr("10.7.0.1/24", None)]));
        let out = render_interface_brief(&[iface("eth0"), down, unobserved], &[bond]);
        // Column widths are the table module's business: compare cells.
        let rows: Vec<Vec<&str>> = out
            .lines()
            .skip(2)
            .map(|l| l.split_whitespace().collect())
            .collect();
        assert_eq!(rows.len(), 6, "{out}");
        assert_eq!(rows[0][..3], ["eth0", "up", "up"]);
        assert!(out.contains("eth0.5"), "{out}");
        assert!(rows[2].contains(&"(no-carrier)"), "{out}");
        assert_eq!(rows[2][1], "up");
        assert!(rows[2].contains(&"bond1"), "{out}");
        assert_eq!(rows[3][..3], ["lo", "-", "-"]);
        assert_eq!(rows[4][..3], ["bond1", "up", "up"]);
        assert!(
            out.contains("bond1.7") && out.contains("10.7.0.1/24"),
            "{out}"
        );
    }

    #[test]
    fn interface_renderers_neutralize_forged_values() {
        let mut st = iface(EVIL);
        st.routing_table = Some(EVIL.to_string());
        st.port_aggregate = Some(EVIL.to_string());
        st.link = Some(oper(true, false, Some(EVIL), None));
        st.subinterfaces[0].routing_table = Some(EVIL.to_string());
        let detail = render_interface_detail(&st);
        assert!(!has_raw_control(&detail.replace('\n', "")), "{detail:?}");
        let mut bond = agg();
        bond.name = EVIL.to_string();
        let brief = render_interface_brief(&[st.clone()], &[bond]);
        assert!(!has_raw_control(&brief.replace('\n', "")), "{brief:?}");
        assert_eq!(brief.lines().count(), 2 + 3);
    }

    #[test]
    fn render_lacp_summaries_v2_line_only_for_version_2() {
        let mut s = PortAggregateLacpSummary {
            aggregate: "bond1".to_string(),
            actor_system_id: [0; 6],
            actor_key: 1,
            actor_system_priority: 32768,
            rate: LacpRate::Slow,
            min_links: 1,
            min_links_met: true,
            ports: Vec::new(),
            version: nos_proto::LacpVersion::V1,
            port_algorithm: nos_proto::LacpPortAlgorithm::CVlan,
            agreement: nos_proto::LacpAgreement::Agreed,
            conversations_per_link: vec![("eth1".to_string(), 2048), ("eth2".to_string(), 2048)],
        };
        assert!(!render_lacp_summaries(&[s.clone()]).contains("version 2"));
        s.version = nos_proto::LacpVersion::V2;
        assert!(render_lacp_summaries(&[s]).contains(
            "\n  version 2, algorithm c-vlan, agreement agreed, conversations eth1 2048, eth2 2048"
        ));
    }

    #[test]
    fn render_lacp_port_names_every_state() {
        let port = |receive, mux, actor_churn, partner_churn| nos_proto::LacpPortStatus {
            interface: "eth1".to_string(),
            actor_port_number: 1,
            receive_state: receive,
            mux_state: mux,
            partner_system_id: Some([2, 0, 0, 0, 0, 1]),
            partner_key: None,
            partner_port_number: None,
            actor_port_priority: 32768,
            mode: nos_proto::LacpMode::Active,
            partner_system_priority: None,
            partner_port_priority: None,
            selected: false,
            synchronized: false,
            actor_churn,
            partner_churn,
            individual: false,
            unsupported_version_pdus: 0,
            partner_version: None,
            partner_port_algorithm: None,
        };
        for (p, want) in [
            (
                port(LacpReceiveState::Initialize, LacpMuxState::Waiting, true, false),
                "receive initialize, mux waiting, partner none, selected no, synchronized no, churn actor",
            ),
            (
                port(LacpReceiveState::PortDisabled, LacpMuxState::Attached, true, true),
                "receive port-disabled, mux attached, partner none, selected no, synchronized no, churn actor+partner",
            ),
            (
                port(LacpReceiveState::LacpDisabled, LacpMuxState::Collecting, false, false),
                "receive lacp-disabled, mux collecting,",
            ),
            (
                port(LacpReceiveState::Expired, LacpMuxState::Detached, false, false),
                "receive expired, mux detached,",
            ),
        ] {
            let out = render_lacp_port(&p);
            assert!(out.contains(want), "{out}");
        }
        let empty = PortAggregateLacpSummary {
            aggregate: "bond1".to_string(),
            actor_system_id: [0; 6],
            actor_key: 1,
            actor_system_priority: 32768,
            rate: LacpRate::Slow,
            min_links: 1,
            min_links_met: true,
            ports: Vec::new(),
            version: nos_proto::LacpVersion::V1,
            port_algorithm: nos_proto::LacpPortAlgorithm::Unspecified,
            agreement: nos_proto::LacpAgreement::NotApplicable,
            conversations_per_link: Vec::new(),
        };
        assert!(
            render_lacp_summaries(&[empty]).ends_with("system priority 32768\n  no member ports")
        );
    }

    #[test]
    fn render_ospfv3_neighbors_and_database() {
        assert_eq!(
            render_ospfv3_database("v3", &[]),
            "ospfv3 instance v3: no LSAs installed"
        );
        let lsa = |link: Option<&str>| Ospfv3LsaSummary {
            area_id: Ipv4Addr::UNSPECIFIED,
            lsa_type: 0x2001,
            link_state_id: Ipv4Addr::UNSPECIFIED,
            advertising_router: Ipv4Addr::new(2, 2, 2, 2),
            sequence_number: 1,
            age: 3,
            checksum: 0x1234,
            link: link.map(str::to_string),
            router_flags: None,
            virtual_links: Vec::new(),
        };
        let out = render_ospfv3_database("v3", &[lsa(Some("eth0.0")), lsa(None)]);
        assert!(out.contains("router  0.0.0.0        2.2.2.2"), "{out}");
        assert!(out.contains("eth0.0"), "{out}");
    }

    #[test]
    fn render_small_enums_and_edge_cases() {
        assert_eq!(
            render_bgp_session_state(BgpSessionState::OpenSent),
            "OpenSent"
        );
        assert_eq!(
            render_bgp_session_state(BgpSessionState::OpenConfirm),
            "OpenConfirm"
        );
        for (s, want) in [
            (RouteSourceKind::Static, "static"),
            (RouteSourceKind::Bgp, "bgp"),
            (RouteSourceKind::Connected, "connected"),
            (RouteSourceKind::Evpn, "evpn"),
            (RouteSourceKind::Vpn, "vpn"),
        ] {
            assert_eq!(render_route_source(s), want);
        }
        for (l, want) in [
            (LogLevel::Trace, "TRACE"),
            (LogLevel::Debug, "DEBUG"),
            (LogLevel::Warn, "WARN"),
            (LogLevel::Error, "ERROR"),
        ] {
            assert_eq!(render_log_level(l), want);
        }
        assert_eq!(render_prefix_routes(&[]), "no routes");
        assert_eq!(render_policy_source(""), "(empty)");
        // An out-of-range timestamp falls back to the raw milliseconds.
        let mut entry = log_entry("configd", "m");
        entry.timestamp_ms = u64::MAX;
        entry.fields.clear();
        assert!(render_log_entry(&entry).starts_with(&u64::MAX.to_string()));
    }

    /// A config from the fields given, the rest default.
    fn config_from(json: &serde_json::Value) -> Config {
        let mut base = serde_json::to_value(Config::default()).unwrap();
        base.as_object_mut()
            .unwrap()
            .extend(json.as_object().unwrap().clone());
        serde_json::from_value(base).unwrap()
    }

    /// The fields #116 found missing from the hand-written renderer.
    fn ospf_config() -> Config {
        config_from(&serde_json::json!({
            "hostname": "r1",
            "ospf_instances": [{
                "name": "o1", "router_id": "1.1.1.1", "areas": [{
                    "area_id": "0.0.0.0", "profiles": [{
                        "name": "p1", "hello_interval": 5, "dead_interval": 20,
                        "cost": 10, "priority": 3, "mtu": 1400,
                        "network_type": "PointToPoint",
                        "auth": {"Crypto": {"keys": [
                            {"key_id": 1, "algorithm": "HmacSha256", "key": "k", "is_current": true}
                        ]}}
                    }]
                }]
            }],
            "routing_tables": [{
                "name": "rt1", "ospfv3_instances": ["o3"],
                "evpn": {"l3_vni": 5000, "rd": "1:1"}
            }],
            "users": [{"name": "admin", "password": "$argon2id$secret"}]
        }))
    }

    #[test]
    fn show_config_lists_every_configured_field() {
        let out = render_config(&ospf_config());
        for want in [
            "hostname r1",
            "ospf instance o1",
            "  area 0.0.0.0",
            "      hello-interval 5",
            "      dead-interval 20",
            "      cost 10",
            "      priority 3",
            "      mtu 1400",
            "      network-type point-to-point",
            "      crypto-key 1 hmac-sha256 k",
            "      crypto-key 1 current",
            "routing-table rt1",
            "  ospfv3-instance o3",
            "  evpn",
            "    l3-vni 5000",
            "    rd 1:1",
        ] {
            assert!(out.lines().any(|l| l == want), "missing `{want}` in\n{out}");
        }
    }

    #[test]
    fn show_config_never_prints_a_password() {
        let out = render_config(&ospf_config());
        assert!(out.contains("user admin\n  password <hidden>"), "{out}");
        assert!(!out.contains("argon2id"), "{out}");
    }

    fn admin_config() -> Config {
        config_from(&serde_json::json!({
            "hostname": "r1",
            "admin": {"keys": [{"label": "bgp-1", "secret": "needle-secret"}]}
        }))
    }

    #[test]
    fn show_config_leaves_the_keystore_out() {
        let out = render_config(&admin_config());
        assert_eq!(out, "hostname r1");
        assert!(!out.contains("needle-secret"), "{out}");
    }

    #[test]
    fn show_config_admin_lists_labels_with_hidden_secrets() {
        let out = render_admin_config(&admin_config());
        assert_eq!(out, "admin\n  key bgp-1\n    secret <hidden>");
        assert!(!out.contains("needle-secret"), "{out}");
        assert_eq!(
            render_admin_config(&config_from(&serde_json::json!({"hostname": "r1"}))),
            "no admin keys configured"
        );
    }

    #[test]
    fn a_transaction_shows_the_keystore_only_inside_admin() {
        let snap = TransactionSnapshot {
            name: "t".to_string(),
            config: admin_config(),
            dirty: true,
            resumed: false,
            generation: 1,
        };
        let root = render_transaction(&snap, &Path::root());
        assert!(!root.contains("bgp-1"), "{root}");
        let path = Path::from(vec!["admin".to_string()]);
        let inside = render_transaction(&snap, &path);
        assert!(
            inside.contains("key bgp-1") && inside.contains("<hidden>"),
            "{inside}"
        );
        assert!(!inside.contains("needle-secret"), "{inside}");
    }

    #[test]
    fn show_config_of_nothing_says_so() {
        assert_eq!(
            render_config(&config_from(&serde_json::json!({"hostname": "nos"}))),
            "nothing configured"
        );
    }

    #[test]
    fn show_config_path_scopes_and_reports_misses() {
        let cfg = config_from(&serde_json::json!({"hostname": "nos"}));
        assert_eq!(
            render_config_path(&cfg, &["bgp", "bogus"]).unwrap_err(),
            "no such object: bgp bogus"
        );
        let err = render_config_path(&cfg, &["x\u{1b}[31m"]).unwrap_err();
        assert!(!err.contains('\u{1b}'), "{err:?}");
    }

    #[test]
    fn show_config_path_goldens() {
        let cfg = ospf_config();
        assert_eq!(
            render_config_path(&cfg, &["routing-table", "rt1", "evpn"]).unwrap(),
            "evpn\n  l3-vni 5000\n  rd 1:1"
        );
        let out = render_config_path(&cfg, &["ospf", "instance", "o1"]).unwrap();
        assert!(
            out.starts_with("ospf instance o1\n  router-id 1.1.1.1"),
            "{out}"
        );
        // Secrets stay hidden in a scoped print.
        let out = render_config_path(&cfg, &["user", "admin"]).unwrap();
        assert_eq!(out, "user admin\n  password <hidden>");
        assert!(!out.contains("argon2id"), "{out}");
        // An existing but empty object prints just its header, never a miss.
        let empty = config_from(&serde_json::json!({
            "routing_tables": [{"name": "rt1"}]
        }));
        let out = render_config_path(&empty, &["routing-table", "rt1"]).unwrap();
        assert_eq!(out, "routing-table rt1");
    }

    #[test]
    fn show_this_scopes_to_the_position() {
        let snap = TransactionSnapshot {
            name: "t".to_string(),
            config: ospf_config(),
            dirty: false,
            resumed: false,
            generation: 0,
        };
        let at = |segs: &[&str]| {
            let path = Path::from(segs.iter().map(ToString::to_string).collect::<Vec<_>>());
            render_transaction(&snap, &path)
        };
        let out = at(&["ospf-instance", "o1", "area", "0.0.0.0", "profile", "p1"]);
        assert!(out.starts_with("profile p1\n  hello-interval 5"), "{out}");
        assert_eq!(at(&["routing-table", "nope"]), "nothing configured here");
        assert!(at(&["routing-table", "rt1", "evpn"]).starts_with("evpn\n  l3-vni 5000"));
    }

    #[test]
    fn show_config_of_a_switching_profile() {
        let cfg = config_from(&serde_json::json!({
            "broadcast_domains": [{"name": "bd1", "addresses": []}],
            "switching_profiles": [{"name": "sp1", "members": [
                {"broadcast_domain": "bd1", "tag": {"Dot1q": 100}}
            ]}]
        }));
        assert_eq!(render_config(&cfg), "broadcast domain bd1\nswitching-profile sp1\n  broadcast-domain bd1\n    tag dot1q 100");
    }

    #[test]
    fn sanitize_escapes_control_and_format_chars_visibly() {
        for (raw, want) in [
            ("\x1b[31mred", "\\x1b[31mred"),
            ("\x1b]0;title\x07", "\\x1b]0;title\\x07"),
            ("\x1b]52;c;AAAA\x07", "\\x1b]52;c;AAAA\\x07"),
            ("a\u{9b}b\u{9d}", "a\\x9bb\\x9d"),
            ("\x7f\0\r", "\\x7f\\x00\\x0d"),
            (
                "a\u{202e}b\u{200b}\u{2066}\u{feff}",
                "a\\u{202e}b\\u{200b}\\u{2066}\\u{feff}",
            ),
        ] {
            assert_eq!(sanitize(raw), want);
        }
    }

    #[test]
    fn sanitize_keeps_clean_text_borrowed_and_layout_whitespace() {
        for clean in ["plain", "tab\there\nline two", "héllo 日本 🦀"] {
            assert!(matches!(sanitize(clean), Cow::Borrowed(_)));
        }
        assert_eq!(sanitize_line("a\nb\tc"), "a\\nb\tc");
    }

    fn has_raw_control(s: &str) -> bool {
        s.chars()
            .any(|c| (c.is_control() && c != '\n' && c != '\t') || needs_escape(c, false))
    }

    const EVIL: &str = "x\x1b]0;pwn\x07\u{9b}31m\u{202e}\r";

    #[test]
    fn a_multi_line_lldp_name_cannot_forge_a_row() {
        let n = nos_proto::LldpNeighbor {
            local_interface: "eth1".to_string(),
            system_name: Some("evil\neth9: neighbor fake".to_string()),
            chassis_id: EVIL.to_string(),
            port_id: "p\nq".to_string(),
            port_description: Some("d\ne".to_string()),
            system_description: Some("s\n  chassis forged".to_string()),
            ..nos_proto::LldpNeighbor::default()
        };
        let summary = render_lldp_neighbors(std::slice::from_ref(&n));
        assert_eq!(summary.lines().count(), 1, "{summary}");
        assert!(!has_raw_control(&summary), "{summary}");
        let detail = render_lldp_neighbors_detail(std::slice::from_ref(&n));
        // header, chassis, port, port-description, system-description, ttl
        assert_eq!(detail.lines().count(), 6, "{detail}");
        assert!(!has_raw_control(&detail));
        assert!(!detail.contains("\n  chassis forged"));
    }

    #[test]
    fn log_entries_stay_one_line_each() {
        let e = LogEntry {
            timestamp_ms: 1,
            level: LogLevel::Info,
            source: EVIL.to_string(),
            target: "t\nu".to_string(),
            message: "m\n2026-01-01 INFO forged: hi".to_string(),
            fields: vec![("k\n".to_string(), EVIL.to_string())],
        };
        let out = render_log_entry(&e);
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(!has_raw_control(&out));
    }

    #[test]
    fn names_in_bgp_and_interface_output_are_escaped() {
        let mut peer = idle_peer("10.0.0.1");
        peer.peer_group = EVIL.to_string();
        let out = render_bgp_summary(EVIL, &[peer]);
        assert!(!has_raw_control(&out), "{out}");
        let status = InterfaceStatus {
            link_local_address: None,
            name: EVIL.to_string(),
            addresses: Vec::new(),
            routing_table: Some(EVIL.to_string()),
            switching_profile: None,
            port_aggregate: None,
            mtu: 1500,
            speed_mbps: None,
            subinterfaces: Vec::new(),
            err_disabled: false,
            link: None,
        };
        let out = render_interface_detail(&status);
        assert!(!has_raw_control(&out.replace('\n', "")), "{out:?}");
    }

    #[test]
    fn diff_escapes_values_but_keeps_its_own_sgr_codes() {
        let diff = ConfigDiff {
            hostname: Some(FieldDiff {
                label: EVIL.to_string(),
                old: Some(EVIL.to_string()),
                new: Some("new\x1b[2J".to_string()),
            }),
            ..ConfigDiff::default()
        };
        let out = render_diff(&diff, true);
        assert!(out.contains(RED) && out.contains(GREEN) && out.contains(RESET));
        let stripped = [RED, GREEN, EMPH_ON, EMPH_OFF, RESET]
            .iter()
            .fold(out, |acc, c| acc.replace(c, ""));
        assert!(!has_raw_control(&stripped), "{stripped:?}");
    }

    #[test]
    fn operator_text_keeps_its_newlines() {
        let out = render_policy_source("a\n\tb\x1b");
        assert!(out.contains("a\n") && out.contains("\tb\\x1b"), "{out}");
    }

    /// A new `render_*` cannot skip the terminal escaping (#1365).
    #[test]
    fn every_public_renderer_sanitizes() {
        let src = include_str!("format.rs");
        let body = src.split("#[cfg(test)]\nmod tests").next().unwrap();
        let mut checked = 0;
        for chunk in body.split("\npub fn render_").skip(1) {
            let name = chunk.split('(').next().unwrap();
            let end = chunk.find("\n}\n").unwrap();
            // `render_diff` emits SGR itself, so it escapes values instead.
            if name == "diff" {
                continue;
            }
            assert!(
                chunk[..end].contains("sanitize("),
                "render_{name} lacks a sanitize pass"
            );
            checked += 1;
        }
        assert!(checked > 30);
    }

    /// No Debug formatting in production code: output words are explicit.
    #[test]
    fn no_debug_formatting_outside_tests() {
        let src = include_str!("format.rs");
        let body = src.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(!body.contains("{:?}"), "format.rs uses {{:?}}");
    }

    /// A daemon string with a newline must not add a line to a one-record
    /// renderer (the whole-output `sanitize` keeps `\n`).
    #[test]
    fn newline_in_daemon_strings_cannot_forge_a_row() {
        const BAD: &str = "x\nFORGED";
        let lines = |s: String| s.lines().count();
        let bmp = |err: &str| {
            let s = nos_proto::BmpStationStatus {
                name: "c1".into(),
                address: "192.0.2.9".parse().unwrap(),
                port: 1,
                state: nos_proto::BmpStationState::Backoff,
                connected_since: None,
                monitor: nos_proto::BmpMonitor::Both,
                statistics_interval: None,
                peers_monitored: 0,
                frames_sent: nos_proto::BmpFrameCounts::default(),
                overflows: 0,
                reconnects: 0,
                last_error: Some(err.into()),
            };
            render_bgp_bmp("r1", &[s])
        };
        assert_eq!(lines(bmp(BAD)), lines(bmp("x")));
        let stp = |n: &str| {
            let mut s = nos_proto::StpSummary {
                enabled: true,
                ..Default::default()
            };
            s.ports = vec![nos_proto::StpPortInfo {
                name: n.into(),
                ..nos_proto::StpPortInfo::default()
            }];
            render_spanning_tree(&s)
        };
        assert_eq!(lines(stp(BAD)), lines(stp("x")));
    }
}

#[cfg(test)]
mod mst_tests {
    use super::{render_mst_config, render_spanning_tree, render_stp_domain, render_stp_instance};
    use nos_proto::{StpInstance, StpInstancePort, StpMst, StpState, StpSummary};

    fn summary() -> StpSummary {
        let port = |name: &str, boundary| StpInstancePort {
            name: name.into(),
            state: StpState::Forwarding,
            boundary,
            cost: 2000,
            priority: 128,
            ..StpInstancePort::default()
        };
        StpSummary {
            enabled: true,
            mst: Some(StpMst {
                region_name: "lab".into(),
                revision: 7,
                digest: "9357ebb7a8d74dd5fef4f2bab50531aa".into(),
                max_hops: 20,
                instances: vec![
                    StpInstance::default(),
                    StpInstance {
                        id: 1,
                        vlans: "10,20-30".into(),
                        domains: vec!["bd1".into(), "bd2".into()],
                        bridge_id: "1000.02:00:00:00:00:01".into(),
                        root_id: "1000.02:00:00:00:00:01".into(),
                        ports: vec![port("eth1", false), port("eth2", true)],
                        ..StpInstance::default()
                    },
                ],
            }),
            ..StpSummary::default()
        }
    }

    #[test]
    fn mst_config_lists_region_and_vlan_map() {
        let out = render_mst_config(&summary());
        assert!(out.contains("name     lab"));
        assert!(out.contains("digest   9357ebb7a8d74dd5fef4f2bab50531aa"));
        assert!(out.contains("       1  10,20-30  bd1,bd2"), "{out}");
        assert!(out.contains("       0  -         -"), "{out}");
        assert_eq!(
            render_mst_config(&StpSummary::default()),
            "spanning-tree is not in mode mstp"
        );
    }

    #[test]
    fn instance_shows_ports_and_boundary() {
        let out = render_stp_instance(&summary(), 1);
        assert!(out.starts_with("instance 1 (MSTI)"));
        assert!(out.contains("this bridge is the root"));
        assert!(out.contains("eth2"));
        assert!(out.lines().last().unwrap().ends_with("  Boundary"));
        assert!(render_stp_instance(&summary(), 0).starts_with("instance 0 (CIST)"));
        assert_eq!(
            render_stp_instance(&summary(), 9),
            "no spanning-tree instance 9"
        );
    }

    #[test]
    fn domain_view_flags_compat_and_pvid_inconsistent_ports() {
        let port = |name: &str, compat, inconsistent| StpInstancePort {
            name: name.into(),
            state: StpState::Discarding,
            compat,
            inconsistent,
            ..StpInstancePort::default()
        };
        let s = StpSummary {
            enabled: true,
            mode: nos_proto::StpMode::RapidPvst,
            bridge_id: "8000.02:00:00:00:00:01".into(),
            pvst: vec![StpInstance {
                id: 10,
                vlans: "10".into(),
                domains: vec!["bd1".into()],
                bridge_id: "800a.02:00:00:00:00:01".into(),
                root_id: "100a.02:00:00:00:00:02".into(),
                root_port: Some("eth1".into()),
                ports: vec![port("eth1", true, false), port("eth2", false, true)],
                ..StpInstance::default()
            }],
            ..StpSummary::default()
        };
        let out = render_stp_domain(&s, "bd1");
        assert!(out.contains("vlan      10"));
        assert!(out.contains("root port eth1"));
        let rows: Vec<_> = out.lines().skip(7).collect();
        assert!(rows[0].ends_with("  Compat"), "{out}");
        assert!(rows[1].ends_with("  PVID-inconsistent"), "{out}");
        assert_eq!(
            render_stp_domain(&s, "bd9"),
            "no spanning-tree tree for domain bd9"
        );
        assert_eq!(
            render_stp_domain(&StpSummary::default(), "bd1"),
            "spanning-tree is not in mode rapid-pvst"
        );
        let all = render_spanning_tree(&s);
        assert!(all.starts_with("mode rapid-pvst"));
        assert!(all.contains("bd1") && all.contains("100a.02:00:00:00:00:02"));
    }
}

#[cfg(test)]
mod stp_detail_tests {
    use super::render_stp_detail;
    use nos_proto::{
        StpInstance, StpInstancePort, StpMode, StpMst, StpPortCounters, StpPortInfo, StpSummary,
        StpTcCause, StpTopology,
    };

    fn counters() -> StpPortCounters {
        StpPortCounters {
            in_rstp_bpdu: 7,
            out_rstp_bpdu: 9,
            tc_received: 2,
            forward_transitions: 1,
            ..StpPortCounters::default()
        }
    }

    fn topology() -> StpTopology {
        StpTopology {
            count: 3,
            last_secs_ago: Some(12),
            last_port: Some("eth1".into()),
            last_cause: Some(StpTcCause::Received),
        }
    }

    fn tree(id: u16) -> StpInstance {
        StpInstance {
            id,
            domains: vec![format!("bd{id}")],
            topology: topology(),
            ports: vec![StpInstancePort {
                name: "eth1".into(),
                boundary: true,
                point_to_point: true,
                counters: counters(),
                ..StpInstancePort::default()
            }],
            ..StpInstance::default()
        }
    }

    #[test]
    fn cist_detail_follows_the_table() {
        let s = StpSummary {
            enabled: true,
            topology: topology(),
            ports: vec![StpPortInfo {
                name: "eth1".into(),
                edge: true,
                root_guard: true,
                counters: counters(),
                ..StpPortInfo::default()
            }],
            ..StpSummary::default()
        };
        let out = render_stp_detail(&s, None, None);
        assert!(out.contains("topology changes 3, last change 12s ago via eth1 (received)"));
        assert!(out.contains("eth1: edge yes, point-to-point no, Edge,RootGuard"));
        assert!(out.contains("  in:  config 0, tcn 0, rstp 7, mst 0"));
        assert!(out.contains("  out: config 0, tcn 0, rstp 9, mst 0"));
        assert!(out.contains("topology-change sent 0, received 2; protocol-migration 0; invalid-bpdu 0; forward-transitions 1"));
        let mut quiet = s;
        quiet.topology = StpTopology::default();
        assert!(render_stp_detail(&quiet, None, None).contains("topology changes 0, no change yet"));
        assert_eq!(
            render_stp_detail(&StpSummary::default(), None, None),
            "spanning-tree is disabled"
        );
    }

    #[test]
    fn instance_and_domain_detail_pick_their_tree() {
        let s = StpSummary {
            enabled: true,
            mode: StpMode::Mstp,
            mst: Some(StpMst {
                instances: vec![tree(0), tree(5)],
                ..StpMst::default()
            }),
            ..StpSummary::default()
        };
        let out = render_stp_detail(&s, Some(5), None);
        assert!(out.starts_with("instance 5 (MSTI)"));
        assert!(out.contains("eth1: edge no, point-to-point yes, boundary"));
        assert!(render_stp_detail(&s, Some(9), None).ends_with("no spanning-tree instance 9"));

        let p = StpSummary {
            enabled: true,
            mode: StpMode::RapidPvst,
            pvst: vec![tree(10), tree(20)],
            ..StpSummary::default()
        };
        let one = render_stp_detail(&p, None, Some("bd20"));
        assert!(one.starts_with("domain    bd20"));
        assert!(!one.contains("bd10") && one.contains("point-to-point yes"));
        let all = render_stp_detail(&p, None, None);
        assert!(all.contains("\ndomain bd10\n") && all.contains("\ndomain bd20\n"));
    }
}
