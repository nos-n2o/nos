use std::net::IpAddr;

use crate::spec;
use nos_proto::TransactionBase;

/// A parsed REPL input line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ShowConfig,
    /// `show config admin` — the keystore section `show config` leaves out.
    ShowConfigAdmin,
    /// `show this` — only meaningful in configuration mode.
    Show,
    /// `show route <table>` (whole table) or `show route <table> <address>`
    /// (longest-prefix-match lookup).
    ShowRoute {
        table: String,
        address: Option<IpAddr>,
    },
    /// `show fdb <domain>` — one broadcast domain's forwarding database.
    ShowFdb {
        domain: String,
    },
    /// `show interface` (every interface) or `show interface <name>` (one).
    ShowInterface {
        name: Option<String>,
    },
    /// `show port-aggregate` (every aggregate) or `show port-aggregate
    /// <name>` (one).
    ShowPortAggregate {
        name: Option<String>,
    },
    /// `show lacp` (every aggregate) or `show lacp <name>` (one).
    ShowLacp {
        name: Option<String>,
    },
    /// `show lldp neighbors [detail]` — every LLDP neighbor heard on any
    /// interface, one line each or (`detail`) one block each.
    ShowLldpNeighbors {
        detail: bool,
    },
    /// `show lldp statistics` — every LLDP-enabled interface's counters.
    ShowLldpStatistics,
    /// `show version` — local, valid in any mode.
    ShowVersion,
    /// `show acl` (every ACL) or `show acl <name>` (one): counters included.
    ShowAcl {
        name: Option<String>,
    },
    /// `show spanning-tree` — the bridge and every port's role/state.
    ShowSpanningTree,
    /// `show spanning-tree instance <id>` — one MST instance (0: the CIST).
    ShowSpanningTreeInstance {
        id: u16,
    },
    /// `show spanning-tree mst-config` — region name, revision, digest, VLAN map.
    ShowSpanningTreeMstConfig,
    /// `show spanning-tree domain <bd>` — one Rapid-PVST+ tree.
    ShowSpanningTreeDomain {
        domain: String,
    },
    /// `show spanning-tree [instance <id> | domain <bd>] detail` — the tables
    /// plus topology changes and the RFC 4318 counters of every port.
    ShowSpanningTreeDetail {
        instance: Option<u16>,
        domain: Option<String>,
    },
    /// `show bfd sessions [<peer>]` — every BFD session `nos-bfdd` holds, or
    /// only those to one peer address.
    ShowBfdSessions {
        peer: Option<IpAddr>,
    },
    /// `show bfd reflector` — the S-BFD reflector's discriminators and counters.
    ShowBfdReflector,
    /// `show log [<source>] [--follow]` — a one-shot buffer snapshot,
    /// optionally filtered to one source, or a live tail with `--follow`.
    ShowLog {
        source: Option<String>,
        follow: bool,
    },
    /// `show bgp brief` — a one-line-per-peer session summary across every
    /// configured BGP instance.
    ShowBgpBrief,
    /// `show bgp evpn` — every EVPN route received by every configured BGP
    /// instance.
    ShowBgpEvpn,
    /// `show bgp flowspec` — every Flowspec rule received by every configured
    /// BGP instance.
    ShowBgpFlowspec,
    /// `show bgp rpki` — every configured BGP instance's RPKI cache sessions.
    ShowBgpRpki,
    /// `show bgp bmp` — every configured BGP instance's BMP station status.
    ShowBgpBmp,
    /// `show bgp vpnv4|vpnv6 [rd <rd>]` — every VPN path of `family` received
    /// by every configured BGP instance, optionally of one RD only.
    ShowBgpVpn {
        family: nos_proto::AddressFamily,
        rd: Option<String>,
    },
    /// `show bgp routes` — every BGP instance's unicast routes with their
    /// RPKI origin validation state.
    ShowBgpRoutes,
    /// `show ospf neigh` — a one-line-per-link neighbor summary across every
    /// configured OSPF instance.
    ShowOspfNeigh,
    /// `show ospf database` — every installed LSA's header, across every
    /// configured OSPF instance.
    ShowOspfDatabase,
    /// `show ospfv3 neigh` — mirrors `ShowOspfNeigh`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Neigh,
    /// `show ospfv3 database` — mirrors `ShowOspfDatabase`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Database,
    /// `clear bgp <instance> <peer> soft-in` — ask `<peer>`'s live session
    /// on `<instance>` to resend its routes (RFC 2918 route refresh).
    ClearBgpSoftIn {
        instance: String,
        peer: IpAddr,
    },
    /// `clear bgp <instance> <peer>` — release `<peer>`'s maximum-prefix
    /// hold and reset its session (Cease/Administrative Reset).
    ClearBgpPeer {
        instance: String,
        peer: IpAddr,
    },
    /// `clear spanning-tree detected-protocols [interface <i>]` — 802.1Q
    /// `mcheck`: re-probe a port (or all) for RSTP after a legacy fallback.
    ClearStpMcheck {
        interface: Option<String>,
    },
    /// `clear spanning-tree err-disabled <i>` — bring a port that BPDU guard
    /// shut down back up.
    ClearStpErrDisabled {
        interface: String,
    },
    Save,
    Help,
    /// `exit` | `quit` | `end`
    Exit,
    Configure {
        name: String,
        /// `None` when `from ...` was omitted (defaults to `Current`).
        base: Option<TransactionBase>,
    },
    /// An `edit`/`set`/`delete` line, resolved against the config tree by
    /// `config_grammar` once the current position and config are known.
    Config(String),
    /// `edit source` — only valid while navigated into a policy-definition;
    /// opens `$EDITOR`/`$VISUAL`/`vim` on its current source. See root
    /// `CLAUDE.md`'s "nos-cli editing UX".
    EditSource,
    /// `show source` — only valid while navigated into a policy-definition.
    ShowSource,
    /// `set source line <n> <text>` — only valid while navigated into a
    /// policy-definition. `<text>` is the raw remainder of the line
    /// (leading whitespace preserved) since RPL's indentation is
    /// semantically meaningful — parsed outside the generic
    /// `split_whitespace()` matcher below, see `parse`'s doc comment.
    SetSourceLine {
        line: usize,
        text: String,
    },
    /// `delete source line <n>` — only valid while navigated into a
    /// policy-definition.
    DeleteSourceLine {
        line: usize,
    },
    Up,
    Top,
    Commit,
    /// `discard` | `abort`
    Discard,
    /// `diff` — only meaningful in configuration mode.
    Diff,
    Empty,
    Unknown(String),
}

impl Command {
    /// Show and shell commands come from `spec::COMMAND_SPECS`' `cmd!` rows;
    /// any other `edit`/`set`/`delete` line is a config edit, left for
    /// `config_grammar` — which needs the current position and config — to
    /// resolve (#109).
    pub fn parse(line: &str) -> Self {
        let trimmed = line.trim();
        if let Some((_, command)) = spec::parse(trimmed) {
            return command.unwrap_or_else(|| Command::Unknown(trimmed.to_string()));
        }
        match trimmed.split_whitespace().next() {
            None => Command::Empty,
            Some("edit" | "set" | "delete" | "move") => Command::Config(trimmed.to_string()),
            Some(_) => Command::Unknown(trimmed.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_config() {
        assert_eq!(Command::parse("show config"), Command::ShowConfig);
    }

    #[test]
    fn show_config_extra_whitespace() {
        assert_eq!(Command::parse("  show   config  "), Command::ShowConfig);
    }

    #[test]
    fn show_config_admin() {
        assert_eq!(
            Command::parse("show config admin"),
            Command::ShowConfigAdmin
        );
    }

    #[test]
    fn show_this() {
        assert_eq!(Command::parse("show this"), Command::Show);
    }

    #[test]
    fn bare_show_is_unknown() {
        assert_eq!(Command::parse("show"), Command::Unknown("show".to_string()));
    }

    #[test]
    fn show_route_whole_table() {
        assert_eq!(
            Command::parse("show route rt1"),
            Command::ShowRoute {
                table: "rt1".to_string(),
                address: None,
            }
        );
    }

    #[test]
    fn show_route_with_address() {
        assert_eq!(
            Command::parse("show route rt1 10.0.0.5"),
            Command::ShowRoute {
                table: "rt1".to_string(),
                address: Some("10.0.0.5".parse().unwrap()),
            }
        );
    }

    #[test]
    fn show_route_with_invalid_address_is_unknown() {
        assert_eq!(
            Command::parse("show route rt1 not-an-address"),
            Command::Unknown("show route rt1 not-an-address".to_string())
        );
    }

    #[test]
    fn clear_spanning_tree_detected_protocols() {
        assert_eq!(
            Command::parse("clear spanning-tree detected-protocols"),
            Command::ClearStpMcheck { interface: None }
        );
        assert_eq!(
            Command::parse("clear spanning-tree detected-protocols interface eth1"),
            Command::ClearStpMcheck {
                interface: Some("eth1".into())
            }
        );
    }

    #[test]
    fn clear_spanning_tree_err_disabled() {
        assert_eq!(
            Command::parse("clear spanning-tree err-disabled eth1"),
            Command::ClearStpErrDisabled {
                interface: "eth1".into()
            }
        );
    }

    #[test]
    fn show_spanning_tree() {
        assert_eq!(
            Command::parse("show spanning-tree"),
            Command::ShowSpanningTree
        );
        assert_eq!(
            Command::parse("show spanning-tree instance 12"),
            Command::ShowSpanningTreeInstance { id: 12 }
        );
        assert_eq!(
            Command::parse("show spanning-tree mst-config"),
            Command::ShowSpanningTreeMstConfig
        );
        assert_eq!(
            Command::parse("show spanning-tree domain bd1"),
            Command::ShowSpanningTreeDomain {
                domain: "bd1".into()
            }
        );
    }

    #[test]
    fn show_spanning_tree_detail() {
        assert_eq!(
            Command::parse("show spanning-tree detail"),
            Command::ShowSpanningTreeDetail {
                instance: None,
                domain: None
            }
        );
        assert_eq!(
            Command::parse("show spanning-tree instance 3 detail"),
            Command::ShowSpanningTreeDetail {
                instance: Some(3),
                domain: None
            }
        );
        assert_eq!(
            Command::parse("show spanning-tree domain bd1 detail"),
            Command::ShowSpanningTreeDetail {
                instance: None,
                domain: Some("bd1".into())
            }
        );
    }

    #[test]
    fn show_lldp_neighbors() {
        assert_eq!(
            Command::parse("show lldp neighbors"),
            Command::ShowLldpNeighbors { detail: false }
        );
        assert_eq!(
            Command::parse("show lldp neighbors detail"),
            Command::ShowLldpNeighbors { detail: true }
        );
        assert_eq!(
            Command::parse("show lldp statistics"),
            Command::ShowLldpStatistics
        );
        assert_eq!(
            Command::parse("show lldp"),
            Command::Unknown("show lldp".to_string())
        );
    }

    #[test]
    fn show_version() {
        assert_eq!(Command::parse("show version"), Command::ShowVersion);
    }

    #[test]
    fn show_bfd_reflector() {
        assert_eq!(
            Command::parse("show bfd reflector"),
            Command::ShowBfdReflector
        );
    }

    #[test]
    fn show_bfd_sessions() {
        assert_eq!(
            Command::parse("show bfd sessions"),
            Command::ShowBfdSessions { peer: None }
        );
        assert_eq!(
            Command::parse("show bfd sessions 192.0.2.1"),
            Command::ShowBfdSessions {
                peer: Some("192.0.2.1".parse().unwrap())
            }
        );
        assert_eq!(
            Command::parse("show bfd sessions nope"),
            Command::Unknown("show bfd sessions nope".to_string())
        );
        assert_eq!(
            Command::parse("show bfd"),
            Command::Unknown("show bfd".to_string())
        );
    }

    #[test]
    fn show_lacp() {
        assert_eq!(
            Command::parse("show lacp"),
            Command::ShowLacp { name: None }
        );
        assert_eq!(
            Command::parse("show lacp bond1"),
            Command::ShowLacp {
                name: Some("bond1".to_string()),
            }
        );
    }

    #[test]
    fn show_port_aggregate() {
        assert_eq!(
            Command::parse("show port-aggregate"),
            Command::ShowPortAggregate { name: None }
        );
        assert_eq!(
            Command::parse("show port-aggregate bond1"),
            Command::ShowPortAggregate {
                name: Some("bond1".to_string()),
            }
        );
    }

    #[test]
    fn set_source_line_preserves_leading_whitespace() {
        assert_eq!(
            Command::parse("set source line 2     accept"),
            Command::SetSourceLine {
                line: 2,
                text: "    accept".to_string(),
            }
        );
    }

    #[test]
    fn set_source_line_preserves_deep_indentation() {
        // The generic split_whitespace() matcher used by every other
        // command would collapse this to a single space — this command's
        // whole reason for a dedicated pre-check is that RPL's indentation
        // is semantically meaningful and must survive verbatim.
        assert_eq!(
            Command::parse("set source line 5         set this.bgp.local_pref = 150"),
            Command::SetSourceLine {
                line: 5,
                text: "        set this.bgp.local_pref = 150".to_string(),
            }
        );
    }

    #[test]
    fn set_source_line_with_no_text_is_not_a_source_edit() {
        // Not the `set source line` row: left to the config grammar, which
        // rejects it (`source` takes one value).
        assert_eq!(
            Command::parse("set source line 3"),
            Command::Config("set source line 3".to_string())
        );
    }

    #[test]
    fn set_source_line_with_non_numeric_line_is_unknown() {
        assert_eq!(
            Command::parse("set source line abc accept"),
            Command::Unknown("set source line abc accept".to_string())
        );
    }

    #[test]
    fn delete_source_line() {
        assert_eq!(
            Command::parse("delete source line 4"),
            Command::DeleteSourceLine { line: 4 }
        );
    }

    #[test]
    fn save() {
        assert_eq!(Command::parse("save"), Command::Save);
    }

    #[test]
    fn help() {
        assert_eq!(Command::parse("help"), Command::Help);
    }

    #[test]
    fn exit_quit_and_end() {
        assert_eq!(Command::parse("exit"), Command::Exit);
        assert_eq!(Command::parse("quit"), Command::Exit);
        assert_eq!(Command::parse("end"), Command::Exit);
    }

    #[test]
    fn commit() {
        assert_eq!(Command::parse("commit"), Command::Commit);
    }

    #[test]
    fn discard_and_abort() {
        assert_eq!(Command::parse("discard"), Command::Discard);
        assert_eq!(Command::parse("abort"), Command::Discard);
    }

    #[test]
    fn diff() {
        assert_eq!(Command::parse("diff"), Command::Diff);
    }

    #[test]
    fn up_and_top() {
        assert_eq!(Command::parse("up"), Command::Up);
        assert_eq!(Command::parse("top"), Command::Top);
    }

    #[test]
    fn empty_line() {
        assert_eq!(Command::parse(""), Command::Empty);
        assert_eq!(Command::parse("   "), Command::Empty);
    }

    #[test]
    fn unknown_command() {
        assert_eq!(
            Command::parse("show interfaces"),
            Command::Unknown("show interfaces".to_string())
        );
    }

    #[test]
    fn configure_default_base() {
        assert_eq!(
            Command::parse("configure my-txn"),
            Command::Configure {
                name: "my-txn".to_string(),
                base: None,
            }
        );
    }

    #[test]
    fn configure_from_blank() {
        assert_eq!(
            Command::parse("configure my-txn from blank"),
            Command::Configure {
                name: "my-txn".to_string(),
                base: Some(TransactionBase::Blank),
            }
        );
    }

    #[test]
    fn configure_from_current() {
        assert_eq!(
            Command::parse("configure my-txn from current"),
            Command::Configure {
                name: "my-txn".to_string(),
                base: Some(TransactionBase::Current),
            }
        );
    }

    #[test]
    fn show_log_variants() {
        assert_eq!(
            Command::parse("show log"),
            Command::ShowLog {
                source: None,
                follow: false,
            }
        );
        assert_eq!(
            Command::parse("show log --follow"),
            Command::ShowLog {
                source: None,
                follow: true,
            }
        );
        assert_eq!(
            Command::parse("show log nos-ribd[rt1]"),
            Command::ShowLog {
                source: Some("nos-ribd[rt1]".to_string()),
                follow: false,
            }
        );
        assert_eq!(
            Command::parse("show log nos-ribd[rt1] --follow"),
            Command::ShowLog {
                source: Some("nos-ribd[rt1]".to_string()),
                follow: true,
            }
        );
    }

    #[test]
    fn show_bgp_brief() {
        assert_eq!(Command::parse("show bgp brief"), Command::ShowBgpBrief);
    }

    #[test]
    fn show_bgp_evpn() {
        assert_eq!(Command::parse("show bgp evpn"), Command::ShowBgpEvpn);
        assert_eq!(
            Command::parse("show bgp flowspec"),
            Command::ShowBgpFlowspec
        );
        assert_eq!(Command::parse("show bgp rpki"), Command::ShowBgpRpki);
        assert_eq!(Command::parse("show bgp bmp"), Command::ShowBgpBmp);
        assert_eq!(Command::parse("show bgp routes"), Command::ShowBgpRoutes);
        assert_eq!(
            Command::parse("show bgp vpnv6"),
            Command::ShowBgpVpn {
                family: nos_proto::AddressFamily::Vpnv6Unicast,
                rd: None
            }
        );
        assert_eq!(
            Command::parse("show bgp vpnv4 rd 65001:1"),
            Command::ShowBgpVpn {
                family: nos_proto::AddressFamily::Vpnv4Unicast,
                rd: Some("65001:1".into())
            }
        );
    }

    #[test]
    fn show_ospf_neigh() {
        assert_eq!(Command::parse("show ospf neigh"), Command::ShowOspfNeigh);
    }

    #[test]
    fn clear_bgp_peer() {
        assert_eq!(
            Command::parse("clear bgp r1 10.0.0.1"),
            Command::ClearBgpPeer {
                instance: "r1".to_string(),
                peer: "10.0.0.1".parse().unwrap(),
            }
        );
        assert_eq!(
            Command::parse("clear bgp r1 not-an-ip"),
            Command::Unknown("clear bgp r1 not-an-ip".to_string())
        );
    }

    #[test]
    fn clear_bgp_soft_in() {
        assert_eq!(
            Command::parse("clear bgp r1 10.0.0.1 soft-in"),
            Command::ClearBgpSoftIn {
                instance: "r1".to_string(),
                peer: "10.0.0.1".parse().unwrap(),
            }
        );
        assert_eq!(
            Command::parse("clear bgp r1 not-an-ip soft-in"),
            Command::Unknown("clear bgp r1 not-an-ip soft-in".to_string())
        );
    }

    #[test]
    fn show_interface_all_and_named() {
        assert_eq!(
            Command::parse("show interface"),
            Command::ShowInterface { name: None }
        );
        assert_eq!(
            Command::parse("show interface eth0"),
            Command::ShowInterface {
                name: Some("eth0".to_string())
            }
        );
    }

    #[test]
    fn show_ospfv3_neigh_and_database() {
        assert_eq!(
            Command::parse("show ospfv3 neigh"),
            Command::ShowOspfv3Neigh
        );
        assert_eq!(
            Command::parse("show ospfv3 database"),
            Command::ShowOspfv3Database
        );
    }

    #[test]
    fn show_fdb_takes_one_domain() {
        assert_eq!(
            Command::parse("show fdb bd1"),
            Command::ShowFdb {
                domain: "bd1".to_string()
            }
        );
        assert_eq!(
            Command::parse("show fdb"),
            Command::Unknown("show fdb".to_string())
        );
    }

    #[test]
    fn config_verbs_are_left_to_the_config_grammar() {
        assert_eq!(
            Command::parse("  set bgp instance r1 asn 65000 "),
            Command::Config("set bgp instance r1 asn 65000".to_string())
        );
        assert_eq!(
            Command::parse("delete"),
            Command::Config("delete".to_string())
        );
    }
}
