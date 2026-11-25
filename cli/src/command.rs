use std::net::IpAddr;

use crate::spec;
use nos_proto::TransactionBase;

/// A parsed REPL input line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ShowConfig,
    /// `show config admin` — the keystore section `show config` leaves out.
    ShowConfigAdmin,
    /// `show config <path>` — the running config scoped to the object the
    /// `edit` words name; resolved against the config at action time (#1459).
    ShowConfigPath(String),
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
    /// `show interface brief` — one table row per interface, tagged
    /// subinterface and port aggregate.
    ShowInterfaceBrief,
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
    /// `show bfd sessions [<peer>] [detail]` — every BFD session `nos-bfdd`
    /// holds, or only those to one peer address; `detail` prints one block each.
    ShowBfdSessions {
        peer: Option<IpAddr>,
        detail: bool,
    },
    /// `show bfd reflector` — the S-BFD reflector's discriminators and counters.
    ShowBfdReflector,
    /// `show log [<source>] [last <n>] [level <l>] [--follow] [match <text>]`
    /// — a buffer snapshot (default last 200), optionally of one source, at
    /// least `level`, whose rendered line contains `match`; or a live tail
    /// with `--follow`. The clauses come in any order, `match` last.
    ShowLog {
        source: Option<String>,
        follow: bool,
        last: Option<usize>,
        level: Option<nos_proto::LogLevel>,
        needle: Option<String>,
    },
    /// `show bgp brief` — a one-line-per-peer session summary across every
    /// configured BGP instance.
    ShowBgpBrief,
    /// `show bgp evpn` — every EVPN route received by every configured BGP
    /// instance.
    ShowBgpEvpn,
    /// `show bgp flowspec [family <f> | vrf <table>]` — every Flowspec rule
    /// received by every configured BGP instance (#1084: the VPN families
    /// and one VRF's view).
    ShowBgpFlowspec {
        family: Option<nos_proto::AddressFamily>,
        vrf: Option<String>,
    },
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
    ShowOspfDatabase {
        lsa_type: Option<String>,
        adv_router: Option<String>,
    },
    /// `show ospf segment-routing` (#1382): SRGBs, Prefix-SIDs and Adj-SIDs
    /// across every configured OSPF instance.
    ShowOspfSegmentRouting,
    /// `show ospfv3 neigh` — mirrors `ShowOspfNeigh`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Neigh,
    /// `show ospfv3 database` — mirrors `ShowOspfDatabase`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Database {
        lsa_type: Option<String>,
        adv_router: Option<String>,
    },
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
    /// `show aaa users` (#1374): the external users with an ssh account entry.
    ShowAaaUsers,
    /// `allocate aaa user <name>` (#1374).
    AllocateAaaUser {
        name: String,
    },
    /// `clear aaa user <name>` (#1374).
    ClearAaaUser {
        name: String,
    },
    /// `show configuration history`
    ShowHistory,
    /// `show configuration diff <n> [<m>]`: from history `n` to `m` (0 = running).
    ShowConfigDiff {
        from: u32,
        to: u32,
    },
    /// `rollback <n>` — configuration mode.
    Rollback {
        n: u32,
    },
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
    /// opens the built-in editor on its current source. See root
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
    /// `commit confirmed [<minutes>]` (#1144).
    CommitConfirmed {
        minutes: Option<u32>,
    },
    /// `commit confirm`
    ConfirmCommit,
    /// `commit cancel`
    CancelCommit,
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
    fn show_config_path() {
        let want = Command::ShowConfigPath("bgp instance r1".into());
        assert_eq!(Command::parse("show config bgp instance r1"), want);
        assert_eq!(Command::parse("  show  config  bgp instance r1  "), want);
    }

    #[test]
    fn show_config_admin() {
        assert_eq!(
            Command::parse("show config admin"),
            Command::ShowConfigAdmin
        );
    }

    #[test]
    fn history_and_rollback() {
        assert_eq!(
            Command::parse("show configuration history"),
            Command::ShowHistory
        );
        assert_eq!(
            Command::parse("show configuration diff 2"),
            Command::ShowConfigDiff { from: 2, to: 0 }
        );
        assert_eq!(
            Command::parse("show configuration diff 3 1"),
            Command::ShowConfigDiff { from: 3, to: 1 }
        );
        assert!(matches!(
            Command::parse("show configuration diff x"),
            Command::Unknown(_)
        ));
        assert!(matches!(
            Command::parse("show configuration diff"),
            Command::Unknown(_)
        ));
        assert_eq!(Command::parse("rollback 3"), Command::Rollback { n: 3 });
        assert!(matches!(Command::parse("rollback x"), Command::Unknown(_)));
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
            Command::ShowBfdSessions {
                peer: None,
                detail: false
            }
        );
        assert_eq!(
            Command::parse("show bfd sessions 192.0.2.1"),
            Command::ShowBfdSessions {
                peer: Some("192.0.2.1".parse().unwrap()),
                detail: false
            }
        );
        assert_eq!(
            Command::parse("show bfd sessions detail"),
            Command::ShowBfdSessions {
                peer: None,
                detail: true
            }
        );
        assert_eq!(
            Command::parse("show bfd sessions 192.0.2.1 detail"),
            Command::ShowBfdSessions {
                peer: Some("192.0.2.1".parse().unwrap()),
                detail: true
            }
        );
        for bad in [
            "show bfd sessions detail 192.0.2.1",
            "show bfd sessions nope detail",
        ] {
            assert_eq!(Command::parse(bad), Command::Unknown(bad.to_string()));
        }
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

    fn log(
        source: Option<&str>,
        follow: bool,
        last: Option<usize>,
        level: Option<nos_proto::LogLevel>,
        needle: Option<&str>,
    ) -> Command {
        Command::ShowLog {
            source: source.map(str::to_string),
            follow,
            last,
            level,
            needle: needle.map(str::to_string),
        }
    }

    #[test]
    fn show_log_variants() {
        use nos_proto::LogLevel::Warn;
        assert_eq!(
            Command::parse("show log"),
            log(None, false, None, None, None)
        );
        assert_eq!(
            Command::parse("show log --follow"),
            log(None, true, None, None, None)
        );
        assert_eq!(
            Command::parse("show log nos-ribd[rt1] --follow"),
            log(Some("nos-ribd[rt1]"), true, None, None, None)
        );
        assert_eq!(
            Command::parse("show log nos-ribd[rt1]"),
            log(Some("nos-ribd[rt1]"), false, None, None, None)
        );
        assert_eq!(
            Command::parse("show log last 5"),
            log(None, false, Some(5), None, None)
        );
        assert_eq!(
            Command::parse("show log level warn"),
            log(None, false, None, Some(Warn), None)
        );
        assert!(matches!(
            Command::parse("show log --follow nos-ribd"),
            Command::Unknown(_)
        ));
    }

    /// Every subset and order of `last`/`level`/`--follow`, with and without a
    /// source, parses to the same fields.
    #[test]
    fn show_log_clauses_any_order() {
        use nos_proto::LogLevel::Error;
        let clauses = [["last", "7"], ["level", "error"], ["--follow", ""]];
        for mask in 0..8u8 {
            let picked: Vec<_> = (0..3).filter(|i| mask >> i & 1 == 1).collect();
            let perms: Vec<Vec<usize>> = match picked.len() {
                0 => vec![vec![]],
                1 => vec![picked.clone()],
                2 => vec![picked.clone(), vec![picked[1], picked[0]]],
                _ => vec![
                    vec![0, 1, 2],
                    vec![0, 2, 1],
                    vec![1, 0, 2],
                    vec![1, 2, 0],
                    vec![2, 0, 1],
                    vec![2, 1, 0],
                ],
            };
            for perm in perms {
                for src in [None, Some("nos-x")] {
                    let mut words = vec!["show", "log"];
                    words.extend(src);
                    for i in &perm {
                        words.extend(clauses[*i].iter().filter(|w| !w.is_empty()));
                    }
                    let line = words.join(" ");
                    let want = log(
                        src,
                        mask & 4 != 0,
                        (mask & 1 != 0).then_some(7),
                        (mask & 2 != 0).then_some(Error),
                        None,
                    );
                    assert_eq!(Command::parse(&line), want, "{line}");
                    // `match` last, whatever came before.
                    let with = Command::parse(&format!("{line} match  a b"));
                    let want = match want {
                        Command::ShowLog {
                            source,
                            follow,
                            last,
                            level,
                            ..
                        } => Command::ShowLog {
                            source,
                            follow,
                            last,
                            level,
                            needle: Some(" a b".into()),
                        },
                        _ => unreachable!(),
                    };
                    assert_eq!(with, want, "{line} match");
                }
            }
        }
    }

    #[test]
    fn show_log_match_swallows_the_rest() {
        assert_eq!(
            Command::parse("show log match last 5"),
            log(None, false, None, None, Some("last 5"))
        );
        assert_eq!(
            Command::parse("show log last 2 match  --follow  x"),
            log(None, false, Some(2), None, Some(" --follow  x"))
        );
    }

    #[test]
    fn show_log_rejects_bad_clauses() {
        for line in [
            "show log last",
            "show log last x",
            "show log last -1",
            "show log level",
            "show log level loud",
            "show log match",
            "show log last 1 last 2",
            "show log level info level warn",
            "show log --follow --follow",
            "show log match a match b nos-x",
            "show log last 5 nos-x",
        ] {
            let c = Command::parse(line);
            // `match a match b ...` is valid (needle "a match b ...").
            if line.starts_with("show log match a") {
                assert!(matches!(c, Command::ShowLog { .. }), "{line}");
            } else {
                assert!(matches!(c, Command::Unknown(_)), "{line}: {c:?}");
            }
        }
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
            Command::ShowBgpFlowspec {
                family: None,
                vrf: None
            }
        );
        assert_eq!(
            Command::parse("show bgp flowspec family vpnv4-flowspec"),
            Command::ShowBgpFlowspec {
                family: Some(nos_proto::AddressFamily::Vpnv4Flowspec),
                vrf: None
            }
        );
        assert_eq!(
            Command::parse("show bgp flowspec vrf red"),
            Command::ShowBgpFlowspec {
                family: None,
                vrf: Some("red".into())
            }
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
        assert_eq!(Command::parse("show ospf neighbor"), Command::ShowOspfNeigh);
        assert_eq!(
            Command::parse("show ospf neighbors"),
            Command::ShowOspfNeigh
        );
    }

    #[test]
    fn show_ospf_database_filters() {
        assert_eq!(
            Command::parse("show ospf database"),
            Command::ShowOspfDatabase {
                lsa_type: None,
                adv_router: None
            }
        );
        assert_eq!(
            Command::parse("show ospf database router"),
            Command::ShowOspfDatabase {
                lsa_type: Some("router".into()),
                adv_router: None
            }
        );
        assert_eq!(
            Command::parse("show ospf database router 1.1.1.1"),
            Command::ShowOspfDatabase {
                lsa_type: Some("router".into()),
                adv_router: Some("1.1.1.1".into())
            }
        );
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

        assert_eq!(
            Command::parse("show interface brief"),
            Command::ShowInterfaceBrief
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
            Command::ShowOspfv3Database {
                lsa_type: None,
                adv_router: None
            }
        );
        assert_eq!(
            Command::parse("show ospfv3 database link 1.1.1.1"),
            Command::ShowOspfv3Database {
                lsa_type: Some("link".into()),
                adv_router: Some("1.1.1.1".into())
            }
        );
        assert_eq!(
            Command::parse("show ospfv3 neighbors"),
            Command::ShowOspfv3Neigh
        );
    }

    #[test]
    fn aaa_user_commands() {
        assert_eq!(Command::parse("show aaa users"), Command::ShowAaaUsers);
        assert_eq!(
            Command::parse("allocate aaa user alice"),
            Command::AllocateAaaUser {
                name: "alice".to_string()
            }
        );
        assert_eq!(
            Command::parse("clear aaa user alice"),
            Command::ClearAaaUser {
                name: "alice".to_string()
            }
        );
        assert_eq!(
            Command::parse("clear aaa user"),
            Command::Unknown("clear aaa user".to_string())
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
