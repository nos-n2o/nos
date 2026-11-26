use std::fmt;
use std::net::IpAddr;

use nos_proto::TransactionBase;

use crate::command::{Command, RouteQuery};

/// Navigation position within the transaction's config tree, as REST
/// segments (`config_path`): `["bgp-instance", "r1", "peer-group", "pg1"]`.
/// Empty is the transaction root. Every step is a list name and a key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Path(Vec<String>);

impl Path {
    pub fn root() -> Self {
        Path(Vec::new())
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn segments(&self) -> &[String] {
        &self.0
    }

    /// One object up.
    #[must_use]
    pub fn up(&self) -> Path {
        Path(self.0[..self.0.len().saturating_sub(2)].to_vec())
    }

    /// The policy-definition this position is, if it is one.
    pub fn policy_definition(&self) -> Option<&str> {
        match self.0.as_slice() {
            [list, name] if list == "policy-definition" => Some(name),
            _ => None,
        }
    }
}

impl From<Vec<String>> for Path {
    fn from(segments: Vec<String>) -> Self {
        Path(segments)
    }
}

/// `bgp-instance:r1/peer-group:pg1` — the prompt's position.
impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let steps: Vec<String> = self.0.chunks(2).map(|c| c.join(":")).collect();
        f.write_str(&steps.join("/"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Operational,
    Configuration {
        transaction: String,
        path: Path,
        dirty: bool,
    },
}

/// The concrete next step for the REPL to execute, computed from `Mode` and
/// a parsed `Command`.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolved {
    Nothing,
    Help,
    /// Operational `exit`/`quit`/`end` — exit the whole shell.
    ExitShell,
    /// Configuration-mode `exit`/`quit`/`end` with uncommitted changes — the
    /// REPL must interactively ask commit/discard/leave-open.
    LeaveConfigPrompt,
    NavigateTop,
    /// Navigate to a specific position with no edit — `up`.
    Navigate(Path),
    ShowRunningConfig,
    /// `show config admin` — only the keystore, values `<hidden>`.
    ShowAdminConfig,
    /// `show config <path>` — the running config scoped to `path` (#1459).
    ShowConfigPath(String),
    /// `show this` in configuration mode — fetch the transaction and render
    /// it at the current path.
    ShowTransaction,
    /// `show route <table> [...]` — data-plane, valid in any mode.
    ShowRoute {
        table: String,
        query: RouteQuery,
    },
    /// `show route` (#1446).
    ShowRouteTables,
    /// `show route <table> summary` (#1446).
    ShowRouteSummary {
        table: String,
    },
    /// `show fdb [<domain>] [mac <mac>]` — data-plane, valid in any mode.
    ShowFdb {
        domain: Option<String>,
        mac: Option<String>,
    },
    /// `show interface` (every interface) or `show interface <name>` (one)
    /// — data-plane, valid in any mode.
    ShowInterface {
        name: Option<String>,
    },
    /// `show interface brief` — data-plane, valid in any mode.
    ShowInterfaceBrief,
    /// `show port-aggregate` (every aggregate) or `show port-aggregate
    /// <name>` (one) — data-plane, valid in any mode.
    ShowPortAggregate {
        name: Option<String>,
    },
    ShowLacp {
        name: Option<String>,
        detail: bool,
    },
    /// `show lldp neighbors [interface <if>] [detail]` — data-plane, valid in
    /// any mode.
    ShowLldpNeighbors {
        detail: bool,
        interface: Option<String>,
    },
    /// `show lldp statistics` — data-plane, valid in any mode.
    ShowLldpStatistics,
    /// `show version` — printed locally, no IPC.
    ShowVersion,
    /// `show acl [<name>]` — data-plane, valid in any mode.
    /// `clear acl [<name>] counters` — valid in any mode.
    ClearAclCounters {
        name: Option<String>,
    },
    ShowAcl {
        name: Option<String>,
    },
    /// `show spanning-tree` — data-plane, valid in any mode.
    ShowSpanningTree,
    /// `show spanning-tree instance <id>` — data-plane, valid in any mode.
    ShowSpanningTreeInstance {
        id: u16,
    },
    /// `show spanning-tree mst-config` — data-plane, valid in any mode.
    ShowSpanningTreeMstConfig,
    /// `show spanning-tree domain <bd>` — data-plane, valid in any mode.
    ShowSpanningTreeDomain {
        domain: String,
    },
    /// `show spanning-tree [instance <id> | domain <bd>] detail` — data-plane,
    /// valid in any mode.
    ShowSpanningTreeDetail {
        instance: Option<u16>,
        domain: Option<String>,
    },
    /// `show bfd sessions [<peer>] [detail]` — data-plane, valid in any mode.
    ShowBfdSessions {
        peer: Option<std::net::IpAddr>,
        detail: bool,
    },
    /// `show bfd reflector` — data-plane, valid in any mode.
    ShowBfdReflector,
    /// `show log [<source>] [last <n>] [level <l>] [--follow] [match <text>]`
    /// — data-plane, valid in any mode.
    ShowLog {
        source: Option<String>,
        follow: bool,
        last: Option<usize>,
        level: Option<nos_proto::LogLevel>,
        needle: Option<String>,
    },
    /// `show bgp summary [instance <name>]` — data-plane, valid in any mode.
    /// The caller iterates the `BgpInstance`s of the running config itself.
    ShowBgpSummary {
        instance: Option<String>,
    },
    /// `show bgp neighbor [<ip>] [instance <name>]` — data-plane, valid in any mode.
    ShowBgpNeighbor {
        peer: Option<std::net::IpAddr>,
        instance: Option<String>,
    },
    /// `show bgp evpn` — data-plane, valid in any mode. Router-wide like
    /// `ShowBgpSummary`.
    ShowBgpEvpn,
    /// `show bgp flowspec [family <f> | vrf <table>]` — data-plane, valid in
    /// any mode, router-wide.
    ShowBgpFlowspec {
        family: Option<nos_proto::AddressFamily>,
        vrf: Option<String>,
    },
    /// `show bgp rpki` — data-plane, valid in any mode, router-wide.
    ShowBgpRpki,
    /// `show bgp bmp` — data-plane, valid in any mode, router-wide.
    ShowBgpBmp,
    /// `show bgp vpnv4|vpnv6 [rd <rd>]` — data-plane, any mode, router-wide.
    ShowBgpVpn {
        family: nos_proto::AddressFamily,
        rd: Option<String>,
    },
    /// `show bgp routes` — data-plane, valid in any mode, router-wide.
    ShowBgpRoutes,
    /// `show ospf neigh` — data-plane, valid in any mode. Router-wide (no
    /// instance argument), mirroring `ShowBgpSummary`: the caller iterates
    /// every `OspfInstance` in the running config itself.
    ShowOspfNeigh,
    /// `show ospf interface` (#1438).
    ShowOspfInterface,
    /// `show ospf route` (#1453).
    ShowOspfRoute,
    /// `show ospf database` — data-plane, valid in any mode. Router-wide (no
    /// instance argument), mirroring `ShowOspfNeigh`.
    ShowOspfDatabase {
        lsa_type: Option<String>,
        adv_router: Option<String>,
    },
    /// `show ospf segment-routing` — mirrors `ShowOspfDatabase`.
    ShowOspfSegmentRouting,
    ShowOspfInstance,
    ShowOspfv3Instance,
    /// `show ospfv3 neigh` — mirrors `ShowOspfNeigh`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Neigh,
    /// `show ospfv3 interface` (#1438).
    ShowOspfv3Interface,
    /// `show ospfv3 route` (#1453).
    ShowOspfv3Route,
    /// `show ospfv3 database` — mirrors `ShowOspfDatabase`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Database {
        lsa_type: Option<String>,
        adv_router: Option<String>,
    },
    /// `clear bgp <instance> <peer> soft-in` — data-plane action, valid in
    /// any mode.
    ClearBgpSoftIn {
        instance: String,
        peer: IpAddr,
    },
    /// `clear bgp <instance> <peer>` — likewise valid in any mode.
    ClearBgpPeer {
        instance: String,
        peer: IpAddr,
    },
    /// `clear spanning-tree detected-protocols [interface <i>]` — valid in any mode.
    ClearStpMcheck {
        interface: Option<String>,
    },
    /// `clear spanning-tree err-disabled <i>` — valid in any mode.
    ClearStpErrDisabled {
        interface: String,
    },
    SaveRunningConfig,
    ShowAaaUsers,
    AllocateAaaUser {
        name: String,
    },
    ClearAaaUser {
        name: String,
    },
    ShowHistory,
    ShowConfigDiff {
        from: u32,
        to: u32,
    },
    Rollback {
        n: u32,
    },
    OpenTransaction {
        name: String,
        base: TransactionBase,
        explicit_base: bool,
    },
    /// An `edit`/`set`/`delete` line, for `config_grammar` to resolve against
    /// the transaction's config at the current position.
    ConfigEdit(String),
    Commit,
    CommitConfirmed {
        minutes: Option<u32>,
    },
    ConfirmCommit,
    CancelCommit,
    Discard,
    /// `diff` — fetch and render the transaction's diff against running.
    Diff,
    /// `edit source` — only valid navigated into a policy-definition. Fetches
    /// the transaction, opens an external editor on the current source,
    /// compiles the result client-side, and (on success) stages `SetSource`
    /// — see root `CLAUDE.md`'s "nos-cli editing UX".
    EditPolicySource {
        name: String,
    },
    /// `show source` — only valid navigated into a policy-definition.
    ShowPolicySource {
        name: String,
    },
    /// `set source line <n> <text>` — only valid navigated into a
    /// policy-definition.
    SetPolicySourceLine {
        name: String,
        line: usize,
        text: String,
    },
    /// `delete source line <n>` — only valid navigated into a
    /// policy-definition.
    DeletePolicySourceLine {
        name: String,
        line: usize,
    },
    Error(String),
}

impl Resolved {
    /// Does `| display set` (#1462) work on this command? Exhaustive on
    /// purpose; keep in step with `actions::handle_action_out`.
    pub fn display_set_capable(&self) -> bool {
        matches!(
            self,
            Resolved::ShowRunningConfig | Resolved::ShowConfigPath(_) | Resolved::ShowTransaction
        )
    }

    /// Does `| json` (#1415) work on this command? Exhaustive on purpose: a
    /// new variant must be classified. Keep in step with
    /// `actions::handle_action_out`; a flat view's migration flips its arm.
    pub fn json_capable(&self) -> bool {
        match self {
            Resolved::ShowBfdSessions { .. }
            | Resolved::ShowRoute { .. }
            | Resolved::ShowRouteTables
            | Resolved::ShowRouteSummary { .. }
            | Resolved::ShowBgpRoutes => true,
            Resolved::Nothing
            | Resolved::Help
            | Resolved::ExitShell
            | Resolved::LeaveConfigPrompt
            | Resolved::NavigateTop
            | Resolved::Navigate(_)
            | Resolved::ShowRunningConfig
            | Resolved::ShowAdminConfig
            | Resolved::ShowConfigPath(_)
            | Resolved::ShowTransaction
            | Resolved::ShowFdb { .. }
            | Resolved::ShowInterface { .. }
            | Resolved::ShowInterfaceBrief
            | Resolved::ShowPortAggregate { .. }
            | Resolved::ShowLacp { .. }
            | Resolved::ShowLldpNeighbors { .. }
            | Resolved::ShowLldpStatistics
            | Resolved::ShowOspfInstance
            | Resolved::ShowOspfv3Instance
            | Resolved::ShowVersion
            | Resolved::ShowAcl { .. }
            | Resolved::ShowSpanningTree
            | Resolved::ShowSpanningTreeInstance { .. }
            | Resolved::ShowSpanningTreeMstConfig
            | Resolved::ShowSpanningTreeDomain { .. }
            | Resolved::ShowSpanningTreeDetail { .. }
            | Resolved::ShowBfdReflector
            | Resolved::ShowLog { .. }
            | Resolved::ShowBgpSummary { .. }
            | Resolved::ShowBgpEvpn
            | Resolved::ShowBgpFlowspec { .. }
            | Resolved::ShowBgpRpki
            | Resolved::ShowBgpBmp
            | Resolved::ShowBgpVpn { .. }
            | Resolved::ShowOspfNeigh
            | Resolved::ShowOspfDatabase { .. }
            | Resolved::ShowOspfSegmentRouting
            | Resolved::ShowOspfv3Neigh
            | Resolved::ShowOspfv3Database { .. }
            | Resolved::ClearBgpSoftIn { .. }
            | Resolved::ClearBgpPeer { .. }
            | Resolved::ClearStpMcheck { .. }
            | Resolved::ClearStpErrDisabled { .. }
            | Resolved::SaveRunningConfig
            | Resolved::ShowAaaUsers
            | Resolved::AllocateAaaUser { .. }
            | Resolved::ClearAaaUser { .. }
            | Resolved::ShowHistory
            | Resolved::ShowConfigDiff { .. }
            | Resolved::Rollback { .. }
            | Resolved::OpenTransaction { .. }
            | Resolved::ConfigEdit(_)
            | Resolved::Commit
            | Resolved::CommitConfirmed { .. }
            | Resolved::ConfirmCommit
            | Resolved::CancelCommit
            | Resolved::Discard
            | Resolved::Diff
            | Resolved::EditPolicySource { .. }
            | Resolved::ShowPolicySource { .. }
            | Resolved::SetPolicySourceLine { .. }
            | Resolved::DeletePolicySourceLine { .. }
            | Resolved::ClearAclCounters { .. }
            | Resolved::ShowBgpNeighbor { .. }
            | Resolved::ShowOspfInterface
            | Resolved::ShowOspfRoute
            | Resolved::ShowOspfv3Interface
            | Resolved::ShowOspfv3Route
            | Resolved::Error(_) => false,
        }
    }

    /// Is this a show/ops command to account (#1155)? Everything but
    /// navigation and the config edit/commit/save family, which `nos-configd`
    /// accounts itself. Deny-list: a new command is accounted by default.
    pub fn is_accounted(&self) -> bool {
        !matches!(
            self,
            Resolved::Nothing
                | Resolved::Help
                | Resolved::ExitShell
                | Resolved::LeaveConfigPrompt
                | Resolved::NavigateTop
                | Resolved::Navigate(_)
                | Resolved::SaveRunningConfig
                | Resolved::Rollback { .. }
                | Resolved::OpenTransaction { .. }
                | Resolved::ConfigEdit(_)
                | Resolved::Commit
                | Resolved::CommitConfirmed { .. }
                | Resolved::ConfirmCommit
                | Resolved::CancelCommit
                | Resolved::Discard
                | Resolved::EditPolicySource { .. }
                | Resolved::SetPolicySourceLine { .. }
                | Resolved::DeletePolicySourceLine { .. }
                | Resolved::Error(_)
        )
    }
}

pub fn resolve(mode: &Mode, cmd: Command) -> Resolved {
    match cmd {
        Command::Empty => Resolved::Nothing,
        Command::Help => Resolved::Help,
        Command::ShowConfig => Resolved::ShowRunningConfig,
        Command::ShowConfigAdmin => Resolved::ShowAdminConfig,
        Command::ShowConfigPath(p) => Resolved::ShowConfigPath(p),
        Command::ShowHistory => Resolved::ShowHistory,
        Command::ShowConfigDiff { from, to } => Resolved::ShowConfigDiff { from, to },
        Command::ShowAaaUsers => Resolved::ShowAaaUsers,
        Command::AllocateAaaUser { name } => Resolved::AllocateAaaUser { name },
        Command::ClearAaaUser { name } => Resolved::ClearAaaUser { name },
        Command::ConfirmCommit => Resolved::ConfirmCommit,
        Command::CancelCommit => Resolved::CancelCommit,
        Command::ShowRoute { table, query } => Resolved::ShowRoute { table, query },
        Command::ShowRouteTables => Resolved::ShowRouteTables,
        Command::ShowRouteSummary { table } => Resolved::ShowRouteSummary { table },
        Command::ShowFdb { domain, mac } => Resolved::ShowFdb { domain, mac },
        Command::ShowInterface { name } => Resolved::ShowInterface { name },
        Command::ShowInterfaceBrief => Resolved::ShowInterfaceBrief,
        Command::ShowPortAggregate { name } => Resolved::ShowPortAggregate { name },
        Command::ShowLacp { name, detail } => Resolved::ShowLacp { name, detail },
        Command::ShowLldpNeighbors { detail, interface } => {
            Resolved::ShowLldpNeighbors { detail, interface }
        }
        Command::ShowLldpStatistics => Resolved::ShowLldpStatistics,
        Command::ShowVersion => Resolved::ShowVersion,
        Command::ShowAcl { name } => Resolved::ShowAcl { name },
        Command::ClearAclCounters { name } => Resolved::ClearAclCounters { name },
        Command::ShowSpanningTree => Resolved::ShowSpanningTree,
        Command::ShowSpanningTreeInstance { id } => Resolved::ShowSpanningTreeInstance { id },
        Command::ShowSpanningTreeMstConfig => Resolved::ShowSpanningTreeMstConfig,
        Command::ShowSpanningTreeDomain { domain } => Resolved::ShowSpanningTreeDomain { domain },
        Command::ShowSpanningTreeDetail { instance, domain } => {
            Resolved::ShowSpanningTreeDetail { instance, domain }
        }
        Command::ShowBfdSessions { peer, detail } => Resolved::ShowBfdSessions { peer, detail },
        Command::ShowBfdReflector => Resolved::ShowBfdReflector,
        Command::ShowLog {
            source,
            follow,
            last,
            level,
            needle,
        } => Resolved::ShowLog {
            source,
            follow,
            last,
            level,
            needle,
        },
        Command::ShowBgpSummary { instance } => Resolved::ShowBgpSummary { instance },
        Command::ShowBgpNeighbor { peer, instance } => {
            Resolved::ShowBgpNeighbor { peer, instance }
        }
        Command::ShowBgpEvpn => Resolved::ShowBgpEvpn,
        Command::ShowBgpFlowspec { family, vrf } => Resolved::ShowBgpFlowspec { family, vrf },
        Command::ShowBgpRpki => Resolved::ShowBgpRpki,
        Command::ShowBgpBmp => Resolved::ShowBgpBmp,
        Command::ShowBgpVpn { family, rd } => Resolved::ShowBgpVpn { family, rd },
        Command::ShowBgpRoutes => Resolved::ShowBgpRoutes,
        Command::ShowOspfNeigh => Resolved::ShowOspfNeigh,
        Command::ShowOspfInterface => Resolved::ShowOspfInterface,
        Command::ShowOspfRoute => Resolved::ShowOspfRoute,
        Command::ShowOspfDatabase {
            lsa_type,
            adv_router,
        } => Resolved::ShowOspfDatabase {
            lsa_type,
            adv_router,
        },
        Command::ShowOspfSegmentRouting => Resolved::ShowOspfSegmentRouting,
        Command::ShowOspfInstance => Resolved::ShowOspfInstance,
        Command::ShowOspfv3Instance => Resolved::ShowOspfv3Instance,
        Command::ShowOspfv3Neigh => Resolved::ShowOspfv3Neigh,
        Command::ShowOspfv3Interface => Resolved::ShowOspfv3Interface,
        Command::ShowOspfv3Route => Resolved::ShowOspfv3Route,
        Command::ShowOspfv3Database {
            lsa_type,
            adv_router,
        } => Resolved::ShowOspfv3Database {
            lsa_type,
            adv_router,
        },
        Command::ClearBgpSoftIn { instance, peer } => Resolved::ClearBgpSoftIn { instance, peer },
        Command::ClearBgpPeer { instance, peer } => Resolved::ClearBgpPeer { instance, peer },
        Command::ClearStpMcheck { interface } => Resolved::ClearStpMcheck { interface },
        Command::ClearStpErrDisabled { interface } => Resolved::ClearStpErrDisabled { interface },
        Command::Unknown(s) => {
            Resolved::Error(format!("unknown command: '{s}' (type 'help' for a list)"))
        }

        Command::Exit => match mode {
            Mode::Operational => Resolved::ExitShell,
            Mode::Configuration { .. } => Resolved::LeaveConfigPrompt,
        },

        Command::Save => match mode {
            Mode::Operational => Resolved::SaveRunningConfig,
            Mode::Configuration { .. } => Resolved::Error(
                "'save' persists the running config; commit first, or run it after leaving configuration mode".to_string(),
            ),
        },

        Command::Configure { name, base } => resolve_configure(mode, name, base),

        // Everything else only makes sense once a transaction is open.
        other => match mode {
            Mode::Operational => not_configuring(&other),
            Mode::Configuration { path, .. } => resolve_in_transaction(path, other),
        },
    }
}

fn resolve_configure(mode: &Mode, name: String, base: Option<TransactionBase>) -> Resolved {
    match mode {
        Mode::Operational => Resolved::OpenTransaction {
            name,
            base: base.unwrap_or(TransactionBase::Current),
            explicit_base: base.is_some(),
        },
        Mode::Configuration { transaction, .. } => Resolved::Error(format!(
            "already editing transaction '{transaction}' — use 'top' or 'exit' first"
        )),
    }
}

/// The error for a command that requires configuration mode, issued while
/// still `Operational`. `Commit`/`Discard` get a more specific message.
fn not_configuring(cmd: &Command) -> Resolved {
    let msg = match cmd {
        Command::Commit => "not in configuration mode — nothing to commit",
        Command::Discard => "not in configuration mode — nothing to discard",
        _ => "not in configuration mode — use 'configure <name>' first",
    };
    Resolved::Error(msg.to_string())
}

const NO_CURRENT_POLICY_DEFINITION: &str =
    "no current policy-definition — use 'edit policy-definition <name>' first";
const ALREADY_AT_TOP: &str = "already at the top level";

fn resolve_in_transaction(path: &Path, cmd: Command) -> Resolved {
    let policy = || {
        path.policy_definition()
            .map(str::to_string)
            .ok_or(NO_CURRENT_POLICY_DEFINITION)
    };
    let resolved = match cmd {
        Command::Show => Ok(Resolved::ShowTransaction),
        Command::Config(line) => Ok(Resolved::ConfigEdit(line)),
        Command::EditSource => policy().map(|name| Resolved::EditPolicySource { name }),
        Command::ShowSource => policy().map(|name| Resolved::ShowPolicySource { name }),
        Command::SetSourceLine { line, text } => {
            policy().map(|name| Resolved::SetPolicySourceLine { name, line, text })
        }
        Command::DeleteSourceLine { line } => {
            policy().map(|name| Resolved::DeletePolicySourceLine { name, line })
        }
        Command::Top | Command::Up if path.is_root() => Err(ALREADY_AT_TOP),
        Command::Top => Ok(Resolved::NavigateTop),
        Command::Up => Ok(Resolved::Navigate(path.up())),
        Command::Commit => Ok(Resolved::Commit),
        Command::CommitConfirmed { minutes } => Ok(Resolved::CommitConfirmed { minutes }),
        Command::Rollback { n } => Ok(Resolved::Rollback { n }),
        Command::Discard => Ok(Resolved::Discard),
        Command::Diff => Ok(Resolved::Diff),
        Command::Configure { .. }
        | Command::Empty
        | Command::Help
        | Command::ShowConfig
        | Command::ShowConfigAdmin
        | Command::ShowConfigPath(_)
        | Command::ShowHistory
        | Command::ShowConfigDiff { .. }
        | Command::ShowAaaUsers
        | Command::AllocateAaaUser { .. }
        | Command::ClearAaaUser { .. }
        | Command::ConfirmCommit
        | Command::CancelCommit
        | Command::ShowRoute { .. }
        | Command::ShowRouteTables
        | Command::ShowRouteSummary { .. }
        | Command::ShowFdb { .. }
        | Command::ShowInterface { .. }
        | Command::ShowInterfaceBrief
        | Command::ShowPortAggregate { .. }
        | Command::ShowLacp { .. }
        | Command::ShowLldpNeighbors { .. }
        | Command::ShowLldpStatistics
        | Command::ShowVersion
        | Command::ShowAcl { .. }
        | Command::ClearAclCounters { .. }
        | Command::ShowSpanningTree
        | Command::ShowSpanningTreeInstance { .. }
        | Command::ShowSpanningTreeMstConfig
        | Command::ShowSpanningTreeDomain { .. }
        | Command::ShowSpanningTreeDetail { .. }
        | Command::ShowBfdSessions { .. }
        | Command::ShowBfdReflector
        | Command::ShowLog { .. }
        | Command::ShowBgpSummary { .. }
        | Command::ShowBgpNeighbor { .. }
        | Command::ShowBgpEvpn
        | Command::ShowBgpFlowspec { .. }
        | Command::ShowBgpRpki
        | Command::ShowBgpBmp
        | Command::ShowBgpVpn { .. }
        | Command::ShowBgpRoutes
        | Command::ShowOspfNeigh
        | Command::ShowOspfInterface
        | Command::ShowOspfRoute
        | Command::ShowOspfDatabase { .. }
        | Command::ShowOspfSegmentRouting
        | Command::ShowOspfInstance
        | Command::ShowOspfv3Instance
        | Command::ShowOspfv3Neigh
        | Command::ShowOspfv3Interface
        | Command::ShowOspfv3Route
        | Command::ShowOspfv3Database { .. }
        | Command::ClearBgpSoftIn { .. }
        | Command::ClearBgpPeer { .. }
        | Command::ClearStpMcheck { .. }
        | Command::ClearStpErrDisabled { .. }
        | Command::Unknown(_)
        | Command::Exit
        | Command::Save => {
            unreachable!("resolve() handles these before delegating to resolve_in_transaction")
        }
    };
    resolved.unwrap_or_else(|err| Resolved::Error(err.to_string()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_show_and_ops_commands_are_accounted() {
        assert!(Resolved::ShowVersion.is_accounted());
        assert!(Resolved::ShowHistory.is_accounted());
        assert!(!Resolved::Commit.is_accounted());
        assert!(!Resolved::Help.is_accounted());
        assert!(!Resolved::ConfigEdit("set x".into()).is_accounted());
    }

    use super::*;

    fn at(segments: &[&str]) -> Path {
        Path::from(segments.iter().map(ToString::to_string).collect::<Vec<_>>())
    }

    fn config_mode(path: Path) -> Mode {
        Mode::Configuration {
            transaction: "t1".to_string(),
            path,
            dirty: false,
        }
    }

    #[test]
    fn config_lines_need_a_transaction() {
        let line = || Command::Config("set hostname r1".to_string());
        assert!(matches!(
            resolve(&Mode::Operational, line()),
            Resolved::Error(_)
        ));
        assert_eq!(
            resolve(&config_mode(Path::root()), line()),
            Resolved::ConfigEdit("set hostname r1".to_string())
        );
    }

    #[test]
    fn up_goes_one_object_up_and_top_to_the_root() {
        let profile = at(&["ospf-instance", "o1", "area", "0.0.0.0", "profile", "p1"]);
        assert_eq!(
            resolve(&config_mode(profile.clone()), Command::Up),
            Resolved::Navigate(at(&["ospf-instance", "o1", "area", "0.0.0.0"]))
        );
        assert_eq!(
            resolve(&config_mode(profile), Command::Top),
            Resolved::NavigateTop
        );
        assert!(matches!(
            resolve(&config_mode(Path::root()), Command::Up),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn source_commands_need_a_policy_definition() {
        assert_eq!(
            resolve(
                &config_mode(at(&["policy-definition", "p1"])),
                Command::ShowSource
            ),
            Resolved::ShowPolicySource {
                name: "p1".to_string()
            }
        );
        assert!(matches!(
            resolve(&config_mode(Path::root()), Command::EditSource),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn prompt_position_pairs_list_and_key() {
        assert_eq!(
            at(&["bgp-instance", "r1", "peer-group", "pg1"]).to_string(),
            "bgp-instance:r1/peer-group:pg1"
        );
        assert_eq!(Path::root().to_string(), "");
    }

    #[test]
    fn exit_and_save_depend_on_mode() {
        assert_eq!(
            resolve(&Mode::Operational, Command::Exit),
            Resolved::ExitShell
        );
        assert_eq!(
            resolve(&config_mode(Path::root()), Command::Exit),
            Resolved::LeaveConfigPrompt
        );
        assert_eq!(
            resolve(&Mode::Operational, Command::Save),
            Resolved::SaveRunningConfig
        );
        assert!(matches!(
            resolve(&config_mode(Path::root()), Command::Save),
            Resolved::Error(_)
        ));
    }

    #[test]
    fn configure_opens_a_transaction_only_from_operational_mode() {
        assert_eq!(
            resolve(
                &Mode::Operational,
                Command::Configure {
                    name: "t1".to_string(),
                    base: None
                }
            ),
            Resolved::OpenTransaction {
                name: "t1".to_string(),
                base: TransactionBase::Current,
                explicit_base: false,
            }
        );
        assert!(matches!(
            resolve(
                &config_mode(Path::root()),
                Command::Configure {
                    name: "t2".to_string(),
                    base: None
                }
            ),
            Resolved::Error(_)
        ));
    }
}
