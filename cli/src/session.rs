use std::fmt;
use std::net::IpAddr;

use nos_proto::TransactionBase;

use crate::command::Command;

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
    /// `show this` in configuration mode — fetch the transaction and render
    /// it at the current path.
    ShowTransaction,
    /// `show route <table>` (whole table) or `show route <table> <address>`
    /// (longest-prefix-match lookup) — data-plane, valid in any mode.
    ShowRoute {
        table: String,
        address: Option<IpAddr>,
    },
    /// `show fdb <domain>` — data-plane, valid in any mode.
    ShowFdb {
        domain: String,
    },
    /// `show interface` (every interface) or `show interface <name>` (one)
    /// — data-plane, valid in any mode.
    ShowInterface {
        name: Option<String>,
    },
    /// `show port-aggregate` (every aggregate) or `show port-aggregate
    /// <name>` (one) — data-plane, valid in any mode.
    ShowPortAggregate {
        name: Option<String>,
    },
    ShowLacp {
        name: Option<String>,
    },
    /// `show lldp neighbors [detail]` — data-plane, valid in any mode.
    ShowLldpNeighbors {
        detail: bool,
    },
    /// `show lldp statistics` — data-plane, valid in any mode.
    ShowLldpStatistics,
    /// `show version` — printed locally, no IPC.
    ShowVersion,
    /// `show acl [<name>]` — data-plane, valid in any mode.
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
    /// `show bfd sessions [<peer>]` — data-plane, valid in any mode.
    ShowBfdSessions {
        peer: Option<std::net::IpAddr>,
    },
    /// `show bfd reflector` — data-plane, valid in any mode.
    ShowBfdReflector,
    /// `show log [<source>] [--follow]` — data-plane, valid in any mode.
    ShowLog {
        source: Option<String>,
        follow: bool,
    },
    /// `show bgp brief` — data-plane, valid in any mode. Router-wide (no
    /// instance argument): the caller iterates every `BgpInstance` in the
    /// running config itself.
    ShowBgpBrief,
    /// `show bgp evpn` — data-plane, valid in any mode. Router-wide like
    /// `ShowBgpBrief`.
    ShowBgpEvpn,
    /// `show bgp flowspec` — data-plane, valid in any mode, router-wide.
    ShowBgpFlowspec,
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
    /// instance argument), mirroring `ShowBgpBrief`: the caller iterates
    /// every `OspfInstance` in the running config itself.
    ShowOspfNeigh,
    /// `show ospf database` — data-plane, valid in any mode. Router-wide (no
    /// instance argument), mirroring `ShowOspfNeigh`.
    ShowOspfDatabase,
    /// `show ospfv3 neigh` — mirrors `ShowOspfNeigh`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Neigh,
    /// `show ospfv3 database` — mirrors `ShowOspfDatabase`, across every
    /// configured `Ospfv3Instance`.
    ShowOspfv3Database,
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
    OpenTransaction {
        name: String,
        base: TransactionBase,
        explicit_base: bool,
    },
    /// An `edit`/`set`/`delete` line, for `config_grammar` to resolve against
    /// the transaction's config at the current position.
    ConfigEdit(String),
    Commit,
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

pub fn resolve(mode: &Mode, cmd: Command) -> Resolved {
    match cmd {
        Command::Empty => Resolved::Nothing,
        Command::Help => Resolved::Help,
        Command::ShowConfig => Resolved::ShowRunningConfig,
        Command::ShowConfigAdmin => Resolved::ShowAdminConfig,
        Command::ShowRoute { table, address } => Resolved::ShowRoute { table, address },
        Command::ShowFdb { domain } => Resolved::ShowFdb { domain },
        Command::ShowInterface { name } => Resolved::ShowInterface { name },
        Command::ShowPortAggregate { name } => Resolved::ShowPortAggregate { name },
        Command::ShowLacp { name } => Resolved::ShowLacp { name },
        Command::ShowLldpNeighbors { detail } => Resolved::ShowLldpNeighbors { detail },
        Command::ShowLldpStatistics => Resolved::ShowLldpStatistics,
        Command::ShowVersion => Resolved::ShowVersion,
        Command::ShowAcl { name } => Resolved::ShowAcl { name },
        Command::ShowSpanningTree => Resolved::ShowSpanningTree,
        Command::ShowSpanningTreeInstance { id } => Resolved::ShowSpanningTreeInstance { id },
        Command::ShowSpanningTreeMstConfig => Resolved::ShowSpanningTreeMstConfig,
        Command::ShowSpanningTreeDomain { domain } => Resolved::ShowSpanningTreeDomain { domain },
        Command::ShowSpanningTreeDetail { instance, domain } => {
            Resolved::ShowSpanningTreeDetail { instance, domain }
        }
        Command::ShowBfdSessions { peer } => Resolved::ShowBfdSessions { peer },
        Command::ShowBfdReflector => Resolved::ShowBfdReflector,
        Command::ShowLog { source, follow } => Resolved::ShowLog { source, follow },
        Command::ShowBgpBrief => Resolved::ShowBgpBrief,
        Command::ShowBgpEvpn => Resolved::ShowBgpEvpn,
        Command::ShowBgpFlowspec => Resolved::ShowBgpFlowspec,
        Command::ShowBgpRpki => Resolved::ShowBgpRpki,
        Command::ShowBgpBmp => Resolved::ShowBgpBmp,
        Command::ShowBgpVpn { family, rd } => Resolved::ShowBgpVpn { family, rd },
        Command::ShowBgpRoutes => Resolved::ShowBgpRoutes,
        Command::ShowOspfNeigh => Resolved::ShowOspfNeigh,
        Command::ShowOspfDatabase => Resolved::ShowOspfDatabase,
        Command::ShowOspfv3Neigh => Resolved::ShowOspfv3Neigh,
        Command::ShowOspfv3Database => Resolved::ShowOspfv3Database,
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
        Command::Discard => Ok(Resolved::Discard),
        Command::Diff => Ok(Resolved::Diff),
        Command::Configure { .. }
        | Command::Empty
        | Command::Help
        | Command::ShowConfig
        | Command::ShowConfigAdmin
        | Command::ShowRoute { .. }
        | Command::ShowFdb { .. }
        | Command::ShowInterface { .. }
        | Command::ShowPortAggregate { .. }
        | Command::ShowLacp { .. }
        | Command::ShowLldpNeighbors { .. }
        | Command::ShowLldpStatistics
        | Command::ShowVersion
        | Command::ShowAcl { .. }
        | Command::ShowSpanningTree
        | Command::ShowSpanningTreeInstance { .. }
        | Command::ShowSpanningTreeMstConfig
        | Command::ShowSpanningTreeDomain { .. }
        | Command::ShowSpanningTreeDetail { .. }
        | Command::ShowBfdSessions { .. }
        | Command::ShowBfdReflector
        | Command::ShowLog { .. }
        | Command::ShowBgpBrief
        | Command::ShowBgpEvpn
        | Command::ShowBgpFlowspec
        | Command::ShowBgpRpki
        | Command::ShowBgpBmp
        | Command::ShowBgpVpn { .. }
        | Command::ShowBgpRoutes
        | Command::ShowOspfNeigh
        | Command::ShowOspfDatabase
        | Command::ShowOspfv3Neigh
        | Command::ShowOspfv3Database
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
