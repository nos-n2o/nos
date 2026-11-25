//! The show/shell half of the CLI's grammar: every command that isn't a
//! config edit, with its tokens, where it's valid, where its documentation
//! comes from, and the `Command` it builds — `help`, Tab-completion and the
//! live `?` key read these rows, and `parse` walks them. Config edits
//! (`edit`/`set`/`delete`) have no rows: they come from the schema's tree,
//! see `config_grammar` (#109).
//! The *semantic* explanation of what a command does comes from
//! `nos-config` (see `Doc::FromConfig`) — `spec.rs` stays pure and knows
//! nothing about caching or IPC; resolving a `Doc::FromConfig(topic)` into
//! actual text is the caller's job (see `main.rs`'s `doc_for`/`doc_for_blocking`).

use nos_proto::{Topic, TransactionBase};

use crate::command::Command;
use crate::session::Mode;

/// One piece of a command's token sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    Literal(&'static str),
    Arg(ArgKind),
    /// One optional trailing clause (`[--follow]`, `[last <n>]`, `[<source>]`):
    /// its first token is a `Literal` keyword, or the clause is the lone
    /// source `Arg`. Only ever after every non-`Opt` token of a row (#1450).
    Opt(&'static [Token]),
}

/// What kind of value an argument slot accepts — `BgpInstanceName` and
/// `BgpPeerGroupName` are the slots Tab-completion can fill from live
/// daemon state.
/// What kind of value an argument slot accepts. The `*Name` kinds complete
/// from the keys of that top-level config list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    Plain,
    BgpInstanceName,
    RoutingTableName,
    InterfaceName,
    BroadcastDomainName,
    PortAggregateName,
    AclName,
    /// An IPv4 or IPv6 address.
    IpAddr,
    /// A non-negative integer.
    Number,
    /// The rest of the line, verbatim (leading whitespace kept) — only ever
    /// a row's last token.
    Rest,
    /// A log level (`ArgKind::fixed_values`).
    LogLevel,
    /// A log source name; completion comes with the lazy fetch (#1452).
    LogSource,
}

impl ArgKind {
    /// The config list (serde field of `Config`) a `*Name` slot names a key of.
    pub fn config_list(self) -> Option<&'static str> {
        Some(match self {
            ArgKind::BgpInstanceName => "bgp_instances",
            ArgKind::RoutingTableName => "routing_tables",
            ArgKind::InterfaceName => "interfaces",
            ArgKind::BroadcastDomainName => "broadcast_domains",
            ArgKind::PortAggregateName => "port_aggregates",
            ArgKind::AclName => "acls",
            _ => return None,
        })
    }

    /// The closed set of words a slot accepts, for Tab.
    pub fn fixed_values(self) -> Option<&'static [&'static str]> {
        match self {
            ArgKind::LogLevel => Some(&["trace", "debug", "info", "warn", "error"]),
            _ => None,
        }
    }
}

/// A `level` clause's word (`ArgKind::LogLevel::fixed_values`).
pub fn parse_log_level(word: &str) -> Option<nos_proto::LogLevel> {
    use nos_proto::LogLevel::{Debug, Error, Info, Trace, Warn};
    Some(match word {
        "trace" => Trace,
        "debug" => Debug,
        "info" => Info,
        "warn" => Warn,
        "error" => Error,
        _ => return None,
    })
}

/// Where a command's summary/detail text comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Doc {
    /// Resolve via `nos-config`'s `Request::Describe { topic }` (cached).
    FromConfig(Topic),
    /// Purely local shell mechanics with no server-side meaning.
    Local {
        summary: &'static str,
        detail: &'static str,
    },
}

/// Which `Mode`/position a command is valid in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Always,
    Operational,
    Configuration,
    /// Navigated into any object (not at the transaction root).
    ConfigurationNested,
    ConfigurationPolicyDefinition,
}

pub fn availability_matches(availability: Availability, mode: &Mode) -> bool {
    let path = match mode {
        Mode::Operational => {
            return matches!(
                availability,
                Availability::Always | Availability::Operational
            )
        }
        Mode::Configuration { path, .. } => path,
    };
    match availability {
        Availability::Always | Availability::Configuration => true,
        Availability::Operational => false,
        Availability::ConfigurationNested => !path.is_root(),
        Availability::ConfigurationPolicyDefinition => path.policy_definition().is_some(),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CommandSpec {
    pub tokens: &'static [Token],
    /// Generated from the tokens, e.g. `"show route <table> <address>"`.
    pub usage: &'static str,
    pub doc: Doc,
    pub availability: Availability,
    /// Builds the `Command` from the row's argument words, in token order —
    /// so a command can't be accepted without the `doc` it is declared with.
    pub build: Build,
}

/// A row's constructor: its argument words in, the `Command` out.
pub type Build = fn(&[&str]) -> Option<Command>;

/// The config verbs: their words come from the schema's tree, not from rows.
pub const CONFIG_VERBS: &[(&str, Doc)] = &[
    (
        "edit",
        Doc::Local {
            summary: "Navigate into a config object, creating it if missing.",
            detail: "`edit <path>` walks the config tree (relative to where you are, else from \
                     the top) to an object such as `bgp instance r1` or `interface eth0`, \
                     creating it with default values if it doesn't exist, and makes it the \
                     current position: `set`/`delete` then take paths relative to it.",
        },
    ),
    (
        "set",
        Doc::Local {
            summary: "Set a config field, or add a list entry.",
            detail: "`set <path> <field> <value>`: the path is relative to the current \
                     position, else from the top; any missing object on the way is created \
                     with default values. A switch (e.g. `route-reflector-client`) takes no \
                     value. Inside a list entry, `set <entry> first|last|before <key>|after \
                     <key>` places it in the list (without one, a new entry is appended and \
                     an existing one keeps its place). Press ? after a word to see what fits \
                     next.",
        },
    ),
    (
        "move",
        Doc::Local {
            summary: "Move a list entry to another place in its list.",
            detail: "`move <path> first|last|before <key>|after <key>`: re-orders an existing \
                     entry of an ordered list (e.g. an ACL's rules) without changing it. The \
                     path is relative to the current position, else from the top.",
        },
    ),
    (
        "delete",
        Doc::Local {
            summary: "Clear a config field, remove a list entry, or delete an object.",
            detail: "`delete <path> <field>` clears the field back to its default; `delete \
                     <path> <list> <key>` removes that entry or object; bare `delete` removes \
                     the object you are in and moves up one level.",
        },
    ),
];

const EXIT_DOC: Doc = Doc::Local {
    summary: "Exit the shell (or leave configuration mode).",
    detail: "In operational mode, exits the shell entirely. In configuration mode, returns \
             to operational mode instead — prompting to commit, discard, or leave the \
             transaction open first if there are uncommitted changes. `quit` and `end` are \
             synonyms.",
};

/// One token of a command's syntax: a bare string literal is a keyword, a
/// parenthesised identifier is an argument slot naming its `ArgKind` —
/// optionally named, `(table: RoutingTableName)`, which `cmd!` needs for the
/// usage string.
macro_rules! tok {
    ($l:literal) => {
        Token::Literal($l)
    };
    (($k:ident)) => {
        Token::Arg(ArgKind::$k)
    };
    (($n:ident : $k:ident)) => {
        Token::Arg(ArgKind::$k)
    };
    ([$f:tt $($r:tt)*]) => {
        Token::Opt(&[tok!($f) $(, tok!($r))*])
    };
}

/// A token's text in a generated usage string: the keyword, or `<name>`.
macro_rules! usage_tok {
    ($l:literal) => {
        $l
    };
    (($n:ident : $k:ident)) => {
        concat!("<", stringify!($n), ">")
    };
    ([$f:tt $($r:tt)*]) => {
        concat!("[", usage_tok!($f) $(, " ", usage_tok!($r))*, "]")
    };
}

/// One row of the command grammar: its token syntax (every argument named),
/// where its prose comes from, where it's valid, and the `Command` it
/// parses to — built from the argument words, bound in token order. The
/// usage string is generated from the tokens. A body that fails (`?`) makes
/// the whole line `Command::Unknown`; it never falls through to a later row.
///
/// ```ignore
/// cmd!(["show" "route" (table: RoutingTableName) (address: IpAddr)],
///     Doc::Local { summary: "…", detail: "…" },
///     Always,
///     |table, address| Command::ShowRoute {
///         table: table.to_string(),
///         address: Some(address.parse().ok()?),
///     }),
/// ```
macro_rules! cmd {
    ([$first:tt $($rest:tt)*], $doc:expr, $avail:ident, |$($arg:ident),+| $body:expr) => {
        cmd!(@row [$first $($rest)*], $doc, $avail, |args: &[&str]| {
            let &[$($arg),+] = args else { return None };
            Some($body)
        })
    };
    ([$first:tt $($rest:tt)*], $doc:expr, $avail:ident, $body:expr) => {
        cmd!(@row [$first $($rest)*], $doc, $avail, |_: &[&str]| Some($body))
    };
    (@row [$first:tt $($rest:tt)*], $doc:expr, $avail:ident, $build:expr) => {
        CommandSpec {
            tokens: &[tok!($first) $(, tok!($rest))*],
            usage: concat!(usage_tok!($first) $(, " ", usage_tok!($rest))*),
            doc: $doc,
            availability: Availability::$avail,
            build: $build,
        }
    };
}

const OSPF_NEIGH_DOC: Doc = Doc::Local {
    summary: "Show a one-line-per-neighbor OSPF adjacency summary across every instance.",
    detail: "Queries every configured OSPF instance's nos-ospfd (each resolved via \
             nos-watchdogd) for its links' current neighbor state, interface state, \
             last-hello age, and elected DR/BDR. An instance whose nos-ospfd isn't \
             running is reported individually rather than aborting the whole command.",
};

const OSPFV3_NEIGH_DOC: Doc = Doc::Local {
    summary: "Show a one-line-per-neighbor OSPFv3 adjacency summary across every instance.",
    detail: "Mirrors 'show ospf neigh' for OSPFv3 (RFC 5340): queries every configured \
             Ospfv3Instance's nos-ospfv3d (each resolved via nos-watchdogd) for its \
             links' current neighbor state, interface state, last-hello age, and \
             elected DR/BDR.",
};

const OSPF_IF_DOC: Doc = Doc::Local {
    summary: "Show every running OSPF interface across every instance.",
    detail: "Queries every configured OSPF instance's nos-ospfd for its running links: \
             area, address, network type, state, cost, timers, elected DR/BDR and the \
             neighbor counts (known and Full). A passive interface or one without an \
             address does not run and is not listed.",
};

const OSPFV3_IF_DOC: Doc = Doc::Local {
    summary: "Show every running OSPFv3 interface across every instance.",
    detail: "Mirrors 'show ospf interface' for OSPFv3: link-local address and Interface ID \
             instead of the IPv4 address.",
};

const OSPF_DB_DOC: Doc = Doc::Local {
    summary: "Show every installed LSA's header across every OSPF instance, optionally of one type and advertising router.",
    detail: "Queries every configured OSPF instance's daemon (each resolved via nos-watchdogd) for \
             its per-area LSDB's installed LSA headers, as a table (type, link-state-id, advertising router, sequence number, age, checksum, metric and flags). The Info column shows an \
             external LSA's metric and E1/E2, a router LSA's B/E/V flags and virtual links. \
             <type> is one of router, network, summary, asbr-summary, external, nssa, opaque-link, opaque-area, opaque-as, or a decimal number; <adv-router> is a router id. An instance whose daemon \
             isn't running is reported individually rather than aborting the whole command.",
};

const OSPFV3_DB_DOC: Doc = Doc::Local {
    summary: "Show every installed LSA's header across every OSPFv3 instance, optionally of one type and advertising router.",
    detail: "Queries every configured OSPFv3 instance's daemon (each resolved via nos-watchdogd) for \
             its per-area LSDB's installed LSA headers, as a table (type, link-state-id, advertising router, sequence number, age, checksum, owning link, flags). The Info column shows an \
             external LSA's metric and E1/E2, a router LSA's B/E/V flags and virtual links. \
             <type> is one of router, network, inter-area-prefix, inter-area-router, as-external, nssa, link, intra-area-prefix, grace and the e-* E-LSA types, or a decimal or 0x hex number; <adv-router> is a router id. An instance whose daemon \
             isn't running is reported individually rather than aborting the whole command.",
};

#[rustfmt::skip]
pub const COMMAND_SPECS: &[CommandSpec] = &[
    cmd!(["show" "config"],
        Doc::FromConfig(Topic::ShowRunningConfig),
        Always,
        Command::ShowConfig),
    cmd!(["show" "config" "admin"],
        Doc::FromConfig(Topic::Admin),
        Always,
        Command::ShowConfigAdmin),
    cmd!(["show" "config" (path: Rest)],
        Doc::FromConfig(Topic::ShowRunningConfig),
        Always,
        |path| Command::ShowConfigPath(path.trim().to_string())),
    cmd!(["show" "this"],
        Doc::FromConfig(Topic::GetTransaction),
        Configuration,
        Command::Show),
    cmd!(["show" "route" (table: RoutingTableName)],
        Doc::Local {
            summary: "Show every route in a routing table, best to worst per prefix.",
            detail: "Queries the table's nos-ribd instance (resolved via nos-watchdogd) for \
                     every prefix it currently knows, each with its full list of candidate \
                     routes ordered from the winning route to the losing ones — since more \
                     than one source (e.g. static and BGP) can target the same prefix. \
                     Prefixes are listed in ascending CIDR order.",
        },
        Always,
        |table| Command::ShowRoute {
            table: table.to_string(),
            address: None,
        }),
    cmd!(["show" "route" (table: RoutingTableName) (address: IpAddr)],
        Doc::Local {
            summary: "Look up the best route(s) for one destination address.",
            detail: "Performs a longest-prefix-match lookup against the table's nos-ribd \
                     instance for the given address, and shows every candidate route for the \
                     matched prefix, ordered from the winning route to the losing ones.",
        },
        Always,
        |table, address| Command::ShowRoute {
            table: table.to_string(),
            address: Some(address.parse().ok()?),
        }),
    cmd!(["show" "fdb" (domain: BroadcastDomainName)],
        Doc::Local {
            summary: "Show a broadcast domain's forwarding database.",
            detail: "Queries the domain's nos-fdbd instance (resolved via nos-watchdogd) for \
                     the MACs behind its VXLAN device — learned locally on the bridge, or \
                     from EVPN Type-2 routes with the VTEP they sit behind — and the remote \
                     VTEPs its flood list replicates broadcast/unknown/multicast traffic to.",
        },
        Always,
        |domain| Command::ShowFdb {
            domain: domain.to_string(),
        }),
    cmd!(
        ["save"],
        Doc::FromConfig(Topic::Save),
        Operational,
        Command::Save
    ),
    cmd!(["show" "aaa" "users"],
        Doc::Local {
            summary: "Show the externally authenticated users that have an ssh account entry.",
            detail: "Lists the names (RADIUS or TACACS+ users) nos-configd gave a persistent \
                     uid after an accepted login, or an administrator allocated. Admin only.",
        },
        Always,
        Command::ShowAaaUsers),
    cmd!(["allocate" "aaa" "user" (name: Plain)],
        Doc::Local {
            summary: "Give an external user a persistent uid and ssh account entry.",
            detail: "Allocates the name an account entry ahead of its first login, so an \
                     ssh-only user need not log in through the shell first. The name must be a \
                     valid unix user name, not a local user, not in /etc/passwd. The uid is never \
                     reused. Admin only.",
        },
        Always,
        |name| Command::AllocateAaaUser {
            name: name.to_string(),
        }),
    cmd!(["clear" "aaa" "user" (name: Plain)],
        Doc::Local {
            summary: "Remove an external user's ssh account entry.",
            detail: "Drops the entry from the passwd file; the uid stays reserved for that \
                     name and is never given to another. Admin only.",
        },
        Always,
        |name| Command::ClearAaaUser {
            name: name.to_string(),
        }),
    cmd!(
        ["show" "configuration" "history"],
        Doc::FromConfig(Topic::ShowHistory),
        Always,
        Command::ShowHistory
    ),
    cmd!(
        ["show" "configuration" "diff" (n: Number)],
        Doc::FromConfig(Topic::ShowConfigurationDiff),
        Always,
        |n| Command::ShowConfigDiff { from: n.parse().ok()?, to: 0 }
    ),
    cmd!(
        ["show" "configuration" "diff" (n: Number) (m: Number)],
        Doc::FromConfig(Topic::ShowConfigurationDiff),
        Always,
        |n, m| Command::ShowConfigDiff { from: n.parse().ok()?, to: m.parse().ok()? }
    ),
    cmd!(
        ["rollback" (n: Number)],
        Doc::FromConfig(Topic::Rollback),
        Configuration,
        |n| Command::Rollback { n: n.parse().ok()? }
    ),
    cmd!(
        ["help"],
        Doc::Local {
            summary: "Show available commands for the current mode.",
            detail: "Lists every command valid right now, given whether the shell is in \
                     operational mode or configuration mode (and, within configuration \
                     mode, the current navigation position). Equivalent to pressing `?` on \
                     an empty line.",
        },
        Always,
        Command::Help
    ),
    cmd!(["exit"], EXIT_DOC, Always, Command::Exit),
    cmd!(["quit"], EXIT_DOC, Always, Command::Exit),
    cmd!(["end"], EXIT_DOC, Always, Command::Exit),
    cmd!(["configure" (name: Plain)],
        Doc::FromConfig(Topic::OpenTransaction),
        Operational,
        |name| Command::Configure {
            name: name.to_string(),
            base: None,
        }),
    cmd!(["configure" (name: Plain) "from" "blank"],
        Doc::FromConfig(Topic::OpenTransaction),
        Operational,
        |name| Command::Configure {
            name: name.to_string(),
            base: Some(TransactionBase::Blank),
        }),
    cmd!(["configure" (name: Plain) "from" "current"],
        Doc::FromConfig(Topic::OpenTransaction),
        Operational,
        |name| Command::Configure {
            name: name.to_string(),
            base: Some(TransactionBase::Current),
        }),
    cmd!(
        ["up"],
        Doc::Local {
            summary: "Navigate up one level.",
            detail: "Moves the current navigation position up one level: from a peer-group, \
                     to its owning BGP instance; from a BGP instance, to the transaction \
                     root (same as `top`).",
        },
        ConfigurationNested,
        Command::Up
    ),
    cmd!(
        ["top"],
        Doc::Local {
            summary: "Navigate back to the transaction root.",
            detail: "Moves the current navigation position directly to the transaction \
                     root, regardless of how deep it is.",
        },
        ConfigurationNested,
        Command::Top
    ),
    cmd!(
        ["commit"],
        Doc::FromConfig(Topic::CommitTransaction),
        Configuration,
        Command::Commit
    ),
    cmd!(
        ["commit" "confirmed"],
        Doc::FromConfig(Topic::CommitTransaction),
        Configuration,
        Command::CommitConfirmed { minutes: None }
    ),
    cmd!(
        ["commit" "confirmed" (n: Number)],
        Doc::FromConfig(Topic::CommitTransaction),
        Configuration,
        |n| Command::CommitConfirmed { minutes: Some(n.parse().ok()?) }
    ),
    cmd!(
        ["commit" "confirm"],
        Doc::FromConfig(Topic::ConfirmCommit),
        Configuration,
        Command::ConfirmCommit
    ),
    cmd!(
        ["commit" "cancel"],
        Doc::FromConfig(Topic::CancelCommit),
        Configuration,
        Command::CancelCommit
    ),
    cmd!(
        ["discard"],
        Doc::FromConfig(Topic::DiscardTransaction),
        Configuration,
        Command::Discard
    ),
    cmd!(
        ["abort"],
        Doc::FromConfig(Topic::DiscardTransaction),
        Configuration,
        Command::Discard
    ),
    cmd!(
        ["diff"],
        Doc::FromConfig(Topic::DiffTransaction),
        Configuration,
        Command::Diff
    ),
    cmd!(["edit" "source"],
        Doc::Local {
            summary: "Edit the current policy's RPL source in the built-in editor.",
            detail: "Opens the built-in editor (Ctrl-S saves, Ctrl-Q cancels) on the current \
                     policy-definition's source. On save, the edited source is compiled against \
                     the transaction and applied only if it compiles; otherwise it is \
                     discarded.",
        },
        ConfigurationPolicyDefinition,
        Command::EditSource),
    cmd!(["show" "source"],
        Doc::Local {
            summary: "Show the current policy's RPL source with line numbers.",
            detail: "Prints the current policy-definition's source as held by the \
                     transaction, one numbered line at a time — the numbers `set source line` \
                     and `delete source line` take.",
        },
        ConfigurationPolicyDefinition,
        Command::ShowSource),
    cmd!(["set" "source" "line" (line: Number) (text: Rest)],
        Doc::Local {
            summary: "Replace (or append) one line of the current policy's RPL source.",
            detail: "Sets line <line> of the current policy-definition's source to <text>, \
                     taken verbatim — leading whitespace is kept, since RPL's indentation is \
                     meaningful. A line number one past the end appends. The change is \
                     staged even if the script doesn't compile yet (with a warning), so a \
                     new script can be built line by line; commit checks it.",
        },
        ConfigurationPolicyDefinition,
        |line, text| Command::SetSourceLine {
            line: line.parse().ok()?,
            text: text.to_string(),
        }),
    cmd!(["delete" "source" "line" (line: Number)],
        Doc::Local {
            summary: "Delete one line of the current policy's RPL source.",
            detail: "Removes line <line> from the current policy-definition's source; the \
                     lines after it move up by one. Staged even if the result doesn't \
                     compile (with a warning); commit checks it.",
        },
        ConfigurationPolicyDefinition,
        |line| Command::DeleteSourceLine {
            line: line.parse().ok()?,
        }),
    cmd!(["show" "port-aggregate"],
        Doc::Local {
            summary: "Show every port aggregate's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for every configured \
                     port aggregate's mode, switching-profile, mtu, and subinterfaces.",
        },
        Always,
        Command::ShowPortAggregate { name: None }),
    cmd!(["show" "port-aggregate" (name: PortAggregateName)],
        Doc::Local {
            summary: "Show one port aggregate's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for the named port \
                     aggregate's mode, switching-profile, mtu, and subinterfaces.",
        },
        Always,
        |name| Command::ShowPortAggregate {
            name: Some(name.to_string()),
        }),
    cmd!(["show" "lldp" "neighbors"],
        Doc::Local {
            summary: "Show every LLDP neighbor heard on any interface.",
            detail: "Queries nos-lldpd (resolved via nos-watchdogd) for every neighbor learned \
                     from received LLDPDUs (IEEE 802.1AB): the local interface it was heard on, \
                     its chassis id, port id, system name and enabled capabilities, and how long \
                     until its entry ages out.",
        },
        Always,
        Command::ShowLldpNeighbors { detail: false }),
    cmd!(["show" "lldp" "neighbors" "detail"],
        Doc::Local {
            summary: "Show every LLDP neighbor in full, one block each.",
            detail: "Like show lldp neighbors, plus what the neighbor advertised in its IEEE \
                     802.1/802.3 TLVs: its VLANs and port VLAN id, link aggregation state, \
                     maximum frame size and auto-negotiation/MAU type. Only the lines the \
                     neighbor sent are printed.",
        },
        Always,
        Command::ShowLldpNeighbors { detail: true }),
    cmd!(["show" "acl"],
        Doc::Local {
            summary: "Show every access list with its counters.",
            detail: "Queries nos-acld (resolved via nos-watchdogd) for every ACL: where it is \
                     attached, its default action and, per rule, the packets and bytes it \
                     matched (summed over every device it is attached to). Rules the optimiser \
                     dropped (shadowed by an earlier rule, or trailing and equal to the default) \
                     are marked and stay at 0. Counters reset when the ACL is edited.",
        },
        Always,
        Command::ShowAcl { name: None }),
    cmd!(["show" "acl" (name: AclName)],
        Doc::Local {
            summary: "Show one access list with its counters.",
            detail: "Same as show acl, for the named ACL only.",
        },
        Always,
        |name| Command::ShowAcl {
            name: Some(name.to_string()),
        }),
    cmd!(["show" "version"],
        Doc::Local {
            summary: "Show the nos version and build revision.",
            detail: "Prints the compile-time version and the short git revision this nos \
                     binary was built from (unknown outside the Docker build). Local to the \
                     shell: it does not contact any daemon.",
        },
        Always,
        Command::ShowVersion),
    cmd!(["show" "lldp" "statistics"],
        Doc::Local {
            summary: "Show every LLDP-enabled interface's counters.",
            detail: "Queries nos-lldpd (resolved via nos-watchdogd) for the IEEE 802.1AB \
                     statistics of each LLDP-enabled interface: frames sent and received, \
                     received frames in error or discarded, optional TLVs discarded or \
                     unrecognized, neighbors aged out, and new neighbors refused because the \
                     table was full. Counters reset when nos-lldpd restarts or LLDP is turned \
                     off on the interface.",
        },
        Always,
        Command::ShowLldpStatistics),
    cmd!(["show" "spanning-tree"],
        Doc::Local {
            summary: "Show the spanning-tree bridge and every port's role and state.",
            detail: "Queries nos-stpd (resolved via nos-watchdogd) for this bridge's id, the \
                     root bridge, the root path cost and root port, the hello/max-age/\
                     forward-delay timers, and a table of every spanning-tree port: its role \
                     (root, designated, alternate, backup, disabled), state (discarding, \
                     learning, forwarding), path cost, priority and the designated \
                     bridge/port on its segment.",
        },
        Always,
        Command::ShowSpanningTree),
    cmd!(["show" "spanning-tree" "instance" (id: Number)],
        Doc::Local {
            summary: "Show one spanning-tree instance of the MST region.",
            detail: "Queries nos-stpd for instance <id> (0 is the CIST): the VLANs and broadcast \
                     domains mapped to it, this bridge's id in the instance, its root and root \
                     port, and every port's role and state in it. A port whose peer is outside \
                     the region is a boundary port and follows the CIST. Only in 'spanning-tree \
                     mode mstp'.",
        },
        Always,
        |id| Command::ShowSpanningTreeInstance {
            id: id.parse().ok()?,
        }),
    cmd!(["show" "spanning-tree" "mst-config"],
        Doc::Local {
            summary: "Show the MST region identity and the instance to VLAN map.",
            detail: "Queries nos-stpd for the MST region name, revision and configuration \
                     digest (the value a peer must match to share MSTIs with this bridge), and \
                     the VLANs and broadcast domains of every instance. The VLAN of a domain is \
                     its dot1q tag (VLAN 1 when it is only untagged). Only in 'spanning-tree \
                     mode mstp'.",
        },
        Always,
        Command::ShowSpanningTreeMstConfig),
    cmd!(["show" "spanning-tree" "domain" (domain: BroadcastDomainName)],
        Doc::Local {
            summary: "Show one broadcast domain's Rapid-PVST+ tree.",
            detail: "Queries nos-stpd for the spanning tree of the domain's VLAN: this bridge's \
                     id in the tree (priority plus VLAN), its root and root port, and every \
                     member port's role and state. A port marked 'PVID-inconsistent' received a \
                     BPDU for another VLAN and is blocked in this tree; 'Compat' means its peer \
                     speaks plain PVST+ (802.1D) in this VLAN. Only in 'spanning-tree mode \
                     rapid-pvst'.",
        },
        Always,
        |domain| Command::ShowSpanningTreeDomain {
            domain: domain.to_string(),
        }),
    cmd!(["show" "spanning-tree" "detail"],
        Doc::Local {
            summary: "Show the spanning tree with topology changes and per-port counters.",
            detail: "Like show spanning-tree, plus when and where the last topology change \
                     came from and, per port, the operational edge and point-to-point status \
                     and the RFC 4318 counters: BPDUs received and sent by kind (config, tcn, \
                     rstp, mst), topology-change flags, protocol migrations, invalid BPDUs and \
                     forward transitions. In 'spanning-tree mode rapid-pvst' every tree is \
                     listed.",
        },
        Always,
        Command::ShowSpanningTreeDetail { instance: None, domain: None }),
    cmd!(["show" "spanning-tree" "instance" (id: Number) "detail"],
        Doc::Local {
            summary: "Show one MST instance with topology changes and per-port counters.",
            detail: "Like show spanning-tree instance, plus the instance's topology changes \
                     and every port's operational status and counters (the counters are the \
                     port's, shared by every instance). Only in 'spanning-tree mode mstp'.",
        },
        Always,
        |id| Command::ShowSpanningTreeDetail {
            instance: Some(id.parse().ok()?),
            domain: None,
        }),
    cmd!(["show" "spanning-tree" "domain" (domain: BroadcastDomainName) "detail"],
        Doc::Local {
            summary: "Show one Rapid-PVST+ tree with topology changes and per-port counters.",
            detail: "Like show spanning-tree domain, plus the tree's topology changes and \
                     every member port's operational status and counters in this VLAN's tree. \
                     Only in 'spanning-tree mode rapid-pvst'.",
        },
        Always,
        |domain| Command::ShowSpanningTreeDetail {
            instance: None,
            domain: Some(domain.to_string()),
        }),
    cmd!(["show" "bfd" "sessions"],
        Doc::Local {
            summary: "Show every BFD session.",
            detail: "Queries nos-bfdd (resolved via nos-watchdogd) for every BFD session (RFC \
                     5880) it holds, one line each: routing table, peer, state and diagnostic, \
                     the negotiated transmit interval and the detection time. A session is \
                     identified by its routing table and peer address.",
        },
        Always,
        Command::ShowBfdSessions { peer: None, detail: false }),
    cmd!(["show" "bfd" "sessions" "detail"],
        Doc::Local {
            summary: "Show every BFD session in full, one block each.",
            detail: "Like show bfd sessions, plus per session: the uptime since the last Up, \
                     the time since the last state change, how often it went down, the \
                     Control packets sent and received (received counts only those accepted \
                     after authentication), the peer's advertised min-rx, min-tx and \
                     detect multiplier, and the clients (protocols) that own the session. \
                     Counters restart with the session.",
        },
        Always,
        Command::ShowBfdSessions { peer: None, detail: true }),
    cmd!(["show" "bfd" "sessions" (peer: IpAddr)],
        Doc::Local {
            summary: "Show the BFD sessions to one peer address.",
            detail: "Like show bfd sessions, restricted by nos-bfdd to the sessions whose remote \
                     address is the given one (one per routing table).",
        },
        Always,
        |peer| Command::ShowBfdSessions {
            peer: Some(peer.parse().ok()?),
            detail: false,
        }),
    cmd!(["show" "bfd" "sessions" (peer: IpAddr) "detail"],
        Doc::Local {
            summary: "Show the BFD sessions to one peer address in full.",
            detail: "Like show bfd sessions detail, restricted by nos-bfdd to the sessions \
                     whose remote address is the given one (one per routing table).",
        },
        Always,
        |peer| Command::ShowBfdSessions {
            peer: Some(peer.parse().ok()?),
            detail: true,
        }),
    cmd!(["show" "bfd" "reflector"],
        Doc::Local {
            summary: "Show the S-BFD reflector.",
            detail: "Queries nos-bfdd (resolved via nos-watchdogd) for the Seamless BFD reflector \
                     (RFC 7880): the discriminators it answers for, how many probes it received \
                     and answered, and how many it dropped per reason.",
        },
        Always,
        Command::ShowBfdReflector),
    cmd!(["show" "lacp"],
        Doc::Local {
            summary: "Show every LACP port aggregate's negotiation state.",
            detail: "Queries nos-lacpd (resolved via nos-watchdogd) for every lacp-mode port \
                     aggregate's actor system id, key and rate, and each member port's \
                     receive/mux machine state, partner identity, and whether it is selected \
                     and synchronized.",
        },
        Always,
        Command::ShowLacp { name: None }),
    cmd!(["show" "lacp" (name: PortAggregateName)],
        Doc::Local {
            summary: "Show one LACP port aggregate's negotiation state.",
            detail: "Queries nos-lacpd (resolved via nos-watchdogd) for the named lacp-mode \
                     port aggregate's actor identity and rate, and each member port's \
                     receive/mux machine state and partner identity.",
        },
        Always,
        |name| Command::ShowLacp {
            name: Some(name.to_string()),
        }),
    cmd!(["show" "interface"],
        Doc::Local {
            summary: "Show every interface's link state and reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for every configured \
                     interface: admin/oper state, last change, speed, MTU, addresses, \
                     routing table and subinterfaces, one block per interface.",
        },
        Always,
        Command::ShowInterface { name: None }),
    cmd!(["show" "interface" "brief"],
        Doc::Local {
            summary: "Show a one-line-per-interface table: state, speed, MTU, VRF, addresses.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for every interface, \
                     tagged subinterface and port aggregate: admin and oper state, speed, MTU, \
                     routing table, port-aggregate membership and addresses. An interface \
                     literally named `brief` is only reachable over REST.",
        },
        Always,
        Command::ShowInterfaceBrief),
    cmd!(["show" "interface" (name: InterfaceName)],
        Doc::Local {
            summary: "Show one interface's link state and reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for the named \
                     interface: admin/oper state, last change, speed, MTU, addresses, \
                     routing table and subinterfaces.",
        },
        Always,
        |name| Command::ShowInterface {
            name: Some(name.to_string()),
        }),
    cmd!(["show" "log" [(source: LogSource)] ["last" (n: Number)] ["level" (l: LogLevel)] ["--follow"] ["match" (text: Rest)]],
        Doc::FromConfig(Topic::ShowLog),
        Always,
        |source, last, level, follow, text| Command::ShowLog {
            source: (!source.is_empty()).then(|| source.to_string()),
            follow: !follow.is_empty(),
            last: if last.is_empty() { None } else { Some(last.parse().ok()?) },
            level: if level.is_empty() { None } else { Some(parse_log_level(level)?) },
            needle: if text.is_empty() { None } else { Some(text.to_string()) },
        }),
    cmd!(["show" "bgp" "summary"],
        Doc::Local {
            summary: "Show a one-line-per-peer BGP session summary, per instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for its peers' current session: Neighbor, AS, Remote-Id, \
                     State, Status (Admin-Shutdown, Max-Prefix, Gr-Stale), Up/Down, Hold, \
                     Keepalive, Peer-group and the accepted prefixes per family (PfxRcd). \
                     An instance whose nos-bgpd isn't running is reported individually \
                     rather than aborting the whole command; TCP-AO counters and graceful \
                     restart state are in `| json`.",
        },
        Always,
        Command::ShowBgpSummary { instance: None }),
    cmd!(["show" "bgp" "summary" "instance" (name: Plain)],
        Doc::Local {
            summary: "Show the BGP session summary of one instance.",
            detail: "Same as show bgp summary, restricted to the instance <name>.",
        },
        Always,
        |name| Command::ShowBgpSummary { instance: Some(name.to_string()) }),
    cmd!(["show" "bgp" "brief"],
        Doc::Local {
            summary: "The old name of show bgp summary.",
            detail: "Same as show bgp summary.",
        },
        Always,
        Command::ShowBgpSummary { instance: None }),
    cmd!(["show" "bgp" "evpn"],
        Doc::Local {
            summary: "Show every EVPN route received from BGP peers, across every instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for the EVPN (AFI 25 / SAFI 70) routes its peers sent: \
                     route type, NLRI, next-hop and extended communities (Route Targets, \
                     Encapsulation). Only peers whose peer-group has `address-family \
                     l2vpn-evpn` exchange them. An instance whose nos-bgpd isn't running is \
                     reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowBgpEvpn),
    cmd!(["show" "bgp" "flowspec"],
        Doc::Local {
            summary: "Show every Flowspec rule received from BGP peers, across every instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for the Flowspec (RFC 8955/8956, SAFI 133) rules its peers \
                     sent: peer, the rule's components and extended communities (the actions). \
                     Only peers whose peer-group has `address-family ipv4-flowspec` or \
                     `ipv6-flowspec` exchange them; the VPN Flowspec (SAFI 134) rules are shown \
                     with `family` or `vrf`. An instance whose nos-bgpd isn't running is \
                     reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowBgpFlowspec { family: None, vrf: None }),
    cmd!(["show" "bgp" "flowspec" "family" "ipv4-flowspec"],
        Doc::Local {
            summary: "Show the ipv4-flowspec rules received from BGP peers.",
            detail: "Same as show bgp flowspec, restricted to the ipv4-flowspec family. A VPN \
                     Flowspec (SAFI 134) rule shows its Route Distinguisher and its validity in \
                     each VRF that imports it (`-` when it is imported nowhere).",
        },
        Always,
        Command::ShowBgpFlowspec { family: Some(nos_proto::AddressFamily::Ipv4Flowspec), vrf: None }),
    cmd!(["show" "bgp" "flowspec" "family" "ipv6-flowspec"],
        Doc::Local {
            summary: "Show the ipv6-flowspec rules received from BGP peers.",
            detail: "Same as show bgp flowspec, restricted to the ipv6-flowspec family. A VPN \
                     Flowspec (SAFI 134) rule shows its Route Distinguisher and its validity in \
                     each VRF that imports it (`-` when it is imported nowhere).",
        },
        Always,
        Command::ShowBgpFlowspec { family: Some(nos_proto::AddressFamily::Ipv6Flowspec), vrf: None }),
    cmd!(["show" "bgp" "flowspec" "family" "vpnv4-flowspec"],
        Doc::Local {
            summary: "Show the vpnv4-flowspec rules received from BGP peers.",
            detail: "Same as show bgp flowspec, restricted to the vpnv4-flowspec family. A VPN \
                     Flowspec (SAFI 134) rule shows its Route Distinguisher and its validity in \
                     each VRF that imports it (`-` when it is imported nowhere).",
        },
        Always,
        Command::ShowBgpFlowspec { family: Some(nos_proto::AddressFamily::Vpnv4Flowspec), vrf: None }),
    cmd!(["show" "bgp" "flowspec" "family" "vpnv6-flowspec"],
        Doc::Local {
            summary: "Show the vpnv6-flowspec rules received from BGP peers.",
            detail: "Same as show bgp flowspec, restricted to the vpnv6-flowspec family. A VPN \
                     Flowspec (SAFI 134) rule shows its Route Distinguisher and its validity in \
                     each VRF that imports it (`-` when it is imported nowhere).",
        },
        Always,
        Command::ShowBgpFlowspec { family: Some(nos_proto::AddressFamily::Vpnv6Flowspec), vrf: None }),
    cmd!(["show" "bgp" "flowspec" "vrf" (table: Plain)],
        Doc::Local {
            summary: "Show the VPN Flowspec rules imported into one VRF.",
            detail: "The VPN Flowspec (SAFI 134) rules whose Route Targets match <table>'s \
                     import set, with their validity in that VRF (RFC 8955 section 6, against \
                     the VPN routes the VRF imports). A rule with no matching Route Target is \
                     in no VRF view.",
        },
        Always,
        |table| Command::ShowBgpFlowspec { family: None, vrf: Some(table.to_string()) }),
    cmd!(["show" "bgp" "rpki"],
        Doc::Local {
            summary: "Show every BGP instance's RPKI cache sessions (RFC 8210).",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for its rpki-cache sessions: state, whether the cache's \
                     VRPs are the ones in use, RTR version, session id, serial, VRP count and \
                     the time since its last End of Data. An instance whose nos-bgpd isn't \
                     running is reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowBgpRpki),
    cmd!(["show" "bgp" "bmp"],
        Doc::Local {
            summary: "Show every BGP instance's BMP station connections (RFC 7854).",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for its bmp-stations: connection state (connecting, \
                     connected, backoff), the monitored policy view, statistics interval, \
                     monitored peers, messages sent by type, queue overflows, reconnect \
                     attempts and the last error. An instance whose nos-bgpd isn't running \
                     is reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowBgpBmp),
    cmd!(["show" "bgp" "routes"],
        Doc::Local {
            summary: "Show every BGP instance's IPv4/IPv6 unicast routes with their RPKI validation state.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for the routes it holds: prefix, advertising peer (or \
                     `local` for a redistributed route), next-hop, AS path, origin AS, \
                     LOCAL_PREF and the RFC 6811 origin validation state (valid, invalid, \
                     not-found). `>` marks the best path. A route an import policy rejected, \
                     including via `rpki-reject-invalid`, is not held and not shown. An \
                     instance whose nos-bgpd isn't running is reported individually rather \
                     than aborting the whole command.",
        },
        Always,
        Command::ShowBgpRoutes),
    cmd!(["show" "bgp" "vpnv4"],
        Doc::Local {
            summary: "Show every vpnv4 route received from BGP peers, across every instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for the VPN-IPv4 (RFC 4364, AFI 1 / SAFI 128) paths its peers sent, one line \
                     each: `>` for the best path of its (RD, prefix), RD, prefix, label stack, \
                     next hop (the egress PE), peer and Route Targets. Every path is held \
                     whatever its Route Targets. Only peers whose peer-group has \
                     `address-family vpnv4` exchange them. An instance whose nos-bgpd isn't \
                     running is reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowBgpVpn {
            family: nos_proto::AddressFamily::Vpnv4Unicast,
            rd: None,
        }),
    cmd!(["show" "bgp" "vpnv4" "rd" (rd: Plain)],
        Doc::Local {
            summary: "Show the vpnv4 routes of one Route Distinguisher.",
            detail: "Same as show bgp vpnv4, for the paths whose Route Distinguisher is <rd> \
                     (`65001:1`, `192.0.2.1:7`, `4200000000:9`).",
        },
        Always,
        |rd| Command::ShowBgpVpn {
            family: nos_proto::AddressFamily::Vpnv4Unicast,
            rd: Some(rd.to_string()),
        }),
    cmd!(["show" "bgp" "vpnv6"],
        Doc::Local {
            summary: "Show every vpnv6 route received from BGP peers, across every instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for the VPN-IPv6 (RFC 4659, AFI 2 / SAFI 128) paths its peers sent, one line \
                     each: `>` for the best path of its (RD, prefix), RD, prefix, label stack, \
                     next hop (the egress PE), peer and Route Targets. Every path is held \
                     whatever its Route Targets. Only peers whose peer-group has \
                     `address-family vpnv6` exchange them. An instance whose nos-bgpd isn't \
                     running is reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowBgpVpn {
            family: nos_proto::AddressFamily::Vpnv6Unicast,
            rd: None,
        }),
    cmd!(["show" "bgp" "vpnv6" "rd" (rd: Plain)],
        Doc::Local {
            summary: "Show the vpnv6 routes of one Route Distinguisher.",
            detail: "Same as show bgp vpnv6, for the paths whose Route Distinguisher is <rd> \
                     (`65001:1`, `192.0.2.1:7`, `4200000000:9`).",
        },
        Always,
        |rd| Command::ShowBgpVpn {
            family: nos_proto::AddressFamily::Vpnv6Unicast,
            rd: Some(rd.to_string()),
        }),
    cmd!(["show" "ospf" "neigh"],
        OSPF_NEIGH_DOC,
        Always,
        Command::ShowOspfNeigh),
    cmd!(["show" "ospf" "neighbor"], OSPF_NEIGH_DOC, Always, Command::ShowOspfNeigh),
    cmd!(["show" "ospf" "neighbors"], OSPF_NEIGH_DOC, Always, Command::ShowOspfNeigh),
    cmd!(["show" "ospf" "interface"], OSPF_IF_DOC, Always, Command::ShowOspfInterface),
    cmd!(["show" "ospf" "interfaces"], OSPF_IF_DOC, Always, Command::ShowOspfInterface),
    cmd!(["show" "ospf" "database"],
        OSPF_DB_DOC,
        Always,
        Command::ShowOspfDatabase { lsa_type: None, adv_router: None }),
    cmd!(["show" "ospf" "database" (type: Plain)],
        OSPF_DB_DOC,
        Always,
        |t| Command::ShowOspfDatabase { lsa_type: Some(t.to_string()), adv_router: None }),
    cmd!(["show" "ospf" "database" (type: Plain) (adv_router: IpAddr)],
        OSPF_DB_DOC,
        Always,
        |t, r| Command::ShowOspfDatabase {
            lsa_type: Some(t.to_string()),
            adv_router: Some(r.to_string()),
        }),
    cmd!(["show" "ospf" "segment-routing"],
        Doc::Local {
            summary: "Show OSPF segment routing: SRGBs, Prefix-SIDs and Adj-SIDs.",
            detail: "Queries every configured OSPF instance's nos-ospfd for the segment routing \
                     state in its LSDB, ours and every other router's: SRGB ranges, Prefix-SIDs \
                     (index and label) and Adj-SIDs (label per adjacency, the neighbour for a \
                     LAN Adj-SID).",
        },
        Always,
        Command::ShowOspfSegmentRouting),
    cmd!(["show" "ospfv3" "neigh"],
        OSPFV3_NEIGH_DOC,
        Always,
        Command::ShowOspfv3Neigh),
    cmd!(["show" "ospfv3" "neighbor"], OSPFV3_NEIGH_DOC, Always, Command::ShowOspfv3Neigh),
    cmd!(["show" "ospfv3" "neighbors"], OSPFV3_NEIGH_DOC, Always, Command::ShowOspfv3Neigh),
    cmd!(["show" "ospfv3" "interface"], OSPFV3_IF_DOC, Always, Command::ShowOspfv3Interface),
    cmd!(["show" "ospfv3" "interfaces"], OSPFV3_IF_DOC, Always, Command::ShowOspfv3Interface),
    cmd!(["show" "ospfv3" "database"],
        OSPFV3_DB_DOC,
        Always,
        Command::ShowOspfv3Database { lsa_type: None, adv_router: None }),
    cmd!(["show" "ospfv3" "database" (type: Plain)],
        OSPFV3_DB_DOC,
        Always,
        |t| Command::ShowOspfv3Database { lsa_type: Some(t.to_string()), adv_router: None }),
    cmd!(["show" "ospfv3" "database" (type: Plain) (adv_router: IpAddr)],
        OSPFV3_DB_DOC,
        Always,
        |t, r| Command::ShowOspfv3Database {
            lsa_type: Some(t.to_string()),
            adv_router: Some(r.to_string()),
        }),
    cmd!(["clear" "spanning-tree" "detected-protocols"],
        Doc::Local {
            summary: "Re-probe every spanning-tree port for RSTP (802.1Q mcheck).",
            detail: "A port that heard an 802.1D STP BPDU falls back to STP and stays there. \
                     This sends it back to RSTP on every port; a port whose peer still speaks \
                     STP migrates again after Migrate Time (3 s).",
        },
        Always,
        Command::ClearStpMcheck { interface: None }),
    cmd!(["clear" "spanning-tree" "detected-protocols" "interface" (name: InterfaceName)],
        Doc::Local {
            summary: "Re-probe one spanning-tree port for RSTP (802.1Q mcheck).",
            detail: "Like 'clear spanning-tree detected-protocols', for <name> only. Reported \
                     as an error if <name> is not a spanning-tree port.",
        },
        Always,
        |name| Command::ClearStpMcheck {
            interface: Some(name.to_string()),
        }),
    cmd!(["clear" "spanning-tree" "err-disabled" (name: InterfaceName)],
        Doc::Local {
            summary: "Bring a port that BPDU guard shut down back up.",
            detail: "Lifts the err-disabled state of <name> at once, instead of waiting for its \
                     'bpdu-guard-recovery' timer. If the cause is still there (a BPDU arrives \
                     on the edge port again) the port is err-disabled again. Reported as an \
                     error if <name> is not err-disabled.",
        },
        Always,
        |name| Command::ClearStpErrDisabled {
            interface: name.to_string(),
        }),
    cmd!(["clear" "bgp" (instance: BgpInstanceName) (peer: IpAddr) "soft-in"],
        Doc::Local {
            summary: "Ask a peer to resend its routes (RFC 2918 route refresh).",
            detail: "Sends a BGP ROUTE_REFRESH message to <peer> over its current session on \
                     <instance>'s nos-bgpd, asking it to re-advertise its full Adj-RIB-Out for \
                     every address family this session negotiated. Reported as an error if \
                     <instance> has no established session with <peer> right now.",
        },
        Always,
        |instance, peer| Command::ClearBgpSoftIn {
            instance: instance.to_string(),
            peer: peer.parse().ok()?,
        }),
    cmd!(["clear" "bgp" (instance: BgpInstanceName) (peer: IpAddr)],
        Doc::FromConfig(Topic::BgpClearPeer),
        Always,
        |instance, peer| Command::ClearBgpPeer {
            instance: instance.to_string(),
            peer: peer.parse().ok()?,
        }),
];

/// One whitespace-delimited token of `line`, with its start byte offset.
pub(crate) fn tokenize_with_offsets(line: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, ch) in line.char_indices() {
        if ch.is_whitespace() {
            if let Some(s) = start.take() {
                out.push((s, &line[s..i]));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        out.push((s, &line[s..]));
    }
    out
}

/// Where a row's walk over the typed words ended (see `walk`).
#[derive(Debug)]
pub struct Walk<'a> {
    /// Argument words in `build` order; an absent optional clause is `""`.
    pub args: Vec<&'a str>,
    /// What may come at the next position (Tab and `?`).
    pub next: Vec<Token>,
    /// Every required token is bound and no clause awaits its argument.
    pub complete: bool,
}

/// The one matcher behind `parse` and Tab: walks `words` (with their offsets
/// in `line`) over a row's fixed tokens, then its trailing `Opt` clauses —
/// the source `Arg` clause first (only as the first tail word), keyword
/// clauses in any order, each once. `None`: the words do not fit the row.
pub fn walk<'a>(spec: &CommandSpec, line: &'a str, words: &[(usize, &'a str)]) -> Option<Walk<'a>> {
    // Everything after the one separator that follows the previous word, so
    // leading whitespace survives.
    let rest_from = |j: usize| {
        let (start, prev) = words[j - 1];
        let mut rest = line[start + prev.len()..].chars();
        rest.next();
        rest.as_str()
    };
    let fixed = spec
        .tokens
        .iter()
        .position(|t| matches!(t, Token::Opt(_)))
        .unwrap_or(spec.tokens.len());
    let mut args = Vec::new();
    for (j, token) in spec.tokens[..fixed].iter().enumerate() {
        let Some(&(_, word)) = words.get(j) else {
            return Some(Walk {
                args,
                next: vec![*token],
                complete: false,
            });
        };
        match token {
            Token::Literal(lit) if *lit == word => {}
            Token::Literal(_) => return None,
            Token::Arg(ArgKind::Rest) => {
                args.push(rest_from(j));
                return Some(Walk {
                    args,
                    next: vec![],
                    complete: true,
                });
            }
            Token::Arg(_) => args.push(word),
            Token::Opt(_) => unreachable!("the fixed prefix has no Opt"),
        }
    }
    let clauses: Vec<&'static [Token]> = spec.tokens[fixed..]
        .iter()
        .map(|t| match t {
            Token::Opt(c) => *c,
            _ => unreachable!("Opt tokens are trailing"),
        })
        .collect();
    // One build slot per arg token, or one for a flag clause; "" if absent.
    let mut offsets = Vec::new();
    for c in &clauses {
        offsets.push(args.len());
        let n = c.iter().filter(|t| matches!(t, Token::Arg(_))).count();
        args.extend(std::iter::repeat_n("", n.max(1)));
    }
    let keyword = |c: &[Token]| match c[0] {
        Token::Literal(l) => Some(l),
        _ => None,
    };
    let mut used = vec![false; clauses.len()];
    let mut i = fixed;
    while let Some(&(_, word)) = words.get(i) {
        let c = match clauses.iter().position(|c| keyword(c) == Some(word)) {
            Some(c) if used[c] => return None,
            Some(c) => c,
            // The source is only ever the first tail word.
            None => match clauses.iter().position(|c| keyword(c).is_none()) {
                Some(c) if i == fixed => c,
                _ => return None,
            },
        };
        used[c] = true;
        let slot = offsets[c];
        i += 1;
        if keyword(clauses[c]).is_none() || clauses[c].len() == 1 {
            args[slot] = word;
            continue;
        }
        for (k, tok) in clauses[c][1..].iter().enumerate() {
            let Some(&(_, w)) = words.get(i) else {
                return Some(Walk {
                    args,
                    next: vec![*tok],
                    complete: false,
                });
            };
            if matches!(tok, Token::Arg(ArgKind::Rest)) {
                args[slot + k] = rest_from(i);
                return Some(Walk {
                    args,
                    next: vec![],
                    complete: true,
                });
            }
            args[slot + k] = w;
            i += 1;
        }
    }
    let typed_tail = i > fixed;
    let next = clauses
        .iter()
        .zip(&used)
        .filter(|(c, u)| !**u && (keyword(c).is_some() || !typed_tail))
        .map(|(c, _)| c[0])
        .collect();
    Some(Walk {
        args,
        next,
        complete: true,
    })
}

/// Parses `line` against the `cmd!` rows: the index of the first row whose
/// token shape fits, and what its `build` made of the argument words
/// (`None` — an argument that doesn't parse — is final, never a reason to
/// try a later row). `None` when no row fits.
pub fn parse(line: &str) -> Option<(usize, Option<Command>)> {
    let words = tokenize_with_offsets(line);
    COMMAND_SPECS.iter().enumerate().find_map(|(i, spec)| {
        let w = walk(spec, line, &words)?;
        w.complete.then(|| (i, (spec.build)(&w.args)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Path;

    fn config_mode(path: &[&str]) -> Mode {
        Mode::Configuration {
            transaction: "t1".to_string(),
            path: Path::from(path.iter().map(ToString::to_string).collect::<Vec<_>>()),
            dirty: false,
        }
    }

    #[test]
    fn availability_follows_mode_and_position() {
        let root = config_mode(&[]);
        let policy = config_mode(&["policy-definition", "p1"]);
        assert!(availability_matches(
            Availability::Always,
            &Mode::Operational
        ));
        assert!(availability_matches(
            Availability::Operational,
            &Mode::Operational
        ));
        assert!(!availability_matches(
            Availability::Configuration,
            &Mode::Operational
        ));
        assert!(!availability_matches(Availability::Operational, &root));
        assert!(availability_matches(Availability::Configuration, &root));
        assert!(!availability_matches(
            Availability::ConfigurationNested,
            &root
        ));
        assert!(availability_matches(
            Availability::ConfigurationNested,
            &policy
        ));
        assert!(!availability_matches(
            Availability::ConfigurationPolicyDefinition,
            &root
        ));
        assert!(availability_matches(
            Availability::ConfigurationPolicyDefinition,
            &policy
        ));
    }

    fn sample(t: &Token, out: &mut Vec<&'static str>) {
        match t {
            Token::Literal(lit) => out.push(lit),
            Token::Arg(ArgKind::IpAddr) => out.push("192.0.2.1"),
            Token::Arg(ArgKind::Number) => out.push("1"),
            Token::Arg(ArgKind::Rest) => out.push("  some text"),
            Token::Arg(ArgKind::LogLevel) => out.push("info"),
            Token::Arg(_) => out.push("sample"),
            Token::Opt(clause) => clause.iter().for_each(|t| sample(t, out)),
        }
    }

    /// Every `cmd!` row, filled with a sample word per argument, parses back
    /// through `parse` to a command built by that same row — so no row is
    /// shadowed by an earlier one, and each `build` binds as many words as
    /// the row has argument slots. Once without, once with every optional
    /// clause.
    #[test]
    fn every_cmd_row_round_trips() {
        for (i, spec) in COMMAND_SPECS.iter().enumerate() {
            for with_opt in [false, true] {
                let mut words = Vec::new();
                for t in spec
                    .tokens
                    .iter()
                    .filter(|t| with_opt || !matches!(t, Token::Opt(_)))
                {
                    sample(t, &mut words);
                }
                let line = words.join(" ");
                match parse(&line) {
                    Some((j, Some(_))) if j == i => {}
                    other => panic!("{:?} ({line:?}) parsed to {other:?}", spec.usage),
                }
            }
        }
    }

    #[test]
    fn opt_tokens_are_trailing() {
        for spec in COMMAND_SPECS {
            if let Some(first) = spec.tokens.iter().position(|t| matches!(t, Token::Opt(_))) {
                assert!(
                    spec.tokens[first..]
                        .iter()
                        .all(|t| matches!(t, Token::Opt(_))),
                    "{}: Opt not trailing",
                    spec.usage
                );
            }
        }
    }

    /// The final `show log` grammar (#1412), proven on a fixture: the real
    /// row only has `[<source>] [--follow]` until #1452.
    const FIXTURE: CommandSpec = CommandSpec {
        tokens: &[
            tok!("show"),
            tok!("log"),
            tok!([(source: LogSource)]),
            tok!(["last" (n: Number)]),
            tok!(["level" (l: LogLevel)]),
            tok!(["--follow"]),
            tok!(["match" (text: Rest)]),
        ],
        usage: concat!(
            "show log ",
            usage_tok!([(source: LogSource)]),
            " ",
            usage_tok!(["last" (n: Number)]),
            " ",
            usage_tok!(["level" (l: LogLevel)]),
            " ",
            usage_tok!(["--follow"]),
            " ",
            usage_tok!(["match" (text: Rest)])
        ),
        doc: Doc::Local {
            summary: "",
            detail: "",
        },
        availability: Availability::Always,
        build: |_| None,
    };

    fn fixture(line: &str) -> Option<Walk<'_>> {
        walk(&FIXTURE, line, &tokenize_with_offsets(line))
    }

    #[test]
    fn fixture_usage_is_generated() {
        assert_eq!(
            FIXTURE.usage,
            "show log [<source>] [last <n>] [level <l>] [--follow] [match <text>]"
        );
    }

    #[test]
    fn fixture_accepts_every_subset_and_order_of_the_simple_clauses() {
        // (words, build slot, bound value)
        let clauses = [
            ("last 5", 1, "5"),
            ("level warn", 2, "warn"),
            ("--follow", 3, "--follow"),
        ];
        let orders = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        for order in orders {
            for mask in 0..8u8 {
                let chosen: Vec<usize> = order.into_iter().filter(|b| mask >> b & 1 == 1).collect();
                for source in [false, true] {
                    let mut line = "show log".to_string();
                    if source {
                        line.push_str(" nos-ribd");
                    }
                    for &b in &chosen {
                        line.push(' ');
                        line.push_str(clauses[b].0);
                    }
                    let w = fixture(&line).unwrap_or_else(|| panic!("{line:?} did not fit"));
                    assert!(w.complete, "{line:?}");
                    assert_eq!(w.args[0], if source { "nos-ribd" } else { "" }, "{line:?}");
                    for (b, (_, slot, want)) in clauses.iter().enumerate() {
                        let present = chosen.contains(&b);
                        assert_eq!(
                            w.args[*slot],
                            [*want, ""][usize::from(!present)],
                            "{line:?}"
                        );
                    }
                    assert_eq!(w.args[4], "");
                }
            }
        }
    }

    #[test]
    fn fixture_match_is_last_verbatim_and_swallows_clause_words() {
        let w = fixture("show log nos-x last 3 match   a  --follow  b").unwrap();
        assert_eq!(w.args[4], "  a  --follow  b");
        assert_eq!(w.args[3], "");
        assert!(w.next.is_empty() && w.complete);
    }

    #[test]
    fn fixture_rejects_misplaced_and_repeated_clauses() {
        assert!(fixture("show log --follow --follow").is_none());
        assert!(fixture("show log last 1 last 2").is_none());
        assert!(fixture("show log last 1 nos-x").is_none());
        assert!(fixture("show log --follow nos-x").is_none());
        assert!(fixture("show log nos-x nos-y").is_none());
        // a missing clause argument leaves the row incomplete
        assert!(!fixture("show log last").unwrap().complete);
        assert!(!fixture("show log match").unwrap().complete);
        // a malformed one is left to `build`
        assert_eq!(fixture("show log last x").unwrap().args[1], "x");
    }

    #[test]
    fn fixture_next_offers_only_what_is_still_valid() {
        let next = |line| fixture(line).unwrap().next;
        let n = next("show log ");
        assert_eq!(n.len(), 5);
        assert!(n.contains(&Token::Arg(ArgKind::LogSource)));
        assert_eq!(
            next("show log nos-x last 2 "),
            vec![
                Token::Literal("level"),
                Token::Literal("--follow"),
                Token::Literal("match")
            ]
        );
        assert_eq!(next("show log level "), vec![Token::Arg(ArgKind::LogLevel)]);
        assert_eq!(next("show log last "), vec![Token::Arg(ArgKind::Number)]);
        assert_eq!(next("show log match x"), Vec::<Token>::new());
        assert_eq!(
            next("show log nos-x last 1 level info --follow "),
            vec![Token::Literal("match")]
        );
    }

    #[test]
    fn log_level_values_match_the_wire_enum() {
        let want: Vec<String> = [
            nos_proto::LogLevel::Trace,
            nos_proto::LogLevel::Debug,
            nos_proto::LogLevel::Info,
            nos_proto::LogLevel::Warn,
            nos_proto::LogLevel::Error,
        ]
        .iter()
        .map(|l| format!("{l:?}").to_lowercase())
        .collect();
        assert_eq!(ArgKind::LogLevel.fixed_values().unwrap(), want);
    }

    #[test]
    fn cmd_usage_is_generated_from_tokens() {
        let usages: Vec<_> = COMMAND_SPECS.iter().map(|s| s.usage).collect();
        assert!(usages.contains(&"show route <table> <address>"));
        assert!(usages.contains(&"clear bgp <instance> <peer> soft-in"));
        assert!(usages.contains(&"clear bgp <instance> <peer>"));
        assert!(usages.contains(&"set source line <line> <text>"));
        assert!(usages
            .contains(&"show log [<source>] [last <n>] [level <l>] [--follow] [match <text>]"));
    }

    #[test]
    fn rest_keeps_leading_whitespace() {
        assert_eq!(
            Command::parse("set source line 2     accept"),
            Command::SetSourceLine {
                line: 2,
                text: "    accept".to_string(),
            }
        );
    }
}
