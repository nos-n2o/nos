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
}

/// A token's text in a generated usage string: the keyword, or `<name>`.
macro_rules! usage_tok {
    ($l:literal) => {
        $l
    };
    (($n:ident : $k:ident)) => {
        concat!("<", stringify!($n), ">")
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
            summary: "Edit the current policy's RPL source in $EDITOR.",
            detail: "Opens $EDITOR (else $VISUAL, else vim; the value may carry arguments) on the current \
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
        Command::ShowBfdSessions { peer: None }),
    cmd!(["show" "bfd" "sessions" (peer: IpAddr)],
        Doc::Local {
            summary: "Show the BFD sessions to one peer address.",
            detail: "Like show bfd sessions, restricted by nos-bfdd to the sessions whose remote \
                     address is the given one (one per routing table).",
        },
        Always,
        |peer| Command::ShowBfdSessions {
            peer: Some(peer.parse().ok()?),
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
            summary: "Show every interface's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for every configured \
                     interface's addresses and routing-table assignment.",
        },
        Always,
        Command::ShowInterface { name: None }),
    cmd!(["show" "interface" (name: InterfaceName)],
        Doc::Local {
            summary: "Show one interface's reconciled status.",
            detail: "Queries nos-interfaced (resolved via nos-watchdogd) for the named \
                     interface's addresses and routing-table assignment.",
        },
        Always,
        |name| Command::ShowInterface {
            name: Some(name.to_string()),
        }),
    cmd!(["show" "log"],
        Doc::Local {
            summary: "Show the most recent collected log entries from every daemon.",
            detail: "Queries nos-logd (resolved via nos-watchdogd) for its current buffer of \
                     log entries pushed by every other component process.",
        },
        Always,
        Command::ShowLog {
            source: None,
            follow: false,
        }),
    cmd!(["show" "log" "--follow"],
        Doc::Local {
            summary: "Live-tail collected log entries from every daemon.",
            detail: "Prints the current buffer, then streams new entries as they're pushed to \
                     nos-logd until Ctrl-C is pressed or the connection is lost.",
        },
        Always,
        Command::ShowLog {
            source: None,
            follow: true,
        }),
    cmd!(["show" "log" (source: Plain)],
        Doc::Local {
            summary: "Show the most recent collected log entries from one source.",
            detail: "Same as `show log`, filtered to entries whose source exactly matches \
                     <source> (e.g. `nos-ribd[rt1]`, `nos-interfaced`, `nos-configd`).",
        },
        Always,
        |source| Command::ShowLog {
            source: Some(source.to_string()),
            follow: false,
        }),
    cmd!(["show" "log" (source: Plain) "--follow"],
        Doc::Local {
            summary: "Live-tail collected log entries from one source.",
            detail: "Same as `show log --follow`, filtered to entries whose source exactly \
                     matches <source>.",
        },
        Always,
        |source| Command::ShowLog {
            source: Some(source.to_string()),
            follow: true,
        }),
    cmd!(["show" "bgp" "brief"],
        Doc::Local {
            summary: "Show a one-line-per-peer BGP session summary across every instance.",
            detail: "Queries every configured BGP instance's nos-bgpd (each resolved via \
                     nos-watchdogd) for its peers' current session state, remote AS, uptime, \
                     and negotiated hold-time. An instance whose nos-bgpd isn't running is \
                     reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowBgpBrief),
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
                     `ipv6-flowspec` exchange them. Receive-only: rules are neither validated \
                     nor enforced. An instance whose nos-bgpd isn't running is reported \
                     individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowBgpFlowspec),
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
        Doc::Local {
            summary: "Show a one-line-per-neighbor OSPF adjacency summary across every instance.",
            detail: "Queries every configured OSPF instance's nos-ospfd (each resolved via \
                     nos-watchdogd) for its links' current neighbor state, interface state, \
                     last-hello age, and elected DR/BDR. An instance whose nos-ospfd isn't \
                     running is reported individually rather than aborting the whole command.",
        },
        Always,
        Command::ShowOspfNeigh),
    cmd!(["show" "ospf" "database"],
        Doc::Local {
            summary: "Show every installed LSA's header across every OSPF instance.",
            detail: "Queries every configured OSPF instance's nos-ospfd (each resolved via \
                     nos-watchdogd) for its per-area LSDB's installed LSA headers (type, \
                     link-state-id, advertising router, sequence number, age, checksum). An \
                     instance whose nos-ospfd isn't running is reported individually rather \
                     than aborting the whole command.",
        },
        Always,
        Command::ShowOspfDatabase),
    cmd!(["show" "ospfv3" "neigh"],
        Doc::Local {
            summary: "Show a one-line-per-neighbor OSPFv3 adjacency summary across every instance.",
            detail: "Mirrors 'show ospf neigh' for OSPFv3 (RFC 5340): queries every configured \
                     Ospfv3Instance's nos-ospfv3d (each resolved via nos-watchdogd) for its \
                     links' current neighbor state, interface state, last-hello age, and \
                     elected DR/BDR.",
        },
        Always,
        Command::ShowOspfv3Neigh),
    cmd!(["show" "ospfv3" "database"],
        Doc::Local {
            summary: "Show every installed LSA's header across every OSPFv3 instance.",
            detail: "Mirrors 'show ospf database' for OSPFv3 (RFC 5340).",
        },
        Always,
        Command::ShowOspfv3Database),
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

/// Parses `line` against the `cmd!` rows: the index of the first row whose
/// token shape fits, and what its `build` made of the argument words
/// (`None` — an argument that doesn't parse — is final, never a reason to
/// try a later row). `None` when no row fits.
pub fn parse(line: &str) -> Option<(usize, Option<Command>)> {
    let words = tokenize_with_offsets(line);
    COMMAND_SPECS.iter().enumerate().find_map(|(i, spec)| {
        let build = spec.build;
        let mut args = Vec::new();
        for (j, token) in spec.tokens.iter().enumerate() {
            let &(_, word) = words.get(j)?;
            match token {
                Token::Literal(lit) if *lit == word => {}
                Token::Literal(_) => return None,
                // Everything after the one separator that follows the
                // previous word, so leading whitespace survives.
                Token::Arg(ArgKind::Rest) => {
                    let (prev_start, prev) = words[j - 1];
                    let mut rest = line[prev_start + prev.len()..].chars();
                    rest.next();
                    args.push(rest.as_str());
                    return Some((i, build(&args)));
                }
                Token::Arg(_) => args.push(word),
            }
        }
        (words.len() == spec.tokens.len()).then(|| (i, build(&args)))
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

    /// Every `cmd!` row, filled with a sample word per argument, parses back
    /// through `parse` to a command built by that same row — so no row is
    /// shadowed by an earlier one, and each `build` binds as many words as
    /// the row has argument slots.
    #[test]
    fn every_cmd_row_round_trips() {
        for (i, spec) in COMMAND_SPECS.iter().enumerate() {
            let line = spec
                .tokens
                .iter()
                .map(|t| match t {
                    Token::Literal(lit) => *lit,
                    Token::Arg(ArgKind::IpAddr) => "192.0.2.1",
                    Token::Arg(ArgKind::Number) => "1",
                    Token::Arg(ArgKind::Rest) => "  some text",
                    Token::Arg(_) => "sample",
                })
                .collect::<Vec<_>>()
                .join(" ");
            match parse(&line) {
                Some((j, Some(_))) if j == i => {}
                other => panic!("{:?} ({line:?}) parsed to {other:?}", spec.usage),
            }
        }
    }

    #[test]
    fn cmd_usage_is_generated_from_tokens() {
        let usages: Vec<_> = COMMAND_SPECS.iter().map(|s| s.usage).collect();
        assert!(usages.contains(&"show route <table> <address>"));
        assert!(usages.contains(&"clear bgp <instance> <peer> soft-in"));
        assert!(usages.contains(&"clear bgp <instance> <peer>"));
        assert!(usages.contains(&"set source line <line> <text>"));
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
