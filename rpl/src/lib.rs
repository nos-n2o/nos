//! `nos-rpl` — the Routing Policy Language compiler and VM. Zero
//! NOS-internal dependencies, like `nos-tcp-auth`: it's a plain library
//! consumed by `nos-proto` (commit-time validation of `PolicyDefinition`
//! source) and `nos-bgp` (compiling, caching, and executing policies against
//! real routes). See `docs/architecture/rpl.md`
//! section for the language and architecture this implements.
#![warn(missing_docs)]

/// Parsed syntax tree (statements and expressions).
pub mod ast;
mod check;
mod codegen;
mod lexer;
mod parser;
pub mod schema;
mod symbols;
/// Bytecode, inputs, edits and the interpreter.
pub mod vm;

pub use symbols::{PrefixListEntry, Symbols};
pub use vm::{
    AsPathRegexes, BgpInput, CmpKind, CompiledPolicy, Edits, Input, NextHopSet, Op, Origin, Role,
    SegKind, Segment, ValidationState, Value, Verdict,
};

use std::fmt;
use std::sync::LazyLock;

/// A compile-time error with its 1-based source line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    /// 1-based source line of the error.
    pub line: usize,
    /// Human-readable description.
    pub message: String,
}

impl CompileError {
    pub(crate) fn new(line: usize, message: impl Into<String>) -> Self {
        CompileError {
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for CompileError {}

/// Longest accepted script source in bytes, enforced by [`compile`],
/// [`unconditional_next_hop`] and called-policy compilation.
pub const MAX_SOURCE_LEN: usize = 16 * 1024;

pub(crate) fn check_source_len(src: &str) -> Result<(), CompileError> {
    if src.len() > MAX_SOURCE_LEN {
        return Err(CompileError::new(
            1,
            format!("source longer than {MAX_SOURCE_LEN} bytes"),
        ));
    }
    Ok(())
}

/// Compiles RPL source into bytecode: lex -> parse -> termination/
/// reachability check -> type-checked codegen. Called both by
/// `nos-config` (commit-time validation of `PolicyDefinition.source`,
/// discarding the result) and `nos-bgp` (which caches and runs it).
/// `symbols` resolves any bare-identifier reference to a `community-alias`/
/// `community-group`/`prefix-list` object — pass `&Symbols::EMPTY` when none
/// are in scope.
pub fn compile(src: &str, symbols: &Symbols) -> Result<CompiledPolicy, CompileError> {
    check_source_len(src)?;
    let tokens = lexer::lex(src)?;
    let policy = parser::parse(&tokens)?;
    check::check_termination(&policy)?;
    codegen::compile(&policy, symbols)
}

/// The next-hop literal a policy sets on EVERY path, if any: the last
/// `set this.bgp.next_hop = <ip>` among the top-level statements before the
/// first `if` (`= self` clears it). Syntax only (no symbols needed). Anything
/// behind a condition is undecidable without path-sensitive prefix analysis
/// and is deliberately not reported; the BGP runtime guard covers it.
pub fn unconditional_next_hop(src: &str) -> Option<std::net::IpAddr> {
    use ast::{ExprKind, Postfix, StmtKind};
    check_source_len(src).ok()?;
    let policy = parser::parse(&lexer::lex(src).ok()?).ok()?;
    let mut found = None;
    for stmt in &policy {
        match &stmt.kind {
            StmtKind::If { .. } | StmtKind::Call(_) | StmtKind::Accept | StmtKind::Reject => break,
            StmtKind::Set(target, value) => {
                let ExprKind::This(path) = &target.kind else {
                    continue;
                };
                if !matches!(path.as_slice(), [Postfix::Field(a), Postfix::Field(b)] if a == "bgp" && b == "next_hop")
                {
                    continue;
                }
                found = match &value.kind {
                    ExprKind::IpLit(ip) => Some(*ip),
                    _ => None,
                };
            }
            _ => {}
        }
    }
    found
}

/// Parses a bare colon-separated community literal (`"65000:100"` ->
/// `Some(vec![65000, 100])`), the exact grammar `parse_atom` accepts inline
/// in a script for `.contains(..)`/`.add(..)`/`.remove(..)`. Returns `None`
/// if `s` isn't exactly that shape (extra tokens, wrong token kinds, empty)
/// — reuses the real lexer so this never drifts from the script grammar.
/// Used by `nos-proto` to validate a stored `CommunityAlias.value` (and a
/// `CommunityGroup` member that isn't an alias name) without duplicating
/// RPL's literal grammar. Arity (2 parts for standard, 3 for extended/large)
/// is intentionally not checked here — it's ambiguous until the value is
/// referenced from a specific field inside a script, exactly like an inline
/// `ColonLit` today.
pub fn parse_colon_literal(s: &str) -> Option<Vec<i64>> {
    let tokens = lexer::lex(s).ok()?;
    let mut iter = tokens.iter().map(|t| &t.token);
    let lexer::Token::Int(first) = iter.next()? else {
        return None;
    };
    let mut parts = vec![*first];
    loop {
        match iter.next()? {
            lexer::Token::Colon => {
                let lexer::Token::Int(n) = iter.next()? else {
                    return None;
                };
                parts.push(*n);
            }
            lexer::Token::Newline => break,
            _ => return None,
        }
    }
    matches!(iter.next(), Some(lexer::Token::Eof)).then_some(parts)
}

/// The two reserved system policies every consumer resolves the same way —
/// see root `CLAUDE.md`'s "Built-in system policies". Not stored as
/// `PolicyDefinition` config entries: nothing to edit, nothing to delete.
pub static ACCEPT_ALL: LazyLock<CompiledPolicy> =
    LazyLock::new(|| compile("accept\n", &Symbols::EMPTY).expect("accept-all must compile"));
/// Compiled `reject`: the deny-all system policy.
pub static DENY_ALL: LazyLock<CompiledPolicy> =
    LazyLock::new(|| compile("reject\n", &Symbols::EMPTY).expect("deny-all must compile"));

/// The two reserved policy names — see `ACCEPT_ALL`/`DENY_ALL`.
pub const ACCEPT_ALL_NAME: &str = "accept-all";
/// Reserved name of [`DENY_ALL`].
pub const DENY_ALL_NAME: &str = "deny-all";

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `f` on a deliberately small (2 MiB) stack: an unbounded
    /// recursion aborts the process instead of failing the assertion.
    fn small_stack(f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    fn compiles(src: &str) -> Result<(), CompileError> {
        compile(src, &Symbols::EMPTY).map(|_| ())
    }

    #[test]
    fn deep_nesting_is_rejected_not_overflowed() {
        small_stack(|| {
            let n = 10_000;
            let parens = format!(
                "if {}1 == 1{}:\n  accept\nelse:\n  reject\n",
                "(".repeat(n),
                ")".repeat(n)
            );
            let nots = format!(
                "if {}1 == 1:\n  accept\nelse:\n  reject\n",
                "not ".repeat(n)
            );
            let nest = |k: usize| {
                let mut ifs = String::new();
                for i in 0..k {
                    ifs.push_str(&"  ".repeat(i));
                    ifs.push_str("if 1 == 1:\n");
                }
                ifs
            };
            let ifs = nest(n);
            for src in [parens, nots] {
                assert!(compiles(&src).is_err());
            }
            assert!(compiles(&ifs).is_err());
            // Under the source cap too, so the depth check itself fires.
            let nots = format!(
                "if {}1 == 1:\n  accept\nelse:\n  reject\n",
                "not ".repeat(1000)
            );
            assert!(compiles(&nots).unwrap_err().message.contains("nesting"));
            let ifs = nest(100);
            assert!(compiles(&ifs).unwrap_err().message.contains("nesting"));
        });
    }

    #[test]
    fn long_left_chains_are_rejected_not_overflowed() {
        small_stack(|| {
            for (op, w) in [("or", "1 == 1"), ("and", "1 == 1"), ("+", "1")] {
                let sep = format!(" {op} ");
                let chain = vec![w; 1_000].join(&sep);
                let src = if op == "+" {
                    format!("set this.bgp.local_pref = {chain}\naccept\n")
                } else {
                    format!("if {chain}:\n  accept\nelse:\n  reject\n")
                };
                assert!(src.len() < MAX_SOURCE_LEN);
                assert!(
                    compiles(&src).unwrap_err().message.contains("nesting"),
                    "{op}"
                );
            }
        });
    }

    type Case<'a> = (&'a str, usize, Box<dyn Fn(usize) -> String>);

    /// For each construct, the largest `k` that compiles is exactly `max`
    /// (depth 64 compiles) and `max + 1` fails with the nesting error.
    #[test]
    fn depth_limit_is_exact_per_construct() {
        small_stack(|| {
            let cond = |c: String| format!("if {c}:\n  accept\nelse:\n  reject\n");
            let chain = |op: &str, n: usize| vec!["1 == 1"; n].join(&format!(" {op} "));
            let nest = |k: usize| {
                let mut src = String::new();
                for i in 0..k {
                    src.push_str(&"  ".repeat(i));
                    src.push_str("if 1 == 1:\n");
                }
                src.push_str(&"  ".repeat(k));
                src.push_str("accept\n");
                src.push_str("accept\n");
                src
            };
            let cases: Vec<Case> = vec![
                // `1 == 1` is depth 2, each `not`/paren adds 1.
                (
                    "not",
                    62,
                    Box::new(move |k| cond(format!("{}1 == 1", "not ".repeat(k)))),
                ),
                (
                    "parens",
                    62,
                    Box::new(move |k| {
                        format!(
                            "if {}1 == 1{}:\n  accept\nelse:\n  reject\n",
                            "(".repeat(k),
                            ")".repeat(k)
                        )
                    }),
                ),
                // k comparisons joined by `or`/`and`: depth k + 1.
                (
                    "or",
                    63,
                    Box::new(move |k| {
                        format!("if {}:\n  accept\nelse:\n  reject\n", chain("or", k))
                    }),
                ),
                (
                    "and",
                    63,
                    Box::new(move |k| {
                        format!("if {}:\n  accept\nelse:\n  reject\n", chain("and", k))
                    }),
                ),
                // k leaves joined by `+`: depth k.
                (
                    "+",
                    64,
                    Box::new(|k| {
                        format!(
                            "set this.bgp.local_pref = {}\naccept\n",
                            vec!["1"; k].join(" + ")
                        )
                    }),
                ),
                // k nested `if` suites: the innermost condition sits at nest k - 1 with depth 2.
                ("if", 63, Box::new(nest)),
            ];
            for (name, max, build) in cases {
                let r = compiles(&build(max));
                assert!(r.is_ok(), "{name} at {max}: {r:?}");
                let err = compiles(&build(max + 1)).unwrap_err();
                assert!(err.message.contains("nesting"), "{name} at {}", max + 1);
            }
            // Comparisons add no chain depth: `a == b` is one node.
            assert!(compiles(&cond("1 == 1".into())).is_ok());
        });
    }

    #[test]
    fn oversize_source_is_rejected() {
        let big = format!("{}accept\n", "# pad\n".repeat(MAX_SOURCE_LEN / 6 + 1));
        assert!(big.len() > MAX_SOURCE_LEN);
        assert!(compiles(&big).unwrap_err().message.contains("longer"));
        assert_eq!(
            unconditional_next_hop(&format!("set this.bgp.next_hop = 192.0.2.1\n{big}")),
            None
        );
        let syms = Symbols {
            policies: &[("big", big.as_str())],
            ..Symbols::EMPTY
        };
        assert!(compile("call big\naccept\n", &syms)
            .unwrap_err()
            .message
            .contains("longer"));
    }

    #[test]
    fn unconditional_next_hop_cases() {
        let nh = |s: &str| unconditional_next_hop(s);
        let v4 = Some("192.0.2.1".parse().unwrap());
        assert_eq!(nh("set this.bgp.next_hop = 192.0.2.1\naccept\n"), v4);
        assert_eq!(nh("set this.bgp.next_hop = self\naccept\n"), None);
        assert_eq!(
            nh("set this.bgp.next_hop = 192.0.2.1\nset this.bgp.next_hop = self\naccept\n"),
            None
        );
        // Guarded, or after an `if`: not decidable, never reported.
        assert_eq!(
            nh("if this.bgp.local_pref == 1:\n    set this.bgp.next_hop = 192.0.2.1\n    accept\nelse:\n    reject\n"),
            None
        );
        assert_eq!(nh("accept\n"), None);
        assert_eq!(nh("not rpl !!"), None);
    }

    #[test]
    fn accept_all_always_accepts() {
        let input = Input {
            prefix: "10.0.0.0/8".parse().unwrap(),
            bgp: BgpInput {
                origin: Origin::Igp,
                as_path: &[],
                as_path_segments: &[],
                local_pref: 100,
                med: None,
                next_hop: None,
                learned_via_ibgp: false,
                router_id: None,
                originator_id: None,
                cluster_list: &[],
                peer: None,
                peer_as: 0,
                communities: &[],
                extended_communities: &[],
                large_communities: &[],
                validation_state: ValidationState::default(),
                rd: None,
                local_role: None,
                remote_role: None,
                otc: None,
            },
        };
        assert_eq!(
            vm::run(&ACCEPT_ALL, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn deny_all_always_rejects() {
        let input = Input {
            prefix: "10.0.0.0/8".parse().unwrap(),
            bgp: BgpInput {
                origin: Origin::Igp,
                as_path: &[],
                as_path_segments: &[],
                local_pref: 100,
                med: None,
                next_hop: None,
                learned_via_ibgp: false,
                router_id: None,
                originator_id: None,
                cluster_list: &[],
                peer: None,
                peer_as: 0,
                communities: &[],
                extended_communities: &[],
                large_communities: &[],
                validation_state: ValidationState::default(),
                rd: None,
                local_role: None,
                remote_role: None,
                otc: None,
            },
        };
        assert_eq!(vm::run(&DENY_ALL, &input), Verdict::Reject);
    }

    #[test]
    fn compile_rejects_syntax_error() {
        assert!(compile("if this.prefix in :\n    accept\n", &Symbols::EMPTY).is_err());
    }

    #[test]
    fn compile_error_display_includes_line() {
        let err = compile(
            "if this.bgp.nonexistent == 1:\n    accept\nelse:\n    reject\n",
            &Symbols::EMPTY,
        )
        .unwrap_err();
        assert!(err.to_string().starts_with("line 1:"));
    }

    #[test]
    fn parse_colon_literal_accepts_two_and_three_part() {
        assert_eq!(parse_colon_literal("65000:100"), Some(vec![65000, 100]));
        assert_eq!(parse_colon_literal("65000:1:2"), Some(vec![65000, 1, 2]));
    }

    #[test]
    fn parse_colon_literal_rejects_non_literal_text() {
        assert_eq!(parse_colon_literal(""), None);
        assert_eq!(parse_colon_literal("not-a-literal"), None);
        assert_eq!(parse_colon_literal("65000:100 extra"), None);
        assert_eq!(parse_colon_literal("10.0.0.0/8"), None);
    }

    #[test]
    fn unconditional_next_hop_stops_at_a_call() {
        let src = "call p\nset this.bgp.next_hop = 192.0.2.1\naccept\n";
        assert_eq!(unconditional_next_hop(src), None);
    }
}
