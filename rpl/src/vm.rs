use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use ipnet::IpNet;

use crate::schema::FieldId;
use crate::symbols::PrefixListEntry;

/// One community value, tagged by kind so `Op::CommunityAdd`/`Remove`/
/// `ListContainsCommunity` know which of `Input`'s three community slices to
/// operate on without also carrying a redundant `FieldId` match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityValue {
    /// RFC 1997 standard community, packed `(AA << 16) | NN`.
    Standard(u32),
    /// RFC 4360 extended community, packed as its 8 raw wire bytes (one
    /// big-endian `u64`).
    Extended(u64),
    /// RFC 8092 large community: global admin, local data 1, local data 2.
    Large(u32, u32, u32),
}

/// Mirrors `nos_bgp::message::Origin`'s discriminants exactly (`Igp = 0`,
/// `Egp = 1`, `Incomplete = 2`) so `Value::Enum(u8)` round-trips without a
/// translation table. `nos-rpl` doesn't depend on `nos-bgp`, so this is its
/// own copy, not a shared type — see `Input`'s doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `IGP` (RFC 4271 ORIGIN 0).
    Igp = 0,
    /// `EGP` (RFC 4271 ORIGIN 1).
    Egp = 1,
    /// `INCOMPLETE` (RFC 4271 ORIGIN 2).
    Incomplete = 2,
}

/// RFC 6811 §2 origin validation state, `rpki.valid`/`rpki.invalid`/
/// `rpki.not_found` in a script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationState {
    /// A covering VRP validates the origin AS.
    Valid = 0,
    /// A covering VRP exists but none matches.
    Invalid = 1,
    /// No covering VRP (the default).
    #[default]
    NotFound = 2,
}

/// RFC 9234 §4.1 BGP role, `role.provider`/`role.rs`/`role.rs_client`/
/// `role.customer`/`role.peer` in a script (same values as the capability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Provider.
    Provider = 0,
    /// Route server.
    RouteServer = 1,
    /// Route server client.
    RouteServerClient = 2,
    /// Customer.
    Customer = 3,
    /// Peer (lateral peer).
    Peer = 4,
}

/// A stack value of the interpreter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    /// Integer.
    Int(i64),
    /// Boolean.
    Bool(bool),
    /// IP prefix.
    Prefix(IpNet),
    /// IP address.
    Ip(IpAddr),
    /// Enum variant discriminant (e.g. an [`Origin`]).
    Enum(u8),
}

/// `AS_PATH` segment type (RFC 4271 §4.3, RFC 5065 §3); `nos-rpl` has its own
/// copy, like [`Origin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegKind {
    /// `AS_SEQUENCE`, rendered bare: `1 2`.
    Sequence,
    /// `AS_SET`, rendered `{1 2}`.
    Set,
    /// `AS_CONFED_SEQUENCE`, rendered `(1 2)`.
    ConfedSequence,
    /// `AS_CONFED_SET`, rendered `({1 2})`.
    ConfedSet,
}

/// One `AS_PATH` segment, nearest hop first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    /// The segment type.
    pub kind: SegKind,
    /// The segment's ASNs.
    pub asns: &'a [u32],
}

/// Compiled as-path regexes, matched against the path rendered as
/// space-separated ASNs with segment delimiters (`"65001 {65002 65003}"`, see
/// [`SegKind`]). `_` is the Cisco-style boundary (start, end, space or one of
/// `{ } ( )`), so `_65001_` matches the ASN 65001 anywhere. `_` inside `[...]`
/// is a literal, and `\_` is a literal `_` outside it.
#[derive(Debug, Clone)]
pub struct AsPathRegexes(Vec<regex::Regex>);

/// `_` expansion that leaves character classes and escapes alone.
fn expand_underscore(p: &str) -> String {
    let mut out = String::with_capacity(p.len() + 16);
    let mut depth = 0usize;
    // Just after `[` or `[^`: a `]` here is a literal member.
    let mut class_start = false;
    let mut chars = p.chars().peekable();
    while let Some(c) = chars.next() {
        let was_start = std::mem::take(&mut class_start);
        match c {
            '\\' => match chars.next() {
                Some('_') => out.push('_'),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            },
            '[' => {
                depth += 1;
                class_start = true;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    out.push('^');
                    chars.next();
                }
            }
            ']' if depth > 0 && !was_start => {
                depth -= 1;
                out.push(']');
            }
            '_' if depth == 0 => out.push_str("(?:^|$|[ {}()])"),
            c => out.push(c),
        }
    }
    out
}

/// Appends one rendered segment (space-separated ASNs between delimiters).
fn push_seg(out: &mut String, asns: impl Iterator<Item = u32>, open: &str, close: &str) {
    use std::fmt::Write;
    if !out.is_empty() {
        out.push(' ');
    }
    out.push_str(open);
    for (i, a) in asns.enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{a}");
    }
    out.push_str(close);
}

/// Renders the path as the regexes see it; the first `added` ASNs of `flat`
/// (from `prepend`) join the first `AS_SEQUENCE`. With no segment view the
/// flat list is one sequence.
fn render_path(flat: &[u32], segments: &[Segment], added: usize) -> String {
    let mut out = String::new();
    if segments.is_empty() {
        push_seg(&mut out, flat.iter().copied(), "", "");
        return out;
    }
    let new = &flat[..added.min(flat.len())];
    let mut pending = !new.is_empty();
    if pending && segments[0].kind != SegKind::Sequence {
        push_seg(&mut out, new.iter().copied(), "", "");
        pending = false;
    }
    for sg in segments {
        let asns = sg.asns.iter().copied();
        match sg.kind {
            SegKind::Sequence if pending => {
                pending = false;
                push_seg(&mut out, new.iter().copied().chain(asns), "", "");
            }
            SegKind::Sequence => push_seg(&mut out, asns, "", ""),
            SegKind::Set => push_seg(&mut out, asns, "{", "}"),
            SegKind::ConfedSequence => push_seg(&mut out, asns, "(", ")"),
            SegKind::ConfedSet => push_seg(&mut out, asns, "({", "})"),
        }
    }
    out
}

impl AsPathRegexes {
    /// Compiles each pattern; an invalid regex is the error string.
    pub fn new(patterns: &[&str]) -> Result<Self, String> {
        Self::new_for("as-path", patterns)
    }

    /// [`Self::new`] for another text kind (`"community"`): only the error
    /// text differs.
    pub fn new_for(kind: &str, patterns: &[&str]) -> Result<Self, String> {
        patterns
            .iter()
            .map(|p| {
                regex::Regex::new(&expand_underscore(p))
                    .map_err(|e| format!("invalid {kind} regex '{p}': {e}"))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }

    // ponytail: allocates the rendered path per evaluation, only for
    // scripts that use a regex; render lazily once per run if it shows up
    // in profiles.
    fn is_match(&self, text: &str) -> bool {
        self.0.iter().any(|re| re.is_match(text))
    }
}

impl PartialEq for AsPathRegexes {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(&other.0)
                .all(|(a, b)| a.as_str() == b.as_str())
    }
}
impl Eq for AsPathRegexes {}

/// One instruction. List-typed fields (`as_path`, `cluster_list`) are never
/// pushed onto the stack as a whole — `FieldLen`/`ListContains*` read
/// straight from the borrowed slice in `Input` and push only the scalar
/// result, so `Value` never needs a list variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Pushes a scalar field of the input.
    LoadField(FieldId),
    /// Pushes an integer constant.
    LoadConstInt(i64),
    /// Pushes a prefix constant.
    LoadConstPrefix(IpNet),
    /// Pushes an IP address constant.
    LoadConstIp(IpAddr),
    /// Pushes an enum discriminant constant.
    LoadConstEnum(u8),
    /// Pushes the length of a list field.
    FieldLen(FieldId),
    /// Pushes whether a list field contains the integer.
    ListContainsInt(FieldId, u32),
    /// Pushes whether a list field contains the IPv4 address.
    ListContainsIp(FieldId, Ipv4Addr),
    /// Pushes whether a community list contains the value.
    ListContainsCommunity(FieldId, CommunityValue),
    /// `this.bgp.as_path.matches(..)` / `this.bgp.as_path in LIST` — true if
    /// any regex matches the current path.
    AsPathMatches(Arc<AsPathRegexes>),
    /// Pushes whether any value of the community list matches (rendered as
    /// decimal `AA:NN` / `type:subtype:value` / `ga:ld1:ld2`).
    CommunityMatches(FieldId, AsPathRegexes),
    /// Removes every community value whose rendered text matches.
    CommunityRemoveMatching(FieldId, AsPathRegexes),
    /// `this.bgp.as_path.prepend(asn, count)`.
    AsPathPrepend(u32, u8),
    /// `this.bgp.<field> == <ip literal>` on an optional-address field:
    /// false when the field is unset.
    OptIpEq(FieldId, IpAddr),
    /// `this.bgp.med` read: pushes the current MED, 0 when unset.
    LoadMed,
    /// `this.bgp.{first,neighbor,origin}_as <cmp> <int literal>` on the
    /// effective path: unset is false for every comparison but `!=`.
    OptIntCmp(FieldId, CmpKind, i64),
    /// `this.bgp.<optional-ip field> in <cidr>`: false when unset.
    OptIpIn(FieldId, IpNet),
    /// `this.bgp.<optional-ip field> in <prefix-list>`: false when unset.
    OptIpInList(FieldId, Arc<PrefixSet>),
    /// `this.bgp.as_path.path_length` (RFC 4271 section 9.1.2.2) over the
    /// effective path.
    AsPathLen,
    /// `this.bgp.rd == rd(..)`: false when the route has no RD.
    OptRdEq(u64),
    /// `this.bgp.{local,remote}_role == role.*`: false when the role is unset.
    OptEnumEq(FieldId, u8),
    /// Pops an `Enum` and sets `this.bgp.origin`.
    SetOrigin,
    /// Pops an `Ip` and sets `this.bgp.next_hop`.
    SetNextHop,
    /// `set this.bgp.next_hop = self`.
    SetNextHopSelf,
    /// Adds a community to a community-list field.
    CommunityAdd(FieldId, CommunityValue),
    /// Removes a community from a community-list field.
    CommunityRemove(FieldId, CommunityValue),
    /// Empties a community-list field.
    CommunityClear(FieldId),
    /// Pops two integers, pushes their sum.
    Add,
    /// Pops two integers, pushes their difference.
    Sub,
    /// Pops two values, pushes `==`.
    CmpEq,
    /// Pops two values, pushes `!=`.
    CmpNe,
    /// Pops two integers, pushes `<`.
    CmpLt,
    /// Pops two integers, pushes `<=`.
    CmpLe,
    /// Pops two integers, pushes `>`.
    CmpGt,
    /// Pops two integers, pushes `>=`.
    CmpGe,
    /// Pops a prefix literal and a prefix, pushes containment.
    PrefixIn,
    /// `this.prefix in SOME_PREFIX_LIST` — the entry list is resolved and
    /// compiled in at codegen time (not pushed as a runtime value), unlike
    /// `PrefixIn`'s plain-literal rhs. See `PrefixListEntry`'s doc comment
    /// for exact-vs-range matching.
    PrefixInList(Arc<PrefixSet>),
    /// Pops two booleans, pushes their conjunction.
    And,
    /// Pops two booleans, pushes their disjunction.
    Or,
    /// Pops a boolean, pushes its negation.
    Not,
    /// Pops a boolean; jumps to the instruction index when false.
    JumpIfFalse(usize),
    /// Jumps to the instruction index.
    Jump(usize),
    /// Pops a value and stores it in a mutable field.
    SetField(FieldId),
    /// Pops a signed delta and adds it (saturating) to a numeric field; an
    /// unset `med` counts as 0.
    AddField(FieldId),
    /// Ends evaluation accepting the route.
    Accept,
    /// Ends evaluation rejecting the route.
    Reject,
}

/// Comparison of an [`Op::OptIntCmp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpKind {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
}

/// A compiled policy: bytecode plus the stack depth it needs. Only
/// `codegen::compile` builds one (fields are `pub(crate)`), so `run` may trust
/// its jump targets and stack depth (#673).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    /// The instructions.
    pub(crate) code: Vec<Op>,
    /// Maximum operand-stack depth any path reaches.
    pub(crate) max_stack_depth: usize,
}

impl CompiledPolicy {
    /// Whether the script reads `this.bgp.validation_state` — only such a
    /// policy's verdict can change when the RPKI VRP set does.
    pub fn reads_validation_state(&self) -> bool {
        self.code
            .contains(&Op::LoadField(FieldId::BgpValidationState))
    }
}

/// The route data a policy script can see, adapted from whatever the caller's
/// own route type is — `nos-rpl` has zero knowledge of `RibRoute` or any
/// other NOS-internal type, so a consumer (e.g. `nos-bgp`) writes a plain
/// conversion function into this shape rather than `nos-rpl` depending on it.
pub struct Input<'a> {
    /// The route's prefix.
    pub prefix: IpNet,
    /// BGP path attributes.
    pub bgp: BgpInput<'a>,
}

/// The BGP attributes a policy can read.
pub struct BgpInput<'a> {
    /// ORIGIN (RFC 4271 §5.1.1).
    pub origin: Origin,
    /// `AS_PATH` as a flat ASN list (RFC 4271 §5.1.2).
    pub as_path: &'a [u32],
    /// The same path split into segments, for `matches`/`as-path-list`
    /// rendering. For `matches` empty means "one `AS_SEQUENCE` of
    /// `as_path`"; `path_length` and `first_as`/`neighbor_as`/`origin_as`
    /// ignore the flat list. A caller MUST therefore pass the complete
    /// path here, concatenating to `as_path` (empty only for an empty
    /// path); `run` debug-asserts it.
    pub as_path_segments: &'a [Segment<'a>],
    /// `LOCAL_PREF` (RFC 4271 §5.1.5).
    pub local_pref: u32,
    /// `MULTI_EXIT_DISC`, if present (RFC 4271 §5.1.4).
    pub med: Option<u32>,
    /// Local route tag (`this.bgp.tag`), 0 when untagged.
    pub tag: u32,
    /// `NEXT_HOP`, if known (RFC 4271 §5.1.3).
    pub next_hop: Option<IpAddr>,
    /// Whether the route was learned over IBGP.
    pub learned_via_ibgp: bool,
    /// BGP identifier of the advertising peer, if known.
    pub router_id: Option<Ipv4Addr>,
    /// `ORIGINATOR_ID` (RFC 4456 §8), if present.
    pub originator_id: Option<Ipv4Addr>,
    /// `CLUSTER_LIST` (RFC 4456 §8).
    pub cluster_list: &'a [Ipv4Addr],
    /// The neighbor this route is being imported from / exported to; `None`
    /// (and `peer_as == 0`, never a real ASN) for a locally-redistributed
    /// route, which has no neighbor.
    pub peer: Option<IpAddr>,
    /// AS number of that neighbor (0 for a locally-redistributed route).
    pub peer_as: u32,
    /// Standard communities (RFC 1997), raw `AA:NN` values.
    pub communities: &'a [u32],
    /// Extended communities (RFC 4360), raw 8-octet values.
    pub extended_communities: &'a [u64],
    /// Large communities (RFC 8092), `(global, local1, local2)`.
    pub large_communities: &'a [(u32, u32, u32)],
    /// RFC 6811 origin validation state.
    pub validation_state: ValidationState,
    /// The Route Distinguisher of a VPN route (RFC 4364 section 4.2), the 8
    /// octets as a big-endian integer (types 0/1/2 start with a zero octet,
    /// so it is also a non-negative `i64`); `None` for a non-VPN route.
    pub rd: Option<u64>,
    /// Our RFC 9234 role on the session; `None` for a route with no unicast
    /// session (redistributed, EVPN, VPN, Flowspec) or no configured role.
    pub local_role: Option<Role>,
    /// The peer's negotiated RFC 9234 role; `None` when none was negotiated.
    pub remote_role: Option<Role>,
    /// The route's RFC 9234 Only-To-Customer ASN (after ingress marking).
    pub otc: Option<u32>,
}

/// Attribute rewrites beyond the always-carried ones on `Verdict::Accept`.
/// Every field is "unchanged" by default so a policy that never touches it
/// costs nothing (no allocation, and the consumer keeps its shared `Arc`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Edits {
    /// The full replacement `AS_PATH`, only if the script prepended.
    pub as_path: Option<Vec<u32>>,
    /// Replacement ORIGIN, if the script set it.
    pub origin: Option<Origin>,
    /// What the script did to the next hop.
    pub next_hop: NextHopSet,
}

/// What a policy did to the route's next hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NextHopSet {
    /// The script did not touch the next hop.
    #[default]
    Unchanged,
    /// `set this.bgp.next_hop = self`.
    SelfAddress,
    /// `set this.bgp.next_hop = <ip>`.
    Addr(IpAddr),
}

/// The outcome of running a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The route is accepted, with its (possibly rewritten) attributes.
    Accept {
        /// Final `LOCAL_PREF`.
        local_pref: u32,
        /// Final MED.
        med: Option<u32>,
        /// Final local route tag (`this.bgp.tag`); local only, never sent.
        tag: u32,
        /// Final standard communities.
        communities: Vec<u32>,
        /// Final extended communities.
        extended_communities: Vec<u64>,
        /// Final large communities.
        large_communities: Vec<(u32, u32, u32)>,
        /// Further rewrites (AS path, origin, next hop).
        edits: Edits,
    },
    /// The route is rejected.
    Reject,
}

/// Upper bound on a policy's compile-time-computed `max_stack_depth` —
/// `codegen::compile` refuses to produce a `CompiledPolicy` that would
/// exceed it. Policies have no calls and no loops, so real scripts sit at a
/// handful of stack slots; this is already generous headroom, chosen so
/// `run`'s stack can be a fixed-size array (zero heap allocation on the hot
/// path — this runs once per route, per peer, per update) rather than a
/// `Vec`.
pub const MAX_STACK_DEPTH: usize = 32;

/// Cap on emitted ops: `call` inlines callees, so fan-out k at depth 8 would
/// compile k^8 copies; this bounds compile time and memory.
pub const MAX_CODE_OPS: usize = 65_536;

/// Executes `policy` against `input`. `local_pref`/`med` start at `input`'s
/// own values and are only ever changed by a `SetField` the script actually
/// executes — reading `this.bgp.local_pref` after a `set` sees the updated
/// value, exactly like a normal imperative variable. The three community
/// slices follow the same pattern via `Cow`, the one deliberate exception to
/// this module's "zero heap allocation on the hot path" stack — a
/// `CommunityAdd`/`Remove`/`Clear` needs to hand back an owned `Vec` through
/// `Verdict`, but `Cow::to_mut()` only clones on a script's first actual
/// write, and `Reject` never pays for it at all.
#[allow(
    clippy::too_many_lines,
    reason = "one flat op-dispatch loop; splitting it would only move the arms"
)]
pub fn run(policy: &CompiledPolicy, input: &Input) -> Verdict {
    debug_assert!(
        segments_match_flat(input),
        "BgpInput.as_path_segments must concatenate to as_path"
    );
    let mut stack = [Value::Int(0); MAX_STACK_DEPTH];
    let mut sp = 0usize;
    let mut cur_local_pref = input.bgp.local_pref;
    let mut cur_med = input.bgp.med;
    let mut cur_tag = input.bgp.tag;
    let mut lists = Lists {
        std: Cow::Borrowed(input.bgp.communities),
        ext: Cow::Borrowed(input.bgp.extended_communities),
        large: Cow::Borrowed(input.bgp.large_communities),
        as_path: Cow::Borrowed(input.bgp.as_path),
    };
    let mut cur_origin = input.bgp.origin;
    let mut next_hop_edit = NextHopSet::Unchanged;
    let mut pc = 0usize;

    macro_rules! push {
        ($v:expr) => {{
            stack[sp] = $v;
            sp += 1;
        }};
    }
    macro_rules! pop {
        () => {{
            sp -= 1;
            stack[sp]
        }};
    }

    loop {
        let op = &policy.code[pc];
        match op {
            Op::LoadField(id) => push!(load_field(*id, input, cur_origin, cur_local_pref, cur_tag)),
            Op::LoadConstInt(n) => push!(Value::Int(*n)),
            Op::LoadConstPrefix(p) => push!(Value::Prefix(*p)),
            Op::LoadConstIp(a) => push!(Value::Ip(*a)),
            Op::LoadConstEnum(e) => push!(Value::Enum(*e)),
            Op::FieldLen(id) => push!(Value::Int(field_len(*id, input, &lists))),
            Op::ListContainsInt(id, n) => push!(Value::Bool(match id {
                FieldId::BgpAsPath => lists.as_path.contains(n),
                _ => unreachable!("check.rs rejects ListContainsInt for {id:?}"),
            })),
            Op::ListContainsIp(id, addr) => push!(Value::Bool(match id {
                FieldId::BgpClusterList => input.bgp.cluster_list.contains(addr),
                _ => unreachable!("check.rs rejects ListContainsIp for {id:?}"),
            })),
            Op::ListContainsCommunity(id, val) => push!(Value::Bool(lists.has(*id, val))),
            Op::AsPathMatches(re) => push!(Value::Bool(as_path_matches(re, input, &lists))),
            Op::CommunityMatches(id, re) => push!(Value::Bool(lists.matches(*id, re))),
            Op::AsPathPrepend(asn, count) => lists.prepend(*asn, *count),
            Op::LoadMed
            | Op::OptIntCmp(..)
            | Op::OptEnumEq(..)
            | Op::OptIpEq(..)
            | Op::OptIpIn(..)
            | Op::OptIpInList(..)
            | Op::AsPathLen => push!(read_op(op, input, &lists, next_hop_edit, cur_med)),
            Op::OptRdEq(rd) => push!(Value::Bool(input.bgp.rd == Some(*rd))),
            Op::SetOrigin => cur_origin = origin_from(pop!()),
            Op::SetNextHop => match pop!() {
                Value::Ip(a) => next_hop_edit = NextHopSet::Addr(a),
                other => unreachable!("codegen.rs guarantees an Ip here, got {other:?}"),
            },
            Op::SetNextHopSelf => next_hop_edit = NextHopSet::SelfAddress,
            Op::Add | Op::Sub => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Int(if matches!(op, Op::Add) {
                    a.saturating_add(b)
                } else {
                    a.saturating_sub(b)
                }));
            }
            Op::CmpEq | Op::CmpNe => {
                let b = pop!();
                let a = pop!();
                push!(Value::Bool((a == b) == matches!(op, Op::CmpEq)));
            }
            Op::CmpLt | Op::CmpLe | Op::CmpGt | Op::CmpGe => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Bool(match op {
                    Op::CmpLt => a < b,
                    Op::CmpLe => a <= b,
                    Op::CmpGt => a > b,
                    _ => a >= b,
                }));
            }
            Op::PrefixIn => {
                let network = as_prefix(pop!());
                let candidate = as_prefix(pop!());
                push!(Value::Bool(network.contains(&candidate)));
            }
            Op::PrefixInList(entries) => {
                let candidate = as_prefix(pop!());
                push!(Value::Bool(entries.contains(candidate)));
            }
            Op::And | Op::Or => {
                let b = as_bool(pop!());
                let a = as_bool(pop!());
                push!(Value::Bool(if matches!(op, Op::And) {
                    a && b
                } else {
                    a || b
                }));
            }
            Op::Not => {
                let a = as_bool(pop!());
                push!(Value::Bool(!a));
            }
            Op::JumpIfFalse(target) if !as_bool(pop!()) => {
                pc = *target;
                continue;
            }
            Op::JumpIfFalse(_) => {}
            Op::Jump(target) => {
                pc = *target;
                continue;
            }
            Op::SetField(id) => {
                let v = as_int(pop!());
                set_field(*id, v, &mut cur_local_pref, &mut cur_med, &mut cur_tag);
            }
            Op::AddField(id) => {
                let d = as_int(pop!());
                add_field(*id, d, &mut cur_local_pref, &mut cur_med, &mut cur_tag);
            }
            Op::CommunityAdd(id, val) => lists.add(*id, val),
            Op::CommunityRemove(id, val) => lists.remove(*id, val),
            Op::CommunityRemoveMatching(id, re) => lists.remove_matching(*id, re),
            Op::CommunityClear(id) => lists.clear(*id),
            Op::Accept => {
                return Verdict::Accept {
                    local_pref: cur_local_pref,
                    med: cur_med,
                    tag: cur_tag,
                    communities: lists.std.into_owned(),
                    extended_communities: lists.ext.into_owned(),
                    large_communities: lists.large.into_owned(),
                    edits: edits(
                        lists.as_path,
                        cur_origin != input.bgp.origin,
                        cur_origin,
                        next_hop_edit,
                    ),
                }
            }
            Op::Reject => return Verdict::Reject,
        }
        pc += 1;
    }
}

/// The policy-mutable lists, copy-on-write so a script that never edits one
/// never clones it.
struct Lists<'a> {
    std: Cow<'a, [u32]>,
    ext: Cow<'a, [u64]>,
    large: Cow<'a, [(u32, u32, u32)]>,
    as_path: Cow<'a, [u32]>,
}

impl Lists<'_> {
    /// `Op::AsPathPrepend`.
    fn prepend(&mut self, asn: u32, count: u8) {
        self.as_path
            .to_mut()
            .splice(0..0, std::iter::repeat_n(asn, usize::from(count)));
    }

    /// `Op::ListContainsCommunity`.
    fn has(&self, id: FieldId, val: &CommunityValue) -> bool {
        match (id, val) {
            (FieldId::BgpCommunities, CommunityValue::Standard(n)) => self.std.contains(n),
            (FieldId::BgpExtCommunities, CommunityValue::Extended(n)) => self.ext.contains(n),
            (FieldId::BgpLargeCommunities, CommunityValue::Large(ga, l1, l2)) => {
                self.large.contains(&(*ga, *l1, *l2))
            }
            _ => unreachable!("codegen.rs pairs FieldId/CommunityValue consistently"),
        }
    }

    /// `Op::CommunityAdd`; `Cow::to_mut` clones only on the first write.
    fn add(&mut self, id: FieldId, val: &CommunityValue) {
        match (id, val) {
            (FieldId::BgpCommunities, CommunityValue::Standard(n)) => {
                let list = self.std.to_mut();
                if !list.contains(n) {
                    list.push(*n);
                }
            }
            (FieldId::BgpExtCommunities, CommunityValue::Extended(n)) => {
                let list = self.ext.to_mut();
                if !list.contains(n) {
                    list.push(*n);
                }
            }
            (FieldId::BgpLargeCommunities, CommunityValue::Large(ga, l1, l2)) => {
                let list = self.large.to_mut();
                let v = (*ga, *l1, *l2);
                if !list.contains(&v) {
                    list.push(v);
                }
            }
            _ => unreachable!("codegen.rs pairs FieldId/CommunityValue consistently"),
        }
    }

    /// `Op::CommunityRemove`.
    fn remove(&mut self, id: FieldId, val: &CommunityValue) {
        match (id, val) {
            (FieldId::BgpCommunities, CommunityValue::Standard(n)) => {
                self.std.to_mut().retain(|c| c != n);
            }
            (FieldId::BgpExtCommunities, CommunityValue::Extended(n)) => {
                self.ext.to_mut().retain(|c| c != n);
            }
            (FieldId::BgpLargeCommunities, CommunityValue::Large(ga, l1, l2)) => {
                let v = (*ga, *l1, *l2);
                self.large.to_mut().retain(|c| *c != v);
            }
            _ => unreachable!("codegen.rs pairs FieldId/CommunityValue consistently"),
        }
    }

    /// `Op::CommunityMatches`.
    fn matches(&self, id: FieldId, re: &AsPathRegexes) -> bool {
        match id {
            FieldId::BgpCommunities => self.std.iter().any(|c| re.is_match(&render_std(*c))),
            FieldId::BgpExtCommunities => self.ext.iter().any(|c| re.is_match(&render_ext(*c))),
            FieldId::BgpLargeCommunities => {
                self.large.iter().any(|c| re.is_match(&render_large(*c)))
            }
            _ => unreachable!("codegen.rs rejects CommunityMatches for {id:?}"),
        }
    }

    /// `Op::CommunityRemoveMatching`; an immutable pass first so a script
    /// that removes nothing never clones the list.
    fn remove_matching(&mut self, id: FieldId, re: &AsPathRegexes) {
        if !self.matches(id, re) {
            return;
        }
        match id {
            FieldId::BgpCommunities => self.std.to_mut().retain(|c| !re.is_match(&render_std(*c))),
            FieldId::BgpExtCommunities => {
                self.ext.to_mut().retain(|c| !re.is_match(&render_ext(*c)));
            }
            FieldId::BgpLargeCommunities => self
                .large
                .to_mut()
                .retain(|c| !re.is_match(&render_large(*c))),
            _ => unreachable!("codegen.rs rejects CommunityRemoveMatching for {id:?}"),
        }
    }

    /// `Op::CommunityClear`.
    fn clear(&mut self, id: FieldId) {
        match id {
            FieldId::BgpCommunities => self.std.to_mut().clear(),
            FieldId::BgpExtCommunities => self.ext.to_mut().clear(),
            FieldId::BgpLargeCommunities => self.large.to_mut().clear(),
            _ => unreachable!("check.rs/codegen.rs reject CommunityClear for {id:?}"),
        }
    }
}

/// `Op::AsPathMatches`, split out of `run` for length.
fn as_path_matches(re: &AsPathRegexes, input: &Input, lists: &Lists) -> bool {
    let added = lists.as_path.len().saturating_sub(input.bgp.as_path.len());
    re.is_match(&render_path(
        &lists.as_path,
        input.bgp.as_path_segments,
        added,
    ))
}

/// Community text a regex sees: the same decimal syntax as the literals.
fn render_std(c: u32) -> String {
    format!("{}:{}", c >> 16, c & 0xffff)
}

fn render_ext(c: u64) -> String {
    format!("{}:{}:{}", c >> 56, (c >> 48) & 0xff, c & ((1 << 48) - 1))
}

fn render_large((ga, l1, l2): (u32, u32, u32)) -> String {
    format!("{ga}:{l1}:{l2}")
}

/// `Op::FieldLen`, split out of `run` for length.
fn field_len(id: FieldId, input: &Input, lists: &Lists) -> i64 {
    match id {
        FieldId::Prefix => i64::from(input.prefix.prefix_len()),
        FieldId::BgpAsPath => len_as_int(lists.as_path.len()),
        FieldId::BgpClusterList => len_as_int(input.bgp.cluster_list.len()),
        FieldId::BgpCommunities => len_as_int(lists.std.len()),
        FieldId::BgpExtCommunities => len_as_int(lists.ext.len()),
        FieldId::BgpLargeCommunities => len_as_int(lists.large.len()),
        _ => unreachable!("check.rs rejects FieldLen for {id:?}"),
    }
}

/// `Op::LoadField`, split out of `run` for length.
fn load_field(id: FieldId, input: &Input, origin: Origin, local_pref: u32, tag: u32) -> Value {
    match id {
        FieldId::Prefix => Value::Prefix(input.prefix),
        FieldId::BgpOrigin => Value::Enum(origin as u8),
        FieldId::BgpPeerAs => Value::Int(i64::from(input.bgp.peer_as)),
        FieldId::BgpLocalPref => Value::Int(i64::from(local_pref)),
        FieldId::BgpTag => Value::Int(i64::from(tag)),
        FieldId::BgpLearnedViaIbgp => Value::Bool(input.bgp.learned_via_ibgp),
        FieldId::BgpValidationState => Value::Enum(input.bgp.validation_state as u8),
        _ => unreachable!("check.rs rejects LoadField for {id:?}"),
    }
}

/// The path as segments for `path_length` and the AS accessors: the input
/// segments, with the ASNs the script prepended (the first
/// `lists.as_path.len() - input.as_path.len()`) joined to the first
/// `AS_SEQUENCE`, or leading a new one. The flat `as_path` is never a
/// fallback.
// ponytail: allocates per evaluation, only for scripts using these ops.
fn effective_segments(input: &Input, lists: &Lists) -> Vec<(SegKind, Vec<u32>)> {
    let added = lists.as_path.len().saturating_sub(input.bgp.as_path.len());
    let new = &lists.as_path[..added];
    let mut out: Vec<(SegKind, Vec<u32>)> = input
        .bgp
        .as_path_segments
        .iter()
        .map(|s| (s.kind, s.asns.to_vec()))
        .collect();
    if !new.is_empty() {
        match out.first_mut() {
            Some((SegKind::Sequence, asns)) => {
                *asns = new.iter().chain(asns.iter()).copied().collect();
            }
            _ => out.insert(0, (SegKind::Sequence, new.to_vec())),
        }
    }
    out
}

/// The side-effect-free reads (`LoadMed`, the optional-field and path ops),
/// split out of `run` for length.
fn read_op(
    op: &Op,
    input: &Input,
    lists: &Lists,
    next_hop_edit: NextHopSet,
    med: Option<u32>,
) -> Value {
    match op {
        Op::LoadMed => Value::Int(i64::from(med.unwrap_or(0))),
        Op::OptIntCmp(id, kind, n) => {
            Value::Bool(opt_int_cmp(opt_int(*id, input, lists), *kind, *n))
        }
        Op::OptEnumEq(id, v) => Value::Bool(
            match id {
                FieldId::BgpLocalRole => input.bgp.local_role,
                _ => input.bgp.remote_role,
            }
            .is_some_and(|r| r as u8 == *v),
        ),
        Op::OptIpEq(id, ip) => Value::Bool(opt_ip(*id, input, next_hop_edit) == Some(*ip)),
        Op::OptIpIn(id, net) => {
            Value::Bool(opt_ip(*id, input, next_hop_edit).is_some_and(|a| net.contains(&a)))
        }
        Op::OptIpInList(id, entries) => Value::Bool(
            opt_ip(*id, input, next_hop_edit).is_some_and(|a| entries.contains(IpNet::from(a))),
        ),
        Op::AsPathLen => Value::Int(as_path_len(input, lists)),
        _ => unreachable!("run() routes only read ops here"),
    }
}

/// The `BgpInput.as_path_segments` contract: empty, or the flat path.
fn segments_match_flat(input: &Input) -> bool {
    input.bgp.as_path_segments.is_empty()
        || input
            .bgp
            .as_path_segments
            .iter()
            .flat_map(|s| s.asns.iter().copied())
            .eq(input.bgp.as_path.iter().copied())
}

/// `Op::OptIntCmp`: an unset value is false for every comparison but `!=`.
fn opt_int_cmp(v: Option<u32>, kind: CmpKind, n: i64) -> bool {
    let Some(v) = v.map(i64::from) else {
        return kind == CmpKind::Ne;
    };
    match kind {
        CmpKind::Eq => v == n,
        CmpKind::Ne => v != n,
        CmpKind::Lt => v < n,
        CmpKind::Le => v <= n,
        CmpKind::Gt => v > n,
        CmpKind::Ge => v >= n,
    }
}

/// `Op::AsPathLen` (RFC 4271 section 9.1.2.2) over the effective path.
fn as_path_len(input: &Input, lists: &Lists) -> i64 {
    effective_segments(input, lists)
        .iter()
        .map(|(k, a)| match k {
            SegKind::Sequence => len_as_int(a.len()),
            SegKind::Set => 1,
            SegKind::ConfedSequence | SegKind::ConfedSet => 0,
        })
        .fold(0, i64::saturating_add)
}

/// `Op::OptIntCmp`'s current value.
fn opt_int(id: FieldId, input: &Input, lists: &Lists) -> Option<u32> {
    let segs = effective_segments(input, lists);
    let seq = |s: Option<&(SegKind, Vec<u32>)>, last: bool| match s {
        Some((SegKind::Sequence, a)) if last => a.last().copied(),
        Some((SegKind::Sequence, a)) => a.first().copied(),
        _ => None,
    };
    match id {
        FieldId::BgpFirstAs => seq(segs.first(), false),
        FieldId::BgpNeighborAs => seq(
            segs.iter()
                .find(|(k, _)| !matches!(k, SegKind::ConfedSequence | SegKind::ConfedSet)),
            false,
        ),
        FieldId::BgpOriginAs => seq(segs.last(), true),
        FieldId::BgpOtc => input.bgp.otc,
        _ => unreachable!("codegen.rs only emits OptIntCmp for these accessors"),
    }
}

/// `Op::OptIpEq`'s current value, split out of `run` for length.
fn opt_ip(id: FieldId, input: &Input, next_hop_edit: NextHopSet) -> Option<IpAddr> {
    match id {
        FieldId::BgpNextHop => match next_hop_edit {
            NextHopSet::Addr(a) => Some(a),
            NextHopSet::SelfAddress => None,
            NextHopSet::Unchanged => input.bgp.next_hop,
        },
        FieldId::BgpPeer => input.bgp.peer,
        FieldId::BgpRouterId => input.bgp.router_id.map(IpAddr::V4),
        FieldId::BgpOriginatorId => input.bgp.originator_id.map(IpAddr::V4),
        _ => unreachable!("codegen.rs only emits OptIpEq for optional-ip fields"),
    }
}

/// `Op::SetOrigin`'s operand (an `Enum`), split out of `run` for length.
fn origin_from(v: Value) -> Origin {
    match v {
        Value::Enum(0) => Origin::Igp,
        Value::Enum(1) => Origin::Egp,
        _ => Origin::Incomplete,
    }
}

/// `Op::SetField`, split out of `run` for length.
fn set_field(id: FieldId, v: i64, local_pref: &mut u32, med: &mut Option<u32>, tag: &mut u32) {
    match id {
        FieldId::BgpLocalPref => *local_pref = to_u32_saturating(v),
        FieldId::BgpMed => *med = Some(to_u32_saturating(v)),
        FieldId::BgpTag => *tag = to_u32_saturating(v),
        _ => unreachable!("check.rs rejects SetField for {id:?}"),
    }
}

/// `Op::AddField`, split out of `run` for length.
fn add_field(id: FieldId, d: i64, local_pref: &mut u32, med: &mut Option<u32>, tag: &mut u32) {
    match id {
        FieldId::BgpLocalPref => {
            *local_pref = to_u32_saturating(i64::from(*local_pref).saturating_add(d));
        }
        FieldId::BgpMed => {
            *med = Some(to_u32_saturating(
                i64::from(med.unwrap_or(0)).saturating_add(d),
            ));
        }
        FieldId::BgpTag => *tag = to_u32_saturating(i64::from(*tag).saturating_add(d)),
        _ => unreachable!("check.rs rejects AddField for {id:?}"),
    }
}

/// A prefix-list indexed for lookup: a candidate costs at most one hash probe
/// per distinct entry prefix length (<= 33 / 129), not one compare per entry.
/// Same semantics as the linear scan it replaces: no `range` is an exact
/// match, a `range` is containment plus an inclusive bound on the
/// candidate's own length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixSet {
    exact: HashSet<IpNet>,
    /// Ranged entries by truncated network: the `(min, max)` bounds of each.
    ranged: HashMap<IpNet, Vec<(u8, u8)>>,
    /// Distinct prefix lengths in `ranged`, ascending, per family.
    lens_v4: Vec<u8>,
    lens_v6: Vec<u8>,
}

impl PrefixSet {
    /// Indexes `entries`.
    pub fn new(entries: &[PrefixListEntry]) -> Self {
        let mut set = Self {
            exact: HashSet::new(),
            ranged: HashMap::new(),
            lens_v4: Vec::new(),
            lens_v6: Vec::new(),
        };
        for e in entries {
            match e.range {
                None => {
                    set.exact.insert(e.cidr);
                }
                Some(b) => {
                    set.ranged.entry(e.cidr.trunc()).or_default().push(b);
                    let lens = match e.cidr {
                        IpNet::V4(_) => &mut set.lens_v4,
                        IpNet::V6(_) => &mut set.lens_v6,
                    };
                    lens.push(e.cidr.prefix_len());
                }
            }
        }
        for l in [&mut set.lens_v4, &mut set.lens_v6] {
            l.sort_unstable();
            l.dedup();
        }
        set
    }

    /// Whether any entry matches `candidate`.
    pub fn contains(&self, candidate: IpNet) -> bool {
        if self.exact.contains(&candidate) {
            return true;
        }
        let len = candidate.prefix_len();
        let lens = match candidate {
            IpNet::V4(_) => &self.lens_v4,
            IpNet::V6(_) => &self.lens_v6,
        };
        lens.iter().take_while(|&&l| l <= len).any(|&l| {
            IpNet::new(candidate.addr(), l)
                .ok()
                .and_then(|anc| self.ranged.get(&anc.trunc()))
                .is_some_and(|b| b.iter().any(|&(min, max)| (min..=max).contains(&len)))
        })
    }
}

/// The `Edits` of an `Accept`, split out of `run` for length.
fn edits(as_path: Cow<[u32]>, origin_changed: bool, origin: Origin, next_hop: NextHopSet) -> Edits {
    Edits {
        as_path: match as_path {
            Cow::Owned(v) => Some(v),
            Cow::Borrowed(_) => None,
        },
        origin: origin_changed.then_some(origin),
        next_hop,
    }
}

fn len_as_int(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// `set this.bgp.local_pref = <expr>` carries a runtime-computed `i64`, not
/// always a literal, so out-of-range values can't be rejected at compile
/// time — clamp instead of wrapping, since a wrapped negative-to-huge value
/// would be a far more surprising outcome for a route attribute than a
/// clamped one.
fn to_u32_saturating(v: i64) -> u32 {
    u32::try_from(v).unwrap_or(if v.is_negative() { 0 } else { u32::MAX })
}

fn as_int(v: Value) -> i64 {
    match v {
        Value::Int(n) => n,
        other => unreachable!("codegen.rs guarantees an Int here, got {other:?}"),
    }
}

fn as_bool(v: Value) -> bool {
    match v {
        Value::Bool(b) => b,
        other => unreachable!("codegen.rs guarantees a Bool here, got {other:?}"),
    }
}

fn as_prefix(v: Value) -> IpNet {
    match v {
        Value::Prefix(p) => p,
        other => unreachable!("codegen.rs guarantees a Prefix here, got {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_policies_satisfy_the_invariants_run_trusts() {
        for src in [
            "accept\n",
            "if this.prefix.length > 24:\n    reject\naccept\n",
            "if this.bgp.local_pref > 100:\n    accept\nelif this.bgp.med < 5:\n    reject\nelse:\n    accept\n",
        ] {
            let p = crate::compile(src, &crate::Symbols::EMPTY).unwrap();
            assert!(p.max_stack_depth <= MAX_STACK_DEPTH, "{src}");
            for op in &p.code {
                if let Op::Jump(t) | Op::JumpIfFalse(t) = op {
                    assert!(*t < p.code.len(), "{src}");
                }
            }
        }
    }

    fn m(pat: &str, text: &str) -> bool {
        AsPathRegexes::new(&[pat]).unwrap().is_match(text)
    }

    #[test]
    fn underscore_is_a_boundary_only_outside_classes() {
        assert!(m("_65001_", "1 65001 2"));
        assert!(m("^65001_", "65001"));
        assert!(m("_65001_", "{65001 2}"));
        assert!(m("_65001_", "(65001)"));
        assert!(!m("_65001_", "165001"));
        // `[_]` and `[^_]` are literal classes.
        assert!(!m("^[_]", "65001"));
        assert!(m("^[_]", "_"));
        assert!(m("^[^_]+$", "65001 2"));
        assert!(m("^[]_]$", "]"));
        // `\_` is a literal underscore.
        assert!(m(r"^\_$", "_"));
        assert!(!m(r"^\_$", ""));
    }

    #[test]
    fn rendering_keeps_segment_boundaries() {
        use SegKind::*;
        let seg = |kind, asns| Segment { kind, asns };
        let flat = [65101, 65001, 1, 2, 3];
        let segs = [
            seg(ConfedSequence, &flat[..1]),
            seg(Sequence, &flat[1..2]),
            seg(Set, &flat[2..4]),
            seg(ConfedSet, &flat[4..]),
        ];
        assert_eq!(render_path(&flat, &segs, 0), "(65101) 65001 {1 2} ({3})");
        assert_eq!(render_path(&[7, 8], &[], 0), "7 8");
        // Prepended ASNs join the first sequence, or start one.
        let flat2 = [9, 9, 65001, 1];
        let segs2 = [seg(Sequence, &flat2[2..3]), seg(Set, &flat2[3..])];
        assert_eq!(render_path(&flat2, &segs2, 2), "9 9 65001 {1}");
        let segs3 = [seg(Set, &flat2[2..])];
        assert_eq!(render_path(&flat2, &segs3, 2), "9 9 {65001 1}");
        // The flat view no longer matches a set member as a bare sequence ASN.
        assert!(!m("^65001_", "{65001 2}"));
        assert!(m(r"^\{", "{65001 2}"));
        assert!(m(r"^\(", "(65001) 1"));
    }

    /// The linear scan `PrefixSet` replaced, kept as the oracle.
    fn linear(entries: &[PrefixListEntry], c: IpNet) -> bool {
        entries.iter().any(|e| match e.range {
            None => c == e.cidr,
            Some((min, max)) => e.cidr.contains(&c) && (min..=max).contains(&c.prefix_len()),
        })
    }

    #[test]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_lossless,
        clippy::cast_possible_wrap,
        clippy::precedence,
        reason = "test PRNG, values bounded by construction"
    )]
    fn prefix_set_matches_linear_scan() {
        let mut x = 0x9e37_79b9_7f4a_7c15_u64;
        let mut rnd = move |n: u64| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (x >> 33) % n
        };
        // A small address space so entries and candidates collide often.
        let net = |rnd: &mut dyn FnMut(u64) -> u64| -> IpNet {
            if rnd(2) == 0 {
                let len = rnd(33) as u8;
                let a = Ipv4Addr::from(((rnd(4) as u32) << 30) | (rnd(1 << 16) as u32 * 7));
                IpNet::new(IpAddr::V4(a), len).unwrap()
            } else {
                let len = rnd(129) as u8;
                let a = std::net::Ipv6Addr::from(((rnd(4) as u128) << 126) | rnd(1 << 16) as u128);
                IpNet::new(IpAddr::V6(a), len).unwrap()
            }
        };
        for _ in 0..300 {
            let entries: Vec<PrefixListEntry> = (0..rnd(12))
                .map(|_| {
                    let cidr = net(&mut rnd);
                    let range = (rnd(3) > 0).then(|| {
                        let (a, b) = (rnd(130) as u8, rnd(130) as u8);
                        (a.min(b), a.max(b))
                    });
                    PrefixListEntry { cidr, range }
                })
                .collect();
            let set = PrefixSet::new(&entries);
            for _ in 0..60 {
                // Half the candidates derive from an entry so hits happen.
                let c = if entries.is_empty() || rnd(2) == 0 {
                    net(&mut rnd)
                } else {
                    let e = entries[rnd(entries.len() as u64) as usize].cidr;
                    let max = if e.addr().is_ipv4() { 32 } else { 128 };
                    let len = (e.prefix_len() as u64 + rnd(4)).min(max) as u8;
                    IpNet::new(e.addr(), len).unwrap()
                };
                assert_eq!(set.contains(c), linear(&entries, c), "{entries:?} {c}");
            }
        }
    }

    #[test]
    fn prefix_set_range_edges() {
        let e = |c: &str, range| PrefixListEntry {
            cidr: c.parse().unwrap(),
            range,
        };
        let set = PrefixSet::new(&[
            e("10.0.0.0/8", Some((16, 16))),
            e("::ffff:10.0.0.0/104", None),
        ]);
        let has = |c: &str| set.contains(c.parse().unwrap());
        assert!(has("10.1.0.0/16"));
        assert!(!has("10.0.0.0/8")); // shorter than min
        assert!(!has("10.1.0.0/17")); // above max
        assert!(!has("11.1.0.0/16"));
        assert!(!has("fe80::/16")); // other family
        assert!(has("::ffff:10.0.0.0/104")); // v4-mapped is plain v6
        assert!(!has("::ffff:10.0.0.0/105"));
    }
}
