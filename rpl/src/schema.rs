//! The fixed table of fields a policy script can read/write through `this`.
//! This is the one place a future *read-only* capability (`this.static.*`)
//! gets added — purely additive, no grammar/AST change needed elsewhere. A
//! settable *list* field (like `bgp.communities` below) additionally needs
//! `ast.rs`/`parser.rs`/`check.rs`/`codegen.rs`/`vm.rs` changes for its
//! `.add`/`.remove`/`.clear` statement forms — this table only wires up the
//! field path and its type. v1 has exactly one capability (`bgp`) plus the
//! always-present `prefix`, and both of `nos-rpl`'s attach points (BGP
//! import/export) guarantee the same set, so there's no per-attach-point
//! variation to model yet — see root `CLAUDE.md`'s "Explicitly out of
//! scope" for why a genuinely optional capability isn't built now.

/// A field of the route a policy can read (and, where [`FieldInfo::mutable`], write).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldId {
    /// `this.prefix`.
    Prefix,
    /// `this.bgp.origin` (RFC 4271 ORIGIN).
    BgpOrigin,
    /// `this.bgp.as_path` (RFC 4271 `AS_PATH`).
    BgpAsPath,
    /// `this.bgp.local_pref` (RFC 4271 `LOCAL_PREF`).
    BgpLocalPref,
    /// `this.bgp.med` (RFC 4271 `MULTI_EXIT_DISC`).
    BgpMed,
    /// `this.bgp.tag`: a local route tag, never sent to a peer (absent = 0).
    BgpTag,
    /// `this.bgp.next_hop` (RFC 4271 `NEXT_HOP`).
    BgpNextHop,
    /// First AS of the effective path, read-only (see `Op::OptIntCmp`).
    BgpFirstAs,
    /// First non-confederation AS of the effective path, read-only.
    BgpNeighborAs,
    /// Last AS of the effective path, read-only.
    BgpOriginAs,
    /// Address of the neighbor the route is imported from / exported to.
    BgpPeer,
    /// AS number of that neighbor.
    BgpPeerAs,
    /// Whether the route was learned over IBGP.
    BgpLearnedViaIbgp,
    /// BGP identifier of the advertising peer.
    BgpRouterId,
    /// `ORIGINATOR_ID` (RFC 4456), if present.
    BgpOriginatorId,
    /// `CLUSTER_LIST` (RFC 4456).
    BgpClusterList,
    /// Standard communities (RFC 1997).
    BgpCommunities,
    /// Extended communities (RFC 4360).
    BgpExtCommunities,
    /// Large communities (RFC 8092).
    BgpLargeCommunities,
    /// RFC 6811 origin validation state, read-only.
    BgpValidationState,
    /// `this.bgp.rd`: the Route Distinguisher of a VPN route (RFC 4364),
    /// read-only; unset for a non-VPN route.
    BgpRd,
    /// `this.bgp.local_role`: our RFC 9234 role on the session, read-only.
    BgpLocalRole,
    /// `this.bgp.remote_role`: the peer's negotiated RFC 9234 role, read-only.
    BgpRemoteRole,
    /// `this.bgp.otc`: the RFC 9234 Only-To-Customer ASN after ingress, read-only.
    BgpOtc,
}

/// The type of a [`FieldId`], as the checker sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// Integer.
    Int,
    /// Boolean.
    Bool,
    /// IP prefix.
    Prefix,
    /// IP address that may be absent.
    OptionalIp,
    /// Integer that may be absent.
    OptionalInt,
    /// A Route Distinguisher that may be absent; only `==`/`!=` against `rd(..)`.
    OptionalRd,
    /// An enum that may be absent; only `==`/`!=` against its literals.
    OptionalEnum(&'static str),
    /// One of the named enum's variants (e.g. `origin`).
    Enum(&'static str),
    /// List of integers (e.g. an AS path).
    ListInt,
    /// List of IP addresses.
    ListIp,
    /// RFC 1997 standard community — `AA:NN` colon literals only.
    ListCommunity,
    /// RFC 4360 extended community — `type:subtype:value` colon literals only.
    ListExtCommunity,
    /// RFC 8092 large community — `ga:ld1:ld2` colon literals only.
    ListLargeCommunity,
}

/// Schema entry for one route field.
#[derive(Debug, Clone, Copy)]
pub struct FieldInfo {
    /// Which field this describes.
    pub id: FieldId,
    /// Its type.
    pub ty: FieldType,
    /// Whether policies may `set` it.
    pub mutable: bool,
}

/// Every valid field path off `this`, keyed by its dotted segments (without
/// the leading `this`). `this.prefix` is `&["prefix"]`; `this.bgp.local_pref`
/// is `&["bgp", "local_pref"]`.
const FIELDS: &[(&[&str], FieldInfo)] = &[
    (
        &["prefix"],
        FieldInfo {
            id: FieldId::Prefix,
            ty: FieldType::Prefix,
            mutable: false,
        },
    ),
    (
        &["bgp", "origin"],
        FieldInfo {
            id: FieldId::BgpOrigin,
            ty: FieldType::Enum("origin"),
            mutable: true,
        },
    ),
    (
        &["bgp", "as_path"],
        FieldInfo {
            id: FieldId::BgpAsPath,
            ty: FieldType::ListInt,
            mutable: true,
        },
    ),
    (
        &["bgp", "local_pref"],
        FieldInfo {
            id: FieldId::BgpLocalPref,
            ty: FieldType::Int,
            mutable: true,
        },
    ),
    (
        &["bgp", "tag"],
        FieldInfo {
            id: FieldId::BgpTag,
            ty: FieldType::Int,
            mutable: true,
        },
    ),
    (
        &["bgp", "med"],
        FieldInfo {
            id: FieldId::BgpMed,
            ty: FieldType::OptionalInt,
            mutable: true,
        },
    ),
    (
        &["bgp", "first_as"],
        FieldInfo {
            id: FieldId::BgpFirstAs,
            ty: FieldType::OptionalInt,
            mutable: false,
        },
    ),
    (
        &["bgp", "neighbor_as"],
        FieldInfo {
            id: FieldId::BgpNeighborAs,
            ty: FieldType::OptionalInt,
            mutable: false,
        },
    ),
    (
        &["bgp", "origin_as"],
        FieldInfo {
            id: FieldId::BgpOriginAs,
            ty: FieldType::OptionalInt,
            mutable: false,
        },
    ),
    (
        &["bgp", "next_hop"],
        FieldInfo {
            id: FieldId::BgpNextHop,
            ty: FieldType::OptionalIp,
            mutable: true,
        },
    ),
    (
        &["bgp", "peer"],
        FieldInfo {
            id: FieldId::BgpPeer,
            ty: FieldType::OptionalIp,
            mutable: false,
        },
    ),
    (
        &["bgp", "peer_as"],
        FieldInfo {
            id: FieldId::BgpPeerAs,
            ty: FieldType::Int,
            mutable: false,
        },
    ),
    (
        &["bgp", "learned_via_ibgp"],
        FieldInfo {
            id: FieldId::BgpLearnedViaIbgp,
            ty: FieldType::Bool,
            mutable: false,
        },
    ),
    (
        &["bgp", "router_id"],
        FieldInfo {
            id: FieldId::BgpRouterId,
            ty: FieldType::OptionalIp,
            mutable: false,
        },
    ),
    (
        &["bgp", "originator_id"],
        FieldInfo {
            id: FieldId::BgpOriginatorId,
            ty: FieldType::OptionalIp,
            mutable: false,
        },
    ),
    (
        &["bgp", "cluster_list"],
        FieldInfo {
            id: FieldId::BgpClusterList,
            ty: FieldType::ListIp,
            mutable: false,
        },
    ),
    (
        &["bgp", "communities"],
        FieldInfo {
            id: FieldId::BgpCommunities,
            ty: FieldType::ListCommunity,
            mutable: true,
        },
    ),
    (
        &["bgp", "extended_communities"],
        FieldInfo {
            id: FieldId::BgpExtCommunities,
            ty: FieldType::ListExtCommunity,
            mutable: true,
        },
    ),
    (
        &["bgp", "large_communities"],
        FieldInfo {
            id: FieldId::BgpLargeCommunities,
            ty: FieldType::ListLargeCommunity,
            mutable: true,
        },
    ),
    (
        &["bgp", "validation_state"],
        FieldInfo {
            id: FieldId::BgpValidationState,
            ty: FieldType::Enum("rpki"),
            mutable: false,
        },
    ),
    (
        &["bgp", "rd"],
        FieldInfo {
            id: FieldId::BgpRd,
            ty: FieldType::OptionalRd,
            mutable: false,
        },
    ),
    (
        &["bgp", "local_role"],
        FieldInfo {
            id: FieldId::BgpLocalRole,
            ty: FieldType::OptionalEnum("role"),
            mutable: false,
        },
    ),
    (
        &["bgp", "remote_role"],
        FieldInfo {
            id: FieldId::BgpRemoteRole,
            ty: FieldType::OptionalEnum("role"),
            mutable: false,
        },
    ),
    (
        &["bgp", "otc"],
        FieldInfo {
            id: FieldId::BgpOtc,
            ty: FieldType::OptionalInt,
            mutable: false,
        },
    ),
];

/// Looks up the longest field path that is a prefix of `segments`, returning
/// the matched field plus how many leading segments it consumed. The
/// remaining (unconsumed) segments, if any, are a suffix operation
/// (`.length`/`.contains(..)`) for `check.rs` to resolve separately.
pub fn resolve_field(segments: &[String]) -> Option<(&'static FieldInfo, usize)> {
    FIELDS
        .iter()
        .filter(|(path, _)| {
            path.len() <= segments.len() && path.iter().zip(segments.iter()).all(|(p, s)| p == s)
        })
        .map(|(path, info)| (info, path.len()))
        .max_by_key(|(_, len)| *len)
}
