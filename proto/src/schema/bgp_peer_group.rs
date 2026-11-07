use garde::Validate;
use serde::{Deserialize, Serialize};

use super::Config;
use crate::validators::bfd_reference_valid;
use nos_proto_derive::Cli;

use super::sugar;

/// Which NLRI (AFI/SAFI) is exchanged over a peer-group's session —
/// independent of whatever address family `source_address` resolves to at
/// runtime, or a peer's `remote_address`. RFC 8950's extended next-hop
/// encoding allows an IPv6-transport session to carry IPv4 unicast NLRI, so
/// this must never be derived from, or cross-validated against, either
/// address's IP version.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Cli)]
pub enum AddressFamily {
    #[cli(words = "ipv4")]
    /// Unicast IPv4 (AFI 1, SAFI 1).
    Ipv4Unicast,
    #[cli(words = "ipv6")]
    /// Unicast IPv6 (AFI 2, SAFI 1).
    Ipv6Unicast,
    /// RFC 7432 EVPN (AFI 25 / SAFI 70). Appended last: postcard indexes
    /// enum variants by position.
    L2vpnEvpn,
    #[cli(words = "ipv4-flowspec")]
    /// RFC 8955 IPv4 Flowspec (AFI 1 / SAFI 133).
    Ipv4Flowspec,
    #[cli(words = "ipv6-flowspec")]
    /// RFC 8956 IPv6 Flowspec (AFI 2 / SAFI 133).
    Ipv6Flowspec,
    #[cli(words = "vpnv4")]
    /// RFC 4364 VPN-IPv4 unicast (AFI 1 / SAFI 128).
    Vpnv4Unicast,
    #[cli(words = "vpnv6")]
    /// RFC 4659 VPN-IPv6 unicast (AFI 2 / SAFI 128).
    Vpnv6Unicast,
    #[cli(words = "rt-constraint")]
    /// RFC 4684 Route Target Constraint (AFI 1 / SAFI 132): only the VPN and
    /// EVPN routes the peer asked for are sent. Needs a VPN or EVPN family.
    RtConstraint,
}

impl AddressFamily {
    /// Every variant, in declaration order.
    pub const ALL: [AddressFamily; 8] = [
        AddressFamily::Ipv4Unicast,
        AddressFamily::Ipv6Unicast,
        AddressFamily::L2vpnEvpn,
        AddressFamily::Ipv4Flowspec,
        AddressFamily::Ipv6Flowspec,
        AddressFamily::Vpnv4Unicast,
        AddressFamily::Vpnv6Unicast,
        AddressFamily::RtConstraint,
    ];

    /// The CLI spelling of the family.
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressFamily::Ipv4Unicast => "ipv4",
            AddressFamily::Ipv6Unicast => "ipv6",
            AddressFamily::L2vpnEvpn => "l2vpn-evpn",
            AddressFamily::Ipv4Flowspec => "ipv4-flowspec",
            AddressFamily::Ipv6Flowspec => "ipv6-flowspec",
            AddressFamily::Vpnv4Unicast => "vpnv4",
            AddressFamily::Vpnv6Unicast => "vpnv6",
            AddressFamily::RtConstraint => "rt-constraint",
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A peer-group's transport source address, referenced by interface + label
/// rather than a literal `IpAddr` — resolved to an actual address by
/// `nos-bgpd` at runtime (querying `nos-interfaced`, the same way a
/// `BgpInstance.routing_table` reference resolves to a VRF name via
/// `nos-ribd`), never here. `label` disambiguates which of an interface's
/// addresses to use when it carries more than one; `None` requires the
/// interface to carry exactly one address.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum SourceAddress {
    /// An explicitly named interface.
    Interface {
        /// Interface whose address becomes the session's local address.
        interface: String,
        /// Selects one of the interface's addresses; `None` requires exactly one.
        label: Option<String>,
    },
    /// This peer-group's owning `BgpInstance`'s own loopback interface
    /// (`loopback-<table>`, where `<table>` is that instance's
    /// `routing_table`) — so no interface name needs to be spelled out.
    /// Invalid (an error, not a fallback) for an instance with no owning
    /// routing table, exactly like `BgpInstance.routing_table` itself.
    Loopback {
        /// Selects one of the loopback's addresses; `None` requires exactly one.
        label: Option<String>,
    },
}

impl std::fmt::Display for SourceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceAddress::Interface { interface, label } => {
                write!(f, "interface {interface}")?;
                if let Some(label) = label {
                    write!(f, " label {label}")?;
                }
                Ok(())
            }
            SourceAddress::Loopback { label } => {
                write!(f, "loopback")?;
                if let Some(label) = label {
                    write!(f, " label {label}")?;
                }
                Ok(())
            }
        }
    }
}

/// RFC 4271 §6.2: a proposed hold time of 1 or 2 seconds is invalid — it
/// must be exactly 0 (disables the hold timer and keepalives entirely) or
/// at least 3. Shared with `nos-bgp::fsm`, which applies the identical rule
/// to the *remote* peer's proposed hold time in its OPEN message.
pub const HOLD_TIME_FLOOR: u16 = 3;

/// This instance's own proposed hold time when a peer-group leaves
/// `hold_time` unset. Sits at the fast end of common router defaults (many
/// ship 90-180s).
pub const HOLD_TIME_DEFAULT: u16 = 90;

/// RFC 4271's own suggested `ConnectRetryTimer` default, used when a
/// peer-group leaves `connect_retry_time` unset.
pub const CONNECT_RETRY_TIME_DEFAULT_SECS: u16 = 120;

/// RFC 7313 §4 default upper bound on how long routes stay stale after a
/// `BoRR` with no `EoRR` (`BgpPeerGroup.route_refresh_stale_time`): the
/// stale-path default FRR and Cisco use for graceful restart.
pub const ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS: u16 = 360;

/// Controls the `NEXT_HOP` path attribute this instance writes into every
/// UPDATE it advertises to a peer-group's sessions. `SelfAddress` rewrites it
/// to the session's own local address ("next-hop-self"); `Unchanged`
/// preserves the next-hop the route already carries (the address it was
/// received with, for a peer-learned route). `BgpPeerGroup.next_hop: None`
/// resolves to `SelfAddress` for an eBGP peer-group and `Unchanged` for an
/// iBGP or route-server-client one — standard BGP practice, since an iBGP speaker must not silently
/// mask a route's real eBGP-learned next-hop unless explicitly told to.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum NextHopMode {
    #[cli(words = "self")]
    /// Rewrite `NEXT_HOP` to the session's local address.
    SelfAddress,
    /// Keep the `NEXT_HOP` the route already carries.
    Unchanged,
}

/// RFC 9234 §4.1 BGP Role: what this speaker is to the peer. Carried in the
/// OPEN's Role capability (code 9); the pair must be legal (Provider/Customer,
/// RS/RS-Client, Peer/Peer) or the session is refused with Role Mismatch.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum BgpRole {
    /// The local AS is the provider of the peer (RFC 9234).
    Provider,
    /// The local AS runs a route server.
    RouteServer,
    /// The local AS is a client of the peer's route server.
    RouteServerClient,
    /// The local AS is a customer of the peer.
    Customer,
    /// Lateral peering between equals.
    Peer,
}

impl BgpRole {
    /// RFC 9234 §4.1 capability value.
    pub fn wire(self) -> u8 {
        match self {
            BgpRole::Provider => 0,
            BgpRole::RouteServer => 1,
            BgpRole::RouteServerClient => 2,
            BgpRole::Customer => 3,
            BgpRole::Peer => 4,
        }
    }

    /// Parses the RFC 9234 §4.1 capability value; `None` when unassigned.
    pub fn from_wire(v: u8) -> Option<Self> {
        Some(match v {
            0 => BgpRole::Provider,
            1 => BgpRole::RouteServer,
            2 => BgpRole::RouteServerClient,
            3 => BgpRole::Customer,
            4 => BgpRole::Peer,
            _ => return None,
        })
    }

    /// RFC 9234 §4.2 Table 2: the role the *peer* must announce for this
    /// one to be a legal pair.
    #[must_use]
    pub fn counterpart(self) -> Self {
        match self {
            BgpRole::Provider => BgpRole::Customer,
            BgpRole::Customer => BgpRole::Provider,
            BgpRole::RouteServer => BgpRole::RouteServerClient,
            BgpRole::RouteServerClient => BgpRole::RouteServer,
            BgpRole::Peer => BgpRole::Peer,
        }
    }

    /// The CLI spelling of the role.
    pub fn as_str(self) -> &'static str {
        match self {
            BgpRole::Provider => "provider",
            BgpRole::RouteServer => "route-server",
            BgpRole::RouteServerClient => "route-server-client",
            BgpRole::Customer => "customer",
            BgpRole::Peer => "peer",
        }
    }
}

/// RFC 7911 ADD-PATH direction for a peer-group's unicast families: whether
/// this side offers to receive several paths per prefix, send them, or both.
/// What is actually used per family is negotiated against the peer's own
/// capability (RFC 7911 §5).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum BgpAddPath {
    /// Offer to receive several paths per prefix.
    Receive,
    /// Send several paths per prefix.
    Send,
    /// Both receive and send.
    Both,
}

impl BgpAddPath {
    /// The capability's Send/Receive value (RFC 7911 §4): 1 receive, 2
    /// send, 3 both.
    pub fn send_receive(self) -> u8 {
        match self {
            BgpAddPath::Receive => 1,
            BgpAddPath::Send => 2,
            BgpAddPath::Both => 3,
        }
    }

    /// The CLI spelling of the direction.
    pub fn as_str(self) -> &'static str {
        match self {
            BgpAddPath::Receive => "receive",
            BgpAddPath::Send => "send",
            BgpAddPath::Both => "both",
        }
    }
}

/// Administrative shutdown (RFC 4486 Cease/Administrative Shutdown). While set
/// on a peer-group, or on an individual `BgpPeer` (which overrides the group),
/// no session is opened or accepted; an established one is closed with a
/// NOTIFICATION carrying `message` as an RFC 9003 shutdown communication.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BgpShutdown {
    #[cli(topic = BgpPeerGroupShutdown)]
    /// Optional RFC 9003 shutdown communication text carried in the NOTIFICATION.
    pub message: Option<String>,
}

/// RFC 2439 route flap damping of routes received from a peer-group, all times
/// in seconds. A route's penalty rises on each flap, halves every `half_life`,
/// suppresses the route at `>= suppress` and releases it below `reuse`; it
/// never exceeds the ceiling implied by `max_suppress`. `Default` is RFC 7196's
/// conservative recommendation. eBGP peer-groups only (`bgp_instance`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct BgpDamping {
    #[cli(topic = BgpPeerGroupDamping)]
    /// Seconds for the penalty to halve.
    pub half_life: u32,
    #[cli(topic = BgpPeerGroupDamping)]
    /// Penalty below which a suppressed route is released again.
    pub reuse: u32,
    #[cli(topic = BgpPeerGroupDamping)]
    /// Penalty at or above which a route is suppressed.
    pub suppress: u32,
    #[cli(topic = BgpPeerGroupDamping)]
    /// Longest time in seconds a route can stay suppressed.
    pub max_suppress: u32,
}

impl Default for BgpDamping {
    fn default() -> Self {
        Self {
            half_life: 900,
            reuse: 750,
            suppress: 6000,
            max_suppress: 3600,
        }
    }
}

pub(super) fn valid_damping(d: Option<&BgpDamping>) -> garde::Result {
    let Some(d) = d else { return Ok(()) };
    if d.half_life == 0 || d.reuse == 0 || d.suppress <= d.reuse || d.max_suppress < d.half_life {
        return Err(garde::Error::new(
            "damping needs half-life > 0, reuse > 0, suppress > reuse and max-suppress >= half-life",
        ));
    }
    Ok(())
}

/// Vendor `local-as` (IOS/Junos; no RFC): the AS this group's peers see
/// instead of the instance's own (its `asn`, or the confederation
/// identifier). The OPEN carries `asn`; outbound `AS_PATH` gets `[asn, own]`
/// (`[asn]` with `replace_as`); a received path gets `asn` prepended unless
/// `no_prepend`, and holding `asn` counts as a loop for this group's routes.
/// External (non-confederation eBGP) peer-groups only
/// (`bgp_instance::valid_route_reflection_and_server`).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BgpLocalAs {
    #[cli(topic = BgpPeerGroupLocalAs)]
    /// AS number this group's peers see instead of the instance's own; carried in OPEN.
    pub asn: u32,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupLocalAs)]
    /// Do not prepend `asn` to the `AS_PATH` of received routes.
    pub no_prepend: bool,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupLocalAs)]
    /// Advertise `[asn]` only instead of `[asn, own]`.
    pub replace_as: bool,
}

/// One address family's RFC 4486 §4 maximum-prefix limit: more than `limit`
/// accepted (post-import-policy) prefixes from one peer closes the session
/// with Cease/Maximum Number of Prefixes Reached, unless `warning_only`.
/// `restart_interval` (seconds) re-allows the session after that long; `0`
/// keeps the peer down until `clear bgp <instance> <peer>` or a shut/no-shut.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BgpPrefixLimit {
    #[cli(topic = BgpPeerGroupMaximumPrefixLimit)]
    /// Maximum number of prefixes accepted from the peer for the family.
    pub limit: u32,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupMaximumPrefixWarningOnly)]
    /// Log when the limit is exceeded instead of closing the session.
    pub warning_only: bool,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupMaximumPrefixRestartInterval)]
    /// Seconds before a session closed for exceeding `limit` restarts; 0 leaves it down.
    pub restart_interval: u16,
}

/// Per-address-family maximum-prefix limits; `None` means unlimited. A fixed
/// struct rather than a list keyed by `AddressFamily`: the family set is
/// closed, and three fields give the same CLI/REST shape with no enum-keyed
/// list support in the config path grammar.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BgpMaximumPrefix {
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    /// Limit for IPv4 unicast; `None` is unlimited.
    pub ipv4: Option<BgpPrefixLimit>,
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    /// Limit for IPv6 unicast; `None` is unlimited.
    pub ipv6: Option<BgpPrefixLimit>,
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    /// Limit for L2VPN EVPN; `None` is unlimited.
    pub l2vpn_evpn: Option<BgpPrefixLimit>,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    /// Limit for IPv4 Flowspec; `None` is unlimited.
    pub ipv4_flowspec: Option<BgpPrefixLimit>,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    /// Limit for IPv6 Flowspec; `None` is unlimited.
    pub ipv6_flowspec: Option<BgpPrefixLimit>,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    /// Limit for VPN-IPv4; `None` is unlimited.
    pub vpnv4: Option<BgpPrefixLimit>,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    /// Limit for VPN-IPv6; `None` is unlimited.
    pub vpnv6: Option<BgpPrefixLimit>,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    /// Limit for RT-Constraint membership routes; `None` is unlimited.
    pub rt_constraint: Option<BgpPrefixLimit>,
}

impl BgpMaximumPrefix {
    /// The limit configured for `family`.
    pub fn get(&self, family: AddressFamily) -> Option<BgpPrefixLimit> {
        match family {
            AddressFamily::Ipv4Unicast => self.ipv4,
            AddressFamily::Ipv6Unicast => self.ipv6,
            AddressFamily::L2vpnEvpn => self.l2vpn_evpn,
            AddressFamily::Ipv4Flowspec => self.ipv4_flowspec,
            AddressFamily::Ipv6Flowspec => self.ipv6_flowspec,
            AddressFamily::Vpnv4Unicast => self.vpnv4,
            AddressFamily::Vpnv6Unicast => self.vpnv6,
            AddressFamily::RtConstraint => self.rt_constraint,
        }
    }

    /// Mutable access to the limit configured for `family`.
    pub fn slot_mut(&mut self, family: AddressFamily) -> &mut Option<BgpPrefixLimit> {
        match family {
            AddressFamily::Ipv4Unicast => &mut self.ipv4,
            AddressFamily::Ipv6Unicast => &mut self.ipv6,
            AddressFamily::L2vpnEvpn => &mut self.l2vpn_evpn,
            AddressFamily::Ipv4Flowspec => &mut self.ipv4_flowspec,
            AddressFamily::Ipv6Flowspec => &mut self.ipv6_flowspec,
            AddressFamily::Vpnv4Unicast => &mut self.vpnv4,
            AddressFamily::Vpnv6Unicast => &mut self.vpnv6,
            AddressFamily::RtConstraint => &mut self.rt_constraint,
        }
    }
}

/// RFC 9003 §2: the shutdown communication is at most 255 octets of UTF-8.
pub const SHUTDOWN_MESSAGE_MAX: usize = 255;

pub(super) fn valid_shutdown(s: Option<&BgpShutdown>) -> garde::Result {
    match s.and_then(|s| s.message.as_ref()) {
        Some(m) if m.len() > SHUTDOWN_MESSAGE_MAX => Err(garde::Error::new(
            "shutdown message must be at most 255 bytes",
        )),
        _ => Ok(()),
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli, Default)]
#[garde(context(Config as ctx))]
#[allow(clippy::struct_excessive_bools)] // each bool is an independent schema field
/// Session settings shared by every `BgpPeer` that names this group.
pub struct BgpPeerGroup {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_name(n, ctx))
    )]
    #[cli(key)]
    /// Group name, 1 to 64 characters (letters, digits, `_`, `-`), unique within the instance.
    pub name: String,

    // RFC 6793: ASN 0 and 4_294_967_295 are reserved.
    #[garde(range(min = 1, max = 4_294_967_294u32))]
    #[cli(topic = BgpPeerGroupRemoteAs)]
    /// Expected remote AS, 1 to 4294967294; equal to the local ASN means iBGP.
    pub remote_as: u32,

    // Transport source address. Deliberately `#[garde(skip)]` and never
    // cross-validated against `address_families` or a peer's
    // `remote_address` — see `AddressFamily`'s doc comment. Also never
    // cross-validated against `Config.interfaces` — like
    // `BgpInstance.routing_table`'s VRF, the referenced interface is
    // resolved by `nos-bgpd` itself and may not exist yet in this
    // transaction.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupSourceAddress)]
    /// Transport source address, resolved by `nos-bgpd` at runtime; `None` lets the kernel choose.
    pub source_address: Option<SourceAddress>,

    #[garde(custom(|afs, _ctx: &Config| non_empty_no_duplicate_afs(afs)))]
    #[cli(topic = BgpPeerGroupAddressFamily)]
    /// Families to negotiate; non-empty, no duplicates.
    pub address_families: Vec<AddressFamily>,

    /// `None` defaults to `HOLD_TIME_DEFAULT` (90s). `Some(0)` disables both
    /// the hold timer and keepalives entirely; otherwise must be `>=
    /// HOLD_TIME_FLOOR` (RFC 4271 §6.2). The value actually used by a
    /// session is `min(this, the peer's own proposed hold time)`.
    #[garde(custom(|h: &Option<u16>, _ctx: &Config| valid_hold_time(*h)))]
    #[cli(topic = BgpPeerGroupHoldTime)]
    pub hold_time: Option<u16>,

    /// `None` defaults to `negotiated_hold / 3`, computed after negotiation
    /// (RFC 4271's suggested ratio). When both this and `hold_time` are set,
    /// this must be strictly less than `hold_time` — checked one level up,
    /// on `BgpInstance.peer_groups`, since garde's per-field `custom`
    /// closures can't see a sibling field (see `bgp_instance.rs`).
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupKeepaliveInterval)]
    pub keepalive_interval: Option<u16>,

    /// `None` defaults to `CONNECT_RETRY_TIME_DEFAULT_SECS` (120s).
    #[garde(custom(|c: &Option<u16>, _ctx: &Config| valid_connect_retry_time(*c)))]
    #[cli(topic = BgpPeerGroupConnectRetryTime)]
    pub connect_retry_time: Option<u16>,

    /// RFC 4271 §9.2.1.1 `MinRouteAdvertisementInterval`, in seconds: at most
    /// one batch of advertisements per this interval to each peer (withdrawals
    /// are exempt). `None` (or 0) disables pacing — every change is sent at once.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupMrai)]
    pub mrai: Option<u16>,

    /// RFC 7313 §4: seconds routes from a peer stay stale after its `BoRR`
    /// before they're purged as if its `EoRR` had arrived. `None` defaults to
    /// `ROUTE_REFRESH_STALE_TIME_DEFAULT_SECS` (360s); 0 disables the timer.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupRouteRefreshStaleTime)]
    pub route_refresh_stale_time: Option<u16>,

    /// RFC 2439 flap damping of routes received from this group; `None`
    /// disables it. See `BgpDamping`.
    #[garde(custom(|d: &Option<BgpDamping>, _ctx: &Config| valid_damping(d.as_ref())))]
    #[cli(topic = BgpPeerGroupDamping)]
    pub damping: Option<BgpDamping>,

    /// RFC 5082 GTSM: the most router hops away the peer may be (1 =
    /// directly connected, 1..=254). Sends with TTL/hop-limit 255 and drops
    /// received packets below `256 - max_hops`. `None` disables it.
    #[garde(custom(|h: &Option<u8>, _ctx: &Config| valid_max_hops(*h)))]
    #[cli(topic = BgpPeerGroupMaxHops)]
    pub max_hops: Option<u8>,

    /// `None` opens sessions with no transport authentication at all.
    /// Keys are admin-keystore labels, never inline secrets — see `BgpAuth`.
    #[garde(custom(|a: &Option<BgpAuth>, ctx: &Config| valid_auth(a.as_ref(), ctx)))]
    #[cli(topic = BgpPeerGroupAuth, render = sugar::render_bgp_auth, sugar(word = "md5-password", with = sugar::md5_password, topic = BgpPeerGroupMd5Password), sugar(word = "ao-key", with = sugar::ao_key, topic = BgpPeerGroupAoKey))]
    pub auth: Option<BgpAuth>,

    /// Name of a `BfdProfile` to run BFD with; `None` runs no BFD. Not part
    /// of the session identity: adding or removing it never resets a session.
    #[serde(default)]
    #[garde(custom(|b: &Option<String>, ctx: &Config| bfd_reference_valid(b.as_ref(), ctx)))]
    #[cli(topic = BfdReference)]
    pub bfd: Option<String>,

    /// `None` defaults to `SelfAddress` for an eBGP peer-group and
    /// `Unchanged` for an iBGP or `route_server_client` one (RFC 7947
    /// §2.2.1) — see `NextHopMode`.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupNextHop)]
    pub next_hop: Option<NextHopMode>,

    /// RFC 4456 route-reflector client: routes learned from other iBGP
    /// peers are reflected to this peer (and vice versa) instead of being
    /// withheld by the usual iBGP split-horizon rule. Requires this
    /// peer-group's `remote_as` to equal the owning instance's `asn` (an
    /// iBGP peer-group) — checked cross-instance, see
    /// `bgp_instance::valid_route_reflection_and_server`. Mutually exclusive
    /// with `route_server_client`.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupRouteReflectorClient)]
    pub route_reflector_client: bool,

    /// RFC 7947 route-server client: this peer-group's own ASN is never
    /// prepended to `AS_PATH` when advertising to it, and (via RFC 7911
    /// ADD-PATH) it receives every other route-server-client's path for a
    /// prefix, not just the one instance-wide elected best path. Requires
    /// this peer-group's `remote_as` to differ from the owning instance's
    /// `asn` (an eBGP peer-group). Mutually exclusive with
    /// `route_reflector_client`.
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupRouteServerClient)]
    pub route_server_client: bool,

    /// `None` defaults to `deny-all` — this NOS never leaves a direction
    /// unfiltered, unlike every other `Option` field on this struct, which
    /// defaults to some permissive/derived behavior. See root `CLAUDE.md`'s
    /// "Default-deny rollout impact".
    #[garde(custom(|p: &Option<String>, ctx: &Config| policy_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = BgpPeerGroupImportPolicy)]
    pub import_policy: Option<String>,

    /// Same default-deny semantics as `import_policy`, applied on
    /// advertisement instead of receipt.
    #[garde(custom(|p: &Option<String>, ctx: &Config| policy_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = BgpPeerGroupExportPolicy)]
    pub export_policy: Option<String>,

    /// See `BgpShutdown`. Appended last, like every later-added field.
    #[garde(custom(|s: &Option<BgpShutdown>, _ctx: &Config| valid_shutdown(s.as_ref())))]
    #[cli(topic = BgpPeerGroupShutdown, render = sugar::render_shutdown, sugar(word = "shutdown", with = sugar::shutdown, topic = BgpPeerGroupShutdown))]
    pub shutdown: Option<BgpShutdown>,

    /// RFC 4486 §4 per-address-family maximum-prefix limits — see
    /// `BgpPrefixLimit` (`limit 0` = explicitly uncapped). A limit for a family not in `address_families` is
    /// rejected (`valid_peer_group_timers`).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupMaximumPrefix)]
    pub maximum_prefix: BgpMaximumPrefix,

    /// RFC 8097: send each route's RPKI origin validation state to these
    /// peers as a non-transitive extended community, and take the state
    /// from theirs while this instance has no VRP data of its own. iBGP
    /// peer-groups only (`bgp_instance::valid_route_reflection_and_server`).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupAnnounceRpkiState)]
    pub announce_rpki_state: bool,

    /// See `BgpLocalAs`; `None` presents the instance's own AS.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupLocalAs)]
    pub local_as: Option<BgpLocalAs>,

    /// RFC 7911 ADD-PATH for this group's unicast families (`ipv4`/`ipv6`;
    /// never EVPN). `None` is `Both` for a `route_server_client` group and off
    /// otherwise. Carried in the OPEN, so a change restarts the sessions.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupAddPath)]
    pub add_path: Option<BgpAddPath>,

    /// RFC 7911: how many paths per prefix this group is sent when ADD-PATH
    /// send is negotiated: the best N by the decision process, after this
    /// group's own filtering (split horizon, export policy). Unset: 2, or
    /// every path for a route-server client. Needs `add_path` send or both.
    #[serde(default)]
    #[garde(range(min = 2, max = 64))]
    #[cli(topic = BgpPeerGroupAddPathSendCount)]
    pub add_path_send_count: Option<u8>,

    /// RFC 9234 BGP Role this group's peers are to us — see `BgpRole`. eBGP
    /// only; a change restarts the sessions (it is in the OPEN).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupRole)]
    pub role: Option<BgpRole>,

    /// RFC 9234 §4.2 strict mode: refuse (Role Mismatch) a peer whose OPEN
    /// carries no Role capability. Needs `role`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupStrictMode)]
    pub strict_mode: bool,

    /// Accept/reject filter for EVPN routes received from this group's
    /// peers (Type-1/2/3/5; Type-4 bypasses it). Unlike `import_policy`,
    /// `None` accepts every EVPN route, so existing deployments keep
    /// working. Rewrites are ignored.
    #[serde(default)]
    #[garde(custom(|p: &Option<String>, ctx: &Config| policy_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = BgpPeerGroupEvpnImportPolicy)]
    pub evpn_import_policy: Option<String>,

    /// RFC 4271 §6.3 first-AS check: on an eBGP session, an UPDATE whose
    /// `AS_PATH` does not start with the peer's AS is treated as a withdraw.
    /// `None` is on. A `route_server_client` group is always exempt (RFC 7947
    /// §2.2.2.1).
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupEnforceFirstAs)]
    pub enforce_first_as: Option<bool>,

    /// RFC 8955 §6 Flowspec validation tuning. Validation itself cannot be
    /// switched off.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupFlowspecValidation)]
    pub flowspec_validation: BgpFlowspecValidation,

    /// Policy applied to valid Flowspec rules received from this group's
    /// peers before best-path selection. Like `evpn_import_policy`, `None`
    /// accepts every rule; rewrites are honoured.
    #[serde(default)]
    #[garde(custom(|p: &Option<String>, ctx: &Config| policy_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = BgpPeerGroupFlowspecImportPolicy)]
    pub flowspec_import_policy: Option<String>,

    /// Policy applied to Flowspec rules advertised to this group's peers.
    /// `None` advertises every selected rule.
    #[serde(default)]
    #[garde(custom(|p: &Option<String>, ctx: &Config| policy_reference_valid(p.as_ref(), ctx)))]
    #[cli(topic = BgpPeerGroupFlowspecExportPolicy)]
    pub flowspec_export_policy: Option<String>,

    /// Keep every route received from this group's peers before import
    /// policy, so a policy change is re-evaluated locally without a session
    /// reset or Route Refresh. Costs roughly one extra copy of the peer's
    /// Adj-RIB-In.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupSoftReconfigurationInbound)]
    pub soft_reconfiguration_inbound: bool,

    /// RFC 8326 sender side: tag every route exchanged with this group's
    /// eBGP peers with `GRACEFUL_SHUTDOWN` (65535:0) and demote what they send
    /// to `LOCAL_PREF` 0, so traffic drains before a `shutdown`. eBGP only
    /// (`bgp_instance::valid_route_reflection_and_server`). Applied live.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupGracefulShutdown)]
    pub graceful_shutdown: bool,

    /// RFC 8326 §4.1 receiver side is on by default (an eBGP path carrying
    /// 65535:0 gets `LOCAL_PREF` 0); `true` turns it off. Applied live.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpPeerGroupGracefulShutdownReceiveDisabled, words = "graceful-shutdown-receive disable")]
    pub graceful_shutdown_receive_disabled: bool,

    /// RFC 7999 BLACKHOLE handling for this group's peers; `None` leaves the
    /// community an ordinary one. See `BgpBlackhole`. eBGP only.
    #[serde(default)]
    #[garde(custom(|b: &Option<BgpBlackhole>, ctx: &Config| valid_blackhole(b.as_ref(), ctx)))]
    #[cli(topic = BgpPeerGroupBlackhole)]
    pub blackhole: Option<BgpBlackhole>,
}

/// RFC 7999 remotely triggered blackhole: a unicast route from this group's
/// peers that carries BLACKHOLE (65535:666) and falls inside `prefix_list`
/// (the authorisation, with normal prefix-list `range` rules: write
/// `10.0.0.0/8 upto 32` to cover host routes) is tagged `NO_EXPORT` and, once
/// best, installed as a discard route. It still runs through `import_policy`,
/// which under the default deny-all must accept it. eBGP peer-groups only.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BgpBlackhole {
    #[cli(topic = BgpPeerGroupBlackhole)]
    /// Name of the `PrefixList` bounding which prefixes the peer may blackhole.
    pub prefix_list: String,
}

pub(super) fn valid_blackhole(b: Option<&BgpBlackhole>, ctx: &Config) -> garde::Result {
    match b {
        Some(b) if !ctx.prefix_lists.iter().any(|p| p.name == b.prefix_list) => {
            Err(garde::Error::new("referenced prefix-list does not exist"))
        }
        _ => Ok(()),
    }
}

/// Knobs of the Flowspec validation procedure (RFC 8955 §6 as updated by
/// RFC 9117, which is the default).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli, Default)]
pub struct BgpFlowspecValidation {
    #[serde(default)]
    #[cli(topic = BgpPeerGroupFlowspecValidation)]
    /// Rule (a) of RFC 8955 §6 is not enforced: a flow without a destination
    /// prefix is accepted (the unicast checks (b) and (c) then do not apply).
    pub disable_dest_prefix_rule: bool,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupFlowspecValidation)]
    /// Validate as RFC 8955 §6 is written instead of RFC 9117: no (b.2)
    /// exemption for flows with an empty or confederation-only `AS_PATH`, and
    /// the eBGP check compares the flow's leftmost AS with the neighbour's.
    pub rfc8955_strict: bool,
}

impl BgpPeerGroup {
    /// `add_path` with its default applied: `Both` for a route-server client.
    pub fn effective_add_path(&self) -> Option<BgpAddPath> {
        self.add_path
            .or(self.route_server_client.then_some(BgpAddPath::Both))
    }

    /// How many paths per prefix an ADD-PATH send peer of this group gets:
    /// `add_path_send_count`, else `default_add_path_send_count`. `None` is
    /// every path.
    pub fn effective_add_path_send_count(&self) -> Option<usize> {
        self.add_path_send_count.map_or_else(
            || Self::default_add_path_send_count(self.route_server_client),
            |n| Some(usize::from(n)),
        )
    }

    /// The unset `add_path_send_count`: every path for a route-server client
    /// (RFC 7947 transparency), 2 (best plus one backup) otherwise.
    pub fn default_add_path_send_count(route_server_client: bool) -> Option<usize> {
        (!route_server_client).then_some(2)
    }
}

/// `"accept-all"`/`"deny-all"` are always valid regardless of what's
/// configured — see `nos_rpl::ACCEPT_ALL_NAME`/`DENY_ALL_NAME`. Any other
/// name must match a real `PolicyDefinition`.
fn policy_reference_valid(name: Option<&String>, ctx: &Config) -> garde::Result {
    let Some(name) = name else {
        return Ok(());
    };
    if name == nos_rpl::ACCEPT_ALL_NAME || name == nos_rpl::DENY_ALL_NAME {
        return Ok(());
    }
    if ctx.policy_definitions.iter().any(|p| &p.name == name) {
        Ok(())
    } else {
        Err(garde::Error::new("referenced policy does not exist"))
    }
}

/// Transport authentication for a peer-group's sessions — mutually
/// exclusive mechanisms, matching the kernel (a socket can carry
/// `TCP_MD5SIG` or TCP-AO keys, never both at once). Keys are labels of
/// `Config.admin` keystore entries; the secret itself never appears here.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum BgpAuth {
    /// RFC 2385 TCP MD5 signature — a single shared password.
    Md5 {
        /// Label of the admin key the TCP MD5 signature option is keyed with.
        key_ref: String,
    },
    /// RFC 5925 TCP Authentication Option — one or more keys, supporting
    /// rotation via `send_id`/`recv_id` and the `is_current`/`is_rnext`
    /// flags.
    Ao {
        /// The keychain; `is_current` and `is_rnext` drive rotation.
        keys: Vec<BgpAoKey>,
    },
}

/// One TCP-AO key. `send_id`/`recv_id` identify it on the wire (RFC 5925's
/// `KeyID`/`RNextKeyID`); `is_current` marks the key a new connection starts
/// signing with (exactly one key must have this set; on a live session the
/// peer's `RNextKeyID` decides, RFC 5925 §7.5.2); `is_rnext` optionally asks
/// the peer to switch to this key next, for rotation without a dropped
/// session (applied to the live session in place); `exclude_options` (RFC 5925 §5.2, `#[serde(default)]`
/// so pre-existing on-disk config still loads as today's always-include
/// behavior) excludes TCP options from this key's MAC coverage — both peers
/// must agree, or authentication fails.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
#[cli(no_default)]
pub struct BgpAoKey {
    #[cli(key)]
    /// `SendID`: the `KeyID` this side puts in the TCP-AO option (0 to 255); the list key.
    pub send_id: u8,
    #[cli(topic = BgpPeerGroupAoKey)]
    /// `RecvID`: the `KeyID` expected in the peer's TCP-AO option.
    pub recv_id: u8,
    #[cli(topic = BgpPeerGroupAoKey)]
    /// MAC algorithm of this key.
    pub algorithm: BgpAoAlgorithm,
    #[cli(topic = BgpPeerGroupAoKey)]
    /// Label of the admin key holding the master key.
    pub key_ref: String,
    #[cli(topic = BgpPeerGroupAoKey)]
    /// Whether this key signs outgoing segments.
    pub is_current: bool,
    #[cli(topic = BgpPeerGroupAoKey)]
    /// Whether this key is advertised as the next one to switch to (`RNextKeyID`).
    pub is_rnext: bool,
    #[serde(default)]
    #[cli(topic = BgpPeerGroupAoKey)]
    /// Leave TCP options out of the MAC computation.
    pub exclude_options: bool,
}

/// RFC 5925's two mandatory-to-implement algorithms.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub enum BgpAoAlgorithm {
    #[cli(words = "hmac-sha1")]
    /// HMAC-SHA-1 truncated to 96 bits (RFC 5926).
    HmacSha1_96,
    #[cli(words = "aes-cmac")]
    /// AES-128-CMAC truncated to 96 bits (RFC 5926).
    AesCmac96,
}

/// Maximum key/password length accepted by Linux's `TCP_MD5SIG`/TCP-AO
/// socket options (`TCP_MD5SIG_MAXKEYLEN`/`TCP_AO_MAXKEYLEN`, both 80).
const MAX_AUTH_KEY_LEN: usize = 80;

/// The referenced admin secret must exist and fit the kernel's key limit.
fn valid_key_ref(label: &str, cfg: &Config, what: &str) -> garde::Result {
    match cfg.key(label) {
        None => Err(garde::Error::new(format!(
            "{what} references unknown admin key '{label}'"
        ))),
        Some(s) if s.is_empty() || s.len() > MAX_AUTH_KEY_LEN => Err(garde::Error::new(format!(
            "admin key '{label}' must be 1 to 80 bytes long to be used as an {what}"
        ))),
        Some(_) => Ok(()),
    }
}

pub(crate) fn valid_auth(auth: Option<&BgpAuth>, cfg: &Config) -> garde::Result {
    match auth {
        None => Ok(()),
        Some(BgpAuth::Md5 { key_ref }) => valid_key_ref(key_ref, cfg, "md5 password"),
        Some(BgpAuth::Ao { keys }) => {
            if keys.is_empty() {
                return Err(garde::Error::new(
                    "ao auth must have at least one key (or be cleared)",
                ));
            }
            let mut seen_send_ids: Vec<u8> = Vec::new();
            let mut seen_recv_ids: Vec<u8> = Vec::new();
            let mut current_count = 0;
            let mut rnext_count = 0;
            for key in keys {
                valid_key_ref(&key.key_ref, cfg, "ao key")?;
                if seen_send_ids.contains(&key.send_id) {
                    return Err(garde::Error::new(
                        "ao key send-id must be unique within a peer-group",
                    ));
                }
                seen_send_ids.push(key.send_id);
                // RFC 5925 §3.1: the kernel refuses (EEXIST) overlapping
                // RecvIDs just like SendIDs, at socket time otherwise.
                if seen_recv_ids.contains(&key.recv_id) {
                    return Err(garde::Error::new(
                        "ao key recv-id must be unique within a peer-group",
                    ));
                }
                seen_recv_ids.push(key.recv_id);
                if key.is_current {
                    current_count += 1;
                }
                if key.is_rnext {
                    rnext_count += 1;
                }
            }
            if current_count != 1 {
                return Err(garde::Error::new(
                    "ao auth must have exactly one current key",
                ));
            }
            if rnext_count > 1 {
                return Err(garde::Error::new("ao auth must have at most one rnext key"));
            }
            Ok(())
        }
    }
}

/// Peer-group names are unique across the whole config, not just within the
/// owning instance — garde's validation context is fixed as `&Config` for
/// the whole dive chain, so this is the simplest correct scoping, and a
/// name collision is a real conflict regardless of which instance either
/// group belongs to.
fn unique_name(name: &str, ctx: &Config) -> garde::Result {
    let count = ctx
        .bgp_instances
        .iter()
        .flat_map(|i| &i.peer_groups)
        .filter(|g| g.name == name)
        .count();
    if count > 1 {
        return Err(garde::Error::new("must be unique"));
    }
    Ok(())
}

fn non_empty_no_duplicate_afs(afs: &[AddressFamily]) -> garde::Result {
    if afs.is_empty() {
        return Err(garde::Error::new(
            "must include at least one address family",
        ));
    }
    let mut seen: Vec<AddressFamily> = Vec::new();
    for af in afs {
        if seen.contains(af) {
            return Err(garde::Error::new("address families must not repeat"));
        }
        seen.push(*af);
    }
    Ok(())
}

fn valid_hold_time(hold_time: Option<u16>) -> garde::Result {
    match hold_time {
        None | Some(0) => Ok(()),
        Some(h) if h >= HOLD_TIME_FLOOR => Ok(()),
        Some(_) => Err(garde::Error::new("hold-time must be 0 or >= 3")),
    }
}

fn valid_connect_retry_time(connect_retry_time: Option<u16>) -> garde::Result {
    match connect_retry_time {
        None | Some(1..=u16::MAX) => Ok(()),
        Some(0) => Err(garde::Error::new(
            "connect-retry-time must be at least 1 second",
        )),
    }
}

fn valid_max_hops(max_hops: Option<u8>) -> garde::Result {
    match max_hops {
        None | Some(1..=254) => Ok(()),
        Some(_) => Err(garde::Error::new("max-hops must be between 1 and 254")),
    }
}

/// Cross-field check for a `BgpInstance`'s whole `peer_groups` list — garde's
/// per-field `custom` closures only ever see `(field_value, &Config)`, never
/// a sibling field on the same struct, so this must be wired on
/// `BgpInstance.peer_groups` rather than on either field here (mirrors
/// `static_routing_instance::unique_subnets`'s technique of validating a
/// whole `Vec<Item>` to reach a sibling field).
///
/// `keepalive_interval` must be strictly less than `hold_time` whenever both
/// are explicitly set. This is applied uniformly even when `hold_time` is
/// explicitly `Some(0)` — since `keepalive_interval: u16` can never be less
/// than 0, the only combination that satisfies the inequality with
/// `hold_time: Some(0)` is `keepalive_interval: None`, so hold-time-disables
/// keepalives falls out of the one rule with no special case needed.
pub(crate) fn valid_peer_group_timers(groups: &[BgpPeerGroup], ctx: &Config) -> garde::Result {
    for group in groups {
        if let (Some(hold), Some(keepalive)) = (group.hold_time, group.keepalive_interval)
            && keepalive >= hold
        {
            return Err(garde::Error::new(
                "keepalive-interval must be less than hold-time when both are set \
                     (hold-time 0 requires keepalive-interval to be left unset)",
            ));
        }
        if AddressFamily::ALL.iter().any(|af| {
            group.maximum_prefix.get(*af).is_some() && !group.address_families.contains(af)
        }) {
            return Err(garde::Error::new(
                "maximum-prefix is set for an address family the peer-group does not negotiate",
            ));
        }
        if group
            .address_families
            .contains(&AddressFamily::RtConstraint)
            && ![
                AddressFamily::Vpnv4Unicast,
                AddressFamily::Vpnv6Unicast,
                AddressFamily::L2vpnEvpn,
            ]
            .iter()
            .any(|af| group.address_families.contains(af))
        {
            return Err(garde::Error::new(format!(
                "peer-group '{}' enables rt-constraint without vpnv4, vpnv6 or l2vpn-evpn: \
                 there is nothing to constrain",
                group.name
            )));
        }
        valid_next_hop_family(group, ctx)?;
    }
    Ok(())
}

/// An IPv6-unicast group whose import/export policy sets an IPv4 next-hop
/// literal on every path would have it ignored (import) or the route dropped
/// (export) for every IPv6 prefix: reject it. Guarded `set`s are not
/// decidable here and fall to the runtime guard in `nos-bgpd`.
fn valid_next_hop_family(group: &BgpPeerGroup, ctx: &Config) -> garde::Result {
    if !group.address_families.contains(&AddressFamily::Ipv6Unicast) {
        return Ok(());
    }
    for (dir, name) in [
        ("import", &group.import_policy),
        ("export", &group.export_policy),
    ] {
        let Some(def) = name
            .as_ref()
            .and_then(|n| ctx.policy_definitions.iter().find(|p| &p.name == n))
        else {
            continue;
        };
        if let Some(ip @ std::net::IpAddr::V4(_)) = nos_rpl::unconditional_next_hop(&def.source) {
            return Err(garde::Error::new(format!(
                "peer-group '{}' negotiates ipv6 but its {dir} policy sets next-hop {ip} (IPv4) on every route; \
                 guard it with a prefix condition or use an IPv6 address",
                group.name
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::schema::{BgpInstance, Config};

    use super::*;

    fn instance_with_groups(name: &str, groups: Vec<BgpPeerGroup>) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn: 65000,
            peer_groups: groups,
            peers: Vec::new(),
            cluster_id: None,
            maximum_paths: None,
            confederation: crate::schema::BgpConfederation::default(),
            rpki_caches: Vec::new(),
            bmp_stations: Vec::new(),
            aggregates: Vec::new(),
            graceful_restart: crate::schema::BgpGracefulRestart::default(),
            routing_table: None,
            redistribute_policy: None,
        }
    }

    fn group(name: &str, remote_as: u32, afs: Vec<AddressFamily>) -> BgpPeerGroup {
        BgpPeerGroup {
            bfd: None,
            name: name.to_string(),
            remote_as,
            source_address: None,
            address_families: afs,
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
            mrai: None,
            route_refresh_stale_time: None,
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            route_reflector_client: false,
            route_server_client: false,
            import_policy: None,
            export_policy: None,
            evpn_import_policy: None,
            enforce_first_as: None,
            flowspec_validation: BgpFlowspecValidation::default(),
            flowspec_import_policy: None,
            flowspec_export_policy: None,
            shutdown: None,
            maximum_prefix: crate::schema::BgpMaximumPrefix::default(),
            announce_rpki_state: false,
            soft_reconfiguration_inbound: false,
            graceful_shutdown: false,
            graceful_shutdown_receive_disabled: false,
            blackhole: None,
            local_as: None,
            add_path: None,
            add_path_send_count: None,
            role: None,
            strict_mode: false,
        }
    }

    /// Admin keystore holding the `secret` and `k` labels the auth tests reference.
    fn keystore() -> crate::schema::Admin {
        let key = |l: &str, s: &str| crate::schema::AdminKey {
            label: l.to_string(),
            secret: s.to_string(),
        };
        crate::schema::Admin {
            keys: vec![key("secret", "s3cr3t"), key("k", "kk")],
        }
    }

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            admin: keystore(),
            ..Default::default()
        }
    }

    #[test]
    fn maximum_prefix_needs_a_negotiated_family_and_a_zero_limit_means_uncapped() {
        let check = |family: AddressFamily, limit: u32| {
            let mut g = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
            *g.maximum_prefix.slot_mut(family) = Some(BgpPrefixLimit {
                limit,
                ..Default::default()
            });
            let cfg = config_with(vec![instance_with_groups("r1", vec![g])]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(AddressFamily::Ipv4Unicast, 1));
        assert!(check(AddressFamily::Ipv4Unicast, 0), "limit 0 = uncapped");
        assert!(!check(AddressFamily::Ipv6Unicast, 5), "ipv6 not negotiated");
        assert!(!check(AddressFamily::L2vpnEvpn, 5), "evpn not negotiated");
    }

    #[test]
    fn valid_group_passes() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group("pg1", 65001, vec![AddressFamily::Ipv4Unicast])],
        )]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn remote_as_zero_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group("pg1", 0, vec![AddressFamily::Ipv4Unicast])],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn remote_as_max_reserved_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group(
                "pg1",
                4_294_967_295,
                vec![AddressFamily::Ipv4Unicast],
            )],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn empty_address_families_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group("pg1", 65001, vec![])],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_address_family_fails() {
        let cfg = config_with(vec![instance_with_groups(
            "r1",
            vec![group(
                "pg1",
                65001,
                vec![AddressFamily::Ipv4Unicast, AddressFamily::Ipv4Unicast],
            )],
        )]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn duplicate_name_fails_across_different_instances() {
        let cfg = config_with(vec![
            instance_with_groups(
                "r1",
                vec![group("pg1", 65001, vec![AddressFamily::Ipv4Unicast])],
            ),
            instance_with_groups(
                "r2",
                vec![group("pg1", 65002, vec![AddressFamily::Ipv4Unicast])],
            ),
        ]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_names_across_instances_pass() {
        let cfg = config_with(vec![
            instance_with_groups(
                "r1",
                vec![group("pg1", 65001, vec![AddressFamily::Ipv4Unicast])],
            ),
            instance_with_groups(
                "r2",
                vec![group("pg2", 65002, vec![AddressFamily::Ipv4Unicast])],
            ),
        ]);
        cfg.validate_with(&cfg).unwrap();
    }

    /// RFC 8950: an IPv6-transport session may carry IPv4 unicast NLRI.
    /// `source_address`'s resolved IP version must never constrain
    /// `address_families`.
    #[test]
    fn source_address_never_constrains_address_family() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.source_address = Some(SourceAddress::Interface {
            interface: "eth0".to_string(),
            label: None,
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn loopback_source_address_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.source_address = Some(SourceAddress::Loopback {
            label: Some("mgmt".to_string()),
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn hold_time_one_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(1);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn hold_time_two_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(2);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn hold_time_zero_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(0);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn hold_time_three_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(3);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn connect_retry_time_zero_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.connect_retry_time = Some(0);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn connect_retry_time_one_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.connect_retry_time = Some(1);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn keepalive_equal_to_hold_time_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(30);
        pg.keepalive_interval = Some(30);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn keepalive_less_than_hold_time_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(30);
        pg.keepalive_interval = Some(10);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn keepalive_with_hold_time_zero_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(0);
        pg.keepalive_interval = Some(0);
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn keepalive_unset_with_hold_time_zero_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.hold_time = Some(0);
        pg.keepalive_interval = None;
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    fn ao_key(send_id: u8, is_current: bool) -> BgpAoKey {
        BgpAoKey {
            send_id,
            recv_id: send_id,
            algorithm: BgpAoAlgorithm::HmacSha1_96,
            key_ref: "secret".to_string(),
            is_current,
            is_rnext: false,
            exclude_options: false,
        }
    }

    #[test]
    fn md5_password_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Md5 {
            key_ref: "secret".to_string(),
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn md5_with_unknown_label_fails_naming_the_label() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Md5 {
            key_ref: "nope".to_string(),
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        let err = cfg.validate_with(&cfg).unwrap_err().to_string();
        assert!(err.contains("nope"), "{err}");
    }

    #[test]
    fn ao_with_unknown_label_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        let mut key = ao_key(1, true);
        key.key_ref = "nope".to_string();
        pg.auth = Some(BgpAuth::Ao { keys: vec![key] });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn deleting_a_referenced_admin_key_fails_but_an_unreferenced_one_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Md5 {
            key_ref: "secret".to_string(),
        });
        let mut cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.admin.keys.retain(|k| k.label != "k");
        cfg.validate_with(&cfg).unwrap();
        cfg.admin.keys.retain(|k| k.label != "secret");
        let err = cfg.validate_with(&cfg).unwrap_err().to_string();
        assert!(err.contains("secret"), "{err}");
    }

    #[test]
    fn debug_of_auth_shows_the_label_only() {
        let auth = BgpAuth::Md5 {
            key_ref: "lbl".to_string(),
        };
        assert!(format!("{auth:?}").contains("lbl"));
        assert!(!format!("{:?}", keystore()).contains("s3cr3t"));
    }

    #[test]
    fn ao_with_one_current_key_passes() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![ao_key(1, true)],
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn ao_with_no_keys_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Ao { keys: vec![] });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ao_with_no_current_key_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![ao_key(1, false)],
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ao_with_two_current_keys_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![ao_key(1, true), ao_key(2, true)],
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ao_with_duplicate_send_id_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![ao_key(1, true), ao_key(1, false)],
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn ao_with_duplicate_recv_id_fails() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        let mut second = ao_key(2, false);
        second.recv_id = 1;
        pg.auth = Some(BgpAuth::Ao {
            keys: vec![ao_key(1, true), second],
        });
        let cfg = config_with(vec![instance_with_groups("r1", vec![pg])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn add_path_defaults_to_both_for_a_route_server_client_only() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        assert_eq!(pg.effective_add_path(), None);
        pg.route_server_client = true;
        assert_eq!(pg.effective_add_path(), Some(BgpAddPath::Both));
        pg.add_path = Some(BgpAddPath::Receive);
        assert_eq!(pg.effective_add_path(), Some(BgpAddPath::Receive));
    }

    #[test]
    fn role_wire_and_counterpart() {
        for v in 0..=4 {
            let r = BgpRole::from_wire(v).unwrap();
            assert_eq!(r.wire(), v);
            assert_eq!(r.counterpart().counterpart(), r);
        }
        assert_eq!(BgpRole::from_wire(5), None);
        assert_eq!(BgpRole::Provider.counterpart(), BgpRole::Customer);
        assert_eq!(BgpRole::Peer.counterpart(), BgpRole::Peer);
    }

    // ---- rejecting cases (#360) ----

    #[test]
    fn damping_rejects_each_bad_field_and_accepts_the_boundaries() {
        assert!(valid_damping(None).is_ok());
        assert!(valid_damping(Some(&BgpDamping::default())).is_ok());
        let d = BgpDamping::default();
        let bad = [
            BgpDamping { half_life: 0, ..d },
            BgpDamping { reuse: 0, ..d },
            BgpDamping {
                suppress: d.reuse,
                ..d
            },
            BgpDamping {
                suppress: d.reuse - 1,
                ..d
            },
            BgpDamping {
                max_suppress: d.half_life - 1,
                ..d
            },
        ];
        for b in bad {
            assert!(valid_damping(Some(&b)).is_err(), "{b:?}");
        }
        let edge = BgpDamping {
            half_life: 1,
            reuse: 1,
            suppress: 2,
            max_suppress: 1,
        };
        assert!(valid_damping(Some(&edge)).is_ok());
    }

    #[test]
    fn unconditional_v4_next_hop_on_ipv6_group_is_rejected() {
        let check = |src: &str, afs: Vec<AddressFamily>| {
            let mut g = group("pg1", 65001, afs);
            g.export_policy = Some("p".to_string());
            let mut cfg = config_with(vec![instance_with_groups("r1", vec![g])]);
            cfg.policy_definitions = vec![crate::schema::PolicyDefinition {
                name: "p".to_string(),
                source: src.to_string(),
            }];
            cfg.validate_with(&cfg).is_ok()
        };
        let dual = vec![AddressFamily::Ipv4Unicast, AddressFamily::Ipv6Unicast];
        let bad = "set this.bgp.next_hop = 192.0.2.1\naccept\n";
        assert!(!check(bad, dual.clone()));
        assert!(check(bad, vec![AddressFamily::Ipv4Unicast]));
        assert!(check(
            "set this.bgp.next_hop = self\naccept\n",
            dual.clone()
        ));
        let guarded = "if this.prefix in 198.51.100.0/24:\n    set this.bgp.next_hop = 192.0.2.1\n    accept\nelse:\n    accept\n";
        assert!(check(guarded, dual));
    }

    #[test]
    fn policy_reference_must_exist_unless_builtin() {
        let cfg = Config {
            policy_definitions: vec![crate::schema::PolicyDefinition {
                name: "mine".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let s = |s: &str| s.to_string();
        assert!(policy_reference_valid(None, &cfg).is_ok());
        assert!(policy_reference_valid(Some(&s(nos_rpl::ACCEPT_ALL_NAME)), &cfg).is_ok());
        assert!(policy_reference_valid(Some(&s(nos_rpl::DENY_ALL_NAME)), &cfg).is_ok());
        assert!(policy_reference_valid(Some(&s("mine")), &cfg).is_ok());
        assert!(policy_reference_valid(Some(&s("nope")), &cfg).is_err());
        assert!(policy_reference_valid(Some(&s("nope")), &Config::default()).is_err());
    }

    fn aokey(send_id: u8, recv_id: u8, is_current: bool, is_rnext: bool) -> BgpAoKey {
        BgpAoKey {
            send_id,
            recv_id,
            algorithm: BgpAoAlgorithm::HmacSha1_96,
            key_ref: "k".to_string(),
            is_current,
            is_rnext,
            exclude_options: false,
        }
    }

    fn ao_valid(keys: Vec<BgpAoKey>) -> bool {
        valid_auth(Some(&BgpAuth::Ao { keys }), &config_with(vec![])).is_ok()
    }

    #[test]
    fn ao_auth_rejects_duplicate_ids_and_bad_current_rnext_counts() {
        assert!(valid_auth(None, &Config::default()).is_ok());
        assert!(ao_valid(vec![aokey(1, 1, true, false)]));
        assert!(ao_valid(vec![
            aokey(1, 1, true, true),
            aokey(2, 2, false, false)
        ]));
        assert!(ao_valid(vec![
            aokey(1, 1, true, false),
            aokey(2, 2, false, true)
        ]));
        // Duplicate send-id, duplicate recv-id (each alone).
        assert!(!ao_valid(vec![
            aokey(1, 1, true, false),
            aokey(1, 2, false, false)
        ]));
        assert!(!ao_valid(vec![
            aokey(1, 1, true, false),
            aokey(2, 1, false, false)
        ]));
        // No current key, two current keys, two rnext keys.
        assert!(!ao_valid(vec![aokey(1, 1, false, false)]));
        assert!(!ao_valid(vec![
            aokey(1, 1, true, false),
            aokey(2, 2, true, false)
        ]));
        assert!(!ao_valid(vec![
            aokey(1, 1, true, true),
            aokey(2, 2, false, true)
        ]));
        assert!(!ao_valid(vec![]));
    }

    #[test]
    fn md5_and_ao_key_length_boundaries() {
        let with_secret = |n: usize| Config {
            admin: crate::schema::Admin {
                keys: vec![crate::schema::AdminKey {
                    label: "l".to_string(),
                    secret: "x".repeat(n),
                }],
            },
            ..Default::default()
        };
        let md5 = |n: usize| {
            valid_auth(
                Some(&BgpAuth::Md5 {
                    key_ref: "l".to_string(),
                }),
                &with_secret(n),
            )
            .is_ok()
        };
        assert!(!md5(0));
        assert!(md5(1));
        assert!(md5(80));
        assert!(!md5(81));
        let mut k = aokey(1, 1, true, false);
        k.key_ref = "l".to_string();
        let ao = |n: usize| {
            valid_auth(
                Some(&BgpAuth::Ao {
                    keys: vec![k.clone()],
                }),
                &with_secret(n),
            )
            .is_ok()
        };
        assert!(ao(80));
        assert!(!ao(0));
        assert!(!ao(81));
    }

    #[test]
    fn rt_constraint_needs_a_vpn_or_evpn_family() {
        use AddressFamily::*;
        let ok = |afs: Vec<AddressFamily>| {
            let cfg = config_with(vec![instance_with_groups(
                "r1",
                vec![group("pg1", 65001, afs)],
            )]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(!ok(vec![Ipv4Unicast, RtConstraint]));
        assert!(!ok(vec![RtConstraint]));
        for f in [Vpnv4Unicast, Vpnv6Unicast, L2vpnEvpn] {
            assert!(ok(vec![f, RtConstraint]));
        }
    }

    #[test]
    fn vpn_families_are_appended_and_round_trip() {
        use AddressFamily::*;
        // postcard indexes by position: existing variants must never move.
        for (i, f) in [
            (0u8, Ipv4Unicast),
            (1, Ipv6Unicast),
            (2, L2vpnEvpn),
            (3, Ipv4Flowspec),
            (4, Ipv6Flowspec),
            (5, Vpnv4Unicast),
            (6, Vpnv6Unicast),
            (7, RtConstraint),
        ] {
            let bytes = postcard::to_allocvec(&f).unwrap();
            assert_eq!(bytes, [i]);
            assert_eq!(postcard::from_bytes::<AddressFamily>(&bytes).unwrap(), f);
        }
        let mut mp = BgpMaximumPrefix::default();
        let limit = BgpPrefixLimit {
            limit: 7,
            warning_only: false,
            restart_interval: 0,
        };
        *mp.slot_mut(Vpnv4Unicast) = Some(limit);
        assert_eq!(
            (mp.get(Vpnv4Unicast), mp.get(Vpnv6Unicast)),
            (Some(limit), None)
        );
        *mp.slot_mut(Vpnv6Unicast) = Some(limit);
        assert_eq!(mp.vpnv6, Some(limit));
    }

    #[test]
    fn display_words_for_family_role_and_source_address() {
        let fam = AddressFamily::ALL.map(|f| f.to_string());
        assert_eq!(
            fam,
            [
                "ipv4",
                "ipv6",
                "l2vpn-evpn",
                "ipv4-flowspec",
                "ipv6-flowspec",
                "vpnv4",
                "vpnv6",
                "rt-constraint"
            ]
        );
        let roles = [
            (BgpRole::Provider, "provider"),
            (BgpRole::RouteServer, "route-server"),
            (BgpRole::RouteServerClient, "route-server-client"),
            (BgpRole::Customer, "customer"),
            (BgpRole::Peer, "peer"),
        ];
        for (r, w) in roles {
            assert_eq!(r.as_str(), w);
        }
        let s = |v: &SourceAddress| v.to_string();
        let label = Some("l".to_string());
        let iface = |label| SourceAddress::Interface {
            interface: "eth0".to_string(),
            label,
        };
        assert_eq!(s(&iface(None)), "interface eth0");
        assert_eq!(s(&iface(label.clone())), "interface eth0 label l");
        assert_eq!(s(&SourceAddress::Loopback { label: None }), "loopback");
        assert_eq!(s(&SourceAddress::Loopback { label }), "loopback label l");
    }

    #[test]
    fn shutdown_message_and_max_hops_boundaries() {
        let msg = |n: usize| {
            valid_shutdown(Some(&BgpShutdown {
                message: Some("x".repeat(n)),
            }))
            .is_ok()
        };
        assert!(valid_shutdown(None).is_ok());
        assert!(valid_shutdown(Some(&BgpShutdown { message: None })).is_ok());
        assert!(msg(0));
        assert!(msg(SHUTDOWN_MESSAGE_MAX));
        assert!(!msg(SHUTDOWN_MESSAGE_MAX + 1));
        assert!(valid_max_hops(None).is_ok());
        assert!(valid_max_hops(Some(1)).is_ok());
        assert!(valid_max_hops(Some(254)).is_ok());
        assert!(valid_max_hops(Some(0)).is_err());
        assert!(valid_max_hops(Some(255)).is_err());
    }

    #[test]
    fn add_path_send_count_defaults_depend_on_route_server_client() {
        let mut pg = group("pg1", 65001, vec![AddressFamily::Ipv4Unicast]);
        assert_eq!(BgpPeerGroup::default_add_path_send_count(false), Some(2));
        assert_eq!(BgpPeerGroup::default_add_path_send_count(true), None);
        assert_eq!(pg.effective_add_path_send_count(), Some(2));
        pg.route_server_client = true;
        assert_eq!(pg.effective_add_path_send_count(), None);
        pg.add_path_send_count = Some(7);
        assert_eq!(pg.effective_add_path_send_count(), Some(7));
    }

    #[test]
    fn add_path_words_and_wire_values() {
        assert_eq!(BgpAddPath::Receive.as_str(), "receive");
        assert_eq!(BgpAddPath::Send.as_str(), "send");
        assert_eq!(BgpAddPath::Both.as_str(), "both");
        assert_eq!(BgpAddPath::Receive.send_receive(), 1);
        assert_eq!(BgpAddPath::Send.send_receive(), 2);
        assert_eq!(BgpAddPath::Both.send_receive(), 3);
    }
}
