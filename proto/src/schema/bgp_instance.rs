use std::net::{IpAddr, Ipv4Addr};

use garde::Validate;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::validators::unique_in;

use super::bgp_peer_group;
use super::{sugar, BgpAuth, BgpPeer, BgpPeerGroup, Config};
use nos_proto_derive::Cli;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
/// One BGP speaker: identity, peer-groups and peers; served by one `nos-bgpd` process.
pub struct BgpInstance {
    #[garde(
        length(min = 1, max = 64),
        custom(|n, _ctx: &Config| crate::validators::name_charset(n)),
        custom(|n, ctx: &Config| unique_in(n, &ctx.bgp_instances, |i| &i.name))
    )]
    #[cli(key)]
    /// Instance name, 1 to 64 characters (letters, digits, `_`, `-`), unique among BGP instances.
    pub name: String,

    // Ipv4Addr is structurally valid by construction; no additional garde rule needed.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(topic = BgpInstanceRouterId)]
    /// BGP identifier sent in OPEN (RFC 4271 §4.2).
    pub router_id: Ipv4Addr,

    // RFC 6793: ASN 0 and 4_294_967_295 are reserved.
    #[garde(range(min = 1, max = 4_294_967_294u32))]
    #[cli(topic = BgpInstanceAsn)]
    /// Local AS number, 1 to 4294967294 (RFC 6793 reserves 0 and 4294967295).
    pub asn: u32,

    #[garde(
        dive,
        custom(|groups, ctx: &Config| bgp_peer_group::valid_peer_group_timers(groups, ctx))
    )]
    #[cli(topic = BgpPeerGroup)]
    /// Session templates; their timers are validated together.
    pub peer_groups: Vec<BgpPeerGroup>,

    #[garde(dive)]
    #[cli(topic = BgpPeer)]
    /// Neighbors, each naming one entry of `peer_groups`.
    pub peers: Vec<BgpPeer>,

    /// RFC 4456 route reflector cluster id. `None` resolves to this
    /// instance's own `router_id` — the standard single-RR-per-cluster
    /// convention. Only meaningful when at least one peer-group has
    /// `route_reflector_client` set; harmless (unused) otherwise.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[cli(topic = BgpInstanceClusterId)]
    pub cluster_id: Option<Ipv4Addr>,

    /// How many equal paths' next hops a prefix installs in the kernel
    /// (BGP multipath): the best path plus every path tying with it up to
    /// the IGP cost to the next hop and learned from the same neighbouring
    /// AS. Only the best path is advertised. Unset or 1 installs the best
    /// path alone.
    #[serde(default)]
    #[garde(range(min = 1, max = 64))]
    #[cli(topic = BgpInstanceMaximumPaths)]
    pub maximum_paths: Option<u8>,

    /// RFC 5065 confederation: once `identifier` is set, `asn` is this
    /// router's member AS and `identifier` the AS the confederation shows
    /// to the outside. A plain struct (not an `Option`) so the CLI can set
    /// its two fields one at a time. Checked by
    /// `valid_route_reflection_and_server`.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = BgpInstanceConfederation)]
    pub confederation: BgpConfederation,

    /// RFC 4724 graceful restart with RFC 8538's N bit: on unless
    /// `disabled`. While on, a peer that advertised the capability keeps its
    /// routes in use across a session reset, until it sends End-of-RIB or a
    /// timer expires. A plain struct (not an `Option`) so each field can be
    /// set and deleted on its own.
    #[serde(default)]
    #[garde(custom(|g: &BgpGracefulRestart, _ctx: &Config| valid_graceful_restart(g)))]
    #[cli(topic = BgpInstanceGracefulRestart)]
    pub graceful_restart: BgpGracefulRestart,

    /// RFC 8210 RPKI-to-Router caches this instance's `nos-bgpd` takes its
    /// validated ROA payloads from, reached inside the instance's VRF. One
    /// is used at a time: the lowest `preference` that answers (RFC 8210
    /// §10), ties in list order.
    #[serde(default)]
    #[garde(custom(|c: &Vec<RpkiCache>, ctx: &Config| valid_rpki_caches(c, ctx)))]
    #[cli(topic = BgpInstanceRpkiCache, words = "rpki-cache")]
    pub rpki_caches: Vec<RpkiCache>,

    /// RFC 7854 BMP stations (collectors) this instance's `nos-bgpd` dials
    /// inside the instance's VRF and exports peer up/down events to.
    #[serde(default)]
    #[garde(custom(|s: &Vec<BmpStation>, _ctx: &Config| valid_bmp_stations(s)))]
    #[cli(topic = BgpInstanceBmpStation, words = "bmp-station")]
    pub bmp_stations: Vec<BmpStation>,

    /// RFC 4271 §9.2.2.2 aggregates this instance originates while some
    /// more specific route is in its Loc-RIB.
    #[serde(default)]
    #[garde(custom(|a: &Vec<BgpAggregate>, _ctx: &Config| valid_aggregates(a)))]
    #[cli(topic = BgpInstanceAggregate, words = "aggregate-address")]
    pub aggregates: Vec<BgpAggregate>,

    /// The name of the `RoutingTable` that claims this instance (i.e. the
    /// VRF it belongs to), mirrored from that table's `bgp_instance` field.
    /// Derived and read-only: never set by any `BgpInstanceOp`, recomputed
    /// by `nos-config` (`crate::derive::sync_routing_table_refs`) on every
    /// commit and on load, so an operator only ever edits the one
    /// authoritative reference (`RoutingTable.bgp_instance`). `nos-bgpd`
    /// reads this directly to resolve its own VRF without scanning every
    /// routing table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    #[cli(hidden)]
    pub routing_table: Option<String>,

    /// The name of the RPL policy filtering routes redistributed into this
    /// instance, mirrored from the owning `RoutingTable.redistribute.policy`
    /// (only when `redistribute.to == Bgp`). Derived and read-only, exactly
    /// like `routing_table` above: never set by any `BgpInstanceOp`,
    /// recomputed by `nos-config` (`crate::derive::sync_routing_table_refs`)
    /// on every commit and on load. `nos-bgpd` reads this directly to
    /// resolve its own redistribution policy without scanning every routing
    /// table. Deliberately not rendered by `nos-cli`.
    #[garde(skip)]
    #[cli(hidden)]
    pub redistribute_policy: Option<String>,
}

/// The well-known RPKI-RTR port (RFC 8210 §3 / IANA `rpki-rtr`).
pub const RPKI_RTR_PORT_DEFAULT: u16 = 323;

fn rpki_rtr_port_default() -> u16 {
    RPKI_RTR_PORT_DEFAULT
}

/// One RPKI-to-Router cache (RFC 8210), keyed by its address.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct RpkiCache {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// Address of the RPKI-to-Router cache; the key.
    pub address: IpAddr,
    #[serde(default = "rpki_rtr_port_default")]
    #[cli(topic = BgpInstanceRpkiCachePort)]
    /// TCP port of the cache, `RPKI_RTR_PORT_DEFAULT` unless set.
    pub port: u16,
    /// Lower is preferred (RFC 8210 §10).
    #[serde(default)]
    #[cli(topic = BgpInstanceRpkiCachePreference)]
    pub preference: u8,
    /// RTR session authentication (RFC 8210 §9): TCP-MD5 or TCP-AO toward the
    /// cache, same rules as `BgpPeerGroup.auth`. `None` is an unauthenticated
    /// session. Keys are admin-keystore labels, like `BgpPeerGroup.auth`.
    /// Appended last: postcard is positional.
    #[serde(default)]
    #[cli(topic = BgpInstanceRpkiCacheAuth, render = sugar::render_bgp_auth, sugar(word = "md5-password", with = sugar::md5_password, topic = BgpInstanceRpkiCacheMd5Password), sugar(word = "ao-key", with = sugar::ao_key, topic = BgpInstanceRpkiCacheAoKey))]
    pub auth: Option<BgpAuth>,
}

impl Default for RpkiCache {
    fn default() -> Self {
        RpkiCache {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: RPKI_RTR_PORT_DEFAULT,
            preference: 0,
            auth: None,
        }
    }
}

fn valid_rpki_caches(caches: &[RpkiCache], cfg: &Config) -> garde::Result {
    for (i, c) in caches.iter().enumerate() {
        if c.port == 0 || c.address.is_unspecified() {
            return Err(garde::Error::new(
                "an rpki cache needs a specified address and a non-zero port",
            ));
        }
        if caches[..i].iter().any(|o| o.address == c.address) {
            return Err(garde::Error::new("rpki cache addresses must be unique"));
        }
        bgp_peer_group::valid_auth(c.auth.as_ref(), cfg)?;
    }
    Ok(())
}

/// One BMP station (RFC 7854), keyed by its name.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct BmpStation {
    /// Name of the station; the key.
    #[cli(key)]
    pub name: String,
    /// Address of the BMP station (collector).
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(topic = BgpInstanceBmpStationAddress)]
    pub address: IpAddr,
    /// TCP port of the station. Mandatory: BMP has no assigned port, so
    /// there is deliberately no serde default (and `Default` gives 0, which
    /// the commit refuses).
    #[cli(topic = BgpInstanceBmpStationPort)]
    pub port: u16,
    /// Which policy view of the Adj-RIB-In the station gets as Route
    /// Monitoring (#864). Appended last: postcard is positional.
    #[serde(default)]
    #[cli(topic = BgpInstanceBmpStationMonitor)]
    pub monitor: BmpMonitor,
}

/// The policy view a `bmp-station` monitors (RFC 7854 section 5).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum BmpMonitor {
    /// Only routes after the import policy (what the Adj-RIB-In holds).
    PostPolicy,
    /// Only routes as received, before the import policy.
    PrePolicy,
    /// Both views.
    #[default]
    Both,
}

impl Default for BmpStation {
    fn default() -> Self {
        BmpStation {
            name: String::new(),
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 0,
            monitor: BmpMonitor::default(),
        }
    }
}

fn valid_bmp_stations(stations: &[BmpStation]) -> garde::Result {
    for (i, s) in stations.iter().enumerate() {
        crate::validators::name_charset(&s.name)?;
        if s.port == 0 {
            return Err(garde::Error::new(
                "a bmp-station needs a port: it is mandatory (BMP has no default port)",
            ));
        }
        if s.address.is_unspecified() {
            return Err(garde::Error::new("a bmp-station needs a specified address"));
        }
        if stations[..i].iter().any(|o| o.name == s.name) {
            return Err(garde::Error::new("bmp-station names must be unique"));
        }
    }
    Ok(())
}

/// One aggregate (RFC 4271 §9.2.2.2), keyed by its prefix.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct BgpAggregate {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// Aggregate prefix to originate; the key.
    pub prefix: IpNet,
    /// Carry the contributors' ASNs as an `AS_SET` instead of setting
    /// `ATOMIC_AGGREGATE`.
    #[serde(default)]
    #[cli(topic = BgpInstanceAggregateAsSet)]
    pub as_set: bool,
    /// Withdraw the contributing more-specifics from every peer while the
    /// aggregate is active.
    #[serde(default)]
    #[cli(topic = BgpInstanceAggregateSummaryOnly)]
    pub summary_only: bool,
}

fn valid_aggregates(aggregates: &[BgpAggregate]) -> garde::Result {
    for (i, a) in aggregates.iter().enumerate() {
        if a.prefix != a.prefix.trunc() {
            return Err(garde::Error::new(
                "an aggregate-address must be a network address (no host bits set)",
            ));
        }
        if a.prefix.prefix_len() == a.prefix.max_prefix_len() {
            return Err(garde::Error::new(
                "an aggregate-address can't be a host route: nothing is more specific",
            ));
        }
        if aggregates[..i].iter().any(|o| o.prefix == a.prefix) {
            return Err(garde::Error::new(
                "aggregate-address prefixes must be unique",
            ));
        }
    }
    Ok(())
}

/// RFC 5065 §2: the confederation identifier (`None`: not in a
/// confederation) and the other member ASes (`peers`) — a peer-group whose
/// `remote_as` is one of them is a confederation-external peer, not an
/// external one.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct BgpConfederation {
    #[serde(default)]
    #[cli(topic = BgpInstanceConfederationIdentifier)]
    /// AS number the outside world sees for the whole confederation (RFC 5065); `None` means no confederation.
    pub identifier: Option<u32>,
    #[serde(default)]
    #[cli(topic = BgpInstanceConfederationPeer)]
    /// AS numbers of the other member sub-ASes, reached over confederation eBGP.
    pub peers: Vec<u32>,
}

impl BgpConfederation {
    /// `asn` is another member AS — only meaningful with an identifier set.
    pub fn is_member(&self, asn: u32) -> bool {
        self.identifier.is_some() && self.peers.contains(&asn)
    }
}

/// RFC 4724 §3: the default Restart Time (seconds) a peer gets to come back.
pub const GR_RESTART_TIME_DEFAULT: u16 = 120;
/// How long a returned peer's retained routes wait for its End-of-RIB.
pub const GR_STALE_TIME_DEFAULT: u16 = 180;
/// RFC 4724 §4.1 `Selection_Deferral_Timer` default.
pub const GR_SELECTION_DEFERRAL_TIME_DEFAULT: u16 = 360;
/// The Restart Time field is 12 bits wide.
pub const GR_RESTART_TIME_MAX: u16 = 4095;

/// RFC 4724 / RFC 8538 graceful restart of one BGP instance. `Default` is
/// on, with every timer at its default.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct BgpGracefulRestart {
    /// Turn graceful restart off: no capability is advertised, and no
    /// peer's routes are kept across a reset.
    #[serde(default)]
    #[cli(topic = BgpInstanceGracefulRestart, words = "disable")]
    pub disabled: bool,
    /// Seconds a peer may take to come back before its routes are dropped,
    /// advertised as our own Restart Time (unset: 120, at most 4095).
    #[serde(default)]
    #[cli(topic = BgpInstanceGracefulRestart)]
    pub restart_time: Option<u16>,
    /// Seconds a returned peer's kept routes wait for its End-of-RIB
    /// (unset: 180).
    #[serde(default)]
    #[cli(topic = BgpInstanceGracefulRestart)]
    pub stale_time: Option<u16>,
    /// Seconds a restarting instance waits for its peers' End-of-RIB before
    /// selecting and advertising routes (unset: 360).
    #[serde(default)]
    #[cli(topic = BgpInstanceGracefulRestart)]
    pub selection_deferral_time: Option<u16>,
}

impl BgpGracefulRestart {
    /// The Restart Time to advertise, `None` when disabled.
    pub fn enabled_restart_time(&self) -> Option<u16> {
        (!self.disabled).then(|| self.restart_time.unwrap_or(GR_RESTART_TIME_DEFAULT))
    }
    /// Seconds a restarted peer's routes stay stale, `GR_STALE_TIME_DEFAULT` unless set.
    pub fn stale_time(&self) -> u16 {
        self.stale_time.unwrap_or(GR_STALE_TIME_DEFAULT)
    }
    /// Seconds to wait for End-of-RIB before route selection, 360 unless set.
    pub fn selection_deferral_time(&self) -> u16 {
        self.selection_deferral_time
            .unwrap_or(GR_SELECTION_DEFERRAL_TIME_DEFAULT)
    }
}

fn valid_graceful_restart(g: &BgpGracefulRestart) -> garde::Result {
    if g.restart_time.is_some_and(|t| t > GR_RESTART_TIME_MAX) {
        return Err(garde::Error::new(
            "graceful-restart restart-time must be at most 4095 seconds",
        ));
    }
    if g.stale_time == Some(0) || g.selection_deferral_time == Some(0) {
        return Err(garde::Error::new(
            "graceful-restart stale-time and selection-deferral-time must be at least 1 second",
        ));
    }
    Ok(())
}

fn valid_confederation(instance: &BgpInstance) -> garde::Result {
    let c = &instance.confederation;
    let Some(id) = c.identifier else {
        if c.peers.is_empty() {
            return Ok(());
        }
        return Err(garde::Error::new(
            "confederation peers need a confederation identifier",
        ));
    };
    if id == 0 || id == u32::MAX || id == instance.asn {
        return Err(garde::Error::new(
            "confederation identifier must be a valid asn (1..=4294967294) different from this instance's asn",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for &p in &c.peers {
        if p == 0 || p == u32::MAX || p == instance.asn || p == id || !seen.insert(p) {
            return Err(garde::Error::new(
                "confederation peers must be distinct valid asns, neither this instance's asn nor the confederation identifier",
            ));
        }
    }
    Ok(())
}

/// The placeholder a new `BgpInstance` starts from (`edit` on a missing one).
impl Default for BgpInstance {
    fn default() -> Self {
        BgpInstance {
            name: String::new(),
            router_id: Ipv4Addr::UNSPECIFIED,
            asn: 0,
            peer_groups: Vec::new(),
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
}

/// Cross-instance check needing both `BgpInstance.asn` and a sibling
/// `BgpPeerGroup`'s fields — a per-field `custom` closure scoped to
/// `peer_groups` can't see `asn` (a different field on the same parent), so
/// this is wired one level up, on `Config.bgp_instances` itself (mirrors
/// `routing_table::valid_redistribute_rules`'s wiring on
/// `Config.routing_tables`).
///
/// - `route_reflector_client` and `route_server_client` are mutually
///   exclusive on the same peer-group.
/// - `route_reflector_client` requires an iBGP peer-group (`remote_as ==
///   asn`) — reflection is an iBGP-only concept (RFC 4456).
/// - `announce_rpki_state` requires an iBGP peer-group: RFC 8097's
///   community is non-transitive, and ignored when received over eBGP.
/// - `blackhole` requires an eBGP peer-group (RFC 7999 is customer-facing).
/// - `graceful_shutdown` requires an eBGP peer-group (RFC 8326 is eBGP-only).
/// - `route_server_client` requires an eBGP peer-group (`remote_as != asn`)
///   — a route server's transparency (no `AS_PATH` prepend) is an eBGP concept
///   (RFC 7947) — outside the confederation, if there is one.
/// - `confederation`: identifier in 1..=4294967294 and not `asn`; peers
///   distinct, neither `asn` nor the identifier (RFC 5065).
pub(crate) fn valid_route_reflection_and_server(instances: &[BgpInstance]) -> garde::Result {
    for instance in instances {
        valid_confederation(instance)?;
        for group in &instance.peer_groups {
            if group.route_reflector_client && group.route_server_client {
                return Err(garde::Error::new(
                    "route-reflector-client and route-server-client are mutually exclusive",
                ));
            }
            if group.route_reflector_client && group.remote_as != instance.asn {
                return Err(garde::Error::new(
                    "route-reflector-client requires an iBGP peer-group (remote-as must equal this instance's asn)",
                ));
            }
            if group.announce_rpki_state && group.remote_as != instance.asn {
                return Err(garde::Error::new(
                    "announce-rpki-state requires an iBGP peer-group (remote-as must equal this instance's asn)",
                ));
            }
            if group.graceful_shutdown && group.remote_as == instance.asn {
                return Err(garde::Error::new(
                    "graceful-shutdown requires an eBGP peer-group (remote-as must differ from this instance's asn)",
                ));
            }
            if group.blackhole.is_some() && group.remote_as == instance.asn {
                return Err(garde::Error::new(
                    "blackhole requires an eBGP peer-group (remote-as must differ from this instance's asn)",
                ));
            }
            if group.damping.is_some() && group.remote_as == instance.asn {
                return Err(garde::Error::new(
                    "damping requires an eBGP peer-group (remote-as must differ from this instance's asn)",
                ));
            }
            if group.route_server_client && group.remote_as == instance.asn {
                return Err(garde::Error::new(
                    "route-server-client requires an eBGP peer-group (remote-as must differ from this instance's asn)",
                ));
            }
            if group.route_server_client && instance.confederation.is_member(group.remote_as) {
                return Err(garde::Error::new(
                    "route-server-client requires a peer-group outside the confederation (remote-as must not be a confederation peer)",
                ));
            }
            if group.add_path_send_count.is_some()
                && !matches!(
                    group.effective_add_path(),
                    Some(crate::schema::BgpAddPath::Send | crate::schema::BgpAddPath::Both)
                )
            {
                return Err(garde::Error::new(
                    "add-path-send-count requires add-path send or both",
                ));
            }
            valid_role(instance, group)?;
            if let Some(l) = group.local_as {
                valid_local_as(instance, group.remote_as, group.route_server_client, l.asn)?;
            }
        }
    }
    Ok(())
}

/// RFC 9234 roles are an eBGP concept (not iBGP, not a confederation
/// member); `strict-mode` needs a role; a route-server-client group's peers
/// can only be route-server(-client)s.
fn valid_role(instance: &BgpInstance, group: &crate::schema::BgpPeerGroup) -> garde::Result {
    use crate::schema::BgpRole::{RouteServer, RouteServerClient};
    let Some(role) = group.role else {
        return if group.strict_mode {
            Err(garde::Error::new("strict-mode requires a role"))
        } else {
            Ok(())
        };
    };
    if group.remote_as == instance.asn || instance.confederation.is_member(group.remote_as) {
        return Err(garde::Error::new(
            "role requires an eBGP peer-group outside the confederation",
        ));
    }
    if group.route_server_client && !matches!(role, RouteServer | RouteServerClient) {
        return Err(garde::Error::new(
            "a route-server-client peer-group's role can only be route-server or route-server-client",
        ));
    }
    Ok(())
}

/// `local-as` only means something toward a peer outside our AS (and
/// confederation), and must be an AS that is neither ours nor the peer's.
fn valid_local_as(
    instance: &BgpInstance,
    remote_as: u32,
    route_server_client: bool,
    asn: u32,
) -> garde::Result {
    let err = |m: &str| Err(garde::Error::new(format!("local-as {m}")));
    if asn == 0 || asn == u32::MAX {
        return err("must be in 1..=4294967294");
    }
    if remote_as == instance.asn || instance.confederation.is_member(remote_as) {
        return err("requires an eBGP peer-group outside the confederation");
    }
    if asn == instance.asn || instance.confederation.identifier == Some(asn) {
        return err("must differ from this instance's asn and confederation identifier");
    }
    if asn == remote_as {
        return err("must differ from the peer-group's remote-as");
    }
    if route_server_client {
        return err("and route-server-client are mutually exclusive");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use garde::Validate as _;

    use crate::schema::Config;

    use super::BgpInstance;

    fn instance(name: &str, asn: u32) -> BgpInstance {
        BgpInstance {
            name: name.to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            asn,
            peer_groups: Vec::new(),
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

    fn config_with(instances: Vec<BgpInstance>) -> Config {
        Config {
            bgp_instances: instances,
            ..Default::default()
        }
    }

    #[test]
    fn valid_instance_passes() {
        let cfg = config_with(vec![instance("default", 65000)]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn asn_zero_fails() {
        let cfg = config_with(vec![instance("default", 0)]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn asn_max_reserved_fails() {
        let cfg = config_with(vec![instance("default", 4_294_967_295)]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn graceful_restart_timers_are_checked() {
        use super::BgpGracefulRestart;
        let with = |f: fn(&mut BgpGracefulRestart)| {
            let mut g = BgpGracefulRestart::default();
            f(&mut g);
            g
        };
        let cases = [
            (BgpGracefulRestart::default(), true),
            (with(|g| g.restart_time = Some(4095)), true),
            (with(|g| g.restart_time = Some(4096)), false),
            (with(|g| g.stale_time = Some(0)), false),
            (with(|g| g.selection_deferral_time = Some(0)), false),
        ];
        for (g, ok) in cases {
            let mut i = instance("default", 65000);
            i.graceful_restart = g;
            let cfg = config_with(vec![i]);
            assert_eq!(cfg.validate_with(&cfg).is_ok(), ok, "{g:?}");
        }
    }

    /// Default-on: an instance saved before graceful restart existed loads
    /// with it enabled and default timers.
    #[test]
    fn graceful_restart_defaults_to_on() {
        let json = r#"{"name":"r1","router_id":"1.1.1.1","asn":65000,"peer_groups":[],
            "peers":[],"cluster_id":null,"routing_table":null,"redistribute_policy":null}"#;
        let i: BgpInstance = serde_json::from_str(json).unwrap();
        assert_eq!(i.graceful_restart.enabled_restart_time(), Some(120));
        assert_eq!(i.graceful_restart.stale_time(), 180);
        assert_eq!(i.graceful_restart.selection_deferral_time(), 360);
        let off = super::BgpGracefulRestart {
            disabled: true,
            ..Default::default()
        };
        assert_eq!(off.enabled_restart_time(), None);
    }

    #[test]
    fn add_path_send_count_range_and_mode() {
        use crate::schema::BgpAddPath::{Both, Receive, Send};
        let check = |count: u8, mode: Option<crate::schema::BgpAddPath>, rs: bool| {
            let mut i = instance("default", 65000);
            let mut g = group_with_flags("pg1", 65001, false, false);
            g.add_path = mode;
            g.route_server_client = rs;
            g.add_path_send_count = Some(count);
            i.peer_groups.push(g);
            let cfg = config_with(vec![i]);
            cfg.validate_with(&cfg).is_ok()
        };
        for (n, ok) in [(1, false), (2, true), (64, true), (65, false)] {
            assert_eq!(check(n, Some(Send), false), ok, "add-path-send-count {n}");
        }
        assert!(!check(2, Some(Receive), false));
        assert!(!check(2, None, false));
        assert!(check(2, Some(Both), false));
        assert!(
            check(2, None, true),
            "a route-server client is both by default"
        );
    }

    #[test]
    fn maximum_paths_range() {
        for (n, ok) in [(0, false), (1, true), (64, true), (65, false)] {
            let mut i = instance("default", 65000);
            i.maximum_paths = Some(n);
            let cfg = config_with(vec![i]);
            assert_eq!(cfg.validate_with(&cfg).is_ok(), ok, "maximum-paths {n}");
        }
    }

    #[test]
    fn duplicate_name_fails() {
        let cfg = config_with(vec![instance("vrf-a", 65001), instance("vrf-a", 65002)]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_names_pass() {
        let cfg = config_with(vec![instance("vrf-a", 65001), instance("vrf-b", 65002)]);
        cfg.validate_with(&cfg).unwrap();
    }

    /// The cross-field `keepalive_interval < hold_time` check is wired on
    /// `peer_groups` (not on `BgpPeerGroup` itself, which can't see sibling
    /// fields) — this proves it fires per-group, not globally across the
    /// whole list.
    #[test]
    fn invalid_timer_combo_on_one_group_fails_even_with_another_valid_group() {
        use crate::schema::{AddressFamily, BgpPeerGroup};

        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![
            BgpPeerGroup {
                bfd: None,
                name: "valid".to_string(),
                remote_as: 65001,
                source_address: None,
                address_families: vec![AddressFamily::Ipv4Unicast],
                hold_time: Some(30),
                keepalive_interval: Some(10),
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
                flowspec_validation: crate::schema::BgpFlowspecValidation::default(),
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
            },
            BgpPeerGroup {
                bfd: None,
                name: "invalid".to_string(),
                remote_as: 65002,
                source_address: None,
                address_families: vec![AddressFamily::Ipv4Unicast],
                hold_time: Some(30),
                keepalive_interval: Some(30),
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
                flowspec_validation: crate::schema::BgpFlowspecValidation::default(),
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
            },
        ];
        let cfg = config_with(vec![inst]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    fn group_with_flags(
        name: &str,
        remote_as: u32,
        route_reflector_client: bool,
        route_server_client: bool,
    ) -> crate::schema::BgpPeerGroup {
        use crate::schema::AddressFamily;
        crate::schema::BgpPeerGroup {
            bfd: None,
            name: name.to_string(),
            remote_as,
            source_address: None,
            address_families: vec![AddressFamily::Ipv4Unicast],
            hold_time: None,
            keepalive_interval: None,
            connect_retry_time: None,
            mrai: None,
            route_refresh_stale_time: None,
            damping: None,
            max_hops: None,
            auth: None,
            next_hop: None,
            route_reflector_client,
            route_server_client,
            import_policy: None,
            export_policy: None,
            evpn_import_policy: None,
            enforce_first_as: None,
            flowspec_validation: crate::schema::BgpFlowspecValidation::default(),
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

    #[test]
    fn route_reflector_and_route_server_client_together_fails() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![group_with_flags("pg1", 65000, true, true)];
        let cfg = config_with(vec![inst]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn route_reflector_client_on_ebgp_group_fails() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![group_with_flags("pg1", 65001, true, false)];
        let cfg = config_with(vec![inst]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn announce_rpki_state_needs_an_ibgp_group() {
        for (remote_as, ok) in [(65001, false), (65000, true)] {
            let mut inst = instance("r1", 65000);
            let mut g = group_with_flags("pg1", remote_as, false, false);
            g.announce_rpki_state = true;
            inst.peer_groups = vec![g];
            let cfg = config_with(vec![inst]);
            assert_eq!(cfg.validate_with(&cfg).is_ok(), ok, "remote-as {remote_as}");
        }
    }

    #[test]
    fn graceful_shutdown_needs_an_ebgp_group() {
        for (remote_as, ok) in [(65001, true), (65000, false)] {
            let mut inst = instance("r1", 65000);
            let mut g = group_with_flags("pg1", remote_as, false, false);
            g.graceful_shutdown = true;
            // The receiver-side opt-out is accepted anywhere.
            g.graceful_shutdown_receive_disabled = true;
            inst.peer_groups = vec![g];
            let cfg = config_with(vec![inst]);
            assert_eq!(cfg.validate_with(&cfg).is_ok(), ok, "remote-as {remote_as}");
        }
    }

    #[test]
    fn route_reflector_client_on_ibgp_group_passes() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![group_with_flags("pg1", 65000, true, false)];
        let cfg = config_with(vec![inst]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn route_server_client_on_ibgp_group_fails() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![group_with_flags("pg1", 65000, false, true)];
        let cfg = config_with(vec![inst]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn route_server_client_on_ebgp_group_passes() {
        let mut inst = instance("r1", 65000);
        inst.peer_groups = vec![group_with_flags("pg1", 65001, false, true)];
        let cfg = config_with(vec![inst]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn confederation_is_checked() {
        use super::BgpConfederation;
        let check = |identifier: u32, peers: Vec<u32>, rs_remote: Option<u32>| {
            let mut inst = instance("r1", 65101);
            inst.confederation = BgpConfederation {
                identifier: Some(identifier),
                peers,
            };
            if let Some(r) = rs_remote {
                inst.peer_groups = vec![group_with_flags("pg1", r, false, true)];
            }
            let cfg = config_with(vec![inst]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(65100, vec![65102, 65103], None));
        assert!(!check(0, vec![], None), "identifier 0");
        assert!(!check(65101, vec![], None), "identifier == asn");
        assert!(!check(65100, vec![65101], None), "peer == asn");
        assert!(!check(65100, vec![65100], None), "peer == identifier");
        assert!(!check(65100, vec![65102, 65102], None), "duplicate peer");
        assert!(check(65100, vec![65102], Some(65003)), "external rs client");
        assert!(!check(65100, vec![65102], Some(65102)), "confed rs client");
        let mut inst = instance("r1", 65101);
        inst.confederation.peers = vec![65102];
        let cfg = config_with(vec![inst]);
        assert!(cfg.validate_with(&cfg).is_err(), "peers without identifier");
    }

    #[test]
    fn aggregates_are_checked() {
        use super::BgpAggregate;
        let check = |prefixes: &[&str]| {
            let mut inst = instance("r1", 65000);
            inst.aggregates = prefixes
                .iter()
                .map(|p| BgpAggregate {
                    prefix: p.parse().unwrap(),
                    ..Default::default()
                })
                .collect();
            let cfg = config_with(vec![inst]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(&["198.51.0.0/16", "2001:db8::/32"]));
        assert!(!check(&["198.51.1.0/16"]), "host bits set");
        assert!(!check(&["198.51.0.1/32"]), "host route");
        assert!(!check(&["2001:db8::1/128"]), "v6 host route");
        assert!(!check(&["198.51.0.0/16", "198.51.0.0/16"]), "duplicate");
    }

    #[test]
    fn rpki_caches_are_checked() {
        use super::RpkiCache;
        use crate::schema::BgpAuth;
        let check = |caches: Vec<RpkiCache>| {
            let mut inst = instance("r1", 65000);
            inst.rpki_caches = caches;
            let mut cfg = config_with(vec![inst]);
            cfg.admin.keys = vec![crate::schema::AdminKey {
                label: "k".to_string(),
                secret: "s3cr3t".to_string(),
            }];
            cfg.validate_with(&cfg).is_ok()
        };
        let cache = |a: &str, port: u16| RpkiCache {
            address: a.parse().unwrap(),
            port,
            preference: 0,
            auth: None,
        };
        assert!(check(vec![
            cache("192.0.2.1", 323),
            cache("2001:db8::1", 8282)
        ]));
        assert!(!check(vec![cache("192.0.2.1", 0)]), "port 0");
        assert!(!check(vec![RpkiCache::default()]), "unspecified address");
        assert!(
            !check(vec![cache("192.0.2.1", 323), cache("192.0.2.1", 8282)]),
            "duplicate address"
        );
        let old: super::BgpInstance = serde_json::from_str(
            r#"{"name":"r1","router_id":"1.1.1.1","asn":1,"peer_groups":[],"peers":[],"cluster_id":null,"routing_table":null,"redistribute_policy":null}"#,
        )
        .unwrap();
        assert!(
            old.rpki_caches.is_empty(),
            "a saved config without caches loads"
        );
        let c: RpkiCache = serde_json::from_str(r#"{"address":"192.0.2.1"}"#).unwrap();
        assert_eq!((c.port, c.preference), (323, 0));
        assert_eq!(c.auth, None, "a saved cache without auth loads");
        // Same key rules as a peer-group's auth.
        let md5 = |label: &str| {
            let mut c = cache("192.0.2.1", 323);
            c.auth = Some(BgpAuth::Md5 {
                key_ref: label.into(),
            });
            c
        };
        assert!(check(vec![md5("k")]));
        assert!(!check(vec![md5("nope")]), "unknown admin key");
        let mut ao = cache("192.0.2.1", 323);
        ao.auth = Some(BgpAuth::Ao { keys: vec![] });
        assert!(!check(vec![ao]), "ao with no key");
        let json = serde_json::to_string(&md5("k")).unwrap();
        assert_eq!(serde_json::from_str::<RpkiCache>(&json).unwrap(), md5("k"));
    }

    #[test]
    fn bmp_stations_are_checked() {
        use super::BmpStation;
        let check = |stations: Vec<BmpStation>| {
            let mut inst = instance("r1", 65000);
            inst.bmp_stations = stations;
            let cfg = config_with(vec![inst]);
            cfg.validate_with(&cfg).is_ok()
        };
        let st = |n: &str, a: &str, port: u16| BmpStation {
            name: n.into(),
            address: a.parse().unwrap(),
            port,
            ..Default::default()
        };
        assert!(check(vec![
            st("a", "192.0.2.1", 5000),
            st("b", "2001:db8::1", 1)
        ]));
        assert!(!check(vec![st("a", "192.0.2.1", 0)]), "port 0");
        assert!(!check(vec![BmpStation {
            name: "a".into(),
            ..Default::default()
        }]));
        assert!(!check(vec![st("a", "0.0.0.0", 5000)]), "unspecified");
        assert!(
            !check(vec![st("a", "192.0.2.1", 1), st("a", "192.0.2.2", 1)]),
            "dup"
        );
        assert!(!check(vec![st("a b", "192.0.2.1", 1)]), "charset");
        assert!(
            serde_json::from_str::<BmpStation>(r#"{"name":"a","address":"192.0.2.1"}"#).is_err()
        );
    }

    #[test]
    fn local_as_is_checked() {
        let check = |remote_as: u32, asn: u32, rs: bool, confed: bool| {
            let mut inst = instance("r1", 65000);
            if confed {
                inst.confederation = crate::schema::BgpConfederation {
                    identifier: Some(65100),
                    peers: vec![65002],
                };
            }
            let mut g = group_with_flags("pg1", remote_as, false, rs);
            g.local_as = Some(crate::schema::BgpLocalAs {
                asn,
                ..Default::default()
            });
            inst.peer_groups = vec![g];
            let cfg = config_with(vec![inst]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(65001, 65009, false, false));
        assert!(check(65001, 65009, false, true), "external, confederated");
        assert!(!check(65000, 65009, false, false), "iBGP group");
        assert!(!check(65002, 65009, false, true), "confed member group");
        assert!(!check(65001, 65000, false, false), "== asn");
        assert!(!check(65001, 65100, false, true), "== identifier");
        assert!(!check(65001, 65001, false, false), "== remote-as");
        assert!(!check(65001, 0, false, false), "asn 0");
        assert!(!check(65001, 65009, true, false), "route-server-client");
    }

    #[test]
    fn blackhole_needs_an_ebgp_group_and_an_existing_prefix_list() {
        let check = |remote_as: u32, list: &str, defined: bool| {
            let mut inst = instance("r1", 65000);
            let mut g = group_with_flags("pg1", remote_as, false, false);
            g.blackhole = Some(crate::schema::BgpBlackhole {
                prefix_list: list.to_string(),
            });
            inst.peer_groups = vec![g];
            let mut cfg = config_with(vec![inst]);
            if defined {
                cfg.prefix_lists = vec![crate::schema::PrefixList {
                    name: "bh".to_string(),
                    entries: vec![crate::schema::PrefixListEntry {
                        cidr: "192.0.2.0/24".parse().unwrap(),
                        range: Some((32, 32)),
                    }],
                }];
            }
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(65001, "bh", true));
        assert!(!check(65001, "bh", false), "unknown prefix-list");
        assert!(!check(65000, "bh", true), "iBGP group");
    }

    #[test]
    fn damping_needs_an_ebgp_group_and_sane_values() {
        let d = crate::schema::BgpDamping::default();
        let check = |remote_as: u32, damping: crate::schema::BgpDamping| {
            let mut inst = instance("r1", 65000);
            let mut g = group_with_flags("pg1", remote_as, false, false);
            g.damping = Some(damping);
            inst.peer_groups = vec![g];
            let cfg = config_with(vec![inst]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(65001, d));
        assert!(!check(65000, d), "iBGP group");
        assert!(
            !check(65001, crate::schema::BgpDamping { suppress: 750, ..d }),
            "suppress <= reuse"
        );
        assert!(!check(
            65001,
            crate::schema::BgpDamping { half_life: 0, ..d }
        ));
    }

    #[test]
    fn role_is_checked() {
        use crate::schema::BgpRole::{Customer, Provider, RouteServer};
        let check = |remote_as: u32,
                     role: Option<crate::schema::BgpRole>,
                     strict: bool,
                     rs: bool,
                     confed: bool| {
            let mut inst = instance("r1", 65000);
            if confed {
                inst.confederation = crate::schema::BgpConfederation {
                    identifier: Some(65100),
                    peers: vec![65002],
                };
            }
            let mut g = group_with_flags("pg1", remote_as, false, rs);
            g.role = role;
            g.strict_mode = strict;
            inst.peer_groups = vec![g];
            let cfg = config_with(vec![inst]);
            cfg.validate_with(&cfg).is_ok()
        };
        assert!(check(65001, Some(Provider), true, false, false));
        assert!(check(65001, None, false, false, false));
        assert!(
            !check(65001, None, true, false, false),
            "strict needs a role"
        );
        assert!(!check(65000, Some(Provider), false, false, false), "iBGP");
        assert!(
            !check(65002, Some(Provider), false, false, true),
            "confed member"
        );
        assert!(check(65001, Some(RouteServer), false, true, false));
        assert!(
            !check(65001, Some(Customer), false, true, false),
            "rs-client group"
        );
    }
}
