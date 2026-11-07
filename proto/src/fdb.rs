//! `nos-fdbd`'s wire protocol: the EVPN route shape it exchanges with
//! `nos-bgpd` in both directions, and its own MAC-table query.
//!
//! `nos-proto` can't depend on `nos-bgp`, so EVPN routes cross the wire in
//! this small structured form rather than as `bgp::evpn::EvpnNlri`.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// An Ethernet Segment Identifier; all-zero is "single-homed".
pub use crate::evpn_id::Esi;

/// Route identity: what a withdrawal names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvpnKey {
    /// Type-2 MAC advertisement (no IP, Ethernet tag 0).
    Mac {
        /// Route Distinguisher (RFC 4364 section 4.2), 8 octets.
        rd: [u8; 8],
        /// MAC address.
        mac: [u8; 6],
    },
    /// Type-3 inclusive multicast: `origin` is the advertising VTEP.
    Imet {
        /// Route Distinguisher (RFC 4364 section 4.2), 8 octets.
        rd: [u8; 8],
        /// The advertising VTEP or PE.
        origin: IpAddr,
    },
    /// Type-2 MAC/IP advertisement (Ethernet tag 0). Appended:
    /// postcard indexes variants by position.
    MacIp {
        /// Route Distinguisher (RFC 4364 section 4.2), 8 octets.
        rd: [u8; 8],
        /// MAC address.
        mac: [u8; 6],
        /// IP address.
        ip: IpAddr,
    },
    /// Type-4 Ethernet Segment route: `origin` is the advertising PE. Appended
    /// (postcard indexes variants by position).
    EthernetSegment {
        /// Route Distinguisher (RFC 4364 section 4.2), 8 octets.
        rd: [u8; 8],
        /// Ethernet Segment Identifier.
        esi: Esi,
        /// The advertising VTEP or PE.
        origin: IpAddr,
    },
    /// Type-1 Ethernet Auto-Discovery: per-ES when `tag == AD_TAG_ES`, per-EVI
    /// otherwise (its VNI is `EvpnRoute::vni`). `origin` is the advertising PE
    /// — the BGP next hop on a received route, our VTEP on a local one. It is
    /// *not* on the wire (the NLRI has no originator), so it is only here to
    /// keep two PEs' routes apart. Appended (postcard indexes by position).
    EthernetAd {
        /// Route Distinguisher (RFC 4364 section 4.2), 8 octets.
        rd: [u8; 8],
        /// Ethernet Segment Identifier.
        esi: Esi,
        /// Ethernet Tag ID (RFC 7432 section 7).
        tag: u32,
        /// The advertising VTEP or PE.
        origin: IpAddr,
    },
    /// Type-5 IP Prefix (RFC 9136) of an IP-VRF: its L3 VNI is
    /// `EvpnRoute::vni`, its Router's MAC an extended community; ESI, Ethernet
    /// tag and gateway IP are zero on every route nos originates or accepts.
    /// Appended (postcard indexes by position).
    IpPrefix {
        /// Route Distinguisher (RFC 4364 section 4.2), 8 octets.
        rd: [u8; 8],
        /// The IP prefix.
        prefix: ipnet::IpNet,
    },
}

/// The Ethernet Tag ID of a per-ES Ethernet A-D route (RFC 7432 §8.2.1,
/// "MAX-ET").
pub const AD_TAG_ES: u32 = 0xFFFF_FFFF;

/// One EVPN route exchanged between `nos-bgpd` and `nos-fdbd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvpnRoute {
    /// Route identity.
    pub key: EvpnKey,
    /// The VXLAN VNI. Always set on a Type-2; on a received Type-3 it is the
    /// PMSI Tunnel attribute's label (RFC 6514 §5, ingress replication), or 0
    /// when the route carried no PMSI — `nos-fdbd` then matches the domain by
    /// Route Target alone.
    pub vni: u32,
    /// The remote VTEP (BGP next-hop).
    pub next_hop: IpAddr,
    /// Raw RFC 4360 extended communities (Route Targets, encapsulation).
    pub ext_communities: Vec<u64>,
    /// The Ethernet Segment of a Type-2 (all-zero = single-homed). Deliberately
    /// in the value, not the key: a MAC moving onto or off a segment is a
    /// replacement of one route, not a second one. (`bgp` withdraws the old
    /// NLRI itself, since the ESI is part of the wire identity.)
    pub esi: Esi,
    /// RFC 9135 symmetric IRB: a Type-2 MAC+IP's MPLS Label2, the L3 VNI of
    /// the tenant IP-VRF. `None` on every other route (and on a received
    /// Label2 of 0, which RFC 9135 §5.2 reads as asymmetric).
    pub l3_vni: Option<u32>,
}

/// A persistent, long-lived push in either direction (`nos-fdbd` ->
/// `nos-bgpd` local MACs, `nos-bgpd` -> `nos-fdbd` received routes): `Full`
/// on connect, then incremental `Add`/`Remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvpnUpdate {
    /// The complete route set, replacing any previous one.
    Full(Vec<EvpnRoute>),
    /// One route added or changed.
    Add(EvpnRoute),
    /// One route withdrawn.
    Remove(EvpnKey),
    /// A leading part of a `Full` too large for one frame: the receiver
    /// stages it and applies nothing until the closing `Full`. Appended
    /// (postcard indexes variants by position).
    FullPart(Vec<EvpnRoute>),
}

/// Encoded-byte budget of one `EvpnUpdate` frame: a quarter of the codec's
/// `MAX_FRAME`. A route's `ext_communities` is bounded only by the 64 KiB BGP
/// attribute, so a route-count budget would not do; bytes do.
pub const EVPN_PUSH_BYTES: usize = crate::codec::MAX_FRAME / 4;

/// The budget every sender passes to [`EvpnUpdate::split_with`]:
/// [`EVPN_PUSH_BYTES`], or `NOS_EVPN_PUSH_BYTES` when set (a test hook, so
/// tests and dev runs need few routes). Not usable under the watchdog, which
/// clears its children's environment.
#[must_use]
pub fn evpn_push_budget() -> usize {
    parse_budget(std::env::var("NOS_EVPN_PUSH_BYTES").ok().as_deref())
}

fn parse_budget(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.trim().parse().ok())
        .unwrap_or(EVPN_PUSH_BYTES)
}

impl EvpnUpdate {
    /// [`Self::split_with`] at [`evpn_push_budget`].
    #[must_use]
    pub fn split(self) -> Vec<Self> {
        self.split_with(evpn_push_budget())
    }

    /// The frames to send for this update: anything but a `Full` over
    /// `budget` encoded bytes is itself; that one becomes `FullPart`s closed
    /// by a `Full` holding the last chunk (see [`crate::chunk::split_full`]).
    #[must_use]
    pub fn split_with(self, budget: usize) -> Vec<Self> {
        let Self::Full(routes) = self else {
            return vec![self];
        };
        let weight = |r: &EvpnRoute| postcard::to_allocvec(r).map_or(usize::MAX, |v| v.len());
        let (parts, last) = crate::chunk::split_full(routes, budget, weight);
        let mut out: Vec<_> = parts.into_iter().map(Self::FullPart).collect();
        out.push(Self::Full(last));
        out
    }

    /// Receiver side of [`Self::split_with`]: stages a `FullPart` (returns
    /// `None`), folds the staged parts into the closing `Full`, passes
    /// `Add`/`Remove` through. The `usize` is the frames the update took (1
    /// when unchunked), for the receiver's log.
    pub fn absorb(
        self,
        staging: &mut crate::chunk::FullStaging<EvpnRoute>,
    ) -> Option<(Self, usize)> {
        match self {
            Self::FullPart(r) => {
                staging.part(r);
                None
            }
            Self::Full(r) => {
                let (all, parts) = staging.close(r);
                Some((Self::Full(all), parts))
            }
            other => Some((other, 1)),
        }
    }
}

/// Messages to one `nos-fdbd` instance's socket. Append-only (postcard).
#[derive(Debug, Serialize, Deserialize)]
pub enum FdbRequest {
    /// Query the domain's MAC table.
    GetMacs,
    /// Fire-and-forget, `nos-bgpd` only: every EVPN route the BGP instance
    /// named by the domain's `redistribute from mac to bgp` received.
    PushEvpnRoutes(EvpnUpdate),
}

/// Replies from `nos-fdbd`.
#[derive(Debug, Serialize, Deserialize)]
pub enum FdbEvent {
    /// Reply to `GetMacs`.
    Table(FdbTable),
}

/// A broadcast domain's forwarding table, for `show fdb`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdbTable {
    /// Broadcast domain name.
    pub domain: String,
    /// VXLAN Network Identifier of the domain.
    pub vni: u32,
    /// Bridge and VXLAN device names, once nos-fdbd has resolved/created them.
    pub bridge: Option<String>,
    /// Name of the VXLAN device, once created.
    pub vxlan: Option<String>,
    /// The MAC entries.
    pub macs: Vec<MacEntry>,
    /// IP-to-MAC bindings: local ARP/ND and SVI addresses, and remote Type-2
    /// routes carrying an IP.
    pub neighbours: Vec<NeighEntry>,
    /// Remote VTEPs BUM traffic is replicated to (one per received Type-3).
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub flood: Vec<IpAddr>,
    /// The Ethernet Segments this domain is attached to (an aggregate with an
    /// `esi` that is a member of the domain) and this PE's Designated
    /// Forwarder role on each.
    pub segments: Vec<EsEntry>,
    /// Whether ARP/ND suppression (`neigh-suppress`) is in effect on the
    /// VXLAN bridge port: the value nos-fdbd last applied to the kernel,
    /// not merely the configured one.
    pub neigh_suppress: bool,
}

/// One locally attached Ethernet Segment, as seen from one broadcast domain.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // wire status flags, one per independent fact
pub struct EsEntry {
    /// `00:11:22:33:44:55:66:77:88:99`.
    pub esi: String,
    /// The bridge port the segment attaches through (the bond or its VLAN
    /// sub-link).
    pub port: String,
    /// Whether this PE is the segment's Designated Forwarder for the domain's
    /// BUM traffic. A non-DF has flooding to `port` turned off.
    pub designated_forwarder: bool,
    /// Every PE attached to the segment (this one included), in the order the
    /// DF election ranks them.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub pes: Vec<IpAddr>,
    /// The PEs whose per-ES Ethernet A-D route for this segment is currently
    /// held (this one excluded): a remote MAC on the segment is only installed
    /// while its PE is listed here.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub ad_pes: Vec<IpAddr>,
    /// Whether the segment's port is up (carrier). A down segment withdraws its
    /// Type-4 and Type-1 routes and stops being a DF candidate.
    pub up: bool,
    /// Single-active redundancy: a non-DF blocks the port outright (unicast
    /// too), instead of only refusing BUM.
    pub single_active: bool,
    /// The DF election algorithm in effect (RFC 8584 §2.2.3): `Hrw` only when
    /// every candidate PE asked for it, else `Modulo`.
    pub df_algorithm: crate::DfAlgorithm,
    /// EVPN local bias (RFC 8365 §8.3.1) is fully in place on this segment:
    /// the PE delivers BUM from its own hosts to the segment whatever the DF
    /// role and drops BUM from the other PEs on it. `false` on a single-active
    /// segment (it does not apply) and when the kernel could not be set up
    /// (missing tc modules), in which case only the DF floods to the segment.
    pub local_bias: bool,
}

/// One MAC in a domain's forwarding table.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacEntry {
    /// `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    /// How the entry was learned.
    pub source: MacSource,
    /// The remote VTEP for a `Remote` entry (the first of `vteps`).
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub vtep: Option<IpAddr>,
    /// Every VTEP a `Remote` entry is reached through: one, or several when
    /// the MAC sits on an all-active Ethernet Segment and traffic is balanced
    /// over its PEs (aliasing, RFC 7432 §8.4.1.1). Empty for a `Local` MAC.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub vteps: Vec<IpAddr>,
    /// The Ethernet Segment a `Local` MAC was learned on, when its port is one.
    pub esi: Option<String>,
}

/// One IP-to-MAC neighbor entry of an IP-VRF.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighEntry {
    /// IP address.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: IpAddr,
    /// `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    /// How the entry was learned.
    pub source: MacSource,
    /// The remote VTEP for a `Remote` entry.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub vtep: Option<IpAddr>,
}

/// How a MAC or neighbor entry was learned.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacSource {
    /// Learned by the bridge on a local port.
    Local,
    /// Learned from an EVPN Type-2 route.
    Remote,
}

#[cfg(test)]
mod tests {
    use tokio_util::codec::Encoder;

    use super::*;
    use crate::codec::{IpcCodec, MAX_FRAME};

    fn route(i: u32, communities: usize) -> EvpnRoute {
        EvpnRoute {
            key: EvpnKey::Mac {
                rd: [0; 8],
                mac: [
                    0,
                    0,
                    i.to_be_bytes()[0],
                    i.to_be_bytes()[1],
                    i.to_be_bytes()[2],
                    i.to_be_bytes()[3],
                ],
            },
            vni: 10,
            next_hop: IpAddr::from([10, 0, 0, 1]),
            ext_communities: vec![u64::MAX; communities],
            esi: Esi::default(),
            l3_vni: None,
        }
    }

    fn size(r: &EvpnRoute) -> usize {
        postcard::to_allocvec(r).unwrap().len()
    }

    fn rejoin(frames: Vec<EvpnUpdate>) -> Vec<EvpnRoute> {
        frames
            .into_iter()
            .flat_map(|u| match u {
                EvpnUpdate::Full(r) | EvpnUpdate::FullPart(r) => r,
                _ => unreachable!(),
            })
            .collect()
    }

    #[test]
    fn absorb_stages_parts_and_closes_with_the_full() {
        let all: Vec<_> = (0..20).map(|i| route(i, 0)).collect();
        let mut st = crate::chunk::FullStaging::default();
        let mut got = None;
        for f in EvpnUpdate::Full(all.clone()).split_with(200) {
            assert!(got.is_none(), "nothing before the closing Full");
            got = f.absorb(&mut st);
        }
        let (u, parts) = got.unwrap();
        assert_eq!(u, EvpnUpdate::Full(all));
        assert!(parts > 1);
        let add = EvpnUpdate::Add(route(1, 0));
        assert_eq!(add.clone().absorb(&mut st), Some((add, 1)));
    }

    #[test]
    fn small_full_and_incrementals_are_not_split() {
        let r = route(1, 0);
        assert_eq!(
            EvpnUpdate::Full(vec![]).split_with(100),
            [EvpnUpdate::Full(vec![])]
        );
        let exact = vec![r.clone(), r.clone()];
        let budget = 2 * size(&r);
        assert_eq!(
            EvpnUpdate::Full(exact.clone()).split_with(budget),
            [EvpnUpdate::Full(exact)]
        );
        assert_eq!(
            EvpnUpdate::Add(r.clone()).split_with(1),
            [EvpnUpdate::Add(r.clone())]
        );
        let k = r.key;
        assert_eq!(
            EvpnUpdate::Remove(k.clone()).split_with(1),
            [EvpnUpdate::Remove(k)]
        );
    }

    #[test]
    fn a_big_full_is_cut_by_encoded_bytes_in_order() {
        let all: Vec<_> = (0..50).map(|i| route(i, (i % 7) as usize * 10)).collect();
        let budget = 1024;
        let frames = EvpnUpdate::Full(all.clone()).split_with(budget);
        assert!(frames.len() > 2);
        let (last, parts) = frames.split_last().unwrap();
        assert!(matches!(last, EvpnUpdate::Full(_)));
        assert!(parts.iter().all(|u| matches!(u, EvpnUpdate::FullPart(_))));
        for f in &frames {
            let (EvpnUpdate::Full(r) | EvpnUpdate::FullPart(r)) = f else {
                unreachable!()
            };
            assert!(r.iter().map(size).sum::<usize>() <= budget);
        }
        assert_eq!(rejoin(frames), all);
    }

    #[test]
    fn a_lone_oversized_route_travels_alone() {
        let all = vec![route(1, 0), route(2, 500), route(3, 0)];
        let frames = EvpnUpdate::Full(all.clone()).split_with(200);
        assert_eq!(frames.len(), 3);
        assert_eq!(rejoin(frames), all);
    }

    #[test]
    fn budget_env_parsing() {
        assert_eq!(parse_budget(None), EVPN_PUSH_BYTES);
        assert_eq!(parse_budget(Some("junk")), EVPN_PUSH_BYTES);
        assert_eq!(parse_budget(Some(" 16384 ")), 16384);
        assert!(evpn_push_budget() > 0);
    }

    /// The reason for the byte budget: a `Full` over `MAX_FRAME` is cut so
    /// every frame, at the production budget, still encodes.
    #[test]
    #[cfg_attr(miri, ignore = "serialises >16 MiB, minutes under the interpreter")]
    fn a_full_over_max_frame_splits_under_it() {
        let all: Vec<_> = (0..300).map(|i| route(i, 8000)).collect();
        let whole =
            postcard::to_allocvec(&FdbRequest::PushEvpnRoutes(EvpnUpdate::Full(all.clone())))
                .unwrap();
        assert!(whole.len() > MAX_FRAME, "{} bytes", whole.len());
        let frames = EvpnUpdate::Full(all.clone()).split_with(EVPN_PUSH_BYTES);
        assert!(frames.len() > 1);
        for f in &frames {
            let mut buf = bytes::BytesMut::new();
            IpcCodec::<FdbRequest>::default()
                .encode(FdbRequest::PushEvpnRoutes(f.clone()), &mut buf)
                .unwrap();
            assert!(buf.len() < MAX_FRAME);
        }
        assert_eq!(rejoin(frames), all);
    }
}
