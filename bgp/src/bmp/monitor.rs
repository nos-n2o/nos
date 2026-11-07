//! Route Monitoring (RFC 7854 section 4.6) and End-of-RIB builders (#864).
//! Pure: a stored route or a received UPDATE in, BMP frames out.
//!
//! Every PDU is re-encoded with 4-byte `AS_PATH` (so the A flag stays 0,
//! section 4.2 allows reformatting), one BMP message per BGP PDU.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use ipnet::IpNet;
use tokio_util::codec::Encoder;

use super::{frame, PeerUpInfo, Scope};
use crate::message::{
    BgpCodec, BgpMessage, MpReachNlri, MpUnreachNlri, PathAttributes, UpdateMessage, AFI_IPV4,
    AFI_IPV6,
};
use crate::rib::RibRoute;

const TYPE_ROUTE_MONITORING: u8 = 0;
/// A BGP PDU's length field sits after the 16-byte marker.
const PDU_LEN_AT: usize = 16;

pub(super) fn afi_of(prefix: IpNet) -> u16 {
    match prefix {
        IpNet::V4(_) => AFI_IPV4,
        IpNet::V6(_) => AFI_IPV6,
    }
}

pub(super) fn is_unicast(afi: u16, safi: u8) -> bool {
    safi == 1 && (afi == AFI_IPV4 || afi == AFI_IPV6)
}

/// `update` reduced to IPv4/IPv6 unicast, `None` when nothing is left.
/// ponytail: unicast only for now; the other families land with the all-family
/// monitoring sub-issue.
pub fn unicast_only(update: &UpdateMessage) -> Option<UpdateMessage> {
    let mut u = update.clone();
    u.mp_reach.retain(|m| is_unicast(m.afi, m.safi));
    u.mp_unreach.retain(|m| is_unicast(m.afi, m.safi));
    if u.nlri.is_empty() && u.mp_reach.is_empty() {
        u.attributes = None;
    }
    let empty = u.withdrawn_routes.is_empty()
        && u.nlri.is_empty()
        && u.mp_reach.is_empty()
        && u.mp_unreach.is_empty();
    (!empty).then_some(u)
}

/// The UPDATE announcing path `id` of `prefix` as stored: IPv4 in `nlri`
/// (unless its next hop is IPv6, RFC 8950), everything else in `MP_REACH_NLRI`.
/// `add_path` writes the path id (the session negotiated it for this AFI).
pub fn rib_route_to_update(prefix: IpNet, id: u32, r: &RibRoute, add_path: bool) -> UpdateMessage {
    let legacy = match (prefix, r.next_hop) {
        (IpNet::V4(p), None | Some(IpAddr::V4(_))) => Some(p),
        _ => None,
    };
    let v4_hop = match r.next_hop {
        Some(IpAddr::V4(a)) => a,
        _ => Ipv4Addr::UNSPECIFIED,
    };
    let ids = if add_path { vec![id] } else { Vec::new() };
    let attributes = Some(PathAttributes {
        origin: r.bgp_origin,
        as_path: (*r.as_path).clone(),
        next_hop: if legacy.is_some() {
            v4_hop
        } else {
            Ipv4Addr::UNSPECIFIED
        },
        local_pref: Some(r.local_pref),
        med: r.med,
        originator_id: r.originator_id,
        cluster_list: r.cluster_list.to_vec(),
        communities: r.communities.clone(),
        extended_communities: r.extended_communities.clone(),
        large_communities: r.large_communities.clone(),
        ipv6_extended_communities: Vec::new(),
        pmsi: None,
        atomic_aggregate: r.atomic_aggregate,
        aggregator: r.aggregator,
        otc: r.otc,
    });
    match legacy {
        Some(p) => UpdateMessage {
            nlri: vec![p],
            nlri_path_ids: ids,
            attributes,
            ..Default::default()
        },
        None => UpdateMessage {
            attributes,
            mp_reach: vec![MpReachNlri {
                afi: afi_of(prefix),
                safi: 1,
                next_hop: r.next_hop.unwrap_or(match prefix {
                    IpNet::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpNet::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                }),
                nlri: vec![prefix],
                nlri_path_ids: ids,
                evpn: Vec::new(),
                flowspec: Vec::new(),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..Default::default()
        },
    }
}

/// The UPDATE withdrawing path `id` of `prefix`.
pub fn rib_withdraw_to_update(prefix: IpNet, id: u32, add_path: bool) -> UpdateMessage {
    let ids = if add_path { vec![id] } else { Vec::new() };
    match prefix {
        IpNet::V4(p) => UpdateMessage {
            withdrawn_routes: vec![p],
            withdrawn_path_ids: ids,
            ..Default::default()
        },
        IpNet::V6(_) => UpdateMessage {
            mp_unreach: vec![MpUnreachNlri {
                afi: AFI_IPV6,
                safi: 1,
                withdrawn: vec![prefix],
                withdrawn_path_ids: ids,
                evpn: Vec::new(),
                flowspec: Vec::new(),
                vpn: Vec::new(),
                rtc: Vec::new(),
            }],
            ..Default::default()
        },
    }
}

fn body(scope: &Scope, p: &PeerUpInfo, post: bool, ts: Duration, pdu: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(42 + pdu.len());
    p.put_header(&mut b, scope, ts, false, post);
    b.extend_from_slice(pdu);
    frame(TYPE_ROUTE_MONITORING, &b)
}

/// Route Monitoring frames for `update`: one per BGP PDU the encoder needs
/// (it splits an UPDATE over the 4096-byte limit). `post` sets the L flag.
pub fn route_monitoring(
    scope: &Scope,
    p: &PeerUpInfo,
    post: bool,
    update: &UpdateMessage,
    ts: Duration,
) -> Vec<Bytes> {
    let mut codec = BgpCodec {
        add_path_afis: p.add_path_afis.clone(),
        ..Default::default()
    };
    let mut buf = BytesMut::new();
    if codec
        .encode(BgpMessage::Update(update.clone()), &mut buf)
        .is_err()
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut rest = &buf[..];
    while rest.len() > PDU_LEN_AT + 2 {
        let len = usize::from(u16::from_be_bytes([rest[PDU_LEN_AT], rest[PDU_LEN_AT + 1]]));
        if len < 19 || len > rest.len() {
            break;
        }
        out.push(body(scope, p, post, ts, &rest[..len]));
        rest = &rest[len..];
    }
    out
}

/// A per-peer End-of-RIB marker (RFC 4724 form) for `afi`/`safi`.
pub fn end_of_rib(scope: &Scope, p: &PeerUpInfo, post: bool, afi: u16, safi: u8) -> Bytes {
    let pdu = super::bgp_pdu(BgpMessage::EndOfRib { afi, safi });
    body(scope, p, post, super::now(), &pdu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Origin;
    use std::sync::Arc;
    use tokio_util::codec::Decoder;

    fn peer(addr: &str, add_path: &[u16]) -> PeerUpInfo {
        PeerUpInfo {
            peer: addr.parse().unwrap(),
            asn: 65002,
            bgp_id: Ipv4Addr::new(2, 2, 2, 2),
            two_octet_as: true,
            local: "192.0.2.1".parse().unwrap(),
            local_port: 179,
            remote_port: 1,
            sent_open: Bytes::new(),
            recv_open: Bytes::new(),
            time: Duration::ZERO,
            add_path_afis: add_path.iter().copied().collect(),
        }
    }

    fn route(next_hop: Option<&str>) -> RibRoute {
        RibRoute {
            origin: crate::rib::RouteOrigin::Peer("192.0.2.2".parse().unwrap()),
            as_path: Arc::new(crate::as_path::AsPath::from(vec![65002, 4_200_000_000])),
            bgp_origin: Origin::Igp,
            local_pref: 150,
            med: Some(7),
            learned_via_ibgp: false,
            learned_via_confed: false,
            router_id: None,
            next_hop: next_hop.map(|a| a.parse().unwrap()),
            received_at: std::time::Instant::now(),
            originator_id: None,
            cluster_list: Arc::new(Vec::new()),
            communities: vec![0x0001_0002],
            extended_communities: Vec::new(),
            large_communities: vec![(1, 2, 3)],
            atomic_aggregate: false,
            aggregator: None,
            otc: None,
            validation_state: nos_rpl::ValidationState::NotFound,
            received_ov: None,
        }
    }

    fn decode(f: &Bytes) -> UpdateMessage {
        assert_eq!((f[0], f[5]), (3, 0), "BMP v3, Route Monitoring");
        assert_eq!(
            usize::try_from(u32::from_be_bytes(f[1..5].try_into().unwrap())).unwrap(),
            f.len()
        );
        let mut b = BytesMut::from(&f[6 + 42..]);
        match BgpCodec::default().decode(&mut b).unwrap().unwrap() {
            BgpMessage::Update(u) => u,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ipv4_announce_round_trips_with_the_l_flag() {
        let p = "10.1.0.0/16".parse().unwrap();
        let u = rib_route_to_update(p, 0, &route(Some("192.0.2.2")), false);
        let post = route_monitoring(
            &Scope::default(),
            &peer("192.0.2.2", &[]),
            true,
            &u,
            Duration::new(5, 6000),
        );
        let pre = route_monitoring(
            &Scope::default(),
            &peer("192.0.2.2", &[]),
            false,
            &u,
            Duration::ZERO,
        );
        assert_eq!((post.len(), pre.len()), (1, 1));
        let h = &post[0][6..];
        assert_eq!(h[0], 0, "global peer");
        assert_eq!(
            h[1], 0x40,
            "L set, V clear, A clear even for a 2-octet session"
        );
        assert_eq!(pre[0][7], 0, "L clear pre-policy");
        assert_eq!(&h[34..38], &5u32.to_be_bytes());
        let back = decode(&post[0]);
        assert_eq!(back.nlri, vec!["10.1.0.0/16".parse().unwrap()]);
        let a = back.attributes.unwrap();
        assert_eq!(a.as_path.flat(), [65002, 4_200_000_000]);
        assert_eq!(
            (
                a.local_pref,
                a.med,
                a.communities,
                a.large_communities,
                a.next_hop
            ),
            (
                Some(150),
                Some(7),
                vec![0x0001_0002],
                vec![(1, 2, 3)],
                Ipv4Addr::new(192, 0, 2, 2)
            )
        );
    }

    #[test]
    fn ipv6_announce_uses_mp_reach_and_the_v_flag() {
        let p: IpNet = "2001:db8:1::/48".parse().unwrap();
        let u = rib_route_to_update(p, 0, &route(Some("2001:db8::2")), false);
        let f = route_monitoring(
            &Scope::default(),
            &peer("2001:db8::2", &[]),
            true,
            &u,
            Duration::ZERO,
        );
        assert_eq!(f[0][7], 0x80 | 0x40);
        let back = decode(&f[0]);
        assert_eq!(back.nlri, Vec::<ipnet::Ipv4Net>::new());
        assert_eq!(back.mp_reach[0].nlri, vec![p]);
        assert_eq!(
            back.mp_reach[0].next_hop,
            "2001:db8::2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ipv4_with_an_ipv6_next_hop_goes_through_mp_reach() {
        let p: IpNet = "10.2.0.0/16".parse().unwrap();
        let u = rib_route_to_update(p, 0, &route(Some("2001:db8::2")), false);
        assert_eq!(u.nlri, Vec::<ipnet::Ipv4Net>::new());
        assert_eq!(u.mp_reach[0].afi, AFI_IPV4);
    }

    #[test]
    fn add_path_ids_follow_the_session() {
        let p: IpNet = "10.1.0.0/16".parse().unwrap();
        let info = peer("192.0.2.2", &[AFI_IPV4]);
        let ann = rib_route_to_update(p, 7, &route(None), true);
        let mut codec = BgpCodec {
            add_path_afis: info.add_path_afis.clone(),
            ..Default::default()
        };
        let f = route_monitoring(&Scope::default(), &info, true, &ann, Duration::ZERO);
        let mut b = BytesMut::from(&f[0][6 + 42..]);
        let Some(BgpMessage::Update(back)) = codec.decode(&mut b).unwrap() else {
            panic!()
        };
        assert_eq!(back.nlri_path_ids, [7]);
        let w = rib_withdraw_to_update(p, 7, true);
        let f = route_monitoring(&Scope::default(), &info, true, &w, Duration::ZERO);
        let mut b = BytesMut::from(&f[0][6 + 42..]);
        let Some(BgpMessage::Update(back)) = codec.decode(&mut b).unwrap() else {
            panic!()
        };
        assert_eq!(
            (back.withdrawn_routes, back.withdrawn_path_ids),
            (vec!["10.1.0.0/16".parse().unwrap()], vec![7])
        );
    }

    #[test]
    fn withdraws_for_both_families() {
        let v4 = rib_withdraw_to_update("10.1.0.0/16".parse().unwrap(), 0, false);
        assert_eq!(
            decode(
                &route_monitoring(
                    &Scope::default(),
                    &peer("192.0.2.2", &[]),
                    true,
                    &v4,
                    Duration::ZERO
                )[0]
            )
            .withdrawn_routes
            .len(),
            1
        );
        let v6 = rib_withdraw_to_update("2001:db8::/32".parse().unwrap(), 0, false);
        let back = decode(
            &route_monitoring(
                &Scope::default(),
                &peer("192.0.2.2", &[]),
                true,
                &v6,
                Duration::ZERO,
            )[0],
        );
        assert_eq!(back.mp_unreach[0].withdrawn.len(), 1);
    }

    #[test]
    fn end_of_rib_forms() {
        let i = peer("192.0.2.2", &[]);
        let v4 = end_of_rib(&Scope::default(), &i, true, 1, 1);
        assert_eq!(v4[7], 0x40);
        assert_eq!(&v4[6 + 42 + 16..], &[0, 23, 2, 0, 0, 0, 0]);
        let v6 = end_of_rib(&Scope::default(), &i, false, 2, 1);
        assert_eq!(v6[7], 0);
        assert_eq!(&v6[6 + 42 + 19..], &[0, 0, 0, 6, 0x80, 15, 3, 0, 2, 1]);
    }

    #[test]
    fn unicast_only_filters_other_families() {
        let mut u = rib_route_to_update(
            "2001:db8::/32".parse().unwrap(),
            0,
            &route(Some("2001:db8::2")),
            false,
        );
        let mut evpn = u.mp_reach[0].clone();
        evpn.afi = 25;
        evpn.safi = 70;
        u.mp_reach.push(evpn);
        assert_eq!(unicast_only(&u).unwrap().mp_reach.len(), 1);
        u.mp_reach.retain(|m| m.afi == 25);
        u.withdrawn_routes.push("10.0.0.0/8".parse().unwrap());
        let only = unicast_only(&u).unwrap();
        assert!(only.mp_reach.is_empty() && only.attributes.is_none());
        u.withdrawn_routes.clear();
        assert!(unicast_only(&u).is_none(), "nothing unicast left");
    }

    #[test]
    fn an_oversize_update_becomes_several_frames() {
        let mut u = rib_route_to_update("10.0.0.0/24".parse().unwrap(), 0, &route(None), false);
        u.nlri = (0..2000u32)
            .map(|i| ipnet::Ipv4Net::new(Ipv4Addr::from(0x0a00_0000 + (i << 8)), 24).unwrap())
            .collect();
        let frames = route_monitoring(
            &Scope::default(),
            &peer("192.0.2.2", &[]),
            false,
            &u,
            Duration::ZERO,
        );
        assert!(frames.len() > 1);
        let n: usize = frames.iter().map(|f| decode(f).nlri.len()).sum();
        assert_eq!(n, 2000);
    }
}
