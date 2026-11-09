//! The I/O half of `fsm.rs` (#344): the pure encode/classify helpers called
//! directly, and `run` over loopback TCP against a scripted peer, one
//! command or message per branch. The negotiation core (`step`) keeps its
//! unit tests in `fsm.rs`.

use crate::message::MessageHeaderSubcode;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use ipnet::IpNet;
use nos_proto::{BgpAddPath, BgpMaximumPrefix, BgpPrefixLimit, BgpRole};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;

use super::*;
use crate::collision::Role;
use crate::message::{Capability, Origin, PathAttributes, UpdateMessage};
use crate::rib::{AdvertisedRoute, BgpRib};
use crate::session::ResolvedPeer;

const PEER: &str = "10.0.0.2";
const OTHER: &str = "10.9.9.9";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn rpeer() -> ResolvedPeer {
    let accept = Arc::new(nos_rpl::ACCEPT_ALL.clone());
    ResolvedPeer {
        remote_address: ip(PEER),
        source_address: None,
        remote_as: 65002,
        peer_group: "pg".into(),
        hold_time: 90,
        keepalive_interval: None,
        connect_retry_time: Duration::from_secs(120),
        mrai: Duration::ZERO,
        route_refresh_stale_time: Duration::ZERO,
        damping: None,
        max_hops: None,
        auth: None,
        next_hop: None,
        address_families: vec![AddressFamily::Ipv4Unicast],
        route_reflector_client: false,
        route_server_client: false,
        import_policy: accept.clone(),
        export_policy: accept,
        evpn_import_policy: None,
        flowspec_import_policy: None,
        flowspec_export_policy: None,
        enforce_first_as: true,
        flowspec_validation: nos_proto::BgpFlowspecValidation::default(),
        shutdown: None,
        maximum_prefix: BgpMaximumPrefix::default(),
        announce_rpki_state: false,
        blackhole: None,
        soft_reconfiguration_inbound: false,
        local_as: None,
        add_path: None,
        add_path_send_count: None,
        role: None,
        strict_mode: false,
        confed_id: None,
        confed_member: false,
        graceful_restart: None,
    }
}

fn pctx(rp: &ResolvedPeer) -> PeerContext {
    PeerContext {
        remote_address: rp.remote_address,
        expected_remote_as: rp.remote_as,
        local_hold_time: rp.hold_time,
        keepalive_override: rp.keepalive_interval,
        mrai: rp.mrai,
        route_refresh_stale_time: rp.route_refresh_stale_time,
        damping: rp.damping,
        next_hop: rp.next_hop,
        address_families: rp.address_families.clone(),
        is_rr_client: rp.route_reflector_client,
        is_rs_client: rp.route_server_client,
        import_policy: rp.import_policy.clone(),
        export_policy: rp.export_policy.clone(),
    }
}

fn local() -> LocalIdentity {
    LocalIdentity {
        asn: 65001,
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        cluster_id: Ipv4Addr::new(1, 1, 1, 1),
        confed_id: None,
    }
}

fn new_rib() -> Arc<SharedRib> {
    let mut rib = BgpRib::new();
    rib.set_local_identity(65001, Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 1, 1, 1));
    Arc::new(SharedRib::new(rib))
}

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, connected) = tokio::join!(async { listener.accept().await.unwrap().0 }, async {
        TcpStream::connect(addr).await.unwrap()
    });
    (connected, accepted)
}

fn path_attrs(asn: u32) -> PathAttributes {
    PathAttributes {
        origin: Origin::Igp,
        as_path: vec![asn].into(),
        next_hop: Ipv4Addr::new(10, 0, 0, 2),
        local_pref: None,
        med: None,
        originator_id: None,
        atomic_aggregate: false,
        aggregator: None,
        otc: None,
        cluster_list: vec![],
        communities: vec![],
        extended_communities: vec![],
        large_communities: vec![],
        ipv6_extended_communities: Vec::new(),
        pmsi: None,
    }
}

fn update(asn: u32, prefixes: &[&str]) -> UpdateMessage {
    UpdateMessage {
        withdrawn_routes: vec![],
        withdrawn_path_ids: vec![],
        nlri: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
        nlri_path_ids: vec![],
        attributes: Some(path_attrs(asn)),
        mp_reach: vec![],
        mp_unreach: vec![],
        ..Default::default()
    }
}

/// An established-looking `RemoteInfo` for the direct (no socket) tests.
fn remote(enhanced: bool, route_refresh: bool) -> RemoteInfo {
    RemoteInfo {
        asn: 65002,
        bgp_id: Ipv4Addr::new(2, 2, 2, 2),
        mp_bgp_negotiated: true,
        negotiated_ipv4_unicast: true,
        negotiated_ipv6_unicast: true,
        negotiated_evpn: false,
        negotiated_flowspec: [false; 2],
        negotiated_vpn: [false; 2],
        negotiated_rtc: false,
        add_path: [AddPathDir::default(); 2],
        four_octet_as: true,
        extended_message: false,
        enhanced_refresh: enhanced,
        route_refresh,
        gr: None,
        role: None,
    }
}

async fn within<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .unwrap_or_else(|_| panic!("timed out: {what}"))
}

// -------------------------------------------------------- pure helpers

#[test]
fn family_and_afi_mappings() {
    assert_eq!(afi_of(AddressFamily::Ipv4Unicast), 1);
    assert_eq!(afi_of(AddressFamily::Ipv6Unicast), 2);
    assert_eq!(afi_of(AddressFamily::L2vpnEvpn), message::AFI_L2VPN);
    assert_eq!(safi_of(AddressFamily::Ipv4Unicast), 1);
    assert_eq!(safi_of(AddressFamily::Ipv6Unicast), 1);
    assert_eq!(safi_of(AddressFamily::L2vpnEvpn), message::SAFI_EVPN);
    assert_eq!(afi_of_addr(ip("10.0.0.1")), AFI_IPV4);
    assert_eq!(afi_of_addr(ip("2001:db8::1")), AFI_IPV6);
    assert_eq!(afi_of_ipnet("10.0.0.0/8".parse().unwrap()), AFI_IPV4);
    assert_eq!(afi_of_ipnet("2001:db8::/32".parse().unwrap()), AFI_IPV6);
    assert_eq!(family_of_afi(1), Some(AddressFamily::Ipv4Unicast));
    assert_eq!(family_of_afi(2), Some(AddressFamily::Ipv6Unicast));
    assert_eq!(family_of_afi(25), None, "EVPN has no ROUTE_REFRESH here");
    assert_eq!(family_of_afi(99), None);
}

#[test]
fn mp_capabilities_add_extended_next_hop_only_for_a_cross_family_unicast() {
    let caps = build_mp_capabilities(
        &[
            AddressFamily::Ipv4Unicast,
            AddressFamily::Ipv6Unicast,
            AddressFamily::L2vpnEvpn,
        ],
        AFI_IPV4,
    );
    assert_eq!(
        caps,
        [
            Capability::MultiProtocol { afi: 1, safi: 1 },
            Capability::MultiProtocol { afi: 2, safi: 1 },
            Capability::ExtendedNextHop {
                nlri_afi: 2,
                nlri_safi: 1,
                nh_afi: 1
            },
            Capability::MultiProtocol {
                afi: message::AFI_L2VPN,
                safi: message::SAFI_EVPN
            },
        ]
    );
}

#[test]
fn a_cross_family_unicast_needs_the_peers_extended_next_hop() {
    let ctx = NegotiationContext {
        expected_remote_as: 65002,
        local_hold_time: 90,
        keepalive_override: None,
        address_families: vec![AddressFamily::Ipv4Unicast, AddressFamily::Ipv6Unicast],
        transport_afi: AFI_IPV4,
        add_path: None,
        role: None,
        strict_mode: false,
    };
    let mut open = message::build_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90);
    open.capabilities.extend([
        Capability::MultiProtocol { afi: 1, safi: 1 },
        Capability::MultiProtocol { afi: 2, safi: 1 },
    ]);
    assert_eq!(
        negotiate_address_families(&open, &ctx),
        (true, true, false, false),
        "no ENH tuple: v6 over a v4 session is not carried"
    );
    open.capabilities.push(Capability::ExtendedNextHop {
        nlri_afi: 2,
        nlri_safi: 1,
        nh_afi: 1,
    });
    assert_eq!(
        negotiate_address_families(&open, &ctx),
        (true, true, true, false)
    );
}

#[test]
fn rtc_is_negotiated_only_when_configured_and_advertised() {
    let ctx = |afs: Vec<AddressFamily>| NegotiationContext {
        expected_remote_as: 65002,
        local_hold_time: 90,
        keepalive_override: None,
        address_families: afs,
        transport_afi: AFI_IPV4,
        add_path: None,
        role: None,
        strict_mode: false,
    };
    let mut open = message::build_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90);
    let both = vec![AddressFamily::Vpnv4Unicast, AddressFamily::RtConstraint];
    assert!(!negotiate_rtc(&open, &ctx(both.clone())), "peer silent");
    open.capabilities.push(Capability::MultiProtocol {
        afi: 1,
        safi: message::SAFI_RTC,
    });
    assert!(negotiate_rtc(&open, &ctx(both)));
    assert!(
        !negotiate_rtc(&open, &ctx(vec![AddressFamily::Vpnv4Unicast])),
        "not configured here"
    );
    assert_eq!(
        (
            afi_of(AddressFamily::RtConstraint),
            safi_of(AddressFamily::RtConstraint)
        ),
        (1, 132)
    );
    assert_eq!(
        build_mp_capabilities(&[AddressFamily::RtConstraint], AFI_IPV6),
        [Capability::MultiProtocol { afi: 1, safi: 132 }],
        "no extended next hop for a non-unicast SAFI"
    );
}

#[tokio::test]
async fn route_refresh_requests_cover_rtc_when_negotiated() {
    let rp = rpeer();
    let peer = pctx(&rp);
    let (mut w, mut r) = script_pair().await;
    let mut rem = remote(true, true);
    rem.negotiated_ipv4_unicast = false;
    rem.negotiated_ipv6_unicast = false;
    rem.negotiated_rtc = true;
    send_route_refresh(&mut w, &State::Established(rem), &peer).await;
    let m = within("refresh", r.next()).await.unwrap().unwrap();
    assert_eq!(
        m,
        BgpMessage::RouteRefresh(RouteRefreshMessage {
            afi: AFI_IPV4,
            subtype: message::REFRESH_REQUEST,
            safi: message::SAFI_RTC
        })
    );
}

#[test]
fn add_path_direction_names() {
    let d = |rx, tx| AddPathDir { rx, tx }.as_str();
    assert_eq!(d(false, false), "none");
    assert_eq!(d(true, false), "receive");
    assert_eq!(d(false, true), "send");
    assert_eq!(d(true, true), "both");
}

#[test]
fn a_malformed_message_in_any_state_sends_its_notification_and_closes() {
    let (next, actions) = step(
        State::OpenSent,
        Event::MalformedMessage(WireError::BadMarker),
        &NegotiationContext {
            expected_remote_as: 1,
            local_hold_time: 90,
            keepalive_override: None,
            address_families: vec![],
            transport_afi: AFI_IPV4,
            add_path: None,
            role: None,
            strict_mode: false,
        },
    );
    assert_eq!(next, None);
    assert_eq!(
        actions,
        [
            Action::SendNotificationData(
                ErrorCode::MessageHeader as u8,
                MessageHeaderSubcode::ConnectionNotSynchronized as u8,
                Bytes::new()
            ),
            Action::Close
        ]
    );
}

#[test]
fn event_outcome_reads_the_closing_cause_back() {
    let sent = |c: u8, s: u8| [Action::SendNotification(c, s), Action::Close];
    assert!(matches!(
        event_outcome(&sent(ErrorCode::HoldTimerExpired as u8, 0)),
        Some(FsmOutcome::HoldTimerExpired)
    ));
    assert!(matches!(
        event_outcome(&sent(
            ErrorCode::Cease as u8,
            CeaseSubcode::ConnectionCollisionResolution as u8
        )),
        Some(FsmOutcome::CollisionLost)
    ));
    assert!(event_outcome(&sent(ErrorCode::Cease as u8, 2)).is_none());
    assert!(event_outcome(&[Action::Close]).is_none());
}

#[tokio::test(start_paused = true)]
async fn sleep_until_opt_is_pending_without_a_deadline() {
    let none = tokio::time::timeout(Duration::from_secs(3600), sleep_until_opt(None)).await;
    assert!(none.is_err(), "no deadline never fires");
    let some = tokio::time::timeout(
        Duration::from_secs(3600),
        sleep_until_opt(Some(Instant::now() + Duration::from_secs(5))),
    )
    .await;
    assert!(some.is_ok());
}

fn route(prefix: &str, next_hop: &str, use_mp: bool, path_id: Option<u32>) -> AdvertisedRoute {
    AdvertisedRoute {
        prefix: prefix.parse().unwrap(),
        as_path: vec![65001, 65003].into(),
        next_hop: ip(next_hop),
        local_pref: Some(150),
        med: Some(7),
        origin: Origin::Egp,
        use_mp,
        originator_id: Some(Ipv4Addr::new(9, 9, 9, 9)),
        cluster_list: vec![Ipv4Addr::new(8, 8, 8, 8)],
        communities: vec![0x0001_0002],
        extended_communities: vec![5],
        large_communities: vec![(1, 2, 3)],
        atomic_aggregate: true,
        aggregator: None,
        otc: Some(65009),
        path_id,
    }
}

/// The announced prefixes of an UPDATE, legacy or `MP_REACH`.
fn announced(u: &UpdateMessage) -> Vec<IpNet> {
    let mut v: Vec<IpNet> = u.nlri.iter().map(|n| IpNet::V4(*n)).collect();
    for mp in &u.mp_reach {
        v.extend(mp.nlri.iter().copied());
    }
    v
}

fn expect_update(m: BgpMessage) -> UpdateMessage {
    match m {
        BgpMessage::Update(u) => u,
        other => panic!("not an update: {other:?}"),
    }
}

#[test]
fn announces_encode_as_legacy_nlri_or_mp_reach() {
    // Legacy: plain NLRI + NEXT_HOP, the id only when there is one.
    let u = expect_update(outbound_update_to_message(OutboundUpdate::Announce(route(
        "192.0.2.0/24",
        "10.0.0.1",
        false,
        Some(4),
    ))));
    assert_eq!(u.nlri, ["192.0.2.0/24".parse().unwrap()]);
    assert_eq!(u.nlri_path_ids, [4]);
    assert_eq!(u.mp_reach.len(), 0);
    let a = u.attributes.unwrap();
    assert_eq!(a.next_hop, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(a.local_pref, Some(150));
    assert_eq!(a.origin, Origin::Egp);
    assert!(a.atomic_aggregate);
    assert_eq!(a.otc, Some(65009));

    let u = expect_update(outbound_update_to_message(OutboundUpdate::Announce(route(
        "192.0.2.0/24",
        "10.0.0.1",
        false,
        None,
    ))));
    assert_eq!(u.nlri_path_ids.len(), 0);

    // MP: the next hop and NLRI ride MP_REACH, the plain fields are empty.
    let u = expect_update(outbound_update_to_message(OutboundUpdate::Announce(route(
        "2001:db8::/32",
        "2001:db8::1",
        true,
        Some(9),
    ))));
    assert_eq!(u.nlri.len(), 0);
    assert_eq!(u.mp_reach.len(), 1);
    let mp = &u.mp_reach[0];
    assert_eq!((mp.afi, mp.safi), (AFI_IPV6, 1));
    assert_eq!(mp.next_hop, ip("2001:db8::1"));
    assert_eq!(mp.nlri, ["2001:db8::/32".parse::<IpNet>().unwrap()]);
    assert_eq!(mp.nlri_path_ids, [9]);
    assert_eq!(u.attributes.unwrap().next_hop, Ipv4Addr::UNSPECIFIED);

    let u = expect_update(outbound_update_to_message(OutboundUpdate::Announce(route(
        "192.0.2.0/24",
        "10.0.0.1",
        true,
        None,
    ))));
    assert_eq!(u.mp_reach[0].afi, AFI_IPV4);
    assert_eq!(u.mp_reach[0].nlri_path_ids.len(), 0);
}

#[test]
fn flowspec_encodes_as_safi_133_with_its_ipv6_communities() {
    let rule = crate::flowspec::FlowSpec::decode(
        crate::flowspec::Afi::V6,
        &[7, 1, 32, 0, 0x20, 0x01, 0x0d, 0xb8],
    )
    .unwrap()
    .0;
    let c = [3u8; 20];
    let u = expect_update(outbound_update_to_message(
        OutboundUpdate::AnnounceFlowspec(crate::rib::AdvertisedFlowspec {
            family: AddressFamily::Ipv6Flowspec,
            nlri: rule.clone(),
            route: route("2001:db8::/32", "2001:db8::1", true, None),
            ipv6_extended_communities: vec![c],
        }),
    ));
    assert_eq!(u.nlri.len(), 0);
    let mp = &u.mp_reach[0];
    assert_eq!((mp.afi, mp.safi), (AFI_IPV6, message::SAFI_FLOWSPEC));
    assert_eq!(mp.nlri.len(), 0);
    assert_eq!(mp.flowspec, std::slice::from_ref(&rule));
    let a = u.attributes.unwrap();
    assert_eq!(a.ipv6_extended_communities, [c]);
    assert_eq!(a.extended_communities, [5]);
    assert_eq!(a.local_pref, Some(150));

    let u = expect_update(outbound_update_to_message(
        OutboundUpdate::WithdrawFlowspec(AddressFamily::Ipv6Flowspec, rule.clone()),
    ));
    assert!(u.attributes.is_none() && u.mp_reach.is_empty());
    let mp = &u.mp_unreach[0];
    assert_eq!((mp.afi, mp.safi), (AFI_IPV6, message::SAFI_FLOWSPEC));
    assert_eq!(mp.flowspec, [rule]);
}

#[test]
fn vpn_encodes_as_safi_128_with_its_label_rd_and_next_hop() {
    let rd = [0, 0, 0xfd, 0xe9, 0, 0, 0, 1];
    let prefix: ipnet::IpNet = "2001:db8:5::/48".parse().unwrap();
    let u = expect_update(outbound_update_to_message(OutboundUpdate::AnnounceVpn(
        crate::rib::AdvertisedVpn {
            key: (rd, prefix),
            labels: vec![100],
            route: route("2001:db8:5::/48", "192.0.2.9", true, None),
        },
    )));
    let mp = &u.mp_reach[0];
    assert_eq!((mp.afi, mp.safi), (AFI_IPV6, message::SAFI_VPN));
    assert_eq!(mp.next_hop, "192.0.2.9".parse::<IpAddr>().unwrap());
    assert_eq!(
        mp.vpn,
        [crate::vpn::VpnNlri {
            labels: vec![100],
            rd,
            prefix
        }]
    );
    assert_eq!(u.attributes.unwrap().local_pref, Some(150));

    let u = expect_update(outbound_update_to_message(OutboundUpdate::WithdrawVpn((
        rd, prefix,
    ))));
    assert!(u.attributes.is_none() && u.mp_reach.is_empty());
    let mp = &u.mp_unreach[0];
    assert_eq!((mp.afi, mp.safi), (AFI_IPV6, message::SAFI_VPN));
    assert_eq!(mp.vpn[0].labels, Vec::<u32>::new());
    assert_eq!(mp.vpn[0].rd, rd);
}

#[test]
fn rtc_encodes_as_safi_132_with_our_next_hop() {
    let key = message::RtcNlri {
        origin_as: 65000,
        rt: 0x0002_fde8_0000_0001,
        bits: 96,
    };
    let u = expect_update(outbound_update_to_message(OutboundUpdate::AnnounceRtc(
        crate::rib::AdvertisedRtc {
            key,
            route: route("0.0.0.0/0", "192.0.2.9", true, None),
        },
    )));
    let mp = &u.mp_reach[0];
    assert_eq!((mp.afi, mp.safi), (AFI_IPV4, message::SAFI_RTC));
    assert_eq!(mp.next_hop, "192.0.2.9".parse::<IpAddr>().unwrap());
    assert_eq!(mp.rtc, [key]);
    assert_eq!(u.attributes.unwrap().local_pref, Some(150));
    let u = expect_update(outbound_update_to_message(OutboundUpdate::WithdrawRtc(key)));
    assert!(u.attributes.is_none() && u.mp_reach.is_empty());
    assert_eq!(u.mp_unreach[0].rtc, [key]);
    assert_eq!(u.mp_unreach[0].safi, message::SAFI_RTC);
}

#[test]
fn withdraws_encode_as_legacy_or_mp_unreach() {
    let v4: IpNet = "192.0.2.0/24".parse().unwrap();
    let v6: IpNet = "2001:db8::/32".parse().unwrap();
    let u = expect_update(outbound_update_to_message(OutboundUpdate::Withdraw(
        v4,
        false,
        Some(3),
    )));
    assert_eq!(u.withdrawn_routes, ["192.0.2.0/24".parse().unwrap()]);
    assert_eq!(u.withdrawn_path_ids, [3]);
    assert!(u.attributes.is_none() && u.mp_unreach.is_empty());
    let u = expect_update(outbound_update_to_message(OutboundUpdate::Withdraw(
        v4, false, None,
    )));
    assert_eq!(u.withdrawn_path_ids.len(), 0);

    let u = expect_update(outbound_update_to_message(OutboundUpdate::Withdraw(
        v6,
        true,
        Some(8),
    )));
    assert_eq!(u.withdrawn_routes.len(), 0);
    let mp = &u.mp_unreach[0];
    assert_eq!((mp.afi, mp.safi), (AFI_IPV6, 1));
    assert_eq!(mp.withdrawn, [v6]);
    assert_eq!(mp.withdrawn_path_ids, [8]);
    let u = expect_update(outbound_update_to_message(OutboundUpdate::Withdraw(
        v4, true, None,
    )));
    assert_eq!(u.mp_unreach[0].afi, AFI_IPV4);
    assert_eq!(u.mp_unreach[0].withdrawn_path_ids.len(), 0);
}

#[test]
fn markers_and_evpn_encode_per_family() {
    assert_eq!(
        outbound_update_to_message(OutboundUpdate::EndOfRib(AddressFamily::Ipv6Unicast)),
        BgpMessage::EndOfRib { afi: 2, safi: 1 }
    );
    assert_eq!(
        outbound_update_to_message(OutboundUpdate::RefreshMarker {
            family: AddressFamily::L2vpnEvpn,
            subtype: message::REFRESH_BORR
        }),
        BgpMessage::RouteRefresh(RouteRefreshMessage {
            afi: message::AFI_L2VPN,
            subtype: message::REFRESH_BORR,
            safi: message::SAFI_EVPN
        })
    );

    let nlri = crate::evpn::EvpnNlri::InclusiveMulticast {
        rd: [0, 0, 0xfd, 0xe8, 0, 0, 0, 1],
        tag: 0,
        origin: "192.0.2.2".parse().unwrap(),
    };
    let u = expect_update(outbound_update_to_message(OutboundUpdate::AnnounceEvpn(
        crate::rib::AdvertisedEvpn {
            nlri: nlri.clone(),
            next_hop: ip("192.0.2.2"),
            as_path: vec![65001].into(),
            local_pref: None,
            communities: Vec::new(),
            extended_communities: vec![1],
            pmsi: None,
        },
    )));
    let mp = &u.mp_reach[0];
    assert_eq!((mp.afi, mp.safi), (message::AFI_L2VPN, message::SAFI_EVPN));
    assert_eq!(mp.evpn, std::slice::from_ref(&nlri));
    assert_eq!(u.attributes.unwrap().extended_communities, [1]);

    let u = expect_update(outbound_update_to_message(OutboundUpdate::WithdrawEvpn(
        nlri.clone(),
    )));
    assert_eq!(u.mp_unreach[0].evpn, [nlri]);
    assert!(u.attributes.is_none());
}

// ------------------------------------------------------ log_notification

#[derive(Clone, Default)]
struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Everything `f` logs at info and above, as one string.
fn captured(f: impl FnOnce()) -> String {
    let buf = Buf::default();
    let b = buf.clone();
    let sub = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || b.clone())
        .finish();
    tracing::subscriber::with_default(sub, f);
    let bytes = buf.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

fn notification(code: u8, subcode: u8, data: Bytes) -> NotificationMessage {
    NotificationMessage {
        error_code: code,
        error_subcode: subcode,
        data,
    }
}

#[test]
fn log_notification_decodes_shutdown_communications() {
    let cease = ErrorCode::Cease as u8;
    let text = message::encode_shutdown_message("planned maintenance");
    let plain = captured(|| {
        log_notification(ip(PEER), &notification(cease, 2, text.clone()));
    });
    assert!(plain.contains("planned maintenance"), "{plain}");

    // Invalid data (length byte disagrees) logs without the message.
    let bad = captured(|| {
        log_notification(
            ip(PEER),
            &notification(cease, 2, Bytes::from_static(&[9, b'x'])),
        );
    });
    assert!(bad.contains("received notification"), "{bad}");
    assert!(!bad.contains("planned"), "{bad}");

    // A non-Cease notification never gets its data read as a message.
    let other = captured(|| {
        log_notification(ip(PEER), &notification(3, 2, text.clone()));
    });
    assert!(!other.contains("planned maintenance"), "{other}");

    // RFC 8538: a Hard Reset logs the wrapped notification.
    let hard = captured(|| {
        log_notification(
            ip(PEER),
            &notification(
                cease,
                CeaseSubcode::HardReset as u8,
                message::encode_hard_reset(CeaseSubcode::AdministrativeShutdown as u8, &text),
            ),
        );
    });
    assert!(hard.contains("planned maintenance"), "{hard}");
    assert!(hard.contains("hard_reset_subcode=2"), "{hard}");

    // A Hard Reset too short to wrap anything is an ordinary notification.
    let short = captured(|| {
        log_notification(
            ip(PEER),
            &notification(cease, CeaseSubcode::HardReset as u8, Bytes::new()),
        );
    });
    assert!(!short.contains("hard_reset_code"), "{short}");
}

// -------------------------------------------- classify_inbound and friends

struct Cls {
    rib: Arc<SharedRib>,
    slot: Arc<PeerSlot>,
    peer: PeerContext,
    rx: Receiver<OutboundUpdate>,
    stale: RefreshState,
}

impl Cls {
    /// A rib with `PEER` registered as an eBGP neighbour.
    async fn new() -> Self {
        let rp = rpeer();
        let rib = new_rib();
        let (tx, rx) = crate::rib::test_channel();
        rib.lock().await.peer_established(
            rp.remote_address,
            false,
            Some(ip("10.0.0.1")),
            HashSet::from([AddressFamily::Ipv4Unicast]),
            true,
            None,
            false,
            false,
            HashSet::new(),
            rp.export_policy.clone(),
            tx,
        );
        Cls {
            rib,
            peer: pctx(&rp),
            slot: PeerSlot::new(rp),
            rx,
            stale: RefreshState::default(),
        }
    }

    async fn feed(&mut self, msg: BgpMessage, state: &State) -> Option<Event> {
        classify_inbound(
            msg,
            state,
            &self.peer,
            false,
            &self.rib,
            &self.slot,
            &mut self.stale,
        )
        .await
    }

    async fn held(&self) -> u32 {
        self.rib.lock().await.accepted_prefixes(ip(PEER))[0]
    }

    fn queued(&mut self) -> Vec<OutboundUpdate> {
        let mut v = vec![];
        while let Ok(u) = self.rx.try_recv() {
            v.push(u);
        }
        v
    }
}

#[tokio::test]
async fn inbound_messages_map_to_their_events() {
    let mut c = Cls::new().await;
    let est = State::Established(remote(true, true));
    assert!(matches!(
        c.feed(
            BgpMessage::Open(message::build_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)),
            &State::OpenSent
        )
        .await,
        Some(Event::OpenReceived(_))
    ));
    assert!(matches!(
        c.feed(BgpMessage::Keepalive, &est).await,
        Some(Event::KeepaliveReceived)
    ));
    assert!(matches!(
        c.feed(
            BgpMessage::Notification(notification(6, 2, Bytes::new())),
            &est
        )
        .await,
        Some(Event::NotificationReceived(_))
    ));
}

#[tokio::test]
async fn an_update_counts_only_once_established() {
    let mut c = Cls::new().await;
    let msg = || BgpMessage::Update(update(65002, &["192.0.2.0/24"]));
    assert!(matches!(
        c.feed(msg(), &State::OpenConfirm(remote(true, true))).await,
        Some(Event::UnexpectedUpdate)
    ));
    assert_eq!(c.held().await, 0, "not counted before Established");
    assert!(c
        .feed(msg(), &State::Established(remote(true, true)))
        .await
        .is_none());
    assert_eq!(c.held().await, 1);
}

#[tokio::test]
async fn crossing_the_maximum_prefix_queues_one_cease() {
    let mut c = Cls::new().await;
    c.rib.lock().await.set_peer_max_prefix(
        ip(PEER),
        BgpMaximumPrefix {
            ipv4: Some(BgpPrefixLimit {
                limit: 1,
                warning_only: false,
                restart_interval: 0,
            }),
            ..Default::default()
        },
    );
    let est = State::Established(remote(true, true));
    c.feed(
        BgpMessage::Update(update(65002, &["192.0.2.0/24", "198.51.100.0/24"])),
        &est,
    )
    .await;
    assert!(c.slot.max_prefix_held());
    let cmd = within("the cease", c.slot.recv_command()).await.unwrap();
    match cmd {
        FsmCommand::Cease { subcode, data } => {
            assert_eq!(subcode, CeaseSubcode::MaximumPrefixesReached);
            assert_eq!(data, message::encode_max_prefix_data(AFI_IPV4, 1, 1));
        }
        other => panic!("unexpected command {other:?}"),
    }
    // A second UPDATE read before the command arm ran queues nothing.
    c.feed(BgpMessage::Update(update(65002, &["203.0.113.0/24"])), &est)
        .await;
    let again = tokio::time::timeout(Duration::from_millis(100), c.slot.recv_command()).await;
    assert!(again.is_err(), "no second Cease");
}

#[tokio::test]
async fn end_of_rib_is_for_established_known_families_only() {
    let mut c = Cls::new().await;
    let est = State::Established(remote(true, true));
    // Before Established it is an FSM error (RFC 4271 §6.6).
    assert!(matches!(
        c.feed(
            BgpMessage::EndOfRib { afi: 1, safi: 1 },
            &State::OpenConfirm(remote(true, true))
        )
        .await,
        Some(Event::UnexpectedUpdate)
    ));
    for (state, afi, safi) in [(&est, 1, 1), (&est, 99, 99)] {
        assert!(c
            .feed(BgpMessage::EndOfRib { afi, safi }, state)
            .await
            .is_none());
    }
}

#[tokio::test]
async fn route_refresh_resends_the_loc_rib_once_established() {
    let mut c = Cls::new().await;
    // One learned route from another peer reaches our neighbour's outbox.
    c.rib.lock().await.handle_update(
        ip(OTHER),
        false,
        Ipv4Addr::new(9, 9, 9, 9),
        &update(65003, &["192.0.2.0/24"]),
        &c.peer.import_policy,
    );
    assert!(
        c.queued()
            .iter()
            .any(|u| matches!(u, OutboundUpdate::Announce(_))),
        "advertised on learning"
    );
    let request = || {
        BgpMessage::RouteRefresh(RouteRefreshMessage {
            afi: 1,
            subtype: message::REFRESH_REQUEST,
            safi: 1,
        })
    };

    // Not established, or an unknown family: nothing resent.
    c.feed(request(), &State::OpenConfirm(remote(true, true)))
        .await;
    c.feed(
        BgpMessage::RouteRefresh(RouteRefreshMessage {
            afi: 99,
            subtype: message::REFRESH_REQUEST,
            safi: 1,
        }),
        &State::Established(remote(true, true)),
    )
    .await;
    assert_eq!(c.queued().len(), 0);

    // Established without enhanced refresh: routes only.
    c.feed(request(), &State::Established(remote(false, true)))
        .await;
    let q = c.queued();
    assert!(
        matches!(q.as_slice(), [OutboundUpdate::Announce(_)]),
        "{q:?}"
    );

    // With enhanced refresh the resend is bracketed by BoRR/EoRR.
    c.feed(request(), &State::Established(remote(true, true)))
        .await;
    let q = c.queued();
    assert!(
        matches!(
            q.as_slice(),
            [
                OutboundUpdate::RefreshMarker {
                    subtype: message::REFRESH_BORR,
                    ..
                },
                OutboundUpdate::Announce(_),
                OutboundUpdate::RefreshMarker {
                    subtype: message::REFRESH_EORR,
                    ..
                },
            ]
        ),
        "{q:?}"
    );
}

#[tokio::test]
async fn enhanced_refresh_markers_arm_and_cancel_the_stale_timer() {
    let mut c = Cls::new().await;
    let marker = |subtype| {
        BgpMessage::RouteRefresh(RouteRefreshMessage {
            afi: 1,
            subtype,
            safi: 1,
        })
    };
    let v4 = AddressFamily::Ipv4Unicast;

    // Stale time 0: a BoRR never arms the timer.
    let est = State::Established(remote(true, true));
    c.feed(marker(message::REFRESH_BORR), &est).await;
    assert_eq!(c.stale.stale_until.len(), 0);

    c.peer.route_refresh_stale_time = Duration::from_secs(30);
    c.feed(marker(message::REFRESH_BORR), &est).await;
    assert!(c.stale.stale_until.contains_key(&v4));
    c.feed(marker(message::REFRESH_EORR), &est).await;
    assert!(c.stale.stale_until.is_empty(), "EoRR cancels it");

    // Without the negotiated capability markers mean nothing.
    c.feed(
        marker(message::REFRESH_BORR),
        &State::Established(remote(false, true)),
    )
    .await;
    assert_eq!(c.stale.stale_until.len(), 0);
    // Nor does an unknown subtype.
    c.feed(marker(200), &est).await;
    assert_eq!(c.stale.stale_until.len(), 0);
}

async fn script_pair() -> (
    FramedWrite<OwnedWriteHalf, BgpCodec>,
    FramedRead<OwnedReadHalf, BgpCodec>,
) {
    let (local, peer) = loopback_pair().await;
    let (_, w) = local.into_split();
    let (r, _w) = peer.into_split();
    // The peer's write half is dropped on purpose: only reads are checked.
    (
        FramedWrite::new(w, BgpCodec::default()),
        FramedRead::new(r, BgpCodec::default()),
    )
}

#[tokio::test]
async fn route_refresh_requests_follow_the_negotiated_capability() {
    let rp = rpeer();
    let peer = pctx(&rp);
    let (mut w, mut r) = script_pair().await;

    // Not established, then established without the capability: silent.
    send_route_refresh(&mut w, &State::OpenSent, &peer).await;
    let mut no_cap = remote(true, false);
    no_cap.negotiated_ipv6_unicast = false;
    send_route_refresh(&mut w, &State::Established(no_cap), &peer).await;
    let nothing = tokio::time::timeout(Duration::from_millis(150), r.next()).await;
    assert!(nothing.is_err(), "nothing was sent");

    // Both families negotiated: one request each.
    send_route_refresh(&mut w, &State::Established(remote(true, true)), &peer).await;
    for afi in [AFI_IPV4, AFI_IPV6] {
        let m = within("refresh", r.next()).await.unwrap().unwrap();
        assert_eq!(
            m,
            BgpMessage::RouteRefresh(RouteRefreshMessage {
                afi,
                subtype: message::REFRESH_REQUEST,
                safi: 1
            })
        );
    }
}

#[tokio::test]
async fn route_refresh_requests_cover_evpn_and_flowspec_when_negotiated() {
    let rp = rpeer();
    let peer = pctx(&rp);
    let (mut w, mut r) = script_pair().await;
    let mut rem = remote(true, true);
    rem.negotiated_ipv4_unicast = false;
    rem.negotiated_ipv6_unicast = false;
    rem.negotiated_evpn = true;
    rem.negotiated_flowspec = [true, true];
    send_route_refresh(&mut w, &State::Established(rem), &peer).await;
    for (afi, safi) in [
        (message::AFI_L2VPN, message::SAFI_EVPN),
        (AFI_IPV4, message::SAFI_FLOWSPEC),
        (AFI_IPV6, message::SAFI_FLOWSPEC),
    ] {
        let m = within("refresh", r.next()).await.unwrap().unwrap();
        assert_eq!(
            m,
            BgpMessage::RouteRefresh(RouteRefreshMessage {
                afi,
                subtype: message::REFRESH_REQUEST,
                safi
            })
        );
    }
}

#[tokio::test]
async fn collision_verdict_publishes_the_winner_and_rewrites_the_loser() {
    let rp = rpeer();
    let slot = PeerSlot::new(rp);
    let rem = RemoteInfo {
        bgp_id: Ipv4Addr::new(2, 2, 2, 2),
        ..remote(true, true)
    };

    // First OPEN on an idle slot proceeds and fills the status.
    assert!(slot.begin(Role::Active).await);
    let v = apply_collision_verdict(rem, Role::Active, &local(), &slot, Arc::default()).await;
    assert!(v.is_none());
    let s = *slot.status_receiver().borrow();
    assert_eq!(s.state, PeerState::OpenConfirm);
    assert_eq!(s.remote_asn, Some(65002));
    assert_eq!(s.remote_bgp_id, Some(Ipv4Addr::new(2, 2, 2, 2)));

    // The other role's connection is already Established: this one loses.
    slot.mark_established(Role::Active, false, Arc::default())
        .await;
    assert!(slot.begin(Role::Passive).await);
    let (next, actions) =
        apply_collision_verdict(rem, Role::Passive, &local(), &slot, Arc::default())
            .await
            .expect("lost");
    assert_eq!(next, None);
    assert_eq!(
        actions,
        [
            Action::SendNotification(
                ErrorCode::Cease as u8,
                CeaseSubcode::ConnectionCollisionResolution as u8
            ),
            Action::Close
        ]
    );
}

// -------------------------------------------------------- run over TCP

/// The remote end of a session, speaking `BgpCodec` by hand.
struct Script {
    r: FramedRead<OwnedReadHalf, BgpCodec>,
    w: FramedWrite<OwnedWriteHalf, BgpCodec>,
}

impl Script {
    async fn send(&mut self, m: BgpMessage) {
        self.w.send(m).await.unwrap();
    }

    async fn recv(&mut self) -> BgpMessage {
        within("a frame from the router", self.r.next())
            .await
            .expect("connection open")
            .expect("well-formed")
    }

    /// The next frame, or `None` on silence (`ms`) or a closed connection.
    async fn recv_within(&mut self, ms: u64) -> Option<BgpMessage> {
        tokio::time::timeout(Duration::from_millis(ms), self.r.next())
            .await
            .ok()
            .flatten()
            .and_then(Result::ok)
    }

    /// Skips KEEPALIVEs and UPDATEs until a NOTIFICATION arrives.
    async fn notification(&mut self) -> NotificationMessage {
        loop {
            if let BgpMessage::Notification(n) = self.recv().await {
                return n;
            }
        }
    }
}

struct Sess {
    peer: Script,
    slot: Arc<PeerSlot>,
    rib: Arc<SharedRib>,
    task: JoinHandle<FsmOutcome>,
    /// The OPEN the router sent.
    local_open: OpenMessage,
}

/// The peer's OPEN: MP v4 unicast, RR and ERR, plus `caps`.
fn peer_open(hold: u16, caps: Vec<Capability>) -> OpenMessage {
    let mut open = message::build_open(65002, Ipv4Addr::new(2, 2, 2, 2), hold);
    open.capabilities.extend([
        Capability::MultiProtocol { afi: 1, safi: 1 },
        Capability::RouteRefresh,
        Capability::EnhancedRouteRefresh,
    ]);
    open.capabilities.extend(caps);
    open
}

/// Starts `run` against a scripted peer. With `establish` the OPEN and
/// KEEPALIVE exchange is completed and waited for.
async fn start(rp: ResolvedPeer, open: OpenMessage, establish: bool) -> Sess {
    start_with(rp, open, establish, |_| {}).await
}

async fn start_with(
    rp: ResolvedPeer,
    open: OpenMessage,
    establish: bool,
    tweak: impl FnOnce(&mut PeerContext),
) -> Sess {
    let (local_stream, peer_stream) = loopback_pair().await;
    let mut ctx = pctx(&rp);
    tweak(&mut ctx);
    let slot = PeerSlot::new(rp);
    assert!(slot.begin(Role::Active).await);
    let rib = new_rib();
    let task = tokio::spawn(run(
        local_stream,
        Role::Active,
        local(),
        ctx,
        slot.clone(),
        rib.clone(),
    ));
    let (r, w) = peer_stream.into_split();
    let mut peer = Script {
        r: FramedRead::new(r, BgpCodec::default()),
        w: FramedWrite::new(w, BgpCodec::default()),
    };
    let local_open = match peer.recv().await {
        BgpMessage::Open(o) => o,
        other => panic!("expected the router's OPEN, got {other:?}"),
    };
    peer.send(BgpMessage::Open(open)).await;
    if establish {
        assert_eq!(peer.recv().await, BgpMessage::Keepalive);
        peer.send(BgpMessage::Keepalive).await;
        let mut status = slot.status_receiver();
        within("established", async {
            while status.borrow_and_update().state != PeerState::Established {
                status.changed().await.unwrap();
            }
        })
        .await;
    }
    Sess {
        peer,
        slot,
        rib,
        task,
        local_open,
    }
}

impl Sess {
    async fn outcome(self) -> FsmOutcome {
        within("the session to end", self.task).await.unwrap()
    }

    /// Learns `prefixes` from a third peer so they are advertised to ours.
    async fn learn(&self, prefixes: &[&str], local_pref_asn: u32) {
        self.rib.lock().await.handle_update(
            ip(OTHER),
            false,
            Ipv4Addr::new(9, 9, 9, 9),
            &update(local_pref_asn, prefixes),
            &Arc::new(nos_rpl::ACCEPT_ALL.clone()),
        );
    }
}

fn gr_cap() -> Capability {
    Capability::GracefulRestart(gr::our_cap(120, &[AddressFamily::Ipv4Unicast], false, true))
}

/// #965: the winner's `on_open` took this loser's record while its KEEPALIVE
/// was already in flight (`clear` stands in, without the `cease` permit that
/// `select!` would pick at random): the session must not register or
/// publish `Established`, and ends as a collision loser with a Cease.
#[tokio::test]
async fn a_loser_whose_record_is_gone_never_registers() {
    let mut s = start(rpeer(), peer_open(90, vec![]), false).await;
    assert_eq!(s.peer.recv().await, BgpMessage::Keepalive);
    let mut status = s.slot.status_receiver();
    within("open-confirm", async {
        while status.borrow_and_update().state != PeerState::OpenConfirm {
            status.changed().await.unwrap();
        }
    })
    .await;
    s.slot.clear(Role::Active).await;
    s.peer.send(BgpMessage::Keepalive).await;
    let n = s.peer.notification().await;
    assert_eq!(
        (n.error_code, n.error_subcode),
        (
            ErrorCode::Cease as u8,
            CeaseSubcode::ConnectionCollisionResolution as u8
        )
    );
    let slot = s.slot.clone();
    assert!(matches!(s.outcome().await, FsmOutcome::CollisionLost));
    assert_ne!(
        slot.status_receiver().borrow().state,
        PeerState::Established
    );
    assert!(!slot.is_established().await);
}

#[tokio::test]
async fn a_cease_command_goes_out_as_that_cease() {
    let mut s = start(rpeer(), peer_open(90, vec![]), true).await;
    s.slot.send_command(FsmCommand::Cease {
        subcode: CeaseSubcode::AdministrativeShutdown,
        data: message::encode_shutdown_message("bye"),
    });
    let n = s.peer.notification().await;
    assert_eq!(
        (n.error_code, n.error_subcode),
        (
            ErrorCode::Cease as u8,
            CeaseSubcode::AdministrativeShutdown as u8
        )
    );
    assert_eq!(
        message::decode_shutdown_message(&n.data).as_deref(),
        Some("bye")
    );
    assert!(matches!(
        s.outcome().await,
        FsmOutcome::NotificationSent {
            code: 6,
            subcode: 2
        }
    ));
}

#[tokio::test]
async fn bfd_down_is_a_hard_reset_only_with_n_and_the_flush_bit() {
    let cease = ErrorCode::Cease as u8;
    // (our GR on, peer GR cap, flush) -> expected wire subcode
    let cases = [
        (true, true, true, CeaseSubcode::HardReset as u8),
        (true, true, false, CeaseSubcode::BfdDown as u8),
        (true, false, true, CeaseSubcode::BfdDown as u8),
        (false, true, true, CeaseSubcode::BfdDown as u8),
    ];
    for (ours, theirs, flush, want) in cases {
        let mut rp = rpeer();
        rp.graceful_restart = ours.then_some(120);
        let caps = if theirs { vec![gr_cap()] } else { vec![] };
        let mut s = start(rp, peer_open(90, caps), true).await;
        s.slot.send_command(FsmCommand::BfdDown { flush });
        let n = s.peer.notification().await;
        assert_eq!(
            (n.error_code, n.error_subcode),
            (cease, want),
            "ours={ours} theirs={theirs} flush={flush}"
        );
        if want == CeaseSubcode::HardReset as u8 {
            assert_eq!(&n.data[..], &[cease, CeaseSubcode::BfdDown as u8]);
        }
        assert!(matches!(
            s.outcome().await,
            FsmOutcome::NotificationSent { .. }
        ));
    }
}

#[tokio::test]
async fn a_route_refresh_command_asks_the_peer_for_its_routes() {
    let mut s = start(rpeer(), peer_open(90, vec![]), true).await;
    s.slot.send_command(FsmCommand::SendRouteRefresh);
    assert_eq!(
        s.peer.recv().await,
        BgpMessage::RouteRefresh(RouteRefreshMessage {
            afi: 1,
            subtype: message::REFRESH_REQUEST,
            safi: 1
        })
    );
    s.task.abort();
}

#[tokio::test]
async fn an_ao_update_the_socket_refuses_resets_the_session() {
    // A loopback socket carries no TCP-AO state, so the in-place update
    // fails and the session falls back to Cease/Other Configuration Change.
    let mut s = start(rpeer(), peer_open(90, vec![]), true).await;
    s.slot
        .send_command(FsmCommand::UpdateAo(crate::session::AoDelta {
            add: vec![],
            remove: vec![],
            rnext_recv_id: 1,
        }));
    let n = s.peer.notification().await;
    assert_eq!(
        (n.error_code, n.error_subcode),
        (
            ErrorCode::Cease as u8,
            CeaseSubcode::OtherConfigurationChange as u8
        )
    );
    assert!(matches!(
        s.outcome().await,
        FsmOutcome::NotificationSent {
            code: 6,
            subcode: 6
        }
    ));
}

#[tokio::test]
async fn a_malformed_message_gets_a_notification_and_ends_the_session() {
    let mut s = start(rpeer(), peer_open(90, vec![]), true).await;
    // 19 bytes of a header whose marker is not all ones.
    let mut junk = vec![0u8; 19];
    junk[16..18].copy_from_slice(&19u16.to_be_bytes());
    junk[18] = 4;
    s.peer.w.get_mut().write_all(&junk).await.unwrap();
    let n = s.peer.notification().await;
    assert_eq!(
        (n.error_code, n.error_subcode),
        (
            ErrorCode::MessageHeader as u8,
            MessageHeaderSubcode::ConnectionNotSynchronized as u8
        )
    );
    assert!(matches!(
        s.outcome().await,
        FsmOutcome::NotificationSent {
            code: 1,
            subcode: 1
        }
    ));
}

#[tokio::test]
async fn a_closing_peer_ends_the_session_as_peer_closed() {
    let s = start(rpeer(), peer_open(90, vec![]), true).await;
    let Sess {
        peer, task, rib, ..
    } = s;
    drop(peer);
    assert!(matches!(
        within("end", task).await.unwrap(),
        FsmOutcome::PeerClosed | FsmOutcome::TcpError
    ));
    assert!(
        !rib.lock().await.has_peer(ip(PEER)),
        "the session deregistered itself"
    );
}

#[tokio::test]
async fn a_silent_peer_expires_the_hold_timer() {
    let mut rp = rpeer();
    rp.hold_time = 1;
    let mut s = start(rp, peer_open(90, vec![]), true).await;
    let n = s.peer.notification().await;
    assert_eq!(n.error_code, ErrorCode::HoldTimerExpired as u8);
    assert!(matches!(s.outcome().await, FsmOutcome::HoldTimerExpired));
}

#[tokio::test]
async fn a_notification_from_the_peer_ends_the_session() {
    for inner in [false, true] {
        let mut s = start(rpeer(), peer_open(90, vec![]), true).await;
        let text = message::encode_shutdown_message("going down");
        let n = if inner {
            notification(
                ErrorCode::Cease as u8,
                CeaseSubcode::HardReset as u8,
                message::encode_hard_reset(CeaseSubcode::AdministrativeShutdown as u8, &text),
            )
        } else {
            notification(
                ErrorCode::Cease as u8,
                CeaseSubcode::AdministrativeShutdown as u8,
                text,
            )
        };
        let (code, subcode) = (n.error_code, n.error_subcode);
        s.peer.send(BgpMessage::Notification(n)).await;
        match s.outcome().await {
            FsmOutcome::NotificationReceived {
                code: c,
                subcode: sc,
            } => {
                assert_eq!((c, sc), (code, subcode));
            }
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn the_open_advertises_and_negotiates_add_path_role_and_graceful_restart() {
    let mut rp = rpeer();
    rp.address_families = vec![AddressFamily::Ipv4Unicast, AddressFamily::Ipv6Unicast];
    rp.add_path = Some(BgpAddPath::Both);
    rp.role = Some(BgpRole::Customer);
    rp.graceful_restart = Some(90);
    let caps = vec![
        Capability::MultiProtocol { afi: 2, safi: 1 },
        Capability::ExtendedNextHop {
            nlri_afi: 2,
            nlri_safi: 1,
            nh_afi: 1,
        },
        Capability::AddPath(vec![
            message::AddPathTuple {
                afi: 1,
                safi: 1,
                send_receive: 3,
            },
            message::AddPathTuple {
                afi: 2,
                safi: 1,
                send_receive: 3,
            },
        ]),
        Capability::Role(BgpRole::Provider.wire()),
        gr_cap(),
    ];
    let s = start(rp, peer_open(90, caps), true).await;
    let has = |f: fn(&Capability) -> bool| s.local_open.capabilities.iter().any(f);
    assert!(has(|c| matches!(c, Capability::AddPath(t) if t.len() == 2)));
    assert!(has(
        |c| matches!(c, Capability::Role(r) if *r == BgpRole::Customer.wire())
    ));
    assert!(has(
        |c| matches!(c, Capability::GracefulRestart(g) if g.time == 90 && !g.restart)
    ));
    assert!(has(|c| matches!(
        c,
        Capability::ExtendedNextHop {
            nlri_afi: 2,
            nh_afi: 1,
            ..
        }
    )));
    let status = *s.slot.status_receiver().borrow();
    assert_eq!(status.state, PeerState::Established);
    s.task.abort();
}

#[tokio::test]
async fn a_role_mismatch_is_refused() {
    let mut rp = rpeer();
    rp.role = Some(BgpRole::Customer);
    // The peer announces Peer where Provider is the only counterpart.
    let mut s = start(
        rp,
        peer_open(90, vec![Capability::Role(BgpRole::Peer.wire())]),
        false,
    )
    .await;
    let n = s.peer.notification().await;
    assert_eq!(
        (n.error_code, n.error_subcode),
        (
            ErrorCode::OpenMessage as u8,
            OpenMessageSubcode::RoleMismatch as u8
        )
    );
    assert!(matches!(
        s.outcome().await,
        FsmOutcome::NotificationSent { .. }
    ));
}

#[tokio::test]
async fn an_open_while_the_peer_is_held_for_max_prefix_is_rejected() {
    let rp = rpeer();
    let (local_stream, peer_stream) = loopback_pair().await;
    let slot = PeerSlot::new(rp.clone());
    slot.trip_max_prefix(0);
    let task = tokio::spawn(run(
        local_stream,
        Role::Passive,
        local(),
        pctx(&rp),
        slot.clone(),
        new_rib(),
    ));
    let (r, w) = peer_stream.into_split();
    let mut peer = Script {
        r: FramedRead::new(r, BgpCodec::default()),
        w: FramedWrite::new(w, BgpCodec::default()),
    };
    peer.send(BgpMessage::Open(peer_open(90, vec![]))).await;
    let n = peer.notification().await;
    assert_eq!(
        (n.error_code, n.error_subcode),
        (
            ErrorCode::Cease as u8,
            CeaseSubcode::ConnectionRejected as u8
        )
    );
    assert!(matches!(
        within("end", task).await.unwrap(),
        FsmOutcome::NotificationSent {
            code: 6,
            subcode: 5
        }
    ));
}

#[tokio::test]
async fn a_peer_that_replaces_a_graceful_session_ends_it_as_replaced() {
    let mut rp = rpeer();
    rp.graceful_restart = Some(120);
    let s = start(rp, peer_open(90, vec![gr_cap()]), true).await;
    // A new connection of the same role arrives for a GR-capable session.
    let slot = s.slot.clone();
    let begin = tokio::spawn(async move { slot.begin(Role::Active).await });
    assert!(matches!(
        within("replaced", s.task).await.unwrap(),
        FsmOutcome::GrReplaced
    ));
    s.slot.clear(Role::Active).await;
    assert!(within("begin", begin).await.unwrap());
}

#[tokio::test]
async fn mrai_holds_a_changed_advertisement_until_its_deadline() {
    let mut rp = rpeer();
    rp.mrai = Duration::from_secs(1);
    let mut s = start(rp, peer_open(90, vec![]), true).await;

    s.learn(&["192.0.2.0/24"], 65003).await;
    let first = expect_update(s.peer.recv().await);
    assert_eq!(
        announced(&first),
        ["192.0.2.0/24".parse::<IpNet>().unwrap()]
    );
    let sent_at = std::time::Instant::now();

    // A changed advertisement of the same prefix waits out the interval.
    s.learn(&["192.0.2.0/24"], 65004).await;
    let second = expect_update(s.peer.recv().await);
    assert_eq!(
        announced(&second),
        ["192.0.2.0/24".parse::<IpNet>().unwrap()]
    );
    assert!(
        sent_at.elapsed() >= Duration::from_millis(900),
        "held for the MRAI, got {:?}",
        sent_at.elapsed()
    );
    s.task.abort();
}

#[tokio::test]
async fn held_advertisements_are_released_before_the_refresh_end_marker() {
    let mut rp = rpeer();
    rp.mrai = Duration::from_secs(60);
    let mut s = start(rp, peer_open(90, vec![]), true).await;
    s.learn(&["192.0.2.0/24"], 65003).await;
    expect_update(s.peer.recv().await);
    // Changed -> held for a minute.
    s.learn(&["192.0.2.0/24"], 65004).await;
    assert!(s.peer.recv_within(200).await.is_none(), "held");

    // The peer asks for a refresh: BoRR, the route (held again), EoRR. The
    // EoRR must flush what MRAI holds first.
    s.peer
        .send(BgpMessage::RouteRefresh(RouteRefreshMessage {
            afi: 1,
            subtype: message::REFRESH_REQUEST,
            safi: 1,
        }))
        .await;
    let mut kinds = vec![];
    for _ in 0..3 {
        kinds.push(match s.peer.recv().await {
            BgpMessage::RouteRefresh(r) => format!("refresh-{}", r.subtype),
            BgpMessage::Update(_) => "update".to_string(),
            other => format!("{other:?}"),
        });
    }
    assert_eq!(
        kinds.last().map(String::as_str),
        Some("refresh-2"),
        "{kinds:?}"
    );
    assert!(kinds.iter().any(|k| k == "update"), "{kinds:?}");
    s.task.abort();
}

#[tokio::test]
async fn a_legacy_session_sends_plain_nlri_and_withdraws() {
    // No Multiprotocol capability from the peer: plain IPv4 NLRI both ways.
    let mut legacy = message::build_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90);
    legacy.capabilities.push(Capability::RouteRefresh);
    let mut s = start(rpeer(), legacy, true).await;
    s.learn(&["192.0.2.0/24"], 65003).await;
    let a = expect_update(s.peer.recv().await);
    assert_eq!(a.nlri, ["192.0.2.0/24".parse().unwrap()]);
    // The route goes away: a legacy withdraw reaches the peer.
    s.rib.lock().await.handle_update(
        ip(OTHER),
        false,
        Ipv4Addr::new(9, 9, 9, 9),
        &UpdateMessage {
            withdrawn_routes: vec!["192.0.2.0/24".parse().unwrap()],
            withdrawn_path_ids: vec![],
            nlri: vec![],
            nlri_path_ids: vec![],
            attributes: None,
            mp_reach: vec![],
            mp_unreach: vec![],
            ..Default::default()
        },
        &Arc::new(nos_rpl::ACCEPT_ALL.clone()),
    );
    let w = expect_update(s.peer.recv().await);
    assert_eq!(w.withdrawn_routes, ["192.0.2.0/24".parse().unwrap()]);
    s.task.abort();
}

#[tokio::test]
async fn a_failing_socket_ends_the_session_as_a_tcp_error() {
    // The peer end is gone before the OPEN can be written.
    let (local_stream, peer_stream) = loopback_pair().await;
    drop(peer_stream);
    let rp = rpeer();
    let slot = PeerSlot::new(rp.clone());
    slot.begin(Role::Active).await;
    let outcome = within(
        "outcome",
        run(
            local_stream,
            Role::Active,
            local(),
            pctx(&rp),
            slot,
            new_rib(),
        ),
    )
    .await;
    assert!(
        matches!(outcome, FsmOutcome::TcpError | FsmOutcome::PeerClosed),
        "{outcome:?}"
    );
}
