//! VPN Flowspec (SAFI 134) sent as per-VRF winners with Add-Path ids (#1127).

use super::flowspec_vpn::{feed, flow, flow_reach, unicast, vrf, RD2, RT2};
use super::vpn::{nlri, reach, RD1, RT};
use super::*;
use crate::vpn::VrfSet;

const SRC: &str = "10.0.0.1"; // eBGP source, AS 65001
const ADD: &str = "10.0.0.3"; // eBGP observer with Add-Path
const PLAIN: &str = "10.0.0.4"; // eBGP observer without

type Rx = mpsc::Receiver<OutboundUpdate>;

fn key() -> VpnFlowKey {
    (AddressFamily::Vpnv4Flowspec, (RD1, flow()))
}

fn reg(rib: &mut BgpRib, peer: &str, add_path: bool, count: Option<usize>) -> Rx {
    let (tx, rx) = test_channel();
    let afs = HashSet::from([
        AddressFamily::Ipv4Unicast,
        AddressFamily::Vpnv4Unicast,
        AddressFamily::Vpnv4Flowspec,
    ]);
    rib.set_peer_add_path_send_count(addr(peer), count);
    let ap = if add_path {
        HashSet::from([AddressFamily::Vpnv4Flowspec])
    } else {
        HashSet::new()
    };
    rib.peer_established(
        addr(peer),
        false,
        Some(addr("10.0.0.254")),
        afs,
        true,
        None,
        false,
        false,
        ap,
        accept_all_policy(),
        tx,
    );
    rx
}

/// `red` (RT) and `blue` (RT2) hold one copy each (ids 1, 2) of one rule.
fn setup(count: Option<usize>) -> (BgpRib, Rx, Rx) {
    let mut rib = new_rib_with_identity(65000, v4("1.1.1.1"), v4("1.1.1.1"));
    for (p, asn) in [(SRC, 65001), (ADD, 65003), (PLAIN, 65004)] {
        rib.set_peer_asn(addr(p), asn);
    }
    rib.set_vpn_vrfs(VrfSet(vec![
        vrf("red", vec![RT], None),
        vrf("blue", vec![RT2], None),
    ]));
    std::mem::forget(reg(&mut rib, SRC, false, None));
    let add = reg(&mut rib, ADD, true, count);
    let plain = reg(&mut rib, PLAIN, false, None);
    unicast(&mut rib, SRC, 65001, "10.10.0.0/24");
    let mut u = reach(SRC, vec![65001], vec![nlri(RD2, "10.10.0.0/24", 1)]);
    u.attributes.as_mut().unwrap().extended_communities = vec![RT2];
    feed(&mut rib, SRC, &u);
    for (id, rt) in [(1, RT), (2, RT2)] {
        feed(&mut rib, SRC, &copy_reach(id, rt));
    }
    (rib, add, plain)
}

fn copy_reach(id: u32, rt: u64) -> UpdateMessage {
    let mut u = flow_reach(65001, vec![rt], RD1, flow());
    u.mp_reach[0].nlri_path_ids = vec![id];
    u
}

fn sent(rx: &mut Rx) -> Vec<OutboundUpdate> {
    recv_all(rx)
        .into_iter()
        .filter(|u| {
            matches!(
                u,
                OutboundUpdate::AnnounceVpnFlowspec(..) | OutboundUpdate::WithdrawVpnFlowspec(..)
            )
        })
        .collect()
}

fn announced_ids(us: &[OutboundUpdate]) -> Vec<Option<u32>> {
    us.iter()
        .filter_map(|u| match u {
            OutboundUpdate::AnnounceVpnFlowspec(_, a) => Some(a.route.path_id),
            _ => None,
        })
        .collect()
}

#[test]
fn an_add_path_peer_gets_every_vrf_winner_under_its_own_id() {
    let (_rib, mut add, mut plain) = setup(None);
    let mut ids = announced_ids(&sent(&mut add));
    ids.sort();
    ids.dedup();
    assert_eq!(ids, [Some(1), Some(2)]);
    // No Add-Path: one copy at a time, no id.
    let p = announced_ids(&sent(&mut plain));
    assert!(!p.is_empty() && p.iter().all(Option::is_none));
}

#[test]
fn send_count_one_limits_the_copies() {
    let (_rib, mut add, _plain) = setup(Some(1));
    let mut ids = announced_ids(&sent(&mut add));
    ids.dedup();
    assert_eq!(ids, [Some(1)]);
}

#[test]
fn withdrawing_one_copy_withdraws_only_its_id() {
    let (mut rib, mut add, _plain) = setup(None);
    sent(&mut add);
    let mut w = empty_update();
    w.mp_unreach = vec![message::MpUnreachNlri {
        afi: 1,
        safi: message::SAFI_FLOWSPEC_VPN,
        withdrawn: vec![],
        withdrawn_path_ids: vec![1],
        evpn: vec![],
        flowspec: vec![],
        flowspec_vpn: vec![crate::flowspec::FlowSpecVpn {
            rd: RD1,
            flow: flow(),
        }],
        vpn: vec![],
        rtc: vec![],
    }];
    feed(&mut rib, SRC, &w);
    assert_eq!(
        sent(&mut add),
        [OutboundUpdate::WithdrawVpnFlowspec(key(), Some(1))]
    );
}

#[test]
fn a_refresh_replays_every_id() {
    let (rib, mut add, _plain) = setup(None);
    sent(&mut add);
    rib.resend_vpn_flow(addr(ADD), AddressFamily::Vpnv4Flowspec);
    let mut ids = announced_ids(&sent(&mut add));
    ids.sort();
    assert_eq!(ids, [Some(1), Some(2)]);
}
