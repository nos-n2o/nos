use std::time::Duration;

use proptest::prelude::*;

use super::*;
use crate::exchange::{due_retransmissions, on_lsack_received};
use crate::lsa::test_lsa::{H, L};

type Adj = AdjacencyData<L>;

fn rid(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, n)
}

fn lsa(seq: i32) -> Arc<L> {
    Arc::new(L(H {
        id: 7,
        seq,
        age: 0,
        checksum: 0,
    }))
}

const P2P: LinkFlood = LinkFlood {
    broadcast: false,
    we_are_dr: false,
    we_are_bdr: false,
};
const DR: LinkFlood = LinkFlood {
    broadcast: true,
    we_are_dr: true,
    we_are_bdr: false,
};
const BDR: LinkFlood = LinkFlood {
    broadcast: true,
    we_are_dr: false,
    we_are_bdr: true,
};
const OTHER: LinkFlood = LinkFlood {
    broadcast: true,
    we_are_dr: false,
    we_are_bdr: false,
};

#[allow(clippy::unnecessary_wraps)]
fn from(n: u8, dr: bool) -> Option<Receipt> {
    Some(Receipt {
        from: rid(n),
        from_dr_or_bdr: dr,
    })
}

type PeerSet = [(u8, NeighborState, Adj)];

fn flood(
    link: LinkFlood,
    rx: Option<Receipt>,
    set: &mut PeerSet,
    now: Instant,
) -> Option<FloodOut<L>> {
    let mut peers: Vec<Peer<'_, L>> = set
        .iter_mut()
        .map(|(n, state, adj)| Peer {
            id: rid(*n),
            state: *state,
            adj,
        })
        .collect();
    flood_on_link(&lsa(1), rx, link, &mut peers, now)
}

fn full(n: u8) -> (u8, NeighborState, Adj) {
    (n, NeighborState::Full, Adj::default())
}

#[test]
fn state_below_exchange_is_skipped() {
    let mut set = [(1, NeighborState::TwoWay, Adj::default()), full(2)];
    let out = flood(P2P, None, &mut set, Instant::now()).unwrap();
    assert_eq!(out.to, vec![rid(2)]);
    assert!(set[0].2.retransmission_list.is_empty());
    let mut set = [(1, NeighborState::ExStart, Adj::default())];
    assert!(
        flood(P2P, None, &mut set, Instant::now()).is_none(),
        "step 2"
    );
}

#[test]
fn request_is_dropped_in_exchange_and_loading_only() {
    let req = |s| {
        let a = Adj {
            request_list: vec![7, 8],
            ..Adj::default()
        };
        (1, s, a)
    };
    for s in [NeighborState::Exchange, NeighborState::Loading] {
        let mut set = [req(s)];
        flood(P2P, None, &mut set, Instant::now());
        assert_eq!(set[0].2.request_list, vec![8], "{s:?}");
        assert!(set[0].2.retransmission_list.contains_key(&7));
    }
    let mut set = [req(NeighborState::Full)];
    flood(P2P, None, &mut set, Instant::now());
    assert_eq!(set[0].2.request_list, vec![7, 8], "Full has no requests");
}

#[test]
fn sender_is_skipped_and_entry_is_stamped() {
    let now = Instant::now();
    let mut set = [full(1), full(2)];
    let out = flood(P2P, from(1, false), &mut set, now).unwrap();
    assert_eq!(out.to, vec![rid(2)]);
    assert!(set[0].2.retransmission_list.is_empty());
    assert_eq!(set[1].2.retransmission_list[&7].last_sent, now);
    let mut set = [full(1)];
    assert!(
        flood(P2P, from(1, false), &mut set, now).is_none(),
        "step 2"
    );
}

#[test]
fn steps_3_and_4_suppress_the_send_but_not_the_lists() {
    let now = Instant::now();
    // Step 3: received from the DR or BDR on a broadcast link.
    let mut set = [full(1), full(2)];
    assert!(flood(OTHER, from(1, true), &mut set, now).is_none());
    assert!(set[1].2.retransmission_list.contains_key(&7));
    // Step 4: we are the BDR and it was received here.
    let mut set = [full(1), full(2)];
    assert!(flood(BDR, from(1, false), &mut set, now).is_none());
    assert!(set[1].2.retransmission_list.contains_key(&7));
    // Not received here: the BDR floods.
    let mut set = [full(2)];
    assert!(flood(BDR, None, &mut set, now).is_some());
}

#[test]
fn destination_follows_link_type_and_role() {
    let now = Instant::now();
    for (link, dest) in [
        (P2P, Dest::Unicast),
        (DR, Dest::AllSpfRouters),
        (BDR, Dest::AllSpfRouters),
        (OTHER, Dest::AllDRouters),
    ] {
        let mut set = [full(2)];
        assert_eq!(flood(link, None, &mut set, now).unwrap().dest, dest);
    }
}

#[test]
fn merge_groups_by_dest_and_recipients() {
    let out = |dest, to: &[u8], seq| FloodOut {
        dest,
        to: to.iter().map(|n| rid(*n)).collect(),
        lsa: lsa(seq),
    };
    let merged = merge_floods(vec![
        out(Dest::Unicast, &[1], 1),
        out(Dest::AllDRouters, &[1], 2),
        out(Dest::Unicast, &[1], 3),
        out(Dest::Unicast, &[1, 2], 4),
    ]);
    assert_eq!(merged.len(), 3);
    assert_eq!(merged[0].0, Dest::Unicast);
    assert_eq!(merged[0].2.len(), 2);
    assert_eq!(merged[0].2[1].0.seq, 3);
    assert_eq!(merged[1].0, Dest::AllDRouters);
    assert_eq!(merged[2].1, vec![rid(1), rid(2)]);
    assert_eq!(merge_floods::<L>(Vec::new()), Vec::new());
}

#[test]
fn ack_action_is_table_19() {
    use AckAction::{Delayed, Direct, None as No};
    use RxVerdict::{DbNewer, Duplicate, DuplicateImplied, MaxAgeNoCopy, Newer, NewerFloodedBack};
    // (verdict, we_are_backup, from_dr) -> action
    let table = [
        (NewerFloodedBack, false, false, No),
        (NewerFloodedBack, true, true, No),
        (DbNewer, false, false, No),
        (DbNewer, true, true, No),
        (Newer, false, false, Delayed),
        (Newer, false, true, Delayed),
        (Newer, true, false, No),
        (Newer, true, true, Delayed),
        (DuplicateImplied, false, false, No),
        (DuplicateImplied, false, true, No),
        (DuplicateImplied, true, false, No),
        (DuplicateImplied, true, true, Delayed),
        (Duplicate, false, false, Direct),
        (Duplicate, true, true, Direct),
        (MaxAgeNoCopy, false, false, Direct),
        (MaxAgeNoCopy, true, true, Direct),
    ];
    for (v, backup, dr, want) in table {
        assert_eq!(ack_action(v, backup, dr), want, "{v:?} {backup} {dr}");
    }
}

#[test]
fn floods_back_truth_table() {
    for broadcast in [false, true] {
        for other in [false, true] {
            for dr in [false, true] {
                for bdr in [false, true] {
                    let link = LinkFlood {
                        broadcast,
                        we_are_dr: false,
                        we_are_bdr: bdr,
                    };
                    let rx = Receipt {
                        from: rid(1),
                        from_dr_or_bdr: dr,
                    };
                    assert_eq!(
                        floods_back(rx, link, other),
                        broadcast && other && !dr && !bdr
                    );
                }
            }
        }
    }
}

#[test]
fn due_retransmissions_waits_for_rxmt_then_stamps() {
    let t0 = Instant::now();
    let rxmt = Duration::from_secs(5);
    let mut set = [full(1)];
    flood(P2P, None, &mut set, t0);
    let adj = &mut set[0].2;
    assert_eq!(
        due_retransmissions(adj, t0 + Duration::from_secs(4), rxmt),
        Vec::new()
    );
    let at = t0 + rxmt;
    assert_eq!(due_retransmissions(adj, at, rxmt).len(), 1, "at rxmt");
    assert!(due_retransmissions(adj, at, rxmt).is_empty(), "stamped");
    assert_eq!(due_retransmissions(adj, at + rxmt, rxmt).len(), 1, "after");
}

#[test]
fn lsack_only_clears_the_same_instance() {
    let mut set = [full(1)];
    flood(P2P, None, &mut set, Instant::now());
    let adj = &mut set[0].2;
    on_lsack_received(adj, &[lsa(2).0]);
    assert_eq!(adj.retransmission_list.len(), 1, "other instance");
    on_lsack_received(adj, &[lsa(1).0]);
    assert!(adj.retransmission_list.is_empty());
}

fn state() -> impl Strategy<Value = NeighborState> {
    prop::sample::select(vec![
        NeighborState::Down,
        NeighborState::Init,
        NeighborState::TwoWay,
        NeighborState::ExStart,
        NeighborState::Exchange,
        NeighborState::Loading,
        NeighborState::Full,
    ])
}

proptest! {
    #[test]
    fn flood_never_adds_sender_or_low_state_and_some_iff_added(
        peers in prop::collection::vec((state(), any::<bool>()), 0..6),
        sender in 0u8..8,
        has_rx in any::<bool>(),
        from_dr in any::<bool>(),
        broadcast in any::<bool>(),
        bdr in any::<bool>(),
    ) {
        let mut set: Vec<_> = peers.iter().enumerate().map(|(i, (s, req))| {
            let a = Adj {
                request_list: if *req { vec![7] } else { Vec::new() },
                ..Adj::default()
            };
            (u8::try_from(i).unwrap(), *s, a)
        }).collect();
        let rx = has_rx.then(|| Receipt { from: rid(sender), from_dr_or_bdr: from_dr });
        let link = LinkFlood { broadcast, we_are_dr: false, we_are_bdr: bdr };
        let out = flood(link, rx, &mut set, Instant::now());
        let mut added = 0;
        for (n, s, a) in &set {
            if !a.retransmission_list.is_empty() {
                added += 1;
                prop_assert!(*s >= NeighborState::Exchange);
                prop_assert!(!has_rx || rid(*n) != rid(sender));
            }
        }
        let suppressed = broadcast && has_rx && (from_dr || bdr);
        prop_assert_eq!(out.is_some(), added > 0 && !suppressed);
        if let Some(o) = out { prop_assert_eq!(o.to.len(), added); }
    }

    #[test]
    fn flood_then_ack_empties_lists(n in 1u8..6, wrong in any::<bool>()) {
        let mut set: Vec<_> = (0..n).map(full).collect();
        flood(OTHER, None, &mut set, Instant::now());
        for (_, _, adj) in &mut set {
            if wrong {
                on_lsack_received(adj, &[lsa(9).0]);
                prop_assert_eq!(adj.retransmission_list.len(), 1);
            }
            on_lsack_received(adj, &[lsa(1).0]);
            prop_assert!(adj.retransmission_list.is_empty());
        }
    }

    #[test]
    fn due_returns_each_entry_once_per_window(gaps in prop::collection::vec(0u64..10, 1..20)) {
        let rxmt = Duration::from_secs(5);
        let t0 = Instant::now();
        let mut set = [full(1)];
        flood(P2P, None, &mut set, t0);
        let adj = &mut set[0].2;
        let (mut now, mut last) = (t0, t0);
        for g in gaps {
            now += Duration::from_secs(g);
            let got = due_retransmissions(adj, now, rxmt).len();
            prop_assert_eq!(got, usize::from(now - last >= rxmt));
            if got == 1 { last = now; }
        }
    }
}
