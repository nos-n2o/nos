//! Moved from `ospf::exchange`'s tests onto `lsa::test_lsa`, through a
//! positional shim with the old signature so each case reads as before.

use super::*;
use crate::lsa::test_lsa::{H, L};

type DbdPacket = Dbd<H, ()>;
type AdjacencyData = super::AdjacencyData<L>;
type Action = super::Action<L>;

/// Any non-zero value: proves the shared code stamps `Params::dbd_options`.
const DBD_OPTIONS: u32 = 0x42;

fn router_id(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn header(link_state_id: &str, seq: i32) -> H {
    H {
        id: u32::from(router_id(link_state_id)),
        seq,
        age: 0,
        checksum: 0,
    }
}

fn negotiation_dbd(router_id: Ipv4Addr, seq: u32) -> DbdPacket {
    DbdPacket {
        lls: None,
        router_id,
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: true,
        more: true,
        master: true,
        dd_sequence_number: seq,
        lsa_headers: Vec::new(),
    }
}

/// The pre-#430 positional signature; every header is in scope and none is
/// opaque.
#[allow(clippy::too_many_arguments)]
fn on_dbd_received(
    adj: &mut AdjacencyData,
    state: NeighborState,
    local_router_id: Ipv4Addr,
    neighbor_router_id: Ipv4Addr,
    dbd: &DbdPacket,
    local_lsdb_headers: &[H],
    max_headers: usize,
    mtu: u16,
) -> Vec<Action> {
    assert_eq!(neighbor_router_id, dbd.router_id);
    let p = Params {
        local_router_id,
        max_headers,
        mtu,
        dbd_options: DBD_OPTIONS,
        peer_opaque_capable: false,
    };
    super::on_dbd_received(adj, state, &p, dbd, local_lsdb_headers, |_| true, |_| false)
}

#[test]
fn mtu_derived_budget() {
    assert_eq!(mtu_based_max_headers(1500, 20 + 24 + 8), 72);
    assert_eq!(mtu_based_max_headers(1500, 40 + 16 + 12), 71);
    assert_eq!(mtu_based_max_headers(68, 40 + 16 + 12), 1);
    assert_eq!(mtu_based_max_headers(0, 52), 1);
}

#[test]
fn mtu_acceptable_only_rejects_a_larger_neighbor_mtu() {
    assert!(mtu_acceptable(1500, 1500, false));
    assert!(mtu_acceptable(1400, 1500, false));
    assert!(mtu_acceptable(0, 1500, false));
    assert!(!mtu_acceptable(1500, 1400, false));
    assert!(mtu_acceptable(1500, 1400, true));
}

#[test]
fn higher_neighbor_router_id_makes_us_slave() {
    let mut adj = AdjacencyData {
        dd_sequence_number: 99,
        ..Default::default()
    };
    let dbd = negotiation_dbd(router_id("9.9.9.10"), 42);
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::ExStart,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &dbd,
        &[],
        100,
        1500,
    );
    assert!(!adj.is_master);
    assert_eq!(adj.dd_sequence_number, 42);
    assert!(matches!(
        actions.as_slice(),
        [Action::SendDbd(reply), Action::NeighborEvent(Event::NegotiationDone)]
            if !reply.master && reply.dd_sequence_number == 42
    ));
}

#[test]
fn slave_accepts_masters_reply_as_exstart_trigger() {
    // Regression test (found via a real three-router Docker scenario,
    // `ospf-dr`, not a unit test): symmetric to
    // `master_accepts_neighbors_reply_as_exstart_trigger` below, but for
    // the *slave* side. If the master reaches ExStart (and sends its
    // attempt) before we ourselves reach 2-Way with it, `handle_dbd` has
    // no adjacency yet to receive that attempt into and drops it — and
    // every retransmitted copy, since the master, once it processes our
    // own (later) attempt, only ever resends its reply to that. Without
    // this, the slave waits here forever for a message that will never
    // come again.
    let mut adj = AdjacencyData::default();
    let master_lsa = header("1.1.1.1", 0x8000_0001u32.cast_signed());
    let poll = DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.10"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more: false,
        master: true,
        dd_sequence_number: 42,
        lsa_headers: vec![master_lsa],
    };
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::ExStart,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &poll,
        &[],
        100,
        1500,
    );
    assert!(!adj.is_master);
    assert_eq!(adj.dd_sequence_number, 42);
    assert_eq!(adj.request_list, vec![master_lsa.key()]);
    // The master's poll already says `more: false`, and our own reply
    // carries no data of its own (empty local LSDB) — both sides are
    // done in this same round, so `ExchangeDone` fires alongside it.
    assert_eq!(
        actions,
        vec![
            Action::SendDbd(DbdPacket {
                lls: None,
                router_id: router_id("9.9.9.9"),
                area_id: Ipv4Addr::UNSPECIFIED,
                interface_mtu: 1500,
                options: DBD_OPTIONS,
                init: false,
                more: false,
                master: false,
                dd_sequence_number: 42,
                lsa_headers: Vec::new(),
            }),
            Action::NeighborEvent(Event::NegotiationDone),
            Action::NeighborEvent(Event::ExchangeDone { more_to_load: true }),
        ]
    );
}

#[test]
fn lower_neighbor_router_id_makes_us_master() {
    let mut adj = AdjacencyData {
        dd_sequence_number: 7,
        ..Default::default()
    };
    let dbd = negotiation_dbd(router_id("9.9.9.5"), 1);
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::ExStart,
        router_id("9.9.9.9"),
        router_id("9.9.9.5"),
        &dbd,
        &[],
        100,
        1500,
    );
    assert!(adj.is_master);
    assert_eq!(adj.dd_sequence_number, 7);
    // A bare negotiation attempt carries no content from either side —
    // real content-sending only begins once the slave's actual reply
    // arrives (RFC 2328 §10.8), so this fires only `NegotiationDone`,
    // no `SendDbd`. Our already-sent negotiation attempt keeps being
    // retransmitted as-is until then.
    assert_eq!(actions, vec![Action::NeighborEvent(Event::NegotiationDone)]);
}

#[test]
fn master_accepts_neighbors_reply_as_exstart_trigger() {
    // Regression test: the two sides' Hello-driven ExStart entry isn't
    // synchronized, so the master may receive the (lower-id)
    // neighbor's reply (MS=0) before/instead of ever seeing its
    // negotiation attempt — e.g. because that attempt was sent before
    // this side even reached ExStart. A reply alone must still be
    // accepted as proof the neighbor deferred to us as master, or this
    // side gets stuck in ExStart forever (the neighbor, already past
    // ExStart itself, never resends the original attempt). Since that
    // reply is also the *only* copy of the neighbor's summary we'll
    // ever see (it won't send another once it's moved on), its
    // content must be processed immediately too — not just used to
    // learn our role — or *this* side gets stuck instead, waiting on
    // a second message that never comes.
    let mut adj = AdjacencyData {
        dd_sequence_number: 7,
        ..Default::default()
    };
    let neighbor_lsa = header("1.1.1.1", 0x8000_0001u32.cast_signed());
    let reply = DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.5"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more: false,
        master: false,
        dd_sequence_number: 999, // the neighbor's own, irrelevant to us
        lsa_headers: vec![neighbor_lsa],
    };
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::ExStart,
        router_id("9.9.9.9"),
        router_id("9.9.9.5"),
        &reply,
        &[],
        100,
        1500,
    );
    assert!(adj.is_master);
    assert_eq!(adj.dd_sequence_number, 7, "must keep our own chosen seed");
    assert_eq!(adj.request_list, vec![neighbor_lsa.key()]);
    // The neighbor's reply already says `more: false`, and our own
    // local LSDB is empty (nothing to poll back with) — both sides are
    // done immediately, with no `SendDbd` at all (we have nothing of
    // our own to send).
    assert_eq!(
        actions,
        vec![
            Action::NeighborEvent(Event::NegotiationDone),
            Action::NeighborEvent(Event::ExchangeDone { more_to_load: true }),
        ]
    );
}

#[test]
fn slave_ignores_a_reply_shaped_packet_in_exstart() {
    // A lower-id neighbor sending MS=0 to us would be nonsensical (we'd
    // be slave, so it can't also think it's slave) — ignored rather
    // than acted on.
    let mut adj = AdjacencyData::default();
    let reply = DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.10"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more: false,
        master: false,
        dd_sequence_number: 1,
        lsa_headers: Vec::new(),
    };
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::ExStart,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &reply,
        &[],
        100,
        1500,
    );
    assert_eq!(actions, []);
}

#[test]
fn non_negotiation_dbd_in_exstart_is_ignored() {
    let mut adj = AdjacencyData::default();
    let mut dbd = negotiation_dbd(router_id("9.9.9.10"), 42);
    dbd.more = false;
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::ExStart,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &dbd,
        &[],
        100,
        1500,
    );
    assert_eq!(actions, []);
}

#[test]
fn exchange_as_master_with_empty_summaries_reaches_exchange_done() {
    let mut adj = AdjacencyData {
        is_master: true,
        dd_sequence_number: 5,
        ..Default::default()
    };
    let dbd = DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.10"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more: false,
        master: false,
        dd_sequence_number: 5,
        lsa_headers: Vec::new(),
    };
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &dbd,
        &[],
        100,
        1500,
    );
    assert_eq!(
        actions,
        vec![Action::NeighborEvent(Event::ExchangeDone {
            more_to_load: false
        })]
    );
    assert_eq!(adj.request_list, []);
}

#[test]
fn exchange_as_slave_with_master_poll_reaches_exchange_done() {
    // `adj.dd_sequence_number == 5` models round 5 already having
    // happened via `on_dbd_in_exstart` (which now always sends the
    // slave's own first chunk immediately) — this poll is round 6, the
    // master's next (and, since both sides carry no more data, final)
    // poll.
    let mut adj = AdjacencyData {
        is_master: false,
        dd_sequence_number: 5,
        ..Default::default()
    };
    let dbd = DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.5"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more: false,
        master: true,
        dd_sequence_number: 6,
        lsa_headers: Vec::new(),
    };
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.5"),
        &dbd,
        &[],
        100,
        1500,
    );
    assert_eq!(adj.dd_sequence_number, 6);
    // The slave must still send its own (empty) reply at the new
    // sequence number alongside declaring the exchange done — the
    // master needs to see it to know the slave has nothing left too.
    assert_eq!(
        actions,
        vec![
            Action::SendDbd(DbdPacket {
                lls: None,
                router_id: router_id("9.9.9.9"),
                area_id: Ipv4Addr::UNSPECIFIED,
                interface_mtu: 1500,
                options: DBD_OPTIONS,
                init: false,
                more: false,
                master: false,
                dd_sequence_number: 6,
                lsa_headers: Vec::new(),
            }),
            Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: false
            }),
        ]
    );
}

#[test]
fn exchange_requests_lsas_missing_locally() {
    let mut adj = AdjacencyData {
        is_master: true,
        dd_sequence_number: 5,
        ..Default::default()
    };
    let neighbor_header = header("1.1.1.1", 0x8000_0001u32.cast_signed());
    let dbd = DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.10"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more: false,
        master: false,
        dd_sequence_number: 5,
        lsa_headers: vec![neighbor_header],
    };
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &dbd,
        &[],
        100,
        1500,
    );
    assert_eq!(adj.request_list, vec![neighbor_header.key()]);
    assert_eq!(
        actions,
        vec![Action::NeighborEvent(Event::ExchangeDone {
            more_to_load: true
        })]
    );
}

#[test]
fn exchange_does_not_request_lsas_already_current_locally() {
    let mut adj = AdjacencyData {
        is_master: true,
        dd_sequence_number: 5,
        ..Default::default()
    };
    let local = header("1.1.1.1", 0x8000_0002u32.cast_signed());
    let neighbor_header = header("1.1.1.1", 0x8000_0001u32.cast_signed());
    let dbd = DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.10"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more: false,
        master: false,
        dd_sequence_number: 5,
        lsa_headers: vec![neighbor_header],
    };
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &dbd,
        &[local],
        100,
        1500,
    );
    assert_eq!(adj.request_list, []);
    assert_eq!(
        actions,
        vec![Action::NeighborEvent(Event::ExchangeDone {
            more_to_load: false
        })]
    );
}

#[test]
fn master_paginates_own_summary_across_multiple_rounds() {
    // Models round 5 (`on_dbd_in_exstart`) already having sent the
    // first chunk (`h0`, not itself constructed here), leaving two more
    // headers to drain one at a time (`max_headers: 1`).
    let h1 = header("2.2.2.2", 1);
    let h2 = header("3.3.3.3", 1);
    let mut adj = AdjacencyData {
        is_master: true,
        dd_sequence_number: 5,
        summary_remaining: VecDeque::from(vec![h1, h2]),
        ..Default::default()
    };
    let empty_slave_reply = |seq: u32| DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.10"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more: false,
        master: false,
        dd_sequence_number: seq,
        lsa_headers: Vec::new(),
    };

    // Round 5's reply: master still has h1/h2 left, so it must poll
    // again rather than declare done.
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &empty_slave_reply(5),
        &[],
        1,
        1500,
    );
    assert_eq!(adj.dd_sequence_number, 6);
    assert_eq!(adj.summary_remaining, VecDeque::from(vec![h2]));
    assert_eq!(
        actions,
        vec![Action::SendDbd(DbdPacket {
            lls: None,
            router_id: router_id("9.9.9.9"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 1500,
            options: DBD_OPTIONS,
            init: false,
            more: true,
            master: true,
            dd_sequence_number: 6,
            lsa_headers: vec![h1],
        })]
    );

    // Round 6's reply: one header (h2) left, still not done.
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &empty_slave_reply(6),
        &[],
        1,
        1500,
    );
    assert_eq!(adj.dd_sequence_number, 7);
    assert!(adj.summary_remaining.is_empty());
    assert_eq!(
        actions,
        vec![Action::SendDbd(DbdPacket {
            lls: None,
            router_id: router_id("9.9.9.9"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 1500,
            options: DBD_OPTIONS,
            init: false,
            more: false,
            master: true,
            dd_sequence_number: 7,
            lsa_headers: vec![h2],
        })]
    );

    // Round 7's reply: both sides now empty -- done.
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &empty_slave_reply(7),
        &[],
        1,
        1500,
    );
    assert_eq!(
        actions,
        vec![Action::NeighborEvent(Event::ExchangeDone {
            more_to_load: false
        })]
    );
}

#[test]
fn slave_paginates_own_summary_across_multiple_rounds() {
    // Symmetric to `master_paginates_own_summary_across_multiple_rounds`,
    // for the slave side: round 5 already sent the first chunk, two
    // more headers remain, drained one at a time.
    let h1 = header("2.2.2.2", 1);
    let h2 = header("3.3.3.3", 1);
    let mut adj = AdjacencyData {
        is_master: false,
        dd_sequence_number: 5,
        summary_remaining: VecDeque::from(vec![h1, h2]),
        ..Default::default()
    };
    let master_poll = |seq: u32, more: bool| DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.5"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more,
        master: true,
        dd_sequence_number: seq,
        lsa_headers: Vec::new(),
    };

    // Master's next poll (round 6) -- master has nothing else, but the
    // slave still has h1/h2 to send.
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.5"),
        &master_poll(6, false),
        &[],
        1,
        1500,
    );
    assert_eq!(adj.dd_sequence_number, 6);
    assert_eq!(adj.summary_remaining, VecDeque::from(vec![h2]));
    assert_eq!(
        actions,
        vec![Action::SendDbd(DbdPacket {
            lls: None,
            router_id: router_id("9.9.9.9"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 1500,
            options: DBD_OPTIONS,
            init: false,
            more: true,
            master: false,
            dd_sequence_number: 6,
            lsa_headers: vec![h1],
        })]
    );

    // Round 7: slave's last header, both sides now declare done in the
    // same round.
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.5"),
        &master_poll(7, false),
        &[],
        1,
        1500,
    );
    assert_eq!(adj.dd_sequence_number, 7);
    assert!(adj.summary_remaining.is_empty());
    assert_eq!(
        actions,
        vec![
            Action::SendDbd(DbdPacket {
                lls: None,
                router_id: router_id("9.9.9.9"),
                area_id: Ipv4Addr::UNSPECIFIED,
                interface_mtu: 1500,
                options: DBD_OPTIONS,
                init: false,
                more: false,
                master: false,
                dd_sequence_number: 7,
                lsa_headers: vec![h2],
            }),
            Action::NeighborEvent(Event::ExchangeDone {
                more_to_load: false
            }),
        ]
    );
}

#[test]
fn master_keeps_polling_with_empty_chunk_while_slave_still_has_data() {
    // Master's own summary is already fully sent (`summary_remaining`
    // empty), but the slave's `more` bit is still set -- master must
    // keep polling (with an empty chunk of its own) purely to let the
    // slave send what it has left, and `request_list` must accumulate
    // across both rounds rather than losing round 5's entry.
    let h_a = header("4.4.4.4", 1);
    let h_b = header("5.5.5.5", 1);
    let mut adj = AdjacencyData {
        is_master: true,
        dd_sequence_number: 5,
        ..Default::default()
    };
    let slave_reply = |seq: u32, more: bool, header: H| DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.10"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more,
        master: false,
        dd_sequence_number: seq,
        lsa_headers: vec![header],
    };

    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &slave_reply(5, true, h_a),
        &[],
        100,
        1500,
    );
    assert_eq!(adj.request_list, vec![h_a.key()]);
    assert_eq!(
        actions,
        vec![Action::SendDbd(DbdPacket {
            lls: None,
            router_id: router_id("9.9.9.9"),
            area_id: Ipv4Addr::UNSPECIFIED,
            interface_mtu: 1500,
            options: DBD_OPTIONS,
            init: false,
            more: false,
            master: true,
            dd_sequence_number: 6,
            lsa_headers: Vec::new(),
        })]
    );

    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &slave_reply(6, false, h_b),
        &[],
        100,
        1500,
    );
    assert_eq!(
        adj.request_list,
        vec![h_a.key(), h_b.key()],
        "request_list must accumulate across rounds, not overwrite"
    );
    assert_eq!(
        actions,
        vec![Action::NeighborEvent(Event::ExchangeDone {
            more_to_load: true
        })]
    );
}

#[test]
fn exchange_mismatch_as_master_triggers_seq_number_mismatch() {
    let mut adj = AdjacencyData {
        is_master: true,
        dd_sequence_number: 5,
        ..Default::default()
    };
    let dbd = DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.10"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more: false,
        master: false,
        dd_sequence_number: 6, // wrong sequence number
        lsa_headers: Vec::new(),
    };
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &dbd,
        &[],
        100,
        1500,
    );
    assert_eq!(
        actions,
        vec![Action::NeighborEvent(Event::SeqNumberMismatch)]
    );
}

#[test]
fn exchange_mismatch_as_slave_triggers_seq_number_mismatch() {
    // The slave expects the master's next poll to be exactly one past
    // the last sequence number it accepted -- a repeated or skipped
    // value is a mismatch, not just an equal one (equal was the
    // pre-pagination check; every subsequent round now legitimately
    // increments).
    let mut adj = AdjacencyData {
        is_master: false,
        dd_sequence_number: 5,
        ..Default::default()
    };
    let dbd = DbdPacket {
        lls: None,
        router_id: router_id("9.9.9.5"),
        area_id: Ipv4Addr::UNSPECIFIED,
        interface_mtu: 0,
        options: DBD_OPTIONS,
        init: false,
        more: false,
        master: true,
        dd_sequence_number: 5, // stale, not 6
        lsa_headers: Vec::new(),
    };
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.5"),
        &dbd,
        &[],
        100,
        1500,
    );
    assert_eq!(
        actions,
        vec![Action::NeighborEvent(Event::SeqNumberMismatch)]
    );
}

#[test]
fn exchange_ignores_negotiation_shaped_duplicate_as_master() {
    // The slave's own retransmitted original negotiation packet,
    // arriving after we've already moved past ExStart — a real, common
    // race (the two sides' retransmit timers run independently), not a
    // restart signal.
    let mut adj = AdjacencyData {
        is_master: true,
        dd_sequence_number: 5,
        ..Default::default()
    };
    let dbd = negotiation_dbd(router_id("9.9.9.10"), 999);
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &dbd,
        &[],
        100,
        1500,
    );
    assert_eq!(actions, []);
    assert_eq!(adj.dd_sequence_number, 5, "must not adopt the stray seq");
}

#[test]
fn exchange_ignores_negotiation_shaped_duplicate_as_slave() {
    let mut adj = AdjacencyData {
        is_master: false,
        dd_sequence_number: 5,
        ..Default::default()
    };
    let dbd = negotiation_dbd(router_id("9.9.9.10"), 999);
    let actions = on_dbd_received(
        &mut adj,
        NeighborState::Exchange,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        &dbd,
        &[],
        100,
        1500,
    );
    assert_eq!(actions, []);
    assert_eq!(adj.dd_sequence_number, 5, "must not adopt the stray seq");
}

/// Feeds `dbd` to `adj` in `state` (local 9.9.9.9, neighbor 9.9.9.10).
fn dbd_in(adj: &mut AdjacencyData, state: NeighborState, dbd: &DbdPacket) -> Vec<Action> {
    on_dbd_received(
        adj,
        state,
        router_id("9.9.9.9"),
        router_id("9.9.9.10"),
        dbd,
        &[],
        100,
        1500,
    )
}

#[test]
fn init_dbd_while_full_is_seq_number_mismatch() {
    // RFC 2328 §10.6: the peer restarted negotiation on its own side
    // (its Hellos may still list us), so we must restart too (#146).
    for state in [NeighborState::Loading, NeighborState::Full] {
        let mut adj = AdjacencyData::default();
        let dbd = negotiation_dbd(router_id("9.9.9.10"), 1);
        assert_eq!(
            dbd_in(&mut adj, state, &dbd),
            vec![Action::NeighborEvent(Event::SeqNumberMismatch)],
            "{state:?}"
        );
    }
}

#[test]
fn stray_non_init_dbd_while_full_is_ignored() {
    for state in [NeighborState::Loading, NeighborState::Full] {
        let mut adj = AdjacencyData::default();
        let mut dbd = negotiation_dbd(router_id("9.9.9.10"), 1);
        dbd.init = false;
        assert!(dbd_in(&mut adj, state, &dbd).is_empty(), "{state:?}");
    }
}

/// A slave adjacency that already sent its final reply at seq 42, and
/// the master's poll at that seq (its duplicate once we are `Full`).
fn slave_after_final_reply() -> (AdjacencyData, DbdPacket, DbdPacket) {
    let mut reply = negotiation_dbd(router_id("9.9.9.9"), 42);
    reply.init = false;
    reply.more = false;
    reply.master = false;
    let adj = AdjacencyData {
        is_master: false,
        dd_sequence_number: 42,
        last_dbd_sent: Some(reply.clone()),
        ..Default::default()
    };
    let mut poll = negotiation_dbd(router_id("9.9.9.10"), 42);
    poll.init = false;
    poll.more = false;
    (adj, reply, poll)
}

#[test]
fn slave_resends_last_dbd_for_masters_duplicate_in_full() {
    for state in [NeighborState::Loading, NeighborState::Full] {
        let (mut adj, reply, poll) = slave_after_final_reply();
        assert_eq!(
            dbd_in(&mut adj, state, &poll),
            vec![Action::SendDbd(reply)],
            "{state:?}"
        );
    }
}

#[test]
fn slave_ignores_other_master_dbds_in_full() {
    // A different sequence number is no duplicate of our last reply.
    let (mut adj, _, mut poll) = slave_after_final_reply();
    poll.dd_sequence_number = 43;
    assert_eq!(dbd_in(&mut adj, NeighborState::Full, &poll), []);
    // Nothing kept to resend.
    let (mut adj, _, poll) = slave_after_final_reply();
    adj.last_dbd_sent = None;
    assert_eq!(dbd_in(&mut adj, NeighborState::Full, &poll), []);
}

#[test]
fn master_discards_duplicate_in_full() {
    let (mut adj, _, mut dup) = slave_after_final_reply();
    adj.is_master = true;
    dup.master = false;
    assert_eq!(dbd_in(&mut adj, NeighborState::Full, &dup), []);
    dup.master = true;
    assert_eq!(dbd_in(&mut adj, NeighborState::Full, &dup), []);
}

// LSR/LSU/LSAck, moved from both daemons' `exchange` tests. Each daemon
// keeps only the tests of its own closures.

fn lsa_id(id: u32, seq: i32) -> L {
    L(H {
        id,
        seq,
        age: 0,
        checksum: 0,
    })
}

const SEQ1: i32 = 0x8000_0001u32.cast_signed();

/// Runs one LSU into `area`/`link`/`as_scope`: scope by id (100s are
/// link-local, 200s AS, anything else area), ids 900+ discarded, id 500
/// exempt from the `MaxAge` discard.
fn lsu_at(
    adj: &mut AdjacencyData,
    area: &mut Lsdb<L>,
    link: &mut Lsdb<L>,
    as_scope: Option<&mut Lsdb<L>>,
    lsas: &[L],
    now: Instant,
) -> (Vec<Action>, Vec<H>) {
    let mut stores = Stores {
        area,
        link_local: link,
        as_scope,
    };
    on_lsu_received(
        adj,
        &mut stores,
        lsas,
        now,
        |h| match h.id / 100 {
            1 => Scope::LinkLocal,
            2 => Scope::As,
            _ => Scope::Area,
        },
        |h| h.id >= 900,
        |h| h.id == 500,
    )
}

fn lsu(adj: &mut AdjacencyData, area: &mut Lsdb<L>, lsas: &[L]) -> (Vec<Action>, Vec<H>) {
    lsu_at(adj, area, &mut Lsdb::new(), None, lsas, Instant::now())
}

#[test]
fn lsr_for_held_lsas_sends_one_lsu_from_whichever_store_holds_each() {
    let mut adj = AdjacencyData::default();
    let (mut area, mut link) = (Lsdb::new(), Lsdb::new());
    area.install(lsa_id(1, SEQ1));
    link.install(lsa_id(101, SEQ1));
    let actions = on_lsr_received(&mut adj, &[&area, &link], &[1, 101]);
    assert!(matches!(&actions[..], [Action::SendLsu(lsas)] if lsas.len() == 2));
    assert!(adj.retransmission_list.contains_key(&1));
    assert!(adj.retransmission_list.contains_key(&101));
    assert_eq!(on_lsr_received(&mut adj, &[&area], &[]), []);
}

#[test]
fn lsr_for_unknown_lsa_triggers_seq_number_mismatch() {
    let mut adj = AdjacencyData::default();
    let mut area = Lsdb::new();
    area.install(lsa_id(1, SEQ1));
    // 101 lives in another link's store, so it is not servable here.
    assert_eq!(
        on_lsr_received(&mut adj, &[&area, &Lsdb::new()], &[1, 101]),
        vec![Action::NeighborEvent(Event::SeqNumberMismatch)]
    );
    assert!(adj.retransmission_list.is_empty());
}

#[test]
fn lsu_installs_and_acks_and_clears_request_list() {
    let mut adj = AdjacencyData {
        request_list: vec![1],
        ..Default::default()
    };
    let mut area = Lsdb::new();
    let l = lsa_id(1, SEQ1);
    let (actions, newly_installed) = lsu(&mut adj, &mut area, std::slice::from_ref(&l));
    assert_eq!(adj.request_list, []);
    assert!(area.get(&1).is_some());
    assert_eq!(actions, vec![Action::NeighborEvent(Event::LoadingDone)]);
    assert_eq!(newly_installed, vec![l.0]);
    // RFC 2328 §13.5: the ack goes out on the next sweep, as one packet.
    assert_eq!(
        take_pending_acks(&mut adj),
        Some(Action::SendLsAck(vec![l.0]))
    );
    assert_eq!(take_pending_acks(&mut adj), None);
}

#[test]
fn lsu_with_stale_duplicate_is_acked_but_not_reported_as_newly_installed() {
    let mut adj = AdjacencyData::default();
    let mut area = Lsdb::new();
    let l = lsa_id(1, SEQ1);
    area.install(l.clone());
    let (actions, newly_installed) = lsu(&mut adj, &mut area, std::slice::from_ref(&l));
    assert_eq!(actions, vec![Action::NeighborEvent(Event::LoadingDone)]);
    assert_eq!(adj.pending_acks, vec![l.0]);
    assert_eq!(newly_installed, []);
}

#[test]
fn lsu_without_emptying_request_list_does_not_fire_loading_done() {
    let mut adj = AdjacencyData {
        request_list: vec![1, 2],
        ..Default::default()
    };
    let l = lsa_id(1, SEQ1);
    let (actions, newly_installed) = lsu(&mut adj, &mut Lsdb::new(), std::slice::from_ref(&l));
    assert_eq!(adj.request_list, vec![2]);
    assert_eq!(actions, []);
    assert_eq!(newly_installed, vec![l.0]);
}

/// RFC 2328 §13 step 4: an unheld `MaxAge` LSA is acked but not installed,
/// unless this adjacency asked for it or `exempt_max_age` says so.
#[test]
fn lsu_with_unheld_max_age_lsa_is_acked_but_discarded() {
    let mut l = lsa_id(1, SEQ1);
    l.0.age = MAX_AGE;
    let mut adj = AdjacencyData::default();
    let mut area = Lsdb::new();
    let (actions, newly_installed) = lsu(&mut adj, &mut area, std::slice::from_ref(&l));
    assert!(area.get(&1).is_none());
    assert_eq!(newly_installed, []);
    assert!(!actions.iter().any(|a| matches!(a, Action::SendLsAck(_))));
    assert_eq!(adj.pending_acks, vec![l.0]);

    let mut adj = AdjacencyData {
        request_list: vec![1],
        ..Default::default()
    };
    let (_, newly_installed) = lsu(&mut adj, &mut area, std::slice::from_ref(&l));
    assert_eq!(newly_installed, vec![l.0]);
    assert_eq!(adj.request_list, []);

    let mut exempt = lsa_id(500, SEQ1);
    exempt.0.age = MAX_AGE;
    let (_, newly_installed) = lsu(
        &mut AdjacencyData::default(),
        &mut area,
        std::slice::from_ref(&exempt),
    );
    assert_eq!(newly_installed, vec![exempt.0]);
}

/// A flushed copy (same sequence/checksum, age `MaxAge`) of a held LSA
/// supersedes it: `is_newer`'s `MaxAge` tie-break.
#[test]
fn lsu_with_max_age_copy_of_held_lsa_supersedes_it() {
    let mut area = Lsdb::new();
    let l = lsa_id(1, SEQ1);
    area.install(l.clone());
    let mut flushed = l;
    flushed.0.age = MAX_AGE;
    let (_, newly_installed) = lsu(
        &mut AdjacencyData::default(),
        &mut area,
        std::slice::from_ref(&flushed),
    );
    assert_eq!(newly_installed, vec![flushed.0]);
    assert_eq!(area.get(&1).unwrap().0.age, MAX_AGE);
}

/// RFC 2328 §13.5: acks from several LSUs accumulate into one `LSAck`.
#[test]
fn lsu_acks_accumulate_across_lsus_until_taken() {
    let mut adj = AdjacencyData::default();
    let mut area = Lsdb::new();
    let (first, second) = (lsa_id(1, SEQ1), lsa_id(2, SEQ1));
    for l in [&first, &second] {
        lsu(&mut adj, &mut area, std::slice::from_ref(l));
    }
    assert_eq!(
        take_pending_acks(&mut adj),
        Some(Action::SendLsAck(vec![first.0, second.0]))
    );
}

/// RFC 2328 §13 step 5a: a newer instance within `MinLSArrival` of the last
/// received one is discarded: not installed, not acked, and not counted as
/// answering a request.
#[test]
fn lsu_with_newer_instance_too_soon_is_discarded_without_ack() {
    let first = lsa_id(1, SEQ1);
    let second = lsa_id(1, SEQ1 + 1);
    let mut adj = AdjacencyData {
        request_list: vec![1],
        ..Default::default()
    };
    let mut area = Lsdb::new();
    let t0 = Instant::now();
    area.install_received(first, t0);
    let run = |adj: &mut AdjacencyData, area: &mut Lsdb<L>, at| {
        lsu_at(
            adj,
            area,
            &mut Lsdb::new(),
            None,
            std::slice::from_ref(&second),
            at,
        )
    };
    let (actions, newly_installed) = run(&mut adj, &mut area, t0 + crate::lsdb::MIN_LS_ARRIVAL / 2);
    assert_eq!(newly_installed, []);
    assert_eq!(adj.pending_acks, []);
    assert_eq!(actions, []);
    assert_eq!(adj.request_list, vec![1]);
    assert_eq!(area.get(&1).unwrap().0.seq, SEQ1);

    let (actions, newly_installed) = run(&mut adj, &mut area, t0 + crate::lsdb::MIN_LS_ARRIVAL);
    assert_eq!(newly_installed, vec![second.0]);
    assert_eq!(adj.pending_acks, vec![second.0]);
    assert_eq!(actions, vec![Action::NeighborEvent(Event::LoadingDone)]);
}

/// `scope` routes each LSA of one LSU to its store; `discard` drops one
/// unacked.
#[test]
fn lsu_routes_each_lsa_to_its_scope_store_and_drops_discarded_unacked() {
    let mut adj = AdjacencyData::default();
    let (mut area, mut link, mut as_scope) = (Lsdb::new(), Lsdb::new(), Lsdb::new());
    let lsas = [
        lsa_id(1, SEQ1),
        lsa_id(101, SEQ1),
        lsa_id(201, SEQ1),
        lsa_id(901, SEQ1),
    ];
    let (_, installed) = lsu_at(
        &mut adj,
        &mut area,
        &mut link,
        Some(&mut as_scope),
        &lsas,
        Instant::now(),
    );
    assert_eq!(installed.len(), 3);
    assert_eq!(adj.pending_acks.len(), 3);
    for (store, held) in [(&area, 1), (&link, 101), (&as_scope, 201)] {
        let ids: Vec<u32> = store.headers().iter().map(|h| h.id).collect();
        assert_eq!(ids, [held]);
    }
}

/// `Scope::As` without an AS store is a caller bug: a debug build asserts.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "Scope::As without an AS store")]
fn lsu_as_scope_without_as_store_asserts() {
    lsu(
        &mut AdjacencyData::default(),
        &mut Lsdb::new(),
        &[lsa_id(201, SEQ1)],
    );
}

#[test]
fn compute_request_list_picks_missing_and_older_in_neighbor_order() {
    let local = [
        header("0.0.0.1", 5),
        header("0.0.0.2", 5),
        header("0.0.0.3", 5),
    ];
    let nbr = [
        header("0.0.0.9", 1), // missing locally
        header("0.0.0.1", 6), // newer than ours
        header("0.0.0.2", 5), // equal
        header("0.0.0.3", 4), // older
        header("0.0.0.4", 1), // missing locally
    ];
    let id = |s: &str| u32::from(router_id(s));
    assert_eq!(
        compute_request_list(&nbr, &local),
        vec![id("0.0.0.9"), id("0.0.0.1"), id("0.0.0.4")]
    );
}

#[test]
fn compute_request_list_handles_ten_thousand_headers() {
    let h = |id, seq| H {
        id,
        seq,
        age: 0,
        checksum: 0,
    };
    let local: Vec<H> = (0..10_000).map(|i| h(i, 1)).collect();
    let nbr: Vec<H> = (0..10_000)
        .map(|i| h(i, if i % 2 == 0 { 2 } else { 1 }))
        .collect();
    let want: Vec<u32> = (0..10_000).filter(|i| i % 2 == 0).collect();
    assert_eq!(compute_request_list(&nbr, &local), want);
}

#[test]
fn lsu_trims_a_large_request_list_keeping_order() {
    let mut adj = AdjacencyData {
        request_list: (0..10_000).collect(),
        ..Default::default()
    };
    let mut area = Lsdb::new();
    // LSU order differs from list order.
    let lsas = [lsa_id(3, SEQ1), lsa_id(450, SEQ1), lsa_id(42, SEQ1)];
    let (actions, installed) = lsu(&mut adj, &mut area, &lsas);
    assert_eq!(actions, []);
    assert_eq!(installed.len(), 3);
    let want: Vec<u32> = (0..10_000).filter(|i| ![3, 42, 450].contains(i)).collect();
    assert_eq!(adj.request_list, want);
}

#[test]
fn lsu_max_age_of_requested_key_installs_but_unknown_key_only_acks() {
    let mut adj = AdjacencyData {
        request_list: vec![1, 2],
        ..Default::default()
    };
    let mut area = Lsdb::new();
    let aged = |id| {
        let mut l = lsa_id(id, SEQ1);
        l.0.age = MAX_AGE;
        l
    };
    let (_, installed) = lsu(&mut adj, &mut area, &[aged(1), aged(77)]);
    assert_eq!(installed.len(), 1);
    assert!(area.get(&1).is_some() && area.get(&77).is_none());
    assert_eq!(adj.pending_acks.len(), 2);
    assert_eq!(adj.request_list, vec![2]);
}

#[test]
fn lsack_clears_retransmission_list() {
    let l = lsa_id(1, SEQ1);
    let mut adj = AdjacencyData {
        retransmission_list: HashMap::from([(1, Arc::new(l.clone()))]),
        ..Default::default()
    };
    on_lsack_received(&mut adj, &[l.0]);
    assert!(adj.retransmission_list.is_empty());
}

#[test]
fn lsack_of_other_instance_keeps_entry() {
    for acked_seq in [SEQ1 - 1, SEQ1 + 1] {
        let l = lsa_id(1, SEQ1);
        let mut adj = AdjacencyData {
            retransmission_list: HashMap::from([(1, Arc::new(l))]),
            ..Default::default()
        };
        on_lsack_received(&mut adj, &[lsa_id(1, acked_seq).0]);
        assert_eq!(adj.retransmission_list.len(), 1, "seq {acked_seq}");
    }
}

#[test]
fn chunk_by_budget_cases() {
    let sz = |n: &usize| *n;
    let empty: [usize; 0] = [];
    assert_eq!(chunk_by_budget(&empty, 10, sz).len(), 0);
    // Exact fit stays one chunk; one over splits.
    assert_eq!(chunk_by_budget(&[5, 5], 10, sz), vec![&[5, 5][..]]);
    assert_eq!(
        chunk_by_budget(&[5, 5, 1], 10, sz),
        vec![&[5, 5][..], &[1][..]]
    );
    // An oversize item goes alone, order kept.
    let items = [3, 50, 3, 3];
    let chunks = chunk_by_budget(&items, 10, sz);
    assert_eq!(chunks, vec![&[3][..], &[50][..], &[3, 3][..]]);
    assert_eq!(chunks.concat(), items);
}

#[test]
fn truncated_only_past_the_buffer() {
    assert!(!truncated(RECV_BUF_LEN, RECV_BUF_LEN));
    assert!(truncated(RECV_BUF_LEN + 1, RECV_BUF_LEN));
}

#[test]
fn take_all_pending_acks_dedupes_drains_and_keeps_oldest_since() {
    let t0 = Instant::now();
    let t1 = t0 + std::time::Duration::from_secs(1);
    let (h1, h2) = (header("1.0.0.1", SEQ1), header("1.0.0.2", SEQ1));
    let mut a = AdjacencyData {
        pending_acks: vec![h1, h2],
        pending_acks_since: Some(t1),
        ..Default::default()
    };
    let mut b = AdjacencyData {
        pending_acks: vec![h1],
        pending_acks_since: Some(t0),
        ..Default::default()
    };
    let mut idle = AdjacencyData::default();
    let (set, since) = take_all_pending_acks([&mut a, &mut idle, &mut b].into_iter());
    assert_eq!(set, vec![h1, h2]);
    assert_eq!(since, Some(t0));
    assert!(a.pending_acks.is_empty() && b.pending_acks.is_empty());
    assert_eq!(a.pending_acks_since, None);
    assert_eq!(
        take_all_pending_acks([&mut a, &mut b].into_iter()),
        (vec![], None)
    );
}
