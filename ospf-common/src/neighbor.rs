//! RFC 2328 §10.5 neighbor event processing — the full state ladder from
//! `Down` through `Full`. Pure state transition, no I/O — `link.rs` drives
//! real Hello/DBD/LSR/LSU/LSAck send/receive and every timer around this,
//! and `exchange.rs` holds the heavier DBD/LSR/LSU negotiation logic that
//! decides which `Event` to feed in once a neighbor is past `TwoWay`.

/// A link's neighbor state. Deliberately a plain enum (not
/// `Option<NeighborState>` like `bgp::fsm::step`'s `Option<State>`) — `Down`
/// is an ongoing, valid state here, not a signal to tear down the driver
/// task (a point-to-point link keeps sending Hellos while `Down`, hoping to
/// hear one back).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NeighborState {
    Down,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A valid Hello was received from the neighbor (matching area,
    /// well-formed). `saw_self` is whether the Hello's own neighbor list
    /// included this router's router-id.
    HelloReceived {
        saw_self: bool,
    },
    InactivityTimerExpired,
    /// RFC 2328 §7.5/§10.4: this neighbor is now eligible to form a full
    /// adjacency (point-to-point, always; broadcast, only once this router
    /// or the neighbor is the elected DR/BDR — see `link::should_form_adjacency`).
    AdjacencyEligible,
    /// RFC 2328 §10.6's master/slave negotiation has concluded.
    NegotiationDone,
    /// RFC 2328 §10.8's summary-list exchange has concluded. `more_to_load`
    /// is whether the resulting request list is non-empty.
    ExchangeDone {
        more_to_load: bool,
    },
    /// Every requested LSA has been received.
    LoadingDone,
    /// RFC 2328 §10.8's `SeqNumberMismatch` — an out-of-sequence or otherwise
    /// invalid DBD/LSR/LSU arrived mid-exchange, forcing negotiation to
    /// restart from `ExStart`.
    SeqNumberMismatch,
    /// The neighbor relationship failed outright (link down, or any other
    /// condition immediately invalidating the adjacency).
    AdjacencyLost,
}

/// RFC 2328 §10.7/§13/§13.7: LSR, LSU and `LSAck` are ignored from a neighbor
/// below `Exchange`.
#[must_use]
pub fn exchange_or_later(state: NeighborState) -> bool {
    matches!(
        state,
        NeighborState::Exchange | NeighborState::Loading | NeighborState::Full
    )
}

/// Pure state transition — no I/O, no timers. `link.rs` drives real
/// Hello/DBD/LSR/LSU/LSAck send/receive and every timer around this.
pub fn step(state: NeighborState, event: Event) -> NeighborState {
    match event {
        Event::HelloReceived { saw_self } => match state {
            NeighborState::Down => NeighborState::Init,
            NeighborState::Init | NeighborState::TwoWay => {
                if saw_self {
                    NeighborState::TwoWay
                } else {
                    // RFC 2328's "1-WayReceived": the neighbor stopped
                    // listing us, so we drop back to Init.
                    NeighborState::Init
                }
            }
            // Once adjacency negotiation has begun, an ordinary Hello no
            // longer drives state forward — only DBD/LSR/LSU events do.
            // "1-WayReceived" still tears the adjacency back down to Init,
            // exactly as it would from TwoWay.
            NeighborState::ExStart
            | NeighborState::Exchange
            | NeighborState::Loading
            | NeighborState::Full => {
                if saw_self {
                    state
                } else {
                    NeighborState::Init
                }
            }
        },
        Event::InactivityTimerExpired | Event::AdjacencyLost => NeighborState::Down,
        Event::AdjacencyEligible => match state {
            NeighborState::TwoWay => NeighborState::ExStart,
            other => other,
        },
        Event::NegotiationDone => match state {
            NeighborState::ExStart => NeighborState::Exchange,
            other => other,
        },
        Event::ExchangeDone { more_to_load } => match state {
            NeighborState::Exchange => {
                if more_to_load {
                    NeighborState::Loading
                } else {
                    NeighborState::Full
                }
            }
            other => other,
        },
        Event::LoadingDone => match state {
            NeighborState::Loading => NeighborState::Full,
            other => other,
        },
        Event::SeqNumberMismatch => match state {
            NeighborState::ExStart
            | NeighborState::Exchange
            | NeighborState::Loading
            | NeighborState::Full => NeighborState::ExStart,
            other => other,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn down_to_init_on_first_hello() {
        assert_eq!(
            step(
                NeighborState::Down,
                Event::HelloReceived { saw_self: false }
            ),
            NeighborState::Init
        );
    }

    #[test]
    fn init_to_two_way_when_self_seen() {
        assert_eq!(
            step(NeighborState::Init, Event::HelloReceived { saw_self: true }),
            NeighborState::TwoWay
        );
    }

    #[test]
    fn init_stays_init_when_self_not_seen() {
        assert_eq!(
            step(
                NeighborState::Init,
                Event::HelloReceived { saw_self: false }
            ),
            NeighborState::Init
        );
    }

    #[test]
    fn two_way_stays_two_way_when_self_seen() {
        assert_eq!(
            step(
                NeighborState::TwoWay,
                Event::HelloReceived { saw_self: true }
            ),
            NeighborState::TwoWay
        );
    }

    #[test]
    fn two_way_drops_to_init_when_self_no_longer_seen() {
        assert_eq!(
            step(
                NeighborState::TwoWay,
                Event::HelloReceived { saw_self: false }
            ),
            NeighborState::Init
        );
    }

    #[test]
    fn inactivity_timer_forces_down_from_any_state() {
        for state in [
            NeighborState::Down,
            NeighborState::Init,
            NeighborState::TwoWay,
            NeighborState::ExStart,
            NeighborState::Exchange,
            NeighborState::Loading,
            NeighborState::Full,
        ] {
            assert_eq!(
                step(state, Event::InactivityTimerExpired),
                NeighborState::Down
            );
            assert_eq!(step(state, Event::AdjacencyLost), NeighborState::Down);
        }
    }

    #[test]
    fn adjacency_eligible_advances_two_way_to_exstart() {
        assert_eq!(
            step(NeighborState::TwoWay, Event::AdjacencyEligible),
            NeighborState::ExStart
        );
    }

    #[test]
    fn adjacency_eligible_is_a_no_op_outside_two_way() {
        assert_eq!(
            step(NeighborState::Init, Event::AdjacencyEligible),
            NeighborState::Init
        );
        assert_eq!(
            step(NeighborState::Full, Event::AdjacencyEligible),
            NeighborState::Full
        );
    }

    #[test]
    fn negotiation_done_advances_exstart_to_exchange() {
        assert_eq!(
            step(NeighborState::ExStart, Event::NegotiationDone),
            NeighborState::Exchange
        );
    }

    #[test]
    fn exchange_done_with_nothing_to_load_reaches_full() {
        assert_eq!(
            step(
                NeighborState::Exchange,
                Event::ExchangeDone {
                    more_to_load: false
                }
            ),
            NeighborState::Full
        );
    }

    #[test]
    fn exchange_done_with_something_to_load_reaches_loading() {
        assert_eq!(
            step(
                NeighborState::Exchange,
                Event::ExchangeDone { more_to_load: true }
            ),
            NeighborState::Loading
        );
    }

    #[test]
    fn loading_done_reaches_full() {
        assert_eq!(
            step(NeighborState::Loading, Event::LoadingDone),
            NeighborState::Full
        );
    }

    #[test]
    fn seq_number_mismatch_restarts_negotiation_from_any_adjacency_state() {
        for state in [
            NeighborState::ExStart,
            NeighborState::Exchange,
            NeighborState::Loading,
            NeighborState::Full,
        ] {
            assert_eq!(
                step(state, Event::SeqNumberMismatch),
                NeighborState::ExStart
            );
        }
    }

    #[test]
    fn hello_with_self_seen_does_not_downgrade_full() {
        assert_eq!(
            step(NeighborState::Full, Event::HelloReceived { saw_self: true }),
            NeighborState::Full
        );
    }

    #[test]
    fn hello_without_self_seen_tears_down_full_to_init() {
        assert_eq!(
            step(
                NeighborState::Full,
                Event::HelloReceived { saw_self: false }
            ),
            NeighborState::Init
        );
    }

    #[test]
    fn exchange_or_later_truth_table() {
        use NeighborState::*;
        for (s, want) in [
            (Down, false),
            (Init, false),
            (TwoWay, false),
            (ExStart, false),
            (Exchange, true),
            (Loading, true),
            (Full, true),
        ] {
            assert_eq!(exchange_or_later(s), want, "{s:?}");
        }
    }
}
