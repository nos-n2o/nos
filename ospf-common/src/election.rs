//! RFC 2328 §9.4 DR/BDR election — pure, synchronous, no I/O. Mirrors
//! `neighbor.rs`'s/`packet.rs`'s pure-core style; `link.rs` drives real
//! Hello send/receive and timers around this.
//!
//! # ponytail: single-pass election
//! RFC 2328 §9.4 says to recompute DR/BDR a second time if the first pass
//! changed *this router's own* role (Backup/DR/DROther) — a stability
//! refinement. This is skipped: `elect` always runs a single pass.
//! `link.rs` re-runs `elect` after every Hello-driven neighbor-state change
//! and every dead-interval sweep, so the correct steady state is still
//! reached, just within one extra Hello interval instead of instantly.
//!
//! Adjacency formation *does* now depend on DR/BDR-ness (`link::
//! should_form_adjacency`, re-checked on every re-election) — but that's
//! still harmless: a delayed-by-one-interval settle only delays *when*
//! `ExStart` begins for a newly-eligible pair, it never produces a wrong
//! adjacency decision, since eligibility is re-evaluated fresh on every
//! election result rather than cached. Upgrade to a second pass if a
//! faster DR/BDR settle time ever matters on its own merits.

use std::net::Ipv4Addr;

/// One router's (self's or a neighbor's) candidacy for DR/BDR, as of its
/// most recently received Hello (or, for `self_`, this link's own current
/// view).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub router_id: Ipv4Addr,
    pub priority: u8,
    /// Router-ID space (`OSPFv3` Hellos carry router IDs on the wire; `OSPFv2`'s
    /// carry interface addresses, which `nos-ospf` translates first, #608).
    /// `Ipv4Addr::UNSPECIFIED` if this candidate declares no DR.
    pub declared_dr: Ipv4Addr,
    /// `Ipv4Addr::UNSPECIFIED` if this candidate declares no BDR.
    pub declared_bdr: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ElectionResult {
    pub dr: Option<Ipv4Addr>,
    pub bdr: Option<Ipv4Addr>,
}

/// Runs RFC 2328 §9.4's election given `self_`'s own candidacy and every
/// neighbor's. `neighbors` must already be filtered by the caller to
/// 2-Way-or-better — this function has no state-machine awareness of its
/// own.
// `declaring_bdr`/`declaring_dr` are RFC 2328 §9.4's own two distinct
// candidate sets, side by side here for a reason — renaming one to look
// less alike would hurt clarity, not help it.
#[allow(clippy::similar_names)]
pub fn elect(self_: Candidate, neighbors: &[Candidate]) -> ElectionResult {
    let eligible: Vec<Candidate> = std::iter::once(self_)
        .chain(neighbors.iter().copied())
        .filter(|c| c.priority > 0)
        .collect();

    if eligible.is_empty() {
        return ElectionResult::default();
    }

    // RFC 2328 §9.4 step (2)'s fallback set for BDR — "the router having
    // highest Router Priority, among routers not declaring themselves to
    // be DR" — deliberately excludes DR self-declarers even as a
    // fallback. Without this exclusion, a lone highest-priority/-id
    // candidate that has declared itself DR would also keep winning BDR
    // on every subsequent recomputation (since it's still the highest
    // priority/id candidate overall), a stable-but-wrong fixed point that
    // never converges to a real DR/BDR split.
    let not_declaring_dr: Vec<Candidate> = eligible
        .iter()
        .copied()
        .filter(|c| c.declared_dr != c.router_id)
        .collect();
    let bdr_pool: &[Candidate] = if not_declaring_dr.is_empty() {
        &eligible
    } else {
        &not_declaring_dr
    };
    let declaring_bdr: Vec<Candidate> = eligible
        .iter()
        .copied()
        .filter(|c| c.declared_bdr == c.router_id && c.declared_dr != c.router_id)
        .collect();
    let bdr = best(if declaring_bdr.is_empty() {
        bdr_pool
    } else {
        &declaring_bdr
    });

    let declaring_dr: Vec<Candidate> = eligible
        .iter()
        .copied()
        .filter(|c| c.declared_dr == c.router_id)
        .collect();
    let dr = if declaring_dr.is_empty() {
        bdr
    } else {
        best(&declaring_dr)
    };

    ElectionResult {
        dr: Some(dr),
        bdr: Some(bdr),
    }
}

/// Highest `(priority, router_id)`, both maximized — RFC 2328 §9.4's
/// tie-break rule. `candidates` must be non-empty.
fn best(candidates: &[Candidate]) -> Ipv4Addr {
    candidates
        .iter()
        .max_by_key(|c| (c.priority, c.router_id))
        .expect("best() called with an empty slice")
        .router_id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(router_id: &str, priority: u8) -> Candidate {
        Candidate {
            router_id: router_id.parse().unwrap(),
            priority,
            declared_dr: Ipv4Addr::UNSPECIFIED,
            declared_bdr: Ipv4Addr::UNSPECIFIED,
        }
    }

    #[test]
    fn clear_winner_by_priority() {
        let self_ = candidate("1.1.1.1", 1);
        let neighbor = candidate("2.2.2.2", 200);
        let result = elect(self_, &[neighbor]);
        // Nobody has declared a DR/BDR yet, so the BDR pass picks the
        // highest-priority candidate, and — since nobody declares
        // themselves DR — the freshly-elected BDR is promoted to DR.
        assert_eq!(result.dr, Some(neighbor.router_id));
        assert_eq!(result.bdr, Some(neighbor.router_id));
    }

    #[test]
    fn router_id_tiebreak_on_equal_priority() {
        let self_ = candidate("1.1.1.1", 1);
        let neighbor = candidate("2.2.2.2", 1);
        let result = elect(self_, &[neighbor]);
        assert_eq!(result.dr, Some(neighbor.router_id));
    }

    #[test]
    fn incumbent_dr_keeps_precedence_over_higher_priority_newcomer() {
        let mut incumbent = candidate("1.1.1.1", 1);
        incumbent.declared_dr = incumbent.router_id;
        let mut newcomer = candidate("2.2.2.2", 200);
        // The newcomer doesn't declare itself DR — it defers to the
        // already-elected incumbent, exactly as a real neighbor would once
        // it's seen the incumbent's own Hello declaring itself DR.
        newcomer.declared_dr = incumbent.router_id;
        let result = elect(newcomer, &[incumbent]);
        assert_eq!(result.dr, Some(incumbent.router_id));
    }

    #[test]
    fn priority_zero_excluded_from_candidacy() {
        let self_ = candidate("1.1.1.1", 1);
        let mut zero_priority = candidate("2.2.2.2", 0);
        zero_priority.declared_dr = zero_priority.router_id;
        let result = elect(self_, &[zero_priority]);
        assert_eq!(result.dr, Some(self_.router_id));
    }

    #[test]
    fn bdr_excludes_self_declared_dr_even_as_fallback() {
        // Regression test: once one candidate has declared itself DR but
        // nobody has declared BDR yet, the BDR fallback pool must exclude
        // that DR self-declarer — otherwise, on a two-router segment, the
        // same (highest-priority/-id) router would keep winning both DR
        // and BDR forever, never converging to a real split.
        let self_ = candidate("9.9.9.9", 1);
        let mut neighbor = candidate("9.9.9.10", 1);
        neighbor.declared_dr = neighbor.router_id;
        let result = elect(self_, &[neighbor]);
        assert_eq!(result.dr, Some(neighbor.router_id));
        assert_eq!(result.bdr, Some(self_.router_id));
    }

    #[test]
    fn empty_neighbors_elects_self_dr_and_bdr() {
        let self_ = candidate("1.1.1.1", 1);
        let result = elect(self_, &[]);
        assert_eq!(result.dr, Some(self_.router_id));
        assert_eq!(result.bdr, Some(self_.router_id));
    }

    #[test]
    fn bdr_promoted_to_dr_when_nobody_declares_self_dr() {
        let self_ = candidate("1.1.1.1", 100);
        let neighbor = candidate("2.2.2.2", 50);
        let result = elect(self_, &[neighbor]);
        assert_eq!(result.bdr, Some(self_.router_id));
        assert_eq!(result.dr, Some(self_.router_id));
    }

    #[test]
    fn all_priority_zero_elects_nobody() {
        let self_ = candidate("1.1.1.1", 0);
        let neighbor = candidate("2.2.2.2", 0);
        let result = elect(self_, &[neighbor]);
        assert_eq!(result, ElectionResult::default());
    }
}
