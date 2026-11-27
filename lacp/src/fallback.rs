//! LACP fallback (#1575): pure choice of the one port that carries traffic
//! alone while no partner negotiates. Only `aggregate::selection_loop` calls
//! it; it never touches Mux, Receive or the wire.

use std::time::Duration;

use tokio::time::Instant;

/// One member port as the fallback sees it.
#[derive(Debug, Clone)]
pub struct FallbackPort {
    pub interface: String,
    pub enabled: bool,
    pub timeout: Duration,
    /// `None` = link down; else when it came up (first observed).
    pub link_up_since: Option<Instant>,
    /// `PortObservation::selectable()`: a partner is (still) known.
    pub selectable: bool,
    /// The last LACPDU the Receive Machine accepted.
    pub last_pdu: Option<Instant>,
    pub priority: u16,
    pub number: u16,
}

impl FallbackPort {
    /// The dwell starts at the later of the last LACPDU and the link-up.
    fn origin(&self) -> Option<Instant> {
        let up = self.link_up_since?;
        Some(self.last_pdu.map_or(up, |p| p.max(up)))
    }

    fn eligible(&self, now: Instant) -> bool {
        self.enabled
            && !self.selectable
            && self.origin().is_some_and(|o| now >= o + self.timeout)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Pick {
    pub chosen: Option<String>,
    /// Earliest moment a waiting port becomes eligible.
    pub next_deadline: Option<Instant>,
}

/// `current` stays chosen while eligible (no preemption); otherwise the
/// lowest `(priority, number)` eligible port. Nothing while the negotiated
/// set is non-empty.
pub fn pick(
    ports: &[FallbackPort],
    now: Instant,
    negotiated_empty: bool,
    current: Option<&str>,
) -> Pick {
    if !negotiated_empty {
        return Pick {
            chosen: None,
            next_deadline: None,
        };
    }
    let next_deadline = ports
        .iter()
        .filter(|p| p.enabled && !p.selectable && !p.eligible(now))
        .filter_map(|p| p.origin().map(|o| o + p.timeout))
        .min();
    let sticky = current.and_then(|c| ports.iter().find(|p| p.interface == c && p.eligible(now)));
    let chosen = sticky
        .or_else(|| {
            ports
                .iter()
                .filter(|p| p.eligible(now))
                .min_by_key(|p| (p.priority, p.number))
        })
        .map(|p| p.interface.clone());
    Pick {
        chosen,
        next_deadline,
    }
}

/// Why `current` is no longer chosen, for the `lacp fallback ended` log.
pub fn end_reason(ports: &[FallbackPort], current: &str, negotiated_empty: bool) -> &'static str {
    if !negotiated_empty {
        return "negotiated";
    }
    match ports.iter().find(|p| p.interface == current) {
        Some(p) if p.enabled && p.link_up_since.is_none() => "link-down",
        Some(p) if p.enabled && p.selectable => "partner",
        Some(p) if p.enabled => "timeout",
        _ => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(5);

    fn port(name: &str, prio: u16, num: u16, t0: Instant) -> FallbackPort {
        FallbackPort {
            interface: name.into(),
            enabled: true,
            timeout: T,
            link_up_since: Some(t0),
            selectable: false,
            last_pdu: None,
            priority: prio,
            number: num,
        }
    }

    fn chosen(ports: &[FallbackPort], now: Instant, cur: Option<&str>) -> Option<String> {
        pick(ports, now, true, cur).chosen
    }

    #[tokio::test(start_paused = true)]
    async fn lowest_priority_number_wins_and_sticks() {
        let t0 = Instant::now();
        let mut ports = vec![port("eth2", 10, 2, t0), port("eth1", 10, 1, t0)];
        assert_eq!(chosen(&ports, t0 + T, None), Some("eth1".into()));
        // A better port later does not preempt the current one.
        ports.push(port("eth0", 1, 9, t0));
        assert_eq!(chosen(&ports, t0 + T, Some("eth1")), Some("eth1".into()));
        assert_eq!(chosen(&ports, t0 + T, None), Some("eth0".into()));
    }

    #[tokio::test(start_paused = true)]
    async fn dwell_runs_from_last_pdu_never_heard_from_link_up() {
        let t0 = Instant::now();
        let mut p = port("eth1", 1, 1, t0);
        assert_eq!(
            chosen(&[p.clone()], t0 + T - Duration::from_millis(1), None),
            None
        );
        assert!(chosen(&[p.clone()], t0 + T, None).is_some());
        // A PDU at timeout-1 postpones eligibility to its own +timeout.
        let pdu = t0 + T - Duration::from_secs(1);
        p.last_pdu = Some(pdu);
        assert_eq!(chosen(&[p.clone()], t0 + T, None), None);
        assert_eq!(
            pick(&[p.clone()], t0 + T, true, None).next_deadline,
            Some(pdu + T)
        );
        assert!(chosen(&[p], pdu + T, None).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn partner_known_disabled_down_or_negotiated_block_it() {
        let t0 = Instant::now();
        let now = t0 + T;
        let mut p = port("eth1", 1, 1, t0);
        p.selectable = true; // Expired with a learned partner
        assert_eq!(chosen(&[p.clone()], now, None), None);
        assert_eq!(pick(&[p.clone()], now, true, None).next_deadline, None);
        p.selectable = false;
        p.enabled = false;
        assert_eq!(chosen(&[p.clone()], now, None), None);
        p.enabled = true;
        p.link_up_since = None;
        assert_eq!(chosen(&[p.clone()], now, None), None);
        // A link flap restarts the dwell.
        p.link_up_since = Some(now);
        assert_eq!(chosen(&[p.clone()], now, None), None);
        assert!(chosen(&[p.clone()], now + T, None).is_some());
        assert_eq!(pick(&[p], now + T, false, None).chosen, None);
    }

    #[tokio::test(start_paused = true)]
    async fn end_reasons() {
        let t0 = Instant::now();
        let mut p = port("eth1", 1, 1, t0);
        assert_eq!(end_reason(&[p.clone()], "eth1", false), "negotiated");
        p.selectable = true;
        assert_eq!(end_reason(&[p.clone()], "eth1", true), "partner");
        p.link_up_since = None;
        assert_eq!(end_reason(&[p.clone()], "eth1", true), "link-down");
        p.enabled = false;
        assert_eq!(end_reason(&[p], "eth1", true), "disabled");
        assert_eq!(end_reason(&[], "eth1", true), "disabled");
    }
}
