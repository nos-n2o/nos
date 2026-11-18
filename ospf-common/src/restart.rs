//! RFC 3623 (and RFC 5187) restarting-router logic shared by both daemons:
//! the `<instance>.gr` marker format and the "when does restart mode end"
//! rule. Pure; the daemons own the file, the clock and what restart mode
//! suppresses (origination, route pushes).

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

/// Why restart mode ended (the `reason=` log field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Every pre-restart `Full` neighbor is `Full` again.
    Complete,
    /// The remaining grace period ran out.
    Timeout,
    /// Strict LSA checking (§2.2): a router other than us changed an LSA
    /// that was already installed, so the helpers' old view is stale.
    TopologyChange,
}

impl ExitReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Timeout => "timeout",
            Self::TopologyChange => "topology-change",
        }
    }
}

/// What the previous incarnation left in the marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// Unix seconds the grace period ends.
    pub deadline: u64,
    /// Router ids of the neighbors that were `Full` when it stopped.
    pub neighbors: BTreeSet<Ipv4Addr>,
}

/// `deadline` on the first line, the `Full` neighbors comma-separated on the
/// second (absent in a marker from before restart mode: no neighbors).
#[must_use]
pub fn encode_marker(deadline: u64, neighbors: &BTreeSet<Ipv4Addr>) -> String {
    let ids: Vec<String> = neighbors.iter().map(ToString::to_string).collect();
    format!("{deadline}\n{}", ids.join(","))
}

/// `None` for garbage or a deadline not ahead of `now` or further than a
/// `u16` grace period away (a clock jump).
#[must_use]
pub fn parse_marker(content: &str, now: u64) -> Option<Marker> {
    let mut lines = content.lines();
    let deadline: u64 = lines.next()?.trim().parse().ok()?;
    if !(now < deadline && deadline <= now + u64::from(u16::MAX)) {
        return None;
    }
    let neighbors = lines
        .next()
        .unwrap_or("")
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    Some(Marker {
        deadline,
        neighbors,
    })
}

/// Whether restart mode ends now: complete first (nothing left to wait for),
/// then a topology change, then the timeout.
#[must_use]
pub fn exit_reason(
    expected: &BTreeSet<Ipv4Addr>,
    full: &BTreeSet<Ipv4Addr>,
    timed_out: bool,
    topology_changed: bool,
) -> Option<ExitReason> {
    if expected.is_subset(full) {
        Some(ExitReason::Complete)
    } else if topology_changed {
        Some(ExitReason::TopologyChange)
    } else if timed_out {
        Some(ExitReason::Timeout)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[u8]) -> BTreeSet<Ipv4Addr> {
        v.iter().map(|&b| Ipv4Addr::new(1, 1, 1, b)).collect()
    }

    #[test]
    fn marker_round_trips_and_is_range_checked() {
        let m = encode_marker(1120, &ids(&[1, 2]));
        let parsed = parse_marker(&m, 1000).unwrap();
        assert_eq!((parsed.deadline, parsed.neighbors), (1120, ids(&[1, 2])));
        // Old format: deadline only.
        assert_eq!(parse_marker("1120", 1000).unwrap().neighbors, ids(&[]));
        assert!(parse_marker(&m, 1120).is_none());
        assert!(parse_marker(&encode_marker(1000 + 65_536, &ids(&[])), 1000).is_none());
        assert!(parse_marker("garbage", 1000).is_none());
        // A bad id is skipped, not fatal.
        assert_eq!(
            parse_marker("1120\n1.1.1.1,x", 1000).unwrap().neighbors,
            ids(&[1])
        );
    }

    #[test]
    fn exit_rule_priority() {
        let exp = ids(&[1, 2]);
        assert_eq!(exit_reason(&exp, &ids(&[1]), false, false), None);
        assert_eq!(
            exit_reason(&exp, &ids(&[1, 2, 3]), true, true),
            Some(ExitReason::Complete)
        );
        assert_eq!(
            exit_reason(&exp, &ids(&[1]), true, true),
            Some(ExitReason::TopologyChange)
        );
        assert_eq!(
            exit_reason(&exp, &ids(&[]), true, false),
            Some(ExitReason::Timeout)
        );
        assert_eq!(ExitReason::Timeout.as_str(), "timeout");
        assert_eq!(ExitReason::Complete.as_str(), "complete");
        assert_eq!(ExitReason::TopologyChange.as_str(), "topology-change");
    }
}
