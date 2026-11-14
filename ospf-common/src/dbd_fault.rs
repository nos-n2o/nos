//! Test-only DBD loss injection (#607): `--dbd-fault drop:2,dup:4` makes the
//! daemon drop or duplicate its Nth outgoing exchange DBD (1-based, counted
//! on the reply/poll send path, not timer retransmits), so `nos-e2e` can prove
//! the RFC 2328 §10.6 duplicate handling against a real peer.
//! ponytail: a process-global, since the send path has no daemon-wide context
//! to hang it on; never set outside tests and the `--dbd-fault` flag.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    Drop,
    Dup,
}

#[derive(Debug, Default)]
pub struct DbdFault {
    plan: Vec<(u32, Fault)>,
    sent: AtomicU32,
}

impl DbdFault {
    /// Parses `drop:N` / `dup:N`, comma-separated.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let plan = spec
            .split(',')
            .map(|item| {
                let (kind, n) = item.split_once(':').ok_or(format!("bad fault {item:?}"))?;
                let n = n.parse::<u32>().map_err(|e| format!("{item:?}: {e}"))?;
                match kind {
                    "drop" => Ok((n, Fault::Drop)),
                    "dup" => Ok((n, Fault::Dup)),
                    _ => Err(format!("unknown fault kind {kind:?}")),
                }
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            plan,
            sent: AtomicU32::new(0),
        })
    }

    /// How many copies of the next DBD to put on the wire: 1, 0 or 2.
    pub fn copies(&self) -> usize {
        let n = self.sent.fetch_add(1, Ordering::Relaxed) + 1;
        match self.plan.iter().find(|(at, _)| *at == n) {
            Some((_, Fault::Drop)) => 0,
            Some((_, Fault::Dup)) => 2,
            None => 1,
        }
    }
}

static GLOBAL: OnceLock<DbdFault> = OnceLock::new();

/// Installs the process-wide plan (`main`, from `--dbd-fault`).
pub fn install(spec: &str) -> Result<(), String> {
    let _ = GLOBAL.set(DbdFault::parse(spec)?);
    Ok(())
}

/// Copies of the next outgoing exchange DBD to send (1 when no plan is set).
pub fn copies() -> usize {
    GLOBAL.get().map_or(1, DbdFault::copies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_and_duplicates_exactly_the_nth() {
        let f = DbdFault::parse("drop:2,dup:3").unwrap();
        assert_eq!(
            (0..5).map(|_| f.copies()).collect::<Vec<_>>(),
            [1, 0, 2, 1, 1]
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(DbdFault::parse("drop").is_err());
        assert!(DbdFault::parse("lose:1").is_err());
        assert!(DbdFault::parse("drop:x").is_err());
    }
}
