//! A loopback TCP port that cannot collide with the kernel's ephemeral
//! (auto-bound source) ports or with another test process (#965).
//!
//! `bind(":0")`-and-drop hands out a port from the ephemeral range
//! (32768-60999 by default); between that drop and the code under test
//! binding it, any outgoing connection on the machine can take it, and a
//! daemon that loses that race stays deaf. A random pick below the range
//! floor, probe-bound on both wildcard addresses, avoids the race.

use std::collections::HashSet;
use std::hash::BuildHasher;
use std::sync::Mutex;

/// 20000-31999: below the default `ip_local_port_range` floor of 32768.
const FIRST: u16 = 20000;
const COUNT: u16 = 12000;

/// Handed out by this process: a freed probe cannot tell two callers apart.
static TAKEN: Mutex<Option<HashSet<u16>>> = Mutex::new(None);

/// A port in 20000-31999 that was bindable on `0.0.0.0` and `[::]` just now
/// and was not handed out earlier by this process. Randomness is
/// `RandomState` (no dependency), so concurrent test processes spread out.
///
/// # Panics
/// If no port is found after 1000 attempts.
#[must_use]
pub fn free_port() -> u16 {
    let mut taken = TAKEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let taken = taken.get_or_insert_with(HashSet::new);
    for _ in 0..1000 {
        let r = std::hash::RandomState::new().hash_one(std::time::Instant::now());
        let port = FIRST + u16::try_from(r % u64::from(COUNT)).unwrap_or(0);
        if !taken.contains(&port)
            && ["0.0.0.0", "::"].iter().all(|a| {
                // Only "in use" disqualifies: a host without IPv6 is fine.
                std::net::TcpListener::bind((*a, port))
                    .map_or_else(|e| e.kind() != std::io::ErrorKind::AddrInUse, |_| true)
            })
        {
            taken.insert(port);
            return port;
        }
    }
    panic!("no free port in {FIRST}..{}", FIRST + COUNT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_outside_the_ephemeral_range_and_distinct() {
        let ports: HashSet<u16> = (0..200).map(|_| free_port()).collect();
        assert_eq!(ports.len(), 200);
        assert!(ports.iter().all(|p| (FIRST..FIRST + COUNT).contains(p)));
    }
}
