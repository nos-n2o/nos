//! Single-use login tickets (#990): a password check traded for a short-lived
//! secret that `RedeemTicket` later turns into a certificate.
//!
//! Only the SHA-256 of a ticket is kept, so a memory dump of the map yields no
//! usable ticket.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use nos_proto::{LOGIN_TICKET_LEN, LOGIN_TICKET_TTL};
use sha2::{Digest, Sha256};

/// At most this many unredeemed tickets; the oldest is evicted for a new one.
const MAX_TICKETS: usize = 256;

struct Entry {
    user: String,
    expires: Instant,
    created: u64,
}

#[derive(Default)]
struct Inner {
    map: HashMap<[u8; 32], Entry>,
    counter: u64,
}

#[derive(Default)]
pub struct Tickets(Mutex<Inner>);

fn key(ticket: &[u8]) -> [u8; 32] {
    Sha256::digest(ticket).into()
}

impl Tickets {
    /// Mints a ticket for `user`, valid until `now + LOGIN_TICKET_TTL`.
    pub fn issue(&self, user: &str, now: Instant) -> Vec<u8> {
        let mut ticket = vec![0u8; LOGIN_TICKET_LEN];
        // ponytail: an unreadable OS RNG panics the login task, never mints a weak ticket.
        getrandom::getrandom(&mut ticket).expect("OS random source");
        let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        g.map.retain(|_, e| e.expires > now);
        let oldest = g.map.iter().min_by_key(|(_, e)| e.created).map(|(k, _)| *k);
        if let Some(oldest) = oldest.filter(|_| g.map.len() >= MAX_TICKETS) {
            g.map.remove(&oldest);
        }
        g.counter += 1;
        let created = g.counter;
        g.map.insert(
            key(&ticket),
            Entry {
                user: user.to_string(),
                expires: now + LOGIN_TICKET_TTL,
                created,
            },
        );
        ticket
    }

    /// Consumes `ticket`: the user it was issued to, if it is known and
    /// unexpired. A failed (late) attempt still burns it.
    pub fn redeem(&self, ticket: &[u8], now: Instant) -> Option<String> {
        let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let e = g.map.remove(&key(ticket))?;
        (e.expires > now).then_some(e.user)
    }

    /// Drops every outstanding ticket of `user` (deleted, or password changed).
    pub fn forget_user(&self, user: &str) {
        let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        g.map.retain(|_, e| e.user != user);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn single_use_and_unique_32_bytes() {
        let t = Tickets::default();
        let now = Instant::now();
        let (a, b) = (t.issue("alice", now), t.issue("alice", now));
        assert_eq!((a.len(), b.len()), (32, 32));
        assert_ne!(a, b);
        assert_eq!(t.redeem(&a, now).as_deref(), Some("alice"));
        assert_eq!(t.redeem(&a, now), None);
        assert_eq!(t.redeem(&b[..31], now), None);
        assert_eq!(t.redeem(&[0; 32], now), None);
    }

    #[test]
    fn expires_at_the_ttl_and_a_late_attempt_burns_it() {
        let t = Tickets::default();
        let now = Instant::now();
        let a = t.issue("alice", now);
        assert_eq!(t.redeem(&a, now + LOGIN_TICKET_TTL), None);
        assert_eq!(t.redeem(&a, now), None);
        let b = t.issue("alice", now);
        assert!(t.redeem(&b, now + Duration::from_secs(59)).is_some());
    }

    #[test]
    fn the_257th_ticket_evicts_the_oldest() {
        let t = Tickets::default();
        let now = Instant::now();
        let all: Vec<_> = (0..=MAX_TICKETS).map(|_| t.issue("alice", now)).collect();
        assert_eq!(t.redeem(&all[0], now), None);
        assert!(t.redeem(&all[1], now).is_some());
        assert!(t.redeem(&all[MAX_TICKETS], now).is_some());
    }

    #[test]
    fn forget_user_drops_only_that_users_tickets() {
        let t = Tickets::default();
        let now = Instant::now();
        let (a, b) = (t.issue("alice", now), t.issue("bob", now));
        t.forget_user("alice");
        assert_eq!(t.redeem(&a, now), None);
        assert_eq!(t.redeem(&b, now).as_deref(), Some("bob"));
    }

    #[test]
    fn the_stored_key_is_the_hash_not_the_ticket() {
        let t = Tickets::default();
        let a = t.issue("alice", Instant::now());
        let g = t.0.lock().unwrap();
        assert!(!g.map.keys().any(|k| k[..] == a[..]));
        assert!(g.map.contains_key(&key(&a)));
    }
}
