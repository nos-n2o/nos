//! The S-BFD reflector's shared state (RFC 7880 §7.2): what it answers for, a
//! global packet-rate limit and the counters `show bfd reflector` prints.
//! The sockets that feed `handle` are `socket::ReflectorNet`.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nos_proto::{Config, ReflectorDiscards, ReflectorView};

use crate::auth::AuthKey;
use crate::packet;
use crate::sbfd::{reflect, Discard, Policy};
use tracing::debug;

/// Packets per second the reflector handles in total (RFC 7880 §7.2.1 "rate
/// limiter"): 100 initiators at the 10 ms floor fit. ponytail: one global
/// bucket, so one noisy source can starve the rest; per-source buckets if
/// that matters.
pub const RATE_PPS: u64 = 10_000;
/// Packets a quiet reflector accepts back to back.
pub const BURST: u64 = 2_000;

/// A token bucket, pure: `now` is an argument.
#[derive(Debug)]
struct Bucket {
    tokens: u64,
    last: Instant,
}

impl Bucket {
    fn take(&mut self, now: Instant) -> bool {
        let us =
            u64::try_from(now.saturating_duration_since(self.last).as_micros()).unwrap_or(u64::MAX);
        let add = us.saturating_mul(RATE_PPS) / 1_000_000;
        if add > 0 {
            // Keep the remainder: only advance by the time the tokens paid for.
            self.last += Duration::from_micros(add * 1_000_000 / RATE_PPS);
            self.tokens = (self.tokens + add).min(BURST);
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

const REASONS: usize = 9;

fn slot(d: Discard) -> usize {
    match d {
        Discard::Malformed => 0,
        Discard::SourcePort => 1,
        Discard::Martian => 2,
        Discard::Filtered => 3,
        Discard::RateLimited => 4,
        Discard::Authenticated => 5,
        Discard::DemandClear => 6,
        Discard::UnknownDiscriminator => 7,
        Discard::AuthFailed => 8,
    }
}

pub struct Reflector {
    policy: Mutex<Arc<Policy>>,
    bucket: Mutex<Bucket>,
    received: AtomicU64,
    replied: AtomicU64,
    discarded: [AtomicU64; REASONS],
    /// When the last auth failure was logged (one `debug!` per second).
    last_auth_log: Mutex<Option<Instant>>,
}

impl Default for Reflector {
    fn default() -> Self {
        Reflector {
            policy: Mutex::default(),
            bucket: Mutex::new(Bucket {
                tokens: BURST,
                last: Instant::now(),
            }),
            received: AtomicU64::new(0),
            replied: AtomicU64::new(0),
            discarded: Default::default(),
            last_auth_log: Mutex::default(),
        }
    }
}

/// What the running config asks the reflector to answer for.
pub fn policy_of(cfg: &Config) -> Policy {
    Policy {
        discriminators: cfg
            .sbfd_reflector
            .discriminators
            .iter()
            .map(|d| u32::from(*d))
            .collect(),
        allow_from: cfg.sbfd_reflector.allow_from.clone(),
        // A label missing from the keystore is skipped: fail closed.
        keys: cfg
            .sbfd_reflector
            .auth
            .iter()
            .filter_map(|a| cfg.key(&a.key).map(|s| AuthKey::new(&a.as_auth(), s)))
            .collect(),
    }
}

impl Reflector {
    pub fn set_policy(&self, policy: Policy) {
        *self.policy.lock().unwrap() = Arc::new(policy);
    }

    /// Whether any discriminator is configured (sockets run only then).
    pub fn enabled(&self) -> bool {
        !self.policy.lock().unwrap().discriminators.is_empty()
    }

    fn count(&self, d: Discard) {
        self.discarded[slot(d)].fetch_add(1, Ordering::Relaxed);
    }

    /// One received datagram `data` from `src`, addressed to `dst`: the wire
    /// bytes of the reply, if there is one.
    pub fn handle(
        &self,
        now: Instant,
        src: SocketAddr,
        dst: IpAddr,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        self.received.fetch_add(1, Ordering::Relaxed);
        // Before any parsing: a flood costs one lock and a counter.
        if !self.bucket.lock().unwrap().take(now) {
            self.count(Discard::RateLimited);
            return None;
        }
        let policy = self.policy.lock().unwrap().clone();
        let Ok(p) = packet::decode(data) else {
            self.count(Discard::Malformed);
            return None;
        };
        match reflect(&p, src, dst, &policy) {
            Ok(reply) => {
                self.replied.fetch_add(1, Ordering::Relaxed);
                Some(Policy::wire(&reply))
            }
            Err(d) => {
                self.count(d);
                if d == Discard::AuthFailed {
                    let mut last = self.last_auth_log.lock().unwrap();
                    if last
                        .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(1))
                    {
                        *last = Some(now);
                        debug!(peer = %src.ip(), "bfd reflector auth failed");
                    }
                }
                None
            }
        }
    }

    pub fn view(&self) -> ReflectorView {
        let n = |d| self.discarded[slot(d)].load(Ordering::Relaxed);
        let mut discriminators = self.policy.lock().unwrap().discriminators.clone();
        discriminators.sort_unstable();
        ReflectorView {
            discriminators,
            received: self.received.load(Ordering::Relaxed),
            replied: self.replied.load(Ordering::Relaxed),
            discarded: ReflectorDiscards {
                malformed: n(Discard::Malformed),
                source_port: n(Discard::SourcePort),
                martian: n(Discard::Martian),
                filtered: n(Discard::Filtered),
                rate_limited: n(Discard::RateLimited),
                authenticated: n(Discard::Authenticated),
                demand_clear: n(Discard::DemandClear),
                unknown_discriminator: n(Discard::UnknownDiscriminator),
                auth_failed: n(Discard::AuthFailed),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;
    use nos_proto::BfdState;

    fn probe(your: u32) -> Vec<u8> {
        Packet {
            diag: 0,
            state: BfdState::Down,
            poll: false,
            final_: false,
            control_plane_independent: true,
            demand: true,
            detect_mult: 3,
            my_discriminator: 5,
            your_discriminator: your,
            desired_min_tx: 300_000,
            required_min_rx: 0,
            required_min_echo_rx: 0,
            auth: None,
        }
        .encode()
        .to_vec()
    }

    fn src() -> SocketAddr {
        "10.0.0.1:50000".parse().unwrap()
    }

    fn dst() -> IpAddr {
        "10.0.0.2".parse().unwrap()
    }

    fn reflector() -> Reflector {
        let r = Reflector::default();
        r.set_policy(Policy {
            discriminators: vec![9, 3],
            allow_from: vec![],
            keys: vec![],
        });
        r
    }

    #[test]
    fn replies_to_a_known_discriminator_and_counts_each_discard() {
        let r = reflector();
        let now = Instant::now();
        let reply = r.handle(now, src(), dst(), &probe(9)).expect("reflected");
        let p = packet::decode(&reply).unwrap();
        assert_eq!((p.my_discriminator, p.your_discriminator), (9, 5));
        assert!(r.handle(now, src(), dst(), &probe(4)).is_none());
        assert!(r.handle(now, src(), dst(), &[1, 2, 3]).is_none());
        assert!(r
            .handle(now, "10.0.0.1:7784".parse().unwrap(), dst(), &probe(9))
            .is_none());
        assert!(r
            .handle(now, "127.0.0.1:5000".parse().unwrap(), dst(), &probe(9))
            .is_none());
        let v = r.view();
        assert_eq!(v.discriminators, [3, 9]);
        assert_eq!((v.received, v.replied), (5, 1));
        assert_eq!(
            (
                v.discarded.unknown_discriminator,
                v.discarded.malformed,
                v.discarded.source_port,
                v.discarded.martian
            ),
            (1, 1, 1, 1)
        );
    }

    #[test]
    fn the_rate_limit_drops_a_flood_and_recovers() {
        let r = reflector();
        let t0 = Instant::now();
        let burst = usize::try_from(BURST).unwrap();
        let answered = (0..burst + 500)
            .filter(|_| r.handle(t0, src(), dst(), &probe(9)).is_some())
            .count();
        assert!(answered <= burst + 1, "{answered}");
        assert!(r.view().discarded.rate_limited >= 400);
        // 10 ms later the bucket has paid for RATE_PPS / 100 more.
        let later = t0 + Duration::from_millis(10);
        assert!(r.handle(later, src(), dst(), &probe(9)).is_some());
    }

    #[test]
    fn enabled_follows_the_policy_and_config_maps_to_it() {
        let r = Reflector::default();
        assert!(!r.enabled());
        let mut cfg = Config::default();
        cfg.sbfd_reflector.discriminators = vec!["10.0.0.1".parse().unwrap()];
        cfg.sbfd_reflector.allow_from = vec!["10.0.0.0/8".parse().unwrap()];
        let p = policy_of(&cfg);
        assert_eq!(p.discriminators, [0x0a00_0001]);
        assert_eq!(p.allow_from.len(), 1);
        r.set_policy(p);
        assert!(r.enabled());
        r.set_policy(policy_of(&Config::default()));
        assert!(!r.enabled());
    }

    #[test]
    fn auth_failures_are_counted_and_keys_come_from_the_config() {
        use nos_proto::schema::{AdminKey, BfdAuth, BfdAuthMethod, SbfdReflectorKey};
        let mut cfg = Config::default();
        cfg.sbfd_reflector.discriminators = vec!["0.0.0.9".parse().unwrap()];
        cfg.sbfd_reflector.auth = vec![
            SbfdReflectorKey {
                key_id: 1,
                method: BfdAuthMethod::KeyedSha1,
                key: "k".into(),
            },
            SbfdReflectorKey {
                key_id: 2,
                method: BfdAuthMethod::KeyedSha1,
                key: "gone".into(),
            },
        ];
        cfg.admin.keys = vec![AdminKey {
            label: "k".into(),
            secret: "secretA".into(),
        }];
        let r = Reflector::default();
        r.set_policy(policy_of(&cfg));
        let k = |secret: &str, id| {
            AuthKey::new(
                &BfdAuth {
                    key_id: id,
                    method: BfdAuthMethod::KeyedSha1,
                    key: String::new(),
                },
                secret,
            )
        };
        let signed = |key: &AuthKey| crate::auth::sign(&probe(9), key, 7);
        let t = Instant::now();
        assert!(r
            .handle(t, src(), dst(), &signed(&k("secretA", 1)))
            .is_some());
        assert!(r.handle(t, src(), dst(), &signed(&k("wrong", 1))).is_none());
        assert!(r
            .handle(t, src(), dst(), &signed(&k("secretA", 2)))
            .is_none());
        let d = r.view().discarded;
        assert_eq!(
            (d.auth_failed, d.authenticated),
            (1, 1),
            "unresolved label is absent"
        );
    }
}
