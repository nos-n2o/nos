//! RADIUS accounting records (#1153): what is sent, and the bounded queue it
//! goes through. The sending worker lives in `broker.rs` (it needs the
//! config, the keystore and the VRF lookup).

use tokio::sync::mpsc;
use tracing::warn;

use nos_radius::attr;

/// Records waiting for the worker; more are dropped, never waited for.
pub const QUEUE: usize = 256;

/// Acct-Status-Type values (RFC 2866 §5.1).
const START: u32 = 1;
const STOP: u32 = 2;
const INTERIM: u32 = 3;
/// Acct-Terminate-Cause 5: Session-Timeout (the certificate lapsed or was revoked).
const SESSION_TIMEOUT: u32 = 5;

/// One accounting event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A login was accepted; `session` ties it to its `Stop`.
    Start { user: String, session: String },
    /// That login's session ended after `secs`.
    Stop {
        user: String,
        session: String,
        secs: u32,
    },
    /// A config commit by `actor`.
    Commit { actor: String, transaction: String },
}

/// A fresh Acct-Session-Id.
pub fn session_id() -> String {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("the OS random source is available");
    format!("{:016x}", u64::from_be_bytes(b))
}

/// The sending half of the queue.
pub type Sender = mpsc::Sender<Record>;

/// A queue of [`QUEUE`] records.
pub fn queue() -> (Sender, mpsc::Receiver<Record>) {
    mpsc::channel(QUEUE)
}

/// Queues `record` without waiting; a full queue (a slow or dead server) drops it.
pub fn offer(tx: &Sender, record: Record) {
    if tx.try_send(record).is_err() {
        warn!("radius accounting queue full or closed, dropping a record");
    }
}

/// The Accounting-Request attributes of `record`.
pub fn attrs(record: &Record) -> Vec<(u8, Vec<u8>)> {
    let text = |ty, s: &str| (ty, s.as_bytes().to_vec());
    let num = |ty, n: u32| (ty, n.to_be_bytes().to_vec());
    let mut out = vec![text(attr::NAS_IDENTIFIER, "nos")];
    match record {
        Record::Start { user, session } => out.extend([
            num(attr::ACCT_STATUS_TYPE, START),
            text(attr::USER_NAME, user),
            text(attr::ACCT_SESSION_ID, session),
        ]),
        Record::Stop {
            user,
            session,
            secs,
        } => out.extend([
            num(attr::ACCT_STATUS_TYPE, STOP),
            text(attr::USER_NAME, user),
            text(attr::ACCT_SESSION_ID, session),
            num(attr::ACCT_SESSION_TIME, *secs),
            num(attr::ACCT_TERMINATE_CAUSE, SESSION_TIMEOUT),
        ]),
        Record::Commit { actor, transaction } => out.extend([
            num(attr::ACCT_STATUS_TYPE, INTERIM),
            text(attr::USER_NAME, actor),
            text(attr::ACCT_SESSION_ID, &format!("commit:{transaction}")),
        ]),
    }
    out
}

/// The TACACS+ flags, user and AV pairs of `record`. A commit is a lone STOP
/// (RFC 8907 §7: one-shot events carry no matching START).
pub fn tacacs(record: &Record) -> (nos_tacacs::AcctFlags, &str, Vec<String>) {
    use nos_tacacs::AcctFlags;
    let base = |task: &str| vec!["service=nos".to_string(), format!("task_id={task}")];
    match record {
        Record::Start { user, session } => (AcctFlags::Start, user, base(session)),
        Record::Stop {
            user,
            session,
            secs,
        } => {
            let mut a = base(session);
            a.push(format!("elapsed_time={secs}"));
            (AcctFlags::Stop, user, a)
        }
        Record::Commit { actor, transaction } => {
            let mut a = base(&format!("commit:{transaction}"));
            a.push("cmd=commit".to_string());
            (AcctFlags::Stop, actor, a)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(a: &[(u8, Vec<u8>)], ty: u8) -> Option<&[u8]> {
        a.iter().find(|(t, _)| *t == ty).map(|(_, v)| &v[..])
    }

    #[test]
    fn records_carry_their_status_and_identity() {
        let start = attrs(&Record::Start {
            user: "u".into(),
            session: "s1".into(),
        });
        assert_eq!(get(&start, attr::ACCT_STATUS_TYPE), Some(&[0, 0, 0, 1][..]));
        assert_eq!(get(&start, attr::USER_NAME), Some(&b"u"[..]));
        let stop = attrs(&Record::Stop {
            user: "u".into(),
            session: "s1".into(),
            secs: 7,
        });
        assert_eq!(get(&stop, attr::ACCT_STATUS_TYPE), Some(&[0, 0, 0, 2][..]));
        assert_eq!(get(&stop, attr::ACCT_SESSION_TIME), Some(&[0, 0, 0, 7][..]));
        let commit = attrs(&Record::Commit {
            actor: "a".into(),
            transaction: "t".into(),
        });
        assert_eq!(
            get(&commit, attr::ACCT_STATUS_TYPE),
            Some(&[0, 0, 0, 3][..])
        );
        assert_eq!(get(&commit, attr::ACCT_SESSION_ID), Some(&b"commit:t"[..]));
    }

    #[test]
    fn tacacs_records_carry_flags_and_task() {
        use nos_tacacs::AcctFlags;
        let rec = Record::Start {
            user: "u".into(),
            session: "s1".into(),
        };
        let (f, u, a) = tacacs(&rec);
        assert_eq!((f, u), (AcctFlags::Start, "u"));
        assert!(a.contains(&"task_id=s1".to_string()));
        let rec = Record::Stop {
            user: "u".into(),
            session: "s1".into(),
            secs: 7,
        };
        let (f, _, a) = tacacs(&rec);
        assert_eq!(f, AcctFlags::Stop);
        assert!(a.contains(&"elapsed_time=7".to_string()));
        let rec = Record::Commit {
            actor: "a".into(),
            transaction: "t".into(),
        };
        let (f, u, a) = tacacs(&rec);
        assert_eq!((f, u), (AcctFlags::Stop, "a"));
        assert!(a.contains(&"task_id=commit:t".to_string()));
    }

    #[test]
    fn a_full_queue_drops_instead_of_waiting() {
        let (tx, mut rx) = mpsc::channel(1);
        let r = Record::Commit {
            actor: "a".into(),
            transaction: "t".into(),
        };
        offer(&tx, r.clone());
        offer(&tx, r.clone());
        assert_eq!(rx.try_recv().unwrap(), r);
        assert!(rx.try_recv().is_err());
        assert_ne!(session_id(), session_id());
    }
}
