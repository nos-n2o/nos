//! Who may send which `Request`. mTLS proves *who* is calling; this decides
//! what they may do. Reading the config is open to every authenticated
//! daemon (they all subscribe to it); everything that edits or persists it
//! is for people — a `User`, or `Restd` acting on one's behalf.

use nos_proto::{Request, Role};

/// Deliberately no wildcard arm: a new `Request` variant must not compile
/// until someone decides who may send it.
pub fn allowed(role: Role, req: &Request) -> bool {
    match req {
        Request::Get
        | Request::Subscribe
        | Request::Unsubscribe
        | Request::SubscribeDiff { .. }
        | Request::Describe { .. } => true,
        Request::UpgradePasswordHash { .. } => role == Role::Watchdog,
        Request::SetSshHostKey { .. } => role == Role::Sshd,
        Request::UserExists { .. }
        | Request::ListBgpInstances
        | Request::ListOspfInstances
        | Request::ListOspfv3Instances
        | Request::GetRestApi { .. } => role == Role::Restd,
        Request::Save
        | Request::OpenTransaction { .. }
        | Request::ApplyOp { .. }
        | Request::GetTransaction { .. }
        | Request::CommitTransaction { .. }
        | Request::DiscardTransaction { .. }
        | Request::DiffTransaction { .. }
        | Request::SetTransactionPath { .. }
        | Request::EditTransactionPath { .. } => matches!(role, Role::User | Role::Restd),
    }
}

#[cfg(test)]
mod tests {
    use nos_proto::TransactionBase;

    use super::*;

    fn open() -> Request {
        Request::OpenTransaction {
            name: "t".into(),
            base: TransactionBase::Blank,
            actor: None,
        }
    }

    #[test]
    fn every_role_may_read_but_only_people_may_edit() {
        for role in Role::ALL {
            assert!(allowed(role, &Request::Get), "{role:?} must read");
            assert!(
                allowed(role, &Request::Subscribe),
                "{role:?} must subscribe"
            );
            let may_edit = matches!(role, Role::User | Role::Restd);
            assert_eq!(allowed(role, &open()), may_edit, "{role:?} editing");
            assert_eq!(allowed(role, &Request::Save), may_edit, "{role:?} saving");
            let edit = Request::EditTransactionPath {
                name: "t".into(),
                path: vec![],
                value: None,
                if_match: None,
                position: None,
            };
            assert_eq!(allowed(role, &edit), may_edit, "{role:?} path edit");
            let upgrade = Request::UpgradePasswordHash {
                user: "u".into(),
                old: "a".into(),
                new: "b".into(),
            };
            assert_eq!(allowed(role, &upgrade), role == Role::Watchdog, "{role:?}");
            let ssh = Request::SetSshHostKey { seed: "s".into() };
            assert_eq!(allowed(role, &ssh), role == Role::Sshd, "{role:?} ssh key");
            let probe = Request::UserExists { name: "u".into() };
            assert_eq!(allowed(role, &probe), role == Role::Restd, "{role:?} probe");
            for r in [
                Request::ListBgpInstances,
                Request::ListOspfInstances,
                Request::ListOspfv3Instances,
                Request::GetRestApi { table: "t".into() },
            ] {
                assert_eq!(allowed(role, &r), role == Role::Restd, "{role:?} {r:?}");
            }
        }
    }
}
