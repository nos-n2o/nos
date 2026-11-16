//! Who may send which `Request`. mTLS proves *who* is calling; this decides
//! what they may do. Reading the config is open to every authenticated
//! daemon (they all subscribe to it); everything that edits or persists it
//! is for people — a `User`, or `Restd` acting on one's behalf.

use nos_proto::{ConfigOp, Request, Role, UserOp, UserRole};

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
        Request::Save { .. }
        | Request::SaveStatus
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

/// What a *person* may do, by `User.role` (#1147; RFC 8341 NACM style):
/// `allowed` has already let the request through for its IPC role. `actor` is
/// the user the request acts for. Deliberately no wildcard arm either.
///
/// `Operator` and `ReadOnly` are the same here: `nos-configd` has no
/// operational requests yet (they live in the other daemons), so both read and
/// may change only their own password — `Open`/`Apply`/`Set`/`Edit` are only
/// let through for that edit, and `Commit` additionally checks the diff
/// (`ConfigStore::commit_transaction_as`).
pub fn permitted(user_role: UserRole, actor: &str, req: &Request) -> bool {
    if user_role == UserRole::Admin {
        return true;
    }
    match req {
        Request::Get
        | Request::Subscribe
        | Request::Unsubscribe
        | Request::SubscribeDiff { .. }
        | Request::Describe { .. }
        | Request::SaveStatus
        | Request::OpenTransaction { .. }
        | Request::GetTransaction { .. }
        | Request::DiffTransaction { .. }
        | Request::DiscardTransaction { .. }
        | Request::CommitTransaction { .. }
        | Request::UserExists { .. }
        | Request::ListBgpInstances
        | Request::ListOspfInstances
        | Request::ListOspfv3Instances
        | Request::GetRestApi { .. }
        | Request::UpgradePasswordHash { .. }
        | Request::SetSshHostKey { .. } => true,
        Request::Save { .. } => false,
        Request::ApplyOp { op, .. } => {
            matches!(op, ConfigOp::User(UserOp::SetPassword { name, .. }) if name == actor)
        }
        Request::SetTransactionPath { path, .. } | Request::EditTransactionPath { path, .. } => {
            own_password_path(path, actor)
        }
    }
}

/// `users/<actor>/password`, spelled exactly (an exact key always wins over a
/// fuzzy match, so no other user can be selected by it).
fn own_password_path(path: &[String], actor: &str) -> bool {
    matches!(path, [f, k, p] if (f == "users" || f == "user") && k == actor && p == "password")
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
            assert_eq!(
                allowed(role, &Request::Save { actor: None }),
                may_edit,
                "{role:?} saving"
            );
            let edit = Request::EditTransactionPath {
                name: "t".into(),
                path: vec![],
                value: None,
                if_match: None,
                position: None,
                actor: None,
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

    fn edit(path: &[&str]) -> Request {
        Request::EditTransactionPath {
            name: "t".into(),
            path: path.iter().map(|s| (*s).to_string()).collect(),
            value: Some("x".into()),
            if_match: None,
            position: None,
            actor: None,
        }
    }

    #[test]
    fn admin_may_do_everything_others_read_and_change_their_own_password() {
        let save = Request::Save { actor: None };
        let own = edit(&["users", "bob", "password"]);
        let others = edit(&["users", "alice", "password"]);
        let role = edit(&["users", "bob", "role"]);
        let own_op = Request::ApplyOp {
            name: "t".into(),
            op: ConfigOp::User(UserOp::SetPassword {
                name: "bob".into(),
                password: "p".into(),
            }),
            actor: None,
        };
        let other_op = Request::ApplyOp {
            name: "t".into(),
            op: ConfigOp::User(UserOp::Delete {
                name: "alice".into(),
            }),
            actor: None,
        };
        for r in [&save, &others, &role, &other_op] {
            assert!(permitted(UserRole::Admin, "bob", r), "{r:?}");
            for ur in [UserRole::Operator, UserRole::ReadOnly] {
                assert!(!permitted(ur, "bob", r), "{ur:?} {r:?}");
            }
        }
        for ur in [UserRole::Operator, UserRole::ReadOnly] {
            assert!(permitted(ur, "bob", &own), "{ur:?}");
            assert!(permitted(ur, "bob", &own_op), "{ur:?}");
            for r in [
                Request::Get,
                Request::Subscribe,
                open(),
                Request::SaveStatus,
            ] {
                assert!(permitted(ur, "bob", &r), "{ur:?} {r:?}");
            }
        }
    }
}
