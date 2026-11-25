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
        Request::AccountCommand { .. } => matches!(role, Role::User | Role::Restd),
        // `AllocateExternalUser` is the AAA accept path (#1374): only the broker, never a
        // person or another daemon.
        Request::UpgradePasswordHash { .. } | Request::AllocateExternalUser { .. } => {
            role == Role::Watchdog
        }
        // The broker also reads the list, to refuse a ticket of a cleared name (#1376).
        Request::ListExternalUsers => matches!(role, Role::User | Role::Restd | Role::Watchdog),
        Request::SetSshHostKey { .. } => role == Role::Sshd,
        Request::AdminAllocateExternalUser { .. } | Request::ClearExternalUser { .. } => {
            matches!(role, Role::User | Role::Restd)
        }
        Request::UserExists { .. }
        | Request::ListBgpInstances
        | Request::ListOspfInstances
        | Request::ListOspfv3Instances
        | Request::GetRestApi { .. } => role == Role::Restd,
        Request::Save { .. }
        | Request::SaveStatus
        | Request::ListHistory
        | Request::GetHistoryConfig { .. }
        | Request::Rollback { .. }
        | Request::ConfirmCommit { .. }
        | Request::CancelCommit { .. }
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
        | Request::ListHistory
        | Request::GetHistoryConfig { .. }
        | Request::OpenTransaction { .. }
        | Request::GetTransaction { .. }
        | Request::DiffTransaction { .. }
        | Request::DiscardTransaction { .. }
        | Request::UserExists { .. }
        | Request::ListBgpInstances
        | Request::ListOspfInstances
        | Request::ListOspfv3Instances
        | Request::GetRestApi { .. }
        | Request::UpgradePasswordHash { .. }
        | Request::SetSshHostKey { .. }
        | Request::AccountCommand { .. }
        | Request::AllocateExternalUser { .. } => true,
        // A non-admin may commit, but not arm a rollback timer.
        Request::CommitTransaction {
            confirm_timeout, ..
        } => confirm_timeout.is_none(),
        // Account management (#1374) is admin only, like saving and rolling back.
        Request::Save { .. }
        | Request::Rollback { .. }
        | Request::ConfirmCommit { .. }
        | Request::CancelCommit { .. }
        | Request::AdminAllocateExternalUser { .. }
        | Request::ClearExternalUser { .. }
        | Request::ListExternalUsers => false,
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
            assert_eq!(
                allowed(role, &Request::ListHistory),
                may_edit,
                "{role:?} history"
            );
            assert_eq!(
                allowed(role, &Request::GetHistoryConfig { index: 1 }),
                may_edit,
                "{role:?} history config"
            );
            let back = Request::Rollback {
                index: 1,
                actor: None,
            };
            assert_eq!(allowed(role, &back), may_edit, "{role:?} rollback");
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

    /// #1141: a non-admin may list the history but not roll back.
    #[test]
    fn rollback_is_admin_only_and_history_is_readable() {
        let back = Request::Rollback {
            index: 1,
            actor: None,
        };
        for r in [UserRole::Operator, UserRole::ReadOnly] {
            assert!(permitted(r, "u", &Request::ListHistory));
            assert!(permitted(r, "u", &Request::GetHistoryConfig { index: 1 }));
            assert!(!permitted(r, "u", &back));
        }
        assert!(permitted(UserRole::Admin, "u", &back));
    }

    /// #1374: only the watchdog may allocate from an AAA accept; people manage, admin only.
    #[test]
    fn command_accounting_is_for_people_and_any_user_role() {
        let r = Request::AccountCommand {
            command: "show version".into(),
            actor: None,
        };
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &r),
                matches!(role, Role::User | Role::Restd),
                "{role:?}"
            );
        }
        assert!(permitted(UserRole::ReadOnly, "bob", &r));
    }

    #[test]
    fn external_user_requests_are_classified() {
        let name = || "u".to_string();
        let accept = Request::AllocateExternalUser { name: name() };
        let people = [
            Request::AdminAllocateExternalUser { name: name() },
            Request::ClearExternalUser { name: name() },
        ];
        let list = Request::ListExternalUsers;
        for role in Role::ALL {
            let may = matches!(role, Role::User | Role::Restd | Role::Watchdog);
            assert_eq!(allowed(role, &list), may, "{role:?}");
            assert_eq!(allowed(role, &accept), role == Role::Watchdog, "{role:?}");
            for r in &people {
                let may = matches!(role, Role::User | Role::Restd);
                assert_eq!(allowed(role, r), may, "{role:?} {r:?}");
            }
        }
        for r in people.iter().chain([&list]) {
            assert!(permitted(UserRole::Admin, "a", r));
            for ur in [UserRole::Operator, UserRole::ReadOnly] {
                assert!(!permitted(ur, "a", r), "{ur:?} {r:?}");
            }
        }
    }

    /// #1144: only an admin may arm, confirm or cancel a confirmed commit.
    #[test]
    fn confirmed_commit_is_admin_only() {
        let commit = |t| Request::CommitTransaction {
            name: "t".into(),
            if_match: None,
            actor: None,
            confirm_timeout: t,
        };
        let confirm = Request::ConfirmCommit { actor: None };
        let cancel = Request::CancelCommit { actor: None };
        for r in [UserRole::Operator, UserRole::ReadOnly] {
            assert!(permitted(r, "u", &commit(None)));
            assert!(!permitted(r, "u", &commit(Some(60))));
            assert!(!permitted(r, "u", &confirm));
            assert!(!permitted(r, "u", &cancel));
        }
        assert!(permitted(UserRole::Admin, "u", &commit(Some(60))));
        assert!(permitted(UserRole::Admin, "u", &confirm));
        for role in Role::ALL {
            let may = matches!(role, Role::User | Role::Restd);
            assert_eq!(allowed(role, &confirm), may);
            assert_eq!(allowed(role, &cancel), may);
        }
    }
}
