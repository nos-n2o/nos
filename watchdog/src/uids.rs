//! One Unix uid per daemon role (#513): a compromised daemon cannot `kill`,
//! `ptrace` or read `/var/lib/nos/<other role>` of another. The numbers are
//! fixed and must match the `useradd` lines in the `Dockerfile` (a test checks).

use std::os::unix::fs::{chown, PermissionsExt};
use std::path::Path;

use anyhow::Context;
use nos_proto::broker::Role;

/// `Some(uid)` for the fifteen roles `nos-watchdogd` spawns (`Sshd` is uid 0), `None` for
/// `Watchdog` (its own uid, `nos-wd`) and `User` (a person, never a process).
/// Exhaustive on purpose: a new `Role` fails to compile until it gets a uid.
/// 10001+ in `Role` declaration order; new roles append, never renumber.
pub const fn role_uid(role: Role) -> Option<u32> {
    match role {
        Role::Watchdog | Role::User => None,
        Role::Configd => Some(10001),
        Role::Logd => Some(10002),
        Role::Bgpd => Some(10003),
        Role::Ribd => Some(10004),
        Role::Ospfd => Some(10005),
        Role::Ospfv3d => Some(10006),
        Role::Interfaced => Some(10007),
        Role::Lacpd => Some(10008),
        Role::Lldpd => Some(10009),
        Role::Fdbd => Some(10010),
        Role::Restd => Some(10011),
        Role::Bfdd => Some(10012),
        Role::Stpd => Some(10013),
        Role::Acld => Some(10014),
        Role::Radvd => Some(10015),
        // Root on purpose (#994): `nos-sshd` hands each connection to `sshd`, which
        // needs uid 0 to authenticate and setuid; it drops its capability set itself.
        Role::Sshd => Some(0),
    }
}

/// Creates (idempotently) `<base>/<role>` for every daemon role, `0700`
/// `nos-<role>:<gid>`; `base` itself becomes `0755` owned by `owner` (the
/// watchdog) so this works on a volume an older image left `nos:nos`.
/// Needs `CAP_CHOWN` (the image's file cap on `nos-watchdogd`).
pub fn ensure_state_dirs(base: &Path, owner: (u32, u32), gid: u32) -> anyhow::Result<()> {
    std::fs::create_dir_all(base).with_context(|| format!("creating {}", base.display()))?;
    chown(base, Some(owner.0), Some(owner.1))
        .with_context(|| format!("chown {}", base.display()))?;
    std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o755))?;
    for (role, uid) in Role::ALL
        .into_iter()
        .filter_map(|r| role_uid(r).map(|u| (r, u)))
    {
        let dir = base.join(role.as_str());
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        // Ours for the chmod (a directory left by a previous run, or created
        // by a root-run harness, belongs to someone else), theirs at the end.
        chown(&dir, Some(owner.0), Some(owner.1))
            .with_context(|| format!("chown {}", dir.display()))?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        chown(&dir, Some(uid), Some(gid)).with_context(|| format!("chown {}", dir.display()))?;
    }
    Ok(())
}

/// The directory `nos-configd` writes the NSS passwd file into (#999): `0755`, owned by
/// the configd role so it can write and everyone (sshd, `getent`) can read. The watchdog
/// never writes the file. Needs `CAP_CHOWN`.
pub fn ensure_users_dir(dir: &Path, owner: (u32, u32), gid: u32) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    chown(dir, Some(owner.0), Some(owner.1)).with_context(|| format!("chown {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    let configd = role_uid(Role::Configd).expect("configd has a uid");
    chown(dir, Some(configd), Some(gid)).with_context(|| format!("chown {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn table_covers_every_daemon_role_uniquely() {
        let uids: Vec<_> = Role::ALL.into_iter().filter_map(role_uid).collect();
        assert_eq!(uids.len(), 16);
        assert_eq!(uids.iter().collect::<HashSet<_>>().len(), 16);
        assert!(uids.iter().all(|u| *u >= 10_000 || *u == 0));
        assert_eq!(role_uid(Role::Sshd), Some(0));
        assert_eq!(
            (role_uid(Role::Watchdog), role_uid(Role::User)),
            (None, None)
        );
    }

    /// The image creates the same users: a drifted number would run a daemon
    /// as a uid with no passwd entry (or someone else's).
    #[test]
    fn dockerfile_useradd_lines_match_the_table() {
        let df = include_str!("../../Dockerfile");
        for r in Role::ALL {
            let Some(uid) = role_uid(r).filter(|u| *u != 0) else {
                continue; // root exists already
            };
            let want = format!(
                "--uid {uid} --gid nos --no-create-home --home-dir /nonexistent nos-{}",
                r.as_str()
            );
            assert!(df.contains(&want), "Dockerfile lacks: {want}");
        }
    }

    /// Unprivileged, chown to another uid is refused (the error names the
    /// dir); as root the whole layout is checked, twice (idempotent).
    #[test]
    fn state_dirs_are_private_and_idempotent() {
        let t = tempfile::tempdir().unwrap();
        let me = std::fs::metadata(t.path()).unwrap();
        let base = t.path().join("nos");
        let r = ensure_state_dirs(&base, (me.uid(), me.gid()), me.gid());
        if me.uid() == 0 {
            r.unwrap();
            ensure_state_dirs(&base, (me.uid(), me.gid()), me.gid()).unwrap();
            let m = std::fs::metadata(base.join("configd")).unwrap();
            assert_eq!((m.mode() & 0o7777, m.uid()), (0o700, 10001));
            assert_eq!(std::fs::metadata(&base).unwrap().mode() & 0o7777, 0o755);
        } else {
            let e = format!("{:#}", r.unwrap_err());
            assert!(e.contains("configd"), "{e}");
        }
    }

    #[test]
    fn users_dir_belongs_to_configd() {
        let t = tempfile::tempdir().unwrap();
        let me = std::fs::metadata(t.path()).unwrap();
        let dir = t.path().join("nos-users");
        let r = ensure_users_dir(&dir, (me.uid(), me.gid()), me.gid());
        if me.uid() == 0 {
            r.unwrap();
            ensure_users_dir(&dir, (me.uid(), me.gid()), me.gid()).unwrap();
            let m = std::fs::metadata(&dir).unwrap();
            assert_eq!((m.mode() & 0o7777, m.uid()), (0o755, 10001));
        } else {
            assert!(format!("{:#}", r.unwrap_err()).contains("nos-users"));
        }
    }
}
