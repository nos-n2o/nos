//! The account mapping behind `libnss_nos` (#999, docs/architecture/pam.md): every
//! `Config.users` name gets a stable uid in 20000..=59999 and one `name:uid:gid:dir:shell`
//! line in `/run/nos-users/passwd`, so sshd (`UsePAM`, which needs a passwd entry) can
//! resolve a NOS user. Names only, never a password or hash: a hash cannot leak by
//! construction. Login itself is decided by `nos-watchdogd` against the config.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use nos_proto::User;
use tracing::{error, warn};

pub const UID_MIN: u32 = 20_000;
pub const UID_MAX: u32 = 59_999;
pub const DEFAULT_PASSWD_FILE: &str = "/run/nos-users/passwd";
pub const DEFAULT_IDS_FILE: &str = "/var/lib/nos/configd/user-ids";
const SHELL: &str = "/usr/bin/nos";
const HOME: &str = "/nonexistent";

/// `^[a-z_][a-z0-9_-]{0,31}$`: what a passwd name may be (no `:`, newline, empty, >32).
/// Wider PRECIS names are legal in the config and simply get no ssh account.
pub fn safe_name(n: &str) -> bool {
    let mut c = n.chars();
    n.len() <= 32
        && c.next().is_some_and(|f| f.is_ascii_lowercase() || f == '_')
        && c.all(|f| f.is_ascii_lowercase() || f.is_ascii_digit() || f == '_' || f == '-')
}

/// `name -> uid`, persisted as `name:uid` lines. Monotone: a uid is never handed to
/// another name, and an entry survives its user's deletion (re-creating a user gets the
/// same uid back).
// ponytail: entries are never pruned; every distinct safe name ever created costs a line
// and a uid, 40000 of them at most. Prune only with a recycling policy if that ever bites.
#[derive(Debug)]
pub struct UidMap {
    path: PathBuf,
    uids: BTreeMap<String, u32>,
    min: u32,
    max: u32,
}

impl UidMap {
    /// A missing file is a fresh start; an unreadable, unparsable or out-of-range one is
    /// an error (regenerating it would reuse uids).
    pub fn load(path: &Path, min: u32, max: u32) -> Result<Self, String> {
        let mut uids = BTreeMap::new();
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let mut seen = BTreeSet::new();
                for l in text.lines().filter(|l| !l.is_empty()) {
                    let (name, uid) = l
                        .split_once(':')
                        .and_then(|(n, u)| Some((n, u.parse::<u32>().ok()?)))
                        .ok_or_else(|| format!("malformed line {l:?}"))?;
                    if !safe_name(name)
                        || !(min..=max).contains(&uid)
                        || !seen.insert(uid)
                        || uids.insert(name.to_string(), uid).is_some()
                    {
                        return Err(format!("invalid entry {l:?}"));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        Ok(Self {
            path: path.to_path_buf(),
            uids,
            min,
            max,
        })
    }

    /// The existing uid, else the next one above every uid ever allocated; `None` when
    /// the range is exhausted. Returns whether the map changed.
    fn allocate(&mut self, name: &str) -> (Option<u32>, bool) {
        if let Some(u) = self.uids.get(name) {
            return (Some(*u), false);
        }
        let next = self
            .uids
            .values()
            .max()
            .map_or(self.min, |m| m.saturating_add(1));
        if next > self.max {
            return (None, false);
        }
        self.uids.insert(name.to_string(), next);
        (Some(next), true)
    }

    fn persist(&self) -> std::io::Result<()> {
        let text = self
            .uids
            .iter()
            .map(|(n, u)| {
                format!(
                    "{n}:{u}
"
                )
            })
            .collect::<Vec<_>>()
            .concat();
        write_atomic(&self.path, &text, 0o600)
    }
}

/// `name:uid:gid:dir:shell` lines sorted by uid; gid = uid. Unsafe names are skipped with
/// a warning, an exhausted range likewise. Returns the text and whether `map` grew.
pub fn render(users: &[User], map: &mut UidMap) -> (String, bool) {
    let mut rows = Vec::new();
    let mut grew = false;
    for u in users {
        if !safe_name(&u.name) {
            warn!(user = ?u.name, "no ssh account: name is not a valid unix user name");
            continue;
        }
        if let (Some(uid), g) = map.allocate(&u.name) {
            grew |= g;
            rows.push((uid, u.name.as_str()));
        } else {
            error!(user = %u.name, "no ssh account: the uid range is exhausted");
        }
    }
    rows.sort_unstable();
    let text = rows
        .iter()
        .map(|(uid, n)| format!("{n}:{uid}:{uid}:{HOME}:{SHELL}\n"))
        .collect::<Vec<_>>()
        .concat();
    (text, grew)
}

fn write_atomic(path: &Path, contents: &str, mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("nss")
    ));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Where `ConfigStore` mirrors its users.
pub struct UserDb {
    passwd: PathBuf,
    map: Mutex<UidMap>,
}

impl UserDb {
    /// `None` (after an `error!`) when the uid map is unusable: `passwd` is then left alone.
    pub fn open(passwd: PathBuf, ids_file: &Path) -> Option<Self> {
        Self::open_range(passwd, ids_file, UID_MIN, UID_MAX)
    }

    fn open_range(passwd: PathBuf, ids_file: &Path, min: u32, max: u32) -> Option<Self> {
        match UidMap::load(ids_file, min, max) {
            Ok(m) => Some(Self {
                passwd,
                map: Mutex::new(m),
            }),
            Err(e) => {
                error!(file = %ids_file.display(), error = %e, "uid map unusable, not writing the nss passwd file");
                None
            }
        }
    }

    /// Persists any new uid first, then the passwd file, so a crash never exposes an
    /// unpersisted uid. Failures are logged, never returned: a stale entry is harmless.
    pub fn sync(&self, users: &[User]) {
        let mut map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (text, grew) = render(users, &mut map);
        if grew && let Err(e) = map.persist() {
            error!(error = %e, "persisting the uid map failed, nss passwd file not updated");
            return;
        }
        if let Err(e) = write_atomic(&self.passwd, &text, 0o644) {
            warn!(file = %self.passwd.display(), error = %e, "writing the nss passwd file failed");
        }
    }
}

/// Whether two user lists differ in their set of names (a password change does not).
pub fn names_differ(a: &[User], b: &[User]) -> bool {
    let set = |u: &[User]| u.iter().map(|u| u.name.clone()).collect::<BTreeSet<_>>();
    set(a) != set(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(n: &str) -> User {
        User {
            name: n.into(),
            password: "$argon2id$v=19$secret".into(),
        }
    }

    fn users(n: &[&str]) -> Vec<User> {
        n.iter().map(|n| user(n)).collect()
    }

    fn db(dir: &Path, min: u32, max: u32) -> UserDb {
        UserDb::open_range(dir.join("passwd"), &dir.join("ids"), min, max).unwrap()
    }

    fn passwd(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("passwd")).unwrap()
    }

    #[test]
    fn uid_is_stable_across_reload_deletion_and_recreation() {
        let t = tempfile::tempdir().unwrap();
        db(t.path(), UID_MIN, UID_MAX).sync(&users(&["alice", "bob"]));
        assert_eq!(
            passwd(t.path()),
            "alice:20000:20000:/nonexistent:/usr/bin/nos\nbob:20001:20001:/nonexistent:/usr/bin/nos\n"
        );
        // reload (restart), alice deleted, carol added: carol never takes alice's uid
        let d = db(t.path(), UID_MIN, UID_MAX);
        d.sync(&users(&["bob", "carol"]));
        assert_eq!(
            passwd(t.path()),
            "bob:20001:20001:/nonexistent:/usr/bin/nos\ncarol:20002:20002:/nonexistent:/usr/bin/nos\n"
        );
        d.sync(&users(&["alice", "bob"]));
        assert!(passwd(t.path()).starts_with("alice:20000:20000:"));
        let ids = std::fs::read_to_string(t.path().join("ids")).unwrap();
        assert_eq!(ids, "alice:20000\nbob:20001\ncarol:20002\n");
    }

    #[test]
    fn range_exhaustion_drops_only_the_overflowing_user() {
        let t = tempfile::tempdir().unwrap();
        db(t.path(), 100, 101).sync(&users(&["a", "b", "c"]));
        assert_eq!(
            passwd(t.path()),
            "a:100:100:/nonexistent:/usr/bin/nos\nb:101:101:/nonexistent:/usr/bin/nos\n"
        );
    }

    #[test]
    fn a_corrupt_or_out_of_range_map_refuses_to_write() {
        let t = tempfile::tempdir().unwrap();
        let ids = t.path().join("ids");
        for bad in [
            "garbage\n",
            "alice:5\n",
            "alice:20000\nbob:20000\n",
            "A:20000\n",
            "a:20000\na:20001\n",
        ] {
            std::fs::write(&ids, bad).unwrap();
            assert!(
                UserDb::open(t.path().join("passwd"), &ids).is_none(),
                "{bad}"
            );
        }
        assert!(!t.path().join("passwd").exists());
    }

    #[test]
    fn unsafe_names_get_no_entry() {
        for n in [
            "a:b",
            "Alice",
            "café",
            "",
            &"a".repeat(33),
            "a\nb",
            "1a",
            "-a",
        ] {
            assert!(!safe_name(n), "{n:?}");
        }
        for n in ["alice", "_x", "a-b_9", &"a".repeat(32)] {
            assert!(safe_name(n), "{n:?}");
        }
        let t = tempfile::tempdir().unwrap();
        db(t.path(), UID_MIN, UID_MAX).sync(&users(&["a:b", "Alice", "ok"]));
        assert_eq!(
            passwd(t.path()),
            "ok:20000:20000:/nonexistent:/usr/bin/nos\n"
        );
    }

    #[test]
    fn no_hash_in_the_output() {
        let t = tempfile::tempdir().unwrap();
        db(t.path(), UID_MIN, UID_MAX).sync(&users(&["alice"]));
        assert!(!passwd(t.path()).contains("argon2"));
    }

    /// Every fixed uid the image creates sits below the NSS range.
    #[test]
    fn dockerfile_uids_are_below_the_range() {
        let df = include_str!("../../Dockerfile");
        let uids: Vec<u32> = df
            .split("--uid ")
            .skip(1)
            .filter_map(|r| r.split_whitespace().next()?.parse().ok())
            .collect();
        assert!(uids.len() > 10);
        assert!(uids.iter().all(|u| *u < UID_MIN), "{uids:?}");
    }

    #[test]
    fn only_a_name_change_counts() {
        let a = users(&["alice", "bob"]);
        let mut b = users(&["bob", "alice"]);
        b[0].password = "$argon2id$other".into();
        assert!(!names_differ(&a, &b));
        assert!(names_differ(&a, &users(&["alice"])));
    }
}
