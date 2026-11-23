//! The account mapping behind `libnss_nos` (#999, docs/architecture/pam.md): every
//! `Config.users` name, and every external (AAA-authenticated, #1374) name, gets a stable
//! uid in 20000..=59999 and one `name:uid:gid:dir:shell` line in `/run/nos-users/passwd`, so
//! sshd (`UsePAM`, which needs a passwd entry) can resolve a NOS user. Names only, never a
//! password or hash: a hash cannot leak by construction. Login itself is decided by
//! `nos-watchdogd` (the config, or the AAA server).
//!
//! One uid map serves both kinds, so a uid is never shared by two names. Nothing here
//! trusts the names or ids already on the box: `/etc/passwd` and `/etc/group` are parsed as
//! files (never through NSS) and a clash is refused or skipped, never merged.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub use nos_proto::safe_name;
use nos_proto::User;
use thiserror::Error;
use tracing::{error, info, warn};

pub const UID_MIN: u32 = 20_000;
pub const UID_MAX: u32 = 59_999;
pub const DEFAULT_PASSWD_FILE: &str = "/run/nos-users/passwd";
pub const DEFAULT_IDS_FILE: &str = "/var/lib/nos/configd/user-ids";
/// Next to the ids file: the external names (one per line), 0600.
const AAA_USERS_FILE: &str = "aaa-users";
const ETC_PASSWD: &str = "/etc/passwd";
const ETC_GROUP: &str = "/etc/group";
/// At most this many external names, of the 40000 ids; local users keep at least 30000.
pub const EXTERNAL_CAP: usize = 10_000;
/// The service-account prefix (`nos-wd`, `nos-configd`, ...): never an external name.
const RESERVED_PREFIX: &str = "nos-";
const SHELL: &str = "/usr/bin/nos";
const HOME: &str = "/nonexistent";

/// Why an external user was not allocated or cleared. Texts are returned to the caller
/// (the watchdog, or an admin), so they carry no more than the cause.
#[derive(Debug, Error)]
pub enum ExternalUserError {
    #[error("not a valid unix user name")]
    Unsafe,
    #[error("reserved name")]
    Reserved,
    #[error("a local user has that name")]
    LocalUser,
    #[error("the name or id exists in /etc/passwd or /etc/group")]
    SystemClash,
    #[error("too many external users")]
    Full,
    #[error("the uid range is exhausted")]
    Exhausted,
    #[error("no such external user")]
    NotFound,
    #[error("account database unavailable")]
    Unavailable,
    #[error("storing the account failed: {0}")]
    Io(String),
}

/// Names and numeric ids found in `/etc/passwd` and `/etc/group`, parsed as files.
#[derive(Debug, Default)]
pub struct Taken {
    names: BTreeSet<String>,
    ids: BTreeSet<u32>,
}

impl Taken {
    /// A missing file is empty; any other read error is an error (fail closed).
    pub fn load(passwd: &Path, group: &Path) -> std::io::Result<Self> {
        let mut t = Self::default();
        for (path, is_passwd) in [(passwd, true), (group, false)] {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for l in text.lines() {
                let f: Vec<&str> = l.split(':').collect();
                if f.len() < 3 || l.starts_with('#') {
                    continue;
                }
                if is_passwd {
                    t.names.insert(f[0].to_string());
                    // field 3 is the primary gid
                    t.ids.extend(f.get(3).and_then(|g| g.parse::<u32>().ok()));
                }
                t.ids.extend(f[2].parse::<u32>().ok());
            }
        }
        Ok(t)
    }
}

/// `name -> uid`, persisted as `name:uid` lines. Monotone: a uid is never handed to
/// another name, and an entry survives its user's deletion (re-creating a user gets the
/// same uid back).
// ponytail: entries are never pruned; every distinct safe name ever created costs a line
// and a uid, 40000 of them at most. Prune only with a recycling policy if that ever bites.
#[derive(Clone, Debug)]
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

    /// The existing uid, else the next one above every uid ever allocated that is not an
    /// id on the box (a clashing one is skipped, never handed out); `None` when the range
    /// is exhausted. Returns whether the map changed.
    fn allocate(&mut self, name: &str, taken: &Taken) -> (Option<u32>, bool) {
        if let Some(u) = self.uids.get(name) {
            return (Some(*u), false);
        }
        let mut next = self
            .uids
            .values()
            .max()
            .map_or(self.min, |m| m.saturating_add(1));
        while taken.ids.contains(&next) {
            next = next.saturating_add(1);
        }
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
            .map(|(n, u)| format!("{n}:{u}\n"))
            .collect::<Vec<_>>()
            .concat();
        write_atomic(&self.path, &text, 0o600)
    }
}

/// `name:uid:gid:dir:shell` lines sorted by uid; gid = uid. Local users first, then the
/// external names not already local. Skipped with a log line: an unsafe name, a name or
/// uid already on the box (re-checked on every rewrite), a `nos-` external name, an
/// exhausted range. Returns the text and whether `map` grew.
pub fn render(
    users: &[User],
    external: &BTreeSet<String>,
    map: &mut UidMap,
    taken: &Taken,
) -> (String, bool) {
    let mut rows = Vec::new();
    let mut grew = false;
    let local: BTreeSet<&str> = users.iter().map(|u| u.name.as_str()).collect();
    let names = users
        .iter()
        .map(|u| (u.name.as_str(), false))
        .chain(
            external
                .iter()
                .filter(|n| !local.contains(n.as_str()))
                .map(|n| (n.as_str(), true)),
        )
        .collect::<Vec<_>>();
    for (name, is_external) in names {
        if !safe_name(name) {
            warn!(user = ?name, "no ssh account: name is not a valid unix user name");
            continue;
        }
        if taken.names.contains(name) || (is_external && name.starts_with(RESERVED_PREFIX)) {
            error!(user = %name, "no ssh account: the name exists in /etc/passwd or is reserved");
            continue;
        }
        match map.allocate(name, taken) {
            (Some(uid), _) if taken.ids.contains(&uid) => {
                error!(user = %name, uid, "no ssh account: the uid exists in /etc/passwd or /etc/group");
            }
            (Some(uid), g) => {
                grew |= g;
                rows.push((uid, name));
            }
            (None, _) => error!(user = %name, "no ssh account: the uid range is exhausted"),
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

struct State {
    map: UidMap,
    /// Names given an entry by an AAA accept or an admin; their uids live in `map`.
    external: BTreeSet<String>,
}

/// Where `ConfigStore` mirrors its users.
pub struct UserDb {
    passwd: PathBuf,
    aaa_file: PathBuf,
    etc_passwd: PathBuf,
    etc_group: PathBuf,
    state: Mutex<State>,
}

impl UserDb {
    /// `None` (after an `error!`) when the uid map or the external-name file is unusable:
    /// `passwd` is then left alone.
    pub fn open(passwd: PathBuf, ids_file: &Path) -> Option<Self> {
        Self::open_range(passwd, ids_file, UID_MIN, UID_MAX)
    }

    fn open_range(passwd: PathBuf, ids_file: &Path, min: u32, max: u32) -> Option<Self> {
        let aaa_file = ids_file.with_file_name(AAA_USERS_FILE);
        let loaded = UidMap::load(ids_file, min, max).and_then(|map| {
            let external = load_external(&aaa_file, &map)?;
            Ok(State { map, external })
        });
        match loaded {
            Ok(state) => Some(Self {
                passwd,
                aaa_file,
                etc_passwd: ETC_PASSWD.into(),
                etc_group: ETC_GROUP.into(),
                state: Mutex::new(state),
            }),
            Err(e) => {
                error!(file = %ids_file.display(), error = %e, "uid map unusable, not writing the nss passwd file");
                None
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn taken(&self) -> std::io::Result<Taken> {
        Taken::load(&self.etc_passwd, &self.etc_group)
    }

    /// Persists any new uid first, then the passwd file, so a crash never exposes an
    /// unpersisted uid. Failures are logged, never returned: a stale entry is harmless.
    pub fn sync(&self, users: &[User]) {
        let mut st = self.lock();
        if let Err(e) = self.write_locked(users, &mut st) {
            warn!(error = %e, "updating the nss passwd file failed");
        }
    }

    fn write_locked(&self, users: &[User], st: &mut State) -> Result<(), String> {
        let taken = self.taken().map_err(|e| format!("reading /etc: {e}"))?;
        let (text, grew) = render(users, &st.external, &mut st.map, &taken);
        if grew {
            st.map
                .persist()
                .map_err(|e| format!("persisting the uid map: {e}"))?;
        }
        write_atomic(&self.passwd, &text, 0o644)
            .map_err(|e| format!("writing {}: {e}", self.passwd.display()))
    }

    /// Gives `name` an entry (idempotent), returning its uid. `users` are the running
    /// config's users; the caller holds the `running` lock so no commit interleaves.
    pub fn allocate_external(&self, name: &str, users: &[User]) -> Result<u32, ExternalUserError> {
        let io = |e: &dyn std::fmt::Display| ExternalUserError::Io(e.to_string());
        if !safe_name(name) {
            return Err(ExternalUserError::Unsafe);
        }
        if name.starts_with(RESERVED_PREFIX) {
            return Err(ExternalUserError::Reserved);
        }
        if users.iter().any(|u| u.name == name) {
            return Err(ExternalUserError::LocalUser);
        }
        let taken = self.taken().map_err(|e| io(&e))?;
        if taken.names.contains(name) {
            return Err(ExternalUserError::SystemClash);
        }
        let mut st = self.lock();
        let created = !st.external.contains(name);
        if created && st.external.len() >= EXTERNAL_CAP {
            return Err(ExternalUserError::Full);
        }
        // Work on copies: nothing changes in memory unless it reached the disk.
        let mut map = st.map.clone();
        let (uid, grew) = map.allocate(name, &taken);
        let uid = uid.ok_or(ExternalUserError::Exhausted)?;
        if taken.ids.contains(&uid) {
            return Err(ExternalUserError::SystemClash);
        }
        if grew {
            map.persist().map_err(|e| io(&e))?;
        }
        let mut external = st.external.clone();
        if created {
            external.insert(name.to_string());
            write_atomic(&self.aaa_file, &names_text(&external), 0o600).map_err(|e| io(&e))?;
        }
        st.map = map;
        st.external = external;
        // Also on an idempotent call: heals a passwd file that was not written before.
        self.write_locked(users, &mut st).map_err(|e| io(&e))?;
        if created {
            info!(user = %name, uid, "external user allocated");
        }
        Ok(uid)
    }

    /// Drops `name`'s entry; its uid stays reserved in the map for good.
    pub fn clear_external(&self, name: &str, users: &[User]) -> Result<u32, ExternalUserError> {
        let mut st = self.lock();
        let uid = *st.map.uids.get(name).ok_or(ExternalUserError::NotFound)?;
        let mut external = st.external.clone();
        if !external.remove(name) {
            return Err(ExternalUserError::NotFound);
        }
        write_atomic(&self.aaa_file, &names_text(&external), 0o600)
            .map_err(|e| ExternalUserError::Io(e.to_string()))?;
        st.external = external;
        self.write_locked(users, &mut st)
            .map_err(ExternalUserError::Io)?;
        info!(user = %name, uid, "external user cleared, uid stays reserved");
        Ok(uid)
    }

    /// `(name, uid)` of every external name, by name.
    pub fn list_external(&self) -> Vec<(String, u32)> {
        let st = self.lock();
        st.external
            .iter()
            .filter_map(|n| Some((n.clone(), *st.map.uids.get(n)?)))
            .collect()
    }
}

fn names_text(names: &BTreeSet<String>) -> String {
    names.iter().flat_map(|n| [n.as_str(), "\n"]).collect()
}

/// The persisted external names. Every one must be a safe name with a uid in `map`: a
/// name without one means the map was lost, and regenerating would reuse uids.
fn load_external(path: &Path, map: &UidMap) -> Result<BTreeSet<String>, String> {
    let mut set = BTreeSet::new();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(set),
        Err(e) => return Err(e.to_string()),
    };
    for n in text.lines().filter(|l| !l.is_empty()) {
        if !safe_name(n) || !map.uids.contains_key(n) || !set.insert(n.to_string()) {
            return Err(format!("invalid external user {n:?}"));
        }
    }
    Ok(set)
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
            ..Default::default()
        }
    }

    fn users(n: &[&str]) -> Vec<User> {
        n.iter().map(|n| user(n)).collect()
    }

    fn db(dir: &Path, min: u32, max: u32) -> UserDb {
        let mut d = UserDb::open_range(dir.join("passwd"), &dir.join("ids"), min, max).unwrap();
        // never the host's /etc: its system ids would make the tests depend on the machine
        d.etc_passwd = dir.join("no-etc-passwd");
        d.etc_group = dir.join("no-etc-group");
        d
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

    fn ext(d: &UserDb, n: &str, local: &[&str]) -> Result<u32, ExternalUserError> {
        d.allocate_external(n, &users(local))
    }

    fn etc(d: &mut UserDb, dir: &Path, passwd: &str, group: &str) {
        std::fs::write(dir.join("etc-passwd"), passwd).unwrap();
        std::fs::write(dir.join("etc-group"), group).unwrap();
        d.etc_passwd = dir.join("etc-passwd");
        d.etc_group = dir.join("etc-group");
    }

    #[test]
    fn external_refusals() {
        let t = tempfile::tempdir().unwrap();
        let mut d = db(t.path(), UID_MIN, UID_MAX);
        etc(
            &mut d,
            t.path(),
            "daemon:x:1:1::/:/bin/false\nsvc:x:30000:30001::/:/bin/false\n",
            "grp:x:30002:\n",
        );
        for (n, want) in [
            ("a:b", "not a valid"),
            ("Root", "not a valid"),
            ("nos-wd", "reserved"),
            ("alice", "local user"),
            ("daemon", "/etc/passwd"),
        ] {
            let e = ext(&d, n, &["alice"]).unwrap_err().to_string();
            assert!(e.contains(want), "{n}: {e}");
        }
        assert_eq!(d.list_external().len(), 0);
        assert!(
            !t.path().join("passwd").exists(),
            "nothing written for a refusal"
        );
        assert!(!t.path().join("aaa-users").exists());
    }

    #[test]
    fn external_uid_skips_ids_on_the_box_and_is_idempotent() {
        let t = tempfile::tempdir().unwrap();
        let mut d = db(t.path(), 30_000, 30_010);
        etc(
            &mut d,
            t.path(),
            "svc:x:30000:30001::/:/bin/false\n",
            "grp:x:30002:\n",
        );
        // 30000 (uid), 30001 (primary gid) and 30002 (group) are taken
        assert_eq!(ext(&d, "bob", &[]).unwrap(), 30_003);
        assert_eq!(ext(&d, "bob", &[]).unwrap(), 30_003);
        assert_eq!(ext(&d, "carol", &[]).unwrap(), 30_004);
        assert_eq!(
            passwd(t.path()),
            "bob:30003:30003:/nonexistent:/usr/bin/nos\ncarol:30004:30004:/nonexistent:/usr/bin/nos\n"
        );
        assert_eq!(
            std::fs::read_to_string(t.path().join("aaa-users")).unwrap(),
            "bob\ncarol\n"
        );
    }

    #[test]
    fn clear_keeps_the_uid_reserved_and_never_shares_it() {
        let t = tempfile::tempdir().unwrap();
        let d = db(t.path(), UID_MIN, UID_MAX);
        assert_eq!(ext(&d, "bob", &[]).unwrap(), 20_000);
        assert_eq!(d.clear_external("bob", &[]).unwrap(), 20_000);
        assert!(matches!(
            d.clear_external("bob", &[]),
            Err(ExternalUserError::NotFound)
        ));
        assert_eq!(passwd(t.path()), "");
        assert_eq!(ext(&d, "carol", &[]).unwrap(), 20_001);
        // restart: the same uid comes back for bob, carol keeps hers
        let d = db(t.path(), UID_MIN, UID_MAX);
        assert_eq!(d.list_external(), vec![("carol".to_string(), 20_001)]);
        assert_eq!(ext(&d, "bob", &[]).unwrap(), 20_000);
        assert_eq!(
            d.list_external(),
            vec![("bob".to_string(), 20_000), ("carol".to_string(), 20_001)]
        );
    }

    #[test]
    fn local_and_external_share_one_map_and_a_later_local_user_keeps_the_uid() {
        let t = tempfile::tempdir().unwrap();
        let d = db(t.path(), UID_MIN, UID_MAX);
        d.sync(&users(&["alice"]));
        assert_eq!(ext(&d, "bob", &["alice"]).unwrap(), 20_001);
        // bob becomes a local user: one line, same uid
        d.sync(&users(&["alice", "bob"]));
        assert_eq!(passwd(t.path()).matches("bob:20001:").count(), 1);
        assert!(matches!(
            ext(&d, "bob", &["alice", "bob"]),
            Err(ExternalUserError::LocalUser)
        ));
    }

    #[test]
    fn a_rewrite_skips_names_and_uids_that_appeared_in_etc() {
        let t = tempfile::tempdir().unwrap();
        let mut d = db(t.path(), UID_MIN, UID_MAX);
        assert_eq!(ext(&d, "bob", &[]).unwrap(), 20_000);
        assert_eq!(ext(&d, "carol", &[]).unwrap(), 20_001);
        etc(
            &mut d,
            t.path(),
            "bob:x:500:500::/:/bin/sh\n",
            "g:x:20001:\n",
        );
        d.sync(&[]);
        assert_eq!(passwd(t.path()), "");
        // the allocation itself fails closed too
        assert!(matches!(
            ext(&d, "carol", &[]),
            Err(ExternalUserError::SystemClash)
        ));
    }

    #[test]
    fn the_cap_and_the_range_refuse_only_the_allocation() {
        let t = tempfile::tempdir().unwrap();
        let d = db(t.path(), 100, 101);
        ext(&d, "a", &[]).unwrap();
        ext(&d, "b", &[]).unwrap();
        assert!(matches!(
            ext(&d, "c", &[]),
            Err(ExternalUserError::Exhausted)
        ));
        assert_eq!(ext(&d, "a", &[]).unwrap(), 100);
        let t = tempfile::tempdir().unwrap();
        let d = db(t.path(), UID_MIN, UID_MAX);
        {
            let mut st = d.lock();
            for i in 0..EXTERNAL_CAP {
                st.external.insert(format!("u{i}"));
            }
        }
        assert!(matches!(ext(&d, "new", &[]), Err(ExternalUserError::Full)));
    }

    #[test]
    fn a_corrupt_external_file_refuses_to_open_and_no_secret_is_stored() {
        let t = tempfile::tempdir().unwrap();
        let d = db(t.path(), UID_MIN, UID_MAX);
        ext(&d, "bob", &[]).unwrap();
        let aaa = std::fs::read_to_string(t.path().join("aaa-users")).unwrap();
        assert_eq!(aaa, "bob\n");
        let mode = std::fs::metadata(t.path().join("aaa-users")).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
            0o600
        );
        let open = || UserDb::open(t.path().join("passwd"), &t.path().join("ids"));
        assert!(open().is_some());
        for bad in ["BAD\n", "bob\nbob\n", "ghost\n"] {
            std::fs::write(t.path().join("aaa-users"), bad).unwrap();
            assert!(open().is_none(), "{bad}");
        }
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
