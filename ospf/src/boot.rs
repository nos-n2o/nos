//! RFC 7474's persisted boot count — the high 32 bits of an extended
//! cryptographic sequence number. Every (re)start of a link driver takes a
//! fresh, strictly larger value, so a neighbor's replay check never sees the
//! sequence go backwards across a link restart *or* a process restart.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use nos_ospf_common::restart;
use tracing::warn;

pub struct BootCounter {
    /// `None` keeps the count in memory only (tests).
    path: Option<PathBuf>,
    last: Mutex<u32>,
}

impl BootCounter {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            last: Mutex::new(0),
        }
    }

    /// Persists to `path` (parent directory created if missing).
    pub fn persistent(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            last: Mutex::new(0),
        }
    }

    /// Returns the next boot count, durably recorded before it is returned.
    pub fn next(&self) -> u32 {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stored = self.path.as_deref().map_or(Ok(0), read_count);
        let next = match stored {
            Ok(n) => n.max(*last).saturating_add(1),
            Err(e) => {
                // ponytail: an unreadable/corrupt file falls back to wall-clock
                // seconds — far above any real boot count, so still increasing
                // here; a later good file with a smaller value would regress.
                warn!(error = %e, "cannot read ospf boot count, using the clock");
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
                now.max(*last).saturating_add(1)
            }
        };
        if let Some(path) = &self.path
            && let Err(e) = write_count(path, next)
        {
            warn!(error = %e, "cannot persist ospf boot count");
        }
        *last = next;
        next
    }
}

fn read_count(path: &Path) -> io::Result<u32> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .trim()
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

fn write_count(path: &Path, n: u32) -> io::Result<()> {
    write_atomic(path, &n.to_string())
}

/// Temp file in the target's directory (`O_EXCL`, mode 0600: never follows a
/// planted symlink), then renamed over `path`.
fn write_atomic(path: &Path, contents: &str) -> io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => {
            std::fs::create_dir_all(d)?;
            d
        }
        _ => Path::new("."),
    };
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(contents.as_bytes())?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// RFC 3623 graceful-restart marker (`<instance>.gr`, format in
/// `nos_ospf_common::restart`): the grace deadline and the `Full` neighbors,
/// written before the Grace-LSAs go out so the respawned process enters
/// restart mode and skips RFC 6987's on-startup period while its helpers
/// keep the old topology. Atomic, like the boot count.
pub fn write_grace_marker(
    path: &Path,
    deadline: u64,
    neighbors: &BTreeSet<Ipv4Addr>,
) -> io::Result<()> {
    write_atomic(path, &restart::encode_marker(deadline, neighbors))
}

/// Consumes the marker (deleted whatever its content): `Some` only if its
/// deadline is still ahead of `now` and at most a `u16` grace period away
/// (rejects a clock jump or garbage). Missing, unreadable or corrupt: `None`.
pub fn take_grace_marker(path: &Path, now: u64) -> Option<restart::Marker> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(error = %e, "cannot read ospf graceful restart marker");
            String::new()
        }
    };
    if let Err(e) = std::fs::remove_file(path) {
        warn!(error = %e, "cannot delete ospf graceful restart marker");
    }
    let marker = restart::parse_marker(&content, now);
    if marker.is_none() {
        warn!("corrupt or expired ospf graceful restart marker, ignoring");
    }
    marker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grace_marker_is_consumed_once_and_checked() {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir -- test scratch dir, not a security boundary.
        let dir = std::env::temp_dir().join(format!("nos-gr-{}", std::process::id()));
        let path = dir.join("i.gr");
        let _ = std::fs::remove_dir_all(&dir);
        let nb: BTreeSet<Ipv4Addr> = [Ipv4Addr::new(2, 2, 2, 2)].into();
        assert!(take_grace_marker(&path, 1000).is_none());
        write_grace_marker(&path, 1120, &nb).unwrap();
        let m = take_grace_marker(&path, 1000).unwrap();
        assert_eq!((m.deadline, m.neighbors), (1120, nb.clone()));
        assert!(!path.exists());
        assert!(take_grace_marker(&path, 1000).is_none());
        // At or past the deadline.
        write_grace_marker(&path, 1000, &nb).unwrap();
        assert!(take_grace_marker(&path, 1000).is_none());
        std::fs::write(&path, "garbage").unwrap();
        assert!(take_grace_marker(&path, 1000).is_none());
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn increments_and_survives_restart() {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir -- test scratch dir, not a security boundary.
        let dir = std::env::temp_dir().join(format!("nos-boot-{}", std::process::id()));
        let path = dir.join("i.boot");
        let _ = std::fs::remove_dir_all(&dir);
        let c = BootCounter::persistent(path.clone());
        assert_eq!((c.next(), c.next()), (1, 2));
        // A new process (fresh counter object) continues from the file.
        assert_eq!(BootCounter::persistent(path.clone()).next(), 3);
        // A corrupt file must not reset to a low value.
        std::fs::write(&path, "garbage").unwrap();
        assert!(BootCounter::persistent(path).next() > 1_000_000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_leaves_only_target_and_ignores_planted_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("i.tmp")).unwrap();
        let path = dir.path().join("i.boot");
        assert_eq!(BootCounter::persistent(path).next(), 1);
        write_grace_marker(&dir.path().join("i.gr"), 5, &BTreeSet::new()).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["i.boot", "i.gr", "i.tmp", "victim"]);
    }

    #[test]
    fn in_memory_is_strictly_increasing() {
        let c = BootCounter::in_memory();
        assert!(c.next() < c.next());
    }
}
