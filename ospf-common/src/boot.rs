//! RFC 7474 / RFC 7166 §4.1's persisted boot count — the high 32 bits of an
//! extended cryptographic sequence number. Every (re)start of a link driver
//! takes a fresh, strictly larger value, so a neighbor's replay check never
//! sees the sequence go backwards across a link restart *or* a process
//! restart. `std` only: problems come back in [`Next::warning`] for the
//! daemon to log.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// One [`BootCounter::next`] result.
#[derive(Debug, PartialEq, Eq)]
pub struct Next {
    pub count: u32,
    /// An unreadable or unwritable file, for the caller's `warn!`.
    pub warning: Option<String>,
}

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
    pub fn next(&self) -> Next {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut warnings = Vec::new();
        let stored = self.path.as_deref().map_or(Ok(0), read_count);
        let count = match stored {
            Ok(n) => n.max(*last).saturating_add(1),
            Err(e) => {
                // ponytail: an unreadable/corrupt file falls back to wall-clock
                // seconds — far above any real boot count, so still increasing
                // here; a later good file with a smaller value would regress.
                warnings.push(format!("cannot read boot count, using the clock: {e}"));
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
                now.max(*last).saturating_add(1)
            }
        };
        if let Some(path) = &self.path
            && let Err(e) = write_atomic(path, &count.to_string())
        {
            warnings.push(format!("cannot persist boot count: {e}"));
        }
        *last = count;
        Next {
            count,
            warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
        }
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

/// Temp file in the target's directory (`O_EXCL`, mode 0600: never follows a
/// planted symlink), then renamed over `path`.
pub fn write_atomic(path: &Path, contents: &str) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn n(c: &BootCounter) -> u32 {
        c.next().count
    }

    #[test]
    fn increments_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/i.boot");
        let c = BootCounter::persistent(path.clone());
        assert_eq!((n(&c), n(&c)), (1, 2));
        // A new process (fresh counter object) continues from the file.
        assert_eq!(n(&BootCounter::persistent(path.clone())), 3);
        // A corrupt file must not reset to a low value, and says so.
        std::fs::write(&path, "garbage").unwrap();
        let r = BootCounter::persistent(path).next();
        assert!(r.count > 1_000_000);
        assert!(r.warning.is_some());
    }

    #[test]
    fn write_leaves_only_target_and_ignores_planted_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("i.tmp")).unwrap();
        assert_eq!(n(&BootCounter::persistent(dir.path().join("i.boot"))), 1);
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }

    #[test]
    fn in_memory_is_strictly_increasing() {
        let c = BootCounter::in_memory();
        assert!(n(&c) < n(&c));
        assert_eq!(c.next().warning, None);
    }

    #[test]
    fn unwritable_path_warns() {
        let c = BootCounter::persistent(PathBuf::from("/proc/nope/i.boot"));
        assert!(c.next().warning.is_some());
    }
}
