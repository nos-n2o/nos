use std::collections::HashMap;
use std::io::{self, Write as _};
use std::path::Path;

use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace, warn};

use super::Lookup;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Registry {
    #[serde(default)]
    by_name: HashMap<String, u32>,
}

/// Returns the persisted bridge id for `domain_name`, allocating (smallest
/// unused id starting at 1) and persisting a fresh one on first use. Reused
/// verbatim on every later call for the same name — including across a full
/// process restart — so a crash/restart reuses the same bridge name. This
/// id only ever feeds `bridge_ifname` (a short, unique kernel device name —
/// `BroadcastDomain.name` can be up to 64 bytes, too long for Linux's
/// `IFNAMSIZ`), unlike `nos-ribd`'s table id it is never a real kernel
/// routing table id, so there's no reserved range to avoid.
///
/// This is purely `nos-interfaced`'s own private persistence, exactly like
/// `nos-ribd`'s `table_registry`: no other process ever reads this file.
/// Takes an exclusive lock on a `.lock` sibling file for the whole
/// read-allocate-write sequence — `nos-interfaced` is a single process, but
/// the lock still guards against a concurrent `ensure_broadcast_domain`
/// call for a different domain racing on the same file.
pub fn ensure_bridge_id(path: &Path, domain_name: &str) -> io::Result<u32> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path(path))?;
    lock_file.lock_exclusive()?;
    let result = (|| {
        let mut reg = load(path)?;
        if let Some(&id) = reg.by_name.get(domain_name) {
            trace!(domain = %domain_name, bridge_id = id, "reusing allocated bridge id");
            return Ok(id);
        }
        let used: std::collections::HashSet<u32> = reg.by_name.values().copied().collect();
        let id = (1..=u32::MAX)
            .find(|id| !used.contains(id))
            .expect("u32 range never exhausted in practice");
        reg.by_name.insert(domain_name.to_string(), id);
        save(path, &reg)?;
        info!(domain = %domain_name, bridge_id = id, "allocated new bridge id");
        Ok(id)
    })();
    if let Err(e) = fs2::FileExt::unlock(&lock_file) {
        warn!(domain = %domain_name, error = %e, "failed to unlock bridge-id registry lock file");
    }
    result
}

/// Read-only, no lock needed — atomic renames (see `save`) mean a reader
/// never observes a torn write. `NotConfigured` if this domain has never had
/// `ensure_bridge_id` succeed;
/// `Unknown` if the file is unreadable or unparseable.
pub fn lookup_bridge_id(path: &Path, domain_name: &str) -> Lookup<u32> {
    match std::fs::read(path) {
        Ok(bytes) => match serde_norway::from_slice::<Registry>(&bytes) {
            Ok(reg) => reg
                .by_name
                .get(domain_name)
                .map_or(Lookup::NotConfigured, |&id| Lookup::Found(id)),
            // `load` starts empty for the writers; a reader must not
            // mistake that for "never allocated" (#615).
            Err(_) => Lookup::Unknown,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Lookup::NotConfigured,
        Err(_) => Lookup::Unknown,
    }
}

pub fn bridge_ifname(bridge_id: u32) -> String {
    format!("br{bridge_id}")
}

fn lock_path(path: &Path) -> std::path::PathBuf {
    path.with_extension("lock")
}

fn load(path: &Path) -> io::Result<Registry> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_norway::from_slice(&bytes).unwrap_or_else(|e| {
            warn!(
                path = %path.display(),
                error = %e,
                "failed to parse bridge-id registry, starting from an empty registry"
            );
            Registry::default()
        })),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Registry::default()),
        Err(e) => Err(e),
    }
}

/// Same atomic-write pattern as `nos-ribd`'s `table_registry::save`: a temp
/// file in the same directory, then renamed over `path`.
fn save(path: &Path, reg: &Registry) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let yaml = serde_norway::to_string(reg).expect("Registry serialization cannot fail");

    let mut tmp = match dir {
        Some(dir) => tempfile::NamedTempFile::new_in(dir),
        None => tempfile::NamedTempFile::new(),
    }?;
    tmp.write_all(yaml.as_bytes())?;
    tmp.persist(path).map_err(|e| e.error)?;
    debug!(path = %path.display(), entries = reg.by_name.len(), "persisted bridge-id registry");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocating_twice_for_the_same_name_reuses_the_id() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bridge-ids.yaml");

        let first = ensure_bridge_id(&path, "bd1").unwrap();
        let second = ensure_bridge_id(&path, "bd1").unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn different_names_get_distinct_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bridge-ids.yaml");

        let a = ensure_bridge_id(&path, "bd1").unwrap();
        let b = ensure_bridge_id(&path, "bd2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn allocation_starts_at_one() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bridge-ids.yaml");

        let a = ensure_bridge_id(&path, "bd1").unwrap();
        assert_eq!(a, 1);
        let b = ensure_bridge_id(&path, "bd2").unwrap();
        assert_eq!(b, 2);
    }

    #[test]
    fn lookup_of_missing_entry_is_not_configured() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bridge-ids.yaml");
        assert_eq!(lookup_bridge_id(&path, "bd1"), Lookup::NotConfigured);

        ensure_bridge_id(&path, "bd1").unwrap();
        assert_eq!(lookup_bridge_id(&path, "bd2"), Lookup::NotConfigured);
        assert_eq!(lookup_bridge_id(&path, "bd1"), Lookup::Found(1));
    }

    #[test]
    fn lookup_against_a_missing_file_is_not_configured() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.yaml");
        assert_eq!(lookup_bridge_id(&path, "bd1"), Lookup::NotConfigured);
    }

    #[test]
    fn lookup_of_an_unparseable_file_is_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ids.yaml");
        std::fs::write(&path, "by_name: [not, a, map").unwrap();
        assert_eq!(lookup_bridge_id(&path, "bd1"), Lookup::Unknown);
    }

    #[test]
    fn lookup_of_an_unreadable_path_is_unknown() {
        // A directory where the file should be: `read` fails with a
        // non-NotFound I/O error.
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(lookup_bridge_id(tmp.path(), "bd1"), Lookup::Unknown);
    }

    #[test]
    fn bridge_ifname_formats_from_id() {
        assert_eq!(bridge_ifname(1), "br1");
        assert_eq!(bridge_ifname(42), "br42");
    }
}
