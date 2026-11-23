//! RFC 7474's persisted boot count — the high 32 bits of an extended
//! cryptographic sequence number. Every (re)start of a link driver takes a
//! fresh, strictly larger value, so a neighbor's replay check never sees the
//! sequence go backwards across a link restart *or* a process restart.

use std::collections::BTreeSet;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use nos_ospf_common::boot::write_atomic;
use nos_ospf_common::restart;
use tracing::warn;

/// The persisted counter, shared with `nos-ospfv3` (`nos_ospf_common::boot`),
/// wrapped so a read/write problem is logged here.
pub struct BootCounter(nos_ospf_common::boot::BootCounter);

impl BootCounter {
    pub fn in_memory() -> Self {
        Self(nos_ospf_common::boot::BootCounter::in_memory())
    }

    pub fn persistent(path: PathBuf) -> Self {
        Self(nos_ospf_common::boot::BootCounter::persistent(path))
    }

    pub fn next(&self) -> u32 {
        let n = self.0.next();
        if let Some(w) = n.warning {
            warn!(warning = %w, "ospf boot count problem");
        }
        n.count
    }
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

/// The running marker (#1163): same file, rewritten periodically while the
/// daemon is up, so a respawn that finds it knows the process crashed.
pub fn write_running_marker(
    path: &Path,
    deadline: u64,
    neighbors: &BTreeSet<Ipv4Addr>,
) -> io::Result<()> {
    write_atomic(path, &restart::encode_running_marker(deadline, neighbors))
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
        // The running marker (#1163): a crash leaves it, a clean exit deletes it.
        write_running_marker(&path, 1120, &nb).unwrap();
        let m = take_grace_marker(&path, 1000).unwrap();
        assert!(m.unplanned);
        assert_eq!(m.neighbors, nb);
        write_grace_marker(&path, 1120, &nb).unwrap();
        assert!(!take_grace_marker(&path, 1000).unwrap().unplanned);
        std::fs::write(&path, "garbage").unwrap();
        assert!(take_grace_marker(&path, 1000).is_none());
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
