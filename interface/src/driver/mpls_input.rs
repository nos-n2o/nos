//! `net.mpls.conf.<if>.input`, the `Interface.mpls_input` knob (#1380).
//! Pure file logic over a sysctl root (`/proc/sys`, a tempdir in tests), so
//! it is unit-tested; the Linux driver only owns an instance.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Mutex;

use tracing::{info, warn};

use super::DriverError;

pub struct MplsInput {
    root: PathBuf,
    /// Interfaces this process switched on: only those are ever switched
    /// off, so a value the operator wrote on an unconfigured one is kept.
    // ponytail: a restart forgets it, leaving a removed knob at 1 until the
    // operator clears it; persist the set if that matters.
    on: Mutex<HashSet<String>>,
}

impl Default for MplsInput {
    fn default() -> Self {
        Self::new("/proc/sys")
    }
}

impl MplsInput {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            on: Mutex::new(HashSet::new()),
        }
    }

    /// Read first, written only when different. A missing conf entry
    /// (`mpls_router` not loaded, no such device) is skipped, warned while
    /// `enabled`.
    pub fn set(&self, name: &str, enabled: bool) -> Result<(), DriverError> {
        if !enabled && !self.on.lock().unwrap().contains(name) {
            return Ok(());
        }
        let path = self.root.join("net/mpls/conf").join(name).join("input");
        let want = if enabled { "1" } else { "0" };
        match std::fs::read_to_string(&path) {
            Ok(v) if v.trim() == want => {}
            Ok(_) => {
                std::fs::write(&path, want)
                    .map_err(|e| DriverError::Other(format!("net.mpls.conf.{name}.input: {e}")))?;
                info!(interface = %name, enabled, "set mpls input");
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // ponytail: warns every resync (10 s) while the device or the
                // mpls_router module is missing; dedupe if it proves noisy.
                if enabled {
                    warn!(interface = %name, "mpls input not set: no net.mpls.conf entry (mpls_router not loaded, or no such device)");
                }
                return Ok(());
            }
            Err(e) => return Err(DriverError::Io(e)),
        }
        let mut on = self.on.lock().unwrap();
        if enabled {
            on.insert(name.to_string());
        } else {
            on.remove(name);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(ifaces: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (n, v) in ifaces {
            let d = dir.path().join("net/mpls/conf").join(n);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("input"), v).unwrap();
        }
        dir
    }

    fn get(dir: &tempfile::TempDir, n: &str) -> String {
        std::fs::read_to_string(dir.path().join("net/mpls/conf").join(n).join("input")).unwrap()
    }

    #[test]
    fn set_then_unset_round_trips() {
        let t = tree(&[("eth0", "0\n")]);
        let m = MplsInput::new(t.path());
        m.set("eth0", true).unwrap();
        assert_eq!(get(&t, "eth0"), "1");
        m.set("eth0", false).unwrap();
        assert_eq!(get(&t, "eth0"), "0");
    }

    #[test]
    fn a_value_already_right_is_not_rewritten() {
        let t = tree(&[("eth0", "1\n")]);
        let m = MplsInput::new(t.path());
        m.set("eth0", true).unwrap();
        assert_eq!(get(&t, "eth0"), "1\n");
        m.set("eth0", false).unwrap();
        assert_eq!(get(&t, "eth0"), "0", "it was ours once enabled was seen");
    }

    #[test]
    fn unset_leaves_an_operator_value_alone() {
        let t = tree(&[("eth0", "1\n")]);
        MplsInput::new(t.path()).set("eth0", false).unwrap();
        assert_eq!(get(&t, "eth0"), "1\n");
    }

    #[test]
    fn a_missing_device_is_skipped() {
        let t = tree(&[]);
        let m = MplsInput::new(t.path());
        m.set("nope", true).unwrap();
        m.set("nope", false).unwrap();
        assert_eq!(MplsInput::default().root, PathBuf::from("/proc/sys"));
    }

    #[test]
    fn an_unwritable_file_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let t = tree(&[("eth0", "0")]);
        let f = t.path().join("net/mpls/conf/eth0/input");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o444)).unwrap();
        if std::fs::OpenOptions::new().write(true).open(&f).is_ok() {
            return; // root ignores file modes
        }
        let e = MplsInput::new(t.path()).set("eth0", true).unwrap_err();
        assert!(e.to_string().contains("net.mpls.conf.eth0.input"), "{e}");
    }
}
