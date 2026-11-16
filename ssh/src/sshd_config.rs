//! The `sshd_config` every per-connection `sshd -i` reads (#994).

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub struct Settings {
    pub host_key: PathBuf,
}

/// Appended last, so a later feature (#989, #987) can add directives without
/// touching the fixed block.
pub fn extra_directives() -> &'static str {
    ""
}

/// Password-only (PAM does the check against `nos-watchdogd`); no forwarding,
/// no tunnels (`DisableForwarding` overrides the older per-kind directives, which stay as
/// explicit belt and braces), no environment or `~/.ssh/rc` from the user. No `Subsystem` (no
/// sftp) and no `ForceCommand` (it would run as `<shell> -c`, breaking the interactive login).
///
/// `PAMServiceName nos-sshd` selects `/etc/pam.d/nos-sshd` (#998) instead of the
/// distro's `sshd` service file; needs OpenSSH >= the trixie 10.0p2 the image ships.
pub fn render(s: &Settings) -> String {
    let mut out = format!(
        "UsePAM yes\n\
         PAMServiceName nos-sshd\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication yes\n\
         PubkeyAuthentication no\n\
         PermitRootLogin no\n\
         HostKey {}\n\
         PidFile none\n\
         X11Forwarding no\n\
         AllowAgentForwarding no\n\
         AllowTcpForwarding no\n\
         AllowStreamLocalForwarding no\n\
         DisableForwarding yes\n\
         PermitTunnel no\n\
         PermitUserRC no\n\
         PermitUserEnvironment no\n\
         LoginGraceTime 30\n\
         MaxAuthTries 3\n\
         UseDNS no\n\
         LogLevel VERBOSE\n",
        s.host_key.display()
    );
    out.push_str(extra_directives());
    out
}

/// Writes `text` to `path` (0600) through a temp file and rename, unless the
/// file already holds exactly that. Returns whether it wrote.
pub fn write_if_changed(path: &Path, text: &str) -> io::Result<bool> {
    if std::fs::read_to_string(path).is_ok_and(|old| old == text) {
        return Ok(false);
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text() -> String {
        render(&Settings {
            host_key: "/run/nos-sshd/rt1/ssh_host_ed25519_key".into(),
        })
    }

    #[test]
    fn carries_the_security_critical_lines() {
        let t = text();
        for line in [
            "UsePAM yes",
            "PAMServiceName nos-sshd",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication yes",
            "PubkeyAuthentication no",
            "PermitRootLogin no",
            "HostKey /run/nos-sshd/rt1/ssh_host_ed25519_key",
            "AllowTcpForwarding no",
            "AllowStreamLocalForwarding no",
            "DisableForwarding yes",
            "PermitTunnel no",
            "PermitUserRC no",
            "PermitUserEnvironment no",
            "LogLevel VERBOSE",
        ] {
            assert!(t.lines().any(|l| l == line), "missing {line}");
        }
        assert!(!t.contains("PubkeyAuthentication yes"));
        assert!(!t
            .lines()
            .any(|l| l.contains("Forwarding yes") && l != "DisableForwarding yes"));
        assert!(!t
            .lines()
            .any(|l| l.starts_with("Subsystem") || l.starts_with("ForceCommand")));
        assert!(t.ends_with(extra_directives()));
    }

    #[test]
    fn rewrite_is_skipped_when_unchanged_and_file_is_private() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sshd_config");
        assert!(write_if_changed(&p, &text()).unwrap());
        assert!(!write_if_changed(&p, &text()).unwrap());
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_if_changed(&p, "other\n").unwrap());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "other\n");
    }
}
