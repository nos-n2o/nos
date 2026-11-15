//! The persistent ed25519 host key (#994). Several `nos-sshd` (one per table)
//! share `/var/lib/nos/sshd`; the first to finish wins and the rest use its key.

use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

pub const KEY_NAME: &str = "ssh_host_ed25519_key";

/// Makes sure `<dir>/ssh_host_ed25519_key` (+ `.pub`) exists, returning the private key's path.
pub fn ensure(dir: &Path) -> io::Result<PathBuf> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let key = dir.join(KEY_NAME);
    if key.exists() {
        return Ok(key);
    }
    let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(io::Error::other)?;
    let pem = private
        .to_openssh(LineEnding::LF)
        .map_err(io::Error::other)?;
    let public = private
        .public_key()
        .to_openssh()
        .map_err(io::Error::other)?;

    // A unique temp file, then a hard link: the link fails if another process
    // already published a key, which is then the one in use.
    let tmp = dir.join(format!(".{KEY_NAME}.{}.tmp", std::process::id()));
    write_private(&tmp, pem.as_bytes())?;
    let linked = std::fs::hard_link(&tmp, &key);
    std::fs::remove_file(&tmp)?;
    match linked {
        Ok(()) => {
            let pub_path = dir.join(format!("{KEY_NAME}.pub"));
            std::fs::write(&pub_path, format!("{public}\n"))?;
            std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))?;
            Ok(key)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(key),
        Err(e) => Err(e),
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_once_with_private_modes() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("sshd");
        let key = ensure(&dir).unwrap();
        let first = std::fs::read(&key).unwrap();
        assert_eq!(ensure(&dir).unwrap(), key);
        assert_eq!(std::fs::read(&key).unwrap(), first);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&dir), mode(&key)), (0o700, 0o600));
        let parsed = PrivateKey::from_openssh(&first).unwrap();
        assert_eq!(parsed.algorithm(), Algorithm::Ed25519);
        assert!(dir.join(format!("{KEY_NAME}.pub")).exists());
        // No temp file left behind.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
    }

    #[test]
    fn existing_key_wins_a_race() {
        let d = tempfile::tempdir().unwrap();
        let key = d.path().join(KEY_NAME);
        std::fs::write(&key, b"winner").unwrap();
        assert_eq!(ensure(d.path()).unwrap(), key);
        assert_eq!(std::fs::read(&key).unwrap(), b"winner");
    }

    #[test]
    fn losing_the_link_keeps_the_winner() {
        // Publish between the exists() check and the link: simulated by making
        // the final name appear as a dangling entry the link then collides with.
        let d = tempfile::tempdir().unwrap();
        let key = d.path().join(KEY_NAME);
        std::os::unix::fs::symlink("nowhere", &key).unwrap(); // exists() is false
        assert_eq!(ensure(d.path()).unwrap(), key);
        assert!(std::fs::symlink_metadata(&key)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }
}
