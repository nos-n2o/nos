//! The persistent ed25519 host key (#994). Several `nos-sshd` (one per table)
//! share `/var/lib/nos/sshd`; the first to finish wins and the rest use its key.

use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aws_lc_rs::rand;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

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
    let (pem, public) = generate()?;

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

/// A fresh ed25519 key as (`OPENSSH PRIVATE KEY` PEM, `ssh-ed25519 ...` public line).
/// Hand-encoded (PROTOCOL.key): the usual crate drags RSA and its advisories into
/// the lockfile, and `aws-lc-rs` is already the workspace's crypto provider.
fn generate() -> io::Result<(String, String)> {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed).map_err(|_| io::Error::other("random seed"))?;
    let pair =
        Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| io::Error::other("ed25519 key"))?;
    Ok(encode(&seed, pair.public_key().as_ref()))
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("short field")
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
}

fn encode(seed: &[u8; 32], public: &[u8]) -> (String, String) {
    let mut blob = Vec::new();
    put(&mut blob, b"ssh-ed25519");
    put(&mut blob, public);

    let mut private = Vec::new();
    let mut check = [0u8; 4];
    check.copy_from_slice(&seed[..4]);
    private.extend_from_slice(&check);
    private.extend_from_slice(&check);
    put(&mut private, b"ssh-ed25519");
    put(&mut private, public);
    put(&mut private, &[seed.as_slice(), public].concat());
    put(&mut private, b""); // comment
    for pad in 1..=(8 - private.len() % 8) % 8 {
        private.push(u8::try_from(pad).expect("pad < 8"));
    }

    let mut key = b"openssh-key-v1\0".to_vec();
    put(&mut key, b"none"); // cipher
    put(&mut key, b"none"); // kdf
    put(&mut key, b""); // kdf options
    key.extend_from_slice(&1u32.to_be_bytes());
    put(&mut key, &blob);
    put(&mut key, &private);

    let b64 = STANDARD.encode(&key);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    (pem, format!("ssh-ed25519 {}", STANDARD.encode(&blob)))
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
        let text = String::from_utf8(first).unwrap();
        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(text.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        assert!(dir.join(format!("{KEY_NAME}.pub")).exists());
        // No temp file left behind.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
    }

    #[test]
    fn encoding_has_the_openssh_layout() {
        let (pem, public) = encode(&[7u8; 32], &[9u8; 32]);
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let raw = STANDARD.decode(body).unwrap();
        assert!(raw.starts_with(b"openssh-key-v1\0"));
        // magic, three strings (cipher, kdf, options), key count, public blob, private section.
        let mut at = 15;
        let field = |at: &mut usize| {
            let n = u32::from_be_bytes(raw[*at..*at + 4].try_into().unwrap()) as usize;
            *at += 4 + n;
            n
        };
        for _ in 0..3 {
            field(&mut at);
        }
        at += 4;
        field(&mut at);
        assert_eq!(field(&mut at) % 8, 0, "private section is block-aligned");
        assert_eq!(at, raw.len());
        assert!(public.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
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
