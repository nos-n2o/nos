//! The host key (#994, #1104). The key is the admin-keystore secret
//! `ssh-host-key` (the base64 of the 32-byte ed25519 seed), kept by
//! `nos-configd`; every table's `nos-sshd` renders it to a 0600 file on tmpfs
//! (`sshd` needs a file) and generates it first when no one has yet.

use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use aws_lc_rs::{digest, rand};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use tracing::{info, warn};

pub const KEY_NAME: &str = "ssh_host_ed25519_key";

/// Where the key is stored: `nos-configd`'s admin keystore in production.
#[allow(
    async_fn_in_trait,
    reason = "crate-internal, only used with concrete types"
)]
pub trait Keys {
    /// The stored seed (`Some(None)` = read fine, none stored); `None` if unreadable.
    async fn get(&self) -> Option<Option<String>>;
    /// Set-if-absent; the caller re-reads, so who won does not matter.
    async fn set(&self, seed: &str);
}

/// A key as `sshd` wants it plus its `SHA256:` fingerprint (what `ssh` prints).
pub struct HostKey {
    pub pem: String,
    pub fingerprint: String,
}

/// A fresh random seed, base64.
pub fn new_seed() -> io::Result<String> {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed).map_err(|_| io::Error::other("random seed"))?;
    Ok(STANDARD.encode(seed))
}

/// The key a base64 seed stands for (deterministic).
pub fn from_seed(b64: &str) -> io::Result<HostKey> {
    let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
    let seed: [u8; 32] = STANDARD
        .decode(b64)
        .map_err(|_| bad("ssh-host-key is not base64"))?
        .try_into()
        .map_err(|_| bad("ssh-host-key is not a 32-byte seed"))?;
    let pair =
        Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| bad("not an ed25519 seed"))?;
    let (pem, public) = encode(&seed, pair.public_key().as_ref());
    let blob = STANDARD
        .decode(public.trim_start_matches("ssh-ed25519 "))
        .expect("own encoding");
    let fingerprint = format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(digest::digest(&digest::SHA256, &blob))
    );
    Ok(HostKey { pem, fingerprint })
}

/// Keeps `path` equal to the configured key, generating one when none exists.
pub struct Keeper<K> {
    pub keys: K,
    pub path: PathBuf,
    written: Option<String>,
}

impl<K: Keys> Keeper<K> {
    pub fn new(keys: K, path: PathBuf) -> Self {
        Self {
            keys,
            path,
            written: None,
        }
    }

    /// One convergence step; `true` once the file holds a usable key.
    pub async fn sync(&mut self) -> bool {
        let Some(stored) = self.keys.get().await else {
            return self.written.is_some(); // config unreadable: keep the file
        };
        let seed = if let Some(s) = stored {
            s
        } else {
            let Ok(new) = new_seed() else { return false };
            self.keys.set(&new).await;
            match self.keys.get().await {
                Some(Some(s)) => s,
                _ => return false,
            }
        };
        if self.written.as_deref() == Some(&seed) {
            return true;
        }
        let key = match from_seed(&seed) {
            Ok(k) => k,
            Err(e) => {
                warn!(error = %e, "ssh-host-key is unusable; keeping the previous key");
                return self.written.is_some();
            }
        };
        if let Err(e) = write_private(&self.path, key.pem.as_bytes()) {
            warn!(error = %e, "writing the host key failed");
            return self.written.is_some();
        }
        info!(fingerprint = %key.fingerprint, "host key");
        self.written = Some(seed);
        true
    }
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("short field")
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
}

/// Hand-encoded (PROTOCOL.key): the usual crate drags RSA and its advisories into
/// the lockfile, and `aws-lc-rs` is already the workspace's crypto provider.
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

/// Atomic 0600 write: temp file, then rename over the key.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
#[allow(clippy::unused_async_trait_impl, reason = "fake store")]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::fs::PermissionsExt;

    #[derive(Default)]
    struct Fake {
        stored: RefCell<Option<String>>,
        /// A rival that sets its own seed just before ours.
        rival: Option<String>,
        unreadable: RefCell<bool>,
    }

    impl Keys for &Fake {
        async fn get(&self) -> Option<Option<String>> {
            (!*self.unreadable.borrow()).then(|| self.stored.borrow().clone())
        }
        async fn set(&self, seed: &str) {
            let mut s = self.stored.borrow_mut();
            if s.is_none() {
                *s = Some(self.rival.clone().unwrap_or_else(|| seed.into()));
            }
        }
    }

    fn pem(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    #[tokio::test]
    async fn generates_once_stores_and_reuses_it() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join(KEY_NAME);
        let fake = Fake::default();
        let mut k = Keeper::new(&fake, path.clone());
        assert!(k.sync().await);
        let first = pem(&path);
        assert!(first.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(first.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        // A restart (new keeper, same store) renders the same key.
        std::fs::remove_file(&path).unwrap();
        assert!(Keeper::new(&fake, path.clone()).sync().await);
        assert_eq!(pem(&path), first);
        // No temp file left behind.
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn the_loser_of_a_race_adopts_the_winner() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join(KEY_NAME);
        let winner = new_seed().unwrap();
        let fake = Fake {
            rival: Some(winner.clone()),
            ..Fake::default()
        };
        assert!(Keeper::new(&fake, path.clone()).sync().await);
        assert_eq!(pem(&path), from_seed(&winner).unwrap().pem);
    }

    #[tokio::test]
    async fn a_removed_key_is_regenerated_and_blips_or_junk_keep_the_file() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join(KEY_NAME);
        let fake = Fake::default();
        let mut k = Keeper::new(&fake, path.clone());
        assert!(k.sync().await);
        let first = pem(&path);
        *fake.unreadable.borrow_mut() = true;
        assert!(k.sync().await, "unreadable config keeps the file");
        *fake.unreadable.borrow_mut() = false;
        *fake.stored.borrow_mut() = None; // `delete admin key ssh-host-key`
        assert!(k.sync().await);
        let second = pem(&path);
        assert_ne!(second, first);
        *fake.stored.borrow_mut() = Some("junk".into());
        assert!(k.sync().await, "a bad seed keeps the previous key");
        assert_eq!(pem(&path), second);
        // And a keeper that never had a key reports failure for junk.
        let mut fresh = Keeper::new(&fake, d.path().join("other"));
        assert!(!fresh.sync().await);
    }

    #[test]
    fn the_same_seed_gives_the_same_key_and_fingerprint() {
        let seed = STANDARD.encode([7u8; 32]);
        let (a, b) = (from_seed(&seed).unwrap(), from_seed(&seed).unwrap());
        assert_eq!((&a.pem, &a.fingerprint), (&b.pem, &b.fingerprint));
        assert!(a.fingerprint.starts_with("SHA256:") && !a.fingerprint.ends_with('='));
        assert!(from_seed("!!").is_err());
        assert!(from_seed(&STANDARD.encode([1u8; 31])).is_err());
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
}
