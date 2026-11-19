//! `nos-sandbox-exec`'s pure logic: file-capability parsing, target check, argument parser.
//! The syscalls live in [`sys`] (excluded from coverage: only the real kernel tests them).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::similar_names,
    clippy::redundant_closure_for_method_calls,
    reason = "32/64-bit capability word splitting and byte-slice plumbing, all bounded"
)]

pub mod sys;

use std::fmt;
use std::path::{Path, PathBuf};

/// Where production daemons live; the trampoline execs nothing else.
pub const TARGET_DIR: &str = "/usr/local/bin";

#[derive(Debug, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

/// A parsed `security.capability` xattr (Linux `vfs_cap_data`).
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct FileCaps {
    pub permitted: u64,
    pub inheritable: u64,
    pub effective: bool,
}

const REV_1: u32 = 0x0100_0000;
const REV_2: u32 = 0x0200_0000;
const REV_3: u32 = 0x0300_0000;
const REV_MASK: u32 = 0xFF00_0000;

fn le32(b: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]))
}

/// Parses v1 (32-bit sets), v2 and v3 (64-bit; v3 only with `rootid` 0, i.e. not a
/// user-namespace-scoped capability). Anything else, or a wrong length, is an error.
pub fn parse_vfs_cap(b: &[u8]) -> Result<FileCaps, Error> {
    if b.len() < 4 {
        return err("file capability xattr too short");
    }
    let magic = le32(b, 0) as u32;
    let (want, permitted, inheritable) = match magic & REV_MASK {
        REV_1 if b.len() == 12 => (12, le32(b, 4), le32(b, 8)),
        REV_2 | REV_3 => {
            let want = if magic & REV_MASK == REV_2 { 20 } else { 24 };
            if b.len() != want {
                return err("file capability xattr has the wrong length");
            }
            if want == 24 && le32(b, 20) != 0 {
                return err("namespaced (non-zero rootid) file capability refused");
            }
            (
                want,
                le32(b, 4) | le32(b, 12) << 32,
                le32(b, 8) | le32(b, 16) << 32,
            )
        }
        REV_1 => return err("file capability xattr has the wrong length"),
        _ => return err("unknown file capability revision"),
    };
    debug_assert_eq!(b.len(), want);
    Ok(FileCaps {
        permitted,
        inheritable,
        effective: magic & 1 != 0,
    })
}

/// The canonical target if it is a regular file directly inside `dir`.
pub fn check_target(target: &Path, dir: &Path) -> Result<PathBuf, Error> {
    let real = target
        .canonicalize()
        .map_err(|e| Error(format!("{}: {e}", target.display())))?;
    let dir = dir
        .canonicalize()
        .map_err(|e| Error(format!("{}: {e}", dir.display())))?;
    if !real.is_file() {
        return err(format!("{} is not a regular file", real.display()));
    }
    if real.parent() != Some(dir.as_path()) {
        return err(format!("{} is outside {}", real.display(), dir.display()));
    }
    Ok(real)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Invocation {
    pub profile: String,
    pub program: String,
    pub args: Vec<String>,
}

/// `--profile <name> -- <program> [args...]` (argv without the binary name).
pub fn parse_args(argv: &[String]) -> Result<Invocation, Error> {
    match argv {
        [flag, profile, sep, program, rest @ ..] if flag == "--profile" && sep == "--" => {
            Ok(Invocation {
                profile: profile.clone(),
                program: program.clone(),
                args: rest.to_vec(),
            })
        }
        _ => err("usage: nos-sandbox-exec --profile <name> -- <program> [args...]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2(eff: bool, perm: u64, inh: u64) -> Vec<u8> {
        let mut b = (REV_2 | u32::from(eff)).to_le_bytes().to_vec();
        for w in [
            perm as u32,
            inh as u32,
            (perm >> 32) as u32,
            (inh >> 32) as u32,
        ] {
            b.extend(w.to_le_bytes());
        }
        b
    }

    #[test]
    fn v1_v2_v3() {
        let mut v1 = (REV_1 | 1).to_le_bytes().to_vec();
        v1.extend(0x3000u32.to_le_bytes());
        v1.extend(0u32.to_le_bytes());
        let c = parse_vfs_cap(&v1).unwrap();
        assert_eq!((c.permitted, c.inheritable, c.effective), (0x3000, 0, true));

        let c = parse_vfs_cap(&v2(true, 0x3000 | 1 << 33, 4)).unwrap();
        assert_eq!(c.permitted, 0x3000 | 1 << 33);
        assert_eq!(c.inheritable, 4);
        assert!(!parse_vfs_cap(&v2(false, 1, 0)).unwrap().effective);

        let mut v3 = v2(true, 0x2400, 0);
        v3[..4].copy_from_slice(&(REV_3 | 1).to_le_bytes());
        v3.extend(0u32.to_le_bytes());
        assert_eq!(parse_vfs_cap(&v3).unwrap().permitted, 0x2400);
        v3[20] = 1;
        assert!(parse_vfs_cap(&v3).unwrap_err().0.contains("rootid"));
    }

    #[test]
    fn rejects_garbage_and_short() {
        assert!(parse_vfs_cap(&[]).is_err());
        assert!(parse_vfs_cap(&[1, 2, 3]).is_err());
        assert!(parse_vfs_cap(&[0, 0, 0, 0x09, 0, 0, 0, 0]).is_err());
        assert!(parse_vfs_cap(&v2(true, 1, 0)[..19]).is_err());
        let mut long = v2(true, 1, 0);
        long.push(0);
        assert!(parse_vfs_cap(&long).is_err());
        let mut v1 = REV_1.to_le_bytes().to_vec();
        v1.extend([0; 4]);
        assert!(parse_vfs_cap(&v1).is_err());
    }

    #[test]
    fn target_must_be_a_regular_file_inside_dir() {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir -- test-only, pid-named dir in a unit test
        let tmp = std::env::temp_dir().join(format!("nos-sandbox-test-{}", std::process::id()));
        let dir = tmp.join("bin");
        std::fs::create_dir_all(&dir).unwrap();
        let other = tmp.join("other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(dir.join("ok"), b"x").unwrap();
        std::fs::write(other.join("evil"), b"x").unwrap();
        std::os::unix::fs::symlink(other.join("evil"), dir.join("link")).unwrap();

        assert_eq!(
            check_target(&dir.join("ok"), &dir).unwrap(),
            dir.canonicalize().unwrap().join("ok")
        );
        assert!(check_target(&other.join("evil"), &dir).is_err());
        assert!(check_target(&dir.join("link"), &dir).is_err());
        assert!(check_target(&dir, &dir).is_err());
        assert!(check_target(&dir.join("missing"), &dir).is_err());
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn args() {
        let a = |s: &[&str]| s.iter().map(ToString::to_string).collect::<Vec<_>>();
        let i = parse_args(&a(&["--profile", "ribd", "--", "/x/p", "--a", "b"])).unwrap();
        assert_eq!(i.profile, "ribd");
        assert_eq!(i.program, "/x/p");
        assert_eq!(i.args, a(&["--a", "b"]));
        assert!(parse_args(&a(&["--profile", "ribd", "/x/p"])).is_err());
        assert!(parse_args(&a(&["--", "/x/p"])).is_err());
        assert!(parse_args(&[]).is_err());
    }
}
