//! `libnss_nos.so.2`: glibc NSS `passwd` database over `/run/nos-users/passwd`, the file
//! `nos-configd` writes (#999, docs/architecture/pam.md). Read-only, no network, no secrets.

pub mod parse;

use libnss::interop::Response;
use libnss::libnss_passwd_hooks;
use libnss::passwd::{Passwd, PasswdHooks};
use std::panic::catch_unwind;

/// Fixed: glibc loads this into sshd, `ls` and everything else; nothing is configurable.
pub const PASSWD_FILE: &str = "/run/nos-users/passwd";

struct NosPasswd;

// The only unsafe: the macro expands to `extern "C"` NSS entry points; no hand-written FFI.
#[allow(
    unsafe_code,
    reason = "libnss_passwd_hooks! expands to extern \"C\" NSS entry points"
)]
mod export {
    use super::{libnss_passwd_hooks, NosPasswd};
    libnss_passwd_hooks!(nos, NosPasswd);
}

fn to_passwd(e: parse::Entry) -> Passwd {
    Passwd {
        name: e.name,
        passwd: "x".into(),
        uid: e.uid,
        gid: e.gid,
        gecos: String::new(),
        dir: e.dir,
        shell: e.shell,
    }
}

/// `Unavail` when the file cannot be read, `NotFound` when `pick` finds nothing; a
/// panic must not unwind through `extern "C"` into the caller, so it is `Unavail` too.
fn lookup<T>(path: &str, pick: impl FnOnce(&str) -> Option<T>) -> Response<T> {
    match catch_unwind(std::panic::AssertUnwindSafe(|| {
        std::fs::read_to_string(path).map(|t| pick(&t))
    })) {
        Ok(Ok(Some(v))) => Response::Success(v),
        Ok(Ok(None)) => Response::NotFound,
        _ => Response::Unavail,
    }
}

fn all(path: &str) -> Response<Vec<Passwd>> {
    lookup(path, |t| {
        Some(parse::entries(t).into_iter().map(to_passwd).collect())
    })
}

fn by_name(path: &str, name: &str) -> Response<Passwd> {
    lookup(path, |t| parse::by_name(t, name).map(to_passwd))
}

fn by_uid(path: &str, uid: u32) -> Response<Passwd> {
    lookup(path, |t| parse::by_uid(t, uid).map(to_passwd))
}

impl PasswdHooks for NosPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        all(PASSWD_FILE)
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        by_uid(PASSWD_FILE, uid)
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        by_name(PASSWD_FILE, &name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "alice:20000:20000:/nonexistent:/usr/bin/nos\n").unwrap();
        f
    }

    #[test]
    fn lookups_against_a_file() {
        let f = file();
        let p = f.path().to_str().unwrap();
        let Response::Success(a) = by_name(p, "alice") else {
            panic!("alice")
        };
        assert_eq!(
            (a.uid, a.gid, a.shell.as_str()),
            (20000, 20000, "/usr/bin/nos")
        );
        assert!(matches!(by_uid(p, 20000), Response::Success(_)));
        assert!(matches!(by_name(p, "bob"), Response::NotFound));
        assert!(matches!(by_uid(p, 7), Response::NotFound));
        assert!(matches!(all(p), Response::Success(v) if v.len() == 1));
    }

    #[test]
    fn a_missing_file_is_unavail() {
        assert!(matches!(by_name("/nonexistent/x", "a"), Response::Unavail));
        assert!(matches!(all("/nonexistent/x"), Response::Unavail));
    }

    #[test]
    fn a_panic_is_unavail() {
        let f = file();
        let r: Response<u8> = lookup(f.path().to_str().unwrap(), |_| panic!("boom"));
        assert!(matches!(r, Response::Unavail));
    }

    /// A buffer too small for the entry: libnss reports `ERANGE` via `TryAgain`.
    #[test]
    #[allow(unsafe_code, reason = "calls the C-buffer conversion libnss exposes")]
    fn a_tiny_buffer_is_erange() {
        let f = file();
        let r = by_name(f.path().to_str().unwrap(), "alice");
        let mut out: libnss::passwd::CPasswd = unsafe { std::mem::zeroed() };
        let mut buf = [0 as libc::c_char; 4];
        let mut errno = 0;
        let st = unsafe { r.to_c(&raw mut out, buf.as_mut_ptr(), buf.len(), &raw mut errno) };
        assert_eq!(
            (st, errno),
            (libnss::interop::NssStatus::TryAgain, libc::ERANGE)
        );
    }
}
