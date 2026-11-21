//! Thin FFI: the only `unsafe` in the crate. No logic worth a mock; `nos-e2e`'s
//! `sandbox-nnp` phase is its test.

use std::ffi::CString;
use std::io;
use std::path::Path;

use crate::{parse_vfs_cap, Error, FileCaps};

const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn errno(what: &str) -> Error {
    Error(format!("{what}: {}", io::Error::last_os_error()))
}

fn cstr(s: &[u8]) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error("string contains NUL".into()))
}

/// The target's file capabilities; no xattr (`ENODATA`/`ENOTSUP`) is the empty set.
pub fn read_file_caps(path: &Path) -> Result<FileCaps, Error> {
    use std::os::unix::ffi::OsStrExt;
    let p = cstr(path.as_os_str().as_bytes())?;
    let mut buf = [0u8; 64];
    // SAFETY: valid NUL-terminated strings and a writable buffer of the given length.
    #[allow(unsafe_code, reason = "getxattr FFI, bounded buffer (#1211)")]
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- bounded getxattr
    let n = unsafe {
        libc::getxattr(
            p.as_ptr(),
            c"security.capability".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return match io::Error::last_os_error().raw_os_error() {
            Some(libc::ENODATA | libc::ENOTSUP) => Ok(FileCaps::default()),
            _ => Err(errno("getxattr security.capability")),
        };
    }
    parse_vfs_cap(&buf[..n as usize])
}

/// Trims this process to the target's permitted set (inheritable emptied): under
/// `NO_NEW_PRIVS` the exec'd file's permitted set is clipped to ours, so this is
/// exactly the ceiling the target's own file caps can reach. Lowering needs no
/// privilege; bits we do not hold are dropped, never gained.
pub fn set_caps(permitted: u64) -> Result<(), Error> {
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: header and two-element data array match capget(2) for version 3.
    #[allow(unsafe_code, reason = "capget FFI (#1211)")]
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- capget
    let r = unsafe { libc::syscall(libc::SYS_capget, &mut hdr, data.as_mut_ptr()) };
    if r != 0 {
        return Err(errno("capget"));
    }
    let have = u64::from(data[0].permitted) | u64::from(data[1].permitted) << 32;
    let keep = permitted & have;
    for (d, w) in data.iter_mut().zip([keep as u32, (keep >> 32) as u32]) {
        *d = CapData {
            effective: w,
            permitted: w,
            inheritable: 0,
        };
    }
    // SAFETY: as above, for capset(2).
    #[allow(unsafe_code, reason = "capset FFI (#1211)")]
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- capset
    let r = unsafe { libc::syscall(libc::SYS_capset, &mut hdr, data.as_ptr()) };
    if r != 0 {
        return Err(errno("capset"));
    }
    Ok(())
}

fn prctl(opt: libc::c_int, a: libc::c_ulong, what: &str) -> Result<(), Error> {
    // SAFETY: a prctl with integer arguments.
    #[allow(unsafe_code, reason = "prctl, integer args only (#1211)")]
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- integer-arg prctl
    let r = unsafe { libc::prctl(opt, a, 0, 0, 0) };
    if r != 0 {
        return Err(errno(what));
    }
    Ok(())
}

pub fn clear_ambient() -> Result<(), Error> {
    prctl(
        PR_CAP_AMBIENT,
        PR_CAP_AMBIENT_CLEAR_ALL,
        "PR_CAP_AMBIENT_CLEAR_ALL",
    )
}

pub fn no_new_privs() -> Result<(), Error> {
    prctl(PR_SET_NO_NEW_PRIVS, 1, "PR_SET_NO_NEW_PRIVS")
}

/// `execv` (argv[0] = `path`); only returns, with the error, on failure.
pub fn exec(path: &Path, args: &[String]) -> Error {
    use std::os::unix::ffi::OsStrExt;
    let argv = std::iter::once(path.as_os_str().as_bytes())
        .chain(args.iter().map(|a| a.as_bytes()))
        .map(cstr)
        .collect::<Result<Vec<_>, _>>();
    let (p, argv) = match (cstr(path.as_os_str().as_bytes()), argv) {
        (Ok(p), Ok(a)) => (p, a),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: NUL-terminated path and a NULL-terminated argv that outlive the call.
    #[allow(unsafe_code, reason = "execv FFI (#1211)")]
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- execv
    unsafe {
        libc::execv(p.as_ptr(), ptrs.as_ptr());
    }
    errno("execv")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_xattr_is_the_empty_set_and_missing_file_errors() {
        assert_eq!(
            read_file_caps(Path::new("/proc/self/exe")).map(|c| c.inheritable),
            Ok(0)
        );
        assert!(read_file_caps(Path::new("/nonexistent/x")).is_err());
        assert!(read_file_caps(Path::new("/proc/\0")).is_err());
    }

    /// Process-wide and irrevocable, so one test: lower caps, clear ambient, set NNP,
    /// then a failing exec returns its error instead of replacing the test binary.
    #[test]
    fn trims_then_exec_failure_returns() {
        set_caps(0).unwrap();
        clear_ambient().unwrap();
        no_new_privs().unwrap();
        let e = exec(Path::new("/nonexistent/x"), &["a".into()]);
        assert!(e.0.starts_with("execv"), "{e}");
        assert!(exec(Path::new("/bin/true"), &["a\0".into()])
            .0
            .contains("NUL"));
    }
}
