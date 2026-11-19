//! Proves the BPF kills (not just assembles): a forked child applies NNP + the filter.
#![allow(unsafe_code, reason = "fork/prctl/ptrace in a test (#1217)")]

use nos_sandbox::seccomp::{deny_list, install};

/// Forks, runs `f` in the child (`_exit(0)` if it returns), returns the wait status.
fn in_child(f: impl FnOnce()) -> libc::c_int {
    // SAFETY: the child only makes syscalls and `_exit`s; the filter is built beforehand.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only fork (#1217)
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only _exit in the child (#1217)
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only waitpid on our own child (#1217)
    unsafe { libc::waitpid(pid, &raw mut st, 0) };
    st
}

#[test]
fn denied_syscall_is_sigsys_allowed_one_is_not() {
    let prog = deny_list().unwrap();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only prctl/_exit in the child (#1217)
    let setup = || unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if install(&prog).is_err() {
            libc::_exit(77);
        }
    };
    let st = in_child(|| {
        setup();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only denied syscall, must die of SIGSYS (#1217)
        unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
    });
    if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 77 {
        eprintln!("seccomp not permitted here, skipping");
        return;
    }
    assert!(
        libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGSYS,
        "{st:#x}"
    );
    let st = in_child(|| {
        setup();
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- test-only allowed syscall (#1217)
        unsafe { libc::getpid() };
    });
    assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "{st:#x}");
}
