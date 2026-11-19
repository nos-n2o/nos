//! Proves the BPF kills (not just assembles): a forked child applies NNP + the filter.
#![allow(unsafe_code, reason = "fork/prctl/ptrace in a test (#1217)")]

use nos_sandbox::seccomp::{deny_list, install};

/// Forks, runs `f` in the child (`_exit(0)` if it returns), returns the wait status.
fn in_child(f: impl FnOnce()) -> libc::c_int {
    // SAFETY: the child only makes syscalls and `_exit`s; the filter is built beforehand.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &raw mut st, 0) };
    st
}

#[test]
fn denied_syscall_is_sigsys_allowed_one_is_not() {
    let prog = deny_list().unwrap();
    let setup = || unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if install(&prog).is_err() {
            libc::_exit(77);
        }
    };
    let st = in_child(|| {
        setup();
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
        unsafe { libc::getpid() };
    });
    assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "{st:#x}");
}
