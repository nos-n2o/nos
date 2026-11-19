//! The seccomp deny-list (#1217): every syscall a daemon never legitimately needs
//! kills the process with `SIGSYS` (`SECCOMP_RET_KILL_PROCESS`); everything else is
//! allowed. Built by `seccompiler` (rust-vmm), never hand-rolled BPF, except the
//! three-instruction x32 guard below. Rationale per syscall: docs/architecture/ipc-security.md.

use std::collections::BTreeMap;

use seccompiler::{sock_filter, BpfProgram, SeccompAction, SeccompFilter, TargetArch};

use crate::Error;

#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("nos-sandbox: no seccomp deny-list for this architecture (no silent no-op filter)");

/// Denied syscalls. `unshare`/`setns` (VRF/netns) and `clone3` (tokio/glibc) stay allowed;
/// `execve` stays allowed (the trampoline execs after installing the filter).
pub const DENIED: &[(&str, i64)] = &[
    ("ptrace", libc::SYS_ptrace),
    ("process_vm_readv", libc::SYS_process_vm_readv),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("personality", libc::SYS_personality),
    ("kexec_load", libc::SYS_kexec_load),
    ("kexec_file_load", libc::SYS_kexec_file_load),
    ("reboot", libc::SYS_reboot),
    ("init_module", libc::SYS_init_module),
    ("finit_module", libc::SYS_finit_module),
    ("delete_module", libc::SYS_delete_module),
    ("mount", libc::SYS_mount),
    ("umount2", libc::SYS_umount2),
    ("pivot_root", libc::SYS_pivot_root),
    ("swapon", libc::SYS_swapon),
    ("swapoff", libc::SYS_swapoff),
    ("bpf", libc::SYS_bpf),
    ("perf_event_open", libc::SYS_perf_event_open),
    ("keyctl", libc::SYS_keyctl),
    ("add_key", libc::SYS_add_key),
    ("request_key", libc::SYS_request_key),
    ("userfaultfd", libc::SYS_userfaultfd),
    ("open_by_handle_at", libc::SYS_open_by_handle_at),
    ("fsopen", libc::SYS_fsopen),
    ("fsmount", libc::SYS_fsmount),
    ("move_mount", libc::SYS_move_mount),
    ("open_tree", libc::SYS_open_tree),
    ("fsconfig", libc::SYS_fsconfig),
    ("fspick", libc::SYS_fspick),
    ("mount_setattr", libc::SYS_mount_setattr),
];

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;
/// x32 sets this bit in the syscall number under `AUDIT_ARCH_X86_64`.
#[cfg(target_arch = "x86_64")]
const X32_BIT: u32 = 0x4000_0000;

/// `ld nr; jge X32_BIT -> kill; (fall through)`. Prepending keeps the rest's relative jumps.
#[cfg(target_arch = "x86_64")]
fn x32_guard() -> [sock_filter; 3] {
    let ins = |code, jt, jf, k| sock_filter { code, jt, jf, k };
    [
        ins(BPF_LD_W_ABS, 0, 0, 0),
        ins(BPF_JGE_K, 0, 1, X32_BIT),
        ins(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
    ]
}

/// Pure: builds the program, installs nothing.
pub fn deny_list() -> Result<BpfProgram, Error> {
    let rules: BTreeMap<_, _> = DENIED.iter().map(|&(_, nr)| (nr, vec![])).collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        ARCH,
    )
    .map_err(|e| Error(format!("seccomp filter: {e}")))?;
    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| Error(format!("seccomp compile: {e}")))?;
    #[cfg(target_arch = "x86_64")]
    let prog = x32_guard().into_iter().chain(prog).collect();
    Ok(prog)
}

/// Installs on the calling thread (single-threaded trampoline, so no TSYNC).
/// Needs `NO_NEW_PRIVS` already set.
pub fn install(prog: &BpfProgram) -> Result<(), Error> {
    seccompiler::apply_filter(prog).map_err(|e| Error(format!("seccomp install: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_names_are_distinct() {
        let prog = deny_list().unwrap();
        assert!(prog.len() > DENIED.len());
        let mut nrs: Vec<_> = DENIED.iter().map(|d| d.1).collect();
        nrs.sort_unstable();
        nrs.dedup();
        assert_eq!(nrs.len(), DENIED.len());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_guard_comes_first_then_the_arch_check() {
        let p = deny_list().unwrap();
        assert_eq!((p[0].code, p[0].k), (BPF_LD_W_ABS, 0));
        assert_eq!((p[1].code, p[1].k), (BPF_JGE_K, X32_BIT));
        assert_eq!(
            (p[2].code, p[2].k),
            (BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS)
        );
        // seccompiler's own program starts by loading the arch word (offset 4).
        assert_eq!((p[3].code, p[3].k), (BPF_LD_W_ABS, 4));
    }
}
