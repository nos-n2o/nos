//! Capability restriction: `nos-sshd` runs as uid 0 but keeps only what `sshd`
//! needs, and every `sshd` it spawns inherits that bounding set (#994).
//!
//! `PR_CAPBSET_DROP` alone only limits what a later `execve` can gain, so the
//! process also `capset`s its own sets down to the same list.

use std::io;

pub const CAP_CHOWN: u32 = 0;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_SYS_CHROOT: u32 = 18;
pub const CAP_AUDIT_WRITE: u32 = 29;

/// What stays: privilege separation (`SETUID`/`SETGID`/`SYS_CHROOT`/`CHOWN` for the
/// pty), `SO_BINDTODEVICE` (`NET_RAW`), low ports, audit, and signalling the
/// children. Deliberately no `DAC_OVERRIDE`/`FOWNER` (see `ssh/CLAUDE.md`).
pub const KEEP: [u32; 8] = [
    CAP_SETUID,
    CAP_SETGID,
    CAP_SYS_CHROOT,
    CAP_CHOWN,
    CAP_NET_RAW,
    CAP_NET_BIND_SERVICE,
    CAP_AUDIT_WRITE,
    CAP_KILL,
];

/// Every capability number up to `last_cap` that is not in `keep`.
pub fn to_drop(last_cap: u32, keep: &[u32]) -> Vec<u32> {
    (0..=last_cap).filter(|c| !keep.contains(c)).collect()
}

/// `keep` as the two 32-bit words of a v3 capability set.
pub fn mask(keep: &[u32]) -> [u32; 2] {
    let mut m = [0u32; 2];
    for c in keep {
        m[(*c / 32) as usize & 1] |= 1 << (c % 32);
    }
    m
}

fn last_cap() -> io::Result<u32> {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
        .trim()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Drops everything outside [`KEEP`] from the bounding set, then from this
/// process's own sets. Fatal on failure: the caller must exit rather than run
/// with the full root set. Run before any socket is opened.
#[allow(
    unsafe_code,
    reason = "prctl/capset have no safe wrapper in libc or nix's feature set here"
)]
pub fn restrict() -> io::Result<()> {
    for cap in to_drop(last_cap()?, &KEEP) {
        // SAFETY: PR_CAPBSET_READ/DROP take one integer argument and touch no memory.
        let held = unsafe { libc::prctl(libc::PR_CAPBSET_READ, libc::c_ulong::from(cap), 0, 0, 0) };
        if held == 0 {
            continue; // already absent from the bounding set
        }
        // SAFETY: as above.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut header = Header {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // SAFETY: `header` and `data` are valid, correctly sized (`data` is two
    // structs for version 3) and live across both calls.
    unsafe {
        if libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let keep = mask(&KEEP);
    for (d, k) in data.iter_mut().zip(keep) {
        // Intersect with what is held now, so an unprivileged dev run keeps working.
        d.permitted &= k;
        d.effective &= d.permitted;
        d.inheritable &= d.permitted;
    }
    // SAFETY: as above.
    unsafe {
        if libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_everything_but_keep() {
        for last in [21, 40] {
            let drop = to_drop(last, &KEEP);
            assert!(KEEP.iter().all(|k| !drop.contains(k)));
            // `last + 1` capabilities exist; KEEP are all <= 29, so for 21 only
            // those below 22 count as present.
            let present_keep = KEEP.iter().filter(|k| **k <= last).count();
            assert_eq!(drop.len(), last as usize + 1 - present_keep);
            assert!(drop.contains(&1)); // CAP_DAC_OVERRIDE
            assert!(drop.contains(&3)); // CAP_FOWNER
        }
    }

    #[test]
    fn mask_sets_exactly_the_kept_bits() {
        let [lo, hi] = mask(&KEEP);
        assert_eq!(hi, 0);
        assert_eq!(lo.count_ones() as usize, KEEP.len());
        assert_ne!(lo & (1 << CAP_NET_RAW), 0);
        assert_eq!(lo & (1 << 1), 0);
        assert_eq!(mask(&[33]), [0, 2]);
    }
}
