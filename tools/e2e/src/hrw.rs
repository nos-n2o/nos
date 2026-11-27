//! The RFC 8584 §3.2 HRW DF of `evpn-dataplane`'s segment, computed by the
//! harness: an oracle independent of `nos-fdb` (it would pick the same winner
//! if `fdb::df::hrw_weight` were wrong). The winner depends on the lab's
//! addresses (`lab::shift`), so the phase asks here instead of hard-coding it.

use crate::consts::{ESI, EVPN_VNI, IP_A, IP_B};
use crate::router::{Id, A, B};

/// RFC 8584 §3.2: `D` = CRC-32 over the 4-octet VNI then the 10-octet ESI;
/// only the low 31 bits of the result survive, so wrapping u64 is exact.
pub fn hrw_weight(vni: u32, esi: [u8; 10], si: u32) -> u32 {
    const M: u64 = 1_103_515_245;
    let mut h = crc32fast::Hasher::new();
    h.update(&vni.to_be_bytes());
    h.update(&esi);
    let d = u64::from(h.finalize());
    let inner = M.wrapping_mul(u64::from(si)).wrapping_add(12345) ^ d;
    u32::try_from(M.wrapping_mul(inner).wrapping_add(12345) & 0x7fff_ffff).unwrap_or(0)
}

/// `00:11:..:99` as the ten ESI octets.
pub fn esi_bytes(s: &str) -> [u8; 10] {
    let parts: Vec<&str> = s.split(':').collect();
    assert_eq!(parts.len(), 10, "ESI {s:?} is not 10 octets");
    let mut out = [0; 10];
    for (o, p) in out.iter_mut().zip(parts) {
        *o = u8::from_str_radix(p, 16).expect("ESI octet");
    }
    out
}

fn weight(ip: &str, vni: u32, esi: [u8; 10]) -> u32 {
    let v4: std::net::Ipv4Addr = ip.parse().expect("IPv4 PE address");
    hrw_weight(vni, esi, u32::from(v4))
}

/// True when the PE at `ip_a` (the lower address) wins HRW over `ip_b`; a tie
/// goes to the lower address.
fn a_wins(ip_a: &str, ip_b: &str, vni: u32, esi: [u8; 10]) -> bool {
    weight(ip_a, vni, esi) >= weight(ip_b, vni, esi)
}

/// The HRW DF of `ESI`/`EVPN_VNI` between router-a and router-b in this lab.
pub fn df_for_lab() -> Id {
    if a_wins(IP_A.s(), IP_B.s(), EVPN_VNI, esi_bytes(ESI)) {
        A
    } else {
        B
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::{shift, LABS};

    const E: [u8; 10] = [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];

    #[test]
    fn esi_parses() {
        assert_eq!(esi_bytes(ESI), E);
    }

    /// The vectors `fdb/src/df.rs` pins, computed independently with Python.
    #[test]
    fn matches_the_hand_computed_vectors() {
        for (vni, want) in [
            (10100, [156_340_126, 942_677_242, 180_950_870]),
            (10101, [268_822_238, 545_567_674, 1_620_906_902]),
        ] {
            for (ip, w) in ["192.0.2.1", "192.0.2.5", "192.0.2.9"]
                .into_iter()
                .zip(want)
            {
                assert_eq!(weight(ip, vni, E), w, "{ip} for VNI {vni}");
            }
        }
    }

    /// Winners per lab: a change of ESI, VNI or the addresses shows up here.
    #[test]
    fn winners_for_labs_0_1_2() {
        let w = |k, ip: crate::lab::Addr| weight(&shift(ip.0, k), EVPN_VNI, E);
        assert_eq!((w(0, IP_A), w(0, IP_B)), (51_651_125, 1_988_780_236));
        assert_eq!((w(1, IP_A), w(1, IP_B)), (127_017_525, 1_852_858_572));
        assert_eq!((w(2, IP_A), w(2, IP_B)), (2_138_579_509, 1_083_072_716));
        let a_wins_in: Vec<bool> = (0..LABS)
            .map(|k| a_wins(&shift(IP_A.0, k), &shift(IP_B.0, k), EVPN_VNI, E))
            .collect();
        // router-b on labs 0 and 1, router-a on lab 2.
        assert_eq!(a_wins_in, [false, false, true]);
    }

    /// Lab 0 (CI): HRW elects router-b where modulo (10100 % 2 == 0) elects
    /// router-a, so the phase still proves HRW is not modulo.
    #[test]
    fn lab_0_hrw_differs_from_modulo() {
        assert_eq!(EVPN_VNI % 2, 0);
        assert!(!a_wins(IP_A.0, IP_B.0, EVPN_VNI, E));
    }
}
