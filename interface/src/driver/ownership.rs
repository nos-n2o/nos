//! Kernel-side ownership markers (#1515): `nos-interfaced` only removes what
//! it put there, so adopting a link never strips the operator's own
//! addresses or VLAN sub-interfaces.
//!
//! - Addresses carry `IFA_PROTO` = [`ADDR_PROTO`] (kernel >= 5.18).
//! - VLAN sub-links carry `IFLA_IFALIAS` = [`LINK_ALIAS`].
//!
//! The marker lives in the kernel, so it survives a `nos-interfaced` restart
//! with no private registry. A desired entry that is already present without
//! the marker is adopted (stamped), never removed.

use nos_proto::IpNet;

/// `IFA_PROTO` value for addresses NOS added or adopted (1..=3 are kernel's).
pub const ADDR_PROTO: u8 = 0x4e;
/// `IFLA_IFALIAS` value on VLAN sub-links NOS created or adopted.
pub const LINK_ALIAS: &str = "nos";

/// Result of comparing the kernel's addresses with the desired set.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AddressPlan {
    pub to_add: Vec<IpNet>,
    pub to_remove: Vec<IpNet>,
    /// Desired and present, but not yet stamped: re-stamp, never remove.
    pub to_adopt: Vec<IpNet>,
}

/// `observed` pairs each present address with whether it carries our marker
/// (callers pass `true` for every address on a device NOS created itself).
/// Foreign addresses never reach `to_remove`.
pub fn plan_addresses(observed: &[(IpNet, bool)], desired: &[IpNet]) -> AddressPlan {
    AddressPlan {
        to_add: desired
            .iter()
            .filter(|d| !observed.iter().any(|(o, _)| o == *d))
            .copied()
            .collect(),
        to_remove: observed
            .iter()
            .filter(|(o, marked)| *marked && !desired.contains(o))
            .map(|(o, _)| *o)
            .collect(),
        to_adopt: observed
            .iter()
            .filter(|(o, marked)| !*marked && desired.contains(o))
            .map(|(o, _)| *o)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn foreign_address_is_never_removed() {
        let p = plan_addresses(&[(n("192.0.2.77/24"), false)], &[]);
        assert_eq!(p, AddressPlan::default());
    }

    #[test]
    fn owned_undesired_is_removed_and_new_added() {
        let p = plan_addresses(&[(n("10.0.0.9/24"), true)], &[n("10.0.0.2/24")]);
        assert_eq!(p.to_remove, vec![n("10.0.0.9/24")]);
        assert_eq!(p.to_add, vec![n("10.0.0.2/24")]);
    }

    #[test]
    fn prefix_change_removes_owned_old_and_adds_new() {
        let p = plan_addresses(&[(n("10.0.0.1/24"), true)], &[n("10.0.0.1/25")]);
        assert_eq!(p.to_remove, vec![n("10.0.0.1/24")]);
        assert_eq!(p.to_add, vec![n("10.0.0.1/25")]);
    }

    #[test]
    fn present_unmarked_desired_is_adopted() {
        let p = plan_addresses(&[(n("10.0.0.1/24"), false)], &[n("10.0.0.1/24")]);
        assert_eq!(p.to_adopt, vec![n("10.0.0.1/24")]);
        assert!(p.to_add.is_empty() && p.to_remove.is_empty());
    }

    #[test]
    fn marked_desired_is_untouched() {
        let p = plan_addresses(&[(n("10.0.0.1/24"), true)], &[n("10.0.0.1/24")]);
        assert_eq!(p, AddressPlan::default());
    }
}
