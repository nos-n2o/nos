//! VPN-IPv4/IPv6 (RFC 4364, RFC 4659) wire pieces: the SAFI 128 NLRI codec
//! and the Route Target / Site of Origin extended-community helpers.
//! The family-agnostic VRF import surface (`VrfSet`, #579) lives here too;
//! the unicast import itself is `rib::vpn_import`.

mod ext_comm;
mod nlri;
mod vrf;

pub use crate::evpn::{format_ext_community, format_rd, Rd};
pub use ext_comm::{
    format_soo, has_soo, is_route_target, route_targets, rt, sites_of_origin, soo_from_rt,
};
pub use nlri::{
    decode_next_hop, decode_vpn_reach, decode_vpn_unreach, encode_next_hop, encode_vpn_reach,
    encode_vpn_unreach,
};
pub use vrf::{Vrf, VrfSet};

use ipnet::IpNet;

/// A VPN route's identity (RFC 4364 section 4.3.5): routes with different
/// RDs never compete, so the decision key is the full (RD, NLRI). Generic so
/// VPN Flowspec (#574) keys `VpnKey<FlowSpec>` the same way.
pub type VpnKey<T> = (Rd, T);

/// One labelled VPN route (RFC 4364 section 4.3.4): the label stack, the
/// Route Distinguisher and the customer prefix. `labels` is empty for a
/// withdrawal (RFC 8277 section 2.4: the label field there is a fixed
/// compatibility value, not a label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnNlri {
    pub labels: Vec<u32>,
    pub rd: Rd,
    pub prefix: IpNet,
    /// RFC 7911 Path Identifier: `Some` only where the session negotiated
    /// Add-Path for this family; written before the length octet.
    pub path_id: Option<u32>,
}
