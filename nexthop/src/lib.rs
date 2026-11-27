//! Hand-encoded Linux nexthop objects (`RTM_NEWNEXTHOP`, `RTM_DELNEXTHOP`,
//! `RTM_GETNEXTHOP` dumps) over a plain `NETLINK_ROUTE` socket: gateways with
//! an optional MPLS label stack, groups with weights, and FDB nexthops.
//! `netlink-packet-route` has no nexthop messages, hence this crate. A leaf
//! with no NOS dependencies, like `nos-tc`, shared by `nos-fdbd` (and later
//! `nos-ribd`).
//!
//! [`send`] and [`dump`] block: call them from `spawn_blocking`.

mod consts;
mod decode;
mod encode;
mod socket;

pub use decode::NexthopRecord;
pub use encode::{encode, Gateway, Group, Nexthop, MAX_LABELS};
pub use socket::{dump, send};
