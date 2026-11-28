// nos-radv: IPv6 Router Advertisements (RFC 4861/4191/8106) over a raw ICMPv6
// socket per advertising link (see radv/CLAUDE.md). Never touches rtnetlink.

pub mod link;
pub mod link_client;
pub mod packet;
pub mod reconcile;
pub mod schedule;
pub mod socket;
