//! uapi values, read from `linux/rtnetlink.h`, `linux/nexthop.h`,
//! `linux/lwtunnel.h` and `linux/mpls_iptunnel.h`.

pub const RTM_NEWNEXTHOP: u16 = 104;
pub const RTM_DELNEXTHOP: u16 = 105;
pub const RTM_GETNEXTHOP: u16 = 106;

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLA_F_NESTED: u16 = 0x8000;

pub const NHA_ID: u16 = 1;
pub const NHA_GROUP: u16 = 2;
pub const NHA_BLACKHOLE: u16 = 4;
pub const NHA_OIF: u16 = 5;
pub const NHA_GATEWAY: u16 = 6;
pub const NHA_ENCAP_TYPE: u16 = 7;
pub const NHA_ENCAP: u16 = 8;
pub const NHA_FDB: u16 = 11;

pub const LWTUNNEL_ENCAP_MPLS: u16 = 1;
pub const MPLS_IPTUNNEL_DST: u16 = 1;

/// `nhmsg.nh_flags`: the gateway need not be on-link.
pub const RTNH_F_ONLINK: u32 = 4;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const RTPROT_STATIC: u8 = 4;
