//! Kernel uapi values, each from the header named in its group comment. The
//! byte tests in `encode.rs`/`decode.rs` pin them.

// include/uapi/linux/rtnetlink.h
pub const RTM_NEWQDISC: u16 = 36;
pub const RTM_NEWTFILTER: u16 = 44;
pub const RTM_DELTFILTER: u16 = 45;
pub const RTM_GETTFILTER: u16 = 46;
pub const RTM_DELCHAIN: u16 = 101;
pub const TCA_KIND: u16 = 1;
pub const TCA_OPTIONS: u16 = 2;
pub const TCA_CHAIN: u16 = 11;

// include/uapi/linux/netlink.h
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLA_F_NESTED: u16 = 1 << 15;
/// `NLA_TYPE_MASK`: the type without `NLA_F_NESTED`/`NLA_F_NET_BYTEORDER`.
pub const NLA_TYPE_MASK: u16 = 0x3FFF;

// include/uapi/linux/pkt_sched.h: `TC_H_CLSACT` and its two hooks.
pub const CLSACT: u32 = 0xFFFF_FFF1;
pub const HOOK_INGRESS: u32 = 0xFFFF_FFF2;
pub const HOOK_EGRESS: u32 = 0xFFFF_FFF3;

// include/uapi/linux/if_ether.h
pub const ETH_P_ALL: u16 = 0x0003;
pub const ETH_P_802_2: u16 = 0x0004;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_IPV6: u16 = 0x86DD;

// include/uapi/linux/pkt_cls.h: actions
pub const TCA_ACT_KIND: u16 = 1;
pub const TCA_ACT_OPTIONS: u16 = 2;
pub const TCA_ACT_STATS: u16 = 4;
pub const TCA_ACT_COOKIE: u16 = 6;
pub const TC_COOKIE_MAX_SIZE: usize = 16;
pub const TC_ACT_UNSPEC: i32 = -1;
pub const TC_ACT_OK: i32 = 0;
pub const TC_ACT_SHOT: i32 = 2;
pub const TC_ACT_PIPE: i32 = 3;
pub const TC_ACT_STOLEN: i32 = 4;
/// `__TC_ACT_EXT(2)`: the opcode above bit 28, the chain in the low 28 bits.
pub const TC_ACT_GOTO_CHAIN: u32 = 2 << 28;
pub const TC_ACT_EXT_VAL_MASK: u32 = (1 << 28) - 1;

// include/uapi/linux/pkt_cls.h: flower
pub const TCA_FLOWER_ACT: u16 = 3;
pub const TCA_FLOWER_KEY_ETH_DST: u16 = 4;
pub const TCA_FLOWER_KEY_ETH_DST_MASK: u16 = 5;
pub const TCA_FLOWER_KEY_ETH_TYPE: u16 = 8;
pub const TCA_FLOWER_KEY_IP_PROTO: u16 = 9;
pub const TCA_FLOWER_KEY_IPV4_SRC: u16 = 10;
pub const TCA_FLOWER_KEY_IPV4_SRC_MASK: u16 = 11;
pub const TCA_FLOWER_KEY_IPV4_DST: u16 = 12;
pub const TCA_FLOWER_KEY_IPV4_DST_MASK: u16 = 13;
pub const TCA_FLOWER_KEY_IPV6_SRC: u16 = 14;
pub const TCA_FLOWER_KEY_IPV6_SRC_MASK: u16 = 15;
pub const TCA_FLOWER_KEY_IPV6_DST: u16 = 16;
pub const TCA_FLOWER_KEY_IPV6_DST_MASK: u16 = 17;
pub const TCA_FLOWER_KEY_TCP_SRC: u16 = 18;
pub const TCA_FLOWER_KEY_TCP_DST: u16 = 19;
pub const TCA_FLOWER_KEY_UDP_SRC: u16 = 20;
pub const TCA_FLOWER_KEY_UDP_DST: u16 = 21;
pub const TCA_FLOWER_KEY_VLAN_ID: u16 = 23;
pub const TCA_FLOWER_KEY_ENC_IPV4_SRC: u16 = 27;
pub const TCA_FLOWER_KEY_ENC_IPV6_SRC: u16 = 31;
pub const TCA_FLOWER_KEY_IP_TOS: u16 = 73;
pub const TCA_FLOWER_KEY_IP_TOS_MASK: u16 = 74;
pub const TCA_FLOWER_KEY_FLAGS: u16 = 47;
pub const TCA_FLOWER_KEY_FLAGS_MASK: u16 = 48;
pub const TCA_FLOWER_KEY_ICMPV4_CODE: u16 = 49;
pub const TCA_FLOWER_KEY_ICMPV4_TYPE: u16 = 51;
pub const TCA_FLOWER_KEY_ICMPV6_CODE: u16 = 53;
pub const TCA_FLOWER_KEY_ICMPV6_TYPE: u16 = 55;
pub const TCA_FLOWER_KEY_TCP_FLAGS: u16 = 71;
pub const TCA_FLOWER_KEY_TCP_FLAGS_MASK: u16 = 72;
pub const TCA_FLOWER_KEY_PORT_SRC_MIN: u16 = 87;
pub const TCA_FLOWER_KEY_PORT_SRC_MAX: u16 = 88;
pub const TCA_FLOWER_KEY_PORT_DST_MIN: u16 = 89;
pub const TCA_FLOWER_KEY_PORT_DST_MAX: u16 = 90;

// include/uapi/linux/pkt_cls.h: fw
pub const TCA_FW_ACT: u16 = 4;
pub const TCA_FW_MASK: u16 = 5;

// include/uapi/linux/tc_act/tc_gact.h, tc_skbedit.h
pub const TCA_GACT_PARMS: u16 = 2;
pub const TCA_SKBEDIT_PARMS: u16 = 2;
pub const TCA_SKBEDIT_MARK: u16 = 5;
pub const TCA_SKBEDIT_MASK: u16 = 8;

// include/uapi/linux/pkt_sched.h: `act_police` (`struct tc_police` is 56 bytes)
pub const TCA_POLICE_TBF: u16 = 1;
pub const TCA_POLICE_RATE: u16 = 2;
pub const TCA_POLICE_RESULT: u16 = 5;
pub const TCA_POLICE_RATE64: u16 = 8;
pub const TCA_POLICE_PKTRATE64: u16 = 10;
pub const TCA_POLICE_PKTBURST64: u16 = 11;

// include/uapi/linux/tc_act/tc_pedit.h
pub const TCA_PEDIT_PARMS_EX: u16 = 4;
pub const TCA_PEDIT_KEYS_EX: u16 = 5;
pub const TCA_PEDIT_KEY_EX: u16 = 6;
pub const TCA_PEDIT_KEY_EX_HTYPE: u16 = 1;
pub const TCA_PEDIT_KEY_EX_CMD: u16 = 2;
pub const TCA_PEDIT_HDR_TYPE_IP4: u16 = 2;
pub const TCA_PEDIT_HDR_TYPE_IP6: u16 = 3;
pub const TCA_PEDIT_CMD_SET: u16 = 0;

// include/uapi/linux/tc_act/tc_csum.h
pub const TCA_CSUM_PARMS: u16 = 1;
pub const TCA_CSUM_UPDATE_FLAG_IPV4HDR: u32 = 1;

// include/uapi/linux/tc_act/tc_mirred.h
pub const TCA_MIRRED_PARMS: u16 = 2;
pub const TCA_EGRESS_REDIR: i32 = 1;

// include/uapi/linux/tc_act/tc_sample.h
pub const TCA_SAMPLE_PARMS: u16 = 2;
pub const TCA_SAMPLE_RATE: u16 = 3;
pub const TCA_SAMPLE_TRUNC_SIZE: u16 = 4;
pub const TCA_SAMPLE_PSAMPLE_GROUP: u16 = 5;

// include/uapi/linux/genetlink.h
pub const GENL_ID_CTRL: u16 = 16;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_MAXATTR: u16 = 5;
pub const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
pub const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
pub const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

// include/uapi/linux/psample.h
pub const PSAMPLE_CMD_SAMPLE: u8 = 0;
pub const PSAMPLE_ATTR_IIFINDEX: u16 = 0;
pub const PSAMPLE_ATTR_OIFINDEX: u16 = 1;
pub const PSAMPLE_ATTR_SAMPLE_GROUP: u16 = 3;
pub const PSAMPLE_ATTR_DATA: u16 = 6;
pub const PSAMPLE_ATTR_USER_COOKIE: u16 = 15;

// include/uapi/linux/gen_stats.h
pub const TCA_STATS_BASIC: u16 = 1;
pub const TCA_STATS_PKT64: u16 = 8;

// include/uapi/linux/in.h
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
