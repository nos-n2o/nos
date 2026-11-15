//! `nos-acld`'s IPC query protocol — backs `show acl` and `GET /v1/acl`.
//! One-shot request/event pair framed by `IpcCodec`, resolved through the
//! broker (`ServiceRef::Acl`, a single instance), like `stp`.

use std::fmt;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::schema::AclAction;

/// Which way an ACL filters on its device.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AclDirection {
    /// `acl in`: packets arriving on the device.
    In,
    /// `acl out`: packets leaving the device.
    Out,
}

/// One device an ACL is installed on.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AclAttachment {
    /// The kernel device name (`eth1`, `eth1.100`, `bond3`).
    pub interface: String,
    /// The direction it filters.
    pub direction: AclDirection,
}

/// One user rule's counters, summed over every filter it compiled to and
/// every device the ACL is attached to.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRuleStatus {
    /// The rule's name.
    pub name: String,
    /// What it does with a match.
    pub action: AclAction,
    /// `shadowed` (an earlier rule matches everything it does) or `trailing`
    /// (last rules equal to the default action): the optimiser gave the rule
    /// no filter, so its counters stay 0. `None` when it is installed.
    pub dropped: Option<String>,
    /// The priority level the rule's filters were packed into; `None` when
    /// dropped.
    pub level: Option<u32>,
    /// Packets matched.
    pub packets: u64,
    /// Bytes matched.
    pub bytes: u64,
}

/// One ACL: its compile shape, attachments and counters.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclStatus {
    /// The ACL's name.
    pub name: String,
    /// What a packet no rule matched gets.
    pub default_action: AclAction,
    /// Packets that hit the default action.
    pub default_packets: u64,
    /// Bytes that hit the default action.
    pub default_bytes: u64,
    /// Priority levels the compiled ACL uses.
    pub levels: u32,
    /// Kernel filters per attachment, the two default filters included.
    pub filters: u32,
    /// Every device it is installed on (empty: unattached, counters 0).
    pub attached: Vec<AclAttachment>,
    /// The rules, in order.
    pub rules: Vec<AclRuleStatus>,
}

/// One RFC 8955 `{numeric_op, value}` pair (mirror of `nos-bgp`'s `NumOp`):
/// `lt`/`gt`/`eq` combine as RFC 8955 Table 1, AND binds tighter than OR.
#[allow(clippy::struct_excessive_bools, reason = "the RFC's operator bits")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowNumOp {
    /// AND with the previous pair (else OR); unset on the first.
    pub and: bool,
    /// Less than `value`.
    pub lt: bool,
    /// Greater than `value`.
    pub gt: bool,
    /// Equal to `value`.
    pub eq: bool,
    /// The operand.
    pub value: u64,
}

/// One RFC 8955 `{bitmask_op, bitmask}` pair (mirror of `nos-bgp`'s `BitOp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowBitOp {
    /// AND with the previous pair (else OR); unset on the first.
    pub and: bool,
    /// Negates the result.
    pub not: bool,
    /// Match: every bit of `value` set (else any of them).
    pub m: bool,
    /// The bitmask.
    pub value: u64,
}

/// One Flow Specification component (RFC 8955 section 4.2.2, RFC 8956),
/// mirrored from `nos-bgp`'s decoded `Component` so `nos-acld` needs no BGP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowComponent {
    /// Type 1: destination prefix.
    Dest {
        /// The prefix; for IPv6 the pattern sits at bits `offset..`.
        prefix: IpNet,
        /// IPv6 pattern offset (RFC 8956); 0 for IPv4.
        offset: u8,
    },
    /// Type 2: source prefix.
    Source {
        /// The prefix; for IPv6 the pattern sits at bits `offset..`.
        prefix: IpNet,
        /// IPv6 pattern offset (RFC 8956); 0 for IPv4.
        offset: u8,
    },
    /// Type 3: IP protocol / IPv6 upper-layer protocol.
    Protocol(Vec<FlowNumOp>),
    /// Type 4: source or destination port.
    Port(Vec<FlowNumOp>),
    /// Type 5: destination port.
    DstPort(Vec<FlowNumOp>),
    /// Type 6: source port.
    SrcPort(Vec<FlowNumOp>),
    /// Type 7: ICMP type.
    IcmpType(Vec<FlowNumOp>),
    /// Type 8: ICMP code.
    IcmpCode(Vec<FlowNumOp>),
    /// Type 9: TCP flags.
    TcpFlags(Vec<FlowBitOp>),
    /// Type 10: packet length.
    PacketLen(Vec<FlowNumOp>),
    /// Type 11: DSCP.
    Dscp(Vec<FlowNumOp>),
    /// Type 12: fragment bits (`DF` 0x01, `IsF` 0x02, `FF` 0x04, `LF` 0x08).
    Fragment(Vec<FlowBitOp>),
    /// Type 13: IPv6 flow label.
    FlowLabel(Vec<FlowNumOp>),
}

/// One traffic action of a flow rule (RFC 8955 section 7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlowRuleAction {
    /// Traffic-rate in bytes per second; 0 discards.
    RateBytes(f32),
    /// Traffic-rate in packets per second; 0 discards.
    RatePackets(f32),
    /// Traffic-action: `sample` logs, `terminal` is the RFC's T bit: SET
    /// means later rules also apply (RFC 8955 section 7.3).
    TrafficAction {
        /// The S bit.
        sample: bool,
        /// The T bit.
        terminal: bool,
    },
    /// Traffic-marking: rewrite the DSCP.
    Dscp(u8),
    /// An action `nos-acld` cannot apply (a redirect): the rule is shown
    /// with this text and not installed.
    Unsupported(String),
}

impl fmt::Display for FlowRuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateBytes(r) => write!(f, "rate {r} bytes/s"),
            Self::RatePackets(r) => write!(f, "rate {r} packets/s"),
            Self::TrafficAction { sample, terminal } => {
                write!(f, "sample={sample} terminal={terminal}")
            }
            Self::Dscp(d) => write!(f, "dscp {d}"),
            Self::Unsupported(s) => f.write_str(s),
        }
    }
}

/// One Flow Specification rule as `nos-acld` lowers it to tc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowRule {
    /// The flow as text, for `show` and logs.
    pub flow: String,
    /// IPv6 flow (AFI 2), else IPv4.
    pub ipv6: bool,
    /// Components in increasing type order.
    pub components: Vec<FlowComponent>,
    /// Actions in attribute order; a shadowed traffic-rate is left out by
    /// the sender.
    pub actions: Vec<FlowRuleAction>,
}

/// One BGP instance's flow rules and the devices they filter (ingress), as
/// a snapshot: it replaces that instance's previous one, empty clears it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowspecSet {
    /// The pushing BGP instance.
    pub instance: String,
    /// The VRF (routing table) whose VPN flowspec rules these are; `None`
    /// = the instance's own table.
    pub table: Option<String>,
    /// Kernel device names to filter on.
    pub devices: Vec<String>,
    /// The rules in RFC 8955 section 5.1 order.
    pub rules: Vec<FlowRule>,
}

/// One flow rule's state in the dataplane, for `show acl` and
/// `GET /v1/flowspec`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowspecRuleStatus {
    /// The BGP instance that pushed it.
    pub instance: String,
    /// The VRF the rule filters; `None` = the instance's own table.
    pub table: Option<String>,
    /// The flow as text.
    pub flow: String,
    /// Its actions as text.
    pub actions: Vec<String>,
    /// Why it is not installed (an unsupported match or action, the rule
    /// cap); `None` when installed.
    pub unsupported: Option<String>,
    /// Packets matched, summed over every device.
    pub packets: u64,
    /// Bytes matched, summed over every device.
    pub bytes: u64,
}

/// Messages sent from a client to `nos-acld`'s IPC socket.
///
/// New variants must always be appended, never inserted — `postcard` encodes
/// enum variants by index.
#[derive(Debug, Serialize, Deserialize)]
pub enum AclRequest {
    /// One-shot: every ACL (`None`) or the named one; an unknown name gives
    /// an empty reply.
    Show {
        /// Restrict the reply to this ACL.
        name: Option<String>,
    },
    /// From `nos-bgpd`: one instance's flow rules (a snapshot), answered by
    /// `AclEvent::Ack`.
    PushFlowspec(FlowspecSet),
    /// One-shot: every flow rule with its state and counters, answered by
    /// `AclEvent::Flowspec`.
    ShowFlowspec,
}

/// Messages sent from `nos-acld` to a query client.
#[derive(Debug, Serialize, Deserialize)]
pub enum AclEvent {
    /// Reply with the ACLs, ordered by name.
    Acls(Vec<AclStatus>),
    /// A push was applied.
    Ack,
    /// Reply to `ShowFlowspec`: per instance (by name), rules in order.
    Flowspec(Vec<FlowspecRuleStatus>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_push_round_trips_through_postcard_and_json() {
        let num = |value| FlowNumOp {
            and: false,
            lt: false,
            gt: false,
            eq: true,
            value,
        };
        let set = FlowspecSet {
            instance: "b1".into(),
            table: Some("rt2".into()),
            devices: vec!["eth0".into()],
            rules: vec![FlowRule {
                flow: "src 192.0.2.0/24 proto =6".into(),
                ipv6: false,
                components: vec![
                    FlowComponent::Source {
                        prefix: "192.0.2.0/24".parse().unwrap(),
                        offset: 0,
                    },
                    FlowComponent::Protocol(vec![num(6)]),
                    FlowComponent::Fragment(vec![FlowBitOp {
                        and: false,
                        not: true,
                        m: false,
                        value: 2,
                    }]),
                ],
                actions: vec![
                    FlowRuleAction::RateBytes(0.0),
                    FlowRuleAction::TrafficAction {
                        sample: true,
                        terminal: false,
                    },
                    FlowRuleAction::Unsupported("redirect 65000:1".into()),
                ],
            }],
        };
        let req = AclRequest::PushFlowspec(set.clone());
        let bytes = postcard::to_allocvec(&req).unwrap();
        let AclRequest::PushFlowspec(back) = postcard::from_bytes(&bytes).unwrap() else {
            panic!()
        };
        assert_eq!(back, set);
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(serde_json::from_str::<FlowspecSet>(&json).unwrap(), set);
        let shown: Vec<String> = set.rules[0]
            .actions
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            shown,
            [
                "rate 0 bytes/s",
                "sample=true terminal=false",
                "redirect 65000:1"
            ]
        );
        assert_eq!(
            FlowRuleAction::RatePackets(5.0).to_string(),
            "rate 5 packets/s"
        );
        assert_eq!(FlowRuleAction::Dscp(46).to_string(), "dscp 46");
    }
}
