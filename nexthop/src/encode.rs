//! Building the request bytes. Pure: no I/O.

use std::io;
use std::net::IpAddr;

use crate::consts::*;

/// The kernel's `MAX_NEW_LABELS` (`net/mpls/internal.h`).
pub const MAX_LABELS: usize = 30;

/// A gateway nexthop: a next-hop address, optionally out of one device and
/// with an MPLS label stack pushed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    /// Ids are netns-global and ours: `0` (auto-assign) is refused.
    pub id: u32,
    pub gateway: IpAddr,
    pub oif: Option<u32>,
    pub onlink: bool,
    /// MPLS label stack, outermost first; empty means no encap.
    pub labels: Vec<u32>,
    /// An FDB nexthop (a bare VTEP): excludes `oif`, `onlink`, `labels`.
    pub fdb: bool,
    /// Replace an existing nexthop of that id in place (else `EEXIST`).
    pub replace: bool,
}

impl Gateway {
    /// What `nos-fdbd` needs: `ip nexthop add id N via <vtep> fdb`.
    pub fn fdb(id: u32, gateway: IpAddr) -> Self {
        Self {
            id,
            gateway,
            oif: None,
            onlink: false,
            labels: Vec::new(),
            fdb: true,
            replace: true,
        }
    }
}

/// A multipath group over existing nexthops. A re-send with the same id is an
/// atomic in-place replace of the member list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: u32,
    /// `(nexthop id, weight)`, weight 1..=65536 (the kernel stores weight-1
    /// in a `u16`, so 65536 itself is not representable here).
    pub members: Vec<(u32, u16)>,
    pub fdb: bool,
}

/// What one request creates or removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nexthop {
    Gateway(Gateway),
    Group(Group),
    Delete { id: u32 },
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_owned())
}

fn nla(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = u16::try_from(4 + payload.len()).expect("a nexthop attribute is small");
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len().next_multiple_of(4), 0);
}

fn validate(nh: &Nexthop) -> io::Result<()> {
    match nh {
        Nexthop::Gateway(g) => {
            if g.id == 0 {
                return Err(invalid("nexthop id 0 would be auto-assigned"));
            }
            if g.fdb && (g.oif.is_some() || g.onlink || !g.labels.is_empty()) {
                return Err(invalid("an fdb nexthop takes no oif, onlink or labels"));
            }
            if g.labels.len() > MAX_LABELS {
                return Err(invalid("too many MPLS labels"));
            }
            if g.labels.iter().any(|l| *l >= 1 << 20) {
                return Err(invalid("an MPLS label is 20 bits"));
            }
        }
        Nexthop::Group(g) => {
            if g.id == 0 {
                return Err(invalid("nexthop id 0 would be auto-assigned"));
            }
            if g.members.is_empty() {
                return Err(invalid("a group needs members"));
            }
            if g.members
                .iter()
                .any(|(m, w)| *m == g.id || *m == 0 || *w == 0)
            {
                return Err(invalid("a group member is itself, id 0, or has weight 0"));
            }
        }
        Nexthop::Delete { id } => {
            if *id == 0 {
                return Err(invalid("nexthop id 0 cannot be deleted"));
            }
        }
    }
    Ok(())
}

fn header(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&u32::try_from(16 + body.len()).unwrap().to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    out
}

/// The whole netlink message, `seq` chosen by the caller.
pub fn encode(nh: &Nexthop, seq: u32) -> io::Result<Vec<u8>> {
    validate(nh)?;
    // nhmsg: family, scope, protocol, resvd, flags. The scope must be zero:
    // the kernel rejects any other with EINVAL and picks link scope itself.
    // A delete has to leave the protocol zero too (`nh_valid_get_del_req`).
    let mut body = vec![0u8; 8];
    let (kind, flags) = match nh {
        Nexthop::Gateway(g) => {
            body[0] = if g.gateway.is_ipv4() {
                AF_INET
            } else {
                AF_INET6
            };
            body[2] = RTPROT_STATIC;
            if g.onlink {
                body[4..8].copy_from_slice(&RTNH_F_ONLINK.to_ne_bytes());
            }
            nla(&mut body, NHA_ID, &g.id.to_ne_bytes());
            match g.gateway {
                IpAddr::V4(a) => nla(&mut body, NHA_GATEWAY, &a.octets()),
                IpAddr::V6(a) => nla(&mut body, NHA_GATEWAY, &a.octets()),
            }
            if let Some(oif) = g.oif {
                nla(&mut body, NHA_OIF, &oif.to_ne_bytes());
            }
            if !g.labels.is_empty() {
                nla(
                    &mut body,
                    NHA_ENCAP_TYPE,
                    &LWTUNNEL_ENCAP_MPLS.to_ne_bytes(),
                );
                let last = g.labels.len() - 1;
                let stack: Vec<u8> = g
                    .labels
                    .iter()
                    .enumerate()
                    .flat_map(|(i, l)| {
                        let bos = if i == last { 0x100 } else { 0 };
                        ((l << 12) | bos).to_be_bytes()
                    })
                    .collect();
                let mut inner = Vec::new();
                nla(&mut inner, MPLS_IPTUNNEL_DST, &stack);
                nla(&mut body, NHA_ENCAP | NLA_F_NESTED, &inner);
            }
            if g.fdb {
                nla(&mut body, NHA_FDB, &[]);
            }
            let f = if g.replace {
                NLM_F_CREATE | NLM_F_REPLACE
            } else {
                NLM_F_CREATE
            };
            (RTM_NEWNEXTHOP, f)
        }
        // A group has no family of its own and takes no gateway/oif/encap.
        Nexthop::Group(g) => {
            body[2] = RTPROT_STATIC;
            nla(&mut body, NHA_ID, &g.id.to_ne_bytes());
            // struct nexthop_grp: id, weight-1 split over weight/weight_high, resvd.
            let grp: Vec<u8> = g
                .members
                .iter()
                .flat_map(|(m, w)| {
                    let w = w - 1;
                    let mut e = m.to_ne_bytes().to_vec();
                    e.extend_from_slice(&[(w & 0xff) as u8, (w >> 8) as u8, 0, 0]);
                    e
                })
                .collect();
            nla(&mut body, NHA_GROUP, &grp);
            if g.fdb {
                nla(&mut body, NHA_FDB, &[]);
            }
            (RTM_NEWNEXTHOP, NLM_F_CREATE | NLM_F_REPLACE)
        }
        Nexthop::Delete { id } => {
            body[2] = 0;
            nla(&mut body, NHA_ID, &id.to_ne_bytes());
            (RTM_DELNEXTHOP, 0)
        }
    };
    Ok(header(kind, NLM_F_REQUEST | NLM_F_ACK | flags, seq, &body))
}

/// `RTM_GETNEXTHOP` with `NLM_F_DUMP`: every nexthop of the netns.
pub(crate) fn dump_request(seq: u32) -> Vec<u8> {
    header(RTM_GETNEXTHOP, NLM_F_REQUEST | NLM_F_DUMP, seq, &[0u8; 8])
}

#[cfg(test)]
#[path = "encode_tests.rs"]
mod tests;
