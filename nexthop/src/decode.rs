//! Parsing acks and dump replies. Pure: no I/O.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;

use crate::consts::*;

/// One nexthop as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NexthopRecord {
    pub id: u32,
    pub gateway: Option<IpAddr>,
    pub oif: Option<u32>,
    pub onlink: bool,
    pub labels: Vec<u32>,
    /// `(nexthop id, weight)` for a group.
    pub group: Option<Vec<(u32, u16)>>,
    pub fdb: bool,
    pub blackhole: bool,
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

/// The errno an ack (`nlmsgerr`) carries, `0` for a plain acknowledgement.
pub(crate) fn ack_errno(reply: &[u8]) -> io::Result<i32> {
    if reply.len() < 20 || u16::from_ne_bytes([reply[4], reply[5]]) != NLMSG_ERROR {
        return Err(bad("not a netlink ack"));
    }
    Ok(i32::from_ne_bytes([
        reply[16], reply[17], reply[18], reply[19],
    ]))
}

/// The attributes of `buf` as `(type without flags, payload)`.
fn attrs(mut buf: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes([buf[0], buf[1]]));
        let kind = u16::from_ne_bytes([buf[2], buf[3]]) & !(NLA_F_NESTED | 0x4000);
        if len < 4 || len > buf.len() {
            return Err(bad("truncated attribute"));
        }
        out.push((kind, &buf[4..len]));
        buf = &buf[len.next_multiple_of(4).min(buf.len())..];
    }
    Ok(out)
}

fn u32_of(p: &[u8]) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        p.try_into().map_err(|_| bad("not a u32"))?,
    ))
}

fn record(body: &[u8]) -> io::Result<NexthopRecord> {
    if body.len() < 8 {
        return Err(bad("short nhmsg"));
    }
    let mut r = NexthopRecord {
        onlink: u32::from_ne_bytes(body[4..8].try_into().unwrap()) & RTNH_F_ONLINK != 0,
        ..Default::default()
    };
    let mut encap_mpls = false;
    let mut encap: &[u8] = &[];
    for (kind, p) in attrs(&body[8..])? {
        match kind {
            NHA_ID => r.id = u32_of(p)?,
            NHA_OIF => r.oif = Some(u32_of(p)?),
            NHA_GATEWAY => {
                r.gateway = match p.len() {
                    4 => Some(Ipv4Addr::from(<[u8; 4]>::try_from(p).unwrap()).into()),
                    16 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(p).unwrap()).into()),
                    _ => return Err(bad("bad gateway length")),
                }
            }
            NHA_GROUP => {
                r.group = Some(
                    p.chunks_exact(8)
                        .map(|e| {
                            let id = u32::from_ne_bytes(e[..4].try_into().unwrap());
                            let w = u16::from(e[4]) | u16::from(e[5]) << 8;
                            (id, w.saturating_add(1))
                        })
                        .collect(),
                );
            }
            NHA_FDB => r.fdb = true,
            NHA_BLACKHOLE => r.blackhole = true,
            NHA_ENCAP_TYPE => {
                encap_mpls =
                    p.len() == 2 && u16::from_ne_bytes([p[0], p[1]]) == LWTUNNEL_ENCAP_MPLS;
            }
            NHA_ENCAP => encap = p,
            _ => {}
        }
    }
    if encap_mpls {
        for (kind, p) in attrs(encap)? {
            if kind == MPLS_IPTUNNEL_DST {
                r.labels = p
                    .chunks_exact(4)
                    .map(|e| u32::from_be_bytes(e.try_into().unwrap()) >> 12)
                    .collect();
            }
        }
    }
    Ok(r)
}

/// Adds the nexthops of one received buffer whose id is in `range`; `true`
/// once `NLMSG_DONE` ended the dump.
pub(crate) fn dump_part(
    mut buf: &[u8],
    range: &RangeInclusive<u32>,
    out: &mut Vec<NexthopRecord>,
) -> io::Result<bool> {
    while buf.len() >= 16 {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes([buf[4], buf[5]]);
        if len < 16 || len > buf.len() {
            return Err(bad("truncated netlink message"));
        }
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let e = ack_errno(&buf[..len])?;
                if e != 0 {
                    return Err(io::Error::from_raw_os_error(-e));
                }
            }
            RTM_NEWNEXTHOP => {
                let r = record(&buf[16..len])?;
                if range.contains(&r.id) {
                    out.push(r);
                }
            }
            _ => {}
        }
        buf = &buf[len.next_multiple_of(4).min(buf.len())..];
    }
    Ok(false)
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
