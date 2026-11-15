//! The reply side: acks and `RTM_GETTFILTER` dump messages. Pure;
//! `socket.rs` feeds it what it receives.

use std::io;

#[allow(clippy::wildcard_imports, reason = "the uapi constant table")]
use crate::consts::*;

/// One action's counters in a dumped filter: a filter with two actions
/// yields two rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterStats {
    pub chain: u32,
    pub prio: u16,
    pub handle: u32,
    /// The action's kind (`gact`, `skbedit`, ...).
    pub action: String,
    /// Empty when the action has none.
    pub cookie: Vec<u8>,
    pub packets: u64,
    pub bytes: u64,
}

pub(crate) fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

pub(crate) fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}

/// The `(type, payload)` attributes of a block, one level deep, flags
/// stripped.
pub(crate) fn attrs(b: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut v = Vec::new();
    let mut at = 0;
    while at + 4 <= b.len() {
        let len = usize::from(u16_at(b, at));
        if len < 4 || at + len > b.len() {
            return Err(bad("truncated netlink attribute"));
        }
        v.push((u16_at(b, at + 2) & NLA_TYPE_MASK, &b[at + 4..at + len]));
        at += len.next_multiple_of(4);
    }
    Ok(v)
}

pub(crate) fn find<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> Option<&'a [u8]> {
    attrs.iter().find(|(k, _)| *k == kind).map(|(_, v)| *v)
}

pub(crate) fn errno_of(msg: &[u8]) -> io::Result<i32> {
    if msg.len() < 20 {
        return Err(bad("short netlink error"));
    }
    #[allow(clippy::cast_possible_wrap, reason = "kernel int, bit pattern")]
    Ok(u32_at(msg, 16) as i32)
}

/// The acknowledgement of one request. `tolerate` are errnos (positive)
/// that count as success.
pub(crate) fn ack(reply: &[u8], tolerate: &[i32]) -> io::Result<()> {
    if reply.len() < 20 || u16_at(reply, 4) != NLMSG_ERROR {
        return Err(bad("not a netlink ack"));
    }
    let errno = errno_of(reply)?;
    if errno == 0 || tolerate.contains(&-errno) {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(-errno))
    }
}

/// Counters of one action (`TCA_ACT_STATS`): `TCA_STATS_PKT64` overrides the
/// 32-bit `gnet_stats_basic.packets` when the kernel sends it.
fn stats(b: &[u8]) -> io::Result<(u64, u64)> {
    let a = attrs(b)?;
    let (mut packets, mut bytes) = (0, 0);
    if let Some(basic) = find(&a, TCA_STATS_BASIC) {
        if basic.len() < 12 {
            return Err(bad("short gnet_stats_basic"));
        }
        bytes = u64_at(basic, 0);
        packets = u64::from(u32_at(basic, 8));
    }
    if let Some(p) = find(&a, TCA_STATS_PKT64).filter(|p| p.len() >= 8) {
        packets = u64_at(p, 0);
    }
    Ok((packets, bytes))
}

/// One `RTM_NEWTFILTER` dump entry (header included) into one row per
/// action. A priority's head entry has no options and yields nothing.
fn filter(msg: &[u8], out: &mut Vec<FilterStats>) -> io::Result<()> {
    if msg.len() < 36 {
        return Err(bad("short tcmsg"));
    }
    let handle = u32_at(msg, 24);
    let prio = u16::try_from(u32_at(msg, 32) >> 16).unwrap();
    let top = attrs(&msg[36..])?;
    let chain = find(&top, TCA_CHAIN)
        .filter(|c| c.len() >= 4)
        .map_or(0, |c| u32_at(c, 0));
    let act_attr = match find(&top, TCA_KIND) {
        Some(b"flower\0") => TCA_FLOWER_ACT,
        Some(b"fw\0") => TCA_FW_ACT,
        _ => return Ok(()),
    };
    let Some(opts) = find(&top, TCA_OPTIONS) else {
        return Ok(());
    };
    let Some(table) = find(&attrs(opts)?, act_attr) else {
        return Ok(());
    };
    for (_, act) in attrs(table)? {
        let a = attrs(act)?;
        let action = find(&a, TCA_ACT_KIND)
            .map_or_default(|k| String::from_utf8_lossy(k).trim_end_matches('\0').to_owned());
        let (packets, bytes) = find(&a, TCA_ACT_STATS).map_or(Ok((0, 0)), stats)?;
        out.push(FilterStats {
            chain,
            prio,
            handle,
            action,
            cookie: find(&a, TCA_ACT_COOKIE).unwrap_or_default().to_vec(),
            packets,
            bytes,
        });
    }
    Ok(())
}

/// One received buffer of a dump (any number of messages) into `out`.
/// `true` once `NLMSG_DONE` is seen; an error message is returned as such.
pub(crate) fn dump_part(buf: &[u8], out: &mut Vec<FilterStats>) -> io::Result<bool> {
    let mut at = 0;
    while at + 16 <= buf.len() {
        let len = usize::try_from(u32_at(buf, at)).unwrap();
        if len < 16 || at + len > buf.len() {
            return Err(bad("truncated netlink message"));
        }
        let msg = &buf[at..at + len];
        match u16_at(msg, 4) {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let errno = errno_of(msg)?;
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(-errno));
                }
            }
            RTM_NEWTFILTER => filter(msg, out)?,
            _ => {}
        }
        at += len.next_multiple_of(4);
    }
    Ok(false)
}

#[cfg(test)]
#[path = "decode_tests.rs"]
mod tests;
