//! RFC 8955 / RFC 8956 Flow Specification NLRI (SAFI 133, and SAFI 134 with a
//! Route Distinguisher): pure encode/decode, the section 5.1 precedence order
//! and a text form. No I/O, no RIB state.
//!
//! Operand lengths are not kept: encoding always picks the smallest of
//! 1/2/4/8 octets that holds the value, and the first operator's AND bit is
//! always emitted (and read) as 0, so decode followed by encode is canonical
//! and the value doubles as a RIB key (`Eq + Hash`). IPv6 type 1/2 pattern
//! bits outside `offset..len` are zeroed for the same reason.

use std::cmp::Ordering;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::evpn::{format_rd, Rd};
use crate::message::WireError;

pub const COMP_DEST: u8 = 1;
pub const COMP_SOURCE: u8 = 2;
pub const COMP_PROTOCOL: u8 = 3;
pub const COMP_PORT: u8 = 4;
pub const COMP_DST_PORT: u8 = 5;
pub const COMP_SRC_PORT: u8 = 6;
pub const COMP_ICMP_TYPE: u8 = 7;
pub const COMP_ICMP_CODE: u8 = 8;
pub const COMP_TCP_FLAGS: u8 = 9;
pub const COMP_PACKET_LEN: u8 = 10;
pub const COMP_DSCP: u8 = 11;
pub const COMP_FRAGMENT: u8 = 12;
pub const COMP_FLOW_LABEL: u8 = 13;

/// RFC 8955 section 4.1: the longest NLRI value a `0xfnnn` length can carry.
const MAX_LEN: usize = 4095;

/// Address family of a Flow Specification (the AFI of the MP attribute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Afi {
    V4,
    V6,
}

/// One `{numeric_op, value}` pair. `lt`/`gt`/`eq` combine as RFC 8955 Table 1.
#[allow(clippy::struct_excessive_bools, reason = "the RFC's operator bits")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NumOp {
    pub and: bool,
    pub lt: bool,
    pub gt: bool,
    pub eq: bool,
    pub value: u64,
}

/// One `{bitmask_op, bitmask}` pair: `m` = "all bits set" (else "any"), `not`
/// negates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitOp {
    pub and: bool,
    pub not: bool,
    pub m: bool,
    pub value: u64,
}

/// A type 1/2 prefix. For IPv6, `net` holds the pattern at bit positions
/// `offset..net.prefix_len()` (all other bits zero); `offset` is 0 for IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub net: IpNet,
    pub offset: u8,
}

impl Prefix {
    #[must_use]
    pub fn v4(net: Ipv4Net) -> Self {
        Self {
            net: IpNet::V4(net.trunc()),
            offset: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Component {
    Dest(Prefix),
    Source(Prefix),
    /// IPv4 protocol / IPv6 upper-layer protocol.
    Protocol(Vec<NumOp>),
    Port(Vec<NumOp>),
    DstPort(Vec<NumOp>),
    SrcPort(Vec<NumOp>),
    IcmpType(Vec<NumOp>),
    IcmpCode(Vec<NumOp>),
    TcpFlags(Vec<BitOp>),
    PacketLen(Vec<NumOp>),
    Dscp(Vec<NumOp>),
    Fragment(Vec<BitOp>),
    /// IPv6 only (RFC 8956 section 3.7).
    FlowLabel(Vec<NumOp>),
}

/// A Flow Specification NLRI value: components in strictly increasing type
/// order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowSpec {
    pub components: Vec<Component>,
}

/// SAFI 134 (RFC 8955 section 8): a Route Distinguisher, then the value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowSpecVpn {
    pub rd: Rd,
    pub flow: FlowSpec,
}

fn bad() -> WireError {
    WireError::MalformedUpdate
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], WireError> {
    if b.len() < n {
        return Err(WireError::Truncated);
    }
    let (head, tail) = b.split_at(n);
    *b = tail;
    Ok(head)
}

/// Strips the RFC 8955 section 4.1 length and returns `(value, total octets
/// consumed)`. A zero length is malformed (an empty rule matches nothing).
fn split_nlri(data: &[u8]) -> Result<(&[u8], usize), WireError> {
    let mut b = data;
    let first = take(&mut b, 1)?[0];
    let (len, hdr) = if first >= 0xf0 {
        let second = take(&mut b, 1)?[0];
        ((usize::from(first & 0x0f) << 8) | usize::from(second), 2)
    } else {
        (usize::from(first), 1)
    };
    if len == 0 {
        return Err(bad());
    }
    Ok((take(&mut b, len)?, hdr + len))
}

fn put_len(len: usize, out: &mut Vec<u8>) -> Result<(), WireError> {
    if len > MAX_LEN {
        return Err(bad());
    }
    if len < 240 {
        out.push(u8::try_from(len).map_err(|_| bad())?);
    } else {
        out.extend_from_slice(&(0xf000 | u16::try_from(len).map_err(|_| bad())?).to_be_bytes());
    }
    Ok(())
}

fn be(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |v, b| (v << 8) | u64::from(*b))
}

/// `(len field, octets)` of the smallest operand holding `v`.
fn width(v: u64) -> (u8, usize) {
    match v {
        0..=0xff => (0, 1),
        0x100..=0xffff => (1, 2),
        0x1_0000..=0xffff_ffff => (2, 4),
        _ => (3, 8),
    }
}

fn decode_num(b: &mut &[u8]) -> Result<Vec<NumOp>, WireError> {
    let mut ops = Vec::new();
    loop {
        let op = take(b, 1)?[0];
        let value = be(take(b, 1 << ((op >> 4) & 3))?);
        ops.push(NumOp {
            and: !ops.is_empty() && op & 0x40 != 0,
            lt: op & 4 != 0,
            gt: op & 2 != 0,
            eq: op & 1 != 0,
            value,
        });
        if op & 0x80 != 0 {
            return Ok(ops);
        }
    }
}

fn decode_bit(b: &mut &[u8]) -> Result<Vec<BitOp>, WireError> {
    let mut ops = Vec::new();
    loop {
        let op = take(b, 1)?[0];
        let value = be(take(b, 1 << ((op >> 4) & 3))?);
        ops.push(BitOp {
            and: !ops.is_empty() && op & 0x40 != 0,
            not: op & 2 != 0,
            m: op & 1 != 0,
            value,
        });
        if op & 0x80 != 0 {
            return Ok(ops);
        }
    }
}

fn encode_num(ops: &[NumOp], out: &mut Vec<u8>) -> Result<(), WireError> {
    if ops.is_empty() {
        return Err(bad());
    }
    for (i, o) in ops.iter().enumerate() {
        let (l, n) = width(o.value);
        out.push(
            u8::from(i + 1 == ops.len()) << 7
                | u8::from(i > 0 && o.and) << 6
                | l << 4
                | u8::from(o.lt) << 2
                | u8::from(o.gt) << 1
                | u8::from(o.eq),
        );
        out.extend_from_slice(&o.value.to_be_bytes()[8 - n..]);
    }
    Ok(())
}

fn encode_bit(ops: &[BitOp], out: &mut Vec<u8>) -> Result<(), WireError> {
    if ops.is_empty() {
        return Err(bad());
    }
    for (i, o) in ops.iter().enumerate() {
        let (l, n) = width(o.value);
        out.push(
            u8::from(i + 1 == ops.len()) << 7
                | u8::from(i > 0 && o.and) << 6
                | l << 4
                | u8::from(o.not) << 1
                | u8::from(o.m),
        );
        out.extend_from_slice(&o.value.to_be_bytes()[8 - n..]);
    }
    Ok(())
}

fn decode_prefix(afi: Afi, b: &mut &[u8]) -> Result<Prefix, WireError> {
    let len = take(b, 1)?[0];
    match afi {
        Afi::V4 => {
            if len > 32 {
                return Err(bad());
            }
            let mut a = [0u8; 4];
            let raw = take(b, usize::from(len).div_ceil(8))?;
            a[..raw.len()].copy_from_slice(raw);
            let net = Ipv4Net::new(Ipv4Addr::from(a), len)
                .map_err(|_| bad())?
                .trunc();
            Ok(Prefix::v4(net))
        }
        Afi::V6 => {
            let offset = take(b, 1)?[0];
            if (len != 0 || offset != 0) && (offset >= len || len > 128) {
                return Err(bad());
            }
            let bits = usize::from(len - offset);
            let pat = take(b, bits.div_ceil(8))?;
            let mut a = [0u8; 16];
            for i in 0..bits {
                let pos = usize::from(offset) + i;
                a[pos / 8] |= ((pat[i / 8] >> (7 - i % 8)) & 1) << (7 - pos % 8);
            }
            let net = Ipv6Net::new(Ipv6Addr::from(a), len)
                .map_err(|_| bad())?
                .trunc();
            Ok(Prefix {
                net: IpNet::V6(net),
                offset,
            })
        }
    }
}

fn encode_prefix(p: &Prefix, out: &mut Vec<u8>) -> Result<(), WireError> {
    match p.net {
        IpNet::V4(n) => {
            if p.offset != 0 {
                return Err(bad());
            }
            out.push(n.prefix_len());
            out.extend_from_slice(&n.addr().octets()[..usize::from(n.prefix_len()).div_ceil(8)]);
        }
        IpNet::V6(n) => {
            let len = n.prefix_len();
            if !(len == 0 && p.offset == 0) && p.offset >= len {
                return Err(bad());
            }
            out.push(len);
            out.push(p.offset);
            let a = n.addr().octets();
            let bits = usize::from(len - p.offset);
            let mut pat = vec![0u8; bits.div_ceil(8)];
            for i in 0..bits {
                let pos = usize::from(p.offset) + i;
                pat[i / 8] |= ((a[pos / 8] >> (7 - pos % 8)) & 1) << (7 - i % 8);
            }
            out.extend_from_slice(&pat);
        }
    }
    Ok(())
}

impl Component {
    /// The RFC 8955 / 8956 component type code.
    #[must_use]
    pub fn type_code(&self) -> u8 {
        match self {
            Component::Dest(_) => COMP_DEST,
            Component::Source(_) => COMP_SOURCE,
            Component::Protocol(_) => COMP_PROTOCOL,
            Component::Port(_) => COMP_PORT,
            Component::DstPort(_) => COMP_DST_PORT,
            Component::SrcPort(_) => COMP_SRC_PORT,
            Component::IcmpType(_) => COMP_ICMP_TYPE,
            Component::IcmpCode(_) => COMP_ICMP_CODE,
            Component::TcpFlags(_) => COMP_TCP_FLAGS,
            Component::PacketLen(_) => COMP_PACKET_LEN,
            Component::Dscp(_) => COMP_DSCP,
            Component::Fragment(_) => COMP_FRAGMENT,
            Component::FlowLabel(_) => COMP_FLOW_LABEL,
        }
    }

    /// Everything after the type octet.
    fn encode_body(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        match self {
            Component::Dest(p) | Component::Source(p) => encode_prefix(p, out),
            Component::Protocol(o)
            | Component::Port(o)
            | Component::DstPort(o)
            | Component::SrcPort(o)
            | Component::IcmpType(o)
            | Component::IcmpCode(o)
            | Component::PacketLen(o)
            | Component::Dscp(o)
            | Component::FlowLabel(o) => encode_num(o, out),
            Component::TcpFlags(o) | Component::Fragment(o) => encode_bit(o, out),
        }
    }

    fn body_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        // ponytail: an unencodable component compares as empty; encode() reports it
        let _ = self.encode_body(&mut v);
        v
    }
}

impl FlowSpec {
    /// Decodes one length-prefixed NLRI from the front of `data` and returns
    /// it with the number of octets consumed. Errors (truncation, unsorted or
    /// repeated or unknown component types, bad IPv6 length/offset, a
    /// zero-length NLRI) make the whole NLRI malformed, which a caller treats
    /// as withdraw (RFC 8955 section 10).
    pub fn decode(afi: Afi, data: &[u8]) -> Result<(Self, usize), WireError> {
        let (body, used) = split_nlri(data)?;
        Ok((Self::decode_value(afi, body)?, used))
    }

    fn decode_value(afi: Afi, mut b: &[u8]) -> Result<Self, WireError> {
        let mut components: Vec<Component> = Vec::new();
        let mut last = 0u8;
        while !b.is_empty() {
            let t = take(&mut b, 1)?[0];
            if t <= last {
                return Err(bad());
            }
            last = t;
            let c = match t {
                COMP_DEST => Component::Dest(decode_prefix(afi, &mut b)?),
                COMP_SOURCE => Component::Source(decode_prefix(afi, &mut b)?),
                COMP_PROTOCOL => Component::Protocol(decode_num(&mut b)?),
                COMP_PORT => Component::Port(decode_num(&mut b)?),
                COMP_DST_PORT => Component::DstPort(decode_num(&mut b)?),
                COMP_SRC_PORT => Component::SrcPort(decode_num(&mut b)?),
                COMP_ICMP_TYPE => Component::IcmpType(decode_num(&mut b)?),
                COMP_ICMP_CODE => Component::IcmpCode(decode_num(&mut b)?),
                COMP_TCP_FLAGS => Component::TcpFlags(decode_bit(&mut b)?),
                COMP_PACKET_LEN => Component::PacketLen(decode_num(&mut b)?),
                COMP_DSCP => Component::Dscp(decode_num(&mut b)?),
                COMP_FRAGMENT => {
                    let ops = decode_bit(&mut b)?;
                    // RFC 8956 section 3.6: no DF bit (0x01) on IPv6.
                    if afi == Afi::V6 && ops.iter().any(|o| o.value & 1 != 0) {
                        return Err(bad());
                    }
                    Component::Fragment(ops)
                }
                COMP_FLOW_LABEL if afi == Afi::V6 => Component::FlowLabel(decode_num(&mut b)?),
                _ => return Err(bad()),
            };
            components.push(c);
        }
        if components.is_empty() {
            return Err(bad());
        }
        Ok(Self { components })
    }

    /// Appends the length-prefixed NLRI. Fails for an empty rule, components
    /// out of strict type order, an empty operator list, an invalid IPv6
    /// length/offset, or a value longer than 4095 octets.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        let mut body = Vec::new();
        self.encode_value(&mut body)?;
        put_len(body.len(), out)?;
        out.extend_from_slice(&body);
        Ok(())
    }

    fn encode_value(&self, body: &mut Vec<u8>) -> Result<(), WireError> {
        if self.components.is_empty() {
            return Err(bad());
        }
        let mut last = 0;
        for c in &self.components {
            if c.type_code() <= last {
                return Err(bad());
            }
            last = c.type_code();
            body.push(last);
            c.encode_body(body)?;
        }
        Ok(())
    }
}

impl FlowSpecVpn {
    /// As [`FlowSpec::decode`]; the length covers the 8-octet RD too.
    pub fn decode(afi: Afi, data: &[u8]) -> Result<(Self, usize), WireError> {
        let (mut body, used) = split_nlri(data)?;
        let rd: Rd = take(&mut body, 8)?.try_into().map_err(|_| bad())?;
        Ok((
            Self {
                rd,
                flow: FlowSpec::decode_value(afi, body)?,
            },
            used,
        ))
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        let mut body = self.rd.to_vec();
        self.flow.encode_value(&mut body)?;
        put_len(body.len(), out)?;
        out.extend_from_slice(&body);
        Ok(())
    }
}

/// RFC 8955 section 5.1 / RFC 8956 section 4: `Less` when `a` has the higher
/// precedence (matches first), `Greater` when `b` does, `Equal` when the two
/// rules are the same.
#[must_use]
pub fn cmp_precedence(a: &FlowSpec, b: &FlowSpec) -> Ordering {
    for i in 0..a.components.len().max(b.components.len()) {
        let (ca, cb) = match (a.components.get(i), b.components.get(i)) {
            (Some(x), Some(y)) => (x, y),
            // the rule with fewer components loses
            (None, _) => return Ordering::Greater,
            (_, None) => return Ordering::Less,
        };
        let o = ca
            .type_code()
            .cmp(&cb.type_code())
            .then_with(|| match (ca, cb) {
                (
                    Component::Dest(x) | Component::Source(x),
                    Component::Dest(y) | Component::Source(y),
                ) => cmp_prefix(x, y),
                _ => cmp_bytes(&ca.body_bytes(), &cb.body_bytes()),
            });
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

fn cmp_prefix(x: &Prefix, y: &Prefix) -> Ordering {
    // lowest offset first (8956 section 4)
    x.offset.cmp(&y.offset).then_with(|| {
        if x.net.contains(&y.net) || y.net.contains(&x.net) {
            // more specific first
            y.net.prefix_len().cmp(&x.net.prefix_len())
        } else {
            x.net.addr().cmp(&y.net.addr())
        }
    })
}

/// memcmp over the common prefix; if equal, the longer string wins.
fn cmp_bytes(x: &[u8], y: &[u8]) -> Ordering {
    let n = x.len().min(y.len());
    x[..n].cmp(&y[..n]).then_with(|| y.len().cmp(&x.len()))
}

fn fmt_ops<T>(
    f: &mut fmt::Formatter<'_>,
    ops: &[T],
    and: impl Fn(&T) -> bool,
    one: impl Fn(&T) -> String,
) -> fmt::Result {
    for (i, o) in ops.iter().enumerate() {
        if i > 0 {
            f.write_str(if and(o) { " && " } else { " || " })?;
        }
        f.write_str(&one(o))?;
    }
    Ok(())
}

impl fmt::Display for NumOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sym = match (self.lt, self.gt, self.eq) {
            (false, false, false) => return f.write_str("false"),
            (true, true, true) => return f.write_str("true"),
            (false, false, true) => "=",
            (false, true, false) => ">",
            (false, true, true) => ">=",
            (true, false, false) => "<",
            (true, false, true) => "<=",
            (true, true, false) => "!=",
        };
        write!(f, "{sym}{}", self.value)
    }
}

impl fmt::Display for BitOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{} {:#x}",
            if self.not { "not " } else { "" },
            if self.m { "match" } else { "any" },
            self.value
        )
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let num = |f: &mut fmt::Formatter<'_>, name: &str, o: &[NumOp]| {
            write!(f, "{name} ")?;
            fmt_ops(f, o, |x| x.and, ToString::to_string)
        };
        let bit = |f: &mut fmt::Formatter<'_>, name: &str, o: &[BitOp]| {
            write!(f, "{name} ")?;
            fmt_ops(f, o, |x| x.and, ToString::to_string)
        };
        match self {
            Component::Dest(p) | Component::Source(p) => {
                let name = if matches!(self, Component::Dest(_)) {
                    "dest"
                } else {
                    "source"
                };
                match p.net {
                    IpNet::V4(_) => write!(f, "{name} {}", p.net),
                    IpNet::V6(_) => write!(f, "{name} {} offset {}", p.net, p.offset),
                }
            }
            Component::Protocol(o) => num(f, "proto", o),
            Component::Port(o) => num(f, "port", o),
            Component::DstPort(o) => num(f, "dst-port", o),
            Component::SrcPort(o) => num(f, "src-port", o),
            Component::IcmpType(o) => num(f, "icmp-type", o),
            Component::IcmpCode(o) => num(f, "icmp-code", o),
            Component::TcpFlags(o) => bit(f, "tcp-flags", o),
            Component::PacketLen(o) => num(f, "len", o),
            Component::Dscp(o) => num(f, "dscp", o),
            Component::Fragment(o) => bit(f, "fragment", o),
            Component::FlowLabel(o) => num(f, "flow-label", o),
        }
    }
}

impl fmt::Display for FlowSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

/// An RFC 8955 section 7 action community as text (`traffic-rate:0:0` is
/// "discard"); anything else falls back to `evpn::format_ext_community`.
pub fn format_action(c: u64) -> String {
    let b = c.to_be_bytes();
    match (b[0], b[1]) {
        (0x80, 0x06) => format!(
            "traffic-rate:{}:{}",
            u16::from_be_bytes([b[2], b[3]]),
            f32::from_be_bytes([b[4], b[5], b[6], b[7]])
        ),
        (0x80, 0x08) => format!(
            "redirect:{}:{}",
            u16::from_be_bytes([b[2], b[3]]),
            u32::from_be_bytes([b[4], b[5], b[6], b[7]])
        ),
        (0x80, 0x09) => format!("traffic-marking:{}", b[7] & 0x3f),
        _ => crate::evpn::format_ext_community(c),
    }
}

impl fmt::Display for FlowSpecVpn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rd {} {}", format_rd(&self.rd), self.flow)
    }
}

#[cfg(test)]
#[path = "flowspec_tests.rs"]
mod tests;
