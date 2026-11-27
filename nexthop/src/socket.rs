//! The only I/O: one `NETLINK_ROUTE` socket per call. Blocking, so run it on
//! `spawn_blocking`.

use std::io;
use std::ops::RangeInclusive;

use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

use crate::decode::{self, NexthopRecord};
use crate::encode::{self, Nexthop};

fn open() -> io::Result<Socket> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    Ok(socket)
}

/// Sends one request and waits for its acknowledgement. `tolerate` is an
/// errno (positive) that counts as success.
pub fn send(nh: &Nexthop, tolerate: i32) -> io::Result<()> {
    let socket = open()?;
    socket.send(&encode::encode(nh, 1)?, 0)?;
    let mut reply = Vec::with_capacity(4096);
    socket.recv(&mut reply, 0)?;
    match decode::ack_errno(&reply)? {
        0 => Ok(()),
        e if -e == tolerate => Ok(()),
        e => Err(io::Error::from_raw_os_error(-e)),
    }
}

/// Every nexthop of the netns whose id is in `ids` (ribd and fdbd each see
/// only their own range).
pub fn dump(ids: RangeInclusive<u32>) -> io::Result<Vec<NexthopRecord>> {
    let socket = open()?;
    socket.send(&encode::dump_request(1), 0)?;
    let mut out = Vec::new();
    let mut buf = Vec::with_capacity(1 << 16);
    loop {
        buf.clear();
        socket.recv(&mut buf, 0)?;
        if decode::dump_part(&buf, &ids, &mut out)? {
            return Ok(out);
        }
    }
}
