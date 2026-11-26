//! Hand-adds, removes and probes one IPv4 route with a chosen `rtm_protocol`
//! for `nos-e2e`'s `foreign-route` phase (#1514): the runtime image has no `ip`.
//!
//! `nos-route-stub add|del <prefix/len> <gateway> <table> <proto>`
//! `nos-route-stub has <prefix/len> <table>` exits 0 when present, 1 when not.
//!
//! Test-only: lab image only, needs `CAP_NET_ADMIN` (run as root in a router).

use std::net::Ipv4Addr;

use anyhow::{bail, Context};
use futures::TryStreamExt as _;
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteProtocol};
use rtnetlink::RouteMessageBuilder;

fn prefix(s: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let (a, l) = s.split_once('/').context("prefix/len")?;
    Ok((a.parse()?, l.parse()?))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [op @ ("add" | "del"), pfx, gw, table, proto] => {
            let (addr, len) = prefix(pfx)?;
            let route = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(addr, len)
                .gateway(gw.parse::<Ipv4Addr>()?)
                .table_id(table.parse()?)
                .protocol(RouteProtocol::from(proto.parse::<u8>()?))
                .build();
            if op == "add" {
                handle.route().add(route).execute().await?;
            } else {
                handle.route().del(route).execute().await?;
            }
        }
        ["has", pfx, table] => {
            let (addr, len) = prefix(pfx)?;
            let table: u32 = table.parse()?;
            let filter = RouteMessageBuilder::<Ipv4Addr>::new()
                .table_id(table)
                .build();
            let mut dump = handle.route().get(filter).execute();
            while let Some(r) = dump.try_next().await? {
                let dst = r.attributes.iter().any(
                    |a| matches!(a, RouteAttribute::Destination(RouteAddress::Inet(d)) if *d == addr),
                );
                if dst
                    && r.header.destination_prefix_length == len
                    && u32::from(r.header.table) == table
                {
                    return Ok(());
                }
            }
            std::process::exit(1);
        }
        _ => bail!("usage: add|del <prefix/len> <gw> <table> <proto> | has <prefix/len> <table>"),
    }
    Ok(())
}
