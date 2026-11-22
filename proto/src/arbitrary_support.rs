//! `Arbitrary` helpers for `ipnet` types (no `arbitrary` feature upstream), used via
//! `#[arbitrary(with = ...)]`. Fuzz-only: see `tools/ci/no-arbitrary.sh` (#1216).

use arbitrary::{Result, Unstructured};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};

pub fn ipv4_net(u: &mut Unstructured<'_>) -> Result<Ipv4Net> {
    let a: Ipv4Addr = u.arbitrary()?;
    Ok(Ipv4Net::new(a, u.int_in_range(0..=32)?).expect("len <= 32"))
}

pub fn ipv6_net(u: &mut Unstructured<'_>) -> Result<Ipv6Net> {
    let a: Ipv6Addr = u.arbitrary()?;
    Ok(Ipv6Net::new(a, u.int_in_range(0..=128)?).expect("len <= 128"))
}

pub fn ip_net(u: &mut Unstructured<'_>) -> Result<IpNet> {
    Ok(if u.arbitrary()? {
        IpNet::V4(ipv4_net(u)?)
    } else {
        IpNet::V6(ipv6_net(u)?)
    })
}

pub fn opt_ip_net(u: &mut Unstructured<'_>) -> Result<Option<IpNet>> {
    u.arbitrary::<bool>()?.then(|| ip_net(u)).transpose()
}

pub fn vec_ip_net(u: &mut Unstructured<'_>) -> Result<Vec<IpNet>> {
    let n = u.int_in_range(0..=4)?;
    (0..n).map(|_| ip_net(u)).collect()
}
