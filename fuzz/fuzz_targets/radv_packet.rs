#![no_main]
use libfuzzer_sys::fuzz_target;
use std::net::Ipv6Addr;

fuzz_target!(|data: &[u8]| {
    let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let _ = nos_radv::packet::decode_rs(data, src, Some(255));
    let _ = nos_radv::packet::decode_ra(data, src, Some(255));
});
