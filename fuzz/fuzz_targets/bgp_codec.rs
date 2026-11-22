#![no_main]
use libfuzzer_sys::fuzz_target;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    // First byte: bit0 two_octet_as, bit1 extended, bits 2-5 pick ADD-PATH AFIs.
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let mut codec = nos_bgp::message::BgpCodec {
        add_path_afis: [
            (1u16, 1u8),
            (2, 1),
            (1, 134),
            (2, 134),
            (25, 70),
            (0xffff, 1),
        ]
        .into_iter()
        .enumerate()
        .filter(|(i, _)| (flags >> (2 + i)) & 1 == 1)
        .map(|(_, a)| a)
        .collect(),
        two_octet_as: flags & 1 == 1,
        extended: flags & 2 == 2,
    };
    let mut buf = bytes::BytesMut::from(rest);
    // Multi-frame: keep decoding until the buffer yields nothing or errors.
    while let Ok(Some(_)) = codec.decode(&mut buf) {}
});
