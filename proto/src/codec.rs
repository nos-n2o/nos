use std::marker::PhantomData;

use bytes::{Buf, BufMut, BytesMut};
use serde::{de::DeserializeOwned, Serialize};
use tokio_util::codec::{Decoder, Encoder};

/// Largest accepted payload; a longer length prefix is `InvalidData` on both encode and decode.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Most bytes a single `decode` call reserves for an incomplete frame, so buffer memory grows
/// as bytes actually arrive rather than to the declared length up front.
pub const RESERVE_CHUNK: usize = 64 * 1024;

fn too_large() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "ipc frame too large")
}

/// Framed codec for IPC messages over a Unix socket.
///
/// Wire format: 4-byte little-endian length prefix followed by a postcard-encoded payload
/// of at most [`MAX_FRAME`] bytes.
/// A single `IpcCodec<T>` instance handles both encoding and decoding of type `T`.
pub struct IpcCodec<T>(PhantomData<T>);

impl<T> Default for IpcCodec<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: Serialize> Encoder<T> for IpcCodec<T> {
    type Error = std::io::Error;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload = postcard::to_allocvec(&item)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        if payload.len() > MAX_FRAME {
            return Err(too_large());
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "bounded by MAX_FRAME < u32::MAX"
        )]
        dst.put_u32_le(payload.len() as u32);
        dst.put_slice(&payload);
        Ok(())
    }
}

impl<T: DeserializeOwned> Decoder for IpcCodec<T> {
    type Item = T;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<T>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes(src[..4].try_into().unwrap()) as usize;
        if len > MAX_FRAME {
            return Err(too_large());
        }
        if src.len() < 4 + len {
            src.reserve((4 + len - src.len()).min(RESERVE_CHUNK));
            return Ok(None);
        }
        src.advance(4);
        let data = src.split_to(len);
        postcard::from_bytes(&data)
            .map(Some)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // postcard encodes a `u8` as one byte, so `[len=1, 0, 0, 0, v]` is a frame.
    fn dec(buf: &mut BytesMut) -> Result<Option<u8>, std::io::Error> {
        IpcCodec::<u8>::default().decode(buf)
    }

    #[test]
    fn header_split_across_reads_needs_more() {
        for n in 0..4 {
            let mut b = BytesMut::from(&[1u8, 0, 0, 0][..n]);
            assert_eq!(dec(&mut b).unwrap(), None);
            assert_eq!(b.len(), n);
        }
    }

    #[test]
    fn exact_frame_decodes_and_one_byte_short_waits() {
        let mut b = BytesMut::from(&[1u8, 0, 0, 0, 42][..]);
        assert_eq!(dec(&mut b).unwrap(), Some(42));
        assert!(b.is_empty());

        let mut b = BytesMut::from(&[2u8, 0, 0, 0, 42][..]); // len 2, 1 payload byte
        assert_eq!(dec(&mut b).unwrap(), None);
        assert_eq!(&b[..], &[2, 0, 0, 0, 42], "untouched while incomplete");
    }

    #[test]
    fn zero_length_frame_is_a_decode_error_not_need_more() {
        let mut b = BytesMut::from(&[0u8, 0, 0, 0][..]);
        assert!(dec(&mut b).is_err());
        assert!(b.is_empty());
    }

    #[test]
    fn over_cap_header_rejected_without_reserving() {
        for len in [u32::try_from(MAX_FRAME + 1).unwrap(), u32::MAX] {
            let mut b = BytesMut::from(&len.to_le_bytes()[..]);
            let cap = b.capacity();
            let e = dec(&mut b).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(b.capacity(), cap, "no reserve for a hostile length");
        }
    }

    #[test]
    fn at_cap_header_reserves_one_chunk_not_the_declared_length() {
        let mut b = BytesMut::from(&u32::try_from(MAX_FRAME).unwrap().to_le_bytes()[..]);
        assert_eq!(dec(&mut b).unwrap(), None);
        assert!(b.capacity() >= RESERVE_CHUNK, "reserved a chunk");
        assert!(b.capacity() < 2 * RESERVE_CHUNK, "not the declared length");
    }

    #[test]
    #[cfg_attr(miri, ignore = "16 MiB frame, minutes under the interpreter")]
    fn at_cap_frame_roundtrips_and_over_cap_encode_fails() {
        // postcard `Vec<u8>` = varint length (4 bytes at this size) + bytes.
        let mut c = IpcCodec::<Vec<u8>>::default();
        let mut buf = BytesMut::new();
        c.encode(vec![7u8; MAX_FRAME - 4], &mut buf).unwrap();
        assert_eq!(buf.len(), 4 + MAX_FRAME);
        assert_eq!(c.decode(&mut buf).unwrap().unwrap().len(), MAX_FRAME - 4);

        let e = c
            .encode(vec![7u8; MAX_FRAME - 3], &mut BytesMut::new())
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn trailing_bytes_stay_for_the_next_frame() {
        let mut b = BytesMut::from(&[1u8, 0, 0, 0, 7, 1, 0][..]);
        assert_eq!(dec(&mut b).unwrap(), Some(7));
        assert_eq!(&b[..], &[1, 0]);
    }
}
