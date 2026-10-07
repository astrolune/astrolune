// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Binary frame encoding, decoding, and wire-format constants.

use crate::error::NetworkError;
use crate::message::MessageKind;

/// Maximum frame payload size in bytes (1 MiB).
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Frame header size: 1 byte kind + 4 bytes LE length.
pub const FRAME_HEADER_SIZE: usize = 5;

/// A zero-copy view over a validated binary frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    /// Message discriminator.
    pub kind: MessageKind,
    /// Borrowed payload from the transport receive buffer.
    pub payload: &'a [u8],
}

/// Decodes one bounded canonical frame without owning the input buffer.
pub trait FrameDecoder {
    /// Rejects unknown versions, oversized frames, non-canonical lengths, and
    /// trailing bytes before returning a borrowed payload.
    fn decode<'a>(&self, bytes: &'a [u8]) -> Result<Frame<'a>, NetworkError>;
}

/// A [`FrameDecoder`] implementation that enforces a maximum payload size.
#[derive(Clone, Copy, Debug)]
pub struct BoundedFrameDecoder {
    max_frame_size: usize,
}

impl BoundedFrameDecoder {
    /// Creates a new decoder with the given maximum frame payload size.
    #[must_use]
    pub fn new(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }
}

impl FrameDecoder for BoundedFrameDecoder {
    fn decode<'a>(&self, bytes: &'a [u8]) -> Result<Frame<'a>, NetworkError> {
        if bytes.len() < FRAME_HEADER_SIZE {
            return Err(NetworkError::InvalidFrame);
        }

        let kind = MessageKind::from_u8(bytes[0]).ok_or(NetworkError::InvalidFrame)?;

        let len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;

        if len > self.max_frame_size {
            return Err(NetworkError::LimitExceeded);
        }

        if bytes.len() != FRAME_HEADER_SIZE + len {
            return Err(NetworkError::InvalidFrame);
        }

        Ok(Frame {
            kind,
            payload: &bytes[FRAME_HEADER_SIZE..],
        })
    }
}

/// Encodes a message kind and payload into a canonical binary frame.
#[derive(Clone, Copy, Debug)]
pub struct FrameEncoder;

impl FrameEncoder {
    /// Encodes `kind` and `payload` into a byte vector with a 5-byte header.
    ///
    /// # Panics
    ///
    /// Panics if `payload.len()` exceeds `u32::MAX`.
    #[must_use]
    pub fn encode(kind: MessageKind, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).expect("payload exceeds u32::MAX");
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
        buf.push(kind as u8);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_frame_size_is_1_mib() {
        assert_eq!(MAX_FRAME_SIZE, 1024 * 1024);
    }

    #[test]
    fn frame_header_size_is_5() {
        assert_eq!(FRAME_HEADER_SIZE, 5);
    }

    #[test]
    fn encode_decode_roundtrip() {
        for kind in [
            MessageKind::Hello,
            MessageKind::Transactions,
            MessageKind::CompactBlock,
            MessageKind::Proposal,
            MessageKind::Vote,
            MessageKind::Finality,
        ] {
            let payload = b"hello world";
            let encoded = FrameEncoder::encode(kind, payload);
            let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
            let frame = decoder.decode(&encoded).unwrap();
            assert_eq!(frame.kind, kind);
            assert_eq!(frame.payload, payload);
        }
    }

    #[test]
    fn encode_decode_empty_payload() {
        let encoded = FrameEncoder::encode(MessageKind::Hello, &[]);
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        let frame = decoder.decode(&encoded).unwrap();
        assert_eq!(frame.kind, MessageKind::Hello);
        assert_eq!(frame.payload.len(), 0);
    }

    #[test]
    fn encode_decode_max_payload() {
        let payload = vec![0xAB; MAX_FRAME_SIZE];
        let encoded = FrameEncoder::encode(MessageKind::Vote, &payload);
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        let frame = decoder.decode(&encoded).unwrap();
        assert_eq!(frame.kind, MessageKind::Vote);
        assert_eq!(frame.payload, &payload[..]);
    }

    #[test]
    fn oversized_frame_rejected() {
        let payload = vec![0u8; 100];
        let encoded = FrameEncoder::encode(MessageKind::Hello, &payload);
        let decoder = BoundedFrameDecoder::new(50);
        assert_eq!(decoder.decode(&encoded), Err(NetworkError::LimitExceeded));
    }

    #[test]
    fn unknown_kind_rejected() {
        let mut bytes = vec![0xFF; 10];
        bytes[0] = 0xFF;
        bytes[1] = 5;
        bytes[2] = 0;
        bytes[3] = 0;
        bytes[4] = 0;
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        assert_eq!(decoder.decode(&bytes), Err(NetworkError::InvalidFrame));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let payload = b"payload";
        let mut encoded = FrameEncoder::encode(MessageKind::Hello, payload);
        encoded.push(0xFF);
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        assert_eq!(decoder.decode(&encoded), Err(NetworkError::InvalidFrame));
    }

    #[test]
    fn too_short_header_rejected() {
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        assert_eq!(decoder.decode(&[0, 1, 2]), Err(NetworkError::InvalidFrame));
        assert_eq!(decoder.decode(&[]), Err(NetworkError::InvalidFrame));
    }
}
