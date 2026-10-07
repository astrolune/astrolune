// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical encoding and decoding traits.

use crate::decoder::Decoder;
use crate::error::DecodeError;

/// A value that has one canonical byte representation.
pub trait CanonicalEncode {
    /// Appends the canonical representation to `output`.
    fn encode(&self, output: &mut Vec<u8>);

    /// Returns the canonical representation.
    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.encode(&mut output);
        output
    }
}

/// A value decoded from one complete canonical input.
pub trait CanonicalDecode: Sized {
    /// Decodes exactly one value and rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when the input is malformed, non-canonical,
    /// unsupported, too large, truncated, or contains trailing bytes.
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError>;
}

/// Extension trait for decoding a value from an already-positioned decoder.
pub(crate) trait DecoderExt<'a> {
    /// Reads a `StateKey` at the current position.
    fn read_state_key(&mut self) -> Result<types::StateKey, DecodeError>;

    /// Reads a `Resources` at the current position.
    fn read_resources(&mut self) -> Result<types::Resources, DecodeError>;
}

/// Helper trait for decoding at a decoder position.
pub(crate) trait DecodeAt: Sized {
    fn decode_at(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError>;
}
