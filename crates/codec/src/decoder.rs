// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded cursor for canonical decoding without allocation.

use crate::error::DecodeError;

/// Cursor that performs bounded reads without allocation.
#[derive(Clone, Copy, Debug)]
pub struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    /// Creates a decoder over borrowed input.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Returns the number of unread bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    /// Reads an exact borrowed slice.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] when fewer than `length` bytes remain.
    pub fn read_exact(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DecodeError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(DecodeError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    /// Reads a fixed-size byte array.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] when fewer than `N` bytes remain.
    ///
    /// # Panics
    ///
    /// Panics only if `read_exact` returns a slice of wrong length, which is
    /// impossible because `read_exact` guarantees exactly `N` bytes.
    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let bytes = self.read_exact(N)?;
        Ok(bytes.try_into().expect("length already validated"))
    }

    /// Reads one little-endian `u8`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] when no bytes remain.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    /// Reads one little-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] unless two bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let bytes: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Reads one little-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] unless four bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Reads one little-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] unless eight bytes remain.
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Completes decoding and rejects unconsumed input.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::TrailingBytes`] when unread bytes remain.
    pub const fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncation() {
        let mut decoder = Decoder::new(&[1]);
        assert_eq!(decoder.read_u16(), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let decoder = Decoder::new(&[1, 2, 3]);
        assert_eq!(decoder.finish(), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn empty_succeeds() {
        let decoder = Decoder::new(&[]);
        assert_eq!(decoder.remaining(), 0);
        assert!(decoder.finish().is_ok());
    }

    #[test]
    fn tracks_position() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut decoder = Decoder::new(&data);
        assert_eq!(decoder.remaining(), 8);
        let _ = decoder.read_u8();
        assert_eq!(decoder.remaining(), 7);
        let _ = decoder.read_u32();
        assert_eq!(decoder.remaining(), 3);
        let _ = decoder.read_exact(3).unwrap();
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn read_u8_exact_one_byte() {
        let mut decoder = Decoder::new(&[0x42]);
        assert_eq!(decoder.read_u8().unwrap(), 0x42);
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn read_u16_little_endian() {
        let mut decoder = Decoder::new(&[0x34, 0x12]);
        assert_eq!(decoder.read_u16().unwrap(), 0x1234);
    }

    #[test]
    fn read_u32_little_endian() {
        let mut decoder = Decoder::new(&[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(decoder.read_u32().unwrap(), 0x1234_5678);
    }

    #[test]
    fn read_u64_little_endian() {
        let bytes = [0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];
        let mut decoder = Decoder::new(&bytes);
        assert_eq!(decoder.read_u64().unwrap(), 0x1234_5678_90AB_CDEF);
    }

    #[test]
    fn read_exact_zero_length() {
        let mut decoder = Decoder::new(&[1, 2, 3]);
        let result = decoder.read_exact(0).unwrap();
        assert_eq!(result, &[]);
        assert_eq!(decoder.remaining(), 3);
    }

    #[test]
    fn read_exact_full_length() {
        let mut decoder = Decoder::new(&[1, 2, 3]);
        let result = decoder.read_exact(3).unwrap();
        assert_eq!(result, &[1, 2, 3]);
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn read_exact_returns_error_on_truncation() {
        let mut decoder = Decoder::new(&[1, 2]);
        assert_eq!(decoder.read_exact(3), Err(DecodeError::Truncated));
    }

    #[test]
    fn read_fixed_32_bytes() {
        let data = [0xAB; 32];
        let mut decoder = Decoder::new(&data);
        let result = decoder.read_fixed::<32>().unwrap();
        assert_eq!(result, [0xAB; 32]);
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn read_fixed_returns_error_on_truncation() {
        let data = [0xAB; 31];
        let mut decoder = Decoder::new(&data);
        assert_eq!(decoder.read_fixed::<32>(), Err(DecodeError::Truncated));
    }

    #[test]
    fn finish_succeeds_on_empty() {
        let decoder = Decoder::new(&[]);
        assert!(decoder.finish().is_ok());
    }

    #[test]
    fn finish_fails_on_remaining() {
        let decoder = Decoder::new(&[1, 2, 3]);
        assert_eq!(decoder.finish(), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn sequential_reads() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut decoder = Decoder::new(&data);
        assert_eq!(decoder.read_u8().unwrap(), 1);
        assert_eq!(decoder.read_u16().unwrap(), 0x0302);
        assert_eq!(decoder.read_u32().unwrap(), 0x0706_0504);
        assert_eq!(decoder.read_u16().unwrap(), 0x0908);
        assert_eq!(decoder.finish(), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn read_u16_insufficient_bytes() {
        let mut decoder = Decoder::new(&[0x01]);
        assert_eq!(decoder.read_u16(), Err(DecodeError::Truncated));
    }

    #[test]
    fn read_u32_insufficient_bytes() {
        let mut decoder = Decoder::new(&[0x01, 0x02, 0x03]);
        assert_eq!(decoder.read_u32(), Err(DecodeError::Truncated));
    }

    #[test]
    fn read_u64_insufficient_bytes() {
        let mut decoder = Decoder::new(&[0x01; 7]);
        assert_eq!(decoder.read_u64(), Err(DecodeError::Truncated));
    }

    #[test]
    fn clone_decoder() {
        let data = [1u8, 2, 3, 4];
        let mut decoder = Decoder::new(&data);
        let _ = decoder.read_u8();
        let cloned = decoder;
        assert_eq!(decoder.remaining(), cloned.remaining());
    }

    #[test]
    fn debug_decoder() {
        let decoder = Decoder::new(&[1, 2, 3]);
        let debug = format!("{decoder:?}");
        assert!(debug.contains("Decoder"));
    }
}
