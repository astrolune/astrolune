// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical encoding and decoding for primitive Rust types.

use crate::decoder::Decoder;
use crate::error::DecodeError;
use crate::traits::{CanonicalDecode, CanonicalEncode};

impl CanonicalEncode for u8 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(*self);
    }
}

impl CanonicalEncode for u16 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.to_le_bytes());
    }
}

impl CanonicalEncode for u32 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.to_le_bytes());
    }
}

impl CanonicalEncode for u64 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.to_le_bytes());
    }
}

impl CanonicalEncode for bool {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(u8::from(*self));
    }
}

impl<const N: usize> CanonicalEncode for [u8; N] {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(self);
    }
}

impl CanonicalDecode for u8 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_u8()?;
        decoder.finish()?;
        Ok(value)
    }
}

impl CanonicalDecode for u16 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_u16()?;
        decoder.finish()?;
        Ok(value)
    }
}

impl CanonicalDecode for u32 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_u32()?;
        decoder.finish()?;
        Ok(value)
    }
}

impl CanonicalDecode for u64 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_u64()?;
        decoder.finish()?;
        Ok(value)
    }
}

impl CanonicalDecode for bool {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_u8()?;
        decoder.finish()?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::NonCanonical),
        }
    }
}

impl<const N: usize> CanonicalDecode for [u8; N] {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_fixed::<N>()?;
        decoder.finish()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::CanonicalEncode;

    #[test]
    fn u8_roundtrip() {
        let values = [0u8, 1, 127, 128, 255];
        for v in values {
            let encoded = v.to_bytes();
            let decoded = u8::decode(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn u16_roundtrip() {
        let values = [0u16, 1, 255, 256, 1024, u16::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 2);
            let decoded = u16::decode(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn u32_roundtrip() {
        let values = [0u32, 1, 256, 65536, u32::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 4);
            let decoded = u32::decode(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn u64_roundtrip() {
        let values = [0u64, 1, 256, 65536, u64::from(u32::MAX) + 1, u64::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 8);
            let decoded = u64::decode(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn bool_roundtrip() {
        let encoded_false = false.to_bytes();
        assert_eq!(encoded_false, [0]);
        assert!(!bool::decode(&encoded_false).unwrap());

        let encoded_true = true.to_bytes();
        assert_eq!(encoded_true, [1]);
        assert!(bool::decode(&encoded_true).unwrap());
    }

    #[test]
    fn bool_rejects_non_canonical() {
        assert_eq!(bool::decode(&[2]), Err(DecodeError::NonCanonical));
        assert_eq!(bool::decode(&[255]), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn fixed_array_roundtrips() {
        let arr1: [u8; 1] = [42];
        assert_eq!(<[u8; 1]>::decode(&arr1.to_bytes()).unwrap(), arr1);

        let arr4: [u8; 4] = [1, 2, 3, 4];
        assert_eq!(<[u8; 4]>::decode(&arr4.to_bytes()).unwrap(), arr4);

        let arr32: [u8; 32] = [0xAB; 32];
        assert_eq!(<[u8; 32]>::decode(&arr32.to_bytes()).unwrap(), arr32);
    }

    #[test]
    fn u8_exhaustive_roundtrip() {
        for v in 0u8..=255 {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 1);
            let decoded = u8::decode(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn u16_boundary_values() {
        let values = [0, 1, 127, 128, 255, 256, 1023, 1024, 32767, 32768, u16::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 2);
            assert_eq!(u16::decode(&encoded).unwrap(), v);
        }
    }

    #[test]
    fn u32_boundary_values() {
        let values = [0u32, 1, 255, 256, 65535, 65536, u32::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 4);
            assert_eq!(u32::decode(&encoded).unwrap(), v);
        }
    }

    #[test]
    fn u64_boundary_values() {
        let values: [u64; 8] = [0, 1, 255, 256, 65535, 65536, u64::from(u32::MAX), u64::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 8);
            assert_eq!(u64::decode(&encoded).unwrap(), v);
        }
    }

    #[test]
    fn bool_only_canonical_values_accepted() {
        assert!(!bool::decode(&[0]).unwrap());
        assert!(bool::decode(&[1]).unwrap());
        for v in 2..=255 {
            assert_eq!(bool::decode(&[v]), Err(DecodeError::NonCanonical));
        }
    }

    #[test]
    fn golden_u16_zero() {
        assert_eq!(0u16.to_bytes(), [0, 0]);
    }

    #[test]
    fn golden_u16_one() {
        assert_eq!(1u16.to_bytes(), [1, 0]);
    }

    #[test]
    fn golden_u16_256() {
        assert_eq!(256u16.to_bytes(), [0, 1]);
    }

    #[test]
    fn golden_u32_max() {
        assert_eq!(u32::MAX.to_bytes(), [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn golden_u64_one() {
        assert_eq!(1u64.to_bytes(), [1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn encoding_determinism() {
        for v in [0u64, 1, 42, u64::MAX / 2, u64::MAX] {
            let e1 = v.to_bytes();
            let e2 = v.to_bytes();
            assert_eq!(e1, e2);
        }
    }

    #[test]
    fn trailing_byte_rejection_all_types() {
        assert_eq!(u8::decode(&[0, 0xFF]), Err(DecodeError::TrailingBytes));
        assert_eq!(u16::decode(&[0, 0, 0xFF]), Err(DecodeError::TrailingBytes));
        assert_eq!(
            u32::decode(&[0, 0, 0, 0, 0xFF]),
            Err(DecodeError::TrailingBytes)
        );
        assert_eq!(u64::decode(&[0; 9]), Err(DecodeError::TrailingBytes));
        assert_eq!(bool::decode(&[0, 0xFF]), Err(DecodeError::TrailingBytes));
        let data = vec![0u8; 33];
        assert_eq!(<[u8; 32]>::decode(&data), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn truncation_rejection_all_types() {
        assert!(u16::decode(&[0]).is_err());
        assert!(u32::decode(&[0, 0]).is_err());
        assert!(u64::decode(&[0; 7]).is_err());
        assert!(<[u8; 32]>::decode(&[0; 31]).is_err());
    }
}
