// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! A cryptographic digest committed by the protocol.

use blake2::{Blake2s256, Digest};

/// Computes the protocol BLAKE2s-256 digest with a length-framed domain.
#[must_use]
pub fn domain_hash(domain: &[u8], message: &[u8]) -> Hash256 {
    let mut hash = Blake2s256::new();
    hash.update(b"astrolune.v1.");
    hash.update((domain.len() as u64).to_le_bytes());
    hash.update(domain);
    hash.update(message);
    Hash256(hash.finalize().into())
}

/// A cryptographic digest committed by the protocol.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// The all-zero digest.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Creates a digest from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns `true` if the digest is the all-zero value.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Combines two digests by XOR-ing their bytes.
    ///
    /// This commutative bit operation is not a cryptographic commitment.
    #[must_use]
    pub const fn xor(self, other: Self) -> Self {
        let mut result = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            result[i] = self.0[i] ^ other.0[i];
            i += 1;
        }
        Self(result)
    }
}

impl std::fmt::Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_all_zeros() {
        assert_eq!(Hash256::ZERO.0, [0u8; 32]);
        assert!(Hash256::ZERO.is_zero());
    }

    #[test]
    fn from_bytes_roundtrips() {
        let bytes = [0xAB_u8; 32];
        let hash = Hash256::from_bytes(bytes);
        assert_eq!(*hash.as_bytes(), bytes);
    }

    #[test]
    fn xor_is_deterministic() {
        let a = Hash256([1u8; 32]);
        let b = Hash256([2u8; 32]);
        let result = a.xor(b);
        assert_eq!(result, b.xor(a));
        assert_eq!(result.0, [3u8; 32]);
    }

    #[test]
    fn display_is_hex_lowercase() {
        let hash = Hash256([
            0x0A, 0xFB, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ]);
        let display = format!("{hash}");
        assert!(display.starts_with("0afb00"));
        assert_eq!(display.len(), 64);
    }

    #[test]
    fn xor_commutative() {
        let a = Hash256([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let b = Hash256([
            32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
            10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ]);
        assert_eq!(a.xor(b), b.xor(a));
    }

    #[test]
    fn xor_self_yields_zero() {
        let a = Hash256([42; 32]);
        assert_eq!(a.xor(a), Hash256::ZERO);
    }

    #[test]
    fn xor_zero_identity() {
        for byte in 0u8..=255 {
            let h = Hash256([byte; 32]);
            assert_eq!(h.xor(Hash256::ZERO), h);
            assert_eq!(Hash256::ZERO.xor(h), h);
        }
    }

    #[test]
    fn display_all_64_hex_chars() {
        for byte in 0u8..=255 {
            let hash = Hash256([byte; 32]);
            let display = format!("{hash}");
            assert_eq!(display.len(), 64);
            assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(display.chars().all(|c| !c.is_uppercase()));
        }
    }
}
