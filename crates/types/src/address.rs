// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Wallet and contract addresses, and validator identity keys.

/// A wallet or contract address.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// The zero address.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Creates an address from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns `true` if the address is the zero value.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A validator identity key.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValidatorId(pub [u8; 32]);

impl ValidatorId {
    /// The zero validator identity (invalid in consensus).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Creates a validator identity from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns `true` if the identity is the zero value.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl std::fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
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
    fn address_zero_is_all_zeros() {
        assert!(Address::ZERO.is_zero());
    }

    #[test]
    fn address_display_prefixes_0x() {
        let addr = Address::from_bytes([0x42; 32]);
        let display = format!("{addr}");
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 66);
    }

    #[test]
    fn address_display_all_start_with_0x() {
        for byte in 0u8..=10 {
            let addr = Address([byte; 32]);
            let display = format!("{addr}");
            assert!(display.starts_with("0x"));
            assert_eq!(display.len(), 66);
        }
    }

    #[test]
    fn validator_id_zero_is_all_zeros() {
        assert!(ValidatorId::ZERO.is_zero());
    }

    #[test]
    fn validator_id_ordering() {
        let a = ValidatorId([1u8; 32]);
        let b = ValidatorId([2u8; 32]);
        assert!(a < b);
    }

    #[test]
    fn validator_id_ordering_transitive() {
        let a = ValidatorId([1; 32]);
        let b = ValidatorId([2; 32]);
        let c = ValidatorId([3; 32]);
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn validator_id_ordering_antisymmetric() {
        let a = ValidatorId([5; 32]);
        let b = ValidatorId([10; 32]);
        assert!(a < b);
        assert!(b >= a);
    }

    #[test]
    fn address_from_bytes_roundtrips() {
        let bytes = [0xAB; 32];
        let addr = Address::from_bytes(bytes);
        assert_eq!(addr.0, bytes);
        assert_eq!(*addr.as_bytes(), bytes);
    }

    #[test]
    fn validator_id_from_bytes_roundtrips() {
        let bytes = [0xCD; 32];
        let vid = ValidatorId::from_bytes(bytes);
        assert_eq!(vid.0, bytes);
        assert_eq!(*vid.as_bytes(), bytes);
    }

    #[test]
    fn address_not_zero() {
        let addr = Address([0xFF; 32]);
        assert!(!addr.is_zero());
    }

    #[test]
    fn validator_id_not_zero() {
        let vid = ValidatorId([0xFF; 32]);
        assert!(!vid.is_zero());
    }

    #[test]
    fn address_display_hex_lowercase() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x0A;
        bytes[1] = 0xFB;
        bytes[2] = 0x00;
        let addr = Address(bytes);
        let display = format!("{addr}");
        assert!(display.starts_with("0x0afb00"));
        assert!(display.chars().all(|c| c.is_ascii_hexdigit() || c == 'x'));
    }

    #[test]
    fn validator_id_display_hex_lowercase() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x0A;
        bytes[1] = 0xFB;
        bytes[2] = 0x00;
        let vid = ValidatorId(bytes);
        let display = format!("{vid}");
        assert!(display.starts_with("0x0afb00"));
        assert!(display.chars().all(|c| c.is_ascii_hexdigit() || c == 'x'));
    }

    #[test]
    fn address_eq_reflexive() {
        let addr = Address([0x42; 32]);
        assert_eq!(addr, addr);
    }

    #[test]
    fn address_eq_symmetric() {
        let a = Address([0x42; 32]);
        let b = Address([0x42; 32]);
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn validator_id_eq_reflexive() {
        let vid = ValidatorId([0x42; 32]);
        assert_eq!(vid, vid);
    }

    #[test]
    fn validator_id_eq_symmetric() {
        let a = ValidatorId([0x42; 32]);
        let b = ValidatorId([0x42; 32]);
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn address_clone() {
        let addr = Address([0x42; 32]);
        let cloned = addr;
        assert_eq!(addr, cloned);
    }

    #[test]
    fn validator_id_clone() {
        let vid = ValidatorId([0x42; 32]);
        let cloned = vid;
        assert_eq!(vid, cloned);
    }
}
