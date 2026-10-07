// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded-length state keys for deterministic state access.

/// A state key. Canonical encoding must impose a bounded length before use.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateKey(pub Vec<u8>);

impl StateKey {
    /// Maximum allowed key length in bytes.
    pub const MAX_LEN: usize = 256;

    /// Creates a new state key from bytes.
    ///
    /// Returns `None` if the key exceeds [`Self::MAX_LEN`].
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() > Self::MAX_LEN {
            None
        } else {
            Some(Self(bytes))
        }
    }

    /// Returns the key bytes as a slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the key is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_len_enforced() {
        let ok = StateKey::new(vec![0u8; 256]);
        assert!(ok.is_some());

        let too_long = StateKey::new(vec![0u8; 257]);
        assert!(too_long.is_none());
    }

    #[test]
    fn empty() {
        let key = StateKey(Vec::new());
        assert!(key.is_empty());
        assert_eq!(key.len(), 0);
    }

    #[test]
    fn new_returns_some_for_valid_length() {
        assert!(StateKey::new(vec![0u8; 0]).is_some());
        assert!(StateKey::new(vec![0u8; 1]).is_some());
        assert!(StateKey::new(vec![0u8; 128]).is_some());
        assert!(StateKey::new(vec![0u8; 255]).is_some());
        assert!(StateKey::new(vec![0u8; 256]).is_some());
    }

    #[test]
    fn new_returns_none_for_excess_length() {
        assert!(StateKey::new(vec![0u8; 257]).is_none());
        assert!(StateKey::new(vec![0u8; 258]).is_none());
        assert!(StateKey::new(vec![0u8; 1024]).is_none());
    }

    #[test]
    fn as_bytes_returns_slice() {
        let key = StateKey(vec![1, 2, 3, 4, 5]);
        assert_eq!(key.as_bytes(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn len_returns_correct_length() {
        let key = StateKey(vec![0u8; 42]);
        assert_eq!(key.len(), 42);
    }

    #[test]
    fn is_empty_correct() {
        let empty = StateKey(Vec::new());
        assert!(empty.is_empty());

        let non_empty = StateKey(vec![0u8; 1]);
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn state_key_clone() {
        let key = StateKey(vec![1, 2, 3]);
        let cloned = key.clone();
        assert_eq!(key, cloned);
    }

    #[test]
    fn state_key_eq_reflexive() {
        let key = StateKey(vec![1, 2, 3]);
        assert_eq!(key, key);
    }

    #[test]
    fn state_key_eq_symmetric() {
        let a = StateKey(vec![1, 2, 3]);
        let b = StateKey(vec![1, 2, 3]);
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn state_key_ord() {
        let a = StateKey(vec![1, 2, 3]);
        let b = StateKey(vec![1, 2, 4]);
        assert!(a < b);
    }

    #[test]
    fn state_key_ord_equal() {
        let a = StateKey(vec![1, 2, 3]);
        let b = StateKey(vec![1, 2, 3]);
        assert!(a <= b);
        assert!(a >= b);
    }

    #[test]
    fn state_key_max_len_boundary() {
        let max = StateKey::new(vec![0xAA; 256]);
        assert!(max.is_some());
        assert_eq!(max.unwrap().len(), 256);

        let over = StateKey::new(vec![0xBB; 257]);
        assert!(over.is_none());
    }

    #[test]
    fn state_key_various_lengths() {
        for len in [0, 1, 32, 64, 128, 256] {
            let key = StateKey::new(vec![0u8; len]);
            assert!(key.is_some());
            assert_eq!(key.unwrap().len(), len);
        }
    }
}
