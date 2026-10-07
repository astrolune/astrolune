// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! State access leasing for deterministic scheduling.

use types::StateKey;

/// Access mode requested by a transaction lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessMode {
    /// Concurrent immutable access.
    Read,
    /// Exclusive mutable access.
    Write,
}

/// One declared state access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    /// Canonical state key.
    pub key: StateKey,
    /// Required access mode.
    pub mode: AccessMode,
}

/// A deterministic lease over state keys for one execution wave.
///
/// Keys are canonically sorted and deduplicated before scheduling. A lease
/// that omits an accessed key or uses the wrong mode triggers deterministic
/// failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateLease {
    /// Canonically sorted and deduplicated requests.
    pub requests: Vec<AccessRequest>,
}

impl StateLease {
    /// Sorts requests by key and merges duplicates, preserving write access.
    #[must_use]
    pub fn new(requests: impl IntoIterator<Item = AccessRequest>) -> Self {
        let mut modes = std::collections::BTreeMap::new();
        for request in requests {
            modes
                .entry(request.key)
                .and_modify(|mode| {
                    if request.mode == AccessMode::Write {
                        *mode = AccessMode::Write;
                    }
                })
                .or_insert(request.mode);
        }
        Self {
            requests: modes
                .into_iter()
                .map(|(key, mode)| AccessRequest { key, mode })
                .collect(),
        }
    }

    /// Returns `true` if the lease contains the given key in the required mode.
    /// A write lease also permits reading that key.
    #[must_use]
    pub fn covers(&self, key: &StateKey, mode: AccessMode) -> bool {
        self.requests
            .iter()
            .any(|req| req.key == *key && (req.mode == AccessMode::Write || req.mode == mode))
    }

    /// Returns whether concurrent execution could read or write conflicting data.
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.requests.iter().any(|left| {
            other.requests.iter().any(|right| {
                left.key == right.key
                    && (left.mode == AccessMode::Write || right.mode == AccessMode::Write)
            })
        })
    }

    /// Returns `true` if the lease has any write access.
    #[must_use]
    pub fn has_writes(&self) -> bool {
        self.requests
            .iter()
            .any(|req| req.mode == AccessMode::Write)
    }

    /// Returns the set of keys with write access.
    #[must_use]
    pub fn write_keys(&self) -> Vec<&StateKey> {
        self.requests
            .iter()
            .filter(|req| req.mode == AccessMode::Write)
            .map(|req| &req.key)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(key: u8, mode: AccessMode) -> AccessRequest {
        AccessRequest {
            key: StateKey(vec![key]),
            mode,
        }
    }

    #[test]
    fn normalization_sorts_and_preserves_strongest_access() {
        let lease = StateLease::new([
            request(2, AccessMode::Read),
            request(1, AccessMode::Write),
            request(2, AccessMode::Write),
            request(1, AccessMode::Read),
        ]);
        assert_eq!(
            lease.requests,
            vec![request(1, AccessMode::Write), request(2, AccessMode::Write)]
        );
        assert!(lease.covers(&StateKey(vec![1]), AccessMode::Read));
        assert!(lease.covers(&StateKey(vec![1]), AccessMode::Write));
        assert!(!lease.covers(&StateKey(vec![3]), AccessMode::Read));
    }

    #[test]
    fn reads_share_but_writes_conflict() {
        for left in [AccessMode::Read, AccessMode::Write] {
            for right in [AccessMode::Read, AccessMode::Write] {
                let a = StateLease::new([request(1, left)]);
                let b = StateLease::new([request(1, right)]);
                let expected = left == AccessMode::Write || right == AccessMode::Write;
                assert_eq!(a.conflicts_with(&b), expected);
                assert_eq!(b.conflicts_with(&a), expected);
                assert!(!a.conflicts_with(&StateLease::new([request(2, right)])));
            }
        }
    }
}
