// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Read-through cache scoped to one immutable execution parent.

use std::{collections::BTreeMap, sync::Mutex};

use state::{StateAbsenceProof, StateError, StateProof, StateSnapshot};
use types::{Hash256, StateKey};

const MAX_ENTRIES: usize = 4096;
const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
struct Entries {
    values: BTreeMap<StateKey, Option<Vec<u8>>>,
    bytes: usize,
}

pub(crate) struct CachedSnapshot<'a> {
    parent: &'a dyn StateSnapshot,
    entries: Mutex<Entries>,
    max_entries: usize,
    max_bytes: usize,
}

impl<'a> CachedSnapshot<'a> {
    pub(crate) fn new(parent: &'a dyn StateSnapshot) -> Self {
        Self {
            parent,
            entries: Mutex::default(),
            max_entries: MAX_ENTRIES,
            max_bytes: MAX_BYTES,
        }
    }
}

impl StateSnapshot for CachedSnapshot<'_> {
    fn root(&self) -> Hash256 {
        self.parent.root()
    }

    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError> {
        if let Ok(entries) = self.entries.lock()
            && let Some(value) = entries.values.get(key)
        {
            return Ok(value.clone());
        }
        // Never hold the cache lock during storage I/O. Concurrent misses may
        // read twice; errors are returned directly and never retained.
        let value = self.parent.get(key)?;
        let Some(bytes) = key.len().checked_add(value.as_ref().map_or(0, Vec::len)) else {
            return Ok(value);
        };
        if let Ok(mut entries) = self.entries.lock()
            && entries.values.len() < self.max_entries
            && bytes <= self.max_bytes.saturating_sub(entries.bytes)
            && !entries.values.contains_key(key)
        {
            entries.values.insert(key.clone(), value.clone());
            entries.bytes += bytes;
        }
        // Full, oversized or unavailable caches simply use the parent value.
        Ok(value)
    }

    fn prove(&self, key: &StateKey) -> Result<Option<StateProof>, StateError> {
        self.parent.prove(key)
    }

    fn prove_absence(&self, key: &StateKey) -> Result<Option<StateAbsenceProof>, StateError> {
        self.parent.prove_absence(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use state::{InMemoryState, StateDatabase, StateDiff};

    struct CountingSnapshot {
        reads: AtomicUsize,
        failures: AtomicUsize,
    }

    impl CountingSnapshot {
        fn new(failures: usize) -> Self {
            Self {
                reads: AtomicUsize::new(0),
                failures: AtomicUsize::new(failures),
            }
        }
    }

    impl StateSnapshot for CountingSnapshot {
        fn root(&self) -> Hash256 {
            Hash256::ZERO
        }

        fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            if self
                .failures
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(StateError::Io);
            }
            Ok((key.as_bytes() != [0]).then(|| vec![7; 3]))
        }

        fn prove(&self, _: &StateKey) -> Result<Option<StateProof>, StateError> {
            Err(StateError::Io)
        }

        fn prove_absence(&self, _: &StateKey) -> Result<Option<StateAbsenceProof>, StateError> {
            Err(StateError::Io)
        }
    }

    #[test]
    fn repeated_values_and_absence_are_cached_but_errors_are_retried() {
        let parent = CountingSnapshot::new(1);
        let cache = CachedSnapshot::new(&parent);
        let key = StateKey(vec![1]);
        assert_eq!(cache.get(&key), Err(StateError::Io));
        for _ in 0..4 {
            assert_eq!(cache.get(&key), Ok(Some(vec![7; 3])));
            assert_eq!(cache.get(&StateKey(vec![0])), Ok(None));
        }
        assert_eq!(parent.reads.load(Ordering::Relaxed), 3);
        assert_eq!(cache.entries.lock().unwrap().bytes, 5);
    }

    #[test]
    fn entry_and_byte_limits_bypass_without_changing_values() {
        for (max_entries, max_bytes) in [(1, 100), (100, 4), (0, 100), (100, 3)] {
            let parent = CountingSnapshot::new(0);
            let cache = CachedSnapshot {
                max_entries,
                max_bytes,
                ..CachedSnapshot::new(&parent)
            };
            for _ in 0..2 {
                for key in [StateKey(vec![1]), StateKey(vec![2])] {
                    assert_eq!(cache.get(&key), Ok(Some(vec![7; 3])));
                }
            }
            let entries = cache.entries.lock().unwrap();
            assert!(entries.values.len() <= max_entries);
            assert!(entries.bytes <= max_bytes);
            let expected_reads = if max_entries == 0 || max_bytes < 4 {
                4
            } else {
                3
            };
            assert_eq!(parent.reads.load(Ordering::Relaxed), expected_reads);
        }
    }

    #[test]
    fn workers_share_cached_reads_and_keep_the_same_budget() {
        let parent = CountingSnapshot::new(0);
        let cache = CachedSnapshot::new(&parent);
        let key = StateKey(vec![1]);
        assert_eq!(cache.get(&key), Ok(Some(vec![7; 3])));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..32 {
                        assert_eq!(cache.get(&key), Ok(Some(vec![7; 3])));
                    }
                });
            }
        });
        assert_eq!(parent.reads.load(Ordering::Relaxed), 1);
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.bytes, 4);
        assert_eq!(entries.values.len(), 1);
    }

    #[test]
    fn overlays_override_cached_values_and_absence_and_new_parents_are_fresh() {
        let mut database = InMemoryState::new();
        let present = StateKey(vec![1]);
        let absent = StateKey(vec![2]);
        let mut initial = StateDiff::new();
        initial.put(present.clone(), vec![9]);
        database.commit(database.root(), &[initial]).unwrap();
        let snapshot = database.snapshot().unwrap();
        let cache = CachedSnapshot::new(snapshot.as_ref());
        assert_eq!(cache.get(&present), Ok(Some(vec![9])));
        assert_eq!(cache.get(&absent), Ok(None));
        assert_eq!(cache.root(), snapshot.root());
        assert_eq!(cache.prove(&present), snapshot.prove(&present));
        assert_eq!(
            cache.prove_absence(&absent),
            snapshot.prove_absence(&absent)
        );
        let mut changes = StateDiff::new();
        changes.delete(present.clone());
        changes.put(absent.clone(), vec![8]);
        let mut overlay = crate::parallel_payment::Overlay {
            parent: &cache,
            values: BTreeMap::new(),
        };
        overlay.apply(&changes);
        assert_eq!(overlay.get(&present), Ok(None));
        assert_eq!(overlay.get(&absent), Ok(Some(vec![8])));
        database.commit(database.root(), &[changes]).unwrap();
        let next = database.snapshot().unwrap();
        let fresh = CachedSnapshot::new(next.as_ref());
        assert_eq!(fresh.get(&present), Ok(None));
        assert_eq!(fresh.get(&absent), Ok(Some(vec![8])));
        assert_eq!(cache.get(&present), Ok(Some(vec![9])));
        assert_eq!(cache.get(&absent), Ok(None));
    }
}
