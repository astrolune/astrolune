// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Measures state commitments, proof generation, proof verification and snapshots.
//!
//! The figures describe one machine, one toolchain and one fixture shape: equal
//! sized accounts inserted in canonical key order. They are not a correctness
//! gate. A proof that verifies faster is not more authentic, and the golden
//! roots, tree shapes and tampering cases that do establish correctness live in
//! `crates/state/tests`, not here.
//!
//! Generation and verification are recorded separately because they are paid by
//! different parties: a prover rebuilds the tree, while a client only walks one
//! path. Comparing the two columns is the point of the sweep.
//!
//! What this does NOT establish: an asymptotic bound of any kind, since three
//! sizes cannot distinguish one growth curve from another; the cost of a tree
//! whose keys or values are unevenly sized; block or network throughput; memory
//! residency of retained snapshots; or a figure comparable to a different
//! machine, allocator or toolchain. Every overlay figure includes allocating
//! and freeing the prepared copy, so it is not a measurement of hashing alone.

use codec::CanonicalEncode;
use state::{
    InMemoryState, StateAbsenceProof, StateDatabase, StateDiff, StateSnapshot, account_key,
    read_account,
};
use std::collections::BTreeMap;
use testkit::bench::Suite;
use types::{AccountState, Address, StateKey};

/// Account counts swept by the commitment, proof and snapshot measurements.
///
/// The range spans more than two orders of magnitude so the growth of a
/// tree-wide operation is visible instead of being summarized by one figure.
const ACCOUNT_COUNTS: [u64; 3] = [16, 256, 4096];

/// Largest swept tree, reused for the change-count and proof transport figures.
const LARGEST_TREE: u64 = 4096;

/// Changes applied to [`LARGEST_TREE`] accounts in one prepared transition.
///
/// Two changes is the shape of a single payment; the larger counts bracket a
/// block that rewrites many accounts at once.
const CHANGE_COUNTS: [u64; 4] = [1, 2, 16, 256];

/// Change counts measured for the ordered diff commitment.
const DIFF_CHANGE_COUNTS: [u64; 3] = [2, 64, 512];

/// Returns the account address stored at `index`.
///
/// The leading eight bytes carry twice the index in big-endian order, so
/// canonical key order follows the index and every odd value names an address
/// that falls strictly inside the gap between two stored accounts.
fn address_at(index: u64) -> Address {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&(index * 2).to_be_bytes());
    Address(bytes)
}

/// Returns a key that is absent, and interior to the tree, just above `index`.
fn gap_key_at(index: u64) -> StateKey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&(index * 2 + 1).to_be_bytes());
    account_key(Address(bytes))
}

/// Returns the canonical key and encoded value of the account at `index`.
fn account_entry(index: u64) -> (StateKey, Vec<u8>) {
    let account = AccountState {
        nonce: index,
        balance: 1_000_000 + index,
    };
    (account_key(address_at(index)), account.to_bytes())
}

/// Returns a diff inserting `count` accounts.
fn insert_accounts(count: u64) -> StateDiff {
    let mut diff = StateDiff::new();
    for index in 0..count {
        let (key, value) = account_entry(index);
        diff.put(key, value);
    }
    diff
}

/// Returns a diff rewriting `count` accounts that already exist.
///
/// Rewrites keep the entry count fixed, so a swept change count measures the
/// transition and not a change in tree size.
fn rewrite_accounts(count: u64) -> StateDiff {
    let mut diff = StateDiff::new();
    for index in 0..count {
        let account = AccountState {
            nonce: index + 1,
            balance: index,
        };
        diff.put(account_key(address_at(index)), account.to_bytes());
    }
    diff
}

/// Returns a committed state holding `count` accounts.
///
/// # Panics
///
/// Panics if the fixture exceeds a reference state bound, which would make the
/// measurement meaningless rather than slow.
fn populated(count: u64) -> InMemoryState {
    let mut state = InMemoryState::new();
    let parent = state.root();
    state
        .commit(parent, &[insert_accounts(count)])
        .expect("bounded account fixture commits");
    state
}

/// Returns the same entries as [`populated`] in a plain ordered map.
///
/// This exists only as a copy baseline. A prepared transition clones the entry
/// map before hashing anything, and the state engine does not expose its own
/// map, so the separable part of an overlay figure is measured here instead.
fn entry_map(count: u64) -> BTreeMap<StateKey, Vec<u8>> {
    (0..count).map(account_entry).collect()
}

/// Records root recomputation, overlay and snapshot figures for one tree size.
fn bench_tree(suite: &mut Suite, count: u64) {
    let state = populated(count);
    let root = state.root();
    let entries = entry_map(count);
    let payment = [rewrite_accounts(2)];
    let bytes = state.export_snapshot();
    let address = address_at(count / 2);

    // A transition with no changes: the staged-size scan, the overlay copy and
    // a complete root recomputation over `count` leaves.
    suite.bench(format!("state_root/recompute/{count}"), || {
        state.prepare(root, &[])
    });
    // The overlay copy on its own, so the hashing share above is separable.
    suite.bench(format!("state_root/overlay_copy_only/{count}"), || {
        entries.clone()
    });
    // A payment-shaped transition: two existing accounts rewritten.
    suite.bench(format!("commit/prepare/{count}/payment"), || {
        state.prepare(root, &payment)
    });
    // Snapshots share immutable entries, so this is a handle and not a copy.
    suite.bench(format!("snapshot/handle/{count}"), || state.snapshot());
    suite.bench(format!("snapshot/export/{count}"), || {
        state.export_snapshot()
    });
    // Import decodes bounded framing and then recomputes the root to check it.
    suite.bench(format!("snapshot/import/{count}"), || {
        InMemoryState::from_snapshot(&bytes, root)
    });
    suite.bench(format!("read/account/{count}"), || {
        read_account(&state, address)
    });
}

/// Records proof generation and verification figures for one tree size.
///
/// # Panics
///
/// Panics if the fixture cannot produce the proofs it is built to produce,
/// which would mean the measurement is not measuring what it claims.
fn bench_proofs(suite: &mut Suite, count: u64) {
    let state = populated(count);
    let root = state.root();
    let (key, value) = account_entry(count / 2);
    let gap = gap_key_at(count / 2);
    let membership = state
        .prove(&key)
        .expect("stored key is within bounds")
        .expect("stored key has a membership path");
    let absence = state
        .prove_absence(&gap)
        .expect("gap key is within bounds")
        .expect("interior gap key is absent");

    suite.bench(format!("prove/membership/{count}"), || state.prove(&key));
    suite.bench(format!("verify/membership/{count}"), || {
        membership.verify(root, &key, &value)
    });
    // An interior gap carries two witnesses, so this is the two-neighbor case.
    suite.bench(format!("prove/absence/{count}"), || {
        state.prove_absence(&gap)
    });
    suite.bench(format!("verify/absence/{count}"), || {
        absence.verify(root, &gap)
    });
}

/// Records prepared transitions over a swept change count at a fixed tree size.
fn bench_change_counts(suite: &mut Suite) {
    let state = populated(LARGEST_TREE);
    let root = state.root();
    for changes in CHANGE_COUNTS {
        let diffs = [rewrite_accounts(changes)];
        suite.bench(
            format!("commit/prepare/{LARGEST_TREE}/{changes}_changes"),
            || state.prepare(root, &diffs),
        );
    }
}

/// Records the ordered diff commitment over a swept change count.
///
/// The commitment binds the operation sequence rather than the resulting
/// entries, so it is independent of the tree it will be applied to.
fn bench_diff_commitment(suite: &mut Suite) {
    for changes in DIFF_CHANGE_COUNTS {
        let diff = rewrite_accounts(changes);
        suite.bench(format!("diff/commitment/{changes}_changes"), || {
            diff.commitment()
        });
    }
}

/// Records bounded absence-proof transport at the largest swept tree.
///
/// Encoded size grows only with the sibling count, so these figures are nearly
/// flat across the sweep and are recorded once.
///
/// # Panics
///
/// Panics if the fixture proof is not encodable, which would contradict the
/// bounds the fixture is built within.
fn bench_proof_transport(suite: &mut Suite) {
    let state = populated(LARGEST_TREE);
    let gap = gap_key_at(LARGEST_TREE / 2);
    let absence = state
        .prove_absence(&gap)
        .expect("gap key is within bounds")
        .expect("interior gap key is absent");
    let bytes = absence.to_bytes().expect("bounded proof encodes");

    suite.bench(format!("absence_proof/to_bytes/{LARGEST_TREE}"), || {
        absence.to_bytes()
    });
    // Decoding checks framing and bounds; it authenticates nothing.
    suite.bench(format!("absence_proof/from_bytes/{LARGEST_TREE}"), || {
        StateAbsenceProof::from_bytes(&bytes)
    });
}

fn main() {
    let mut suite = Suite::new("state");
    for count in ACCOUNT_COUNTS {
        bench_tree(&mut suite, count);
        bench_proofs(&mut suite, count);
    }
    bench_change_counts(&mut suite);
    bench_diff_commitment(&mut suite);
    bench_proof_transport(&mut suite);
    suite.report();
}
