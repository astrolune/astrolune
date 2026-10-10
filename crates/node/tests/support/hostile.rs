// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Shared hostile-schedule fixtures: derived rosters, adverse weight concentration and
//! validly signing Byzantine vote synthesis for the rotating network simulations.
//!
//! Nothing here weakens a production guard. Participants keep their protected signing
//! journals; a Byzantine coalition is synthesized at the wire/vote level with the same
//! deterministic public fixture keys the rest of the test suite already publishes.

#![allow(dead_code)]

use consensus::{
    DoubleVoteEvidence, Vote, potb::PotbPolicy, potb_transition::PotbConfiguration, quorum_power,
};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use genesis::{Genesis, GenesisValidator};
use keystore::{DurableSigner, SigningContext};
use node::network::{NetworkNode, StaticNetwork};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use types::{Hash256, Resources, ValidatorId};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Shared capacity for every simulated profile, matching the consensus fixture.
pub const CAPACITY: Resources = Resources {
    compute: 1_000_000,
    memory: 1_000_000,
    io: 1_000_000,
    bandwidth: 1_000_000,
};

/// Hand-rolled xorshift64 schedule source. These tests never use an RNG crate.
pub struct Random(pub u64);

impl Random {
    /// Deterministic index strictly below `limit`.
    pub fn choose(&mut self, limit: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % u64::try_from(limit).unwrap()).unwrap()
    }
    /// Deterministic in-place Fisher-Yates shuffle.
    pub fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let other = self.choose(index + 1);
            values.swap(index, other);
        }
    }
}

/// Public fixture identity for a deterministic seed.
#[must_use]
pub fn identity(seed: u8) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[seed; 32])).0)
}

/// Registered keys in fixture seed order; genesis member order is independent of it.
#[must_use]
pub fn keys(seeds: &[u8]) -> Vec<[u8; 32]> {
    seeds
        .iter()
        .map(|seed| ed25519_public_key(&[*seed; 32]))
        .collect()
}

/// Rotating genesis with explicit per-seed weights, so quorum is not a seat count.
#[must_use]
pub fn rotating_genesis(seeds: &[u8], weights: &[u128], seats: usize) -> Genesis {
    assert_eq!(seeds.len(), weights.len(), "one weight per registered seed");
    let mut validators: Vec<_> = seeds
        .iter()
        .zip(weights)
        .map(|(seed, weight)| GenesisValidator {
            id: identity(*seed),
            weight: *weight,
        })
        .collect();
    validators.sort_by_key(|member| member.id);
    Genesis {
        version: 2,
        chain_id: 71,
        committee_size: seats,
        rotation_count: 1,
        runtime_version: 2,
        capacity: CAPACITY,
        validators,
        allocations: vec![],
    }
}

/// `PoTB` requires uniform starting weights, so concentration stays a rotating scenario.
///
/// A zero `age_increment` freezes every weight at `weight`, which a coalition scenario
/// needs so its exact share of any reachable committee is known in advance.
#[must_use]
pub fn potb_configuration(
    seeds: &[u8],
    weight: u128,
    seats: usize,
    age_increment: u128,
) -> PotbConfiguration {
    let weights = vec![weight; seeds.len()];
    PotbConfiguration::new(
        rotating_genesis(seeds, &weights, seats),
        PotbPolicy {
            epoch_blocks: 2,
            initial_weight: weight,
            age_increment,
            maximum_weight: if age_increment == 0 {
                weight
            } else {
                weight * 2
            },
        },
    )
    .unwrap()
}

/// Weight two conflicting quorums must share at a given committee total.
/// Equivocating weight strictly below this cannot produce conflicting finality.
///
/// A quorum is strictly more than two thirds of the total, so the complement is
/// strictly smaller and this subtraction cannot wrap. The algebraically equal
/// `2 * quorum_power(total) - total` is deliberately not used: doubling a quorum
/// overflows `u128` at and above `3 * 2^126 - 1`.
#[must_use]
pub fn accountability_threshold(total: u128) -> u128 {
    let quorum = quorum_power(total);
    quorum - (total - quorum)
}

/// Signs a conflicting value in the exact observed slot with the coalition member's own key.
///
/// The result is a genuine equivocation rather than an invalidation: both votes
/// authenticate against the same trusted committee, chain, height, round and phase.
#[must_use]
pub fn equivocating_vote(honest: &Vote, seed: u8, index: usize) -> Vote {
    let mut vote = honest.clone();
    // Repeated-byte digests are distinct per index and are never a real header hash.
    vote.block = Some(Hash256([0xA0 ^ u8::try_from(index).unwrap(); 32]));
    assert_ne!(
        vote.block, honest.block,
        "conflicting value must differ from the honest value"
    );
    vote.signature = ed25519_sign(&[seed; 32], &vote.signing_hash().0);
    vote
}

/// Assembles a canonical proof from two retained conflicting votes.
///
/// Structural decoding is deliberate: comparing offence identities never requires a
/// committee context, and the node under test authenticates its own proofs separately.
#[must_use]
pub fn proof_from_votes(first: &Vote, second: &Vote) -> DoubleVoteEvidence {
    let (first, second) = if first.block < second.block {
        (first, second)
    } else {
        (second, first)
    };
    let mut bytes = b"ALDV\x01\0\0\0".to_vec();
    bytes.extend_from_slice(&first.encode());
    bytes.extend_from_slice(&second.encode());
    DoubleVoteEvidence::decode(&bytes).unwrap()
}

/// Private temporary chain, cache and protected journal layout for one scenario.
pub struct Fixture {
    /// Scenario root under the system temporary directory.
    pub path: PathBuf,
    /// Independently supplied trusted configuration.
    pub network: StaticNetwork,
    /// Node seeds in index order; genesis members first, then standby candidates.
    pub seeds: Vec<u8>,
}

impl Fixture {
    /// Provisions one protected signing journal per node seed.
    pub fn new(network: StaticNetwork, seeds: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-hostile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        for seed in seeds {
            let directory = path.join(seed.to_string());
            std::fs::create_dir(&directory).unwrap();
            drop(
                DurableSigner::create_protected(
                    directory.join("signing.journal"),
                    SigningContext {
                        chain_id: network.chain_id(),
                        genesis: network.genesis_hash(),
                    },
                    [*seed; 32],
                )
                .unwrap(),
            );
        }
        Self {
            path,
            network,
            seeds: seeds.to_vec(),
        }
    }

    /// Opens one participant from its own chain, cache and protected journal.
    pub fn open(&self, index: usize) -> NetworkNode {
        let seed = self.seeds[index];
        let directory = self.path.join(seed.to_string());
        let signer = DurableSigner::open(
            directory.join("signing.journal"),
            SigningContext {
                chain_id: self.network.chain_id(),
                genesis: self.network.genesis_hash(),
            },
            [seed; 32],
        )
        .unwrap();
        NetworkNode::open(
            self.network.clone(),
            &directory,
            signer,
            Duration::from_millis(100),
        )
        .unwrap()
    }

    /// Reopens one participant in place, requiring an unchanged published checkpoint.
    pub fn restart(&self, nodes: &mut Vec<NetworkNode>, index: usize) {
        let before = *nodes[index].storage().checkpoint().unwrap();
        drop(nodes.remove(index));
        nodes.insert(index, self.open(index));
        assert_eq!(nodes[index].storage().checkpoint(), Some(&before));
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self.path.canonicalize().unwrap();
        assert_eq!(
            path.parent(),
            Some(std::env::temp_dir().canonicalize().unwrap().as_path())
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
