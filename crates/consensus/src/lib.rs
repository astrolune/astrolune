// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Proof of Trusted Behavior committee selection and fast `BFT` finality.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

pub mod admission;
pub mod authenticated;
pub mod certificate;
pub mod committee;
pub mod error;
pub mod evidence;
pub mod finality;
pub mod governance;
pub mod history;
pub mod local;
pub mod potb;
pub mod potb_transition;
pub mod prevote;
pub mod proposal;
pub mod rotation;
pub mod sampler;
pub mod vote;
pub mod vrf_selection;
pub mod weight;

pub use authenticated::{AuthenticatedCommittee, MAX_COMMITTEE_MEMBERS};
pub use certificate::{CertificateSignature, FinalityCertificate};
pub use committee::{Candidate, Committee, CommitteeMember, CommitteeSelector};
pub use error::ConsensusError;
pub use evidence::DoubleVoteEvidence;
pub use finality::{BftFinalityEngine, FinalityEngine};
pub use local::{LocalBft, LocalBftError, VotingStep};
pub use prevote::PrevoteCertificate;
pub use proposal::Proposal;
pub use sampler::DemonstrationSampler;
pub use vote::{Vote, VotePhase};
pub use vrf_selection::{VerifiedVrfSampler, VrfValidator};
pub use weight::{PotbWeight, quorum_power};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::{Candidate, Committee, CommitteeMember};
    use crate::weight::PotbWeight;
    use crypto::VrfOutput;
    use std::collections::BTreeSet;
    use types::{Hash256, ValidatorId};

    fn identity(id: u8) -> ValidatorId {
        ValidatorId(crypto::blake2s_hash(&crypto::blake2s::ed25519_public_key(&[id; 32])).0)
    }

    fn make_vrf(byte: u8) -> VrfOutput {
        VrfOutput {
            randomness: Hash256([byte; 32]),
            proof: vec![byte],
        }
    }

    fn make_candidate(id: u8, weight: u128, vrf_byte: u8) -> Candidate {
        Candidate {
            id: identity(id),
            weight: PotbWeight(weight),
            vrf: make_vrf(vrf_byte),
        }
    }

    fn make_member(id: u8, power: u128) -> CommitteeMember {
        CommitteeMember {
            id: identity(id),
            power: PotbWeight(power),
        }
    }

    #[test]
    fn full_lifecycle_committee_rotation_and_finality() {
        let initial_committee = Committee {
            height: 0,
            members: vec![
                make_member(1, 10),
                make_member(2, 20),
                make_member(3, 30),
                make_member(4, 40),
            ],
        };

        let sampler = DemonstrationSampler;

        let candidates = vec![
            make_candidate(5, 50, 0x05),
            make_candidate(6, 60, 0x06),
            make_candidate(7, 70, 0x07),
        ];

        let next_committee = sampler.rotate(&initial_committee, &candidates, 2);
        assert_eq!(next_committee.height, 1);
        assert_eq!(next_committee.members.len(), 4);

        assert_eq!(next_committee.members[0].id, identity(1));
        assert_eq!(next_committee.members[1].id, identity(2));

        let new_ids: BTreeSet<ValidatorId> =
            next_committee.members[2..].iter().map(|m| m.id).collect();
        assert!(new_ids.contains(&identity(7)));
        assert!(new_ids.contains(&identity(6)));

        let seeds = [1u8, 2, 7, 6];
        let keys = seeds.map(|seed| crypto::blake2s::ed25519_public_key(&[seed; 32]));
        let context = AuthenticatedCommittee::new(7, &next_committee, &keys).unwrap();
        let root = context.root();
        let mut engine = BftFinalityEngine::new(context);
        let block = Hash256([0xBB; 32]);
        let total_power: u128 = next_committee.members.iter().map(|m| m.power.0).sum();
        let q = quorum_power(total_power);

        let mut accumulated = 0u128;
        for member in &next_committee.members {
            if accumulated >= q {
                break;
            }
            let seed = seeds
                .iter()
                .find(|seed| identity(**seed) == member.id)
                .unwrap();
            let mut vote = Vote {
                chain_id: 7,
                committee_root: root,
                height: 1,
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(block),
                voter: member.id,
                signature: [0; 64],
            };
            vote.signature = crypto::blake2s::ed25519_sign(&[*seed; 32], &vote.signing_hash().0);
            engine.receive_vote(vote).unwrap();
            accumulated += member.power.0;
        }

        assert_eq!(engine.finalized_block(), Some(block));
    }
}
