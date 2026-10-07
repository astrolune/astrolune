// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Unauthenticated demonstration committee sorting, for legacy fixtures only.

use std::collections::BTreeSet;

use crate::committee::{Candidate, Committee, CommitteeMember, CommitteeSelector};
use types::ValidatorId;

/// Demonstration sorter without proof verification or proportional weighting.
/// Use [`crate::VerifiedVrfSampler`] for authenticated weighted selection.
///
/// Determinism is guaranteed by sorting candidates first by descending `VRF`
/// randomness (big-endian `Hash256` comparison), then by descending effective
/// weight, and finally by ascending validator identity for tie-breaking.
pub struct DemonstrationSampler;

impl CommitteeSelector for DemonstrationSampler {
    fn rotate(
        &self,
        current: &Committee,
        candidates: &[Candidate],
        replacement_count: usize,
    ) -> Committee {
        let next_height = current.height.saturating_add(1);
        let committee_size = current.members.len();

        if committee_size == 0 || replacement_count == 0 {
            return Committee {
                height: next_height,
                members: current.members.clone(),
            };
        }

        let retained_count = committee_size.saturating_sub(replacement_count);

        let mut retained: Vec<CommitteeMember> = current.members[..retained_count].to_vec();

        let retained_ids: BTreeSet<ValidatorId> = retained.iter().map(|m| m.id).collect();

        let mut new_slots = committee_size.saturating_sub(retained_count);

        if new_slots == 0 {
            return Committee {
                height: next_height,
                members: retained,
            };
        }

        let mut eligible: Vec<&Candidate> = candidates
            .iter()
            .filter(|c| !retained_ids.contains(&c.id))
            .collect();

        eligible.sort_by(|a, b| {
            b.vrf
                .randomness
                .cmp(&a.vrf.randomness)
                .then_with(|| b.weight.cmp(&a.weight))
                .then_with(|| a.id.cmp(&b.id))
        });

        let mut selected_ids: BTreeSet<ValidatorId> = retained_ids;

        for candidate in eligible {
            if new_slots == 0 {
                break;
            }
            if selected_ids.insert(candidate.id) {
                retained.push(CommitteeMember {
                    id: candidate.id,
                    power: candidate.weight,
                });
                new_slots -= 1;
            }
        }

        Committee {
            height: next_height,
            members: retained,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::{Candidate, Committee, CommitteeMember};
    use crate::weight::PotbWeight;
    use crypto::VrfOutput;
    use types::{Hash256, ValidatorId};

    fn make_vrf(byte: u8) -> VrfOutput {
        VrfOutput {
            randomness: Hash256([byte; 32]),
            proof: vec![byte],
        }
    }

    fn make_candidate(id: u8, weight: u128, vrf_byte: u8) -> Candidate {
        Candidate {
            id: ValidatorId::from_bytes([id; 32]),
            weight: PotbWeight(weight),
            vrf: make_vrf(vrf_byte),
        }
    }

    fn make_member(id: u8, power: u128) -> CommitteeMember {
        CommitteeMember {
            id: ValidatorId::from_bytes([id; 32]),
            power: PotbWeight(power),
        }
    }

    #[test]
    fn retains_committee_size_minus_replacement_count_members() {
        let current = Committee {
            height: 0,
            members: vec![
                make_member(1, 10),
                make_member(2, 20),
                make_member(3, 30),
                make_member(4, 40),
            ],
        };

        let candidates = vec![make_candidate(5, 50, 0xFF), make_candidate(6, 60, 0xFE)];

        let sampler = DemonstrationSampler;
        let next = sampler.rotate(&current, &candidates, 2);

        assert_eq!(next.height, 1);
        assert_eq!(next.members.len(), 4);
        assert_eq!(next.members[0].id, ValidatorId::from_bytes([1; 32]));
        assert_eq!(next.members[1].id, ValidatorId::from_bytes([2; 32]));
        assert_eq!(next.members[2].id, ValidatorId::from_bytes([5; 32]));
        assert_eq!(next.members[3].id, ValidatorId::from_bytes([6; 32]));
    }

    #[test]
    fn sorts_new_members_by_vrf_then_weight_then_id() {
        let current = Committee {
            height: 0,
            members: vec![make_member(1, 10)],
        };

        let candidates = vec![
            make_candidate(2, 100, 0x01),
            make_candidate(3, 200, 0x02),
            make_candidate(4, 150, 0x03),
        ];

        let sampler = DemonstrationSampler;
        let next = sampler.rotate(&current, &candidates, 1);

        assert_eq!(next.members.len(), 1);
        assert_eq!(next.members[0].id, ValidatorId::from_bytes([4; 32]));
    }

    #[test]
    fn no_duplicates_in_committee() {
        let current = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 20), make_member(3, 30)],
        };

        let candidates = vec![make_candidate(1, 100, 0xFF), make_candidate(4, 40, 0xFE)];

        let sampler = DemonstrationSampler;
        let next = sampler.rotate(&current, &candidates, 1);

        let ids: Vec<ValidatorId> = next.members.iter().map(|m| m.id).collect();
        let unique: BTreeSet<ValidatorId> = ids.iter().copied().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn empty_committee_unchanged() {
        let current = Committee {
            height: 5,
            members: vec![],
        };
        let candidates = vec![make_candidate(1, 10, 0x01)];

        let sampler = DemonstrationSampler;
        let next = sampler.rotate(&current, &candidates, 1);

        assert_eq!(next.height, 6);
        assert_eq!(next.members.len(), 0);
    }

    #[test]
    fn zero_replacement_count_unchanged() {
        let current = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 20)],
        };
        let candidates = vec![make_candidate(3, 30, 0x01)];

        let sampler = DemonstrationSampler;
        let next = sampler.rotate(&current, &candidates, 0);

        assert_eq!(next.members.len(), 2);
        assert_eq!(next.members[0].id, ValidatorId::from_bytes([1; 32]));
        assert_eq!(next.members[1].id, ValidatorId::from_bytes([2; 32]));
    }

    #[test]
    fn total_power_is_sum_of_member_powers() {
        let current = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 20)],
        };
        let candidates = vec![make_candidate(3, 30, 0x01)];

        let sampler = DemonstrationSampler;
        let next = sampler.rotate(&current, &candidates, 1);

        let total: u128 = next.members.iter().map(|m| m.power.0).sum();
        let expected: u128 = next.members.iter().map(|m| m.power.0).sum::<u128>();
        assert_eq!(total, expected);
    }

    #[test]
    fn replacement_count_exceeds_committee_replaces_available_seats() {
        let current = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 20)],
        };
        let candidates = vec![make_candidate(3, 30, 0x01)];

        let sampler = DemonstrationSampler;
        let next = sampler.rotate(&current, &candidates, 100);

        assert_eq!(next.members.len(), 1);
        assert_eq!(next.members[0].id, ValidatorId::from_bytes([3; 32]));
    }
}
