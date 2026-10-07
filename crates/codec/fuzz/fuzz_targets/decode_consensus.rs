// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

#![no_main]

use consensus::{
    AuthenticatedCommittee, Committee, CommitteeMember, FinalityCertificate, PotbWeight,
    PrevoteCertificate, Proposal, Vote,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use types::ValidatorId;

fn context() -> &'static AuthenticatedCommittee {
    static CONTEXT: OnceLock<AuthenticatedCommittee> = OnceLock::new();
    CONTEXT.get_or_init(|| {
        // RFC 8032 test key and its independently computed BLAKE2s identity.
        let key = [
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];
        let id = ValidatorId([
            8, 254, 74, 105, 171, 124, 14, 144, 44, 144, 102, 250, 96, 163, 79, 106, 120, 100, 119,
            154, 58, 204, 145, 152, 189, 223, 34, 104, 138, 133, 220, 0,
        ]);
        AuthenticatedCommittee::new(
            7,
            &Committee {
                height: 42,
                members: vec![CommitteeMember {
                    id,
                    power: PotbWeight(1),
                }],
            },
            &[key],
        )
        .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(proposal) = Proposal::decode(data) {
        assert_eq!(proposal.encode().as_slice(), data);
    }
    if let Ok(vote) = Vote::decode(data) {
        assert_eq!(vote.encode().as_slice(), data);
    }
    if let Ok(certificate) = FinalityCertificate::decode(data) {
        assert_eq!(certificate.encode().unwrap(), data);
    }
    if let Ok(proof) = PrevoteCertificate::decode(context(), data) {
        assert_eq!(proof.encode(), data);
    }
});
