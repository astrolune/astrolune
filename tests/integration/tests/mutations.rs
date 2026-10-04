// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Deterministic seeded mutation coverage runnable on the pinned stable toolchain.

#[path = "support/extensions.rs"]
mod extensions;
#[path = "../../../crates/consensus/tests/support/potb.rs"]
mod potb_support;
#[path = "support/governance_compatibility.rs"]
mod governance_support;
use contract_sdk::registry::{MAX_CALL, RegistryAction, RegistryCall, RegistryRecord};
use crypto::{VrfInput, VrfRole};
use state::StateDatabase;
use types::{Hash256, Resources, ValidatorId};

fn seeds() -> Vec<Vec<u8>> {
    let key = crypto::blake2s::ed25519_public_key(&[1; 32]);
    let genesis = genesis::Genesis {
        version: 1,
        chain_id: 7,
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 2,
        capacity: Resources {
            compute: 1000,
            memory: 1000,
            io: 1000,
            bandwidth: 1000,
        },
        validators: vec![genesis::GenesisValidator {
            id: ValidatorId(crypto::blake2s_hash(&key).0),
            weight: 1,
        }],
        allocations: vec![],
    };
    let database = genesis.materialize().unwrap();
    let snapshot = database.snapshot().unwrap();
    let value = state::StateValueProof::create(snapshot.as_ref(), &genesis::genesis_key()).unwrap();
    let proof =
        rpc::CertifiedStateProof::create(snapshot.as_ref(), &genesis::genesis_key(), None).unwrap();
    let effects = storage::BlockEffects {
        committee: None,
        potb: None,
        receipts: vec![],
        genesis: value.clone(),
    };
    let vrf = crypto::prove_vrf(
        &[1; 32],
        VrfInput {
            chain_id: 7,
            genesis: genesis.commitment().unwrap(),
            epoch: 0,
            height: 1,
            parent_randomness: Hash256([1; 32]),
            role: VrfRole::Committee,
            round: 0,
        },
    )
    .unwrap();
    let mut call = [0; MAX_CALL];
    let length = RegistryCall {
        name: b"alice",
        action: RegistryAction::Register(
            100,
            RegistryRecord {
                kind: 1,
                value: b"service",
            },
        ),
    }
    .encode(&mut call)
    .unwrap();
    let receipts = rpc::CertifiedReceiptProof(storage::StoredReceipts {
        header: types::BlockHeader {
            height: 1,
            parent: genesis.commitment().unwrap(),
            state_root: database.root(),
            transactions_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256([2; 32]),
            capacity: genesis.capacity,
        },
        certificate: vec![],
        effects: effects.clone(),
    });
    let mut seeds = vec![
        vrf.encode().unwrap().to_vec(), value.to_bytes().unwrap(), proof.to_bytes().unwrap(), effects.to_bytes().unwrap(),
        receipts.to_bytes().unwrap(), call[..length].to_vec(),
        p2p::discovery::encode(Hash256([1; 32]), &["127.0.0.1:1234".parse().unwrap()], b"fixture", 4096).unwrap(),
        wat::parse_str("(module (memory (export \"memory\") 1 1) (func (export \"call\") (result i32) i32.const 0))").unwrap(),
        wat::parse_str("(module (memory (export \"memory\") 1 1) (func (export \"call\") (result i32) (loop br 0) i32.const 0))").unwrap(),
    ];
    seeds.extend(rotation_seeds(&genesis, key));
    seeds.extend(admission_seeds(&genesis, key));
    seeds.extend(potb_seeds());
    seeds.extend(governance_support::build().into_values());
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/protocol-v1");
    for line in include_str!("../fixtures/protocol-v1/MANIFEST.blake2s").lines() {
        let name = line.split_whitespace().nth(2).unwrap();
        if !name.ends_with("public-keys.bin") {
            seeds.push(std::fs::read(directory.join(name)).unwrap());
        }
    }
    seeds
}

fn rotation_seeds(genesis: &genesis::Genesis, key: [u8; 32]) -> Vec<Vec<u8>> {
    use consensus::rotation::{
        CommitteeHandoff, HandoffVerifier, VrfBatch, VrfContribution, committee_state_key,
    };
    use consensus::{CertificateSignature, FinalityCertificate, Vote, VotePhase};
    let mut verifier = HandoffVerifier::new(genesis, &[key]).unwrap();
    let current = verifier.current();
    let contribution = VrfContribution {
        validator: genesis.validators[0].id,
        committee: crypto::prove_vrf(&[1; 32], current.input(VrfRole::Committee).unwrap()).unwrap(),
        producer: crypto::prove_vrf(&[1; 32], current.input(VrfRole::Producer).unwrap()).unwrap(),
    };
    let batch = VrfBatch::new(vec![contribution.clone()]).unwrap();
    let next = current.transition(&batch).unwrap();
    let mut database = genesis.materialize().unwrap();
    let mut diff = state::StateDiff::new();
    diff.put(committee_state_key(), next.to_bytes().unwrap());
    database.commit(database.root(), &[diff]).unwrap();
    let header = types::BlockHeader {
        height: 1,
        parent: verifier.parent(),
        state_root: database.root(),
        transactions_root: Hash256::ZERO,
        receipts_root: Hash256::ZERO,
        committee_root: current.context().unwrap().root(),
        capacity: genesis.capacity,
    };
    let vote = Vote {
        chain_id: genesis.chain_id,
        height: 1,
        round: 0,
        committee_root: header.committee_root,
        phase: VotePhase::Precommit,
        block: Some(header.compute_hash()),
        voter: contribution.validator,
        signature: [0; 64],
    };
    let certificate = FinalityCertificate {
        chain_id: vote.chain_id,
        height: vote.height,
        round: vote.round,
        committee_root: vote.committee_root,
        block: header.compute_hash(),
        signatures: vec![CertificateSignature {
            voter: vote.voter,
            signature: crypto::blake2s::ed25519_sign(&[1; 32], &vote.signing_hash().0),
        }],
    };
    let handoff = CommitteeHandoff {
        header,
        certificate,
        contributions: batch.clone(),
        next_state: state::StateValueProof::create(
            database.snapshot().unwrap().as_ref(),
            &committee_state_key(),
        )
        .unwrap(),
    };
    let mut result = vec![
        current.to_bytes().unwrap(),
        contribution.to_bytes().unwrap(),
        batch.to_bytes().unwrap(),
        handoff.to_bytes().unwrap(),
    ];
    result.push(
        node::network_wire::encode_exchange(
            Hash256([1; 32]),
            &[node::network_wire::NetworkMessage::VrfContribution {
                height: 1,
                contribution,
            }],
        )
        .unwrap(),
    );
    let mut rotating = genesis.clone();
    rotating.version = genesis::ROTATING_GENESIS_VERSION;
    result.push(codec::CanonicalEncode::to_bytes(&rotating));
    result.push(
        storage::BlockEffects {
            receipts: vec![],
            genesis: state::StateValueProof::create(
                database.snapshot().unwrap().as_ref(),
                &genesis::genesis_key(),
            )
            .unwrap(),
            committee: Some(handoff.next_state.clone()),
            potb: None,
        }
        .to_bytes()
        .unwrap(),
    );
    let context = verifier.current().context().unwrap();
    verifier.apply(&handoff).unwrap();
    result.extend(history_seeds(&verifier, &context, &vote, key));
    result
}
fn history_seeds(
    trusted: &consensus::rotation::HandoffVerifier,
    context: &consensus::AuthenticatedCommittee,
    vote: &consensus::Vote,
    key: [u8; 32],
) -> Vec<Vec<u8>> {
    let history = trusted.history();
    let proof = history.prove(1, 1, |_| Ok(context.root())).unwrap();
    let mut first = vote.clone();
    first.signature = crypto::blake2s::ed25519_sign(&[1; 32], &first.signing_hash().0);
    let mut second = first.clone();
    second.block = None;
    second.signature = crypto::blake2s::ed25519_sign(&[1; 32], &second.signing_hash().0);
    let evidence = consensus::DoubleVoteEvidence::from_votes(context, first, second).unwrap();
    let committee = consensus::Committee {
        height: 1,
        members: vec![consensus::CommitteeMember {
            id: evidence.voter(),
            power: consensus::PotbWeight(1),
        }],
    };
    let bundle = consensus::history::HistoricalEvidence::new(
        history,
        &committee,
        &[key],
        proof.clone(),
        evidence,
    )
    .unwrap();
    vec![
        history.to_bytes(),
        proof.to_bytes().unwrap(),
        bundle.to_bytes().unwrap(),
    ]
}

fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn potb_seeds() -> Vec<Vec<u8>> {
    use consensus::potb_transition::{PotbBatch, PotbVerifier};
    let (config, keys) = potb_support::fixture();
    let mut trusted = PotbVerifier::new(&config, &keys).unwrap();
    let first = trusted.current().committee().clone();
    let roots = vec![first.context().unwrap().root()];
    let handoff = potb_support::handoff(&trusted, potb_support::batch(trusted.current()));
    let mut seeds = vec![
        config.to_bytes(),
        trusted.current().to_bytes().unwrap(),
        handoff.batch.to_bytes().unwrap(),
        handoff.to_bytes().unwrap(),
    ];
    trusted.apply(&handoff).unwrap();
    let evidence = potb_support::evidence(trusted.current(), &first, &roots, 1);
    let admission = potb_support::admission(trusted.current(), trusted.parent(), 99);
    for message in [
        node::network_wire::NetworkMessage::PotbEvidence(evidence.clone()),
        node::network_wire::NetworkMessage::PotbAdmission(admission.clone()),
    ] {
        seeds.push(node::network_wire::encode_exchange(Hash256([1; 32]), &[message]).unwrap());
    }
    let batch = PotbBatch::new(
        potb_support::contributions(trusted.current()),
        vec![evidence],
        vec![admission],
    )
    .unwrap();
    let handoff = potb_support::handoff(&trusted, batch);
    trusted.apply(&handoff).unwrap();
    seeds.push(
        storage::BlockEffects {
            receipts: vec![],
            genesis: state::StateValueProof::create(
                config
                    .materialize(&keys)
                    .unwrap()
                    .snapshot()
                    .unwrap()
                    .as_ref(),
                &genesis::genesis_key(),
            )
            .unwrap(),
            committee: None,
            potb: Some(handoff.next_state.clone()),
        }
        .to_bytes()
        .unwrap(),
    );
    seeds.extend([
        trusted.current().to_bytes().unwrap(),
        handoff.batch.to_bytes().unwrap(),
        handoff.to_bytes().unwrap(),
    ]);
    seeds
}
fn campaign(rounds: usize) {
    let seeds = seeds();
    for bytes in &seeds {
        assert!(extensions::check(bytes) > 0);
    }
    let mut random_state = 0x6173_7472_6f6c_756e;
    let mut accepted = 0;
    for index in 0..rounds {
        let mut bytes = seeds[index % seeds.len()].clone();
        let at = usize::try_from(random(&mut random_state) % bytes.len() as u64).unwrap();
        match index % 5 {
            0 => bytes[at] ^= u8::try_from(random(&mut random_state) & 255).unwrap(),
            1 => bytes.truncate(at),
            2 => bytes.insert(at, u8::try_from(random(&mut random_state) & 255).unwrap()),
            3 => {
                bytes.remove(at);
            }
            _ => {
                let end = (at + 8).min(bytes.len());
                bytes[at..end].fill(255);
            }
        }
        accepted += extensions::check(&bytes);
    }
    println!(
        "{rounds} mutations; {} structured seeds; {accepted} accepted decoder paths",
        seeds.len()
    );
    assert!(
        accepted > 0,
        "mutations must also reach accepted-input roundtrip paths"
    );
}
#[test]
fn extension_mutation_smoke() {
    campaign(3000);
}
#[test]
#[ignore = "extended deterministic mutation campaign; no coverage-guided fuzzing claim"]
fn extended_extension_mutations() {
    campaign(100_000);
}

#[test]
#[ignore = "million-input deterministic campaign; no coverage-guided fuzzing claim"]
fn million_extension_mutations() {
    campaign(1_000_000);
}

fn admission_seeds(genesis: &genesis::Genesis, key: [u8; 32]) -> Vec<Vec<u8>> {
    use consensus::admission::{AdmissionApproval, AdmissionCertificate, AdmissionRequest};
    let current = consensus::rotation::CommitteeState::from_genesis(genesis, &[key]).unwrap();
    let request = AdmissionRequest::sign(&current, current.genesis(), &[99; 32]).unwrap();
    let voter = genesis.validators[0].id;
    let signature = crypto::blake2s::ed25519_sign(
        &[1; 32],
        &request.intent().approval_hash(request.consent(), voter).0,
    );
    let mut bytes = b"ALADAP01".to_vec();
    bytes.extend_from_slice(&request.id().0);
    bytes.extend_from_slice(&voter.0);
    bytes.extend_from_slice(&signature);
    let approval = AdmissionApproval::from_bytes(&bytes).unwrap();
    approval
        .verify(&request, &current, current.genesis())
        .unwrap();
    let certificate = AdmissionCertificate::assemble(
        request.clone(),
        vec![approval.clone()],
        &current,
        current.genesis(),
    )
    .unwrap();
    vec![
        request.intent().to_bytes().to_vec(),
        request.to_bytes().unwrap(),
        approval.to_bytes(),
        certificate.to_bytes().unwrap(),
    ]
}
