// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Public deterministic fixtures. Never use these seeds for operator custody.

use codec::CanonicalEncode;
use consensus::rotation::{HandoffVerifier, VrfBatch, VrfContribution};
use consensus::{
    AuthenticatedCommittee, CertificateSignature, DoubleVoteEvidence, FinalityCertificate, Vote,
    VotePhase,
};
use crypto::{
    VrfRole,
    blake2s::{ed25519_public_key, ed25519_sign},
};
use genesis::{Genesis, GenesisValidator};
use node::{
    BlockProducer, ProducerConfig,
    network::StaticNetwork,
    network_wire::{NetworkMessage, encode_exchange},
};
use state::StateDatabase;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use storage::ChainStorage;
use types::{Address, BlockHeader, Hash256, Resources, Transaction, TransactionLane, ValidatorId};

pub type Corpus = BTreeMap<String, Vec<u8>>;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let root = std::env::temp_dir().canonicalize().unwrap();
        if self
            .0
            .canonicalize()
            .is_ok_and(|p| p.parent() == Some(root.as_path()))
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

pub fn keys() -> Vec<[u8; 32]> {
    (1..=4)
        .map(|seed| ed25519_public_key(&[seed; 32]))
        .collect()
}

pub fn genesis(version: u16) -> Genesis {
    let mut validators: Vec<_> = keys()
        .into_iter()
        .map(|key| GenesisValidator {
            id: ValidatorId(crypto::blake2s_hash(&key).0),
            weight: 10,
        })
        .collect();
    validators.sort_by_key(|v| v.id);

    Genesis {
        version,
        chain_id: 7,
        committee_size: if version == 1 { 4 } else { 3 },
        rotation_count: 1,
        runtime_version: 2,
        capacity: Resources {
            compute: 100_000,
            memory: 100_000,
            io: 100_000,
            bandwidth: 100_000,
        },
        validators,
        allocations: vec![genesis::Allocation {
            address: transaction::address_from_public_key(&ed25519_public_key(&[99; 32])),
            amount: 1_000_000,
        }],
    }
}

pub fn payment(nonce: u64) -> Transaction {
    let public_key = ed25519_public_key(&[99; 32]);
    let sender = transaction::address_from_public_key(&public_key);
    let recipient = Address([77; 32]);
    let mut access_list = vec![state::account_key(sender), state::account_key(recipient)];
    access_list.sort();

    let mut tx = Transaction {
        version: 1,
        chain_id: 7,
        sender,
        nonce,
        expires_at: 100,
        lane: TransactionLane::Payments,
        resource_prices: execution::PAYMENT_PRICES,
        access_list,
        resource_limit: Resources::ZERO,
        payload: transaction::Payment {
            public_key,
            recipient,
            amount: 123,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).unwrap();
    tx.signature = ed25519_sign(&[99; 32], &transaction::signing_hash(&tx).0);

    tx
}

fn vote(
    context: &AuthenticatedCommittee,
    header: &BlockHeader,
    seed: u8,
    block: Option<Hash256>,
) -> Vote {
    let mut vote = Vote {
        chain_id: context.chain_id(),
        height: header.height,
        round: 0,
        committee_root: context.root(),
        phase: VotePhase::Precommit,
        block,
        voter: ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[seed; 32])).0),
        signature: [0; 64],
    };
    vote.signature = ed25519_sign(&[seed; 32], &vote.signing_hash().0);

    vote
}

fn certificate(context: &AuthenticatedCommittee, header: &BlockHeader) -> FinalityCertificate {
    let mut signatures: Vec<_> = (1..=4)
        .filter_map(|seed| {
            let vote = vote(context, header, seed, Some(header.compute_hash()));
            context.voting_power(vote.voter)?;

            Some(CertificateSignature {
                voter: vote.voter,
                signature: vote.signature,
            })
        })
        .collect();
    signatures.sort_by_key(|s| s.voter);

    FinalityCertificate {
        chain_id: 7,
        height: header.height,
        round: 0,
        committee_root: context.root(),
        block: header.compute_hash(),
        signatures,
    }
}

fn contributions(trusted: &HandoffVerifier) -> VrfBatch {
    VrfBatch::new(
        (1..=4)
            .map(|seed| VrfContribution {
                validator: ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[seed; 32])).0),
                committee: crypto::prove_vrf(
                    &[seed; 32],
                    trusted.current().input(VrfRole::Committee).unwrap(),
                )
                .unwrap(),
                producer: crypto::prove_vrf(
                    &[seed; 32],
                    trusted.current().input(VrfRole::Producer).unwrap(),
                )
                .unwrap(),
            })
            .collect(),
    )
    .unwrap()
}

fn insert(corpus: &mut Corpus, prefix: &str, name: &str, bytes: Vec<u8>) {
    assert!(
        corpus
            .insert(format!("{prefix}/{name}.bin"), bytes)
            .is_none()
    );
}

pub fn build() -> Corpus {
    let mut corpus = Corpus::new();

    for version in [1, 2] {
        profile(&mut corpus, version);
    }

    corpus
}

fn profile(corpus: &mut Corpus, version: u16) {
    let prefix = format!("genesis-v{version}");
    let genesis = genesis(version);
    let hash = genesis.commitment().unwrap();
    let network = StaticNetwork::new(genesis.clone(), keys()).unwrap();

    let dir = Directory(std::env::temp_dir().join(format!(
        "astrolune-compatibility-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir(&dir.0).unwrap();

    let mut storage = ChainStorage::open(dir.0.join("chain.bin")).unwrap();
    storage
        .initialize_genesis(hash, genesis.materialize().unwrap())
        .unwrap();

    let mut producer = BlockProducer::from_checkpoint(
        ProducerConfig {
            chain_id: 7,
            block_capacity: genesis.capacity,
            ..ProducerConfig::default()
        },
        storage.checkpoint().copied(),
        storage.state().clone(),
    )
    .unwrap();

    let mut trusted = HandoffVerifier::new(&genesis, &keys()).unwrap();
    if version == 2 {
        producer = producer.with_rotation(&trusted).unwrap();
    }

    insert(corpus, &prefix, "genesis", genesis.to_bytes());
    insert(corpus, &prefix, "public-keys", keys().concat());

    for height in 1..=2 {
        let tag = format!("height-{height}");

        if version == 2 {
            producer.set_vrf_batch(contributions(&trusted)).unwrap();
        }

        let tx = payment(height - 1);
        insert(
            corpus,
            &prefix,
            &format!("{tag}-transaction"),
            tx.to_bytes(),
        );
        producer.submit_transaction(tx).unwrap();

        let context = if version == 2 {
            trusted.current().context().unwrap()
        } else {
            network.committee(height).unwrap()
        };

        let proposal = producer.produce_block_for_committee(&context).unwrap();
        let cert = certificate(&context, &proposal.block.header);

        capture_block(corpus, &prefix, &tag, hash, &proposal, &context, &cert);

        if version == 2 {
            let handoff = producer.rotation_handoff(&proposal, &cert).unwrap();

            insert(
                corpus,
                &prefix,
                &format!("{tag}-handoff"),
                handoff.to_bytes().unwrap(),
            );
            insert(
                corpus,
                &prefix,
                &format!("{tag}-committee"),
                trusted.current().to_bytes().unwrap(),
            );
            insert(
                corpus,
                &prefix,
                &format!("{tag}-contributions"),
                handoff.contributions.to_bytes().unwrap(),
            );

            trusted.apply(&handoff).unwrap();
        }

        producer
            .commit_certified_block(&proposal, &cert, &context, &mut storage)
            .unwrap();

        capture_state(
            corpus,
            &prefix,
            &tag,
            &storage,
            &proposal.block.header,
            &cert,
        );
    }
}

fn capture_block(
    corpus: &mut Corpus,
    prefix: &str,
    tag: &str,
    hash: Hash256,
    proposal: &node::BlockProposal,
    context: &AuthenticatedCommittee,
    cert: &FinalityCertificate,
) {
    let active_seed = (1..=4)
        .find(|seed| {
            context
                .voting_power(vote(context, &proposal.block.header, *seed, None).voter)
                .is_some()
        })
        .unwrap();

    let first = vote(context, &proposal.block.header, active_seed, None);
    let second = vote(
        context,
        &proposal.block.header,
        active_seed,
        Some(cert.block),
    );
    let evidence = DoubleVoteEvidence::from_votes(context, first.clone(), second).unwrap();

    insert(
        corpus,
        prefix,
        &format!("{tag}-vote"),
        first.encode().to_vec(),
    );
    insert(
        corpus,
        prefix,
        &format!("{tag}-evidence"),
        evidence.encode().to_vec(),
    );
    insert(
        corpus,
        prefix,
        &format!("{tag}-certificate"),
        cert.encode().unwrap(),
    );
    insert(
        corpus,
        prefix,
        &format!("{tag}-header"),
        proposal.block.header.to_bytes(),
    );
    insert(
        corpus,
        prefix,
        &format!("{tag}-network"),
        encode_exchange(
            hash,
            &[NetworkMessage::Finalized {
                block: proposal.block.clone(),
                certificate: cert.clone(),
            }],
        )
        .unwrap(),
    );
}

fn capture_state(
    corpus: &mut Corpus,
    prefix: &str,
    tag: &str,
    storage: &ChainStorage,
    header: &BlockHeader,
    cert: &FinalityCertificate,
) {
    let receipts = storage.read_receipts(header.height).unwrap().unwrap();

    insert(
        corpus,
        prefix,
        &format!("{tag}-effects"),
        receipts.effects.to_bytes().unwrap(),
    );
    insert(
        corpus,
        prefix,
        &format!("{tag}-receipts"),
        rpc::CertifiedReceiptProof(receipts).to_bytes().unwrap(),
    );

    let snapshot = storage.state().snapshot().unwrap();

    for (kind, key) in [
        ("present", state::account_key(Address([77; 32]))),
        ("absent", state::account_key(Address([78; 32]))),
    ] {
        let proof = rpc::CertifiedStateProof::create(
            snapshot.as_ref(),
            &key,
            Some((*header, cert.encode().unwrap())),
        )
        .unwrap();

        insert(
            corpus,
            prefix,
            &format!("{tag}-state-{kind}"),
            proof.to_bytes().unwrap(),
        );
    }
}
