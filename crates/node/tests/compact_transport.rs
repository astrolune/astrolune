// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Compact transport preserves the reference codec and its expanded size limits.

use codec::{CanonicalEncode, DecodeError};
use consensus::{CertificateSignature, FinalityCertificate, Proposal, Vote, VotePhase};
use node::{
    compact_wire::{
        CompactRequest, MAX_COMPACT_REQUEST_BYTES, MAX_DICTIONARY_BYTES, MAX_KNOWN_TRANSACTIONS,
        TransactionDictionary, decode_response, encode_response,
    },
    network_wire::{
        MAX_BLOCK_BYTES, MAX_EXCHANGE_BYTES, MAX_TRANSACTION_BYTES, NetworkMessage, SyncRequest,
        encode_block, encode_exchange,
    },
};
use types::{
    Address, Block, BlockHeader, Hash256, Resources, Transaction, TransactionLane, ValidatorId,
};

const GENESIS: Hash256 = Hash256([7; 32]);

fn transaction(nonce: u64, payload_bytes: usize) -> Transaction {
    Transaction {
        version: 1,
        expires_at: 100,
        lane: TransactionLane::Contracts,
        resource_prices: Resources::ZERO,
        chain_id: 42,
        sender: Address([3; 32]),
        nonce,
        access_list: Vec::new(),
        resource_limit: Resources::ZERO,
        payload: vec![19; payload_bytes],
        signature: [0; 64],
    }
}

fn block(transactions: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            height: 1,
            parent: GENESIS,
            transactions_root: Hash256([1; 32]),
            state_root: Hash256([2; 32]),
            receipts_root: Hash256([3; 32]),
            committee_root: Hash256([4; 32]),
            capacity: Resources::ZERO,
        },
        transactions,
    }
}

fn request(dictionary: &TransactionDictionary) -> CompactRequest {
    CompactRequest::new(
        SyncRequest {
            genesis: GENESIS,
            height: 1,
        },
        dictionary,
    )
}

fn messages(transactions: &[Transaction]) -> Vec<NetworkMessage> {
    let block = block(transactions.to_vec());
    let hash = block.header.compute_hash();
    vec![
        NetworkMessage::Proposal {
            envelope: Proposal {
                chain_id: 42,
                genesis: GENESIS,
                height: 1,
                round: 0,
                committee_root: block.header.committee_root,
                block: hash,
                proposer: ValidatorId([1; 32]),
                valid_round: None,
                signature: [0; 64],
            },
            block: block.clone(),
            proof: Vec::new(),
        },
        NetworkMessage::Vote(Vote {
            chain_id: 42,
            committee_root: block.header.committee_root,
            height: 1,
            round: 0,
            phase: VotePhase::Prevote,
            block: Some(hash),
            voter: ValidatorId([1; 32]),
            signature: [0; 64],
        }),
        NetworkMessage::Finalized {
            block: block.clone(),
            certificate: FinalityCertificate {
                chain_id: 42,
                height: 1,
                round: 0,
                committee_root: block.header.committee_root,
                block: hash,
                signatures: vec![CertificateSignature {
                    voter: ValidatorId([1; 32]),
                    signature: [0; 64],
                }],
            },
        },
        NetworkMessage::Transaction(transactions[0].clone()),
        NetworkMessage::ValidValue {
            block,
            proof: vec![11, 12, 13],
        },
    ]
}

#[test]
fn complete_partial_and_empty_dictionaries_preserve_every_message_and_legacy_byte() {
    let transactions = vec![
        transaction(1, 512),
        transaction(2, 1024),
        transaction(3, 256),
    ];
    let messages = messages(&transactions);
    let legacy = encode_exchange(GENESIS, &messages).unwrap();
    for known in [transactions.clone(), transactions[..1].to_vec(), Vec::new()] {
        let dictionary = TransactionDictionary::new(known);
        let request = request(&dictionary);
        let response = encode_response(GENESIS, &messages, request.known()).unwrap();
        let restored = decode_response(GENESIS, &response, &dictionary).unwrap();
        assert_eq!(restored, messages);
        assert_eq!(encode_exchange(GENESIS, &restored).unwrap(), legacy);
        if request.known().is_empty() {
            assert_eq!(response, legacy);
        } else {
            assert!(response.starts_with(b"ALCX"));
            assert!(response.len() < legacy.len());
        }
    }
}

#[test]
fn no_hits_and_nonblock_messages_use_exact_legacy_fallback() {
    let dictionary = TransactionDictionary::new([transaction(99, 512)]);
    let request = request(&dictionary);
    for messages in [
        messages(&[transaction(1, 512)]),
        vec![NetworkMessage::Transaction(transaction(2, 512))],
        Vec::new(),
    ] {
        let legacy = encode_exchange(GENESIS, &messages).unwrap();
        let response = encode_response(GENESIS, &messages, request.known()).unwrap();
        assert_eq!(response, legacy);
        assert_eq!(
            decode_response(GENESIS, &response, &dictionary).unwrap(),
            messages
        );
    }
}

#[test]
fn request_dictionary_owns_transactions_until_response_reconstruction() {
    let (dictionary, response, expected) = {
        let transactions = vec![transaction(1, 1024), transaction(2, 2048)];
        let messages = messages(&transactions);
        let dictionary = TransactionDictionary::new(transactions);
        let response = encode_response(GENESIS, &messages, request(&dictionary).known()).unwrap();
        (
            dictionary,
            response,
            encode_exchange(GENESIS, &messages).unwrap(),
        )
    };
    let restored = decode_response(GENESIS, &response, &dictionary).unwrap();
    assert_eq!(encode_exchange(GENESIS, &restored).unwrap(), expected);
    assert_eq!(
        decode_response(GENESIS, &response, &TransactionDictionary::default()),
        Err(DecodeError::Unsupported)
    );
}

#[test]
fn request_ids_are_sorted_unique_bounded_and_roundtrip() {
    let candidates = (0..300).rev().map(|nonce| transaction(nonce, 8));
    let dictionary = TransactionDictionary::new(candidates);
    let request = request(&dictionary);
    assert_eq!(request.known().len(), MAX_KNOWN_TRANSACTIONS);
    assert!(request.known().windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(request.encode().len(), MAX_COMPACT_REQUEST_BYTES);
    assert_eq!(CompactRequest::decode(&request.encode()).unwrap(), request);
    let duplicate = TransactionDictionary::new(vec![transaction(1, 8); 10]);
    assert_eq!(
        CompactRequest::new(request.sync(), &duplicate)
            .known()
            .len(),
        1
    );
    let mut unsorted = request.encode();
    let first = unsorted[50..82].to_vec();
    unsorted.copy_within(82..114, 50);
    unsorted[82..114].copy_from_slice(&first);
    assert_eq!(
        CompactRequest::decode(&unsorted),
        Err(DecodeError::NonCanonical)
    );
    let mut too_many = request.encode();
    too_many[48..50].copy_from_slice(&257u16.to_le_bytes());
    assert_eq!(
        CompactRequest::decode(&too_many),
        Err(DecodeError::LimitExceeded)
    );
}

#[test]
fn dictionary_respects_canonical_transaction_and_total_byte_bounds() {
    let oversized = transaction(0, MAX_TRANSACTION_BYTES);
    let mut unsupported = transaction(1, 8);
    unsupported.version = 2;
    let valid = transaction(2, 60_000);
    let encoded_len = valid.to_bytes().len();
    let candidates = [oversized, unsupported]
        .into_iter()
        .chain((2..100).map(|nonce| transaction(nonce, 60_000)));
    let dictionary = TransactionDictionary::new(candidates);
    let request = request(&dictionary);
    assert_eq!(request.known().len(), MAX_DICTIONARY_BYTES / encoded_len);
    assert!(request.known().contains(&node::hash_transaction(&valid)));
}

// Build compact fixtures independently of encode_response so expanded limits can
// be exercised even when the legacy encoder would refuse the original response.
fn reference_response(block_count: usize, transaction_count: u16, id: Hash256) -> Vec<u8> {
    let skeleton = vec![
        NetworkMessage::ValidValue {
            block: block(Vec::new()),
            proof: Vec::new()
        };
        block_count
    ];
    let skeleton = encode_exchange(GENESIS, &skeleton).unwrap();
    let mut response = b"ALCX\x01\0\0\0".to_vec();
    response.extend_from_slice(&u32::try_from(skeleton.len()).unwrap().to_le_bytes());
    response.extend_from_slice(&skeleton);
    for _ in 0..block_count {
        response.extend_from_slice(&transaction_count.to_le_bytes());
        for _ in 0..transaction_count {
            response.push(0);
            response.extend_from_slice(id.as_bytes());
        }
    }
    response
}

#[test]
fn compact_references_obey_expanded_block_and_exchange_limits() {
    let transaction = transaction(1, 60_000);
    let id = node::hash_transaction(&transaction);
    let dictionary = TransactionDictionary::new([transaction.clone()]);
    let block_bytes = encode_block(&block(vec![transaction; 16])).unwrap().len();
    assert!(block_bytes < MAX_BLOCK_BYTES);
    assert!(9 * block_bytes > MAX_EXCHANGE_BYTES);
    let within_limits = reference_response(8, 16, id);
    assert_eq!(
        decode_response(GENESIS, &within_limits, &dictionary)
            .unwrap()
            .len(),
        8
    );
    for response in [
        reference_response(1, 18, id),
        reference_response(9, 16, id),
        reference_response(1, 257, id),
    ] {
        assert!(response.len() < MAX_BLOCK_BYTES);
        assert_eq!(
            decode_response(GENESIS, &response, &dictionary),
            Err(DecodeError::LimitExceeded)
        );
    }
}

#[test]
fn inline_transactions_keep_the_legacy_transaction_size_limit() {
    let oversized = transaction(1, MAX_TRANSACTION_BYTES);
    let messages = vec![NetworkMessage::ValidValue {
        block: block(vec![oversized.clone()]),
        proof: Vec::new(),
    }];
    assert_eq!(
        encode_response(GENESIS, &messages, &[]),
        Err(DecodeError::LimitExceeded)
    );
    let mut response = reference_response(1, 0, Hash256([0; 32]));
    response.truncate(response.len() - 2);
    response.extend_from_slice(&1u16.to_le_bytes());
    response.push(1);
    let bytes = oversized.to_bytes();
    response.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
    response.extend_from_slice(&bytes);
    assert_eq!(
        decode_response(GENESIS, &response, &TransactionDictionary::default()),
        Err(DecodeError::LimitExceeded)
    );
}
