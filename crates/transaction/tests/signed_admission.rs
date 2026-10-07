// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Signed transaction commitments, validation order, and resource bounds.

use std::collections::BTreeMap;

use codec::CanonicalEncode;
use crypto::blake2s::{ed25519_public_key, ed25519_sign, ed25519_verify};
use transaction::{
    AccountState, BasicValidator, Envelope, RegisteredAccount, SignedValidator, TransactionError,
    TransactionValidator, ValidationContext, address_from_public_key, compute_tx_id,
    estimate_encoded_len, signing_hash,
};
use types::{Address, Resources, StateKey, Transaction};

const SEED: [u8; 32] = [7; 32];
const MAX_RESOURCES: Resources = Resources {
    compute: u64::MAX,
    memory: u64::MAX,
    io: u64::MAX,
    bandwidth: u64::MAX,
};
const PRICES: Resources = Resources {
    compute: 1,
    memory: 2,
    io: 3,
    bandwidth: 4,
};

fn context() -> ValidationContext {
    ValidationContext {
        chain_id: 7,
        next_height: 10,
        max_transaction_bytes: 1024,
    }
}

fn account() -> RegisteredAccount {
    RegisteredAccount {
        state: AccountState {
            nonce: 5,
            balance: 1000,
        },
        public_key: ed25519_public_key(&SEED),
    }
}

fn validator(account: RegisteredAccount, limits: Resources, prices: Resources) -> SignedValidator {
    SignedValidator::new(
        BTreeMap::from([(address_from_public_key(&account.public_key), account)]),
        limits,
        prices,
    )
}

fn signed_transaction() -> Transaction {
    let mut tx = Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: PRICES,
        chain_id: 7,
        sender: address_from_public_key(&ed25519_public_key(&SEED)),
        nonce: 5,
        access_list: vec![StateKey(vec![1])],
        resource_limit: Resources {
            compute: 10,
            memory: 2,
            io: 3,
            bandwidth: 4,
        },
        payload: transaction::Payment {
            public_key: ed25519_public_key(&SEED),
            recipient: Address([9; 32]),
            amount: 1,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.signature = ed25519_sign(&SEED, signing_hash(&tx).as_bytes());
    tx
}

#[test]
fn admits_valid_signature_without_mutating_account_state() {
    let validator = validator(account(), MAX_RESOURCES, PRICES);
    let tx = signed_transaction();
    let first = validator.validate(tx.clone(), context()).unwrap();
    assert_eq!(first.id, compute_tx_id(&tx));
    assert_eq!(validator.validate(tx, context()), Ok(first));
}

#[test]
fn signatures_and_ids_bind_every_transaction_field() {
    let original = signed_transaction();
    let mut variants = vec![original.clone(); 17];
    variants[0].chain_id += 1;
    variants[1].sender.0[0] ^= 1;
    variants[2].nonce += 1;
    variants[3].access_list[0].0.push(2);
    variants[4].resource_limit.compute += 1;
    variants[5].resource_limit.memory += 1;
    variants[6].resource_limit.io += 1;
    variants[7].resource_limit.bandwidth += 1;
    variants[8].payload.push(4);
    variants[9].signature[0] ^= 1;
    variants[10].version += 1;
    variants[11].expires_at -= 1;
    variants[12].lane = types::TransactionLane::Contracts;
    variants[13].resource_prices.compute += 1;
    variants[14].resource_prices.memory += 1;
    variants[15].resource_prices.io += 1;
    variants[16].resource_prices.bandwidth += 1;
    for tx in variants {
        assert_ne!(compute_tx_id(&tx), compute_tx_id(&original));
        assert!(!ed25519_verify(
            &ed25519_public_key(&SEED),
            signing_hash(&tx).as_bytes(),
            &tx.signature
        ));
    }
    let mut unsigned = original.clone();
    unsigned.signature = [0; 64];
    assert_eq!(signing_hash(&unsigned), signing_hash(&original));
    assert_ne!(signing_hash(&original), compute_tx_id(&original));
}

#[test]
fn commitments_match_independent_blake2s_vectors() {
    let tx = Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: PRICES,
        chain_id: 0x0403_0201,
        sender: Address([0x11; 32]),
        nonce: 0x0807_0605_0403_0201,
        access_list: vec![StateKey(vec![0x22])],
        resource_limit: Resources {
            compute: 1,
            memory: 2,
            io: 3,
            bandwidth: 4,
        },
        payload: vec![0x33],
        signature: [0x44; 64],
    };
    let hex = |value: &str| -> [u8; 32] {
        std::array::from_fn(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap())
    };
    assert_eq!(
        signing_hash(&tx).0,
        hex("a99fec6b1c1a412cd189591de9921873a7692c6b81b10665042e724e26217be3")
    );
    assert_eq!(
        compute_tx_id(&tx).0,
        hex("a7e9b9208d12c9ad8d33b19b679992064ce5d279ed3e1dfb913cf1c73666c112")
    );
}

#[test]
fn validation_reports_the_first_failed_stage() {
    let validator = validator(account(), MAX_RESOURCES, PRICES);
    let mut tx = signed_transaction();
    tx.signature = [0; 64];
    tx.chain_id = 99;
    tx.nonce = 9;
    let mut ctx = context();
    ctx.max_transaction_bytes = 1;
    assert_eq!(
        validator.validate(tx.clone(), ctx),
        Err(TransactionError::InvalidEnvelope)
    );
    assert_eq!(
        validator.validate(tx.clone(), context()),
        Err(TransactionError::WrongChain)
    );
    tx.chain_id = 7;
    assert_eq!(
        validator.validate(tx.clone(), context()),
        Err(TransactionError::InvalidNonce)
    );
    tx.nonce = 5;
    tx.resource_limit.compute = 1001;
    assert_eq!(
        validator.validate(tx.clone(), context()),
        Err(TransactionError::InsufficientResources)
    );
    tx.resource_limit.compute = 10;
    assert_eq!(
        validator.validate(tx, context()),
        Err(TransactionError::InvalidSignature)
    );
}

#[test]
fn rejects_unknown_sender_and_mismatched_registered_key() {
    let tx = signed_transaction();
    let empty = SignedValidator::new(BTreeMap::new(), MAX_RESOURCES, PRICES);
    assert_eq!(
        empty.validate(tx.clone(), context()),
        Err(TransactionError::UnknownSender)
    );
    let mut wrong = account();
    wrong.public_key = ed25519_public_key(&[8; 32]);
    let validator =
        SignedValidator::new(BTreeMap::from([(tx.sender, wrong)]), MAX_RESOURCES, PRICES);
    assert_eq!(
        validator.validate(tx, context()),
        Err(TransactionError::UnknownSender)
    );
}

#[test]
fn resource_cost_checks_every_product_and_sum() {
    assert_eq!(
        signed_transaction().resource_limit.checked_cost(PRICES),
        Some(39)
    );
    assert_eq!(MAX_RESOURCES.checked_cost(Resources::ZERO), Some(0));
    for resources in [
        Resources {
            compute: u64::MAX,
            ..Resources::ZERO
        },
        Resources {
            memory: u64::MAX,
            ..Resources::ZERO
        },
        Resources {
            io: u64::MAX,
            ..Resources::ZERO
        },
        Resources {
            bandwidth: u64::MAX,
            ..Resources::ZERO
        },
    ] {
        assert_eq!(
            resources.checked_cost(Resources {
                compute: 2,
                memory: 2,
                io: 2,
                bandwidth: 2
            }),
            None
        );
    }
    assert_eq!(
        Resources {
            compute: u64::MAX,
            memory: 1,
            ..Resources::ZERO
        }
        .checked_cost(Resources {
            compute: 1,
            memory: 1,
            ..Resources::ZERO
        }),
        None
    );
}

#[test]
fn rejects_excessive_limits_and_resource_payment_overflow() {
    let mut rich = account();
    rich.state.balance = u64::MAX;
    let validator = validator(rich, MAX_RESOURCES, PRICES);
    let mut tx = signed_transaction();
    tx.resource_limit.memory = u64::MAX;
    assert_eq!(
        validator.validate(tx, context()),
        Err(TransactionError::InsufficientResources)
    );
    let limited = SignedValidator::new(
        BTreeMap::from([(signed_transaction().sender, account())]),
        Resources::ZERO,
        PRICES,
    );
    assert_eq!(
        limited.validate(signed_transaction(), context()),
        Err(TransactionError::InsufficientResources)
    );
}

#[test]
fn size_calculation_matches_codec_across_prefix_boundaries() {
    for length in [0, 1, 127, 128, 256] {
        let mut tx = signed_transaction();
        tx.access_list = vec![StateKey(vec![0xAA; length]); length];
        tx.payload = vec![0xBB; length];
        assert_eq!(estimate_encoded_len(&tx), tx.to_bytes().len());
    }
    let validator = validator(account(), MAX_RESOURCES, PRICES);
    let tx = signed_transaction();
    let mut ctx = context();
    ctx.max_transaction_bytes = tx.to_bytes().len();
    assert!(validator.validate(tx.clone(), ctx).is_ok());
    ctx.max_transaction_bytes -= 1;
    assert_eq!(
        validator.validate(tx, ctx),
        Err(TransactionError::InvalidEnvelope)
    );
}

#[test]
fn rejects_codec_limits_even_with_unlimited_context() {
    let validator = validator(account(), MAX_RESOURCES, PRICES);
    let mut ctx = context();
    ctx.max_transaction_bytes = usize::MAX;
    let mut tx = signed_transaction();
    tx.access_list = vec![StateKey(vec![1; codec::MAX_STATE_KEY_LEN + 1])];
    assert_eq!(
        validator.validate(tx, ctx),
        Err(TransactionError::InvalidEnvelope)
    );
    let mut tx = signed_transaction();
    tx.payload = vec![0; codec::MAX_PAYLOAD + 1];
    assert_eq!(
        validator.validate(tx, ctx),
        Err(TransactionError::InvalidEnvelope)
    );
}

#[test]
fn exhausted_nonces_fail_without_wrapping() {
    let mut exhausted = account();
    exhausted.state.nonce = u64::MAX;
    let validator = validator(exhausted.clone(), MAX_RESOURCES, PRICES);
    let mut tx = signed_transaction();
    tx.nonce = u64::MAX;
    assert_eq!(
        validator.validate(tx.clone(), context()),
        Err(TransactionError::InvalidNonce)
    );
    let mut basic = BasicValidator::new(BTreeMap::from([(tx.sender, exhausted.state)]));
    assert_eq!(
        basic.advance_nonce(&tx.sender),
        Err(TransactionError::InvalidNonce)
    );
    assert_eq!(
        basic.advance_nonce(&tx.sender),
        Err(TransactionError::InvalidNonce)
    );
}

#[test]
fn envelope_uses_the_same_signature_and_identifier() {
    let tx = signed_transaction();
    let mut unsigned = tx.clone();
    unsigned.signature = [0; 64];
    let mut envelope = Envelope::new(unsigned, tx.signature);
    assert!(envelope.is_well_formed());
    assert_eq!(envelope.transaction, tx);
    assert_eq!(envelope.id(), compute_tx_id(&tx));
    envelope.transaction.signature[0] ^= 1;
    assert!(!envelope.is_well_formed());
}

#[test]
fn expiry_is_inclusive_and_checked_before_account_or_signature() {
    let validator = validator(account(), MAX_RESOURCES, PRICES);
    let mut tx = signed_transaction();
    tx.expires_at = context().next_height;
    tx.signature = ed25519_sign(&SEED, signing_hash(&tx).as_bytes());
    assert!(validator.validate(tx.clone(), context()).is_ok());
    let mut later = context();
    later.next_height += 1;
    tx.sender = Address::ZERO;
    tx.signature = [0; 64];
    assert_eq!(
        validator.validate(tx.clone(), later),
        Err(TransactionError::Expired)
    );
    tx.chain_id += 1;
    assert_eq!(
        validator.validate(tx, later),
        Err(TransactionError::WrongChain)
    );
}

#[test]
fn unsupported_versions_lanes_payloads_and_prices_are_rejected() {
    let validator = validator(account(), MAX_RESOURCES, PRICES);
    let mut tx = signed_transaction();
    tx.version = 2;
    assert_eq!(
        validator.validate(tx, context()),
        Err(TransactionError::InvalidEnvelope)
    );
    for lane in [
        types::TransactionLane::Contracts,
        types::TransactionLane::System,
    ] {
        let mut tx = signed_transaction();
        tx.lane = lane;
        tx.signature = ed25519_sign(&SEED, signing_hash(&tx).as_bytes());
        assert_eq!(
            validator.validate(tx, context()),
            Err(TransactionError::UnsupportedPayload)
        );
    }
    for price in [Resources::ZERO, MAX_RESOURCES] {
        let mut tx = signed_transaction();
        tx.resource_prices = price;
        tx.signature = ed25519_sign(&SEED, signing_hash(&tx).as_bytes());
        assert_eq!(
            validator.validate(tx, context()),
            Err(TransactionError::InsufficientResources)
        );
    }
    for payload in [
        vec![1],
        transaction::Payment {
            public_key: ed25519_public_key(&[8; 32]),
            recipient: Address([9; 32]),
            amount: 1,
        }
        .to_bytes(),
    ] {
        let mut tx = signed_transaction();
        tx.payload = payload;
        tx.signature = ed25519_sign(&SEED, signing_hash(&tx).as_bytes());
        assert_eq!(
            validator.validate(tx, context()),
            Err(TransactionError::UnsupportedPayload)
        );
    }
}
