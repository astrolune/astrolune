// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Measures signing commitments, strict envelope decode, and staged admission.
//!
//! Each figure describes one machine, one toolchain and one fixture shape. The
//! benchmark establishes no property of admission: that a signature binds every
//! canonical field, that a commitment matches its independent vector, and that
//! each rejection reports the first failed stage are established by the tests in
//! `crates/transaction`, not here. A stage that measures faster is not weaker,
//! and a slower one is not stricter.
//!
//! Two measurement artifacts must be read with the numbers.
//! `TransactionValidator::validate` takes the transaction by value, so every
//! admission row includes one `Transaction::clone`; the `admission/clone_only`
//! rows record that clone alone so it can be subtracted. `Envelope::id` clones
//! internally for the same reason, and is measured on one fixture only.
//!
//! What this does NOT establish: mempool, block or node admission throughput;
//! any bound that holds under contention from other processes; a figure
//! comparable to a different machine or allocator; the cost of admission under
//! a real account view backed by storage rather than a `BTreeMap`; or
//! statistical significance of a gap between two rows.

use std::collections::BTreeMap;

use codec::{CanonicalDecode, CanonicalEncode};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use testkit::bench::Suite;
use transaction::{
    AccountState, BasicValidator, ContractAction, ContractPayload, Envelope, Payment,
    RegisteredAccount, SignedValidator, TransactionValidator, ValidationContext,
    address_from_public_key, compute_tx_id, contract_address, contract_code_key,
    contract_state_key, estimate_encoded_len, signing_hash,
};
use types::{Address, Resources, StateKey, Transaction};

/// Deterministic sender secret key. Benchmark material only, never a key.
const SEED: [u8; 32] = [7; 32];

/// Chain identifier shared by every fixture and validation context.
const CHAIN_ID: u32 = 7;

/// Sender nonce held by the registered account and by every signed fixture.
const NONCE: u64 = 5;

/// Height at which the fixtures are offered for admission.
const NEXT_HEIGHT: u64 = 10;

/// Canonical byte budget wide enough for the largest access-list fixture.
const MAX_BYTES: usize = 65_536;

/// Finalized resource prices a signed fixture must authorize exactly.
const PRICES: Resources = Resources {
    compute: 1,
    memory: 2,
    io: 3,
    bandwidth: 4,
};

/// Resource limits every signed fixture declares, well inside the balance.
const LIMITS: Resources = Resources {
    compute: 10,
    memory: 2,
    io: 3,
    bandwidth: 4,
};

/// Access-list entry counts swept through signing, decode and admission.
const ACCESS_LIST_SIZES: [usize; 4] = [0, 1, 16, 256];

/// Payload byte counts swept through the signing-domain hash.
const PAYLOAD_SIZES: [usize; 4] = [0, 128, 1_024, 16_384];

/// Registered account-view sizes swept through admission.
///
/// The view is a `BTreeMap` keyed by address, so these brackets show how much
/// of an admission is the sender lookup rather than the signature check.
const ACCOUNT_COUNTS: [usize; 2] = [256, 4_096];

/// Contract-call key counts swept through the ABI-v2 payload codec.
const CONTRACT_KEY_COUNTS: [usize; 3] = [0, 16, 256];

/// Byte length of every access-list key built by [`access_keys`].
const KEY_LEN: usize = 32;

/// Deployable code bytes in the contract deployment fixture.
const DEPLOY_LEN: usize = 65_536;

/// Returns the sender address derived from [`SEED`].
fn sender() -> Address {
    address_from_public_key(&ed25519_public_key(&SEED))
}

/// Builds `count` distinct 32-byte access-list keys.
///
/// Two index bytes keep counts above 256 distinct without changing the encoded
/// length, so a sweep varies the entry count and nothing else.
fn access_keys(count: usize) -> Vec<StateKey> {
    (0..count)
        .map(|index| {
            let mut key = vec![0xAA; KEY_LEN];
            key[0] = u8::try_from(index % 256).unwrap_or_default();
            key[1] = u8::try_from(index / 256).unwrap_or_default();
            StateKey(key)
        })
        .collect()
}

/// Builds an unsigned payments-lane transaction with `entries` access keys.
///
/// The payload is the exact `Payment` the signed validator requires, so the
/// fixture reaches the final lane check rather than stopping earlier.
fn unsigned(entries: usize) -> Transaction {
    Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: PRICES,
        chain_id: CHAIN_ID,
        sender: sender(),
        nonce: NONCE,
        access_list: access_keys(entries),
        resource_limit: LIMITS,
        payload: Payment {
            public_key: ed25519_public_key(&SEED),
            recipient: testkit::address(9),
            amount: 1,
        }
        .to_bytes(),
        signature: [0; 64],
    }
}

/// Signs `transaction` over its signing-domain digest.
fn signed(mut transaction: Transaction) -> Transaction {
    transaction.signature = ed25519_sign(&SEED, signing_hash(&transaction).as_bytes());
    transaction
}

/// Builds a validation context admitting at most `max_bytes` canonical bytes.
fn context(max_bytes: usize) -> ValidationContext {
    ValidationContext {
        chain_id: CHAIN_ID,
        next_height: NEXT_HEIGHT,
        max_transaction_bytes: max_bytes,
    }
}

/// Builds an account view of `count` entries whose last insert is the sender.
///
/// Filler accounts carry a zero public key, so none of them could be admitted;
/// they exist only to grow the lookup tree. The sender is inserted last so a
/// filler address can never displace it.
fn accounts(count: usize) -> BTreeMap<Address, RegisteredAccount> {
    let filler = RegisteredAccount {
        state: AccountState {
            nonce: NONCE,
            balance: 0,
        },
        public_key: [0; 32],
    };
    let mut accounts: BTreeMap<Address, RegisteredAccount> = (0..count.saturating_sub(1))
        .map(|index| {
            let mut seed = [0u8; 32];
            seed[0] = u8::try_from(index % 256).unwrap_or_default();
            seed[1] = u8::try_from(index / 256).unwrap_or_default();
            // Hashing spreads the filler addresses the way real keys would.
            let address = Address(types::hash::domain_hash(b"astrolune.bench.filler", &seed).0);
            (address, filler.clone())
        })
        .collect();
    accounts.insert(
        sender(),
        RegisteredAccount {
            state: AccountState {
                nonce: NONCE,
                balance: 1_000_000,
            },
            public_key: ed25519_public_key(&SEED),
        },
    );
    accounts
}

/// Builds a signed validator over an account view of `count` entries.
fn signed_validator(count: usize) -> SignedValidator {
    SignedValidator::new(accounts(count), testkit::resources(u64::MAX), PRICES)
}

/// Builds `count` strictly increasing 16-byte contract-local keys.
///
/// Indices are written big-endian so lexicographic order matches numeric order,
/// which is what the decoder's strict ordering check requires.
fn contract_keys(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| {
            let mut key = vec![0u8; 16];
            let tag = u64::try_from(index).unwrap_or_default().to_be_bytes();
            key[..8].copy_from_slice(&tag);
            key
        })
        .collect()
}

/// Records the signing-domain hash, the identifier, and address derivation.
///
/// `signing_hash` encodes every field except the signature and hashes it, while
/// `transaction_id` encodes the signature too; the gap between them is the
/// 64 signature bytes and one extra allocation.
fn bench_commitments(suite: &mut Suite) {
    for entries in ACCESS_LIST_SIZES {
        let fixture = signed(unsigned(entries));
        suite.bench(
            format!("commitment/signing_hash/access_list_{entries}"),
            || signing_hash(&fixture),
        );
        suite.bench(
            format!("commitment/transaction_id/access_list_{entries}"),
            || compute_tx_id(&fixture),
        );
    }

    for payload in PAYLOAD_SIZES {
        let mut fixture = unsigned(0);
        fixture.payload = vec![0xAB; payload];
        suite.bench(
            format!("commitment/signing_hash/payload_{payload}B"),
            || signing_hash(&fixture),
        );
    }

    let public_key = ed25519_public_key(&SEED);
    suite.bench("commitment/address_from_public_key", || {
        address_from_public_key(&public_key)
    });

    // The producer path: commit to the unsigned fields, then sign the digest.
    let fixture = unsigned(1);
    suite.bench("commitment/sign_transaction/access_list_1", || {
        ed25519_sign(&SEED, signing_hash(&fixture).as_bytes())
    });
}

/// Records the size estimate beside the encoding it exists to avoid.
///
/// `estimate_encoded_len` walks the access list and payload lengths without
/// writing bytes, so the gap to `to_bytes().len()` is the whole point of it:
/// shape validation needs the size before it is willing to allocate.
fn bench_sizes(suite: &mut Suite) {
    for entries in ACCESS_LIST_SIZES {
        let fixture = signed(unsigned(entries));
        suite.bench(
            format!("size/estimate_encoded_len/access_list_{entries}"),
            || estimate_encoded_len(&fixture),
        );
        suite.bench(
            format!("size/encode_then_len/access_list_{entries}"),
            || fixture.to_bytes().len(),
        );
    }
}

/// Records strict decode of a signed envelope and the envelope helpers.
fn bench_envelope(suite: &mut Suite) {
    for entries in ACCESS_LIST_SIZES {
        let encoded = signed(unsigned(entries)).to_bytes();
        suite.bench(
            format!("envelope/strict_decode/access_list_{entries}"),
            || Transaction::decode(&encoded),
        );
    }

    let fixture = signed(unsigned(1));
    let mut unsigned_form = fixture.clone();
    unsigned_form.signature = [0; 64];
    let envelope = Envelope::new(unsigned_form, fixture.signature);
    suite.bench("envelope/id/access_list_1", || envelope.id());
    suite.bench("envelope/is_well_formed", || envelope.is_well_formed());
}

/// Records the payments and contract payload codecs, accepted and rejected.
///
/// `Payment::decode` rejects an unknown tag on the first eight bytes but a zero
/// amount only after every field has been copied out, so the two rejections sit
/// at opposite ends of the same fixed-size payload.
fn bench_payloads(suite: &mut Suite) {
    let payment = Payment {
        public_key: ed25519_public_key(&SEED),
        recipient: testkit::address(9),
        amount: 1,
    };
    let encoded = payment.to_bytes();
    let mut unknown_tag = encoded.clone();
    unknown_tag[0] ^= 1;
    let mut zero_amount = encoded.clone();
    zero_amount[72..].fill(0);

    suite.bench("payment/encode", || payment.to_bytes());
    suite.bench("payment/decode/accept", || Payment::decode(&encoded));
    suite.bench("payment/decode/reject_unknown_tag", || {
        Payment::decode(&unknown_tag)
    });
    suite.bench("payment/decode/reject_zero_amount", || {
        Payment::decode(&zero_amount)
    });

    let signer = sender();
    let address = contract_address(CHAIN_ID, signer, NONCE);
    let local = vec![0xCD; 64];
    suite.bench("contract/address_derivation", || {
        contract_address(CHAIN_ID, signer, NONCE)
    });
    suite.bench("contract/code_key_derivation", || {
        contract_code_key(address)
    });
    suite.bench("contract/state_key_derivation", || {
        contract_state_key(address, &local)
    });

    bench_contract_payloads(suite, address);
}

/// Records the ABI-v2 contract payload codec across the call-key sweep.
///
/// The unsorted rejection inverts the final pair of a 256-key call, so the
/// strict ordering check fires only after the whole payload has been read.
fn bench_contract_payloads(suite: &mut Suite, address: Address) {
    let public_key = ed25519_public_key(&SEED);
    for count in CONTRACT_KEY_COUNTS {
        let payload = ContractPayload {
            public_key,
            action: ContractAction::Call {
                address,
                input: vec![0xEF; 32],
                keys: contract_keys(count),
            },
        };
        let encoded = payload.to_bytes();
        suite.bench(format!("contract/encode/call_keys_{count}"), || {
            payload.to_bytes()
        });
        suite.bench(format!("contract/decode/call_keys_{count}"), || {
            ContractPayload::decode(&encoded)
        });
    }

    let mut keys = contract_keys(256);
    keys.swap(254, 255);
    let unsorted = ContractPayload {
        public_key,
        action: ContractAction::Call {
            address,
            input: vec![0xEF; 32],
            keys,
        },
    }
    .to_bytes();
    suite.bench("contract/decode/reject_unsorted_keys_256", || {
        ContractPayload::decode(&unsorted)
    });

    let deploy = ContractPayload {
        public_key,
        action: ContractAction::Deploy(vec![0x90; DEPLOY_LEN]),
    };
    let encoded = deploy.to_bytes();
    suite.bench(format!("contract/encode/deploy_{DEPLOY_LEN}B"), || {
        deploy.to_bytes()
    });
    suite.bench(format!("contract/decode/deploy_{DEPLOY_LEN}B"), || {
        ContractPayload::decode(&encoded)
    });
}

/// Records accepted admission, the clone it carries, and the unsigned reference.
///
/// `BasicValidator` runs the same shape, chain, expiry, nonce and balance stages
/// but checks only that the signature is nonzero, so the gap to the signed
/// validator is the strict Ed25519 verification plus the lane payload check.
fn bench_admission(suite: &mut Suite) {
    let single = signed_validator(1);
    let basic = BasicValidator::new(BTreeMap::from([(
        sender(),
        AccountState {
            nonce: NONCE,
            balance: 1_000_000,
        },
    )]));
    let ctx = context(MAX_BYTES);

    for entries in ACCESS_LIST_SIZES {
        let fixture = signed(unsigned(entries));
        suite.bench(
            format!("admission/clone_only/access_list_{entries}"),
            || fixture.clone(),
        );
        suite.bench(
            format!("admission/signed/accept/access_list_{entries}"),
            || single.validate(fixture.clone(), ctx),
        );
        suite.bench(
            format!("admission/basic/accept/access_list_{entries}"),
            || basic.validate(fixture.clone(), ctx),
        );
    }

    // Same fixture as `access_list_1`, with only the account view growing.
    let fixture = signed(unsigned(1));
    for count in ACCOUNT_COUNTS {
        let validator = signed_validator(count);
        suite.bench(format!("admission/signed/accept/accounts_{count}"), || {
            validator.validate(fixture.clone(), ctx)
        });
    }
}

/// Records one rejection per validation stage on a single shared fixture.
///
/// Stages run in a fixed order, so each fixture below is the accepted
/// transaction with exactly the field of its stage changed. Earlier stages
/// never reach the signature check, which is the dominant cost of acceptance.
/// The nonce stage is the first to pay the sender address re-derivation that
/// `SignedValidator` performs from the registered public key, so the gap from
/// `reject_unknown_sender` to `reject_invalid_nonce` is that one hash.
fn bench_rejections(suite: &mut Suite) {
    let validator = signed_validator(1);
    let ctx = context(MAX_BYTES);
    let tiny = context(1);
    let accepted = signed(unsigned(1));

    let mut wrong_chain = accepted.clone();
    wrong_chain.chain_id = CHAIN_ID + 1;
    let mut expired = accepted.clone();
    expired.expires_at = NEXT_HEIGHT - 1;
    let mut unknown_sender = accepted.clone();
    unknown_sender.sender = testkit::address(0xEE);
    let mut invalid_nonce = accepted.clone();
    invalid_nonce.nonce = NONCE + 1;
    let mut insufficient = accepted.clone();
    insufficient.resource_prices = Resources::ZERO;
    let mut invalid_signature = accepted.clone();
    invalid_signature.signature[0] ^= 1;
    let mut unsupported = accepted.clone();
    unsupported.payload = vec![1];
    let unsupported = signed(unsupported);

    suite.bench("admission/signed/reject_invalid_envelope", || {
        validator.validate(accepted.clone(), tiny)
    });
    suite.bench("admission/signed/reject_wrong_chain", || {
        validator.validate(wrong_chain.clone(), ctx)
    });
    suite.bench("admission/signed/reject_expired", || {
        validator.validate(expired.clone(), ctx)
    });
    suite.bench("admission/signed/reject_unknown_sender", || {
        validator.validate(unknown_sender.clone(), ctx)
    });
    suite.bench("admission/signed/reject_invalid_nonce", || {
        validator.validate(invalid_nonce.clone(), ctx)
    });
    suite.bench("admission/signed/reject_insufficient_resources", || {
        validator.validate(insufficient.clone(), ctx)
    });
    suite.bench("admission/signed/reject_invalid_signature", || {
        validator.validate(invalid_signature.clone(), ctx)
    });
    suite.bench("admission/signed/reject_unsupported_payload", || {
        validator.validate(unsupported.clone(), ctx)
    });

    // The nonce stage runs after the sender lookup and before verification, so
    // this row isolates the cost of the account view.
    let large = signed_validator(4_096);
    suite.bench(
        "admission/signed/reject_invalid_nonce/accounts_4096",
        || large.validate(invalid_nonce.clone(), ctx),
    );
}

fn main() {
    let mut suite = Suite::new("transaction");
    bench_commitments(&mut suite);
    bench_sizes(&mut suite);
    bench_envelope(&mut suite);
    bench_payloads(&mut suite);
    bench_admission(&mut suite);
    bench_rejections(&mut suite);
    suite.report();
}
