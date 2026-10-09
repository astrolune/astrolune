// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Measures canonical encoding, strict decoding, and rejection of malformed input.
//!
//! Each figure describes one machine, one toolchain and one input shape. The
//! benchmark establishes no property of the codec: that a fixture encodes to the
//! bytes shown, and that each malformed fixture is rejected with the variant
//! named beside it, is established by the tests in `crates/codec`, not here. A
//! rejection path that measures faster is not more strict, and a slower encode
//! is not less canonical.
//!
//! Accept and reject figures are comparable only within one fixture, and even
//! then they describe different amounts of work rather than a speedup: a
//! rejected transaction never performs the owned allocations an accepted one
//! performs, because `Transaction::decode` validates the whole envelope before
//! it copies any key or payload byte.
//!
//! What this does NOT establish: block, mempool or node throughput; bytes per
//! second for any wire protocol; any bound that holds under contention from
//! other processes; a figure comparable to a different machine or allocator; or
//! statistical significance of a gap between two rows.

use codec::{
    CanonicalDecode, CanonicalEncode, MAX_LIST_LEN, MAX_PAYLOAD, MAX_STATE_KEY_LEN, encode_length,
};
use std::hint::black_box;
use testkit::bench::Suite;
use types::{
    AccountState, Address, BlockHeader, ExecutionReceipt, Hash256, Resources, StateKey,
    Transaction, ValidatorId,
};

/// Access-list entry counts swept through the transaction codec.
const ACCESS_LIST_SIZES: [usize; 4] = [0, 1, 16, 256];

/// Payload byte counts swept through the transaction codec.
///
/// The sweep ends at [`MAX_PAYLOAD`] because decode rejects a longer payload,
/// so that entry is the largest input on which the accepted path exists.
const PAYLOAD_SIZES: [usize; 5] = [0, 64, 1_024, 16_384, MAX_PAYLOAD];

/// Byte length of every access-list key built by [`transaction`].
const KEY_LEN: usize = 32;

/// Access-list entries in the fixture shared by the encode pair and rejections.
const SHARED_ENTRIES: usize = 16;

/// Payload bytes in the fixture shared by the encode pair and rejections.
const SHARED_PAYLOAD: usize = 1_024;

/// Offset of the lane discriminant in a canonical transaction encoding.
///
/// Four magic bytes, version, chain identifier, sender, nonce and expiry
/// precede it; the access-list length prefix follows immediately after.
const LANE_OFFSET: usize = 60;

/// Builds a canonical transaction with `entries` access keys and `payload` bytes.
///
/// Keys differ from one another so decoding cannot share one allocation, and
/// every field outside the two swept dimensions is held fixed.
fn transaction(entries: usize, payload: usize) -> Transaction {
    Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: Resources {
            compute: 1,
            ..Resources::ZERO
        },
        chain_id: 7,
        sender: testkit::address(0x11),
        nonce: 42,
        access_list: (0..entries)
            .map(|index| {
                let mut key = vec![0xAA; KEY_LEN];
                key[0] = u8::try_from(index % 256).unwrap_or_default();
                StateKey(key)
            })
            .collect(),
        resource_limit: testkit::resources(1_000),
        payload: vec![0xAB; payload],
        signature: [0xCD; 64],
    }
}

/// Records encode and strict decode for every primitive the codec defines.
///
/// Inputs pass through [`black_box`] because an integer literal is otherwise a
/// compile-time constant, and the encode would collapse to a stored constant
/// instead of the byte-order conversion being measured.
fn bench_primitives(suite: &mut Suite) {
    suite.bench("primitive/encode/u8", || black_box(0xA5_u8).to_bytes());
    suite.bench("primitive/encode/u16", || black_box(0xA5A5_u16).to_bytes());
    suite.bench("primitive/encode/u32", || {
        black_box(0xA5A5_A5A5_u32).to_bytes()
    });
    suite.bench("primitive/encode/u64", || {
        black_box(0xA5A5_A5A5_A5A5_A5A5_u64).to_bytes()
    });
    suite.bench("primitive/encode/bool", || black_box(true).to_bytes());
    suite.bench("primitive/encode/bytes32", || {
        black_box([0xA5_u8; 32]).to_bytes()
    });

    let byte = 0xA5_u8.to_bytes();
    let short = 0xA5A5_u16.to_bytes();
    let word = 0xA5A5_A5A5_u32.to_bytes();
    let long = 0xA5A5_A5A5_A5A5_A5A5_u64.to_bytes();
    let flag = true.to_bytes();
    let fixed = [0xA5_u8; 32].to_bytes();
    suite.bench("primitive/decode/u8", || u8::decode(black_box(&byte)));
    suite.bench("primitive/decode/u16", || u16::decode(black_box(&short)));
    suite.bench("primitive/decode/u32", || u32::decode(black_box(&word)));
    suite.bench("primitive/decode/u64", || u64::decode(black_box(&long)));
    suite.bench("primitive/decode/bool", || bool::decode(black_box(&flag)));
    suite.bench("primitive/decode/bytes32", || {
        <[u8; 32]>::decode(black_box(&fixed))
    });

    // Three rejections reachable on the first read: a bool outside {0, 1}, an
    // over-long integer, and a digest one byte short.
    suite.bench("primitive/decode/reject_non_canonical_bool", || {
        bool::decode(black_box(&[2_u8]))
    });
    suite.bench("primitive/decode/reject_trailing_u64", || {
        u64::decode(black_box(&[0_u8; 9]))
    });
    suite.bench("primitive/decode/reject_truncated_hash256", || {
        Hash256::decode(black_box(&[0_u8; 31]))
    });
}

/// Records encode and strict decode for each canonical protocol type.
///
/// `Hash256`, `Address` and `ValidatorId` share one 32-byte representation and
/// are measured separately only to show that none of them adds framing.
fn bench_protocol_types(suite: &mut Suite) {
    let hash = testkit::hash(0xAB);
    let address = testkit::address(0x42);
    let validator = testkit::validator(0x99);
    let resources = testkit::resources(1_000);
    let account = AccountState {
        nonce: 42,
        balance: 1_000_000,
    };
    let key = StateKey(vec![0xAA; KEY_LEN]);
    let header = BlockHeader {
        height: 4_096,
        parent: testkit::hash(1),
        transactions_root: testkit::hash(2),
        state_root: testkit::hash(3),
        receipts_root: testkit::hash(4),
        committee_root: testkit::hash(5),
        capacity: testkit::resources(1_000_000),
    };
    let receipt = ExecutionReceipt {
        transaction: testkit::hash(6),
        succeeded: true,
        resources: testkit::resources(512),
        output_root: testkit::hash(7),
    };

    suite.bench("protocol/encode/hash256", || hash.to_bytes());
    suite.bench("protocol/encode/address", || address.to_bytes());
    suite.bench("protocol/encode/validator_id", || validator.to_bytes());
    suite.bench("protocol/encode/resources", || resources.to_bytes());
    suite.bench("protocol/encode/account_state", || account.to_bytes());
    suite.bench("protocol/encode/state_key_32B", || key.to_bytes());
    suite.bench("protocol/encode/block_header", || header.to_bytes());
    suite.bench("protocol/encode/execution_receipt", || receipt.to_bytes());

    let encoded_hash = hash.to_bytes();
    let encoded_address = address.to_bytes();
    let encoded_validator = validator.to_bytes();
    let encoded_resources = resources.to_bytes();
    let encoded_account = account.to_bytes();
    let encoded_key = key.to_bytes();
    let encoded_header = header.to_bytes();
    let encoded_receipt = receipt.to_bytes();
    suite.bench("protocol/decode/hash256", || Hash256::decode(&encoded_hash));
    suite.bench("protocol/decode/address", || {
        Address::decode(&encoded_address)
    });
    suite.bench("protocol/decode/validator_id", || {
        ValidatorId::decode(&encoded_validator)
    });
    suite.bench("protocol/decode/resources", || {
        Resources::decode(&encoded_resources)
    });
    suite.bench("protocol/decode/account_state", || {
        AccountState::decode(&encoded_account)
    });
    suite.bench("protocol/decode/state_key_32B", || {
        StateKey::decode(&encoded_key)
    });
    suite.bench("protocol/decode/block_header", || {
        BlockHeader::decode(&encoded_header)
    });
    suite.bench("protocol/decode/execution_receipt", || {
        ExecutionReceipt::decode(&encoded_receipt)
    });
}

/// Records the compact length prefix and the state-key decode across its boundary.
///
/// Lengths below 128 use one byte and everything else uses five, so 127 and 128
/// bracket the only shape change in the prefix. The two rejections below sit on
/// the same boundary: a short length written in the long form is
/// `NonCanonical`, and a length past [`MAX_STATE_KEY_LEN`] is `LimitExceeded`
/// before any content byte is read.
fn bench_length_prefix(suite: &mut Suite) {
    let mut buffer = Vec::with_capacity(5);
    suite.bench("length_prefix/encode/short_form_127", || {
        buffer.clear();
        encode_length(127, &mut buffer);
        buffer.len()
    });
    suite.bench("length_prefix/encode/long_form_128", || {
        buffer.clear();
        encode_length(128, &mut buffer);
        buffer.len()
    });

    let short = StateKey(vec![0xAA; 127]).to_bytes();
    let long = StateKey(vec![0xAA; 128]).to_bytes();
    suite.bench("state_key/decode/short_prefix_127B", || {
        StateKey::decode(&short)
    });
    suite.bench("state_key/decode/long_prefix_128B", || {
        StateKey::decode(&long)
    });

    let mut overlong = vec![0x80, 127, 0, 0, 0];
    overlong.extend_from_slice(&[0xAA; 127]);
    let over_limit = {
        let mut bytes = vec![0x80];
        let length = u32::try_from(MAX_STATE_KEY_LEN + 1).unwrap_or(u32::MAX);
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes
    };
    suite.bench("state_key/decode/reject_overlong_prefix", || {
        StateKey::decode(&overlong)
    });
    suite.bench("state_key/decode/reject_over_limit", || {
        StateKey::decode(&over_limit)
    });
}

/// Records transaction encode and strict decode across both size sweeps.
///
/// Each sweep varies one dimension and holds the other at zero, so reported
/// growth is attributable to the swept dimension alone.
fn bench_transaction_sizes(suite: &mut Suite) {
    for entries in ACCESS_LIST_SIZES {
        let fixture = transaction(entries, 0);
        let encoded = fixture.to_bytes();
        suite.bench(format!("transaction/encode/access_list_{entries}"), || {
            fixture.to_bytes()
        });
        suite.bench(format!("transaction/decode/access_list_{entries}"), || {
            Transaction::decode(&encoded)
        });
    }

    for payload in PAYLOAD_SIZES {
        let fixture = transaction(0, payload);
        let encoded = fixture.to_bytes();
        suite.bench(format!("transaction/encode/payload_{payload}B"), || {
            fixture.to_bytes()
        });
        suite.bench(format!("transaction/decode/payload_{payload}B"), || {
            Transaction::decode(&encoded)
        });
    }

    // One fixture encoded two ways. `to_bytes` allocates and grows a fresh
    // buffer per call; the reused buffer is already large enough, so the pair
    // separates allocation and growth from the canonical write itself.
    let fixture = transaction(SHARED_ENTRIES, SHARED_PAYLOAD);
    let mut buffer = Vec::with_capacity(fixture.to_bytes().len());
    suite.bench(
        format!("transaction/encode/to_bytes_{SHARED_ENTRIES}keys_{SHARED_PAYLOAD}B"),
        || fixture.to_bytes(),
    );
    suite.bench(
        format!("transaction/encode/reused_buffer_{SHARED_ENTRIES}keys_{SHARED_PAYLOAD}B"),
        || {
            buffer.clear();
            fixture.encode(&mut buffer);
            buffer.len()
        },
    );
}

/// Records the accepted transaction beside each malformed input the codec rejects.
///
/// Every malformed fixture is one minimal mutation of the accepted encoding, so
/// the position at which decoding stops is visible from the construction:
/// `reject_bad_magic`, `reject_bad_version` and `reject_oversized_access_count`
/// stop within the first 66 bytes, while `reject_truncated_signature` and
/// `reject_trailing_byte` stop only after the whole envelope has been walked.
fn bench_rejections(suite: &mut Suite) {
    let accepted = transaction(SHARED_ENTRIES, SHARED_PAYLOAD).to_bytes();

    let mut bad_magic = accepted.clone();
    bad_magic[0] ^= 1;

    let mut bad_version = accepted.clone();
    bad_version[4] = 2;

    let mut bad_lane = accepted.clone();
    bad_lane[LANE_OFFSET] = 3;

    let mut truncated = accepted.clone();
    truncated.truncate(accepted.len() - 1);

    let mut trailing = accepted.clone();
    trailing.push(0);

    let mut oversized = accepted[..=LANE_OFFSET].to_vec();
    encode_length(MAX_LIST_LEN + 1, &mut oversized);

    suite.bench("transaction/decode/accept", || {
        Transaction::decode(&accepted)
    });
    suite.bench("transaction/decode/reject_bad_magic", || {
        Transaction::decode(&bad_magic)
    });
    suite.bench("transaction/decode/reject_bad_version", || {
        Transaction::decode(&bad_version)
    });
    suite.bench("transaction/decode/reject_bad_lane", || {
        Transaction::decode(&bad_lane)
    });
    suite.bench("transaction/decode/reject_oversized_access_count", || {
        Transaction::decode(&oversized)
    });
    suite.bench("transaction/decode/reject_truncated_signature", || {
        Transaction::decode(&truncated)
    });
    suite.bench("transaction/decode/reject_trailing_byte", || {
        Transaction::decode(&trailing)
    });
}

fn main() {
    let mut suite = Suite::new("codec");
    bench_primitives(&mut suite);
    bench_protocol_types(&mut suite);
    bench_length_prefix(&mut suite);
    bench_transaction_sizes(&mut suite);
    bench_rejections(&mut suite);
    suite.report();
}
