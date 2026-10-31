// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Wave dependencies and equivalence to block-order writes.

use std::collections::BTreeMap;

use execution::{ExecutionScheduler, GreedyScheduler, SerialScheduler};
use state::{AccessMode, AccessRequest, StateLease};
use transaction::{ContractAction, ContractPayload, contract_code_key, trocto_contract_code_key};
use types::{Address, Resources, StateKey, Transaction};

fn transaction(sender: u8, keys: &[u8]) -> Transaction {
    Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: types::Resources {
            compute: 1,
            ..types::Resources::ZERO
        },
        chain_id: 7,
        sender: Address([sender; 32]),
        nonce: 0,
        access_list: keys.iter().map(|key| StateKey(vec![*key])).collect(),
        resource_limit: Resources::ZERO,
        payload: Vec::new(),
        signature: [0; 64],
    }
}

fn contract_call(sender: u8, code: u8, keys: &[u8]) -> (Transaction, StateLease) {
    let target = Address([code; 32]);
    let code_key = contract_code_key(target);
    let mut tx = transaction(sender, keys);
    tx.lane = types::TransactionLane::Contracts;
    tx.access_list.push(code_key.clone());
    tx.payload = ContractPayload {
        public_key: [sender; 32],
        action: ContractAction::Call {
            address: target,
            input: Vec::new(),
            keys: Vec::new(),
        },
    }
    .to_bytes();
    let lease = StateLease::new(tx.access_list.iter().map(|key| AccessRequest {
        key: key.clone(),
        mode: if key == &code_key {
            AccessMode::Read
        } else {
            AccessMode::Write
        },
    }));
    (tx, lease)
}

#[test]
fn only_a_canonical_call_can_share_its_exact_code_key() {
    let (call, expected) = contract_call(1, 9, &[1]);
    assert_eq!(GreedyScheduler.lease(&call), expected);
    let mut duplicated = call.clone();
    duplicated.access_list.reverse();
    duplicated
        .access_list
        .extend(call.access_list.iter().cloned());
    assert_eq!(GreedyScheduler.lease(&duplicated), expected);

    let mut foreign_code = call.clone();
    let extra = contract_code_key(Address([8; 32]));
    foreign_code.access_list.push(extra.clone());
    assert!(
        GreedyScheduler
            .lease(&foreign_code)
            .covers(&extra, AccessMode::Write)
    );

    for mutation in 0..5 {
        let mut malformed = call.clone();
        match mutation {
            0 => {
                malformed.payload.pop();
            }
            1 => malformed.payload.push(0),
            2 => malformed.payload[0] ^= 1,
            3 => malformed.payload[41..73].fill(0),
            _ => malformed.lane = types::TransactionLane::Payments,
        }
        assert_eq!(
            GreedyScheduler.lease(&malformed),
            SerialScheduler.lease(&malformed)
        );
    }
    let mut deploy = call;
    deploy.payload = ContractPayload {
        public_key: [1; 32],
        action: ContractAction::Deploy(vec![0; 100_000]),
    }
    .to_bytes();
    assert_eq!(
        GreedyScheduler.lease(&deploy),
        SerialScheduler.lease(&deploy)
    );
}

#[test]
fn a_writer_waits_for_the_highest_prior_reader_wave() {
    let writer_a = transaction(1, &[1]);
    let (reader_after_a, _) = contract_call(2, 9, &[1]);
    let (independent_reader, _) = contract_call(3, 9, &[2]);
    let mut writer_code = transaction(4, &[]);
    writer_code.access_list = vec![contract_code_key(Address([9; 32]))];
    let (reader_after_writer, _) = contract_call(5, 9, &[3]);
    let plan = GreedyScheduler.plan(&[
        writer_a,
        reader_after_a,
        independent_reader,
        writer_code,
        reader_after_writer,
    ]);
    assert_eq!(
        plan.waves
            .iter()
            .map(|wave| &wave.transaction_indexes)
            .collect::<Vec<_>>(),
        vec![&vec![0, 2], &vec![1], &vec![3], &vec![4]]
    );
}

#[test]
fn native_calls_share_only_the_native_immutable_code_key() {
    let target = Address([9; 32]);
    let native = trocto_contract_code_key(target);
    let historical = contract_code_key(target);
    let calls: Vec<_> = [1, 2]
        .into_iter()
        .map(|sender| {
            let mut tx = transaction(sender, &[sender]);
            tx.lane = types::TransactionLane::Contracts;
            tx.access_list.push(native.clone());
            tx.payload = ContractPayload {
                public_key: [sender; 32],
                action: ContractAction::CallTrocto {
                    address: target,
                    input: vec![0; 8],
                    keys: vec![],
                },
            }
            .to_bytes();
            tx
        })
        .collect();
    assert_eq!(
        GreedyScheduler.plan(&calls).waves[0].transaction_indexes,
        vec![0, 1]
    );
    assert!(
        GreedyScheduler
            .lease(&calls[0])
            .covers(&native, AccessMode::Read)
    );
    let mut foreign = calls[0].clone();
    foreign.access_list.push(historical.clone());
    assert!(
        GreedyScheduler
            .lease(&foreign)
            .covers(&historical, AccessMode::Write)
    );
    let mut malformed = calls[0].clone();
    malformed.payload.push(0);
    assert!(
        GreedyScheduler
            .lease(&malformed)
            .covers(&native, AccessMode::Write)
    );
    let mut deploy = calls[0].clone();
    deploy.payload = ContractPayload {
        public_key: [1; 32],
        action: ContractAction::DeployTrocto(b"fn call(input: u64) -> u64 { input }".to_vec()),
    }
    .to_bytes();
    assert!(
        GreedyScheduler
            .lease(&deploy)
            .covers(&native, AccessMode::Write)
    );
}

#[test]
fn generated_read_write_plans_match_an_independent_pairwise_oracle() {
    for seed in 0u64..512 {
        let mut random = seed;
        let mut next = || {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (random >> 32) as usize
        };
        let entries: Vec<_> = (0..seed % 33)
            .map(|_| {
                let sender = u8::try_from(next() % 5 + 1).unwrap();
                let code = u8::try_from(next() % 3 + 10).unwrap();
                let key = u8::try_from(next() % 4).unwrap();
                if next() % 3 == 0 {
                    let mut tx = transaction(sender, &[key]);
                    tx.access_list.push(contract_code_key(Address([code; 32])));
                    let expected = SerialScheduler.lease(&tx);
                    (tx, expected)
                } else {
                    contract_call(sender, code, &[key])
                }
            })
            .collect();
        let transactions: Vec<_> = entries.iter().map(|(tx, _)| tx.clone()).collect();
        let mut positions: Vec<usize> = Vec::new();
        for (index, (tx, expected)) in entries.iter().enumerate() {
            assert_eq!(GreedyScheduler.lease(tx), *expected);
            let wave = entries[..index]
                .iter()
                .enumerate()
                .filter(|(_, (earlier, lease))| {
                    earlier.sender == tx.sender || lease.conflicts_with(expected)
                })
                .map(|(index, _)| positions[index] + 1)
                .max()
                .unwrap_or(0);
            positions.push(wave);
        }
        let plan = GreedyScheduler.plan(&transactions);
        let mut actual = vec![usize::MAX; transactions.len()];
        for (wave, group) in plan.waves.iter().enumerate() {
            for &index in &group.transaction_indexes {
                assert_eq!(
                    actual[index],
                    usize::MAX,
                    "duplicate transaction, seed {seed}"
                );
                actual[index] = wave;
            }
        }
        assert_eq!(actual, positions, "seed {seed}");
    }
}

#[test]
fn independent_transactions_share_a_wave() {
    let transactions = [
        transaction(1, &[1]),
        transaction(2, &[2]),
        transaction(3, &[]),
    ];
    let plan = GreedyScheduler.plan(&transactions);
    assert_eq!(plan.waves.len(), 1);
    assert_eq!(plan.waves[0].transaction_indexes, vec![0, 1, 2]);
    assert_eq!(
        GreedyScheduler.plan(&[]).waves,
        [] as [execution::ExecutionWave; 0]
    );
}

#[test]
fn transitive_conflicts_preserve_block_order() {
    let transactions = [
        transaction(1, &[1]),
        transaction(2, &[1, 2]),
        transaction(3, &[2]),
        transaction(4, &[3]),
    ];
    let plan = GreedyScheduler.plan(&transactions);
    assert_eq!(plan.waves.len(), 3);
    assert_eq!(plan.waves[0].transaction_indexes, vec![0, 3]);
    assert_eq!(plan.waves[1].transaction_indexes, vec![1]);
    assert_eq!(plan.waves[2].transaction_indexes, vec![2]);
}

#[test]
fn same_sender_is_ordered_without_declared_conflicts() {
    let transactions = [
        transaction(1, &[]),
        transaction(1, &[1]),
        transaction(1, &[2]),
    ];
    assert_eq!(
        GreedyScheduler.plan(&transactions),
        SerialScheduler.plan(&transactions)
    );
}

#[test]
fn access_order_and_duplicates_do_not_change_the_plan() {
    let original = [transaction(1, &[1, 2]), transaction(2, &[2, 3])];
    let shuffled = [transaction(1, &[2, 1, 2, 1]), transaction(2, &[3, 2, 3])];
    assert_eq!(
        GreedyScheduler.plan(&original),
        GreedyScheduler.plan(&shuffled)
    );
    assert_eq!(
        GreedyScheduler.lease(&shuffled[0]),
        SerialScheduler.lease(&original[0])
    );
}

fn pairwise_predecessor_plan(transactions: &[Transaction]) -> execution::ExecutionPlan {
    let mut positions = Vec::new();
    let mut waves: Vec<execution::ExecutionWave> = Vec::new();
    for (index, transaction) in transactions.iter().enumerate() {
        let wave = transactions[..index]
            .iter()
            .enumerate()
            .filter(|(_, earlier)| {
                earlier.sender == transaction.sender
                    || earlier
                        .access_list
                        .iter()
                        .any(|key| transaction.access_list.contains(key))
            })
            .map(|(earlier, _)| positions[earlier] + 1)
            .max()
            .unwrap_or(0);
        positions.push(wave);
        if wave == waves.len() {
            waves.push(execution::ExecutionWave {
                transaction_indexes: Vec::new(),
            });
        }
        waves[wave].transaction_indexes.push(index);
    }
    execution::ExecutionPlan { waves }
}

#[test]
fn generated_plans_match_pairwise_predecessors_with_repeated_keys_and_senders() {
    let key_patterns: &[&[u8]] = &[
        &[],
        &[0],
        &[1],
        &[2],
        &[2, 0, 2],
        &[1, 0, 1, 0],
        &[2, 1],
        &[2, 0, 1, 2, 0],
    ];
    for seed in 0u64..256 {
        let mut state = seed;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 32) as usize
        };
        let transactions: Vec<_> = (0..seed % 33)
            .map(|_| {
                let sender = u8::try_from(next() % 8).unwrap();
                let keys = key_patterns[next() % key_patterns.len()];
                transaction(sender, keys)
            })
            .collect();
        assert_eq!(
            GreedyScheduler.plan(&transactions),
            pairwise_predecessor_plan(&transactions),
            "seed {seed}"
        );
    }
}

fn apply_writes(
    transactions: &[Transaction],
    order: impl IntoIterator<Item = usize>,
) -> BTreeMap<StateKey, usize> {
    let mut state = BTreeMap::new();
    for index in order {
        for request in GreedyScheduler.lease(&transactions[index]).requests {
            let value = state.entry(request.key).or_insert(0);
            *value = *value * 3 + index + 1;
        }
    }
    state
}

#[test]
fn generated_plans_are_complete_conflict_free_and_match_serial_writes() {
    for patterns in 0u16..512 {
        let transactions: Vec<_> = (0u8..3)
            .map(|index| {
                let mask = (patterns >> (index * 3)) & 7;
                let keys: Vec<_> = (0..3).filter(|key| mask & (1 << key) != 0).collect();
                transaction(index + 1, &keys)
            })
            .collect();
        let plan = GreedyScheduler.plan(&transactions);
        let order: Vec<_> = plan
            .waves
            .iter()
            .flat_map(|wave| wave.transaction_indexes.iter().copied())
            .collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 1, 2]);
        assert_eq!(
            apply_writes(&transactions, order),
            apply_writes(&transactions, 0..transactions.len())
        );

        let mut positions = [0; 3];
        for (wave_index, wave) in plan.waves.iter().enumerate() {
            assert!(
                wave.transaction_indexes
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            );
            for &index in &wave.transaction_indexes {
                positions[index] = wave_index;
            }
        }
        for earlier in 0..transactions.len() {
            for later in earlier + 1..transactions.len() {
                if GreedyScheduler
                    .lease(&transactions[earlier])
                    .conflicts_with(&GreedyScheduler.lease(&transactions[later]))
                {
                    assert!(positions[earlier] < positions[later]);
                }
            }
        }
    }
}

#[test]
fn readiness_dependencies_preserve_every_conflict_without_whole_wave_edges() {
    let mut slow = transaction(1, &[1]);
    slow.access_list.push(contract_code_key(Address([7; 32])));
    let fast = transaction(2, &[2]);
    let dependent = transaction(3, &[2]);
    assert_eq!(
        GreedyScheduler.dependencies(&[slow, fast, dependent]),
        vec![vec![], vec![], vec![1]]
    );
    for seed in 0u64..256 {
        let mut state = seed;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 32) as usize
        };
        let transactions: Vec<_> = (0..32)
            .map(|_| {
                let sender = u8::try_from(next() % 8).unwrap();
                let key = u8::try_from(next() % 8).unwrap();
                if next() % 3 == 0 {
                    contract_call(sender, key, &[key]).0
                } else {
                    transaction(sender, &[key])
                }
            })
            .collect();
        let dependencies = GreedyScheduler.dependencies(&transactions);
        let mut ancestry = vec![vec![false; transactions.len()]; transactions.len()];
        for (index, previous) in dependencies.iter().enumerate() {
            assert!(previous.windows(2).all(|pair| pair[0] < pair[1]));
            for &predecessor in previous {
                assert!(predecessor < index);
                ancestry[index][predecessor] = true;
                let (prior, current) = ancestry.split_at_mut(index);
                for (known, inherited) in current[0]
                    .iter_mut()
                    .zip(&prior[predecessor])
                    .take(predecessor)
                {
                    *known |= inherited;
                }
            }
            for earlier in 0..index {
                if transactions[earlier].sender == transactions[index].sender
                    || GreedyScheduler
                        .lease(&transactions[earlier])
                        .conflicts_with(&GreedyScheduler.lease(&transactions[index]))
                {
                    assert!(
                        ancestry[index][earlier],
                        "seed {seed}, {earlier} -> {index}"
                    );
                }
            }
        }
    }
}
