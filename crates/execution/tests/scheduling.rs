// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Wave dependencies and equivalence to block-order writes.

use std::collections::BTreeMap;

use execution::{ExecutionScheduler, GreedyScheduler, SerialScheduler};
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
