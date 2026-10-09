// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Measures serial and bounded-parallel payment and contract execution.
//!
//! These figures describe one machine and one toolchain. They are not a
//! correctness gate. The serial path is the reference the parallel path must
//! reproduce exactly, and that equivalence is established by the differential
//! tests in `crates/execution`, not here. A worker count that measures faster
//! is not more correct, and a slower one is not wrong: worker count never
//! enters a protocol commitment, so no figure below licenses changing it.
//!
//! Every benchmarked operation is repeatable without a per-iteration reset.
//! `ReplayState` performs the real staging and root computation of a commit and
//! then discards the new version, so the parent root is unchanged when the
//! closure is called again and the second call does exactly the work of the
//! first. Sessions are rebuilt inside each closure, which is a few empty maps
//! and is included in every figure. Nothing is committed, so the benchmarks
//! that measure a rejected batch measure it identically on every iteration.
//!
//! The batches are shaped deliberately, because wave shape decides what
//! parallel execution can do: `independent` declares no key twice and plans as
//! one wide wave, `dependent_chain` shares a sender and plans as one singleton
//! wave per transaction, and the shaped batches alternate. A figure for one
//! shape says nothing about another.
//!
//! What this does NOT establish: block, node or network throughput for any
//! deployment, the behaviour of a disk-backed `StateDatabase` (the fixtures use
//! `InMemoryState`, whose `prefetch` is a no-op and whose reads never touch
//! storage), a figure comparable to another machine or core count, statistical
//! significance of any difference between two measurements, or any bound under
//! contention from other processes.

use codec::CanonicalEncode;
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use execution::{
    ExecutionError, ExecutionScheduler, GreedyScheduler, PAYMENT_PRICES, PaymentSession,
    SerialScheduler, SignedSession, execute_payments, execute_payments_parallel, execute_signed,
    execute_signed_parallel, payment_resources,
};
use state::{InMemoryState, StateDatabase, StateDiff, StateError, StateSnapshot, account_key};
use testkit::bench::Suite;
use transaction::{
    ContractAction, ContractPayload, Payment, ValidationContext, address_from_public_key,
    contract_address, contract_code_key, contract_state_key, signing_hash,
};
use types::{AccountState, Address, Hash256, Resources, StateKey, Transaction, TransactionLane};

/// Chain identifier every benchmark transaction is signed for.
const CHAIN_ID: u32 = 7;

/// Transaction counts for the payment sweeps.
const PAYMENT_COUNTS: [usize; 3] = [8, 32, 128];

/// Transaction counts for the contract sweeps.
///
/// Contract calls cost orders of magnitude more than transfers, so the counts
/// stay small to keep a round bounded.
const CONTRACT_COUNTS: [usize; 2] = [4, 16];

/// Worker counts measured at each transaction count.
///
/// One worker is the serial reference path. The sweep deliberately runs past
/// the eight logical processors of the measuring machine, because requesting
/// more workers than cores is permitted and its cost should be recorded.
const WORKER_COUNTS: [usize; 5] = [1, 2, 4, 8, 16];

/// Worker counts for the pool-creation floor.
///
/// One worker takes the serial path and builds no pool, so the floor sweep
/// starts at two.
const POOL_WORKERS: [usize; 4] = [2, 4, 8, 16];

/// Accounts funded in the parent state, and the first recipient index.
///
/// Senders are drawn from below this bound and fresh recipients from above it,
/// so a sender set and a recipient set never share an account key.
const SENDERS: usize = 128;

/// Contract modules installed in the parent state.
const CONTRACTS: usize = 16;

/// Balance funded for every sender, large enough that no batch runs it down.
const BALANCE: u64 = 1_000_000_000;

/// Validation context shared by every benchmark batch.
const CONTEXT: ValidationContext = ValidationContext {
    chain_id: CHAIN_ID,
    next_height: 1,
    max_transaction_bytes: 1 << 20,
};

/// Block capacity large enough that no benchmark batch is capacity bound.
///
/// Capacity is authenticated by the caller in production. Here it only has to
/// stay out of the way, so that a measurement is not silently a rejection.
const CAPACITY: Resources = Resources {
    compute: 1 << 40,
    memory: 1 << 40,
    io: 1 << 40,
    bandwidth: 1 << 40,
};

/// Declared limit for one contract call.
///
/// The limit must cover the executor's own overhead as well as the call, since
/// the call budget is the declared limit minus that overhead.
const CONTRACT_LIMIT: Resources = Resources {
    compute: 10_000,
    memory: 65_568,
    io: 1 << 20,
    bandwidth: 4_096,
};

/// A database that performs a real commit but never advances.
///
/// `InMemoryState::prepare` does exactly the staging and root computation that
/// `InMemoryState::commit` does, then returns the new version instead of
/// installing it. A benchmark therefore pays the full commit cost on every
/// iteration while the parent root stays constant, so each call does the work
/// of the first and no closure needs a reset.
struct ReplayState {
    /// The immutable parent every iteration executes against.
    inner: InMemoryState,
}

impl StateDatabase for ReplayState {
    fn snapshot(&self) -> Result<Box<dyn StateSnapshot>, StateError> {
        self.inner.snapshot()
    }

    fn prefetch(&self, keys: &[StateKey]) -> Result<(), StateError> {
        self.inner.prefetch(keys)
    }

    fn commit(&mut self, parent: Hash256, diffs: &[StateDiff]) -> Result<Hash256, StateError> {
        let staged = self.inner.prepare(parent, diffs)?;
        Ok(staged.root())
    }
}

/// Deterministic signing material for one benchmark account.
struct Account {
    /// Ed25519 secret seed.
    secret: [u8; 32],
    /// Public key derived from the seed.
    public_key: [u8; 32],
    /// Address derived from the public key.
    address: Address,
}

/// Derives `count` distinct accounts from a deterministic seed sequence.
fn accounts(count: usize) -> Vec<Account> {
    (0..count)
        .map(|index| {
            let mut secret = [0u8; 32];
            // Spread the index across two bytes so counts above 256 stay distinct.
            secret[0] = u8::try_from(index % 256).unwrap_or_default();
            secret[1] = u8::try_from(index / 256).unwrap_or_default();
            secret[31] = 1; // keep every seed non-zero
            let public_key = ed25519_public_key(&secret);
            Account {
                secret,
                public_key,
                address: address_from_public_key(&public_key),
            }
        })
        .collect()
}

/// Signs `transaction` with `secret` over its canonical signing hash.
fn sign(secret: &[u8; 32], mut transaction: Transaction) -> Transaction {
    transaction.signature = ed25519_sign(secret, signing_hash(&transaction).as_bytes());
    transaction
}

/// Builds one signed transfer between two benchmark accounts.
fn transfer(
    pool: &[Account],
    sender: usize,
    recipient: usize,
    nonce: u64,
    amount: u64,
) -> Transaction {
    let mut keys = vec![
        account_key(pool[sender].address),
        account_key(pool[recipient].address),
    ];
    keys.sort();
    keys.dedup();
    let mut transaction = Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: TransactionLane::Payments,
        resource_prices: PAYMENT_PRICES,
        chain_id: CHAIN_ID,
        sender: pool[sender].address,
        nonce,
        access_list: keys,
        resource_limit: Resources::ZERO,
        payload: Payment {
            public_key: pool[sender].public_key,
            recipient: pool[recipient].address,
            amount,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    // The declared limit is the deterministic version-1 usage, which depends on
    // the canonical byte count and so is computed from the unsigned envelope.
    transaction.resource_limit =
        payment_resources(&transaction).expect("payment resources are bounded");
    sign(&pool[sender].secret, transaction)
}

/// Builds `count` transfers that declare no key in common.
///
/// The planner places all of them in one wave, which is the shape bounded
/// parallel execution exists for and the upper bound on what it can achieve.
fn independent(pool: &[Account], count: usize) -> Vec<Transaction> {
    (0..count)
        .map(|index| transfer(pool, index, SENDERS + index, 0, 1))
        .collect()
}

/// Builds `count` transfers from one sender, which the planner must serialize.
///
/// Transactions from one sender stay ordered for nonce and balance effects, so
/// each lands in its own wave. The parallel path creates no workers for this
/// shape and fuses the whole chain into one sequential session.
fn dependent_chain(pool: &[Account], count: usize) -> Vec<Transaction> {
    (0..count)
        .map(|index| {
            let nonce = u64::try_from(index).expect("benchmark batch fits in u64");
            transfer(pool, 0, SENDERS + index, nonce, 1)
        })
        .collect()
}

/// One transfer in a shaped batch: sender, recipient, amount, and whether it
/// declares the whole shaped account set.
type Shaped = (usize, usize, u64, bool);

/// Repeats `round` `rounds` times with rising per-sender nonces.
///
/// A flagged transaction declares every account in `1..=width`, so the planner
/// can place it only after all of its predecessors and it forms a singleton
/// wave. Re-declaring changes the canonical byte count, so the limit is
/// recomputed and the envelope re-signed.
fn shaped(pool: &[Account], round: &[Shaped], rounds: usize, width: usize) -> Vec<Transaction> {
    let mut nonces = vec![0u64; width + 1];
    let mut batch = Vec::new();
    for _ in 0..rounds {
        for &(sender, recipient, amount, barrier) in round {
            let nonce = nonces[sender];
            nonces[sender] += 1;
            let mut transaction = transfer(pool, sender, recipient, nonce, amount);
            if barrier {
                transaction.access_list = (1..=width)
                    .map(|index| account_key(pool[index].address))
                    .collect();
                transaction.access_list.sort();
                transaction.resource_limit =
                    payment_resources(&transaction).expect("payment resources are bounded");
                transaction = sign(&pool[sender].secret, transaction);
            }
            batch.push(transaction);
        }
    }
    batch
}

/// Builds a batch whose wave widths change from round to round.
///
/// Four independent transfers create balances, the same accounts spend them
/// back, two bridges join the lanes, and a barrier closes the round. This
/// mirrors the shape the crate's differential payment tests use.
fn changing_width(pool: &[Account]) -> Vec<Transaction> {
    const ROUND: [Shaped; 11] = [
        (1, 5, 20, false),
        (2, 6, 20, false),
        (3, 7, 20, false),
        (4, 8, 20, false),
        (5, 1, 5, false),
        (6, 2, 5, false),
        (7, 3, 5, false),
        (8, 4, 5, false),
        (1, 2, 2, false),
        (3, 4, 2, false),
        (2, 3, 1, true),
    ];
    shaped(pool, &ROUND, 4, 8)
}

/// Builds a batch containing runs of three consecutive singleton waves.
///
/// Three barriers in a row are what wave fusion exists for: they execute in one
/// sequential session instead of one session and one overlay publication each.
fn consecutive_singletons(pool: &[Account]) -> Vec<Transaction> {
    const ROUND: [Shaped; 14] = [
        (1, 5, 20, false),
        (2, 6, 20, false),
        (3, 7, 20, false),
        (4, 8, 20, false),
        (5, 9, 12, true),
        (9, 10, 8, true),
        (10, 5, 4, true),
        (5, 1, 5, false),
        (6, 2, 5, false),
        (7, 3, 5, false),
        (8, 4, 5, false),
        (1, 2, 2, false),
        (3, 4, 2, false),
        (2, 3, 1, true),
    ];
    shaped(pool, &ROUND, 3, 10)
}

/// Returns `batch` with the final signature corrupted.
///
/// A trailing failure makes the speculative pass and the serial replay each do
/// the whole batch's work before the canonical error appears, so the measured
/// difference against serial-only is the replay penalty and not an early exit.
fn corrupted(batch: &[Transaction]) -> Vec<Transaction> {
    let mut batch = batch.to_vec();
    if let Some(last) = batch.last_mut() {
        last.signature[0] ^= 1;
    }
    batch
}

/// Builds the ABI-v2 benchmark contract.
///
/// The module copies one input byte into a declared contract-local key and
/// returns it, so a call exercises the input, state and output host helpers
/// without depending on a compiler toolchain.
fn contract_code() -> Vec<u8> {
    wat::parse_str(
        r#"(module
        (import "astrolune_v2" "input_copy" (func $input (param i32 i32 i32) (result i32)))
        (import "astrolune_v2" "state_put" (func $put (param i32 i32 i32 i32) (result i32)))
        (import "astrolune_v2" "output" (func $output (param i32 i32) (result i32)))
        (memory (export "memory") 1 1) (data (i32.const 0) "k")
        (func (export "call") (result i32)
          (drop (call $input (i32.const 0) (i32.const 16) (i32.const 1)))
          (drop (call $put (i32.const 0) (i32.const 1) (i32.const 16) (i32.const 1)))
          (drop (call $output (i32.const 16) (i32.const 1))) (i32.const 0)))"#,
    )
    .expect("benchmark contract text is well formed")
}

/// Returns the deterministic address of the contract attributed to `index`.
fn installed(pool: &[Account], index: usize) -> Address {
    contract_address(CHAIN_ID, pool[index].address, 0)
}

/// Builds one signed call declaring one contract-local key.
fn contract_call(pool: &[Account], sender: usize, target: Address, input: u8) -> Transaction {
    let mut keys = vec![
        account_key(pool[sender].address),
        contract_code_key(target),
        contract_state_key(target, b"k"),
    ];
    keys.sort();
    keys.dedup();
    sign(
        &pool[sender].secret,
        Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: TransactionLane::Contracts,
            resource_prices: PAYMENT_PRICES,
            chain_id: CHAIN_ID,
            sender: pool[sender].address,
            nonce: 0,
            access_list: keys,
            resource_limit: CONTRACT_LIMIT,
            payload: ContractPayload {
                public_key: pool[sender].public_key,
                action: ContractAction::Call {
                    address: target,
                    input: vec![input],
                    keys: vec![b"k".to_vec()],
                },
            }
            .to_bytes(),
            signature: [0; 64],
        },
    )
}

/// Builds `count` calls, each to its own contract, declaring no key twice.
fn independent_calls(pool: &[Account], count: usize) -> Vec<Transaction> {
    (0..count)
        .map(|index| contract_call(pool, index, installed(pool, index), 1))
        .collect()
}

/// Builds `count` calls from distinct senders to one shared contract.
///
/// Every call declares the shared code key, which the planner treats as a
/// write, so a hot contract plans as one singleton wave per call however many
/// workers are available.
fn shared_calls(pool: &[Account], count: usize) -> Vec<Transaction> {
    let target = installed(pool, 0);
    (0..count)
        .map(|index| contract_call(pool, index, target, 1))
        .collect()
}

/// Builds `count` contract calls interleaved with `count` transfers.
fn mixed_lanes(pool: &[Account], count: usize) -> Vec<Transaction> {
    (0..count)
        .flat_map(|index| {
            [
                contract_call(pool, index, installed(pool, index), 1),
                transfer(pool, count + index, SENDERS + index, 0, 1),
            ]
        })
        .collect()
}

/// Builds the parent state: funded senders and pre-installed contract code.
///
/// Code is written straight into the parent instead of being deployed by a
/// transaction, so a call benchmark measures calls and not deployments.
fn parent(pool: &[Account]) -> InMemoryState {
    let mut state = InMemoryState::new();
    let mut diff = StateDiff::new();
    for account in pool.iter().take(SENDERS) {
        diff.put(
            account_key(account.address),
            AccountState {
                nonce: 0,
                balance: BALANCE,
            }
            .to_bytes(),
        );
    }
    let code = contract_code();
    for index in 0..CONTRACTS {
        diff.put(contract_code_key(installed(pool, index)), code.clone());
    }
    state
        .commit(state.root(), &[diff])
        .expect("parent state commits");
    state
}

/// Validates and executes `batch` against one parent, with no hint and no commit.
///
/// This is the floor for payments: revalidation and execution only. The gap to
/// `execute_payments` is the one advisory prefetch hint plus the commit stage.
fn payment_session(
    snapshot: &dyn StateSnapshot,
    batch: &[Transaction],
) -> Result<usize, ExecutionError> {
    let mut session = PaymentSession::new(snapshot, CONTEXT, CAPACITY);
    let mut changes = 0;
    for transaction in batch {
        changes += session.execute(transaction)?.diff.len();
    }
    Ok(changes)
}

/// Executes `batch` serially with a real commit but no advisory prefetch hint.
fn payments_without_hint(
    database: &mut ReplayState,
    batch: &[Transaction],
    root: Hash256,
) -> Result<Hash256, ExecutionError> {
    let snapshot = database.snapshot()?;
    let mut session = PaymentSession::new(snapshot.as_ref(), CONTEXT, CAPACITY);
    let diffs = batch
        .iter()
        .map(|transaction| session.execute(transaction).map(|output| output.diff))
        .collect::<Result<Vec<_>, ExecutionError>>()?;
    Ok(database.commit(root, &diffs)?)
}

/// Executes `batch` serially without the execution-parent read cache.
///
/// `execute_signed` wraps the parent in a read-through cache shared across
/// calls and waves; a direct `SignedSession` caller keeps the snapshot it
/// supplied. The two are otherwise the same path, so the pair isolates the
/// cache, except that `execute_signed` also offers the one prefetch hint.
fn signed_without_cache(
    database: &mut ReplayState,
    batch: &[Transaction],
    root: Hash256,
) -> Result<Hash256, ExecutionError> {
    let snapshot = database.snapshot()?;
    let mut session = SignedSession::new(snapshot.as_ref(), CONTEXT, CAPACITY, true);
    let diffs = batch
        .iter()
        .map(|transaction| session.execute(transaction).map(|output| output.diff))
        .collect::<Result<Vec<_>, ExecutionError>>()?;
    Ok(database.commit(root, &diffs)?)
}

/// Describes a batch by transaction count and planned wave count.
///
/// The shape is recorded in the benchmark name because it, and not the worker
/// count, decides how much of a batch can run concurrently.
fn shape(batch: &[Transaction]) -> String {
    let waves = GreedyScheduler.plan(batch).waves.len();
    format!("{}tx_{waves}w", batch.len())
}

/// Measures wave planning and lease construction.
fn bench_planner(suite: &mut Suite, pool: &[Account]) {
    for count in PAYMENT_COUNTS {
        let wide = independent(pool, count);
        let chain = dependent_chain(pool, count);
        suite.bench(format!("plan/greedy/independent/{count}"), || {
            GreedyScheduler.plan(&wide)
        });
        suite.bench(format!("plan/greedy/dependent_chain/{count}"), || {
            GreedyScheduler.plan(&chain)
        });
        suite.bench(format!("plan/serial/{count}"), || {
            SerialScheduler.plan(&wide)
        });
    }
    let wide = independent(pool, 1);
    suite.bench("lease/greedy/one_transaction", || {
        GreedyScheduler.lease(&wide[0])
    });
}

/// Measures the serial reference and the worker sweep on one-wave batches.
///
/// `session` is execution alone, `serial_no_hint` adds the commit stage, and
/// `serial` is the public entry point, which additionally offers the prefetch
/// hint. `w1` is the same serial path reached through the parallel entry point.
fn bench_independent(suite: &mut Suite, pool: &[Account], database: &mut ReplayState) {
    let root = database.inner.root();
    for count in PAYMENT_COUNTS {
        let batch = independent(pool, count);
        let snapshot = database.snapshot().expect("parent snapshot");
        suite.bench(format!("payments/independent/{count}/session"), || {
            payment_session(snapshot.as_ref(), &batch)
        });
        drop(snapshot);
        suite.bench(
            format!("payments/independent/{count}/serial_no_hint"),
            || payments_without_hint(database, &batch, root),
        );
        suite.bench(format!("payments/independent/{count}/serial"), || {
            execute_payments(database, &batch, root, CONTEXT, CAPACITY)
        });
        for workers in WORKER_COUNTS {
            suite.bench(format!("payments/independent/{count}/w{workers}"), || {
                execute_payments_parallel(database, &batch, root, CONTEXT, CAPACITY, workers)
            });
        }
    }
}

/// Measures the fixed cost of one per-block worker pool.
///
/// Each batch carries exactly one transaction per requested worker, so the work
/// a worker performs is held constant while the pool grows. The `w1` figure is
/// the same batch through the same entry point on the serial path, which builds
/// no pool, so the gap is pool creation and wave coordination and not execution.
fn bench_pool_floor(suite: &mut Suite, pool: &[Account], database: &mut ReplayState) {
    let root = database.inner.root();
    for workers in POOL_WORKERS {
        let batch = independent(pool, workers);
        suite.bench(format!("payments/pool_floor/{workers}tx/w1"), || {
            execute_payments_parallel(database, &batch, root, CONTEXT, CAPACITY, 1)
        });
        suite.bench(
            format!("payments/pool_floor/{workers}tx/w{workers}"),
            || execute_payments_parallel(database, &batch, root, CONTEXT, CAPACITY, workers),
        );
    }
}

/// Measures the shapes the planner cannot widen or can only partly widen.
fn bench_shapes(suite: &mut Suite, pool: &[Account], database: &mut ReplayState) {
    let root = database.inner.root();
    for count in [PAYMENT_COUNTS[1], PAYMENT_COUNTS[2]] {
        let batch = dependent_chain(pool, count);
        let plan = shape(&batch);
        suite.bench(format!("payments/chain/{plan}/serial"), || {
            execute_payments(database, &batch, root, CONTEXT, CAPACITY)
        });
        for workers in [1, 8] {
            suite.bench(format!("payments/chain/{plan}/w{workers}"), || {
                execute_payments_parallel(database, &batch, root, CONTEXT, CAPACITY, workers)
            });
        }
    }
    for batch in [changing_width(pool), consecutive_singletons(pool)] {
        let plan = shape(&batch);
        suite.bench(format!("payments/shaped/{plan}/serial"), || {
            execute_payments(database, &batch, root, CONTEXT, CAPACITY)
        });
        for workers in WORKER_COUNTS {
            suite.bench(format!("payments/shaped/{plan}/w{workers}"), || {
                execute_payments_parallel(database, &batch, root, CONTEXT, CAPACITY, workers)
            });
        }
    }
}

/// Measures the cost of a rejected batch on both paths.
///
/// The parallel figure includes a complete speculative pass that is discarded
/// and a complete serial replay; the serial figure is the replay alone.
fn bench_replay(suite: &mut Suite, pool: &[Account], database: &mut ReplayState) {
    let root = database.inner.root();
    for count in [PAYMENT_COUNTS[1], PAYMENT_COUNTS[2]] {
        let batch = corrupted(&independent(pool, count));
        suite.bench(format!("payments/rejected/{count}/serial"), || {
            execute_payments(database, &batch, root, CONTEXT, CAPACITY)
        });
        for workers in [4, 8] {
            suite.bench(format!("payments/rejected/{count}/w{workers}"), || {
                execute_payments_parallel(database, &batch, root, CONTEXT, CAPACITY, workers)
            });
        }
    }
}

/// Measures contract waves, the parent read cache, and mixed-lane batches.
fn bench_contracts(suite: &mut Suite, pool: &[Account], database: &mut ReplayState) {
    let root = database.inner.root();
    for count in CONTRACT_COUNTS {
        let batch = independent_calls(pool, count);
        let plan = shape(&batch);
        suite.bench(format!("contracts/independent/{plan}/uncached"), || {
            signed_without_cache(database, &batch, root)
        });
        suite.bench(format!("contracts/independent/{plan}/serial"), || {
            execute_signed(database, &batch, root, CONTEXT, CAPACITY)
        });
        for workers in WORKER_COUNTS {
            suite.bench(format!("contracts/independent/{plan}/w{workers}"), || {
                execute_signed_parallel(database, &batch, root, CONTEXT, CAPACITY, workers)
            });
        }

        let batch = shared_calls(pool, count);
        let plan = shape(&batch);
        suite.bench(format!("contracts/shared_code/{plan}/uncached"), || {
            signed_without_cache(database, &batch, root)
        });
        suite.bench(format!("contracts/shared_code/{plan}/serial"), || {
            execute_signed(database, &batch, root, CONTEXT, CAPACITY)
        });
        for workers in [1, 8] {
            suite.bench(format!("contracts/shared_code/{plan}/w{workers}"), || {
                execute_signed_parallel(database, &batch, root, CONTEXT, CAPACITY, workers)
            });
        }

        let batch = mixed_lanes(pool, count);
        let plan = shape(&batch);
        suite.bench(format!("contracts/mixed_lanes/{plan}/serial"), || {
            execute_signed(database, &batch, root, CONTEXT, CAPACITY)
        });
        for workers in WORKER_COUNTS {
            suite.bench(format!("contracts/mixed_lanes/{plan}/w{workers}"), || {
                execute_signed_parallel(database, &batch, root, CONTEXT, CAPACITY, workers)
            });
        }
    }
}

fn main() {
    let mut suite = Suite::new("execution");
    let pool = accounts(SENDERS + SENDERS);
    let mut database = ReplayState {
        inner: parent(&pool),
    };
    bench_planner(&mut suite, &pool);
    bench_independent(&mut suite, &pool, &mut database);
    bench_pool_floor(&mut suite, &pool, &mut database);
    bench_shapes(&mut suite, &pool, &mut database);
    bench_replay(&mut suite, &pool, &mut database);
    bench_contracts(&mut suite, &pool, &mut database);
    suite.report();
}
