// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Measures append-only log publication, history reads and recovery replay.
//!
//! Every figure here touches a real filesystem. The numbers therefore include
//! operating-system page-cache effects, the cost of two `sync_all` calls per
//! published commit, and whatever the host filesystem does with a rename. They
//! say nothing about a different filesystem, a cold cache, a different storage
//! stack, or power-loss behavior, and they are not a durability claim: the
//! publication boundary is established by the failure-injection tests in
//! `crates/storage`, not by any timing recorded here.
//!
//! Two measurements are deliberately not repeatable in the strict sense and are
//! reported with that limitation stated rather than omitted:
//!
//! * `log/commit/*` appends a record per call, so the file, the height index
//!   and the recent-transaction index all grow across the sampled rounds. The
//!   closure must also build the successor block, because the log accepts only
//!   a well-formed successor, so the figure includes one extra state
//!   preparation and one header hash that a caller would already have done.
//! * `memory/commit/*` retains a checkpoint, block, certificate and snapshot
//!   handle per call. It exists only as the same work without a durable
//!   publication, to show what share of a log commit is file synchronization.
//!
//! Read and recovery figures are fully repeatable: the fixture is built once
//! outside the closure and only read back.
//!
//! What this does NOT establish: an asymptotic bound, since three log lengths
//! cannot distinguish one growth curve from another; sustained ingest rate;
//! behavior at a log size beyond these fixtures; recovery cost for a chain
//! whose blocks carry real transaction volume; or a figure comparable to a
//! different machine or filesystem.

use state::{InMemoryState, StateDiff};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use storage::{AppendOnlyStorage, Checkpoint, CommitBatch, InMemoryStorage, NodeStorage};
use testkit::bench::Suite;
use types::{Address, Block, BlockHeader, Hash256, Resources, StateKey, Transaction};

/// Log lengths swept by the history read and recovery measurements.
///
/// The lengths stay modest because each block in a fixture costs two file
/// synchronizations to publish, and the question is the shape of the curve
/// rather than a capacity figure.
const LOG_LENGTHS: [u64; 3] = [16, 64, 256];

/// Blocks committed to the fixture used for the historical-state sweep.
///
/// It exceeds [`storage::MAX_STATE_HISTORY_BLOCKS`] so the retained window is
/// full and the deepest measured read sits exactly on the availability floor.
const HISTORY_BLOCKS: u64 = 80;

/// Distances below the tip measured against the reverse-delta index.
const HISTORY_DEPTHS: [u64; 5] = [0, 1, 8, 32, 64];

/// Delta widths measured for one published commit.
const DELTA_WIDTHS: [u64; 3] = [0, 1, 64];

/// State written by each block of a generated log.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// Every block rewrites one key, so the committed state stays at one entry.
    FixedKey,
    /// Every block writes a new key, so the committed state grows with the log.
    GrowingKeys,
}

/// A unique temporary directory holding one benchmark log.
struct Fixture {
    /// Open log; released before the directory is removed.
    log: Option<AppendOnlyStorage>,
    /// Directory owned exclusively by this fixture.
    directory: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // The writer handle holds an OS lock and open files; release it first.
        self.log = None;
        // This fixture owns its unique temporary directory.
        let _ = fs::remove_dir_all(&self.directory);
    }
}

impl Fixture {
    /// Creates a directory, opens a log in it and installs a genesis anchor.
    ///
    /// # Panics
    ///
    /// Panics if the temporary directory cannot be created or the empty log
    /// cannot be published, which means nothing measurable was set up.
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "astrolune-bench-storage-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("unique benchmark directory is creatable");
        let mut fixture = Self {
            log: None,
            directory,
        };
        let mut log = AppendOnlyStorage::open(fixture.path()).expect("empty log opens");
        log.initialize_genesis(Hash256([1; 32]), InMemoryState::new())
            .expect("genesis anchor publishes");
        fixture.log = Some(log);
        fixture
    }

    /// Returns the log data file path inside this fixture.
    fn path(&self) -> PathBuf {
        self.directory.join("chain.bin")
    }

    /// Borrows the open log.
    ///
    /// # Panics
    ///
    /// Panics if the log was already closed by [`Fixture::close`].
    fn log(&self) -> &AppendOnlyStorage {
        self.log.as_ref().expect("fixture log is open")
    }

    /// Mutably borrows the open log.
    ///
    /// # Panics
    ///
    /// Panics if the log was already closed by [`Fixture::close`].
    fn log_mut(&mut self) -> &mut AppendOnlyStorage {
        self.log.as_mut().expect("fixture log is open")
    }

    /// Releases the writer lock so the directory can be reopened repeatedly.
    fn close(&mut self) {
        self.log = None;
    }

    /// Returns the published tip height.
    ///
    /// # Panics
    ///
    /// Panics if the fixture has no checkpoint, which cannot happen after
    /// [`Fixture::new`] installs its anchor.
    fn tip(&self) -> u64 {
        self.log()
            .checkpoint()
            .expect("anchored log has a tip")
            .height
    }
}

/// Returns the fixture transaction carried by the block at `height`.
///
/// The signature bytes are fixed and meaningless: storage checks the
/// transaction commitment, never a signature.
fn transaction_at(height: u64) -> Transaction {
    Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: Resources {
            compute: 1,
            ..Resources::ZERO
        },
        chain_id: 7,
        sender: Address([1; 32]),
        nonce: height,
        access_list: Vec::new(),
        resource_limit: Resources::ZERO,
        payload: height.to_le_bytes().to_vec(),
        signature: [7; 64],
    }
}

/// Returns `count` distinct state keys, reused by every commit of a fixture.
fn fixed_keys(count: u64) -> Vec<StateKey> {
    (0..count)
        .map(|index| StateKey(index.to_be_bytes().to_vec()))
        .collect()
}

/// Returns the keys written by the block at `height` under `shape`.
fn keys_for(shape: Shape, height: u64) -> Vec<StateKey> {
    match shape {
        Shape::FixedKey => fixed_keys(1),
        // Offset past the fixed-key range so the two shapes never collide.
        Shape::GrowingKeys => vec![StateKey((height + 1024).to_be_bytes().to_vec())],
    }
}

/// Returns a finalized batch extending `previous` and writing `keys`.
///
/// An empty key list produces a block with no delta at all, which is the
/// cheapest record the log will accept.
///
/// # Panics
///
/// Panics if the overlay cannot be prepared, which would mean the fixture
/// exceeded a reference state bound rather than measuring anything.
fn batch(state: &InMemoryState, previous: Option<Checkpoint>, keys: &[StateKey]) -> CommitBatch {
    let height = previous.map_or(0, |checkpoint| checkpoint.height + 1);
    let mut state_diffs = Vec::new();
    if !keys.is_empty() {
        let mut diff = StateDiff::new();
        for key in keys {
            diff.put(key.clone(), height.to_le_bytes().to_vec());
        }
        state_diffs.push(diff);
    }
    let state_root = state
        .prepare(state.root(), &state_diffs)
        .expect("bounded fixture overlay prepares")
        .root();
    let transaction = transaction_at(height);
    let transactions_root =
        crypto::compute_transactions_root(&[transaction::compute_tx_id(&transaction)]);
    CommitBatch {
        effects: None,
        block: Block {
            header: BlockHeader {
                height,
                parent: previous.map_or(Hash256::ZERO, |checkpoint| checkpoint.block),
                transactions_root,
                state_root,
                receipts_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: Resources::ZERO,
            },
            transactions: vec![transaction],
        },
        finality_certificate: vec![3; 80],
        state_diffs,
    }
}

/// Returns a fixture whose log holds a genesis anchor and `blocks` blocks.
///
/// # Panics
///
/// Panics if a generated commit is rejected, which would leave the fixture at
/// an unexpected height and invalidate every figure taken from it.
fn generated(blocks: u64, shape: Shape) -> Fixture {
    let mut fixture = Fixture::new();
    for _ in 0..blocks {
        let checkpoint = fixture.log().checkpoint().copied();
        let height = checkpoint.map_or(0, |checkpoint| checkpoint.height + 1);
        let keys = keys_for(shape, height);
        let next = batch(fixture.log().state(), checkpoint, &keys);
        fixture
            .log_mut()
            .commit(&next)
            .expect("generated fixture commit publishes");
    }
    fixture
}

/// Records one published append per delta width.
///
/// Each call appends a record and advances the chain, so the sampled rounds are
/// not independent repetitions of identical work; see the module header.
fn bench_appends(suite: &mut Suite) {
    for width in DELTA_WIDTHS {
        let keys = fixed_keys(width);
        let mut fixture = Fixture::new();
        let label = if width == 0 {
            "block_only".to_owned()
        } else {
            format!("{width}_change_delta")
        };
        suite.bench(format!("log/commit/{label}"), || {
            let checkpoint = fixture.log().checkpoint().copied();
            let next = batch(fixture.log().state(), checkpoint, &keys);
            fixture
                .log_mut()
                .commit(&next)
                .expect("log commit publishes")
        });
    }
}

/// Records the same commits against the volatile reference store.
///
/// This backend performs no file synchronization, so the gap against
/// `log/commit/*` is the durability cost rather than a storage alternative.
fn bench_memory_appends(suite: &mut Suite) {
    for width in DELTA_WIDTHS {
        let keys = fixed_keys(width);
        let mut storage = InMemoryStorage::new();
        let label = if width == 0 {
            "block_only".to_owned()
        } else {
            format!("{width}_change_delta")
        };
        suite.bench(format!("memory/commit/{label}"), || {
            let next = batch(storage.state(), storage.checkpoint().copied(), &keys);
            storage.commit(&next).expect("reference commit succeeds")
        });
    }
}

/// Records on-demand history reads and index lookups over a log-length sweep.
///
/// A finalized read seeks to an indexed offset, so the figure is expected to be
/// flat in the log length; the sweep is what makes that visible.
fn bench_reads(suite: &mut Suite) {
    for blocks in LOG_LENGTHS {
        let fixture = generated(blocks, Shape::FixedKey);
        let height = blocks / 2;
        let identifier = transaction::compute_tx_id(&transaction_at(height));
        // Opens the data file, reads one framed record, rechecks its chained
        // digest and decodes the block and certificate.
        suite.bench(format!("log/read_finalized/{blocks}"), || {
            fixture.log().read_finalized(height)
        });
        suite.bench(format!("log/transaction_location/{blocks}"), || {
            fixture.log().transaction_location(identifier)
        });
    }
}

/// Records historical state reconstruction at swept distances below the tip.
///
/// The fixture writes a distinct key per block, so a deeper read coalesces more
/// reverse changes and reconstructs a smaller tree. Reconstruction ends in one
/// full root recomputation against the requested checkpoint, and that term
/// dominates the index walk at these depths: the sweep therefore measures the
/// reconstructed state size at least as much as the distance walked, and it
/// must not be read as the cost of walking one more undo entry.
fn bench_history(suite: &mut Suite) {
    let fixture = generated(HISTORY_BLOCKS, Shape::GrowingKeys);
    let tip = fixture.tip();
    for depth in HISTORY_DEPTHS {
        let height = tip - depth;
        suite.bench(format!("log/read_state_at/depth_{depth}"), || {
            fixture.log().read_state_at(height)
        });
    }
}

/// Records recovery of an existing directory over a log-length sweep.
///
/// Opening streams the published prefix, rechecks every chained digest, replays
/// each state transition and rebuilds the height index. Both shapes are
/// measured because replay cost per record depends on the committed state size:
/// under `FixedKey` the state stays at one entry, while under `GrowingKeys`
/// every replayed transition recomputes a root over a larger tree.
fn bench_recovery(suite: &mut Suite) {
    for (shape, label) in [
        (Shape::FixedKey, "log/open"),
        (Shape::GrowingKeys, "log/open_growing_state"),
    ] {
        for blocks in LOG_LENGTHS {
            let mut fixture = generated(blocks, shape);
            fixture.close();
            let path = fixture.path();
            suite.bench(format!("{label}/{blocks}"), || {
                AppendOnlyStorage::open(&path).expect("published log reopens")
            });
        }
    }
}

fn main() {
    let mut suite = Suite::new("storage");
    bench_appends(&mut suite);
    bench_memory_appends(&mut suite);
    bench_reads(&mut suite);
    bench_history(&mut suite);
    bench_recovery(&mut suite);
    suite.report();
}
