// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Block production pipeline.
//!
//! Coordinates transaction selection from the mempool, block assembly,
//! deterministic execution, and preparation of storage commit batches.
//! The producer follows the finalization path described in ARCHITECTURE.md:
//!
//! ```text
//! transactions -> bounded validation -> mempool -> compact proposal
//!              -> deterministic execution -> commitment verification
//!              -> atomic finalized storage
//! ```

mod potb;
mod pipeline;
mod rotation;

pub(crate) use pipeline::VerifiedExecution;

use std::{collections::BTreeMap, sync::{Arc, Mutex}};

use execution::{
    ExecutionError, ExecutionPolicy, ExecutorConfig, SignedSession, SimpleExecutor,
    TransactionOutput, execute_parallel,
};
use mempool::{Mempool, MempoolError, PoolEntry, PoolLimits};
use state::{InMemoryState, StateDatabase, StateDiff};
use storage::{Checkpoint, CommitBatch, NodeStorage, StorageError};
use transaction::{BasicValidator, TransactionError, TransactionValidator, ValidationContext};
use types::{Address, Block, BlockHeader, Hash256, Resources, Transaction};

/// Maximum number of transactions to include in a single block.
const MAX_BLOCK_TRANSACTIONS: usize = 256;

/// Maximum size in bytes of a single transaction accepted by the producer.
const MAX_TRANSACTION_BYTES: usize = 1024 * 1024;

/// Block production configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducerConfig {
    /// Chain identifier for transaction validation.
    pub chain_id: u32,
    /// Maximum transactions per block.
    pub max_block_transactions: usize,
    /// Maximum size in bytes for a single transaction.
    pub max_transaction_bytes: usize,
    /// Maximum pool capacity.
    pub pool_limits: PoolLimits,
    /// Adaptive block capacity.
    pub block_capacity: Resources,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            chain_id: 7,
            max_block_transactions: MAX_BLOCK_TRANSACTIONS,
            max_transaction_bytes: MAX_TRANSACTION_BYTES,
            pool_limits: PoolLimits {
                max_transactions: 10_000,
                max_bytes: 10 * 1024 * 1024,
            },
            block_capacity: Resources {
                compute: 1000,
                memory: 1024,
                io: 256,
                bandwidth: 1024,
            },
        }
    }
}

/// A prepared block ready for consensus voting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockProposal {
    /// The assembled block with header and transactions.
    pub block: Block,
    /// Execution outputs for each transaction.
    pub outputs: Vec<TransactionOutput>,
    /// Final state root after execution.
    pub state_root: Hash256,
    /// Total resources consumed by the block.
    pub resources_used: Resources,
}

/// Errors that can occur during block production.
#[derive(Debug)]
pub enum ProducerError {
    /// Authenticated consensus context or certificate is invalid.
    Consensus(consensus::ConsensusError),
    /// Transaction validation or execution failed.
    Execution(ExecutionError),
    /// Mempool admission failed.
    Mempool(MempoolError),
    /// Storage commit failed.
    Storage(StorageError),
    /// Block assembly failed due to node constraints.
    Assembly(String),
}

impl std::fmt::Display for ProducerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Consensus(e) => write!(f, "consensus error: {e}"),
            Self::Execution(e) => write!(f, "execution error: {e}"),
            Self::Mempool(e) => write!(f, "mempool error: {e}"),
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::Assembly(msg) => write!(f, "assembly error: {msg}"),
        }
    }
}

impl std::error::Error for ProducerError {}

impl From<consensus::ConsensusError> for ProducerError {
    fn from(error: consensus::ConsensusError) -> Self {
        Self::Consensus(error)
    }
}

impl From<ExecutionError> for ProducerError {
    fn from(e: ExecutionError) -> Self {
        Self::Execution(e)
    }
}

impl From<MempoolError> for ProducerError {
    fn from(e: MempoolError) -> Self {
        Self::Mempool(e)
    }
}

impl From<StorageError> for ProducerError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

impl From<TransactionError> for ProducerError {
    fn from(e: TransactionError) -> Self {
        Self::Assembly(format!("transaction validation: {e}"))
    }
}

/// Block production pipeline that coordinates mempool, execution, and storage.
///
/// The producer maintains an in-memory state database for execution and
/// prepares commit batches for durable storage. It does not participate
/// in consensus voting directly; that responsibility belongs to the node
/// service layer.
pub struct BlockProducer {
    /// Production configuration.
    config: ProducerConfig,
    /// Transaction pool with bounded admission.
    mempool: Mempool,
    /// In-memory state for deterministic execution.
    state: InMemoryState,
    /// Current block height (next to produce).
    height: u64,
    /// Parent block hash for the next block.
    parent_hash: Hash256,
    /// Transaction validator.
    validator: BasicValidator,
    /// Sequence counter for mempool admission ordering.
    admission_sequence: u64,
    /// Genesis-backed chains use authenticated native payments.
    account_execution: bool,
    rotation: Option<consensus::rotation::CommitteeState>,
    contributions: Option<rotation::VerifiedTransition>,
    potb: Option<consensus::potb_transition::PotbVerifier>,
    potb_batch: Option<(
        consensus::potb_transition::PotbBatch,
        consensus::potb_transition::PotbState,
    )>,
    verified_execution: Mutex<Option<Arc<VerifiedExecution>>>,
}

impl BlockProducer {
    /// Restores execution state and the next position from a trusted local checkpoint.
    ///
    /// The caller authenticates chain identity and finality. Pending transactions and
    /// the demonstration validator's account cache are not durable account state.
    pub fn from_checkpoint(
        config: ProducerConfig,
        checkpoint: Option<Checkpoint>,
        state: InMemoryState,
    ) -> Result<Self, ProducerError> {
        let (height, parent_hash) = match checkpoint {
            Some(checkpoint) => {
                if checkpoint.state_root != state.root() {
                    return Err(StorageError::VerificationFailed.into());
                }
                (
                    checkpoint
                        .height
                        .checked_add(1)
                        .ok_or(StorageError::InvalidOrder)?,
                    checkpoint.block,
                )
            }
            None if state.is_empty() => (0, Hash256::ZERO),
            None => return Err(StorageError::VerificationFailed.into()),
        };
        let mut producer = Self::new(config);
        producer.height = height;
        producer.parent_hash = parent_hash;
        producer.account_execution = state.get(&genesis::genesis_key()).is_some();
        producer.state = state;
        Ok(producer)
    }

    /// Creates a new block producer with the given configuration.
    ///
    /// The producer starts at height 0 (genesis) with the zero hash as parent.
    ///
    /// # Panics
    ///
    /// Panics if the pool limits in the configuration are zero.
    #[must_use]
    pub fn new(config: ProducerConfig) -> Self {
        let mempool =
            Mempool::new(config.pool_limits).expect("default pool limits are always valid");

        Self {
            config,
            mempool,
            state: InMemoryState::new(),
            height: 0,
            parent_hash: Hash256::ZERO,
            validator: BasicValidator::empty(),
            admission_sequence: 0,
            account_execution: false,
            rotation: None,
            contributions: None,
            potb: None,
            potb_batch: None,
            verified_execution: Mutex::new(None),
        }
    }

    /// Creates a producer initialized with an account for transaction validation.
    ///
    /// # Panics
    ///
    /// Panics if the pool limits in the configuration are zero.
    #[must_use]
    pub fn with_account(
        address: Address,
        nonce: u64,
        balance: u64,
        config: ProducerConfig,
    ) -> Self {
        let mut accounts = BTreeMap::new();
        accounts.insert(address, transaction::AccountState { nonce, balance });
        let validator = BasicValidator::new(accounts);

        let mempool =
            Mempool::new(config.pool_limits).expect("default pool limits are always valid");

        Self {
            config,
            mempool,
            state: InMemoryState::new(),
            height: 0,
            parent_hash: Hash256::ZERO,
            validator,
            admission_sequence: 0,
            account_execution: false,
            rotation: None,
            contributions: None,
            potb: None,
            potb_batch: None,
        }
    }

    /// Returns the current block height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Returns the parent block hash.
    #[must_use]
    pub fn parent_hash(&self) -> Hash256 {
        self.parent_hash
    }

    /// Returns the number of pending transactions in the mempool.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.mempool.len()
    }

    /// Returns a reference to the in-memory state.
    #[must_use]
    pub fn state(&self) -> &InMemoryState {
        &self.state
    }

    /// Submits a transaction to the mempool for inclusion in future blocks.
    ///
    /// The transaction is validated and admitted only if it passes bounds
    /// checks and does not conflict with existing entries.
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<Hash256, ProducerError> {
        self.ensure_rotation_profile()?;
        let context = ValidationContext {
            chain_id: self.config.chain_id,
            next_height: self.height,
            max_transaction_bytes: self.config.max_transaction_bytes,
        };

        let validated = if self.account_execution {
            let snapshot = self.state.snapshot().map_err(ExecutionError::from)?;
            let mut session = SignedSession::new(
                snapshot.as_ref(),
                context,
                self.admission_capacity()?,
                self.contracts_enabled(),
            )
            .with_prices(self.current_prices());
            let output = session.execute(&tx)?;
            transaction::ValidatedTransaction {
                id: output.receipt.transaction,
                lane: tx.lane,
                transaction: tx,
            }
        } else {
            self.validator.validate(tx, context)?
        };

        let id = validated.id;
        let sender = validated.transaction.sender;
        let encoded_len = transaction::estimate_encoded_len(&validated.transaction);

        let entry = PoolEntry {
            id,
            transaction: validated.transaction,
            priority: 0,
            sequence: self.admission_sequence,
        };
        let next_sequence = self
            .admission_sequence
            .checked_add(1)
            .ok_or_else(|| ProducerError::Assembly("admission sequence exhausted".into()))?;
        self.mempool.insert(entry, encoded_len)?;
        if !self.account_execution {
            self.validator.advance_nonce(&sender)?;
        }
        self.admission_sequence = next_sequence;
        Ok(id)
    }

    /// Assembles and executes a block from pending mempool transactions.
    ///
    /// Selects transactions, builds a block header, executes against the
    /// current state, and returns a proposal ready for consensus voting.
    ///
    /// # Errors
    ///
    /// Returns [`ProducerError`] if transaction execution fails or the
    /// state root cannot be computed.
    pub fn produce_block(&mut self) -> Result<BlockProposal, ProducerError> {
        self.ensure_rotation_profile()?;
        if self.potb.is_some() {
            self.produce_potb_block()
        } else if self.rotation.is_some() {
            self.produce_rotating_block()
        } else {
            self.produce_application_block(
                &self.state,
                self.config.block_capacity,
                self.config.max_block_transactions,
            )
        }
    }

    fn produce_application_block(
        &self,
        base: &InMemoryState,
        capacity: Resources,
        maximum_transactions: usize,
    ) -> Result<BlockProposal, ProducerError> {
        // Select transactions from the mempool based on priority and capacity
        let selected = if self.account_execution {
            self.mempool.candidates()
        } else {
            self.mempool.select(maximum_transactions, capacity)
        };

        let mut transactions: Vec<Transaction> = selected
            .iter()
            .map(|entry| entry.transaction.clone())
            .collect();

        let parent_root = base.root();
        // Proposal execution must not publish state before storage accepts finalization.
        let mut staged = base.clone();
        let (outputs, state_root) = if self.account_execution {
            let snapshot = base.snapshot().map_err(ExecutionError::from)?;
            let mut session = SignedSession::new(
                snapshot.as_ref(),
                self.validation_context(),
                capacity,
                self.contracts_enabled(),
            )
            .with_prices(self.current_prices());
            let mut accepted = Vec::new();
            let mut outputs = Vec::new();
            for tx in transactions {
                if accepted.len() == maximum_transactions {
                    break;
                }
                match session.execute(&tx) {
                    Ok(output) => {
                        accepted.push(tx);
                        outputs.push(output);
                    }
                    Err(ExecutionError::State(error)) => {
                        return Err(ExecutionError::State(error).into());
                    }
                    // Conflicts with earlier transfers may invalidate a pool entry.
                    // Keep it pending while building the proposal; never stall valid work.
                    Err(_) => {}
                }
            }
            transactions = accepted;
            let diffs: Vec<_> = outputs.iter().map(|output| output.diff.clone()).collect();
            let root = staged
                .commit(parent_root, &diffs)
                .map_err(ExecutionError::from)?;
            (outputs, root)
        } else {
            self.execute_application_transactions(&mut staged, &transactions, capacity)?
        };
        let transactions_root = compute_transactions_root(&transactions);

        // Compute the receipts root commitment
        let receipts: Vec<types::ExecutionReceipt> =
            outputs.iter().map(|o| o.receipt.clone()).collect();
        let receipts_root = compute_receipts_root(&receipts);

        let resources_used = checked_resources(&receipts)?;

        // Build the block header
        let header = BlockHeader {
            height: self.height,
            parent: self.parent_hash,
            transactions_root,
            state_root,
            receipts_root,
            committee_root: Hash256::ZERO,
            capacity: self.config.block_capacity,
        };

        let block = Block {
            header,
            transactions,
        };

        let proposal = BlockProposal {
            block,
            outputs,
            state_root,
            resources_used,
        };

        Ok(proposal)
    }

    /// Prepares a proposal bound to independently trusted committee membership.
    pub fn produce_block_for_committee(
        &mut self,
        committee: &consensus::AuthenticatedCommittee,
    ) -> Result<BlockProposal, ProducerError> {
        if committee.chain_id() != self.config.chain_id || committee.height() != self.height {
            return Err(consensus::ConsensusError::InvalidTransition.into());
        }
        self.check_rotation_committee(committee.root())?;
        let mut proposal = self.produce_block()?;
        proposal.block.header.committee_root = committee.root();
        Ok(proposal)
    }

    /// Authenticates finality before re-executing and atomically committing a proposal.
    ///
    /// The caller supplies membership from trusted finalized state, not peer input.
    /// Failed proofs, execution, or storage writes preserve local state and the pool.
    pub fn commit_certified_block<S: NodeStorage>(
        &mut self,
        proposal: &BlockProposal,
        certificate: &consensus::FinalityCertificate,
        committee: &consensus::AuthenticatedCommittee,
        storage: &mut S,
    ) -> Result<storage::Checkpoint, ProducerError> {
        if committee.chain_id() != self.config.chain_id || committee.height() != self.height {
            return Err(consensus::ConsensusError::InvalidTransition.into());
        }
        self.check_rotation_committee(committee.root())?;
        committee.verify_certificate(certificate, &proposal.block.header)?;
        let bytes = certificate
            .encode()
            .map_err(|_| consensus::ConsensusError::InvalidCertificate)?;
        self.commit_block(proposal, bytes, storage)
    }

    /// Read-only recovery of a certified suffix after an independently authenticated anchor.
    pub(crate) fn replay_certified(
        &mut self,
        block: types::Block,
        certificate: &consensus::FinalityCertificate,
        committee: &consensus::AuthenticatedCommittee,
    ) -> Result<(), ProducerError> {
        committee.verify_certificate(certificate, &block.header)?;
        self.check_rotation_committee(committee.root())?;
        self.prepare_received_vrf(&block)?;
        let proposal = self.execute_received_block(block)?;
        let encoded = certificate
            .encode()
            .map_err(|_| consensus::ConsensusError::InvalidCertificate)?;
        self.verify_rotation_certificate(&proposal, &encoded)?;
        let (staged, _) = self.prepare_verified(&proposal)?;
        let rotation = self.next_rotation(&staged)?;
        let potb = self.next_potb(&proposal, &encoded, &staged)?;
        let height = self
            .height
            .checked_add(1)
            .ok_or(consensus::ConsensusError::InvalidTransition)?;
        if let Some(trusted) = &potb {
            self.config.block_capacity = trusted.current().committee().capacity();
        }
        self.parent_hash = proposal.block.header.compute_hash();

        self.clear_execution();
        self.height = height;
        self.state = staged;
        self.rotation = rotation;
        self.potb = potb;
        self.contributions = None;
        self.potb_batch = None;
        Ok(())
    }

    /// Commits a finalized block to storage after consensus approval.
    ///
    /// Re-executes the reference transition, verifies commitments and resource totals,
    /// then updates state, height, and the pool only after storage succeeds.
    /// The caller remains responsible for authenticating the finality certificate.
    pub fn commit_block<S: NodeStorage>(
        &mut self,
        proposal: &BlockProposal,
        certificate: Vec<u8>,
        storage: &mut S,
    ) -> Result<storage::Checkpoint, ProducerError> {
        let next_height = self
            .height
            .checked_add(1)
            .ok_or_else(|| ProducerError::Assembly("block height exhausted".into()))?;
        self.verify_rotation_certificate(proposal, &certificate)?;
        let (staged, diffs) = self.prepare_verified(proposal)?;

        let next_rotation = self.next_rotation(&staged)?;
        let next_potb = self.next_potb(proposal, &certificate, &staged)?;

        let effects = if self.account_execution {
            let snapshot = staged.snapshot().map_err(ExecutionError::from)?;
            Some(storage::BlockEffects {
                potb: self
                    .potb
                    .as_ref()
                    .map(|_| {
                        state::StateValueProof::create(
                            snapshot.as_ref(),
                            &consensus::potb_transition::potb_state_key(),
                        )
                        .map_err(ExecutionError::from)
                    })
                    .transpose()?,
                committee: self
                    .rotation
                    .as_ref()
                    .map(|_| {
                        state::StateValueProof::create(
                            snapshot.as_ref(),
                            &consensus::rotation::committee_state_key(),
                        )
                        .map_err(ExecutionError::from)
                    })
                    .transpose()?,
                receipts: proposal
                    .outputs
                    .iter()
                    .map(|output| output.receipt.clone())
                    .collect(),
                genesis: state::StateValueProof::create(snapshot.as_ref(), &genesis::genesis_key())
                    .map_err(ExecutionError::from)?,
            })
        } else {
            None
        };
        let batch = CommitBatch {
            effects,
            block: proposal.block.clone(),
            finality_certificate: certificate,
            state_diffs: diffs,
        };

        let checkpoint = storage.commit(&batch)?;

        // Publish locally only after the storage transaction succeeds.
        self.state = staged;
        self.rotation = next_rotation;
        self.contributions = None;
        if let Some(trusted) = &next_potb {
            self.config.block_capacity = trusted.current().committee().capacity();
        }
        self.potb = next_potb;
        self.potb_batch = None;
        let selected_keys: Vec<_> = proposal
            .block
            .transactions
            .iter()
            .map(|tx| (tx.sender, tx.nonce))
            .collect();
        self.mempool.remove_batch(&selected_keys);
        self.height = next_height;
        self.mempool.remove_expired(next_height);
        self.parent_hash = proposal.block.header.compute_hash();
        self.clear_execution();

        Ok(checkpoint)
    }

    /// Re-executes and validates a proposed transition without publishing state,
    /// consuming the pool, or writing storage. Proposer authorization is external.
    pub fn validate_proposal(&self, proposal: &BlockProposal) -> Result<(), ProducerError> {
        self.prepare_verified(proposal).map(|_| ())
    }

    /// Reconstructs execution outputs from an untrusted network block.
    /// Bounds, parent, capacity, and transaction commitments are checked before execution.
    pub fn execute_received_block(&self, block: Block) -> Result<BlockProposal, ProducerError> {
        let header = &block.header;
        self.check_rotation_committee(header.committee_root)?;
        if header.height != self.height
            || header.parent != self.parent_hash
            || header.capacity != self.config.block_capacity
            || block.transactions.len() > self.config.max_block_transactions
            || block.transactions.iter().any(|tx| {
                tx.chain_id != self.config.chain_id
                    || transaction::estimate_encoded_len(tx) > self.config.max_transaction_bytes
            })
            || compute_transactions_root(&block.transactions) != header.transactions_root
        {
            return Err(ProducerError::Assembly(
                "network block context mismatch".into(),
            ));
        }
        if let Some(verified) = self.verified_for_block(&block) {
            return Ok(verified.proposal.clone());
        }
        let mut staged = self.state.clone();
        let (outputs, state_root) = self.execute_transactions(&mut staged, &block.transactions)?;
        let receipts: Vec<_> = outputs
            .iter()
            .map(|output| output.receipt.clone())
            .collect();
        let resources_used = checked_resources(&receipts)?;
        if state_root != header.state_root
            || compute_receipts_root(&receipts) != header.receipts_root
            || !resources_used.fits_in(header.capacity)
        {
            return Err(ProducerError::Assembly(
                "network execution commitment mismatch".into(),
            ));
        }
        let proposal = BlockProposal {
            block,
            outputs,
            state_root,
            resources_used,
        };
        let diffs = proposal.outputs.iter().map(|output| output.diff.clone()).collect();
        self.remember_execution(&proposal, &staged, diffs);
        Ok(proposal)
    }

    /// Bounded admission candidates for reference transaction gossip.
    #[must_use]
    pub fn pending_transactions(&self) -> Vec<Transaction> {
        self.mempool
            .candidates()
            .into_iter()
            .take(self.config.max_block_transactions)
            .map(|entry| entry.transaction.clone())
            .collect()
    }

    fn prepare_verified(
        &self,
        proposal: &BlockProposal,
    ) -> Result<(InMemoryState, Vec<StateDiff>), ProducerError> {
        self.height
            .checked_add(1)
            .ok_or_else(|| ProducerError::Assembly("block height exhausted".into()))?;
        let header = &proposal.block.header;
        self.check_rotation_committee(header.committee_root)?;
        if proposal.block.transactions.len() > self.config.max_block_transactions
            || proposal.block.transactions.iter().any(|tx| {
                tx.chain_id != self.config.chain_id
                    || transaction::estimate_encoded_len(tx) > self.config.max_transaction_bytes
            })
        {
            return Err(ProducerError::Assembly(
                "proposal transaction bounds do not match".into(),
            ));
        }
        let receipts: Vec<_> = proposal
            .outputs
            .iter()
            .map(|output| output.receipt.clone())
            .collect();
        if header.height != self.height
            || header.parent != self.parent_hash
            || header.capacity != self.config.block_capacity
            || checked_resources(&receipts)? != proposal.resources_used
            || !proposal.resources_used.fits_in(header.capacity)
            || proposal.state_root != header.state_root
            || proposal.outputs.len() != proposal.block.transactions.len()
            || compute_transactions_root(&proposal.block.transactions) != header.transactions_root
            || compute_receipts_root(&receipts) != header.receipts_root
            || proposal
                .outputs
                .iter()
                .zip(&proposal.block.transactions)
                .any(|(output, tx)| output.receipt.transaction != hash_transaction(tx))
        {
            return Err(ProducerError::Assembly(
                "proposal commitments do not match".into(),
            ));
        }
        if let Some(verified) = self.verified_for_proposal(proposal) {
            return Ok((verified.staged.clone(), verified.diffs.clone()));
        }
        // Re-execute the reference transition: mutually consistent forged roots are not proof
        // that the supplied outputs actually follow from these transactions and this parent.
        let mut staged = self.state.clone();
        let (outputs, root) =
            self.execute_transactions(&mut staged, &proposal.block.transactions)?;
        if outputs != proposal.outputs || root != header.state_root {
            return Err(ProducerError::Assembly(
                "proposal execution does not match".into(),
            ));
        }
        let diffs: Vec<StateDiff> = outputs.into_iter().map(|output| output.diff).collect();

        self.remember_execution(proposal, &staged, diffs.clone());

        Ok((staged, diffs))
    }

    fn validation_context(&self) -> ValidationContext {
        ValidationContext {
            chain_id: self.config.chain_id,
            next_height: self.height,
            max_transaction_bytes: self.config.max_transaction_bytes,
        }
    }

    /// Prices authenticated by the finalized parent for this height.
    #[must_use]
    pub fn current_prices(&self) -> Resources {
        self.potb_state()
            .and_then(consensus::potb_transition::PotbState::governance)
            .map_or(execution::PAYMENT_PRICES, |state| state.active().prices)
    }

    fn execute_application_transactions(
        &self,
        staged: &mut InMemoryState,
        transactions: &[Transaction],
        capacity: Resources,
    ) -> Result<(Vec<TransactionOutput>, Hash256), ExecutionError> {
        let parent = staged.root();
        if self.account_execution {
            execute_parallel(
                staged,
                transactions,
                parent,
                self.validation_context(),
                ExecutionPolicy {
                    capacity,
                    prices: self.current_prices(),
                    contracts: self.contracts_enabled(),
                },
                std::thread::available_parallelism().map_or(1, |count| count.get().min(8)),
            )
        } else {
            SimpleExecutor::new(
                staged,
                BasicValidator::empty(),
                ExecutorConfig {
                    chain_id: self.config.chain_id,
                    next_height: self.height,
                    max_transaction_bytes: self.config.max_transaction_bytes,
                },
            )
            .execute_block(transactions, parent)
        }
    }

    /// Whether committed genesis activated ABI-v2 contract execution.
    #[must_use]
    pub fn contracts_enabled(&self) -> bool {
        self.state
            .get(&genesis::runtime_key())
            .is_some_and(|bytes| bytes == 2u32.to_le_bytes())
    }

    /// Chain identity used for admission and execution.
    #[must_use]
    pub const fn chain_id(&self) -> u32 {
        self.config.chain_id
    }

    /// Computes a simple deterministic hash for the mempool selection tie-breaking.
    #[allow(dead_code)]
    fn select_priority(entry: &PoolEntry) -> (std::cmp::Reverse<u64>, u64, Hash256) {
        (std::cmp::Reverse(entry.priority), entry.sequence, entry.id)
    }
}

fn checked_resources(receipts: &[types::ExecutionReceipt]) -> Result<Resources, ProducerError> {
    receipts.iter().try_fold(Resources::ZERO, |sum, receipt| {
        sum.checked_add(receipt.resources)
            .ok_or_else(|| ProducerError::Assembly("block resource accounting overflow".into()))
    })
}

/// Computes a Merkle root over canonical signed transaction identifiers.
#[must_use]
pub fn compute_transactions_root(transactions: &[Transaction]) -> Hash256 {
    let hashes: Vec<_> = transactions.iter().map(hash_transaction).collect();
    crypto::compute_transactions_root(&hashes)
}

/// Computes a Merkle root over domain-separated canonical receipt hashes.
#[must_use]
pub fn compute_receipts_root(receipts: &[types::ExecutionReceipt]) -> Hash256 {
    let hashes: Vec<_> = receipts
        .iter()
        .map(types::ExecutionReceipt::commitment)
        .collect();
    crypto::compute_receipts_root(&hashes)
}

/// Returns the canonical signed transaction identifier used by admission.
#[must_use]
pub fn hash_transaction(tx: &Transaction) -> Hash256 {
    transaction::compute_tx_id(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Address, Resources};

    #[test]
    fn proposal_is_repeatable_without_publishing_or_consuming_the_pool() {
        let mut producer = BlockProducer::new(test_config());
        producer.submit_transaction(make_tx(0, vec![1, 2])).unwrap();
        let parent = producer.state().root();
        let first = producer.produce_block().unwrap();
        let second = producer.produce_block().unwrap();
        assert_eq!(first, second);
        assert_ne!(first.state_root, parent);
        assert_eq!(producer.state().root(), parent);
        assert_eq!(producer.pending_count(), 1);
        assert_eq!(producer.height(), 0);
        let mut storage = storage::InMemoryStorage::new();
        producer
            .commit_block(&first, vec![1], &mut storage)
            .unwrap();
        assert_eq!(producer.state().root(), first.state_root);
        assert_eq!(storage.state().root(), first.state_root);
        assert_eq!(producer.pending_count(), 0);
        assert_eq!(producer.height(), 1);
    }

    #[test]
    fn failed_storage_commit_preserves_proposal_for_retry() {
        let mut producer = BlockProducer::new(test_config());
        producer.submit_transaction(make_tx(0, vec![1])).unwrap();
        let proposal = producer.produce_block().unwrap();
        let parent = producer.state().root();
        let mut occupied = storage::InMemoryStorage::new();
        let mut other = BlockProducer::new(test_config());
        let empty = other.produce_block().unwrap();
        other.commit_block(&empty, vec![1], &mut occupied).unwrap();
        assert!(matches!(
            producer.commit_block(&proposal, vec![1], &mut occupied),
            Err(ProducerError::Storage(StorageError::InvalidOrder))
        ));
        assert_eq!(producer.state().root(), parent);
        assert_eq!(producer.height(), 0);
        assert_eq!(producer.parent_hash(), Hash256::ZERO);
        assert_eq!(producer.pending_count(), 1);
        assert_eq!(producer.produce_block().unwrap(), proposal);
        let mut storage = storage::InMemoryStorage::new();
        producer
            .commit_block(&proposal, vec![1], &mut storage)
            .unwrap();
    }

    #[test]
    fn altered_proposals_are_rejected_before_publication() {
        let mut producer = BlockProducer::new(test_config());
        producer.submit_transaction(make_tx(0, vec![1])).unwrap();
        let proposal = producer.produce_block().unwrap();
        let parent = producer.state().root();
        let mut storage = storage::InMemoryStorage::new();
        let mut mutations = Vec::new();
        let mut changed = proposal.clone();
        changed.block.header.state_root = Hash256::ZERO;
        mutations.push(changed);
        changed = proposal.clone();
        changed.block.header.parent = Hash256([1; 32]);
        mutations.push(changed);
        changed = proposal.clone();
        changed.block.transactions[0].payload.push(2);
        mutations.push(changed);
        changed = proposal.clone();
        changed.outputs[0]
            .diff
            .put(types::StateKey(vec![1]), vec![99]);
        mutations.push(changed);
        changed = proposal.clone();
        changed.resources_used.compute += 1;
        mutations.push(changed);
        changed = proposal.clone();
        changed.block.header.capacity.compute += 1;
        mutations.push(changed);
        changed = proposal.clone();
        changed.outputs[0]
            .diff
            .put(types::StateKey(vec![99]), vec![99]);
        changed.outputs[0].receipt.output_root = changed.outputs[0].diff.commitment();
        changed.block.header.receipts_root =
            compute_receipts_root(&[changed.outputs[0].receipt.clone()]);
        changed.state_root = producer
            .state
            .prepare(parent, &[changed.outputs[0].diff.clone()])
            .unwrap()
            .root();
        changed.block.header.state_root = changed.state_root;
        mutations.push(changed);
        for changed in mutations {
            assert!(
                producer
                    .commit_block(&changed, vec![1], &mut storage)
                    .is_err()
            );
            assert_eq!(producer.state().root(), parent);
            assert_eq!(producer.pending_count(), 1);
            assert_eq!(producer.height(), 0);
            assert!(storage.checkpoint().is_none());
        }
        producer
            .commit_block(&proposal, vec![1], &mut storage)
            .unwrap();
        let committed = producer.state().root();
        assert!(
            producer
                .commit_block(&proposal, vec![1], &mut storage)
                .is_err()
        );
        assert_eq!(producer.state().root(), committed);
    }

    #[test]
    fn rejected_pool_admission_preserves_sender_nonce() {
        let mut config = test_config();
        config.pool_limits.max_transactions = 1;
        let mut producer = BlockProducer::with_account(sender(), 0, 1000, config);
        producer.submit_transaction(make_tx(0, vec![1])).unwrap();
        assert!(matches!(
            producer.submit_transaction(make_tx(1, vec![2])),
            Err(ProducerError::Mempool(_))
        ));
        assert!(matches!(
            producer.submit_transaction(make_tx(1, vec![2])),
            Err(ProducerError::Mempool(_))
        ));
        assert_eq!(producer.pending_count(), 1);
        assert_eq!(producer.admission_sequence, 1);
    }

    #[test]
    fn producer_and_admission_use_the_same_transaction_commitment() {
        let tx = make_tx(0, vec![1]);
        assert_eq!(hash_transaction(&tx), transaction::compute_tx_id(&tx));
        let original = compute_transactions_root(std::slice::from_ref(&tx));
        let mut changed = tx.clone();
        changed.access_list.push(types::StateKey(vec![1]));
        assert_ne!(compute_transactions_root(&[changed]), original);
        let mut changed = tx;
        changed.signature[0] ^= 1;
        assert_ne!(compute_transactions_root(&[changed]), original);
    }

    #[test]
    fn transaction_root_binds_order_and_duplicate_count() {
        let first = make_tx(0, vec![1]);
        let second = make_tx(0, vec![2]);
        assert_ne!(
            compute_transactions_root(&[first.clone(), second.clone()]),
            compute_transactions_root(&[second, first.clone()])
        );
        assert_ne!(
            compute_transactions_root(std::slice::from_ref(&first)),
            compute_transactions_root(&[first.clone(), first])
        );
    }

    fn sender() -> Address {
        Address([1u8; 32])
    }

    fn make_tx(nonce: u64, payload: Vec<u8>) -> Transaction {
        Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 7,
            sender: sender(),
            nonce,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 10,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload,
            signature: [0xFF; 64],
        }
    }

    fn test_config() -> ProducerConfig {
        ProducerConfig {
            chain_id: 7,
            max_block_transactions: 10,
            max_transaction_bytes: 1024,
            pool_limits: PoolLimits {
                max_transactions: 100,
                max_bytes: 1024 * 1024,
            },
            block_capacity: Resources {
                compute: 1000,
                memory: 1024,
                io: 256,
                bandwidth: 1024,
            },
        }
    }

    #[test]
    fn producer_starts_at_height_zero() {
        let producer = BlockProducer::new(test_config());
        assert_eq!(producer.height(), 0);
        assert_eq!(producer.parent_hash(), Hash256::ZERO);
        assert_eq!(producer.pending_count(), 0);
    }

    #[test]
    fn submit_and_produce_empty_block() {
        let mut producer = BlockProducer::new(test_config());
        let proposal = producer.produce_block().unwrap();
        assert_eq!(proposal.block.header.height, 0);
        assert_eq!(proposal.block.transactions.len(), 0);
        assert_eq!(proposal.outputs.len(), 0);
        assert_eq!(proposal.state_root, producer.state().root());
    }

    #[test]
    fn submit_transaction_increases_pending() {
        let mut producer = BlockProducer::new(test_config());
        let tx = make_tx(0, vec![1, 2, 3]);
        producer.submit_transaction(tx).unwrap();
        assert_eq!(producer.pending_count(), 1);
    }

    #[test]
    fn produce_block_includes_submitted_transactions() {
        let mut producer = BlockProducer::new(test_config());
        let tx = make_tx(0, vec![1, 2, 3]);
        producer.submit_transaction(tx.clone()).unwrap();

        let proposal = producer.produce_block().unwrap();
        assert_eq!(proposal.block.transactions.len(), 1);
        assert_eq!(proposal.block.transactions[0], tx);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn produce_block_multiple_transactions() {
        let mut producer = BlockProducer::with_account(sender(), 0, 100_000, test_config());
        for i in 0u64..3 {
            let tx = make_tx(i, vec![i as u8]);
            producer.submit_transaction(tx).unwrap();
        }

        let proposal = producer.produce_block().unwrap();
        assert_eq!(proposal.block.transactions.len(), 3);
        assert!(proposal.outputs.iter().all(|o| o.receipt.succeeded));
    }

    #[test]
    fn commit_block_advances_height() {
        let mut producer = BlockProducer::new(test_config());
        let proposal = producer.produce_block().unwrap();
        let mut storage = storage::InMemoryStorage::new();

        producer
            .commit_block(&proposal, vec![0xAA; 32], &mut storage)
            .unwrap();

        assert_eq!(producer.height(), 1);
        assert_eq!(producer.parent_hash(), proposal.block.header.compute_hash());
    }

    #[test]
    fn transactions_root_deterministic() {
        let txs = vec![make_tx(0, vec![1]), make_tx(1, vec![2])];
        let root1 = compute_transactions_root(&txs);
        let root2 = compute_transactions_root(&txs);
        assert_eq!(root1, root2);
    }

    #[test]
    fn transactions_root_empty() {
        assert_eq!(compute_transactions_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn receipts_root_empty() {
        assert_eq!(compute_receipts_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn hash_transaction_deterministic() {
        let tx = make_tx(0, vec![1, 2, 3]);
        let h1 = hash_transaction(&tx);
        let h2 = hash_transaction(&tx);
        assert_eq!(h1, h2);
    }

    #[test]
    fn producer_config_default() {
        let config = ProducerConfig::default();
        assert_eq!(config.chain_id, 7);
        assert_eq!(config.max_block_transactions, MAX_BLOCK_TRANSACTIONS);
        assert_eq!(config.max_transaction_bytes, MAX_TRANSACTION_BYTES);
    }

    #[test]
    fn producer_error_display() {
        let errors = [ProducerError::Assembly("test".into())];
        for e in &errors {
            assert_ne!(e.to_string().len(), 0);
        }
    }

    #[test]
    fn producer_with_account() {
        let mut producer = BlockProducer::with_account(sender(), 0, 1000, test_config());
        let tx = make_tx(0, vec![1, 2, 3]);
        producer.submit_transaction(tx).unwrap();
        let proposal = producer.produce_block().unwrap();
        assert_eq!(proposal.block.transactions.len(), 1);
    }

    #[test]
    fn block_header_parent_linkage() {
        let mut producer = BlockProducer::new(test_config());
        let proposal1 = producer.produce_block().unwrap();
        let mut storage = storage::InMemoryStorage::new();

        producer
            .commit_block(&proposal1, vec![0xAA; 32], &mut storage)
            .unwrap();

        let proposal2 = producer.produce_block().unwrap();
        assert_eq!(proposal2.block.header.height, 1);
        assert_eq!(
            proposal2.block.header.parent,
            proposal1.block.header.compute_hash()
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn multiple_blocks_sequential() {
        let mut producer = BlockProducer::with_account(sender(), 0, 100_000, test_config());
        let mut storage = storage::InMemoryStorage::new();

        for h in 0u64..5 {
            let tx = make_tx(h, vec![h as u8]);
            producer.submit_transaction(tx).unwrap();

            let proposal = producer.produce_block().unwrap();
            assert_eq!(proposal.block.header.height, h);

            producer
                .commit_block(&proposal, vec![0xAA; 32], &mut storage)
                .unwrap();
        }

        assert_eq!(producer.height(), 5);
        assert_eq!(storage.recover().unwrap().unwrap().height, 4);
    }
}
