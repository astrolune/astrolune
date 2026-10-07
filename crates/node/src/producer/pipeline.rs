// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! One exact execution result per producer; detached jobs cannot publish state.

use super::{BlockProducer, BlockProposal, ProducerConfig, ProducerError};
use crate::execution_pipeline::{CompletedExecution, ExecutionJob, ExecutionWork};
use consensus::{
    potb_transition::{PotbBatch, PotbState, PotbVerifier},
    rotation::CommitteeState,
};
use mempool::Mempool;
use state::{InMemoryState, StateDiff};
use std::sync::{Arc, Mutex};
use types::{Block, Hash256};

struct ExecutionSnapshot {
    config: ProducerConfig,
    height: u64,
    parent_hash: Hash256,
    state_root: Hash256,
    account_execution: bool,
    rotation: Option<CommitteeState>,
    contributions: Option<super::rotation::VerifiedTransition>,
    potb: Option<PotbVerifier>,
    potb_batch: Option<(PotbBatch, PotbState)>,
}

impl ExecutionSnapshot {
    fn capture(producer: &BlockProducer) -> Self {
        Self {
            config: producer.config.clone(),
            height: producer.height,
            parent_hash: producer.parent_hash,
            state_root: producer.state.root(),
            account_execution: producer.account_execution,
            rotation: producer.rotation.clone(),
            contributions: producer.contributions.clone(),
            potb: producer.potb.clone(),
            potb_batch: producer.potb_batch.clone(),
        }
    }

    fn matches(&self, producer: &BlockProducer) -> bool {
        self.config == producer.config
            && self.height == producer.height
            && self.parent_hash == producer.parent_hash
            && self.state_root == producer.state.root()
            && self.account_execution == producer.account_execution
            && self.rotation == producer.rotation
            && self.contributions == producer.contributions
            && self.potb == producer.potb
            && self.potb_batch == producer.potb_batch
    }
}

pub(crate) struct VerifiedExecution {
    snapshot: ExecutionSnapshot,
    pub(super) proposal: BlockProposal,
    pub(super) staged: InMemoryState,
    pub(super) diffs: Vec<StateDiff>,
}

impl BlockProducer {
    /// Captures an imported block for execution outside the node lock.
    /// The node must still authenticate its envelope or finality certificate.
    #[must_use]
    pub fn prepare_block_execution(&self, block: Block) -> ExecutionJob {
        ExecutionJob {
            producer: self.execution_snapshot(),
            work: ExecutionWork::Received(block),
            admission_sequence: None,
        }
    }

    /// Captures bounded local candidates for speculative proposal preparation.
    /// The supplied root does not establish committee or proposer authority.
    pub fn prepare_block_production(
        &self,
        committee_root: Hash256,
    ) -> Result<ExecutionJob, ProducerError> {
        self.check_rotation_committee(committee_root)?;
        let mut producer = self.execution_snapshot();
        for entry in self.mempool.candidates() {
            producer.mempool.insert(
                entry.clone(),
                transaction::estimate_encoded_len(&entry.transaction),
            )?;
        }
        Ok(ExecutionJob {
            producer,
            work: ExecutionWork::Production(committee_root),
            admission_sequence: Some(self.admission_sequence),
        })
    }

    /// Reuses a completed result only while its exact execution context remains current.
    /// Local production also requires unchanged admission order. This method grants
    /// no consensus authority and never changes committed state or consumes the pool.
    pub fn accept_execution(
        &self,
        completed: CompletedExecution,
    ) -> Result<BlockProposal, ProducerError> {
        if !completed.verified.snapshot.matches(self)
            || completed.admission_sequence.is_some_and(|sequence| sequence != self.admission_sequence)
        {
            return Err(ProducerError::Assembly("stale detached execution result".into()));
        }
        let proposal = completed.verified.proposal.clone();
        *self.verified_execution.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(completed.verified);
        Ok(proposal)
    }

    fn execution_snapshot(&self) -> Self {
        Self {
            config: self.config.clone(),
            mempool: Mempool::new(self.config.pool_limits).expect("producer pool limits are valid"),
            state: self.state.clone(),
            height: self.height,
            parent_hash: self.parent_hash,
            validator: self.validator.clone(),
            admission_sequence: self.admission_sequence,
            account_execution: self.account_execution,
            rotation: self.rotation.clone(),
            contributions: self.contributions.clone(),
            potb: self.potb.clone(),
            potb_batch: self.potb_batch.clone(),
            verified_execution: Mutex::new(None),
        }
    }

    pub(crate) fn verified_for_proposal(&self, proposal: &BlockProposal) -> Option<Arc<VerifiedExecution>> {
        self.verified_for_block(&proposal.block)
            .filter(|verified| verified.proposal == *proposal)
    }

    pub(super) fn verified_for_block(&self, block: &Block) -> Option<Arc<VerifiedExecution>> {
        self.verified_execution.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|verified| verified.snapshot.matches(self) && verified.proposal.block == *block)
            .cloned()
    }

    pub(super) fn remember_execution(
        &self,
        proposal: &BlockProposal,
        staged: &InMemoryState,
        diffs: Vec<StateDiff>,
    ) {
        let verified = VerifiedExecution {
            snapshot: ExecutionSnapshot::capture(self),
            proposal: proposal.clone(),
            staged: staged.clone(),
            diffs,
        };
        *self.verified_execution.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Arc::new(verified));
    }

    pub(super) fn clear_execution(&self) {
        *self.verified_execution.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}
