// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Detached deterministic execution with results bound to an exact producer snapshot.
//!
//! Jobs hold no signer or storage writer. Completing a job does not authorize a
//! proposal, vote or commit: the node must retain its ordinary consensus checks.

use crate::{BlockProducer, ProducerError, producer::VerifiedExecution};
use std::sync::Arc;
use types::{Block, Hash256};

pub(crate) enum ExecutionWork {
    Received(Block),
    Production(Hash256),
}

/// An owned, bounded execution job for a background worker.
/// The caller should retain at most one active job and discard obsolete results.
pub struct ExecutionJob {
    pub(crate) producer: BlockProducer,
    pub(crate) work: ExecutionWork,
    pub(crate) admission_sequence: Option<u64>,
}

/// An opaque execution result; only its originating deterministic snapshot can reuse it.
pub struct CompletedExecution {
    pub(crate) verified: Arc<VerifiedExecution>,
    pub(crate) admission_sequence: Option<u64>,
}

impl ExecutionJob {
    /// Executes against the captured state without publishing state or creating votes.
    pub fn execute(mut self) -> Result<CompletedExecution, ProducerError> {
        let proposal = match self.work {
            ExecutionWork::Received(block) => self.producer.execute_received_block(block)?,
            ExecutionWork::Production(root) => {
                let mut proposal = self.producer.produce_block()?;
                proposal.block.header.committee_root = root;
                self.producer.validate_proposal(&proposal)?;
                proposal
            }
        };
        let verified = self.producer.verified_for_proposal(&proposal).ok_or_else(|| {
            ProducerError::Assembly("detached execution result unavailable".into())
        })?;
        Ok(CompletedExecution {
            verified,
            admission_sequence: self.admission_sequence,
        })
    }
}
