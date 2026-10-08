// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Detached deterministic execution with results bound to an exact producer snapshot.
//!
//! Jobs hold no signer or storage writer. Completing a job does not authorize a
//! proposal, vote or commit: the node must retain its ordinary consensus checks.

use crate::{BlockProducer, ProducerError, producer::VerifiedExecution};
use std::{
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
};
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

/// One persistent worker with at most one submitted or uncollected execution.
/// A completed result remains bounded until the caller collects it. Dropping the
/// worker waits for its current job and joins the thread without publishing state.
pub struct ExecutionWorker {
    requests: Option<mpsc::SyncSender<ExecutionJob>>,
    completions: mpsc::Receiver<Result<CompletedExecution, ProducerError>>,
    thread: Option<JoinHandle<()>>,
    busy: bool,
}

impl ExecutionWorker {
    /// Starts the worker without creating any producer snapshot or queued job.
    pub fn spawn() -> std::io::Result<Self> {
        let (requests, jobs) = mpsc::sync_channel::<ExecutionJob>(1);
        let (completed, completions) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("block-execution".into())
            .spawn(move || {
                while let Ok(job) = jobs.recv() {
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job.execute()))
                            .unwrap_or_else(|_| Err(worker_error("execution worker panicked")));
                    if completed.send(result).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            requests: Some(requests),
            completions,
            thread: Some(thread),
            busy: false,
        })
    }

    /// Submits only when the previous completion has been collected.
    /// This never waits for execution; rejection leaves the worker unchanged.
    pub fn submit(&mut self, job: ExecutionJob) -> Result<(), ProducerError> {
        if self.busy {
            return Err(worker_error("execution worker is busy"));
        }
        self.requests
            .as_ref()
            .ok_or_else(|| worker_error("execution worker is stopped"))?
            .try_send(job)
            .map_err(|_| worker_error("execution worker is unavailable"))?;
        self.busy = true;
        Ok(())
    }

    /// Collects a completed job without waiting; errors also release the one slot.
    pub fn try_complete(&mut self) -> Option<Result<CompletedExecution, ProducerError>> {
        if !self.busy {
            return None;
        }
        match self.completions.try_recv() {
            Ok(result) => {
                self.busy = false;
                Some(result)
            }
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.busy = false;
                Some(Err(worker_error("execution worker disconnected")))
            }
        }
    }

    /// Includes finished work whose result the caller has not yet collected.
    #[must_use]
    pub const fn busy(&self) -> bool {
        self.busy
    }
}

impl Drop for ExecutionWorker {
    fn drop(&mut self) {
        // Closing requests ends the loop after its current job. The sole result
        // fits in the completion channel even when the caller never collects it.
        self.requests.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn worker_error(message: &str) -> ProducerError {
    ProducerError::Worker(message.into())
}

impl ExecutionJob {
    /// Executes against the captured state without publishing state or creating votes.
    pub fn execute(mut self) -> Result<CompletedExecution, ProducerError> {
        let proposal = match self.work {
            ExecutionWork::Received(block) => {
                self.producer.prepare_received_vrf(&block)?;
                self.producer.execute_received_block(block)?
            }
            ExecutionWork::Production(root) => {
                let mut proposal = self.producer.produce_block()?;
                proposal.block.header.committee_root = root;
                self.producer.validate_proposal(&proposal)?;
                self.producer.mark_production_execution()?;
                proposal
            }
        };
        let verified = self
            .producer
            .verified_for_proposal(&proposal)
            .ok_or_else(|| {
                ProducerError::Assembly("detached execution result unavailable".into())
            })?;
        Ok(CompletedExecution {
            verified,
            admission_sequence: self.admission_sequence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkNodeError;

    #[test]
    fn disconnected_completion_is_a_local_failure_and_releases_slot() {
        let (requests, jobs) = mpsc::sync_channel(1);
        let (completed, completions) = mpsc::sync_channel(1);
        drop(jobs);
        drop(completed);
        let mut worker = ExecutionWorker {
            requests: Some(requests),
            completions,
            thread: None,
            busy: true,
        };
        let Some(Err(error)) = worker.try_complete() else {
            panic!("disconnected worker must fail locally");
        };
        assert!(matches!(
            NetworkNodeError::from(error),
            NetworkNodeError::Local(_)
        ));
        assert!(!worker.busy());
        assert!(worker.try_complete().is_none());
        assert!(matches!(
            NetworkNodeError::from(worker_error("execution worker panicked")),
            NetworkNodeError::Local(_)
        ));
    }
}
