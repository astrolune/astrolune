// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit rotating-profile execution; the version-1 daemon never enables it implicitly.

use consensus::rotation::{
    CommitteeHandoff, CommitteeState, HandoffVerifier, VrfBatch, committee_state_key,
};
use consensus::{ConsensusError, FinalityCertificate};
use execution::{ExecutionError, TransactionOutput};
use state::{
    AccessMode, AccessRequest, InMemoryState, StateDatabase, StateDiff, StateLease, StateValueProof,
};
use types::{Address, ExecutionReceipt, Hash256, Resources, Transaction, TransactionLane};

use super::{
    BlockProducer, BlockProposal, ProducerError, checked_resources, compute_receipts_root,
    compute_transactions_root, hash_transaction,
};

// Only installed after complete verification against this producer's private current state.
// Successful commit clears it; failed publication preserves it with the unchanged parent.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct VerifiedTransition {
    batch: VrfBatch,
    next: CommitteeState,
}

impl BlockProducer {
    /// Replays complete stored rotating history from independently trusted genesis.
    /// Every old quorum, full VRF batch and application transition is rechecked;
    /// neither saved committee bytes nor the checkpoint can choose voting authority.
    /// Reads one block at a time and performs no writes or signing. The caller must
    /// enforce an external minimum height when protection against rollback is needed.
    pub fn recover_rotation(
        config: super::ProducerConfig,
        genesis: &genesis::Genesis,
        keys: &[[u8; 32]],
        storage: &storage::ChainStorage,
    ) -> Result<(Self, HandoffVerifier), ProducerError> {
        let head = storage
            .checkpoint()
            .copied()
            .ok_or_else(|| invalid("missing checkpoint"))?;
        if usize::try_from(head.height).ok() != Some(storage.block_count()) {
            return Err(invalid("rotating recovery requires complete history"));
        }
        let mut trusted = HandoffVerifier::new(genesis, keys)?;
        let initial = genesis.materialize().map_err(invalid)?;
        let checkpoint = storage::Checkpoint {
            height: 0,
            block: trusted.parent(),
            state_root: initial.root(),
        };
        let mut producer =
            Self::from_checkpoint(config, Some(checkpoint), initial)?.with_rotation(&trusted)?;
        for height in 1..=head.height {
            let (block, encoded) = storage
                .read_finalized(height)?
                .ok_or_else(|| invalid("missing finalized rotating block"))?;
            let certificate = FinalityCertificate::decode(&encoded).map_err(invalid)?;
            trusted.verify_header(&block.header, &certificate)?;
            producer.prepare_received_vrf(&block)?;
            let proposal = producer.execute_received_block(block)?;
            let diffs: Vec<_> = proposal
                .outputs
                .iter()
                .map(|output| output.diff.clone())
                .collect();
            let staged = producer
                .state
                .prepare(producer.state.root(), &diffs)
                .map_err(ExecutionError::from)?;
            let handoff = handoff_for(&proposal, &certificate, &staged)?;
            trusted.apply(&handoff)?;
            producer.state = staged;
            producer.height = trusted.current().height();
            producer.parent_hash = trusted.parent();
            producer.rotation = Some(trusted.current().clone());
            producer.contributions = None;
        }
        if producer.state.root() != head.state_root
            || producer.state.root() != storage.state().root()
            || producer.parent_hash != head.block
        {
            return Err(invalid("rotating recovery checkpoint mismatch"));
        }
        Ok((producer, trusted))
    }

    /// Explicitly enables rotation using independently authenticated committee state.
    /// The verifier establishes both committee authority and exact parent ancestry.
    /// An arbitrary decoded state cannot be used as a trust anchor. Genesis-v2 daemons
    /// activate this API explicitly. Recovery checks the exact persisted next-state bytes.
    pub fn with_rotation(mut self, trusted: &HandoffVerifier) -> Result<Self, ProducerError> {
        let current = trusted.current().clone();
        let encoded = current.to_bytes().map_err(invalid)?;
        let persisted = self.state.get(&committee_state_key());
        if self.parent_hash != trusted.parent()
            || !self.account_execution
            || self.rotation.is_some()
            || self.potb.is_some()
            || self
                .state
                .get(&consensus::potb_transition::potb_state_key())
                .is_some()
            || current.height() != self.height
            || current.chain_id() != self.chain_id()
            || current.capacity() != self.config.block_capacity
            || self.state.get(&genesis::genesis_key())
                != Some(current.genesis().as_bytes().as_slice())
            || (self.height == 1 && persisted.is_some())
            || (self.height > 1 && persisted != Some(encoded.as_slice()))
            || self.config.max_block_transactions == 0
        {
            return Err(ConsensusError::InvalidTransition.into());
        }
        remaining(self.config.block_capacity, system_resources(&current))?;
        self.rotation = Some(current);
        Ok(self)
    }

    /// Current independently supplied or durably finalized rotation state.
    #[must_use]
    pub const fn rotation_state(&self) -> Option<&CommitteeState> {
        self.rotation.as_ref()
    }

    /// Current committee for either explicitly activated rotating profile.
    #[must_use]
    pub fn active_committee_state(&self) -> Option<&CommitteeState> {
        self.potb_state()
            .map(consensus::potb_transition::PotbState::committee)
            .or(self.rotation.as_ref())
    }

    /// Installs a complete verified batch for local proposal assembly at this height.
    /// This does not change voting authority or persist the transition. Invalid
    /// replacement attempts leave any previously installed complete batch intact.
    pub fn set_vrf_batch(&mut self, batch: VrfBatch) -> Result<(), ProducerError> {
        if self
            .contributions
            .as_ref()
            .is_some_and(|verified| verified.batch == batch)
        {
            return Ok(());
        }
        let next = self
            .rotation
            .as_ref()
            .ok_or(ConsensusError::InvalidTransition)?
            .transition(&batch)?;
        self.contributions = Some(VerifiedTransition { batch, next });
        self.discard_stale_execution();
        Ok(())
    }

    /// Builds the portable witness for a fully executed and certified transition.
    /// The caller may publish this proof only after committing this same proposal
    /// durably. This method itself does not commit state or advance authority.
    pub fn rotation_handoff(
        &self,
        proposal: &BlockProposal,
        certificate: &FinalityCertificate,
    ) -> Result<CommitteeHandoff, ProducerError> {
        let current = self
            .rotation
            .as_ref()
            .ok_or(ConsensusError::InvalidTransition)?;
        current
            .context()?
            .verify_certificate(certificate, &proposal.block.header)?;
        let (staged, _) = self.prepare_verified(proposal)?;
        handoff_for(proposal, certificate, &staged)
    }

    pub(super) fn verify_rotation_certificate(
        &self,
        proposal: &BlockProposal,
        encoded: &[u8],
    ) -> Result<(), ProducerError> {
        if let Some(trusted) = &self.potb {
            let certificate = FinalityCertificate::decode(encoded).map_err(invalid)?;
            trusted.verify_header(&proposal.block.header, &certificate)?;
        }
        if let Some(current) = &self.rotation {
            let certificate = FinalityCertificate::decode(encoded).map_err(invalid)?;
            current
                .context()?
                .verify_certificate(&certificate, &proposal.block.header)?;
        }
        Ok(())
    }
    pub(super) fn check_rotation_committee(&self, root: Hash256) -> Result<(), ProducerError> {
        self.ensure_rotation_profile()?;
        if let Some(trusted) = &self.potb
            && trusted.current().committee().context()?.root() != root
        {
            return Err(ConsensusError::InvalidCommittee.into());
        }
        if let Some(current) = &self.rotation
            && current.context()?.root() != root
        {
            return Err(ConsensusError::InvalidCommittee.into());
        }
        Ok(())
    }

    pub(super) fn ensure_rotation_profile(&self) -> Result<(), ProducerError> {
        if self.potb.is_none()
            && self
                .state
                .get(&consensus::potb_transition::potb_state_key())
                .is_some()
        {
            return Err(invalid(
                "persisted PoTB state requires authenticated PoTB recovery",
            ));
        }
        if self.rotation.is_none()
            && (self.state.get(&committee_state_key()).is_some()
                || self
                    .state
                    .get(&types::StateKey(
                        types::domain::ROTATING_PROFILE_KEY.to_vec(),
                    ))
                    .is_some())
        {
            return Err(invalid(
                "persisted rotating state requires authenticated rotation recovery",
            ));
        }
        Ok(())
    }

    pub(super) fn admission_capacity(&self) -> Result<Resources, ProducerError> {
        if self.potb.is_some() {
            return self.potb_admission_capacity();
        }
        if let Some(current) = &self.rotation {
            if self.config.max_block_transactions <= 1 {
                return Err(ExecutionError::ResourceLimit.into());
            }
            remaining(self.config.block_capacity, system_resources(current))
        } else {
            Ok(self.config.block_capacity)
        }
    }

    pub(super) fn next_rotation(
        &self,
        staged: &InMemoryState,
    ) -> Result<Option<CommitteeState>, ProducerError> {
        self.rotation
            .as_ref()
            .map(|current| {
                let encoded = staged
                    .get(&committee_state_key())
                    .ok_or(ConsensusError::InvalidTransition)?;
                let next = CommitteeState::from_bytes(encoded).map_err(invalid)?;
                if current.height().checked_add(1) != Some(next.height()) {
                    return Err(ConsensusError::InvalidTransition.into());
                }
                Ok(next)
            })
            .transpose()
    }

    pub(super) fn produce_rotating_block(&self) -> Result<BlockProposal, ProducerError> {
        let current = self
            .rotation
            .as_ref()
            .ok_or(ConsensusError::InvalidTransition)?;
        let verified = self
            .contributions
            .as_ref()
            .ok_or_else(|| invalid("complete VRF batch is unavailable"))?;
        let (transaction, output) = self.system_transition(current, &verified.batch)?;
        if transaction::estimate_encoded_len(&transaction) > self.config.max_transaction_bytes {
            return Err(invalid(
                "VRF system envelope exceeds configured transaction limit",
            ));
        }
        let capacity = remaining(self.config.block_capacity, output.receipt.resources)?;
        let base = self
            .state
            .prepare(self.state.root(), std::slice::from_ref(&output.diff))
            .map_err(ExecutionError::from)?;
        let mut proposal = self.produce_application_block(
            &base,
            capacity,
            self.config.max_block_transactions - 1,
        )?;
        proposal.block.transactions.insert(0, transaction);
        proposal.outputs.insert(0, output);
        let receipts: Vec<_> = proposal
            .outputs
            .iter()
            .map(|output| output.receipt.clone())
            .collect();
        proposal.block.header.transactions_root =
            compute_transactions_root(&proposal.block.transactions);
        proposal.block.header.receipts_root = compute_receipts_root(&receipts);
        proposal.block.header.committee_root = current.context()?.root();
        proposal.resources_used = checked_resources(&receipts)?;
        Ok(proposal)
    }

    pub(super) fn execute_transactions(
        &self,
        staged: &mut InMemoryState,
        transactions: &[Transaction],
    ) -> Result<(Vec<TransactionOutput>, Hash256), ProducerError> {
        self.ensure_rotation_profile()?;
        if self.potb.is_some() {
            return self.execute_potb_transactions(staged, transactions);
        }
        let Some(current) = &self.rotation else {
            return self
                .execute_application_transactions(staged, transactions, self.config.block_capacity)
                .map_err(Into::into);
        };
        let (first, applications) = transactions
            .split_first()
            .ok_or(ConsensusError::InvalidTransition)?;
        if first.payload.len() > VrfBatch::MAX_BYTES {
            return Err(ConsensusError::InvalidTransition.into());
        }
        let batch = VrfBatch::from_bytes(&first.payload).map_err(invalid)?;
        let (expected, output) = self.system_transition(current, &batch)?;
        if *first != expected {
            return Err(ConsensusError::InvalidTransition.into());
        }
        let capacity = remaining(self.config.block_capacity, output.receipt.resources)?;
        staged
            .commit(staged.root(), std::slice::from_ref(&output.diff))
            .map_err(ExecutionError::from)?;
        let (mut outputs, root) =
            self.execute_application_transactions(staged, applications, capacity)?;
        outputs.insert(0, output);
        Ok((outputs, root))
    }
    fn system_transition(
        &self,
        current: &CommitteeState,
        batch: &VrfBatch,
    ) -> Result<(Transaction, TransactionOutput), ProducerError> {
        if let Some(verified) = &self.contributions
            && verified.batch == *batch
        {
            return system_effect(current, batch, &verified.next);
        }
        let next = current.transition(batch)?;
        system_effect(current, batch, &next)
    }

    /// Prepares a bounded verified transition cache for repeated execution of an imported block.
    /// Header/body execution and certificate validation remain mandatory. Cached authority is never
    /// installed: only a successful finalized commit changes the current committee.
    pub fn prepare_received_vrf(&mut self, block: &types::Block) -> Result<(), ProducerError> {
        if self.rotation.is_none() && self.potb.is_none() {
            return Ok(());
        }
        if block.header.height != self.height || block.header.parent != self.parent_hash {
            return Err(ConsensusError::InvalidTransition.into());
        }
        let first = block
            .transactions
            .first()
            .filter(|tx| tx.lane == TransactionLane::System)
            .ok_or(ConsensusError::InvalidTransition)?;
        if self.potb.is_some() {
            self.set_potb_batch(
                consensus::potb_transition::PotbBatch::from_bytes(&first.payload)
                    .map_err(invalid)?,
            )
        } else {
            self.set_vrf_batch(VrfBatch::from_bytes(&first.payload).map_err(invalid)?)
        }
    }
}

fn handoff_for(
    proposal: &BlockProposal,
    certificate: &FinalityCertificate,
    staged: &InMemoryState,
) -> Result<CommitteeHandoff, ProducerError> {
    let first = proposal
        .block
        .transactions
        .first()
        .ok_or(ConsensusError::InvalidTransition)?;
    let contributions = VrfBatch::from_bytes(&first.payload).map_err(invalid)?;
    Ok(CommitteeHandoff {
        header: proposal.block.header,
        certificate: certificate.clone(),
        contributions,
        next_state: StateValueProof::create(
            staged.snapshot().map_err(ExecutionError::from)?.as_ref(),
            &committee_state_key(),
        )
        .map_err(ExecutionError::from)?,
    })
}

fn system_effect(
    current: &CommitteeState,
    batch: &VrfBatch,
    next: &CommitteeState,
) -> Result<(Transaction, TransactionOutput), ProducerError> {
    let encoded = next.to_bytes().map_err(invalid)?;
    let resources = system_resources(current);
    let transaction = Transaction {
        version: types::TRANSACTION_VERSION,
        chain_id: current.chain_id(),
        expires_at: current.height(),
        nonce: current.height(),
        sender: Address::ZERO,
        lane: TransactionLane::System,
        resource_prices: Resources::ZERO,
        resource_limit: resources,
        access_list: vec![committee_state_key()],
        payload: batch.to_bytes().map_err(invalid)?,
        signature: [0; 64],
    };
    let mut diff = StateDiff::new();
    diff.put(committee_state_key(), encoded.clone());
    let output = TransactionOutput {
        diff,
        receipt: ExecutionReceipt {
            transaction: hash_transaction(&transaction),
            succeeded: true,
            resources,
            output_root: types::hash::domain_hash(b"astrolune.rotation.effect.v1", &encoded),
        },
        observed_lease: StateLease {
            requests: vec![AccessRequest {
                key: committee_state_key(),
                mode: AccessMode::Write,
            }],
        },
    };
    Ok((transaction, output))
}

// Fixed protocol charges, not wall-clock timing. The byte bounds cover the full
// 32-member envelope and state; applications receive only the remaining budget.
fn system_resources(current: &CommitteeState) -> Resources {
    Resources {
        compute: 10_000 * current.roster().len() as u64,
        memory: 16 * 1024,
        io: 4096,
        bandwidth: 12 * 1024,
    }
}

pub(super) fn remaining(capacity: Resources, used: Resources) -> Result<Resources, ProducerError> {
    if !used.fits_in(capacity) {
        return Err(ExecutionError::ResourceLimit.into());
    }
    Ok(Resources {
        compute: capacity.compute - used.compute,
        memory: capacity.memory - used.memory,
        io: capacity.io - used.io,
        bandwidth: capacity.bandwidth - used.bandwidth,
    })
}

fn invalid(error: impl std::fmt::Display) -> ProducerError {
    ProducerError::Assembly(error.to_string())
}
