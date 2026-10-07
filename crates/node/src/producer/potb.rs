// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit `PoTB` system execution, atomic storage publication and authenticated replay.

use super::{
    BlockProducer, BlockProposal, ProducerConfig, ProducerError, checked_resources,
    compute_receipts_root, compute_transactions_root, hash_transaction, rotation::remaining,
};
use consensus::{
    ConsensusError, FinalityCertificate,
    potb_transition::{
        PotbBatch, PotbConfiguration, PotbHandoff, PotbState, PotbVerifier, potb_state_key,
    },
};
use execution::{ExecutionError, TransactionOutput};
use state::{
    AccessMode, AccessRequest, InMemoryState, StateDatabase, StateDiff, StateLease, StateValueProof,
};
use types::{Address, ExecutionReceipt, Hash256, Resources, Transaction, TransactionLane};

impl BlockProducer {
    /// Activates the separate `PoTB` profile only from independently authenticated
    /// authority and exact persisted state. Legacy profiles cannot be rebound.
    pub fn with_potb(mut self, trusted: &PotbVerifier) -> Result<Self, ProducerError> {
        let current = trusted.current();
        let committee = current.committee();
        let encoded = current.to_bytes().map_err(invalid)?;
        if self.potb.is_some()
            || self.rotation.is_some()
            || !self.account_execution
            || self.parent_hash != trusted.parent()
            || self.height != committee.height()
            || self.config.chain_id != committee.chain_id()
            || self.config.block_capacity != committee.capacity()
            || self.config.max_block_transactions == 0
            || self.state.get(&potb_state_key()) != Some(encoded.as_slice())
            || self.state.get(&genesis::genesis_key())
                != Some(committee.genesis().as_bytes().as_slice())
            || self
                .state
                .get(&consensus::rotation::committee_state_key())
                .is_some()
            || self
                .state
                .get(&types::StateKey(
                    types::domain::ROTATING_PROFILE_KEY.to_vec(),
                ))
                .is_some()
        {
            return Err(ConsensusError::InvalidTransition.into());
        }
        remaining(self.config.block_capacity, minimum_resources(current))?;
        self.potb = Some(trusted.clone());
        Ok(self)
    }

    /// Durably finalized `PoTB` authority, never the pending staged batch.
    #[must_use]
    pub fn potb_state(&self) -> Option<&PotbState> {
        self.potb.as_ref().map(PotbVerifier::current)
    }

    /// Verifies one bounded candidate batch without changing state or authority.
    /// Failed replacements preserve the existing candidate for retry.
    pub fn set_potb_batch(&mut self, batch: PotbBatch) -> Result<(), ProducerError> {
        if self
            .potb_batch
            .as_ref()
            .is_some_and(|(old, _)| *old == batch)
        {
            return Ok(());
        }
        let current = self.potb_state().ok_or(ConsensusError::InvalidTransition)?;
        remaining(
            self.config.block_capacity,
            system_resources(current, &batch)?,
        )?;
        let next = current.stage(self.parent_hash, &batch)?;
        let (tx, _) = system_effect(current, &batch, &next)?;
        if transaction::estimate_encoded_len(&tx) > self.config.max_transaction_bytes {
            return Err(invalid("PoTB system envelope exceeds transaction limit"));
        }
        self.potb_batch = Some((batch, next));
        self.clear_execution();
        Ok(())
    }

    pub(super) fn potb_admission_capacity(&self) -> Result<Resources, ProducerError> {
        if self.config.max_block_transactions <= 1 {
            return Err(ExecutionError::ResourceLimit.into());
        }
        remaining(
            self.config.block_capacity,
            minimum_resources(self.potb_state().ok_or(ConsensusError::InvalidTransition)?),
        )
    }

    pub(super) fn produce_potb_block(&self) -> Result<BlockProposal, ProducerError> {
        let current = self.potb_state().ok_or(ConsensusError::InvalidTransition)?;
        let (batch, next) = self
            .potb_batch
            .as_ref()
            .ok_or_else(|| invalid("complete PoTB batch is unavailable"))?;
        let (transaction, output) = system_effect(current, batch, next)?;
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
        let receipts: Vec<_> = proposal.outputs.iter().map(|o| o.receipt.clone()).collect();
        proposal.block.header.transactions_root =
            compute_transactions_root(&proposal.block.transactions);
        proposal.block.header.receipts_root = compute_receipts_root(&receipts);
        proposal.block.header.committee_root = current.committee().context()?.root();
        proposal.resources_used = checked_resources(&receipts)?;
        Ok(proposal)
    }

    pub(super) fn execute_potb_transactions(
        &self,
        staged: &mut InMemoryState,
        transactions: &[Transaction],
    ) -> Result<(Vec<TransactionOutput>, Hash256), ProducerError> {
        let current = self.potb_state().ok_or(ConsensusError::InvalidTransition)?;
        let (first, applications) = transactions
            .split_first()
            .ok_or(ConsensusError::InvalidTransition)?;
        let batch = PotbBatch::from_bytes(&first.payload).map_err(invalid)?;
        let next = if let Some((old, next)) = &self.potb_batch
            && *old == batch
        {
            next.clone()
        } else {
            current.stage(self.parent_hash, &batch)?
        };
        let (expected, output) = system_effect(current, &batch, &next)?;
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

    /// Builds the portable handoff for this fully executed, old-quorum-certified
    /// proposal. Publication still requires a successful durable block commit.
    pub fn potb_handoff(
        &self,
        proposal: &BlockProposal,
        certificate: &FinalityCertificate,
    ) -> Result<PotbHandoff, ProducerError> {
        let trusted = self
            .potb
            .as_ref()
            .ok_or(ConsensusError::InvalidTransition)?;
        trusted.verify_header(&proposal.block.header, certificate)?;
        let (staged, _) = self.prepare_verified(proposal)?;
        handoff_for(proposal, certificate, &staged)
    }

    pub(super) fn next_potb(
        &self,
        proposal: &BlockProposal,
        encoded: &[u8],
        staged: &InMemoryState,
    ) -> Result<Option<PotbVerifier>, ProducerError> {
        let Some(trusted) = &self.potb else {
            return Ok(None);
        };
        let certificate = FinalityCertificate::decode(encoded).map_err(invalid)?;
        let handoff = handoff_for(proposal, &certificate, staged)?;
        let mut next = trusted.clone();
        next.apply(&handoff)?;
        Ok(Some(next))
    }

    /// Re-executes all stored system and application transitions from the supplied
    /// configuration. Saved state cannot choose its own history, policy or weights.
    /// No signing or writes occur; rollback protection requires an external anchor.
    pub fn recover_potb(
        config: ProducerConfig,
        profile: &PotbConfiguration,
        keys: &[[u8; 32]],
        storage: &storage::ChainStorage,
    ) -> Result<(Self, PotbVerifier), ProducerError> {
        let head = storage
            .checkpoint()
            .copied()
            .ok_or_else(|| invalid("missing PoTB checkpoint"))?;
        if usize::try_from(head.height).ok() != Some(storage.block_count()) {
            return Err(invalid("PoTB recovery requires complete history"));
        }
        let mut trusted = PotbVerifier::new(profile, keys)?;
        let initial = profile.materialize(keys)?;
        let checkpoint = storage::Checkpoint {
            height: 0,
            block: trusted.parent(),
            state_root: initial.root(),
        };
        let mut producer =
            Self::from_checkpoint(config, Some(checkpoint), initial)?.with_potb(&trusted)?;
        for height in 1..=head.height {
            let (block, encoded) = storage
                .read_finalized(height)?
                .ok_or_else(|| invalid("missing finalized PoTB block"))?;
            let certificate = FinalityCertificate::decode(&encoded).map_err(invalid)?;
            trusted.verify_header(&block.header, &certificate)?;
            let proposal = producer.execute_received_block(block)?;
            let (staged, _) = producer.prepare_verified(&proposal)?;
            trusted.apply(&handoff_for(&proposal, &certificate, &staged)?)?;
            producer.state = staged;
            producer.height = trusted.current().committee().height();
            producer.parent_hash = trusted.parent();
            producer.config.block_capacity = trusted.current().committee().capacity();
            producer.potb = Some(trusted.clone());
        }
        if producer.state.root() != head.state_root
            || producer.state.root() != storage.state().root()
            || producer.parent_hash != head.block
        {
            return Err(invalid("PoTB recovery checkpoint mismatch"));
        }
        Ok((producer, trusted))
    }
}

fn handoff_for(
    proposal: &BlockProposal,
    certificate: &FinalityCertificate,
    staged: &InMemoryState,
) -> Result<PotbHandoff, ProducerError> {
    let first = proposal
        .block
        .transactions
        .first()
        .ok_or(ConsensusError::InvalidTransition)?;
    Ok(PotbHandoff {
        header: proposal.block.header,
        certificate: certificate.clone(),
        batch: PotbBatch::from_bytes(&first.payload).map_err(invalid)?,
        next_state: StateValueProof::create(
            staged.snapshot().map_err(ExecutionError::from)?.as_ref(),
            &potb_state_key(),
        )
        .map_err(ExecutionError::from)?,
    })
}

fn system_effect(
    current: &PotbState,
    batch: &PotbBatch,
    next: &PotbState,
) -> Result<(Transaction, TransactionOutput), ProducerError> {
    let encoded = next.to_bytes().map_err(invalid)?;
    let resources = system_resources(current, batch)?;
    let committee = current.committee();
    let transaction = Transaction {
        version: types::TRANSACTION_VERSION,
        chain_id: committee.chain_id(),
        expires_at: committee.height(),
        nonce: committee.height(),
        sender: Address::ZERO,
        lane: TransactionLane::System,
        resource_prices: Resources::ZERO,
        resource_limit: resources,
        access_list: vec![potb_state_key()],
        payload: batch.to_bytes().map_err(invalid)?,
        signature: [0; 64],
    };
    let mut diff = StateDiff::new();
    diff.put(potb_state_key(), encoded.clone());
    let output = TransactionOutput {
        diff,
        receipt: ExecutionReceipt {
            transaction: hash_transaction(&transaction),
            succeeded: true,
            resources,
            output_root: types::hash::domain_hash(b"astrolune.potb.effect.v1", &encoded),
        },
        observed_lease: StateLease {
            requests: vec![AccessRequest {
                key: potb_state_key(),
                mode: AccessMode::Write,
            }],
        },
    };
    Ok((transaction, output))
}

// Fixed integer protocol charges. Every count is already bounded by the codecs;
// actual elapsed time, certificate subset and host concurrency have no effect.
fn system_resources(current: &PotbState, batch: &PotbBatch) -> Result<Resources, ProducerError> {
    let bytes = batch.to_bytes().map_err(invalid)?.len() as u64;
    let approvals: usize = batch
        .admissions()
        .iter()
        .map(|a| a.voters().count())
        .sum::<usize>()
        + batch.governance().map_or(0, |a| a.voters().count());
    Ok(Resources {
        compute: 10_000 * batch.contributions().entries().len() as u64
            + 25_000 * batch.evidence().len() as u64
            + 2_000 * approvals as u64,
        memory: 16 * 1024 + current.encoded_bound() as u64 + bytes,
        io: current.encoded_bound() as u64,
        bandwidth: bytes + 512,
    })
}

fn minimum_resources(state: &PotbState) -> Resources {
    let count = state.committee().roster().len() as u64;
    let bytes = 23 + consensus::rotation::VrfContribution::BYTES as u64 * count;
    Resources {
        compute: 10_000 * count,
        memory: 16 * 1024 + state.encoded_bound() as u64 + bytes,
        io: state.encoded_bound() as u64,
        bandwidth: bytes + 512,
    }
}

fn invalid(error: impl std::fmt::Display) -> ProducerError {
    ProducerError::Assembly(error.to_string())
}
