// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Explicit trust pins for bounded retained history; never inferred from storage.

use super::{NetworkNodeError, StaticNetwork, input, local};
use crate::BlockProducer;
use codec::Decoder;
use consensus::{
    history::CommitteeHistory, potb_transition::PotbVerifier, rotation::HandoffVerifier,
};
use state::{InMemoryState, StateDatabase, StateValueProof};
use storage::{ChainStorage, Checkpoint};
use types::{Hash256, hash::domain_hash};

/// An independently pinned recovery boundary. The pin authenticates the complete
/// checkpoint and, for legacy rotation, its committee history frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCheckpoint {
    namespace: Hash256,
    checkpoint: Checkpoint,
    history: Option<CommitteeHistory>,
}
impl RecoveryCheckpoint {
    /// Fixed coordinates plus the bounded optional history frontier.
    pub const MAX_BYTES: usize = 116 + CommitteeHistory::MAX_BYTES;
    /// Coordinates authenticated by this explicit pin.
    #[must_use]
    pub const fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }
    /// Exact canonical pin material; contains no secret keys or snapshot data.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Private validated history is at most 2 KiB.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = b"ALANCH01".to_vec();
        bytes.extend_from_slice(&self.namespace.0);
        bytes.extend_from_slice(&self.checkpoint.height.to_le_bytes());
        bytes.extend_from_slice(&self.checkpoint.block.0);
        bytes.extend_from_slice(&self.checkpoint.state_root.0);
        let history = self
            .history
            .as_ref()
            .map_or_else(Vec::new, CommitteeHistory::to_bytes);
        bytes.extend_from_slice(&(history.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&history);
        bytes
    }
    /// Pin to retain independently of the exported directory.
    #[must_use]
    pub fn id(&self) -> Hash256 {
        domain_hash(b"astrolune.recovery.checkpoint.v1", &self.to_bytes())
    }
    /// Requires an independently supplied pin; bytes cannot choose their own authority.
    pub fn from_bytes(bytes: &[u8], expected: Hash256) -> Result<Self, NetworkNodeError> {
        if bytes.len() > Self::MAX_BYTES
            || domain_hash(b"astrolune.recovery.checkpoint.v1", bytes) != expected
        {
            return Err(input("recovery checkpoint pin mismatch"));
        }
        let decode = || -> Result<Self, codec::DecodeError> {
            let mut reader = Decoder::new(bytes);
            if reader.read_exact(8)? != b"ALANCH01" {
                return Err(codec::DecodeError::Unsupported);
            }
            let namespace = Hash256(reader.read_fixed()?);
            let checkpoint = Checkpoint {
                height: reader.read_u64()?,
                block: Hash256(reader.read_fixed()?),
                state_root: Hash256(reader.read_fixed()?),
            };
            let length = usize::try_from(reader.read_u32()?)
                .map_err(|_| codec::DecodeError::LimitExceeded)?;
            let history = if length == 0 {
                None
            } else {
                Some(CommitteeHistory::from_bytes(reader.read_exact(length)?)?)
            };
            reader.finish()?;
            if checkpoint.height == 0
                || checkpoint.height == u64::MAX
                || checkpoint.block.is_zero()
                || namespace.is_zero()
            {
                return Err(codec::DecodeError::NonCanonical);
            }
            Ok(Self {
                namespace,
                checkpoint,
                history,
            })
        };
        decode().map_err(input)
    }
}

impl StaticNetwork {
    pub(super) fn pinned_authorities(
        &self,
        storage: &ChainStorage,
    ) -> Result<(Option<PotbVerifier>, Option<HandoffVerifier>), NetworkNodeError> {
        let point = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| input("missing checkpoint"))?;
        let (cp, state) = storage
            .read_anchor()
            .map_err(local)?
            .ok_or_else(|| input("missing anchor"))?;
        if cp != point.checkpoint {
            return Err(input("anchor pin mismatch"));
        }
        let snapshot = state.snapshot().map_err(input)?;
        if self.potb() {
            let proof = StateValueProof::create(
                snapshot.as_ref(),
                &consensus::potb_transition::potb_state_key(),
            )
            .map_err(input)?;
            Ok((
                Some(
                    PotbVerifier::from_checkpoint(cp.height, cp.block, cp.state_root, &proof)
                        .map_err(input)?,
                ),
                None,
            ))
        } else if self.rotating() {
            let proof = StateValueProof::create(
                snapshot.as_ref(),
                &consensus::rotation::committee_state_key(),
            )
            .map_err(input)?;
            Ok((
                None,
                Some(
                    HandoffVerifier::from_checkpoint(
                        cp.height,
                        cp.block,
                        cp.state_root,
                        &proof,
                        point
                            .history
                            .clone()
                            .ok_or_else(|| input("missing history"))?,
                    )
                    .map_err(input)?,
                ),
            ))
        } else {
            Ok((None, None))
        }
    }

    /// Selects an independently pinned start point, retaining the same network identity.
    pub fn with_checkpoint(
        mut self,
        checkpoint: RecoveryCheckpoint,
    ) -> Result<Self, NetworkNodeError> {
        if checkpoint.namespace != self.hash
            || checkpoint.history.is_some() != (self.rotating() && !self.potb())
        {
            return Err(input("checkpoint profile mismatch"));
        }
        if let Some(history) = &checkpoint.history
            && (history.chain_id() != self.chain_id()
                || history.genesis() != self.hash
                || history.entries() != checkpoint.checkpoint.height)
        {
            return Err(input("checkpoint history mismatch"));
        }
        self.checkpoint = Some(checkpoint);
        Ok(self)
    }

    pub(super) fn recover_checkpoint(
        &self,
        storage: &ChainStorage,
    ) -> Result<BlockProducer, NetworkNodeError> {
        let point = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| input("explicit checkpoint required"))?;
        let (anchor, state) = storage
            .read_anchor()
            .map_err(local)?
            .ok_or_else(|| input("missing retained anchor"))?;
        if anchor != point.checkpoint {
            return Err(input("stored anchor differs from independent pin"));
        }
        let head = storage
            .checkpoint()
            .copied()
            .ok_or_else(|| input("missing retained head"))?;
        if head
            .height
            .checked_sub(anchor.height)
            .and_then(|n| usize::try_from(n).ok())
            != Some(storage.block_count())
        {
            return Err(input("incomplete retained suffix"));
        }
        let mut producer = self.checkpoint_producer(point, state)?;
        for height in anchor.height + 1..=head.height {
            let (block, bytes) = storage
                .read_finalized(height)
                .map_err(local)?
                .ok_or_else(|| input("missing retained block"))?;
            let certificate = consensus::FinalityCertificate::decode(&bytes).map_err(input)?;
            let committee = self.current_committee(&producer)?;
            producer.replay_certified(block, &certificate, &committee)?;
        }
        if producer.state().root() != head.state_root
            || producer.state().root() != storage.state().root()
            || producer.parent_hash() != head.block
        {
            return Err(input("retained checkpoint replay mismatch"));
        }
        Ok(producer)
    }

    fn checkpoint_producer(
        &self,
        point: &RecoveryCheckpoint,
        state: InMemoryState,
    ) -> Result<BlockProducer, NetworkNodeError> {
        let cp = point.checkpoint;
        if cp.state_root != state.root()
            || state.get(&genesis::genesis_key()) != Some(self.hash.as_bytes().as_slice())
        {
            return Err(input("checkpoint state mismatch"));
        }
        let mut config = self.producer_config();
        let snapshot = state.snapshot().map_err(input)?;
        if let Some(profile) = &self.potb {
            let proof = StateValueProof::create(
                snapshot.as_ref(),
                &consensus::potb_transition::potb_state_key(),
            )
            .map_err(input)?;
            let trusted = PotbVerifier::from_checkpoint(cp.height, cp.block, cp.state_root, &proof)
                .map_err(input)?;
            let current = trusted.current();
            if current.committee().genesis() != self.hash
                || current.committee().chain_id() != self.chain_id()
                || current.policy() != profile.policy()
                || current
                    .governance()
                    .map(consensus::governance::GovernanceState::policy)
                    != profile.governance()
            {
                return Err(input("checkpoint policy mismatch"));
            }
            config.block_capacity = current.committee().capacity();
            return BlockProducer::from_checkpoint(config, Some(cp), state)?
                .with_potb(&trusted)
                .map_err(Into::into);
        }
        if self.rotating() {
            let proof = StateValueProof::create(
                snapshot.as_ref(),
                &consensus::rotation::committee_state_key(),
            )
            .map_err(input)?;
            let trusted = HandoffVerifier::from_checkpoint(
                cp.height,
                cp.block,
                cp.state_root,
                &proof,
                point
                    .history
                    .clone()
                    .ok_or_else(|| input("missing history frontier"))?,
            )
            .map_err(input)?;
            if trusted.current().genesis() != self.hash
                || trusted.current().chain_id() != self.chain_id()
                || trusted.current().capacity() != self.genesis.capacity
            {
                return Err(input("checkpoint committee mismatch"));
            }
            return BlockProducer::from_checkpoint(config, Some(cp), state)?
                .with_rotation(&trusted)
                .map_err(Into::into);
        }
        if state
            .get(&consensus::rotation::committee_state_key())
            .is_some()
            || state
                .get(&consensus::potb_transition::potb_state_key())
                .is_some()
        {
            return Err(input("checkpoint execution profile mismatch"));
        }
        BlockProducer::from_checkpoint(config, Some(cp), state).map_err(Into::into)
    }

    /// Exports a bounded suffix to a NEW directory after verifying source history.
    /// Keeps 0..=64 bodies; the chosen anchor must still be in the recent state index.
    /// The original is retained and the returned pin must be stored independently.
    pub fn export_retained(
        &self,
        source: &ChainStorage,
        retained: u64,
        destination: &std::path::Path,
    ) -> Result<RecoveryCheckpoint, NetworkNodeError> {
        if retained > storage::MAX_STATE_HISTORY_BLOCKS as u64 {
            return Err(input("retained count exceeds historical index bound"));
        }
        let head = self.verify_storage(source)?;
        let floor = head
            .height
            .checked_sub(retained)
            .filter(|height| *height > 0)
            .ok_or_else(|| input("retention requires a positive checkpoint height"))?;
        let (cp, state) = source
            .read_state_at(floor)
            .map_err(local)?
            .ok_or_else(|| input("requested checkpoint is outside the retained state index"))?;
        let point = RecoveryCheckpoint {
            namespace: self.hash,
            checkpoint: cp,
            history: self.retained_history(source, floor)?,
        };
        let network = self.clone().with_checkpoint(point.clone())?;
        let mut producer = network.checkpoint_producer(&point, state.clone())?;
        std::fs::create_dir(destination).map_err(local)?;
        let mut output = ChainStorage::open(destination.join("chain.bin")).map_err(local)?;
        output.initialize_checkpoint(cp, state).map_err(local)?;
        for height in floor + 1..=head.height {
            let (block, bytes) = source
                .read_finalized(height)
                .map_err(local)?
                .ok_or_else(|| input("missing export block"))?;
            let certificate = consensus::FinalityCertificate::decode(&bytes).map_err(input)?;
            let committee = network.current_committee(&producer)?;
            producer.prepare_received_vrf(&block)?;
            let proposal = producer.execute_received_block(block)?;
            producer.commit_certified_block(&proposal, &certificate, &committee, &mut output)?;
        }
        if network.verify_storage(&output)? != head {
            return Err(input("retained export verification mismatch"));
        }
        Ok(point)
    }

    fn retained_history(
        &self,
        source: &ChainStorage,
        floor: u64,
    ) -> Result<Option<CommitteeHistory>, NetworkNodeError> {
        if !self.rotating() || self.potb() {
            return Ok(None);
        }
        let (mut history, first) = match &self.checkpoint {
            Some(point) => (
                point
                    .history
                    .clone()
                    .ok_or_else(|| input("missing pinned history"))?,
                point.checkpoint.height + 1,
            ),
            None => (
                CommitteeHistory::new(self.chain_id(), self.hash).map_err(input)?,
                1,
            ),
        };
        if floor < first - 1 {
            return Err(input("retention cannot precede its trust pin"));
        }
        // Source was fully authenticated above; verify each stored outgoing context again.
        let mut trusted = if let Some(point) = &self.checkpoint {
            let (_, state) = source
                .read_anchor()
                .map_err(local)?
                .ok_or_else(|| input("missing anchor"))?;
            let proof = StateValueProof::create(
                state.snapshot().map_err(input)?.as_ref(),
                &consensus::rotation::committee_state_key(),
            )
            .map_err(input)?;
            HandoffVerifier::from_checkpoint(
                point.checkpoint.height,
                point.checkpoint.block,
                point.checkpoint.state_root,
                &proof,
                history.clone(),
            )
            .map_err(input)?
        } else {
            HandoffVerifier::new(&self.genesis, &self.keys).map_err(input)?
        };
        for height in first..=floor {
            trusted
                .apply(
                    &crate::handoff::read_handoff(source, height)
                        .map_err(local)?
                        .ok_or_else(|| input("missing handoff"))?,
                )
                .map_err(input)?;
        }
        history = trusted.history().clone();
        Ok(Some(history))
    }
}
