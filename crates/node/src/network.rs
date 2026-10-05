// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Fixed-membership reference network with durable voting and certified catch-up.

mod checkpoint;
mod potb;
mod rotation;
pub use checkpoint::RecoveryCheckpoint;

use crate::network_wire::{
    MAX_EXCHANGE_BYTES, MAX_TRANSACTION_BYTES, NetworkMessage, SyncRequest, decode_exchange,
    encode_block, encode_exchange,
};
use crate::{
    BlockProducer, ProducerConfig, ProducerError, RoundRobinValidator, SignedBlockProposal,
    TimeoutEvent, ValidatorError,
};
use consensus::potb_transition::{PotbConfiguration, PotbVerifier};
use consensus::rotation::{ContributionPool, HandoffVerifier, VrfContribution};
use consensus::{
    AuthenticatedCommittee, Committee, CommitteeMember, LocalBft, LocalBftError, PotbWeight,
    PrevoteCertificate, Vote, VotePhase, VotingStep,
};
use keystore::{ChainSigner, DurableSigner, KeystoreError, Signer};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use storage::ChainStorage;
use types::{Block, Hash256, Transaction, ValidatorId};

/// The reference driver deliberately bounds membership and retains a fixed committee.
pub const MAX_NETWORK_VALIDATORS: usize = 32;

/// Shared authenticated recovery state for voting and non-voting network nodes.
pub(crate) struct RecoveredNetwork {
    pub(crate) storage: ChainStorage,
    pub(crate) producer: BlockProducer,
}

/// Distinguishes untrusted peer input from local durability failures that must stop signing.
#[derive(Debug)]
pub enum NetworkNodeError {
    /// Malformed, stale, unauthenticated, or incompatible input.
    Input(String),
    /// Local storage/signing failure; the daemon must stop and recover.
    Local(String),
}

/// An owned response snapshot that can be encoded after releasing the node lock.
///
/// Preparation retains the selected messages independently of later node changes.
/// Encoding uses the same bounded reference-network codec as [`NetworkNode::respond`].
pub struct PreparedResponse {
    genesis: Hash256,
    messages: Vec<NetworkMessage>,
}

impl PreparedResponse {
    pub(crate) fn new(genesis: Hash256, messages: Vec<NetworkMessage>) -> Self {
        Self { genesis, messages }
    }

    /// Consumes the snapshot and encodes its messages without accessing the node.
    pub fn encode(self) -> Result<Vec<u8>, NetworkNodeError> {
        encode_exchange(self.genesis, &self.messages).map_err(input)
    }
}

impl std::fmt::Display for NetworkNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(message) | Self::Local(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for NetworkNodeError {}
impl From<ProducerError> for NetworkNodeError {
    fn from(error: ProducerError) -> Self {
        if matches!(error, ProducerError::Storage(_)) {
            Self::Local(error.to_string())
        } else {
            Self::Input(error.to_string())
        }
    }
}
impl From<ValidatorError> for NetworkNodeError {
    fn from(error: ValidatorError) -> Self {
        match error {
            ValidatorError::Production(error) => error.into(),
            ValidatorError::Voting(LocalBftError::Signing(error))
                if error != KeystoreError::ConflictingSign =>
            {
                Self::Local(error.to_string())
            }
            ValidatorError::Voting(_) => Self::Input(error.to_string()),
        }
    }
}
pub(crate) fn input(error: impl std::fmt::Display) -> NetworkNodeError {
    NetworkNodeError::Input(error.to_string())
}
pub(crate) fn local(error: impl std::fmt::Display) -> NetworkNodeError {
    NetworkNodeError::Local(error.to_string())
}

/// Independently supplied genesis and exact registered keys; peer data cannot change them.
#[derive(Clone)]
pub struct StaticNetwork {
    genesis: genesis::Genesis,
    hash: Hash256,
    keys: Vec<[u8; 32]>,
    potb: Option<PotbConfiguration>,
    checkpoint: Option<RecoveryCheckpoint>,
}
impl StaticNetwork {
    /// Explicitly selects all genesis validators for the fixed round-robin profile.
    pub fn new(genesis: genesis::Genesis, keys: Vec<[u8; 32]>) -> Result<Self, NetworkNodeError> {
        let hash = genesis.commitment().map_err(input)?;
        if (genesis.version == genesis::GENESIS_VERSION
            && genesis.committee_size != genesis.validators.len())
            || keys.len() > MAX_NETWORK_VALIDATORS
        {
            return Err(input(
                "reference network requires the complete genesis committee, at most 32 validators",
            ));
        }
        let result = Self {
            genesis,
            hash,
            keys,
            potb: None,
            checkpoint: None,
        };
        result.committee(1)?;
        if result.rotating() {
            HandoffVerifier::new(&result.genesis, &result.keys).map_err(input)?;
        }
        Ok(result)
    }

    /// Explicit `PoTB` configuration supplies a distinct namespace and immutable policy.
    pub fn with_potb(
        configuration: PotbConfiguration,
        keys: Vec<[u8; 32]>,
    ) -> Result<Self, NetworkNodeError> {
        PotbVerifier::new(&configuration, &keys).map_err(input)?;
        Ok(Self {
            genesis: configuration.genesis().clone(),
            hash: configuration.commitment(),
            keys,
            potb: Some(configuration),
            checkpoint: None,
        })
    }

    /// Decodes an independently supplied genesis or explicitly tagged `PoTB` configuration.
    pub fn decode(bytes: &[u8], keys: Vec<[u8; 32]>) -> Result<Self, NetworkNodeError> {
        use codec::CanonicalDecode;
        if consensus::potb_transition::PotbConfiguration::is_envelope(bytes) {
            Self::with_potb(PotbConfiguration::from_bytes(bytes).map_err(input)?, keys)
        } else {
            Self::new(genesis::Genesis::decode(bytes).map_err(input)?, keys)
        }
    }

    /// Whether the independently supplied configuration activates `PoTB`.
    #[must_use]
    pub const fn potb(&self) -> bool {
        self.potb.is_some()
    }
    /// Trusted genesis namespace.
    #[must_use]
    pub const fn genesis_hash(&self) -> Hash256 {
        self.hash
    }
    /// Chain identifier exposed to RPC clients.
    #[must_use]
    pub const fn chain_id(&self) -> u32 {
        self.genesis.chain_id
    }
    /// Whether independently configured genesis explicitly activates VRF rotation.
    #[must_use]
    pub const fn rotating(&self) -> bool {
        self.genesis.version == genesis::ROTATING_GENESIS_VERSION
    }
    pub(crate) fn current_committee(
        &self,
        producer: &BlockProducer,
    ) -> Result<AuthenticatedCommittee, NetworkNodeError> {
        if producer.potb_state().is_some() != self.potb() {
            return Err(input(
                "execution profile disagrees with trusted configuration",
            ));
        }
        match producer.active_committee_state() {
            Some(current) if self.rotating() => current.context().map_err(input),
            None if !self.rotating() => self.committee(producer.height()),
            _ => Err(input("execution profile disagrees with trusted genesis")),
        }
    }
    /// Reconstructs a height-bound context from trusted immutable membership.
    pub fn committee(&self, height: u64) -> Result<AuthenticatedCommittee, NetworkNodeError> {
        if self.rotating() && height != 1 {
            return Err(input("rotating authority requires verified handoffs"));
        }
        AuthenticatedCommittee::new(
            self.genesis.chain_id,
            &Committee {
                height,
                members: self
                    .genesis
                    .validators
                    .iter()
                    .map(|member| CommitteeMember {
                        id: member.id,
                        power: PotbWeight(member.weight),
                    })
                    .collect(),
            },
            &self.keys,
        )
        .map_err(input)
    }
    pub(crate) fn recover(&self, directory: &Path) -> Result<RecoveredNetwork, NetworkNodeError> {
        let network = self;
        let initial = if let Some(profile) = &self.potb {
            profile.materialize(&self.keys).map_err(input)?
        } else {
            network.genesis.materialize().map_err(input)?
        };
        if self.checkpoint.is_some() && !directory.join("chain.bin").is_file() {
            return Err(input("pinned recovery requires existing retained history"));
        }
        let mut storage = ChainStorage::open(directory.join("chain.bin")).map_err(local)?;
        if self.checkpoint.is_some() {
            let producer = self.recover_checkpoint(&storage)?;
            return Ok(RecoveredNetwork { storage, producer });
        }
        if storage.checkpoint().is_none() {
            storage
                .initialize_genesis(network.hash, initial.clone())
                .map_err(local)?;
        }
        if let Some(profile) = &self.potb {
            let (producer, _) =
                BlockProducer::recover_potb(self.producer_config(), profile, &self.keys, &storage)?;
            return Ok(RecoveredNetwork { storage, producer });
        }
        if self.rotating() {
            let (producer, _) = BlockProducer::recover_rotation(
                self.producer_config(),
                &self.genesis,
                &self.keys,
                &storage,
            )?;
            return Ok(RecoveredNetwork { storage, producer });
        }
        let checkpoint = self.verify_storage(&storage)?;
        let producer = BlockProducer::from_checkpoint(
            network.producer_config(),
            Some(checkpoint),
            storage.state().clone(),
        )?;
        Ok(RecoveredNetwork { storage, producer })
    }

    /// Authenticates every retained certificate and complete ancestry against trusted genesis.
    /// Storage must already have passed its structural replay and state-root recovery checks.
    /// No signing authority is needed; coherent rollback requires a separate minimum-height anchor.
    pub fn verify_storage(
        &self,
        storage: &ChainStorage,
    ) -> Result<storage::Checkpoint, NetworkNodeError> {
        if self.checkpoint.is_some() {
            self.recover_checkpoint(storage)?;
            return storage
                .checkpoint()
                .copied()
                .ok_or_else(|| input("missing retained checkpoint"));
        }
        if let Some(profile) = &self.potb {
            BlockProducer::recover_potb(self.producer_config(), profile, &self.keys, storage)?;
            return storage
                .checkpoint()
                .copied()
                .ok_or_else(|| local("missing checkpoint"));
        }
        if self.rotating() {
            BlockProducer::recover_rotation(
                self.producer_config(),
                &self.genesis,
                &self.keys,
                storage,
            )?;
            return storage
                .checkpoint()
                .copied()
                .ok_or_else(|| local("missing checkpoint"));
        }
        let network = self;
        let initial = network.genesis.materialize().map_err(input)?;
        let checkpoint = *storage
            .checkpoint()
            .ok_or_else(|| local("missing checkpoint"))?;
        if storage
            .state()
            .get(&consensus::rotation::committee_state_key())
            .is_some()
        {
            return Err(input(
                "rotating history requires explicit rotating recovery",
            ));
        }
        if usize::try_from(checkpoint.height).ok() != Some(storage.block_count()) {
            return Err(input(
                "certified network requires complete history from genesis",
            ));
        }
        if storage.state().get(&genesis::genesis_key()) != Some(network.hash.as_bytes().as_slice())
            || (checkpoint.height == 0
                && (checkpoint.block != network.hash || checkpoint.state_root != initial.root()))
        {
            return Err(input("archive genesis mismatch"));
        }
        let mut parent = network.hash;
        for height in 1..=checkpoint.height {
            let (block, encoded) = storage
                .read_finalized(height)
                .map_err(local)?
                .ok_or_else(|| input("incomplete certified history"))?;
            if block.header.height != height || block.header.parent != parent {
                return Err(input("history does not descend from trusted genesis"));
            }
            let certificate = consensus::FinalityCertificate::decode(&encoded).map_err(input)?;
            network
                .committee(height)?
                .verify_certificate(&certificate, &block.header)
                .map_err(input)?;
            parent = block.header.compute_hash();
        }
        if parent != checkpoint.block {
            return Err(input("history checkpoint mismatch"));
        }
        Ok(checkpoint)
    }

    fn producer_config(&self) -> ProducerConfig {
        ProducerConfig {
            chain_id: self.chain_id(),
            block_capacity: self.genesis.capacity,
            max_transaction_bytes: MAX_TRANSACTION_BYTES,
            max_block_transactions: 15,
            ..ProducerConfig::default()
        }
    }
}

/// Network-driven participant. Only durable certificates advance its public checkpoint.
pub struct NetworkNode {
    admissions: BTreeMap<ValidatorId, consensus::admission::AdmissionCertificate>,
    governance: Option<consensus::governance::GovernanceCertificate>,
    inclusions: BTreeMap<ValidatorId, consensus::history::HistoricalEvidence>,
    network: StaticNetwork,
    participant: Option<RoundRobinValidator>,
    standby: Option<(BlockProducer, DurableSigner)>,
    contributions: Option<ContributionPool>,
    storage: ChainStorage,
    voter: ValidatorId,
    proposal: Option<SignedBlockProposal>,
    valid: Option<(Block, PrevoteCertificate)>,
    votes: BTreeMap<(ValidatorId, VotePhase), Vote>,
    cache_path: PathBuf,
    timer: Option<(TimeoutEvent, Instant)>,
    base_timeout: Duration,
    evidence: crate::evidence::EvidenceStore,
}

impl NetworkNode {
    /// Opens a certified archive and protected signer, rejecting demonstration history.
    /// `signer` must already be provisioned explicitly; missing journals are never recreated.
    pub fn open(
        network: StaticNetwork,
        directory: &Path,
        signer: DurableSigner,
        base_timeout: Duration,
    ) -> Result<Self, NetworkNodeError> {
        if base_timeout < Duration::from_millis(100) || base_timeout > Duration::from_secs(60) {
            return Err(input(
                "round timeout must be between 100 and 60000 milliseconds",
            ));
        }
        let RecoveredNetwork { storage, producer } = network.recover(directory)?;
        let identities: Vec<_> = if let Some(current) = producer.potb_state() {
            current.records().map(|(id, _)| id).collect()
        } else {
            network.committee(1)?.members().collect()
        };
        let voter = signer.validator_id(&signer.key_handle()).map_err(local)?;
        let (participant, standby) = Self::bind_height(&network, producer, signer)?;
        let mut result = Self {
            admissions: BTreeMap::new(),
            governance: None,
            inclusions: BTreeMap::new(),
            evidence: crate::evidence::EvidenceStore::open(
                directory,
                &network,
                &storage,
                &identities,
            )?,
            network,
            participant,
            standby,
            contributions: None,
            storage,
            voter,
            proposal: None,
            valid: None,
            votes: BTreeMap::new(),
            cache_path: directory.join("consensus-cache.bin"),
            timer: None,
            base_timeout,
        };
        result.start_contributions()?;
        result.restore_cache()?;
        Ok(result)
    }

    fn participant(&self) -> &RoundRobinValidator {
        self.participant
            .as_ref()
            .expect("participant available outside height handoff")
    }
    /// Verified local double-vote proofs, durably retained at most once per member.
    /// Their presence does not alter active weights or finalize an economic penalty.
    pub fn evidence(&self) -> impl Iterator<Item = &consensus::DoubleVoteEvidence> {
        self.evidence.records()
    }
    fn participant_mut(&mut self) -> &mut RoundRobinValidator {
        self.participant
            .as_mut()
            .expect("participant available outside height handoff")
    }
    /// Current committed storage view.
    #[must_use]
    pub const fn storage(&self) -> &ChainStorage {
        &self.storage
    }
    /// Current next height and trusted genesis for synchronization.
    #[must_use]
    pub fn request(&self) -> SyncRequest {
        SyncRequest {
            genesis: self.network.hash,
            height: self.producer().height(),
        }
    }
    /// Current round, useful for operator diagnostics and simulations.
    #[must_use]
    pub fn round(&self) -> u32 {
        self.participant
            .as_ref()
            .map_or(0, |participant| participant.local().round())
    }
    /// Admits a signed transaction for both production and gossip.
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<Hash256, NetworkNodeError> {
        let id = crate::hash_transaction(&tx);
        self.producer_mut().submit_transaction(tx)?;
        Ok(id)
    }

    /// Bounded response. Untrusted requests select a height, never committee or state authority.
    pub fn respond(&self, request: SyncRequest) -> Result<Vec<u8>, NetworkNodeError> {
        self.prepare_response(request)?.encode()
    }

    /// Selects an owned response snapshot for encoding outside the node lock.
    /// The exchange codec's size and message limits are checked during encoding.
    pub fn prepare_response(
        &self,
        request: SyncRequest,
    ) -> Result<PreparedResponse, NetworkNodeError> {
        if request.genesis != self.network.hash {
            return Err(input("peer genesis mismatch"));
        }
        let messages = if let Some((block, encoded)) =
            self.storage.read_finalized(request.height).map_err(local)?
        {
            vec![NetworkMessage::Finalized {
                block,
                certificate: consensus::FinalityCertificate::decode(&encoded).map_err(local)?,
            }]
        } else if request.height == self.request().height {
            let mut messages = self.consensus_messages();
            let mut size = 0;
            for tx in self.producer().pending_transactions() {
                size += transaction::estimate_encoded_len(&tx);
                if size > 2 * 1024 * 1024 {
                    break;
                }
                messages.push(NetworkMessage::Transaction(tx));
            }
            messages
        } else {
            Vec::new()
        };
        Ok(PreparedResponse::new(self.network.hash, messages))
    }

    fn consensus_messages(&self) -> Vec<NetworkMessage> {
        let mut messages = Vec::new();
        messages.extend(
            self.governance
                .iter()
                .cloned()
                .map(NetworkMessage::Governance),
        );
        messages.extend(
            self.admissions
                .values()
                .cloned()
                .map(NetworkMessage::PotbAdmission),
        );
        messages.extend(
            self.inclusions
                .values()
                .cloned()
                .map(NetworkMessage::PotbEvidence),
        );
        if let Some(pool) = &self.contributions {
            messages.extend(pool.entries().cloned().map(|contribution| {
                NetworkMessage::VrfContribution {
                    height: self.request().height,
                    contribution,
                }
            }));
        }
        if let Some((block, proof)) = &self.valid {
            messages.push(NetworkMessage::ValidValue {
                block: block.clone(),
                proof: proof.encode(),
            });
        }
        if let Some(proposal) = &self.proposal {
            messages.push(NetworkMessage::Proposal {
                envelope: proposal.envelope.clone(),
                block: proposal.proposal.block.clone(),
                proof: proposal
                    .valid_round
                    .as_ref()
                    .map_or_else(Vec::new, PrevoteCertificate::encode),
            });
        }
        messages.extend(self.votes.values().cloned().map(NetworkMessage::Vote));
        messages
    }

    /// Decodes the complete response, then authenticates messages individually.
    /// Returns the number rejected; local signing/storage errors are never suppressed.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<usize, NetworkNodeError> {
        let messages = decode_exchange(self.network.hash, bytes).map_err(input)?;
        let mut rejected = 0;
        for message in messages {
            match self.receive_message(message) {
                Ok(()) => {}
                Err(NetworkNodeError::Input(_)) => rejected += 1,
                Err(error) => return Err(error),
            }
        }
        Ok(rejected)
    }

    fn receive_message(&mut self, message: NetworkMessage) -> Result<(), NetworkNodeError> {
        if self.participant.is_none()
            && matches!(
                &message,
                NetworkMessage::Vote(_)
                    | NetworkMessage::ValidValue { .. }
                    | NetworkMessage::Proposal { .. }
            )
        {
            return Ok(());
        }
        match message {
            NetworkMessage::Governance(certificate) => {
                self.submit_governance(certificate)?;
            }
            NetworkMessage::PotbAdmission(certificate) => {
                self.submit_potb_admission(certificate)?;
            }
            NetworkMessage::PotbEvidence(evidence) => {
                self.submit_potb_evidence(evidence)?;
            }
            NetworkMessage::VrfContribution {
                height,
                contribution,
            } => {
                self.receive_contribution(height, contribution)?;
            }
            NetworkMessage::Transaction(tx) => {
                self.submit_transaction(tx)?;
            }
            NetworkMessage::Finalized { block, certificate } => {
                self.receive_finalized(block, &certificate)?;
            }
            NetworkMessage::Vote(vote) => {
                self.receive_peer_vote(vote)?;
            }
            NetworkMessage::ValidValue { block, proof } => {
                self.receive_valid_value(block, &proof)?;
            }
            NetworkMessage::Proposal {
                envelope,
                block,
                proof,
            } => {
                if self
                    .proposal
                    .as_ref()
                    .is_some_and(|previous| previous.envelope == envelope)
                {
                    return Ok(());
                }
                if self.proposal.is_some() {
                    return Err(input("conflicting proposal in the active round"));
                }
                let proof = if proof.is_empty() {
                    None
                } else {
                    Some(
                        PrevoteCertificate::decode(self.participant().local().committee(), &proof)
                            .map_err(input)?,
                    )
                };
                self.participant()
                    .local()
                    .verify_proposal(
                        self.participant().proposer(),
                        &envelope,
                        &block.header,
                        proof.as_ref(),
                    )
                    .map_err(input)?;
                self.producer_mut().prepare_received_vrf(&block)?;
                let proposal = SignedBlockProposal {
                    envelope,
                    proposal: self
                        .participant()
                        .producer()
                        .execute_received_block(block)?,
                    valid_round: proof,
                };
                // Body is durable before reserving a non-nil vote or lock.
                self.proposal = Some(proposal.clone());
                self.persist_cache()?;
                self.accept_available(&proposal)?;
            }
        }
        Ok(())
    }

    fn receive_valid_value(
        &mut self,
        block: types::Block,
        proof: &[u8],
    ) -> Result<(), NetworkNodeError> {
        let proof = PrevoteCertificate::decode(self.participant().local().committee(), proof)
            .map_err(input)?;
        if proof.block() != block.header.compute_hash() || proof.round() > self.round() {
            return Err(input("invalid available-value evidence"));
        }
        if self
            .valid
            .as_ref()
            .is_some_and(|(_, previous)| previous.round() >= proof.round())
        {
            return Ok(());
        }
        self.producer_mut().prepare_received_vrf(&block)?;
        self.participant()
            .producer()
            .execute_received_block(block.clone())?;
        self.valid = Some((block, proof));
        self.persist_cache()?;
        Ok(())
    }

    fn accept_available(&mut self, proposal: &SignedBlockProposal) -> Result<(), NetworkNodeError> {
        if let Some(certificate) = self.participant().certificate().cloned() {
            if certificate.block == proposal.envelope.block {
                let participant = self
                    .participant
                    .as_mut()
                    .ok_or_else(|| local("missing participant"))?;
                participant.commit_finalized(
                    &proposal.proposal,
                    &certificate,
                    &mut self.storage,
                )?;
                self.advance_height()?;
            }
        } else if self.participant().local().step() == VotingStep::Precommitted {
            self.participant_mut().restore_proposal(proposal)?;
        } else if !self.votes.contains_key(&(self.voter, VotePhase::Prevote)) {
            let vote = self.participant_mut().accept_proposal(proposal)?;
            self.record_local(vote)?;
        } else {
            self.participant_mut().restore_proposal(proposal)?;
        }
        Ok(())
    }

    fn record_local(&mut self, vote: Vote) -> Result<(), NetworkNodeError> {
        self.votes.insert((vote.voter, vote.phase), vote);
        self.persist_cache()
    }

    fn receive_peer_vote(&mut self, vote: Vote) -> Result<(), NetworkNodeError> {
        let key = (vote.voter, vote.phase);
        if self.votes.get(&key) == Some(&vote) {
            return Ok(());
        }
        let result = self.participant_mut().receive_vote(vote.clone());
        if result.is_err() {
            let proofs: Vec<_> = self.participant().evidence().cloned().collect();
            for proof in proofs {
                self.evidence.persist(proof)?;
            }
        }
        result?;
        self.votes.insert(key, vote);
        Ok(())
    }

    /// Drives one bounded unit of work using a monotonic clock. No synthetic votes exist.
    pub fn tick(&mut self, now: Instant) -> Result<(), NetworkNodeError> {
        if self.participant.is_none() {
            return Ok(());
        }
        if self.proposal.is_none()
            && self.valid.is_none()
            && self
                .contributions
                .as_ref()
                .is_some_and(|pool| !pool.missing().is_empty())
        {
            self.timer = None;
            return Ok(());
        }
        if let Some(certificate) = self.participant().certificate().cloned()
            && let Some(proposal) = &self.proposal
            && proposal.envelope.block == certificate.block
        {
            let proposal = proposal.proposal.clone();
            let participant = self
                .participant
                .as_mut()
                .ok_or_else(|| local("missing participant"))?;
            participant.commit_finalized(&proposal, &certificate, &mut self.storage)?;
            self.advance_height()?;
            return Ok(());
        }
        if self.participant().certificate().is_some() {
            return Ok(());
        }
        if !self.votes.contains_key(&(self.voter, VotePhase::Prevote))
            && matches!(
                self.participant().local().step(),
                VotingStep::AwaitingProposal | VotingStep::Prevoted
            )
            && let Some(proposal) = self.proposal.clone()
        {
            match self.accept_available(&proposal) {
                Ok(()) | Err(NetworkNodeError::Input(_)) => {}
                Err(error) => return Err(error),
            }
        }
        self.propose_if_designated()?;
        if self.proposal.is_some()
            && !self.votes.contains_key(&(self.voter, VotePhase::Precommit))
            && matches!(
                self.participant().local().step(),
                VotingStep::Prevoted | VotingStep::Precommitted
            )
            && let Ok(proof) = self.participant().prevote_certificate()
        {
            let block = self
                .proposal
                .as_ref()
                .ok_or_else(|| local("missing proposal"))?
                .proposal
                .block
                .clone();
            self.valid = Some((block, proof));
            self.persist_cache()?;
            match self
                .participant_mut()
                .precommit()
                .map_err(NetworkNodeError::from)
            {
                Ok(vote) => self.record_local(vote)?,
                Err(NetworkNodeError::Input(_)) => {}
                Err(error) => return Err(error),
            }
        }
        let Some(event) = self.participant().timeout_event() else {
            return Ok(());
        };
        if self.timer.is_none_or(|(previous, _)| previous != event) {
            self.timer = Some((event, now));
        }
        // Growing round deadlines permit eventual overlap after delayed startup/reconnect.
        let duration = self
            .base_timeout
            .saturating_mul(event.round.saturating_add(1));
        if self
            .timer
            .is_some_and(|(_, started)| now.saturating_duration_since(started) >= duration)
        {
            if let Some(vote) = self.participant_mut().timeout(event)? {
                self.record_local(vote)?;
            } else {
                self.proposal = None;
                self.votes.clear();
                self.persist_cache()?;
            }
            self.timer = None;
        }
        Ok(())
    }

    fn propose_if_designated(&mut self) -> Result<(), NetworkNodeError> {
        if self.proposal.is_none()
            && self.participant().local().step() == VotingStep::AwaitingProposal
            && self.participant().proposer() == self.voter
        {
            let attempt = if let Some((block, proof)) = &self.valid {
                if proof.round() < self.round() {
                    let proposal = self
                        .participant()
                        .producer()
                        .execute_received_block(block.clone())?;
                    let proof = proof.clone();
                    Some(self.participant_mut().repropose(proposal, proof))
                } else {
                    None
                }
            } else if self.participant().local().locked().is_none() {
                Some(self.participant_mut().propose())
            } else {
                None
            };
            if let Some(result) = attempt {
                match result {
                    Ok(proposal) => {
                        encode_block(&proposal.proposal.block).map_err(input)?;
                        self.proposal = Some(proposal.clone());
                        self.persist_cache()?;
                        self.accept_available(&proposal)?;
                    }
                    Err(error) => match NetworkNodeError::from(error) {
                        NetworkNodeError::Input(_) => {}
                        error @ NetworkNodeError::Local(_) => return Err(error),
                    },
                }
            }
        }
        Ok(())
    }

    fn advance_height(&mut self) -> Result<(), NetworkNodeError> {
        let (producer, signer) = if let Some(participant) = self.participant.take() {
            let (producer, previous) = participant.into_parts();
            (producer, previous.into_signer())
        } else {
            self.standby
                .take()
                .ok_or_else(|| local("missing standby state"))?
        };
        (self.participant, self.standby) = Self::bind_height(&self.network, producer, signer)?;
        self.admissions.clear();
        self.governance = None;
        self.inclusions.clear();
        self.start_contributions()?;
        self.proposal = None;
        self.valid = None;
        self.votes.clear();
        self.timer = None;
        self.persist_cache()
    }

    fn persist_cache(&self) -> Result<(), NetworkNodeError> {
        let bytes =
            encode_exchange(self.network.hash, &self.consensus_messages()).map_err(local)?;
        let temporary = self.cache_path.with_extension("pending");
        if temporary.exists() {
            std::fs::remove_file(&temporary).map_err(local)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(local)?;
        file.write_all(&bytes).map_err(local)?;
        file.sync_all().map_err(local)?;
        drop(file);
        std::fs::rename(temporary, &self.cache_path).map_err(local)?;
        #[cfg(unix)]
        std::fs::File::open(
            self.cache_path
                .parent()
                .ok_or_else(|| local("cache directory missing"))?,
        )
        .and_then(|directory| directory.sync_all())
        .map_err(local)?;
        Ok(())
    }

    fn restore_cache(&mut self) -> Result<(), NetworkNodeError> {
        let file = match std::fs::File::open(&self.cache_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(local(error)),
        };
        let mut bytes = Vec::new();
        file.take(MAX_EXCHANGE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(local)?;
        let messages = decode_exchange(self.network.hash, &bytes).map_err(local)?;
        // Pending submissions are scoped to one parent/frontier. Expired entries are discarded.
        self.restore_potb_inclusions(&messages)?;
        if self.participant.is_none() {
            return Ok(());
        }
        // Cache data is reauthenticated; it cannot relax the journal's signed watermark.
        for message in &messages {
            if let NetworkMessage::Vote(vote) = message
                && vote.height == self.request().height
                && vote.round == self.round()
            {
                self.participant()
                    .local()
                    .committee()
                    .verify_vote(vote)
                    .map_err(local)?;
                if self.participant().certificate().is_none() {
                    self.participant_mut().receive_vote(vote.clone())?;
                }
                self.votes.insert((vote.voter, vote.phase), vote.clone());
            }
        }
        for message in messages {
            match message {
                NetworkMessage::Proposal {
                    envelope,
                    block,
                    proof,
                } if envelope.height == self.request().height && envelope.round == self.round() => {
                    let proof = if proof.is_empty() {
                        None
                    } else {
                        Some(
                            PrevoteCertificate::decode(
                                self.participant().local().committee(),
                                &proof,
                            )
                            .map_err(local)?,
                        )
                    };
                    self.participant()
                        .local()
                        .verify_proposal(
                            self.participant().proposer(),
                            &envelope,
                            &block.header,
                            proof.as_ref(),
                        )
                        .map_err(local)?;
                    self.producer_mut().prepare_received_vrf(&block)?;
                    let proposal = SignedBlockProposal {
                        envelope,
                        proposal: self
                            .participant()
                            .producer()
                            .execute_received_block(block)?,
                        valid_round: proof,
                    };
                    if matches!(
                        self.participant().local().step(),
                        VotingStep::Prevoted | VotingStep::Precommitted
                    ) {
                        self.participant_mut().restore_proposal(&proposal)?;
                    }
                    self.proposal = Some(proposal);
                }
                NetworkMessage::ValidValue { block, proof }
                    if block.header.height == self.request().height =>
                {
                    let proof =
                        PrevoteCertificate::decode(self.participant().local().committee(), &proof)
                            .map_err(local)?;
                    if proof.block() != block.header.compute_hash() {
                        return Err(local("cached proof body mismatch"));
                    }
                    self.producer_mut().prepare_received_vrf(&block)?;
                    self.participant()
                        .producer()
                        .execute_received_block(block.clone())?;
                    self.valid = Some((block, proof));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
