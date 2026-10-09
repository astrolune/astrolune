// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Measures weighted VRF selection, committee handoff and `PoTB` transitions.
//!
//! These figures describe one machine and one toolchain. They are not a
//! correctness gate. A transition is accepted because every roster proof
//! verifies, the weighted draw is integer-only and unbiased, and the incoming
//! state matches a committed witness; those rules are established by the
//! crate's formal model and tests, not by timing. A path that measures faster
//! is not more trustworthy, and a slower one is not less.
//!
//! What this does NOT establish: distributed liveness, round latency under
//! partition, whether a handoff can complete inside any particular block
//! interval, any safety property, the statistical quality of the weighted
//! draw, a figure comparable to another machine, or a bound that holds under
//! contention from other processes. Roster sizes expose a growth curve; they do
//! not describe a planned network.
//!
//! The sweep stops at 31 rather than `MAX_ROTATION_VALIDATORS`, because a full
//! roster cannot admit a new candidate: `AdmissionRequest::verify` rejects a
//! roster that has already reached the bound, so 31 is the largest roster for
//! which every benchmark here has a valid fixture.

use consensus::{
    Candidate, CertificateSignature, FinalityCertificate, VerifiedVrfSampler, Vote, VotePhase,
    VrfValidator,
    admission::{AdmissionApproval, AdmissionCertificate, AdmissionRequest},
    potb::PotbPolicy,
    potb_transition::{PotbBatch, PotbConfiguration, PotbHandoff, PotbVerifier, potb_state_key},
    rotation::{
        CommitteeHandoff, CommitteeState, HandoffVerifier, VrfBatch, VrfContribution,
        committee_state_key,
    },
};
use crypto::{
    VrfRole,
    blake2s::{ed25519_public_key, ed25519_sign},
    prove_vrf,
};
use genesis::{Genesis, GenesisValidator};
use state::{InMemoryState, StateDatabase, StateDiff, StateValueProof};
use testkit::bench::Suite;
use types::{BlockHeader, Hash256, Resources, ValidatorId};

/// Chain identity bound into every benchmark roster and proof.
const CHAIN_ID: u32 = 71;

/// Roster sizes measured by every size-dependent benchmark.
const ROSTER_SIZES: [usize; 4] = [4, 8, 16, 31];

/// Seats replaced at each rotation, matching the repository test fixtures.
const ROTATION_COUNT: usize = 1;

/// Immutable experimental `PoTB` policy, identical to the crate test fixture.
///
/// Every genesis weight must equal `initial_weight`, which
/// `PotbConfiguration::new` requires, so the roster starts uniformly weighted.
const POLICY: PotbPolicy = PotbPolicy {
    epoch_blocks: 2,
    initial_weight: 10,
    age_increment: 3,
    maximum_weight: 20,
};

/// Fixed capacity carried by the benchmark genesis and every header.
const CAPACITY: Resources = Resources {
    compute: 1_000_000,
    memory: 1_000_000,
    io: 1_000_000,
    bandwidth: 1_000_000,
};

/// Deterministic benchmark key material for one roster member.
struct Validator {
    /// Secret seed; benchmark-only material that never leaves this process.
    secret: [u8; 32],
    /// Registered Ed25519 public key.
    public: [u8; 32],
    /// Identity derived from the public key exactly as the provider derives it.
    id: ValidatorId,
}

/// Returns a nonzero secret seed distinct for every `index`.
fn secret_seed(index: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0] = u8::try_from(index % 256).unwrap_or_default();
    seed[1] = u8::try_from(index / 256).unwrap_or_default();
    seed[31] = 1; // keep every seed nonzero
    seed
}

/// Builds `size` distinct validators in canonical identity order.
///
/// A validated `CommitteeState` roster is strictly ordered by derived identity,
/// so sorting here lets the roster, the genesis validator list and the
/// contribution batch share one index.
fn validators(size: usize) -> Vec<Validator> {
    let mut seats: Vec<_> = (0..size)
        .map(|index| {
            let secret = secret_seed(index);
            let public = ed25519_public_key(&secret);
            Validator {
                secret,
                public,
                id: ValidatorId(crypto::blake2s_hash(&public).0),
            }
        })
        .collect();
    seats.sort_by_key(|seat| seat.id);
    seats
}

/// One bootstrapped roster with everything the benchmarks verify against.
struct Fixture {
    /// Roster key material in canonical identity order.
    seats: Vec<Validator>,
    /// Trusted rotating genesis for this roster.
    genesis: Genesis,
    /// Registered keys in the same order as the genesis validator list.
    keys: Vec<[u8; 32]>,
    /// Committee state authoritative for height one.
    state: CommitteeState,
    /// Complete role-separated batch for the transition out of height one.
    batch: VrfBatch,
}

impl Fixture {
    /// Bootstraps a `size`-member roster and proves its complete VRF batch.
    fn new(size: usize) -> Self {
        let seats = validators(size);
        let genesis = Genesis {
            version: genesis::ROTATING_GENESIS_VERSION,
            chain_id: CHAIN_ID,
            committee_size: size,
            rotation_count: ROTATION_COUNT,
            runtime_version: 2,
            capacity: CAPACITY,
            validators: seats
                .iter()
                .map(|seat| GenesisValidator {
                    id: seat.id,
                    weight: POLICY.initial_weight,
                })
                .collect(),
            allocations: vec![],
        };
        let keys: Vec<_> = seats.iter().map(|seat| seat.public).collect();
        let state = CommitteeState::from_genesis(&genesis, &keys)
            .expect("a uniform rotating genesis bootstraps height one");
        let batch = contributions(&seats, &state);
        Self {
            seats,
            genesis,
            keys,
            state,
            batch,
        }
    }

    /// Returns the secret seed registered for `id`.
    fn secret(&self, id: ValidatorId) -> [u8; 32] {
        self.seats
            .iter()
            .find(|seat| seat.id == id)
            .expect("every benchmark member comes from this roster")
            .secret
    }

    /// Returns the parent this fixture's state and requests are anchored to.
    fn parent(&self) -> Hash256 {
        self.state.genesis()
    }

    /// Reproves the complete batch against a different committee state.
    ///
    /// The `PoTB` profile commits its own genesis namespace, so its VRF inputs
    /// differ from the plain rotation profile's and its proofs cannot be shared.
    fn reproved(&self, state: &CommitteeState) -> VrfBatch {
        contributions(&self.seats, state)
    }
}

/// Proves both role contributions for every member of `state`'s roster.
fn contributions(seats: &[Validator], state: &CommitteeState) -> VrfBatch {
    VrfBatch::new(
        seats
            .iter()
            .map(|seat| VrfContribution {
                validator: seat.id,
                committee: role_proof(seat, state, VrfRole::Committee),
                producer: role_proof(seat, state, VrfRole::Producer),
            })
            .collect(),
    )
    .expect("a complete, unique roster batch is canonical")
}

/// Proves one role for one member against `state`'s finalized input.
fn role_proof(seat: &Validator, state: &CommitteeState, role: VrfRole) -> crypto::VrfOutput {
    prove_vrf(
        &seat.secret,
        state.input(role).expect("height one has a next input"),
    )
    .expect("a registered benchmark seed proves its own role")
}

/// Builds a verified sampler for `role` over the fixture's complete roster.
fn sampler(fixture: &Fixture, role: VrfRole) -> VerifiedVrfSampler {
    VerifiedVrfSampler::new(
        fixture
            .state
            .input(role)
            .expect("height one has a next input"),
        fixture.state.roster(),
        &candidates(fixture, role),
    )
    .expect("a complete batch over a trusted roster verifies")
}

/// Pairs each roster weight with that member's proof for `role`.
///
/// The roster and the batch are both in canonical identity order, so the zip
/// below pairs every member with its own proof.
fn candidates(fixture: &Fixture, role: VrfRole) -> Vec<Candidate> {
    fixture
        .state
        .roster()
        .iter()
        .zip(fixture.batch.entries())
        .map(|(validator, entry)| Candidate {
            id: entry.validator,
            weight: validator.weight,
            vrf: match role {
                VrfRole::Committee => entry.committee.clone(),
                VrfRole::Producer => entry.producer.clone(),
            },
        })
        .collect()
}

/// Signs a full-committee precommit certificate for `header`.
fn certificate(
    fixture: &Fixture,
    current: &CommitteeState,
    header: &BlockHeader,
) -> FinalityCertificate {
    let context = current
        .context()
        .expect("a validated state authenticates its active seats");
    let mut signatures: Vec<_> = context
        .members()
        .map(|id| {
            let vote = Vote {
                chain_id: current.chain_id(),
                committee_root: context.root(),
                height: current.height(),
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(header.compute_hash()),
                voter: id,
                signature: [0; 64],
            };
            CertificateSignature {
                voter: id,
                signature: ed25519_sign(&fixture.secret(id), &vote.signing_hash().0),
            }
        })
        .collect();
    signatures.sort_by_key(|entry| entry.voter);
    FinalityCertificate {
        chain_id: current.chain_id(),
        height: current.height(),
        round: 0,
        committee_root: context.root(),
        block: header.compute_hash(),
        signatures,
    }
}

/// Builds the header and membership witness committing `value` under `key`.
fn committed(
    current: &CommitteeState,
    parent: Hash256,
    key: &types::StateKey,
    value: Vec<u8>,
) -> (BlockHeader, StateValueProof) {
    let mut database = InMemoryState::default();
    let mut diff = StateDiff::new();
    diff.put(key.clone(), value);
    database
        .commit(database.root(), &[diff])
        .expect("one bounded value commits");
    let header = BlockHeader {
        height: current.height(),
        parent,
        transactions_root: Hash256([0x22; 32]),
        state_root: database.root(),
        receipts_root: Hash256::ZERO,
        committee_root: current
            .context()
            .expect("a validated state authenticates its active seats")
            .root(),
        capacity: current.capacity(),
    };
    let witness = StateValueProof::create(
        database
            .snapshot()
            .expect("a committed database snapshots")
            .as_ref(),
        key,
    )
    .expect("a present key proves its own membership");
    (header, witness)
}

/// Builds one old-quorum-authenticated rotation handoff for `verifier`.
fn handoff(fixture: &Fixture, verifier: &HandoffVerifier) -> CommitteeHandoff {
    let current = verifier.current();
    let next = current
        .transition(&fixture.batch)
        .expect("a complete batch transitions height one");
    let (header, next_state) = committed(
        current,
        verifier.parent(),
        &committee_state_key(),
        next.to_bytes().expect("a validated state encodes"),
    );
    CommitteeHandoff {
        certificate: certificate(fixture, current, &header),
        header,
        contributions: fixture.batch.clone(),
        next_state,
    }
}

/// A bootstrapped `PoTB` profile over the fixture's roster.
struct Potb {
    /// Verifier holding the authority for height one.
    verifier: PotbVerifier,
    /// Complete system batch with no evidence and no admissions.
    batch: PotbBatch,
    /// One authenticated transfer out of height one.
    handoff: PotbHandoff,
}

impl Potb {
    /// Bootstraps the profile and stages one complete transition.
    fn new(fixture: &Fixture) -> Self {
        let config = PotbConfiguration::new(fixture.genesis.clone(), POLICY)
            .expect("a uniform rotating genesis configures the profile");
        let verifier = PotbVerifier::new(&config, &fixture.keys)
            .expect("the exact registered key set bootstraps the profile");
        let batch = PotbBatch::new(
            fixture.reproved(verifier.current().committee()),
            vec![],
            vec![],
        )
        .expect("a complete batch without evidence or admissions is canonical");
        let next = verifier
            .current()
            .stage(verifier.parent(), &batch)
            .expect("a complete batch stages the next authority");
        let (header, next_state) = committed(
            verifier.current().committee(),
            verifier.parent(),
            &potb_state_key(),
            next.to_bytes().expect("a validated state encodes"),
        );
        let handoff = PotbHandoff {
            certificate: certificate(fixture, verifier.current().committee(), &header),
            header,
            batch: batch.clone(),
            next_state,
        };
        Self {
            verifier,
            batch,
            handoff,
        }
    }
}

/// A candidate request with one approval from every incumbent.
struct Admission {
    /// Signed candidate request bound to this exact state and parent.
    request: AdmissionRequest,
    /// Canonical certificate carrying every incumbent approval.
    certificate: AdmissionCertificate,
    /// Canonical certificate bytes.
    encoded: Vec<u8>,
}

impl Admission {
    /// Signs a request and collects an approval from every active seat.
    ///
    /// Every incumbent approves, including the surplus beyond quorum, because
    /// `AdmissionCertificate::verify` authenticates all of them. That makes the
    /// approval count equal to the roster size, which is what the sweep needs.
    fn new(fixture: &Fixture) -> Self {
        let parent = fixture.parent();
        let candidate = secret_seed(fixture.seats.len() + 1);
        let request = AdmissionRequest::sign(&fixture.state, parent, &candidate)
            .expect("an unregistered candidate may request admission");
        let context = fixture
            .state
            .context()
            .expect("a validated state authenticates its active seats");
        // Public benchmark keys only; an operator approval uses DurableSigner.
        let approvals: Vec<_> = context
            .members()
            .map(|id| {
                let mut bytes = b"ALADAP01".to_vec();
                bytes.extend_from_slice(&request.id().0);
                bytes.extend_from_slice(&id.0);
                bytes.extend_from_slice(&ed25519_sign(
                    &fixture.secret(id),
                    &request.intent().approval_hash(request.consent(), id).0,
                ));
                AdmissionApproval::from_bytes(&bytes).expect("an exact approval envelope decodes")
            })
            .collect();
        let certificate =
            AdmissionCertificate::assemble(request.clone(), approvals, &fixture.state, parent)
                .expect("every incumbent approving is a quorum");
        let encoded = certificate
            .to_bytes()
            .expect("a canonical certificate encodes");
        Self {
            request,
            certificate,
            encoded,
        }
    }
}

/// Measures verified VRF batches and the weighted draws taken from them.
fn vrf_benchmarks(suite: &mut Suite, fixture: &Fixture, size: usize) {
    let committee_role = sampler(fixture, VrfRole::Committee);
    let producer_role = sampler(fixture, VrfRole::Producer);
    let current = fixture.state.committee();
    let selected = committee_role
        .select(size)
        .expect("the whole roster is a valid target");
    let input = fixture
        .state
        .input(VrfRole::Committee)
        .expect("height one has a next input");
    let roster: Vec<VrfValidator> = fixture.state.roster().to_vec();
    let prepared = candidates(fixture, VrfRole::Committee);

    // One proof verification per roster member, plus the transcript hash.
    suite.bench(format!("vrf/batch_verify/{size}"), || {
        VerifiedVrfSampler::new(input, &roster, &prepared)
    });
    // Draws only: no proof is re-verified once a sampler exists.
    suite.bench(format!("vrf/select/{size}"), || committee_role.select(size));
    suite.bench(format!("vrf/rotate/{size}"), || {
        committee_role.rotate(&current, ROTATION_COUNT)
    });
    suite.bench(format!("vrf/producer/{size}"), || {
        producer_role.producer(&selected)
    });
}

/// Measures the committee state transition and the reuse guard that skips it.
fn rotation_benchmarks(suite: &mut Suite, fixture: &Fixture, size: usize) {
    let cached = fixture.batch.clone();
    let encoded = fixture.batch.to_bytes().expect("a canonical batch encodes");

    // The cold path: two samplers, so two proof verifications per member,
    // then the weighted draw and a full revalidation of the result.
    suite.bench(format!("rotation/transition_cold/{size}"), || {
        fixture.state.transition(&fixture.batch)
    });
    // A producer retains at most one verified batch and its computed next
    // committee, and reuses them only when this exact equality holds. The
    // guard is measured against an equal batch, which is its worst case: a
    // mismatching batch stops at the first differing entry. Only the decision
    // is timed; what a caller then does with the retained committee is outside
    // this crate and is not measured here.
    suite.bench(format!("rotation/transition_cache_guard/{size}"), || {
        cached == fixture.batch
    });
    suite.bench(format!("rotation/context/{size}"), || {
        fixture.state.context()
    });
    suite.bench(format!("rotation/proposer/{size}"), || {
        fixture.state.proposer(3)
    });
    // Framing is not a byte copy: `VrfOutput::encode` and `decode` both parse
    // the proof point, so both directions do curve work per contribution.
    suite.bench(format!("rotation/batch_encode/{size}"), || {
        fixture.batch.to_bytes()
    });
    suite.bench(format!("rotation/batch_decode/{size}"), || {
        VrfBatch::from_bytes(&encoded)
    });
    // Both role proofs of one member, against this exact transition context.
    suite.bench(format!("rotation/contribution_verify/{size}"), || {
        fixture.batch.entries()[0].verify(&fixture.state)
    });
}

/// Measures sequential handoff verification from a trusted genesis anchor.
fn handoff_benchmarks(suite: &mut Suite, fixture: &Fixture, size: usize) {
    let verifier = HandoffVerifier::new(&fixture.genesis, &fixture.keys)
        .expect("the exact registered key set anchors a verifier");
    let transfer = handoff(fixture, &verifier);
    let encoded = transfer.to_bytes().expect("a canonical handoff encodes");

    // Ancestry, capacity and the outgoing weighted quorum, with no transition.
    suite.bench(format!("handoff/verify_header/{size}"), || {
        verifier.verify_header(&transfer.header, &transfer.certificate)
    });
    // `apply` publishes into the verifier, so each measured call needs an
    // unadvanced one; the clone is inside the measurement and
    // `handoff/clone` reports it separately.
    suite.bench(format!("handoff/apply/{size}"), || {
        let mut trusted = verifier.clone();
        trusted.apply(&transfer)
    });
    suite.bench(format!("handoff/clone/{size}"), || verifier.clone());
    suite.bench(format!("handoff/encode/{size}"), || transfer.to_bytes());
    suite.bench(format!("handoff/decode/{size}"), || {
        CommitteeHandoff::from_bytes(&encoded)
    });
}

/// Measures incumbent-quorum admission authorization.
fn admission_benchmarks(suite: &mut Suite, fixture: &Fixture, size: usize) {
    let admission = Admission::new(fixture);
    let parent = fixture.parent();

    // Anchor equality plus one roster scan for the candidate key. The anchor
    // check compares the incumbent committee root, so this builds a full
    // verification context and is therefore linear in the roster, not constant.
    suite.bench(format!("admission/request_verify/{size}"), || {
        admission.request.verify(&fixture.state, parent)
    });
    // One approval per incumbent. A prior review found this quadratic in the
    // roster, because every approval rebuilt the incumbent context and
    // rescanned the roster; the context and key index are now resolved once
    // for the whole approval loop. The request check above still resolves its
    // own context, so one certificate builds two, which is linear and not
    // quadratic but is also not one.
    suite.bench(format!("admission/certificate_verify/{size}"), || {
        admission.certificate.verify(&fixture.state, parent)
    });
    suite.bench(format!("admission/certificate_encode/{size}"), || {
        admission.certificate.to_bytes()
    });
    suite.bench(format!("admission/certificate_decode/{size}"), || {
        AdmissionCertificate::from_bytes(&admission.encoded)
    });
}

/// Measures the `PoTB` profile's staging and authenticated replay.
fn potb_benchmarks(suite: &mut Suite, fixture: &Fixture, size: usize) {
    let profile = Potb::new(fixture);
    let parent = profile.verifier.parent();
    let current = profile.verifier.current();

    // Age accounting, policy reweighting, both samplers and one full
    // revalidation of the staged authority.
    suite.bench(format!("potb/stage/{size}"), || {
        current.stage(parent, &profile.batch)
    });
    // `apply` publishes into the verifier, so each measured call needs an
    // unadvanced one; the clone is inside the measurement.
    suite.bench(format!("potb/verifier_apply/{size}"), || {
        let mut trusted = profile.verifier.clone();
        trusted.apply(&profile.handoff)
    });
    suite.bench(format!("potb/verifier_clone/{size}"), || {
        profile.verifier.clone()
    });
    suite.bench(format!("potb/state_encode/{size}"), || current.to_bytes());
    suite.bench(format!("potb/batch_commitment/{size}"), || {
        profile.batch.commitment()
    });
}

fn main() {
    let mut suite = Suite::new("consensus-potb");
    suite.bench("potb/policy_score", || POLICY.score(1_000, false));
    for size in ROSTER_SIZES {
        let fixture = Fixture::new(size);
        vrf_benchmarks(&mut suite, &fixture, size);
        rotation_benchmarks(&mut suite, &fixture, size);
        handoff_benchmarks(&mut suite, &fixture, size);
        admission_benchmarks(&mut suite, &fixture, size);
        potb_benchmarks(&mut suite, &fixture, size);
    }
    suite.report();
}
