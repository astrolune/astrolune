// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Measures finality certificate authentication and committee bookkeeping.
//!
//! These figures describe one machine and one toolchain. They are not a
//! correctness gate: a certificate is accepted because
//! `AuthenticatedCommittee::verify_certificate` reaches a strict weighted
//! quorum of strict Ed25519 signatures over the exact header, and that rule is
//! established by the crate's formal model and tests, not by timing. A
//! configuration that measures faster does not make a check weaker, and a
//! slower one does not make it stronger.
//!
//! What this does NOT establish: distributed liveness, round latency under
//! partition, time to finality, any safety property, end-to-end block or
//! network throughput, a figure comparable to another machine, or a bound that
//! holds under contention from other processes. Committee sizes are chosen to
//! expose a growth curve, not to describe a planned network. Signature batches
//! above `crypto::batch::MIN_PARALLEL_REQUESTS` are decided on borrowed worker
//! threads, so a measurement at one size includes whatever that host's
//! scheduler charged for them.

use consensus::{
    AuthenticatedCommittee, CertificateSignature, Committee, CommitteeMember, ConsensusError,
    DoubleVoteEvidence, FinalityCertificate, PotbWeight, PrevoteCertificate, Vote, VotePhase,
    history::{CommitteeHistory, HistoricalEvidence},
    quorum_power,
};
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use testkit::bench::Suite;
use types::{BlockHeader, Hash256, Resources, ValidatorId};

/// Chain identity bound into every benchmark committee, vote and certificate.
const CHAIN_ID: u32 = 7;

/// Genesis namespace used by the benchmark committee history.
const GENESIS: Hash256 = Hash256([0x6e; 32]);

/// Equal voting power held by every benchmark committee seat.
///
/// Equal weights make the minimum quorum a seat count, so a sweep over sizes
/// changes the number of signatures and nothing else.
const MEMBER_POWER: u128 = 10;

/// Committee sizes measured by every size-dependent benchmark.
///
/// Four brackets the serial signature path, and the larger sizes sit above
/// `crypto::batch::MIN_PARALLEL_REQUESTS`, where batches are decided on worker
/// threads. The version-1 bound is `MAX_COMMITTEE_MEMBERS`, far above 128.
const COMMITTEE_SIZES: [usize; 4] = [4, 16, 64, 128];

/// Recorded committee heights measured by the history benchmarks.
///
/// Each count is all ones in binary, so appending the next height performs the
/// largest number of frontier merges available at that scale instead of the
/// cheapest one.
const HISTORY_LENGTHS: [u64; 3] = [15, 255, 1023];

/// Seat count of the committee replicated at every recorded history height.
const HISTORY_COMMITTEE: usize = 4;

/// Fixed capacity carried by every benchmark header.
const CAPACITY: Resources = Resources {
    compute: 1_000_000,
    memory: 1_000_000,
    io: 1_000_000,
    bandwidth: 1_000_000,
};

/// Deterministic benchmark key material for one committee seat.
struct Validator {
    /// Secret seed; benchmark-only material that never leaves this process.
    secret: [u8; 32],
    /// Registered Ed25519 public key.
    public: [u8; 32],
    /// Identity derived from the public key exactly as the provider derives it.
    id: ValidatorId,
}

/// Returns a nonzero secret seed distinct for every `index`.
///
/// The index is spread across two bytes so counts above 256 stay distinct.
fn secret_seed(index: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0] = u8::try_from(index % 256).unwrap_or_default();
    seed[1] = u8::try_from(index / 256).unwrap_or_default();
    seed[31] = 1; // keep every seed nonzero
    seed
}

/// Builds `size` distinct validators in canonical identity order.
///
/// Seat order equals identity order, so a certificate assembled from a prefix
/// of this slice is already strictly ascending, which is what
/// `FinalityCertificate::validate_shape` requires.
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

/// Borrows the registered public keys of these seats in seat order.
fn public_keys(seats: &[Validator]) -> Vec<[u8; 32]> {
    seats.iter().map(|seat| seat.public).collect()
}

/// Builds an equal-weight committee for `height` over these seats.
fn committee(seats: &[Validator], height: u64) -> Committee {
    Committee {
        height,
        members: seats
            .iter()
            .map(|seat| CommitteeMember {
                id: seat.id,
                power: PotbWeight(MEMBER_POWER),
            })
            .collect(),
    }
}

/// Authenticates these seats as the committee for `height`.
fn context(seats: &[Validator], height: u64) -> AuthenticatedCommittee {
    AuthenticatedCommittee::new(CHAIN_ID, &committee(seats, height), &public_keys(seats))
        .expect("benchmark committee and its complete key set are valid")
}

/// Builds the single header that a benchmark certificate finalizes.
fn header(context: &AuthenticatedCommittee) -> BlockHeader {
    BlockHeader {
        height: context.height(),
        parent: Hash256([0x11; 32]),
        transactions_root: Hash256([0x22; 32]),
        state_root: Hash256([0x33; 32]),
        receipts_root: Hash256([0x44; 32]),
        committee_root: context.root(),
        capacity: CAPACITY,
    }
}

/// Builds one precommit vote for `block` from `seat`, signed with its seed.
fn precommit(seat: &Validator, context: &AuthenticatedCommittee, block: Hash256) -> Vote {
    let mut vote = Vote {
        chain_id: CHAIN_ID,
        committee_root: context.root(),
        height: context.height(),
        round: 0,
        phase: VotePhase::Precommit,
        block: Some(block),
        voter: seat.id,
        signature: [0; 64],
    };
    vote.signature = ed25519_sign(&seat.secret, &vote.signing_hash().0);
    vote
}

/// Signs a precommit certificate for `block` with the first `signers` seats.
fn certificate(
    seats: &[Validator],
    context: &AuthenticatedCommittee,
    block: Hash256,
    signers: usize,
) -> FinalityCertificate {
    FinalityCertificate {
        chain_id: CHAIN_ID,
        height: context.height(),
        round: 0,
        committee_root: context.root(),
        block,
        signatures: seats[..signers]
            .iter()
            .map(|seat| CertificateSignature {
                voter: seat.id,
                signature: precommit(seat, context, block).signature,
            })
            .collect(),
    }
}

/// Returns the smallest seat count whose equal weights reach the strict quorum.
///
/// The accumulation mirrors the checked fold inside `verify_certificate` rather
/// than dividing, so no cast or rounding choice enters the result.
fn quorum_seats(size: usize) -> usize {
    let mut total = 0u128;
    for _ in 0..size {
        total += MEMBER_POWER;
    }
    let quorum = quorum_power(total);
    let mut accumulated = 0u128;
    for count in 1..=size {
        accumulated += MEMBER_POWER;
        if accumulated >= quorum {
            return count;
        }
    }
    size
}

/// Resolves certificate weights and compares them to the strict quorum.
///
/// This is the non-cryptographic half of `verify_certificate`: identity
/// lookup, the checked weighted sum and the threshold comparison, with no
/// signature decided. It is measured on its own so the share of a
/// certificate's cost that is not Ed25519 is visible, and it authenticates
/// nothing by itself.
fn weighted_quorum_met(
    context: &AuthenticatedCommittee,
    certificate: &FinalityCertificate,
) -> bool {
    let mut total = 0u128;
    for entry in &certificate.signatures {
        let Some(power) = context.voting_power(entry.voter) else {
            return false;
        };
        let Some(sum) = total.checked_add(power) else {
            return false;
        };
        total = sum;
    }
    total >= context.quorum()
}

/// Builds authenticated double-vote evidence against the first seat.
///
/// Both votes share one slot and differ only in value, which is the exact
/// shape `DoubleVoteEvidence::verify` accepts.
fn evidence(seats: &[Validator], context: &AuthenticatedCommittee) -> DoubleVoteEvidence {
    let accused = &seats[0];
    let signed = |block| {
        let mut vote = Vote {
            chain_id: CHAIN_ID,
            committee_root: context.root(),
            height: context.height(),
            round: 1,
            phase: VotePhase::Prevote,
            block,
            voter: accused.id,
            signature: [0; 64],
        };
        vote.signature = ed25519_sign(&accused.secret, &vote.signing_hash().0);
        vote
    };
    DoubleVoteEvidence::from_votes(context, signed(None), signed(Some(Hash256([0x99; 32]))))
        .expect("two distinct values signed in one benchmark slot are evidence")
}

/// A committee history together with the roots it has recorded.
struct History {
    /// Frontier a caller is expected to have authenticated independently.
    trusted: CommitteeHistory,
    /// Committee root recorded at height `index + 1`.
    roots: Vec<Hash256>,
}

impl History {
    /// Reads the recorded root for `height`, as `prove` requires of a lookup.
    fn lookup(&self, height: u64) -> Result<Hash256, ConsensusError> {
        let index = usize::try_from(height).map_err(|_| ConsensusError::InvalidTransition)?;
        self.roots
            .get(index - 1)
            .copied()
            .ok_or(ConsensusError::InvalidTransition)
    }
}

/// Records one equal-weight committee per height from one to `entries`.
fn history(seats: &[Validator], entries: u64) -> History {
    let mut trusted =
        CommitteeHistory::new(CHAIN_ID, GENESIS).expect("benchmark namespace is nonzero");
    let mut roots = Vec::new();
    for height in 1..=entries {
        let context = context(seats, height);
        roots.push(context.root());
        trusted
            .append(&context)
            .expect("contiguous heights in one namespace append");
    }
    History { trusted, roots }
}

/// Bundles an offence at height one with its historical membership witness.
///
/// Height one is the deepest path in the recorded tree, so the witness is the
/// longest one that history length admits.
fn historical_evidence(seats: &[Validator], recorded: &History) -> HistoricalEvidence {
    let entries = recorded.trusted.entries();
    let proof = recorded
        .trusted
        .prove(1, entries, |height| recorded.lookup(height))
        .expect("the complete recorded frontier proves its own first height");
    let context = context(seats, 1);
    HistoricalEvidence::new(
        &recorded.trusted,
        &committee(seats, 1),
        &public_keys(seats),
        proof,
        evidence(seats, &context),
    )
    .expect("a verified offence at a recorded height bundles")
}

/// Measures committee authentication and finality certificate verification.
fn certificate_benchmarks(suite: &mut Suite) {
    for size in COMMITTEE_SIZES {
        let seats = validators(size);
        let keys = public_keys(&seats);
        let members = committee(&seats, 1);
        let authenticated = context(&seats, 1);
        let block = header(&authenticated).compute_hash();
        let finalized = header(&authenticated);
        let full = certificate(&seats, &authenticated, block, size);
        let minimum = certificate(&seats, &authenticated, block, quorum_seats(size));
        let encoded = full.encode().expect("a canonical certificate encodes");

        suite.bench(format!("committee/total_power/{size}"), || {
            members.total_power()
        });
        suite.bench(format!("committee/commitment/{size}"), || {
            members.commitment(CHAIN_ID)
        });
        // One registration per seat, so this is the cost of trusting a new
        // committee rather than the cost of using an existing one.
        suite.bench(format!("committee/authenticate/{size}"), || {
            AuthenticatedCommittee::new(CHAIN_ID, &members, &keys)
        });
        suite.bench(format!("committee/round_robin_proposer/{size}"), || {
            authenticated.round_robin_proposer(3)
        });
        // Every seat signs, so this decides exactly `size` signatures.
        suite.bench(format!("certificate/verify_all_seats/{size}"), || {
            authenticated.verify_certificate(&full, &finalized)
        });
        // A certificate carrying only the minimum quorum, which is what a
        // collector emits as soon as the threshold is first crossed.
        suite.bench(format!("certificate/verify_minimum_quorum/{size}"), || {
            authenticated.verify_certificate(&minimum, &finalized)
        });
        suite.bench(format!("certificate/weighted_quorum_only/{size}"), || {
            weighted_quorum_met(&authenticated, &full)
        });
        suite.bench(format!("certificate/encode/{size}"), || full.encode());
        suite.bench(format!("certificate/decode/{size}"), || {
            FinalityCertificate::decode(&encoded)
        });
    }
}

/// Measures the prevote quorum path over the same committee sizes.
fn prevote_benchmarks(suite: &mut Suite) {
    for size in COMMITTEE_SIZES {
        let seats = validators(size);
        let authenticated = context(&seats, 1);
        let block = header(&authenticated).compute_hash();
        let mut votes: Vec<_> = seats
            .iter()
            .map(|seat| {
                let mut vote = precommit(seat, &authenticated, block);
                vote.phase = VotePhase::Prevote;
                vote.signature = ed25519_sign(&seat.secret, &vote.signing_hash().0);
                vote
            })
            .collect();
        votes.sort_by_key(|vote| vote.voter);
        // `from_votes` takes ownership, so the clone of `size` fixed-width
        // votes is inside the measurement and cannot be subtracted from it.
        suite.bench(format!("prevote/from_votes/{size}"), || {
            PrevoteCertificate::from_votes(&authenticated, votes.clone())
        });
    }
}

/// Measures single-vote signing bytes, verification and framing.
fn vote_benchmarks(suite: &mut Suite) {
    let seats = validators(4);
    let authenticated = context(&seats, 1);
    let block = header(&authenticated).compute_hash();
    let vote = precommit(&seats[0], &authenticated, block);
    let encoded = vote.encode();

    suite.bench("vote/signing_hash", || vote.signing_hash());
    suite.bench("vote/verify", || authenticated.verify_vote(&vote));
    suite.bench("vote/encode", || vote.encode());
    suite.bench("vote/decode", || Vote::decode(&encoded));
    suite.bench("quorum/power", || quorum_power(MEMBER_POWER * 128));
}

/// Measures portable double-vote evidence, independent of any history.
fn evidence_benchmarks(suite: &mut Suite) {
    let seats = validators(4);
    let authenticated = context(&seats, 1);
    let proof = evidence(&seats, &authenticated);
    let encoded = proof.encode();

    // Two strict signatures plus the slot comparison; committee size does not
    // enter, because only the accused seat is verified.
    suite.bench("evidence/verify", || proof.verify(&authenticated));
    suite.bench("evidence/encode", || proof.encode());
    suite.bench("evidence/decode", || DoubleVoteEvidence::decode(&encoded));
    suite.bench("evidence/offence_id", || proof.offence_id());
}

/// Measures the committee history frontier and its historical witnesses.
fn history_benchmarks(suite: &mut Suite) {
    let seats = validators(HISTORY_COMMITTEE);
    for entries in HISTORY_LENGTHS {
        let recorded = history(&seats, entries);
        let next = context(&seats, entries + 1);
        let bundle = historical_evidence(&seats, &recorded);
        let witness = recorded
            .trusted
            .prove(1, entries, |height| recorded.lookup(height))
            .expect("the complete recorded frontier proves its own first height");
        let proven = context(&seats, 1);

        // `append` needs an owned frontier, so the clone of 64 peak slots is
        // inside this measurement; `history/clone` reports it separately.
        suite.bench(format!("history/append/{entries}"), || {
            let mut frontier = recorded.trusted.clone();
            frontier.append(&next)
        });
        suite.bench(format!("history/clone/{entries}"), || {
            recorded.trusted.clone()
        });
        suite.bench(format!("history/commitment/{entries}"), || {
            recorded.trusted.commitment()
        });
        // Proving reads every recorded root once, unlike verifying a proof.
        suite.bench(format!("history/prove/{entries}"), || {
            recorded
                .trusted
                .prove(1, entries, |height| recorded.lookup(height))
        });
        suite.bench(format!("history/proof_verify/{entries}"), || {
            witness.verify(&recorded.trusted, &proven)
        });
        // Rebuilds the historical context from the bundle's own keys, then
        // checks the witness and both signatures. Amortizing a shared history
        // prefix across several bundles is a caller concern, not measured here.
        suite.bench(format!("history/evidence_verify/{entries}"), || {
            bundle.verify(&recorded.trusted)
        });
    }
}

fn main() {
    let mut suite = Suite::new("consensus");
    certificate_benchmarks(&mut suite);
    prevote_benchmarks(&mut suite);
    vote_benchmarks(&mut suite);
    evidence_benchmarks(&mut suite);
    history_benchmarks(&mut suite);
    suite.report();
}
