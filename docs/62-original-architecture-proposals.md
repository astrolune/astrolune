<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 62. VeyraFold and LuneSeal: Candidates for Original Architecture

Date: October 15, 2026. Status: **planned / research hypothesis**.
These are non-normative experiment designs, not implemented network properties.
For context, the baseline, and the development plan, see
[document 61](61-network-architecture-research.md).

## What could qualify as an original contribution

The names are provisional. Targeted searches for `"VeyraFold"` and
`"LuneSeal" consensus blockchain` returned no matches; this does not establish
global name uniqueness or algorithmic originality. Those claims require a
separate review of equivalent mechanisms.

Novelty must rest on a verifiable algorithmic distinction. Prefix scans, dependency
DAGs, incremental Merkle trees, memoization, and pipelining are already known.
None of those techniques alone is claimed as an invention here. The following
sections define specific designs that may contain an original contribution, along
with conditions under which that claim must be rejected. These designs introduce
no new consensus protocol and do not change PoTB.

## VeyraFold — Guarded Prefix Execution

**Description:** transform native-payment chains into compositions of verifiable
account transitions while preserving every intermediate balance, nonce, resource
reservation, receipt, and the first sequential error.

A conventional parallel executor encounters an A→B→C chain and waits for each
preceding transaction to finish. VeyraFold explores a different path: native
transfer amounts are specified in signed payloads rather than computed by an
arbitrary VM. Debit/credit event sequences can be constructed for each account
in advance, and their prefixes computed in parallel. Invalid operations are not
skipped: if any operation fails the exact checks, the entire speculative result
is discarded.

### Initial scope

Only a contiguous segment of native payments, with unchanged height/prices/capacity
and all touched accounts present in the parent snapshot. Contracts, system
operations, account creation, and context changes introduce a segment boundary
or trigger fallback. Self-transfers initially also use the reference path: their
reserve check includes the amount, although their final balance delta is only
minus the fee.

This limits acceleration, not transaction validity: every unsupported case runs
through the existing serial executor.

### Transition algebra

A balance transition is represented by `G = (d, lo, hi)`: a valid input balance
`b` must be in `[lo, hi]`, and the output is `b + d`. All calculations use checked
integer arithmetic in a sufficiently wide type; representation overflow triggers
fallback.

Composition, “A followed by B”:

```text
d(A·B)  = d(A) + d(B)
lo(A·B) = max(lo(A), lo(B) - d(A))
hi(A·B) = min(hi(A), hi(B) - d(A))
```

`lo > hi` denotes an impossible segment. The identity is `(0, 0, u64::MAX)` for
valid account balances. This composes partial translations and is therefore
associative under exact arithmetic. Its formal correspondence with the **complete**
executor still needs to be proved; associativity alone is insufficient.

For the sender of an ordinary transfer, `d = -(amount + actual_fee)`, and the lower
bound includes `amount + cost(resource_limit, authenticated_prices)`, matching the
reserve check in [PaymentSession](../crates/execution/src/payment.rs).
For the recipient, `d = amount`, with an upper bound of `u64::MAX - amount`.
Replacing the reserve with the actual fee would change transaction validity.

A separate prefix count of outgoing transfers gives the expected nonce before
each transaction. Incoming transfers do not increment the nonce. Separate checked
prefix sums cover the four Resources components; prices and limits remain unchanged.

### Proposed algorithm

1. Decode the entire segment with bounded inputs; prepare canonical IDs, payloads,
   and stateless checks. Strictly verify every Ed25519 signature; cryptographic
   verification is not disabled.
2. Construct `(account, original_tx_index, debit_or_credit)` events, preserving
   the original order within each account. Bound event counts and memory.
3. Run segmented prefix scans over guards, balance deltas, nonces, and resources.
   Reconstruct the exact input/output account states for every transaction.
4. Apply ALL reference-path checks, including chain/version/expiry, prices,
   nonce, account existence, access lists, resources, and overflow. Stateless and
   stateful check results cannot be treated as interchangeable in error precedence.
5. On any error or unsupported case, replay the original segment sequentially.
   Replay determines the canonical first error and preserves atomicity; worker
   completion order does not.
6. For a wholly successful segment, materialize **every** transaction diff,
   observed lease, and receipt in the original order. Then use the existing
   atomic commit.

Summing the whole segment without prefixes is insufficient. With `balance(A)=5`,
an `A→B:8` transfer, and a later `C→A:10` transfer, the final balance might be
positive, but the first transaction must fail. A guard before each operation
preserves that rule.

### Potential benefit and cost

For a long payment chain, the balance computation's dependency depth could fall
from `O(n)` to `O(log n)` with enough workers. Total work remains at least `O(n)`,
and grouping may cost `O(n log n)`. Signature verification, construction of all
receipts/diffs, and state commit remain mandatory. At the current small block
sizes, overhead could consume the entire benefit.

The accelerator does not permit arbitrary DEX operations to execute in parallel:
such an operation's amount/output may depend on the preceding call's result.

### Candidate original contribution

The candidate is a bounded algebraic executor for **complete AstroLune
native-payment semantics**, combining prefix feasibility, reserve-versus-fee
handling, nonces, per-transaction effects, and reference error replay. Successful
supported segments compute account transitions directly, without a VM
speculate/abort/reexecute loop.

The review must distinguish this complete composition from ordinary prefix scans,
escrow accounting, and speculative transaction execution. If the same conditions
and results follow from an established mechanism, the originality claim must be
withdrawn. The reference executor remains the correctness oracle.

### Experiment and stopping conditions

- Oracle: `PaymentSession`, comparing all receipts, diffs, resources, observed
  leases, roots, errors, and the absence of publication on failure.
- Small exhaustive models: 2–4 accounts, small balances, cycles, and chains;
  additional mutation/fuzz cases for `u64::MAX`, nonce overflow, reserve overflow,
  invalid signatures before/after balance errors, and total-capacity violations.
- Workloads: same sender, same recipient, funding chains, and independent
  transfers; lengths 8/32/128/256, workers 1/2/4/8/16, invalid fractions 0/1/10%.
- Compare with serial execution and current waves on the same host, including
  cryptography and commit. A timing breakdown must show whether state-root
  computation erases the gain.
- Proposed gate: at least a sustained 20% improvement on the target contended
  workload, with no more than 5% regression on other profiles when path selection
  is enabled. This is a future experiment criterion, not an achieved result.
- Any mismatch with the oracle blocks activation. No improvement, or improvement
  obtained only by removing mandatory checks, closes the experiment.

## LuneSeal — Execution-Commitment Sealing

**Description:** combine execution-result readiness with Merkle-subtree readiness,
allowing final portions of state to be hashed while other transactions are still
executing, while preserving the current root and proof formats.

Today, execution produces diffs, after which the reference backend scans the whole
state again. A conventional incremental tree addresses part of the problem and is
an established solution. LuneSeal investigates a narrower mechanism: each portion
of the commitment is “sealed” only after all potential writes to that portion
from the complete verified transaction plan have finished.

### Prerequisites for the first version

The persistent state and cached Merkle foundation has since been implemented in
[document 63](63-incremental-state.md). Early execution-driven sealing remains a
research proposal and is not implemented by that backend change.

Persistent/COW state and the cached Merkle levels from stage P1 are required;
hashing optimization alone would leave full-map cloning and size scanning in
place. The first version supports only a fixed set of existing keys. Insertions,
deletions, unknown accesses, or exceeded limits use the full reference commit.

The existing tree sorts leaves by key. An insertion at the beginning changes the
indices of all following leaves: an `O(log N)` update cannot be promised for this
operation while preserving v1 semantics. This is an explicit first-version limit.

### Seal structure and rules

A local seal contains `(parent_root, ordered_tx_root, layout_identity,
subtree_range, last_writer_frontier, subtree_hash)`. It is a private record of
locally verified computation, **not a cryptographic proof of another node's
execution** or a new consensus certificate.

1. Build a complete bounded plan of potential writes, including implicit account
   effects, nonces, fees, and system effects. Do not trust a producer-supplied plan.
2. Track every writer of each key in the original order. The execution DAG
   preserves read/write dependencies; sealing uses the key's final writer.
3. Maintain a bounded counter of unfinished final writers for each subtree.
   Once they have all completed successfully, assemble its final leaf values
   in a private overlay and compute the subtree hash.
4. Seal a parent subtree after both children are ready; reuse unchanged children
   from the cache only with the correct parent/layout identity. Preserve the
   existing format's unpaired-node promotion and count-bound root wrapper.
5. Verify receipts, the aggregate resource budget, and the final root. Only the
   ordinary certified durable commit publishes state to other subsystems.
6. Any transaction failure, stale context, planning error, or unsupported effect
   discards partial seals; the reference path remains the final authority.

A region cannot be considered ready merely because currently running transactions
do not touch it: a later transaction in the block may still write to it. A proof
for private intermediate state must not be returned as a finalized-block proof.

### Example

```text
T0 -> updates subtree A --------> seal A --+
T1 -> reads unrelated state              +--> root --> verify --> durable commit
T2 -> long call, writes subtree B -> seal B+
```

If T3 later writes to A, seal A waits for T3 even if T0 finished much earlier.
Computing hash(A) may overlap with T2, but the long contract may still determine
the block's overall latency. Completing a seal does not establish finality.

### Distinction and baseline requirements

The proposed contribution is a **shared frontier of completed writes and ready
commitment subtrees, with exact v1 equivalence and rollback of the whole attempt**,
not a new Merkle hash, a new tree, or a new name for ordinary incremental updates.

Compare the proposal with the same incremental backend after all execution has
finished, with early sealing disabled. This isolates the effect of coupling
execution readiness to commitment readiness: ordinary cache reuse must not be
credited to LuneSeal.

### Experiment and stopping conditions

- Baselines: full reference commit; incremental backend after all execution;
  the same backend with early sealing. Hashing and storage parameters are identical.
- Workloads: 1/16/256 updates across different state sizes; uniform and clustered
  keys; a long contract at the beginning/end; late writes to an already touched
  region; insertion/deletion fallback; restarts and stale execution jobs.
- Verify exact equality of roots, membership/absence proofs, receipts, error
  ordering, and storage size bounds; no partial seal may survive an invalid block.
- Metrics: time from the last transaction to root readiness, total block time,
  CPU/allocations/peak RSS, repeated hash count, and fallback rate.
- Proposed gate: at least a 10% improvement in full execution+commit time over an
  already incremental baseline on target mixed workloads, with no more than 5%
  regression on other profiles and a fixed memory budget. This is a measurement plan.
- If only the state microbenchmark improves and E2E does not, do not promote the
  mechanism as a network speedup. Withdraw the novelty claim if the algorithm
  matches an existing one.

## Ideas deliberately left without new branding

| Idea | Why it is not claimed as an original invention |
|---|---|
| Read/write access lists and parallel waves | Established dependency and concurrency control |
| MVCC, DAG scheduling, selective replay | Established transaction-processing techniques |
| Prioritizing transactions that unblock others | A scheduling policy requiring correctness and workload evaluation |
| Finding executable portions of a dependency graph | Dependency analysis rather than a new consensus mechanism |
| Caching results with read/context-set validation | Memoization with explicit validity conditions |
| Incremental Merkle trees, prefetching, historical proof stores | Established state-storage and commitment techniques |
| Caching a verified VRF transition | Already implemented in AstroLune itself |

## Next-stage plan

1. Implement P0/P1 from document 61, retaining the reference path and frozen fixtures.
2. For VeyraFold, first build a bounded mathematical prototype and differential
   oracle; after establishing correspondence, implement an experimental Rust executor.
3. For LuneSeal, first establish a separate incremental baseline, then couple
   execution and commitment readiness. This isolates the candidate contribution.
4. Run ablation experiments for each mechanism and their combined mode. Speedups
   cannot simply be multiplied: the mechanisms may compete for CPU/memory bandwidth.
5. Only after positive results, propose enabling the default path, complete the
   full platform/recovery/compatibility gates, and run distributed benchmarks.

This document delivers two research experiment specifications. Implementation
and performance advantage remain to be established. Any originality claim also
requires a separate review.
