<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 56. Local performance measurement

`crates/testkit/src/bench.rs` is a bounded measurement harness, and each
benchmarked crate carries `benches/` targets that use it. A benchmark run
records integer nanosecond statistics for one operation on one machine. The
harness has no assertions and no timing threshold anywhere, so no measured
figure can fail CI, and a benchmark can never substitute for a test.

Until this harness existed the workspace had no benchmarks at all, and several
documents said so explicitly. Those statements are now narrowed rather than
deleted: a harness and micro-benchmarks exist, while distributed and end-to-end
throughput remain unmeasured.

## Why no benchmarking framework

The workspace pins every dependency to an exact version and
`.github/scripts/check-license-coverage.py` pins `locked_packages` at 158 with a
committed baseline. A benchmarking framework would add tens of locked packages,
break that baseline, and widen the dependency and licence surface that
[document 51](51-dependency-and-security-review.md) records. The harness is
therefore standard-library only, and the sole new dependency edge is a path
dev-dependency on the existing in-workspace `testkit`. The locked package count
is unchanged at 158.

## Measurement method

A round executes a calibrated batch of operations under one `Instant` bracket,
and the elapsed time is divided by the batch size before any statistic is taken.
Calibration starts at one operation and doubles the batch until a round reaches
`DEFAULT_TARGET_ROUND` (2 ms) or the batch reaches `MAX_BATCH` (2^24), so
per-call clock overhead is not attributed to the operation and an expensive
operation is never run more than twice as often as needed. Three unmeasured
warmup rounds precede sampling. Every statistic is an integer nanosecond count;
no floating point participates, and the even-sample median uses `u128::midpoint`
rather than a sum that could overflow.

`ASTROLUNE_BENCH_ROUNDS` and `ASTROLUNE_BENCH_TARGET_US` shorten exploratory
runs. Malformed or zero values are ignored rather than rejected, because an
override exists to save time and must not stop a measurement. Overrides change
only sampling duration and the reported round count.

Each suite prints a readable table followed by one `astrolune.benchmark/1` JSON
record, matching the schema convention of the other report tools in
`.github/scripts`, so a run can be captured as an artifact without re-parsing
the table.

## What a measurement does not establish

- **Not correctness.** Worker-count equivalence for parallel verification and
  parallel execution is established by the tests described in
  [document 9](09-cryptographic-foundations.md#bounded-parallel-verification)
  and [document 29](29-parallel-payments-and-wasm.md). A worker count that
  measures faster is not more correct, and a slower one is not wrong.
- **Not comparable across machines.** Figures below state one host. They do not
  transfer to another CPU, another toolchain, or a virtualized runner.
- **Not statistically qualified.** The harness reports the minimum, median,
  arithmetic mean and maximum of the sampled rounds. It reports no confidence
  interval, and a difference between two medians is not tested for
  significance.
- **Not operation-latency percentiles.** A sample is a batch mean, not a single
  operation, so percentiles over samples would not be operation-latency
  percentiles. The harness deliberately does not print p95 or p99, and the
  p50/p95/p99 latency requirement of
  [section 7.6](07-validator-requirements.md) remains open.
- **Not throughput.** No figure here is a block, transaction or quorum
  throughput claim, and none is measured under contention from another process
  or under any network condition.
- **Not reliable below about a microsecond.** These figures were taken while the
  same workspace was being compiled, so sub-microsecond rows moved by factors of
  three to seven between repeat runs, and one 16 KiB encode row moved by seven
  as an allocator-state effect. Relative findings reproduced across runs; single
  small absolute values should not be quoted. A stray `maximum_ns` far above its
  median is a scheduling stall, not a tail latency.

## Running the benchmarks

```text
cargo bench --locked -p crypto
ASTROLUNE_BENCH_ROUNDS=5 ASTROLUNE_BENCH_TARGET_US=500 cargo bench --locked -p crypto
```

`cargo bench` builds with optimizations, so a debug-profile figure is not
comparable.

## Hosted runs

The `Benchmarks (ubuntu-latest)` and `Benchmarks (windows-latest)` CI jobs run
every suite on both platforms and are part of the required checks. What they
establish is narrow and deliberate: that every declared benchmark still
compiles, executes and produces measurements on both platforms. What they do not
establish is any figure worth comparing, because the runners are shared and
their timings move between runs by more than the differences this document
draws conclusions from.

Nothing in the job thresholds a duration. It fails only when a benchmark panics,
when the process exits non-zero, when a suite reports no measurement, or when a
declared `[[bench]]` target produces no suite at all. That last check matters
most: `.github/scripts/benchmark-report.py` counts `[[bench]]` targets across the
workspace manifests and refuses a run with fewer suites than targets, so a
benchmark cannot quietly stop running and still report success. Counting targets
rather than matching names is deliberate, since a target may name its suite
differently, as `crates/consensus/benches/potb.rs` reports `consensus-potb`.

Each leg uploads a `benchmarks-<os>` artifact holding one
`astrolune.benchmark-report/1` document, retained for 90 days. Unlike the
`astrolune.suite-result/1` record, which excludes timings so two runs of one
revision stay byte-identical, this record carries its measurements and is
therefore reproducible by neither construction nor intent. It states both facts
in a `comparability` field so a consumer cannot mistake it for a bound. Sampling
is shortened to three rounds at a 300 us target round, since more sampling on a
shared runner buys precision that the environment immediately spends.

Benchmarks are also compiled and linted on every run independently of that job:
the `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
gate includes `benches/`, so a benchmark cannot rot without failing CI. The test
gate does not run them, because a `[[bench]]` target defaults to `test = false`.

## Measured figures

Host: AMD Ryzen 7 7800X3D, 8 physical and 8 logical cores, 31.1 GiB RAM,
Windows 11 10.0.26200, `rustc 1.99.0 (b940084d7 2026-09-28)`, release profile,
5 rounds at a 500 us target round. The host had other processes running; these
are not quiet-machine figures.

### Hash and signature primitives

| Operation | Median |
| --- | --- |
| `blake2s` 32 B | 95 ns |
| `blake2s` 256 B | 304 ns |
| `blake2s` 1 KiB | 1 138 ns |
| `blake2s` 16 KiB | 18 218 ns |
| `ed25519_public_key` from secret | 13 885 ns |
| `ed25519_sign` | 28 756 ns |
| `ed25519_verify` strict | 33 375 ns |

Hashing is linear in input length above the 32-byte block, as expected for a
single-pass construction. Strict verification costs more than signing, which is
the usual asymmetry for the strict checks `ed25519_verify` applies.

### Bounded parallel verification

`crates/crypto/src/batch.rs` verifies independent strict Ed25519 requests across
a bounded worker pool. `MIN_PARALLEL_REQUESTS` is 8, the documented threshold
below which the serial path is taken regardless of the requested worker count.
Medians in nanoseconds:

| Requests | serial | w1 | w2 | w4 | w8 | w16 |
| --- | --- | --- | --- | --- | --- | --- |
| 8 | 375 950 | 276 450 | 236 100 | 250 250 | 286 500 | 287 700 |
| 64 | 2 286 300 | 2 234 600 | 1 229 400 | 818 500 | 532 800 | 673 500 |
| 512 | 18 250 000 | 18 332 900 | 10 730 800 | 5 248 000 | 3 190 500 | 2 972 200 |

This is the first measurement of a path that
[document 9](09-cryptographic-foundations.md#bounded-parallel-verification)
previously qualified only functionally. At 512 requests the measured speedup
from one worker to eight is 5.7x on eight logical cores. At 64 requests
scaling stops at eight workers and sixteen is slower, which is the
oversubscription the worker bound exists to limit. At 8 requests, the smallest
count eligible for more than one worker, the spread between worker counts is
within the run-to-run noise of this host, so these figures do not resolve
whether parallelism helps at that size.

### VRF

| Operation | Median |
| --- | --- |
| `VrfInput::seed` | 242 ns |
| `prove_vrf` | 209 850 ns |
| `verify_vrf` | 119 475 ns |
| `verify_ecvrf` raw | 118 787 ns |
| `VrfOutput::encode` | 6 117 ns |
| `VrfOutput::decode` | 6 026 ns |
| `verify_vrf` rejecting a tampered proof | 9 876 ns |

Two results are worth recording. VRF verification costs roughly 3.6x a strict
Ed25519 verification on this host, which is the per-evaluation charge the
rotating committee path pays. Rejecting a tampered proof costs about one twelfth
of accepting a valid one, because `decode_proof` enforces unique wire bytes by
re-encoding before any group operation runs; cheap rejection of malformed input
is the desirable direction for a path exposed to hostile peers.

`prove_vrf` verifies its own proof before returning, so its figure includes one
verification and is not a lower bound on proving alone. `VrfOutput::encode`
costs about as much as a decode because it also calls `decode_proof`, so
encoding an already-proven output is not the memory copy its signature
suggests.

### State commitments and proofs

Medians at 16, 256 and 4 096 equal-sized accounts. Recomputing the state root
costs 8 585 ns, 136 125 ns and 2 332 500 ns. Subtracting an overlay-copy-only
baseline isolates the hashing at 475, 472 and 475 ns per entry, so per-entry cost
is flat and the root is linear in the account count. A snapshot handle is 30 ns at
every size, which is the structural sharing
[document 10](10-state-and-recovery.md) describes rather than a copy.

Two asymmetries are worth recording.

Proof generation is linear in accounts while verification is logarithmic. At
4 096 accounts a membership proof costs 1 850 400 ns to generate and 2 523 ns to
verify, a factor of 733. Absence proofs are about twice membership on both sides,
as the two-witness design implies. Document 10 already states that proof
generation recomputes a membership path for each neighbour and that incremental
indexing remains future work; these figures quantify what that costs a node
serving proofs today.

A prepared transition costs the same whether it changes 1 account or 256: 2.314,
2.531, 2.331 and 2.474 ms for 1, 2, 16 and 256 changes at 4 096 accounts, all
equal within noise to recomputing the root over zero changes. The whole-map copy
and whole-tree rehash dominate, so block cost tracks the total account count
rather than the block size. Document 10 records the limitation; the measurement
shows the change count is not the variable that matters.

### Durable storage

Durability dominates publication. Committing a block through the append-only log
costs about 2.2 ms regardless of delta width, while the same work against
`InMemoryStorage` costs 3.6 to 4.8 us for zero or one change, roughly a factor of
450. Widening the delta to 64 changes moves the log figure by about 10 percent,
so the two `sync_all` calls, not the payload, set the cost.

`read_finalized` is flat near 140 us across 16, 64 and 256 blocks, which is the
offset-direct read the height index exists to give. `transaction_location` is 20
to 32 ns over the same sweep, the shallow growth of an in-memory map.

Recovery is the one measured result that contradicted a documented bound. With a
constant key set, reopening a 16, 64 and 256 block log costs 1.50, 1.77 and
3.67 ms, consistent with linear replay. With one new key per block the same sweep
costs 1.36, 2.88 and 18.56 ms, so the work grows close to quadratically because
replay re-executes every transition and each recomputes a root over the whole
reconstructed state. [Document 22](22-append-only-chain-storage.md) previously
recorded recovery as linear replay without qualification and now states the
blocks-times-accounts growth.

`read_state_at` measures faster at greater depth, 33 900 ns at depth 1 against
17 209 ns at depth 64. That is not a faster undo walk: reconstruction ends in one
full root recomputation, and in a fixture that adds a key per block a deeper read
reconstructs a smaller tree. The sweep therefore measures reconstructed tree size
more than distance walked, and should not be read as a depth cost.

### Codec and transaction admission

Three observations are recorded as measured facts rather than acted on here,
because each one changes production code on the admission path and belongs in a
change of its own.

`SignedValidator::validate` re-derives the sender address from the account's
already-registered public key on every call. `address_from_public_key` measures
178 ns standalone, and the gap between the rejection that stops before the
derivation and the one immediately after it is 174 ns, at 262 against 436 ns. The
step is 0.5 percent of a signature-verified acceptance and therefore invisible
there, but it is the largest single component of every rejection that gets past
the sender lookup, and the registered key cannot change between calls.

`Resources` and `AccountState` encode field by field into a zero-capacity vector
and pay a reallocation per field, while `BlockHeader` and `ExecutionReceipt`
extend once from a stack `canonical_bytes()` array. The result is a 32-byte
`Resources` encode at 100 ns against a 200-byte `BlockHeader` at 35 ns.

Rejection is cheap on the transaction codec and is not cheap on the contract
codec. A trailing byte or truncated signature is rejected in 56 to 59 ns against
599 ns to accept the same fixture, because `read_exact` borrows and `finish` runs
before anything owned is allocated. The contract payload copies each call key as
it reads, so a key ordering violation at the final pair costs 9 012 ns against
8 642 ns to accept — a late rejection costs more than acceptance there.

Separately, `estimate_encoded_len` is 9 to 220 times cheaper than encoding to
measure a length, at 1 against 224 ns with no access list and 183 against
1 617 ns at 256 entries, which is what lets shape validation reject on size
before allocating. Decode is slower than encode for the repeated-field types,
reversing the primitive relationship: at 256 access-list entries decode is
8 643 ns against 1 483 ns to encode, because encode grows one buffer while decode
performs an owned allocation per item.

### Parallel execution and the runtime

The full scaling result and the per-optimization findings are recorded in
[document 29](29-parallel-payments-and-wasm.md), which previously stated that
local execution performance had not been benchmarked. In summary: the best
observed speedup over the serial path is 2.56x at 128 independent transfers and
four workers, scaling saturates at four workers on an eight-core host, and below
about eight transactions per worker the parallel path loses. The per-attempt
worker pool costs roughly 50 us per thread against a 41 us payment, so one
worker thread costs about one transaction.

Two named optimizations show no measurable wall-clock benefit: the
execution-parent read cache, which has nothing to recover against an in-memory
parent, and bounded declared-key prefetch, whose `InMemoryState::prefetch` is a
no-op. Both remain justified on the read-count grounds their tests establish, and
both are recorded here as unmeasured in wall clock rather than as wins.

In the runtime, engine construction is 51 ns and identical across all six
profiles, so building a `WasmRuntime` per transaction is not a cost. A contract
call's floor is about 8.9 us, of which roughly 6.8 us is compile and validate,
and `execute_call` recompiles the module on every call, so that cost is paid per
transaction in addition to the separate `validate` in `execute_contract`. Fuel
exhaustion is linear in the budget at 22.6 us, 143 us and 1.53 ms for 10 000,
100 000 and 1 000 000 fuel, which implies roughly 15 ms of wall clock for a call
that legally burns 10 000 000 fuel.

The disqualified lazy profiles are visible in wall clock as well as in fuel.
`Lazy` validates a 256-step body in 13 860 ns against the reference profile's
41 343 ns, then executes it in 46 056 ns against 44 906 ns. The work moves to the
executing call rather than disappearing, which is the wall-clock counterpart of
the charged-fuel divergence
[document 29](29-parallel-payments-and-wasm.md#qualified-alternate-engine-configurations)
records, and it is why both modes are disqualified.

### Consensus verification

Finality certificate verification is sublinear from 4 to 64 seats and linear
above it. Per-signature cost is 35 050 ns at 4 seats, which equals a single
`vote/verify` at 34 850 ns because 4 is below `MIN_PARALLEL_REQUESTS`, then falls
to 13 520 ns at 64 and 12 711 ns at 128 seats as the bounded worker pool engages.
A 2x size increase from 64 to 128 costs 1.88x the time, so the path is linear
with a slope near 12.7 us per signature once the pool is saturated. Nothing
superlinear appears.

The non-cryptographic half of verification is negligible: the identity lookup,
checked weighted sum and threshold comparison total 46 to 3 242 ns across the
same sweep, which is 0.03 to 0.20 percent of verification. Strict Ed25519 is
about 99.8 percent of the cost.

`AdmissionCertificate::verify` is now linear in roster size. Over a 7.75x roster
increase from 4 to 31 the time grows 4.19x, where the O(roster^2) behaviour a
prior review removed would have grown it about 60x, and per-approval cost falls
with roster size for the same batching reason as above. This is the regression
evidence that fix deserved.

One residual is visible in the data rather than inferred, and is recorded here
rather than changed: `AdmissionCertificate::verify` builds the incumbent
`AuthenticatedCommittee` twice, once inside the request check and once again
afterwards. Rebuilding a 31-key context measures 227 825 ns, so roughly 43
percent of the 1 063 400 ns certificate verification at the maximum roster is
spent registering the same keys twice. That is linear rather than quadratic, so
it is not a return of the old defect, but it is an available saving if the
request check accepted a pre-resolved context.

The bounded verified VRF transition cache is the clearest optimization in the
measured set, and it contrasts with the execution-parent cache above. A reuse
guard costs 24 to 185 ns across rosters of 4 to 31 and avoids a cold transition
of 1.08 to 8.85 ms, a reduction of 4.3 to 4.8 times ten to the fourth. Only the
decision is timed; what a caller does with a retained committee after a hit lives
in `crates/node` and is not measured here.

Two smaller results are worth recording. `HistoricalEvidence::verify` is
essentially independent of history length at 101 875 to 105 087 ns over a 68x
range of recorded heights, because it is dominated by one context rebuild and two
signature verifications. `CommitteeHistory::prove` is linear in recorded heights
at 531 to 563 ns per entry while proof verification is logarithmic at about
400 ns per path node, the same generation-versus-verification asymmetry the state
proofs show. VRF batch framing is not a byte copy either: encode and decode both
cost about 12.7 us per contribution because the proof point is parsed in both
directions.

## Relation to the preliminary benchmark suite

[Section 7.6](07-validator-requirements.md) lists what must be measured before a
public testnet. This harness addresses part of that list on one local machine
only. Signature verification by batch size and worker count is measured above.
Sequential and parallel execution, committee sizes, and snapshot read scaling
are measured by the per-crate benchmarks in their respective crates.

The following section 7.6 requirements are **not** addressed and remain open:
proposal-to-prevote, prevote-to-precommit and certificate latency at p50/p95/p99;
compact-block reconstruction success and fallback bandwidth; AOT and JIT warm-up,
native-cache hit rate and interpreter parity, none of which exist to measure;
behavior under packet loss, partitions, slow disks, corrupt frames and worker
failure; and the confidence intervals and multi-machine topology a calibration
report must state. Those are distributed measurements on provisioned hardware,
not micro-benchmarks, and [document 52](52-network-operations.md) keeps them as
release activities.
