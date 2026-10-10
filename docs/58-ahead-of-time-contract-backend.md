<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 58. Ahead-of-time contract backend

## What ahead of time means here

`WasmRuntime::compile_artifact` validates and translates a module to Wasmi
bytecode and returns a `CompiledArtifact`. `WasmRuntime::execute_artifact` runs
a prepared artifact and translates nothing. Both are new; `execute_call` is
unchanged and still compiles on every call. The whole of the claim is the
ordering: translation now happens strictly before `Store::set_fuel` installs a
call budget, so no call can be charged for it, and the artifact is reused so
that later calls do not repeat it.

The executed code is the same pinned Wasmi 2.0.0 interpreter under the same
engine policy `WasmRuntime::new` pins: the same rejected WebAssembly proposals,
the same fuel schedule, the same 128-frame recursion cap and the same
16,384-byte value stack cap. `BackendKind::Aot` is reported by exactly one type,
`AotBackend`, and it reports that class because translation is complete before a
call's budget exists, not because anything is compiled to machine code.

What this section does not establish: that any native machine code is emitted,
because none is; that a second independent implementation of WebAssembly now
exists, because both sides of every comparison below run one interpreter, one
translator and one fuel schedule; or that `BackendKind::Jit` has an
implementation, because it does not and cannot, which `## SIMD and JIT`
explains. It also does not establish a changed runtime version: `WASM_VERSION`
stays `{ abi: 2, metering: 1 }`.

## Why earlier is safe and later is not

The workspace had already measured the opposite direction and rejected it.
`EngineProfile::LazyTranslation` and `EngineProfile::Lazy` defer translation
into the call, Wasmi charges that work to the executing call's own fuel, and
`EngineProfile::DISQUALIFIED` keeps both out of live execution for that reason.
Ahead-of-time compilation is the inverse move and is safe for the mirror-image
reason: work that happens before any budget exists cannot be charged to a
budget.

Reusing an artifact makes that argument measurable rather than rhetorical. On
2026-10-10, Windows with Rust 1.99.0 and pinned Wasmi 2.0.0, one artifact of the
minimal returning module executed twice charges the following compute.

| Profile | First call through the artifact | Second call | Recompiling call |
| --- | --- | --- | --- |
| `Reference` | 2 | 2 | 2 |
| `PreallocatedStack` | 2 | 2 | 2 |
| `UnpooledStack` | 2 | 2 | 2 |
| `Alternate` | 2 | 2 | 2 |
| `LazyTranslation` | 30 | 2 | 30 |
| `Lazy` | 38 | 2 | 38 |

The two deferred rows are the finding. Under a deferred strategy a reused
artifact charges 30 or 38 on its first use and 2 on every later use, so the
charge would depend on whether a cache happened to hold the artifact, which is a
consensus split that no amount of agreement elsewhere would repair.
`ArtifactCache::with_profile` and `AotBackend::with_profile` therefore return
`None` for those two profiles, `EngineProfile::translates_ahead_of_the_call`
decides it, and
`deferred_translation_makes_a_charge_depend_on_cache_state_and_stays_refused`
pins the figures above so the refusal keeps a measured reason.

What this section does not establish: that the four eager rows are
interchangeable with the deferred rows for any other purpose, since both
deferred profiles stay disqualified however they measure; or that 30 and 38 are
bounds, since both grow with the size of the translated body.

## The artifact identity

`ArtifactKey` was declared for this work and had no references anywhere in the
workspace until now. Its four fields are populated as follows.

`code_hash` is `wasm_code_hash` of the canonical module bytes, which already
commits to the ABI and metering identity through its domain tag. `version` is
the module's own `RuntimeVersion`.

`compiler` is a `BLAKE2s-256` digest under the domain
`astrolune.contract.wasm.compiler.v1` over the pinned engine release, the pinned
engine cargo features, every engine toggle this runtime applies, and the stack
and tuning values the profile resolves to.

```text
compiler = domain_hash(
    "astrolune.contract.wasm.compiler.v1",
    len(WASM_ENGINE_VERSION) || WASM_ENGINE_VERSION
      || len(WASM_ENGINE_FEATURES) || for each feature: len(f) || f
      || len(PINNED_TOGGLES) || for each toggle: code(toggle) || enabled
      || max_recursion_depth || max_stack_height
      || (0) or (1 || min_stack_height)
      || max_cached_stacks || compilation_mode)
```

Three properties make that digest worth keying on. One value, `EnginePolicy`,
produces both the `Config` the engine is built from and the digest, and the
toggles are enumerated in one `PINNED_TOGGLES` table that both the builder and
the encoder iterate, so a toggle cannot be applied without being committed. The
cargo feature list participates because Wasmi derives its default proposal set
from its features rather than from a `Config` call, so enabling `simd` would
change the accepted instruction set without moving any other field; the
`the_declared_engine_pin_matches_the_manifest` test asserts that
`WASM_ENGINE_VERSION`, `WASM_ENGINE_FEATURES` and the `wasmi` line of
`crates/runtime/Cargo.toml` agree, so the engine cannot be bumped or
re-featured without moving every identity. The digest is derived from settings
and not from a profile's name, so renaming `EngineProfile::Alternate` changes no
identity, and all six profiles are measured to produce six distinct digests.

`target` is a digest under `astrolune.contract.wasm.target.v1` over
`std::env::consts::ARCH`, `std::env::consts::OS`, `std::env::consts::FAMILY`,
`usize::BITS` and the target endianness, each length-framed. No CPU feature
detection participates, because the interpreter emits no native code and the
`simd` cargo feature is off, so there is no dispatch for a detected feature to
select.

A configuration digest is not an engine instance, and translated Wasmi bytecode
cannot cross `Engine` instances. `WasmRuntime::execute_artifact` therefore
checks `Engine::same` in addition to the version, compiler and target, and
returns `RuntimeError::Unsupported` when an artifact belongs to another engine,
which `an_artifact_is_refused_by_a_runtime_that_did_not_produce_it` exercises
against a runtime built from the same profile.

What this section does not establish: that the target digest distinguishes two
toolchains, since a different `rustc` that leaves all five encoded values equal
produces the same digest; or that the digest is a security boundary, since it
identifies a configuration and authenticates nothing.

## The bounded generational cache

`ArtifactCache` holds one engine and the artifacts translated into it, and
retires both together. Retirement is all-or-nothing for a specific reason:
Wasmi 2.0.0's code map exposes `alloc_funcs` and no removal, so a translated
function body stays in the engine for the engine's life. Dropping one artifact
would therefore shrink the map and reclaim nothing, and only dropping the engine
with every artifact built on it actually returns the memory. A generation is
retired when the next translation would exceed either bound:
`DEFAULT_CACHE_ARTIFACTS` is 256 artifacts and `DEFAULT_CACHE_CODE_BYTES` is
16,777,216 canonical module bytes. A module larger than the whole byte bound is
executed and never retained, so it cannot retire a generation on every call.

The eviction rule is deterministic in the sense that matters under concurrency:
the cache's contents depend only on the sequence of translations and their
sizes, never on the order of hits and never on how callers interleave. A hit
moves counters and nothing else. Calls execute outside the lock, holding an
`Arc` of the engine and a clone of the artifact, so a generation retired
mid-call stays alive until that call finishes and a result in flight cannot
change. A poisoned lock is recovered rather than propagated, because an artifact
is inserted only after it has been produced and the byte total is updated in the
same statement, so a panic inside translation cannot leave a generation
inconsistent.

`ArtifactCache` implements `ModuleValidator`, so validating bytes retains the
artifact as a side effect and the first call to a freshly deployed contract is
already a hit. A deployment later rejected for an unrelated reason can leave an
artifact for code that never reached state; it is keyed by that code's hash,
bounded with every other artifact, and reachable by no other module.

What this section does not establish: a bound on engine memory across distinct
modules beyond one generation, since the bound is on a generation and a workload
cycling through more than 256 modules retires and retranslates rather than
growing; a bound in translated bytes, since the byte bound counts canonical
WebAssembly input and Wasmi does not expose the size of its output; or any
claim that eviction policy is tuned, since no workload model was measured.

## Removing the double compile from a contract transaction

`crates/execution/src/contract.rs` previously built a `WasmRuntime::new()` per
transaction, called `validate` on the stored code, which compiles, and then
`execute_call` on the same bytes, which compiles again. A contract call
therefore paid for two full translations of one module, every time, on an engine
that was discarded immediately afterwards.

The call path now builds the `ContractModule` identity directly and executes it
through one `ArtifactCache`, which compiles at most once and not at all once the
contract is held. The deploy path keeps its single `validate` call, which now
also retains the artifact. The order of failures is preserved exactly:
`ArtifactCache::execute` checks the module's version, then its hash, then
compiles or reuses, then checks the call's own bounds, which is the order the
old validate-then-execute pair produced, so a module that is invalid and a call
whose budget is out of range still yield `ExecutionError::InvalidContract` and
not `ExecutionError::ResourceLimit`.

The cache is a process-wide `OnceLock` in that module. Ownership was the open
question and the answer is forced: `execute_action` is reached from
`SimpleExecutor`, from `SignedSession` and from a worker-pool chunk, and each of
those is created per block, per execution attempt or per wave and dropped before
the next one, so a cache owned by any of them would be cold on every transaction
and invisible to the others. The process is the only scope that outlives every
caller. Sharing it is safe because it is not consensus state: a hit and a miss
produce identical output, which is pinned, so a node that has never seen a
contract computes what a node that has executed it a thousand times computes.
Sharing one engine across the parallel workers is likewise safe, because the
engine stack pool is the already-qualified `UnpooledStack` axis and
`EngineProfile::QUALIFIED` is measured to be indifferent to it.

What this section does not establish: that contract transactions are now faster
end to end, since only the micro-benchmarks below were measured and block
throughput was not; or that the cache survives a restart, since it is in memory
and a fresh process starts cold.

## Differential qualification

The oracle is `wasm_difference` on `WasmOutput`, never `runtime_difference` on
`RuntimeOutput`. That choice is deliberate and already proven necessary:
`project_wasm_output` drops `events`, `writes` and `accessed`, and
`the_seam_cannot_express_events_writes_or_accessed_keys` demonstrates that a
seam comparison cannot see a staged-effect difference at all. Every comparison
below requires `wasm_difference` to return `None`, which compares acceptance,
error variant, return data, events in order, staged writes, actually accessed
keys and all four charged resource classes exactly, with no tolerance.

`crates/runtime/tests/aot.rs` covers the fixed corpus, which
`crates/runtime/tests/support/corpus.rs` now shares with
`crates/runtime/tests/backends.rs` so both campaigns compare the same modules.
The ten accepted modules are compared against the reference interpreter 160
times: ten modules across the four qualified profiles, twice through a prepared
artifact and twice through a cache, so the second comparison of each pair is a
reused artifact. The ten rejected candidates are compared 40 times, ten across
four profiles, and each requires the same `RuntimeError` variant from
`compile_artifact`, from `ArtifactCache::validate` and from
`ArtifactCache::execute`, and requires the cache to retain nothing.

Charged compute is pinned bit-exactly. The minimal returning module charges 2
compute units on the reference interpreter and on every ahead-of-time path:
three successive calls through one artifact, three successive cache executions,
one cache execution after an explicit retirement, and one execution across the
`AotBackend` seam, for every one of the four qualified profiles. This is the
single most important assertion in the deliverable, because a change that starts
charging translation to the call raises it and fails loudly.

The two consensus-visible stack bounds do not move. Under every qualified
profile a self-recursive module whose frames hold only an `i32` parameter
succeeds at depth 126 and returns `RuntimeError::LimitExceeded` at depth 127,
and the same recursion with thirty-two additional `i64` locals per frame
succeeds at depth 60 and fails at depth 61. Each is executed twice, so a
retained artifact cannot shift a threshold.

Cache behaviour is qualified separately: a hit and a miss produce equal output
for all ten modules; a different `code_hash`, a different engine profile and a
foreign compiler or target digest are each measured not to collide; a cache
bounded to three artifacts replaying ten modules four times leaves every result
unchanged across the retirements it triggers; a cache whose byte bound is one
byte retains nothing, retires nothing and still answers correctly; an explicit
retirement between two executions of each module changes neither; and eight
threads replaying ten modules five times each against one cache bounded to four
artifacts produce 400 executions that all match the reference interpreter.

The workspace campaign in `tests/integration/tests/backends.rs` now drives the
ahead-of-time path alongside the engine profiles, so it inherits all three
campaign sizes and the same xorshift64 mutator seeded `0x6173_7472_6f6c_756e`.
Per candidate it compares `ArtifactCache::validate` against the reference
validator, then executes once on a cold cache, twice on a process-wide cache
bounded to 64 artifacts and 1,048,576 bytes, and twice across a per-candidate
`AotBackend` seam.

```text
cargo test --locked -p runtime --test aot
cargo test --locked -p runtime --test backends
cargo test --locked -p integration --test backends
cargo test --release --locked -p integration --test backends -- --ignored
```

On 2026-10-10, Windows with Rust 1.99.0 and pinned Wasmi 2.0.0, the campaigns
reported the following. The smoke figure is from the unoptimized dev profile;
the two durations are from `--release`, each campaign run on its own.

| Campaign | Candidates | Accepted modules | AOT validations | AOT executions | From a retained artifact | AOT seam executions | Generations retired | Disagreements | Duration |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `backend_qualification_smoke` | 3,012 | 72 | 2,837 | 216 | 144 | 144 | 1 | 0 | n/a |
| `extended_backend_qualification` | 100,012 | 2,514 | 94,672 | 7,542 | 5,028 | 5,028 | 37 | 0 | 1.38 s |
| `million_backend_qualification` | 1,000,012 | 24,681 | 946,320 | 74,043 | 49,362 | 49,362 | 368 | 0 | 14.63 s |

The retirement count is cumulative over the process, so running both ignored
campaigns in one process reports 405 rather than 368 for the second. The
existing engine-profile figures in that report are unchanged, because the
ahead-of-time counters are new fields rather than additions to the old ones.

What this section does not establish: agreement with an independent
WebAssembly implementation, since the reference and the candidate are the same
interpreter and differ only in when translation happened; coverage of inputs the
mutator does not reach, since a seeded mutation campaign is a sample and not a
proof; or anything about throughput, since the reported durations are campaign
wall clock and not benchmarks.

## Measured figures

`crates/runtime/benches/runtime.rs` records five rows per module size.
`aot/compile_artifact` is the translation paid once ahead of any call;
`aot/execute_artifact` is a call that translates nothing;
`aot/transaction/recompiled` is a validating pass followed by a recompiling
call, which is exactly what a contract transaction did before this work;
`aot/transaction/cached` is the same transaction against a warm cache; and
`aot/cache/cold` builds an engine and translates, which is what a call pays
after a retirement.

On 2026-10-10, Windows with Rust 1.99.0, an AMD Ryzen 7 7800X3D with eight cores
and `cargo bench --locked -p runtime`, the medians over 20 rounds were as
follows. All figures are nanoseconds per operation.

| Body steps | Module bytes | `transaction/recompiled` | `transaction/cached` | Ratio | `compile_artifact` | `execute_artifact` | `cache/cold` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 81 | 15,743 | 4,115 | 3.8x | 6,758 | 3,221 | 12,970 |
| 16 | 186 | 20,418 | 3,997 | 5.1x | 8,805 | 3,239 | 14,534 |
| 256 | 1,868 | 92,479 | 6,744 | 13.7x | 44,166 | 3,702 | 51,522 |
| 4,096 | 28,750 | 1,202,750 | 43,469 | 27.7x | 608,225 | 10,169 | 625,325 |

The gain grows with module size because translation does and the rest of a call
does not. A second run on the same host, taken while the workspace was being
compiled, gave 16,434, 21,958, 117,294 and 1,248,650 for the recompiling row and
4,496, 3,883, 9,417 and 48,835 for the cached row, that is 3.7x, 5.7x, 12.5x and
25.6x, so the relative finding reproduced and the absolute values moved by up to
a quarter.

One residual is worth naming, because it limits the gain and is not translation.
At 4,096 body steps the cached transaction costs 43,469 while
`aot/execute_artifact` costs 10,169; the difference is close to the 32,141 that
`wasm_code_hash/28750B` measures, because `ArtifactCache::execute` re-hashes the
module bytes to reject a forged `ContractModule` identity exactly as
`execute_call` does. That check is kept deliberately: skipping it on a hit would
let a caller present forged bytes with a cached hash and have the genuine module
execute. For a large contract the cached path is therefore dominated by a
BLAKE2s pass over the code, not by the interpreter.

What this section does not establish: block, transaction or contract throughput
for any deployment; a figure comparable to another machine, another toolchain or
a shared CI runner; statistical significance of any difference, since the
harness reports no confidence interval; or any license to change the runtime
version, the fuel schedule or the selected engine profile, none of which a
nanosecond figure can justify. Charged compute is a consensus quantity measured
in fuel and is identical on every row above.

## SIMD and JIT

No SIMD backend is delivered, and the decision is deliberate rather than
pending. `crates/runtime/Cargo.toml` pins `wasmi` with
`default-features = false` and five features that exclude `simd`, and Wasmi
derives its default proposal set from its cargo features, setting
`WasmFeatures::SIMD` and `WasmFeatures::RELAXED_SIMD` to
`cfg!(feature = "simd")`. With the feature off the `Config::wasm_simd` setter
does not even exist, so SIMD cannot be enabled from code. Enabling the cargo
feature would widen the accepted instruction set, which `crates/runtime/src/wasm.rs`
already classifies as a runtime-version change rather than a backend axis,
alongside the fuel schedule and the proposal toggles. Four modules whose only
forbidden construct is a SIMD type or operator, a `v128.const`, an `i8x16.add`,
a `v128.load` and a `v128` function parameter, are assembled by `wat` and
rejected with `RuntimeError::InvalidModule` by every qualified profile, by
`compile_artifact`, by `ArtifactCache::prepare` and by `ArtifactCache::execute`,
which `simd_opcodes_stay_rejected_so_the_engine_feature_cannot_be_enabled_silently`
pins so the feature cannot be turned on without a failing test. The cargo
feature list is additionally part of the compiler identity, so enabling it would
invalidate every existing artifact rather than silently reusing one.

No just-in-time backend is delivered, and none can be. `unsafe_code` is
forbidden workspace-wide in `Cargo.toml`, and a native-codegen backend has to
make a page of generated bytes executable and transfer control to it, which no
safe Rust interface offers. The decision is therefore structural rather than a
matter of effort: `BackendKind::Jit` stays a reserved declaration with no
implementation, `AotBackend` is asserted never to report it, and relaxing the
workspace lint would be a change to the project's safety posture and not a
backend choice.

What this section does not establish: that SIMD or native code generation would
be unsound or unprofitable, neither of which was investigated; or that
`BackendKind::Jit` should be removed, since it remains a reserved declaration.

## Limits

The cache is in memory and process-local. Nothing is persisted, no artifact is
shared between processes, and a restart starts cold.

One generation is bounded, the process is not. A workload cycling through more
than `DEFAULT_CACHE_ARTIFACTS` distinct contracts retires and retranslates
rather than growing, which is correct but is thrashing, and no workload model
was measured to choose 256. The byte bound counts canonical WebAssembly input,
because Wasmi 2.0.0 does not expose the size of its translated output, so the
relationship between the bound and resident memory is not measured.

The target identity distinguishes architecture, operating system, target family,
pointer width and endianness, and nothing else. Two different Rust toolchains on
one target produce the same target digest, so an artifact is not invalidated by
a compiler upgrade; artifacts never leave the process, so this bounds nothing in
practice, but it does mean the digest must not be treated as a build identity.

Every comparison in this document is between one interpreter and itself with
translation moved. That qualifies the ordering and the cache, and it establishes
nothing about a hypothetical independent or native implementation. The ten
accepted modules and ten rejected candidates are hand-written fixtures, and the
mutation campaign is a seeded sample; neither is exhaustive over the accepted
instruction set.

No figure in this document is a correctness gate. The benchmark harness has no
assertions and no threshold, the reported campaign durations are wall clock on
one host, and `ROADMAP.md` continues to list unbounded formal qualification and
independent review as open.
