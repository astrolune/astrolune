<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 64. Trocto and the Native LLVM Runtime

Trocto `.tc` source compiles directly to LLVM IR and native machine code. Genesis
runtime profile **3** activates signed source deployment, calls, numeric state,
events, fees and deterministic receipts. Profiles 1 and 2 retain their existing
behavior; historical ABI-v2 deployments remain executable under profile 3.

## Source and execution identities

```text
.tc / .tcp -> bounded parser and type checker -> immutable checked program
           -> LLVM 22.1.8 + lld -> isolated persistent native workers
           -> reference/native comparison -> private effects -> atomic commit
```

`trocto-compiler` produces the checked program, independent reference semantics
and LLVM IR. `trocto-runtime` accepts only that program, not external IR or native
binaries. Native artifacts are local derived data and never consensus state.
Source identities include language and metering domains. Native cache identities
also bind the compiler path, pinned toolchain identity and local target.

Existing scalar programs retain language/metering **1/1** and their exact charging.
Typed control flow and host operations use **2/2**. A `.tcp` source package has
`ALTROC02`, little-endian language/metering/source-length `u32` fields and exact
UTF-8 source. Decoding rechecks source, profiles, bounds and absence of trailing
bytes. Publishing a native executable cannot bypass source checking.

## Language profile 2

```tc
fn call(input: u64) -> u64 {
    let current: u64 = state_get("counter");
    let mut next: u64 = current;
    if input > 0 {
        next = current + input;
        state_set("counter", next);
        emit(1, next);
    }
    return next;
}
```

The language supports `u64` and `bool`, inferred or explicit local types,
immutable `let`, `let mut`, checked assignment, lexical scopes, comparisons,
`!`, short-circuit `&&`/`||`, `if`/`else`, `while` and early return. Locals must be
initialized before use; immutable assignment and mixed boolean/integer operations
are rejected. Each source has one `fn call(input: u64) -> u64` entry point.

Scalars are copied values. The profile exposes no pointers, references, heap,
floating point, imports, helper functions, recursive calls or operating-system APIs. Memory safety
uses bounded scalar storage and checked capability indexes. This is not a
Rust-style ownership/borrowing implementation for aggregates; adding such values
requires a new language profile and safety review.

| Bound | Limit |
| --- | ---: |
| UTF-8 source | 65,536 bytes |
| Tokens / checked instructions | 16,384 / 4,096 |
| Locals / syntax nesting / identifier bytes | 1,024 / 64 / 64 |
| State capabilities / key bytes | 1,024 / 256 |
| Events | 256 |
| Native call fuel | 10,000,000 |

The reference evaluator uses flat instructions rather than recursive runtime
syntax trees. Checked arithmetic rejects overflow, underflow and zero divisors.
LLVM uses overflow intrinsics and guarded division. Fuel is charged before each
operation's deterministic error checks, including operations whose values are
unused. Branches, loop backedges, assignment and host operations are charged;
empty infinite loops exhaust fuel. Logical short-circuiting skips the unused
operand and its charges. Binding storage, internal moves and return syntax have
no separate charge. The exact source/control schedule is independent of LLVM
optimization.

## State capabilities and metadata

| Operation | Meaning |
| --- | --- |
| `state_get("key")` | Read a literal ASCII local key; absent value is zero |
| `state_set("key", value)` / `state_delete("key")` | Stage a write or deletion |
| `state_get_at(index)` / `state_set_at(index, value)` / `state_delete_at(index)` | Use a checked transaction capability slot |
| `key_count()` | Number of context slots |
| `key_word(index, word)` | Read a literal limb 0..3 of a 32-byte public raw key |
| `height()` / `caller(word)` | Authenticated height / literal caller-address limb 0..3 |
| `emit(topic, value)` | Stage an ordered numeric event |

Literal keys form the context's sorted prefix. Declared transaction keys not in
that prefix follow in canonical order. The complete table is unique and bounded.
Every state operation checks its slot bounds and authorization. Undeclared
literal keys are represented without reading their state; mentioning one in an
unexecuted branch is allowed. Dynamic address keys can be compared with caller
limbs before accessing per-account balances. Key metadata is public; inspecting
it does not read state. `key_word` requires an exactly 32-byte key.

Stored numeric values use exactly eight little-endian bytes. Call input and return
value have the same representation. Context snapshots, writes, deletes and events
are private. Failure discards all effects, including previously staged writes and
events. Resource accounting includes source/instruction/key storage, declared
state loading, dynamic fuel and final effects. Fees and the sender nonce advance
only after the complete call and transaction budget pass.

The native ABI carries input, fuel, height, state count, key metadata, caller,
state/presence/authorization/write arrays, event buffer/count and output/fuel
fields. Pointers remain inside the trusted harness. Statuses are success `0`,
fuel `1`, overflow `2`, zero divisor `3`, access `4`, event limit `5`, malformed
context `6`, and capability bounds `7`.

## Native isolation and lifecycle

Supported native workers target x86-64 Linux and Windows with LLVM **22.1.8** and
lld. Native Windows builds use MSVC to build and embed the fixed compiler
supervisor; the ordinary Rust build does not require native LLVM. The supervisor
assigns the compiler's job and exact inherited standard handles before resuming
its first thread. Completion is published through an atomic status-file rename
after closing the owned job. This removes PowerShell and dynamic `Add-Type`
compilation from runtime startup. Linux establishes seccomp with pipe-only reads/writes, restricted syscalls
and process/CPU/stack/address-space limits. Windows launches workers in a
capability-free AppContainer and a job with process/memory quotas. Startup checks
the isolation identity and performs file, network, process and memory enforcement
probes before the readiness handshake. A failed check refuses startup.
Windows protects host files through AppContainer confinement; the executable and
AppContainer's own profile storage remain accessible. The file probes verify a
protected host file. Linux's syscall filter denies opening any filesystem path.

Compilation uses an owned directory, bounded diagnostics, disabled clang config
files and a cleared environment. Compiler process-tree cleanup and worker cleanup
retain ownership through failures. Workers have a 128 MiB memory quota. The cache
and per-artifact worker pools are bounded; calls do not hold the global cache lock
while executing. A deterministic trap permits reuse; local failures retire the
affected worker. Compiler identity/configuration, process startup and compilation
do not consume contract fuel.

Linux compiler children inherit per-process limits of 1 GiB address space,
30 CPU seconds, no core dumps and 64 MiB per output file. Windows compiler jobs
limit each process to 512 MiB, the job to 1 GiB and the tree to eight processes.
The compilation deadline covers the complete operation on both platforms.
Linux limits do not provide an aggregate compiler-tree memory or process-count
quota; production deployments can add host cgroup limits.

Every native value, fuel count, state slot, write flag and event is compared with
the reference evaluator. Reference verification supports cooperative local
deadline interruption; interruption is never a contract verdict. Exceeding the
protocol fuel cap is a resource refusal. Missing tools, isolation failures,
timeouts, malformed IPC and divergent results are local infrastructure errors.
The node stops the affected operation and does not score the peer for them.
There is no silent reference fallback for native contract execution.

OS restrictions and differential tests establish specific tested properties.
They do not certify the compiler or isolation implementation through an
independent security audit. Independent review remains necessary for production
qualification.

## Working commands

```powershell
. ./tools/enter-dev.ps1
# Set ASTROLUNE_LLVM_CLANG to the supported clang executable.
cargo run --locked -p cargo-contract -- trocto init target/counter
cargo run --locked -p cargo-contract -- trocto check target/counter/main.tc
cargo run --locked -p cargo-contract -- trocto build target/counter/main.tc target/counter.tcp
cargo run --locked -p cargo-contract -- trocto verify-source target/counter/main.tc target/counter.tcp
cargo run --locked -p cargo-contract -- trocto run target/counter.tcp 5 1000
cargo run --locked -p cli -- devnet target/trocto-network 4 --trocto
```

`package` checks and publishes source without LLVM; `build` also compiles and
starts the isolated backend. `emit-llvm` exports checked IR. Outputs refuse
overwrite. Optional run state files contain `counter=10` or
`hex:<encoded-address>=10`; declared slots are authorized for this local call.
Signing supports `.tc` and `.tcp` and commits identical raw source for both:

```text
cli sign-trocto-deploy <genesis> <seed> <source.tc|source.tcp> <nonce> <expires> <new-output>
cli sign-trocto-call <genesis> <seed> <contract> <input-u64> <keys-file> <nonce> <expires> <max-compute> <new-output>
```

The keys file contains one hex-encoded raw local key per line. Offline signing
does not submit the transaction. Trocto envelopes use `ALCON003`; deployment
addresses, code keys, state keys and receipt-result domains use distinct v3
namespaces. A committed profile-3 marker is required even when a caller enables
contract execution through a direct API. Historical `ALCON002` bytes and domains
retain their original interpretation.

## Execution architecture and evidence

Canonical call code keys are immutable reads, so independent callers can share
code without introducing write dependencies. Mixed dependency plans dispatch a
ready transaction as soon as its predecessors complete, without a whole-wave
barrier. Retained scoped workers and immutable views preserve sender order and
RAW/WAR/WAW edges; output ordering, capacity checks and final commit stay
canonical. Speculative deterministic errors replay serially. Native infrastructure
failures remain local and do not select another execution backend.

The earlier scheduler measurement changed 16 shared-code calls from 16 waves to
one: median 0.889 ms to 0.539 ms with four workers on one Windows host. The
[comparison](assets/trocto-architecture-2026-10-31/comparison.json),
[before](assets/trocto-architecture-2026-10-31/before.log) and
[after](assets/trocto-architecture-2026-10-31/after.log) retain its conditions.
These figures describe that scheduler change, not the new native backend.

The [readiness comparison](assets/trocto-readiness-2026-10-31/comparison.json)
uses an isolated source copy with identical fixtures and a switched wave/ready
dispatch path. For 44 payment transactions shaped into 16 dependency waves,
four-worker median changed from 1.4465 ms to 1.1710 ms (1.235×). Two workers
regressed from 1.4423 ms to 1.6334 ms. Unchanged control paths fluctuated 5–15%
under background load; seven short rounds establish no general speedup or
statistical significance. [Before](assets/trocto-readiness-2026-10-31/before.log)
and [after](assets/trocto-readiness-2026-10-31/after.log) retain the raw measurements.

Native/compiler/CLI/node tests cover rejection, control flow, dynamic capabilities,
fuel/error ordering, isolation startup, state rollback, concurrent worker reuse,
and receipt/archive equality after restart. Certified validator tests verify a
native call's finality certificate and receipt, then replay its state through
observer catch-up and restart. CI is configured to install the pinned toolchain
and require native qualification on Linux and Windows. Local executor measurements
cannot establish a worldwide ranking; network qualification must measure
verified finality, durable publication, queue growth and latency under load.
