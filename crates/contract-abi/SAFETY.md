<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# ABI-v2 binding review

This is the dedicated exception described by CONTRIBUTING. Rust 2024 requires
`unsafe extern` declarations and unsafe calls for these imports. Without them,
Rust contracts cannot invoke the implemented memory-based WebAssembly host ABI.
The exception is restricted to `src/guest.rs`, compiled only for wasm32. Workspace
lint policy is unchanged. This is an implementation review, not an external audit.

The only intended host is the validated ABI-v2 interpreter in `runtime/src/wasm.rs`.
Its import signatures are fixed; it cannot call guest functions, retain pointers,
access ambient I/O or execute concurrently with the guest. Memory is at most
16 MiB. Import pointers and lengths must be nonnegative i32 and are bounds-checked.

- Input, state reads and caller write only the exclusive output slices/array.
- Output, state writes/deletes and events read only shared input slices.
- Rust borrowing prevents an exclusive destination from aliasing live shared keys.
- No references cross the boundary: only checked integer offsets and lengths.
- Input copying and state reads copy synchronously. Nothing outlives its borrow.
- Empty slices remain valid zero-length ranges. Keys are additionally checked by
  the runtime. Failed host operations trap the whole transaction.
- Signed height bits are reconstructed without numeric narrowing. Return lengths
  are checked against capacity. Unexpected statuses are rejected.
- There is no allocator, raw-pointer dereference, mutable static or native fallback.

The portable Wasmi interpreter is the reference host. The pinned wasm32 build
integration test exercises these bindings against its real implementations;
runtime adversarial tests cover bounds, malformed imports, metering and traps.
Changing the host's synchronous/no-reentry rules requires reviewing this boundary.
