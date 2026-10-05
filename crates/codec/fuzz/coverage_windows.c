// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

// COFF section boundaries for coverage-only fuzzing without the ASan runtime.
// LLVM inserts counters into .SCOV$CM and PC pairs into .SCOVP$M. Its initializer
// advances eight bytes past each start sentinel; the one-byte counter end avoids
// linker padding being miscounted as coverage. These are data, not callbacks.
// ABI reference: https://llvm.org/doxygen/SanitizerCoverage_8cpp_source.html
#include <stdint.h>

#pragma section(".SCOV$CA", read, write)
#pragma section(".SCOV$CZ", read, write)
#pragma section(".SCOVP$A", read)
#pragma section(".SCOVP$Z", read)

__declspec(allocate(".SCOV$CA")) uint64_t __start___sancov_cntrs = 0;
__declspec(allocate(".SCOV$CZ")) __declspec(align(1)) uint8_t __stop___sancov_cntrs = 0;
__declspec(allocate(".SCOVP$A")) const uint64_t __start___sancov_pcs = 0;
__declspec(allocate(".SCOVP$Z")) const uint64_t __stop___sancov_pcs = 0;
