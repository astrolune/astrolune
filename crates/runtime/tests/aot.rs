// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Qualification of the ahead-of-time contract backend against the reference
//! interpreter: differential agreement on the shared corpus, bit-exact charged
//! compute, the consensus-visible stack bounds, cache correctness under
//! retirement and concurrency, and the measured reason the lazy compilation
//! strategies may not back a cache.
//!
//! "Ahead of time" is qualified here in one narrow sense: a module is validated
//! and translated before any call budget exists, the artifact is reused, and
//! every consensus-visible field of the result is identical to the reference
//! interpreter that retranslates inside each call. Both sides of every
//! comparison run the same pinned Wasmi 2.0.0 interpreter, so nothing here is a
//! second independent implementation of WebAssembly and nothing here agrees
//! with a hypothetical native backend. No native machine code is emitted, no
//! just-in-time backend exists, and SIMD stays rejected, which
//! `simd_opcodes_stay_rejected_so_the_engine_feature_cannot_be_enabled_silently`
//! pins. No figure here is a throughput measurement.

#[path = "support/corpus.rs"]
mod corpus;

use corpus::{LIMITS, call, context, forge, module, modules, narrow_frames, rejected, wide_frames};
use runtime::{
    AotBackend, ArtifactCache, ArtifactCacheStats, ArtifactKey, BackendKind, EngineProfile,
    ModuleValidator, RuntimeBackend, RuntimeError, WASM_VERSION, WasmRuntime, project_wasm_output,
    runtime_difference, target_identity, wasm_difference,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    thread,
};
use types::Hash256;

/// Charged compute for the minimal returning module, measured on 2026-10-10
/// with Rust 1.99.0 and pinned Wasmi 2.0.0.
///
/// This is the single figure the whole deliverable rests on. The reference
/// interpreter charges it while retranslating inside the call, and every
/// ahead-of-time path must charge exactly the same, on a cache miss and on a
/// cache hit alike. A change that starts charging translation to the call
/// raises it and fails here.
const MINIMAL_COMPUTE: u64 = 2;

/// Builds modules whose only forbidden construct is a SIMD type or operator.
///
/// `wat` assembles all four, so each reaches the engine and is rejected there
/// rather than failing to assemble. Were the pinned engine's `simd` cargo
/// feature enabled, Wasmi's default proposal set would accept them.
fn simd_candidates() -> Vec<Vec<u8>> {
    [
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32)
                (drop (v128.const i32x4 1 2 3 4)) (i32.const 0)))"#,
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32)
                (drop (i8x16.add (v128.const i32x4 1 2 3 4) (v128.const i32x4 5 6 7 8)))
                (i32.const 0)))"#,
        r#"(module (memory (export "memory") 1 1)
            (func (export "call") (result i32)
                (drop (v128.load (i32.const 0))) (i32.const 0)))"#,
        r#"(module (memory (export "memory") 1 1)
            (func $wide (param v128) (result i32) (i32.const 0))
            (func (export "call") (result i32)
                (call $wide (v128.const i32x4 0 0 0 0))))"#,
    ]
    .into_iter()
    .map(module)
    .collect()
}

#[test]
fn the_ahead_of_time_path_agrees_with_the_reference_interpreter_on_accepted_modules() {
    let reference = WasmRuntime::new();
    let (state, access) = context();
    let mut compared = 0;

    for (index, bytes) in modules().into_iter().enumerate() {
        let contract = reference.validate(&bytes, WASM_VERSION).unwrap();
        let expected = reference.execute_call(&contract, call(&state, &access));

        for profile in EngineProfile::QUALIFIED {
            let runtime = WasmRuntime::with_profile(profile);
            let artifact = runtime.compile_artifact(&contract).unwrap();
            assert_eq!(artifact.key(), runtime.artifact_key(&contract));
            assert_eq!(artifact.code_hash(), contract.code_hash);
            assert_eq!(artifact.code_len(), contract.code.len());

            // The same artifact twice: a reused artifact must charge what a
            // freshly translated one charges, or a cache would be observable.
            for repeat in 0..2 {
                assert_eq!(
                    wasm_difference(
                        &expected,
                        &runtime.execute_artifact(&artifact, call(&state, &access))
                    ),
                    None,
                    "module {index} execution {repeat} under {profile:?} must match \
                     the reference interpreter exactly"
                );
                compared += 1;
            }

            let cache = ArtifactCache::with_profile(profile).unwrap();
            for repeat in 0..2 {
                assert_eq!(
                    wasm_difference(&expected, &cache.execute(&contract, call(&state, &access))),
                    None,
                    "module {index} cache execution {repeat} under {profile:?} must \
                     match the reference interpreter exactly"
                );
                compared += 1;
            }
            let counters = cache.stats();
            assert_eq!(
                (
                    counters.hits,
                    counters.misses,
                    counters.compilations,
                    counters.retirements
                ),
                (1, 1, 1, 0),
                "module {index} under {profile:?} must translate once and then hit"
            );
        }
    }

    assert_eq!(
        compared, 160,
        "ten modules, four qualified profiles, two direct and two cached executions each"
    );
}

#[test]
fn the_ahead_of_time_path_agrees_on_rejected_modules_and_error_variants() {
    let reference = WasmRuntime::new();
    let (state, access) = context();
    let mut compared = 0;

    for (index, bytes) in rejected().into_iter().enumerate() {
        let expected_validation = reference.validate(&bytes, WASM_VERSION);
        assert!(
            expected_validation.is_err(),
            "candidate {index} must be rejected by the reference validator"
        );
        let contract = forge(bytes.clone());
        let expected = reference.execute_call(&contract, call(&state, &access));

        for profile in EngineProfile::QUALIFIED {
            let runtime = WasmRuntime::with_profile(profile);
            assert_eq!(
                runtime.compile_artifact(&contract).err(),
                expected_validation.as_ref().err().copied(),
                "candidate {index} must fail to compile with the same error under {profile:?}"
            );

            let cache = ArtifactCache::with_profile(profile).unwrap();
            assert_eq!(
                cache.validate(&bytes, WASM_VERSION),
                expected_validation,
                "candidate {index} must be rejected identically by the cache under {profile:?}"
            );
            assert_eq!(
                wasm_difference(&expected, &cache.execute(&contract, call(&state, &access))),
                None,
                "candidate {index} must fail with the same error under {profile:?}"
            );
            // A rejection is never retained, so a retry cannot become a hit.
            assert_eq!(
                cache.stats(),
                ArtifactCacheStats {
                    misses: 2,
                    ..ArtifactCacheStats::default()
                },
                "candidate {index} must leave the cache empty under {profile:?}"
            );
            compared += 1;
        }
    }

    assert_eq!(
        compared, 40,
        "ten rejected candidates across four qualified profiles"
    );
}

#[test]
fn charged_compute_is_bit_exact_on_every_ahead_of_time_path() {
    let (state, access) = context();
    let bytes = modules().swap_remove(0);
    let reference = WasmRuntime::new();
    let contract = reference.validate(&bytes, WASM_VERSION).unwrap();

    assert_eq!(
        reference
            .execute_call(&contract, call(&state, &access))
            .unwrap()
            .resources
            .compute,
        MINIMAL_COMPUTE,
        "the reference interpreter must still charge {MINIMAL_COMPUTE} for the minimal module"
    );

    for profile in EngineProfile::QUALIFIED {
        let runtime = WasmRuntime::with_profile(profile);
        let artifact = runtime.compile_artifact(&contract).unwrap();
        for repeat in 0..3 {
            assert_eq!(
                runtime
                    .execute_artifact(&artifact, call(&state, &access))
                    .unwrap()
                    .resources
                    .compute,
                MINIMAL_COMPUTE,
                "{profile:?} execution {repeat} of one artifact must charge exactly \
                 {MINIMAL_COMPUTE}; translation must never be charged to a call"
            );
        }

        let cache = ArtifactCache::with_profile(profile).unwrap();
        for repeat in 0..3 {
            assert_eq!(
                cache
                    .execute(&contract, call(&state, &access))
                    .unwrap()
                    .resources
                    .compute,
                MINIMAL_COMPUTE,
                "{profile:?} cache execution {repeat} must charge exactly {MINIMAL_COMPUTE}"
            );
        }
        // Retirement forces a fresh engine and a fresh translation; the charge
        // must not move across it either.
        cache.retire();
        assert_eq!(
            cache
                .execute(&contract, call(&state, &access))
                .unwrap()
                .resources
                .compute,
            MINIMAL_COMPUTE,
            "{profile:?} must charge exactly {MINIMAL_COMPUTE} after a retirement"
        );

        let backend = AotBackend::with_profile(profile, LIMITS).unwrap();
        let seam = backend.execute(&contract, b"seam").unwrap();
        assert_eq!(
            seam.resources.compute, MINIMAL_COMPUTE,
            "{profile:?} must charge exactly {MINIMAL_COMPUTE} across the seam"
        );
    }
}

#[test]
fn deferred_translation_makes_a_charge_depend_on_cache_state_and_stays_refused() {
    let (state, access) = context();
    let bytes = modules().swap_remove(0);
    // Measured on 2026-10-10, Windows with Rust 1.99.0 and pinned Wasmi 2.0.0.
    // Under a deferred strategy the first call through a fresh artifact is
    // charged for the translation it performs, and a second call through the
    // same artifact finds the body already translated and is charged the
    // reference figure. The charge would therefore depend on whether a cache
    // held the artifact, which is why `ArtifactCache` refuses these profiles.
    let expected = [
        (EngineProfile::LazyTranslation, 30),
        (EngineProfile::Lazy, 38),
    ];

    for (profile, first_charge) in expected {
        let runtime = WasmRuntime::with_profile(profile);
        let contract = runtime.validate(&bytes, WASM_VERSION).unwrap();
        let artifact = runtime.compile_artifact(&contract).unwrap();

        let first = runtime
            .execute_artifact(&artifact, call(&state, &access))
            .unwrap();
        let second = runtime
            .execute_artifact(&artifact, call(&state, &access))
            .unwrap();
        assert_eq!(
            first.resources.compute, first_charge,
            "{profile:?} must charge {first_charge} for the first call through an artifact"
        );
        assert_eq!(
            second.resources.compute, MINIMAL_COMPUTE,
            "{profile:?} must charge {MINIMAL_COMPUTE} once the body is translated"
        );
        assert!(
            first.resources.compute > second.resources.compute,
            "{profile:?} must charge the translating call more, not less"
        );
        assert_eq!(
            wasm_difference(&Ok(first.clone()), &Ok(second)),
            Some(runtime::OutputDifference::Compute),
            "{profile:?} must disagree only in charged compute"
        );

        assert!(
            ArtifactCache::with_profile(profile).is_none(),
            "{profile:?} must not be allowed to back an artifact cache"
        );
        assert!(
            AotBackend::with_profile(profile, LIMITS).is_none(),
            "{profile:?} must not be allowed to back the AOT backend"
        );
    }
}

#[test]
fn the_recursion_and_stack_caps_do_not_move_on_the_ahead_of_time_path() {
    let (state, access) = context();
    // Measured on 2026-10-10 with Rust 1.99.0 and pinned Wasmi 2.0.0, and
    // identical to the figures `tests/backends.rs` pins for the recompiling
    // path: the 128-frame cap retires narrow frames at depth 127, and the
    // 16,384-byte value stack cap retires thirty-two-i64 frames at depth 61.
    // Hoisting translation out of the call moves neither bound.
    for profile in EngineProfile::QUALIFIED {
        let cache = ArtifactCache::with_profile(profile).unwrap();

        for (build, last, first_failing) in [
            (narrow_frames as fn(u32) -> Vec<u8>, 126, 127),
            (wide_frames as fn(u32) -> Vec<u8>, 60, 61),
        ] {
            let accepted = cache.validate(&build(last), WASM_VERSION).unwrap();
            assert!(
                cache.execute(&accepted, call(&state, &access)).is_ok(),
                "depth {last} must stay inside the fixed caps under {profile:?}"
            );
            // Once as a hit, so a retained artifact cannot shift the bound.
            assert!(
                cache.execute(&accepted, call(&state, &access)).is_ok(),
                "depth {last} must still succeed on a cache hit under {profile:?}"
            );

            let exhausted = cache.validate(&build(first_failing), WASM_VERSION).unwrap();
            for repeat in 0..2 {
                assert_eq!(
                    cache.execute(&exhausted, call(&state, &access)),
                    Err(RuntimeError::LimitExceeded),
                    "depth {first_failing} execution {repeat} must exceed the fixed \
                     caps under {profile:?}"
                );
            }
        }
    }
}

#[test]
fn simd_opcodes_stay_rejected_so_the_engine_feature_cannot_be_enabled_silently() {
    let (state, access) = context();
    let candidates = simd_candidates();
    assert_eq!(candidates.len(), 4);

    for (index, bytes) in candidates.into_iter().enumerate() {
        let contract = forge(bytes.clone());
        for profile in EngineProfile::QUALIFIED {
            let runtime = WasmRuntime::with_profile(profile);
            // The pinned engine's `simd` cargo feature is off, so Wasmi's
            // default proposal set excludes SIMD and these modules fail
            // validation. Enabling the feature would change the accepted
            // instruction set, which is a runtime-version change and not a
            // backend axis, so this must stay a rejection.
            assert_eq!(
                runtime.validate(&bytes, WASM_VERSION),
                Err(RuntimeError::InvalidModule),
                "SIMD candidate {index} must be rejected by {profile:?}"
            );
            assert_eq!(
                runtime.compile_artifact(&contract).err(),
                Some(RuntimeError::InvalidModule),
                "SIMD candidate {index} must not produce an artifact under {profile:?}"
            );

            let cache = ArtifactCache::with_profile(profile).unwrap();
            assert_eq!(
                cache.prepare(&contract),
                Err(RuntimeError::InvalidModule),
                "SIMD candidate {index} must not be cached under {profile:?}"
            );
            assert_eq!(
                cache.execute(&contract, call(&state, &access)),
                Err(RuntimeError::InvalidModule),
                "SIMD candidate {index} must not execute under {profile:?}"
            );
        }
    }
}

#[test]
fn a_cache_hit_and_a_cache_miss_produce_identical_output_for_every_module() {
    let (state, access) = context();
    let cache = ArtifactCache::new();
    let reference = WasmRuntime::new();
    let mut compared = 0;

    for (index, bytes) in modules().into_iter().enumerate() {
        let contract = reference.validate(&bytes, WASM_VERSION).unwrap();
        let key = cache.prepare(&contract).unwrap();
        assert!(cache.contains(&key), "module {index} must be retained");

        let miss = ArtifactCache::new().execute(&contract, call(&state, &access));
        let hit = cache.execute(&contract, call(&state, &access));
        assert_eq!(
            wasm_difference(&miss, &hit),
            None,
            "module {index} must produce identical output on a hit and a miss"
        );
        assert_eq!(
            miss, hit,
            "module {index} output must be equal, not merely \
                               indistinguishable to the comparison"
        );
        compared += 1;
    }

    assert_eq!(compared, 10);
    let counters = cache.stats();
    assert_eq!(counters.artifacts, 10);
    assert_eq!(
        (counters.hits, counters.misses, counters.compilations),
        (10, 10, 10)
    );
}

#[test]
fn an_artifact_key_separates_code_engine_configuration_and_target() {
    let reference = WasmRuntime::new();
    let first = reference.validate(&modules()[0], WASM_VERSION).unwrap();
    let second = reference.validate(&modules()[7], WASM_VERSION).unwrap();
    assert_ne!(first.code_hash, second.code_hash);

    let base = reference.artifact_key(&first);
    assert_eq!(base.code_hash, first.code_hash);
    assert_eq!(base.version, WASM_VERSION);
    assert_eq!(base.compiler, reference.compiler_identity());
    assert_eq!(base.target, target_identity());

    // Different code never collides.
    assert_ne!(base, reference.artifact_key(&second));

    // One configuration has one identity, whatever engine instance holds it.
    assert_eq!(
        reference.compiler_identity(),
        WasmRuntime::new().compiler_identity()
    );
    assert_eq!(target_identity(), target_identity());

    // Every distinct profile has a distinct compiler identity, so an artifact
    // can never be looked up under an engine it was not compiled by.
    let mut identities = Vec::new();
    for profile in EngineProfile::QUALIFIED
        .into_iter()
        .chain(EngineProfile::DISQUALIFIED)
    {
        let runtime = WasmRuntime::with_profile(profile);
        let identity = runtime.compiler_identity();
        assert!(
            !identities.contains(&identity),
            "{profile:?} must not share a compiler identity with another profile"
        );
        identities.push(identity);
        let key = runtime.artifact_key(&first);
        if profile == EngineProfile::Reference {
            assert_eq!(key, base, "the reference profile is the base identity");
        } else {
            assert_ne!(
                key, base,
                "{profile:?} must key the same code differently from the reference"
            );
        }
    }
    assert_eq!(identities.len(), 6);
    assert_eq!(identities[0], base.compiler);

    // A key carrying a foreign compiler or target is not a key of this cache.
    let cache = ArtifactCache::new();
    cache.prepare(&first).unwrap();
    for foreign in [
        ArtifactKey {
            compiler: Hash256::ZERO,
            ..base
        },
        ArtifactKey {
            target: Hash256::ZERO,
            ..base
        },
        ArtifactKey {
            code_hash: second.code_hash,
            ..base
        },
    ] {
        assert!(
            !cache.contains(&foreign),
            "a cache must not answer for {foreign:?}"
        );
    }
    assert!(cache.contains(&base));
}

#[test]
fn an_artifact_is_refused_by_a_runtime_that_did_not_produce_it() {
    let (state, access) = context();
    let reference = WasmRuntime::new();
    let contract = reference.validate(&modules()[0], WASM_VERSION).unwrap();
    let artifact = reference.compile_artifact(&contract).unwrap();

    // Same configuration, so the same compiler identity, but a different
    // engine instance: translated code cannot cross engines.
    let twin = WasmRuntime::new();
    assert_eq!(twin.compiler_identity(), reference.compiler_identity());
    assert_eq!(
        twin.execute_artifact(&artifact, call(&state, &access)),
        Err(RuntimeError::Unsupported),
        "an artifact of another engine instance must be refused, not executed"
    );

    // A different configuration is refused for the identity reason as well.
    for profile in EngineProfile::ALTERNATES {
        assert_eq!(
            WasmRuntime::with_profile(profile).execute_artifact(&artifact, call(&state, &access)),
            Err(RuntimeError::Unsupported),
            "{profile:?} must refuse an artifact compiled by the reference engine"
        );
    }

    // Its own runtime still executes it, so the refusal is about ownership.
    assert!(
        reference
            .execute_artifact(&artifact, call(&state, &access))
            .is_ok()
    );
}

#[test]
fn a_forged_module_identity_is_refused_before_any_translation() {
    let (state, access) = context();
    let reference = WasmRuntime::new();
    let cache = ArtifactCache::new();
    let accepted = reference.validate(&modules()[0], WASM_VERSION).unwrap();

    let mut forged_hash = accepted.clone();
    forged_hash.code_hash = Hash256::ZERO;
    let mut forged_version = accepted.clone();
    forged_version.version = runtime::DEMO_VERSION;

    for (label, module, expected) in [
        ("hash", forged_hash, RuntimeError::InvalidModule),
        ("version", forged_version, RuntimeError::Unsupported),
    ] {
        assert_eq!(
            reference.compile_artifact(&module).err(),
            Some(expected),
            "a forged {label} must be refused by compile_artifact"
        );
        assert_eq!(
            cache.execute(&module, call(&state, &access)),
            Err(expected),
            "a forged {label} must be refused by the cache"
        );
        assert_eq!(
            reference.execute_call(&module, call(&state, &access)),
            Err(expected),
            "the recompiling path must refuse a forged {label} identically"
        );
    }
    assert_eq!(cache.stats(), ArtifactCacheStats::default());
}

#[test]
fn retirement_bounds_the_cache_and_never_changes_a_result() {
    let (state, access) = context();
    let reference = WasmRuntime::new();
    let contracts = modules()
        .into_iter()
        .map(|bytes| reference.validate(&bytes, WASM_VERSION).unwrap())
        .collect::<Vec<_>>();
    let expected = contracts
        .iter()
        .map(|contract| reference.execute_call(contract, call(&state, &access)))
        .collect::<Vec<_>>();

    // Three artifacts per generation, with ten distinct modules replayed four
    // times: retirement is reached repeatedly and in the middle of the sweep.
    let cache = ArtifactCache::with_bounds(EngineProfile::Reference, 3, 1 << 20).unwrap();
    assert_eq!(cache.bounds(), (3, 1 << 20));
    for round in 0..4 {
        for (index, contract) in contracts.iter().enumerate() {
            assert_eq!(
                wasm_difference(
                    &expected[index],
                    &cache.execute(contract, call(&state, &access))
                ),
                None,
                "module {index} in round {round} must be unaffected by retirement"
            );
            assert!(
                cache.stats().artifacts <= 3,
                "module {index} in round {round} must leave the cache inside its bound"
            );
        }
    }
    let counters = cache.stats();
    assert!(
        counters.retirements > 0,
        "the bound must actually have been reached"
    );
    assert_eq!(counters.hits + counters.misses, 40);
    assert_eq!(counters.misses, counters.compilations);

    // A byte bound smaller than any module retains nothing and still answers.
    let tiny = ArtifactCache::with_bounds(EngineProfile::Reference, 256, 1).unwrap();
    for (index, contract) in contracts.iter().enumerate() {
        assert_eq!(
            wasm_difference(
                &expected[index],
                &tiny.execute(contract, call(&state, &access))
            ),
            None,
            "module {index} must execute correctly when it cannot be retained"
        );
    }
    let counters = tiny.stats();
    assert_eq!(
        (
            counters.artifacts,
            counters.code_bytes,
            counters.hits,
            counters.retirements
        ),
        (0, 0, 0, 0),
        "a module larger than the byte bound must be neither retained nor retire a generation"
    );

    // An explicit retirement in the middle of a run changes nothing either.
    let cache = ArtifactCache::new();
    for (index, contract) in contracts.iter().enumerate() {
        let before = cache.execute(contract, call(&state, &access));
        cache.retire();
        let after = cache.execute(contract, call(&state, &access));
        assert_eq!(
            wasm_difference(&before, &after),
            None,
            "module {index} must be unaffected by an explicit retirement"
        );
        assert_eq!(&before, &expected[index]);
    }
    assert_eq!(cache.stats().retirements, 10);
}

#[test]
fn one_shared_cache_agrees_with_the_reference_across_concurrent_callers() {
    let reference = WasmRuntime::new();
    let contracts = modules()
        .into_iter()
        .map(|bytes| reference.validate(&bytes, WASM_VERSION).unwrap())
        .collect::<Vec<_>>();
    let (state, access) = context();
    let expected = contracts
        .iter()
        .map(|contract| reference.execute_call(contract, call(&state, &access)))
        .collect::<Vec<_>>();

    // A bound of four over ten modules keeps retirement firing while eight
    // threads execute, which is the interleaving a shared cache must survive.
    let cache = ArtifactCache::with_bounds(EngineProfile::Reference, 4, 1 << 20).unwrap();
    thread::scope(|scope| {
        for thread_index in 0..8 {
            let cache = &cache;
            let contracts = &contracts;
            let expected = &expected;
            scope.spawn(move || {
                let (state, access) = context();
                for round in 0..5 {
                    for (index, contract) in contracts.iter().enumerate() {
                        assert_eq!(
                            wasm_difference(
                                &expected[index],
                                &cache.execute(contract, call(&state, &access))
                            ),
                            None,
                            "module {index} in round {round} on thread {thread_index} \
                             must match the reference interpreter"
                        );
                    }
                }
            });
        }
    });

    let counters = cache.stats();
    assert_eq!(counters.hits + counters.misses, 400);
    assert_eq!(counters.misses, counters.compilations);
    assert!(
        counters.artifacts <= 4,
        "the bound must hold under concurrency"
    );
}

#[test]
fn the_aot_seam_returns_exactly_the_projection_of_the_cached_interpreter_output() {
    let backend = AotBackend::new(LIMITS);
    let (state, access) = (BTreeMap::new(), BTreeSet::new());
    let reference = WasmRuntime::new();
    assert_eq!(backend.kind(), BackendKind::Aot);

    for (index, bytes) in modules().into_iter().enumerate() {
        let contract = reference.validate(&bytes, WASM_VERSION).unwrap();
        let complete = backend
            .cache()
            .execute(&contract, backend.seam_call(b"seam", &state, &access));
        let seam = backend.execute(&contract, b"seam");

        assert_eq!(
            seam,
            match &complete {
                Ok(output) => Ok(project_wasm_output(output)),
                Err(error) => Err(*error),
            },
            "module {index} seam output must be the projected cached output"
        );
        assert_eq!(
            runtime_difference(
                &seam,
                &runtime::WasmBackend::new(EngineProfile::Reference, LIMITS)
                    .execute(&contract, b"seam")
            ),
            None,
            "module {index} must agree with the recompiling seam"
        );
    }
}

#[test]
fn every_qualified_profile_translates_eagerly_and_every_other_one_does_not() {
    // The cache accepts a profile by consensus neutrality, and refuses it
    // because deferred translation would make a charge depend on cache state.
    // The two conditions must keep coinciding, or the constructor would be
    // testing the wrong property.
    for profile in EngineProfile::QUALIFIED {
        assert!(profile.is_consensus_neutral());
        assert!(
            profile.translates_ahead_of_the_call(),
            "{profile:?} is accepted as neutral and must therefore be eager"
        );
        assert!(matches!(
            profile.compilation_mode(),
            wasmi::CompilationMode::Eager
        ));
    }
    for profile in EngineProfile::DISQUALIFIED {
        assert!(!profile.is_consensus_neutral());
        assert!(
            !profile.translates_ahead_of_the_call(),
            "{profile:?} is refused as non-neutral and must therefore defer translation"
        );
        assert!(!matches!(
            profile.compilation_mode(),
            wasmi::CompilationMode::Eager
        ));
    }
}
