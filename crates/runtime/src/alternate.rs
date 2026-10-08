// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Alternate engine configuration behind the [`RuntimeBackend`] seam, and the
//! comparison that qualifies it against the reference interpreter.
//!
//! [`RuntimeBackend`] states that an optimized backend must match the
//! interpreter. This module supplies the backend that claim is tested against
//! and the exact field-by-field decision procedure for "match". The alternate
//! backend is the same Wasmi interpreter under a different value-stack
//! allocation and stack-pooling strategy, selected by [`EngineProfile`]. It is
//! not an ahead-of-time compiler, not a just-in-time compiler, not a SIMD
//! backend and not a second independent implementation of WebAssembly; no such
//! backend exists in this workspace.

use std::collections::{BTreeMap, BTreeSet};

use types::{Address, Resources};

use crate::backend::{BackendKind, RuntimeBackend};
use crate::error::RuntimeError;
use crate::version::{ContractModule, RuntimeOutput};
use crate::wasm::{EngineProfile, WasmCall, WasmOutput, WasmRuntime};

/// The first consensus-visible field on which two executions of one module and
/// one finalized call disagree.
///
/// Fields are checked in declaration order, so the reported variant is the
/// earliest disagreement and not an arbitrary one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputDifference {
    /// One execution succeeded where the other failed.
    Acceptance,
    /// Both failed, with different [`RuntimeError`] variants.
    Error,
    /// Contract return bytes differ.
    ReturnData,
    /// The ordered event sequence differs in length, order, topic or body.
    Events,
    /// Staged writes or deletions differ.
    Writes,
    /// Actually accessed keys differ.
    Accessed,
    /// Charged compute, including Wasmi fuel and host work, differs.
    Compute,
    /// Reported linear memory size differs.
    Memory,
    /// Charged state I/O bytes differ.
    Io,
    /// Charged output and event bandwidth bytes differ.
    Bandwidth,
}

/// Compares two complete ABI-v2 executions of one module and one finalized call.
///
/// Returns [`None`] when every consensus-visible field agrees. Return data,
/// events in order, staged writes, actually accessed keys and all four
/// [`Resources`] classes are compared exactly; no tolerance is applied to
/// consumed resources.
#[must_use]
pub fn wasm_difference(
    reference: &Result<WasmOutput, RuntimeError>,
    candidate: &Result<WasmOutput, RuntimeError>,
) -> Option<OutputDifference> {
    match (reference, candidate) {
        (Ok(reference), Ok(candidate)) => {
            if reference.return_data != candidate.return_data {
                Some(OutputDifference::ReturnData)
            } else if reference.events != candidate.events {
                Some(OutputDifference::Events)
            } else if reference.writes != candidate.writes {
                Some(OutputDifference::Writes)
            } else if reference.accessed != candidate.accessed {
                Some(OutputDifference::Accessed)
            } else {
                resource_difference(reference.resources, candidate.resources)
            }
        }
        (Err(reference), Err(candidate)) => {
            (reference != candidate).then_some(OutputDifference::Error)
        }
        _ => Some(OutputDifference::Acceptance),
    }
}

/// Compares two [`RuntimeBackend`] executions of one module and one input.
///
/// This decides agreement only over the fields [`RuntimeOutput`] can express.
/// [`project_wasm_output`] names the three staged effects it cannot, so a
/// passing seam comparison is strictly weaker than a passing
/// [`wasm_difference`] and never substitutes for one.
#[must_use]
pub fn runtime_difference(
    reference: &Result<RuntimeOutput, RuntimeError>,
    candidate: &Result<RuntimeOutput, RuntimeError>,
) -> Option<OutputDifference> {
    match (reference, candidate) {
        (Ok(reference), Ok(candidate)) => {
            if reference.return_data == candidate.return_data {
                resource_difference(reference.resources, candidate.resources)
            } else {
                Some(OutputDifference::ReturnData)
            }
        }
        (Err(reference), Err(candidate)) => {
            (reference != candidate).then_some(OutputDifference::Error)
        }
        _ => Some(OutputDifference::Acceptance),
    }
}

/// Compares the four charged resource classes in declaration order.
fn resource_difference(reference: Resources, candidate: Resources) -> Option<OutputDifference> {
    if reference.compute != candidate.compute {
        Some(OutputDifference::Compute)
    } else if reference.memory != candidate.memory {
        Some(OutputDifference::Memory)
    } else if reference.io != candidate.io {
        Some(OutputDifference::Io)
    } else if reference.bandwidth != candidate.bandwidth {
        Some(OutputDifference::Bandwidth)
    } else {
        None
    }
}

/// Projects a complete ABI-v2 output onto the narrower [`RuntimeOutput`] that
/// the [`RuntimeBackend`] seam returns.
///
/// [`RuntimeOutput`] has exactly two fields, `return_data` and `resources`. It
/// has no field able to carry [`WasmOutput::events`], [`WasmOutput::writes`] or
/// [`WasmOutput::accessed`], so this projection drops those three staged
/// effects and the seam cannot report them to a caller. Widening the seam would
/// change the legacy ABI-v1 interface, so the complete contract is instead
/// compared on [`WasmOutput`] through [`wasm_difference`], and the seam is
/// qualified as exactly this projection of the interpreter path.
#[must_use]
pub fn project_wasm_output(output: &WasmOutput) -> RuntimeOutput {
    RuntimeOutput {
        return_data: output.return_data.clone(),
        resources: output.resources,
    }
}

/// Executes bounded ABI-v2 WebAssembly behind the legacy [`RuntimeBackend`]
/// seam under one [`EngineProfile`].
///
/// The seam passes a module and an input and carries no caller, no finalized
/// height, no contract-local state and no access declaration, so every call
/// runs against [`Address::ZERO`], height zero, empty state and an empty access
/// set under the fixed grant supplied at construction. State helpers therefore
/// trap exactly as they do for an undeclared key, and the seam is usable for
/// equivalence qualification rather than for production execution, which goes
/// through [`WasmRuntime::execute_call`] with a real finalized context.
pub struct WasmBackend {
    /// The interpreter, built under one engine tuning profile.
    runtime: WasmRuntime,
    /// Fixed deterministic grant applied to every seam call.
    limits: Resources,
}

impl WasmBackend {
    /// Creates a seam backend over one engine profile and one resource grant.
    #[must_use]
    pub fn new(profile: EngineProfile, limits: Resources) -> Self {
        Self {
            runtime: WasmRuntime::with_profile(profile),
            limits,
        }
    }

    /// Borrows the interpreter so complete ABI-v2 outputs can be compared.
    #[must_use]
    pub fn runtime(&self) -> &WasmRuntime {
        &self.runtime
    }

    /// Returns the engine tuning profile this backend was built with.
    #[must_use]
    pub fn profile(&self) -> EngineProfile {
        self.runtime.profile()
    }

    /// Returns the finalized call context the seam executes, for the input.
    ///
    /// Exposed so a caller can run the same context through
    /// [`WasmRuntime::execute_call`] and check that the seam result is the
    /// [`project_wasm_output`] projection of the complete output.
    #[must_use]
    pub fn seam_call<'a>(
        &self,
        input: &'a [u8],
        state: &'a BTreeMap<Vec<u8>, Vec<u8>>,
        access: &'a BTreeSet<Vec<u8>>,
    ) -> WasmCall<'a> {
        WasmCall {
            input,
            caller: Address::ZERO,
            height: 0,
            state,
            access,
            limits: self.limits,
        }
    }
}

impl RuntimeBackend for WasmBackend {
    fn kind(&self) -> BackendKind {
        // Every profile interprets Wasmi bytecode. None emits native code, so
        // reporting Aot or Jit here would be a false claim.
        BackendKind::Interpreter
    }

    fn execute(
        &self,
        module: &ContractModule,
        input: &[u8],
    ) -> Result<RuntimeOutput, RuntimeError> {
        let state = BTreeMap::new();
        let access = BTreeSet::new();
        self.runtime
            .execute_call(module, self.seam_call(input, &state, &access))
            .map(|output| project_wasm_output(&output))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EngineProfile, OutputDifference, Resources, WasmOutput, project_wasm_output,
        resource_difference, runtime_difference, wasm_difference,
    };
    use crate::error::RuntimeError;

    /// One mutation of a reference output and the difference it must produce.
    type Case = (fn(&mut WasmOutput), OutputDifference);

    fn output() -> WasmOutput {
        WasmOutput {
            return_data: vec![1, 2, 3],
            events: vec![([7; 32], vec![9])],
            writes: [(vec![1], Some(vec![2]))].into_iter().collect(),
            accessed: [vec![1]].into_iter().collect(),
            resources: Resources {
                compute: 11,
                memory: 65_536,
                io: 3,
                bandwidth: 5,
            },
        }
    }

    #[test]
    fn identical_wasm_outputs_report_no_difference() {
        assert_eq!(wasm_difference(&Ok(output()), &Ok(output())), None);
        assert_eq!(
            wasm_difference(
                &Err(RuntimeError::LimitExceeded),
                &Err(RuntimeError::LimitExceeded)
            ),
            None
        );
    }

    #[test]
    fn every_consensus_visible_wasm_field_is_compared() {
        let cases: [Case; 8] = [
            (
                |output| output.return_data.push(4),
                OutputDifference::ReturnData,
            ),
            (
                |output| output.events.push(([8; 32], vec![])),
                OutputDifference::Events,
            ),
            (
                |output| {
                    output.writes.insert(vec![2], None);
                },
                OutputDifference::Writes,
            ),
            (
                |output| {
                    output.accessed.insert(vec![3]);
                },
                OutputDifference::Accessed,
            ),
            (
                |output| output.resources.compute += 1,
                OutputDifference::Compute,
            ),
            (
                |output| output.resources.memory += 1,
                OutputDifference::Memory,
            ),
            (|output| output.resources.io += 1, OutputDifference::Io),
            (
                |output| output.resources.bandwidth += 1,
                OutputDifference::Bandwidth,
            ),
        ];

        for (mutate, expected) in cases {
            let mut candidate = output();
            mutate(&mut candidate);
            assert_eq!(
                wasm_difference(&Ok(output()), &Ok(candidate)),
                Some(expected),
                "a changed field must be reported as {expected:?}"
            );
        }
    }

    #[test]
    fn event_order_alone_is_a_difference() {
        let mut reference = output();
        reference.events.push(([8; 32], vec![1]));
        let mut candidate = output();
        candidate.events.insert(0, ([8; 32], vec![1]));
        assert_eq!(
            wasm_difference(&Ok(reference), &Ok(candidate)),
            Some(OutputDifference::Events)
        );
    }

    #[test]
    fn acceptance_and_error_variants_are_distinguished() {
        assert_eq!(
            wasm_difference(&Ok(output()), &Err(RuntimeError::Trap)),
            Some(OutputDifference::Acceptance)
        );
        assert_eq!(
            wasm_difference(&Err(RuntimeError::Trap), &Ok(output())),
            Some(OutputDifference::Acceptance)
        );
        assert_eq!(
            wasm_difference(&Err(RuntimeError::Trap), &Err(RuntimeError::LimitExceeded)),
            Some(OutputDifference::Error)
        );
    }

    #[test]
    fn seam_projection_drops_events_writes_and_accessed_keys() {
        let full = output();
        let projected = project_wasm_output(&full);
        assert_eq!(projected.return_data, full.return_data);
        assert_eq!(projected.resources, full.resources);

        // RuntimeOutput cannot express these three, so a seam comparison of two
        // outputs differing only in staged effects reports no difference.
        for mutate in [
            |output: &mut WasmOutput| output.events.clear(),
            |output: &mut WasmOutput| output.writes.clear(),
            |output: &mut WasmOutput| output.accessed.clear(),
        ] {
            let mut candidate = full.clone();
            mutate(&mut candidate);
            assert!(wasm_difference(&Ok(full.clone()), &Ok(candidate.clone())).is_some());
            assert_eq!(
                runtime_difference(
                    &Ok(project_wasm_output(&full)),
                    &Ok(project_wasm_output(&candidate))
                ),
                None,
                "the narrow seam cannot observe a staged-effect difference"
            );
        }
    }

    #[test]
    fn seam_comparison_still_checks_return_data_and_resources() {
        let reference = project_wasm_output(&output());
        let cases: [Case; 2] = [
            (
                |output| output.return_data.clear(),
                OutputDifference::ReturnData,
            ),
            (
                |output| output.resources.compute += 1,
                OutputDifference::Compute,
            ),
        ];
        for (mutate, expected) in cases {
            let mut candidate = output();
            mutate(&mut candidate);
            assert_eq!(
                runtime_difference(&Ok(reference.clone()), &Ok(project_wasm_output(&candidate))),
                Some(expected),
                "the seam must still report {expected:?}"
            );
        }
        assert_eq!(
            runtime_difference(&Ok(reference), &Err(RuntimeError::Trap)),
            Some(OutputDifference::Acceptance)
        );
    }

    #[test]
    fn resource_classes_are_reported_in_declaration_order() {
        let reference = Resources::ZERO;
        let candidate = Resources {
            compute: 1,
            memory: 1,
            io: 1,
            bandwidth: 1,
        };
        assert_eq!(
            resource_difference(reference, candidate),
            Some(OutputDifference::Compute)
        );
        assert_eq!(resource_difference(reference, reference), None);
    }

    #[test]
    fn qualified_profiles_each_move_at_least_one_neutral_axis() {
        assert_eq!(EngineProfile::QUALIFIED[0], EngineProfile::Reference);
        assert_eq!(
            EngineProfile::QUALIFIED.len(),
            EngineProfile::ALTERNATES.len() + 1
        );
        assert!(EngineProfile::Reference.is_consensus_neutral());

        for profile in EngineProfile::ALTERNATES {
            assert!(
                profile.is_consensus_neutral(),
                "{profile:?} must be a qualified profile"
            );
            assert!(
                EngineProfile::QUALIFIED.contains(&profile),
                "{profile:?} must be listed in QUALIFIED"
            );
            assert!(
                profile.preallocates_stack()
                    || profile.cached_stacks() != EngineProfile::Reference.cached_stacks(),
                "{profile:?} must differ from the reference on at least one neutral axis"
            );
        }

        for profile in EngineProfile::DISQUALIFIED {
            assert!(
                !profile.is_consensus_neutral(),
                "{profile:?} must stay disqualified"
            );
            assert!(
                !EngineProfile::QUALIFIED.contains(&profile),
                "{profile:?} must not be listed in QUALIFIED"
            );
        }
    }
}
