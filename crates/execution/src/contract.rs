// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Authenticated historical and native contract transitions, staged until commit.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

use codec::CanonicalEncode;
use runtime::{
    ArtifactCache, ContractModule, ModuleValidator, RuntimeError, WASM_VERSION, WasmCall,
    wasm_code_hash,
};
use state::{
    AccessMode, AccessRequest, StateDiff, StateLease, StateSnapshot, account_key, read_account,
};
use transaction::{
    ContractAction, ContractPayload, RegisteredAccount, SignedValidator, TransactionError,
    TransactionValidator, ValidationContext, contract_address, contract_code_key,
    contract_state_key, trocto_contract_address, trocto_contract_code_key,
    trocto_contract_state_key,
};
use types::{AccountState, ExecutionReceipt, Resources, Transaction};

use crate::{ExecutionError, TransactionOutput};

pub(crate) fn execute_contract(
    snapshot: &dyn StateSnapshot,
    tx: &Transaction,
    context: ValidationContext,
    capacity: Resources,
    prices: Resources,
) -> Result<TransactionOutput, ExecutionError> {
    let payload = ContractPayload::decode(&tx.payload)?;
    let sender = read_account(snapshot, tx.sender)?.ok_or(TransactionError::UnknownSender)?;
    let validated = SignedValidator::new(
        BTreeMap::from([(
            tx.sender,
            RegisteredAccount {
                state: sender.clone(),
                public_key: payload.public_key,
            },
        )]),
        capacity,
        prices,
    )
    .validate(tx.clone(), context)?;
    let sender_key = account_key(tx.sender);
    if !tx.access_list.contains(&sender_key) {
        return Err(ExecutionError::UndeclaredStateAccess);
    }
    let Effects {
        mut diff,
        actual,
        resources,
        result_bytes,
    } = execute_action(snapshot, tx, context, &payload)?;
    if !resources.fits_in(tx.resource_limit) || !resources.fits_in(capacity) {
        return Err(ExecutionError::ResourceLimit);
    }
    let fee = resources
        .checked_cost(prices)
        .ok_or(ExecutionError::ResourceLimit)?;
    let next = AccountState {
        nonce: sender
            .nonce
            .checked_add(1)
            .ok_or(TransactionError::InvalidNonce)?,
        balance: sender
            .balance
            .checked_sub(fee)
            .ok_or(TransactionError::InsufficientResources)?,
    };
    diff.put(sender_key, next.to_bytes());
    diff.sort_canonical();
    let mut commitment = diff.commitment().as_bytes().to_vec();
    commitment.extend_from_slice(&result_bytes);
    Ok(TransactionOutput {
        receipt: ExecutionReceipt {
            transaction: validated.id,
            succeeded: true,
            resources,
            output_root: types::hash::domain_hash(
                if matches!(
                    payload.action,
                    ContractAction::DeployTrocto(_) | ContractAction::CallTrocto { .. }
                ) {
                    b"astrolune.contract.result.v3"
                } else {
                    b"astrolune.contract.result.v2"
                },
                &commitment,
            ),
        },
        diff,
        observed_lease: StateLease::new(actual),
    })
}

struct Effects {
    diff: StateDiff,
    actual: Vec<AccessRequest>,
    resources: Resources,
    result_bytes: Vec<u8>,
}

/// The process-wide ahead-of-time artifact cache every contract transaction
/// shares.
///
/// Ownership is deliberate. A contract transaction has no object that outlives
/// it: `execute_action` is reached from `SimpleExecutor`, from `SignedSession`
/// and from a worker-pool chunk, and each of those is created per block, per
/// execution attempt or per wave and dropped before the next one. A cache held
/// by any of them would be cold on every transaction and would buy nothing, and
/// a cache held by one of them would be invisible to the others. The cache is
/// therefore anchored to the process, which is the only scope that outlives
/// every caller, and it is bounded so that doing so cannot grow without limit.
///
/// Sharing it is safe because it is not consensus state. An artifact is keyed
/// by code hash, runtime version, engine configuration and target, a hit and a
/// miss produce identical output, and `crates/runtime/tests/aot.rs` pins both
/// properties. A node that has never seen a contract therefore computes the
/// same result as one that has executed it a thousand times.
fn artifacts() -> &'static ArtifactCache {
    static CACHE: OnceLock<ArtifactCache> = OnceLock::new();
    CACHE.get_or_init(ArtifactCache::new)
}

fn execute_action(
    snapshot: &dyn StateSnapshot,
    tx: &Transaction,
    context: ValidationContext,
    payload: &ContractPayload,
) -> Result<Effects, ExecutionError> {
    if matches!(
        payload.action,
        ContractAction::DeployTrocto(_) | ContractAction::CallTrocto { .. }
    ) {
        return execute_trocto_action(snapshot, tx, context, payload);
    }
    let sender_key = account_key(tx.sender);
    let address = match &payload.action {
        ContractAction::Deploy(_) => contract_address(tx.chain_id, tx.sender, tx.nonce),
        ContractAction::Call { address, .. } => *address,
        ContractAction::DeployTrocto(_) | ContractAction::CallTrocto { .. } => unreachable!(),
    };
    let code_key = contract_code_key(address);
    if !tx.access_list.contains(&code_key) {
        return Err(ExecutionError::UndeclaredStateAccess);
    }
    let runtime = artifacts();
    let mut diff = StateDiff::new();
    let mut actual = vec![
        AccessRequest {
            key: sender_key.clone(),
            mode: AccessMode::Write,
        },
        AccessRequest {
            key: code_key.clone(),
            mode: AccessMode::Read,
        },
    ];
    let mut result_bytes = Vec::new();
    let bandwidth = transaction::estimate_encoded_len(tx) as u64;
    let resources = match &payload.action {
        ContractAction::Deploy(code) => {
            if snapshot.get(&code_key)?.is_some() {
                return Err(ExecutionError::InvalidContract);
            }
            // Deployment compiles once and retains the artifact, so the first
            // call to this contract is already a cache hit. The acceptance
            // decision is unchanged; retaining the result is a side effect.
            runtime
                .validate(code, WASM_VERSION)
                .map_err(runtime_error)?;
            diff.put(code_key, code.clone());
            actual[1].mode = AccessMode::Write;
            result_bytes.extend_from_slice(address.as_bytes());
            Resources {
                compute: 100 + code.len() as u64,
                memory: code.len() as u64 + 32,
                io: code.len() as u64 + 32,
                bandwidth,
            }
        }
        ContractAction::Call { input, keys, .. } => {
            let code = snapshot
                .get(&code_key)?
                .ok_or(ExecutionError::InvalidContract)?;
            let mut overhead = Resources {
                compute: 100,
                memory: 32,
                io: code.len() as u64 + 32,
                bandwidth,
            };
            let (local, loaded) = load_state(snapshot, tx, address, keys, &mut actual)?;
            overhead.io += loaded as u64;
            overhead.compute += loaded as u64;
            let limits = subtract(tx.resource_limit, overhead)?;
            let access = keys.iter().cloned().collect::<BTreeSet<_>>();
            // One compile at most, and none at all once the cache holds this
            // contract. The identity is built here rather than by a separate
            // validating pass, so the module's acceptance is decided exactly
            // once: `ArtifactCache::execute` checks the version and the hash,
            // compiles or reuses, and only then checks the call's own bounds,
            // which is the order a validate-then-execute pair produced.
            let module = ContractModule {
                code_hash: wasm_code_hash(&code),
                version: WASM_VERSION,
                code,
            };
            let result = runtime
                .execute(
                    &module,
                    WasmCall {
                        input,
                        caller: tx.sender,
                        height: context.next_height,
                        state: &local,
                        access: &access,
                        limits,
                    },
                )
                .map_err(runtime_error)?;
            let charged = stage_result(address, result, &mut diff, &mut actual, &mut result_bytes);
            overhead
                .checked_add(charged)
                .ok_or(ExecutionError::ResourceLimit)?
        }
        ContractAction::DeployTrocto(_) | ContractAction::CallTrocto { .. } => unreachable!(),
    };
    Ok(Effects {
        diff,
        actual,
        resources,
        result_bytes,
    })
}

fn native_artifacts() -> &'static trocto_runtime::NativeArtifactCache {
    static CACHE: OnceLock<trocto_runtime::NativeArtifactCache> = OnceLock::new();
    CACHE.get_or_init(trocto_runtime::NativeArtifactCache::new)
}

fn execute_trocto_action(
    snapshot: &dyn StateSnapshot,
    tx: &Transaction,
    context: ValidationContext,
    payload: &ContractPayload,
) -> Result<Effects, ExecutionError> {
    // The caller's contracts flag is insufficient: only committed profile 3
    // authorizes native source, including through direct execution APIs.
    if snapshot.get(&genesis::runtime_key())?.as_deref() != Some(&3u32.to_le_bytes()) {
        return Err(TransactionError::UnsupportedPayload.into());
    }
    if tx.resource_limit.compute > trocto_runtime::MAX_NATIVE_FUEL {
        return Err(ExecutionError::ResourceLimit);
    }
    let address = match &payload.action {
        ContractAction::DeployTrocto(_) => {
            trocto_contract_address(tx.chain_id, tx.sender, tx.nonce)
        }
        ContractAction::CallTrocto { address, .. } => *address,
        _ => unreachable!(),
    };
    let code_key = trocto_contract_code_key(address);
    if !tx.access_list.contains(&code_key) {
        return Err(ExecutionError::UndeclaredStateAccess);
    }
    let mut actual = vec![
        AccessRequest {
            key: account_key(tx.sender),
            mode: AccessMode::Write,
        },
        AccessRequest {
            key: code_key.clone(),
            mode: AccessMode::Read,
        },
    ];
    let mut diff = StateDiff::new();
    let mut result_bytes = Vec::new();
    let bandwidth = transaction::estimate_encoded_len(tx) as u64;
    let resources = match &payload.action {
        ContractAction::DeployTrocto(code) => {
            if snapshot.get(&code_key)?.is_some() {
                return Err(ExecutionError::InvalidContract);
            }
            let source = std::str::from_utf8(code).map_err(|_| ExecutionError::InvalidContract)?;
            // Native artifacts are local only. Committed bytes are bounded UTF-8
            // source; every node independently checks and compiles this source.
            trocto_compiler::compile(source).map_err(|_| ExecutionError::InvalidContract)?;
            let resources = Resources {
                compute: 100 + code.len() as u64,
                memory: code.len() as u64 + 32,
                io: code.len() as u64 + 32,
                bandwidth,
            };
            subtract(tx.resource_limit, resources)?;
            native_artifacts()
                .prepare(source)
                .map_err(|error| native_error(&error))?;
            diff.put(code_key, code.clone());
            actual[1].mode = AccessMode::Write;
            result_bytes.extend_from_slice(address.as_bytes());
            resources
        }
        ContractAction::CallTrocto { input, keys, .. } => execute_trocto_call(
            snapshot,
            tx,
            context,
            address,
            (input, keys),
            &mut NativeEffects {
                diff: &mut diff,
                actual: &mut actual,
                result_bytes: &mut result_bytes,
            },
        )?,
        _ => unreachable!(),
    };
    Ok(Effects {
        diff,
        actual,
        resources,
        result_bytes,
    })
}

struct NativeEffects<'a> {
    diff: &'a mut StateDiff,
    actual: &'a mut Vec<AccessRequest>,
    result_bytes: &'a mut Vec<u8>,
}

fn execute_trocto_call(
    snapshot: &dyn StateSnapshot,
    tx: &Transaction,
    context: ValidationContext,
    address: types::Address,
    (input, keys): (&[u8], &[Vec<u8>]),
    effects: &mut NativeEffects<'_>,
) -> Result<Resources, ExecutionError> {
    let code_key = trocto_contract_code_key(address);
    let bandwidth = transaction::estimate_encoded_len(tx) as u64;
    let code = snapshot
        .get(&code_key)?
        .ok_or(ExecutionError::InvalidContract)?;
    let source = std::str::from_utf8(&code).map_err(|_| ExecutionError::InvalidContract)?;
    let program = native_artifacts()
        .program(source)
        .map_err(|error| native_error(&error))?;
    for local in keys {
        if !tx
            .access_list
            .contains(&trocto_contract_state_key(address, local))
        {
            return Err(ExecutionError::UndeclaredStateAccess);
        }
    }
    let mut context_keys = program.state_keys().to_vec();
    context_keys.extend(
        keys.iter()
            .filter(|key| program.state_keys().binary_search(key).is_err())
            .cloned(),
    );
    if context_keys.len() > transaction::contract::MAX_CONTRACT_KEYS {
        return Err(ExecutionError::ResourceLimit);
    }
    let mut state = Vec::with_capacity(context_keys.len());
    let mut access = Vec::with_capacity(context_keys.len());
    let mut loaded = 0u64;
    let mut logical_memory = code.len() as u64 + 32 + program.instruction_count() as u64 * 8;
    for local in &context_keys {
        logical_memory += local.len() as u64 + 16;
        let authorized = keys.binary_search(local).is_ok();
        access.push(authorized);
        if authorized {
            let global = trocto_contract_state_key(address, local);
            let bytes = snapshot.get(&global)?;
            let value = bytes
                .as_deref()
                .map(|bytes| {
                    let bytes: [u8; 8] = bytes
                        .try_into()
                        .map_err(|_| ExecutionError::InvalidContract)?;
                    Ok::<_, ExecutionError>(u64::from_le_bytes(bytes))
                })
                .transpose()?;
            loaded += local.len() as u64 + bytes.as_ref().map_or(0, |value| value.len() as u64);
            state.push(value);
            effects.actual.push(AccessRequest {
                key: global,
                mode: AccessMode::Read,
            });
        } else {
            // Do not inspect unleased state. Access is checked at use, so
            // an unexecuted branch may safely mention an unleased key.
            state.push(None);
        }
    }
    let overhead = Resources {
        compute: 100 + loaded,
        memory: logical_memory,
        io: code.len() as u64 + 32 + loaded,
        bandwidth,
    };
    let limits = subtract(tx.resource_limit, overhead)?;
    let input = u64::from_le_bytes(
        input
            .try_into()
            .map_err(|_| ExecutionError::InvalidContract)?,
    );
    let caller = std::array::from_fn(|index| {
        let mut word = [0; 8];
        word.copy_from_slice(&tx.sender.as_bytes()[index * 8..index * 8 + 8]);
        u64::from_le_bytes(word)
    });
    let result = native_artifacts()
        .execute_contract(
            source,
            input,
            &trocto_compiler::ContractContext {
                height: context.next_height,
                caller,
                keys: context_keys.clone(),
                state,
                access,
            },
            limits.compute,
        )
        .map_err(|error| native_error(&error))?;
    let charged = stage_trocto_result(
        address,
        &context_keys,
        result,
        effects.diff,
        effects.actual,
        effects.result_bytes,
    )?;
    overhead
        .checked_add(charged)
        .ok_or(ExecutionError::ResourceLimit)
}

fn stage_trocto_result(
    address: types::Address,
    keys: &[Vec<u8>],
    result: trocto_compiler::ContractExecution,
    diff: &mut StateDiff,
    actual: &mut Vec<AccessRequest>,
    result_bytes: &mut Vec<u8>,
) -> Result<Resources, ExecutionError> {
    if result.state.len() != keys.len() || result.writes.len() != keys.len() {
        return Err(ExecutionError::NativeUnavailable);
    }
    let mut io = 8 + 4 + result.events.len() as u64 * 16;
    for ((local, value), written) in keys.iter().zip(result.state).zip(result.writes) {
        if written {
            let global = trocto_contract_state_key(address, local);
            io += local.len() as u64 + if value.is_some() { 8 } else { 0 };
            match value {
                Some(value) => diff.put(global.clone(), value.to_le_bytes().to_vec()),
                None => diff.delete(global.clone()),
            }
            actual.push(AccessRequest {
                key: global,
                mode: AccessMode::Write,
            });
        }
    }
    result_bytes.extend_from_slice(&result.value.to_le_bytes());
    codec::encode_length(result.events.len(), result_bytes);
    for (topic, value) in result.events {
        result_bytes.extend_from_slice(&topic.to_le_bytes());
        result_bytes.extend_from_slice(&value.to_le_bytes());
    }
    Ok(Resources {
        compute: result.fuel_used,
        memory: io,
        io,
        bandwidth: 0,
    })
}

fn native_error(error: &trocto_runtime::NativeError) -> ExecutionError {
    use trocto_compiler::ExecutionError as ContractError;
    match error {
        trocto_runtime::NativeError::Source(_) => ExecutionError::InvalidContract,
        trocto_runtime::NativeError::FuelLimit
        | trocto_runtime::NativeError::Contract(
            ContractError::FuelExhausted | ContractError::EventLimit,
        ) => ExecutionError::ResourceLimit,
        trocto_runtime::NativeError::Contract(ContractError::AccessDenied) => {
            ExecutionError::UndeclaredStateAccess
        }
        trocto_runtime::NativeError::Contract(
            ContractError::Overflow | ContractError::DivisionByZero | ContractError::Bounds,
        ) => ExecutionError::Trap,
        _ => ExecutionError::NativeUnavailable,
    }
}

/// Stages one call's writes and encodes its return data and events.
///
/// Returns the resources the call itself was charged, which the caller adds to
/// the transaction's own overhead.
fn stage_result(
    address: types::Address,
    result: runtime::WasmOutput,
    diff: &mut StateDiff,
    actual: &mut Vec<AccessRequest>,
    result_bytes: &mut Vec<u8>,
) -> Resources {
    for (key, value) in result.writes {
        let global = contract_state_key(address, &key);
        match value {
            Some(value) => diff.put(global.clone(), value),
            None => diff.delete(global.clone()),
        }
        actual.push(AccessRequest {
            key: global,
            mode: AccessMode::Write,
        });
    }
    codec::encode_bytes(&result.return_data, result_bytes);
    codec::encode_length(result.events.len(), result_bytes);
    for (topic, data) in result.events {
        result_bytes.extend_from_slice(&topic);
        codec::encode_bytes(&data, result_bytes);
    }
    result.resources
}

type ContractState = BTreeMap<Vec<u8>, Vec<u8>>;

fn load_state(
    snapshot: &dyn StateSnapshot,
    tx: &Transaction,
    address: types::Address,
    keys: &[Vec<u8>],
    actual: &mut Vec<AccessRequest>,
) -> Result<(ContractState, usize), ExecutionError> {
    let mut local = BTreeMap::new();
    let mut loaded = 0usize;
    for key in keys {
        let global = contract_state_key(address, key);
        if !tx.access_list.contains(&global) {
            return Err(ExecutionError::UndeclaredStateAccess);
        }
        if let Some(value) = snapshot.get(&global)? {
            loaded = loaded
                .checked_add(value.len() + key.len())
                .ok_or(ExecutionError::ResourceLimit)?;
            if value.len() > runtime::MAX_HOST_VALUE || loaded as u64 > runtime::MAX_HOST_IO {
                return Err(ExecutionError::ResourceLimit);
            }
            local.insert(key.clone(), value);
        }
        // Loading declared values is a real read, even when the contract does not use one.
        actual.push(AccessRequest {
            key: global,
            mode: AccessMode::Read,
        });
    }
    Ok((local, loaded))
}

fn subtract(a: Resources, b: Resources) -> Result<Resources, ExecutionError> {
    Ok(Resources {
        compute: a
            .compute
            .checked_sub(b.compute)
            .ok_or(ExecutionError::ResourceLimit)?,
        memory: a
            .memory
            .checked_sub(b.memory)
            .ok_or(ExecutionError::ResourceLimit)?,
        io: a
            .io
            .checked_sub(b.io)
            .ok_or(ExecutionError::ResourceLimit)?,
        bandwidth: a
            .bandwidth
            .checked_sub(b.bandwidth)
            .ok_or(ExecutionError::ResourceLimit)?,
    })
}

fn runtime_error(error: RuntimeError) -> ExecutionError {
    match error {
        RuntimeError::InvalidModule | RuntimeError::Unsupported => ExecutionError::InvalidContract,
        RuntimeError::LimitExceeded => ExecutionError::ResourceLimit,
        RuntimeError::Trap => ExecutionError::Trap,
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use trocto_compiler::ExecutionError as ContractError;
    use trocto_runtime::NativeError;

    #[test]
    fn local_native_failures_never_become_invalid_transactions_or_traps() {
        for error in [
            NativeError::Isolation("unavailable".into()),
            NativeError::Capacity,
            NativeError::CompilerIdentity("unavailable".into()),
            NativeError::Compilation("unavailable".into()),
            NativeError::Io("unavailable".into()),
            NativeError::DiagnosticLimit,
            NativeError::CompilationTimeout,
            NativeError::ExecutionTimeout,
            NativeError::WorkerUnavailable,
            NativeError::Protocol,
            NativeError::Divergence,
            NativeError::InvalidDeadline,
            NativeError::Contract(ContractError::InvalidContext),
        ] {
            assert_eq!(native_error(&error), ExecutionError::NativeUnavailable);
        }
        for (error, expected) in [
            (NativeError::FuelLimit, ExecutionError::ResourceLimit),
            (
                NativeError::Contract(ContractError::FuelExhausted),
                ExecutionError::ResourceLimit,
            ),
            (
                NativeError::Contract(ContractError::EventLimit),
                ExecutionError::ResourceLimit,
            ),
            (
                NativeError::Contract(ContractError::AccessDenied),
                ExecutionError::UndeclaredStateAccess,
            ),
            (
                NativeError::Contract(ContractError::Bounds),
                ExecutionError::Trap,
            ),
            (
                NativeError::Contract(ContractError::Overflow),
                ExecutionError::Trap,
            ),
            (
                NativeError::Contract(ContractError::DivisionByZero),
                ExecutionError::Trap,
            ),
            (
                NativeError::Source(trocto_compiler::compile("external native IR").unwrap_err()),
                ExecutionError::InvalidContract,
            ),
        ] {
            assert_eq!(native_error(&error), expected);
        }
    }
}
