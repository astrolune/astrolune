// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Authenticated ABI-v2 contract transitions. All effects are private until commit.

use std::collections::{BTreeMap, BTreeSet};

use codec::CanonicalEncode;
use runtime::{ModuleValidator, RuntimeError, WASM_VERSION, WasmCall, WasmRuntime};
use state::{
    AccessMode, AccessRequest, StateDiff, StateLease, StateSnapshot, account_key, read_account,
};
use transaction::{
    ContractAction, ContractPayload, RegisteredAccount, SignedValidator, TransactionError,
    TransactionValidator, ValidationContext, contract_address, contract_code_key,
    contract_state_key,
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
            output_root: types::hash::domain_hash(b"astrolune.contract.result.v2", &commitment),
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

fn execute_action(
    snapshot: &dyn StateSnapshot,
    tx: &Transaction,
    context: ValidationContext,
    payload: &ContractPayload,
) -> Result<Effects, ExecutionError> {
    let sender_key = account_key(tx.sender);
    let address = match &payload.action {
        ContractAction::Deploy(_) => contract_address(tx.chain_id, tx.sender, tx.nonce),
        ContractAction::Call { address, .. } => *address,
    };
    let code_key = contract_code_key(address);
    if !tx.access_list.contains(&code_key) {
        return Err(ExecutionError::UndeclaredStateAccess);
    }
    let runtime = WasmRuntime::new();
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
            let module = runtime
                .validate(&code, WASM_VERSION)
                .map_err(runtime_error)?;
            let result = runtime
                .execute_call(
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
            codec::encode_bytes(&result.return_data, &mut result_bytes);
            codec::encode_length(result.events.len(), &mut result_bytes);
            for (topic, data) in result.events {
                result_bytes.extend_from_slice(&topic);
                codec::encode_bytes(&data, &mut result_bytes);
            }
            overhead
                .checked_add(result.resources)
                .ok_or(ExecutionError::ResourceLimit)?
        }
    };
    Ok(Effects {
        diff,
        actual,
        resources,
        result_bytes,
    })
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
