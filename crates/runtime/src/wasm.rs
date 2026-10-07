// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Integer-only WebAssembly contracts with a bounded, deterministic host ABI.

use std::collections::{BTreeMap, BTreeSet};

use types::{Address, Hash256, Resources};
use wasmi::{
    Caller, CompilationMode, Config, Engine, ExternType, Linker, Memory, Module, Store,
    StoreLimits, StoreLimitsBuilder, ValType,
};

use crate::{
    ContractModule, MAX_INPUT_SIZE, MAX_MODULE_SIZE, MAX_OUTPUT_SIZE, ModuleValidator,
    RuntimeError, RuntimeVersion,
};

/// WebAssembly host ABI v2 and pinned Wasmi 2.0.0 metering schedule v1.
pub const WASM_VERSION: RuntimeVersion = RuntimeVersion {
    abi: 2,
    metering: 1,
};
/// Maximum linear memory in bytes (256 WebAssembly pages).
pub const MAX_WASM_MEMORY: usize = 16 * 1024 * 1024;
/// Maximum state value or event body in bytes.
pub const MAX_HOST_VALUE: usize = 64 * 1024;
/// Maximum combined state I/O per call, in bytes.
pub const MAX_HOST_IO: u64 = 1024 * 1024;

/// Finalized call context and explicit contract-local access authorization.
#[derive(Clone, Copy)]
pub struct WasmCall<'a> {
    /// Canonical call input bytes.
    pub input: &'a [u8],
    /// Caller authenticated by the enclosing transaction.
    pub caller: Address,
    /// Finalized block height; no wall clock is exposed.
    pub height: u64,
    /// Immutable contract-local state; keys are scoped by the outer executor.
    pub state: &'a BTreeMap<Vec<u8>, Vec<u8>>,
    /// Authorized keys for reads and writes. Missing declarations trap.
    pub access: &'a BTreeSet<Vec<u8>>,
    /// Deterministic call budget in compute, memory bytes, I/O bytes, output bytes.
    pub limits: Resources,
}

/// Successful staged output. Traps return no writes or events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmOutput {
    /// Contract return bytes.
    pub return_data: Vec<u8>,
    /// Ordered events, with 32-byte topics.
    pub events: Vec<([u8; 32], Vec<u8>)>,
    /// Canonically ordered writes; `None` deletes a key.
    pub writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Actual read/write keys, independent of declared supersets.
    pub accessed: BTreeSet<Vec<u8>>,
    /// Charged resources. Compute includes Wasmi fuel and host work.
    pub resources: Resources,
}

/// Portable interpreter and validator for the versioned contract profile.
pub struct WasmRuntime {
    engine: Engine,
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmRuntime {
    /// Creates the fixed, integer-only engine with eager validation and fuel.
    #[must_use]
    pub fn new() -> Self {
        let mut config = Config::default();
        config
            .consume_fuel(true)
            .floats(false)
            .allow_start_fn(false)
            .wasm_multi_memory(false)
            .wasm_reference_types(false)
            .wasm_tail_call(false)
            .wasm_extended_const(false)
            .wasm_saturating_float_to_int(false)
            .wasm_multi_value(false)
            .set_max_recursion_depth(128)
            .set_max_stack_height(16_384)
            .compilation_mode(CompilationMode::Eager);
        Self {
            engine: Engine::new(&config),
        }
    }

    fn compile(&self, bytes: &[u8]) -> Result<Module, RuntimeError> {
        if bytes.len() > MAX_MODULE_SIZE {
            return Err(RuntimeError::LimitExceeded);
        }
        // The wire profile accepts binary modules only, never WAT or native code.
        if !bytes.starts_with(b"\0asm\x01\0\0\0") {
            return Err(RuntimeError::InvalidModule);
        }
        // Validate complete bodies before Wasmi's combined validation/translation.
        // In 2.0.0 an instruction after a function's end can reach the translator
        // with an empty control stack before its validator rejects the operator.
        // Keep the same engine feature policy and never pass malformed code to it.
        Module::validate(&self.engine, bytes).map_err(|_| RuntimeError::InvalidModule)?;
        let module = Module::new(&self.engine, bytes).map_err(|_| RuntimeError::InvalidModule)?;
        let Some(ExternType::Memory(memory)) = module.get_export("memory") else {
            return Err(RuntimeError::InvalidModule);
        };
        if memory.minimum() > 256 || memory.maximum().is_none_or(|max| max > 256) {
            return Err(RuntimeError::LimitExceeded);
        }
        let Some(ExternType::Func(call)) = module.get_export("call") else {
            return Err(RuntimeError::InvalidModule);
        };
        if !call.params().is_empty() || call.results() != [ValType::I32] {
            return Err(RuntimeError::InvalidModule);
        }
        for import in module.imports() {
            let ExternType::Func(function) = import.ty() else {
                return Err(RuntimeError::Unsupported);
            };
            let (parameters, result) = match import.name() {
                "input_len" => (0, ValType::I32),
                "input_copy" | "emit" => (3, ValType::I32),
                "output" | "state_delete" => (2, ValType::I32),
                "state_get" | "state_put" => (4, ValType::I32),
                "caller" => (1, ValType::I32),
                "block_height" => (0, ValType::I64),
                _ => return Err(RuntimeError::Unsupported),
            };
            if import.module() != "astrolune_v2"
                || function.params().len() != parameters
                || function.params().iter().any(|ty| *ty != ValType::I32)
                || function.results() != [result]
            {
                return Err(RuntimeError::Unsupported);
            }
        }
        Ok(module)
    }

    /// Executes a validated module in a fresh instance with private writes.
    ///
    /// # Errors
    /// Rejects forged module hashes/versions, forbidden imports/features, exhausted
    /// resources, invalid pointers, undeclared accesses, nonzero returns, and traps.
    pub fn execute_call(
        &self,
        module: &ContractModule,
        call: WasmCall<'_>,
    ) -> Result<WasmOutput, RuntimeError> {
        if module.version != WASM_VERSION {
            return Err(RuntimeError::Unsupported);
        }
        if module.code_hash != wasm_code_hash(&module.code) {
            return Err(RuntimeError::InvalidModule);
        }
        validate_call(&call)?;
        let compiled = self.compile(&module.code)?;
        let fuel = call.limits.compute;
        let host = Host {
            call,
            output: Vec::new(),
            writes: BTreeMap::new(),
            accessed: BTreeSet::new(),
            events: Vec::new(),
            io: 0,
            bandwidth: 0,
            limiter: StoreLimitsBuilder::new()
                .memory_size(
                    usize::try_from(call.limits.memory).map_err(|_| RuntimeError::LimitExceeded)?,
                )
                .table_elements(4096)
                .instances(1)
                .memories(1)
                .tables(1)
                .trap_on_grow_failure(true)
                .build(),
            failure: None,
        };
        let mut store = Store::new(&self.engine, host);
        store.limiter(|host| &mut host.limiter);
        store
            .set_fuel(fuel)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        let linker = host_linker(&self.engine).map_err(|_| RuntimeError::InvalidModule)?;
        let instance = linker
            .instantiate_and_start(&mut store, &compiled)
            .map_err(|error| runtime_error(&error))?;
        let function = instance
            .get_typed_func::<(), i32>(&store, "call")
            .map_err(|_| RuntimeError::InvalidModule)?;
        let status = function.call(&mut store, ()).map_err(|error| {
            store
                .data()
                .failure
                .unwrap_or_else(|| runtime_error(&error))
        })?;
        if status != 0 {
            return Err(RuntimeError::Trap);
        }
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or(RuntimeError::InvalidModule)?;
        let resources = Resources {
            compute: fuel - store.get_fuel().map_err(|_| RuntimeError::Trap)?,
            memory: memory.data_size(&store) as u64,
            io: store.data().io,
            bandwidth: store.data().bandwidth,
        };
        let host = store.into_data();
        Ok(WasmOutput {
            return_data: host.output,
            events: host.events,
            writes: host.writes,
            accessed: host.accessed,
            resources,
        })
    }
}

impl ModuleValidator for WasmRuntime {
    fn validate(
        &self,
        bytes: &[u8],
        version: RuntimeVersion,
    ) -> Result<ContractModule, RuntimeError> {
        if version != WASM_VERSION {
            return Err(RuntimeError::Unsupported);
        }
        self.compile(bytes)?;
        Ok(ContractModule {
            code_hash: wasm_code_hash(bytes),
            version,
            code: bytes.to_vec(),
        })
    }
}

/// Commits the fixed WebAssembly ABI/metering identity and exact binary bytes.
#[must_use]
pub fn wasm_code_hash(bytes: &[u8]) -> Hash256 {
    types::hash::domain_hash(b"astrolune.contract.wasm.abi2.meter1", bytes)
}

fn validate_call(call: &WasmCall<'_>) -> Result<(), RuntimeError> {
    if call.input.len() > MAX_INPUT_SIZE
        || call.limits.compute == 0
        || call.limits.compute > 10_000_000
        || call.limits.memory > MAX_WASM_MEMORY as u64
        || call.limits.io > MAX_HOST_IO
        || call.limits.bandwidth > MAX_OUTPUT_SIZE as u64
        || call.state.len() > 1024
        || call.access.len() > 1024
    {
        return Err(RuntimeError::LimitExceeded);
    }
    let mut bytes = 0usize;
    for (key, value) in call.state {
        if key.is_empty() || key.len() > 256 || value.len() > MAX_HOST_VALUE {
            return Err(RuntimeError::LimitExceeded);
        }
        bytes = bytes
            .checked_add(key.len() + value.len())
            .ok_or(RuntimeError::LimitExceeded)?;
        if bytes as u64 > MAX_HOST_IO {
            return Err(RuntimeError::LimitExceeded);
        }
    }
    if call
        .access
        .iter()
        .any(|key| key.is_empty() || key.len() > 256)
    {
        return Err(RuntimeError::LimitExceeded);
    }
    Ok(())
}

struct Host<'a> {
    call: WasmCall<'a>,
    output: Vec<u8>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    accessed: BTreeSet<Vec<u8>>,
    events: Vec<([u8; 32], Vec<u8>)>,
    io: u64,
    bandwidth: u64,
    limiter: StoreLimits,
    failure: Option<RuntimeError>,
}

fn runtime_error(error: &wasmi::Error) -> RuntimeError {
    match error.as_trap_code() {
        Some(wasmi::TrapCode::OutOfFuel | wasmi::TrapCode::StackOverflow) => {
            RuntimeError::LimitExceeded
        }
        _ => RuntimeError::Trap,
    }
}

fn fail(caller: &mut Caller<'_, Host<'_>>, error: RuntimeError) -> wasmi::Error {
    caller.data_mut().failure = Some(error);
    wasmi::Error::new("contract host rejected operation")
}

fn memory(caller: &Caller<'_, Host<'_>>) -> Result<Memory, wasmi::Error> {
    caller
        .get_export("memory")
        .and_then(wasmi::Extern::into_memory)
        .ok_or_else(|| wasmi::Error::new("missing contract memory"))
}

fn charge(
    caller: &mut Caller<'_, Host<'_>>,
    bytes: usize,
    io: bool,
    bandwidth: bool,
) -> Result<(), wasmi::Error> {
    let cost = 20 + bytes as u64;
    let remaining = caller.get_fuel()?;
    if remaining < cost {
        return Err(fail(caller, RuntimeError::LimitExceeded));
    }
    caller.set_fuel(remaining - cost)?;
    let host = caller.data_mut();
    if io {
        host.io = host
            .io
            .checked_add(bytes as u64)
            .ok_or_else(|| wasmi::Error::new("I/O overflow"))?;
    }
    if bandwidth {
        host.bandwidth = host
            .bandwidth
            .checked_add(bytes as u64)
            .ok_or_else(|| wasmi::Error::new("output overflow"))?;
    }
    if host.io > host.call.limits.io || host.bandwidth > host.call.limits.bandwidth {
        return Err(fail(caller, RuntimeError::LimitExceeded));
    }
    Ok(())
}

fn read_memory(
    caller: &mut Caller<'_, Host<'_>>,
    pointer: i32,
    length: i32,
    maximum: usize,
) -> Result<Vec<u8>, wasmi::Error> {
    let pointer = usize::try_from(pointer).map_err(|_| fail(caller, RuntimeError::Trap))?;
    let length = usize::try_from(length).map_err(|_| fail(caller, RuntimeError::Trap))?;
    if length > maximum {
        return Err(fail(caller, RuntimeError::LimitExceeded));
    }
    charge(caller, length, false, false)?;
    let mut bytes = vec![0; length];
    memory(caller)?
        .read(&*caller, pointer, &mut bytes)
        .map_err(|_| fail(caller, RuntimeError::Trap))?;
    Ok(bytes)
}

fn write_memory(
    caller: &mut Caller<'_, Host<'_>>,
    pointer: i32,
    bytes: &[u8],
) -> Result<(), wasmi::Error> {
    let pointer = usize::try_from(pointer).map_err(|_| fail(caller, RuntimeError::Trap))?;
    charge(caller, bytes.len(), false, false)?;
    memory(caller)?
        .write(&mut *caller, pointer, bytes)
        .map_err(|_| fail(caller, RuntimeError::Trap))
}

fn read_key(
    caller: &mut Caller<'_, Host<'_>>,
    pointer: i32,
    length: i32,
) -> Result<Vec<u8>, wasmi::Error> {
    let key = read_memory(caller, pointer, length, 256)?;
    if key.is_empty() || !caller.data().call.access.contains(&key) {
        return Err(fail(caller, RuntimeError::Trap));
    }
    caller.data_mut().accessed.insert(key.clone());
    Ok(key)
}

fn host_linker(engine: &Engine) -> Result<Linker<Host<'_>>, wasmi::Error> {
    let mut linker = Linker::new(engine);
    link_io(&mut linker)?;
    link_state(&mut linker)?;
    link_context(&mut linker)?;
    Ok(linker)
}

fn link_io(linker: &mut Linker<Host<'_>>) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        "astrolune_v2",
        "input_len",
        |mut caller: Caller<'_, Host<'_>>| -> Result<i32, wasmi::Error> {
            charge(&mut caller, 0, false, false)?;
            Ok(i32::try_from(caller.data().call.input.len()).expect("bounded input"))
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "input_copy",
        |mut caller: Caller<'_, Host<'_>>,
         offset: i32,
         pointer: i32,
         length: i32|
         -> Result<i32, wasmi::Error> {
            let offset =
                usize::try_from(offset).map_err(|_| fail(&mut caller, RuntimeError::Trap))?;
            let length =
                usize::try_from(length).map_err(|_| fail(&mut caller, RuntimeError::Trap))?;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| fail(&mut caller, RuntimeError::Trap))?;
            let bytes = caller
                .data()
                .call
                .input
                .get(offset..end)
                .ok_or_else(|| wasmi::Error::new("input bounds"))?
                .to_vec();
            write_memory(&mut caller, pointer, &bytes)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "output",
        |mut caller: Caller<'_, Host<'_>>,
         pointer: i32,
         length: i32|
         -> Result<i32, wasmi::Error> {
            let bytes = read_memory(&mut caller, pointer, length, MAX_OUTPUT_SIZE)?;
            charge(&mut caller, bytes.len(), false, true)?;
            caller.data_mut().output = bytes;
            Ok(0)
        },
    )?;
    Ok(())
}

fn link_state(linker: &mut Linker<Host<'_>>) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        "astrolune_v2",
        "state_get",
        |mut caller: Caller<'_, Host<'_>>,
         key: i32,
         key_len: i32,
         output: i32,
         capacity: i32|
         -> Result<i32, wasmi::Error> {
            let key = read_key(&mut caller, key, key_len)?;
            let value = caller
                .data()
                .writes
                .get(&key)
                .cloned()
                .unwrap_or_else(|| caller.data().call.state.get(&key).cloned());
            charge(
                &mut caller,
                key.len() + value.as_ref().map_or(0, Vec::len),
                true,
                false,
            )?;
            let Some(value) = value else {
                return Ok(-1);
            };
            if !usize::try_from(capacity).is_ok_and(|capacity| capacity >= value.len()) {
                return Err(fail(&mut caller, RuntimeError::LimitExceeded));
            }
            write_memory(&mut caller, output, &value)?;
            Ok(i32::try_from(value.len()).expect("bounded value"))
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "state_put",
        |mut caller: Caller<'_, Host<'_>>,
         key: i32,
         key_len: i32,
         value: i32,
         value_len: i32|
         -> Result<i32, wasmi::Error> {
            let key = read_key(&mut caller, key, key_len)?;
            let value = read_memory(&mut caller, value, value_len, MAX_HOST_VALUE)?;
            charge(&mut caller, key.len() + value.len(), true, false)?;
            caller.data_mut().writes.insert(key, Some(value));
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "state_delete",
        |mut caller: Caller<'_, Host<'_>>, key: i32, key_len: i32| -> Result<i32, wasmi::Error> {
            let key = read_key(&mut caller, key, key_len)?;
            charge(&mut caller, key.len(), true, false)?;
            caller.data_mut().writes.insert(key, None);
            Ok(0)
        },
    )?;
    Ok(())
}

fn link_context(linker: &mut Linker<Host<'_>>) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        "astrolune_v2",
        "caller",
        |mut caller: Caller<'_, Host<'_>>, output: i32| -> Result<i32, wasmi::Error> {
            let address = caller.data().call.caller.0;
            write_memory(&mut caller, output, &address)?;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "block_height",
        |mut caller: Caller<'_, Host<'_>>| -> Result<i64, wasmi::Error> {
            charge(&mut caller, 0, false, false)?;
            Ok(i64::from_le_bytes(caller.data().call.height.to_le_bytes()))
        },
    )?;
    linker.func_wrap(
        "astrolune_v2",
        "emit",
        |mut caller: Caller<'_, Host<'_>>,
         topic: i32,
         value: i32,
         length: i32|
         -> Result<i32, wasmi::Error> {
            if caller.data().events.len() >= 256 {
                return Err(fail(&mut caller, RuntimeError::LimitExceeded));
            }
            let topic = read_memory(&mut caller, topic, 32, 32)?;
            let value = read_memory(&mut caller, value, length, MAX_HOST_VALUE)?;
            charge(&mut caller, 32 + value.len(), false, true)?;
            caller
                .data_mut()
                .events
                .push((topic.try_into().expect("32-byte topic"), value));
            Ok(0)
        },
    )?;
    Ok(())
}
