// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded native artifact reuse with independent workers for shared code.

use crate::{NativeError, NativeProgram};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use trocto_compiler::{ContractContext, ContractExecution, Program};

/// Maximum simultaneous cached or compiling artifacts.
pub const MAX_NATIVE_CACHE_ENTRIES: usize = 16;
/// Maximum isolated workers owned by one artifact (64 per cache).
pub const MAX_NATIVE_WORKERS_PER_ARTIFACT: usize = 4;
const COMPILE_TIMEOUT: Duration = Duration::from_secs(30);
const EXECUTE_TIMEOUT: Duration = Duration::from_secs(5);

/// Observed cache work; counts never imply successful contract execution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeCacheStats {
    /// Current artifact reservations.
    pub entries: usize,
    /// LLVM builds successfully completed.
    pub compilations: u64,
    /// Isolated workers successfully started, including replacements.
    pub workers_started: u64,
    /// Calls that acquired a worker.
    pub executions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_source_and_fuel_never_reserve_artifacts() {
        let cache = NativeArtifactCache::with_compiler(PathBuf::from("missing-compiler"));
        assert!(matches!(
            cache.prepare(&" ".repeat(trocto_compiler::MAX_SOURCE_BYTES + 1)),
            Err(NativeError::Source(_))
        ));
        assert!(matches!(
            cache.execute_contract(
                "",
                0,
                &ContractContext::default(),
                crate::MAX_NATIVE_FUEL + 1
            ),
            Err(NativeError::FuelLimit)
        ));
        assert_eq!(cache.stats(), NativeCacheStats::default());
    }
    #[test]
    fn all_pending_reservations_refuse_excess_capacity_without_compiling() {
        let cache = NativeArtifactCache::new();
        let mut entries = cache.entries.lock().unwrap();
        for index in 0..MAX_NATIVE_CACHE_ENTRIES {
            entries.insert(
                index.to_string(),
                Arc::new(Entry {
                    state: Mutex::new(Prepared::Pending),
                    ready: Condvar::new(),
                }),
            );
        }
        drop(entries);
        assert!(matches!(
            cache.prepare("fn call(input: u64) -> u64 { return input; }"),
            Err(NativeError::Capacity)
        ));
        assert_eq!(cache.stats().compilations, 0);
    }
    #[test]
    fn preparation_waiters_receive_the_original_deterministic_source_error() {
        let error = trocto_compiler::compile("invalid").unwrap_err();
        let entry = Entry {
            state: Mutex::new(Prepared::Failed(NativeError::Source(error.clone()))),
            ready: Condvar::new(),
        };
        assert!(
            matches!(NativeArtifactCache::wait_prepared(&entry),Err(NativeError::Source(actual)) if actual==error)
        );
    }
    #[test]
    #[ignore = "requires pinned native clang 22.1.8"]
    fn failed_worker_is_replaced_without_recompiling_artifact() {
        let cache = NativeArtifactCache::new();
        let source = "fn call(input: u64) -> u64 { return input; }";
        let artifact = cache.artifact(source).unwrap();
        {
            let mut pool = artifact.pool.lock().unwrap();
            let worker = pool.idle[0].worker.as_mut().unwrap();
            crate::process::terminate_tree(&mut worker.process);
        }
        assert!(matches!(
            cache.execute_contract(source, 7, &ContractContext::default(), 10),
            Err(NativeError::WorkerUnavailable)
        ));
        assert_eq!(
            cache
                .execute_contract(source, 8, &ContractContext::default(), 10)
                .unwrap()
                .value,
            8
        );
        assert_eq!(cache.stats().compilations, 1);
        assert_eq!(cache.stats().workers_started, 2);
    }
}

#[derive(Debug)]
struct Pool {
    idle: Vec<NativeProgram>,
    total: usize,
}
#[derive(Debug)]
struct Artifact {
    template: Mutex<NativeProgram>,
    pool: Mutex<Pool>,
    available: Condvar,
    program: Arc<Program>,
}
#[derive(Debug)]
enum Prepared {
    Pending,
    Ready(Arc<Artifact>),
    Failed(NativeError),
}
#[derive(Debug)]
struct Entry {
    state: Mutex<Prepared>,
    ready: Condvar,
}

/// A bounded source/artifact cache. Compilation never holds the global map lock.
#[derive(Debug)]
pub struct NativeArtifactCache {
    clang: PathBuf,
    entries: Mutex<BTreeMap<String, Arc<Entry>>>,
    compilations: AtomicU64,
    workers_started: AtomicU64,
    executions: AtomicU64,
}
impl Default for NativeArtifactCache {
    fn default() -> Self {
        Self::new()
    }
}
impl NativeArtifactCache {
    /// Uses `ASTROLUNE_LLVM_CLANG`, or trusted PATH discovery of clang.
    #[must_use]
    pub fn new() -> Self {
        Self::with_compiler(
            std::env::var_os("ASTROLUNE_LLVM_CLANG")
                .map_or_else(|| PathBuf::from("clang"), PathBuf::from),
        )
    }
    /// Selects the pinned compiler executable; identity is verified before use.
    #[must_use]
    pub fn with_compiler(clang: PathBuf) -> Self {
        Self {
            clang,
            entries: Mutex::new(BTreeMap::new()),
            compilations: AtomicU64::new(0),
            workers_started: AtomicU64::new(0),
            executions: AtomicU64::new(0),
        }
    }
    /// Returns current bounded-cache observations.
    #[must_use]
    pub fn stats(&self) -> NativeCacheStats {
        NativeCacheStats {
            entries: self.entries.lock().map_or(0, |entries| entries.len()),
            compilations: self.compilations.load(Ordering::Relaxed),
            workers_started: self.workers_started.load(Ordering::Relaxed),
            executions: self.executions.load(Ordering::Relaxed),
        }
    }
    /// Compiles and probes isolation once, without executing contract effects.
    ///
    /// # Errors
    /// Returns invalid source, capacity exhaustion or local compiler/isolation failure.
    pub fn prepare(&self, source: &str) -> Result<(), NativeError> {
        self.artifact(source).map(|_| ())
    }
    /// Returns the checked program of a prepared native artifact.
    ///
    /// # Errors
    /// Returns the same errors as `prepare`.
    pub fn program(&self, source: &str) -> Result<Arc<Program>, NativeError> {
        self.artifact(source)
            .map(|artifact| artifact.program.clone())
    }
    /// Executes using a pooled, independently isolated worker.
    ///
    /// # Errors
    /// Deterministic traps and local unavailability remain distinct; no fallback occurs.
    pub fn execute_contract(
        &self,
        source: &str,
        input: u64,
        context: &ContractContext,
        fuel: u64,
    ) -> Result<ContractExecution, NativeError> {
        if fuel > crate::MAX_NATIVE_FUEL {
            return Err(NativeError::FuelLimit);
        }
        let artifact = self.artifact(source)?;
        let end = crate::process::deadline(EXECUTE_TIMEOUT)?;
        let mut native = {
            let mut pool = artifact
                .pool
                .lock()
                .map_err(|_| NativeError::WorkerUnavailable)?;
            loop {
                if let Some(native) = pool.idle.pop() {
                    break Some(native);
                }
                if pool.total < MAX_NATIVE_WORKERS_PER_ARTIFACT {
                    pool.total += 1;
                    break None;
                }
                let remaining = end.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(NativeError::ExecutionTimeout);
                }
                let (next, wait) = artifact
                    .available
                    .wait_timeout(pool, remaining)
                    .map_err(|_| NativeError::WorkerUnavailable)?;
                pool = next;
                if wait.timed_out() {
                    return Err(NativeError::ExecutionTimeout);
                }
            }
        };
        if native.is_none() {
            let spawned = artifact
                .template
                .lock()
                .map_err(|_| NativeError::WorkerUnavailable)
                .and_then(|template| {
                    let remaining = end.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        Err(NativeError::ExecutionTimeout)
                    } else {
                        template.sibling(remaining)
                    }
                });
            match spawned {
                Ok(worker) => {
                    native = Some(worker);
                    self.workers_started.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    if let Ok(mut pool) = artifact.pool.lock() {
                        pool.total -= 1;
                        artifact.available.notify_one();
                    }
                    return Err(error);
                }
            }
        }
        let mut native = native.ok_or(NativeError::WorkerUnavailable)?;
        self.executions.fetch_add(1, Ordering::Relaxed);
        let remaining = end.saturating_duration_since(std::time::Instant::now());
        let result = if remaining.is_zero() {
            Err(NativeError::ExecutionTimeout)
        } else {
            native.execute_contract(input, context, fuel, remaining)
        };
        let mut pool = artifact
            .pool
            .lock()
            .map_err(|_| NativeError::WorkerUnavailable)?;
        if native.worker.is_some() {
            pool.idle.push(native);
        } else {
            pool.total -= 1;
        }
        artifact.available.notify_one();
        result
    }
    fn artifact(&self, source: &str) -> Result<Arc<Artifact>, NativeError> {
        if source.len() > trocto_compiler::MAX_SOURCE_BYTES {
            return Err(NativeError::Source(
                trocto_compiler::compile(source).expect_err("oversized source must fail"),
            ));
        }
        let (entry, should_build, evicted) = {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| NativeError::WorkerUnavailable)?;
            if let Some(entry) = entries.get(source) {
                (entry.clone(), false, None)
            } else {
                let mut evicted = None;
                // Evict only an unreferenced, completely idle ready artifact.
                if entries.len() >= MAX_NATIVE_CACHE_ENTRIES {
                    let victim = entries
                        .iter()
                        .find_map(|(key, entry)| {
                            if Arc::strong_count(entry) != 1 {
                                return None;
                            }
                            let state = entry.state.lock().ok()?;
                            let Prepared::Ready(artifact) = &*state else {
                                return None;
                            };
                            if Arc::strong_count(artifact) != 1 {
                                return None;
                            }
                            let pool = artifact.pool.lock().ok()?;
                            (pool.total == pool.idle.len()).then(|| key.clone())
                        })
                        .ok_or(NativeError::Capacity)?;
                    evicted = entries.remove(&victim);
                }
                let entry = Arc::new(Entry {
                    state: Mutex::new(Prepared::Pending),
                    ready: Condvar::new(),
                });
                entries.insert(source.to_owned(), entry.clone());
                (entry, true, evicted)
            }
        };
        drop(evicted);
        if should_build {
            let compilation = trocto_compiler::compile(source)
                .map_err(NativeError::Source)
                .and_then(|program| NativeProgram::compile(program, &self.clang, COMPILE_TIMEOUT));
            match compilation {
                Ok(native) => {
                    let template = NativeProgram {
                        program: native.program.clone(),
                        worker: None,
                        compiler_identity: native.compiler_identity.clone(),
                        directory: native.directory.clone(),
                        clang: native.clang.clone(),
                    };
                    let artifact = Arc::new(Artifact {
                        program: native.program.clone(),
                        template: Mutex::new(template),
                        available: Condvar::new(),
                        pool: Mutex::new(Pool {
                            idle: vec![native],
                            total: 1,
                        }),
                    });
                    self.compilations.fetch_add(1, Ordering::Relaxed);
                    self.workers_started.fetch_add(1, Ordering::Relaxed);
                    *entry
                        .state
                        .lock()
                        .map_err(|_| NativeError::WorkerUnavailable)? =
                        Prepared::Ready(artifact.clone());
                    entry.ready.notify_all();
                    return Ok(artifact);
                }
                Err(error) => {
                    *entry
                        .state
                        .lock()
                        .map_err(|_| NativeError::WorkerUnavailable)? =
                        Prepared::Failed(error.clone());
                    entry.ready.notify_all();
                    self.entries
                        .lock()
                        .map_err(|_| NativeError::WorkerUnavailable)?
                        .remove(source);
                    return Err(error);
                }
            }
        }
        Self::wait_prepared(&entry)
    }
    fn wait_prepared(entry: &Entry) -> Result<Arc<Artifact>, NativeError> {
        let end = crate::process::deadline(Duration::from_secs(65))?;
        let mut state = entry
            .state
            .lock()
            .map_err(|_| NativeError::WorkerUnavailable)?;
        loop {
            match &*state {
                Prepared::Ready(artifact) => return Ok(artifact.clone()),
                Prepared::Failed(error) => return Err(error.clone()),
                Prepared::Pending => {
                    let remaining = end.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(NativeError::CompilationTimeout);
                    }
                    let (next, wait) = entry
                        .ready
                        .wait_timeout(state, remaining)
                        .map_err(|_| NativeError::WorkerUnavailable)?;
                    state = next;
                    if wait.timed_out() {
                        return Err(NativeError::CompilationTimeout);
                    }
                }
            }
        }
    }
}
