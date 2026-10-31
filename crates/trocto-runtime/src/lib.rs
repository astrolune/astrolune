// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Native LLVM execution of checked Trocto programs with fail-closed OS isolation.
//!
//! Linux workers enforce seccomp, file/network/process denial and rlimits.
//! Windows workers run in a capability-free `AppContainer` and a quota-limited job.
//! Startup includes real enforcement probes and an exact readiness handshake.
//! Every native state/event/fuel result is checked against reference semantics.
//! Arbitrary external IR/native binaries cannot enter this API.

#![forbid(unsafe_code)]

mod cache;
mod process;
pub use cache::{
    MAX_NATIVE_CACHE_ENTRIES, MAX_NATIVE_WORKERS_PER_ARTIFACT, NativeArtifactCache,
    NativeCacheStats,
};

use std::{
    fmt,
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel},
    thread::JoinHandle,
    time::Duration,
};

use process::{BuildDirectory, bounded_command, configure, deadline, resolve_compiler};
use trocto_compiler::{ContractContext, ContractExecution, Execution, ExecutionError, Program};

/// Exact LLVM release supported by this experimental native backend.
pub const LLVM_VERSION: &str = "22.1.8";
/// Protocol maximum compute units per native invocation.
pub const MAX_NATIVE_FUEL: u64 = 10_000_000;

/// A local tool/worker failure or a deterministic Trocto execution error.
#[derive(Clone, Debug)]
pub enum NativeError {
    /// Checked source was invalid.
    Source(trocto_compiler::CompileError),
    /// OS security isolation or quota enforcement could not be established.
    Isolation(String),
    /// Bounded cache or worker-pool capacity was unavailable.
    Capacity,
    /// Invocation exceeded the protocol compute bound.
    FuelLimit,
    /// Compiler discovery, filesystem or process I/O failed locally.
    Io(String),
    /// The compiler does not identify itself as the pinned LLVM release.
    CompilerIdentity(String),
    /// LLVM rejected the generated module or worker harness.
    Compilation(String),
    /// Compiler output exceeded the bounded diagnostic capture.
    DiagnosticLimit,
    /// A local compiler/version-query deadline elapsed.
    CompilationTimeout,
    /// A local worker response deadline elapsed; this is not a contract trap.
    ExecutionTimeout,
    /// The local worker exited, or an earlier local failure retired it.
    WorkerUnavailable,
    /// Worker output was malformed, truncated or used an unknown status.
    Protocol,
    /// Native results did not match the checked reference semantics.
    Divergence,
    /// A deterministic execution result agreed across native/reference paths.
    Contract(ExecutionError),
    /// A deadline was zero, above the local maximum, or not representable.
    InvalidDeadline,
}

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(formatter, "{error}"),
            Self::Isolation(message) => write!(formatter, "native isolation refused: {message}"),
            Self::Capacity => formatter.write_str("native artifact/worker capacity unavailable"),
            Self::FuelLimit => {
                formatter.write_str("native invocation exceeds 10000000 compute units")
            }
            Self::Io(message) => write!(formatter, "native worker I/O: {message}"),
            Self::CompilerIdentity(message) => {
                write!(
                    formatter,
                    "native backend requires LLVM {LLVM_VERSION}: {message}"
                )
            }
            Self::Compilation(message) => write!(formatter, "LLVM compilation failed: {message}"),
            Self::DiagnosticLimit => {
                formatter.write_str("LLVM diagnostics exceeded 8 KiB per stream")
            }
            Self::CompilationTimeout => {
                formatter.write_str("local LLVM compilation deadline elapsed")
            }
            Self::ExecutionTimeout => formatter.write_str("local native worker deadline elapsed"),
            Self::WorkerUnavailable => formatter.write_str("native worker is unavailable"),
            Self::Protocol => formatter.write_str("invalid native worker response"),
            Self::Divergence => {
                formatter.write_str("native result differs from reference semantics")
            }
            Self::Contract(error) => write!(formatter, "Trocto execution: {error}"),
            Self::InvalidDeadline => formatter
                .write_str("local deadline must be greater than zero and at most 120 seconds"),
        }
    }
}

impl std::error::Error for NativeError {}

impl From<std::io::Error> for NativeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// A checked program compiled once into an isolated persistent native worker.
#[derive(Debug)]
pub struct NativeProgram {
    program: std::sync::Arc<Program>,
    worker: Option<Worker>,
    compiler_identity: String,
    directory: std::sync::Arc<BuildDirectory>,
    clang: std::path::PathBuf,
}

impl NativeProgram {
    /// Builds with pinned LLVM and verifies OS isolation before exposing a worker.
    ///
    /// # Errors
    /// Returns local compilation/isolation failures; no reference fallback occurs.
    pub fn compile(program: Program, clang: &Path, timeout: Duration) -> Result<Self, NativeError> {
        let end = deadline(timeout)?;
        if !cfg!(any(target_os = "linux", target_os = "windows")) || !cfg!(target_arch = "x86_64") {
            return Err(NativeError::Isolation(
                "native isolation requires Linux or Windows x86-64".into(),
            ));
        }
        let clang = resolve_compiler(clang)?;
        let directory = std::sync::Arc::new(BuildDirectory::new()?);
        let mut version = Command::new(&clang);
        configure(&mut version, &directory.path, &clang)?;
        version.args(["--no-default-config", "--version"]);
        let identity = bounded_command(version, compilation_remaining(end)?)?;
        let compiler_identity = identity.stdout.lines().next().unwrap_or("").to_owned();
        if !identity.success
            || compiler_identity
                .split_once("clang version ")
                .and_then(|(_, tail)| tail.split_whitespace().next())
                != Some(LLVM_VERSION)
        {
            return Err(NativeError::CompilerIdentity(format!(
                "{compiler_identity} {}",
                identity.stderr
            )));
        }
        let module = directory.path.join("module.ll");
        let harness = directory.path.join("worker.c");
        let executable = directory.path.join(if cfg!(windows) {
            "worker.exe"
        } else {
            "worker"
        });
        std::fs::write(&module, program.llvm_ir())?;
        std::fs::write(&harness, include_str!("worker.c"))?;
        let mut compiler = Command::new(&clang);
        configure(&mut compiler, &directory.path, &clang)?;
        compiler
            .args([
                "--no-default-config",
                "-O2",
                "-static",
                "-fuse-ld=lld",
                "-Wno-override-module",
                "-x",
                "ir",
            ])
            .arg(&module)
            .args(["-x", "c"])
            .arg(&harness)
            .arg(format!("-DTROCTO_KEYS={}", program.state_keys().len()))
            .arg(format!("-DTROCTO_LANGUAGE={}", program.language_version()))
            .arg("-o")
            .arg(&executable);
        if cfg!(windows) {
            compiler.args([
                "-rtlib=compiler-rt",
                "-unwindlib=libunwind",
                "-ladvapi32",
                "-luserenv",
                "-lws2_32",
            ]);
        }
        let build = bounded_command(compiler, compilation_remaining(end)?)?;
        if !build.success {
            return Err(NativeError::Compilation(build.stderr));
        }
        let mut native = Self {
            program: std::sync::Arc::new(program),
            worker: None,
            compiler_identity,
            directory,
            clang,
        };
        let started = native.start_worker(compilation_remaining(end)?);
        if std::time::Instant::now() >= end {
            return Err(NativeError::CompilationTimeout);
        }
        native.worker = Some(started?);
        Ok(native)
    }

    fn start_worker(&self, timeout: Duration) -> Result<Worker, NativeError> {
        let executable = self.directory.path.join(if cfg!(windows) {
            "worker.exe"
        } else {
            "worker"
        });
        Worker::start(
            &executable,
            &self.directory,
            &self.clang,
            response_bytes(),
            timeout,
        )
    }

    pub(crate) fn sibling(&self, timeout: Duration) -> Result<Self, NativeError> {
        let mut native = Self {
            program: self.program.clone(),
            worker: None,
            compiler_identity: self.compiler_identity.clone(),
            directory: self.directory.clone(),
            clang: self.clang.clone(),
        };
        native.worker = Some(native.start_worker(timeout)?);
        Ok(native)
    }

    /// The checked compiler version line.
    #[must_use]
    pub fn compiler_identity(&self) -> &str {
        &self.compiler_identity
    }

    /// Executes a context-free scalar program.
    ///
    /// # Errors
    /// Stateful programs return deterministic `InvalidContext`; local failures are distinct.
    pub fn execute(
        &mut self,
        input: u64,
        fuel: u64,
        timeout: Duration,
    ) -> Result<Execution, NativeError> {
        if self.program.requires_context() {
            return Err(NativeError::Contract(ExecutionError::InvalidContext));
        }
        let context = ContractContext::default();
        let output = self.execute_contract(input, &context, fuel, timeout)?;
        Ok(Execution {
            value: output.value,
            fuel_used: output.fuel_used,
        })
    }

    /// Executes bounded stateful input and validates every native effect and fuel count.
    ///
    /// All native state/events are discarded on traps or local failures. A timeout
    /// retires the worker and its entire owned process tree.
    ///
    /// # Errors
    /// Returns deterministic failures as Contract, and local failures separately.
    pub fn execute_contract(
        &mut self,
        input: u64,
        context: &ContractContext,
        fuel: u64,
        timeout: Duration,
    ) -> Result<ContractExecution, NativeError> {
        let end = deadline(timeout)?;
        if fuel > MAX_NATIVE_FUEL {
            return Err(NativeError::FuelLimit);
        }
        let count = context.keys.len();
        validate_context(context, self.program.state_keys()).map_err(NativeError::Contract)?;
        let bytes = encode_request(input, context, fuel);
        let response = self
            .worker
            .as_mut()
            .ok_or(NativeError::WorkerUnavailable)?
            .request(bytes, end);
        let actual = match response.and_then(|bytes| decode_contract_response(&bytes, count)) {
            Ok(value) => value,
            Err(error) => {
                self.worker.take();
                return Err(error);
            }
        };
        let expected =
            match self
                .program
                .evaluate_contract_with_interrupt(input, context, fuel, || {
                    std::time::Instant::now() >= end
                }) {
                Ok(Some(value)) => Ok(value),
                Ok(None) => {
                    self.worker.take();
                    return Err(NativeError::ExecutionTimeout);
                }
                Err(error) => Err(error),
            };
        if std::time::Instant::now() >= end {
            self.worker.take();
            return Err(NativeError::ExecutionTimeout);
        }
        if actual != expected {
            self.worker.take();
            return Err(NativeError::Divergence);
        }
        actual.map_err(NativeError::Contract)
    }
}
fn compilation_remaining(end: std::time::Instant) -> Result<Duration, NativeError> {
    let remaining = end.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        Err(NativeError::CompilationTimeout)
    } else {
        Ok(remaining)
    }
}
impl Drop for NativeProgram {
    fn drop(&mut self) {
        self.worker.take();
    }
}

fn response_bytes() -> usize {
    8 * (4 + 3 * trocto_compiler::MAX_STATE_KEYS + 2 * trocto_compiler::MAX_EVENTS)
}
fn request_bytes() -> usize {
    8 * (8 + 8 * trocto_compiler::MAX_STATE_KEYS)
}
fn validate_context(context: &ContractContext, prefix: &[Vec<u8>]) -> Result<(), ExecutionError> {
    let count = context.keys.len();
    if count > trocto_compiler::MAX_STATE_KEYS
        || context.state.len() != count
        || context.access.len() != count
        || !context.keys.starts_with(prefix)
        || context
            .keys
            .iter()
            .any(|key| key.is_empty() || key.len() > trocto_compiler::MAX_STATE_KEY_BYTES)
        || context.keys[prefix.len()..]
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || context
            .keys
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != count
    {
        return Err(ExecutionError::InvalidContext);
    }
    Ok(())
}
fn encode_request(input: u64, context: &ContractContext, fuel: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(request_bytes());
    for value in [input, fuel, context.height]
        .into_iter()
        .chain(context.caller)
        .chain([context.state.len() as u64])
    {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for ((key, value), access) in context.keys.iter().zip(&context.state).zip(&context.access) {
        bytes.extend_from_slice(&(key.len() as u64).to_le_bytes());
        if key.len() == 32 {
            bytes.extend_from_slice(key);
        } else {
            bytes.extend_from_slice(&[0; 32]);
        }
        for word in [
            value.unwrap_or(0),
            u64::from(value.is_some()),
            u64::from(*access),
        ] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    bytes.resize(request_bytes(), 0);
    bytes
}
fn decode_contract_response(
    bytes: &[u8],
    keys: usize,
) -> Result<Result<ContractExecution, ExecutionError>, NativeError> {
    if keys > trocto_compiler::MAX_STATE_KEYS || bytes.len() != response_bytes() {
        return Err(NativeError::Protocol);
    }
    let word = |index: usize| {
        let mut value = [0; 8];
        value.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
        u64::from_le_bytes(value)
    };
    let status = word(0);
    if status != 0 {
        if bytes[8..].iter().any(|byte| *byte != 0) {
            return Err(NativeError::Protocol);
        }
        return Ok(Err(match status {
            1 => ExecutionError::FuelExhausted,
            2 => ExecutionError::Overflow,
            3 => ExecutionError::DivisionByZero,
            4 => ExecutionError::AccessDenied,
            5 => ExecutionError::EventLimit,
            6 => ExecutionError::InvalidContext,
            7 => ExecutionError::Bounds,
            _ => return Err(NativeError::Protocol),
        }));
    }
    let count = usize::try_from(word(3)).map_err(|_| NativeError::Protocol)?;
    if count > trocto_compiler::MAX_EVENTS {
        return Err(NativeError::Protocol);
    }
    let mut state = Vec::with_capacity(keys);
    let mut writes = Vec::with_capacity(keys);
    for index in 0..keys {
        let value = word(4 + index * 3);
        let present = word(5 + index * 3);
        let written = word(6 + index * 3);
        if present > 1 || written > 1 || (present == 0 && value != 0) {
            return Err(NativeError::Protocol);
        }
        state.push(if present == 1 { Some(value) } else { None });
        writes.push(written == 1);
    }
    let start = 4 + 3 * trocto_compiler::MAX_STATE_KEYS;
    if bytes[(4 + 3 * keys) * 8..start * 8]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(NativeError::Protocol);
    }
    let events = (0..count)
        .map(|index| (word(start + index * 2), word(start + index * 2 + 1)))
        .collect();
    if bytes[(start + count * 2) * 8..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(NativeError::Protocol);
    }
    Ok(Ok(ContractExecution {
        value: word(1),
        fuel_used: word(2),
        state,
        writes,
        events,
    }))
}

#[derive(Debug)]
struct Worker {
    process: Child,
    io: IoThread,
}
#[derive(Debug)]
struct IoThread {
    requests: Option<SyncSender<Vec<u8>>>,
    responses: Option<Receiver<Result<Vec<u8>, ()>>>,
    ready: Receiver<Result<(), ()>>,
    thread: Option<JoinHandle<()>>,
}
impl IoThread {
    fn spawn(
        mut input: impl Write + Send + 'static,
        mut output: impl Read + Send + 'static,
        size: usize,
    ) -> Result<Self, NativeError> {
        if size != response_bytes() {
            return Err(NativeError::Protocol);
        }
        let (requests, incoming) = sync_channel::<Vec<u8>>(1);
        let (outgoing, responses) = sync_channel(1);
        let (started, ready) = sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("trocto-worker-io".into())
            .spawn(move || {
                let mut status = [0; 16];
                if output.read_exact(&mut status).is_err()
                    || &status[..8] != b"TCSBX002"
                    || status[8..] != 31u64.to_le_bytes()
                {
                    let _ = started.send(Err(()));
                    return;
                }
                if started.send(Ok(())).is_err() {
                    return;
                }
                while let Ok(request) = incoming.recv() {
                    let mut response = vec![0; size];
                    if input
                        .write_all(&request)
                        .and_then(|()| input.flush())
                        .is_err()
                        || output.read_exact(&mut response).is_err()
                    {
                        let _ = outgoing.send(Err(()));
                        break;
                    }
                    if outgoing.send(Ok(response)).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            requests: Some(requests),
            responses: Some(responses),
            ready,
            thread: Some(thread),
        })
    }
    fn exchange(&self, request: Vec<u8>, end: std::time::Instant) -> Result<Vec<u8>, NativeError> {
        if request.len() != request_bytes() {
            return Err(NativeError::Protocol);
        }
        match self
            .requests
            .as_ref()
            .ok_or(NativeError::WorkerUnavailable)?
            .try_send(request)
        {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(NativeError::Protocol),
            Err(TrySendError::Disconnected(_)) => return Err(NativeError::WorkerUnavailable),
        }
        match self
            .responses
            .as_ref()
            .ok_or(NativeError::WorkerUnavailable)?
            .recv_timeout(end.saturating_duration_since(std::time::Instant::now()))
        {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(())) | Err(RecvTimeoutError::Disconnected) => Err(NativeError::Protocol),
            Err(RecvTimeoutError::Timeout) => Err(NativeError::ExecutionTimeout),
        }
    }
}
impl Drop for IoThread {
    fn drop(&mut self) {
        self.requests.take();
        self.responses.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Worker {
    fn start(
        executable: &Path,
        directory: &BuildDirectory,
        clang: &Path,
        size: usize,
        timeout: Duration,
    ) -> Result<Self, NativeError> {
        let mut command = Command::new(executable);
        configure(&mut command, &directory.path, clang)?;
        command
            .env("TROCTO_SANDBOX_PROBE", &directory.probe)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut process = command.spawn()?;
        let start = (|| {
            let input = process.stdin.take().ok_or(NativeError::WorkerUnavailable)?;
            let output = process
                .stdout
                .take()
                .ok_or(NativeError::WorkerUnavailable)?;
            let io = IoThread::spawn(input, output, size)?;
            let started = io.ready.recv_timeout(timeout);
            if !matches!(started, Ok(Ok(()))) {
                let status = process.try_wait().ok().flatten();
                process::terminate_tree(&mut process);
                drop(io);
                return Err(NativeError::Isolation(format!(
                    "worker failed filesystem/network/process/memory enforcement probes: {status:?}"
                )));
            }
            Ok(io)
        })();
        match start {
            Ok(io) => Ok(Self { process, io }),
            Err(error) => {
                process::terminate_tree(&mut process);
                Err(error)
            }
        }
    }
    fn request(
        &mut self,
        request: Vec<u8>,
        end: std::time::Instant,
    ) -> Result<Vec<u8>, NativeError> {
        if self.process.try_wait()?.is_some() {
            return Err(NativeError::WorkerUnavailable);
        }
        self.io.exchange(request, end)
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        process::terminate_tree(&mut self.process);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn framing_preserves_address_words_and_rejects_noncanonical_effects() {
        let context = ContractContext {
            keys: vec![vec![3; 32]],
            state: vec![Some(9)],
            access: vec![true],
            ..ContractContext::default()
        };
        let request = encode_request(7, &context, 8);
        assert_eq!(request.len(), request_bytes());
        assert_eq!(&request[72..104], &[3; 32]);
        assert!(request[128..].iter().all(|byte| *byte == 0));
        let mut response = vec![0; response_bytes()];
        response[32..40].copy_from_slice(&9u64.to_le_bytes());
        response[40..48].copy_from_slice(&1u64.to_le_bytes());
        let result = decode_contract_response(&response, 1).unwrap().unwrap();
        assert_eq!(result.state, vec![Some(9)]);
        response[40..48].copy_from_slice(&2u64.to_le_bytes());
        assert!(matches!(
            decode_contract_response(&response, 1),
            Err(NativeError::Protocol)
        ));
        response.fill(0);
        response[0] = 7;
        assert_eq!(
            decode_contract_response(&response, 1).unwrap(),
            Err(ExecutionError::Bounds)
        );
        response[32] = 1;
        assert!(matches!(
            decode_contract_response(&response, 1),
            Err(NativeError::Protocol)
        ));
        response.fill(0);
        response[0] = 8;
        assert!(matches!(
            decode_contract_response(&response, 1),
            Err(NativeError::Protocol)
        ));
    }

    #[test]
    fn invalid_contexts_are_rejected_before_native_work() {
        let mut context = ContractContext {
            keys: vec![b"a".to_vec(), b"b".to_vec()],
            state: vec![None; 2],
            access: vec![true; 2],
            ..ContractContext::default()
        };
        assert_eq!(validate_context(&context, &[]), Ok(()));
        context.keys.reverse();
        assert_eq!(
            validate_context(&context, &[]),
            Err(ExecutionError::InvalidContext)
        );
        context.keys = vec![b"a".to_vec(), b"a".to_vec()];
        assert_eq!(
            validate_context(&context, &[]),
            Err(ExecutionError::InvalidContext)
        );
        context.keys = vec![b"a".to_vec()];
        assert_eq!(
            validate_context(&context, &[]),
            Err(ExecutionError::InvalidContext)
        );
        assert!(matches!(
            deadline(Duration::ZERO),
            Err(NativeError::InvalidDeadline)
        ));
    }

    #[test]
    fn worker_readiness_requires_every_enforcement_capability() {
        let mut readiness = b"TCSBX002".to_vec();
        readiness.extend_from_slice(&30u64.to_le_bytes());
        let io =
            IoThread::spawn(std::io::sink(), Cursor::new(readiness), response_bytes()).unwrap();
        assert!(matches!(
            io.ready.recv_timeout(Duration::from_secs(1)),
            Ok(Err(()))
        ));
    }

    struct BlockedWriter(Receiver<()>);
    impl Write for BlockedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .recv()
                .map_err(|_| std::io::Error::other("writer release closed"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn blocked_pipe_write_cannot_escape_caller_deadline() {
        let mut output = b"TCSBX002".to_vec();
        output.extend_from_slice(&31u64.to_le_bytes());
        output.resize(16 + response_bytes(), 0);
        let (release, blocked) = sync_channel(1);
        let io = IoThread::spawn(
            BlockedWriter(blocked),
            Cursor::new(output),
            response_bytes(),
        )
        .unwrap();
        io.ready
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let start = std::time::Instant::now();
        assert!(matches!(
            io.exchange(
                vec![0; request_bytes()],
                deadline(Duration::from_millis(5)).unwrap()
            ),
            Err(NativeError::ExecutionTimeout)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
        drop(io);
    }
}
