// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Experimental native LLVM execution of compiler-checked Trocto programs.
//!
//! Programs compile once into a persistent worker, outside the validator process.
//! Every result is checked against the compiler's portable reference semantics.
//! This is process separation, **not an operating-system security sandbox**. It
//! does not enforce a process memory quota or replace the active consensus runtime.
//! Only [`trocto_compiler::Program`] is accepted; external IR and executable
//! artifacts cannot be loaded through this interface. Compiler timeout cleanup
//! terminates the direct compiler child; OS-owned compiler process trees and
//! security sandboxes remain a separate qualification requirement.

#![forbid(unsafe_code)]

mod process;

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
use trocto_compiler::{Execution, ExecutionError, Program};

/// Exact LLVM release supported by this experimental native backend.
pub const LLVM_VERSION: &str = "22.1.8";

/// A local tool/worker failure or a deterministic Trocto execution error.
#[derive(Debug)]
pub enum NativeError {
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

/// A checked program compiled once into an owned persistent native worker.
///
/// Worker startup and LLVM compilation are outside the Trocto fuel budget.
/// Local deadline failures are reported separately from deterministic traps.
/// The initial prototype verifies every response with the reference evaluator;
/// its timings do not establish a native-only throughput improvement.
#[derive(Debug)]
pub struct NativeProgram {
    program: Program,
    worker: Option<Worker>,
    compiler_identity: String,
    // Keep the executable and compiler inputs alive until the worker is stopped.
    directory: BuildDirectory,
}

impl NativeProgram {
    /// Builds a checked program with pinned LLVM and starts a persistent worker.
    ///
    /// A bare compiler name is resolved through the caller's PATH; an explicit
    /// path is canonicalized. Each external compiler invocation has its own
    /// deadline. Compiler diagnostics are bounded to 8 KiB per stream.
    ///
    /// # Errors
    /// Returns a local [`NativeError`] for discovery, compilation or startup failure.
    pub fn compile(program: Program, clang: &Path, timeout: Duration) -> Result<Self, NativeError> {
        deadline(timeout)?;
        let clang = resolve_compiler(clang)?;
        let directory = BuildDirectory::new()?;
        let mut version = Command::new(&clang);
        configure(&mut version, &directory.path, &clang)?;
        version.args(["--no-default-config", "--version"]);
        let identity = bounded_command(version, timeout)?;
        if !identity.success {
            return Err(NativeError::CompilerIdentity(identity.stderr));
        }
        let compiler_identity = identity.stdout.lines().next().unwrap_or("").to_owned();
        if compiler_identity
            .split_once("clang version ")
            .and_then(|(_, tail)| tail.split_whitespace().next())
            != Some(LLVM_VERSION)
        {
            return Err(NativeError::CompilerIdentity(compiler_identity));
        }
        let module = directory.path.join("module.ll");
        let harness = directory.path.join("worker.c");
        let executable = directory.path.join(if cfg!(windows) {
            "worker.exe"
        } else {
            "worker"
        });
        std::fs::write(&module, program.llvm_ir())?;
        std::fs::write(&harness, HARNESS)?;
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
            .arg("-o")
            .arg(&executable);
        if cfg!(windows) {
            // LLVM-MinGW's trusted defaults are explicit; user config files
            // cannot inject extra headers, libraries or compiler flags.
            compiler.args(["-rtlib=compiler-rt", "-unwindlib=libunwind"]);
        }
        let build_result = bounded_command(compiler, timeout)?;
        if !build_result.success {
            return Err(NativeError::Compilation(build_result.stderr));
        }
        let worker = Worker::start(&executable, &directory.path, &clang)?;
        Ok(Self {
            program,
            worker: Some(worker),
            compiler_identity,
            directory,
        })
    }

    /// Reports the local compiler's version line, checked against [`LLVM_VERSION`].
    #[must_use]
    pub fn compiler_identity(&self) -> &str {
        &self.compiler_identity
    }

    /// Executes one request and checks native/reference equality before returning.
    ///
    /// Fuel errors, overflow and zero division leave the worker reusable. A local
    /// timeout, I/O failure or divergent response retires it permanently.
    ///
    /// # Errors
    /// Returns deterministic failures as [`NativeError::Contract`]; local resource,
    /// protocol and process failures use separate variants.
    pub fn execute(
        &mut self,
        input: u64,
        fuel: u64,
        timeout: Duration,
    ) -> Result<Execution, NativeError> {
        deadline(timeout)?;
        let expected = self.program.evaluate(input, fuel);
        let result = self
            .worker
            .as_mut()
            .ok_or(NativeError::WorkerUnavailable)?
            .request(input, fuel, timeout);
        let actual = match result {
            Ok(result) => result,
            Err(error) => {
                self.worker.take();
                return Err(error);
            }
        };
        if actual != expected {
            self.worker.take();
            return Err(NativeError::Divergence);
        }
        actual.map_err(NativeError::Contract)
    }
}

impl Drop for NativeProgram {
    fn drop(&mut self) {
        self.worker.take();
        // The explicit ownership order stops the worker before directory cleanup.
        let _ = &self.directory;
    }
}

#[derive(Debug)]
struct Worker {
    process: Child,
    io: IoThread,
}

#[derive(Debug)]
struct IoThread {
    requests: Option<SyncSender<[u8; 16]>>,
    responses: Option<Receiver<Result<[u8; 24], ()>>>,
    thread: Option<JoinHandle<()>>,
}

impl IoThread {
    fn spawn(
        mut input: impl Write + Send + 'static,
        mut output: impl Read + Send + 'static,
    ) -> Result<Self, NativeError> {
        let (requests, incoming) = sync_channel::<[u8; 16]>(1);
        let (outgoing, responses) = sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("trocto-worker-io".into())
            .spawn(move || {
                while let Ok(request) = incoming.recv() {
                    let mut response = [0; 24];
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
            thread: Some(thread),
        })
    }

    fn exchange(
        &self,
        request: [u8; 16],
        end: std::time::Instant,
    ) -> Result<[u8; 24], NativeError> {
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
            Ok(Ok(response)) => Ok(response),
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
    fn start(executable: &Path, directory: &Path, clang: &Path) -> Result<Self, NativeError> {
        let mut command = Command::new(executable);
        configure(&mut command, directory, clang)?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut process = command.spawn()?;
        let start = (|| {
            let input = process.stdin.take().ok_or(NativeError::WorkerUnavailable)?;
            let output = process
                .stdout
                .take()
                .ok_or(NativeError::WorkerUnavailable)?;
            IoThread::spawn(input, output)
        })();
        match start {
            Ok(io) => Ok(Self { process, io }),
            Err(error) => {
                let _ = process.kill();
                let _ = process.wait();
                Err(error)
            }
        }
    }

    fn request(
        &mut self,
        input: u64,
        fuel: u64,
        timeout: Duration,
    ) -> Result<Result<Execution, ExecutionError>, NativeError> {
        let end = deadline(timeout)?;
        if self.process.try_wait()?.is_some() {
            return Err(NativeError::WorkerUnavailable);
        }
        let mut request = [0; 16];
        request[..8].copy_from_slice(&input.to_le_bytes());
        request[8..].copy_from_slice(&fuel.to_le_bytes());
        decode_response(self.io.exchange(request, end)?)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Killing the owned worker closes its pipes and unblocks its I/O thread.
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn decode_response(response: [u8; 24]) -> Result<Result<Execution, ExecutionError>, NativeError> {
    let number = |start| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&response[start..start + 8]);
        u64::from_le_bytes(bytes)
    };
    let status = number(0);
    let value = number(8);
    let used = number(16);
    if status != 0 && (value != 0 || used != 0) {
        return Err(NativeError::Protocol);
    }
    Ok(match status {
        0 => Ok(Execution {
            value,
            fuel_used: used,
        }),
        1 => Err(ExecutionError::FuelExhausted),
        2 => Err(ExecutionError::Overflow),
        3 => Err(ExecutionError::DivisionByZero),
        _ => return Err(NativeError::Protocol),
    })
}

// Only trusted framing/I/O lives in C. The Trocto body comes from checked LLVM IR.
// Explicit little-endian framing avoids architecture/layout-dependent IPC bytes.
const HARNESS: &str = r"#include <stdint.h>
#include <stdio.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
extern int32_t trocto_call(uint64_t, uint64_t, uint64_t *, uint64_t *);
static uint64_t load(const unsigned char *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (i * 8);
    return v;
}
static void store(unsigned char *p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(v >> (i * 8));
}
int main(void) {
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) == -1 || _setmode(_fileno(stdout), _O_BINARY) == -1) return 4;
#endif
    unsigned char request[16];
    for (;;) {
        size_t n = fread(request, 1, sizeof request, stdin);
        if (n == 0 && feof(stdin)) return 0;
        if (n != sizeof request) return 5;
        _Alignas(8) uint64_t value = 0;
        _Alignas(8) uint64_t used = 0;
        int32_t status = trocto_call(load(request), load(request + 8), &value, &used);
        unsigned char response[24];
        store(response, (uint64_t)status);
        store(response + 8, value);
        store(response + 16, used);
        if (fwrite(response, 1, sizeof response, stdout) != sizeof response || fflush(stdout) != 0) return 6;
    }
}
";

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u64, value: u64, used: u64) -> [u8; 24] {
        let mut response = [0; 24];
        response[..8].copy_from_slice(&status.to_le_bytes());
        response[8..16].copy_from_slice(&value.to_le_bytes());
        response[16..].copy_from_slice(&used.to_le_bytes());
        response
    }

    #[test]
    fn binary_protocol_rejects_unknown_status_and_error_output() {
        assert_eq!(
            decode_response(response(0, u64::MAX, 19)).unwrap(),
            Ok(Execution {
                value: u64::MAX,
                fuel_used: 19
            })
        );
        for (status, expected) in [
            (1, ExecutionError::FuelExhausted),
            (2, ExecutionError::Overflow),
            (3, ExecutionError::DivisionByZero),
        ] {
            assert_eq!(
                decode_response(response(status, 0, 0)).unwrap(),
                Err(expected)
            );
            assert!(matches!(
                decode_response(response(status, 1, 0)),
                Err(NativeError::Protocol)
            ));
            assert!(matches!(
                decode_response(response(status, 0, 1)),
                Err(NativeError::Protocol)
            ));
        }
        assert!(matches!(
            decode_response(response(4, 0, 0)),
            Err(NativeError::Protocol)
        ));
    }

    #[test]
    fn deadlines_are_explicit_and_bounded() {
        assert!(matches!(
            deadline(Duration::ZERO),
            Err(NativeError::InvalidDeadline)
        ));
        assert!(matches!(
            deadline(Duration::from_secs(121)),
            Err(NativeError::InvalidDeadline)
        ));
        assert!(deadline(Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn a_blocked_pipe_write_does_not_block_the_request_deadline() {
        struct BlockedWriter {
            entered: std::sync::mpsc::Sender<()>,
            release: Receiver<()>,
        }
        impl Write for BlockedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let _ = self.entered.send(());
                self.release
                    .recv()
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (entered, waiting) = std::sync::mpsc::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let io = IoThread::spawn(
            BlockedWriter {
                entered,
                release: blocked,
            },
            std::io::Cursor::new([0_u8; 48]),
        )
        .unwrap();
        io.requests.as_ref().unwrap().try_send([0; 16]).unwrap();
        waiting.recv_timeout(Duration::from_secs(5)).unwrap();
        // Even after a second bounded enqueue, the caller only waits on the
        // response deadline while the owned thread remains blocked in write().
        assert!(matches!(
            io.exchange([0; 16], deadline(Duration::from_millis(20)).unwrap()),
            Err(NativeError::ExecutionTimeout)
        ));
        release.send(()).unwrap();
        io.responses
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        release.send(()).unwrap();
        io.responses
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        drop(io);
    }
}
