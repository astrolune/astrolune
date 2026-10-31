// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded external compiler handling and owned build directories.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{TryRecvError, channel},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::NativeError;

const DIAGNOSTIC_BYTES: usize = 8192;
static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) fn deadline(timeout: Duration) -> Result<Instant, NativeError> {
    if timeout.is_zero() || timeout > Duration::from_secs(120) {
        return Err(NativeError::InvalidDeadline);
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or(NativeError::InvalidDeadline)
}

#[derive(Debug)]
pub(crate) struct BuildDirectory {
    pub(crate) path: PathBuf,
    parent: PathBuf,
}

impl BuildDirectory {
    pub(crate) fn new() -> Result<Self, NativeError> {
        let parent = std::env::temp_dir().canonicalize()?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| NativeError::Io(error.to_string()))?
            .as_nanos();
        for _ in 0..128 {
            let counter = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "trocto-native-{}-{nonce}-{counter}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path: path.canonicalize()?,
                        parent,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(NativeError::Io(
            "could not allocate an owned build directory".into(),
        ))
    }
}

impl Drop for BuildDirectory {
    fn drop(&mut self) {
        // Never recursively remove the temp root or a path redirected by a symlink.
        if self.path.parent() == Some(self.parent.as_path())
            && self.path.canonicalize().ok().as_ref() == Some(&self.path)
        {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) fn resolve_compiler(path: &Path) -> Result<PathBuf, NativeError> {
    if path.is_absolute() || path.components().count() > 1 {
        return Ok(path.canonicalize()?);
    }
    let search = std::env::var_os("PATH")
        .ok_or_else(|| NativeError::Io("compiler PATH is missing".into()))?;
    for directory in std::env::split_paths(&search) {
        let candidate = directory.join(path);
        if candidate.is_file() {
            return Ok(candidate.canonicalize()?);
        }
        #[cfg(windows)]
        if path.extension().is_none() {
            let candidate = candidate.with_extension("exe");
            if candidate.is_file() {
                return Ok(candidate.canonicalize()?);
            }
        }
    }
    Err(NativeError::Io(
        "configured LLVM compiler was not found".into(),
    ))
}

pub(crate) fn configure(
    command: &mut Command,
    directory: &Path,
    clang: &Path,
) -> Result<(), NativeError> {
    command
        .env_clear()
        .current_dir(directory)
        .stdin(Stdio::null());
    let mut tools = vec![clang.parent().unwrap_or(Path::new("")).to_path_buf()];
    if cfg!(unix) {
        // The platform linker and CRT are trusted parts of the local toolchain.
        tools.extend([PathBuf::from("/usr/bin"), PathBuf::from("/bin")]);
    }
    command.env(
        "PATH",
        std::env::join_paths(tools).map_err(|error| NativeError::Io(error.to_string()))?,
    );
    command
        .env("TMP", directory)
        .env("TEMP", directory)
        .env("TMPDIR", directory);
    for name in ["SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    Ok(())
}

pub(crate) struct Captured {
    pub(crate) success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

fn capture(mut stream: impl Read, maximum: usize) -> Result<Vec<u8>, NativeError> {
    let mut data = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Ok(data);
        }
        if data.len() + count > maximum {
            return Err(NativeError::DiagnosticLimit);
        }
        data.extend_from_slice(&chunk[..count]);
    }
}

// Reap the direct compiler even on thread-start and try_wait I/O failures.
// This initial portable implementation does not own the compiler's descendants.
struct ChildCleanup(Child);

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(crate) fn bounded_command(
    mut command: Command,
    timeout: Duration,
) -> Result<Captured, NativeError> {
    let end = deadline(timeout)?;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = ChildCleanup(command.spawn()?);
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or(NativeError::WorkerUnavailable)?;
    let stderr = child
        .0
        .stderr
        .take()
        .ok_or(NativeError::WorkerUnavailable)?;
    let (sender, receiver) = channel();
    let stdout_sender = sender.clone();
    std::thread::Builder::new()
        .name("trocto-compiler-stdout".into())
        .spawn(move || {
            let _ = stdout_sender.send((0, capture(stdout, DIAGNOSTIC_BYTES)));
        })?;
    std::thread::Builder::new()
        .name("trocto-compiler-stderr".into())
        .spawn(move || {
            let _ = sender.send((1, capture(stderr, DIAGNOSTIC_BYTES)));
        })?;
    let mut captured: [Option<Vec<u8>>; 2] = [None, None];
    let mut status = None;
    'capture_error: loop {
        loop {
            match receiver.try_recv() {
                Ok((slot, Ok(bytes))) => captured[slot] = Some(bytes),
                Ok((_, Err(error))) => break 'capture_error Err(error),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        if status.is_none() {
            status = child.0.try_wait()?;
        }
        if let (Some(status), [Some(stdout), Some(stderr)]) = (status, &captured) {
            break Ok(Captured {
                success: status.success(),
                stdout: String::from_utf8_lossy(stdout).into_owned(),
                stderr: String::from_utf8_lossy(stderr).into_owned(),
            });
        }
        if Instant::now() >= end {
            break Err(NativeError::CompilationTimeout);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_bounded_without_silently_truncating_them() {
        assert_eq!(capture(&b"abc"[..], 3).unwrap(), b"abc");
        assert!(matches!(
            capture(&b"abcd"[..], 3),
            Err(NativeError::DiagnosticLimit)
        ));
    }

    #[test]
    fn build_directories_are_unique_owned_and_removed_after_drop() {
        let first = BuildDirectory::new().unwrap();
        let second = BuildDirectory::new().unwrap();
        assert_ne!(first.path, second.path);
        let path = first.path.clone();
        std::fs::write(path.join("module.ll"), b"test").unwrap();
        drop(first);
        assert!(!path.exists());
        assert!(second.path.is_dir());
    }
}
