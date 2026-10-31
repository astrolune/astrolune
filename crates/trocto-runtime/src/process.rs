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

// Linux /bin/sh uses KiB for -v and POSIX 512-byte blocks for -f.
// Hard and soft limits are inherited by clang, cc1 and lld: 1 GiB address
// space, 30 CPU seconds, no core dump and 64 MiB per output file. The caller's
// separate total compilation deadline still bounds the entire operation.
// RLIMIT_NPROC is intentionally unchanged: it counts the user's other tasks,
// rather than processes belonging to this owned compiler tree.
#[cfg(unix)]
const COMPILER_SUPERVISOR: &str = "status_file=$1; shift
if ulimit -v 1048576 && ulimit -t 30 && ulimit -c 0 && ulimit -f 131072; then
    \"$@\" </dev/null
    compiler_status=$?
else
    compiler_status=125
    printf '%s\\n' 'Trocto compiler resource limits could not be established' >&2
fi
printf '%s' \"$compiler_status\" > \"$status_file\"
IFS= read -r release";

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
    pub(crate) probe: PathBuf,
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
                    let probe = path.with_extension("probe");
                    let file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&probe)?;
                    drop(file);
                    return Ok(Self {
                        path: path.canonicalize()?,
                        probe,
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
            if self.probe.parent() == Some(self.parent.as_path()) {
                let _ = std::fs::remove_file(&self.probe);
            }
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
    #[cfg(windows)]
    let windows_directory = windows_path(directory);
    #[cfg(windows)]
    let directory = windows_directory.as_path();
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
    for name in ["SystemRoot", "WINDIR", "USERPROFILE", "LOCALAPPDATA"] {
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

#[cfg(windows)]
fn windows_path(path: &Path) -> PathBuf {
    let value = path.to_string_lossy();
    if let Some(tail) = value.strip_prefix("\\\\?\\UNC\\") {
        PathBuf::from(format!("\\\\{tail}"))
    } else if let Some(tail) = value.strip_prefix("\\\\?\\") {
        PathBuf::from(tail)
    } else {
        path.to_path_buf()
    }
}

#[derive(Debug)]
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

// Own a fresh compiler process group; linker descendants share its lifetime.
struct ChildCleanup(Child);

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        terminate_tree(&mut self.0);
    }
}

pub(crate) fn terminate_tree(child: &mut Child) {
    // Only signal while the owned direct child is still live: its identifier
    // cannot then have been reused for an unrelated process/group.
    if matches!(child.try_wait(), Ok(None)) {
        #[cfg(unix)]
        {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        #[cfg(windows)]
        if let Some(root) = std::env::var_os("SystemRoot") {
            use std::os::windows::process::CommandExt;
            let _ = Command::new(PathBuf::from(root).join("System32/taskkill.exe"))
                .args(["/PID", &child.id().to_string(), "/T", "/F"])
                .creation_flags(0x0800_0000)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn bounded_command(
    command: Command,
    timeout: Duration,
) -> Result<Captured, NativeError> {
    let end = deadline(timeout)?;
    let mut supervised = supervise(&command)?;
    drop(command);
    let command = &mut supervised.command;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    // Declared before the child so error unwinding kills the process tree
    // before joining any reader blocked on an inherited descendant pipe.
    let mut readers = ReaderThreads::default();
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
    readers.0.push(
        std::thread::Builder::new()
            .name("trocto-compiler-stdout".into())
            .spawn(move || {
                let _ = stdout_sender.send((0, capture(stdout, DIAGNOSTIC_BYTES)));
            })?,
    );
    readers.0.push(
        std::thread::Builder::new()
            .name("trocto-compiler-stderr".into())
            .spawn(move || {
                let _ = sender.send((1, capture(stderr, DIAGNOSTIC_BYTES)));
            })?,
    );
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
            if let Some(marker) = &supervised.status {
                let value = std::fs::read_to_string(marker)?;
                if let Ok(code) = value.parse::<u32>() {
                    terminate_tree(&mut child.0);
                    status = Some(code == 0);
                }
            } else {
                status = child.0.try_wait()?.map(|status| status.success());
            }
        }
        if let (Some(status), [Some(stdout), Some(stderr)]) = (status, &captured) {
            break Ok(Captured {
                success: status,
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

#[derive(Default)]
struct ReaderThreads(Vec<std::thread::JoinHandle<()>>);
impl Drop for ReaderThreads {
    fn drop(&mut self) {
        for reader in self.0.drain(..) {
            let _ = reader.join();
        }
    }
}

struct Supervised {
    command: Command,
    status: Option<PathBuf>,
    _directory: BuildDirectory,
}

fn supervise(original: &Command) -> Result<Supervised, NativeError> {
    let directory = BuildDirectory::new()?;
    #[cfg(unix)]
    let (mut command, status) = {
        let status = directory.path.join("status");
        std::fs::write(&status, [])?;
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", COMPILER_SUPERVISOR, "trocto-compiler-supervisor"])
            .arg(&status)
            .arg(original.get_program())
            .args(original.get_args())
            .stdin(Stdio::piped());
        (command, Some(status))
    };
    #[cfg(windows)]
    let (mut command, status) = {
        use std::os::windows::process::CommandExt;
        let root = std::env::var_os("SystemRoot")
            .ok_or_else(|| NativeError::Io("Windows system root unavailable".into()))?;
        let script = directory.path.join("compiler-supervisor.ps1");
        std::fs::write(&script, include_str!("compiler-supervisor.ps1"))?;
        let request = directory.path.join("arguments.bin");
        let mut bytes = Vec::new();
        for argument in std::iter::once(original.get_program()).chain(original.get_args()) {
            let argument = argument
                .to_str()
                .ok_or_else(|| NativeError::Io("compiler arguments require valid UTF-8".into()))?;
            let length = u32::try_from(argument.len()).map_err(|_| NativeError::Protocol)?;
            if length > 65536 {
                return Err(NativeError::Protocol);
            }
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(argument.as_bytes());
        }
        std::fs::write(&request, bytes)?;
        let mut command = Command::new(
            PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe"),
        );
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(windows_path(&script))
            .arg("-Request")
            .arg(windows_path(&request))
            .stdin(Stdio::null());
        command.creation_flags(0x0800_0000);
        (command, None)
    };
    command
        .env_clear()
        .current_dir(original.get_current_dir().unwrap_or(&directory.path));
    for (name, value) in original.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        } else {
            command.env_remove(name);
        }
    }
    Ok(Supervised {
        command,
        status,
        _directory: directory,
    })
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

    fn platform_command() -> Command {
        #[cfg(unix)]
        {
            Command::new("/bin/sh")
        }
        #[cfg(windows)]
        {
            Command::new(
                PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                    .join("System32/WindowsPowerShell/v1.0/powershell.exe"),
            )
        }
    }
    #[test]
    fn compiler_descendant_inherited_pipes_end_when_direct_compiler_exits() {
        let directory = BuildDirectory::new().unwrap();
        let mut command = platform_command();
        configure(&mut command, &directory.path, Path::new("clang")).unwrap();
        #[cfg(unix)]
        command.args(["-c", "sleep 30 & printf 'compiler-done\\n'"]);
        #[cfg(windows)]
        command.args(["-NoProfile","-NonInteractive","-Command","Start-Process -FilePath (Join-Path $env:SystemRoot 'System32/ping.exe') -ArgumentList @('-n','30','127.0.0.1') -NoNewWindow | Out-Null; [Console]::WriteLine('compiler-done')"]);
        let start = Instant::now();
        let result = bounded_command(command, Duration::from_secs(5)).unwrap();
        assert!(result.success);
        assert!(start.elapsed() < Duration::from_secs(3));
    }
    #[test]
    fn compiler_timeout_and_diagnostic_limit_join_owned_readers() {
        for flood in [false, true] {
            let directory = BuildDirectory::new().unwrap();
            let mut command = platform_command();
            configure(&mut command, &directory.path, Path::new("clang")).unwrap();
            #[cfg(unix)]
            command.args(["-c", if flood { "yes x" } else { "sleep 30" }]);
            #[cfg(windows)]
            command.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                if flood {
                    "1..10000 | ForEach-Object { [Console]::WriteLine('xxxxxxxx') }"
                } else {
                    "Start-Sleep -Seconds 30"
                },
            ]);
            let start = Instant::now();
            let result = bounded_command(
                command,
                if flood {
                    Duration::from_secs(5)
                } else {
                    Duration::from_millis(50)
                },
            );
            if flood {
                assert!(
                    matches!(result, Err(NativeError::DiagnosticLimit)),
                    "{result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(NativeError::CompilationTimeout)),
                    "{result:?}"
                );
            }
            assert!(start.elapsed() < Duration::from_secs(3));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compiler_children_inherit_kernel_hard_resource_limits() {
        let directory = BuildDirectory::new().unwrap();
        let mut command = Command::new("/bin/cat");
        configure(&mut command, &directory.path, Path::new("clang")).unwrap();
        command.arg("/proc/self/limits");
        let result = bounded_command(command, Duration::from_secs(5)).unwrap();
        assert!(result.success, "{result:?}");
        for (name, limit) in [
            ("Max address space", "1073741824"),
            ("Max cpu time", "30"),
            ("Max core file size", "0"),
            ("Max file size", "67108864"),
        ] {
            let values = result
                .stdout
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>();
            assert_eq!(&values[..2], &[limit, limit], "{name}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compiler_child_cannot_raise_inherited_memory_and_output_limits() {
        let directory = BuildDirectory::new().unwrap();
        let mut command = Command::new("/bin/sh");
        configure(&mut command, &directory.path, Path::new("clang")).unwrap();
        command.args(["-c","if ulimit -v 2097152 2>/dev/null; then exit 7; fi; if ulimit -f 262144 2>/dev/null; then exit 8; fi; printf 'limits-refused\\n'"]);
        let result = bounded_command(command, Duration::from_secs(5)).unwrap();
        assert!(result.success, "{result:?}");
        assert_eq!(result.stdout, "limits-refused\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires pinned native clang 22.1.8"]
    fn large_checked_module_compiles_and_runs_under_compiler_quotas() {
        let source = format!(
            "fn call(input: u64) -> u64 {{ {} return state_get_at(0); }}",
            "state_set_at(0, input); ".repeat(1000)
        );
        let program = trocto_compiler::compile(&source).unwrap();
        assert!(program.instruction_count() >= 2000);
        let clang = std::env::var_os("ASTROLUNE_LLVM_CLANG")
            .map_or_else(|| PathBuf::from("clang"), PathBuf::from);
        let mut native =
            crate::NativeProgram::compile(program, &clang, Duration::from_secs(30)).unwrap();
        let context = trocto_compiler::ContractContext {
            keys: vec![b"large-module".to_vec()],
            state: vec![None],
            access: vec![true],
            ..trocto_compiler::ContractContext::default()
        };
        let output = native
            .execute_contract(123, &context, 10000, Duration::from_secs(5))
            .unwrap();
        assert_eq!(output.value, 123);
        assert_eq!(output.state, vec![Some(123)]);
        assert_eq!(output.writes, vec![true]);
    }
}
