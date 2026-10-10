// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Ordering between test threads that spawn a child process and test threads
//! that drop and re-open an operating-system file lock.
//!
//! Several test binaries in this workspace do two incompatible things at once.
//! One test proves that an abrupt process exit releases a writer lock, so it
//! spawns a child with [`std::process::Command`]. Other tests in the same
//! binary drop a lock-holding handle and immediately re-open the same path, to
//! prove that an ordinary shutdown releases the lock too. The default test
//! harness runs those tests in sibling threads of one process, and on Unix the
//! two activities race.
//!
//! # Why spawning breaks an unrelated thread's lock
//!
//! Spawning a process on Unix is `fork` (or `posix_spawn`, which forks
//! internally) followed by `execve`. The child begins as a duplicate of the
//! entire parent, so every descriptor the parent had open is duplicated into
//! it, and a duplicated descriptor refers to the *same open file description*
//! as the original. An `flock(2)` lock is a property of that open file
//! description, and the kernel releases it only once *every* descriptor
//! referring to the description has been closed. Rust opens files `O_CLOEXEC`,
//! so the child's duplicates do close -- but not until `execve`. In the window
//! between `fork` and `execve` the child therefore holds duplicates of locks
//! belonging to entirely unrelated sibling threads. If a sibling drops its
//! handle inside that window, the lock outlives the drop, and the sibling's
//! immediate re-open fails with the production "already locked" error.
//!
//! Windows has no `fork` and Rust marks handles non-inheritable, so the race
//! cannot occur there. Hosted CI runners have few virtual cores and little
//! thread overlap, so it rarely occurs there either. It reproduces readily on
//! an idle multi-core Linux machine, which is why this guard exists even though
//! the affected tests look sound on a developer's Windows workstation.
//!
//! # How to use it
//!
//! A test that drops a lock-holding handle and re-opens it holds
//! [`holding_file_lock`] for its whole body; a test that spawns a child process
//! holds [`spawning_child`] for its whole body. Shared holders do not exclude
//! each other, so lock-holding tests keep running in parallel and only spawning
//! is serialised against them.
//!
//! Take the shared guard *before* opening the handle, not just before the
//! re-open. Taking it later does not help, because the fork may already have
//! duplicated the descriptor and the child may not have reached `execve`.
//!
//! Both guards come from one [`RwLock`], which is not reentrant, so a single
//! test takes exactly one of them. A test that both spawns a child and re-opens
//! a lock takes [`spawning_child`] alone: exclusive access already excludes
//! every shared holder, so no second guard is needed.
//!
//! This is deliberately not a retry loop inside the production `open` path. The
//! "already locked" error is a meaningful production result, and retrying there
//! would hide genuine contention between processes.
//!
//! What this does NOT establish: that the production file lock is fork-safe --
//! a production process that forks while holding one has exactly the same
//! window, and nothing here changes that; that unrelated processes are ordered
//! -- the guard is a `static` and therefore orders threads within one test
//! binary only, never two test binaries, nor a test binary against the children
//! it spawns; that a genuine "already locked" error is spurious -- contention
//! between real competing processes is still a true result and must still fail
//! a test that does not expect it; or that any file or path is mutually
//! excluded -- the guard carries no data and protects no path, it only orders
//! the two kinds of participant that opt in by calling the functions below.

use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Orders the spawning and lock-holding test threads of one test binary.
static FORK_WINDOW: RwLock<()> = RwLock::new(());

/// Shared guard proving no sibling thread is between `fork` and `execve`.
pub type FileLockGuard = RwLockReadGuard<'static, ()>;

/// Exclusive guard proving no sibling thread holds a droppable file lock.
pub type SpawnGuard = RwLockWriteGuard<'static, ()>;

/// Acquires shared access for a test that drops and re-opens a file lock.
///
/// Hold the returned guard for the whole test body, acquired before the
/// lock-holding handle is opened. Shared holders run concurrently with one
/// another; they exclude only [`spawning_child`].
#[must_use = "the guard must stay alive for the whole test body; binding it to `_` drops it at once and restores the race"]
pub fn holding_file_lock() -> FileLockGuard {
    // The guard carries no data, so a panicking holder leaves nothing
    // inconsistent and recovering from poisoning is correct: one failed test
    // must not cascade into every later test in the binary.
    FORK_WINDOW.read().unwrap_or_else(PoisonError::into_inner)
}

/// Acquires exclusive access for a test that spawns a child process.
///
/// Hold the returned guard for the whole test body, acquired before the spawn
/// and released only after the child has been reaped. Exclusive access also
/// covers a re-open performed by the spawning test itself, which must therefore
/// not additionally call [`holding_file_lock`].
#[must_use = "the guard must stay alive until the spawned child has been reaped; binding it to `_` drops it at once and restores the race"]
pub fn spawning_child() -> SpawnGuard {
    FORK_WINDOW.write().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::{holding_file_lock, spawning_child};

    #[test]
    fn a_holder_that_panics_does_not_poison_later_acquisitions() {
        // The helper thread prints an expected panic message; the guard protects
        // no data, so both modes must still be acquirable afterwards.
        let outcome = std::thread::spawn(|| {
            let _guard = spawning_child();
            panic!("deliberate panic while the exclusive guard is held");
        })
        .join();
        assert!(outcome.is_err(), "the helper thread must have panicked");
        drop(holding_file_lock());
        drop(spawning_child());
    }
}
