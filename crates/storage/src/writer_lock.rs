// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Writer ownership ends at guard drop even if a child inherited a descriptor.

use std::{
    fs::{File, OpenOptions, TryLockError},
    path::Path,
};

use crate::StorageError;

#[derive(Debug)]
pub(crate) struct WriterLock(File);

impl WriterLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, StorageError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|_| StorageError::Io)?;
        file.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => StorageError::Locked,
            TryLockError::Error(_) => StorageError::Io,
        })?;
        Ok(Self(file))
    }
}

impl Drop for WriterLock {
    fn drop(&mut self) {
        // Linux flock belongs to the open file description. Closing only our
        // descriptor leaves it locked while a concurrent fork retains a copy,
        // even when that copy is marked close-on-exec. Release ownership now;
        // keep the sidecar inode stable for existing and subsequent writers.
        let _ = self.0.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn dropping_owner_releases_lock_while_duplicate_descriptor_remains_open() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-writer-lock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let owner = WriterLock::acquire(&path).unwrap();
        let inherited = owner.0.try_clone().unwrap();
        assert!(matches!(
            WriterLock::acquire(&path),
            Err(StorageError::Locked)
        ));
        drop(owner);
        assert!(path.is_file());
        let successor = WriterLock::acquire(&path).unwrap();
        // A surviving duplicate does not release a successor's separate lock.
        drop(inherited);
        assert!(matches!(
            WriterLock::acquire(&path),
            Err(StorageError::Locked)
        ));
        drop(successor);
        drop(WriterLock::acquire(&path).unwrap());
        std::fs::remove_file(path).unwrap();
    }
}
