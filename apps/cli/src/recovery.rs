// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Offline authenticated history recovery and exclusive observer export without signing keys.

use crate::{CliError, proofs::anchors, wallet};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use storage::{ChainStorage, NodeStorage, RetentionPolicy};

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Config(value.to_string())
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    if matches!(command, "export-retained" | "verify-retained") {
        return retained(command, args);
    }
    if matches!(command, "retention-status" | "retention-compact") {
        return retention(command, args);
    }
    let expected = if command == "export-history" { 5 } else { 4 };
    if args.len() != expected {
        return Err(error("invalid history arguments; run cli help"));
    }
    let (genesis, keys) = anchors(Path::new(&args[0]), Path::new(&args[1]))?;
    let network = genesis.network(keys.clone())?;
    let directory = Path::new(&args[2]);
    let minimum = wallet::integer(&args[3])?;
    let path = directory.join("chain.bin");
    // Never initialize missing history when the operator requested verification/recovery.
    if !std::fs::symlink_metadata(&path)
        .map_err(error)?
        .file_type()
        .is_file()
    {
        return Err(error("chain.bin must be an existing regular file"));
    }
    let storage = ChainStorage::open(&path).map_err(error)?;
    let checkpoint = network.verify_storage(&storage).map_err(error)?;
    if checkpoint.height < minimum {
        return Err(error(
            "history is below the independently retained minimum height",
        ));
    }
    if command == "export-history" {
        let output = Path::new(&args[4]);
        // Refuse existing directories; failed exports remain for inspection, never auto-reused.
        std::fs::create_dir(output).map_err(error)?;
        copy_new(&path, &output.join("chain.bin"), 1 << 40)?;
        if !storage.is_legacy_archive() {
            copy_new(
                &directory.join("chain.bin.head"),
                &output.join("chain.bin.head"),
                80,
            )?;
        }
        write_new(&output.join("genesis.bin"), &genesis.to_bytes())?;
        write_new(&output.join("validators.bin"), &keys.concat())?;
        // Reopen the copy and verify the exact checkpoint before marking it as a ready observer.
        let copied = ChainStorage::open(output.join("chain.bin")).map_err(error)?;
        if network.verify_storage(&copied).map_err(error)? != checkpoint {
            return Err(error("copied checkpoint mismatch"));
        }
        let mut marker = b"ALOB".to_vec();
        marker.extend_from_slice(network.genesis_hash().as_bytes());
        write_new(&output.join("observer.mode"), &marker)?;
        write_new(&output.join("RECOVERY.txt"), format!("AstroLune authenticated observer history\nchain_id: {}\ngenesis: {}\nheight: {}\nblock: {}\nstate_root: {}\nUse the exported genesis.bin and validators.bin with daemon --observer.\nSupply a separately provisioned TLS identity and available peers.\nNo consensus keys, signing journals, transport keys or pending transactions are included.\n", network.chain_id(), network.genesis_hash(), checkpoint.height, checkpoint.block, checkpoint.state_root).as_bytes())?;
        #[cfg(unix)]
        File::open(output)
            .and_then(|file| file.sync_all())
            .map_err(error)?;
    }
    println!("verified_height: {}", checkpoint.height);
    println!("verified_block: {}", checkpoint.block);
    println!("verified_state_root: {}", checkpoint.state_root);
    println!(
        "backend: {}",
        if storage.is_legacy_archive() {
            "archive"
        } else {
            "append-only log"
        }
    );
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(error)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(error)
}
fn copy_new(source: &Path, destination: &Path, maximum: u64) -> Result<(), CliError> {
    let source = File::open(source).map_err(error)?;
    let length = source.metadata().map_err(error)?.len();
    if length > maximum {
        return Err(error("history export file exceeds its bound"));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(error)?;
    let copied = std::io::copy(&mut source.take(length + 1), &mut output).map_err(error)?;
    if copied != length {
        return Err(error("source changed during exclusive history export"));
    }
    output.sync_all().map_err(error)
}

fn retained(command: &str, args: &[OsString]) -> Result<(), CliError> {
    if !(args.len() == 6 || command == "export-retained" && args.len() == 8) {
        return Err(error("invalid retained-history arguments; run cli help"));
    }
    let (genesis, keys) = anchors(Path::new(&args[0]), Path::new(&args[1]))?;
    let mut network = genesis.network(keys.clone())?;
    let pin_offset = if command == "verify-retained" {
        Some(4)
    } else if args.len() == 8 {
        Some(6)
    } else {
        None
    };
    if let Some(at) = pin_offset {
        let bytes = crate::contracts::read_bounded(
            Path::new(&args[at]),
            node::network::RecoveryCheckpoint::MAX_BYTES,
        )?;
        let pin = rpc::client::decode_hex::<32>(wallet::text(&args[at + 1])?).map_err(error)?;
        let pin = types::Hash256(pin);
        network = network
            .with_checkpoint(
                node::network::RecoveryCheckpoint::from_bytes(&bytes, pin).map_err(error)?,
            )
            .map_err(error)?;
    }
    let path = Path::new(&args[2]).join("chain.bin");
    if !std::fs::symlink_metadata(&path)
        .map_err(error)?
        .file_type()
        .is_file()
    {
        return Err(error("existing regular chain.bin required"));
    }
    let storage = ChainStorage::open(&path).map_err(error)?;
    let head = network.verify_storage(&storage).map_err(error)?;
    if head.height < wallet::integer(&args[3])? {
        return Err(error("history precedes the independent minimum height"));
    }
    if command == "export-retained" {
        let destination = Path::new(&args[5]);
        let checkpoint = network
            .export_retained(&storage, wallet::integer(&args[4])?, destination)
            .map_err(error)?;
        write_new(&destination.join("genesis.bin"), &genesis.to_bytes())?;
        write_new(&destination.join("validators.bin"), &keys.concat())?;
        write_new(&destination.join("checkpoint.bin"), &checkpoint.to_bytes())?;
        let mut marker = b"ALOB".to_vec();
        marker.extend_from_slice(network.genesis_hash().as_bytes());
        write_new(&destination.join("observer.mode"), &marker)?;
        write_new(&destination.join("RECOVERY.txt"), format!("Retained observer history. Retain this pin independently: {}\nStart with --checkpoint checkpoint.bin --checkpoint-id {} and the original trusted profile/keys.\nThe original directory remains intact. No signing or transport keys are exported.\n", checkpoint.id(), checkpoint.id()).as_bytes())?;
        println!("checkpoint_id: {}", checkpoint.id());
        println!("checkpoint_height: {}", checkpoint.checkpoint().height);
    }
    println!("verified_height: {}", head.height);
    println!("verified_block: {}", head.block);
    Ok(())
}

/// Reports or applies automated in-place retention for one local directory.
///
/// Both commands acquire the exclusive storage writer lock, so the validator must
/// be stopped first. Reporting is read-only. Applying requires the independently
/// trusted profile and public keys, authenticates the existing history before
/// discarding anything, and reauthenticates the shortened directory afterwards.
/// Neither command reads, copies or resets a signing journal or its anchor.
fn retention(command: &str, args: &[OsString]) -> Result<(), CliError> {
    let status = command == "retention-status";
    if !(status && matches!(args.len(), 1 | 3) || !status && args.len() == 5) {
        return Err(error("invalid retention arguments; run cli help"));
    }
    let directory = Path::new(&args[if status { 0 } else { 2 }]);
    let path = directory.join("chain.bin");
    if !std::fs::symlink_metadata(&path)
        .map_err(error)?
        .file_type()
        .is_file()
    {
        return Err(error("existing regular chain.bin required"));
    }
    let mut storage = ChainStorage::open(&path).map_err(error)?;
    if status {
        return report(&storage, args.get(1..3));
    }
    let (genesis, keys) = anchors(Path::new(&args[0]), Path::new(&args[1]))?;
    let network = genesis.network(keys)?;
    let head = network.verify_storage(&storage).map_err(error)?;
    if head.height < wallet::integer(&args[3])? {
        return Err(error("history precedes the independent minimum height"));
    }
    let retain = wallet::integer(&args[4])?;
    let floor = head
        .height
        .checked_sub(retain)
        .filter(|floor| *floor > 0)
        .ok_or_else(|| error("retention requires a positive anchor height"))?;
    storage.prune(floor).map_err(error)?;
    // The shortened directory must still authenticate from its recorded anchor.
    if network.verify_storage(&storage).map_err(error)? != head {
        return Err(error("compacted history failed reauthentication"));
    }
    report(&storage, None)
}

/// Prints the retained floor and retention state, and what a policy would do next.
fn report(storage: &ChainStorage, policy: Option<&[OsString]>) -> Result<(), CliError> {
    let state = storage.retention_state();
    let head = storage.checkpoint().map_or(0, |cp| cp.height);
    println!(
        "backend: {}",
        if storage.is_legacy_archive() {
            "archive"
        } else {
            "append-only log"
        }
    );
    println!("head_height: {head}");
    println!("retained_floor: {}", height(state.retained_floor));
    println!("retained_bodies: {}", storage.block_count());
    println!("history_floor: {}", height(state.history_floor));
    println!("self_compacted: {}", state.self_compacted);
    println!("compactions: {}", state.compactions);
    println!(
        "policy: {}",
        if state.policy.is_enabled() {
            "bounded"
        } else {
            "disabled"
        }
    );
    match state.last_error {
        Some(error) => println!("last_retention_error: {error}"),
        None => println!("last_retention_error: none"),
    }
    let Some(requested) = policy else {
        return Ok(());
    };
    let retention = config::HistoryRetentionConfig {
        enabled: true,
        retained_blocks: wallet::integer(&requested[0])?,
        interval_blocks: wallet::integer(&requested[1])?,
        ..config::HistoryRetentionConfig::default()
    };
    retention
        .validate()
        .map_err(|e| error(format!("invalid retention policy: {e:?}")))?;
    let requested = RetentionPolicy::bounded(
        retention.retained_blocks,
        retention.interval_blocks,
        retention.max_compaction_bytes,
    )
    .map_err(error)?;
    println!("requested_retained_blocks: {}", requested.retained_blocks());
    println!("requested_interval_blocks: {}", requested.interval_blocks());
    println!(
        "requested_next_floor: {}",
        height(requested.target_floor(state.retained_floor.unwrap_or(0), head))
    );
    Ok(())
}

fn height(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_owned(), |height| height.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn configuration_and_storage_retention_bounds_state_the_same_numbers() {
        assert_eq!(config::MIN_RETAINED_BLOCKS, storage::MIN_RETAINED_BLOCKS);
        assert_eq!(config::MAX_RETAINED_BLOCKS, storage::MAX_RETAINED_BLOCKS);
        assert_eq!(
            config::DEFAULT_RETAINED_BLOCKS,
            storage::DEFAULT_RETAINED_BLOCKS
        );
        assert_eq!(
            config::MIN_RETENTION_INTERVAL_BLOCKS,
            storage::MIN_COMPACTION_INTERVAL_BLOCKS
        );
        assert_eq!(
            config::DEFAULT_RETENTION_INTERVAL_BLOCKS,
            storage::DEFAULT_COMPACTION_INTERVAL_BLOCKS
        );
        assert_eq!(
            config::MAX_RETENTION_INTERVAL_BLOCKS,
            storage::MAX_COMPACTION_INTERVAL_BLOCKS
        );
        assert_eq!(config::MIN_COMPACTION_BYTES, storage::MIN_COMPACTION_BYTES);
        assert_eq!(
            config::DEFAULT_COMPACTION_BYTES,
            storage::DEFAULT_COMPACTION_BYTES
        );
        assert_eq!(config::MAX_COMPACTION_BYTES, storage::MAX_COMPACTION_BYTES);
    }
}
