// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Automated retention: in-place compaction, restart, refusal without a record, custody.
//!
//! Compaction here reclaims only history this writer authenticated and published.
//! It establishes no trust pin and never touches a protected signing journal.

#[path = "../../../crates/consensus/tests/support/potb.rs"]
mod support;

use codec::CanonicalEncode;
use keystore::{DurableSigner, SigningContext};
use node::network::{NetworkNode, StaticNetwork};
use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use storage::ChainStorage;

const RETAINED: u64 = storage::MIN_RETAINED_BLOCKS;
const HEIGHT: u64 = RETAINED + 4;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        // This fixture owns its unique temporary directory.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn context(network: &StaticNetwork) -> SigningContext {
    SigningContext {
        chain_id: network.chain_id(),
        genesis: network.genesis_hash(),
    }
}

fn open(directory: &Directory, network: &StaticNetwork, seed: u8) -> NetworkNode {
    let path = directory.0.join(seed.to_string());
    let signer =
        DurableSigner::open(path.join("signing.journal"), context(network), [seed; 32]).unwrap();
    NetworkNode::open(network.clone(), &path, signer, Duration::from_millis(100)).unwrap()
}

fn advance(nodes: &mut [NetworkNode], height: u64) {
    let now = Instant::now();
    for step in 0..400 {
        for index in 0..nodes.len() {
            if nodes[index].request().height >= height {
                continue;
            }
            let request = nodes[index].request();
            let responses: Vec<_> = nodes
                .iter()
                .map(|node| node.respond(request).unwrap())
                .collect();
            for response in responses {
                nodes[index].receive(&response).unwrap();
            }
            if nodes[index].request().height < height {
                nodes[index]
                    .tick(now + Duration::from_millis(step * 20))
                    .unwrap();
            }
        }
        if nodes.iter().all(|node| node.request().height == height) {
            return;
        }
    }
    panic!("reference cluster did not reach height {height}");
}

fn cli(directory: &Directory, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cli"))
        .current_dir(&directory.0)
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn field(output: &Output, name: &str) -> String {
    stdout(output)
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")).map(str::to_owned))
        .unwrap_or_else(|| panic!("missing field {name} in:\n{}", stdout(output)))
}

/// Builds a fixed-committee cluster of four validators with protected journals.
fn cluster() -> (Directory, StaticNetwork) {
    let (base, keys) = support::fixture();
    let mut genesis = base.genesis().clone();
    genesis.version = 1;
    genesis.committee_size = genesis.validators.len();
    let network = StaticNetwork::new(genesis.clone(), keys.clone()).unwrap();
    let directory = Directory(std::env::temp_dir().join(format!(
        "astrolune-cli-retention-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir(&directory.0).unwrap();
    std::fs::write(directory.0.join("genesis"), genesis.to_bytes()).unwrap();
    std::fs::write(directory.0.join("validators"), keys.concat()).unwrap();
    for seed in 1..=4u8 {
        let path = directory.0.join(seed.to_string());
        std::fs::create_dir(&path).unwrap();
        drop(
            DurableSigner::create_protected(
                path.join("signing.journal"),
                context(&network),
                [seed; 32],
            )
            .unwrap(),
        );
    }
    (directory, network)
}

#[test]
fn in_place_retention_survives_restart_and_still_refuses_unrecorded_shortening() {
    let (directory, network) = cluster();
    let mut nodes: Vec<_> = (1..=4u8).map(|s| open(&directory, &network, s)).collect();
    advance(&mut nodes, HEIGHT + 1);
    let head = *nodes[0].storage().checkpoint().unwrap();
    assert_eq!(head.height, HEIGHT);
    drop(nodes);

    // An independent rollback anchor is provisioned before any retention runs.
    let node = directory.0.join("1");
    let journal = node.join("signing.journal");
    let anchor = node.join("independent.anchor");
    let signer =
        DurableSigner::create_anchor(&journal, context(&network), [1; 32], &anchor).unwrap();
    let witnessed = signer.anchor_sequence().unwrap();
    let identity = signer.anchor_journal_identity().unwrap();
    drop(signer);
    let journal_bytes = std::fs::read(&journal).unwrap();
    let anchor_bytes = std::fs::read(&anchor).unwrap();

    let before = cli(&directory, &["retention-status", "1"]);
    assert!(before.status.success(), "{}", stdout(&before));
    assert_eq!(field(&before, "retained_floor"), "0");
    assert_eq!(field(&before, "self_compacted"), "false");
    assert_eq!(field(&before, "policy"), "disabled");

    let applied = cli(
        &directory,
        &[
            "retention-compact",
            "genesis",
            "validators",
            "1",
            "1",
            &RETAINED.to_string(),
        ],
    );
    assert!(applied.status.success(), "{}", stdout(&applied));
    let floor = HEIGHT - RETAINED;
    assert_eq!(field(&applied, "retained_floor"), floor.to_string());
    assert_eq!(field(&applied, "self_compacted"), "true");
    assert_eq!(field(&applied, "compactions"), "1");
    assert_eq!(
        field(&applied, "retained_bodies"),
        RETAINED.to_string(),
        "wrong retained suffix"
    );
    // Retention never reads, copies, resets or invalidates signing state.
    assert_eq!(std::fs::read(&journal).unwrap(), journal_bytes);
    assert_eq!(std::fs::read(&anchor).unwrap(), anchor_bytes);
    let paired =
        DurableSigner::open_with_anchor(&journal, context(&network), [1; 32], &anchor).unwrap();
    assert_eq!(paired.anchor_journal_identity(), Some(identity));
    assert_eq!(paired.anchor_sequence(), Some(witnessed));
    let watermark = paired.last_position().map(|position| position.height);
    drop(paired);

    let record = node.join("chain.bin.retain");
    let saved = std::fs::read(&record).unwrap();
    {
        let storage = ChainStorage::open(node.join("chain.bin")).unwrap();
        assert_eq!(storage.retained_floor(), Some(floor));
        assert_eq!(
            storage.local_retention_anchor().map(|cp| cp.height),
            Some(floor)
        );
        assert!(storage.read_finalized(floor).unwrap().is_none());
        assert!(storage.read_finalized(floor + 1).unwrap().is_some());
        // Local continuity, recorded under the writer lock, authenticates the shortening.
        assert_eq!(network.verify_storage(&storage).unwrap(), head);
    }
    {
        // The same bytes without that record are an externally supplied history.
        std::fs::remove_file(&record).unwrap();
        let storage = ChainStorage::open(node.join("chain.bin")).unwrap();
        assert_eq!(storage.local_retention_anchor(), None);
        assert!(
            network.verify_storage(&storage).is_err(),
            "shortened history was accepted without a local record or an independent pin"
        );
    }
    std::fs::write(&record, &saved).unwrap();

    let mut nodes: Vec<_> = (1..=4u8).map(|s| open(&directory, &network, s)).collect();
    assert_eq!(nodes[0].storage().checkpoint(), Some(&head));
    assert_eq!(nodes[0].storage().retained_floor(), Some(floor));
    advance(&mut nodes, HEIGHT + 3);
    assert_eq!(
        nodes[0].storage().checkpoint(),
        nodes[1].storage().checkpoint(),
        "the compacted validator diverged from full-history peers"
    );
    drop(nodes);

    // The protected journal only ever advanced; nothing reset its watermark.
    let resumed = DurableSigner::open(&journal, context(&network), [1; 32]).unwrap();
    assert!(
        resumed.last_position().map(|position| position.height) >= watermark,
        "the journal watermark moved backwards across retention and restart"
    );
    assert!(
        resumed.last_position().map(|position| position.height) >= Some(HEIGHT),
        "the journal does not witness the retained history it signed"
    );
}

#[test]
fn retention_status_reports_a_requested_policy_without_changing_anything() {
    let (directory, network) = cluster();
    let mut nodes: Vec<_> = (1..=4u8).map(|s| open(&directory, &network, s)).collect();
    advance(&mut nodes, HEIGHT + 1);
    drop(nodes);
    let node = directory.0.join("1");
    let bytes = std::fs::read(node.join("chain.bin")).unwrap();
    let output = cli(
        &directory,
        &["retention-status", "1", &RETAINED.to_string(), "1"],
    );
    assert!(output.status.success(), "{}", stdout(&output));
    assert_eq!(
        field(&output, "requested_next_floor"),
        (HEIGHT - RETAINED).to_string()
    );
    assert_eq!(field(&output, "retained_floor"), "0");
    assert_eq!(std::fs::read(node.join("chain.bin")).unwrap(), bytes);
    assert!(!node.join("chain.bin.retain").exists());
    for invalid in [["1", "1"], ["4096", "1"], [&RETAINED.to_string(), "0"]] {
        let refused = cli(
            &directory,
            &["retention-status", "1", invalid[0], invalid[1]],
        );
        assert!(
            !refused.status.success(),
            "accepted retention policy {invalid:?}"
        );
    }
    assert!(
        !cli(&directory, &["retention-status", "missing"])
            .status
            .success()
    );
    assert!(
        !cli(
            &directory,
            &["retention-compact", "genesis", "validators", "1", "1"]
        )
        .status
        .success(),
        "accepted a compaction without a retained-block count"
    );
}

#[test]
fn offline_compaction_requires_the_independently_trusted_profile_and_minimum_height() {
    let (directory, network) = cluster();
    let mut nodes: Vec<_> = (1..=4u8).map(|s| open(&directory, &network, s)).collect();
    advance(&mut nodes, HEIGHT + 1);
    drop(nodes);
    let node = directory.0.join("1");
    let bytes = std::fs::read(node.join("chain.bin")).unwrap();
    let mut forged = std::fs::read(directory.0.join("validators")).unwrap();
    forged[0] ^= 1;
    std::fs::write(directory.0.join("forged"), &forged).unwrap();
    for args in [
        vec!["retention-compact", "genesis", "forged", "1", "1", "8"],
        vec![
            "retention-compact",
            "genesis",
            "validators",
            "1",
            "9999",
            "8",
        ],
        vec!["retention-compact", "genesis", "validators", "1", "1", "1"],
        vec![
            "retention-compact",
            "genesis",
            "validators",
            "1",
            "1",
            &HEIGHT.to_string(),
        ],
    ] {
        let refused = cli(&directory, &args);
        assert!(!refused.status.success(), "accepted {args:?}");
        assert_eq!(
            std::fs::read(node.join("chain.bin")).unwrap(),
            bytes,
            "{args:?} changed the log"
        );
        assert!(!node.join("chain.bin.compact").exists(), "{args:?}");
        assert!(!node.join("chain.bin.swap").exists(), "{args:?}");
    }
    assert!(node.join("chain.bin").is_file());
}
