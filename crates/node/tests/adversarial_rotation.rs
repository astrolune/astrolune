// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Deterministic hostile delivery schedules using real rotating nodes and durable signers.

#[path = "../../consensus/tests/support/potb.rs"]
mod support;

use keystore::{DurableSigner, SigningContext};
use node::{
    network::{NetworkNode, StaticNetwork},
    network_wire::{NetworkMessage, decode_exchange, encode_exchange},
    observer::ObserverNode,
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use types::Hash256;

const TARGET: u64 = 6;
const PARTITION_STEPS: u64 = 8;
const FAULT_STEPS: u64 = 40;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    path: PathBuf,
    network: StaticNetwork,
}
impl Fixture {
    fn new(potb: bool) -> Self {
        let (profile, keys) = support::fixture();
        let network = if potb {
            StaticNetwork::with_potb(profile, keys).unwrap()
        } else {
            StaticNetwork::new(profile.genesis().clone(), keys).unwrap()
        };
        let path = std::env::temp_dir().join(format!(
            "astrolune-hostile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        for seed in 1..=4 {
            let directory = path.join(seed.to_string());
            std::fs::create_dir(&directory).unwrap();
            drop(
                DurableSigner::create_protected(
                    directory.join("signing.journal"),
                    SigningContext {
                        chain_id: network.chain_id(),
                        genesis: network.genesis_hash(),
                    },
                    [seed; 32],
                )
                .unwrap(),
            );
        }
        Self { path, network }
    }
    fn open(&self, index: usize) -> NetworkNode {
        let seed = u8::try_from(index + 1).unwrap();
        let directory = self.path.join(seed.to_string());
        let signer = DurableSigner::open(
            directory.join("signing.journal"),
            SigningContext {
                chain_id: self.network.chain_id(),
                genesis: self.network.genesis_hash(),
            },
            [seed; 32],
        )
        .unwrap();
        NetworkNode::open(
            self.network.clone(),
            &directory,
            signer,
            Duration::from_millis(100),
        )
        .unwrap()
    }
    fn restart(&self, nodes: &mut Vec<NetworkNode>, index: usize) {
        let before = *nodes[index].storage().checkpoint().unwrap();
        drop(nodes.remove(index));
        nodes.insert(index, self.open(index));
        assert_eq!(nodes[index].storage().checkpoint(), Some(&before));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self.path.canonicalize().unwrap();
        assert_eq!(
            path.parent(),
            Some(std::env::temp_dir().canonicalize().unwrap().as_path())
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}

struct Random(u64);
impl Random {
    fn choose(&mut self, limit: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % u64::try_from(limit).unwrap()).unwrap()
    }
    fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let other = self.choose(index + 1);
            values.swap(index, other);
        }
    }
}

struct Packet {
    destination: usize,
    due: u64,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Schedule {
    pending: Vec<Packet>,
    dropped: usize,
    delayed: usize,
    duplicated: usize,
    attacked: usize,
    rounds: u32,
}
impl std::fmt::Debug for Schedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Schedule")
            .field("pending", &self.pending.len())
            .field("dropped", &self.dropped)
            .field("delayed", &self.delayed)
            .field("duplicated", &self.duplicated)
            .field("attacked", &self.attacked)
            .field("rounds", &self.rounds)
            .finish()
    }
}

// Corrupt authenticated fields without changing framing; no private node state is touched.
fn corrupt(message: &mut NetworkMessage) {
    match message {
        NetworkMessage::Proposal { envelope, .. } => envelope.signature[0] ^= 1,
        NetworkMessage::Vote(vote) => vote.signature[0] ^= 1,
        NetworkMessage::VrfContribution { height, .. } => *height += 100,
        NetworkMessage::Finalized { block, .. } | NetworkMessage::ValidValue { block, .. } => {
            block.header.state_root = Hash256::ZERO;
        }
        _ => unreachable!("this fixture has no application or admission gossip"),
    }
}

impl Schedule {
    fn collect(
        &mut self,
        nodes: &mut [NetworkNode],
        network: &StaticNetwork,
        random: &mut Random,
        step: u64,
    ) {
        for destination in 0..nodes.len() {
            if nodes[destination].request().height >= TARGET {
                continue;
            }
            for source in 0..nodes.len() {
                if source == destination {
                    continue;
                }
                if step < PARTITION_STEPS && source / 2 != destination / 2 {
                    self.dropped += 1;
                    continue;
                }
                let bytes = nodes[source].respond(nodes[destination].request()).unwrap();
                let mut messages = decode_exchange(network.genesis_hash(), &bytes).unwrap();
                if step < FAULT_STEPS && !messages.is_empty() {
                    if random.choose(5) == 0 {
                        self.dropped += 1;
                        continue;
                    }
                    random.shuffle(&mut messages);
                    let mut forged = messages[0].clone();
                    corrupt(&mut forged);
                    let before = *nodes[destination].storage().checkpoint().unwrap();
                    nodes[destination]
                        .receive(&encode_exchange(network.genesis_hash(), &[forged]).unwrap())
                        .unwrap();
                    assert_eq!(nodes[destination].storage().checkpoint(), Some(&before));
                    self.attacked += 1;
                }
                let bytes = encode_exchange(network.genesis_hash(), &messages).unwrap();
                let delay = if step < FAULT_STEPS {
                    u64::try_from(random.choose(8)).unwrap()
                } else {
                    0
                };
                self.delayed += usize::from(delay != 0);
                if step < FAULT_STEPS && random.choose(4) == 0 {
                    self.pending.push(Packet {
                        destination,
                        due: step + delay + 1,
                        bytes: bytes.clone(),
                    });
                    self.duplicated += 1;
                }
                self.pending.push(Packet {
                    destination,
                    due: step + delay,
                    bytes,
                });
            }
        }
        // Twelve directed routes, at most eight ticks of delay and one duplicate per route.
        assert!(self.pending.len() <= 216);
    }

    fn deliver(&mut self, nodes: &mut [NetworkNode], random: &mut Random, step: u64) {
        random.shuffle(&mut self.pending);
        let mut waiting = Vec::new();
        for packet in self.pending.drain(..) {
            if packet.due <= step {
                nodes[packet.destination].receive(&packet.bytes).unwrap();
            } else {
                waiting.push(packet);
            }
        }
        self.pending = waiting;
    }
}

// Compare every newly published prefix, including heights passed by sequential catch-up.
fn check_safety(
    nodes: &[NetworkNode],
    checked: &mut [u64; 4],
    history: &mut BTreeMap<u64, Hash256>,
) {
    for (index, node) in nodes.iter().enumerate() {
        let checkpoint = node.storage().checkpoint().unwrap();
        assert!(
            checkpoint.height >= checked[index],
            "committed height regressed"
        );
        for height in checked[index] + 1..=checkpoint.height {
            let (block, _) = node.storage().read_finalized(height).unwrap().unwrap();
            let hash = block.header.compute_hash();
            if let Some(previous) = history.insert(height, hash) {
                assert_eq!(previous, hash, "conflicting finality at height {height}");
            }
        }
        checked[index] = checkpoint.height;
    }
}

fn run(potb: bool, seed: u64) -> Schedule {
    let fixture = Fixture::new(potb);
    let mut nodes: Vec<_> = (0..4).map(|index| fixture.open(index)).collect();
    let mut random = Random(seed);
    let mut schedule = Schedule::default();
    let mut history = BTreeMap::new();
    let mut checked = [0; 4];
    let mut restarted_after_commit = false;
    let now = Instant::now();
    for step in 0..400 {
        if step == 4 {
            fixture.restart(&mut nodes, 2);
        }
        if !restarted_after_commit && nodes[1].request().height >= 3 {
            fixture.restart(&mut nodes, 1);
            restarted_after_commit = true;
        }
        schedule.collect(&mut nodes, &fixture.network, &mut random, step);
        schedule.deliver(&mut nodes, &mut random, step);
        let mut order = [0, 1, 2, 3];
        random.shuffle(&mut order);
        for index in order {
            if nodes[index].request().height < TARGET {
                // Independent monotonic clocks with fixed bounded skew.
                let skew = u64::try_from(index).unwrap() * 3;
                nodes[index]
                    .tick(now + Duration::from_millis(step * 20 + skew))
                    .unwrap();
                schedule.rounds = schedule.rounds.max(nodes[index].round());
            }
        }
        check_safety(&nodes, &mut checked, &mut history);
        if step < PARTITION_STEPS {
            assert_eq!(
                checked, [0; 4],
                "a partition cannot replace missing VRF proofs"
            );
        }
        if nodes.iter().all(|node| node.request().height == TARGET) {
            break;
        }
    }
    assert_eq!(
        checked,
        [TARGET - 1; 4],
        "potb={potb}, seed={seed}, {schedule:?}"
    );
    assert!(restarted_after_commit);
    assert!(schedule.dropped > 0 && schedule.delayed > 0 && schedule.duplicated > 0);
    assert!(schedule.attacked > 0);
    assert!(
        schedule.rounds > 0,
        "the schedule must exercise round recovery"
    );
    let checkpoint = *nodes[0].storage().checkpoint().unwrap();
    for node in &nodes {
        assert_eq!(node.storage().checkpoint(), Some(&checkpoint));
        fixture.network.verify_storage(node.storage()).unwrap();
    }
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    while observer.request().height < TARGET {
        let response = nodes[0].respond(observer.request()).unwrap();
        observer.receive(&response).unwrap();
    }
    assert_eq!(observer.storage().checkpoint(), Some(&checkpoint));
    fixture.network.verify_storage(observer.storage()).unwrap();
    schedule
}

#[test]
fn rotating_profiles_preserve_finality_and_recover_after_hostile_delivery() {
    for potb in [false, true] {
        let result = run(potb, 0x1234_5678_9abc_def0);
        eprintln!("potb={potb}: {result:?}");
    }
}

#[test]
#[ignore = "explicit multi-seed schedule campaign; run with --release --ignored"]
fn extended_rotating_schedule_campaign() {
    for seed in 1..=12 {
        for potb in [false, true] {
            let result = run(potb, seed);
            eprintln!("potb={potb}, seed={seed}: {result:?}");
        }
    }
}
