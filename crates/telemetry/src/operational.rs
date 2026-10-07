// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Fixed-cardinality operational counters. These values never enter protocol decisions.

use std::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

/// Fixed metric slots; peer names, remote input and keys cannot create labels.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum NodeMetric {
    /// Durable head height.
    FinalizedHeight,
    /// Blocks advanced since process start, including catch-up.
    FinalizedBlocks,
    /// Accepted incoming sessions currently open.
    IncomingSessions,
    /// Authenticated outgoing sessions currently open.
    OutgoingSessions,
    /// Outgoing TCP/TLS connections successfully established.
    ConnectionsOpened,
    /// Outgoing connection/handshake failures.
    ConnectionFailures,
    /// Failed packet exchanges, including orderly remote rotation.
    ExchangeFailures,
    /// Successful outgoing exchanges.
    Exchanges,
    /// Snapshots dropped because the bounded inbound mailbox was full.
    QueueDrops,
    /// Invalid consensus or sync input rejected by the node.
    RejectedMessages,
    /// Configured and discovered remote routing candidates.
    KnownPeers,
    /// Connections refused at the incoming session bound.
    SessionLimitDrops,
    /// RPC submissions accepted by local admission.
    TransactionsAccepted,
    /// RPC submissions rejected by local admission.
    TransactionsRejected,
    /// Local durability or signing failures requiring recovery.
    LocalFailures,
}
const DESCRIPTORS: [(&str, &str); 15] = [
    ("finalized_height", "gauge"),
    ("finalized_blocks_total", "counter"),
    ("p2p_incoming_sessions", "gauge"),
    ("p2p_outgoing_sessions", "gauge"),
    ("p2p_connections_opened_total", "counter"),
    ("p2p_connection_failures_total", "counter"),
    ("p2p_exchange_failures_total", "counter"),
    ("p2p_exchanges_total", "counter"),
    ("p2p_queue_drops_total", "counter"),
    ("p2p_rejected_messages_total", "counter"),
    ("p2p_known_peers", "gauge"),
    ("p2p_session_limit_drops_total", "counter"),
    ("rpc_transactions_accepted_total", "counter"),
    ("rpc_transactions_rejected_total", "counter"),
    ("local_failures_total", "counter"),
];

/// Process-local metrics with bounded memory and nonblocking saturating updates.
pub struct NodeMetrics {
    values: [AtomicU64; DESCRIPTORS.len()],
    started: Instant,
    last_finalized: AtomicU64,
    observer: bool,
}
impl NodeMetrics {
    /// Records the recovered head without counting historical blocks as process activity.
    #[must_use]
    pub fn new(finalized_height: u64, observer: bool) -> Self {
        let value = Self {
            values: std::array::from_fn(|_| AtomicU64::new(0)),
            started: Instant::now(),
            last_finalized: AtomicU64::new(0),
            observer,
        };
        value.set(NodeMetric::FinalizedHeight, finalized_height);
        value
    }
    /// Sets a local gauge.
    pub fn set(&self, metric: NodeMetric, value: u64) {
        self.values[metric as usize].store(value, Ordering::Relaxed);
    }
    /// Saturating addition used for local counters and session gauges.
    pub fn add(&self, metric: NodeMetric, value: u64) {
        let _ =
            self.values[metric as usize].try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(old.saturating_add(value))
            });
    }
    /// Saturating subtraction for session completion, including error paths.
    pub fn subtract(&self, metric: NodeMetric, value: u64) {
        let _ =
            self.values[metric as usize].try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(old.saturating_sub(value))
            });
    }
    /// Reads a best-effort atomic observation.
    #[must_use]
    pub fn get(&self, metric: NodeMetric) -> u64 {
        self.values[metric as usize].load(Ordering::Relaxed)
    }
    /// Reports durable advancement; observations never change the node's state.
    pub fn finalized(&self, height: u64) {
        let previous =
            self.values[NodeMetric::FinalizedHeight as usize].swap(height, Ordering::Relaxed);
        if height > previous {
            self.add(NodeMetric::FinalizedBlocks, height - previous);
            self.last_finalized
                .store(self.started.elapsed().as_secs(), Ordering::Relaxed);
        }
    }
    /// Emits bounded Prometheus text with stable names and no remote-controlled labels.
    #[must_use]
    pub fn prometheus(&self) -> String {
        let mut output = String::with_capacity(3000);
        for (index, (name, kind)) in DESCRIPTORS.iter().enumerate() {
            let value = self.values[index].load(Ordering::Relaxed);
            let _ = writeln!(
                output,
                "# TYPE astrolune_{name} {kind}\nastrolune_{name} {value}"
            );
        }
        let uptime = self.started.elapsed().as_secs();
        let age = uptime.saturating_sub(self.last_finalized.load(Ordering::Relaxed));
        for (name, value) in [
            ("uptime_seconds", uptime),
            ("finality_age_seconds", age),
            ("observer", u64::from(self.observer)),
        ] {
            let _ = writeln!(
                output,
                "# TYPE astrolune_{name} gauge\nastrolune_{name} {value}"
            );
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metrics_are_bounded_saturating_and_count_only_new_finality() {
        let metrics = NodeMetrics::new(500, true);
        metrics.finalized(503);
        metrics.finalized(503);
        assert_eq!(metrics.get(NodeMetric::FinalizedBlocks), 3);
        metrics.add(NodeMetric::ConnectionsOpened, u64::MAX);
        metrics.add(NodeMetric::ConnectionsOpened, 1);
        assert_eq!(metrics.get(NodeMetric::ConnectionsOpened), u64::MAX);
        metrics.subtract(NodeMetric::IncomingSessions, 1);
        assert_eq!(metrics.get(NodeMetric::IncomingSessions), 0);
        let text = metrics.prometheus();
        assert!(text.contains("astrolune_finalized_height 503\n"));
        assert!(text.contains("astrolune_observer 1\n"));
        assert!(text.len() < 4096);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..1000 {
                        metrics.add(NodeMetric::Exchanges, 1);
                    }
                });
            }
        });
        assert_eq!(metrics.get(NodeMetric::Exchanges), 4000);
    }
}
