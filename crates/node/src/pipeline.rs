// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Pipeline stages for height-overlapping block processing.

/// Overlappable stages for height `h` and `h + 1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineStage {
    /// Receive or reconstruct an ordered proposal.
    Propagation,
    /// Collect prevotes and precommits without mutating canonical state.
    Voting,
    /// Execute the consensus-fixed transaction order on a snapshot.
    Execution,
    /// Publish deferred state changes after execution and finality validation.
    Commit,
}
