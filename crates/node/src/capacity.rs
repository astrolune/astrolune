// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Adaptive block-capacity management.

use types::Resources;

/// Default initial capacity for a newly created node.
pub const DEFAULT_CAPACITY: Resources = Resources {
    compute: 1000,
    memory: 1024,
    io: 256,
    bandwidth: 1024,
};

/// Minimum capacity floor — never scale below this.
pub const MIN_CAPACITY: Resources = Resources {
    compute: 1,
    memory: 1,
    io: 1,
    bandwidth: 1,
};

/// Number of observations retained in the rolling window for adaptive sizing.
pub const LATENCY_WINDOW: usize = 16;

/// Finalized performance observations used by adaptive block sizing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityObservation {
    /// Measured resources consumed by a finalized block.
    pub used: Resources,
    /// Whether the block met the finality latency target.
    pub within_latency_target: bool,
}

/// Deterministically adjusts block limits from a finalized observation window.
pub trait CapacityController {
    /// Computes the next consensus-visible capacity. Local live measurements may
    /// inform proposals, but only finalized, quantized observations may change it.
    fn next_capacity(&self, current: Resources, observations: &[CapacityObservation]) -> Resources;
}

/// Adaptive controller that scales block capacity based on finalized observations.
///
/// Maintains a rolling window of [`CapacityObservation`]s. After the window is
/// full the controller computes the average used resources and scales up (110%)
/// if every class is within target or down (90%) if any class exceeds it, never
/// dropping below [`MIN_CAPACITY`].
#[derive(Clone, Debug)]
pub struct AdaptiveCapacityController {
    #[allow(dead_code)]
    initial: Resources,
    window_size: usize,
}

impl AdaptiveCapacityController {
    /// Creates a new controller with the given initial capacity and window size.
    #[must_use]
    pub fn new(initial: Resources, window_size: usize) -> Self {
        Self {
            initial,
            window_size,
        }
    }

    /// Computes the average used resources across a set of observations.
    fn average_used(observations: &[CapacityObservation]) -> Resources {
        if observations.is_empty() {
            return Resources::ZERO;
        }
        let count = observations.len() as u64;
        let mut sum = Resources::ZERO;
        for obs in observations {
            sum = sum.saturating_add(obs.used);
        }
        Resources {
            compute: sum.compute / count,
            memory: sum.memory / count,
            io: sum.io / count,
            bandwidth: sum.bandwidth / count,
        }
    }

    /// Scales a resource value by the given percentage using checked integer math.
    ///
    /// `percent` is expressed as hundredths (e.g. 110 = 110%). The result is
    /// `(value * percent) / 100`, floored to at least `floor` or clamped on
    /// overflow.
    fn scale(value: u64, percent: u64, floor: u64) -> u64 {
        value
            .checked_mul(percent)
            .map_or(u64::MAX, |v| v / 100)
            .max(floor)
    }
}

impl CapacityController for AdaptiveCapacityController {
    fn next_capacity(&self, current: Resources, observations: &[CapacityObservation]) -> Resources {
        let usable = if observations.len() > self.window_size {
            &observations[observations.len() - self.window_size..]
        } else {
            observations
        };

        if usable.is_empty() {
            return current;
        }

        let avg = Self::average_used(usable);

        let scale_up = avg.fits_in(current);

        if scale_up {
            Resources {
                compute: Self::scale(current.compute, 110, MIN_CAPACITY.compute),
                memory: Self::scale(current.memory, 110, MIN_CAPACITY.memory),
                io: Self::scale(current.io, 110, MIN_CAPACITY.io),
                bandwidth: Self::scale(current.bandwidth, 110, MIN_CAPACITY.bandwidth),
            }
        } else {
            Resources {
                compute: Self::scale(current.compute, 90, MIN_CAPACITY.compute),
                memory: Self::scale(current.memory, 90, MIN_CAPACITY.memory),
                io: Self::scale(current.io, 90, MIN_CAPACITY.io),
                bandwidth: Self::scale(current.bandwidth, 90, MIN_CAPACITY.bandwidth),
            }
        }
    }
}

/// Node orchestration failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeError {
    /// A required subsystem is not ready.
    NotReady,
    /// A finalized commitment disagrees with deterministic execution.
    CommitmentMismatch,
    /// A bounded queue or configured resource ceiling was reached.
    CapacityExceeded,
    /// Finalized storage rejected or could not persist the batch.
    Storage(storage::StorageError),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "required subsystem not ready"),
            Self::CommitmentMismatch => {
                write!(
                    f,
                    "finalized commitment disagrees with deterministic execution"
                )
            }
            Self::CapacityExceeded => {
                write!(
                    f,
                    "bounded queue or configured resource ceiling was reached"
                )
            }
            Self::Storage(error) => write!(f, "finalized storage: {error}"),
        }
    }
}

impl std::error::Error for NodeError {}
