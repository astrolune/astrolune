// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Consensus weight and quorum calculations.

/// Consensus weight derived from finalized `PoTB` state.
///
/// Fixed-point arithmetic is mandatory; floating point must never influence
/// committee selection or quorum calculations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PotbWeight(pub u128);

/// Returns the minimum power that is strictly greater than two thirds.
#[must_use]
pub const fn quorum_power(total_power: u128) -> u128 {
    (total_power / 3) * 2 + (total_power % 3) * 2 / 3 + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_is_strictly_greater_than_two_thirds() {
        assert_eq!(quorum_power(100), 67);
        assert_eq!(quorum_power(3), 3);
        assert_eq!(quorum_power(0), 1);
    }

    #[test]
    fn quorum_does_not_saturate_for_large_genesis_weights() {
        assert_eq!(quorum_power(u128::MAX), (u128::MAX / 3) * 2 + 1);
        for total in [
            1,
            2,
            3,
            u128::MAX / 2,
            u128::MAX - 2,
            u128::MAX - 1,
            u128::MAX,
        ] {
            let expected = total - total / 3 + u128::from(total % 3 == 0);
            assert_eq!(quorum_power(total), expected);
        }
    }
}
