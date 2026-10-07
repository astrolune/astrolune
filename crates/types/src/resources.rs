// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Four consensus-metered resource classes.

/// Four consensus-metered resource classes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Resources {
    /// Deterministic compute units.
    pub compute: u64,
    /// Peak and allocated memory units.
    pub memory: u64,
    /// State read/write units.
    pub io: u64,
    /// Encoded network bytes.
    pub bandwidth: u64,
}

impl Resources {
    /// All-zero resources.
    pub const ZERO: Self = Self {
        compute: 0,
        memory: 0,
        io: 0,
        bandwidth: 0,
    };

    /// Returns `true` if every resource class is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.compute == 0 && self.memory == 0 && self.io == 0 && self.bandwidth == 0
    }

    /// Returns `true` if no resource class exceeds `other`.
    #[must_use]
    pub fn fits_in(self, other: Self) -> bool {
        self.compute <= other.compute
            && self.memory <= other.memory
            && self.io <= other.io
            && self.bandwidth <= other.bandwidth
    }

    /// Saturating addition of two resource sets.
    #[must_use]
    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            compute: self.compute.saturating_add(other.compute),
            memory: self.memory.saturating_add(other.memory),
            io: self.io.saturating_add(other.io),
            bandwidth: self.bandwidth.saturating_add(other.bandwidth),
        }
    }

    /// Checked addition of two resource sets.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            compute: self.compute.checked_add(other.compute)?,
            memory: self.memory.checked_add(other.memory)?,
            io: self.io.checked_add(other.io)?,
            bandwidth: self.bandwidth.checked_add(other.bandwidth)?,
        })
    }

    /// Scalar multiplication of all resource classes.
    #[must_use]
    pub fn checked_mul(self, scalar: u64) -> Option<Self> {
        Some(Self {
            compute: self.compute.checked_mul(scalar)?,
            memory: self.memory.checked_mul(scalar)?,
            io: self.io.checked_mul(scalar)?,
            bandwidth: self.bandwidth.checked_mul(scalar)?,
        })
    }

    /// Returns the total charge at the supplied per-class unit prices.
    ///
    /// Returns `None` if any product or the total exceeds `u64::MAX`.
    #[must_use]
    pub fn checked_cost(self, prices: Self) -> Option<u64> {
        self.compute
            .checked_mul(prices.compute)?
            .checked_add(self.memory.checked_mul(prices.memory)?)?
            .checked_add(self.io.checked_mul(prices.io)?)?
            .checked_add(self.bandwidth.checked_mul(prices.bandwidth)?)
    }

    /// Returns the number of non-zero resource classes.
    #[must_use]
    pub fn count(self) -> u32 {
        u32::from(self.compute != 0)
            + u32::from(self.memory != 0)
            + u32::from(self.io != 0)
            + u32::from(self.bandwidth != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_all_zeros() {
        assert!(Resources::ZERO.is_zero());
    }

    #[test]
    fn fits_in() {
        let small = Resources {
            compute: 1,
            memory: 2,
            io: 3,
            bandwidth: 4,
        };
        let large = Resources {
            compute: 5,
            memory: 5,
            io: 5,
            bandwidth: 5,
        };
        assert!(small.fits_in(large));
        assert!(!large.fits_in(small));
    }

    #[test]
    fn checked_add() {
        let a = Resources {
            compute: 1,
            memory: 2,
            io: 3,
            bandwidth: 4,
        };
        let b = Resources {
            compute: 5,
            memory: 6,
            io: 7,
            bandwidth: 8,
        };
        let sum = a.checked_add(b).unwrap();
        assert_eq!(
            sum,
            Resources {
                compute: 6,
                memory: 8,
                io: 10,
                bandwidth: 12
            }
        );
    }

    #[test]
    fn checked_add_overflow() {
        let max = Resources {
            compute: u64::MAX,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        let one = Resources {
            compute: 1,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        assert!(max.checked_add(one).is_none());
    }

    #[test]
    fn saturating_add() {
        let a = Resources {
            compute: u64::MAX,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        let b = Resources {
            compute: 1,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        let sum = a.saturating_add(b);
        assert_eq!(sum.compute, u64::MAX);
    }

    #[test]
    fn checked_mul() {
        let r = Resources {
            compute: 3,
            memory: 4,
            io: 5,
            bandwidth: 6,
        };
        let product = r.checked_mul(2).unwrap();
        assert_eq!(
            product,
            Resources {
                compute: 6,
                memory: 8,
                io: 10,
                bandwidth: 12
            }
        );
    }

    #[test]
    fn checked_mul_overflow() {
        let r = Resources {
            compute: u64::MAX,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        assert!(r.checked_mul(2).is_none());
    }

    #[test]
    fn count() {
        let none = Resources::ZERO;
        assert_eq!(none.count(), 0);

        let partial = Resources {
            compute: 1,
            memory: 0,
            io: 3,
            bandwidth: 0,
        };
        assert_eq!(partial.count(), 2);

        let all = Resources {
            compute: 1,
            memory: 1,
            io: 1,
            bandwidth: 1,
        };
        assert_eq!(all.count(), 4);
    }

    #[test]
    fn fits_in_reflexive() {
        let r = Resources {
            compute: 100,
            memory: 200,
            io: 300,
            bandwidth: 400,
        };
        assert!(r.fits_in(r));
    }

    #[test]
    fn fits_in_transitive() {
        let a = Resources {
            compute: 1,
            memory: 2,
            io: 3,
            bandwidth: 4,
        };
        let b = Resources {
            compute: 5,
            memory: 6,
            io: 7,
            bandwidth: 8,
        };
        let c = Resources {
            compute: 9,
            memory: 10,
            io: 11,
            bandwidth: 12,
        };
        assert!(a.fits_in(b));
        assert!(b.fits_in(c));
        assert!(a.fits_in(c));
    }

    #[test]
    fn checked_add_none_on_overflow() {
        let max = Resources {
            compute: u64::MAX,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        let one = Resources {
            compute: 1,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        assert!(max.checked_add(one).is_none());

        let a = Resources {
            compute: u64::MAX,
            memory: u64::MAX,
            io: 0,
            bandwidth: 0,
        };
        let b = Resources {
            compute: 0,
            memory: 0,
            io: 1,
            bandwidth: 0,
        };
        assert!(a.checked_add(b).is_some());
    }

    #[test]
    fn checked_add_sum_correct() {
        let values: &[(u64, u64)] = &[(0, 0), (1, 2), (100, 200), (u64::MAX - 1, 1)];
        for &(a, b) in values {
            let ra = Resources {
                compute: a,
                memory: 0,
                io: 0,
                bandwidth: 0,
            };
            let rb = Resources {
                compute: b,
                memory: 0,
                io: 0,
                bandwidth: 0,
            };
            if let Some(sum) = ra.checked_add(rb) {
                assert_eq!(sum.compute, a.wrapping_add(b));
            }
        }
    }

    #[test]
    fn checked_mul_none_on_overflow() {
        let big = Resources {
            compute: u64::MAX,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        assert!(big.checked_mul(2).is_none());
        assert!(big.checked_mul(1).is_some());
        assert!(big.checked_mul(0).is_some());
    }

    #[test]
    fn saturating_add_never_exceeds_max() {
        let a = Resources {
            compute: u64::MAX,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        let b = Resources {
            compute: 1,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        let sum = a.saturating_add(b);
        assert_eq!(sum.compute, u64::MAX);
    }

    #[test]
    fn count_correct() {
        assert_eq!(Resources::ZERO.count(), 0);
        assert_eq!(
            Resources {
                compute: 1,
                memory: 0,
                io: 0,
                bandwidth: 0
            }
            .count(),
            1
        );
        assert_eq!(
            Resources {
                compute: 1,
                memory: 1,
                io: 0,
                bandwidth: 0
            }
            .count(),
            2
        );
        assert_eq!(
            Resources {
                compute: 1,
                memory: 1,
                io: 1,
                bandwidth: 0
            }
            .count(),
            3
        );
        assert_eq!(
            Resources {
                compute: 1,
                memory: 1,
                io: 1,
                bandwidth: 1
            }
            .count(),
            4
        );
    }

    #[test]
    fn checked_add_commutative() {
        let a = Resources {
            compute: 10,
            memory: 20,
            io: 30,
            bandwidth: 40,
        };
        let b = Resources {
            compute: 5,
            memory: 15,
            io: 25,
            bandwidth: 35,
        };
        assert_eq!(a.checked_add(b), b.checked_add(a));
    }

    #[test]
    fn checked_add_associative() {
        let a = Resources {
            compute: 1,
            memory: 2,
            io: 3,
            bandwidth: 4,
        };
        let b = Resources {
            compute: 5,
            memory: 6,
            io: 7,
            bandwidth: 8,
        };
        let c = Resources {
            compute: 9,
            memory: 10,
            io: 11,
            bandwidth: 12,
        };
        let ab_c = a.checked_add(b).and_then(|r| r.checked_add(c));
        let a_bc = b.checked_add(c).and_then(|r| a.checked_add(r));
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn checked_add_identity() {
        let a = Resources {
            compute: 42,
            memory: 100,
            io: 200,
            bandwidth: 300,
        };
        assert_eq!(a.checked_add(Resources::ZERO), Some(a));
        assert_eq!(Resources::ZERO.checked_add(a), Some(a));
    }

    #[test]
    fn checked_mul_distributive_over_add() {
        let a = Resources {
            compute: 2,
            memory: 3,
            io: 4,
            bandwidth: 5,
        };
        let b = Resources {
            compute: 6,
            memory: 7,
            io: 8,
            bandwidth: 9,
        };
        let scalar = 3u64;
        let lhs = a.checked_add(b).and_then(|r| r.checked_mul(scalar));
        let rhs = a
            .checked_mul(scalar)
            .and_then(|ra| b.checked_mul(scalar).map(|rb| ra.checked_add(rb)))
            .flatten();
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn checked_mul_zero() {
        let a = Resources {
            compute: 100,
            memory: 200,
            io: 300,
            bandwidth: 400,
        };
        assert_eq!(a.checked_mul(0), Some(Resources::ZERO));
    }

    #[test]
    fn checked_mul_one() {
        let a = Resources {
            compute: 100,
            memory: 200,
            io: 300,
            bandwidth: 400,
        };
        assert_eq!(a.checked_mul(1), Some(a));
    }

    #[test]
    fn saturating_add_associative() {
        let a = Resources {
            compute: u64::MAX - 10,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        let b = Resources {
            compute: 5,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        let c = Resources {
            compute: 10,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        let ab_c = a.saturating_add(b).saturating_add(c);
        let a_bc = a.saturating_add(b.saturating_add(c));
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn fits_in_antisymmetric() {
        let a = Resources {
            compute: 1,
            memory: 2,
            io: 3,
            bandwidth: 4,
        };
        let b = Resources {
            compute: 5,
            memory: 6,
            io: 7,
            bandwidth: 8,
        };
        assert!(a.fits_in(b));
        assert!(!b.fits_in(a));
    }

    #[test]
    fn fits_in_transitive_closure() {
        let a = Resources {
            compute: 1,
            memory: 1,
            io: 1,
            bandwidth: 1,
        };
        let b = Resources {
            compute: 2,
            memory: 2,
            io: 2,
            bandwidth: 2,
        };
        let c = Resources {
            compute: 3,
            memory: 3,
            io: 3,
            bandwidth: 3,
        };
        assert!(a.fits_in(b));
        assert!(b.fits_in(c));
        assert!(a.fits_in(c));
    }

    #[test]
    fn zero_fits_in_everything() {
        let any = Resources {
            compute: u64::MAX,
            memory: u64::MAX,
            io: u64::MAX,
            bandwidth: u64::MAX,
        };
        assert!(Resources::ZERO.fits_in(any));
    }

    #[test]
    fn nothing_fits_in_zero_except_zero() {
        let nonzero = Resources {
            compute: 1,
            memory: 0,
            io: 0,
            bandwidth: 0,
        };
        assert!(!nonzero.fits_in(Resources::ZERO));
        assert!(Resources::ZERO.fits_in(Resources::ZERO));
    }

    #[test]
    fn count_popcount_equivalent() {
        let r = Resources {
            compute: 42,
            memory: 0,
            io: 99,
            bandwidth: 0,
        };
        assert_eq!(r.count(), 2);
    }
}
