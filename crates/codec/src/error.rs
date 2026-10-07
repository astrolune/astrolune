// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical decoding failures.

/// Canonical decoding failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Input ended before the declared value was complete.
    Truncated,
    /// A length computation overflowed the host index type.
    LengthOverflow,
    /// Input exceeded a protocol bound.
    LimitExceeded,
    /// Input has more than one representation for the same value.
    NonCanonical,
    /// Input uses an unsupported version or mandatory feature.
    Unsupported,
    /// Bytes remained after decoding one complete value.
    TrailingBytes,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "input truncated"),
            Self::LengthOverflow => write!(f, "length overflow"),
            Self::LimitExceeded => write!(f, "protocol limit exceeded"),
            Self::NonCanonical => write!(f, "non-canonical encoding"),
            Self::Unsupported => write!(f, "unsupported version or feature"),
            Self::TrailingBytes => write!(f, "trailing bytes after value"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_variants() {
        assert_ne!(DecodeError::Truncated.to_string(), "");
        assert_ne!(DecodeError::LengthOverflow.to_string(), "");
        assert_ne!(DecodeError::LimitExceeded.to_string(), "");
        assert_ne!(DecodeError::NonCanonical.to_string(), "");
        assert_ne!(DecodeError::Unsupported.to_string(), "");
        assert_ne!(DecodeError::TrailingBytes.to_string(), "");
    }

    #[test]
    fn variants_are_distinct() {
        let errors = [
            DecodeError::Truncated,
            DecodeError::LengthOverflow,
            DecodeError::LimitExceeded,
            DecodeError::NonCanonical,
            DecodeError::Unsupported,
            DecodeError::TrailingBytes,
        ];
        for (i, a) in errors.iter().enumerate() {
            for (j, b) in errors.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }
}
