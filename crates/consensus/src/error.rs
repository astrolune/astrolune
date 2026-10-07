// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Consensus-level validation failures.

/// Consensus-level validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusError {
    /// Membership is empty, duplicated, zero-powered, oversized, or overflows.
    InvalidCommittee,
    /// Two authenticated values occupy the same voting slot.
    Equivocation,
    /// A certificate is malformed or lacks sufficient voting power.
    InvalidCertificate,
    /// The signer is not in the active committee.
    UnknownVoter,
    /// A validator voted more than once in one phase and round.
    DuplicateVote,
    /// A signature or `VRF` proof is invalid.
    InvalidProof,
    /// Height, round, phase, or lock rules were violated.
    InvalidTransition,
}

impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCommittee => write!(f, "invalid committee membership or power"),
            Self::Equivocation => write!(f, "conflicting authenticated votes"),
            Self::InvalidCertificate => write!(f, "invalid finality certificate"),
            Self::UnknownVoter => write!(f, "voter is not in the active committee"),
            Self::DuplicateVote => {
                write!(f, "validator voted more than once in one phase and round")
            }
            Self::InvalidProof => write!(f, "signature or VRF proof is invalid"),
            Self::InvalidTransition => {
                write!(f, "height, round, phase, or lock rules were violated")
            }
        }
    }
}

impl std::error::Error for ConsensusError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        assert_eq!(
            format!("{}", ConsensusError::UnknownVoter),
            "voter is not in the active committee"
        );
        assert_eq!(
            format!("{}", ConsensusError::DuplicateVote),
            "validator voted more than once in one phase and round"
        );
        assert_eq!(
            format!("{}", ConsensusError::InvalidProof),
            "signature or VRF proof is invalid"
        );
        assert_eq!(
            format!("{}", ConsensusError::InvalidTransition),
            "height, round, phase, or lock rules were violated"
        );
    }

    #[test]
    fn is_std_error() {
        let err: &dyn std::error::Error = &ConsensusError::UnknownVoter;
        assert!(err.source().is_none());
    }
}
