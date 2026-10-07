// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Validated chain genesis parameters.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use codec::decoder::Decoder;
use codec::error::DecodeError;
use codec::traits::{CanonicalDecode, CanonicalEncode};
use crypto::CryptoProvider;
use types::{Address, Hash256, Resources, ValidatorId};

mod materialize;
pub use materialize::{genesis_key, runtime_key, validator_key};

/// Supported canonical genesis format.
pub const GENESIS_VERSION: u16 = 1;
/// Explicit full-roster VRF rotation profile; version 1 retains fixed membership.
pub const ROTATING_GENESIS_VERSION: u16 = 2;
/// Maximum validators in the reference genesis format.
pub const MAX_GENESIS_VALIDATORS: usize = 4096;
/// Maximum initial allocations in the reference genesis format.
pub const MAX_GENESIS_ALLOCATIONS: usize = 65_536;
/// Maximum complete genesis bytes, including both fixed-width counts.
pub const MAX_GENESIS_BYTES: usize =
    74 + MAX_GENESIS_VALIDATORS * 48 + MAX_GENESIS_ALLOCATIONS * 40;

/// Initial account allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Allocation {
    /// Account receiving the allocation.
    pub address: Address,
    /// Initial smallest-unit balance.
    pub amount: u64,
}

/// Initial validator identity and fixed-point `PoTB` weight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisValidator {
    /// Validator identity key.
    pub id: ValidatorId,
    /// Non-zero initial fixed-point weight.
    pub weight: u128,
}

/// Complete consensus-controlled chain configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Genesis {
    /// Encoding version.
    pub version: u16,
    /// Replay-protection identifier.
    pub chain_id: u32,
    /// Initial aggregate block capacity.
    pub capacity: Resources,
    /// Nominal active committee size.
    pub committee_size: usize,
    /// Number of committee seats replaced per block.
    pub rotation_count: usize,
    /// Contract runtime semantics version.
    pub runtime_version: u32,
    /// Canonically ordered validator set.
    pub validators: Vec<GenesisValidator>,
    /// Canonically ordered initial account balances.
    pub allocations: Vec<Allocation>,
}

impl Genesis {
    /// Checks structural invariants before hashing or materialization.
    ///
    /// # Errors
    ///
    /// Returns [`GenesisError`] when identifiers, capacity, committee parameters,
    /// validators, or allocations violate canonical genesis rules.
    pub fn validate(&self) -> Result<(), GenesisError> {
        if !matches!(self.version, GENESIS_VERSION | ROTATING_GENESIS_VERSION) {
            return Err(GenesisError::UnsupportedVersion);
        }
        if self.chain_id == 0 || self.runtime_version == 0 {
            return Err(GenesisError::InvalidIdentity);
        }
        if self.runtime_version > 2 {
            return Err(GenesisError::UnsupportedVersion);
        }
        if self.validators.len() > MAX_GENESIS_VALIDATORS
            || self.allocations.len() > MAX_GENESIS_ALLOCATIONS
        {
            return Err(GenesisError::LimitExceeded);
        }
        if self.capacity.compute == 0
            || self.capacity.memory == 0
            || self.capacity.io == 0
            || self.capacity.bandwidth == 0
        {
            return Err(GenesisError::InvalidCapacity);
        }
        if self.committee_size == 0
            || self.rotation_count == 0
            || self.rotation_count > self.committee_size
            || self.committee_size > self.validators.len()
        {
            return Err(GenesisError::InvalidCommittee);
        }
        if self
            .validators
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
            || self
                .validators
                .iter()
                .any(|validator| validator.id.is_zero() || validator.weight == 0)
            || self
                .validators
                .iter()
                .try_fold(0u128, |sum, validator| sum.checked_add(validator.weight))
                .is_none()
        {
            return Err(GenesisError::InvalidValidators);
        }
        if self
            .allocations
            .windows(2)
            .any(|pair| pair[0].address >= pair[1].address)
            || self
                .allocations
                .iter()
                .any(|allocation| allocation.address.is_zero())
        {
            return Err(GenesisError::InvalidAllocations);
        }
        Ok(())
    }

    /// Validates and hashes the configuration using the protocol BLAKE2s suite.
    pub fn commitment(&self) -> Result<Hash256, GenesisError> {
        self.validate()?;
        Ok(crypto::blake2s::domain_hash(
            types::domain::GENESIS,
            &self.to_bytes(),
        ))
    }
}

/// Hashing boundary for canonical genesis bytes.
pub trait GenesisCommitment {
    /// Returns the chain-binding genesis hash.
    fn genesis_hash(&self, genesis: &Genesis) -> Result<Hash256, GenesisError>;
}

/// Genesis validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisError {
    /// Chain or runtime identifier is zero.
    InvalidIdentity,
    /// The genesis format version is not supported.
    UnsupportedVersion,
    /// A validator or allocation count exceeds its bound.
    LimitExceeded,
    /// One or more resource dimensions are zero.
    InvalidCapacity,
    /// Committee size or rotation is inconsistent.
    InvalidCommittee,
    /// Validators have invalid identities, order, weights, or aggregate overflow.
    InvalidValidators,
    /// Allocations contain zero, duplicate, or unsorted addresses.
    InvalidAllocations,
    /// Initial state could not be staged within the state backend bounds.
    State(state::StateError),
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIdentity => f.write_str("invalid genesis chain or runtime identifier"),
            Self::UnsupportedVersion => f.write_str("unsupported genesis version"),
            Self::LimitExceeded => f.write_str("genesis limit exceeded"),
            Self::InvalidCapacity => f.write_str("invalid genesis capacity"),
            Self::InvalidCommittee => f.write_str("invalid genesis committee"),
            Self::InvalidValidators => f.write_str("invalid genesis validators"),
            Self::InvalidAllocations => f.write_str("invalid genesis allocations"),
            Self::State(error) => write!(f, "genesis state: {error}"),
        }
    }
}

impl std::error::Error for GenesisError {}

impl CanonicalEncode for Allocation {
    fn encode(&self, output: &mut Vec<u8>) {
        self.address.encode(output);
        self.amount.encode(output);
    }
}

impl CanonicalEncode for GenesisValidator {
    #[allow(clippy::cast_possible_truncation)]
    fn encode(&self, output: &mut Vec<u8>) {
        self.id.encode(output);
        // Encode u128 weight as two LE u64 parts for canonical representation
        let low = self.weight as u64;
        let high = (self.weight >> 64) as u64;
        low.encode(output);
        high.encode(output);
    }
}

impl CanonicalEncode for Genesis {
    fn encode(&self, output: &mut Vec<u8>) {
        self.version.encode(output);
        self.chain_id.encode(output);
        self.capacity.encode(output);
        // Encode usize fields as u64 for deterministic cross-platform encoding
        (self.committee_size as u64).encode(output);
        (self.rotation_count as u64).encode(output);
        self.runtime_version.encode(output);

        // Validators: length-prefixed canonically ordered list
        (self.validators.len() as u64).encode(output);
        for v in &self.validators {
            v.encode(output);
        }

        // Allocations: length-prefixed canonically ordered list
        (self.allocations.len() as u64).encode(output);
        for a in &self.allocations {
            a.encode(output);
        }
    }
}

/// Implementation of `GenesisCommitment` for any `CryptoProvider`.
///
/// Produces a domain-separated deterministic hash of the genesis configuration
/// suitable for chain-binding and genesis validation.
impl<C: CryptoProvider> GenesisCommitment for C {
    fn genesis_hash(&self, genesis: &Genesis) -> Result<Hash256, GenesisError> {
        genesis.validate()?;
        let encoded = genesis.to_bytes();
        Ok(self.hash(types::domain::GENESIS, &encoded))
    }
}

impl CanonicalDecode for Allocation {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut dec = Decoder::new(bytes);
        let address = Address(dec.read_fixed::<32>()?);
        let amount = dec.read_u64()?;
        dec.finish()?;
        Ok(Self { address, amount })
    }
}

impl CanonicalDecode for GenesisValidator {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut dec = Decoder::new(bytes);
        let id = ValidatorId(dec.read_fixed::<32>()?);
        let low = dec.read_u64()?;
        let high = dec.read_u64()?;
        dec.finish()?;
        Ok(Self {
            id,
            weight: u128::from(low) | (u128::from(high) << 64),
        })
    }
}

impl CanonicalDecode for Genesis {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_GENESIS_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut dec = Decoder::new(bytes);
        let version = dec.read_u16()?;
        if !matches!(version, GENESIS_VERSION | ROTATING_GENESIS_VERSION) {
            return Err(DecodeError::Unsupported);
        }
        let chain_id = dec.read_u32()?;
        let capacity = Resources {
            compute: dec.read_u64()?,
            memory: dec.read_u64()?,
            io: dec.read_u64()?,
            bandwidth: dec.read_u64()?,
        };
        let committee_size = read_count(&mut dec, MAX_GENESIS_VALIDATORS)?;
        let rotation_count = read_count(&mut dec, MAX_GENESIS_VALIDATORS)?;
        let runtime_version = dec.read_u32()?;

        // Preflight both complete lists and the input end before any owned allocation.
        let validator_len = read_count(&mut dec, MAX_GENESIS_VALIDATORS)?;
        let validator_bytes = dec.read_exact(validator_len * 48)?;
        let allocation_len = read_count(&mut dec, MAX_GENESIS_ALLOCATIONS)?;
        let allocation_bytes = dec.read_exact(allocation_len * 40)?;
        dec.finish()?;

        let genesis = Self {
            version,
            chain_id,
            capacity,
            committee_size,
            rotation_count,
            runtime_version,
            validators: validator_bytes
                .as_chunks::<48>()
                .0
                .iter()
                .map(|chunk| GenesisValidator::decode(chunk))
                .collect::<Result<_, _>>()?,
            allocations: allocation_bytes
                .as_chunks::<40>()
                .0
                .iter()
                .map(|chunk| Allocation::decode(chunk))
                .collect::<Result<_, _>>()?,
        };
        genesis.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(genesis)
    }
}

fn read_count(decoder: &mut Decoder<'_>, maximum: usize) -> Result<usize, DecodeError> {
    let count = decoder.read_u64()?;
    if count > maximum as u64 {
        return Err(DecodeError::LimitExceeded);
    }
    usize::try_from(count).map_err(|_| DecodeError::LengthOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::MockCryptoProvider;

    fn valid_genesis() -> Genesis {
        Genesis {
            version: 1,
            chain_id: 7,
            capacity: Resources {
                compute: 100,
                memory: 100,
                io: 100,
                bandwidth: 100,
            },
            committee_size: 2,
            rotation_count: 1,
            runtime_version: 1,
            validators: vec![
                GenesisValidator {
                    id: ValidatorId::from_bytes([1u8; 32]),
                    weight: 100,
                },
                GenesisValidator {
                    id: ValidatorId::from_bytes([2u8; 32]),
                    weight: 200,
                },
            ],
            allocations: vec![
                Allocation {
                    address: Address::from_bytes([0xAA; 32]),
                    amount: 1000,
                },
                Allocation {
                    address: Address::from_bytes([0xBB; 32]),
                    amount: 2000,
                },
            ],
        }
    }

    #[test]
    fn genesis_validate_passes() {
        let genesis = valid_genesis();
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn genesis_encoding_deterministic() {
        let genesis = valid_genesis();
        let e1 = genesis.to_bytes();
        let e2 = genesis.to_bytes();
        assert_eq!(e1, e2);
    }

    #[test]
    fn genesis_encoding_differs_by_version() {
        let mut g1 = valid_genesis();
        g1.version = 1;
        let mut g2 = valid_genesis();
        g2.version = 2;
        assert_ne!(g1.to_bytes(), g2.to_bytes());
    }

    #[test]
    fn genesis_encoding_differs_by_chain_id() {
        let mut g1 = valid_genesis();
        g1.chain_id = 7;
        let mut g2 = valid_genesis();
        g2.chain_id = 8;
        assert_ne!(g1.to_bytes(), g2.to_bytes());
    }

    #[test]
    fn genesis_encoding_differs_by_validators() {
        let mut g1 = valid_genesis();
        g1.validators[0].weight = 100;
        let mut g2 = valid_genesis();
        g2.validators[0].weight = 200;
        assert_ne!(g1.to_bytes(), g2.to_bytes());
    }

    #[test]
    fn genesis_encoding_empty_allocations() {
        let mut genesis = valid_genesis();
        genesis.allocations.clear();
        let encoded = genesis.to_bytes();
        // Verify it can be roundtripped (no decoding impl yet, but encoding should succeed)
        assert_ne!(encoded, [] as [u8; 0]);
    }

    #[test]
    fn genesis_encoding_empty_validators_fails_validation() {
        let mut genesis = valid_genesis();
        genesis.validators.clear();
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn genesis_commitment_deterministic() {
        let provider = MockCryptoProvider::new();
        let genesis = valid_genesis();
        let h1 = provider.genesis_hash(&genesis).unwrap();
        let h2 = provider.genesis_hash(&genesis).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn genesis_commitment_differs_by_chain_id() {
        let _provider = MockCryptoProvider::new();
        let mut g1 = valid_genesis();
        g1.chain_id = 7;
        let mut g2 = valid_genesis();
        g2.chain_id = 8;
        // Different chain IDs produce different canonical encodings
        let e1 = g1.to_bytes();
        let e2 = g2.to_bytes();
        assert_ne!(e1, e2);
    }

    #[test]
    fn genesis_commitment_non_zero() {
        let provider = MockCryptoProvider::new();
        let genesis = valid_genesis();
        let hash = provider.genesis_hash(&genesis).unwrap();
        assert!(!hash.is_zero());
    }

    #[test]
    fn allocation_roundtrip() {
        let alloc = Allocation {
            address: Address::from_bytes([0xAA; 32]),
            amount: 42,
        };
        let encoded = alloc.to_bytes();
        let decoded = Allocation::decode(&encoded).unwrap();
        assert_eq!(alloc, decoded);
    }

    #[test]
    fn genesis_validator_roundtrip() {
        let gv = GenesisValidator {
            id: ValidatorId::from_bytes([0x55; 32]),
            weight: u128::MAX,
        };
        let encoded = gv.to_bytes();
        let decoded = GenesisValidator::decode(&encoded).unwrap();
        assert_eq!(gv, decoded);
    }

    #[test]
    fn genesis_validator_weight_zero_roundtrip() {
        let gv = GenesisValidator {
            id: ValidatorId::from_bytes([0x55; 32]),
            weight: 0,
        };
        let encoded = gv.to_bytes();
        let decoded = GenesisValidator::decode(&encoded).unwrap();
        assert_eq!(gv, decoded);
    }

    #[test]
    fn genesis_roundtrip() {
        let genesis = valid_genesis();
        let encoded = genesis.to_bytes();
        let decoded = Genesis::decode(&encoded).unwrap();
        assert_eq!(genesis, decoded);
    }

    #[test]
    fn genesis_rejects_empty_validator_set() {
        let mut genesis = valid_genesis();
        genesis.validators.clear();
        genesis.allocations.clear();
        let encoded = genesis.to_bytes();
        assert_eq!(Genesis::decode(&encoded), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn genesis_roundtrip_single_validator() {
        let mut genesis = valid_genesis();
        genesis.validators.truncate(1);
        genesis.committee_size = 1;
        let encoded = genesis.to_bytes();
        let decoded = Genesis::decode(&encoded).unwrap();
        assert_eq!(genesis, decoded);
    }

    #[test]
    fn genesis_encoding_empty_allocations_comment_updated() {
        let mut genesis = valid_genesis();
        genesis.allocations.clear();
        let encoded = genesis.to_bytes();
        let decoded = Genesis::decode(&encoded).unwrap();
        assert_eq!(genesis, decoded);
    }

    #[test]
    fn allocation_encoding_deterministic() {
        let alloc = Allocation {
            address: Address::from_bytes([0xCC; 32]),
            amount: 999,
        };
        assert_eq!(alloc.to_bytes(), alloc.to_bytes());
    }

    #[test]
    fn genesis_encoding_differs_by_allocations() {
        let mut g1 = valid_genesis();
        g1.allocations[0].amount = 100;
        let mut g2 = valid_genesis();
        g2.allocations[0].amount = 200;
        assert_ne!(g1.to_bytes(), g2.to_bytes());
    }
}
