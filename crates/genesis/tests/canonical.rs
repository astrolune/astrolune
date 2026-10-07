// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Genesis bounds, independent vectors, and committed state layout.

use codec::{CanonicalDecode, CanonicalEncode, DecodeError};
use crypto::blake2s::Blake2sProvider;
use genesis::{
    Allocation, Genesis, GenesisCommitment, GenesisError, GenesisValidator,
    MAX_GENESIS_ALLOCATIONS, MAX_GENESIS_BYTES, MAX_GENESIS_VALIDATORS, genesis_key, validator_key,
};
use state::{
    InMemoryState, StateDatabase, StateDiff, StateError, StateSnapshot, account_key, read_account,
};
use types::{AccountState, Address, Hash256, Resources, ValidatorId};

fn fixture() -> Genesis {
    Genesis {
        version: 1,
        chain_id: 7,
        capacity: Resources {
            compute: 11,
            memory: 22,
            io: 33,
            bandwidth: 44,
        },
        committee_size: 1,
        rotation_count: 1,
        runtime_version: 1,
        validators: vec![GenesisValidator {
            id: ValidatorId([1; 32]),
            weight: (1 << 80) + 3,
        }],
        allocations: vec![Allocation {
            address: Address([2; 32]),
            amount: 500,
        }],
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(&mut output, "{byte:02x}").unwrap();
        output
    })
}

#[test]
fn independent_genesis_and_state_vectors() {
    // Independently calculated with Python struct and hashlib.blake2s.
    let genesis = fixture();
    assert_eq!(
        hex(&genesis.to_bytes()),
        concat!(
            "0100070000000b00000000000000160000000000000021000000000000002c00000000000000",
            "01000000000000000100000000000000010000000100000000000000",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "030000000000000000000100000000000100000000000000",
            "0202020202020202020202020202020202020202020202020202020202020202f401000000000000"
        )
    );
    let hash = genesis.commitment().unwrap();
    assert_eq!(
        hex(hash.as_bytes()),
        "98ddf60aafa73a4717c1b94fbc4df02f1c2ff9ba909f236ee3924c70895c0bf6"
    );
    assert_eq!(Blake2sProvider::new().genesis_hash(&genesis).unwrap(), hash);
    let state = genesis.materialize().unwrap();
    assert_eq!(
        hex(state.root().as_bytes()),
        "0b818b0904e6b79282d518498a87120b61e622fd672fc9e78853d8190c4770ef"
    );
    assert_eq!(state.len(), 3);
    assert_eq!(state.get(&genesis_key()), Some(hash.as_bytes().as_slice()));
    assert_eq!(
        state.get(&validator_key(ValidatorId([1; 32]))),
        Some(((1u128 << 80) + 3).to_le_bytes().as_slice())
    );
    let account = read_account(&state, Address([2; 32])).unwrap().unwrap();
    assert_eq!(
        account,
        AccountState {
            nonce: 0,
            balance: 500
        }
    );
    assert_eq!(hex(&account.to_bytes()), "0000000000000000f401000000000000");
    let key = account_key(Address([2; 32]));
    assert!(
        state
            .prove(&key)
            .unwrap()
            .unwrap()
            .verify(state.root(), &key, &account.to_bytes())
    );
    let missing = account_key(Address([3; 32]));
    assert!(
        state
            .prove_absence(&missing)
            .unwrap()
            .unwrap()
            .verify(state.root(), &missing)
    );
}

#[test]
fn truncation_trailing_bytes_and_hostile_counts_fail() {
    let bytes = fixture().to_bytes();
    for length in 0..bytes.len() {
        assert!(
            Genesis::decode(&bytes[..length]).is_err(),
            "length {length}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(Genesis::decode(&extra), Err(DecodeError::TrailingBytes));
    for (offset, maximum) in [
        (38, MAX_GENESIS_VALIDATORS),
        (46, MAX_GENESIS_VALIDATORS),
        (58, MAX_GENESIS_VALIDATORS),
        (114, MAX_GENESIS_ALLOCATIONS),
    ] {
        for count in [maximum as u64 + 1, u64::MAX] {
            let mut malformed = bytes.clone();
            malformed[offset..offset + 8].copy_from_slice(&count.to_le_bytes());
            assert_eq!(Genesis::decode(&malformed), Err(DecodeError::LimitExceeded));
        }
    }
    assert_eq!(
        Genesis::decode(&vec![0; MAX_GENESIS_BYTES + 1]),
        Err(DecodeError::LimitExceeded)
    );
}

#[test]
fn invalid_configuration_cannot_be_decoded_hashed_or_materialized() {
    let mut cases = Vec::new();
    for change in [
        |g: &mut Genesis| g.chain_id = 0,
        |g: &mut Genesis| g.runtime_version = 0,
        |g: &mut Genesis| g.capacity.memory = 0,
        |g: &mut Genesis| g.committee_size = 0,
        |g: &mut Genesis| g.rotation_count = 0,
        |g: &mut Genesis| g.rotation_count = 2,
        |g: &mut Genesis| g.validators[0].id = ValidatorId([0; 32]),
        |g: &mut Genesis| g.validators[0].weight = 0,
        |g: &mut Genesis| g.validators.push(g.validators[0]),
        |g: &mut Genesis| g.allocations[0].address = Address::ZERO,
        |g: &mut Genesis| g.allocations.push(g.allocations[0]),
    ] {
        let mut genesis = fixture();
        change(&mut genesis);
        cases.push(genesis);
    }
    let mut overflow = fixture();
    overflow.validators[0].weight = u128::MAX;
    overflow.validators.push(GenesisValidator {
        id: ValidatorId([2; 32]),
        weight: 1,
    });
    cases.push(overflow);
    let mut unordered = fixture();
    unordered.allocations.push(Allocation {
        address: Address([1; 32]),
        amount: 0,
    });
    cases.push(unordered);
    for genesis in cases {
        assert!(genesis.validate().is_err());
        assert!(genesis.commitment().is_err());
        assert!(genesis.materialize().is_err());
        assert!(Blake2sProvider::new().genesis_hash(&genesis).is_err());
        assert_eq!(
            Genesis::decode(&genesis.to_bytes()),
            Err(DecodeError::NonCanonical)
        );
    }
    for version in [0, 3, u16::MAX] {
        let mut genesis = fixture();
        genesis.version = version;
        assert_eq!(genesis.validate(), Err(GenesisError::UnsupportedVersion));
        assert_eq!(
            Genesis::decode(&genesis.to_bytes()),
            Err(DecodeError::Unsupported)
        );
    }
}

#[test]
fn every_accepted_single_byte_mutation_is_canonical() {
    let bytes = fixture().to_bytes();
    for offset in 0..bytes.len() {
        for value in [0, 1, 0x7f, 0x80, 0xff] {
            let mut changed = bytes.clone();
            changed[offset] = value;
            if let Ok(genesis) = Genesis::decode(&changed) {
                assert_eq!(genesis.to_bytes(), changed);
                assert!(genesis.validate().is_ok());
            }
        }
    }
}

#[test]
fn parameters_and_allocations_bind_the_initial_root() {
    let base = fixture();
    let expected = base.materialize().unwrap().root();
    for change in [
        |g: &mut Genesis| g.chain_id += 1,
        |g: &mut Genesis| g.capacity.compute += 1,
        |g: &mut Genesis| g.runtime_version += 1,
        |g: &mut Genesis| g.validators[0].weight += 1,
        |g: &mut Genesis| g.allocations[0].amount += 1,
    ] {
        let mut changed = base.clone();
        change(&mut changed);
        assert_ne!(changed.materialize().unwrap().root(), expected);
    }
    let mut zero = base;
    zero.allocations[0].amount = 0;
    assert_eq!(
        read_account(&zero.materialize().unwrap(), Address([2; 32])).unwrap(),
        Some(AccountState {
            nonce: 0,
            balance: 0
        })
    );
    zero.allocations.clear();
    assert!(
        read_account(&zero.materialize().unwrap(), Address([2; 32]))
            .unwrap()
            .is_none()
    );
}

#[test]
fn snapshot_roundtrip_and_corrupt_account_rejection() {
    let initial = fixture().materialize().unwrap();
    let encoded = initial.export_snapshot();
    let mut restored = InMemoryState::from_snapshot(&encoded, initial.root()).unwrap();
    assert_eq!(restored.export_snapshot(), encoded);
    assert!(matches!(
        InMemoryState::from_snapshot(&encoded, Hash256::ZERO),
        Err(StateError::RootMismatch)
    ));
    let key = account_key(Address([2; 32]));
    let original = restored.get(&key).unwrap().to_vec();
    for bytes in [
        original[..15].to_vec(),
        [original.as_slice(), &[0]].concat(),
    ] {
        let mut diff = StateDiff::new();
        diff.put(key.clone(), bytes);
        restored.commit(restored.root(), &[diff]).unwrap();
        assert_eq!(
            read_account(&restored, Address([2; 32])),
            Err(StateError::Corrupt)
        );
    }
    assert_eq!(read_account(&restored, Address([3; 32])), Ok(None));
}

#[test]
fn maximum_lists_fit_the_codec_and_state_bounds() {
    fn id(index: usize) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        bytes
    }
    let mut genesis = fixture();
    genesis.validators = (0..MAX_GENESIS_VALIDATORS)
        .map(|i| GenesisValidator {
            id: ValidatorId(id(i)),
            weight: 1,
        })
        .collect();
    genesis.allocations = (0..MAX_GENESIS_ALLOCATIONS)
        .map(|i| Allocation {
            address: Address(id(i)),
            amount: u64::MAX,
        })
        .collect();
    let bytes = genesis.to_bytes();
    assert_eq!(bytes.len(), MAX_GENESIS_BYTES);
    assert_eq!(Genesis::decode(&bytes).unwrap(), genesis);
    assert_eq!(
        genesis.materialize().unwrap().len(),
        1 + MAX_GENESIS_VALIDATORS + MAX_GENESIS_ALLOCATIONS
    );
    genesis.allocations.push(Allocation {
        address: Address([0xff; 32]),
        amount: 0,
    });
    assert_eq!(genesis.validate(), Err(GenesisError::LimitExceeded));
}

#[test]
fn rotating_activation_is_explicit_in_genesis_bytes_and_materialized_state() {
    let fixed = fixture();
    let mut rotating = fixed.clone();
    rotating.version = genesis::ROTATING_GENESIS_VERSION;
    let mut expected = fixed.to_bytes();
    expected[..2].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(rotating.to_bytes(), expected);
    assert_eq!(Genesis::decode(&expected).unwrap(), rotating);
    assert_ne!(fixed.commitment().unwrap(), rotating.commitment().unwrap());
    let profile = types::StateKey(types::domain::ROTATING_PROFILE_KEY.to_vec());
    assert!(fixed.materialize().unwrap().get(&profile).is_none());
    assert_eq!(
        rotating.materialize().unwrap().get(&profile),
        Some([2].as_slice())
    );
}
