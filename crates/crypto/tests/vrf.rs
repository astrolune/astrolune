// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! RFC vectors, canonical encodings, and protocol-context replay rejection.

use crypto::blake2s::ed25519_public_key;
use crypto::vrf::{verify_ecvrf, verify_vrf};
use crypto::{Blake2sProvider, CryptoProvider, VrfInput, VrfOutput, VrfRole, prove_vrf};
use types::{Hash256, ValidatorId};

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap())
}

fn input() -> VrfInput {
    VrfInput {
        chain_id: 7,
        genesis: Hash256([1; 32]),
        epoch: 2,
        height: 30,
        parent_randomness: Hash256([4; 32]),
        round: 0,
        role: VrfRole::Committee,
    }
}

#[test]
fn rfc9381_examples_16_through_18() {
    // RFC 9381, Appendix B.3. Independent expected proofs and 64-byte outputs.
    use vrf_rfc9381::{Proof, Prover, ec::edwards25519::tai::EdVrfEdwards25519TaiSecretKey};
    for (secret, public, alpha, proof, beta) in [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            vec![],
            concat!(
                "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f7",
                "23f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1",
                "268a1b0db10836d9826a528ca76567805"
            ),
            concat!(
                "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757",
                "876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd",
                "8ae"
            ),
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            vec![0x72],
            concat!(
                "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed",
                "5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926",
                "da3ef39226bbc355bdc9850112c8f4b02"
            ),
            concat!(
                "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496",
                "310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5",
                "031"
            ),
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            vec![0xaf, 0x82],
            concat!(
                "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccb",
                "f8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7",
                "a2d41b00b05081ed0f58ee5e31b3a970e"
            ),
            concat!(
                "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c",
                "61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df",
                "19f"
            ),
        ),
    ] {
        let public = hex(public);
        let proof = hex::<80>(proof);
        assert_eq!(
            verify_ecvrf(&public, &alpha, &proof).unwrap(),
            hex::<64>(beta)
        );
        let secret = EdVrfEdwards25519TaiSecretKey::from_slice(&hex::<32>(secret)).unwrap();
        assert_eq!(secret.prove(&alpha).unwrap().encode_to_pi(), proof);
    }
}

#[test]
fn proof_is_deterministic_registered_and_context_bound() {
    let input = input();
    let proof = prove_vrf(&[7; 32], input).unwrap();
    assert_eq!(proof, prove_vrf(&[7; 32], input).unwrap());
    let public = ed25519_public_key(&[7; 32]);
    let mut provider = Blake2sProvider::new();
    let id = ValidatorId(crypto::blake2s_hash(&public).0);
    assert!(!provider.verify_vrf(id, input.seed(), &proof));
    assert_eq!(provider.register_validator(public).unwrap(), id);
    assert!(provider.verify_vrf(id, input.seed(), &proof));
    assert!(!provider.verify_vrf(ValidatorId::ZERO, input.seed(), &proof));
    for changed in [
        VrfInput {
            chain_id: 8,
            ..input
        },
        VrfInput {
            genesis: Hash256([2; 32]),
            ..input
        },
        VrfInput { epoch: 3, ..input },
        VrfInput {
            height: 31,
            ..input
        },
        VrfInput {
            parent_randomness: Hash256([5; 32]),
            ..input
        },
        VrfInput { round: 1, ..input },
        VrfInput {
            role: VrfRole::Producer,
            ..input
        },
    ] {
        assert!(!provider.verify_vrf(id, changed.seed(), &proof));
    }
}

#[test]
fn rejects_mutations_wrong_key_output_lengths_and_weak_keys() {
    let input = input();
    let output = prove_vrf(&[9; 32], input).unwrap();
    let key = ed25519_public_key(&[9; 32]);
    assert!(verify_vrf(&ed25519_public_key(&[8; 32]), input.seed(), &output).is_err());
    for index in 0..80 {
        let mut changed = output.clone();
        changed.proof[index] ^= 1;
        assert!(verify_vrf(&key, input.seed(), &changed).is_err());
    }
    for index in 0..32 {
        let mut changed = output.clone();
        changed.randomness.0[index] ^= 1;
        assert!(verify_vrf(&key, input.seed(), &changed).is_err());
    }
    for length in [0, 1, 79, 81, 4096] {
        let mut changed = output.clone();
        changed.proof.resize(length, 0);
        assert!(verify_vrf(&key, input.seed(), &changed).is_err());
    }
    let mut identity = [0; 32];
    identity[0] = 1;
    assert!(verify_vrf(&identity, input.seed(), &output).is_err());
}

#[test]
fn noncanonical_scalar_is_rejected_even_when_congruent_mod_order() {
    let mut output = prove_vrf(&[9; 32], input()).unwrap();
    let order = hex::<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut carry = 0u16;
    for (byte, added) in output.proof[48..].iter_mut().zip(order) {
        let sum = u16::from(*byte) + u16::from(added) + carry;
        *byte = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    assert!(verify_vrf(&ed25519_public_key(&[9; 32]), input().seed(), &output).is_err());
    assert!(output.encode().is_err());
}

#[test]
fn wire_envelope_is_exact_bounded_and_versioned() {
    let output = prove_vrf(&[9; 32], input()).unwrap();
    let bytes = output.encode().unwrap();
    assert_eq!(bytes.len(), 120);
    assert_eq!(&bytes[..8], b"ALVR\x01\0\0\0");
    assert_eq!(VrfOutput::decode(&bytes).unwrap(), output);
    for end in 0..bytes.len() {
        assert!(VrfOutput::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(VrfOutput::decode(&trailing).is_err());
    for index in 0..8 {
        let mut changed = bytes;
        changed[index] ^= 1;
        assert!(VrfOutput::decode(&changed).is_err());
    }
}
