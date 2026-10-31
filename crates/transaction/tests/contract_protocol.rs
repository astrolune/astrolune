// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Historical byte stability and bounded native source/call admission.

use transaction::{
    ContractAction, ContractPayload, TransactionError, contract_address, contract_code_key,
    contract_state_key, trocto_contract_address, trocto_contract_code_key,
    trocto_contract_state_key,
};
use types::Address;

fn payload(action: ContractAction) -> ContractPayload {
    ContractPayload {
        public_key: [7; 32],
        action,
    }
}

#[test]
fn historical_encodings_are_byte_identical() {
    let deploy = payload(ContractAction::Deploy(vec![1, 2, 3]));
    let expected = [
        b"ALCON002".as_slice(),
        &[7; 32],
        &[0],
        &3u32.to_le_bytes(),
        &[1, 2, 3],
    ]
    .concat();
    assert_eq!(deploy.to_bytes(), expected);
    let call = payload(ContractAction::Call {
        address: Address([9; 32]),
        input: vec![4],
        keys: vec![b"k".to_vec()],
    });
    let expected = [
        b"ALCON002".as_slice(),
        &[7; 32],
        &[1],
        &[9; 32],
        &1u32.to_le_bytes(),
        &[4],
        &1u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        b"k",
    ]
    .concat();
    assert_eq!(call.to_bytes(), expected);
    assert_eq!(ContractPayload::decode(&deploy.to_bytes()), Ok(deploy));
    assert_eq!(ContractPayload::decode(&call.to_bytes()), Ok(call));
}

#[test]
fn native_roundtrip_and_namespaces_are_separate() {
    let old = contract_address(7, Address([1; 32]), 2);
    let native = trocto_contract_address(7, Address([1; 32]), 2);
    assert_ne!(old, native);
    assert_ne!(contract_code_key(native), trocto_contract_code_key(native));
    assert_ne!(
        contract_state_key(native, b"k"),
        trocto_contract_state_key(native, b"k")
    );
    for action in [
        ContractAction::DeployTrocto(b"fn call(input: u64) -> u64 { input }".to_vec()),
        ContractAction::CallTrocto {
            address: native,
            input: 42u64.to_le_bytes().to_vec(),
            keys: vec![b"a".to_vec(), b"b".to_vec()],
        },
    ] {
        let payload = payload(action);
        let bytes = payload.to_bytes();
        assert_eq!(&bytes[..8], b"ALCON003");
        assert_eq!(ContractPayload::decode(&bytes), Ok(payload));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            ContractPayload::decode(&trailing),
            Err(TransactionError::UnsupportedPayload)
        );
        for cut in 0..bytes.len() {
            assert!(ContractPayload::decode(&bytes[..cut]).is_err());
        }
    }
}

#[test]
fn native_rejects_invalid_source_input_keys_and_counts() {
    for source in [vec![], vec![0xff], vec![b'a'; 65_537]] {
        assert!(
            ContractPayload::decode(&payload(ContractAction::DeployTrocto(source)).to_bytes())
                .is_err()
        );
    }
    let max = payload(ContractAction::DeployTrocto(vec![b'a'; 65_536]));
    assert_eq!(ContractPayload::decode(&max.to_bytes()), Ok(max));
    for input in [vec![], vec![0; 7], vec![0; 9]] {
        assert!(
            ContractPayload::decode(
                &payload(ContractAction::CallTrocto {
                    address: Address([1; 32]),
                    input,
                    keys: vec![]
                })
                .to_bytes()
            )
            .is_err()
        );
    }
    for keys in [
        vec![vec![]],
        vec![vec![b'a'; 257]],
        vec![b"a".to_vec(), b"a".to_vec()],
        vec![b"b".to_vec(), b"a".to_vec()],
    ] {
        assert!(
            ContractPayload::decode(
                &payload(ContractAction::CallTrocto {
                    address: Address([1; 32]),
                    input: vec![0; 8],
                    keys
                })
                .to_bytes()
            )
            .is_err()
        );
    }
    let mut count = payload(ContractAction::CallTrocto {
        address: Address([1; 32]),
        input: vec![0; 8],
        keys: vec![],
    })
    .to_bytes();
    count[85..89].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(ContractPayload::decode(&count).is_err());
}
