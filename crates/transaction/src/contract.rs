// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded ABI-v2 deployment and call payloads within signed envelopes.

use codec::{CanonicalEncode, decoder::Decoder};
use types::{Address, StateKey};

use crate::TransactionError;

/// Maximum deployable code bytes, leaving space for the transaction envelope.
pub const MAX_CONTRACT_CODE: usize = 1_000_000;
/// Maximum raw contract-local keys authorized by one call.
pub const MAX_CONTRACT_KEYS: usize = 1024;

/// Immutable deployment or a call with explicit local state keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractAction {
    /// Deploy ABI-v2 code at the sender/nonce-derived address.
    Deploy(Vec<u8>),
    /// Execute an existing module. Keys are strictly increasing and nonempty.
    Call {
        /// Address derived at deployment.
        address: Address,
        /// Contract input, at most 64 KiB.
        input: Vec<u8>,
        /// Raw local keys; the outer envelope also leases their scoped hashes.
        keys: Vec<Vec<u8>>,
    },
}

/// Contract payload authenticated by the enclosing transaction signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractPayload {
    /// Sender's Ed25519 public key.
    pub public_key: [u8; 32],
    /// Deployment or call.
    pub action: ContractAction,
}

impl ContractPayload {
    /// Encodes the payload. Decoding enforces all bounds and canonical ordering.
    ///
    /// # Panics
    /// Panics if an in-memory field or key count exceeds `u32::MAX`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = b"ALCON002".to_vec();
        out.extend_from_slice(&self.public_key);
        match &self.action {
            ContractAction::Deploy(code) => {
                out.push(0);
                encode_bytes(code, &mut out);
            }
            ContractAction::Call {
                address,
                input,
                keys,
            } => {
                out.push(1);
                address.encode(&mut out);
                encode_bytes(input, &mut out);
                out.extend_from_slice(
                    &u32::try_from(keys.len())
                        .expect("key count fits u32")
                        .to_le_bytes(),
                );
                for key in keys {
                    encode_bytes(key, &mut out);
                }
            }
        }
        out
    }

    /// Rejects unsupported tags, oversized fields, duplicate keys and trailing bytes.
    ///
    /// # Errors
    /// Returns `UnsupportedPayload` for any malformed or out-of-bounds payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransactionError> {
        Self::decode_inner(bytes).map_err(|_| TransactionError::UnsupportedPayload)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, codec::DecodeError> {
        use codec::DecodeError;
        if bytes.len() > MAX_CONTRACT_CODE + 45 {
            return Err(DecodeError::LimitExceeded);
        }
        let mut dec = Decoder::new(bytes);
        if dec.read_exact(8)? != b"ALCON002" {
            return Err(DecodeError::NonCanonical);
        }
        let public_key = dec.read_fixed()?;
        let action = match dec.read_u8()? {
            0 => {
                let code = decode_bytes(&mut dec, MAX_CONTRACT_CODE)?;
                if code.is_empty() {
                    return Err(DecodeError::NonCanonical);
                }
                ContractAction::Deploy(code.to_vec())
            }
            1 => {
                let address = Address(dec.read_fixed()?);
                if address.is_zero() {
                    return Err(DecodeError::NonCanonical);
                }
                let input = decode_bytes(&mut dec, 65_536)?.to_vec();
                let count = dec.read_u32()? as usize;
                if count > MAX_CONTRACT_KEYS || count > dec.remaining() / 5 {
                    return Err(DecodeError::LimitExceeded);
                }
                let mut keys = Vec::with_capacity(count);
                for _ in 0..count {
                    let key = decode_bytes(&mut dec, 256)?.to_vec();
                    if key.is_empty() || keys.last().is_some_and(|previous| previous >= &key) {
                        return Err(DecodeError::NonCanonical);
                    }
                    keys.push(key);
                }
                ContractAction::Call {
                    address,
                    input,
                    keys,
                }
            }
            _ => return Err(DecodeError::NonCanonical),
        };
        dec.finish()?;
        Ok(Self { public_key, action })
    }
}

/// Domain-separated deployment address, independent of the deployed code.
#[must_use]
pub fn contract_address(chain_id: u32, sender: Address, nonce: u64) -> Address {
    let mut bytes = chain_id.to_le_bytes().to_vec();
    bytes.extend_from_slice(sender.as_bytes());
    bytes.extend_from_slice(&nonce.to_le_bytes());
    Address(types::hash::domain_hash(b"astrolune.contract.address.v2", &bytes).0)
}

/// Immutable code key, outside all account and contract-local namespaces.
#[must_use]
pub fn contract_code_key(address: Address) -> StateKey {
    let mut key = b"astrolune/contract/code/v2/".to_vec();
    key.extend_from_slice(address.as_bytes());
    StateKey(key)
}

/// Scopes an arbitrary local key to exactly one contract and bounds global key length.
#[must_use]
pub fn contract_state_key(address: Address, local: &[u8]) -> StateKey {
    let mut key = b"astrolune/contract/state/v2/".to_vec();
    key.extend_from_slice(address.as_bytes());
    key.extend_from_slice(types::hash::domain_hash(b"astrolune.contract.key.v2", local).as_bytes());
    StateKey(key)
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("field length fits u32")
            .to_le_bytes(),
    );
    out.extend_from_slice(bytes);
}

fn decode_bytes<'a>(dec: &mut Decoder<'a>, max: usize) -> Result<&'a [u8], codec::DecodeError> {
    let length = dec.read_u32()? as usize;
    if length > max {
        return Err(codec::DecodeError::LimitExceeded);
    }
    dec.read_exact(length)
}
