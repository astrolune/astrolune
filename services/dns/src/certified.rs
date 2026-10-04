// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Network resolver authenticated against independent registry code and genesis anchors.

use contract_sdk::registry::{self, Lease};
use genesis::Genesis;
use rpc::{CertifiedStateProof, TcpRpcClient};
use types::{Address, Hash256, StateKey};

/// Owned application lease returned only after both proofs are authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedLease {
    /// Current authorized owner.
    pub owner: Address,
    /// Exclusive expiry in finalized blocks.
    pub expires: u64,
    /// Zero denotes an address; one a printable ASCII service description.
    pub kind: u8,
    /// Application record data.
    pub value: Vec<u8>,
}

/// A verified name result, including authenticated absence or expiration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolution {
    /// Canonical queried name.
    pub name: String,
    /// Height of the authenticated registry state.
    pub height: u64,
    /// Active exact-name lease, if any.
    pub lease: Option<ResolvedLease>,
}

/// Immutable anchors provisioned independently of the resolver's RPC endpoint.
pub struct RegistryTrust {
    /// Trusted genesis, including the contract runtime activation.
    pub genesis: Genesis,
    /// Complete fixed-committee public-key registry.
    pub validators: Vec<[u8; 32]>,
    /// Deployed registry contract address.
    pub address: Address,
    /// Code commitment derived from the reviewed registry artifact.
    pub code_hash: Hash256,
}

impl RegistryTrust {
    /// Verifies immutable contract code and the queried lease in certified state.
    pub fn verify(
        &self,
        name: &str,
        minimum: u64,
        code: &CertifiedStateProof,
        value: &CertifiedStateProof,
    ) -> Result<Resolution, String> {
        self.verify_using(name, minimum, code, value, |proof, key, minimum| {
            proof
                .verify(&self.genesis, &self.validators, key, minimum)
                .map_err(|_| "registry proof failed authentication".into())
        })
    }

    fn verify_using<'a>(
        &self,
        name: &str,
        minimum: u64,
        code: &'a CertifiedStateProof,
        value: &'a CertifiedStateProof,
        mut verify: impl FnMut(
            &'a CertifiedStateProof,
            &StateKey,
            u64,
        ) -> Result<Option<&'a [u8]>, String>,
    ) -> Result<Resolution, String> {
        if self.genesis.runtime_version != 2 {
            return Err("registry requires activated ABI v2".into());
        }
        let name = canonical_name(name)?;
        let code_key = transaction::contract_code_key(self.address);
        let code_bytes = verify(code, &code_key, minimum)?.ok_or("registry is not deployed")?;
        if runtime::wasm_code_hash(code_bytes) != self.code_hash {
            return Err("registry code commitment mismatch".into());
        }
        let minimum = minimum.max(code.header.map_or(0, |header| header.height));
        let key = self.state_key(&name)?;
        let bytes = verify(value, &key, minimum)?;
        let height = value.header.map_or(0, |header| header.height);
        let lease = bytes
            .map(Lease::decode)
            .transpose()
            .map_err(|_| "invalid registry lease encoding")?;
        if lease.is_some_and(|lease| lease.issued > height) {
            return Err("lease was issued after its state height".into());
        }
        let lease = lease
            .filter(|lease| lease.name == name.as_bytes() && height < lease.expires)
            .map(|lease| ResolvedLease {
                owner: Address(lease.owner),
                expires: lease.expires,
                kind: lease.record.kind,
                value: lease.record.value.to_vec(),
            });
        Ok(Resolution {
            name,
            height,
            lease,
        })
    }

    /// Converts a normalized name to its contract-scoped global state key.
    pub fn state_key(&self, name: &str) -> Result<StateKey, String> {
        let name = canonical_name(name)?;
        let mut key = [0; registry::MAX_NAME + 7];
        let length =
            registry::registry_key(name.as_bytes(), &mut key).map_err(|_| "invalid name")?;
        Ok(transaction::contract_state_key(
            self.address,
            &key[..length],
        ))
    }
}

/// Stateful resolver retaining the highest accepted height for rollback rejection.
pub struct CertifiedResolver {
    trust: RegistryTrust,
    client: TcpRpcClient,
    minimum: u64,
    handoffs: Option<consensus::rotation::HandoffVerifier>,
    potb: Option<consensus::potb_transition::PotbVerifier>,
}
impl CertifiedResolver {
    /// Creates a resolver with operator-supplied freshness floor and trust anchors.
    #[must_use]
    pub fn new(trust: RegistryTrust, client: TcpRpcClient, minimum: u64) -> Self {
        Self {
            trust,
            client,
            minimum,
            handoffs: None,
            potb: None,
        }
    }

    /// Creates a resolver anchored to an explicitly supplied `PoTB` configuration.
    /// The base deployment/runtime settings must agree with the supplied registry trust.
    pub fn with_potb(
        trust: RegistryTrust,
        client: TcpRpcClient,
        minimum: u64,
        profile: &consensus::potb_transition::PotbConfiguration,
    ) -> Result<Self, String> {
        if &trust.genesis != profile.genesis() {
            return Err("registry and PoTB configuration disagree".into());
        }
        let potb = consensus::potb_transition::PotbVerifier::new(profile, &trust.validators)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            trust,
            client,
            minimum,
            handoffs: None,
            potb: Some(potb),
        })
    }

    /// Fetches and verifies proofs without using public DNS or unauthenticated fallback.
    pub fn resolve(&mut self, name: &str) -> Result<Resolution, String> {
        let key = self.trust.state_key(name)?;
        let code = self
            .client
            .state_proof(&transaction::contract_code_key(self.trust.address))
            .map_err(|error| error.to_string())?;
        let value = self
            .client
            .state_proof(&key)
            .map_err(|error| error.to_string())?;
        let result = if self.potb.is_some() {
            self.resolve_potb(name, &code, &value)?
        } else if self.trust.genesis.version == genesis::ROTATING_GENESIS_VERSION {
            let mut trusted = match &self.handoffs {
                Some(trusted) => trusted.clone(),
                None => consensus::rotation::HandoffVerifier::new(
                    &self.trust.genesis,
                    &self.trust.validators,
                )
                .map_err(|error| error.to_string())?,
            };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let result = self.trust.verify_using(
                name,
                self.minimum,
                &code,
                &value,
                |proof, key, minimum| {
                    let height = proof
                        .header
                        .ok_or("registry requires finalized deployment")?
                        .height;
                    if height < minimum {
                        return Err("registry proof precedes freshness floor".into());
                    }
                    let remaining = deadline
                        .checked_duration_since(std::time::Instant::now())
                        .ok_or("handoff deadline exceeded")?;
                    self.client
                        .advance_handoffs(&mut trusted, height, 10_000, remaining)
                        .map_err(|error| error.to_string())?;
                    proof
                        .verify_with_handoffs(&trusted, key, minimum)
                        .map_err(|_| "registry proof failed authentication".into())
                },
            )?;
            self.handoffs = Some(trusted);
            result
        } else {
            self.trust.verify(name, self.minimum, &code, &value)?
        };
        self.minimum = self.minimum.max(result.height);
        Ok(result)
    }

    fn resolve_potb(
        &mut self,
        name: &str,
        code: &CertifiedStateProof,
        value: &CertifiedStateProof,
    ) -> Result<Resolution, String> {
        let mut trusted = self.potb.clone().ok_or("PoTB is not configured")?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let result =
            self.trust
                .verify_using(name, self.minimum, code, value, |proof, key, minimum| {
                    let height = proof
                        .header
                        .ok_or("registry requires finalized deployment")?
                        .height;
                    if height < minimum {
                        return Err("registry proof precedes freshness floor".into());
                    }
                    let remaining = deadline
                        .checked_duration_since(std::time::Instant::now())
                        .ok_or("handoff deadline exceeded")?;
                    self.client
                        .advance_potb_handoffs(&mut trusted, height, 10_000, remaining)
                        .map_err(|error| error.to_string())?;
                    proof
                        .verify_with_potb(&trusted, key, minimum)
                        .map_err(|_| "registry proof failed authentication".into())
                })?;
        self.potb = Some(trusted);
        Ok(result)
    }
}

/// Normalizes ASCII case/outer whitespace and checks the on-chain name policy.
pub fn canonical_name(name: &str) -> Result<String, String> {
    if name.len() > 128 {
        return Err("name input too long".into());
    }
    let name = name.trim().to_ascii_lowercase();
    registry::validate_name(name.as_bytes()).map_err(|_| "invalid or reserved registry name")?;
    Ok(name)
}
