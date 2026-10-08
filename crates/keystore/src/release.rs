// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Detached release-manifest signatures over the project's strict Ed25519.

use crypto::blake2s::{ed25519_public_key, ed25519_sign, ed25519_verify};
use types::{Hash256, hash::domain_hash};

const MAGIC: &[u8; 8] = b"ALRS0001";
const MANIFEST_DOMAIN: &[u8] = b"astrolune.release.manifest.v1";

/// Exact detached release-signature length, including its framing.
pub const RELEASE_SIGNATURE_BYTES: usize = 8 + 32 + 32 + 64;
/// Largest accepted release manifest; an untrusted file cannot request more work.
pub const MAX_RELEASE_MANIFEST_BYTES: usize = 1 << 20;

/// Release-authority failure; no signing identity is defined by this repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseError {
    /// Unsupported framing, or a manifest outside its accepted bounds.
    InvalidFormat,
    /// The signature does not authenticate this manifest under the supplied authority.
    Authentication,
}

impl core::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidFormat => "invalid release signature format or manifest length",
            Self::Authentication => "release manifest authentication failed",
        })
    }
}
impl std::error::Error for ReleaseError {}

/// Commits to the exact manifest bytes under a release-specific domain.
///
/// # Errors
/// Rejects an empty manifest or one above `MAX_RELEASE_MANIFEST_BYTES`.
pub fn release_manifest_digest(manifest: &[u8]) -> Result<Hash256, ReleaseError> {
    if manifest.is_empty() || manifest.len() > MAX_RELEASE_MANIFEST_BYTES {
        return Err(ReleaseError::InvalidFormat);
    }
    Ok(domain_hash(MANIFEST_DOMAIN, manifest))
}

/// Produces a detached signature over a release manifest.
///
/// The manifest is expected to commit transitively to every published file, so one
/// signature covers the whole artifact set rather than a single archive digest.
///
/// # Errors
/// Rejects manifests outside their accepted bounds.
pub fn sign_release_manifest(seed: &[u8; 32], manifest: &[u8]) -> Result<Vec<u8>, ReleaseError> {
    let digest = release_manifest_digest(manifest)?;
    let mut bytes = Vec::with_capacity(RELEASE_SIGNATURE_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&ed25519_public_key(seed));
    bytes.extend_from_slice(&digest.0);
    bytes.extend_from_slice(&ed25519_sign(seed, &digest.0));
    Ok(bytes)
}

/// Verifies a detached signature against an explicitly supplied authority key.
///
/// The authority key is never read from the signature artifact: the embedded key is
/// compared with the supplied one and disagreement is an authentication failure.
/// Establishing which key is authoritative is an operator decision outside this API.
///
/// # Errors
/// Rejects wrong framing or lengths, a foreign authority key, a manifest digest that
/// does not match, and an invalid strict Ed25519 signature.
pub fn verify_release_manifest(
    authority: &[u8; 32],
    manifest: &[u8],
    signature: &[u8],
) -> Result<Hash256, ReleaseError> {
    let digest = release_manifest_digest(manifest)?;
    if signature.len() != RELEASE_SIGNATURE_BYTES || &signature[..8] != MAGIC {
        return Err(ReleaseError::InvalidFormat);
    }
    let embedded =
        <[u8; 64]>::try_from(&signature[72..]).map_err(|_| ReleaseError::InvalidFormat)?;
    if &signature[8..40] != authority.as_slice()
        || signature[40..72] != digest.0
        || !ed25519_verify(authority, &digest.0, &embedded)
    {
        return Err(ReleaseError::Authentication);
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_manifest_domain_matches_an_independent_blake2s_vector() {
        assert_eq!(
            release_manifest_digest(b"{\"release\": true}")
                .expect("bounded manifest")
                .to_string(),
            "63bc54d7407a50f1e6720d18a5ce7c4cddcfe7a43cb4e110e8a1adb531d316d5"
        );
        assert_eq!(
            release_manifest_digest(b""),
            Err(ReleaseError::InvalidFormat)
        );
        assert_eq!(
            release_manifest_digest(&vec![0; MAX_RELEASE_MANIFEST_BYTES + 1]),
            Err(ReleaseError::InvalidFormat)
        );
    }

    #[test]
    fn a_manifest_signature_authenticates_only_its_own_bytes_and_authority() {
        let manifest = b"{\"files\": {}, \"release\": true}";
        let signature = sign_release_manifest(&[1; 32], manifest).expect("sign");
        assert_eq!(signature.len(), RELEASE_SIGNATURE_BYTES);
        let authority = ed25519_public_key(&[1; 32]);
        assert_eq!(
            verify_release_manifest(&authority, manifest, &signature).expect("verify"),
            release_manifest_digest(manifest).expect("digest")
        );
        assert_eq!(
            verify_release_manifest(&ed25519_public_key(&[2; 32]), manifest, &signature),
            Err(ReleaseError::Authentication)
        );
        assert_eq!(
            verify_release_manifest(
                &authority,
                b"{\"files\": {}, \"release\": false}",
                &signature
            ),
            Err(ReleaseError::Authentication)
        );
        for index in 0..signature.len() {
            let mut altered = signature.clone();
            altered[index] ^= 1;
            assert!(verify_release_manifest(&authority, manifest, &altered).is_err());
        }
        for length in 0..signature.len() {
            assert_eq!(
                verify_release_manifest(&authority, manifest, &signature[..length]),
                Err(ReleaseError::InvalidFormat)
            );
        }
    }

    #[test]
    fn release_error_display_is_stable() {
        assert_eq!(
            ReleaseError::InvalidFormat.to_string(),
            "invalid release signature format or manifest length"
        );
        assert_eq!(
            ReleaseError::Authentication.to_string(),
            "release manifest authentication failed"
        );
    }
}
