// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Offline generation of a small transport trust domain with independent random keys.
//! The CA private key stays in memory and is never returned or written by this module.

use crate::tls::PEER_DNS_NAME;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::io;

fn error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn parameters(name: &str) -> io::Result<CertificateParams> {
    let mut params = CertificateParams::new(vec![PEER_DNS_NAME.into()]).map_err(error)?;
    params.distinguished_name.push(DnType::CommonName, name);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(365);
    Ok(params)
}

/// Private, temporary authority for provisioning an isolated network in one operation.
pub struct TransportAuthority(CertifiedIssuer<'static, KeyPair>);

impl TransportAuthority {
    /// Generates an independent random CA key using the OS-backed cryptographic RNG.
    pub fn generate() -> io::Result<Self> {
        let mut params = parameters("AstroLune transport CA")?;
        params.subject_alt_names.clear();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        Ok(Self(
            CertifiedIssuer::self_signed(params, KeyPair::generate().map_err(error)?)
                .map_err(error)?,
        ))
    }

    /// Issues a one-year client/server certificate with a fresh random transport key.
    /// The name is an operator label, never a consensus validator identifier.
    pub fn issue(&self, name: &str) -> io::Result<TransportIdentity> {
        if name.is_empty() || name.len() > 64 || !name.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid transport label",
            ));
        }
        let mut params = parameters(name)?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let key = KeyPair::generate().map_err(error)?;
        let certificate = params.signed_by(&key, &self.0).map_err(error)?;
        Ok(TransportIdentity {
            ca_der: self.0.der().to_vec(),
            certificate_der: certificate.der().to_vec(),
            private_key_der: zeroize::Zeroizing::new(key.serialize_der()),
        })
    }
}

/// Separate transport material. Private key buffers are erased when dropped.
pub struct TransportIdentity {
    /// DER root certificate to distribute as the explicit trust anchor.
    pub ca_der: Vec<u8>,
    /// DER client/server leaf certificate.
    pub certificate_der: Vec<u8>,
    /// Secret DER PKCS#8 key, unrelated to any consensus or wallet seed.
    pub private_key_der: zeroize::Zeroizing<Vec<u8>>,
}
