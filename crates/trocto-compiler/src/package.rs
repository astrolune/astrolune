// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Canonical source packages. Native executables and external LLVM IR are never input.

use crate::{CompileError, MAX_SOURCE_BYTES, Program, compile};

const MAGIC: &[u8; 8] = b"ALTROC02";
const HEADER: usize = 20;

/// Maximum encoded Trocto source package, including its versioned header.
pub const MAX_PACKAGE_BYTES: usize = MAX_SOURCE_BYTES + HEADER;

/// Checked UTF-8 source together with its exact compiler and metering profile.
#[derive(Clone, Debug)]
pub struct SourcePackage {
    source: String,
    program: Program,
}

impl SourcePackage {
    /// Checks the source before constructing a publishable package.
    ///
    /// # Errors
    /// Rejects any source the bounded Trocto compiler refuses.
    pub fn new(source: &str) -> Result<Self, CompileError> {
        let program = compile(source)?;
        Ok(Self {
            source: source.to_owned(),
            program,
        })
    }

    /// Decodes exact canonical bytes and rechecks the source's declared profile.
    ///
    /// # Errors
    /// Rejects oversized, truncated, non-UTF-8, trailing or incompatible bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CompileError> {
        let invalid = || CompileError::new(0, "invalid Trocto source package");
        if bytes.len() < HEADER || bytes.len() > MAX_PACKAGE_BYTES || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        let word = |offset| {
            bytes[offset..offset + 4]
                .try_into()
                .map(u32::from_le_bytes)
                .map_err(|_| invalid())
        };
        let language = word(8)?;
        let metering = word(12)?;
        let length = usize::try_from(word(16)?).map_err(|_| invalid())?;
        if length > MAX_SOURCE_BYTES || bytes.len() - HEADER != length {
            return Err(invalid());
        }
        let source = std::str::from_utf8(&bytes[HEADER..]).map_err(|_| invalid())?;
        let package = Self::new(source)?;
        if package.program.language_version() != language
            || package.program.metering_version() != metering
        {
            return Err(CompileError::new(
                8,
                "Trocto source package profile mismatch",
            ));
        }
        Ok(package)
    }

    /// Returns the exact source bytes covered by the program's identity.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the checked program, ready to generate LLVM or compile natively.
    #[must_use]
    pub const fn program(&self) -> &Program {
        &self.program
    }

    /// Encodes the canonical package without platform-specific native artifacts.
    ///
    /// # Panics
    /// Panics if the private compiler-checked source length invariant is violated.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER + self.source.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.program.language_version().to_le_bytes());
        bytes.extend_from_slice(&self.program.metering_version().to_le_bytes());
        // SourcePackage can only contain compiler-checked source of at most 64 KiB.
        bytes.extend_from_slice(
            &u32::try_from(self.source.len())
                .expect("checked source fits u32")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(self.source.as_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_source_is_canonical_and_profile_authenticated() {
        let source = "fn call(input: u64) -> u64 { return input + 1; }";
        let package = SourcePackage::new(source).unwrap();
        let bytes = package.to_bytes();
        let decoded = SourcePackage::decode(&bytes).unwrap();
        assert_eq!(decoded.source(), source);
        assert_eq!(decoded.to_bytes(), bytes);
        assert_eq!(
            decoded.program().source_hash(),
            package.program().source_hash()
        );
        for length in 0..bytes.len() {
            assert!(SourcePackage::decode(&bytes[..length]).is_err());
        }
        for offset in [0, 8, 12, 16] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(SourcePackage::decode(&changed).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(SourcePackage::decode(&trailing).is_err());
    }

    #[test]
    fn rejects_native_and_invalid_source_artifacts() {
        assert!(SourcePackage::new("define i32 @trocto_call() { ret i32 0 }").is_err());
        assert!(SourcePackage::decode(b"MZ executable").is_err());
        let mut bytes = SourcePackage::new("fn call(input: u64) -> u64 { return input; }")
            .unwrap()
            .to_bytes();
        bytes[HEADER] = 0xff;
        assert!(SourcePackage::decode(&bytes).is_err());
    }
}
