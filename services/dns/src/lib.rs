// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! `AstroLune DNS` resolves authenticated in-network names.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

pub mod certified;

use core::fmt;
use std::collections::BTreeMap;

use types::Address;

/// Default lease duration of 30 days in seconds.
pub const DEFAULT_LEASE_SECS: u64 = 30 * 24 * 60 * 60;

/// A supported `AstroLune` name record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Record {
    /// Wallet or contract destination.
    Address(Address),
    /// Application service endpoint.
    Service(Vec<u8>),
}

/// A lease binding an owner to a name and record with an expiry window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameLease {
    /// The address that owns this lease.
    pub owner: Address,
    /// The record stored under this name.
    pub record: Record,
    /// Timestamp when the lease was issued.
    pub issued_at: u64,
    /// Timestamp when the lease expires.
    pub expires_at: u64,
}

/// Reserved names that cannot be registered.
const RESERVED_NAMES: &[&str] = &[
    "admin",
    "root",
    "system",
    "astrolune",
    "localhost",
    "daemon",
    "validator",
    "consensus",
    "genesis",
    "null",
    "undefined",
    "www",
    "api",
    "rpc",
    "p2p",
];

/// Character substitution pairs for confusable detection.
/// Each entry is `(from_char, to_char)` where the `to_char` is the real character
/// that the `from_char` may be confused with.
const CONFUSABLE_SUBS: &[(char, char)] = &[
    ('0', 'o'),
    ('1', 'l'),
    ('1', 'i'),
    ('3', 'e'),
    ('5', 's'),
    ('8', 'b'),
];

/// Returns `true` when `name` is one of the reserved system names.
#[must_use]
pub fn is_reserved(name: &str) -> bool {
    RESERVED_NAMES.contains(&name)
}

/// Collapse confusable characters in `name` by applying substitution mappings.
///
/// Digits that look like letters are replaced with their letter equivalent so
/// that visually similar names compare as equal. The returned string is always
/// lowercase ASCII since `normalize_name` must be called first.
#[must_use]
pub fn confusable_key(name: &str) -> String {
    name.chars()
        .map(|c| {
            CONFUSABLE_SUBS
                .iter()
                .find(|&&(from, _)| from == c)
                .map_or(c, |&(_, to)| to)
        })
        .collect()
}

/// Returns `true` when two normalized names are confusable with each other.
///
/// Two names are confusable when they differ only by confusable character
/// substitutions. An exact match is considered confusable with itself.
#[must_use]
pub fn are_confusable(a: &str, b: &str) -> bool {
    confusable_key(a) == confusable_key(b)
}

/// Resolves normalized names from finalized registry state.
pub trait Resolver {
    /// Returns the active record and never falls back to public `DNS` implicitly.
    fn resolve(&self, name: &str) -> Result<Option<Record>, DnsError>;
}

/// Extended resolver that exposes lease and ownership queries.
pub trait ExtendedResolver: Resolver {
    /// Returns the lease for `name` if it exists and is not expired.
    fn lease(&self, name: &str) -> Result<Option<NameLease>, DnsError>;

    /// Returns the owner address for `name` if a valid, non-expired lease exists.
    fn owner(&self, name: &str) -> Result<Option<Address>, DnsError>;
}

/// Name resolution failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsError {
    /// Name encoding or normalization is invalid.
    InvalidName,
    /// Registry state could not be verified.
    InvalidRegistryProof,
    /// The requested name is reserved and cannot be registered.
    ReservedName,
    /// The lease for the requested name has expired.
    LeaseExpired,
    /// The caller is not the owner of the requested lease.
    NotOwner,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => write!(f, "invalid name"),
            Self::InvalidRegistryProof => write!(f, "invalid registry proof"),
            Self::ReservedName => write!(f, "reserved name"),
            Self::LeaseExpired => write!(f, "lease expired"),
            Self::NotOwner => write!(f, "not owner"),
        }
    }
}

impl std::error::Error for DnsError {}

/// Normalize a DNS name for registry lookup.
///
/// * Trims leading/trailing whitespace.
/// * Converts to lowercase ASCII (rejects non-ASCII bytes).
/// * Rejects empty names, names containing dots, and names longer than 64 bytes.
pub fn normalize_name(name: &str) -> Result<String, DnsError> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(DnsError::InvalidName);
    }

    if trimmed.len() > 64 {
        return Err(DnsError::InvalidName);
    }

    for byte in trimmed.as_bytes() {
        if !byte.is_ascii() {
            return Err(DnsError::InvalidName);
        }
    }

    let lowered = trimmed.to_ascii_lowercase();

    if lowered.contains('.') {
        return Err(DnsError::InvalidName);
    }

    Ok(lowered)
}

/// An in-memory resolver backed by a deterministic `BTreeMap`.
#[derive(Clone, Debug, Default)]
pub struct InMemoryResolver {
    records: BTreeMap<String, NameLease>,
}

impl InMemoryResolver {
    /// Create an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `name` with `record` owned by `owner`, issued at `issued_at`
    /// with a lease lasting `lease_secs` seconds.
    pub fn register(
        &mut self,
        name: &str,
        owner: Address,
        record: Record,
        issued_at: u64,
        lease_secs: u64,
    ) -> Result<(), DnsError> {
        let normalized = normalize_name(name)?;

        if is_reserved(&normalized) {
            return Err(DnsError::ReservedName);
        }

        let expires_at = issued_at.saturating_add(lease_secs);
        self.records.insert(
            normalized,
            NameLease {
                owner,
                record,
                issued_at,
                expires_at,
            },
        );

        Ok(())
    }

    /// Renew the lease for `name`. Only the current owner may renew.
    ///
    /// The new expiry is set to the later of `now` or the current expiry,
    /// plus `lease_secs` seconds.
    pub fn renew(
        &mut self,
        name: &str,
        caller: Address,
        now: u64,
        lease_secs: u64,
    ) -> Result<(), DnsError> {
        let normalized = normalize_name(name)?;

        let lease = self
            .records
            .get_mut(&normalized)
            .ok_or(DnsError::InvalidRegistryProof)?;

        if lease.owner != caller {
            return Err(DnsError::NotOwner);
        }

        if now >= lease.expires_at {
            lease.expires_at = now.saturating_add(lease_secs);
        } else {
            lease.expires_at = lease.expires_at.saturating_add(lease_secs);
        }

        Ok(())
    }

    /// Remove the record for `name` if the caller is the owner.
    pub fn remove(&mut self, name: &str, caller: Address) -> Result<bool, DnsError> {
        let normalized = normalize_name(name)?;

        match self.records.get(&normalized) {
            Some(lease) if lease.owner == caller => {
                self.records.remove(&normalized);

                Ok(true)
            }
            Some(_) => Err(DnsError::NotOwner),
            None => Ok(false),
        }
    }

    /// Returns `true` if a non-expired record exists for the given name.
    pub fn has_name(&self, name: &str, current_time: u64) -> Result<bool, DnsError> {
        let normalized = normalize_name(name)?;

        match self.records.get(&normalized) {
            Some(lease) => Ok(current_time < lease.expires_at),
            None => Ok(false),
        }
    }

    /// Purge all expired entries from the resolver and return the count removed.
    pub fn purge_expired(&mut self, current_time: u64) -> usize {
        let before = self.records.len();
        self.records
            .retain(|_, lease| current_time < lease.expires_at);

        before - self.records.len()
    }

    /// Number of records currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` when no records are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Resolver for InMemoryResolver {
    fn resolve(&self, name: &str) -> Result<Option<Record>, DnsError> {
        let normalized = normalize_name(name)?;

        Ok(self
            .records
            .get(&normalized)
            .map(|lease| lease.record.clone()))
    }
}

impl ExtendedResolver for InMemoryResolver {
    fn lease(&self, name: &str) -> Result<Option<NameLease>, DnsError> {
        let normalized = normalize_name(name)?;

        Ok(self.records.get(&normalized).cloned())
    }

    fn owner(&self, name: &str) -> Result<Option<Address>, DnsError> {
        Ok(self.lease(name)?.map(|l| l.owner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_valid_name() {
        assert_eq!(normalize_name("  Alice  ").unwrap(), "alice");
        assert_eq!(normalize_name("BOB").unwrap(), "bob");
        assert_eq!(normalize_name("charlie").unwrap(), "charlie");
    }

    #[test]
    fn normalize_empty_name() {
        assert_eq!(normalize_name(""), Err(DnsError::InvalidName));
        assert_eq!(normalize_name("   "), Err(DnsError::InvalidName));
    }

    #[test]
    fn normalize_too_long() {
        let long = "a".repeat(65);
        assert_eq!(normalize_name(&long), Err(DnsError::InvalidName));
    }

    #[test]
    fn normalize_max_length() {
        let exact = "a".repeat(64);
        assert_eq!(normalize_name(&exact).unwrap(), exact);
    }

    #[test]
    fn normalize_non_ascii() {
        assert_eq!(normalize_name("café"), Err(DnsError::InvalidName));
        assert_eq!(normalize_name("日本語"), Err(DnsError::InvalidName));
    }

    #[test]
    fn normalize_rejects_dots() {
        assert_eq!(normalize_name("a.b"), Err(DnsError::InvalidName));
        assert_eq!(normalize_name("sub.example"), Err(DnsError::InvalidName));
    }

    #[test]
    fn display_and_error_trait() {
        let err = DnsError::InvalidName;
        assert_eq!(format!("{err}"), "invalid name");

        let err: Box<dyn std::error::Error> = Box::new(DnsError::InvalidRegistryProof);
        assert_eq!(err.to_string(), "invalid registry proof");
    }

    #[test]
    fn display_reserved_name() {
        let err = DnsError::ReservedName;
        assert_eq!(format!("{err}"), "reserved name");
    }

    #[test]
    fn display_lease_expired() {
        let err = DnsError::LeaseExpired;
        assert_eq!(format!("{err}"), "lease expired");
    }

    #[test]
    fn display_not_owner() {
        let err = DnsError::NotOwner;
        assert_eq!(format!("{err}"), "not owner");
    }

    #[test]
    fn register_and_resolve() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver
            .register(
                "alice",
                addr,
                Record::Address(addr),
                100,
                DEFAULT_LEASE_SECS,
            )
            .unwrap();
        assert_eq!(resolver.len(), 1);

        let result = resolver.resolve("alice").unwrap().unwrap();
        assert_eq!(result, Record::Address(addr));
    }

    #[test]
    fn resolve_missing_returns_none() {
        let resolver = InMemoryResolver::new();
        assert!(resolver.resolve("nobody").unwrap().is_none());
    }

    #[test]
    fn resolve_case_insensitive() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver
            .register(
                "Alice",
                addr,
                Record::Address(addr),
                100,
                DEFAULT_LEASE_SECS,
            )
            .unwrap();

        assert_eq!(
            resolver.resolve("alice").unwrap(),
            Some(Record::Address(addr))
        );
        assert_eq!(
            resolver.resolve("ALICE").unwrap(),
            Some(Record::Address(addr))
        );
    }

    #[test]
    fn remove_by_owner() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver
            .register(
                "alice",
                addr,
                Record::Address(Address::default()),
                100,
                DEFAULT_LEASE_SECS,
            )
            .unwrap();

        assert!(resolver.remove("alice", addr).unwrap());
        assert!(!resolver.remove("alice", addr).unwrap());
        assert!(resolver.is_empty());
    }

    #[test]
    fn remove_rejects_non_owner() {
        let mut resolver = InMemoryResolver::new();
        let owner = Address::from_bytes([0xAA; 32]);
        let other = Address::from_bytes([0xBB; 32]);
        resolver
            .register(
                "alice",
                owner,
                Record::Address(Address::default()),
                100,
                DEFAULT_LEASE_SECS,
            )
            .unwrap();

        assert_eq!(resolver.remove("alice", other), Err(DnsError::NotOwner));
        assert!(!resolver.is_empty());
    }

    #[test]
    fn has_name() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver
            .register(
                "bob",
                addr,
                Record::Service(vec![1, 2, 3]),
                100,
                DEFAULT_LEASE_SECS,
            )
            .unwrap();

        assert!(resolver.has_name("bob", 200).unwrap());
        assert!(!resolver.has_name("carol", 200).unwrap());
    }

    #[test]
    fn has_name_respects_expiry() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver
            .register("bob", addr, Record::Service(vec![1, 2, 3]), 100, 60)
            .unwrap();

        assert!(resolver.has_name("bob", 150).unwrap());

        let mut expired_resolver = InMemoryResolver::new();
        expired_resolver
            .register("bob", addr, Record::Service(vec![1, 2, 3]), 100, 60)
            .unwrap();

        expired_resolver.records.get_mut("bob").unwrap().expires_at = 0;

        assert!(!expired_resolver.has_name("bob", 1).unwrap());
    }

    #[test]
    fn multiple_records() {
        let mut resolver = InMemoryResolver::new();
        let a1 = Address::default();
        let endpoint = b"application".to_vec();

        resolver
            .register("alice", a1, Record::Address(a1), 100, DEFAULT_LEASE_SECS)
            .unwrap();
        resolver
            .register(
                "bob",
                a1,
                Record::Service(endpoint.clone()),
                100,
                DEFAULT_LEASE_SECS,
            )
            .unwrap();
        resolver
            .register(
                "carol",
                a1,
                Record::Service(vec![42]),
                100,
                DEFAULT_LEASE_SECS,
            )
            .unwrap();

        assert_eq!(resolver.len(), 3);

        assert_eq!(
            resolver.resolve("alice").unwrap(),
            Some(Record::Address(a1))
        );
        assert_eq!(
            resolver.resolve("bob").unwrap(),
            Some(Record::Service(endpoint.clone()))
        );
        assert_eq!(
            resolver.resolve("carol").unwrap(),
            Some(Record::Service(vec![42]))
        );

        let names: Vec<&String> = resolver.records.keys().collect();
        assert_eq!(names, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn register_overwrites_existing() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        let a1 = Address::default();
        let a2 = Address::default();

        resolver
            .register("alice", addr, Record::Address(a1), 100, DEFAULT_LEASE_SECS)
            .unwrap();
        resolver
            .register("alice", addr, Record::Address(a2), 200, DEFAULT_LEASE_SECS)
            .unwrap();

        assert_eq!(resolver.len(), 1);
        assert_eq!(
            resolver.resolve("alice").unwrap(),
            Some(Record::Address(a2))
        );
    }

    #[test]
    fn register_rejects_reserved_names() {
        let addr = Address::default();
        let mut resolver = InMemoryResolver::new();

        for name in RESERVED_NAMES {
            assert_eq!(
                resolver.register(name, addr, Record::Address(addr), 100, DEFAULT_LEASE_SECS),
                Err(DnsError::ReservedName)
            );
        }

        assert!(resolver.is_empty());
    }

    #[test]
    fn confusable_identical() {
        assert!(are_confusable("alice", "alice"));
    }

    #[test]
    fn confusable_zero_vs_o() {
        assert!(are_confusable("a0ice", "aoice"));
        assert!(!are_confusable("a0ice", "abice"));
    }

    #[test]
    fn confusable_one_vs_l() {
        assert!(are_confusable("a1ice", "alice"));
    }

    #[test]
    fn confusable_different_names() {
        assert!(!are_confusable("alice", "bob"));
    }

    #[test]
    fn confusable_length_differs() {
        assert!(!are_confusable("alice", "alicia"));
    }

    #[test]
    fn confusable_three_vs_e() {
        assert!(are_confusable("cr3ator", "creator"));
    }

    #[test]
    fn confusable_five_vs_s() {
        assert!(are_confusable("ba5e", "base"));
    }

    #[test]
    fn confusable_eight_vs_b() {
        assert!(are_confusable("8lue", "blue"));
    }

    #[test]
    fn lease_expiry() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver
            .register("alice", addr, Record::Address(addr), 100, 60)
            .unwrap();

        let lease = resolver.lease("alice").unwrap().unwrap();
        assert_eq!(lease.expires_at, 160);

        assert!(resolver.has_name("alice", 150).unwrap());
        assert!(!resolver.has_name("alice", 160).unwrap());
        assert!(!resolver.has_name("alice", 200).unwrap());
    }

    #[test]
    fn owner_can_renew() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver
            .register("alice", addr, Record::Address(addr), 100, 60)
            .unwrap();

        resolver.renew("alice", addr, 150, 60).unwrap();

        let lease = resolver.lease("alice").unwrap().unwrap();
        assert_eq!(lease.expires_at, 220);
    }

    #[test]
    fn non_owner_cannot_renew() {
        let mut resolver = InMemoryResolver::new();
        let owner = Address::from_bytes([0xAA; 32]);
        let other = Address::from_bytes([0xBB; 32]);
        resolver
            .register("alice", owner, Record::Address(owner), 100, 60)
            .unwrap();

        assert_eq!(
            resolver.renew("alice", other, 150, 60),
            Err(DnsError::NotOwner)
        );
    }

    #[test]
    fn renew_extends_from_later_of_now_or_expiry() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver
            .register("alice", addr, Record::Address(addr), 100, 60)
            .unwrap();

        resolver.renew("alice", addr, 200, 60).unwrap();

        let lease = resolver.lease("alice").unwrap().unwrap();
        assert_eq!(lease.expires_at, 260);
    }

    #[test]
    fn purge_expired_entries() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver
            .register("alice", addr, Record::Address(addr), 100, 60)
            .unwrap();
        resolver
            .register("bob", addr, Record::Address(addr), 100, 300)
            .unwrap();

        resolver.records.get_mut("alice").unwrap().expires_at = 0;

        let purged = resolver.purge_expired(1);
        assert_eq!(purged, 1);
        assert_eq!(resolver.len(), 1);
        assert!(resolver.has_name("bob", 200).unwrap());
    }

    #[test]
    fn extended_resolver_queries() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver
            .register(
                "alice",
                addr,
                Record::Address(addr),
                100,
                DEFAULT_LEASE_SECS,
            )
            .unwrap();

        let owner = ExtendedResolver::owner(&resolver, "alice")
            .unwrap()
            .unwrap();
        assert_eq!(owner, addr);

        let lease = ExtendedResolver::lease(&resolver, "alice")
            .unwrap()
            .unwrap();
        assert_eq!(lease.owner, addr);
        assert_eq!(lease.record, Record::Address(addr));

        assert!(
            ExtendedResolver::owner(&resolver, "nobody")
                .unwrap()
                .is_none()
        );
        assert!(
            ExtendedResolver::lease(&resolver, "nobody")
                .unwrap()
                .is_none()
        );
    }
}