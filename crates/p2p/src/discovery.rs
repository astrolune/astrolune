// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded routing hints for an explicitly scoped, mutually authenticated private network.
//! Discovery never grants consensus authority and must run only after TLS authentication.

use codec::{DecodeError, Decoder};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
};
use types::Hash256;

/// Maximum remote routes and maximum advertisements in one message.
pub const MAX_PEERS: usize = 32;
/// Maximum bytes added around an existing request or response.
pub const MAX_OVERHEAD: usize = 8 + 32 + 1 + MAX_PEERS * 6 + 4;
const MAGIC: &[u8; 8] = b"ALDISC01";

/// An operator-selected IPv4 subnet wholly within RFC 1918 or loopback space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryScope {
    network: u32,
    mask: u32,
}
impl FromStr for DiscoveryScope {
    type Err = &'static str;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = text.split_once('/').ok_or("discovery requires IPv4 CIDR")?;
        let ip: Ipv4Addr = ip.parse().map_err(|_| "invalid discovery network")?;
        let prefix: u32 = prefix.parse().map_err(|_| "invalid discovery prefix")?;
        if !(8..=32).contains(&prefix) {
            return Err("discovery prefix must be 8..32");
        }
        let mask = u32::MAX << (32 - prefix);
        let network = u32::from(ip);
        let last = Ipv4Addr::from(network | !mask);
        if network & mask != network || !private(ip) || !private(last) {
            return Err("discovery scope must be canonical and wholly private or loopback");
        }
        Ok(Self { network, mask })
    }
}
fn private(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback()
}
impl DiscoveryScope {
    /// Checks an exact dial target, excluding zero ports, subnet/broadcast and IPv6 aliases.
    #[must_use]
    pub fn contains(self, address: SocketAddr) -> bool {
        let SocketAddr::V4(address) = address else {
            return false;
        };
        let ip = u32::from(*address.ip());
        address.port() != 0
            && ip & self.mask == self.network
            && (self.mask >= u32::MAX - 1
                || (ip != self.network && ip != self.network | !self.mask))
    }
}

/// Encodes sorted, unique IPv4 routing hints and an unchanged inner protocol frame.
pub fn encode(
    genesis: Hash256,
    peers: &[SocketAddr],
    payload: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, DecodeError> {
    if peers.len() > MAX_PEERS || payload.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(genesis.as_bytes());
    bytes.push(u8::try_from(peers.len()).map_err(|_| DecodeError::LimitExceeded)?);
    let mut previous = None;
    for address in peers {
        if previous.is_some_and(|old| old >= *address) {
            return Err(DecodeError::NonCanonical);
        }
        let SocketAddr::V4(value) = address else {
            return Err(DecodeError::Unsupported);
        };
        if value.port() == 0 {
            return Err(DecodeError::NonCanonical);
        }
        bytes.extend_from_slice(&value.ip().octets());
        bytes.extend_from_slice(&value.port().to_le_bytes());
        previous = Some(*address);
    }
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| DecodeError::LimitExceeded)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Decodes bounded hints, exact framing and the trusted genesis namespace.
/// Returned addresses still require operator-scope filtering and endpoint authentication.
pub fn decode(
    bytes: &[u8],
    genesis: Hash256,
    maximum: usize,
) -> Result<(Vec<SocketAddr>, &[u8]), DecodeError> {
    if bytes.len() > maximum.saturating_add(MAX_OVERHEAD) {
        return Err(DecodeError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.read_exact(8)? != MAGIC || decoder.read_fixed::<32>()? != genesis.0 {
        return Err(DecodeError::Unsupported);
    }
    let count = usize::from(decoder.read_u8()?);
    if count > MAX_PEERS {
        return Err(DecodeError::LimitExceeded);
    }
    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        let address = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(decoder.read_fixed::<4>()?),
            decoder.read_u16()?,
        ));
        if address.port() == 0 || peers.last().is_some_and(|old| *old >= address) {
            return Err(DecodeError::NonCanonical);
        }
        peers.push(address);
    }
    let length = decoder.read_u32()? as usize;
    if length > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    let payload = decoder.read_exact(length)?;
    decoder.finish()?;
    Ok((peers, payload))
}

#[derive(Clone, Copy)]
struct Route {
    seed: bool,
    verified: bool,
    failures: u8,
}
/// Volatile, bounded route directory; configured seeds survive failures and restart.
pub struct PeerDirectory {
    scope: Option<DiscoveryScope>,
    local: SocketAddr,
    routes: BTreeMap<SocketAddr, Route>,
}
impl PeerDirectory {
    /// Installs operator-supplied seeds. Discovery is disabled without a scope.
    pub fn new(
        scope: Option<DiscoveryScope>,
        local: SocketAddr,
        seeds: &[SocketAddr],
    ) -> Result<Self, &'static str> {
        if seeds.len() > MAX_PEERS || scope.is_some_and(|scope| !scope.contains(local)) {
            return Err("invalid peer directory scope or size");
        }
        let mut directory = Self {
            scope,
            local,
            routes: BTreeMap::new(),
        };
        for address in seeds {
            if *address == local {
                continue;
            }
            if address.port() == 0 || scope.is_some_and(|scope| !scope.contains(*address)) {
                return Err("bootstrap peer is outside discovery scope");
            }
            directory.routes.insert(
                *address,
                Route {
                    seed: true,
                    verified: false,
                    failures: 0,
                },
            );
        }
        Ok(directory)
    }
    /// Learns only bounded, in-scope hints from an authenticated exchange.
    pub fn learn(&mut self, peers: &[SocketAddr]) {
        let Some(scope) = self.scope else {
            return;
        };
        for address in peers.iter().take(MAX_PEERS) {
            if *address != self.local && scope.contains(*address) && self.routes.len() < MAX_PEERS {
                self.routes.entry(*address).or_insert(Route {
                    seed: false,
                    verified: false,
                    failures: 0,
                });
            }
        }
    }
    /// Re-advertises only endpoints whose authenticated exchange succeeded, plus ourselves.
    #[must_use]
    pub fn advertisement(&self) -> Vec<SocketAddr> {
        if self.scope.is_none() {
            return Vec::new();
        }
        let mut values: Vec<_> = self
            .routes
            .iter()
            .filter(|(_, route)| route.verified)
            .map(|(address, _)| *address)
            .take(MAX_PEERS - 1)
            .collect();
        values.push(self.local);
        values.sort_unstable();
        values
    }
    /// Current bounded connection candidates; call again when discovery changes them.
    #[must_use]
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.routes.keys().copied().collect()
    }
    /// Records endpoint verification or removes an unreachable discovered route after eight failures.
    pub fn result(&mut self, address: SocketAddr, success: bool) {
        let Some(route) = self.routes.get_mut(&address) else {
            return;
        };
        if success {
            route.verified = true;
            route.failures = 0;
        } else {
            route.verified = false;
            route.failures = route.failures.saturating_add(1);
            if !route.seed && route.failures >= 8 {
                self.routes.remove(&address);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn address(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }
    #[test]
    fn scope_and_directory_never_expand_operator_authority_or_unbounded_hints() {
        for bad in [
            "0.0.0.0/0",
            "8.0.0.0/8",
            "10.0.0.1/24",
            "172.0.0.0/8",
            "127.0.0.0/7",
            "::1/128",
        ] {
            assert!(bad.parse::<DiscoveryScope>().is_err());
        }
        let scope: DiscoveryScope = "127.0.0.0/8".parse().unwrap();
        let mut directory = PeerDirectory::new(Some(scope), address(1), &[address(2)]).unwrap();
        directory.learn(&[
            address(3),
            "10.0.0.1:4".parse().unwrap(),
            address(0),
            address(1),
        ]);
        assert_eq!(directory.addresses(), vec![address(2), address(3)]);
        assert_eq!(directory.advertisement(), vec![address(1)]);
        directory.result(address(3), true);
        assert_eq!(directory.advertisement(), vec![address(1), address(3)]);
        for _ in 0..8 {
            directory.result(address(2), false);
            directory.result(address(3), false);
        }
        assert_eq!(directory.addresses(), vec![address(2)]);
        directory.learn(&(3..100).map(address).collect::<Vec<_>>());
        assert_eq!(directory.addresses().len(), MAX_PEERS);
        let mut fixed = PeerDirectory::new(None, address(1), &[address(2)]).unwrap();
        fixed.learn(&[address(3)]);
        assert_eq!(fixed.addresses(), vec![address(2)]);
    }
    #[test]
    fn envelope_is_canonical_bounded_and_genesis_bound() {
        let genesis = Hash256([1; 32]);
        let bytes = encode(genesis, &[address(1), address(2)], b"hello", 5).unwrap();
        let (peers, payload) = decode(&bytes, genesis, 5).unwrap();
        assert_eq!(encode(genesis, &peers, payload, 5).unwrap(), bytes);
        for length in 0..bytes.len() {
            assert!(decode(&bytes[..length], genesis, 5).is_err());
        }
        assert!(decode(&bytes, Hash256::ZERO, 5).is_err());
        assert!(decode(&bytes, genesis, 4).is_err());
        assert!(encode(genesis, &[address(1), address(1)], b"", 0).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing, genesis, 5).is_err());
        for offset in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[offset] ^= 255;
            if let Ok((peers, payload)) = decode(&changed, genesis, 5) {
                assert_eq!(encode(genesis, &peers, payload, 5).unwrap(), changed);
            }
        }
    }
}
