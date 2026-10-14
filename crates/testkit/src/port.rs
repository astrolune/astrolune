// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Cross-process TCP port reservations for tests that must name an address
//! before the child process that binds it exists.
//!
//! Most tests never need this module. A test that binds a listener itself asks
//! for port zero and keeps the listener; a test that only has to learn a child's
//! address passes `127.0.0.1:0` and reads the address the child prints. Both are
//! race-free, and both are already used in this workspace.
//!
//! The case this module exists for is different. A multi-node network test has
//! to build the whole peer list *before* any node starts, because every node is
//! given the other nodes' addresses on its command line and cross-wired seeds
//! cannot be learned afterwards. The address is therefore chosen by the test and
//! not by the operating system inside the child.
//!
//! # Why choosing with port zero and letting go does not work
//!
//! The obvious way to choose is to bind port zero, read `local_addr`, drop the
//! listener and pass the address on. That is a time-of-check to time-of-use
//! race, and it fails in one specific way. Port zero asks the kernel for a port
//! out of its automatic range -- `net.ipv4.ip_local_port_range`, by default
//! 32768-60999 on Linux, and the 49152-65535 dynamic range on Windows. Dropping
//! the listener returns the port to that range while the test is still the only
//! thing naming it. Anything else on the machine that binds port zero or opens
//! an outbound connection in the window before the child binds can be handed the
//! same port, and the child then dies with `EADDRINUSE`.
//!
//! That window is wide enough to be observed on a loaded shared runner. It
//! denied a four-leg suite run on 2026-10-10: one leg of four, one test of the
//! fourteen in one binary, reported `Address already in use (os error 98)`, and
//! because the leg stopped at its first failing binary the refusal that followed
//! named cross-leg count drift rather than the race.
//!
//! # How a reservation closes it
//!
//! A reservation is two mechanisms and it needs both.
//!
//! Candidates come from [`FIRST`]..=[`LAST`], a window below every automatic
//! range named above. The kernel never hands a port from this window to a
//! port-zero bind or to an outbound connection, so nothing can be given one by
//! accident; a competitor has to ask for that exact port by number.
//!
//! This workspace's own test processes do ask by number, so the window alone is
//! not enough: two test binaries walking it would still collide. Each candidate
//! is therefore claimed by taking an operating-system lock on a file named for
//! the port, through the same [`std::fs::File::try_lock`] the production writer
//! locks use. [`PortReservation`] holds that lock for as long as the test keeps
//! the value, and the kernel releases it when the holder exits however it exits,
//! so an aborted test leaves no port permanently claimed. A candidate whose lock
//! is already held belongs to another test and the walk moves on.
//!
//! A claimed candidate is then probed by binding it once and dropping that
//! listener immediately. The probe is what notices a port this module did not
//! hand out -- a `TIME_WAIT` remnant of an earlier child, or an unrelated server
//! -- and a declined probe moves the walk on as well. The walk starts at an
//! offset derived from the process identifier, so two binaries that start
//! together do not contend on the same candidate before the lock files separate
//! them.
//!
//! # How to use it
//!
//! Reserve every address the test needs, read [`PortReservation::address`] into
//! the peer list, and keep the reservations alive for the whole test body.
//! Unlike the port-zero pattern this replaces, a reservation is *not* dropped
//! before the child that uses it starts: dropping it is what releases the port.
//!
//! What this does NOT establish: that the port is held against every program on
//! the machine -- a program that binds a port in this window by number without
//! taking the lock file is excluded by nothing here, and the probe is the only
//! thing that notices it; that the remaining probe-to-child window is closed --
//! the probe listener must be gone before the child can bind, so a
//! non-participating program can still take the port in between, and a
//! reservation only makes that require a deliberate bind by number instead of an
//! ordinary ephemeral allocation; that a child binds successfully -- a child may
//! fail for reasons that have nothing to do with its address, and a test must
//! still check; that this window is unused on every host -- it is below the
//! automatic ranges, not reserved by anybody, and on a host running its own
//! service there the probe declines those ports one at a time; or that a test may
//! hold unboundedly many ports -- the window is finite, and a binary that leaks
//! reservations exhausts it and panics rather than quietly reusing one.

use std::{
    fs::{File, OpenOptions},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    sync::atomic::{AtomicU16, Ordering},
};

/// Lowest port this module hands out.
///
/// Below Linux's default `ip_local_port_range` floor of 32768 and Windows'
/// dynamic-range floor of 49152, so a port-zero bind in an unrelated process is
/// never given one of these.
pub const FIRST: u16 = 20_000;

/// Highest port this module hands out.
pub const LAST: u16 = 31_999;

/// Candidate count, used to wrap the walk inside the window.
const SPAN: u16 = LAST - FIRST + 1;

/// Shared walk position, so two threads never offer one candidate twice.
static NEXT: AtomicU16 = AtomicU16::new(0);

/// A port held out of circulation for as long as this value is alive.
///
/// Keep it for the whole test body. Dropping it releases the claim, which is
/// correct only once nothing is expected to be listening on the address.
#[derive(Debug)]
pub struct PortReservation {
    address: SocketAddr,
    // The claim is the operating-system lock on this handle, not the file's
    // contents and not its continued existence; the handle is kept only to hold
    // the lock, and dropping it is what releases the port.
    _claim: File,
}

impl PortReservation {
    /// Returns the reserved socket address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the reserved port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.address.port()
    }
}

/// Reserves a loopback address for a child process to bind.
///
/// # Panics
///
/// Panics when no candidate in [`FIRST`]..=[`LAST`] can be claimed and probed,
/// which means the window is exhausted or the temporary directory is unusable.
/// A test helper reports that by failing rather than by returning an address
/// that is not actually free.
#[must_use = "dropping the reservation releases the port it names"]
pub fn reserve() -> PortReservation {
    reserve_on(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Reserves an address on one local interface for a child process to bind.
///
/// # Panics
///
/// Panics under the conditions [`reserve`] documents.
#[must_use = "dropping the reservation releases the port it names"]
pub fn reserve_on(ip: IpAddr) -> PortReservation {
    let base = walk_offset();
    for _ in 0..SPAN {
        let step = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = FIRST + (base.wrapping_add(step) % SPAN);
        let Some(claim) = claim(port) else { continue };
        let address = SocketAddr::new(ip, port);
        if probe(address) {
            return PortReservation {
                address,
                _claim: claim,
            };
        }
    }
    panic!("no port in {FIRST}..={LAST} could be reserved for a test child process");
}

/// Derives the walk's first candidate from the process identifier.
///
/// Two test binaries started together receive different identifiers, so they
/// begin at different candidates instead of contending on one until the lock
/// files separate them. The multiplier is an odd constant, so consecutive
/// identifiers do not produce adjacent offsets.
fn walk_offset() -> u16 {
    let mixed = std::process::id().wrapping_mul(2_654_435_761);
    // A remainder by SPAN is always below SPAN, which fits a u16 by
    // construction, so the fallback is unreachable rather than a chosen default.
    u16::try_from(mixed % u32::from(SPAN)).unwrap_or(0)
}

/// Takes the cross-process claim on one candidate port.
///
/// Returns [`None`] when another process holds the claim, and also when the lock
/// file cannot be opened at all; both mean the candidate is unusable now, and
/// the caller moves on rather than distinguishing them.
fn claim(port: u16) -> Option<File> {
    let path = std::env::temp_dir().join(format!("astrolune-test-port-{port}.lock"));
    // The file is never truncated and never removed: its contents carry nothing,
    // and removing it while another process held its lock would detach that lock
    // from the name the next claimant opens.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .ok()?;
    file.try_lock().ok()?;
    Some(file)
}

/// Confirms a claimed port is bindable, releasing the probe within the call.
///
/// The probe must not outlive this call: the child process is what binds the
/// address, and it cannot do so while the probe holds it. Any bind error at all
/// declines the candidate, because an address this process cannot bind is not
/// one a child can bind either.
fn probe(address: SocketAddr) -> bool {
    TcpListener::bind(address).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{FIRST, LAST, PortReservation, claim, probe, reserve, reserve_on};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};

    #[test]
    fn a_reservation_sits_inside_the_window_and_below_every_automatic_range() {
        let reservation = reserve();
        assert!((FIRST..=LAST).contains(&reservation.port()));
        // 32768 is Linux's default automatic floor and 49152 is Windows'. The
        // window has to stay below both or the race this module closes returns.
        assert!(reservation.port() < 32_768);
        assert!(reservation.address().ip().is_loopback());
    }

    #[test]
    fn many_reservations_held_at_once_are_all_distinct() {
        let held: Vec<PortReservation> = (0..64).map(|_| reserve()).collect();
        let mut ports: Vec<u16> = held.iter().map(PortReservation::port).collect();
        let total = ports.len();
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports.len(), total, "one port was handed out twice");
    }

    #[test]
    fn a_reserved_port_binds_while_reserved_and_binds_again_after_release() {
        let reservation = reserve();
        let address = reservation.address();
        // The reservation holds the claim and not the socket, so the caller --
        // here this thread, in production a child process -- is what binds it.
        drop(TcpListener::bind(address).expect("a reserved port binds"));
        drop(reservation);
        drop(TcpListener::bind(address).expect("a released port binds again"));
    }

    #[test]
    fn a_claim_excludes_a_second_holder_of_the_same_port() {
        let reservation = reserve();
        assert!(
            claim(reservation.port()).is_none(),
            "a claimed port was claimed a second time"
        );
        let port = reservation.port();
        drop(reservation);
        assert!(
            claim(port).is_some(),
            "a released port could not be claimed again"
        );
    }

    #[test]
    fn a_probe_declines_an_address_a_listener_already_holds() {
        let reservation = reserve();
        let occupied = TcpListener::bind(reservation.address()).expect("the probe bound it");
        assert!(
            !probe(reservation.address()),
            "a probe accepted an address a live listener holds"
        );
        drop(occupied);
        assert!(
            probe(reservation.address()),
            "a probe declined an address nothing holds"
        );
    }

    #[test]
    fn an_explicit_interface_is_preserved() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let reservation = reserve_on(ip);
        assert_eq!(
            reservation.address(),
            SocketAddr::new(ip, reservation.port())
        );
    }
}
