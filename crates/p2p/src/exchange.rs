// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded length-prefixed packets with an absolute I/O deadline per packet.

use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

pub(crate) fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "packet deadline expired"))
}

/// Packet I/O whose underlying reads and writes share an absolute deadline.
/// Buffered transports must also enforce it inside handshakes and record processing.
pub trait PacketIo: Read + Write {
    /// Installs an absolute deadline for the next packet operation.
    fn set_deadline(&mut self, deadline: Instant) -> io::Result<()>;
}

impl PacketIo for TcpStream {
    fn set_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        let timeout = Some(remaining(deadline)?);
        self.set_read_timeout(timeout)?;
        self.set_write_timeout(timeout)
    }
}

fn read_exact(
    stream: &mut impl PacketIo,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_deadline(deadline)?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Reads one packet, checking the advertised size before allocation.
/// A trickle of partial reads cannot extend the absolute deadline.
pub fn read_packet(
    stream: &mut impl PacketIo,
    maximum: usize,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut length = [0; 4];
    read_exact(stream, &mut length, deadline)?;
    let length =
        usize::try_from(u32::from_le_bytes(length)).map_err(|_| io::ErrorKind::InvalidData)?;
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet size exceeds limit",
        ));
    }
    let mut bytes = vec![0; length];
    read_exact(stream, &mut bytes, deadline)?;
    Ok(bytes)
}

/// Writes one bounded packet under a single deadline, including its length prefix.
pub fn write_packet(
    stream: &mut impl PacketIo,
    bytes: &[u8],
    maximum: usize,
    timeout: Duration,
) -> io::Result<()> {
    if bytes.len() > maximum {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::ErrorKind::InvalidInput)?
        .to_le_bytes();
    let deadline = Instant::now() + timeout;
    for mut part in [&length[..], bytes] {
        while !part.is_empty() {
            stream.set_deadline(deadline)?;
            match stream.write(part) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => part = &part[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
    stream.set_deadline(deadline)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn bounded_round_trip_and_oversized_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        write_packet(&mut client, b"hello", 5, Duration::from_secs(1)).unwrap();
        assert_eq!(
            read_packet(&mut server, 5, Duration::from_secs(1)).unwrap(),
            b"hello"
        );
        client.write_all(&u32::MAX.to_le_bytes()).unwrap();
        assert_eq!(
            read_packet(&mut server, 5, Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
