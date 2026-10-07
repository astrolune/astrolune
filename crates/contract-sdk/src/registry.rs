// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Allocation-free name registry protocol and deterministic transition function.
//! Lease time is measured in finalized block heights, never local wall-clock time.

/// Maximum canonical name length.
pub const MAX_NAME: usize = 63;
/// Maximum record value length.
pub const MAX_RECORD: usize = 256;
/// Maximum encoded lease.
pub const MAX_LEASE: usize = 379;
/// Maximum encoded call.
pub const MAX_CALL: usize = 340;
/// Maximum lease extension or remaining lease duration in blocks.
pub const MAX_DURATION: u64 = 1_000_000;
const RESERVED: &[&[u8]] = &[
    b"admin",
    b"root",
    b"system",
    b"astrolune",
    b"localhost",
    b"daemon",
    b"validator",
    b"consensus",
    b"genesis",
    b"null",
    b"undefined",
    b"www",
    b"api",
    b"rpc",
    b"p2p",
];

/// Registry validation or authorization error; no state changes accompany an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// Invalid version, lengths, fields or noncanonical bytes.
    Encoding,
    /// Invalid, reserved or noncanonical name.
    Name,
    /// A live lease already occupies this name or its confusable skeleton.
    Occupied,
    /// No live lease exists for this exact name.
    Expired,
    /// Only the current owner can modify a live lease.
    Owner,
    /// Duration or height arithmetic exceeds the protocol bound.
    Duration,
}

/// One application record, borrowed from canonical input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryRecord<'a> {
    /// Zero is a 32-byte address; one is a printable ASCII service description.
    pub kind: u8,
    /// Bounded record data.
    pub value: &'a [u8],
}
impl RegistryRecord<'_> {
    fn validate(self) -> Result<(), RegistryError> {
        match self.kind {
            0 if self.value.len() == 32 && self.value.iter().any(|b| *b != 0) => Ok(()),
            1 if !self.value.is_empty()
                && self.value.len() <= MAX_RECORD
                && self.value.iter().all(|b| (32..=126).contains(b)) =>
            {
                Ok(())
            }
            _ => Err(RegistryError::Encoding),
        }
    }
}

/// Authenticated lease stored by the contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease<'a> {
    /// Exact canonical spelling, distinguishing confusable collisions.
    pub name: &'a [u8],
    /// Address allowed to renew, transfer, update or release.
    pub owner: [u8; 32],
    /// Registration height.
    pub issued: u64,
    /// Exclusive expiry height.
    pub expires: u64,
    /// Resolved application data.
    pub record: RegistryRecord<'a>,
}
impl<'a> Lease<'a> {
    /// Strictly decodes a bounded lease without allocation.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, RegistryError> {
        let mut reader = Reader(bytes);
        if reader.take(8)? != b"ALDNSL01" {
            return Err(RegistryError::Encoding);
        }
        let name = reader.name()?;
        let owner = reader
            .take(32)?
            .try_into()
            .map_err(|_| RegistryError::Encoding)?;
        let issued = reader.number()?;
        let expires = reader.number()?;
        let record = reader.record()?;
        reader.finish()?;
        if owner == [0; 32] || issued == 0 || expires <= issued {
            return Err(RegistryError::Encoding);
        }
        Ok(Self {
            name,
            owner,
            issued,
            expires,
            record,
        })
    }

    fn encode(self, output: &mut [u8; MAX_LEASE]) -> Result<usize, RegistryError> {
        let mut at = 0;
        for bytes in [
            b"ALDNSL01".as_slice(),
            &[u8::try_from(self.name.len()).map_err(|_| RegistryError::Name)?],
            self.name,
            &self.owner,
            &self.issued.to_le_bytes(),
            &self.expires.to_le_bytes(),
            &[self.record.kind],
            &u16::try_from(self.record.value.len())
                .map_err(|_| RegistryError::Encoding)?
                .to_le_bytes(),
            self.record.value,
        ] {
            output[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        }
        Ok(at)
    }
}

/// Owner-authorized mutation or first-come registration of an expired/free name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryAction<'a> {
    /// Register a free name for a bounded number of blocks.
    Register(u64, RegistryRecord<'a>),
    /// Replace record data, preserving owner and expiry.
    Update(RegistryRecord<'a>),
    /// Extend a live lease, capped at the maximum future duration.
    Renew(u64),
    /// Transfer ownership to a nonzero address.
    Transfer([u8; 32]),
    /// Delete a live lease.
    Release,
}

/// Canonical registry call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryCall<'a> {
    /// Canonical lowercase ASCII name.
    pub name: &'a [u8],
    /// Requested action.
    pub action: RegistryAction<'a>,
}
impl<'a> RegistryCall<'a> {
    /// Validates the complete bounded call and rejects trailing data.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, RegistryError> {
        if bytes.len() > MAX_CALL {
            return Err(RegistryError::Encoding);
        }
        let mut reader = Reader(bytes);
        if reader.take(8)? != b"ALDNSC01" {
            return Err(RegistryError::Encoding);
        }
        let action = reader.take(1)?[0];
        let name = reader.name()?;
        let action = match action {
            0 => RegistryAction::Register(reader.number()?, reader.record()?),
            1 => RegistryAction::Update(reader.record()?),
            2 => RegistryAction::Renew(reader.number()?),
            3 => RegistryAction::Transfer(
                reader
                    .take(32)?
                    .try_into()
                    .map_err(|_| RegistryError::Encoding)?,
            ),
            4 => RegistryAction::Release,
            _ => return Err(RegistryError::Encoding),
        };
        reader.finish()?;
        Ok(Self { name, action })
    }

    /// Encodes a validated call into a caller-owned bounded buffer.
    pub fn encode(self, output: &mut [u8; MAX_CALL]) -> Result<usize, RegistryError> {
        validate_name(self.name)?;
        let (tag, duration, record, owner) = match self.action {
            RegistryAction::Register(duration, record) => (0, Some(duration), Some(record), None),
            RegistryAction::Update(record) => (1, None, Some(record), None),
            RegistryAction::Renew(duration) => (2, Some(duration), None, None),
            RegistryAction::Transfer(owner) => (3, None, None, Some(owner)),
            RegistryAction::Release => (4, None, None, None),
        };
        let mut at = 0;
        let mut append = |bytes: &[u8]| {
            output[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        append(b"ALDNSC01");
        append(&[
            tag,
            u8::try_from(self.name.len()).map_err(|_| RegistryError::Name)?,
        ]);
        append(self.name);
        if let Some(duration) = duration {
            append(&duration.to_le_bytes());
        }
        if let Some(owner) = owner {
            append(&owner);
        }
        if let Some(record) = record {
            record.validate()?;
            append(&[record.kind]);
            append(
                &u16::try_from(record.value.len())
                    .map_err(|_| RegistryError::Encoding)?
                    .to_le_bytes(),
            );
            append(record.value);
        }
        Ok(at)
    }
}

/// Checks a canonical name and reserved/confusable system-name policy.
pub fn validate_name(name: &[u8]) -> Result<(), RegistryError> {
    if name.is_empty()
        || name.len() > MAX_NAME
        || name[0] == b'-'
        || name[name.len() - 1] == b'-'
        || !name
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        || RESERVED.iter().any(|reserved| {
            name.len() == reserved.len()
                && name
                    .iter()
                    .zip(*reserved)
                    .all(|(a, b)| skeleton(*a) == skeleton(*b))
        })
    {
        return Err(RegistryError::Name);
    }
    Ok(())
}

/// Computes the single declared local state key, shared by confusable spellings.
pub fn registry_key(name: &[u8], output: &mut [u8; MAX_NAME + 7]) -> Result<usize, RegistryError> {
    validate_name(name)?;
    output[..7].copy_from_slice(b"dns/v1/");
    for (index, byte) in name.iter().enumerate() {
        output[7 + index] = skeleton(*byte);
    }
    Ok(7 + name.len())
}

fn skeleton(byte: u8) -> u8 {
    match byte {
        b'0' => b'o',
        b'1' => b'l',
        b'3' => b'e',
        b'5' => b's',
        b'8' => b'b',
        _ => byte,
    }
}

/// Computes the next lease; `None` means deletion. Errors leave output/state unpublished.
pub fn transition(
    call: RegistryCall<'_>,
    previous: Option<&[u8]>,
    caller: [u8; 32],
    height: u64,
    output: &mut [u8; MAX_LEASE],
) -> Result<Option<usize>, RegistryError> {
    validate_name(call.name)?;
    if caller == [0; 32] || height == 0 {
        return Err(RegistryError::Owner);
    }
    let previous = previous.map(Lease::decode).transpose()?;
    let live = previous.filter(|lease| height < lease.expires);
    if let RegistryAction::Register(duration, record) = call.action {
        if live.is_some() {
            return Err(RegistryError::Occupied);
        }
        record.validate()?;
        return Lease {
            name: call.name,
            owner: caller,
            issued: height,
            expires: expiry(height, duration)?,
            record,
        }
        .encode(output)
        .map(Some);
    }
    let mut lease = live
        .filter(|lease| lease.name == call.name)
        .ok_or(RegistryError::Expired)?;
    if lease.owner != caller {
        return Err(RegistryError::Owner);
    }
    match call.action {
        RegistryAction::Register(..) => return Err(RegistryError::Encoding),
        RegistryAction::Update(record) => {
            record.validate()?;
            lease.record = record;
        }
        RegistryAction::Renew(duration) => {
            lease.expires = expiry(lease.expires, duration)?;
            if lease.expires - height > MAX_DURATION {
                return Err(RegistryError::Duration);
            }
        }
        RegistryAction::Transfer(owner) => {
            if owner == [0; 32] {
                return Err(RegistryError::Owner);
            }
            lease.owner = owner;
        }
        RegistryAction::Release => return Ok(None),
    }
    lease.encode(output).map(Some)
}

fn expiry(height: u64, duration: u64) -> Result<u64, RegistryError> {
    if duration == 0 || duration > MAX_DURATION {
        return Err(RegistryError::Duration);
    }
    height.checked_add(duration).ok_or(RegistryError::Duration)
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], RegistryError> {
        if self.0.len() < count {
            return Err(RegistryError::Encoding);
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(value)
    }
    fn name(&mut self) -> Result<&'a [u8], RegistryError> {
        let count = usize::from(self.take(1)?[0]);
        let name = self.take(count)?;
        validate_name(name)?;
        Ok(name)
    }
    fn number(&mut self) -> Result<u64, RegistryError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| RegistryError::Encoding)?,
        ))
    }
    fn record(&mut self) -> Result<RegistryRecord<'a>, RegistryError> {
        let kind = self.take(1)?[0];
        let length = u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| RegistryError::Encoding)?,
        );
        let record = RegistryRecord {
            kind,
            value: self.take(usize::from(length))?,
        };
        record.validate()?;
        Ok(record)
    }
    fn finish(self) -> Result<(), RegistryError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(RegistryError::Encoding)
        }
    }
}
