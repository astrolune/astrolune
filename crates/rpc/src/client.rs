// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Typed client for the daemon's length-prefixed JSON-RPC protocol.
//! One connection per call, one absolute deadline, and no automatic retries.
//! This transport has no authentication: use a trusted local endpoint or tunnel.

use std::{
    fmt::{self, Write as _},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use codec::CanonicalDecode;
use types::{AccountState, Address, Hash256};

use crate::json::{JsonValue, parse_json, to_json};

/// Maximum canonical transaction accepted by the network exchange.
pub const MAX_TRANSACTION_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 4096;

mod potb;

/// Finalized head reported by the contacted node; not a cryptographic proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainStatus {
    /// Chain replay-protection identifier.
    pub chain_id: u32,
    /// Finalized block height.
    pub finalized_height: u64,
    /// Finalized block commitment.
    pub finalized_block: Hash256,
}

/// Client failure. A transport/protocol failure after submission can be ambiguous.
#[derive(Debug)]
pub enum ClientError {
    /// Connection, deadline, or incomplete frame.
    Io(io::Error),
    /// Response violates the expected JSON-RPC or typed result schema.
    Protocol(&'static str),
    /// Request would exceed the supported bound.
    LimitExceeded,
    /// A matching JSON-RPC error response was received.
    Remote {
        /// Remote error code.
        code: i64,
        /// Remote error description.
        message: String,
    },
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "RPC transport: {error}"),
            Self::Protocol(message) => write!(f, "RPC protocol: {message}"),
            Self::LimitExceeded => write!(f, "RPC request or history exceeds the configured limit"),
            Self::Remote { code, message } => {
                // Escape terminal controls supplied by an untrusted server.
                write!(f, "RPC rejected request ({code}): {message:?}")
            }
        }
    }
}
impl std::error::Error for ClientError {}
impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Bounded, synchronous RPC client. Numeric socket addresses avoid unbounded DNS.
pub struct TcpRpcClient {
    address: SocketAddr,
    timeout: Duration,
}

impl TcpRpcClient {
    /// Creates a client with a positive per-call deadline of at most 60 seconds.
    pub fn new(address: SocketAddr, timeout: Duration) -> Result<Self, ClientError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(ClientError::Protocol("timeout must be in (0, 60s]"));
        }
        Ok(Self { address, timeout })
    }

    /// Reads the contacted node's finalized head.
    pub fn chain_status(&self) -> Result<ChainStatus, ClientError> {
        let value = self.call("chain_status", JsonValue::Object(vec![]))?;
        let chain_id = number_field(&value, "chain_id")?;
        let finalized_height = number_field(&value, "finalized_height")?;
        let finalized_block = hash_value(value.get("finalized_block"))?;
        Ok(ChainStatus {
            chain_id: u32::try_from(chain_id)
                .map_err(|_| ClientError::Protocol("invalid chain id"))?,
            finalized_height,
            finalized_block,
        })
    }

    /// Reads a finalized account; absence is distinct from a zero-balance account.
    pub fn account(&self, address: Address) -> Result<Option<AccountState>, ClientError> {
        let value = self.call(
            "account",
            JsonValue::Object(vec![(
                "address".into(),
                JsonValue::String(address.to_string()),
            )]),
        )?;
        if value == JsonValue::Null {
            return Ok(None);
        }
        let hex = value
            .as_str()
            .ok_or(ClientError::Protocol("invalid account"))?;
        let bytes = decode_hex::<16>(hex)?;
        AccountState::decode(&bytes)
            .map(Some)
            .map_err(|_| ClientError::Protocol("invalid canonical account"))
    }

    /// Submits exactly these bytes once. Acceptance does not mean finalization.
    /// Callers should retain the signed bytes and verify the returned identifier.
    pub fn submit_transaction(&self, bytes: &[u8]) -> Result<Hash256, ClientError> {
        if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(ClientError::LimitExceeded);
        }
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(hex, "{byte:02x}");
        }
        let value = self.call(
            "submit_transaction",
            JsonValue::Object(vec![("data".into(), JsonValue::String(hex))]),
        )?;
        hash_value(Some(&value))
    }

    fn call(&self, method: &str, params: JsonValue) -> Result<JsonValue, ClientError> {
        self.call_bounded(method, params, MAX_RESPONSE_BYTES)
    }

    /// Fetches one untrusted handoff, with bounded framing and an exact-height check.
    /// Decoding does not establish authority; use `HandoffVerifier::apply` to authenticate it.
    pub fn committee_handoff(
        &self,
        height: u64,
    ) -> Result<Option<consensus::rotation::CommitteeHandoff>, ClientError> {
        use consensus::rotation::CommitteeHandoff;
        let value = self.call_bounded(
            "committee_handoff",
            JsonValue::Object(vec![(
                "height".into(),
                JsonValue::String(height.to_string()),
            )]),
            CommitteeHandoff::MAX_BYTES * 2 + 1024,
        )?;
        if value == JsonValue::Null {
            return Ok(None);
        }
        let hex = value
            .as_str()
            .ok_or(ClientError::Protocol("invalid handoff response"))?;
        let bytes = proof_hex(hex, CommitteeHandoff::MAX_BYTES)?;
        let handoff = CommitteeHandoff::from_bytes(&bytes)
            .map_err(|_| ClientError::Protocol("invalid canonical handoff"))?;
        if handoff.header.height != height {
            return Err(ClientError::Protocol("handoff height mismatch"));
        }
        Ok(Some(handoff))
    }

    /// Advances authenticated authority to `target_height` (the next header to verify).
    /// Reads at most `max_steps` transitions under one total deadline in (0, 3600s].
    /// A missing or invalid transition stops immediately; only the verified prefix is
    /// retained on failure, allowing callers to resume from the last trusted position.
    pub fn advance_handoffs(
        &self,
        trusted: &mut consensus::rotation::HandoffVerifier,
        target_height: u64,
        max_steps: u64,
        timeout: Duration,
    ) -> Result<(), ClientError> {
        self.advance_handoffs_with(trusted, target_height, max_steps, timeout, |_| Ok(()))
    }

    /// Streams each authenticated transition to a bounded consumer before advancing authority.
    /// A consumer failure retains the previously accepted prefix, just like a transport failure.
    pub fn advance_handoffs_with(
        &self,
        trusted: &mut consensus::rotation::HandoffVerifier,
        target_height: u64,
        max_steps: u64,
        timeout: Duration,
        mut accept: impl FnMut(&consensus::rotation::CommitteeHandoff) -> Result<(), ClientError>,
    ) -> Result<(), ClientError> {
        let steps = target_height
            .checked_sub(trusted.current().height())
            .ok_or(ClientError::Protocol(
                "handoff target precedes trusted position",
            ))?;
        if steps > max_steps {
            return Err(ClientError::LimitExceeded);
        }
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err(ClientError::Protocol(
                "handoff timeout must be in (0, 3600s]",
            ));
        }
        let deadline = Instant::now() + timeout;
        for _ in 0..steps {
            let client = Self {
                address: self.address,
                timeout: self.timeout.min(remaining(deadline)?),
            };
            let handoff = client
                .committee_handoff(trusted.current().height())?
                .ok_or(ClientError::Protocol("required handoff unavailable"))?;
            let mut next = trusted.clone();
            next.apply(&handoff)
                .map_err(|_| ClientError::Protocol("handoff authentication failed"))?;
            remaining(deadline)?;
            accept(&handoff)?;
            *trusted = next;
        }
        Ok(())
    }

    /// Fetches an untrusted proof bundle. Call its `verify` method with independent genesis/keys.
    pub fn state_proof(
        &self,
        key: &types::StateKey,
    ) -> Result<crate::CertifiedStateProof, ClientError> {
        self.read_state_proof(key, None)?
            .ok_or(ClientError::Protocol("missing proof response"))
    }

    /// Fetches a proof for exactly this height. None means unavailable retained history.
    /// Callers must still authenticate the certificate and state witnesses independently.
    pub fn state_proof_at(
        &self,
        key: &types::StateKey,
        height: u64,
    ) -> Result<Option<crate::CertifiedStateProof>, ClientError> {
        self.read_state_proof(key, Some(height))
    }

    fn read_state_proof(
        &self,
        key: &types::StateKey,
        height: Option<u64>,
    ) -> Result<Option<crate::CertifiedStateProof>, ClientError> {
        if key.len() > state::MAX_STATE_KEY_BYTES {
            return Err(ClientError::LimitExceeded);
        }
        let mut fields = vec![(
            "key".into(),
            JsonValue::String(crate::proof::hex(key.as_bytes())),
        )];
        if let Some(height) = height {
            fields.push(("height".into(), JsonValue::String(height.to_string())));
        }
        let value = self.call_bounded(
            if height.is_some() {
                "state_proof_at"
            } else {
                "state_proof"
            },
            JsonValue::Object(fields),
            8 * 1024 * 1024,
        )?;
        if height.is_some() && value == JsonValue::Null {
            return Ok(None);
        }
        let hex = value
            .as_str()
            .ok_or(ClientError::Protocol("invalid proof response"))?;
        if hex.len() > crate::CertifiedStateProof::MAX_BYTES * 2
            || !hex.len().is_multiple_of(2)
            || !hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(ClientError::LimitExceeded);
        }
        let bytes = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair)
                    .map_err(|_| ClientError::Protocol("invalid proof hex"))?;
                u8::from_str_radix(text, 16).map_err(|_| ClientError::Protocol("invalid proof hex"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proof = crate::CertifiedStateProof::from_bytes(&bytes)
            .map_err(|_| ClientError::Protocol("invalid canonical proof"))?;
        if height.is_some_and(|height| proof.header.map_or(0, |header| header.height) != height) {
            return Err(ClientError::Protocol("state proof height mismatch"));
        }
        Ok(Some(proof))
    }

    /// Fetches a retained receipt proof. None does not prove that a transaction never finalized.
    /// Authenticate the returned bundle with independently supplied genesis and keys.
    pub fn receipt(
        &self,
        id: Hash256,
        height: Option<u64>,
    ) -> Result<Option<crate::CertifiedReceiptProof>, ClientError> {
        let mut fields = vec![("id".into(), JsonValue::String(id.to_string()))];
        if let Some(height) = height {
            fields.push(("height".into(), JsonValue::String(height.to_string())));
        }
        let value = self.call_bounded("receipt", JsonValue::Object(fields), 8 * 1024 * 1024)?;
        if value == JsonValue::Null {
            return Ok(None);
        }
        let hex = value
            .as_str()
            .ok_or(ClientError::Protocol("invalid receipt response"))?;
        let bytes = proof_hex(hex, crate::CertifiedReceiptProof::MAX_BYTES)?;
        crate::CertifiedReceiptProof::from_bytes(&bytes)
            .map(Some)
            .map_err(|_| ClientError::Protocol("invalid receipt proof"))
    }
    /// Polls receipt availability under one total deadline; never resubmits a transaction.
    /// None means timeout, not rejection. The caller must authenticate any returned proof.
    pub fn wait_receipt(
        &self,
        id: Hash256,
        timeout: Duration,
    ) -> Result<Option<crate::CertifiedReceiptProof>, ClientError> {
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err(ClientError::Protocol("wait timeout must be in (0, 3600s]"));
        }
        let deadline = Instant::now() + timeout;
        loop {
            let Some(remaining) = deadline
                .checked_duration_since(Instant::now())
                .filter(|time| !time.is_zero())
            else {
                return Ok(None);
            };
            let client = Self {
                address: self.address,
                timeout: self.timeout.min(remaining),
            };
            match client.receipt(id, None) {
                Ok(Some(proof)) => return Ok(Some(proof)),
                Ok(None) => {}
                Err(ClientError::Io(_)) if Instant::now() >= deadline => return Ok(None),
                Err(error) => return Err(error),
            }
            let pause = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250));
            std::thread::sleep(pause);
        }
    }
    fn call_bounded(
        &self,
        method: &str,
        params: JsonValue,
        max_response: usize,
    ) -> Result<JsonValue, ClientError> {
        let request = to_json(&JsonValue::Object(vec![
            ("jsonrpc".into(), JsonValue::String("2.0".into())),
            ("id".into(), JsonValue::Number(1)),
            ("method".into(), JsonValue::String(method.into())),
            ("params".into(), params),
        ]));
        let length = u32::try_from(request.len()).map_err(|_| ClientError::LimitExceeded)?;
        let mut frame = length.to_le_bytes().to_vec();
        frame.extend_from_slice(request.as_bytes());
        let deadline = Instant::now() + self.timeout;
        let mut stream = TcpStream::connect_timeout(&self.address, remaining(deadline)?)?;
        let mut bytes = frame.as_slice();
        while !bytes.is_empty() {
            stream.set_write_timeout(Some(remaining(deadline)?))?;
            match stream.write(bytes) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => bytes = &bytes[count..],
                // Socket timeouts may round down on Windows. Keep the same request and
                // retry only the unfinished I/O against our original absolute deadline.
                Err(error) if retryable_io(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut prefix = [0; 4];
        read_exact(&mut stream, &mut prefix, deadline)?;
        let length = u32::from_le_bytes(prefix) as usize;
        if length == 0 || length > max_response {
            return Err(ClientError::Protocol("invalid response frame size"));
        }
        let mut payload = vec![0; length];
        read_exact(&mut stream, &mut payload, deadline)?;
        let text =
            std::str::from_utf8(&payload).map_err(|_| ClientError::Protocol("invalid UTF-8"))?;
        let value = parse_json(text).map_err(|_| ClientError::Protocol("invalid JSON"))?;
        response_result(&value)
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

fn retryable_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn read_exact(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if retryable_io(&error) => {}
            Err(error) => return Err(error),
        }
    }
    // Also reject a final chunk delivered after the overall deadline.
    remaining(deadline)?;
    Ok(())
}

fn response_result(value: &JsonValue) -> Result<JsonValue, ClientError> {
    if value.get("jsonrpc").and_then(JsonValue::as_str) != Some("2.0")
        || value.get("id").and_then(JsonValue::as_i64) != Some(1)
    {
        return Err(ClientError::Protocol("response version or id mismatch"));
    }
    match (value.get("result"), value.get("error")) {
        (Some(result), None) => Ok(result.clone()),
        (None, Some(error)) => {
            let code = error
                .get("code")
                .and_then(JsonValue::as_i64)
                .ok_or(ClientError::Protocol("invalid error code"))?;
            let message = error
                .get("message")
                .and_then(JsonValue::as_str)
                .ok_or(ClientError::Protocol("invalid error message"))?;
            Err(ClientError::Remote {
                code,
                message: message.into(),
            })
        }
        _ => Err(ClientError::Protocol(
            "expected exactly one result or error",
        )),
    }
}

fn number_field(value: &JsonValue, field: &str) -> Result<u64, ClientError> {
    value
        .get(field)
        .and_then(JsonValue::as_i64)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(ClientError::Protocol("missing or invalid unsigned integer"))
}

fn hash_value(value: Option<&JsonValue>) -> Result<Hash256, ClientError> {
    let text = value
        .and_then(JsonValue::as_str)
        .ok_or(ClientError::Protocol("invalid hash"))?;
    decode_hex(text).map(Hash256)
}

/// Decodes an exact-size hexadecimal value, optionally prefixed with `0x`.
pub fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], ClientError> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.len() != N * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ClientError::Protocol("invalid hexadecimal value"));
    }
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| ClientError::Protocol("invalid hexadecimal value"))?;
    }
    Ok(result)
}

impl From<io::ErrorKind> for ClientError {
    fn from(kind: io::ErrorKind) -> Self {
        Self::Io(kind.into())
    }
}

fn proof_hex(hex: &str, max: usize) -> Result<Vec<u8>, ClientError> {
    if hex.len() > max * 2
        || !hex.len().is_multiple_of(2)
        || !hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(ClientError::LimitExceeded);
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| ClientError::Protocol("invalid proof hex"))?;
            u8::from_str_radix(text, 16).map_err(|_| ClientError::Protocol("invalid proof hex"))
        })
        .collect()
}
