// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Synchronous TCP-based JSON-RPC server for external clients.
//!
//! The server listens on a TCP socket and processes JSON-RPC 2.0 requests
//! one at a time per connection. Each request is read as a length-prefixed
//! frame, dispatched to the service handler, and the response is sent back
//! as a length-prefixed frame.
//!
//! Frame format: [4 bytes LE length][JSON payload]

use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use crate::json::{JsonValue, rpc_error, rpc_success, serialize_rpc_response};
use crate::{RpcError, RpcRequest, RpcResponse, RpcService};

/// Maximum request payload size in bytes (1 MiB).
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

/// Maximum response payload size in bytes (8 MiB).
const MAX_RESPONSE_SIZE: usize = 8 * 1024 * 1024;

/// A synchronous TCP-based JSON-RPC server.
///
/// Accepts TCP connections, reads length-prefixed JSON-RPC 2.0 requests,
/// dispatches them to the provided service, and writes length-prefixed
/// JSON-RPC responses.
///
/// # Thread Safety
///
/// The server is thread-safe. Multiple connections are handled sequentially
/// on the calling thread. For concurrent handling, wrap in `std::thread::spawn`.
pub struct TcpRpcServer {
    /// Shared reference to the RPC service implementation.
    service: Arc<Mutex<dyn RpcService>>,
    /// TCP listener bound to the address.
    listener: TcpListener,
}

impl TcpRpcServer {
    /// Creates a new TCP RPC server bound to the given address.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if the address cannot be bound.
    pub fn bind(service: Arc<Mutex<dyn RpcService>>, addr: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;
        Ok(Self { service, listener })
    }

    /// Runs the server, accepting and processing connections until shutdown.
    ///
    /// This is a blocking call that runs until the process is terminated or
    /// the listener socket encounters an error.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` on listener failure.
    pub fn run(&self) -> std::io::Result<()> {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(e) = Self::handle_connection(&self.service, stream) {
                        eprintln!("connection error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("accept error: {e}");
                }
            }
        }
        Ok(())
    }

    /// Returns the local address this server is listening on.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Handles a single client connection.
    ///
    /// Reads requests in a loop, dispatches each to the service, and writes
    /// the response back. The connection is closed when the client disconnects
    /// or an error occurs.
    fn handle_connection(
        service: &Arc<Mutex<dyn RpcService>>,
        mut stream: TcpStream,
    ) -> std::io::Result<()> {
        let peer = stream.peer_addr().ok();
        let mut reader = BufReader::new(stream.try_clone()?);

        loop {
            // Read the 4-byte length prefix
            let mut len_bytes = [0u8; 4];
            match reader.read_exact(&mut len_bytes) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Client disconnected cleanly
                    return Ok(());
                }
                Err(e) => return Err(e),
            }

            let len = u32::from_le_bytes(len_bytes) as usize;
            if len > MAX_REQUEST_SIZE {
                Self::write_error_response(&mut stream, 0, -32600, "request too large")?;
                continue;
            }

            // Read the JSON payload
            let mut payload = vec![0u8; len];
            reader.read_exact(&mut payload)?;

            let Ok(request_str) = String::from_utf8(payload) else {
                Self::write_error_response(&mut stream, 0, -32700, "invalid UTF-8")?;
                continue;
            };

            // Parse and dispatch the request
            match crate::json::parse_rpc_request(&request_str) {
                Ok(rpc_req) => {
                    let response = Self::dispatch(service, &rpc_req);
                    let json = serialize_rpc_response(&response);
                    Self::write_response(&mut stream, &json)?;
                }
                Err(e) => {
                    Self::write_error_response(&mut stream, 0, -32700, &e.to_string())?;
                }
            }

            if let Some(addr) = peer {
                let _ = addr;
            }
        }
    }

    /// Dispatches a parsed JSON-RPC request to the service.
    ///
    /// Maps the JSON-RPC method name to the corresponding `RpcRequest` variant,
    /// invokes the service, and converts the result back to a JSON-RPC response.
    fn dispatch(
        service: &Arc<Mutex<dyn RpcService>>,
        rpc_req: &crate::json::JsonRpcRequest,
    ) -> crate::json::JsonRpcResponse {
        let request = match rpc_req.method.as_str() {
            "receipt" => match receipt_request(&rpc_req.params) {
                Ok(request) => request,
                Err(error) => return rpc_error(rpc_req.id, -32602, error),
            },
            "state_proof" | "state_proof_at" => {
                let Some(key) = rpc_req.params.get("key").and_then(JsonValue::as_str) else {
                    return rpc_error(rpc_req.id, -32602, "missing state key");
                };
                if key.strip_prefix("0x").unwrap_or(key).len() > 512 {
                    return rpc_error(rpc_req.id, -32602, "state key exceeds limit");
                }
                match parse_hex_bytes(key) {
                    Ok(key) => {
                        if rpc_req.method == "state_proof_at" {
                            let height = match request_height(&rpc_req.params) {
                                Ok(height) => height,
                                Err(error) => return rpc_error(rpc_req.id, -32602, error),
                            };
                            RpcRequest::StateProofAt {
                                key: types::StateKey(key),
                                height,
                            }
                        } else {
                            RpcRequest::StateProof(types::StateKey(key))
                        }
                    }
                    Err(error) => return rpc_error(rpc_req.id, -32602, error),
                }
            }
            "block" | "committee_handoff" | "potb_handoff" => {
                let height = match request_height(&rpc_req.params) {
                    Ok(height) => height,
                    Err(error) => return rpc_error(rpc_req.id, -32602, error),
                };
                if rpc_req.method == "potb_handoff" {
                    RpcRequest::PotbHandoff(height)
                } else if rpc_req.method == "committee_handoff" {
                    RpcRequest::CommitteeHandoff(height)
                } else {
                    RpcRequest::Block(height)
                }
            }
            "chain_status" => RpcRequest::ChainStatus,
            "account" => {
                // Extract the address parameter
                let addr_hex = rpc_req.params.get("address").and_then(|v| v.as_str());
                match addr_hex {
                    Some(hex) => match parse_hex_address(hex) {
                        Ok(addr) => RpcRequest::Account(addr),
                        Err(msg) => return rpc_error(rpc_req.id, -32602, msg),
                    },
                    None => {
                        return rpc_error(rpc_req.id, -32602, "missing 'address' parameter");
                    }
                }
            }
            "submit_transaction" => {
                let bytes_hex = rpc_req.params.get("data").and_then(|v| v.as_str());
                match bytes_hex {
                    Some(hex) => match parse_hex_bytes(hex) {
                        Ok(bytes) => RpcRequest::SubmitTransaction(bytes),
                        Err(msg) => return rpc_error(rpc_req.id, -32602, msg),
                    },
                    None => {
                        return rpc_error(rpc_req.id, -32602, "missing 'data' parameter");
                    }
                }
            }
            "submit_potb_admission" | "submit_potb_evidence" | "submit_governance" => {
                match potb_request(rpc_req) {
                    Ok(request) => request,
                    Err(error) => return rpc_error(rpc_req.id, -32602, error),
                }
            }
            _ => {
                return rpc_error(rpc_req.id, -32601, "method not found");
            }
        };

        // Acquire the service lock and process the request
        let Ok(svc) = service.lock() else {
            return rpc_error(rpc_req.id, -32603, "internal error");
        };

        match svc.handle(request) {
            Ok(response) => Self::response_to_json(rpc_req.id, response),
            Err(e) => {
                let code = match e {
                    RpcError::InvalidRequest | RpcError::Unauthorized | RpcError::LimitExceeded => {
                        -32600
                    }
                    RpcError::Unavailable => -32000,
                };
                rpc_error(rpc_req.id, code, e.to_string())
            }
        }
    }

    /// Converts an `RpcResponse` to a JSON-RPC response.
    fn response_to_json(id: i64, response: RpcResponse) -> crate::json::JsonRpcResponse {
        match response {
            RpcResponse::Receipt(None)
            | RpcResponse::StateProofAt(None)
            | RpcResponse::Block(None)
            | RpcResponse::CommitteeHandoff(None)
            | RpcResponse::PotbHandoff(None) => rpc_success(id, JsonValue::Null),
            RpcResponse::Receipt(Some(bytes))
            | RpcResponse::StateProofAt(Some(bytes))
            | RpcResponse::StateProof(bytes)
            | RpcResponse::CommitteeHandoff(Some(bytes))
            | RpcResponse::PotbHandoff(Some(bytes)) => {
                rpc_success(id, JsonValue::String(crate::proof::hex(&bytes)))
            }
            RpcResponse::Block(Some(block)) => match crate::block::to_json(&block) {
                Some(value) => rpc_success(id, value),
                None => rpc_error(id, -32600, "block response exceeds limit"),
            },
            RpcResponse::ChainStatus {
                chain_id,
                finalized_height,
                finalized_block,
            } => {
                #[allow(clippy::cast_possible_wrap)]
                let fields = vec![
                    ("chain_id".into(), JsonValue::Number(i64::from(chain_id))),
                    (
                        "finalized_height".into(),
                        JsonValue::Number(finalized_height as i64),
                    ),
                    (
                        "finalized_block".into(),
                        JsonValue::String(crate::json::hash_to_hex(finalized_block)),
                    ),
                ];
                rpc_success(id, JsonValue::Object(fields))
            }
            RpcResponse::Account(data) => match data {
                Some(bytes) => {
                    #[allow(clippy::format_collect)]
                    let hex: String = bytes.iter().map(|b: &u8| format!("{b:02x}")).collect();
                    rpc_success(id, JsonValue::String(hex))
                }
                None => rpc_success(id, JsonValue::Null),
            },
            RpcResponse::TransactionAccepted(hash) | RpcResponse::PotbAccepted(hash) => {
                rpc_success(id, JsonValue::String(crate::json::hash_to_hex(hash)))
            }
        }
    }

    /// Writes a length-prefixed JSON response to the stream.
    fn write_response(stream: &mut TcpStream, json: &str) -> std::io::Result<()> {
        let bytes = json.as_bytes();
        if bytes.len() > MAX_RESPONSE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response too large",
            ));
        }
        #[allow(clippy::cast_possible_truncation)]
        stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
        stream.write_all(bytes)?;
        stream.flush()
    }

    /// Writes an error response when request parsing itself fails.
    fn write_error_response(
        stream: &mut TcpStream,
        id: i64,
        code: i64,
        message: &str,
    ) -> std::io::Result<()> {
        let response = rpc_error(id, code, message);
        let json = serialize_rpc_response(&response);
        Self::write_response(stream, &json)
    }
}

fn request_height(params: &JsonValue) -> Result<u64, &'static str> {
    params
        .get("height")
        .and_then(|value| match value {
            JsonValue::String(text)
                if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) =>
            {
                text.parse().ok()
            }
            JsonValue::Number(number) => u64::try_from(*number).ok(),
            _ => None,
        })
        .ok_or("invalid or missing block height")
}

fn potb_request(request: &crate::json::JsonRpcRequest) -> Result<RpcRequest, &'static str> {
    let hex = request
        .params
        .get("data")
        .and_then(JsonValue::as_str)
        .ok_or("missing 'data' parameter")?;
    let admission = request.method == "submit_potb_admission";
    let governed = request.method == "submit_governance";
    let limit = if governed {
        consensus::governance::GovernanceCertificate::MAX_BYTES
    } else if admission {
        consensus::admission::AdmissionCertificate::MAX_BYTES
    } else {
        consensus::history::HistoricalEvidence::MAX_BYTES
    };
    if hex.strip_prefix("0x").unwrap_or(hex).len() > limit * 2 {
        return Err("PoTB submission exceeds limit");
    }
    let bytes = parse_hex_bytes(hex).map_err(|_| "invalid submission hex")?;
    Ok(if governed {
        RpcRequest::SubmitGovernance(bytes)
    } else if admission {
        RpcRequest::SubmitPotbAdmission(bytes)
    } else {
        RpcRequest::SubmitPotbEvidence(bytes)
    })
}

/// Parses a hex-encoded address string into an `Address`.
///
/// Accepts both `0x`-prefixed and bare hex strings.
fn parse_hex_address(hex: &str) -> Result<types::Address, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(format!("address must be 64 hex chars, got {}", hex.len()));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "invalid hex character")?;
        bytes[i] = u8::from_str_radix(s, 16).map_err(|_| "invalid hex character")?;
    }
    Ok(types::Address::from_bytes(bytes))
}

/// Parses a hex-encoded byte string into a `Vec<u8>`.
fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if !hex.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().as_chunks::<2>().0 {
        let s = std::str::from_utf8(chunk).map_err(|_| "invalid hex character")?;
        bytes.push(u8::from_str_radix(s, 16).map_err(|_| "invalid hex character")?);
    }
    Ok(bytes)
}

fn receipt_request(params: &JsonValue) -> Result<RpcRequest, &'static str> {
    let text = params
        .get("id")
        .and_then(JsonValue::as_str)
        .ok_or("missing transaction id")?;
    let id = crate::client::decode_hex(text)
        .map(types::Hash256)
        .map_err(|_| "invalid transaction id")?;
    let height = match params.get("height") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::String(text))
            if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(text.parse().map_err(|_| "invalid height")?)
        }
        Some(JsonValue::Number(number)) => {
            Some(u64::try_from(*number).map_err(|_| "invalid height")?)
        }
        _ => return Err("invalid receipt height"),
    };
    Ok(RpcRequest::Receipt { id, height })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryRpcService;

    #[test]
    fn block_height_accepts_full_width_decimal_and_rejects_invalid_input() {
        let service: Arc<Mutex<dyn RpcService>> = Arc::new(Mutex::new(InMemoryRpcService::new(42)));
        for method in [
            "block",
            "committee_handoff",
            "potb_handoff",
            "state_proof_at",
        ] {
            for value in [
                JsonValue::Number(0),
                JsonValue::String(u64::MAX.to_string()),
            ] {
                let req = crate::json::JsonRpcRequest {
                    id: 1,
                    method: method.into(),
                    params: JsonValue::Object(vec![
                        ("height".into(), value),
                        ("key".into(), JsonValue::String("00".into())),
                    ]),
                };
                assert_eq!(
                    TcpRpcServer::dispatch(&service, &req).result,
                    Some(JsonValue::Null)
                );
            }
            for value in [
                JsonValue::Number(-1),
                JsonValue::Null,
                JsonValue::String("+1".into()),
                JsonValue::String("18446744073709551616".into()),
                JsonValue::String("1.2".into()),
            ] {
                let req = crate::json::JsonRpcRequest {
                    id: 1,
                    method: method.into(),
                    params: JsonValue::Object(vec![
                        ("height".into(), value),
                        ("key".into(), JsonValue::String("00".into())),
                    ]),
                };
                assert_eq!(
                    TcpRpcServer::dispatch(&service, &req).error.unwrap().code,
                    -32602
                );
            }
        }
    }

    #[test]
    fn parse_hex_address_valid() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let addr = parse_hex_address(hex).unwrap();
        assert_eq!(addr.as_bytes()[31], 1);
    }

    #[test]
    fn parse_hex_address_with_prefix() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let addr = parse_hex_address(hex).unwrap();
        assert_eq!(addr.as_bytes()[31], 1);
    }

    #[test]
    fn parse_hex_address_wrong_length() {
        let hex = "0001";
        assert!(parse_hex_address(hex).is_err());
    }

    #[test]
    fn parse_hex_bytes_valid() {
        let hex = "deadbeef";
        let bytes = parse_hex_bytes(hex).unwrap();
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_hex_bytes_with_prefix() {
        let hex = "0xdeadbeef";
        let bytes = parse_hex_bytes(hex).unwrap();
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn dispatch_chain_status() {
        let service: Arc<Mutex<dyn RpcService>> = Arc::new(Mutex::new(InMemoryRpcService::new(42)));
        let rpc_req = crate::json::JsonRpcRequest {
            id: 1,
            method: "chain_status".into(),
            params: JsonValue::Object(Vec::new()),
        };
        let response = TcpRpcServer::dispatch(&service, &rpc_req);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn dispatch_unknown_method() {
        let service: Arc<Mutex<dyn RpcService>> = Arc::new(Mutex::new(InMemoryRpcService::new(1)));
        let rpc_req = crate::json::JsonRpcRequest {
            id: 1,
            method: "unknown_method".into(),
            params: JsonValue::Object(Vec::new()),
        };
        let response = TcpRpcServer::dispatch(&service, &rpc_req);
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32601);
    }
}
