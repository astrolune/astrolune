// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Authenticated application-name resolver and offline registry-call preparation.
#![forbid(unsafe_code)]

mod prepare;

use codec::CanonicalDecode;
use dns::certified::{CertifiedResolver, RegistryTrust, Resolution};
use rpc::json::{JsonValue, to_json};
use std::{
    fs::File,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    time::{Duration, Instant},
};
use types::{Address, Hash256};

const HELP: &str = "AstroLune authenticated name resolver
Usage:
  dns resolve <genesis> <validators> <registry-address> <code-hash> <name> <minimum-height> <rpc-address>
  dns serve <genesis> <validators> <registry-address> <code-hash> <listen-address> <minimum-height> <rpc-address>
  dns prepare register <name> <blocks> <address|service> <value> <new-directory>
  dns prepare update <name> <address|service> <value> <new-directory>
  dns prepare renew <name> <blocks> <new-directory>
  dns prepare transfer <name> <new-owner> <new-directory>
  dns prepare release <name> <new-directory>

Serve accepts one UTF-8 name followed by LF per TCP connection and returns one JSON line.
Prepared input.bin and keys.txt are used with cli sign-call. All addresses are numeric IP:port.
";

fn main() {
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [] => {
            print!("{HELP}");
            Ok(())
        }
        [command] if command == "--help" || command == "help" => {
            print!("{HELP}");
            Ok(())
        }
        [command, rest @ ..] if command == "prepare" => prepare::run(rest),
        [command, rest @ ..] if (command == "resolve" || command == "serve") && rest.len() == 7 => {
            let mut resolver = resolver(rest)?;

            if command == "resolve" {
                println!("{}", response(&resolver.resolve(&rest[4])?));
                return Ok(());
            }

            let address: std::net::SocketAddr =
                rest[4].parse().map_err(|_| "invalid listen address")?;
            let listener = TcpListener::bind(address).map_err(|e| e.to_string())?;
            println!(
                "listening: {}",
                listener.local_addr().map_err(|e| e.to_string())?
            );
            std::io::stdout().flush().map_err(|e| e.to_string())?;

            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };

                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .map_err(|e| e.to_string())?;

                let result = read_name(&mut stream).and_then(|name| resolver.resolve(&name));
                let text = result.map_or_else(
                    |_| "{\"error\":\"resolution unavailable\"}".into(),
                    |value| response(&value),
                );
                let _ = writeln!(stream, "{text}");
            }

            Ok(())
        }
        _ => Err("invalid command; use dns --help".into()),
    }
}

fn resolver(args: &[String]) -> Result<CertifiedResolver, String> {
    let configuration = read(
        Path::new(&args[0]),
        consensus::potb_transition::PotbConfiguration::MAX_BYTES,
    )?;

    let potb = if consensus::potb_transition::PotbConfiguration::is_envelope(&configuration) {
        Some(
            consensus::potb_transition::PotbConfiguration::from_bytes(&configuration)
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };

    let genesis = match &potb {
        Some(profile) => profile.genesis().clone(),
        None => genesis::Genesis::decode(&configuration).map_err(|e| e.to_string())?,
    };

    let bytes = read(Path::new(&args[1]), genesis::MAX_GENESIS_VALIDATORS * 32)?;
    if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
        return Err("invalid validator registry".into());
    }
    let validators = bytes.as_chunks::<32>().0.to_vec();

    let trust = RegistryTrust {
        genesis,
        validators,
        address: Address(rpc::client::decode_hex(&args[2]).map_err(|e| e.to_string())?),
        code_hash: Hash256(rpc::client::decode_hex(&args[3]).map_err(|e| e.to_string())?),
    };

    let minimum = args[5]
        .parse::<u64>()
        .map_err(|_| "invalid minimum height")?;
    let address = args[6].parse().map_err(|_| "invalid numeric RPC address")?;
    let client =
        rpc::TcpRpcClient::new(address, Duration::from_secs(5)).map_err(|e| e.to_string())?;

    match potb {
        Some(profile) => CertifiedResolver::with_potb(trust, client, minimum, &profile),
        None => Ok(CertifiedResolver::new(trust, client, minimum)),
    }
}

fn read(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(max as u64 + 1).read_to_end(&mut bytes))
        .map_err(|e| e.to_string())?;

    if bytes.len() > max {
        return Err("input too large".into());
    }

    Ok(bytes)
}

fn response(value: &Resolution) -> String {
    let mut fields = vec![
        ("name".into(), JsonValue::String(value.name.clone())),
        ("height".into(), JsonValue::String(value.height.to_string())),
    ];

    let lease = value.lease.as_ref().map_or(JsonValue::Null, |lease| {
        JsonValue::Object(vec![
            ("owner".into(), JsonValue::String(lease.owner.to_string())),
            (
                "expires".into(),
                JsonValue::String(lease.expires.to_string()),
            ),
            ("kind".into(), JsonValue::Number(i64::from(lease.kind))),
            ("value".into(), JsonValue::String(hex(&lease.value))),
        ])
    });
    fields.push(("lease".into(), lease));

    to_json(&JsonValue::Object(fields))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut text = String::new();
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }

    text
}

fn read_name(stream: &mut TcpStream) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut bytes = Vec::new();

    while bytes.len() <= 128 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or("request deadline exceeded")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| error.to_string())?;

        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .map_err(|error| error.to_string())?;

        if byte[0] == b'\n' {
            return String::from_utf8(bytes).map_err(|_| "invalid UTF-8".into());
        }

        bytes.push(byte[0]);
    }

    Err("name input too long".into())
}
