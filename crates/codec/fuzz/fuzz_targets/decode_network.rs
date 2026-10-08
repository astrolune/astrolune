// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

#![no_main]
use libfuzzer_sys::fuzz_target;
use node::network_wire::{decode_exchange, encode_exchange, SyncRequest};
use types::Hash256;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(request) = SyncRequest::decode(bytes) {
        assert_eq!(request.encode(), bytes);
    }
    if let Ok(messages) = decode_exchange(Hash256([1; 32]), bytes) {
        assert_eq!(encode_exchange(Hash256([1; 32]), &messages).unwrap(), bytes);
    }
});
