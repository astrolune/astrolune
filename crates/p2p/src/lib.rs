// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Specialized binary `P2P` primitives for consensus and block propagation.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

pub mod discovery;
pub mod error;
pub mod exchange;
pub mod frame;
pub mod message;
#[cfg(any(feature = "provisioning", test))]
pub mod provisioning;
pub mod tls;
pub mod transport;

pub use error::NetworkError;
pub use frame::{
    BoundedFrameDecoder, FRAME_HEADER_SIZE, Frame, FrameDecoder, FrameEncoder, MAX_FRAME_SIZE,
};
pub use message::{CompactBlock, MessageKind, Reconstruction};
pub use transport::{
    OwnedFrame, PeerConnection, PeerId, PeerManager, PeerMessage, TcpPeerListener, TransportError,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> types::BlockHeader {
        types::BlockHeader {
            height: 1,
            parent: types::Hash256([0xAA; 32]),
            transactions_root: types::Hash256([1u8; 32]),
            state_root: types::Hash256([2u8; 32]),
            receipts_root: types::Hash256([3u8; 32]),
            committee_root: types::Hash256([4u8; 32]),
            capacity: types::Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
        }
    }

    fn sample_tx(nonce: u64) -> types::Transaction {
        types::Transaction {
            version: types::TRANSACTION_VERSION,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources {
                compute: 1,
                ..types::Resources::ZERO
            },
            chain_id: 1,
            sender: types::Address([0x10; 32]),
            nonce,
            access_list: Vec::new(),
            resource_limit: types::Resources::ZERO,
            payload: vec![0xDE, 0xAD],
            signature: [0xAB; 64],
        }
    }

    #[test]
    fn network_error_display() {
        assert_eq!(format!("{}", NetworkError::InvalidFrame), "invalid frame");
        assert_eq!(
            format!("{}", NetworkError::IncompatiblePeer),
            "incompatible peer"
        );
        assert_eq!(format!("{}", NetworkError::LimitExceeded), "limit exceeded");
    }

    #[test]
    fn network_error_is_error() {
        let err: &dyn std::error::Error = &NetworkError::InvalidFrame;
        assert_eq!(err.to_string(), "invalid frame");
    }

    #[test]
    fn max_frame_size_is_1_mib() {
        assert_eq!(MAX_FRAME_SIZE, 1024 * 1024);
    }

    #[test]
    fn frame_header_size_is_5() {
        assert_eq!(FRAME_HEADER_SIZE, 5);
    }

    #[test]
    fn encode_decode_roundtrip() {
        for kind in [
            MessageKind::Hello,
            MessageKind::Transactions,
            MessageKind::CompactBlock,
            MessageKind::Proposal,
            MessageKind::Vote,
            MessageKind::Finality,
        ] {
            let payload = b"hello world";
            let encoded = FrameEncoder::encode(kind, payload);
            let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
            let frame = decoder.decode(&encoded).unwrap();
            assert_eq!(frame.kind, kind);
            assert_eq!(frame.payload, payload);
        }
    }

    #[test]
    fn encode_decode_empty_payload() {
        let encoded = FrameEncoder::encode(MessageKind::Hello, &[]);
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        let frame = decoder.decode(&encoded).unwrap();
        assert_eq!(frame.kind, MessageKind::Hello);
        assert_eq!(frame.payload.len(), 0);
    }

    #[test]
    fn encode_decode_max_payload() {
        let payload = vec![0xAB; MAX_FRAME_SIZE];
        let encoded = FrameEncoder::encode(MessageKind::Vote, &payload);
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        let frame = decoder.decode(&encoded).unwrap();
        assert_eq!(frame.kind, MessageKind::Vote);
        assert_eq!(frame.payload, &payload[..]);
    }

    #[test]
    fn oversized_frame_rejected() {
        let payload = vec![0u8; 100];
        let encoded = FrameEncoder::encode(MessageKind::Hello, &payload);
        let decoder = BoundedFrameDecoder::new(50);
        assert_eq!(decoder.decode(&encoded), Err(NetworkError::LimitExceeded));
    }

    #[test]
    fn unknown_kind_rejected() {
        let mut bytes = vec![0xFF; 10];
        bytes[0] = 0xFF;
        bytes[1] = 5;
        bytes[2] = 0;
        bytes[3] = 0;
        bytes[4] = 0;
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        assert_eq!(decoder.decode(&bytes), Err(NetworkError::InvalidFrame));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let payload = b"payload";
        let mut encoded = FrameEncoder::encode(MessageKind::Hello, payload);
        encoded.push(0xFF);
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        assert_eq!(decoder.decode(&encoded), Err(NetworkError::InvalidFrame));
    }

    #[test]
    fn too_short_header_rejected() {
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        assert_eq!(decoder.decode(&[0, 1, 2]), Err(NetworkError::InvalidFrame));
        assert_eq!(decoder.decode(&[]), Err(NetworkError::InvalidFrame));
    }

    #[test]
    fn compact_block_reconstruct_complete() {
        let tx0 = sample_tx(0);
        let tx1 = sample_tx(1);
        let tx2 = sample_tx(2);

        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![100, 300],
            prefilled: vec![(1, tx1.clone())],
        };

        let mut known = std::collections::BTreeMap::new();
        known.insert(100, tx0.clone());
        known.insert(300, tx2.clone());

        let result = block.reconstruct(&known);
        match result {
            Reconstruction::Complete(txs) => {
                assert_eq!(txs.len(), 3);
                assert_eq!(txs[0], tx0);
                assert_eq!(txs[1], tx1);
                assert_eq!(txs[2], tx2);
            }
            Reconstruction::Missing(_) => panic!("expected Complete"),
        }
    }

    #[test]
    fn compact_block_reconstruct_missing() {
        let tx0 = sample_tx(0);

        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![100, 200, 300],
            prefilled: vec![],
        };

        let mut known = std::collections::BTreeMap::new();
        known.insert(100, tx0);

        let result = block.reconstruct(&known);
        match result {
            Reconstruction::Complete(_) => panic!("expected Missing"),
            Reconstruction::Missing(missing) => {
                assert_eq!(missing.len(), 2);
                let mut h0 = [0u8; 32];
                h0[..8].copy_from_slice(&200u64.to_le_bytes());
                assert_eq!(missing[0], types::Hash256(h0));
                let mut h1 = [0u8; 32];
                h1[..8].copy_from_slice(&300u64.to_le_bytes());
                assert_eq!(missing[1], types::Hash256(h1));
            }
        }
    }

    #[test]
    fn compact_block_reconstruct_all_prefilled() {
        let tx0 = sample_tx(0);
        let tx1 = sample_tx(1);

        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![],
            prefilled: vec![(0, tx0.clone()), (1, tx1.clone())],
        };

        let known = std::collections::BTreeMap::new();
        let result = block.reconstruct(&known);
        match result {
            Reconstruction::Complete(txs) => {
                assert_eq!(txs, vec![tx0, tx1]);
            }
            Reconstruction::Missing(_) => panic!("expected Complete"),
        }
    }

    #[test]
    fn compact_block_reconstruct_empty() {
        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![],
            prefilled: vec![],
        };
        let known = std::collections::BTreeMap::new();
        let result = block.reconstruct(&known);
        assert_eq!(result, Reconstruction::Complete(vec![]));
    }

    #[test]
    fn message_kind_from_u8_roundtrips() {
        let kinds = [
            MessageKind::Hello,
            MessageKind::Transactions,
            MessageKind::CompactBlock,
            MessageKind::Proposal,
            MessageKind::Vote,
            MessageKind::Finality,
        ];
        for kind in kinds {
            assert_eq!(MessageKind::from_u8(kind as u8), Some(kind));
        }
        assert_eq!(MessageKind::from_u8(6), None);
        assert_eq!(MessageKind::from_u8(255), None);
    }
}
