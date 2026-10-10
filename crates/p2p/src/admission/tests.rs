// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Deterministic replay checks for bounded admission control.
//!
//! These tests supply every tick explicitly and use exhaustive loops instead of
//! randomized property generation. They establish arithmetic exactness, bounded
//! tables and bounded bans; they establish nothing about a distributed attack,
//! about throughput, or about any consensus outcome.

use super::*;

/// Endpoint of an arbitrary loopback connection used where identity is irrelevant.
fn peer(port: u16) -> PeerId {
    PeerId::new(&format!("127.0.0.1:{port}"))
}

/// Endpoint of one connection from a distinct IPv4 source.
fn source(index: u32) -> PeerId {
    PeerId::new(&format!("{}:1", Ipv4Addr::from(0x0A00_0000 + index)))
}

/// Configuration with every rate budget removed from the comparison.
fn unlimited() -> AdmissionConfig {
    let wide = ClassLimits {
        per_class: [ClassLimit::new(
            RateLimit::new(u64::MAX, u64::MAX),
            RateLimit::new(u64::MAX, u64::MAX),
        ); MessageClass::COUNT],
    };
    AdmissionConfig {
        peer_limits: wide,
        source_limits: wide,
        global_limits: wide,
        connection_attempts: RateLimit::new(u64::MAX, u64::MAX),
        ..AdmissionConfig::default()
    }
}

/// Drains `bucket` one token at a time at `tick_ms`, returning the count removed.
fn drain(bucket: &mut TokenBucket, tick_ms: u64) -> u64 {
    let mut admitted = 0;
    while bucket.try_take(tick_ms, 1) {
        admitted += 1;
    }
    admitted
}

#[test]
fn refill_in_many_small_steps_admits_exactly_as_many_as_one_large_step() {
    for per_second in [1_u64, 2, 3, 7, 97, 333, 999, 1_000, 1_001, 65_537] {
        for step_ms in [1_u64, 3, 7, 13, 100] {
            let steps = 97_u64;
            let total_ms = steps * step_ms;
            let limit = RateLimit::new(per_second, 100_000_000);

            let mut stepped = TokenBucket::new(limit, 0);
            stepped.take(limit.burst);
            let mut small = 0;
            for step in 1..=steps {
                small += drain(&mut stepped, step * step_ms);
            }

            let mut single = TokenBucket::new(limit, 0);
            single.take(limit.burst);
            let large = drain(&mut single, total_ms);

            let exact = total_ms * per_second / 1_000;
            assert_eq!(
                small, large,
                "per_second={per_second} step_ms={step_ms} steps={steps}: \
                 {small} admitted in small steps but {large} in one step"
            );
            assert_eq!(
                small, exact,
                "per_second={per_second} step_ms={step_ms} steps={steps}: \
                 {small} admitted but exact integer accrual is {exact}"
            );
        }
    }
}

#[test]
fn score_decay_in_many_small_steps_removes_exactly_as_much_as_one_large_step() {
    for per_second in [1_u32, 3, 7, 97, 333, 1_001] {
        for step_ms in [1_u64, 3, 7, 13] {
            let steps = 97_u64;
            let total_ms = steps * step_ms;
            let config = AdmissionConfig {
                offence_weights: [1_000_000; Offence::COUNT],
                ban_threshold: u32::MAX,
                score_ceiling: 1_000_000,
                score_decay_per_second: per_second,
                ..unlimited()
            };

            let mut stepped = AdmissionController::new(config);
            assert!(!stepped.record_offence(&peer(1), Offence::InvalidFrame, 0));
            for step in 1..=steps {
                let _ = stepped.score(&peer(1), step * step_ms);
            }

            let mut single = AdmissionController::new(config);
            assert!(!single.record_offence(&peer(1), Offence::InvalidFrame, 0));

            let small = stepped.score(&peer(1), total_ms);
            let large = single.score(&peer(1), total_ms);
            let exact =
                1_000_000 - u32::try_from(total_ms * u64::from(per_second) / 1_000).unwrap();
            assert_eq!(
                small, large,
                "per_second={per_second} step_ms={step_ms}: score {small} after small \
                 steps but {large} after one step"
            );
            assert_eq!(
                small, exact,
                "per_second={per_second} step_ms={step_ms}: score {small} but exact \
                 integer decay leaves {exact}"
            );
        }
    }
}

#[test]
fn refill_never_exceeds_the_configured_burst_at_any_elapsed_tick() {
    for burst in [0_u64, 1, 5, 64] {
        for per_second in [0_u64, 1, 1_000, u64::MAX] {
            for elapsed in [0_u64, 1, 999, 1_000, 1_001, 86_400_000, u64::MAX] {
                let mut bucket = TokenBucket::new(RateLimit::new(per_second, burst), 0);
                bucket.take(burst);
                bucket.advance(elapsed);
                assert!(
                    bucket.tokens() <= burst,
                    "burst={burst} per_second={per_second} elapsed={elapsed}: \
                     bucket holds {} tokens",
                    bucket.tokens()
                );
            }
        }
    }
}

#[test]
fn a_tick_below_the_highest_observed_tick_accrues_nothing_and_never_refunds() {
    let mut bucket = TokenBucket::new(RateLimit::new(1_000, 10), 0);
    bucket.advance(60_000);
    assert_eq!(
        drain(&mut bucket, 60_000),
        10,
        "a full bucket admits its burst"
    );
    for earlier in [59_999_u64, 30_000, 1, 0] {
        bucket.advance(earlier);
        assert_eq!(
            bucket.tokens(),
            0,
            "tick={earlier}: a backwards tick granted {} tokens",
            bucket.tokens()
        );
        assert!(
            !bucket.try_take(earlier, 1),
            "tick={earlier}: a backwards tick admitted a charge"
        );
    }
    bucket.advance(60_010);
    assert_eq!(
        bucket.tokens(),
        10,
        "refill resumes from the highest observed tick, not the backwards one"
    );
}

#[test]
fn backwards_ticks_never_widen_a_connection_attempt_or_message_budget() {
    let config = AdmissionConfig {
        connection_attempts: RateLimit::new(1, 1),
        max_connections_per_source: 64,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    controller.admit_inbound(&peer(1), 100_000).unwrap();
    for earlier in [99_999_u64, 50_000, 1, 0] {
        assert_eq!(
            controller.admit_inbound(&peer(2), earlier),
            Err(Refusal::AttemptRate),
            "tick={earlier}: a backwards tick refilled the attempt budget"
        );
    }

    let mut charged = AdmissionController::new(AdmissionConfig {
        peer_limits: ClassLimits {
            per_class: [ClassLimit::new(RateLimit::new(1, 1), RateLimit::new(0, 1_000));
                MessageClass::COUNT],
        },
        ..unlimited()
    });
    charged
        .charge_class(&peer(3), MessageClass::Blocks, 1, 100_000)
        .unwrap();
    for earlier in [99_999_u64, 50_000, 1, 0] {
        assert_eq!(
            charged.charge_class(&peer(3), MessageClass::Blocks, 1, earlier),
            Err(Refusal::MessageRate(Tier::Peer)),
            "tick={earlier}: a backwards tick refilled the message budget"
        );
    }
}

#[test]
fn a_zero_rate_bucket_admits_its_burst_once_and_nothing_afterwards() {
    let mut bucket = TokenBucket::new(RateLimit::new(0, 4), 0);
    assert_eq!(drain(&mut bucket, 0), 4, "the initial burst is admitted");
    for tick in [1_u64, 1_000, 86_400_000, u64::MAX] {
        assert_eq!(
            drain(&mut bucket, tick),
            0,
            "tick={tick}: a zero-rate bucket refilled"
        );
    }
}

#[test]
fn every_message_kind_maps_to_one_class_and_every_class_is_reachable() {
    for (index, class) in MessageClass::ALL.into_iter().enumerate() {
        assert_eq!(
            class as usize, index,
            "class={class}: discriminant disagrees with its position in ALL"
        );
    }
    let kinds = [
        (MessageKind::Hello, MessageClass::Handshake),
        (MessageKind::Transactions, MessageClass::Transactions),
        (MessageKind::CompactBlock, MessageClass::Blocks),
        (MessageKind::Proposal, MessageClass::Consensus),
        (MessageKind::Vote, MessageClass::Consensus),
        (MessageKind::Finality, MessageClass::Consensus),
    ];
    for (kind, expected) in kinds {
        assert_eq!(
            MessageClass::of(kind),
            expected,
            "kind={kind:?}: charged to the wrong class"
        );
    }
    for class in MessageClass::ALL {
        assert!(
            kinds.iter().any(|(_, mapped)| *mapped == class),
            "class={class}: no message kind maps to it"
        );
    }
}

#[test]
fn exhausting_one_class_budget_leaves_every_other_class_fully_available() {
    for exhausted in MessageClass::ALL {
        let mut controller = AdmissionController::default();
        let limit = AdmissionConfig::default().peer_limits.get(exhausted);
        for index in 0..limit.messages.burst {
            controller
                .charge_class(&peer(1), exhausted, 0, 0)
                .unwrap_or_else(|error| {
                    panic!("class={exhausted} index={index}: budgeted charge refused: {error}")
                });
        }
        assert!(
            controller.charge_class(&peer(1), exhausted, 0, 0).is_err(),
            "class={exhausted}: the budget did not run out after {} messages",
            limit.messages.burst
        );
        for other in MessageClass::ALL {
            if other == exhausted {
                continue;
            }
            controller
                .charge_class(&peer(1), other, 0, 0)
                .unwrap_or_else(|error| {
                    panic!("exhausted={exhausted} other={other}: starved class refused: {error}")
                });
        }
    }
}

#[test]
fn a_byte_heavy_message_is_refused_by_the_byte_budget_not_the_message_budget() {
    let mut controller = AdmissionController::default();
    let limit = AdmissionConfig::default()
        .peer_limits
        .get(MessageClass::Handshake);
    let oversized = usize::try_from(limit.bytes.burst).unwrap() + 1;
    assert_eq!(
        controller.charge_class(&peer(1), MessageClass::Handshake, oversized, 0),
        Err(Refusal::ByteRate(Tier::Peer)),
        "a payload above the per-peer byte burst must be refused by the byte budget"
    );
    controller
        .charge_class(&peer(1), MessageClass::Handshake, 1, 0)
        .expect("the message budget must be untouched by a refused byte charge");
}

#[test]
fn a_refused_charge_deducts_nothing_from_any_tier() {
    let mut controller = AdmissionController::new(AdmissionConfig {
        peer_limits: ClassLimits {
            per_class: [ClassLimit::new(RateLimit::new(0, 2), RateLimit::new(0, 50));
                MessageClass::COUNT],
        },
        source_limits: ClassLimits {
            per_class: [ClassLimit::new(RateLimit::new(0, 8), RateLimit::new(0, 100));
                MessageClass::COUNT],
        },
        ..unlimited()
    });
    assert_eq!(
        controller.charge_class(&peer(1), MessageClass::Blocks, 80, 0),
        Err(Refusal::ByteRate(Tier::Peer)),
        "80 bytes exceeds the 50-byte per-peer burst"
    );
    controller
        .charge_class(&peer(1), MessageClass::Blocks, 10, 0)
        .expect("a refused charge must not have spent a message token");
    controller
        .charge_class(&peer(1), MessageClass::Blocks, 10, 0)
        .expect("a refused charge must not have spent the second message token");
    controller
        .charge_class(&peer(2), MessageClass::Blocks, 50, 0)
        .expect("a refused per-peer charge must not have spent the source byte budget");
    assert_eq!(
        controller.charge_class(&peer(3), MessageClass::Blocks, 50, 0),
        Err(Refusal::ByteRate(Tier::Source)),
        "exactly 20 of the 100 source bytes were spent before the refused charge"
    );
}

#[test]
fn the_source_tier_keeps_its_debt_when_a_peer_reconnects_from_a_new_port() {
    let mut controller = AdmissionController::new(AdmissionConfig {
        peer_limits: ClassLimits {
            per_class: [ClassLimit::new(RateLimit::new(0, 4), RateLimit::new(0, u64::MAX));
                MessageClass::COUNT],
        },
        source_limits: ClassLimits {
            per_class: [ClassLimit::new(RateLimit::new(0, 4), RateLimit::new(0, u64::MAX));
                MessageClass::COUNT],
        },
        ..unlimited()
    });
    for index in 0..4 {
        controller
            .charge_class(&peer(1), MessageClass::Consensus, 0, 0)
            .unwrap_or_else(|error| panic!("index={index}: budgeted charge refused: {error}"));
    }
    for port in 2..8_u16 {
        assert_eq!(
            controller.charge_class(&peer(port), MessageClass::Consensus, 0, 0),
            Err(Refusal::MessageRate(Tier::Source)),
            "port={port}: a new connection reset the source budget"
        );
    }
}

#[test]
fn the_global_tier_refuses_a_charge_that_no_single_peer_budget_would_refuse() {
    let mut controller = AdmissionController::new(AdmissionConfig {
        global_limits: ClassLimits {
            per_class: [ClassLimit::new(RateLimit::new(0, 2), RateLimit::new(0, u64::MAX));
                MessageClass::COUNT],
        },
        ..unlimited()
    });
    for index in 0..2_u32 {
        controller
            .charge_class(&source(index), MessageClass::Transactions, 0, 0)
            .unwrap_or_else(|error| panic!("index={index}: budgeted charge refused: {error}"));
    }
    for index in 2..6_u32 {
        assert_eq!(
            controller.charge_class(&source(index), MessageClass::Transactions, 0, 0),
            Err(Refusal::MessageRate(Tier::Global)),
            "index={index}: the process-wide budget admitted a charge past its burst"
        );
    }
}

#[test]
fn charging_zero_bytes_still_spends_one_message_token() {
    let mut controller = AdmissionController::new(AdmissionConfig {
        peer_limits: ClassLimits {
            per_class: [ClassLimit::new(RateLimit::new(0, 3), RateLimit::new(0, u64::MAX));
                MessageClass::COUNT],
        },
        ..unlimited()
    });
    for index in 0..3 {
        controller
            .charge_message(&peer(1), MessageKind::Vote, 0, 0)
            .unwrap_or_else(|error| panic!("index={index}: budgeted charge refused: {error}"));
    }
    assert_eq!(
        controller.charge_message(&peer(1), MessageKind::Vote, 0, 0),
        Err(Refusal::MessageRate(Tier::Peer)),
        "an empty payload must still consume a message token"
    );
}

#[test]
fn every_offence_class_carries_its_documented_default_weight() {
    let config = AdmissionConfig::default();
    let expected = [
        (Offence::InvalidFrame, DEFAULT_WEIGHT_INVALID_FRAME),
        (Offence::OversizedPayload, DEFAULT_WEIGHT_OVERSIZED_PAYLOAD),
        (
            Offence::UnauthenticatedMessage,
            DEFAULT_WEIGHT_UNAUTHENTICATED_MESSAGE,
        ),
        (Offence::RateLimitBreach, DEFAULT_WEIGHT_RATE_LIMIT_BREACH),
        (
            Offence::ProtocolViolation,
            DEFAULT_WEIGHT_PROTOCOL_VIOLATION,
        ),
    ];
    for (index, offence) in Offence::ALL.into_iter().enumerate() {
        assert_eq!(
            offence as usize, index,
            "offence={offence}: discriminant disagrees with its position in ALL"
        );
    }
    for (offence, weight) in expected {
        assert_eq!(
            config.weight(offence),
            weight,
            "offence={offence}: default weight is {} not {weight}",
            config.weight(offence)
        );
        let mut controller = AdmissionController::new(AdmissionConfig {
            ban_threshold: u32::MAX,
            ..AdmissionConfig::default()
        });
        assert!(
            !controller.record_offence(&peer(1), offence, 0),
            "offence={offence}: a single offence banned the source"
        );
        assert_eq!(
            controller.score(&peer(1), 0),
            weight,
            "offence={offence}: recorded score disagrees with its weight"
        );
    }
}

#[test]
fn every_network_error_maps_to_a_named_offence_class() {
    let expected = [
        (NetworkError::InvalidFrame, Offence::InvalidFrame),
        (NetworkError::LimitExceeded, Offence::OversizedPayload),
        (NetworkError::IncompatiblePeer, Offence::ProtocolViolation),
    ];
    for (error, offence) in expected {
        assert_eq!(
            Offence::of_network_error(error),
            offence,
            "error={error}: classified as the wrong offence"
        );
        let mut controller = AdmissionController::new(AdmissionConfig {
            ban_threshold: u32::MAX,
            ..AdmissionConfig::default()
        });
        assert!(!controller.record_network_error(&peer(1), error, 0));
        assert_eq!(
            controller.score(&peer(1), 0),
            AdmissionConfig::default().weight(offence),
            "error={error}: recorded a score the mapped offence does not carry"
        );
    }
}

#[test]
fn crossing_the_ban_threshold_bans_for_exactly_the_configured_duration() {
    let config = AdmissionConfig {
        offence_weights: [10; Offence::COUNT],
        ban_threshold: 20,
        score_decay_per_second: 0,
        ban_duration_ms: 5_000,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    assert!(
        !controller.record_offence(&peer(1), Offence::InvalidFrame, 1_000),
        "one offence of weight 10 must not reach a threshold of 20"
    );
    assert!(
        controller.record_offence(&peer(1), Offence::InvalidFrame, 1_000),
        "two offences of weight 10 must reach a threshold of 20"
    );
    assert_eq!(
        controller.ban_remaining_ms(&peer(1), 1_000),
        5_000,
        "the ban must run for exactly the configured duration"
    );
    for tick in [1_000_u64, 3_000, 5_999] {
        assert!(
            controller.is_banned(&peer(1), tick),
            "tick={tick}: the ban expired before its deadline"
        );
    }
}

#[test]
fn a_ban_expires_at_its_exact_tick_and_the_source_is_admitted_again() {
    let config = AdmissionConfig {
        offence_weights: [20; Offence::COUNT],
        ban_threshold: 20,
        ban_duration_ms: 5_000,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    assert!(controller.record_offence(&peer(1), Offence::ProtocolViolation, 1_000));
    assert_eq!(
        controller.admit_inbound(&peer(1), 6_000 - 1),
        Err(Refusal::Banned),
        "the ban must still apply one millisecond before it expires"
    );
    assert!(
        !controller.is_banned(&peer(1), 6_000),
        "the ban must expire at exactly its deadline"
    );
    controller
        .admit_inbound(&peer(1), 6_000)
        .expect("an expired ban must admit the source again");
    assert_eq!(
        controller.ban_remaining_ms(&peer(1), 6_000),
        0,
        "no ban time may remain after expiry"
    );
    assert_eq!(
        controller.score(&peer(1), 6_000),
        0,
        "a served ban must leave the score cleared"
    );
}

#[test]
fn offences_below_the_threshold_decay_back_to_zero_without_a_ban() {
    let config = AdmissionConfig {
        offence_weights: [10; Offence::COUNT],
        ban_threshold: 100,
        score_decay_per_second: 5,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    for round in 0..5_u64 {
        let tick = round * 4_000;
        assert!(
            !controller.record_offence(&peer(1), Offence::UnauthenticatedMessage, tick),
            "round={round}: an offence every four seconds reached the threshold"
        );
        assert_eq!(
            controller.score(&peer(1), tick + 2_000),
            0,
            "round={round}: a weight of 10 did not decay within two seconds at 5 per second"
        );
    }
    assert!(
        !controller.is_banned(&peer(1), 20_000),
        "decaying offences must never produce a ban"
    );
}

#[test]
fn the_score_saturates_at_its_ceiling_instead_of_wrapping() {
    let config = AdmissionConfig {
        offence_weights: [u32::MAX; Offence::COUNT],
        ban_threshold: u32::MAX,
        score_ceiling: 100,
        score_decay_per_second: 0,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    for round in 0..32 {
        assert!(
            !controller.record_offence(&peer(1), Offence::OversizedPayload, 0),
            "round={round}: a threshold of u32::MAX must be unreachable below the ceiling"
        );
        assert_eq!(
            controller.score(&peer(1), 0),
            100,
            "round={round}: the score left its ceiling"
        );
    }
}

#[test]
fn a_rate_limit_breach_is_itself_scored_and_eventually_bans_the_source() {
    let config = AdmissionConfig {
        peer_limits: ClassLimits {
            per_class: [ClassLimit::new(RateLimit::new(0, 1), RateLimit::new(0, u64::MAX));
                MessageClass::COUNT],
        },
        offence_weights: [8; Offence::COUNT],
        ban_threshold: 16,
        score_decay_per_second: 0,
        ban_duration_ms: 1_000,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    controller
        .charge_class(&peer(1), MessageClass::Blocks, 0, 0)
        .expect("the first charge fits the burst of one");
    assert_eq!(
        controller.charge_class(&peer(1), MessageClass::Blocks, 0, 0),
        Err(Refusal::MessageRate(Tier::Peer)),
        "the second charge must exhaust a burst of one"
    );
    assert_eq!(
        controller.score(&peer(1), 0),
        8,
        "a refused charge must be scored as a rate-limit breach"
    );
    assert_eq!(
        controller.charge_class(&peer(1), MessageClass::Blocks, 0, 0),
        Err(Refusal::MessageRate(Tier::Peer)),
        "the third charge must also be refused"
    );
    assert!(
        controller.is_banned(&peer(1), 0),
        "two scored breaches must reach a threshold of 16"
    );
    assert_eq!(
        controller.charge_class(&peer(2), MessageClass::Blocks, 0, 0),
        Err(Refusal::Banned),
        "a banned source must be refused before any budget is consulted"
    );
}

#[test]
fn a_banned_source_is_refused_on_inbound_admission_and_outbound_dialling() {
    let config = AdmissionConfig {
        offence_weights: [64; Offence::COUNT],
        ban_threshold: 64,
        ban_duration_ms: 60_000,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    assert!(controller.record_offence(&peer(1), Offence::InvalidFrame, 0));
    assert_eq!(
        controller.admit_inbound(&peer(2), 0),
        Err(Refusal::Banned),
        "an inbound connection from a banned source must be refused"
    );
    assert_eq!(
        controller.admit_outbound(&peer(3), 0),
        Err(Refusal::Banned),
        "a banned source must not be dialled"
    );
    assert_eq!(
        controller.total_connections(),
        0,
        "a refused connection must not occupy a slot"
    );
}

#[test]
fn one_source_cannot_occupy_more_than_its_configured_share_of_the_total_slots() {
    let config = AdmissionConfig {
        max_total_connections: 16,
        max_connections_per_source: 4,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    for port in 1..=4_u16 {
        controller
            .admit_inbound(&peer(port), 0)
            .unwrap_or_else(|error| {
                panic!("port={port}: admission within the share refused: {error}")
            });
    }
    for port in 5..=8_u16 {
        assert_eq!(
            controller.admit_inbound(&peer(port), 0),
            Err(Refusal::SourceConnections),
            "port={port}: one source exceeded its concurrent allowance"
        );
    }
    assert_eq!(controller.source_connections("127.0.0.1:1"), 4);
    for index in 0..12_u32 {
        controller
            .admit_inbound(&source(index), 0)
            .unwrap_or_else(|error| {
                panic!("index={index}: a distinct source was refused: {error}")
            });
    }
    assert_eq!(
        controller.total_connections(),
        16,
        "the remaining slots must be available to other sources"
    );
}

#[test]
fn the_total_connection_cap_holds_across_many_distinct_sources() {
    let config = AdmissionConfig {
        max_total_connections: 4,
        max_connections_per_source: 4,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    for index in 0..4_u32 {
        controller
            .admit_inbound(&source(index), 0)
            .unwrap_or_else(|error| {
                panic!("index={index}: admission within the cap refused: {error}")
            });
    }
    for index in 4..16_u32 {
        assert_eq!(
            controller.admit_inbound(&source(index), 0),
            Err(Refusal::TotalConnections),
            "index={index}: the total cap admitted a connection past its bound"
        );
    }
    assert_eq!(controller.total_connections(), 4);
}

#[test]
fn released_slots_return_to_both_the_total_and_the_source_count() {
    let config = AdmissionConfig {
        max_total_connections: 2,
        max_connections_per_source: 2,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    for round in 0..8_u16 {
        controller
            .admit_inbound(&peer(round), 0)
            .unwrap_or_else(|error| {
                panic!("round={round}: a released slot was not reusable: {error}")
            });
        assert_eq!(
            controller.total_connections(),
            1,
            "round={round}: exactly one slot must be held"
        );
        assert_eq!(
            controller.source_connections("127.0.0.1:0"),
            1,
            "round={round}: the source count must track the held slot"
        );
        controller.release_connection(&peer(round));
        assert_eq!(
            controller.total_connections(),
            0,
            "round={round}: the released slot was not returned"
        );
    }
}

#[test]
fn releasing_an_unadmitted_or_already_released_peer_saturates_at_zero() {
    let mut controller = AdmissionController::new(unlimited());
    for round in 0..4 {
        controller.release_connection(&peer(1));
        assert_eq!(
            controller.total_connections(),
            0,
            "round={round}: releasing an unadmitted peer wrapped the total"
        );
        assert_eq!(
            controller.source_connections("127.0.0.1:1"),
            0,
            "round={round}: releasing an unadmitted peer wrapped the source count"
        );
    }
    controller.admit_inbound(&peer(1), 0).unwrap();
    controller.release_connection(&peer(1));
    controller.release_connection(&peer(1));
    assert_eq!(
        controller.total_connections(),
        0,
        "a double release must not wrap the total"
    );
}

#[test]
fn connection_attempts_from_one_source_are_bounded_over_time() {
    let config = AdmissionConfig {
        connection_attempts: RateLimit::new(2, 3),
        max_connections_per_source: 64,
        max_total_connections: 64,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    for port in 1..=3_u16 {
        controller
            .admit_inbound(&peer(port), 0)
            .unwrap_or_else(|error| {
                panic!("port={port}: an attempt within the burst failed: {error}")
            });
    }
    for port in 4..=8_u16 {
        assert_eq!(
            controller.admit_inbound(&peer(port), 0),
            Err(Refusal::AttemptRate),
            "port={port}: the attempt burst admitted more than three attempts"
        );
    }
    assert_eq!(
        controller.admit_inbound(&peer(9), 499),
        Err(Refusal::AttemptRate),
        "two attempts per second must not restore a token within 499 milliseconds"
    );
    controller
        .admit_inbound(&peer(10), 500)
        .expect("two attempts per second must restore one token at 500 milliseconds");
}

#[test]
fn repeated_connect_and_disconnect_churn_is_bounded_by_the_attempt_budget() {
    let config = AdmissionConfig {
        connection_attempts: RateLimit::new(0, 5),
        max_connections_per_source: 1,
        max_total_connections: 8,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    for round in 0..5_u16 {
        controller
            .admit_inbound(&peer(round), 0)
            .unwrap_or_else(|error| {
                panic!("round={round}: churn within the burst refused: {error}")
            });
        controller.release_connection(&peer(round));
    }
    for round in 5..16_u16 {
        assert_eq!(
            controller.admit_inbound(&peer(round), 0),
            Err(Refusal::AttemptRate),
            "round={round}: closing a connection restored an attempt token"
        );
    }
}

#[test]
fn a_refused_attempt_is_itself_charged_so_refusals_cannot_be_retried_freely() {
    let config = AdmissionConfig {
        connection_attempts: RateLimit::new(0, 4),
        max_connections_per_source: 1,
        max_total_connections: 8,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    controller.admit_inbound(&peer(1), 0).unwrap();
    for round in 2..=4_u16 {
        assert_eq!(
            controller.admit_inbound(&peer(round), 0),
            Err(Refusal::SourceConnections),
            "round={round}: expected the per-source connection cap to refuse"
        );
    }
    assert_eq!(
        controller.admit_inbound(&peer(5), 0),
        Err(Refusal::AttemptRate),
        "a refused attempt must still spend an attempt token"
    );
}

#[test]
fn ipv4_ipv6_bare_and_bracketed_endpoints_resolve_to_their_source_address() {
    let accepted: [(&str, IpAddr); 12] = [
        ("127.0.0.1:8080", IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ("127.0.0.1", IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ("  127.0.0.1:1  ", IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ("10.0.0.5:0", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
        ("255.255.255.255:65535", IpAddr::V4(Ipv4Addr::BROADCAST)),
        ("[::1]:8080", IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ("[::1]", IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ("::1", IpAddr::V6(Ipv6Addr::LOCALHOST)),
        (
            "[2001:db8::1]:443",
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        ),
        (
            "2001:db8::1",
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        ),
        ("[::ffff:127.0.0.1]:9", IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ("::ffff:7f00:1", IpAddr::V4(Ipv4Addr::LOCALHOST)),
    ];
    for (endpoint, expected) in accepted {
        assert_eq!(
            source_address(endpoint),
            Some(expected),
            "endpoint={endpoint:?}: resolved to the wrong source address"
        );
    }
    let rejected = [
        "",
        "   ",
        "unknown",
        "localhost:80",
        "fe80::1%eth0",
        "[::1",
        "::1]",
        "127.0.0.1:",
        "127.0.0.1:abc",
        "1.2.3.4.5:1",
        "[]",
        ":",
    ];
    for endpoint in rejected {
        assert_eq!(
            source_address(endpoint),
            None,
            "endpoint={endpoint:?}: an unparsable endpoint produced a source address"
        );
    }
}

#[test]
fn an_ipv4_mapped_ipv6_endpoint_shares_the_allowance_of_its_ipv4_form() {
    let config = AdmissionConfig {
        max_connections_per_source: 1,
        max_total_connections: 8,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    controller
        .admit_inbound(&PeerId::new("127.0.0.1:1"), 0)
        .expect("the first connection from the source must be admitted");
    for endpoint in ["[::ffff:127.0.0.1]:2", "::ffff:7f00:1"] {
        assert_eq!(
            controller.admit_inbound(&PeerId::new(endpoint), 0),
            Err(Refusal::SourceConnections),
            "endpoint={endpoint:?}: an alternate representation doubled the allowance"
        );
    }
}

#[test]
fn per_source_caps_apply_independently_to_distinct_ipv4_and_ipv6_sources() {
    let config = AdmissionConfig {
        max_connections_per_source: 2,
        max_total_connections: 64,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    let groups: [[&str; 3]; 3] = [
        ["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"],
        ["[::1]:1", "[::1]:2", "[::1]:3"],
        ["[2001:db8::1]:1", "[2001:db8::1]:2", "[2001:db8::1]:3"],
    ];
    for group in groups {
        for endpoint in &group[..2] {
            controller
                .admit_inbound(&PeerId::new(endpoint), 0)
                .unwrap_or_else(|error| {
                    panic!("endpoint={endpoint:?}: admission within the cap refused: {error}")
                });
        }
        assert_eq!(
            controller.admit_inbound(&PeerId::new(group[2]), 0),
            Err(Refusal::SourceConnections),
            "endpoint={:?}: the per-source cap did not apply",
            group[2]
        );
    }
    assert_eq!(
        controller.total_connections(),
        6,
        "each distinct source must receive its own allowance"
    );
}

#[test]
fn an_unparsable_endpoint_is_refused_rather_than_admitted() {
    let mut controller = AdmissionController::new(unlimited());
    for endpoint in ["unknown", "", "localhost:1"] {
        let id = PeerId::new(endpoint);
        assert_eq!(
            controller.admit_inbound(&id, 0),
            Err(Refusal::UnknownSource),
            "endpoint={endpoint:?}: an unparsable endpoint was admitted inbound"
        );
        assert_eq!(
            controller.admit_outbound(&id, 0),
            Err(Refusal::UnknownSource),
            "endpoint={endpoint:?}: an unparsable endpoint was dialled"
        );
        assert_eq!(
            controller.charge_class(&id, MessageClass::Blocks, 1, 0),
            Err(Refusal::UnknownSource),
            "endpoint={endpoint:?}: an unparsable endpoint was charged"
        );
        assert!(
            !controller.record_offence(&id, Offence::InvalidFrame, 0),
            "endpoint={endpoint:?}: an unparsable endpoint was scored"
        );
        assert!(!controller.is_banned(&id, 0));
        assert_eq!(controller.score(&id, 0), 0);
        assert_eq!(controller.ban_remaining_ms(&id, 0), 0);
    }
    assert_eq!(
        controller.tracked_sources(),
        0,
        "an unparsable endpoint must not create a tracking record"
    );
}

#[test]
fn the_source_table_never_grows_beyond_its_bound_under_an_address_flood() {
    let config = AdmissionConfig {
        max_tracked_sources: 8,
        offence_weights: [64; Offence::COUNT],
        ban_threshold: 64,
        ban_duration_ms: 3_600_000,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    for index in 0..4_096_u32 {
        let _ = controller.record_offence(&source(index), Offence::InvalidFrame, index.into());
        assert!(
            controller.tracked_sources() <= 8,
            "index={index}: the source table grew to {} records",
            controller.tracked_sources()
        );
    }
    assert_eq!(
        controller.tracked_sources(),
        8,
        "the bounded table must stay populated up to its limit"
    );
}

#[test]
fn a_flood_of_new_sources_never_evicts_a_record_holding_a_live_connection() {
    let config = AdmissionConfig {
        max_tracked_sources: 4,
        max_connections_per_source: 2,
        offence_weights: [64; Offence::COUNT],
        ban_threshold: 64,
        ban_duration_ms: 3_600_000,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    controller.admit_inbound(&peer(1), 0).unwrap();
    for index in 0..1_024_u32 {
        let _ = controller.record_offence(&source(index), Offence::OversizedPayload, 0);
        assert_eq!(
            controller.source_connections("127.0.0.1:1"),
            1,
            "index={index}: a flood evicted a record holding a live connection"
        );
        assert_eq!(
            controller.total_connections(),
            1,
            "index={index}: the total connection count drifted during eviction"
        );
    }
}

#[test]
fn eviction_removes_the_least_penalised_record_and_retains_an_active_ban() {
    let config = AdmissionConfig {
        max_tracked_sources: 3,
        offence_weights: [
            100, // invalid frame reaches the threshold on its own
            1, 1, 1, 1,
        ],
        ban_threshold: 100,
        score_decay_per_second: 0,
        ban_duration_ms: 3_600_000,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    let banned = source(0);
    assert!(controller.record_offence(&banned, Offence::InvalidFrame, 0));
    assert!(!controller.record_offence(&source(1), Offence::RateLimitBreach, 0));
    assert!(!controller.record_offence(&source(2), Offence::RateLimitBreach, 0));
    for index in 3..64_u32 {
        let _ = controller.record_offence(&source(index), Offence::RateLimitBreach, 0);
        assert!(
            controller.is_banned(&banned, 0),
            "index={index}: a flood of lightly scored sources evicted an active ban"
        );
        assert!(
            controller.tracked_sources() <= 3,
            "index={index}: the table grew to {} records",
            controller.tracked_sources()
        );
    }
}

#[test]
fn a_flood_of_banned_sources_evicts_the_earliest_expiring_ban_first() {
    let config = AdmissionConfig {
        max_tracked_sources: 2,
        offence_weights: [100; Offence::COUNT],
        ban_threshold: 100,
        ban_duration_ms: 10_000,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    assert!(controller.record_offence(&source(0), Offence::InvalidFrame, 0));
    assert!(controller.record_offence(&source(1), Offence::InvalidFrame, 1_000));
    assert!(controller.record_offence(&source(2), Offence::InvalidFrame, 2_000));
    assert_eq!(
        controller.tracked_sources(),
        2,
        "the table must stay at its bound"
    );
    assert!(
        !controller.is_banned(&source(0), 2_000),
        "the earliest expiring ban must be the evicted one"
    );
    for index in [1_u32, 2] {
        assert!(
            controller.is_banned(&source(index), 2_000),
            "index={index}: a later ban was evicted before an earlier one"
        );
    }
}

#[test]
fn the_peer_table_never_grows_beyond_its_bound_under_connection_churn() {
    let config = AdmissionConfig {
        max_tracked_peers: 8,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    for port in 1..=1_024_u16 {
        controller
            .charge_class(&peer(port), MessageClass::Handshake, 1, 0)
            .unwrap_or_else(|error| {
                panic!("port={port}: an unlimited charge was refused: {error}")
            });
        assert!(
            controller.tracked_peers() <= 8,
            "port={port}: the peer table grew to {} records",
            controller.tracked_peers()
        );
    }
}

#[test]
fn prune_reclaims_only_records_that_owe_and_remember_nothing() {
    let config = AdmissionConfig {
        offence_weights: [10; Offence::COUNT],
        ban_threshold: 1_000,
        score_decay_per_second: 10,
        peer_limits: ClassLimits {
            per_class: [ClassLimit::new(RateLimit::new(10, 10), RateLimit::new(10, 10));
                MessageClass::COUNT],
        },
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    assert!(!controller.record_offence(&peer(1), Offence::InvalidFrame, 0));
    controller
        .charge_class(&peer(1), MessageClass::Blocks, 5, 0)
        .unwrap();
    controller.prune(0);
    assert_eq!(
        controller.tracked_sources(),
        1,
        "a scored source must survive pruning at the same tick"
    );
    assert_eq!(
        controller.tracked_peers(),
        1,
        "a peer still holding debt must survive pruning"
    );
    controller.prune(10_000);
    assert_eq!(
        controller.tracked_sources(),
        0,
        "a fully decayed, fully refilled source must be reclaimed"
    );
    assert_eq!(
        controller.tracked_peers(),
        0,
        "a fully refilled peer must be reclaimed"
    );

    let mut held = AdmissionController::new(config);
    held.admit_inbound(&peer(2), 0).unwrap();
    held.prune(86_400_000);
    assert_eq!(
        held.tracked_sources(),
        1,
        "a source holding a live connection must never be pruned"
    );
}

#[test]
fn an_admitted_connection_is_not_charged_against_the_inbound_attempt_budget_when_dialled() {
    let config = AdmissionConfig {
        connection_attempts: RateLimit::new(0, 1),
        max_connections_per_source: 8,
        max_total_connections: 8,
        ..unlimited()
    };
    let mut controller = AdmissionController::new(config);
    for port in 1..=8_u16 {
        controller
            .admit_outbound(&peer(port), 0)
            .unwrap_or_else(|error| panic!("port={port}: a dial was charged an attempt: {error}"));
    }
    assert_eq!(
        controller.total_connections(),
        8,
        "every dialled connection must hold a slot"
    );
}

#[test]
fn default_configuration_matches_the_documented_named_constants() {
    let config = AdmissionConfig::default();
    assert_eq!(config.max_total_connections, DEFAULT_MAX_TOTAL_CONNECTIONS);
    assert_eq!(
        config.max_connections_per_source,
        DEFAULT_MAX_CONNECTIONS_PER_SOURCE
    );
    assert_eq!(
        config.connection_attempts,
        RateLimit::new(
            DEFAULT_CONNECTION_ATTEMPTS_PER_SECOND,
            DEFAULT_CONNECTION_ATTEMPT_BURST
        )
    );
    assert_eq!(config.ban_threshold, DEFAULT_BAN_THRESHOLD);
    assert_eq!(config.score_ceiling, DEFAULT_SCORE_CEILING);
    assert_eq!(
        config.score_decay_per_second,
        DEFAULT_SCORE_DECAY_PER_SECOND
    );
    assert_eq!(config.ban_duration_ms, DEFAULT_BAN_DURATION_MS);
    assert_eq!(config.max_tracked_sources, DEFAULT_MAX_TRACKED_SOURCES);
    assert_eq!(config.max_tracked_peers, DEFAULT_MAX_TRACKED_PEERS);

    let expected = [
        (
            MessageClass::Handshake,
            DEFAULT_HANDSHAKE_MESSAGES_PER_SECOND,
            DEFAULT_HANDSHAKE_MESSAGE_BURST,
            DEFAULT_HANDSHAKE_BYTES_PER_SECOND,
            DEFAULT_HANDSHAKE_BYTE_BURST,
        ),
        (
            MessageClass::Transactions,
            DEFAULT_TRANSACTION_MESSAGES_PER_SECOND,
            DEFAULT_TRANSACTION_MESSAGE_BURST,
            DEFAULT_TRANSACTION_BYTES_PER_SECOND,
            DEFAULT_TRANSACTION_BYTE_BURST,
        ),
        (
            MessageClass::Blocks,
            DEFAULT_BLOCK_MESSAGES_PER_SECOND,
            DEFAULT_BLOCK_MESSAGE_BURST,
            DEFAULT_BLOCK_BYTES_PER_SECOND,
            DEFAULT_BLOCK_BYTE_BURST,
        ),
        (
            MessageClass::Consensus,
            DEFAULT_CONSENSUS_MESSAGES_PER_SECOND,
            DEFAULT_CONSENSUS_MESSAGE_BURST,
            DEFAULT_CONSENSUS_BYTES_PER_SECOND,
            DEFAULT_CONSENSUS_BYTE_BURST,
        ),
    ];
    for (class, messages_rate, messages_burst, bytes_rate, bytes_burst) in expected {
        let limit = config.peer_limits.get(class);
        assert_eq!(
            limit,
            ClassLimit::new(
                RateLimit::new(messages_rate, messages_burst),
                RateLimit::new(bytes_rate, bytes_burst)
            ),
            "class={class}: per-peer defaults disagree with the named constants"
        );
        assert_eq!(
            config.source_limits.get(class),
            limit.scaled(DEFAULT_SOURCE_RATE_MULTIPLIER),
            "class={class}: per-source defaults are not the documented multiple"
        );
        assert_eq!(
            config.global_limits.get(class),
            limit.scaled(DEFAULT_GLOBAL_RATE_MULTIPLIER),
            "class={class}: process-wide defaults are not the documented multiple"
        );
    }
    for tier in [Tier::Peer, Tier::Source, Tier::Global] {
        for class in MessageClass::ALL {
            assert!(
                config.limits(tier).get(class).messages.burst > 0,
                "tier={tier} class={class}: a default burst of zero would refuse everything"
            );
        }
    }
}

#[test]
fn scaling_a_rate_limit_saturates_instead_of_wrapping() {
    assert_eq!(
        RateLimit::new(u64::MAX, u64::MAX).scaled(2),
        RateLimit::new(u64::MAX, u64::MAX),
        "scaling must saturate at u64::MAX"
    );
    assert_eq!(
        RateLimit::new(3, 7).scaled(0),
        RateLimit::new(0, 0),
        "scaling by zero must remove the budget entirely"
    );
    for factor in [1_u64, 2, 32, 128] {
        assert_eq!(
            RateLimit::new(5, 9).scaled(factor),
            RateLimit::new(5 * factor, 9 * factor),
            "factor={factor}: scaling is not exact"
        );
    }
}

#[test]
fn every_refusal_offence_class_and_tier_renders_a_distinct_message() {
    let refusals = [
        Refusal::UnknownSource,
        Refusal::Banned,
        Refusal::TotalConnections,
        Refusal::SourceConnections,
        Refusal::AttemptRate,
        Refusal::MessageRate(Tier::Peer),
        Refusal::MessageRate(Tier::Source),
        Refusal::MessageRate(Tier::Global),
        Refusal::ByteRate(Tier::Peer),
        Refusal::ByteRate(Tier::Source),
        Refusal::ByteRate(Tier::Global),
        Refusal::TrackingFull,
    ];
    let mut rendered: Vec<String> = refusals
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let total = rendered.len();
    rendered.sort();
    rendered.dedup();
    assert_eq!(
        rendered.len(),
        total,
        "two refusals render the same message: {rendered:?}"
    );
    let error: &dyn std::error::Error = &Refusal::Banned;
    assert_eq!(error.to_string(), "source is banned");

    let mut names: Vec<&str> = Offence::ALL.iter().map(|offence| offence.name()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        Offence::COUNT,
        "offence names are not distinct"
    );
    let mut classes: Vec<&str> = MessageClass::ALL.iter().map(|class| class.name()).collect();
    classes.sort_unstable();
    classes.dedup();
    assert_eq!(
        classes.len(),
        MessageClass::COUNT,
        "class names are not distinct"
    );
    for tier in [Tier::Peer, Tier::Source, Tier::Global] {
        assert_eq!(
            format!("{tier}"),
            tier.name(),
            "tier={tier}: Display disagrees with name()"
        );
    }
    for offence in Offence::ALL {
        assert_eq!(format!("{offence}"), offence.name());
    }
    for class in MessageClass::ALL {
        assert_eq!(format!("{class}"), class.name());
    }
}
