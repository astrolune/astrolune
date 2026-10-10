// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded local admission control for a peer listener exposed to untrusted callers.
//!
//! The controller answers three questions for one process: may this connection
//! occupy a slot, may this received message be charged against the budget its
//! traffic class was given, and has this source address misbehaved often enough
//! to be refused for a bounded period. Connection slots are capped in total and
//! per source address, connection attempts and message/byte volume are metered
//! by integer token buckets at the peer, source and process tiers, and offences
//! accumulate into a capped score that decays and expires.
//!
//! Every decision is a pure function of the caller-supplied millisecond tick.
//! This module never reads a clock, never allocates without a bound and never
//! spawns anything, so a test can replay an entire admission history
//! deterministically. Ticks are expected to be monotonically non-decreasing; a
//! tick below the highest already observed accrues nothing instead of panicking,
//! wrapping or granting a refund.
//!
//! This is bounded local admission control and nothing more. It is not a defence
//! against a distributed attack from many source addresses, not an argument about
//! amplification or reflection, not a congestion-control or fair-queueing
//! algorithm and not a reputation system shared between nodes. It never
//! influences consensus: no decision here changes voting power, committee
//! membership, block validity, finality or the content of any signed message. It
//! authenticates nobody — transport authentication and message signature
//! verification remain entirely separate and still mandatory. A ban is one
//! node's local refusal to spend resources on one address for a bounded time; it
//! is not a protocol penalty and it is not evidence of anything.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::NetworkError;
use crate::message::MessageKind;
use crate::transport::PeerId;

/// Milliseconds in one second, the fixed denominator of every refill and decay.
const MILLISECONDS_PER_SECOND: u128 = 1_000;

/// Default concurrent connections admitted across every source (`128`).
///
/// Matches the flat peer ceiling the transport layer has always enforced.
pub const DEFAULT_MAX_TOTAL_CONNECTIONS: usize = 128;

/// Default concurrent connections admitted from one source address (`32`).
///
/// One quarter of [`DEFAULT_MAX_TOTAL_CONNECTIONS`], so one remote host cannot
/// occupy every slot, and large enough for the 32 route workers a private
/// network profile may run behind a single address.
pub const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: usize = 32;

/// Default sustained connection attempts admitted per source per second (`32`).
pub const DEFAULT_CONNECTION_ATTEMPTS_PER_SECOND: u64 = 32;

/// Default connection-attempt burst admitted per source (`128`).
pub const DEFAULT_CONNECTION_ATTEMPT_BURST: u64 = 128;

/// Default sustained [`MessageClass::Handshake`] messages per peer per second (`8`).
pub const DEFAULT_HANDSHAKE_MESSAGES_PER_SECOND: u64 = 8;

/// Default [`MessageClass::Handshake`] message burst per peer (`16`).
pub const DEFAULT_HANDSHAKE_MESSAGE_BURST: u64 = 16;

/// Default sustained [`MessageClass::Handshake`] bytes per peer per second (`65,536` bytes).
pub const DEFAULT_HANDSHAKE_BYTES_PER_SECOND: u64 = 65_536;

/// Default [`MessageClass::Handshake`] byte burst per peer (`131,072` bytes).
pub const DEFAULT_HANDSHAKE_BYTE_BURST: u64 = 131_072;

/// Default sustained [`MessageClass::Transactions`] messages per peer per second (`64`).
pub const DEFAULT_TRANSACTION_MESSAGES_PER_SECOND: u64 = 64;

/// Default [`MessageClass::Transactions`] message burst per peer (`128`).
pub const DEFAULT_TRANSACTION_MESSAGE_BURST: u64 = 128;

/// Default sustained [`MessageClass::Transactions`] bytes per peer per second (`4,194,304` bytes).
pub const DEFAULT_TRANSACTION_BYTES_PER_SECOND: u64 = 4_194_304;

/// Default [`MessageClass::Transactions`] byte burst per peer (`8,388,608` bytes).
pub const DEFAULT_TRANSACTION_BYTE_BURST: u64 = 8_388_608;

/// Default sustained [`MessageClass::Blocks`] messages per peer per second (`64`).
pub const DEFAULT_BLOCK_MESSAGES_PER_SECOND: u64 = 64;

/// Default [`MessageClass::Blocks`] message burst per peer (`128`).
pub const DEFAULT_BLOCK_MESSAGE_BURST: u64 = 128;

/// Default sustained [`MessageClass::Blocks`] bytes per peer per second (`16,777,216` bytes).
pub const DEFAULT_BLOCK_BYTES_PER_SECOND: u64 = 16_777_216;

/// Default [`MessageClass::Blocks`] byte burst per peer (`33,554,432` bytes).
pub const DEFAULT_BLOCK_BYTE_BURST: u64 = 33_554_432;

/// Default sustained [`MessageClass::Consensus`] messages per peer per second (`128`).
pub const DEFAULT_CONSENSUS_MESSAGES_PER_SECOND: u64 = 128;

/// Default [`MessageClass::Consensus`] message burst per peer (`256`).
pub const DEFAULT_CONSENSUS_MESSAGE_BURST: u64 = 256;

/// Default sustained [`MessageClass::Consensus`] bytes per peer per second (`2,097,152` bytes).
pub const DEFAULT_CONSENSUS_BYTES_PER_SECOND: u64 = 2_097_152;

/// Default [`MessageClass::Consensus`] byte burst per peer (`4,194,304` bytes).
pub const DEFAULT_CONSENSUS_BYTE_BURST: u64 = 4_194_304;

/// Default factor from the per-peer defaults to the per-source defaults (`32`).
///
/// Equal to [`DEFAULT_MAX_CONNECTIONS_PER_SOURCE`], so connections a host holds
/// concurrently are not penalised for sharing an address, while a host that
/// opens and closes connections keeps that one source budget across all of them.
pub const DEFAULT_SOURCE_RATE_MULTIPLIER: u64 = 32;

/// Default factor from the per-peer defaults to the process-wide defaults (`128`).
///
/// Equal to [`DEFAULT_MAX_TOTAL_CONNECTIONS`], so the process ceiling is the
/// aggregate of every admitted connection spending its own per-peer allowance.
pub const DEFAULT_GLOBAL_RATE_MULTIPLIER: u64 = 128;

/// Default score added for [`Offence::InvalidFrame`] (`32`).
pub const DEFAULT_WEIGHT_INVALID_FRAME: u32 = 32;

/// Default score added for [`Offence::OversizedPayload`] (`48`).
pub const DEFAULT_WEIGHT_OVERSIZED_PAYLOAD: u32 = 48;

/// Default score added for [`Offence::UnauthenticatedMessage`] (`16`).
pub const DEFAULT_WEIGHT_UNAUTHENTICATED_MESSAGE: u32 = 16;

/// Default score added for [`Offence::RateLimitBreach`] (`8`).
pub const DEFAULT_WEIGHT_RATE_LIMIT_BREACH: u32 = 8;

/// Default score added for [`Offence::ProtocolViolation`] (`24`).
pub const DEFAULT_WEIGHT_PROTOCOL_VIOLATION: u32 = 24;

/// Default score at or above which a source is banned (`128`).
pub const DEFAULT_BAN_THRESHOLD: u32 = 128;

/// Default ceiling the retained score saturates at (`1,024`).
pub const DEFAULT_SCORE_CEILING: u32 = 1_024;

/// Default score removed per second of supplied tick advance (`4`).
pub const DEFAULT_SCORE_DECAY_PER_SECOND: u32 = 4;

/// Default bounded ban duration (`600,000` milliseconds).
pub const DEFAULT_BAN_DURATION_MS: u64 = 600_000;

/// Default retained source records (`1,024`).
pub const DEFAULT_MAX_TRACKED_SOURCES: usize = 1_024;

/// Default retained per-connection records (`1,024`).
pub const DEFAULT_MAX_TRACKED_PEERS: usize = 1_024;

/// Exact integer accrual of `per_second` units over `elapsed_ms` milliseconds.
///
/// Returns the whole units accrued and the unspent remainder in unit
/// milliseconds, always below [`MILLISECONDS_PER_SECOND`]. Carrying that
/// remainder into the next call is what makes a sequence of short advances
/// accrue exactly as many whole units as one advance of the same total length;
/// discarding it would lose up to one unit per advance. The product is formed at
/// double width, so no multiplication here can wrap.
fn accrue(elapsed_ms: u64, per_second: u64, remainder: u64) -> (u64, u64) {
    let scaled = u128::from(elapsed_ms) * u128::from(per_second) + u128::from(remainder);
    (
        u64::try_from(scaled / MILLISECONDS_PER_SECOND).unwrap_or(u64::MAX),
        u64::try_from(scaled % MILLISECONDS_PER_SECOND).unwrap_or(0),
    )
}

/// A sustained refill rate paired with the instantaneous burst it may hoard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimit {
    /// Tokens restored per second of supplied tick advance.
    pub per_second: u64,
    /// Maximum tokens held at once, which is the admitted burst.
    pub burst: u64,
}

impl RateLimit {
    /// Creates a limit from a sustained rate and a burst.
    #[must_use]
    pub const fn new(per_second: u64, burst: u64) -> Self {
        Self { per_second, burst }
    }

    /// Returns this limit with both components multiplied, saturating at [`u64::MAX`].
    #[must_use]
    pub const fn scaled(self, factor: u64) -> Self {
        Self {
            per_second: self.per_second.saturating_mul(factor),
            burst: self.burst.saturating_mul(factor),
        }
    }
}

/// An integer token bucket that refills without precision drift.
///
/// The bucket holds whole tokens plus a carried sub-token remainder. It is not a
/// scheduler, a queue or a delay line: a refused charge is refused, never
/// deferred, and nothing here reorders or paces admitted work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenBucket {
    /// Maximum tokens held at once.
    capacity: u64,
    /// Tokens restored per second of supplied tick advance.
    per_second: u64,
    /// Whole tokens currently available.
    tokens: u64,
    /// Carried sub-token refill remainder in token milliseconds.
    remainder: u64,
    /// Highest tick observed so far.
    tick_ms: u64,
}

impl TokenBucket {
    /// Creates a bucket holding its full burst as of `tick_ms`.
    #[must_use]
    pub const fn new(limit: RateLimit, tick_ms: u64) -> Self {
        Self {
            capacity: limit.burst,
            per_second: limit.per_second,
            tokens: limit.burst,
            remainder: 0,
            tick_ms,
        }
    }

    /// Refills the bucket up to `tick_ms`.
    ///
    /// A tick at or below the highest tick already observed accrues nothing and
    /// never moves the bucket backwards, so a caller whose clock jumps backwards
    /// cannot be granted a refund or trigger an overflow.
    pub fn advance(&mut self, tick_ms: u64) {
        let elapsed = tick_ms.saturating_sub(self.tick_ms);
        if elapsed == 0 {
            return;
        }
        self.tick_ms = tick_ms;
        let (whole, remainder) = accrue(elapsed, self.per_second, self.remainder);
        self.remainder = remainder;
        self.tokens = self.tokens.saturating_add(whole).min(self.capacity);
    }

    /// Refills to `tick_ms` and reports whether `cost` tokens are available.
    pub fn available(&mut self, tick_ms: u64, cost: u64) -> bool {
        self.advance(tick_ms);
        self.tokens >= cost
    }

    /// Removes `cost` tokens, saturating at zero.
    pub fn take(&mut self, cost: u64) {
        self.tokens = self.tokens.saturating_sub(cost);
    }

    /// Refills to `tick_ms` and removes `cost` tokens only if all are available.
    pub fn try_take(&mut self, tick_ms: u64, cost: u64) -> bool {
        if !self.available(tick_ms, cost) {
            return false;
        }
        self.take(cost);
        true
    }

    /// Whole tokens currently available, without refilling.
    #[must_use]
    pub const fn tokens(&self) -> u64 {
        self.tokens
    }

    /// Whether the bucket holds its full burst and therefore owes nothing.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.tokens >= self.capacity
    }
}

/// The budget a wire message kind is charged to.
///
/// Classes separate work a peer can ask for cheaply from work that obliges this
/// node to read, decode or verify a large amount, so exhausting one class never
/// starves another. The grouping is a local cost judgement; it is not part of
/// the wire protocol and no peer can observe or select it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(usize)]
pub enum MessageClass {
    /// Session negotiation and catch-up requests: [`MessageKind::Hello`].
    Handshake = 0,
    /// Transaction announcement and relay: [`MessageKind::Transactions`].
    Transactions = 1,
    /// Block propagation and finalized history: [`MessageKind::CompactBlock`].
    Blocks = 2,
    /// Live consensus traffic: [`MessageKind::Proposal`], [`MessageKind::Vote`]
    /// and [`MessageKind::Finality`].
    Consensus = 3,
}

impl MessageClass {
    /// Number of distinct classes.
    pub const COUNT: usize = 4;

    /// Every class in discriminant order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::Handshake,
        Self::Transactions,
        Self::Blocks,
        Self::Consensus,
    ];

    /// Returns the class a wire message kind is charged to.
    #[must_use]
    pub const fn of(kind: MessageKind) -> Self {
        match kind {
            MessageKind::Hello => Self::Handshake,
            MessageKind::Transactions => Self::Transactions,
            MessageKind::CompactBlock => Self::Blocks,
            MessageKind::Proposal | MessageKind::Vote | MessageKind::Finality => Self::Consensus,
        }
    }

    /// Stable lowercase identifier for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::Transactions => "transactions",
            Self::Blocks => "blocks",
            Self::Consensus => "consensus",
        }
    }
}

impl fmt::Display for MessageClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Message-count and byte-volume limits for one traffic class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassLimit {
    /// Admitted message count.
    pub messages: RateLimit,
    /// Admitted payload byte volume.
    pub bytes: RateLimit,
}

impl ClassLimit {
    /// Creates a class limit from a message-count limit and a byte-volume limit.
    #[must_use]
    pub const fn new(messages: RateLimit, bytes: RateLimit) -> Self {
        Self { messages, bytes }
    }

    /// Returns this limit with every component multiplied, saturating at [`u64::MAX`].
    #[must_use]
    pub const fn scaled(self, factor: u64) -> Self {
        Self {
            messages: self.messages.scaled(factor),
            bytes: self.bytes.scaled(factor),
        }
    }
}

/// One [`ClassLimit`] per [`MessageClass`] at a single aggregation tier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassLimits {
    /// Limits indexed by `MessageClass as usize`.
    pub per_class: [ClassLimit; MessageClass::COUNT],
}

impl ClassLimits {
    /// Returns the limit configured for `class`.
    #[must_use]
    pub const fn get(&self, class: MessageClass) -> ClassLimit {
        self.per_class[class as usize]
    }

    /// Returns these limits with every component multiplied, saturating at [`u64::MAX`].
    #[must_use]
    pub const fn scaled(&self, factor: u64) -> Self {
        let mut per_class = self.per_class;
        let mut index = 0;
        while index < MessageClass::COUNT {
            per_class[index] = per_class[index].scaled(factor);
            index += 1;
        }
        Self { per_class }
    }
}

impl Default for ClassLimits {
    fn default() -> Self {
        Self {
            per_class: [
                ClassLimit::new(
                    RateLimit::new(
                        DEFAULT_HANDSHAKE_MESSAGES_PER_SECOND,
                        DEFAULT_HANDSHAKE_MESSAGE_BURST,
                    ),
                    RateLimit::new(
                        DEFAULT_HANDSHAKE_BYTES_PER_SECOND,
                        DEFAULT_HANDSHAKE_BYTE_BURST,
                    ),
                ),
                ClassLimit::new(
                    RateLimit::new(
                        DEFAULT_TRANSACTION_MESSAGES_PER_SECOND,
                        DEFAULT_TRANSACTION_MESSAGE_BURST,
                    ),
                    RateLimit::new(
                        DEFAULT_TRANSACTION_BYTES_PER_SECOND,
                        DEFAULT_TRANSACTION_BYTE_BURST,
                    ),
                ),
                ClassLimit::new(
                    RateLimit::new(
                        DEFAULT_BLOCK_MESSAGES_PER_SECOND,
                        DEFAULT_BLOCK_MESSAGE_BURST,
                    ),
                    RateLimit::new(DEFAULT_BLOCK_BYTES_PER_SECOND, DEFAULT_BLOCK_BYTE_BURST),
                ),
                ClassLimit::new(
                    RateLimit::new(
                        DEFAULT_CONSENSUS_MESSAGES_PER_SECOND,
                        DEFAULT_CONSENSUS_MESSAGE_BURST,
                    ),
                    RateLimit::new(
                        DEFAULT_CONSENSUS_BYTES_PER_SECOND,
                        DEFAULT_CONSENSUS_BYTE_BURST,
                    ),
                ),
            ],
        }
    }
}

/// A named class of peer misbehaviour.
///
/// Every variant corresponds to a failure the existing stack actually reports:
/// the three [`NetworkError`] cases, an exhausted budget in this module, and the
/// genesis/committee/signature rejections the node layer raises for peer input.
/// Nothing here describes an intent, only an observed local failure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(usize)]
pub enum Offence {
    /// Frame bytes were malformed or non-canonical: [`NetworkError::InvalidFrame`].
    InvalidFrame = 0,
    /// A declared or decoded payload exceeded a configured bound:
    /// [`NetworkError::LimitExceeded`].
    OversizedPayload = 1,
    /// A message failed genesis, committee or signature verification.
    UnauthenticatedMessage = 2,
    /// A charge was refused because the class budget was already exhausted.
    RateLimitBreach = 3,
    /// Protocol or chain identity was incompatible, or the session sequence was
    /// violated: [`NetworkError::IncompatiblePeer`].
    ProtocolViolation = 4,
}

impl Offence {
    /// Number of distinct offence classes.
    pub const COUNT: usize = 5;

    /// Every offence class in discriminant order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::InvalidFrame,
        Self::OversizedPayload,
        Self::UnauthenticatedMessage,
        Self::RateLimitBreach,
        Self::ProtocolViolation,
    ];

    /// Classifies a reported [`NetworkError`].
    #[must_use]
    pub const fn of_network_error(error: NetworkError) -> Self {
        match error {
            NetworkError::InvalidFrame => Self::InvalidFrame,
            NetworkError::IncompatiblePeer => Self::ProtocolViolation,
            NetworkError::LimitExceeded => Self::OversizedPayload,
        }
    }

    /// Stable lowercase identifier for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidFrame => "invalid frame",
            Self::OversizedPayload => "oversized payload",
            Self::UnauthenticatedMessage => "unauthenticated message",
            Self::RateLimitBreach => "rate limit breach",
            Self::ProtocolViolation => "protocol violation",
        }
    }
}

impl fmt::Display for Offence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The aggregation level whose budget refused a charge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tier {
    /// One connection, identified by its full socket address.
    Peer,
    /// One remote host, identified by its source address across reconnects.
    Source,
    /// Every admitted connection in this process.
    Global,
}

impl Tier {
    /// Stable lowercase identifier for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Source => "source",
            Self::Global => "global",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why admission refused a connection or a charge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// No source address could be parsed out of the peer identity.
    UnknownSource,
    /// The source is serving a bounded ban.
    Banned,
    /// The process-wide concurrent connection cap is full.
    TotalConnections,
    /// This source already holds its concurrent connection allowance.
    SourceConnections,
    /// This source exhausted its connection-attempt budget.
    AttemptRate,
    /// The message-count budget for this class is exhausted at this tier.
    MessageRate(Tier),
    /// The byte-volume budget for this class is exhausted at this tier.
    ByteRate(Tier),
    /// No bounded tracking slot could be reclaimed for a new source.
    TrackingFull,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSource => write!(f, "unparsable source address"),
            Self::Banned => write!(f, "source is banned"),
            Self::TotalConnections => write!(f, "total connection limit reached"),
            Self::SourceConnections => write!(f, "per-source connection limit reached"),
            Self::AttemptRate => write!(f, "per-source connection attempt limit reached"),
            Self::MessageRate(tier) => write!(f, "{tier} message rate limit reached"),
            Self::ByteRate(tier) => write!(f, "{tier} byte rate limit reached"),
            Self::TrackingFull => write!(f, "source tracking table is full"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Every configurable admission bound.
///
/// [`Default`] supplies the documented `DEFAULT_*` constants of this module and
/// nothing else; there is no hidden policy and no value read from the
/// environment, a file or a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionConfig {
    /// Concurrent connections admitted across every source.
    pub max_total_connections: usize,
    /// Concurrent connections admitted from one source address.
    pub max_connections_per_source: usize,
    /// Connection attempts admitted per source address over time.
    pub connection_attempts: RateLimit,
    /// Message and byte budgets for one connection.
    pub peer_limits: ClassLimits,
    /// Message and byte budgets aggregated over one source address.
    pub source_limits: ClassLimits,
    /// Message and byte budgets aggregated over the whole process.
    pub global_limits: ClassLimits,
    /// Score added per offence, indexed by `Offence as usize`.
    pub offence_weights: [u32; Offence::COUNT],
    /// Score at or above which a source is banned.
    pub ban_threshold: u32,
    /// Ceiling the retained score saturates at.
    pub score_ceiling: u32,
    /// Score removed per second of supplied tick advance.
    pub score_decay_per_second: u32,
    /// Bounded ban duration in milliseconds.
    pub ban_duration_ms: u64,
    /// Retained source records before deterministic eviction.
    pub max_tracked_sources: usize,
    /// Retained per-connection records before deterministic eviction.
    pub max_tracked_peers: usize,
}

impl AdmissionConfig {
    /// Returns the score added for `offence`.
    #[must_use]
    pub const fn weight(&self, offence: Offence) -> u32 {
        self.offence_weights[offence as usize]
    }

    /// Returns the configured limits for `tier`.
    #[must_use]
    pub const fn limits(&self, tier: Tier) -> &ClassLimits {
        match tier {
            Tier::Peer => &self.peer_limits,
            Tier::Source => &self.source_limits,
            Tier::Global => &self.global_limits,
        }
    }

    /// Returns this configuration with the process-wide connection cap replaced.
    #[must_use]
    pub const fn with_max_total_connections(mut self, maximum: usize) -> Self {
        self.max_total_connections = maximum;
        self
    }
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        let peer_limits = ClassLimits::default();
        Self {
            max_total_connections: DEFAULT_MAX_TOTAL_CONNECTIONS,
            max_connections_per_source: DEFAULT_MAX_CONNECTIONS_PER_SOURCE,
            connection_attempts: RateLimit::new(
                DEFAULT_CONNECTION_ATTEMPTS_PER_SECOND,
                DEFAULT_CONNECTION_ATTEMPT_BURST,
            ),
            peer_limits,
            source_limits: peer_limits.scaled(DEFAULT_SOURCE_RATE_MULTIPLIER),
            global_limits: peer_limits.scaled(DEFAULT_GLOBAL_RATE_MULTIPLIER),
            offence_weights: [
                DEFAULT_WEIGHT_INVALID_FRAME,
                DEFAULT_WEIGHT_OVERSIZED_PAYLOAD,
                DEFAULT_WEIGHT_UNAUTHENTICATED_MESSAGE,
                DEFAULT_WEIGHT_RATE_LIMIT_BREACH,
                DEFAULT_WEIGHT_PROTOCOL_VIOLATION,
            ],
            ban_threshold: DEFAULT_BAN_THRESHOLD,
            score_ceiling: DEFAULT_SCORE_CEILING,
            score_decay_per_second: DEFAULT_SCORE_DECAY_PER_SECOND,
            ban_duration_ms: DEFAULT_BAN_DURATION_MS,
            max_tracked_sources: DEFAULT_MAX_TRACKED_SOURCES,
            max_tracked_peers: DEFAULT_MAX_TRACKED_PEERS,
        }
    }
}

/// Which bucket of one [`ClassBuckets`] set was exhausted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Exhausted {
    /// The message-count bucket held less than one token.
    Messages,
    /// The byte-volume bucket held fewer tokens than the charged payload.
    Bytes,
}

/// Message-count and byte-volume buckets for every class at one tier.
#[derive(Clone, Debug)]
struct ClassBuckets {
    /// Message-count buckets indexed by `MessageClass as usize`.
    messages: [TokenBucket; MessageClass::COUNT],
    /// Byte-volume buckets indexed by `MessageClass as usize`.
    bytes: [TokenBucket; MessageClass::COUNT],
}

impl ClassBuckets {
    /// Creates a full set of buckets from `limits` as of `tick_ms`.
    fn new(limits: &ClassLimits, tick_ms: u64) -> Self {
        Self {
            messages: std::array::from_fn(|index| {
                TokenBucket::new(limits.per_class[index].messages, tick_ms)
            }),
            bytes: std::array::from_fn(|index| {
                TokenBucket::new(limits.per_class[index].bytes, tick_ms)
            }),
        }
    }

    /// Refills both buckets of `class` and reports the first exhausted one.
    fn shortfall(&mut self, class: MessageClass, bytes: u64, tick_ms: u64) -> Option<Exhausted> {
        let index = class as usize;
        if !self.messages[index].available(tick_ms, 1) {
            return Some(Exhausted::Messages);
        }
        if !self.bytes[index].available(tick_ms, bytes) {
            return Some(Exhausted::Bytes);
        }
        None
    }

    /// Removes one message token and `bytes` byte tokens from `class`.
    fn take(&mut self, class: MessageClass, bytes: u64) {
        let index = class as usize;
        self.messages[index].take(1);
        self.bytes[index].take(bytes);
    }

    /// Refills every bucket to `tick_ms`.
    fn advance(&mut self, tick_ms: u64) {
        for bucket in self.messages.iter_mut().chain(self.bytes.iter_mut()) {
            bucket.advance(tick_ms);
        }
    }

    /// Whether every bucket holds its full burst and therefore owes nothing.
    fn is_debt_free(&self) -> bool {
        self.messages
            .iter()
            .chain(self.bytes.iter())
            .all(TokenBucket::is_full)
    }

    /// Total tokens held, used as part of a deterministic eviction ordering.
    fn held_tokens(&self) -> u64 {
        self.messages
            .iter()
            .chain(self.bytes.iter())
            .fold(0_u64, |total, bucket| total.saturating_add(bucket.tokens()))
    }
}

/// Everything retained about one source address.
#[derive(Clone, Debug)]
struct SourceState {
    /// Concurrent connections currently admitted from this source.
    connections: usize,
    /// Connection-attempt bucket.
    attempts: TokenBucket,
    /// Message and byte buckets aggregated over every connection from this source.
    buckets: ClassBuckets,
    /// Capped misbehaviour score.
    score: u32,
    /// Carried sub-point decay remainder in score milliseconds.
    decay_remainder: u64,
    /// Highest tick the score was decayed to.
    score_tick: u64,
    /// Tick at which an active ban expires, if any.
    banned_until: Option<u64>,
}

impl SourceState {
    /// Creates an unpenalised record with full buckets as of `tick_ms`.
    fn new(config: &AdmissionConfig, tick_ms: u64) -> Self {
        Self {
            connections: 0,
            attempts: TokenBucket::new(config.connection_attempts, tick_ms),
            buckets: ClassBuckets::new(&config.source_limits, tick_ms),
            score: 0,
            decay_remainder: 0,
            score_tick: tick_ms,
            banned_until: None,
        }
    }

    /// Decays the score up to `tick_ms` with an exact carried remainder.
    fn decay(&mut self, config: &AdmissionConfig, tick_ms: u64) {
        let elapsed = tick_ms.saturating_sub(self.score_tick);
        if elapsed == 0 {
            return;
        }
        self.score_tick = tick_ms;
        let (whole, remainder) = accrue(
            elapsed,
            u64::from(config.score_decay_per_second),
            self.decay_remainder,
        );
        self.decay_remainder = remainder;
        self.score = self
            .score
            .saturating_sub(u32::try_from(whole).unwrap_or(u32::MAX));
    }

    /// Expires a finished ban and reports whether one is still active at `tick_ms`.
    fn banned(&mut self, tick_ms: u64) -> bool {
        match self.banned_until {
            Some(until) if tick_ms < until => true,
            Some(_) => {
                self.banned_until = None;
                false
            }
            None => false,
        }
    }

    /// Adds `weight` and applies a bounded ban if the threshold is crossed.
    fn penalise(&mut self, config: &AdmissionConfig, weight: u32, tick_ms: u64) -> bool {
        self.score = self.score.saturating_add(weight).min(config.score_ceiling);
        if self.score < config.ban_threshold {
            return false;
        }
        self.banned_until = Some(tick_ms.saturating_add(config.ban_duration_ms));
        self.score = 0;
        self.decay_remainder = 0;
        true
    }

    /// Whether nothing is owed and nothing is remembered about this source.
    fn is_reclaimable(&self) -> bool {
        self.connections == 0
            && self.banned_until.is_none()
            && self.score == 0
            && self.attempts.is_full()
            && self.buckets.is_debt_free()
    }

    /// Advances every bucket, the ban and the score to `tick_ms`.
    fn advance(&mut self, config: &AdmissionConfig, tick_ms: u64) {
        let _ = self.banned(tick_ms);
        self.decay(config, tick_ms);
        self.attempts.advance(tick_ms);
        self.buckets.advance(tick_ms);
    }

    /// Deterministic eviction ordering key: least penalised records sort first.
    fn eviction_key(&self) -> (u64, u32, u64) {
        (
            self.banned_until.unwrap_or(0),
            self.score,
            self.buckets.held_tokens(),
        )
    }
}

/// Extracts the source address from a textual peer endpoint.
///
/// Accepts an `address:port` socket address, a bare address, and the bracketed
/// `[::1]` and `[::1]:port` IPv6 forms. An IPv4-mapped IPv6 address is reduced
/// to its IPv4 form, so one host cannot be granted two allowances by alternating
/// representations. A scoped address such as `fe80::1%eth0`, a DNS name, and the
/// placeholder used when a socket has no reportable peer all return [`None`];
/// callers treat that as [`Refusal::UnknownSource`] rather than as a free pass.
/// This performs no lookup of any kind and contacts nothing.
#[must_use]
pub fn source_address(endpoint: &str) -> Option<IpAddr> {
    let text = endpoint.trim();
    if let Ok(socket) = text.parse::<SocketAddr>() {
        return Some(socket.ip().to_canonical());
    }
    if let Ok(address) = text.parse::<IpAddr>() {
        return Some(address.to_canonical());
    }
    if let Some(inner) = bracketed(text) {
        return inner
            .parse::<Ipv6Addr>()
            .ok()
            .map(|address| IpAddr::V6(address).to_canonical());
    }
    let (host, port) = text.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if let Some(inner) = bracketed(host) {
        return inner
            .parse::<Ipv6Addr>()
            .ok()
            .map(|address| IpAddr::V6(address).to_canonical());
    }
    if host.contains(':') {
        return None;
    }
    host.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// Returns the contents of a `[...]` literal host, if the text is one.
fn bracketed(text: &str) -> Option<&str> {
    text.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
}

/// Bounded admission decisions for one listener, driven entirely by supplied ticks.
///
/// Three budget tiers serve different purposes. The peer tier bounds one
/// connection. The source tier bounds one remote host across every connection it
/// holds and every connection it reopens, which is the tier a churning caller
/// cannot reset. The process tier bounds this node's total exposure. A charge is
/// all-or-nothing: if any tier is short, nothing is deducted anywhere.
///
/// Every table is bounded and every eviction rule is a total order, so a caller
/// cannot grow this structure. It holds no payload bytes, no keys and no message
/// contents, and it never retains anything after a record is reclaimed.
#[derive(Debug)]
pub struct AdmissionController {
    /// Configured bounds.
    config: AdmissionConfig,
    /// Process-wide message and byte buckets.
    global: ClassBuckets,
    /// Retained per-source records, bounded by `max_tracked_sources`.
    sources: BTreeMap<IpAddr, SourceState>,
    /// Retained per-connection buckets, bounded by `max_tracked_peers`.
    peers: BTreeMap<PeerId, ClassBuckets>,
    /// Concurrent connections admitted across every source.
    total_connections: usize,
}

impl AdmissionController {
    /// Creates a controller with the supplied configuration.
    #[must_use]
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            global: ClassBuckets::new(&config.global_limits, 0),
            config,
            sources: BTreeMap::new(),
            peers: BTreeMap::new(),
            total_connections: 0,
        }
    }

    /// Returns the configured bounds.
    #[must_use]
    pub const fn config(&self) -> &AdmissionConfig {
        &self.config
    }

    /// Concurrent connections admitted across every source.
    #[must_use]
    pub const fn total_connections(&self) -> usize {
        self.total_connections
    }

    /// Retained source records.
    #[must_use]
    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }

    /// Retained per-connection records.
    #[must_use]
    pub fn tracked_peers(&self) -> usize {
        self.peers.len()
    }

    /// Concurrent connections admitted from the source of `endpoint`.
    #[must_use]
    pub fn source_connections(&self, endpoint: &str) -> usize {
        source_address(endpoint)
            .and_then(|address| self.sources.get(&address))
            .map_or(0, |state| state.connections)
    }

    /// Decides whether an inbound connection from `peer` may occupy a slot.
    ///
    /// Charges one connection attempt whether or not a slot is then granted, so
    /// repeatedly refused attempts are themselves bounded. A granted slot is held
    /// until [`AdmissionController::release_connection`] returns it.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] that applied; the caller must close the connection.
    pub fn admit_inbound(&mut self, peer: &PeerId, tick_ms: u64) -> Result<(), Refusal> {
        let address = source_address(&peer.addr).ok_or(Refusal::UnknownSource)?;
        let total = self.total_connections;
        let config = self.config;
        let state = Self::entry(&mut self.sources, &config, address, tick_ms)?;
        if state.banned(tick_ms) {
            return Err(Refusal::Banned);
        }
        if !state.attempts.try_take(tick_ms, 1) {
            return Err(Refusal::AttemptRate);
        }
        if state.connections >= config.max_connections_per_source {
            return Err(Refusal::SourceConnections);
        }
        if total >= config.max_total_connections {
            return Err(Refusal::TotalConnections);
        }
        state.connections = state.connections.saturating_add(1);
        self.total_connections = total.saturating_add(1);
        Ok(())
    }

    /// Decides whether this node may dial `peer` and reserve a slot for it.
    ///
    /// A dial this node chose to make is not charged against the inbound
    /// connection-attempt budget, because that budget exists to bound a remote
    /// caller. The ban, per-source and total caps still apply, so a banned
    /// address is not dialled either.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] that applied; the caller must not dial.
    pub fn admit_outbound(&mut self, peer: &PeerId, tick_ms: u64) -> Result<(), Refusal> {
        let address = source_address(&peer.addr).ok_or(Refusal::UnknownSource)?;
        let total = self.total_connections;
        let config = self.config;
        let state = Self::entry(&mut self.sources, &config, address, tick_ms)?;
        if state.banned(tick_ms) {
            return Err(Refusal::Banned);
        }
        if state.connections >= config.max_connections_per_source {
            return Err(Refusal::SourceConnections);
        }
        if total >= config.max_total_connections {
            return Err(Refusal::TotalConnections);
        }
        state.connections = state.connections.saturating_add(1);
        self.total_connections = total.saturating_add(1);
        Ok(())
    }

    /// Returns one previously admitted connection slot.
    ///
    /// Releasing a slot that was never admitted, or releasing twice, saturates at
    /// zero instead of wrapping. The per-connection buckets of `peer` are dropped,
    /// because a new connection from the same host is still bound by the source
    /// tier, which never resets on reconnection.
    pub fn release_connection(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
        let Some(address) = source_address(&peer.addr) else {
            return;
        };
        if let Some(state) = self.sources.get_mut(&address) {
            state.connections = state.connections.saturating_sub(1);
        }
        self.total_connections = self.total_connections.saturating_sub(1);
    }

    /// Charges one received message of `kind` carrying `bytes` payload bytes.
    ///
    /// The message-count and byte-volume budgets of the message's
    /// [`MessageClass`] are checked at the peer, source and process tiers before
    /// anything is deducted. A refusal also records [`Offence::RateLimitBreach`]
    /// against the source, so a caller that keeps pushing past its budget
    /// eventually earns a bounded ban.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] that applied; the caller must drop the message.
    pub fn charge_message(
        &mut self,
        peer: &PeerId,
        kind: MessageKind,
        bytes: usize,
        tick_ms: u64,
    ) -> Result<(), Refusal> {
        self.charge_class(peer, MessageClass::of(kind), bytes, tick_ms)
    }

    /// Charges one received message directly against `class`.
    ///
    /// Behaves exactly like [`AdmissionController::charge_message`] and exists for
    /// a caller whose request carries no [`MessageKind`] discriminant but whose
    /// cost belongs to a known class.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] that applied; the caller must drop the message.
    pub fn charge_class(
        &mut self,
        peer: &PeerId,
        class: MessageClass,
        bytes: usize,
        tick_ms: u64,
    ) -> Result<(), Refusal> {
        let charged = u64::try_from(bytes).unwrap_or(u64::MAX);
        let outcome = self.try_charge(peer, class, charged, tick_ms);
        if matches!(outcome, Err(reason) if reason != Refusal::UnknownSource) {
            self.record_offence(peer, Offence::RateLimitBreach, tick_ms);
        }
        outcome
    }

    /// Checks every tier and deducts only when all of them can pay.
    fn try_charge(
        &mut self,
        peer: &PeerId,
        class: MessageClass,
        bytes: u64,
        tick_ms: u64,
    ) -> Result<(), Refusal> {
        let address = source_address(&peer.addr).ok_or(Refusal::UnknownSource)?;
        let config = self.config;
        if let Some(reason) = self.global.shortfall(class, bytes, tick_ms) {
            return Err(refusal(reason, Tier::Global));
        }
        {
            let state = Self::entry(&mut self.sources, &config, address, tick_ms)?;
            if state.banned(tick_ms) {
                return Err(Refusal::Banned);
            }
            if let Some(reason) = state.buckets.shortfall(class, bytes, tick_ms) {
                return Err(refusal(reason, Tier::Source));
            }
        }
        Self::reclaim_peers(&mut self.peers, config.max_tracked_peers, class);
        let buckets = self
            .peers
            .entry(peer.clone())
            .or_insert_with(|| ClassBuckets::new(&config.peer_limits, tick_ms));
        if let Some(reason) = buckets.shortfall(class, bytes, tick_ms) {
            return Err(refusal(reason, Tier::Peer));
        }
        buckets.take(class, bytes);
        if let Some(state) = self.sources.get_mut(&address) {
            state.buckets.take(class, bytes);
        }
        self.global.take(class, bytes);
        Ok(())
    }

    /// Records `offence` against the source of `peer`, reporting whether it is
    /// now banned.
    ///
    /// An unparsable endpoint cannot be scored and returns `false`; such a peer
    /// is already refused outright by [`AdmissionController::admit_inbound`].
    pub fn record_offence(&mut self, peer: &PeerId, offence: Offence, tick_ms: u64) -> bool {
        let Some(address) = source_address(&peer.addr) else {
            return false;
        };
        let config = self.config;
        let Ok(state) = Self::entry(&mut self.sources, &config, address, tick_ms) else {
            return false;
        };
        if state.banned(tick_ms) {
            return true;
        }
        state.decay(&config, tick_ms);
        state.penalise(&config, config.weight(offence), tick_ms)
    }

    /// Records the offence a reported [`NetworkError`] implies.
    pub fn record_network_error(
        &mut self,
        peer: &PeerId,
        error: NetworkError,
        tick_ms: u64,
    ) -> bool {
        self.record_offence(peer, Offence::of_network_error(error), tick_ms)
    }

    /// Whether the source of `peer` is serving a ban at `tick_ms`.
    ///
    /// Expires a finished ban as a side effect, so the answer stays a pure
    /// function of the supplied tick.
    pub fn is_banned(&mut self, peer: &PeerId, tick_ms: u64) -> bool {
        let Some(address) = source_address(&peer.addr) else {
            return false;
        };
        self.sources
            .get_mut(&address)
            .is_some_and(|state| state.banned(tick_ms))
    }

    /// Current decayed misbehaviour score for the source of `peer`.
    pub fn score(&mut self, peer: &PeerId, tick_ms: u64) -> u32 {
        let Some(address) = source_address(&peer.addr) else {
            return 0;
        };
        let config = self.config;
        self.sources.get_mut(&address).map_or(0, |state| {
            state.decay(&config, tick_ms);
            state.score
        })
    }

    /// Remaining ban duration in milliseconds for the source of `peer`.
    pub fn ban_remaining_ms(&mut self, peer: &PeerId, tick_ms: u64) -> u64 {
        let Some(address) = source_address(&peer.addr) else {
            return 0;
        };
        self.sources.get_mut(&address).map_or(0, |state| {
            if state.banned(tick_ms) {
                state
                    .banned_until
                    .unwrap_or(tick_ms)
                    .saturating_sub(tick_ms)
            } else {
                0
            }
        })
    }

    /// Drops every record that owes nothing and remembers nothing at `tick_ms`.
    ///
    /// Housekeeping only: pruning never admits, refuses or forgives anything a
    /// later call would have decided differently.
    pub fn prune(&mut self, tick_ms: u64) {
        let config = self.config;
        for state in self.sources.values_mut() {
            state.advance(&config, tick_ms);
        }
        self.sources.retain(|_, state| !state.is_reclaimable());
        for buckets in self.peers.values_mut() {
            buckets.advance(tick_ms);
        }
        self.peers.retain(|_, buckets| !buckets.is_debt_free());
    }

    /// Returns the record for `address`, creating one within the bounded table.
    ///
    /// When the table is full, records that owe nothing are dropped first. If
    /// every slot is still occupied, the least penalised record without a live
    /// connection is evicted, ordered by ban expiry, then score, then retained
    /// tokens, then address. A record with a live connection is never evicted,
    /// and the total connection cap keeps that set far smaller than the table.
    fn entry<'a>(
        sources: &'a mut BTreeMap<IpAddr, SourceState>,
        config: &AdmissionConfig,
        address: IpAddr,
        tick_ms: u64,
    ) -> Result<&'a mut SourceState, Refusal> {
        if !sources.contains_key(&address) {
            if sources.len() >= config.max_tracked_sources {
                sources.retain(|_, state| {
                    state.advance(config, tick_ms);
                    !state.is_reclaimable()
                });
            }
            if sources.len() >= config.max_tracked_sources {
                let victim = sources
                    .iter()
                    .filter(|(_, state)| state.connections == 0)
                    .min_by_key(|(key, state)| (state.eviction_key(), **key))
                    .map(|(key, _)| *key)
                    .ok_or(Refusal::TrackingFull)?;
                sources.remove(&victim);
            }
            sources.insert(address, SourceState::new(config, tick_ms));
        }
        sources.get_mut(&address).ok_or(Refusal::TrackingFull)
    }

    /// Makes room in the bounded per-connection table before inserting a record.
    ///
    /// Debt-free records are dropped first. If every slot still holds debt, the
    /// record holding the most tokens in `class` is evicted, ties broken by peer
    /// identity. Evicting a per-connection record cannot buy extra allowance,
    /// because the source tier of that host keeps its own debt regardless.
    fn reclaim_peers(
        peers: &mut BTreeMap<PeerId, ClassBuckets>,
        maximum: usize,
        class: MessageClass,
    ) {
        if peers.len() < maximum {
            return;
        }
        peers.retain(|_, buckets| !buckets.is_debt_free());
        while peers.len() >= maximum {
            let Some(victim) = peers
                .iter()
                .max_by_key(|(key, buckets)| {
                    (
                        buckets.messages[class as usize].tokens(),
                        buckets.bytes[class as usize].tokens(),
                        (*key).clone(),
                    )
                })
                .map(|(key, _)| key.clone())
            else {
                return;
            };
            peers.remove(&victim);
        }
    }
}

impl Default for AdmissionController {
    fn default() -> Self {
        Self::new(AdmissionConfig::default())
    }
}

/// Pairs an exhausted bucket with the tier that reported it.
const fn refusal(reason: Exhausted, tier: Tier) -> Refusal {
    match reason {
        Exhausted::Messages => Refusal::MessageRate(tier),
        Exhausted::Bytes => Refusal::ByteRate(tier),
    }
}

#[cfg(test)]
mod tests;
