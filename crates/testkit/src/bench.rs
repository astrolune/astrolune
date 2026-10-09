// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded measurement harness for workspace benchmarks.
//!
//! The harness times a closure and reports integer nanosecond statistics. It
//! deliberately carries no assertions and no pass/fail notion: a benchmark run
//! records what one machine observed and nothing more. Measurements are not
//! correctness gates and do not establish throughput for any deployment.
//!
//! What this does NOT establish: distributed or end-to-end throughput, results
//! comparable across machines or toolchains, statistical significance of a
//! difference between two measurements, or any bound that holds under
//! contention from other processes. Round statistics describe the sampled
//! rounds only; they are not estimates of a population parameter.

use std::{
    env,
    fmt::Write as _,
    hint::black_box,
    time::{Duration, Instant},
};

/// Measured rounds recorded for each benchmark unless overridden.
pub const DEFAULT_ROUNDS: u32 = 20;

/// Unmeasured rounds executed before sampling, to settle caches and branch state.
pub const DEFAULT_WARMUP_ROUNDS: u32 = 3;

/// Target duration of a single round, used to calibrate the per-round batch.
///
/// Rounds shorter than this resolve poorly against operating-system scheduling
/// noise, so the batch size doubles until a round reaches this duration.
pub const DEFAULT_TARGET_ROUND: Duration = Duration::from_micros(2_000);

/// Largest per-round batch the calibrator will choose.
///
/// The cap bounds total run time when an operation is far cheaper than the
/// target round duration; a capped batch is reported as measured.
pub const MAX_BATCH: u64 = 1 << 24;

/// Environment variable overriding [`DEFAULT_ROUNDS`].
pub const ROUNDS_VARIABLE: &str = "ASTROLUNE_BENCH_ROUNDS";

/// Environment variable overriding [`DEFAULT_TARGET_ROUND`], in microseconds.
pub const TARGET_VARIABLE: &str = "ASTROLUNE_BENCH_TARGET_US";

/// Integer nanosecond statistics for one benchmarked operation.
///
/// Every duration is per single operation: a round times `batch` operations and
/// the elapsed time is divided by `batch` before any statistic is taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurement {
    /// Benchmark name as supplied by the caller.
    pub name: String,
    /// Measured rounds contributing to the statistics.
    pub rounds: u32,
    /// Operations executed per round, chosen by calibration.
    pub batch: u64,
    /// Fastest observed per-operation time, in nanoseconds.
    pub minimum_ns: u128,
    /// Median per-operation time over the measured rounds, in nanoseconds.
    pub median_ns: u128,
    /// Arithmetic mean per-operation time, in nanoseconds.
    pub mean_ns: u128,
    /// Slowest observed per-operation time, in nanoseconds.
    pub maximum_ns: u128,
}

impl Measurement {
    /// Returns whole operations per second implied by [`Self::median_ns`].
    ///
    /// Returns `None` when the median rounds to zero nanoseconds, which means
    /// the operation is below the harness resolution rather than infinitely
    /// fast.
    #[must_use]
    pub const fn operations_per_second(&self) -> Option<u128> {
        1_000_000_000_u128.checked_div(self.median_ns)
    }

    /// Returns the spread between the slowest and fastest round, in nanoseconds.
    ///
    /// A wide spread indicates scheduling noise or input-dependent work and is
    /// reported so a single median is not read as a stable figure.
    #[must_use]
    pub const fn spread_ns(&self) -> u128 {
        self.maximum_ns - self.minimum_ns
    }
}

/// Measurement settings shared by the benchmarks of one suite.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// Measured rounds per benchmark.
    pub rounds: u32,
    /// Unmeasured rounds executed before sampling.
    pub warmup_rounds: u32,
    /// Round duration the batch calibrator aims for.
    pub target_round: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            rounds: DEFAULT_ROUNDS,
            warmup_rounds: DEFAULT_WARMUP_ROUNDS,
            target_round: DEFAULT_TARGET_ROUND,
        }
    }
}

impl Settings {
    /// Reads settings from the environment, falling back to the defaults.
    ///
    /// Unparsable or zero values are ignored rather than rejected: the
    /// overrides exist to shorten exploratory runs, so a malformed value must
    /// not stop a measurement. Overrides change only how long sampling takes
    /// and how many rounds are reported.
    #[must_use]
    pub fn from_environment() -> Self {
        let mut settings = Self::default();
        if let Some(rounds) = env::var(ROUNDS_VARIABLE)
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|rounds| *rounds > 0)
        {
            settings.rounds = rounds;
        }
        if let Some(target) = env::var(TARGET_VARIABLE)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|microseconds| *microseconds > 0)
        {
            settings.target_round = Duration::from_micros(target);
        }
        settings
    }
}

/// A named group of benchmarks that reports once, after all of them have run.
///
/// Reporting is deferred so the printed table and the machine-readable record
/// describe the same set of measurements.
#[derive(Clone, Debug)]
pub struct Suite {
    name: String,
    settings: Settings,
    measurements: Vec<Measurement>,
}

impl Suite {
    /// Creates a suite that reads its measurement settings from the environment.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self::with_settings(name, Settings::from_environment())
    }

    /// Creates a suite with explicit settings, ignoring the environment.
    #[must_use]
    pub fn with_settings(name: impl Into<String>, settings: Settings) -> Self {
        Self {
            name: name.into(),
            settings,
            measurements: Vec::new(),
        }
    }

    /// Returns the measurements recorded so far.
    #[must_use]
    pub fn measurements(&self) -> &[Measurement] {
        &self.measurements
    }

    /// Times `operation` and records the result under `name`.
    ///
    /// The returned value of `operation` is passed through [`black_box`] so the
    /// optimizer cannot discard the work being measured. The closure is called
    /// many times, so it must be cheap to repeat and must not accumulate
    /// unbounded state. Use [`Suite::measurements`] to read what was recorded.
    pub fn bench<T, F: FnMut() -> T>(&mut self, name: impl Into<String>, operation: F) {
        let measurement = measure(name, self.settings, operation);
        self.measurements.push(measurement);
    }

    /// Prints a readable table followed by one machine-readable JSON record.
    ///
    /// The JSON line carries the `astrolune.benchmark/1` schema so a run can be
    /// captured as an artifact without re-parsing the table.
    pub fn report(&self) {
        println!("benchmark suite: {}", self.name);
        println!(
            "rounds: {}, warmup: {}, target round: {} us",
            self.settings.rounds,
            self.settings.warmup_rounds,
            self.settings.target_round.as_micros()
        );
        println!(
            "{:<54} {:>12} {:>12} {:>12} {:>14}",
            "name", "median ns", "min ns", "max ns", "ops/s"
        );
        for measurement in &self.measurements {
            let rate = measurement
                .operations_per_second()
                .map_or_else(|| "below resolution".to_owned(), |rate| rate.to_string());
            println!(
                "{:<54} {:>12} {:>12} {:>12} {:>14}",
                measurement.name,
                measurement.median_ns,
                measurement.minimum_ns,
                measurement.maximum_ns,
                rate
            );
        }
        println!("{}", self.to_json());
    }

    /// Renders the suite as a single-line `astrolune.benchmark/1` JSON record.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut json = String::from(r#"{"schema":"astrolune.benchmark/1","suite":""#);
        escape_into(&mut json, &self.name);
        let _ = write!(
            json,
            r#"","rounds":{},"target_round_us":{},"measurements":["#,
            self.settings.rounds,
            self.settings.target_round.as_micros()
        );
        for (index, measurement) in self.measurements.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            json.push_str(r#"{"name":""#);
            escape_into(&mut json, &measurement.name);
            let _ = write!(
                json,
                r#"","batch":{},"rounds":{},"minimum_ns":{},"median_ns":{},"mean_ns":{},"maximum_ns":{}}}"#,
                measurement.batch,
                measurement.rounds,
                measurement.minimum_ns,
                measurement.median_ns,
                measurement.mean_ns,
                measurement.maximum_ns
            );
        }
        json.push_str("]}");
        json
    }
}

/// Times a single operation and returns its per-operation statistics.
///
/// Prefer [`Suite::bench`] so related measurements report together; this entry
/// point exists for a benchmark that records exactly one figure.
pub fn measure<T, F: FnMut() -> T>(
    name: impl Into<String>,
    settings: Settings,
    mut operation: F,
) -> Measurement {
    let batch = calibrate(settings.target_round, &mut operation);
    for _ in 0..settings.warmup_rounds {
        run_batch(batch, &mut operation);
    }
    let mut samples = Vec::with_capacity(settings.rounds as usize);
    for _ in 0..settings.rounds {
        let elapsed = run_batch(batch, &mut operation);
        samples.push(elapsed.as_nanos() / u128::from(batch));
    }
    samples.sort_unstable();
    let rounds = u32::try_from(samples.len()).unwrap_or(u32::MAX);
    let total: u128 = samples.iter().sum();
    Measurement {
        name: name.into(),
        rounds,
        batch,
        minimum_ns: samples.first().copied().unwrap_or_default(),
        median_ns: median(&samples),
        mean_ns: total / u128::from(rounds.max(1)),
        maximum_ns: samples.last().copied().unwrap_or_default(),
    }
}

/// Returns the median of an already sorted sample set.
///
/// Even sample counts take the midpoint of the two central values, which floors
/// to a whole nanosecond count and cannot overflow on the way there. An empty
/// set has no median and reports zero.
fn median(sorted: &[u128]) -> u128 {
    let middle = sorted.len() / 2;
    match sorted.len() {
        0 => 0,
        length if length.is_multiple_of(2) => u128::midpoint(sorted[middle - 1], sorted[middle]),
        _ => sorted[middle],
    }
}

/// Chooses the smallest power-of-two batch whose round reaches `target`.
///
/// Calibration starts at a single operation and doubles, so an expensive
/// operation is never executed more than twice as often as needed. The search
/// stops at [`MAX_BATCH`] even when the target is unmet.
fn calibrate<T, F: FnMut() -> T>(target: Duration, operation: &mut F) -> u64 {
    let mut batch = 1;
    loop {
        if run_batch(batch, operation) >= target || batch >= MAX_BATCH {
            return batch;
        }
        batch *= 2;
    }
}

/// Runs `operation` `batch` times and returns the elapsed wall-clock time.
///
/// The timer brackets the whole batch rather than each call, so per-call clock
/// overhead is not attributed to the operation.
fn run_batch<T, F: FnMut() -> T>(batch: u64, operation: &mut F) -> Duration {
    let started = Instant::now();
    for _ in 0..batch {
        black_box(operation());
    }
    started.elapsed()
}

/// Appends `value` to `json` with the escapes required for a JSON string.
///
/// Benchmark names are written in source, so this guards against an accidental
/// quote or control byte rather than against hostile input.
fn escape_into(json: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '"' => json.push_str("\\\""),
            '\\' => json.push_str("\\\\"),
            '\n' => json.push_str("\\n"),
            '\r' => json.push_str("\\r"),
            '\t' => json.push_str("\\t"),
            control if control.is_control() => {
                let _ = write!(json, "\\u{:04x}", u32::from(control));
            }
            other => json.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Measurement, Settings, Suite, calibrate, escape_into, measure, median};
    use std::time::Duration;

    fn quick() -> Settings {
        Settings {
            rounds: 3,
            warmup_rounds: 1,
            target_round: Duration::from_micros(1),
        }
    }

    #[test]
    fn median_handles_odd_even_and_empty_sample_sets() {
        assert_eq!(median(&[]), 0);
        assert_eq!(median(&[7]), 7);
        assert_eq!(median(&[2, 4]), 3);
        assert_eq!(median(&[1, 2, 3]), 2);
        // Integer division truncates rather than rounding the central average.
        assert_eq!(median(&[1, 2]), 1);
    }

    #[test]
    fn calibration_returns_a_power_of_two_within_the_cap() {
        let batch = calibrate(Duration::from_micros(1), &mut || 1_u64 + 1);
        assert!(
            batch.is_power_of_two(),
            "batch {batch} is not a power of two"
        );
        assert!(batch <= super::MAX_BATCH);
    }

    #[test]
    fn a_measurement_orders_its_statistics_and_counts_every_round() {
        let settings = quick();
        let measurement = measure("addition", settings, || 1_u64 + 1);
        assert_eq!(measurement.rounds, settings.rounds);
        assert!(measurement.batch >= 1);
        assert!(measurement.minimum_ns <= measurement.median_ns);
        assert!(measurement.median_ns <= measurement.maximum_ns);
        assert!(measurement.mean_ns >= measurement.minimum_ns);
        assert!(measurement.mean_ns <= measurement.maximum_ns);
        assert_eq!(
            measurement.spread_ns(),
            measurement.maximum_ns - measurement.minimum_ns
        );
    }

    #[test]
    fn a_zero_median_reports_no_rate_instead_of_dividing_by_zero() {
        let measurement = Measurement {
            name: "resolution".to_owned(),
            rounds: 1,
            batch: 1,
            minimum_ns: 0,
            median_ns: 0,
            mean_ns: 0,
            maximum_ns: 0,
        };
        assert_eq!(measurement.operations_per_second(), None);
        assert_eq!(
            Measurement {
                median_ns: 500,
                ..measurement
            }
            .operations_per_second(),
            Some(2_000_000)
        );
    }

    #[test]
    fn a_suite_records_every_benchmark_and_emits_the_pinned_schema() {
        let mut suite = Suite::with_settings("arithmetic", quick());
        suite.bench("addition", || 1_u64 + 1);
        suite.bench("multiplication", || 3_u64 * 3);
        assert_eq!(suite.measurements().len(), 2);
        let json = suite.to_json();
        assert!(json.starts_with(r#"{"schema":"astrolune.benchmark/1","suite":"arithmetic""#));
        assert!(json.contains(r#"{"name":"addition","batch":"#));
        assert!(json.contains(r#"{"name":"multiplication","batch":"#));
        assert!(json.ends_with("]}"));
        // One record per benchmark, so the separator count is one fewer.
        assert_eq!(json.matches(r#"{"name":"#).count(), 2);
    }

    #[test]
    fn names_with_quotes_or_control_bytes_stay_inside_one_json_string() {
        let mut json = String::new();
        escape_into(&mut json, "a\"b\\c\nd\te\r\u{1}");
        assert_eq!(json, r#"a\"b\\c\nd\te\r\u0001"#);
    }

    #[test]
    fn environment_settings_ignore_malformed_and_zero_overrides() {
        // The variables are only read here, so a parallel test cannot observe a
        // mutation from this one; whatever the ambient values are, both fields
        // must stay usable as divisors and loop bounds.
        let settings = Settings::from_environment();
        assert!(settings.rounds > 0);
        assert!(settings.target_round > Duration::ZERO);
    }
}
