<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# 52. Routine network operations and calibration

This runbook covers starting an already provisioned private network, planned
maintenance, catch-up, telemetry and disk planning. Identity provisioning,
signing-state recovery and incident handling remain in the existing
[network operations](36-private-network-operations.md),
[durable signing](16-durable-signing.md) and
[custody and release authority](53-key-custody-and-release-authority.md) documents.
The procedures here are operational; they do not establish distributed-load
qualification, which needs its own retained evidence.

## Start and verify

Retain the exact binary revision, network configuration, role, data-directory path,
peer addresses and launch arguments with the deployment record. Use the generated
`START.txt` or the deployment's existing launch command for each validator. An
already provisioned observer can use:

```text
daemon --observer --run --genesis genesis.bin --validators validators.bin \
  --data-dir observer-data --tls-dir observer-tls \
  --p2p-listen 10.20.0.5:18000 --rpc-listen 127.0.0.1:19000 \
  --peers 10.20.0.1:18000 --metrics-listen 127.0.0.1:19001
```

Use one line in PowerShell. Select addresses for the actual deployment. The
observer uses the same public genesis/profile and initial registry as its peers.
`--discover-in` and `--compact-blocks` are optional; record their values when
comparing runs. Leave RPC and metrics on the intended local interface. The metrics
listener requires loopback, so run the sampler on each host or use an already
configured local forwarding arrangement; it does not create remote access.

Before starting listeners, run the same command with `--dry-run` in place of
`--run`. This checks configuration and identity inputs without opening the
validator journal or fully replaying its history. When the service is stopped,
`--blocks 0` instead of `--run` performs actual history and node-role recovery and
then exits. That operation opens the data directory and is not a concurrent
inspection command.

Start each process once with its assigned directory. Save standard output and
standard error in the service manager's rotated logs. Check the printed genesis
hash, role, storage format, recovered next height, P2P/RPC addresses and metrics
address against the deployment record. Then observe at least several successive
advancing heights:

```text
cli status 127.0.0.1:19000
```

Record the returned chain ID, height and block hash. Sampling different nodes at
different times can legitimately return different heights. RPC status and metrics
are local observations; independent verification follows the existing
[state-proof](32-certified-state-proofs.md) and
[receipt](35-certified-receipts.md) workflows.

## Stop, restart and planned maintenance

For a finite qualification run, `--blocks N` exits after N additional finalized
heights, including imports. For a running service, stop its exact process through
the existing service manager, then wait until that process has exited before
restarting it. The daemon currently has no application-level shutdown RPC or
signal-driven drain; operating-system termination uses the normal durable recovery
path on restart. Do not describe a service-manager stop as a drained mempool.
Accepted pending transactions can be lost on process termination. Applications
should retain their submission identifiers and use the receipt workflow.

Restart using the same directory, network profile and existing launch command.
Confirm recovered height and subsequent advancement. Record uptime reset and the
maintenance interval with telemetry; counters from separate processes cannot be
subtracted as one uninterrupted run. If recovery fails, keep the directory and
logs and follow the linked recovery procedure rather than improvising data edits.

Plan rolling maintenance by profile:

| Profile | Expected availability during maintenance |
|---|---|
| Fixed committee | Continuing finality needs more than two thirds of configured voting weight online. Node count alone does not establish this. |
| VRF/PoTB rotation | Fresh production requires complete-roster contributions, including eligible standby identities. Taking one of those identities offline can intentionally pause production even when voting weight is otherwise sufficient. |
| Observer | Stopping an observer removes its RPC/relay capacity. Confirm another route exists before stopping a bootstrap or application endpoint. |

Start with an observer when possible. Stop one selected process, perform the
planned binary/configuration replacement, restart it and verify catch-up before
moving to another. Keep the same protocol profile unless a separate upgrade plan
defines a transition. In the rotating profiles, schedule a production pause when
complete-roster availability cannot be maintained; do not promise zero-downtime
rolling upgrades. End maintenance only after every intended participant is back,
reachable and advancing again. Compatibility of an arbitrary older binary is not
established by these instructions.

## Catch-up and disk growth

An observer requests its first missing finalized height from configured peers.
Compare its height over time with an advancing reference peer. A decreasing height
gap shows catch-up; an increasing local finalized-block counter includes imported
history and must not be counted as newly produced network throughput. Repeated
samples with unchanged height deserve examination of peer routes, connection and
exchange counters, and local logs. Session rotation can increment exchange-failure
counters during otherwise normal operation.

Record data-directory size, filesystem free bytes, finalized height and UTC time
at the beginning and end of each representative workload window. Linux examples:

```sh
du -sb -- observer-data
df -B1 -- observer-data
```

PowerShell equivalents, with the deployment's literal path:

```powershell
(Get-ChildItem -LiteralPath 'D:\nodes\observer-data' -File -Recurse |
    Measure-Object -Property Length -Sum).Sum
Get-PSDrive -Name D | Select-Object Name, Used, Free
```

Directory enumeration measures logical file bytes, while filesystem free space
includes allocation and other activity. Keep rotated logs and other services in
the capacity estimate. For a positive size increase, compute bytes per elapsed
second and, when height advanced, bytes per imported/finalized block. Use several
windows with the actual transaction/contract mix and retain the highest observed
sustained growth for planning. Free bytes divided by that rate estimates remaining
time only while the workload and other disk activity stay comparable. Set local
thresholds early enough for the deployment's maintenance lead time. No universal
disk threshold is established here; each deployment derives its own from its
measured growth rate.

New network directories use append-only history; automatic retention is not
implemented. Existing archive formats keep their documented caps. Do not remove
individual history files as a space-management procedure. Planned manual export
and retained-history operations follow
[pinned history retention](49-pinned-history-retention.md), including its stop and
destination requirements.

## Bounded calibration sampler

[`tools/calibrate-network.py`](../tools/calibrate-network.py) uses only the Python
standard library and performs read-only HTTP metrics requests. Example from the
repository root, with an unused output directory and the actual build revision:

```text
python tools/calibrate-network.py \
  --endpoint validator-a=http://127.0.0.1:19001/metrics \
  --endpoint observer-b=http://127.0.0.1:19002/metrics \
  --duration 60 --interval 1 --timeout 2 --workers 2 \
  --revision EXACT_BUILD_REVISION \
  --topology "one host; fixed committee; existing workload; compact blocks off" \
  --output measurements/run-001
```

Endpoint names must be unique. URLs require numeric IPv4/IPv6 addresses, an explicit
port and exactly `/metrics`; there is no DNS lookup, proxy lookup or redirect
following. The sampler accepts the current unlabelled unsigned AstroLune exporter
format and HTTP Content-Length or close-delimited responses. It does not support
HTTPS or chunked framing. Existing remote access arrangements must present the
compatible endpoint locally rather than changing the daemon's listener policy.

The limits are 32 endpoints, eight worker threads, 10,000 total samples, a one-hour
sampling window, a minimum 100 ms round interval and a maximum ten-second poll
timeout. Each complete response is limited to 16 KiB and 64 metrics. All socket
operations share one absolute per-poll deadline capped by the run deadline; a
queued poll cannot extend the sampling window by its own timeout. Local scheduling,
thread teardown and output writes can add overhead after that deadline. Missed
rounds are skipped rather than accumulated in a backlog.

The exclusive new output directory contains:

| File | Contents |
|---|---|
| `metadata.json` | Schema version, UTC start, sampler host/Python/platform, supplied revision/topology, endpoints and bounds. |
| `samples.jsonl` | One flushed JSON record per completed attempt: node, round, UTC and monotonic offsets, raw exporter text when available, parsed values or error, and poll duration. |
| `report.json` | Metadata, completion/interruption status and per-node summaries. |

Files and existing output directories are never overwritten. Exit code 0 means
all recorded polls succeeded; 1 means at least one failed or none completed; 2 means invalid
configuration or a local I/O error; 130 means interruption with a partial report.
An interrupted run may omit in-flight results. An I/O failure can leave an
incomplete directory without `report.json`; retain it as incomplete evidence.

Rates use adjacent successful samples with strictly increasing monotonic offsets.
Intervals across failed polls, missed rounds, counter/uptime decreases or height
regressions are excluded and reported. A restart that does not produce an observed
decrease can remain invisible; the tool cannot reconstruct activity inside gaps.
Counter deltas include only names present at both comparable endpoints. Metrics
are independently read process-local values, not an atomic chain snapshot.

`poll_duration_ms_all` and `poll_duration_ms_successful` give nearest-rank p50,
p95 and p99 of HTTP polling duration. **They do not measure consensus or transaction
finality latency.** Finalized blocks per second includes catch-up; accepted RPC
transactions are not finalized transactions. Do not sum the same replicated chain's
per-node advancement as network throughput. Measuring submission-to-finality latency
requires a separately recorded workload and receipt observations.

For a reproducible comparison, retain exact launch options, node hardware/OS,
binary revision, profile, topology, workload, initial height and catch-up state.
Measure an idle baseline, a stable workload window and a planned restart/catch-up
window separately. Compare the same conditions with the optional feature toggled
and retain raw outputs from both runs. When sampling on multiple hosts, preserve
each host's report and clock-alignment information; monotonic offsets are meaningful
only within their own run. The sampler records supplied topology/revision without
independently attesting them.

## Observed qualification

On 2026-10-07, these dependency-free tests passed on Windows Python and Ubuntu WSL
Python: **17 tests on each platform**, using temporary outputs and local HTTP
servers. The tests cover exporter parsing, address families, response framing,
slow-response and queued-request deadlines, worker limits, configured bounds,
exclusive output creation, interruptions, resets, gaps and summary calculations.

```text
python -B -m unittest discover -s tools -p test_calibrate_network.py -v
```

```sh
python3 -B -m unittest discover -s tools -p test_calibrate_network.py -v
```

This is qualification of the sampler. It is not a Linux Rust workspace run,
independent-machine reproducibility, a distributed network benchmark, or an
operating acceptance result for a deployment. Those results require their own
retained evidence. No consensus-latency or throughput improvement is inferred
from these functional tests.
