# Copyright (c) 2026 Astrolune contributors
# SPDX-License-Identifier: MIT

# Coverage feedback only: this does not enable AddressSanitizer or instrument std.
param(
    [ValidateRange(1, 86400)][int]$Seconds = 300,
    [ValidateRange(1, 2147483647)][int]$Seed = 20261005
)

$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$previousFlags = $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS
$previousIncremental = $env:CARGO_INCREMENTAL
$previousArtifacts = $env:ASTROLUNE_FUZZ_ARTIFACTS

Push-Location $root

try {
    . (Join-Path $PSScriptRoot 'enter-dev.ps1')

    $env:CARGO_INCREMENTAL = '0'

    # Optimized sancov-module on the pinned MSVC compiler can produce mismatched
    # counter/PC tables. Keep the verified unoptimized instrumentation profile.
    $flags = '-Copt-level=0 -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares'
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = $flags

    $run = Join-Path $root ('target/fuzz-campaign-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $run | Out-Null

    $corpus = Join-Path $run 'corpus'
    $artifacts = Join-Path $run 'artifacts'
    New-Item -ItemType Directory -Path $artifacts | Out-Null

    cargo build --locked --offline --release --manifest-path crates/codec/fuzz/Cargo.toml --target x86_64-pc-windows-msvc --target-dir target/fuzz-coverage --features windows-coverage --bin decode_extensions *> (Join-Path $run 'build.log')
    if ($LASTEXITCODE -ne 0) { throw "Fuzzer build failed; see $run/build.log" }

    # The seed exporter is ordinary Rust, without fuzz instrumentation.
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = $previousFlags

    cargo run --locked --offline --release -p integration --example export_fuzz_seeds -- $corpus *> (Join-Path $run 'seeds.log')
    if ($LASTEXITCODE -ne 0) { throw "Seed export failed; see $run/seeds.log" }

    $binary = Join-Path $root 'target/fuzz-coverage/x86_64-pc-windows-msvc/release/decode_extensions.exe'

    $seedHashes = @(Get-ChildItem -LiteralPath $corpus -File | Sort-Object Name | ForEach-Object {
        @{ name = $_.Name; bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })

    $report = [ordered]@{
        startedUtc = [DateTime]::UtcNow.ToString('o'); compiler = @(rustc -Vv)
        flags = $flags; binarySha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
        seconds = $Seconds; seed = $Seed; initialCorpus = $seedHashes
        addressSanitizer = $false; standardLibraryInstrumented = $false
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $run 'report.json')

    Write-Output "Coverage campaign: $run"

    $env:ASTROLUNE_FUZZ_ARTIFACTS = $artifacts

    & $binary $corpus "-max_total_time=$Seconds" "-seed=$Seed" -max_len=65536 -timeout=15 -rss_limit_mb=2048 -print_final_stats=1 "-artifact_prefix=$artifacts/" *> (Join-Path $run 'fuzzer.log')
    $result = $LASTEXITCODE

    $log = Get-Content -LiteralPath (Join-Path $run 'fuzzer.log') -Raw
    $counters = [regex]::Match($log, '(\d+) inline 8-bit counters')
    $pcs = [regex]::Match($log, '(\d+) PCs')

    $report.completedUtc = [DateTime]::UtcNow.ToString('o')
    $report.exitCode = $result
    $report.validCoverage = $counters.Success -and $pcs.Success -and
        $counters.Groups[1].Value -eq $pcs.Groups[1].Value -and
        $log.Contains('DONE') -and $log.Contains('NEW')
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $run 'report.json')

    Get-Content -LiteralPath (Join-Path $run 'fuzzer.log') -Tail 12

    if ($result -ne 0 -or -not $report.validCoverage) { throw "Campaign failed qualification; preserve $run" }
}
finally {
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = $previousFlags
    $env:CARGO_INCREMENTAL = $previousIncremental
    $env:ASTROLUNE_FUZZ_ARTIFACTS = $previousArtifacts
    Pop-Location
}