# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

# Use rustup proxies even when an old standalone Rust installation precedes them.
$rustupDirectory = Join-Path $env:USERPROFILE '.cargo/bin'

if (-not (Test-Path -LiteralPath (Join-Path $rustupDirectory 'rustup.exe'))) {
    throw 'Install rustup before activating the pinned project toolchain.'
}

$env:PATH = $rustupDirectory + ';' + $env:PATH

rustup show active-toolchain
rustc --version
cargo --version