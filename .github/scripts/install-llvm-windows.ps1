# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT
param([string]$Compiler)
$ErrorActionPreference = 'Stop'

if (-not $Compiler) {
    $parent = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
    $llvmDirectory = Join-Path $parent 'astrolune-llvm-22.1.8'
    $Compiler = Join-Path $llvmDirectory 'llvm-mingw-20260616-ucrt-x86_64/bin/clang.exe'
    if (-not (Test-Path -LiteralPath $Compiler)) {
        if (Test-Path -LiteralPath $llvmDirectory) {
            throw 'An incomplete LLVM installation exists. Choose an empty installation directory.'
        }
        New-Item -ItemType Directory -Path $llvmDirectory | Out-Null
        $archive = Join-Path $llvmDirectory 'llvm.zip'
        # Version and SHA256 are pinned to the LLVM-MinGW UCRT publisher archive.
        Invoke-WebRequest -Uri 'https://github.com/mstorsjo/llvm-mingw/releases/download/20260616/llvm-mingw-20260616-ucrt-x86_64.zip' -OutFile $archive -TimeoutSec 180
        $expected = 'b9b68a4d276e16fa25802aaba458e4638f64b3884c290aaccdc2d87083b6ca35'
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
            throw 'Pinned LLVM-MinGW archive checksum mismatch.'
        }
        Expand-Archive -LiteralPath $archive -DestinationPath $llvmDirectory
    }
}
$Compiler = (Resolve-Path -LiteralPath $Compiler).Path
$identity = & $Compiler --no-default-config --version
if ($LASTEXITCODE -ne 0 -or $identity[0] -notmatch 'clang version 22\.1\.8(?:\s|$)') {
    throw 'Native conformance requires LLVM 22.1.8.'
}
$env:ASTROLUNE_LLVM_CLANG = $Compiler
if ($env:GITHUB_ENV) {
    "ASTROLUNE_LLVM_CLANG=$Compiler" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
}
Write-Output $identity[0]
