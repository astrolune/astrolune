#!/usr/bin/env bash
# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT
set -euo pipefail

# LLVM's signed distribution supplies the same release as LLVM-MinGW.
# shellcheck source=/dev/null
. /etc/os-release
codename="${VERSION_CODENAME:?Ubuntu codename is required}"
if [ "${ID}" != ubuntu ]; then
  echo 'The native conformance installer requires Ubuntu.' >&2
  exit 1
fi
curl --fail --silent --show-error --location --max-time 60 \
  https://apt.llvm.org/llvm-snapshot.gpg.key \
  -o /usr/share/keyrings/astrolune-llvm.asc
printf 'deb [signed-by=/usr/share/keyrings/astrolune-llvm.asc] https://apt.llvm.org/%s/ llvm-toolchain-%s-22 main\n' \
  "$codename" "$codename" > /etc/apt/sources.list.d/astrolune-llvm.list
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes clang-22 lld-22
/usr/lib/llvm-22/bin/clang --version | head -n 1 | grep -F 'clang version 22.1.8 '
