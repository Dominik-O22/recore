#!/usr/bin/env bash
# Rebuilds arm64-data-in-code.o from its assembly. Needs clang.
set -euo pipefail
cd "$(dirname "$0")"
clang --target=aarch64-linux-gnu -c arm64-data-in-code.s -o arm64-data-in-code.o
