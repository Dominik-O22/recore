#!/usr/bin/env bash
# The inner loop: build, analyze the corpus with and without unwind info, and score both.
set -euo pipefail
cd "$(dirname "$0")"
# Only the crates the loop needs; other crates may be mid-change.
cargo build --release -q -p recore -p recore-corpus
./target/release/recore corpus corpus/bin corpus/recore
./target/release/recore corpus corpus/bin corpus/recore-noframes --no-frames
./target/release/recore-corpus score corpus/recore corpus/recore-noframes "$@"
