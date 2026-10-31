#!/usr/bin/env bash
# The inner loop: build, analyze each corpus with and without unwind info, and score.
# Extra arguments go to the scorer, e.g. `./check.sh --detail`. The corpora are read where
# corpus/store.py says, and recore's output goes to target/corpus/<corpus>.
#
# `./check.sh --against <ref>` is how to say what a change did: it also analyzes every corpus
# with recore built at <ref>, and `recore-corpus compare` prints each count that moved, with
# the binaries it moved in. It fails when a total got worse.
#
# Last, `recore-bench ratchet` counts the instructions analysis and `diff` execute on the
# benchmark set, and fails when a count grew past bench/budget.json.
set -euo pipefail
cd "$(dirname "$0")"
# What the run below is of, for the status it leaves on that commit.
head="$(git rev-parse HEAD)" uncommitted="$(git status --porcelain)"
against=
if [ "${1:-}" = --against ]; then
  against="$(git rev-parse --verify "${2:?--against takes a git ref}^{commit}")"
  shift 2
fi
# Only the crates the loop needs; other crates may be mid-change.
cargo build --release -q -p recore -p recore-corpus -p recore-bench
# Only crates/*/tests may name the program a test needs. CI runs this scan with the other
# tests; the loop runs it first, so a leaked name fails before the corpora are scored.
cargo test --release -q -p recore --test general_naming
corpora="${RECORE_CORPORA:-$HOME/recore-corpora}"
# The base is built once per commit, from a worktree that goes away after, and its analysis is
# kept by commit, so the next comparison against the same commit only analyzes this checkout.
if [ -n "$against" ]; then
  base="target/against/recore-$against"
  if [ ! -x "$base" ]; then
    src=target/against/src
    git worktree remove --force "$src" 2>/dev/null || true
    git worktree add -q --detach "$src" "$against"
    CARGO_TARGET_DIR="$PWD/target/against/build" cargo build --release -q -p recore --manifest-path "$src/Cargo.toml"
    cp target/against/build/release/recore "$base"
    git worktree remove --force "$src"
  fi
fi
# analyze <variant> <binaries> [flags]: this checkout's recore, and the base's when there is one.
analyze() {
  local variant="$1" bin="$2"
  shift 2
  ./target/release/recore corpus "$bin" "$out/$variant" "$@" 2>/dev/null
  dirs+=("$out/$variant")
  if [ -n "$against" ] && [ ! -e "$out/against-$against/$variant/done" ]; then
    "$base" corpus "$bin" "$out/against-$against/$variant" "$@" 2>/dev/null
    touch "$out/against-$against/$variant/done"
  fi
}
worse=()
# Every corpus in the store that has truth, so a new corpus is scored without a change here.
for in in "$corpora"/*/; do
  in="${in%/}" corpus="$(basename "$in")"
  [ -d "$in/truth" ] || continue
  # The held-out corpora score a change once it is done, and are never part of the loop.
  [[ "$corpus" == *-holdout ]] && continue
  out="target/corpus/$corpus"
  dirs=()
  analyze recore "$in/bin"
  # A raw image, which a layout file describes, has no unwind info to leave out.
  if ! compgen -G "$in/bin/*.toml" >/dev/null; then
    analyze recore-noframes "$in/bin" --no-frames
  fi
  # Mach-O truth is mostly the linker's list of function starts, which the first run reads.
  # This one gets the same binaries without that list.
  if [ -d "$in/nostarts" ]; then
    analyze recore-nostarts "$in/nostarts"
  fi
  # The same PE images with their base relocations stripped, as corpus/strip_relocs.py writes them.
  if [ -d "$in/norelocs" ]; then
    analyze recore-norelocs "$in/norelocs"
  fi
  ./target/release/recore-corpus --corpus "$in" score "${dirs[@]}" "$@"
  if [ -n "$against" ]; then
    for dir in "${dirs[@]}"; do
      ./target/release/recore-corpus --corpus "$in" compare "$out/against-$against/${dir##*/}" "$dir" || worse+=("$dir")
    done
  fi
done
if ! ./target/release/recore-bench ratchet; then
  worse+=("bench/budget.json")
fi
if [ ${#worse[@]} -gt 0 ]; then
  echo "worse${against:+ than $against}: ${worse[*]}" >&2
  exit 1
fi
# `main` takes a commit only with this status, so it says that this run passed on that commit. A
# budget this run lowered is left to commit, and the commit then needs a run of its own.
if [ -z "$against" ] || [ -n "$uncommitted$(git status --porcelain)" ] || [ "$head" != "$(git rev-parse HEAD)" ]; then
  echo "no check status: that takes --against, on a commit with nothing left to commit" >&2
elif ! gh api --silent "repos/{owner}/{repo}/statuses/$head" -f state=success -f context=check -f description="passed against ${against:0:12}"; then
  echo "no check status: GitHub has to know $head, so push before the run" >&2
fi
