#!/usr/bin/env bash
# The inner loop: build, analyze each corpus with and without unwind info, and score.
# Extra arguments go to the scorer, e.g. `./check.sh --detail`. The corpora are read where
# corpus/store.py says, and recore's output goes to target/corpus/<corpus>.
#
# `./check.sh --against <ref>` is how to say what a change did: it also analyzes every corpus
# with recore built at <ref>, and `recore-corpus compare` prints each count that moved, with
# the binaries it moved in. It fails when a total got worse.
#
# Where a corpus has DWARF, the decompiler's signatures are scored too: a fixed sample of each
# binary's functions, each one's parameter count, whether it returns a value, and what its
# parameters, its return and the globals it uses are (a number, a float or a pointer, and its
# size), held against the
# base's decompiler on the same functions with `recore-decompile params --against`.
#
# Last, `recore-bench ratchet` counts the instructions of what an agent waits for on the
# benchmark set, and fails when a count grew past bench/budget.json.
#
# With a base, `recore-bench cost` then fails when the largest binaries took more than 10% more
# time or 10% more memory with this build than with the base's. RECORE_COST_ACCEPTED=1 lets a
# change past that which its description says is worth it.
#
# `--quick` is for while a change is made: it builds the ci profile, without whole-program
# optimization, which rebuilds in seconds rather than minutes and scores the same unless a number
# overflows, which panics there. It skips the ratchet, the cost and the status, which measure the
# build that ships. The run that leaves the status is a full one.
set -euo pipefail
cd "$(dirname "$0")"
# What the run below is of, for the status it leaves on that commit.
head="$(git rev-parse HEAD)" uncommitted="$(git status --porcelain)"
quick= against=
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) quick=1; shift ;;
    --against) against="$(git rev-parse --verify "${2:?--against takes a git ref}^{commit}")"; shift 2 ;;
    *) break ;;
  esac
done
profile=release
[ -n "$quick" ] && profile=ci
build="target/$profile"
# Only the crates the loop needs; other crates may be mid-change.
if [ -n "$quick" ]; then
  cargo build --profile ci -q -p recore -p recore-corpus -p recore-decomp
else
  cargo build --release -q -p recore -p recore-corpus -p recore-bench -p recore-mcp -p recore-decomp
fi
# Only crates/*/tests may name the program a test needs. CI runs this scan with the other
# tests; the loop runs it first, so a leaked name fails before the corpora are scored. It reads
# only the sources, so it takes the profile the tests already build rather than linking a release.
cargo test --profile ci -q -p recore --test general_naming
corpora="${RECORE_CORPORA:-$HOME/recore-corpora}"
# once <dir> <stamp> <command>...: runs the command, which writes <dir>, unless a run from any
# checkout already did with the same stamp. The lock keeps two checkouts from writing it at once.
once() {
  local dir="$1" stamp="$2"
  shift 2
  mkdir -p "$(dirname "$dir")"
  (
    flock 9
    if [ "$(cat "$dir.done" 2>/dev/null)" != "$stamp" ]; then
      rm -f "$dir.done"
      rm -rf "$dir"
      "$@"
      echo "$stamp" >"$dir.done"
    fi
  ) 9>"$dir.lock"
}
# The base is a build of <ref> with this run's profile, which every worktree of this repository
# shares: its binaries and its outputs, kept under the main checkout's target/bases. Its
# decompiler stops at a time limit, so a base made with the other profile is a different base.
if [ -n "$against" ]; then
  shared="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")/target/bases"
  base="$shared/$against-$profile"
  # Held to the end of the run, so that no other run prunes the base while this one reads it.
  mkdir -p "$base"
  exec 7>"$base.lock"
  flock -s 7
  build_base() {
    (
      flock 8
      git worktree remove --force "$shared/src" 2>/dev/null || true
      git worktree add -q --detach "$shared/src" "$against"
      CARGO_TARGET_DIR="$shared/build" cargo build --profile "$profile" -q -p recore -p recore-mcp -p recore-decomp --manifest-path "$shared/src/Cargo.toml"
      mkdir -p "$base/bin"
      cp "$shared/build/$profile"/{recore,recore-mcp,recore-decompile} "$base/bin"
      git worktree remove --force "$shared/src"
    ) 8>"$shared/build.lock"
  }
  once "$base/bin" built build_base
  # The four newest bases stay, and one that a run still holds.
  touch "$base"
  { ls -dt "$shared"/*-release/ "$shared"/*-ci/ 2>/dev/null || true; } | tail -n +5 | while read -r old; do
    flock -n "${old%/}.lock" rm -rf "$old" || true
  done
fi
# analyze <variant> <binaries> [flags]: this checkout's recore, and the base's when there is one.
analyze() {
  local variant="$1" bin="$2"
  shift 2
  "$build/recore" corpus "$bin" "$out/$variant" "$@" 2>/dev/null
  dirs+=("$out/$variant")
  if [ -n "$against" ]; then
    once "$base_out/$variant" done "$base/bin/recore" corpus "$bin" "$base_out/$variant" "$@" 2>/dev/null
  fi
}
# signatures <corpus>: decompiles the sample of each binary with this checkout's decompiler and
# the base's, scores it, and compares the two over the functions both decompiled in time. Shards
# of 25 split the largest binaries over several processes.
signatures() {
  local in="$1" sample=(--sample "$SIGNATURE_SAMPLE" --debug-dir "$1/debug" --timeout 5 --shard 25 --jobs "$CORES")
  # A report left from an earlier run would pass for this one's.
  rm -rf "$out/signatures"
  "$build/recore-decompile" corpus "$in/bin" "$out/signatures" "${sample[@]}" >"$out/signatures.log" 2>&1
  # A debug file without DWARF, as the unstripped original of a Mach-O binary is, lists no
  # function to decompile. Only summary.json is written then, and 0 of 0 would read as a score.
  local reports=("$out"/signatures/*.json)
  if [ "${#reports[@]}" -le 1 ]; then
    echo "$out/signatures: no debug file lists a function, so no signature is scored"
    return
  fi
  "$build/recore-decompile" params "$out/signatures" "$in/debug" | sed -n '1p;3,7p'
  if [ -n "$against" ] && [[ "$("$base/bin/recore-decompile" corpus --help)" != *--sample* ]]; then
    echo "$out/signatures: the base's decompiler takes no --sample, so nothing to compare with"
  elif [ -n "$against" ]; then
    # Made again if this checkout samples differently.
    once "$base_out/signatures" "${sample[*]}" base_signatures "$in" "${sample[@]}"
    echo "$out/signatures against $base_out/signatures"
    "$build/recore-decompile" params "$out/signatures" "$in/debug" --against "$base_out/signatures" || worse+=("$out/signatures")
  fi
}
base_signatures() {
  local in="$1"
  shift
  "$base/bin/recore-decompile" corpus "$in/bin" "$base_out/signatures" "$@" >"$base_out/signatures.log" 2>&1
}
# Functions of each binary whose signatures are scored: enough to see a change that reaches many
# functions, few enough to keep the run short.
SIGNATURE_SAMPLE=100
# One decompiler per core. Two on the threads of one core take twice as long each and finish no
# sooner, and twice as many reach the time limit.
CORES="$(lscpu -p=core 2>/dev/null | awk '!/^#/' | sort -u | wc -l || true)"
[ "$CORES" -gt 1 ] || CORES="$(nproc)"
worse=()
# Every corpus in the store that has truth, so a new corpus is scored without a change here.
for in in "$corpora"/*/; do
  in="${in%/}" corpus="$(basename "$in")"
  [ -d "$in/truth" ] || continue
  # The held-out corpora score a change once it is done, and are never part of the loop.
  [[ "$corpus" == *-holdout ]] && continue
  out="target/corpus/$corpus"
  base_out="${base:-}/corpus/$corpus"
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
  "$build/recore-corpus" --corpus "$in" score "${dirs[@]}" "$@"
  if [ -n "$against" ]; then
    for dir in "${dirs[@]}"; do
      "$build/recore-corpus" --corpus "$in" compare "$base_out/${dir##*/}" "$dir" || worse+=("$dir")
    done
  fi
  # The decompiler's signatures against the debug files: the parameter count of every so many
  # functions of each binary, whether it returns a value, and what each parameter and the
  # return are. corpus-large holds the largest
  # programs for timing, whose setup alone takes longer than every other corpus's sample.
  if compgen -G "$in/debug/*.debug" >/dev/null && [ "$corpus" != corpus-large ]; then
    signatures "$in"
  fi
done
# The ratchet and the cost measure the build that ships, which a --quick run does not build.
if [ -z "$quick" ] && ! "$build/recore-bench" ratchet; then
  worse+=("bench/budget.json")
fi
if [ -z "$quick" ] && [ -n "$against" ] && ! "$build/recore-bench" cost --base "$base/bin/recore-mcp" ${RECORE_COST_ACCEPTED:+--accept}; then
  worse+=("time or memory")
fi
if [ ${#worse[@]} -gt 0 ]; then
  echo "worse${against:+ than $against}: ${worse[*]}" >&2
  exit 1
fi
# `main` takes a commit only with this status, so it says that this run passed on that commit. A
# budget this run lowered is left to commit, and the commit then needs a run of its own.
if [ -n "$quick" ]; then
  echo "no check status: a --quick run leaves out the ratchet and the cost, so run without it last" >&2
elif [ -z "$against" ] || [ -n "$uncommitted$(git status --porcelain)" ] || [ "$head" != "$(git rev-parse HEAD)" ]; then
  echo "no check status: that takes --against, on a commit with nothing left to commit" >&2
elif ! gh api --silent "repos/{owner}/{repo}/statuses/$head" -f state=success -f context=check -f description="passed against ${against:0:12}"; then
  echo "no check status: GitHub has to know $head, so push before the run" >&2
fi
