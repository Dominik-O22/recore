#!/usr/bin/env bash
# Runs the Kani proofs of src/x87/proofs.rs, each on its own, as many at once as there are cores,
# and prints a line per proof: passed, FAILED, TIMEOUT or ERROR, and its seconds. A proof that
# passed without `fast` ever answering says so. Logs go to target/kani-logs/<proof>.log. Run it
# through mise, which pins Kani:
#   MISE_ENV=verify mise run x87-proofs [-- name filter]
# A filter keeps the proofs whose name contains it, as `add::` or `to_10`.
set -euo pipefail
cd "$(dirname "$0")"
filter=${1:-}
limit=${KANI_TIMEOUT:-900}
logs=../../target/kani-logs
mkdir -p "$logs"

# Each run below compiles the crate again for its own proof, but this builds the dependencies
# once, and stops at a build error before any proof starts.
cargo kani --only-codegen >"$logs/build.log" 2>&1 || { tail -30 "$logs/build.log"; exit 1; }

# The proofs `proofs!` writes: a module per operation, with `to_1` for a comparison and `to_4`,
# `to_8` and `to_10` for the others.
harnesses=()
while read -r kind module; do
    if [[ $kind == compare ]]; then widths=(to_1); else widths=(to_4 to_8 to_10); fi
    for width in "${widths[@]}"; do
        name="x87::proofs::$module::$width"
        [[ $name == *"$filter"* ]] && harnesses+=("$name")
    done
done < <(sed -n '/^proofs! {/,/^}/p' src/x87/proofs.rs | sed -n 's/^ *\(compare\|float\) \([a-z0-9_]*\): .*/\1 \2/p')
((${#harnesses[@]})) || { echo "no proof matches '$filter'" >&2; exit 1; }

one() {
    local name=$1 log="$2/${1//::/_}.log" start=$SECONDS
    local status=0
    timeout "$3" cargo kani --harness "$name" --exact >"$log" 2>&1 || status=$?
    if ((status == 0)) && grep -q '\*\* 0 of [0-9]* cover properties satisfied' "$log"; then
        printf 'passed   %4ds  %s  (fast never answers)\n' $((SECONDS - start)) "$name"
    elif ((status == 0)); then
        printf 'passed   %4ds  %s\n' $((SECONDS - start)) "$name"
    elif ((status == 124)); then
        printf 'TIMEOUT  %4ds  %s\n' $((SECONDS - start)) "$name"
    elif grep -q 'VERIFICATION:- FAILED' "$log"; then
        printf 'FAILED   %4ds  %s  (%s)\n' $((SECONDS - start)) "$name" "$log"
    else
        printf 'ERROR    %4ds  %s  (%s)\n' $((SECONDS - start)) "$name" "$log"
    fi
}
export -f one
printf '%s\n' "${harnesses[@]}" | xargs -P "$(nproc)" -I{} bash -c 'one "$@"' _ {} "$logs" "$limit" | tee "$logs/summary.txt"
! grep -Eq '^(FAILED|TIMEOUT|ERROR)' "$logs/summary.txt"
