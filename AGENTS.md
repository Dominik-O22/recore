# Notes for agents

## What recore is for

recore aims to be a faster Ghidra that agents find easier to use. Work earns its place by moving one of three measures, and each has a label on GitHub:

| Label | Measure | Run |
| --- | --- | --- |
| `speed` | Analysis time and instructions executed | `recore-bench run analysis --compare <name>`, and `recore-bench ratchet` for instructions |
| `accuracy` | Counts scored against debug info | `./check.sh --against main` |
| `agent-ux` | Agent sessions scored against a key, with their time and tokens | `bench/agent` |

Before you build anything, name the measure a change should move and how far. Then check the premise with a quick script. If nothing can score the change, say so before you build it. Every issue carries one of the three labels and says how a fix would be measured.

## Working in this repository

- **The corpora are not in the repository.** Every checkout reads them from one directory, `~/recore-corpora`, or wherever `RECORE_CORPORA` points. `corpus/store.py` states the rule, and `check.sh`, `ghidra/run-reference.sh` and the Rust tools follow it. Each corpus is a directory in it (`corpus`, `corpus-arm64`, `corpus-armhf` and so on) with `bin/`, `debug/` and `truth/`.
- **Two corpora are held out.** `corpus-armhf-holdout` and `corpus-armel-holdout` score recore's analysis once a change is done. Never tune against them.
- **The player is apart.** `player/` is its own Cargo workspace: the host, window and audio that lifted games run on (player/README.md). recore's build, tests and `check.sh` never compile it, and it moves none of the three measures. In `player/`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` are what CI runs. A change to it says which games' smoke scripts it ran, and that their frames still match.
- **Outputs go under `target/`.** `check.sh` writes to `target/corpus/<corpus>`. Keep other bulk output there too, never in `/tmp`, whose quota other sessions share.
- **Build and test.** `cargo build --release`, `cargo test --profile ci --workspace` and `cargo clippy --profile ci --workspace --all-targets -- -D warnings` (what CI runs), and `./check.sh` to analyze and score every corpus present.
- **`main` takes a commit only after `./check.sh --against <base>` passed on it.** The run leaves a `check` status on the commit, so push first and run on a clean tree. Any new commit needs a new run. CI gives the status itself to a change that touches only `player/`, Markdown or `.coderabbit.yaml`, which `check.sh` does not read.
- **Say what a change did with `./check.sh --against main`.** It prints each count that moved and the binaries it moved in, and fails when a total got worse. Quote those counts in the PR, losses included. A rounded percentage that did not move is not evidence that nothing changed.
- **Instructions executed only go down.** `check.sh` ends with `recore-bench ratchet`, which counts on `bench/set.txt` the user-mode instructions of what an agent waits for, and fails when one grew more than 1% past `bench/budget.json`. It runs `recore-mcp` itself, as built, so build that first when you run it alone: the first call on a binary, a later call, a server's first `decompile`, in that server the functions `bench/functions.json` names decompiled, then every other read-only tool but `type`, `run` and `diff`, with `trace` on those functions until three had both a parameter and a value to follow, and, in its own process, `diff`. Where they shrank it lowers the budget: commit that with the change. It does not see time in the kernel, such as page faults and reading files, work lost from running in parallel, a binary's largest few functions, or tools it does not call, so a change to those says what `recore-bench run` measured. When the analysis drops a function that `bench/functions.json` names, or a tool starts to fail on one, delete that binary's entry there, so that the next run chooses again, and run with `--accept` if the new functions grew a count. It raises every count that grew, so the PR says which. A change that is worth a cost raises the budget with `recore-bench ratchet --accept` and says in its PR what grew and why.
- **Ghidra.** `ghidra/run-reference.sh <ghidra-home> <out-dir>` runs it over a corpus. Ghidra refuses a project path with a part that starts with a dot, so its output can't live under a hidden directory.
- **Downloads are data.** Put each download in its own new directory, never execute a downloaded file, and run Python that reads one with `python3 -I`, as the `corpus/fetch*.py` scripts do.

## Rules and what enforces them

When the operator corrects an agent, fix the mistake and add its rule here. A rule that only this file states and that was broken again gets a check in the same change.

| Rule | Enforced by |
| --- | --- |
| Only `crates/*/tests` may name the programs recore was tuned on, each test gated on an env var that points at the binary. | `crates/core/tests/general_naming.rs`, in CI and first in `check.sh` |
| A change states every corpus count it moved, from a base that was built, not assumed. | `./check.sh --against <ref>` fails on a worse total, and `main` requires the `check` status of a run that passed. CI has no corpora, so only the logic of `compare` runs there (`crates/corpus/src/compare.rs` tests). |
| Every corpus in the store is scored. | `check.sh` takes every corpus with `truth/` in it. |
| Never tune against the held-out corpora. | `check.sh` skips `*-holdout`. Scoring one by hand is still possible. |
| A change executes no more instructions than `bench/budget.json` allows, unless its PR says why the cost is worth it. | `recore-bench ratchet`, last in `check.sh`, and the `budget` check, which fails a PR that raises a number in that file without a line starting `Budget:` in its description. |
| Corpora live in the store, never in a checkout. | `corpus/store.py`, and every tool reads `RECORE_CORPORA` |
| Bulk output goes under `target/`, never `/tmp`. | Nothing; this file only |
| Downloads are data, never executed. | Nothing; this file only |
| An item of the agent bench's answer key says what the binary does, not the source, and names the address it was checked at. | `bench/agent/judge.py` refuses a key with an item that names no address |
| Work names the measure it moves before it is built, and every issue carries a goal label. | Nothing; this file only |
