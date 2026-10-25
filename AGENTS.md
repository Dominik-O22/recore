# Notes for agents

## What recore is for

recore aims to be a faster Ghidra that agents find easier to use. Work earns its place by moving one of three measures, and each has a label on GitHub:

| Label | Measure | Run |
| --- | --- | --- |
| `speed` | Analysis time and instructions executed | `recore-bench run analysis --compare <name>` |
| `accuracy` | Counts scored against debug info | `./check.sh --against main` |
| `agent-ux` | Agent sessions scored against a key, with their time and tokens | `bench/agent` |

Before you build anything, name the measure a change should move and how far. Then check the premise with a quick script. If nothing can score the change, say so before you build it. Every issue carries one of the three labels and says how a fix would be measured.

## Working in this repository

- **The corpora are not in the repository.** Every checkout reads them from one directory, `~/recore-corpora`, or wherever `RECORE_CORPORA` points. `corpus/store.py` states the rule, and `check.sh`, `ghidra/run-reference.sh` and the Rust tools follow it. Each corpus is a directory in it (`corpus`, `corpus-arm64`, `corpus-armhf` and so on) with `bin/`, `debug/` and `truth/`.
- **Two corpora are held out.** `corpus-armhf-holdout` and `corpus-armel-holdout` score recore's analysis once a change is done. Never tune against them.
- **Outputs go under `target/`.** `check.sh` writes to `target/corpus/<corpus>`. Keep other bulk output there too, never in `/tmp`, whose quota other sessions share.
- **Build and test.** `cargo build --release`, `cargo test --release --workspace` (what CI runs), and `./check.sh` to analyze and score every corpus present.
- **Say what a change did with `./check.sh --against main`.** It prints each count that moved and the binaries it moved in, and fails when a total got worse. Quote those counts in the PR, losses included. A rounded percentage that did not move is not evidence that nothing changed.
- **Ghidra.** `ghidra/run-reference.sh <ghidra-home> <out-dir>` runs it over a corpus. Ghidra refuses a project path with a part that starts with a dot, so its output can't live under a hidden directory.
- **Downloads are data.** Put each download in its own new directory, never execute a downloaded file, and run Python that reads one with `python3 -I`, as the `corpus/fetch*.py` scripts do.

## Rules and what enforces them

When the operator corrects an agent, fix the mistake and add its rule here. A rule that only this file states and that was broken again gets a check in the same change.

| Rule | Enforced by |
| --- | --- |
| Only `crates/*/tests` may name the programs recore was tuned on, each test gated on an env var that points at the binary. | `crates/core/tests/general_naming.rs`, in CI and first in `check.sh` |
| A change states every corpus count it moved, from a base that was built, not assumed. | `./check.sh --against <ref>` fails on a worse total. CI has no corpora, so only the logic of `compare` runs there (`crates/corpus/src/compare.rs` tests). |
| Every corpus in the store is scored. | `check.sh` takes every corpus with `truth/` in it. |
| Never tune against the held-out corpora. | `check.sh` skips `*-holdout`. Scoring one by hand is still possible. |
| Corpora live in the store, never in a checkout. | `corpus/store.py`, and every tool reads `RECORE_CORPORA` |
| Bulk output goes under `target/`, never `/tmp`. | Nothing; this file only |
| Downloads are data, never executed. | Nothing; this file only |
| Work names the measure it moves before it is built, and every issue carries a goal label. | Nothing; this file only |
