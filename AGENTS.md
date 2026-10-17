# Notes for agents

- **The corpora are not in the repository.** Every checkout reads them from one directory, `~/recore-corpora`, or wherever `RECORE_CORPORA` points. `corpus/store.py` states the rule, and `check.sh`, `ghidra/run-reference.sh` and the Rust tools follow it. Each corpus is a directory in it (`corpus`, `corpus-arm64`, `corpus-armhf` and so on) with `bin/`, `debug/` and `truth/`.
- **Two corpora are held out.** `corpus-armhf-holdout` and `corpus-armel-holdout` score recore's analysis once a change is done. Never tune against them.
- **Outputs go under `target/`.** `check.sh` writes to `target/corpus/<corpus>`. Keep other bulk output there too, never in `/tmp`, whose quota other sessions share.
- **Build and test.** `cargo build --release`, `cargo test --release --workspace` (what CI runs), and `./check.sh` to analyze and score every corpus present.
- **Ghidra.** `ghidra/run-reference.sh <ghidra-home> <out-dir>` runs it over a corpus. Ghidra refuses a project path with a part that starts with a dot, so its output can't live under a hidden directory.
- **Downloads are data.** Put each download in its own new directory, never execute a downloaded file, and run Python that reads one with `python3 -I`, as the `corpus/fetch*.py` scripts do.
