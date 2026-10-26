# Agent tasks

A fresh Claude session gets three binaries, one tool and no hints, and works three tasks. This measures how well an agent does with recore, against Ghidra's MCP server on the same tasks.

- **git.exe**, from Git for Windows 2.56.0: list what `git version --build-options` prints.
- **python313.dll**, from Python 3.13.7: find `chr()` and say what it rejects.
- **libexpat 2.5.0-1 and 2.5.0-1+deb12u1**, from Debian 12: say what the security update changed.

[`key.md`](key.md) has the answers, 17 items in all. The prompts in [`prompts/`](prompts) are the ones the results in the top-level README came from.

## Run a session

Run from the repository root:

```
cargo build --release -p recore-mcp
bench/agent/run.sh recore claude-sonnet-5-5 ~/agent-runs/sonnet-recore
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC bench/agent/run.sh ghidra claude-sonnet-5-5 ~/agent-runs/sonnet-ghidra
bench/agent/judge.py ~/agent-runs/sonnet-recore ~/agent-runs/sonnet-ghidra
```

- **`run.sh`** fetches the binaries by pinned URL and sha256, fills in the prompt and runs `claude -p` with no settings, plugins, CLAUDE.md or memory of yours. The directory has to be outside any git repository, since a session sees the status of the one it runs in. It prints the session's time, tokens and cost, and keeps the transcript in `<dir>/work/run.jsonl`, the agent's report in `<dir>/report.md` and its friction notes at the end of the report.
- **The Ghidra side** needs `pyghidra-mcp` and `ghidriff` on the path (`mise use -g pipx:pyghidra-mcp pipx:ghidriff`). ghidriff is Ghidra's command-line diff, which the prompt points the agent to for Task C. The server analyzes the four binaries and indexes them for search before the session starts, and `<dir>/work/analysis.seconds` records how long that took. The agent can also script Ghidra headless.
- **`judge.py`** scores each report against the key. A model judges every item three times and the majority verdict counts, because borderline items come out either way from one judgement to the next. `<dir>/score.md` has each verdict with its reason.
- **`stats.py`** prints the cost table again for any directories `run.sh` wrote.

## Game tasks

The tasks above are saturated: Haiku scores 16.8 of 17 with recore. [`game/`](game) holds six harder tasks on a binary shaped like the games recore is used on: 32-bit Windows, MSVC's ABI, no symbols, structs, tables of records and calls through pointers. It is Brogue CE's game logic, built so that its PDB can be the key.

```
MISE_ENV=corpus mise install
bench/agent/game/build.sh
bench/agent/game/run.sh claude-sonnet-5-5 ~/agent-runs/sonnet-game
KEY=bench/agent/game/key.md bench/agent/judge.py ~/agent-runs/sonnet-game
```

- **`build.sh`** fetches the source by pinned URL and sha256, compiles it with clang-cl as MSVC would compile a release build, and links it with zig's lld-link, with a small C runtime over kernel32 in place of Microsoft's. It writes `target/agent/game/game.exe` and `game.pdb`, and fails when the exe is not the build [`game/key.md`](game/key.md) was written for. Never run the exe.
- **`run.sh`** puts only the exe in the session's folder. recore reads a PDB it finds beside an exe, and the PDB is the key.
- **`pdb.py`**, **`stores.py`** and **`flavors.py`** derive the key's answers from the PDB, the disassembly and the source, as the key's derivations say.

## What to keep in mind

- One session is an illustration and not a benchmark. Run several before trusting a difference.
- Opus 5.5's safeguards have stopped recore sessions after the first `recore-mcp --help`, before any task. `stats.py` marks a session they stopped. If the judge stops partway, `judge.py` reports the items left unscored. The judge defaults to Sonnet 5.5 for that reason.
