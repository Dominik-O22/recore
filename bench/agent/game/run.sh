#!/usr/bin/env bash
# One agent session on the six tasks of key.md with recore, laid out as ../run.sh lays out its
# sessions: the transcript in <dir>/work/run.jsonl, the report in <dir>/report.md, the cost in
# <dir>/stats.json. Only game.exe goes in the session's folder: recore reads a PDB it finds beside
# an exe, and game.pdb is the key.
# Usage: bench/agent/game/run.sh <model> <dir>, with <dir> outside any git repository.
#   RECORE_MCP names the binary, target/release/recore-mcp unless set.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
model=$1 dir=$(realpath -m "$2")
mkdir -p "$dir/task" "$dir/work" "$dir/bin"
# Claude Code shows a session the branch and recent commits of the repository it runs in.
if git -C "$dir" rev-parse --git-dir > /dev/null 2>&1; then
  echo "$dir is inside a git repository, whose status the session would see; choose another directory" >&2
  exit 2
fi
"$here/build.sh" > /dev/null
cp "$root/target/agent/game/game.exe" "$dir/task/"
# The agent runs the tool through a wrapper that logs each call's tool, however it names it.
cp "${RECORE_MCP:-$root/target/release/recore-mcp}" "$dir/bin/.recore-mcp"
printf '#!/bin/sh\necho "$1" >> "%s/work/calls.log"\nexec "%s/bin/.recore-mcp" "$@"\n' "$dir" "$dir" > "$dir/bin/recore-mcp"
chmod +x "$dir/bin/recore-mcp"
sed "s#{DIR}#$dir#g" "$here/prompt.md" > "$dir/prompt.md"
cd "$dir"
date +%s.%N > work/agent.start
# No settings, plugins, CLAUDE.md or memory of the user's: the prompt is all the session is told.
CLAUDE_CODE_DISABLE_CLAUDE_MDS=1 CLAUDE_CODE_DISABLE_AUTO_MEMORY=1 claude -p "$(cat prompt.md)" --model "$model" --strict-mcp-config --setting-sources project \
  --dangerously-skip-permissions --output-format stream-json --verbose > work/run.jsonl
date +%s.%N > work/agent.end
python3 -I "$here/../stats.py" "$dir"
