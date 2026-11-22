#!/usr/bin/env bash
# One agent session on the six tasks of key.md with recore, laid out as ../run.sh lays out its
# sessions: the transcript in <dir>/work/run.jsonl, the report in <dir>/report.md, the cost in
# <dir>/stats.json. Only the raw Image and the three stripped modules go in the session's folder:
# recore reads a debug file it finds beside a binary, and vmlinux, System.map and the unstripped
# modules are the key.
# Usage: bench/agent/android/run.sh <model> <dir> [--setup], with <dir> outside any git repository.
#   RECORE_MCP names the binary, target/release/recore-mcp unless set.
#   --setup lays out <dir> and fills in the prompt, and stops before the session.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
model=$1 dir=$(realpath -m "$2") setup=${3:-}
mkdir -p "$dir/task" "$dir/work" "$dir/bin"
# Claude Code shows a session the branch and recent commits of the repository it runs in.
if git -C "$dir" rev-parse --git-dir > /dev/null 2>&1; then
  echo "$dir is inside a git repository, whose status the session would see; choose another directory" >&2
  exit 2
fi
# judge.py scores the tasks lettered here, and A to C where a session names none.
echo ABCDEF > "$dir/tasks"
python3 -I "$here/fetch.py" "$root/target/agent/android"
cp "$root"/target/agent/android/task/{Image,gzvm.ko,zram.ko,rfkill.ko} "$dir/task/"
# The agent runs the tool through a wrapper that logs each call's tool, however it names it.
cp "${RECORE_MCP:-$root/target/release/recore-mcp}" "$dir/bin/.recore-mcp"
printf '#!/bin/sh\necho "$1" >> "%s/work/calls.log"\nexec "%s/bin/.recore-mcp" "$@"\n' "$dir" "$dir" > "$dir/bin/recore-mcp"
chmod +x "$dir/bin/recore-mcp"
sed "s#{DIR}#$dir#g" "$here/prompt.md" > "$dir/prompt.md"
if [ "$setup" = --setup ]; then
  echo "$dir is ready; the prompt is $dir/prompt.md" >&2
  exit 0
fi
cd "$dir"
date +%s.%N > work/agent.start
# No settings, plugins, CLAUDE.md or memory of the user's: the prompt is all the session is told.
CLAUDE_CODE_DISABLE_CLAUDE_MDS=1 CLAUDE_CODE_DISABLE_AUTO_MEMORY=1 claude -p "$(cat prompt.md)" --model "$model" --strict-mcp-config --setting-sources project \
  --dangerously-skip-permissions --output-format stream-json --verbose > work/run.jsonl
date +%s.%N > work/agent.end
python3 -I "$here/../stats.py" "$dir"
