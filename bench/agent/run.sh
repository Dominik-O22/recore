#!/usr/bin/env bash
# One agent session on the three tasks of key.md with one tool: the targets fetched, the prompt
# filled in, and the session recorded in <dir>/work/run.jsonl. The agent's report goes to
# <dir>/report.md, and its cost to <dir>/stats.json.
# Usage: bench/agent/run.sh <recore|ghidra> <model> <dir>, with <dir> outside any git repository.
#   recore: RECORE_MCP names the binary, target/release/recore-mcp unless set.
#   ghidra: GHIDRA_INSTALL_DIR names Ghidra, and pyghidra-mcp and ghidriff must be on the path. Ghidra
#   analyzes the targets before the session starts, in <dir>/work/analysis.seconds.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
tool=$1 model=$2 dir=$(realpath -m "$3")
mkdir -p "$dir/task" "$dir/work"
# Claude Code shows a session the branch and recent commits of the repository it runs in.
if git -C "$dir" rev-parse --git-dir > /dev/null 2>&1; then
  echo "$dir is inside a git repository, whose status the session would see; choose another directory" >&2
  exit 2
fi
python3 -I "$here/fetch.py" "$root/target/agent"
cp "$root"/target/agent/{git.exe,python313.dll,libx-before.so,libx-after.so} "$dir/task/"
mcp=(--strict-mcp-config)
case $tool in
  recore)
    mkdir -p "$dir/bin"
    # The agent runs the tool through a wrapper that logs each call's tool, however it names it.
    cp "${RECORE_MCP:-$root/target/release/recore-mcp}" "$dir/bin/.recore-mcp"
    printf '#!/bin/sh\necho "$1" >> "%s/work/calls.log"\nexec "%s/bin/.recore-mcp" "$@"\n' "$dir" "$dir" > "$dir/bin/recore-mcp"
    chmod +x "$dir/bin/recore-mcp"
    sed "s#{DIR}#$dir#g" "$here/prompts/recore.md" > "$dir/prompt.md" ;;
  ghidra)
    command -v pyghidra-mcp ghidriff > /dev/null || { echo "the Ghidra side needs pyghidra-mcp and ghidriff on the path" >&2; exit 2; }
    port=${PORT:-8765}
    start=$(date +%s)
    pyghidra-mcp -t streamable-http -p "$port" --project-path "$dir/work/proj" --project-name eval --max-workers 2 --wait-for-analysis "$dir"/task/* > "$dir/work/server.log" 2>&1 &
    server=$!
    trap 'kill $server' EXIT
    # Search waits on an index pyghidra-mcp builds after the analysis, one per binary.
    until [ "$(grep -c 'Background indexing completed' "$dir/work/server.log")" = 4 ]; do
      kill -0 "$server"
      sleep 5
    done
    echo $(($(date +%s) - start)) > "$dir/work/analysis.seconds"
    printf '{"mcpServers":{"ghidra":{"type":"http","url":"http://127.0.0.1:%s/mcp"}}}\n' "$port" > "$dir/mcp.json"
    mcp+=(--mcp-config "$dir/mcp.json")
    sed "s#{DIR}#$dir#g; s#{GHIDRA}#$GHIDRA_INSTALL_DIR#g" "$here/prompts/ghidra.md" > "$dir/prompt.md" ;;
  *)
    echo "the tool is recore or ghidra" >&2
    exit 2 ;;
esac
cd "$dir"
date +%s.%N > work/agent.start
# No settings, plugins, CLAUDE.md or memory of the user's: the prompt is all the session is told.
CLAUDE_CODE_DISABLE_CLAUDE_MDS=1 CLAUDE_CODE_DISABLE_AUTO_MEMORY=1 claude -p "$(cat prompt.md)" --model "$model" "${mcp[@]}" --setting-sources project \
  --dangerously-skip-permissions --output-format stream-json --verbose > work/run.jsonl
date +%s.%N > work/agent.end
python3 -I "$here/stats.py" "$dir"
