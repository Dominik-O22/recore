#!/usr/bin/env bash
# One agent session on one part of the firmware benchmark with one tool, recorded as
# bench/agent/run.sh records one: the transcript in <dir>/work/run.jsonl, the report in
# <dir>/report.md and the cost in <dir>/stats.json. Each part's score.py scores the session.
# Usage: bench/firmware/run.sh <part> <recore|ghidra> <model> <dir>, where <part> is a folder of
# bench/firmware (verify, find) and <dir> is outside any git repository, with no part of its
# path starting with a dot, which Ghidra refuses.
#   The part names its images in images.tsv, the programs Ghidra analyzes first in programs.txt,
#   and its task in task.md; its prepare.py writes what else the task folder holds.
#   recore: RECORE_MCP names the binary, target/release/recore-mcp unless set.
#   ghidra: GHIDRA_INSTALL_DIR names Ghidra, and pyghidra-mcp must be on the path. Ghidra analyzes
#   the part's programs of every image before the session starts, in <dir>/work/analysis.seconds.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
part=$here/$1 tool=$2 model=$3 dir=$(realpath -m "$4")
images="${RECORE_CORPORA:-$HOME/recore-corpora}/corpus-openwrt/images"
mkdir -p "$dir/task" "$dir/work"
if git -C "$dir" rev-parse --git-dir > /dev/null 2>&1; then
  echo "$dir is inside a git repository, whose status the session would see; choose another directory" >&2
  exit 2
fi
tail -n +2 "$part/images.tsv" | while IFS=$'\t' read -r img image; do
  [ -d "$dir/task/$img" ] || cp -a "$images/$image/rootfs" "$dir/task/$img"
done
python3 -I "$part/prepare.py" "$dir/task"
mcp=(--strict-mcp-config)
case $tool in
  recore)
    mkdir -p "$dir/bin"
    # The agent runs the tool through a wrapper that logs each call's tool.
    cp "${RECORE_MCP:-$root/target/release/recore-mcp}" "$dir/bin/.recore-mcp"
    printf '#!/bin/sh\necho "$1" >> "%s/work/calls.log"\nexec "%s/bin/.recore-mcp" "$@"\n' "$dir" "$dir" > "$dir/bin/recore-mcp"
    chmod +x "$dir/bin/recore-mcp"
    sed "s#{DIR}#$dir#g" "$here/prompts/recore.md" "$part/task.md" > "$dir/prompt.md" ;;
  ghidra)
    command -v pyghidra-mcp > /dev/null || { echo "the Ghidra side needs pyghidra-mcp on the path" >&2; exit 2; }
    # pyghidra-mcp names a program after its file, so each copy carries its image's name.
    mkdir -p "$dir/work/imported"
    for img in $(tail -n +2 "$part/images.tsv" | cut -f1); do
      for program in $(cat "$part/programs.txt"); do
        [ -f "$dir/task/$img/$program" ] && cp "$dir/task/$img/$program" "$dir/work/imported/$img-$(basename "$program")"
      done
    done
    imported="The programs $(sed 's/.*/`&`/' "$part/programs.txt" | paste -sd, | sed 's/,/, /g') of every image are imported into its project and fully analyzed."
    port=${PORT:-8766}
    start=$(date +%s)
    pyghidra-mcp -t streamable-http -p "$port" --project-path "$dir/work/proj" --project-name triage --max-workers 2 --wait-for-analysis "$dir"/work/imported/* > "$dir/work/server.log" 2>&1 &
    server=$!
    trap 'kill $server' EXIT
    # Search waits on an index pyghidra-mcp builds after the analysis, one per binary.
    until [ "$(grep -c 'Background indexing completed' "$dir/work/server.log")" = "$(ls "$dir/work/imported" | wc -l)" ]; do
      kill -0 "$server"
      sleep 5
    done
    echo $(($(date +%s) - start)) > "$dir/work/analysis.seconds"
    printf '{"mcpServers":{"ghidra":{"type":"http","url":"http://127.0.0.1:%s/mcp"}}}\n' "$port" > "$dir/mcp.json"
    mcp+=(--mcp-config "$dir/mcp.json")
    sed "s#{DIR}#$dir#g; s#{GHIDRA}#$GHIDRA_INSTALL_DIR#g; s#{IMPORTED}#$imported#g" "$here/prompts/ghidra.md" "$part/task.md" > "$dir/prompt.md" ;;
  *)
    echo "the tool is recore or ghidra" >&2
    exit 2 ;;
esac
cd "$dir"
date +%s.%N > work/agent.start
# The prompt gives the agent 30 minutes; the session is stopped at 45.
CLAUDE_CODE_DISABLE_CLAUDE_MDS=1 CLAUDE_CODE_DISABLE_AUTO_MEMORY=1 timeout 45m claude -p "$(cat prompt.md)" --model "$model" "${mcp[@]}" --setting-sources project \
  --dangerously-skip-permissions --output-format stream-json --verbose > work/run.jsonl || echo "the session ended with status $?" >&2
date +%s.%N > work/agent.end
python3 -I "$root/bench/agent/stats.py" "$dir"
