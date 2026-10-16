#!/usr/bin/env python3
"""What agent sessions cost, from the directories `run.sh` recorded them in: a Markdown row for
each. Writes each session's final report to <dir>/report.md and its numbers to <dir>/stats.json.

Usage: stats.py <dir>...
"""
import json, re, sys
from collections import Counter
from pathlib import Path


def stats(dir: Path) -> dict:
    work = dir / "work"
    usage, tools, result, headless = {}, Counter(), {}, 0
    for line in (work / "run.jsonl").read_text().splitlines():
        event = json.loads(line)
        if event.get("type") == "assistant":
            message = event["message"]
            # A response streams as several events with one id; the last has its usage.
            usage[message["id"]] = message.get("usage") or {}
            uses = [block for block in message["content"] if block["type"] == "tool_use"]
            tools.update(block["name"] for block in uses)
            headless += sum(bool(re.search(r"analyzeHeadless|pyghidraRun", block["input"].get("command", ""))) for block in uses if block["name"] == "Bash")
        elif event.get("type") == "result":
            result = event
    context = [u.get("input_tokens", 0) + u.get("cache_read_input_tokens", 0) + u.get("cache_creation_input_tokens", 0) for u in usage.values()]
    (dir / "report.md").write_text(result.get("result", ""))
    analysis = work / "analysis.seconds"
    # What the agent asked the tool: recore's calls from the log its wrapper keeps, Ghidra's as its
    # MCP tools and the headless runs of scripts the agent wrote.
    queries = Counter()
    calls = work / "calls.log"
    if calls.exists():
        queries.update(line.strip() for line in calls.read_text().splitlines() if line.strip())
    queries.update(name.removeprefix("mcp__ghidra__") for name in tools.elements() if name.startswith("mcp__ghidra__"))
    queries["headless run"] += headless
    queries = +queries
    return {
        "seconds": round(float((work / "agent.end").read_text()) - float((work / "agent.start").read_text())),
        "analysis_seconds": int(analysis.read_text()) if analysis.exists() else 0,
        "responses": len(usage),
        "input_tokens": sum(context),
        "final_context": context[-1] if context else 0,
        "output_tokens": result.get("usage", {}).get("output_tokens", 0),
        "cost_usd": round(result.get("total_cost_usd", 0), 2),
        "tool_calls": sum(tools.values()),
        "queries": sum(queries.values()),
        "queries_by_tool": dict(queries.most_common()),
        "stopped_by_safeguards": "safeguards stopped" in (work / "run.jsonl").read_text(),
    }


def main() -> None:
    print("| run | seconds | analysis | responses | input tokens | final context | cost | tool calls | queries | most asked |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for arg in sys.argv[1:]:
        dir = Path(arg)
        row = stats(dir)
        (dir / "stats.json").write_text(json.dumps(row, indent=2) + "\n")
        stopped = " (stopped by safeguards)" if row["stopped_by_safeguards"] else ""
        most = ", ".join(f"{name} {count}" for name, count in list(row["queries_by_tool"].items())[:4])
        print(f"| {dir.name}{stopped} | {row['seconds']} | {row['analysis_seconds']} | {row['responses']} | {row['input_tokens']:,} | {row['final_context']:,} | ${row['cost_usd']} | {row['tool_calls']} | {row['queries']} | {most} |")


if __name__ == "__main__":
    main()
