#!/usr/bin/env python3
"""Lists what in a session's transcript breaks the pilot's rules, for a person to judge: shell
tools run on binaries, files read outside the session's folder, the network, and any look at
the labels.

Usage: python3 -I bench/firmware/pilot/audit.py <dir>...
Prints each flagged tool call with the rule it may break, then a count per session. A flag is a
lead, not a verdict: `grep` over the package database is allowed, `grep` over a binary is not.
"""
import json, re, sys
from pathlib import Path

# A command in its own right, not a recore-mcp tool of the same name such as `strings`.
BINARY_TOOLS = re.compile(r"(^|[|;&(`]\s*|\bxargs\s+|\bdo\s+|\bthen\s+)(strings|hexdump|od|xxd|objdump|readelf|nm|file|r2|radare2|gdb)\s")
SEARCH = re.compile(r"(^|[|;&(\s])(grep|rg|ag|awk|sed)\s")
BINARY_PATHS = re.compile(r"(usr/s?bin/|/bin/|/sbin/|lib/[^ ]*\.so)")
PYTHON = re.compile(r"(^|[|;&(\s])python3?\s")
NETWORK = re.compile(r"(^|[|;&(\s])(curl|wget|nc|git|pip)\s|https?://")
LABELS = re.compile(r"labels\.tsv|advisories\.toml|recore-corpora|firmware-bench|bench/firmware")


def flags(dir: Path) -> list[tuple[str, str]]:
    out = []
    for line in (dir / "work" / "run.jsonl").read_text().splitlines():
        event = json.loads(line)
        if event.get("type") != "assistant":
            continue
        for block in event["message"]["content"]:
            if block.get("type") != "tool_use":
                continue
            given = block["input"]
            # A shell command or a file path when there is one, and otherwise every argument, as
            # an MCP tool such as `import_binary` takes a path under its own name.
            text = given.get("command") or given.get("file_path") or given.get("path") or given.get("pattern") or json.dumps(given)
            if not isinstance(text, str):
                continue
            if block["name"] in ("WebFetch", "WebSearch") or NETWORK.search(text):
                out.append(("uses the network", text))
            if LABELS.search(text):
                out.append(("names the labels or the repository", text))
            if block["name"] == "Bash":
                if BINARY_TOOLS.search(text):
                    out.append(("runs a binary tool", text))
                elif SEARCH.search(text) and BINARY_PATHS.search(text) and "recore-mcp" not in text.split("|")[0]:
                    out.append(("searches a path where binaries are", text))
                if PYTHON.search(text):
                    out.append(("runs python", text))
            # Absolute paths only: a slash that does not continue a relative path or a name.
            paths = re.findall(r"(?<![\w.$}-])(/[\w./-]+)", text)
            if any(not p.startswith(str(dir)) and not p.startswith(("/dev/null", "/usr/bin", "/bin/")) for p in paths if p.count("/") > 1):
                out.append(("names a path outside its folder", text))
    return out


def main() -> None:
    for arg in sys.argv[1:]:
        dir = Path(arg).resolve()
        found = flags(dir)
        print(f"== {dir.name}: {len(found)} flagged")
        for rule, text in found:
            print(f"  [{rule}] {text[:300]}")


if __name__ == "__main__":
    main()
