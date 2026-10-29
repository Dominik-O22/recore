#!/usr/bin/env python3
"""Scores the report of each session against key.md into <dir>/score.md: a model judges every
item of the session's tasks three times, and each item takes the verdict most of the three
gave. Borderline items come out either way from one judgement to the next. The tasks are the
letters in <dir>/tasks, A to C where it has none.

Usage: judge.py <dir>... (JUDGE names the model, claude-sonnet-5-5 unless set)
"""
import os, re, subprocess, sys
from collections import Counter
from pathlib import Path

KEY = (Path(__file__).parent / "key.md").read_text()
ITEM = re.compile(r"^- \*\*([A-Z]\d+)\.\*\*(.*)$", re.M)
VERDICT = re.compile(r"^([A-Z]\d+)[.:]?\s+(PASS|FAIL)\W*(.*)$", re.M)
TIMES = 3

PROMPT = """You score a report on reverse engineering tasks against an answer key. For each item of the key, in order, write one line: the item's id, PASS or FAIL, and a short reason quoting the report. Follow the key's own rules for passing. Write nothing else.

<key>
{key}
</key>

<report>
{report}
</report>"""


def key_for(tasks: str) -> str:
    """The key's opening and its sections for the tasks lettered in `tasks`."""
    opening, *sections = re.split(r"(?m)^(?=## Task )", KEY)
    return opening + "".join(section for section in sections if section[len("## Task ")] in tasks)


def judge(key: str, report: str) -> dict[str, tuple[str, str]]:
    environment = os.environ | {"CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1", "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"}
    command = ["claude", "-p", PROMPT.format(key=key, report=report), "--model", os.environ.get("JUDGE", "claude-sonnet-5-5"), "--strict-mcp-config", "--setting-sources", "project", "--tools", ""]
    text = subprocess.run(command, capture_output=True, text=True, env=environment, stdin=subprocess.DEVNULL).stdout
    return {item: (verdict, reason) for item, verdict, reason in VERDICT.findall(text)}


def main() -> None:
    # An item written from the source can say what the binary does not, as D5 once named a call
    # the build inlines, so each one names the address it was checked at.
    unchecked = [item for item, text in ITEM.findall(KEY) if not re.search(r"0x[0-9a-f]+", text)]
    if unchecked:
        sys.exit(f"key.md: {', '.join(unchecked)} name no address where the binary was checked")
    for arg in sys.argv[1:]:
        dir = Path(arg)
        tasks = (dir / "tasks").read_text().strip() if (dir / "tasks").exists() else "ABC"
        key = key_for(tasks)
        items = [item for item, _ in ITEM.findall(key)]
        rounds = [judge(key, (dir / "report.md").read_text()) for _ in range(TIMES)]
        lines, passed = [], 0
        for item in items:
            given = [round[item] for round in rounds if item in round]
            if not given:
                lines.append(f"{item} UNSCORED: no judgement gave a verdict")
                continue
            verdict = Counter(verdict for verdict, _ in given).most_common(1)[0][0]
            reason = next(reason for v, reason in given if v == verdict)
            votes = sum(v == verdict for v, _ in given)
            passed += verdict == "PASS"
            lines.append(f"{item} {verdict} ({votes} of {len(given)}): {reason}")
        (dir / "score.md").write_text("\n".join(lines) + "\n")
        unscored = sum("UNSCORED" in line for line in lines)
        print(f"{dir.name}: {passed}/{len(items)}" + (f", {unscored} unscored" if unscored else ""))


if __name__ == "__main__":
    main()
