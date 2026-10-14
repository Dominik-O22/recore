#!/usr/bin/env python3
"""Scores the strings recore reports on the 8051 corpus against SDCC's listings.

Usage: strings_8051.py <corpus-8051> <analysis-dir>

A listing gives each string literal a label, `___str_N`, with its address, and names the label
in the instructions that use the literal. A literal counts as found when recore reports a
string at its address, and as found with a user when one of the references recore gives for it
comes from a function the listing uses it in.
"""
import bisect
import json
import re
import sys
import tomllib
from pathlib import Path

LINE = re.compile(r"^\s+([0-9A-F]{6})\s(?:[0-9A-F]{2}\s)*\s*(?:\[\d+\])?\s*\d+\s(.*)$")
LABEL = re.compile(r"^(___str_\d+):")
USE = re.compile(r"#\(?(___str_\d+)\b")
# The shortest string recore takes: see `MIN_CHARS_FROM_CODE` in `crates/core/src/strings.rs`.
SHORTEST = 2


def literals(listing):
    """`{address: {instruction addresses that name it}}` over the modules of one listing."""
    found = {}
    module = []

    def close():
        where = {label: addr for addr, text in module if (label := LABEL.match(text)) and (label := label.group(1))}
        for addr in where.values():
            found.setdefault(addr, set())
        for addr, text in module:
            for label in USE.findall(text):
                if label in where:
                    found[where[label]].add(addr)
        module.clear()

    for line in listing.read_text(errors="replace").splitlines():
        if ".module " in line:
            close()
        if parsed := LINE.match(line):
            module.append((int(parsed.group(1), 16), parsed.group(2).strip()))
    close()
    return found


def main(corpus, analyses):
    total = dict.fromkeys(("literals", "short", "used", "found", "found_used", "right_user", "reported", "not_literal"), 0)
    for layout in sorted((corpus / "bin").glob("*.toml")):
        name = layout.stem
        truth = json.loads((corpus / "truth" / f"{name}.json").read_text())
        analysis = json.loads((analyses / f"{name}.json").read_text())
        regions = [(region["address"], (layout.parent / region["file"]).read_bytes()[region["offset"] :][: region["length"]]) for region in tomllib.loads(layout.read_text())["region"]]
        text_at = lambda addr: next((data[addr - base : data.index(0, addr - base)] for base, data in regions if base <= addr < base + len(data)), None)
        starts = sorted(function["addr"] for function in truth["functions"])
        owner = lambda addr: starts[bisect.bisect_right(starts, addr) - 1]
        reported = {string["addr"]: string["text"] for string in analysis["strings"]}
        users = {}
        for reference in analysis["data_refs"]:
            users.setdefault(reference["to"], set()).add(owner(reference["from"]))
        known = literals(corpus / "debug" / f"{name}.rst")
        for addr, uses in known.items():
            length = len(text_at(addr))
            total["literals"] += 1
            if length < SHORTEST:
                total["short"] += 1
                continue
            total["used"] += bool(uses)
            if addr in reported:
                total["found"] += 1
                total["found_used"] += bool(uses)
                total["right_user"] += bool(users.get(addr, set()) & {owner(use) for use in uses})
        total["reported"] += len(reported)
        total["not_literal"] += sum(addr not in known for addr in reported)
    long = total["literals"] - total["short"]
    print(
        f"literals {total['literals']} ({total['short']} shorter than {SHORTEST} characters), found {total['found']}/{long}, "
        f"with a right user {total['right_user']}/{total['used']} of those an instruction names; "
        f"strings reported {total['reported']}, {total['not_literal']} of them not a literal"
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
