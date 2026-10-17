#!/usr/bin/env python3
"""Breaks an analyzer's reported function starts down by evidence type and outcome.

Usage: origins.py <analysis-dir> [corpus-dir]   e.g. target/corpus/corpus/recore-noframes
The corpus is the x86-64 one in the corpora's directory, which corpus/store.py names, unless given.
Outcome is hit (true start), mid (inside a real function), cold (inside a cold fragment) or
outside (not in any known function).
"""
import bisect, collections, glob, json, os, sys

from store import CORPORA

corpus = sys.argv[2] if len(sys.argv) > 2 else CORPORA / "corpus"
counts = collections.Counter()
worst = collections.Counter()
for path in glob.glob(f"{corpus}/truth/*.json"):
    name = os.path.basename(path)[:-5]
    truth = json.load(open(path))
    try:
        analysis = json.load(open(f"{sys.argv[1]}/{name}.json"))
    except FileNotFoundError:
        continue
    lo, hi = truth["text"]
    starts = {f["addr"] for f in truth["functions"] if not f["fragment"]}
    fragments = sorted((f["addr"], f["addr"] + f["size"]) for f in truth["functions"] if f["fragment"])
    everything = sorted((f["addr"], f["addr"] + f["size"]) for f in truth["functions"])

    def inside(ranges, addr):
        i = bisect.bisect_right(ranges, (addr, 1 << 62)) - 1
        return i >= 0 and ranges[i][0] <= addr < ranges[i][1]

    for f in analysis["functions"]:
        addr = f["addr"]
        if not lo <= addr < hi:
            continue
        outcome = "hit" if addr in starts else "cold" if inside(fragments, addr) else "mid" if inside(everything, addr) else "outside"
        counts[(f.get("origin", "unknown"), outcome)] += 1
        if outcome == "mid":
            worst[name] += 1

for origin in sorted({k[0] for k in counts}):
    row = {k[1]: v for k, v in counts.items() if k[0] == origin}
    print(f"{origin:14} " + "  ".join(f"{o} {row.get(o, 0):6}" for o in ("hit", "mid", "cold", "outside")))
print("most mid-function starts:", worst.most_common(6))
