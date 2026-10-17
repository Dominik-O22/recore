#!/usr/bin/env python3
"""Times recore against Ghidra on the OpenWrt binaries that bench/firmware/pick.py chose.

Usage: python3 -I bench/firmware/speed.py <recore-mcp> <ghidra-dir>...
Each <ghidra-dir> is one run of ghidra/run-reference.sh over <corpora>/corpus-openwrt, whose
times.txt gives per binary Ghidra's own reported analysis time and the wall time of the whole
headless run, JVM start and import included. recore's time is `recore-mcp summary` as a new
process, from launch to answer: the median of 5 runs pinned to one core and of 5 with all
cores, alternated. A run that reports no functions counts as an error.
"""
import os, re, statistics, subprocess, sys, time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "corpus"))
from store import CORPORA  # noqa: E402

RUNS = 5


def ghidra(directory: str) -> dict[str, tuple[int, int]]:
    out = {}
    for line in open(Path(directory) / "times.txt"):
        name, analysis, wall = line.split()
        out[name] = (int(analysis), int(wall))
    return out


def recore(mcp: str, path: Path) -> tuple[float, float, int]:
    """Median seconds on one core and on all, and how many runs found no functions."""
    one, all_cores, errors = [], [], 0
    single = dict(os.environ, RAYON_NUM_THREADS="1")
    for _ in range(RUNS):
        for times, command, env in ((one, ["taskset", "-c", "3", mcp], single), (all_cores, [mcp], os.environ)):
            start = time.perf_counter()
            out = subprocess.run([*command, "summary", str(path)], capture_output=True, text=True, env=env).stdout
            times.append(time.perf_counter() - start)
            found = re.search(r"^(\d+) functions", out, re.M)
            errors += not found or found.group(1) == "0"
    return statistics.median(one), statistics.median(all_cores), errors


def main() -> None:
    mcp, runs = sys.argv[1], [ghidra(d) for d in sys.argv[2:]]
    rows = []
    for path in sorted((CORPORA / "corpus-openwrt" / "bin").iterdir()):
        if all(path.name in run for run in runs):
            rows.append((path.name, [run[path.name] for run in runs], *recore(mcp, path)))
    by_arch = defaultdict(list)
    for row in rows:
        by_arch[row[0].split("__")[0].split("-")[1]].append(row)
    print("| | binaries | Ghidra analysis, per run | Ghidra wall, per run | recore, one core | recore, all cores | overall | median binary |")
    print("|---|---|---|---|---|---|---|---|")
    for arch, group in [*sorted(by_arch.items()), ("all", rows)]:
        analysis = [sum(r[1][i][0] for r in group) for i in range(len(runs))]
        wall = [sum(r[1][i][1] for r in group) for i in range(len(runs))]
        one, many = sum(r[2] for r in group), sum(r[3] for r in group)
        median = statistics.median(statistics.median(a for a, _ in r[1]) / r[2] for r in group)
        print(f"| {arch} | {len(group)} | {' / '.join(f'{a} s' for a in analysis)} | {' / '.join(f'{w} s' for w in wall)} | {one:.3f} s | {many:.3f} s | {min(analysis) / one:,.0f}x | {median:,.0f}x |")
    print(f"\nrecore runs that found no functions: {sum(r[4] for r in rows)} of {2 * RUNS * len(rows)}")
    spread = [max(a for a, _ in r[1]) - min(a for a, _ in r[1]) for r in rows]
    print(f"Ghidra analysis time, largest difference between runs of one binary: {max(spread)} s")


if __name__ == "__main__":
    main()
