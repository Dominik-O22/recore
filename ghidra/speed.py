#!/usr/bin/env python3
"""Times `recore-mcp summary` on every binary Ghidra analyzed for the README's speed table,
fastest of three runs each, pinned to one core and with all cores, against Ghidra's own Total
Time from each corpus's `ghidra/times.txt`.

Usage: speed.py <recore-mcp> [cutoff], where a cutoff date keeps only the binaries whose Ghidra
export is older than it. The corpora are where corpus/store.py says."""
import datetime, os, statistics, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "corpus"))
from store import CORPORA  # noqa: E402
mcp = sys.argv[1]
cut = datetime.datetime.fromisoformat(sys.argv[2]).timestamp() if len(sys.argv) > 2 else float("inf")
rows = []
for corpus in ["corpus", "corpus-pe", "corpus-pe32"]:
    times = {}
    for line in open(f"{CORPORA}/{corpus}/ghidra/times.txt"):
        p = line.split()
        if len(p) >= 2 and p[1].isdigit():
            times.setdefault(p[0], int(p[1]))
    for f in sorted(os.listdir(f"{CORPORA}/{corpus}/ghidra")):
        name = f[:-5]
        if f.endswith(".json") and os.path.getmtime(f"{CORPORA}/{corpus}/ghidra/{f}") < cut and name in times:
            rows.append((f"{CORPORA}/{corpus}/bin/{name}", times[name]))

def fastest(path, env, pin=()):
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        subprocess.run([*pin, mcp, "summary", path], capture_output=True, env=env, check=True)
        best = min(best, time.perf_counter() - start)
    return best

one = dict(os.environ, RAYON_NUM_THREADS="1")
# One core: the whole process pinned to one CPU, so no thread of it runs elsewhere.
results = [(path, ghidra, fastest(path, one, ("taskset", "-c", "3")), fastest(path, os.environ)) for path, ghidra in rows]
ghidra = sum(r[1] for r in results)
single, multi = sum(r[2] for r in results), sum(r[3] for r in results)
ratios = sorted((r[1] / r[3], os.path.basename(r[0])) for r in results)
print(f"{len(results)} binaries, Ghidra {ghidra} s ({ghidra / 3600:.2f} h)")
print(f"recore pinned to one core {single:.2f} s, all cores {multi:.2f} s")
print(f"one core: overall {ghidra / single:.0f}x, median binary {statistics.median(r[1] / r[2] for r in results):.0f}x")
print(f"all cores: overall {ghidra / multi:.0f}x, median binary {statistics.median(r[0] for r in ratios):.0f}x")
print("largest:", ", ".join(f"{name} {ratio:.0f}x" for ratio, name in ratios[-3:]))
for path, g, s, m in results:
    if any(k in path for k in ("git__git.exe", "obs__obs-browser.dll", "mingw__bzip2.exe")):
        print(f"{os.path.basename(path)}: Ghidra {g} s, recore {m:.3f} s")
