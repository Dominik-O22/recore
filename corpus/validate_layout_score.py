"""Checks the score recore gives a layout without truth against truth: scores each banked build
of the 8051 corpus under its true layout and under layouts made wrong in one way each, and
prints how often and by how much the true one scores higher.

Usage: python3 -I validate_layout_score.py <recore-bin-dir> <corpus-8051-dir> <out-dir>

A wrong layout under which analysis finds what it finds under the true one, measured against
the corpus truth, is counted as the same layout and not as a loss.
"""
import itertools, re, statistics, subprocess, sys, tomllib
from pathlib import Path

bins, corpus, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
CALL = "78 ll 79 hh 7a bb 12 ss ss"
STUB = "c0 b1 c8 c0 e0 e9 c0 e0 ea 54 0f 53 b1 f0 42 b1 c8 22"


def text(entry, regions, common, trampoline):
    lines = ['machine = "8051"', "entry = [" + ", ".join(f"{v:#06x}" for v in entry) + "]", ""]
    for file, offset, length, address in regions:
        lines += ["[[region]]", f'file = "{file}"', f"offset = {offset:#x}", f"length = {length:#x}", f"address = {address:#08x}", "executable = true", ""]
    lines += ["[banking]", f"common = [[0x0000, {common:#x}]]", ""]
    if trampoline:
        lines += ["[[banking.trampoline]]", f'call = "{trampoline[0]}"', f'stub = "{trampoline[1]}"']
    return "\n".join(lines) + "\n"


def variants(regions):
    """Each wrong layout as (kind, what is wrong, regions, end of the common range, trampoline)."""
    banked = [i for i, region in enumerate(regions) if region[3] >= 0x10000]
    moved = lambda change: [(*region[:3], change(i, region[3])) if i in banked else region for i, region in enumerate(regions)]
    for order in itertools.permutations(banked):
        if list(order) != banked:
            place = dict(zip(banked, order))
            yield "bank assignment", "regions as banks " + " ".join(str(regions[place[i]][3] >> 16) for i in banked), moved(lambda i, _: regions[place[i]][3]), 0x8000, (CALL, STUB)
    for end in (0x2000, 0x4000, 0x7000, 0x7F00, 0x8100, 0x9000, 0xC000):
        yield "common range", f"common ends at {end:#x}", regions, end, (CALL, STUB)
    wrong = {
        "target bytes swapped": "78 hh 79 ll 7a bb 12 ss ss",
        "bank and high byte swapped": "78 ll 79 bb 7a hh 12 ss ss",
        "bank and low byte swapped": "78 bb 79 hh 7a ll 12 ss ss",
        "a jump in place of the call": "78 ll 79 hh 7a bb 02 ss ss",
    }
    for name, call in wrong.items():
        yield "trampoline pattern", name, regions, 0x8000, (call, STUB)
    yield "trampoline pattern", "none", regions, 0x8000, None
    for shift in (1, 2, 3, 5, 16, 0x100, 0x1000):
        yield "shifted base", f"every bank {shift:#x} higher", moved(lambda _, address: address + shift), 0x8000, (CALL, STUB)
        for i in banked:
            yield "shifted base", f"bank {regions[i][3] >> 16} {shift:#x} higher", moved(lambda j, address: address + shift * (i == j)), 0x8000, (CALL, STUB)


def run(*command):
    return subprocess.run([str(part) for part in command], capture_output=True, text=True)


def measure(name, directory, layout):
    """The score of `layout` in bits and its parts, and what analysis under it finds of the truth."""
    file = directory / "bin" / f"{name}.toml"
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(layout)
    scored = run(bins / "recore", "score", file)
    if scored.returncode:
        return None
    lines = scored.stdout.splitlines()
    parts = " ".join("/".join(re.search(r"(\d+) of (\d+)", line).groups()) for line in lines[1:])
    (directory / "recore").mkdir(exist_ok=True)
    (directory / "recore" / f"{name}.json").write_text(run(bins / "recore", "analyze", file).stdout)
    truth = run(bins / "recore-corpus", "--corpus", corpus, "score", directory / "recore", "--detail").stdout
    line = next(line for line in truth.splitlines() if line.startswith(name + " "))
    found = re.search(r"starts (\d+)/(\d+).*precision\s+([\d.]+)%", line).groups()
    return float(lines[0].split()[0]), parts, f"{found[0]}/{found[1]}", found[2]


rows, summary = [], {}
for name in ("coremark_banked", "crypto_banked", "uip_banked"):
    path = corpus / "bin" / f"{name}.toml"
    layout = tomllib.loads(path.read_text())
    regions = [((path.parent / r["file"]).resolve(), r["offset"], r["length"], r["address"]) for r in layout["region"]]
    true = measure(name, out / "true", text(layout["entry"], regions, 0x8000, (CALL, STUB)))
    rows.append((name, "true", "", *true, ""))
    for number, (kind, what, placed, common, trampoline) in enumerate(variants(regions)):
        wrong = measure(name, out / f"{number:03}", text(layout["entry"], placed, common, trampoline))
        counts = summary.setdefault(kind, {"higher": [], "same analysis": 0, "tied": 0, "lower": [], "refused": 0})
        if wrong is None:
            counts["refused"] += 1
            verdict = "refused by the loader"
        elif wrong[2:] == true[2:] and wrong[0] == true[0]:
            counts["same analysis"] += 1
            verdict = "same analysis, same score"
        elif true[0] > wrong[0]:
            counts["higher"].append(true[0] - wrong[0])
            verdict = f"true higher by {true[0] - wrong[0]:.0f}"
        elif true[0] == wrong[0]:
            counts["tied"] += 1
            verdict = "TIED"
        else:
            counts["lower"].append(wrong[0] - true[0])
            verdict = f"TRUE LOWER by {wrong[0] - true[0]:.0f}"
        rows.append((name, kind, what, *(wrong or (float("nan"), "", "", "")), verdict))

print(f"{'build':<16} {'kind':<19} {'layout':<30} {'bits':>6}  {'end called on-insn local':<28} {'starts':>8} {'prec':>6}  verdict")
for row in rows:
    print(f"{row[0]:<16} {row[1]:<19} {row[2]:<30} {row[3]:>6.0f}  {row[4]:<28} {row[5]:>8} {row[6]:>6}  {row[7]}")
print(f"\n{'kind':<19} {'wrong':>5} {'true higher':>11} {'same analysis':>13} {'tied':>4} {'true lower':>10} {'refused':>7}  margin in bits: least, median, most")
for kind, counts in summary.items():
    higher, lower = counts["higher"], counts["lower"]
    total = len(higher) + len(lower) + counts["same analysis"] + counts["tied"] + counts["refused"]
    margin = f"{min(higher):.0f}, {statistics.median(higher):.0f}, {max(higher):.0f}" if higher else ""
    print(f"{kind:<19} {total:>5} {len(higher):>11} {counts['same analysis']:>13} {counts['tied']:>4} {len(lower):>10} {counts['refused']:>7}  {margin}")
