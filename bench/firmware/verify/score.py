#!/usr/bin/env python3
"""Scores verify sessions: how many of the version scanner's wrong claims an agent refuted, and
how many right ones it broke.

Usage: python3 -I bench/firmware/verify/score.py <dir>...
Each <dir> is a session of bench/firmware/run.sh verify, with its verdicts in work/verdicts.tsv;
<dir>/score.md gets each claim's outcome. A claim is "affected" or "not affected", and so is the
truth, from labels.tsv: vulnerable is affected, fixed and absent are not. A claim the agent did
not check stands. A verdict that changes the claim counts only when its evidence holds: the
advisory's binary and, for vulnerable or fixed, an address in that binary's code. "Traps" are
the claims the scanner got wrong.
"""
import csv, struct, sys, tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "corpus"))
from store import CORPORA  # noqa: E402

IMAGES = dict(line.split("\t") for line in (HERE / "images.tsv").read_text().splitlines()[1:])
IDS = (HERE / "advisories.txt").read_text().split()
FILES = {a["id"]: a["files"][0] for a in tomllib.loads((HERE.parent / "advisories.toml").read_text())["advisory"]}
LABELS = {(row["image"], row["advisory"]): row for row in csv.DictReader(open(HERE.parent / "labels.tsv"), delimiter="\t")}
STATUSES = {"vulnerable", "fixed", "absent"}


def in_code(path: Path, address: int) -> bool:
    """Whether `address` lies in an executable segment of the ELF file at `path`, at the file's own
    addresses or, for a position-independent file linked at 0, where Ghidra loads it by default:
    0x100000 for 64-bit code and 0x10000 for 32-bit."""
    data = path.read_bytes()
    base = 0x100000 if data[4] == 2 else 0x10000
    if int.from_bytes(data[16:18], "little") == 3 and address >= base and in_code_at(data, address - base):
        return True
    return in_code_at(data, address)


def in_code_at(data: bytes, address: int) -> bool:
    if data[4] == 2:
        (phoff,), (phentsize, phnum) = struct.unpack_from("<Q", data, 0x20), struct.unpack_from("<HH", data, 0x36)
    else:
        (phoff,), (phentsize, phnum) = struct.unpack_from("<I", data, 0x1C), struct.unpack_from("<HH", data, 0x2A)
    for index in range(phnum):
        at = phoff + index * phentsize
        if data[4] == 2:
            kind, flags, _, vaddr, _, _, memsz = struct.unpack_from("<IIQQQQQ", data, at)
        else:
            kind, _, vaddr, _, _, memsz, flags = struct.unpack_from("<IIIIIII", data, at)
        if kind == 1 and flags & 1 and vaddr <= address < vaddr + memsz:
            return True
    return False


def holds(img: str, advisory: str, verdict: dict) -> bool:
    """Whether a verdict's evidence names the advisory's binary and, unless absent, its code."""
    if verdict.get("binary", "").strip().lstrip("/") != FILES[advisory]:
        return False
    if verdict["status"] == "absent":
        return True
    try:
        address = int(verdict.get("address", "").strip(), 16)
    except ValueError:
        return False
    return in_code(CORPORA / "corpus-openwrt" / "images" / IMAGES[img] / "rootfs" / FILES[advisory], address)


def score(verdicts: dict) -> tuple[dict, list[str]]:
    counts = {"right": 0, "traps": 0, "caught": 0, "broken": 0, "checked": 0, "refuted": 0, "unsupported": 0}
    lines = []
    for img in IMAGES:
        for advisory in IDS:
            label = LABELS[(IMAGES[img], advisory)]
            truth = label["status"] == "vulnerable"
            claim = label["by_version"] == "vulnerable"
            verdict = verdicts.get((img, advisory))
            final, note = claim, "unchecked"
            if verdict and verdict["status"] in STATUSES:
                counts["checked"] += 1
                said = verdict["status"] == "vulnerable"
                if said == claim:
                    note = "confirmed"
                elif holds(img, advisory, verdict):
                    final, note = said, "refuted"
                    counts["refuted"] += 1
                else:
                    note = "refuted without evidence that holds"
                    counts["unsupported"] += 1
            trap = truth != claim
            counts["traps"] += trap
            counts["right"] += final == truth
            counts["caught"] += trap and final == truth
            counts["broken"] += not trap and final != truth
            lines.append(f"{img} {advisory}: claim {'affected' if claim else 'not affected'}, truth {label['status']}, {note}, {'right' if final == truth else 'WRONG'}")
    return counts, lines


def main() -> None:
    print("| run | right after checking | traps caught | right claims broken | claims checked | refuted | refuted without evidence |")
    print("|---|---|---|---|---|---|---|")
    total = len(IMAGES) * len(IDS)
    counts, _ = score({})
    print(f"| version scanner alone | {counts['right']} of {total} | 0 of {counts['traps']} | 0 | | | |")
    for arg in sys.argv[1:]:
        dir = Path(arg)
        path = dir / "work" / "verdicts.tsv"
        rows = csv.DictReader(open(path), delimiter="\t") if path.exists() else []
        verdicts = {(row["image"].strip(), row["advisory"].strip()): {k: (v or "").strip() for k, v in row.items() if k} for row in rows if row.get("image")}
        counts, lines = score(verdicts)
        (dir / "score.md").write_text("\n".join(lines) + "\n")
        right_claims = total - counts["traps"]
        print(f"| {dir.name} | {counts['right']} of {total} | {counts['caught']} of {counts['traps']} | {counts['broken']} of {right_claims} | {counts['checked']} | {counts['refuted']} | {counts['unsupported']} |")


if __name__ == "__main__":
    main()
