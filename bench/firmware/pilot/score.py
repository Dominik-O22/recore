#!/usr/bin/env python3
"""Scores fleet triage answers against bench/firmware/labels.tsv, with the baselines beside them.

Usage: python3 -I bench/firmware/pilot/score.py <dir>...
Each <dir> is a session of run.sh, with its answers in work/answer.tsv; <dir>/score.md gets the
verdict of each cell. A cell scores 1 when its status is right and its evidence holds: for
vulnerable or fixed, the binary is the file the advisory's code is in and the address lies in
that file's code. A right status with evidence that does not hold scores half. "Traps" are the
cells where the version alone misjudges whether the image is vulnerable.
"""
import csv, struct, sys, tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "corpus"))
from store import CORPORA  # noqa: E402

IMAGES = dict(line.split("\t") for line in (HERE / "images.tsv").read_text().splitlines()[1:])
ADVISORIES = (HERE / "advisories.txt").read_text().split()
FILES = {a["id"]: a["files"][0] for a in tomllib.loads((HERE.parent / "advisories.toml").read_text())["advisory"]}
LABELS = {(row["image"], row["advisory"]): row for row in csv.DictReader(open(HERE.parent / "labels.tsv"), delimiter="\t")}


def in_code(path: Path, address: int) -> bool:
    """Whether `address` lies in an executable segment of the ELF file at `path`."""
    data = path.read_bytes()
    wide = data[4] == 2
    if wide:
        (phoff,), (phentsize, phnum) = struct.unpack_from("<Q", data, 0x20), struct.unpack_from("<HH", data, 0x36)
    else:
        (phoff,), (phentsize, phnum) = struct.unpack_from("<I", data, 0x1C), struct.unpack_from("<HH", data, 0x2A)
    for index in range(phnum):
        at = phoff + index * phentsize
        if wide:
            kind, flags, _, vaddr, _, _, memsz = struct.unpack_from("<IIQQQQQ", data, at)
        else:
            kind, _, vaddr, _, _, memsz, flags = struct.unpack_from("<IIIIIII", data, at)
        if kind == 1 and flags & 1 and vaddr <= address < vaddr + memsz:
            return True
    return False


def evidence(img: str, advisory: str, answer: dict) -> bool:
    if answer["status"] == "absent":
        return True
    binary = answer.get("binary", "").strip().lstrip("/")
    if binary != FILES[advisory]:
        return False
    try:
        address = int(answer.get("address", "").strip(), 16)
    except ValueError:
        return False
    return in_code(CORPORA / "corpus-openwrt" / "images" / IMAGES[img] / "rootfs" / binary, address)


def summary(cells: list[tuple[str, str, float]]) -> list[str]:
    """Points, right statuses, and the F1 score of "vulnerable", over (truth, answer, points)."""
    right = sum(truth == answer for truth, answer, _ in cells)
    said = sum(answer == "vulnerable" for _, answer, _ in cells)
    real = sum(truth == "vulnerable" for truth, _, _ in cells)
    both = sum(truth == answer == "vulnerable" for truth, answer, _ in cells)
    f1 = 2 * both / (said + real) if both else 0.0
    return [f"{sum(p for _, _, p in cells):g} of {len(cells)}", f"{right}", f"{f1:.2f}"]


def score(answers: dict[tuple[str, str], dict]) -> tuple[list[str], dict[str, list]]:
    lines, groups = [], {"all": [], "traps": [], **{a: [] for a in ADVISORIES}}
    for img in IMAGES:
        for advisory in ADVISORIES:
            label = LABELS[(IMAGES[img], advisory)]
            answer = answers.get((img, advisory))
            status = answer["status"].strip() if answer else "none"
            points = (1.0 if evidence(img, advisory, answer) else 0.5) if status == label["status"] else 0.0
            cell = (label["status"], status, points)
            groups["all"].append(cell)
            groups[advisory].append(cell)
            if (label["status"] == "vulnerable") != (label["by_version"] == "vulnerable"):
                groups["traps"].append(cell)
            lines.append(f"{img} {advisory}: {status}, truth {label['status']}, {points} ({label['evidence']})")
    return lines, groups


def main() -> None:
    print("| run | points | right status | F1 of vulnerable | traps, points | " + " | ".join(f"{a}, points" for a in ADVISORIES) + " |")
    print("|---|---|---|---|---|" + "---|" * len(ADVISORIES))
    baselines = {
        "version scanner": {(img, a): {"status": LABELS[(IMAGES[img], a)]["by_version"]} for img in IMAGES for a in ADVISORIES},
        "everything vulnerable": {(img, a): {"status": "vulnerable"} for img in IMAGES for a in ADVISORIES},
    }
    runs = [(Path(arg).name, Path(arg)) for arg in sys.argv[1:]]
    for name, answers in [*((n, None) for n in baselines), *runs]:
        if answers is None:
            table = baselines[name]
        else:
            path = answers / "work" / "answer.tsv"
            rows = csv.DictReader(open(path), delimiter="\t") if path.exists() else []
            table = {(row["image"].strip(), row["advisory"].strip()): row for row in rows if row.get("status")}
        lines, groups = score(table)
        if answers is not None:
            (answers / "score.md").write_text("\n".join(lines) + "\n")
        # A baseline cites no code, so it is scored on status alone.
        if answers is None:
            groups = {k: [(t, a, float(t == a)) for t, a, _ in v] for k, v in groups.items()}
        row = [*summary(groups["all"]), summary(groups["traps"])[0], *(summary(groups[a])[0] for a in ADVISORIES)]
        print(f"| {name} | " + " | ".join(row) + " |")

if __name__ == "__main__":
    main()
