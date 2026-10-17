#!/usr/bin/env python3
"""Writes the verify task's advisories and the version scanner's claims into a task folder.

Usage: python3 -I bench/firmware/verify/prepare.py <task dir>
The claims come from the by_version column of labels.tsv, the answer the version in each image's
package database gives on its own, and say nothing else about the labels.
"""
import csv, sys, tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGES = dict(line.split("\t") for line in (HERE / "images.tsv").read_text().splitlines()[1:])
IDS = (HERE / "advisories.txt").read_text().split()
ADVISORIES = {a["id"]: a for a in tomllib.loads((HERE.parent / "advisories.toml").read_text())["advisory"]}
LABELS = {(row["image"], row["advisory"]): row for row in csv.DictReader(open(HERE.parent / "labels.tsv"), delimiter="\t")}

task = Path(sys.argv[1])
(task / "advisories.md").write_text("".join(f"## {id}\n\n{ADVISORIES[id]['text']}\n\n" for id in IDS))
rows = ["image\tadvisory\tprogram\tversion\tclaim"]
for img, image in IMAGES.items():
    for id in IDS:
        label = LABELS[(image, id)]
        claim = "affected" if label["by_version"] == "vulnerable" else "not affected"
        rows.append(f"{img}\t{id}\t{ADVISORIES[id]['files'][0]}\t{label['reported']}\t{claim}")
(task / "claims.tsv").write_text("\n".join(rows) + "\n")
