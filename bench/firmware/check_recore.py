#!/usr/bin/env python3
"""Runs `recore summary` on every distinct ELF file in the OpenWrt fleet and reports each that
fails, times out, or yields no functions although it has code.

Usage: python3 -I bench/firmware/check_recore.py <recore> <out.tsv>
Each file is analyzed once however many images carry it, on one thread, with a 60 s limit.
The table has a row per file: sha256, size, ELF type, exit status, functions, milliseconds and
the first image that carries it.
"""
import hashlib, os, re, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "corpus"))
from store import CORPORA  # noqa: E402

TYPES = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}


def elves() -> dict[str, Path]:
    """One path for each distinct ELF file, by sha256."""
    found = {}
    for image in sorted((CORPORA / "corpus-openwrt" / "images").iterdir()):
        for path in (image / "rootfs").rglob("*"):
            if path.is_file() and not path.is_symlink() and path.stat().st_size > 52:
                with path.open("rb") as file:
                    if file.read(4) != b"\x7fELF":
                        continue
                found.setdefault(hashlib.sha256(path.read_bytes()).hexdigest(), path)
    return found


def check(recore: str, digest: str, path: Path) -> str:
    data = path.read_bytes()
    kind = TYPES.get(int.from_bytes(data[16:18], "little"), "?")
    env = dict(os.environ, RAYON_NUM_THREADS="1")
    try:
        run = subprocess.run([recore, "summary", str(path)], capture_output=True, text=True, timeout=60, env=env)
        status, out = str(run.returncode), run.stdout + run.stderr
    except subprocess.TimeoutExpired:
        status, out = "timeout", ""
    functions = re.search(r"^(\d+) functions", out, re.M)
    ms = re.search(r"analyzed in (\d+) ms", out)
    error = "" if status == "0" else out.strip().splitlines()[-1][:200] if out.strip() else ""
    image = path.relative_to(CORPORA / "corpus-openwrt" / "images")
    return "\t".join([digest[:16], str(len(data)), kind, status, functions.group(1) if functions else "", ms.group(1) if ms else "", str(image), error])


def main() -> None:
    recore, out = sys.argv[1], Path(sys.argv[2])
    files = elves()
    with ThreadPoolExecutor(12) as pool:
        rows = list(pool.map(lambda item: check(recore, *item), files.items()))
    out.write_text("sha256\tbytes\ttype\tstatus\tfunctions\tms\tfile\terror\n" + "\n".join(rows) + "\n")
    cells = [row.split("\t") for row in rows]
    by_type = {}
    for cell in cells:
        by_type.setdefault(cell[2], []).append(cell)
    for kind, group in sorted(by_type.items()):
        failed = [c for c in group if c[3] != "0"]
        empty = [c for c in group if c[3] == "0" and c[4] == "0"]
        print(f"{kind}: {len(group)} files, {len(failed)} failed, {len(empty)} with no functions")


if __name__ == "__main__":
    main()
