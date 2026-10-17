#!/usr/bin/env python3
"""Counts what makes decompiled C hard to read or wrong, across the benchmark set: for each kind
of defect, how many functions show it and how often it comes per 1,000 lines of C. Fixes to the
decompiler's output are ordered by these counts.

Usage, from the repository root: bench/census.py [--set bench/set.txt] [--sample 200]
    [--recore target/release/recore-mcp] [--save <file.json>] [--compare <file.json>]
"""
import argparse, json, re, subprocess, tempfile
from collections import Counter
from pathlib import Path

# Each kind of defect, as a pattern on one line of C.
KINDS = {
    "stack argument lost (in_stack_ above the return address)": r"\bin_stack_0000[0-9a-f]{4}\b",
    "caller frame read (in_stack_ below the stack pointer)": r"\bin_stack_ffff[0-9a-f]+\b",
    "vector store cast (undefined1 (*) [16])": r"\(undefined1 \(\*\) \[(?:16|32|64)\]\)",
    "CONCAT / SUB piece": r"\b(?:CONCAT|SUB)\d+\(",
    "ZEXT / SEXT": r"\b(?:ZEXT|SEXT)\d+\(",
    "register left over (extraout_, unaff_, in_REG)": r"\b(?:extraout_\w+|unaff_\w+|in_(?!FS_OFFSET|stack_)[A-Z][A-Z0-9]{1,4})\b",
    "raw address of data (xRam0000...)": r"\b[a-z]{1,3}Ram[0-9a-f]{8,}\b",
    "field by element index (param_1[0x4a])": r"\b(?:param_\d+|[a-z]{1,3}Var\d+)\[0x[0-9a-f]+\]",
    "field by byte offset (*(T *)(p + 0x28))": r"\*\([\w ]+\*\)\((?:param_\d+|[a-z]{1,3}Var\d+) \+ 0x[0-9a-f]+\)",
    # A struct indexed by a constant is one a recovered layout came out too small for: the
    # canary for struct recovery, which must stay where it was.
    "struct element by constant index (p[2].f)": r"\b(?:param_\d+|[a-z]{1,3}Var\d+)\[(?:0x)?[0-9a-f]+\]\.\w+",
    # Where a recovered struct meets code that sees the value as something else.
    "cast to a recovered struct": r"\(S_[0-9a-f]+_\w+ \*\)",
    "undefinedN type": r"\bundefined\d?\b",
    "goto": r"\bgoto \w+;",
    "stack canary (in_FS_OFFSET)": r"\bin_FS_OFFSET\b",
    # Most are a stripped binary's own functions; a change between builds is an import or a
    # named function that a call no longer reaches by name, or now does.
    "call to an unnamed function (func_0x...)": r"\bfunc_0x[0-9a-f]+\(",
}
WARNING = re.compile(r"/\* WARNING: (.*?)(?: \(ram,0x[0-9a-f]+\))?\s*\*/")


def functions(recore: str, binary: str, edits: str) -> list[str]:
    listing = subprocess.run([recore, "functions", binary, "--limit", "1000000"], capture_output=True, text=True, env={"RECORE_EDITS_DIR": edits, "PATH": "/usr/bin:/bin"}).stdout
    return [line.split()[0] for line in listing.splitlines()[2:] if line.startswith("0x")]


def sample(addrs: list[str], count: int) -> list[str]:
    """Every so many functions, so that a sample spreads over the whole binary the same way each run."""
    step = max(1, len(addrs) // count)
    return addrs[::step][:count]


def decompile(recore: str, binary: str, addrs: list[str], edits: str) -> dict[str, str]:
    """Each function's C, by address, as one `decompile` call prints them after a `// 0x...` line,
    whose name may hold spaces. A function the decompiler failed on has the reason for its C,
    starting `failed: `."""
    text = subprocess.run([recore, "decompile", binary, *addrs, "--timeout", "20"], capture_output=True, text=True, env={"RECORE_EDITS_DIR": edits, "PATH": "/usr/bin:/bin"}).stdout
    parts = re.split(r"^// (0x[0-9a-f]+)(.*)$", text, flags=re.M)
    found = {}
    for i in range(1, len(parts) - 2, 3):
        rest = parts[i + 1]
        found[parts[i]] = rest[2:].strip() if rest.startswith(": failed") else parts[i + 2]
    return found


def census(recore: str, binaries: list[str], count: int) -> dict:
    lines, functions_seen = 0, 0
    hits, affected, warnings, failures = Counter(), Counter(), Counter(), Counter()
    patterns = {kind: re.compile(pattern) for kind, pattern in KINDS.items()}
    for binary in binaries:
        with tempfile.TemporaryDirectory() as edits:
            for addr, c_text in decompile(recore, binary, sample(functions(recore, binary, edits), count), edits).items():
                functions_seen += 1
                if c_text.startswith("failed: "):
                    failures[re.sub(r"0x[0-9a-f]+", "N", c_text.splitlines()[0][8:])] += 1
                    continue
                body = [line for line in c_text.splitlines() if line.strip()]
                lines += len(body)
                for kind, pattern in patterns.items():
                    n = sum(len(pattern.findall(line)) for line in body)
                    hits[kind] += n
                    affected[kind] += n > 0
                for line in body:
                    for message in WARNING.findall(line):
                        warnings[re.sub(r"0x[0-9a-f]+", "N", message)] += 1
    return {"functions": functions_seen, "lines": lines, "hits": dict(hits), "affected": dict(affected), "warnings": dict(warnings), "failures": dict(failures)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--set", default="bench/set.txt")
    parser.add_argument("--sample", type=int, default=200)
    parser.add_argument("--recore", default="target/release/recore-mcp")
    parser.add_argument("--save")
    parser.add_argument("--compare")
    args = parser.parse_args()
    binaries = [line.strip() for line in open(args.set) if line.strip() and not line.startswith("#")]
    result = census(args.recore, binaries, args.sample)
    if args.save:
        Path(args.save).write_text(json.dumps(result, indent=2) + "\n")
    before = json.loads(Path(args.compare).read_text()) if args.compare else None
    per_k = lambda r, kind: 1000 * r["hits"].get(kind, 0) / max(1, r["lines"])
    print(f"{result['functions']} functions, {result['lines']:,} lines of C, from {len(binaries)} binaries")
    print(f"{'defect':<58} {'functions':>10} {'per 1k lines':>13}" + ("   before" if before else ""))
    for kind in sorted(KINDS, key=lambda k: -per_k(result, k)):
        share = 100 * result["affected"].get(kind, 0) / max(1, result["functions"])
        was = f"   {per_k(before, kind):6.1f}" if before else ""
        print(f"{kind:<58} {share:9.1f}% {per_k(result, kind):13.1f}{was}")
    failed = sum(result["failures"].values())
    print(f"\nfunctions the decompiler failed on: {failed} ({100 * failed / max(1, result['functions']):.1f}%)")
    for message, n in Counter(result["failures"]).most_common(8):
        print(f"{n:>7}  {message[:110]}")
    print("\nwarnings the decompiler writes into the C:")
    for message, n in Counter(result["warnings"]).most_common(12):
        print(f"{n:>7}  {message[:110]}")


if __name__ == "__main__":
    main()
