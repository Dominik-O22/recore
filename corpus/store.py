"""Where the corpora live: outside the repository, in one directory every checkout of it shares.

`RECORE_CORPORA` names it, and it is ~/recore-corpora when that is not set: no part of that
path starts with a dot, which Ghidra refuses in a project path. Each corpus is a directory in it
under the name it always had, such as `corpus` or `corpus-arm64`. check.sh, bench/snapshot.sh,
ghidra/run-reference.sh and the Rust tools find it by the same rule.
"""
import os
from pathlib import Path

CORPORA = Path(os.environ.get("RECORE_CORPORA") or Path.home() / "recore-corpora")
