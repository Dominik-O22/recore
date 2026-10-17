#!/usr/bin/env python3
"""Labels every image of the OpenWrt fleet against every advisory, from the source tree at the
image's release tag and never from the version string the image reports.

Usage: python3 -I corpus/label_openwrt.py
Reads corpus/openwrt-images.tsv, bench/firmware/advisories.toml and the unpacked images that
corpus/fetch_openwrt.py wrote, and writes bench/firmware/labels.tsv. It clones the OpenWrt tree
and the upstream trees of the packages it builds from git snapshots into
<corpora>/corpus-openwrt/src, without their file contents, which git fetches as it reads them.

A cell is one of:
  vulnerable  the code the advisory names is built in, and the fix is not;
  fixed       the upstream release or snapshot has the fix, or OpenWrt applies a patch with it;
  absent      the image does not carry the file, or the build leaves the code out.
The reported column is the package version in the image's own package database, and by_version
is what that version would say on its own: the answer a version scanner gives, which a report can
be scored against.
"""
import re, subprocess, sys, tomllib
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from store import CORPORA  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
IMAGES = ROOT / "corpus" / "openwrt-images.tsv"
ADVISORIES = ROOT / "bench" / "firmware" / "advisories.toml"
LABELS = ROOT / "bench" / "firmware" / "labels.tsv"
FLEET = CORPORA / "corpus-openwrt"
SRC = FLEET / "src"
REPOS = {
    "openwrt": "https://github.com/openwrt/openwrt.git",
    "uhttpd": "https://github.com/openwrt/uhttpd.git",
    "odhcpd": "https://github.com/openwrt/odhcpd.git",
}


def git(repo: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(SRC / f"{repo}.git"), *args], capture_output=True, text=True, check=check)


def clone(repo: str) -> None:
    if not (SRC / f"{repo}.git").is_dir():
        SRC.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "-q", "--bare", "--filter=blob:none", REPOS[repo], str(SRC / f"{repo}.git")], check=True)


def version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text))


@dataclass(frozen=True)
class Package:
    """A package as the tree builds it at one tag: its Makefile's variables and its patches."""
    vars: dict[str, str]
    patches: tuple[str, ...]

    @property
    def upstream(self) -> str:
        return self.vars.get("PKG_UPSTREAM_VERSION") or self.vars.get("PKG_VERSION", "")


def package(tag: str, path: str) -> Package:
    makefile = git("openwrt", "show", f"{tag}:package/{path}/Makefile").stdout
    vars = dict(re.findall(r"^(PKG_\w+)\s*[:?]?=\s*(.*?)\s*$", makefile, re.M))
    listing = git("openwrt", "ls-tree", "--name-only", f"{tag}:package/{path}/patches", check=False).stdout
    return Package(vars, tuple(listing.split()))


def busybox_default(tag: str, symbol: str) -> bool:
    defaults = git("openwrt", "show", f"{tag}:package/utils/busybox/Config-defaults.in").stdout
    block = re.search(rf"^config {symbol}\n((?:[ \t].*\n)+)", defaults, re.M)
    return bool(block and re.search(r"^\s*default y\s*$", block.group(1), re.M))


def installed(rootfs: Path) -> dict[str, str]:
    """Package name to version, from opkg's status file or, from 25.12 on, apk's database."""
    opkg, apk = rootfs / "usr/lib/opkg/status", rootfs / "lib/apk/db/installed"
    if opkg.exists():
        stanzas = opkg.read_text(errors="replace").split("\n\n")
        pairs = [(re.search(r"^Package: (.+)$", s, re.M), re.search(r"^Version: (.+)$", s, re.M)) for s in stanzas]
    else:
        stanzas = apk.read_text(errors="replace").split("\n\n")
        pairs = [(re.search(r"^P:(.+)$", s, re.M), re.search(r"^V:(.+)$", s, re.M)) for s in stanzas]
    return {name.group(1): ver.group(1) for name, ver in pairs if name and ver}


def label(advisory: dict, tag: str, rootfs: Path, packages: dict[str, str], pkg: Package) -> tuple[str, str, str]:
    """The cell's status, the evidence for it, and what the reported version alone would say."""
    file = advisory["files"][0]
    if not (rootfs / file).exists():
        return "absent", f"no {file}", "absent"
    if "fixed" in advisory:
        claimed = "fixed" if version(pkg.upstream) >= version(advisory["fixed"]) else "vulnerable"
    else:
        # A version scanner can only compare the snapshot's date with the fix's date.
        fix_date = git(advisory["repo"], "log", "-1", "--format=%cs", advisory["commit"]).stdout.strip()
        claimed = "fixed" if pkg.vars["PKG_SOURCE_DATE"] >= fix_date else "vulnerable"
    kind, _, names = advisory.get("needs", ":").partition(":")
    if kind == "variant" and not any(name in packages for name in names.split(",")):
        return "absent", f"built without the code: the image has {', '.join(n for n in packages if n.startswith('dnsmasq'))}", claimed
    if kind == "busybox" and not busybox_default(tag, names):
        return "absent", f"{names} is off", claimed
    if "fixed" in advisory and version(pkg.upstream) >= version(advisory["fixed"]):
        return "fixed", f"upstream {pkg.upstream} has the fix from {advisory['fixed']}", claimed
    if "commit" in advisory:
        snapshot = pkg.vars["PKG_SOURCE_VERSION"]
        if git(advisory["repo"], "merge-base", "--is-ancestor", advisory["commit"], snapshot, check=False).returncode == 0:
            return "fixed", f"snapshot {snapshot[:12]} contains {advisory['commit'][:12]}", claimed
        # A release branch takes the fix as a cherry-pick, a new commit with the fix's subject.
        subject = git(advisory["repo"], "log", "-1", "--format=%s", advisory["commit"]).stdout.strip()
        picked = git(advisory["repo"], "log", "--format=%h %s", snapshot).stdout.splitlines()
        pick = next((line.split()[0] for line in picked if line.split(" ", 1)[1] == subject), None)
        if pick:
            return "fixed", f"snapshot {snapshot[:12]} has {pick}, a cherry-pick of {advisory['commit'][:12]}", claimed
    patch = next((p for p in pkg.patches if "backport" in advisory and re.search(advisory["backport"], p)), None)
    if patch:
        return "fixed", f"patch {patch}", claimed
    built = pkg.upstream or f"snapshot {pkg.vars.get('PKG_SOURCE_DATE')}"
    return "vulnerable", f"{built}, no fix and no patch with it", claimed


def main() -> None:
    for repo in REPOS:
        clone(repo)
    advisories = tomllib.loads(ADVISORIES.read_text())["advisory"]
    images = [line.split("\t")[0] for line in IMAGES.read_text().splitlines()[1:]]
    rows, cache = [], {}
    for id in images:
        release = id.rsplit("-", 1)[0]
        tag = f"v{release}"
        rootfs = FLEET / "images" / id / "rootfs"
        packages = installed(rootfs)
        for advisory in advisories:
            key = (tag, advisory["package"])
            if key not in cache:
                cache[key] = package(*key)
            pkg = cache[key]
            status, evidence, claimed = label(advisory, tag, rootfs, packages, pkg)
            name = advisory["package"].rsplit("/", 1)[1]
            reported = next((v for n, v in packages.items() if n == name or n.startswith(name + "-")), "")
            # The image's own package database has to agree with the tree it was labelled from.
            if reported and pkg.upstream and not reported.startswith(pkg.upstream):
                raise SystemExit(f"{id}: the image reports {name} {reported}, the tree at {tag} builds {pkg.upstream}")
            rows.append(f"{id}\t{advisory['id']}\t{status}\t{claimed}\t{reported}\t{evidence}")
    LABELS.write_text("image\tadvisory\tstatus\tby_version\treported\tevidence\n" + "\n".join(rows) + "\n")
    counts = {}
    for row in rows:
        status = row.split("\t")[2]
        counts[status] = counts.get(status, 0) + 1
    # A version scanner is wrong where it calls a cell vulnerable that is not, or the reverse.
    wrong = sum((row.split("\t")[2] == "vulnerable") != (row.split("\t")[3] == "vulnerable") for row in rows)
    print(f"{len(rows)} cells: {counts}; the version alone misjudges {wrong} as vulnerable or not")


if __name__ == "__main__":
    main()
