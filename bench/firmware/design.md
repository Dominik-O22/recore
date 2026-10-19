# Firmware benchmark: design

Date: 2026-10-17. Inputs: [research.md](research.md), the agent eval in [bench/agent](../agent). The first commit of this file is the draft as it was written; this version finishes it.

## What it has to show

The current agent eval is saturated. Haiku scores 17 of 17 with recore, so it can no longer tell a better tool from a worse one. The firmware benchmark should:

- measure work defenders do on firmware, where Ghidra is the default tool;
- be big enough that analysis time counts (a fleet, not one binary), so recore's speed shows up in the result and not only in a side table;
- have checkable ground truth that a model cannot recall from training data or read off a version string;
- leave headroom, so a strong model with the best tool still does not score full marks.

## Architectures

recore reads x86-64, AArch64, 32-bit ARM Linux (A32 and Thumb-2, since PR #17), x86, 8051 and Cortex-M. The research ruled out 32-bit ARM router firmware. It is in scope now, so every OpenWrt task covers three architectures:

| Architecture | OpenWrt targets | Releases |
|---|---|---|
| x86_64 | x86/64 | 17.01.1 to 25.12.5, 66 |
| aarch64 | armvirt/64, then armsr/armv8 from 23.05 | 18.06.0 to 25.12.5, 59 |
| armv7 | armvirt/generic in 17.01, armvirt/32, then armsr/armv7 | 17.01.1 to 25.12.5, 66 |

These are the virtual-machine targets. They build the same packages from the same tree as the routers of their architecture, and they exist for every release, which no single router target does. MIPS is still out. When recore reads it, ath79 and ramips images bring the same packages and the task sets carry over.

Cortex-M is part 2's. The Debian builds in `corpus-armhf-holdout` and `corpus-armel-holdout` score recore's own analysis and stay out of this benchmark, so nothing here is tuned on them.

## Corpus

### The natural fleet

[corpus/fetch_openwrt.py](../../corpus/fetch_openwrt.py) fetches 191 release images, one per release and architecture, pinned by URL and SHA-256 in [corpus/openwrt-images.tsv](../../corpus/openwrt-images.tsv). They go to `corpus-openwrt/` in the corpora directory and are never committed. Every release ships its root filesystem as a tarball beside the disk images, so the fetcher reads that tarball through Python's `tarfile` data filter and needs no firmware unpacker. That changes the draft's plan of unpacking squashfs and ext4 with unblob. The agent gets one rootfs directory per image either way.

Packages labelled: dnsmasq, dropbear, BusyBox, uhttpd and odhcpd. libubox ships in every image but carries no advisory yet, because I could not pin the fix commit of its one CVE (CVE-2020-7248). hostapd and wpad are not in the virtual-machine images, which have no radio. A vendor-style variant (below) can add them from the release's own package feed.

### Labels

[corpus/label_openwrt.py](../../corpus/label_openwrt.py) labels each image against each advisory in [advisories.toml](advisories.toml). It reads the OpenWrt tree at the image's release tag and never reads the version string. Each cell of [labels.tsv](labels.tsv) is one of:

- **vulnerable.** The code the advisory names is built in, and the fix is not.
- **fixed.** The upstream release or git snapshot has the fix, or OpenWrt applies a patch with it.
- **absent.** The image does not carry the file, or the build leaves the code out.

The rules come from three places. The package's Makefile at the tag gives the upstream version, or the git snapshot it builds. The tag's `patches/` directory gives the backports. Upstream's own changelog, or `git tag --contains` on the fix commit, gives the first fixed release. A git snapshot counts as fixed when it contains the fix commit or a cherry-pick of it with the same subject: 25.12.5's odhcpd carries CVE-2026-53922's fix as a cherry-pick, which an ancestry test alone misses. The labeller also checks that the version in each image's own package database is the one the tree builds, and stops if not. All 191 agree.

17 advisories over 191 images give 3,247 cells: 1,657 vulnerable, 1,208 fixed, 382 absent. A version scanner gets 338 of them wrong about whether the cell is vulnerable. The `by_version` column records its answer, so any report can be scored against it. The traps the research expected are real:

- dnsmasq 2.80 in 19.07.6 to 19.07.10 carries the DNSpooq fixes (CVE-2020-25684, 25685, 25686) as patches. 2.80 in 18.06 does not.
- dropbear 2022.82 is in every release from 22.03.0 to 23.05.6. The strict-KEX patch for Terrapin arrives in 22.03.7 and 23.05.3, so the same version string is fixed in some images and vulnerable in others.
- dnsmasq 2.90 in 24.10.7 and 2.91 in 25.12.4 carry backports of CVE-2026-2291 and CVE-2026-5172, but not of CVE-2026-12969. One binary is fixed for two advisories and vulnerable for a third.
- CVE-2022-0934 is in dnsmasq's DHCPv6 code and CVE-2020-25681 in its DNSSEC code. Stock images ship the `dnsmasq` variant, built with `NO_DHCP6` and without DNSSEC, so both cells are absent in all 191 images even where the version is in range. The binary's compile-options string confirms it (`no-DHCPv6 ... no-DNSSEC`). The draft's example, the 21.02.7 backport of CVE-2022-0934, only matters in an image that ships `dnsmasq-full`.

Labels were checked against the binaries where a string settles it. The strict-KEX name `kex-strict-s-v00@openssh.com` is in dropbear exactly in the images labelled fixed for CVE-2023-48795.

### Variants

Variants put the cells the natural fleet lacks into real images. Each is a release image with one package replaced, recorded in the manifest with what was changed, so its label stays exact.

- **Package swap.** `dnsmasq-full` from the release's own package feed, pinned by the SHA-256 in its `Packages` index, replaces `dnsmasq`. Many vendor images ship it. This turns CVE-2022-0934 and CVE-2020-25681 from absent into present cells, with the 21.02.7 and 22.03.7 backports as the trap. No build is needed.
- **Stale program.** One program comes from an older release image of the same architecture, and the package database stays as it was, as when a vendor ships a stale binary. The version claims a fix the code lacks. No build is needed. Two are built: 25.12.5's database names dnsmasq 2.93 over 24.10.6's 2.90, and 24.10.8's names dropbear 2024.86 over 23.05.2's 2022.82.
- **Patch dropped.** The release's SDK rebuilds the package without its CVE patch. The version still claims fixed, and the code is vulnerable. Not built yet: it runs the SDK's downloaded toolchain.
- **Patch added.** The SDK rebuilds an older release's package with a later backport. The version says vulnerable, and the code is fixed. Not built yet, for the same reason.

The SDK builds use the release's own toolchain and flags, so the rebuilt binary differs from the shipped one only by the patch. The agent never sees both (see the pitfalls).

## Two parts

A version scanner and a binary analysis tool do different jobs, so the benchmark scores them apart. The scanner matches versions against a database of advisories, which is fast and covers a fleet, and it cannot tell a backport from a vulnerable build or code that is built out from code that is there. Binary analysis can. Part 1 scores what analysis adds to the scanner. Part 2 scores analysis with no advisory at all.

### Part 1. Check the scanner's claims (a fleet; speed matters)

The agent gets unpacked images, the advisories as published, and the scanner's claim for each image and advisory: `affected` or `not affected`, with the program and version it read. It checks the claims against the binaries and refutes the wrong ones, with the binary and the function that decide each verdict as evidence. A claim it does not check stands. Images are named `img01` and so on, in random order, and keep `/etc/openwrt_release` and the package database, as a defender's images would.

The scanner is wrong in both directions, and a task holds both:

- **Claimed affected, not affected.** A backport (dropbear 2022.82 in 22.03.7), code built out (DHCPv6 in stock dnsmasq), or a mixed-status binary (24.10.7's dnsmasq, fixed for two 2026 advisories and not a third).
- **Claimed not affected, affected.** A stale program, and once they are built, a dropped patch.

A full task has 40 to 60 images and 5 to 8 advisories and a 45-minute budget. The budget only makes the fleet count when the agent has to look at many binaries. Ghidra took 6 s of analysis and 9.4 s of wall time per OpenWrt binary in the first measurements, so an advisory that names one daemon costs it 50 binaries and about 8 minutes, well inside the budget. Speed shows where the advisory does not say which binary carries the code:

- **Library advisories.** A flaw in libubox, musl or another shared library: the agent has to find which programs use the vulnerable function, not only whether the library has the fix.
- **Bundled copies.** Code that programs carry inside them, such as dropbear's libtommath or BusyBox's DHCP client.
- **Component unknown.** An advisory that names the bug and the protocol but not the program, as vendor advisories often do.

Each full task carries at least two such advisories. An image has 85 to 96 programs and libraries, so a fleet of 50 has about 4,500, roughly 12 hours of Ghidra wall time on one 4-core job (inferred from the per-binary average), and a Ghidra agent has to choose which to analyze. recore analyzed all 3,228 distinct ones in the 197 images in 8.5 s on one core.

### Part 2. Find security bugs with no prior knowledge (depth)

The agent gets programs and a scope, such as "the web server and the DHCPv6 server of this router image", and no advisory. It reports each security bug it finds: the binary, the function, the class of bug and the input that reaches it.

Truth comes from security fixes OpenWrt shipped as patches between two releases built from the same source snapshot. The earlier release's program carries every one of those bugs, and the later one exists to check the truth against: a diff of the two builds shows each fixed function. 24.10.7 and 24.10.8 are such a pair for uhttpd and odhcpd, with dozens of fixes from 2026, most without a CVE, so a model cannot recall them. Cortex-M firmware joins the same way, from the Zephyr and Contiki-NG fix commits and their parents.

The agent never sees the fixed build, so diffing is not available to it. The truth list itself is not in this repository yet.

## Scoring

- **Part 1.** The scanner's claims are the starting point. A session is scored on the wrong claims it refutes and the right claims it breaks, and on how many claims end up right. A refutation counts only with evidence that holds, the advisory's binary and an address in its code, at the file's addresses or at Ghidra's default image base. Results are reported separately for claims a string decides (an advisory's `tell`) and for claims only the code decides.
- **Part 2.** A finding matches a known bug when it names the right program and an address inside the fixed function, and a judge model agrees, three times with the majority taken as `bench/agent/judge.py` does, that it describes that bug. A finding that matches no known bug is not counted as wrong, since the program may hold bugs nobody has fixed. It goes to review by a person.
- **Cost.** Wall time, the analysis time each tool spent before and during the session, tokens read and dollars, from `bench/agent/stats.py`.
- **Baselines.** Part 1 has the scanner alone. Part 2 has the model with no tool, which measures what it recalls.

## Pitfalls, and what the design does about each

The research's section 4 names seven, and the brief that asked for this design names five. Each has an answer here.

1. **A diff where only one function changed.** No task contains a variant beside the release it came from, on the same architecture, and part 2 never gives the agent the fixed build. A patch-dropped variant replaces its release in a task; its twin is not in the fleet.
2. **Strings that give the answer away.** Some fixes add a string. Terrapin's strict-KEX name is one. An advisory records the string in `tell` where one decides it, and results are reported separately for those cells and for cells only the code decides. CVE-2023-28450 is a constant (an EDNS size of 4096 or 1232), CVE-2026-5172 one comparison, and UHTTPD-2026-CHUNKED a cap on a counter: no string tells. Version banners stay in, because they are the trap. Images are numbered, so a file name says nothing.
3. **CVEs a model may remember.** Five advisories are 2026 fixes. CVE-2026-53922's text was published on 2026-10-12, and the uhttpd fix has no CVE, so its text is the fix commit's own description. OpenWrt's backports are the part a model might recall ("22.03.7 has the Terrapin patch"), and the stale and patch-dropped variants make that recall wrong. Part 2's bugs are mostly fixes with no CVE, and its no-tool baseline measures how much recall is worth.
4. **Version-only labels.** Labels come from the tree and the patch list at the tag, never from the version string. The labeller refuses an image whose package database disagrees with the tree.
5. **Build variance.** Variants are built with the release's own SDK, pinned by URL and SHA-256 with its toolchain version. A variant whose untouched rebuild does not match the shipped binary's code is not used. The release images are the release's own builds, so the natural fleet has no build variance of ours.
6. **Canaries and logging calls.** Nothing is instrumented. Variants are plain builds with a real patch dropped or added.
7. **Synthetic bugs near the entry point or behind magic constants.** Nothing is seeded. Every bug is a real one with a real fix, which a variant removes or adds.

## Headroom

Several things keep a strong model with the best tool short of full marks:

- **The budget.** Part 1 is a time-bound sweep, and a claim the agent does not reach stands, right or wrong.
- **Architectures.** Two thirds of the binaries are ARM, a third of them 32-bit, stripped, built with musl.
- **Code-only claims.** Advisories with no telling string have to be settled in the code, in a function the advisory describes but does not always name.
- **Mixed-status binaries.** The model has to judge each advisory on its own, even when it shares one dnsmasq binary with others.
- **Compiled-out code.** The model has to show the code is missing, not just that the version is old.
- **Part 2.** Bugs with no advisory, in programs with no symbols.

The pilots have to show that the harder claims separate the tools and that neither arm saturates them.

## Pilots

Part 1, small: 10 images and 3 advisories, 30 claims, run with Haiku and Sonnet on both arms. `bench/firmware/verify/` holds the task, its scorer and the scanner's claims, and `bench/firmware/run.sh` runs a session. A first pilot asked the agent to fill the matrix with no claims. The results of both and an audit of the sessions are in [results.md](results.md).
