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

Cortex-M is tier C's. The Debian builds in `corpus-armhf-holdout` and `corpus-armel-holdout` score recore's own analysis and stay out of this benchmark, so nothing here is tuned on them.

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
- **Patch dropped.** The release's SDK rebuilds the package without its CVE patch. The version still claims fixed, and the code is vulnerable.
- **Patch added.** The SDK rebuilds an older release's package with a later backport. The version says vulnerable, and the code is fixed.

The SDK builds use the release's own toolchain and flags, so the rebuilt binary differs from the shipped one only by the patch. The agent never sees both (see the pitfalls).

## Three task tiers

### A. Fleet triage (the core; speed matters)

The agent gets 40 to 60 unpacked images and 5 to 8 advisories, with the advisory text as published and no fix commit. It fills a matrix: for each image and advisory, vulnerable, fixed or absent, with the binary and the function that decide it as evidence. Images are named `img01` and so on, in random order. The rootfs keeps `/etc/openwrt_release` and the package database, as a defender's images would.

The session has a wall-clock budget, 45 minutes for the full tier. That is what makes the fleet size count. A full tier has about 50 images with 5 to 10 daemons each, a few hundred binaries. Ghidra's headless analysis of the binaries alone takes longer than the budget on one machine (measured: see the measurements below), so a Ghidra agent has to choose which binaries to analyze. A recore agent can afford all of them.

Each advisory in a task is picked so the version alone misjudges some of its cells. A full tier mixes one advisory a string decides (Terrapin), one compiled-out case (CVE-2022-0934 with some `dnsmasq-full` images), one mixed-status binary (24.10.7's dnsmasq) and at least two advisories published after the models' training data (the 2026 dnsmasq, uhttpd and odhcpd fixes).

### B. Locate and prove (depth on one advisory)

The agent gets one advisory and three to five binaries of one package from different releases and architectures, for example dropbear from 19.07.10 x86_64, 22.03.6 armv7 and 23.05.6 aarch64. For each binary it reports the address of the function that the fix changes, whether the fix is there, and the instructions that show it. Examples are the comparison CVE-2026-5172 adds after `extract_name`, or the cap UHTTPD-2026-CHUNKED puts on the chunk counter.

Truth comes from SDK builds of the same package and release, which keep their symbols until the strip step. The unstripped build gives the function's address, and the stripped release binary has it at the same address when the build reproduces. That holds when the rebuilt and the shipped binary have the same code bytes, and the benchmark checks it before it uses a binary. A cell scores when the address is the function's start and the stated status is right. The evidence is judged against the fix's diff by a model, three times with the majority taken, as `bench/agent/judge.py` does.

The binaries are never one build with and without the patch. Each pair differs by release, compiler version and architecture, so diffing two binaries turns up hundreds of changed functions, and the agent has to find the one the advisory describes.

### C. Firmware without a name (Cortex-M, and bugs nobody published)

Two sources, both with exact truth and neither in training data as an answer.

- **Cortex-M.** The Zephyr and Contiki-NG CVE samples from fuzzware-experiments, 15 with ELF truth, and our own builds of each fix commit and its parent across two boards and two compilers. Raw `.bin` images with a layout file, as recore's Cortex-M corpus already has.
- **Reverted fixes that never got a CVE.** OpenWrt's patch lists carry security fixes with no CVE, such as libubox's `blobmsg-fix-heap-buffer-overflow-in-blobmsg_parse` in 18.06.9 and uhttpd's `fix-off-by-one-out-of-bounds-read-in-uh_b64decode` in 24.10.8. The SDK builds each release with and without one. The advisory is written as a defender would get it from a vendor, with the component and the bug class but no function name.

The task is tier B's: name the function, say fixed or vulnerable per build. Tier C has the fewest images and the hardest cells, and is where headroom lives once tiers A and B saturate.

## Scoring

- **Cells.** Each cell is right or wrong on its status. The headline is the F1 score of "vulnerable", because a defender acts on that call. Accuracy over all three statuses comes second. A cell with no answer counts as wrong.
- **Evidence.** A status counts only with evidence. In tier A that is the binary that carries the code and a function address in it. The scorer checks that the binary exists in the image and is the package's, and that the address is a function start in recore's and Ghidra's analysis of it. A right status with wrong or no evidence scores half.
- **Cost.** Wall time, the analysis time each tool spent before and during the session, tokens read and dollars. They come from `bench/agent/stats.py`.
- **Baselines, published with every result.** The version scanner (the `by_version` column), "everything vulnerable", and the model with no tool at all, which measures what it recalls. A tool's score is worth what it adds over the best of these.

## Pitfalls, and what the design does about each

The research's section 4 names seven, and the brief that asked for this design names five. Each has an answer here.

1. **A diff where only one function changed.** No task contains a variant beside the release it came from, on the same architecture. Tier B pairs differ by release, compiler and architecture. A patch-dropped variant replaces its release in a task; its twin is not in the fleet.
2. **Strings that give the answer away.** Some fixes add a string. Terrapin's strict-KEX name is one. An advisory records the string in `tell` where one decides it, and results are reported separately for those cells and for cells only the code decides. CVE-2023-28450 is a constant (an EDNS size of 4096 or 1232), CVE-2026-5172 one comparison, and UHTTPD-2026-CHUNKED a cap on a counter: no string tells. Version banners stay in, because they are the trap. Images are numbered, so a file name says nothing.
3. **CVEs a model may remember.** Five advisories are 2026 fixes. CVE-2026-53922's text was published on 2026-10-12, and the uhttpd fix has no CVE, so its text is the fix commit's own description. OpenWrt's backports are the part a model might recall ("22.03.7 has the Terrapin patch"), and the patch-dropped variants make that recall wrong. The no-tool baseline measures how much recall is worth.
4. **Version-only labels.** Labels come from the tree and the patch list at the tag, never from the version string. The labeller refuses an image whose package database disagrees with the tree.
5. **Build variance.** Variants are built with the release's own SDK, pinned by URL and SHA-256 with its toolchain version. A variant whose untouched rebuild does not match the shipped binary's code is not used. The release images are the release's own builds, so the natural fleet has no build variance of ours.
6. **Canaries and logging calls.** Nothing is instrumented. Variants are plain builds with a real patch dropped or added.
7. **Synthetic bugs near the entry point or behind magic constants.** Nothing is seeded. Every bug is a real one with a real fix, which a variant removes or adds.

## Headroom

Several things keep a strong model with the best tool short of full marks:

- **The budget.** Fleet triage is a time-bound sweep, and the cells it misses count as wrong.
- **Architectures.** Two thirds of the binaries are ARM, a third of them 32-bit, stripped, built with musl.
- **Code-only cells.** Advisories with no telling string have to be settled in the code, in a function the advisory describes but does not always name.
- **Mixed-status binaries.** The model has to judge each advisory on its own, even when it shares one dnsmasq binary with others.
- **Compiled-out cells.** The model has to show the code is missing, not just that the version is old.
- **Tier C.** Bugs with no public name, in images with no file system.

The pilot below has to show that the harder cells separate the tools and that neither arm saturates them.

## Pilot

Tier A, small: 10 images and 3 advisories, run with Haiku on both arms. `bench/firmware/pilot/` holds the task, its scorer and the prompts. The results and an audit of the sessions are in [results.md](results.md).
