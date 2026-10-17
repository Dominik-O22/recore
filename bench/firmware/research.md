# Firmware security benchmark: corpus and prior art

Date of survey: 2026-10-17. No firmware images were downloaded. I fetched directory listings, checksum files, package indexes, repo metadata and the small LVFS metadata file (250 KB).

Evidence tags used below:

- [V] verified in this session. I read the page, ran the command, or got an HTTP 200.
- [S] taken from a web search result summary. I did not open the primary source.
- [I] inferred, from general knowledge or from combining verified facts.

## Summary and recommendation

recore reads x86-64, AArch64 and Cortex-M, so the corpus has to come from three places. OpenWrt x86_64 and aarch64 builds cover embedded Linux. Zephyr and Contiki-NG cover Cortex-M. Our own rebuilds cover everything where we need exact ground truth. Most public router firmware is MIPS or A32 and is out. I would build all three options below and share one scoring harness.

### Option 1. OpenWrt release fleet, x86_64 and aarch64 (n-day detection across a fleet)

- Size. About 64 final releases from 17.01 to 25.12, counted from the directory listing [V]. For x86_64, the base and packages feeds hold 3,896 packages (880 MB) in 19.07.10, 4,876 (2.1 GB) in 21.02.7 and 5,114 (2.3 GB) in 23.05.6 [V]. These counts leave out the luci, routing and telephony feeds, and many packages are scripts. Full images are small, about 10 to 12 MB gzipped each [V]. aarch64 package feeds exist in 21.02.7 through 24.10.8 for aarch64_generic, cortex-a53 and cortex-a72 [V].
- Fetch path. `downloads.openwrt.org/releases/<ver>/targets/<target>/sha256sums` lists every image with SHA-256 [V for x86/64 23.05.5]. The armsr/armv8 target also ships `sha256sums.asc` and `.sig` [V]. Each `Packages.gz` gives Filename, Size, SHA256sum, License and a CPE-ID per package [V], so the NVD mapping is partly done for us. Targets: x86/64 from 17.01 on [V], armvirt/64 up to 21.02 [V], armsr/armv8 from 23.05 (404 in 22.03.7) [V], mediatek/filogic from 23.05 (404 in 22.03.7) [V], rockchip/armv8 from 22.03 [V].
- Licence. The build system and each package carry their own licences (dnsmasq is GPL-2.0 [V]). Treat it as fetch-by-script with a URL and hash manifest, not as something we redistribute.
- Ground truth. Package version plus NVD affected ranges plus the OpenWrt source tree at the release tag. The third part matters because OpenWrt backports. dnsmasq 2.85 in 21.02.7 and 2.86 in 22.03.7 both carry `001-CVE-2022-0934-Fix-write-after-free-error-in-DHCPv6-code.patch`, and dropbear in 22.03.7 carries `021-Implement-Strict-KEX-mode.patch` [V]. A version-string answer is wrong for those, and that is a useful trap for the patch-presence task.
- Tasks. Fleet n-day detection (which images ship dnsmasq below 2.83 and so on), patch presence for backported fixes, and "find the vulnerable function given an advisory".
- Weak points. Binaries are stripped, so function-level truth needs a rebuild (Option 3). dnsmasq spans 2.78 to 2.93 across releases, so one package straddles several CVE boundaries [V].

### Option 2. Cortex-M RTOS builds with CVEs (Zephyr, Contiki-NG, FreeRTOS+TCP)

- Size. Start with the 15 prebuilt Cortex-M samples in `fuzzware-fuzzer/fuzzware-experiments`, 12 Zephyr and 3 Contiki-NG, each with `.bin`, `.elf` and `config.yml` [V]. The `.bin` plus `config.yml` memory map is close to recore's raw firmware plus layout-file input [I]. Scale up by building from source. Zephyr has 61 stable release tags [V] and 279 published security advisories [V]. Contiki-NG has 33, RIOT 42, FreeRTOS-Plus-TCP 12, FreeRTOS-Kernel 7 and ThreadX 16 [V].
- Fetch path. Fuzzware samples are plain files in a git repo (Apache-2.0 [V]). Each CVE has a row with fix PR and fix commit, for example CVE-2020-10064 with commit 38970c07 and CVE-2021-3321 with commit 60680794 [V]. Zephyr advisories come from `gh api repos/zephyrproject-rtos/zephyr/security-advisories`. Each has `vulnerable_version_range` and `patched_versions` (CVE-2021-3319 reads "> v2.4.0" and "v2.5.0") [V].
- Licence. Zephyr Apache-2.0, Contiki-NG BSD-3-Clause, FreeRTOS-Plus-TCP and ThreadX MIT, RIOT LGPL-2.1, FNET Apache-2.0 [V]. All can be rebuilt and redistributed with attribution.
- Ground truth. Fix commits. We build the parent of the fix and the fix itself, so vulnerable versus fixed is exact, and the unstripped ELF gives the function address [I, mechanism verified in Fuzzware's `build_sample_CVE-*.sh` and `patches/`].
- Tasks. Locate the vulnerable function from an advisory, patch presence on stripped `.bin` pairs, and fleet detection across many board and version builds.
- Weak points. Build settings change code a lot (board, Kconfig, toolchain), so one commit gives many different binaries. Ripple20 (Treck) is proprietary and has no public source, so it is not usable [I, not searched]. AMNESIA:33 covers uIP, picoTCP, FNET and Nut/Net [S], and only uIP (Contiki), FNET and picoTCP have public repos [V]. I found no public 8051 corpus (see question 1).

### Option 3. Our own rebuilds with exact paired ground truth, with a seeded layer

- Size. Our choice. A sensible start is dnsmasq, dropbear, busybox and uhttpd built with the OpenWrt SDK for x86_64 and aarch64, plus the Option 2 RTOSes for Cortex-M. About 30 to 60 CVE pairs gives a few hundred images.
- Fetch path. OpenWrt publishes an SDK and ImageBuilder per target, for example `openwrt-sdk-23.05.5-armsr-armv8_gcc-12.3.0_musl...tar.xz` and the x86-64 equivalent [V]. Each package's `patches/` directory is the ground truth. Drop the CVE patch to get the vulnerable build [I]. Compile the whole image in both states.
- Licence. Same as Option 1, and the images are ours.
- Tasks. Everything, including bugs that appear in no public advisory, so a model cannot recall the answer from training data.
- Weak points. Cost to build, and the seeding pitfalls in question 4.

Also worth a spike, not first. UEFI firmware from LVFS is x86-64 PE, 868 components and about 39 GB in the current metadata, 588 of them UEFI capsules [V]. Ground truth is weak (60 distinct CVEs in vendor release notes [V]) and the capsules need unpacking to PE modules before recore can read them [I]. Binarly's FwHunt rules (CC0-1.0) cover AMD, AMI, EDK2, Fujitsu, HP, Insyde, Intel and Lenovo [V] and could supply labels. LVFS limits unauthenticated downloads to 1,000 per IP per day and a full mirror needs a token [V]. Its redistribution terms for firmware are not stated in the docs I read [V].

## 1. Public firmware on recore's architectures

### OpenWrt (x86_64, aarch64)

Release directories seen at `https://downloads.openwrt.org/releases/` [V]: 17.01.1 to 17.01.7, 18.06.0 to 18.06.9, 19.07.0 to 19.07.10, 21.02.0 to 21.02.7, 22.03.0 to 22.03.7, 23.05.0 to 23.05.6, 24.10.0 to 24.10.8 and 25.12.0 to 25.12.5, plus release candidates. The listing does not mark any series end of life. The listing shows 17.01 and 18.06 with only package and faillog directories in places, but I resolved `17.01.7/targets/x86/64/` and `18.06.9/targets/x86/64/` with HTTP 200 [V]. The old releases are therefore still fetchable.

x86/64 in 23.05.5 offers `generic-squashfs-combined(-efi).img.gz` (10.2 to 10.4 MB), `ext4-combined` (11.1 to 11.3 MB), a rootfs image and a kernel `.bin` [V]. armsr/armv8 offers squashfs and ext4 combined and rootfs images, `rootfs.tar.gz`, and two kernel binaries (16 MB and 29.6 MB initramfs) [V]. The sha256sums file for x86/64 also lists `config.buildinfo`, `feeds.buildinfo` (pinned feed commits) and `kernel-debug.tar.zst` [V]. The kernel debug archive is the one place debug info is published. Userland packages are stripped [I].

Package versions per release for x86_64, from the feed listings [V]:

| Release | dnsmasq | dropbear | busybox | uhttpd date | libubox date |
|---|---|---|---|---|---|
| 17.01.7 | 2.78-6 | 2017.75-5 | 1.25.1 | 2018-11-28 | 2018-11-16 |
| 18.06.9 | 2.80-1.4 | 2017.75-7.1 | 1.28.4 | 2020-02-12 | 2018-07-25 |
| 19.07.10 | 2.80-16.3 | 2019.78-2 | 1.30.1 | 2020-10-01 | 2020-05-25 |
| 21.02.7 | 2.85-9 | 2020.81-2 | 1.33.2 | 2021-03-21 | 2021-05-16 |
| 22.03.7 | 2.86-16 | 2022.82-4 | 1.35.0 | 2023-06-25 | 2022-05-15 |
| 23.05.6 | 2.90-2 | 2022.82-6 | 1.36.1 | 2023-06-25 | 2023-05-23 |
| 24.10.8 | 2.93-r1 | 2024.86-r3 | 1.36.1 | 2025-07-06 | 2025-07-23 |

From 21.02 on, dropbear is in the per-target feed (`targets/x86/64/packages/`), not in `packages/x86_64/base/` [V]. Package counts and sizes above leave that feed out. Dropbear patch files for 22.03.7 are visible in the source tree [V].

CVE ranges I checked on NVD [V]. CVE-2020-25681 (DNSpooq heap overflow) affects dnsmasq before 2.83, so 2.80 builds in 18.06 and 19.07 are vulnerable and 2.85 is not. CVE-2023-28450 affects dnsmasq before 2.90, so 2.86 (22.03.7) is in range and 2.90 (23.05.6) is not. Check backports in each release before labelling, as in the CVE-2022-0934 example above.

Other aarch64 targets exist: rockchip/armv8 in 22.03.7 and 23.05.6, sunxi/cortexa53 in both, and mediatek/filogic in 23.05.6 [V]. Most other OpenWrt targets (ath79, ramips, bcm27xx 32-bit and so on) are MIPS or A32 and are out [I].

OpenWrt itself has 67 release tags matched as `vN.N.N` on GitHub [V]. The repo licence field reads NOASSERTION [V], since the tree mixes licences.

### Yocto, Raspberry Pi OS, Debian

- Yocto publishes prebuilt machine images at `downloads.yoctoproject.org/releases/yocto/yocto-<ver>/machines/`. For 4.0.14, `genericx86-64`, `qemux86-64` and `qemu/qemuarm64` exist [V]. Each image has a `.rootfs.manifest` listing package versions and `.sha256sum` files [V], so version ground truth is free. I did not open the manifest contents [I].
- Raspberry Pi OS arm64 images are listed at `downloads.raspberrypi.com/raspios_arm64/images/` (29 entries) and `raspios_lite_arm64` from 2020-08-24 [V]. Hashes appear next to images [I, not opened]. Licences are mixed Debian packages plus Raspberry Pi additions [I].
- Debian is the best-documented source of fixed versions. The Security Tracker JSON is one HTTP 200 file of 83 MB [V]. `snapshot.debian.org` keeps old packages [V]. BinPool already combines them (see question 2).

### Cortex-M and other MCU stacks

- Zephyr: 279 published advisories [V] (29 from 2021, 9 from 2022, 24 from 2023, 20 from 2024, 14 from 2025, 183 from 2026). The 2026 jump looks like a bulk publication, so do not read it as a trend [I]. Per-CVE docs list fix PRs and backports, for example CVE-2026-1678 backported to 4.3, 4.2 and 3.7 [V]. Bluetooth, USB, 802.15.4 and 6LoWPAN, DNS and LwM2M issues are listed in the CVE record [S] (CVE-2020-10061, 10068, 10069, 10021, 10019, CVE-2021-3321, 3322, 3323).
- Fuzzware Zephyr and Contiki-NG samples: CVE-2020-10064, 10065, 10066 and CVE-2021-3319 through 3323, 3329, 3330, plus two non-CVE false-positive samples, for Zephyr. CVE-2020-12140, 12141 and a HALucinator CVE-2019-9183 sample for Contiki-NG [V]. CVE-2020-10065 is marked WONTFIX, so it has no fixed build [V].
- AMNESIA:33. Forescout, 2020-12-08. 13 bugs in uIP, 10 in picoTCP, 5 in FNET, 5 in Nut/Net [S]. Advisory versions: picoTCP 1.7.0 and prior, FNET 4.6.3, Nut/Net 5.1 and prior [S]. Repos: `butok/FNET` Apache-2.0, `tass-belgium/picotcp` and `virtualsquare/picotcp` (licence not detected), `contiki-os/contiki` (not detected) [V].
- FreeRTOS+TCP 2018 (Zimperium). CVE-2018-16528 is fixed in AWS FreeRTOS v1.3.2. CVE-2018-16601 affects FreeRTOS+TCP through 10.0.1 [S]. Source is MIT at `FreeRTOS/FreeRTOS-Plus-TCP` [V]. Old tags and the fix diff are in git [I].
- Others. `RIOT-OS/RIOT` LGPL-2.1, `apache/nuttx` Apache-2.0 with no GitHub advisories (CVEs go through Apache) [V], `ARMmbed/mbed-os` last pushed 2024-10-08 with licence undetected [V], `Mbed-TLS/mbedtls` with licence undetected and no GitHub advisories [V].
- 8051. I did not find or search for a public corpus. A candidate is Contiki 2.x on CC2530 built with SDCC [I, unverified]. Treat 8051 as a gap and build our own from small open projects.
- Vendor SDK samples (STM32Cube, nRF5, MCUXpresso). Not researched. They bundle lwIP, FreeRTOS and mbedTLS at fixed versions [I], which would work for library n-day detection but the licences are vendor-specific and need a read before use.

## 2. Existing benchmarks and datasets

| Name | What it measures | Ground truth | Architectures | Availability | Fit for recore |
|---|---|---|---|---|---|
| Magma | Fuzzer bug finding | Real bugs forward-ported with canaries; 138 bugs in 9 targets per the docs [V], 118 in 7 targets per the paper [S] | Linux userland, likely x86-64 [I] | github.com/HexHive/magma, no SPDX licence detected [V] | Method only, not binaries |
| LAVA, LAVA-M, Rode0day | Fuzzer and analysis tools on injected bugs | Synthetic bugs from dead/unused/available input bytes [V] | x86 Linux [I] | github.com/panda-re/lava, licence NOASSERTION [V] | Cautionary example, see q4 |
| FixReverter / RevBugBench | Fuzzers on realistic injected bugs | Reverted fix patterns; about 8,000 bugs in 10 programs [S] | Linux x86-64 [I] | Artifact on figshare [S] | Method, reusable pattern list |
| CGC | Autonomous bug finding and patching | Challenge authors' PoVs | 32-bit x86 DECREE | not checked | Unlikely to load in recore [I] |
| BinKit | Binary code similarity | Symbol names across 1,352 compile-option sets, 243,128 binaries, 51 GNU packages, 8 architectures [S] | Includes arm, mips, x86 [I]; Thumb and AArch64 not confirmed | github.com/SysSec-KAIST/BinKit, MIT [V] | Partial; not firmware |
| FirmKit | Similarity on firmware | Hand-marked vulnerable function addresses in router and camera firmware from FirmAE and BaseSpec work [V] | arm, mips, x86 32-bit [V] | MIT; ground truth in repo; images not bundled and no release [V] | Mostly MIPS and A32, out |
| FirmAE | Emulation of 1,124 router and camera images | Emulation success (892 of 1,124) [S] | MIPS, ARM mainly [I] | github.com/pr0v3rbs/FirmAE, MIT [V]; I could not confirm the 1,124-image set is downloadable | Out for arch reasons |
| Karonte | Static taint across binaries | 46 zero-days in 53 samples, then 899 samples [S] | Linux router and camera [I] | github.com/ucsb-seclab/karonte, BSD-2 [V]; no firmware directory in repo root listing [V] | Out |
| FirmSec | Third-party component n-days in firmware | 34,136 images (11,086 public, 23,050 private), 584 components, 429 CVEs [S] | Mixed | Private portion not released [S] | Closest task match, data not available |
| Costin et al., USENIX Sec 2014 | Survey of embedded firmware | 32 thousand images, 38 new vulnerabilities [S] | Mixed | Dataset availability unconfirmed [S] | Not usable |
| BinXray, PS3, PatchScout, PDiff | Patch presence in binaries | BinXray: 12 projects and 479 CVEs [S]; PS3 from USENIX Sec 2018 [S] | x86 and ARM [I] | Not checked | Method reference |
| PLocator | 1-day detection via patch location | Patch lines hashed, mapped through addr2line; 73 CVEs, 4 projects, 160 binaries [V] | x86 only [V] | No release link seen [V] | Method reference for labels |
| REACT (ASE 2024) | Patch presence | Beats BinXray and PS3 on speed [S] | Not checked | Not checked | Baseline names |
| CveBinarySheet | Prebuilt vulnerable binaries | 1,033 CVEs, 16 components, O0 and O3 builds [S] | x86-64, i386, MIPS, ARMv7, RISC-V64 [S]; no AArch64 or Thumb | arXiv 2501.08840 [S] | Component list is useful, arch is not |
| BinPool | Vulnerable and patched Debian binaries | Debian Security Tracker plus snapshot, patch applied or withheld with quilt; 603 CVEs, 162 packages, 6,144 binaries (an earlier version said 254 and 2,200) [S] | Not confirmed | arXiv 2504.19055 [S] | Pattern to copy |
| EvoPatch-IoT | Function retrieval in BusyBox | 57 versions (1.11.0 to 1.37.0), 270 unstripped and 285 stripped binaries, 5 architectures including AArch64 and x86_64, 130 source releases [V] | AArch64, ARM, MIPS, MIPSEL, x86_64 [V] | github.com/xxxyyyzzz3984/EvoPatch-IoT resolves [V]; licence not given | Subset (AArch64, x86_64) is usable |
| CyberGym | Agent PoC generation | 1,507 instances from OSS-Fuzz in 188 projects; pass means crash before patch and none after [S] | Source-level, Linux | arXiv 2506.02548 [S] | Scoring template for agents |
| CrackMeBench, CREBench, Veritas, Reveree | LLM agents in reverse engineering | Per-task keys or labels [S] | Not firmware | arXiv [S] | I found no firmware n-day benchmark for agents |

Not researched this session: Asm2Vec, SAFE, jTrans and BinaryCorp. They measure function similarity on mostly x86 and ARM compiles of open source projects [I]. Ghidra BSim sits in the same family.

Honest read. The patch-presence literature mostly uses open source projects compiled on x86, scored against NVD-linked patches. The firmware literature mostly uses MIPS and A32 router images with hand-made labels. Nothing I found combines Cortex-M or AArch64 firmware with agent scoring, so the benchmark would be new in that corner.

## 3. How practitioners work today

- Unpacking. binwalk (MIT, last push 2026-08-11) and unblob (MIT, last push 2026-10-16) [V]. FACT_core and EMBA both use extraction [I].
- EMBA (`e-m-b-a/emba`, GPL-3.0). Bash tool that builds an SBOM and a vulnerability report; the wiki says module S09 does static version detection across all binaries [S]. Run time is long. One 2026 study says scans "often stretch into many hours" and compares a local machine against an Azure VM, with cloud charges of "several hundred dollars" for a small set of images [V]. A practitioner post reports 24 hours or more per image, and one about an hour with a trimmed profile [S].
- FACT (`fkie-cad/FACT_core`, GPL-3.0). Multiprocess web and REST tool. Requires 4 cores and 8 GB at minimum and recommends 16 cores and 64 GB. Exported results can be 2 to 10 times the size of the firmware. The README gives no run times [V].
- cve-bin-tool (`ossf/cve-bin-tool`, GPL-3.0). 451 checkers per the README, over 350 components per another line on the same page [V]. It matches library signatures and version numbers, and says it "cannot tell if someone has backported fixes" [V]. That is exactly the OpenWrt trap above.
- Patch diffing. ghidriff (GPL-3.0) wraps Ghidra's version tracking. Its README example takes about 1,350 s of Ghidra analysis per Windows kernel binary, then about 86 s to diff [V]. BinDiff (Apache-2.0) and Diaphora (AGPL-3.0) are the other standard tools [V for licences].
- Ghidra sweep cost, the numbers I trust. EvoPatch-IoT reports 5.04 hours for 285 stripped BusyBox binaries, with mean export time per binary of 43.5 s (AArch64), 58.6 s (ARM), 82.2 s (MIPS), 84.3 s (MIPSEL) and 50.0 s (x86_64). Binaries are 3.8 to 6.3 MB [V, read in the extracted PDF text]. The REFuSe-Bench paper reports about 24 to 28 minutes of CPU per file for Ghidra's BSim [S, from a page fetch summary]. Another writer reports Ghidra headless at 2 s per sample using 128 cores on small decompilation samples [S]. Ghidra headless has a per-file analysis timeout flag, `-analysisTimeoutPerFile` [S].
- What that means for sizing. A 5,000-binary OpenWrt sweep at 50 s each is about 70 hours of single-core Ghidra [I, arithmetic from the numbers above]. That is the cost recore removes, and it is the number to measure on our own corpus rather than quote.

## 4. Seeding vulnerabilities

- Magma. Each target has `patches/setup/` and `patches/bugs/`; bug patches forward-port a real bug into the newest source and add a canary call that records "reached" and "triggered" [V]. Building with the `fixes` argument disables the bugs [V]. This is real bugs with real fix history, and it is extensible by adding patches [V]. Ground truth is exact because the canary fires.
- LAVA. Injects bugs by finding input bytes that are dead, uncomplicated and available (DUA) and adding a comparison on them [V]. Bundt et al. ran 8 fuzzers on LAVA-M and Rode0day and found no organic CVE bugs, while injected bugs were found [V]. They report that injected bugs sit near the main execution path, and that dictionaries of constants pulled from the binary or comparison splitting solve many of them [V]. A 4-byte magic value compare is the cheap tell [V]. Rode0day updates made bugs harder but still easier than organic ones [V]. Their suggestions are to require attacker data to satisfy more than equality checks, and to place bugs far from commonly executed code [V].
- FixReverter. Reverses fix patterns (conditional-abort, conditional-execute, conditional-assign) wherever static analysis says the pattern matches, injecting nearly 8,000 bugs into 10 programs [S]. The authors argue LAVA and Apocalypse fail a realism test [S]. For us this is closest to "revert the fix commit", but automated.
- Reverting real fixes. Fuzzware already does this for firmware. Its `build_sample_CVE-*.sh` scripts and `patches/` directory check out the vulnerable commit and build it [V]. In OpenWrt the CVE patch file is the switch [V].

Pitfalls for a binary-analysis benchmark, in order of how likely they are to bite:

1. Canaries and logging calls change the binary. Magma's `magma_log` calls would give the agent a free pointer. Build one instrumented binary to validate truth and ship a clean one [I].
2. A one-function diff is too easy. If the only difference between vulnerable and fixed builds is the bug, diffing finds it in seconds. Real patch presence has compiler noise, inlining and layout shifts. Rebuild with the same flags but include cross-version and cross-flag pairs [I].
3. Strings give it away. Version banners, CVE-named strings and symbol names in ELF `.elf` files let an agent grep. Strip, and keep a labelled tier where version strings are scrubbed [I].
4. Public CVEs are in training data. An agent may name the function from memory. Seeded bugs and rebuilt combinations (an old library in a new image) separate recall from analysis [I].
5. Synthetic checks near the entry point or against constants. See the LAVA findings above [V].
6. Version-only labels. OpenWrt and Debian both backport. Always label from the source tree or patch list, not from the version string [V].
7. Build variance. For Zephyr, one commit gives many binaries by board and Kconfig. Fix the configs in the manifest and record toolchain version and flags with the hash [I].

## Source list

OpenWrt and package indexes
- https://downloads.openwrt.org/releases/
- https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/ and `sha256sums`
- https://downloads.openwrt.org/releases/23.05.5/targets/armsr/armv8/
- https://downloads.openwrt.org/releases/23.05.6/packages/x86_64/base/Packages.gz
- https://github.com/openwrt/openwrt (tags v21.02.7, v22.03.7, v23.05.5, package/network/services/dnsmasq/patches)

Cortex-M and RTOS
- https://github.com/fuzzware-fuzzer/fuzzware-experiments (03-fuzzing-new-targets, bug-details/README.md)
- https://github.com/zephyrproject-rtos/zephyr/security/advisories and https://docs.zephyrproject.org/latest/security/vulnerabilities.html
- https://www.tenable.com/blog/amnesia33-researchers-disclose-33-vulnerabilities-tcpip-libraries-uip-fnet-picotcp-nutnet
- https://securityaffairs.com/77294/iot/freertos-flaws.html and https://nvd.nist.gov/vuln/detail/CVE-2018-16601
- https://github.com/FreeRTOS/FreeRTOS-Plus-TCP, https://github.com/contiki-ng/contiki-ng, https://github.com/RIOT-OS/RIOT, https://github.com/apache/nuttx

Other firmware sources
- https://cdn.fwupd.org/downloads/firmware.xml.gz and https://lvfs.readthedocs.io/en/latest/offline.html
- https://github.com/binarly-io/FwHunt
- https://downloads.yoctoproject.org/releases/yocto/ and https://downloads.raspberrypi.com/raspios_arm64/images/
- https://security-tracker.debian.org/tracker/data/json and https://snapshot.debian.org/

Benchmarks and papers
- https://arxiv.org/abs/2009.01120 (Magma) and https://hexhive.epfl.ch/magma/docs/bugs.html, /docs/technical.html
- https://www.usenix.org/conference/usenixsecurity22/presentation/zhang-zenong (FixReverter)
- https://arxiv.org/pdf/2208.11088 (Evaluating Synthetic Bugs)
- https://arxiv.org/pdf/1808.09700 (Evaluating Fuzz Testing)
- https://arxiv.org/pdf/2011.10749 (BinKit) and https://github.com/SysSec-KAIST/FirmKit
- https://github.com/pr0v3rbs/FirmAE and https://acsac.org/2020/program/final/s313.html
- https://seclab.cs.ucsb.edu/publications/redini2020_karonte/ and https://github.com/ucsb-seclab/karonte
- https://arxiv.org/pdf/2212.13716 (FirmSec)
- https://www.s3.eurecom.fr/docs/usenixsec14_costin.pdf
- https://arxiv.org/html/2501.17413v1 (PLocator)
- https://faculty.sist.shanghaitech.edu.cn/faculty/songfu/publications/ISSTA20.pdf (BinXray)
- https://arxiv.org/pdf/2504.19055 (BinPool) and https://arxiv.org/html/2501.08840v1 (CveBinarySheet)
- https://arxiv.org/abs/2604.19496 and https://github.com/xxxyyyzzz3984/EvoPatch-IoT (EvoPatch-IoT)
- https://arxiv.org/html/2410.22677v1 (REFuSe-Bench)
- https://arxiv.org/pdf/2506.02548 (CyberGym), https://arxiv.org/html/2605.10597v1 (CrackMeBench), https://arxiv.org/pdf/2604.03750 (CREBench)

Tools
- https://github.com/e-m-b-a/emba, https://github.com/fkie-cad/FACT_core, https://github.com/ReFirmLabs/binwalk, https://github.com/onekey-sec/unblob
- https://github.com/ossf/cve-bin-tool, https://github.com/clearbluejar/ghidriff, https://github.com/google/bindiff, https://github.com/joxeankoret/diaphora
- https://www.helpnetsecurity.com/2026/01/14/emba-iot-firmware-security/

## Open items

- Confirm which of FirmAE's 1,124 images, Karonte's 899 samples and FirmSec's public 11,086 images can still be fetched. I did not find a pinned URL for any of them, and they are mostly MIPS and A32 anyway.
- Open one Yocto `.rootfs.manifest` and one Raspberry Pi OS hash file to confirm the format.
- Measure recore against Ghidra on 50 OpenWrt aarch64 and x86_64 binaries before quoting any speedup.
- Check whether BinPool and CveBinarySheet publish aarch64 builds. Neither listing says so.
