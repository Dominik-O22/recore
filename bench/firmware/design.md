# Firmware benchmark: design draft

Date: 2026-10-17. Inputs: research.md (same folder), the agent eval in bench/agent.

## What it has to show

The current agent eval is saturated: Haiku scores 17 of 17 with recore, so it can no longer tell a better tool from a worse one. The firmware benchmark should:

- measure work defenders do on firmware, where Ghidra is the default tool;
- be big enough that analysis time counts (a fleet, not one binary), so recore's speed shows up in the result and not only in a side table;
- have checkable ground truth that a model cannot recall from training data or read off a version string;
- leave headroom, so a strong model with the best tool still does not score full marks.

## Corpus: real images, with binaries we built swapped in

Real OpenWrt release images for x86_64 and aarch64 (17.01 to 25.12, fetched by URL and sha256, never redistributed), plus variants of them in which some binaries are replaced by ones we build with the OpenWrt SDK of that release:

- **patch dropped**: the package's CVE patch removed, version string unchanged, so the image claims a fixed version and is vulnerable;
- **patch added**: a backport applied to an old version, so the version says vulnerable and the code is fixed (OpenWrt itself does this: dnsmasq 2.85 in 21.02.7 carries the CVE-2022-0934 fix);
- **untouched**: the release as shipped, labelled from the release's source tree, not the version.

Every label is exact because we built the binary or read the patch list of the release tag. Unpacking (squashfs, ext4) happens in the fetch script with unblob, so the agent gets a rootfs directory per image. Packages to start with: dnsmasq, dropbear, busybox, uhttpd, hostapd/wpad, libubox, odhcpd: the network-facing daemons with CVE history.

When 32-bit ARM (PR #17) and MIPS land, the same packages come from the armsr/armv7 and ath79/ramips images and the task sets carry over.

Cortex-M: the Zephyr and Contiki-NG CVE samples from fuzzware-experiments (15, with ELF truth), and our own builds of the fix commit and its parent. Fewer images, used for the depth tier.

## Three task tiers

### A. Fleet triage (the core; speed matters)

The agent gets 40 to 60 unpacked images and 5 to 8 advisories (CVE text as published, no fix commit), and fills a matrix: for each image and advisory, vulnerable, fixed or not present, with the binary and function as evidence. Scored per cell (precision and recall of "vulnerable"), plus time, tokens and cost. Version strings are traps in a known share of cells (patch dropped, patch added), so answering from versions scores at a fixed, published level that