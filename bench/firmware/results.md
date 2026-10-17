# Firmware benchmark: first measurements

Date: 2026-10-17. Machine: 16 cores, 30 GB, other sessions running at low load (load average 1.3 to 2.3 when idle). recore at this branch, Ghidra 12.1.4 headless.

## recore on the fleet

OpenWrt runs `sstrip` on every program it ships, which deletes the section header table. recore read code, symbols and relocations only through sections, so it found no functions in any OpenWrt binary. The loader now rebuilds the section headers from the program headers and the dynamic table when a file has none (`crates/core/src/sectionless.rs`).

To check the rebuild against truth, `corpus/sectionless.py` copies a corpus with only its section headers deleted. recore scores the copies as it scores the originals:

| Corpus | Recall | Precision | Jump tables exact |
|---|---|---|---|
| Linux x86-64, with sections / without | 100.0% / 100.0% | 100.0% / 100.0% | 535 / 535 of 535 |
| Linux AArch64 | 100.0% / 100.0% | 99.9% / 99.9% | |
| armhf | 99.1% / 99.1% | 99.7% / 99.7% | 5,090 / 5,090 of 5,158 |
| armel | 99.0% / 99.0% | 99.6% / 99.6% | 5,252 / 5,252 of 5,323 |

Calls that never return drop from 100% to 99.8% on armhf and from 99.9% to 99.8% on armel.

`bench/firmware/check_recore.py` runs `recore summary` on every distinct ELF file in the 197 images: 3,228 programs and libraries and 5,624 kernel modules. Every program and library loads, with no error or timeout, and has functions. Their analysis takes 8.5 s in all on one core. The kernel modules load with no functions: recore does not read relocatable objects.

Without truth for OpenWrt itself, Ghidra's functions are the cross-check. On the 81 binaries of the timing below, leaving out Ghidra's thunks and one-byte external placeholders, recore finds 94.8% of Ghidra's functions on aarch64, 95.2% on armv7 and 83.2% on x86_64, and Ghidra finds 92.7%, 86.4% and 88.3% of recore's. Most of the x86_64 gap is one binary, below.

Findings:

- **Retpoline import calls.** OpenWrt 19.07 built x86_64 with Spectre v2 thunks, so each import call goes to a local stub, `push [slot]; jmp __x86_indirect_thunk`. recore takes the stubs for parts of their callers: in 19.07.10's dropbear it sees 3 imports of 152 and 376 functions where Ghidra has about 2,250, most of them the stubs. The dropbear of every 19.07 x86_64 image carries the thunks, and 18.06 and 21.02 do not. Not fixed here.
- **Kernel modules.** recore loads `.ko` files and finds nothing in them.
- **musl's libc.so** places `.fini` in the middle of its code. The first version of the rebuild ended `.text` there and found 225 of the library's 1,822 functions. Fixed: code now runs to the end of the last exported function as well.

## recore against Ghidra on 81 OpenWrt binaries

Nine programs and libraries (dnsmasq, dropbear, busybox, uhttpd, odhcpd, netifd, procd, musl's libc.so and libubox) from 19.07.10, 22.03.7 and 24.10.8 on each architecture, chosen by `bench/firmware/pick.py`. Ghidra ran twice through `ghidra/run-reference.sh`, two jobs at a time with 4 cores each, as the README's numbers did. recore is `recore-mcp summary` as a new process, the median of 5 runs pinned to one core and of 5 with all cores, alternated. `bench/firmware/speed.py` prints the table.

| | Binaries | Ghidra analysis, run 1 / run 2 | Ghidra wall, run 1 / run 2 | recore, one core | recore, all cores | Overall | Median binary |
|---|---|---|---|---|---|---|---|
| aarch64 | 27 | 157 s / 160 s | 254 s / 255 s | 0.58 s | 0.27 s | 269x | 312x |
| armv7 | 27 | 200 s / 204 s | 288 s / 297 s | 0.75 s | 0.26 s | 266x | 265x |
| x86_64 | 27 | 130 s / 134 s | 219 s / 227 s | 0.56 s | 0.19 s | 232x | 214x |
| all | 81 | 487 s / 498 s | 761 s / 779 s | 1.90 s | 0.72 s | 257x | 265x |

The ratios compare Ghidra's reported analysis time, without JVM start, import or export, with recore's whole process on one core.

- **Repeatable.** No binary's Ghidra analysis time differs by more than 1 s between the two runs, and recore found functions in all 810 of its runs.
- **What limits each side.** Ghidra reports whole seconds, and a small binary takes it 2 to 16 s, so a single binary's ratio is coarse. The sums are not. JVM start, import and export add 3.4 s a binary to Ghidra's wall time. recore's time is its analysis: `--help` takes 1 ms, and busybox analyzes in 51 ms of a 54 ms run.
- **Why 257x and not the README's 1,000x and more.** These binaries are small, 37 KB to 590 KB, and Ghidra spends most of its time on large ones with many jump tables: the README's corpus averages 61 s a binary, this one 6 s. The research's 43 to 84 s a binary was for BusyBox builds of 3.8 to 6.3 MB.
- **The fleet.** At 9.4 s of wall time a binary, Ghidra needs about 15 minutes for one image's 85 to 96 programs and libraries, and about 8.4 hours for the 3,228 distinct ones of all 197 images, on one 4-core job (inferred from the per-binary average). The research's 70 hours for 5,000 binaries becomes about 13 hours. recore analyzed the 3,228 in 8.5 s on one core (measured).

## Part 1: checking a version scanner's claims

`bench/firmware/verify/`. Ten images over three architectures and three advisories, 30 claims. The agent gets the scanner's claim for each image and advisory, `affected` or `not affected` from the package version, and checks it against the binary. A claim it does not check stands. A refutation counts only with evidence that holds, the advisory's binary and an address in its code. The advisories each test one way a version misleads:

- **CVE-2023-48795 (Terrapin, dropbear).** A string decides it: the fix adds `kex-strict-s-v00@openssh.com`. dropbear 2022.82 is fixed in two images and vulnerable in three.
- **CVE-2022-0934 (dnsmasq, DHCPv6).** Stock images leave the code out, and dnsmasq's compile options in the binary say `no-DHCPv6`. Four images ship `dnsmasq-full`, two of them with the backport.
- **CVE-2026-5172 (dnsmasq, `extract_addresses`).** Only the code decides it: one comparison after `extract_name`, backported in 24.10.7 and 25.12.4.

Two images are stale variants (`corpus/fetch_openwrt.py`), so 2 of the scanner's 9 wrong claims say `not affected` for a vulnerable binary. The other 7 say `affected` for code that is fixed or absent. Ghidra's arm had the images' dnsmasq and dropbear analyzed before the session, and recore's analyzed on demand.

| Session | Right after checking | Wrong claims caught | Right claims broken | Claims checked | Session | Analysis first | Cost |
|---|---|---|---|---|---|---|---|
| version scanner alone | 21 of 30 | 0 of 9 | 0 of 21 | | | | |
| Haiku 5.5, recore, 1 | 27 | 6 | 0 | 18 | 388 s | none | $0.32 |
| Haiku 5.5, recore, 2 | 24 | 3 | 0 | 10 | 349 s | none | $0.21 |
| Haiku 5.5, Ghidra, 1 | 22 | 1 | 0 | 7 | 302 s | 390 s | $0.44 |
| Haiku 5.5, Ghidra, 2 | 24 | 3 | 0 | 10 | 671 s | 385 s | $0.42 |
| Sonnet 5.5, recore | 26 | 6 | 1 | 26 | 483 s | none | $1.95 |
| Sonnet 5.5, Ghidra | 28 | 7 | 0 | 26 | 291 s | 380 s | $2.01 |

What it shows:

- **Every session adds to the scanner, and none saturates it.** The best, Sonnet with Ghidra, ends at 28 of 30. Across all six, only one right claim was broken.
- **The cells only code decides get solved.** Haiku with recore refuted both CVE-2026-5172 backports and the stale dnsmasq in its first session, and Sonnet with Ghidra did the same. Sonnet with recore broke the one right claim, refuting img01's 5172 claim on code it misread.
- **No session caught the two `dnsmasq-full` backports of CVE-2022-0934.** That is the headroom cell: it needs the agent to find the DHCPv6 code and tell the patched copy from the unpatched one.
- **No clear winner between the tools yet.** With Haiku, recore's sessions caught 6 and 3, Ghidra's 1 and 3. With Sonnet, Ghidra's caught 7 and recore's 6. One or two sessions per cell is an illustration. recore's sessions started at once, while Ghidra's waited about 6.5 minutes for its analysis.
- **Framing mattered more than the tool.** In the first pilot, below, the same Haiku with the same tools ended below the scanner, because it had to fill the matrix from nothing and abstained. Handed the scanner's claims, it checked them.

### A scorer bug that cost Ghidra points

Ghidra loads a position-independent program at 0x100000 on 64-bit and 0x10000 on 32-bit ARM, so its addresses are the file's plus that base: Sonnet's `0x131850` is recore's `0x31850`. The first scorer accepted only the file's own addresses and rejected four of Sonnet with Ghidra's right refutations, which made it look like the weakest session. Both scorers now accept either convention. Every number in this file is from the fixed scorer.

### The first pilot: filling the matrix from nothing

Before part 1, the same ten images (with 24.10.6-armv7 and 23.05.2-aarch64 where the stale variants are now) were given to Haiku with no claims: decide every cell. Its prompt and scorer are in the history of `bench/firmware/pilot/`.

| Session | Points of 30 | Right status | Cost |
|---|---|---|---|
| version scanner | 18 | 18 | |
| Haiku, recore, 1 and 2 | 10 and 10 | 10 and 10 | $0.14 and $0.26 |
| Haiku, Ghidra, 1 and 2 | 2.5 and 11 | 5 and 12 | $0.22 and $0.61 |

Every session stopped after 4 to 7 minutes of a 30-minute budget and left most dnsmasq cells undecided. The second Ghidra session called all ten CVE-2026-5172 cells fixed, so two came out right by chance.

### Audit of the sessions

`bench/firmware/audit.py` lists shell tools run on binaries, paths outside the session's folder, the network and any mention of the labels, over every tool call's arguments. Every flag was then read by hand.

- **Part 1.** No session broke a rule. The flags are `grep` and `awk` over the agents' own saved output, Python that writes the verdicts file, and Ghidra's second Haiku session running `analyzeHeadless` from the installation the prompt names. The prompts now tell agents not to read the files Claude Code saves an oversized answer to; Sonnet with Ghidra saw such a path and did not read it.
- **First pilot.** Ghidra's second session read an oversized `decompile_function` result that Claude Code had saved outside its folder. That is its own tool's output, not the labels, but it broke the folder rule.
- No session read the labels, the corpora directory or the repository, ran `strings` or another binary tool, or used the network.

### What the sessions found about recore

- **ARM references.** `xrefs` and `strings` miss references that the disassembly shows (`add r1, pc, r1 ; 0x...`): 342 of the first 400 strings of 23.05.6's armv7 dnsmasq say `used by: none`. Not caused by the missing sections: the armhf corpus gives the same counts with and without them (377 of 744 for `less`).
- **Truncated decompile.** On armv7 dropbear, `decompile --functions 0xa6a8` printed four lines and `...` with no reason given.
- **`used by` names a table's user.** `kex-strict-s-v00@openssh.com` is "used by" dropbear's `main`, which reaches it only through a table.
