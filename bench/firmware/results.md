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

## Pilot: fleet triage with Haiku

Ten images, three architectures, three advisories, 30 cells: `bench/firmware/pilot/`. The advisories were picked for one pitfall each:

- **CVE-2023-48795 (Terrapin, dropbear).** A string decides it: the fix adds `kex-strict-s-v00@openssh.com`. dropbear 2022.82 is fixed in two of the images and vulnerable in three.
- **CVE-2022-0934 (dnsmasq, DHCPv6).** Stock images leave the code out: dnsmasq's compile options in the binary say `no-DHCPv6`. Four images ship `dnsmasq-full`, two of them with the backport.
- **CVE-2026-5172 (dnsmasq, `extract_addresses`).** Only the code decides it, one comparison after `extract_name`, and 24.10.7 and 25.12.4 carry it as a backport on 2.90 and 2.91.

A version scanner misjudges 7 of the 30 cells (the "traps"). Two Haiku 5.5 sessions ran per arm. The Ghidra arm had every image's dnsmasq and dropbear analyzed before the session; the recore arm analyzed on demand. `score.py` gives a cell 1 for the right status with evidence that holds (the right binary, an address in its code) and half for the right status without it.

| Run | Points | Right status | F1 of vulnerable | Traps | Terrapin | CVE-2022-0934 | CVE-2026-5172 | Session | Analysis first | Cost |
|---|---|---|---|---|---|---|---|---|---|---|
| version scanner | 18 | 18 | 0.81 | 0 of 7 | 8 | 2 | 8 | | | |
| everything vulnerable | 15 | 15 | 0.67 | 0 of 7 | 5 | 2 | 8 | | | |
| recore 1 | 10 | 10 | 0.50 | 2 | 10 | 0 | 0 | 323 s | none | $0.14 |
| recore 2 | 10 | 10 | 0.50 | 2 | 10 | 0 | 0 | 375 s | none | $0.26 |
| Ghidra 1 | 2.5 | 5 | 0.48 | 0 | 2.5 | 0 | 0 | 225 s | 445 s | $0.22 |
| Ghidra 2 | 7 | 12 | 0.50 | 2.5 | 6 | 0 | 1 | 438 s | 385 s | $0.61 |

What it shows:

- **Headroom, plenty.** The best session scores 10 of 30, below the 18 a version scanner gets. No session got a CVE-2022-0934 cell, though the binary's own compile-options string settles the 6 where the code is left out. Nobody decided CVE-2026-5172 from code: the recore sessions left it undecided, and Ghidra's second session called all ten fixed, so two came out right by chance.
- **The string cell is easy, as the design expected.** Both recore sessions and Ghidra's second got all ten Terrapin statuses right from the strict-KEX strings. Results without such cells are the ones to watch.
- **The tools separate on evidence and cost, not yet on the hard cells.** recore's sessions cited an address in the right binary for every cell they decided. Ghidra's cited `unknown` or an address outside the code for most, and took 6.4 to 7.4 minutes of analysis before starting. Haiku with either tool stopped after 4 to 7 minutes of a 30-minute budget, so the cells that need code reading never got a real attempt. Two sessions per arm is an illustration, not a result.
- **Calibration.** Every session wrote its own word for an undecided cell (`undecided`, `unresolved`, `undetermined`). The prompt should say that an undecided cell scores as wrong, as the design's scoring does, and the next pilot should run a stronger model than Haiku.

### Audit of the sessions

`audit.py` lists shell tools run on binaries, paths outside the session's folder and any mention of the labels, and every non-recore command of the recore sessions was read by hand as well.

- Neither recore session broke a rule. Their `grep` and `sed` ran over the package database and over decompiled C they had saved.
- Ghidra's second session read a file outside its folder: Claude Code had saved an oversized `decompile_function` result under `~/.claude/projects/.../tool-results/`, and the agent parsed it with `python3`. That file is its own tool's output, not the labels or the answers, but it breaks the folder rule. Ghidra's first session saw the same file path and left it alone.
- No session read the labels, the corpora directory or the repository, ran `strings` or another binary tool, or used the network.

### What the sessions found about recore

- **ARM references.** `xrefs` and `strings` miss references that the disassembly shows (`add r1, pc, r1 ; 0x...`): 342 of the first 400 strings of 23.05.6's armv7 dnsmasq say `used by: none`. Not caused by the missing sections: the armhf corpus gives the same counts with and without them (377 of 744 for `less`).
- **Truncated decompile.** On armv7 dropbear, `decompile --functions 0xa6a8` printed four lines and `...` with no reason given.
- **`used by` names a table's user.** `kex-strict-s-v00@openssh.com` is "used by" dropbear's `main`, which reaches it only through a table.
