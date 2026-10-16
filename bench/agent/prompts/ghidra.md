You are testing a reverse engineering tool by using it as its intended user would: an AI agent with a shell.

Your folder is `{DIR}/`. Do not list or read anything outside it, except the Ghidra installation named below. Put every file you create under `{DIR}/work/`, never under /tmp.

The tool is Ghidra 12.1.4. It is already running as an MCP server (pyghidra-mcp), and its tools are available to you as `mcp__ghidra__*`. All four targets are imported into its project and fully analyzed. Use those tools first. If they cannot do something you need, you may also script Ghidra yourself: it is installed at `{GHIDRA}` (`support/analyzeHeadless`, `support/pyghidraRun`), Java 25 is installed, and the MCP server's project is locked while it runs, so a script needs its own project under `work/`. Run at most one Ghidra process of your own at a time; the machine is short on memory.

For comparing two builds, `ghidriff` is installed: headless Ghidra's diff engine, which writes a Markdown report of the functions added, deleted and modified (`ghidriff <old> <new> -o work/<dir> -p work/<dir>`; see `ghidriff --help`). Its default engine crashes on the builds of Task C; `--engine SimpleDiff` works.

Ghidra is the ONLY analysis tool you may use on the targets: no objdump, gdb, strings, readelf, radare, recore, python disassemblers or parsers, no source code, no network, and no answering from memory of any open source project: every claim must come from what Ghidra showed you. You may use python only for arithmetic.

Targets, in `task/`:

Task A. `git.exe` (Windows x86-64, 4 MB). `git version --build-options` prints several facts about how git was built. Find the function that prints them. Report its address, the address of the function that parses the `--build-options` option, and every line the printing function can print, in order, with the value each prints where the binary fixes it.

Task B. `python313.dll` (Windows x86-64, 6 MB). Find the function that implements the builtin `chr()`. Report its address, how you identified it, the largest argument it accepts, the exact error text for an argument out of range, and which exception type it raises if you can establish it.

Task C. `libx-before.so` and `libx-after.so` (Linux x86-64) are a library before and after a security update. Report:
- which functions really changed and what each change does, in plain words;
- which change or changes are the security fix, what input they now reject or handle differently, and what could go wrong without them;
- which reported differences are not real changes in behaviour, and why;
- what the 8-byte value at offset 0x398 of the main object is for, and every function that sets it.
Rank your confidence in each claim and say what evidence it rests on.

Run `date +%s.%N` at the start and end of each task. Return a final report with:
1. Per task: the answer, and the exact sequence of tool calls you made in order (every one, dead ends included) with a one-line note each.
2. Seconds each task took, the number of tool calls per task (MCP calls and Ghidra script runs counted separately), and how many script files you wrote.
3. Friction report: every place the tool confused you, gave output that was too long, too short or misleading, an unhelpful error, a missing capability, anything you worked around. Quote the call and the output line. Also what worked well, and one sentence on whether using the tool was pleasant and what single change would improve it most. Be blunt.

If you cannot finish a task, say so plainly and report how far you got.
