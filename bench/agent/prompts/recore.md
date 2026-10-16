You are testing a reverse engineering tool by using it as its intended user would: an AI agent with a shell.

Your folder is `{DIR}/`. Do not list or read anything outside it.

The tool is the binary `{DIR}/bin/recore-mcp`. Run `recore-mcp --help` first, and `recore-mcp <tool> --help` for one tool. It is the ONLY analysis tool you may use on the targets: no objdump, gdb, strings, readelf, ghidra, radare, python disassemblers, no source code, no network, and no answering from memory of any open source project: every claim must come from what the tool showed you. You may use python only for arithmetic.

Before every recore-mcp call, set `RECORE_EDITS_DIR={DIR}/edits` in the environment.

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
1. Per task: the answer, and the exact sequence of tool commands you ran in order (every one, dead ends included) with a one-line note each.
2. Seconds each task took and the number of tool calls per task.
3. Friction report: every place the tool confused you, gave output that was too long, too short or misleading, an unhelpful error, a missing capability, anything you worked around. Quote the command and the output line. Also what worked well, and one sentence on whether using the tool was pleasant and what single change would improve it most. Be blunt.

If you cannot finish a task, say so plainly and report how far you got. Do not write code files.