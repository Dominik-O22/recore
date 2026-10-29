You are testing a reverse engineering tool by using it as its intended user would: an AI agent with a shell.

Your folder is `{DIR}/`. Do not list or read anything outside it.

The tool is the binary `{DIR}/bin/recore-mcp`. Run `recore-mcp --help` first, and `recore-mcp <tool> --help` for one tool. It is the ONLY analysis tool you may use on the targets: no objdump, gdb, strings, readelf, ghidra, radare, python disassemblers, no source code, no network, and no answering from memory of any open source project: every claim must come from what the tool showed you. You may use python only for arithmetic.

Before every recore-mcp call, set `RECORE_EDITS_DIR={DIR}/edits` in the environment.

Target, in `task/`:

Task D. `GameAssembly.so` (Linux x86-64, 80 MB) is the code of a Unity game built with IL2CPP. `Game_Data/` beside it is the game's data directory, as the game ships it. Report, with the address of each function you name:
- The player character's class keeps the direction the player faces in a one-byte field. Which method writes it, and which value it stores for each direction.
- How the mouse turns the view: what scales the mouse input, and the limits of the camera's pitch.
- What turning flying on or off does to noclip, and what turning noclip on or off does to flying.
- When the game puts the player in flight and noclip without any input from the player, and what else it does then.
- How the scroll wheel changes the flying speed, and by how much a step, unless something changes it.
- The game routes each light modification that crosses into another chunk one of several ways. Find the function that decides, and say what it returns for each combination of its inputs.
Rank your confidence in each claim and say what evidence it rests on.

Run `date +%s.%N` at the start and end of the task. Return a final report with:
1. The answer, and the exact sequence of tool commands you ran in order (every one, dead ends included) with a one-line note each.
2. Seconds the task took and the number of tool calls.
3. Friction report: every place the tool confused you, gave output that was too long, too short or misleading, an unhelpful error, a missing capability, anything you worked around. Quote the command and the output line. Also what worked well, and one sentence on whether using the tool was pleasant and what single change would improve it most. Be blunt.

If you cannot finish the task, say so plainly and report how far you got. Do not write code files.