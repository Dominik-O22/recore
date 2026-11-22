You are testing a reverse engineering tool by using it as its intended user would: an AI agent with a shell.

Your folder is `{DIR}/`. Do not list or read anything outside it.

The tool is the binary `{DIR}/bin/recore-mcp`. Run `recore-mcp --help` first, and `recore-mcp <tool> --help` for one tool. It is the ONLY analysis tool you may use on the targets: no objdump, gdb, strings, readelf, ghidra, radare, python disassemblers, no source code, no network, and no answering from memory of the Linux source: every claim must come from what the tool showed you. You may use python only for arithmetic.

Before every recore-mcp call, set `RECORE_EDITS_DIR={DIR}/edits` in the environment.

The targets in `task/` are from Android phone kernels, GKI builds for arm64:
- `Image` is an Android phone's Linux kernel as a boot partition holds it: the raw image, with no ELF header and no section table.
- `gzvm.ko`, `zram.ko` and `rfkill.ko` are three modules of another Android kernel, stripped of every symbol they can do without.

Addresses are as recore shows them.

Task A. `gzvm.ko` drives a hypervisor. Find the ioctl handler of the character device it registers. Which commands does it handle, and what does it do with the argument of each? What does it return for a command it does not handle, and for the extension query with an argument of 0? One command makes a VM, which is a file of its own: list the commands that file's ioctl handler handles.

Task B. In `gzvm.ko`, follow the VM's command 0x40209246, which sets up a region of guest memory. How many bytes does it read from the caller, and which field limits what? What must hold for it to go on, and what does it return when it does not? Where does the guest physical address the caller gave end up: at which offset of the driver's record of the VM, and in what the driver hands the hypervisor (the call number, the register, and the offset in any buffer)?

Task C. `zram.ko` is a compressed RAM disk. Which block device operations table does it register, and which function fills each slot it sets (give the slot's offset)? Which function creates a device, how many bytes does it allocate for the device's record, what does it check, and what does it return when the disk cannot be allocated? What compression algorithm does a new device get?

Task D. A program opens `rfkill.ko`'s character device and calls write() with a 100-byte buffer. How many bytes does the driver read from it, and what does write() return? What does write() return for a 5-byte buffer? What sets the limit, can the program change it, and to which values? What must the bytes it reads hold for the write to succeed?

Task E. In `Image`, find binder's ioctl handler. What does BINDER_SET_MAX_THREADS (0x40046205) do with its argument: how many bytes does it read, at which offset of the process's record does it store the value, what does it hold while it stores it, and what does it check about the value? What does the handler return when it cannot get the calling thread's record?

Task F. In `Image`, which function does arm64 system call 434 reach, and through which table entry (its address)? What does that function check, in the order the code checks it, and what does it return for each failed check? Which functions call `binder_proc_dec_tmpref` directly?

Rank your confidence in each claim and say what evidence it rests on.

Run `date +%s.%N` at the start and end of each task. Return a final report with:
1. Per task: the answer, and the exact sequence of tool commands you ran in order (every one, dead ends included) with a one-line note each.
2. Seconds each task took and the number of tool calls per task.
3. Friction report: every place the tool confused you, gave output that was too long, too short or misleading, an unhelpful error, a missing capability, anything you worked around. Quote the command and the output line. Also what worked well, and one sentence on whether using the tool was pleasant and what single change would improve it most. Be blunt.

If you cannot finish a task, say so plainly and report how far you got. Do not write code files.
