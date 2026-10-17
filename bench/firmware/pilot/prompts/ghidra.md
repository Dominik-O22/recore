You are testing a reverse engineering tool by using it as its intended user would: an AI agent with a shell.

Your folder is `{DIR}/`. Do not list or read anything outside it, except the Ghidra installation named below. Put every file you create under `{DIR}/work/`, never under /tmp.

The tool is Ghidra 12.1.4. It is already running as an MCP server (pyghidra-mcp), and its tools are available to you as `mcp__ghidra__*`. The `dnsmasq` and `dropbear` of every image are imported into its project and fully analyzed, named after their image, such as `img01-dnsmasq` for `task/img01/usr/sbin/dnsmasq`. `mcp__ghidra__import_binary` imports another file if you need one. If the MCP tools cannot do something you need, you may also script Ghidra yourself: it is installed at `{GHIDRA}` (`support/analyzeHeadless`, `support/pyghidraRun`), Java 25 is installed, and the MCP server's project is locked while it runs, so a script needs its own project under `work/`. Run at most one Ghidra process of your own at a time; the machine is short on memory. Ghidra is the only analysis tool you may use on the binaries.

