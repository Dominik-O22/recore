You are testing a reverse engineering tool by using it as its intended user would: an AI agent with a shell.

Your folder is `{DIR}/`. Do not list or read anything outside it. Put every file you create under `{DIR}/work/`, never under /tmp.

The tool is the binary `{DIR}/bin/recore-mcp`. Run `recore-mcp --help` first, and `recore-mcp <tool> --help` for one tool. It is the only analysis tool you may use on the binaries. Before every recore-mcp call, set `RECORE_EDITS_DIR={DIR}/edits` in the environment.

