# Security

recore reads binaries that may be hostile. The analysis runs in the `recore-mcp` process and the decompiler in a child process, so a crash, a hang or memory corruption on a crafted file is a bug worth reporting, and one that runs code of the file's choosing is a vulnerability.

Report a vulnerability privately through [GitHub's advisory form](https://github.com/Dominik-O22/recore/security/advisories/new), with the file or the steps that trigger it. Crashes and hangs that are not exploitable can go in a public issue.

Fixes go into the latest release only.
