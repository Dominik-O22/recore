# Answer key

One point per item. An item passes when the report states it, and a report that asserts something this key calls false fails the item that covers it. Addresses are as the binaries load, without relocation.

## Task A: git.exe

- **A1.** The function that prints the build options is at `0x1401b4b60`.
- **A2.** `--build-options` is handled by `cmd_version` at `0x1401b6920`, which builds the option table and passes it to the generic parser at `0x140219b00`. Either address passes.
- **A3.** The printer's lines, in order, with these values: `cpu: x86_64`, `built from commit: cc4dbf752a05efdc0e04e71fd3e8110d11bdd35c`, `sizeof-long: 4`, `sizeof-size_t: 8`, `shell-path: D:/git-sdk-64-build-installers/usr/bin/sh`, `rust: disabled`, `feature: fsmonitor--daemon`, `gettext: enabled`, `libcurl: 8.22.0`, `OpenSSL: OpenSSL 3.5.9 29 Sep 2026`, `zlib: 1.3.2`, `SHA-1: SHA1_DC`, `SHA-256: SHA256_BLK`, `default-ref-format: files`, `default-hash: sha1`. `git version 2.56.0.windows.2` before them, from the caller, does not count against it, and neither does leaving out `no commit associated with this build`, which the binary cannot print: its commit string is never empty.
- **A4.** `feature: fsmonitor--daemon` is always printed: the function at `0x1401a7a80` that decides it returns 1.

## Task B: python313.dll

- **B1.** `chr()` is the function at `0x18009aac0`.
- **B2.** It is identified through the method table: the record at `0x180553070` holds the name "chr", the function, flags 8 and the docstring.
- **B3.** The largest argument accepted is `0x10ffff` (1114111).
- **B4.** The error text is `chr() arg not in range(0x110000)`.
- **B5.** The exception is `ValueError`.

## Task C: libexpat 2.5.0-1 and 2.5.0-1+deb12u1

Debian's changelog for the update names three fixes. CVE-2024-45490: `XML_ParseBuffer` did not reject a negative length. CVE-2024-45491 and CVE-2024-45492: integer overflow checks in `dtdCopy` and `nextScaffoldPart`, which upstream compiles only where `UINT_MAX >= SIZE_MAX`, so this 64-bit build has no code for them. Their source lines remain, and they move the line numbers after them.

- **C1.** The security fix: `XML_ParseBuffer` (`0x88f0` before, `0x8780` after) now rejects a negative `len` with error `0x29` (`XML_ERROR_INVALID_ARGUMENT`). `XML_Parse` already rejected it.
- **C2.** What goes wrong without it: the end of the data moves before its start, so the parser reads out of bounds. Inference from the code is enough.
- **C3.** The salt's source changed: before, `getrandom`, then `/dev/urandom`, then time of day XOR pid; after, `arc4random_buf` only. It is not ranked above C1 as the fix. Hardening is a fair reading; it is not in the changelog, and is most likely the build finding `arc4random_buf` in a newer C library, which the report need not know.
- **C4.** The salt code and the namespace setup of `XML_Parse` and `XML_ParseBuffer` moved into a new helper at `0x6440`, with no change in behaviour.
- **C5.** The 17 functions that differ only in numbers differ in the source line numbers passed to `__assert_fail` and to accounting helpers. Saying why the lines moved is not needed.
- **C6.** No other change is real. A report that names one fails this item: the "widening" of the tokenizer's arithmetic, for one, is Ghidra decoding the earlier build wrongly.
- **C7.** The 8 bytes at `0x398` are the hash salt, the secret that seeds the hashing of names for the parser's tables (a SipHash key, which the report need not name).
- **C8.** What sets it, before: parser init `0x51f0` stores 0, `XML_SetHashSalt` `0x88a0` stores the caller's value, `XML_ExternalEntityParserCreate` `0x7a90` copies the parent's, and `XML_ParseBuffer` `0x88f0` and `XML_Parse` `0x8e20` store a random value when it is 0. After: `0x51a0`, `0x8730`, `0x7920`, and the helper `0x6440`. Every writer is needed. Naming them all in one of the two builds is enough.
