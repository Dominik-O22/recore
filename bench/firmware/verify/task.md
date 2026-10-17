Task. You check a version scanner's findings for a defender. `task/` holds ten unpacked OpenWrt root filesystems, `task/img01/` to `task/img10/`, and `task/advisories.md` holds three published advisories. A version scanner matched each image's package versions against the advisories and wrote `task/claims.tsv`: for each image and advisory, `affected` or `not affected`, with the program and version it read.

Versions mislead. Distributions backport fixes without changing version numbers, builds leave optional code out, and an image can ship a program other than the one its package database names. Some claims are wrong in each direction. Your job is to check the claims against the code of the binaries and to refute the wrong ones.

Write your verdicts to `{DIR}/work/verdicts.tsv` as you go, so a verdict counts even if you run out of time. One line per claim you checked, tab-separated, with this header:

```
image	advisory	verdict	status	binary	address	evidence
```

- `verdict` is `confirm` or `refute`.
- `status` is what the code shows: `vulnerable` (the code the advisory describes, without the fix), `fixed` (that code with the fix) or `absent` (the program is missing, or was built without that code). `vulnerable` means affected; `fixed` and `absent` mean not affected.
- `binary` is the file's path inside the image, such as `usr/sbin/dnsmasq`, and `address` the hex address of the function that decides the claim. For `absent`, name the binary and say in `evidence` what in it shows the code is missing.
- `evidence` is one line on what you saw.

How it is scored: a claim you do not check stands as the scanner made it. A refutation counts only with evidence that holds, the right binary and an address in its code, and otherwise the claim stands. A refutation of a claim that was right makes it wrong. So refute what the code shows is wrong, and only that.

You may read the text files of the images (configuration, `/etc/openwrt_release`, the package database) with shell tools. You may not run any other tool on a binary: no `strings`, `grep`, `hexdump`, `od`, `xxd`, `objdump`, `readelf`, `file` or scripts that read binaries. No network, no source code, and no answers from what you remember about OpenWrt releases or their patches.

You have 30 minutes. Run `date +%s` at the start and at the end. Return a final report with: your verdicts as a table; for each advisory, how you identified the function and what told fixed from vulnerable; the number of tool calls; and a friction report: every place the tool confused you, gave output that was too long, too short or misleading, an unhelpful error, a missing capability, anything you worked around, quoting the call and the output line. Be blunt.
