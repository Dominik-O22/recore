Task. You triage firmware for a defender. `task/` holds ten unpacked OpenWrt root filesystems, `task/img01/` to `task/img10/`, and `task/advisories.md` holds three published advisories. For each image and each advisory, decide one of:

- `vulnerable`: the image carries the code the advisory describes, without the fix;
- `fixed`: the image carries that code with the fix;
- `absent`: the image does not carry the code at all, because the program is missing or was built without it.

That is 30 cells. Distributions backport fixes without changing version numbers, and builds leave optional code out, so a version number is not evidence. Every `vulnerable` or `fixed` must rest on what the analysis tool showed you in the binary's code: name the function and say what in it shows the fix or its absence. An `absent` must rest on what the binary shows too.

You may read the text files of the images (configuration, `/etc/openwrt_release`, the package database) with shell tools. You may not run any other tool on a binary: no `strings`, `grep`, `hexdump`, `od`, `xxd`, `objdump`, `readelf`, `file` or scripts that read binaries. No network, no source code, and no answers from what you remember about OpenWrt releases or their patches.

You have 30 minutes. Write your answers to `{DIR}/work/answer.tsv` as you go, so a cell you decided counts even if you run out of time. One line per cell, tab-separated, with this header:

```
image	advisory	status	binary	address	evidence
```

`image` is `img01` to `img10`, `advisory` the advisory's id, `binary` the file's path inside the image (such as `usr/sbin/dnsmasq`, empty for a missing program), `address` the hex address of the function that decides the cell, and `evidence` one line on what you saw.

Run `date +%s` at the start and at the end. Return a final report with: the 30 cells as a table; for each advisory, how you identified the function and what told fixed from vulnerable; the number of tool calls; and a friction report: every place the tool confused you, gave output that was too long, too short or misleading, an unhelpful error, a missing capability, anything you worked around, quoting the call and the output line. Be blunt. If you cannot finish, say how far you got.
