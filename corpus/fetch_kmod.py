#!/usr/bin/env python3
"""Adds Linux kernel modules to a corpus, from Debian's kernel debug package.

Usage: fetch_kmod.py [corpus]      corpus-kmod by default, or corpus-kmod-holdout, corpus-kmod-arm64
                                   or corpus-kmod-arm64-holdout; the name picks the kernel and the list
Downloads linux-image-<version>-<arch>-dbg (about 1 GB) once, takes the modules below out of it,
and writes <corpus>/debug/kmod__<module>.ko.debug, the module as built, and
<corpus>/bin/kmod__<module>.ko, the same module with `strip --strip-unneeded`, which leaves only
the symbols its relocations and its exports need. Debian ships modules with every symbol, so
the stripped copy asks recore to find the functions it is not told about.
"""
import re, shutil, subprocess, sys
from pathlib import Path

from fetch_debian import MIRROR, SUITE, fetch, index
from store import CORPORA

# Drivers for the hardware a desktop or a laptop plugs in, and a few file systems and network
# devices.
AMD64 = """btusb btintel xhci-hcd ftdi_sio cp210x usbserial usb-storage cdc-acm r8152 cdc_ether usbnet
e1000e igb r8169 tg3 mt7601u hid-logitech-dj hid-multitouch usbhid hid-apple hid-playstation xpad joydev
uinput snd-usb-audio uvcvideo i2c-i801 coretemp it87 sdhci thinkpad_acpi asus-wmi vfat isofs loop zram
iTCO_wdt tun wireguard rfcomm""".split()
# Modules of the same kinds, none of them in AMD64. The held-out corpus scores a change once it
# is done, so nothing is tuned on it.
AMD64_HOLDOUT = """btrtl ehci-hcd pl2303 ch341 uas ax88179_178a cdc_ncm rndis_host e1000 ixgbe atlantic ath9k_htc
hid-sony hid-steam hid-nintendo i2c-hid-acpi evdev snd-hda-intel snd-hda-codec-realtek nct6775-core
rtsx_pci_sdmmc ums-realtek dell-laptop nbd veth""".split()
# The drivers a phone or a board's system on a chip needs, as an Android device's vendor modules
# are, and the USB and file system modules of AMD64 that arm64 builds too.
ARM64 = """btusb btintel xhci-hcd ftdi_sio cp210x usbserial usb-storage cdc-acm r8152 cdc_ether usbnet mt7601u
hid-logitech-dj hid-multitouch usbhid joydev uinput snd-usb-audio uvcvideo vfat isofs loop zram tun wireguard rfcomm
goodix_ts edt-ft5x06 brcmfmac rtw88_core panfrost rockchipdrm dw_mmc-rockchip sdhci-of-arasan dwc3 dwc2 i2c-rk3x
spi-rockchip rockchip_saradc pwm-rockchip snd-soc-rockchip-i2s snd-soc-es8316 snd-soc-rt5640 sun4i-drm sunxi-mmc
bq27xxx_battery venus-core ath10k_core mt7921e meson-gx-mmc""".split()
# Modules of the same kinds, none of them in ARM64.
ARM64_HOLDOUT = """btrtl pl2303 ch341 uas cdc_ncm rndis_host hid-sony evdev nbd veth lima rockchip-rga hantro-vpu
snd-soc-wm8904 mt7663u rtw88_8822bu sdhci-of-dwcmshc ehci-platform sun8i-ce cros_ec_keyb rk805-pwrkey
phy-rockchip-inno-usb2 mxsfb snd-soc-simple-card ath11k rk808-regulator fusb302 tcpm adc-keys pwm_bl""".split()
MODULES = {"amd64": (AMD64, AMD64_HOLDOUT), "arm64": (ARM64, ARM64_HOLDOUT)}


def newest_dbg(packages, arch):
    """The pool path of the newest kernel's debug package for `arch`."""
    found = {}
    for name, path in packages.items():
        m = re.fullmatch(rf"linux-image-(\d+)\.(\d+)\.(\d+)\+deb\d+-{arch}-dbg", name)
        if m:
            found[tuple(map(int, m.groups()))] = path
    return found[max(found)]


def main():
    corpus = CORPORA / (sys.argv[1] if len(sys.argv) > 1 else "corpus-kmod")
    arch = "arm64" if corpus.name.startswith("corpus-kmod-arm64") else "amd64"
    modules = MODULES[arch][corpus.name.endswith("-holdout")]
    pkgs = CORPORA / "corpus-kmod" / "pkgs"
    pkgs.mkdir(parents=True, exist_ok=True)
    deb = fetch("debian", newest_dbg(index(f"{MIRROR}/debian/dists/{SUITE}/main/binary-{arch}/Packages.xz"), arch), pkgs)

    work = pkgs / "x" / corpus.name
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    member = next(m for m in subprocess.run(["ar", "t", deb], capture_output=True, text=True, check=True).stdout.split() if m.startswith("data.tar"))
    archive = subprocess.Popen(["ar", "p", deb, member], stdout=subprocess.PIPE)
    patterns = [f"*/kernel/*/{module}.ko" for module in modules]
    decompress = {".xz": "--xz", ".zst": "--zstd", ".gz": "--gzip"}[Path(member).suffix]
    subprocess.run(["tar", "-x", decompress, "-f", "-", "-C", work, "--wildcards", *patterns], stdin=archive.stdout, check=False, stderr=subprocess.DEVNULL)
    archive.wait()

    for d in ("bin", "debug"):
        (corpus / d).mkdir(parents=True, exist_ok=True)
    found = {path.stem: path for path in work.rglob("*.ko")}
    for module in modules:
        if module not in found:
            print(f"{module:24} not in the package")
            continue
        name = f"kmod__{module}.ko"
        shutil.copyfile(found[module], corpus / "debug" / f"{name}.debug")
        # The host's strip reads only its own architecture; llvm-strip reads any.
        strip = "strip" if arch == "amd64" else "llvm-strip"
        subprocess.run([strip, "--strip-unneeded", found[module], "-o", corpus / "bin" / name], check=True)
    made = list((corpus / "bin").glob("kmod__*"))
    print(f"total: {len(made)} modules, {sum(f.stat().st_size for f in made) / 1e6:.0f} MB stripped")


if __name__ == "__main__":
    main()
