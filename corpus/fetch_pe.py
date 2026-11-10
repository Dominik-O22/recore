#!/usr/bin/env python3
"""Fetches the Windows corpora: released PE binaries whose projects publish matching PDBs.

Usage: fetch_pe.py [corpus-pe | corpus-pe32 | corpus-pe-holdout | corpus-pe32-holdout]...
                                                            default: all four

corpus-pe holds PE32+ (x86-64) images and corpus-pe32 holds PE32 (i386) images, each as
<corpus>/bin/<source>__<file> with its PDB at <corpus>/debug/<source>__<file>.pdb. Every archive
is pinned by URL and sha256 and cached in <corpus>/pkgs. A binary is paired with its PDB by the
GUID both carry (the image's CodeView record and the PDB's info stream), never by file name, so
a pair that made it into the corpus is known to belong together.

The two -holdout corpora hold projects none of the others has, and score a change once it is
done, so nothing is tuned on them. Some of their PDBs come from a symbol server, by the name and
GUID their image names, and Mozilla's serves them as .pd_ cabinets.

MSI packages (python.org ships its PDBs that way), installers (cached as .7z) and .pd_ cabinets
are unpacked with 7-Zip, run through mise. Nothing downloaded is executed. corpus/build_pe.py adds programs compiled here with llvm-mingw.
"""
import hashlib, shutil, struct, subprocess, sys, urllib.request, zipfile
from dataclasses import dataclass, field
from pathlib import Path

from store import CORPORA

SEVENZIP = ["mise", "x", "7zip@26.04", "--", "7zz"]
MACHINE = {"corpus-pe": 0x8664, "corpus-pe32": 0x14C}
PYTHON = "https://www.python.org/ftp/python/3.13.7"
PHP = "https://windows.php.net/downloads/releases/archives"
GITHUB = "https://github.com"
OBS = f"{GITHUB}/obsproject/obs-studio/releases/download/32.2.2"
OPENSSH = f"{GITHUB}/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview"
X64DBG = f"{GITHUB}/x64dbg/x64dbg/releases/download/2026.05.27"
GIT = f"{GITHUB}/git-for-windows/git/releases/download"
FIREFOX = "https://archive.mozilla.org/pub/firefox/releases/140.5.0esr"
DOTNET = "https://api.nuget.org/v3-flatcontainer"
WIRESHARK = "https://www.wireshark.org/download"
MOZILLA_SYMBOLS = "https://symbols.mozilla.org"
MICROSOFT_SYMBOLS = "https://msdl.microsoft.com/download/symbols"


@dataclass
class Source:
    """One project release: archives holding binaries and PDBs, and which binaries to keep."""
    # (url, sha256) or (url, sha256, cache file name) where the URL's own name is ambiguous.
    archives: list[tuple]
    # The binaries to keep, by file name or by a longer path suffix where the name alone is ambiguous.
    keep: list[str] = field(default_factory=list)


def symbols(server, pdbs, packed=False):
    """Archives for PDBs on a symbol server, each given as (PDB name, GUID and age, sha256)."""
    return [(f"{server}/{name}/{key}/{name[:-1] + '_' if packed else name}", sha256) for name, key, sha256 in pdbs]


FIREFOX_KEEP = ["firefox.exe", "mozglue.dll", "nss3.dll", "freebl3.dll", "softokn3.dll", "lgpllibs.dll", "mozavutil.dll",
                "mozavcodec.dll", "gkcodecs.dll", "libGLESv2.dll", "plugin-container.exe", "updater.exe",
                "crashhelper.exe", "maintenanceservice.exe"]
DOTNET_KEEP = ["coreclr.dll", "clrjit.dll", "clrgc.dll", "hostfxr.dll", "hostpolicy.dll", "mscordbi.dll",
               "mscordaccore.dll", "msquic.dll", "System.IO.Compression.Native.dll"]
WIRESHARK_KEEP = ["tshark.exe", "dumpcap.exe", "sharkd.exe", "libwiretap.dll", "libwsutil.dll", "editcap.exe",
                  "capinfos.exe", "rawshark.exe", "glib-2.0-0.dll", "libxml2.dll"]


SOURCES = {
    "corpus-pe": {
        # MSVC 19.4x (VS 2022), C, profile-guided: hot/cold splitting, chained unwind info.
        "py": Source(
            [(f"{PYTHON}/python-3.13.7-embed-amd64.zip", "f6cca216a359be84797cabb54149ce5e062afb16cc7567eb7fc51cacb2d86b65"),
             (f"{PYTHON}/amd64/core_pdb.msi", "4d84413e6cb29a642c3f849ccba91076e39a2fc47e1c00e13794ed071f66b993"),
             (f"{PYTHON}/amd64/exe_pdb.msi", "91669a2fcb2563198e8361d4942c88283830445a422f75168a648c5942adfc86"),
             (f"{PYTHON}/amd64/lib_pdb.msi", "6d36d7b4e3f6b3bd769a509496100deed16160570b7525544ed9f35b529447ca")],
            ["python313.dll", "python.exe", "libcrypto-3.dll", "libssl-3.dll", "unicodedata.pyd", "_decimal.pyd",
             "pyexpat.pyd", "_ssl.pyd", "_lzma.pyd", "_elementtree.pyd", "_ctypes.pyd", "_sqlite3.pyd", "_socket.pyd",
             "_bz2.pyd"]),
        # MSVC 19.00 (VS 2015), C++ (V8, ICU) and OpenSSL assembly, static C runtime.
        "node4": Source(
            [("https://nodejs.org/dist/v4.9.1/win-x64/node.exe",
              "cf303c36126b9bbfa2efd77e68d80a7cead2fe2604400b39c4901195e1614579", "node-v4.9.1-x64.exe"),
             ("https://nodejs.org/dist/v4.9.1/win-x64/node_pdb.zip",
              "62982c0bc42b15d56c4cf2c58919fea6aa51a68c8707020d0ee45c5ed9a8854b", "node-v4.9.1-x64_pdb.zip")],
            ["node-v4.9.1-x64.exe"]),
        # MSVC 19.29 (VS 2019), C, control-flow guard.
        "php83": Source(
            [(f"{PHP}/php-8.3.14-Win32-vs16-x64.zip", "3cd79691564c3634aec79f721773bf9308f8f4698904ca7ca27281ec099480d6"),
             (f"{PHP}/php-debug-pack-8.3.14-Win32-vs16-x64.zip",
              "43b013ac40ded6b45026918191f0480355bd13d8765b6815f1d152863318436e")],
            ["php8ts.dll", "php.exe", "php-cgi.exe", "phpdbg.exe", "php8phpdbg.dll", "icuuc72.dll", "php_opcache.dll",
             "php_curl.dll", "php_intl.dll", "php_tidy.dll", "php_snmp.dll", "php_soap.dll", "php_ldap.dll",
             "php_gmp.dll", "php_fileinfo.dll", "libssh2.dll", "libsodium.dll", "nghttp2.dll", "libpq.dll",
             "libsasl.dll"]),
        # MSVC 19.4x (VS 2022), C and C++.
        "obs": Source(
            [(f"{OBS}/OBS-Studio-32.2.2-Windows-x64.zip", "4d6e40e3ab155f56b30de517380566a206d74b63cdf5ad49aa596924768f97e1"),
             (f"{OBS}/OBS-Studio-32.2.2-Windows-x64-PDBs.zip",
              "a2d2c16859ea3c2508f49c2b9a48b8ec630578334d301fbdf42718f6e473662a")],
            ["obs.dll", "obs64.exe", "obslua.dll", "obs-websocket.dll", "obs-browser.dll", "frontend-tools.dll",
             "libobs-d3d11.dll", "libobs-opengl.dll", "obs-ffmpeg.dll", "win-dshow.dll", "graphics-hook64.dll",
             "obs-virtualcam-module64.dll", "w32-pthreads.dll", "obs-ffmpeg-mux.exe"]),
        # MSVC 19.4x (VS 2022), C, with LibreSSL's libcrypto.
        "openssh": Source(
            [(f"{OPENSSH}/OpenSSH-Win64.zip", "23f50f3458c4c5d0b12217c6a5ddfde0137210a30fa870e98b29827f7b43aba5"),
             (f"{OPENSSH}/OpenSSH-Win64_Symbols.zip", "b39df505ac56b52f38a9109eb6dfc6b3adb5309d661441cc3cd0b90dd19fdc57")],
            ["ssh.exe", "sshd.exe", "sshd-session.exe", "sftp.exe", "ssh-keygen.exe", "ssh-agent.exe",
             "ssh-shellhost.exe", "libcrypto.dll"]),
        # GCC (MSYS2 UCRT64), C. The PDBs are converted from DWARF by cv2pdb: procedures with
        # lengths, but no "never returns" flags and no thunk records.
        "git": Source(
            [(f"{GIT}/v2.56.0.windows.2/MinGit-2.56.0.2-64-bit.zip",
              "da35e72aa21c005a5a0d298cfbae110bc1609a815730ea0dde84b01a1b3cd3be"),
             (f"{GIT}/v2.56.0.windows.2/pdbs-for-git-ucrt64-2.56.0.2-1.zip",
              "3e78910b6a2f7da26e0d61bcb285ae1c54e1ded245944758501869e1ec9aec69")],
            ["ucrt64/bin/git.exe", "git-remote-https.exe", "git-http-fetch.exe", "libcurl-4.dll"]),
    },
    "corpus-pe32": {
        "py": Source(
            [(f"{PYTHON}/python-3.13.7-embed-win32.zip", "19248889d63e1599bc6ae132a40a737d9143e4917d79156e157418f5efc50019"),
             (f"{PYTHON}/win32/core_pdb.msi", "95c71d89d114c2511abaf1b3ea25d2499740a3649ef323f3591dd67ab3b5461f"),
             (f"{PYTHON}/win32/exe_pdb.msi", "336ebf1813f57d324d1a2778de6e80ee13231217e8fa165ea34f7c418f49b9cf"),
             (f"{PYTHON}/win32/lib_pdb.msi", "9ec48c543f35a4879da373091108c910f36b7798a11000c84d7f83c53c6dc649")],
            ["python313.dll", "python.exe", "libcrypto-3.dll", "libssl-3.dll", "unicodedata.pyd", "_decimal.pyd",
             "pyexpat.pyd", "_ssl.pyd", "_lzma.pyd", "_elementtree.pyd", "_ctypes.pyd", "_sqlite3.pyd", "_socket.pyd",
             "_bz2.pyd"]),
        "node4": Source(
            [("https://nodejs.org/dist/v4.9.1/win-x86/node.exe",
              "26675281b58986a1577cf303d4f86a12f9d9772473b178322ba70d11a65dff5a", "node-v4.9.1-x86.exe"),
             ("https://nodejs.org/dist/v4.9.1/win-x86/node_pdb.zip",
              "8f259d638d8d77736cca9e241bdacc8f83aa99961893934c85c3ee43406cb61d", "node-v4.9.1-x86_pdb.zip")],
            ["node-v4.9.1-x86.exe"]),
        # MSVC 18.00 (VS 2013).
        "node012": Source(
            [("https://nodejs.org/dist/v0.12.18/node.exe",
              "e16b22197bb3e0716cf0bd994c1dde9046be0e0813e8214eb8cde9c709b8df0c", "node-v0.12.18-x86.exe"),
             ("https://nodejs.org/dist/v0.12.18/node.pdb",
              "0f430bc1d311b8dc328ce1c1d1c715eb75275152a904582ac9574a6681ea229e", "node-v0.12.18-x86.pdb")],
            ["node-v0.12.18-x86.exe"]),
        "php83": Source(
            [(f"{PHP}/php-8.3.14-Win32-vs16-x86.zip", "b78c3334b611e0a2a9cfe19bc5ec1f582b12ecc9318708ecadb640907ddc3f63"),
             (f"{PHP}/php-debug-pack-8.3.14-Win32-vs16-x86.zip",
              "d158092068614cb1087b30f927b778d4beeb0cf9d143db5233abac8bcb85ff9d")],
            ["php8ts.dll", "php.exe", "php-cgi.exe", "phpdbg.exe", "icuuc72.dll", "php_opcache.dll", "php_curl.dll",
             "php_intl.dll", "php_tidy.dll", "php_soap.dll", "php_ldap.dll", "php_fileinfo.dll", "libssh2.dll",
             "libsodium.dll", "nghttp2.dll", "libpq.dll"]),
        # MSVC 19.1x (VS 2017), non-thread-safe build.
        "php74": Source(
            [(f"{PHP}/php-7.4.33-nts-Win32-vc15-x86.zip", "3719efc430c3b82cf809ff1b4bb7d720e388f793b1e1857e4d892c62fa950b68"),
             (f"{PHP}/php-debug-pack-7.4.33-nts-Win32-vc15-x86.zip",
              "ba5b7833916dc21fa61e0eae8fae6a396c631b3c9249920e554905821442b37d")],
            ["php7.dll", "php.exe", "icuuc66.dll", "php_opcache.dll", "php_curl.dll", "php_tidy.dll", "php_soap.dll",
             "libssh2.dll"]),
        # The 32-bit helpers ship inside the x64 release.
        "obs": Source(
            [(f"{OBS}/OBS-Studio-32.2.2-Windows-x64.zip", "4d6e40e3ab155f56b30de517380566a206d74b63cdf5ad49aa596924768f97e1"),
             (f"{OBS}/OBS-Studio-32.2.2-Windows-x64-PDBs.zip",
              "a2d2c16859ea3c2508f49c2b9a48b8ec630578334d301fbdf42718f6e473662a")],
            ["graphics-hook32.dll", "obs-virtualcam-module32.dll", "inject-helper32.exe",
             "get-graphics-offsets32.exe"]),
        "openssh": Source(
            [(f"{OPENSSH}/OpenSSH-Win32.zip", "c61d7fea20ddfe0fc50eb56210a66464557721120f7794ff9cc883b5ba526abd"),
             (f"{OPENSSH}/OpenSSH-Win32_Symbols.zip", "ebfa41d87071cd4df0d0d97f0e493d42331673f4bd65518bbc8b9c54fc9bad64")],
            ["ssh.exe", "sshd.exe", "sshd-session.exe", "sftp.exe", "ssh-keygen.exe", "ssh-agent.exe",
             "ssh-shellhost.exe", "libcrypto.dll"]),
        # The last Git for Windows release with a 32-bit build. GCC (MSYS2 MINGW32), via cv2pdb.
        "git": Source(
            [(f"{GIT}/v2.48.1.windows.1/MinGit-2.48.1-32-bit.zip",
              "6a8c7acd63e2f0e7c901082c287ac3f0f94ebd1598cc02440979f411cb7de81a"),
             (f"{GIT}/v2.48.1.windows.1/pdbs-for-git-32-bit-2.48.1.1.2bd190bcd2-1.zip",
              "47f26cc01e9f6f04ca4c9ba49809a8f4aa645e292d099feb2f193f15adbcd4a8")],
            ["mingw32/bin/git.exe", "git-remote-https.exe", "git-http-fetch.exe"]),
    },
    # clang-cl, C++ and C with Rust linked in. The installer is a 7-Zip archive.
    "corpus-pe-holdout": {
        "firefox": Source(
            [(f"{FIREFOX}/win64/en-US/Firefox%20Setup%20140.5.0esr.exe",
              "e24385749a6b2fccb2157722d94a9235cc141da7e43d947c01844eb530a9e01d", "firefox-140.5.0esr-win64.7z"),
             *symbols(MOZILLA_SYMBOLS, [
                 ("firefox.pdb", "0D5729EA62924F954C4C44205044422E1", "0dda7b4e6d58f394cd12c4462e2be8a5faba8baa57858067ab39147a172ab827"),
                 ("mozglue.pdb", "F51B0E089F14D8A74C4C44205044422E1", "3f644650e145c3aa0060c709be67ab8cb3d47602230cb6971b3b065d34b9aec1"),
                 ("nss3.pdb", "65B82AA7BBC04F7D4C4C44205044422E1", "a2a11ad755a06e4961c6a149b4a237857963c98fa7bca99649898360766ba689"),
                 ("freebl3.pdb", "467C07D78DB6DE834C4C44205044422E1", "ed472422535ead66331578615ebec08daeed9320f0c2f01948a2ad11dba89b26"),
                 ("softokn3.pdb", "F0F4E6AEC5D95FC44C4C44205044422E1", "bab9527fc1a532490a1316e5a0cb9889f3572da8a7c5cabcfac651a836d8ca5c"),
                 ("lgpllibs.pdb", "3A138185FAFBB1E74C4C44205044422E1", "dedbe67faa9e91fd040dfe7d389d0c194196278620d80d6187445bae31640402"),
                 ("mozavutil.pdb", "EAAFF1E4B75E83704C4C44205044422E1", "0815e0d5cd36b92e34b28c8923ceeb0dcc201c1816cfcb3ec6efe791ab1c18dd"),
                 ("mozavcodec.pdb", "4FF2D448F1598B724C4C44205044422E1", "262780ffd80bb031b75fe3d9f9e58f8d467644de688d7c2a5b2fe72ed5c4fa68"),
                 ("gkcodecs.pdb", "BEA87BB7872E82014C4C44205044422E1", "985b4da054eaf07442672b196fd1ff9d6df15b9b386c55f384761e969a78e251"),
                 ("libGLESv2.pdb", "92459B8198E2C4E94C4C44205044422E1", "092995d82931fc307fe9aa6c907889eee289d2af03f4b8a1d27dc085096d7276"),
                 ("plugin-container.pdb", "C69B44A271C24B9C4C4C44205044422E1", "f900b7616f5f0b058630d1289755250067dc6045e9b39a85a1a51ec01dc1eaef"),
                 ("updater.pdb", "67FEF2A760DAF7144C4C44205044422E1", "723e24836c9c3509def5bc3ccafd9788aa2aa74bc170d20217559ce0291ed82c"),
                 ("crashhelper.pdb", "E31D4D657F395BA24C4C44205044422E1", "026c9aacec698576211e036380df411655147adab09d0e02d65bf42d64a4839b"),
                 ("maintenanceservice.pdb", "544EC4A7A3A12A184C4C44205044422E1", "50cd8085d14995a90388127710e3d08ba876756a17c0b8971b5d7310300398c4"),
             ], packed=True)],
            FIREFOX_KEEP),
        # MSVC, C++: the .NET runtime's native part, from its NuGet runtime pack.
        "dotnet": Source(
            [(f"{DOTNET}/microsoft.netcore.app.runtime.win-x64/9.0.11/microsoft.netcore.app.runtime.win-x64.9.0.11.nupkg",
              "32862c1b409bc570f94d62a4e87b65ed2bff28c889d07f47c2c8f2197719126e", "microsoft.netcore.app.runtime.win-x64.9.0.11.zip"),
             *symbols(MICROSOFT_SYMBOLS, [
                 ("coreclr.pdb", "9A11BC2D917E4FDD9A0F60908232B7141", "8db470292ee8ef7f1e6af517b033a27dd761535958075a73b6885986c2d221f1"),
                 ("clrjit.pdb", "13040EFF9B4A4C9D83CAE3707EA582A71", "badc4b0d831c500c91b04e9f14e7d0a19f20502b11fef16de47f7ea1ba40a39e"),
                 ("clrgc.pdb", "07D567E33DC246ABAED9E8F63DB3B7D21", "dde1177d6b362a5e7e91821a3020e55f5720294bbfddae981b78a40032376c49"),
                 ("hostfxr.pdb", "D9714B9BF0CF4E57881CC90B7D52B7201", "969c823f1cfe1adc7967c041407eac449f7acb9d7b7f8f7f9e83f11c8ec11c1f"),
                 ("hostpolicy.pdb", "179CC3A4A57B4DB18FE83373D60301F51", "42c22ad3deadc45905e7d2040678a01c18e592f8039469f59566ead8095810bc"),
                 ("mscordbi.pdb", "AFA178C72A454C8AB1CDF99905105E881", "4f5988eb36740d636f7db37033b59678d6dcfb3c1680330be7ffbf35de168342"),
                 ("mscordaccore.pdb", "39C389895F764F6C9578103DF9A8513A1", "6668b609d90db4cacc627e46ec30c066a6f9915298058bc90fe239dc2d2aa64f"),
                 ("msquic.pdb", "01E07A25093646F493F93B2140E3018E1", "bfb7f102fe4348759aab859d1d972b412fda8c0a95eb9e6748a2137594048ba7"),
                 ("System.IO.Compression.Native.pdb", "D5FB8C1E93F04DA389A7A31C6DD502621",
                  "2fe95a2299014e71351dc0dac40c8d25deb27bae9906cf5821f9182f42479565"),
             ])],
            DOTNET_KEEP),
        # MSVC, C, with Qt and libraries vcpkg builds. The installer is NSIS, which 7-Zip unpacks.
        "wireshark": Source(
            [(f"{WIRESHARK}/win64/all-versions/Wireshark-4.6.9-x64.exe",
              "bf9b5ce8a89f244c376a9b1a946276eaa06463dde3e33069a34d7f102f5878cf", "Wireshark-4.6.9-x64.7z"),
             (f"{WIRESHARK}/win64/all-versions/Wireshark-pdb-4.6.9-x64.zip",
              "91d6e7df23115364a004c8fbe64d122d296468f65db4eab667cdb61cb4a5c1f4")],
            WIRESHARK_KEEP),
    },
    "corpus-pe32-holdout": {
        "firefox": Source(
            [(f"{FIREFOX}/win32/en-US/Firefox%20Setup%20140.5.0esr.exe",
              "25c13854ca75bddb349745c3ecf15aaa7cb75ebaae575491ecf1c6b932178ab3", "firefox-140.5.0esr-win32.7z"),
             *symbols(MOZILLA_SYMBOLS, [
                 ("firefox.pdb", "1B1DA80E1A1A439E4C4C44205044422E1", "26ed6c7afcafd24d8f620cb6a40571973044fdc5b1fa72d8e5f8ac55e6acb2f5"),
                 ("mozglue.pdb", "1590F520C4C9A6504C4C44205044422E1", "b1355ba02619649c28682e6843d9ca374eff6cbc60cff3cb09f48ae538fcec15"),
                 ("nss3.pdb", "3C058BAE37DB3A424C4C44205044422E1", "dfc9c21b5540e944d027a8085ef12918c6916c6b9da315d4b38482dd025378cc"),
                 ("freebl3.pdb", "FE01031852BC520A4C4C44205044422E1", "2d9aac6e53e80077cc6cba0a7ffb516b8058788c71962be3bd538d7f88845469"),
                 ("softokn3.pdb", "1BFA620101018C124C4C44205044422E1", "fb11777b922168b3452500c8fc5c6c08d6b5521a9e364b72a7296b8025b547d6"),
                 ("lgpllibs.pdb", "0DF6E0CEAAFBC2804C4C44205044422E1", "095941b9d9ccd73d6f896587c2280da0d3da3d3ff6262cc30ef77ae3c7f345f1"),
                 ("mozavutil.pdb", "DF4F20C447D761D24C4C44205044422E1", "ba7bf20f667bc9ead7896fc27df3b2da6153ffe66cd59c91d50f2107e69d97ea"),
                 ("mozavcodec.pdb", "BA9310D30C970B5B4C4C44205044422E1", "585fd3c20bf02a9df6ff6d14e7b5b8fcfafa96a7c71832b231081bc2f9f14768"),
                 ("gkcodecs.pdb", "DAEB7A65495AE8904C4C44205044422E1", "18d94b77f79c8b04b576bfd85da4ed476de021e20e209c5af6e70ffe84cb8e59"),
                 ("libGLESv2.pdb", "B1725CC2BE14F7694C4C44205044422E1", "89aef7c95dd341175449724b0158b904233fda2b606ba5e6feb9cbb2533d1e64"),
                 ("plugin-container.pdb", "F23FFC234A72B1EF4C4C44205044422E1", "8f0364b20b1e955a65ae32f607404bd4724d85bdbede542cb59d182a09684b99"),
                 ("updater.pdb", "414141DDCFDEAB0A4C4C44205044422E1", "565fb0219ad73b51ea2b924ccc7e75a4a0278e51408b740593b86b6645d53c3b"),
                 ("crashhelper.pdb", "0D110E83CCF9E57B4C4C44205044422E1", "259f05bcf583c2d9a3a218579e9c989582eea808e2a8e0137db963efa32fb7d5"),
                 ("maintenanceservice.pdb", "C811A9F9E824AA8A4C4C44205044422E1", "0efcce227b7272613783c638746cb6116b97f08bd43c645252bca708d25b7dfc"),
             ], packed=True)],
            FIREFOX_KEEP),
        "dotnet": Source(
            [(f"{DOTNET}/microsoft.netcore.app.runtime.win-x86/9.0.11/microsoft.netcore.app.runtime.win-x86.9.0.11.nupkg",
              "362975bbcb7f85f14d14cc936ca9eedcd1e785f6228799a78db16854e2c9031a", "microsoft.netcore.app.runtime.win-x86.9.0.11.zip"),
             *symbols(MICROSOFT_SYMBOLS, [
                 ("coreclr.pdb", "388C00448FD04196BE397E3FD703C1C61", "8cfad970919cd3123d69e433a87b93c2201eb365ab591f6aee87eceea93a73e0"),
                 ("clrjit.pdb", "4F9F5F252B134F769D3642352BD01F681", "9d7f27dad70d36f476b54652216054304151493448c0f47228941880b2059478"),
                 ("clrgc.pdb", "F4708884610C45D0B6181282DC01F7F91", "2fcbd5405169d709398244dcac7e22b589e1fb32aa00e68c4801164fcf65ecc4"),
                 ("hostfxr.pdb", "FDB257BFD46740178630254B2D800BE11", "07cf1dacddd9d5a8f96e9cd57b6ea2827ff418433458d780f95c82b910a6bcc0"),
                 ("hostpolicy.pdb", "0CBB0B021935439998CE725FAB1BEB731", "28a3c020d19e8d6169d8f220a83bea7dd726a7a866abb97cc17f875055b766d1"),
                 ("mscordbi.pdb", "24AB7D71F9584E828DF2DFBF7B877AEC1", "b7ca4702565406fe398242c9eac735553079b12559a6a40cde0b72f9ddb5f56c"),
                 ("mscordaccore.pdb", "06710B1380FD407B8F130BAE4D7070131", "7fb5733c551a14083441c5ab6894f79e8c81037bbf836590656deee4411631a6"),
                 ("msquic.pdb", "485B3F8711984DE1A4FBBBAE48EE49A21", "ed1f1f3fc579dd4e2ddc99f38a9ecc063f436efee75cb60e0e4f967e19533a35"),
                 ("System.IO.Compression.Native.pdb", "932BFE09DCA3463FB430B81651BFFD601",
                  "f9778f085b555d1718190d2699c4fa0dc3e42044a54fe67cb6050c7a5b88c792"),
             ])],
            DOTNET_KEEP),
        # Wireshark 3.6 is the last release with a 32-bit build.
        "wireshark": Source(
            [(f"{WIRESHARK}/win32/all-versions/Wireshark-win32-3.6.24.exe",
              "38a62949d38f96457633982c8b1ec465587e01a9370807ab2e67c8504cff679a", "Wireshark-win32-3.6.24.7z"),
             (f"{WIRESHARK}/win32/all-versions/Wireshark-pdb-win32-3.6.24.zip",
              "a5c32fea12dd35d50006a9a5126c2a2ad21bfde5749c133554a05162187eea53")],
            WIRESHARK_KEEP),
    },
}


def download(pkgs, url, sha256, name=None):
    """Fetches one archive into the cache and checks it against its pinned hash."""
    dest = pkgs / (name or url.rsplit("/", 1)[1])
    if not dest.exists():
        tmp = dest.with_name(dest.name + ".part")
        urllib.request.urlretrieve(url, tmp)
        tmp.rename(dest)
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    if digest != sha256:
        raise RuntimeError(f"{dest.name}: sha256 {digest}, expected {sha256}")
    return dest


def unpack(archive):
    """Returns the files of an archive, extracting it next to the cache. A bare file is itself."""
    if archive.suffix not in (".zip", ".msi", ".7z", ".pd_"):
        return [archive]
    dest = archive.parent / "x" / archive.name
    if not dest.exists():
        tmp = dest.with_name(dest.name + ".part")
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as z:
                z.extractall(tmp)
        else:
            subprocess.run([*SEVENZIP, "x", "-y", f"-o{tmp}", archive], check=True, stdout=subprocess.DEVNULL)
        tmp.rename(dest)
    return sorted(p for p in dest.rglob("*") if p.is_file())


def image_identity(path):
    """(machine, PDB GUID) of a PE image, or None if it is not one or names no PDB."""
    data = path.read_bytes()
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return None
    machine, sections = struct.unpack_from("<HH", data, pe + 4)
    optional = pe + 24
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    plus = struct.unpack_from("<H", data, optional)[0] == 0x20B
    debug_rva, debug_size = struct.unpack_from("<II", data, optional + (112 if plus else 96) + 6 * 8)

    def offset(rva):
        for i in range(sections):
            _, va, raw_size, raw = struct.unpack_from("<IIII", data, optional + optional_size + 40 * i + 8)
            if va <= rva < va + raw_size:
                return raw + rva - va
        return None

    directory = offset(debug_rva)
    for entry in range(directory or 0, (directory or 0) + debug_size, 28):
        kind, _, _, raw = struct.unpack_from("<IIII", data, entry + 12)
        if kind == 2 and data[raw:raw + 4] == b"RSDS":
            return machine, data[raw + 4:raw + 20]
    return None


def pdb_guid(path):
    """The GUID in a PDB's info stream (stream 1 of the MSF container)."""
    with open(path, "rb") as f:
        header = f.read(56)
        if not header.startswith(b"Microsoft C/C++ MSF 7.00\r\n"):
            return None
        block, _, _, directory_size, _, map_block = struct.unpack_from("<IIIIII", header, 32)

        def read(blocks, size):
            out = b""
            for index in blocks:
                f.seek(index * block)
                out += f.read(block)
            return out[:size]

        count = -(-directory_size // block)
        f.seek(map_block * block)
        directory = read(struct.unpack(f"<{count}I", f.read(4 * count)), directory_size)
        streams = struct.unpack_from("<I", directory)[0]
        sizes = struct.unpack_from(f"<{streams}I", directory, 4)
        blocks_of = lambda size: 0 if size == 0xFFFFFFFF else -(-size // block)
        first = 4 + 4 * streams + 4 * blocks_of(sizes[0])
        info = read(struct.unpack_from(f"<{blocks_of(sizes[1])}I", directory, first), sizes[1])
        return info[12:28]


def fetch(corpus_name):
    corpus = CORPORA / corpus_name
    pkgs = corpus / "pkgs"
    for d in (pkgs, corpus / "bin", corpus / "debug"):
        d.mkdir(parents=True, exist_ok=True)
    total = 0
    for prefix, source in SOURCES[corpus_name].items():
        files = [f for archive in source.archives for f in unpack(download(pkgs, *archive))]
        pdbs = {guid: f for f in files if f.suffix == ".pdb" and (guid := pdb_guid(f))}
        kept = []
        for f in files:
            wanted = next((k for k in source.keep if f"/{f.as_posix()}".endswith(f"/{k}")), None)
            if not wanted or wanted in kept:
                continue
            identity = image_identity(f)
            if not identity or identity[0] != MACHINE[corpus_name.removesuffix("-holdout")]:
                continue
            if identity[1] not in pdbs:
                print(f"{prefix:8} {f.name}: no PDB with its GUID, skipped")
                continue
            name = f"{prefix}__{f.name}"
            shutil.copyfile(f, corpus / "bin" / name)
            shutil.copyfile(pdbs[identity[1]], corpus / "debug" / f"{name}.pdb")
            kept.append(wanted)
        missing = sorted(set(source.keep) - set(kept))
        print(f"{prefix:8} {len(kept)} binaries" + (f", missing {' '.join(missing)}" if missing else ""))
        total += len(kept)
    print(f"{corpus_name}: {total} binaries")


if __name__ == "__main__":
    for name in sys.argv[1:] or list(SOURCES):
        fetch(name)
