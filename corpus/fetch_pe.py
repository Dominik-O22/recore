#!/usr/bin/env python3
"""Fetches the Windows corpora: released PE binaries whose projects publish matching PDBs.

Usage: fetch_pe.py [corpus-pe | corpus-pe32]...      default: both

corpus-pe holds PE32+ (x86-64) images and corpus-pe32 holds PE32 (i386) images, each as
<corpus>/bin/<source>__<file> with its PDB at <corpus>/debug/<source>__<file>.pdb. Every archive
is pinned by URL and sha256 and cached in <corpus>/pkgs. A binary is paired with its PDB by the
GUID both carry (the image's CodeView record and the PDB's info stream), never by file name, so
a pair that made it into the corpus is known to belong together.

MSI packages (python.org ships its PDBs that way) are unpacked with 7-Zip, run through mise.
Nothing downloaded is executed. corpus/build_pe.py adds programs compiled here with llvm-mingw.
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


@dataclass
class Source:
    """One project release: archives holding binaries and PDBs, and which binaries to keep."""
    # (url, sha256) or (url, sha256, cache file name) where the URL's own name is ambiguous.
    archives: list[tuple]
    # The binaries to keep, by file name or by a longer path suffix where the name alone is ambiguous.
    keep: list[str] = field(default_factory=list)


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
    if archive.suffix not in (".zip", ".msi"):
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
            if not identity or identity[0] != MACHINE[corpus_name]:
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
