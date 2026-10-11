#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=invalid-name
"""Positive control: mutate a copy of build B in ways the rules must NOT explain,
run eve-build-diff against A, and check that every mutation is reported as an
ERROR while the untouched known differences stay FLAGGED.

Usage: positive-controls.py <A tree> <B tree> <workdir> [<tool> [<rules>]]
A and B are extracted rootfs directories (eve-build-diff --workdir leaves them
in <workdir>/a and <workdir>/b). <tool> and <rules> select another version of
eve-build-diff, to show that a control fails against it.
"""
import gzip
import io
import json
import os
import re
import struct
import subprocess
import sys
import tarfile

A, B, WORK = sys.argv[1:4]
M = os.path.join(WORK, "mutated")
TOOL = sys.argv[4] if len(sys.argv) > 4 else \
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "eve-build-diff.py")
RULES = ["--rules", sys.argv[5]] if len(sys.argv) > 5 else []

subprocess.run(["rm", "-rf", M], check=True)
subprocess.run(["cp", "-al", B, M], check=True)


def read_bytes(path):
    """Content of the file at path."""
    with open(path, "rb") as fh:
        return fh.read()


def write_text(path, text):
    """Create the file at path with text as its content."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def rewrite(rel, fn):
    """Replace a hard-linked file with a modified copy (never write through the link)."""
    full = os.path.join(M, rel)
    data = read_bytes(full)
    mode = os.stat(full).st_mode
    os.remove(full)
    with open(full, "wb") as fh:
        fh.write(fn(data))
    os.chmod(full, mode)


def own(rel):
    """Replace the hard link at rel with a copy, so metadata changes stay in M."""
    rewrite(rel, lambda d: d)
    return os.path.join(M, rel)


def flip(at):
    """A rewrite function that inverts the byte at offset at."""
    return lambda d: d[:at] + bytes([d[at] ^ 0xFF]) + d[at + 1:]


def elf_section(data, *names):
    """(offset, size) of the first of the named sections in a 64-bit
    little-endian ELF file."""
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    hdr = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    stroff = hdr[shstrndx][4]
    found = {data[stroff + h[0]:data.index(b"\0", stroff + h[0])].decode(): (h[4], h[5])
             for h in hdr}
    return found[next(n for n in names if n in found)]


def swap_strings(section):
    """A rewrite function that swaps the first two distinct, unique, printable
    NUL-terminated strings of equal length (12 or more bytes) in section."""
    def fn(d):
        so, sz = elf_section(d, section, ".rodata")
        buf = d[so:so + sz]
        seen, by_len, i = {}, {}, 0
        while i < len(buf):
            j = buf.find(b"\0", i)
            j = len(buf) if j < 0 else j
            seen[buf[i:j]] = seen.get(buf[i:j], 0) + 1
            by_len.setdefault(j - i, []).append(i)
            i = j + 1
        for n, starts in sorted(by_len.items()):
            good = [k for k in starts if n >= 12 and seen[buf[k:k + n]] == 1
                    and buf[k:k + n].isascii() and buf[k:k + n].decode().isprintable()]
            if len(good) >= 2:
                x, y = good[:2]
                out = bytearray(d)
                out[so + x:so + x + n], out[so + y:so + y + n] = buf[y:y + n], buf[x:x + n]
                return bytes(out)
        raise ValueError("no two strings to swap")
    return fn


expect = {}   # path -> description of the mutation

V = "containers/services/vector/lower/usr/bin/vector"
rewrite(V, swap_strings(".rodata.str1.1"))
expect[V] = "vector: two strings swapped, their references unchanged"

G = "containers/services/edgeview/lower/usr/bin/edge-view"
off, size = elf_section(read_bytes(os.path.join(B, G)), ".text")
rewrite(G, flip(off + size // 3))
expect[G] = "Go binary: one .text byte besides the version"

H = "containers/services/xen-tools/lower/usr/lib/xen/boot/hvmloader"
rewrite(H, flip(0x1000))
expect[H] = "hvmloader: a byte outside the BIOS date"

X = "boot/xen.gz"
rewrite(X, lambda d: gzip.compress(flip(0x2000)(gzip.decompress(d)), mtime=0))
expect[X] = "xen.gz: a byte outside the compile date, inside the gzip stream"

MAN = "containers/services/vtpm/lower/usr/share/man/man8/swtpm.8"
rewrite(MAN, lambda d: d.replace(b"swtpm", b"swtpX", 2))
expect[MAN] = "man page: text besides the .TH date"

SH = "containers/onboot/004-pillar-onboot/lower/etc/shadow"
rewrite(SH, lambda d: re.sub(rb"^(root:)[^:]*", rb"\1$6$changed", d, count=1, flags=re.M))
expect[SH] = "shadow: root password field"

U = "boot/ucode.img"
rewrite(U, flip(600))
expect[U] = "ucode.img: a byte of GenuineIntel.bin content"

APK = "containers/services/debug/lower/lib/apk/db/installed"
rewrite(APK, lambda d: re.sub(rb"^(V:)(\S+)", rb"\g<1>9.9.9-r0", d, count=1, flags=re.M))
expect[APK] = "apk db: a package version"

Z = "etc/zfs-files"
rewrite(Z, lambda d: b"\n".join(d.split(b"\n")[1:]))
expect[Z] = "zfs-files: a dropped line"

MID = "containers/services/wwan/lower/etc/machine-id"
rewrite(MID, lambda d: b"not-a-machine-id\n")
expect[MID] = "machine-id: not a 32-hex ID"

OV = "containers/services/xen-tools/lower/usr/lib/xen/boot/ovmf.bin"
rewrite(OV, flip(0x100))
expect[OV] = "ovmf.bin: an unknown variant"

SB = "sbom.spdx.json"
def sbom(d):
    """Change musl's version in an SPDX SBOM."""
    j = json.loads(d)
    for pkg in j["packages"]:
        if pkg.get("name") == "musl":
            pkg["versionInfo"] = "0.0.1"
            break
    return json.dumps(j).encode()
rewrite(SB, sbom)
expect[SB] = "root SBOM: a package version"

CS = "containers/services/monitor/lower/sbin/sbom.spdx.json"
def cargo(d):
    """Drop the first relationship of an SPDX SBOM."""
    j = json.loads(d)
    j["relationships"] = j["relationships"][1:]
    return json.dumps(j).encode()
rewrite(CS, cargo)
expect[CS] = "cargo SBOM: a dropped relationship"

ST = "lib/apk/db/scripts.tar"
def tar_content(d):
    """Append a line to the first member of a tar archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(d)) as src, \
            tarfile.open(fileobj=buf, mode="w", format=src.format) as dst:
        for i, m in enumerate(src.getmembers()):
            data = src.extractfile(m).read() if m.isfile() else None
            if i == 0:
                data = data + b"\n# injected\n"
                m.size = len(data)
            dst.addfile(m, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()
rewrite(ST, tar_content)
expect[ST] = "apk scripts.tar: a member's content"

KEY = next(os.path.relpath(os.path.join(d, f), M)
           for d, _, fs in os.walk(os.path.join(M, "etc/apk/keys"))
           for f in fs if f.startswith("builder@projecteve.dev-"))
rewrite(KEY, lambda d: d.replace(b"-----END PUBLIC KEY-----",
                                 b"not a key\n-----END PUBLIC KEY-----"))
expect[KEY] = "builder key: not a PEM public key"

NEWKEY = "etc/apk/keys/builder@projecteve.dev-00000000.rsa.pub"
write_text(os.path.join(M, NEWKEY), "#!/bin/sh\n")
expect[NEWKEY] = "builder key only in B: not a PEM public key"

ADD = "etc/new-file"
write_text(os.path.join(M, ADD), "x\n")
expect[ADD] = "an added file"

DEL = "etc/motd"
os.remove(os.path.join(M, DEL))
expect[DEL] = "a removed file"

SUID = "usr/bin/rungetty.sh"
os.chmod(own(SUID), 0o4775)
expect[SUID] = "a setuid bit"

OW = "etc/init.d/001-getty"
getty = own(OW)
os.chmod(getty, os.stat(getty).st_mode | 0o002)
expect[OW] = "other-write on a file"

XA = "etc/init.d/002-logging"
os.setxattr(own(XA), "user.test", b"1")
expect[XA] = "an extended attribute"

DUP = "containers/onboot/004-pillar-onboot/lower/lib/apk/db/installed"
def dup_record(d):
    """Prepend a second record for the first package, with another version."""
    first = d.split(b"\n\n", 1)[0]
    return re.sub(rb"^V:.*$", b"V:9.9.9-r0", first, count=1, flags=re.M) + b"\n\n" + d
rewrite(DUP, dup_record)
expect[DUP] = "apk db: a duplicate package record"

KEYLINK = "etc/apk/keys/builder@projecteve.dev-1.rsa.pub"
os.symlink("/etc/shadow", os.path.join(M, KEYLINK))
expect[KEYLINK] = "builder key only in B: a symlink"

RX = next(p for p in ("boot/runx-initrd",
                      "containers/services/xen-tools/lower/usr/lib/xen/boot/runx-initrd")
          if os.path.exists(os.path.join(B, p)))
def cpio_uid(d):
    """Set the first cpio member's uid to 4242."""
    gz = d[:2] == b"\x1f\x8b"
    raw = bytearray(gzip.decompress(d) if gz else d)
    i = raw.find(b"070701")
    raw[i + 22:i + 30] = b"%08X" % 4242
    return gzip.compress(bytes(raw), mtime=0) if gz else bytes(raw)
rewrite(RX, cpio_uid)
expect[RX] = "runx-initrd: a member uid outside the allowed set"

NL = "etc/init.d/001-getty\nx"
write_text(os.path.join(M, NL), "#!/bin/sh\n")
expect["B:" + NL] = "a name with a newline"
also = {NL}

R = "containers/onboot/000-rngd/rootfs/sbin/rngd"
if b"0f0c1f426536 " in read_bytes(os.path.join(A, R)):
    def length_moved(d):
        """Undo one real version-length decrement in .data, and decrement a byte
        of .noptrdata that is not a length."""
        a, out = read_bytes(os.path.join(A, R)), bytearray(d)
        so, sz = elf_section(a, ".data")
        pos = next(k for k in range(so, so + sz) if a[k] == out[k] + 1)
        out[pos] = a[pos]
        so, sz = elf_section(a, ".noptrdata")
        q = next(k for k in range(so, so + sz) if a[k] == out[k] >= 2)
        out[q] -= 1
        return bytes(out)
    rewrite(R, length_moved)
    expect[R] = "rngd: a .noptrdata byte one lower, posing as a version length"

LNK = next(os.path.relpath(os.path.join(d, f), M)
           for d, _, fs in os.walk(os.path.join(M, "usr/lib"))
           for f in fs if os.path.islink(os.path.join(d, f)))
os.remove(os.path.join(M, LNK))
os.symlink("/elsewhere", os.path.join(M, LNK))
expect[LNK] = "a symlink target"

report = os.path.join(WORK, "controls.json")
rc = subprocess.run([sys.executable, "-I", TOOL, "-q", "--json", report, *RULES, A, M],
                    check=False, stdout=subprocess.DEVNULL).returncode
with open(report, encoding="utf-8") as report_fh:
    res = json.load(report_fh)
status = {}
for r in res["results"]:
    status.setdefault(r["path"], set()).add(r["status"])

fail = 0
for rel_path, what in expect.items():
    ok = "ERROR" in status.get(rel_path, set())
    fail += not ok
    print(f"{'ok  ' if ok else 'MISS'} {what}: {rel_path}")
unexpected = sorted(rel for rel, st in status.items()
                    if "ERROR" in st and rel not in expect and rel not in also)
for p in unexpected:
    print(f"EXTRA error on an unmutated path: {p}")
print(f"exit status {rc} (expected 1); {res['flagged']} flagged, {res['errors']} errors")
sys.exit(1 if fail or unexpected or rc != 1 else 0)
