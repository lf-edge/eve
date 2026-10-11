#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# a/b and x/y name the two builds throughout.
# pylint: disable=invalid-name
"""Compare two EVE rootfs builds and sort every difference into known or unknown.

Each input is a squashfs rootfs.img, an extracted directory, or
docker:<name>@sha256:<digest> (an lfedge/eve image, whose rootfs.img is read
from the path in its org.lfedge.eci.artifact.root label without running it).

Differences that a rule in the rules file explains are reported as FLAGGED.
Any other difference is reported as an ERROR, and the exit status is 1. Exit
status 2 means a usage or input problem. File mtimes are not compared.
"""

import argparse
import collections
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib  # pylint: disable=import-error

# ---------------------------------------------------------------- inputs

Entry = collections.namedtuple("Entry", "kind mode uid gid size rdev target xattrs")
META = ("kind", "mode", "uid", "gid", "rdev", "target", "xattrs")

LISTING_RE = re.compile(
    r"^(?P<mode>[-dlcbps][-rwxsStTl]{9})\s+(?P<uid>\d+)/(?P<gid>\d+)\s+"
    r"(?P<size>\d+|\d+,\s*\d+)\s+\d{4}-\d\d-\d\d \d\d:\d\d squashfs-root(?P<path>.*)$")
# unsquashfs prints names unescaped, so a name with a newline spans two lines.
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
ARTIFACT_ROOT_LABEL = "org.lfedge.eci.artifact.root"


class InputError(Exception):
    """An input that cannot be compared; exit status 2."""


def mode_bits(s):
    """Convert an ls-style mode string to permission bits."""
    bits = 0
    for ch, val in zip(s[1:], (0o400, 0o200, 0o100, 0o40, 0o20, 0o10, 4, 2, 1)):
        if ch in "rwxst":
            bits |= val
    for pos, ch_set, special in ((3, "sS", 0o4000), (6, "sS", 0o2000), (9, "tT", 0o1000)):
        if s[pos] in ch_set:
            bits |= special
    return bits


def squashfs_listing(img):
    """Entries of a squashfs image by path, from `unsquashfs -lln`, and a list of
    (path, problem) for listing lines that cannot be trusted."""
    res = subprocess.run(["unsquashfs", "-lln", img], check=False, capture_output=True,
                         text=True, errors="surrogateescape")
    if res.returncode:
        why = res.stderr.strip().splitlines() or [f"exit status {res.returncode}"]
        raise InputError(f"{img}: unsquashfs cannot list it: {why[0]}")
    out = res.stdout
    entries, problems = {}, []
    for line in out.splitlines():
        m = LISTING_RE.match(line)
        if not m:
            problems.append((line, "unparsable listing line (a name with a newline?)"))
            continue
        path, target = m["path"].lstrip("/"), None
        kind = m["mode"][0]
        if kind == "l":
            path, target = path.split(" -> ", 1)
        if path == "":
            continue
        if path in entries:
            problems.append((path, "listed twice (a name with a newline?)"))
        size, rdev = m["size"], None
        if "," in size:
            rdev, size = size.replace(" ", ""), 0
        entries[path] = Entry(kind, mode_bits(m["mode"]), int(m["uid"]), int(m["gid"]),
                              int(size), rdev, target, None)
    return entries, problems


def squashfs_xattr_ids(img):
    """The number of extended attribute ids in a squashfs image."""
    out = subprocess.run(["unsquashfs", "-s", img], check=True, capture_output=True,
                         text=True).stdout
    if re.search(r"^Xattrs are not stored$", out, re.M):
        return 0
    m = re.search(r"^Number of xattr ids (\d+)$", out, re.M)
    if not m:
        raise InputError(f"{img}: unsquashfs -s does not report the xattr id count")
    return int(m[1])


def read_xattrs(path):
    """Sorted (name, value) pairs of the extended attributes of path."""
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError:
        return ()
    return tuple(sorted((n, os.getxattr(path, n, follow_symlinks=False)) for n in names))


FILE_KINDS = {stat.S_IFREG: "-", stat.S_IFDIR: "d", stat.S_IFLNK: "l", stat.S_IFCHR: "c",
              stat.S_IFBLK: "b", stat.S_IFIFO: "p", stat.S_IFSOCK: "s"}


def tree_listing(root):
    """Entries of a directory tree by path relative to root."""
    entries = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            kind = FILE_KINDS[stat.S_IFMT(st.st_mode)]
            rdev = f"{os.major(st.st_rdev)},{os.minor(st.st_rdev)}" if kind in "cb" else None
            target = os.readlink(full) if kind == "l" else None
            entries[os.path.relpath(full, root)] = Entry(
                kind, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid,
                st.st_size if kind == "-" else 0, rdev, target, read_xattrs(full))
    return entries


def docker_rootfs(ref, img):
    """Copy the rootfs.img of an lfedge/eve image to img without running the image."""
    if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", ref):
        raise InputError(f"docker:{ref}: name the image by digest, <name>@sha256:<hex>")
    cid = subprocess.run(["docker", "create", ref], check=True, capture_output=True,
                         text=True).stdout.strip()
    try:
        path = subprocess.run(
            ["docker", "image", "inspect", "--format",
             f'{{{{index .Config.Labels "{ARTIFACT_ROOT_LABEL}"}}}}', ref],
            check=True, capture_output=True, text=True).stdout.strip()
        if not path.startswith("/"):
            raise InputError(f"docker:{ref}: no {ARTIFACT_ROOT_LABEL} label")
        subprocess.run(["docker", "cp", f"{cid}:{path}", img], check=True,
                       stdout=subprocess.DEVNULL)
    finally:
        subprocess.run(["docker", "rm", cid], check=False, capture_output=True)


def materialize(spec, workdir, label):
    """Return (listing, root directory, problems) for an input spec. problems lists
    (path, detail) for entries the listing cannot represent."""
    if spec.startswith("docker:"):
        img = os.path.join(workdir, f"{label}-rootfs.img")
        docker_rootfs(spec[7:], img)
        spec = img
    if os.path.isdir(spec):
        listing = tree_listing(spec)
        return listing, spec, [(p, "name contains a control character")
                               for p in listing if CONTROL_RE.search(p)]
    listing, problems = squashfs_listing(spec)
    n = squashfs_xattr_ids(spec)
    if n:
        problems.append(("<image>", f"{n} extended attribute ids; xattrs are not compared"))
    root = os.path.join(workdir, label)
    # Device nodes cannot be created without root; they are compared from the listing.
    subprocess.run(["unsquashfs", "-q", "-no-xattrs", "-d", root, spec],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Metadata comes from the listing, so the extracted copy may be made readable.
    subprocess.run(["chmod", "-R", "u+rwX", root], check=True)
    for p in tree_listing(root):
        if CONTROL_RE.search(p):
            problems.append((p, "name contains a control character"))
        elif p not in listing:
            problems.append((p, "extracted but not in the listing"))
    return listing, root, problems


# ---------------------------------------------------------------- helpers

def diff_positions(a, b):
    """Offsets at which a and b differ, up to the shorter length."""
    out, chunk = [], 1 << 16
    for i in range(0, min(len(a), len(b)), chunk):
        ca, cb = a[i:i + chunk], b[i:i + chunk]
        if ca != cb:
            out.extend(i + j for j in range(len(ca)) if ca[j] != cb[j])
    return out


Section = collections.namedtuple("Section", "name type flags addr offset size")
SHT_NOBITS, SHF_EXECINSTR = 8, 0x4


def elf_sections(data):  # pylint: disable=too-many-locals
    """Section headers of a little-endian ELF file, or None if not ELF."""
    if data[:4] != b"\x7fELF" or data[5] != 1:
        return None
    is64 = data[4] == 2
    if is64:
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        fmt = "<IIQQQQIIQQ"
    else:
        shoff, = struct.unpack_from("<I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
        fmt = "<IIIIIIIIII"
    if shoff == 0 or shoff + shnum * shentsize > len(data):
        return []
    raw = [struct.unpack_from(fmt, data, shoff + i * shentsize) for i in range(shnum)]
    stroff = raw[shstrndx][4]
    secs = []
    for name, typ, flags, addr, off, size, *_ in raw:
        end = data.index(b"\0", stroff + name)
        secs.append(Section(data[stroff + name:end].decode(errors="replace"),
                            typ, flags, addr, off, size))
    return secs


def section_at(secs, off):
    """The section holding file offset off, or None."""
    for s in secs:
        if s.type != SHT_NOBITS and s.size and s.offset <= off < s.offset + s.size:
            return s
    return None


def describe_binary_diff(a, b):
    """One-line summary of where two byte strings differ."""
    if len(a) != len(b):
        return f"size {len(a)} -> {len(b)}"
    pos = diff_positions(a, b)
    secs = elf_sections(a)
    if secs:
        unknown = Section("?", 0, 0, 0, 0, 0)
        names = collections.Counter((section_at(secs, p) or unknown).name for p in pos)
        return f"{len(pos)} bytes differ in " + \
            ", ".join(f"{n} ({c})" for n, c in names.most_common())
    return f"{len(pos)} bytes differ, first at {pos[0]:#x}" if pos else "identical"


def maybe_gunzip(data):
    """Decompress data if it is gzip, else return it unchanged."""
    return gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data


GNU_BUILD_ID_RE = re.compile(
    rb"\x04\x00\x00\x00([\x10\x14\x20])\x00\x00\x00\x03\x00\x00\x00GNU\x00", re.S)


def note_ranges(secs, data=None):
    """Byte ranges holding build IDs: the ELF note sections, and any GNU build-ID
    note found by its header (Xen keeps one inside .text)."""
    out = [(s.offset, s.offset + s.size) for s in secs or ()
           if s.name in (".note.gnu.build-id", ".note.go.buildid")]
    if data is not None:
        out += [(m.end(), m.end() + m.group(1)[0]) for m in GNU_BUILD_ID_RE.finditer(data)]
    return out


def in_ranges(p, ranges):
    """Whether p falls in any of the [lo, hi) ranges."""
    return any(lo <= p < hi for lo, hi in ranges)


def same_layout(sa, sb):
    """Whether two section lists have the same names, addresses, offsets and sizes."""
    def layout(secs):
        return [(s.name, s.addr, s.offset, s.size) for s in secs]
    return layout(sa) == layout(sb)


_GLOB_CACHE = {}


def path_match(path, glob):
    """Whether path matches glob, in which * and ? stay within one path segment
    and ** matches across segments."""
    rx = _GLOB_CACHE.get(glob)
    if rx is None:
        out, i = [], 0
        while i < len(glob):
            if glob.startswith("**", i):
                out.append(".*")
                i += 2
            elif glob[i] == "*":
                out.append("[^/]*")
                i += 1
            elif glob[i] == "?":
                out.append("[^/]")
                i += 1
            else:
                out.append(re.escape(glob[i]))
                i += 1
        rx = _GLOB_CACHE[glob] = re.compile("".join(out) + r"\Z", re.S)
    return rx.match(path) is not None


# ---------------------------------------------------------------- checkers
# Each checker returns (True, detail) when the rule explains the difference,
# or (False, reason) when it does not.

GO_VERSION_RE = re.compile(rb"-X[ =]main\.Version=([\w.+-]+)")


def check_go_build_version(a, b, params, ctx, _path):  # pylint: disable=too-many-locals
    """Go binaries that differ only in -X main.Version and the build IDs."""
    va, vb = GO_VERSION_RE.search(a), GO_VERSION_RE.search(b)
    if not va or not vb:
        return False, "no -X main.Version in build info"
    va, vb = va.group(1), vb.group(1)
    if len(va) != len(vb) or len(a) != len(b):
        return False, "version or file length differs"
    sa, sb = elf_sections(a), elf_sections(b)
    if not sa or not same_layout(sa, sb):
        return False, "ELF section layout differs"
    detail = ""
    na = bytearray(a.replace(va, vb))
    nb = bytearray(b)
    for lo, hi in note_ranges(sa):
        na[lo:hi] = nb[lo:hi] = bytes(hi - lo)
    if na != nb:
        why = describe_binary_diff(bytes(na), bytes(nb)) + " after substituting the version"
        if not (params.get("trailing_space") and va + b" " in a):
            return False, why
        ok, how = trailing_space_aligns(a, b, sa, va, vb)
        if not ok:
            return False, f"{why}; with a trailing space: {how}"
        detail = f" (A has a trailing space: {how})"
    ctx["version_pairs"][va.decode()] = vb.decode()
    return True, f"main.Version {va.decode()} -> {vb.decode()}{detail}"


def vaddr_to_offset(secs, addr):
    """The file offset of virtual address addr, or None."""
    for s in secs:
        if s.type != SHT_NOBITS and s.addr and s.addr <= addr < s.addr + s.size:
            return addr - s.addr + s.offset
    return None


def uvarint(data, off):
    """(value, length) of the unsigned LEB128 varint at off."""
    value = shift = 0
    for k in range(10):
        c = data[off + k]
        value |= (c & 0x7f) << shift
        if c < 0x80:
            return value, k + 1
        shift += 7
    raise ValueError("varint too long")


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def length_field(a, b, sa, sec, oa, ob, needle):
    """Whether offset oa in A and ob in B start the length of a string that holds
    needle in A and is one byte shorter in B: the len of a Go string header
    {ptr, len} in .data or .noptrdata, or the varint before the module info in
    .go.buildinfo."""
    if sec.name in (".data", ".noptrdata"):
        if (oa - sec.offset) % 8 or oa < sec.offset + 8:
            return False
        ptr, la = struct.unpack_from("<QQ", a, oa - 8)
        ptr_b, lb = struct.unpack_from("<QQ", b, ob - 8)
        off = vaddr_to_offset(sa, ptr)
        return ptr == ptr_b and lb == la - 1 and off is not None and needle in a[off:off + la]
    if sec.name == ".go.buildinfo":
        try:
            (la, k), (lb, _) = uvarint(a, oa), uvarint(b, ob)
        except (ValueError, IndexError):
            return False
        return lb == la - 1 and needle in a[oa + k:oa + k + la]
    return False


def trailing_space_aligns(a, b, sa, va, vb):  # pylint: disable=too-many-locals,too-many-branches
    """linuxkit before v1.8.1 passed GOPKGVERSION untrimmed, so A's version ends
    in a space. With "va " replaced by vb, each section of A must equal B's except
    for one zero padding byte per removed space, and the lengths of the strings
    holding the version one less in B (see length_field)."""
    notes = note_ranges(sa)
    covered = bytearray(len(a))
    for s in sa:
        if s.type != SHT_NOBITS:
            covered[s.offset:s.offset + s.size] = b"\1" * s.size
    if any(not covered[p] for p in diff_positions(a, b)):
        return False, "bytes outside the ELF sections differ"
    spaces = lengths = 0
    for s in sa:
        if s.type == 8 or in_ranges(s.offset, notes):
            continue
        x, y = a[s.offset:s.offset + s.size], b[s.offset:s.offset + s.size]
        if x == y:
            continue
        # End of each substituted version in x; i plus the ends before it is A's offset.
        ends = [m.start() - k + len(vb)
                for k, m in enumerate(re.finditer(re.escape(va + b" "), x))]
        n = len(ends)
        x = x.replace(va + b" ", vb)
        i = j = pads = 0
        while i < len(x) and j < len(y):
            if x[i] == y[j]:
                i, j = i + 1, j + 1
            elif y[j] == 0 and pads < n:
                pads, j = pads + 1, j + 1
            elif x[i] == y[j] + 1 and length_field(
                    a, b, sa, s, s.offset + i + sum(e <= i for e in ends), s.offset + j,
                    va + b" "):
                lengths, i, j = lengths + 1, i + 1, j + 1
            else:
                return False, (f"{s.name}: difference at +{i:#x} is not the version, "
                               "padding or a length")
        if i != len(x) or len(y) - j != n - pads or any(y[j:]):
            return False, f"{s.name}: section does not realign after the version"
        spaces += n
    if not spaces or lengths > spaces:
        return False, f"{spaces} trailing spaces, {lengths} length fields"
    return True, f"{spaces} strings one byte shorter in B, {lengths} length fields"


def compile_patterns(params):
    """The rule's patterns, compiled as bytes regexes."""
    return [re.compile(p.encode()) for p in params.get("patterns", [])]


def check_volatile_strings(a, b, params, _ctx, _path):
    """Byte differences confined to pattern matches at the same offset, and build IDs.
    In an ELF file the matches must lie in non-executable sections unless the rule
    sets code_sections."""
    if params.get("decompress") == "gzip":
        a, b = maybe_gunzip(a), maybe_gunzip(b)
    if len(a) != len(b):
        return False, f"size {len(a)} -> {len(b)}"
    pos = diff_positions(a, b)
    covered = set()
    hits = []
    for pat in compile_patterns(params):
        mb = {(m.start(), m.end()): m.group() for m in pat.finditer(b)}
        for m in pat.finditer(a):
            if (m.start(), m.end()) in mb and m.group() != mb[(m.start(), m.end())]:
                covered.update(range(m.start(), m.end()))
                hits.append(f"{m.group().decode(errors='replace')!r} -> "
                            f"{mb[(m.start(), m.end())].decode(errors='replace')!r}")
    secs = elf_sections(a)
    if secs and not params.get("code_sections"):
        for p in sorted(covered):
            s = section_at(secs, p)
            if not s or s.flags & SHF_EXECINSTR:
                return False, (f"volatile string at {p:#x} is in "
                               f"{s.name if s else 'no section'}, not in data")
    notes = note_ranges(secs, a) if params.get("elf_notes", True) else []
    rest = [p for p in pos if p not in covered and not in_ranges(p, notes)]
    if rest:
        return False, (f"{len(rest)} of {len(pos)} differing bytes outside the volatile "
                       f"strings, first at {rest[0]:#x}")
    if not hits:
        return False, "no volatile string differs"
    extra = ", build ID" if any(in_ranges(p, notes) for p in pos) else ""
    return True, "; ".join(dict.fromkeys(hits)) + extra


def keep_groups(m):
    """Mask a match, keeping its capturing groups so they must still be equal."""
    return "".join(g or "" for g in m.groups()) + "\0"


def check_line_subst(a, b, params, _ctx, _path):
    """Line-for-line equality after masking the patterns."""
    la = a.decode(errors="surrogateescape").splitlines()
    lb = b.decode(errors="surrogateescape").splitlines()
    if len(la) != len(lb):
        return False, f"{len(la)} -> {len(lb)} lines"
    pats = [re.compile(p) for p in params["patterns"]]
    changed = 0
    for x, y in zip(la, lb):
        if x == y:
            continue
        nx, ny = x, y
        for p in pats:
            nx, ny = p.sub(keep_groups, nx), p.sub(keep_groups, ny)
        if nx != ny:
            return False, f"line differs beyond the allowed fields: {x[:80]!r} -> {y[:80]!r}"
        changed += 1
    return True, f"{changed} line(s) differ only in {params.get('what', 'the allowed fields')}"


def check_line_set(a, b, _params, _ctx, _path):
    """The same lines in a different order."""
    la, lb = a.splitlines(), b.splitlines()
    if collections.Counter(la) != collections.Counter(lb):
        return False, "line sets differ"
    return True, f"same {len(la)} lines, different order"


def parse_cpio(data):  # pylint: disable=too-many-locals
    """Members of one or more concatenated newc archives, in order."""
    out, i = [], 0
    while True:
        i = data.find(b"070701", i)
        if i < 0:
            break
        h = data[i:i + 110]
        f = [int(h[6 + 8 * k:14 + 8 * k], 16) for k in range(13)]
        ino, mode, uid, gid, nlink, mtime, size, _, _, rmaj, rmin, namesize, _ = f
        name_end = i + 110 + namesize - 1
        name = data[i + 110:name_end].decode(errors="replace")
        body = (i + 110 + namesize + 3) & ~3
        content = data[body:body + size]
        i = (body + size + 3) & ~3
        if name == "TRAILER!!!":
            continue
        out.append({"name": name, "ino": ino, "mode": mode, "uid": uid, "gid": gid,
                    "nlink": nlink, "mtime": mtime, "rdev": (rmaj, rmin), "content": content})
    return out


def check_cpio_metadata(a, b, params, _ctx, _path):
    """cpio archives with the same members and content, differing in allowed fields.
    uids and gids, when given, bound the values those fields may take."""
    ma, mb = parse_cpio(maybe_gunzip(a)), parse_cpio(maybe_gunzip(b))
    if [m["name"] for m in ma] != [m["name"] for m in mb]:
        return False, "member names or order differ"
    allowed = set(params.get("fields", ["mtime", "ino"]))
    mode_mask = int(params.get("mode_mask", "0"), 8)
    bounds = {k: set(params[k + "s"]) for k in ("uid", "gid") if k + "s" in params}
    seen = collections.Counter()
    for x, y in zip(ma, mb):
        for k in x:
            if x[k] == y[k]:
                continue
            if k == "mode" and (x[k] ^ y[k]) & ~mode_mask == 0:
                seen[f"mode (mask {mode_mask:o})"] += 1
            elif k in bounds and not {x[k], y[k]} <= bounds[k]:
                return False, f"{x['name']}: {k} {x[k]} -> {y[k]} outside {sorted(bounds[k])}"
            elif k in allowed:
                seen[k] += 1
            else:
                return False, f"{x['name']}: {k} differs"
    if not seen:
        return False, "archive members identical; difference is in the container format"
    return True, f"{len(ma)} members, contents identical; differ in " + \
        ", ".join(f"{k} ({n})" for k, n in seen.items())


def parse_apk_db(data):
    """Records of an apk installed database, by package name. Each record must
    have exactly one P: line, and no name may repeat."""
    pkgs = {}
    for rec in data.decode(errors="surrogateescape").split("\n\n"):
        lines = [l for l in rec.splitlines() if l]
        if not lines:
            continue
        names = [l[2:] for l in lines if l.startswith("P:")]
        if len(names) != 1:
            raise ValueError(f"record with {len(names)} P: lines: {lines[0][:60]!r}")
        if names[0] in pkgs:
            raise ValueError(f"package {names[0]} listed twice")
        pkgs[names[0]] = lines
    return pkgs


def check_apk_db(a, b, params, _ctx, _path):
    """apk databases with the same packages, differing only in allowed fields."""
    pa, pb = parse_apk_db(a), parse_apk_db(b)
    if set(pa) != set(pb):
        return False, f"package set differs: {sorted(set(pa) ^ set(pb))[:5]}"
    allowed = set(params.get("fields", ["C", "S", "t"]))
    changed = []
    for name, rec in pa.items():
        if rec == pb[name]:
            continue
        if len(rec) != len(pb[name]):
            return False, f"{name}: record length differs"
        for x, y in zip(rec, pb[name]):
            if x != y and (x[:2] != y[:2] or x[0] not in allowed):
                return False, f"{name}: {x[:60]!r} -> {y[:60]!r}"
        changed.append(name)
    return True, (f"{', '.join(changed)}: only fields {', '.join(sorted(allowed))} differ; "
                  "installed file checksums equal")


def check_tar_metadata(a, b, params, _ctx, _path):
    """tar archives with the same members and content, differing in allowed fields."""
    def members(data):
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            return [(m, t.extractfile(m).read() if m.isfile() else None) for m in t.getmembers()]
    ma, mb = members(a), members(b)
    if [m.name for m, _ in ma] != [m.name for m, _ in mb]:
        return False, "member names or order differ"
    allowed = set(params.get("fields", ["mtime"]))
    seen = collections.Counter()
    for (x, cx), (y, cy) in zip(ma, mb):
        if cx != cy:
            return False, f"{x.name}: content differs"
        for k in ("mode", "uid", "gid", "uname", "gname", "type", "linkname", "mtime", "size"):
            if getattr(x, k) != getattr(y, k):
                if k not in allowed:
                    return False, f"{x.name}: {k} differs"
                seen[k] += 1
    if not seen:
        return False, "members identical; difference is in the container format"
    return True, f"{len(ma)} members, contents identical; differ in " + \
        ", ".join(f"{k} ({n})" for k, n in seen.items())


PEM_PUBKEY_RE = re.compile(
    rb"\A-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?\Z")


def check_pem_public_key(a, b, _params, _ctx, _path):
    """Two PEM public keys."""
    if not PEM_PUBKEY_RE.match(a) or not PEM_PUBKEY_RE.match(b):
        return False, "not a PEM public key"
    return True, "a different public key"


def check_known_variant(a, b, params, _ctx, _path):
    """A pair of sha256 sums listed as equivalent builds."""
    ha, hb = hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest()
    for x, y in params["pairs"]:
        if {ha, hb} == {x, y}:
            return True, f"known variants {ha[:16]} / {hb[:16]}"
    return False, f"sha256 {ha[:16]} / {hb[:16]} not a known pair"


# An older syft writes a Go module's subpackage as a purl subpath, and an
# all-zero SHA1 for an empty file.
ZERO_SHA1 = [{"algorithm": "SHA1", "checksumValue": "0" * 40}]
EMPTY_SHA256 = [{"algorithm": "SHA256", "checksumValue": hashlib.sha256(b"").hexdigest()}]
PURL_SUBPATH_RE = re.compile(r"^(pkg:golang/[^@#]+)@([^#]+)#(.+)$")


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def check_spdx(a, b, params, ctx, _path):  # pylint: disable=too-many-return-statements
    """SPDX SBOMs equal after IDs, namespace, creation time, order and build-commit
    versions are ignored, with the relaxations the rule allows."""
    da, db = json.loads(a), json.loads(b)
    subs = ctx["version_pairs"]
    notes = []

    def sub(text):
        for x, y in subs.items():
            text = text.replace(x, y)
        return text

    def entry_set(items):
        return {json.dumps(x, sort_keys=True) for x in items}

    additions = params.get("allow_additions", False)
    volatile_top = {"documentNamespace", "creationInfo", "packages", "files", "relationships",
                    "SPDXID"}
    for k in set(da) | set(db):
        if k in volatile_top or da.get(k) == db.get(k):
            continue
        if additions and isinstance(da.get(k), list) and isinstance(db.get(k), list) and \
                entry_set(da[k]) == entry_set(db[k]):
            notes.append(f"{k}: same entries, different multiplicity")
            continue
        return False, f"top-level {k} differs"
    ca, cb = dict(da.get("creationInfo", {})), dict(db.get("creationInfo", {}))
    ca.pop("created", None)
    cb.pop("created", None)
    if ca != cb:
        return False, "creationInfo differs beyond 'created'"

    def purl_subpath_to_path(ref):
        if ref.get("referenceType") != "purl":
            return ref
        return dict(ref, referenceLocator=PURL_SUBPATH_RE.sub(r"\1/\3@\2", ref["referenceLocator"]))

    def pkg_norm(p, cpe):
        q = {k: v for k, v in p.items() if k != "SPDXID"}
        if not cpe:
            q["externalRefs"] = [r for r in q.get("externalRefs", [])
                                 if r.get("referenceType") != "cpe23Type"]
            if params.get("older_syft"):
                q["externalRefs"] = [purl_subpath_to_path(r) for r in q["externalRefs"]]
        return sub(json.dumps(q, sort_keys=True))

    allow_cpe = params.get("allow_cpe_drift", False)
    pka = collections.Counter(pkg_norm(p, True) for p in da.get("packages", []))
    pkb = collections.Counter(json.dumps({k: v for k, v in p.items() if k != "SPDXID"},
                                         sort_keys=True) for p in db.get("packages", []))
    if pka != pkb:
        if not allow_cpe:
            return False, f"packages differ ({sum((pka - pkb).values())} only in A)"
        na = collections.Counter(pkg_norm(p, False) for p in da.get("packages", []))
        nb = collections.Counter(pkg_norm(p, False) for p in db.get("packages", []))
        if na - nb or (nb - na and not additions):
            return False, f"packages differ beyond CPEs ({sum((na - nb).values())} only in A)"
        if nb - na:
            notes.append(f"{sum((nb - na).values())} packages only in B")
        if pka - pkb:
            notes.append(f"CPEs differ on {sum((pka - pkb).values())} packages")

    fa = {f["fileName"]: f for f in da.get("files", [])}
    fb = {f["fileName"]: f for f in db.get("files", [])}
    if set(fa) - set(fb) or (set(fb) - set(fa) and not additions):
        return False, "file set differs"
    if set(fb) - set(fa):
        notes.append(f"{len(set(fb) - set(fa))} files only in B")
    layer, cks, empty = 0, [], 0
    for n in fa:
        x = {k: v for k, v in fa[n].items() if k != "SPDXID"}
        y = {k: v for k, v in fb[n].items() if k != "SPDXID"}
        if params.get("allow_layer_comment") and x.get("comment") != y.get("comment"):
            layer += 1
            x.pop("comment", None)
            y.pop("comment", None)
        if params.get("older_syft") and x.get("checksums") == ZERO_SHA1 and \
                y.get("checksums") == EMPTY_SHA256:
            empty += 1
            x.pop("checksums")
            y.pop("checksums")
        if x.get("checksums") != y.get("checksums"):
            if n not in ctx["differing"]:
                return False, f"checksum of {n} differs but the file is identical"
            cks.append(n)
            x.pop("checksums")
            y.pop("checksums")
        if x != y:
            return False, f"file entry {n} differs"
    if layer:
        notes.append(f"layerID on {layer} files")
    if cks:
        notes.append(f"checksums of {len(cks)} differing files")
    if empty:
        notes.append(f"{empty} empty files with a zero SHA1 in A")

    def rels(d, translate):
        m = {p["SPDXID"]: f"{p.get('name')}@{p.get('versionInfo')}" for p in d.get("packages", [])}
        m.update({f["SPDXID"]: f["fileName"] for f in d.get("files", [])})
        m[d.get("SPDXID")] = "DOCUMENT"
        tr = sub if translate else (lambda s: s)
        return collections.Counter((tr(m.get(r["spdxElementId"], "?")), r["relationshipType"],
                                    tr(m.get(r["relatedSpdxElement"], "?")))
                                   for r in d.get("relationships", []))
    ra, rb = rels(da, True), rels(db, False)
    if ra != rb:
        drift = f"{sum((ra - rb).values())} only in A, {sum((rb - ra).values())} only in B"
        if not params.get("allow_relationship_drift"):
            return False, f"relationships differ ({drift})"
        notes.append(f"relationships {drift}")
    if subs and a != b and any(x.encode() in a for x in subs):
        notes.append("build-commit versions")
    notes.insert(0, "namespace/created/IDs/order")
    return True, "; ".join(notes)


def one_sided(p, side, e, root, rules, rule_hits):  # pylint: disable=too-many-arguments,too-many-positional-arguments
    """An entry present in one tree only is flagged by a rule with one_sided = true
    whose content check, when it has one, accepts the entry, a regular file,
    against itself."""
    for r in rules:
        if not r.get("one_sided") or not any(path_match(p, g) for g in r["paths"]):
            continue
        if CHECKERS.get(r["kind"]):
            if e.kind != "-":
                continue
            try:
                with open(os.path.join(root, p), "rb") as fh:
                    data = fh.read()
                ok, _ = CHECKERS[r["kind"]](data, data, r, {}, p)
            except Exception:  # pylint: disable=broad-exception-caught
                ok = False
            if not ok:
                continue
        rule_hits[r["name"]] += 1
        return ("FLAGGED", p, r["name"], f"only in {side}")
    return ("ERROR", p, None, f"only in {side} ({e.kind})")


def check_metadata(ea, eb, params):
    """Mode bits within mode_mask, and uids and gids in the allowed sets, may differ."""
    mask = int(params.get("mode_mask", "0"), 8)
    gids = set(params.get("gids", []))
    uids = set(params.get("uids", []))
    what = []
    for k in META:
        x, y = getattr(ea, k), getattr(eb, k)
        if x == y or (k == "xattrs" and None in (x, y)):
            continue
        if k == "mode" and (x ^ y) & ~mask == 0:
            what.append(f"mode {x:o} -> {y:o}")
        elif k == "gid" and {x, y} <= gids:
            what.append(f"gid {x} -> {y}")
        elif k == "uid" and {x, y} <= uids:
            what.append(f"uid {x} -> {y}")
        else:
            return False, f"{k} {x} -> {y}"
    return True, ", ".join(what)


CHECKERS = {
    "go-build-version": check_go_build_version,
    "volatile-strings": check_volatile_strings,
    "line-subst": check_line_subst,
    "line-set": check_line_set,
    "cpio-metadata": check_cpio_metadata,
    "apk-db": check_apk_db,
    "known-variant": check_known_variant,
    "tar-metadata": check_tar_metadata,
    "pem-public-key": check_pem_public_key,
    "spdx": check_spdx,
    "metadata": None,
}
DEFERRED = {"spdx"}   # need the results of the other files


# ---------------------------------------------------------------- main

def main():  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Compare the two builds, print the report and return the exit status."""
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a", help="reference build (e.g. the release)")
    ap.add_argument("b", help="build to check")
    ap.add_argument("--rules", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                    "known-diffs.toml"))
    ap.add_argument("--json", help="also write the report as JSON to this file")
    ap.add_argument("--workdir", help="extract here instead of a temporary directory (kept)")
    ap.add_argument("-q", "--quiet", action="store_true", help="print errors and the summary only")
    ap.add_argument("-v", "--verbose", action="store_true", help="list every flagged entry")
    args = ap.parse_args()

    with open(args.rules, "rb") as fh:
        rules_bytes = fh.read()
    rules = tomllib.loads(rules_bytes.decode()).get("rule", [])
    with open(os.path.abspath(__file__), "rb") as fh:
        tool_sha256 = hashlib.sha256(fh.read()).hexdigest()
    rules_sha256 = hashlib.sha256(rules_bytes).hexdigest()
    for r in rules:
        if r["kind"] not in CHECKERS:
            sys.exit(f"rule {r['name']}: unknown kind {r['kind']}")

    workdir = args.workdir or tempfile.mkdtemp(prefix="eve-build-diff-")
    os.makedirs(workdir, exist_ok=True)
    try:
        try:
            la, ra, pa = materialize(args.a, workdir, "a")
            lb, rb, pb = materialize(args.b, workdir, "b")
        except InputError as e:
            print(f"eve-build-diff: {e}", file=sys.stderr)
            return 2
        results = [("ERROR", f"{side}:{p}", None, detail)       # (status, path, rule, detail)
                   for side, problems in (("A", pa), ("B", pb)) for p, detail in problems]

        rule_hits = collections.Counter()

        def matches(rule, path):
            return any(path_match(path, g) for g in rule["paths"])

        for side, only, root in (("A", set(la) - set(lb), ra), ("B", set(lb) - set(la), rb)):
            for p in sorted(only):
                entry = (la if side == "A" else lb)[p]
                results.append(one_sided(p, side, entry, root, rules, rule_hits))

        common = sorted(set(la) & set(lb))
        ctx = {"version_pairs": {}, "differing": set()}
        pending = []
        identical = 0
        for p in common:
            ea, eb = la[p], lb[p]
            meta = [k for k in META if getattr(ea, k) != getattr(eb, k)
                    and not (k == "xattrs" and None in (ea.xattrs, eb.xattrs))]
            if meta:
                res = None
                for r in rules:
                    if r["kind"] == "metadata" and matches(r, p):
                        ok, detail = check_metadata(ea, eb, r)
                        if ok:
                            rule_hits[r["name"]] += 1
                            res = ("FLAGGED", p, r["name"], detail)
                            break
                results.append(res or ("ERROR", p, None, "metadata differs: " + ", ".join(
                    f"{k} {getattr(ea, k) if k != 'mode' else oct(ea.mode)} -> "
                    f"{getattr(eb, k) if k != 'mode' else oct(eb.mode)}" for k in meta)))
            if ea.kind != "-" or eb.kind != "-":
                continue
            fa, fb = os.path.join(ra, p), os.path.join(rb, p)
            try:
                with open(fa, "rb") as x, open(fb, "rb") as y:
                    da, db = x.read(), y.read()
            except OSError as e:
                results.append(("ERROR", p, None, f"cannot read: {e}"))
                continue
            if da == db:
                identical += 1
                continue
            ctx["differing"].add(p)
            pending.append((p, da, db))

        def classify(p, da, db, deferred):
            tried = []
            for r in rules:
                if r["kind"] == "metadata" or (r["kind"] in DEFERRED) != deferred:
                    continue
                if not matches(r, p):
                    continue
                try:
                    ok, detail = CHECKERS[r["kind"]](da, db, r, ctx, p)
                # A malformed file is a difference, not a crash.
                except Exception as e:  # pylint: disable=broad-exception-caught
                    ok, detail = False, f"{type(e).__name__}: {e}"
                if ok:
                    rule_hits[r["name"]] += 1
                    return ("FLAGGED", p, r["name"], detail)
                tried.append(f"{r['name']}: {detail}")
            if deferred is False and any(r["kind"] in DEFERRED and matches(r, p) for r in rules):
                return None
            detail = describe_binary_diff(da, db)
            if tried:
                detail += " [rules tried: " + " | ".join(tried) + "]"
            return ("ERROR", p, None, detail)

        later = []
        for p, da, db in pending:
            res = classify(p, da, db, False)
            if res is None:
                later.append((p, da, db))
            else:
                results.append(res)
        for p, da, db in later:
            results.append(classify(p, da, db, True))
    finally:
        if not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    results.sort(key=lambda r: (r[0] != "ERROR", r[1]))
    errors = sum(1 for r in results if r[0] == "ERROR")
    flagged = sum(1 for r in results if r[0] == "FLAGGED")
    by_rule = collections.defaultdict(list)
    for status, p, rule, detail in results:
        if status == "ERROR":
            print(f"ERROR    {p}\n         {detail}")
        else:
            by_rule[rule].append((p, detail))
    if not args.quiet:
        for rule, hits in by_rule.items():
            if args.verbose or len(hits) <= 5:
                for p, detail in hits:
                    print(f"FLAGGED  {p}  [{rule}]\n         {detail}")
            else:
                print(f"FLAGGED  {len(hits)} entries  [{rule}], e.g.\n"
                      f"         {hits[0][0]}: {hits[0][1]}")
    unused = [r["name"] for r in rules if not rule_hits[r["name"]]]
    print(f"\n{len(set(la) | set(lb))} entries, {identical} identical regular files, "
          f"{flagged} flagged, {errors} errors")
    if unused and not args.quiet:
        print("rules that matched nothing: " + ", ".join(unused))
    print(f"tool sha256 {tool_sha256}\nrules sha256 {rules_sha256} ({args.rules})")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"a": args.a, "b": args.b, "tool_sha256": tool_sha256,
                       "rules_sha256": rules_sha256, "identical": identical, "flagged": flagged,
                       "errors": errors, "unused_rules": unused,
                       "results": [{"status": s, "path": p, "rule": r, "detail": d}
                                   for s, p, r, d in results]},
                      fh, indent=1)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
