#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=invalid-name
"""Positive controls for how eve-build-diff reads its inputs, on small squashfs
images and trees built here: a name with a newline, extended attributes,
docker: inputs, which must be named by digest and never run, globs that cross
a path segment, and volatile strings in code. docker is replaced by a stub on
PATH, so no image store is touched. Needs mksquashfs and gcc.

Usage: input-controls.py <workdir> [<tool> [<rules>]]
<tool> and <rules> select another version of eve-build-diff, to show that a
control fails against it.
"""
import json
import os
import struct
import subprocess
import sys

WORK = os.path.abspath(sys.argv[1])
TOOL = sys.argv[2] if len(sys.argv) > 2 else \
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "eve-build-diff.py")
RULES = ["--rules", sys.argv[3]] if len(sys.argv) > 3 else []
DIGEST_A, DIGEST_B = "a" * 64, "b" * 64

STUB = """#!/bin/sh
# docker stub: serves $STUB_DIR/<digest>.img as /bits/rootfs.img.
case "$1" in
create) echo "cid-${2##*@sha256:}" ;;
image) for a; do ref=$a; done
       case "$ref" in *@sha256:*) echo /bits/rootfs.img ;; *) exit 1 ;; esac ;;
cp) src=${2%%:*}; cp "$STUB_DIR/${src#cid-}.img" "$3" ;;
rm) ;;
*) echo "$*" >> "$STUB_DIR/forbidden.log"; exit 1 ;;
esac
"""


def tree(dirname, files):
    """Create directory dirname under WORK holding files {path: (mode, content)}."""
    root = os.path.join(WORK, dirname)
    subprocess.run(["rm", "-rf", root], check=True)
    for rel, (mode, content) in files.items():
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as out:
            out.write(content)
        os.chmod(full, mode)
    return root


def squash(root, *opts):
    """Pack root into root.img and return its path."""
    img = root + ".img"
    subprocess.run(["mksquashfs", root, img, "-noappend", "-all-root", "-quiet", *opts],
                   check=True, stdout=subprocess.DEVNULL)
    return img


def run(a, b, run_env=None, rules=()):
    """Run the tool; return (exit status, JSON report or None)."""
    report = os.path.join(WORK, "report.json")
    if os.path.exists(report):
        os.remove(report)
    cmd = [sys.executable, "-I", TOOL, "-q", "--json", report, *RULES, *rules, a, b]
    status = subprocess.run(cmd,
                            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=run_env).returncode
    if not os.path.exists(report):
        return status, None
    with open(report, encoding="utf-8") as report_fh:
        return status, json.load(report_fh)


os.makedirs(WORK, exist_ok=True)
base = {"usr/bin/tool": (0o755, "#!/bin/sh\necho ok\n"), "etc/passwd": (0o644, "root:x:0:0\n")}
img_a = squash(tree("a", base), "-no-xattrs")
img_hidden = squash(tree("hidden", dict(base, **{"usr/bin/tool\nx": (0o755, "#!/bin/sh\n")})),
                    "-no-xattrs")
xroot = tree("xattr", base)
os.setxattr(os.path.join(xroot, "usr/bin/tool"), "user.test", b"1")
img_xattr = squash(xroot, "-xattrs")
img_b = squash(tree("b", dict(base, **{"usr/bin/tool": (0o755, "#!/bin/sh\necho evil\n")})),
               "-no-xattrs")

stub_dir = os.path.join(WORK, "stub")
os.makedirs(stub_dir, exist_ok=True)
with open(os.path.join(stub_dir, "docker"), "w", encoding="utf-8") as stub_fh:
    stub_fh.write(STUB)
os.chmod(os.path.join(stub_dir, "docker"), 0o755)
subprocess.run(["cp", img_a, os.path.join(stub_dir, DIGEST_A + ".img")], check=True)
subprocess.run(["cp", img_b, os.path.join(stub_dir, DIGEST_B + ".img")], check=True)
forbidden = os.path.join(stub_dir, "forbidden.log")
env = dict(os.environ, PATH=stub_dir + os.pathsep + os.environ["PATH"], STUB_DIR=stub_dir)
dock_a, dock_b = f"docker:eve@sha256:{DIGEST_A}", f"docker:eve@sha256:{DIGEST_B}"

checks = []


def check(what, ok):
    """Record one control's outcome."""
    checks.append(ok)
    print(f"{'ok  ' if ok else 'MISS'} {what}")


rc, rep = run(img_a, img_a)
check("identical images: exit 0 (negative control)", rc == 0)
check("report names the tool and rules sha256",
      bool(rep) and all(len(rep.get(k, "")) == 64 for k in ("tool_sha256", "rules_sha256")))
rc, _ = run(img_a, img_hidden)
check("a file whose name has a newline: exit 1", rc == 1)
rc, _ = run(img_a, img_xattr)
check("an extended attribute in the image: exit 1", rc == 1)

if os.path.exists(forbidden):
    os.remove(forbidden)
rc, _ = run(dock_a, dock_a, env)
check("docker: same digest twice: exit 0 (negative control)", rc == 0)
rc, _ = run(dock_a, dock_b, env)
check("docker: a different rootfs.img: exit 1", rc == 1)
check("docker: the image is never run", not os.path.exists(forbidden))
rc, _ = run("docker:eve:latest", dock_a, env)
check("docker: a tag without a digest: exit 2", rc == 2)

PEM = ("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE" + "A" * 64
       + "\n-----END PUBLIC KEY-----\n")
key_rules = os.path.join(WORK, "keys.toml")
with open(key_rules, "w", encoding="utf-8") as rules_fh:
    rules_fh.write('[[rule]]\nname = "key"\nkind = "pem-public-key"\none_sided = true\n'
                   'paths = ["etc/keys/k-*.pub"]\n')
key_a = tree("keys-a", {"etc/keys/k-1.pub": (0o644, PEM)})
key_b = tree("keys-b", {"etc/keys/k-1.pub": (0o644, PEM), "etc/keys/k-2.pub/x.pub": (0o644, PEM)})
rc, _ = run(key_a, key_a, rules=("--rules", key_rules))
check("keys: identical trees: exit 0 (negative control)", rc == 0)
rc, _ = run(key_a, tree("keys-b2", {"etc/keys/k-1.pub": (0o644, PEM),
                                    "etc/keys/k-2.pub": (0o644, PEM)}),
            rules=("--rules", key_rules))
check("keys: a second key the glob names: exit 0 (negative control)", rc == 0)
rc, _ = run(key_a, key_b, rules=("--rules", key_rules))
check("keys: a key one directory below the glob: exit 1", rc == 1)

date_rules = os.path.join(WORK, "dates.toml")
with open(date_rules, "w", encoding="utf-8") as rules_fh:
    rules_fh.write('[[rule]]\nname = "date"\nkind = "volatile-strings"\n'
                   'paths = ["bin/*"]\npatterns = [\'\\d\\d/\\d\\d/\\d{4}\']\n')
src = os.path.join(WORK, "prog.c")
with open(src, "w", encoding="utf-8") as src_fh:
    src_fh.write('const char *date = "01/02/2024";\nint main(void) { return date[0]; }\n')
prog = os.path.join(WORK, "prog")
subprocess.run(["gcc", "-O1", "-o", prog, src], check=True)
with open(prog, "rb") as prog_fh:
    elf = prog_fh.read()
shoff, = struct.unpack_from("<Q", elf, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 0x3A)
hdrs = [struct.unpack_from("<IIQQQQ", elf, shoff + i * shentsize) for i in range(shnum)]
names = {elf[hdrs[shstrndx][4] + h[0]:elf.index(b"\0", hdrs[shstrndx][4] + h[0])]: h for h in hdrs}
text = names[b".text"][4]
in_data = elf.replace(b"01/02/2024", b"05/06/2025")
in_code_a = elf[:text] + b"01/02/2024" + elf[text + 10:]
in_code_b = elf[:text] + b"05/06/2025" + elf[text + 10:]
pairs = {}
for name, data in (("date-a", elf), ("date-b", in_data), ("code-a", in_code_a),
                   ("code-b", in_code_b)):
    pairs[name] = tree(name, {})
    os.makedirs(os.path.join(pairs[name], "bin"))
    with open(os.path.join(pairs[name], "bin", "prog"), "wb") as out_fh:
        out_fh.write(data)
rc, _ = run(pairs["date-a"], pairs["date-b"], rules=("--rules", date_rules))
check("dates: a date in .rodata: exit 0 (negative control)", rc == 0)
rc, _ = run(pairs["code-a"], pairs["code-b"], rules=("--rules", date_rules))
check("dates: date-shaped bytes in .text: exit 1", rc == 1)

sys.exit(0 if all(checks) else 1)
