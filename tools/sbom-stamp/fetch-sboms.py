#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Fetch the SBoM of every published variant of an EVE release.

Each variant (architecture, hypervisor and platform) ships different
packages: EVE-k adds kube and its Go modules, ai-generic glibc and the NVIDIA
userland, and the arm64 NVIDIA platforms their own images. update-licenses.py
and update-suppliers.py only see the packages of the documents they are
given, so they need every variant's. This finds the
lfedge/eve:<release>-[<platform>-]<hv>-<arch> images on Docker Hub and writes
the SPDX document from each one's /bits to <dir>/<tag>.spdx.json, streaming
the layer through oras rather than pulling the image:

    tools/sbom-stamp/fetch-sboms.py /tmp/sboms 0.0.0-master-<commit>
    tools/sbom-stamp/update-licenses.py /tmp/sboms/*.spdx.json

Use the release of one master commit: snapshot also matches variants that
are no longer published.
"""

# pylint: disable=invalid-name

import json
import os
import re
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request

REPO = "lfedge/eve"
TAGS = f"https://hub.docker.com/v2/repositories/{REPO}/tags"


def variants(release):
    """Return the single-architecture tags of release."""
    pattern = re.compile(re.escape(release)
                         + r"-(?:[a-z0-9-]+-)?(?:kvm|k|mini)-(?:amd64|arm64|riscv64)")
    url = f"{TAGS}?page_size=100&name=" + urllib.parse.quote(release + "-")
    tags = []
    while url:
        with urllib.request.urlopen(url, timeout=60) as resp:
            page = json.load(resp)
        tags += [t["name"] for t in page["results"] if pattern.fullmatch(t["name"])]
        url = page.get("next")
    return sorted(tags)


def oras(*args, **kwargs):
    """Run oras with args and return the process."""
    return subprocess.Popen(["oras", *args], stdout=subprocess.PIPE, **kwargs)


def sbom(tag, out):
    """Write the SPDX document in /bits of REPO:tag to out; return False if
    the image has none."""
    with oras("manifest", "fetch", f"docker.io/{REPO}:{tag}") as proc:
        manifest = json.load(proc.stdout)
    for layer in sorted(manifest["layers"], key=lambda l: -l["size"]):
        with oras("blob", "fetch", "--output", "-",
                  f"docker.io/{REPO}@{layer['digest']}") as proc, \
                tarfile.open(fileobj=proc.stdout, mode="r|*") as tar:
            for member in tar:
                if re.fullmatch(r"bits/[^/]*\.spdx\.json", member.name) and member.isfile():
                    with open(out, "wb") as doc:
                        doc.write(tar.extractfile(member).read())
                    proc.kill()
                    return True
    return False


def main(args):
    """Fetch the SBoMs of release args[1] into directory args[0]."""
    if len(args) != 2:
        sys.exit(__doc__)
    out_dir, release = args
    tags = variants(release)
    if not tags:
        sys.exit(f"no {REPO}:{release}-* images")
    os.makedirs(out_dir, exist_ok=True)
    for tag in tags:
        out = os.path.join(out_dir, tag + ".spdx.json")
        if sbom(tag, out):
            print(out)
        else:
            print(f"no SBoM: {REPO}:{tag}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
