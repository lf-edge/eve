#!/usr/bin/env python3
# Copyright (c) 2026, Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Add a tag to the image in a docker-format archive.

usage: add_repo_tag.py <archive.tar> <tag>

linuxkit exports an image under a single name. This writes a copy of the
archive whose manifest.json also lists <tag> in RepoTags, checks the copy and
replaces the archive with it. The archive is streamed entry by entry, never
edited in place (tar --delete corrupts archives of this size).
"""
import io
import json
import os
import sys
import tarfile


def main(path, tag):
    """Add tag to the RepoTags of the only image in the archive at path."""
    tmp = path + ".new"
    seen = False
    with tarfile.open(path, "r|") as src, tarfile.open(tmp, "w|") as dst:
        for member in src:
            data = src.extractfile(member) if member.isfile() else None
            if member.name != "manifest.json":
                dst.addfile(member, data)
                continue
            if seen:
                sys.exit(f"{path} has more than one manifest.json")
            seen = True
            manifest = json.load(data)
            if len(manifest) != 1:
                sys.exit(f"expected one image in {path}, found {len(manifest)}")
            tags = manifest[0].setdefault("RepoTags", [])
            if tag not in tags:
                tags.append(tag)
            raw = json.dumps(manifest, separators=(",", ":")).encode()
            member.size = len(raw)
            dst.addfile(member, io.BytesIO(raw))
    if not seen:
        sys.exit(f"{path} has no manifest.json")

    with tarfile.open(tmp, "r|") as check:
        for member in check:
            if member.name == "manifest.json":
                tags = json.load(check.extractfile(member))[0]["RepoTags"]
                break
        else:
            sys.exit("the rewritten archive has no manifest.json")
    if tag not in tags:
        sys.exit(f"the rewritten archive does not list {tag}: {tags}")
    os.replace(tmp, path)
    print(f"{path} now carries the tags: {', '.join(tags)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
