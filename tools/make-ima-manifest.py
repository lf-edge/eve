#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Hash every regular file in a final EVE rootfs image for IMA comparisons."""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile


def digest_stream(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def source_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Invalid archive path: {name!r}")
    return "/" if str(path) == "." else "/" + str(path)


def identity(path):
    parts = PurePosixPath(path).parts
    # LinuxKit uses rootfs for ordinary containers and lower for overlays.
    if len(parts) >= 6 and parts[1] == "containers" and parts[2] in ("services", "onboot") and parts[4] in ("rootfs", "lower"):
        return f"{parts[2]}/{parts[3]}", "/" + "/".join(parts[5:])
    return "host", path


def entries_from_tar(stream):
    entries = {}
    skipped = collections.Counter()
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            path = source_path(member.name)
            if path in entries:
                raise ValueError(f"Duplicate final filesystem path: {path}")
            scope, runtime_path = identity(path)
            entry = {"source_path": path, "scope": scope, "path": runtime_path}
            if member.isfile():
                with archive.extractfile(member) as contents:
                    entry.update(type="file", size=member.size, sha256=digest_stream(contents))
            elif member.islnk():
                entry.update(type="file", hardlink_target=source_path(member.linkname))
            elif member.issym():
                entry.update(type="symlink", target=member.linkname)
            else:
                kind = "directory" if member.isdir() else "special"
                skipped[kind] += 1
                continue
            entries[path] = entry

    def resolve(entry, seen):
        if "sha256" in entry:
            return
        path = entry["source_path"]
        if path in seen:
            raise ValueError(f"Hardlink cycle at {path}")
        target = entries.get(entry["hardlink_target"])
        if target is None or target["type"] != "file":
            raise ValueError(f"Missing regular hardlink target for {path}")
        resolve(target, seen | {path})
        entry.update(size=target["size"], sha256=target["sha256"])

    for entry in entries.values():
        if entry["type"] == "file":
            resolve(entry, set())
    return [entries[path] for path in sorted(entries)], dict(sorted(skipped.items()))


def extract_entries(image, filesystem, extractor_image):
    # Extraction happens inside the existing rootfs builder container, never
    # on the host. The completed input image is mounted read-only.
    if filesystem == "squash":
        command = "unsquashfs -no-progress -processors 2 -d /tmp/rootfs /image.img >&2; tar -C /tmp/rootfs -cf - ."
    else:
        command = "mkdir -p /tmp/rootfs; mount -o loop,ro,noload /image.img /tmp/rootfs; trap 'umount /tmp/rootfs' EXIT; tar -C /tmp/rootfs -cf - ."
    docker = ["docker", "run", "--rm"]
    if filesystem == "ext4":
        docker.append("--privileged")
    docker += ["--volume", f"{image}:/image.img:ro", "--entrypoint", "/bin/sh", extractor_image, "-ec", command]
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(docker, stdout=subprocess.PIPE, stderr=errors)
        try:
            entries, skipped = entries_from_tar(process.stdout)
        except BaseException:
            process.stdout.close()
            process.wait()
            errors.seek(0)
            sys.stderr.write(errors.read().decode(errors="replace"))
            raise
        finally:
            process.stdout.close()
        status = process.wait()
        if status:
            errors.seek(0)
            raise RuntimeError(f"Rootfs extraction failed ({status}):\n{errors.read().decode(errors='replace')}")
    return entries, skipped


def write_manifest(output, manifest):
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output.parent, prefix=output.name + ".", delete=False) as stream:
            temporary = stream.name
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, output)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--format", required=True, choices=("squash", "ext4"))
    parser.add_argument("--extractor-image", required=True, help="EVE mkrootfs builder image containing extraction tools")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--kernel-tag", required=True)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    if args.output.resolve() == image:
        parser.error("Output must differ from the rootfs image")
    with image.open("rb") as stream:
        image_digest = digest_stream(stream)
    entries, skipped = extract_entries(image, args.format, args.extractor_image)
    with image.open("rb") as stream:
        if digest_stream(stream) != image_digest:
            raise ValueError("Rootfs image changed during manifest generation")
    files = sum(entry["type"] == "file" for entry in entries)
    if not files:
        raise ValueError("Extracted rootfs contains no regular files")
    manifest = {
        "schema_version": 1,
        "hash_algorithm": "sha256",
        "image": {"file": image.name, "format": args.format, "sha256": image_digest},
        "build": {"id": args.build_id, "architecture": args.arch, "platform": args.platform, "kernel_tag": args.kernel_tag},
        "counts": {"files": files, "symlinks": len(entries) - files, "unhashed": skipped},
        "entries": entries,
    }
    write_manifest(args.output, manifest)
    print(f"IMA manifest: {args.output} ({files} regular files, {len(entries) - files} symlinks)")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as error:
        sys.exit(f"IMA manifest failed: {error}")
