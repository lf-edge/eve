#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Account for every ima-ng ASCII record against an EVE rootfs manifest."""

import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import sys


def check(manifest, lines, image_mount_prefix=None):
    if manifest.get("schema_version") != 1 or manifest.get("hash_algorithm") != "sha256":
        raise ValueError("Unsupported manifest schema or hash algorithm")
    paths = collections.defaultdict(list)
    sources = collections.defaultdict(list)
    files = [entry for entry in manifest["entries"] if entry["type"] == "file"]
    by_source = {entry["source_path"]: entry for entry in files}
    if len(by_source) != len(files):
        raise ValueError("Duplicate manifest source paths")
    if len(files) != manifest["counts"]["files"]:
        raise ValueError("Manifest file count disagrees with entries")
    for entry in files:
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("Invalid manifest file digest")
        # The kernel replaces spaces with underscores before hashing n-ng.
        for path in {entry["path"], entry["source_path"]}:
            paths[path.replace(" ", "_")].append(entry)
        sources[entry["source_path"].replace(" ", "_")].append(entry)
    records = []
    seen = set()
    pcrs = {"sha1": bytes(20), "sha256": bytes(32)}
    replayable = True
    for number, line in enumerate(lines, 1):
        record = {"line": number, "raw": line.rstrip("\n")}
        records.append(record)
        try:
            fields = line.rstrip("\n").split(" ", 4)
            if len(fields) != 5:
                raise ValueError("Expected five ima-ng fields")
            pcr, template_hash, template, digest_field, path = fields
            if pcr != "10" or template != "ima-ng":
                raise ValueError("Expected PCR 10 and ima-ng")
            if not re.fullmatch(r"[0-9a-f]{40}", template_hash):
                raise ValueError("Invalid SHA-1 template digest")
            algorithm, digest = digest_field.split(":", 1)
            if algorithm != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Expected SHA-256 file digest")
            d = b"sha256:\0" + bytes.fromhex(digest)
            n = path.encode("utf-8", errors="surrogateescape") + b"\0"
            payload = struct.pack("<I", len(d)) + d + struct.pack("<I", len(n)) + n
            if template_hash == "0" * 40:
                if digest != "0" * 64:
                    raise ValueError("Nonzero file digest in violation record")
                for bank in pcrs:
                    event = b"\xff" * len(pcrs[bank])
                    pcrs[bank] = hashlib.new(bank, pcrs[bank] + event).digest()
                record.update(status="violation", path=path)
                continue
            if hashlib.sha1(payload).hexdigest() != template_hash:
                raise ValueError("Template digest does not match ASCII fields")
            for bank in pcrs:
                event = hashlib.new(bank, payload).digest()
                pcrs[bank] = hashlib.new(bank, pcrs[bank] + event).digest()
            record.update(path=path, sha256=digest)
            if number == 1 and path == "boot_aggregate":
                record["status"] = "boot_aggregate"
                continue
            candidates = paths.get(path, [])
            if image_mount_prefix and path.startswith(image_mount_prefix + "/"):
                candidates = sources.get(path[len(image_mount_prefix):], [])
                record["image_mount_alias"] = True
            matches = [entry for entry in candidates if entry["sha256"] == digest]
            if matches:
                record["status"] = "match"
                record["sources"] = sorted({entry["source_path"] for entry in matches})
                seen.update(record["sources"])
                record["ambiguous"] = len(record["sources"]) > 1
            elif candidates:
                record["status"] = "mismatch"
                record["expected"] = sorted({entry["sha256"] for entry in candidates})
            else:
                record["status"] = "unknown_path"
        except (ValueError, UnicodeError) as error:
            record.update(status="invalid", error=str(error))
            replayable = False
    if not records or records[0].get("status") != "boot_aggregate":
        replayable = False
    counts = dict(collections.Counter(record["status"] for record in records))
    def inode_group(path, visited=None):
        visited = set() if visited is None else visited
        if path in visited or path not in by_source:
            raise ValueError("Invalid manifest hardlink relationship")
        entry = by_source[path]
        if "hardlink_target" not in entry:
            return path
        target = by_source.get(entry["hardlink_target"])
        if not target or (entry["sha256"], entry["size"]) != (target["sha256"], target["size"]):
            raise ValueError("Inconsistent manifest hardlink content")
        return inode_group(entry["hardlink_target"], visited | {path})

    groups = {path: inode_group(path) for path in by_source}
    measured_groups = {groups[path] for path in seen}
    unobserved = sorted(path for path in by_source if path not in seen)
    return {
        "records": records, "counts": counts,
        "total_records": len(records), "manifest_files": len(files),
        "matched_sources": len(seen),
        "ambiguous_records": sum(record.get("ambiguous", False) for record in records),
        "unobserved_sources": unobserved,
        "unobserved_hardlink_aliases": [path for path in unobserved if groups[path] in measured_groups],
        "unobserved_inode_groups": sorted(set(groups.values()) - measured_groups),
        "replayed_pcr10": {bank: value.hex() for bank, value in pcrs.items()} if replayable else None,
        "ambiguity_notice": "ASCII paths do not identify mount namespaces; matching candidates do not prove container identity.",
        "source_coverage_notice": "Source coverage includes matching candidates from ambiguous namespaces and is not per-file attestation.",
        "image_mount_prefix": image_mount_prefix,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--measurements", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--pcr-sha1")
    parser.add_argument("--pcr-sha256")
    parser.add_argument("--image-mount-prefix", help="Explicit read-only mount of this exact rootfs image used for a scan")
    args = parser.parse_args()
    if args.output.resolve() in {args.manifest.resolve(), args.measurements.resolve()}:
        parser.error("Report must differ from input files")
    with args.manifest.open() as stream:
        manifest = json.load(stream)
    with args.measurements.open(encoding="utf-8", errors="surrogateescape") as stream:
        prefix = args.image_mount_prefix
        if prefix and (not prefix.startswith("/") or prefix == "/" or prefix.endswith("/")):
            parser.error("Image mount prefix must be an absolute directory without a trailing slash")
        report = check(manifest, stream, prefix)
    comparisons = {}
    for bank in ("sha1", "sha256"):
        expected = getattr(args, "pcr_" + bank)
        if expected is not None:
            if not re.fullmatch(r"[0-9a-f]{" + str(hashlib.new(bank).digest_size * 2) + r"}", expected):
                raise ValueError(f"Invalid {bank} PCR value")
            replay = report["replayed_pcr10"]
            comparisons[bank] = bool(replay and replay[bank] == expected)
    report["pcr_matches"] = comparisons
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in ("total_records", "counts", "manifest_files", "matched_sources", "pcr_matches")}, sort_keys=True))
    # Differences remain visible and fail closed; runtime files need their own baseline.
    return 1 if (not report["records"] or report["replayed_pcr10"] is None
                 or any(report["counts"].get(key, 0) for key in ("invalid", "violation", "mismatch", "unknown_path"))
                 or not all(comparisons.values())) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(f"IMA comparison failed: {error}")
