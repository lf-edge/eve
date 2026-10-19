#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Add suppliers for Go modules and Rust crates to suppliers.txt.

The scanner has no supplier for these: Go build info and cargo-sbom record
none. For each package in the given SPDX documents that has a golang or cargo
purl, no supplier and no entry in suppliers.txt, this looks up the owner of
its source repository on ecosyste.ms, as snyk/parlay does, and adds it as
Organization or Person. A Go module under github.com gets one entry for its
owner. Existing entries are kept, so a curated entry overrides the lookup.
Run it on the SBoM of a fresh build after Cargo.lock or go.mod files change:

    tar -xOf dist/amd64/current/rootfs-generic.tar sbom.spdx.json > /tmp/sbom.json
    tools/sbom-stamp/update-suppliers.py /tmp/sbom.json

It prints the packages it could not resolve; add those by hand.
"""

# pylint: disable=invalid-name

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "suppliers.txt")
API = "https://packages.ecosyste.ms/api/v1/registries"
REGISTRY = {"golang": "proxy.golang.org", "cargo": "crates.io"}
# ecosyste.ms answers 403 to urllib's default User-Agent.
AGENT = "lf-edge-eve-update-suppliers (https://github.com/lf-edge/eve)"


def base(purl):
    """Return purl without version, qualifiers and subpath."""
    for sep in "#?@":
        purl = purl.split(sep, 1)[0]
    return purl


def lookup(entries, purl):
    """Return the supplier of the longest matching prefix, as sbom-stamp does."""
    key = base(purl)
    while key.startswith("pkg:"):
        if key in entries:
            return entries[key]
        if "/" not in key:
            break
        key = key.rsplit("/", 1)[0]
    return ""


def read_map():
    """Return the leading comment lines of suppliers.txt and its entries."""
    header, entries = [], {}
    with open(MAP, encoding="utf-8") as map_file:
        for line in map_file:
            line = line.rstrip("\n")
            if not entries and (line.startswith("#") or not line):
                header.append(line)
            elif line and not line.startswith("#"):
                prefix, value = line.split("\t", 1)
                entries[prefix] = value
    return header, entries


def write_map(header, entries):
    """Replace suppliers.txt with header and entries sorted by prefix."""
    tmp = MAP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as map_file:
        map_file.write("\n".join(header) + "\n")
        for prefix in sorted(entries):
            map_file.write(f"{prefix}\t{entries[prefix]}\n")
    os.replace(tmp, MAP)


def wanted(paths, entries):
    """Return the supplier-less golang and cargo purls the map does not cover."""
    purls = set()
    for path in paths:
        with open(path, encoding="utf-8") as doc_file:
            doc = json.load(doc_file)
        for pkg in doc.get("packages", []):
            if pkg.get("supplier", "NOASSERTION") not in ("", "NOASSERTION"):
                continue
            for ref in pkg.get("externalRefs", []):
                purl = ref.get("referenceLocator", "")
                kind = purl.split("/", 1)[0]
                if ref.get("referenceType") == "purl" and kind in ("pkg:golang", "pkg:cargo"):
                    if not lookup(entries, purl):
                        purls.add(base(purl))
    return sorted(purls)


def owner(kind, name):
    """Return the ecosyste.ms owner record of a package's repository, or None."""
    url = f"{API}/{REGISTRY[kind]}/packages/{urllib.parse.quote(name, safe='')}"
    for _ in range(5):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": AGENT})
            with urllib.request.urlopen(req, timeout=60) as resp:
                pkg = json.load(resp)
            return (pkg.get("repo_metadata") or {}).get("owner_record") or None
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return None
            if err.code != 429 and err.code < 500:
                raise
            reset = err.headers.get("x-ratelimit-reset", "")
            wait = int(reset) - int(time.time()) if reset.isdigit() else 60
            time.sleep(min(max(wait, 10), 900))
    raise RuntimeError(f"{url}: still failing after retries")


def supplier(rec):
    """Return an SPDX supplier for an owner record, or "" if it names none."""
    name = (rec.get("name") or rec.get("login") or "").strip()
    if not name or rec.get("kind") not in ("organization", "user"):
        return ""
    name = " ".join(name.replace("(", "").replace(")", "").split())
    return ("Organization: " if rec["kind"] == "organization" else "Person: ") + name


def main(paths):
    """Add entries for the packages in the SPDX documents at paths."""
    if not paths:
        sys.exit(__doc__)
    header, entries = read_map()
    unresolved = []
    for count, purl in enumerate(wanted(paths, entries), 1):
        if lookup(entries, purl):
            continue
        kind, name = purl[len("pkg:"):].split("/", 1)
        name = urllib.parse.unquote(name)
        rec = owner(kind, name)
        found = supplier(rec) if rec else ""
        if not found:
            unresolved.append(purl)
            continue
        parts = name.split("/")
        if kind == "golang" and parts[0] == "github.com" and len(parts) > 1:
            entries[f"pkg:golang/github.com/{parts[1]}"] = found
        else:
            entries[purl] = found
        if count % 50 == 0:
            write_map(header, entries)
    write_map(header, entries)
    for purl in unresolved:
        print(f"unresolved: {purl}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
