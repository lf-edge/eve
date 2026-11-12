#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Add declared licenses for Go modules and Rust crates to licenses.txt.

Go build info records no license, and the scanner does not read the module
source. For each package in the given SPDX documents that has a golang or
cargo purl and no license, or the license licenses.txt gives it, this asks
deps.dev for the licenses it found in that version's source and adds them
joined with AND. A package whose versions disagree gets one entry per version.
Existing entries are kept, so a curated entry overrides the lookup; the ones
deps.dev disagrees with are printed. Each variant ships different modules, so
run it on the SBoMs of all of them, which fetch-sboms.py gets for a published
master commit:

    tools/sbom-stamp/fetch-sboms.py /tmp/sboms 0.0.0-master-<commit>
    tools/sbom-stamp/update-licenses.py /tmp/sboms/*.spdx.json

For a change not yet published, add the SBoM of each variant it touches, from
make ZARCH=<arch> HV=<hv> PLATFORM=<platform> pkgs sbom. It prints the
packages it could not resolve; add those by hand.
"""

# pylint: disable=invalid-name

import concurrent.futures
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses.txt")
API = "https://api.deps.dev/v3/systems"
SYSTEM = {"golang": "go", "cargo": "cargo"}
# The license expressions sbom-stamp accepts.
EXPR = re.compile(r"^\(*[A-Za-z0-9.+-]+\)*(?: (?:AND|OR|WITH) \(*[A-Za-z0-9.+-]+\)*)*$")


def split(purl):
    """Return purl without version, qualifiers and subpath, and its version."""
    for sep in "#?":
        purl = purl.split(sep, 1)[0]
    base, _, version = purl.partition("@")
    return base, version


def lookup(entries, purl):
    """Return the license of the purl's version, else of its longest prefix,
    as sbom-stamp does."""
    base, version = split(purl)
    if version and f"{base}@{version}" in entries:
        return entries[f"{base}@{version}"]
    key = base
    while key.startswith("pkg:"):
        if key in entries:
            return entries[key]
        if "/" not in key:
            break
        key = key.rsplit("/", 1)[0]
    return ""


def read_map():
    """Return the leading comment lines of licenses.txt and its entries."""
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
    """Replace licenses.txt with header and entries sorted by prefix."""
    tmp = MAP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as map_file:
        map_file.write("\n".join(header) + "\n")
        for prefix in sorted(entries):
            map_file.write(f"{prefix}\t{entries[prefix]}\n")
    os.replace(tmp, MAP)


def wanted(paths, entries):
    """Return the golang and cargo (base, version) pairs without a license
    other than the one licenses.txt gives."""
    pairs = set()
    for path in paths:
        with open(path, encoding="utf-8") as doc_file:
            doc = json.load(doc_file)
        for pkg in doc.get("packages", []):
            declared = pkg.get("licenseDeclared", "NOASSERTION")
            for ref in pkg.get("externalRefs", []):
                purl = ref.get("referenceLocator", "")
                if ref.get("referenceType") != "purl" or \
                        purl.split("/", 1)[0] not in ("pkg:golang", "pkg:cargo"):
                    continue
                if declared in ("", "NOASSERTION") or declared == lookup(entries, purl):
                    pairs.add(split(purl))
    return sorted(pairs)


def licenses(pair):
    """Return the deps.dev license expression of a (base, version), or ""."""
    base, version = pair
    kind, name = base[len("pkg:"):].split("/", 1)
    if not version:
        return pair, ""
    url = (f"{API}/{SYSTEM[kind]}/packages/"
           + urllib.parse.quote(urllib.parse.unquote(name), safe="")
           + "/versions/" + urllib.parse.quote(urllib.parse.unquote(version), safe=""))
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            found = json.load(resp).get("licenses", [])
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return pair, ""
        raise
    # deps.dev reports a license file it cannot classify as non-standard.
    expr = " AND ".join(found)
    return pair, expr if EXPR.match(expr) and "non-standard" not in found else ""


def add(entries, base, versions):
    """Add entries for the deps.dev licenses of the versions of base that
    licenses.txt does not map to that license, print the ones it maps to
    another, and return the purls neither resolves."""
    added, unresolved = {}, []
    for version, expr in sorted(versions.items()):
        purl = f"{base}@{version}" if version else base
        mapped = lookup(entries, purl)
        if not expr:
            if not mapped:
                unresolved.append(purl)
        elif mapped == expr:
            continue
        elif mapped and (purl in entries or base in entries):
            print(f"differs: {purl}: licenses.txt {mapped}, deps.dev {expr}", file=sys.stderr)
        else:
            # Unmapped, or mapped by a shorter prefix, which a nested Go
            # module with its own license overrides.
            added[version] = expr
    if len(added) == len(versions) and len(set(added.values())) == 1:
        entries[base] = next(iter(added.values()))
    else:
        for version, expr in added.items():
            entries[f"{base}@{version}"] = expr
    return unresolved


def main(paths):
    """Add entries for the packages in the SPDX documents at paths."""
    if not paths:
        sys.exit(__doc__)
    header, entries = read_map()
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        found = dict(pool.map(licenses, wanted(paths, entries)))
    by_base = {}
    for (base, version), expr in found.items():
        by_base.setdefault(base, {})[version] = expr
    unresolved = []
    for base, versions in sorted(by_base.items()):
        unresolved += add(entries, base, versions)
    write_map(header, entries)
    for purl in unresolved:
        print(f"unresolved: {purl}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
