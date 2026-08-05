#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# merge-sbom-db.sh - Merge APK DBs into one, dropping duplicate packages.
#
# Usage:
#   merge-sbom-db.sh -o <output> <input> [<input> ...]
#
# Use this instead of "cat a b >> db" whenever several stages contribute
# packages to one image's SBOM.
#
# apk keeps one record per package and identifies it by its C: checksum. Any two
# DBs built on an Alpine rootfs share its base packages, so concatenating them
# yields duplicate checksums: apk frees a still-referenced package (SIGSEGV) and
# the SBOM double-counts.
#
# First record per name wins, so list the image's own DB first. Missing inputs
# are skipped so arch-specific stages that contribute nothing don't break builds.
#
set -e

usage() {
    echo "Usage: $0 -o <output> <input> [<input> ...]" >&2
    exit 1
}

OUTFILE=""

while getopts "o:" opt; do
    case "$opt" in
        o) OUTFILE="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

[ -n "$OUTFILE" ] || { echo "ERROR: -o (output) is required" >&2; usage; }
[ $# -gt 0 ]      || { echo "ERROR: at least one input DB is required" >&2; usage; }

INPUTS=""
for db in "$@"; do
    if [ -f "$db" ]; then
        INPUTS="$INPUTS $db"
    else
        echo "merge-sbom-db.sh: skipping missing $db" >&2
    fi
done
[ -n "$INPUTS" ] || { echo "ERROR: none of the input DBs exist" >&2; exit 1; }

mkdir -p "$(dirname "$OUTFILE")"

# The output is usually also an input, so build the result aside first.
TMPFILE="$(mktemp)"
trap 'rm -f "$TMPFILE"' EXIT

# Paragraph mode keys on blank-line separated records; busybox awk supports RS="".
# shellcheck disable=SC2086
awk 'BEGIN { RS = ""; FS = "\n" }
{
    name = ""
    for (i = 1; i <= NF; i++)
        if (substr($i, 1, 2) == "P:") { name = substr($i, 3); break }
    if (name == "" || (name in seen)) next
    seen[name] = 1
    printf "%s\n\n", $0
    kept++
}
END { printf "merged %d packages\n", kept > "/dev/stderr" }' $INPUTS > "$TMPFILE"

cat "$TMPFILE" > "$OUTFILE"

echo "Merged$INPUTS into $OUTFILE"
