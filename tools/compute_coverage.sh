#!/usr/bin/env bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Compute aggregate block coverage from one or more Go coverage text
# profiles. Each (file, range) block is counted once and is considered
# covered if ANY input profile recorded a non-zero hit for it.
#
# This matters because `make coverage-merge` concatenates profiles
# without deduplicating — a block hit by both unit tests and Eden e2e
# appears as two lines in the combined file. A naive
# `awk '$3>0{c++} END{print c}'` over the combined file would
# double-count. Using this script instead produces the correct union.
#
# Usage:
#     tools/compute_coverage.sh <label> <file1.txt> [file2.txt ...]
#
# Output format (one line, label left-padded):
#     <label>           <covered> / <total> = <pct> %
#
# Examples:
#     tools/compute_coverage.sh "unit"                 pkg/pillar/coverage.txt
#     tools/compute_coverage.sh "unit + eden"          \
#         pkg/pillar/coverage.txt \
#         dist/amd64/current/eden_coverage/eden_e2e_coverage.txt
#     tools/compute_coverage.sh "unit + eden + extras" \
#         pkg/pillar/coverage.txt \
#         dist/amd64/current/eden_coverage/eden_e2e_coverage.txt \
#         dist/amd64/current/combined_coverage.txt
#
# Filter co-located: tools/filter_coverage_conflicts.py is discovered
# relative to this script, so the script is portable across workspaces.

set -euo pipefail

usage() {
    sed -n '2,/^$/p; /^#/!q' "$0" | sed 's/^# \{0,1\}//'
    exit "$1"
}

case "${1:-}" in
    -h|--help) usage 0 ;;
    "") echo "error: missing <label>" >&2; usage 1 ;;
esac

if [ "$#" -lt 2 ]; then
    echo "error: at least one coverage file is required" >&2
    usage 1
fi

LABEL=$1; shift

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
FILTER="$SCRIPT_DIR/filter_coverage_conflicts.py"
if [ ! -f "$FILTER" ]; then
    echo "error: filter_coverage_conflicts.py not found at $FILTER" >&2
    exit 1
fi

for f in "$@"; do
    if [ ! -f "$f" ]; then
        echo "error: input not found: $f" >&2
        exit 1
    fi
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

OUT=$WORK/merged.txt
echo "mode: atomic" > "$OUT"
for f in "$@"; do
    # Drop the per-file "mode:" header (first line); concatenate the rest.
    tail -n +2 "$f"
done >> "$OUT"

# Filter conflicting NumStmt entries (warnings go to stderr; let them through).
FILTERED=$WORK/filtered.txt
python3 "$FILTER" "$OUT" "$FILTERED"

# Dedup blocks by (file, range). A block counts once toward "total"; it is
# "covered" if any of its occurrences across the input profiles has a
# non-zero hit count.
awk -v LABEL="$LABEL" '
NR == 1 { next }              # skip the merged "mode: atomic" header
NF == 3 {
    key = $1
    count = $3
    if (!(key in seen)) {
        seen[key] = 1
        max_count[key] = count
        total++
    } else if (count > 0) {
        max_count[key] = count
    }
}
END {
    for (k in max_count) if (max_count[k] > 0) covered++
    pct = (total > 0) ? (100.0 * covered / total) : 0.0
    printf "%-50s %6d / %6d = %5.2f %%\n", LABEL, covered, total, pct
}
' "$FILTERED"
