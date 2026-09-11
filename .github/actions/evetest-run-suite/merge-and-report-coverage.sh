#!/bin/bash
# Copyright (c) 2026, Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# merge-and-report-coverage.sh <output-dir> <step-summary-heading> <comma-separated-coverage-dirs>
#
# Shared by evetest-run-suite's per-suite "Coverage summary" step and
# evetest-nightly's cross-suite "Merge and report overall coverage" step --
# the two differ only in how they arrive at <comma-separated-coverage-dirs>
# (a single suite's raw per-device directories vs. every suite's own
# already-merged output), everything after that is identical.
#
# "go tool covdata merge" aborts and discards its ENTIRE input on the first
# counter file it can't parse, so every covcounters file in the given dirs
# is first validated individually against its covmeta by actually trying
# to read it with "go tool covdata percent" -- corruption isn't necessarily
# visible as a 0 byte file, so this checks by reading it rather than by
# size. Anything that fails is moved aside into a "quarantined"
# subdirectory and reported as a "::warning::". The caller does not need
# to know about this convention: any "quarantined" directory already
# present in <comma-separated-coverage-dirs> (e.g. restored from a
# previous failed attempt's packaged artifacts) is skipped here too,
# rather than merged as if it were a fresh coverage directory.
#
# The rest is merged into <output-dir>, and the coverage percentage is
# appended under <step-summary-heading> to $GITHUB_STEP_SUMMARY. Also
# writes <output-dir>.txt (Go's textfmt), for a caller that wants a
# line-by-line report (e.g. "go tool cover -html").

set -u

OUT_DIR="$1"
HEADING="$2"
COVER_DIRS="$3"

BAD=0
CLEAN_DIRS=""
for DIR in $(echo "$COVER_DIRS" | tr ',' '\n'); do
    case "$DIR" in
    */quarantined | */quarantined/*) continue ;;
    esac
    DIR=$(cd "$DIR" && pwd) || continue
    CLEAN_DIRS="${CLEAN_DIRS:+$CLEAN_DIRS,}$DIR"
    META=$(find "$DIR" -maxdepth 1 -name 'covmeta.*' 2>/dev/null | head -1)
    [ -n "$META" ] || continue
    for F in "$DIR"/covcounters.*; do
        [ -f "$F" ] || continue
        CHECK=$(mktemp -d)
        ln -s "$META" "$CHECK/"
        ln -s "$F" "$CHECK/"
        if ! go tool covdata percent -i="$CHECK" >/dev/null 2>&1; then
            echo "::warning::discarding unparsable coverage file: $F"
            mkdir -p "$DIR/quarantined"
            mv "$F" "$DIR/quarantined/"
            BAD=$((BAD + 1))
        fi
        rm -rf "$CHECK"
    done
done
if [ "$BAD" -gt 0 ]; then
    echo "Discarded $BAD unparsable coverage file(s) before merging." | tee -a "$GITHUB_STEP_SUMMARY"
fi

mkdir -p "$OUT_DIR"
go tool covdata merge -i "$CLEAN_DIRS" -o "$OUT_DIR"
echo "$HEADING" >> "$GITHUB_STEP_SUMMARY"
go tool covdata percent -i "$OUT_DIR" | tee -a "$GITHUB_STEP_SUMMARY"
go tool covdata textfmt -i "$OUT_DIR" -o "$OUT_DIR.txt"
TOTAL=$(cd pkg/pillar && go tool cover -func="$OUT_DIR.txt" | tail -1)
echo "$TOTAL"
echo "**$TOTAL**" >> "$GITHUB_STEP_SUMMARY"
