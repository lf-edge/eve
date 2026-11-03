#!/bin/bash
# Copyright (c) 2026, Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# pr-diff.sh <repo-dir> <base-ref> <head-ref> <out-dir>
#
# Computes a pull request's diff with git instead of `gh pr diff`: the API
# refuses PRs touching more than 300 files, which vendor bumps easily exceed.
# <repo-dir> must hold the full history of both refs (blobless is enough).
#
# Writes to <out-dir>:
#   pr.diff              the diff against the merge-base, vendored code excluded
#   pr-vendored.txt      vendored modules added, removed or bumped (may be empty)
set -euo pipefail

repo="$1" base="$2" head="$3" out="$4"

mb=$(git -C "$repo" merge-base "$base" "$head")
mkdir -p "$out"
git -C "$repo" diff "$mb" "$head" -- . ':(glob,exclude)**/vendor/**' > "$out/pr.diff"
git -C "$repo" diff --unified=0 "$mb" "$head" -- ':(glob)**/vendor/modules.txt' \
    | sed -nE -e 's#^\+\+\+ b/(.*)/modules\.txt$#\n\1:#p' -e 's#^([-+])\# (.*)$#  \1 \2#p' \
    > "$out/pr-vendored.txt"
echo "PR diff against merge-base $mb: $(wc -l < "$out/pr.diff") lines" \
    "($(grep -c '^  ' "$out/pr-vendored.txt" || true) vendored module changes omitted)"
