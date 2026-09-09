#!/bin/bash
# Copyright (c) 2026, Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# shift-headings.sh <min-depth>
#
# Reads markdown from stdin and writes it to stdout with every heading
# shifted deeper by a fixed amount, so the *shallowest* heading present
# lands at exactly <min-depth> -- e.g. text starting at "#" (depth 1) piped
# through `shift-headings.sh 3` gets every heading prefixed with two more
# "#"s, nesting it under an existing depth-2 heading. A no-op if the
# shallowest heading is already at or deeper than <min-depth>, or if there
# are no headings at all.

set -u

MIN_DEPTH="$1"
TEXT=$(cat)

CURRENT_MIN=$(grep -oE '^#{1,6} ' <<<"$TEXT" | awk '{ print length($0) - 1 }' | sort -n | head -1 || true)
if [[ -z "$CURRENT_MIN" || "$CURRENT_MIN" -ge "$MIN_DEPTH" ]]; then
    printf '%s\n' "$TEXT"
    exit 0
fi

SHIFT=$((MIN_DEPTH - CURRENT_MIN))
PREFIX=$(printf '#%.0s' $(seq 1 "$SHIFT"))
sed -E "s/^(#{1,6})([[:space:]])/${PREFIX}\1\2/" <<<"$TEXT"
