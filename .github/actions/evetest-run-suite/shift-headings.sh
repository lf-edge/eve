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

# Lines inside fenced code blocks are left alone.

set -u

MIN_DEPTH="$1"
TEXT=$(cat)

# Shared awk fragment: tracks whether the current line is inside a ``` or ~~~
# fenced block and whether it is a heading ("#" to "######" plus a space).
AWK_HEADING='
/^ *(```|~~~)/ { fence = !fence; next_is_fence = 1 }
{ heading = 0 }
!fence && !next_is_fence && match($0, /^#+ /) && RLENGTH - 1 <= 6 { heading = 1; depth = RLENGTH - 1 }
{ next_is_fence = 0 }
'

CURRENT_MIN=$(awk "$AWK_HEADING"'
heading && (min == "" || depth < min) { min = depth }
END { if (min != "") print min }' <<<"$TEXT")
if [[ -z "$CURRENT_MIN" || "$CURRENT_MIN" -ge "$MIN_DEPTH" ]]; then
    printf '%s\n' "$TEXT"
    exit 0
fi

SHIFT=$((MIN_DEPTH - CURRENT_MIN))
PREFIX=$(printf '#%.0s' $(seq 1 "$SHIFT"))
awk -v prefix="$PREFIX" "$AWK_HEADING"'
{ print (heading ? prefix : "") $0 }' <<<"$TEXT"
