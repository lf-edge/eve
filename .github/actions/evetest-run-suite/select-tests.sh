#!/usr/bin/env bash
# Copyright (c) 2026, Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Turn a list of requested evetest names into the suites to run and an
# EVETEST_SKIP list.
#
# Usage: select-tests.sh <list-tests-output> "<name> <name> ..."
#
# Names may be suites, test cases or variants, as printed by `make -C evetest
# list-tests`. A requested suite runs entirely; a requested test case runs with
# all its variants; a requested variant runs alone. Everything else inside a
# selected suite is added to the skip list, except a variant named like its own
# test case: EVETEST_SKIP matches the case name too, so skipping that variant
# would skip its selected siblings. It runs instead. Prints
# {"suites": [...], "skip": [...]} to stdout; exits non-zero on unknown names.

set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <list-tests-output> \"<name> ...\"" >&2; exit 2; }

result=$(awk -v wanted="$2" '
BEGIN {
    n = split(wanted, w, " ")
    for (i = 1; i <= n; i++) want[w[i]] = 1
}
/^Test suites:/ { in_suites = 1; next }
/^Individual tests:/ { in_suites = 0; done = 1 }
done || !in_suites { next }
{
    sub(/[ \t\r]+$/, "")
    if ($0 == "") next
    match($0, /^ */)
    indent = RLENGTH
    text = substr($0, indent + 1)
    sub(/  +\[.*$/, "", text)
    if (indent == 2) {
        s++; suite[s] = text; nc[s] = 0
    } else if (indent == 4 && text ~ /^- /) {
        c = ++nc[s]; cname[s, c] = substr(text, 3); nv[s, c] = 0
    } else if (indent >= 8) {
        v = ++nv[s, nc[s]]; vname[s, nc[s], v] = text
    }
}
function add_skip(name) {
    if (!(name in skipped)) { skipped[name] = 1; skiplist = skiplist name " " }
}
END {
    for (i = 1; i <= s; i++) {
        known[suite[i]] = 1
        for (j = 1; j <= nc[i]; j++) {
            known[cname[i, j]] = 1
            for (k = 1; k <= nv[i, j]; k++) known[vname[i, j, k]] = 1
        }
    }
    bad = 0
    for (name in want) {
        if (!(name in known)) {
            printf "::error::unknown evetest name: %s\n", name > "/dev/stderr"
            bad = 1
        }
    }
    if (bad) exit 1

    for (i = 1; i <= s; i++) {
        if (suite[i] in want) { runlist = runlist suite[i] " "; continue }
        selected = 0
        delete pending
        np = 0
        for (j = 1; j <= nc[i]; j++) {
            if (cname[i, j] in want) {
                selected = 1
                continue
            }
            any = 0
            for (k = 1; k <= nv[i, j]; k++) if (vname[i, j, k] in want) any = 1
            if (any) {
                selected = 1
                for (k = 1; k <= nv[i, j]; k++)
                    if (!(vname[i, j, k] in want) && vname[i, j, k] != cname[i, j])
                        pending[++np] = vname[i, j, k]
            } else {
                pending[++np] = cname[i, j]
            }
        }
        if (selected) {
            runlist = runlist suite[i] " "
            for (p = 1; p <= np; p++) add_skip(pending[p])
        }
    }
    print runlist
    print skiplist
}
' "$1")

run_line=$(sed -n 1p <<<"$result")
skip_line=$(sed -n 2p <<<"$result")

jq -n -c --arg run "$run_line" --arg skip "$skip_line" \
    '{suites: ($run | split(" ") | map(select(length > 0))),
      skip: ($skip | split(" ") | map(select(length > 0)) | sort)}'
