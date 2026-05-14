#!/usr/bin/env bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Drive multiple Eden test suites against a single Eden lifetime.
# Per-suite EVE-tag verification + between-suite state reset.
#
# Usage:
#     tools/run_eden_suites.sh [flags] \
#         <label>:<suite-dir>:<scenario> [<label>:<suite-dir>:<scenario>...]
#
# Flags:
#     --coverage-dir <path>     pass --coverage-dir to each `eden test`;
#                               also runs `eden eve collect-coverage` at end
#     --assert-no-baseos        in pre-flight, abort if adam still has a
#                               baseos config (catches stale state from a
#                               prior aborted run; useful for baseos /
#                               nodeagent / update_eve_image suites)
#
# Required env (or set inline before invocation):
#     EDEN, EDEN_HOME, EVE_EXPECTED_TAG, EVE_SSH_KEY, EDEN_RUNLOGS
#
# This driver assumes eden + EVE are already set up and onboarded. The
# multi-suite phase is its only scope. For bring-up, see `make eden-cover`
# or the `run-eden-test` skill.
#
# See tools/README-coverage.md for a worked end-to-end example.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=tools/eden_run_lib.sh
. "$SCRIPT_DIR/eden_run_lib.sh"

usage() {
    sed -n '2,/^$/p; /^#/!q' "$0" | sed 's/^# \{0,1\}//'
    exit "$1"
}

assert_no_baseos=0
while [ $# -gt 0 ]; do
    case "$1" in
        --coverage-dir) EVE_COVERAGE_DIR="$2"; shift 2 ;;
        --assert-no-baseos) assert_no_baseos=1; shift ;;
        -h|--help) usage 0 ;;
        --) shift; break ;;
        -*) echo "error: unknown flag: $1" >&2; usage 1 ;;
        *) break ;;
    esac
done

if [ $# -eq 0 ]; then
    echo "error: at least one suite spec required" >&2
    usage 1
fi

# Caller env validation.
for v in EDEN EDEN_HOME EVE_EXPECTED_TAG EVE_SSH_KEY EDEN_RUNLOGS; do
    if [ -z "${!v:-}" ]; then
        echo "error: required environment variable $v is not set" >&2
        exit 1
    fi
done

mkdir -p "$EDEN_RUNLOGS"
[ -n "${EVE_COVERAGE_DIR:-}" ] && mkdir -p "$EVE_COVERAGE_DIR"

# Pre-flight: verify EVE is on the expected image, clear adam state,
# re-verify, optionally assert no leftover baseos config.
verify_eve_tag "pre-flight" || exit 1
eden_reset_state "pre-flight"
verify_eve_tag "pre-flight-post-reset" || exit 1

if [ "$assert_no_baseos" = "1" ]; then
    cfg=$("$EDEN" controller edge-node get-config 2>&1)
    if echo "$cfg" | grep -qE '"base_os_version"\s*:\s*"[^"]'; then
        echo "ABORT — adam still has baseos config after reset:" >&2
        echo "$cfg" | grep -E '"base_os_version"|"content_tree_uuid"' | head -5 >&2
        exit 1
    fi
fi

# Run each suite spec.
for spec in "$@"; do
    IFS=':' read -r label dir scenario <<<"$spec"
    if [ -z "$label" ] || [ -z "$dir" ] || [ -z "$scenario" ]; then
        echo "error: malformed spec '$spec' (want label:dir:scenario)" >&2
        exit 1
    fi
    run_eden_suite "$label" "$dir" "$scenario" || exit 1
done

# Optional: final coverage collect.
if [ -n "${EVE_COVERAGE_DIR:-}" ]; then
    echo "[final] eden eve collect-coverage at $(date)"
    "$EDEN" eve collect-coverage --output-dir "$EVE_COVERAGE_DIR" \
        > "$EDEN_RUNLOGS/coverage_final.log" 2>&1 \
        || echo "[final] coverage collect failed (see log)" >&2
fi

echo "[done] at $(date)"
