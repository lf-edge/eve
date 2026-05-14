#!/usr/bin/env bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Reusable shell functions for driving multiple Eden test suites against
# a single Eden lifetime, with per-suite EVE-tag verification and
# between-suite state reset.
#
# Source this file from a driver script:
#     . "$(dirname "$0")/eden_run_lib.sh"
#
# Required environment (caller sets before sourcing or before calling):
#     EDEN              path to eden binary
#     EDEN_HOME         eden context dir (standard eden env var)
#     EVE_EXPECTED_TAG  e.g. "0.0.0-mybranch-deadbeef-kvm-amd64"
#     EVE_SSH_KEY       path to SSH key for the EVE qemu instance
#     EDEN_RUNLOGS      directory for per-suite log files (created if absent)
#
# Optional environment:
#     EVE_SSH_PORT      default 2222 (matches eden's default eve.hostfwd)
#     EVE_SSH_HOST      default 127.0.0.1
#     EVE_COVERAGE_DIR  if set, passed to `eden test --coverage-dir`
#     EDEN_RESET_SETTLE default 30 (seconds to wait after eden eve reset)

: "${EVE_SSH_PORT:=2222}"
: "${EVE_SSH_HOST:=127.0.0.1}"
: "${EDEN_RESET_SETTLE:=30}"

# eve_ssh <command> — run a one-shot SSH command against EVE.
# Removes stale known_hosts entries (qemu reboots shuffle host keys).
# Returns SSH's exit status; caller decides whether to retry.
eve_ssh() {
    ssh-keygen -f "$HOME/.ssh/known_hosts" \
        -R "[$EVE_SSH_HOST]:$EVE_SSH_PORT" >/dev/null 2>&1 || true
    ssh -i "$EVE_SSH_KEY" -p "$EVE_SSH_PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o LogLevel=ERROR \
        "root@$EVE_SSH_HOST" "$@"
}

# verify_eve_tag <label> [max_attempts] — SSH to EVE, check that
# /run/eve-release matches $EVE_EXPECTED_TAG. Retries until SSH is up
# or max_attempts is reached. Returns 0 if the tag matches, 1 otherwise.
verify_eve_tag() {
    local label="$1" max_attempts="${2:-30}" running raw
    for i in $(seq 1 "$max_attempts"); do
        raw=$(eve_ssh 'cat /run/eve-release' 2>&1)
        running=$(printf '%s' "$raw" | tr -d '\r' | grep -v '^$' | tail -1)
        # A well-formed tag looks like "<version>-<hv>-<arch>".
        if printf '%s' "$running" | grep -qE '^[0-9A-Za-z._-]+-(kvm|xen)-(amd64|arm64)$'; then
            break
        fi
        running=""
        echo "[$label] SSH not ready (attempt $i/$max_attempts); retrying in 10s..." >&2
        sleep 10
    done
    if [ -z "$running" ]; then
        echo "[$label] ABORT — could not read /run/eve-release" >&2
        return 1
    fi
    if [ "$running" != "$EVE_EXPECTED_TAG" ]; then
        echo "[$label] ABORT — EVE is running '$running', expected '$EVE_EXPECTED_TAG'" >&2
        return 1
    fi
    echo "[$label] EVE OK ($running)"
    return 0
}

# eden_reset_state <label> — clear adam-side config + bump epoch + settle.
# Logs to $EDEN_RUNLOGS/reset_<label>.log. Non-fatal on individual command
# failures (we expect transient failures during EVE reboots).
eden_reset_state() {
    local label="$1" log="$EDEN_RUNLOGS/reset_${label}.log"
    echo "[$label] eden reset"
    "$EDEN" eve reset > "$log" 2>&1 \
        || echo "[$label] WARNING: 'eden eve reset' failed (see $log)" >&2
    "$EDEN" eve epoch >> "$log" 2>&1 || true
    sleep "$EDEN_RESET_SETTLE"
}

# run_eden_suite <label> <suite-dir> <scenario> — run one suite, verify
# EVE didn't drift, reset state. Returns 0 on success, 1 if EVE drifted.
# The suite's own pass/fail rc is logged but doesn't gate this function —
# the caller decides what to do with it (typically: abort on drift,
# continue on suite failure).
run_eden_suite() {
    local label="$1" dir="$2" scenario="$3" rc
    local extra=()
    [ -n "${EVE_COVERAGE_DIR:-}" ] && extra+=(--coverage-dir "$EVE_COVERAGE_DIR")

    echo "================================================================"
    echo "[$label] Running (suite=$dir, scenario=$scenario) at $(date)"
    "$EDEN" test "$dir" -s "$scenario" -v debug "${extra[@]}" \
        > "$EDEN_RUNLOGS/${label}.log" 2>&1
    rc=$?
    echo "[$label] completed rc=$rc at $(date)"

    if ! verify_eve_tag "after-$label"; then
        echo "[$label] EVE drifted during this suite — aborting" >&2
        return 1
    fi
    eden_reset_state "after-$label"
    return 0
}
