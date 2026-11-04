#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# retry.sh runs a command up to 3 times, 15 seconds apart (RETRY_DELAY
# overrides the delay), so that a transient network failure (e.g. a
# proxy.golang.org TLS handshake timeout) does not fail the whole suite before
# any test runs.
#
# Usage: retry.sh <command> [args...]

attempts=3
delay=${RETRY_DELAY:-15}
i=1
while :; do
    "$@" && exit 0
    rc=$?
    if [ "$i" -ge "$attempts" ]; then
        echo "::error::'$*' failed $attempts times (last exit code $rc)"
        exit "$rc"
    fi
    echo "::warning::'$*' failed (attempt $i/$attempts, exit code $rc); retrying in ${delay}s"
    sleep "$delay"
    i=$((i + 1))
done
