#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# check-sbom-coverage.sh
#
# CI check: every pkg/*/Dockerfile that pulls external source code MUST also
# call register-sbom-pkg.sh so that syft picks up the resulting package in the
# SBOM via the apk-db-cataloger.
#
# Heuristic:
#   - Count ADD lines targeting an external URL (ADD https://..., including
#     ADD --keep-git-dir=true https://... for git sources).
#   - Count register-sbom-pkg.sh invocations.
#   - If the Dockerfile fetches external sources but never calls the registry
#     helper, fail — unless the Dockerfile path is explicitly listed in
#     tools/sbom-coverage-allowlist.txt with a justification.
#
# Out of scope: Go modules (go.mod/go.sum) and Rust crates (Cargo.lock) are
# resolved by syft's language-specific catalogers and do not need apk-db
# entries. apk add ... is handled by Alpine's own apk database.

set -eu

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$ROOT"

ALLOWLIST_FILE="tools/sbom-coverage-allowlist.txt"

is_allowed() {
    [ -f "$ALLOWLIST_FILE" ] || return 1
    # Lines beginning with # are comments; blank lines ignored.
    grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST_FILE" | grep -qxF "$1"
}

failures=0
FAILED_FILES=""

for df in $(find pkg -type f -name Dockerfile | sort); do
    ext_fetches=$(grep -cE '^[[:space:]]*ADD([[:space:]]+--[a-z-]+(=[^[:space:]]+)?)*[[:space:]]+https?://' "$df" 2>/dev/null || true)
    [ "$ext_fetches" -gt 0 ] || continue

    registers=$(grep -cE 'register-sbom-pkg\.sh' "$df" 2>/dev/null || true)
    [ "$registers" -eq 0 ] || continue

    is_allowed "$df" && continue

    FAILED_FILES="$FAILED_FILES $df"
    failures=$((failures + 1))
done

if [ "$failures" -gt 0 ]; then
    echo ""
    echo "===== SBOM coverage check FAILED ====="
    echo ""
    for f in $FAILED_FILES; do
        # shellcheck disable=SC2086
        echo "  $f  (pulls external source via ADD but never calls register-sbom-pkg.sh)"
    done
    cat >&2 <<EOF

One or more Dockerfiles fetch external source code (ADD https:// or
ADD --keep-git-dir=...) but do not register the resulting package in the
APK DB via register-sbom-pkg.sh. Without that call, syft cannot include
the package in the final SBOM.

Either:

  1. Add a register-sbom-pkg.sh call after the build step that produces the
     binary/library, e.g.:

       RUN register-sbom-pkg.sh \\
           -n <name> -v <version> -l <SPDX-license> -u <upstream-url>

     See pkg/alpine/register-sbom-pkg.sh for the full interface, and
     pkg/dnsmasq/Dockerfile for a typical example.

  2. If the Dockerfile legitimately does not need a registration (e.g., the
     fetched artifact is a build-time toolchain that never reaches the final
     image, or the resulting binary is repackaged into another pkg that
     already covers the SBOM entry), add the Dockerfile path to
     ${ALLOWLIST_FILE} with a one-line justification comment.

EOF
    exit 1
fi

echo "SBOM coverage check passed: every Dockerfile with external source fetches calls register-sbom-pkg.sh."
