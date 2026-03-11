#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "restore-persist-certs.sh is deprecated; use ./manage-device-identity.sh instead." >&2
exec "${SCRIPT_DIR}/manage-device-identity.sh" "$@"
