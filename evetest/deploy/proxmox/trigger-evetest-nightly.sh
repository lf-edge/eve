#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# trigger-evetest-nightly.sh - dispatch a evetest-nightly.yml run via the
# GitHub API. Meant to be driven by your own cron (e.g. on a runner VM),
# since GitHub's own `schedule` trigger is documented to be best-effort and
# can drift under platform load.
#
#   GH_TOKEN=<token> trigger-evetest-nightly.sh --gh-repo <owner>/eve --branch <branch>
set -eu

GH_REPO=""
WORKFLOW="evetest-nightly.yml"
REF=""
COVERAGE="false"
# GH_TOKEN (environment) needs "Actions: read and write" permission
# (fine-grained PAT) or the classic "repo" scope, on the target repository.
GH_TOKEN="${GH_TOKEN:-}"

usage() {
    cat <<USAGE
Usage: GH_TOKEN=<token> trigger-evetest-nightly.sh --gh-repo OWNER/REPO --branch BRANCH [flags]

Dispatches a workflow_dispatch run of evetest-nightly.yml via the GitHub API.

Required:
  --gh-repo OWNER/REPO   Repository to dispatch the workflow in.
  --branch BRANCH        Branch/tag to run the workflow on (alias: --ref).

Optional:
  --workflow NAME_OR_ID  Workflow file name or numeric ID. Default: $WORKFLOW
  --collect-coverage     Set the collect-coverage workflow input to true.
  -h, --help             Show this help.

Environment:
  GH_TOKEN               GitHub token used to authenticate (required).
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --gh-repo)   GH_REPO="$2"; shift 2 ;;
        --workflow)  WORKFLOW="$2"; shift 2 ;;
        --branch|--ref) REF="$2"; shift 2 ;;
        --collect-coverage) COVERAGE="true"; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "error: unknown flag: $1" >&2; usage >&2; exit 2 ;;
    esac
done

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
need curl

[ -n "$GH_REPO" ] || die "--gh-repo is required"
[ -n "$REF" ] || die "--branch is required"
[ -n "$GH_TOKEN" ] || die "GH_TOKEN environment variable is required"

RESPONSE_FILE=$(mktemp)
trap 'rm -f "$RESPONSE_FILE"' EXIT

HTTP_STATUS=$(curl -s -o "$RESPONSE_FILE" -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${GH_REPO}/actions/workflows/${WORKFLOW}/dispatches" \
    -d "{\"ref\":\"${REF}\",\"inputs\":{\"collect-coverage\":\"${COVERAGE}\"}}")

if [ "$HTTP_STATUS" = "204" ]; then
    echo "Dispatched ${WORKFLOW} on ${GH_REPO}@${REF} (collect-coverage=${COVERAGE})."
    exit 0
fi

echo "error: dispatch failed (HTTP $HTTP_STATUS)" >&2
cat "$RESPONSE_FILE" >&2
exit 1
