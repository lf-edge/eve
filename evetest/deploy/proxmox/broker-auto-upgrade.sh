#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Upgrades the evetest broker container on the broker VM to the latest
# version on a git repository branch, but only while the broker is idle: no
# evetest client is connected and no image upload ("evetest broker image") is
# claimed. Run periodically by evetest-broker-auto-upgrade.timer (see
# broker-cloudinit.yaml); every step logs to the journal of
# evetest-broker-auto-upgrade.service.
#
# The broker image tag is the content hash printed by evetest/content-hash.sh
# (see the evetest Makefile), so the latest version is computed by running
# that script on a shallow, sparse checkout of the branch. The image is pulled
# from the repository of the currently running image (e.g.
# lfedge/evetest-broker), which also tells whether that version has been
# published yet. A version whose broker does not come up is rolled back and
# tried again an hour later at the earliest, up to MAX_ATTEMPTS times.

set -eu

# EVETEST_AUTO_UPGRADE_REPO and EVETEST_AUTO_UPGRADE_BRANCH.
# shellcheck source=/dev/null
. /etc/evetest/auto-upgrade.env
# EVETEST_BROKER_IMAGE, the image evetest-broker.service runs.
IMAGE_ENV=/etc/evetest/broker-image.env
# shellcheck source=/dev/null
. "$IMAGE_ENV"

STATE_DIR=/var/lib/evetest-broker-auto-upgrade
REPO_DIR="$STATE_DIR/repo"
# One line per version that failed to start: "<tag> <attempts> <epoch>".
FAILED_TAGS="$STATE_DIR/failed-tags"
MAX_ATTEMPTS=3
RETRY_AFTER_SECS=3600
BROKER_PORT=50221
# An image with this label has "evetest-broker check-idle" (see
# Dockerfile.broker).
CHECK_IDLE_LABEL=org.lfedge.evetest.broker.check-idle
# A client disconnecting is followed by the teardown of its devices, so wait
# this long after seeing no clients and check again before restarting.
IDLE_GRACE_SECS=120
START_TIMEOUT_SECS=180

# Every evetest client keeps a gRPC stream open to the broker for its whole
# session, so an established connection on the broker port means a test runs.
# A broker that can tell also reports the sessions whose devices are still
# being torn down, and image uploads claimed by clients that are still
# fetching the image, which hold no connection meanwhile. Prints what keeps
# the broker busy.
idle() {
    if [ "$(ss -Htn state established "( sport = :$BROKER_PORT )" | wc -l)" -ne 0 ]; then
        echo "evetest clients are connected"
        return 1
    fi
    if [ "$(docker inspect -f "{{index .Config.Labels \"$CHECK_IDLE_LABEL\"}}" evetest-broker 2>/dev/null)" = true ]; then
        rc=0
        docker exec evetest-broker evetest-broker check-idle 2>&1 || rc=$?
        case "$rc" in
            0) ;;
            1) return 1 ;;
            *) echo "the broker cannot tell whether it is idle"; return 1 ;;
        esac
    fi
}

failed_attempts() {   # $1 = tag
    awk -v t="$1" '$1 == t { print $2 }' "$FAILED_TAGS"
}

last_failure() {   # $1 = tag
    awk -v t="$1" '$1 == t { print $3 }' "$FAILED_TAGS"
}

record_failure() {   # $1 = tag
    attempts="$(failed_attempts "$1")"
    attempts=$(( ${attempts:-0} + 1 ))
    { awk -v t="$1" '$1 != t' "$FAILED_TAGS"; echo "$1 $attempts $(date +%s)"; } > "$FAILED_TAGS.tmp"
    mv "$FAILED_TAGS.tmp" "$FAILED_TAGS"
}

broker_up() {   # $1 = image
    [ "$(docker inspect -f '{{.State.Running}} {{.Config.Image}}' evetest-broker 2>/dev/null)" = "true $1" ] &&
        [ -n "$(ss -Htln "( sport = :$BROKER_PORT )")" ]
}

set_image() {   # $1 = image
    printf 'EVETEST_BROKER_IMAGE=%s\n' "$1" > "$IMAGE_ENV.tmp"
    mv "$IMAGE_ENV.tmp" "$IMAGE_ENV"
}

if ! idle; then
    echo "the broker is busy, not upgrading"
    exit 0
fi

mkdir -p "$STATE_DIR"
touch "$FAILED_TAGS"

if [ "$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null)" != "$EVETEST_AUTO_UPGRADE_REPO" ]; then
    rm -rf "$REPO_DIR"
    git clone -q --depth 1 --filter=blob:none --sparse --no-checkout \
        "$EVETEST_AUTO_UPGRADE_REPO" "$REPO_DIR"
    git -C "$REPO_DIR" sparse-checkout set evetest
fi
git -C "$REPO_DIR" fetch -q --depth 1 origin "$EVETEST_AUTO_UPGRADE_BRANCH"
git -C "$REPO_DIR" checkout -q -f --detach FETCH_HEAD
git -C "$REPO_DIR" clean -q -fdx
COMMIT="$(git -C "$REPO_DIR" rev-parse --short HEAD)"
LATEST_TAG="$(sh "$REPO_DIR/evetest/content-hash.sh" framework)"

CURRENT_IMAGE="$EVETEST_BROKER_IMAGE"
CURRENT_TAG="${CURRENT_IMAGE##*:}"
NEW_IMAGE="${CURRENT_IMAGE%:*}:$LATEST_TAG"
if [ "$LATEST_TAG" = "$CURRENT_TAG" ]; then
    echo "broker $CURRENT_IMAGE is up to date with $EVETEST_AUTO_UPGRADE_BRANCH ($COMMIT)"
    exit 0
fi
ATTEMPTS="$(failed_attempts "$LATEST_TAG")"
if [ -n "$ATTEMPTS" ]; then
    if [ "$ATTEMPTS" -ge "$MAX_ATTEMPTS" ]; then
        echo "skipping $NEW_IMAGE: it failed to start $ATTEMPTS times" \
            "(remove it from $FAILED_TAGS to try again)"
        exit 0
    fi
    if [ "$(date +%s)" -lt "$(( $(last_failure "$LATEST_TAG") + RETRY_AFTER_SECS ))" ]; then
        echo "not retrying $NEW_IMAGE yet: it failed to start $ATTEMPTS time(s), last within an hour"
        exit 0
    fi
fi
if ! docker pull -q "$NEW_IMAGE" >/dev/null 2>&1; then
    echo "$NEW_IMAGE ($EVETEST_AUTO_UPGRADE_BRANCH at $COMMIT) is not published yet"
    exit 0
fi

sleep "$IDLE_GRACE_SECS"
if ! idle; then
    echo "the broker became busy meanwhile, not upgrading to $NEW_IMAGE"
    exit 0
fi

echo "upgrading broker from $CURRENT_IMAGE to $NEW_IMAGE ($EVETEST_AUTO_UPGRADE_BRANCH at $COMMIT)"
set_image "$NEW_IMAGE"
systemctl restart evetest-broker
waited=0
while [ "$waited" -lt "$START_TIMEOUT_SECS" ]; do
    if broker_up "$NEW_IMAGE"; then
        echo "broker upgraded to $NEW_IMAGE"
        exit 0
    fi
    sleep 5
    waited=$((waited + 5))
done

echo "broker $NEW_IMAGE did not come up within ${START_TIMEOUT_SECS}s, rolling back to $CURRENT_IMAGE" >&2
record_failure "$LATEST_TAG"
set_image "$CURRENT_IMAGE"
systemctl restart evetest-broker
exit 1
