#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

if [ -z "$EVETEST_NAME" ]; then
    exec /usr/local/bin/list-tests
fi

# Create artifact directory for this test execution
TIMESTAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
export EVETEST_ARTIFACT_DIR="/artifacts/${EVETEST_NAME}-${TIMESTAMP}"
mkdir -p "$EVETEST_ARTIFACT_DIR"
# Write the artifact dir path so CI can locate it after the container exits.
echo "$EVETEST_ARTIFACT_DIR" > /artifacts/.last-artifact-dir

BROKER_PID=""
if [ -z "$EVETEST_BROKER_ADDRESS" ]; then
  # Run broker inside the container (the all-in-one deployment mode)
  export EVETEST_BROKER_DEVICE_PROVIDER=qemu
  evetest-broker >"${EVETEST_ARTIFACT_DIR}/broker-output" 2>&1 &
  BROKER_PID=$!
fi

# Enable use of the Adam CLI inside the container for troubleshooting and debugging.
# This installs a small wrapper that automatically configures Adam connection
# parameters before invoking the real CLI.
cat <<EOF > /etc/adam-cli.conf
export ADAM_SERVER=https://245.245.245.245:443
export ADAM_SERVER_CA=${EVETEST_ARTIFACT_DIR}/adam-certs/server.pem
EOF

cat <<'EOF' > /usr/local/bin/adam-cli
#!/bin/sh
set -e
. /etc/adam-cli.conf
exec adam "$@"
EOF

chmod +x /usr/local/bin/adam-cli

# Run go test in background
GO_TEST_FLAGS="-v"
GO_TEST_OUTPUT_FILE="${EVETEST_ARTIFACT_DIR}/gotest.txt"

if [ -n "$EVETEST_OUTPUT_FORMAT" ]; then
    case "$(printf '%s' "$EVETEST_OUTPUT_FORMAT" | tr '[:upper:]' '[:lower:]')" in
        json)
            GO_TEST_FLAGS="-json"
            GO_TEST_OUTPUT_FILE="${EVETEST_ARTIFACT_DIR}/gotest.json"
            ;;
        quiet)
            GO_TEST_FLAGS=""
            # Warn if pause-on-failure or pause-on-checkpoint is also set:
            # without -v, go test buffers all output until the test completes,
            # so a pause will appear frozen with no visible output.
            if [ -n "$EVETEST_PAUSE_ON_CHECKPOINT" ] || \
               { [ -n "$EVETEST_PAUSE_ON_FAILURE" ] && \
                 [ "$EVETEST_PAUSE_ON_FAILURE" != "false" ] && \
                 [ "$EVETEST_PAUSE_ON_FAILURE" != "0" ]; }; then
                echo "WARNING: EVETEST_OUTPUT_FORMAT=quiet combined with pause-on-failure/checkpoint" \
                     "will suppress all output while the test is paused. Use verbose output instead." >&2
            fi
            ;;
    esac
fi

echo "Starting test: $EVETEST_NAME"

# shellcheck disable=SC3001  # process substitution is supported by bash (used in golang image)
go test $GO_TEST_FLAGS -timeout 0 -parallel 1 -p 1 \
        -run "^${EVETEST_NAME}$" ./tests/... > >(tee "$GO_TEST_OUTPUT_FILE") &
GO_TEST_PID=$!

# Setup signal handler for cleanup
# shellcheck disable=SC2317,SC2015  # false positives: function is called via trap
cleanup() {
    echo "Received termination signal, forwarding to child processes..."
    [ -n "$GO_TEST_PID" ] && kill -TERM "$GO_TEST_PID" 2>/dev/null || true
    [ -n "$BROKER_PID" ] && kill -TERM "$BROKER_PID" 2>/dev/null || true

    # Wait for go test to exit
    [ -n "$GO_TEST_PID" ] && wait_with_timeout "go-test" "$GO_TEST_PID" 15
    set_artifact_ownership

    # Wait for broker to exit
    [ -n "$BROKER_PID" ] && wait_with_timeout "broker" "$BROKER_PID" 15
    echo "Cleanup completed"
    exit 0
}

# Make sure the artifacts are readable for the user.
set_artifact_ownership() {
    if [ -n "$EVETEST_COLLECT_ARTIFACTS" ]; then
      if [ -n "$EVETEST_HOST_UID" ] && [ -n "$EVETEST_HOST_GID" ]; then
          chown -R "$EVETEST_HOST_UID:$EVETEST_HOST_GID" /artifacts
      fi
    fi
}

# wait_with_timeout <process_name> <pid> <timeout_seconds>
# Wait for the process with the given PID to exit, but no longer than the specified
# timeout. If the timeout elapses first, stop waiting and print a warning
wait_with_timeout() {
    local process_name="$1"
    local pid="$2"
    local timeout="$3"

    (
        sleep "$timeout"
        # Check if the process is still alive before warning and killing it.
        # Without this check, the warning could be printed even if the process
        # exited just as the sleep timer elapsed (a race with kill "$timer_pid").
        kill -0 "$pid" 2>/dev/null || exit 0
        echo "WARNING: timeout of ${timeout}s elapsed while waiting for ${process_name}; killing it" >&2
        kill -9 "$pid" 2>/dev/null || true
    ) &
    timer_pid=$!

    # Wait for the target process
    wait "$pid"
    rc=$?

    # Cancel the timer if the process exited in time
    kill "$timer_pid" 2>/dev/null || true

    return "$rc"
}

trap cleanup TERM INT QUIT

# Wait for go test to finish
wait "$GO_TEST_PID"
GO_TEST_RC=$?
set_artifact_ownership

# Even if go test finishes naturally, still make sure that broker stopped (if it was started).
# This is important in order to ensure proper cleanup of all VMs, images, etc.
if [ -n "$BROKER_PID" ]; then
    kill -TERM "$BROKER_PID" 2>/dev/null
    wait_with_timeout "broker" "$BROKER_PID" 15 2>/dev/null
fi

exit $GO_TEST_RC

