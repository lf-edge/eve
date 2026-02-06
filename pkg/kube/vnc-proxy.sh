#!/bin/sh
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# VNC proxy utilities for cluster-init.sh
# Handles VNC session lifecycle for both remote-console and edgeview VNC.
# Uses inotifywait to monitor VNC config file and starts/stops virtctl vnc proxy.

# VNC parameters - unified for both remote-console and edgeview VNC
# Both methods now use the same file path and JSON format
VNC_CONFIG_DIR="/run/edgeview/VncParams"
VNC_CONFIG_FILE="${VNC_CONFIG_DIR}/vmiVNC.run"
VNC_RUNNING=false

# Handle VNC file creation/deletion - start or stop virtctl vnc
# Unified handler for both remote-console VNC (from zedkube) and edgeview VNC
# JSON format: {"VMIName": "...", "VNCPort": ..., "CallerPID": ...}
# CallerPID is optional - only present for edgeview VNC (used to cleanup when edgeview exits)
handle_vnc() {
    local virtctl_pid
    virtctl_pid=$(pgrep -f "/usr/bin/virtctl.*vnc.*--proxy-only")

    if [ -f "$VNC_CONFIG_FILE" ] && { [ "$VNC_RUNNING" = false ] || [ -z "$virtctl_pid" ]; }; then
        # Parse JSON format using jq
        local vmiName
        local vmiPort
        local callerPid
        vmiName=$(jq -r '.VMIName // empty' "$VNC_CONFIG_FILE" 2>/dev/null)
        vmiPort=$(jq -r '.VNCPort // empty' "$VNC_CONFIG_FILE" 2>/dev/null)
        # CallerPID is optional - only present for edgeview VNC
        callerPid=$(jq -r '.CallerPID // empty' "$VNC_CONFIG_FILE" 2>/dev/null)

        if [ -z "$vmiName" ] || [ -z "$vmiPort" ]; then
            logmsg "handle_vnc: Error: VMIName or VNCPort is empty in $VNC_CONFIG_FILE"
            return 1
        fi

        # Log file uses shell PID for unique naming per session
        local virtctl_log="/tmp/virtctl-vnc.$$"

        # Retry logic - try 5 times
        local max_retries=5
        local attempt=1

        while [ $attempt -le $max_retries ]; do
            # Check if a virtctl process is already running for this VMI
            local existing_pid
            existing_pid=$(pgrep -f "/usr/bin/virtctl.*vnc.*$vmiName.*--proxy-only")

            if [ -z "$existing_pid" ]; then
                # No existing process - start a new one
                logmsg "handle_vnc: Attempt $attempt/$max_retries: Starting virtctl vnc for $vmiName on port $vmiPort"

                # Add timestamp before each virtctl invocation
                echo "" >> "$virtctl_log"
                echo "==== $(date '+%Y-%m-%d %H:%M:%S') Attempt $attempt ====" >> "$virtctl_log"

                # Use nohup to prevent process from being killed when parent shell exits
                nohup /usr/bin/virtctl vnc "$vmiName" -n eve-kube-app --port "$vmiPort" --proxy-only >> "$virtctl_log" 2>&1 &
                existing_pid=$!
                logmsg "handle_vnc: Started virtctl with PID $existing_pid"
            else
                logmsg "handle_vnc: Attempt $attempt/$max_retries: virtctl already running for $vmiName (PID: $existing_pid), waiting for port $vmiPort"
            fi

            # Wait up to 5 seconds for the port to become available
            local port_wait=0
            local max_port_wait=5
            while [ $port_wait -lt $max_port_wait ]; do
                # Check if port is listening
                if ss -tln "sport = :$vmiPort" | grep -q ":$vmiPort"; then
                    logmsg "handle_vnc: Success: port $vmiPort is now listening (PID: $existing_pid)"
                    VNC_RUNNING=true
                    # Start monitoring the caller PID if present (edgeview VNC)
                    if [ -n "$callerPid" ]; then
                        monitor_caller_pid "$callerPid" &
                    fi
                    return 0
                fi

                sleep 1
                port_wait=$((port_wait + 1))

                # Check if process is still running
                if ! kill -0 "$existing_pid" 2>/dev/null; then
                    logmsg "handle_vnc: virtctl process $existing_pid exited while waiting for port"
                    break
                fi
            done

            # If process is still running but port not listening, continue to next attempt
            # (which will find the existing process and wait again)
            if kill -0 "$existing_pid" 2>/dev/null; then
                logmsg "handle_vnc: Attempt $attempt: process $existing_pid still running but port not listening after ${max_port_wait}s"
            else
                logmsg "handle_vnc: Attempt $attempt: process exited, will start new one"
            fi

            sleep 2
            attempt=$((attempt + 1))
        done

        logmsg "handle_vnc: Error: Failed to start virtctl vnc for $vmiName after $max_retries attempts"
        VNC_RUNNING=false
        return 1

    elif [ ! -f "$VNC_CONFIG_FILE" ] && [ "$VNC_RUNNING" = true ]; then
        # File removed (detected by inotifywait) - stop virtctl vnc
        logmsg "handle_vnc: VNC config file removed, stopping VNC session"

        # Log to virtctl log file (same shell PID, so same log file path)
        local virtctl_log="/tmp/virtctl-vnc.$$"
        if [ -f "$virtctl_log" ]; then
            echo "" >> "$virtctl_log"
            echo "==== $(date '+%Y-%m-%d %H:%M:%S') VNC config file removed, session ending ====" >> "$virtctl_log"
        fi

        if [ -n "$virtctl_pid" ]; then
            logmsg "handle_vnc: Stopping virtctl vnc process (PID: $virtctl_pid)"
            kill -9 "$virtctl_pid" 2>/dev/null
        else
            logmsg "handle_vnc: virtctl vnc process already exited"
        fi
        VNC_RUNNING=false
    fi
}

# Monitor caller PID (edgeview) and cleanup when it crashes
# This is only used for edgeview VNC - handles the case when edgeview process crashes
# Normal cleanup when TCP session ends is done by edgeview itself (cleanupEveKVNC)
monitor_caller_pid() {
    local caller_pid="$1"
    local check_interval=5

    logmsg "monitor_caller_pid: Starting to monitor caller PID $caller_pid"

    while true; do
        sleep $check_interval

        # Check if caller process (edgeview) crashed
        if ! kill -0 "$caller_pid" 2>/dev/null; then
            logmsg "monitor_caller_pid: Caller PID $caller_pid is gone (crashed?), cleaning up"

            # Stop virtctl vnc process
            local virtctl_pid
            virtctl_pid=$(pgrep -f "/usr/bin/virtctl.*vnc.*--proxy-only")
            if [ -n "$virtctl_pid" ]; then
                logmsg "monitor_caller_pid: Stopping virtctl vnc process (PID: $virtctl_pid)"
                kill -9 "$virtctl_pid" 2>/dev/null
            fi

            # Remove the VNC file
            if [ -f "$VNC_CONFIG_FILE" ]; then
                logmsg "monitor_caller_pid: Removing stale VNC file $VNC_CONFIG_FILE"
                rm -f "$VNC_CONFIG_FILE"
            fi

            VNC_RUNNING=false
            return 0
        fi

        # Check if the VNC file was removed (normal cleanup by edgeview)
        if [ ! -f "$VNC_CONFIG_FILE" ]; then
            logmsg "monitor_caller_pid: VNC file removed, stopping monitor"
            return 0
        fi
    done
}

# Monitor VNC config file for changes using inotifywait
# Uses inotifywait to get notified of filesystem events (event-driven, no polling)
monitor_vnc_config() {
    local vnc_dir="$VNC_CONFIG_DIR"

    logmsg "monitor_vnc_config: Starting monitor for $vnc_dir"

    # Create the VNC directory if it doesn't exist
    # This ensures inotifywait can start monitoring immediately
    if [ ! -d "$vnc_dir" ]; then
        logmsg "monitor_vnc_config: Creating VNC config directory $vnc_dir"
        mkdir -p "$vnc_dir"
    fi

    logmsg "monitor_vnc_config: VNC config directory $vnc_dir ready"

    # Use inotifywait in non-monitor mode (-e without -m) to wait for single event
    # Then handle virtctl OUTSIDE the pipe to avoid subshell issues
    # Running virtctl from inside a pipe subshell causes websocket connection issues
    while true; do
        # Check if VNC file already exists before waiting for inotify event
        if [ -f "$VNC_CONFIG_FILE" ] && [ "$VNC_RUNNING" = false ]; then
            logmsg "monitor_vnc_config: VNC file already exists, handling it"
            handle_vnc
        fi

        # Wait for a single filesystem event (not in monitor mode)
        # This blocks until an event occurs, then returns
        event=$(inotifywait -q -e create,modify,delete,moved_to,moved_from "$vnc_dir" 2>/dev/null)
        if [ -n "$event" ]; then
            logmsg "monitor_vnc_config: Event detected: $event"
            # Handle virtctl outside the pipe - this is the key fix
            handle_vnc
        fi
    done
}
