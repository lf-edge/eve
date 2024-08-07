#!/bin/sh
# shellcheck shell=dash
if grep -q interactive /proc/cmdline; then
    echo "stop rungetty.sh to not re-run login"
    killall -STOP rungetty.sh
    echo "killing login"
    killall login
    echo "Running RUST installer"
    RUST_BACKTRACE=full /sbin/installer
    echo "resume rungetty.sh"
    killall -CONT rungetty.sh
fi
