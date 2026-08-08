#!/bin/sh
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Operator-facing aliases for the kube-init control socket.
# Symlinked as k3s-start / k3s-stop / k3s-status; the action is
# taken either from $1 or from the symlink basename.
#
# All work is delegated to /usr/bin/k3s-sctl, which speaks the
# control-socket protocol directly. "k3s-start" maps to "restart"
# because there is no standalone start: the daemon brings k3s up
# on boot and an operator only needs to ask for a cycle.

ACTION="${1:-$(basename "$0" | sed 's/^k3s-//')}"

case "$ACTION" in
    start|restart)
        exec /usr/bin/k3s-sctl restart
        ;;
    stop)
        exec /usr/bin/k3s-sctl stop
        ;;
    status)
        exec /usr/bin/k3s-sctl status
        ;;
    *)
        echo "Usage: $(basename "$0") {start|stop|status|restart}" >&2
        exit 1
        ;;
esac
