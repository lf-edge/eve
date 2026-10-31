#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# CDI hook used by the specs the NVIDIA device plugin generates.
#
# The update-ldcache hook runs the host's ldconfig (default /sbin/ldconfig)
# against the container rootfs. In the kube container that is Alpine's shell
# script, which cannot be exec'ed from the memfd the hook copies it into, so
# point the hook at the glibc ldconfig shipped by pkg/nvidia instead. The
# device plugin offers no knob for this, only for the hook binary path.
#
# Specs reference this hook with nvidia-cdi-hook style arguments
# ("<hook> args..."); the nvidia-ctk style ("hook <hook> args...") is
# accepted as well.

NVIDIA_BIN=/opt/vendor/nvidia/bin

[ "$1" = "hook" ] && shift
if [ "$1" = "update-ldcache" ]; then
    shift
    exec "$NVIDIA_BIN/nvidia-cdi-hook" update-ldcache \
        --ldconfig-path "$NVIDIA_BIN/ldconfig-glibc" "$@"
fi
exec "$NVIDIA_BIN/nvidia-cdi-hook" "$@"
