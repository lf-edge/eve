#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Executed by pillar from /opt/vendor/nvidia/init.d/ to bring up the NVIDIA
# x86 dGPU compute stack. Compute-only: no display/OpenGL support (see
# Dockerfile and README.md for why nvidia_modeset/nvidia_drm and the GL
# stack are excluded).

VENDOR=/opt/vendor/nvidia

# This script is executed from pillar, so export the tools/libraries it
# needs to run, same pattern as pkg/nvidia's nv-init.sh for the /hostfs case.
export PATH="${VENDOR}/bin:${PATH}"
# /lib/x86_64-linux-gnu is the host's glibc, bind-mounted into pillar (see
# pkg/pillar/build-k.yml). pillar's own /etc/ld.so.cache is musl's, so the
# glibc loader gets no cache hits and needs the path spelled out.
export LD_LIBRARY_PATH="${VENDOR}/dist/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH}"

echo "nvidia-dgpu: loading kernel modules"

# Compute-only build: only nvidia and nvidia_uvm are loaded, never
# nvidia_modeset or nvidia_drm (those belong to the display/KMS stack we
# deliberately don't ship). A node may simply have no NVIDIA GPU at all, so
# a failed modprobe is logged as a warning, not treated as fatal.
if ! modprobe nvidia 2>/dev/null; then
    echo "nvidia-dgpu: warning: modprobe nvidia failed (no NVIDIA GPU present?)"
fi

if ! modprobe nvidia_uvm 2>/dev/null; then
    echo "nvidia-dgpu: warning: modprobe nvidia_uvm failed"
fi

# Device nodes. There is no nvidia-modprobe available from Ubuntu's restricted
# pool, so hotplug relies on 71-nvidia.rules invoking ub-device-create through
# udev. Install the rules for hotplug, then fall back to nvidia-smi (see below)
# so node creation does not depend on udev event timing at boot.
#
# Note the shipped rules also modprobe nvidia-modeset and nvidia-drm, which this
# build deliberately does not include; those RUN+= lines fail harmlessly.
if [ -d "${VENDOR}/etc/udev/rules.d" ]; then
    mkdir -p /run/udev/rules.d
    cp "${VENDOR}"/etc/udev/rules.d/* /run/udev/rules.d/ 2>/dev/null || true
    udevadm control --reload 2>/dev/null || true
    # Re-run the rules for NVIDIA PCI devices so 71-nvidia.rules gets a chance to
    # invoke ub-device-create through udev. Scoped to vendor 0x10de so this does
    # not re-trigger add events for unrelated hardware. udevd is persistent on EVE
    # (pkg/udev/etc/init.d/008-udevd starts it with --daemon), so a reload plus a
    # scoped trigger is sufficient; the direct call below remains the fallback.
    udevadm trigger --subsystem-match=pci --attr-match=vendor=0x10de --action=add 2>/dev/null || true
    udevadm settle -t 10 2>/dev/null || true
fi

# nvidia-smi creates the full set of nodes (/dev/nvidia0, nvidiactl, nvidia-uvm,
# nvidia-uvm-tools, nvidia-caps/*) as a side effect of enumerating the GPU as
# root, and it is already shipped here. ub-device-create is NOT usable: it links
# libpciaccess.so.0, which Ubuntu's restricted pool does not ship alongside the
# driver, so it exits 127. A node may legitimately have no NVIDIA GPU, so a
# failure here is a warning, not fatal.
if [ ! -e /dev/nvidia0 ]; then
    echo "nvidia-dgpu: no /dev/nvidia0, creating device nodes via nvidia-smi"
    if ! "${VENDOR}/bin/nvidia-smi" -L; then
        echo "nvidia-dgpu: warning: nvidia-smi failed (no NVIDIA GPU present?)"
    fi
fi

# CDI spec.
#
# Generated with explicit paths rather than by rewriting the YAML afterwards:
#   --library-search-path   discovery finds the libraries where EVE actually keeps
#                           them, so the spec needs no root transform at all
#   --nvidia-cdi-hook-path  embeds the hook path containerd will invoke
#   --ldconfig-path         embeds the glibc ldconfig the update-ldcache hook runs
#                           against the container rootfs (Alpine's musl ldconfig
#                           cannot write a glibc ld.so.cache)
#
# Deliberately NO "cdi transform root" pass. Beyond being unnecessary once the
# search path is right, a --from /lib transform would rewrite the GSP firmware
# path /lib/firmware/nvidia/<ver> into the vendor dir, where it does not exist -
# the firmware ships in the kernel image, not here.
#
# /run is a tmpfs, so a spec written there does not survive a reboot. The
# authoritative copy therefore lives under /persist and is restored into /run/cdi,
# regenerating only when the driver version or the set of NVIDIA PCI devices
# changes. That is the "generate once, persist, re-trigger on inventory change"
# behaviour the design calls for; writing only to /run would silently regenerate
# on every boot instead.
CDI_RUN=/run/cdi/nvidia.yaml
CDI_STORE=/persist/nvidia/cdi
CDI_CACHE="${CDI_STORE}/nvidia.yaml"
CDI_FP="${CDI_STORE}/fingerprint"

# Driver version plus every NVIDIA PCI device present. Changing either invalidates
# the cached spec: a driver bump moves the library paths, and adding or removing a
# GPU changes the device list the spec enumerates.
cdi_fingerprint() {
    cat /sys/module/nvidia/version 2>/dev/null
    for d in /sys/bus/pci/devices/*; do
        [ "$(cat "$d/vendor" 2>/dev/null)" = "0x10de" ] || continue
        echo "${d##*/} $(cat "$d/device" 2>/dev/null)"
    done
}

mkdir -p /run/cdi
FP=$(cdi_fingerprint | sha256sum | awk '{print $1}')

if [ -f "${CDI_CACHE}" ] && [ "$(cat "${CDI_FP}" 2>/dev/null)" = "${FP}" ]; then
    echo "nvidia-dgpu: restoring cached CDI spec (inventory unchanged)"
    cp "${CDI_CACHE}" "${CDI_RUN}"
else
    echo "nvidia-dgpu: generating CDI spec at ${CDI_RUN}"
    if "${VENDOR}/bin/nvidia-ctk" cdi generate \
        --mode=nvml \
        --library-search-path="${VENDOR}/dist/usr/lib/x86_64-linux-gnu" \
        --nvidia-cdi-hook-path="${VENDOR}/bin/nvidia-cdi-hook" \
        --ldconfig-path="${VENDOR}/bin/ldconfig-glibc" \
        --output="${CDI_RUN}"; then

        # Surface anything discovered outside the paths EVE can actually serve,
        # rather than silently shipping a spec that fails at container start.
        BAD=$(grep -oE 'hostPath: .*' "${CDI_RUN}" 2>/dev/null \
              | awk '{print $2}' \
              | grep -vE "^(${VENDOR}/|/dev/|/lib/firmware/)" || true)
        if [ -n "${BAD}" ]; then
            echo "nvidia-dgpu: warning: CDI spec references unexpected host paths:"
            echo "${BAD}" | sed 's/^/nvidia-dgpu:   /'
        fi

        mkdir -p "${CDI_STORE}"
        cp "${CDI_RUN}" "${CDI_CACHE}" && echo "${FP}" > "${CDI_FP}" \
            && echo "nvidia-dgpu: cached CDI spec under ${CDI_STORE}" \
            || echo "nvidia-dgpu: warning: could not cache CDI spec under ${CDI_STORE}"
    else
        echo "nvidia-dgpu: warning: nvidia-ctk cdi generate failed"
    fi
fi

echo "nvidia-dgpu: init complete"
