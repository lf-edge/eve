#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Executed by pillar from /opt/vendor/nvidia/init.d/ to bring up the NVIDIA
# x86 dGPU compute stack. Compute-only: no display/OpenGL support (see
# Dockerfile and README.md for why nvidia_modeset/nvidia_drm and the GL
# stack are excluded).

VENDOR=/opt/vendor/nvidia

# This script is executed from pillar, so put the vendor tools first on PATH,
# same pattern as pkg/nvidia's nv-init.sh for the /hostfs case.
export PATH="${VENDOR}/bin:${PATH}"

# The NVIDIA tools are glibc binaries. Their libraries are the vendor tree and
# the host's glibc, which images/modifiers/platform/ai-generic/ai-generic.yq
# bind-mounts into pillar at /lib/x86_64-linux-gnu. pillar's own
# /etc/ld.so.cache is musl's, so the glibc loader needs the path spelled out -
# for those tools only, because musl's loader reads LD_LIBRARY_PATH too.
GLIBC_LIBRARY_PATH="${VENDOR}/dist/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu"

# Bound on each NVML call below (nvidia-smi, nvidia-ctk). device-steps.sh runs
# this script synchronously before zedagent and nim start, so a GPU that wedges
# driver initialisation must not keep the device from reaching its controller.
# Generous, because the first NVML session initialises every GPU, GSP firmware
# included.
NVML_TIMEOUT=${NVML_TIMEOUT:-120}

# Runs an NVIDIA tool with its libraries, bounded by NVML_TIMEOUT.
nvml() {
    timeout -k 10 "${NVML_TIMEOUT}" env LD_LIBRARY_PATH="${GLIBC_LIBRARY_PATH}" "$@"
}

echo "nvidia-dgpu: loading kernel modules"

# Compute-only build: only nvidia and nvidia_uvm are loaded, never
# nvidia_modeset or nvidia_drm (those belong to the display/KMS stack we
# deliberately don't ship). nvidia.ko refuses to load without an NVIDIA GPU,
# which a node may simply not have, and everything below needs it - so stop
# here rather than spend the NVML calls, and their timeouts, on nothing.
modprobe nvidia 2>/dev/null
if [ ! -d /sys/module/nvidia ]; then
    echo "nvidia-dgpu: nvidia module not loaded (no NVIDIA GPU, or the driver rejected it); nothing to configure"
    exit 0
fi

if ! modprobe nvidia_uvm 2>/dev/null; then
    echo "nvidia-dgpu: warning: modprobe nvidia_uvm failed"
fi

# The kernel module comes with eve-kernel and this userland with
# pkg/nvidia, and they must be the same driver release. NVML refuses a
# mismatch ("Driver/library version mismatch"), so nothing below could work,
# and a cached CDI spec - keyed on the module's version - could name libraries
# this userland does not have. Say so plainly and stop.
KMOD_VERSION=$(cat /sys/module/nvidia/version 2>/dev/null)
USER_VERSION=
for lib in "${VENDOR}"/dist/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.*.*; do
    [ -e "${lib}" ] && USER_VERSION=${lib##*/libnvidia-ml.so.}
done
if [ -n "${KMOD_VERSION}" ] && [ "${KMOD_VERSION}" != "${USER_VERSION}" ]; then
    echo "nvidia-dgpu: error: kernel module ${KMOD_VERSION} does not match userland ${USER_VERSION:-(no libnvidia-ml)}; GPU left unconfigured - eve-kernel and pkg/nvidia must ship the same driver version"
    exit 1
fi

# Device nodes come from nvidia-smi below. 71-nvidia.rules is installed for
# what else it does: runtime power management of the GPU's audio and USB
# functions. Its RUN+= lines fail harmlessly - they modprobe nvidia-modeset and
# nvidia-drm, which this compute-only build does not have, and call
# /sbin/ub-device-create, which EVE does not have (the deb's copy needs
# libpciaccess.so.0, which is not shipped).
if [ -d "${VENDOR}/etc/udev/rules.d" ]; then
    mkdir -p /run/udev/rules.d
    cp "${VENDOR}"/etc/udev/rules.d/* /run/udev/rules.d/ 2>/dev/null || true
    udevadm control --reload 2>/dev/null || true
    # Replay add events for NVIDIA PCI functions only, so unrelated hardware is
    # not re-triggered. udevd is persistent on EVE
    # (pkg/udev/etc/init.d/008-udevd starts it with --daemon), so a reload plus
    # a scoped trigger is sufficient.
    udevadm trigger --subsystem-match=pci --attr-match=vendor=0x10de --action=add 2>/dev/null || true
    udevadm settle -t 10 2>/dev/null || true
fi

# nvidia-smi creates the full set of nodes (/dev/nvidia0, nvidiactl, nvidia-uvm,
# nvidia-uvm-tools, nvidia-caps/*) as a side effect of enumerating the GPU as
# root, and it is already shipped here; there is no nvidia-modprobe and no
# usable ub-device-create (see above). A failure here is a warning, not fatal.
if [ ! -e /dev/nvidia0 ]; then
    echo "nvidia-dgpu: no /dev/nvidia0, creating device nodes via nvidia-smi"
    nvml "${VENDOR}/bin/nvidia-smi" -L
    rc=$?
    if [ "${rc}" = 124 ]; then
        echo "nvidia-dgpu: warning: nvidia-smi timed out after ${NVML_TIMEOUT}s"
    elif [ "${rc}" != 0 ]; then
        echo "nvidia-dgpu: warning: nvidia-smi failed (rc ${rc})"
    fi
fi

# CDI spec.
#
# --driver-root is what makes the spec usable by an ordinary workload container.
# EVE stages the driver userland under /opt/vendor/nvidia/dist rather than at /,
# and nvidia-ctk derives each mount's containerPath by stripping the driver root
# from its hostPath. Without it, containerPath == hostPath and everything lands
# in the container at /opt/vendor/nvidia/... - libraries still resolve, because
# the update-ldcache hook is pointed at that directory, but nvidia-smi is not on
# PATH and nothing else finds the stack where it conventionally lives.
#
# --dev-root=/ because only the userland is relocated; the device nodes
# nv-init.sh creates above live at the real /dev. It defaults to --driver-root.
#
#   --nvidia-cdi-hook-path  embeds the hook path containerd will invoke
#   --ldconfig-path         embeds the glibc ldconfig the update-ldcache hook runs
#                           against the container rootfs (Alpine's musl ldconfig
#                           cannot write a glibc ld.so.cache)
#
# Both of those stay host paths under the driver-root rewrite, which is correct:
# runc execs them on the host, not inside the container.
#
# Note --library-search-path is deliberately absent: it only applies to CSV
# (Jetson) discovery mode, so in nvml mode it is silently ignored.
#
# /run is a tmpfs, so a spec written there does not survive a reboot. The
# authoritative copy therefore lives under /persist and is restored into /run/cdi,
# regenerating only when the fingerprint below changes. That is the
# "generate once, persist, re-trigger on inventory change"
# behaviour the design calls for; writing only to /run would silently regenerate
# on every boot instead.
CDI_RUN=/run/cdi/nvidia.yaml
CDI_STORE=/persist/nvidia/cdi
CDI_CACHE="${CDI_STORE}/nvidia.yaml"
CDI_FP="${CDI_STORE}/fingerprint"

# Bump whenever the nvidia-ctk invocation below changes in a way that alters the
# generated spec. It is part of the fingerprint so an in-place EVE update
# regenerates instead of restoring a spec built by the previous recipe - the
# driver version and PCI inventory alone do not change across such an update.
CDI_RECIPE=1

# The recipe, the driver version, the kernel, and every NVIDIA PCI device
# present. Changing any of them invalidates the cached spec: a driver bump moves
# the library paths, adding or removing a GPU changes the device list the spec
# enumerates, and the kernel decides which device nodes exist at all -- a kernel
# built without nvidia-drm creates no /dev/dri/card* or /dev/dri/render* nodes
# for the GPU.
# Without the kernel here, moving between such kernels at the same driver
# version restores a spec naming nodes that no longer exist, and every pod
# requesting a GPU fails at start with "failed to stat CDI host device".
cdi_fingerprint() {
    echo "recipe ${CDI_RECIPE}"
    cat /sys/module/nvidia/version 2>/dev/null
    echo "kernel $(uname -r)"
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
    if nvml "${VENDOR}/bin/nvidia-ctk" cdi generate \
        --mode=nvml \
        --driver-root="${VENDOR}/dist" \
        --dev-root=/ \
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
        # A timed-out generate can leave a partial spec behind.
        rm -f "${CDI_RUN}"
        echo "nvidia-dgpu: warning: nvidia-ctk cdi generate failed or timed out"
    fi
fi

echo "nvidia-dgpu: init complete"
