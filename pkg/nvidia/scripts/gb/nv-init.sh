#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

VENDOR="/opt/vendor/nvidia"

# This script is executed from pillar, so we need to export the variables
# below to execute udevadm from hostfs
export PATH="$PATH:/hostfs/bin"
export LD_LIBRARY_PATH="/hostfs/lib"

# Setup modules and devices
modprobe nvidia
modprobe nvidia_modeset
modprobe nvidia_uvm
# Loaded here rather than left to udev, so the GPU's DRM nodes exist when the
# CDI spec below is generated
modprobe nvidia_drm
modprobe governor_pod_scaling

mkdir -p /dev/dri/by-path

# Setup udev rules
mkdir -p /run/udev/rules.d/
cp "${VENDOR}"/etc/udev/rules.d/* /run/udev/rules.d/
# Reload rules and trigger udev events
udevadm control --reload

# Enforces add for framebuffer and nvidia modules, so we have /dev/fb0 and
# /dev/nvidiactrl even when there is no monitor connected to the display
# port. These devices must be present because they are on the CDI spec.
echo "add" > /sys/module/fb/uevent 2> /dev/null
echo "add" > /sys/module/nvidia/uevent 2> /dev/null
echo "add" > /sys/module/nvidia_modeset/uevent 2> /dev/null
echo "add" > /sys/module/nvidia_uvm/uevent 2> /dev/null

# CDI spec
#
# The device entries depend on the board: the GPU's UUID (the NVIDIA device
# plugin requests GPUs by UUID), its PCI address, and its DRM nodes, which a
# GPU without display support, like GB300's, does not have. They are built
# here from what the driver reports in /proc and sysfs, and appended to the
# board-independent part of the spec (libraries, binaries, control nodes and
# hooks), which the build derives from cdi/gb/gb.yaml. nvidia-ctk cdi
# generate cannot do this: NVML needs glibc, which this platform does not
# have.
#
# /run/cdi is /var/run/cdi, the dynamic CDI spec directory read by pillar and
# by the kube containerd and nvidia-container-runtime.
CDI_BASE="${VENDOR}/etc/cdi/nvidia-base.yaml"
CDI_RUN=/run/cdi/nvidia.yaml
CDI_HOOK="${VENDOR}/bin/nvidia-cdi-hook"

# Prints the value of a field of /proc/driver/nvidia/gpus/<bus>/information
gpu_info() {
    sed -n "s/^$2:[[:space:]]*//p" "/proc/driver/nvidia/gpus/$1/information" 2>/dev/null
}

# Prints the containerEdits of a CDI device made of the GPUs whose PCI
# addresses are given: their /dev/nvidiaN nodes and, for GPUs with display
# support, their DRM nodes and the /dev/dri/by-path links to them.
cdi_edits() {
    echo "    containerEdits:"
    echo "      deviceNodes:"
    for bus in "$@"; do
        echo "        - path: /dev/nvidia$(gpu_info "$bus" "Device Minor")"
        echo "          fileMode: 438"
        echo "          permissions: rwm"
    done
    links=
    for bus in "$@"; do
        for node in /sys/bus/pci/devices/"$bus"/drm/card* /sys/bus/pci/devices/"$bus"/drm/renderD*; do # codespell:ignore
            [ -e "$node" ] || continue
            node=${node##*/}
            case "$node" in
                card*) gid=44; link=card ;;
                *) gid=993; link=render ;;
            esac
            echo "        - path: /dev/dri/${node}"
            echo "          fileMode: 432"
            echo "          permissions: rwm"
            echo "          gid: ${gid}"
            links="${links} ../${node}::/dev/dri/by-path/pci-${bus}-${link}"
        done
    done
    [ -n "${links}" ] || return 0
    echo "      hooks:"
    echo "        - hookName: createContainer"
    echo "          path: ${CDI_HOOK}"
    echo "          args:"
    echo "            - nvidia-cdi-hook"
    echo "            - create-symlinks"
    for link in ${links}; do
        echo "            - '--link'"
        echo "            - ${link}"
    done
    echo "          env:"
    echo "            - NVIDIA_CTK_DEBUG=false"
    echo "      additionalGids:"
    echo "        - 44"
    echo "        - 993"
}

GPUS=
for gpu in /proc/driver/nvidia/gpus/*; do
    [ -f "${gpu}/information" ] && GPUS="${GPUS} ${gpu##*/}"
done

# The UUID reads as question marks until the driver has initialized the GPU,
# which the GSP firmware boot can delay
for bus in ${GPUS}; do
    tries=30
    while [ "${tries}" -gt 0 ] && ! gpu_info "${bus}" "GPU UUID" | grep -q '^GPU-[0-9a-f-]*$'; do
        sleep 1
        tries=$((tries - 1))
    done
done

mkdir -p /run/cdi
if [ -z "${GPUS}" ]; then
    echo "nv-init: no NVIDIA GPU found, no CDI spec generated"
    rm -f "${CDI_RUN}"
elif [ ! -f "${CDI_BASE}" ]; then
    echo "nv-init: ${CDI_BASE} not found, no CDI spec generated"
    rm -f "${CDI_RUN}"
else
    {
        cat "${CDI_BASE}"
        echo "devices:"
        for bus in ${GPUS}; do
            echo "  - name: \"$(gpu_info "${bus}" "Device Minor")\""
            cdi_edits "${bus}"
            uuid=$(gpu_info "${bus}" "GPU UUID")
            if echo "${uuid}" | grep -q '^GPU-[0-9a-f-]*$'; then
                echo "  - name: ${uuid}"
                cdi_edits "${bus}"
            else
                echo "nv-init: warning: no UUID for GPU ${bus}, it can only be requested by index"
            fi
        done
        echo "  - name: all"
        # shellcheck disable=SC2086
        cdi_edits ${GPUS}
    } > "${CDI_RUN}.tmp" && mv "${CDI_RUN}.tmp" "${CDI_RUN}"
    echo "nv-init: generated ${CDI_RUN} for GPU(s):${GPUS}"
fi

