# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG PLATFORM=generic

FROM lfedge/eve-alpine:1fdf3241f1aef1dd3e8ad7433c85474bc522f3f5 AS build-base
ENV BUILD_PKGS="autoconf automake build-base coreutils gettext git glib-dev libtool libmd-dev ncurses-dev tar xz-dev yq zstd-dev dpkg"

RUN eve-alpine-deploy.sh

# Set EVE_PLATFORM
ARG PLATFORM
ENV EVE_PLATFORM=$PLATFORM

# Setup git to apply patches
RUN git config --global user.email 'builder@projecteve.dev' && \
    git config --global user.name 'Project EVE'

# Jetpack tarballs
ENV JETSON_JP5=https://developer.nvidia.com/downloads/embedded/l4t/r35_release_v5.0/release/jetson_linux_r35.5.0_aarch64.tbz2
ENV JETSON_JP6=https://developer.nvidia.com/downloads/embedded/l4t/r36_release_v3.0/release/jetson_linux_r36.3.0_aarch64.tbz2
ENV JETSON_JP7=https://developer.nvidia.com/downloads/embedded/L4T/r38_Release_v4.0/release/Jetson_Linux_R38.4.0_aarch64.tbz2

# Default Jetpack version
ENV JETSON_LINUX=${JETSON_JP5}
ENV JETPACK_VER=jp5

# This is an arm64 (only) package, nothing to do for other architectures
FROM build-base AS amd64-generic
FROM build-base AS amd64-nvidia-jp5
FROM build-base AS amd64-nvidia-jp6
FROM build-base AS amd64-nvidia-jp7
FROM build-base AS riscv64-generic
FROM build-base AS riscv64-nvidia-jp5
FROM build-base AS riscv64-nvidia-jp6
FROM build-base AS riscv64-nvidia-jp7

FROM build-base AS arm64-nvidia-jp5
ENV JETSON_LINUX=${JETSON_JP5}
ENV JETPACK_VER=jp5

FROM build-base AS arm64-nvidia-jp6
ENV JETSON_LINUX=${JETSON_JP6}
ENV JETPACK_VER=jp6

FROM build-base AS arm64-nvidia-jp7
ENV JETSON_LINUX=${JETSON_JP7}
ENV JETPACK_VER=jp7

FROM ${TARGETARCH}-${PLATFORM} AS build

RUN echo "${EVE_PLATFORM}" > /eve-platform

# CDI Files
COPY cdi/${JETPACK_VER} /cdi

ADD ${JETSON_LINUX} /jetson_linux.tbz2

# Extract tarball
WORKDIR /
RUN tar -xjf /jetson_linux.tbz2

# Build nvidia-ctk
ENV NVIDIA_CONTAINER_TOOLKIT_REV=v1.16.2
ADD --keep-git-dir=true https://github.com/NVIDIA/nvidia-container-toolkit.git#${NVIDIA_CONTAINER_TOOLKIT_REV} /nvct

WORKDIR /nvct

COPY patches/* /nvct
RUN for x in /nvct/*.patch; do \
        git am "$x" ; \
    done

RUN mkdir -p dist
RUN make cmd-nvidia-ctk && cp nvidia-ctk dist/
RUN make cmd-nvidia-cdi-hook && cp nvidia-cdi-hook dist/
RUN make cmd-nvidia-container-runtime && cp nvidia-container-runtime dist/
RUN make cmd-nvidia-container-runtime-hook && cp nvidia-container-runtime-hook dist/

# Build nvfanctrl
COPY nvfanctrl/ /nvfanctrl
WORKDIR /nvfanctrl
RUN make && mkdir -p dist/ && cp nvfanctrl dist/

# Get and extract ldconfig for glibc, this tool runs over the rootfs of the
# application container, like CUDA application containers (glibc based).
ADD http://ports.ubuntu.com/ubuntu-ports/pool/main/g/glibc/libc-bin_2.31-0ubuntu9_arm64.deb /
RUN mkdir -p /ldconfig-bin && \
    dpkg -x /libc-bin_2.31-0ubuntu9_arm64.deb /ldconfig && \
    cp /ldconfig/sbin/ldconfig.real /ldconfig-bin/ldconfig-glibc

# Register source-built / downloaded NVIDIA components in the APK DB, mandatory
# for them to be included in the SBOM.
RUN case "${JETPACK_VER}" in \
        jp5) JL_VER=r35.5.0 ;; \
        jp6) JL_VER=r36.3.0 ;; \
        jp7) JL_VER=r38.4.0 ;; \
        *)   JL_VER="${JETPACK_VER}" ;; \
    esac && \
    register-sbom-pkg.sh -n jetson-linux -v "${JL_VER}" -l proprietary -u https://developer.nvidia.com/embedded/jetson-linux -o /sbom-out && \
    register-sbom-pkg.sh -n nvidia-container-toolkit -v "${NVIDIA_CONTAINER_TOOLKIT_REV}" -l Apache-2.0 -u https://github.com/NVIDIA/nvidia-container-toolkit -o /sbom-out && \
    register-sbom-pkg.sh -n libc-bin -v 2.31-0ubuntu9 -l LGPL-2.1-or-later -u http://ports.ubuntu.com/ubuntu-ports/pool/main/g/glibc -o /sbom-out

# Copy udev rules
COPY udev/${JETPACK_VER}/rules.d/* /rules.d/

# Copy scripts to processing CDI files and initialization
COPY scripts/*.sh /
COPY scripts/${JETPACK_VER}/* /

# Process CDI files
WORKDIR /
RUN mkdir -p /ldconfig-bin /nvfanctrl/dist /nvct/dist /cdi /rootfs-dist /cdi-dist /rules.d && \
    mkdir -p /rootfs && \
    if [ -n "$(ls /cdi/* 2> /dev/null)" ]; then \
        for x in /cdi/*.yaml; do \
            OUTFILE=/cdi-dist/$(basename "$x") ; \
            /process-cdi.sh "$x" /rootfs /rootfs-dist &&  \
            yq '. | (.devices[].containerEdits.hooks[] | select(.path == "/usr/bin/nvidia-ctk")).path = "/opt/vendor/nvidia/bin/nvidia-ctk"' -i "$x" && \
            yq '. | (.devices[].containerEdits.hooks[] | select(.path == "/usr/bin/nvidia-cdi-hook")).path = "/opt/vendor/nvidia/bin/nvidia-cdi-hook"' -i "$x" && \
            yq '. | (.devices[].containerEdits.hooks[] | select(.path == "/usr/bin/nvidia-container-runtime")).path = "/opt/vendor/nvidia/bin/nvidia-container-runtime"' -i "$x" && \
            yq '. | (.devices[].containerEdits.hooks[] | select(.path == "/usr/bin/nvidia-container-runtime-hook")).path = "/opt/vendor/nvidia/bin/nvidia-container-runtime-hook"' -i "$x" && \
            /nvct/dist/nvidia-ctk cdi transform root --relative-to host \
                --from /usr --to /opt/vendor/nvidia/dist/usr --input "$x" | \
            /nvct/dist/nvidia-ctk cdi transform root --relative-to host \
                --from /etc --to /opt/vendor/nvidia/dist/etc | \
            /nvct/dist/nvidia-ctk cdi transform root --relative-to host \
                --from /lib --to /opt/vendor/nvidia/dist/lib --output "$OUTFILE" && \
            yq '. | (.devices[].containerEdits.hooks[] | select(.args[] == "update-ldcache")).args += ["--ldconfig-path", "/opt/vendor/nvidia/bin/ldconfig-glibc"]' -i "$OUTFILE" ; \
        done ; \
    fi && \
    rm -rf /rootfs/*

FROM scratch AS out-jetson
COPY --from=build /cdi-dist/*.yaml /etc/cdi/
COPY --from=build /rules.d/* /opt/vendor/nvidia/etc/udev/rules.d/
COPY --from=build /rootfs-dist/ /opt/vendor/nvidia/dist/
COPY --from=build /ldconfig-bin/* /opt/vendor/nvidia/bin/
COPY --from=build /nvfanctrl/dist/* /opt/vendor/nvidia/bin/
COPY --from=build /nvct/dist/* /opt/vendor/nvidia/bin/
COPY --from=build /nv-dev-nodes.sh /opt/vendor/nvidia/bin/
COPY --from=build /nv-init.sh /opt/vendor/nvidia/init.d/
COPY --from=build /eve-platform /opt/vendor/nvidia/
COPY --from=build /sbom-out/lib/apk/db/installed /lib/apk/db/installed

ENTRYPOINT []
CMD []

# ---------------------------------------------------------------------------
# PLATFORM=ai-generic: NVIDIA userland for x86 discrete GPUs, compute only.
# Shares nothing with the Jetson stages above except the output layout under
# /opt/vendor/nvidia; buildkit builds only the stages the selected platform
# reaches, so neither pipeline runs for the other.
# ---------------------------------------------------------------------------
FROM lfedge/eve-alpine:1fdf3241f1aef1dd3e8ad7433c85474bc522f3f5 AS dgpu-base
ENV BUILD_PKGS="dpkg tar zstd"
RUN eve-alpine-deploy.sh && \
    mkdir -p /staging/opt /staging/etc && \
    register-sbom-pkg.sh -o /sbom-out

# Nothing to stage on these architectures - empty package.
FROM dgpu-base AS dgpu-arm64
FROM dgpu-base AS dgpu-riscv64

FROM dgpu-base AS dgpu-amd64
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# NVIDIA_DRIVER_VERSION must match eve-kernel's Makefile.eve: the kernel module,
# this userland and the GSP firmware are pinned to each other exactly.
ARG NVIDIA_DRIVER_BRANCH=580
ARG NVIDIA_DRIVER_VERSION=580.173.02-0ubuntu0.24.04.1
ARG NVCT_VERSION=1.20.0-1
ARG LIBC_BIN_VERSION=2.39-0ubuntu8.9

# Launchpad's per-file URLs keep every published version; the archive pool
# deletes superseded ones. ADD verifies each checksum and needs no network
# for RUN, so build-ai-generic.yml declares none.
# libnvidia-gl and libc-bin are set aside: one file is taken from each below.
ADD --checksum=sha256:ad87a8a478849efcc47dbe1aefd39dc58d15d7b4852bf3c1ef1671286e623984 https://launchpad.net/ubuntu/+archive/primary/+files/libnvidia-compute-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb /debs/
ADD --checksum=sha256:e04add4fb1f8e644e0d71d45bf0c0f72347e7e85a6427951a4c3c94f41d722b9 https://launchpad.net/ubuntu/+archive/primary/+files/libnvidia-cfg1-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb /debs/
ADD --checksum=sha256:5e57c845e34f119d67164e7a81b73d5fdc7ddc6dc82a9a29c1d7d76cd7664064 https://launchpad.net/ubuntu/+archive/primary/+files/nvidia-utils-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb /debs/
ADD --checksum=sha256:e685fce27209c2f746105f98c052b134097ff259578cbf7497813f3371e07b12 https://launchpad.net/ubuntu/+archive/primary/+files/nvidia-compute-utils-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb /debs/
ADD --checksum=sha256:ce1150fd18ecc16e2ceb4df6a1acdf31068dad2e86c71b5bcbd9a8430433ddf1 https://launchpad.net/ubuntu/+archive/primary/+files/libnvidia-common-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_all.deb /debs/
ADD --checksum=sha256:35f21f801a14ea75d65504a6fe9e83b95ed7dce1b638e157604c00a697fdbcff https://launchpad.net/ubuntu/+archive/primary/+files/nvidia-kernel-common-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb /debs/
ADD --checksum=sha256:73e4590815acc5d97b69ddbc72d6a30c6682825328a27b73f909c9d813aff37c https://launchpad.net/ubuntu/+archive/primary/+files/libnvidia-extra-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb /debs/
ADD --checksum=sha256:d1cc61d9ce8ea08bb4d03ba0950aa499e31640b83f028a2832cc72d92085a0a1 https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/nvidia-container-toolkit-base_${NVCT_VERSION}_amd64.deb /debs/
ADD --checksum=sha256:0eccf4563b0f3aa4f181df00047869213b1890160bf1a85905219607c406529e https://launchpad.net/ubuntu/+archive/primary/+files/libnvidia-gl-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb /gl/
ADD --checksum=sha256:066398a06ef1a218d4109461d4c636eafe83322ad19b179de9ef7af42b3fec58 https://launchpad.net/ubuntu/+archive/primary/+files/libc-bin_${LIBC_BIN_VERSION}_amd64.deb /libc-bin/

# Keep usr/share/doc/*/copyright: NVIDIA's licence (section 1.1(d)) permits
# redistribution with an OSI-licensed kernel only if the agreement reaches every
# recipient, and these files are how it does.
ENV DIST=/staging/opt/vendor/nvidia/dist
RUN mkdir -p "$DIST" && \
    for deb in /debs/*.deb; do dpkg-deb -x "$deb" "$DIST"; done && \
    test -s "$DIST/usr/share/doc/libnvidia-compute-${NVIDIA_DRIVER_BRANCH}/copyright"

# libnvidia-gpucomp is dlopen'd by libcuda, so nothing notices it missing before
# a workload does. Ubuntu ships it only inside libnvidia-gl; take that one file.
RUN gl="/gl/libnvidia-gl-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb" && \
    dpkg-deb --fsys-tarfile "$gl" | tar -x -C "$DIST" --wildcards './usr/lib/*/libnvidia-gpucomp.so*' && \
    test -f "$DIST/usr/lib/x86_64-linux-gnu/libnvidia-gpucomp.so.${NVIDIA_DRIVER_VERSION%%-*}"

# glibc ldconfig (static) for the CDI update-ldcache hook, which runs it against
# the workload container's glibc rootfs. Ubuntu's ldconfig is a wrapper script;
# ldconfig.real is the binary.
RUN mkdir -p /staging/opt/vendor/nvidia/bin && \
    dpkg-deb --fsys-tarfile /libc-bin/libc-bin_${LIBC_BIN_VERSION}_amd64.deb | \
        tar -x -O ./usr/sbin/ldconfig.real > /staging/opt/vendor/nvidia/bin/ldconfig-glibc && \
    chmod 0755 /staging/opt/vendor/nvidia/bin/ldconfig-glibc && \
    test -s /staging/opt/vendor/nvidia/bin/ldconfig-glibc

# Stable entry points for nv-init.sh; a missing tool fails the build, not the
# device. No nvidia-modprobe (not in Ubuntu's restricted pool) and no
# ub-device-create (needs libpciaccess): nvidia-smi creates the device nodes.
RUN for bin in nvidia-ctk nvidia-cdi-hook nvidia-container-runtime \
               nvidia-smi nvidia-persistenced; do \
        found=$(find "$DIST" -type f -name "$bin" -print -quit) ; \
        [ -n "$found" ] || { echo "ERROR: $bin not found in extracted debs" >&2 ; exit 1 ; } ; \
        ln -s "${found#/staging}" "/staging/opt/vendor/nvidia/bin/$bin" ; \
    done

# NVIDIA's modprobe.d blacklists nouveau and nova, which claim the same PCI IDs.
# Scoped to ai-generic; other images keep nouveau for basic display.
RUN mkdir -p /staging/etc/modprobe.d /staging/opt/vendor/nvidia/etc/udev/rules.d && \
    cp "$DIST/lib/modprobe.d/nvidia-graphics-drivers.conf" /staging/etc/modprobe.d/ && \
    cp "$DIST/lib/udev/rules.d/71-nvidia.rules" /staging/opt/vendor/nvidia/etc/udev/rules.d/

COPY --chmod=0755 scripts/ai-generic/nv-init.sh /staging/opt/vendor/nvidia/init.d/nv-init.sh

# kube-init picks the NVIDIA device plugin manifest by it, as for Jetson.
ARG PLATFORM
RUN echo "${PLATFORM}" > /staging/opt/vendor/nvidia/eve-platform

# Every deb whose contents ship goes into the SBOM: the driver as proprietary,
# the container toolkit as Apache-2.0, libc-bin for ldconfig-glibc.
RUN for deb in /debs/*.deb /gl/*.deb /libc-bin/*.deb; do \
        name=$(dpkg-deb -f "$deb" Package) ; \
        case "$name" in \
            nvidia-container-toolkit*) lic=Apache-2.0; url=https://github.com/NVIDIA/nvidia-container-toolkit ;; \
            libc-bin) lic=LGPL-2.1-or-later; url=https://launchpad.net/ubuntu/+source/glibc ;; \
            *) lic=proprietary; url=https://launchpad.net/ubuntu/+source/nvidia-graphics-drivers-${NVIDIA_DRIVER_BRANCH} ;; \
        esac ; \
        register-sbom-pkg.sh -n "$name" -v "$(dpkg-deb -f "$deb" Version)" -l "$lic" -u "$url" \
            -d "$name (prebuilt .deb)" -o /sbom-out ; \
    done

# hadolint ignore=DL3006
FROM dgpu-${TARGETARCH} AS dgpu

FROM scratch AS out-dgpu
COPY --from=dgpu /staging/opt /opt
COPY --from=dgpu /staging/etc /etc
COPY --from=dgpu /sbom-out/lib/apk/db/installed /lib/apk/db/installed

ENTRYPOINT []
CMD []

# The image for each PLATFORM. linuxkit rejects a FROM whose base name is empty
# once variables are stripped, hence the literal prefix.
FROM out-jetson AS final-generic
FROM out-jetson AS final-nvidia-jp5
FROM out-jetson AS final-nvidia-jp6
FROM out-jetson AS final-nvidia-jp7
FROM out-dgpu AS final-ai-generic
# hadolint ignore=DL3006
FROM final-${PLATFORM}
