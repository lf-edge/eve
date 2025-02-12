# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG PLATFORM=generic

FROM lfedge/eve-alpine:591df01e581889c3027514c8a91feaca1c8ad49f as build-base
ENV BUILD_PKGS="autoconf automake build-base coreutils gettext git glib-dev go libtool libmd-dev ncurses-dev tar xz-dev yq zstd-dev"

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

# Default Jetpack version
ENV JETSON_LINUX=${JETSON_JP5}
ENV JETPACK_VER=jp5

# This is an arm64 (only) package, nothing to do for other architectures
FROM build-base AS amd64-generic
FROM build-base AS amd64-nvidia-jp5
FROM build-base AS amd64-nvidia-jp6
FROM build-base AS riscv64-generic
FROM build-base AS riscv64-nvidia-jp5
FROM build-base AS riscv64-nvidia-jp6

FROM build-base as arm64-nvidia-jp5
ENV JETSON_LINUX=${JETSON_JP5}
ENV JETPACK_VER=jp5

FROM build-base as arm64-nvidia-jp6
ENV JETSON_LINUX=${JETSON_JP6}
ENV JETPACK_VER=jp6

FROM ${TARGETARCH}-${PLATFORM} AS build

RUN echo "${EVE_PLATFORM}" > /eve-platform

# CDI Files
COPY cdi/${JETPACK_VER} /cdi

ADD ${JETSON_LINUX} /jetson_linux.tbz2

# We need to build dpkg in order to get support for .deb packages
# compressed with zstd. Unfortunately dpkg from Alpine 3.16 doesn't support
# it. It won't be required to build when we upgrade to Alpine 3.20.
ENV DPKG_REVISION=1.22.6
ADD --keep-git-dir=true https://salsa.debian.org/dpkg-team/dpkg.git#${DPKG_REVISION} /dpkg
WORKDIR /dpkg
RUN ./autogen && \
    ./configure --prefix=/ && \
    make -j "$(nproc)" && \
    make install

# Extract tarball
WORKDIR /
RUN tar -xjf /jetson_linux.tbz2

# Build nvidia-ctk
ENV NVIDIA_CONTAINER_TOOLKIT_REV=v1.16.0
ADD --keep-git-dir=true https://github.com/NVIDIA/nvidia-container-toolkit.git#${NVIDIA_CONTAINER_TOOLKIT_REV} /nvct

WORKDIR /nvct

COPY patches/* /nvct
RUN for x in /nvct/*.patch; do \
        git am "$x" ; \
    done

RUN mkdir -p dist
RUN make cmd-nvidia-ctk && cp nvidia-ctk dist/
RUN make cmd-nvidia-cdi-hook && cp nvidia-cdi-hook dist/

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

FROM scratch
COPY --from=build /cdi-dist/*.yaml /etc/cdi/
COPY --from=build /rules.d/* /opt/vendor/nvidia/etc/udev/rules.d/
COPY --from=build /rootfs-dist/ /opt/vendor/nvidia/dist/
COPY --from=build /ldconfig-bin/* /opt/vendor/nvidia/bin/
COPY --from=build /nvfanctrl/dist/* /opt/vendor/nvidia/bin/
COPY --from=build /nvct/dist/* /opt/vendor/nvidia/bin/
COPY --from=build /nv-init.sh /opt/vendor/nvidia/init.d/
COPY --from=build /eve-platform /opt/vendor/nvidia/

ENTRYPOINT []
CMD []
