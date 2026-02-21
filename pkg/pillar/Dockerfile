# Copyright (c) 2018-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Dockerfile to build pillar

# use the same set of packages for simplicity
ARG BUILD_PKGS_BASE="git gcc linux-headers libc-dev make linux-pam-dev m4 findutils util-linux make patch \
                     libintl libuuid libtirpc libblkid libcrypto1.1 zlib tar"

# we use the same image in several places
ARG EVE_ALPINE_IMAGE=lfedge/eve-alpine:745ae9066273c73b0fd879c4ba4ff626a8392d04

FROM lfedge/eve-uefi:b3ef9ca37c99439c776673aeba83c52ea8b84626 AS uefi-build
FROM lfedge/eve-dom0-ztools:e9fb7d625a47288420efa7431a8d9c5dc6f146e3 AS zfs
RUN mkdir /out
# copy zfs-related files from dom0-ztools using prepared list of files
RUN while read -r x; do \
        if [ -d "$x" ]; then \
          mkdir -p "/out/$x"; \
        else \
          cp -P "$x" "/out/$x"; \
        fi \
    done < /etc/zfs-files

# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS build-native
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# hadolint ignore=DL3006,DL3029
FROM --platform=${BUILDPLATFORM} ${EVE_ALPINE_IMAGE} AS build-cross
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# hadolint ignore=DL3029
FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:f476a79bcd086759592a105a49f9ed5bfa2c4ffa AS cross-compilers

# will use several packages from target arch and copy them to sysroot
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS cross-compile-libs
ENV PKGS musl-dev libgcc libintl libuuid libtirpc libblkid linux-headers
RUN eve-alpine-deploy.sh
# we need zfs files during build
COPY --from=zfs / /

# adjust EVE_TARGET_ARCH for cross-compiler
FROM build-cross AS build-cross-target-arm64
ENV EVE_TARGET_ARCH=aarch64
FROM build-cross AS build-cross-target-amd64
ENV EVE_TARGET_ARCH=x86_64

# hadolint ignore=DL3006
FROM build-cross-target-${TARGETARCH} AS build-cross-target
ENV CROSS_COMPILE_ENV="${EVE_TARGET_ARCH}"-alpine-linux-musl-
COPY --from=cross-compilers /packages /packages
# hadolint ignore=DL3018
RUN apk add --no-cache --allow-untrusted -X /packages build-base-"${EVE_TARGET_ARCH}"
COPY --from=cross-compile-libs /out/ /usr/"${EVE_TARGET_ARCH}"-alpine-linux-musl/

# cross-compilers
FROM build-cross-target AS target-arm64-build-amd64
FROM build-cross-target AS target-amd64-build-arm64
# native
FROM build-native AS target-amd64-build-amd64
FROM build-native AS target-arm64-build-arm64

# hadolint ignore=DL3006
FROM target-${TARGETARCH}-build-${BUILDARCH} AS build
ARG DEV=n
ARG TEST_TOOLS=n
ARG TARGETARCH

# some parts of pillar are build conditionally based on the hypervisor
ARG HV

# We need dhcpcd version 10.0.0 at least, especially for IPv6, containing these patches:
#   - https://github.com/NetworkConfiguration/dhcpcd/commit/5f6f61cbe3edfc8313d7db63d6ecf1b08d7232f1
#     Fixes: https://github.com/NetworkConfiguration/dhcpcd/issues/69
#     Without this, NetworkMonitor fails to retrieve DHCPv6/RA info from dhcpcd.
#   - https://github.com/NetworkConfiguration/dhcpcd/commit/2b4fe4c12b5d4366ff21fabf3a6c3799f8e4fa53
#     Fixes: https://github.com/NetworkConfiguration/dhcpcd/issues/183
#     Without this, dhcpcd will not obtain NTP server IPs from a DHCPv6 server.
# I tried version 10.0.0, but "dhcpcd --release <interface>" crashes with a segfault.
# Version 10.1.0 seems to be stable across all the features that we are using.
# Note: After upgrading Alpine to version v3.21 or newer, a sufficiently up-to-date dhcpcd
# will be available in the official Alpine repositories, so building it manually will no longer
# be necessary.
ENV DHCPCD_VERSION=v10.1.0

ENV CC=${CROSS_COMPILE_ENV}gcc

ADD --keep-git-dir=true https://github.com/NetworkConfiguration/dhcpcd.git#${DHCPCD_VERSION} /dhcpcd
WORKDIR /dhcpcd
RUN ./configure --libexecdir=/usr/lib/dhcpcd --dbdir=/var/lib/dhcpcd --runstatedir=/run && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && make install

# building with runtime stats
ARG RSTATS=n
ARG RSTATS_ENDPOINT=
ARG RSTATS_TAG=
ARG IMM_PROFILING=n
ENV IMM_PROFILING=${IMM_PROFILING}
ARG ARTIFICIAL_LEAK=n
ENV ARTIFICIAL_LEAK=${ARTIFICIAL_LEAK}

# we need zfs files during build
COPY --from=zfs /out /

COPY ./  /pillar/

# go vet/format and go install
WORKDIR /pillar

ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=${TARGETARCH}
ARG GOPKGVERSION

# make LK build args affect a layer, so value change will invalidate cache
RUN echo "IMM_PROFILING: ${IMM_PROFILING}"
RUN echo "ARTIFICIAL_LEAK: ${ARTIFICIAL_LEAK}"

# hadolint ignore=DL4006
RUN --mount=type=cache,target=/root/.cache/go-build echo "Running go vet" && make HV="$HV" vet && \
    echo "Running go fmt" && ERR="$(find . -name \*.go | grep -v /vendor/ | xargs gofmt -d -e -l -s)" && \
       if [ -n "$ERR" ] ; then printf 'go fmt Failed - ERR: %s' "$ERR" ; exit 1 ; fi && \
       make ZARCH=${TARGETARCH} HV="$HV" DEV="$DEV" RSTATS=$RSTATS RSTATS_ENDPOINT=$RSTATS_ENDPOINT RSTATS_TAG=$RSTATS_TAG IMM_PROFILING=$IMM_PROFILING ARTIFICIAL_LEAK=$ARTIFICIAL_LEAK DISTDIR=/final/opt/zededa/bin BUILD_VERSION=${GOPKGVERSION} build

WORKDIR /

ENV DELVE_VERSION 1.20.1
ENV DELVE_SOURCE=https://github.com/go-delve/delve/archive/refs/tags/v${DELVE_VERSION}.tar.gz
# hadolint ignore=DL3020
ADD ${DELVE_SOURCE} /delve.tar.gz
RUN if [ ${DEV} = "y" ]; then tar --absolute-names -xz < /delve.tar.gz; fi
WORKDIR /delve-${DELVE_VERSION}
RUN --mount=type=cache,target=/root/.cache/go-build if [ ${DEV} = "y" ]; then \
    GOFLAGS= CGO_ENABLED=0 go build -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv && \
    cp dlv /final/opt/ ; \
fi
WORKDIR /
RUN --mount=type=cache,target=/root/.cache/go-build if [ "${TEST_TOOLS}" = "y" ]; then \
    apk add --no-cache dmidecode pciutils; \
    GOBIN=/final/opt/ GOFLAGS="" go install gotest.tools/gotestsum@v1.7.0; \
fi

FROM lfedge/eve-fscrypt:d528516ed00f61a5ba4ba2407ab3a94bd55aff90 AS fscrypt
FROM lfedge/eve-dnsmasq:66334faad5620503b542c8faa2012c3697659ce2 AS dnsmasq
FROM lfedge/eve-gpt-tools:8e4f3e10e861373aa269b3ebeef483153f3399dc AS gpttools

# collector collects everything together and then does any processing like stripping binaries.
# We use this interim "collector" so that we can do processing.
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS collector
ENV BUILD_PKGS patch
ENV PKGS alpine-baselayout musl-utils libtasn1-progs pciutils yajl xz bash iptables ip6tables iproute2 \
    coreutils dmidecode libbz2 libuuid ipset curl radvd ethtool util-linux e2fsprogs libcrypto1.1 xorriso \
    qemu-img jq e2fsprogs-extra keyutils ca-certificates ip6tables-openrc iptables-openrc ipset-openrc hdparm \
    libintl libtirpc libblkid zlib rsync chrony wireless-tools wpa_supplicant
RUN eve-alpine-deploy.sh

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

WORKDIR /

RUN mkdir -p /out/usr/lib/xen/boot
COPY --from=uefi-build /OVMF_VARS.fd /out/usr/lib/xen/boot/OVMF_VARS.fd

COPY --from=zfs /out /out
COPY --from=fscrypt /opt/zededa/bin /out/opt/zededa/bin
COPY --from=gpttools / /out
COPY --from=dnsmasq /usr/sbin/dnsmasq /out/opt/zededa/bin/dnsmasq
# we use final directory and move the line to the bottom
# to avoid conflicts and speedup re-builds
COPY --from=build /final /out
COPY --from=build /usr/lib/dhcpcd /out/usr/lib/dhcpcd
COPY --from=build /sbin/dhcpcd /out/sbin/dhcpcd

COPY scripts/device-steps.sh \
    scripts/onboot.sh \
    scripts/handlezedserverconfig.sh \
    scripts/veth.sh \
    scripts/dhcpcd.sh \
    scripts/direct-net.sh \
    scripts/copy-image-to-qcow.sh \
    scripts/check-eval-state.sh \
    /out/opt/zededa/bin/
COPY conf/lisp.config.base /out/var/tmp/zededa/lisp.config.base

COPY patches/* /sys-patches/
# hadolint ignore=SC1097
RUN set -e && for patch in /sys-patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p0 --no-backup-if-mismatch -r /tmp/deleteme.rej < "$patch"; \
    done

# And now a few local tweaks
COPY rootfs/ /out

# We will start experimenting with stripping go binaries on ARM only for now
RUN if [ "$(uname -m)" = "aarch64" ] ; then                                             \
       apk add --no-cache findutils binutils file                                      ;\
       find /out -type f -executable -exec file {} \; | grep 'not stripped' | cut -f1 -d: |\
       xargs strip                                                                     ;\
       apk del findutils binutils file                                                 ;\
    fi

FROM scratch

SHELL ["/bin/sh", "-c"]

COPY --from=collector /out /

RUN rm -rf /usr/bin/qemu-storage-daemon

# FIXME: replace with tini+monit ASAP
WORKDIR /
CMD ["/init.sh"]
