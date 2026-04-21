# Copyright (c) 2018-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Dockerfile to build pillar

# use the same set of packages for simplicity
ARG BUILD_PKGS_BASE="git gcc linux-headers libc-dev make linux-pam-dev m4 findutils util-linux make patch \
                     libintl libuuid libtirpc libblkid libcrypto3 zlib tar"

# we use the same image in several places
ARG EVE_ALPINE_IMAGE=lfedge/eve-alpine:1f744180283ffb4eabcc3862531aeacf1de886b3

FROM lfedge/eve-uefi:382a7a614c0414cefabde13505f87b705a0a044c AS uefi-build
FROM lfedge/eve-dom0-ztools:12f3be8183942a1134241414bc265f624dbaad51 AS zfs
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
ENV CGO_CFLAGS="-Dfstat64=fstat -Dstat64=stat"

# hadolint ignore=DL3006,DL3029
FROM --platform=${BUILDPLATFORM} ${EVE_ALPINE_IMAGE} AS build-cross
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# hadolint ignore=DL3029
FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:d794c049baf50389be1dd48da056fb2472574c3e AS cross-compilers

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
ENV CGO_CFLAGS="-Dfstat64=fstat -Dstat64=stat --sysroot=/usr/${EVE_TARGET_ARCH}-alpine-linux-musl"
# GCC 14 no longer implicitly forwards --with-sysroot to the linker when acting as a
# linker driver. Passing it explicitly via CGO_LDFLAGS ensures ld.bfd finds crt1.o and
# all target libraries in the cross-compilation sysroot rather than the host arm64 paths.
ENV CGO_LDFLAGS="--sysroot=/usr/${EVE_TARGET_ARCH}-alpine-linux-musl"

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

ENV CC=${CROSS_COMPILE_ENV}gcc

# building with runtime stats
ARG RSTATS=n
ARG RSTATS_ENDPOINT=
ARG RSTATS_TAG=
ARG IMM_PROFILING=n
ENV IMM_PROFILING=${IMM_PROFILING}
ARG ARTIFICIAL_LEAK=n
ENV ARTIFICIAL_LEAK=${ARTIFICIAL_LEAK}
ARG COVER=n

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
RUN echo "COVER: ${COVER}"

# hadolint ignore=DL4006
RUN --mount=type=cache,target=/root/.cache/go-build echo "Running go vet" && make HV="$HV" vet && \
    echo "Running go fmt" && ERR="$(find . -name \*.go | grep -v /vendor/ | xargs gofmt -d -e -l -s)" && \
       if [ -n "$ERR" ] ; then printf 'go fmt Failed - ERR: %s' "$ERR" ; exit 1 ; fi && \
       make ZARCH=${TARGETARCH} HV="$HV" DEV="$DEV" COVER="$COVER" RSTATS=$RSTATS RSTATS_ENDPOINT=$RSTATS_ENDPOINT RSTATS_TAG=$RSTATS_TAG IMM_PROFILING=$IMM_PROFILING ARTIFICIAL_LEAK=$ARTIFICIAL_LEAK DISTDIR=/final/opt/zededa/bin BUILD_VERSION=${GOPKGVERSION} build

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

FROM lfedge/eve-fscrypt:e6a8b9da0aa85206bf84cbebd3a2c6e8df959216 AS fscrypt
FROM lfedge/eve-dnsmasq:960948b6a5627ec1d3815d58235d6f2ca64642bc AS dnsmasq
FROM lfedge/eve-gpt-tools:36b9660038be7724ef1a7d2e0458a33fe4489b45 AS gpttools

# dhcpcd: Alpine 3.21+ ships a sufficiently up-to-date version (10.x with required IPv6 fixes).
# No --platform means Docker BuildKit uses the target platform, giving us the correct binary arch.
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS dhcpcd-bin
ENV PKGS dhcpcd
RUN eve-alpine-deploy.sh

# collector collects everything together and then does any processing like stripping binaries.
# We use this interim "collector" so that we can do processing.
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS collector
ENV BUILD_PKGS patch
ENV PKGS alpine-baselayout musl-utils libtasn1-progs pciutils yajl xz bash iptables ip6tables iproute2 \
    coreutils dmidecode libbz2 libuuid ipset curl radvd ethtool util-linux e2fsprogs libcrypto3 xorriso \
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
COPY --from=dhcpcd-bin /out/usr/lib/dhcpcd /out/usr/lib/dhcpcd
COPY --from=dhcpcd-bin /out/sbin/dhcpcd /out/sbin/dhcpcd

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
