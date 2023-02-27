# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# use the same set of packages for simplicity
ARG BUILD_PKGS_BASE="git gcc linux-headers libc-dev make linux-pam-dev m4 findutils go util-linux make patch \
                     libintl libuuid libtirpc libblkid libcrypto1.1 zlib tar"

# we use the same image in several places
ARG EVE_ALPINE_IMAGE=lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb

FROM lfedge/eve-dom0-ztools:417d4ff6a57d2317c9e65166274b0ea6f6da16e2 as zfs
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
FROM ${EVE_ALPINE_IMAGE} as build-native
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# hadolint ignore=DL3006,DL3029
FROM --platform=${BUILDPLATFORM} ${EVE_ALPINE_IMAGE} as build-cross
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# hadolint ignore=DL3029
FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:2a1d062fce410865e7024a83de327a68e52db26c AS cross-compilers

# will use several packages from target arch and copy them to sysroot
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS cross-compile-libs
ENV PKGS musl-dev libgcc libintl libuuid libtirpc libblkid
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
ARG TARGETARCH

# building with runtime stats
ARG RSTATS=n
ARG RSTATS_ENDPOINT=
ARG RSTATS_TAG=

# we need zfs files during build
COPY --from=zfs /out /

ADD ./  /pillar/

# go vet/format and go install
WORKDIR /pillar

ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=${TARGETARCH}
ENV CC=${CROSS_COMPILE_ENV}gcc

COPY pillar-patches/* /patches/
RUN set -e && for patch in ../patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 --no-backup-if-mismatch -r /tmp/deleteme.rej < "$patch"; \
    done

# hadolint ignore=DL4006
RUN --mount=type=cache,target=/root/.cache/go-build echo "Running go vet" && go vet ./... && \
    echo "Running go fmt" && ERR="$(find . -name \*.go | grep -v /vendor/ | xargs gofmt -d -e -l -s)" && \
       if [ -n "$ERR" ] ; then printf 'go fmt Failed - ERR: %s' "$ERR" ; exit 1 ; fi && \
       make DEV="$DEV" RSTATS=$RSTATS RSTATS_ENDPOINT=$RSTATS_ENDPOINT RSTATS_TAG=$RSTATS_TAG DISTDIR=/final/opt/zededa/bin build

WORKDIR /

ENV DELVE_VERSION 1.20.1
ENV DELVE_SOURCE=https://github.com/go-delve/delve/archive/refs/tags/v${DELVE_VERSION}.tar.gz
# hadolint ignore=DL3020
ADD ${DELVE_SOURCE} /delve.tar.gz
RUN --mount=type=cache,target=/root/.cache/go-build if [ ${DEV} = "y" ]; then \
    tar --absolute-names -xz < /delve.tar.gz && \
    cd "/delve-${DELVE_VERSION}" &&  \
    GOFLAGS= CGO_ENABLED=0 go build -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv && \
    cp dlv /final/opt/ ; \
fi

FROM lfedge/eve-fscrypt:0b7cc0d9d620e47fc54e21d56cb8a5cd224f9c9b as fscrypt
FROM lfedge/eve-dnsmasq:3af908d86a95a627c729e09b1b125bf8de7fadcb as dnsmasq
FROM lfedge/eve-gpt-tools:ab2e9f924e22709b4e08ebedd6d3c6a2882d071e as gpttools

# collector collects everything together and then does any processing like stripping binaries.
# We use this interim "collector" so that we can do processing.
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} as collector
ENV BUILD_PKGS patch
ENV PKGS alpine-baselayout musl-utils libtasn1-progs pciutils yajl xz bash iptables ip6tables iproute2 dhcpcd \
    coreutils dmidecode libbz2 libuuid ipset curl radvd ethtool util-linux e2fsprogs libcrypto1.1 xorriso \
    qemu-img jq e2fsprogs-extra keyutils ca-certificates ip6tables-openrc iptables-openrc ipset-openrc hdparm \
    libintl libtirpc libblkid zlib
RUN eve-alpine-deploy.sh

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

WORKDIR /

COPY patches/* /sys-patches/
# hadolint ignore=SC1097
RUN set -e && for patch in /sys-patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p0 --no-backup-if-mismatch -r /tmp/deleteme.rej < "$patch"; \
    done

COPY --from=zfs /out /out
COPY --from=fscrypt /opt/zededa/bin /out/opt/zededa/bin
COPY --from=gpttools / /out
COPY --from=dnsmasq /usr/sbin/dnsmasq /out/opt/zededa/bin/dnsmasq
# we use final directory and move the line to the bottom
# to avoid conflicts and speedup re-builds
COPY --from=build /final /out

# We have to make sure configs survive in some location, but they don't pollute
# the default /config (since that is expected to be an empty mount point)
ADD conf/root-certificate.pem conf/server conf/server.production /out/opt/zededa/examples/config/
ADD scripts/device-steps.sh \
    scripts/onboot.sh \
    scripts/handlezedserverconfig.sh \
    scripts/veth.sh \
    scripts/dhcpcd.sh \
  /out/opt/zededa/bin/
ADD conf/lisp.config.base /out/var/tmp/zededa/lisp.config.base

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

# FIXME: replace with tini+monit ASAP
WORKDIR /
CMD ["/init.sh"]
