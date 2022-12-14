# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-fscrypt:0b7cc0d9d620e47fc54e21d56cb8a5cd224f9c9b as fscrypt

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

FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as build

ARG DEV=n

ENV BUILD_PKGS git gcc linux-headers libc-dev make linux-pam-dev m4 findutils go util-linux make patch \
    libintl libuuid libtirpc libblkid libcrypto1.1 zlib tar
ENV PKGS alpine-baselayout musl-utils libtasn1-progs pciutils yajl xz bash iptables ip6tables iproute2 dhcpcd \
    coreutils dmidecode libbz2 libuuid ipset curl radvd ethtool util-linux e2fsprogs libcrypto1.1 xorriso \
    qemu-img jq e2fsprogs-extra keyutils ca-certificates ip6tables-openrc iptables-openrc ipset-openrc hdparm \
    libintl libtirpc libblkid zlib
RUN eve-alpine-deploy.sh

COPY --from=fscrypt /opt/zededa/bin /out/opt/zededa/bin

# we need zfs files during build
COPY --from=zfs /out /

# These three are supporting rudimentary cross-build capabilities.
# The only one supported so far is cross compiling for aarch64 on x86
ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1
ARG GOARCH=
ARG CROSS_GCC=https://musl.cc/aarch64-linux-musl-cross.tgz
# hadolint ignore=DL3020
ADD ${CROSS_GCC} /cross.tgz
RUN [ -z "$GOARCH" ] || tar -C / -xzvf /cross.tgz && rm -f /cross.tgz

ADD ./  /pillar/

# go vet/format and go install
WORKDIR /pillar

COPY pillar-patches/* /patches/
RUN set -e && for patch in ../patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 --no-backup-if-mismatch -r /tmp/deleteme.rej < "$patch"; \
    done

# hadolint ignore=DL4006
RUN [ -z "$GOARCH" ] || export CC=$(echo /*-cross/bin/*-gcc) ;\
    echo "Running go vet" && go vet ./... && \
    echo "Running go fmt" && ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
       if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: "$ERR ; exit 1 ; fi && \
    make DEV=$DEV DISTDIR=/out/opt/zededa/bin build

WORKDIR /

ENV DELVE_VERSION 1.20.1
ENV DELVE_SOURCE=https://github.com/go-delve/delve/archive/refs/tags/v${DELVE_VERSION}.tar.gz
# hadolint ignore=DL3020
ADD ${DELVE_SOURCE} /delve.tar.gz
RUN if [ ${DEV} = "y" ]; then \
    tar --absolute-names -xz < /delve.tar.gz && \
    cd "/delve-${DELVE_VERSION}" &&  \
    GOFLAGS= CGO_ENABLED=0 GOBIN=/out/opt go install -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv ; \
fi

WORKDIR /

COPY patches/* /sys-patches/
# hadolint ignore=SC1097
RUN set -e && for patch in /sys-patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p0 --no-backup-if-mismatch -r /tmp/deleteme.rej < "$patch"; \
    done

# we need zfs files on running system
COPY --from=zfs /out /out

FROM lfedge/eve-dnsmasq:3af908d86a95a627c729e09b1b125bf8de7fadcb as dnsmasq
FROM lfedge/eve-strongswan:3f426e1c9fe2bbeb324a61c33b861c37459f616a as strongswan
FROM lfedge/eve-gpt-tools:ab2e9f924e22709b4e08ebedd6d3c6a2882d071e as gpttools

# collector collects everything together and then does any processing like stripping binaries.
# We use this interim "collector" so that we can do processing.
FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as collector

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# we put everything into /final
COPY --from=build /out/ /final
COPY --from=gpttools / /final
COPY --from=dnsmasq /usr/sbin/dnsmasq /final/opt/zededa/bin/dnsmasq
COPY --from=strongswan / /final

# We have to make sure configs survive in some location, but they don't pollute
# the default /config (since that is expected to be an empty mount point)
ADD conf/root-certificate.pem conf/server conf/server.production /final/opt/zededa/examples/config/
ADD scripts/device-steps.sh \
    scripts/onboot.sh \
    scripts/handlezedserverconfig.sh \
    scripts/veth.sh \
    scripts/dhcpcd.sh \
  /final/opt/zededa/bin/
ADD conf/lisp.config.base /final/var/tmp/zededa/lisp.config.base

# And now a few local tweaks
COPY rootfs/ /final

# We will start experimenting with stripping go binaries on ARM only for now
RUN if [ "$(uname -m)" = "aarch64" ] ; then                                             \
       apk add --no-cache findutils binutils file                                      ;\
       find /final -type f -executable -exec file {} \; | grep 'not stripped' | cut -f1 -d: |\
       xargs strip                                                                     ;\
       apk del findutils binutils file                                                 ;\
    fi

FROM scratch

SHELL ["/bin/sh", "-c"]

COPY --from=collector /final /

# FIXME: replace with tini+monit ASAP
WORKDIR /
CMD ["/init.sh"]
