# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:3a7658b4168bcf40dfbcb15fbae8979d81efb6f1 as build

ARG DEV=n

ENV BUILD_PKGS git gcc linux-headers libc-dev make linux-pam-dev m4 findutils go util-linux make patch wget zfs-dev
ENV PKGS alpine-baselayout musl-utils libtasn1-progs pciutils yajl xz bash iptables ip6tables iproute2 dhcpcd coreutils dmidecode libbz2 libuuid ipset curl radvd ethtool util-linux e2fsprogs libcrypto1.1 xorriso qemu-img jq e2fsprogs-extra keyutils ca-certificates ip6tables-openrc iptables-openrc ipset-openrc hdparm zfs
RUN eve-alpine-deploy.sh

# FIXME bump eve-alpine to alpine 3.14
# hadolint ignore=DL3018
RUN apk --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/v3.14/community add -U --upgrade go && go version

RUN mkdir -p /go/src/github.com/google
WORKDIR /go/src/github.com/google
RUN git clone https://github.com/google/fscrypt
WORKDIR /go/src/github.com/google/fscrypt
RUN git reset --hard b41569d397d3e66099cde07d8eef36b2f42dd0ec
COPY fscrypt/* ./
RUN patch -p1 < patch01-no-pam.diff && \
    patch -p1 < patch02-rotate-raw-key.diff && \
    patch -p1 < patch03-vendor.diff && \
    patch -p1 < patch04-goConv.diff && \
    make && make DESTDIR=/out/opt/zededa/bin install

# These three are supporting rudimentary cross-build capabilities.
# The only one supported so far is cross compiling for aarch64 on x86
ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1
ARG GOARCH=
ARG CROSS_GCC=https://musl.cc/aarch64-linux-musleabi-cross.tgz
RUN [ -z "$GOARCH" ] || wget -O - $CROSS_GCC | tar -C / -xzvf -

ADD ./  /pillar/

# go vet/format and go install
WORKDIR /pillar

COPY pillar-patches/* /patches/
RUN set -e && for patch in ../patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 --no-backup-if-mismatch -r /tmp/deleteme.rej < "$patch"; \
    done

RUN [ -z "$GOARCH" ] || export CC=$(echo /*-cross/bin/*-gcc) ;\
    echo "Running go vet" && go vet ./... && \
    echo "Running go fmt" && ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
       if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: "$ERR ; exit 1 ; fi && \
    make DEV=$DEV DISTDIR=/out/opt/zededa/bin build

WORKDIR /

RUN if [ ${DEV} = "y" ]; then \
    CGO_ENABLED=0 go get -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv@v1.8.3 && \
    cp /root/go/bin/dlv /out/opt; \
fi

COPY patches/* /sys-patches/
# hadolint ignore=SC1097
RUN set -e && for patch in /sys-patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p0 < "$patch"; \
    done

# hadolint ignore=DL3006
FROM lfedge/eve-dnsmasq:cc2426e0f51538f60e82c7ffe26e6a857fdc2483 as dnsmasq
# hadolint ignore=DL3006
FROM lfedge/eve-strongswan:5b322e95477774eca6ecf2fbe10945b56ff5310b as strongswan
# hadolint ignore=DL3006
FROM lfedge/eve-gpt-tools:d4440cebd4cd3caef733880f401ecee964ff7c81 as gpttools

FROM scratch
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

COPY --from=build /out/ /
COPY --from=gpttools / /
COPY --from=dnsmasq /usr/sbin/dnsmasq /opt/zededa/bin/dnsmasq
COPY --from=strongswan / /

# We have to make sure configs survive in some location, but they don't pollute
# the default /config (since that is expected to be an empty mount point)
ADD conf/root-certificate.pem conf/server conf/server.production /opt/zededa/examples/config/
ADD scripts/device-steps.sh \
    scripts/handlezedserverconfig.sh \
    scripts/veth.sh \
  /opt/zededa/bin/
ADD conf/lisp.config.base /var/tmp/zededa/lisp.config.base

# And now a few local tweaks
COPY rootfs/ /

# We will start experimenting with stripping go binaries on ARM only for now
RUN if [ "$(uname -m)" = "aarch64" ] ; then                                             \
       apk add --no-cache findutils binutils file                                      ;\
       find / -type f -executable -exec file {} \; | grep 'not stripped' | cut -f1 -d: |\
       xargs strip                                                                     ;\
       apk del findutils binutils file                                                 ;\
    fi

SHELL ["/bin/sh", "-c"]

# FIXME: replace with tini+monit ASAP
WORKDIR /
CMD ["/init.sh"]
