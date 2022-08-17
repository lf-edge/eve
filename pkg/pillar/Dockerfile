# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

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

ENV BUILD_PKGS git gcc linux-headers libc-dev make linux-pam-dev m4 findutils go util-linux make patch wget \
    libintl libuuid libtirpc libblkid libcrypto1.1 zlib
ENV PKGS alpine-baselayout musl-utils libtasn1-progs pciutils yajl xz bash iptables ip6tables iproute2 dhcpcd \
    coreutils dmidecode libbz2 libuuid ipset curl radvd ethtool util-linux e2fsprogs libcrypto1.1 xorriso \
    qemu-img jq e2fsprogs-extra keyutils ca-certificates ip6tables-openrc iptables-openrc ipset-openrc hdparm \
    libintl libtirpc libblkid zlib
RUN eve-alpine-deploy.sh

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

# we need zfs files during build
COPY --from=zfs /out /

# These three are supporting rudimentary cross-build capabilities.
# The only one supported so far is cross compiling for aarch64 on x86
ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1
ARG GOARCH=
ARG CROSS_GCC=https://musl.cc/aarch64-linux-musleabi-cross.tgz
RUN [ -z "$GOARCH" ] || wget -q -O - $CROSS_GCC | tar -C / -xzvf -

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

RUN if [ ${DEV} = "y" ]; then \
    CGO_ENABLED=0 go get -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv@v1.8.3 && \
    cp /root/go/bin/dlv /out/opt; \
fi

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
