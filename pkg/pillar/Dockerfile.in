# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
ARG GOVER=1.12.4
FROM golang:${GOVER}-alpine as build
RUN apk update
RUN apk add --no-cache git gcc linux-headers libc-dev util-linux libpcap-dev make

# These three are supporting rudimentary cross-build capabilities.
# The only one supported so far is cross compiling for aarch64 on x86
ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1
ARG GOARCH=
ARG CROSS_GCC=https://musl.cc/aarch64-linux-musleabi-cross.tgz
RUN [ -z "$GOARCH" ] || (cd / ; apk add --no-cache wget && wget -O - $CROSS_GCC | tar xzvf -)

ADD ./  /pillar/

# go vet/format and go install
WORKDIR /pillar
RUN [ -z "$GOARCH" ] || export CC=$(echo /*-cross/bin/*-gcc) ;\
    echo "Running go vet" && go vet ./... && \
    echo "Running go fmt" && ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
       if [ -n "$ERR" ] ; then echo $ERR ; exit 1 ; fi && \
    make DISTDIR=/dist build

# hadolint ignore=DL3006
FROM LISP_TAG as lisp
# hadolint ignore=DL3006
FROM XENTOOLS_TAG as xen-tools
# hadolint ignore=DL3006
FROM DNSMASQ_TAG as dnsmasq
# hadolint ignore=DL3006
FROM STRONGSWAN_TAG as strongswan
# hadolint ignore=DL3006
FROM GPTTOOLS_TAG as gpttools
# hadolint ignore=DL3006
FROM WATCHDOG_TAG as watchdog

FROM alpine:3.8
RUN apk add --no-cache \
    yajl xz bash openssl iptables ip6tables iproute2 dhcpcd \
    apk-cron coreutils dmidecode sudo libbz2 libuuid ipset \
    libaio logrotate pixman glib curl radvd perl ethtool \
    util-linux e2fsprogs libcrypto1.0 xorriso \
    python libpcap libffi

# The following is for xen-tools
RUN [ `uname -m` = "aarch64" ] && apk add --no-cache libfdt || :

# We have to make sure configs survive in some location, but they don't pollute
# the default /config (since that is expected to be an empty mount point)
ADD conf/root-certificate.pem conf/server conf/server.production /opt/zededa/examples/config/
ADD scripts/device-steps.sh \
    scripts/generate-device.sh \
    scripts/generate-self-signed.sh \
    scripts/handlezedserverconfig.sh \
    scripts/watchdog-report.sh \
  /opt/zededa/bin/
ADD conf/AssignableAdapters /var/tmp/zededa/AssignableAdapters
ADD conf/DeviceNetworkConfig /var/tmp/zededa/DeviceNetworkConfig
ADD conf/lisp.config.base /var/tmp/zededa/lisp.config.base

COPY --from=build /dist /opt/zededa/bin
COPY --from=xen-tools / /
COPY --from=lisp / /
COPY --from=gpttools / /
COPY --from=dnsmasq /usr/sbin/dnsmasq /opt/zededa/bin/dnsmasq
COPY --from=strongswan / /
COPY --from=watchdog /usr/sbin /usr/sbin

# And now a few local tweaks
COPY rootfs/ /
# logrotate requires restricted permissions
RUN chmod 644 /etc/logrotate.d/zededa

# FIXME: replace with tini+monit ASAP
WORKDIR /
CMD /init.sh
