# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# for debug container we need to build our own copy of musl
# with -fno-omit-frame-pointer to make sure that perf(1)
# has a fast path for stack unwinding. This also happens
# to be a perfect place to put any other kind of debug info
# into the package: see abuild/etc/abuild.conf.
FROM lfedge/eve-recovertpm:bd766d518e4d158c95775d6c0922f04694638c01 AS recovertpm
FROM lfedge/eve-bpftrace:ac4647a62438ecf5b0430f38cd3fee6f287c7c47 AS bpftrace
FROM lfedge/eve-alpine:7b892c4653d567eb3b6a306064c3bc7fc14f6bab AS build
ENV BUILD_PKGS="abuild curl tar make linux-headers patch g++ git gcc gpg gettext gettext-static ncurses-dev jq autoconf openssl-dev zlib-dev zlib-static gpg-agent"
# Feel free to add additional packages here, but be aware that
# EVE's rootfs image can be no larger than 300Mb (and don't
# forget to check on all supported architectures: e.g. arm64
# binaries are typically larger than amd64 ones).
# RUN apk add --no-cache gdb valgrind
ENV PKGS="openssl openssh-client openssh-server tini util-linux ca-certificates pciutils usbutils tcpdump strace iproute2-minimal curl zlib procps-ng tar dmidecode iptables dhcpcd tio socat"

RUN eve-alpine-deploy.sh

ENV LSHW_VERSION="02.20"

# setting up building account
RUN adduser -G abuild -D builder || :
RUN abuild-keygen -a -n

COPY --chown=builder:abuild abuild/ /
ENV MUSL_VERSION="1.2.5"
ENV DISTFILES_MIRROR="/tmp/mirror"
RUN mkdir -p ${DISTFILES_MIRROR}
ADD --chown=builder:abuild http://ftp.us.debian.org/debian/pool/main/m/musl/musl_${MUSL_VERSION}.orig.tar.gz /var/cache/distfiles//musl-v${MUSL_VERSION}.tar.gz
WORKDIR /musl
RUN abuild -F checksum
RUN abuild -r -F || :

WORKDIR /
# now install it locally so we can pick it up later on below
# hadolint ignore=DL3019,DL3018
RUN apk add -p /out --allow-untrusted /root/packages/*/musl-1.2*.apk

# hadolint ignore=DL4006
ADD https://www.ezix.org/software/files/lshw-B.${LSHW_VERSION}.tar.gz lshw.tar.gz
RUN tar -xzvf lshw.tar.gz

WORKDIR /
COPY lshw/ lshw-B.${LSHW_VERSION}/

WORKDIR /lshw-B.${LSHW_VERSION}

RUN for patch in *.patch; do \
    patch -p1 < "$patch"; \
    done && \
    make -C src VERSION=B.${LSHW_VERSION} NO_VERSION_CHECK=1  RPM_OPT_FLAGS=-DNONLS ZLIB=1 GZIP="busybox gzip -n9" static && \
    cp src/lshw-static /out/usr/bin/lshw && strip /out/usr/bin/lshw

# building hexedit
WORKDIR /tmp/hexedit/hexedit-1.5
# hadolint ignore=DL4006
ADD https://github.com/pixel/hexedit/archive/refs/tags/1.5.tar.gz ../1.5.tar.gz
RUN tar -C .. -xzvf ../1.5.tar.gz
RUN ./autogen.sh && ./configure && make DESTDIR=/out install

# tweaking various bit
WORKDIR /out
COPY debug-services.sh ssh-service.sh edgeview-collectinfo.sh spec.sh scripts/ ./usr/bin/
RUN mkdir -p ./etc/ssh ./root/.ssh && chmod 0700 ./root/.ssh
RUN cp /etc/passwd /etc/group ./etc/
RUN ln -s /run ./var/run
RUN sed -i -e 's#AllowTcpForwarding.*$#AllowTcpForwarding yes#' ./etc/ssh/sshd_config

RUN mkdir /bpftrace
COPY --from=bpftrace / /bpftrace
RUN mkdir -p /bpftrace/bpftrace-aotrt

# add recover-tpm to debug container
WORKDIR /
COPY --from=recovertpm /usr/bin/recovertpm /out/usr/bin/recovertpm

FROM build AS test
# run collect-info test
COPY collect-info-test /collect-info-test
WORKDIR /collect-info-test
RUN go test

FROM scratch
ENTRYPOINT []
WORKDIR /

COPY --from=build /out/ /
COPY --from=build /bpftrace/bpftrace-aotrt /

RUN rm -rf /usr/share/vim/vim82/doc/

CMD ["/sbin/tini", "/usr/bin/debug-services.sh"]
