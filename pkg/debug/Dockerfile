# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# for debug container we need to build our own copy of musl
# with -fno-omit-frame-pointer to make sure that perf(1)
# has a fast path for stack unwinding. This also happens
# to be a perfect place to put any other kind of debug info
# into the package: see abuild/etc/abuild.conf.
FROM lfedge/eve-recovertpm:65bbf2b0bc6bee41d43774d7a5aa6c962fa894f0 AS recovertpm
FROM lfedge/eve-bpftrace:2e05faecb6a725acdd5a57ff2c74ee214b0261a7 AS bpftrace
FROM lfedge/eve-alpine:a5885b38222df4ba5add4acca2d219c85741bf79 AS openssh
ENV BUILD_PKGS="abuild curl tar make linux-headers patch g++ git gcc gpg gettext gettext-static ncurses-dev jq autoconf openssl-dev zlib-dev zlib-static gpg-agent pciutils usbutils lsblk"
# Feel free to add additional packages here, but be aware that
# EVE's rootfs image can be no larger than 300Mb (and don't
# forget to check on all supported architectures: e.g. arm64
# binaries are typically larger than amd64 ones).
# RUN apk add --no-cache gdb valgrind
ENV PKGS="openssl openssh-client openssh-server tini util-linux ca-certificates pciutils usbutils tcpdump strace iproute2-minimal curl zlib procps-ng tar dmidecode iptables dhcpcd tio socat"

RUN eve-alpine-deploy.sh

# Alpine 3.22 backported the upstream password-authentication fix in r11.
# Install its signed APKs without rebuilding the shared Alpine package cache.
# Pin every architecture's archives to keep builds reproducible.
ENV OPENSSH_VERSION="10.0_p1-r11"
COPY openssh.sha256 /tmp/openssh.sha256
WORKDIR /tmp/openssh
# Local APK filenames and SHA-256 checksums pin every package version.
# hadolint ignore=DL3018
RUN set -eu; \
    arch="$(apk --print-arch)"; \
    mkdir -p "$arch"; \
    grep "  $arch/" /tmp/openssh.sha256 > checksums; \
    while read -r _checksum package; do \
        curl -fsSL "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/$package" -o "$package"; \
    done < checksums; \
    sha256sum -c checksums; \
    apk add --no-network --no-cache --root /out "$arch"/*.apk; \
    apk --root /out info -v > /tmp/openssh-installed; \
    grep -Fx "openssh-server-${OPENSSH_VERSION}" /tmp/openssh-installed; \
    rm -rf /tmp/openssh /tmp/openssh-installed
WORKDIR /

FROM openssh AS openssh-test
RUN cp /etc/passwd /etc/group /out/etc/
COPY tests/openssh.sh /tmp/openssh-test.sh
RUN sh /tmp/openssh-test.sh

FROM openssh AS build
WORKDIR /
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

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# Ensure that the output of spec.sh is valid json
RUN ./usr/bin/spec.sh -v 2>/dev/null | jq . > /dev/null || ./usr/bin/spec.sh -v
RUN ./usr/bin/spec.sh 2>/dev/null | jq . > /dev/null || ./usr/bin/spec.sh
RUN mkdir /tmp/bin
COPY tests/lsusb /tmp/bin
RUN chmod a+x /tmp/bin/lsusb
RUN PATH=/tmp/bin:$PATH /out/usr/bin/spec.sh -u 2>/dev/null | jq . > /dev/null || ./usr/bin/spec.sh -u

RUN mkdir -p ./etc/ssh ./root/.ssh && chmod 0700 ./root/.ssh
RUN cp /etc/passwd /etc/group ./etc/
RUN ln -s /run ./var/run
RUN sed -i -e 's#AllowTcpForwarding.*$#AllowTcpForwarding yes#' ./etc/ssh/sshd_config
# No account has a password, so key-only login changes nothing that is
# allowed; it stops sshd from offering password methods to the network.
RUN mkdir -p ./etc/ssh/sshd_config.d && \
    printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
      > ./etc/ssh/sshd_config.d/10-eve-pubkey-only.conf

RUN mkdir /bpftrace
COPY --from=bpftrace / /bpftrace
RUN mkdir -p /bpftrace/bpftrace-aotrt

# add recover-tpm to debug container
WORKDIR /
COPY --from=recovertpm /usr/bin/recovertpm /out/usr/bin/recovertpm

FROM build AS test
COPY tests/openssh.sh /tmp/openssh-test.sh
RUN sh /tmp/openssh-test.sh
RUN chroot /out /usr/sbin/sshd -T -h /ssh-test/host_key > /tmp/sshd-effective.conf && \
    grep -qix 'passwordauthentication no' /tmp/sshd-effective.conf && \
    grep -qix 'kbdinteractiveauthentication no' /tmp/sshd-effective.conf
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
