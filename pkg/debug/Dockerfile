# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# for debug container we need to build our own copy of musl
# with -fno-omit-frame-pointer to make sure that perf(1)
# has a fast path for stack unwinding. This also happens
# to be a perfect place to put any other kind of debug info
# into the package: see abuild/etc/abuild.conf.
# Fetch only the target architecture's signed APKs. Remote ADD works with
# LinuxKit's offline RUN steps and verifies every archive before installation.
FROM scratch AS openssh-apks-amd64
ADD --checksum=sha256:955f644d912f5906d38c286bf4d4c3000557872bb0065a9439b318b20c03cc36 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/openssh-client-common-10.0_p1-r11.apk /openssh-client-common-10.0_p1-r11.apk
ADD --checksum=sha256:38302fe12d30a19e08ce47decf20b14bf405396952feeaf9feaa0d5a4cf85544 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/openssh-client-default-10.0_p1-r11.apk /openssh-client-default-10.0_p1-r11.apk
ADD --checksum=sha256:59ef4542f5e6e61fb32e3ece3442e9ec8575ea22096edc1a5aad03b6c28ee6bb https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/openssh-keygen-10.0_p1-r11.apk /openssh-keygen-10.0_p1-r11.apk
ADD --checksum=sha256:95f9a9073ae00fd9587f1e4ca87159ae53ed6355b897472de2bdcec56c1776a6 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/openssh-server-common-10.0_p1-r11.apk /openssh-server-common-10.0_p1-r11.apk
ADD --checksum=sha256:9a40af11bd5a81360df0fb498685ba13de9c736fda8dea23b4ec85b352a38303 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/openssh-server-10.0_p1-r11.apk /openssh-server-10.0_p1-r11.apk
ADD --checksum=sha256:e9344b149bdc49e18f8826d19ebca9d0d0623c6500c92314d83ffd96cd344bb7 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/openssh-sftp-server-10.0_p1-r11.apk /openssh-sftp-server-10.0_p1-r11.apk

FROM scratch AS openssh-apks-arm64
ADD --checksum=sha256:15d6ccd99985488525755657cdf9a820405217ce79be9476d7550350a5b56a16 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/openssh-client-common-10.0_p1-r11.apk /openssh-client-common-10.0_p1-r11.apk
ADD --checksum=sha256:8df7c09e340fefe4c0e46a9af5eb41be6f40fff7eb35906d8e0258b477f50063 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/openssh-client-default-10.0_p1-r11.apk /openssh-client-default-10.0_p1-r11.apk
ADD --checksum=sha256:876102399f823493106775d262ae9a0a02cd27ceffeedc227d4f9b1ed8ecebf5 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/openssh-keygen-10.0_p1-r11.apk /openssh-keygen-10.0_p1-r11.apk
ADD --checksum=sha256:f9783580372b7ba22b4233b2184f9991b91e6578975aad3778534e466064f107 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/openssh-server-common-10.0_p1-r11.apk /openssh-server-common-10.0_p1-r11.apk
ADD --checksum=sha256:bf9fd3fb8840c679699ca57b3953e853db28613422f2229e9c1b0e382ee50f0d https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/openssh-server-10.0_p1-r11.apk /openssh-server-10.0_p1-r11.apk
ADD --checksum=sha256:fbddd2b28333949efbed4b650339cc0a0397f9a8ddee4bbb45199e51d872d8ce https://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64/openssh-sftp-server-10.0_p1-r11.apk /openssh-sftp-server-10.0_p1-r11.apk

FROM scratch AS openssh-apks-riscv64
ADD --checksum=sha256:8cb1bc3632bcf508f8848fbe290146b71e11d327cffb62f1981527d44f168de4 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/riscv64/openssh-client-common-10.0_p1-r11.apk /openssh-client-common-10.0_p1-r11.apk
ADD --checksum=sha256:223249bd5e4ea099d79f3245c9f783d3c352022364295842993cad5ced45c6a0 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/riscv64/openssh-client-default-10.0_p1-r11.apk /openssh-client-default-10.0_p1-r11.apk
ADD --checksum=sha256:0f785298eb0652b580bea1c9d7c96e2d5ad528f40f9de6367ecd7f432c0239cd https://dl-cdn.alpinelinux.org/alpine/v3.22/main/riscv64/openssh-keygen-10.0_p1-r11.apk /openssh-keygen-10.0_p1-r11.apk
ADD --checksum=sha256:13f07cbbbe65153e18eeb592c30cc9d1a75f49ecd5536db6870555910a5ff835 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/riscv64/openssh-server-common-10.0_p1-r11.apk /openssh-server-common-10.0_p1-r11.apk
ADD --checksum=sha256:a1d8d29c4dc64e61b1ecf2ef8e10a23ad8852e0f81b59916dfa73cfc1cf5eeb1 https://dl-cdn.alpinelinux.org/alpine/v3.22/main/riscv64/openssh-server-10.0_p1-r11.apk /openssh-server-10.0_p1-r11.apk
ADD --checksum=sha256:843c0990376da94072d6314eae0f8c3c74b6c435967ae3d57c1c0c35651f98bd https://dl-cdn.alpinelinux.org/alpine/v3.22/main/riscv64/openssh-sftp-server-10.0_p1-r11.apk /openssh-sftp-server-10.0_p1-r11.apk

# Select a local build stage, not an external image.
# hadolint ignore=DL3006
FROM openssh-apks-${TARGETARCH} AS openssh-apks

FROM lfedge/eve-recovertpm:34cfcfc5b29ac6fe414b41a24192e708f2dcf4fa AS recovertpm
FROM lfedge/eve-bpftrace:a8524baac7a576365895cfde5fa8e4cbe98bfdb3 AS bpftrace
FROM lfedge/eve-alpine:4635a9f93267ec0e24005aa80f2e7b1b828e5d17 AS openssh
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
COPY --from=openssh-apks / /tmp/openssh/
# Local APK filenames and ADD checksums pin every package version.
# hadolint ignore=DL3018
RUN set -eu; \
    apk add --no-network --no-cache --root /out /tmp/openssh/*.apk; \
    apk --root /out info -v > /tmp/openssh-installed; \
    grep -Fx "openssh-server-${OPENSSH_VERSION}" /tmp/openssh-installed; \
    rm -rf /tmp/openssh /tmp/openssh-installed

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

# hadolint ignore=SC2046
RUN for patch in *.patch; do \
    patch -p1 < "$patch"; \
    done && \
    make -j$(nproc) -C src VERSION=B.${LSHW_VERSION} NO_VERSION_CHECK=1 RPM_OPT_FLAGS=-DNONLS ZLIB=1 core && \
    make -j$(nproc) -C src VERSION=B.${LSHW_VERSION} NO_VERSION_CHECK=1 RPM_OPT_FLAGS=-DNONLS ZLIB=1 GZIP="busybox gzip -n9" static && \
    cp src/lshw-static /out/usr/bin/lshw && strip /out/usr/bin/lshw

# Register lshw in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n lshw -v "B.${LSHW_VERSION}" -l GPL-2.0-only -u https://www.ezix.org/software/files/lshw

# building hexedit
WORKDIR /tmp/hexedit/hexedit-1.5
# hadolint ignore=DL4006
ADD https://github.com/pixel/hexedit/archive/refs/tags/1.5.tar.gz ../1.5.tar.gz
RUN tar -C .. -xzvf ../1.5.tar.gz
# hadolint ignore=SC2046
RUN ./autogen.sh && ./configure && make -j$(nproc) && make DESTDIR=/out install

# Register hexedit in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n hexedit -v 1.5 -l GPL-2.0-only -u https://github.com/pixel/hexedit

# tweaking various bit
WORKDIR /out
COPY debug-services.sh ssh-service.sh edgeview-collectinfo.sh spec.sh scripts/ ./usr/bin/

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# Ensure that the output of spec.sh is valid json
RUN ./usr/bin/spec.sh -v 2>/dev/null | jq . > /dev/null
RUN ./usr/bin/spec.sh 2>/dev/null | jq . > /dev/null
RUN mkdir /tmp/bin
COPY tests/lsusb /tmp/bin
RUN chmod a+x /tmp/bin/lsusb
RUN PATH=/tmp/bin:$PATH /out/usr/bin/spec.sh -u 2>/dev/null | jq .

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
