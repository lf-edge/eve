# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# for debug container we need to build our own copy of musl
# with -fno-omit-frame-pointer to make sure that perf(1)
# has a fast path for stack unwinding. This also happens
# to be a perfect place to put any other kind of debug info
# into the package: see abuild/etc/abuild.conf.
FROM lfedge/eve-recovertpm:827a0328180abf4cb365c3d375e6a89a76ddcb39 AS recovertpm
FROM lfedge/eve-bpftrace:49b22c5e0daaf4e380fa18ffafdba7cfbdfb9f43 AS bpftrace
FROM lfedge/eve-alpine:80c5dbe1085d0650030be8a110eaec66ef532672 AS build
ENV BUILD_PKGS="abuild curl tar make linux-headers patch g++ git gcc gpg gettext gettext-static ncurses-dev jq autoconf openssl-dev zlib-dev zlib-static gpg-agent"
# Feel free to add additional packages here, but be aware that
# EVE's rootfs image can be no larger than 300Mb (and don't
# forget to check on all supported architectures: e.g. arm64
# binaries are typically larger than amd64 ones).
# RUN apk add --no-cache gdb valgrind
ENV PKGS="openssl tini util-linux ca-certificates pciutils usbutils tcpdump perf strace iproute2-minimal curl zlib procps-ng tar dmidecode iptables dhcpcd tio socat"

RUN eve-alpine-deploy.sh

ENV LSHW_VERSION="02.20"
ENV OPENSSH_VERSION="10.6p2"

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

WORKDIR /usr/src
ADD --checksum=sha256:9ae44872090cf2f06b3cf9ff147e7f16f309671340763ed2f99248398ae29d5b https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz /usr/src
ADD https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz.asc /usr/src
ADD https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/RELEASE_KEY.asc /usr/src

# import and verify in same `run` preventing db open race
RUN gpg --import --allow-weak-key-signatures /usr/src/RELEASE_KEY.asc && \
    gpg --verify --allow-weak-key-signatures openssh-${OPENSSH_VERSION}.tar.gz.asc openssh-${OPENSSH_VERSION}.tar.gz
RUN tar xvf openssh-${OPENSSH_VERSION}.tar.gz
WORKDIR /usr/src/openssh-${OPENSSH_VERSION}
# The old utmpx IPv6 fix is already included in upstream OpenSSH.
RUN ./configure \
    --prefix=/usr \
    --sysconfdir=/etc/ssh \
    --libexecdir=/usr/lib/ssh \
    --mandir=/usr/share/man \
    --with-pid-dir=/run \
    --with-mantype=doc \
    --disable-utmp \
    --disable-wtmp \
    --disable-lastlog \
    --disable-strip \
    --with-privsep-path=/var/empty \
    --with-xauth=/usr/bin/xauth \
    --with-default-path='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \
    --with-privsep-user=sshd

RUN make -j "$(getconf _NPROCESSORS_ONLN)"
RUN make install
ARG TARGETARCH
# QEMU user-mode cannot install the seccomp filter required by OpenSSH tests.
RUN if [ "$TARGETARCH" != riscv64 ]; then \
        HARNESS_JOBS="$(getconf _NPROCESSORS_ONLN)" make tests; \
    fi

RUN mkdir -p /out/usr/lib/ssh
RUN /usr/bin/install -c -m 0755 -s ssh /out/usr/bin/ssh
RUN /usr/bin/install -c -m 0755 -s scp /out/usr/bin/scp
RUN /usr/bin/install -c -m 0755 -s ssh-keyscan /out/usr/bin/ssh-keyscan
RUN /usr/bin/install -c -m 0755 -s ssh-keygen /out/usr/bin/ssh-keygen
RUN /usr/bin/install -c -m 0755 -s sshd /out/usr/sbin/sshd
RUN /usr/bin/install -c -m 0755 -s sshd-session /out/usr/lib/ssh/sshd-session
RUN /usr/bin/install -c -m 0755 -s sshd-auth /out/usr/lib/ssh/sshd-auth
RUN /usr/bin/install -c -m 0755 -s ssh-pkcs11-helper /out/usr/lib/ssh/ssh-pkcs11-helper
RUN /usr/bin/install -c -m 0755 -s ssh-sk-helper /out/usr/lib/ssh/ssh-sk-helper
RUN /usr/bin/install -c -m 0755 -s sftp /out/usr/bin/sftp
RUN /usr/bin/install -c -m 0755 -s sftp-server /out/usr/lib/ssh/sftp-server
RUN mkdir -p /out/etc/ssh
COPY ssh/* /out/etc/ssh/
RUN mkdir -p /out/var/empty
COPY register-sbom-pkg.sh /usr/local/bin/register-sbom-pkg.sh
RUN register-sbom-pkg.sh -n openssh -v "${OPENSSH_VERSION}" -l SSH-OpenSSH -u https://www.openssh.com/portable.html

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

RUN mkdir -p ./etc/ssh ./root/.ssh
RUN chmod 0700 ./root/.ssh
RUN cp /etc/passwd /etc/group ./etc/
RUN ln -s /run ./var/run

RUN mkdir /bpftrace
COPY --from=bpftrace / /bpftrace
RUN mkdir -p /bpftrace/bpftrace-aotrt

# add recover-tpm to debug container
WORKDIR /
COPY --from=recovertpm /usr/bin/recovertpm /out/usr/bin/recovertpm

FROM build AS openssh-test
COPY tests/openssh.sh /tmp/openssh-test.sh
RUN sh /tmp/openssh-test.sh
RUN chroot /out /usr/sbin/sshd -T -h /ssh-test/host_key > /tmp/sshd-effective.conf && \
    grep -qix 'passwordauthentication no' /tmp/sshd-effective.conf && \
    grep -qix 'kbdinteractiveauthentication no' /tmp/sshd-effective.conf

FROM openssh-test AS test
# run collect-info test
COPY collect-info-test /collect-info-test
WORKDIR /collect-info-test
RUN go test


FROM scratch
ENTRYPOINT []
WORKDIR /

COPY --from=build /out/ /
COPY --from=build /bpftrace/bpftrace-aotrt /

CMD ["/sbin/tini", "/usr/bin/debug-services.sh"]

