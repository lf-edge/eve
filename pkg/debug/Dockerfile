# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# for debug container we need to build our own copy of musl
# with -fno-omit-frame-pointer to make sure that perf(1)
# has a fast path for stack unwinding. This also happens
# to be a perfect place to put any other kind of debug info
# into the package: see abuild/etc/abuild.conf.
FROM lfedge/eve-recovertpm:0da17f65aba4fb09c83944cf5847dd7b523118b4 as recovertpm
FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 as build
ENV BUILD_PKGS abuild curl tar make linux-headers patch g++ git gcc gpg ncurses-dev autoconf openssl-dev zlib-dev
# Feel free to add additional packages here, but be aware that
# EVE's rootfs image can be no larger than 300Mb (and don't
# forget to check on all supported architectures: e.g. arm64
# binaries are typically larger and amd64 ones).
# RUN apk add --no-cache gdb valgrind
ENV PKGS openssl tini util-linux ca-certificates pciutils usbutils vim tcpdump perf strace iproute2-minimal curl zlib

# These packages are not available on the riscv arch, so I have no idea how
# deliver those, but still install them on other archs.
ENV PKGS_amd64 procps tar dmidecode iptables dhcpcd tio socat
ENV PKGS_arm64 procps tar dmidecode iptables dhcpcd tio socat

RUN eve-alpine-deploy.sh

ENV LSHW_VERSION 02.19.2
ENV OPENSSH_VERSION 9.8p1

# setting up building account
RUN adduser -G abuild -D builder || :
RUN su builder -c 'abuild-keygen -a -n'

COPY --chown=builder:abuild abuild/ /
ENV MUSL_VERSION v1.2.3
ENV DISTFILES_MIRROR /tmp/mirror
ADD --chown=builder:abuild https://git.musl-libc.org/cgit/musl/snapshot/${MUSL_VERSION}.tar.gz ${DISTFILES_MIRROR}/musl-${MUSL_VERSION}.tar.gz
RUN su builder -c 'cd /musl && abuild checksum && abuild -r'

# now install it locally so we can pick it up later on below
# hadolint ignore=DL3019,DL3018
RUN apk add -p /out --allow-untrusted /home/builder/packages/*/musl-1.2*.apk

# hadolint ignore=DL4006
ADD https://www.ezix.org/software/files/lshw-B.${LSHW_VERSION}.tar.gz lshw.tar.gz
RUN tar -xzvf lshw.tar.gz

WORKDIR /
COPY lshw/ lshw-B.${LSHW_VERSION}/

WORKDIR /lshw-B.${LSHW_VERSION}

RUN for patch in *.patch; do \
   patch -p1 < "$patch"; \
 done && \
 make -C src RPM_OPT_FLAGS=-DNONLS static && \
 cp src/lshw-static /out/usr/bin/lshw && strip /out/usr/bin/lshw

# building hexedit
WORKDIR /tmp/hexedit/hexedit-1.5
# hadolint ignore=DL4006
ADD https://github.com/pixel/hexedit/archive/refs/tags/1.5.tar.gz ../1.5.tar.gz
RUN tar -C .. -xzvf ../1.5.tar.gz
RUN ./autogen.sh && ./configure && make DESTDIR=/out install

WORKDIR /usr/src
ADD https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz /usr/src
ADD https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz.asc /usr/src
COPY ssh/RELEASE_KEY.asc /usr/src
RUN gpg --import RELEASE_KEY.asc || :
RUN gpg --verify openssh-${OPENSSH_VERSION}.tar.gz.asc openssh-${OPENSSH_VERSION}.tar.gz
RUN tar xvf openssh-${OPENSSH_VERSION}.tar.gz
WORKDIR /usr/src/openssh-${OPENSSH_VERSION}
COPY ssh/fix-utmpx-ipv6.patch .
RUN git apply fix-utmpx-ipv6.patch
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
    --with-privsep-user=sshd \
    --with-ssl-engine

RUN make -j "$(getconf _NPROCESSORS_ONLN)"
RUN make install
# Disabling the rekey test saves at least a half hour of build time.  SKIP_LTESTS in README.regress
RUN HARNESS_JOBS="$(getconf _NPROCESSORS_ONLN)" make tests SKIP_LTESTS=rekey

RUN /usr/bin/install -c -m 0755 -s ssh /out/usr/bin/ssh
RUN /usr/bin/install -c -m 0755 -s scp /out/usr/bin/scp
RUN /usr/bin/install -c -m 0755 -s ssh-keygen /out/usr/bin/ssh-keygen
RUN /usr/bin/install -c -m 0755 -s sshd /out/usr/sbin/sshd
RUN /usr/bin/install -c -m 0755 -s sshd-session /out/usr/libexec/sshd-session
RUN /usr/bin/install -c -m 4711 -s ssh-keysign /out/usr/libexec/ssh-keysign
RUN /usr/bin/install -c -m 0755 -s ssh-pkcs11-helper /out/usr/libexec/ssh-pkcs11-helper
RUN /usr/bin/install -c -m 0755 -s ssh-sk-helper /out/usr/libexec/ssh-sk-helper
RUN /usr/bin/install -c -m 0755 -s sftp /out/usr/bin/sftp
RUN /usr/bin/install -c -m 0755 -s sftp-server /out/usr/libexec/sftp-server
RUN mkdir -p /out/etc/ssh
COPY ssh/* /out/etc/ssh/
RUN mkdir -p /out/var/empty

# tweaking various bit
WORKDIR /out
COPY ssh.sh spec.sh scripts/ ./usr/bin/
RUN mkdir -p ./etc/ssh ./root/.ssh
RUN chmod 0700 ./root/.ssh
RUN cp /etc/passwd /etc/group ./etc/
RUN ln -s /run ./var/run

# add recover-tpm to debug container
WORKDIR /
COPY --from=recovertpm /usr/bin/recovertpm /out/usr/bin/recovertpm

FROM scratch
ENTRYPOINT []
WORKDIR /

COPY --from=build /out/ /

CMD ["/sbin/tini", "/usr/bin/ssh.sh"]
