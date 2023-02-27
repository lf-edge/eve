# for debug container we need to build our own copy of musl
# with -fno-omit-frame-pointer to make sure that perf(1)
# has a fast path for stack unwinding. This also happens
# to be a perfect place to put any other kind of debug info
# into the package: see abuild/etc/abuild.conf.
FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb as build
ENV BUILD_PKGS abuild curl tar make linux-headers patch g++ git gcc ncurses-dev autoconf
# Feel free to add additional packages here, but be aware that
# EVE's rootfs image can be no larger than 300Mb (and don't
# forget to check on all supported architectures: e.g. arm64
# binaries are typically larger and amd64 ones).
# RUN apk add --no-cache gdb valgrind
ENV PKGS openssl openssh-client openssh-server tini util-linux ca-certificates pciutils usbutils vim tcpdump perf strace iproute2-minimal curl
RUN eve-alpine-deploy.sh

ENV LSHW_VERSION 02.19.2

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

# tweaking various bit
WORKDIR /out
COPY ssh.sh spec.sh scripts/ ./usr/bin/
RUN mkdir -p ./etc/ssh ./root/.ssh && chmod 0700 ./root/.ssh
RUN cp /etc/passwd /etc/group ./etc/
RUN ln -s /run ./var/run
RUN sed -i -e 's#AllowTcpForwarding.*$#AllowTcpForwarding yes#' ./etc/ssh/sshd_config

FROM scratch
ENTRYPOINT []
WORKDIR /

COPY --from=build /out/ /

CMD ["/sbin/tini", "/usr/bin/ssh.sh"]
