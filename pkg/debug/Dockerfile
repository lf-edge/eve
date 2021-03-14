# for debug container we need to build our own copy of musl
# with -fno-omit-frame-pointer to make sure that perf(1)
# has a fast path for stack unwinding. This also happens
# to be a perfect place to put any other kind of debug info
# into the package: see abuild/etc/abuild.conf.
FROM lfedge/eve-alpine:99db0c3af59a9656315c9d7a0ad8a24f631134b0 as build
ENV BUILD_PKGS abuild curl tar make linux-headers patch g++
# Feel free to add additional packages here, but be aware that
# EVE's rootfs image can be no larger than 300Mb
# RUN apk add --no-cache gdb valgrind
ENV PKGS openssh-client openssh-server tini util-linux ca-certificates pciutils usbutils vim tcpdump perf strace
RUN eve-alpine-deploy.sh

ENV LSHW_VERSION 02.19.2

# setting up building account
RUN adduser -G abuild -D builder
RUN su builder -c 'abuild-keygen -a -n'

COPY --chown=builder:abuild abuild/ /
RUN su builder -c 'cd /musl && abuild checksum && abuild -r'

# now install it locally so we can pick it up later on below
# hadolint ignore=DL3019,DL3018
RUN apk add -p /out --allow-untrusted /home/builder/packages/*/musl-*.apk

# hadolint ignore=DL4006
RUN curl -L https://www.ezix.org/software/files/lshw-B.${LSHW_VERSION}.tar.gz | tar xzvf -

COPY lshw/ lshw-B.${LSHW_VERSION}/

WORKDIR /lshw-B.${LSHW_VERSION}

# order is important
RUN for patch in fix-musl-sc_long_bit.patch wrapper-for-basename.patch 15565229509455527de9ce7cbb9530e2b31d043b.patch\
 2b1c730b493d647bbab4854713571458e82a81e7.patch; do patch -p1 < $patch; done &&\
 make -C src RPM_OPT_FLAGS=-DNONLS static &&\
 cp src/lshw-static /out/usr/bin/lshw && strip /out/usr/bin/lshw

FROM linuxkit/sshd:666b4a1a323140aa1f332826164afba506abf597

COPY ssh.sh spec.sh /usr/bin/
COPY --from=build /out/ /
