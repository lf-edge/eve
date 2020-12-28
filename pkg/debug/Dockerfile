# for debug container we need to build our own copy of musl
# with -fno-omit-frame-pointer to make sure that perf(1)
# has a fast path for stack unwinding. This also happens
# to be a perfect place to put any other kind of debug info
# into the package: see abuild/etc/abuild.conf.
FROM alpine:3.12 as musl-build

# setting up building account
# hadolint ignore=DL3019
RUN apk add abuild
RUN adduser -G abuild -D builder
RUN su builder -c 'abuild-keygen -a -n'

COPY --chown=builder:abuild abuild/ /
RUN su builder -c 'cd /musl && abuild checksum && abuild -r'

# now install it locally so we can pick it up later on below
# hadolint ignore=DL3019,DL3018
RUN apk add --allow-untrusted /home/builder/packages/*/musl-*.apk

FROM alpine:3.12 as lshw-build

ENV LSHW_VERSION 02.19.2

RUN apk add --no-cache curl=7.69.1-r3 tar=1.32-r1 make=4.3-r0 linux-headers=5.4.5-r1 patch=2.7.6-r6 g++=9.3.0-r2

# hadolint ignore=DL4006
RUN curl -L https://www.ezix.org/software/files/lshw-B.${LSHW_VERSION}.tar.gz | tar xzvf -

COPY lshw/ lshw-B.${LSHW_VERSION}/

WORKDIR /lshw-B.${LSHW_VERSION}

# order is important
RUN for patch in fix-musl-sc_long_bit.patch wrapper-for-basename.patch 15565229509455527de9ce7cbb9530e2b31d043b.patch\
 2b1c730b493d647bbab4854713571458e82a81e7.patch; do patch -p1 < $patch; done &&\
 make -C src RPM_OPT_FLAGS=-DNONLS static &&\
 cp src/lshw-static /lshw && strip /lshw

FROM linuxkit/sshd:666b4a1a323140aa1f332826164afba506abf597

COPY ssh.sh /usr/bin/ssh.sh
# get the rebuilt musl from above
COPY --from=musl-build /lib/ld-musl-*.so.1 /lib/

# Feel free to add additional packages here, but be aware that
# EVE's rootfs image can be no larger than 300Mb
# RUN apk add --no-cache gdb valgrind
# hadolint ignore=DL3018
RUN apk add --no-cache pciutils usbutils vim tcpdump perf strace

COPY --from=lshw-build /lshw /usr/bin/lshw
