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

FROM linuxkit/sshd:666b4a1a323140aa1f332826164afba506abf597

COPY ssh.sh /usr/bin/ssh.sh

# get the rebuilt musl from above
COPY --from=musl-build /lib/ld-musl-*.so.1 /lib/

# Feel free to add additional packages here, but be aware that
# EVE's rootfs image can be no larger than 300Mb
# RUN apk add --no-cache gdb valgrind
# hadolint ignore=DL3018
RUN apk add --no-cache pciutils usbutils vim tcpdump perf strace
