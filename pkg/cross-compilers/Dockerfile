FROM lfedge/eve-alpine:7b892c4653d567eb3b6a306064c3bc7fc14f6bab AS build-base
ENV BUILD_PKGS="abuild curl tar make linux-headers patch g++ git gcc ncurses-dev autoconf file sudo scdoc lua5.3-lzlib lua5.3"
RUN eve-alpine-deploy.sh

ENV ALPINE_VERSION=3.22.3
ENV APORTS=/home/builder/aports

RUN mkdir -p /tmp/armhf/bin
COPY armv6-alpine-linux-musleabihf-cc /tmp/armhf/bin
RUN chmod a+x /tmp/armhf/bin/armv6-alpine-linux-musleabihf-cc

# setting up building account and output directory
RUN adduser -G abuild -D builder && \
    echo 'builder ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    install -d -m 0755 -o builder -g abuild /packages

USER builder

RUN git config --global user.email 'builder@projecteve.dev'
RUN git config --global user.name 'Project EVE'
RUN abuild-keygen -a -n -i
RUN mkdir /home/builder/packages

ADD --chown=builder:abuild https://gitlab.alpinelinux.org/alpine/aports/-/archive/"v${ALPINE_VERSION}"/aports-"v${ALPINE_VERSION}".tar.gz "${APORTS}"/aports.tar.gz

COPY --chown=builder:abuild patches/aports /home/builder/patches

WORKDIR $APORTS

RUN tar -xzvf aports.tar.gz --strip-components=1 && rm -rf aports.tar.gz

ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/abuild-3.15.0.tar.gz /var/cache/distfiles/abuild-3.15.0.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/acl-2.3.2.tar.gz /var/cache/distfiles/acl-2.3.2.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/alpine-conf-3.20.0.tar.gz /var/cache/distfiles/alpine-conf-3.20.0.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/apk-tools-v2.14.9.tar.gz /var/cache/distfiles/apk-tools-v2.14.9.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/argon2-20190702.tar.gz /var/cache/distfiles/argon2-20190702.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/attr-2.5.2.tar.gz /var/cache/distfiles/attr-2.5.2.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/binutils-with-gold-2.44.tar.xz /var/cache/distfiles/binutils-with-gold-2.44.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/busybox-1.37.0.tar.bz2 /var/cache/distfiles/busybox-1.37.0.tar.bz2
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/ca-certificates-20250911.tar.bz2 /var/cache/distfiles/ca-certificates-20250911.tar.bz2
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/cryptsetup-2.7.5.tar.gz /var/cache/distfiles/cryptsetup-2.7.5.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/fakeroot-upstream-1.37.1.1.tar.gz /var/cache/distfiles/fakeroot-upstream-1.37.1.1.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/file-5.46.tar.gz /var/cache/distfiles/file-5.46.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/fortify-headers-1.1.tar.gz /var/cache/distfiles/fortify-headers-1.1.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/gcc-14.2.0.tar.xz /var/cache/distfiles/gcc-14.2.0.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/gmp-6.3.0.tar.xz /var/cache/distfiles/gmp-6.3.0.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/isl-0.26.tar.bz2 /var/cache/distfiles/isl-0.26.tar.bz2
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/json-c-0.18.tar.gz /var/cache/distfiles/json-c-0.18.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/kmod-34.2.tar.xz /var/cache/distfiles/kmod-34.2.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/lddtree-1.27.tar.gz /var/cache/distfiles/lddtree-1.27.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/libaio-libaio-0.3.113.tar.gz /var/cache/distfiles/libaio-libaio-0.3.113.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/libbsd-0.12.2.tar.xz /var/cache/distfiles/libbsd-0.12.2.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/libcap-2.76.tar.xz /var/cache/distfiles/libcap-2.76.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/libcap-ng-0.8.5.tar.gz /var/cache/distfiles/libcap-ng-0.8.5.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/libmd-1.1.0.tar.xz /var/cache/distfiles/libmd-1.1.0.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/libucontext-1.3.2.tar.xz /var/cache/distfiles/libucontext-1.3.2.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/linux-6.14.tar.xz /var/cache/distfiles/linux-6.14.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/LVM2.2.03.32.tgz /var/cache/distfiles/LVM2.2.03.32.tgz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/lzip-1.25.tar.gz /var/cache/distfiles/lzip-1.25.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/make-4.4.1.tar.gz /var/cache/distfiles/make-4.4.1.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/mkinitfs-3.12.0.tar.gz /var/cache/distfiles/mkinitfs-3.12.0.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/mpc-1.3.1.tar.gz /var/cache/distfiles/mpc-1.3.1.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/mpfr-4.2.1-patch01.patch /var/cache/distfiles/mpfr-4.2.1-patch01.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/mpfr-4.2.1.tar.xz /var/cache/distfiles/mpfr-4.2.1.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/musl-1.2.5.tar.gz /var/cache/distfiles/musl-1.2.5.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/ncurses-6.5-20250503.tgz /var/cache/distfiles/ncurses-6.5-20250503.tgz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/openrc-0.62.6.tar.gz /var/cache/distfiles/openrc-0.62.6.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/openssl-3.5.5.tar.gz /var/cache/distfiles/openssl-3.5.5.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/patch-2.8.tar.xz /var/cache/distfiles/patch-2.8.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/patch-6.14.2.patch.xz /var/cache/distfiles/patch-6.14.2.patch.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/pkgconf-2.4.3.tar.xz /var/cache/distfiles/pkgconf-2.4.3.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/popt-1.19.tar.gz /var/cache/distfiles/popt-1.19.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/protocols-6.4 /var/cache/distfiles/protocols-6.4
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-001.patch /var/cache/distfiles/readline82-001.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-002.patch /var/cache/distfiles/readline82-002.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-003.patch /var/cache/distfiles/readline82-003.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-004.patch /var/cache/distfiles/readline82-004.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-005.patch /var/cache/distfiles/readline82-005.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-006.patch /var/cache/distfiles/readline82-006.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-007.patch /var/cache/distfiles/readline82-007.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-008.patch /var/cache/distfiles/readline82-008.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-009.patch /var/cache/distfiles/readline82-009.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-010.patch /var/cache/distfiles/readline82-010.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-011.patch /var/cache/distfiles/readline82-011.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-012.patch /var/cache/distfiles/readline82-012.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline82-013.patch /var/cache/distfiles/readline82-013.patch
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/readline-8.2.tar.gz /var/cache/distfiles/readline-8.2.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/services-6.4 /var/cache/distfiles/services-6.4
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/sqlite-3490200-LICENSE.md /var/cache/distfiles/sqlite-3490200-LICENSE.md
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/sqlite-autoconf-3490200.tar.gz /var/cache/distfiles/sqlite-autoconf-3490200.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/tar-1.35.tar.xz /var/cache/distfiles/tar-1.35.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/util-linux-2.41.tar.xz /var/cache/distfiles/util-linux-2.41.tar.xz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/xz-5.8.1.tar.gz /var/cache/distfiles/xz-5.8.1.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/zlib-1.3.1.tar.gz /var/cache/distfiles/zlib-1.3.1.tar.gz
ADD --chown=builder:abuild --unpack=false https://distfiles.alpinelinux.org/distfiles/v3.22/zstd-1.5.7.tar.gz /var/cache/distfiles/zstd-1.5.7.tar.gz

RUN sudo chmod a+r /var/cache/distfiles/*

# do not unpack files
RUN [ "riscv64" = "${EVE_BUILD_ARCH}" ] || sh ./scripts/bootstrap.sh "riscv64"
RUN [ "aarch64" = "${EVE_BUILD_ARCH}" ] || sh -x ./scripts/bootstrap.sh "aarch64"
RUN [ "armhf" = "${EVE_BUILD_ARCH}" ] || PATH=/tmp/armhf/bin:$PATH sh -x ./scripts/bootstrap.sh "armhf"
RUN [ "x86_64" = "${EVE_BUILD_ARCH}" ] || sh -x ./scripts/bootstrap.sh "x86_64"

RUN rm -rf /home/builder/packages/main/"${EVE_BUILD_ARCH}"/gcc-pass2*
RUN cp -r /home/builder/packages/main/"${EVE_BUILD_ARCH}" /packages/

FROM build-base AS build-amd64
FROM build-base AS build-arm64
FROM build-base AS build-armhf
# we do not support cross-compilers for riscv64 host
# as gcc-gnat is not available on riscv64
# we cannot build cross-compilers without additional patches
FROM lfedge/eve-alpine:7b892c4653d567eb3b6a306064c3bc7fc14f6bab AS build-riscv64

# hadolint ignore=DL3006
FROM build-${TARGETARCH} AS build
RUN mkdir -p /packages

FROM scratch
COPY --from=build /packages /packages
