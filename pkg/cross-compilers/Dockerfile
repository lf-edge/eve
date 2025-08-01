FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as build-base
ENV BUILD_PKGS abuild curl tar make linux-headers patch g++ git gcc ncurses-dev autoconf file sudo
RUN eve-alpine-deploy.sh

ENV ALPINE_VERSION 3.16.9
ENV APORTS /home/builder/aports

# setting up building account and output directory
RUN adduser -G abuild -D builder && \
    echo 'builder ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    install -d -m 0755 -o builder -g abuild /packages

USER builder

RUN git config --global user.email 'builder@projecteve.dev' && git config --global user.name 'Project EVE' && \
    abuild-keygen -a -n -i && \
    mkdir /home/builder/packages

ADD --chown=builder:abuild https://gitlab.alpinelinux.org/alpine/aports/-/archive/"v${ALPINE_VERSION}"/aports-"v${ALPINE_VERSION}".tar.gz "${APORTS}"/aports.tar.gz

COPY --chown=builder:abuild patches/aports /home/builder/patches

WORKDIR $APORTS

RUN tar -xzvf aports.tar.gz --strip-components=1 && rm -rf aports.tar.gz

# Versions must be aligned with content of APKBUILD
ENV BINUTILS_VERSION 2.38
ENV MUSL_VERSION 1.2.3
ENV GCC_VERSION 11.2.1_git20220219
ADD --chown=builder:abuild https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/binutils/2.38-4ubuntu2.6/binutils_${BINUTILS_VERSION}.orig.tar.xz /var/cache/distfiles/binutils-${BINUTILS_VERSION}.tar.xz
ADD --chown=builder:abuild http://deb.debian.org/debian/pool/main/m/musl/musl_${MUSL_VERSION}.orig.tar.gz /var/cache/distfiles/musl-${MUSL_VERSION}.tar.gz
ADD --chown=builder:abuild https://dev.alpinelinux.org/~nenolod/gcc-${GCC_VERSION}.tar.xz /var/cache/distfiles/gcc-${GCC_VERSION}.tar.xz

RUN for patch in /home/builder/patches/*patch ; do patch -p1 < "$patch" ; done
RUN [ "riscv64" = "${EVE_BUILD_ARCH}" ] || sh -x ./scripts/bootstrap.sh "riscv64"
RUN [ "aarch64" = "${EVE_BUILD_ARCH}" ] || sh -x ./scripts/bootstrap.sh "aarch64"
RUN [ "armhf" = "${EVE_BUILD_ARCH}" ] || sh -x ./scripts/bootstrap.sh "armhf"
RUN [ "x86_64" = "${EVE_BUILD_ARCH}" ] || sh -x ./scripts/bootstrap.sh "x86_64"

RUN rm -rf /home/builder/packages/main/"${EVE_BUILD_ARCH}"/gcc-pass2*
RUN cp -r /home/builder/packages/main/"${EVE_BUILD_ARCH}" /packages/

FROM build-base as build-amd64
FROM build-base as build-arm64
FROM build-base as build-armhf
# we do not support cross-compilers for riscv64 host
# as gcc-gnat is not available on riscv64
# we cannot build cross-compilers without additional patches
FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as build-riscv64

# hadolint ignore=DL3006
FROM build-${TARGETARCH} as build
RUN mkdir -p /packages

FROM scratch
COPY --from=build /packages /packages
