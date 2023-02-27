FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb as build-base
ENV BUILD_PKGS abuild curl tar make linux-headers patch g++ git gcc ncurses-dev autoconf file sudo
RUN eve-alpine-deploy.sh

ENV ALPINE_VERSION 3.16.2
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
ADD --chown=builder:abuild https://ftp.gnu.org/gnu/binutils/binutils-${BINUTILS_VERSION}.tar.xz /var/cache/distfiles/binutils-${BINUTILS_VERSION}.tar.xz
ADD --chown=builder:abuild https://git.musl-libc.org/cgit/musl/snapshot/v${MUSL_VERSION}.tar.gz /var/cache/distfiles/musl-v${MUSL_VERSION}.tar.gz
ADD --chown=builder:abuild https://dev.alpinelinux.org/~nenolod/gcc-${GCC_VERSION}.tar.xz /var/cache/distfiles/gcc-${GCC_VERSION}.tar.xz

RUN for patch in /home/builder/patches/*patch ; do patch -p1 < "$patch" ; done
RUN [ "riscv64" = "${EVE_BUILD_ARCH}" ] || sh -x ./scripts/bootstrap.sh "riscv64"
RUN [ "aarch64" = "${EVE_BUILD_ARCH}" ] || sh -x ./scripts/bootstrap.sh "aarch64"
RUN [ "x86_64" = "${EVE_BUILD_ARCH}" ] || sh -x ./scripts/bootstrap.sh "x86_64"

RUN rm -rf /home/builder/packages/main/"${EVE_BUILD_ARCH}"/gcc-pass2*
RUN cp -r /home/builder/packages/main/"${EVE_BUILD_ARCH}" /packages/

FROM build-base as build-amd64
FROM build-base as build-arm64
# we do not support cross-compilers for riscv64 host
# as gcc-gnat is not available on riscv64
# we cannot build cross-compilers without additional patches
FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb as build-riscv64

# hadolint ignore=DL3006
FROM build-${TARGETARCH} as build
RUN mkdir -p /packages

FROM scratch
COPY --from=build /packages /packages
