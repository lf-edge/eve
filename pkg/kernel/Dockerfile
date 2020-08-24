FROM linuxkit/alpine:3fdc49366257e53276c6f363956a4353f95d9a81 AS kernel-build

RUN apk add \
    argp-standalone \
    automake \
    bash \
    bc \
    binutils-dev \
    bison \
    build-base \
    curl \
    diffutils \
    flex \
    git \
    gmp-dev \
    gnupg \
    installkernel \
    kmod \
    elfutils-dev \
    linux-headers \
    libunwind-dev \
    mpc1-dev \
    mpfr-dev \
    ncurses-dev \
    findutils \
    openssl-dev \
    patch \
    rsync \
    sed \
    squashfs-tools \
    tar \
    xz \
    xz-dev \
    zlib-dev \
    openssl

# required for ZFS build
RUN apk add --no-cache \
    attr-dev=2.4.47-r7 \
    autoconf=2.69-r2 \
    file=5.36-r0 \
    libtirpc-dev=1.0.3-r0 \
    libtool=2.4.6-r5 \
    util-linux-dev=2.33-r0

ARG PREFIX=/ws/kernel-build
ARG CONTAINERBLD='yes'
ARG ARCHIVE=kernel-build.tar.gz

# We copy the entire directory. This copies some unneeded files, but
# allows us to check for the existence /patches-${KERNEL_SERIES} to
# build kernels without patches.
COPY / $PREFIX/
WORKDIR $PREFIX
RUN ./build-kernel.sh $PREFIX $ARCHIVE $CONTAINERBLD

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=kernel-build /tmp/$ARCHIVE /
