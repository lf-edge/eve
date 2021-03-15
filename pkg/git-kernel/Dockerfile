# This file must be kept as much in sync with pkg/kernel/Dockerfile as posisble
FROM alpine:3.12 as kernel-build

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
    gcc \
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

ENV KERNEL_REPO "https://github.com/itmo-eve/linux-kernel.git"
ENV KERNEL_BRANCH "st/vhost-nvme-5.10"

# We copy the entire directory. This copies some unneeded files, but
# allows us to check for the existence /patches-${KERNEL_SERIES} to
# build kernels without patches.
COPY / /

# Download and verify kernel
RUN git clone ${KERNEL_REPO} --depth 1 -b ${KERNEL_BRANCH} /linux

# Apply local patches
WORKDIR /linux

RUN case $(uname -m) in \
    x86_64) \
        KERNEL_DEF_CONF=/linux/arch/x86/configs/x86_64_defconfig; \
        ;; \
    aarch64) \
        KERNEL_DEF_CONF=/linux/arch/arm64/configs/defconfig; \
        ;; \
    esac  && \
    cp /kernel-config-git-$(uname -m) ${KERNEL_DEF_CONF}; \
    sed -i "s/CONFIG_LOCALVERSION=\"-linuxkit\"/CONFIG_LOCALVERSION=\"-linuxkit${EXTRA}\"/" ${KERNEL_DEF_CONF}; \
    make defconfig;

RUN mkdir -p /out

# Kernel
RUN make -j "$(getconf _NPROCESSORS_ONLN)" && \
    case $(uname -m) in \
    x86_64) \
        cp arch/x86_64/boot/bzImage /out/kernel; \
        ;; \
    aarch64) \
        cp arch/arm64/boot/Image.gz /out/kernel; \
        ;; \
    esac && \
    cp System.map /out

# Modules
RUN make INSTALL_MOD_PATH=/tmp/kernel-modules modules_install

#  * ZFS on Linux
RUN apk add --no-cache \
    attr-dev \
    autoconf \
    file \
    coreutils \
    libtirpc-dev \
    libtool \
    util-linux-dev
ENV ZFS_VERSION=2.0.0
ENV ZFS_COMMIT=zfs-${ZFS_VERSION}
ENV ZFS_REPO=https://github.com/zfsonlinux/zfs.git

#WORKDIR /tmp/zfs
#RUN git clone --depth 1 -b ${ZFS_COMMIT} ${ZFS_REPO} .
#RUN sed -ie '/Linux-Maximum:/s/^.*$/Linux-Maximum: 5.10/' META
#RUN ./autogen.sh && \
#    ./configure --with-linux=/linux && \
#    ./scripts/make_gitrev.sh && \
#    make -C module -j "$(getconf _NPROCESSORS_ONLN)" && \
#    make -C module INSTALL_MOD_PATH=/tmp/kernel-modules install # cd /lib/modules && depmod -ae *

# Strip at least some of the modules to conserve space
RUN if [ "$(uname -m)" = aarch64 ];then strip --strip-debug `find /tmp/kernel-modules/lib/modules -name \*.ko` ;fi

# Device Tree Blobs
RUN if [ "$(uname -m)" = aarch64 ];then make INSTALL_DTBS_PATH=/tmp/kernel-modules/boot/dtb dtbs_install ;fi

WORKDIR /linux
# Package all the modules up
RUN ( DVER=$(basename $(find /tmp/kernel-modules/lib/modules/ -mindepth 1 -maxdepth 1)) && \
      cd /tmp/kernel-modules/lib/modules/$DVER && \
      rm build source && \
      ln -s /usr/src/linux-headers-$DVER build ) && \
    ( cd /tmp/kernel-modules && tar cf /out/kernel.tar . )

# Headers (userspace API)
RUN mkdir -p /tmp/kernel-headers/usr && \
    make INSTALL_HDR_PATH=/tmp/kernel-headers/usr headers_install && \
    ( cd /tmp/kernel-headers && tar cf /out/kernel-headers.tar usr )

# Headers (kernel development)
RUN DVER=$(basename $(find /tmp/kernel-modules/lib/modules/ -mindepth 1 -maxdepth 1)) && \
    dir=/tmp/usr/src/linux-headers-$DVER && \
    mkdir -p $dir && \
    cp /linux/.config $dir && \
    cp /linux/Module.symvers $dir && \
    find . -path './include/*' -prune -o \
           -path './arch/*/include' -prune -o \
           -path './scripts/*' -prune -o \
           -type f \( -name 'Makefile*' -o -name 'Kconfig*' -o -name 'Kbuild*' -o \
                      -name '*.lds' -o -name '*.pl' -o -name '*.sh' \) | \
         tar cf - -T - | (cd $dir; tar xf -) && \
    ( cd /tmp && tar cf /out/kernel-dev.tar usr/src )

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=kernel-build /out/* /
