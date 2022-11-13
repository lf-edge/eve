# This file must be kept as much in sync with pkg/kernel/Dockerfile as possible
FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as kernel-build-base

ENV BUILD_PKGS \
    argp-standalone automake bash bc binutils-dev bison build-base \
    diffutils flex git gmp-dev gnupg installkernel kmod elfutils-dev    \
    linux-headers libunwind-dev mpc1-dev mpfr-dev ncurses-dev findutils \
    openssl-dev patch rsync sed squashfs-tools tar xz xz-dev zlib-dev openssl \
    attr-dev autoconf file coreutils libtirpc-dev libtool util-linux-dev
RUN eve-alpine-deploy.sh

# set versions for arm64
FROM kernel-build-base AS kernel-build-arm64
ARG KERNEL_VERSION_arm64=5.15.46
# this has to be specified separately because of dockerfile limitations
ARG KERNEL_MAJOR=5
ENV KERNEL_VERSION=${KERNEL_VERSION_arm64}
ENV KERNEL_MAJOR=${KERNEL_MAJOR}

# set versions for amd64
FROM kernel-build-base AS kernel-build-amd64
ARG KERNEL_VERSION_amd64=5.15.46
# this has to be specified separately because of dockerfile limitations
ARG KERNEL_MAJOR=5
ENV KERNEL_VERSION=${KERNEL_VERSION_amd64}
ENV KERNEL_MAJOR=${KERNEL_MAJOR}

# set versions for riscv64
FROM kernel-build-base AS kernel-build-riscv64
ARG KERNEL_VERSION_riscv64=5.15.46
# this has to be specified separately because of dockerfile limitations
ARG KERNEL_MAJOR=5
ENV KERNEL_VERSION=${KERNEL_VERSION_riscv64}
ENV KERNEL_MAJOR=${KERNEL_MAJOR}

# build for all arches
# hadolint ignore=DL3006
FROM kernel-build-${TARGETARCH} AS kernel-build

# We copy the entire directory. This copies some unneeded files, but
# allows us to check for the existence /patches-${KERNEL_SERIES} to
# build kernels without patches.
COPY / /

ARG KERNEL_SOURCE=https://www.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz
ARG KERNEL_SHA256_SUMS=https://www.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/sha256sums.asc
ARG KERNEL_PGP2_SIGN=https://www.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.sign

# Download and verify kernel
# PGP keys: 589DA6B1 (greg@kroah.com) & 6092693E (autosigner@kernel.org) & 00411886 (torvalds@linux-foundation.org)
# hadolint ignore=DL3020
ADD ${KERNEL_SHA256_SUMS} sha256sums.asc
# hadolint ignore=DL3020
ADD ${KERNEL_PGP2_SIGN} linux-${KERNEL_VERSION}.tar.sign
# hadolint ignore=DL3020
ADD ${KERNEL_SOURCE} /tmp/linux-${KERNEL_VERSION}.tar.xz


# hadolint ignore=DL4006
RUN gpg2 -q --import keys.asc && \
    gpg2 --verify sha256sums.asc && \
    KERNEL_SHA256=$(grep linux-${KERNEL_VERSION}.tar.xz sha256sums.asc | cut -d ' ' -f 1) && \
    [ -f linux-${KERNEL_VERSION}.tar.xz ] || mv /tmp/linux-${KERNEL_VERSION}.tar.xz . && \
    echo "${KERNEL_SHA256}  linux-${KERNEL_VERSION}.tar.xz" | sha256sum -c - && \
    xz -d linux-${KERNEL_VERSION}.tar.xz && \
    gpg2 --verify linux-${KERNEL_VERSION}.tar.sign linux-${KERNEL_VERSION}.tar && \
    cat linux-${KERNEL_VERSION}.tar | tar --absolute-names -x && mv /linux-${KERNEL_VERSION} /linux && \
    rm -rf /out && mkdir /out && echo "KERNEL_SOURCE=${KERNEL_SOURCE}" > /out/kernel-source-info

# Apply local patches
WORKDIR /linux
RUN set -e ; KERNEL_SERIES=${KERNEL_VERSION%.*}.x; \
    [ ! -d /patches-"${KERNEL_SERIES}" ] || for patch in /patches-"${KERNEL_SERIES}"/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done

# Copy default kconfig and prepare kbuild
RUN case $(uname -m) in \
    x86_64) \
        KERNEL_DEF_CONF=/linux/arch/x86/configs/x86_64_defconfig; \
        ;; \
    aarch64) \
        KERNEL_DEF_CONF=/linux/arch/arm64/configs/defconfig; \
        ;; \
    riscv64) \
        KERNEL_DEF_CONF=/linux/arch/riscv/configs/defconfig; \
        ;; \
    esac  && \
    KERNEL_SERIES=${KERNEL_VERSION%.*}.x; \
    cp /kernel_config-${KERNEL_SERIES}-$(uname -m) ${KERNEL_DEF_CONF}; \
    if [ -n "${EXTRA}" ]; then \
        sed -i "s/CONFIG_LOCALVERSION=\"-linuxkit\"/CONFIG_LOCALVERSION=\"-linuxkit${EXTRA}\"/" ${KERNEL_DEF_CONF}; \
        if [ "${EXTRA}" = "-dbg" ]; then \
            sed -i 's/CONFIG_PANIC_ON_OOPS=y/# CONFIG_PANIC_ON_OOPS is not set/' ${KERNEL_DEF_CONF}; \
        fi && \
        cat /kernel_config${EXTRA} >> ${KERNEL_DEF_CONF}; \
    fi && \
    cp ${KERNEL_DEF_CONF} .config && \
    cp ${KERNEL_DEF_CONF} .config.new && \
    make prepare

# Prepare built-in ZFS
#  * ZFS on Linux
ENV ZFS_VERSION=2.1.2
ENV ZFS_COMMIT=zfs-${ZFS_VERSION}
ENV ZFS_REPO=https://github.com/openzfs/zfs
ENV ZFS_PATCH_DIR=/patches-zfs-"${ZFS_VERSION}"

WORKDIR /tmp/zfs

# hadolint ignore=DL3020
ADD ${ZFS_REPO}/tarball/${ZFS_COMMIT} /zfs.tgz
RUN tar -zxvf /zfs.tgz --strip-components=1 && \
    rm /zfs.tgz
RUN set -e; \
    if [ ! -d "${ZFS_PATCH_DIR}" ]; then \
        echo "No such dir ${ZFS_PATCH_DIR}"; \
    else \
        for patch in "${ZFS_PATCH_DIR}"/*.patch; do \
            echo "Applying $patch"; \
            patch -p1 < "$patch"; \
        done \
    fi
RUN ./autogen.sh && \
    ./configure \
        --with-linux=/linux \
        --with-linux-obj=/linux \
        --with-config=kernel  \
        --enable-linux-builtin && \
    ./scripts/make_gitrev.sh && \
    ./copy-builtin /linux

# Verify kconfig after ZFS is prepared as built-in
WORKDIR /linux
RUN make defconfig && \
    make oldconfig && \
    diff -cw .config .config.new

# Make kernel
RUN make -j "$(getconf _NPROCESSORS_ONLN)" KCFLAGS="-fno-pie" && \
    case $(uname -m) in \
    x86_64) \
        cp arch/x86_64/boot/bzImage /out/kernel; \
        ;; \
    aarch64) \
        cp arch/arm64/boot/Image.gz /out/kernel; \
        ;; \
    riscv64) \
        cp arch/riscv/boot/Image.gz /out/kernel; \
        ;; \
    esac && \
    cp System.map /out && \
    DVER=$(make kernelrelease) && \
    DIR=linux-debug-$DVER && \
    rsync -rv --include '*/' --include '*.dwo' --exclude '*' --prune-empty-dirs . /tmp/$DIR && \
    cp vmlinux /tmp/$DIR && \
    tar -cf /out/kernel-debug.tar -C /tmp $DIR

# Modules
RUN make -j "$(getconf _NPROCESSORS_ONLN)" INSTALL_MOD_PATH=/tmp/kernel-modules modules_install

# Out-of-tree, creepy modules
WORKDIR /tmp/rtl8821CU
ADD https://github.com/brektrou/rtl8821CU/tarball/8c2226a7 /tmp/rtl8821CU.tgz
RUN tar -zxvf /tmp/rtl8821CU.tgz --strip-components=1 && \
    rm /tmp/rtl8821CU.tgz

WORKDIR /linux
RUN if [ "$(uname -m)" != riscv64 ]; then \
        make -j "$(getconf _NPROCESSORS_ONLN)" -C /tmp/rtl8821CU KSRC=/linux modules && \
        install -D -p -m 644 /tmp/rtl8821CU/8821cu.ko $(echo /tmp/kernel-modules/lib/modules/*)/kernel/drivers/net/wireless/realtek/rtl8821cu/8821cu.ko ;\
    fi

WORKDIR /linux

# Strip at least some of the modules to conserve space
RUN [ "$(uname -m)" = x86_64 ] || strip --strip-debug `find /tmp/kernel-modules/lib/modules -name \*.ko`

# Device Tree Blobs
RUN [ "$(uname -m)" = x86_64 ] || make INSTALL_DTBS_PATH=/tmp/kernel-modules/boot/dtb dtbs_install

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
