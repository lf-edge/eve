# This file must be kept as much in sync with pkg/kernel/Dockerfile as possible
# use the same set of packages for simplicity
ARG BUILD_PKGS_BASE="argp-standalone automake bash bc binutils-dev bison build-base \
                     diffutils flex git gmp-dev gnupg installkernel kmod elfutils-dev    \
                     linux-headers libunwind-dev mpc1-dev mpfr-dev ncurses-dev findutils \
                     openssl-dev patch rsync sed squashfs-tools tar xz xz-dev zlib-dev openssl \
                     attr-dev autoconf file coreutils libtirpc-dev libtool util-linux-dev python3"

# we use the same image in several places
ARG EVE_ALPINE_IMAGE=lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb

# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} as kernel-build-base-native
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# use build platform as a base image for cross-compilation
# hadolint ignore=DL3006,DL3029
FROM --platform=${BUILDPLATFORM} ${EVE_ALPINE_IMAGE} as kernel-build-base-cross
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh

# hadolint ignore=DL3029
FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:2a1d062fce410865e7024a83de327a68e52db26c AS cross-compilers

# will use several packages from target arch and copy them to sysroot
# hadolint ignore=DL3006
FROM ${EVE_ALPINE_IMAGE} AS cross-compile-libs
ENV PKGS musl-dev libgcc
RUN eve-alpine-deploy.sh

# adjust EVE_TARGET_ARCH for cross-compiler
FROM kernel-build-base-cross AS kernel-cross-target-arm64
ENV EVE_TARGET_ARCH=aarch64
FROM kernel-build-base-cross AS kernel-cross-target-riscv64
ENV EVE_TARGET_ARCH=riscv64

# install cross-compile packages and libs for target
# hadolint ignore=DL3006
FROM kernel-cross-target-${TARGETARCH} AS kernel-cross-build-target
ENV CROSS_COMPILE_ENV="${EVE_TARGET_ARCH}"-alpine-linux-musl-
COPY --from=cross-compilers /packages /packages
# hadolint ignore=DL3018
RUN apk add --no-cache --allow-untrusted -X /packages build-base-"${EVE_TARGET_ARCH}"
COPY --from=cross-compile-libs /out/ /usr/"${EVE_TARGET_ARCH}"-alpine-linux-musl/

# support cross compile from amd64 and arm64 for now
FROM kernel-cross-build-target AS kernel-target-arm64-build-amd64
FROM kernel-cross-build-target AS kernel-target-riscv64-build-amd64
FROM kernel-cross-build-target AS kernel-target-amd64-build-arm64
FROM kernel-cross-build-target AS kernel-target-riscv64-build-arm64

# use kernel-build-base-native image as a base for the rest of target and build archs
FROM kernel-build-base-native AS kernel-target-amd64-build-amd64
FROM kernel-build-base-native AS kernel-target-amd64-build-riscv64
FROM kernel-build-base-native AS kernel-target-arm64-build-arm64
FROM kernel-build-base-native AS kernel-target-arm64-build-riscv64
FROM kernel-build-base-native AS kernel-target-riscv64-build-riscv64

# set versions for arm64
# hadolint ignore=DL3006
FROM kernel-target-${TARGETARCH}-build-${BUILDARCH} AS kernel-target-arm64
ARG KERNEL_VERSION_arm64=5.15.46
# this has to be specified separately because of dockerfile limitations
ARG KERNEL_MAJOR=5
ENV KERNEL_VERSION=${KERNEL_VERSION_arm64}
ENV KERNEL_MAJOR=${KERNEL_MAJOR}
ENV KERNEL_ARCH=arm64
ENV KERNEL_DEFCONFIG=defconfig

# set versions for amd64
# hadolint ignore=DL3006
FROM kernel-target-${TARGETARCH}-build-${BUILDARCH} AS kernel-target-amd64
ARG KERNEL_VERSION_amd64=5.15.46
# this has to be specified separately because of dockerfile limitations
ARG KERNEL_MAJOR=5
ENV KERNEL_VERSION=${KERNEL_VERSION_amd64}
ENV KERNEL_MAJOR=${KERNEL_MAJOR}
ENV KERNEL_ARCH=x86
ENV KERNEL_DEFCONFIG=x86_64_defconfig

# set versions for riscv64
# hadolint ignore=DL3006
FROM kernel-target-${TARGETARCH}-build-${BUILDARCH} AS kernel-target-riscv64
ARG KERNEL_VERSION_riscv64=5.15.46
# this has to be specified separately because of dockerfile limitations
ARG KERNEL_MAJOR=5
ENV KERNEL_VERSION=${KERNEL_VERSION_riscv64}
ENV KERNEL_MAJOR=${KERNEL_MAJOR}
ENV KERNEL_ARCH=riscv
ENV KERNEL_DEFCONFIG=defconfig

# build for all arches
# hadolint ignore=DL3006
FROM kernel-target-${TARGETARCH} AS kernel-build

COPY /kernel-config/* /
COPY /patches-5.15.x /patches-5.15.x
COPY /patches-zfs-2.1.2 /patches-zfs-2.1.2

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
RUN set -e ; KERNEL_SERIES="${KERNEL_VERSION%.*}".x; \
    [ ! -d /patches-"${KERNEL_SERIES}" ] || for patch in /patches-"${KERNEL_SERIES}"/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done

# Copy default kconfig and prepare kbuild
# hadolint ignore=SC2086
RUN KERNEL_DEF_CONF="/linux/arch/${KERNEL_ARCH}/configs/${KERNEL_DEFCONFIG}"; \
    KERNEL_SERIES="${KERNEL_VERSION%.*}".x; \
    cp /kernel_config-"${KERNEL_SERIES}"-"${EVE_TARGET_ARCH}" "${KERNEL_DEF_CONF}"; \
    if [ -n "${EXTRA}" ]; then \
        sed -i "s/CONFIG_LOCALVERSION=\"-linuxkit\"/CONFIG_LOCALVERSION=\"-linuxkit${EXTRA}\"/" "${KERNEL_DEF_CONF}"; \
        if [ "${EXTRA}" = "-dbg" ]; then \
            sed -i 's/CONFIG_PANIC_ON_OOPS=y/# CONFIG_PANIC_ON_OOPS is not set/' "${KERNEL_DEF_CONF}"; \
        fi && \
        cat /kernel_config"${EXTRA}" >> "${KERNEL_DEF_CONF}"; \
    fi && \
    sed -i "s/CONFIG_CC_VERSION_TEXT=\"gcc/CONFIG_CC_VERSION_TEXT=\"${CROSS_COMPILE_ENV}gcc/" "${KERNEL_DEF_CONF}" && \
    cp "${KERNEL_DEF_CONF}" .config && \
    cp "${KERNEL_DEF_CONF}" .config.new && \
    make CROSS_COMPILE="${CROSS_COMPILE_ENV}" ARCH="${KERNEL_ARCH}" prepare

# Verify kconfig after `make prepare` call
WORKDIR /linux
RUN make CROSS_COMPILE="${CROSS_COMPILE_ENV}" ARCH="${KERNEL_ARCH}" "${KERNEL_DEFCONFIG}"
RUN make CROSS_COMPILE="${CROSS_COMPILE_ENV}" ARCH="${KERNEL_ARCH}" oldconfig
# diffconfig returns 0 in all cases, grep to throw error in a case config has changed between build stages.
RUN ! scripts/diffconfig .config .config.new | grep .

# To have a reproducible kernel build
ARG KBUILD_BUILD_TIMESTAMP
ARG KBUILD_BUILD_USER
ARG KBUILD_BUILD_HOST
ARG KCONFIG_NOTIMESTAMP
ARG SOURCE_DATE_EPOCH
ENV KBUILD_BUILD_TIMESTAMP=${KBUILD_BUILD_TIMESTAMP}
ENV KBUILD_BUILD_USER=${KBUILD_BUILD_USER}
ENV KBUILD_BUILD_HOST=${KBUILD_BUILD_HOST}
ENV KCONFIG_NOTIMESTAMP=${KCONFIG_NOTIMESTAMP}
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
RUN sed -i Makefile -e 's/--build-id=sha1/--build-id=none/g'

# Make kernel
RUN make -j "$(getconf _NPROCESSORS_ONLN)" CROSS_COMPILE="${CROSS_COMPILE_ENV}" ARCH="${KERNEL_ARCH}" KCFLAGS="-fno-pie" && \
    case ${EVE_TARGET_ARCH} in \
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
RUN make -j "$(getconf _NPROCESSORS_ONLN)" CROSS_COMPILE="${CROSS_COMPILE_ENV}" ARCH="${KERNEL_ARCH}" INSTALL_MOD_PATH=/tmp/kernel-modules modules_install


# Out-of-tree, open source modules
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
    CROSS_COMPILE="${CROSS_COMPILE_ENV}" ARCH="${KERNEL_ARCH}" ./configure \
        --with-linux=/linux \
        --host="${EVE_TARGET_ARCH}"-linux-musl --build="${EVE_BUILD_ARCH}"-linux-musl && \
    ./scripts/make_gitrev.sh && \
    make -C module -j "$(getconf _NPROCESSORS_ONLN)" CROSS_COMPILE="${CROSS_COMPILE_ENV}" ARCH="${KERNEL_ARCH}" && \
    make -C module INSTALL_MOD_PATH=/tmp/kernel-modules install


# Out-of-tree, creepy modules
WORKDIR /tmp/rtl8821CU
ADD https://github.com/brektrou/rtl8821CU/tarball/8c2226a7 /tmp/rtl8821CU.tgz
RUN tar -zxvf /tmp/rtl8821CU.tgz --strip-components=1 && \
    rm /tmp/rtl8821CU.tgz

WORKDIR /linux
RUN if [ "${EVE_TARGET_ARCH}" != riscv64 ]; then \
        make -j "$(getconf _NPROCESSORS_ONLN)" -C /tmp/rtl8821CU KSRC=/linux CROSS_COMPILE="${CROSS_COMPILE_ENV}" ARCH="${KERNEL_ARCH}" modules && \
        install -D -p -m 644 /tmp/rtl8821CU/8821cu.ko $(echo /tmp/kernel-modules/lib/modules/*)/kernel/drivers/net/wireless/realtek/rtl8821cu/8821cu.ko ;\
    fi

WORKDIR /linux

# Strip at least some of the modules to conserve space
RUN [ "${EVE_TARGET_ARCH}" = x86_64 ] || "${CROSS_COMPILE_ENV}strip" --strip-debug `find /tmp/kernel-modules/lib/modules -name \*.ko`

# Device Tree Blobs
RUN [ "${EVE_TARGET_ARCH}" = x86_64 ] || make INSTALL_DTBS_PATH=/tmp/kernel-modules/boot/dtb CROSS_COMPILE="${CROSS_COMPILE_ENV}" ARCH="${KERNEL_ARCH}" dtbs_install

# copy build time gnerated module-signing public key, used for diffing builds
RUN DVER=$(basename "$(find /tmp/kernel-modules/lib/modules/ -mindepth 1 -maxdepth 1)"); \
    if [ -f "/linux/certs/signing_key.x509" ]; then \
        cp /linux/certs/signing_key.x509 "/tmp/kernel-modules/lib/modules/$DVER"; \
    fi

# Package all the modules up
# hadolint ignore=SC2086
RUN ( DVER=$(basename $(find /tmp/kernel-modules/lib/modules/ -mindepth 1 -maxdepth 1)) && \
      cd /tmp/kernel-modules/lib/modules/$DVER && \
      rm build source && \
      ln -s /usr/src/linux-headers-$DVER build ) && \
    ( cd /tmp/kernel-modules && tar cf /out/kernel.tar . )

# Headers (userspace API)
RUN mkdir -p /tmp/kernel-headers/usr && \
    make INSTALL_HDR_PATH=/tmp/kernel-headers/usr CROSS_COMPILE="${CROSS_COMPILE_ENV}" ARCH="${KERNEL_ARCH}" headers_install && \
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
