# This file must be kept as much in sync with pkg/new-kernel/Dockerfile as posisble
FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 AS kernel-build

ENV BUILD_PKGS \
    argp-standalone automake bash bc binutils-dev bison build-base curl \
    diffutils flex git gmp-dev gnupg installkernel kmod elfutils-dev    \
    linux-headers libunwind-dev mpc1-dev mpfr-dev ncurses-dev findutils \
    openssl-dev patch rsync sed squashfs-tools tar xz xz-dev zlib-dev openssl \
    attr-dev autoconf file coreutils libtirpc-dev libtool util-linux-dev
RUN eve-alpine-deploy.sh

ARG KERNEL_VERSION_aarch64=5.10.121
ARG KERNEL_VERSION_x86_64=5.10.121
ARG KERNEL_SOURCE
ARG KERNEL_SHA256_SUMS
ARG KERNEL_PGP2_SIGN

# The only variable that is used everywhere is KERNEL_SERIES, so we stick it into env
SHELL ["/bin/sh", "-c", "export KERNEL_SERIES=$(eval echo \\$KERNEL_VERSION_$(uname -m) | sed -e 's#.[^.]*$#.x#') ; /bin/sh -c \"$1\"", "-" ]

# We copy the entire directory. This copies some unneeded files, but
# allows us to check for the existence /patches-${KERNEL_SERIES} to
# build kernels without patches.
COPY / /

# Download and verify kernel
# PGP keys: 589DA6B1 (greg@kroah.com) & 6092693E (autosigner@kernel.org) & 00411886 (torvalds@linux-foundation.org)
RUN KERNEL_VERSION="$(eval echo \$KERNEL_VERSION_"$(uname -m)")" && KERNEL_MAJOR="$(echo "$KERNEL_VERSION" | cut -f1 -d.)" && \
    KERNEL_SOURCE=${KERNEL_SOURCE:-https://www.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz} && \
    KERNEL_SHA256_SUMS=${KERNEL_SHA256_SUMS:-https://www.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/sha256sums.asc} && \
    KERNEL_PGP2_SIGN=${KERNEL_PGP2_SIGN:-https://www.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.sign} && \
    curl -fsSLO ${KERNEL_SHA256_SUMS} && \
    gpg2 -q --import keys.asc && \
    gpg2 --verify sha256sums.asc && \
    KERNEL_SHA256=$(grep linux-${KERNEL_VERSION}.tar.xz sha256sums.asc | cut -d ' ' -f 1) && \
    [ -f linux-${KERNEL_VERSION}.tar.xz ] || curl -fsSLO ${KERNEL_SOURCE} && \
    echo "${KERNEL_SHA256}  linux-${KERNEL_VERSION}.tar.xz" | sha256sum -c - && \
    xz -d linux-${KERNEL_VERSION}.tar.xz && \
    curl -fsSLO ${KERNEL_PGP2_SIGN} && \
    gpg2 --verify linux-${KERNEL_VERSION}.tar.sign linux-${KERNEL_VERSION}.tar && \
    cat linux-${KERNEL_VERSION}.tar | tar --absolute-names -x && mv /linux-${KERNEL_VERSION} /linux && \
    rm -rf /out && mkdir /out && echo "KERNEL_SOURCE=${KERNEL_SOURCE}" > /out/kernel-source-info

# Apply local patches
WORKDIR /linux
RUN set -e ; [ ! -d /patches-"${KERNEL_SERIES}" ] || for patch in /patches-"${KERNEL_SERIES}"/*.patch; do \
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
    esac  && \
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
ENV ZFS_REPO=https://github.com/openzfs/zfs.git
ENV ZFS_PATCH_DIR=/patches-zfs-"${ZFS_VERSION}"

WORKDIR /tmp/zfs

RUN git clone --depth 1 -b ${ZFS_COMMIT} ${ZFS_REPO} .
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
    esac && \
    cp System.map /out && \
    DVER=$(make kernelrelease) && \
    DIR=linux-debug-$DVER && \
    rsync -rv --include '*/' --include '*.dwo' --exclude '*' --prune-empty-dirs . /tmp/$DIR && \
    cp vmlinux /tmp/$DIR && \
    tar -cf /out/kernel-debug.tar -C /tmp $DIR

# Modules
RUN make INSTALL_MOD_PATH=/tmp/kernel-modules modules_install

# Out-of-tree, creepy modules
#  * Maxlinear USB (option #2 https://github.com/lipnitsk/xr/archive/master.zip)
WORKDIR /linux
ADD https://www.maxlinear.com/document?id=21651 /tmp/xr.zip
RUN unzip -d /tmp /tmp/xr.zip ;\
    make -C /linux INSTALL_MOD_PATH=/tmp/kernel-modules \
                   M=/tmp/xr_usb_serial_common_lnx-3.6-and-newer-pak \
         modules modules_install

RUN git clone https://github.com/brektrou/rtl8821CU.git /tmp/rtl8821CU &&\
    (cd /tmp/rtl8821CU && git checkout 8c2226a7 ) &&\
    make -C /tmp/rtl8821CU KSRC=/linux modules &&\
    install -D -p -m 644 /tmp/rtl8821CU/8821cu.ko $(echo /tmp/kernel-modules/lib/modules/*)/kernel/drivers/net/wireless/realtek/rtl8821cu/8821cu.ko

# Strip at least some of the modules to conserve space
RUN if [ "$(uname -m)" = aarch64 ];then strip --strip-debug `find /tmp/kernel-modules/lib/modules -name \*.ko` ;fi

# Device Tree Blobs
RUN if [ "$(uname -m)" = aarch64 ];then make INSTALL_DTBS_PATH=/tmp/kernel-modules/boot/dtb dtbs_install ;fi

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
