FROM lfedge/eve-alpine:7428d0de172b8086289945d78234daf2eac03818 AS build
ENV BUILD_PKGS="gcc make file patch libc-dev linux-headers openssl-dev g++ tar coreutils"
# util-linux-static on riscv64 is broken; we build libuuid from source instead (see below).
ENV BUILD_PKGS_amd64="util-linux-static util-linux-dev"
ENV BUILD_PKGS_arm64="util-linux-static util-linux-dev"
ENV BUILD_PKGS_riscv64="sqlite-dev"
RUN eve-alpine-deploy.sh

ENV POPT_VERSION=1.16
ENV GPTFDISK_VERSION=1.0.3
ENV VBOOT_REPO=https://github.com/coreboot/vboot.git
ENV VBOOT_COMMIT=ed6cb4054134efdd67215d9504f501cd36030d6a

ARG TARGETARCH
ADD https://www.kernel.org/pub/linux/utils/util-linux/v2.41/util-linux-2.41.tar.gz /tmp/ul.tar.gz
RUN if [ "${TARGETARCH}" = "riscv64" ]; then \
      tar -xzf /tmp/ul.tar.gz -C /tmp/ && \
      cd /tmp/util-linux-2.41 && \
      ./configure --enable-static --disable-shared && \
      make libuuid.la && \
      cp .libs/libuuid.a /usr/lib/libuuid.a && \
      mkdir -p /usr/include/uuid && \
      cp libuuid/src/uuid.h /usr/include/uuid/uuid.h; \
    fi

#
# Step 1: Install SGDISK
#

WORKDIR /
RUN mkdir /popt
COPY popt-${POPT_VERSION}.tar.gz /popt

WORKDIR /popt
RUN tar xvzf popt-${POPT_VERSION}.tar.gz
WORKDIR /popt/popt-${POPT_VERSION}
COPY patches/popt* /popt
RUN for patch in /popt/*patch ; do patch -p1 < $patch ; done
RUN ./configure && make -j "$(getconf _NPROCESSORS_ONLN)" && make install

WORKDIR /
RUN mkdir -p /sgdisk/patches
COPY gptfdisk-${GPTFDISK_VERSION}.tar.gz /sgdisk
COPY patches/* /sgdisk/patches/

WORKDIR /sgdisk
RUN tar xvzf gptfdisk-${GPTFDISK_VERSION}.tar.gz

WORKDIR /sgdisk/gptfdisk-${GPTFDISK_VERSION}
RUN set -e && for patch in ../patches/sgdisk-*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done
RUN make -j "$(getconf _NPROCESSORS_ONLN)" CXXFLAGS="-Dfstat64=fstat -Dstat64=stat -Dlseek64=lseek" LDFLAGS=-static sgdisk
RUN strip sgdisk
RUN cp sgdisk /out/sgdisk


#
# Step 2: Fetch and compile CGPT
#

WORKDIR /
ADD --keep-git-dir=true ${VBOOT_REPO}#${VBOOT_COMMIT} /vboot

WORKDIR /vboot
RUN [ -d host/arch/riscv64 ] || cp -r host/arch/arm host/arch/riscv64
RUN make cgpt -j "$(getconf _NPROCESSORS_ONLN)" USE_FLASHROM=0 LDFLAGS=-static
RUN cp build/cgpt/cgpt /out/cgpt

FROM scratch
COPY --from=build /out/sgdisk /usr/bin/sgdisk
COPY --from=build /out/cgpt /usr/bin/cgpt
COPY files/zboot /usr/bin/zboot
