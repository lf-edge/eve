FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
ENV BUILD_PKGS="gcc make file patch libc6-dev linux-libc-dev libssl-dev g++ tar coreutils uuid-dev pkg-config"
RUN eve-ubuntu-deploy.sh

ENV POPT_VERSION=1.16
ENV GPTFDISK_VERSION=1.0.3
ENV VBOOT_REPO=https://github.com/coreboot/vboot.git
ENV VBOOT_COMMIT=ed6cb4054134efdd67215d9504f501cd36030d6a

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

# Register popt in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n popt -v "${POPT_VERSION}" -l MIT -u https://github.com/rpm-software-management/popt

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
RUN make -j "$(getconf _NPROCESSORS_ONLN)" LDFLAGS=-static sgdisk
RUN strip sgdisk
RUN cp sgdisk /out/sgdisk

# Register gptfdisk in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n gptfdisk -v "${GPTFDISK_VERSION}" -l GPL-2.0-only -u https://sourceforge.net/projects/gptfdisk


#
# Step 2: Fetch and compile CGPT
#

WORKDIR /
ADD --keep-git-dir=true ${VBOOT_REPO}#${VBOOT_COMMIT} /vboot

WORKDIR /vboot
RUN [ -d host/arch/riscv64 ] || cp -r host/arch/arm host/arch/riscv64
# gcc 15 adds warnings vboot does not know yet; its -Werror comes via WERROR
RUN make cgpt -j "$(getconf _NPROCESSORS_ONLN)" USE_FLASHROM=0 LDFLAGS=-static WERROR=
RUN cp build/cgpt/cgpt /out/cgpt

# Register vboot in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n vboot -v "$(printf '%.8s' "${VBOOT_COMMIT}")" -l GPL-3.0-only -u https://github.com/coreboot/vboot

FROM scratch
COPY --from=build /out/sgdisk /usr/bin/sgdisk
COPY --from=build /out/cgpt /usr/bin/cgpt
COPY --from=build /out/var/lib/dpkg/status.d /var/lib/dpkg/status.d
COPY files/zboot /usr/bin/zboot
