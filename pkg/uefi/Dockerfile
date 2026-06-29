# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
# Instructions for this package are taken from:
#   https://wiki.ubuntu.com/UEFI/EDK2
#   https://wiki.linaro.org/LEG/UEFIforQEMU
#
# On ARM here's what works for other boars:
#   git clone https://github.com/tianocore/edk2
#   git clone https://github.com/tianocore/edk2-platforms
#   git clone https://github.com/tianocore/edk2-non-osi
#   git clone https://git.linaro.org/uefi/uefi-tools.git
#   ./uefi-tools/edk2-build.sh -b DEBUG -b RELEASE all
#
FROM lfedge/eve-alpine:fb0a297e3939c06cd3e4a4b9293b4cf76847d9c0 AS build
ENV BUILD_PKGS make gcc g++ python3 libuuid nasm util-linux-dev bash git util-linux patch
ENV BUILD_PKGS_amd64 iasl
ENV BUILD_PKGS_arm64 iasl
RUN eve-alpine-deploy.sh

COPY edk2-patches /edk2-patches
COPY vfioigd-patches /vfioigd-patches
COPY vfioigd-debug-patches /vfioigd-debug-patches

FROM build AS build-arm64-versions

ENV EDK_VERSION edk2-stable202208
ENV EDK_COMMIT ba0e0e4c6a174b71b18ccd6e47319cc45878893c

# FIXME: we should be building Raspberry Pi 4 UEFI implementations
COPY rpi /rpi

FROM build AS build-amd64-versions

ENV EDK_VERSION edk2-stable202508.01
ENV EDK_COMMIT 3d244c3b364bd4e21261380662186d064659161c

FROM build-${TARGETARCH}-versions AS build-edk2

WORKDIR /edk2
ADD --keep-git-dir=true https://github.com/tianocore/edk2.git#${EDK_COMMIT} /edk2

RUN set -e ; [ ! -d /edk2 ] ||  [ ! -d /edk2-patches/${EDK_VERSION} ] || \
        for patch in /edk2-patches/${EDK_VERSION}/*.patch; do \
            echo "Applying $patch"; \
            git apply -p1 < "$patch" || exit 1 ; \
        done

FROM build-edk2 AS build-amd64

# VfioIgdPkg: open-source EFI option-ROM package for Intel iGPU
# passthrough.  Builds IgdAssignmentDxe, which sets the guest's emulated
# ASLS / BDSM PCI config registers correctly so the guest's iGPU
# driver can find OpRegion and stolen memory.  Handles the Gen11+
# 64-bit BDSM at offset 0xC0 — the classic upstream IgdAssignmentDxe
# does not.
ENV VFIOIGD_COMMIT 348860da70ca3a9ed6c1d95c30a97c757f54336b
ADD --keep-git-dir=true https://github.com/tomitamoeko/VfioIgdPkg.git#${VFIOIGD_COMMIT} /edk2/VfioIgdPkg

# VfioIgdPkg patches:
#   /vfioigd-patches/        — always applied (toolchain regressions etc.)
#   /vfioigd-debug-patches/  — applied by build.sh only when UEFI_TARGET=DEBUG
#
# The always-on set is applied here at image-build time so the unpatched
# upstream tree never ships in the runtime layer.  The debug-only set is
# left to build.sh, which conditionalises both the patch apply and the
# matching VfioIgdPkg.dsc PCD/HobLib mods on UEFI_TARGET=DEBUG.
RUN set -e ; [ ! -d /edk2/VfioIgdPkg ] || [ ! -d /vfioigd-patches ] || \
        for patch in /vfioigd-patches/*.patch; do \
            echo "Applying $patch"; \
            git -C /edk2/VfioIgdPkg apply -p1 < "$patch" || exit 1 ; \
        done

FROM build-edk2 AS build-arm64

FROM build AS build-riscv64

ENV SBI_COMMIT cbaa9b0333517b3c25bea8d1c71ac8005ff1f727
ADD https://github.com/riscv/opensbi/tarball/${SBI_COMMIT} /opensbi.tgz

WORKDIR /opensbi
RUN tar -zxvf /opensbi.tgz  --strip-components=1 && \
    rm /opensbi.tgz

FROM build-${TARGETARCH} AS build-interim

WORKDIR /edk2
COPY build.sh /edk2/
RUN ./build.sh

# create an out dir for all the artifacts
RUN rm -rf /out && mkdir /out && cp /edk2/OVMF*.fd /out && \
    if [ -f /edk2/igd.rom ]; then cp /edk2/igd.rom /out/; fi

# some architecture specific cases. There probably is a cleaner dockerfile-native way to do this.
RUN case $(uname -m) in \
    aarch64) \
        cp -r /rpi /out/ \
        ;; \
    esac

# Register source-built UEFI components in the APK DB, mandatory for them to be included in the SBOM.
RUN case "$(uname -m)" in \
        x86_64)  register-sbom-pkg.sh -n edk2 -v "${EDK_VERSION}" -l BSD-2-Clause-Patent -u https://github.com/tianocore/edk2 -o /sbom-out && \
                 register-sbom-pkg.sh -n VfioIgdPkg -v "${VFIOIGD_COMMIT:0:8}" -l BSD-2-Clause-Patent -u https://github.com/tomitamoeko/VfioIgdPkg -o /sbom-out ;; \
        aarch64) register-sbom-pkg.sh -n edk2 -v "${EDK_VERSION}" -l BSD-2-Clause-Patent -u https://github.com/tianocore/edk2 -o /sbom-out ;; \
        riscv64) register-sbom-pkg.sh -n opensbi -v "${SBI_COMMIT:0:8}" -l BSD-2-Clause -u https://github.com/riscv/opensbi -o /sbom-out ;; \
    esac


FROM scratch
COPY --from=build-interim /sbom-out/lib/apk/db/installed /lib/apk/db/installed
COPY --from=build-interim /out/* /
