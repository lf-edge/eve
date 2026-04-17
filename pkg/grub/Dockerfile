# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
# Copyright (c) 2025-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:1f744180283ffb4eabcc3862531aeacf1de886b3 AS grub-build-base
ENV BUILD_PKGS="automake \
               make \
               bison \
               gettext \
               flex \
               gcc \
               git \
               libtool \
               libc-dev \
               linux-headers \
               python3 \
               autoconf \
               pkgconf \
               patch \
               gettext-dev \
               bash \
               gawk \
               coreutils"
RUN eve-alpine-deploy.sh

# list of grub modules that are portable between x86_64 and aarch64
ENV GRUB_MODULES_PORT="part_gpt fat ext2 iso9660 squash4 gzio linux acpi normal cpio crypto disk boot crc64 \
search_disk_uuid search_part_uuid search_part_label search_label xzio xfs video gfxterm serial gptprio chain probe reboot regexp smbios \
part_msdos cat echo test configfile loopback net tftp http true gcry_sha256"

FROM grub-build-base AS grub-build-amd64
ENV GRUB_MODULES="multiboot multiboot2 efi_uga efi_gop gpt measurefs efinet getenv"
ENV GRUB_MODULES_i386_pc="multiboot multiboot2 biosdisk gpt"
ENV GRUB_COMMIT=grub-2.12
ENV GRUB_PATCHES=patches-2.12
# colon separates a platform from an additional option.
# this is far from perfect, but it works for now.
ENV GRUB_PLATFORM="efi pc:--disable-efiemu"

FROM grub-build-base AS grub-build-arm64
ENV GRUB_MODULES="xen_boot efi_gop gpt measurefs efinet getenv"
ENV GRUB_COMMIT=grub-2.12
ENV GRUB_PATCHES=patches-2.12
ENV GRUB_PLATFORM=efi

FROM grub-build-base AS grub-build-riscv64
ENV GRUB_MODULES="efinet"
ENV GRUB_COMMIT=grub-2.12
ENV GRUB_PATCHES=patches-2.12
ENV GRUB_PLATFORM=efi

# hadolint ignore=DL3006
FROM grub-build-${TARGETARCH} AS grub-build

COPY patches-2.12 /patches-2.12
RUN mkdir /grub-lib

ENV GRUB_REPO=https://gitlab.freedesktop.org/gnu-grub/grub.git
ADD ${GRUB_REPO}#${GRUB_COMMIT} /grub
ENV GNULIB_REVISION=9f48fb992a3d7e96610c4ce8be969cff2d61a01b
ADD --keep-git-dir https://github.com/coreutils/gnulib.git#${GNULIB_REVISION} /gnulib

WORKDIR /grub
RUN mkdir -p /apply/patches
RUN for dir in ${GRUB_PATCHES}; do \
    cp -r /${dir}/* /apply/patches; \
    done
RUN git config --global user.name 'Project EVE'
RUN git config --global user.email 'builder@projecteve.dev'
RUN git init . && git add . && git commit -m "init"
RUN git am /apply/patches/*

RUN ./bootstrap --gnulib-srcdir=/gnulib || ./autogen.sh

# hadolint ignore=SC2046
RUN set -e; for p in ${GRUB_PLATFORM}; do \
      platform=${p%%:*}; \
      begin=$(( ${#platform} + 1 )); \
      opt=${p:${begin}}; \
      if [ -f Makefile ]; then make distclean; fi; \
      ./configure --disable-werror --libdir=/grub-lib --with-platform="${platform}" ${opt} CFLAGS='-Os -Wno-unused-value -Wno-incompatible-pointer-types'; \
      make -j $(getconf _NPROCESSORS_ONLN); \
      make install; \
    done

COPY embedded.cfg /

# hadolint ignore=SC2086
RUN case "$(uname -m)" in \
  x86_64) \
    ./grub-mkimage -O x86_64-efi -d /grub-lib/grub/x86_64-efi -o /grub-lib/BOOTX64.EFI -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES} &&\
    ./grub-mkimage -O i386-pc -d /grub-lib/grub/i386-pc -o /grub-lib/BOOT.pc -p /EFI/BOOT -c /embedded.cfg ${GRUB_MODULES_PORT} ${GRUB_MODULES_i386_pc} && \
    cp /grub-lib/grub/i386-pc/boot.img /grub-lib/BOOT.img ;;\
  aarch64) \
    ./grub-mkimage -O arm64-efi -d /grub-lib/grub/arm64-efi -o /grub-lib/BOOTAA64.EFI -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES} ;; \
  riscv64) \
    ./grub-mkimage -O riscv64-efi -d /grub-lib/grub/riscv64-efi -o /grub-lib/BOOTRISCV64.EFI -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES} ;;\
  esac

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /EFI/BOOT
COPY --from=grub-build /grub-lib/BOOT* ./
COPY rootfs.cfg grub.cfg
