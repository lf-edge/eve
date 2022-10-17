FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as grub-build
ENV BUILD_PKGS automake \
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
               bash
ENV BUILD_PKGS_arm64 coreutils
ENV BUILD_PKGS_riscv64 coreutils
RUN eve-alpine-deploy.sh

# list of grub modules that are portable between x86_64 and aarch64
ENV GRUB_MODULES_PORT="part_gpt fat ext2 iso9660 squash4 gzio linux acpi normal cpio crypto disk boot crc64 \
search_disk_uuid search_part_label search_label xzio xfs video gfxterm serial gptprio chain probe reboot regexp smbios \
part_msdos cat echo test configfile loopback"
ENV GRUB_MODULES_i386_pc="multiboot multiboot2 biosdisk gpt verify"
ENV GRUB_MODULES_x86_64="multiboot multiboot2 efi_uga efi_gop linuxefi gpt verify gcry_sha256 measurefs"
ENV GRUB_MODULES_aarch64="xen_boot efi_gop gpt"
ENV GRUB_MODULES_riscv64=""
ENV GRUB_COMMIT=71f9e4ac44142af52c3fc1860436cf9e432bf764
ENV GRUB_TAG_riscv64=2.06
ENV GRUB_TAG_aarch64=2.06

ENV GRUB_REPO=https://git.savannah.gnu.org/git/grub.git

COPY / /
# because python is not available
RUN ln -s python3 /usr/bin/python && \
    mkdir /grub-lib

# hadolint ignore=DL3003
RUN if [ ! -d "grub" ]; then \
        git clone ${GRUB_REPO} \
        && cd /grub \
        && git config --add user.email a@b.c \
        && git config user.name a \
        && if [ "$(uname -m)" != x86_64 ]; then \
            GRUB_COMMIT="$(git show-ref -s tags/grub-"$(eval echo "\$GRUB_TAG_$(uname -m)")")"; \
        fi \
        && git checkout -b grub-build "$GRUB_COMMIT" \
	&& echo "git ${GRUB_REPO} ${GRUB_COMMIT}" >>/source-info \
        && if [ "$(uname -m)" != x86_64 ]; then \
            rm -rf /patches \
            && mv /patches-"$(eval echo "\$GRUB_TAG_$(uname -m)")" /patches \
            && cp /patches-"$(uname -m)"-"$(eval echo "\$GRUB_TAG_$(uname -m)")"/* /patches/; \
        fi \
        && git am /patches/* \
        && (./bootstrap || ./autogen.sh) ; \
    fi


WORKDIR /grub

ENV BUILD_GRUB="set -e && \
  if [ -f Makefile ]; then make distclean; fi && \
  ./configure --disable-werror --libdir=/grub-lib --with-platform=\${GRUB_PLATFORM} CFLAGS='-Os -Wno-unused-value' && \
  make -j $(getconf _NPROCESSORS_ONLN) && \
  make install"

ENV GRUB_PLATFORM=efi
RUN eval $BUILD_GRUB
RUN if [ "$(uname -m)" = x86_64 ]; then GRUB_PLATFORM="pc --disable-efiemu" && eval "$BUILD_GRUB" ; fi


COPY embedded.cfg /

# create the grub core image
RUN case $(uname -m) in \
  x86_64) \
    ./grub-mkimage -O x86_64-efi -d /grub-lib/grub/x86_64-efi -o /grub-lib/BOOTX64.EFI -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES_x86_64} &&\
    ./grub-mkimage -O i386-pc -d /grub-lib/grub/i386-pc -o /grub-lib/BOOT.pc -p /EFI/BOOT -c /embedded.cfg ${GRUB_MODULES_PORT} ${GRUB_MODULES_i386_pc} && \
    cp /grub-lib/grub/i386-pc/boot.img /grub-lib/BOOT.img ;;\
  aarch64) \
    ./grub-mkimage -O arm64-efi -d /grub-lib/grub/arm64-efi -o /grub-lib/BOOTAA64.EFI -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES_aarch64} ;; \
  riscv64) \
     ./grub-mkimage -O riscv64-efi -d /grub-lib/grub/riscv64-efi -o /grub-lib/BOOTRISCV64.EFI -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES_riscv64} ;;\
  esac

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /EFI/BOOT
COPY --from=grub-build /grub-lib/BOOT* ./
COPY rootfs.cfg grub.cfg
