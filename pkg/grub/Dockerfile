FROM linuxkit/alpine:8b53d842a47fce43464e15f65ee2f68b82542330 AS grub-build

RUN apk add \
  automake \
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
  autoconf

# because python is not available
RUN ln -s python3 /usr/bin/python

# list of grub modules that are portable between x86_64 and aarch64
ENV GRUB_MODULES_PORT="part_gpt fat ext2 iso9660 squash4 gzio linux acpi normal cpio crypto disk boot crc64 gpt \
search_disk_uuid search_part_label search_label verify xzio xfs video gfxterm serial gptprio chain probe reboot regexp smbios    \
part_msdos cat echo test configfile loopback"
ENV GRUB_MODULES_i386_pc="multiboot multiboot2 biosdisk"
ENV GRUB_MODULES_x86_64="multiboot multiboot2 efi_uga efi_gop"
ENV GRUB_MODULES_aarch64="xen_boot efi_gop"
ENV GRUB_COMMIT=71f9e4ac44142af52c3fc1860436cf9e432bf764
ENV GRUB_REPO=https://git.savannah.gnu.org/git/grub.git

COPY patches/* /patches/
RUN mkdir /grub-lib && git clone ${GRUB_REPO}

WORKDIR /grub
RUN git config --add user.email a@b.c && git config user.name a && \
    git checkout -b grub-build ${GRUB_COMMIT} && git am /patches/*

ENV BUILD_GRUB="set -e && git clean -f -d -x && git reset --hard HEAD && \
  ./autogen.sh && \
  ./configure --libdir=/grub-lib --with-platform=\${GRUB_PLATFORM} CFLAGS='-Os -Wno-unused-value' && \
  make -j $(getconf _NPROCESSORS_ONLN) && \
  make install"

ENV GRUB_PLATFORM=efi
RUN eval $BUILD_GRUB
RUN if [ "$(uname -m)" = x86_64 ]; then GRUB_PLATFORM="pc --disable-efiemu" && eval "$BUILD_GRUB" ; fi

# create the grub core image
RUN case $(uname -m) in \
  x86_64) \
    ./grub-mkimage -O x86_64-efi -d /grub-lib/grub/x86_64-efi -o /grub-lib/BOOTX64.EFI -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES_x86_64} &&\
    ./grub-mkimage -O i386-pc -d /grub-lib/grub/i386-pc -o /grub-lib/BOOT.pc -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES_i386_pc} ;\
    ;; \
  aarch64) \
    ./grub-mkimage -O arm64-efi -d /grub-lib/grub/arm64-efi -o /grub-lib/BOOTAA64.EFI -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES_aarch64} ;\
    ;; \
  esac

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /EFI/BOOT
COPY --from=grub-build /grub-lib/BOOT* ./
COPY rootfs.cfg grub.cfg
