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
search_disk_uuid verify xzio xfs video gfxterm efi_gop gptprio chain probe reboot regexp smbios part_msdos"
ENV GRUB_MODULES_x86_64="multiboot2 efi_uga"
ENV GRUB_MODULES_aarch64="xen_boot"
ENV GRUB_COMMIT=71f9e4ac44142af52c3fc1860436cf9e432bf764
ENV GRUB_REPO=git://git.sv.gnu.org/grub.git

COPY patches/* /patches/
RUN mkdir /grub-lib && \
  set -e && \
  git clone ${GRUB_REPO} && \
  cd grub && \
  git checkout -b grub-build ${GRUB_COMMIT} && \
  for patch in /patches/*.patch; do \
    echo "Applying $patch"; \
    patch -p1 < "$patch"; \
  done && \
  ./autogen.sh && \
  ./configure --libdir=/grub-lib --with-platform=efi CFLAGS="-Os -Wno-unused-value" && \
  make -j "$(getconf _NPROCESSORS_ONLN)" && \
  make install

# create the grub core image
RUN cd grub ; case $(uname -m) in \
  x86_64) \
    ./grub-mkimage -O x86_64-efi -d /grub-lib/grub/x86_64-efi -o /grub-lib/BOOTX64.EFI -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES_x86_64} ;\
    ;; \
  aarch64) \
    ./grub-mkimage -O arm64-efi -d /grub-lib/grub/arm64-efi -o /grub-lib/BOOTAA64.EFI -p /EFI/BOOT ${GRUB_MODULES_PORT} ${GRUB_MODULES_aarch64} ;\
    ln -s BOOTAA64.EFI /grub-lib/BOOTX64.EFI ;\
    ;; \
  esac

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /EFI/BOOT
COPY --from=grub-build /grub-lib/BOOT*.EFI ./
COPY rootfs.cfg grub.cfg
