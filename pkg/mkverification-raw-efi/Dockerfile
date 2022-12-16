# This mkverification-raw-efi produces the raw EFI partition for EVE,
# including the files in efi-files in the image.  This includes:
#
#   /EFI/BOOT/grub.cfg - Chainloads main bootloader
#   /UsbInvocationScript.txt - Enables USB boot on Dell 3000 series
#
# The image of mkverification-raw-efi tests the compatibility of the underlying
# hardware with EVE-OS. If the verification procedure is successful, EVE-OS
# will operate without problems with the edge device that is being verified
FROM lfedge/eve-alpine:c114cf1d3ea51534f061f9aa949beb6ac5c12fb3 AS build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

ENV BUILD_PKGS mkinitfs grep patch make coreutils musl-dev gcc g++ perl \
    autoconf automake libtool file bsd-compat-headers libc-dev \
    util-linux-dev flex linux-headers glib-dev libxrandr-dev zlib-dev \
    libusb-dev kmod-dev curl eudev-dev libdrm-dev i2c-tools-dev hwinfo \
    binutils-dev libaio-dev zlib-static libvncserver-dev python3 pixman-dev \
    py3-setuptools bash perl cmake m4 pkgconf autoconf-archive tpm2-tss-dev
ENV PKGS mtools dosfstools libarchive-tools sgdisk e2fsprogs util-linux \
    squashfs-tools coreutils tar dmidecode smartmontools libaio libaio-dev \
    perl glib zlib libusb curl xz pciutils usbutils hdparm util-linux \
    wireless-tools libxrandr eudev-libs libusb sudo fio iperf3 sysstat \
    lm-sensors acpi iw libdrm hwinfo dhclient dmidecode smartmontools \
    pciutils libgcc pixman glib libvncserver musl-utils dhclient \
    qemu-system-x86_64 tpm2-tss-dev tpm2-tss-esys tpm2-tss-fapi tpm2-tss-rc \
    tpm2-tss-sys tpm2-tss-tctildr tpm2-abrmd
RUN eve-alpine-deploy.sh

WORKDIR /out
RUN echo "mtools_skip_check=1" >> etc/mtools.conf; \
    mkdir -p efifs parts root bits config persist opt/pillar opt/debug \
    lib/modules run sys

ADD https://www.ddcutil.com/tarballs/ddcutil-1.2.2.tar.gz /out/ddcutil-1.2.2.tar.gz
ADD http://sources.buildroot.net/edid-decode/edid-decode-188950472c19492547e298b27f9da0d72cf826df.tar.gz /out/edid-decode-188950472c19492547e298b27f9da0d72cf826df.tar.gz
ADD https://github.com/linuxhw/build-stuff/releases/download/1.6/hw-probe-1.6-AI.tar.gz /out/hw-probe-1.6-AI.tar.gz
ADD https://cloud-images.ubuntu.com/minimal/releases/jammy/release/ubuntu-22.04-minimal-cloudimg-amd64.img /out/ubuntu-22.04-minimal-cloudimg-amd64.img
ADD https://github.com/tpm2-software/tpm2-tools/archive/5.2.tar.gz /out/5.2.tar.gz

COPY make-raw verify grub.cfg.in UsbInvocationScript.txt ./

RUN tar -xf hw-probe-1.6-AI.tar.gz \
    && tar -xf ddcutil-1.2.2.tar.gz \
    && tar -xf edid-decode-188950472c19492547e298b27f9da0d72cf826df.tar.gz \
    && tar -xf 5.2.tar.gz \
    && rm -rf hw-probe-1.6-AI.tar.gz ddcutil-1.2.2.tar.gz 5.2.tar.gz \
    edid-decode-188950472c19492547e298b27f9da0d72cf826df.tar.gz
WORKDIR /out/edid-decode-188950472c19492547e298b27f9da0d72cf826df
RUN make \
    && find . -type f | perl -lne "print if -B and -x" | xargs strip \
    && install -m 0755 edid-decode /out/usr/bin
WORKDIR /out/ddcutil-1.2.2
RUN ./configure --prefix=/out/usr \
    && make \
    && find . -type f | perl -lne "print if -B and -x" | xargs strip \
    && make install
WORKDIR /out/hw-probe-1.6-AI
RUN install -m 755 hw-probe.pl /out/usr/bin/hw-probe  \
    && sed -i "s/root\/HW_PROBE/tmp\/HW_PROBE/" /out/usr/bin/hw-probe
WORKDIR /out/tpm2-tools-5.2
RUN ./bootstrap \
    && ./configure --prefix=/out/usr \
    && make -j"$(nproc)" \
    && make install
# Before changing something here please take a look into the
# images/rootfs.yml.in onboot section: the verification should
# precede the storage-init container.
#
# now lets create an edge container
# FIXME: 003-installer? why not linuxkit build?
WORKDIR /eco/media/root-rw/root/containers/onboot/003-installer
COPY runtime.json config.json ./
RUN mv /out rootfs
# hadolint ignore=DL3003
RUN (cd /eco && find . -xdev | grep -v verification.img | sort | cpio --quiet -o -H newc) | gzip > rootfs/verification.img
RUN mv rootfs /out

# bootstrap Alpine's initrd
WORKDIR /
COPY initramfs-init.patch /tmp/
RUN patch -p1 < /tmp/initramfs-init.patch; \
    echo /bin/grep >> /etc/mkinitfs/features.d/base.files; \
    mkinitfs -n -o /out/initrd.img

FROM scratch
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

COPY --from=build /out/ /

ENTRYPOINT [ "/make-raw" ]
