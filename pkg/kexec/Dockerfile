FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build

ENV BUILD_PKGS="patch curl make gcc perl uuid-dev libblkid-dev git mtools linux-libc-dev libc6-dev liblzma-dev libelf-dev libdw-dev libbz2-dev zlib1g-dev"

RUN eve-ubuntu-deploy.sh

# Build kexec-tools. The image is an init overlay of the EVE host rootfs,
# whose userland is linuxkit's busybox, so kexec is linked statically and
# the overlay carries no libraries.
ENV KEXEC_VERSION=2.0.32
WORKDIR /tmp/kexec/kexec-tools-${KEXEC_VERSION}
ADD https://mirrors.edge.kernel.org/pub/linux/utils/kernel/kexec/kexec-tools-${KEXEC_VERSION}.tar.gz /tmp/kexec/kexec-tools.tgz
RUN tar -C .. -xzvf ../kexec-tools.tgz && rm -f ../kexec-tools.tgz
RUN ./configure --prefix /usr LDFLAGS=-static
RUN make -j "$(getconf _NPROCESSORS_ONLN)"
RUN make DESTDIR=/stage install && rm -rf /stage/usr/share /stage/usr/lib/kexec-tools

# Register kexec-tools in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n kexec-tools -v "${KEXEC_VERSION}" -l GPL-2.0-only -u https://kernel.org/pub/linux/utils/kernel/kexec -o /stage

FROM scratch
COPY --from=build /stage /
