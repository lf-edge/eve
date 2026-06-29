FROM lfedge/eve-alpine:fb0a297e3939c06cd3e4a4b9293b4cf76847d9c0 AS build

ENV BUILD_PKGS patch curl make gcc perl util-linux-dev git mtools linux-headers musl-dev xz-dev elfutils-dev libbz2
ENV PKGS xz-libs util-linux elfutils-dev libbz2

RUN eve-alpine-deploy.sh

# Build kexec-tools
ENV KEXEC_VERSION=2.0.32
WORKDIR /tmp/kexec/kexec-tools-${KEXEC_VERSION}
ADD https://mirrors.edge.kernel.org/pub/linux/utils/kernel/kexec/kexec-tools-${KEXEC_VERSION}.tar.gz /tmp/kexec/kexec-tools.tgz
RUN tar -C .. -xzvf ../kexec-tools.tgz && rm -f ../kexec-tools.tgz
RUN ./configure --prefix /usr
RUN make -j "$(getconf _NPROCESSORS_ONLN)"
RUN make DESTDIR=/out install

# Register kexec-tools in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n kexec-tools -v "${KEXEC_VERSION}" -l GPL-2.0-only -u https://kernel.org/pub/linux/utils/kernel/kexec

FROM scratch
COPY --from=build /out /
