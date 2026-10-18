FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build

ENV BUILD_PKGS="patch make gcc perl uuid-dev git mtools linux-libc-dev libc6-dev liblzma-dev binutils"
RUN eve-ubuntu-deploy.sh

ENV IPXE_VERSION="5b3ebf8b24ae40a6f9f9f78491702d508f843e56"

ADD https://github.com/ipxe/ipxe.git#${IPXE_VERSION} /ws
WORKDIR /ws

COPY embedded.cfg src/embedded.cfg
COPY *patch /tmp/

# hadolint ignore=DL4006
RUN cat /tmp/*patch | patch -p1

# bin/ipxe.iso
ENV TARGET_x86_64="bin-x86_64-efi/ipxe.efi bin/ipxe.dsk bin/ipxe.lkrn bin/undionly.kpxe"
ENV TARGET_aarch64="bin-arm64-efi/ipxe.efi"
ENV TARGET_riscv64="clean"

RUN eval make -j "$(getconf _NPROCESSORS_ONLN)" -C src DOWNLOAD_PROTO_HTTPS=1 NO_ERROR=1 EMBED=embedded.cfg \$TARGET_`uname -m`
RUN mkdir -p /ws/src/bin-riscv64 && touch /ws/src/bin-riscv64/ipxe.riscv64 && touch /ws/src/bin-riscv64/ipxe.riscv64.debug
RUN mv /ws/src/bin/undionly.kpxe /ws/src/bin/ipxe.undionly 2>/dev/null || :
RUN rm /ws/src/bin*/*.*.*

# Register ipxe in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n ipxe -v "$(printf '%.8s' "${IPXE_VERSION}")" -l GPL-2.0-only -u https://ipxe.org

FROM scratch
COPY --from=build /out/var/lib/dpkg/status.d /var/lib/dpkg/status.d
COPY --from=build /ws/src/bin*/ipxe.* /
