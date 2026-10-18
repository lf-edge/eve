# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build-base

FROM build-base AS build-amd64
FROM build-base AS build-arm64
FROM build-base AS build-riscv64

# hadolint ignore=DL3006
FROM build-${TARGETARCH} AS build

ENV BUILD_PKGS="git gcc make libc6-dev libpam0g-dev m4 findutils util-linux patch"
RUN eve-ubuntu-deploy.sh

ENV FSCRYPT_COMMIT=v0.3.4
WORKDIR /go/src/github.com/google/fscrypt
# hadolint ignore=DL3020
ADD --keep-git-dir=true https://github.com/google/fscrypt.git#${FSCRYPT_COMMIT} .
COPY patch/* ./

# hadolint ignore=SC1097
RUN set -e && for patch in *.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done

RUN make -j "$(getconf _NPROCESSORS_ONLN)" && make DESTDIR="/out/opt/zededa" PREFIX="" install

# Register fscrypt in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n fscrypt -v "${FSCRYPT_COMMIT}" -l Apache-2.0 -u https://github.com/google/fscrypt

FROM scratch
COPY --from=build /out/opt/zededa/bin /opt/zededa/bin
COPY --from=build /out/var/lib/dpkg/status.d /var/lib/dpkg/status.d
