# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:745ae9066273c73b0fd879c4ba4ff626a8392d04 AS build-base

FROM build-base AS build-amd64
FROM build-base AS build-arm64
FROM build-base AS build-riscv64

# hadolint ignore=DL3006
FROM build-${TARGETARCH} AS build

ENV BUILD_PKGS git gcc make libc-dev linux-pam-dev m4 findutils util-linux make patch
RUN eve-alpine-deploy.sh

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

FROM scratch
COPY --from=build /out/opt/zededa/bin /opt/zededa/bin