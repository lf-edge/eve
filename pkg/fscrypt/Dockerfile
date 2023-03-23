# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb AS build

ENV BUILD_PKGS git gcc make libc-dev linux-pam-dev m4 findutils go util-linux make patch
RUN eve-alpine-deploy.sh

ENV FSCRYPT_COMMIT=b41569d397d3e66099cde07d8eef36b2f42dd0ec
WORKDIR /go/src/github.com/google/fscrypt
# hadolint ignore=DL3020
ADD --keep-git-dir=true https://github.com/google/fscrypt.git#${FSCRYPT_COMMIT} .
COPY patch/* ./
RUN patch -p1 < patch01-no-pam.diff && \
    patch -p1 < patch02-rotate-raw-key.diff && \
    patch -p1 < patch03-vendor.diff && \
    patch -p1 < patch04-goConv.diff && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && make DESTDIR=/out/opt/zededa/bin install

FROM scratch
COPY --from=build /out/opt/zededa/bin /opt/zededa/bin