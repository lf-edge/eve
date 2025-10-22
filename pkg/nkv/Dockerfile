# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG NKV_VERSION=0.0.3
ARG RUST_VERSION=lfedge/eve-rust:1.84.1
FROM --platform=$BUILDPLATFORM ${RUST_VERSION} AS toolchain-base
ARG TARGETARCH

FROM toolchain-base AS target-amd64
ENV CARGO_BUILD_TARGET="x86_64-unknown-linux-musl"

FROM toolchain-base AS target-arm64
ENV CARGO_BUILD_TARGET="aarch64-unknown-linux-musl"

FROM toolchain-base AS target-riscv64
ENV CARGO_BUILD_TARGET="riscv64gc-unknown-linux-gnu"

FROM target-$TARGETARCH as toolchain
ARG NKV_VERSION
RUN echo "Toolchain cargo target: $CARGO_BUILD_TARGET"

FROM toolchain AS planer
ADD --keep-git-dir=true https://github.com/nkval/nkv.git#${NKV_VERSION} /app

WORKDIR /app

RUN cargo chef prepare --recipe-path recipe.json

FROM toolchain AS cacher

WORKDIR /app
COPY --from=planer /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM toolchain AS builder
ADD --keep-git-dir=true https://github.com/nkval/nkv.git#${NKV_VERSION} /app
WORKDIR /app

COPY --from=cacher /app/target /app/target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN echo "Cacher cargo target: $CARGO_BUILD_TARGET"

RUN cargo build --release
RUN cargo sbom > sbom.spdx.json
RUN cp /app/target/$CARGO_BUILD_TARGET/release/nkv-server /app/target/
RUN cp /app/target/$CARGO_BUILD_TARGET/release/nkv-client /app/target/

FROM lfedge/eve-alpine:591df01e581889c3027514c8a91feaca1c8ad49f AS runtime
ENV PKGS="kbd pciutils usbutils"
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=runtime /out/lib /lib
COPY --from=runtime /out/usr/lib /usr/lib

# copy busybox and install all symbolic links but just for debugging
COPY --from=runtime /out/bin/busybox /bin/busybox
# using an 'exec' form of RUN, shell form of 'RUN'
# command expects /bin/sh which doesn't yet exist
RUN [ "/bin/busybox", "--install", "-s", "/bin" ]
COPY --from=runtime /out/usr/bin/du /usr/bin/du

COPY --from=builder /app/target/nkv-server /sbin/nkv-server
COPY --from=builder /app/sbom.spdx.json /sbin/sbom.spdx.json

# Use this binary in debug container
COPY --from=builder /app/target/nkv-client /sbin/nkv-client

# Since we don't have /tmp in our containers and use run
# for such purposes, set this variable to make TempDir work
ENV TMPDIR=/run

CMD ["nkv-server", "--dir", "/persist/nkv-storage/",  "--addr", "/run/nkv.sock"]
