# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG REL_HASH_LFEDGE_EVE_ALPINE
ARG RUST_VERSION=lfedge/eve-rust:1.85.1-2
ARG VECTOR_FEATURES='--no-default-features --features \
sources-socket,\
sources-internal_metrics,\
transforms-aws_ec2_metadata,\
transforms-dedupe,\
transforms-filter,\
transforms-window,\
transforms-log_to_metric,\
transforms-metric_to_log,\
transforms-reduce,\
transforms-remap,\
transforms-route,\
transforms-exclusive-route,\
transforms-sample,\
transforms-throttle,\
sinks-socket,\
sources-prometheus-scrape,\
sinks-prometheus'

FROM --platform=$BUILDPLATFORM ${RUST_VERSION} AS toolchain-base
ARG TARGETARCH

FROM toolchain-base AS target-amd64
ENV CARGO_BUILD_TARGET="x86_64-unknown-linux-musl"

FROM toolchain-base AS target-arm64
ENV CARGO_BUILD_TARGET="aarch64-unknown-linux-musl"

FROM toolchain-base AS target-riscv64
ENV CARGO_BUILD_TARGET="riscv64gc-unknown-linux-gnu"

FROM target-$TARGETARCH AS toolchain
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

# building the final image
FROM toolchain AS builder
ARG VECTOR_FEATURES
ADD https://github.com/vectordotdev/vector.git#v0.47.0 /app
# we have our own options, so remove the default cargo config
# if this doesn't help then remove everything leaving only
# the files from .dockerignore except rust-toolchain.toml
RUN rm -rf /app/.cargo /app/rust-toolchain.toml

WORKDIR /app

ENV RUSTFLAGS="\
    -C opt-level=z \
    -C lto=fat \
    -C embed-bitcode=yes \
    -C codegen-units=1"
RUN cargo build --release $VECTOR_FEATURES

# strip unneeded symbols
RUN strip "/app/target/$CARGO_BUILD_TARGET/release/vector"

RUN cargo sbom > sbom.spdx.json
RUN cp "/app/target/$CARGO_BUILD_TARGET/release/vector" /app/target/

FROM ${REL_HASH_LFEDGE_EVE_ALPINE} AS runtime
ENV PKGS="inotify-tools"
RUN eve-alpine-deploy.sh

# Assemble the final image
FROM scratch
COPY --from=runtime /out/ /
COPY --from=builder /app/target/vector /usr/bin/vector
COPY --from=builder /app/sbom.spdx.json /sbom.spdx.json

COPY etc/vector.yaml /etc/vector/vector.yaml
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
