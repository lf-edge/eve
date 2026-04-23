# Copyright (c) 2025-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG RUST_VERSION=lfedge/eve-rust:1.93.1-1
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

# hadolint ignore=DL3006
FROM --platform=$BUILDPLATFORM ${RUST_VERSION} AS toolchain-base
ARG TARGETARCH

FROM toolchain-base AS target-amd64
ENV CARGO_BUILD_TARGET="x86_64-unknown-linux-musl"

FROM toolchain-base AS target-arm64
ENV CARGO_BUILD_TARGET="aarch64-unknown-linux-musl"

FROM toolchain-base AS target-riscv64
ENV CARGO_BUILD_TARGET="riscv64gc-unknown-linux-musl"

# hadolint ignore=DL3006
FROM target-$TARGETARCH AS toolchain
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

# building the final image
FROM toolchain AS builder
ARG VECTOR_FEATURES
ADD https://github.com/vectordotdev/vector.git#v0.54.0 /app

# Drop upstream vector's own .cargo (pins rust-toolchain etc) and replace
# with ours. Our config.toml merges with eve-rust's per-target linker config
# (`[target.<triple>]`) — profile/codegen tweaks go here, cross-compile
# linker config stays in the base image.
RUN rm -rf /app/.cargo /app/rust-toolchain.toml
COPY cargo-config.toml /app/.cargo/config.toml

WORKDIR /app

RUN cargo build --release $VECTOR_FEATURES

# Symbols are stripped via `profile.release.strip = "symbols"` in
# cargo-config.toml. Doing it in the Rust profile (rather than invoking
# a host `strip`/`llvm-strip` binary here) keeps the operation arch-aware:
# the host is amd64 but the binary may be riscv64/aarch64.

RUN cargo sbom > sbom.spdx.json
RUN cp "/app/target/$CARGO_BUILD_TARGET/release/vector" /app/target/

FROM lfedge/eve-alpine:1f744180283ffb4eabcc3862531aeacf1de886b3 AS runtime
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
