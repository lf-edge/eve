# Copyright (c) 2025-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG RUST_VERSION=lfedge/eve-rust:1.93.1-2
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
ADD --keep-git-dir=true https://github.com/vectordotdev/vector.git#v0.56.0 /app

# The vendored OpenSSL embeds SOURCE_DATE_EPOCH, or else the build time, in
# its "built on:" string; use the commit time of the tag. Drop .git so
# vector's build.rs embeds no git hash.
RUN git -C /app log -1 --format=%ct > /source-date-epoch && rm -rf /app/.git

# Drop upstream vector's own .cargo (pins rust-toolchain etc) and replace
# with ours. Our config.toml merges with eve-rust's per-target linker config
# (`[target.<triple>]`) — profile/codegen tweaks go here, cross-compile
# linker config stays in the base image.
RUN rm -rf /app/.cargo /app/rust-toolchain.toml
COPY cargo-config.toml /app/.cargo/config.toml

WORKDIR /app

# Move the crates of vector's Cargo.lock with published advisories to the
# fixed release that still satisfies vector's version requirements, as
# crate@locked-version=fixed-version. The locked version pins each entry to
# this vector release: on a vector bump, drop the pins its new Cargo.lock
# already covers and re-check the rest.
#   postgres-protocol, tokio-postgres: GHSA-5x78-73v4-xg6w,
#     GHSA-rgqc-3x5p-6gwg, GHSA-3gjw-f78c-vvpw (RUSTSEC-2026-0178/0179/0180)
#   quinn-proto: CVE-2026-31812, GHSA-4w2j-m93h-cj5j, GHSA-3g6h-r5qx-f6hq,
#     GHSA-465w-v9q3-7j98, GHSA-hmxj-32vh-65vr, GHSA-2hv7-gw8g-gpq5
#   hickory-proto, hickory-resolver: RUSTSEC-2026-0118, RUSTSEC-2026-0119,
#     CVE-2026-93657
#   serde_with: GHSA-7gcf-g7xr-8hxj
#   aws-smithy-json (needs aws-smithy-runtime-api 1.12): CVE-2026-18140
#   xxhash-rust: GHSA-6g2r-675j-hx59
#   rustls: GHSA-2mjx-qc3c-rqvc
#   anyhow: RUSTSEC-2026-0190; tokio: RUSTSEC-2026-0386
#   crossbeam-epoch: RUSTSEC-2026-0204; domain: RUSTSEC-2026-0310
#   event-listener: RUSTSEC-2026-0221; memmap2: RUSTSEC-2026-0186
#   webbrowser: GHSA-2ph8-5cr8-hr33; libz-sys: GHSA-8p3x-q3q3-q3v5
#   libredox is only moved so that tokio-postgres 0.7.18 resolves.
RUN set -e; for pin in \
        postgres-protocol@0.6.10=0.6.12 \
        libredox@0.1.3=0.1.25 \
        tokio-postgres@0.7.15=0.7.18 \
        quinn-proto@0.11.14=0.11.18 \
        hickory-proto@0.26.1=0.26.3 \
        hickory-resolver@0.26.0=0.26.3 \
        serde_with@3.20.0=3.24.0 \
        aws-smithy-runtime-api@1.11.6=1.12.3 \
        aws-smithy-json@0.62.5=0.62.7 \
        xxhash-rust@0.8.15=0.8.19 \
        rustls@0.23.37=0.23.46 \
        anyhow@1.0.102=1.0.104 \
        tokio@1.52.2=1.54.1 \
        crossbeam-epoch@0.9.15=0.9.20 \
        domain@0.12.1=0.12.3 \
        event-listener@5.3.1=5.4.2 \
        memmap2@0.9.10=0.9.11 \
        webbrowser@1.0.0=1.2.2 \
        libz-sys@1.1.28=1.1.31; do \
        cargo update -p "${pin%=*}" --precise "${pin#*=}"; \
    done

RUN SOURCE_DATE_EPOCH=$(cat /source-date-epoch) cargo build --release --locked $VECTOR_FEATURES

# Symbols are stripped via `profile.release.strip = "symbols"` in
# cargo-config.toml. Doing it in the Rust profile (rather than invoking
# a host `strip`/`llvm-strip` binary here) keeps the operation arch-aware:
# the host is amd64 but the binary may be riscv64/aarch64.

RUN cargo sbom > sbom.spdx.json
RUN cp "/app/target/$CARGO_BUILD_TARGET/release/vector" /app/target/

FROM lfedge/eve-alpine:61283a3a978a7cdc9073a1ba678717fc3ea1fe97 AS runtime
ENV PKGS="inotify-tools"
RUN eve-alpine-deploy.sh

# Register vector in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n vector -v 0.56.0 -l MPL-2.0 -u https://github.com/vectordotdev/vector

# Assemble the final image
FROM scratch
COPY --from=runtime /out/ /
COPY --from=builder /app/target/vector /usr/bin/vector
COPY --from=builder /app/sbom.spdx.json /sbom.spdx.json

COPY etc/vector.yaml /etc/vector/vector.yaml
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
