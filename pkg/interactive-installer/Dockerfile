# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 AS build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

ENV BUILD_PKGS curl build-base git ncurses-dev musl-dev python3 bash
ENV PKGS ncurses-dev smartmontools mtools strace util-linux e2fsprogs e2fsprogs-extra jq

RUN eve-alpine-deploy.sh
ENV RUSTUP_HOME=/usr/local
ENV CARGO_HOME=/usr/local/cargo
ENV CARGO_TARGET_DIR=/usr/local/my-installer/target
ENV RUST_VERSION=1.79.0
ADD https://static.rust-lang.org/dist/rust-${RUST_VERSION}-x86_64-unknown-linux-musl.tar.gz rust-${RUST_VERSION}-x86_64-unknown-linux-musl.tar.gz
ADD https://static.rust-lang.org/dist/rust-${RUST_VERSION}-aarch64-unknown-linux-musl.tar.gz rust-${RUST_VERSION}-aarch64-unknown-linux-musl.tar.gz

# Install Rust using the standalone installer
RUN ARCH="aarch64" && \
    if [ "$(uname -m)" == "x86_64" ]; then \
        ARCH="x86_64"; \
    fi && \
    tar -xzf rust-${RUST_VERSION}-${ARCH}-unknown-linux-musl.tar.gz && \
    cd rust-${RUST_VERSION}-${ARCH}-unknown-linux-musl && \
    ./install.sh && \
    cd .. && \
    rm -rf rust-${RUST_VERSION}-${ARCH}-unknown-linux-musl rust-${RUST_VERSION}-${ARCH}-unknown-linux-musl.tar.gz

ENV PATH "$PATH:/usr/local/cargo/bin"

WORKDIR /usr/local/my-installer
COPY . .

# Copy the vendor directory
COPY vendor /usr/local/my-installer/vendor

# Ensure Cargo uses the vendor directory
COPY .cargo/config.toml /usr/local/my-installer/.cargo/config.toml
#RUN cargo install --debug --path .
RUN cargo build

FROM scratch as image
COPY --from=build /out /
ENV RUST_BACKTRACE full
COPY --from=build /usr/local/my-installer/target/debug/installer /sbin/installer
COPY run-installer.sh /sbin/run-installer.sh

WORKDIR /
ENTRYPOINT ["/sbin/run-installer.sh"]
