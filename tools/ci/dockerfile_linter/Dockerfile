
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# Test Dockerfile for CI: intentionally contains old-style ENV/ARG syntax
FROM debian:latest

# Old-style ENV with single token (should modernize to ENV HOME=/root)
ENV HOME /root

# Old-style ENV with spaces and embedded quotes (quotes inside should be escaped)
ENV TITLE The "best" image

# Old-style ARG with default (should modernize to ARG VERSION=1.2.3)
ARG VERSION 1.2.3

# Bare ARG (should remain unchanged; no '=' added)
ARG NO_DEFAULT

# Old-style multi-line ENV with continuations (should collapse and wrap <=100 cols)
ENV BUILD_PKGS gcc make     musl-dev libcurl-dev     python3-dev

# Already modern lines (should stay unchanged)
ENV MODERN_A=1 MODERN_B=2
ARG MODERN_ARG=ok
