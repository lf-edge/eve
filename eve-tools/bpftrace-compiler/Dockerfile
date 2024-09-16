# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.20

# hadolint ignore=DL3018
RUN apk add --no-cache qemu-system-x86_64 qemu-system-aarch64 go make git docker

COPY init_docker_tests.sh /init_docker_tests.sh
RUN chmod u+x /init_docker_tests.sh

RUN mkdir /src
COPY kernel-commits.mk /

WORKDIR /src

ENTRYPOINT ["/init_docker_tests.sh"]
