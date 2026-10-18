# Copyright (c) 2018-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# hadolint ignore=DL3006
FROM eve-ubuntu-dnstest

ENV PKGS="dnsmasq-base"
RUN eve-ubuntu-deploy.sh
# the test execs /out's dnsmasq from the builder root: its libraries (dbus, nftables,
# conntrack) only exist under /out, and like pillar it runs as nobody:nobody while
# Debian names gid 65534 nogroup
ENV LD_LIBRARY_PATH=/out/usr/lib/x86_64-linux-gnu:/out/usr/lib/aarch64-linux-gnu:/out/usr/lib/riscv64-linux-gnu
RUN echo "nobody:x:65534:" >> /etc/group

COPY . /dnstest/
WORKDIR /dnstest
RUN go test -mod=vendor -c -o /out/dnstest

CMD ["/out/dnstest", "-test.v"]
