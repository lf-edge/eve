# Copyright (c) 2018-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM eve-alpine-dnstest

ENV PKGS dnsmasq
RUN eve-alpine-deploy.sh

COPY . /dnstest/
WORKDIR /dnstest
RUN go test -mod=vendor -c -o /out/dnstest

CMD ["/out/dnstest", "-test.v"]
