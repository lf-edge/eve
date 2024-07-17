# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:e34284a8dd69c9c5ba7c52cd7b7d08fc2db1e0ac as build
ENV PKGS alpine-baselayout guacamole-server guacamole-server-vnc
RUN eve-alpine-deploy.sh

FROM scratch

COPY --from=build /out/ /

ENTRYPOINT []
CMD ["/usr/sbin/guacd", "-l", "4822", "-b", "0.0.0.0", "-L", "info", "-f"]
