# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# linuxkit's runc image with the binary stripped: upstream ships runc with
# its symbol tables, 17 MB that cost 7 MB in the compressed rootfs.

FROM linuxkit/runc:v1.3.0 AS upstream

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS strip
COPY --from=upstream /usr/bin/runc /runc
RUN strip /runc

FROM upstream
COPY --from=strip /runc /usr/bin/runc
